/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_conn.c,v 1.27.166.1 2005/05/27 02:35:29 lindak Exp $
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Connection engine.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/vnode.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/socketvar.h>
#include <sys/cred.h>
#include <sys/cred_impl.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/cmn_err.h>
#include <sys/thread.h>
#include <sys/atomic.h>

#ifdef APPLE
#include <sys/smb_apple.h>
#include <sys/smb_iconv.h>
#else
#include <netsmb/smb_osdep.h>
#endif

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>
#include <netsmb/smb_pass.h>

static struct smb_connobj smb_vclist;
static uint_t smb_vcnext = 0;	/* next unique id for VC */

void smb_co_init(struct smb_connobj *cp, int level, char *objname);
void smb_co_done(struct smb_connobj *cp);
void smb_co_hold(struct smb_connobj *cp);
void smb_co_rele(struct smb_connobj *cp);
void smb_co_kill(struct smb_connobj *cp);

#ifdef APPLE
static void smb_sm_lockvclist(void);
static void smb_sm_unlockvclist(void);
#endif

static void smb_vc_free(struct smb_connobj *cp);
static void smb_vc_gone(struct smb_connobj *cp);

static void smb_share_free(struct smb_connobj *cp);
static void smb_share_gone(struct smb_connobj *cp);

/* smb_dup_sockaddr moved to smb_tran.c */

int
smb_sm_init(void)
{
	smb_co_init(&smb_vclist, SMBL_SM, "smbsm");
	return (0);
}

int
smb_sm_idle(void)
{
	int error = 0;
	SMB_CO_LOCK(&smb_vclist);
	if (smb_vclist.co_usecount > 1) {
		SMBSDEBUG("%d connections still active\n",
		    smb_vclist.co_usecount - 1);
		error = EBUSY;
	}
	SMB_CO_UNLOCK(&smb_vclist);
	return (error);
}

void
smb_sm_done(void)
{
	/*
	 * XXX Q4BP why are we not iterating on smb_vclist here?
	 * Because the caller has just called smb_sm_idle() to
	 * make sure we have no VCs before calling this.
	 */
	smb_co_done(&smb_vclist);
}

/*
 * Find a VC identified by the info in vcspec,
 * and return it with a "hold", but not locked.
 */
/*ARGSUSED*/
static int
smb_sm_lookupvc(
	struct smb_vcspec *vcspec,
	struct smb_cred *scred,
	struct smb_vc **vcpp)
{
	struct smb_connobj *co;
	struct smb_vc *vcp;
	zoneid_t zoneid = getzoneid();

	ASSERT(MUTEX_HELD(&smb_vclist.co_lock));

	/* var, head, next_field */
	SLIST_FOREACH(co, &smb_vclist.co_children, co_next) {
		vcp = CPTOVC(co);

		/*
		 * Some things we can check without
		 * holding the lock (those that are
		 * set at creation and never change).
		 */

		/* VCs in other zones are invisibile. */
		if (vcp->vc_zoneid != zoneid)
			continue;

		/* Also segregate by owner. */
		if (vcp->vc_uid != vcspec->owner)
			continue;

		/* XXX: we ignore the group.  Remove vc_gid? */

		/* server */
		if (smb_cmp_sockaddr(vcp->vc_paddr, vcspec->sap))
			continue;

		/* domain+user */
		if (strcmp(vcp->vc_domain, vcspec->domain))
			continue;
		if (strcmp(vcp->vc_username, vcspec->username))
			continue;

		SMB_VC_LOCK(vcp);

		/* No new references allowed when _GONE is set */
		if (vcp->vc_flags & SMBV_GONE)
			goto unlock_continue;

		if (vcp->vc_vopt & SMBVOPT_PRIVATE)
			goto unlock_continue;

	found:
		/*
		 * Success! (Found one we can use)
		 * Return with it held, unlocked.
		 * In-line smb_vc_hold here.
		 */
		co->co_usecount++;
		SMB_VC_UNLOCK(vcp);
		*vcpp = vcp;
		return (0);

	unlock_continue:
		SMB_VC_UNLOCK(vcp);
		/* keep looking. */
	}

	return (ENOENT);
}

int
smb_sm_findvc(
	struct smb_vcspec *vcspec,
	struct smb_cred *scred,
	struct smb_vc **vcpp)
{
	struct smb_vc *vcp;
	int error;

	*vcpp = vcp = NULL;

	SMB_CO_LOCK(&smb_vclist);
	error = smb_sm_lookupvc(vcspec, scred, &vcp);
	SMB_CO_UNLOCK(&smb_vclist);

	/* Return if smb_sm_lookupvc fails */
	if (error != 0)
		return (error);

	/* Ingore any VC that's not active. */
	if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		smb_vc_rele(vcp);
		return (ENOENT);
	}

	/* Active VC. Return it held. */
	*vcpp = vcp;
	return (error);
}

int
smb_sm_negotiate(
	struct smb_vcspec *vcspec,
	struct smb_cred *scred,
	struct smb_vc **vcpp)
{
	struct smb_vc *vcp;
	clock_t tmo;
	int created, error;

top:
	*vcpp = vcp = NULL;

	SMB_CO_LOCK(&smb_vclist);
	error = smb_sm_lookupvc(vcspec, scred, &vcp);
	if (error) {
		/* The VC was not found.  Create? */
		if ((vcspec->optflags & SMBVOPT_CREATE) == 0) {
			SMB_CO_UNLOCK(&smb_vclist);
			return (error);
		}
		error = smb_vc_create(vcspec, scred, &vcp);
		if (error) {
			/* Could not create? Unusual. */
			SMB_CO_UNLOCK(&smb_vclist);
			return (error);
		}
		/* Note: co_usecount == 1 */
		created = 1;
	} else
		created = 0;
	SMB_CO_UNLOCK(&smb_vclist);

	if (created == 0) {
		/*
		 * Found an existing VC.  Reuse it, but first,
		 * wait for any other thread doing setup, etc.
		 * Note: We hold a reference on the VC.
		 */
		error = 0;
		SMB_VC_LOCK(vcp);
		while (vcp->vc_state < SMBIOD_ST_VCACTIVE) {
			if (vcp->vc_flags & SMBV_GONE)
				break;
			tmo = lbolt + SEC_TO_TICK(2);
			tmo = cv_timedwait_sig(&vcp->vc_statechg,
			    &vcp->vc_lock, tmo);
			if (tmo == 0) {
				error = EINTR;
				break;
			}
		}
		SMB_VC_UNLOCK(vcp);

		/* Interrupted? */
		if (error)
			goto out;

		/*
		 * Was there a vc_kill while we waited?
		 * If so, this VC is gone.  Start over.
		 */
		if (vcp->vc_flags & SMBV_GONE) {
			smb_vc_rele(vcp);
			goto top;
		}

		/*
		 * The possible states here are:
		 * SMBIOD_ST_VCACTIVE, SMBIOD_ST_DEAD
		 *
		 * SMBIOD_ST_VCACTIVE is the normal case,
		 * where found a connection ready to use.
		 *
		 * We may find vc_state == SMBIOD_ST_DEAD
		 * if a previous session has disconnected.
		 * In this case, we'd like to reconnect,
		 * so take over setting up this VC as if
		 * this thread had created it.
		 */
		SMB_VC_LOCK(vcp);
		if (vcp->vc_state == SMBIOD_ST_DEAD) {
			vcp->vc_state = SMBIOD_ST_NOTCONN;
			created = 1;
			/* Will signal vc_statechg below */
		}
		SMB_VC_UNLOCK(vcp);
	}

	if (created) {
		/*
		 * We have a NEW VC, held, but not locked.
		 */

		SMBIODEBUG("vc_state=%d\n", vcp->vc_state);
		switch (vcp->vc_state) {

		case SMBIOD_ST_NOTCONN:
			(void) smb_vc_setup(vcspec, scred, vcp, 0);
			vcp->vc_genid++;
			/* XXX: Save credentials of caller here? */
			vcp->vc_state = SMBIOD_ST_RECONNECT;
			/* FALLTHROUGH */

		case SMBIOD_ST_RECONNECT:
			error = smb_iod_connect(vcp);
			if (error)
				break;
			vcp->vc_state = SMBIOD_ST_TRANACTIVE;
			/* FALLTHROUGH */

		case SMBIOD_ST_TRANACTIVE:
			/* XXX: Just pass vcspec instead? */
			vcp->vc_intok = vcspec->tok;
			vcp->vc_intoklen = vcspec->toklen;
			error = smb_smb_negotiate(vcp, &vcp->vc_scred);
			vcp->vc_intok = NULL;
			vcp->vc_intoklen = 0;
			if (error)
				break;
			vcp->vc_state = SMBIOD_ST_NEGOACTIVE;
			/* FALLTHROUGH */

		case SMBIOD_ST_NEGOACTIVE:
		case SMBIOD_ST_SSNSETUP:
		case SMBIOD_ST_VCACTIVE:
			/* We can (re)use this VC. */
			error = 0;
			break;

		default:
			error = EINVAL;
			break;
		}

		if (error) {
			/*
			 * Leave the VC in a state that allows the
			 * next open to attempt a new connection.
			 * This call does the cv_broadcast too,
			 * so that's in the else part.
			 */
			smb_iod_disconnect(vcp);
		} else {
			SMB_VC_LOCK(vcp);
			cv_broadcast(&vcp->vc_statechg);
			SMB_VC_UNLOCK(vcp);
		}
	}

out:
	if (error) {
		/*
		 * Undo the hold from lookupvc,
		 * or destroy if from vc_create.
		 */
		smb_vc_rele(vcp);
	} else {
		/* Return it held. */
		*vcpp = vcp;
	}

	return (error);
}


int
smb_sm_ssnsetup(
	struct smb_vcspec *vcspec,
	struct smb_cred *scred,
	struct smb_vc *vcp)
{
	int error;

	/*
	 * We have a VC, held, but not locked.
	 *
	 * Code from smb_iod_ssnsetup,
	 * with lots of rework.
	 */

	SMBIODEBUG("vc_state=%d\n", vcp->vc_state);
	switch (vcp->vc_state) {

	case SMBIOD_ST_NEGOACTIVE:
		/*
		 * This is the state we normally find.
		 * Calling _setup AGAIN to update the
		 * flags, security info, etc.
		 */
		error = smb_vc_setup(vcspec, scred, vcp, 1);
		if (error)
			break;
		vcp->vc_state = SMBIOD_ST_SSNSETUP;
		/* FALLTHROUGH */

	case SMBIOD_ST_SSNSETUP:
		/* XXX: Just pass vcspec instead? */
		vcp->vc_intok = vcspec->tok;
		vcp->vc_intoklen = vcspec->toklen;
		error = smb_smb_ssnsetup(vcp, &vcp->vc_scred);
		vcp->vc_intok = NULL;
		vcp->vc_intoklen = 0;
		if (error)
			break;
		/* OK, start the reader thread... */
		error = smb_iod_create(vcp);
		if (error)
			break;
		vcp->vc_state = SMBIOD_ST_VCACTIVE;
		/* FALLTHROUGH */

	case SMBIOD_ST_VCACTIVE:
		/* We can (re)use this VC. */
		error = 0;
		break;

	default:
		error = EINVAL;
		break;
	}

	SMB_VC_LOCK(vcp);
	cv_broadcast(&vcp->vc_statechg);
	SMB_VC_UNLOCK(vcp);

	return (error);
}

int
smb_sm_tcon(
	struct smb_sharespec *shspec,
	struct smb_cred *scred,
	struct smb_vc *vcp,
	struct smb_share **sspp)
{
	struct smb_share *ssp;
	int error;

	*sspp = ssp = NULL;

	if (vcp->vc_state != SMBIOD_ST_VCACTIVE) {
		/*
		 * The wait for vc_state in smb_sm_negotiate
		 * _should_ get us a VC in the right state.
		 */
		SMBIODEBUG("bad vc_state=%d\n", vcp->vc_state);
		return (ENOTCONN);
	}

	SMB_VC_LOCK(vcp);
	error = smb_vc_lookupshare(vcp, shspec, scred, &ssp);
	if (error) {
		/* The share was not found.  Create? */
		if ((shspec->optflags & SMBVOPT_CREATE) == 0) {
			SMB_VC_UNLOCK(vcp);
			return (error);
		}
		error = smb_share_create(vcp, shspec, scred, &ssp);
		if (error) {
			/* Could not create? Unusual. */
			SMB_VC_UNLOCK(vcp);
			return (error);
		}
		/* Note: co_usecount == 1 */
	}
	SMB_VC_UNLOCK(vcp);

	/*
	 * We have a share, held, but not locked.
	 * Make it connected...
	 */
	SMB_SS_LOCK(ssp);
	if (!smb_share_valid(ssp))
		error = smb_share_tcon(ssp);
	SMB_SS_UNLOCK(ssp);

	if (error) {
		/*
		 * Undo hold from lookupshare,
		 * or destroy if from _create.
		 */
		smb_share_rele(ssp);
	} else {
		/* Return it held. */
		*sspp = ssp;
	}

	return (error);
}

/*
 * Common code for connection object
 */
/*ARGSUSED*/
void
smb_co_init(struct smb_connobj *cp, int level, char *objname)
{

	mutex_init(&cp->co_lock, objname,  MUTEX_DRIVER, NULL);

	cp->co_level = level;
	cp->co_usecount = 1;
	SLIST_INIT(&cp->co_children);
}

/*
 * Called just before free of an object
 * of which smb_connobj is a part, i.e.
 * _vc_free, _share_free, also sm_done.
 */
void
smb_co_done(struct smb_connobj *cp)
{
	ASSERT(SLIST_EMPTY(&cp->co_children));
	mutex_destroy(&cp->co_lock);
}

static void
smb_co_addchild(
	struct smb_connobj *parent,
	struct smb_connobj *child)
{

	/*
	 * Set the child's pointer to the parent.
	 * No references yet, so no need to lock.
	 */
	ASSERT(child->co_usecount == 1);
	child->co_parent = parent;

	/*
	 * Add the child to the parent's list of
	 * children, and in-line smb_co_hold
	 */
	ASSERT(MUTEX_HELD(&parent->co_lock));
	parent->co_usecount++;
	SLIST_INSERT_HEAD(&parent->co_children, child, co_next);
}

void
smb_co_hold(struct smb_connobj *cp)
{
	SMB_CO_LOCK(cp);
	cp->co_usecount++;
	SMB_CO_UNLOCK(cp);
}

/*
 * Called via smb_vc_rele, smb_share_rele
 */
void
smb_co_rele(struct smb_connobj *co)
{
	struct smb_connobj *parent;
	int old_flags;

	SMB_CO_LOCK(co);
	if (co->co_usecount > 1) {
		co->co_usecount--;
		SMB_CO_UNLOCK(co);
		return;
	}
	ASSERT(co->co_usecount == 1);
	co->co_usecount = 0;

	/*
	 * This list of children should be empty now.
	 * Check this while we're still linked, so
	 * we have a better chance of debugging.
	 */
	ASSERT(SLIST_EMPTY(&co->co_children));

	/*
	 * OK, this element is going away.
	 *
	 * We need to drop the lock on this CO so we can take the
	 * parent CO lock. The _GONE flag prevents this CO from
	 * getting new references before we can unlink it from the
	 * parent list.
	 *
	 * The _GONE flag is also used to ensure that the co_gone
	 * function is called only once.  Note that smb_co_kill may
	 * do this before we get here.  If we find that the _GONE
	 * flag was not already set, then call the co_gone hook
	 * (smb_share_gone, smb_vc_gone) which will disconnect
	 * the share or the VC, respectively.
	 *
	 * Note the old: smb_co_gone(co, scred);
	 * is now in-line here.
	 */
	old_flags = co->co_flags;
	co->co_flags |= SMBO_GONE;
	SMB_CO_UNLOCK(co);

	if ((old_flags & SMBO_GONE) == 0 && co->co_gone)
		co->co_gone(co);

	/*
	 * If we have a parent (only smb_vclist does not)
	 * then unlink from parent's list of children.
	 * We have the only reference to the child.
	 */
	parent = co->co_parent;
	if (parent) {
		SMB_CO_LOCK(parent);
		ASSERT(SLIST_FIRST(&parent->co_children));
		if (SLIST_FIRST(&parent->co_children)) {
			SLIST_REMOVE(&parent->co_children, co,
			    smb_connobj, co_next);
		}
		SMB_CO_UNLOCK(parent);
	}

	/*
	 * Now it's safe to free the CO
	 */
	if (co->co_free) {
		co->co_free(co);
	}

	/*
	 * Finally, if the CO had a parent, decrement
	 * the parent's hold count for the lost child.
	 */
	if (parent) {
		/*
		 * Recursive call here (easier for debugging).
		 * Can only go two levels.
		 */
		smb_co_rele(parent);
	}
}

/*
 * Do just the first part of what co_gone does,
 * i.e. tree disconnect, or disconnect a VC.
 * This is used to forcibly close things.
 */
void
smb_co_kill(struct smb_connobj *co)
{
	int old_flags;

	SMB_CO_LOCK(co);
	old_flags = co->co_flags;
	co->co_flags |= SMBO_GONE;
	SMB_CO_UNLOCK(co);

	/*
	 * Do the same "call only once" logic here as in
	 * smb_co_rele, though it's probably not possible
	 * for this to be called after smb_co_rele.
	 */
	if ((old_flags & SMBO_GONE) == 0 && co->co_gone)
		co->co_gone(co);

	/* XXX: Walk list of children and kill those too? */
}


/*
 * Session implementation
 */

/*
 * This sets the fields that are allowed to change
 * when doing a reconnect.  Many others are set in
 * smb_vc_create and never change afterwards.
 * Don't want domain or user to change here.
 */
int
smb_vc_setup(struct smb_vcspec *vcspec, struct smb_cred *scred,
	struct smb_vc *vcp, int is_ss)
{
	int error, minauth;

	/* Just save all the SMBVOPT_ options. */
	vcp->vc_vopt = vcspec->optflags;

	/* Cleared if nego response shows antique server! */
	vcp->vc_hflags2 |= SMB_FLAGS2_KNOWS_LONG_NAMES;

	/* XXX: Odd place for this. */
	if (vcspec->optflags & SMBVOPT_EXT_SEC)
		vcp->vc_hflags2 |= SMB_FLAGS2_EXT_SEC;

	if (is_ss) {
		/* Called from smb_sm_ssnsetup */

		if (vcspec->optflags & SMBVOPT_USE_KEYCHAIN) {
			/*
			 * Get p/w hashes from the keychain.
			 * The password in vcspec->pass is
			 * fiction, so don't store it.
			 */
			error = smb_pkey_getpwh(vcp, scred->vc_ucred);
			return (error);
		}

		/*
		 * Note: this can be called more than once
		 * for a given vcp, so free the old strings.
		 */
		SMB_STRFREE(vcp->vc_pass);

		/*
		 * Don't store the cleartext password
		 * unless the minauth value was changed
		 * to allow use of cleartext passwords.
		 * (By default, this is not allowed.)
		 */
		minauth = vcspec->optflags & SMBVOPT_MINAUTH;
		if (minauth == SMBVOPT_MINAUTH_NONE)
			vcp->vc_pass = smb_strdup(vcspec->pass);

		/* Compute LM and NTLM hashes. */
		smb_oldlm_hash(vcspec->pass, vcp->vc_lmhash);
		smb_ntlmv1hash(vcspec->pass, vcp->vc_nthash);
	}

	/* Success! */
	error = 0;
	return (error);
}

/*ARGSUSED*/
int
smb_vc_create(struct smb_vcspec *vcspec,
	struct smb_cred *scred, struct smb_vc **vcpp)
{
	static char objtype[] = "smb_vc";
	struct smb_vc *vcp;
	int error = 0;

	ASSERT(MUTEX_HELD(&smb_vclist.co_lock));

	/*
	 * Checks for valid uid/gid are now in
	 * smb_usr_ioc2vcspec, so at this point
	 * we know the user has right to create
	 * with the uid/gid in the vcspec.
	 */

	vcp = kmem_zalloc(sizeof (struct smb_vc), KM_SLEEP);

	smb_co_init(VCTOCP(vcp), SMBL_VC, objtype);
	vcp->vc_co.co_free = smb_vc_free;
	vcp->vc_co.co_gone = smb_vc_gone;

	cv_init(&vcp->vc_statechg, objtype, CV_DRIVER, NULL);
	sema_init(&vcp->vc_sendlock, 1, objtype, SEMA_DRIVER, NULL);
	rw_init(&vcp->iod_rqlock, objtype, RW_DRIVER, NULL);
	cv_init(&vcp->iod_exit, objtype, CV_DRIVER, NULL);

	vcp->vc_number = atomic_inc_uint_nv(&smb_vcnext);
	vcp->vc_state = SMBIOD_ST_NOTCONN;
	vcp->vc_timo = SMB_DEFRQTIMO;
	/*
	 * I think SMB_UID_UNKNOWN is not the correct
	 * initial value for vc_smbuid. See the long
	 * comment in smb_iod_sendrq()
	 */
	vcp->vc_smbuid = SMB_UID_UNKNOWN; /* XXX should be zero */
	vcp->vc_tdesc = &smb_tran_nbtcp_desc;

	/*
	 * These identify the connection.
	 */
	vcp->vc_zoneid = getzoneid();
	vcp->vc_uid = vcspec->owner;
	vcp->vc_grp = vcspec->group;
	vcp->vc_mode = vcspec->rights & SMBM_MASK;

	vcp->vc_domain = smb_strdup(vcspec->domain);
	vcp->vc_username = smb_strdup(vcspec->username);
	vcp->vc_srvname = smb_strdup(vcspec->srvname);
	vcp->vc_paddr = smb_dup_sockaddr(vcspec->sap);
	vcp->vc_laddr = smb_dup_sockaddr(vcspec->lap);

#ifdef NOICONVSUPPORT
	/*
	 * REVISIT
	 */
	error = iconv_open("tolower", vcspec->localcs, &vcp->vc_tolower);
	if (error)
		goto errout;

	error = iconv_open("toupper", vcspec->localcs, &vcp->vc_toupper);
	if (error)
		goto errout;

	if (vcspec->servercs[0]) {

		error = iconv_open(vcspec->servercs, vcspec->localcs,
		    &vcp->vc_toserver);
		if (error)
			goto errout;

		error = iconv_open(vcspec->localcs, vcspec->servercs,
		    &vcp->vc_tolocal);
		if (error)
			goto errout;
	}
#endif /* NOICONVSUPPORT */

	/* This fills in vcp->vc_tdata */
	if ((error = SMB_TRAN_CREATE(vcp, curproc)) != 0)
		goto errout;

	/* Success! */
	smb_co_addchild(&smb_vclist, VCTOCP(vcp));
	*vcpp = vcp;
	return (0);

errout:
	/*
	 * This will destroy the new vc.
	 * See: smb_vc_free
	 */
	smb_vc_rele(vcp);
	return (error);
}

void
smb_vc_hold(struct smb_vc *vcp)
{
	smb_co_hold(VCTOCP(vcp));
}

void
smb_vc_rele(struct smb_vc *vcp)
{
	smb_co_rele(VCTOCP(vcp));
}

void
smb_vc_kill(struct smb_vc *vcp)
{
	smb_co_kill(VCTOCP(vcp));
}

/*
 * Normally called via smb_vc_rele()
 * after co_usecount drops to zero.
 * Also called via: smb_vc_kill()
 *
 * Shutdown the VC to this server,
 * invalidate shares linked with it.
 */
/*ARGSUSED*/
static void
smb_vc_gone(struct smb_connobj *cp)
{
	struct smb_vc *vcp = CPTOVC(cp);

	/*
	 * Was smb_vc_disconnect(vcp);
	 */
	smb_iod_disconnect(vcp);

	/* Note: smb_iod_destroy in vc_free */
}

static void
smb_vc_free(struct smb_connobj *cp)
{
	struct smb_vc *vcp = CPTOVC(cp);

	/*
	 * The VC has no more references, so
	 * no locks should be needed here.
	 * Make sure the IOD is gone.
	 */
	smb_iod_destroy(vcp);

	if (vcp->vc_tdata)
		SMB_TRAN_DONE(vcp, curproc);

	SMB_STRFREE(vcp->vc_username);
	SMB_STRFREE(vcp->vc_srvname);
	SMB_STRFREE(vcp->vc_pass);
	SMB_STRFREE(vcp->vc_domain);
	if (vcp->vc_paddr) {
		smb_free_sockaddr(vcp->vc_paddr);
		vcp->vc_paddr = NULL;
	}
	if (vcp->vc_laddr) {
		smb_free_sockaddr(vcp->vc_laddr);
		vcp->vc_laddr = NULL;
	}

/*
 * We are not using the iconv routines here. So commenting them for now.
 * REVISIT.
 */
#ifdef NOTYETDEFINED
	if (vcp->vc_tolower)
		iconv_close(vcp->vc_tolower);
	if (vcp->vc_toupper)
		iconv_close(vcp->vc_toupper);
	if (vcp->vc_tolocal)
		iconv_close(vcp->vc_tolocal);
	if (vcp->vc_toserver)
		iconv_close(vcp->vc_toserver);
#endif
	if (vcp->vc_intok)
		kmem_free(vcp->vc_intok, vcp->vc_intoklen);
	if (vcp->vc_outtok)
		kmem_free(vcp->vc_outtok, vcp->vc_outtoklen);
	if (vcp->vc_negtok)
		kmem_free(vcp->vc_negtok, vcp->vc_negtoklen);

	cv_destroy(&vcp->iod_exit);
	rw_destroy(&vcp->iod_rqlock);
	sema_destroy(&vcp->vc_sendlock);
	cv_destroy(&vcp->vc_statechg);
	smb_co_done(VCTOCP(vcp));
	kmem_free(vcp, sizeof (*vcp));
}


/*
 * Lookup share in the given VC. Share referenced and locked on return.
 * VC expected to be locked on entry and will be left locked on exit.
 */
/*ARGSUSED*/
int
smb_vc_lookupshare(struct smb_vc *vcp, struct smb_sharespec *shspec,
	struct smb_cred *scred,	struct smb_share **sspp)
{
	struct smb_connobj *co;
	struct smb_share *ssp = NULL;

	ASSERT(MUTEX_HELD(&vcp->vc_lock));

	*sspp = NULL;

	/* var, head, next_field */
	SLIST_FOREACH(co, &(VCTOCP(vcp)->co_children), co_next) {
		ssp = CPTOSS(co);

		/* No new refs if _GONE is set. */
		if (ssp->ss_flags & SMBS_GONE)
			continue;

		/* This has a hold, so no need to lock it. */
		if (strcmp(ssp->ss_name, shspec->name) == 0)
			goto found;
	}
	return (ENOENT);

found:
	/* Return it with a hold. */
	smb_share_hold(ssp);
	*sspp = ssp;
	return (0);
}


static char smb_emptypass[] = "";

const char *
smb_vc_getpass(struct smb_vc *vcp)
{
	if (vcp->vc_pass)
		return (vcp->vc_pass);
	return (smb_emptypass);
}

uint16_t
smb_vc_nextmid(struct smb_vc *vcp)
{
	uint16_t r;

	r = atomic_inc_16_nv(&vcp->vc_mid);
	return (r);
}

/*
 * Get a pointer to the IP address suitable for passing to Trusted
 * Extensions find_tpc() routine.  Used by smbfs_mount_label_policy().
 * Compare this code to nfs_mount_label_policy() if problems arise.
 * Without support for direct CIFS-over-TCP, we should always see
 * an AF_NETBIOS sockaddr here.
 */
void *
smb_vc_getipaddr(struct smb_vc *vcp, int *ipvers)
{
	switch (vcp->vc_paddr->sa_family) {
	case AF_NETBIOS: {
		struct sockaddr_nb *snb;

		*ipvers = IPV4_VERSION;
		/*LINTED*/
		snb = (struct sockaddr_nb *)vcp->vc_paddr;
		return ((void *)&snb->snb_ipaddr);
	}
	case AF_INET: {
		struct sockaddr_in *sin;

		*ipvers = IPV4_VERSION;
		/*LINTED*/
		sin = (struct sockaddr_in *)vcp->vc_paddr;
		return ((void *)&sin->sin_addr);
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6;

		*ipvers = IPV6_VERSION;
		/*LINTED*/
		sin6 = (struct sockaddr_in6 *)vcp->vc_paddr;
		return ((void *)&sin6->sin6_addr);
	}
	default:
		SMBSDEBUG("invalid address family %d\n",
		    vcp->vc_paddr->sa_family);
		*ipvers = 0;
		return (NULL);
	}
}

/*
 * Share implementation
 */
/*
 * Allocate share structure and attach it to the given VC
 * Connection expected to be locked on entry. Share will be returned
 * in locked state.
 */
/*ARGSUSED*/
int
smb_share_create(struct smb_vc *vcp, struct smb_sharespec *shspec,
	struct smb_cred *scred, struct smb_share **sspp)
{
	static char objtype[] = "smb_ss";
	struct smb_share *ssp;

	ASSERT(MUTEX_HELD(&vcp->vc_lock));

	ssp = kmem_zalloc(sizeof (struct smb_share), KM_SLEEP);
	smb_co_init(SSTOCP(ssp), SMBL_SHARE, objtype);
	ssp->ss_co.co_free = smb_share_free;
	ssp->ss_co.co_gone = smb_share_gone;

	ssp->ss_name = smb_strdup(shspec->name);
	ssp->ss_mount = NULL;
	if (shspec->pass && shspec->pass[0])
		ssp->ss_pass = smb_strdup(shspec->pass);
	ssp->ss_type = shspec->stype;
	ssp->ss_tid = SMB_TID_UNKNOWN;
	ssp->ss_mode = shspec->rights & SMBM_MASK;
	ssp->ss_fsname = NULL;
	smb_co_addchild(VCTOCP(vcp), SSTOCP(ssp));
	*sspp = ssp;

	return (0);
}

/*
 * Normally called via smb_share_rele()
 * after co_usecount drops to zero.
 */
static void
smb_share_free(struct smb_connobj *cp)
{
	struct smb_share *ssp = CPTOSS(cp);

	SMB_STRFREE(ssp->ss_name);
	SMB_STRFREE(ssp->ss_pass);
	SMB_STRFREE(ssp->ss_fsname);
	smb_co_done(SSTOCP(ssp));
	kmem_free(ssp, sizeof (*ssp));
}

/*
 * Normally called via smb_share_rele()
 * after co_usecount drops to zero.
 * Also called via: smb_share_kill()
 */
static void
smb_share_gone(struct smb_connobj *cp)
{
	struct smb_cred scred;
	struct smb_share *ssp = CPTOSS(cp);

	smb_credinit(&scred, curproc, NULL);
	smb_iod_shutdown_share(ssp);
	smb_smb_treedisconnect(ssp, &scred);
	smb_credrele(&scred);
}

void
smb_share_hold(struct smb_share *ssp)
{
	smb_co_hold(SSTOCP(ssp));
}

void
smb_share_rele(struct smb_share *ssp)
{
	smb_co_rele(SSTOCP(ssp));
}

void
smb_share_kill(struct smb_share *ssp)
{
	smb_co_kill(SSTOCP(ssp));
}


void
smb_share_invalidate(struct smb_share *ssp)
{
	ssp->ss_tid = SMB_TID_UNKNOWN;
}

/*
 * Returns NON-zero if the share is valid.
 * Called with the share locked.
 */
int
smb_share_valid(struct smb_share *ssp)
{
	struct smb_vc *vcp = SSTOVC(ssp);

	ASSERT(MUTEX_HELD(&ssp->ss_lock));

	if ((ssp->ss_flags & SMBS_CONNECTED) == 0)
		return (0);

	if (ssp->ss_tid == SMB_TID_UNKNOWN) {
		SMBIODEBUG("found TID unknown\n");
		ssp->ss_flags &= ~SMBS_CONNECTED;
	}

	if (ssp->ss_vcgenid != vcp->vc_genid) {
		SMBIODEBUG("wrong genid\n");
		ssp->ss_flags &= ~SMBS_CONNECTED;
	}

	return (ssp->ss_flags & SMBS_CONNECTED);
}

/*
 * Connect (or reconnect) a share object.
 * Called with the share locked.
 */
int
smb_share_tcon(struct smb_share *ssp)
{
	struct smb_vc *vcp = SSTOVC(ssp);
	clock_t tmo;
	int error;

	ASSERT(MUTEX_HELD(&ssp->ss_lock));

	if (ssp->ss_flags & SMBS_CONNECTED) {
		SMBIODEBUG("alread connected?");
		return (0);
	}

	/*
	 * Wait for completion of any state changes
	 * that might be underway.
	 */
	while (ssp->ss_flags & SMBS_RECONNECTING) {
		ssp->ss_conn_waiters++;
		tmo = cv_wait_sig(&ssp->ss_conn_done, &ssp->ss_lock);
		ssp->ss_conn_waiters--;
		if (tmo == 0) {
			/* Interrupt! */
			return (EINTR);
		}
	}

	/* Did someone else do it for us? */
	if (ssp->ss_flags & SMBS_CONNECTED)
		return (0);

	/*
	 * OK, we'll do the work.
	 */
	ssp->ss_flags |= SMBS_RECONNECTING;

	/* Drop the lock while doing the call. */
	SMB_SS_UNLOCK(ssp);
	error = smb_smb_treeconnect(ssp, &vcp->vc_scred);
	SMB_SS_LOCK(ssp);

	if (!error)
		ssp->ss_flags |= SMBS_CONNECTED;
	ssp->ss_flags &= ~SMBS_RECONNECTING;

	/* They can all go ahead! */
	if (ssp->ss_conn_waiters)
		cv_broadcast(&ssp->ss_conn_done);

	return (error);
}

const char *
smb_share_getpass(struct smb_share *ssp)
{
	struct smb_vc *vcp;

	if (ssp->ss_pass)
		return (ssp->ss_pass);
	vcp = SSTOVC(ssp);
	if (vcp->vc_pass)
		return (vcp->vc_pass);
	return (smb_emptypass);
}

int
smb_share_count(void)
{
	struct smb_connobj *covc, *coss;
	struct smb_vc *vcp;
	zoneid_t zoneid = getzoneid();
	int nshares = 0;

	SMB_CO_LOCK(&smb_vclist);
	SLIST_FOREACH(covc, &smb_vclist.co_children, co_next) {
		vcp = CPTOVC(covc);

		/* VCs in other zones are invisibile. */
		if (vcp->vc_zoneid != zoneid)
			continue;

		SMB_VC_LOCK(vcp);

		/* var, head, next_field */
		SLIST_FOREACH(coss, &(VCTOCP(vcp)->co_children), co_next) {
			nshares++;
		}

		SMB_VC_UNLOCK(vcp);
	}
	SMB_CO_UNLOCK(&smb_vclist);

	return (nshares);
}

/*
 * Solaris zones support
 */
/*ARGSUSED*/
void
lingering_vc(struct smb_vc *vc)
{
	/* good place for a breakpoint */
	DEBUG_ENTER("lingering VC");
}

/*
 * On zone shutdown, kill any IOD threads still running in this zone.
 */
/* ARGSUSED */
void
nsmb_zone_shutdown(zoneid_t zoneid, void *data)
{
	struct smb_connobj *co;
	struct smb_vc *vcp;

	SMB_CO_LOCK(&smb_vclist);
	SLIST_FOREACH(co, &smb_vclist.co_children, co_next) {
		vcp = CPTOVC(co);

		if (vcp->vc_zoneid != zoneid)
			continue;

		/*
		 * This will close the connection, and
		 * cause the IOD thread to terminate.
		 */
		smb_vc_kill(vcp);
	}
	SMB_CO_UNLOCK(&smb_vclist);
}

/*
 * On zone destroy, kill any IOD threads and free all resources they used.
 */
/* ARGSUSED */
void
nsmb_zone_destroy(zoneid_t zoneid, void *data)
{
	struct smb_connobj *co;
	struct smb_vc *vcp;

	/*
	 * We will repeat what should have already happened
	 * in zone_shutdown to make things go away.
	 *
	 * There should have been an smb_vc_rele call
	 * by now for all VCs in the zone.  If not,
	 * there's probably more we needed to do in
	 * the shutdown call.
	 */

	SMB_CO_LOCK(&smb_vclist);

	if (smb_vclist.co_usecount > 1) {
		SMBERROR("%d connections still active\n",
		    smb_vclist.co_usecount - 1);
	}

	/* var, head, next_field */
	SLIST_FOREACH(co, &smb_vclist.co_children, co_next) {
		vcp = CPTOVC(co);

		if (vcp->vc_zoneid != zoneid)
			continue;

		/* Debugging */
		lingering_vc(vcp);
	}

	SMB_CO_UNLOCK(&smb_vclist);
}
