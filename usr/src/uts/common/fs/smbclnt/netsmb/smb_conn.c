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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
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
#include <netinet/in.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/cmn_err.h>
#include <sys/thread.h>
#include <sys/atomic.h>
#include <sys/u8_textprep.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_tran.h>
#include <netsmb/smb_pass.h>

static struct smb_connobj smb_vclist;

void smb_co_init(struct smb_connobj *cp, int level, char *objname);
void smb_co_done(struct smb_connobj *cp);
void smb_co_hold(struct smb_connobj *cp);
void smb_co_rele(struct smb_connobj *cp);
void smb_co_kill(struct smb_connobj *cp);

static void smb_vc_free(struct smb_connobj *cp);
static void smb_vc_gone(struct smb_connobj *cp);

static void smb_share_free(struct smb_connobj *cp);
static void smb_share_gone(struct smb_connobj *cp);

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
	 * Why are we not iterating on smb_vclist here?
	 * Because the caller has just called smb_sm_idle() to
	 * make sure we have no VCs before calling this.
	 */
	smb_co_done(&smb_vclist);
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
 * Session objects, which are referred to as "VC" for
 * "virtual cirtuit". This has nothing to do with the
 * CIFS notion of a "virtual cirtuit".  See smb_conn.h
 */

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
}

/*
 * The VC has no more references.  Free it.
 * No locks needed here.
 */
static void
smb_vc_free(struct smb_connobj *cp)
{
	struct smb_vc *vcp = CPTOVC(cp);

	/*
	 * The _gone call should have emptied the request list,
	 * but let's make sure, as requests may have references
	 * to this VC without taking a hold.  (The hold is the
	 * responsibility of threads placing requests.)
	 */
	ASSERT(vcp->iod_rqlist.tqh_first == NULL);

	if (vcp->vc_tdata)
		SMB_TRAN_DONE(vcp);

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

	if (vcp->vc_mackey != NULL)
		kmem_free(vcp->vc_mackey, vcp->vc_mackeylen);
	if (vcp->vc_ssnkey != NULL)
		kmem_free(vcp->vc_ssnkey, vcp->vc_ssnkeylen);

	cv_destroy(&vcp->iod_idle);
	rw_destroy(&vcp->iod_rqlock);
	sema_destroy(&vcp->vc_sendlock);
	cv_destroy(&vcp->vc_statechg);
	smb_co_done(VCTOCP(vcp));
	kmem_free(vcp, sizeof (*vcp));
}

/*ARGSUSED*/
int
smb_vc_create(smbioc_ossn_t *ossn, smb_cred_t *scred, smb_vc_t **vcpp)
{
	static char objtype[] = "smb_vc";
	cred_t *cr = scred->scr_cred;
	struct smb_vc *vcp;
	int error = 0;

	ASSERT(MUTEX_HELD(&smb_vclist.co_lock));

	vcp = kmem_zalloc(sizeof (struct smb_vc), KM_SLEEP);

	smb_co_init(VCTOCP(vcp), SMBL_VC, objtype);
	vcp->vc_co.co_free = smb_vc_free;
	vcp->vc_co.co_gone = smb_vc_gone;

	cv_init(&vcp->vc_statechg, objtype, CV_DRIVER, NULL);
	sema_init(&vcp->vc_sendlock, 1, objtype, SEMA_DRIVER, NULL);
	rw_init(&vcp->iod_rqlock, objtype, RW_DRIVER, NULL);
	cv_init(&vcp->iod_idle, objtype, CV_DRIVER, NULL);

	/* Expanded TAILQ_HEAD_INITIALIZER */
	vcp->iod_rqlist.tqh_last = &vcp->iod_rqlist.tqh_first;

	/* A brand new VC should connect. */
	vcp->vc_state = SMBIOD_ST_RECONNECT;

	/*
	 * These identify the connection.
	 */
	vcp->vc_zoneid = getzoneid();
	bcopy(ossn, &vcp->vc_ssn, sizeof (*ossn));

	/* This fills in vcp->vc_tdata */
	vcp->vc_tdesc = &smb_tran_nbtcp_desc;
	if ((error = SMB_TRAN_CREATE(vcp, cr)) != 0)
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

/*
 * Find or create a VC identified by the info in ossn
 * and return it with a "hold", but not locked.
 */
/*ARGSUSED*/
int
smb_vc_findcreate(smbioc_ossn_t *ossn, smb_cred_t *scred, smb_vc_t **vcpp)
{
	struct smb_connobj *co;
	struct smb_vc *vcp;
	smbioc_ssn_ident_t *vc_id;
	int error;
	zoneid_t zoneid = getzoneid();

	*vcpp = vcp = NULL;

	SMB_CO_LOCK(&smb_vclist);

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

		/* Also segregate by Unix owner. */
		if (vcp->vc_owner != ossn->ssn_owner)
			continue;

		/*
		 * Compare identifying info:
		 * server address, user, domain
		 * names are case-insensitive
		 */
		vc_id = &vcp->vc_ssn.ssn_id;
		if (bcmp(&vc_id->id_srvaddr,
		    &ossn->ssn_id.id_srvaddr,
		    sizeof (vc_id->id_srvaddr)))
			continue;
		if (u8_strcmp(vc_id->id_user, ossn->ssn_id.id_user, 0,
		    U8_STRCMP_CI_LOWER, U8_UNICODE_LATEST, &error))
			continue;
		if (u8_strcmp(vc_id->id_domain, ossn->ssn_id.id_domain, 0,
		    U8_STRCMP_CI_LOWER, U8_UNICODE_LATEST, &error))
			continue;

		/*
		 * We have a match, but still have to check
		 * the _GONE flag, and do that with a lock.
		 * No new references when _GONE is set.
		 *
		 * Also clear SMBVOPT_CREATE which the caller
		 * may check to find out if we did create.
		 */
		SMB_VC_LOCK(vcp);
		if ((vcp->vc_flags & SMBV_GONE) == 0) {
			ossn->ssn_vopt &= ~SMBVOPT_CREATE;
			/*
			 * Return it held, unlocked.
			 * In-line smb_vc_hold here.
			 */
			co->co_usecount++;
			SMB_VC_UNLOCK(vcp);
			*vcpp = vcp;
			error = 0;
			goto out;
		}
		SMB_VC_UNLOCK(vcp);
		/* keep looking. */
	}
	vcp = NULL;

	/* Note: smb_vclist is still locked. */

	if (ossn->ssn_vopt & SMBVOPT_CREATE) {
		/*
		 * Create a new VC.  It starts out with
		 * hold count = 1, so don't incr. here.
		 */
		error = smb_vc_create(ossn, scred, &vcp);
		if (error == 0)
			*vcpp = vcp;
	} else
		error = ENOENT;

out:
	SMB_CO_UNLOCK(&smb_vclist);
	return (error);
}


/*
 * Helper functions that operate on VCs
 */

/*
 * Get a pointer to the IP address suitable for passing to Trusted
 * Extensions find_tpc() routine.  Used by smbfs_mount_label_policy().
 * Compare this code to nfs_mount_label_policy() if problems arise.
 */
void *
smb_vc_getipaddr(struct smb_vc *vcp, int *ipvers)
{
	smbioc_ssn_ident_t *id = &vcp->vc_ssn.ssn_id;
	void *ret;

	switch (id->id_srvaddr.sa.sa_family) {
	case AF_INET:
		*ipvers = IPV4_VERSION;
		ret = &id->id_srvaddr.sin.sin_addr;
		break;

	case AF_INET6:
		*ipvers = IPV6_VERSION;
		ret = &id->id_srvaddr.sin6.sin6_addr;
		break;
	default:
		SMBSDEBUG("invalid address family %d\n",
		    id->id_srvaddr.sa.sa_family);
		*ipvers = 0;
		ret = NULL;
		break;
	}
	return (ret);
}

void
smb_vc_walkshares(struct smb_vc *vcp,
	walk_share_func_t func)
{
	smb_connobj_t *co;
	smb_share_t *ssp;

	/*
	 * Walk the share list calling func(ssp, arg)
	 */
	SMB_VC_LOCK(vcp);
	SLIST_FOREACH(co, &(VCTOCP(vcp)->co_children), co_next) {
		ssp = CPTOSS(co);
		SMB_SS_LOCK(ssp);
		func(ssp);
		SMB_SS_UNLOCK(ssp);
	}
	SMB_VC_UNLOCK(vcp);
}


/*
 * Share implementation
 */

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

	smb_credinit(&scred, NULL);
	smb_iod_shutdown_share(ssp);
	(void) smb_smb_treedisconnect(ssp, &scred);
	smb_credrele(&scred);
}

/*
 * Normally called via smb_share_rele()
 * after co_usecount drops to zero.
 */
static void
smb_share_free(struct smb_connobj *cp)
{
	struct smb_share *ssp = CPTOSS(cp);

	cv_destroy(&ssp->ss_conn_done);
	smb_co_done(SSTOCP(ssp));
	kmem_free(ssp, sizeof (*ssp));
}

/*
 * Allocate share structure and attach it to the given VC
 * Connection expected to be locked on entry. Share will be returned
 * in locked state.
 */
/*ARGSUSED*/
int
smb_share_create(smbioc_tcon_t *tcon, struct smb_vc *vcp,
	struct smb_share **sspp, struct smb_cred *scred)
{
	static char objtype[] = "smb_ss";
	struct smb_share *ssp;

	ASSERT(MUTEX_HELD(&vcp->vc_lock));

	ssp = kmem_zalloc(sizeof (struct smb_share), KM_SLEEP);
	smb_co_init(SSTOCP(ssp), SMBL_SHARE, objtype);
	ssp->ss_co.co_free = smb_share_free;
	ssp->ss_co.co_gone = smb_share_gone;

	cv_init(&ssp->ss_conn_done, objtype, CV_DRIVER, NULL);
	ssp->ss_tid = SMB_TID_UNKNOWN;

	bcopy(&tcon->tc_sh, &ssp->ss_ioc,
	    sizeof (smbioc_oshare_t));

	smb_co_addchild(VCTOCP(vcp), SSTOCP(ssp));
	*sspp = ssp;

	return (0);
}

/*
 * Find or create a share under the given VC
 * and return it with a "hold", but not locked.
 */

int
smb_share_findcreate(smbioc_tcon_t *tcon, struct smb_vc *vcp,
	struct smb_share **sspp, struct smb_cred *scred)
{
	struct smb_connobj *co;
	struct smb_share *ssp = NULL;
	int error = 0;

	*sspp = NULL;

	SMB_VC_LOCK(vcp);

	/* var, head, next_field */
	SLIST_FOREACH(co, &(VCTOCP(vcp)->co_children), co_next) {
		ssp = CPTOSS(co);

		/* Share name */
		if (u8_strcmp(ssp->ss_name, tcon->tc_sh.sh_name, 0,
		    U8_STRCMP_CI_LOWER, U8_UNICODE_LATEST, &error))
			continue;

		/*
		 * We have a match, but still have to check
		 * the _GONE flag, and do that with a lock.
		 * No new references when _GONE is set.
		 *
		 * Also clear SMBSOPT_CREATE which the caller
		 * may check to find out if we did create.
		 */
		SMB_SS_LOCK(ssp);
		if ((ssp->ss_flags & SMBS_GONE) == 0) {
			tcon->tc_opt &= ~SMBSOPT_CREATE;
			/*
			 * Return it held, unlocked.
			 * In-line smb_share_hold here.
			 */
			co->co_usecount++;
			SMB_SS_UNLOCK(ssp);
			*sspp = ssp;
			error = 0;
			goto out;
		}
		SMB_SS_UNLOCK(ssp);
		/* keep looking. */
	}
	ssp = NULL;

	/* Note: vcp (list of shares) is still locked. */

	if (tcon->tc_opt & SMBSOPT_CREATE) {
		/*
		 * Create a new share.  It starts out with
		 * hold count = 1, so don't incr. here.
		 */
		error = smb_share_create(tcon, vcp, &ssp, scred);
		if (error == 0)
			*sspp = ssp;
	} else
		error = ENOENT;

out:
	SMB_VC_UNLOCK(vcp);
	return (error);
}


/*
 * Helper functions that operate on shares
 */

/*
 * Mark this share as invalid, so consumers will know
 * their file handles have become invalid.
 *
 * Most share consumers store a copy of ss_vcgenid when
 * opening a file handle and compare that with what's in
 * the share before using a file handle.  If the genid
 * doesn't match, the file handle has become "stale"
 * due to disconnect.  Therefore, zap ss_vcgenid here.
 */
void
smb_share_invalidate(struct smb_share *ssp)
{

	ASSERT(MUTEX_HELD(&ssp->ss_lock));

	ssp->ss_flags &= ~SMBS_CONNECTED;
	ssp->ss_tid = SMB_TID_UNKNOWN;
	ssp->ss_vcgenid = 0;
}

/*
 * Connect (or reconnect) a share object.
 *
 * Called by smb_usr_get_tree() for new connections,
 * and called by smb_rq_enqueue() for reconnect.
 */
int
smb_share_tcon(smb_share_t *ssp, smb_cred_t *scred)
{
	clock_t tmo;
	int error;

	SMB_SS_LOCK(ssp);

	if (ssp->ss_flags & SMBS_CONNECTED) {
		SMBIODEBUG("alread connected?");
		error = 0;
		goto out;
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
			error = EINTR;
			goto out;
		}
	}

	/* Did someone else do it for us? */
	if (ssp->ss_flags & SMBS_CONNECTED) {
		error = 0;
		goto out;
	}

	/*
	 * OK, we'll do the work.
	 */
	ssp->ss_flags |= SMBS_RECONNECTING;

	/*
	 * Drop the lock while doing the TCON.
	 * On success, sets ss_tid, ss_vcgenid,
	 * and ss_flags |= SMBS_CONNECTED;
	 */
	SMB_SS_UNLOCK(ssp);
	error = smb_smb_treeconnect(ssp, scred);
	SMB_SS_LOCK(ssp);

	ssp->ss_flags &= ~SMBS_RECONNECTING;

	/* They can all go ahead! */
	if (ssp->ss_conn_waiters)
		cv_broadcast(&ssp->ss_conn_done);

out:
	SMB_SS_UNLOCK(ssp);

	return (error);
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
