/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cred_impl.h>
#include <sys/policy.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/debug.h>
#include <sys/atomic.h>
#include <sys/ucred.h>
#include <sys/prsystm.h>
#include <sys/modctl.h>
#include <sys/avl.h>
#include <sys/door.h>
#include <c2/audit.h>
#include <sys/zone.h>
#include <sys/tsol/label.h>
#include <sys/sid.h>
#include <sys/idmap.h>
#include <sys/varargs.h>


/* Ephemeral IDs Zones specific data */
typedef struct ephemeral_zsd {
	uid_t		min_uid;
	uid_t		last_uid;
	gid_t		min_gid;
	gid_t		last_gid;
	kmutex_t	eph_lock;
	cred_t		*eph_nobody;
} ephemeral_zsd_t;


static kmutex_t		ephemeral_zone_mutex;
static zone_key_t	ephemeral_zone_key;

static struct kmem_cache *cred_cache;
static size_t		crsize = 0;
static int		audoff = 0;
uint32_t		ucredsize;
cred_t			*kcred;
static cred_t		*dummycr;

int rstlink;		/* link(2) restricted to files owned by user? */

static int get_c2audit_load(void);

#define	CR_AUINFO(c)	(auditinfo_addr_t *)((audoff == 0) ? NULL : \
			    ((char *)(c)) + audoff)

#define	REMOTE_PEER_CRED(c)	((c)->cr_gid == -1)


static boolean_t hasephids = B_FALSE;

static ephemeral_zsd_t *
get_ephemeral_zsd(zone_t *zone)
{
	ephemeral_zsd_t *eph_zsd;

	eph_zsd = zone_getspecific(ephemeral_zone_key, zone);
	if (eph_zsd != NULL) {
		return (eph_zsd);
	}

	mutex_enter(&ephemeral_zone_mutex);
	eph_zsd = zone_getspecific(ephemeral_zone_key, zone);
	if (eph_zsd == NULL) {
		eph_zsd = kmem_zalloc(sizeof (ephemeral_zsd_t), KM_SLEEP);
		eph_zsd->min_uid = MAXUID;
		eph_zsd->last_uid = IDMAP_WK__MAX_UID;
		eph_zsd->min_gid = MAXUID;
		eph_zsd->last_gid = IDMAP_WK__MAX_GID;
		mutex_init(&eph_zsd->eph_lock, NULL, MUTEX_DEFAULT, NULL);

		/*
		 * nobody is used to map SID containing CRs.
		 */
		eph_zsd->eph_nobody = crdup(zone->zone_kcred);
		(void) crsetugid(eph_zsd->eph_nobody, UID_NOBODY, GID_NOBODY);
		CR_FLAGS(eph_zsd->eph_nobody) = 0;
		eph_zsd->eph_nobody->cr_zone = zone;

		(void) zone_setspecific(ephemeral_zone_key, zone, eph_zsd);
	}
	mutex_exit(&ephemeral_zone_mutex);
	return (eph_zsd);
}

/*
 * This function is called when a zone is destroyed
 */
static void
/* ARGSUSED */
destroy_ephemeral_zsd(zoneid_t zone_id, void *arg)
{
	ephemeral_zsd_t *eph_zsd = arg;
	if (eph_zsd != NULL) {
		mutex_destroy(&eph_zsd->eph_lock);
		crfree(eph_zsd->eph_nobody);
		kmem_free(eph_zsd, sizeof (ephemeral_zsd_t));
	}
}



/*
 * Initialize credentials data structures.
 */

void
cred_init(void)
{
	priv_init();

	crsize = sizeof (cred_t) + sizeof (gid_t) * (ngroups_max - 1);
	/*
	 * Make sure it's word-aligned.
	 */
	crsize = (crsize + sizeof (int) - 1) & ~(sizeof (int) - 1);

	if (get_c2audit_load() > 0) {
#ifdef _LP64
		/* assure audit context is 64-bit aligned */
		audoff = (crsize +
		    sizeof (int64_t) - 1) & ~(sizeof (int64_t) - 1);
#else	/* _LP64 */
		audoff = crsize;
#endif	/* _LP64 */
		crsize = audoff + sizeof (auditinfo_addr_t);
		crsize = (crsize + sizeof (int) - 1) & ~(sizeof (int) - 1);
	}

	cred_cache = kmem_cache_create("cred_cache", crsize, 0,
	    NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * dummycr is used to copy initial state for creds.
	 */
	dummycr = cralloc();
	bzero(dummycr, crsize);
	dummycr->cr_ref = 1;
	dummycr->cr_uid = (uid_t)-1;
	dummycr->cr_gid = (gid_t)-1;
	dummycr->cr_ruid = (uid_t)-1;
	dummycr->cr_rgid = (gid_t)-1;
	dummycr->cr_suid = (uid_t)-1;
	dummycr->cr_sgid = (gid_t)-1;


	/*
	 * kcred is used by anything that needs all privileges; it's
	 * also the template used for crget as it has all the compatible
	 * sets filled in.
	 */
	kcred = cralloc();

	bzero(kcred, crsize);
	kcred->cr_ref = 1;

	/* kcred is never freed, so we don't need zone_cred_hold here */
	kcred->cr_zone = &zone0;

	priv_fillset(&CR_LPRIV(kcred));
	CR_IPRIV(kcred) = *priv_basic;

	/* Not a basic privilege, if chown is not restricted add it to I0 */
	if (!rstchown)
		priv_addset(&CR_IPRIV(kcred), PRIV_FILE_CHOWN_SELF);

	/* Basic privilege, if link is restricted remove it from I0 */
	if (rstlink)
		priv_delset(&CR_IPRIV(kcred), PRIV_FILE_LINK_ANY);

	CR_EPRIV(kcred) = CR_PPRIV(kcred) = CR_IPRIV(kcred);

	CR_FLAGS(kcred) = NET_MAC_AWARE;

	/*
	 * Set up credentials of p0.
	 */
	ttoproc(curthread)->p_cred = kcred;
	curthread->t_cred = kcred;

	ucredsize = UCRED_SIZE;

	mutex_init(&ephemeral_zone_mutex, NULL, MUTEX_DEFAULT, NULL);
	zone_key_create(&ephemeral_zone_key, NULL, NULL, destroy_ephemeral_zsd);
}

/*
 * Allocate (nearly) uninitialized cred_t.
 */
cred_t *
cralloc(void)
{
	cred_t *cr = kmem_cache_alloc(cred_cache, KM_SLEEP);
	cr->cr_ref = 1;		/* So we can crfree() */
	cr->cr_zone = NULL;
	cr->cr_label = NULL;
	cr->cr_ksid = NULL;
	return (cr);
}

/*
 * As cralloc but prepared for ksid change (if appropriate).
 */
cred_t *
cralloc_ksid(void)
{
	cred_t *cr = cralloc();
	if (hasephids)
		cr->cr_ksid = kcrsid_alloc();
	return (cr);
}

/*
 * Allocate a initialized cred structure and crhold() it.
 * Initialized means: all ids 0, group count 0, L=Full, E=P=I=I0
 */
cred_t *
crget(void)
{
	cred_t *cr = kmem_cache_alloc(cred_cache, KM_SLEEP);

	bcopy(kcred, cr, crsize);
	cr->cr_ref = 1;
	zone_cred_hold(cr->cr_zone);
	if (cr->cr_label)
		label_hold(cr->cr_label);
	return (cr);
}

/*
 * Broadcast the cred to all the threads in the process.
 * The current thread's credentials can be set right away, but other
 * threads must wait until the start of the next system call or trap.
 * This avoids changing the cred in the middle of a system call.
 *
 * The cred has already been held for the process and the thread (2 holds),
 * and p->p_cred set.
 *
 * p->p_crlock shouldn't be held here, since p_lock must be acquired.
 */
void
crset(proc_t *p, cred_t *cr)
{
	kthread_id_t	t;
	kthread_id_t	first;
	cred_t *oldcr;

	ASSERT(p == curproc);	/* assumes p_lwpcnt can't change */

	/*
	 * DTrace accesses t_cred in probe context.  t_cred must always be
	 * either NULL, or point to a valid, allocated cred structure.
	 */
	t = curthread;
	oldcr = t->t_cred;
	t->t_cred = cr;		/* the cred is held by caller for this thread */
	crfree(oldcr);		/* free the old cred for the thread */

	/*
	 * Broadcast to other threads, if any.
	 */
	if (p->p_lwpcnt > 1) {
		mutex_enter(&p->p_lock);	/* to keep thread list safe */
		first = curthread;
		for (t = first->t_forw; t != first; t = t->t_forw)
			t->t_pre_sys = 1; /* so syscall will get new cred */
		mutex_exit(&p->p_lock);
	}
}

/*
 * Put a hold on a cred structure.
 */
void
crhold(cred_t *cr)
{
	atomic_add_32(&cr->cr_ref, 1);
}

/*
 * Release previous hold on a cred structure.  Free it if refcnt == 0.
 * If cred uses label different from zone label, free it.
 */
void
crfree(cred_t *cr)
{
	if (atomic_add_32_nv(&cr->cr_ref, -1) == 0) {
		ASSERT(cr != kcred);
		if (cr->cr_label)
			label_rele(cr->cr_label);
		if (cr->cr_zone)
			zone_cred_rele(cr->cr_zone);
		if (cr->cr_ksid)
			kcrsid_rele(cr->cr_ksid);
		kmem_cache_free(cred_cache, cr);
	}
}

/*
 * Copy a cred structure to a new one and free the old one.
 *	The new cred will have two references.  One for the calling process,
 * 	and one for the thread.
 */
cred_t *
crcopy(cred_t *cr)
{
	cred_t *newcr;

	newcr = cralloc();
	bcopy(cr, newcr, crsize);
	if (newcr->cr_zone)
		zone_cred_hold(newcr->cr_zone);
	if (newcr->cr_label)
		label_hold(cr->cr_label);
	if (newcr->cr_ksid)
		kcrsid_hold(cr->cr_ksid);
	crfree(cr);
	newcr->cr_ref = 2;		/* caller gets two references */
	return (newcr);
}

/*
 * Copy a cred structure to a new one and free the old one.
 *	The new cred will have two references.  One for the calling process,
 * 	and one for the thread.
 * This variation on crcopy uses a pre-allocated structure for the
 * "new" cred.
 */
void
crcopy_to(cred_t *oldcr, cred_t *newcr)
{
	credsid_t *nkcr = newcr->cr_ksid;

	bcopy(oldcr, newcr, crsize);
	if (newcr->cr_zone)
		zone_cred_hold(newcr->cr_zone);
	if (newcr->cr_label)
		label_hold(newcr->cr_label);
	if (nkcr) {
		newcr->cr_ksid = nkcr;
		kcrsidcopy_to(oldcr->cr_ksid, newcr->cr_ksid);
	} else if (newcr->cr_ksid)
		kcrsid_hold(newcr->cr_ksid);
	crfree(oldcr);
	newcr->cr_ref = 2;		/* caller gets two references */
}

/*
 * Dup a cred struct to a new held one.
 *	The old cred is not freed.
 */
cred_t *
crdup(cred_t *cr)
{
	cred_t *newcr;

	newcr = cralloc();
	bcopy(cr, newcr, crsize);
	if (newcr->cr_zone)
		zone_cred_hold(newcr->cr_zone);
	if (newcr->cr_label)
		label_hold(newcr->cr_label);
	if (newcr->cr_ksid)
		kcrsid_hold(newcr->cr_ksid);
	newcr->cr_ref = 1;
	return (newcr);
}

/*
 * Dup a cred struct to a new held one.
 *	The old cred is not freed.
 * This variation on crdup uses a pre-allocated structure for the
 * "new" cred.
 */
void
crdup_to(cred_t *oldcr, cred_t *newcr)
{
	credsid_t *nkcr = newcr->cr_ksid;

	bcopy(oldcr, newcr, crsize);
	if (newcr->cr_zone)
		zone_cred_hold(newcr->cr_zone);
	if (newcr->cr_label)
		label_hold(newcr->cr_label);
	if (nkcr) {
		newcr->cr_ksid = nkcr;
		kcrsidcopy_to(oldcr->cr_ksid, newcr->cr_ksid);
	} else if (newcr->cr_ksid)
		kcrsid_hold(newcr->cr_ksid);
	newcr->cr_ref = 1;
}

/*
 * Return the (held) credentials for the current running process.
 */
cred_t *
crgetcred(void)
{
	cred_t *cr;
	proc_t *p;

	p = ttoproc(curthread);
	mutex_enter(&p->p_crlock);
	crhold(cr = p->p_cred);
	mutex_exit(&p->p_crlock);
	return (cr);
}

/*
 * Backward compatibility check for suser().
 * Accounting flag is now set in the policy functions; auditing is
 * done through use of privilege in the audit trail.
 */
int
suser(cred_t *cr)
{
	return (PRIV_POLICY(cr, PRIV_SYS_SUSER_COMPAT, B_FALSE, EPERM, NULL)
	    == 0);
}

/*
 * Determine whether the supplied group id is a member of the group
 * described by the supplied credentials.
 */
int
groupmember(gid_t gid, const cred_t *cr)
{
	if (gid == cr->cr_gid)
		return (1);
	return (supgroupmember(gid, cr));
}

/*
 * As groupmember but only check against the supplemental groups.
 */
int
supgroupmember(gid_t gid, const cred_t *cr)
{
	const gid_t *gp, *endgp;

	endgp = &cr->cr_groups[cr->cr_ngroups];
	for (gp = cr->cr_groups; gp < endgp; gp++)
		if (*gp == gid)
			return (1);
	return (0);
}

/*
 * This function is called to check whether the credentials set
 * "scrp" has permission to act on credentials set "tcrp".  It enforces the
 * permission requirements needed to send a signal to a process.
 * The same requirements are imposed by other system calls, however.
 *
 * The rules are:
 * (1) if the credentials are the same, the check succeeds
 * (2) if the zone ids don't match, and scrp is not in the global zone or
 *     does not have the PRIV_PROC_ZONE privilege, the check fails
 * (3) if the real or effective user id of scrp matches the real or saved
 *     user id of tcrp or scrp has the PRIV_PROC_OWNER privilege, the check
 *     succeeds
 * (4) otherwise, the check fails
 */
int
hasprocperm(const cred_t *tcrp, const cred_t *scrp)
{
	if (scrp == tcrp)
		return (1);
	if (scrp->cr_zone != tcrp->cr_zone &&
	    (scrp->cr_zone != global_zone ||
	    secpolicy_proc_zone(scrp) != 0))
		return (0);
	if (scrp->cr_uid == tcrp->cr_ruid ||
	    scrp->cr_ruid == tcrp->cr_ruid ||
	    scrp->cr_uid  == tcrp->cr_suid ||
	    scrp->cr_ruid == tcrp->cr_suid ||
	    !PRIV_POLICY(scrp, PRIV_PROC_OWNER, B_FALSE, EPERM, "hasprocperm"))
		return (1);
	return (0);
}

/*
 * This interface replaces hasprocperm; it works like hasprocperm but
 * additionally returns success if the proc_t's match
 * It is the preferred interface for most uses.
 * And it will acquire pcrlock itself, so it assert's that it shouldn't
 * be held.
 */
int
prochasprocperm(proc_t *tp, proc_t *sp, const cred_t *scrp)
{
	int rets;
	cred_t *tcrp;

	ASSERT(MUTEX_NOT_HELD(&tp->p_crlock));

	if (tp == sp)
		return (1);

	if (tp->p_sessp != sp->p_sessp && secpolicy_basic_proc(scrp) != 0)
		return (0);

	mutex_enter(&tp->p_crlock);
	tcrp = tp->p_cred;
	rets = hasprocperm(tcrp, scrp);
	mutex_exit(&tp->p_crlock);

	return (rets);
}

/*
 * This routine is used to compare two credentials to determine if
 * they refer to the same "user".  If the pointers are equal, then
 * they must refer to the same user.  Otherwise, the contents of
 * the credentials are compared to see whether they are equivalent.
 *
 * This routine returns 0 if the credentials refer to the same user,
 * 1 if they do not.
 */
int
crcmp(const cred_t *cr1, const cred_t *cr2)
{

	if (cr1 == cr2)
		return (0);

	if (cr1->cr_uid == cr2->cr_uid &&
	    cr1->cr_gid == cr2->cr_gid &&
	    cr1->cr_ruid == cr2->cr_ruid &&
	    cr1->cr_rgid == cr2->cr_rgid &&
	    cr1->cr_ngroups == cr2->cr_ngroups &&
	    cr1->cr_zone == cr2->cr_zone &&
	    bcmp(cr1->cr_groups, cr2->cr_groups,
	    cr1->cr_ngroups * sizeof (gid_t)) == 0) {
		return (!priv_isequalset(&CR_OEPRIV(cr1), &CR_OEPRIV(cr2)));
	}
	return (1);
}

/*
 * Read access functions to cred_t.
 */
uid_t
crgetuid(const cred_t *cr)
{
	return (cr->cr_uid);
}

uid_t
crgetruid(const cred_t *cr)
{
	return (cr->cr_ruid);
}

uid_t
crgetsuid(const cred_t *cr)
{
	return (cr->cr_suid);
}

gid_t
crgetgid(const cred_t *cr)
{
	return (cr->cr_gid);
}

gid_t
crgetrgid(const cred_t *cr)
{
	return (cr->cr_rgid);
}

gid_t
crgetsgid(const cred_t *cr)
{
	return (cr->cr_sgid);
}

const auditinfo_addr_t *
crgetauinfo(const cred_t *cr)
{
	return ((const auditinfo_addr_t *)CR_AUINFO(cr));
}

auditinfo_addr_t *
crgetauinfo_modifiable(cred_t *cr)
{
	return (CR_AUINFO(cr));
}

zoneid_t
crgetzoneid(const cred_t *cr)
{
	return (cr->cr_zone == NULL ?
	    (cr->cr_uid == -1 ? (zoneid_t)-1 : GLOBAL_ZONEID) :
	    cr->cr_zone->zone_id);
}

projid_t
crgetprojid(const cred_t *cr)
{
	return (cr->cr_projid);
}

zone_t *
crgetzone(const cred_t *cr)
{
	return (cr->cr_zone);
}

struct ts_label_s *
crgetlabel(const cred_t *cr)
{
	return (cr->cr_label ?
	    cr->cr_label :
	    (cr->cr_zone ? cr->cr_zone->zone_slabel : NULL));
}

boolean_t
crisremote(const cred_t *cr)
{
	return (REMOTE_PEER_CRED(cr));
}

#define	BADUID(x, zn)	((x) != -1 && !VALID_UID((x), (zn)))
#define	BADGID(x, zn)	((x) != -1 && !VALID_GID((x), (zn)))

int
crsetresuid(cred_t *cr, uid_t r, uid_t e, uid_t s)
{
	zone_t	*zone = crgetzone(cr);

	ASSERT(cr->cr_ref <= 2);

	if (BADUID(r, zone) || BADUID(e, zone) || BADUID(s, zone))
		return (-1);

	if (r != -1)
		cr->cr_ruid = r;
	if (e != -1)
		cr->cr_uid = e;
	if (s != -1)
		cr->cr_suid = s;

	return (0);
}

int
crsetresgid(cred_t *cr, gid_t r, gid_t e, gid_t s)
{
	zone_t	*zone = crgetzone(cr);

	ASSERT(cr->cr_ref <= 2);

	if (BADGID(r, zone) || BADGID(e, zone) || BADGID(s, zone))
		return (-1);

	if (r != -1)
		cr->cr_rgid = r;
	if (e != -1)
		cr->cr_gid = e;
	if (s != -1)
		cr->cr_sgid = s;

	return (0);
}

int
crsetugid(cred_t *cr, uid_t uid, gid_t gid)
{
	zone_t	*zone = crgetzone(cr);

	ASSERT(cr->cr_ref <= 2);

	if (!VALID_UID(uid, zone) || !VALID_GID(gid, zone))
		return (-1);

	cr->cr_uid = cr->cr_ruid = cr->cr_suid = uid;
	cr->cr_gid = cr->cr_rgid = cr->cr_sgid = gid;

	return (0);
}

int
crsetgroups(cred_t *cr, int n, gid_t *grp)
{
	ASSERT(cr->cr_ref <= 2);

	if (n > ngroups_max || n < 0)
		return (-1);

	cr->cr_ngroups = n;

	if (n > 0)
		bcopy(grp, cr->cr_groups, n * sizeof (gid_t));

	return (0);
}

void
crsetprojid(cred_t *cr, projid_t projid)
{
	ASSERT(projid >= 0 && projid <= MAXPROJID);
	cr->cr_projid = projid;
}

/*
 * This routine returns the pointer to the first element of the cr_groups
 * array.  It can move around in an implementation defined way.
 */
const gid_t *
crgetgroups(const cred_t *cr)
{
	return (cr->cr_groups);
}

int
crgetngroups(const cred_t *cr)
{
	return (cr->cr_ngroups);
}

void
cred2prcred(const cred_t *cr, prcred_t *pcrp)
{
	pcrp->pr_euid = cr->cr_uid;
	pcrp->pr_ruid = cr->cr_ruid;
	pcrp->pr_suid = cr->cr_suid;
	pcrp->pr_egid = cr->cr_gid;
	pcrp->pr_rgid = cr->cr_rgid;
	pcrp->pr_sgid = cr->cr_sgid;
	pcrp->pr_ngroups = MIN(cr->cr_ngroups, (uint_t)ngroups_max);
	pcrp->pr_groups[0] = 0;	/* in case ngroups == 0 */

	if (pcrp->pr_ngroups != 0)
		bcopy(cr->cr_groups, pcrp->pr_groups,
		    sizeof (gid_t) * cr->cr_ngroups);
}

static int
cred2ucaud(const cred_t *cr, auditinfo64_addr_t *ainfo, const cred_t *rcr)
{
	auditinfo_addr_t	*ai;
	au_tid_addr_t	tid;

	if (secpolicy_audit_getattr(rcr) != 0)
		return (-1);

	ai = CR_AUINFO(cr);	/* caller makes sure this is non-NULL */
	tid = ai->ai_termid;

	ainfo->ai_auid = ai->ai_auid;
	ainfo->ai_mask = ai->ai_mask;
	ainfo->ai_asid = ai->ai_asid;

	ainfo->ai_termid.at_type = tid.at_type;
	bcopy(&tid.at_addr, &ainfo->ai_termid.at_addr, 4 * sizeof (uint_t));

	ainfo->ai_termid.at_port.at_major = (uint32_t)getmajor(tid.at_port);
	ainfo->ai_termid.at_port.at_minor = (uint32_t)getminor(tid.at_port);

	return (0);
}

void
cred2uclabel(const cred_t *cr, bslabel_t *labelp)
{
	ts_label_t	*tslp;

	if ((tslp = crgetlabel(cr)) != NULL)
		bcopy(&tslp->tsl_label, labelp, sizeof (bslabel_t));
}

/*
 * Convert a credential into a "ucred".  Allow the caller to specify
 * and aligned buffer, e.g., in an mblk, so we don't have to allocate
 * memory and copy it twice.
 *
 * This function may call cred2ucaud(), which calls CRED(). Since this
 * can be called from an interrupt thread, receiver's cred (rcr) is needed
 * to determine whether audit info should be included.
 */
struct ucred_s *
cred2ucred(const cred_t *cr, pid_t pid, void *buf, const cred_t *rcr)
{
	struct ucred_s *uc;

	/* The structure isn't always completely filled in, so zero it */
	if (buf == NULL) {
		uc = kmem_zalloc(ucredsize, KM_SLEEP);
	} else {
		bzero(buf, ucredsize);
		uc = buf;
	}
	uc->uc_size = ucredsize;
	uc->uc_credoff = UCRED_CRED_OFF;
	uc->uc_privoff = UCRED_PRIV_OFF;
	uc->uc_audoff = UCRED_AUD_OFF;
	uc->uc_labeloff = UCRED_LABEL_OFF;
	uc->uc_pid = pid;
	uc->uc_projid = cr->cr_projid;
	uc->uc_zoneid = crgetzoneid(cr);

	/*
	 * Note that cred2uclabel() call should not be factored out
	 * to the bottom of the if-else. UCXXX() macros depend on
	 * uc_xxxoff values to work correctly.
	 */
	if (REMOTE_PEER_CRED(cr)) {
		/*
		 * other than label, the rest of cred info about a
		 * remote peer isn't available.
		 */
		cred2uclabel(cr, UCLABEL(uc));
		uc->uc_credoff = 0;
		uc->uc_privoff = 0;
		uc->uc_audoff = 0;
	} else {
		cred2prcred(cr, UCCRED(uc));
		cred2prpriv(cr, UCPRIV(uc));
		if (audoff == 0 || cred2ucaud(cr, UCAUD(uc), rcr) != 0)
			uc->uc_audoff = 0;
		cred2uclabel(cr, UCLABEL(uc));
	}

	return (uc);
}

/*
 * Get the "ucred" of a process.
 */
struct ucred_s *
pgetucred(proc_t *p)
{
	cred_t *cr;
	struct ucred_s *uc;

	mutex_enter(&p->p_crlock);
	cr = p->p_cred;
	crhold(cr);
	mutex_exit(&p->p_crlock);

	uc = cred2ucred(cr, p->p_pid, NULL, CRED());
	crfree(cr);

	return (uc);
}

/*
 * If the reply status is NFSERR_EACCES, it may be because we are
 * root (no root net access).  Check the real uid, if it isn't root
 * make that the uid instead and retry the call.
 * Private interface for NFS.
 */
cred_t *
crnetadjust(cred_t *cr)
{
	if (cr->cr_uid == 0 && cr->cr_ruid != 0) {
		cr = crdup(cr);
		cr->cr_uid = cr->cr_ruid;
		return (cr);
	}
	return (NULL);
}

/*
 * The reference count is of interest when you want to check
 * whether it is ok to modify the credential in place.
 */
uint_t
crgetref(const cred_t *cr)
{
	return (cr->cr_ref);
}

static int
get_c2audit_load(void)
{
	static int	gotit = 0;
	static int	c2audit_load;
	u_longlong_t	audit_load_val;

	if (gotit)
		return (c2audit_load);
	audit_load_val = 0;		/* set default value once */
	(void) mod_sysvar("c2audit", "audit_load", &audit_load_val);
	c2audit_load = (int)audit_load_val;
	gotit++;
	return (c2audit_load);
}

int
get_audit_ucrsize(void)
{
	return (get_c2audit_load() ? sizeof (auditinfo64_addr_t) : 0);
}

/*
 * Set zone pointer in credential to indicated value.  First adds a
 * hold for the new zone, then drops the hold on previous zone (if any).
 * This is done in this order in case the old and new zones are the
 * same.
 */
void
crsetzone(cred_t *cr, zone_t *zptr)
{
	zone_t *oldzptr = cr->cr_zone;

	ASSERT(cr != kcred);
	ASSERT(cr->cr_ref <= 2);
	cr->cr_zone = zptr;
	zone_cred_hold(zptr);
	if (oldzptr)
		zone_cred_rele(oldzptr);
}

/*
 * Create a new cred based on the supplied label
 */
cred_t *
newcred_from_bslabel(bslabel_t *blabel, uint32_t doi, int flags)
{
	ts_label_t *lbl = labelalloc(blabel, doi, flags);
	cred_t *cr = NULL;

	if (lbl != NULL) {
		if ((cr = kmem_cache_alloc(cred_cache, flags)) != NULL) {
			bcopy(dummycr, cr, crsize);
			cr->cr_label = lbl;
		} else {
			label_rele(lbl);
		}
	}

	return (cr);
}

/*
 * Derive a new cred from the existing cred, but with a different label.
 * To be used when a cred is being shared, but the label needs to be changed
 * by a caller without affecting other users
 */
cred_t *
copycred_from_bslabel(cred_t *cr, bslabel_t *blabel, uint32_t doi, int flags)
{
	ts_label_t *lbl = labelalloc(blabel, doi, flags);
	cred_t *newcr = NULL;

	if (lbl != NULL) {
		if ((newcr = kmem_cache_alloc(cred_cache, flags)) != NULL) {
			bcopy(cr, newcr, crsize);
			if (newcr->cr_zone)
				zone_cred_hold(newcr->cr_zone);
			newcr->cr_label = lbl;
			newcr->cr_ref = 1;
		} else {
			label_rele(lbl);
		}
	}

	return (newcr);
}

/*
 * This function returns a pointer to the kcred-equivalent in the current zone.
 */
cred_t *
zone_kcred(void)
{
	zone_t *zone;

	if ((zone = CRED()->cr_zone) != NULL)
		return (zone->zone_kcred);
	else
		return (kcred);
}

boolean_t
valid_ephemeral_uid(zone_t *zone, uid_t id)
{
	ephemeral_zsd_t *eph_zsd;
	if (id <= IDMAP_WK__MAX_UID)
		return (B_TRUE);

	eph_zsd = get_ephemeral_zsd(zone);
	ASSERT(eph_zsd != NULL);
	membar_consumer();
	return (id > eph_zsd->min_uid && id <= eph_zsd->last_uid);
}

boolean_t
valid_ephemeral_gid(zone_t *zone, gid_t id)
{
	ephemeral_zsd_t *eph_zsd;
	if (id <= IDMAP_WK__MAX_GID)
		return (B_TRUE);

	eph_zsd = get_ephemeral_zsd(zone);
	ASSERT(eph_zsd != NULL);
	membar_consumer();
	return (id > eph_zsd->min_gid && id <= eph_zsd->last_gid);
}

int
eph_uid_alloc(zone_t *zone, int flags, uid_t *start, int count)
{
	ephemeral_zsd_t *eph_zsd = get_ephemeral_zsd(zone);

	ASSERT(eph_zsd != NULL);

	mutex_enter(&eph_zsd->eph_lock);

	/* Test for unsigned integer wrap around */
	if (eph_zsd->last_uid + count < eph_zsd->last_uid) {
		mutex_exit(&eph_zsd->eph_lock);
		return (-1);
	}

	/* first call or idmap crashed and state corrupted */
	if (flags != 0)
		eph_zsd->min_uid = eph_zsd->last_uid;

	hasephids = B_TRUE;
	*start = eph_zsd->last_uid + 1;
	atomic_add_32(&eph_zsd->last_uid, count);
	mutex_exit(&eph_zsd->eph_lock);
	return (0);
}

int
eph_gid_alloc(zone_t *zone, int flags, gid_t *start, int count)
{
	ephemeral_zsd_t *eph_zsd = get_ephemeral_zsd(zone);

	ASSERT(eph_zsd != NULL);

	mutex_enter(&eph_zsd->eph_lock);

	/* Test for unsigned integer wrap around */
	if (eph_zsd->last_gid + count < eph_zsd->last_gid) {
		mutex_exit(&eph_zsd->eph_lock);
		return (-1);
	}

	/* first call or idmap crashed and state corrupted */
	if (flags != 0)
		eph_zsd->min_gid = eph_zsd->last_gid;

	hasephids = B_TRUE;
	*start = eph_zsd->last_gid + 1;
	atomic_add_32(&eph_zsd->last_gid, count);
	mutex_exit(&eph_zsd->eph_lock);
	return (0);
}

/*
 * IMPORTANT.The two functions get_ephemeral_data() and set_ephemeral_data()
 * are project private functions that are for use of the test system only and
 * are not to be used for other purposes.
 */

void
get_ephemeral_data(zone_t *zone, uid_t *min_uid, uid_t *last_uid,
	gid_t *min_gid, gid_t *last_gid)
{
	ephemeral_zsd_t *eph_zsd = get_ephemeral_zsd(zone);

	ASSERT(eph_zsd != NULL);

	mutex_enter(&eph_zsd->eph_lock);

	*min_uid = eph_zsd->min_uid;
	*last_uid = eph_zsd->last_uid;
	*min_gid = eph_zsd->min_gid;
	*last_gid = eph_zsd->last_gid;

	mutex_exit(&eph_zsd->eph_lock);
}


void
set_ephemeral_data(zone_t *zone, uid_t min_uid, uid_t last_uid,
	gid_t min_gid, gid_t last_gid)
{
	ephemeral_zsd_t *eph_zsd = get_ephemeral_zsd(zone);

	ASSERT(eph_zsd != NULL);

	mutex_enter(&eph_zsd->eph_lock);

	if (min_uid != 0)
		eph_zsd->min_uid = min_uid;
	if (last_uid != 0)
		eph_zsd->last_uid = last_uid;
	if (min_gid != 0)
		eph_zsd->min_gid = min_gid;
	if (last_gid != 0)
		eph_zsd->last_gid = last_gid;

	mutex_exit(&eph_zsd->eph_lock);
}

/*
 * If the credential user SID or group SID is mapped to an ephemeral
 * ID, map the credential to nobody.
 */
cred_t *
crgetmapped(const cred_t *cr)
{
	ephemeral_zsd_t *eph_zsd;
	/*
	 * Someone incorrectly passed a NULL cred to a vnode operation
	 * either on purpose or by calling CRED() in interrupt context.
	 */
	if (cr == NULL)
		return (NULL);

	if (cr->cr_ksid != NULL) {
		if (cr->cr_ksid->kr_sidx[KSID_USER].ks_id > MAXUID) {
			eph_zsd = get_ephemeral_zsd(crgetzone(cr));
			return (eph_zsd->eph_nobody);
		}

		if (cr->cr_ksid->kr_sidx[KSID_GROUP].ks_id > MAXUID) {
			eph_zsd = get_ephemeral_zsd(crgetzone(cr));
			return (eph_zsd->eph_nobody);
		}
	}

	return ((cred_t *)cr);
}

/* index should be in range for a ksidindex_t */
void
crsetsid(cred_t *cr, ksid_t *ksp, int index)
{
	ASSERT(cr->cr_ref <= 2);
	ASSERT(index >= 0 && index < KSID_COUNT);
	if (cr->cr_ksid == NULL && ksp == NULL)
		return;
	cr->cr_ksid = kcrsid_setsid(cr->cr_ksid, ksp, index);
}

void
crsetsidlist(cred_t *cr, ksidlist_t *ksl)
{
	ASSERT(cr->cr_ref <= 2);
	if (cr->cr_ksid == NULL && ksl == NULL)
		return;
	cr->cr_ksid = kcrsid_setsidlist(cr->cr_ksid, ksl);
}

ksid_t *
crgetsid(const cred_t *cr, int i)
{
	ASSERT(i >= 0 && i < KSID_COUNT);
	if (cr->cr_ksid != NULL && cr->cr_ksid->kr_sidx[i].ks_domain)
		return ((ksid_t *)&cr->cr_ksid->kr_sidx[i]);
	return (NULL);
}

ksidlist_t *
crgetsidlist(const cred_t *cr)
{
	if (cr->cr_ksid != NULL)
		return (cr->cr_ksid->kr_sidlist);
	return (NULL);
}

/*
 * Interface to set the effective and permitted privileges for
 * a credential; this interface does no security checks and is
 * intended for kernel (file)servers creating credentials with
 * specific privileges.
 */
int
crsetpriv(cred_t *cr, ...)
{
	va_list ap;
	const char *privnm;

	ASSERT(cr->cr_ref <= 2);

	priv_set_PA(cr);

	va_start(ap, cr);

	while ((privnm = va_arg(ap, const char *)) != NULL) {
		int priv = priv_getbyname(privnm, 0);
		if (priv < 0)
			return (-1);

		priv_addset(&CR_PPRIV(cr), priv);
		priv_addset(&CR_EPRIV(cr), priv);
	}
	priv_adjust_PA(cr);
	va_end(ap);
	return (0);
}
