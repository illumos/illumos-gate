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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015, Joyent, Inc.
 */

#include <sys/atomic.h>
#include <sys/door.h>
#include <sys/proc.h>
#include <sys/cred_impl.h>
#include <sys/policy.h>
#include <sys/priv.h>
#include <sys/klpd.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/project.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/pathname.h>
#include <sys/varargs.h>
#include <sys/zone.h>
#include <netinet/in.h>

#define	ROUNDUP(a, n) (((a) + ((n) - 1)) & ~((n) - 1))

static kmutex_t klpd_mutex;

typedef struct klpd_reg {
	struct klpd_reg *klpd_next;
	struct klpd_reg **klpd_refp;
	door_handle_t 	klpd_door;
	pid_t		klpd_door_pid;
	priv_set_t	klpd_pset;
	cred_t		*klpd_cred;
	int		klpd_indel;		/* Disabled */
	uint32_t	klpd_ref;
} klpd_reg_t;


/*
 * This data structure hangs off the credential of a process; the
 * credential is finalized and cannot be changed; but this structure
 * can be changed when a new door server for the particular group
 * needs to be registered.  It is refcounted and shared between
 * processes with common ancestry.
 *
 * The reference count is atomically updated.
 *
 * But the registration probably needs to be updated under a lock.
 */
typedef struct credklpd {
	kmutex_t	crkl_lock;
	klpd_reg_t	*crkl_reg;
	uint32_t	crkl_ref;
} credklpd_t;

klpd_reg_t *klpd_list;

static void klpd_unlink(klpd_reg_t *);
static int klpd_unreg_dh(door_handle_t);

static credklpd_t *crklpd_alloc(void);

void crklpd_setreg(credklpd_t *, klpd_reg_t *);

extern size_t max_vnode_path;

void
klpd_rele(klpd_reg_t *p)
{
	if (atomic_dec_32_nv(&p->klpd_ref) == 0) {
		if (p->klpd_refp != NULL)
			klpd_unlink(p);
		if (p->klpd_cred != NULL)
			crfree(p->klpd_cred);
		door_ki_rele(p->klpd_door);
		kmem_free(p, sizeof (*p));
	}
}

/*
 * In order to be able to walk the lists, we can't unlink the entry
 * until the reference count drops to 0.  If we remove it too soon,
 * list walkers will terminate when they happen to call a now orphaned
 * entry.
 */
static klpd_reg_t *
klpd_rele_next(klpd_reg_t *p)
{
	klpd_reg_t *r = p->klpd_next;

	klpd_rele(p);
	return (r);
}


static void
klpd_hold(klpd_reg_t *p)
{
	atomic_inc_32(&p->klpd_ref);
}

/*
 * Remove registration from where it is registered.  Returns next in list.
 */
static void
klpd_unlink(klpd_reg_t *p)
{
	ASSERT(p->klpd_refp == NULL || *p->klpd_refp == p);

	if (p->klpd_refp != NULL)
		*p->klpd_refp = p->klpd_next;

	if (p->klpd_next != NULL)
		p->klpd_next->klpd_refp = p->klpd_refp;
	p->klpd_refp = NULL;
}

/*
 * Remove all elements of the klpd list and decrement their refcnts.
 * The lock guarding the list should be held; this function is
 * called when we are sure we want to destroy the list completely
 * list but not so sure that the reference counts of all elements have
 * dropped back to 1.
 */
void
klpd_freelist(klpd_reg_t **pp)
{
	klpd_reg_t *p;

	while ((p = *pp) != NULL) {
		klpd_unlink(p);
		klpd_rele(p);
	}
}

/*
 * Link new entry in list.  The Boolean argument specifies whether this
 * list can contain only a single item or multiple items.
 * Returns the entry which needs to be released if single is B_TRUE.
 */
static klpd_reg_t *
klpd_link(klpd_reg_t *p, klpd_reg_t **listp, boolean_t single)
{
	klpd_reg_t *old = *listp;

	ASSERT(p->klpd_ref == 1);

	ASSERT(old == NULL || *old->klpd_refp == old);
	p->klpd_refp = listp;
	p->klpd_next = single ? NULL : old;
	*listp = p;
	if (old != NULL) {
		if (single) {
			ASSERT(old->klpd_next == NULL);
			old->klpd_refp = NULL;
			return (old);
		} else
			old->klpd_refp = &p->klpd_next;
	}
	return (NULL);
}

/*
 * The typical call consists of:
 *	- priv_set_t
 *	- some integer data (type, value)
 * for now, it's just one bit.
 */
static klpd_head_t *
klpd_marshall(klpd_reg_t *p, const priv_set_t *rq, va_list ap)
{
	char	*tmp;
	uint_t	type;
	vnode_t *vp;
	size_t	len = sizeof (priv_set_t) + sizeof (klpd_head_t);
	size_t	plen, clen;
	int	proto;

	klpd_arg_t *kap = NULL;
	klpd_head_t *khp;

	type = va_arg(ap, uint_t);
	switch (type) {
	case KLPDARG_NOMORE:
		khp = kmem_zalloc(len, KM_SLEEP);
		khp->klh_argoff = 0;
		break;
	case KLPDARG_VNODE:
		len += offsetof(klpd_arg_t, kla_str);
		vp = va_arg(ap, vnode_t *);
		if (vp == NULL)
			return (NULL);

		tmp = va_arg(ap, char *);

		if (tmp != NULL && *tmp != '\0')
			clen = strlen(tmp) + 1;
		else
			clen = 0;

		len += ROUNDUP(MAXPATHLEN, sizeof (uint_t));
		khp = kmem_zalloc(len, KM_SLEEP);

		khp->klh_argoff = sizeof (klpd_head_t) + sizeof (priv_set_t);
		kap = KLH_ARG(khp);

		if (vnodetopath(crgetzone(p->klpd_cred)->zone_rootvp,
		    vp, kap->kla_str, MAXPATHLEN, p->klpd_cred) != 0) {
			kmem_free(khp, len);
			return (NULL);
		}
		if (clen != 0) {
			plen = strlen(kap->kla_str);
			if (plen + clen + 1 >= MAXPATHLEN) {
				kmem_free(khp, len);
				return (NULL);
			}
			/* Don't make root into a double "/" */
			if (plen <= 2)
				plen = 0;
			kap->kla_str[plen] = '/';
			bcopy(tmp, &kap->kla_str[plen + 1], clen);
		}
		break;
	case KLPDARG_PORT:
		proto = va_arg(ap, int);
		switch (proto) {
		case IPPROTO_TCP:	type = KLPDARG_TCPPORT;
					break;
		case IPPROTO_UDP:	type = KLPDARG_UDPPORT;
					break;
		case IPPROTO_SCTP:	type = KLPDARG_SCTPPORT;
					break;
		case PROTO_SDP:		type = KLPDARG_SDPPORT;
					break;
		}
		/* FALLTHROUGH */
	case KLPDARG_INT:
	case KLPDARG_TCPPORT:
	case KLPDARG_UDPPORT:
	case KLPDARG_SCTPPORT:
	case KLPDARG_SDPPORT:
		len += sizeof (*kap);
		khp = kmem_zalloc(len, KM_SLEEP);
		khp->klh_argoff = sizeof (klpd_head_t) + sizeof (priv_set_t);
		kap = KLH_ARG(khp);
		kap->kla_int = va_arg(ap, int);
		break;
	default:
		return (NULL);
	}
	khp->klh_vers = KLPDCALL_VERS;
	khp->klh_len = len;
	khp->klh_privoff = sizeof (*khp);
	*KLH_PRIVSET(khp) = *rq;
	if (kap != NULL) {
		kap->kla_type = type;
		kap->kla_dlen = len - khp->klh_argoff;
	}
	return (khp);
}

static int
klpd_do_call(klpd_reg_t *p, const priv_set_t *req, va_list ap)
{
	door_arg_t da;
	int res;
	int dres;
	klpd_head_t *klh;

	if (p->klpd_door_pid == curproc->p_pid)
		return (-1);

	klh = klpd_marshall(p, req, ap);

	if (klh == NULL)
		return (-1);

	da.data_ptr = (char *)klh;
	da.data_size = klh->klh_len;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)&res;
	da.rsize = sizeof (res);

	while ((dres = door_ki_upcall_limited(p->klpd_door, &da, NULL,
	    SIZE_MAX, 0)) != 0) {
		switch (dres) {
		case EAGAIN:
			delay(1);
			continue;
		case EINVAL:
		case EBADF:
			/* Bad door, don't call it again. */
			(void) klpd_unreg_dh(p->klpd_door);
			/* FALLTHROUGH */
		case EINTR:
			/* Pending signal, nothing we can do. */
			/* FALLTHROUGH */
		default:
			kmem_free(klh, klh->klh_len);
			return (-1);
		}
	}
	kmem_free(klh, klh->klh_len);
	/* Bogus return value, must be a failure */
	if (da.rbuf != (char *)&res) {
		kmem_free(da.rbuf, da.rsize);
		return (-1);
	}
	return (res);
}

uint32_t klpd_bad_locks;

int
klpd_call(const cred_t *cr, const priv_set_t *req, va_list ap)
{
	klpd_reg_t *p;
	int rv = -1;
	credklpd_t *ckp;
	zone_t *ckzone;

	/*
	 * These locks must not be held when this code is called;
	 * callbacks to userland with these locks held will result
	 * in issues.  That said, the code at the call sides was
	 * restructured not to call with any of the locks held and
	 * no policies operate by default on most processes.
	 */
	if (mutex_owned(&pidlock) || mutex_owned(&curproc->p_lock) ||
	    mutex_owned(&curproc->p_crlock)) {
		atomic_inc_32(&klpd_bad_locks);
		return (-1);
	}

	/*
	 * Enforce the limit set for the call process (still).
	 */
	if (!priv_issubset(req, &CR_LPRIV(cr)))
		return (-1);

	/* Try 1: get the credential specific klpd */
	if ((ckp = crgetcrklpd(cr)) != NULL) {
		mutex_enter(&ckp->crkl_lock);
		if ((p = ckp->crkl_reg) != NULL &&
		    p->klpd_indel == 0 &&
		    priv_issubset(req, &p->klpd_pset)) {
			klpd_hold(p);
			mutex_exit(&ckp->crkl_lock);
			rv = klpd_do_call(p, req, ap);
			mutex_enter(&ckp->crkl_lock);
			klpd_rele(p);
			mutex_exit(&ckp->crkl_lock);
			if (rv != -1)
				return (rv == 0 ? 0 : -1);
		} else {
			mutex_exit(&ckp->crkl_lock);
		}
	}

	/* Try 2: get the project specific klpd */
	mutex_enter(&klpd_mutex);

	if ((p = curproj->kpj_klpd) != NULL) {
		klpd_hold(p);
		mutex_exit(&klpd_mutex);
		if (p->klpd_indel == 0 &&
		    priv_issubset(req, &p->klpd_pset)) {
			rv = klpd_do_call(p, req, ap);
		}
		mutex_enter(&klpd_mutex);
		klpd_rele(p);
		mutex_exit(&klpd_mutex);

		if (rv != -1)
			return (rv == 0 ? 0 : -1);
	} else {
		mutex_exit(&klpd_mutex);
	}

	/* Try 3: get the global klpd list */
	ckzone = crgetzone(cr);
	mutex_enter(&klpd_mutex);

	for (p = klpd_list; p != NULL; ) {
		zone_t *kkzone = crgetzone(p->klpd_cred);
		if ((kkzone == &zone0 || kkzone == ckzone) &&
		    p->klpd_indel == 0 &&
		    priv_issubset(req, &p->klpd_pset)) {
			klpd_hold(p);
			mutex_exit(&klpd_mutex);
			rv = klpd_do_call(p, req, ap);
			mutex_enter(&klpd_mutex);

			p = klpd_rele_next(p);

			if (rv != -1)
				break;
		} else {
			p = p->klpd_next;
		}
	}
	mutex_exit(&klpd_mutex);
	return (rv == 0 ? 0 : -1);
}

/*
 * Register the klpd.
 * If the pid_t passed in is positive, update the registration for
 * the specific process; that is only possible if the process already
 * has a registration on it.  This change of registration will affect
 * all processes which share common ancestry.
 *
 * MY_PID (pid 0) can be used to create or change the context for
 * the current process, typically done after fork().
 *
 * A negative value can be used to register a klpd globally.
 *
 * The per-credential klpd needs to be cleaned up when entering
 * a zone or unsetting the flag.
 */
int
klpd_reg(int did, idtype_t type, id_t id, priv_set_t *psetbuf)
{
	cred_t *cr = CRED();
	door_handle_t dh;
	klpd_reg_t *kpd;
	priv_set_t pset;
	door_info_t di;
	credklpd_t *ckp = NULL;
	pid_t pid = -1;
	projid_t proj = -1;
	kproject_t *kpp = NULL;

	if (CR_FLAGS(cr) & PRIV_XPOLICY)
		return (set_errno(EINVAL));

	if (copyin(psetbuf, &pset, sizeof (priv_set_t)))
		return (set_errno(EFAULT));

	if (!priv_issubset(&pset, &CR_OEPRIV(cr)))
		return (set_errno(EPERM));

	switch (type) {
	case P_PID:
		pid = (pid_t)id;
		if (pid == P_MYPID)
			pid = curproc->p_pid;
		if (pid == curproc->p_pid)
			ckp = crklpd_alloc();
		break;
	case P_PROJID:
		proj = (projid_t)id;
		kpp = project_hold_by_id(proj, crgetzone(cr),
		    PROJECT_HOLD_FIND);
		if (kpp == NULL)
			return (set_errno(ESRCH));
		break;
	default:
		return (set_errno(ENOTSUP));
	}


	/*
	 * Verify the door passed in; it must be a door and we won't
	 * allow processes to be called on their own behalf.
	 */
	dh = door_ki_lookup(did);
	if (dh == NULL || door_ki_info(dh, &di) != 0) {
		if (ckp != NULL)
			crklpd_rele(ckp);
		if (kpp != NULL)
			project_rele(kpp);
		return (set_errno(EBADF));
	}
	if (type == P_PID && pid == di.di_target) {
		if (ckp != NULL)
			crklpd_rele(ckp);
		ASSERT(kpp == NULL);
		return (set_errno(EINVAL));
	}

	kpd = kmem_zalloc(sizeof (*kpd), KM_SLEEP);
	crhold(kpd->klpd_cred = cr);
	kpd->klpd_door = dh;
	kpd->klpd_door_pid = di.di_target;
	kpd->klpd_ref = 1;
	kpd->klpd_pset = pset;

	if (kpp != NULL) {
		mutex_enter(&klpd_mutex);
		kpd = klpd_link(kpd, &kpp->kpj_klpd, B_TRUE);
		mutex_exit(&klpd_mutex);
		if (kpd != NULL)
			klpd_rele(kpd);
		project_rele(kpp);
	} else if ((int)pid < 0) {
		/* Global daemon */
		mutex_enter(&klpd_mutex);
		(void) klpd_link(kpd, &klpd_list, B_FALSE);
		mutex_exit(&klpd_mutex);
	} else if (pid == curproc->p_pid) {
		proc_t *p = curproc;
		cred_t *newcr = cralloc();

		/* No need to lock, sole reference to ckp */
		kpd = klpd_link(kpd, &ckp->crkl_reg, B_TRUE);

		if (kpd != NULL)
			klpd_rele(kpd);

		mutex_enter(&p->p_crlock);
		cr = p->p_cred;
		crdup_to(cr, newcr);
		crsetcrklpd(newcr, ckp);
		p->p_cred = newcr;	/* Already held for p_cred */

		crhold(newcr);		/* Hold once for the current thread */
		mutex_exit(&p->p_crlock);
		crfree(cr);		/* One for the p_cred */
		crset(p, newcr);
	} else {
		proc_t *p;
		cred_t *pcr;
		mutex_enter(&pidlock);
		p = prfind(pid);
		if (p == NULL || !prochasprocperm(p, curproc, CRED())) {
			mutex_exit(&pidlock);
			klpd_rele(kpd);
			return (set_errno(p == NULL ? ESRCH : EPERM));
		}
		mutex_enter(&p->p_crlock);
		crhold(pcr = p->p_cred);
		mutex_exit(&pidlock);
		mutex_exit(&p->p_crlock);
		/*
		 * We're going to update the credential's ckp in place;
		 * this requires that it exists.
		 */
		ckp = crgetcrklpd(pcr);
		if (ckp == NULL) {
			crfree(pcr);
			klpd_rele(kpd);
			return (set_errno(EINVAL));
		}
		crklpd_setreg(ckp, kpd);
		crfree(pcr);
	}

	return (0);
}

static int
klpd_unreg_dh(door_handle_t dh)
{
	klpd_reg_t *p;

	mutex_enter(&klpd_mutex);
	for (p = klpd_list; p != NULL; p = p->klpd_next) {
		if (p->klpd_door == dh)
			break;
	}
	if (p == NULL) {
		mutex_exit(&klpd_mutex);
		return (EINVAL);
	}
	if (p->klpd_indel != 0) {
		mutex_exit(&klpd_mutex);
		return (EAGAIN);
	}
	p->klpd_indel = 1;
	klpd_rele(p);
	mutex_exit(&klpd_mutex);
	return (0);
}

int
klpd_unreg(int did, idtype_t type, id_t id)
{
	door_handle_t dh;
	int res = 0;
	proc_t *p;
	pid_t pid;
	projid_t proj;
	kproject_t *kpp = NULL;
	credklpd_t *ckp;

	switch (type) {
	case P_PID:
		pid = (pid_t)id;
		break;
	case P_PROJID:
		proj = (projid_t)id;
		kpp = project_hold_by_id(proj, crgetzone(CRED()),
		    PROJECT_HOLD_FIND);
		if (kpp == NULL)
			return (set_errno(ESRCH));
		break;
	default:
		return (set_errno(ENOTSUP));
	}

	dh = door_ki_lookup(did);
	if (dh == NULL) {
		if (kpp != NULL)
			project_rele(kpp);
		return (set_errno(EINVAL));
	}

	if (kpp != NULL) {
		mutex_enter(&klpd_mutex);
		if (kpp->kpj_klpd == NULL)
			res = ESRCH;
		else
			klpd_freelist(&kpp->kpj_klpd);
		mutex_exit(&klpd_mutex);
		project_rele(kpp);
		goto out;
	} else if ((int)pid > 0) {
		mutex_enter(&pidlock);
		p = prfind(pid);
		if (p == NULL) {
			mutex_exit(&pidlock);
			door_ki_rele(dh);
			return (set_errno(ESRCH));
		}
		mutex_enter(&p->p_crlock);
		mutex_exit(&pidlock);
	} else if (pid == 0) {
		p = curproc;
		mutex_enter(&p->p_crlock);
	} else {
		res = klpd_unreg_dh(dh);
		goto out;
	}

	ckp = crgetcrklpd(p->p_cred);
	if (ckp != NULL) {
		crklpd_setreg(ckp, NULL);
	} else {
		res = ESRCH;
	}
	mutex_exit(&p->p_crlock);

out:
	door_ki_rele(dh);

	if (res != 0)
		return (set_errno(res));
	return (0);
}

void
crklpd_hold(credklpd_t *crkpd)
{
	atomic_inc_32(&crkpd->crkl_ref);
}

void
crklpd_rele(credklpd_t *crkpd)
{
	if (atomic_dec_32_nv(&crkpd->crkl_ref) == 0) {
		if (crkpd->crkl_reg != NULL)
			klpd_rele(crkpd->crkl_reg);
		mutex_destroy(&crkpd->crkl_lock);
		kmem_free(crkpd, sizeof (*crkpd));
	}
}

static credklpd_t *
crklpd_alloc(void)
{
	credklpd_t *res = kmem_alloc(sizeof (*res), KM_SLEEP);

	mutex_init(&res->crkl_lock, NULL, MUTEX_DEFAULT, NULL);
	res->crkl_ref = 1;
	res->crkl_reg = NULL;

	return (res);
}

void
crklpd_setreg(credklpd_t *crk, klpd_reg_t *new)
{
	klpd_reg_t *old;

	mutex_enter(&crk->crkl_lock);
	if (new == NULL) {
		old = crk->crkl_reg;
		if (old != NULL)
			klpd_unlink(old);
	} else {
		old = klpd_link(new, &crk->crkl_reg, B_TRUE);
	}
	mutex_exit(&crk->crkl_lock);

	if (old != NULL)
		klpd_rele(old);
}

/* Allocate and register the pfexec specific callback */
int
pfexec_reg(int did)
{
	door_handle_t dh;
	int err = secpolicy_pfexec_register(CRED());
	klpd_reg_t *pfx;
	door_info_t di;
	zone_t *myzone = crgetzone(CRED());

	if (err != 0)
		return (set_errno(err));

	dh = door_ki_lookup(did);
	if (dh == NULL || door_ki_info(dh, &di) != 0)
		return (set_errno(EBADF));

	pfx = kmem_zalloc(sizeof (*pfx), KM_SLEEP);

	pfx->klpd_door = dh;
	pfx->klpd_door_pid = di.di_target;
	pfx->klpd_ref = 1;
	pfx->klpd_cred = NULL;
	mutex_enter(&myzone->zone_lock);
	pfx = klpd_link(pfx, &myzone->zone_pfexecd, B_TRUE);
	mutex_exit(&myzone->zone_lock);
	if (pfx != NULL)
		klpd_rele(pfx);

	return (0);
}

int
pfexec_unreg(int did)
{
	door_handle_t dh;
	int err = 0;
	zone_t *myzone = crgetzone(CRED());
	klpd_reg_t *pfd;

	dh = door_ki_lookup(did);
	if (dh == NULL)
		return (set_errno(EBADF));

	mutex_enter(&myzone->zone_lock);
	pfd = myzone->zone_pfexecd;
	if (pfd != NULL && pfd->klpd_door == dh) {
		klpd_unlink(pfd);
	} else {
		pfd = NULL;
		err = EINVAL;
	}
	mutex_exit(&myzone->zone_lock);
	door_ki_rele(dh);
	/*
	 * crfree() cannot be called with zone_lock held; it is called
	 * indirectly through closing the door handle
	 */
	if (pfd != NULL)
		klpd_rele(pfd);
	if (err != 0)
		return (set_errno(err));
	return (0);
}

static int
get_path(char *buf, const char *path, int len)
{
	size_t lc;
	char *s;

	if (len < 0)
		len = strlen(path);

	if (*path == '/' && len < MAXPATHLEN) {
		(void) strcpy(buf, path);
		return (0);
	}
	/*
	 * Build the pathname using the current directory + resolve pathname.
	 * The resolve pathname either starts with a normal component and
	 * we can just concatenate them or it starts with one
	 * or more ".." component and we can remove those; the
	 * last one cannot be a ".." and the current directory has
	 * more components than the number of ".." in the resolved pathname.
	 */
	if (dogetcwd(buf, MAXPATHLEN) != 0)
		return (-1);

	lc = strlen(buf);

	while (len > 3 && strncmp("../", path, 3) == 0) {
		len -= 3;
		path += 3;

		s = strrchr(buf, '/');
		if (s == NULL || s == buf)
			return (-1);

		*s = '\0';
		lc = s - buf;
	}
	/* Add a "/" and a NUL */
	if (lc < 2 || lc + len + 2 >= MAXPATHLEN)
		return (-1);

	buf[lc] = '/';
	(void) strcpy(buf + lc + 1, path);

	return (0);
}

/*
 * Perform the pfexec upcall.
 *
 * The pfexec upcall is different from the klpd_upcall in that a failure
 * will lead to a denial of execution.
 */
int
pfexec_call(const cred_t *cr, struct pathname *rpnp, cred_t **pfcr,
    boolean_t *scrub)
{
	klpd_reg_t *pfd;
	pfexec_arg_t *pap;
	pfexec_reply_t pr, *prp;
	door_arg_t da;
	int dres;
	cred_t *ncr = NULL;
	int err = EACCES;
	priv_set_t *iset;
	priv_set_t *lset;
	zone_t *myzone = crgetzone(CRED());
	size_t pasize = PFEXEC_ARG_SIZE(MAXPATHLEN);

	/* Find registration */
	mutex_enter(&myzone->zone_lock);
	if ((pfd = myzone->zone_pfexecd) != NULL)
		klpd_hold(pfd);
	mutex_exit(&myzone->zone_lock);

	if (pfd == NULL)
		return (0);

	if (pfd->klpd_door_pid == curproc->p_pid) {
		klpd_rele(pfd);
		return (0);
	}

	pap = kmem_zalloc(pasize, KM_SLEEP);

	if (get_path(pap->pfa_path, rpnp->pn_path, rpnp->pn_pathlen) == -1)
		goto out1;

	pap->pfa_vers = PFEXEC_ARG_VERS;
	pap->pfa_call = PFEXEC_EXEC_ATTRS;
	pap->pfa_len = pasize;
	pap->pfa_uid = crgetruid(cr);

	da.data_ptr = (char *)pap;
	da.data_size = pap->pfa_len;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)&pr;
	da.rsize = sizeof (pr);

	while ((dres = door_ki_upcall(pfd->klpd_door, &da)) != 0) {
		switch (dres) {
		case EAGAIN:
			delay(1);
			continue;
		case EINVAL:
		case EBADF:
			/* FALLTHROUGH */
		case EINTR:
			/* FALLTHROUGH */
		default:
			goto out;
		}
	}

	prp = (pfexec_reply_t *)da.rbuf;
	/*
	 * Check the size of the result and the alignment of the
	 * privilege sets.
	 */
	if (da.rsize < sizeof (pr) ||
	    prp->pfr_ioff > da.rsize - sizeof (priv_set_t) ||
	    prp->pfr_loff > da.rsize - sizeof (priv_set_t) ||
	    (prp->pfr_loff & (sizeof (priv_chunk_t) - 1)) != 0 ||
	    (prp->pfr_ioff & (sizeof (priv_chunk_t) - 1)) != 0)
		goto out;

	/*
	 * Get results:
	 *	allow/allow with additional credentials/disallow[*]
	 *
	 *	euid, uid, egid, gid, privs, and limitprivs
	 * We now have somewhat more flexibility we could even set E and P
	 * judiciously but that would break some currently valid assumptions
	 *	[*] Disallow is not readily supported by always including
	 *	the Basic Solaris User profile in all user's profiles.
	 */

	if (!prp->pfr_allowed) {
		err = EACCES;
		goto out;
	}
	if (!prp->pfr_setcred) {
		err = 0;
		goto out;
	}
	ncr = crdup((cred_t *)cr);

	/*
	 * Generate the new credential set scrubenv if ruid != euid (or set)
	 * the "I'm set-uid flag" but that is not inherited so scrubbing
	 * the environment is a requirement.
	 */
	/* Set uids or gids, note that -1 will do the right thing */
	if (crsetresuid(ncr, prp->pfr_ruid, prp->pfr_euid, prp->pfr_euid) != 0)
		goto out;
	if (crsetresgid(ncr, prp->pfr_rgid, prp->pfr_egid, prp->pfr_egid) != 0)
		goto out;

	*scrub = prp->pfr_scrubenv;

	if (prp->pfr_clearflag)
		CR_FLAGS(ncr) &= ~PRIV_PFEXEC;

	/* We cannot exceed our Limit set, no matter what */
	iset = PFEXEC_REPLY_IPRIV(prp);

	if (iset != NULL) {
		if (!priv_issubset(iset, &CR_LPRIV(ncr)))
			goto out;
		priv_union(iset, &CR_IPRIV(ncr));
	}

	/* Nor can we increate our Limit set itself */
	lset = PFEXEC_REPLY_LPRIV(prp);

	if (lset != NULL) {
		if (!priv_issubset(lset, &CR_LPRIV(ncr)))
			goto out;
		CR_LPRIV(ncr) = *lset;
	}

	/* Exec will do the standard set operations */

	err = 0;
out:
	if (da.rbuf != (char *)&pr)
		kmem_free(da.rbuf, da.rsize);
out1:
	kmem_free(pap, pasize);
	klpd_rele(pfd);
	if (ncr != NULL) {
		if (err == 0)
			*pfcr = ncr;
		else
			crfree(ncr);
	}
	return (err);
}

int
get_forced_privs(const cred_t *cr, const char *respn, priv_set_t *set)
{
	klpd_reg_t *pfd;
	pfexec_arg_t *pap;
	door_arg_t da;
	int dres;
	int err = -1;
	priv_set_t *fset, pmem;
	cred_t *zkcr;
	zone_t *myzone = crgetzone(cr);
	size_t pasize = PFEXEC_ARG_SIZE(MAXPATHLEN);

	mutex_enter(&myzone->zone_lock);
	if ((pfd = myzone->zone_pfexecd) != NULL)
		klpd_hold(pfd);
	mutex_exit(&myzone->zone_lock);

	if (pfd == NULL)
		return (-1);

	if (pfd->klpd_door_pid == curproc->p_pid) {
		klpd_rele(pfd);
		return (0);
	}

	pap = kmem_zalloc(pasize, KM_SLEEP);

	if (get_path(pap->pfa_path, respn, -1) == -1)
		goto out1;

	pap->pfa_vers = PFEXEC_ARG_VERS;
	pap->pfa_call = PFEXEC_FORCED_PRIVS;
	pap->pfa_len = pasize;
	pap->pfa_uid = (uid_t)-1;			/* Not relevant */

	da.data_ptr = (char *)pap;
	da.data_size = pap->pfa_len;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)&pmem;
	da.rsize = sizeof (pmem);

	while ((dres = door_ki_upcall(pfd->klpd_door, &da)) != 0) {
		switch (dres) {
		case EAGAIN:
			delay(1);
			continue;
		case EINVAL:
		case EBADF:
		case EINTR:
		default:
			goto out;
		}
	}

	/*
	 * Check the size of the result, it's a privilege set.
	 */
	if (da.rsize != sizeof (priv_set_t))
		goto out;

	fset = (priv_set_t *)da.rbuf;

	/*
	 * We restrict the forced privileges with whatever is available in
	 * the current zone.
	 */
	zkcr = zone_kcred();
	priv_intersect(&CR_LPRIV(zkcr), fset);

	/*
	 * But we fail if the forced privileges are not found in the current
	 * Limit set.
	 */
	if (!priv_issubset(fset, &CR_LPRIV(cr))) {
		err = EACCES;
	} else if (!priv_isemptyset(fset)) {
		err = 0;
		*set = *fset;
	}
out:
	if (da.rbuf != (char *)&pmem)
		kmem_free(da.rbuf, da.rsize);
out1:
	kmem_free(pap, pasize);
	klpd_rele(pfd);
	return (err);
}

int
check_user_privs(const cred_t *cr, const priv_set_t *set)
{
	klpd_reg_t *pfd;
	pfexec_arg_t *pap;
	door_arg_t da;
	int dres;
	int err = -1;
	zone_t *myzone = crgetzone(cr);
	size_t pasize = PFEXEC_ARG_SIZE(sizeof (priv_set_t));
	uint32_t res;

	mutex_enter(&myzone->zone_lock);
	if ((pfd = myzone->zone_pfexecd) != NULL)
		klpd_hold(pfd);
	mutex_exit(&myzone->zone_lock);

	if (pfd == NULL)
		return (-1);

	if (pfd->klpd_door_pid == curproc->p_pid) {
		klpd_rele(pfd);
		return (0);
	}

	pap = kmem_zalloc(pasize, KM_SLEEP);

	*(priv_set_t *)&pap->pfa_buf = *set;

	pap->pfa_vers = PFEXEC_ARG_VERS;
	pap->pfa_call = PFEXEC_USER_PRIVS;
	pap->pfa_len = pasize;
	pap->pfa_uid = crgetruid(cr);

	da.data_ptr = (char *)pap;
	da.data_size = pap->pfa_len;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = (char *)&res;
	da.rsize = sizeof (res);

	while ((dres = door_ki_upcall(pfd->klpd_door, &da)) != 0) {
		switch (dres) {
		case EAGAIN:
			delay(1);
			continue;
		case EINVAL:
		case EBADF:
		case EINTR:
		default:
			goto out;
		}
	}

	/*
	 * Check the size of the result.
	 */
	if (da.rsize != sizeof (res))
		goto out;

	if (*(uint32_t *)da.rbuf == 1)
		err = 0;
out:
	if (da.rbuf != (char *)&res)
		kmem_free(da.rbuf, da.rsize);
out1:
	kmem_free(pap, pasize);
	klpd_rele(pfd);
	return (err);
}
