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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Privilege implementation.
 *
 * This file provides the infrastructure for privilege sets and limits
 * the number of files that requires to include <sys/cred_impl.h> and/or
 * <sys/priv_impl.h>.
 *
 * The Solaris privilege mechanism has been designed in a
 * future proof manner.  While the kernel may use fixed size arrays
 * and fixed bitmasks and bit values, the representation of those
 * is kernel private.  All external interfaces as well as K-to-K interfaces
 * have been constructed in a manner to provide the maximum flexibility.
 *
 * There can be X privilege sets each containing Y 32 bit words.
 * <X, Y> are constant for a kernel invocation.
 *
 * As a consequence, all privilege set manipulation happens in functions
 * below.
 *
 */

#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/priv_impl.h>
#include <sys/procfs.h>
#include <sys/policy.h>
#include <sys/cred_impl.h>
#include <sys/devpolicy.h>
#include <sys/atomic.h>

/*
 * Privilege name to number mapping table consists in the generated
 * priv_const.c file.  This lock protects against updates of the privilege
 * names and counts; all other priv_info fields are read-only.
 * The actual protected values are:
 *	global variable nprivs
 *	the priv_max field
 *	the priv_names field
 *	the priv names info item (cnt/strings)
 */
krwlock_t privinfo_lock;

static boolean_t priv_valid(const cred_t *);

priv_set_t priv_fullset;	/* set of all privileges */
priv_set_t priv_unsafe;	/* unsafe to exec set-uid root if these are not in L */

/*
 * Privilege initialization functions.
 * Called from common/os/cred.c when cred_init is called.
 */

void
priv_init(void)
{
#ifdef DEBUG
	int alloc_test_priv = 1;
#else
	int alloc_test_priv = priv_debug;
#endif
	rw_init(&privinfo_lock, NULL, RW_DRIVER, NULL);

	PRIV_BASIC_ASSERT(priv_basic);
	PRIV_UNSAFE_ASSERT(&priv_unsafe);
	priv_fillset(&priv_fullset);

	/*
	 * When booting with priv_debug set or in a DEBUG kernel, then we'll
	 * add an additional basic privilege and we verify that it is always
	 * present in E.
	 */
	if (alloc_test_priv != 0 &&
	    (priv_basic_test = priv_getbyname("basic_test", PRIV_ALLOC)) >= 0) {
		priv_addset(priv_basic, priv_basic_test);
	}

	devpolicy_init();
}

/* Utility functions: privilege sets as opaque data types */

/*
 * Guts of prgetprivsize.
 */
int
priv_prgetprivsize(const prpriv_t *tmpl)
{
	return (sizeof (prpriv_t) +
	    PRIV_SETBYTES - sizeof (priv_chunk_t) +
	    (tmpl ? tmpl->pr_infosize : priv_info->priv_infosize));
}

/*
 * Guts of prgetpriv.
 */
void
cred2prpriv(const cred_t *cp, prpriv_t *pr)
{
	priv_set_t *psa;
	int i;

	pr->pr_nsets = PRIV_NSET;
	pr->pr_setsize = PRIV_SETSIZE;
	pr->pr_infosize = priv_info->priv_infosize;

	psa = (priv_set_t *)pr->pr_sets;

	for (i = 0; i < PRIV_NSET; i++)
		psa[i] = *priv_getset(cp, i);

	priv_getinfo(cp, (char *)pr + PRIV_PRPRIV_INFO_OFFSET(pr));
}

/*
 * Guts of pr_spriv:
 *
 * Set the privileges of a process.
 *
 * In order to set the privileges, the setting process will need to
 * have those privileges in its effective set in order to prevent
 * specially privileged processes to easily gain additional privileges.
 * Pre-existing privileges can be retained.  To change any privileges,
 * PRIV_PROC_OWNER needs to be asserted.
 *
 * In formula:
 *
 *	S' <= S || S' <= S + Ea
 *
 * the new set must either be subset of the old set or a subset of
 * the oldset merged with the effective set of the acting process; or just:
 *
 *	S' <= S + Ea
 *
 * It's not legal to grow the limit set this way.
 *
 */
int
priv_pr_spriv(proc_t *p, prpriv_t *prpriv, const cred_t *cr)
{
	cred_t *oldcred;
	cred_t *newcred;
	int i;
	int err = EPERM;
	cred_priv_t *cp, *ocp;
	priv_set_t eset;

	ASSERT(MUTEX_HELD(&p->p_lock));

	/*
	 * Set must have proper dimension; infosize must be absent
	 * or properly sized.
	 */
	if (prpriv->pr_nsets != PRIV_NSET ||
	    prpriv->pr_setsize != PRIV_SETSIZE ||
	    (prpriv->pr_infosize & (sizeof (uint32_t) - 1)) != 0 ||
	    prpriv->pr_infosize > priv_info->priv_infosize)
		return (EINVAL);

	mutex_exit(&p->p_lock);

	if (priv_proc_cred_perm(cr, p, &oldcred, VWRITE) != 0) {
		mutex_enter(&p->p_lock);
		return (EPERM);
	}

	newcred = crdup(oldcred);

	/* Copy the privilege sets from prpriv to newcred */
	bcopy(prpriv->pr_sets, CR_PRIVSETS(newcred), PRIV_SETBYTES);

	cp = &newcred->cr_priv;
	ocp = &oldcred->cr_priv;
	eset = CR_OEPRIV(cr);

	priv_intersect(&CR_LPRIV(oldcred), &eset);

	/*
	 * Verify the constraints laid out:
	 * for the limit set, we require that the new set is a subset
	 * of the old limit set.
	 * for all other sets, we require that the new set is either a
	 * subset of the old set or a subset of the intersection of
	 * the old limit set and the effective set of the acting process.
	 */
	for (i = 0; i < PRIV_NSET; i++)
		if (!priv_issubset(&cp->crprivs[i], &ocp->crprivs[i]) &&
		    (i == PRIV_LIMIT || !priv_issubset(&cp->crprivs[i], &eset)))
			break;

	crfree(oldcred);

	if (i < PRIV_NSET || !priv_valid(newcred))
		goto err;

	/* Load the settable privilege information */
	if (prpriv->pr_infosize > 0) {
		char *x = (char *)prpriv + PRIV_PRPRIV_INFO_OFFSET(prpriv);
		char *lastx = x + prpriv->pr_infosize;

		while (x < lastx) {
			priv_info_t *pi = (priv_info_t *)x;
			priv_info_uint_t *pii;

			switch (pi->priv_info_type) {
			case PRIV_INFO_FLAGS:
				pii = (priv_info_uint_t *)x;
				if (pii->info.priv_info_size != sizeof (*pii)) {
					err = EINVAL;
					goto err;
				}
				CR_FLAGS(newcred) &= ~PRIV_USER;
				CR_FLAGS(newcred) |= (pii->val & PRIV_USER);
				break;
			default:
				err = EINVAL;
				goto err;
			}
			/* Guarantee alignment and forward progress */
			if ((pi->priv_info_size & (sizeof (uint32_t) - 1)) ||
			    pi->priv_info_size < sizeof (*pi) ||
			    lastx - x > pi->priv_info_size) {
				err = EINVAL;
				goto err;
			}

			x += pi->priv_info_size;
		}
	}

	/*
	 * We'll try to copy the privilege aware flag; but since the
	 * privileges sets are all individually set, they are set
	 * as if we're privilege aware.  If PRIV_AWARE wasn't set
	 * or was explicitely unset, we need to set the flag and then
	 * try to get rid of it.
	 */
	if ((CR_FLAGS(newcred) & PRIV_AWARE) == 0) {
		CR_FLAGS(newcred) |= PRIV_AWARE;
		priv_adjust_PA(newcred);
	}

	mutex_enter(&p->p_crlock);
	oldcred = p->p_cred;
	p->p_cred = newcred;
	mutex_exit(&p->p_crlock);
	crfree(oldcred);

	mutex_enter(&p->p_lock);
	return (0);

err:
	crfree(newcred);
	mutex_enter(&p->p_lock);
	return (err);
}

priv_impl_info_t
*priv_hold_implinfo(void)
{
	rw_enter(&privinfo_lock, RW_READER);
	return (priv_info);
}

void
priv_release_implinfo(void)
{
	rw_exit(&privinfo_lock);
}

size_t
priv_get_implinfo_size(void)
{
	return (privinfosize);
}


/*
 * Return the nth privilege set
 */
const priv_set_t *
priv_getset(const cred_t *cr, int set)
{
	ASSERT(PRIV_VALIDSET(set));

	if ((CR_FLAGS(cr) & PRIV_AWARE) == 0)
		switch (set) {
		case PRIV_EFFECTIVE:
			return (&CR_OEPRIV(cr));
		case PRIV_PERMITTED:
			return (&CR_OPPRIV(cr));
		}
	return (&CR_PRIVS(cr)->crprivs[set]);
}

/*
 * Buf must be allocated by caller and contain sufficient space to
 * contain all additional info structures using priv_info.priv_infosize.
 * The buffer must be properly aligned.
 */
/*ARGSUSED*/
void
priv_getinfo(const cred_t *cr, void *buf)
{
	struct priv_info_uint *ii;

	ii = buf;
	ii->val = CR_FLAGS(cr);
	ii->info.priv_info_size = (uint32_t)sizeof (*ii);
	ii->info.priv_info_type = PRIV_INFO_FLAGS;
}

int
priv_getbyname(const char *name, uint_t flag)
{
	int i;
	int wheld = 0;
	int len;
	char *p;

	if (flag != 0 && flag != PRIV_ALLOC)
		return (-EINVAL);

	if (strncasecmp(name, "priv_", 5) == 0)
		name += 5;

	rw_enter(&privinfo_lock, RW_READER);
rescan:
	for (i = 0; i < nprivs; i++)
		if (strcasecmp(priv_names[i], name) == 0) {
			rw_exit(&privinfo_lock);
			return (i);
		}


	if (!wheld) {
		if (!(flag & PRIV_ALLOC)) {
			rw_exit(&privinfo_lock);
			return (-EINVAL);
		}

		/* check length, validity and available space */
		len = strlen(name) + 1;

		if (len > PRIVNAME_MAX) {
			rw_exit(&privinfo_lock);
			return (-ENAMETOOLONG);
		}

		for (p = (char *)name; *p != '\0'; p++) {
			char c = *p;

			if (!((c >= 'A' && c <= 'Z') ||
			    (c >= 'a' && c <= 'z') ||
			    (c >= '0' && c <= '9') ||
			    c == '_')) {
				rw_exit(&privinfo_lock);
				return (-EINVAL);
			}
		}

		if (!rw_tryupgrade(&privinfo_lock)) {
			rw_exit(&privinfo_lock);
			rw_enter(&privinfo_lock, RW_WRITER);
			wheld = 1;
			/* Someone may have added our privilege */
			goto rescan;
		}
	}

	if (nprivs == MAX_PRIVILEGE || len + privbytes > maxprivbytes) {
		rw_exit(&privinfo_lock);
		return (-ENOMEM);
	}

	priv_names[i] = p = priv_str + privbytes;

	bcopy(name, p, len);

	/* make the priv_names[i] and privilege name globally visible */
	membar_producer();

	/* adjust priv count and bytes count */
	priv_ninfo->cnt = priv_info->priv_max = ++nprivs;
	privbytes += len;

	rw_exit(&privinfo_lock);
	return (i);
}

/*
 * We can't afford locking the privileges here because of the locations
 * we call this from; so we make sure that the privileges table
 * is visible to us; it is made visible before the value of nprivs is
 * updated.
 */
const char *
priv_getbynum(int priv)
{
	int maxpriv = nprivs;

	membar_consumer();

	if (priv >= 0 && priv < maxpriv)
		return (priv_names[priv]);

	return (NULL);
}

const char *
priv_getsetbynum(int setno)
{
	if (!PRIV_VALIDSET(setno))
		return (NULL);

	return (priv_setnames[setno]);
}

/*
 * Privilege sanity checking when setting: E <= P.
 */
static boolean_t
priv_valid(const cred_t *cr)
{
	return (priv_issubset(&CR_EPRIV(cr), &CR_PPRIV(cr)));
}

/*
 * Privilege manipulation functions
 *
 * Without knowing the details of the privilege set implementation,
 * opaque pointers can be used to manipulate sets at will.
 */
void
priv_emptyset(priv_set_t *set)
{
	bzero(set, sizeof (*set));
}

void
priv_fillset(priv_set_t *set)
{
	int i;

	/* memset? */
	for (i = 0; i < PRIV_SETSIZE; i++)
		set->pbits[i] = ~(priv_chunk_t)0;
}

void
priv_addset(priv_set_t *set, int priv)
{
	ASSERT(priv >= 0 && priv < MAX_PRIVILEGE);
	__PRIV_ASSERT(set, priv);
}

void
priv_delset(priv_set_t *set, int priv)
{
	ASSERT(priv >= 0 && priv < MAX_PRIVILEGE);
	__PRIV_CLEAR(set, priv);
}

boolean_t
priv_ismember(const priv_set_t *set, int priv)
{
	ASSERT(priv >= 0 && priv < MAX_PRIVILEGE);
	return (__PRIV_ISASSERT(set, priv) ? B_TRUE : B_FALSE);
}

#define	PRIV_TEST_BODY(test) \
	int i; \
\
	for (i = 0; i < PRIV_SETSIZE; i++) \
		if (!(test)) \
			return (B_FALSE); \
\
	return (B_TRUE)

boolean_t
priv_isequalset(const priv_set_t *a, const priv_set_t *b)
{
	return ((boolean_t)(bcmp(a, b, sizeof (*a)) == 0));
}

boolean_t
priv_isemptyset(const priv_set_t *set)
{
	PRIV_TEST_BODY(set->pbits[i] == 0);
}

boolean_t
priv_isfullset(const priv_set_t *set)
{
	PRIV_TEST_BODY(set->pbits[i] == ~(priv_chunk_t)0);
}

/*
 * Return true if a is a subset of b
 */
boolean_t
priv_issubset(const priv_set_t *a, const priv_set_t *b)
{
	PRIV_TEST_BODY((a->pbits[i] | b->pbits[i]) == b->pbits[i]);
}

#define	PRIV_CHANGE_BODY(a, op, b) \
	int i; \
\
	for (i = 0; i < PRIV_SETSIZE; i++) \
		a->pbits[i] op b->pbits[i]

/* B = A ^ B */
void
priv_intersect(const priv_set_t *a, priv_set_t *b)
{
	/* CSTYLED */
	PRIV_CHANGE_BODY(b, &=, a);
}

/* B = A v B */
void
priv_union(const priv_set_t *a, priv_set_t *b)
{
	/* CSTYLED */
	PRIV_CHANGE_BODY(b, |=, a);
}

/* A = ! A */
void
priv_inverse(priv_set_t *a)
{
	PRIV_CHANGE_BODY(a, = ~, a);
}

/*
 * Can the source cred act on the target credential?
 *
 * We will you allow to gain uids this way but not privileges.
 */
int
priv_proc_cred_perm(const cred_t *scr, proc_t *tp, cred_t **pcr, int mode)
{
	const priv_set_t *eset;
	int idsmatch;
	cred_t *tcr;
	int res = 0;

	/* prevent the cred from going away */
	mutex_enter(&tp->p_crlock);
	crhold(tcr = tp->p_cred);
	mutex_exit(&tp->p_crlock);

	if (scr == tcr && !(tp->p_flag & SNOCD))
		goto out;

	idsmatch = (scr->cr_uid == tcr->cr_uid &&
	    scr->cr_uid == tcr->cr_ruid &&
	    scr->cr_uid == tcr->cr_suid &&
	    scr->cr_gid == tcr->cr_gid &&
	    scr->cr_gid == tcr->cr_rgid &&
	    scr->cr_gid == tcr->cr_sgid &&
	    !(tp->p_flag & SNOCD));

	/*
	 * Source credential must have the proc_zone privilege if referencing
	 * a process in another zone.
	 */
	if (scr->cr_zone != tcr->cr_zone && secpolicy_proc_zone(scr) != 0) {
		res = EACCES;
		goto out;
	}

	if (!(mode & VWRITE)) {
		if (!idsmatch && secpolicy_proc_owner(scr, tcr, 0) != 0)
			res = EACCES;
		goto out;
	}

	/*
	 * For writing, the effective set of scr must dominate all sets of tcr,
	 * We test Pt <= Es (Et <= Pt so no need to test) and It <= Es
	 * The Limit set of scr must be a superset of the limitset of
	 * tcr.
	 */
	eset = &CR_OEPRIV(scr);

	if (!priv_issubset(&CR_IPRIV(tcr), eset) ||
	    !priv_issubset(&CR_OPPRIV(tcr), eset) ||
	    !priv_issubset(&CR_LPRIV(tcr), &CR_LPRIV(scr)) ||
	    !idsmatch && secpolicy_proc_owner(scr, tcr, mode) != 0)
		res = EACCES;

out:
	if (res == 0 && pcr != NULL)
		*pcr = tcr;
	else
		crfree(tcr);
	return (res);
}

/*
 * Set the privilege aware bit, adding L to E/P if necessary.
 * Each time we set it, we also clear PRIV_AWARE_RESET.
 */
void
priv_set_PA(cred_t *cr)
{
	ASSERT(cr->cr_ref <= 2);

	if ((CR_FLAGS(cr) & (PRIV_AWARE|PRIV_AWARE_RESET)) == PRIV_AWARE)
		return;

	CR_FLAGS(cr) |= PRIV_AWARE;
	CR_FLAGS(cr) &= ~PRIV_AWARE_RESET;

	if (cr->cr_uid == 0)
		priv_union(&CR_LPRIV(cr), &CR_EPRIV(cr));

	if (cr->cr_uid == 0 || cr->cr_suid == 0 || cr->cr_ruid == 0)
		priv_union(&CR_LPRIV(cr), &CR_PPRIV(cr));
}

boolean_t
priv_can_clear_PA(const cred_t *cr)
{
	/*
	 * We can clear PA in the following cases:
	 *
	 * None of the uids are 0.
	 * Any uid == 0 and P == L and (Euid != 0 or E == L)
	 */
	return ((cr->cr_suid != 0 && cr->cr_ruid != 0 && cr->cr_uid != 0) ||
	    priv_isequalset(&CR_PPRIV(cr), &CR_LPRIV(cr)) &&
	    (cr->cr_uid != 0 || priv_isequalset(&CR_EPRIV(cr), &CR_LPRIV(cr))));
}

/*
 * Clear privilege aware bit if it is an idempotent operation and by
 * clearing it the process cannot get to uid 0 and all privileges.
 *
 * This function should be called with caution as it may cause "E" to be
 * lost once a processes assumes euid 0 again.
 */
void
priv_adjust_PA(cred_t *cr)
{
	ASSERT(cr->cr_ref <= 2);

	if (!(CR_FLAGS(cr) & PRIV_AWARE) ||
	    !priv_can_clear_PA(cr)) {
		CR_FLAGS(cr) &= ~PRIV_AWARE_RESET;
		return;
	}

	if (CR_FLAGS(cr) & PRIV_AWARE_INHERIT)
		return;

	/*
	 * We now need to adjust P/E in those cases when uids
	 * are zero; the rules are P' = I & L, E' = I & L;
	 * but since P = L and E = L, we can use P &= I, E &= I,
	 * depending on which uids are 0.
	 */
	if (cr->cr_suid == 0 || cr->cr_ruid == 0 || cr->cr_uid == 0) {
		if (cr->cr_uid == 0)
			priv_intersect(&CR_IPRIV(cr), &CR_EPRIV(cr));
		priv_intersect(&CR_IPRIV(cr), &CR_PPRIV(cr));
	}

	CR_FLAGS(cr) &= ~(PRIV_AWARE|PRIV_AWARE_RESET);
}

/*
 * Reset privilege aware bit if so requested by setting the PRIV_AWARE_RESET
 * flag.
 */
void
priv_reset_PA(cred_t *cr, boolean_t finalize)
{
	ASSERT(cr->cr_ref <= 2);

	if ((CR_FLAGS(cr) & (PRIV_AWARE|PRIV_AWARE_RESET)) !=
	    (PRIV_AWARE|PRIV_AWARE_RESET)) {
		CR_FLAGS(cr) &= ~PRIV_AWARE_RESET;
		return;
	}

	/*
	 * When PRIV_AWARE_RESET is enabled, any change of uids causes
	 * a change to the P and E sets.  Bracketing with
	 * seteuid(0) ... seteuid(uid)/setreuid(-1, 0) .. setreuid(-1, uid)
	 * will cause the privilege sets "do the right thing.".
	 * When the change of the uid is "final", e.g., by using setuid(uid),
	 * or setreuid(uid, uid) or when the last set*uid() call causes all
	 * uids to be the same, we set P and E to I & L, like when you exec.
	 * We make an exception when all the uids are 0; this is required
	 * when we login as root as in that particular case we cannot
	 * make a distinction between seteuid(0) and seteuid(uid).
	 * We rely on seteuid/setreuid/setuid to tell us with the
	 * "finalize" argument that we no longer expect new uid changes,
	 * cf. setreuid(uid, uid) and setuid(uid).
	 */
	if (cr->cr_suid == cr->cr_ruid && cr->cr_suid == cr->cr_uid) {
		if (finalize || cr->cr_uid != 0) {
			CR_EPRIV(cr) = CR_IPRIV(cr);
			priv_intersect(&CR_LPRIV(cr), &CR_EPRIV(cr));
			CR_PPRIV(cr) = CR_EPRIV(cr);
			CR_FLAGS(cr) &= ~(PRIV_AWARE|PRIV_AWARE_RESET);
		} else {
			CR_EPRIV(cr) = CR_PPRIV(cr);
		}
	} else if (cr->cr_uid != 0 && (cr->cr_ruid == 0 || cr->cr_suid == 0)) {
		CR_EPRIV(cr) = CR_IPRIV(cr);
		priv_intersect(&CR_LPRIV(cr), &CR_EPRIV(cr));
	}
}
