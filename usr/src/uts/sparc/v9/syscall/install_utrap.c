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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/machpcb.h>
#include <sys/utrap.h>
#include <sys/model.h>

int
install_utrap(utrap_entry_t type, utrap_handler_t new_handler,
	utrap_handler_t *old_handlerp)
{
	struct proc *p = curthread->t_procp;
	utrap_handler_t *ov, *nv, *pv, *sv, *tmp;
	caddr32_t nv32;
	int idx;

	/*
	 * Check trap number.
	 */
	switch (type) {
	case UTRAP_V8P_FP_DISABLED:
#ifdef SF_ERRATA_30 /* call causes fp-disabled */
		{
		extern int spitfire_call_bug;

		if (spitfire_call_bug)
			return ((int)set_errno(ENOSYS));
		}
#endif /* SF_ERRATA_30 */
		idx = UTRAP_V8P_FP_DISABLED;
		break;
	case UTRAP_V8P_MEM_ADDRESS_NOT_ALIGNED:
		idx = UTRAP_V8P_MEM_ADDRESS_NOT_ALIGNED;
		break;
	default:
		return ((int)set_errno(EINVAL));
	}
	if (get_udatamodel() == DATAMODEL_LP64)
		return ((int)set_errno(EINVAL));

	/*
	 * Be sure handler address is word aligned.  The uintptr_t casts are
	 * there to prevent warnings when using a certain compiler, and the
	 * temporary 32 bit variable is intended to ensure proper code
	 * generation and avoid a messy quadruple cast.
	 */
	nv32 = (caddr32_t)(uintptr_t)new_handler;
	nv = (utrap_handler_t *)(uintptr_t)nv32;
	if (nv != UTRAP_UTH_NOCHANGE) {
		if (((uintptr_t)nv) & 0x3)
			return ((int)set_errno(EINVAL));
	}
	/*
	 * Allocate proc space for saving the addresses to these user
	 * trap handlers, which must later be freed. Use atomic_cas_ptr to
	 * do this atomically.
	 */
	if (p->p_utraps == NULL) {
		pv = sv = kmem_zalloc((UT_PRECISE_MAXTRAPS+1) *
		    sizeof (utrap_handler_t *), KM_SLEEP);
		tmp = atomic_cas_ptr(&p->p_utraps, NULL, sv);
		if (tmp != NULL) {
			kmem_free(pv, (UT_PRECISE_MAXTRAPS+1) *
			    sizeof (utrap_handler_t *));
		}
	}
	ASSERT(p->p_utraps != NULL);

	/*
	 * Use atomic_cas_ptr to atomically install the handler.
	 */
	ov = p->p_utraps[idx];
	if (new_handler != (utrap_handler_t)UTRAP_UTH_NOCHANGE) {
		for (;;) {
			tmp = atomic_cas_ptr(&p->p_utraps[idx], ov, nv);
			if (ov == tmp)
				break;
			ov = tmp;
		}
	}
	if (old_handlerp != NULL) {
		if (suword32(old_handlerp, (uint32_t)(uintptr_t)ov) == -1)
			return ((int)set_errno(EINVAL));
	}
	return (0);
}

void
utrap_dup(struct proc *pp, struct proc *cp)
{
	if (pp->p_utraps != NULL) {
		cp->p_utraps = kmem_alloc((UT_PRECISE_MAXTRAPS+1) *
		    sizeof (utrap_handler_t *), KM_SLEEP);
		bcopy(pp->p_utraps, cp->p_utraps,
		    (UT_PRECISE_MAXTRAPS+1) * sizeof (utrap_handler_t *));
	} else {
		cp->p_utraps = NULL;
	}
}

void
utrap_free(struct proc *p)
{
	/* Free any kmem_alloc'ed space for user trap handlers. */
	if (p->p_utraps != NULL) {
		kmem_free(p->p_utraps, (UT_PRECISE_MAXTRAPS+1) *
		    sizeof (utrap_handler_t *));
		p->p_utraps = NULL;
	}
}

/*
 * The code below supports the set of user traps which are required and
 * "must be provided by all ABI-conforming implementations", according to
 * 3.3.3 User Traps of the SPARC V9 ABI SUPPLEMENT, Delta Document 1.38.
 * There is only 1 deferred trap in Ultra I&II, the asynchronous error
 * traps, which are not required, so the deferred args are not used.
 */
/*ARGSUSED*/
int
sparc_utrap_install(utrap_entry_t type,
	utrap_handler_t new_precise, utrap_handler_t new_deferred,
	utrap_handler_t *old_precise, utrap_handler_t *old_deferred)
{
	struct proc *p = curthread->t_procp;
	utrap_handler_t *ov, *nvp, *pv, *sv, *tmp;
	int idx;

	/*
	 * Check trap number.
	 */
	switch (type) {
	case UT_ILLTRAP_INSTRUCTION:
		idx = UT_ILLTRAP_INSTRUCTION;
		break;
	case UT_FP_DISABLED:
#ifdef SF_ERRATA_30 /* call causes fp-disabled */
		{
		extern int spitfire_call_bug;

		if (spitfire_call_bug)
			return ((int)set_errno(ENOSYS));
		}
#endif /* SF_ERRATA_30 */
		idx = UT_FP_DISABLED;
		break;
	case UT_FP_EXCEPTION_IEEE_754:
		idx = UT_FP_EXCEPTION_IEEE_754;
		break;
	case UT_TAG_OVERFLOW:
		idx = UT_TAG_OVERFLOW;
		break;
	case UT_DIVISION_BY_ZERO:
		idx = UT_DIVISION_BY_ZERO;
		break;
	case UT_MEM_ADDRESS_NOT_ALIGNED:
		idx = UT_MEM_ADDRESS_NOT_ALIGNED;
		break;
	case UT_PRIVILEGED_ACTION:
		idx = UT_PRIVILEGED_ACTION;
		break;
	case UT_TRAP_INSTRUCTION_16:
	case UT_TRAP_INSTRUCTION_17:
	case UT_TRAP_INSTRUCTION_18:
	case UT_TRAP_INSTRUCTION_19:
	case UT_TRAP_INSTRUCTION_20:
	case UT_TRAP_INSTRUCTION_21:
	case UT_TRAP_INSTRUCTION_22:
	case UT_TRAP_INSTRUCTION_23:
	case UT_TRAP_INSTRUCTION_24:
	case UT_TRAP_INSTRUCTION_25:
	case UT_TRAP_INSTRUCTION_26:
	case UT_TRAP_INSTRUCTION_27:
	case UT_TRAP_INSTRUCTION_28:
	case UT_TRAP_INSTRUCTION_29:
	case UT_TRAP_INSTRUCTION_30:
	case UT_TRAP_INSTRUCTION_31:
		idx = type;
		break;
	default:
		return ((int)set_errno(EINVAL));
	}

	if (get_udatamodel() == DATAMODEL_ILP32)
		return ((int)set_errno(EINVAL));

	/*
	 * Be sure handler address is word aligned.
	 * There are no deferred traps, so ignore them.
	 */
	nvp = (utrap_handler_t *)new_precise;
	if (nvp != UTRAP_UTH_NOCHANGE) {
		if (((uintptr_t)nvp) & 0x3)
			return ((int)set_errno(EINVAL));
	}

	/*
	 * Allocate proc space for saving the addresses to these user
	 * trap handlers, which must later be freed. Use atomic_cas_ptr to
	 * do this atomically.
	 */
	if (p->p_utraps == NULL) {
		pv = sv = kmem_zalloc((UT_PRECISE_MAXTRAPS+1) *
		    sizeof (utrap_handler_t *), KM_SLEEP);
		tmp = atomic_cas_ptr(&p->p_utraps, NULL, sv);
		if (tmp != NULL) {
			kmem_free(pv, (UT_PRECISE_MAXTRAPS+1) *
			    sizeof (utrap_handler_t *));
		}
	}
	ASSERT(p->p_utraps != NULL);

	/*
	 * Use atomic_cas_ptr to atomically install the handlers.
	 */
	ov = p->p_utraps[idx];
	if (new_precise != (utrap_handler_t)UTH_NOCHANGE) {
		for (;;) {
			tmp = atomic_cas_ptr(&p->p_utraps[idx], ov, nvp);
			if (ov == tmp)
				break;
			ov = tmp;
		}
	}
	if (old_precise != NULL) {
		if (suword64(old_precise, (uint64_t)ov) == -1)
			return ((int)set_errno(EINVAL));
	}
	return (0);
}
