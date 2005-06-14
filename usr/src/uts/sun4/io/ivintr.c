/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interrupt Vector Table Configuration
 */

#include <sys/cpuvar.h>
#include <sys/ivintr.h>
#include <sys/intreg.h>
#include <sys/cmn_err.h>
#include <sys/privregs.h>
#include <sys/sunddi.h>


/*
 * fill in an interrupt vector entry
 */
#define	fill_intr(a, b, c, d, e) \
	a->iv_pil = b; a->iv_pending = 0; \
	a->iv_arg = d; a->iv_handler = c; a->iv_payload_buf = e;

/*
 * create a null interrupt handler entry used for returned values
 * only - never on intr_vector[]
 */
#define	nullify_intr(v)		fill_intr(v, 0, NULL, NULL, NULL)

/*
 * replace an intr_vector[] entry with a default set of values
 * this is done instead of nulling the entry, so the handler and
 * pil are always valid for the assembler code
 */
#define	empty_intr(v)		fill_intr((v), PIL_MAX, nohandler, \
						(void *)(v), NULL)

/*
 * test whether an intr_vector[] entry points to our default handler
 */
#define	intr_is_empty(v)		((v)->iv_handler == nohandler)

extern uint_t swinum_base;
extern uint_t maxswinum;
extern kmutex_t soft_iv_lock;
int ignore_invalid_vecintr = 0;
uint64_t invalid_vecintr_count = 0;

/*
 * default (non-)handler for otherwise unhandled interrupts
 */
uint_t
nohandler(caddr_t ivptr)
{
	if (!ignore_invalid_vecintr) {
		ASSERT((struct intr_vector *)ivptr - intr_vector < MAXIVNUM);
		return (DDI_INTR_UNCLAIMED);
	} else {
		invalid_vecintr_count++;
		return (DDI_INTR_CLAIMED);
	}
}

/*
 * initialization - fill the entire table with default values
 */
void
init_ivintr(void)
{
	struct intr_vector *inump;
	int i;

	for (inump = intr_vector, i = 0; i <= MAXIVNUM; ++inump, ++i) {
		empty_intr(inump);
	}
}

/*
 * add_ivintr() - add an interrupt handler to the system
 *	This routine is not protected by the lock; it's the caller's
 *	responsibility to make sure <source>_INR.INT_EN = 0
 *	and <source>_ISM != PENDING before the routine is called.
 */
int
add_ivintr(uint_t inum, uint_t pil, intrfunc intr_handler,
    caddr_t intr_arg, caddr_t intr_payload)
{
	struct intr_vector *inump;

	if (inum >= MAXIVNUM || pil > PIL_MAX)
		return (EINVAL);

	ASSERT((uintptr_t)intr_handler > KERNELBASE);
	/* Make sure the payload buffer address is 64 bit aligned */
	VERIFY(((uint64_t)intr_payload & 0x7) == 0);

	inump = &intr_vector[inum];

	if (inump->iv_handler != nohandler)
		return (EINVAL);

	fill_intr(inump, (ushort_t)pil, intr_handler, intr_arg, intr_payload);
	return (0);
}

/*
 * rem_ivintr() - remove an interrupt handler from intr_vector[]
 *	This routine is not protected by the lock; it's the caller's
 *	responsibility to make sure <source>_INR.INT_EN = 0
 *	and <source>_ISM != PENDING before the routine is called.
 */
void
rem_ivintr(uint_t inum, struct intr_vector *iv_return)
{
	struct intr_vector *inump;

	ASSERT(inum != NULL && inum < MAXIVNUM);

	inump = &intr_vector[inum];

	if (iv_return) {
		if (intr_is_empty(inump)) {
			nullify_intr(iv_return);
		} else {
			/*
			 * the caller requires the current entry to be
			 * returned
			 */
			fill_intr(iv_return, inump->iv_pil,
			    inump->iv_handler, inump->iv_arg,
			    inump->iv_payload_buf);
		}
	}

	/*
	 * empty the current entry
	 */
	empty_intr(inump);
}

/*
 * add_softintr() - add a software interrupt handler to the system
 */
uint_t
add_softintr(uint_t pil, softintrfunc intr_handler, caddr_t intr_arg)
{
	struct intr_vector *inump;
	register uint_t i;

	mutex_enter(&soft_iv_lock);

	for (i = swinum_base; i < maxswinum; i++) {
		inump = &intr_vector[i];
		if (intr_is_empty(inump))
			break;
	}

	if (!intr_is_empty(inump)) {
		cmn_err(CE_PANIC, "add_softintr: exceeded %d handlers",
			maxswinum - swinum_base);
	}

	VERIFY(add_ivintr(i, pil, (intrfunc)intr_handler,
	    intr_arg, NULL) == 0);

	mutex_exit(&soft_iv_lock);

	return (i);
}

/*
 * rem_softintr() - remove a software interrupt handler from the system
 */
void
rem_softintr(uint_t inum)
{
	ASSERT(swinum_base <= inum && inum < MAXIVNUM);

	mutex_enter(&soft_iv_lock);
	rem_ivintr(inum, NULL);
	mutex_exit(&soft_iv_lock);
}

int
update_softint_arg2(uint_t intr_id, caddr_t arg2)
{
	struct intr_vector *inump = &intr_vector[intr_id];

	if (inump->iv_pending)
		return (DDI_EPENDING);

	inump->iv_softint_arg2 = arg2;

	return (DDI_SUCCESS);
}

int
update_softint_pri(uint_t intr_id, int pri)
{
	struct intr_vector *inump = &intr_vector[intr_id];

	mutex_enter(&soft_iv_lock);
	inump->iv_pil = pri;
	mutex_exit(&soft_iv_lock);

	return (DDI_SUCCESS);
}
