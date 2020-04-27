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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Interrupt Vector Table Configuration
 */

#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/ivintr.h>
#include <sys/intreg.h>
#include <sys/cmn_err.h>
#include <sys/privregs.h>
#include <sys/sunddi.h>

/*
 * Allocate an Interrupt Vector Table and some interrupt vector data structures
 * for the reserved pool as part of the startup code. First try to allocate an
 * interrupt vector data structure from the reserved pool, otherwise allocate it
 * using kmem cache method.
 */
static	kmutex_t intr_vec_mutex;	/* Protect interrupt vector table */

/*
 * Global softint linked list - used by softint mdb dcmd.
 */
static	kmutex_t softint_mutex;		/* Protect global softint linked list */
intr_vec_t	*softint_list = NULL;

/* Reserved pool for interrupt allocation */
intr_vec_t	*intr_vec_pool = NULL;	/* For HW and single target SW intrs */
intr_vecx_t	*intr_vecx_pool = NULL;	/* For multi target SW intrs */
static	kmutex_t intr_vec_pool_mutex;	/* Protect interrupt vector pool */

/* Kmem cache handle for interrupt allocation */
kmem_cache_t	*intr_vec_cache = NULL;	/* For HW and single target SW intrs */
static	kmutex_t intr_vec_cache_mutex;	/* Protect intr_vec_cache usage */

/*
 * init_ivintr() - Initialize an Interrupt Vector Table.
 */
void
init_ivintr()
{
	mutex_init(&intr_vec_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&softint_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&intr_vec_pool_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&intr_vec_cache_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Initialize the reserved interrupt vector data structure pools
	 * used for hardware and software interrupts.
	 */
	intr_vec_pool = (intr_vec_t *)((caddr_t)intr_vec_table +
	    (MAXIVNUM * sizeof (intr_vec_t *)));
	intr_vecx_pool = (intr_vecx_t *)((caddr_t)intr_vec_pool +
	    (MAX_RSVD_IV * sizeof (intr_vec_t)));

	bzero(intr_vec_table, MAXIVNUM * sizeof (intr_vec_t *));
	bzero(intr_vec_pool, MAX_RSVD_IV * sizeof (intr_vec_t));
	bzero(intr_vecx_pool, MAX_RSVD_IVX * sizeof (intr_vecx_t));
}

/*
 * fini_ivintr() - Uninitialize an Interrupt Vector Table.
 */
void
fini_ivintr()
{
	mutex_enter(&intr_vec_cache_mutex);
	if (intr_vec_cache) {
		kmem_cache_destroy(intr_vec_cache);
		intr_vec_cache = NULL;
	}
	mutex_exit(&intr_vec_cache_mutex);

	mutex_destroy(&intr_vec_pool_mutex);
	mutex_destroy(&softint_mutex);
	mutex_destroy(&intr_vec_mutex);
	mutex_destroy(&intr_vec_cache_mutex);
}

/*
 * iv_alloc() - Allocate an interrupt vector data structure.
 *
 * This function allocates an interrupt vector data structure for hardware
 * and single or multi target software interrupts either from the reserved
 * pool or using kmem cache method.
 */
static intr_vec_t *
iv_alloc(softint_type_t type)
{
	intr_vec_t	*iv_p;
	int		i, count;

	count = (type == SOFTINT_MT) ? MAX_RSVD_IVX : MAX_RSVD_IV;

	/*
	 * First try to allocate an interrupt vector data structure from the
	 * reserved pool, otherwise allocate it using kmem_cache_alloc().
	 */
	mutex_enter(&intr_vec_pool_mutex);
	for (i = 0; i < count; i++) {
		iv_p = (type == SOFTINT_MT) ?
		    (intr_vec_t *)&intr_vecx_pool[i] : &intr_vec_pool[i];

		if (iv_p->iv_pil == 0) {
			iv_p->iv_pil = 1;	/* Default PIL */
			break;
		}
	}
	mutex_exit(&intr_vec_pool_mutex);

	if (i < count)
		return (iv_p);

	if (type == SOFTINT_MT)
		cmn_err(CE_PANIC, "iv_alloc: exceeded number of multi "
		    "target software interrupts, %d", MAX_RSVD_IVX);

	/*
	 * If the interrupt vector data structure reserved pool is already
	 * exhausted, then allocate an interrupt vector data structure using
	 * kmem_cache_alloc(), but only for the hardware and single software
	 * interrupts. Create a kmem cache for the interrupt allocation,
	 * if it is not already available.
	 */
	mutex_enter(&intr_vec_cache_mutex);
	if (intr_vec_cache == NULL)
		intr_vec_cache = kmem_cache_create("intr_vec_cache",
		    sizeof (intr_vec_t), 64, NULL, NULL, NULL, NULL, NULL, 0);
	mutex_exit(&intr_vec_cache_mutex);

	iv_p = kmem_cache_alloc(intr_vec_cache, KM_SLEEP);
	bzero(iv_p, sizeof (intr_vec_t));
	iv_p->iv_flags =  IV_CACHE_ALLOC;

	return (iv_p);
}

/*
 * iv_free() - Free an interrupt vector data structure.
 */
static void
iv_free(intr_vec_t *iv_p)
{
	if (iv_p->iv_flags & IV_CACHE_ALLOC) {
		ASSERT(!(iv_p->iv_flags & IV_SOFTINT_MT));
		kmem_cache_free(intr_vec_cache, iv_p);
	} else {
		mutex_enter(&intr_vec_pool_mutex);
		bzero(iv_p, (iv_p->iv_flags & IV_SOFTINT_MT) ?
		    sizeof (intr_vecx_t) : sizeof (intr_vec_t));
		mutex_exit(&intr_vec_pool_mutex);
	}
}

/*
 * add_ivintr() - Add an interrupt handler to the system
 */
int
add_ivintr(uint_t inum, uint_t pil, intrfunc intr_handler,
    caddr_t intr_arg1, caddr_t intr_arg2, caddr_t intr_payload)
{
	intr_vec_t	*iv_p, *new_iv_p;

	if (inum >= MAXIVNUM || pil > PIL_MAX)
		return (EINVAL);

	ASSERT((uintptr_t)intr_handler > KERNELBASE);

	/* Make sure the payload buffer address is 64 bit aligned */
	VERIFY(((uint64_t)intr_payload & 0x7) == 0);

	new_iv_p = iv_alloc(SOFTINT_ST);
	mutex_enter(&intr_vec_mutex);

	for (iv_p = (intr_vec_t *)intr_vec_table[inum];
	    iv_p; iv_p = iv_p->iv_vec_next) {
		if (iv_p->iv_pil == pil) {
			mutex_exit(&intr_vec_mutex);
			iv_free(new_iv_p);
			return (EINVAL);
		}
	}

	ASSERT(iv_p == NULL);

	new_iv_p->iv_handler = intr_handler;
	new_iv_p->iv_arg1 = intr_arg1;
	new_iv_p->iv_arg2 = intr_arg2;
	new_iv_p->iv_payload_buf = intr_payload;
	new_iv_p->iv_pil = (ushort_t)pil;
	new_iv_p->iv_inum = inum;

	new_iv_p->iv_vec_next = (intr_vec_t *)intr_vec_table[inum];
	intr_vec_table[inum] = (uint64_t)new_iv_p;

	mutex_exit(&intr_vec_mutex);
	return (0);
}

/*
 * rem_ivintr() - Remove an interrupt handler from the system
 */
int
rem_ivintr(uint_t inum, uint_t pil)
{
	intr_vec_t	*iv_p, *prev_iv_p;

	if (inum >= MAXIVNUM || pil > PIL_MAX)
		return (EINVAL);

	mutex_enter(&intr_vec_mutex);

	for (iv_p = prev_iv_p = (intr_vec_t *)intr_vec_table[inum];
	    iv_p; prev_iv_p = iv_p, iv_p = iv_p->iv_vec_next)
		if (iv_p->iv_pil == pil)
			break;

	if (iv_p == NULL) {
		mutex_exit(&intr_vec_mutex);
		return (EIO);
	}

	ASSERT(iv_p->iv_pil_next == NULL);

	if (prev_iv_p == iv_p)
		intr_vec_table[inum] = (uint64_t)iv_p->iv_vec_next;
	else
		prev_iv_p->iv_vec_next = iv_p->iv_vec_next;

	mutex_exit(&intr_vec_mutex);

	iv_free(iv_p);
	return (0);
}

/*
 * add_softintr() - add a software interrupt handler to the system
 */
uint64_t
add_softintr(uint_t pil, softintrfunc intr_handler, caddr_t intr_arg1,
    softint_type_t type)
{
	intr_vec_t	*iv_p;

	if (pil > PIL_MAX)
		return ((uint64_t)NULL);

	iv_p = iv_alloc(type);

	iv_p->iv_handler = (intrfunc)intr_handler;
	iv_p->iv_arg1 = intr_arg1;
	iv_p->iv_pil = (ushort_t)pil;
	if (type == SOFTINT_MT)
		iv_p->iv_flags |=  IV_SOFTINT_MT;

	mutex_enter(&softint_mutex);
	if (softint_list)
		iv_p->iv_vec_next = softint_list;
	softint_list = iv_p;
	mutex_exit(&softint_mutex);

	return ((uint64_t)iv_p);
}

/*
 * rem_softintr() - remove a software interrupt handler from the system
 */
int
rem_softintr(uint64_t softint_id)
{
	intr_vec_t	*iv_p = (intr_vec_t *)softint_id;

	ASSERT(iv_p != NULL);

	if (iv_p->iv_flags & IV_SOFTINT_PEND)
		return (EIO);

	ASSERT(iv_p->iv_pil_next == NULL);

	mutex_enter(&softint_mutex);
	if (softint_list == iv_p) {
		softint_list = iv_p->iv_vec_next;
	} else {
		intr_vec_t	*list = softint_list;

		while (list && (list->iv_vec_next != iv_p))
			list = list->iv_vec_next;

		list->iv_vec_next = iv_p->iv_vec_next;
	}
	mutex_exit(&softint_mutex);

	iv_free(iv_p);
	return (0);
}

/*
 * update_softint_arg2() - Update softint arg2.
 *
 * NOTE: Do not grab any mutex in this function since it may get called
 *	 from the high-level interrupt context.
 */
int
update_softint_arg2(uint64_t softint_id, caddr_t intr_arg2)
{
	intr_vec_t	*iv_p = (intr_vec_t *)softint_id;

	ASSERT(iv_p != NULL);

	if (iv_p->iv_flags & IV_SOFTINT_PEND)
		return (EIO);

	iv_p->iv_arg2 = intr_arg2;
	return (0);
}

/*
 * update_softint_pri() - Update softint priority.
 */
int
update_softint_pri(uint64_t softint_id, uint_t pil)
{
	intr_vec_t	*iv_p = (intr_vec_t *)softint_id;

	ASSERT(iv_p != NULL);

	if (pil > PIL_MAX)
		return (EINVAL);

	iv_p->iv_pil = pil;
	return (0);
}
