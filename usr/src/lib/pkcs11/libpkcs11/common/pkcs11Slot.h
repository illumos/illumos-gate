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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PKCS11_SLOT_H
#define	_PKCS11_SLOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "pkcs11Session.h"

#define	MECHLIST_SIZE	32

/*
 * Used to pass arguments to child threads for C_WaitForSlotEvent.
 */
typedef struct wfse_args {

	CK_FLAGS flags;
	CK_VOID_PTR pReserved;
	CK_SLOT_ID slotid;

} wfse_args_t;

typedef struct pkcs11_slot {

	CK_SLOT_ID		sl_id;  	/* real slotID from provider */
	struct pkcs11_session 	*sl_sess_list;	/* all open sessions */
	pthread_mutex_t		sl_mutex;	/* protects: sl_sess_list, */
						/* sl_tid, sl_wfse_state, */
						/* and sl_wfse_args */
	CK_FUNCTION_LIST_PTR 	sl_func_list;	/* function entry points */
	boolean_t		sl_enabledpol;	/* TRUE if policy for enabled */
	CK_MECHANISM_TYPE_PTR	sl_pol_mechs;	/* policy restricted */
	uint_t			sl_pol_count;	/* policy restricted */
	boolean_t		sl_norandom;	/* TRUE if random is disabled */
	void			*sl_dldesc;	/* from dlopen */
	uint_t			sl_prov_id;	/* set by order read in */
	uchar_t			sl_wfse_state;	/* Used by C_WaitForSlotEvent */
	boolean_t		sl_no_wfse;	/* WaitForSlotEvent not impl */
	pthread_t		sl_tid;		/* Used to track child thread */
	wfse_args_t		*sl_wfse_args;	/* Used for WaitForSlotEvent */

} pkcs11_slot_t;

/*
 * State definitions used for C_WaitForSlotEvent, stored in sl_wfse_state
 * for each slot.  These states are mutually exclusive, ie only one should
 * be set at a time.
 */
#define	WFSE_CLEAR	0x0
#define	WFSE_EVENT	0x1
#define	WFSE_ACTIVE	0x2

/*
 * Dynamically allocated array of slots, indexed by the slotID assigned
 * by the framework.  st_first will be initialized to 1.  Only if there
 * is more than one other slot present, triggering the existence of the
 * metaslot, with st_first be set to 0.  st_last will be set to the
 * last slotID assigned, also used for looping through the slottable.
 */
typedef struct pkcs11_slottable {

	pkcs11_slot_t	**st_slots;
	pthread_mutex_t	st_mutex;	/* Protects all data in the slottable */
					/* except for st_start_cond. */
	CK_SLOT_ID	st_first;	/* First used slot ID, used for loops */
	CK_SLOT_ID	st_last;	/* Last slot ID allocated */
	ulong_t		st_cur_size; 	/* current memory allocated */
	pthread_cond_t  st_wait_cond;   /* Used for C_WaitForSlotEvent */
	CK_SLOT_ID	st_event_slot;	/* Slot with event */
	boolean_t	st_wfse_active; /* A thread is actively running WFSE */
	boolean_t	st_blocking;	/* Blocking for C_WaitForSlotEvent */
	boolean_t	st_list_signaled; /* Listener has been signaled */
	uint_t		st_thr_count;	/* Used for C_WaitForSlotEvent */
	pthread_t	st_tid;
	pthread_mutex_t st_start_mutex; /* wait for listener to start */
	pthread_cond_t	st_start_cond;	/* signal when listener has started */

} pkcs11_slottable_t;


/*
 * This macro is used to quickly derefence from a framework slot ID,
 * provided by an application, to the function pointers for the correct
 * underlying provider.
 */
#define	FUNCLIST(slotID) (slottable->st_slots[(slotID)]->sl_func_list)

/*
 * This macro is used to quickly get the slot ID associated with this
 * slot ID, that is used by the underlying provider.
 */
#define	TRUEID(slotID) (slottable->st_slots[(slotID)]->sl_id)


extern pkcs11_slottable_t *slottable;

extern CK_RV pkcs11_slottable_initialize();
extern CK_RV pkcs11_slottable_increase(ulong_t increase);
extern CK_RV pkcs11_slot_allocate(CK_SLOT_ID *slot);
extern CK_RV pkcs11_slottable_delete();
extern CK_RV pkcs11_is_valid_slot(CK_SLOT_ID slot_id);
extern CK_RV pkcs11_validate_and_convert_slotid(CK_SLOT_ID slot_id,
    CK_SLOT_ID *real_slot_id);

#ifdef __cplusplus
}
#endif

#endif /* _PKCS11_SLOT_H */
