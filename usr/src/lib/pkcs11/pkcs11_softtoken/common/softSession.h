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

#ifndef _SOFTSESSION_H
#define	_SOFTSESSION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <security/pkcs11t.h>


#define	SOFTTOKEN_SESSION_MAGIC	0xECF00002

/*
 * This is only used by the C_G(S)etOperationState.
 */
#define	DIGEST_OP		1

/*
 * This is only used by the C_G(S)etOperationState.
 */
typedef struct internal_op_state {
	/* Holds the length of the saved state */
	CK_ULONG	op_len;

	/* crypto operation to be saved or restored */
	CK_ULONG	op_active;

	/* Holds the saved session state */
	CK_STATE	op_session_state;

} internal_op_state_t;

typedef struct crypto_active_op {
	CK_MECHANISM	mech;
	void		*context;
	uint32_t	flags;
} crypto_active_op_t;


/*
 * Definition for flags in crypto_active_op_t
 */
#define	CRYPTO_OPERATION_ACTIVE		1 /* Cryptoki operation is active */
#define	CRYPTO_OPERATION_UPDATE		2 /* Cryptoki multi-part op active */
#define	CRYPTO_KEY_DIGESTED		3 /* A C_DigestKey() was called */

typedef struct session {
	ulong_t		magic_marker;	/* magic # be validated for integrity */
	pthread_mutex_t	session_mutex;	/* session's mutex lock */
	pthread_cond_t	ses_free_cond;	/* cond variable for signal and wait */
	uint32_t	ses_refcnt;	/* session reference count */
	uint32_t	ses_close_sync;	/* session closing flags */
	CK_STATE	state;		/* session state */

	/* Place holder for parameters passed in the C_OpenSession */
	CK_FLAGS	flags;
	CK_NOTIFY	Notify;
	CK_VOID_PTR	pApplication;

	/* Pointers to form the global session list */
	struct session	*next;		/* points to next session on the list */
	struct session	*prev;		/* points to prev session on the list */

	struct object	*object_list;	/* points to list of objects */

	crypto_active_op_t	digest;	/* context of active digest operation */
	crypto_active_op_t	encrypt; /* context of active encrypt op */
	crypto_active_op_t	decrypt; /* context of active decrypt op */
	crypto_active_op_t	sign;	/* context of active sign op */
	crypto_active_op_t	verify;	/* context of active verify op */
	/* context of active FindObjects op */
	crypto_active_op_t	find_objects;
} soft_session_t;

/*
 * slot_t is a global structure to be used only by the
 * token objects to hold the token object related
 * in-core information.
 */
typedef struct slot {
	uint_t		ks_version;	/* in-core keystore version number */
	boolean_t	authenticated;	/* Has C_Login called */
	boolean_t	userpin_change_needed; /* set if PIN expired */
	pthread_mutex_t	slot_mutex;
	pthread_mutex_t	keystore_mutex; /* Protects keystore_load_status */
	uint_t		keystore_load_status; /* Keystore load status */
	/* points to in-core token object list */
	struct object	*token_object_list;
} slot_t;

/*
 * The following structure is used to link the to-be-freed sessions
 * into a linked list. The sessions on this linked list have
 * not yet been freed via free() after C_CloseSession() call; instead
 * they are added to this list. The actual free will take place when
 * the number of sessions queued reaches MAX_SES_TO_BE_FREED, at which
 * time the first session in the list will be freed.
 */
#define	MAX_SES_TO_BE_FREED		300

typedef struct ses_to_be_freed_list {
	struct session	*first;	/* points to the first session in the list */
	struct session	*last;	/* points to the last session in the list */
	uint32_t	count;	/* current total sessions in the list */
	pthread_mutex_t	ses_to_be_free_mutex;
} ses_to_be_freed_list_t;

/*
 * Flag definitions for ses_close_sync
 */
#define	SESSION_IS_CLOSING	1	/* Session is in a closing state */
#define	SESSION_REFCNT_WAITING	2	/* Waiting for session reference */
					/* count to become zero */

/*
 * This macro is used to decrement the session reference count by one.
 *
 * The caller of this macro uses the argument lock_held to indicate that
 * whether the caller holds the lock on the session or not.
 *
 * SES_REFRELE macro does the following:
 * 1) Get the session lock if the caller does not hold it.
 * 2) Decrement the session reference count by one.
 * 3) If the session reference count becomes zero after being decremented,
 *    and there is a closing session thread in the wait state, then
 *    call pthread_cond_signal() to wake up that thread who is blocked
 *    in the session deletion routine due to non-zero reference ount.
 * 4) Always release the session lock.
 */
#define	SES_REFRELE(s, lock_held) { \
	if (!lock_held) \
		(void) pthread_mutex_lock(&s->session_mutex);   \
	if ((--((s)->ses_refcnt) == 0) &&    \
	    (s->ses_close_sync & SESSION_REFCNT_WAITING)) {     \
		(void) pthread_mutex_unlock(&s->session_mutex);   \
		(void) pthread_cond_signal(&s->ses_free_cond); \
	} else {        \
		(void) pthread_mutex_unlock(&s->session_mutex);   \
	}       \
}


extern pthread_mutex_t soft_sessionlist_mutex;
extern soft_session_t *soft_session_list;
extern int all_sessions_closing;
extern CK_ULONG soft_session_cnt;	/* the number of opened sessions */
extern CK_ULONG soft_session_rw_cnt;	/* the number of opened R/W sessions */


/*
 * Function Prototypes.
 */
CK_RV handle2session(CK_SESSION_HANDLE hSession, soft_session_t **session_p);

CK_RV soft_delete_all_sessions(boolean_t force);

void soft_delete_all_objects_in_session(soft_session_t *sp);

CK_RV soft_add_session(CK_FLAGS flags, CK_VOID_PTR pApplication,
    CK_NOTIFY notify, CK_ULONG *phSession);

CK_RV soft_delete_session(soft_session_t *sp,
    boolean_t force, boolean_t lock_held);

CK_RV soft_get_operationstate(soft_session_t *, CK_BYTE_PTR, CK_ULONG_PTR);
CK_RV soft_set_operationstate(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
    CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);


/* Token object related function prototypes. */

CK_RV soft_login(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

void soft_logout(void);

void soft_acquire_all_session_mutexes();
void soft_release_all_session_mutexes();

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTSESSION_H */
