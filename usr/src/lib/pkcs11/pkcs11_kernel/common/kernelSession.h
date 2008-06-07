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

#ifndef _KERNELSESSION_H
#define	_KERNELSESSION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <sys/crypto/common.h>
#include <security/pkcs11t.h>


#define	KERNELTOKEN_SESSION_MAGIC	0xECF00003

typedef struct crypto_active_op {
	CK_MECHANISM	mech;
	void		*context;
	uint32_t	flags;
} crypto_active_op_t;

#define	EDIGEST_LENGTH  1024

/* Used for emulating digest and HMAC mechs */
typedef struct digest_buf {
	uint8_t		*buf;
	int		buf_len;
	int		indata_len;
	void		*soft_sp;
} digest_buf_t;

/*
 * Definition for flags in crypto_active_op_t
 *
 * CRYPTO_EMULATE flag is set for a digest or sign/verify with a HMAC
 * mechanism, if the session slot has a CRYPTO_LIMITED_HASH_SUPPORT flag set.
 * CRYPTO_EMULATE_USING_SW flag is meaningful only when CRYPTO_EMULATE flag
 * is set. And CRYPTO_EMULATE_UPDATE_DONE flag is meaningful only when
 * CRYPTO_EMULATE_USING_SW flag is set.
 */
#define	CRYPTO_OPERATION_ACTIVE	0x00000001 /* Cryptoki operation is active */
#define	CRYPTO_OPERATION_UPDATE	0x00000002 /* Cryptoki multi-part op active */
#define	CRYPTO_EMULATE		0x00000004 /* op needs emulation */
#define	CRYPTO_EMULATE_USING_SW	0x00000008 /* ... use software */
#define	CRYPTO_EMULATE_UPDATE_DONE 0x00000010 /* did at least one update */
#define	CRYPTO_EMULATE_INIT_DONE 0x00000020 /* did init */

typedef struct session {
	CK_ULONG	magic_marker;	/* magic # be validated for integrity */
	pthread_mutex_t	session_mutex;	/* session's mutex lock */
	pthread_mutex_t ses_free_mutex;	/* mutex used during closing session */
	pthread_cond_t	ses_free_cond;	/* cond variable for signal and wait */
	uint32_t	ses_refcnt;	/* session reference count */
	uint32_t	ses_close_sync;	/* session closing flags */
	crypto_session_id_t k_session;	/* kernel session ID */
	boolean_t	ses_RO;		/* RO or RW session flag */
	CK_SLOT_ID	ses_slotid;	/* slotID saved from C_OpenSession() */

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
	crypto_active_op_t	find_objects;
} kernel_session_t;

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
	kernel_session_t *first; /* points to the first session in the list */
	kernel_session_t *last;  /* points to the last session in the list */
	uint32_t	count;   /* current total sessions in the list */
	pthread_mutex_t ses_to_be_free_mutex;
} ses_to_be_freed_list_t;

extern ses_to_be_freed_list_t ses_delay_freed;

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
 * REFRELE macro does the following:
 * 1) Get the session lock if the caller does not hold it.
 * 2) Decrement the session reference count by one.
 * 3) If the session reference count becomes zero after being decremented,
 *    and there is a closing session thread in the wait state, then
 *    call pthread_cond_signal() to wake up that thread who is blocked
 *    in the session deletion routine due to non-zero reference ount.
 * 4) Always release the session lock.
 */
#define	REFRELE(s, ses_lock_held) { \
	if (!ses_lock_held) \
		(void) pthread_mutex_lock(&s->session_mutex);   \
	if ((--((s)->ses_refcnt) == 0) &&    \
	    (s->ses_close_sync & SESSION_REFCNT_WAITING)) {     \
		(void) pthread_mutex_unlock(&s->session_mutex);   \
		(void) pthread_cond_signal(&s->ses_free_cond); \
	} else {        \
		(void) pthread_mutex_unlock(&s->session_mutex);   \
	}       \
}


/*
 * Function Prototypes.
 */
CK_RV handle2session(CK_SESSION_HANDLE hSession, kernel_session_t **session_p);

void kernel_delete_all_sessions(CK_SLOT_ID slotID, boolean_t wrapper_only);

void kernel_delete_all_objects_in_session(kernel_session_t *sp,
    boolean_t wrapper_only);

CK_RV kernel_add_session(CK_SLOT_ID slotID, CK_FLAGS flags,
    CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_ULONG *phSession);

void kernel_delete_session(CK_SLOT_ID slotID, kernel_session_t *sp,
    boolean_t lock_held, boolean_t wrapper_only);

void kernel_session_delay_free(kernel_session_t *sp);

void kernel_acquire_all_slots_mutexes();
void kernel_release_all_slots_mutexes();

#ifdef	__cplusplus
}
#endif

#endif /* _KERNELSESSION_H */
