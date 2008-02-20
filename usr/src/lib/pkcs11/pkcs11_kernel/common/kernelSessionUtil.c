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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <pthread.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/crypto/ioctl.h>
#include <security/cryptoki.h>
#include "kernelGlobal.h"
#include "kernelSession.h"
#include "kernelSlot.h"
#include "kernelEmulate.h"

static pthread_mutex_t delete_sessions_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Delete all the sessions. First, obtain the slot lock.
 * Then start to delete one session at a time.  The boolean wrapper_only
 * argument indicates that whether the caller only wants to clean up the
 * session wrappers and the object wrappers in the library.
 * - When this function is called by C_CloseAllSessions or indirectly by
 *   C_Finalize, wrapper_only is FALSE.
 * - When this function is called by cleanup_child, wrapper_only is TRUE.
 */
void
kernel_delete_all_sessions(CK_SLOT_ID slotID, boolean_t wrapper_only)
{
	kernel_session_t *session_p;
	kernel_slot_t *pslot;

	(void) pthread_mutex_lock(&delete_sessions_mutex);

	pslot = slot_table[slotID];

	/*
	 * Delete all the sessions in the slot's session list.
	 * The routine kernel_delete_session() updates the linked list.
	 * So, we do not need to maintain the list here.
	 */
	for (;;) {
		(void) pthread_mutex_lock(&pslot->sl_mutex);
		if (pslot->sl_sess_list == NULL)
			break;

		session_p = pslot->sl_sess_list;
		/*
		 * Set SESSION_IS_CLOSING flag so any access to this
		 * session will be rejected.
		 */
		(void) pthread_mutex_lock(&session_p->session_mutex);
		if (session_p->ses_close_sync & SESSION_IS_CLOSING) {
			(void) pthread_mutex_unlock(&session_p->session_mutex);
			continue;
		}
		session_p->ses_close_sync |= SESSION_IS_CLOSING;
		(void) pthread_mutex_unlock(&session_p->session_mutex);

		(void) pthread_mutex_unlock(&pslot->sl_mutex);
		kernel_delete_session(slotID, session_p, B_FALSE, wrapper_only);
	}
	(void) pthread_mutex_unlock(&pslot->sl_mutex);
	(void) pthread_mutex_unlock(&delete_sessions_mutex);
}

/*
 * Create a new session struct, and add it to the slot's session list.
 *
 * This function is called by C_OpenSession(), which hold the slot lock.
 */
CK_RV
kernel_add_session(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
	CK_NOTIFY notify, CK_ULONG *sessionhandle_p)
{
	CK_RV rv = CKR_OK;
	kernel_session_t *new_sp = NULL;
	crypto_open_session_t open_session;
	kernel_slot_t	*pslot;
	int r;

	/* Allocate a new session struct */
	new_sp = calloc(1, sizeof (kernel_session_t));
	if (new_sp == NULL) {
		return (CKR_HOST_MEMORY);
	}

	new_sp->magic_marker = KERNELTOKEN_SESSION_MAGIC;
	new_sp->pApplication = pApplication;
	new_sp->Notify = notify;
	new_sp->flags = flags;
	new_sp->ses_RO = (flags & CKF_RW_SESSION) ? B_FALSE : B_TRUE;
	new_sp->ses_slotid = slotID;
	new_sp->object_list = NULL;
	new_sp->ses_refcnt = 0;
	new_sp->ses_close_sync = 0;

	/* Initialize the lock for the newly created session */
	if (pthread_mutex_init(&new_sp->session_mutex, NULL) != 0) {
		free(new_sp);
		return (CKR_CANT_LOCK);
	}

	pslot = slot_table[slotID];
	open_session.os_provider_id = pslot->sl_provider_id;
	open_session.os_flags = flags;
	while ((r = ioctl(kernel_fd, CRYPTO_OPEN_SESSION, &open_session)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(open_session.os_return_value);
	}

	if (rv != CKR_OK) {
		(void) pthread_mutex_destroy(&new_sp->session_mutex);
		free(new_sp);
		return (rv);
	}

	new_sp->k_session = open_session.os_session;

	(void) pthread_mutex_init(&new_sp->ses_free_mutex, NULL);
	(void) pthread_cond_init(&new_sp->ses_free_cond, NULL);

	/* Insert the new session in front of the slot's session list */
	if (pslot->sl_sess_list == NULL) {
		pslot->sl_sess_list = new_sp;
		new_sp->prev = NULL;
		new_sp->next = NULL;
	} else {
		pslot->sl_sess_list->prev = new_sp;
		new_sp->next = pslot->sl_sess_list;
		new_sp->prev = NULL;
		pslot->sl_sess_list = new_sp;
	}

	/* Type casting the address of a session struct to a session handle */
	*sessionhandle_p =  (CK_ULONG)new_sp;

	return (CKR_OK);
}

/*
 * Delete a session:
 * - Remove the session from the slot's session list.
 * - Release all the objects created by the session.
 *
 * The boolean argument slot_lock_held is used to indicate that whether
 * the caller of this function holds the slot lock or not.
 * - When called by kernel_delete_all_sessions(), which is called by
 *   C_Finalize() or C_CloseAllSessions() -- slot_lock_held = TRUE.
 * - When called by C_CloseSession() -- slot_lock_held = FALSE.
 */
void
kernel_delete_session(CK_SLOT_ID slotID, kernel_session_t *session_p,
    boolean_t slot_lock_held, boolean_t wrapper_only)
{
	crypto_session_id_t k_session;
	crypto_close_session_t close_session;
	kernel_slot_t	*pslot;
	kernel_object_t *objp;
	kernel_object_t *objp1;

	/*
	 * Check to see if the caller holds the lock on the global
	 * session list. If not, we need to acquire that lock in
	 * order to proceed.
	 */
	pslot = slot_table[slotID];
	if (!slot_lock_held) {
		/* Acquire the slot lock */
		(void) pthread_mutex_lock(&pslot->sl_mutex);
	}

	/*
	 * Remove the session from the slot's session list first.
	 */
	if (pslot->sl_sess_list == session_p) {
		/* Session is the first one in the list */
		if (session_p->next) {
			pslot->sl_sess_list = session_p->next;
			session_p->next->prev = NULL;
		} else {
			/* Session is the only one in the list */
			pslot->sl_sess_list = NULL;
		}
	} else {
		/* Session is not the first one in the list */
		if (session_p->next) {
			/* Session is in the middle of the list */
			session_p->prev->next = session_p->next;
			session_p->next->prev = session_p->prev;
		} else {
			/* Session is the last one in the list */
			session_p->prev->next = NULL;
		}
	}

	if (!slot_lock_held) {
		/*
		 * If the slot lock is obtained by
		 * this function, then release that lock after
		 * removing the session from session linked list.
		 * We want the releasing of the objects of the
		 * session, and freeing of the session itself to
		 * be done without holding the slot's session list
		 * lock.
		 */
		(void) pthread_mutex_unlock(&pslot->sl_mutex);
	}

	/* Acquire the individual session lock */
	(void) pthread_mutex_lock(&session_p->session_mutex);

	/*
	 * Make sure another thread hasn't freed the session.
	 */
	if (session_p->magic_marker != KERNELTOKEN_SESSION_MAGIC) {
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		return;
	}

	/*
	 * The deletion of a session must be blocked when the session reference
	 * count is not zero. This means that if the thread that is attempting
	 * to close the session must wait until the prior operations on this
	 * session are finished.
	 */
	(void) pthread_mutex_lock(&session_p->ses_free_mutex);

	while (session_p->ses_refcnt != 0) {
		/*
		 * We set the SESSION_REFCNT_WAITING flag before we put
		 * this closing thread in a wait state, so other non-closing
		 * operation thread will wake it up only when
		 * the session reference count becomes zero and this flag
		 * is set.
		 */
		session_p->ses_close_sync |= SESSION_REFCNT_WAITING;
		(void) pthread_mutex_unlock(&session_p->session_mutex);
		(void) pthread_cond_wait(&session_p->ses_free_cond,
		    &session_p->ses_free_mutex);
		(void) pthread_mutex_lock(&session_p->session_mutex);
	}

	session_p->ses_close_sync &= ~SESSION_REFCNT_WAITING;

	/* Mark session as no longer valid. */
	session_p->magic_marker = 0;

	(void) pthread_mutex_unlock(&session_p->ses_free_mutex);
	(void) pthread_mutex_destroy(&session_p->ses_free_mutex);
	(void) pthread_cond_destroy(&session_p->ses_free_cond);

	/*
	 * Remove all the objects created in this session, waiting
	 * until each object's refcnt is 0.
	 */
	kernel_delete_all_objects_in_session(session_p, wrapper_only);

	/* In case application did not call Final */
	if (session_p->digest.context != NULL) {
		digest_buf_t *bufp = session_p->digest.context;

		if (bufp->buf != NULL) {
			free_soft_ctx(get_sp(&session_p->digest), OP_DIGEST);
			bzero(bufp->buf, bufp->indata_len);
			free(bufp->buf);
		}
		free(bufp);
	}

	if (session_p->encrypt.context != NULL)
		free(session_p->encrypt.context);

	if (session_p->decrypt.context != NULL)
		free(session_p->decrypt.context);

	if (session_p->sign.context != NULL) {
		digest_buf_t *bufp = session_p->sign.context;

		if (bufp->buf != NULL) {
			free_soft_ctx(get_sp(&session_p->sign), OP_SIGN);
			bzero(bufp->buf, bufp->indata_len);
			free(bufp->buf);
		}
		free(bufp);
	}

	if (session_p->verify.context != NULL) {
		digest_buf_t *bufp = session_p->verify.context;

		if (bufp->buf != NULL) {
			free_soft_ctx(get_sp(&session_p->verify), OP_VERIFY);
			bzero(bufp->buf, bufp->indata_len);
			free(bufp->buf);
		}
		free(bufp);
	}

	k_session = session_p->k_session;

	/* Reset SESSION_IS_CLOSING flag. */
	session_p->ses_close_sync &= ~SESSION_IS_CLOSING;

	(void) pthread_mutex_unlock(&session_p->session_mutex);
	/* Destroy the individual session lock */
	(void) pthread_mutex_destroy(&session_p->session_mutex);

	if (!wrapper_only) {
		close_session.cs_session = k_session;
		while (ioctl(kernel_fd, CRYPTO_CLOSE_SESSION,
		    &close_session) < 0) {
			if (errno != EINTR)
				break;
		}
		/*
		 * Ignore ioctl return codes. If the library tells the kernel
		 * to close a session and the kernel says "I don't know what
		 * session you're talking about", there's not much that can be
		 * done.  All sessions in the kernel will be closed when the
		 * application exits and closes /dev/crypto.
		 */
	}
	kernel_session_delay_free(session_p);

	/*
	 * If there is no more session remained in this slot, reset the slot's
	 * session state to CKU_PUBLIC.  Also, clean up all the token object
	 * wrappers in the library for this slot.
	 */
	/* Acquire the slot lock if lock is not held */
	if (!slot_lock_held) {
		(void) pthread_mutex_lock(&pslot->sl_mutex);
	}

	if (pslot->sl_sess_list == NULL) {
		/* Reset the session auth state. */
		pslot->sl_state = CKU_PUBLIC;

		/* Clean up token object wrappers. */
		objp = pslot->sl_tobj_list;
		while (objp) {
			objp1 = objp->next;
			(void) pthread_mutex_destroy(&objp->object_mutex);
			(void) kernel_object_delay_free(objp);
			objp = objp1;
		}
		pslot->sl_tobj_list = NULL;
	}

	/* Release the slot lock if lock is not held */
	if (!slot_lock_held) {
		(void) pthread_mutex_unlock(&pslot->sl_mutex);
	}
}

/*
 * This function is used to type cast a session handle to a pointer to
 * the session struct. Also, it does the following things:
 * 1) Check to see if the session struct is tagged with a session
 *    magic number. This is to detect when an application passes
 *    a bogus session pointer.
 * 2) Acquire the locks on the designated session.
 * 3) Check to see if the session is in the closing state that another
 *    thread is performing.
 * 4) Increment the session reference count by one. This is to prevent
 *    this session from being closed by other thread.
 * 5) Release the locks on the designated session.
 */
CK_RV
handle2session(CK_SESSION_HANDLE hSession, kernel_session_t **session_p)
{
	kernel_session_t *sp = (kernel_session_t *)(hSession);
	CK_RV rv;

	if ((sp == NULL) ||
	    (sp->magic_marker != KERNELTOKEN_SESSION_MAGIC)) {
		return (CKR_SESSION_HANDLE_INVALID);
	} else {
		(void) pthread_mutex_lock(&sp->session_mutex);
		if (sp->ses_close_sync & SESSION_IS_CLOSING) {
			rv = CKR_SESSION_CLOSED;
		} else {
			/* Increment session ref count. */
			sp->ses_refcnt++;
			rv = CKR_OK;
		}
		(void) pthread_mutex_unlock(&sp->session_mutex);
	}

	if (rv == CKR_OK)
		*session_p = sp;

	return (rv);
}

/*
 * This function adds the to-be-freed session to a linked list.
 * When the number of sessions queued in the linked list reaches the
 * maximum threshold MAX_SES_TO_BE_FREED, it will free the first
 * session (FIFO) in the list.
 */
void
kernel_session_delay_free(kernel_session_t *sp)
{
	kernel_session_t *tmp;

	(void) pthread_mutex_lock(&ses_delay_freed.ses_to_be_free_mutex);

	/* Add the newly deleted session at the end of the list */
	sp->next = NULL;
	if (ses_delay_freed.first == NULL) {
		ses_delay_freed.last = sp;
		ses_delay_freed.first = sp;
	} else {
		ses_delay_freed.last->next = sp;
		ses_delay_freed.last = sp;
	}

	if (++ses_delay_freed.count >= MAX_SES_TO_BE_FREED) {
		/*
		 * Free the first session in the list only if
		 * the total count reaches maximum threshold.
		 */
		ses_delay_freed.count--;
		tmp = ses_delay_freed.first->next;
		free(ses_delay_freed.first);
		ses_delay_freed.first = tmp;
	}
	(void) pthread_mutex_unlock(&ses_delay_freed.ses_to_be_free_mutex);
}
