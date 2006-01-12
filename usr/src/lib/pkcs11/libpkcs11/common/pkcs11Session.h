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

#ifndef	_PKCS11_SESSION_H
#define	_PKCS11_SESSION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PKCS11_SESSION_MAGIC	0xECF00001

typedef struct pkcs11_session {

	ulong_t			se_magic; /* ensure this is a valid session */
	CK_SESSION_HANDLE	se_handle; /* from slot's C_OpenSession() */
	CK_SLOT_ID		se_slotid; /* slotID in framework */
	struct pkcs11_session	*se_prev;	/* Chain of sessions  */
	struct pkcs11_session	*se_next; 	/* in this slot */

} pkcs11_session_t;


/*
 * This macro is used to typecast a session handle to a pointer
 * to a session structure.  It also checks to see if the session
 * is tagged with a session magic number.  This is to detect when an
 * application passes a bogus session pointer.
 */
#define	HANDLE2SESSION(hSession, sessionp, rv)\
		sessionp = (pkcs11_session_t *)(hSession);	\
		rv = CKR_OK;					\
		if ((sessionp == NULL) || 			\
		    (sessionp->se_magic != PKCS11_SESSION_MAGIC)) \
			rv = CKR_SESSION_HANDLE_INVALID;


struct pkcs11_slot;

extern CK_RV pkcs11_session_add(struct pkcs11_slot *pslot, CK_SLOT_ID slot_id,
	CK_SESSION_HANDLE_PTR pfwhandle, CK_SESSION_HANDLE prov_sess);

extern void pkcs11_session_delete(struct pkcs11_slot *pslot,
	pkcs11_session_t *psess);

extern void pkcs11_sessionlist_delete(struct pkcs11_slot *pslot);

#ifdef	__cplusplus
}
#endif

#endif /* _PKCS11_SESSION_H */
