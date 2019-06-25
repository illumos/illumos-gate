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

#include <cryptoutil.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <strings.h>
#include "metaGlobal.h"

extern cipher_mechs_threshold_t	meta_mechs_threshold[];
static boolean_t threshold_chk_enabled = B_FALSE;

CK_RV
meta_operation_init_defer(CK_FLAGS optype, meta_session_t *session,
    CK_MECHANISM *pMechanism, meta_object_t *key)
{

	if (session->init.pMech == NULL) {
		session->init.pMech = malloc(sizeof (CK_MECHANISM));
		if (session->init.pMech == NULL)
			return (CKR_HOST_MEMORY);

		(void) memcpy(session->init.pMech, pMechanism,
		    sizeof (CK_MECHANISM));

		if ((pMechanism->ulParameterLen > 0) &&
		    (pMechanism->pParameter != NULL)) {
			session->init.pMech->pParameter =
			    malloc(pMechanism->ulParameterLen);
			if (session->init.pMech->pParameter == NULL) {
				free(session->init.pMech);
				session->init.pMech = NULL;
				return (CKR_HOST_MEMORY);
			}
			(void) memcpy(session->init.pMech->pParameter,
			    pMechanism->pParameter, pMechanism->ulParameterLen);
		} else {
			session->init.pMech->pParameter = NULL;
		}
	} else { /* reuse it */
		if ((pMechanism->ulParameterLen > 0) &&
		    (pMechanism->pParameter != NULL)) {
			if (pMechanism->ulParameterLen !=
			    session->init.pMech->ulParameterLen) {
				if (session->init.pMech->pParameter != NULL)
					free(session->init.pMech->pParameter);
				session->init.pMech->pParameter =
				    malloc(pMechanism->ulParameterLen);
				if (session->init.pMech->pParameter == NULL) {
					free(session->init.pMech);
					session->init.pMech = NULL;
					return (CKR_HOST_MEMORY);
				}
			} /* otherwise reuse it */
			(void) memcpy(session->init.pMech->pParameter,
			    pMechanism->pParameter, pMechanism->ulParameterLen);
		} else {
			/*
			 * free the previous pParameter if not yet freed
			 * because we don't need it now.
			 */
			if (session->init.pMech->pParameter != NULL) {
				free(session->init.pMech->pParameter);
				session->init.pMech->pParameter = NULL;
			}
		}
		/* copy the rest of data */
		session->init.pMech->mechanism =
		    pMechanism->mechanism;
		session->init.pMech->ulParameterLen =
		    pMechanism->ulParameterLen;
	}

	session->init.session = session;
	session->init.optype = optype;
	session->init.key = key;
	session->init.done = B_FALSE;
	session->init.app = B_TRUE;
	return (CKR_OK);
}

/*
 * meta_operation_init
 *
 */
CK_RV
meta_operation_init(CK_FLAGS optype, meta_session_t *session,
    CK_MECHANISM *pMechanism, meta_object_t *key)
{
	CK_RV rv, save_rv;
	mechinfo_t **supporting_slots;
	CK_ULONG slotnum;
	unsigned long i, slotCount = 0;
	slot_session_t *init_session = NULL;
	CK_MECHANISM_INFO mech_info;

	/*
	 * If an operation is already active, cleanup existing operation
	 * and start a new one.
	 */
	if (session->op1.type != 0) {
		CK_MECHANISM mech;
		if ((optype == CKF_ENCRYPT) || (optype == CKF_DECRYPT) ||
		    (optype == CKF_DIGEST)) {
			mech = *pMechanism;

			if ((pMechanism->ulParameterLen > 0) &&
			    (pMechanism->pParameter != NULL)) {
				mech.pParameter =
				    malloc(pMechanism->ulParameterLen);
				if (mech.pParameter == NULL) {
					return (CKR_HOST_MEMORY);
				}
				(void) memcpy(mech.pParameter,
				    pMechanism->pParameter,
				    pMechanism->ulParameterLen);
			} else {
				mech.pParameter = NULL;
				mech.ulParameterLen = 0;
			}

			meta_operation_cleanup(session, session->op1.type,
			    B_FALSE);
			rv = meta_operation_init_defer(optype, session,
			    &mech, key);
			if (mech.pParameter != NULL) {
				free(mech.pParameter);
			}
			if (rv != CKR_OK)
				return (rv);
		} else {
			meta_operation_cleanup(session, session->op1.type,
			    B_FALSE);
		}

	}

	mech_info.flags = optype;

	/*
	 * Get a list of capable slots.
	 *
	 * If the specified mechanism is used in this session last time,
	 * the list of capable slots is already retrieved.  We can save
	 * some processing, and just use that list of slots.
	 */
	if (((session->mech_support_info).mech != pMechanism->mechanism) ||
	    ((session->mech_support_info).num_supporting_slots == 0)) {
		(session->mech_support_info).mech = pMechanism->mechanism;
		rv = meta_mechManager_get_slots(&(session->mech_support_info),
		    B_FALSE, &mech_info);
		if (rv != CKR_OK) {
			goto finish;
		}
	}

	rv = CKR_FUNCTION_FAILED;

	/* The following 2 assignment is just to make the code more readable */
	slotCount = (session->mech_support_info).num_supporting_slots;
	supporting_slots = (session->mech_support_info).supporting_slots;

	/* Attempt to initialize operation on slots until one succeeds. */
	for (i = 0; i < slotCount; i++) {
		slot_object_t *init_key;
		CK_SLOT_ID fw_st_id;

		init_session = NULL;

		slotnum = supporting_slots[i]->slotnum;

		/*
		 * An actual session with the underlying slot is required
		 * for the operation.  When the operation is successfully
		 * completed, the underlying session with the slot
		 * is not released back to the list of available sessions
		 * pool.  This will help if the next operation can
		 * also be done on the same slot, because it avoids
		 * one extra trip to the session pool to get an idle session.
		 * If the operation can't be done on that slot,
		 * we release the session back to the session pool then.
		 */
		if (session->op1.session != NULL) {

			if ((session->op1.session)->slotnum == slotnum) {
				init_session = session->op1.session;
				/*
				 * set it to NULL for now, assign it to
				 * init_session again if it is successful
				 */
				session->op1.session = NULL;
			} else {
				init_session = NULL;
			}

		}

		if (!init_session) {
			rv = meta_get_slot_session(slotnum, &init_session,
			    session->session_flags);
			if (rv != CKR_OK) {
				goto loop_cleanup;
			}
		}

		/* if necessary, ensure a clone of the obj exists in slot */
		if (optype != CKF_DIGEST) {
			rv = meta_object_get_clone(key, slotnum, init_session,
			    &init_key);

			if (rv != CKR_OK) {
				goto loop_cleanup;
			}
		}

		fw_st_id = init_session->fw_st_id;
		switch (optype) {
			case CKF_ENCRYPT:
				rv = FUNCLIST(fw_st_id)->C_EncryptInit(
				    init_session->hSession, pMechanism,
				    init_key->hObject);
				break;
			case CKF_DECRYPT:
				rv = FUNCLIST(fw_st_id)->C_DecryptInit(
				    init_session->hSession, pMechanism,
				    init_key->hObject);
				break;
			case CKF_DIGEST:
				rv = FUNCLIST(fw_st_id)->C_DigestInit(
				    init_session->hSession, pMechanism);
				break;
			case CKF_SIGN:
				rv = FUNCLIST(fw_st_id)->C_SignInit(
				    init_session->hSession, pMechanism,
				    init_key->hObject);
				break;
			case CKF_VERIFY:
				rv = FUNCLIST(fw_st_id)->C_VerifyInit(
				    init_session->hSession, pMechanism,
				    init_key->hObject);
				break;
			case CKF_SIGN_RECOVER:
				rv = FUNCLIST(fw_st_id)->C_SignRecoverInit(
				    init_session->hSession, pMechanism,
				    init_key->hObject);
				break;
			case CKF_VERIFY_RECOVER:
				rv = FUNCLIST(fw_st_id)->C_VerifyRecoverInit(
				    init_session->hSession, pMechanism,
				    init_key->hObject);
				break;

			default:
				/*NOTREACHED*/
				rv = CKR_FUNCTION_FAILED;
				break;
		}

		if (rv == CKR_OK)
			break;

loop_cleanup:
		if (i == 0) {
			save_rv = rv;
		}

		if (init_session) {
			meta_release_slot_session(init_session);
			init_session = NULL;
		}

	}

	if (rv == CKR_OK) {

		/*
		 * If currently stored session is not the one being in use now,
		 * release the previous one and store the current one
		 */
		if ((session->op1.session) &&
		    (session->op1.session != init_session)) {
			meta_release_slot_session(session->op1.session);
		}

		/* Save the session */
		session->op1.session = init_session;
		session->op1.type = optype;

		session->init.slotnum = slotnum;
		session->init.done = B_TRUE;
	} else {
		rv = save_rv;
	}

finish:
	return (rv);
}

/*
 * meta_operation_init_softtoken()
 * It will always do the crypto init operation on softtoken slot.
 */
CK_RV
meta_operation_init_softtoken(CK_FLAGS optype, meta_session_t *session,
    CK_MECHANISM *pMechanism, meta_object_t *key)
{
	CK_RV rv = CKR_FUNCTION_FAILED;
	slot_session_t *init_session = NULL;
	slot_object_t *init_key;
	CK_SLOT_ID fw_st_id;
	CK_ULONG softtoken_slot_num;

	softtoken_slot_num = get_softtoken_slotnum();
	/*
	 * If an operation is already active, cleanup existing operation
	 * and start a new one.
	 */
	if (session->op1.type != 0) {
		CK_MECHANISM mech;
		mech = *pMechanism;

		if ((pMechanism->ulParameterLen > 0) &&
		    (pMechanism->pParameter != NULL)) {
			mech.pParameter =
			    malloc(pMechanism->ulParameterLen);
			if (mech.pParameter == NULL) {
				return (CKR_HOST_MEMORY);
			}
			(void) memcpy(mech.pParameter,
			    pMechanism->pParameter, pMechanism->ulParameterLen);
		} else {
			mech.pParameter = NULL;
			mech.ulParameterLen = 0;
		}

		meta_operation_cleanup(session, session->op1.type, B_FALSE);
		rv = meta_operation_init_defer(optype, session, &mech,
		    key);
		if (mech.pParameter != NULL) {
			free(mech.pParameter);
		}
		if (rv != CKR_OK)
			return (rv);
	}

	/*
	 * An actual session with the underlying slot is required
	 * for the operation.  When the operation is successfully
	 * completed, the underlying session with the slot
	 * is not released back to the list of available sessions
	 * pool.  This will help if the next operation can
	 * also be done on the same slot, because it avoids
	 * one extra trip to the session pool to get an idle session.
	 * If the operation can't be done on that slot,
	 * we release the session back to the session pool.
	 */
	if (session->op1.session != NULL) {
		if ((session->op1.session)->slotnum ==
		    softtoken_slot_num) {
			init_session = session->op1.session;
			/*
			 * set it to NULL for now, assign it to
			 * init_session again if it is successful
			 */
			session->op1.session = NULL;
		} else {
			init_session = NULL;
		}
	}

	if (init_session == NULL) {
		/* get the active session from softtoken slot */
		rv = meta_get_slot_session(softtoken_slot_num,
		    &init_session, session->session_flags);
		if (rv != CKR_OK) {
			goto finish;
		}
	}

	/* if necessary, ensure a clone of the obj exists in softtoken slot */
	if (optype != CKF_DIGEST) {
		rv = meta_object_get_clone(key, softtoken_slot_num,
		    init_session, &init_key);

		if (rv != CKR_OK) {
			if (init_session != NULL) {
				meta_release_slot_session(init_session);
				init_session = NULL;
			}
			goto finish;
		}
	}

	fw_st_id = init_session->fw_st_id;

	/*
	 * Currently, we only support offloading encrypt, decrypt
	 * and digest operations to softtoken based on kernel
	 * threshold for the supported mechanisms.
	 */
	switch (optype) {
		case CKF_ENCRYPT:
			rv = FUNCLIST(fw_st_id)->C_EncryptInit(
			    init_session->hSession, pMechanism,
			    init_key->hObject);
			break;
		case CKF_DECRYPT:
			rv = FUNCLIST(fw_st_id)->C_DecryptInit(
			    init_session->hSession, pMechanism,
			    init_key->hObject);
			break;
		case CKF_DIGEST:
			rv = FUNCLIST(fw_st_id)->C_DigestInit(
			    init_session->hSession, pMechanism);
			break;

		default:
			/*NOTREACHED*/
			rv = CKR_FUNCTION_FAILED;
			break;
	}

	if (rv == CKR_OK) {

		/*
		 * If currently stored session is not the one being in use now,
		 * release the previous one and store the current one
		 */
		if ((session->op1.session) &&
		    (session->op1.session != init_session)) {
			meta_release_slot_session(session->op1.session);
		}

		/* Save the session */
		session->op1.session = init_session;
		session->op1.type = optype;
		/*
		 * The init.done flag will be checked by the meta_do_operation()
		 * to indicate whether the C_xxxInit has been done against
		 * softtoken.
		 */
		session->init.done = B_TRUE;
		session->init.slotnum = softtoken_slot_num;
	}

finish:
	return (rv);
}

int
meta_GetThreshold(CK_MECHANISM_TYPE mechanism)
{

	int i;

	for (i = 0; i < MAX_NUM_THRESHOLD; i++) {
		if (mechanism == meta_mechs_threshold[i].mech_type)
			return (meta_mechs_threshold[i].mech_threshold);
	}

	/* no matching mechanism */
	return (0);
}

/*
 * meta_do_operation
 *
 * NOTES:
 *
 * 1) The spec says you cannot do a C_Encrypt after a C_EncUpdate,
 *    but we don't explicitly enforce it here (ie, disallow doing MODE_SINGLE
 *    after a MODE_UPDATE). Instead, we just assume the underlying provider
 *    will catch the problem and return an appropriate error.
 *
 * 2) Note that the Verify operations are a little unusual, due to the
 *    PKCS#11 API. For C_Verify, the last two arguments are used as inputs,
 *    unlike the other single pass operations (where they are outputs). For
 *    C_VerifyFinal, in/inLen are passed instead of out/outLen like the other
 *    Final operations.
 *
 * 3) C_DigestKey is the only crypto operation that uses an object after
 *    the operation has been initialized. No other callers should provide
 *    this argument (use NULL).
 */
CK_RV
meta_do_operation(CK_FLAGS optype, int mode,
    meta_session_t *session, meta_object_t *object,
    CK_BYTE *in, CK_ULONG inLen, CK_BYTE *out, CK_ULONG *outLen)
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_SLOT_ID fw_st_id;
	slot_session_t *slot_session = NULL;
	slot_object_t *slot_object = NULL;
	int threshold = 0;

	boolean_t shutdown, finished_normally;

	/*
	 * We've deferred the init for encrypt, decrypt and digest
	 * operations. As we know the size of the input data now, we
	 * can decide where to perform the real init operation based
	 * on the kernel cipher-specific thresholds for certain
	 * supported mechanisms.
	 */
	if ((optype == CKF_ENCRYPT) || (optype == CKF_DECRYPT) ||
	    (optype == CKF_DIGEST)) {
		if (Tmp_GetThreshold != NULL) {
			if (!session->init.app) {
				return (CKR_OPERATION_NOT_INITIALIZED);
			}
			threshold = meta_GetThreshold(
			    session->init.pMech->mechanism);
		}

		if ((threshold_chk_enabled == B_FALSE) || (inLen > threshold)) {
			if ((session->init.app) && (!session->init.done)) {
				/*
				 * Call real init operation only if the
				 * application has called C_xxxInit
				 * but the real init operation has not
				 * been done.
				 */
				rv = meta_operation_init(optype,
				    session->init.session,
				    session->init.pMech,
				    session->init.key);
				if (rv != CKR_OK)
					goto exit;
			} else if (!session->init.app) {
				/*
				 * This checking detects the case that
				 * application calls C_En(De)Crypt/Digest
				 * directly without calling C_xxxInit.
				 */
				return (CKR_OPERATION_NOT_INITIALIZED);
			}
		} else {
			/*
			 * The size of the input data is smaller than the
			 * threshold so we'll use softoken to perform the
			 * crypto operation for better performance reason.
			 */
			if ((session->init.app) && (!session->init.done))  {
				/*
				 * Call real init operation only if the
				 * application has called C_xxxInit
				 * but the real init operation has not
				 * been done.
				 */
				rv = meta_operation_init_softtoken(optype,
				    session->init.session,
				    session->init.pMech,
				    session->init.key);
				if (rv != CKR_OK) {
					/*
					 * In case the operation fails in
					 * softtoken, go back to use the
					 * original slot again.
					 */
					rv = meta_operation_init(optype,
					    session->init.session,
					    session->init.pMech,
					    session->init.key);
					if (rv != CKR_OK)
						goto exit;
				}
			} else if (!session->init.app) {
				/*
				 * This checking detects the case that
				 * application calls C_En(De)Crypt/Digest
				 * directly without calling C_xxxInit.
				 */
				return (CKR_OPERATION_NOT_INITIALIZED);
			}
		}
	} else if (optype != session->op1.type) {
			return (CKR_OPERATION_NOT_INITIALIZED);
	}

	slot_session = session->op1.session;

	if (slot_session) {
		hSession = slot_session->hSession;
		fw_st_id = slot_session->fw_st_id;
	} else {
		/* should never be here */
		rv = CKR_FUNCTION_FAILED;
		goto exit;
	}

	/* Do the operation... */
	if (optype == CKF_ENCRYPT && mode == MODE_SINGLE) {
			rv = FUNCLIST(fw_st_id)->C_Encrypt(hSession, in,
			    inLen, out, outLen);
	} else if (optype == CKF_ENCRYPT && mode == MODE_UPDATE) {
			rv = FUNCLIST(fw_st_id)->C_EncryptUpdate(hSession, in,
			    inLen, out, outLen);
	} else if (optype == CKF_ENCRYPT && mode == MODE_FINAL) {
			rv = FUNCLIST(fw_st_id)->C_EncryptFinal(hSession, out,
			    outLen);

	} else if (optype == CKF_DECRYPT && mode == MODE_SINGLE) {
			rv = FUNCLIST(fw_st_id)->C_Decrypt(hSession, in,
			    inLen, out, outLen);
	} else if (optype == CKF_DECRYPT && mode == MODE_UPDATE) {
			rv = FUNCLIST(fw_st_id)->C_DecryptUpdate(hSession, in,
			    inLen, out, outLen);
	} else if (optype == CKF_DECRYPT && mode == MODE_FINAL) {
			rv = FUNCLIST(fw_st_id)->C_DecryptFinal(hSession, out,
			    outLen);

	} else if (optype == CKF_DIGEST && mode == MODE_SINGLE) {
			rv = FUNCLIST(fw_st_id)->C_Digest(hSession, in, inLen,
			    out, outLen);
	} else if (optype == CKF_DIGEST && mode == MODE_UPDATE) {
			/* noOutputForOp = TRUE; */
			rv = FUNCLIST(fw_st_id)->C_DigestUpdate(hSession, in,
			    inLen);
	} else if (optype == CKF_DIGEST && mode == MODE_UPDATE_WITHKEY) {
			/* noOutputForOp = TRUE; */
			/*
			 * For C_DigestKey, a key is provided and
			 * we need the clone.
			 */
			rv = meta_object_get_clone(object,
			    slot_session->slotnum, slot_session, &slot_object);
			if (rv == CKR_OK)
				rv = FUNCLIST(fw_st_id)->C_DigestKey(hSession,
				    slot_object->hObject);
	} else if (optype == CKF_DIGEST && mode == MODE_FINAL) {
			rv = FUNCLIST(fw_st_id)->C_DigestFinal(hSession, out,
			    outLen);

	} else if (optype == CKF_SIGN && mode == MODE_SINGLE) {
			rv = FUNCLIST(fw_st_id)->C_Sign(hSession, in, inLen,
			    out, outLen);
	} else if (optype == CKF_SIGN && mode == MODE_UPDATE) {
			/* noOutputForOp = TRUE; */
			rv = FUNCLIST(fw_st_id)->C_SignUpdate(hSession, in,
			    inLen);
	} else if (optype == CKF_SIGN && mode == MODE_FINAL) {
			rv = FUNCLIST(fw_st_id)->C_SignFinal(hSession, out,
			    outLen);

	} else if (optype == CKF_VERIFY && mode == MODE_SINGLE) {
			/* noOutputForOp = TRUE; */
			/* Yes, use *outLen not outLen (think in2/in2Len) */
			rv = FUNCLIST(fw_st_id)->C_Verify(hSession, in,
			    inLen, out, *outLen);
	} else if (optype == CKF_VERIFY && mode == MODE_UPDATE) {
			/* noOutputForOp = TRUE; */
			rv = FUNCLIST(fw_st_id)->C_VerifyUpdate(hSession, in,
			    inLen);
	} else if (optype == CKF_VERIFY && mode == MODE_FINAL) {
			/* noOutputForOp = TRUE; */
			/* Yes, use in/inLen instead of out/outLen */
			rv = FUNCLIST(fw_st_id)->C_VerifyFinal(hSession, in,
			    inLen);

	} else if (optype == CKF_SIGN_RECOVER && mode == MODE_SINGLE) {
			rv = FUNCLIST(fw_st_id)->C_SignRecover(hSession, in,
			    inLen, out, outLen);
	} else if (optype == CKF_VERIFY_RECOVER && mode == MODE_SINGLE) {
			rv = FUNCLIST(fw_st_id)->C_VerifyRecover(hSession, in,
			    inLen, out, outLen);

	} else {
			rv = CKR_FUNCTION_FAILED;
	}


	/*
	 * Mark the operation type as inactive if an abnormal error
	 * happens, or if the operation normally results in an inactive
	 * operation state.
	 *
	 * NOTE: The spec isn't very explicit about what happens when you
	 * call C_FooFinal (or C_Foo) with a NULL output buffer (to get the
	 * output size), but there is no output. Technically this should be
	 * no different than the normal case (ie, when there is output), and
	 * the operation should remain active until the second call actually
	 * terminates it. However, one could make the case that there is no
	 * need for a second call, since no data is available. This presents
	 * dilemma for metaslot, because we don't know if the operation is
	 * going to remain active or not. We will assume a strict reading of
	 * the spec, the operation will remain active.
	 */
exit:
	if (rv == CKR_BUFFER_TOO_SMALL ||
	    (rv == CKR_OK && out == NULL && optype != CKF_VERIFY)) {
		/* Leave op active for retry (with larger buffer). */
		shutdown = B_FALSE;
	} else if (rv != CKR_OK) {
		shutdown = B_TRUE;
		finished_normally = B_FALSE;
	} else { /* CKR_OK */
		if (mode == MODE_SINGLE || mode == MODE_FINAL) {
			shutdown = B_TRUE;
			finished_normally = B_TRUE;
		} else { /* mode == MODE_UPDATE */
			shutdown = B_FALSE;
		}
	}

	if (shutdown) {
		if (mode == MODE_SINGLE || mode == MODE_FINAL) {
			session->init.app = B_FALSE;
		}

		meta_operation_cleanup(session, optype, finished_normally);
	}

	return (rv);
}

void
free_session_mechanism(meta_session_t *session)
{
	if (session->init.pMech != NULL) {
		if (session->init.pMech->pParameter != NULL) {
			free(session->init.pMech->pParameter);
			session->init.pMech->pParameter = NULL;
			session->init.pMech->ulParameterLen = 0;
		}
		free(session->init.pMech);
		session->init.pMech = NULL;
	}
}

/*
 * meta_operation_cleanup
 *
 * Cleans up an operation in the specified session.
 * If the operation did not finish normally, it will force
 * the operation to terminate.
 */
void
meta_operation_cleanup(meta_session_t *session, CK_FLAGS optype,
    boolean_t finished_normally)
{
	operation_info_t *op;
	CK_SESSION_HANDLE hSession;
	CK_SLOT_ID fw_st_id;

	if (!finished_normally) {
		CK_BYTE dummy_buf[8];

		if (session->op1.type == optype) {
			op = &session->op1;
		} else {
			if ((optype == CKF_ENCRYPT) ||
			    (optype == CKF_DECRYPT) ||
			    (optype == CKF_DIGEST)) {
				session->op1.type = 0;
				session->init.app = B_FALSE;
				session->init.done = B_FALSE;
				free_session_mechanism(session);
			}
			return;
		}

		hSession = op->session->hSession;
		fw_st_id = op->session->fw_st_id;

		/*
		 * There's no simple, reliable way to abort an
		 * operation. So, we'll force the operation to finish.
		 *
		 * We are here either because we need to abort either after
		 * C_xxxxxInit() or C_xxxxxUpdate().
		 *
		 * We will call C_xxxxxUpdate() with invalid argument to
		 * force the operation to abort.  According to the PKCS#11
		 * spec, any call to C_xxxxxUpdate() returns in an error
		 * will terminate the current operation.
		 */

		switch (optype) {
		case CKF_ENCRYPT:
			(void) FUNCLIST(fw_st_id)->C_EncryptUpdate(hSession,
			    NULL, 8, dummy_buf, NULL);
			break;
		case CKF_DECRYPT:
			(void) FUNCLIST(fw_st_id)->C_DecryptUpdate(hSession,
			    NULL, 8, dummy_buf, NULL);
			break;
		case CKF_DIGEST:
			(void) FUNCLIST(fw_st_id)->C_DigestUpdate(hSession,
			    NULL, 8);
			break;
		case CKF_SIGN:
			(void) FUNCLIST(fw_st_id)->C_SignUpdate(hSession,
			    NULL, 8);
			break;
		case CKF_SIGN_RECOVER:
			(void) FUNCLIST(fw_st_id)->C_SignRecover(hSession,
			    NULL, 8, dummy_buf, NULL);
			break;
		case CKF_VERIFY:
			(void) FUNCLIST(fw_st_id)->C_VerifyUpdate(hSession,
			    NULL, 8);
			break;
		case CKF_VERIFY_RECOVER:
			(void) FUNCLIST(fw_st_id)->C_VerifyRecover(hSession,
			    NULL, 8, dummy_buf, NULL);
			break;
		default:
			/*NOTREACHED*/
			break;
		}
		meta_release_slot_session(session->op1.session);
		session->op1.session = NULL;
	}

	if ((optype == CKF_ENCRYPT) || (optype == CKF_DECRYPT) ||
	    (optype == CKF_DIGEST)) {
		session->init.done = B_FALSE;
		free_session_mechanism(session);
	}
	session->op1.type = 0;
}

/*
 * Gets the list of slots that supports the specified mechanism.
 *
 * If "token_only", check if the keystore slot supports the specified mech,
 * if so, return that slot only
 *
 * Otherwise, get list of all slots that support the mech.
 *
 */
static CK_RV
get_slotlist_for_mech(CK_MECHANISM_TYPE mech_type,
    mech_support_info_t *mech_support_info,
    mechinfo_t ***slots, unsigned long *slot_count, boolean_t token_only,
    CK_MECHANISM_INFO *mech_info)
{
	boolean_t mech_supported = B_FALSE;
	CK_RV rv = CKR_OK;

	if (token_only) {
		rv = meta_mechManager_slot_supports_mech(mech_type,
		    get_keystore_slotnum(), &mech_supported,
		    &((mech_support_info->supporting_slots)[0]), B_FALSE,
		    mech_info);

		if (rv != CKR_OK) {
			return (rv);
		}

		if (mech_supported) {
			mech_support_info->mech = mech_type;
			/*
			 * Want to leave this at 0, that way, when
			 * other operation needs to
			 * use this mechanism, but not just for the
			 * keystore slot, we will look at other slots
			 */
			mech_support_info->num_supporting_slots = 0;
			*slots = mech_support_info->supporting_slots;
			*slot_count = 1;
		} else {
			rv = CKR_FUNCTION_FAILED;
		}
	} else {
		/*
		 * Get a list of slots that support this mech .
		 *
		 * If the specified mechanism is used last time,
		 * the list of capable slots is already retrieved.
		 * We can save some processing, and just use that list of slots.
		 */
		if ((mech_support_info->mech != mech_type) ||
		    (mech_support_info->num_supporting_slots == 0)) {
			mech_support_info->mech = mech_type;
			rv = meta_mechManager_get_slots(mech_support_info,
			    B_FALSE, mech_info);
			if (rv != CKR_OK) {
				return (CKR_FUNCTION_FAILED);
			}
		}
		*slots = mech_support_info->supporting_slots;
		*slot_count = mech_support_info->num_supporting_slots;
	}
	return (rv);
}

/*
 * meta_generate_keys
 *
 * Generates symmetric (k1=key, k2=null) or asymmetric (k1=pub, k2=priv) keys.
 *
 */
CK_RV
meta_generate_keys(meta_session_t *session, CK_MECHANISM *pMechanism,
    CK_ATTRIBUTE *k1Template, CK_ULONG k1AttrCount, meta_object_t *key1,
    CK_ATTRIBUTE *k2Template, CK_ULONG k2AttrCount, meta_object_t *key2)
{
	CK_RV rv, save_rv;
	slot_session_t *gen_session = NULL;
	slot_object_t *slot_key1 = NULL, *slot_key2 = NULL;
	mechinfo_t **slots = NULL;
	unsigned long i, slotCount = 0;
	boolean_t doKeyPair = B_FALSE, token_only = B_FALSE;
	CK_ULONG slotnum;
	CK_MECHANISM_INFO mech_info;
	/*
	 * Since the keygen call is in a loop, it is performance-wise useful
	 * to keep track of the token value
	 */
	CK_BBOOL current_token1_value = FALSE, current_token2_value = FALSE;

	(void) get_template_boolean(CKA_TOKEN, k1Template, k1AttrCount,
	    &(key1->isToken));
	(void) get_template_boolean(CKA_SENSITIVE, k1Template, k1AttrCount,
	    &(key1->isSensitive));
	(void) get_template_boolean(CKA_PRIVATE, k1Template, k1AttrCount,
	    &(key1->isPrivate));

	if (!get_template_boolean(CKA_EXTRACTABLE, k1Template, k1AttrCount,
	    &(key1->isExtractable)))
		key1->isExtractable = B_TRUE;

	if (key1->isToken)
		current_token1_value = TRUE;

	mech_info.flags = CKF_GENERATE;

	if (key2) {
		(void) get_template_boolean(CKA_TOKEN, k2Template, k2AttrCount,
		    &(key2->isToken));
		(void) get_template_boolean(CKA_SENSITIVE, k2Template,
		    k2AttrCount, &(key2->isSensitive));
		(void) get_template_boolean(CKA_PRIVATE, k2Template,
		    k2AttrCount, &(key2->isPrivate));

		if (!get_template_boolean(CKA_EXTRACTABLE, k2Template,
		    k2AttrCount, &(key2->isExtractable)))
			key2->isExtractable = B_TRUE;

		if (key2->isToken)
			current_token2_value = TRUE;

		doKeyPair = B_TRUE;
		mech_info.flags = CKF_GENERATE_KEY_PAIR;
	}


	/* Can't create token objects in a read-only session. */
	if ((IS_READ_ONLY_SESSION(session->session_flags)) &&
	    ((key1->isToken) || ((key2) && (key2->isToken)))) {
		return (CKR_SESSION_READ_ONLY);
	}

	if (meta_freeobject_check(session, key1, pMechanism, k1Template,
	    k1AttrCount, 0)) {

		if ((key1->isPrivate || (doKeyPair && key2->isPrivate)) &&
		    !metaslot_logged_in())
			return (CKR_USER_NOT_LOGGED_IN);

		if (!meta_freeobject_set(key1, k1Template, k1AttrCount,
		    B_FALSE))
			return (CKR_FUNCTION_FAILED);

		if (doKeyPair) {
			key2->isFreeObject = FREE_ALLOWED_KEY;
			if (!meta_freeobject_set(key2, k2Template, k2AttrCount,
			    B_FALSE))
				return (CKR_FUNCTION_FAILED);
		}

	} else if (doKeyPair) {
		/*
		 * If this is a keypair operation, the second key cannot be
		 * a FreeObject if the first is not.  Both keys will have the
		 * same fate when it comes to provider choices
		 */
		key2->isFreeObject = FREE_DISABLED;
		key2->isFreeToken = FREE_DISABLED;
	}

	if ((key1->isToken) || ((doKeyPair) && (key2->isToken))) {
		/*
		 * Token objects can only be generated in the token object
		 * slot.  If token object slot doesn't support generating
		 * the key, it will just not be done.
		 */
		token_only = B_TRUE;
	}

	rv = get_slotlist_for_mech(pMechanism->mechanism,
	    &(session->mech_support_info), &slots, &slotCount, token_only,
	    &mech_info);

	if (rv != CKR_OK) {
		goto finish;
	}

	rv = meta_slot_object_alloc(&slot_key1);
	if (doKeyPair && rv == CKR_OK)
		rv = meta_slot_object_alloc(&slot_key2);
	if (rv != CKR_OK)
		goto finish;

	/* Attempt to generate key on slots until one succeeds. */
	for (i = 0; i < slotCount; i++) {
		CK_SESSION_HANDLE hSession;
		CK_SLOT_ID fw_st_id;

		gen_session = NULL;

		slotnum = slots[i]->slotnum;

		if (session->op1.session != NULL) {
			if ((session->op1.session)->slotnum == slotnum) {
				gen_session = session->op1.session;
				/*
				 * set it to NULL for now, assign it to
				 * gen_session again if it is successful
				 */
				session->op1.session = NULL;
			} else {
				gen_session = NULL;
			}
		}

		if (gen_session == NULL) {
			rv = meta_get_slot_session(slotnum, &gen_session,
			    session->session_flags);
			if (rv != CKR_OK) {
				goto loop_cleanup;
			}
		}

		/*
		 * If this is a freetoken, make sure the templates are
		 * approriate for the slot being used.
		 */
		if (key1->isFreeToken == FREE_ENABLED) {
			rv = meta_freetoken_set(slotnum,
			    &current_token1_value, k1Template, k1AttrCount);
			if (rv != CKR_OK)
				goto loop_cleanup;
		}

		if (doKeyPair && key2->isFreeToken == FREE_ENABLED) {
			rv = meta_freetoken_set(slotnum,
			    &current_token2_value, k2Template, k2AttrCount);
			if (rv != CKR_OK)
				goto loop_cleanup;
		}

		fw_st_id = gen_session->fw_st_id;
		hSession = gen_session->hSession;

		if (doKeyPair) {
			rv = FUNCLIST(fw_st_id)->C_GenerateKeyPair(hSession,
			    pMechanism, k1Template, k1AttrCount,
			    k2Template, k2AttrCount,
			    &slot_key1->hObject, &slot_key2->hObject);
		} else {
			rv = FUNCLIST(fw_st_id)->C_GenerateKey(hSession,
			    pMechanism, k1Template, k1AttrCount,
			    &slot_key1->hObject);
		}

		if (rv == CKR_OK)
			break;

loop_cleanup:
		if (i == 0) {
			save_rv = rv;
		}

		if (gen_session) {
			meta_release_slot_session(gen_session);
			gen_session = NULL;
		}
	}
	if (rv != CKR_OK) {
		rv = save_rv;
		goto finish;
	}

	rv = meta_object_get_attr(gen_session, slot_key1->hObject, key1);
	if (rv != CKR_OK) {
		goto finish;
	}

	if (key2) {
		rv = meta_object_get_attr(gen_session, slot_key2->hObject,
		    key2);
		if (rv != CKR_OK) {
			goto finish;
		}
	}

	/* Allow FreeToken to activate onto token obj list */
	if (key1->isFreeToken == FREE_ENABLED)
		key1->isToken = B_TRUE;

	meta_slot_object_activate(slot_key1, gen_session, key1->isToken);
	key1->clones[slotnum] = slot_key1;
	key1->master_clone_slotnum = slotnum;
	slot_key1 = NULL;
	if (key1->isFreeObject == FREE_ENABLED) {
		rv = meta_freeobject_clone(session, key1);
		if (rv != CKR_OK)
			goto finish;
	}

	if (doKeyPair) {
		/* Allow FreeToken to activate onto token obj list */
		if (key2->isFreeToken == FREE_ENABLED)
			key2->isToken = B_TRUE;

		meta_slot_object_activate(slot_key2, gen_session,
		    key2->isToken);
		key2->clones[slotnum] = slot_key2;
		key2->master_clone_slotnum = slotnum;
		slot_key2 = NULL;
		if (key2->isFreeObject == FREE_ENABLED) {
			rv = meta_freeobject_clone(session, key2);
			if (rv != CKR_OK)
				goto finish;
		}
	}

finish:
	if (slot_key1) {
		meta_slot_object_dealloc(slot_key1);
	}

	if (slot_key2) {
		meta_slot_object_dealloc(slot_key2);
	}

	/* Save the session in case it can be used later */
	if (rv == CKR_OK) {
		/*
		 * If currently stored session is not the one being in use now,
		 * release the previous one and store the current one
		 */
		if ((session->op1.session) &&
		    (session->op1.session != gen_session)) {
			meta_release_slot_session(session->op1.session);
		}

		/* Save the session */
		session->op1.session = gen_session;
	}

	return (rv);
}


/*
 * meta_wrap_key
 *
 */
CK_RV
meta_wrap_key(meta_session_t *session, CK_MECHANISM *pMechanism,
    meta_object_t *wrappingkey, meta_object_t *inputkey, CK_BYTE *wrapped_key,
    CK_ULONG *wrapped_key_len)
{
	CK_RV rv, save_rv;
	slot_session_t *wrap_session = NULL;
	slot_object_t *slot_wrappingkey, *slot_inputkey;
	mechinfo_t **slots = NULL;
	unsigned long i, slotCount = 0;
	CK_ULONG slotnum;
	CK_MECHANISM_INFO mech_info;

	/*
	 * If the key to be wrapped is a token object,
	 * the operation can only be done in the token object slot.
	 */
	mech_info.flags = CKF_WRAP;
	rv = get_slotlist_for_mech(pMechanism->mechanism,
	    &(session->mech_support_info), &slots, &slotCount,
	    inputkey->isToken, &mech_info);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Attempt to wrap key on slots until one succeeds. */
	for (i = 0; i < slotCount; i++) {

		slotnum = slots[i]->slotnum;
		wrap_session = NULL;

		if (session->op1.session != NULL) {
			if ((session->op1.session)->slotnum == slotnum) {
				wrap_session = session->op1.session;
				/*
				 * set it to NULL for now, assign it to
				 * wrap_session again if it is successful
				 */
				session->op1.session = NULL;
			} else {
				wrap_session = NULL;
			}
		}

		if (wrap_session == NULL) {
			rv = meta_get_slot_session(slotnum, &wrap_session,
			    session->session_flags);
			if (rv != CKR_OK) {
				goto loop_cleanup;
			}
		}

		rv = meta_object_get_clone(wrappingkey, slotnum,
		    wrap_session, &slot_wrappingkey);
		if (rv != CKR_OK)
			goto loop_cleanup;

		rv = meta_object_get_clone(inputkey, slotnum,
		    wrap_session, &slot_inputkey);
		if (rv != CKR_OK)
			goto loop_cleanup;

		rv = FUNCLIST(wrap_session->fw_st_id)->C_WrapKey(
		    wrap_session->hSession, pMechanism,
		    slot_wrappingkey->hObject, slot_inputkey->hObject,
		    wrapped_key, wrapped_key_len);

		if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
			break;

loop_cleanup:
		if (i == 0) {
			save_rv = rv;
		}

		if (wrap_session) {
			meta_release_slot_session(wrap_session);
			wrap_session = NULL;
		}
	}
	if (rv != CKR_OK) {
		if (rv != CKR_BUFFER_TOO_SMALL) {
			if (i == slotCount) {
				rv = save_rv;
			}
		}
	}

finish:
	/* Save the session in case it can be used later */
	if (rv == CKR_OK) {
		/*
		 * If currently stored session is not the one being in use now,
		 * release the previous one and store the current one
		 */
		if ((session->op1.session) &&
		    (session->op1.session != wrap_session)) {
			meta_release_slot_session(session->op1.session);
		}

		/* Save the session */
		session->op1.session = wrap_session;
	}
	return (rv);
}



/*
 * meta_unwrap_key
 *
 */
CK_RV
meta_unwrap_key(meta_session_t *session,
    CK_MECHANISM *pMechanism, meta_object_t *unwrapping_key,
    CK_BYTE *wrapped_key, CK_ULONG wrapped_key_len,
    CK_ATTRIBUTE *template, CK_ULONG template_size,
    meta_object_t *unwrapped_key)
{
	CK_RV rv, save_rv;
	CK_OBJECT_HANDLE hUnwrappedKey;
	slot_session_t *unwrap_session = NULL;
	slot_object_t *slot_unwrappingkey, *slot_unwrapped_key;
	mechinfo_t **slots = NULL;
	unsigned long i, slotCount = 0;
	CK_ULONG slotnum;
	CK_MECHANISM_INFO mech_info;

	/* Can't create token objects in a read-only session. */
	if ((IS_READ_ONLY_SESSION(session->session_flags)) &&
	    unwrapped_key->isToken) {
		return (CKR_SESSION_READ_ONLY);
	}

	/*
	 * If the the resulting unwrapped key
	 * needs to be a token object, the operation can only
	 * be performed in the token slot, if it is supported.
	 */
	mech_info.flags = CKF_UNWRAP;
	rv = get_slotlist_for_mech(pMechanism->mechanism,
	    &(session->mech_support_info), &slots, &slotCount,
	    unwrapped_key->isToken, &mech_info);

	if (rv != CKR_OK) {
		return (rv);
	}

	rv = meta_slot_object_alloc(&slot_unwrapped_key);
	if (rv != CKR_OK) {
		goto finish;
	}

	/* Attempt to unwrap key on slots until one succeeds. */
	for (i = 0; i < slotCount; i++) {

		slotnum = slots[i]->slotnum;
		unwrap_session = NULL;

		if (session->op1.session != NULL) {
			if ((session->op1.session)->slotnum == slotnum) {
				unwrap_session = session->op1.session;
				/*
				 * set it to NULL for now, assign it to
				 * unwrap_session again if it is successful
				 */
				session->op1.session = NULL;
			} else {
				unwrap_session = NULL;
			}
		}

		if (unwrap_session == NULL) {
			rv = meta_get_slot_session(slotnum, &unwrap_session,
			    session->session_flags);
			if (rv != CKR_OK) {
				goto loop_cleanup;
			}
		}

		rv = meta_object_get_clone(unwrapping_key, slotnum,
		    unwrap_session, &slot_unwrappingkey);
		if (rv != CKR_OK)
			goto loop_cleanup;

		rv = FUNCLIST(unwrap_session->fw_st_id)->C_UnwrapKey(
		    unwrap_session->hSession, pMechanism,
		    slot_unwrappingkey->hObject, wrapped_key, wrapped_key_len,
		    template, template_size, &hUnwrappedKey);

		if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL)
			break;
loop_cleanup:
		if (i == 0) {
			save_rv = rv;
		}

		if (unwrap_session) {
			meta_release_slot_session(unwrap_session);
			unwrap_session = NULL;
		}
	}


	if (rv != CKR_OK) {
		if (rv != CKR_BUFFER_TOO_SMALL) {
			rv = save_rv;
		}
		goto finish;
	}


	slot_unwrapped_key->hObject = hUnwrappedKey;
	unwrapped_key->clones[slotnum] = slot_unwrapped_key;
	unwrapped_key->master_clone_slotnum = slotnum;
	rv = meta_object_get_attr(unwrap_session,
	    slot_unwrapped_key->hObject, unwrapped_key);
	if (rv != CKR_OK) {
		goto finish;
	}
	meta_slot_object_activate(slot_unwrapped_key, unwrap_session,
	    unwrapped_key->isToken);
	slot_unwrapped_key = NULL;

finish:
	if (slot_unwrapped_key) {
		meta_slot_object_dealloc(slot_unwrapped_key);
	}

	/* Save the session in case it can be used later */
	if (rv == CKR_OK) {
		/*
		 * If currently stored session is not the one being in use now,
		 * release the previous one and store the current one
		 */
		if ((session->op1.session) &&
		    (session->op1.session != unwrap_session)) {
			meta_release_slot_session(session->op1.session);
		}

		/* Save the session */
		session->op1.session = unwrap_session;
	}

	return (rv);
}


/*
 * meta_derive_key
 *
 * Core implementation for C_DeriveKey. This function is a bit gross because
 * of PKCS#11 kludges that pass extra object handles in the mechanism
 * parameters. Normally C_DeriveKey takes a single existing key as input,
 * and creates a single new key as output. But a few mechanisms take 2 keys
 * as input, and the two SSL/TLS mechanisms create 4 keys as output.
 *
 * When an extra input key (basekey2) is set, we set *phBaseKey2 to the clone's
 * object handle. phBaseKey2 is provided by the caller so we don't have to
 * trudge down into different mechanism parameters to set it when issuing the
 * operation.
 *
 * For the SSL/TLS mechanisms, newKey2/newKey3/newKey4 will be set. We pull
 * the new handles from pMech->pParameter in order to fill in the appropriate
 * meta_object fields.
 */
CK_RV
meta_derive_key(meta_session_t *session, CK_MECHANISM *pMechanism,
    meta_object_t *basekey1, meta_object_t *basekey2,
    CK_OBJECT_HANDLE *phBaseKey2,
    CK_ATTRIBUTE *pTemplate, CK_ULONG ulAttributeCount,
    meta_object_t *newKey1, meta_object_t *newKey2,
    meta_object_t *newKey3, meta_object_t *newKey4)
{
	CK_RV rv, save_rv;
	CK_OBJECT_HANDLE hDerivedKey;

	CK_ULONG slotnum;
	boolean_t isSSL = B_FALSE;
	boolean_t isTLSPRF = B_FALSE;
	mechinfo_t **slots = NULL;
	unsigned long i, slot_count = 0;
	slot_session_t *derive_session = NULL;
	slot_object_t *slot_basekey1 = NULL, *slot_basekey2 = NULL;
	slot_object_t *slotkey1 = NULL, *slotkey2 = NULL, *slotkey3 = NULL,
	    *slotkey4 = NULL;
	CK_MECHANISM_INFO mech_info;
	CK_BBOOL current_token_value = FALSE;

	/*
	 * if the derived key needs to be a token object, can only
	 * perform the derive operation in the token slot
	 */
	(void) get_template_boolean(CKA_TOKEN, pTemplate, ulAttributeCount,
	    &(newKey1->isToken));
	(void) get_template_boolean(CKA_PRIVATE, pTemplate, ulAttributeCount,
	    &(newKey1->isPrivate));
	(void) get_template_boolean(CKA_SENSITIVE, pTemplate, ulAttributeCount,
	    &(newKey1->isSensitive));

	if (newKey1->isToken)
		current_token_value = TRUE;

	/* Can't create token objects in a read-only session. */
	if ((IS_READ_ONLY_SESSION(session->session_flags)) &&
	    newKey1->isToken) {
		rv = CKR_SESSION_READ_ONLY;
		goto finish;
	}

	if (meta_freeobject_check(session, newKey1, pMechanism, pTemplate,
	    ulAttributeCount, 0)) {

		if (newKey1->isPrivate && !metaslot_logged_in())
			return (CKR_USER_NOT_LOGGED_IN);

		if (!meta_freeobject_set(newKey1, pTemplate, ulAttributeCount,
		    B_FALSE))
			return (CKR_FUNCTION_FAILED);
	}

	mech_info.flags = CKF_DERIVE;
	rv = get_slotlist_for_mech(pMechanism->mechanism,
	    &(session->mech_support_info), &slots, &slot_count,
	    newKey1->isToken, &mech_info);

	if (rv != CKR_OK) {
		return (rv);
	}

	if (pMechanism->mechanism == CKM_SSL3_KEY_AND_MAC_DERIVE ||
	    pMechanism->mechanism == CKM_TLS_KEY_AND_MAC_DERIVE)
		isSSL = B_TRUE;

	else if (pMechanism->mechanism == CKM_TLS_PRF)
		isTLSPRF = B_TRUE;

	rv = meta_slot_object_alloc(&slotkey1);
	if (isSSL) {
		if (rv == CKR_OK)
			rv = meta_slot_object_alloc(&slotkey2);
		if (rv == CKR_OK)
			rv = meta_slot_object_alloc(&slotkey3);
		if (rv == CKR_OK)
			rv = meta_slot_object_alloc(&slotkey4);
	}
	if (rv != CKR_OK) {
		goto finish;
	}

	for (i = 0; i < slot_count; i++) {
		slotnum = slots[i]->slotnum;

		derive_session = NULL;

		if (session->op1.session != NULL) {
			if ((session->op1.session)->slotnum == slotnum) {
				derive_session = session->op1.session;
				/*
				 * set it to NULL for now, assign it to
				 * derive_session again if it is successful
				 */
				session->op1.session = NULL;
			} else {
				derive_session = NULL;
			}
		}

		if (derive_session == NULL) {
			rv = meta_get_slot_session(slotnum, &derive_session,
			    session->session_flags);
			if (rv != CKR_OK) {
				goto loop_cleanup;
			}
		}

		rv = meta_object_get_clone(basekey1, slotnum,
		    derive_session, &slot_basekey1);
		if (rv != CKR_OK)
			goto loop_cleanup;

		if (basekey2) {
			rv = meta_object_get_clone(basekey2, slotnum,
			    derive_session, &slot_basekey2);
			if (rv != CKR_OK)
				goto loop_cleanup;

			/* Pass the handle somewhere in the mech params. */
			*phBaseKey2 = slot_basekey2->hObject;
		}

		if (newKey1->isFreeToken == FREE_ENABLED) {
			rv = meta_freetoken_set(slotnum, &current_token_value,
			    pTemplate, ulAttributeCount);
			if (rv != CKR_OK)
				goto loop_cleanup;
		}

		rv = FUNCLIST(derive_session->fw_st_id)->C_DeriveKey(
		    derive_session->hSession, pMechanism,
		    slot_basekey1->hObject, pTemplate, ulAttributeCount,
		    (isSSL || isTLSPRF) ? NULL : &hDerivedKey);

		if (rv == CKR_OK)
			break;
loop_cleanup:
		if (i == 0) {
			save_rv = rv;
		}

		if (derive_session) {
			meta_release_slot_session(derive_session);
			derive_session = NULL;
		}
		/* No need to cleanup clones, so we can reuse them later. */
	}

	if (rv != CKR_OK) {
		rv = save_rv;
		goto finish;
	}

	if (isTLSPRF)
		goto finish;

	/*
	 * These SSL/TLS are unique in that the parameter in the API for
	 * the new key is unused (NULL). Instead, there are 4 keys which
	 * are derived, and are passed back through the mechanism params.
	 * Both mechs use the same mechanism parameter type.
	 */
	if (isSSL) {
		CK_SSL3_KEY_MAT_PARAMS *keyparams;
		CK_SSL3_KEY_MAT_OUT *keys;

		/* NULL checks already done by caller */
		keyparams = (CK_SSL3_KEY_MAT_PARAMS*)pMechanism->pParameter;
		keys = keyparams->pReturnedKeyMaterial;

		slotkey1->hObject = keys->hClientMacSecret;
		slotkey2->hObject = keys->hServerMacSecret;
		slotkey3->hObject = keys->hClientKey;
		slotkey4->hObject = keys->hServerKey;

		rv = meta_object_get_attr(derive_session,
		    slotkey1->hObject, newKey1);
		if (rv != CKR_OK) {
			goto finish;
		}

		rv = meta_object_get_attr(derive_session,
		    slotkey2->hObject, newKey2);
		if (rv != CKR_OK) {
			goto finish;
		}

		rv = meta_object_get_attr(derive_session,
		    slotkey3->hObject, newKey3);
		if (rv != CKR_OK) {
			goto finish;
		}

		rv = meta_object_get_attr(derive_session,
		    slotkey4->hObject, newKey4);
		if (rv != CKR_OK) {
			goto finish;
		}

		newKey1->clones[slotnum] = slotkey1;
		newKey2->clones[slotnum] = slotkey2;
		newKey3->clones[slotnum] = slotkey3;
		newKey4->clones[slotnum] = slotkey4;

		newKey1->master_clone_slotnum = slotnum;
		newKey2->master_clone_slotnum = slotnum;
		newKey3->master_clone_slotnum = slotnum;
		newKey4->master_clone_slotnum = slotnum;

		meta_slot_object_activate(slotkey1, derive_session,
		    newKey1->isToken);
		slotkey1 = NULL;
		meta_slot_object_activate(slotkey2, derive_session,
		    newKey2->isToken);
		slotkey2 = NULL;
		meta_slot_object_activate(slotkey3, derive_session,
		    newKey3->isToken);
		slotkey3 = NULL;
		meta_slot_object_activate(slotkey4, derive_session,
		    newKey4->isToken);
		slotkey4 = NULL;

	} else {
		slotkey1->hObject = hDerivedKey;
		newKey1->clones[slotnum] = slotkey1;
		newKey1->master_clone_slotnum = slotnum;

		rv = meta_object_get_attr(derive_session,
		    slotkey1->hObject, newKey1);
		if (rv != CKR_OK) {
			goto finish;
		}

		/* Allow FreeToken to activate onto token obj list */
		if (newKey1->isFreeToken == FREE_ENABLED)
			newKey1->isToken = B_TRUE;

		meta_slot_object_activate(slotkey1, derive_session,
		    newKey1->isToken);
		slotkey1 = NULL;
	}

	if (newKey1->isFreeObject == FREE_ENABLED)
		(void) meta_freeobject_clone(session, newKey1);


finish:
	if (slotkey1) {
		meta_slot_object_dealloc(slotkey1);
	}
	if (slotkey2) {
		meta_slot_object_dealloc(slotkey2);
	}
	if (slotkey3) {
		meta_slot_object_dealloc(slotkey3);
	}
	if (slotkey4) {
		meta_slot_object_dealloc(slotkey4);
	}

	/* Save the session in case it can be used later */
	if (rv == CKR_OK) {
		/*
		 * If currently stored session is not the one being in use now,
		 * release the previous one and store the current one
		 */
		if ((session->op1.session) &&
		    (session->op1.session != derive_session)) {
			meta_release_slot_session(session->op1.session);
		}

		/* Save the session */
		session->op1.session = derive_session;
	}

	return (rv);
}


/*
 * Check the following 4 environment variables for user/application's
 * configuration for metaslot.  User's configuration takes precedence
 * over the system wide configuration for metaslot
 *
 * ${METASLOT_ENABLED}
 * ${METASLOT_OBJECTSTORE_SLOT}
 * ${METASLOT_OBJECTSTORE_TOKEN}
 * ${METASLOT_AUTO_KEY_MIGRATE}
 *
 * ${_METASLOT_ENABLE_THRESHOLD} - private environmental variable to
 * enable the treshold checking which is disabled by default.
 *
 * values defined in these environment variables will be stored in the
 * global variable "metaslot_config". Variable threshold_chk_disabled is an
 * exception.
 */
void
get_user_metaslot_config()
{
	char *env_val = NULL;

	/*
	 * Check to see if any environment variable is defined
	 * by the user for configuring metaslot.
	 */
	bzero(&metaslot_config, sizeof (metaslot_config));

	/* METASLOT_ENABLED */
	env_val = getenv("METASLOT_ENABLED");
	if (env_val) {
		metaslot_config.enabled_specified = B_TRUE;
		if (strcasecmp(env_val, TRUE_STRING) == 0) {
			metaslot_config.enabled = B_TRUE;
		} else if (strcasecmp(env_val, FALSE_STRING) == 0) {
			metaslot_config.enabled = B_FALSE;
		} else {
			/* value is neither 1 or 0, ignore this value */
			metaslot_config.enabled_specified = B_FALSE;
		}
	}

	/* METASLOT_AUTO_KEY_MIGRATE */
	env_val = getenv("METASLOT_AUTO_KEY_MIGRATE");
	if (env_val) {
		metaslot_config.auto_key_migrate_specified = B_TRUE;
		if (strcasecmp(env_val, TRUE_STRING) == 0) {
			metaslot_config.auto_key_migrate = B_TRUE;
		} else if (strcasecmp(env_val, FALSE_STRING) == 0) {
			metaslot_config.auto_key_migrate = B_FALSE;
		} else {
			/* value is neither 1 or 0, ignore this value */
			metaslot_config.auto_key_migrate_specified = B_FALSE;
		}
	}

	/* METASLOT_OBJECTSTORE_SLOT */
	env_val = getenv("METASLOT_OBJECTSTORE_SLOT");
	if (env_val) {
		metaslot_config.keystore_slot_specified = B_TRUE;
		(void) strlcpy((char *)metaslot_config.keystore_slot, env_val,
		    SLOT_DESCRIPTION_SIZE);
	}

	/* METASLOT_OBJECTSTORE_TOKEN */
	env_val = getenv("METASLOT_OBJECTSTORE_TOKEN");
	if (env_val) {
		metaslot_config.keystore_token_specified = B_TRUE;
		(void) strlcpy((char *)metaslot_config.keystore_token, env_val,
		    TOKEN_LABEL_SIZE);
	}

	/* _METASLOT_ENABLE_THRESHOLD */
	env_val = getenv("_METASLOT_ENABLE_THRESHOLD");
	if (env_val) {
		threshold_chk_enabled = B_TRUE;
	}
}
