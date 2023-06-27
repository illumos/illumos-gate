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
 *
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <stdlib.h>
#include <strings.h>
#include <security/cryptoki.h>
#include <cryptoutil.h>
#include <errno.h>
#include <sys/crypto/api.h>
#include <sys/crypto/common.h>
#include <sys/crypto/ioctl.h>
#include <sys/crypto/spi.h>
#include "kernelGlobal.h"
#include "kernelSlot.h"


/* ARGSUSED */
CK_RV
C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount)
{
	int i;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (pulCount == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	if (pSlotList == NULL) {
		*pulCount = slot_count;
		return (CKR_OK);
	}

	if (*pulCount < slot_count) {
		*pulCount = slot_count;
		return (CKR_BUFFER_TOO_SMALL);
	}

	*pulCount = slot_count;

	/*
	 * The slotID returned to an application will be the index to
	 * the slot_table.  The library will map to the provider_id when
	 * making any ioctl call.
	 */
	for (i = 0; i < slot_count; i++) {
		pSlotList[i] = i;
	}

	return (CKR_OK);
}


CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv;
	crypto_get_provider_info_t gi;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID >= slot_count) {
		return (CKR_SLOT_ID_INVALID);
	}

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	/* kernel provider numbers start with 0 */
	gi.gi_provider_id = slot_table[slotID]->sl_provider_id;
	while ((r = ioctl(kernel_fd, CRYPTO_GET_PROVIDER_INFO, &gi)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		if (gi.gi_return_value != CRYPTO_SUCCESS) {
			rv = crypto2pkcs11_error_number(
			    gi.gi_return_value);
		} else {
			rv = CKR_OK;
		}
	}

	if (rv == CKR_OK) {
		bcopy(gi.gi_provider_data.pd_prov_desc,
		    pInfo->slotDescription, CRYPTO_PROVIDER_DESCR_MAX_LEN);
		bcopy(gi.gi_provider_data.pd_manufacturerID,
		    pInfo->manufacturerID, CRYPTO_EXT_SIZE_MANUF);
		pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
		pInfo->hardwareVersion.major =
		    gi.gi_provider_data.pd_hardware_version.cv_major;
		pInfo->hardwareVersion.minor =
		    gi.gi_provider_data.pd_hardware_version.cv_minor;
		pInfo->firmwareVersion.major =
		    gi.gi_provider_data.pd_firmware_version.cv_major;
		pInfo->firmwareVersion.minor =
		    gi.gi_provider_data.pd_firmware_version.cv_minor;
	}

	return (rv);
}


CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv;
	crypto_get_provider_info_t gi;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID >= slot_count)
		return (CKR_SLOT_ID_INVALID);

	if (pInfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	gi.gi_provider_id = slot_table[slotID]->sl_provider_id;
	while ((r = ioctl(kernel_fd, CRYPTO_GET_PROVIDER_INFO, &gi)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(gi.gi_return_value);
	}

	if (rv == CKR_OK) {
		bcopy(gi.gi_provider_data.pd_label, pInfo->label,
		    CRYPTO_EXT_SIZE_LABEL);
		bcopy(gi.gi_provider_data.pd_manufacturerID,
		    pInfo->manufacturerID, CRYPTO_EXT_SIZE_MANUF);
		bcopy(gi.gi_provider_data.pd_model, pInfo->model,
		    CRYPTO_EXT_SIZE_MODEL);
		bcopy(gi.gi_provider_data.pd_serial_number,
		    pInfo->serialNumber, CRYPTO_EXT_SIZE_SERIAL);
		pInfo->flags = gi.gi_provider_data.pd_flags;
		pInfo->ulMaxSessionCount =
		    gi.gi_provider_data.pd_max_session_count;
		pInfo->ulSessionCount =
		    gi.gi_provider_data.pd_session_count;
		pInfo->ulMaxRwSessionCount =
		    gi.gi_provider_data.pd_max_rw_session_count;
		pInfo->ulRwSessionCount =
		    gi.gi_provider_data.pd_rw_session_count;
		pInfo->ulMaxPinLen =
		    gi.gi_provider_data.pd_max_pin_len;
		pInfo->ulMinPinLen =
		    gi.gi_provider_data.pd_min_pin_len;
		pInfo->ulTotalPublicMemory =
		    gi.gi_provider_data.pd_total_public_memory;
		pInfo->ulFreePublicMemory =
		    gi.gi_provider_data.pd_free_public_memory;
		pInfo->ulTotalPrivateMemory =
		    gi.gi_provider_data.pd_total_private_memory;
		pInfo->ulFreePrivateMemory =
		    gi.gi_provider_data.pd_free_private_memory;
		pInfo->hardwareVersion.major =
		    gi.gi_provider_data.pd_hardware_version.cv_major;
		pInfo->hardwareVersion.minor =
		    gi.gi_provider_data.pd_hardware_version.cv_minor;
		pInfo->firmwareVersion.major =
		    gi.gi_provider_data.pd_firmware_version.cv_major;
		pInfo->firmwareVersion.minor =
		    gi.gi_provider_data.pd_firmware_version.cv_minor;
		(void) strncpy((char *)pInfo->utcTime,
		    (const char *)gi.gi_provider_data.pd_time,
		    CRYPTO_EXT_SIZE_TIME);

	}

	return (rv);


}

/*ARGSUSED*/
CK_RV
C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}


CK_RV
C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount)
{
	CK_MECHANISM_TYPE type;
	CK_RV rv;
	CK_FLAGS flags;
	CK_ULONG specified_count, count = 0;
	crypto_get_provider_mechanisms_t *pm, tmp;
	crypto_get_provider_mechanism_info_t mechanism_info;
	crypto_provider_id_t provider_id;
	size_t alloc_bytes;
	int i, r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID >= slot_count)
		return (CKR_SLOT_ID_INVALID);

	/* kernel provider numbers start with 0 */
	provider_id = slot_table[slotID]->sl_provider_id;

	if (pMechanismList != NULL) {
		if (pulCount == NULL) {
			return (CKR_ARGUMENTS_BAD);
		} else if (*pulCount == 0) {
			return (CKR_ARGUMENTS_BAD);
		}
	}
	specified_count = *pulCount;
	tmp.pm_provider_id = provider_id;
	tmp.pm_count = 0;
	while ((r = ioctl(kernel_fd, CRYPTO_GET_PROVIDER_MECHANISMS,
	    &tmp)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		return (CKR_FUNCTION_FAILED);
	} else {
		if (tmp.pm_return_value != CRYPTO_SUCCESS) {
			rv = crypto2pkcs11_error_number(tmp.pm_return_value);
			return (rv);
		}
		alloc_bytes = sizeof (crypto_get_provider_mechanisms_t) +
		    (tmp.pm_count - 1) * sizeof (crypto_mech_name_t);
	}

	pm = malloc(alloc_bytes);
	if (pm == NULL)
		return (CKR_HOST_MEMORY);

	pm->pm_provider_id = provider_id;
	pm->pm_count = tmp.pm_count;

	while ((r = ioctl(kernel_fd, CRYPTO_GET_PROVIDER_MECHANISMS, pm)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(pm->pm_return_value);
	}

	if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL)
		goto clean_exit;

	for (i = 0; i < pm->pm_count; i++) {
		mechanism_info.mi_provider_id = provider_id;
		bcopy(&pm->pm_list[i][0], mechanism_info.mi_mechanism_name,
		    sizeof (crypto_mech_name_t));

		/*
		 * Get each mechanism's flags.
		 * The ioctl should not fail since the mechanism info is
		 * already in the kernel and a call doesn't have to be made
		 * to the provider. If it fails, nothing can be done other
		 * than skip the mechanism.
		 */
		while ((r = ioctl(kernel_fd, CRYPTO_GET_PROVIDER_MECHANISM_INFO,
		    &mechanism_info)) < 0) {
			if (errno != EINTR)
				break;
		}
		if (r < 0) {
			continue;
		}

		if (mechanism_info.mi_return_value != CRYPTO_SUCCESS)
			continue;

		flags = mechanism_info.mi_flags;

		/*
		 * Atomic flags are not part of PKCS#11 so we filter
		 * them out here.
		 * Neither is CRYPTO_FG_MAC.
		 */
		flags &= ~(CRYPTO_FG_DIGEST_ATOMIC | CRYPTO_FG_ENCRYPT_ATOMIC |
		    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_MAC_ATOMIC |
		    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_VERIFY_ATOMIC |
		    CRYPTO_FG_SIGN_RECOVER_ATOMIC |
		    CRYPTO_FG_VERIFY_RECOVER_ATOMIC |
		    CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
		    CRYPTO_FG_MAC_DECRYPT_ATOMIC |
		    CRYPTO_FG_MAC);

		/* mechanism has no PKCS#11 flags, so don't report it */
		if (flags == 0)
			continue;

		/*
		 * The kernel framework has a pseudo mechanism
		 * for RNG which we remove from the list of mechanisms.
		 */
		if (strcmp(&pm->pm_list[i][0], "random") != 0) {

			if (pkcs11_str2mech(&pm->pm_list[i][0],
			    &type) != CKR_OK)
				continue;

			if (pMechanismList != NULL && rv == CKR_OK &&
			    (count < specified_count))
				pMechanismList[count] = type;

			count++;
		}

	}

	if (pMechanismList != NULL && (count > specified_count))
		rv = CKR_BUFFER_TOO_SMALL;

	*pulCount = count;

clean_exit:
	free(pm);
	return (rv);
}


CK_RV
C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo)
{
	uint32_t k_mi_flags;
	CK_RV rv;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	if (slotID >= slot_count)
		return (CKR_SLOT_ID_INVALID);

	if (pInfo == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	rv = get_mechanism_info(slot_table[slotID], type, pInfo, &k_mi_flags);

	return (rv);
}


/*ARGSUSED*/
CK_RV
C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
    CK_UTF8CHAR_PTR pLabel)
{
	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}

/*ARGSUSED*/
CK_RV
C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	return (CKR_FUNCTION_NOT_SUPPORTED);
}


CK_RV
C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	CK_RV	rv = CKR_OK;
	kernel_session_t *session_p;
	boolean_t ses_lock_held = B_FALSE;
	crypto_set_pin_t	setpin;
	int r;

	if (!kernel_initialized)
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

	/*
	 * Obtain the session pointer. Also, increment the session
	 * reference count.
	 */
	rv = handle2session(hSession, &session_p);
	if (rv != CKR_OK)
		return (rv);

	/* Make sure it is a RW session. */
	if (session_p->ses_RO) {
		rv = CKR_SESSION_READ_ONLY;
		REFRELE(session_p, ses_lock_held);
		return (rv);
	}

	/* Lock the session and make the CRYPTO_SET_PIN ioctl call. */
	(void) pthread_mutex_lock(&session_p->session_mutex);
	ses_lock_held = B_TRUE;

	setpin.sp_session = session_p->k_session;
	setpin.sp_old_pin = (char *)pOldPin;
	setpin.sp_old_len = ulOldLen;
	setpin.sp_new_pin = (char *)pNewPin;
	setpin.sp_new_len = ulNewLen;

	while ((r = ioctl(kernel_fd, CRYPTO_SET_PIN, &setpin)) < 0) {
		if (errno != EINTR)
			break;
	}
	if (r < 0) {
		rv = CKR_FUNCTION_FAILED;
	} else {
		rv = crypto2pkcs11_error_number(setpin.sp_return_value);
	}

	REFRELE(session_p, ses_lock_held);
	return (rv);
}
