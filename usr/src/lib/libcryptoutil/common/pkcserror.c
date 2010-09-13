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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Block comment which describes the contents of this file.
 */

#include <stdio.h>
#include <security/cryptoki.h>

/*
 * pkcs11_strerror: returns a string representation of the given return code.
 * The string returned is static pointer.  It doesn't need to be free'd
 * by the caller.
 */
char *
pkcs11_strerror(CK_RV rv)
{
	static char errstr[128];

	switch (rv) {
		case CKR_OK:
			return ("CKR_OK");
			break;
		case CKR_CANCEL:
			return ("CKR_CANCEL");
			break;
		case CKR_HOST_MEMORY:
			return ("CKR_HOST_MEMORY");
			break;
		case CKR_SLOT_ID_INVALID:
			return ("CKR_SLOT_ID_INVALID");
			break;
		case CKR_GENERAL_ERROR:
			return ("CKR_GENERAL_ERROR");
			break;
		case CKR_FUNCTION_FAILED:
			return ("CKR_FUNCTION_FAILED");
			break;
		case CKR_ARGUMENTS_BAD:
			return ("CKR_ARGUMENTS_BAD");
			break;
		case CKR_NO_EVENT:
			return ("CKR_NO_EVENT");
			break;
		case CKR_NEED_TO_CREATE_THREADS:
			return ("CKR_NEED_TO_CREATE_THREADS");
			break;
		case CKR_CANT_LOCK:
			return ("CKR_CANT_LOCK");
			break;
		case CKR_ATTRIBUTE_READ_ONLY:
			return ("CKR_ATTRIBUTE_READ_ONLY");
			break;
		case CKR_ATTRIBUTE_SENSITIVE:
			return ("CKR_ATTRIBUTE_SENSITIVE");
			break;
		case CKR_ATTRIBUTE_TYPE_INVALID:
			return ("CKR_ATTRIBUTE_TYPE_INVALID");
			break;
		case CKR_ATTRIBUTE_VALUE_INVALID:
			return ("CKR_ATTRIBUTE_VALUE_INVALID");
			break;
		case CKR_DATA_INVALID:
			return ("CKR_DATA_INVALID");
			break;
		case CKR_DATA_LEN_RANGE:
			return ("CKR_DATA_LEN_RANGE");
			break;
		case CKR_DEVICE_ERROR:
			return ("CKR_DEVICE_ERROR");
			break;
		case CKR_DEVICE_MEMORY:
			return ("CKR_DEVICE_MEMORY");
			break;
		case CKR_DEVICE_REMOVED:
			return ("CKR_DEVICE_REMOVED");
			break;
		case CKR_ENCRYPTED_DATA_INVALID:
			return ("CKR_ENCRYPTED_DATA_INVALID");
			break;
		case CKR_ENCRYPTED_DATA_LEN_RANGE:
			return ("CKR_ENCRYPTED_DATA_LEN_RANGE");
			break;
		case CKR_FUNCTION_CANCELED:
			return ("CKR_FUNCTION_CANCELED");
			break;
		case CKR_FUNCTION_NOT_PARALLEL:
			return ("CKR_FUNCTION_NOT_PARALLEL");
			break;
		case CKR_FUNCTION_NOT_SUPPORTED:
			return ("CKR_FUNCTION_NOT_SUPPORTED");
			break;
		case CKR_KEY_HANDLE_INVALID:
			return ("CKR_KEY_HANDLE_INVALID");
			break;
		case CKR_KEY_SIZE_RANGE:
			return ("CKR_KEY_SIZE_RANGE");
			break;
		case CKR_KEY_TYPE_INCONSISTENT:
			return ("CKR_KEY_TYPE_INCONSISTENT");
			break;
		case CKR_KEY_NOT_NEEDED:
			return ("CKR_KEY_NOT_NEEDED");
			break;
		case CKR_KEY_CHANGED:
			return ("CKR_KEY_CHANGED");
			break;
		case CKR_KEY_NEEDED:
			return ("CKR_KEY_NEEDED");
			break;
		case CKR_KEY_INDIGESTIBLE:
			return ("CKR_KEY_INDIGESTIBLE");
			break;
		case CKR_KEY_FUNCTION_NOT_PERMITTED:
			return ("CKR_KEY_FUNCTION_NOT_PERMITTED");
			break;
		case CKR_KEY_NOT_WRAPPABLE:
			return ("CKR_KEY_NOT_WRAPPABLE");
			break;
		case CKR_KEY_UNEXTRACTABLE:
			return ("CKR_KEY_UNEXTRACTABLE");
			break;
		case CKR_MECHANISM_INVALID:
			return ("CKR_MECHANISM_INVALID");
			break;
		case CKR_MECHANISM_PARAM_INVALID:
			return ("CKR_MECHANISM_PARAM_INVALID");
			break;
		case CKR_OBJECT_HANDLE_INVALID:
			return ("CKR_OBJECT_HANDLE_INVALID");
			break;
		case CKR_OPERATION_ACTIVE:
			return ("CKR_OPERATION_ACTIVE");
			break;
		case CKR_OPERATION_NOT_INITIALIZED:
			return ("CKR_OPERATION_NOT_INITIALIZED");
			break;
		case CKR_PIN_INCORRECT:
			return ("CKR_PIN_INCORRECT");
			break;
		case CKR_PIN_INVALID:
			return ("CKR_PIN_INVALID");
			break;
		case CKR_PIN_LEN_RANGE:
			return ("CKR_PIN_LEN_RANGE");
			break;
		case CKR_PIN_EXPIRED:
			return ("CKR_PIN_EXPIRED");
			break;
		case CKR_PIN_LOCKED:
			return ("CKR_PIN_LOCKED");
			break;
		case CKR_SESSION_CLOSED:
			return ("CKR_SESSION_CLOSED");
			break;
		case CKR_SESSION_COUNT:
			return ("CKR_SESSION_COUNT");
			break;
		case CKR_SESSION_HANDLE_INVALID:
			return ("CKR_SESSION_HANDLE_INVALID");
			break;
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
			return ("CKR_SESSION_PARALLEL_NOT_SUPPORTED");
			break;
		case CKR_SESSION_READ_ONLY:
			return ("CKR_SESSION_READ_ONLY");
			break;
		case CKR_SESSION_EXISTS:
			return ("CKR_SESSION_EXISTS");
			break;
		case CKR_SESSION_READ_ONLY_EXISTS:
			return ("CKR_SESSION_READ_ONLY_EXISTS");
			break;
		case CKR_SESSION_READ_WRITE_SO_EXISTS:
			return ("CKR_SESSION_READ_WRITE_SO_EXISTS");
			break;
		case CKR_SIGNATURE_INVALID:
			return ("CKR_SIGNATURE_INVALID");
			break;
		case CKR_SIGNATURE_LEN_RANGE:
			return ("CKR_SIGNATURE_LEN_RANGE");
			break;
		case CKR_TEMPLATE_INCOMPLETE:
			return ("CKR_TEMPLATE_INCOMPLETE");
			break;
		case CKR_TEMPLATE_INCONSISTENT:
			return ("CKR_TEMPLATE_INCONSISTENT");
			break;
		case CKR_TOKEN_NOT_PRESENT:
			return ("CKR_TOKEN_NOT_PRESENT");
			break;
		case CKR_TOKEN_NOT_RECOGNIZED:
			return ("CKR_TOKEN_NOT_RECOGNIZED");
			break;
		case CKR_TOKEN_WRITE_PROTECTED:
			return ("CKR_TOKEN_WRITE_PROTECTED");
			break;
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
			return ("CKR_UNWRAPPING_KEY_HANDLE_INVALID");
			break;
		case CKR_UNWRAPPING_KEY_SIZE_RANGE:
			return ("CKR_UNWRAPPING_KEY_SIZE_RANGE");
			break;
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
			return ("CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT");
			break;
		case CKR_USER_ALREADY_LOGGED_IN:
			return ("CKR_USER_ALREADY_LOGGED_IN");
			break;
		case CKR_USER_NOT_LOGGED_IN:
			return ("CKR_USER_NOT_LOGGED_IN");
			break;
		case CKR_USER_PIN_NOT_INITIALIZED:
			return ("CKR_USER_PIN_NOT_INITIALIZED");
			break;
		case CKR_USER_TYPE_INVALID:
			return ("CKR_USER_TYPE_INVALID");
			break;
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
			return ("CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
			break;
		case CKR_USER_TOO_MANY_TYPES:
			return ("CKR_USER_TOO_MANY_TYPES");
			break;
		case CKR_WRAPPED_KEY_INVALID:
			return ("CKR_WRAPPED_KEY_INVALID");
			break;
		case CKR_WRAPPED_KEY_LEN_RANGE:
			return ("CKR_WRAPPED_KEY_LEN_RANGE");
			break;
		case CKR_WRAPPING_KEY_HANDLE_INVALID:
			return ("CKR_WRAPPING_KEY_HANDLE_INVALID");
			break;
		case CKR_WRAPPING_KEY_SIZE_RANGE:
			return ("CKR_WRAPPING_KEY_SIZE_RANGE");
			break;
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
			return ("CKR_WRAPPING_KEY_TYPE_INCONSISTENT");
			break;
		case CKR_RANDOM_SEED_NOT_SUPPORTED:
			return ("CKR_RANDOM_SEED_NOT_SUPPORTED");
			break;
		case CKR_RANDOM_NO_RNG:
			return ("CKR_RANDOM_NO_RNG");
			break;
		case CKR_DOMAIN_PARAMS_INVALID:
			return ("CKR_DOMAIN_PARAMS_INVALID");
			break;
		case CKR_BUFFER_TOO_SMALL:
			return ("CKR_BUFFER_TOO_SMALL");
			break;
		case CKR_SAVED_STATE_INVALID:
			return ("CKR_SAVED_STATE_INVALID");
			break;
		case CKR_INFORMATION_SENSITIVE:
			return ("CKR_INFORMATION_SENSITIVE");
			break;
		case CKR_STATE_UNSAVEABLE:
			return ("CKR_STATE_UNSAVEABLE");
			break;
		case CKR_CRYPTOKI_NOT_INITIALIZED:
			return ("CKR_CRYPTOKI_NOT_INITIALIZED");
			break;
		case CKR_CRYPTOKI_ALREADY_INITIALIZED:
			return ("CKR_CRYPTOKI_ALREADY_INITIALIZED");
			break;
		case CKR_MUTEX_BAD:
			return ("CKR_MUTEX_BAD");
			break;
		case CKR_MUTEX_NOT_LOCKED:
			return ("CKR_MUTEX_NOT_LOCKED");
			break;
		case CKR_VENDOR_DEFINED:
			return ("CKR_VENDOR_DEFINED");
			break;
		default:
			/* rv not found */
			(void) snprintf(errstr, sizeof (errstr),
			    "Unknown return code: 0x%lx", rv);
			return (errstr);
			break;
	}
}
