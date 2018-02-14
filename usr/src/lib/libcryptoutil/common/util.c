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
 * Copyright 2018, Joyent, Inc.
 */

#include <cryptoutil.h>
#include <strings.h>
#include <stdio.h>
#include <tzfile.h>
#include <sys/crypto/common.h>

/*
 * In order to fit everything on one line, the 'CRYPTO_' prefix
 * has been dropped from the KCF #defines, e.g.
 * CRYPTO_SUCCESS becomes SUCCESS.
 */

static CK_RV error_number_table[CRYPTO_LAST_ERROR + 1] = {
CKR_OK,					/* SUCCESS */
CKR_CANCEL,				/* CANCEL */
CKR_HOST_MEMORY,			/* HOST_MEMORY */
CKR_GENERAL_ERROR,			/* GENERAL_ERROR */
CKR_FUNCTION_FAILED,			/* FAILED */
CKR_ARGUMENTS_BAD,			/* ARGUMENTS_BAD */
CKR_ATTRIBUTE_READ_ONLY,		/* ATTRIBUTE_READ_ONLY */
CKR_ATTRIBUTE_SENSITIVE,		/* ATTRIBUTE_SENSITIVE */
CKR_ATTRIBUTE_TYPE_INVALID,		/* ATTRIBUTE_TYPE_INVALID */
CKR_ATTRIBUTE_VALUE_INVALID,		/* ATTRIBUTE_VALUE_INVALID */
CKR_FUNCTION_FAILED,			/* CANCELED */
CKR_DATA_INVALID,			/* DATA_INVALID */
CKR_DATA_LEN_RANGE,			/* DATA_LEN_RANGE */
CKR_DEVICE_ERROR,			/* DEVICE_ERROR */
CKR_DEVICE_MEMORY,			/* DEVICE_MEMORY */
CKR_DEVICE_REMOVED,			/* DEVICE_REMOVED */
CKR_ENCRYPTED_DATA_INVALID,		/* ENCRYPTED_DATA_INVALID */
CKR_ENCRYPTED_DATA_LEN_RANGE,		/* ENCRYPTED_DATA_LEN_RANGE */
CKR_KEY_HANDLE_INVALID,			/* KEY_HANDLE_INVALID */
CKR_KEY_SIZE_RANGE,			/* KEY_SIZE_RANGE */
CKR_KEY_TYPE_INCONSISTENT,		/* KEY_TYPE_INCONSISTENT */
CKR_KEY_NOT_NEEDED,			/* KEY_NOT_NEEDED */
CKR_KEY_CHANGED,			/* KEY_CHANGED */
CKR_KEY_NEEDED,				/* KEY_NEEDED */
CKR_KEY_INDIGESTIBLE,			/* KEY_INDIGESTIBLE */
CKR_KEY_FUNCTION_NOT_PERMITTED,		/* KEY_FUNCTION_NOT_PERMITTED */
CKR_KEY_NOT_WRAPPABLE,			/* KEY_NOT_WRAPPABLE */
CKR_KEY_UNEXTRACTABLE,			/* KEY_UNEXTRACTABLE */
CKR_MECHANISM_INVALID,			/* MECHANISM_INVALID */
CKR_MECHANISM_PARAM_INVALID,		/* MECHANISM_PARAM_INVALID */
CKR_OBJECT_HANDLE_INVALID,		/* OBJECT_HANDLE_INVALID */
CKR_OPERATION_ACTIVE,			/* OPERATION_ACTIVE */
CKR_OPERATION_NOT_INITIALIZED,		/* OPERATION_NOT_INITIALIZED */
CKR_PIN_INCORRECT,			/* PIN_INCORRECT */
CKR_PIN_INVALID,			/* PIN_INVALID */
CKR_PIN_LEN_RANGE,			/* PIN_LEN_RANGE */
CKR_PIN_EXPIRED,			/* PIN_EXPIRED */
CKR_PIN_LOCKED,				/* PIN_LOCKED */
CKR_SESSION_CLOSED,			/* SESSION_CLOSED */
CKR_SESSION_COUNT,			/* SESSION_COUNT */
CKR_SESSION_HANDLE_INVALID,		/* SESSION_HANDLE_INVALID */
CKR_SESSION_READ_ONLY,			/* SESSION_READ_ONLY */
CKR_SESSION_EXISTS,			/* SESSION_EXISTS */
CKR_SESSION_READ_ONLY_EXISTS,		/* SESSION_READ_ONLY_EXISTS */
CKR_SESSION_READ_WRITE_SO_EXISTS,	/* SESSION_READ_WRITE_SO_EXISTS */
CKR_SIGNATURE_INVALID,			/* SIGNATURE_INVALID */
CKR_SIGNATURE_LEN_RANGE,		/* SIGNATURE_LEN_RANGE */
CKR_TEMPLATE_INCOMPLETE,		/* TEMPLATE_INCOMPLETE */
CKR_TEMPLATE_INCONSISTENT,		/* TEMPLATE_INCONSISTENT */
CKR_UNWRAPPING_KEY_HANDLE_INVALID,	/* UNWRAPPING_KEY_HANDLE_INVALID */
CKR_UNWRAPPING_KEY_SIZE_RANGE,		/* UNWRAPPING_KEY_SIZE_RANGE */
CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,	/* UNWRAPPING_KEY_TYPE_INCONSISTENT */
CKR_USER_ALREADY_LOGGED_IN,		/* USER_ALREADY_LOGGED_IN */
CKR_USER_NOT_LOGGED_IN,			/* USER_NOT_LOGGED_IN */
CKR_USER_PIN_NOT_INITIALIZED,		/* USER_PIN_NOT_INITIALIZED */
CKR_USER_TYPE_INVALID,			/* USER_TYPE_INVALID */
CKR_USER_ANOTHER_ALREADY_LOGGED_IN,	/* USER_ANOTHER_ALREADY_LOGGED_IN */
CKR_USER_TOO_MANY_TYPES,		/* USER_TOO_MANY_TYPES */
CKR_WRAPPED_KEY_INVALID,		/* WRAPPED_KEY_INVALID */
CKR_WRAPPED_KEY_LEN_RANGE,		/* WRAPPED_KEY_LEN_RANGE */
CKR_WRAPPING_KEY_HANDLE_INVALID,	/* WRAPPING_KEY_HANDLE_INVALID */
CKR_WRAPPING_KEY_SIZE_RANGE,		/* WRAPPING_KEY_SIZE_RANGE */
CKR_WRAPPING_KEY_TYPE_INCONSISTENT,	/* WRAPPING_KEY_TYPE_INCONSISTENT */
CKR_RANDOM_SEED_NOT_SUPPORTED,		/* RANDOM_SEED_NOT_SUPPORTED */
CKR_RANDOM_NO_RNG,			/* RANDOM_NO_RNG */
CKR_DOMAIN_PARAMS_INVALID,		/* DOMAIN_PARAMS_INVALID */
CKR_BUFFER_TOO_SMALL,			/* BUFFER_TOO_SMALL */
CKR_INFORMATION_SENSITIVE,		/* INFORMATION_SENSITIVE */
CKR_FUNCTION_NOT_SUPPORTED,		/* NOT_SUPPORTED */
CKR_GENERAL_ERROR,			/* QUEUED */
CKR_GENERAL_ERROR,			/* BUFFER_TOO_BIG */
CKR_OPERATION_NOT_INITIALIZED,		/* INVALID_CONTEXT */
CKR_GENERAL_ERROR,			/* INVALID_MAC */
CKR_GENERAL_ERROR,			/* MECH_NOT_SUPPORTED */
CKR_GENERAL_ERROR,			/* INCONSISTENT_ATTRIBUTE */
CKR_GENERAL_ERROR,			/* NO_PERMISSION */
CKR_SLOT_ID_INVALID,			/* INVALID_PROVIDER_ID */
CKR_GENERAL_ERROR,			/* VERSION_MISMATCH */
CKR_GENERAL_ERROR,			/* BUSY */
CKR_GENERAL_ERROR,			/* UNKNOWN_PROVIDER */
CKR_GENERAL_ERROR,			/* MODVERIFICATION_FAILED */
CKR_GENERAL_ERROR,			/* OLD_CTX_TEMPLATE */
CKR_GENERAL_ERROR,			/* WEAK_KEY */
CKR_GENERAL_ERROR			/* FIPS140_ERROR */
};

#if CRYPTO_LAST_ERROR != CRYPTO_FIPS140_ERROR
#error "Crypto to PKCS11 error mapping table needs to be updated!"
#endif

/*
 * This function returns a fullpath based on the "dir" and "filepath" input
 * arugments.
 * - If the filepath specified does not start with a "/" and the directory
 *   is also given, prepend the directory to the filename.
 * - If only dir or filepath is given, this function returns a copy of the
 *   given argument.
 * - If the filepath is fully qualified already and the "dir" is also
 *   given, return NULL to indicate an error.
 */
char *
get_fullpath(char *dir, char *filepath)
{
	char *fullpath = NULL;
	int pathlen = 0;
	int dirlen = 0;

	if (filepath != NULL)
		pathlen = strlen(filepath);

	if (dir != NULL)
		dirlen = strlen(dir);

	if (pathlen > 0 && dirlen > 0) {
		if (filepath[0] != '/') {
			int len = pathlen + dirlen + 2;
			fullpath = (char *)malloc(len);
			if (fullpath != NULL)
				(void) snprintf(fullpath, len, "%s/%s",
				    dir, filepath);
		} else {
			return (NULL);
		}
	} else if (pathlen > 0) {
		fullpath = (char *)strdup(filepath);
	} else if (dirlen > 0) {
		fullpath = (char *)strdup(dir);
	}

	return (fullpath);
}

/*
 * This function converts the input string to the value of time
 * in seconds.
 * - If the input string is NULL, return zero second.
 * - The input string needs to be in the form of:
 *   number-second(s), number-minute(s), number-hour(s) or
 *   number-day(s).
 */
int
str2lifetime(char *ltimestr, uint32_t *ltime)
{
	int num;
	char timetok[10];

	if (ltimestr == NULL || !strlen(ltimestr)) {
		*ltime = 0;
		return (0);
	}

	(void) memset(timetok, 0, sizeof (timetok));
	if (sscanf(ltimestr, "%d-%08s", &num, timetok) != 2)
		return (-1);

	if (!strcasecmp(timetok, "second") ||
	    !strcasecmp(timetok, "seconds")) {
		*ltime = num;
	} else if (!strcasecmp(timetok, "minute") ||
	    !strcasecmp(timetok, "minutes")) {
		*ltime = num * SECSPERMIN;
	} else if (!strcasecmp(timetok, "day") ||
	    !strcasecmp(timetok, "days")) {
		*ltime = num * SECSPERDAY;
	} else if (!strcasecmp(timetok, "hour") ||
	    !strcasecmp(timetok, "hours")) {
		*ltime = num * SECSPERHOUR;
	} else {
		*ltime = 0;
		return (-1);
	}

	return (0);
}

/*
 * Map KCF error codes into PKCS11 error codes.
 */
CK_RV
crypto2pkcs11_error_number(uint_t n)
{
	if (n >= sizeof (error_number_table) / sizeof (error_number_table[0]))
		return (CKR_GENERAL_ERROR);

	return (error_number_table[n]);
}
