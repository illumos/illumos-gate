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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements the token object list operation for this tool.
 * It loads the PKCS#11 modules, finds the object to list, lists it,
 * and cleans up.  User must be logged into the token to list private
 * objects.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"
#include "derparse.h"

/*
 * Get key size based on the key type.
 */
static CK_ULONG
get_key_size(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, CK_KEY_TYPE key_type)
{
	CK_RV		rv = CKR_OK;
	CK_ULONG	key_size;
	CK_ATTRIBUTE	modulus_sz =
		{ CKA_MODULUS, NULL, 0 };	/* RSA */
	CK_ATTRIBUTE	prime_sz =
		{ CKA_PRIME, NULL, 0 };		/* DSA, DH X9.42 */
	CK_ATTRIBUTE	value_sz =
		{ CKA_VALUE, NULL_PTR, 0 };	/* DH, DES/DES3, AES, GENERIC */

	cryptodebug("inside get_key_size");

	switch (key_type) {
	case CKK_RSA:
		if ((rv = C_GetAttributeValue(sess, obj, &modulus_sz, 1)) !=
		    CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to get modulus attribute size (%s)."),
			    pkcs11_strerror(rv));
		} else
			/* Convert key size to bits. */
			key_size = modulus_sz.ulValueLen * 8;
		break;
	case CKK_DH:
		if ((rv = C_GetAttributeValue(sess, obj, &value_sz, 1)) !=
		    CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to get value attribute size (%s)."),
			    pkcs11_strerror(rv));
		} else
			/* Convert key size to bits. */
			key_size = value_sz.ulValueLen * 8;
		break;
	case CKK_X9_42_DH:
	case CKK_DSA:
		if ((rv = C_GetAttributeValue(sess, obj, &prime_sz, 1)) !=
		    CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to get prime attribute size (%s)."),
			    pkcs11_strerror(rv));
		} else
			/* Convert key size to bits. */
			key_size = prime_sz.ulValueLen * 8;
		break;
	case CKK_DES:
	case CKK_DES3:
		if ((rv = C_GetAttributeValue(sess, obj, &value_sz, 1)) !=
		    CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to get value attribute size (%s)."),
			    pkcs11_strerror(rv));
		} else
			/* Convert key size to bits -- omitting parity bit. */
			key_size = value_sz.ulValueLen * 7;
		break;
	case CKK_AES:
	case CKK_GENERIC_SECRET:
		if ((rv = C_GetAttributeValue(sess, obj, &value_sz, 1)) !=
		    CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to get value attribute size (%s)."),
			    pkcs11_strerror(rv));
		} else
			/* Convert key size to bits. */
			key_size = value_sz.ulValueLen * 8;
		break;
	default:
		cryptoerror(LOG_STDERR, gettext(
		    "Unknown object key type (0x%02x)."), key_type);
		break;
	}

	return (key_size);
}

/*
 * Display private key.
 */
static CK_RV
display_prikey(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, int counter)
{
	CK_RV			rv = CKR_OK;
	static CK_BBOOL		private;
	static CK_BBOOL		modifiable;
	static CK_KEY_TYPE	key_type;
	CK_ULONG		key_size;
	CK_BYTE			*label = NULL;
	CK_ULONG		label_len = 0;
	CK_BYTE			*id = NULL;
	CK_ULONG		id_len = 0;
	CK_BYTE			*subject = NULL;
	CK_ULONG		subject_len = 0;
	CK_DATE			*start_date = NULL;
	CK_ULONG		start_date_len = 0;
	CK_DATE			*end_date = NULL;
	CK_ULONG		end_date_len = 0;
	CK_ATTRIBUTE		attrs[18] = {
		/* 0 to 2 */
		{ CKA_PRIVATE, &private, sizeof (private) },
		{ CKA_MODIFIABLE, &modifiable, sizeof (modifiable) },
		{ CKA_KEY_TYPE, &key_type, sizeof (key_type) },
		/* 3 to 12 */
		{ CKA_DERIVE, NULL, 0 },
		{ CKA_LOCAL, NULL, 0 },
		{ CKA_DECRYPT, NULL, 0 },
		{ CKA_SIGN, NULL, 0 },
		{ CKA_SIGN_RECOVER, NULL, 0 },
		{ CKA_UNWRAP, NULL, 0 },
		{ CKA_SENSITIVE, NULL, 0 },
		{ CKA_ALWAYS_SENSITIVE, NULL, 0 },
		{ CKA_EXTRACTABLE, NULL, 0 },
		{ CKA_NEVER_EXTRACTABLE, NULL, 0 },
		/* 13 to 17 */
		{ CKA_LABEL, NULL, 0 },			/* optional */
		{ CKA_ID, NULL, 0 },			/* optional */
		{ CKA_SUBJECT, NULL, 0 },		/* optional */
		{ CKA_START_DATE, NULL, 0 },		/* optional */
		{ CKA_END_DATE, NULL, 0 }		/* optional */
		/* not displaying CKA_KEY_GEN_MECHANISM */
	    };
	CK_ULONG	n_attrs = sizeof (attrs) / sizeof (CK_ATTRIBUTE);
	int		i;
	char		*hex_id = NULL;
	int		hex_id_len = 0;
	char		*hex_subject = NULL;
	int		hex_subject_len = 0;

	cryptodebug("inside display_prikey");

	/* Get the sizes of the attributes we need. */
	cryptodebug("calling C_GetAttributeValue for size info");
	if ((rv = C_GetAttributeValue(sess, obj, attrs, n_attrs)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get private key attribute sizes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Allocate memory for each variable-length attribute. */
	for (i = 3; i < n_attrs; i++) {
		if (attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    attrs[i].ulValueLen == 0) {
			cryptodebug("display_prikey: *** should not happen");
			attrs[i].ulValueLen = 0;
			continue;
		}
		if ((attrs[i].pValue = malloc(attrs[i].ulValueLen)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_prikey;
		}
	}

	/* Now really get the attributes. */
	cryptodebug("calling C_GetAttributeValue for attribute info");
	if ((rv = C_GetAttributeValue(sess, obj, attrs, n_attrs)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get private key attributes (%s)."),
		    pkcs11_strerror(rv));
		goto free_display_prikey;
	}

	/* Fill in all the optional temp variables. */
	i = 13;
	copy_attr_to_string(&(attrs[i++]), &label, &label_len);
	copy_attr_to_string(&(attrs[i++]), &id, &id_len);
	copy_attr_to_string(&(attrs[i++]), &subject, &subject_len);
	copy_attr_to_date(&(attrs[i++]), &start_date, &start_date_len);
	copy_attr_to_date(&(attrs[i++]), &end_date, &end_date_len);

	/* Get the key size for the object. */
	key_size = get_key_size(sess, obj, key_type);

	/* Display the object ... */
		/* ... the label and what it is (and key size in bits) ... */
	(void) fprintf(stdout, gettext("%d.  \"%.*s\" (%d-bit %s %s)\n"),
	    counter, label_len, label_len > 0 ? (char *)label :
	    gettext("<no label>"), key_size, keytype_str(key_type),
	    class_str(CKO_PRIVATE_KEY));

		/* ... the id ... */
	if (id_len == (CK_ULONG)-1 || id_len == 0)
		(void) fprintf(stdout, gettext("\tId:  --\n"));
	else {
		hex_id_len = 3 * id_len + 1;
		if ((hex_id = malloc(hex_id_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_prikey;
		}
		octetify(id, id_len, hex_id, hex_id_len, B_FALSE, B_FALSE, 60,
		    "\n\t\t", "");
		(void) fprintf(stdout, gettext("\tId:  %s\n"), hex_id);
		free(hex_id);
	}

		/* ... the subject name ... */
	if (subject_len == (CK_ULONG)-1 || subject_len == 0)
		(void) fprintf(stdout, gettext("\tSubject:  --\n"));
	else {
		hex_subject_len = 2 * subject_len + 1;	/* best guesstimate */
		if ((hex_subject = malloc(hex_subject_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_prikey;
		}
		rdnseq_to_str(subject, subject_len, hex_subject,
		    hex_subject_len);
		(void) fprintf(stdout, gettext("\tSubject:  %.*s\n"),
		    hex_subject_len, hex_subject);
		free(hex_subject);
	}

		/* ... the start date ... */
	if (start_date_len == (CK_ULONG)-1 || start_date_len == 0)
		(void) fprintf(stdout, gettext("\tStart Date:  --\n"));
	else
		(void) fprintf(stdout, gettext(
		    "\tStart Date:  %02.2s/%02.2s/%04.4s\n"),
		    start_date->month, start_date->day, start_date->year);

		/* ... the end date ... */
	if (end_date_len == (CK_ULONG)-1 || end_date_len == 0)
		(void) fprintf(stdout, gettext("\tEnd Date:  --\n"));
	else
		(void) fprintf(stdout, gettext(
		    "\tEnd Date:  %02.2s/%02.2s/%04.4s\n"),
		    end_date->month, end_date->day, end_date->year);

		/* ... and its capabilities */
	(void) fprintf(stdout, "\t(%s, %s",
	    private != pk_false ? gettext("private") : gettext("public"),
	    modifiable == B_TRUE ? gettext("modifiable") :
	    gettext("not modifiable"));
	for (i = 3; i <= 12; i++) {
		if (attrs[i].ulValueLen != (CK_ULONG)-1 &&
		    attrs[i].ulValueLen != 0 &&
		    *((CK_BBOOL *)(attrs[i].pValue)) == B_TRUE)
			(void) fprintf(stdout, ", %s", attr_str(attrs[i].type));
	}
	(void) fprintf(stdout, ")\n");

free_display_prikey:
	for (i = 3; i < n_attrs; i++)
		if (attrs[i].ulValueLen != (CK_ULONG)-1 &&
		    attrs[i].ulValueLen != 0)
			free(attrs[i].pValue);
	return (rv);
}

/*
 * Display public key.
 */
static CK_RV
display_pubkey(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, int counter)
{
	CK_RV			rv = CKR_OK;
	static CK_BBOOL		private;
	static CK_BBOOL		modifiable;
	static CK_BBOOL		trusted;
	static CK_KEY_TYPE	key_type;
	CK_ULONG		key_size;
	CK_BYTE			*label = NULL;
	CK_ULONG		label_len = 0;
	CK_BYTE			*id = NULL;
	CK_ULONG		id_len = 0;
	CK_BYTE			*subject = NULL;
	CK_ULONG		subject_len = 0;
	CK_DATE			*start_date = NULL;
	CK_ULONG		start_date_len = 0;
	CK_DATE			*end_date = NULL;
	CK_ULONG		end_date_len = 0;
	CK_ATTRIBUTE		attrs[15] = {
		/* 0 to 3 */
		{ CKA_PRIVATE, &private, sizeof (private) },
		{ CKA_MODIFIABLE, &modifiable, sizeof (modifiable) },
		{ CKA_TRUSTED, &trusted, sizeof (trusted) },
		{ CKA_KEY_TYPE, &key_type, sizeof (key_type) },
		/* 4 to 9 */
		{ CKA_DERIVE, NULL, 0 },
		{ CKA_LOCAL, NULL, 0 },
		{ CKA_ENCRYPT, NULL, 0 },
		{ CKA_VERIFY, NULL, 0 },
		{ CKA_VERIFY_RECOVER, NULL, 0 },
		{ CKA_WRAP, NULL, 0 },
		/* 10 to 14 */
		{ CKA_LABEL, NULL, 0 },			/* optional */
		{ CKA_ID, NULL, 0 },			/* optional */
		{ CKA_SUBJECT, NULL, 0 },		/* optional */
		{ CKA_START_DATE, NULL, 0 },		/* optional */
		{ CKA_END_DATE, NULL, 0 }		/* optional */
		/* not displaying CKA_KEY_GEN_MECHANISM */
	    };
	CK_ULONG	n_attrs = sizeof (attrs) / sizeof (CK_ATTRIBUTE);
	int		i;
	char		*hex_id = NULL;
	int		hex_id_len = 0;
	char		*hex_subject = NULL;
	int		hex_subject_len = 0;

	cryptodebug("inside display_pubkey");

	/* Get the sizes of the attributes we need. */
	cryptodebug("calling C_GetAttributeValue for size info");
	if ((rv = C_GetAttributeValue(sess, obj, attrs, n_attrs)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get public key attribute sizes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Allocate memory for each variable-length attribute. */
	for (i = 4; i < n_attrs; i++) {
		if (attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    attrs[i].ulValueLen == 0) {
			cryptodebug("display_pubkey: *** should not happen");
			attrs[i].ulValueLen = 0;
			continue;
		}
		if ((attrs[i].pValue = malloc(attrs[i].ulValueLen)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_pubkey;
		}
	}

	/* Now really get the attributes. */
	cryptodebug("calling C_GetAttributeValue for attribute info");
	if ((rv = C_GetAttributeValue(sess, obj, attrs, n_attrs)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get public key attributes (%s)."),
		    pkcs11_strerror(rv));
		goto free_display_pubkey;
	}

	/* Fill in all the optional temp variables. */
	i = 10;
	copy_attr_to_string(&(attrs[i++]), &label, &label_len);
	copy_attr_to_string(&(attrs[i++]), &id, &id_len);
	copy_attr_to_string(&(attrs[i++]), &subject, &subject_len);
	copy_attr_to_date(&(attrs[i++]), &start_date, &start_date_len);
	copy_attr_to_date(&(attrs[i++]), &end_date, &end_date_len);

	/* Get the key size for the object. */
	key_size = get_key_size(sess, obj, key_type);

	/* Display the object ... */
		/* ... the label and what it is (and key size in bits) ... */
	(void) fprintf(stdout, gettext("%d.  \"%.*s\" (%d-bit %s %s)\n"),
	    counter, label_len, label_len > 0 ? (char *)label :
	    gettext("<no label>"), key_size, keytype_str(key_type),
	    class_str(CKO_PUBLIC_KEY));

		/* ... the id ... */
	if (id_len == (CK_ULONG)-1 || id_len == 0)
		(void) fprintf(stdout, gettext("\tId:  --\n"));
	else {
		hex_id_len = 3 * id_len + 1;
		if ((hex_id = malloc(hex_id_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_pubkey;
		}
		octetify(id, id_len, hex_id, hex_id_len, B_FALSE, B_FALSE, 60,
		    "\n\t\t", "");
		(void) fprintf(stdout, gettext("\tId:  %s\n"), hex_id);
		free(hex_id);
	}

		/* ... the subject name ... */
	if (subject_len == (CK_ULONG)-1 || subject_len == 0)
		(void) fprintf(stdout, gettext("\tSubject:  --\n"));
	else {
		hex_subject_len = 2 * subject_len + 1;	/* best guesstimate */
		if ((hex_subject = malloc(hex_subject_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_pubkey;
		}
		rdnseq_to_str(subject, subject_len, hex_subject,
		    hex_subject_len);
		(void) fprintf(stdout, gettext("\tSubject:  %.*s\n"),
		    hex_subject_len, hex_subject);
		free(hex_subject);
	}

		/* ... the start date ... */
	if (start_date_len == (CK_ULONG)-1 || start_date_len == 0)
		(void) fprintf(stdout, gettext("\tStart Date:  --\n"));
	else
		(void) fprintf(stdout, gettext(
		    "\tStart Date:  %02.2s/%02.2s/%04.4s\n"),
		    start_date->month, start_date->day, start_date->year);

		/* ... the end date ... */
	if (end_date_len == (CK_ULONG)-1 || end_date_len == 0)
		(void) fprintf(stdout, gettext("\tEnd Date:  --\n"));
	else
		(void) fprintf(stdout, gettext(
		    "\tEnd Date:  %02.2s/%02.2s/%04.4s\n"),
		    end_date->month, end_date->day, end_date->year);

		/* ... and its capabilities */
	(void) fprintf(stdout, "\t(%s, %s, %s",
	    private == B_TRUE ? gettext("private") : gettext("public"),
	    modifiable == B_TRUE ? gettext("modifiable") :
	    gettext("not modifiable"),
	    trusted == B_TRUE ? gettext("trusted") : gettext("untrusted"));
	for (i = 4; i <= 9; i++) {
		if (attrs[i].ulValueLen != (CK_ULONG)-1 &&
		    attrs[i].ulValueLen != 0 &&
		    *((CK_BBOOL *)(attrs[i].pValue)) == B_TRUE)
			(void) fprintf(stdout, ", %s", attr_str(attrs[i].type));
	}
	(void) fprintf(stdout, ")\n");

free_display_pubkey:
	for (i = 4; i < n_attrs; i++)
		if (attrs[i].ulValueLen != (CK_ULONG)-1 &&
		    attrs[i].ulValueLen != 0)
			free(attrs[i].pValue);
	return (rv);
}

/*
 * Display secret key.
 */
static CK_RV
display_seckey(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, int counter)
{
	CK_RV			rv = CKR_OK;
	static CK_BBOOL		private;
	static CK_BBOOL		modifiable;
	static CK_KEY_TYPE	key_type;
	static CK_ULONG		key_size;
	CK_BYTE			*label = NULL;
	CK_ULONG		label_len = 0;
	CK_BYTE			*id = NULL;
	CK_ULONG		id_len = 0;
	CK_DATE			*start_date = NULL;
	CK_ULONG		start_date_len = 0;
	CK_DATE			*end_date = NULL;
	CK_ULONG		end_date_len = 0;
	CK_ATTRIBUTE		attrs[19] = {
		/* 0 to 2 */
		{ CKA_PRIVATE, &private, sizeof (private) },
		{ CKA_MODIFIABLE, &modifiable, sizeof (modifiable) },
		{ CKA_KEY_TYPE, &key_type, sizeof (key_type) },
		/* 3 to 14 */
		{ CKA_DERIVE, NULL, 0 },
		{ CKA_LOCAL, NULL, 0 },
		{ CKA_ENCRYPT, NULL, 0 },
		{ CKA_DECRYPT, NULL, 0 },
		{ CKA_SIGN, NULL, 0 },
		{ CKA_VERIFY, NULL, 0 },
		{ CKA_WRAP, NULL, 0 },
		{ CKA_UNWRAP, NULL, 0 },
		{ CKA_SENSITIVE, NULL, 0 },
		{ CKA_ALWAYS_SENSITIVE, NULL, 0 },
		{ CKA_EXTRACTABLE, NULL, 0 },
		{ CKA_NEVER_EXTRACTABLE, 0 },
		/* 15 to 18 */
		{ CKA_LABEL, NULL, 0 },			/* optional */
		{ CKA_ID, NULL, 0 },			/* optional */
		{ CKA_START_DATE, NULL, 0 },		/* optional */
		{ CKA_END_DATE, NULL, 0 }		/* optional */
		/* not displaying CKA_KEY_GEN_MECHANISM */
	    };
	CK_ULONG	n_attrs = sizeof (attrs) / sizeof (CK_ATTRIBUTE);
	int		i;
	char		*hex_id = NULL;
	int		hex_id_len = 0;

	cryptodebug("inside display_seckey");

	/* Get the sizes of the attributes we need. */
	cryptodebug("calling C_GetAttributeValue for size info");
	if ((rv = C_GetAttributeValue(sess, obj, attrs, n_attrs)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get secret key attribute sizes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Allocate memory for each variable-length attribute. */
	for (i = 3; i < n_attrs; i++) {
		if (attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    attrs[i].ulValueLen == 0) {
			cryptodebug("display_seckey: *** should not happen");
			attrs[i].ulValueLen = 0;
			continue;
		}
		if ((attrs[i].pValue = malloc(attrs[i].ulValueLen)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_seckey;
		}
	}

	/* Now really get the attributes. */
	cryptodebug("calling C_GetAttributeValue for attribute info");
	if ((rv = C_GetAttributeValue(sess, obj, attrs, n_attrs)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get secret key attributes (%s)."),
		    pkcs11_strerror(rv));
		goto free_display_seckey;
	}

	/* Fill in all the optional temp variables. */
	i = 15;
	copy_attr_to_string(&(attrs[i++]), &label, &label_len);
	copy_attr_to_string(&(attrs[i++]), &id, &id_len);
	copy_attr_to_date(&(attrs[i++]), &start_date, &start_date_len);
	copy_attr_to_date(&(attrs[i++]), &end_date, &end_date_len);

	/* Get the key size for the object. */
	key_size = get_key_size(sess, obj, key_type);

	/* Display the object ... */
		/* ... the label and what it is (and key size in bytes) ... */
	(void) fprintf(stdout, gettext("%d.  \"%.*s\" (%d-bit %s %s)\n"),
	    counter, label_len, label_len > 0 ? (char *)label :
	    gettext("<no label>"), key_size, keytype_str(key_type),
	    class_str(CKO_SECRET_KEY));

		/* ... the id ... */
	if (id_len == (CK_ULONG)-1 || id_len == 0)
		(void) fprintf(stdout, gettext("\tId:  --\n"));
	else {
		hex_id_len = 3 * id_len + 1;
		if ((hex_id = malloc(hex_id_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_seckey;
		}
		octetify(id, id_len, hex_id, hex_id_len, B_FALSE, B_FALSE, 60,
		    "\n\t\t", "");
		(void) fprintf(stdout, gettext("\tId:  %s\n"), hex_id);
		free(hex_id);
	}

		/* ... the start date ... */
	if (start_date_len == (CK_ULONG)-1 || start_date_len == 0)
		(void) fprintf(stdout, gettext("\tStart Date:  --\n"));
	else
		(void) fprintf(stdout, gettext(
		    "\tStart Date:  %02.2s/%02.2s/%04.4s\n"),
		    start_date->month, start_date->day, start_date->year);

		/* ... the end date ... */
	if (end_date_len == (CK_ULONG)-1 || end_date_len == 0)
		(void) fprintf(stdout, gettext("\tEnd Date:  --\n"));
	else
		(void) fprintf(stdout, gettext(
		    "\tEnd Date:  %02.2s/%02.2s/%04.4s\n"),
		    end_date->month, end_date->day, end_date->year);

		/* ... and its capabilities */
	(void) fprintf(stdout, "\t(%s, %s",
	    private == B_TRUE ? gettext("private") : gettext("public"),
	    modifiable == B_TRUE ? gettext("modifiable") :
	    gettext("not modifiable"));
	for (i = 3; i <= 14; i++) {
		if (attrs[i].ulValueLen != (CK_ULONG)-1 &&
		    attrs[i].ulValueLen != 0 &&
		    *((CK_BBOOL *)(attrs[i].pValue)) == B_TRUE)
			(void) fprintf(stdout, ", %s", attr_str(attrs[i].type));
	}
	(void) fprintf(stdout, ")\n");

free_display_seckey:
	for (i = 3; i < n_attrs; i++)
		if (attrs[i].ulValueLen != (CK_ULONG)-1 &&
		    attrs[i].ulValueLen != 0)
			free(attrs[i].pValue);
	return (rv);
}

/*
 * Display certificate.
 */
static CK_RV
display_cert(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, int counter)
{
	CK_RV			rv = CKR_OK;
	static CK_BBOOL		private;
	static CK_BBOOL		modifiable;
	static CK_BBOOL		trusted;
	CK_BYTE			*subject = NULL;
	CK_ULONG		subject_len = 0;
	CK_BYTE			*value = NULL;
	CK_ULONG		value_len = 0;
	CK_BYTE			*label = NULL;
	CK_ULONG		label_len = 0;
	CK_BYTE			*id = NULL;
	CK_ULONG		id_len = 0;
	CK_BYTE			*issuer = NULL;
	CK_ULONG		issuer_len = 0;
	CK_BYTE			*serial = NULL;
	CK_ULONG		serial_len = 0;
	CK_ATTRIBUTE		attrs[9] = {
		{ CKA_PRIVATE, &private, sizeof (private) },
		{ CKA_MODIFIABLE, &modifiable, sizeof (modifiable) },
		{ CKA_TRUSTED, &trusted, sizeof (trusted) },
		{ CKA_SUBJECT, NULL, 0 },		/* required */
		{ CKA_VALUE, NULL, 0 },			/* required */
		{ CKA_LABEL, NULL, 0 },			/* optional */
		{ CKA_ID, NULL, 0 },			/* optional */
		{ CKA_ISSUER, NULL, 0 },		/* optional */
		{ CKA_SERIAL_NUMBER, NULL, 0 }		/* optional */
	    };
	CK_ULONG	n_attrs = sizeof (attrs) / sizeof (CK_ATTRIBUTE);
	int		i;
	char		*hex_id = NULL;
	int		hex_id_len = 0;
	char		*hex_subject = NULL;
	int		hex_subject_len = 0;
	char		*hex_issuer = NULL;
	int		hex_issuer_len = 0;
	char		*hex_serial = NULL;
	int		hex_serial_len = NULL;
	uint32_t	serial_value = 0;
	char		*hex_value = NULL;
	int		hex_value_len = 0;

	cryptodebug("inside display_cert");

	/* Get the sizes of the attributes we need. */
	cryptodebug("calling C_GetAttributeValue for size info");
	if ((rv = C_GetAttributeValue(sess, obj, attrs, n_attrs)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get certificate attribute sizes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Allocate memory for each variable-length attribute. */
	for (i = 3; i < n_attrs; i++) {
		if (attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    attrs[i].ulValueLen == 0) {
			cryptodebug("display_cert: *** should not happen");
			attrs[i].ulValueLen = 0;
			continue;
		}
		if ((attrs[i].pValue = malloc(attrs[i].ulValueLen)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_cert;
		}
	}

	/* Now really get the attributes. */
	cryptodebug("calling C_GetAttributeValue for attribute info");
	if ((rv = C_GetAttributeValue(sess, obj, attrs, n_attrs)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get certificate attributes (%s)."),
		    pkcs11_strerror(rv));
		goto free_display_cert;
	}

	/*
	 * Fill in all the temp variables.  Subject and value are required.
	 * The rest are optional.
	 */
	i = 3;
	copy_attr_to_string(&(attrs[i++]), &subject, &subject_len);
	copy_attr_to_string(&(attrs[i++]), &value, &value_len);
	copy_attr_to_string(&(attrs[i++]), &label, &label_len);
	copy_attr_to_string(&(attrs[i++]), &id, &id_len);
	copy_attr_to_string(&(attrs[i++]), &issuer, &issuer_len);
	copy_attr_to_string(&(attrs[i++]), &serial, &serial_len);

	/* Display the object ... */
		/* ... the label and what it is ... */
	(void) fprintf(stdout, gettext("%d.  \"%.*s\" (%s %s)\n"),
	    counter, label_len, label_len > 0 ? (char *)label :
	    gettext("<no label>"), "X.509", class_str(CKO_CERTIFICATE));

		/* ... its capabilities ... */
	(void) fprintf(stdout, gettext("\t(%s, %s, %s)\n"),
	    private == B_TRUE ? gettext("private") : gettext("public"),
	    modifiable == B_TRUE ? gettext("modifiable") :
	    gettext("not modifiable"),
	    trusted == B_TRUE ? gettext("trusted") : gettext("untrusted"));

		/* ... the id ... */
	if (id_len == (CK_ULONG)-1 || id_len == 0)
		(void) fprintf(stdout, gettext("\tId:  --\n"));
	else {
		hex_id_len = 3 * id_len + 1;
		if ((hex_id = malloc(hex_id_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_cert;
		}
		octetify(id, id_len, hex_id, hex_id_len, B_FALSE, B_FALSE, 60,
		    "\n\t\t", "");
		(void) fprintf(stdout, gettext("\tId:  %s\n"), hex_id);
		free(hex_id);
	}

		/* ... the subject name ... */
	if (subject_len == (CK_ULONG)-1 || subject_len == 0)
		(void) fprintf(stdout, gettext("\tSubject:  --\n"));
	else {
		hex_subject_len = 2 * subject_len + 1;	/* best guesstimate */
		if ((hex_subject = malloc(hex_subject_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_cert;
		}
		rdnseq_to_str(subject, subject_len, hex_subject,
		    hex_subject_len);
		(void) fprintf(stdout, gettext("\tSubject:  %.*s\n"),
		    hex_subject_len, hex_subject);
		free(hex_subject);
	}

		/* ... the issuer name ... */
	if (issuer_len == (CK_ULONG)-1 || issuer_len == 0)
		(void) fprintf(stdout, gettext("\tIssuer:  --\n"));
	else {
		hex_issuer_len = 2 * issuer_len + 1;	/* best guesstimate */
		if ((hex_issuer = malloc(hex_issuer_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_cert;
		}
		rdnseq_to_str(issuer, issuer_len, hex_issuer, hex_issuer_len);
		(void) fprintf(stdout, gettext("\tIssuer:  %.*s\n"),
		    hex_issuer_len, hex_issuer);
		free(hex_issuer);
	}

		/* ... the serial number ... */
	if (serial_len == (CK_ULONG)-1 || serial_len == 0)
		(void) fprintf(stdout, gettext("\tSerial:  --\n"));
	else {
		hex_serial_len = 3 * serial_len + 1;
		if ((hex_serial = malloc(hex_serial_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_cert;
		}
		octetify(serial, serial_len, hex_serial, hex_serial_len,
		    B_FALSE, B_FALSE, 60, "\n\t\t", "");
		if (serial_len > 4)
			(void) fprintf(stdout, gettext("\tSerial:  %s\n"),
			    hex_serial);
		else {
			for (i = 0; i < serial_len; i++) {
				serial_value <<= 8;
				serial_value |= (serial[i] & 0xff);
			}
			(void) fprintf(stdout, gettext("\tSerial:  %s (%d)\n"),
			    hex_serial, serial_value);
		}
		free(hex_serial);
	}

		/* ... and the value */
	if (value_len == (CK_ULONG)-1 || value_len == 0)
		(void) fprintf(stdout, gettext("\tValue:  --\n"));
	else {
		hex_value_len = 3 * value_len + 1;
		if ((hex_value = malloc(hex_value_len)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			rv = CKR_HOST_MEMORY;
			goto free_display_cert;
		}
		octetify(value, value_len, hex_value, hex_value_len,
		    B_FALSE, B_FALSE, 60, "\n\t\t", "");
		(void) fprintf(stdout, gettext("\tValue:  %s\n"), hex_value);
		free(hex_value);
	}

free_display_cert:
	for (i = 3; i < n_attrs; i++)
		if (attrs[i].ulValueLen != (CK_ULONG)-1 &&
		    attrs[i].ulValueLen != 0)
			free(attrs[i].pValue);
	return (rv);
}

/*
 * List token object.
 */
int
pk_list(int argc, char *argv[])
{
	int			opt;
	extern int		optind;
	extern char		*optarg;
	char			*token_name = NULL;
	char			*manuf_id = NULL;
	char			*serial_no = NULL;
	char			full_name[FULL_NAME_LEN];
	boolean_t		public_objs = B_FALSE;
	boolean_t		private_objs = B_FALSE;
	CK_BYTE			*list_label = NULL;
	int			obj_type = 0x00;
	CK_SLOT_ID		slot_id;
	CK_FLAGS		pin_state;
	CK_UTF8CHAR_PTR		pin = NULL;
	CK_ULONG		pinlen = 0;
	CK_SESSION_HANDLE	sess;
	CK_OBJECT_HANDLE	*objs;
	CK_ULONG		num_objs;
	CK_RV			rv = CKR_OK;
	int			i;
	static CK_OBJECT_CLASS	objclass;
	CK_ATTRIBUTE		class_attr =
		{ CKA_CLASS, &objclass, sizeof (objclass) };

	cryptodebug("inside pk_list");

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt(argc, argv, "p(private)P(public)l:(label)")) !=
	    EOF) {
		switch (opt) {
		case 'p':	/* private objects */
			private_objs = B_TRUE;
			obj_type |= PK_PRIVATE_OBJ;
			break;
		case 'P':	/* public objects */
			public_objs = B_TRUE;
			obj_type |= PK_PUBLIC_OBJ;
			break;
		case 'l':	/* object with specific label */
			if (list_label)
				return (PK_ERR_USAGE);
			list_label = (CK_BYTE *)optarg;
			break;
		default:
			return (PK_ERR_USAGE);
			break;
		}
	}

	/* If nothing specified, default is public objects. */
	if (!public_objs && !private_objs) {
		public_objs = B_TRUE;
		obj_type |= PK_PUBLIC_OBJ;
	}

	/* No additional args allowed. */
	argc -= optind;
	argv += optind;
	if (argc)
		return (PK_ERR_USAGE);
	/* Done parsing command line options. */

	/* List operation only supported on softtoken. */
	if (token_name == NULL)
		token_name = SOFT_TOKEN_LABEL;
	if (manuf_id == NULL)
		manuf_id = SOFT_MANUFACTURER_ID;
	if (serial_no == NULL)
		serial_no = SOFT_TOKEN_SERIAL;
	full_token_name(token_name, manuf_id, serial_no, full_name);

	/* Find the slot with token. */
	if ((rv = find_token_slot(token_name, manuf_id, serial_no, &slot_id,
	    &pin_state)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to find token %s (%s)."), full_name,
		    pkcs11_strerror(rv));
		return (PK_ERR_PK11);
	}

	/* If private objects are to be listed, user must be logged in. */
	if (private_objs) {
		/* Get the user's PIN. */
		if ((rv = get_pin(gettext("Enter token passphrase:"), NULL,
		    &pin, &pinlen)) != CKR_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("Unable to get token passphrase (%s)."),
			    pkcs11_strerror(rv));
			quick_finish(NULL);
			return (PK_ERR_PK11);
		}

		/* Logging in user R/O into the token is sufficient. */
		cryptodebug("logging in with readonly session");
		if ((rv = quick_start(slot_id, 0, pin, pinlen, &sess)) !=
		    CKR_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("Unable to log into token (%s)."),
			    pkcs11_strerror(rv));
			quick_finish(sess);
			return (PK_ERR_PK11);
		}
	/* Otherwise, just create a session. */
	} else {
		cryptodebug("opening a readonly session");
		if ((rv = open_sess(slot_id, 0, &sess)) != CKR_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("Unable to open token session (%s)."),
			    pkcs11_strerror(rv));
			quick_finish(sess);
			return (PK_ERR_PK11);
		}
	}

	/* Find the object(s) with the given label and/or type. */
	if ((rv = find_objs(sess, obj_type, list_label, &objs, &num_objs)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to find token objects (%s)."), pkcs11_strerror(rv));
		quick_finish(sess);
		return (PK_ERR_PK11);
	}

	if (num_objs == 0) {
		cryptoerror(LOG_STDERR, gettext("No objects found."));
		quick_finish(sess);
		return (0);
	}

	/* List the objects found. */
	for (i = 0; i < num_objs; i++) {
		/* Get object class first, then decide what is next. */
		cryptodebug("calling C_GetAttributeValue for object class");
		if ((rv = C_GetAttributeValue(sess, objs[i], &class_attr, 1))
		    != CKR_OK) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to get object #%d class attribute (%s)."),
			    i+1, pkcs11_strerror(rv));
			continue;
		}

		/* Display based on the type of object. */
		switch (objclass) {
		case CKO_CERTIFICATE:
			if ((rv = display_cert(sess, objs[i], i+1)) != CKR_OK)
				cryptoerror(LOG_STDERR,
				    gettext("Unable to display certificate."));
			break;
		case CKO_PUBLIC_KEY:
			if ((rv = display_pubkey(sess, objs[i], i+1)) != CKR_OK)
				cryptoerror(LOG_STDERR,
				    gettext("Unable to display public key."));
			break;
		case CKO_PRIVATE_KEY:
			if ((rv = display_prikey(sess, objs[i], i+1)) != CKR_OK)
				cryptoerror(LOG_STDERR,
				    gettext("Unable to display private key."));
			break;
		case CKO_SECRET_KEY:
			if ((rv = display_seckey(sess, objs[i], i+1)) != CKR_OK)
				cryptoerror(LOG_STDERR,
				    gettext("Unable to display secret key."));
			break;
		case CKO_DATA:
			cryptoerror(LOG_STDERR,
			    gettext("Data object display not implemented."));
			break;
		default:
			cryptoerror(LOG_STDERR, gettext(
			    "Unknown token object class (0x%02x)."), objclass);
			break;
		}
	}

	/* Clean up. */
	quick_finish(sess);
	return (0);
}
