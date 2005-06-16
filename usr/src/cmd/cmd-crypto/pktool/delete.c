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
 * This file implements the token object delete operation for this tool.
 * It loads the PKCS#11 modules, finds the object to delete, deletes it,
 * and cleans up.  User must be R/W logged into the token.
 */

#include <stdio.h>
#include <string.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

/*
 * Delete token objects.
 */
int
pk_delete(int argc, char *argv[])
{
	int		opt;
	extern int	optind;
	extern char	*optarg;
	char		*token_name = NULL;
	char		*manuf_id = NULL;
	char		*serial_no = NULL;
	char		full_name[FULL_NAME_LEN];
	boolean_t	public_objs = B_FALSE;
	boolean_t	private_objs = B_FALSE;
	CK_BYTE		*object_label = NULL;
	int		obj_type = 0x00;
	CK_SLOT_ID	slot_id;
	CK_FLAGS	pin_state;
	CK_UTF8CHAR_PTR	pin = NULL;
	CK_ULONG	pinlen = 0;
	CK_SESSION_HANDLE	sess;
	CK_OBJECT_HANDLE	*objs;
	CK_ULONG	num_objs;
	CK_ATTRIBUTE	label = { CKA_LABEL, NULL, 0 };
	CK_RV		rv = CKR_OK;
	int		i;

	cryptodebug("inside pk_delete");

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
		case 'l':	/* objects with specific label */
			if (object_label)
				return (PK_ERR_USAGE);
			object_label = (CK_BYTE *)optarg;
			break;
		default:
			return (PK_ERR_USAGE);
			break;
		}
	}

	/* At least one of public, private, or object label is required. */
	if (!private_objs && !public_objs && object_label == NULL)
		return (PK_ERR_USAGE);

	/*
	 * If object label is given but neither public/private is specified,
	 * delete all objects with that label.
	 */
	if (!private_objs && !public_objs && object_label != NULL)
		obj_type = PK_ALL_OBJ;

	/* No additional args allowed. */
	argc -= optind;
	argv += optind;
	if (argc)
		return (PK_ERR_USAGE);
	/* Done parsing command line options. */

	/* Delete operation only supported on softtoken. */
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

	/* Always get the user's PIN for delete operations. */
	if ((rv = get_pin(gettext("Enter token passphrase:"), NULL, &pin,
	    &pinlen)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get token passphrase (%s)."),
		    pkcs11_strerror(rv));
		quick_finish(NULL);
		return (PK_ERR_PK11);
	}

	/* Log the user R/W into the token. */
	if ((rv = quick_start(slot_id, CKF_RW_SESSION, pin, pinlen, &sess)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to log into token (%s)."), pkcs11_strerror(rv));
		quick_finish(sess);
		return (PK_ERR_PK11);
	}

	/* Find the object(s) with the given label and/or type. */
	if ((rv = find_objs(sess, obj_type, object_label, &objs, &num_objs)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to find token objects (%s)."), pkcs11_strerror(rv));
		quick_finish(sess);
		return (PK_ERR_PK11);
	}

	if (num_objs == 0) {
		(void) fprintf(stdout, gettext("No matching objects found.\n"));
		quick_finish(sess);
		return (0);
	}

	if (num_objs != 1) {
		(void) fprintf(stdout, gettext(
		    "Warning: %d matching objects found, deleting all.\n"),
		    num_objs);
		if (yesno(gettext("Continue with delete? "),
		    gettext("Respond with yes or no.\n"), B_FALSE) == B_FALSE) {
			quick_finish(sess);
			return (0);
		}
	}

	/* Destroy the objects if found. */
	for (i = 0; i < num_objs; i++) {
		/*
		 * To give nice feedback to the user, get the object's
		 * label before deleting it.
		 */
		cryptodebug("calling C_GetAttributeValue for label");
		label.pValue = NULL;
		label.ulValueLen = 0;
		if (C_GetAttributeValue(sess, objs[i], &label, 1) == CKR_OK) {
			if (label.ulValueLen != (CK_ULONG)-1 &&
			    label.ulValueLen != 0 &&
			    (label.pValue = malloc(label.ulValueLen)) != NULL) {
				if (C_GetAttributeValue(sess, objs[i], &label,
				    1) != CKR_OK) {
					free(label.pValue);
					label.pValue = NULL;
					label.ulValueLen = 0;
				}
			} else {
				label.ulValueLen = 0;
			}
		}

		cryptodebug("calling C_DestroyObject");
		if ((rv = C_DestroyObject(sess, objs[i])) != CKR_OK) {
			if (label.pValue != NULL)
				cryptoerror(LOG_STDERR, gettext(
				    "Unable to delete object #%d \"%.*s\" "
				    "(%s)."), i+1, label.ulValueLen,
				    label.pValue, pkcs11_strerror(rv));
			else
				cryptoerror(LOG_STDERR, gettext(
				    "Unable to delete object #%d (%s)."),
				    i+1, pkcs11_strerror(rv));
		} else {
			if (label.pValue != NULL)
				(void) fprintf(stdout, gettext("Object #%d "
				    "\"%.*s\" successfully deleted.\n"),
				    i+1, label.ulValueLen, label.pValue);
			else
				(void) fprintf(stdout, gettext(
				    "Object #%d successfully deleted.\n"), i+1);
		}

		if (label.pValue != NULL)
			free(label.pValue);
	}

	/* Clean up. */
	quick_finish(sess);
	return (0);
}
