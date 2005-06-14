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
 * This file contains the functions that are shared among
 * the various services this tool will ultimately provide.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

/* Global PKCS#11 error value. */
int		pk11_errno = 0;

/*
 * Gets passphrase from user, caller needs to free when done.
 */
int
get_password(char *prompt, char **password)
{
	char		*phrase;

	/* Prompt user for password. */
	if ((phrase = getpassphrase(prompt)) == NULL)
		return (-1);

	/* Duplicate passphrase in separate chunk of memory */
	if ((*password = strdup(phrase)) == NULL)
		return (-1);

	return (strlen(phrase));
}

/*
 * Perform any PKCS#11 setup here.  Right now, this tool only
 * requires C_Initialize().  Additional features planned for
 * this tool will require more initialization and state info
 * added here.
 */
int
init_pk11(void)
{
	int		rv;

	cryptodebug("inside init_pk11");

	/* Initialize PKCS#11 library. */
	if ((rv = C_Initialize(NULL_PTR)) != CKR_OK &&
	    rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		pk11_errno = rv;
		return (PK_ERR_PK11INIT);
	}

	return (PK_ERR_NONE);
}

/*
 * memcmp_pad_max() is a specialized version of memcmp() which
 * compares two pieces of data up to a maximum length.  If the
 * the two data match up the maximum length, they are considered
 * matching.  Trailing blanks do not cause the match to fail if
 * one of the data is shorted.
 *
 * Examples of matches:
 *	"one"           |
 *	"one      "     |
 *	                ^maximum length
 *
 *	"Number One     |  X"	(X is beyond maximum length)
 *	"Number One   " |
 *	                ^maximum length
 *
 * Examples of mismatches:
 *	" one"
 *	"one"
 *
 *	"Number One    X|"
 *	"Number One     |"
 *	                ^maximum length
 */
static int
memcmp_pad_max(void *d1, uint_t d1_len, void *d2, uint_t d2_len, uint_t max_sz)
{

	uint_t		len, extra_len;
	char		*marker;

	/* No point in comparing anything beyond max_sz */
	if (d1_len > max_sz)
		d1_len = max_sz;
	if (d2_len > max_sz)
		d2_len = max_sz;

	/* Find shorter of the two data. */
	if (d1_len <= d2_len) {
		len = d1_len;
		extra_len = d2_len;
		marker = d2;
	} else {	/* d1_len > d2_len */
		len = d2_len;
		extra_len = d1_len;
		marker = d1;
	}

	/* Have a match in the shortest length of data? */
	if (memcmp(d1, d2, len) != 0)
		/* CONSTCOND */
		return (!0);

	/* If the rest of longer data is nulls or blanks, call it a match. */
	while (len < extra_len)
		if (!isspace(marker[len++]))
			/* CONSTCOND */
			return (!0);
	return (0);
}

/*
 * Locate a token slot whose token matches the label, manufacturer
 * ID, and serial number given.  Token label must be specified,
 * manufacturer ID and serial number are optional.
 */
int
find_token_slot(char *token_name, char *manuf_id, char *serial_no,
		CK_SLOT_ID *slot_id, CK_FLAGS *pin_state)
{
	CK_SLOT_ID_PTR	slot_list;
	CK_TOKEN_INFO	token_info;
	CK_ULONG	slot_count = 0;
	int		rv;
	int		i;
	uint_t		len, max_sz;
	boolean_t	tok_match = B_FALSE,
			man_match = B_FALSE,
			ser_match = B_FALSE;

	cryptodebug("inside find_token_slot");

	/*
	 * Get the slot count first because we don't know how many
	 * slots there are and how many of those slots even have tokens.
	 * Don't specify an arbitrary buffer size for the slot list;
	 * it may be too small (see section 11.5 of PKCS#11 spec).
	 * Also select only those slots that have tokens in them,
	 * because this tool has no need to know about empty slots.
	 */
	if ((rv = C_GetSlotList(1, NULL_PTR, &slot_count)) != CKR_OK) {
		pk11_errno = rv;
		return (PK_ERR_PK11SLOTS);
	}

	if (slot_count == 0)
		return (PK_ERR_NOSLOTS);	/* with tokens in them */

	/* Allocate space for the slot list and get it. */
	if ((slot_list =
	    (CK_SLOT_ID_PTR) malloc(slot_count * sizeof (CK_SLOT_ID))) == NULL)
		return (PK_ERR_NOMEMORY);

	if ((rv = C_GetSlotList(1, slot_list, &slot_count)) != CKR_OK) {
		/* NOTE:  can slot_count change from previous call??? */
		pk11_errno = rv;
		free(slot_list);
		return (PK_ERR_PK11SLOTS);
	}

	/* Search for the token. */
	for (i = 0; i < slot_count; i++) {
		if ((rv =
		    C_GetTokenInfo(slot_list[i], &token_info)) != CKR_OK) {
			cryptodebug("slot %d has no token", i);
			continue;
		}

		len = strlen(token_name);
		max_sz = sizeof (token_info.label);
		if (memcmp_pad_max(&(token_info.label), max_sz, token_name, len,
		    max_sz) == 0)
			tok_match = B_TRUE;

		cryptodebug("slot %d:", i);
		cryptodebug("\tlabel = \"%.32s\"", token_info.label);
		cryptodebug("\tmanuf = \"%.32s\"", token_info.manufacturerID);
		cryptodebug("\tserno = \"%.16s\"", token_info.serialNumber);
		cryptodebug("\tmodel = \"%.16s\"", token_info.model);

		cryptodebug("\tCKF_USER_PIN_INITIALIZED = %s",
		    (token_info.flags & CKF_USER_PIN_INITIALIZED) ?
		    "true" : "false");
		cryptodebug("\tCKF_USER_PIN_TO_BE_CHANGED = %s",
		    (token_info.flags & CKF_USER_PIN_TO_BE_CHANGED) ?
		    "true" : "false");

		if (manuf_id) {
			len = strlen(manuf_id);
			max_sz = sizeof ((char *)(token_info.manufacturerID));
			if (memcmp_pad_max(&(token_info.manufacturerID), max_sz,
			    manuf_id, len, max_sz) == 0)
				man_match = B_TRUE;
		}

		if (serial_no) {
			len = strlen(serial_no);
			max_sz = sizeof ((char *)(token_info.serialNumber));
			if (memcmp_pad_max(&(token_info.serialNumber), max_sz,
			    serial_no, len, max_sz) == 0)
				ser_match = B_TRUE;
		}

		if (tok_match &&
		    (manuf_id ? B_TRUE : B_FALSE) == man_match &&
		    (serial_no ? B_TRUE : B_FALSE) == ser_match)
			break;	/* found it! */
	}

	if (i == slot_count) {
		free(slot_list);
		return (PK_ERR_NOTFOUND);
	}

	cryptodebug("matched token at slot %d", i);
	*slot_id = slot_list[i];
	*pin_state = (token_info.flags & CKF_USER_PIN_TO_BE_CHANGED);
	free(slot_list);
	return (PK_ERR_NONE);
}

/*
 * Log into the token in given slot and create a session for it.
 */
int
login_token(CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen,
	    CK_SESSION_HANDLE_PTR hdl)
{
	int		rv;

	cryptodebug("inside login_token");

	/* Create a read-write session so we can change the PIN. */
	if ((rv = C_OpenSession(slot_id, CKF_SERIAL_SESSION|CKF_RW_SESSION,
	    NULL, NULL, hdl)) != CKR_OK) {
		pk11_errno = rv;
		return (PK_ERR_PK11SESSION);
	}

	/*
	 * If the token is newly created, there initial PIN will be "changme",
	 * and all subsequent PKCS#11 calls will fail with CKR_PIN_EXPIRED,
	 * but C_Login() will succeed.
	 */
	if ((rv = C_Login(*hdl, CKU_USER, pin, pinlen)) != CKR_OK) {
		pk11_errno = rv;
		(void) C_CloseSession(*hdl);
		cryptodebug("C_Login returns %s", pkcs11_strerror(rv));
		if (rv == CKR_USER_PIN_NOT_INITIALIZED)
			return (PK_ERR_CHANGEPIN);
		return (PK_ERR_PK11LOGIN);
	}

	return (PK_ERR_NONE);
}

/*
 * Log out of the token and close the session.
 */
void
logout_token(CK_SESSION_HANDLE hdl)
{
	cryptodebug("inside logout_token");

	if (hdl) {
		(void) C_Logout(hdl);
		(void) C_CloseSession(hdl);
	}
	(void) C_Finalize(NULL);
}
