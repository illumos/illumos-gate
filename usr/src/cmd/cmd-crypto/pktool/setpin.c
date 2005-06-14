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
 * This file implements the setpin operation for this tool.
 * The basic flow of the process is to load the PKCS#11 module,
 * finds the soft token, log into it, prompt the user for the
 * new PIN, change the token's PIN, and log out.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

static int
set_token_pin(CK_SESSION_HANDLE hdl, CK_UTF8CHAR_PTR oldpin, CK_ULONG oldpinlen)
{
	CK_UTF8CHAR_PTR		pin1, pin2;
	int			len1, len2;
	int			rv;

	cryptodebug("inside set_token_pin");

	if ((len1 = get_password(gettext("Enter new PIN:"),
	    (char **)&pin1)) < 0)
		return (PK_ERR_NEWPIN);

	if ((len2 = get_password(gettext("Re-enter new PIN:"),
	    (char **)&pin2)) < 0) {
		free(pin1);
		return (PK_ERR_PINCONFIRM);
	}

	/* NOTE:  Do not use strcmp on pin1 and pin2; they are UTF strings */
	if (len1 != len2 || memcmp(pin1, pin2, len1) != 0) {
		free(pin1);
		free(pin2);
		return (PK_ERR_PINMATCH);
	}

	if ((rv = C_SetPIN(hdl, oldpin, oldpinlen, pin1, (CK_ULONG)len1))
	    != CKR_OK) {
		pk11_errno = rv;
		free(pin1);
		free(pin2);
		return (PK_ERR_PK11SETPIN);
	}

	free(pin1);
	free(pin2);
	return (PK_ERR_NONE);
}

/*
 * This is the main entry point in this module.  It controls the process
 * by which the token's PIN is changed.  It relies on set_token_pin() to
 * handle the extra work of prompting and confirming the new PIN.
 */
int
pk_setpin(int argc, char *argv[])
/* ARGSUSED */
{
	char		*token_name = NULL;
	char		*manuf_id = NULL;
	char		*serial_no = NULL;
	CK_SLOT_ID		slot_id;
	CK_FLAGS		pin_state;
	CK_SESSION_HANDLE	hdl;
	CK_UTF8CHAR_PTR		pin;
	int			pinlen;
	int			rv;

	cryptodebug("inside pk_setpin");

	/*
	 * Token_name, manuf_id, and serial_no are all optional.
	 * If unspecified, token_name must have a default value
	 * at least.
	 */
	token_name = SOFT_TOKEN_LABEL;
	manuf_id = SOFT_MANUFACTURER_ID;

	/* No additional args allowed. */
	if (argc != 1)
		return (PK_ERR_USAGE);
	/* Done parsing command line options. */

	/* Initialize PKCS11, find the slot with token. */
	if ((rv = init_pk11()) != PK_ERR_NONE)
		return (rv);
	if ((rv = find_token_slot(token_name, manuf_id, serial_no,
	    &slot_id, &pin_state)) != PK_ERR_NONE)
		return (rv);

	/* Check if the token flags show the PIN has not be set yet. */
	if (pin_state == CKF_USER_PIN_TO_BE_CHANGED) {
		cryptodebug("pin_state: first time pin is being set");
		if ((pin = (CK_UTF8CHAR_PTR)strdup(SOFT_DEFAULT_PIN)) == NULL)
			return (PK_ERR_NOMEMORY);
		pinlen = strlen(SOFT_DEFAULT_PIN);
	} else {
		cryptodebug("pin_state: changing an existing pin ");
		/* Have user unlock token with correct password */
		if ((pinlen = get_password(gettext("Enter token PIN:"),
		    (char **)&pin)) < 0)
			return (PK_ERR_PASSPHRASE);
	}

	/*
	 * Log into the token.  If login fails with an uninitialized PIN,
	 * it means this is the first time the token has been used.
	 * Or if the login is successful, but all subsequent calls to
	 * any function return with an expired PIN, then this is the
	 * first time the token is used.  In either case, use the
	 * passphrase "changeme" as the initial PIN.
	 */
	if ((rv = login_token(slot_id, pin, (CK_ULONG)pinlen, &hdl))
	    != PK_ERR_NONE) {
		free(pin);
		return (rv);
	}

	/* Set the pin for the PKCS11 token. */
	if ((rv = set_token_pin(hdl, pin, (CK_ULONG)pinlen)) != PK_ERR_NONE) {
		free(pin);
		logout_token(hdl);
		return (rv);
	}

	free(pin);
	logout_token(hdl);
	return (PK_ERR_NONE);
}
