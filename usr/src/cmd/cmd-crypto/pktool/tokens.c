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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements the token list operation for this tool.
 * It loads the PKCS#11 modules, gets the list of slots with
 * tokens in them, displays the list, and cleans up.
 */

#include <stdio.h>
#include <string.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"

/*
 * Lists all slots with tokens in them.
 */
int
pk_tokens(int argc, char *argv[])
{
	CK_SLOT_ID_PTR	slots = NULL;
	CK_ULONG	slot_count = 0;
	CK_TOKEN_INFO	token_info;
	const char	*fmt = NULL;
	CK_RV		rv = CKR_OK;
	int		i;


	/* Get rid of subcommand word "tokens". */
	argc--;
	argv++;

	/* No additional args allowed. */
	if (argc != 0)
		return (PK_ERR_USAGE);
	/* Done parsing command line options. */

	/* Get the list of slots with tokens in them. */
	if ((rv = get_token_slots(&slots, &slot_count)) != CKR_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to get token slot list (%s)."),
		    pkcs11_strerror(rv));
		return (PK_ERR_PK11);
	}

	/* Make sure we have something to display. */
	if (slot_count == 0) {
		cryptoerror(LOG_STDERR, gettext("No slots with tokens found."));
		return (0);
	}

	/* Display the list. */
	fmt = "%-30.30s  %-15.15s  %-15.15s  %-10.10s\n"; /* No I18N/L10N. */
	(void) fprintf(stdout, fmt, gettext("Token Label"), gettext("Manuf ID"),
	    gettext("Serial No"), gettext("PIN State"));
	for (i = 0; i < slot_count; i++) {
		if ((rv = C_GetTokenInfo(slots[i], &token_info)) != CKR_OK) {
			cryptoerror(LOG_STDERR,
			    gettext("Unable to get slot %d token info (%s)."),
			    i, pkcs11_strerror(rv));
			continue;
		}

		(void) fprintf(stdout, fmt, token_info.label,
		    token_info.manufacturerID, token_info.serialNumber,
		    (token_info.flags & CKF_USER_PIN_TO_BE_CHANGED) ?
		    gettext("default") : gettext("user set"));
	}

	/* Clean up. */
	free(slots);
	(void) C_Finalize(NULL);
	return (0);
}
