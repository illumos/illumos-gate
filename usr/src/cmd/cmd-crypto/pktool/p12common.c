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
 * This file implements some of the common PKCS#12 routines.
 */

#include <errno.h>
#include <string.h>
#include <cryptoutil.h>
#include "p12common.h"
#include <openssl/pkcs12.h>

/* I18N helpers. */
#include <libintl.h>
#include <locale.h>

/*
 * Common function to create/open PKCS#12 files.
 */
static int
pkcs12_file(char *filename, boolean_t create, BIO **fbio)
{
	cryptodebug("inside pkcs12_file");

	if (fbio == NULL) {
		cryptoerror(LOG_STDERR, create ?
		    gettext("Error creating file \"%s\", invalid input.") :
		    gettext("Error opening file \"%s\", invalid input."),
		    filename);
		return (-1);
	}

	cryptodebug(create ? "creating %s for binary writes" :
	    "opening %s for binary reads", filename);
	if ((*fbio = BIO_new_file(filename, create ? "wb" : "rb")) == NULL) {
		cryptoerror(LOG_STDERR, create ?
		    gettext("Error creating file \"%s\" (%s).") :
		    gettext("Error opening file \"%s\" (%s)."),
		    filename, strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Create PKCS#12 export file.
 */
int
create_pkcs12(char *filename, BIO **fbio)
{
	cryptodebug("inside create_pkcs12");

	return (pkcs12_file(filename, B_TRUE, fbio));
}

/*
 * Opens PKCS#12 import file.
 */
int
open_pkcs12(char *filename, BIO **fbio)
{
	cryptodebug("inside open_pkcs12");

	return (pkcs12_file(filename, B_FALSE, fbio));
}

/*
 * Closes PKCS#12 export file.
 */
void
close_pkcs12(BIO *fbio)
{
	cryptodebug("inside close_pkcs12");

	BIO_free_all(fbio);
}
