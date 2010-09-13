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

#include    <sun_sas.h>

#define	SUN_SMHBA_VENDOR_LIB VSL_NAME
#define	SUN_SMHBA_VENDOR_LIB_PATH "/usr/lib/libsun_sas.so"
#define	SUN_SMHBA_VENDOR_LIB_VERSION VSL_STRING_VERSION

HBA_UINT32
Sun_sasGetVendorLibraryAttributes(SMHBA_LIBRARYATTRIBUTES *attrs) {
	const char		ROUTINE[] = "Sun_sasGetVendorLibraryAttributes";

	/* Validate the arguments */
	if (attrs == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL attrs structure");
		return (SMHBA_LIBRARY_VERSION1);
	}
	(void) strlcpy(attrs->LibPath, SUN_SMHBA_VENDOR_LIB_PATH,
	    sizeof (attrs->LibPath));
	(void) strlcpy(attrs->VName, SUN_SMHBA_VENDOR_LIB,
	    sizeof (attrs->VName));
	(void) strlcpy(attrs->VVersion, SUN_SMHBA_VENDOR_LIB_VERSION,
	    sizeof (attrs->VVersion));

	return (SMHBA_LIBRARY_VERSION1);
}
