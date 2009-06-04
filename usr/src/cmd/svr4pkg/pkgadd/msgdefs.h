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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

#ifndef _MSGDEFS_H
#define	_MSGDEFS_H


/*
 * Module:	msgdefs
 * Group:	pkgadd
 * Description: l10n strings for pkgadd
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	ERR_NOPKGS	"no packages were found in <%s>"

#define	ERR_DSINIT	"could not process datastream from <%s>"

#define	ERR_STREAMDIR	"unable to make temporary directory to unpack " \
		"datastream"

#define	MSG_SUSPEND	"Installation of <%s> has been suspended."

#define	MSG_VERIFYING	"Verifying signer <%s>"

#define	MSG_PASSPROMPT	"Enter keystore password:"

#define	MSG_1MORE_PROC	"\nThere is 1 more package to be processed."

#define	MSG_1MORE_INST	"\nThere is 1 more package to be installed."

#define	MSG_MORE_PROC	"\nThere are %d more packages to be processed."

#define	MSG_MORE_INST	"\nThere are %d more packages to be installed."

#define	ASK_CONTINUE	"Do you want to continue with installation"

#define	ERR_ROOTREQD	"You must be \"root\" for %s to execute properly."

#define	ERR_NODEVICE	"unable to determine device to install from"

#define	ERR_NORESP	"response file <%s> must not exist"

#define	ERR_ACCRESP	"unable to access response file <%s>"

#define	ERR_PKGVOL	"unable to obtain package volume"

#define	ERR_DSARCH	"unable to find archive for <%s> in datastream"

#define	MSG_PROC_CONT "\nProcessing continuation packages from <%s>"

#define	MSG_PROC_INST "\nProcessing package instance <%s> from <%s>"

#define	ERR_ROOT_CMD "Command line install root contends with environment."

#define	ERR_CAT_LNGTH "The category argument exceeds the SVr4 ABI\n" \
		"        defined maximum supported length of 16 characters."

#define	ERR_CAT_FND "Category argument <%s> cannot be found."

#define	ERR_CAT_INV "Category argument <%s> is invalid."

#define	ERR_ARG	"URL <%s> is not valid"

#define	ERR_ADM_PROXY	"Admin file proxy setting invalid"

#define	ERR_PROXY	"Proxy specification <%s> invalid"

#define	ERR_ILL_HTTP_OPTS "The -i and (-k or -P) options are mutually" \
		"exclusive."
#define	ERR_ILL_PASSWD "A password is required to retrieve the public " \
		"certificate from the keystore."

#define	ERR_PATH "The path <%s> is invalid!"

#define	ERR_DIR_CONST "unable to construct download directory <%s>"

#define	ERR_ADM_KEYSTORE "unable to determine keystore location"

#define	PASSWD_CMDLINE "## WARNING: USING \"%s\" MAKES PASSWORD " \
			"VISIBLE TO ALL USERS."

#define	ERR_NO_LIVE_MODE	"live continue mode is not supported"

#define	ERR_RSP_FILE_NOTFULLPATH	"response file <%s> must be " \
			"full pathname"

#define	ERR_RSP_FILE_NOT_GIVEN	"response file (to write) is required"

#define	ERR_BAD_DEVICE	"bad device <%s> specified"

#define	MSG_INSERT_VOL	"Insert %v into %p."

#define	ERR_UNKNOWN_DEV	"unknown device <%s>"

#define	LOG_GETVOL_RET	"getvol() returned <%d>"

#define	ERR_GPKGLIST_ERROR	"internal error in gpkglist()"

#define	ERR_TOO_MANY_PKGS	"too many packages referenced!"

/* maximum number of args to exec() calls */

#define	MAXARGS 100

#define	MAX_CAT_ARGS 64

#ifdef __cplusplus
}
#endif

#endif	/* _MSGDEFS_H */
