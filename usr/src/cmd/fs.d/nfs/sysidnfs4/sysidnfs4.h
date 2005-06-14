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

#ifndef	_SYSIDNFS4_H
#define	_SYSIDNFS4_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <arpa/nameser.h>
#include <unistd.h>

extern char *optarg;
extern int optind, opterr, optopt;

#define	MAX_IBUF		80

typedef enum {
	NFS4_SUCCESS		= 0,
	NFS4_ERROR_BAD_DOMAIN	= 1,
	NFS4_ERROR_DOMAIN_LEN	= 2
} n4err_t;

typedef enum {
	NFS4_AUTO		= 1,
	NFS4_MANUAL		= 2,
	NFS4_BAIL		= 3
} n4act_t;

#define	TERM_DEFAULT	"TERM=vt100"
#define	PUTTERM_ERR	gettext("Unable to set default %s\n")

#define	NFS4_ACTION_TEXT_OK	\
	gettext(		\
	"\n\n\tThis system is configured with NFS version 4, which uses a "   \
	"domain\n\tname that is automatically derived from the system's name "\
	"services.\n\tThe derived domain name is sufficient for most "        \
	"configurations. In a\n\tfew cases, mounts that cross different "     \
	"domains might cause files to\n\tbe owned by \"nobody\" due to the "  \
	"lack of a common domain name.")

#define	NFS4_ACTION_PROMPT	\
	gettext(		\
	"\n\n\tDo you need to override the system's default NFS version 4 " \
	"domain\n\tname (yes/no) ? [no] : ")

#define	NFS4_ACTION_TEXT_NOTE	\
	gettext(		\
	"\n\tFor more information about how the NFS version 4 default domain"  \
	"\n\tname is derived and its impact, refer to the man pages for nfs(4)"\
	"\n\tand nfsmapid(1m), and the System Administration Guide: Network"   \
	"\n\tServices.\n\n")

#define	NFS4_ACTION_ERR_VALUES	\
	gettext(		\
	"\n\tError: Valid responses are 'y' or 'n' only. Please try again.")

#define	NFS4_DOMAIN_TEXT_OK	\
	gettext(		\
	"\n\n\tEnter the domain to be used as the NFS version 4 domain " \
	"name.\n")

#define	NFS4_DOMAIN_PROMPT	\
	gettext("\n\t\tNFS version 4 domain name [%s]: ")

#define	NFS4_DOMAIN_INVALID	\
	gettext(		\
	"\n\n\tError: A proper domain name should consist of a combination"\
	"\n\t       of alphanumeric characters, underscores, dashes and"\
	"\n\t       dots.\n")

#define	NFS4_STATE_FILE_ERR	\
	gettext(		\
	"\n\tError: %s\n\n\tFailure to create %s. Expect to be "\
	"prompted\n\tagain on your next reboot\n\n")

#define	USAGE_MSG	\
	gettext("Usage: %s -c|-u\n")

#ifdef	__cplusplus
}
#endif

#endif	/* _SYSIDNFS4_H */
