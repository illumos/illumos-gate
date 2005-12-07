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

#ifndef	_FMD_LOG_IMPL_H
#define	_FMD_LOG_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <exacct.h>
#include <fmd_log.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct fmd_log {
	struct stat64 log_stat;		/* fstat64() information for log file */
	ea_file_t log_ea;		/* libexacct handle for log file */
	char *log_path;			/* log file pathname used for open */
	char *log_version;		/* creator version string */
	char *log_label;		/* label indicating type */
	char *log_osrelease;		/* uname -r at log creation time */
	char *log_osversion;		/* uname -v at log creation time */
	char *log_platform;		/* uname -i at log creation time */
	char *log_uuid;			/* log file uuid string */
	int log_abi;			/* abi version of library client */
	int log_errno;			/* err from last library call */
	int log_fd;			/* file descriptor for log */
	int log_flags;			/* miscellaneous flags (see below) */
	struct fmd_log *log_xrefs;	/* list of cross-referenced logs */
	struct fmd_log *log_xnext;	/* next log on cross-reference list */
};

#define	FMD_LF_EAOPEN	0x1		/* log_ea is open and active */
#define	FMD_LF_START	0x2		/* log is at start of iter */
#define	FMD_LF_XREFS	0x4		/* log xrefs have been loaded */
#define	FMD_LF_DEBUG	0x8		/* print debug messages for this log */

typedef struct fmd_log_filtvec {
	const fmd_log_filter_t *filt_argv; /* set of equivalent filters to OR */
	uint_t filt_argc;		/* number of total filters to AND */
} fmd_log_filtvec_t;

#define	EFDL_BASE	1000		/* base value for libfmd_log errnos */

enum {
	EFDL_VERSION = EFDL_BASE,	/* invalid library client version */
	EFDL_NOMEM,			/* memory allocation failure */
	EFDL_BADHDR,			/* invalid fmd file header */
	EFDL_NOCLASS,			/* record does not contain class */
	EFDL_BADTAG,			/* invalid exacct catalog tag */
	EFDL_BADREF,			/* invalid cross-reference group */
	EFDL_BADDEV,			/* invalid cross-reference dev_t */
	/*
	 * Note: EFDL_EXACCT must be the final internal errno definition so we
	 * can store libexacct ea_error() values as EFDL_EXACCT + ea_error().
	 */
	EFDL_EXACCT			/* exacct error (must be last!) */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_LOG_IMPL_H */
