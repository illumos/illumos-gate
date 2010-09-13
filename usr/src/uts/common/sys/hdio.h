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
 * Copyright (c) 1991,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_HDIO_H
#define	_SYS_HDIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Used for generic commands
 */
struct hdk_cmd {
	ushort_t hdkc_cmd;		/* command to be executed */
	int	hdkc_flags;		/* execution flags */
	daddr_t	hdkc_blkno;		/* disk address for command */
	int	hdkc_secnt;		/* sector count for command */
	caddr_t	hdkc_bufaddr;		/* user's buffer address */
	uint_t	hdkc_buflen;		/* size of user's buffer */
};

/*
 * Used for drive info
 */
struct hdk_type {
	ushort_t hdkt_hsect;		/* hard sector count (read only) */
	ushort_t hdkt_promrev;		/* prom revision (read only) */
	uchar_t	hdkt_drtype;		/* drive type (ctlr specific) */
	uchar_t	hdkt_drstat;		/* drive status (ctlr specific, ro) */
};

/*
 * Used for bad sector map
 */
struct hdk_badmap {
	caddr_t hdkb_bufaddr;		/* address of user's map buffer */
};

/*
 * Execution flags.
 */
#define	HDK_SILENT	0x01		/* no error messages */
#define	HDK_DIAGNOSE	0x02		/* fail if any error occurs */
#define	HDK_ISOLATE	0x04		/* isolate from normal commands */
#define	HDK_READ	0x08		/* read from device */
#define	HDK_WRITE	0x10		/* write to device */
#define	HDK_KBUF	0x20		/* write to device */

/*
 * Used for disk diagnostics
 */
struct hdk_diag {
	ushort_t hdkd_errcmd;		/* most recent command in error */
	daddr_t	hdkd_errsect;		/* most recent sector in error */
	uchar_t	hdkd_errno;		/* most recent error number */
	uchar_t	hdkd_severe;		/* severity of most recent error */
};

/*
 * Used for getting disk error log.
 */
struct hdk_loghdr {
	long	hdkl_entries;		/* number of dk_log entries */
	long	hdkl_max_size;		/* max. size of dk_log table */
	caddr_t	hdkl_logbfr;		/* pointer to dk_log table */
};

/*
 * Disk error log table entry.
 */
struct hdk_log {
	daddr_t	hdkl_block;		/* location of block in error */
	ulong_t	hdkl_count;		/* number of failures */
	short	hdkl_type;		/* type of error (e.g. soft error) */
	short	hdkl_err1;		/* primary error code (e.g sense key) */
	short	hdkl_err2;		/* secondary error code */
};

/*
 * Dk_log type flags.
 *
 * FIXME:  Really should specify dkd_errno error codes.
 *	For some reason they're specified in the drivers
 *	instead of here??  Should also use those here for
 *	dk_log.type too.
 */
#define	HDKL_SOFT	0x01		/* recoverable erro */
#define	HDKL_HARD	0x02		/* unrecoverable error */

/*
 * Severity values
 */
#define	HDK_NOERROR	0
#define	HDK_CORRECTED	1
#define	HDK_RECOVERED	2
#define	HDK_FATAL	3

/*
 * Error types
 */
#define	HDK_NONMEDIA	0		/* not caused by a media defect */
#define	HDK_ISMEDIA	1		/* caused by a media defect */


#define	HDIOC		(0x04 << 8)
#define	HDKIOCSTYPE	(HDIOC|101)		/* Set drive info */
#define	HDKIOCGTYPE	(HDIOC|102)		/* Get drive info */
#define	HDKIOCSBAD	(HDIOC|103)		/* Set bad sector map */
#define	HDKIOCGBAD	(HDIOC|104)		/* Get bad sector map */
#define	HDKIOCSCMD	(HDIOC|105)		/* Set generic cmd */
#define	HDKIOCGDIAG	(HDIOC|106)		/* Get diagnostics */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HDIO_H */
