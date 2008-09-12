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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ANALYZE_H
#define	_ANALYZE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains definitions related to surface analysis.
 */

/*
 * These are variables referenced by the analysis routines.  They
 * are declared in analyze.c.
 */
extern	int scan_entire;
extern	diskaddr_t scan_lower, scan_upper;
extern	int scan_correct, scan_stop, scan_loop, scan_passes;
extern	int scan_random, scan_auto;
extern	uint_t scan_size;
extern	int scan_restore_defects, scan_restore_label;

/*
 * These variables hold summary info for the end of analysis.
 * They are declared in analyze.c.
 */
extern	offset_t scan_cur_block;
extern	int64_t scan_blocks_fixed;

/*
 * This variable is used to tell whether the most recent surface
 * analysis error was caused by a media defect or some other problem.
 * It is declared in analyze.c.
 */
extern	int media_error;
extern	int disk_error;

/*
 * These defines are flags for the surface analysis types.
 */
#define	SCAN_VALID		0x01		/* read data off disk */
#define	SCAN_PATTERN		0x02		/* write and read pattern */
#define	SCAN_COMPARE		0x04		/* manually check pattern */
#define	SCAN_WRITE		0x08		/* write data to disk */
#define	SCAN_PURGE		0x10		/* purge data on disk */
#define	SCAN_PURGE_READ_PASS	0x20		/* read/compare pass */
#define	SCAN_PURGE_ALPHA_PASS	0x40		/* alpha pattern pass */
#define	SCAN_VERIFY		0x80		/* verify data on disk */
#define	SCAN_VERIFY_READ_PASS	0x100		/* read/compare pass */


/*
 * Miscellaneous defines.
 */
#define	BUF_SECTS		126		/* size of the buffers */
/*
 * Number of passes for purge command.  It is kept here to allow
 * it to be used in menu_analyze.c also
 * This feature is added at the request of Sun Fed.
 */
#define	NPPATTERNS	4	/* number of purge patterns */
#define	READPATTERN	(NPPATTERNS - 1)


/*
 * defines for disk errors during surface analysis.
 */
#define	DISK_STAT_RESERVED		0x01	/* disk is reserved */
#define	DISK_STAT_NOTREADY		0x02	/* disk not ready */
#define	DISK_STAT_UNAVAILABLE		0x03	/* disk is being formatted */
#define	DISK_STAT_DATA_PROTECT		0x04	/* disk is write protected */

/*
 *	Prototypes for ANSI C compilers
 */
int	do_scan(int flags, int mode);

#ifdef	__cplusplus
}
#endif

#endif	/* _ANALYZE_H */
