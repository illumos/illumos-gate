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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _RJE_H
#define	_RJE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4.1.1 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAXDEVS 7		/* Maximum number of devices (readers, etc.) */
#define	LINEFIL "/usr/rje/lines"

#define	RJECU	"/dev/dn2"	/* Dial-up RJE device */
#define	RJELOGIN "rje"		/* rje login name */
#define	RJEUID	68		/* User-Id for "rje" */
#define	SHQUID	69		/* User-Id for "shqer" */
#define	RJEGID	8		/* Group-Id for "rje" and "shqer" */
#define	QUEDIR	"/usr/rje/sque"	/* shqer directory */
#define	QUELOG	"log"		/* shqer log file name */
#define	QUELEN	50		/* Length of a shqer log entry */
#define	QDELAY	180		/* Delay time for shqer */
#define	QNICE	0
#define	BOOTDLY	60		/* Reboot delay time (seconds) */
#define	RESPMAX 70000		/* Max resp file size */

#define	DEVFD	0	/* KMC device file descriptor */
#define	XMTRD	1	/* xmit read file descriptor */
#define	ERRFD	2	/* errors file descriptor */
#define	XMTWR	3	/* xmit write file descriptor */
#define	DSPRD	4	/* disp read file descriptor */
#define	DSPWR	5	/* disp write file descriptor */
#define	JBLOG	6	/* joblog file descriptor */

#define	NAMESZ	8

struct joblog {
	char j_file[NAMESZ];	/* Name of file to be sent */
	unsigned j_uid;		/* User ID of owner */
	int j_lvl;		/* Message level */
	long j_cnt;		/* Number of "cards" */
};

	/* joblog header info */

struct loghdr {
	int h_pgrp;		/* Process group Id */
};
#define	LBUFMAX 100
#define	MAXLNS	6
struct lines {
	char *l_host;		/* RJE host machine */
	char *l_sys;		/* This system */
	char *l_dir;		/* home directory */
	char *l_prefix;		/* rje prefix */
	char *l_dev;		/* device for transfer */
	char *l_peri;		/* Peripherals field */
	char *l_parm;		/* Parameters field */
	char l_buf[LBUFMAX];	/* buffer for fields */
};

struct dsplog {
	int d_type;		/* Type of record */
	union {
		struct {	/* record from xmit */
			char d_file[NAMESZ];	/* file sent */
			long d_cnt;		/* no. of cards sent */
			unsigned d_uid;		/* who sent the file */
			int d_lvl;		/* message level */
			int d_rdr;		/* reader sent from (0-6) */
		} x;
		struct {	/* record from recv */
			char d_file[NAMESZ];	/* file received */
			long d_cnt;		/* no. of records */
			int d_trunc;		/* file truncation flag */
		} r;
	} d_un;
};

struct sque {
	char sq_exfil[140];	/* Executable file */
	char sq_infil[48];	/* Input file */
	char sq_jobnm[9];	/* Remote job name */
	char sq_pgrmr[25];	/* Programmer name */
	char sq_jobno[9];	/* Remote job number */
	char sq_login[9];	/* Login name from usr= */
	char sq_homed[48];	/* Login directory */
	long sq_min;		/* Minimum file system space */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _RJE_H */
