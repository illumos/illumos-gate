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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

#define	_SYSCALL32

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <libproc.h>
#include "ramdata.h"
#include "proto.h"

void	show_stat32(private_t *, long);
#ifdef _LP64
void	show_stat64(private_t *, long);
#endif

#if defined(i386) && defined(_STAT_VER)

/*
 * Old SVR3 stat structure.
 */
struct	o_stat {
	o_dev_t	st_dev;
	o_ino_t	st_ino;
	o_mode_t st_mode;
	o_nlink_t st_nlink;
	o_uid_t st_uid;
	o_gid_t st_gid;
	o_dev_t	st_rdev;
	off32_t	st_size;
	time_t st_atim;
	time_t st_mtim;
	time_t st_ctim;
};

void
show_o_stat(private_t *pri, long offset)
{
	struct o_stat statb;
	timestruc_t ts;

	if (offset != NULL &&
	    Pread(Proc, &statb, sizeof (statb), offset) == sizeof (statb)) {
		(void) printf(
		    "%s    d=0x%.8X i=%-5u m=0%.6o l=%-2u u=%-5u g=%-5u",
		    pri->pname,
		    statb.st_dev & 0xffff,
		    statb.st_ino,
		    statb.st_mode,
		    statb.st_nlink % 0xffff,
		    statb.st_uid,
		    statb.st_gid);

		switch (statb.st_mode & S_IFMT) {
		case S_IFCHR:
		case S_IFBLK:
			(void) printf(" rdev=0x%.4X\n", statb.st_rdev & 0xffff);
			break;
		default:
			(void) printf(" sz=%u\n", (uint32_t)statb.st_size);
			break;
		}

		ts.tv_nsec = 0;
		ts.tv_sec = statb.st_atim;
		prtimestruc(pri, "at = ", &ts);
		ts.tv_sec = statb.st_atim;
		prtimestruc(pri, "mt = ", &ts);
		ts.tv_sec = statb.st_atim;
		prtimestruc(pri, "ct = ", &ts);
	}
}

void
show_stat(private_t *pri, long offset)
{
	show_o_stat(pri, offset);
}

void
show_xstat(private_t *pri, int version, long offset)
{
	switch (version) {
	case _R3_STAT_VER:
		show_o_stat(pri, offset);
		break;
	case _STAT_VER:
		show_stat32(pri, offset);
		break;
	}
}

void
show_statat(private_t *pri, long offset)
{
#ifdef _LP64
	if (data_model == PR_MODEL_LP64)
		show_stat64(pri, offset);
	else
		show_stat32(pri, offset);
#else
	show_stat32(pri, offset);
#endif
}

#else

void
show_stat(private_t *pri, long offset)
{
#ifdef _LP64
	if (data_model == PR_MODEL_LP64)
		show_stat64(pri, offset);
	else
		show_stat32(pri, offset);
#else
	show_stat32(pri, offset);
#endif
}

void
show_statat(private_t *pri, long offset)
{
	show_stat(pri, offset);
}

/* ARGSUSED */
void
show_xstat(private_t *pri, int version, long offset)
{
	show_stat(pri, offset);
}

#endif

void
show_stat32(private_t *pri, long offset)
{
	struct stat32 statb;
	timestruc_t ts;

	if (offset != NULL &&
	    Pread(Proc, &statb, sizeof (statb), offset) == sizeof (statb)) {
		(void) printf(
		    "%s    d=0x%.8X i=%-5u m=0%.6o l=%-2u u=%-5u g=%-5u",
		    pri->pname,
		    statb.st_dev,
		    statb.st_ino,
		    statb.st_mode,
		    statb.st_nlink,
		    statb.st_uid,
		    statb.st_gid);

		switch (statb.st_mode & S_IFMT) {
		case S_IFCHR:
		case S_IFBLK:
			(void) printf(" rdev=0x%.8X\n", statb.st_rdev);
			break;
		default:
			(void) printf(" sz=%u\n", statb.st_size);
			break;
		}

		TIMESPEC32_TO_TIMESPEC(&ts, &statb.st_atim);
		prtimestruc(pri, "at = ", &ts);
		TIMESPEC32_TO_TIMESPEC(&ts, &statb.st_mtim);
		prtimestruc(pri, "mt = ", &ts);
		TIMESPEC32_TO_TIMESPEC(&ts, &statb.st_ctim);
		prtimestruc(pri, "ct = ", &ts);

		(void) printf(
		    "%s    bsz=%-5d blks=%-5d fs=%.*s\n",
		    pri->pname,
		    statb.st_blksize,
		    statb.st_blocks,
		    _ST_FSTYPSZ,
		    statb.st_fstype);
	}
}

void
show_stat64_32(private_t *pri, long offset)
{
	struct stat64_32 statb;
	timestruc_t ts;

	if (offset != NULL &&
	    Pread(Proc, &statb, sizeof (statb), offset) == sizeof (statb)) {
		(void) printf(
		    "%s    d=0x%.8X i=%-5llu m=0%.6o l=%-2u u=%-5u g=%-5u",
		    pri->pname,
		    statb.st_dev,
		    (u_longlong_t)statb.st_ino,
		    statb.st_mode,
		    statb.st_nlink,
		    statb.st_uid,
		    statb.st_gid);

		switch (statb.st_mode & S_IFMT) {
		case S_IFCHR:
		case S_IFBLK:
			(void) printf(" rdev=0x%.8X\n", statb.st_rdev);
			break;
		default:
			(void) printf(" sz=%llu\n", (long long)statb.st_size);
			break;
		}

		TIMESPEC32_TO_TIMESPEC(&ts, &statb.st_atim);
		prtimestruc(pri, "at = ", &ts);
		TIMESPEC32_TO_TIMESPEC(&ts, &statb.st_mtim);
		prtimestruc(pri, "mt = ", &ts);
		TIMESPEC32_TO_TIMESPEC(&ts, &statb.st_ctim);
		prtimestruc(pri, "ct = ", &ts);

		(void) printf("%s    bsz=%-5d blks=%-5lld fs=%.*s\n",
		    pri->pname,
		    statb.st_blksize,
		    (longlong_t)statb.st_blocks,
		    _ST_FSTYPSZ,
		    statb.st_fstype);
	}
}

#ifdef _LP64
void
show_stat64(private_t *pri, long offset)
{
	struct stat64 statb;

	if (offset != NULL &&
	    Pread(Proc, &statb, sizeof (statb), offset) == sizeof (statb)) {
		(void) printf(
		    "%s    d=0x%.16lX i=%-5lu m=0%.6o l=%-2u u=%-5u g=%-5u",
		    pri->pname,
		    statb.st_dev,
		    statb.st_ino,
		    statb.st_mode,
		    statb.st_nlink,
		    statb.st_uid,
		    statb.st_gid);

		switch (statb.st_mode & S_IFMT) {
		case S_IFCHR:
		case S_IFBLK:
			(void) printf(" rdev=0x%.16lX\n", statb.st_rdev);
			break;
		default:
			(void) printf(" sz=%lu\n", statb.st_size);
			break;
		}

		prtimestruc(pri, "at = ", (timestruc_t *)&statb.st_atim);
		prtimestruc(pri, "mt = ", (timestruc_t *)&statb.st_mtim);
		prtimestruc(pri, "ct = ", (timestruc_t *)&statb.st_ctim);

		(void) printf(
		    "%s    bsz=%-5d blks=%-5ld fs=%.*s\n",
		    pri->pname,
		    statb.st_blksize,
		    statb.st_blocks,
		    _ST_FSTYPSZ,
		    statb.st_fstype);
	}
}
#endif	/* _LP64 */
