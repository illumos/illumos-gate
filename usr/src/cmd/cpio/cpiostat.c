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
 * Copyright 1995-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

#define	_STYPES
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/fcntl.h>
#include <archives.h>
#include "cpio.h"

o_dev_t
convert(dev_t dev)
{
	major_t maj, min;

	maj = major(dev);	/* get major number */
	min = minor(dev);	/* get minor number */

	/* make old device number */
	return ((maj << 8) | min);
}

void
stat_to_svr32_stat(cpioinfo_t *TmpSt, struct stat *FromStat)
{
	TmpSt->st_dev = convert(FromStat->st_dev);
	TmpSt->st_ino = FromStat->st_ino;
	TmpSt->st_mode = FromStat->st_mode;
	TmpSt->st_nlink = FromStat->st_nlink;
	TmpSt->st_uid = FromStat->st_uid;
	TmpSt->st_gid = FromStat->st_gid;
	TmpSt->st_rdev = convert(FromStat->st_rdev);
	TmpSt->st_size = FromStat->st_size;
	TmpSt->st_modtime = FromStat->st_mtime;
}
