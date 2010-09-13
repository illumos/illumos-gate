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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DUMPUSG_H
#define	_DUMPUSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Translate from BSD to System V, where possible.
 */
/*
 * System-V specific header files
 */
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include <sys/systeminfo.h>
#include <sys/vfstab.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_acl.h>

#include <sys/mnttab.h>
#include <sys/vfstab.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * make mnttab look like mtab
 */
#define	MOUNTED		MNTTAB
#define	mntent		mnttab
#define	mnt_fsname	mnt_special
#define	mnt_dir		mnt_mountp
#define	mnt_type	mnt_fstype
#define	mnt_opts	mnt_mntopts
#define	MNTTYPE_42	"ufs"
#define	MNTINFO_DEV	"dev"

#define	setmntent	fopen
#define	endmntent	fclose

/*
 * Function translations
 */
#define	gethostname(name, len)	\
	    ((sysinfo(SI_HOSTNAME, (name), (len)) < 0) ? -1 : 0)
#define	signal			nsignal		/* defined in dumpmain.c */
#define	sigvec			sigaction	/* both struct and func */
#define	sv_flags		sa_flags
#define	sv_handler		sa_handler
#define	sv_mask			sa_mask
#define	sigmask(x)		x
#define	setreuid(r, e)		seteuid(e)
#define	statfs			statvfs		/* both struct and func */
#undef	setjmp
#define	setjmp(b)		sigsetjmp((b), 1)
#define	longjmp			siglongjmp
#define	jmp_buf			sigjmp_buf

#if !__STDC__
extern int seteuid();
#endif

/*
 * Inode related translations
 */
#define	ROOTINO		UFSROOTINO
#define	di_rdev		di_ordev

/*
 * For stat-inode translation.
 * Don't forget the translation from
 * nanosecs to usecs (or vica versa)
 */
#define	st_spare1	st_atim.tv_nsec
#define	st_spare2	st_mtim.tv_nsec
#define	st_spare3	st_ctim.tv_nsec

#define	TMCONV	1000

#ifdef	__cplusplus
}
#endif

#endif /* _DUMPUSG_H */
