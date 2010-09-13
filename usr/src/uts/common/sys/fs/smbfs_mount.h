/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *	must display the following acknowledgement:
 *	This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *	may be used to endorse or promote products derived from this software
 *	without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smbfs.h,v 1.30.100.1 2005/05/27 02:35:28 lindak Exp $
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SMBFS_MOUNT_H
#define	_SMBFS_MOUNT_H

/*
 * This file defines the interface used by mount_smbfs.
 * Some of this came from the Darwin file:
 *   smb-217.2/kernel/fs/smbfs/smbfs.h
 */

#define	SMBFS_VERMAJ	1
#define	SMBFS_VERMIN	3300
#define	SMBFS_VERSION	(SMBFS_VERMAJ*100000 + SMBFS_VERMIN)
#define	SMBFS_VER_STR	"1.33"

#define	SMBFS_VFSNAME	"smbfs"

/* Additions not in mntent.h */
#define	MNTOPT_ACL	"acl"		/* enable smbfs ACLs */
#define	MNTOPT_NOACL	"noacl"		/* disable smbfs ACLs */

/* Values for smbfs_args.flags */
#define	SMBFS_MF_SOFT		0x0001
#define	SMBFS_MF_INTR		0x0002
#define	SMBFS_MF_NOAC		0x0004
#define	SMBFS_MF_ACREGMIN	0x0100	/* set min secs for file attr cache */
#define	SMBFS_MF_ACREGMAX	0x0200	/* set max secs for file attr cache */
#define	SMBFS_MF_ACDIRMIN	0x0400	/* set min secs for dir attr cache */
#define	SMBFS_MF_ACDIRMAX	0x0800	/* set max secs for dir attr cache */

/* Layout of the mount control block for an smb file system. */
struct smbfs_args {
	int		version;		/* smbfs mount version */
	int		devfd;			/* file descriptor */
	uint_t		flags;			/* SMBFS_MF_ flags */
	uid_t		uid;			/* octal user id */
	gid_t		gid;			/* octal group id */
	mode_t		file_mode;		/* octal srwx for files */
	mode_t		dir_mode;		/* octal srwx for dirs */
	int		acregmin;		/* attr cache file min secs */
	int		acregmax;		/* attr cache file max secs */
	int		acdirmin;		/* attr cache dir min secs */
	int		acdirmax;		/* attr cache dir max secs */
};

#ifdef _SYSCALL32

/* Layout of the mount control block for an smb file system. */
struct smbfs_args32 {
	int32_t		version;		/* smbfs mount version */
	int32_t		devfd;			/* file descriptor */
	uint32_t	flags;			/* SMBFS_MF_ flags */
	uid32_t		uid;			/* octal user id */
	gid32_t		gid;			/* octal group id */
	mode32_t	file_mode;		/* octal srwx for files */
	mode32_t	dir_mode;		/* octal srwx for dirs */
	int32_t		acregmin;		/* attr cache file min secs */
	int32_t		acregmax;		/* attr cache file max secs */
	int32_t		acdirmin;		/* attr cache dir min secs */
	int32_t		acdirmax;		/* attr cache dir max secs */
};

#endif /* _SYSCALL32 */
#endif	/* _SMBFS_MOUNT_H */
