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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SMBFS_MOUNT_H
#define	_SMBFS_MOUNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines the interface used by mount_smbfs.
 * Some of this came from the Darwin file:
 *   smb-217.2/kernel/fs/smbfs/smbfs.h
 */

#define	SMBFS_VERMAJ	1
#define	SMBFS_VERMIN	3200
#define	SMBFS_VERSION	(SMBFS_VERMAJ*100000 + SMBFS_VERMIN)
#define	SMBFS_VER_STR	"1.32"

#define	SMBFS_VFSNAME	"smbfs"

/* Values for flags */
#define	SMBFS_MOUNT_SOFT	0x0001
#define	SMBFS_MOUNT_INTR	0x0002
#define	SMBFS_MOUNT_STRONG	  0x0004
#define	SMBFS_MOUNT_HAVE_NLS	0x0008
#define	SMBFS_MOUNT_NO_LONG	 0x0010
#define	SMBFS_MOUNT_HOSTNAME	0x020
#define	SMBFS_MOUNT_SEMISOFT	0x200000 /* read soft, modify hard */
#define	SMBFS_MOUNT_NOPRINT	 0x400000 /* don't print messages */

#define	MNT_RDONLY		0x0001
#define	MNT_NODEV		0x0002
#define	MNT_NOEXEC		0x0004
#define	MNT_NOSUID		0x0008
#define	MNT_UNION		0x0010
#define	MNT_DONTBROWSE		0x0020
#define	MNT_AUTOMOUNTED		0x0040

/* Layout of the mount control block for an smb file system. */
struct smbfs_args {
	int		version;		/* smbfs mount version */
	int		devfd;			/* file descriptor */
	uint_t		flags;			/* mount options, eg: soft */
	mode_t		file_mode;		/* octal srwx for files */
	mode_t		dir_mode;		/* octal srwx for dirs */
	int		caseopt;		/* convert upper|lower|none */
	caddr_t		addr;			/* file server address */
	caddr_t		hostname;		/* server's hostname */
	caddr_t		sharename;		/* server's sharename */
	uid_t		uid;			/* octal user id */
	gid_t		gid;			/* octal group id */
};

#ifdef _SYSCALL32

/* Layout of the mount control block for an smb file system. */
struct smbfs_args32 {
	int32_t		version;		/* smbfs mount version */
	int32_t		devfd;			/* file descriptor */
	uint_t		flags;			/* mount options, eg: soft */
	mode_t		file_mode;		/* octal srwx for files */
	mode_t		dir_mode;		/* octal srwx for dirs */
	int32_t		caseopt;		/* convert upper|lower|none */
	caddr32_t	addr;			/* file server address */
	caddr32_t	hostname;		/* server's hostname */
	caddr32_t	sharename;		/* server's sharename */
	uid32_t		uid;			/* octal user id */
	gid32_t		gid;			/* octal group id */
};

#endif /* _SYSCALL32 */
#endif	/* _SMBFS_MOUNT_H */
