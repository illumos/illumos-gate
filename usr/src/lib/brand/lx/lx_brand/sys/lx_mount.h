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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_LX_MOUNT_H
#define	_LX_MOUNT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <rpc/rpc.h>
#include <nfs/nfs.h>

extern int lx_nfs_mount(char *, char *, char *, int, char *);

/*
 * mount() is significantly different between Linux and Solaris.  The main
 * difference is between the set of flags.  Some flags on Linux can be
 * translated to a Solaris equivalent, some are converted to a
 * filesystem-specific option, while others have no equivalent whatsoever.
 */
#define	LX_MS_MGC_VAL		0xC0ED0000
#define	LX_MS_RDONLY		0x00000001
#define	LX_MS_NOSUID		0x00000002
#define	LX_MS_NODEV		0x00000004
#define	LX_MS_NOEXEC		0x00000008
#define	LX_MS_SYNCHRONOUS	0x00000010
#define	LX_MS_REMOUNT		0x00000020
#define	LX_MS_MANDLOCK		0x00000040
#define	LX_MS_NOATIME		0x00000400
#define	LX_MS_NODIRATIME	0x00000800
#define	LX_MS_BIND		0x00001000
#define	LX_MS_MOVE		0x00002000
#define	LX_MS_REC		0x00004000
#define	LX_MS_SILENT		0x00008000
#define	LX_MS_POSIXACL		0x00010000
#define	LX_MS_UNBINDABLE	0x00020000
#define	LX_MS_PRIVATE		0x00040000
#define	LX_MS_SLAVE		0x00080000
#define	LX_MS_SHARED		0x00100000
#define	LX_MS_RELATIME		0x00200000
#define	LX_MS_KERNMOUNT		0x00400000
#define	LX_MS_I_VERSION		0x00800000
#define	LX_MS_STRICTATIME	0x01000000
#define	LX_MS_LAZYTIME		0x02000000

/* internal flags - ignored if passed in */
#define	LX_MS_NOSEC		0x10000000
#define	LX_MS_BORN		0x20000000
#define	LX_MS_ACTIVE		0x40000000
#define	LX_MS_NOUSER		0x80000000

#define	LX_MS_SUPPORTED		(LX_MS_MGC_VAL | \
				LX_MS_RDONLY | LX_MS_NOSUID | \
				LX_MS_NODEV | LX_MS_NOEXEC | \
				LX_MS_REMOUNT | LX_MS_NOATIME | \
				LX_MS_NODIRATIME | LX_MS_BIND | LX_MS_SILENT | \
				LX_MS_STRICTATIME | LX_MS_NOSEC | \
				LX_MS_BORN | LX_MS_ACTIVE | LX_MS_NOUSER)

/*
 * support for nfs mounts
 */
#define	LX_NMD_MAXHOSTNAMELEN		256

#define	LX_NFS_MOUNT_SOFT		0x00000001
#define	LX_NFS_MOUNT_INTR		0x00000002
#define	LX_NFS_MOUNT_SECURE		0x00000004
#define	LX_NFS_MOUNT_POSIX		0x00000008
#define	LX_NFS_MOUNT_NOCTO		0x00000010
#define	LX_NFS_MOUNT_NOAC		0x00000020
#define	LX_NFS_MOUNT_TCP		0x00000040
#define	LX_NFS_MOUNT_VER3		0x00000080
#define	LX_NFS_MOUNT_KERBEROS		0x00000100
#define	LX_NFS_MOUNT_NONLM		0x00000200
#define	LX_NFS_MOUNT_BROKEN_SUID	0x00000400
#define	LX_NFS_MOUNT_SUPPORTED		(LX_NFS_MOUNT_SOFT | \
					LX_NFS_MOUNT_INTR | \
					LX_NFS_MOUNT_POSIX | \
					LX_NFS_MOUNT_NOCTO | \
					LX_NFS_MOUNT_NOAC | \
					LX_NFS_MOUNT_TCP | \
					LX_NFS_MOUNT_VER3 | \
					LX_NFS_MOUNT_NONLM)

#define	LX_NMD_DEFAULT_RSIZE		0
#define	LX_NMD_DEFAULT_WSIZE		0

/*
 * the nfs v3 file handle structure definitions are _almost_ the same
 * on linux and solaris.  the key difference are:
 *
 * 1) on linux fh3_length is an unsigned short where as on solaris it's
 *    an int.
 *
 * 2) on linux the file handle data doesn't 32 bit members, so the structure
 *    is not 32 bit aligned.  (where as on solaris it is.)
 *
 * so rather than defining a structure that would allow us to intrepret
 * all the contents of the nfs v3 file handle here, we decide to treate
 * the file handle as an array of chars.  this works just fine since it
 * avoids the alignment issues and the actual file handle handle contects
 * are defined by the nfs specification so they are common across solaris
 * and linux.  we do the same thing for nfs v2 file handles.
 */
struct lx_nfs_fh2 {
	unsigned char	lx_fh_data[NFS_FHSIZE];
} lx_nfs_fh2;

struct lx_nfs_fh3 {
	unsigned short	lx_fh3_length;
	unsigned char	lx_fh3_data[NFS3_FHSIZE];
} lx_nfs_fh3;

typedef struct lx_nfs_mount_data {
	int			nmd_version;
	int			nmd_fd;
	struct lx_nfs_fh2	nmd_old_root;
	int			nmd_flags;
	int			nmd_rsize;
	int			nmd_wsize;
	int			nmd_timeo;
	int			nmd_retrans;
	int			nmd_acregmin;
	int			nmd_acregmax;
	int			nmd_acdirmin;
	int			nmd_acdirmax;
	struct sockaddr_in	nmd_addr;
	char			nmd_hostname[LX_NMD_MAXHOSTNAMELEN];
	int			nmd_namlen;
	uint_t			nmd_bsize;
	struct lx_nfs_fh3	nmd_root;
} lx_nfs_mount_data_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_MOUNT_H */
