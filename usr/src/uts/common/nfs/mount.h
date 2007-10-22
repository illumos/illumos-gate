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
 */

/*
 *	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 *		All Rights Reserved
 */

#ifndef	_NFS_MOUNT_H
#define	_NFS_MOUNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/pathconf.h>			/* static pathconf kludge */


#define	NFS_ARGS_EXTA	1
#define	NFS_ARGS_EXTB	2

/*
 * extension data for nfs_args_ext == NFS_ARGS_EXTA.
 */
struct nfs_args_extA {
	struct sec_data		*secdata;	/* security data */
};

/*
 * extension data for nfs_args_ext == NFS_ARGS_EXTB.
 */
struct nfs_args_extB {
	struct sec_data		*secdata;	/* security data */
	struct nfs_args		*next;		/* link for failover */
};

/*
 * Union structure for future extension.
 */
union nfs_ext {
	struct nfs_args_extA	nfs_extA;	/* nfs_args extension v1 */
	struct nfs_args_extB	nfs_extB;	/* nfs_args extension v2 */
};

struct nfs_args {
	struct netbuf		*addr;		/* file server address */
	struct netbuf		*syncaddr;	/* secure NFS time sync addr */
	struct knetconfig	*knconf;	/* transport netconfig struct */
	char			*hostname;	/* server's hostname */
	char			*netname;	/* server's netname */
	caddr_t			fh;		/* File handle to be mounted */
	int			flags;		/* flags */
	int			wsize;		/* write size in bytes */
	int			rsize;		/* read size in bytes */
	int			timeo;		/* initial timeout in .1 secs */
	int			retrans;	/* times to retry send */
	int			acregmin;	/* attr cache file min secs */
	int			acregmax;	/* attr cache file max secs */
	int			acdirmin;	/* attr cache dir min secs */
	int			acdirmax;	/* attr cache dir max secs */
	struct pathcnf		*pathconf;	/* static pathconf kludge */
	int			nfs_args_ext;	/* the nfs_args extension id */
	union nfs_ext		nfs_ext_u;	/* extension union structure */
};

#ifdef _SYSCALL32
struct nfs_args_extA32 {
	caddr32_t		secdata;	/* security data */
};

struct nfs_args_extB32 {
	caddr32_t		secdata;	/* security data */
	caddr32_t		next;		/* link for failover */
};

union nfs_ext32 {
	struct nfs_args_extA32	nfs_extA;	/* nfs_args extension v1 */
	struct nfs_args_extB32	nfs_extB;	/* nfs_args extension v2 */
};

struct nfs_args32 {
	caddr32_t		addr;		/* file server address */
	caddr32_t		syncaddr;	/* secure NFS time sync addr */
	caddr32_t		knconf;		/* transport netconfig struct */
	caddr32_t		hostname;	/* server's hostname */
	caddr32_t		netname;	/* server's netname */
	caddr32_t		fh;		/* File handle to be mounted */
	int32_t			flags;		/* flags */
	int32_t			wsize;		/* write size in bytes */
	int32_t			rsize;		/* read size in bytes */
	int32_t			timeo;		/* initial timeout in .1 secs */
	int32_t			retrans;	/* times to retry send */
	int32_t			acregmin;	/* attr cache file min secs */
	int32_t			acregmax;	/* attr cache file max secs */
	int32_t			acdirmin;	/* attr cache dir min secs */
	int32_t			acdirmax;	/* attr cache dir max secs */
	caddr32_t		pathconf;	/* static pathconf kludge */
	int32_t			nfs_args_ext;	/* the nfs_args extension id */
	union nfs_ext32		nfs_ext_u;	/* extension union structure */
};
#endif /* _SYSCALL32 */

/*
 * NFS mount option flags
 */
#define	NFSMNT_SOFT		0x001	/* soft mount (hard is default) */
#define	NFSMNT_WSIZE		0x002	/* set write size */
#define	NFSMNT_RSIZE		0x004	/* set read size */
#define	NFSMNT_TIMEO		0x008	/* set initial timeout */
#define	NFSMNT_RETRANS		0x010	/* set number of request retrys */
#define	NFSMNT_HOSTNAME		0x020	/* set hostname for error printf */
#define	NFSMNT_INT		0x040	/* allow interrupts on hard mount */
#define	NFSMNT_NOAC		0x080	/* don't cache attributes */
#define	NFSMNT_ACREGMIN		0x0100	/* set min secs for file attr cache */
#define	NFSMNT_ACREGMAX		0x0200	/* set max secs for file attr cache */
#define	NFSMNT_ACDIRMIN		0x0400	/* set min secs for dir attr cache */
#define	NFSMNT_ACDIRMAX		0x0800	/* set max secs for dir attr cache */
#define	NFSMNT_SECURE		0x1000	/* secure mount */
#define	NFSMNT_NOCTO		0x2000	/* no close-to-open consistency */
#define	NFSMNT_KNCONF		0x4000	/* transport's knetconfig structure */
#define	NFSMNT_GRPID		0x8000	/* System V-style gid inheritance */
#define	NFSMNT_RPCTIMESYNC	0x10000	/* use RPC to do secure NFS time sync */
#define	NFSMNT_KERBEROS		0x20000	/* use kerberos credentials */
#define	NFSMNT_POSIX		0x40000 /* static pathconf kludge info */
#define	NFSMNT_LLOCK		0x80000	/* Local locking (no lock manager) */
#define	NFSMNT_LOOPBACK		0x100000 /* Is a loopback mount */
#define	NFSMNT_SEMISOFT		0x200000 /* read soft, modify hard */
#define	NFSMNT_NOPRINT		0x400000 /* don't print messages */
#define	NFSMNT_NEWARGS		0x800000 /* using nfs_args extented structure */
#define	NFSMNT_DIRECTIO		0x1000000 /* do direct I/O */
#define	NFSMNT_PUBLIC		0x2000000 /* mount was done with url/public */
#define	NFSMNT_SECDEFAULT	0x4000000 /* mount using default sec flavor */
#define	NFSMNT_TRYRDMA		0x8000000 /* Try RDMA mount,no proto advised */
#define	NFSMNT_DORDMA		0x10000000 /* Do an RDMA mount, regardless */
#define	NFSMNT_MIRRORMOUNT	0x20000000 /* Is a mirrormount */

/*
 * This will have to change when we do referrals.
 */
#define	NFSMNT_EPHEMERAL	NFSMNT_MIRRORMOUNT

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_MOUNT_H */
