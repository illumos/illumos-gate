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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NFS_MOUNT_ATTR_H
#define	_NFS_MOUNT_ATTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Public data type declarations
 */

/*
 * NFS mount attributes
 */

#define	NFS_ATTRCACHE_FALSE "noac"
#define	NFS_ATTRCACHEDIRMAX "acdirmax="
#define	NFS_ATTRCACHEDIRMIN "acdirmin="
#define	NFS_ATTRCACHEFILESMAX "acregmax="
#define	NFS_ATTRCACHEFILESMIN "acregmin="
#define	NFS_ENABLEQUOTA_TRUE "quota"
#define	NFS_ENABLEQUOTA_FALSE "noquota"
#define	NFS_FORCEDIRECTIO_TRUE "forcedirectio"
#define	NFS_FORCEDIRECTIO_FALSE "noforcedirectio"
#define	NFS_GRPID_TRUE "grpid"
#define	NFS_HARDMNT_TRUE "hard"
#define	NFS_HARDMNT_FALSE "soft"
#define	NFS_INTR_TRUE "intr"
#define	NFS_INTR_FALSE "nointr"
#define	NFS_MAXRETRANSATTEMPTS "retrans="
#define	NFS_MNTFAILRETRIES "retry="
#define	NFS_NOCTO_TRUE "nocto"
#define	NFS_NOMNTTABENT_TRUE "-m"
#define	NFS_NOSUID_FALSE "suid"
#define	NFS_NOSUID_TRUE "nosuid"
#define	NFS_OVERLAY "-O"
#define	NFS_POSIX_TRUE "posix"
#define	NFS_PROTO "proto="
#define	NFS_PUBLIC_TRUE "public"
#define	NFS_READBUFFSIZE "rsize="
#define	NFS_READONLY_TRUE "ro"
#define	NFS_READONLY_FALSE "rw"
#define	NFS_RETRANSTIMEO "timeo="
#define	NFS_FOREGROUND_TRUE "fg"
#define	NFS_FOREGROUND_FALSE "bg"
#define	NFS_SECMODE "sec="
#define	NFS_SERVERCOMMPORT "port="
#define	NFS_VERS "vers="
#define	NFS_WRITEBUFFSIZE "wsize="
#define	NFS_XATTR_TRUE "xattr"
#define	NFS_XATTR_FALSE "noxattr"

#ifdef __cplusplus
}
#endif

#endif /* _NFS_MOUNT_ATTR_H */
