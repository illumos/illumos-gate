/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SMBFS_SMBFS_H
#define	_SMBFS_SMBFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FS-specific VFS structures for smbfs.
 * (per-mount stuff, etc.)
 *
 * This file used to have mount args stuff,
 * but that's now in sys/fs/smbfs_mount.h
 */

#include <sys/list.h>
#include <sys/vfs.h>
#include <sys/fs/smbfs_mount.h>


/*
 * SM_MAX_STATFSTIME is the maximum time to cache statvfs data. Since this
 * should be a fast call on the server, the time the data cached is short.
 * That lets the cache handle bursts of statvfs() requests without generating
 * lots of network traffic.
 */
#define	SM_MAX_STATFSTIME 2

/* Mask values for smbmount structure sm_status field */
#define	SM_STATUS_STATFS_BUSY 0x00000001 /* statvfs is in progress */
#define	SM_STATUS_STATFS_WANT 0x00000002 /* statvfs wakeup is wanted */
#define	SM_STATUS_TIMEO 0x00000004 /* this mount is not responding */
#define	SM_STATUS_DEAD	0x00000010 /* connection gone - unmount this */

extern const struct fs_operation_def	smbfs_vnodeops_template[];
extern struct vnodeops			*smbfs_vnodeops;

struct smbnode;
struct smb_share;

/*
 * The values for smi_flags.
 */
#define	SMI_INT		0x01		/* interrupts allowed */
#define	SMI_DEAD	0x02		/* zone shutting down */
#define	SMI_LLOCK	0x80		/* local locking only */

/*
 * Corresponds to Darwin: struct smbmount
 */
typedef struct smbmntinfo {
	struct vfs		*smi_vfsp;	/* mount back pointer to vfs */
	struct smbnode		*smi_root;	/* the root node */
	struct smb_share	*smi_share;	/* netsmb SMB share conn data */
	kmutex_t		smi_lock;	/* mutex for flags, etc. */
	uint32_t		smi_flags;	/* NFS-derived flag bits */
	uint32_t		smi_fsattr;	/* acls & streams opts */
	uint32_t		smi_status;	/* status bits for this mount */
	hrtime_t		smi_statfstime;	/* sm_statvfsbuf cache time */
	statvfs64_t		smi_statvfsbuf;	/* cached statvfs data */
	kcondvar_t		smi_statvfs_cv;

	/*
	 * Kstat statistics
	 */
	struct kstat    *smi_io_kstats;
	struct kstat    *smi_ro_kstats;

	/*
	 * Zones support.
	 */
	struct zone		*smi_zone;	/* Zone mounted in */
	list_node_t		smi_zone_node;	/* Link to per-zone smi list */
	/* Lock for the list is: smi_globals_t -> smg_lock */

	/*
	 * Copy of the args from mount.
	 */
	struct smbfs_args	smi_args;
} smbmntinfo_t;

typedef struct smbfattr {
	int		fa_attr;
	len_t		fa_size;
	struct timespec fa_atime;
	struct timespec fa_ctime;
	struct timespec fa_mtime;
	ino64_t		fa_ino;
	struct timespec fa_reqtime;
} smbfattr_t;

/*
 * vnode pointer to mount info
 */
#define	VTOSMI(vp)	((smbmntinfo_t *)(((vp)->v_vfsp)->vfs_data))
#define	VFTOSMI(vfsp)	((smbmntinfo_t *)((vfsp)->vfs_data))
#define	SMBINTR(vp)	(VTOSMI(vp)->smi_flags & SMI_INT)

#endif	/* _SMBFS_SMBFS_H */
