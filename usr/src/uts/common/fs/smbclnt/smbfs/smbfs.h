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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SMBFS_SMBFS_H
#define	_SMBFS_SMBFS_H

/*
 * FS-specific VFS structures for smbfs.
 * (per-mount stuff, etc.)
 *
 * This file used to have mount args stuff,
 * but that's now in sys/fs/smbfs_mount.h
 */

#include <sys/param.h>
#include <sys/fstyp.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/t_lock.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/fs/smbfs_mount.h>
#include <sys/zone.h>

/*
 * Path component length
 *
 * The generic fs code uses MAXNAMELEN to represent
 * what the largest component length is, but note:
 * that length DOES include the terminating NULL.
 * SMB_MAXFNAMELEN does NOT include the NULL.
 */
#define	SMB_MAXFNAMELEN		(MAXNAMELEN-1)	/* 255 */

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
 * The values for smi_flags (from nfs_clnt.h)
 */
#define	SMI_INT		0x04		/* interrupts allowed */
#define	SMI_NOAC	0x10		/* don't cache attributes */
#define	SMI_LLOCK	0x80		/* local locking only */
#define	SMI_ACL		0x2000		/* share supports ACLs */
#define	SMI_DIRECTIO	0x40000		/* do direct I/O */
#define	SMI_EXTATTR	0x80000		/* share supports ext. attrs */
#define	SMI_DEAD	0x200000	/* mount has been terminated */

/*
 * Stuff returned by smbfs_smb_qfsattr
 * See [CIFS] SMB_QUERY_FS_ATTRIBUTE_INFO
 */
typedef struct smb_fs_attr_info {
	uint32_t	fsa_aflags;	/* Attr. flags [CIFS 4.1.6.6] */
	uint32_t	fsa_maxname;	/* max. component length */
	char		fsa_tname[FSTYPSZ]; /* type name, i.e. "NTFS" */
} smb_fs_attr_info_t;

/*
 * Corresponds to Darwin: struct smbmount
 */
typedef struct smbmntinfo {
	struct vfs		*smi_vfsp;	/* mount back pointer to vfs */
	struct smbnode		*smi_root;	/* the root node */
	struct smb_share	*smi_share;	/* netsmb SMB share conn data */
	struct taskq		*smi_taskq;	/* for async work */
	kmutex_t		smi_lock;	/* mutex for flags, etc. */
	uint32_t		smi_flags;	/* NFS-derived flag bits */
	uint32_t		smi_status;	/* status bits for this mount */
	hrtime_t		smi_statfstime;	/* sm_statvfsbuf cache time */
	statvfs64_t		smi_statvfsbuf;	/* cached statvfs data */
	kcondvar_t		smi_statvfs_cv;
	smb_fs_attr_info_t	smi_fsa;	/* SMB FS attributes. */
#define	smi_fsattr		smi_fsa.fsa_aflags

	/*
	 * The smbfs node cache for this mount.
	 * Named "hash" for historical reasons.
	 * See smbfs_node.h for details.
	 */
	avl_tree_t		smi_hash_avl;
	krwlock_t		smi_hash_lk;

	/*
	 * Kstat statistics
	 */
	struct kstat    *smi_io_kstats;
	struct kstat    *smi_ro_kstats;

	/*
	 * Zones support.
	 */
	zone_ref_t		smi_zone_ref;	/* Zone FS is mounted in */
	list_node_t		smi_zone_node;	/* Link to per-zone smi list */
	/* Lock for the list is: smi_globals_t -> smg_lock */

	/*
	 * Stuff copied or derived from the mount args
	 */
	uid_t		smi_uid;		/* user id */
	gid_t		smi_gid;		/* group id */
	mode_t		smi_fmode;		/* mode for files */
	mode_t		smi_dmode;		/* mode for dirs */

	hrtime_t	smi_acregmin;	/* min time to hold cached file attr */
	hrtime_t	smi_acregmax;	/* max time to hold cached file attr */
	hrtime_t	smi_acdirmin;	/* min time to hold cached dir attr */
	hrtime_t	smi_acdirmax;	/* max time to hold cached dir attr */
} smbmntinfo_t;

/*
 * Attribute cache timeout defaults (in seconds).
 */
#define	SMBFS_ACREGMIN	3	/* min secs to hold cached file attr */
#define	SMBFS_ACREGMAX	60	/* max secs to hold cached file attr */
#define	SMBFS_ACDIRMIN	30	/* min secs to hold cached dir attr */
#define	SMBFS_ACDIRMAX	60	/* max secs to hold cached dir attr */
/* and limits for the mount options */
#define	SMBFS_ACMINMAX	600	/* 10 min. is longest min timeout */
#define	SMBFS_ACMAXMAX	3600	/* 1 hr is longest max timeout */

/*
 * High-res time is nanoseconds.
 */
#define	SEC2HR(sec)	((sec) * (hrtime_t)NANOSEC)

/*
 * vnode pointer to mount info
 */
#define	VTOSMI(vp)	((smbmntinfo_t *)(((vp)->v_vfsp)->vfs_data))
#define	VFTOSMI(vfsp)	((smbmntinfo_t *)((vfsp)->vfs_data))
#define	SMBINTR(vp)	(VTOSMI(vp)->smi_flags & SMI_INT)

#endif	/* _SMBFS_SMBFS_H */
