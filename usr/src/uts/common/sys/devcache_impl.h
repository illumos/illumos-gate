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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DEVCACHE_IMPL_H
#define	_SYS_DEVCACHE_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/list.h>

/*
 * /etc/devices cache files format
 * Leave some padding for easy extension in the future
 */

#define	NVPF_HDR_MAGIC		0xdeb1dcac
#define	NVPF_HDR_VERSION	1
#define	NVPF_HDR_SIZE		128

typedef struct nvpacked_file_hdr {
	union {
		struct nvfp_hdr {
			uint32_t	magic;
			int32_t		version;
			int64_t		size;
			uint16_t	hdr_chksum;
			uint16_t	chksum;
		} nvpf;
		uchar_t		nvpf_pad[NVPF_HDR_SIZE];
	} un;
} nvpf_hdr_t;

#define	nvpf_magic		un.nvpf.magic
#define	nvpf_version		un.nvpf.version
#define	nvpf_size		un.nvpf.size
#define	nvpf_hdr_chksum		un.nvpf.hdr_chksum
#define	nvpf_chksum		un.nvpf.chksum


#ifdef	_KERNEL

/*
 * Descriptor used for kernel-level file i/o
 */
typedef struct kfile {
	struct vnode	*kf_vp;
	int		kf_vnflags;
	char		*kf_fname;
	offset_t	kf_fpos;
	int		kf_state;
} kfile_t;

/*
 * File descriptor for files in the nvlist format
 */
typedef struct nvfiledesc nvfd_t;

/*
 * Descriptor for a file managed as a backing store for some
 * kernel-generated device state such as device devids,
 * vhci-to-phci mapping, etc.
 * Each client can manage the data in any form convenient.
 * providing functions to unpack (read) and pack (write)
 * the data as an nvlist.
 *
 * Clients should not reference this structure directly
 * but through the handle returned when registering.
 */
struct nvfiledesc {
	nvf_ops_t	*nvf_ops;		/* client ops vectors */
	int		nvf_flags;		/* flags */
	list_t		nvf_data_list;		/* data list */
	krwlock_t	nvf_lock;		/* lock for data list */
	list_node_t	nvf_link;		/* link to next file desc */
};

/*
 * nvf_flags
 */
#define	NVF_F_DIRTY		0x01	/* needs to be flushed */
#define	NVF_F_FLUSHING		0x02	/* in process of being flushed */
#define	NVF_F_ERROR		0x04	/* most recent flush failed */
#define	NVF_F_READONLY		0x10	/* file is read-only */
#define	NVF_F_CREATE_MSG	0x20	/* file not found on boot, emit msg */
#define	NVF_F_REBUILD_MSG	0x40	/* file was found corrupted, emit msg */

#define	NVF_IS_DIRTY(nvfd)	((nvfd)->nvf_flags & NVF_F_DIRTY)
#define	NVF_MARK_DIRTY(nvfd)	((nvfd)->nvf_flags |= NVF_F_DIRTY)
#define	NVF_CLEAR_DIRTY(nvfd)	((nvfd)->nvf_flags &= ~NVF_F_DIRTY)

#define	NVF_IS_READONLY(nvfd)	((nvfd)->nvf_flags & NVF_F_READONLY)
#define	NVF_MARK_READONLY(nvfd)	((nvfd)->nvf_flags |= NVF_F_READONLY)

/* shorthand to client ops */
#define	nvf_cache_path		nvf_ops->nvfr_cache_path
#define	nvf_unpack_nvlist	nvf_ops->nvfr_unpack_nvlist
#define	nvf_pack_list		nvf_ops->nvfr_pack_list
#define	nvf_list_free		nvf_ops->nvfr_list_free
#define	nvf_write_complete	nvf_ops->nvfr_write_complete


/*
 * More thorough error reporting available both debug &
 * non-debug kernels, but turned off by default.
 */
extern int kfio_report_error;		/* kernel file i/o operations */

/*
 * Suffix of temporary file for updates
 */
#define	MAX_SUFFIX_LEN		4
#define	NEW_FILENAME_SUFFIX	"new"


#ifdef	DEBUG

#define	NVPDAEMON_DEBUG(args)	{ if (nvpdaemon_debug) cmn_err args; }
#define	KFDEBUG(args)		{ if (kfio_debug) cmn_err args; }
#define	KFDEBUG1(args)		{ if (kfio_debug > 1) cmn_err args; }
#define	KFDEBUG2(args)		{ if (kfio_debug > 2) cmn_err args; }
#define	KFDUMP(args)		{ if (kfio_debug > 2) args; }

#else

#define	NVPDAEMON_DEBUG(args)
#define	KFDEBUG(args)
#define	KFDEBUG1(args)
#define	KFDEBUG2(args)
#define	KFDUMP(args)

#endif	/* DEBUG */


#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEVCACHE_IMPL_H */
