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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_DRM_IO32_H_
#define	_DRM_IO32_H_

#ifdef _MULTI_DATAMODEL

typedef struct drm_version_32 {
	int version_major;		/* Major version */
	int version_minor;		/* Minor version */
	int version_patchlevel;	/* Patch level */
	uint32_t name_len;		/* Length of name buffer */
	caddr32_t name;			/* Name of driver */
	uint32_t date_len;		/* Length of date buffer */
	caddr32_t date;			/* User-space buffer to hold date */
	uint32_t desc_len;		/* Length of desc buffer */
	caddr32_t desc;			/* User-space buffer to hold desc */
} drm_version_32_t;

typedef struct drm_unique_32 {
	uint32_t unique_len;    /* Length of unique */
	caddr32_t unique;   /* Unique name for driver instantiation */
} drm_unique_32_t;

typedef struct drm_ctx_priv_map_32 {
	unsigned int ctx_id;	/* Context requesting private mapping */
	caddr32_t handle;		/* Handle of map */
} drm_ctx_priv_map_32_t;

typedef struct drm_map_32 {
	unsigned long long offset;
	unsigned long long handle;
	uint32_t size;
	drm_map_type_t type;
	drm_map_flags_t flags;
	int mtrr;
} drm_map_32_t;


typedef struct drm_client_32 {
	int idx;		/* Which client desired? */
	int auth;		/* Is client authenticated? */
	uint32_t pid;	/* Process ID */
	uint32_t uid;	/* User ID */
	uint32_t magic;	/* Magic */
	uint32_t iocs;	/* Ioctl count */
} drm_client_32_t;


typedef struct drm_stats_32 {
	uint32_t count;
	struct {
		uint32_t value;
		drm_stat_type_t type;
	} data[15];
} drm_stats_32_t;


typedef struct drm_buf_desc_32 {
	int		count;		/* Number of buffers of this size */
	int		size;		/* Size in bytes */
	int		low_mark;	/* Low water mark */
	int		high_mark;	/* High water mark */
	drm_buf_flag flags;

	/*
	 * Start address of where the AGP buffers are
	 * in the AGP aperture
	 */
	uint32_t agp_start;

}drm_buf_desc_32_t;

typedef struct drm_buf_free_32 {
	int count;
	uint32_t list;
} drm_buf_free_32_t;

/*
 * Used by DRM_IOCTL_MAP_BUFS_32
 */
typedef struct drm_buf_pub_32 {
	int idx;		/* Index into the master buffer list */
	int total;		/* Buffer size */
	int used;		/* Amount of buffer in use (for DMA) */
	uint32_t address;	/* Address of buffer */
} drm_buf_pub_32_t;

typedef struct drm_buf_map_32 {
	int		count;	/* Length of the buffer list */
#if defined(__cplusplus)
	uint32_t c_virtual;
#else
	uint32_t virtual;	/* Mmap'd area in user-virtual */
#endif
	uint32_t	list; /* Buffer information */
	int    fd;
} drm_buf_map_32_t;

typedef struct drm_agp_mode_32 {
    uint32_t mode;  /* AGP mode */
} drm_agp_mode_32_t;

typedef struct drm_agp_buffer32 {
	uint32_t size;		/* In bytes -- will round to page boundary */
	uint32_t handle;	/* Used for binding / unbinding */
	uint32_t type;		/* Type of memory to allocate */
	uint32_t physical;	/* Physical used by i810 */
} drm_agp_buffer_32_t;

typedef struct drm_agp_binding_32 {
	uint32_t handle;	/* From drm_agp_buffer */
	uint32_t offset;	/* In bytes -- will round to page boundary */
} drm_agp_binding_32_t;

typedef struct drm_agp_info_32 {
	int agp_version_major;
	int agp_version_minor;
	uint32_t mode;
	uint32_t aperture_base;
	uint32_t aperture_size;
	uint32_t memory_allowed;
	uint32_t memory_used;
	unsigned short id_vendor;
	unsigned short id_device;
} drm_agp_info_32_t;

typedef struct drm_scatter_gather_32 {
	uint32_t	size;	/* In bytes -- will round to page boundary */
	uint32_t	handle;	/* Used for mapping/unmapping */
} drm_scatter_gather_32_t;

typedef struct drm_ctx_res_32 {
	int count;
	caddr32_t contexts;
} drm_ctx_res_32_t;

struct drm_wait_vblank_request_32 {
	drm_vblank_seq_type_t type;
	unsigned int sequence;
	unsigned long signal;
};
struct drm_wait_vblank_reply_32 {
	drm_vblank_seq_type_t type;
	unsigned int sequence;
	long tval_sec;
	long tval_usec;
};

/*
 * DRM_IOCTL_WAIT_VBLANK ioctl argument type.
 *
 * \sa drmWaitVBlank().
 */
typedef union drm_wait_vblank_32 {
	struct drm_wait_vblank_request_32 request;
	struct drm_wait_vblank_reply_32 reply;
} drm_wait_vblank_32_t;


#endif  /* _MULTI_DATAMODEL */

#endif	/* _DRM_IO32_H_ */
