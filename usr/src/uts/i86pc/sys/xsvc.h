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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_XSVC_H
#define	_SYS_XSVC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/avl.h>
#include <sys/types.h>

/* xsvc ioctls */
#define	XSVCIOC		('Q'<< 8)
#define	XSVC_ALLOC_MEM	(XSVCIOC | 130)
#define	XSVC_FREE_MEM	(XSVCIOC | 131)
#define	XSVC_FLUSH_MEM	(XSVCIOC | 132)

/* arg * struct for ioctls */
typedef struct _xsvc_mem_req {
	int		xsvc_mem_reqid; /* request ID */
	uint64_t	xsvc_mem_addr_lo; /* low DMA address range */
	uint64_t	xsvc_mem_addr_hi; /* high DMA address range */
	uint64_t	xsvc_mem_align; /* DMA address alignment */
	int		xsvc_mem_sgllen; /* s/g length */
	size_t		xsvc_mem_size; /* length of mem in bytes */
	void		*xsvc_sg_list; /* returned scatter gather list */
} xsvc_mem_req;

/* xsvc_sg_list format */
typedef struct _xsvc_mloc {
	uint64_t	mloc_addr;
	size_t		mloc_size;
} xsvc_mloc;

#ifdef _KERNEL
/* *** Driver Private Below *** */

/* arg * struct for ioctls from 32-bit app in 64-bit kernel */
#pragma pack(1)
typedef struct _xsvc_mem_req_32 {
	int		xsvc_mem_reqid; /* request ID */
	uint64_t	xsvc_mem_addr_lo; /* low DMA address range */
	uint64_t	xsvc_mem_addr_hi; /* high DMA address range */
	uint64_t	xsvc_mem_align; /* DMA address alignment */
	int		xsvc_mem_sgllen; /* s/g length */
	uint32_t	xsvc_mem_size; /* length of mem in bytes */
	uint32_t	xsvc_sg_list; /* returned scatter gather list */
} xsvc_mem_req_32;
#pragma pack()

/* xsvc_sg_list format */
#pragma pack(1)
typedef struct _xsvc_mloc_32 {
	uint64_t	mloc_addr;
	uint32_t	mloc_size;
} xsvc_mloc_32;
#pragma pack()

/* avl node */
typedef struct xsvc_mnode_s {
	avl_node_t		mn_link;
	uint64_t		mn_key;
	struct xsvc_mem_s	*mn_home;
} xsvc_mnode_t;

/* track memory allocs */
typedef struct xsvc_mem_s {
	xsvc_mnode_t		xm_mnode;
	size_t			xm_size;
	caddr_t			xm_addr;
	size_t			xm_real_length;
	ddi_dma_handle_t	xm_dma_handle;
	ddi_acc_handle_t	xm_mem_handle;
	ddi_dma_attr_t		xm_dma_attr;
	ddi_device_acc_attr_t	xm_device_attr;
	uint_t			xm_cookie_count;
	ddi_dma_cookie_t	xm_cookie;
} xsvc_mem_t;

/* list of memory allocs */
typedef struct xsvc_mlist_s {
	kmutex_t	ml_mutex;
	avl_tree_t	ml_avl;
} xsvc_mlist_t;

/* driver state */
typedef struct xsvc_state_s {
	dev_info_t	*xs_dip;
	int		xs_instance;

	/*
	 * track total memory allocated, mutex only covers
	 * xs_currently_alloced
	 */
	kmutex_t	xs_mutex;
	uint64_t	xs_currently_alloced;

	kmutex_t	xs_cookie_mutex;

	xsvc_mlist_t	xs_mlist;
} xsvc_state_t;

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_XSVC_H */
