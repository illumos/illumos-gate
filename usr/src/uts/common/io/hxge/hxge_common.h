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

#ifndef	_SYS_HXGE_HXGE_COMMON_H
#define	_SYS_HXGE_HXGE_COMMON_H

#include <sys/types.h>
#include <hxge_defs.h>
#include <hxge_pfc.h>
#include <hxge_common_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	HXGE_DMA_START	B_TRUE
#define	HXGE_DMA_STOP	B_FALSE
#define	HXGE_TIMER_RESO	2
#define	HXGE_TIMER_LDG	2

/*
 * Receive and Transmit DMA definitions
 */
#ifdef	_DMA_USES_VIRTADDR
#define	HXGE_DMA_BLOCK		1
#else
#define	HXGE_DMA_BLOCK		(64 * 64)
#endif

#define	HXGE_RBR_RBB_MIN	128
#define	HXGE_RBR_RBB_MAX	((64 * 128) - 1)
#if defined(__sparc)
#define	HXGE_RBR_RBB_DEFAULT	1536		/* Number of RBR Blocks */
#else
#define	HXGE_RBR_RBB_DEFAULT	2048		/* Number of RBR Blocks */
#endif
#define	HXGE_RCR_MIN		(HXGE_RBR_RBB_MIN * 2)
#define	HXGE_RCR_MAX		65504			/* 2^16 - 32 */

/*
 * 4096/256 for x86 and 8192 / 256 for Sparc
 *	NOTE: RCR Ring Size should *not* enable bit 19 of the address.
 */
#if defined(__sparc)
#define	HXGE_RCR_DEFAULT	(HXGE_RBR_RBB_DEFAULT * 32)
#else
#define	HXGE_RCR_DEFAULT	(HXGE_RBR_RBB_DEFAULT * 16)
#endif

#define	HXGE_TX_RING_DEFAULT	2048
#define	HXGE_TX_RING_MAX	((64 * 128) - 1)

#define	RBR_BKSIZE_4K		0
#define	RBR_BKSIZE_8K		1
#define	RBR_BKSIZE_4K_BYTES	(4 * 1024)

#define	RBR_BUFSZ2_2K		0
#define	RBR_BUFSZ2_4K		1
#define	RBR_BUFSZ2_2K_BYTES	(2 * 1024)
#define	RBR_BUFSZ2_4K_BYTES	(4 * 1024)

#define	RBR_BUFSZ1_1K		0
#define	RBR_BUFSZ1_2K		1
#define	RBR_BUFSZ1_1K_BYTES	1024
#define	RBR_BUFSZ1_2K_BYTES	(2 * 1024)

#define	RBR_BUFSZ0_256B		0
#define	RBR_BUFSZ0_512B		1
#define	RBR_BUFSZ0_1K		2
#define	RBR_BUFSZ0_256_BYTES	256
#define	RBR_BUFSZ0_512_BYTES	512
#define	RBR_BUFSZ0_1K_BYTES	1024

/*
 * VLAN table configuration
 */
typedef struct hxge_mv_cfg {
	uint8_t		flag;			/* 0:unconfigure 1:configured */
} hxge_mv_cfg_t, *p_hxge_mv_cfg_t;

typedef struct hxge_param_map {
#if defined(_BIG_ENDIAN)
	uint32_t		rsrvd2:2;	/* [30:31] rsrvd */
	uint32_t		remove:1;	/* [29] Remove */
	uint32_t		pref:1;		/* [28] preference */
	uint32_t		rsrv:4;		/* [27:24] preference */
	uint32_t		map_to:8;	/* [23:16] map to resource */
	uint32_t		param_id:16;	/* [15:0] Param ID */
#else
	uint32_t		param_id:16;	/* [15:0] Param ID */
	uint32_t		map_to:8;	/* [23:16] map to resource */
	uint32_t		rsrv:4;		/* [27:24] preference */
	uint32_t		pref:1;		/* [28] preference */
	uint32_t		remove:1;	/* [29] Remove */
	uint32_t		rsrvd2:2;	/* [30:31] rsrvd */
#endif
} hxge_param_map_t, *p_hxge_param_map_t;

typedef struct hxge_hw_pt_cfg {
	uint32_t	start_tdc;	 /* start TDC (0 - 3)		*/
	uint32_t	max_tdcs;	 /* max TDC in sequence		*/
	uint32_t	start_rdc;	 /* start RDC (0 - 3)		*/
	uint32_t	max_rdcs;	 /* max rdc in sequence		*/
	uint32_t	rx_full_header;	 /* select the header flag	*/
	uint32_t	start_ldg;	 /* starting logical group # 	*/
	uint32_t	max_ldgs;	 /* max logical device group	*/
	uint32_t	max_ldvs;	 /* max logical devices		*/
} hxge_hw_pt_cfg_t, *p_hxge_hw_pt_cfg_t;

/* per port configuration */
typedef struct hxge_dma_pt_cfg {
	hxge_hw_pt_cfg_t hw_config;	/* hardware configuration 	*/

	uint32_t	alloc_buf_size;
	uint32_t	rbr_size;
	uint32_t	rcr_size;
} hxge_dma_pt_cfg_t, *p_hxge_dma_pt_cfg_t;

/* classification configuration */
typedef struct hxge_class_pt_cfg {
	/* VLAN table */
	hxge_mv_cfg_t	vlan_tbl[VLAN_ID_MAX + 1];
	/* class config value */
	uint32_t	init_hash;
	uint32_t	class_cfg[TCAM_CLASS_MAX];
} hxge_class_pt_cfg_t, *p_hxge_class_pt_cfg_t;

typedef struct hxge_hw_list {
	struct hxge_hw_list 	*next;
	hxge_os_mutex_t 	hxge_cfg_lock;
	hxge_os_mutex_t 	hxge_tcam_lock;
	hxge_os_mutex_t 	hxge_vlan_lock;

	hxge_dev_info_t		*parent_devp;
	struct _hxge_t		*hxge_p;
	uint32_t		ndevs;
	uint32_t 		flags;
	uint32_t 		magic;
} hxge_hw_list_t, *p_hxge_hw_list_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_COMMON_H */
