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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NXGE_NXGE_IMPL_H
#define	_SYS_NXGE_NXGE_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NIU HV API version definitions.
 *
 * If additional major (HV API) is to be supported,
 * please increment NIU_MAJOR_HI.
 * If additional minor # is to be supported,
 * please increment NIU_MINOR_HI.
 */
#define	NIU_MAJOR_HI		2
#define	NIU_MINOR_HI		1
#define	NIU_MAJOR_VER		1
#define	NIU_MINOR_VER		1
#define	NIU_MAJOR_VER_2		2

#if defined(sun4v)

/*
 * NIU HV API v1.0 definitions
 */
#define	N2NIU_RX_LP_CONF		0x142
#define	N2NIU_RX_LP_INFO		0x143
#define	N2NIU_TX_LP_CONF		0x144
#define	N2NIU_TX_LP_INFO		0x145

#endif /* defined(sun4v) */

#ifndef _ASM

#include	<sys/types.h>
#include	<sys/byteorder.h>
#include	<sys/debug.h>
#include	<sys/stropts.h>
#include	<sys/stream.h>
#include	<sys/strlog.h>
#include	<sys/strsubr.h>
#include	<sys/cmn_err.h>
#include	<sys/vtrace.h>
#include	<sys/kmem.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/strsun.h>
#include	<sys/stat.h>
#include	<sys/cpu.h>
#include	<sys/kstat.h>
#include	<inet/common.h>
#include	<inet/ip.h>
#include	<sys/dlpi.h>
#include	<inet/nd.h>
#include	<netinet/in.h>
#include	<sys/ethernet.h>
#include	<sys/vlan.h>
#include	<sys/pci.h>
#include	<sys/taskq.h>
#include	<sys/atomic.h>

#include 	<sys/nxge/nxge_defs.h>
#include 	<sys/nxge/nxge_hw.h>
#include 	<sys/nxge/nxge_mac.h>
#include	<sys/nxge/nxge_mii.h>
#include	<sys/nxge/nxge_fm.h>
#include	<sys/netlb.h>

#include	<sys/ddi_intr.h>
#include 	<sys/mac_provider.h>
#include	<sys/mac_ether.h>

#if	defined(sun4v)
#include	<sys/hypervisor_api.h>
#include 	<sys/machsystm.h>
#include 	<sys/hsvc.h>
#endif

#include 	<sys/dld.h>

/*
 * Handy macros (taken from bge driver)
 */
#define	RBR_SIZE			4
#define	DMA_COMMON_CHANNEL(area)	((area.dma_channel))
#define	DMA_COMMON_VPTR(area)		((area.kaddrp))
#define	DMA_COMMON_VPTR_INDEX(area, index)	\
					(((char *)(area.kaddrp)) + \
					(index * RBR_SIZE))
#define	DMA_COMMON_HANDLE(area)		((area.dma_handle))
#define	DMA_COMMON_ACC_HANDLE(area)	((area.acc_handle))
#define	DMA_COMMON_IOADDR(area)		((area.dma_cookie.dmac_laddress))
#define	DMA_COMMON_IOADDR_INDEX(area, index)	\
					((area.dma_cookie.dmac_laddress) + \
						(index * RBR_SIZE))

#define	DMA_NPI_HANDLE(area)		((area.npi_handle)

#define	DMA_COMMON_SYNC(area, flag)	((void) ddi_dma_sync((area).dma_handle,\
						(area).offset, (area).alength, \
						(flag)))
#define	DMA_COMMON_SYNC_OFFSET(area, bufoffset, len, flag)	\
					((void) ddi_dma_sync((area).dma_handle,\
					(area.offset + bufoffset), len, \
					(flag)))

#define	DMA_COMMON_SYNC_RBR_DESC(area, index, flag)	\
				((void) ddi_dma_sync((area).dma_handle,\
				(index * RBR_SIZE), RBR_SIZE,	\
				(flag)))

#define	DMA_COMMON_SYNC_RBR_DESC_MULTI(area, index, count, flag)	\
			((void) ddi_dma_sync((area).dma_handle,\
			(index * RBR_SIZE), count * RBR_SIZE,	\
				(flag)))
#define	DMA_COMMON_SYNC_ENTRY(area, index, flag)	\
				((void) ddi_dma_sync((area).dma_handle,\
				(index * (area).block_size),	\
				(area).block_size, \
				(flag)))

#define	NEXT_ENTRY(index, wrap)		((index + 1) & wrap)
#define	NEXT_ENTRY_PTR(ptr, first, last)	\
					((ptr == last) ? first : (ptr + 1))

/*
 * NPI related macros
 */
#define	NXGE_DEV_NPI_HANDLE(nxgep)	(nxgep->npi_handle)

#define	NPI_PCI_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_pci_handle.regh = ah)
#define	NPI_PCI_ADD_HANDLE_SET(nxgep, ap) (nxgep->npi_pci_handle.regp = ap)

#define	NPI_ACC_HANDLE_SET(nxgep, ah)	(nxgep->npi_handle.regh = ah)
#define	NPI_ADD_HANDLE_SET(nxgep, ap)	\
		nxgep->npi_handle.is_vraddr = B_FALSE;	\
		nxgep->npi_handle.function.instance = nxgep->instance;   \
		nxgep->npi_handle.function.function = nxgep->function_num;   \
		nxgep->npi_handle.nxgep = (void *) nxgep;   \
		nxgep->npi_handle.regp = ap;

#define	NPI_REG_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_reg_handle.regh = ah)
#define	NPI_REG_ADD_HANDLE_SET(nxgep, ap)	\
		nxgep->npi_reg_handle.is_vraddr = B_FALSE;	\
		nxgep->npi_handle.function.instance = nxgep->instance;   \
		nxgep->npi_handle.function.function = nxgep->function_num;   \
		nxgep->npi_reg_handle.nxgep = (void *) nxgep;   \
		nxgep->npi_reg_handle.regp = ap;

#define	NPI_MSI_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_msi_handle.regh = ah)
#define	NPI_MSI_ADD_HANDLE_SET(nxgep, ap) (nxgep->npi_msi_handle.regp = ap)

#define	NPI_VREG_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_vreg_handle.regh = ah)
#define	NPI_VREG_ADD_HANDLE_SET(nxgep, ap)	\
		nxgep->npi_vreg_handle.is_vraddr = B_TRUE; \
		nxgep->npi_handle.function.instance = nxgep->instance;   \
		nxgep->npi_handle.function.function = nxgep->function_num;   \
		nxgep->npi_vreg_handle.nxgep = (void *) nxgep;   \
		nxgep->npi_vreg_handle.regp = ap;

#define	NPI_V2REG_ACC_HANDLE_SET(nxgep, ah) (nxgep->npi_v2reg_handle.regh = ah)
#define	NPI_V2REG_ADD_HANDLE_SET(nxgep, ap)	\
		nxgep->npi_v2reg_handle.is_vraddr = B_TRUE; \
		nxgep->npi_handle.function.instance = nxgep->instance;   \
		nxgep->npi_handle.function.function = nxgep->function_num;   \
		nxgep->npi_v2reg_handle.nxgep = (void *) nxgep;   \
		nxgep->npi_v2reg_handle.regp = ap;

#define	NPI_PCI_ACC_HANDLE_GET(nxgep) (nxgep->npi_pci_handle.regh)
#define	NPI_PCI_ADD_HANDLE_GET(nxgep) (nxgep->npi_pci_handle.regp)
#define	NPI_ACC_HANDLE_GET(nxgep) (nxgep->npi_handle.regh)
#define	NPI_ADD_HANDLE_GET(nxgep) (nxgep->npi_handle.regp)
#define	NPI_REG_ACC_HANDLE_GET(nxgep) (nxgep->npi_reg_handle.regh)
#define	NPI_REG_ADD_HANDLE_GET(nxgep) (nxgep->npi_reg_handle.regp)
#define	NPI_MSI_ACC_HANDLE_GET(nxgep) (nxgep->npi_msi_handle.regh)
#define	NPI_MSI_ADD_HANDLE_GET(nxgep) (nxgep->npi_msi_handle.regp)
#define	NPI_VREG_ACC_HANDLE_GET(nxgep) (nxgep->npi_vreg_handle.regh)
#define	NPI_VREG_ADD_HANDLE_GET(nxgep) (nxgep->npi_vreg_handle.regp)
#define	NPI_V2REG_ACC_HANDLE_GET(nxgep) (nxgep->npi_v2reg_handle.regh)
#define	NPI_V2REG_ADD_HANDLE_GET(nxgep) (nxgep->npi_v2reg_handle.regp)

#define	NPI_DMA_ACC_HANDLE_SET(dmap, ah) (dmap->npi_handle.regh = ah)
#define	NPI_DMA_ACC_HANDLE_GET(dmap) 	(dmap->npi_handle.regh)

/*
 * DMA handles.
 */
#define	NXGE_DESC_D_HANDLE_GET(desc)	(desc.dma_handle)
#define	NXGE_DESC_D_IOADD_GET(desc)	(desc.dma_cookie.dmac_laddress)
#define	NXGE_DMA_IOADD_GET(dma_cookie) (dma_cookie.dmac_laddress)
#define	NXGE_DMA_AREA_IOADD_GET(dma_area) (dma_area.dma_cookie.dmac_laddress)

#define	LDV_ON(ldv, vector)	((vector >> ldv) & 0x1)
#define	LDV2_ON_1(ldv, vector)	((vector >> (ldv - 64)) & 0x1)
#define	LDV2_ON_2(ldv, vector)	(((vector >> 5) >> (ldv - 64)) & 0x1)

typedef uint32_t		nxge_status_t;

typedef enum  {
	IDLE,
	PROGRESS,
	CONFIGURED
} dev_func_shared_t;

typedef enum  {
	DVMA,
	DMA,
	SDMA
} dma_method_t;

typedef enum  {
	BKSIZE_4K,
	BKSIZE_8K,
	BKSIZE_16K,
	BKSIZE_32K
} nxge_rx_block_size_t;

#ifdef TX_ONE_BUF
#define	TX_BCOPY_MAX 1514
#else
#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
#define	TX_BCOPY_MAX	4096
#define	TX_BCOPY_SIZE	4096
#else
#define	TX_BCOPY_MAX	2048
#define	TX_BCOPY_SIZE	2048
#endif
#endif

#define	TX_STREAM_MIN 512
#define	TX_FASTDVMA_MIN 1024

/*
 * Send repeated FMA ereports or display messages about some non-fatal
 * hardware errors only the the first NXGE_ERROR_SHOW_MAX -1 times
 */
#define	NXGE_ERROR_SHOW_MAX	2


/*
 * Defaults
 */
#define	NXGE_RDC_RCR_THRESHOLD		32
#define	NXGE_RDC_RCR_TIMEOUT		8

#define	NXGE_RDC_RCR_THRESHOLD_MAX	1024
#define	NXGE_RDC_RCR_TIMEOUT_MAX	64
#define	NXGE_RDC_RCR_THRESHOLD_MIN	8
#define	NXGE_RDC_RCR_TIMEOUT_MIN	1
#define	NXGE_RCR_FULL_HEADER		1

#define	NXGE_IS_VLAN_PACKET(ptr)				\
	((((struct ether_vlan_header *)ptr)->ether_tpid) ==	\
	htons(VLAN_ETHERTYPE))

typedef enum {
	NONE,
	SMALL,
	MEDIUM,
	LARGE
} dma_size_t;

typedef enum {
	USE_NONE,
	USE_BCOPY,
	USE_DVMA,
	USE_DMA,
	USE_SDMA
} dma_type_t;

typedef enum {
	NOT_IN_USE,
	HDR_BUF,
	MTU_BUF,
	RE_ASSEMBLY_BUF,
	FREE_BUF
} rx_page_state_t;

struct _nxge_block_mv_t {
	uint32_t msg_type;
	dma_type_t dma_type;
};

typedef struct _nxge_block_mv_t nxge_block_mv_t, *p_nxge_block_mv_t;

typedef enum {
	NIU_TYPE_NONE = 0,

	/* QGC NIC */
	NEPTUNE_4_1GC =
	    (NXGE_PORT_1G_COPPER |
	    (NXGE_PORT_1G_COPPER << 4) |
	    (NXGE_PORT_1G_COPPER << 8) |
	    (NXGE_PORT_1G_COPPER << 12)),

	/* Huron: 2 fiber XAUI cards */
	NEPTUNE_2_10GF =
	    (NXGE_PORT_10G_FIBRE |
	    (NXGE_PORT_10G_FIBRE << 4) |
	    (NXGE_PORT_NONE << 8) |
	    (NXGE_PORT_NONE << 12)),

	/* Huron: port0 is a TN1010 copper XAUI */
	NEPTUNE_1_TN1010 =
	    (NXGE_PORT_TN1010 |
	    (NXGE_PORT_NONE << 4) |
	    (NXGE_PORT_NONE << 8) |
	    (NXGE_PORT_NONE << 12)),

	/* Huron: port1 is a TN1010 copper XAUI */
	NEPTUNE_1_NONE_1_TN1010 =
	    (NXGE_PORT_NONE |
	    (NXGE_PORT_TN1010 << 4) |
	    (NXGE_PORT_NONE << 8) |
	    (NXGE_PORT_NONE << 12)),

	/* Huron: 2 TN1010 copper XAUI cards */
	NEPTUNE_2_TN1010 =
	    (NXGE_PORT_TN1010 |
	    (NXGE_PORT_TN1010 << 4) |
	    (NXGE_PORT_NONE << 8) |
	    (NXGE_PORT_NONE << 12)),

	/* Huron: port0 is fiber XAUI, port1 is copper XAUI */
	NEPTUNE_1_10GF_1_TN1010 =
	    (NXGE_PORT_10G_FIBRE |
	    (NXGE_PORT_TN1010 << 4) |
	    (NXGE_PORT_NONE << 8) |
	    (NXGE_PORT_NONE << 12)),

	/* Huron: port0 is copper XAUI, port1 is fiber XAUI */
	NEPTUNE_1_TN1010_1_10GF =
	    (NXGE_PORT_TN1010 |
	    (NXGE_PORT_10G_FIBRE << 4) |
	    (NXGE_PORT_NONE << 8) |
	    (NXGE_PORT_NONE << 12)),

	/* Maramba: port0 and port1 are fiber XAUIs */
	NEPTUNE_2_10GF_2_1GC =
	    (NXGE_PORT_10G_FIBRE |
	    (NXGE_PORT_10G_FIBRE << 4) |
	    (NXGE_PORT_1G_COPPER << 8) |
	    (NXGE_PORT_1G_COPPER << 12)),

	/* Maramba: port0 and port1 are copper TN1010 XAUIs */
	NEPTUNE_2_TN1010_2_1GC =
	    (NXGE_PORT_TN1010 |
	    (NXGE_PORT_TN1010 << 4) |
	    (NXGE_PORT_1G_COPPER << 8) |
	    (NXGE_PORT_1G_COPPER << 12)),

	/* Maramba: port0 is copper XAUI, port1 is Fiber XAUI */
	NEPTUNE_1_TN1010_1_10GF_2_1GC =
	    (NXGE_PORT_TN1010 |
	    (NXGE_PORT_10G_FIBRE << 4) |
	    (NXGE_PORT_1G_COPPER << 8) |
	    (NXGE_PORT_1G_COPPER << 12)),

	/* Maramba: port0 is fiber XAUI, port1 is copper XAUI */
	NEPTUNE_1_10GF_1_TN1010_2_1GC =
	    (NXGE_PORT_10G_FIBRE |
	    (NXGE_PORT_TN1010 << 4) |
	    (NXGE_PORT_1G_COPPER << 8) |
	    (NXGE_PORT_1G_COPPER << 12)),

	/* Maramba: port0 is fiber XAUI */
	NEPTUNE_1_10GF_3_1GC =
	    (NXGE_PORT_10G_FIBRE |
	    (NXGE_PORT_1G_COPPER << 4) |
	    (NXGE_PORT_1G_COPPER << 8) |
	    (NXGE_PORT_1G_COPPER << 12)),

	/* Maramba: port0 is TN1010 copper XAUI */
	NEPTUNE_1_TN1010_3_1GC =
	    (NXGE_PORT_TN1010 |
	    (NXGE_PORT_1G_COPPER << 4) |
	    (NXGE_PORT_1G_COPPER << 8) |
	    (NXGE_PORT_1G_COPPER << 12)),

	/* Maramba: port1 is fiber XAUI */
	NEPTUNE_1_1GC_1_10GF_2_1GC =
	    (NXGE_PORT_1G_COPPER |
	    (NXGE_PORT_10G_FIBRE << 4) |
	    (NXGE_PORT_1G_COPPER << 8) |
	    (NXGE_PORT_1G_COPPER << 12)),

	/* Maramba: port1 is TN1010 copper XAUI */
	NEPTUNE_1_1GC_1_TN1010_2_1GC =
	    (NXGE_PORT_1G_COPPER |
	    (NXGE_PORT_TN1010 << 4) |
	    (NXGE_PORT_1G_COPPER << 8) |
	    (NXGE_PORT_1G_COPPER << 12)),

	NEPTUNE_2_1GRF =
	    (NXGE_PORT_NONE |
	    (NXGE_PORT_NONE << 4) |
	    (NXGE_PORT_1G_RGMII_FIBER << 8) |
	    (NXGE_PORT_1G_RGMII_FIBER << 12)),

	NEPTUNE_2_10GF_2_1GRF =
	    (NXGE_PORT_10G_FIBRE |
	    (NXGE_PORT_10G_FIBRE << 4) |
	    (NXGE_PORT_1G_RGMII_FIBER << 8) |
	    (NXGE_PORT_1G_RGMII_FIBER << 12)),

	N2_NIU =
	    (NXGE_PORT_RSVD |
	    (NXGE_PORT_RSVD << 4) |
	    (NXGE_PORT_RSVD << 8) |
	    (NXGE_PORT_RSVD << 12))

} niu_type_t;

/*
 * The niu_hw_type is for non-PHY related functions
 * designed on various versions of NIU chips (i.e. RF/NIU has
 * additional classification features and communicates with
 * a different SerDes than N2/NIU).
 */
typedef enum {
	NIU_HW_TYPE_DEFAULT = 0,	/* N2/NIU */
	NIU_HW_TYPE_RF = 1,		/* RF/NIU */
} niu_hw_type_t;

/*
 * P_NEPTUNE_GENERIC:
 *	The cover-all case for Neptune (as opposed to NIU) where we do not
 *	care the exact platform as we do not do anything that is platform
 *	specific.
 * P_NEPTUNE_ATLAS_2PORT:
 *	Dual Port Fiber Neptune based NIC (2XGF)
 * P_NEPTUNE_ATLAS_4PORT:
 *	Quad Port Copper Neptune based NIC (QGC)
 * P_NEPTUNE_NIU:
 *	This is NIU. Could be Huron, Glendale, Monza or any other NIU based
 *	platform.
 */
typedef enum {
	P_NEPTUNE_NONE,
	P_NEPTUNE_GENERIC,
	P_NEPTUNE_ATLAS_2PORT,
	P_NEPTUNE_ATLAS_4PORT,
	P_NEPTUNE_MARAMBA_P0,
	P_NEPTUNE_MARAMBA_P1,
	P_NEPTUNE_ALONSO,
	P_NEPTUNE_ROCK,
	P_NEPTUNE_NIU
} platform_type_t;

#define	NXGE_IS_VALID_NEPTUNE_TYPE(nxgep) \
	(((nxgep->platform_type) == P_NEPTUNE_ATLAS_2PORT) || \
	    ((nxgep->platform_type) == P_NEPTUNE_ATLAS_4PORT) || \
	    ((nxgep->platform_type) == P_NEPTUNE_MARAMBA_P0) || \
	    ((nxgep->platform_type) == P_NEPTUNE_MARAMBA_P1) || \
	    ((nxgep->platform_type) == P_NEPTUNE_GENERIC) || \
	    ((nxgep->platform_type) == P_NEPTUNE_ALONSO) || \
	    ((nxgep->platform_type) == P_NEPTUNE_ROCK))

#define	NXGE_IS_XAUI_PLATFORM(nxgep) \
	(((nxgep->platform_type) == P_NEPTUNE_NIU) || \
	    ((nxgep->platform_type) == P_NEPTUNE_MARAMBA_P0) || \
	    ((nxgep->platform_type) == P_NEPTUNE_MARAMBA_P1))


typedef enum {
	CFG_DEFAULT = 0,	/* default cfg */
	CFG_EQUAL,	/* Equal */
	CFG_FAIR,	/* Equal */
	CFG_CLASSIFY,
	CFG_L2_CLASSIFY,
	CFG_L3_CLASSIFY,
	CFG_L3_DISTRIBUTE,
	CFG_L3_WEB,
	CFG_L3_TCAM,
	CFG_NOT_SPECIFIED,
	CFG_CUSTOM	/* Custom */
} cfg_type_t;

typedef enum {
	NO_MSG = 0x0,		/* No message output or storage. */
	CONSOLE = 0x1,		/* Messages are go to the console. */
	BUFFER = 0x2,		/* Messages are go to the system buffer. */
	CON_BUF = 0x3,		/* Messages are go to the console and */
				/* system buffer. */
	VERBOSE = 0x4		/* Messages are go out only in VERBOSE node. */
} out_msg_t, *p_out_msg_t;

typedef enum {
	DBG_NO_MSG = 0x0,	/* No message output or storage. */
	DBG_CONSOLE = 0x1,	/* Messages are go to the console. */
	DBG_BUFFER = 0x2,	/* Messages are go to the system buffer. */
	DBG_CON_BUF = 0x3,	/* Messages are go to the console and */
				/* system buffer. */
	STR_LOG = 4		/* Sessage sent to streams logging driver. */
} out_dbgmsg_t, *p_out_dbgmsg_t;

typedef enum {
	DDI_MEM_ALLOC,		/* default (use ddi_dma_mem_alloc) */
	KMEM_ALLOC,		/* use kmem_alloc(). */
	CONTIG_MEM_ALLOC	/* use contig_mem_alloc() (N2/NIU only) */
} buf_alloc_type_t;

#define	BUF_ALLOCATED		0x00000001
#define	BUF_ALLOCATED_WAIT_FREE	0x00000002

typedef struct ether_addr ether_addr_st, *p_ether_addr_t;
typedef struct ether_header ether_header_t, *p_ether_header_t;
typedef queue_t *p_queue_t;
typedef mblk_t *p_mblk_t;

/*
 * Generic phy table to support different phy types.
 *
 * The argument for check_link is nxgep, which is passed to check_link
 * as an argument to the timer routine.
 */
typedef struct _nxge_xcvr_table {
	nxge_status_t	(*serdes_init)	();	/* Serdes init routine */
	nxge_status_t	(*xcvr_init)	();	/* xcvr init routine */
	nxge_status_t	(*link_intr_stop) ();	/* Link intr disable routine */
	nxge_status_t	(*link_intr_start) ();	/* Link intr enable routine */
	nxge_status_t	(*check_link) ();	/* Link check routine */

	uint32_t	xcvr_inuse;
} nxge_xcvr_table_t, *p_nxge_xcvr_table_t;

/*
 * Common DMA data elements.
 */
typedef struct _nxge_dma_pool_t nxge_dma_pool_t, *p_nxge_dma_pool_t;

struct _nxge_dma_common_t {
	uint16_t		dma_channel;
	void			*kaddrp;
	void			*last_kaddrp;
	void			*ioaddr_pp;
	void			*first_ioaddr_pp;
	void			*last_ioaddr_pp;
	ddi_dma_cookie_t 	dma_cookie;
	uint32_t		ncookies;

	ddi_dma_handle_t	dma_handle;
	nxge_os_acc_handle_t	acc_handle;
	npi_handle_t		npi_handle;

	size_t			block_size;
	uint32_t		nblocks;
	size_t			alength;
	uint_t			offset;
	uint_t			dma_chunk_index;
	void			*orig_ioaddr_pp;
	uint64_t		orig_vatopa;
	void			*orig_kaddrp;
	size_t			orig_alength;
	boolean_t		contig_alloc_type;
	/*
	 * Receive buffers may be allocated using
	 * kmem_alloc(). The buffer free function
	 * depends on its allocation function.
	 */
	boolean_t		kmem_alloc_type;
	uint32_t		buf_alloc_state;
	buf_alloc_type_t	buf_alloc_type;
	p_nxge_dma_pool_t	rx_buf_pool_p;
};

typedef struct _nxge_t nxge_t, *p_nxge_t;
typedef struct _nxge_dma_common_t nxge_dma_common_t, *p_nxge_dma_common_t;

struct _nxge_dma_pool_t {
	p_nxge_dma_common_t	*dma_buf_pool_p;
	uint32_t		ndmas;
	uint32_t		*num_chunks;
	boolean_t		buf_allocated;
};

/*
 * Each logical device (69):
 *	- LDG #
 *	- flag bits
 *	- masks.
 *	- interrupt handler function.
 *
 * Generic system interrupt handler with two arguments:
 *	(nxge_sys_intr_t)
 *	Per device instance data structure
 *	Logical group data structure.
 *
 * Logical device interrupt handler with two arguments:
 *	(nxge_ldv_intr_t)
 *	Per device instance data structure
 *	Logical device number
 */
typedef struct	_nxge_ldg_t nxge_ldg_t, *p_nxge_ldg_t;
typedef struct	_nxge_ldv_t nxge_ldv_t, *p_nxge_ldv_t;
typedef uint_t	(*nxge_sys_intr_t)(void *arg1, void *arg2);
typedef uint_t	(*nxge_ldv_intr_t)(void *arg1, void *arg2);

/*
 * Each logical device Group (64) needs to have the following
 * configurations:
 *	- timer counter (6 bits)
 *	- timer resolution (20 bits, number of system clocks)
 *	- system data (7 bits)
 */
struct _nxge_ldg_t {
	uint8_t			ldg;		/* logical group number */
	uint8_t			vldg_index;
	boolean_t		arm;
	uint16_t		ldg_timer;	/* counter */
	uint8_t			func;
	uint8_t			vector;
	uint8_t			intdata;
	uint8_t			nldvs;
	p_nxge_ldv_t		ldvp;
	nxge_sys_intr_t		sys_intr_handler;
	p_nxge_t		nxgep;
	uint32_t		htable_idx;
};

struct _nxge_ldv_t {
	uint8_t			ldg_assigned;
	uint8_t			ldv;
	boolean_t		is_rxdma;
	boolean_t		is_txdma;
	boolean_t		is_mif;
	boolean_t		is_mac;
	boolean_t		is_syserr;
	boolean_t		use_timer;
	uint8_t			channel;
	uint8_t			vdma_index;
	uint8_t			func;
	p_nxge_ldg_t		ldgp;
	uint8_t			ldv_flags;
	uint8_t			ldv_ldf_masks;
	nxge_ldv_intr_t		ldv_intr_handler;
	p_nxge_t		nxgep;
};

typedef struct _nxge_logical_page_t {
	uint16_t		dma;
	uint16_t		page;
	boolean_t		valid;
	uint64_t		mask;
	uint64_t		value;
	uint64_t		reloc;
	uint32_t		handle;
} nxge_logical_page_t, *p_nxge_logical_page_t;

/*
 * (Internal) return values from ioctl subroutines.
 */
enum nxge_ioc_reply {
	IOC_INVAL = -1,				/* bad, NAK with EINVAL	*/
	IOC_DONE,				/* OK, reply sent	*/
	IOC_ACK,				/* OK, just send ACK	*/
	IOC_REPLY,				/* OK, just send reply	*/
	IOC_RESTART_ACK,			/* OK, restart & ACK	*/
	IOC_RESTART_REPLY			/* OK, restart & reply	*/
};

typedef struct _pci_cfg_t {
	uint16_t vendorid;
	uint16_t devid;
	uint16_t command;
	uint16_t status;
	uint8_t  revid;
	uint8_t  res0;
	uint16_t junk1;
	uint8_t  cache_line;
	uint8_t  latency;
	uint8_t  header;
	uint8_t  bist;
	uint32_t base;
	uint32_t base14;
	uint32_t base18;
	uint32_t base1c;
	uint32_t base20;
	uint32_t base24;
	uint32_t base28;
	uint32_t base2c;
	uint32_t base30;
	uint32_t res1[2];
	uint8_t int_line;
	uint8_t int_pin;
	uint8_t	min_gnt;
	uint8_t max_lat;
} pci_cfg_t, *p_pci_cfg_t;

typedef struct _dev_regs_t {
	nxge_os_acc_handle_t	nxge_pciregh;	/* PCI config DDI IO handle */
	p_pci_cfg_t		nxge_pciregp;	/* mapped PCI registers */

	nxge_os_acc_handle_t	nxge_regh;	/* device DDI IO (BAR 0) */
	void			*nxge_regp;	/* mapped device registers */

	nxge_os_acc_handle_t	nxge_msix_regh;	/* MSI/X DDI handle (BAR 2) */
	void 			*nxge_msix_regp; /* MSI/X register */

	nxge_os_acc_handle_t	nxge_vir_regh;	/* virtualization (BAR 4) */
	unsigned char		*nxge_vir_regp;	/* virtualization register */

	nxge_os_acc_handle_t	nxge_vir2_regh;	/* second virtualization */
	unsigned char		*nxge_vir2_regp; /* second virtualization */

	nxge_os_acc_handle_t	nxge_romh;	/* fcode rom handle */
	unsigned char		*nxge_romp;	/* fcode pointer */
} dev_regs_t, *p_dev_regs_t;


typedef struct _nxge_mac_addr_t {
	ether_addr_t	addr;
	uint_t		flags;
} nxge_mac_addr_t;

/*
 * The hardware supports 1 unique MAC and 16 alternate MACs (num_mmac)
 * for each XMAC port and supports 1 unique MAC and 7 alternate MACs
 * for each BMAC port.  The number of MACs assigned by the factory is
 * different and is as follows,
 * 	BMAC port:		   num_factory_mmac = num_mmac = 7
 *	XMAC port on a 2-port NIC: num_factory_mmac = num_mmac - 1 = 15
 *	XMAC port on a 4-port NIC: num_factory_mmac = 7
 * So num_factory_mmac is smaller than num_mmac.  nxge_m_mmac_add uses
 * num_mmac and nxge_m_mmac_reserve uses num_factory_mmac.
 *
 * total_factory_macs is the total number of factory MACs, including
 * the unique MAC, assigned to a Neptune based NIC card, it is 32.
 */
typedef struct _nxge_mmac_t {
	uint8_t		total_factory_macs;
	uint8_t		num_mmac;
	uint8_t		num_factory_mmac;
	nxge_mac_addr_t	mac_pool[XMAC_MAX_ADDR_ENTRY];
	ether_addr_t	factory_mac_pool[XMAC_MAX_ADDR_ENTRY];
	uint8_t		naddrfree;  /* number of alt mac addr available */
} nxge_mmac_t;

/*
 * mmac stats structure
 */
typedef struct _nxge_mmac_stats_t {
	uint8_t mmac_max_cnt;
	uint8_t	mmac_avail_cnt;
	struct ether_addr mmac_avail_pool[16];
} nxge_mmac_stats_t, *p_nxge_mmac_stats_t;

/*
 * Copied from mac.h. Should be cleaned up by driver.
 */
#define	MMAC_SLOT_USED		0x1   /* address slot used */
#define	MMAC_VENDOR_ADDR	0x2   /* address returned is vendor supplied */


#define	NXGE_MAX_MMAC_ADDRS	32
#define	NXGE_NUM_MMAC_ADDRS	8
#define	NXGE_NUM_OF_PORTS_QUAD	4
#define	NXGE_NUM_OF_PORTS_DUAL	2

#define	NXGE_QGC_LP_BM_STR		"501-7606"
#define	NXGE_2XGF_LP_BM_STR		"501-7283"
#define	NXGE_QGC_PEM_BM_STR		"501-7765"
#define	NXGE_2XGF_PEM_BM_STR		"501-7626"
#define	NXGE_ALONSO_BM_STR		"373-0202-01"
#define	NXGE_ALONSO_MODEL_STR		"SUNW,CP3220"
#define	NXGE_RFEM_BM_STR		"501-7961-01"
#define	NXGE_RFEM_MODEL_STR		"SUNW,pcie-rfem"
#define	NXGE_ARTM_BM_STR		"375-3544-01"
#define	NXGE_ARTM_MODEL_STR		"SUNW,pcie-artm"
/* ROCK OBP creates a compatible property for ROCK */
#define	NXGE_ROCK_COMPATIBLE		"SUNW,rock-pciex108e,abcd"
#define	NXGE_EROM_LEN			1048576

#include 	<sys/nxge/nxge_common_impl.h>
#include 	<sys/nxge/nxge_common.h>
#include	<sys/nxge/nxge_txc.h>
#include	<sys/nxge/nxge_rxdma.h>
#include	<sys/nxge/nxge_txdma.h>
#include	<sys/nxge/nxge_fflp.h>
#include	<sys/nxge/nxge_ipp.h>
#include	<sys/nxge/nxge_zcp.h>
#include	<sys/nxge/nxge_fzc.h>
#include	<sys/nxge/nxge_flow.h>
#include	<sys/nxge/nxge_virtual.h>

#include	<npi_espc.h>
#include	<npi_vir.h>

#include 	<sys/nxge/nxge.h>

#include	<sys/modctl.h>
#include	<sys/pattr.h>

extern int secpolicy_net_config(const cred_t *, boolean_t);
extern void nxge_fm_report_error(p_nxge_t, uint8_t,
			uint8_t, nxge_fm_ereport_id_t);
extern int fm_check_acc_handle(ddi_acc_handle_t);
extern int fm_check_dma_handle(ddi_dma_handle_t);

/* nxge_classify.c */
nxge_status_t nxge_classify_init(p_nxge_t);
nxge_status_t nxge_classify_uninit(p_nxge_t);
nxge_status_t nxge_set_hw_classify_config(p_nxge_t);
nxge_status_t nxge_classify_exit_sw(p_nxge_t);

/* nxge_fflp.c */
void nxge_put_tcam(p_nxge_t, p_mblk_t);
void nxge_get_tcam(p_nxge_t, p_mblk_t);
nxge_status_t nxge_classify_init_hw(p_nxge_t);
nxge_status_t nxge_classify_init_sw(p_nxge_t);
nxge_status_t nxge_fflp_ip_class_config_all(p_nxge_t);
nxge_status_t nxge_fflp_ip_class_config(p_nxge_t, tcam_class_t,
				    uint32_t);

nxge_status_t nxge_fflp_ip_class_config_get(p_nxge_t,
				    tcam_class_t,
				    uint32_t *);

nxge_status_t nxge_cfg_ip_cls_flow_key(p_nxge_t, tcam_class_t,
				    uint32_t);

nxge_status_t nxge_fflp_ip_usr_class_config(p_nxge_t, tcam_class_t,
				    uint32_t);

uint64_t nxge_classify_get_cfg_value(p_nxge_t, uint8_t, uint8_t);
nxge_status_t nxge_add_flow(p_nxge_t, flow_resource_t *);
nxge_status_t nxge_fflp_config_tcam_enable(p_nxge_t);
nxge_status_t nxge_fflp_config_tcam_disable(p_nxge_t);

nxge_status_t nxge_fflp_config_hash_lookup_enable(p_nxge_t);
nxge_status_t nxge_fflp_config_hash_lookup_disable(p_nxge_t);

nxge_status_t nxge_fflp_config_llc_snap_enable(p_nxge_t);
nxge_status_t nxge_fflp_config_llc_snap_disable(p_nxge_t);

nxge_status_t nxge_logical_mac_assign_rdc_table(p_nxge_t, uint8_t);
nxge_status_t nxge_fflp_config_vlan_table(p_nxge_t, uint16_t);

nxge_status_t nxge_fflp_set_hash1(p_nxge_t, uint32_t);

nxge_status_t nxge_fflp_set_hash2(p_nxge_t, uint16_t);

nxge_status_t nxge_fflp_init_hostinfo(p_nxge_t);

void nxge_handle_tcam_fragment_bug(p_nxge_t);
int nxge_rxclass_ioctl(p_nxge_t, queue_t *, mblk_t *);
int nxge_rxhash_ioctl(p_nxge_t, queue_t *, mblk_t *);

nxge_status_t nxge_fflp_hw_reset(p_nxge_t);
nxge_status_t nxge_fflp_handle_sys_errors(p_nxge_t);
nxge_status_t nxge_zcp_handle_sys_errors(p_nxge_t);

/* nxge_kstats.c */
void nxge_init_statsp(p_nxge_t);
void nxge_setup_kstats(p_nxge_t);
void nxge_setup_rdc_kstats(p_nxge_t, int);
void nxge_setup_tdc_kstats(p_nxge_t, int);
void nxge_destroy_kstats(p_nxge_t);
int nxge_port_kstat_update(kstat_t *, int);
void nxge_save_cntrs(p_nxge_t);

int nxge_m_stat(void *arg, uint_t, uint64_t *);
int nxge_rx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);
int nxge_tx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);

/* nxge_hw.c */
void
nxge_hw_ioctl(p_nxge_t, queue_t *, mblk_t *, struct iocblk *);
void nxge_loopback_ioctl(p_nxge_t, queue_t *, mblk_t *, struct iocblk *);
nxge_status_t nxge_global_reset(p_nxge_t);
uint_t nxge_intr(void *, void *);
void nxge_intr_enable(p_nxge_t);
void nxge_intr_disable(p_nxge_t);
void nxge_hw_blank(void *arg, time_t, uint_t);
void nxge_hw_id_init(p_nxge_t);
void nxge_hw_init_niu_common(p_nxge_t);
void nxge_intr_hw_enable(p_nxge_t);
void nxge_intr_hw_disable(p_nxge_t);
void nxge_hw_stop(p_nxge_t);
void nxge_check_hw_state(p_nxge_t);

void nxge_rxdma_channel_put64(nxge_os_acc_handle_t,
	void *, uint32_t, uint16_t,
	uint64_t);
uint64_t nxge_rxdma_channel_get64(nxge_os_acc_handle_t, void *,
	uint32_t, uint16_t);


void nxge_get32(p_nxge_t, p_mblk_t);
void nxge_put32(p_nxge_t, p_mblk_t);

void nxge_hw_set_mac_modes(p_nxge_t);

/* nxge_send.c. */
uint_t nxge_reschedule(caddr_t);
mblk_t *nxge_tx_ring_send(void *, mblk_t *);
int nxge_start(p_nxge_t, p_tx_ring_t, p_mblk_t);

/* nxge_rxdma.c */
nxge_status_t nxge_rxdma_cfg_rdcgrp_default_rdc(p_nxge_t,
					    uint8_t, uint8_t);

nxge_status_t nxge_rxdma_cfg_port_default_rdc(p_nxge_t,
				    uint8_t, uint8_t);
nxge_status_t nxge_rxdma_cfg_rcr_threshold(p_nxge_t, uint8_t,
				    uint16_t);
nxge_status_t nxge_rxdma_cfg_rcr_timeout(p_nxge_t, uint8_t,
				    uint16_t, uint8_t);

/* nxge_ndd.c */
void nxge_get_param_soft_properties(p_nxge_t);
void nxge_copy_hw_default_to_param(p_nxge_t);
void nxge_copy_param_hw_to_config(p_nxge_t);
void nxge_setup_param(p_nxge_t);
void nxge_init_param(p_nxge_t);
void nxge_destroy_param(p_nxge_t);
boolean_t nxge_check_rxdma_rdcgrp_member(p_nxge_t, uint8_t, uint8_t);
boolean_t nxge_check_rxdma_port_member(p_nxge_t, uint8_t);
boolean_t nxge_check_rdcgrp_port_member(p_nxge_t, uint8_t);

boolean_t nxge_check_txdma_port_member(p_nxge_t, uint8_t);

int nxge_param_get_generic(p_nxge_t, queue_t *, mblk_t *, caddr_t);
int nxge_param_set_generic(p_nxge_t, queue_t *, mblk_t *, char *, caddr_t);
int nxge_get_default(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
int nxge_set_default(p_nxge_t, queue_t *, p_mblk_t, char *, caddr_t);
int nxge_nd_get_names(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
int nxge_mk_mblk_tail_space(p_mblk_t, p_mblk_t *, size_t);
long nxge_strtol(char *, char **, int);
boolean_t nxge_param_get_instance(queue_t *, mblk_t *);
void nxge_param_ioctl(p_nxge_t, queue_t *, mblk_t *, struct iocblk *);
boolean_t nxge_nd_load(caddr_t *, char *, pfi_t, pfi_t, caddr_t);
void nxge_nd_free(caddr_t *);
int nxge_nd_getset(p_nxge_t, queue_t *, caddr_t, p_mblk_t);

nxge_status_t nxge_set_lb_normal(p_nxge_t);
boolean_t nxge_set_lb(p_nxge_t, queue_t *, p_mblk_t);
boolean_t nxge_param_link_update(p_nxge_t);
int nxge_param_set_ip_opt(p_nxge_t, queue_t *, mblk_t *, char *, caddr_t);
int nxge_dld_get_ip_opt(p_nxge_t, caddr_t);
int nxge_param_rx_intr_pkts(p_nxge_t, queue_t *,
	mblk_t *, char *, caddr_t);
int nxge_param_rx_intr_time(p_nxge_t, queue_t *,
	mblk_t *, char *, caddr_t);


/* nxge_virtual.c */
nxge_status_t nxge_cntlops(dev_info_t *, nxge_ctl_enum_t, void *, void *);
void nxge_common_lock_get(p_nxge_t);
void nxge_common_lock_free(p_nxge_t);

nxge_status_t nxge_get_config_properties(p_nxge_t);
void nxge_get_xcvr_properties(p_nxge_t);
void nxge_init_vlan_config(p_nxge_t);
void nxge_init_mac_config(p_nxge_t);


void nxge_init_logical_devs(p_nxge_t);
int nxge_init_ldg_intrs(p_nxge_t);

void nxge_set_ldgimgmt(p_nxge_t, uint32_t, boolean_t,
	uint32_t);

void nxge_init_fzc_txdma_channels(p_nxge_t);

nxge_status_t nxge_init_fzc_txdma_channel(p_nxge_t, uint16_t,
	p_tx_ring_t, p_tx_mbox_t);
nxge_status_t nxge_init_fzc_txdma_port(p_nxge_t);

nxge_status_t nxge_init_fzc_rxdma_channel(p_nxge_t, uint16_t);

nxge_status_t nxge_init_fzc_rx_common(p_nxge_t);
nxge_status_t nxge_init_fzc_rxdma_port(p_nxge_t);

nxge_status_t nxge_init_fzc_rxdma_channel_pages(p_nxge_t,
	uint16_t, p_rx_rbr_ring_t);
nxge_status_t nxge_init_fzc_rxdma_channel_red(p_nxge_t,
	uint16_t, p_rx_rcr_ring_t);

nxge_status_t nxge_init_fzc_rxdma_channel_clrlog(p_nxge_t,
	uint16_t, p_rx_rbr_ring_t);


nxge_status_t nxge_init_fzc_txdma_channel_pages(p_nxge_t,
	uint16_t, p_tx_ring_t);

nxge_status_t nxge_init_fzc_txdma_channel_drr(p_nxge_t, uint16_t,
	p_tx_ring_t);

nxge_status_t nxge_init_fzc_txdma_port(p_nxge_t);

void nxge_init_fzc_ldg_num(p_nxge_t);
void nxge_init_fzc_sys_int_data(p_nxge_t);
void nxge_init_fzc_ldg_int_timer(p_nxge_t);
nxge_status_t nxge_intr_mask_mgmt_set(p_nxge_t, boolean_t on);

/* MAC functions */
nxge_status_t nxge_mac_init(p_nxge_t);
nxge_status_t nxge_link_init(p_nxge_t);
nxge_status_t nxge_xif_init(p_nxge_t);
nxge_status_t nxge_pcs_init(p_nxge_t);
nxge_status_t nxge_mac_ctrl_init(p_nxge_t);
nxge_status_t nxge_serdes_init(p_nxge_t);
nxge_status_t nxge_serdes_reset(p_nxge_t);
nxge_status_t nxge_xcvr_find(p_nxge_t);
nxge_status_t nxge_get_xcvr_type(p_nxge_t);
nxge_status_t nxge_setup_xcvr_table(p_nxge_t);
nxge_status_t nxge_xcvr_init(p_nxge_t);
nxge_status_t nxge_tx_mac_init(p_nxge_t);
nxge_status_t nxge_rx_mac_init(p_nxge_t);
nxge_status_t nxge_tx_mac_enable(p_nxge_t);
nxge_status_t nxge_tx_mac_disable(p_nxge_t);
nxge_status_t nxge_rx_mac_enable(p_nxge_t);
nxge_status_t nxge_rx_mac_disable(p_nxge_t);
nxge_status_t nxge_tx_mac_reset(p_nxge_t);
nxge_status_t nxge_rx_mac_reset(p_nxge_t);
nxge_status_t nxge_link_intr(p_nxge_t, link_intr_enable_t);
nxge_status_t nxge_mii_xcvr_init(p_nxge_t);
nxge_status_t nxge_mii_xcvr_fiber_init(p_nxge_t);
nxge_status_t nxge_mii_read(p_nxge_t, uint8_t,
			uint8_t, uint16_t *);
nxge_status_t nxge_mii_write(p_nxge_t, uint8_t,
			uint8_t, uint16_t);
nxge_status_t nxge_mdio_read(p_nxge_t, uint8_t, uint8_t,
			uint16_t, uint16_t *);
nxge_status_t nxge_mdio_write(p_nxge_t, uint8_t,
			uint8_t, uint16_t, uint16_t);
nxge_status_t nxge_mii_check(p_nxge_t, mii_bmsr_t,
			mii_bmsr_t, nxge_link_state_t *);
void nxge_pcs_check(p_nxge_t, uint8_t portn, nxge_link_state_t *);
nxge_status_t nxge_add_mcast_addr(p_nxge_t, struct ether_addr *);
nxge_status_t nxge_del_mcast_addr(p_nxge_t, struct ether_addr *);
nxge_status_t nxge_set_mac_addr(p_nxge_t, struct ether_addr *);
nxge_status_t nxge_check_bcm8704_link(p_nxge_t, boolean_t *);
nxge_status_t nxge_check_tn1010_link(p_nxge_t);
void nxge_link_is_down(p_nxge_t);
void nxge_link_is_up(p_nxge_t);
nxge_status_t nxge_link_monitor(p_nxge_t, link_mon_enable_t);
uint32_t crc32_mchash(p_ether_addr_t);
nxge_status_t nxge_set_promisc(p_nxge_t, boolean_t);
nxge_status_t nxge_mac_handle_sys_errors(p_nxge_t);
nxge_status_t nxge_10g_link_led_on(p_nxge_t);
nxge_status_t nxge_10g_link_led_off(p_nxge_t);
nxge_status_t nxge_scan_ports_phy(p_nxge_t, p_nxge_hw_list_t);
boolean_t nxge_is_valid_local_mac(ether_addr_st);
nxge_status_t nxge_mac_set_framesize(p_nxge_t);

/* espc (sprom) prototypes */
nxge_status_t nxge_espc_mac_addrs_get(p_nxge_t);
nxge_status_t nxge_espc_num_macs_get(p_nxge_t, uint8_t *);
nxge_status_t nxge_espc_num_ports_get(p_nxge_t);
nxge_status_t nxge_espc_phy_type_get(p_nxge_t);
nxge_status_t nxge_espc_verify_chksum(p_nxge_t);
void nxge_espc_get_next_mac_addr(uint8_t *, uint8_t, struct ether_addr *);
void nxge_vpd_info_get(p_nxge_t);


void nxge_debug_msg(p_nxge_t, uint64_t, char *, ...);
int nxge_get_nports(p_nxge_t);

void nxge_free_buf(buf_alloc_type_t, uint64_t, uint32_t);

#if defined(sun4v)

uint64_t hv_niu_rx_logical_page_conf(uint64_t, uint64_t,
	uint64_t, uint64_t);
#pragma weak	hv_niu_rx_logical_page_conf

uint64_t hv_niu_rx_logical_page_info(uint64_t, uint64_t,
	uint64_t *, uint64_t *);
#pragma weak	hv_niu_rx_logical_page_info

uint64_t hv_niu_tx_logical_page_conf(uint64_t, uint64_t,
	uint64_t, uint64_t);
#pragma weak	hv_niu_tx_logical_page_conf

uint64_t hv_niu_tx_logical_page_info(uint64_t, uint64_t,
	uint64_t *, uint64_t *);
#pragma weak	hv_niu_tx_logical_page_info

uint64_t hv_niu_vr_assign(uint64_t vridx, uint64_t ldc_id, uint32_t *cookie);
#pragma weak	hv_niu_vr_assign

uint64_t hv_niu_vr_unassign(uint32_t cookie);
#pragma weak	hv_niu_vr_unassign

uint64_t hv_niu_vr_getinfo(uint32_t cookie, uint64_t *real_start,
    uint64_t *size);
#pragma weak	hv_niu_vr_getinfo

uint64_t hv_niu_vr_get_rxmap(uint32_t cookie, uint64_t *dma_map);
#pragma weak	hv_niu_vr_get_rxmap

uint64_t hv_niu_vr_get_txmap(uint32_t cookie, uint64_t *dma_map);
#pragma weak	hv_niu_vr_get_txmap

uint64_t hv_niu_rx_dma_assign(uint32_t cookie, uint64_t chidx,
    uint64_t *vchidx);
#pragma weak	hv_niu_rx_dma_assign

uint64_t hv_niu_rx_dma_unassign(uint32_t cookie, uint64_t chidx);
#pragma weak	hv_niu_rx_dma_unassign

uint64_t hv_niu_tx_dma_assign(uint32_t cookie, uint64_t chidx,
    uint64_t *vchidx);
#pragma weak	hv_niu_tx_dma_assign

uint64_t hv_niu_tx_dma_unassign(uint32_t cookie, uint64_t chidx);
#pragma weak	hv_niu_tx_dma_unassign

uint64_t hv_niu_vrrx_logical_page_conf(uint32_t cookie, uint64_t chidx,
    uint64_t pgidx, uint64_t raddr, uint64_t size);
#pragma weak	hv_niu_vrrx_logical_page_conf

uint64_t hv_niu_vrrx_logical_page_info(uint32_t cookie, uint64_t chidx,
    uint64_t pgidx, uint64_t *raddr, uint64_t *size);
#pragma weak	hv_niu_vrrx_logical_page_info

uint64_t hv_niu_vrtx_logical_page_conf(uint32_t cookie, uint64_t chidx,
    uint64_t pgidx, uint64_t raddr, uint64_t size);
#pragma weak	hv_niu_vrtx_logical_page_conf

uint64_t hv_niu_vrtx_logical_page_info(uint32_t cookie, uint64_t chidx,
    uint64_t pgidx, uint64_t *raddr, uint64_t *size);
#pragma weak	hv_niu_vrtx_logical_page_info

uint64_t hv_niu_cfgh_rx_logical_page_conf(uint64_t, uint64_t, uint64_t,
	uint64_t, uint64_t);
#pragma weak	hv_niu_cfgh_rx_logical_page_conf

uint64_t hv_niu_cfgh_rx_logical_page_info(uint64_t, uint64_t, uint64_t,
	uint64_t *, uint64_t *);
#pragma weak	hv_niu_cfgh_rx_logical_page_info

uint64_t hv_niu_cfgh_tx_logical_page_conf(uint64_t, uint64_t, uint64_t,
	uint64_t, uint64_t);
#pragma weak	hv_niu_cfgh_tx_logical_page_conf

uint64_t hv_niu_cfgh_tx_logical_page_info(uint64_t, uint64_t, uint64_t,
	uint64_t *, uint64_t *);
#pragma weak	hv_niu_cfgh_tx_logical_page_info

uint64_t hv_niu_cfgh_vr_assign(uint64_t, uint64_t vridx, uint64_t ldc_id,
	uint32_t *cookie);
#pragma weak	hv_niu_cfgh_vr_assign

//
// NIU-specific interrupt API
//
uint64_t hv_niu_vrrx_getinfo(uint32_t cookie, uint64_t v_chidx,
    uint64_t *group, uint64_t *logdev);
#pragma weak	hv_niu_vrrx_getinfo

uint64_t hv_niu_vrtx_getinfo(uint32_t cookie, uint64_t v_chidx,
    uint64_t *group, uint64_t *logdev);
#pragma weak	hv_niu_vrtx_getinfo

uint64_t hv_niu_vrrx_to_logical_dev(uint32_t cookie, uint64_t v_chidx,
    uint64_t *ldn);
#pragma weak	hv_niu_vrrx_to_logical_dev

uint64_t hv_niu_vrtx_to_logical_dev(uint32_t cookie, uint64_t v_chidx,
    uint64_t *ldn);
#pragma weak	hv_niu_vrtx_to_logical_dev

#endif /* defined(sun4v) */

#ifdef NXGE_DEBUG
char *nxge_dump_packet(char *, int);
#endif

#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_IMPL_H */
