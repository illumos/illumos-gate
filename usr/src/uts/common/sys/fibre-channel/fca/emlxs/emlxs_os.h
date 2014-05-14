/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_OS_H
#define	_EMLXS_OS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	EMLXS_MODREV2    2	/* Old Solaris 8 & 9 interface */
#define	EMLXS_MODREV3    3	/* New Solaris 10 & 11 interface */
#define	EMLXS_MODREV4    4	/* Sun FC packet change */
				/* Symbolic Node Name interface */
#define	EMLXS_MODREV5    5	/* New Sun NPIV Interface */

#define	EMLXS_MODREV2X   2	/* Old Solaris 8 & 9 x86 interface */
#define	EMLXS_MODREV3X   3	/* New Solaris 10 & 11 x86 interface */


/*
 * DRIVER LEVEL FEATURES
 */
#define	DHCHAP_SUPPORT		/* 2.21 driver */

#define	SATURN_MSI_SUPPORT	/* 2.30 driver */
#define	MENLO_SUPPORT		/* 2.30 driver */
#define	MBOX_EXT_SUPPORT	/* 2.30 driver */

#define	DUMP_SUPPORT		/* 2.40 driver */
#define	SAN_DIAG_SUPPORT	/* 2.40 driver */
#define	FMA_SUPPORT		/* 2.40 driver */

#define	NODE_THROTTLE_SUPPORT	/* 2.70 driver */

/* #define	IDLE_TIMER	 Not yet - untested */

/*
 * OS LEVEL FEATURES
 */


#ifdef S11
#define	MSI_SUPPORT
#define	SFCT_SUPPORT  /* COMSTAR Support */
#define	MODFW_SUPPORT /* Dynamic firmware module support */
#define	EMLXS_MODREV EMLXS_MODREV5 /* Sun NPIV Enhancement */

#ifdef EMLXS_I386
#define	EMLXS_MODREVX EMLXS_MODREV2X
#endif /* i386 */
#endif /* S11 */

/*
 * SUBFEATURES
 */
#ifdef SFCT_SUPPORT
#define	MODSYM_SUPPORT		/* Dynamic Module Loading Support */
#define	FCIO_SUPPORT		/* FCIO IOCTL support */
#endif /* SFCT_SUPPORT */


#ifndef EMLXS_MODREV
#define	EMLXS_MODREV			0
#endif /* EMLXS_MODREV */

#ifndef EMLXS_MODREVX
#define	EMLXS_MODREVX			0
#endif /* EMLXS_MODREVX */

/* Create combined definition */
#if defined(S10) || defined(S11)
#define	S10S11
#endif /* S10 or S11 */

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/devops.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/fcntl.h>

#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/kmem.h>

#include <sys/errno.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/thread.h>
#include <sys/taskq.h>
#include <sys/debug.h>
#include <sys/cpu.h>
#include <sys/autoconf.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/var.h>

#include <sys/map.h>
#include <sys/file.h>
#include <sys/syslog.h>
#include <sys/disp.h>
#include <sys/taskq.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/ethernet.h>
#include <vm/seg_kmem.h>
#include <sys/utsname.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/varargs.h>
#include <sys/atomic.h>
#ifdef S11
#include <sys/pci.h>
#include <sys/pcie.h>
#else	/* !S11 */
/*
 * Capabilities linked list entry offsets
 */
#define	PCI_CAP_ID		0x0	/* capability identifier, 1 byte */
#define	PCI_CAP_NEXT_PTR	0x1	/* next entry pointer, 1 byte */
#define	PCI_CAP_ID_REGS_OFF	0x2	/* cap id register offset */
#define	PCI_CAP_MAX_PTR		0x30	/* maximum number of cap pointers */
#define	PCI_CAP_PTR_OFF		0x40	/* minimum cap pointer offset */
#define	PCI_CAP_PTR_MASK	0xFC	/* mask for capability pointer */

/*
 * Capability identifier values
 */
#define	PCI_CAP_ID_PM		0x1	/* power management entry */
#define	PCI_CAP_ID_AGP		0x2	/* AGP supported */
#define	PCI_CAP_ID_VPD		0x3	/* VPD supported */
#define	PCI_CAP_ID_SLOT_ID	0x4	/* Slot Identification supported */
#define	PCI_CAP_ID_MSI		0x5	/* MSI supported */
#define	PCI_CAP_ID_cPCI_HS	0x6	/* CompactPCI Host Swap supported */
#define	PCI_CAP_ID_PCIX		0x7	/* PCI-X supported */
#define	PCI_CAP_ID_HT		0x8	/* HyperTransport supported */
#define	PCI_CAP_ID_VS		0x9	/* Vendor Specific */
#define	PCI_CAP_ID_DEBUG_PORT	0xA	/* Debug Port supported */
#define	PCI_CAP_ID_cPCI_CRC	0xB	/* CompactPCI central resource ctrl */
#define	PCI_CAP_ID_PCI_HOTPLUG	0xC	/* PCI Hot Plug supported */
#define	PCI_CAP_ID_P2P_SUBSYS	0xD	/* PCI bridge Sub-system ID */
#define	PCI_CAP_ID_AGP_8X	0xE	/* AGP 8X supported */
#define	PCI_CAP_ID_SECURE_DEV	0xF	/* Secure Device supported */
#define	PCI_CAP_ID_PCI_E	0x10	/* PCI Express supported */
#define	PCI_CAP_ID_MSI_X	0x11	/* MSI-X supported */
#define	PCI_CAP_ID_SATA		0x12	/* SATA Data/Index Config supported */
#define	PCI_CAP_ID_FLR		0x13	/* Function Level Reset supported */

/*
 * PCI power management (PM) capability entry offsets
 */
#define	PCI_PMCAP		0x2	/* PM capabilities, 2 bytes */
#define	PCI_PMCSR		0x4	/* PM control/status reg, 2 bytes */
#define	PCI_PMCSR_BSE		0x6	/* PCI-PCI bridge extensions, 1 byte */
#define	PCI_PMDATA		0x7	/* PM data, 1 byte */

/*
 * PM control/status values - 2 bytes
 */
#define	PCI_PMCSR_D0			0x0	/* power state D0 */
#define	PCI_PMCSR_D1			0x1	/* power state D1 */
#define	PCI_PMCSR_D2			0x2	/* power state D2 */
#define	PCI_PMCSR_D3HOT			0x3	/* power state D3hot */


/*
 * PCI Express capability registers in PCI configuration space relative to
 * the PCI Express Capability structure.
 */
#define	PCIE_CAP_ID			PCI_CAP_ID
#define	PCIE_CAP_NEXT_PTR		PCI_CAP_NEXT_PTR
#define	PCIE_PCIECAP			0x02	/* PCI-e Capability Reg */
#define	PCIE_DEVCAP			0x04	/* Device Capability */
#define	PCIE_DEVCTL			0x08	/* Device Control */
#define	PCIE_DEVSTS			0x0A	/* Device Status */
#define	PCIE_LINKCAP			0x0C	/* Link Capability */
#define	PCIE_LINKCTL			0x10	/* Link Control */
#define	PCIE_LINKSTS			0x12	/* Link Status */
#define	PCIE_SLOTCAP			0x14	/* Slot Capability */
#define	PCIE_SLOTCTL			0x18	/* Slot Control */
#define	PCIE_SLOTSTS			0x1A	/* Slot Status */
#define	PCIE_ROOTCTL			0x1C	/* Root Control */
#define	PCIE_ROOTSTS			0x20	/* Root Status */

/*
 * PCI-Express Enhanced Capabilities Link Entry Bit Offsets
 */
#define	PCIE_EXT_CAP			0x100	/* Base Address of Ext Cap */

#define	PCIE_EXT_CAP_ID_SHIFT		0	/* PCI-e Ext Cap ID */
#define	PCIE_EXT_CAP_ID_MASK		0xFFFF
#define	PCIE_EXT_CAP_VER_SHIFT		16	/* PCI-e Ext Cap Ver */
#define	PCIE_EXT_CAP_VER_MASK		0xF
#define	PCIE_EXT_CAP_NEXT_PTR_SHIFT	20	/* PCI-e Ext Cap Next Ptr */
#define	PCIE_EXT_CAP_NEXT_PTR_MASK	0xFFF

#define	PCIE_EXT_CAP_NEXT_PTR_NULL	0x0

/*
 * PCI-Express Enhanced Capability Identifier Values
 */
#define	PCIE_EXT_CAP_ID_AER		0x1	/* Advanced Error Handling */
#define	PCIE_EXT_CAP_ID_VC		0x2	/* Virtual Channel, no MFVC */
#define	PCIE_EXT_CAP_ID_SER		0x3	/* Serial Number */
#define	PCIE_EXT_CAP_ID_PWR_BUDGET	0x4	/* Power Budgeting */
#define	PCIE_EXT_CAP_ID_RC_LINK_DECL	0x5	/* RC Link Declaration */
#define	PCIE_EXT_CAP_ID_RC_INT_LINKCTRL	0x6	/* RC Internal Link Control */
#define	PCIE_EXT_CAP_ID_RC_EVNT_CEA	0x7	/* RC Event Collector */
						/* Endpoint Association */
#define	PCIE_EXT_CAP_ID_MFVC		0x8	/* Multi-func Virtual Channel */
#define	PCIE_EXT_CAP_ID_VC_WITH_MFVC	0x9	/* Virtual Channel w/ MFVC */
#define	PCIE_EXT_CAP_ID_RCRB		0xA	/* Root Complex Register Blck */
#define	PCIE_EXT_CAP_ID_VS		0xB	/* Vendor Spec Extended Cap */
#define	PCIE_EXT_CAP_ID_CAC		0xC	/* Config Access Correlation */
#define	PCIE_EXT_CAP_ID_ACS		0xD	/* Access Control Services */
#define	PCIE_EXT_CAP_ID_ARI		0xE	/* Alternative Routing ID */
#define	PCIE_EXT_CAP_ID_ATS		0xF	/* Address Translation Svcs */
#endif	/* S11 */

#include <emlxs_hbaapi.h>

#ifdef FMA_SUPPORT
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#endif	/* FMA_SUPPORT */
#include <sys/fm/io/ddi.h>

#ifdef S11

/* ULP header files */
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>

#else	/* !S11 */

/* ULP header files */
#include <sys/fibre-channel/fcio.h>
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/fc_appif.h>
#include <sys/fibre-channel/fc_types.h>
#include <sys/fibre-channel/impl/fc_error.h>
#include <sys/fibre-channel/impl/fc_fla.h>
#include <sys/fibre-channel/impl/fc_linkapp.h>
#include <sys/fibre-channel/impl/fcal.h>
#include <sys/fibre-channel/impl/fcgs2.h>
#include <sys/fibre-channel/impl/fcph.h>
#include <sys/fibre-channel/impl/fc_ulpif.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>
#include <sys/fibre-channel/impl/fctl.h>
#include <sys/fibre-channel/impl/fctl_private.h>
#include <sys/fibre-channel/ulp/fcp.h>
#include <sys/fibre-channel/ulp/fcp_util.h>

#endif	/* S11 */

#ifndef FC_HBA_PORTSPEED_8GBIT
#define	FC_HBA_PORTSPEED_8GBIT		16
#endif	/* FC_HBA_PORTSPEED_8GBIT */

#ifndef FP_DEFAULT_SID
#define	FP_DEFAULT_SID		(0x000AE)
#endif	/* FP_DEFAULT_SID */

#ifndef FP_DEFAULT_DID
#define	FP_DEFAULT_DID		(0x000EA)
#endif	/* FP_DEFAULT_DID */

#ifdef MSI_SUPPORT
#pragma weak ddi_intr_get_supported_types
#pragma weak ddi_intr_get_nintrs
#pragma weak ddi_intr_add_handler
#pragma weak ddi_intr_remove_handler
#pragma weak ddi_intr_get_hilevel_pri
#pragma weak ddi_intr_enable
#pragma weak ddi_intr_disable
#pragma weak ddi_intr_get_cap
#pragma weak ddi_intr_get_pri
#pragma weak ddi_intr_alloc
#pragma weak ddi_intr_free
#pragma weak ddi_intr_block_enable
#pragma weak ddi_intr_block_disable
extern int ddi_intr_get_supported_types();
#endif	/* MSI_SUPPORT */

#ifndef MODSYM_SUPPORT
#pragma weak fc_fca_init
#pragma weak fc_fca_attach
#pragma weak fc_fca_detach
#endif /* MODSYM_SUPPORT */

/* S11 flag for dma_attr_flags for ddi_dma_attr_t */
#ifndef DDI_DMA_RELAXED_ORDERING
#define	DDI_DMA_RELAXED_ORDERING	0x400
#endif	/* DDI_DMA_RELAXED_ORDERING */

#ifdef FMA_SUPPORT
/* FMA Support */
#pragma weak ddi_fm_acc_err_clear
extern void ddi_fm_acc_err_clear();
#endif	/* FMA_SUPPORT */

#ifdef EMLXS_SPARC
#define	EMLXS_BIG_ENDIAN
#endif	/* EMLXS_SPARC */

#ifdef EMLXS_I386
#define	EMLXS_LITTLE_ENDIAN
#endif	/* EMLXS_I386 */


/* Solaris 8 does not define this */
#ifndef TASKQ_DYNAMIC
#define	TASKQ_DYNAMIC	0x0004
#endif	/* TASKQ_DYNAMIC */

#ifdef _LP64
#define	DEAD_PTR   0xdeadbeefdeadbeef
#else
#define	DEAD_PTR   0xdeadbeef
#endif	/* _LP64 */

#ifndef FC_STATE_8GBIT_SPEED
/* This was obtained from OpenSolaris */
#define	FC_STATE_8GBIT_SPEED		0x0700	/* 8 Gbit/sec */
#endif	/* FC_STATE_8GBIT_SPEED */

#define	FC_STATE_QUAD_SPEED		0x0500

#ifndef BURSTSIZE
#define	BURSTSIZE
#define	BURST1			0x01
#define	BURST2			0x02
#define	BURST4			0x04
#define	BURST8			0x08
#define	BURST16			0x10
#define	BURST32			0x20
#define	BURST64			0x40
#ifdef _LP64
#define	BURSTSIZE_MASK		0x7f
#else
#define	BURSTSIZE_MASK		0x3f
#endif	/* _LP64 */
#define	DEFAULT_BURSTSIZE	(BURSTSIZE_MASK)	/* all burst sizes */
#endif	/* BURSTSIZE */

#define	PADDR_LO(addr)		((uint32_t)(((uint64_t)(addr)) & 0xffffffff))
#define	PADDR_HI(addr)		((uint32_t)(((uint64_t)(addr)) >> 32))
#define	PADDR(high, low)	((uint64_t)((((uint64_t)(high)) << 32) \
					| (((uint64_t)(low)) & 0xffffffff)))

#ifndef TRUE
#define	TRUE	1
#endif	/* TRUE */

#ifndef FALSE
#define	FALSE	0
#endif	/* FALSE */

#define	DMA_READ_WRITE		0
#define	DMA_READ_ONLY		1
#define	DMA_WRITE_ONLY		2

#define	DMA_SUCC		1

#define	MAX_FC_BRDS		256	/* Maximum # boards per system */

#define	BUSYWAIT_MS(ms)		drv_usecwait((ms*1000))
#define	BUSYWAIT_US(us)		drv_usecwait(us)

#define	EMLXS_MPDATA_SYNC(h, a, b, c)  \
	if (h)  { \
		(void) ddi_dma_sync((ddi_dma_handle_t)(h), \
			(off_t)(a), (size_t)(b), (uint_t)c); \
	}

#define	PKT2PRIV(pkt)		((emlxs_buf_t *)(pkt)->pkt_fca_private)
#define	PRIV2PKT(sbp)		sbp->pkt

#define	EMLXS_INUMBER		0
#define	EMLXS_MSI_INUMBER 	0

#define	EMLXS_DMA_ALIGN		BURST16

/*
 * Register indices in PCI configuration space.
 */
#define	SBUS_FLASH_RD			0	/* FCODE-Flash Read only */
						/* index */
#define	SBUS_FLASH_RDWR			1	/* FCODE-Flash Read/Write */
						/* index */
#define	SBUS_DFLY_SLIM_RINDEX	  2	/* DragonFly SLIM regs index */
#define	SBUS_DFLY_CSR_RINDEX	  3	/* DragonFly I/O regs index */
#define	SBUS_TITAN_CORE_RINDEX	  4	/* TITAN Core register index */
#define	SBUS_DFLY_PCI_CFG_RINDEX	5	/* DragonFly PCI ConfigSpace */
						/* regs index */
#define	SBUS_TITAN_PCI_CFG_RINDEX	6	/* TITAN PCI ConfigSpace regs */
						/* index */
#define	SBUS_TITAN_CSR_RINDEX		7	/* TITAN Control/Status regs */
						/* index */

#define	PCI_CFG_RINDEX		  0
#define	PCI_SLIM_RINDEX		  1
#define	PCI_CSR_RINDEX		  2

#define	PCI_BAR0_RINDEX		  1
#define	PCI_BAR1_RINDEX		  2
#define	PCI_BAR2_RINDEX		  3


#define	EMLXS_MAX_UBUFS		65535

/* Tokens < EMLXS_UB_TOKEN_OFFSET are reserved for ELS response oxids */
#define	EMLXS_UB_TOKEN_OFFSET	0x100

typedef struct emlxs_ub_priv
{
	fc_unsol_buf_t	*ubp;
	void		*port;

	uint32_t	bpl_size;
	uint8_t		*bpl_virt;	/* virtual address ptr */
	uint64_t	bpl_phys;	/* mapped address */
	void		*bpl_data_handle;
	void		*bpl_dma_handle;

	uint32_t	ip_ub_size;
	uint8_t		*ip_ub_virt;	/* virtual address ptr */
	ddi_dma_cookie_t ip_ub_dma_cookies[64];
	ddi_acc_handle_t ip_ub_data_handle;
	ddi_dma_handle_t ip_ub_dma_handle;
	uint32_t	ip_ub_cookie_cnt;
	uint32_t	FC4type;

	uint16_t	flags;
#define	EMLXS_UB_FREE		0x0000
#define	EMLXS_UB_IN_USE		0x0001
#define	EMLXS_UB_REPLY		0x0002
#define	EMLXS_UB_RESV		0x0004
#define	EMLXS_UB_TIMEOUT	0x0008
#define	EMLXS_UB_INTERCEPT	0x0010

	uint16_t	available;

	uint32_t	timeout;	/* Timeout period in seconds */
	uint32_t	time;	/* EMLXS_UB_IN_USE timestamp */
	uint32_t	cmd;
	uint32_t	token;

	struct emlxs_unsol_buf *pool;
	struct emlxs_ub_priv *next;
} emlxs_ub_priv_t;


typedef struct emlxs_unsol_buf
{
	struct emlxs_unsol_buf	*pool_prev;		/* ptr to prev type */
							/* of unsol_buf hdr */
	struct emlxs_unsol_buf	*pool_next;		/* ptr to next type */
							/* of unsol_buf hdr */

	uint32_t		pool_type;		/* FC-4 type */
	uint32_t		pool_buf_size;		/* buffer size for */
							/* this pool */

	uint32_t		pool_nentries;		/* no. of bufs in */
							/* pool */
	uint32_t		pool_available;		/* no. of bufs avail */
							/* in pool */

	uint32_t		pool_flags;
#define	POOL_DESTROY		0x00000001		/* Pool is marked for */
							/* destruction */

	uint32_t		pool_free;		/* Number of free */
							/* buffers */
	uint32_t		pool_free_resv;		/* Number of free */
							/* reserved buffers */

	uint32_t		pool_first_token;	/* First token */
							/* in pool */
	uint32_t		pool_last_token;	/* Last token */
							/* in pool */

	fc_unsol_buf_t		*fc_ubufs;		/* array of unsol buf */
							/* structs */
} emlxs_unsol_buf_t;


#ifndef FC_REASON_NONE
#define	FC_REASON_NONE			0
#endif /* FC_REASON_NONE */

#ifndef FC_ACTION_NONE
#define	FC_ACTION_NONE			0
#endif /* FC_ACTION_NONE */

/*
 * emlx status translation table
 */
typedef struct emlxs_xlat_err
{
	uint32_t	emlxs_status;
	uint32_t	pkt_state;
	uint32_t	pkt_reason;
	uint32_t	pkt_expln;
	uint32_t	pkt_action;
} emlxs_xlat_err_t;


typedef struct emlxs_table
{
	uint32_t	code;
	char		string[48];
} emlxs_table_t;


/* PATCH MASK DEFINES */
#define	EMLXS_PATCH1		0x00000001
#define	EMLXS_PATCH2		0x00000002
#define	EMLXS_PATCH3		0x00000004
#define	EMLXS_PATCH4		0x00000008
#define	EMLXS_PATCH5		0x00000010
#define	EMLXS_PATCH6		0x00000020
#define	EMLXS_PATCH7		0x00000040
#define	EMLXS_PATCH8		0x00000080
#define	EMLXS_PATCH9		0x00000100
#define	EMLXS_PATCH10		0x00000200
#define	EMLXS_PATCH11		0x00000400
#define	EMLXS_PATCH12		0x00000800
#define	EMLXS_PATCH13		0x00001000
#define	EMLXS_PATCH14		0x00002000
#define	EMLXS_PATCH15		0x00004000
#define	EMLXS_PATCH16		0x00008000
#define	EMLXS_PATCH17		0x00010000
#define	EMLXS_PATCH18		0x00020000
#define	EMLXS_PATCH19		0x00040000
#define	EMLXS_PATCH20		0x00080000
#define	EMLXS_PATCH21		0x00100000
#define	EMLXS_PATCH22		0x00200000
#define	EMLXS_PATCH23		0x00400000
#define	EMLXS_PATCH24		0x00800000
#define	EMLXS_PATCH25		0x01000000
#define	EMLXS_PATCH26		0x02000000
#define	EMLXS_PATCH27		0x04000000
#define	EMLXS_PATCH28		0x08000000
#define	EMLXS_PATCH29		0x10000000
#define	EMLXS_PATCH30		0x20000000
#define	EMLXS_PATCH31		0x40000000
#define	EMLXS_PATCH32		0x80000000


/* ULP Patches: */

/* This patch enables the driver to auto respond to unsolicited LOGO's */
/* This is needed because ULP is sometimes doesn't reply itself */
#define	ULP_PATCH2	EMLXS_PATCH2

/* This patch enables the driver to auto respond to unsolicited PRLI's */
/* This is needed because ULP is known to panic sometimes */
#define	ULP_PATCH3	EMLXS_PATCH3

/* This patch enables the driver to auto respond to unsolicited PRLO's */
/* This is needed because ULP is known to panic sometimes */
#define	ULP_PATCH4	EMLXS_PATCH4

/* This patch enables the driver to fail pkt abort requests */
#define	ULP_PATCH5	EMLXS_PATCH5

/* This patch enables the driver to generate an RSCN for unsolicited PRLO's */
/* and LOGO's */
#define	ULP_PATCH6	EMLXS_PATCH6

/* Sun Disk Array Patches: */

/* This patch enables the driver to fix a residual underrun issue with */
/* check conditions */
#define	FCP_UNDERRUN_PATCH1	EMLXS_PATCH9

/* This patch enables the driver to fix a residual underrun issue with */
/* SCSI inquiry commands */
#define	FCP_UNDERRUN_PATCH2	EMLXS_PATCH10


#define	DEFAULT_PATCHES	(ULP_PATCH2 | ULP_PATCH3 | \
			    ULP_PATCH5 | ULP_PATCH6 | \
			    FCP_UNDERRUN_PATCH1 | FCP_UNDERRUN_PATCH2)

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_OS_H */
