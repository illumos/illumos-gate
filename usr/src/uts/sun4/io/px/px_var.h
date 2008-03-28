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

#ifndef _SYS_PX_VAR_H
#define	_SYS_PX_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/callb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * offsets of PCI address spaces from base address:
 */
#define	PX_CONFIG		0x001000000ull
#define	PX_A_IO			0x002000000ull
#define	PX_B_IO			0x002010000ull
#define	PX_A_MEMORY		0x100000000ull
#define	PX_B_MEMORY		0x180000000ull
#define	PX_IO_SIZE		0x000010000ull
#define	PX_MEM_SIZE		0x080000000ull

/*
 * The following typedef is used to represent a
 * 1275 "bus-range" property of a PCI Bus node.
 */
typedef struct px_bus_range {
	uint32_t lo;
	uint32_t hi;
} px_bus_range_t;

/*
 * The following typedef is used to represent an entry in the "ranges"
 * property of a device node.
 */
typedef struct px_ranges {
	uint32_t child_high;
	uint32_t child_mid;
	uint32_t child_low;
	uint32_t parent_high;
	uint32_t parent_low;
	uint32_t size_high;
	uint32_t size_low;
} px_ranges_t;

/*
 * The following typedef is used to represent a
 * 1275 "reg" property of a PCI nexus.
 */
typedef struct px_nexus_regspec {
	uint64_t phys_addr;
	uint64_t size;
} px_nexus_regspec_t;

typedef enum {
	PX_ATTACHED = 1,
	PX_DETACHED,
	PX_SUSPENDED
} px_state_t;

enum { PX_INTR_XBC, PX_INTR_PEC, PX_INTR_HOTPLUG };

#define	PX_ATTACH_RETCODE(obj, op, err) \
	((err) ? (obj) << 8 | (op) << 4 | (err) & 0xf : DDI_SUCCESS)

/*
 * px soft state structure:
 *
 * Each px node has a px soft state structure.
 */
struct px {
	/*
	 * State flags and mutex:
	 */
	px_state_t px_state;
	uint_t px_soft_state;
	uint_t px_open_count;
	kmutex_t px_mutex;

	/*
	 * Links to other state structures:
	 */
	dev_info_t *px_dip;		/* devinfo structure */
	devhandle_t px_dev_hdl;		/* device handle */
	px_ib_t *px_ib_p;		/* interrupt block */
	px_pec_t *px_pec_p;		/* PEC block */
	px_mmu_t *px_mmu_p;		/* IOMMU block */

	/*
	 * px device node properties:
	 */
	pcie_req_id_t px_bdf;
	px_bus_range_t px_bus_range;	/* "bus-range" */
	px_ranges_t *px_ranges_p;	/* "ranges" data & length */
	int px_ranges_length;
	devino_t *px_inos;		/* inos from "interrupts" prop */
	int px_inos_len;		/* "interrupts" length */

	/* Error handling */
	px_fault_t	px_fault;
	px_fault_t	px_cb_fault;

	/* FMA */
	int		px_fm_cap;
	kmutex_t	px_fm_mutex;
	kthread_t	*px_fm_mutex_owner;
	ddi_iblock_cookie_t px_fm_ibc;
	pf_data_t	px_pfd_arr[5];
	int		px_pfd_idx;

	uint32_t	px_dev_caps;

	/* Platform specific information */
	void		*px_plat_p;

	/* Power Management fields */
	kmutex_t	px_l23ready_lock; /* used in PME_To_ACK interrupt */
	kcondvar_t	px_l23ready_cv;	/* used in PME_TO_ACK timeout */
	volatile uint32_t	px_lup_pending;
	int		px_pm_flags;
	msiqid_t	px_pm_msiq_id;	/* EQ id for PCIE_PME_ACK_MSG Message */
	uint32_t	px_pmetoack_ignored; /* count of PME_To_ACKs ignored */

	/* CPR callback id */
	callb_id_t	px_cprcb_id;
	uint32_t	px_dma_sync_opt; /* DMA syncing req. of hw */

	/* Handle for soft intr */
	ddi_softint_handle_t    px_dbg_hdl; /* HDL for dbg printing */
};

/* px soft state flag */
#define	PX_SOFT_STATE_OPEN		1
#define	PX_SOFT_STATE_OPEN_EXCL		2
#define	PX_SOFT_STATE_CLOSED		4

/* px_dev_caps definition */
#define	PX_BYPASS_DMA_ALLOWED		1
#define	PX_HOTPLUG_CAPABLE		2
#define	PX_DMA_SYNC_REQUIRED		4

/* px_pm_flags definitions used with interrupts and FMA code */
#define	PX_PMETOACK_RECVD		0x01 /* With PME_To_ACK interrupt */
#define	PX_PME_TURNOFF_PENDING		0x02 /* With PME_To_ACK interrupt */
#define	PX_LDN_EXPECTED			0x04 /* With FMA code */

#define	DIP_TO_INST(dip)	ddi_get_instance(dip)
#define	INST_TO_STATE(inst)	ddi_get_soft_state(px_state_p, inst)
#define	DIP_TO_STATE(dip)	INST_TO_STATE(DIP_TO_INST(dip))

#define	PX_DEV_TO_SOFTSTATE(dev)	((px_t *)ddi_get_soft_state( \
	px_state_p, PCIHP_AP_MINOR_NUM_TO_INSTANCE(getminor(dev))))

extern void *px_state_p;

/*
 * function prototypes for bus ops routines:
 */
extern int
px_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *addrp);
extern int
px_dma_setup(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_req_t *dmareq, ddi_dma_handle_t *handlep);
extern int
px_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attrp,
	int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep);
extern int
px_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, ddi_dma_req_t *dmareq,
	ddi_dma_cookie_t *cookiep, uint_t *ccountp);
extern int
px_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle);
extern int
px_dma_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
	enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
	uint_t cache_flags);
extern int
px_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result);
extern int
px_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
	ddi_intr_handle_impl_t *handle, void *result);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_VAR_H */
