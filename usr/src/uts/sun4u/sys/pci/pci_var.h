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

#ifndef _SYS_PCI_VAR_H
#define	_SYS_PCI_VAR_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following typedef is used to represent a
 * 1275 "reg" property of a PCI nexus.
 */
typedef struct pci_nexus_regspec {
	uint64_t phys_addr;
	uint64_t size;
} pci_nexus_regspec_t;

typedef enum { PSYCHO, SCHIZO } pci_bridge_t;
typedef enum { A, B } pci_side_t;
typedef enum { PCI_NEW, PCI_ATTACHED, PCI_DETACHED, PCI_SUSPENDED } pci_state_t;
typedef enum { PCI_PBM_OBJ, PCI_ECC_OBJ, PCI_CB_OBJ } pci_obj_t;
typedef enum { PCI_OBJ_INTR_ADD, PCI_OBJ_INTR_REMOVE } pci_obj_op_t;

#define	PCI_ATTACH_RETCODE(obj, op, err) \
	((err) ? (obj) << 8 | (op) << 4 | (err) & 0xf : DDI_SUCCESS)

#define	PCI_OTHER_SIDE(side) ((side) ^ 1)

/*
 * the sequence of the chip_type appearance is significant. There are code
 * depending on it: CHIP_TYPE(pci_p) < PCI_CHIP_SCHIZO.
 */
typedef enum {
	PCI_CHIP_UNIDENTIFIED = 0,

	PCI_CHIP_PSYCHO = 1,
	PCI_CHIP_SABRE,
	PCI_CHIP_HUMMINGBIRD,

	PCI_CHIP_SCHIZO = 0x11,
	PCI_CHIP_XMITS,
	PCI_CHIP_TOMATILLO
} pci_chip_id_t;

/*
 * [msb]				[lsb]
 * 0x00 <chip_type> <version#> <module-revision#>
 */
#define	CHIP_ID(t, v, m) 	(((t) << 16) | ((v) << 8) | (m))
#define	ID_CHIP_TYPE(id) 	((id) >> 16)
#define	PCI_CHIP_ID(pci_p) 	((pci_p)->pci_common_p->pci_chip_id)
#define	CHIP_TYPE(pci_p) 	ID_CHIP_TYPE(PCI_CHIP_ID(pci_p))
#define	CHIP_REV(pci_p)		(PCI_CHIP_ID(pci_p) & 0xFF)
#define	CHIP_VER(pci_p)		((PCI_CHIP_ID(pci_p) >> 8) & 0xFF)
#define	CB_CHIP_TYPE(cb_p) 	((cb_p)->cb_pci_cmn_p->pci_chip_id >> 16)

/*
 * pci common soft state structure:
 *
 * Each psycho or schizo is represented by a pair of pci nodes in the
 * device tree.  A single pci common soft state is allocated for each
 * pair.  The UPA (Safari) bus id of the psycho (schizo) is used for
 * the instance number.  The attach routine uses the existance of a
 * pci common soft state structure to determine if one node from the
 * pair has been attached.
 */
struct pci_common {
	uint_t pci_common_id;

	/* pointers & counters to facilitate attach/detach & suspend/resume */
	ushort_t pci_common_refcnt;	/* # of sides suspended + attached */
	ushort_t pci_common_attachcnt;	/* # of sides attached */
	uint16_t pci_common_tsb_cookie;	/* IOMMU TSB allocation */
	pci_t *pci_p[2];		/* pci soft states of both sides */

	uint32_t pci_chip_id;		/* Bus bridge chip identification */

	/* Links to functional blocks potentially shared between pci nodes */
	iommu_t *pci_common_iommu_p;
	cb_t *pci_common_cb_p;
	ib_t *pci_common_ib_p;
	ecc_t *pci_common_ecc_p;

	/*
	 * Performance counters kstat.
	 */
	pci_cntr_pa_t	pci_cmn_uks_pa;
	kstat_t	*pci_common_uksp;	/* ptr to upstream kstat */
	kmutex_t pci_fm_mutex;		/* per chip error handling mutex */
};

/*
 * pci soft state structure:
 *
 * Each pci node has a pci soft state structure.
 */
struct pci {
	/*
	 * State flags and mutex:
	 */
	pci_state_t pci_state;
	uint_t pci_soft_state;
	uint16_t pci_tsb_cookie;	/* IOMMU TSB allocation */
	kmutex_t pci_mutex;

	/*
	 * Links to other state structures:
	 */
	pci_common_t *pci_common_p;	/* pointer common soft state */
	dev_info_t *pci_dip;		/* devinfo structure */
	ib_t *pci_ib_p;			/* interrupt block */
	cb_t *pci_cb_p;			/* control block */
	pbm_t *pci_pbm_p;		/* PBM block */
	iommu_t	*pci_iommu_p;		/* IOMMU block */
	sc_t *pci_sc_p;			/* streaming cache block */
	ecc_t *pci_ecc_p;		/* ECC error block */

	/*
	 * other state info:
	 */
	uint_t pci_id;			/* UPA (or Safari) device id */
	pci_side_t pci_side;

	/*
	 * pci device node properties:
	 */
	pci_bus_range_t pci_bus_range;	/* "bus-range" */
	pci_ranges_t *pci_ranges;	/* "ranges" data & length */
	int pci_ranges_length;
	uint32_t *pci_inos;		/* inos from "interrupts" prop */
	int pci_inos_len;		/* "interrupts" length */
	int pci_numproxy;		/* upa interrupt proxies */
	int pci_thermal_interrupt;	/* node has thermal interrupt */

	/*
	 * register mapping:
	 */
	caddr_t pci_address[4];
	ddi_acc_handle_t pci_ac[4];

	/* Interrupt support */
	int intr_map_size;
	struct intr_map *intr_map;
	struct intr_map_mask *intr_map_mask;

	/* performance counters */
	pci_cntr_addr_t	pci_ks_addr;
	kstat_t	*pci_ksp;

	/* Hotplug information */

	boolean_t	hotplug_capable;

	/* Fault Management support */
	int pci_fm_cap;
	ddi_iblock_cookie_t pci_fm_ibc;
};

/*
 * PSYCHO and PBM soft state macros:
 */
#define	get_pci_soft_state(i)	\
	((pci_t *)ddi_get_soft_state(per_pci_state, (i)))

#define	alloc_pci_soft_state(i)	\
	ddi_soft_state_zalloc(per_pci_state, (i))

#define	free_pci_soft_state(i)	\
	ddi_soft_state_free(per_pci_state, (i))

#define	get_pci_common_soft_state(i)	\
	((pci_common_t *)ddi_get_soft_state(per_pci_common_state, (i)))

#define	alloc_pci_common_soft_state(i)	\
	ddi_soft_state_zalloc(per_pci_common_state, (i))

#define	free_pci_common_soft_state(i)	\
	ddi_soft_state_free(per_pci_common_state, (i))

#define	DEV_TO_SOFTSTATE(dev)	((pci_t *)ddi_get_soft_state(per_pci_state, \
	PCIHP_AP_MINOR_NUM_TO_INSTANCE(getminor(dev))))

extern void *per_pci_state;		/* per-pbm soft state pointer */
extern void *per_pci_common_state;	/* per-psycho soft state pointer */
extern kmutex_t pci_global_mutex;	/* attach/detach common struct lock */
extern kmutex_t dvma_active_list_mutex;

/*
 * function prototypes for bus ops routines:
 */
extern int
pci_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *addrp);
extern int
pci_dma_setup(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_req_t *dmareq, ddi_dma_handle_t *handlep);
extern int
pci_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attrp,
	int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep);
extern int
pci_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, ddi_dma_req_t *dmareq,
	ddi_dma_cookie_t *cookiep, uint_t *ccountp);
extern int
pci_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle);
extern int
pci_dma_flush(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, off_t off, size_t len,
	uint_t cache_flags);
extern int
pci_dma_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
	enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
	uint_t cache_flags);
extern int
pci_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result);
extern int
pci_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
	ddi_intr_handle_impl_t *handle, void *result);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_VAR_H */
