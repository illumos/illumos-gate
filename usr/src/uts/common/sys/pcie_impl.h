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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_PCIE_IMPL_H
#define	_SYS_PCIE_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/pcie.h>
#include <sys/pciev.h>

#define	PCI_GET_BDF(dip)	\
	PCIE_DIP2BUS(dip)->bus_bdf
#define	PCI_GET_SEC_BUS(dip)	\
	PCIE_DIP2BUS(dip)->bus_bdg_secbus
#define	PCI_GET_PCIE2PCI_SECBUS(dip) \
	PCIE_DIP2BUS(dip)->bus_pcie2pci_secbus

#define	DEVI_PORT_TYPE_PCI \
	((PCI_CLASS_BRIDGE << 16) | (PCI_BRIDGE_PCI << 8) | \
	PCI_BRIDGE_PCI_IF_PCI2PCI)

#define	PCIE_DIP2BUS(dip) \
	(ndi_port_type(dip, B_TRUE, DEVI_PORT_TYPE_PCI) ? \
	PCIE_DIP2UPBUS(dip) : \
	ndi_port_type(dip, B_FALSE, DEVI_PORT_TYPE_PCI) ? \
	PCIE_DIP2DOWNBUS(dip) : NULL)

#define	PCIE_DIP2UPBUS(dip) \
	((pcie_bus_t *)ndi_get_bus_private(dip, B_TRUE))
#define	PCIE_DIP2DOWNBUS(dip) \
	((pcie_bus_t *)ndi_get_bus_private(dip, B_FALSE))
#define	PCIE_DIP2PFD(dip) (PCIE_DIP2BUS(dip))->bus_pfd
#define	PCIE_PFD2BUS(pfd_p) pfd_p->pe_bus_p
#define	PCIE_PFD2DIP(pfd_p) PCIE_PFD2BUS(pfd_p)->bus_dip
#define	PCIE_BUS2DIP(bus_p) bus_p->bus_dip
#define	PCIE_BUS2PFD(bus_p) PCIE_DIP2PFD(PCIE_BUS2DIP(bus_p))
#define	PCIE_BUS2DOM(bus_p) bus_p->bus_dom
#define	PCIE_DIP2DOM(dip) PCIE_BUS2DOM(PCIE_DIP2BUS(dip))

/*
 * These macros depend on initialization of type related data in bus_p.
 */
#define	PCIE_IS_PCIE(bus_p) (bus_p->bus_pcie_off)
#define	PCIE_IS_PCIX(bus_p) (bus_p->bus_pcix_off)
#define	PCIE_IS_PCI(bus_p) (!PCIE_IS_PCIE(bus_p))
#define	PCIE_HAS_AER(bus_p) (bus_p->bus_aer_off)
/* IS_ROOT = is RC or RP */
#define	PCIE_IS_ROOT(bus_p) (PCIE_IS_RC(bus_p) || PCIE_IS_RP(bus_p))

#define	PCIE_IS_HOTPLUG_CAPABLE(dip) \
	(PCIE_DIP2BUS(dip)->bus_hp_sup_modes)

#define	PCIE_IS_HOTPLUG_ENABLED(dip) \
	((PCIE_DIP2BUS(dip)->bus_hp_curr_mode == PCIE_PCI_HP_MODE) || \
	(PCIE_DIP2BUS(dip)->bus_hp_curr_mode == PCIE_NATIVE_HP_MODE))

/*
 * This is a pseudo pcie "device type", but it's needed to explain describe
 * nodes such as PX and NPE, which aren't really PCI devices but do control or
 * interaction with PCI error handling.
 */
#define	PCIE_IS_RC(bus_p) \
	(bus_p->bus_dev_type == PCIE_PCIECAP_DEV_TYPE_RC_PSEUDO)
#define	PCIE_IS_RP(bus_p) \
	((bus_p->bus_dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT) && \
	    PCIE_IS_PCIE(bus_p))
#define	PCIE_IS_SWU(bus_p) \
	(bus_p->bus_dev_type == PCIE_PCIECAP_DEV_TYPE_UP)
#define	PCIE_IS_SWD(bus_p) \
	(bus_p->bus_dev_type == PCIE_PCIECAP_DEV_TYPE_DOWN)
#define	PCIE_IS_SW(bus_p) \
	(PCIE_IS_SWU(bus_p) || PCIE_IS_SWD(bus_p))
#define	PCIE_IS_BDG(bus_p)  (bus_p->bus_hdr_type == PCI_HEADER_ONE)
#define	PCIE_IS_PCI_BDG(bus_p) (PCIE_IS_PCI(bus_p) && PCIE_IS_BDG(bus_p))
#define	PCIE_IS_PCIE_BDG(bus_p) \
	(bus_p->bus_dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI)
#define	PCIE_IS_PCI2PCIE(bus_p) \
	(bus_p->bus_dev_type == PCIE_PCIECAP_DEV_TYPE_PCI2PCIE)
#define	PCIE_IS_PCIE_SEC(bus_p) \
	(PCIE_IS_PCIE(bus_p) && PCIE_IS_BDG(bus_p) && !PCIE_IS_PCIE_BDG(bus_p))
#define	PCIX_ECC_VERSION_CHECK(bus_p) \
	((bus_p->bus_ecc_ver == PCI_PCIX_VER_1) || \
	    (bus_p->bus_ecc_ver == PCI_PCIX_VER_2))

#define	PCIE_VENID(bus_p)	(bus_p->bus_dev_ven_id & 0xffff)
#define	PCIE_DEVID(bus_p)	((bus_p->bus_dev_ven_id >> 16) & 0xffff)

/* PCIE Cap/AER shortcuts */
#define	PCIE_GET(sz, bus_p, off) \
	pci_config_get ## sz(bus_p->bus_cfg_hdl, off)
#define	PCIE_PUT(sz, bus_p, off, val) \
	pci_config_put ## sz(bus_p->bus_cfg_hdl, off, val)
#define	PCIE_CAP_GET(sz, bus_p, off) \
	PCI_CAP_GET ## sz(bus_p->bus_cfg_hdl, 0, bus_p->bus_pcie_off, off)
#define	PCIE_CAP_PUT(sz, bus_p, off, val) \
	PCI_CAP_PUT ## sz(bus_p->bus_cfg_hdl, 0, bus_p->bus_pcie_off, off, \
	    val)
#define	PCIE_AER_GET(sz, bus_p, off) \
	PCI_XCAP_GET ## sz(bus_p->bus_cfg_hdl, 0, bus_p->bus_aer_off, off)
#define	PCIE_AER_PUT(sz, bus_p, off, val) \
	PCI_XCAP_PUT ## sz(bus_p->bus_cfg_hdl, 0, bus_p->bus_aer_off, off, \
	    val)
#define	PCIX_CAP_GET(sz, bus_p, off) \
	PCI_CAP_GET ## sz(bus_p->bus_cfg_hdl, 0, bus_p->bus_pcix_off, off)
#define	PCIX_CAP_PUT(sz, bus_p, off, val) \
	PCI_CAP_PUT ## sz(bus_p->bus_cfg_hdl, 0, bus_p->bus_pcix_off, off, \
	    val)

/* Translate PF error return values to DDI_FM values */
#define	PF_ERR2DDIFM_ERR(sts) \
	(sts & PF_ERR_FATAL_FLAGS ? DDI_FM_FATAL :	\
	(sts == PF_ERR_NO_ERROR ? DDI_FM_OK : DDI_FM_NONFATAL))

/*
 * The following flag is used for Broadcom 5714/5715 bridge prefetch issue.
 * This flag will be used both by px and pcieb nexus drivers.
 */
#define	PX_DMAI_FLAGS_MAP_BUFZONE	0x40000

/*
 * PCI(e/-X) structures used to to gather and report errors detected by
 * PCI(e/-X) compliant devices.  These registers only contain "dynamic" data.
 * Static data such as Capability Offsets and Version #s is saved in the parent
 * private data.
 */
#define	PCI_ERR_REG(pfd_p)	   pfd_p->pe_pci_regs
#define	PCI_BDG_ERR_REG(pfd_p)	   PCI_ERR_REG(pfd_p)->pci_bdg_regs
#define	PCIX_ERR_REG(pfd_p)	   pfd_p->pe_ext.pe_pcix_regs
#define	PCIX_ECC_REG(pfd_p)	   PCIX_ERR_REG(pfd_p)->pcix_ecc_regs
#define	PCIX_BDG_ERR_REG(pfd_p)	   pfd_p->pe_pcix_bdg_regs
#define	PCIX_BDG_ECC_REG(pfd_p, n) PCIX_BDG_ERR_REG(pfd_p)->pcix_bdg_ecc_regs[n]
#define	PCIE_ERR_REG(pfd_p)	   pfd_p->pe_ext.pe_pcie_regs
#define	PCIE_RP_REG(pfd_p)	   PCIE_ERR_REG(pfd_p)->pcie_rp_regs
#define	PCIE_ROOT_FAULT(pfd_p)	   pfd_p->pe_root_fault
#define	PCIE_ROOT_EH_SRC(pfd_p)    pfd_p->pe_root_eh_src
#define	PCIE_ADV_REG(pfd_p)	   PCIE_ERR_REG(pfd_p)->pcie_adv_regs
#define	PCIE_ADV_HDR(pfd_p, n)	   PCIE_ADV_REG(pfd_p)->pcie_ue_hdr[n]
#define	PCIE_ADV_BDG_REG(pfd_p) \
	PCIE_ADV_REG(pfd_p)->pcie_ext.pcie_adv_bdg_regs
#define	PCIE_ADV_BDG_HDR(pfd_p, n) PCIE_ADV_BDG_REG(pfd_p)->pcie_sue_hdr[n]
#define	PCIE_ADV_RP_REG(pfd_p) \
	PCIE_ADV_REG(pfd_p)->pcie_ext.pcie_adv_rp_regs
#define	PFD_AFFECTED_DEV(pfd_p)	   pfd_p->pe_affected_dev
#define	PFD_SET_AFFECTED_FLAG(pfd_p, aff_flag) \
	PFD_AFFECTED_DEV(pfd_p)->pe_affected_flags = aff_flag
#define	PFD_SET_AFFECTED_BDF(pfd_p, bdf) \
	PFD_AFFECTED_DEV(pfd_p)->pe_affected_bdf = bdf

#define	PFD_IS_ROOT(pfd_p)	   PCIE_IS_ROOT(PCIE_PFD2BUS(pfd_p))
#define	PFD_IS_RC(pfd_p)	   PCIE_IS_RC(PCIE_PFD2BUS(pfd_p))
#define	PFD_IS_RP(pfd_p)	   PCIE_IS_RP(PCIE_PFD2BUS(pfd_p))

/* bus_hp_mode field */
typedef enum {
	PCIE_NONE_HP_MODE	= 0x0,
	PCIE_ACPI_HP_MODE	= 0x1,
	PCIE_PCI_HP_MODE	= 0x2,
	PCIE_NATIVE_HP_MODE	= 0x4
} pcie_hp_mode_t;

typedef struct pf_pci_bdg_err_regs {
	uint16_t pci_bdg_sec_stat;	/* PCI secondary status reg */
	uint16_t pci_bdg_ctrl;		/* PCI bridge control reg */
} pf_pci_bdg_err_regs_t;

typedef struct pf_pci_err_regs {
	uint16_t pci_err_status;	/* pci status register */
	uint16_t pci_cfg_comm;		/* pci command register */
	pf_pci_bdg_err_regs_t *pci_bdg_regs;
} pf_pci_err_regs_t;

typedef struct pf_pcix_ecc_regs {
	uint32_t pcix_ecc_ctlstat;	/* pcix ecc control status reg */
	uint32_t pcix_ecc_fstaddr;	/* pcix ecc first address reg */
	uint32_t pcix_ecc_secaddr;	/* pcix ecc second address reg */
	uint32_t pcix_ecc_attr;		/* pcix ecc attributes reg */
} pf_pcix_ecc_regs_t;

typedef struct pf_pcix_err_regs {
	uint16_t pcix_command;		/* pcix command register */
	uint32_t pcix_status;		/* pcix status register */
	pf_pcix_ecc_regs_t *pcix_ecc_regs;	/* pcix ecc registers */
} pf_pcix_err_regs_t;

typedef struct pf_pcix_bdg_err_regs {
	uint16_t pcix_bdg_sec_stat;	/* pcix bridge secondary status reg */
	uint32_t pcix_bdg_stat;		/* pcix bridge status reg */
	pf_pcix_ecc_regs_t *pcix_bdg_ecc_regs[2];	/* pcix ecc registers */
} pf_pcix_bdg_err_regs_t;

typedef struct pf_pcie_adv_bdg_err_regs {
	uint32_t pcie_sue_ctl;		/* pcie bridge secondary ue control */
	uint32_t pcie_sue_status;	/* pcie bridge secondary ue status */
	uint32_t pcie_sue_mask;		/* pcie bridge secondary ue mask */
	uint32_t pcie_sue_sev;		/* pcie bridge secondary ue severity */
	uint32_t pcie_sue_hdr[4];	/* pcie bridge secondary ue hdr log */
	uint32_t pcie_sue_tgt_trans;	/* Fault trans type from SAER Logs */
	uint64_t pcie_sue_tgt_addr;	/* Fault addr from SAER Logs */
	pcie_req_id_t pcie_sue_tgt_bdf;	/* Fault bdf from SAER Logs */
} pf_pcie_adv_bdg_err_regs_t;

typedef struct pf_pcie_adv_rp_err_regs {
	uint32_t pcie_rp_err_status;	/* pcie root complex error status reg */
	uint32_t pcie_rp_err_cmd;	/* pcie root complex error cmd reg */
	uint16_t pcie_rp_ce_src_id;	/* pcie root complex ce sourpe id */
	uint16_t pcie_rp_ue_src_id;	/* pcie root complex ue sourpe id */
} pf_pcie_adv_rp_err_regs_t;

typedef struct pf_pcie_adv_err_regs {
	uint32_t pcie_adv_ctl;		/* pcie advanced control reg */
	uint32_t pcie_ue_status;	/* pcie ue error status reg */
	uint32_t pcie_ue_mask;		/* pcie ue error mask reg */
	uint32_t pcie_ue_sev;		/* pcie ue error severity reg */
	uint32_t pcie_ue_hdr[4];	/* pcie ue header log */
	uint32_t pcie_ce_status;	/* pcie ce error status reg */
	uint32_t pcie_ce_mask;		/* pcie ce error mask reg */
	union {
		pf_pcie_adv_bdg_err_regs_t *pcie_adv_bdg_regs; /* bdg regs */
		pf_pcie_adv_rp_err_regs_t *pcie_adv_rp_regs;	 /* rp regs */
	} pcie_ext;
	uint32_t pcie_ue_tgt_trans;	/* Fault trans type from AER Logs */
	uint64_t pcie_ue_tgt_addr;	/* Fault addr from AER Logs */
	pcie_req_id_t pcie_ue_tgt_bdf;	/* Fault bdf from AER Logs */
} pf_pcie_adv_err_regs_t;

typedef struct pf_pcie_rp_err_regs {
	uint32_t pcie_rp_status;	/* root complex status register */
	uint16_t pcie_rp_ctl;		/* root complex control register */
} pf_pcie_rp_err_regs_t;

typedef struct pf_pcie_err_regs {
	uint16_t pcie_err_status;	/* pcie device status register */
	uint16_t pcie_err_ctl;		/* pcie error control register */
	uint32_t pcie_dev_cap;		/* pcie device capabilities register */
	pf_pcie_rp_err_regs_t *pcie_rp_regs;	 /* pcie root complex regs */
	pf_pcie_adv_err_regs_t *pcie_adv_regs; /* pcie aer regs */
} pf_pcie_err_regs_t;

typedef enum {
	PF_INTR_TYPE_NONE = 0,
	PF_INTR_TYPE_FABRIC = 1,	/* Fabric Message */
	PF_INTR_TYPE_DATA,		/* Data Access Failure, failed loads */
	PF_INTR_TYPE_AER,		/* Root Port AER MSI */
	PF_INTR_TYPE_INTERNAL		/* Chip specific internal errors */
} pf_intr_type_t;

typedef struct pf_root_eh_src {
	pf_intr_type_t	intr_type;
	void		*intr_data;	/* Interrupt Data */
} pf_root_eh_src_t;

typedef struct pf_root_fault {
	pcie_req_id_t	scan_bdf;	/* BDF from error logs */
	uint64_t	scan_addr;	/* Addr from error logs */
	boolean_t	full_scan;	/* Option to do a full scan */
} pf_root_fault_t;

typedef struct pf_data pf_data_t;

/*
 * For hot plugged device, these data are init'ed during during probe
 * For non-hotplugged device, these data are init'ed in pci_autoconfig (on x86),
 * or in px_attach()(on sparc).
 *
 * For root complex the fields are initialized in pcie_rc_init_bus();
 * for others part of the fields are initialized in pcie_init_bus(),
 * and part of fields initialized in pcie_post_init_bus(). See comments
 * on top of respective functions for details.
 */
typedef struct pcie_bus {
	/* Needed for PCI/PCIe fabric error handling */
	dev_info_t	*bus_dip;
	dev_info_t	*bus_rp_dip;
	ddi_acc_handle_t bus_cfg_hdl;		/* error handling acc hdle */
	uint_t		bus_fm_flags;
	uint_t		bus_soft_state;

	/* Static PCI/PCIe information */
	pcie_req_id_t	bus_bdf;
	pcie_req_id_t	bus_rp_bdf;		/* BDF of device's Root Port */
	uint32_t	bus_dev_ven_id;		/* device/vendor ID */
	uint8_t		bus_rev_id;		/* revision ID */
	uint8_t		bus_hdr_type;		/* pci header type, see pci.h */
	uint16_t	bus_dev_type;		/* PCI-E dev type, see pcie.h */
	uint8_t		bus_bdg_secbus;		/* Bridge secondary bus num */
	uint16_t	bus_pcie_off;		/* PCIe Capability Offset */
	uint16_t	bus_aer_off;		/* PCIe Advanced Error Offset */
	uint16_t	bus_pcix_off;		/* PCIx Capability Offset */
	uint16_t	bus_pci_hp_off;		/* PCI HP (SHPC) Cap Offset */
	uint16_t	bus_ecc_ver;		/* PCIX ecc version */
	pci_bus_range_t	bus_bus_range;		/* pci bus-range property */
	ppb_ranges_t	*bus_addr_ranges;	/* pci range property */
	int		bus_addr_entries;	/* number of range prop */
	pci_regspec_t	*bus_assigned_addr;	/* "assigned-address" prop */
	int		bus_assigned_entries;	/* number of prop entries */

	/* Cache of last fault data */
	pf_data_t	*bus_pfd;
	pcie_domain_t	*bus_dom;

	int		bus_mps;		/* Maximum Payload Size */

	void		*bus_plat_private;	/* Platform specific */
	/* Hotplug specific fields */
	pcie_hp_mode_t	bus_hp_sup_modes;	/* HP modes supported */
	pcie_hp_mode_t	bus_hp_curr_mode;	/* HP mode used */
	void		*bus_hp_ctrl;		/* HP bus ctrl data */
	int		bus_ari;		/* ARI device */

	uint64_t	bus_cfgacc_base;	/* config space base address */

	/* workaround for PCI/PCI-X devs behind PCIe2PCI Bridge */
	pcie_req_id_t   bus_pcie2pci_secbus;
} pcie_bus_t;

/*
 * Data structure to log what devices are affected in relationship to the
 * severity after all the errors bits have been analyzed.
 */
#define	PF_AFFECTED_ROOT	(1 << 0) /* RP/RC is affected */
#define	PF_AFFECTED_SELF	(1 << 1) /* Reporting Device is affected */
#define	PF_AFFECTED_PARENT	(1 << 2) /* Parent device is affected */
#define	PF_AFFECTED_CHILDREN	(1 << 3) /* All children below are affected */
#define	PF_AFFECTED_BDF		(1 << 4) /* See affected_bdf */
#define	PF_AFFECTED_AER		(1 << 5) /* See AER Registers */
#define	PF_AFFECTED_SAER	(1 << 6) /* See SAER Registers */
#define	PF_AFFECTED_ADDR	(1 << 7) /* Device targeted by addr */

#define	PF_MAX_AFFECTED_FLAG	PF_AFFECTED_ADDR

typedef struct pf_affected_dev {
	uint16_t		pe_affected_flags;
	pcie_req_id_t		pe_affected_bdf;
} pf_affected_dev_t;

struct pf_data {
	boolean_t		pe_lock;
	boolean_t		pe_valid;
	uint32_t		pe_severity_flags;	/* Severity of error */
	uint32_t		pe_orig_severity_flags; /* Original severity */
	pf_affected_dev_t	*pe_affected_dev;
	pcie_bus_t		*pe_bus_p;
	pf_root_fault_t		*pe_root_fault; /* Only valid for RC and RP */
	pf_root_eh_src_t	*pe_root_eh_src; /* Only valid for RC and RP */
	pf_pci_err_regs_t	*pe_pci_regs;	/* PCI error reg */
	union {
		pf_pcix_err_regs_t	*pe_pcix_regs;	/* PCI-X error reg */
		pf_pcie_err_regs_t	*pe_pcie_regs;	/* PCIe error reg */
	} pe_ext;
	pf_pcix_bdg_err_regs_t *pe_pcix_bdg_regs; /* PCI-X bridge regs */
	pf_data_t		*pe_prev;	/* Next error in queue */
	pf_data_t		*pe_next;	/* Next error in queue */
	boolean_t		pe_rber_fatal;
};

/* Information used while handling errors in the fabric. */
typedef struct pf_impl {
	ddi_fm_error_t	*pf_derr;
	pf_root_fault_t	*pf_fault;	/* captured fault bdf/addr to scan */
	pf_data_t	*pf_dq_head_p;	/* ptr to fault data queue */
	pf_data_t	*pf_dq_tail_p;	/* ptr pt last fault data q */
	uint32_t	pf_total;	/* total non RC pf_datas */
} pf_impl_t;

/* bus_fm_flags field */
#define	PF_FM_READY		(1 << 0)	/* bus_fm_lock initialized */
#define	PF_FM_IS_NH		(1 << 1)	/* known as non-hardened */

/*
 * PCIe fabric handle lookup address flags.  Used to define what type of
 * transaction the address is for.  These same value are defined again in
 * fabric-xlate FM module.  Do not modify these variables, without modifying
 * those.
 */
#define	PF_ADDR_DMA		(1 << 0)
#define	PF_ADDR_PIO		(1 << 1)
#define	PF_ADDR_CFG		(1 << 2)

/* PCIe fabric error scanning status flags */
#define	PF_SCAN_SUCCESS		(1 << 0)
#define	PF_SCAN_CB_FAILURE	(1 << 1) /* hardened device callback failure */
#define	PF_SCAN_NO_ERR_IN_CHILD	(1 << 2) /* no errors in bridge sec stat reg */
#define	PF_SCAN_IN_DQ		(1 << 3) /* already present in the faultq */
#define	PF_SCAN_DEADLOCK	(1 << 4) /* deadlock detected */
#define	PF_SCAN_BAD_RESPONSE	(1 << 5) /* Incorrect device response */

/* PCIe fabric error handling severity return flags */
#define	PF_ERR_NO_ERROR		(1 << 0) /* No error seen */
#define	PF_ERR_CE		(1 << 1) /* Correctable Error */
#define	PF_ERR_NO_PANIC		(1 << 2) /* Error should not panic sys */
#define	PF_ERR_MATCHED_DEVICE	(1 << 3) /* Error Handled By Device */
#define	PF_ERR_MATCHED_RC	(1 << 4) /* Error Handled By RC */
#define	PF_ERR_MATCHED_PARENT	(1 << 5) /* Error Handled By Parent */
#define	PF_ERR_PANIC		(1 << 6) /* Error should panic system */
#define	PF_ERR_PANIC_DEADLOCK	(1 << 7) /* deadlock detected */
#define	PF_ERR_PANIC_BAD_RESPONSE (1 << 8) /* Device no response */
#define	PF_ERR_MATCH_DOM	(1 << 9) /* Error Handled By IO domain */

#define	PF_ERR_FATAL_FLAGS		\
	(PF_ERR_PANIC | PF_ERR_PANIC_DEADLOCK | PF_ERR_PANIC_BAD_RESPONSE)

#define	PF_HDL_FOUND		1
#define	PF_HDL_NOTFOUND		2

/*
 * PCIe Capability Device Type Pseudo Definitions.
 *
 * PCI_PSEUDO is used on real PCI devices.  The Legacy PCI definition in the
 * PCIe spec really refers to PCIe devices that *require* IO Space access.  IO
 * Space access is usually frowned upon now in PCIe, but there for legacy
 * purposes.
 */
#define	PCIE_PCIECAP_DEV_TYPE_RC_PSEUDO		0x100
#define	PCIE_PCIECAP_DEV_TYPE_PCI_PSEUDO	0x101

#define	PCIE_INVALID_BDF	0xFFFF
#define	PCIE_CHECK_VALID_BDF(x)	(x != PCIE_INVALID_BDF)

typedef struct {
	dev_info_t	*dip;
	int		highest_common_mps;
} pcie_max_supported_t;

/*
 * Default interrupt priority for all PCI and PCIe nexus drivers including
 * hotplug interrupts.
 */
#define	PCIE_INTR_PRI		(LOCK_LEVEL - 1)

/*
 * XXX - PCIE_IS_PCIE check is required in order not to invoke these macros
 * for non-standard PCI or PCI Express Hotplug Controllers.
 */
#define	PCIE_ENABLE_ERRORS(dip)	\
	if (PCIE_IS_PCIE(PCIE_DIP2BUS(dip))) {	\
		pcie_enable_errors(dip);	\
		(void) pcie_enable_ce(dip);	\
	}

#define	PCIE_DISABLE_ERRORS(dip)		\
	if (PCIE_IS_PCIE(PCIE_DIP2BUS(dip))) {	\
		pcie_disable_errors(dip);	\
	}

/*
 * pcie_init_buspcie_fini_bus specific flags
 */
#define	PCIE_BUS_INITIAL	0x0001
#define	PCIE_BUS_FINAL		0x0002
#define	PCIE_BUS_ALL		(PCIE_BUS_INITIAL | PCIE_BUS_FINAL)

#ifdef	DEBUG
#define	PCIE_DBG pcie_dbg
/* Common Debugging shortcuts */
#define	PCIE_DBG_CFG(dip, bus_p, name, sz, off, org) \
	PCIE_DBG("%s:%d:(0x%x) %s(0x%x) 0x%x -> 0x%x\n", ddi_node_name(dip), \
	    ddi_get_instance(dip), bus_p->bus_bdf, name, off, org, \
	    PCIE_GET(sz, bus_p, off))
#define	PCIE_DBG_CAP(dip, bus_p, name, sz, off, org) \
	PCIE_DBG("%s:%d:(0x%x) %s(0x%x) 0x%x -> 0x%x\n", ddi_node_name(dip), \
	    ddi_get_instance(dip), bus_p->bus_bdf, name, off, org, \
	    PCIE_CAP_GET(sz, bus_p, off))
#define	PCIE_DBG_AER(dip, bus_p, name, sz, off, org) \
	PCIE_DBG("%s:%d:(0x%x) %s(0x%x) 0x%x -> 0x%x\n", ddi_node_name(dip), \
	    ddi_get_instance(dip), bus_p->bus_bdf, name, off, org, \
	    PCIE_AER_GET(sz, bus_p, off))

#else	/* DEBUG */

#define	PCIE_DBG_CFG 0 &&
#define	PCIE_DBG 0 &&
#define	PCIE_ARI_DBG 0 &&
#define	PCIE_DBG_CAP 0 &&
#define	PCIE_DBG_AER 0 &&

#endif	/* DEBUG */

/* PCIe Friendly Functions */
extern int pcie_init(dev_info_t *dip, caddr_t arg);
extern int pcie_uninit(dev_info_t *dip);
extern int pcie_hpintr_enable(dev_info_t *dip);
extern int pcie_hpintr_disable(dev_info_t *dip);
extern int pcie_intr(dev_info_t *dip);
extern int pcie_open(dev_info_t *dip, dev_t *devp, int flags, int otyp,
    cred_t *credp);
extern int pcie_close(dev_info_t *dip, dev_t dev, int flags, int otyp,
    cred_t *credp);
extern int pcie_ioctl(dev_info_t *dip, dev_t dev, int cmd, intptr_t arg,
    int mode, cred_t *credp, int *rvalp);
extern int pcie_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);

extern void pcie_init_root_port_mps(dev_info_t *dip);
extern int pcie_initchild(dev_info_t *dip);
extern void pcie_uninitchild(dev_info_t *dip);
extern int pcie_init_cfghdl(dev_info_t *dip);
extern void pcie_fini_cfghdl(dev_info_t *dip);
extern void pcie_clear_errors(dev_info_t *dip);
extern int pcie_postattach_child(dev_info_t *dip);
extern void pcie_enable_errors(dev_info_t *dip);
extern void pcie_disable_errors(dev_info_t *dip);
extern int pcie_enable_ce(dev_info_t *dip);
extern boolean_t pcie_bridge_is_link_disabled(dev_info_t *);

extern pcie_bus_t *pcie_init_bus(dev_info_t *dip, pcie_req_id_t bdf,
    uint8_t flags);
extern void pcie_fini_bus(dev_info_t *dip, uint8_t flags);
extern void pcie_fab_init_bus(dev_info_t *dip, uint8_t flags);
extern void pcie_fab_fini_bus(dev_info_t *dip, uint8_t flags);
extern void pcie_rc_init_bus(dev_info_t *dip);
extern void pcie_rc_fini_bus(dev_info_t *dip);
extern void pcie_rc_init_pfd(dev_info_t *dip, pf_data_t *pfd);
extern void pcie_rc_fini_pfd(pf_data_t *pfd);
extern boolean_t pcie_is_child(dev_info_t *dip, dev_info_t *rdip);
extern int pcie_get_bdf_from_dip(dev_info_t *dip, pcie_req_id_t *bdf);
extern dev_info_t *pcie_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip);
extern uint32_t pcie_get_bdf_for_dma_xfer(dev_info_t *dip, dev_info_t *rdip);
extern int pcie_dev(dev_info_t *dip);
extern void pcie_get_fabric_mps(dev_info_t *rc_dip, dev_info_t *dip,
	int *max_supported);
extern int pcie_root_port(dev_info_t *dip);
extern int pcie_initchild_mps(dev_info_t *dip);
extern void pcie_set_rber_fatal(dev_info_t *dip, boolean_t val);
extern boolean_t pcie_get_rber_fatal(dev_info_t *dip);

extern uint32_t pcie_get_aer_uce_mask();
extern uint32_t pcie_get_aer_ce_mask();
extern uint32_t pcie_get_aer_suce_mask();
extern uint32_t pcie_get_serr_mask();
extern void pcie_set_aer_uce_mask(uint32_t mask);
extern void pcie_set_aer_ce_mask(uint32_t mask);
extern void pcie_set_aer_suce_mask(uint32_t mask);
extern void pcie_set_serr_mask(uint32_t mask);
extern void pcie_init_plat(dev_info_t *dip);
extern void pcie_fini_plat(dev_info_t *dip);
extern int pcie_read_only_probe(dev_info_t *, char *, dev_info_t **);
extern dev_info_t *pcie_func_to_dip(dev_info_t *dip, pcie_req_id_t function);
extern int pcie_ari_disable(dev_info_t *dip);
extern int pcie_ari_enable(dev_info_t *dip);

#define	PCIE_ARI_FORW_NOT_SUPPORTED	0
#define	PCIE_ARI_FORW_SUPPORTED		1

extern int pcie_ari_supported(dev_info_t *dip);

#define	PCIE_ARI_FORW_DISABLED	0
#define	PCIE_ARI_FORW_ENABLED	1

extern int pcie_ari_is_enabled(dev_info_t *dip);

#define	PCIE_NOT_ARI_DEVICE		0
#define	PCIE_ARI_DEVICE			1

extern int pcie_ari_device(dev_info_t *dip);
extern int pcie_ari_get_next_function(dev_info_t *dip, int *func);

/* PCIe error handling functions */
extern void pf_eh_enter(pcie_bus_t *bus_p);
extern void pf_eh_exit(pcie_bus_t *bus_p);
extern int pf_scan_fabric(dev_info_t *rpdip, ddi_fm_error_t *derr,
    pf_data_t *root_pfd_p);
extern void pf_init(dev_info_t *, ddi_iblock_cookie_t, ddi_attach_cmd_t);
extern void pf_fini(dev_info_t *, ddi_detach_cmd_t);
extern int pf_hdl_lookup(dev_info_t *, uint64_t, uint32_t, uint64_t,
    pcie_req_id_t);
extern int pf_tlp_decode(pcie_bus_t *, pf_pcie_adv_err_regs_t *);
extern void pcie_force_fullscan();

#ifdef	DEBUG
extern uint_t pcie_debug_flags;
extern void pcie_dbg(char *fmt, ...);
#endif	/* DEBUG */

/* PCIe IOV functions */
extern dev_info_t *pcie_find_dip_by_bdf(dev_info_t *rootp, pcie_req_id_t bdf);

extern boolean_t pf_in_bus_range(pcie_bus_t *, pcie_req_id_t);
extern boolean_t pf_in_assigned_addr(pcie_bus_t *, uint64_t);
extern int pf_pci_decode(pf_data_t *, uint16_t *);
extern pcie_bus_t *pf_find_busp_by_bdf(pf_impl_t *, pcie_req_id_t);
extern pcie_bus_t *pf_find_busp_by_addr(pf_impl_t *, uint64_t);
extern pcie_bus_t *pf_find_busp_by_aer(pf_impl_t *, pf_data_t *);
extern pcie_bus_t *pf_find_busp_by_saer(pf_impl_t *, pf_data_t *);

extern int pciev_eh(pf_data_t *, pf_impl_t *);
extern pcie_bus_t *pciev_get_affected_dev(pf_impl_t *, pf_data_t *,
    uint16_t, uint16_t);
extern void pciev_eh_exit(pf_data_t *, uint_t);
extern boolean_t pcie_in_domain(pcie_bus_t *, uint_t);

#define	PCIE_ZALLOC(data) kmem_zalloc(sizeof (data), KM_SLEEP)


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIE_IMPL_H */
