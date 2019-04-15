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

/*
 * Copyright 2019, Joyent, Inc.
 */

#ifndef _SYS_PCIEB_H
#define	_SYS_PCIEB_H

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(DEBUG)
#define	PCIEB_DEBUG pcieb_dbg
extern void pcieb_dbg(uint_t bit, dev_info_t *dip, char *fmt, ...);
#else /* DEBUG */
#define	PCIEB_DEBUG(...) (void)(0)
#endif /* DEBUG */

typedef enum {	/* same sequence as pcieb_debug_sym[] */
	/*  0 */ DBG_ATTACH,
	/*  1 */ DBG_PWR,
	/*  2 */ DBG_INTR
} pcieb_debug_bit_t;

/*
 * Intel specific register offsets with bit definitions.
 */
#define	PCIEB_PX_CAPABILITY_ID	0x44
#define	PCIEB_BRIDGE_CONF		0x40

/*
 * PCI/PCI-E Configuration register specific values.
 */
#define	PX_PMODE	0x4000		/* PCI/PCIX Mode */
#define	PX_PFREQ_66	0x200		/* PCI clock frequency */
#define	PX_PFREQ_100	0x400
#define	PX_PFREQ_133	0x600
#define	PX_PMRE		0x80		/* Peer memory read enable */

/*
 * Downstream delayed transaction resource partitioning.
 */
#define	PX_ODTP		0x40		/* Max. of two entries PX and PCI */

/*
 * Maximum upstream delayed transaction.
 */
#define	PX_MDT_44	0x00
#define	PX_MDT_11	0x01
#define	PX_MDT_22	0x10

#define	NUM_LOGICAL_SLOTS	32
#define	PCIEB_RANGE_LEN		2
#define	PCIEB_32BIT_IO		1
#define	PCIEB_32bit_MEM		1
#define	PCIEB_MEMGRAIN		0x100000
#define	PCIEB_IOGRAIN		0x1000

#define	PCIEB_16bit_IOADDR(addr) ((uint16_t)(((uint8_t)(addr) & 0xF0) << 8))
#define	PCIEB_LADDR(lo, hi) (((uint16_t)(hi) << 16) | (uint16_t)(lo))
#define	PCIEB_32bit_MEMADDR(addr) (PCIEB_LADDR(0, ((uint16_t)(addr) & 0xFFF0)))

/*
 * Intel 41210 PCIe-to-PCI Bridge has two Functions F0 and F2:
 * VID: 0x8086
 * DID: F0 = 0x340, F2 = 0x341
 */
#define	PCIEB_IS_41210_F0(bus_dev_ven_id) (bus_dev_ven_id == 0x3408086)
#define	PCIEB_IS_41210_F2(bus_dev_ven_id) (bus_dev_ven_id == 0x3418086)
#define	PCIEB_IS_41210_BRIDGE(bus_dev_ven_id) \
	(PCIEB_IS_41210_F0(bus_dev_ven_id) || PCIEB_IS_41210_F2(bus_dev_ven_id))

typedef struct {
	dev_info_t		*pcieb_dip;

	/* Interrupt support */
	ddi_intr_handle_t	*pcieb_htable;		/* Intr Handlers */
	int			pcieb_htable_size;	/* htable size */
	int			pcieb_intr_count;	/* Num of Intr */
	uint_t			pcieb_intr_priority;	/* Intr Priority */
	int			pcieb_intr_type;	/* (MSI | FIXED) */
	int			pcieb_isr_tab[4];	/* MSI source offset */

	int			pcieb_init_flags;
	kmutex_t		pcieb_mutex;		/* Soft state mutex */
	kmutex_t		pcieb_intr_mutex;	/* Intr handler mutex */
	kmutex_t		pcieb_err_mutex;	/* Error mutex */
	kmutex_t		pcieb_peek_poke_mutex;  /* Peekpoke mutex */

	/* FMA */
	boolean_t		pcieb_no_aer_msi;
	ddi_iblock_cookie_t	pcieb_fm_ibc;
} pcieb_devstate_t;

/*
 * soft state pointer
 */
extern void *pcieb_state;

/* soft state flags */
#define	PCIEB_SOFT_STATE_CLOSED		0x00
#define	PCIEB_SOFT_STATE_OPEN		0x01
#define	PCIEB_SOFT_STATE_OPEN_EXCL	0x02

/* init flags */
#define	PCIEB_INIT_MUTEX		0x01
#define	PCIEB_INIT_HTABLE		0x02
#define	PCIEB_INIT_ALLOC		0x04
#define	PCIEB_INIT_HANDLER		0x08
#define	PCIEB_INIT_ENABLE		0x10
#define	PCIEB_INIT_BLOCK		0x20
#define	PCIEB_INIT_FM			0x40

#define	PCIEB_INTR_SRC_UNKNOWN	0x0	/* must be 0 */
#define	PCIEB_INTR_SRC_HP	0x1
#define	PCIEB_INTR_SRC_PME	0x2
#define	PCIEB_INTR_SRC_AER	0x4

/*
 * Need to put vendor ids in a common file and not platform specific files
 * as is done today. Until then putting this vendor id define here.
 */
#define	NVIDIA_VENDOR_ID	0x10de	/* Nvidia Vendor Id */

#ifdef	PCIEB_BCM

/* Workaround for address space limitation in Broadcom 5714/5715 */
#define	PCIEB_ADDR_LIMIT_LO		0ull
#define	PCIEB_ADDR_LIMIT_HI		((1ull << 40) - 1)

#endif	/* PCIEB_BCM */

/*
 * The following values are used to initialize the cache line size
 * and latency timer registers for PCI, PCI-X and PCIe2PCI devices.
 */
#define	PCIEB_CACHE_LINE_SIZE	0x10	/* 64 bytes in # of DWORDs */
#define	PCIEB_LATENCY_TIMER	0x40	/* 64 PCI cycles */

extern void	pcieb_set_pci_perf_parameters(dev_info_t *dip,
		    ddi_acc_handle_t config_handle);
extern void	pcieb_plat_attach_workaround(dev_info_t *dip);
extern void	pcieb_plat_intr_attach(pcieb_devstate_t *pcieb);
extern void	pcieb_plat_initchild(dev_info_t *child);
extern void	pcieb_plat_uninitchild(dev_info_t *child);
extern int	pcieb_plat_ctlops(dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg);
extern int	pcieb_plat_pcishpc_probe(dev_info_t *dip,
    ddi_acc_handle_t config_handle);
extern int	pcieb_plat_peekpoke(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result);
extern void	pcieb_set_prot_scan(dev_info_t *dip, ddi_acc_impl_t *hdlp);
extern int	pcieb_plat_intr_ops(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);
extern boolean_t	pcieb_plat_msi_supported(dev_info_t *dip);
extern boolean_t	pcieb_plat_pwr_disable(dev_info_t *dip);

#if defined(__i386) || defined(__amd64)
extern void	pcieb_intel_error_workaround(dev_info_t *dip);
extern void	pcieb_intel_serr_workaround(dev_info_t *dip, boolean_t mcheck);
extern void	pcieb_intel_rber_workaround(dev_info_t *dip);
extern void	pcieb_intel_sw_workaround(dev_info_t *dip);
extern void	pcieb_intel_mps_workaround(dev_info_t *dip);
extern void	pcieb_init_osc(dev_info_t *dip);
extern void	pcieb_peekpoke_cb(dev_info_t *, ddi_fm_error_t *);
extern int	pcishpc_init(dev_info_t *dip);
extern int	pcishpc_uninit(dev_info_t *dip);
extern int	pcishpc_intr(dev_info_t *dip);
#endif /* defined(__i386) || defined(__amd64) */

#ifdef PX_PLX
extern void	pcieb_attach_plx_workarounds(pcieb_devstate_t *pcieb);
extern int	pcieb_init_plx_workarounds(pcieb_devstate_t *pcieb,
    dev_info_t *child);
#endif /* PX_PLX */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIEB_H */
