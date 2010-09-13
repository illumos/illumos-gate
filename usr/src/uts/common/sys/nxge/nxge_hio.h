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

#ifndef	_SYS_NXGE_NXGE_HIO_H
#define	_SYS_NXGE_NXGE_HIO_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_mac.h>
#include <nxge_ipp.h>
#include <nxge_fflp.h>
#include <sys/mac_provider.h>

#define	isLDOMservice(nxge) \
	(nxge->environs == SOLARIS_SERVICE_DOMAIN)
#define	isLDOMguest(nxge) \
	(nxge->environs == SOLARIS_GUEST_DOMAIN)
#define	isLDOMs(nxge) \
	(isLDOMservice(nxge) || isLDOMguest(nxge))

#define	NXGE_HIO_SHARE_MIN_CHANNELS	2
#define	NXGE_HIO_SHARE_MAX_CHANNELS	2

/* ------------------------------------------------------------------ */
typedef uint8_t nx_rdc_t;
typedef uint8_t nx_tdc_t;

typedef uint64_t res_map_t;

typedef uint64_t hv_rv_t;

typedef hv_rv_t (*vr_assign)(uint64_t, uint64_t, uint32_t *);
typedef hv_rv_t (*vr_unassign)(uint32_t);
typedef hv_rv_t (*vr_getinfo)(uint32_t, uint64_t *, uint64_t *);

/* HV 2.0 API group functions */
typedef hv_rv_t (*vr_cfgh_assign)(uint64_t, uint64_t, uint64_t, uint32_t *);
typedef hv_rv_t (*vrlp_cfgh_conf)(uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t);
typedef hv_rv_t (*vrlp_cfgh_info)(uint64_t, uint64_t, uint64_t, uint64_t *,
    uint64_t *);


typedef struct {
	vr_assign	assign;		/* HV Major 1 interface */
	vr_cfgh_assign	cfgh_assign;	/* HV Major 2 interface */
	vr_unassign	unassign;
	vr_getinfo	getinfo;
} nxhv_vr_fp_t;

typedef hv_rv_t (*vrlp_conf)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef hv_rv_t (*vrlp_info)(uint64_t, uint64_t, uint64_t *, uint64_t *);

typedef hv_rv_t (*dc_assign)(uint32_t, uint64_t, uint64_t *);
typedef hv_rv_t (*dc_unassign)(uint32_t, uint64_t);
typedef hv_rv_t (*dc_getstate)(uint32_t, uint64_t, uint64_t *);
typedef hv_rv_t (*dc_get_map)(uint32_t, uint64_t *);

typedef hv_rv_t (*dc_getinfo)(uint32_t, uint64_t, uint64_t *, uint64_t *);

typedef struct {
	dc_assign	assign;
	dc_unassign	unassign;
	dc_getstate	getstate;
	dc_get_map	get_map;

	vrlp_conf	lp_conf;	/* HV Major 1 interface */
	vrlp_info	lp_info;	/* HV Major 1 interface */
	vrlp_cfgh_conf	lp_cfgh_conf;	/* HV Major 2 interface */
	vrlp_cfgh_info	lp_cfgh_info;	/* HV Major 2 interface */
	dc_getinfo	getinfo;
} nxhv_dc_fp_t;

typedef struct {
	boolean_t	ldoms;
	nxhv_vr_fp_t	vr;
	nxhv_dc_fp_t	tx;
	nxhv_dc_fp_t	rx;
} nxhv_fp_t;

/* ------------------------------------------------------------------ */
#define	NXGE_VR_SR_MAX		8 /* There are 8 subregions (SR). */

typedef enum {
	NXGE_HIO_TYPE_SERVICE = 0x80,	/* We are a service domain driver. */
	NXGE_HIO_TYPE_GUEST		/* We are a guest domain driver. */
} nxge_hio_type_t;

typedef enum {
	FUNC0_MNT,
	FUNC0_VIR = 0x1000000,
	FUNC1_MNT = 0x2000000,
	FUNC1_VIR = 0x3000000,
	FUNC2_MNT = 0x4000000,
	FUNC2_VIR = 0x5000000,
	FUNC3_MNT = 0x6000000,
	FUNC3_VIR = 0x7000000
} vr_base_address_t;

#define	VR_STEP		0x2000000
#define	VR_VC_STEP	0x0004000

typedef enum {			/* 0-8 */
	FUNC0_VIR0,
	FUNC0_VIR1,
	FUNC1_VIR0,
	FUNC1_VIR1,
	FUNC2_VIR0,
	FUNC2_VIR1,
	FUNC3_VIR0,
	FUNC3_VIR1,
	FUNC_VIR_MAX
} vr_region_t;

typedef enum {
	VP_CHANNEL_0,
	VP_CHANNEL_1,
	VP_CHANNEL_2,
	VP_CHANNEL_3,
	VP_CHANNEL_4,
	VP_CHANNEL_5,
	VP_CHANNEL_6,
	VP_CHANNEL_7,
	VP_CHANNEL_MAX
} vp_channel_t;

typedef enum {
	VP_BOUND_TX = 1,
	VP_BOUND_RX
} vpc_type_t;

#define	VP_VC_OFFSET(channel)	(channel << 10)
#define	VP_RDC_OFFSET		(1 << 9)

typedef enum {
	RXDMA_CFIG1		= 0,
	RXDMA_CFIG2		= 8,
	RBR_CFIG_A		= 0x10,
	RBR_CFIG_B		= 0x18,
	RBR_KICK		= 0x20,
	RBR_STAT		= 0x28,
	RBR_HDH			= 0x30,
	RBR_HDL			= 0x38,
	RCRCFIG_A		= 0x40,
	RCRCFIG_B		= 0x48,
	RCRSTAT_A		= 0x50,
	RCRSTAT_B		= 0x58,
	RCRSTAT_C		= 0x60,
	RX_DMA_ENT_MSK		= 0x68,
	RX_DMA_CTL_STAT		= 0x70,
	RCR_FLSH		= 0x78,
	RXMISC			= 0x90,
	RX_DMA_CTL_STAT_DBG	= 0x98

} rdc_csr_offset_t;

typedef enum {
	Tx_RNG_CFIG		= 0,
	Tx_RNG_HDL		= 0x10,
	Tx_RNG_KICK		= 0x18,
	Tx_ENT_MASK		= 0x20,
	Tx_CS			= 0x28,
	TxDMA_MBH		= 0x30,
	TxDMA_MBL		= 0x38,
	TxDMA_PRE_ST		= 0x40,
	Tx_RNG_ERR_LOGH		= 0x48,
	Tx_RNG_ERR_LOGL		= 0x50,
	TDMC_INTR_DBG		= 0x60,
	Tx_CS_DBG		= 0x68

} tdc_csr_offset_t;

/*
 * -------------------------------------------------------------
 * These definitions are used to handle the virtual PIO_LDSV
 * space of a VR.
 * -------------------------------------------------------------
 */
#define	VLDG_OFFSET		0x2000
#define	VLDG_SLL		5

typedef enum {
	PIO_LDSV0,		/* ldf_0, 0-63 */
	PIO_LDSV1,		/* ldf_1, 0-63 */
	PIO_LDSV2,		/* ldf_0 & ldf_1, 64-69 */
	PIO_LDGIMGN		/* arm/timer */

} pio_ld_op_t;

#define	VR_INTR_BLOCK_SIZE	8
#define	HIO_INTR_BLOCK_SIZE	4

/* ------------------------------------------------------------------ */
typedef struct {
	const char	*name;
	int		offset;
} dmc_reg_name_t;

typedef struct {
	uintptr_t	nxge;
	dc_map_t	map;

} nx_rdc_tbl_t;

typedef struct nxge_hio_vr {
	uintptr_t	nxge;

	uint32_t	cookie;	/* The HV cookie. */
	uintptr_t	address;
	size_t		size;
	vr_region_t	region;	/* 1 of 8 regions. */

	int		rdc_tbl; /* 1 of 8 RDC tables. */
	int		tdc_tbl; /* 1 of 8 TDC tables. */
	ether_addr_t	altmac;	/* The alternate MAC address. */
	int		slot;	/* According to nxge_m_mmac_add(). */

	nxge_grp_t	rx_group;
	nxge_grp_t	tx_group;

} nxge_hio_vr_t;

typedef nxge_status_t (*dc_init_t)(nxge_t *, int);
typedef void (*dc_uninit_t)(nxge_t *, int);

typedef struct {
	uint32_t	number;	/* The LDG number assigned to this DC. */
	uint64_t	index;	/* Bits 7:5 of the (virtual) PIO_LDSV. */

	uint64_t	ldsv;	/* The logical device number */
	uint64_t	map;	/* Currently unused */

	int		vector;	/* The DDI vector number (index) */
} hio_ldg_t;

/*
 * -------------------------------------------------------------
 * The service domain driver makes use of both <index>, the index
 * into a VR's virtual page, and <channel>, the absolute channel
 * number, what we will call here the physical channel number.
 *
 * The guest domain will set both fields to the same value, since
 * it doesn't know any better.  And if a service domain owns a
 * DMA channel, it will also set both fields to the same value,
 * since it is not using a VR per se.
 * -------------------------------------------------------------
 */
typedef struct nx_dc {

	struct nx_dc	*next;

	nxge_hio_vr_t	*vr;	/* The VR belonged to. */

	vp_channel_t	page;	/* VP_CHANNEL_0 - VP_CHANNEL_7 */
	nxge_channel_t	channel; /* 1 of 16/24 channels */
	/*
	 * <channel> has its normal meaning. <page> refers to the
	 * virtual page of the VR that <channel> has been bound to.
	 * Therefore, in the service domain, <page> & <channel>
	 * are almost always different. While in a guest domain,
	 * they are always the same.
	 */
	vpc_type_t	type;	/* VP_BOUND_XX */
	dc_init_t	init;	/* nxge_init_xxdma_channel() */
	dc_uninit_t	uninit;	/* nxge_uninit_xxdma_channel() */

	nxge_grp_t	*group;	/* The group belonged to. */
	uint32_t	cookie;	/* The HV cookie. */

	hio_ldg_t	ldg;
	boolean_t	interrupting; /* Interrupt enabled? */

} nxge_hio_dc_t;

typedef struct {
	nxge_hio_type_t		type;

	kmutex_t		lock;
	int			vrs;
	unsigned		sequence;

	nxhv_fp_t		hio;

	/* vr[0] is reserved for the service domain. */
	nxge_hio_vr_t		vr[NXGE_VR_SR_MAX]; /* subregion map */
	nxge_hio_dc_t		rdc[NXGE_MAX_RDCS];
	nxge_hio_dc_t		tdc[NXGE_MAX_TDCS];

	nx_rdc_tbl_t		rdc_tbl[NXGE_MAX_RDC_GROUPS];

} nxge_hio_data_t;

/*
 * -------------------------------------------------------------
 * prototypes
 * -------------------------------------------------------------
 */
extern void nxge_get_environs(nxge_t *);
extern int nxge_hio_init(nxge_t *);
extern void nxge_hio_uninit(nxge_t *);

extern int nxge_dci_map(nxge_t *, vpc_type_t, int);

/*
 * ---------------------------------------------------------------------
 * These are the general-purpose DMA channel group functions.  That is,
 * these functions are used to manage groups of TDCs or RDCs in an HIO
 * environment.
 *
 * But is also expected that in the future they will be able to manage
 * Crossbow groups.
 * ---------------------------------------------------------------------
 */
extern nxge_grp_t *nxge_grp_add(nxge_t *, nxge_grp_type_t);
extern void nxge_grp_remove(nxge_t *, nxge_grp_t *);
extern int nxge_grp_dc_add(nxge_t *, nxge_grp_t *, vpc_type_t, int);
extern void nxge_grp_dc_remove(nxge_t *, vpc_type_t, int);
extern nxge_hio_dc_t *nxge_grp_dc_find(nxge_t *, vpc_type_t, int);

extern void nxge_delay(int);
extern const char *nxge_ddi_perror(int);

/*
 * ---------------------------------------------------------------------
 * These are the Sun4v HIO function prototypes.
 * ---------------------------------------------------------------------
 */
extern void nxge_hio_group_get(void *arg, mac_ring_type_t type, int group,
	mac_group_info_t *infop, mac_group_handle_t ghdl);
extern int nxge_hio_share_alloc(void *arg, mac_share_handle_t *shandle);
extern void nxge_hio_share_free(mac_share_handle_t shandle);
extern void nxge_hio_share_query(mac_share_handle_t shandle,
	mac_ring_type_t type, mac_ring_handle_t *rings, uint_t *n_rings);
extern int nxge_hio_share_add_group(mac_share_handle_t,
    mac_group_driver_t);
extern int nxge_hio_share_rem_group(mac_share_handle_t,
    mac_group_driver_t);
extern int nxge_hio_share_bind(mac_share_handle_t, uint64_t cookie,
    uint64_t *rcookie);
extern void nxge_hio_share_unbind(mac_share_handle_t);
extern int nxge_hio_rxdma_bind_intr(nxge_t *, rx_rcr_ring_t *, int);

				/* nxge_hio_guest.c */
extern void nxge_hio_unregister(nxge_t *);
extern int nxge_hio_get_dc_htable_idx(nxge_t *nxge, vpc_type_t type,
    uint32_t channel);

extern int nxge_guest_regs_map(nxge_t *);
extern void nxge_guest_regs_map_free(nxge_t *);

extern int nxge_hio_vr_add(nxge_t *nxge);
extern int nxge_hio_vr_release(nxge_t *nxge);

extern nxge_status_t nxge_tdc_lp_conf(p_nxge_t, int);
extern nxge_status_t nxge_rdc_lp_conf(p_nxge_t, int);

extern void nxge_hio_start_timer(nxge_t *);

				/* nxge_intr.c */
extern nxge_status_t nxge_hio_intr_init(nxge_t *);
extern void nxge_hio_intr_uninit(nxge_t *);

extern nxge_status_t nxge_intr_add(nxge_t *, vpc_type_t, int);
extern nxge_status_t nxge_intr_remove(nxge_t *, vpc_type_t, int);

extern nxge_status_t nxge_hio_intr_add(nxge_t *, vpc_type_t, int);
extern nxge_status_t nxge_hio_intr_remove(nxge_t *, vpc_type_t, int);

extern nxge_status_t nxge_hio_intr_add(nxge_t *, vpc_type_t, int);
extern nxge_status_t nxge_hio_intr_rem(nxge_t *, int);

extern int nxge_hio_ldsv_add(nxge_t *, nxge_hio_dc_t *);

extern void nxge_hio_ldsv_im(nxge_t *, nxge_ldg_t *, pio_ld_op_t, uint64_t *);
extern void nxge_hio_ldgimgn(nxge_t *, nxge_ldg_t *);

				/* nxge_hv.c */
extern void nxge_hio_hv_init(nxge_t *);

				/* nxge_mac.c */
extern int nxge_hio_hostinfo_get_rdc_table(p_nxge_t);
extern int nxge_hio_hostinfo_init(nxge_t *, nxge_hio_vr_t *, ether_addr_t *);
extern void nxge_hio_hostinfo_uninit(nxge_t *, nxge_hio_vr_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_HIO_H */
