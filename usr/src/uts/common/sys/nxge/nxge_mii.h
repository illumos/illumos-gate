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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_NXGE_NXGE_MII_H_
#define	_SYS_NXGE_NXGE_MII_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/miiregs.h>

/*
 * Configuration Register space.
 */

#define	NXGE_MII_LPRXNPR		8
#define	NXGE_MII_GCR			9
#define	NXGE_MII_GSR			10
#define	NXGE_MII_RES0			11
#define	NXGE_MII_RES1			12
#define	NXGE_MII_RES2			13
#define	NXGE_MII_RES3			14
#define	NXGE_MII_ESR			15

#define	NXGE_MII_SHADOW			MII_VENDOR(0xc)
/* Shadow register definition */
#define	NXGE_MII_MODE_CONTROL_REG	MII_VENDOR(0xf)

#define	NXGE_MAX_MII_REGS		32

/*
 * Configuration Register space.
 */
typedef struct _mii_regs {
	uchar_t bmcr;		/* Basic mode control register */
	uchar_t bmsr;		/* Basic mode status register */
	uchar_t idr1;		/* Phy identifier register 1 */
	uchar_t idr2;		/* Phy identifier register 2 */
	uchar_t anar;		/* Auto-Negotiation advertisement register */
	uchar_t anlpar;		/* Auto-Negotiation link Partner ability reg */
	uchar_t aner;		/* Auto-Negotiation expansion register */
	uchar_t nptxr;		/* Next page transmit register */
	uchar_t lprxnpr;	/* Link partner received next page register */
	uchar_t gcr;		/* Gigabit basic mode control register. */
	uchar_t gsr;		/* Gigabit basic mode status register */
	uchar_t mii_res1[4];	/* For future use by MII working group */
	uchar_t esr;		/* Extended status register. */
	uchar_t vendor_res[12];	/* For future use by Phy Vendors */
	uchar_t shadow;
	uchar_t vendor_res2[3]; /* For future use by Phy Vendors */
} mii_regs_t, *p_mii_regs_t;

/*
 * MII Register 0: Basic mode control register.
 */
typedef union _mii_bmcr {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t reset:1;
		uint16_t loopback:1;
		uint16_t speed_sel:1;
		uint16_t enable_autoneg:1;
		uint16_t power_down:1;
		uint16_t isolate:1;
		uint16_t restart_autoneg:1;
		uint16_t duplex_mode:1;
		uint16_t col_test:1;
		uint16_t speed_1000_sel:1;
		uint16_t res1:6;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res1:6;
		uint16_t speed_1000_sel:1;
		uint16_t col_test:1;
		uint16_t duplex_mode:1;
		uint16_t restart_autoneg:1;
		uint16_t isolate:1;
		uint16_t power_down:1;
		uint16_t enable_autoneg:1;
		uint16_t speed_sel:1;
		uint16_t loopback:1;
		uint16_t reset:1;
#endif
	} bits;
} mii_bmcr_t, *p_mii_bmcr_t;

/*
 * MII Register 1:  Basic mode status register.
 */
typedef union _mii_bmsr {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t link_100T4:1;
		uint16_t link_100fdx:1;
		uint16_t link_100hdx:1;
		uint16_t link_10fdx:1;
		uint16_t link_10hdx:1;
		uint16_t res2:2;
		uint16_t extend_status:1;
		uint16_t res1:1;
		uint16_t preamble_supress:1;
		uint16_t auto_neg_complete:1;
		uint16_t remote_fault:1;
		uint16_t auto_neg_able:1;
		uint16_t link_status:1;
		uint16_t jabber_detect:1;
		uint16_t ext_cap:1;
#elif defined(_BIT_FIELDS_LTOH)
		int16_t ext_cap:1;
		uint16_t jabber_detect:1;
		uint16_t link_status:1;
		uint16_t auto_neg_able:1;
		uint16_t remote_fault:1;
		uint16_t auto_neg_complete:1;
		uint16_t preamble_supress:1;
		uint16_t res1:1;
		uint16_t extend_status:1;
		uint16_t res2:2;
		uint16_t link_10hdx:1;
		uint16_t link_10fdx:1;
		uint16_t link_100hdx:1;
		uint16_t link_100fdx:1;
		uint16_t link_100T4:1;
#endif
	} bits;
} mii_bmsr_t, *p_mii_bmsr_t;

/*
 * MII Register 2: Physical Identifier 1.
 */
/* contains BCM OUI bits [3:18] */
typedef union _mii_idr1 {
	uint16_t value;
	struct {
		uint16_t ieee_address:16;
	} bits;
} mii_idr1_t, *p_mii_idr1_t;

/*
 * MII Register 3: Physical Identifier 2.
 */
typedef union _mii_idr2 {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t ieee_address:6;
		uint16_t model_no:6;
		uint16_t rev_no:4;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t rev_no:4;
		uint16_t model_no:6;
		uint16_t ieee_address:6;
#endif
	} bits;
} mii_idr2_t, *p_mii_idr2_t;

/*
 * MII Register 4: Auto-negotiation advertisement register.
 */
typedef union _mii_anar {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t np_indication:1;
		uint16_t acknowledge:1;
		uint16_t remote_fault:1;
		uint16_t res1:1;
		uint16_t cap_asmpause:1;
		uint16_t cap_pause:1;
		uint16_t cap_100T4:1;
		uint16_t cap_100fdx:1;
		uint16_t cap_100hdx:1;
		uint16_t cap_10fdx:1;
		uint16_t cap_10hdx:1;
		uint16_t selector:5;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t selector:5;
		uint16_t cap_10hdx:1;
		uint16_t cap_10fdx:1;
		uint16_t cap_100hdx:1;
		uint16_t cap_100fdx:1;
		uint16_t cap_100T4:1;
		uint16_t cap_pause:1;
		uint16_t cap_asmpause:1;
		uint16_t res1:1;
		uint16_t remote_fault:1;
		uint16_t acknowledge:1;
		uint16_t np_indication:1;
#endif
	} bits;
} mii_anar_t, *p_mii_anar_t;

/*
 * MII Register 5: Auto-negotiation link partner ability register.
 */
typedef mii_anar_t mii_anlpar_t, *pmii_anlpar_t;

/*
 * MII Register 6: Auto-negotiation expansion register.
 */
typedef union _mii_aner {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res:11;
		uint16_t mlf:1;
		uint16_t lp_np_able:1;
		uint16_t np_able:1;
		uint16_t page_rx:1;
		uint16_t lp_an_able:1;
#else
		uint16_t lp_an_able:1;
		uint16_t page_rx:1;
		uint16_t np_able:1;
		uint16_t lp_np_able:1;
		uint16_t mlf:1;
		uint16_t res:11;
#endif
	} bits;
} mii_aner_t, *p_mii_aner_t;

/*
 * MII Register 7: Next page transmit register.
 */
typedef	union _mii_nptxr {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t np:1;
		uint16_t res:1;
		uint16_t msgp:1;
		uint16_t ack2:1;
		uint16_t toggle:1;
		uint16_t res1:11;
#else
		uint16_t res1:11;
		uint16_t toggle:1;
		uint16_t ack2:1;
		uint16_t msgp:1;
		uint16_t res:1;
		uint16_t np:1;
#endif
	} bits;
} mii_nptxr_t, *p_mii_nptxr_t;

/*
 * MII Register 8: Link partner received next page register.
 */
typedef union _mii_lprxnpr {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t np:1;
			uint16_t ack:1;
		uint16_t msgp:1;
		uint16_t ack2:1;
		uint16_t toggle:1;
		uint16_t mcf:11;
#else
		uint16_t mcf:11;
		uint16_t toggle:1;
		uint16_t ack2:1;
		uint16_t msgp:1;
		uint16_t ack:1;
		uint16_t np:1;
#endif
	} bits;
} mii_lprxnpr_t, *p_mii_lprxnpr_t;

/*
 * MII Register 9: 1000BaseT control register.
 */
typedef union _mii_gcr {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t test_mode:3;
		uint16_t ms_mode_en:1;
		uint16_t master:1;
		uint16_t dte_or_repeater:1;
		uint16_t link_1000fdx:1;
		uint16_t link_1000hdx:1;
		uint16_t res:8;
#else
		uint16_t res:8;
		uint16_t link_1000hdx:1;
		uint16_t link_1000fdx:1;
		uint16_t dte_or_repeater:1;
		uint16_t master:1;
		uint16_t ms_mode_en:1;
		uint16_t test_mode:3;
#endif
	} bits;
} mii_gcr_t, *p_mii_gcr_t;

/*
 * MII Register 10: 1000BaseT status register.
 */
typedef union _mii_gsr {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t ms_config_fault:1;
		uint16_t ms_resolve:1;
		uint16_t local_rx_status:1;
		uint16_t remote_rx_status:1;
		uint16_t link_1000fdx:1;
		uint16_t link_1000hdx:1;
		uint16_t res:2;
		uint16_t idle_err_cnt:8;
#else
		uint16_t idle_err_cnt:8;
		uint16_t res:2;
		uint16_t link_1000hdx:1;
		uint16_t link_1000fdx:1;
		uint16_t remote_rx_status:1;
		uint16_t local_rx_status:1;
		uint16_t ms_resolve:1;
		uint16_t ms_config_fault:1;
#endif
	} bits;
} mii_gsr_t, *p_mii_gsr_t;

/*
 * MII Register 15: Extended status register.
 */
typedef union _mii_esr {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t link_1000Xfdx:1;
		uint16_t link_1000Xhdx:1;
		uint16_t link_1000fdx:1;
		uint16_t link_1000hdx:1;
		uint16_t res:12;
#else
			uint16_t res:12;
		uint16_t link_1000hdx:1;
		uint16_t link_1000fdx:1;
		uint16_t link_1000Xhdx:1;
		uint16_t link_1000Xfdx:1;
#endif
	} bits;
} mii_esr_t, *p_mii_esr_t;

#define	NXGE_MODE_SELECT_FIBER	0x01
/* Shadow regiser 0x11111 */
typedef union _mii_mode_control_stat {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t write_enable:1;
		uint16_t shadow:5;
		uint16_t rsv:1;
		uint16_t change:1;
		uint16_t copper:1;
		uint16_t fiber:1;
		uint16_t copper_energy:1;
		uint16_t fiber_signal:1;
		uint16_t rsv1:1;
		uint16_t mode:2;
		uint16_t enable:1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t enable:1;
		uint16_t mode:2;
		uint16_t rsv1:1;
		uint16_t fiber_signal:1;
		uint16_t copper_energy:1;
		uint16_t fiber:1;
		uint16_t copper:1;
		uint16_t change:1;
		uint16_t rsv:1;
		uint16_t shadow:5;
		uint16_t write_enable:1;
#endif
	} bits;
} mii_mode_control_stat_t, *p_mode_control_stat_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NXGE_NXGE_MII_H_ */
