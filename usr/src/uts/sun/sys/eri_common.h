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

#ifndef	_SYS_ERI_COMMON_H
#define	_SYS_ERI_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

typedef void	(*fptrv_t)();

typedef enum {
	ERI_NO_MSG		= 0,
	ERI_CON_MSG  		= 1,
	ERI_BUF_MSG		= 2,
	ERI_VERB_MSG		= 3,
	ERI_LOG_MSG		= 4
} msg_t;


#ifdef	DEBUG
static msg_t eri_msg_out = ERI_VERB_MSG;
#endif

#ifdef	LATER
static char	*fault_msg_string[] = {
	"NONE       ",
	"LOW        ",
	"MID        ",
	"HIGH       ",
	"UNKNOWN    "

};
#endif

#define	SEVERITY_UNKNOWN 0
#define	SEVERITY_NONE   0
#define	SEVERITY_LOW    0
#define	SEVERITY_MID    1
#define	SEVERITY_HIGH   2


#define	ERI_FAULT_MSG1(p, t, f, a) \
    eri_fault_msg((p), (t), (f), (a));

#define	ERI_FAULT_MSG2(p, t, f, a, b) \
    eri_fault_msg((p), (t), (f), (a), (b));

#define	ERI_FAULT_MSG3(p, t, f, a, b, c) \
    eri_fault_msg((p), (t), (f), (a), (b), (c));

#define	ERI_FAULT_MSG4(p, t, f, a, b, c, d) \
    eri_fault_msg((p), (t), (f), (a), (b), (c), (d));

#ifdef  DEBUG
typedef enum {
	NO_MSG		= 0,
	AUTOCONFIG_MSG  = 1,
	STREAMS_MSG	= 2,
	IOCTL_MSG	= 3,
	PROTO_MSG	= 4,
	INIT_MSG	= 5,
	TX_MSG		= 6,
	RX_MSG		= 7,
	INTR_MSG	= 8,
	UNINIT_MSG	= 9,
	CONFIG_MSG	= 10,
	PROP_MSG	= 11,
	ENTER_MSG	= 12,
	RESUME_MSG	= 13,
	AUTONEG_MSG	= 14,
	NAUTONEG_MSG	= 15,
	FATAL_ERR_MSG   = 16,
	NONFATAL_MSG  = 17,
	NDD_MSG		= 18,
	PHY_MSG		= 19,
	XCVR_MSG	= 20,
	NSUPPORT_MSG	= 21,
	ERX_MSG		= 22,
	FREE_MSG	= 23,
	IPG_MSG		= 24,
	DDI_MSG		= 25,
	DEFAULT_MSG	= 26,
	DISPLAY_MSG	= 27,
	DIAG_MSG	= 28,
	END_TRACE1_MSG	= 29,
	END_TRACE2_MSG	= 30,
	ASSERT_MSG	= 31,
	FRM_MSG		= 32,
	MIF_MSG		= 33,
	LINK_MSG	= 34,
	RESOURCE_MSG	= 35,
	LOOPBACK_MSG	= 36,
	VERBOSE_MSG	= 37,
	MODCTL_MSG	= 38,
	HWCSUM_MSG	= 39,
	CORRUPTION_MSG	= 40,
	EXIT_MSG	= 41,
	DLCAPAB_MSG	= 42

} debug_msg_t;

static debug_msg_t	eri_debug_level = NO_MSG;
static debug_msg_t	eri_debug_all = NO_MSG;

static char	*debug_msg_string[] = {
	"NONE       ",
	"AUTOCONFIG ",
	"STREAMS    ",
	"IOCTL      ",
	"PROTO      ",
	"INIT       ",
	"TX         ",
	"RX         ",
	"INTR       ",
	"UNINIT         ",
	"CONFIG ",
	"PROP   ",
	"ENTER  ",
	"RESUME ",
	"AUTONEG        ",
	"NAUTONEG       ",
	"FATAL_ERR      ",
	"NFATAL_ERR     ",
	"NDD    ",
	"PHY    ",
	"XCVR   ",
	"NSUPPOR        ",
	"ERX    ",
	"FREE   ",
	"IPG    ",
	"DDI    ",
	"DEFAULT        ",
	"DISPLAY        ",
	"DIAG	",
	"TRACE1 ",
	"TRACE2 ",
	"ASSERT",
	"FRM	",
	"MIF	",
	"LINK	",
	"RESOURCE",
	"LOOPBACK",
	"VERBOSE",
	"MODCTL",
	"HWCSUM",
	"CORRUPTION",
	"EXIT",
	"DLCAPAB"
};

static void	eri_debug_msg(const char *, int, struct eri *, debug_msg_t,
    const char *, ...);

#define	ERI_DEBUG_MSG1(t, f, a) \
    eri_debug_msg(__FILE__, __LINE__, (t), (f), (a));

#define	ERI_DEBUG_MSG2(t, f, a, b) \
    eri_debug_msg(__FILE__, __LINE__, (t), (f), (a), (b));

#define	ERI_DEBUG_MSG3(t, f, a, b, c) \
    eri_debug_msg(__FILE__, __LINE__, (t), (f), (a), (b), (c));

#define	ERI_DEBUG_MSG4(t, f, a, b, c, d) \
    eri_debug_msg(__FILE__, __LINE__, (t), (f), (a), (b), (c), (d));

#define	ERI_DEBUG_MSG5(t, f, a, b, c, d, e) \
    eri_debug_msg(__FILE__, __LINE__, (t), (f), (a), (b), (c), (d), (e));

#else

#define	ERI_DEBUG_MSG1(t, f, a)
#define	ERI_DEBUG_MSG2(t, f, a, b)
#define	ERI_DEBUG_MSG3(t, f, a, b, c)
#define	ERI_DEBUG_MSG4(t, f, a, b, c, d)
#define	ERI_DEBUG_MSG5(t, f, a, b, c, d, e)
#define	ERI_DEBUG_MSG6(t, f, a, b, c, d, e, g, h)
#endif

#define	ERI_HWCSUM

/*
 * ERI REV 1.0 has some hardware bugs which doesn't alow it
 * to function to full features. We define this flag to disable
 * the features affected by these bugs.
 */
#ifdef ERI_ERI_REV_1_0
#define		RCV_OVRFLOW_CORRUPTION_BUG
#endif

#define		ERI_HDX_BUG_WORKAROUND
#define		ERI_TX_HUNG
/*
 * In forced speed mode when changing mode from 10 (force) to
 * 10 (force), such as changing from 10/half to 10/full,
 * the driver does not receive a MIF interrupt even though
 * the XCVR status indicates that the link is up, and this
 * is probably caused by the link for some reason does not
 * go down.
 *
 * In forced mode, when changing speed/mode from 10 (force) to
 * 100 (force), the user needs to make sure that the link
 * partner is in forced mode as well by setting speed to
 * 100 and the mode to either full or half duplex or
 * else the link might not come up or come up with a mis-match mode.
 */
#define		ERI_10_10_FORCE_SPEED_WORKAROUND
/*
 * bits 15:0 of MIF status register contains 0 value
 * and it is not defined as described on GEM specification
 */
#define		ERI_MIF_POLL_STATUS_WORKAROUND
#define		ERI_STRETCH_RCV_BUFFER

#ifdef		ERI_STRETCH_RCV_BUFFER
#undef		ERIBUFSIZE
#define		ERIBUFSIZE	3904
#endif

#ifdef	notdef
#define		ERI_DONT_STRIP_CRC
#endif

#ifdef ERI_HWCSUM
#define	ERI_RCV_CKSUM
#endif

#ifdef	notdef
#define		ERI_SERVICE_ROUTINE
#endif
#define	ERIHIWAT	(128 * 1024)    /* hi-water mark */
#define	ERIRINDEX(i)	(i & erip->erirpending_mask)
#define	DONT_FLUSH	-1

/*
 * ddi_dma_sync() a TMD or RMD descriptor.
 */
#define	ERI_SYNCIOPB(erip, a, size, who) \
	(void) ddi_dma_sync((erip)->md_h, \
		((uintptr_t)(a) - (erip)->iopbkbase), \
		(size), \
		(who))

/* ------------------------------------------------------------------------- */
/*
 * Patchable debug flag.
 * Set this to nonzero to enable error messages.
 */

/*
 * The following parameters may be configured by the user. If they are not
 * configured by the user, the values will be based on the capabilities of
 * the transceiver.
 * The value "ERI_NOTUSR" is ORed with the parameter value to indicate values
 * which are NOT configured by the user.
 */

/* command */

#define	ND_BASE		('N' << 8)	/* base */
#define	ND_GET		(ND_BASE + 0)	/* Get a value */
#define	ND_SET		(ND_BASE + 1)	/* Set a value */

#define	ERI_ND_GET	ND_GET
#define	ERI_ND_SET	ND_SET
#define	ERI_NOTUSR	0x0f000000
#define	ERI_MASK_1BIT	0x1
#define	ERI_MASK_2BIT	0x3
#define	ERI_MASK_8BIT	0xff

#define	param_transceiver	(erip->param_arr[0].param_val)
#define	param_linkup		(erip->param_arr[1].param_val)
#define	param_speed		(erip->param_arr[2].param_val)
#define	param_mode		(erip->param_arr[3].param_val)
#define	param_ipg1		(erip->param_arr[4].param_val)
#define	param_ipg2		(erip->param_arr[5].param_val)
#define	param_use_intphy	(erip->param_arr[6].param_val)
#define	param_pace_count	(erip->param_arr[7].param_val)
#define	param_autoneg		(erip->param_arr[8].param_val)
#define	param_anar_100T4	(erip->param_arr[9].param_val)

#define	param_anar_100fdx	(erip->param_arr[10].param_val)
#define	param_anar_100hdx	(erip->param_arr[11].param_val)
#define	param_anar_10fdx	(erip->param_arr[12].param_val)
#define	param_anar_10hdx	(erip->param_arr[13].param_val)
#define	param_bmsr_ancap	(erip->param_arr[14].param_val)
#define	param_bmsr_100T4	(erip->param_arr[15].param_val)
#define	param_bmsr_100fdx	(erip->param_arr[16].param_val)
#define	param_bmsr_100hdx	(erip->param_arr[17].param_val)
#define	param_bmsr_10fdx	(erip->param_arr[18].param_val)
#define	param_bmsr_10hdx	(erip->param_arr[19].param_val)

#define	param_aner_lpancap	(erip->param_arr[20].param_val)
#define	param_anlpar_100T4	(erip->param_arr[21].param_val)
#define	param_anlpar_100fdx	(erip->param_arr[22].param_val)
#define	param_anlpar_100hdx	(erip->param_arr[23].param_val)
#define	param_anlpar_10fdx	(erip->param_arr[24].param_val)
#define	param_anlpar_10hdx	(erip->param_arr[25].param_val)
#define	param_lance_mode	(erip->param_arr[26].param_val)
#define	param_ipg0		(erip->param_arr[27].param_val)
#define	param_intr_blank_time		(erip->param_arr[28].param_val)
#define	param_intr_blank_packets	(erip->param_arr[29].param_val)
#define	param_serial_link	(erip->param_arr[30].param_val)

#define	param_non_serial_link	(erip->param_arr[31].param_val)
#define	param_select_link	(erip->param_arr[32].param_val)
#define	param_default_link	(erip->param_arr[33].param_val)
#define	param_link_in_use	(erip->param_arr[34].param_val)
#define	param_anar_asm_dir	(erip->param_arr[35].param_val)
#define	param_anar_pause	(erip->param_arr[36].param_val)
#define	param_bmsr_asm_dir	(erip->param_arr[37].param_val)
#define	param_bmsr_pause	(erip->param_arr[38].param_val)
#define	param_anlpar_pauseTX 	(erip->param_arr[49].param_val)
#define	param_anlpar_pauseRX 	(erip->param_arr[40].param_val)

/* <<<<<<<<<<<<<<<<<<<<<<  Register operations >>>>>>>>>>>>>>>>>>>>> */
#define	GET_PCSREG(reg) \
	ddi_get32(erip->pcsregh, (uint32_t *)&erip->pcsregp->reg)
#define	PUT_PCSREG(reg, value) \
	ddi_put32(erip->pcsregh, (uint32_t *)&erip->pcsregp->reg, value)
#define	GET_MIFREG(reg) \
	ddi_get32(erip->mifregh, (uint32_t *)&erip->mifregp->reg)
#define	PUT_MIFREG(reg, value) \
	ddi_put32(erip->mifregh, (uint32_t *)&erip->mifregp->reg, value)
#define	GET_ETXREG(reg) \
	ddi_get32(erip->etxregh, (uint32_t *)&erip->etxregp->reg)
#define	PUT_ETXREG(reg, value) \
	ddi_put32(erip->etxregh, (uint32_t *)&erip->etxregp->reg, value)
#define	GET_ERXREG(reg) \
	ddi_get32(erip->erxregh, (uint32_t *)&erip->erxregp->reg)
#define	PUT_ERXREG(reg, value) \
	ddi_put32(erip->erxregh, (uint32_t *)&erip->erxregp->reg, value)
#define	GET_MACREG(reg) \
	ddi_get32(erip->bmacregh, (uint32_t *)&erip->bmacregp->reg)
#define	PUT_MACREG(reg, value) \
	ddi_put32(erip->bmacregh, \
		(uint32_t *)&erip->bmacregp->reg, value)
#define	GET_GLOBREG(reg) \
	ddi_get32(erip->globregh, (uint32_t *)&erip->globregp->reg)
#define	PUT_GLOBREG(reg, value) \
	ddi_put32(erip->globregh, \
		(uint32_t *)&erip->globregp->reg, value)

#define	GET_SWRSTREG(reg) \
	ddi_get32(erip->sw_reset_regh, (uint32_t *)erip->sw_reset_reg)

#define	PUT_SWRSTREG(reg, value) \
	ddi_put32(erip->sw_reset_regh, \
	(uint32_t *)erip->sw_reset_reg, value)

/* ********************** Descriptor OPerations ******************** */

/* <<<<<<<<<<<<<<<<<<<<<  for Solaris 2.6 and 2.7 >>>>>>>>>>>>>>>>>>>> */

/* TMD and RMD Descriptor Operations */
#define	PUT_TMD(ptr, cookie, len, flags) \
	ddi_put64(erip->mdm_h, (uint64_t *)&ptr->tmd_addr, \
		cookie.dmac_laddress); \
	ddi_put64(erip->mdm_h, (uint64_t *)&ptr->tmd_flags, len | flags)

#define	PUT_TMD_FAST(ptr, cookie, len, flags) \
	ddi_put64(erip->mdm_h, (uint64_t *)&ptr->tmd_addr, \
		cookie.dmac_address); \
	ddi_put64(erip->mdm_h, (uint64_t *)&ptr->tmd_flags, len | flags)

#define	GET_TMD_FLAGS(ptr) \
	ddi_get64(erip->mdm_h, (uint64_t *)&ptr->tmd_flags)

#define	PUT_RMD(ptr, cookie) \
	ddi_put64(erip->mdm_h, (uint64_t *)&ptr->rmd_addr, \
		cookie.dmac_laddress); \
	ddi_put64(erip->mdm_h, (uint64_t *)&ptr->rmd_flags, \
	    (uint64_t)(ERI_BUFSIZE << ERI_RMD_BUFSIZE_SHIFT) | ERI_RMD_OWN)

#define	UPDATE_RMD(ptr) \
	ddi_put64(erip->mdm_h, (uint64_t *)&ptr->rmd_flags, \
	    (uint64_t)(ERI_BUFSIZE << ERI_RMD_BUFSIZE_SHIFT) | ERI_RMD_OWN)

#define	PUT_RMD_FAST(ptr, cookie) \
	ddi_put64(erip->mdm_h, (uint64_t *)&ptr->rmd_addr, \
		cookie.dmac_address); \
	ddi_put64(erip->mdm_h, (uint64_t *)&ptr->rmd_flags, \
	    (uint64_t)(ERI_BUFSIZE << ERI_RMD_BUFSIZE_SHIFT) | ERI_RMD_OWN)

#define	GET_RMD_FLAGS(ptr) \
	ddi_get64(erip->mdm_h, (uint64_t *)&ptr->rmd_flags)

#define	ENABLE_TXMAC(erip) \
	PUT_MACREG(txcfg, GET_MACREG(txcfg) | BMAC_TXCFG_ENAB)

#define	ENABLE_RXMAC(erip) \
	PUT_MACREG(rxcfg, GET_MACREG(rxcfg) | BMAC_RXCFG_ENAB)

#define	DISABLE_RXMAC(erip) \
	PUT_MACREG(rxcfg, GET_MACREG(rxcfg) & ~BMAC_RXCFG_ENAB)

#define	DISABLE_TXMAC(erip) \
	PUT_MACREG(txcfg, GET_MACREG(txcfg) & ~BMAC_TXCFG_ENAB)

#define	ENABLE_MAC(erip) \
	ENABLE_RXMAC(erip); \
	ENABLE_TXMAC(erip)

#define	DISABLE_MAC(erip) \
	DISABLE_RXMAC(erip); \
	DISABLE_TXMAC(erip)

#define	ENABLE_TXDMA(erip) \
	PUT_ETXREG(config,  GET_ETXREG(config) | GET_CONFIG_TXDMA_EN)

/* TODO : MBE : GER? */
#define	ENABLE_RXDMA(erip) \
	PUT_ERXREG(config,  GET_ERXREG(config) | GET_CONFIG_RXDMA_EN)


/*
 * Ether-type is specifically big-endian, but data region is unknown endian
 * Ether-type lives at offset 12 from the start of the packet.
 */

#define	get_ether_type(ptr) \
	(((((uint8_t *)ptr)[12] << 8) | (((uint8_t *)ptr)[13])))

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ERI_COMMON_H */
