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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * SunOS MT STREAMS FEPS(SBus)/Cheerio(PCI) 10/100Mb Ethernet Device Driver
 */

#include	<sys/types.h>
#include	<sys/debug.h>
#include	<sys/stream.h>
#include	<sys/cmn_err.h>
#include	<sys/kmem.h>
#include	<sys/crc32.h>
#include	<sys/modctl.h>
#include	<sys/conf.h>
#include	<sys/strsun.h>
#include	<sys/kstat.h>
#include	<sys/pattr.h>
#include	<sys/dlpi.h>
#include	<sys/strsubr.h>
#include	<sys/mac_provider.h>
#include	<sys/mac_ether.h>
#include	<sys/mii.h>
#include	<sys/ethernet.h>
#include	<sys/vlan.h>
#include	<sys/pci.h>
#include	<sys/policy.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/byteorder.h>
#include	"hme_phy.h"
#include	"hme_mac.h"
#include	"hme.h"

typedef void	(*fptrv_t)();

typedef enum {
	NO_MSG		= 0,
	AUTOCONFIG_MSG,
	DISPLAY_MSG,
	INIT_MSG,
	UNINIT_MSG,
	CONFIG_MSG,
	MII_MSG,
	FATAL_ERR_MSG,
	NFATAL_ERR_MSG,
	XCVR_MSG,
	NOXCVR_MSG,
	ERX_MSG,
	DDI_MSG,
} msg_t;

msg_t	hme_debug_level =	NO_MSG;

static char	*msg_string[] = {
	"NONE       ",
	"AUTOCONFIG ",
	"DISPLAY	"
	"INIT       ",
	"UNINIT		",
	"CONFIG	",
	"MII	",
	"FATAL_ERR	",
	"NFATAL_ERR	",
	"XCVR	",
	"NOXCVR	",
	"ERX	",
	"DDI	",
};

#define	SEVERITY_NONE	0
#define	SEVERITY_LOW	0
#define	SEVERITY_MID	1
#define	SEVERITY_HIGH	2
#define	SEVERITY_UNKNOWN 99

#define	FEPS_URUN_BUG
#define	HME_CODEVIOL_BUG

#define	KIOIP	KSTAT_INTR_PTR(hmep->hme_intrstats)

/*
 * The following variables are used for checking fixes in Sbus/FEPS 2.0
 */
static	int	hme_urun_fix = 0;	/* Bug fixed in Sbus/FEPS 2.0 */

/*
 * The following variables are used for configuring various features
 */
static	int	hme_64bit_enable =	1;	/* Use 64-bit sbus transfers */
static	int	hme_reject_own =	1;	/* Reject packets with own SA */
static	int	hme_ngu_enable =	0;	/* Never Give Up mode */

char *hme_priv_prop[] = {
	"_ipg0",
	"_ipg1",
	"_ipg2",
	"_lance_mode",
	NULL
};

static	int	hme_lance_mode =	1;	/* to enable lance mode */
static	int	hme_ipg0 =		16;
static	int	hme_ipg1 =		8;
static	int	hme_ipg2 =		4;

/*
 * The following parameters may be configured by the user. If they are not
 * configured by the user, the values will be based on the capabilities of
 * the transceiver.
 * The value "HME_NOTUSR" is ORed with the parameter value to indicate values
 * which are NOT configured by the user.
 */

#define	HME_NOTUSR	0x0f000000
#define	HME_MASK_1BIT	0x1
#define	HME_MASK_5BIT	0x1f
#define	HME_MASK_8BIT	0xff

/*
 * All strings used by hme messaging functions
 */

static	char *no_xcvr_msg =
	"No transceiver found.";

static	char *burst_size_msg =
	"Could not identify the burst size";

static	char *unk_rx_ringsz_msg =
	"Unknown receive RINGSZ";

static  char *add_intr_fail_msg =
	"ddi_add_intr(9F) failed";

static  char *mregs_4global_reg_fail_msg =
	"ddi_regs_map_setup(9F) for global reg failed";

static	char *mregs_4etx_reg_fail_msg =
	"ddi_map_regs for etx reg failed";

static	char *mregs_4erx_reg_fail_msg =
	"ddi_map_regs for erx reg failed";

static	char *mregs_4bmac_reg_fail_msg =
	"ddi_map_regs for bmac reg failed";

static	char *mregs_4mif_reg_fail_msg =
	"ddi_map_regs for mif reg failed";

static	char *init_fail_gen_msg =
	"Failed to initialize hardware/driver";

static	char *ddi_nregs_fail_msg =
	"ddi_dev_nregs failed(9F), returned %d";

static	char *bad_num_regs_msg =
	"Invalid number of registers.";


/* FATAL ERR msgs */
/*
 * Function prototypes.
 */
/* these two are global so that qfe can use them */
int hmeattach(dev_info_t *, ddi_attach_cmd_t);
int hmedetach(dev_info_t *, ddi_detach_cmd_t);
int hmequiesce(dev_info_t *);
static	boolean_t hmeinit_xfer_params(struct hme *);
static	uint_t hmestop(struct hme *);
static	void hmestatinit(struct hme *);
static	int hmeallocthings(struct hme *);
static	void hmefreethings(struct hme *);
static	int hmeallocbuf(struct hme *, hmebuf_t *, int);
static	int hmeallocbufs(struct hme *);
static	void hmefreebufs(struct hme *);
static	void hmeget_hm_rev_property(struct hme *);
static	boolean_t hmestart(struct hme *, mblk_t *);
static	uint_t hmeintr(caddr_t);
static	void hmereclaim(struct hme *);
static	int hmeinit(struct hme *);
static	void hmeuninit(struct hme *hmep);
static 	mblk_t *hmeread(struct hme *, hmebuf_t *, uint32_t);
static	void hmesavecntrs(struct hme *);
static	void hme_fatal_err(struct hme *, uint_t);
static	void hme_nonfatal_err(struct hme *, uint_t);
static	int hmeburstsizes(struct hme *);
static	void send_bit(struct hme *, uint16_t);
static	uint16_t get_bit_std(uint8_t, struct hme *);
static	uint16_t hme_bb_mii_read(struct hme *, uint8_t, uint8_t);
static	void hme_bb_mii_write(struct hme *, uint8_t, uint8_t, uint16_t);
static	void hme_bb_force_idle(struct hme *);
static	uint16_t hme_mii_read(void *, uint8_t, uint8_t);
static	void hme_mii_write(void *, uint8_t, uint8_t, uint16_t);
static	void hme_setup_mac_address(struct hme *, dev_info_t *);
static	void hme_mii_notify(void *, link_state_t);

static void hme_fault_msg(struct hme *, uint_t, msg_t, char *, ...);

static void hme_check_acc_handle(char *, uint_t, struct hme *,
    ddi_acc_handle_t);

/*
 * Nemo (GLDv3) Functions.
 */
static int	hme_m_stat(void *, uint_t, uint64_t *);
static int	hme_m_start(void *);
static void	hme_m_stop(void *);
static int	hme_m_promisc(void *, boolean_t);
static int	hme_m_multicst(void *, boolean_t, const uint8_t *);
static int	hme_m_unicst(void *, const uint8_t *);
static mblk_t	*hme_m_tx(void *, mblk_t *);
static boolean_t	hme_m_getcapab(void *, mac_capab_t, void *);
static int hme_m_getprop(void *, const char *, mac_prop_id_t, uint_t, void *);
static void hme_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static int hme_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);

static mii_ops_t hme_mii_ops = {
	MII_OPS_VERSION,
	hme_mii_read,
	hme_mii_write,
	hme_mii_notify,
	NULL
};

static mac_callbacks_t hme_m_callbacks = {
	MC_GETCAPAB | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	hme_m_stat,
	hme_m_start,
	hme_m_stop,
	hme_m_promisc,
	hme_m_multicst,
	hme_m_unicst,
	hme_m_tx,
	NULL,
	NULL,
	hme_m_getcapab,
	NULL,
	NULL,
	hme_m_setprop,
	hme_m_getprop,
	hme_m_propinfo
};

DDI_DEFINE_STREAM_OPS(hme_dev_ops, nulldev, nulldev, hmeattach, hmedetach,
    nodev, NULL, D_MP, NULL, hmequiesce);

#define	HME_FAULT_MSG1(p, s, t, f) \
    hme_fault_msg((p), (s), (t), (f));

#define	HME_FAULT_MSG2(p, s, t, f, a) \
    hme_fault_msg((p), (s), (t), (f), (a));

#define	HME_FAULT_MSG3(p, s, t, f, a, b) \
    hme_fault_msg((p), (s), (t), (f), (a), (b));

#define	HME_FAULT_MSG4(p, s, t, f, a, b, c) \
    hme_fault_msg((p), (s), (t), (f), (a), (b), (c));

#define	CHECK_MIFREG() \
	hme_check_acc_handle(__FILE__, __LINE__, hmep, hmep->hme_mifregh)
#define	CHECK_ETXREG() \
	hme_check_acc_handle(__FILE__, __LINE__, hmep, hmep->hme_etxregh)
#define	CHECK_ERXREG() \
	hme_check_acc_handle(__FILE__, __LINE__, hmep, hmep->hme_erxregh)
#define	CHECK_MACREG() \
	hme_check_acc_handle(__FILE__, __LINE__, hmep, hmep->hme_bmacregh)
#define	CHECK_GLOBREG() \
	hme_check_acc_handle(__FILE__, __LINE__, hmep, hmep->hme_globregh)

/*
 * Claim the device is ultra-capable of burst in the beginning.  Use
 * the value returned by ddi_dma_burstsizes() to actually set the HME
 * global configuration register later.
 *
 * Sbus/FEPS supports burst sizes of 16, 32 and 64 bytes. Also, it supports
 * 32-bit and 64-bit Sbus transfers. Hence the dlim_burstsizes field contains
 * the the burstsizes in both the lo and hi words.
 */
#define	HMELIMADDRLO	((uint64_t)0x00000000)
#define	HMELIMADDRHI	((uint64_t)0xffffffff)

/*
 * Note that rx and tx data buffers can be arbitrarily aligned, but
 * that the descriptor rings need to be aligned on 2K boundaries, per
 * the spec.
 */
static ddi_dma_attr_t hme_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	(uint64_t)HMELIMADDRLO,	/* low address */
	(uint64_t)HMELIMADDRHI,	/* high address */
	(uint64_t)0x00ffffff,	/* address counter max */
	(uint64_t)HME_HMDALIGN,	/* alignment */
	(uint_t)0x00700070,	/* dlim_burstsizes for 32 and 64 bit xfers */
	(uint32_t)0x1,		/* minimum transfer size */
	(uint64_t)0x7fffffff,	/* maximum transfer size */
	(uint64_t)0x00ffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	512,			/* granularity */
	0			/* attribute flags */
};

static ddi_device_acc_attr_t hme_buf_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,	/* probably could allow merging & caching */
	DDI_DEFAULT_ACC,
};

static uchar_t pci_latency_timer = 0;

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	"Sun HME 10/100 Mb Ethernet",
	&hme_dev_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/* <<<<<<<<<<<<<<<<<<<<<<  Register operations >>>>>>>>>>>>>>>>>>>>> */

#define	GET_MIFREG(reg) \
	ddi_get32(hmep->hme_mifregh, (uint32_t *)&hmep->hme_mifregp->reg)
#define	PUT_MIFREG(reg, value) \
	ddi_put32(hmep->hme_mifregh, (uint32_t *)&hmep->hme_mifregp->reg, value)

#define	GET_ETXREG(reg) \
	ddi_get32(hmep->hme_etxregh, (uint32_t *)&hmep->hme_etxregp->reg)
#define	PUT_ETXREG(reg, value) \
	ddi_put32(hmep->hme_etxregh, (uint32_t *)&hmep->hme_etxregp->reg, value)
#define	GET_ERXREG(reg) \
	ddi_get32(hmep->hme_erxregh, (uint32_t *)&hmep->hme_erxregp->reg)
#define	PUT_ERXREG(reg, value) \
	ddi_put32(hmep->hme_erxregh, (uint32_t *)&hmep->hme_erxregp->reg, value)
#define	GET_MACREG(reg) \
	ddi_get32(hmep->hme_bmacregh, (uint32_t *)&hmep->hme_bmacregp->reg)
#define	PUT_MACREG(reg, value) \
	ddi_put32(hmep->hme_bmacregh, \
		(uint32_t *)&hmep->hme_bmacregp->reg, value)
#define	GET_GLOBREG(reg) \
	ddi_get32(hmep->hme_globregh, (uint32_t *)&hmep->hme_globregp->reg)
#define	PUT_GLOBREG(reg, value) \
	ddi_put32(hmep->hme_globregh, \
		(uint32_t *)&hmep->hme_globregp->reg, value)
#define	PUT_TMD(ptr, paddr, len, flags)					\
	ddi_put32(hmep->hme_tmd_acch, &hmep->hme_tmdp[ptr].tmd_addr, paddr); \
	ddi_put32(hmep->hme_tmd_acch, &hmep->hme_tmdp[ptr].tmd_flags,	\
	    len | flags)
#define	GET_TMD_FLAGS(ptr)					\
	ddi_get32(hmep->hme_tmd_acch, &hmep->hme_tmdp[ptr].tmd_flags)
#define	PUT_RMD(ptr, paddr) \
	ddi_put32(hmep->hme_rmd_acch, &hmep->hme_rmdp[ptr].rmd_addr, paddr); \
	ddi_put32(hmep->hme_rmd_acch, &hmep->hme_rmdp[ptr].rmd_flags,	\
	    (uint32_t)(HMEBUFSIZE << HMERMD_BUFSIZE_SHIFT) | HMERMD_OWN)
#define	GET_RMD_FLAGS(ptr)					\
	ddi_get32(hmep->hme_rmd_acch, &hmep->hme_rmdp[ptr].rmd_flags)

#define	GET_ROM8(offset) \
	ddi_get8((hmep->hme_romh), (offset))

/*
 * Ether_copy is not endian-correct. Define an endian-correct version.
 */
#define	ether_bcopy(a, b) (bcopy(a, b, 6))

/*
 * Ether-type is specifically big-endian, but data region is unknown endian
 */
#define	get_ether_type(ptr) \
	(((((uint8_t *)ptr)[12] << 8) | (((uint8_t *)ptr)[13])))

/* <<<<<<<<<<<<<<<<<<<<<<  Configuration Parameters >>>>>>>>>>>>>>>>>>>>> */

#define	BMAC_DEFAULT_JAMSIZE	(0x04)		/* jamsize equals 4 */
#define	BMAC_LONG_JAMSIZE	(0x10)		/* jamsize equals 0x10 */
static	int 	jamsize = BMAC_DEFAULT_JAMSIZE;


/*
 * Calculate the bit in the multicast address filter that selects the given
 * address.
 */

static uint32_t
hmeladrf_bit(const uint8_t *addr)
{
	uint32_t crc;

	CRC32(crc, addr, ETHERADDRL, -1U, crc32_table);

	/*
	 * Just want the 6 most significant bits.
	 */
	return (crc >> 26);
}

/* <<<<<<<<<<<<<<<<<<<<<<<<  Bit Bang Operations >>>>>>>>>>>>>>>>>>>>>>>> */

static void
send_bit(struct hme *hmep, uint16_t x)
{
	PUT_MIFREG(mif_bbdata, x);
	PUT_MIFREG(mif_bbclk, HME_BBCLK_LOW);
	PUT_MIFREG(mif_bbclk, HME_BBCLK_HIGH);
}


/*
 * To read the MII register bits according to the IEEE Standard
 */
static uint16_t
get_bit_std(uint8_t phyad, struct hme *hmep)
{
	uint16_t	x;

	PUT_MIFREG(mif_bbclk, HME_BBCLK_LOW);
	drv_usecwait(1);	/* wait for  >330 ns for stable data */
	if (phyad == HME_INTERNAL_PHYAD)
		x = (GET_MIFREG(mif_cfg) & HME_MIF_CFGM0) ? 1 : 0;
	else
		x = (GET_MIFREG(mif_cfg) & HME_MIF_CFGM1) ? 1 : 0;
	PUT_MIFREG(mif_bbclk, HME_BBCLK_HIGH);
	return (x);
}

#define	SEND_BIT(x)		send_bit(hmep, x)
#define	GET_BIT_STD(phyad, x)	x = get_bit_std(phyad, hmep)


static void
hme_bb_mii_write(struct hme *hmep, uint8_t phyad, uint8_t regad, uint16_t data)
{
	int	i;

	PUT_MIFREG(mif_bbopenb, 1);	/* Enable the MII driver */
	(void) hme_bb_force_idle(hmep);
	SEND_BIT(0); SEND_BIT(1);	/* <ST> */
	SEND_BIT(0); SEND_BIT(1);	/* <OP> */

	for (i = 4; i >= 0; i--) {		/* <AAAAA> */
		SEND_BIT((phyad >> i) & 1);
	}

	for (i = 4; i >= 0; i--) {		/* <RRRRR> */
		SEND_BIT((regad >> i) & 1);
	}

	SEND_BIT(1); SEND_BIT(0);	/* <TA> */

	for (i = 0xf; i >= 0; i--) {	/* <DDDDDDDDDDDDDDDD> */
		SEND_BIT((data >> i) & 1);
	}

	PUT_MIFREG(mif_bbopenb, 0);	/* Disable the MII driver */
	CHECK_MIFREG();
}

/* Return 0 if OK, 1 if error (Transceiver does not talk management) */
static uint16_t
hme_bb_mii_read(struct hme *hmep, uint8_t phyad, uint8_t regad)
{
	int		i;
	uint32_t	x;
	uint16_t	data = 0;

	PUT_MIFREG(mif_bbopenb, 1);	/* Enable the MII driver */
	(void) hme_bb_force_idle(hmep);
	SEND_BIT(0); SEND_BIT(1);	/* <ST> */
	SEND_BIT(1); SEND_BIT(0);	/* <OP> */
	for (i = 4; i >= 0; i--) {		/* <AAAAA> */
		SEND_BIT((phyad >> i) & 1);
	}
	for (i = 4; i >= 0; i--) {		/* <RRRRR> */
		SEND_BIT((regad >> i) & 1);
	}

	PUT_MIFREG(mif_bbopenb, 0);	/* Disable the MII driver */

	GET_BIT_STD(phyad, x);
	GET_BIT_STD(phyad, x);		/* <TA> */
	for (i = 0xf; i >= 0; i--) {	/* <DDDDDDDDDDDDDDDD> */
		GET_BIT_STD(phyad, x);
		data += (x << i);
	}
	/*
	 * Kludge to get the Transceiver out of hung mode
	 */
	GET_BIT_STD(phyad, x);
	GET_BIT_STD(phyad, x);
	GET_BIT_STD(phyad, x);
	CHECK_MIFREG();
	return (data);
}


static void
hme_bb_force_idle(struct hme *hmep)
{
	int	i;

	for (i = 0; i < 33; i++) {
		SEND_BIT(1);
	}
}

/* <<<<<<<<<<<<<<<<<<<<End of Bit Bang Operations >>>>>>>>>>>>>>>>>>>>>>>> */


/* <<<<<<<<<<<<< Frame Register used for MII operations >>>>>>>>>>>>>>>>>>>> */

/* Return 0 if OK, 1 if error (Transceiver does not talk management) */
static uint16_t
hme_mii_read(void *arg, uint8_t phyad, uint8_t regad)
{
	struct hme	*hmep = arg;
	uint32_t	frame;
	uint32_t	tmp_mif;
	uint32_t	tmp_xif;

	tmp_mif = GET_MIFREG(mif_cfg);
	tmp_xif = GET_MACREG(xifc);

	switch (phyad) {
	case HME_EXTERNAL_PHYAD:
		PUT_MIFREG(mif_cfg, tmp_mif | HME_MIF_CFGPS);
		PUT_MACREG(xifc, tmp_xif | BMAC_XIFC_MIIBUFDIS);
		break;
	case HME_INTERNAL_PHYAD:
		PUT_MIFREG(mif_cfg, tmp_mif & ~(HME_MIF_CFGPS));
		PUT_MACREG(xifc, tmp_xif & ~(BMAC_XIFC_MIIBUFDIS));
		break;
	default:
		return (0xffff);
	}

	if (!hmep->hme_frame_enable) {
		frame = (hme_bb_mii_read(hmep, phyad, regad));
		PUT_MACREG(xifc, tmp_xif);
		PUT_MIFREG(mif_cfg, tmp_mif);
		return (frame & 0xffff);
	}

	PUT_MIFREG(mif_frame,
	    HME_MIF_FRREAD | (phyad << HME_MIF_FRPHYAD_SHIFT) |
	    (regad << HME_MIF_FRREGAD_SHIFT));
/*
 *	HMEDELAY((*framerp & HME_MIF_FRTA0), HMEMAXRSTDELAY);
 */
	HMEDELAY((GET_MIFREG(mif_frame) & HME_MIF_FRTA0), 300);
	frame = GET_MIFREG(mif_frame);
	CHECK_MIFREG();

	PUT_MACREG(xifc, tmp_xif);
	PUT_MIFREG(mif_cfg, tmp_mif);

	if ((frame & HME_MIF_FRTA0) == 0) {


		HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, MII_MSG,
		    "MIF Read failure");
		return (0xffff);
	}
	return ((uint16_t)(frame & HME_MIF_FRDATA));
}

static void
hme_mii_write(void *arg, uint8_t phyad, uint8_t regad, uint16_t data)
{
	struct hme *hmep = arg;
	uint32_t frame;
	uint32_t tmp_mif;
	uint32_t tmp_xif;

	tmp_mif = GET_MIFREG(mif_cfg);
	tmp_xif = GET_MACREG(xifc);

	switch (phyad) {
	case HME_EXTERNAL_PHYAD:
		PUT_MIFREG(mif_cfg, tmp_mif | HME_MIF_CFGPS);
		PUT_MACREG(xifc, tmp_xif | BMAC_XIFC_MIIBUFDIS);
		break;
	case HME_INTERNAL_PHYAD:
		PUT_MIFREG(mif_cfg, tmp_mif & ~(HME_MIF_CFGPS));
		PUT_MACREG(xifc, tmp_xif & ~(BMAC_XIFC_MIIBUFDIS));
		break;
	default:
		return;
	}

	if (!hmep->hme_frame_enable) {
		hme_bb_mii_write(hmep, phyad, regad, data);
		PUT_MACREG(xifc, tmp_xif);
		PUT_MIFREG(mif_cfg, tmp_mif);
		return;
	}

	PUT_MIFREG(mif_frame,
	    HME_MIF_FRWRITE | (phyad << HME_MIF_FRPHYAD_SHIFT) |
	    (regad << HME_MIF_FRREGAD_SHIFT) | data);
/*
 *	HMEDELAY((*framerp & HME_MIF_FRTA0), HMEMAXRSTDELAY);
 */
	HMEDELAY((GET_MIFREG(mif_frame) & HME_MIF_FRTA0), 300);
	frame = GET_MIFREG(mif_frame);
	PUT_MACREG(xifc, tmp_xif);
	PUT_MIFREG(mif_cfg, tmp_mif);
	CHECK_MIFREG();
	if ((frame & HME_MIF_FRTA0) == 0) {
		HME_FAULT_MSG1(hmep, SEVERITY_MID, MII_MSG,
		    "MIF Write failure");
	}
}

static void
hme_mii_notify(void *arg, link_state_t link)
{
	struct hme *hmep = arg;

	if (link == LINK_STATE_UP) {
		(void) hmeinit(hmep);
	}
	mac_link_update(hmep->hme_mh, link);
}

/* <<<<<<<<<<<<<<<<<<<<<<<<<<<  LOADABLE ENTRIES  >>>>>>>>>>>>>>>>>>>>>>> */

int
_init(void)
{
	int	status;

	mac_init_ops(&hme_dev_ops, "hme");
	if ((status = mod_install(&modlinkage)) != 0) {
		mac_fini_ops(&hme_dev_ops);
	}
	return (status);
}

int
_fini(void)
{
	int	status;

	if ((status = mod_remove(&modlinkage)) == 0) {
		mac_fini_ops(&hme_dev_ops);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * ddi_dma_sync() a TMD or RMD descriptor.
 */
#define	HMESYNCRMD(num, who)				\
	(void) ddi_dma_sync(hmep->hme_rmd_dmah,		\
	    (num * sizeof (struct hme_rmd)),		\
	    sizeof (struct hme_rmd),			\
	    who)

#define	HMESYNCTMD(num, who)				\
	(void) ddi_dma_sync(hmep->hme_tmd_dmah,		\
	    (num * sizeof (struct hme_tmd)),		\
	    sizeof (struct hme_tmd),			\
	    who)

/*
 * Ethernet broadcast address definition.
 */
static	struct ether_addr	etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * MIB II broadcast/multicast packets
 */
#define	IS_BROADCAST(pkt) (bcmp(pkt, &etherbroadcastaddr, ETHERADDRL) == 0)
#define	IS_MULTICAST(pkt) ((pkt[0] & 01) == 1)
#define	BUMP_InNUcast(hmep, pkt) \
	if (IS_MULTICAST(pkt)) {			       \
		if (IS_BROADCAST(pkt)) {		       \
			hmep->hme_brdcstrcv++;		       \
		} else {				       \
			hmep->hme_multircv++;		       \
		}					       \
	}
#define	BUMP_OutNUcast(hmep, pkt) \
	if (IS_MULTICAST(pkt)) {			       \
		if (IS_BROADCAST(pkt)) {		       \
			hmep->hme_brdcstxmt++;		       \
		} else {				       \
			hmep->hme_multixmt++;		       \
		}					       \
	}

static int
hme_create_prop_from_kw(dev_info_t *dip, char *vpdname, char *vpdstr)
{
	char propstr[80];
	int i, needprop = 0;
	struct ether_addr local_mac;

	if (strcmp(vpdname, "NA") == 0) {
		(void) strcpy(propstr, "local-mac-address");
		needprop = 1;
	} else if (strcmp(vpdname, "Z0") == 0) {
		(void) strcpy(propstr, "model");
		needprop = 1;
	} else if (strcmp(vpdname, "Z1") == 0) {
		(void) strcpy(propstr, "board-model");
		needprop = 1;
	}

	if (needprop == 1) {

		if (strcmp(propstr, "local-mac-address") == 0) {
			for (i = 0; i < ETHERADDRL; i++)
				local_mac.ether_addr_octet[i] =
				    (uchar_t)vpdstr[i];
			if (ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, propstr,
			    (char *)local_mac.ether_addr_octet, ETHERADDRL)
			    != DDI_SUCCESS) {
				return (DDI_FAILURE);
			}
		} else {
			if (ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, propstr, vpdstr,
			    strlen(vpdstr)+1) != DDI_SUCCESS) {
				return (DDI_FAILURE);
			}
		}
	}
	return (0);
}

/*
 * Get properties from old VPD
 * for PCI cards
 */
static int
hme_get_oldvpd_props(dev_info_t *dip, int vpd_base)
{
	struct hme *hmep;
	int vpd_start, vpd_len, kw_start, kw_len, kw_ptr;
	char kw_namestr[3];
	char kw_fieldstr[256];
	int i;

	hmep = ddi_get_driver_private(dip);

	vpd_start = vpd_base;

	if ((GET_ROM8(&hmep->hme_romp[vpd_start]) & 0xff) != 0x90) {
		return (1); /* error */
	} else {
		vpd_len = 9;
	}

	/* Get local-mac-address */
	kw_start = vpd_start + 3; /* Location of 1st keyword */
	kw_ptr = kw_start;
	while ((kw_ptr - kw_start) < vpd_len) { /* Get all keywords */
		kw_namestr[0] = GET_ROM8(&hmep->hme_romp[kw_ptr]);
		kw_namestr[1] = GET_ROM8(&hmep->hme_romp[kw_ptr+1]);
		kw_namestr[2] = '\0';
		kw_len = (int)(GET_ROM8(&hmep->hme_romp[kw_ptr+2]) & 0xff);
		for (i = 0, kw_ptr += 3; i < kw_len; i++)
			kw_fieldstr[i] = GET_ROM8(&hmep->hme_romp[kw_ptr+i]);
		kw_fieldstr[i] = '\0';
		if (hme_create_prop_from_kw(dip, kw_namestr, kw_fieldstr)) {
			return (DDI_FAILURE);
		}
		kw_ptr += kw_len;
	} /* next keyword */

	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP, "model",
	    "SUNW,cheerio", strlen("SUNW,cheerio")+1) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	return (0);
}


/*
 * Get properties from new VPD
 * for CompactPCI cards
 */
static int
hme_get_newvpd_props(dev_info_t *dip, int vpd_base)
{
	struct hme *hmep;
	int vpd_start, vpd_len, kw_start, kw_len, kw_ptr;
	char kw_namestr[3];
	char kw_fieldstr[256];
	int maxvpdsize, i;

	hmep = ddi_get_driver_private(dip);

	maxvpdsize = 1024; /* Real size not known until after it is read */

	vpd_start = (int)((GET_ROM8(&(hmep->hme_romp[vpd_base+1])) & 0xff) |
	    ((GET_ROM8(&hmep->hme_romp[vpd_base+2]) & 0xff) << 8)) +3;
	vpd_start = vpd_base + vpd_start;
	while (vpd_start < (vpd_base + maxvpdsize)) { /* Get all VPDs */
		if ((GET_ROM8(&hmep->hme_romp[vpd_start]) & 0xff) != 0x90) {
			break; /* no VPD found */
		} else {
			vpd_len = (int)((GET_ROM8(&hmep->hme_romp[vpd_start
			    + 1]) & 0xff) | (GET_ROM8(&hmep->hme_romp[vpd_start
			    + 2]) & 0xff) << 8);
		}
		/* Get all keywords in this VPD */
		kw_start = vpd_start + 3; /* Location of 1st keyword */
		kw_ptr = kw_start;
		while ((kw_ptr - kw_start) < vpd_len) { /* Get all keywords */
			kw_namestr[0] = GET_ROM8(&hmep->hme_romp[kw_ptr]);
			kw_namestr[1] = GET_ROM8(&hmep->hme_romp[kw_ptr+1]);
			kw_namestr[2] = '\0';
			kw_len =
			    (int)(GET_ROM8(&hmep->hme_romp[kw_ptr+2]) & 0xff);
			for (i = 0, kw_ptr += 3; i < kw_len; i++)
				kw_fieldstr[i] =
				    GET_ROM8(&hmep->hme_romp[kw_ptr+i]);
			kw_fieldstr[i] = '\0';
			if (hme_create_prop_from_kw(dip, kw_namestr,
			    kw_fieldstr)) {
				return (DDI_FAILURE);
			}
			kw_ptr += kw_len;
		} /* next keyword */
		vpd_start += (vpd_len + 3);
	} /* next VPD */
	return (0);
}


/*
 * Get properties from VPD
 */
static int
hme_get_vpd_props(dev_info_t *dip)
{
	struct hme *hmep;
	int v0, v1, vpd_base;
	int i, epromsrchlimit;


	hmep = ddi_get_driver_private(dip);

	v0 = (int)(GET_ROM8(&(hmep->hme_romp[0])));
	v1 = (int)(GET_ROM8(&(hmep->hme_romp[1])));
	v0 = ((v0 & 0xff) << 8 | v1);

	if ((v0 & 0xffff) != 0x55aa) {
		cmn_err(CE_NOTE, " Valid pci prom not found \n");
		return (1);
	}

	epromsrchlimit = 4096;
	for (i = 2; i < epromsrchlimit; i++) {
		/* "PCIR" */
		if (((GET_ROM8(&(hmep->hme_romp[i])) & 0xff) == 'P') &&
		    ((GET_ROM8(&(hmep->hme_romp[i+1])) & 0xff) == 'C') &&
		    ((GET_ROM8(&(hmep->hme_romp[i+2])) & 0xff) == 'I') &&
		    ((GET_ROM8(&(hmep->hme_romp[i+3])) & 0xff) == 'R')) {
			vpd_base =
			    (int)((GET_ROM8(&(hmep->hme_romp[i+8])) & 0xff) |
			    (GET_ROM8(&(hmep->hme_romp[i+9])) & 0xff) << 8);
			break; /* VPD pointer found */
		}
	}

	/* No VPD found */
	if (vpd_base == 0) {
		cmn_err(CE_NOTE, " Vital Product Data pointer not found \n");
		return (1);
	}

	v0 = (int)(GET_ROM8(&(hmep->hme_romp[vpd_base])));
	if (v0 == 0x82) {
		if (hme_get_newvpd_props(dip, vpd_base))
			return (1);
		return (0);
	} else if (v0 == 0x90) {
		/* If we are are SUNW,qfe card, look for the Nth "NA" descr */
		if ((GET_ROM8(&hmep->hme_romp[vpd_base + 12])  != 0x79) &&
		    GET_ROM8(&hmep->hme_romp[vpd_base + 4 * 12]) == 0x79) {
			vpd_base += hmep->hme_devno * 12;
		}
		if (hme_get_oldvpd_props(dip, vpd_base))
			return (1);
		return (0);
	} else
		return (1);	/* unknown start byte in VPD */
}

/*
 * For x86, the BIOS doesn't map the PCI Rom register for the qfe
 * cards, so we have to extract it from the ebus bridge that is
 * function zero of the same device.  This is a bit of an ugly hack.
 * (The ebus bridge leaves the entire ROM mapped at base address
 * register 0x10.)
 */

typedef struct {
	struct hme 		*hmep;
	dev_info_t		*parent;
	uint8_t			bus, dev;
	ddi_acc_handle_t	acch;
	caddr_t			romp;
} ebus_rom_t;

static int
hme_mapebusrom(dev_info_t *dip, void *arg)
{
	int		*regs;
	unsigned	nregs;
	int		reg;
	ebus_rom_t	*rom = arg;
	struct hme	*hmep = rom->hmep;

	/*
	 * We only want to look at our peers.  Skip our parent.
	 */
	if (dip == rom->parent) {
		return (DDI_WALK_PRUNESIB);
	}

	if (ddi_get_parent(dip) != rom->parent)
		return (DDI_WALK_CONTINUE);

	if ((ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0,
	    "reg", &regs, &nregs)) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_PRUNECHILD);
	}

	if (nregs < 1) {
		ddi_prop_free(regs);
		return (DDI_WALK_PRUNECHILD);
	}
	reg = regs[0];
	ddi_prop_free(regs);

	/*
	 * Look for function 0 on our bus and device.  If the device doesn't
	 * match, it might be an alternate peer, in which case we don't want
	 * to examine any of its children.
	 */
	if ((PCI_REG_BUS_G(reg) != rom->bus) ||
	    (PCI_REG_DEV_G(reg) != rom->dev) ||
	    (PCI_REG_FUNC_G(reg) != 0)) {
		return (DDI_WALK_PRUNECHILD);
	}

	(void) ddi_regs_map_setup(dip, 1, &rom->romp, 0, 0, &hmep->hme_dev_attr,
	    &rom->acch);
	/*
	 * If we can't map the registers, the caller will notice that
	 * the acch is NULL.
	 */
	return (DDI_WALK_TERMINATE);
}

static int
hmeget_promebus(dev_info_t *dip)
{
	ebus_rom_t	rom;
	int		*regs;
	unsigned	nregs;
	struct hme	*hmep;

	hmep = ddi_get_driver_private(dip);

	bzero(&rom, sizeof (rom));

	/*
	 * For x86, the BIOS doesn't map the PCI Rom register for the qfe
	 * cards, so we have to extract it from the eBus bridge that is
	 * function zero.  This is a bit of an ugly hack.
	 */
	if ((ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0,
	    "reg", &regs, &nregs)) != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (nregs < 5) {
		ddi_prop_free(regs);
		return (DDI_FAILURE);
	}
	rom.hmep = hmep;
	rom.bus = PCI_REG_BUS_G(regs[0]);
	rom.dev = PCI_REG_DEV_G(regs[0]);
	hmep->hme_devno = rom.dev;
	rom.parent = ddi_get_parent(dip);

	/*
	 * The implementation of ddi_walk_devs says that we must not
	 * be called during autoconfiguration.  However, it turns out
	 * that it is safe to call this during our attach routine,
	 * because we are not a nexus device.
	 *
	 * Previously we rooted our search at our immediate parent,
	 * but this triggered an assertion panic in debug kernels.
	 */
	ddi_walk_devs(ddi_root_node(), hme_mapebusrom, &rom);

	if (rom.acch) {
		hmep->hme_romh = rom.acch;
		hmep->hme_romp = (unsigned char *)rom.romp;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
hmeget_promprops(dev_info_t *dip)
{
	struct hme *hmep;
	int rom_bar;
	ddi_acc_handle_t cfg_handle;
	struct {
		uint16_t vendorid;
		uint16_t devid;
		uint16_t command;
		uint16_t status;
		uint32_t junk1;
		uint8_t cache_line;
		uint8_t latency;
		uint8_t header;
		uint8_t bist;
		uint32_t base;
		uint32_t base14;
		uint32_t base18;
		uint32_t base1c;
		uint32_t base20;
		uint32_t base24;
		uint32_t base28;
		uint32_t base2c;
		uint32_t base30;
	} *cfg_ptr;

	hmep = ddi_get_driver_private(dip);


	/*
	 * map configuration space
	 */
	if (ddi_regs_map_setup(hmep->dip, 0, (caddr_t *)&cfg_ptr,
	    0, 0, &hmep->hme_dev_attr, &cfg_handle)) {
		return (DDI_FAILURE);
	}

	/*
	 * Enable bus-master and memory accesses
	 */
	ddi_put16(cfg_handle, &cfg_ptr->command,
	    PCI_COMM_SERR_ENABLE | PCI_COMM_PARITY_DETECT |
	    PCI_COMM_MAE | PCI_COMM_ME);

	/*
	 * Enable rom accesses
	 */
	rom_bar = ddi_get32(cfg_handle, &cfg_ptr->base30);
	ddi_put32(cfg_handle, &cfg_ptr->base30, rom_bar | 1);


	if ((ddi_regs_map_setup(dip, 2, (caddr_t *)&(hmep->hme_romp), 0, 0,
	    &hmep->hme_dev_attr, &hmep->hme_romh) != DDI_SUCCESS) &&
	    (hmeget_promebus(dip) != DDI_SUCCESS)) {

		if (cfg_ptr)
			ddi_regs_map_free(&cfg_handle);
		return (DDI_FAILURE);
	} else {
		if (hme_get_vpd_props(dip))
			return (DDI_FAILURE);
	}
	if (hmep->hme_romp)
		ddi_regs_map_free(&hmep->hme_romh);
	if (cfg_ptr)
		ddi_regs_map_free(&cfg_handle);
	return (DDI_SUCCESS);

}

static void
hmeget_hm_rev_property(struct hme *hmep)
{
	int	hm_rev;


	hm_rev = hmep->asic_rev;
	switch (hm_rev) {
	case HME_2P1_REVID:
	case HME_2P1_REVID_OBP:
		HME_FAULT_MSG2(hmep, SEVERITY_NONE, DISPLAY_MSG,
		    "SBus 2.1 Found (Rev Id = %x)", hm_rev);
		hmep->hme_frame_enable = 1;
		break;

	case HME_2P0_REVID:
		HME_FAULT_MSG2(hmep, SEVERITY_NONE, DISPLAY_MSG,
		    "SBus 2.0 Found (Rev Id = %x)", hm_rev);
		break;

	case HME_1C0_REVID:
		HME_FAULT_MSG2(hmep, SEVERITY_NONE, DISPLAY_MSG,
		    "PCI IO 1.0 Found (Rev Id = %x)", hm_rev);
		break;

	default:
		HME_FAULT_MSG3(hmep, SEVERITY_NONE, DISPLAY_MSG,
		    "%s (Rev Id = %x) Found",
		    (hm_rev == HME_2C0_REVID) ? "PCI IO 2.0" : "Sbus", hm_rev);
		hmep->hme_frame_enable = 1;
		hmep->hme_lance_mode_enable = 1;
		hmep->hme_rxcv_enable = 1;
		break;
	}
}

/*
 * Interface exists: make available by filling in network interface
 * record.  System will initialize the interface when it is ready
 * to accept packets.
 */
int
hmeattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct hme *hmep;
	mac_register_t *macp = NULL;
	int 	regno;
	int hm_rev = 0;
	int prop_len = sizeof (int);
	ddi_acc_handle_t cfg_handle;
	struct {
		uint16_t vendorid;
		uint16_t devid;
		uint16_t command;
		uint16_t status;
		uint8_t revid;
		uint8_t j1;
		uint16_t j2;
	} *cfg_ptr;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		if ((hmep = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		hmep->hme_flags &= ~HMESUSPENDED;

		mii_resume(hmep->hme_mii);

		if (hmep->hme_started)
			(void) hmeinit(hmep);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/*
	 * Allocate soft device data structure
	 */
	hmep = kmem_zalloc(sizeof (*hmep), KM_SLEEP);

	/*
	 * Might as well set up elements of data structure
	 */
	hmep->dip =		dip;
	hmep->instance = 	ddi_get_instance(dip);
	hmep->pagesize =	ddi_ptob(dip, (ulong_t)1); /* IOMMU PSize */

	/*
	 *  Might as well setup the driver private
	 * structure as part of the dip.
	 */
	ddi_set_driver_private(dip, hmep);

	/*
	 * Reject this device if it's in a slave-only slot.
	 */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
		    "Dev not used - dev in slave only slot");
		goto error_state;
	}

	/*
	 * Map in the device registers.
	 *
	 * Reg # 0 is the Global register set
	 * Reg # 1 is the ETX register set
	 * Reg # 2 is the ERX register set
	 * Reg # 3 is the BigMAC register set.
	 * Reg # 4 is the MIF register set
	 */
	if (ddi_dev_nregs(dip, &regno) != (DDI_SUCCESS)) {
		HME_FAULT_MSG2(hmep, SEVERITY_HIGH, INIT_MSG,
		    ddi_nregs_fail_msg, regno);
		goto error_state;
	}

	switch (regno) {
	case 5:
		hmep->hme_cheerio_mode = 0;
		break;
	case 2:
	case 3: /* for hot swap/plug, there will be 3 entries in "reg" prop */
		hmep->hme_cheerio_mode = 1;
		break;
	default:
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    bad_num_regs_msg);
		goto error_state;
	}

	/* Initialize device attributes structure */
	hmep->hme_dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;

	if (hmep->hme_cheerio_mode)
		hmep->hme_dev_attr.devacc_attr_endian_flags =
		    DDI_STRUCTURE_LE_ACC;
	else
		hmep->hme_dev_attr.devacc_attr_endian_flags =
		    DDI_STRUCTURE_BE_ACC;

	hmep->hme_dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (hmep->hme_cheerio_mode) {
		uint8_t		oldLT;
		uint8_t		newLT = 0;
		dev_info_t	*pdip;
		const char	*pdrvname;

		/*
		 * Map the PCI config space
		 */
		if (pci_config_setup(dip, &hmep->pci_config_handle) !=
		    DDI_SUCCESS) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
			    "pci_config_setup() failed..");
			goto error_state;
		}

		if (ddi_regs_map_setup(dip, 1,
		    (caddr_t *)&(hmep->hme_globregp), 0, 0,
		    &hmep->hme_dev_attr, &hmep->hme_globregh)) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
			    mregs_4global_reg_fail_msg);
			goto error_unmap;
		}
		hmep->hme_etxregh = hmep->hme_erxregh = hmep->hme_bmacregh =
		    hmep->hme_mifregh = hmep->hme_globregh;

		hmep->hme_etxregp =
		    (void *)(((caddr_t)hmep->hme_globregp) + 0x2000);
		hmep->hme_erxregp =
		    (void *)(((caddr_t)hmep->hme_globregp) + 0x4000);
		hmep->hme_bmacregp =
		    (void *)(((caddr_t)hmep->hme_globregp) + 0x6000);
		hmep->hme_mifregp =
		    (void *)(((caddr_t)hmep->hme_globregp) + 0x7000);

		/*
		 * Get parent pci bridge info.
		 */
		pdip = ddi_get_parent(dip);
		pdrvname = ddi_driver_name(pdip);

		oldLT = pci_config_get8(hmep->pci_config_handle,
		    PCI_CONF_LATENCY_TIMER);
		/*
		 * Honor value set in /etc/system
		 * "set hme:pci_latency_timer=0xYY"
		 */
		if (pci_latency_timer)
			newLT = pci_latency_timer;
		/*
		 * Modify LT for simba
		 */
		else if (strcmp("simba", pdrvname) == 0)
			newLT = 0xf0;
		/*
		 * Ensure minimum cheerio latency timer of 0x50
		 * Usually OBP or pci bridge should set this value
		 * based on cheerio
		 * min_grant * 8(33MHz) = 0x50 = 0xa * 0x8
		 * Some system set cheerio LT at 0x40
		 */
		else if (oldLT < 0x40)
			newLT = 0x50;

		/*
		 * Now program cheerio's pci latency timer with newLT
		 */
		if (newLT)
			pci_config_put8(hmep->pci_config_handle,
			    PCI_CONF_LATENCY_TIMER, (uchar_t)newLT);
	} else { /* Map register sets */
		if (ddi_regs_map_setup(dip, 0,
		    (caddr_t *)&(hmep->hme_globregp), 0, 0,
		    &hmep->hme_dev_attr, &hmep->hme_globregh)) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
			    mregs_4global_reg_fail_msg);
			goto error_state;
		}
		if (ddi_regs_map_setup(dip, 1,
		    (caddr_t *)&(hmep->hme_etxregp), 0, 0,
		    &hmep->hme_dev_attr, &hmep->hme_etxregh)) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
			    mregs_4etx_reg_fail_msg);
			goto error_unmap;
		}
		if (ddi_regs_map_setup(dip, 2,
		    (caddr_t *)&(hmep->hme_erxregp), 0, 0,
		    &hmep->hme_dev_attr, &hmep->hme_erxregh)) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
			    mregs_4erx_reg_fail_msg);
			goto error_unmap;
		}
		if (ddi_regs_map_setup(dip, 3,
		    (caddr_t *)&(hmep->hme_bmacregp), 0, 0,
		    &hmep->hme_dev_attr, &hmep->hme_bmacregh)) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
			    mregs_4bmac_reg_fail_msg);
			goto error_unmap;
		}

		if (ddi_regs_map_setup(dip, 4,
		    (caddr_t *)&(hmep->hme_mifregp), 0, 0,
		    &hmep->hme_dev_attr, &hmep->hme_mifregh)) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
			    mregs_4mif_reg_fail_msg);
			goto error_unmap;
		}
	} /* Endif cheerio_mode */

	/*
	 * Based on the hm-rev, set some capabilities
	 * Set up default capabilities for HM 2.0
	 */
	hmep->hme_frame_enable = 0;
	hmep->hme_lance_mode_enable = 0;
	hmep->hme_rxcv_enable = 0;

	/* NEW routine to get the properties */

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, hmep->dip, 0, "hm-rev",
	    (caddr_t)&hm_rev, &prop_len) == DDI_PROP_SUCCESS) {

		hmep->asic_rev = hm_rev;
		hmeget_hm_rev_property(hmep);
	} else {
		/*
		 * hm_rev property not found so, this is
		 * case of hot insertion of card without interpreting fcode.
		 * Get it from revid in config space after mapping it.
		 */
		if (ddi_regs_map_setup(hmep->dip, 0, (caddr_t *)&cfg_ptr,
		    0, 0, &hmep->hme_dev_attr, &cfg_handle)) {
			return (DDI_FAILURE);
		}
		/*
		 * Since this is cheerio-based PCI card, we write 0xC in the
		 * top 4 bits(4-7) of hm-rev and retain the bottom(0-3) bits
		 * for Cheerio version(1.0 or 2.0 = 0xC0 or 0xC1)
		 */
		hm_rev = ddi_get8(cfg_handle, &cfg_ptr->revid);
		hm_rev = HME_1C0_REVID | (hm_rev & HME_REV_VERS_MASK);
		hmep->asic_rev = hm_rev;
		if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
		    "hm-rev", (caddr_t)&hm_rev, sizeof (hm_rev)) !=
		    DDI_SUCCESS) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, AUTOCONFIG_MSG,
			    "ddi_prop_create error for hm_rev");
		}
		ddi_regs_map_free(&cfg_handle);

		hmeget_hm_rev_property(hmep);

		/* get info via VPD */
		if (hmeget_promprops(dip) != DDI_SUCCESS) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, AUTOCONFIG_MSG,
			    "no promprops");
		}
	}

	if (ddi_intr_hilevel(dip, 0)) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, NFATAL_ERR_MSG,
		    " high-level interrupts are not supported");
		goto error_unmap;
	}

	/*
	 * Get intr. block cookie so that mutex locks can be initialized.
	 */
	if (ddi_get_iblock_cookie(dip, 0, &hmep->hme_cookie) != DDI_SUCCESS)
		goto error_unmap;

	/*
	 * Initialize mutex's for this device.
	 */
	mutex_init(&hmep->hme_xmitlock, NULL, MUTEX_DRIVER, hmep->hme_cookie);
	mutex_init(&hmep->hme_intrlock, NULL, MUTEX_DRIVER, hmep->hme_cookie);

	/*
	 * Quiesce the hardware.
	 */
	(void) hmestop(hmep);

	/*
	 * Add interrupt to system
	 */
	if (ddi_add_intr(dip, 0, (ddi_iblock_cookie_t *)NULL,
	    (ddi_idevice_cookie_t *)NULL, hmeintr, (caddr_t)hmep)) {
		HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
		    add_intr_fail_msg);
		goto error_mutex;
	}

	/*
	 * Set up the ethernet mac address.
	 */
	hme_setup_mac_address(hmep, dip);

	if (!hmeinit_xfer_params(hmep))
		goto error_intr;

	if (hmeburstsizes(hmep) == DDI_FAILURE) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG, burst_size_msg);
		goto error_intr;
	}

	if (hmeallocthings(hmep) != DDI_SUCCESS) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, CONFIG_MSG,
		    "resource allocation failed");
		goto error_intr;
	}

	if (hmeallocbufs(hmep) != DDI_SUCCESS) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, CONFIG_MSG,
		    "buffer allocation failed");
		goto error_intr;
	}

	hmestatinit(hmep);

	/* our external (preferred) PHY is at address 0 */
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "first-phy", 0);

	hmep->hme_mii = mii_alloc(hmep, dip, &hme_mii_ops);
	if (hmep->hme_mii == NULL) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, CONFIG_MSG,
		    "mii_alloc failed");
		goto error_intr;
	}
	/* force a probe for the PHY */
	mii_probe(hmep->hme_mii);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, CONFIG_MSG,
		    "mac_alloc failed");
		goto error_intr;
	}
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = hmep;
	macp->m_dip = dip;
	macp->m_src_addr = hmep->hme_ouraddr.ether_addr_octet;
	macp->m_callbacks = &hme_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;
	macp->m_priv_props = hme_priv_prop;
	if (mac_register(macp, &hmep->hme_mh) != 0) {
		mac_free(macp);
		goto error_intr;
	}

	mac_free(macp);

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

	/*
	 * Failure Exit
	 */

error_intr:
	if (hmep->hme_cookie)
		ddi_remove_intr(dip, 0, (ddi_iblock_cookie_t)0);

	if (hmep->hme_mii)
		mii_free(hmep->hme_mii);

error_mutex:
	mutex_destroy(&hmep->hme_xmitlock);
	mutex_destroy(&hmep->hme_intrlock);

error_unmap:
	if (hmep->hme_globregh)
		ddi_regs_map_free(&hmep->hme_globregh);
	if (hmep->hme_cheerio_mode == 0) {
		if (hmep->hme_etxregh)
			ddi_regs_map_free(&hmep->hme_etxregh);
		if (hmep->hme_erxregh)
			ddi_regs_map_free(&hmep->hme_erxregh);
		if (hmep->hme_bmacregh)
			ddi_regs_map_free(&hmep->hme_bmacregh);
		if (hmep->hme_mifregh)
			ddi_regs_map_free(&hmep->hme_mifregh);
	} else {
		if (hmep->pci_config_handle)
			(void) pci_config_teardown(&hmep->pci_config_handle);
		hmep->hme_etxregh = hmep->hme_erxregh = hmep->hme_bmacregh =
		    hmep->hme_mifregh = hmep->hme_globregh = NULL;
	}

error_state:
	hmefreethings(hmep);
	hmefreebufs(hmep);

	if (hmep) {
		kmem_free((caddr_t)hmep, sizeof (*hmep));
		ddi_set_driver_private(dip, NULL);
	}

	return (DDI_FAILURE);
}

int
hmedetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct hme *hmep;

	if ((hmep = ddi_get_driver_private(dip)) == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		mii_suspend(hmep->hme_mii);
		hmep->hme_flags |= HMESUSPENDED;
		hmeuninit(hmep);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}


	if (mac_unregister(hmep->hme_mh) != 0) {
		return (DDI_FAILURE);
	}

	/*
	 * Make driver quiescent, we don't want to prevent the
	 * detach on failure.  Note that this should be redundant,
	 * since mac_stop should already have called hmeuninit().
	 */
	if (!(hmep->hme_flags & HMESUSPENDED)) {
		(void) hmestop(hmep);
	}

	if (hmep->hme_mii)
		mii_free(hmep->hme_mii);

	/*
	 * Remove instance of the intr
	 */
	ddi_remove_intr(dip, 0, (ddi_iblock_cookie_t)0);

	/*
	 * Unregister kstats.
	 */
	if (hmep->hme_ksp != NULL)
		kstat_delete(hmep->hme_ksp);
	if (hmep->hme_intrstats != NULL)
		kstat_delete(hmep->hme_intrstats);

	hmep->hme_ksp = NULL;
	hmep->hme_intrstats = NULL;

	/*
	 * Destroy all mutexes and data structures allocated during
	 * attach time.
	 *
	 * Note: at this time we should be the only thread accessing
	 * the structures for this instance.
	 */

	if (hmep->hme_globregh)
		ddi_regs_map_free(&hmep->hme_globregh);
	if (hmep->hme_cheerio_mode == 0) {
		if (hmep->hme_etxregh)
			ddi_regs_map_free(&hmep->hme_etxregh);
		if (hmep->hme_erxregh)
			ddi_regs_map_free(&hmep->hme_erxregh);
		if (hmep->hme_bmacregh)
			ddi_regs_map_free(&hmep->hme_bmacregh);
		if (hmep->hme_mifregh)
			ddi_regs_map_free(&hmep->hme_mifregh);
	} else {
		if (hmep->pci_config_handle)
			(void) pci_config_teardown(&hmep->pci_config_handle);
		hmep->hme_etxregh = hmep->hme_erxregh = hmep->hme_bmacregh =
		    hmep->hme_mifregh = hmep->hme_globregh = NULL;
	}

	mutex_destroy(&hmep->hme_xmitlock);
	mutex_destroy(&hmep->hme_intrlock);

	hmefreethings(hmep);
	hmefreebufs(hmep);

	ddi_set_driver_private(dip, NULL);
	kmem_free(hmep, sizeof (struct hme));

	return (DDI_SUCCESS);
}

int
hmequiesce(dev_info_t *dip)
{
	struct hme *hmep;

	if ((hmep = ddi_get_driver_private(dip)) == NULL)
		return (DDI_FAILURE);

	(void) hmestop(hmep);
	return (DDI_SUCCESS);
}

static boolean_t
hmeinit_xfer_params(struct hme *hmep)
{
	int hme_ipg1_conf, hme_ipg2_conf;
	int hme_ipg0_conf, hme_lance_mode_conf;
	int prop_len = sizeof (int);
	dev_info_t *dip;

	dip = hmep->dip;

	/*
	 * Set up the start-up values for user-configurable parameters
	 * Get the values from the global variables first.
	 * Use the MASK to limit the value to allowed maximum.
	 */
	hmep->hme_ipg1 = hme_ipg1 & HME_MASK_8BIT;
	hmep->hme_ipg2 = hme_ipg2 & HME_MASK_8BIT;
	hmep->hme_ipg0 = hme_ipg0 & HME_MASK_5BIT;

	/*
	 * Get the parameter values configured in .conf file.
	 */
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "ipg1",
	    (caddr_t)&hme_ipg1_conf, &prop_len) == DDI_PROP_SUCCESS) {
		hmep->hme_ipg1 = hme_ipg1_conf & HME_MASK_8BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "ipg2",
	    (caddr_t)&hme_ipg2_conf, &prop_len) == DDI_PROP_SUCCESS) {
		hmep->hme_ipg2 = hme_ipg2_conf & HME_MASK_8BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "ipg0",
	    (caddr_t)&hme_ipg0_conf, &prop_len) == DDI_PROP_SUCCESS) {
		hmep->hme_ipg0 = hme_ipg0_conf & HME_MASK_5BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "lance_mode",
	    (caddr_t)&hme_lance_mode_conf, &prop_len) == DDI_PROP_SUCCESS) {
		hmep->hme_lance_mode = hme_lance_mode_conf & HME_MASK_1BIT;
	}

	return (B_TRUE);
}

/*
 * Return 0 upon success, 1 on failure.
 */
static uint_t
hmestop(struct hme *hmep)
{
	/*
	 * Disable the Tx dma engine.
	 */
	PUT_ETXREG(config, (GET_ETXREG(config) & ~HMET_CONFIG_TXDMA_EN));
	HMEDELAY(((GET_ETXREG(state_mach) & 0x1f) == 0x1), HMEMAXRSTDELAY);

	/*
	 * Disable the Rx dma engine.
	 */
	PUT_ERXREG(config, (GET_ERXREG(config) & ~HMER_CONFIG_RXDMA_EN));
	HMEDELAY(((GET_ERXREG(state_mach) & 0x3f) == 0), HMEMAXRSTDELAY);

	/*
	 * By this time all things should be quiet, so hit the
	 * chip with a reset.
	 */
	PUT_GLOBREG(reset, HMEG_RESET_GLOBAL);

	HMEDELAY((GET_GLOBREG(reset) == 0), HMEMAXRSTDELAY);
	if (GET_GLOBREG(reset)) {
		return (1);
	}

	CHECK_GLOBREG();
	return (0);
}

static int
hmestat_kstat_update(kstat_t *ksp, int rw)
{
	struct hme *hmep;
	struct hmekstat *hkp;

	hmep = (struct hme *)ksp->ks_private;
	hkp = (struct hmekstat *)ksp->ks_data;

	if (rw != KSTAT_READ)
		return (EACCES);

	/*
	 * Update all the stats by reading all the counter registers.
	 * Counter register stats are not updated till they overflow
	 * and interrupt.
	 */

	mutex_enter(&hmep->hme_xmitlock);
	if (hmep->hme_flags & HMERUNNING) {
		hmereclaim(hmep);
		hmesavecntrs(hmep);
	}
	mutex_exit(&hmep->hme_xmitlock);

	hkp->hk_cvc.value.ul		= hmep->hme_cvc;
	hkp->hk_lenerr.value.ul		= hmep->hme_lenerr;
	hkp->hk_buff.value.ul		= hmep->hme_buff;
	hkp->hk_missed.value.ul		= hmep->hme_missed;
	hkp->hk_allocbfail.value.ul	= hmep->hme_allocbfail;
	hkp->hk_babl.value.ul		= hmep->hme_babl;
	hkp->hk_tmder.value.ul		= hmep->hme_tmder;
	hkp->hk_txlaterr.value.ul	= hmep->hme_txlaterr;
	hkp->hk_rxlaterr.value.ul	= hmep->hme_rxlaterr;
	hkp->hk_slvparerr.value.ul	= hmep->hme_slvparerr;
	hkp->hk_txparerr.value.ul	= hmep->hme_txparerr;
	hkp->hk_rxparerr.value.ul	= hmep->hme_rxparerr;
	hkp->hk_slverrack.value.ul	= hmep->hme_slverrack;
	hkp->hk_txerrack.value.ul	= hmep->hme_txerrack;
	hkp->hk_rxerrack.value.ul	= hmep->hme_rxerrack;
	hkp->hk_txtagerr.value.ul	= hmep->hme_txtagerr;
	hkp->hk_rxtagerr.value.ul	= hmep->hme_rxtagerr;
	hkp->hk_eoperr.value.ul		= hmep->hme_eoperr;
	hkp->hk_notmds.value.ul		= hmep->hme_notmds;
	hkp->hk_notbufs.value.ul	= hmep->hme_notbufs;
	hkp->hk_norbufs.value.ul	= hmep->hme_norbufs;

	/*
	 * Debug kstats
	 */
	hkp->hk_inits.value.ul		= hmep->inits;
	hkp->hk_phyfail.value.ul	= hmep->phyfail;

	/*
	 * xcvr kstats
	 */
	hkp->hk_asic_rev.value.ul	= hmep->asic_rev;

	return (0);
}

static void
hmestatinit(struct hme *hmep)
{
	struct	kstat	*ksp;
	struct	hmekstat	*hkp;
	const char *driver;
	int	instance;
	char	buf[16];

	instance = hmep->instance;
	driver = ddi_driver_name(hmep->dip);

	if ((ksp = kstat_create(driver, instance,
	    "driver_info", "net", KSTAT_TYPE_NAMED,
	    sizeof (struct hmekstat) / sizeof (kstat_named_t), 0)) == NULL) {
		HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, INIT_MSG,
		    "kstat_create failed");
		return;
	}

	(void) snprintf(buf, sizeof (buf), "%sc%d", driver, instance);
	hmep->hme_intrstats = kstat_create(driver, instance, buf, "controller",
	    KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT);
	if (hmep->hme_intrstats)
		kstat_install(hmep->hme_intrstats);

	hmep->hme_ksp = ksp;
	hkp = (struct hmekstat *)ksp->ks_data;
	kstat_named_init(&hkp->hk_cvc,			"code_violations",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_lenerr,		"len_errors",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_buff,			"buff",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_missed,		"missed",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_nocanput,		"nocanput",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_allocbfail,		"allocbfail",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_babl,			"babble",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_tmder,		"tmd_error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_txlaterr,		"tx_late_error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_rxlaterr,		"rx_late_error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_slvparerr,		"slv_parity_error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_txparerr,		"tx_parity_error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_rxparerr,		"rx_parity_error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_slverrack,		"slv_error_ack",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_txerrack,		"tx_error_ack",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_rxerrack,		"rx_error_ack",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_txtagerr,		"tx_tag_error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_rxtagerr,		"rx_tag_error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_eoperr,		"eop_error",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_notmds,		"no_tmds",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_notbufs,		"no_tbufs",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_norbufs,		"no_rbufs",
	    KSTAT_DATA_ULONG);

	/*
	 * Debugging kstats
	 */
	kstat_named_init(&hkp->hk_inits,		"inits",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_phyfail,		"phy_failures",
	    KSTAT_DATA_ULONG);

	/*
	 * xcvr kstats
	 */
	kstat_named_init(&hkp->hk_asic_rev,		"asic_rev",
	    KSTAT_DATA_ULONG);

	ksp->ks_update = hmestat_kstat_update;
	ksp->ks_private = (void *) hmep;
	kstat_install(ksp);
}

int
hme_m_getprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    void *val)
{
	struct hme *hmep = arg;
	int value;
	int rv;

	rv = mii_m_getprop(hmep->hme_mii, name, num, sz, val);
	if (rv != ENOTSUP)
		return (rv);

	switch (num) {
	case MAC_PROP_PRIVATE:
		break;
	default:
		return (ENOTSUP);
	}

	if (strcmp(name, "_ipg0") == 0) {
		value = hmep->hme_ipg0;
	} else if (strcmp(name, "_ipg1") == 0) {
		value = hmep->hme_ipg1;
	} else if (strcmp(name, "_ipg2") == 0) {
		value = hmep->hme_ipg2;
	} else if (strcmp(name, "_lance_mode") == 0) {
		value = hmep->hme_lance_mode;
	} else {
		return (ENOTSUP);
	}
	(void) snprintf(val, sz, "%d", value);
	return (0);
}

static void
hme_m_propinfo(void *arg, const char *name, mac_prop_id_t num,
    mac_prop_info_handle_t mph)
{
	struct hme *hmep = arg;

	mii_m_propinfo(hmep->hme_mii, name, num, mph);

	switch (num) {
	case MAC_PROP_PRIVATE: {
		char valstr[64];
		int default_val;

		if (strcmp(name, "_ipg0") == 0) {
			default_val = hme_ipg0;
		} else if (strcmp(name, "_ipg1") == 0) {
			default_val = hme_ipg1;
		} else if (strcmp(name, "_ipg2") == 0) {
			default_val = hme_ipg2;
		} if (strcmp(name, "_lance_mode") == 0) {
			default_val = hme_lance_mode;
		} else {
			return;
		}

		(void) snprintf(valstr, sizeof (valstr), "%d", default_val);
		mac_prop_info_set_default_str(mph, valstr);
		break;
	}
	}
}

int
hme_m_setprop(void *arg, const char *name, mac_prop_id_t num, uint_t sz,
    const void *val)
{
	struct hme *hmep = arg;
	int rv;
	long lval;
	boolean_t init = B_FALSE;

	rv = mii_m_setprop(hmep->hme_mii, name, num, sz, val);
	if (rv != ENOTSUP)
		return (rv);
	rv = 0;

	switch (num) {
	case MAC_PROP_PRIVATE:
		break;
	default:
		return (ENOTSUP);
	}

	(void) ddi_strtol(val, NULL, 0, &lval);

	if (strcmp(name, "_ipg1") == 0) {
		if ((lval >= 0) && (lval <= 255)) {
			hmep->hme_ipg1 = lval & 0xff;
			init = B_TRUE;
		} else {
			return (EINVAL);
		}

	} else if (strcmp(name, "_ipg2") == 0) {
		if ((lval >= 0) && (lval <= 255)) {
			hmep->hme_ipg2 = lval & 0xff;
			init = B_TRUE;
		} else {
			return (EINVAL);
		}

	} else if (strcmp(name, "_ipg0") == 0) {
		if ((lval >= 0) && (lval <= 31)) {
			hmep->hme_ipg0 = lval & 0xff;
			init = B_TRUE;
		} else {
			return (EINVAL);
		}
	} else if (strcmp(name, "_lance_mode") == 0) {
		if ((lval >= 0) && (lval <= 1)) {
			hmep->hme_lance_mode = lval & 0xff;
			init = B_TRUE;
		} else {
			return (EINVAL);
		}

	} else {
		rv = ENOTSUP;
	}

	if (init) {
		(void) hmeinit(hmep);
	}
	return (rv);
}


/*ARGSUSED*/
static boolean_t
hme_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	switch (cap) {
	case MAC_CAPAB_HCKSUM:
		*(uint32_t *)cap_data = HCKSUM_INET_PARTIAL;
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
}

static int
hme_m_promisc(void *arg, boolean_t on)
{
	struct hme *hmep = arg;

	hmep->hme_promisc = on;
	(void) hmeinit(hmep);
	return (0);
}

static int
hme_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct hme *hmep = arg;

	/*
	 * Set new interface local address and re-init device.
	 * This is destructive to any other streams attached
	 * to this device.
	 */
	mutex_enter(&hmep->hme_intrlock);
	bcopy(macaddr, &hmep->hme_ouraddr, ETHERADDRL);
	mutex_exit(&hmep->hme_intrlock);
	(void) hmeinit(hmep);
	return (0);
}

static int
hme_m_multicst(void *arg, boolean_t add, const uint8_t *macaddr)
{
	struct hme	*hmep = arg;
	uint32_t	ladrf_bit;
	boolean_t	doinit = B_FALSE;

	/*
	 * If this address's bit was not already set in the local address
	 * filter, add it and re-initialize the Hardware.
	 */
	ladrf_bit = hmeladrf_bit(macaddr);

	mutex_enter(&hmep->hme_intrlock);
	if (add) {
		hmep->hme_ladrf_refcnt[ladrf_bit]++;
		if (hmep->hme_ladrf_refcnt[ladrf_bit] == 1) {
			hmep->hme_ladrf[ladrf_bit >> 4] |=
			    1 << (ladrf_bit & 0xf);
			hmep->hme_multi++;
			doinit = B_TRUE;
		}
	} else {
		hmep->hme_ladrf_refcnt[ladrf_bit]--;
		if (hmep->hme_ladrf_refcnt[ladrf_bit] == 0) {
			hmep->hme_ladrf[ladrf_bit >> 4] &=
			    ~(1 << (ladrf_bit & 0xf));
			doinit = B_TRUE;
		}
	}
	mutex_exit(&hmep->hme_intrlock);

	if (doinit) {
		(void) hmeinit(hmep);
	}

	return (0);
}

static int
hme_m_start(void *arg)
{
	struct hme *hmep = arg;

	if (hmeinit(hmep) != 0) {
		/* initialization failed -- really want DL_INITFAILED */
		return (EIO);
	} else {
		hmep->hme_started = B_TRUE;
		mii_start(hmep->hme_mii);
		return (0);
	}
}

static void
hme_m_stop(void *arg)
{
	struct hme *hmep = arg;

	mii_stop(hmep->hme_mii);
	hmep->hme_started = B_FALSE;
	hmeuninit(hmep);
}

static int
hme_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct hme	*hmep = arg;

	mutex_enter(&hmep->hme_xmitlock);
	if (hmep->hme_flags & HMERUNNING) {
		hmereclaim(hmep);
		hmesavecntrs(hmep);
	}
	mutex_exit(&hmep->hme_xmitlock);


	if (mii_m_getstat(hmep->hme_mii, stat, val) == 0) {
		return (0);
	}
	switch (stat) {
	case MAC_STAT_IPACKETS:
		*val = hmep->hme_ipackets;
		break;
	case MAC_STAT_RBYTES:
		*val = hmep->hme_rbytes;
		break;
	case MAC_STAT_IERRORS:
		*val = hmep->hme_ierrors;
		break;
	case MAC_STAT_OPACKETS:
		*val = hmep->hme_opackets;
		break;
	case MAC_STAT_OBYTES:
		*val = hmep->hme_obytes;
		break;
	case MAC_STAT_OERRORS:
		*val = hmep->hme_oerrors;
		break;
	case MAC_STAT_MULTIRCV:
		*val = hmep->hme_multircv;
		break;
	case MAC_STAT_MULTIXMT:
		*val = hmep->hme_multixmt;
		break;
	case MAC_STAT_BRDCSTRCV:
		*val = hmep->hme_brdcstrcv;
		break;
	case MAC_STAT_BRDCSTXMT:
		*val = hmep->hme_brdcstxmt;
		break;
	case MAC_STAT_UNDERFLOWS:
		*val = hmep->hme_uflo;
		break;
	case MAC_STAT_OVERFLOWS:
		*val = hmep->hme_oflo;
		break;
	case MAC_STAT_COLLISIONS:
		*val = hmep->hme_coll;
		break;
	case MAC_STAT_NORCVBUF:
		*val = hmep->hme_norcvbuf;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = hmep->hme_noxmtbuf;
		break;
	case ETHER_STAT_LINK_DUPLEX:
		*val = hmep->hme_duplex;
		break;
	case ETHER_STAT_ALIGN_ERRORS:
		*val = hmep->hme_align_errors;
		break;
	case ETHER_STAT_FCS_ERRORS:
		*val = hmep->hme_fcs_errors;
		break;
	case ETHER_STAT_EX_COLLISIONS:
		*val = hmep->hme_excol;
		break;
	case ETHER_STAT_DEFER_XMTS:
		*val = hmep->hme_defer_xmts;
		break;
	case ETHER_STAT_SQE_ERRORS:
		*val = hmep->hme_sqe_errors;
		break;
	case ETHER_STAT_FIRST_COLLISIONS:
		*val = hmep->hme_fstcol;
		break;
	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = hmep->hme_tlcol;
		break;
	case ETHER_STAT_TOOLONG_ERRORS:
		*val = hmep->hme_toolong_errors;
		break;
	case ETHER_STAT_TOOSHORT_ERRORS:
		*val = hmep->hme_runt;
		break;
	case ETHER_STAT_CARRIER_ERRORS:
		*val = hmep->hme_carrier_errors;
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

static mblk_t *
hme_m_tx(void *arg, mblk_t *mp)
{
	struct hme *hmep = arg;
	mblk_t *next;

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (!hmestart(hmep, mp)) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

/*
 * Software IP checksum, for the edge cases that the
 * hardware can't handle.  See hmestart for more info.
 */
static uint16_t
hme_cksum(void *data, int len)
{
	uint16_t	*words = data;
	int		i, nwords = len / 2;
	uint32_t	sum = 0;

	/* just add up the words */
	for (i = 0; i < nwords; i++) {
		sum += *words++;
	}

	/* pick up residual byte ... assume even half-word allocations */
	if (len % 2) {
		sum += (*words & htons(0xff00));
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);

	return (~(sum & 0xffff));
}

static boolean_t
hmestart(struct hme *hmep, mblk_t *mp)
{
	uint32_t	len;
	boolean_t	retval = B_TRUE;
	hmebuf_t	*tbuf;
	uint32_t	txptr;

	uint32_t	csflags = 0;
	uint32_t	flags;
	uint32_t	start_offset;
	uint32_t	stuff_offset;

	mac_hcksum_get(mp, &start_offset, &stuff_offset, NULL, NULL, &flags);

	if (flags & HCK_PARTIALCKSUM) {
		if (get_ether_type(mp->b_rptr) == ETHERTYPE_VLAN) {
			start_offset += sizeof (struct ether_header) + 4;
			stuff_offset += sizeof (struct ether_header) + 4;
		} else {
			start_offset += sizeof (struct ether_header);
			stuff_offset += sizeof (struct ether_header);
		}
		csflags = HMETMD_CSENABL |
		    (start_offset << HMETMD_CSSTART_SHIFT) |
		    (stuff_offset << HMETMD_CSSTUFF_SHIFT);
	}

	mutex_enter(&hmep->hme_xmitlock);

	if (hmep->hme_flags & HMESUSPENDED) {
		hmep->hme_carrier_errors++;
		hmep->hme_oerrors++;
		goto bad;
	}

	if (hmep->hme_txindex != hmep->hme_txreclaim) {
		hmereclaim(hmep);
	}
	if ((hmep->hme_txindex - HME_TMDMAX) == hmep->hme_txreclaim)
		goto notmds;
	txptr = hmep->hme_txindex % HME_TMDMAX;
	tbuf = &hmep->hme_tbuf[txptr];

	/*
	 * Note that for checksum offload, the hardware cannot
	 * generate correct checksums if the packet is smaller than
	 * 64-bytes.  In such a case, we bcopy the packet and use
	 * a software checksum.
	 */

	len = msgsize(mp);
	if (len < 64) {
		/* zero fill the padding */
		bzero(tbuf->kaddr, 64);
	}
	mcopymsg(mp, tbuf->kaddr);

	if ((csflags != 0) && ((len < 64) ||
	    (start_offset > HMETMD_CSSTART_MAX) ||
	    (stuff_offset > HMETMD_CSSTUFF_MAX))) {
		uint16_t sum;
		sum = hme_cksum(tbuf->kaddr + start_offset,
		    len - start_offset);
		bcopy(&sum, tbuf->kaddr + stuff_offset, sizeof (sum));
		csflags = 0;
	}

	if (ddi_dma_sync(tbuf->dmah, 0, len, DDI_DMA_SYNC_FORDEV) ==
	    DDI_FAILURE) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, DDI_MSG,
		    "ddi_dma_sync failed");
	}

	/*
	 * update MIB II statistics
	 */
	BUMP_OutNUcast(hmep, tbuf->kaddr);

	PUT_TMD(txptr, tbuf->paddr, len,
	    HMETMD_OWN | HMETMD_SOP | HMETMD_EOP | csflags);

	HMESYNCTMD(txptr, DDI_DMA_SYNC_FORDEV);
	hmep->hme_txindex++;

	PUT_ETXREG(txpend, HMET_TXPEND_TDMD);
	CHECK_ETXREG();

	mutex_exit(&hmep->hme_xmitlock);

	hmep->hme_starts++;
	return (B_TRUE);

bad:
	mutex_exit(&hmep->hme_xmitlock);
	freemsg(mp);
	return (B_TRUE);

notmds:
	hmep->hme_notmds++;
	hmep->hme_wantw = B_TRUE;
	hmereclaim(hmep);
	retval = B_FALSE;
done:
	mutex_exit(&hmep->hme_xmitlock);

	return (retval);
}

/*
 * Initialize channel.
 * Return 0 on success, nonzero on error.
 *
 * The recommended sequence for initialization is:
 * 1. Issue a Global Reset command to the Ethernet Channel.
 * 2. Poll the Global_Reset bits until the execution of the reset has been
 *    completed.
 * 2(a). Use the MIF Frame/Output register to reset the transceiver.
 *	 Poll Register 0 to till the Resetbit is 0.
 * 2(b). Use the MIF Frame/Output register to set the PHY in in Normal-Op,
 *	 100Mbps and Non-Isolated mode. The main point here is to bring the
 *	 PHY out of Isolate mode so that it can generate the rx_clk and tx_clk
 *	 to the MII interface so that the Bigmac core can correctly reset
 *	 upon a software reset.
 * 2(c).  Issue another Global Reset command to the Ethernet Channel and poll
 *	  the Global_Reset bits till completion.
 * 3. Set up all the data structures in the host memory.
 * 4. Program the TX_MAC registers/counters (excluding the TX_MAC Configuration
 *    Register).
 * 5. Program the RX_MAC registers/counters (excluding the RX_MAC Configuration
 *    Register).
 * 6. Program the Transmit Descriptor Ring Base Address in the ETX.
 * 7. Program the Receive Descriptor Ring Base Address in the ERX.
 * 8. Program the Global Configuration and the Global Interrupt Mask Registers.
 * 9. Program the ETX Configuration register (enable the Transmit DMA channel).
 * 10. Program the ERX Configuration register (enable the Receive DMA channel).
 * 11. Program the XIF Configuration Register (enable the XIF).
 * 12. Program the RX_MAC Configuration Register (Enable the RX_MAC).
 * 13. Program the TX_MAC Configuration Register (Enable the TX_MAC).
 */


#ifdef FEPS_URUN_BUG
static int hme_palen = 32;
#endif

static int
hmeinit(struct hme *hmep)
{
	uint32_t		i;
	int			ret;
	boolean_t		fdx;
	int			phyad;

	/*
	 * Lock sequence:
	 *	hme_intrlock, hme_xmitlock.
	 */
	mutex_enter(&hmep->hme_intrlock);

	/*
	 * Don't touch the hardware if we are suspended.  But don't
	 * fail either.  Some time later we may be resumed, and then
	 * we'll be back here to program the device using the settings
	 * in the soft state.
	 */
	if (hmep->hme_flags & HMESUSPENDED) {
		mutex_exit(&hmep->hme_intrlock);
		return (0);
	}

	/*
	 * This should prevent us from clearing any interrupts that
	 * may occur by temporarily stopping interrupts from occurring
	 * for a short time.  We need to update the interrupt mask
	 * later in this function.
	 */
	PUT_GLOBREG(intmask, ~HMEG_MASK_MIF_INTR);


	/*
	 * Rearranged the mutex acquisition order to solve the deadlock
	 * situation as described in bug ID 4065896.
	 */

	mutex_enter(&hmep->hme_xmitlock);

	hmep->hme_flags = 0;
	hmep->hme_wantw = B_FALSE;

	if (hmep->inits)
		hmesavecntrs(hmep);

	/*
	 * Perform Global reset of the Sbus/FEPS ENET channel.
	 */
	(void) hmestop(hmep);

	/*
	 * Clear all descriptors.
	 */
	bzero(hmep->hme_rmdp, HME_RMDMAX * sizeof (struct hme_rmd));
	bzero(hmep->hme_tmdp, HME_TMDMAX * sizeof (struct hme_tmd));

	/*
	 * Hang out receive buffers.
	 */
	for (i = 0; i < HME_RMDMAX; i++) {
		PUT_RMD(i, hmep->hme_rbuf[i].paddr);
	}

	/*
	 * DMA sync descriptors.
	 */
	(void) ddi_dma_sync(hmep->hme_rmd_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	(void) ddi_dma_sync(hmep->hme_tmd_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);

	/*
	 * Reset RMD and TMD 'walking' pointers.
	 */
	hmep->hme_rxindex = 0;
	hmep->hme_txindex = hmep->hme_txreclaim = 0;

	/*
	 * This is the right place to initialize MIF !!!
	 */

	PUT_MIFREG(mif_imask, HME_MIF_INTMASK);	/* mask all interrupts */

	if (!hmep->hme_frame_enable)
		PUT_MIFREG(mif_cfg, GET_MIFREG(mif_cfg) | HME_MIF_CFGBB);
	else
		PUT_MIFREG(mif_cfg, GET_MIFREG(mif_cfg) & ~HME_MIF_CFGBB);
						/* enable frame mode */

	/*
	 * Depending on the transceiver detected, select the source
	 * of the clocks for the MAC. Without the clocks, TX_MAC does
	 * not reset. When the Global Reset is issued to the Sbus/FEPS
	 * ASIC, it selects Internal by default.
	 */

	switch ((phyad = mii_get_addr(hmep->hme_mii))) {
	case -1:
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, XCVR_MSG, no_xcvr_msg);
		goto init_fail;	/* abort initialization */

	case HME_INTERNAL_PHYAD:
		PUT_MACREG(xifc, 0);
		break;
	case HME_EXTERNAL_PHYAD:
		/* Isolate the Int. xcvr */
		PUT_MACREG(xifc, BMAC_XIFC_MIIBUFDIS);
		break;
	}

	hmep->inits++;

	/*
	 * Initialize BigMAC registers.
	 * First set the tx enable bit in tx config reg to 0 and poll on
	 * it till it turns to 0. Same for rx config, hash and address
	 * filter reg.
	 * Here is the sequence per the spec.
	 * MADD2 - MAC Address 2
	 * MADD1 - MAC Address 1
	 * MADD0 - MAC Address 0
	 * HASH3, HASH2, HASH1, HASH0 for group address
	 * AFR2, AFR1, AFR0 and AFMR for address filter mask
	 * Program RXMIN and RXMAX for packet length if not 802.3
	 * RXCFG - Rx config for not stripping CRC
	 * XXX Anything else to hme configured in RXCFG
	 * IPG1, IPG2, ALIMIT, SLOT, PALEN, PAPAT, TXSFD, JAM, TXMAX, TXMIN
	 * if not 802.3 compliant
	 * XIF register for speed selection
	 * MASK  - Interrupt mask
	 * Set bit 0 of TXCFG
	 * Set bit 0 of RXCFG
	 */

	/*
	 * Initialize the TX_MAC registers
	 * Initialization of jamsize to work around rx crc bug
	 */
	PUT_MACREG(jam, jamsize);

#ifdef	FEPS_URUN_BUG
	if (hme_urun_fix)
		PUT_MACREG(palen, hme_palen);
#endif

	PUT_MACREG(ipg1, hmep->hme_ipg1);
	PUT_MACREG(ipg2, hmep->hme_ipg2);

	PUT_MACREG(rseed,
	    ((hmep->hme_ouraddr.ether_addr_octet[0] << 8) & 0x3) |
	    hmep->hme_ouraddr.ether_addr_octet[1]);

	/* Initialize the RX_MAC registers */

	/*
	 * Program BigMAC with local individual ethernet address.
	 */
	PUT_MACREG(madd2, (hmep->hme_ouraddr.ether_addr_octet[4] << 8) |
	    hmep->hme_ouraddr.ether_addr_octet[5]);
	PUT_MACREG(madd1, (hmep->hme_ouraddr.ether_addr_octet[2] << 8) |
	    hmep->hme_ouraddr.ether_addr_octet[3]);
	PUT_MACREG(madd0, (hmep->hme_ouraddr.ether_addr_octet[0] << 8) |
	    hmep->hme_ouraddr.ether_addr_octet[1]);

	/*
	 * Set up multicast address filter by passing all multicast
	 * addresses through a crc generator, and then using the
	 * low order 6 bits as a index into the 64 bit logical
	 * address filter. The high order three bits select the word,
	 * while the rest of the bits select the bit within the word.
	 */
	PUT_MACREG(hash0, hmep->hme_ladrf[0]);
	PUT_MACREG(hash1, hmep->hme_ladrf[1]);
	PUT_MACREG(hash2, hmep->hme_ladrf[2]);
	PUT_MACREG(hash3, hmep->hme_ladrf[3]);

	/*
	 * Configure parameters to support VLAN.  (VLAN encapsulation adds
	 * four bytes.)
	 */
	PUT_MACREG(txmax, ETHERMAX + ETHERFCSL + 4);
	PUT_MACREG(rxmax, ETHERMAX + ETHERFCSL + 4);

	/*
	 * Initialize HME Global registers, ETX registers and ERX registers.
	 */

	PUT_ETXREG(txring, hmep->hme_tmd_paddr);
	PUT_ERXREG(rxring, hmep->hme_rmd_paddr);

	/*
	 * ERX registers can be written only if they have even no. of bits set.
	 * So, if the value written is not read back, set the lsb and write
	 * again.
	 * static	int	hme_erx_fix = 1;   : Use the fix for erx bug
	 */
	{
		uint32_t temp;
		temp  = hmep->hme_rmd_paddr;

		if (GET_ERXREG(rxring) != temp)
			PUT_ERXREG(rxring, (temp | 4));
	}

	PUT_GLOBREG(config, (hmep->hme_config |
	    (hmep->hme_64bit_xfer << HMEG_CONFIG_64BIT_SHIFT)));

	/*
	 * Significant performance improvements can be achieved by
	 * disabling transmit interrupt. Thus TMD's are reclaimed only
	 * when we run out of them in hmestart().
	 */
	PUT_GLOBREG(intmask,
	    HMEG_MASK_INTR | HMEG_MASK_TINT | HMEG_MASK_TX_ALL);

	PUT_ETXREG(txring_size, ((HME_TMDMAX -1)>> HMET_RINGSZ_SHIFT));
	PUT_ETXREG(config, (GET_ETXREG(config) | HMET_CONFIG_TXDMA_EN
	    | HMET_CONFIG_TXFIFOTH));
	/* get the rxring size bits */
	switch (HME_RMDMAX) {
	case 32:
		i = HMER_CONFIG_RXRINGSZ32;
		break;
	case 64:
		i = HMER_CONFIG_RXRINGSZ64;
		break;
	case 128:
		i = HMER_CONFIG_RXRINGSZ128;
		break;
	case 256:
		i = HMER_CONFIG_RXRINGSZ256;
		break;
	default:
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    unk_rx_ringsz_msg);
		goto init_fail;
	}
	i |= (HME_FSTBYTE_OFFSET << HMER_CONFIG_FBO_SHIFT)
	    | HMER_CONFIG_RXDMA_EN;

	/* h/w checks start offset in half words */
	i |= ((sizeof (struct ether_header) / 2) << HMER_RX_CSSTART_SHIFT);

	PUT_ERXREG(config, i);

	/*
	 * Bug related to the parity handling in ERX. When erxp-config is
	 * read back.
	 * Sbus/FEPS drives the parity bit. This value is used while
	 * writing again.
	 * This fixes the RECV problem in SS5.
	 * static	int	hme_erx_fix = 1;   : Use the fix for erx bug
	 */
	{
		uint32_t temp;
		temp = GET_ERXREG(config);
		PUT_ERXREG(config, i);

		if (GET_ERXREG(config) != i)
			HME_FAULT_MSG4(hmep, SEVERITY_UNKNOWN, ERX_MSG,
			    "error:temp = %x erxp->config = %x, should be %x",
			    temp, GET_ERXREG(config), i);
	}

	/*
	 * Set up the rxconfig, txconfig and seed register without enabling
	 * them the former two at this time
	 *
	 * BigMAC strips the CRC bytes by default. Since this is
	 * contrary to other pieces of hardware, this bit needs to
	 * enabled to tell BigMAC not to strip the CRC bytes.
	 * Do not filter this node's own packets.
	 */

	if (hme_reject_own) {
		PUT_MACREG(rxcfg,
		    ((hmep->hme_promisc ? BMAC_RXCFG_PROMIS : 0) |
		    BMAC_RXCFG_MYOWN | BMAC_RXCFG_HASH));
	} else {
		PUT_MACREG(rxcfg,
		    ((hmep->hme_promisc ? BMAC_RXCFG_PROMIS : 0) |
		    BMAC_RXCFG_HASH));
	}

	drv_usecwait(10);	/* wait after setting Hash Enable bit */

	fdx = (mii_get_duplex(hmep->hme_mii) == LINK_DUPLEX_FULL);

	if (hme_ngu_enable)
		PUT_MACREG(txcfg, (fdx ? BMAC_TXCFG_FDX : 0) |
		    BMAC_TXCFG_NGU);
	else
		PUT_MACREG(txcfg, (fdx ? BMAC_TXCFG_FDX: 0));

	i = 0;
	if ((hmep->hme_lance_mode) && (hmep->hme_lance_mode_enable))
		i = ((hmep->hme_ipg0 & HME_MASK_5BIT) << BMAC_XIFC_IPG0_SHIFT)
		    | BMAC_XIFC_LANCE_ENAB;
	if (phyad == HME_INTERNAL_PHYAD)
		PUT_MACREG(xifc, i | (BMAC_XIFC_ENAB));
	else
		PUT_MACREG(xifc, i | (BMAC_XIFC_ENAB | BMAC_XIFC_MIIBUFDIS));

	PUT_MACREG(rxcfg, GET_MACREG(rxcfg) | BMAC_RXCFG_ENAB);
	PUT_MACREG(txcfg, GET_MACREG(txcfg) | BMAC_TXCFG_ENAB);

	hmep->hme_flags |= (HMERUNNING | HMEINITIALIZED);
	/*
	 * Update the interrupt mask : this will re-allow interrupts to occur
	 */
	PUT_GLOBREG(intmask, HMEG_MASK_INTR);
	mac_tx_update(hmep->hme_mh);

init_fail:
	/*
	 * Release the locks in reverse order
	 */
	mutex_exit(&hmep->hme_xmitlock);
	mutex_exit(&hmep->hme_intrlock);

	ret = !(hmep->hme_flags & HMERUNNING);
	if (ret) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    init_fail_gen_msg);
	}

	/*
	 * Hardware checks.
	 */
	CHECK_GLOBREG();
	CHECK_MIFREG();
	CHECK_MACREG();
	CHECK_ERXREG();
	CHECK_ETXREG();

init_exit:
	return (ret);
}

/*
 * Calculate the dvma burstsize by setting up a dvma temporarily.  Return
 * 0 as burstsize upon failure as it signifies no burst size.
 * Requests for 64-bit transfer setup, if the platform supports it.
 * NOTE: Do not use ddi_dma_alloc_handle(9f) then ddi_dma_burstsizes(9f),
 * sun4u Ultra-2 incorrectly returns a 32bit transfer.
 */
static int
hmeburstsizes(struct hme *hmep)
{
	int burstsizes;
	ddi_dma_handle_t handle;

	if (ddi_dma_alloc_handle(hmep->dip, &hme_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &handle)) {
		return (0);
	}

	hmep->hme_burstsizes = burstsizes = ddi_dma_burstsizes(handle);
	ddi_dma_free_handle(&handle);

	/*
	 * Use user-configurable parameter for enabling 64-bit transfers
	 */
	burstsizes = (hmep->hme_burstsizes >> 16);
	if (burstsizes)
		hmep->hme_64bit_xfer = hme_64bit_enable; /* user config value */
	else
		burstsizes = hmep->hme_burstsizes;

	if (hmep->hme_cheerio_mode)
		hmep->hme_64bit_xfer = 0; /* Disable for cheerio */

	if (burstsizes & 0x40)
		hmep->hme_config = HMEG_CONFIG_BURST64;
	else if (burstsizes & 0x20)
		hmep->hme_config = HMEG_CONFIG_BURST32;
	else
		hmep->hme_config = HMEG_CONFIG_BURST16;

	return (DDI_SUCCESS);
}

static int
hmeallocbuf(struct hme *hmep, hmebuf_t *buf, int dir)
{
	ddi_dma_cookie_t	dmac;
	size_t			len;
	unsigned		ccnt;

	if (ddi_dma_alloc_handle(hmep->dip, &hme_dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &buf->dmah) != DDI_SUCCESS) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "cannot allocate buf dma handle - failed");
		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(buf->dmah, ROUNDUP(HMEBUFSIZE, 512),
	    &hme_buf_attr, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL,
	    &buf->kaddr, &len, &buf->acch) != DDI_SUCCESS) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "cannot allocate buf memory - failed");
		return (DDI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(buf->dmah, NULL, buf->kaddr,
	    len, dir | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    &dmac, &ccnt) != DDI_DMA_MAPPED) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "cannot map buf for dma - failed");
		return (DDI_FAILURE);
	}
	buf->paddr = dmac.dmac_address;

	/* apparently they don't handle multiple cookies */
	if (ccnt > 1) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "too many buf dma cookies");
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
hmeallocbufs(struct hme *hmep)
{
	hmep->hme_tbuf = kmem_zalloc(HME_TMDMAX * sizeof (hmebuf_t), KM_SLEEP);
	hmep->hme_rbuf = kmem_zalloc(HME_RMDMAX * sizeof (hmebuf_t), KM_SLEEP);

	/* Alloc RX buffers. */
	for (int i = 0; i < HME_RMDMAX; i++) {
		if (hmeallocbuf(hmep, &hmep->hme_rbuf[i], DDI_DMA_READ) !=
		    DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	/* Alloc TX buffers. */
	for (int i = 0; i < HME_TMDMAX; i++) {
		if (hmeallocbuf(hmep, &hmep->hme_tbuf[i], DDI_DMA_WRITE) !=
		    DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

static void
hmefreebufs(struct hme *hmep)
{
	int i;

	if (hmep->hme_rbuf == NULL)
		return;

	/*
	 * Free and unload pending xmit and recv buffers.
	 * Maintaining the 1-to-1 ordered sequence of
	 * We have written the routine to be idempotent.
	 */

	for (i = 0; i < HME_TMDMAX; i++) {
		hmebuf_t *tbuf = &hmep->hme_tbuf[i];
		if (tbuf->paddr) {
			(void) ddi_dma_unbind_handle(tbuf->dmah);
		}
		if (tbuf->kaddr) {
			ddi_dma_mem_free(&tbuf->acch);
		}
		if (tbuf->dmah) {
			ddi_dma_free_handle(&tbuf->dmah);
		}
	}
	for (i = 0; i < HME_RMDMAX; i++) {
		hmebuf_t *rbuf = &hmep->hme_rbuf[i];
		if (rbuf->paddr) {
			(void) ddi_dma_unbind_handle(rbuf->dmah);
		}
		if (rbuf->kaddr) {
			ddi_dma_mem_free(&rbuf->acch);
		}
		if (rbuf->dmah) {
			ddi_dma_free_handle(&rbuf->dmah);
		}
	}
	kmem_free(hmep->hme_rbuf, HME_RMDMAX * sizeof (hmebuf_t));
	kmem_free(hmep->hme_tbuf, HME_TMDMAX * sizeof (hmebuf_t));
}

/*
 * Un-initialize (STOP) HME channel.
 */
static void
hmeuninit(struct hme *hmep)
{
	/*
	 * Allow up to 'HMEDRAINTIME' for pending xmit's to complete.
	 */
	HMEDELAY((hmep->hme_txindex == hmep->hme_txreclaim), HMEDRAINTIME);

	mutex_enter(&hmep->hme_intrlock);
	mutex_enter(&hmep->hme_xmitlock);

	hmep->hme_flags &= ~HMERUNNING;

	(void) hmestop(hmep);

	mutex_exit(&hmep->hme_xmitlock);
	mutex_exit(&hmep->hme_intrlock);
}

/*
 * Allocate CONSISTENT memory for rmds and tmds with appropriate alignment and
 * map it in IO space. Allocate space for transmit and receive ddi_dma_handle
 * structures to use the DMA interface.
 */
static int
hmeallocthings(struct hme *hmep)
{
	int			size;
	int			rval;
	size_t			real_len;
	uint_t			cookiec;
	ddi_dma_cookie_t	dmac;
	dev_info_t		*dip = hmep->dip;

	/*
	 * Allocate the TMD and RMD descriptors and extra for page alignment.
	 */

	rval = ddi_dma_alloc_handle(dip, &hme_dma_attr, DDI_DMA_DONTWAIT, NULL,
	    &hmep->hme_rmd_dmah);
	if (rval != DDI_SUCCESS) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "cannot allocate rmd handle - failed");
		return (DDI_FAILURE);
	}
	size = HME_RMDMAX * sizeof (struct hme_rmd);
	rval = ddi_dma_mem_alloc(hmep->hme_rmd_dmah, size,
	    &hmep->hme_dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    &hmep->hme_rmd_kaddr, &real_len, &hmep->hme_rmd_acch);
	if (rval != DDI_SUCCESS) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "cannot allocate rmd dma mem - failed");
		return (DDI_FAILURE);
	}
	hmep->hme_rmdp = (void *)(hmep->hme_rmd_kaddr);
	rval = ddi_dma_addr_bind_handle(hmep->hme_rmd_dmah, NULL,
	    hmep->hme_rmd_kaddr, size, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &dmac, &cookiec);
	if (rval != DDI_DMA_MAPPED) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "cannot allocate rmd dma - failed");
		return (DDI_FAILURE);
	}
	hmep->hme_rmd_paddr = dmac.dmac_address;
	if (cookiec != 1) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "too many rmd cookies - failed");
		return (DDI_FAILURE);
	}

	rval = ddi_dma_alloc_handle(dip, &hme_dma_attr, DDI_DMA_DONTWAIT, NULL,
	    &hmep->hme_tmd_dmah);
	if (rval != DDI_SUCCESS) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "cannot allocate tmd handle - failed");
		return (DDI_FAILURE);
	}
	size = HME_TMDMAX * sizeof (struct hme_rmd);
	rval = ddi_dma_mem_alloc(hmep->hme_tmd_dmah, size,
	    &hmep->hme_dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    &hmep->hme_tmd_kaddr, &real_len, &hmep->hme_tmd_acch);
	if (rval != DDI_SUCCESS) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "cannot allocate tmd dma mem - failed");
		return (DDI_FAILURE);
	}
	hmep->hme_tmdp = (void *)(hmep->hme_tmd_kaddr);
	rval = ddi_dma_addr_bind_handle(hmep->hme_tmd_dmah, NULL,
	    hmep->hme_tmd_kaddr, size, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &dmac, &cookiec);
	if (rval != DDI_DMA_MAPPED) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "cannot allocate tmd dma - failed");
		return (DDI_FAILURE);
	}
	hmep->hme_tmd_paddr = dmac.dmac_address;
	if (cookiec != 1) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "too many tmd cookies - failed");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
hmefreethings(struct hme *hmep)
{
	if (hmep->hme_rmd_paddr) {
		(void) ddi_dma_unbind_handle(hmep->hme_rmd_dmah);
		hmep->hme_rmd_paddr = 0;
	}
	if (hmep->hme_rmd_acch)
		ddi_dma_mem_free(&hmep->hme_rmd_acch);
	if (hmep->hme_rmd_dmah)
		ddi_dma_free_handle(&hmep->hme_rmd_dmah);

	if (hmep->hme_tmd_paddr) {
		(void) ddi_dma_unbind_handle(hmep->hme_tmd_dmah);
		hmep->hme_tmd_paddr = 0;
	}
	if (hmep->hme_tmd_acch)
		ddi_dma_mem_free(&hmep->hme_tmd_acch);
	if (hmep->hme_tmd_dmah)
		ddi_dma_free_handle(&hmep->hme_tmd_dmah);
}

/*
 *	First check to see if it our device interrupting.
 */
static uint_t
hmeintr(caddr_t arg)
{
	struct hme	*hmep = (void *)arg;
	uint32_t	hmesbits;
	uint32_t	serviced = DDI_INTR_UNCLAIMED;
	uint32_t	num_reads = 0;
	uint32_t	rflags;
	mblk_t		*mp, *head, **tail;


	head = NULL;
	tail = &head;

	mutex_enter(&hmep->hme_intrlock);

	/*
	 * The status register auto-clears on read except for
	 * MIF Interrupt bit
	 */
	hmesbits = GET_GLOBREG(status);
	CHECK_GLOBREG();

	/*
	 * Note: TINT is sometimes enabled in thr hmereclaim()
	 */

	/*
	 * Bugid 1227832 - to handle spurious interrupts on fusion systems.
	 * Claim the first interrupt after initialization
	 */
	if (hmep->hme_flags & HMEINITIALIZED) {
		hmep->hme_flags &= ~HMEINITIALIZED;
		serviced = DDI_INTR_CLAIMED;
	}

	if ((hmesbits & (HMEG_STATUS_INTR | HMEG_STATUS_TINT)) == 0) {
						/* No interesting interrupt */
		if (hmep->hme_intrstats) {
			if (serviced == DDI_INTR_UNCLAIMED)
				KIOIP->intrs[KSTAT_INTR_SPURIOUS]++;
			else
				KIOIP->intrs[KSTAT_INTR_HARD]++;
		}
		mutex_exit(&hmep->hme_intrlock);
		return (serviced);
	}

	serviced = DDI_INTR_CLAIMED;

	if (!(hmep->hme_flags & HMERUNNING)) {
		if (hmep->hme_intrstats)
			KIOIP->intrs[KSTAT_INTR_HARD]++;
		mutex_exit(&hmep->hme_intrlock);
		hmeuninit(hmep);
		return (serviced);
	}

	if (hmesbits & (HMEG_STATUS_FATAL_ERR | HMEG_STATUS_NONFATAL_ERR)) {
		if (hmesbits & HMEG_STATUS_FATAL_ERR) {

			if (hmep->hme_intrstats)
				KIOIP->intrs[KSTAT_INTR_HARD]++;
			hme_fatal_err(hmep, hmesbits);

			mutex_exit(&hmep->hme_intrlock);
			(void) hmeinit(hmep);
			return (serviced);
		}
		hme_nonfatal_err(hmep, hmesbits);
	}

	if (hmesbits & (HMEG_STATUS_TX_ALL | HMEG_STATUS_TINT)) {
		mutex_enter(&hmep->hme_xmitlock);

		hmereclaim(hmep);
		mutex_exit(&hmep->hme_xmitlock);
	}

	if (hmesbits & HMEG_STATUS_RINT) {

		/*
		 * This dummy PIO is required to flush the SBus
		 * Bridge buffers in QFE.
		 */
		(void) GET_GLOBREG(config);

		/*
		 * Loop through each RMD no more than once.
		 */
		while (num_reads++ < HME_RMDMAX) {
			hmebuf_t *rbuf;
			int rxptr;

			rxptr = hmep->hme_rxindex % HME_RMDMAX;
			HMESYNCRMD(rxptr, DDI_DMA_SYNC_FORKERNEL);

			rflags = GET_RMD_FLAGS(rxptr);
			if (rflags & HMERMD_OWN) {
				/*
				 * Chip still owns it.  We're done.
				 */
				break;
			}

			/*
			 * Retrieve the packet.
			 */
			rbuf = &hmep->hme_rbuf[rxptr];
			mp = hmeread(hmep, rbuf, rflags);

			/*
			 * Return ownership of the RMD.
			 */
			PUT_RMD(rxptr, rbuf->paddr);
			HMESYNCRMD(rxptr, DDI_DMA_SYNC_FORDEV);

			if (mp != NULL) {
				*tail = mp;
				tail = &mp->b_next;
			}

			/*
			 * Advance to the next RMD.
			 */
			hmep->hme_rxindex++;
		}
	}

	if (hmep->hme_intrstats)
		KIOIP->intrs[KSTAT_INTR_HARD]++;

	mutex_exit(&hmep->hme_intrlock);

	if (head != NULL)
		mac_rx(hmep->hme_mh, NULL, head);

	return (serviced);
}

/*
 * Transmit completion reclaiming.
 */
static void
hmereclaim(struct hme *hmep)
{
	boolean_t	reclaimed = B_FALSE;

	/*
	 * Loop through each TMD.
	 */
	while (hmep->hme_txindex > hmep->hme_txreclaim) {

		int		reclaim;
		uint32_t	flags;

		reclaim = hmep->hme_txreclaim % HME_TMDMAX;
		HMESYNCTMD(reclaim, DDI_DMA_SYNC_FORKERNEL);

		flags = GET_TMD_FLAGS(reclaim);
		if (flags & HMETMD_OWN) {
			/*
			 * Chip still owns it.  We're done.
			 */
			break;
		}

		/*
		 * Count a chained packet only once.
		 */
		if (flags & HMETMD_SOP) {
			hmep->hme_opackets++;
		}

		/*
		 * MIB II
		 */
		hmep->hme_obytes += flags & HMETMD_BUFSIZE;

		reclaimed = B_TRUE;
		hmep->hme_txreclaim++;
	}

	if (reclaimed) {
		/*
		 * we could reclaim some TMDs so turn off interrupts
		 */
		if (hmep->hme_wantw) {
			PUT_GLOBREG(intmask,
			    HMEG_MASK_INTR | HMEG_MASK_TINT |
			    HMEG_MASK_TX_ALL);
			hmep->hme_wantw = B_FALSE;
			mac_tx_update(hmep->hme_mh);
		}
	} else {
		/*
		 * enable TINTS: so that even if there is no further activity
		 * hmereclaim will get called
		 */
		if (hmep->hme_wantw)
			PUT_GLOBREG(intmask,
			    GET_GLOBREG(intmask) & ~HMEG_MASK_TX_ALL);
	}
	CHECK_GLOBREG();
}

/*
 * Handle interrupts for fatal errors
 * Need reinitialization of the ENET channel.
 */
static void
hme_fatal_err(struct hme *hmep, uint_t hmesbits)
{

	if (hmesbits & HMEG_STATUS_SLV_PAR_ERR) {
		hmep->hme_slvparerr++;
	}

	if (hmesbits & HMEG_STATUS_SLV_ERR_ACK) {
		hmep->hme_slverrack++;
	}

	if (hmesbits & HMEG_STATUS_TX_TAG_ERR) {
		hmep->hme_txtagerr++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_TX_PAR_ERR) {
		hmep->hme_txparerr++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_TX_LATE_ERR) {
		hmep->hme_txlaterr++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_TX_ERR_ACK) {
		hmep->hme_txerrack++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_EOP_ERR) {
		hmep->hme_eoperr++;
	}

	if (hmesbits & HMEG_STATUS_RX_TAG_ERR) {
		hmep->hme_rxtagerr++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_RX_PAR_ERR) {
		hmep->hme_rxparerr++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_RX_LATE_ERR) {
		hmep->hme_rxlaterr++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_RX_ERR_ACK) {
		hmep->hme_rxerrack++;
		hmep->hme_ierrors++;
	}
}

/*
 * Handle interrupts regarding non-fatal errors.
 */
static void
hme_nonfatal_err(struct hme *hmep, uint_t hmesbits)
{

	if (hmesbits & HMEG_STATUS_RX_DROP) {
		hmep->hme_missed++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_DEFTIMR_EXP) {
		hmep->hme_defer_xmts++;
	}

	if (hmesbits & HMEG_STATUS_FSTCOLC_EXP) {
		hmep->hme_fstcol += 256;
	}

	if (hmesbits & HMEG_STATUS_LATCOLC_EXP) {
		hmep->hme_tlcol += 256;
		hmep->hme_oerrors += 256;
	}

	if (hmesbits & HMEG_STATUS_EXCOLC_EXP) {
		hmep->hme_excol += 256;
		hmep->hme_oerrors += 256;
	}

	if (hmesbits & HMEG_STATUS_NRMCOLC_EXP) {
		hmep->hme_coll += 256;
	}

	if (hmesbits & HMEG_STATUS_MXPKTSZ_ERR) {
		hmep->hme_babl++;
		hmep->hme_oerrors++;
	}

	/*
	 * This error is fatal and the board needs to
	 * be reinitialized. Comments?
	 */
	if (hmesbits & HMEG_STATUS_TXFIFO_UNDR) {
		hmep->hme_uflo++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_SQE_TST_ERR) {
		hmep->hme_sqe_errors++;
	}

	if (hmesbits & HMEG_STATUS_RCV_CNT_EXP) {
		if (hmep->hme_rxcv_enable) {
			hmep->hme_cvc += 256;
		}
	}

	if (hmesbits & HMEG_STATUS_RXFIFO_OVFL) {
		hmep->hme_oflo++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_LEN_CNT_EXP) {
		hmep->hme_lenerr += 256;
		hmep->hme_ierrors += 256;
	}

	if (hmesbits & HMEG_STATUS_ALN_CNT_EXP) {
		hmep->hme_align_errors += 256;
		hmep->hme_ierrors += 256;
	}

	if (hmesbits & HMEG_STATUS_CRC_CNT_EXP) {
		hmep->hme_fcs_errors += 256;
		hmep->hme_ierrors += 256;
	}
}

static mblk_t *
hmeread(struct hme *hmep, hmebuf_t *rbuf, uint32_t rflags)
{
	mblk_t		*bp;
	uint32_t	len;
	t_uscalar_t	type;

	len = (rflags & HMERMD_BUFSIZE) >> HMERMD_BUFSIZE_SHIFT;

	/*
	 * Check for short packet
	 * and check for overflow packet also. The processing is the
	 * same for both the cases - reuse the buffer. Update the Buffer
	 * overflow counter.
	 */
	if ((len < ETHERMIN) || (rflags & HMERMD_OVFLOW) ||
	    (len > (ETHERMAX + 4))) {
		if (len < ETHERMIN)
			hmep->hme_runt++;

		else {
			hmep->hme_buff++;
			hmep->hme_toolong_errors++;
		}
		hmep->hme_ierrors++;
		return (NULL);
	}

	/*
	 * Sync the received buffer before looking at it.
	 */

	(void) ddi_dma_sync(rbuf->dmah, 0, 0, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * copy the packet data and then recycle the descriptor.
	 */

	if ((bp = allocb(len + HME_FSTBYTE_OFFSET, BPRI_HI)) == NULL) {

		hmep->hme_allocbfail++;
		hmep->hme_norcvbuf++;

		return (NULL);
	}

	bcopy(rbuf->kaddr, bp->b_rptr, len + HME_FSTBYTE_OFFSET);

	hmep->hme_ipackets++;

	/*  Add the First Byte offset to the b_rptr and copy */
	bp->b_rptr += HME_FSTBYTE_OFFSET;
	bp->b_wptr = bp->b_rptr + len;

	/*
	 * update MIB II statistics
	 */
	BUMP_InNUcast(hmep, bp->b_rptr);
	hmep->hme_rbytes += len;

	type = get_ether_type(bp->b_rptr);

	/*
	 * TCP partial checksum in hardware
	 */
	if (type == ETHERTYPE_IP || type == ETHERTYPE_IPV6) {
		uint16_t cksum = ~rflags & HMERMD_CKSUM;
		uint_t end = len - sizeof (struct ether_header);
		mac_hcksum_set(bp, 0, 0, end, htons(cksum), HCK_PARTIALCKSUM);
	}

	return (bp);
}

/*VARARGS*/
static void
hme_fault_msg(struct hme *hmep, uint_t severity, msg_t type, char *fmt, ...)
{
	char	msg_buffer[255];
	va_list	ap;

	va_start(ap, fmt);
	(void) vsnprintf(msg_buffer, sizeof (msg_buffer), fmt, ap);

	if (hmep == NULL) {
		cmn_err(CE_NOTE, "hme : %s", msg_buffer);

	} else if (type == DISPLAY_MSG) {
		cmn_err(CE_CONT, "?%s%d : %s\n", ddi_driver_name(hmep->dip),
		    hmep->instance, msg_buffer);
	} else if (severity == SEVERITY_HIGH) {
		cmn_err(CE_WARN, "%s%d : %s, SEVERITY_HIGH, %s\n",
		    ddi_driver_name(hmep->dip), hmep->instance,
		    msg_buffer, msg_string[type]);
	} else {
		cmn_err(CE_CONT, "%s%d : %s\n", ddi_driver_name(hmep->dip),
		    hmep->instance, msg_buffer);
	}
	va_end(ap);
}

/*
 * if this is the first init do not bother to save the
 * counters. They should be 0, but do not count on it.
 */
static void
hmesavecntrs(struct hme *hmep)
{
	uint32_t fecnt, aecnt, lecnt, rxcv;
	uint32_t ltcnt, excnt;

	/* XXX What all gets added in ierrors and oerrors? */
	fecnt = GET_MACREG(fecnt);
	PUT_MACREG(fecnt, 0);

	aecnt = GET_MACREG(aecnt);
	hmep->hme_align_errors += aecnt;
	PUT_MACREG(aecnt, 0);

	lecnt = GET_MACREG(lecnt);
	hmep->hme_lenerr += lecnt;
	PUT_MACREG(lecnt, 0);

	rxcv = GET_MACREG(rxcv);
#ifdef HME_CODEVIOL_BUG
	/*
	 * Ignore rxcv errors for Sbus/FEPS 2.1 or earlier
	 */
	if (!hmep->hme_rxcv_enable) {
		rxcv = 0;
	}
#endif
	hmep->hme_cvc += rxcv;
	PUT_MACREG(rxcv, 0);

	ltcnt = GET_MACREG(ltcnt);
	hmep->hme_tlcol += ltcnt;
	PUT_MACREG(ltcnt, 0);

	excnt = GET_MACREG(excnt);
	hmep->hme_excol += excnt;
	PUT_MACREG(excnt, 0);

	hmep->hme_fcs_errors += fecnt;
	hmep->hme_ierrors += (fecnt + aecnt + lecnt);
	hmep->hme_oerrors += (ltcnt + excnt);
	hmep->hme_coll += (GET_MACREG(nccnt) + ltcnt);

	PUT_MACREG(nccnt, 0);
	CHECK_MACREG();
}

/*
 * To set up the mac address for the network interface:
 * The adapter card may support a local mac address which is published
 * in a device node property "local-mac-address". This mac address is
 * treated as the factory-installed mac address for DLPI interface.
 * If the adapter firmware has used the device for diskless boot
 * operation it publishes a property called "mac-address" for use by
 * inetboot and the device driver.
 * If "mac-address" is not found, the system options property
 * "local-mac-address" is used to select the mac-address. If this option
 * is set to "true", and "local-mac-address" has been found, then
 * local-mac-address is used; otherwise the system mac address is used
 * by calling the "localetheraddr()" function.
 */
static void
hme_setup_mac_address(struct hme *hmep, dev_info_t *dip)
{
	char	*prop;
	int	prop_len = sizeof (int);

	hmep->hme_addrflags = 0;

	/*
	 * Check if it is an adapter with its own local mac address
	 * If it is present, save it as the "factory-address"
	 * for this adapter.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "local-mac-address",
	    (caddr_t)&prop, &prop_len) == DDI_PROP_SUCCESS) {
		if (prop_len == ETHERADDRL) {
			hmep->hme_addrflags = HME_FACTADDR_PRESENT;
			ether_bcopy(prop, &hmep->hme_factaddr);
			HME_FAULT_MSG2(hmep, SEVERITY_NONE, DISPLAY_MSG,
			    "Local Ethernet address = %s",
			    ether_sprintf(&hmep->hme_factaddr));
		}
		kmem_free(prop, prop_len);
	}

	/*
	 * Check if the adapter has published "mac-address" property.
	 * If it is present, use it as the mac address for this device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "mac-address", (caddr_t)&prop, &prop_len) == DDI_PROP_SUCCESS) {
		if (prop_len >= ETHERADDRL) {
			ether_bcopy(prop, &hmep->hme_ouraddr);
			kmem_free(prop, prop_len);
			return;
		}
		kmem_free(prop, prop_len);
	}

#ifdef	__sparc
	/*
	 * On sparc, we might be able to use the mac address from the
	 * system.  However, on all other systems, we need to use the
	 * address from the PROM.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, 0, "local-mac-address?",
	    (caddr_t)&prop, &prop_len) == DDI_PROP_SUCCESS) {
		if ((strncmp("true", prop, prop_len) == 0) &&
		    (hmep->hme_addrflags & HME_FACTADDR_PRESENT)) {
			hmep->hme_addrflags |= HME_FACTADDR_USE;
			ether_bcopy(&hmep->hme_factaddr, &hmep->hme_ouraddr);
			kmem_free(prop, prop_len);
			HME_FAULT_MSG1(hmep, SEVERITY_NONE, DISPLAY_MSG,
			    "Using local MAC address");
			return;
		}
		kmem_free(prop, prop_len);
	}

	/*
	 * Get the system ethernet address.
	 */
	(void) localetheraddr((struct ether_addr *)NULL, &hmep->hme_ouraddr);
#else
	ether_bcopy(&hmep->hme_factaddr, &hmep->hme_ouraddr);
#endif
}

/* ARGSUSED */
static void
hme_check_acc_handle(char *file, uint_t line, struct hme *hmep,
    ddi_acc_handle_t handle)
{
}
