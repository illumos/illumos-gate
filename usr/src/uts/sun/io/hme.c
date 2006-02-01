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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SunOS MT STREAMS FEPS(SBus)/Cheerio(PCI) 10/100Mb Ethernet Device Driver
 */

#include	<sys/types.h>
#include	<sys/debug.h>
#include	<sys/stropts.h>
#include	<sys/stream.h>
#include	<sys/cmn_err.h>
#include	<sys/vtrace.h>
#include	<sys/kmem.h>
#include	<sys/crc32.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/strsun.h>
#include	<sys/stat.h>
#include	<sys/cpu.h>
#include	<sys/kstat.h>
#include	<inet/common.h>
#include	<inet/mi.h>
#include	<inet/nd.h>
#include	<sys/dlpi.h>
#include	<sys/ethernet.h>
#include	<sys/hme_phy.h>
#include	<sys/hme_mac.h>
#include	<sys/hme.h>
#include	<sys/pci.h>
#include	<sys/policy.h>

typedef int	(*fptri_t)();
typedef void	(*fptrv_t)();

typedef enum {
	NO_MSG		= 0,
	AUTOCONFIG_MSG	= 1,
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
	FATAL_ERR_MSG	= 16,
	NFATAL_ERR_MSG	= 17,
	NDD_MSG		= 18,
	PHY_MSG		= 19,
	XCVR_MSG	= 20,
	NOXCVR_MSG	= 21,
	NSUPPORT_MSG	= 22,
	ERX_MSG		= 23,
	FREE_MSG	= 24,
	IPG_MSG		= 25,
	DDI_MSG		= 26,
	DEFAULT_MSG	= 27,
	DISPLAY_MSG	= 28,
	LATECOLL_MSG	= 29,
	MIFPOLL_MSG	= 30,
	LINKPULSE_MSG	= 31,
	EXIT_MSG	= 32
} msg_t;

msg_t	hme_debug_level =	NO_MSG;

static char	*msg_string[] = {
	"NONE       ",
	"AUTOCONFIG ",
	"STREAMS    ",
	"IOCTL      ",
	"PROTO      ",
	"INIT       ",
	"TX         ",
	"RX         ",
	"INTR       ",
	"UNINIT		",
	"CONFIG	",
	"PROP	",
	"ENTER	",
	"RESUME	",
	"AUTONEG	",
	"NAUTONEG	",
	"FATAL_ERR	",
	"NFATAL_ERR	",
	"NDD	",
	"PHY	",
	"XCVR	",
	"NOXCVR	",
	"NSUPPOR	",
	"ERX	",
	"FREE	",
	"IPG	",
	"DDI	",
	"DEFAULT	",
	"DISPLAY	"
	"LATECOLL_MSG	",
	"MIFPOLL_MSG	",
	"LINKPULSE_MSG	",
	"EXIT_MSG	"
};

#define	SEVERITY_NONE	0
#define	SEVERITY_LOW	0
#define	SEVERITY_MID	1
#define	SEVERITY_HIGH	2
#define	SEVERITY_UNKNOWN 99

#define	FEPS_URUN_BUG
#define	HME_CODEVIOL_BUG

/* temp: stats from adb */
static int hme_reinit_txhung;
static int hme_reinit_fatal;
static int hme_reinit_jabber;

#define	KIOIP	KSTAT_INTR_PTR(hmep->hme_intrstats)

/*
 * The following variables are used for checking fixes in Sbus/FEPS 2.0
 */
static	int	hme_urun_fix = 0;	/* Bug fixed in Sbus/FEPS 2.0 */

/*
 * Initialize hmestruplock and hmewenlock just once during attach
 */
static	uint_t init_once = 0;

/*
 * The following variables are used for configuring various features
 */
static	int	hme_64bit_enable =	1;	/* Use 64-bit sbus transfers */
static	int	hme_reject_own =	1;	/* Reject packets with own SA */
static	int	hme_autoneg_enable =	1;	/* Enable auto-negotiation */

static	int	hme_ngu_enable =	1; /* to enable Never Give Up mode */
static	int	hme_mifpoll_enable =	1; /* to enable mif poll */

/*
 * The following variables are used for performance tuning.
 */

#define	RX_BCOPY_MAX	(sizeof (struct ether_header) + 256)

static	int	hme_rx_bcopy_max =	RX_BCOPY_MAX;

/*
 * The following variables are used for configuring link-operation.
 * Later these parameters may be changed per interface using "ndd" command
 * These parameters may also be specified as properties using the .conf
 * file mechanism for each interface.
 */

static	int	hme_lance_mode =	1;	/* to enable lance mode */
static	int	hme_ipg0 =		16;
static	int	hme_ipg1 =		8;
static	int	hme_ipg2 =		4;
static	int	hme_use_int_xcvr =	0;
static	int	hme_pace_size =		0;	/* Do not use pacing */

/*
 * The following variable value will be overridden by "link-pulse-disabled"
 * property which may be created by OBP or hme.conf file.
 */
static	int	hme_link_pulse_disabled = 0;	/* link pulse disabled */

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

static	int	hme_adv_autoneg_cap = HME_NOTUSR | 0;
static	int	hme_adv_100T4_cap = HME_NOTUSR | 0;
static	int	hme_adv_100fdx_cap = HME_NOTUSR | 0;
static	int	hme_adv_100hdx_cap = HME_NOTUSR | 0;
static	int	hme_adv_10fdx_cap = HME_NOTUSR | 0;
static	int	hme_adv_10hdx_cap = HME_NOTUSR | 0;

/*
 * PHY_IDR1 and PHY_IDR2 values to identify National Semiconductor's DP83840
 * Rev C chip which needs some work-arounds.
 */
#define	HME_NSIDR1	0x2000
#define	HME_NSIDR2	0x5c00 /* IDR2 register for with revision no. 0 */

/*
 * PHY_IDR1 and PHY_IDR2 values to identify Quality Semiconductor's QS6612
 * chip which needs some work-arounds.
 * Addition Interface Technologies Group (NPG) 8/28/1997.
 */
#define	HME_QSIDR1	0x0181
#define	HME_QSIDR2	0x4400 /* IDR2 register for with revision no. 0 */

/*
 * The least significant 4 bits of HME_NSIDR2 represent the revision
 * no. of the DP83840 chip. For Rev-C of DP83840, the rev. no. is 0.
 * The next revision of the chip is called DP83840A and the value of
 * HME_NSIDR2 is 0x5c01 for this new chip. All the workarounds specific
 * to DP83840 chip are valid for both the revisions of the chip.
 * Assuming that these workarounds are valid for the future revisions
 * also, we will apply these workarounds independent of the revision no.
 * Hence we mask out the last 4 bits of the IDR2 register and compare
 * with 0x5c00 value.
 */

#define	HME_DP83840	((hmep->hme_idr1 == HME_NSIDR1) && \
			((hmep->hme_idr2 & 0xfff0) == HME_NSIDR2))
/*
 * Likewise for the QSI 6612 Fast ethernet phy.
 * Addition Interface Technologies Group (NPG) 8/28/1997.
 */
#define	HME_QS6612	((hmep->hme_idr1 == HME_QSIDR1) && \
			((hmep->hme_idr2 & 0xfff0) == HME_QSIDR2))
/*
 * All strings used by hme messaging functions
 */
static	char *link_down_msg =
	"No response from Ethernet network : Link down -- cable problem?";

static	char *busy_msg =
	"Driver is BUSY with upper layer";

static	char *par_detect_msg =
	"Parallel detection fault.";

static	char *xcvr_no_mii_msg =
	"Transceiver does not talk MII.";

static	char *xcvr_isolate_msg =
	"Transceiver isolate failed.";

static	char *int_xcvr_msg =
	"Internal Transceiver Selected.";

static	char *ext_xcvr_msg =
	"External Transceiver Selected.";

static	char *no_xcvr_msg =
	"No transceiver found.";

static	char *slave_slot_msg =
	"Dev not used - dev in slave only slot";

static	char *burst_size_msg =
	"Could not identify the burst size";

static	char *unk_rx_ringsz_msg =
	"Unknown receive RINGSZ";

static	char *lmac_addr_msg =
	"Using local MAC address";

static  char *lether_addr_msg =
	"Local Ethernet address = %s";

static  char *add_intr_fail_msg =
	"ddi_add_intr(9F) failed";

static  char *create_minor_node_fail_msg =
	"ddi_create_minor_node(9F) failed";

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

static  char *mif_read_fail_msg =
	"MIF Read failure";

static  char *mif_write_fail_msg =
	"MIF Write failure";

static  char *kstat_create_fail_msg =
	"kstat_create failed";

static  char *param_reg_fail_msg =
	"parameter register error";

static	char *init_fail_gen_msg =
	"Failed to initialize hardware/driver";

static	char *ddi_nregs_fail_msg =
	"ddi_dev_nregs failed(9F), returned %d";

static	char *bad_num_regs_msg =
	"Invalid number of registers.";

static	char *anar_not_set_msg =
	"External Transceiver: anar not set with speed selection";

static	char *par_detect_anar_not_set_msg =
	"External Transceiver: anar not set with speed selection";


#ifdef	HME_DEBUG
static  char *mregs_4config_fail_msg =
	"ddi_regs_map_setup(9F) for config space failed";

static  char *attach_fail_msg =
	"Attach entry point failed";

static  char *attach_bad_cmd_msg =
	"Attach entry point rcv'd a bad command";

static  char *detach_bad_cmd_msg =
	"Detach entry point rcv'd a bad command";

static  char *phy_msg =
	"Phy, Vendor Id: %x";

static  char *no_phy_msg =
	"No Phy/xcvr found";

static  char *unk_rx_descr_sze_msg =
	"Unknown Rx descriptor size %x.";

static  char *disable_txmac_msg =
	"Txmac could not be disabled.";

static  char *disable_rxmac_msg =
	"Rxmac could not be disabled.";

static  char *config_space_fatal_msg =
	"Configuration space failed in routine.";

static  char *mregs_4soft_reset_fail_msg =
	"ddi_regs_map_setup(9F) for soft reset failed";

static  char *disable_erx_msg =
	"Can not disable Rx.";

static  char *disable_etx_msg =
	"Can not disable Tx.";

static  char *unk_tx_descr_sze_msg =
	"Unknown Tx descriptor size %x.";

static  char *alloc_tx_dmah_msg =
	"Can not allocate Tx dma handle.";

static  char *alloc_rx_dmah_msg =
	"Can not allocate Rx dma handle.";

static  char *phy_speed_bad_msg =
	"The current Phy/xcvr speed is not valid";

static  char *par_detect_fault_msg =
	"Parallel Detection Fault";

static  char *autoneg_speed_bad_msg =
	"Autonegotiated speed is bad";

#endif

/*
 *	"MIF Read failure: data = %X";
 */

/*
 * SunVTS Loopback messaging support
 *
 * static  char *loopback_val_default =
 *	"Loopback Value: Error In Value.";
 *
 * static  char *loopback_cmd_default =
 *	"Loopback Command: Error In Value.";
 */

/* FATAL ERR msgs */
/*
 * Function prototypes.
 */
static	int hmeattach(dev_info_t *, ddi_attach_cmd_t);
static	int hmedetach(dev_info_t *, ddi_detach_cmd_t);
static	int hmeinit_xfer_params(struct hme *);
static	uint_t hmestop(struct hme *);
static	void hmestatinit(struct hme *);
static	int hmeallocthings(struct hme *);
static	void hmefreebufs(struct hme *);
static  void *hmeallocb(size_t, uint_t);
static	void hmeget_hm_rev_property(struct hme *);
static	int hmeopen(queue_t *, dev_t *, int, int, cred_t *);
static	int hmeclose(queue_t *);
static	int hmewput(queue_t *, mblk_t *);
static	int hmewsrv(queue_t *);
static	void hmeproto(queue_t *, mblk_t *);
static	struct hme *hme_set_ppa(struct hmestr *, queue_t *);
static	void hmeioctl(queue_t *, mblk_t *);
static	void hme_dl_ioc_hdr_info(queue_t *, mblk_t *);
static	void hmeareq(queue_t *, mblk_t *);
static	void hmedreq(queue_t *, mblk_t *);
static	void hmedodetach(struct hmestr *);
static	void hmebreq(queue_t *, mblk_t *);
static	void hmeubreq(queue_t *, mblk_t *);
static	void hmeireq(queue_t *, mblk_t *);
static	void hmeponreq(queue_t *, mblk_t *);
static	void hmepoffreq(queue_t *, mblk_t *);
static	void hmeemreq(queue_t *, mblk_t *);
static	void hmedmreq(queue_t *, mblk_t *);
static	void hmepareq(queue_t *, mblk_t *);
static	void hmespareq(queue_t *, mblk_t *);
static	void hmeudreq(queue_t *, mblk_t *);
static	void hmenreq(queue_t *, mblk_t *);
static	void hmenotify_ind(struct hme *, uint32_t);
static	int hmestart(queue_t *, mblk_t *, struct hme *);
static	uint_t hmeintr();
static	void hmewenable(struct hme *);
static	void hmereclaim(struct hme *);
static	int hmeinit(struct hme *);
static	void hmeuninit(struct hme *hmep);
static	char *hme_ether_sprintf(struct ether_addr *);
static	mblk_t *hmeaddudind(struct hme *, mblk_t *, struct ether_addr *,
	struct ether_addr *, int, uint32_t);
static	struct hmestr *hmeaccept(struct hmestr *, struct hme *, int,
	struct ether_addr *);
static	struct hmestr *hmepaccept(struct hmestr *, struct hme *, int,
	struct	ether_addr *);
static	void hmesetipq(struct hme *);
static	int hmemcmatch(struct hmestr *, struct ether_addr *);
static	void hmesendup(struct hme *, mblk_t *, struct hmestr *(*)());
static 	void hmeread(struct hme *, volatile struct hme_rmd *);
static	void hmesavecntrs(struct hme *);
static	void hme_fatal_err(struct hme *, uint_t);
static	void hme_nonfatal_err(struct hme *, uint_t);
static	int hmeburstsizes(struct hme *);
static	void hme_start_mifpoll(struct hme *);
static	void hme_stop_mifpoll(struct hme *);
static	void hme_param_cleanup(struct hme *);
static	int hme_param_get(queue_t *q, mblk_t *mp, caddr_t cp);
static	int hme_param_register(struct hme *, hmeparam_t *, int);
static	int hme_param_set(queue_t *, mblk_t *, char *, caddr_t);
static	void send_bit(struct hme *, uint_t);
static	uint_t get_bit(struct hme *);
static	uint_t get_bit_std(struct hme *);
static	uint_t hme_bb_mii_read(struct hme *, uchar_t, uint16_t *);
static	void hme_bb_mii_write(struct hme *, uchar_t, uint16_t);
static	void hme_bb_force_idle(struct hme *);
static	uint_t hme_mii_read(struct hme *, uchar_t, uint16_t *);
static	void hme_mii_write(struct hme *, uchar_t, uint16_t);
static	void hme_stop_timer(struct hme *);
static	void hme_start_timer(struct hme *, fptrv_t, int);
static	int hme_select_speed(struct hme *, int);
static	void hme_reset_transceiver(struct hme *);
static	void hme_check_transceiver(struct hme *);
static	void hme_setup_link_default(struct hme *);
static	void hme_setup_link_status(struct hme *);
static	void hme_setup_link_control(struct hme *);
static	int hme_check_txhung(struct hme *hmep);
static	void hme_check_link(void *);

static	void hme_init_xcvr_info(struct hme *);
static	void hme_display_transceiver(struct hme *hmep);
static	void hme_disable_link_pulse(struct hme *);
static	void hme_force_speed(void *);
static	void hme_get_autoinfo(struct hme *);
static	int hme_try_auto_negotiation(struct hme *);
static	void hme_try_speed(void *);
static	void hme_link_now_up(struct hme *);
static	void hme_display_linkup(struct hme *hmep, uint32_t speed);
static	void hme_setup_mac_address(struct hme *, dev_info_t *);

static	void hme_nd_free(caddr_t *nd_pparam);
static	int hme_nd_getset(queue_t *q, caddr_t nd_param, MBLKP mp);
static	boolean_t hme_nd_load(caddr_t *nd_pparam, char *name,
				pfi_t get_pfi, pfi_t set_pfi, caddr_t data);

static void hme_fault_msg(char *, uint_t, struct hme *, uint_t,
			msg_t, char *, ...);

static void hme_check_acc_handle(char *, uint_t, struct hme *,
				ddi_acc_handle_t);

static void hme_check_dma_handle(char *, uint_t, struct hme *,
				ddi_dma_handle_t);

#define	HME_FAULT_MSG1(p, s, t, f) \
    hme_fault_msg(__FILE__, __LINE__, (p), (s), (t), (f));

#define	HME_FAULT_MSG2(p, s, t, f, a) \
    hme_fault_msg(__FILE__, __LINE__, (p), (s), (t), (f), (a));

#define	HME_FAULT_MSG3(p, s, t, f, a, b) \
    hme_fault_msg(__FILE__, __LINE__, (p), (s), (t), (f), (a), (b));

#define	HME_FAULT_MSG4(p, s, t, f, a, b, c) \
    hme_fault_msg(__FILE__, __LINE__, (p), (s), (t), (f), (a), (b), (c));

#ifdef	HME_DEBUG
static void	hme_debug_msg(char *, uint_t, struct hme *, uint_t,
				msg_t, char *, ...);

#define	HME_DEBUG_MSG1(p, s, t, f) \
    hme_debug_msg(__FILE__, __LINE__, (p), (s), (t), (f))

#define	HME_DEBUG_MSG2(p, s, t, f, a) \
    hme_debug_msg(__FILE__, __LINE__, (p), (s), (t), (f), (a))

#define	HME_DEBUG_MSG3(p, s, t, f, a, b) \
    hme_debug_msg(__FILE__, __LINE__, (p), (s), (t), (f), (a), (b))

#define	HME_DEBUG_MSG4(p, s, t, f, a, b, c) \
    hme_debug_msg(__FILE__, __LINE__, (p), (s), (t), (f), (a), (b), (c))

#define	HME_DEBUG_MSG5(p, s, t, f, a, b, c, d) \
    hme_debug_msg(__FILE__, __LINE__, (p), (s), (t), (f), (a), (b), (c), (d))

#define	HME_DEBUG_MSG6(p, s, t, f, a, b, c, d, e) \
    hme_debug_msg(__FILE__, __LINE__, (p), (s), (t), (f), (a), (b), (c),  \
		    (d), (e))

#else

#define	HME_DEBUG_MSG1(p, s, t, f)
#define	HME_DEBUG_MSG2(p, s, t, f, a)
#define	HME_DEBUG_MSG3(p, s, t, f, a, b)
#define	HME_DEBUG_MSG4(p, s, t, f, a, b, c)
#define	HME_DEBUG_MSG5(p, s, t, f, a, b, c, d)
#define	HME_DEBUG_MSG6(p, s, t, f, a, b, c, d, e)

#endif

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

#define	DEV_REPORT_FAULT1(p, i, l, f)
#define	DEV_REPORT_FAULT2(p, i, l, f, a)
#define	DEV_REPORT_FAULT3(p, i, l, f, a, b)
#define	DEV_REPORT_FAULT4(p, i, l, f, a, b, c)

#define	ND_BASE		('N' << 8)	/* base */
#define	ND_GET		(ND_BASE + 0)	/* Get a value */
#define	ND_SET		(ND_BASE + 1)	/* Set a value */

/*
 * Module linkage structures.
 */
static	struct	module_info	hmeminfo = {
	HMEIDNUM,	/* mi_idnum */
	HMENAME,	/* mi_idname */
	HMEMINPSZ,	/* mi_minpsz */
	HMEMAXPSZ,	/* mi_maxpsz */
	HMEHIWAT,	/* mi_hiwat */
	HMELOWAT	/* mi_lowat */
};

static	struct	qinit	hmerinit = {
	NULL,		/* qi_putp */
	NULL,		/* qi_srvp */
	hmeopen,	/* qi_qopen */
	hmeclose,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&hmeminfo,	/* qi_minfo */
	NULL		/* qi_mstat */
};

static	struct	qinit	hmewinit = {
	hmewput,	/* qi_putp */
	hmewsrv,	/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&hmeminfo,	/* qi_minfo */
	NULL		/* qi_mstat */
};

static struct	streamtab	hme_info = {
	&hmerinit,	/* st_rdinit */
	&hmewinit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

static	struct	cb_ops	cb_hme_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&hme_info,		/* cb_stream */
	D_MP | D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)()  */
	nodev			/* int (*cb_awrite)() */
};

static	struct	dev_ops	hme_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ddi_no_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	hmeattach,		/* devo_attach */
	hmedetach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_hme_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL			/* devo_power */
};

#ifndef lint
char _depends_on[] = "drv/ip";
#endif /* lint */

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

static ddi_dma_attr_t hme_dma_attr = {
	DMA_ATTR_V0,		/* version number. */
	(uint64_t)HMELIMADDRLO,	/* low address */
	(uint64_t)HMELIMADDRHI,	/* high address */
	(uint64_t)0x00ffffff,	/* address counter max */
	(uint64_t)1,		/* alignment */
	(uint_t)0x00700070,	/* dlim_burstsizes for 32 and 64 bit xfers */
	(uint32_t)0x1,		/* minimum transfer size */
	(uint64_t)0x7fffffff,	/* maximum transfer size */
	(uint64_t)0x00ffffff,	/* maximum segment size */
	1,			/* scatter/gather list length */
	512,			/* granularity */
	0			/* attribute flags */
};

static ddi_dma_lim_t hme_dma_limits = {
	(uint64_t)HMELIMADDRLO,	/* dlim_addr_lo */
	(uint64_t)HMELIMADDRHI,	/* dlim_addr_hi */
	(uint64_t)HMELIMADDRHI,	/* dlim_cntr_max */
	(uint_t)0x00700070,	/* dlim_burstsizes for 32 and 64 bit xfers */
	(uint32_t)0x1,		/* dlim_minxfer */
	1024			/* dlim_speed */
};

static uchar_t pci_latency_timer = 0;

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	"10/100Mb Ethernet Driver v%I%",
	&hme_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/*
 * Autoconfiguration lock:  We want to initialize all the global
 * locks at _init().  However, we do not have the cookie required which
 * is returned in ddi_add_intr(), which in turn is usually called at attach
 * time.
 */
static	kmutex_t	hmeautolock;

/*
 * Linked list of active (inuse) driver Streams.
 */
static	struct	hmestr	*hmestrup = NULL;
static	krwlock_t	hmestruplock;

/*
 * Single private "global" lock for the few rare conditions
 * we want single-threaded.
 */
static	kmutex_t	hmelock;
static	kmutex_t	hmewenlock;

static	int	hme_device = -1;

/*
 * Internal PHY Id:
 */

#define	HME_BB1	0x15	/* Babybac1, Rev 1.5 */
#define	HME_BB2 0x20	/* Babybac2, Rev 0 */

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
#define	PUT_TMD(ptr, cookie, len, flags) \
	ddi_put32(hmep->hme_mdm_h, (uint32_t *)&ptr->tmd_addr, cookie); \
	ddi_put32(hmep->hme_mdm_h, (uint32_t *)&ptr->tmd_flags, \
	    (uint_t)HMETMD_OWN | len | flags)
#define	GET_TMD_FLAGS(ptr) \
	ddi_get32(hmep->hme_mdm_h, (uint32_t *)&ptr->tmd_flags)
#define	PUT_RMD(ptr, cookie) \
	ddi_put32(hmep->hme_mdm_h, (uint32_t *)&ptr->rmd_addr, cookie); \
	ddi_put32(hmep->hme_mdm_h, (uint32_t *)&ptr->rmd_flags, \
	    (uint_t)(HMEBUFSIZE << HMERMD_BUFSIZE_SHIFT) | HMERMD_OWN)
#define	GET_RMD_FLAGS(ptr) \
	ddi_get32(hmep->hme_mdm_h, (uint32_t *)&ptr->rmd_flags)

#define	CLONE_RMD(old, new) \
	new->rmd_addr = old->rmd_addr; /* This is actually safe */\
	ddi_put32(hmep->hme_mdm_h, (uint32_t *)&new->rmd_flags, \
	    (uint_t)(HMEBUFSIZE << HMERMD_BUFSIZE_SHIFT) | HMERMD_OWN)
#define	GET_ROM8(offset) \
	ddi_get8((hmep->hme_romh), (offset))

/*
 * Ether_copy is not endian-correct. Define an endian-correct version.
 */
#define	ether_bcopy(a, b) (bcopy(a, b, 6))

/*
 * Ether-type is specifically big-endian, but data region is unknown endian
 */

typedef struct ether_header *eehp;

#define	get_ether_type(ptr) (\
	(((uchar_t *)&((eehp)ptr)->ether_type)[0] << 8) | \
	(((uchar_t *)&((eehp)ptr)->ether_type)[1]))

#define	put_ether_type(ptr, value) {\
	((uchar_t *)(&((eehp)ptr)->ether_type))[0] = \
	    ((uint_t)value & 0xff00) >> 8; \
	((uchar_t *)(&((eehp)ptr)->ether_type))[1] = (value & 0xff); }

/* <<<<<<<<<<<<<<<<<<<<<<  Configuration Parameters >>>>>>>>>>>>>>>>>>>>> */

#define	BMAC_DEFAULT_JAMSIZE	(0x04)		/* jamsize equals 4 */
#define	BMAC_LONG_JAMSIZE	(0x10)		/* jamsize equals 0x10 */
static	int 	jamsize = BMAC_DEFAULT_JAMSIZE;

/*
 * The following code is used for performance metering and debugging;
 * This routine is invoked via "TIME_POINT(label)" macros, which will
 * store the label and a timestamp. This allows to execution sequences
 * and timestamps associated with them.
 */


#ifdef	TPOINTS
/* Time trace points */
int time_point_active;
static int time_point_offset, time_point_loc;
hrtime_t last_time_point;
#define	POINTS 1024
int time_points[POINTS];
#define	TPOINT(x) if (time_point_active) hme_time_point(x);
void
hme_time_point(int loc)
{
	static hrtime_t time_point_base;

	hrtime_t now;

	now = gethrtime();
	if (time_point_base == 0) {
		time_point_base = now;
		time_point_loc = loc;
		time_point_offset = 0;
	} else {
		time_points[time_point_offset] = loc;
		time_points[time_point_offset+1] =
		    (now - last_time_point) / 1000;
		time_point_offset += 2;
		if (time_point_offset >= POINTS)
		    time_point_offset = 0; /* wrap at end */
		/* time_point_active = 0;  disable at end */
	}
	last_time_point = now;
}
#else
#define	TPOINT(x)
#endif


/*
 * Calculate the bit in the multicast address filter that selects the given
 * address.
 */

static uint32_t
hmeladrf_bit(struct ether_addr *addr)
{
	uint32_t crc;

	CRC32(crc, addr, ETHERADDRL, -1U, crc32_table);

	/*
	 * Just want the 6 most significant bits.
	 */
	return (crc >> 26);
}

/* <<<<<<<<<<<<<<<<<<<<<<<<  Bit Bang Operations >>>>>>>>>>>>>>>>>>>>>>>> */

static int hme_internal_phy_id = HME_BB2;	/* Internal PHY is Babybac2  */


static void
send_bit(struct hme *hmep, uint32_t x)
{
	PUT_MIFREG(mif_bbdata, x);
	PUT_MIFREG(mif_bbclk, HME_BBCLK_LOW);
	PUT_MIFREG(mif_bbclk, HME_BBCLK_HIGH);
}

/*
 * To read the MII register bits from the Babybac1 transceiver
 */
static uint32_t
get_bit(struct hme *hmep)
{
	uint32_t	x;

	PUT_MIFREG(mif_bbclk, HME_BBCLK_LOW);
	PUT_MIFREG(mif_bbclk, HME_BBCLK_HIGH);
	if (hmep->hme_transceiver == HME_INTERNAL_TRANSCEIVER)
		x = (GET_MIFREG(mif_cfg) & HME_MIF_CFGM0) ? 1 : 0;
	else
		x = (GET_MIFREG(mif_cfg) & HME_MIF_CFGM1) ? 1 : 0;
	return (x);
}


/*
 * To read the MII register bits according to the IEEE Standard
 */
static uint32_t
get_bit_std(struct hme *hmep)
{
	uint32_t	x;

	PUT_MIFREG(mif_bbclk, HME_BBCLK_LOW);
	drv_usecwait(1);	/* wait for  >330 ns for stable data */
	if (hmep->hme_transceiver == HME_INTERNAL_TRANSCEIVER)
		x = (GET_MIFREG(mif_cfg) & HME_MIF_CFGM0) ? 1 : 0;
	else
		x = (GET_MIFREG(mif_cfg) & HME_MIF_CFGM1) ? 1 : 0;
	PUT_MIFREG(mif_bbclk, HME_BBCLK_HIGH);
	return (x);
}

#define	SEND_BIT(x)		send_bit(hmep, x)
#define	GET_BIT(x)		x = get_bit(hmep)
#define	GET_BIT_STD(x)		x = get_bit_std(hmep)


static void
hme_bb_mii_write(struct hme *hmep, uint8_t regad, uint16_t data)
{
	uint8_t	phyad;
	int	i;

	PUT_MIFREG(mif_bbopenb, 1);	/* Enable the MII driver */
	phyad = hmep->hme_phyad;
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
static uint_t
hme_bb_mii_read(struct hme *hmep, uint8_t regad, uint16_t *datap)
{
	uint8_t		phyad;
	int		i;
	uint32_t	x;
	uint32_t	y;

	*datap = 0;

	PUT_MIFREG(mif_bbopenb, 1);	/* Enable the MII driver */
	phyad = hmep->hme_phyad;
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

	if ((hme_internal_phy_id == HME_BB2) ||
			(hmep->hme_transceiver == HME_EXTERNAL_TRANSCEIVER)) {
		GET_BIT_STD(x);
		GET_BIT_STD(y);		/* <TA> */
		for (i = 0xf; i >= 0; i--) {	/* <DDDDDDDDDDDDDDDD> */
			GET_BIT_STD(x);
			*datap += (x << i);
		}
		/*
		 * Kludge to get the Transceiver out of hung mode
		 */
		GET_BIT_STD(x);
		GET_BIT_STD(x);
		GET_BIT_STD(x);
	} else {
		GET_BIT(x);
		GET_BIT(y);		/* <TA> */
		for (i = 0xf; i >= 0; i--) {	/* <DDDDDDDDDDDDDDDD> */
			GET_BIT(x);
			*datap += (x << i);
		}
		/*
		 * Kludge to get the Transceiver out of hung mode
		 */
		GET_BIT(x);
		GET_BIT(x);
		GET_BIT(x);
	}
	CHECK_MIFREG();
	return (y);
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

#ifdef	HME_FRM_DEBUG
int hme_frame_flag = 0;
#endif

/* Return 0 if OK, 1 if error (Transceiver does not talk management) */
static uint_t
hme_mii_read(struct hme *hmep, uchar_t regad, uint16_t *datap)
{
	volatile uint32_t *framerp = &hmep->hme_mifregp->mif_frame;
	uint32_t	frame;
	uint8_t		phyad;

	if (hmep->hme_transceiver == HME_NO_TRANSCEIVER)
		return (1);	/* No transceiver present */

	if (!hmep->hme_frame_enable)
		return (hme_bb_mii_read(hmep, regad, datap));

	phyad = hmep->hme_phyad;
#ifdef	HME_FRM_DEBUG
	if (!hme_frame_flag) {
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, NAUTONEG_MSG,
				"Frame Register used for MII");
		hme_frame_flag = 1;
	}
		HME_DEBUG_MSG3(hmep, SEVERITY_UNKNOWN, NAUTONEG_MSG,
		"Frame Reg :mii_read: phyad = %X reg = %X ", phyad, regad);
#endif

	*framerp = HME_MIF_FRREAD | (phyad << HME_MIF_FRPHYAD_SHIFT) |
					(regad << HME_MIF_FRREGAD_SHIFT);
/*
 *	HMEDELAY((*framerp & HME_MIF_FRTA0), HMEMAXRSTDELAY);
 */
	HMEDELAY((*framerp & HME_MIF_FRTA0), 300);
	frame = *framerp;
	CHECK_MIFREG();
	if ((frame & HME_MIF_FRTA0) == 0) {


		HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, NAUTONEG_MSG,
		    mif_read_fail_msg);
		return (1);
	} else {
		*datap = (uint16_t)(frame & HME_MIF_FRDATA);
		HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, NAUTONEG_MSG,
			"Frame Reg :mii_read: successful:data = %X ", *datap);
		return (0);
	}

}

static void
hme_mii_write(struct hme *hmep, uint8_t regad, uint16_t data)
{
	volatile uint32_t *framerp = &hmep->hme_mifregp->mif_frame;
	uint32_t frame;
	uint8_t	phyad;

	if (!hmep->hme_frame_enable) {
		hme_bb_mii_write(hmep, regad, data);
		return;
	}

	phyad = hmep->hme_phyad;
	HME_DEBUG_MSG4(hmep,  SEVERITY_UNKNOWN, NAUTONEG_MSG,
			"FRame Reg :mii_write: phyad = %X \
			reg = %X data = %X", phyad, regad, data);

	*framerp = HME_MIF_FRWRITE | (phyad << HME_MIF_FRPHYAD_SHIFT) |
					(regad << HME_MIF_FRREGAD_SHIFT) | data;
/*
 *	HMEDELAY((*framerp & HME_MIF_FRTA0), HMEMAXRSTDELAY);
 */
	HMEDELAY((*framerp & HME_MIF_FRTA0), 300);
	frame = *framerp;
	CHECK_MIFREG();
	if ((frame & HME_MIF_FRTA0) == 0) {
		HME_FAULT_MSG1(hmep, SEVERITY_MID, NAUTONEG_MSG,
				mif_write_fail_msg);
	}
#if HME_DEBUG
	else {
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, NAUTONEG_MSG,
				"Frame Reg :mii_write: successful");
	}
#endif
}

/*
 * hme_stop_timer function is used by a function before doing link-related
 * processing. It locks the "hme_linklock" to protect the link-related data
 * structures. This lock will be subsequently released in hme_start_timer().
 */
static void
hme_stop_timer(struct hme *hmep)
{
	timeout_id_t	tid;

	mutex_enter(&hmep->hme_linklock);

	if (hmep->hme_timerid) {
		tid = hmep->hme_timerid;
		hmep->hme_timerid = 0;
		mutex_exit(&hmep->hme_linklock);
		(void) untimeout(tid);
		mutex_enter(&hmep->hme_linklock);
	}
}

static void
hme_start_timer(struct hme *hmep, fptrv_t func, int msec)
{
	if (!(hmep->hme_flags & HMENOTIMEOUTS))
		hmep->hme_timerid = timeout(func, (caddr_t)hmep,
		    drv_usectohz(1000 * msec));

	mutex_exit(&hmep->hme_linklock);
}

/*
 * hme_select_speed is required only when auto-negotiation is not supported.
 * It should be used only for the Internal Transceiver and not the External
 * transceiver because we wouldn't know how to generate Link Down state on
 * the wire.
 * Currently it is required to support Electron 1.1 Build machines. When all
 * these machines are upgraded to 1.2 or better, remove this function.
 *
 * Returns 1 if the link is up, 0 otherwise.
 */

static int
hme_select_speed(struct hme *hmep, int speed)
{
	uint16_t	stat;
	uint16_t	fdx;

	if (hmep->hme_linkup_cnt)  /* not first time */
		goto read_status;

	if (hmep->hme_fdx)
		fdx = PHY_BMCR_FDX;
	else
		fdx = 0;

	switch (speed) {
	case HME_SPEED_100:

		switch (hmep->hme_transceiver) {
		case HME_INTERNAL_TRANSCEIVER:
			hme_mii_write(hmep, HME_PHY_BMCR, fdx | PHY_BMCR_100M);
			break;
		case HME_EXTERNAL_TRANSCEIVER:
			if (hmep->hme_delay == 0) {
				hme_mii_write(hmep, HME_PHY_BMCR,
							fdx | PHY_BMCR_100M);
			}
			break;
		default:
			HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, XCVR_MSG,
					"Default in select speed 100");
			break;
		}
		break;
	case HME_SPEED_10:
		switch (hmep->hme_transceiver) {
		case HME_INTERNAL_TRANSCEIVER:
			hme_mii_write(hmep, HME_PHY_BMCR, fdx);
			break;
		case HME_EXTERNAL_TRANSCEIVER:
			if (hmep->hme_delay == 0) {
				hme_mii_write(hmep, HME_PHY_BMCR, fdx);
			}
			break;
		default:
			HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, XCVR_MSG,
					"Default in select speed 10");
			break;
		}
		break;
	default:
		HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, XCVR_MSG,
				"Default in select speed : Neither speed");
		return (0);
	}

	if (!hmep->hme_linkup_cnt) {  /* first time; select speed */
		(void) hme_mii_read(hmep, HME_PHY_BMSR, &stat);
		hmep->hme_linkup_cnt++;
		return (0);
	}

read_status:
	hmep->hme_linkup_cnt++;
	(void) hme_mii_read(hmep, HME_PHY_BMSR, &stat);
	if (stat & PHY_BMSR_LNKSTS)
		return (1);
	else
		return (0);
}


#define	HME_PHYRST_PERIOD 600	/* 600 milliseconds, instead of 500 */
#define	HME_PDOWN_PERIOD 256	/* 256 milliseconds  power down period to */
				/* insure a good reset of the QSI PHY */

static void
hme_reset_transceiver(struct hme *hmep)
{
	uint32_t	cfg;
	uint16_t	stat;
	uint16_t	anar;
	uint16_t	control;
	uint16_t	csc;
	int		n;

	cfg = GET_MIFREG(mif_cfg);

	if (hmep->hme_transceiver == HME_EXTERNAL_TRANSCEIVER) {
		/* Isolate the Internal Transceiver */
		PUT_MIFREG(mif_cfg, (cfg & ~HME_MIF_CFGPS));
		hmep->hme_phyad = HME_INTERNAL_PHYAD;
		hmep->hme_transceiver = HME_INTERNAL_TRANSCEIVER;
		hme_mii_write(hmep, HME_PHY_BMCR, (PHY_BMCR_ISOLATE |
				PHY_BMCR_PWRDN | PHY_BMCR_LPBK));
		if (hme_mii_read(hmep, HME_PHY_BMCR, &control) == 1)
			goto start_again;

		/* select the External transceiver */
		PUT_MIFREG(mif_cfg, (cfg | HME_MIF_CFGPS));
		hmep->hme_transceiver = HME_EXTERNAL_TRANSCEIVER;
		hmep->hme_phyad = HME_EXTERNAL_PHYAD;

	} else if (cfg & HME_MIF_CFGM1) {
		/* Isolate the External transceiver, if present */
		PUT_MIFREG(mif_cfg, (cfg | HME_MIF_CFGPS));
		hmep->hme_phyad = HME_EXTERNAL_PHYAD;
		hmep->hme_transceiver = HME_EXTERNAL_TRANSCEIVER;
		hme_mii_write(hmep, HME_PHY_BMCR, (PHY_BMCR_ISOLATE |
				PHY_BMCR_PWRDN | PHY_BMCR_LPBK));
		if (hme_mii_read(hmep, HME_PHY_BMCR, &control) == 1)
			goto start_again;

		/* select the Internal transceiver */
		PUT_MIFREG(mif_cfg, (cfg & ~HME_MIF_CFGPS));
		hmep->hme_transceiver = HME_INTERNAL_TRANSCEIVER;
		hmep->hme_phyad = HME_INTERNAL_PHYAD;
	}

	hme_mii_write(hmep, HME_PHY_BMCR, PHY_BMCR_PWRDN);
	drv_usecwait((clock_t)HME_PDOWN_PERIOD);

	/*
	 * Now reset the transceiver.
	 */
	hme_mii_write(hmep, HME_PHY_BMCR, PHY_BMCR_RESET);

	/*
	 * Check for transceiver reset completion.
	 */
	n = HME_PHYRST_PERIOD / HMEWAITPERIOD;

	while (--n > 0) {
		if (hme_mii_read(hmep, HME_PHY_BMCR, &control) == 1) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, XCVR_MSG,
					xcvr_no_mii_msg);
			goto start_again;
		}
		if ((control & PHY_BMCR_RESET) == 0)
			goto reset_issued;
		if (hmep->hme_transceiver == HME_INTERNAL_TRANSCEIVER)
			drv_usecwait((clock_t)HMEWAITPERIOD);
		else
			drv_usecwait((clock_t)(500 * HMEWAITPERIOD));
	}
	/*
	 * phy reset failure
	 */
	hmep->phyfail++;
	goto start_again;

reset_issued:

	HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, PHY_MSG,
			"reset_trans: reset complete.");

	/*
	 * Get the PHY id registers. We need this to implement work-arounds
	 * for bugs in transceivers which use the National DP83840 PHY chip.
	 * National should fix this in the next release.
	 */

	(void) hme_mii_read(hmep, HME_PHY_BMSR, &stat);
	(void) hme_mii_read(hmep, HME_PHY_IDR1, &hmep->hme_idr1);
	(void) hme_mii_read(hmep, HME_PHY_IDR2, &hmep->hme_idr2);
	(void) hme_mii_read(hmep, HME_PHY_ANAR, &anar);

	hme_init_xcvr_info(hmep);
	HME_DEBUG_MSG6(hmep, SEVERITY_UNKNOWN, PHY_MSG,
	"reset_trans: control = %x status = %x idr1 = %x idr2 = %x anar = %x",
	control, stat, hmep->hme_idr1, hmep->hme_idr2, anar);

	hmep->hme_bmcr = control;
	hmep->hme_anar = anar;
	hmep->hme_bmsr = stat;

	/*
	 * The strapping of AN0 and AN1 pins on DP83840 cannot select
	 * 10FDX, 100FDX and Auto-negotiation. So select it here for the
	 * Internal Transceiver.
	 */
	if (hmep->hme_transceiver == HME_INTERNAL_TRANSCEIVER) {
		anar = (PHY_ANAR_TXFDX | PHY_ANAR_10FDX |
			PHY_ANAR_TX | PHY_ANAR_10 | PHY_SELECTOR);
	}
	/*
	 * Modify control and bmsr based on anar for Rev-C of DP83840.
	 */
	if (HME_DP83840) {
		n = 0;
		if (anar & PHY_ANAR_TXFDX) {
			stat |= PHY_BMSR_100FDX;
			n++;
		} else
			stat &= ~PHY_BMSR_100FDX;

		if (anar & PHY_ANAR_TX) {
			stat |= PHY_BMSR_100HDX;
			n++;
		} else
			stat &= ~PHY_BMSR_100HDX;

		if (anar & PHY_ANAR_10FDX) {
			stat |= PHY_BMSR_10FDX;
			n++;
		} else
			stat &= ~PHY_BMSR_10FDX;

		if (anar & PHY_ANAR_10) {
			stat |= PHY_BMSR_10HDX;
			n++;
		} else
			stat &= ~PHY_BMSR_10HDX;

		if (n == 1) { 	/* only one mode. disable auto-negotiation */
			stat &= ~PHY_BMSR_ACFG;
			control &= ~PHY_BMCR_ANE;
		}
		if (n) {
			hmep->hme_bmsr = stat;
			hmep->hme_bmcr = control;

			HME_DEBUG_MSG4(hmep, SEVERITY_NONE, PHY_MSG,
			    "DP83840 Rev-C found: Modified bmsr = %x "
			    "control = %X n = %x", stat, control, n);
		}
	}
	hme_setup_link_default(hmep);
	hme_setup_link_status(hmep);


	/*
	 * Place the Transceiver in normal operation mode
	 */
	hme_mii_write(hmep, HME_PHY_BMCR, (control & ~PHY_BMCR_ISOLATE));

	/*
	 * check if the transceiver is not in Isolate mode
	 */
	n = HME_PHYRST_PERIOD / HMEWAITPERIOD;

	while (--n > 0) {
		if (hme_mii_read(hmep, HME_PHY_BMCR, &control) == 1) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, XCVR_MSG,
					xcvr_no_mii_msg);
			goto start_again; /* Transceiver does not talk MII */
		}
		if ((control & PHY_BMCR_ISOLATE) == 0)
			goto setconn;
		drv_usecwait(HMEWAITPERIOD);
	}
	HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, XCVR_MSG,
			xcvr_isolate_msg);
	goto start_again;	/* transceiver reset failure */

setconn:
	HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, PHY_MSG,
			"reset_trans: isolate complete.");

	/*
	 * Work-around for the late-collision problem with 100m cables.
	 * National should fix this in the next release !
	 */
	if (HME_DP83840) {
		(void) hme_mii_read(hmep, HME_PHY_CSC, &csc);

		HME_DEBUG_MSG3(hmep, SEVERITY_NONE, LATECOLL_MSG,
		"hme_reset_trans: CSC read = %x written = %x",
				csc, csc | PHY_CSCR_FCONN);

		hme_mii_write(hmep, HME_PHY_CSC, (csc | PHY_CSCR_FCONN));
	}

	hmep->hme_linkcheck =		0;
	hmep->hme_linkup =		0;
	hme_setup_link_status(hmep);
	hmep->hme_autoneg =		HME_HWAN_TRY;
	hmep->hme_force_linkdown =	HME_FORCE_LINKDOWN;
	hmep->hme_linkup_cnt =		0;
	hmep->hme_delay =		0;
	hme_setup_link_control(hmep);
	hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);

	if (hmep->hme_mode == HME_FORCE_SPEED)
		hme_force_speed(hmep);
	else {
		hmep->hme_linkup_10 = 	0;
		hmep->hme_tryspeed =	HME_SPEED_100;
		hmep->hme_ntries =	HME_NTRIES_LOW;
		hmep->hme_nlasttries =	HME_NTRIES_LOW;
		hme_try_speed(hmep);
	}
	return;

start_again:
	hme_start_timer(hmep, hme_check_link, HME_TICKS);
}

static void
hme_check_transceiver(struct hme *hmep)
{
	uint32_t	cfgsav;
	uint32_t 	cfg;
	uint32_t 	stat;

	/*
	 * If the MIF Polling is ON, and Internal transceiver is in use, just
	 * check for the presence of the External Transceiver.
	 * Otherwise:
	 * First check to see what transceivers are out there.
	 * If an external transceiver is present
	 * then use it, regardless of whether there is a Internal transceiver.
	 * If Internal transceiver is present and no external transceiver
	 * then use the Internal transceiver.
	 * If there is no external transceiver and no Internal transceiver,
	 * then something is wrong so print an error message.
	 */

	cfgsav = GET_MIFREG(mif_cfg);

	if (hmep->hme_polling_on) {
		HME_DEBUG_MSG2(hmep, SEVERITY_NONE, XCVR_MSG,
				"check_trans: polling_on: cfg = %X", cfgsav);

		if (hmep->hme_transceiver == HME_INTERNAL_TRANSCEIVER) {
			if ((cfgsav & HME_MIF_CFGM1) && !hme_param_use_intphy) {
				hme_stop_mifpoll(hmep);
				hmep->hme_phyad = HME_EXTERNAL_PHYAD;
				hmep->hme_transceiver =
						HME_EXTERNAL_TRANSCEIVER;
				PUT_MIFREG(mif_cfg, ((cfgsav & ~HME_MIF_CFGPE)
						| HME_MIF_CFGPS));
			}
		} else if (hmep->hme_transceiver == HME_EXTERNAL_TRANSCEIVER) {
			stat = (GET_MIFREG(mif_bsts) >> 16);
			if ((stat == 0x00) || (hme_param_use_intphy)) {
				HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN,
						XCVR_MSG,
						"Extern Transcvr Disconnected");

				hme_stop_mifpoll(hmep);
				hmep->hme_phyad = HME_INTERNAL_PHYAD;
				hmep->hme_transceiver =
						HME_INTERNAL_TRANSCEIVER;
				PUT_MIFREG(mif_cfg, (GET_MIFREG(mif_cfg)
						& ~HME_MIF_CFGPS));
			}
		}
		CHECK_MIFREG();
		return;
	}

	HME_DEBUG_MSG2(hmep, SEVERITY_NONE, XCVR_MSG,
		"check_trans: polling_off: cfg = %X", cfgsav);

	cfg = GET_MIFREG(mif_cfg);
	if ((cfg & HME_MIF_CFGM1) && !hme_param_use_intphy) {
		PUT_MIFREG(mif_cfg, (cfgsav | HME_MIF_CFGPS));
		hmep->hme_phyad = HME_EXTERNAL_PHYAD;
		hmep->hme_transceiver = HME_EXTERNAL_TRANSCEIVER;

	} else if (cfg & HME_MIF_CFGM0) {  /* Internal Transceiver OK */
		PUT_MIFREG(mif_cfg, (cfgsav & ~HME_MIF_CFGPS));
		hmep->hme_phyad = HME_INTERNAL_PHYAD;
		hmep->hme_transceiver = HME_INTERNAL_TRANSCEIVER;

	} else {
		hmep->hme_transceiver = HME_NO_TRANSCEIVER;
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, XCVR_MSG, no_xcvr_msg);
	}
	CHECK_MIFREG();
}

static void
hme_setup_link_default(struct hme *hmep)
{
	uint16_t	bmsr;

	bmsr = hmep->hme_bmsr;
	if (hme_param_autoneg & HME_NOTUSR)
		hme_param_autoneg = HME_NOTUSR |
					((bmsr & PHY_BMSR_ACFG) ? 1 : 0);
	if (hme_param_anar_100T4 & HME_NOTUSR)
		hme_param_anar_100T4 = HME_NOTUSR |
					((bmsr & PHY_BMSR_100T4) ? 1 : 0);
	if (hme_param_anar_100fdx & HME_NOTUSR)
		hme_param_anar_100fdx = HME_NOTUSR |
					((bmsr & PHY_BMSR_100FDX) ? 1 : 0);
	if (hme_param_anar_100hdx & HME_NOTUSR)
		hme_param_anar_100hdx = HME_NOTUSR |
					((bmsr & PHY_BMSR_100HDX) ? 1 : 0);
	if (hme_param_anar_10fdx & HME_NOTUSR)
		hme_param_anar_10fdx = HME_NOTUSR |
					((bmsr & PHY_BMSR_10FDX) ? 1 : 0);
	if (hme_param_anar_10hdx & HME_NOTUSR)
		hme_param_anar_10hdx = HME_NOTUSR |
					((bmsr & PHY_BMSR_10HDX) ? 1 : 0);
}

static void
hme_setup_link_status(struct hme *hmep)
{
	uint16_t	tmp;

	if (hmep->hme_transceiver == HME_EXTERNAL_TRANSCEIVER)
		hme_param_transceiver = 1;
	else
		hme_param_transceiver = 0;

	tmp = hmep->hme_bmsr;
	if (tmp & PHY_BMSR_ACFG)
		hme_param_bmsr_ancap = 1;
	else
		hme_param_bmsr_ancap = 0;
	if (tmp & PHY_BMSR_100T4)
		hme_param_bmsr_100T4 = 1;
	else
		hme_param_bmsr_100T4 = 0;
	if (tmp & PHY_BMSR_100FDX)
		hme_param_bmsr_100fdx = 1;
	else
		hme_param_bmsr_100fdx = 0;
	if (tmp & PHY_BMSR_100HDX)
		hme_param_bmsr_100hdx = 1;
	else
		hme_param_bmsr_100hdx = 0;
	if (tmp & PHY_BMSR_10FDX)
		hme_param_bmsr_10fdx = 1;
	else
		hme_param_bmsr_10fdx = 0;
	if (tmp & PHY_BMSR_10HDX)
		hme_param_bmsr_10hdx = 1;
	else
		hme_param_bmsr_10hdx = 0;

	if (hmep->hme_link_pulse_disabled) {
		hme_param_linkup =	1;
		hmep->hme_link_up =	1;
		hme_param_speed =	0;
		hme_param_mode =	0;
		hmep->link_duplex =	1;
		hmenotify_ind(hmep, DL_NOTE_LINK_UP);
		hmenotify_ind(hmep, DL_NOTE_SPEED);
		return;
	}

	if (!hmep->hme_linkup) {
		hme_param_linkup =	0;
		hmep->hme_link_up =	0;
		hmep->link_duplex = 0;
		hmenotify_ind(hmep, DL_NOTE_LINK_DOWN);
		return;
	}

	hme_param_linkup = 1;
	hmep->hme_link_up = 1;
	hmenotify_ind(hmep, DL_NOTE_LINK_UP);
	hmenotify_ind(hmep, DL_NOTE_SPEED);

	if (hmep->hme_fdx == HME_FULL_DUPLEX) {
		hme_param_mode = 1;
		hmep->link_duplex = 2;
	} else {
		hme_param_mode = 0;
		hmep->link_duplex = 1;
	}

	if (hmep->hme_mode == HME_FORCE_SPEED) {
		if (hmep->hme_forcespeed == HME_SPEED_100)
			hme_param_speed = 1;
		else
			hme_param_speed = 0;
		return;
	}
	if (hmep->hme_tryspeed == HME_SPEED_100)
		hme_param_speed = 1;
	else
		hme_param_speed = 0;


	if (!(hmep->hme_aner & PHY_ANER_LPNW)) {
		hme_param_aner_lpancap =	0;
		hme_param_anlpar_100T4 =	0;
		hme_param_anlpar_100fdx =	0;
		hme_param_anlpar_100hdx =	0;
		hme_param_anlpar_10fdx =	0;
		hme_param_anlpar_10hdx =	0;
		return;
	}
	hme_param_aner_lpancap = 1;
	tmp = hmep->hme_anlpar;
	if (tmp & PHY_ANLPAR_T4)
		hme_param_anlpar_100T4 = 1;
	else
		hme_param_anlpar_100T4 = 0;
	if (tmp & PHY_ANLPAR_TXFDX)
		hme_param_anlpar_100fdx = 1;
	else
		hme_param_anlpar_100fdx = 0;
	if (tmp & PHY_ANLPAR_TX)
		hme_param_anlpar_100hdx = 1;
	else
		hme_param_anlpar_100hdx = 0;
	if (tmp & PHY_ANLPAR_10FDX)
		hme_param_anlpar_10fdx = 1;
	else
		hme_param_anlpar_10fdx = 0;
	if (tmp & PHY_ANLPAR_10)
		hme_param_anlpar_10hdx = 1;
	else
		hme_param_anlpar_10hdx = 0;
}

static void
hme_setup_link_control(struct hme *hmep)
{
	uint_t anar = PHY_SELECTOR;
	uint32_t autoneg = ~HME_NOTUSR & hme_param_autoneg;
	uint32_t anar_100T4 = ~HME_NOTUSR & hme_param_anar_100T4;
	uint32_t anar_100fdx = ~HME_NOTUSR & hme_param_anar_100fdx;
	uint32_t anar_100hdx = ~HME_NOTUSR & hme_param_anar_100hdx;
	uint32_t anar_10fdx = ~HME_NOTUSR & hme_param_anar_10fdx;
	uint32_t anar_10hdx = ~HME_NOTUSR & hme_param_anar_10hdx;

	if (autoneg) {
		hmep->hme_mode = HME_AUTO_SPEED;
		hmep->hme_tryspeed = HME_SPEED_100;
		if (anar_100T4)
			anar |= PHY_ANAR_T4;
		if (anar_100fdx)
			anar |= PHY_ANAR_TXFDX;
		if (anar_100hdx)
			anar |= PHY_ANAR_TX;
		if (anar_10fdx)
			anar |= PHY_ANAR_10FDX;
		if (anar_10hdx)
			anar |= PHY_ANAR_10;
		hmep->hme_anar = anar;
	} else {
		hmep->hme_mode = HME_FORCE_SPEED;
		if (anar_100T4) {
			hmep->hme_forcespeed = HME_SPEED_100;
			hmep->hme_fdx = HME_HALF_DUPLEX;
			HME_DEBUG_MSG1(hmep, SEVERITY_NONE, NAUTONEG_MSG,
					"hme_link_control: force 100T4 hdx");

		} else if (anar_100fdx) {
			/* 100fdx needs to be checked first for 100BaseFX */
			hmep->hme_forcespeed = HME_SPEED_100;
			hmep->hme_fdx = HME_FULL_DUPLEX;

		} else if (anar_100hdx) {
			hmep->hme_forcespeed = HME_SPEED_100;
			hmep->hme_fdx = HME_HALF_DUPLEX;
			HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, NAUTONEG_MSG,
					"hme_link_control: force 100 hdx");
		} else if (anar_10hdx) {
			/* 10hdx needs to be checked first for MII-AUI */
			/* MII-AUI BugIds 1252776,4032280,4035106,4028558 */
			hmep->hme_forcespeed = HME_SPEED_10;
			hmep->hme_fdx = HME_HALF_DUPLEX;

		} else if (anar_10fdx) {
			hmep->hme_forcespeed = HME_SPEED_10;
			hmep->hme_fdx = HME_FULL_DUPLEX;

		} else {
			hmep->hme_forcespeed = HME_SPEED_10;
			hmep->hme_fdx = HME_HALF_DUPLEX;
			HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, NAUTONEG_MSG,
					"hme_link_control: force 10 hdx");
		}
	}
}

/* Decide if transmitter went dead and reinitialize everything */
static int hme_txhung_limit = 3;
static int
hme_check_txhung(struct hme *hmep)
{
	boolean_t status;

	mutex_enter(&hmep->hme_xmitlock);
	if (hmep->hme_flags & HMERUNNING)
		hmereclaim(hmep);

	/* Something needs to be sent out but it is not going out */
	if ((hmep->hme_tcurp != hmep->hme_tnextp) &&
	    (hmep->hme_opackets == hmep->hmesave.hme_opackets))
		hmep->hme_txhung++;
	else
		hmep->hme_txhung = 0;

	hmep->hmesave.hme_opackets = hmep->hme_opackets;

	status = hmep->hme_txhung >= hme_txhung_limit;
	mutex_exit(&hmep->hme_xmitlock);

	return (status);
}

/*
 * 	hme_check_link ()
 * Called as a result of HME_LINKCHECK_TIMER timeout, to poll for Transceiver
 * change or when a transceiver change has been detected by the hme_try_speed
 * function.
 * This function will also be called from the interrupt handler when polled mode
 * is used. Before calling this function the interrupt lock should be freed
 * so that the hmeinit() may be called.
 * Note that the hmeinit() function calls hme_select_speed() to set the link
 * speed and check for link status.
 */

static void
hme_check_link(void *arg)
{
	struct hme *hmep = arg;
	uint16_t	stat;
	uint_t 	temp;

	hme_stop_timer(hmep);	/* acquire hme_linklock */

	HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, XCVR_MSG,
			"link_check entered:");
	/*
	 * This condition was added to work around for
	 * a problem with the Synoptics/Bay 28115 switch.
	 * Basically if the link is up but no packets
	 * are being received. This can be checked using
	 * ipackets, which in case of reception will
	 * continue to increment after 'hmep->hme_iipackets'
	 * has been made equal to it and the 'hme_check_link'
	 * timer has expired. Note this could also be done
	 * if there's no traffic on the net.
	 * 'hmep->hme_ipackets' is incremented in hme_read
	 * for successfully received packets.
	 */
	if ((hmep->hme_flags & HMERUNNING) && (hmep->hme_linkup)) {
		if (hmep->hme_ipackets != hmep->hme_iipackets)
			/*
			 * Receptions are occurring set 'hmep->hme_iipackets'
			 * to 'hmep->hme_ipackets' to monitor if receptions
			 * occur during the next timeout interval.
			 */
			hmep->hme_iipackets = hmep->hme_ipackets;
		else
			/*
			 * Receptions not occurring could be due to
			 * Synoptics problem, try switchin of data
			 * scrabbling. That should bring up the link.
			 */
			hme_link_now_up(hmep);
	}

	if ((hmep->hme_flags & HMERUNNING) &&
	    (hmep->hme_linkup) && (hme_check_txhung(hmep))) {

		HME_DEBUG_MSG1(hmep, SEVERITY_LOW, XCVR_MSG,
				"txhung: re-init MAC");
		hme_reinit_txhung++;
		hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);
		(void) hmeinit(hmep);	/* To reset the transceiver and */
					/* to init the interface */
		return;
	}

	/*
	 * check if the transceiver is the same.
	 * init to be done if the external transceiver is
	 * connected/disconnected
	 */
	temp = hmep->hme_transceiver; /* save the transceiver type */
	hme_check_transceiver(hmep);
	if ((temp != hmep->hme_transceiver) || (hmep->hme_linkup == 0)) {
		if (temp != hmep->hme_transceiver) {
			if (hmep->hme_transceiver == HME_EXTERNAL_TRANSCEIVER) {
				HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN,
					XCVR_MSG, ext_xcvr_msg);
			} else {
				HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN,
					XCVR_MSG, int_xcvr_msg);
			}
		}
		hmep->hme_linkcheck = 0;
		hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);
		(void) hmeinit(hmep); /* To reset the transceiver and */
					/* to init the interface */
		return;
	}


	if (hmep->hme_mifpoll_enable) {
		stat = (GET_MIFREG(mif_bsts) >> 16);

		CHECK_MIFREG(); /* Verify */
		HME_DEBUG_MSG4(hmep, SEVERITY_UNKNOWN, MIFPOLL_MSG,
				"int_flag = %X old_stat = %X stat = %X",
			hmep->hme_mifpoll_flag, hmep->hme_mifpoll_data, stat);

		if (!hmep->hme_mifpoll_flag) {
			if (stat & PHY_BMSR_LNKSTS) {
				hme_start_timer(hmep, hme_check_link,
							HME_LINKCHECK_TIMER);
				return;
			}
			HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, MIFPOLL_MSG,
				"hme_check_link:DOWN polled data = %X\n", stat);
			hme_stop_mifpoll(hmep);

			temp = (GET_MIFREG(mif_bsts) >> 16);
			HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, MIFPOLL_MSG,
				"hme_check_link:after poll-stop: stat = %X",
									temp);
		} else {
			hmep->hme_mifpoll_flag = 0;
		}
	} else {
		if (hme_mii_read(hmep, HME_PHY_BMSR, &stat) == 1) {
		/* Transceiver does not talk mii */
			hme_start_timer(hmep, hme_check_link,
					HME_LINKCHECK_TIMER);
			return;
		}

		if (stat & PHY_BMSR_LNKSTS) {
			hme_start_timer(hmep, hme_check_link,
					HME_LINKCHECK_TIMER);
			return;
		}
	}
	HME_DEBUG_MSG3(hmep, SEVERITY_UNKNOWN, MIFPOLL_MSG,
			"mifpoll_flag = %x first stat = %X",
			hmep->hme_mifpoll_flag, stat);

	(void) hme_mii_read(hmep, HME_PHY_BMSR, &stat);
	HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, MIFPOLL_MSG,
			"second stat = %X", stat);
	/*
	 * The PHY may have automatically renegotiated link speed and mode.
	 * Get the new link speed and mode.
	 */
	if ((stat & PHY_BMSR_LNKSTS) && hme_autoneg_enable) {
		if (hmep->hme_mode == HME_AUTO_SPEED) {
			hmep->hme_linkup_msg = 1;
			(void) hme_get_autoinfo(hmep);
			hme_setup_link_status(hmep);
			hme_start_mifpoll(hmep);
			if (hmep->hme_fdx != hmep->hme_macfdx) {
				hme_start_timer(hmep, hme_check_link,
						HME_LINKCHECK_TIMER);
				(void) hmeinit(hmep);
				return;
			}
		}
		hme_start_mifpoll(hmep);
		hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);
		return;
	}
	hmep->hme_linkup_msg = 1; /* Enable display of messages */

	/* Reset the PHY and bring up the link */
	hme_reset_transceiver(hmep);
}

static void
hme_init_xcvr_info(struct hme *hmep)
{
	uint16_t phy_id1, phy_id2;

	(void) hme_mii_read(hmep, HME_PHY_IDR1, &phy_id1);
	(void) hme_mii_read(hmep, HME_PHY_IDR2, &phy_id2);

	hmep->xcvr_vendor_id = ((phy_id1 << 0x6) | (phy_id2 >> 10));
	hmep->xcvr_dev_id = (phy_id2 >>4) & 0x3f;
	hmep->xcvr_dev_rev =  (phy_id2 & 0xf);
}

static void
hme_display_transceiver(struct hme *hmep)
{
	switch (hmep->hme_transceiver) {
	case HME_INTERNAL_TRANSCEIVER:
		ddi_dev_report_fault(hmep->dip, DDI_SERVICE_RESTORED,
			DDI_DEVICE_FAULT, int_xcvr_msg);
		break;

	case HME_EXTERNAL_TRANSCEIVER:
		ddi_dev_report_fault(hmep->dip, DDI_SERVICE_RESTORED,
			DDI_EXTERNAL_FAULT, ext_xcvr_msg);
		break;

	default:
		ddi_dev_report_fault(hmep->dip, DDI_SERVICE_DEGRADED,
			DDI_EXTERNAL_FAULT, no_xcvr_msg);
		break;
	}
}

/*
 * Disable link pulses for the Internal Transceiver
 */

static void
hme_disable_link_pulse(struct hme *hmep)
{
	uint16_t	nicr;

	hme_mii_write(hmep, HME_PHY_BMCR, 0); /* force 10 Mbps */
	(void) hme_mii_read(hmep, HME_PHY_NICR, &nicr);

	HME_DEBUG_MSG3(hmep, SEVERITY_NONE, LINKPULSE_MSG,
			"hme_disable_link_pulse: NICR read = %x written = %x",
			nicr, nicr & ~PHY_NICR_LD);

	hme_mii_write(hmep, HME_PHY_NICR, (nicr & ~PHY_NICR_LD));

	hmep->hme_linkup = 1;
	hmep->hme_linkcheck = 1;
	hme_display_transceiver(hmep);
	hme_display_linkup(hmep, HME_SPEED_10);
	hme_setup_link_status(hmep);
	hme_start_mifpoll(hmep);
	hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);
}

static void
hme_force_speed(void *arg)
{
	struct hme	*hmep = arg;
	int		linkup;
	uint_t		temp;
	uint16_t	csc;

	HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, PROP_MSG,
			"hme_force_speed entered");

	hme_stop_timer(hmep);
	if (hmep->hme_fdx != hmep->hme_macfdx) {
		hme_start_timer(hmep, hme_check_link, HME_TICKS*5);
		return;
	}
	temp = hmep->hme_transceiver; /* save the transceiver type */
	hme_check_transceiver(hmep);
	if (temp != hmep->hme_transceiver) {
		if (hmep->hme_transceiver == HME_EXTERNAL_TRANSCEIVER) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, XCVR_MSG,
					ext_xcvr_msg);
		} else {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, XCVR_MSG,
					int_xcvr_msg);
		}
		hme_start_timer(hmep, hme_check_link, HME_TICKS * 10);
		return;
	}

	if ((hmep->hme_transceiver == HME_INTERNAL_TRANSCEIVER) &&
					(hmep->hme_link_pulse_disabled)) {
		hmep->hme_forcespeed = HME_SPEED_10;
		hme_disable_link_pulse(hmep);
		return;
	}

	/*
	 * To interoperate with auto-negotiable capable systems
	 * the link should be brought down for 1 second.
	 * How to do this using only standard registers ?
	 */
	if (HME_DP83840) {
		if (hmep->hme_force_linkdown == HME_FORCE_LINKDOWN) {
			hmep->hme_force_linkdown = HME_LINKDOWN_STARTED;
			hme_mii_write(hmep, HME_PHY_BMCR, PHY_BMCR_100M);
			(void) hme_mii_read(hmep, HME_PHY_CSC, &csc);
			hme_mii_write(hmep, HME_PHY_CSC,
						(csc | PHY_CSCR_TXOFF));
			hme_start_timer(hmep, hme_force_speed, 10 * HME_TICKS);
			return;
		} else if (hmep->hme_force_linkdown == HME_LINKDOWN_STARTED) {
			(void) hme_mii_read(hmep, HME_PHY_CSC, &csc);
			hme_mii_write(hmep, HME_PHY_CSC,
						(csc & ~PHY_CSCR_TXOFF));
			hmep->hme_force_linkdown = HME_LINKDOWN_DONE;
		}
	} else {
		if (hmep->hme_force_linkdown == HME_FORCE_LINKDOWN) {
#ifdef	HME_100T4_DEBUG
	{
		uint16_t control, stat, aner, anlpar, anar;

		(void) hme_mii_read(hmep, HME_PHY_BMCR, &control);
		(void) hme_mii_read(hmep, HME_PHY_BMSR, &stat);
		(void) hme_mii_read(hmep, HME_PHY_ANER, &aner);
		(void) hme_mii_read(hmep, HME_PHY_ANLPAR, &anlpar);
		(void) hme_mii_read(hmep, HME_PHY_ANAR, &anar);
		HME_DEBUG_MSG5(hmep, SEVERITY_NONE, XCVR_MSG,
				"hme_force_speed: begin:control ="
				"  %X stat = %X aner = %X anar = %X"
				" anlpar = %X",
				control, stat, aner, anar, anlpar);
	}
#endif
			hmep->hme_force_linkdown = HME_LINKDOWN_STARTED;
			hme_mii_write(hmep, HME_PHY_BMCR, PHY_BMCR_LPBK);
			hme_start_timer(hmep, hme_force_speed, 10 * HME_TICKS);
			return;
		} else if (hmep->hme_force_linkdown == HME_LINKDOWN_STARTED) {
			hmep->hme_force_linkdown = HME_LINKDOWN_DONE;
		}
	}


	linkup = hme_select_speed(hmep, hmep->hme_forcespeed);
	if (hmep->hme_linkup_cnt == 1) {
		hme_start_timer(hmep, hme_force_speed, SECOND(4));
		return;
	}
	if (linkup) {

#ifdef	HME_100T4_DEBUG
	{
		uint16_t control, stat, aner, anlpar, anar;

		(void) hme_mii_read(hmep, HME_PHY_BMCR, &control);
		(void) hme_mii_read(hmep, HME_PHY_BMSR, &stat);
		(void) hme_mii_read(hmep, HME_PHY_ANER, &aner);
		(void) hme_mii_read(hmep, HME_PHY_ANLPAR, &anlpar);
		(void) hme_mii_read(hmep, HME_PHY_ANAR, &anar);
		HME_DEBUG_MSG5(hmep, SEVERITY_NONE, XCVR_MSG,
				"hme_force_speed:end: control ="
				"%X stat = %X aner = %X anar = %X anlpar = %X",
				control, stat, aner, anar, anlpar);
	}
#endif
		hmep->hme_linkup = 1;
		hmep->hme_linkcheck = 1;
		hmep->hme_ifspeed = hmep->hme_forcespeed;
		hme_link_now_up(hmep);
		hme_display_transceiver(hmep);
		hme_display_linkup(hmep, hmep->hme_forcespeed);
		hme_setup_link_status(hmep);
		hme_start_mifpoll(hmep);
		hmep->hme_linkup_msg = 1; /* Enable display of messages */
		hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);
	} else {
		hme_start_timer(hmep, hme_force_speed, HME_TICKS);
	}
}

static void
hme_get_autoinfo(struct hme *hmep)
{
	uint16_t	anar;
	uint16_t	aner;
	uint16_t	anlpar;
	uint16_t	tmp;
	uint16_t	ar;

	(void) hme_mii_read(hmep, HME_PHY_ANER, &aner);
	(void) hme_mii_read(hmep, HME_PHY_ANLPAR, &anlpar);
	(void) hme_mii_read(hmep, HME_PHY_ANAR, &anar);

	HME_DEBUG_MSG4(hmep, SEVERITY_NONE, AUTONEG_MSG,
	"autoinfo: aner = %X anar = %X anlpar = %X", aner, anar, anlpar);

	hmep->hme_anlpar = anlpar;
	hmep->hme_aner = aner;

	if (aner & PHY_ANER_LPNW) {

			HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
			"hme_try_autoneg: Link Partner AN able");

		tmp = anar & anlpar;
		if (tmp & PHY_ANAR_TXFDX) {
			hmep->hme_tryspeed = HME_SPEED_100;
			hmep->hme_fdx = HME_FULL_DUPLEX;
		} else if (tmp & PHY_ANAR_TX) {
			hmep->hme_tryspeed = HME_SPEED_100;
			hmep->hme_fdx = HME_HALF_DUPLEX;
		} else if (tmp & PHY_ANLPAR_10FDX) {
			hmep->hme_tryspeed = HME_SPEED_10;
			hmep->hme_fdx = HME_FULL_DUPLEX;
		} else if (tmp & PHY_ANLPAR_10) {
			hmep->hme_tryspeed = HME_SPEED_10;
			hmep->hme_fdx = HME_HALF_DUPLEX;
		} else {
			if (HME_DP83840) {

				HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN,
						AUTONEG_MSG,
			"hme_try_autoneg: anar not set with speed selection");

				hmep->hme_fdx = HME_HALF_DUPLEX;
				(void) hme_mii_read(hmep, HME_PHY_AR, &ar);

				HME_DEBUG_MSG2(hmep, SEVERITY_NONE, AUTONEG_MSG,
						"ar = %X", ar);

				if (ar & PHY_AR_SPEED10)
					hmep->hme_tryspeed = HME_SPEED_10;
				else
					hmep->hme_tryspeed = HME_SPEED_100;
			} else
				HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN,
						AUTONEG_MSG, anar_not_set_msg);
		}
		HME_DEBUG_MSG2(hmep, SEVERITY_NONE, AUTONEG_MSG,
				" hme_try_autoneg: fdx = %d", hmep->hme_fdx);
	} else {
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
				" hme_try_autoneg: parallel detection done");

		hmep->hme_fdx = HME_HALF_DUPLEX;
		if (anlpar & PHY_ANLPAR_TX)
			hmep->hme_tryspeed = HME_SPEED_100;
		else if (anlpar & PHY_ANLPAR_10)
			hmep->hme_tryspeed = HME_SPEED_10;
		else {
			if (HME_DP83840) {
				HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN,
						AUTONEG_MSG,
" hme_try_autoneg: parallel detection: anar not set with speed selection");

				(void) hme_mii_read(hmep, HME_PHY_AR, &ar);

				HME_DEBUG_MSG2(hmep, SEVERITY_NONE, AUTONEG_MSG,
						"ar = %X", ar);

				if (ar & PHY_AR_SPEED10)
					hmep->hme_tryspeed = HME_SPEED_10;
				else
					hmep->hme_tryspeed = HME_SPEED_100;
			} else
				HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN,
						AUTONEG_MSG,
						par_detect_anar_not_set_msg);
		}
	}

	hmep->hme_linkup = 1;
	hmep->hme_linkcheck = 1;
	hmep->hme_ifspeed = hmep->hme_tryspeed;
	hme_link_now_up(hmep);
	hme_display_transceiver(hmep);
	hme_display_linkup(hmep, hmep->hme_tryspeed);
}

/*
 * Return 1 if the link is up or auto-negotiation being tried, 0 otherwise.
 */

static int
hme_try_auto_negotiation(struct hme *hmep)
{
	uint16_t	stat;
	uint16_t	aner;
#ifdef	HME_AUTONEG_DEBUG
	uint16_t	anar;
	uint16_t	anlpar;
	uint16_t	control;
#endif

	if (hmep->hme_autoneg == HME_HWAN_TRY) {
		/* auto negotiation not initiated */
		(void) hme_mii_read(hmep, HME_PHY_BMSR, &stat);
		if (hme_mii_read(hmep, HME_PHY_BMSR, &stat) == 1) {
			/*
			 * Transceiver does not talk mii
			 */
			goto hme_anfail;
		}
		if ((stat & PHY_BMSR_ACFG) == 0) { /* auto neg. not supported */

			HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, NAUTONEG_MSG,
					" PHY status reg = %X", stat);
			HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, NAUTONEG_MSG,
					" Auto-negotiation not supported");

			return (hmep->hme_autoneg = HME_HWAN_FAILED);
		}

		/*
		 * Read ANER to clear status from previous operations.
		 */
		if (hme_mii_read(hmep, HME_PHY_ANER, &aner) == 1) {
			/*
			 * Transceiver does not talk mii
			 */
			goto hme_anfail;
		}

		hme_mii_write(hmep, HME_PHY_ANAR, hmep->hme_anar);
		hme_mii_write(hmep, HME_PHY_BMCR, PHY_BMCR_ANE | PHY_BMCR_RAN);
		/*
		 * auto-negotiation initiated
		 */
		hmep->hme_delay = 0;
		hme_start_timer(hmep, hme_try_speed, HME_TICKS);
		return (hmep->hme_autoneg = HME_HWAN_INPROGRESS);
		/*
		 * auto-negotiation in progress
		 */
	}

	/*
	 * Auto-negotiation has been in progress. Wait for at least
	 * least 3000 ms.
	 * Changed 8/28/97 to fix bug ID 4070989.
	 */
	if (hmep->hme_delay < 30) {
		hmep->hme_delay++;
		hme_start_timer(hmep, hme_try_speed, HME_TICKS);
		return (hmep->hme_autoneg = HME_HWAN_INPROGRESS);
	}

	(void) hme_mii_read(hmep, HME_PHY_BMSR, &stat);
	if (hme_mii_read(hmep, HME_PHY_BMSR, &stat) == 1) {
		/*
		 * Transceiver does not talk mii
		 */
		goto hme_anfail;
	}

	if ((stat & PHY_BMSR_ANC) == 0) {
		/*
		 * wait for a maximum of 5 seconds
		 */
		if (hmep->hme_delay < 50) {
			hmep->hme_delay++;
			hme_start_timer(hmep, hme_try_speed, HME_TICKS);
			return (hmep->hme_autoneg = HME_HWAN_INPROGRESS);
		}
#ifdef	HME_AUTONEG_DEBUG
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
				"Auto-negotiation not completed in 5 seconds");
		HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
				" PHY status reg = %X", stat);

		hme_mii_read(hmep, HME_PHY_BMCR, &control);
		HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
				" PHY control reg = %x", control);

		hme_mii_read(hmep, HME_PHY_ANAR, &anar);
		HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
				" PHY anar reg = %x", anar);

		hme_mii_read(hmep, HME_PHY_ANER, &aner);
		HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
				" PHY aner reg = %x", aner);

		hme_mii_read(hmep, HME_PHY_ANLPAR, &anlpar);
		HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
				" PHY anlpar reg = %x", anlpar);
#endif
		if (HME_DP83840) {
			(void) hme_mii_read(hmep, HME_PHY_ANER, &aner);
			if (aner & PHY_ANER_MLF) {

				HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN,
					AUTONEG_MSG,
					" hme_try_autoneg: MLF Detected"
					" after 5 seconds");

				hmep->hme_linkup_msg = 1;
				return (hmep->hme_autoneg = HME_HWAN_FAILED);
			}
		}

		hmep->hme_linkup_msg = 1; /* Enable display of messages */
		goto hme_anfail;
	}

	HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
	"Auto-negotiation completed within %d 100ms time", hmep->hme_delay);

	(void) hme_mii_read(hmep, HME_PHY_ANER, &aner);
	if (aner & PHY_ANER_MLF) {
		HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
				par_detect_msg);
		goto hme_anfail;
	}

	if (!(stat & PHY_BMSR_LNKSTS)) {
		/*
		 * wait for a maximum of 10 seconds
		 */
		if (hmep->hme_delay < 100) {
			hmep->hme_delay++;
			hme_start_timer(hmep, hme_try_speed, HME_TICKS);
			return (hmep->hme_autoneg = HME_HWAN_INPROGRESS);
		}
		HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
			"Link not Up in 10 seconds: stat = %X", stat);
		goto hme_anfail;
	} else {
		hmep->hme_bmsr |= (PHY_BMSR_LNKSTS);
		hme_get_autoinfo(hmep);
		hmep->hme_force_linkdown = HME_LINKDOWN_DONE;
		hme_setup_link_status(hmep);
		hme_start_mifpoll(hmep);
		hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);
		if (hmep->hme_fdx != hmep->hme_macfdx)
			(void) hmeinit(hmep);
		return (hmep->hme_autoneg = HME_HWAN_SUCCESFUL);
	}

hme_anfail:
	HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, AUTONEG_MSG,
			"Retry Auto-negotiation.");
	hme_start_timer(hmep, hme_try_speed, HME_TICKS);
	return (hmep->hme_autoneg = HME_HWAN_TRY);
}

/*
 * This function is used to perform automatic speed detection.
 * The Internal Transceiver which is based on the National PHY chip
 * 83840 supports auto-negotiation functionality.
 * Some External transceivers may not support auto-negotiation.
 * In that case, the software performs the speed detection.
 * The software tries to bring down the link for about 2 seconds to
 * force the Link Partner to notice speed change.
 * The software speed detection favors the 100 Mbps speed.
 * It does this by setting the 100 Mbps for longer duration ( 5 seconds )
 * than the 10 Mbps ( 2 seconds ). Also, even after the link is up
 * in 10 Mbps once, the 100 Mbps is also tried. Only if the link
 * is not up in 100 Mbps, the 10 Mbps speed is tried again.
 */
static void
hme_try_speed(void *arg)
{
	struct hme	*hmep = arg;
	int		linkup;
	uint_t		temp;

	hme_stop_timer(hmep);
	temp = hmep->hme_transceiver; /* save the transceiver type */
	hme_check_transceiver(hmep);
	if (temp != hmep->hme_transceiver) {
		if (hmep->hme_transceiver == HME_EXTERNAL_TRANSCEIVER) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, XCVR_MSG,
					ext_xcvr_msg);
		} else {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, XCVR_MSG,
					int_xcvr_msg);
		}
		hme_start_timer(hmep, hme_check_link, 10 * HME_TICKS);
		return;
	}

	if ((hmep->hme_transceiver == HME_INTERNAL_TRANSCEIVER) &&
					(hmep->hme_link_pulse_disabled)) {
		hmep->hme_tryspeed = HME_SPEED_10;
		hme_disable_link_pulse(hmep);
		return;
	}

	if (hme_autoneg_enable && (hmep->hme_autoneg != HME_HWAN_FAILED)) {
		if (hme_try_auto_negotiation(hmep) != HME_HWAN_FAILED)
			return;	/* auto negotiation successful or being tried */
	}

	linkup = hme_select_speed(hmep, hmep->hme_tryspeed);
	if (hmep->hme_linkup_cnt == 1) {
		hme_start_timer(hmep, hme_try_speed, SECOND(1));
		return;
	}
	if (linkup) {
		switch (hmep->hme_tryspeed) {
		case HME_SPEED_100:
			if (hmep->hme_linkup_cnt == 4) {
				hmep->hme_ntries =	HME_NTRIES_LOW;
				hmep->hme_nlasttries =	HME_NTRIES_LOW;
				hmep->hme_linkup = 1;
				hmep->hme_linkcheck = 1;
				hme_link_now_up(hmep);
				hme_display_transceiver(hmep);
				hme_display_linkup(hmep, HME_SPEED_100);
				hme_setup_link_status(hmep);
				hme_start_mifpoll(hmep);
				hme_start_timer(hmep, hme_check_link,
							HME_LINKCHECK_TIMER);
				if (hmep->hme_fdx != hmep->hme_macfdx)
					(void) hmeinit(hmep);
			} else
				hme_start_timer(hmep, hme_try_speed, HME_TICKS);
			break;
		case HME_SPEED_10:
			if (hmep->hme_linkup_cnt == 4) {
				if (hmep->hme_linkup_10) {
					hmep->hme_linkup_10 = 0;
					hmep->hme_ntries = HME_NTRIES_LOW;
					hmep->hme_nlasttries = HME_NTRIES_LOW;
					hmep->hme_linkup = 1;
					hmep->hme_linkcheck = 1;
					hmep->hme_ifspeed = HME_SPEED_10;
					hme_display_transceiver(hmep);
					hme_display_linkup(hmep, HME_SPEED_10);
					hme_setup_link_status(hmep);
					hme_start_mifpoll(hmep);
					hme_start_timer(hmep, hme_check_link,
							HME_LINKCHECK_TIMER);
					if (hmep->hme_fdx != hmep->hme_macfdx)
						(void) hmeinit(hmep);
				} else {
					hmep->hme_linkup_10 = 1;
					hmep->hme_tryspeed = HME_SPEED_100;
					hmep->hme_force_linkdown =
							HME_FORCE_LINKDOWN;
					hmep->hme_linkup_cnt = 0;
					hmep->hme_ntries = HME_NTRIES_LOW;
					hmep->hme_nlasttries = HME_NTRIES_LOW;
					hme_start_timer(hmep,
						hme_try_speed, HME_TICKS);
				}

			} else
				hme_start_timer(hmep, hme_try_speed, HME_TICKS);
			break;
		default:
			HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, XCVR_MSG,
					"Default: Try speed");
			break;
		}
		return;
	}

	hmep->hme_ntries--;
	hmep->hme_linkup_cnt = 0;
	if (hmep->hme_ntries == 0) {
		hmep->hme_force_linkdown = HME_FORCE_LINKDOWN;
		switch (hmep->hme_tryspeed) {
		case HME_SPEED_100:
			hmep->hme_tryspeed = HME_SPEED_10;
			hmep->hme_ntries = HME_NTRIES_LOW_10;
			break;
		case HME_SPEED_10:
			hmep->hme_ntries = HME_NTRIES_LOW;
			hmep->hme_tryspeed = HME_SPEED_100;
			break;
		default:
			HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, XCVR_MSG,
					"Default: Try speed");
			break;
		}
	}
	hme_start_timer(hmep, hme_try_speed, HME_TICKS);
}

static void
hme_link_now_up(struct hme *hmep)
{
	uint16_t	btxpc;
	/*
	 * Work-around for the scramble problem with QSI
	 * chip and Synoptics 28115 switch.
	 * Addition Interface Technologies Group (NPG) 8/28/1997.
	 */
	if ((HME_QS6612) &&
		((hmep->hme_tryspeed  == HME_SPEED_100) ||
		(hmep->hme_forcespeed == HME_SPEED_100))) {
		/*
		 * Addition of a check for 'hmep->hme_forcespeed'
		 * This is necessary when the autonegotiation is
		 * disabled by the 'hme.conf' file. In this case
		 * hmep->hme_tryspeed is not initialized. Resulting
		 * in the workaround not being applied.
		 */
		if (hme_mii_read(hmep, HME_PHY_BTXPC, &btxpc) == 0) {
			hme_mii_write(hmep, HME_PHY_BTXPC,
				(btxpc | PHY_BTXPC_DSCRAM));
			drv_usecwait(20);
			hme_mii_write(hmep, HME_PHY_BTXPC, btxpc);
		}
	}
}
/* <<<<<<<<<<<<<<<<<<<<<<<<<<<  LOADABLE ENTRIES  >>>>>>>>>>>>>>>>>>>>>>> */

int
_init(void)
{
	int	status;

	mutex_init(&hmeautolock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&hmelock, NULL, MUTEX_DRIVER, NULL);

	status = mod_install(&modlinkage);
	if (status != 0) {
		mutex_destroy(&hmelock);
		mutex_destroy(&hmeautolock);
	}
	return (status);
}

int
_fini(void)
{
	int	status;

	status = mod_remove(&modlinkage);
	if (status != 0)
		return (status);

	if (init_once) {
		mutex_destroy(&hmewenlock);
		rw_destroy(&hmestruplock);
	}
	mutex_destroy(&hmelock);
	mutex_destroy(&hmeautolock);
	return (status);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



#define	HMERINDEX(i)		(i % HMERPENDING)

#define	DONT_FLUSH		-1

/*
 * Allocate and zero-out "number" structures
 * each of type "structure" in kernel memory.
 */
#define	GETSTRUCT(structure, number)   \
	((structure *)kmem_zalloc(\
		(size_t)(sizeof (structure) * (number)), KM_SLEEP))

/*
 * Translate a kernel virtual address to i/o address.
 */

#define	HMEIOPBIOADDR(hmep, a) \
	((uint32_t)((hmep)->hme_iopbiobase + \
		((uintptr_t)(a) - (hmep)->hme_iopbkbase)))

/*
 * ddi_dma_sync() a TMD or RMD descriptor.
 */
#define	HMESYNCIOPB(hmep, a, size, who) \
	(void) ddi_dma_sync((hmep)->hme_md_h, \
		(off_t)((ulong_t)(a) - (hmep)->hme_iopbkbase), \
		(size_t)(size), \
		(who))

#define	CHECK_IOPB() \
	hme_check_dma_handle(__FILE__, __LINE__, hmep, hmep->hme_md_h)
#define	CHECK_DMA(handle) \
	hme_check_dma_handle(__FILE__, __LINE__, hmep, (handle))

#define	HMESAPMATCH(sap, type, flags) ((sap == type) ? 1 : \
	((flags & HMESALLSAP) ? 1 : \
	((sap <= ETHERMTU) && (sap >= (t_uscalar_t)0) && \
	(type <= ETHERMTU)) ? 1 : 0))

/*
 * Ethernet broadcast address definition.
 */
static	struct ether_addr	etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * MIB II broadcast/multicast packets
 */
#define	IS_BROADCAST(ehp) \
		(ether_cmp(&ehp->ether_dhost, &etherbroadcastaddr) == 0)
#define	IS_MULTICAST(ehp) \
		((ehp->ether_dhost.ether_addr_octet[0] & 01) == 1)
#define	BUMP_InNUcast(hmep, ehp) \
		if (IS_BROADCAST(ehp)) { \
			hmep->hme_brdcstrcv++; \
		} else if (IS_MULTICAST(ehp)) { \
			hmep->hme_multircv++; \
		}
#define	BUMP_OutNUcast(hmep, ehp) \
		if (IS_BROADCAST(ehp)) { \
			hmep->hme_brdcstxmt++; \
		} else if (IS_MULTICAST(ehp)) { \
			hmep->hme_multixmt++; \
		}

/*
 * Linked list of hme structures - one per card.
 */
static struct hme *hmeup = NULL;

/*
 * force the fallback to ddi_dma routines
 */

/*
 * Our DL_INFO_ACK template.
 */
static	dl_info_ack_t hmeinfoack = {
	DL_INFO_ACK,				/* dl_primitive */
	ETHERMTU,				/* dl_max_sdu */
	0,					/* dl_min_sdu */
	HMEADDRL,				/* dl_addr_length */
	DL_ETHER,				/* dl_mac_type */
	0,					/* dl_reserved */
	0,					/* dl_current_state */
	-2,					/* dl_sap_length */
	DL_CLDLS,				/* dl_service_mode */
	0,					/* dl_qos_length */
	0,					/* dl_qos_offset */
	0,					/* dl_range_length */
	0,					/* dl_range_offset */
	DL_STYLE2,				/* dl_provider_style */
	sizeof (dl_info_ack_t),			/* dl_addr_offset */
	DL_VERSION_2,				/* dl_version */
	ETHERADDRL,				/* dl_brdcst_addr_length */
	sizeof (dl_info_ack_t) + HMEADDRL,	/* dl_brdcst_addr_offset */
	0					/* dl_growth */
};

static int
hme_create_prop_from_kw(dev_info_t *dip, char *vpdname, char *vpdstr)
{
	char propstr[80];
	int i, needprop = 0;
	struct ether_addr local_mac;

#ifdef HME_DEBUG
	struct hme *hmep;
	hmep = ddi_get_driver_private(dip);
#endif

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
				HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN,
				AUTOCONFIG_MSG, "hme_create_newvpd_props: \
				ddi_prop_create error");
				return (DDI_FAILURE);
			}
		} else {
			if (ddi_prop_create(DDI_DEV_T_NONE, dip,
				DDI_PROP_CANSLEEP, propstr,
				vpdstr, strlen(vpdstr)+1) != DDI_SUCCESS) {
				HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN,
				AUTOCONFIG_MSG, "hme_create_newvpd_props: \
				ddi_prop_create error");
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
			HME_DEBUG_MSG2(hmep, SEVERITY_NONE, CONFIG_MSG,
				"cannot create_prop_from_kw %s", kw_namestr);
			return (DDI_FAILURE);
		}
		kw_ptr += kw_len;
	} /* next keyword */

	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	"model", "SUNW,cheerio", strlen("SUNW,cheerio")+1) != DDI_SUCCESS) {
		HME_DEBUG_MSG1(hmep, SEVERITY_NONE, AUTOCONFIG_MSG,
			"hme_get_oldvpd model: ddi_prop_create error");
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
			kw_len = (int)(GET_ROM8(&hmep->hme_romp[kw_ptr+2]) &
			0xff);
			for (i = 0, kw_ptr += 3; i < kw_len; i++)
				kw_fieldstr[i] = GET_ROM8
					(&hmep->hme_romp[kw_ptr+i]);
			kw_fieldstr[i] = '\0';
			if (hme_create_prop_from_kw(dip, kw_namestr,
				kw_fieldstr)) {
				HME_DEBUG_MSG2(hmep, SEVERITY_NONE, CONFIG_MSG,
				"cannot create_prop_from_kw %s", kw_namestr);
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
		if ((GET_ROM8(&(hmep->hme_romp[i]))
			& 0xff) == 0x50)	/* 'P' */
		if ((GET_ROM8(&(hmep->hme_romp[i+1]))
			& 0xff) == 0x43)	/* 'C' */
		if ((GET_ROM8(&(hmep->hme_romp[i+2]))
			& 0xff) == 0x49)	/* 'I' */
		if ((GET_ROM8(&(hmep->hme_romp[i+3]))
			& 0xff) == 0x52) {	/* 'R' */
		vpd_base = (int)((GET_ROM8(&(hmep->hme_romp[i+8]))
			& 0xff) |
				(GET_ROM8(&(hmep->hme_romp[i+9]))
			& 0xff) << 8);
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
		if (hme_get_oldvpd_props(dip, vpd_base))
			return (1);
		return (0);
	} else
		return (1);	/* unknown start byte in VPD */
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
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, AUTOCONFIG_MSG,
			"ddi_map_regs for config space failed");
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


	if (ddi_regs_map_setup(dip, 2, (caddr_t *)&(hmep->hme_romp), 0, 0,
				&hmep->hme_dev_attr, &hmep->hme_romh)) {
		HME_DEBUG_MSG1(hmep, SEVERITY_NONE, AUTOCONFIG_MSG,
			"reg mapping failed: Check reg property ");
		if (cfg_ptr)
			ddi_regs_map_free(&cfg_handle);
		return (DDI_FAILURE);
	} else {
		if (hme_get_vpd_props(dip))
			return (1);
	}
	if (hmep->hme_romp)
		ddi_regs_map_free(&hmep->hme_romh);
	if (cfg_ptr)
		ddi_regs_map_free(&cfg_handle);
	return (0);	/* SUCCESS */

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
		hmep->hme_mifpoll_enable = 1;
		hmep->hme_frame_enable = 1;
		break;

	case HME_2P0_REVID:
		HME_FAULT_MSG2(hmep, SEVERITY_NONE, DISPLAY_MSG,
				"SBus 2.0 Found (Rev Id = %x)", hm_rev);
		break;

	case HME_1C0_REVID:
		HME_FAULT_MSG2(hmep, SEVERITY_NONE, DISPLAY_MSG,
				"PCI IO 1.0 Found (Rev Id = %x)",
				hm_rev);
		break;

	default:
		HME_FAULT_MSG3(hmep, SEVERITY_HIGH, DISPLAY_MSG,
				"%s (Rev Id = %x) Found",
				(hm_rev == HME_2C0_REVID) ?
						"PCI IO 2.0" :
						"Sbus",
				hm_rev);
		hmep->hme_mifpoll_enable = 1;
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
static int
hmeattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct hme *hmep;
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


	HME_DEBUG_MSG1(NULL, SEVERITY_NONE, ENTER_MSG,
			"hmeattach:  Entered");

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		if ((hmep = ddi_get_driver_private(dip)) == NULL)
		    return (DDI_FAILURE);

		hmep->hme_flags &= ~HMESUSPENDED;
		hmep->hme_linkcheck = 0;
		{
			struct hmestr	*sqp;
			int		dohmeinit = 0;
			rw_enter(&hmestruplock, RW_READER);
			/* Do hmeinit() only for active interface */
			for (sqp = hmestrup; sqp; sqp = sqp->sb_nextp) {
				if (sqp->sb_hmep == hmep) {
					dohmeinit = 1;
					break;
				}
			}
			rw_exit(&hmestruplock);
			if (dohmeinit)
				(void) hmeinit(hmep);
		}
		return (DDI_SUCCESS);

	default:
		HME_DEBUG_MSG1(NULL, SEVERITY_HIGH, INIT_MSG,
				attach_bad_cmd_msg);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate soft device data structure
	 */
	hmep = GETSTRUCT(struct hme, 1);

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
				slave_slot_msg);
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
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG, bad_num_regs_msg);
		goto error_state;
	}

	/* Initialize device attributes structure */
	hmep->hme_dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;

	if (hmep->hme_cheerio_mode)
	    hmep->hme_dev_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	else
	    hmep->hme_dev_attr.devacc_attr_endian_flags = DDI_STRUCTURE_BE_ACC;

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

	hmep->hme_etxregp =  (void *)(((caddr_t)hmep->hme_globregp) + 0x2000);
	hmep->hme_erxregp =  (void *)(((caddr_t)hmep->hme_globregp) + 0x4000);
	hmep->hme_bmacregp = (void *)(((caddr_t)hmep->hme_globregp) + 0x6000);
	hmep->hme_mifregp =  (void *)(((caddr_t)hmep->hme_globregp) + 0x7000);

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
	hmep->hme_mifpoll_enable = 0;
	hmep->hme_frame_enable = 0;
	hmep->hme_lance_mode_enable = 0;
	hmep->hme_rxcv_enable = 0;

	/* NEW routine to get the properties */

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, hmep->dip, 0, "hm-rev",
				(caddr_t)&hm_rev, &prop_len)
				== DDI_PROP_SUCCESS) {

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
			HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, AUTOCONFIG_MSG,
			"hmeattach: ddi_map_regs for config space failed");
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
				"hmeattach: ddi_prop_create error for hm_rev");
		}
		ddi_regs_map_free(&cfg_handle);

		hmeget_hm_rev_property(hmep);

		/* get info via VPD */
		if (hmeget_promprops(dip)) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, AUTOCONFIG_MSG,
			"hmeattach: no promprops");
		}
	}

	if (!hme_mifpoll_enable)
		hmep->hme_mifpoll_enable = 0;

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
	mutex_init(&hmep->hme_xmitlock, NULL, MUTEX_DRIVER,
		(void *)hmep->hme_cookie);
	mutex_init(&hmep->hme_intrlock, NULL, MUTEX_DRIVER,
		(void *)hmep->hme_cookie);
	mutex_init(&hmep->hme_linklock, NULL, MUTEX_DRIVER,
		(void *)hmep->hme_cookie);

	mutex_enter(&hmeautolock);
	if (!init_once) {
		init_once = 1;
		rw_init(&hmestruplock, NULL, RW_DRIVER,
		    (void *)hmep->hme_cookie);
		mutex_init(&hmewenlock, NULL, MUTEX_DRIVER,
		    (void *)hmep->hme_cookie);
	}
	mutex_exit(&hmeautolock);

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

	/*
	 * Create the filesystem device node.
	 */
	if (ddi_create_minor_node(dip, "hme", S_IFCHR,
		hmep->instance, DDI_NT_NET, CLONE_DEV) == DDI_FAILURE) {
		HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, CONFIG_MSG,
				create_minor_node_fail_msg);
		goto error_intr;
	}

	if (!hmeinit_xfer_params(hmep))
		goto error_minor;

	if (hmeburstsizes(hmep) == DDI_FAILURE) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG, burst_size_msg);
		goto error_minor;
	}


	/* lock hme structure while manipulating link list of hme structs */
	mutex_enter(&hmelock);
	hmep->hme_nextp = hmeup;
	hmeup = hmep;
	mutex_exit(&hmelock);

	hmestatinit(hmep);
	ddi_report_dev(dip);
	return (DDI_SUCCESS);

	/*
	 * Failure Exit
	 */
error_minor:
	ddi_remove_minor_node(dip, NULL);

error_intr:
	if (hmep->hme_cookie)
		ddi_remove_intr(dip, 0, (ddi_iblock_cookie_t)0);

error_mutex:
	/*
	 * hmewenlock and hmestruplock are destroy-ed in _fini()
	 */
	mutex_destroy(&hmep->hme_xmitlock);
	mutex_destroy(&hmep->hme_intrlock);
	mutex_destroy(&hmep->hme_linklock);

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
	if (hmep) {
		kmem_free((caddr_t)hmep, sizeof (*hmep));
		ddi_set_driver_private(dip, NULL);
	}

	HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, EXIT_MSG,
			"hmeattach:  Unsuccessful Exiting");
	return (DDI_FAILURE);
}

static int
hmedetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct hme *hmep, *hmetmp, **prevhmep;
	int32_t	unval;

	if ((hmep = ddi_get_driver_private(dip)) == NULL)
		/*
		 * No resources allocated
		 */
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		hmep->hme_flags |= HMESUSPENDED;
		hmeuninit(hmep);
		return (DDI_SUCCESS);

	default:
		HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, UNINIT_MSG,
				detach_bad_cmd_msg);
		return (DDI_FAILURE);
	}

	/*
	 * Bug ID 4013267
	 * This bug manifests  by allowing the driver to allow detach
	 * while the driver is busy and subsequent packets cause
	 * the driver to panic.
	 */
	if (hmep->hme_flags & (HMERUNNING | HMESUSPENDED)) {
		HME_FAULT_MSG1(hmep, SEVERITY_LOW, CONFIG_MSG, busy_msg);
		return (DDI_FAILURE);
	}

	/*
	 * Make driver quiescent, we don't want to prevent the
	 * detach on failure.
	 */
	(void) hmestop(hmep);

	ddi_remove_minor_node(dip, NULL);

	/*
	 * Remove instance of the intr
	 */
	ddi_remove_intr(dip, 0, (ddi_iblock_cookie_t)0);

	/*
	 * Destroy all mutexes and data structures allocated during
	 * attach time.
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

	/*
	 * Remove hmep from the link list of device structures
	 */
	mutex_enter(&hmelock);
	for (prevhmep = &hmeup; (hmetmp = *prevhmep) != NULL;
		prevhmep = &hmetmp->hme_nextp)
		if (hmetmp == hmep) {
			if (hmetmp->hme_ksp)
				kstat_delete(hmetmp->hme_ksp);
			if (hmetmp->hme_intrstats)
				kstat_delete(hmetmp->hme_intrstats);

			hmetmp->hme_intrstats = NULL;
			*prevhmep = hmetmp->hme_nextp;
			hme_stop_timer(hmetmp);
			mutex_exit(&hmep->hme_linklock);
			mutex_destroy(&hmetmp->hme_xmitlock);
			mutex_destroy(&hmetmp->hme_intrlock);
			mutex_destroy(&hmetmp->hme_linklock);

			if (hmetmp->hme_md_h) {
				unval = ddi_dma_unbind_handle(hmetmp->hme_md_h);
				if (unval == DDI_FAILURE)
					HME_FAULT_MSG1(hmep, SEVERITY_HIGH,
							DDI_MSG,
					"dma_unbind_handle failed");
				ddi_dma_mem_free(&hmetmp->hme_mdm_h);
				ddi_dma_free_handle(&hmetmp->hme_md_h);
			}

			hmefreebufs(hmetmp);

			/*
			 * dvma handle case.
			 */
			if (hmetmp->hme_dvmarh) {
				(void) dvma_release(hmetmp->hme_dvmarh);
				(void) dvma_release(hmetmp->hme_dvmaxh);
				hmetmp->hme_dvmarh = hmetmp->hme_dvmaxh = NULL;
			}

			/*
			 * dma handle case.
			 */
			if (hmetmp->hme_dmarh) {
				kmem_free((caddr_t)hmetmp->hme_dmaxh,
				    (HME_TMDMAX + HMERPENDING) *
				    (sizeof (ddi_dma_handle_t)));
				hmetmp->hme_dmarh = hmetmp->hme_dmaxh = NULL;
			}

			/*
			 * Generated when there was only dma.
			 * else HME_FAULT_MSG1(NULL, SEVERITY_HIGH,
			 *			"expected dmarh");
			 */


			/*
			 * Reset hme_device to default value(-1) when ndd is
			 * referencing the instance being detached.
			 */
			if (hme_device == hmep->instance)
				hme_device = -1;

			hme_param_cleanup(hmetmp);

			ddi_set_driver_private(dip, NULL);
			kmem_free((caddr_t)hmetmp, sizeof (struct hme));
			break;
		}
	mutex_exit(&hmelock);
	return (DDI_SUCCESS);
}

static int
hmeinit_xfer_params(struct hme *hmep)
{
	int i;
	int hme_ipg1_conf, hme_ipg2_conf;
	int hme_use_int_xcvr_conf, hme_pace_count_conf;
	int hme_autoneg_conf;
	int hme_anar_100T4_conf;
	int hme_anar_100fdx_conf, hme_anar_100hdx_conf;
	int hme_anar_10fdx_conf, hme_anar_10hdx_conf;
	int hme_ipg0_conf, hme_lance_mode_conf;
	int prop_len = sizeof (int);
	dev_info_t *dip;

	dip = hmep->dip;

	HME_DEBUG_MSG1(hmep, SEVERITY_NONE, AUTOCONFIG_MSG,
			"==> hmeinit_xfer_params");

	for (i = 0; i < A_CNT(hme_param_arr); i++)
		hmep->hme_param_arr[i] = hme_param_arr[i];

	if (!hmep->hme_g_nd && !hme_param_register(hmep, hmep->hme_param_arr,
		A_CNT(hme_param_arr))) {
		HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, NDD_MSG,
				param_reg_fail_msg);
		return (B_FALSE);
	}

	hme_param_device = hmep->instance;

	/*
	 * Set up the start-up values for user-configurable parameters
	 * Get the values from the global variables first.
	 * Use the MASK to limit the value to allowed maximum.
	 */
	hme_param_ipg1 = hme_ipg1 & HME_MASK_8BIT;
	hme_param_ipg2 = hme_ipg2 & HME_MASK_8BIT;
	hme_param_use_intphy = hme_use_int_xcvr & HME_MASK_1BIT;
	hme_param_pace_count = hme_pace_size & HME_MASK_8BIT;
	hme_param_autoneg = hme_adv_autoneg_cap;
	hme_param_anar_100T4 = hme_adv_100T4_cap;
	hme_param_anar_100fdx = hme_adv_100fdx_cap;
	hme_param_anar_100hdx = hme_adv_100hdx_cap;
	hme_param_anar_10fdx = hme_adv_10fdx_cap;
	hme_param_anar_10hdx = hme_adv_10hdx_cap;
	hme_param_ipg0 = hme_ipg0 & HME_MASK_5BIT;
	hme_param_lance_mode = hme_lance_mode & HME_MASK_1BIT;

	/*
	 * The link speed may be forced to either 10 Mbps or 100 Mbps using the
	 * property "transfer-speed". This may be done in OBP by using the
	 * command "apply transfer-speed=<speed> <device>". The speed may be
	 * either 10 or 100.
	 */
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0,
			"transfer-speed", (caddr_t)&i, &prop_len)
				== DDI_PROP_SUCCESS) {
		HME_DEBUG_MSG2(hmep, SEVERITY_LOW, PROP_MSG,
				"params:  transfer-speed property = %X", i);
		hme_param_autoneg = 0;	/* force speed */
		hme_param_anar_100T4 = 0;
		hme_param_anar_100fdx = 0;
		hme_param_anar_10fdx = 0;
		if (i == 10) {
			hme_param_anar_10hdx = 1;
			hme_param_anar_100hdx = 0;
		} else {
			hme_param_anar_10hdx = 0;
			hme_param_anar_100hdx = 1;
		}
	}

	/*
	 * Get the parameter values configured in .conf file.
	 */
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "ipg1",
				(caddr_t)&hme_ipg1_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		HME_DEBUG_MSG2(hmep, SEVERITY_LOW, PROP_MSG,
			"params: hme_ipg1 property = %X", hme_ipg1_conf);
		hme_param_ipg1 = hme_ipg1_conf & HME_MASK_8BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "ipg2",
				(caddr_t)&hme_ipg2_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_ipg2 = hme_ipg2_conf & HME_MASK_8BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "use_int_xcvr",
				(caddr_t)&hme_use_int_xcvr_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_use_intphy = hme_use_int_xcvr_conf & HME_MASK_1BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "pace_size",
				(caddr_t)&hme_pace_count_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_pace_count = hme_pace_count_conf & HME_MASK_8BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_autoneg_cap",
				(caddr_t)&hme_autoneg_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_autoneg = hme_autoneg_conf & HME_MASK_1BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_100T4_cap",
				(caddr_t)&hme_anar_100T4_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_anar_100T4 = hme_anar_100T4_conf & HME_MASK_1BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_100fdx_cap",
				(caddr_t)&hme_anar_100fdx_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_anar_100fdx = hme_anar_100fdx_conf & HME_MASK_1BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_100hdx_cap",
				(caddr_t)&hme_anar_100hdx_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_anar_100hdx = hme_anar_100hdx_conf & HME_MASK_1BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_10fdx_cap",
				(caddr_t)&hme_anar_10fdx_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_anar_10fdx = hme_anar_10fdx_conf & HME_MASK_1BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "adv_10hdx_cap",
				(caddr_t)&hme_anar_10hdx_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_anar_10hdx = hme_anar_10hdx_conf & HME_MASK_1BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "ipg0",
				(caddr_t)&hme_ipg0_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_ipg0 = hme_ipg0_conf & HME_MASK_5BIT;
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "lance_mode",
				(caddr_t)&hme_lance_mode_conf, &prop_len)
				== DDI_PROP_SUCCESS) {
		hme_param_lance_mode = hme_lance_mode_conf & HME_MASK_1BIT;
	}

	if (hme_link_pulse_disabled)
		hmep->hme_link_pulse_disabled = 1;
	else if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0,
			"link-pulse-disabled", (caddr_t)&i, &prop_len)
				== DDI_PROP_SUCCESS) {
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, PROP_MSG,
				"params:  link-pulse-disable property found.");
		hmep->hme_link_pulse_disabled = 1;
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
		HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, UNINIT_MSG,
				"cannot stop hme - failed to access device");
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

	/*
	 * Update all the stats by reading all the counter registers.
	 * Counter register stats are not updated till they overflow
	 * and interrupt.
	 */

	mutex_enter(&hmep->hme_xmitlock);
	if (hmep->hme_flags & HMERUNNING)
		hmereclaim(hmep);
	mutex_exit(&hmep->hme_xmitlock);

	hmesavecntrs(hmep);

	if (rw == KSTAT_WRITE) {
		hmep->hme_ipackets	= hkp->hk_ipackets.value.ul;
		hmep->hme_ierrors	= hkp->hk_ierrors.value.ul;
		hmep->hme_opackets	= hkp->hk_opackets.value.ul;
		hmep->hme_oerrors	= hkp->hk_oerrors.value.ul;
		hmep->hme_coll		= hkp->hk_coll.value.ul;

		/*
		 * MIB II kstat variables
		 */
		hmep->hme_rcvbytes	= hkp->hk_rcvbytes.value.ul;
		hmep->hme_xmtbytes	= hkp->hk_xmtbytes.value.ul;
		hmep->hme_multircv	= hkp->hk_multircv.value.ul;
		hmep->hme_multixmt	= hkp->hk_multixmt.value.ul;
		hmep->hme_brdcstrcv	= hkp->hk_brdcstrcv.value.ul;
		hmep->hme_brdcstxmt	= hkp->hk_brdcstxmt.value.ul;
		hmep->hme_norcvbuf	= hkp->hk_norcvbuf.value.ul;
		hmep->hme_noxmtbuf	= hkp->hk_noxmtbuf.value.ul;

#ifdef	kstat
		hmep->hme_defer		= hkp->hk_defer.value.ul;
		hmep->hme_fram		= hkp->hk_fram.value.ul;
		hmep->hme_crc		= hkp->hk_crc.value.ul;
		hmep->hme_sqerr		= hkp->hk_sqerr.value.ul;
		hmep->hme_cvc		= hkp->hk_cvc.value.ul;
		hmep->hme_lenerr	= hkp->hk_lenerr.value.ul;
		hmep->hme_buff		= hkp->hk_buff.value.ul;
		hmep->hme_oflo		= hkp->hk_oflo.value.ul;
		hmep->hme_uflo		= hkp->hk_uflo.value.ul;
		hmep->hme_missed	= hkp->hk_missed.value.ul;
		hmep->hme_tlcol		= hkp->hk_tlcol.value.ul;
		hmep->hme_trtry		= hkp->hk_trtry.value.ul;
		hmep->hme_fstcol	= hkp->hk_fstcol.value.ul;
		hmep->hme_nocanput	= hkp->hk_nocanput.value.ul;
		hmep->hme_allocbfail	= hkp->hk_allocbfail.value.ul;
		hmep->hme_runt		= hkp->hk_runt.value.ul;
		hmep->hme_jab		= hkp->hk_jab.value.ul;
		hmep->hme_babl		= hkp->hk_babl.value.ul;
		hmep->hme_tmder 	= hkp->hk_tmder.value.ul;
		hmep->hme_txlaterr	= hkp->hk_txlaterr.value.ul;
		hmep->hme_rxlaterr	= hkp->hk_rxlaterr.value.ul;
		hmep->hme_slvparerr	= hkp->hk_slvparerr.value.ul;
		hmep->hme_txparerr	= hkp->hk_txparerr.value.ul;
		hmep->hme_rxparerr	= hkp->hk_rxparerr.value.ul;
		hmep->hme_slverrack	= hkp->hk_slverrack.value.ul;
		hmep->hme_txerrack	= hkp->hk_txerrack.value.ul;
		hmep->hme_rxerrack	= hkp->hk_rxerrack.value.ul;
		hmep->hme_txtagerr	= hkp->hk_txtagerr.value.ul;
		hmep->hme_rxtagerr	= hkp->hk_rxtagerr.value.ul;
		hmep->hme_eoperr	= hkp->hk_eoperr.value.ul;
		hmep->hme_notmds	= hkp->hk_notmds.value.ul;
		hmep->hme_notbufs	= hkp->hk_notbufs.value.ul;
		hmep->hme_norbufs	= hkp->hk_norbufs.value.ul;
		hmep->hme_clsn		= hkp->hk_clsn.value.ul;
#endif	/* kstat */
		hmep->hme_newfree	= hkp->hk_newfree.value.ul;

		/*
		 * PSARC 1997/198 : 64 bit kstats
		 */
		hmep->hme_ipackets64	= hkp->hk_ipackets64.value.ull;
		hmep->hme_opackets64	= hkp->hk_opackets64.value.ull;
		hmep->hme_rbytes64	= hkp->hk_rbytes64.value.ull;
		hmep->hme_obytes64	= hkp->hk_obytes64.value.ull;

		/*
		 * PSARC 1997/247 : RFC 1643
		 */
		hmep->hme_align_errors	= hkp->hk_align_errors.value.ul;
		hmep->hme_fcs_errors	= hkp->hk_fcs_errors.value.ul;
		/* first collisions */
		hmep->hme_multi_collisions = hkp->hk_multi_collisions.value.ul;
		hmep->hme_sqe_errors	= hkp->hk_sqe_errors.value.ul;
		hmep->hme_defer_xmts	= hkp->hk_defer_xmts.value.ul;
		/* tx_late_collisions */
		hmep->hme_ex_collisions	= hkp->hk_ex_collisions.value.ul;
		hmep->hme_macxmt_errors	= hkp->hk_macxmt_errors.value.ul;
		hmep->hme_carrier_errors = hkp->hk_carrier_errors.value.ul;
		hmep->hme_toolong_errors = hkp->hk_toolong_errors.value.ul;
		hmep->hme_macrcv_errors	= hkp->hk_macrcv_errors.value.ul;

		/*
		 * RFE's (Request for Enhancement)
		 */
		hmep->link_duplex	= hkp->hk_link_duplex.value.ul;

		/*
		 * Debug Kstats
		 */
		hmep->inits		= hkp->hk_inits.value.ul;
		hmep->rxinits		= hkp->hk_rxinits.value.ul;
		hmep->txinits		= hkp->hk_txinits.value.ul;
		hmep->dmarh_init	= hkp->hk_dmarh_inits.value.ul;
		hmep->dmaxh_init	= hkp->hk_dmaxh_inits.value.ul;
		hmep->link_down_cnt	= hkp->hk_link_down_cnt.value.ul;
		hmep->phyfail		= hkp->hk_phyfail.value.ul;

		/*
		 * I/O bus kstats
		 * hmep->hme_pci_speed	= hkp->hk_pci_peed.value.ul;
		 */

		/*
		 * xcvr kstats
		 */
		hmep->xcvr_vendor_id	= hkp->hk_xcvr_vendor_id.value.ul;
		hmep->asic_rev		= hkp->hk_asic_rev.value.ul;

		/*
		 * Link Status
		 */
		hmep->hme_link_up	= hkp->hk_link_up.value.ul;

		return (0);

	} else {
		hkp->hk_ipackets.value.ul	= hmep->hme_ipackets;
		hkp->hk_ierrors.value.ul	= hmep->hme_ierrors;
		hkp->hk_opackets.value.ul	= hmep->hme_opackets;
		hkp->hk_oerrors.value.ul	= hmep->hme_oerrors;
		hkp->hk_coll.value.ul		= hmep->hme_coll;
		hkp->hk_defer.value.ul		= hmep->hme_defer;
		hkp->hk_fram.value.ul		= hmep->hme_fram;
		hkp->hk_crc.value.ul		= hmep->hme_crc;
		hkp->hk_sqerr.value.ul		= hmep->hme_sqerr;
		hkp->hk_cvc.value.ul		= hmep->hme_cvc;
		hkp->hk_lenerr.value.ul		= hmep->hme_lenerr;
		hkp->hk_ifspeed.value.ull	=
					hmep->hme_ifspeed * 1000000ULL;
		hkp->hk_buff.value.ul		= hmep->hme_buff;
		hkp->hk_oflo.value.ul		= hmep->hme_oflo;
		hkp->hk_uflo.value.ul		= hmep->hme_uflo;
		hkp->hk_missed.value.ul		= hmep->hme_missed;
		hkp->hk_tlcol.value.ul		= hmep->hme_tlcol;
		hkp->hk_trtry.value.ul		= hmep->hme_trtry;
		hkp->hk_fstcol.value.ul		= hmep->hme_fstcol;
		hkp->hk_nocanput.value.ul	= hmep->hme_nocanput;
		hkp->hk_allocbfail.value.ul	= hmep->hme_allocbfail;
		hkp->hk_runt.value.ul		= hmep->hme_runt;
		hkp->hk_jab.value.ul		= hmep->hme_jab;
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
		hkp->hk_clsn.value.ul		= hmep->hme_clsn;
		/*
		 * MIB II kstat variables
		 */
		hkp->hk_rcvbytes.value.ul	= hmep->hme_rcvbytes;
		hkp->hk_xmtbytes.value.ul	= hmep->hme_xmtbytes;
		hkp->hk_multircv.value.ul	= hmep->hme_multircv;
		hkp->hk_multixmt.value.ul	= hmep->hme_multixmt;
		hkp->hk_brdcstrcv.value.ul	= hmep->hme_brdcstrcv;
		hkp->hk_brdcstxmt.value.ul	= hmep->hme_brdcstxmt;
		hkp->hk_norcvbuf.value.ul	= hmep->hme_norcvbuf;
		hkp->hk_noxmtbuf.value.ul	= hmep->hme_noxmtbuf;

		hkp->hk_newfree.value.ul	= hmep->hme_newfree;

		/*
		 * PSARC 1997/198
		 */
		hkp->hk_ipackets64.value.ull	= hmep->hme_ipackets64;
		hkp->hk_opackets64.value.ull	= hmep->hme_opackets64;
		hkp->hk_rbytes64.value.ull	= hmep->hme_rbytes64;
		hkp->hk_obytes64.value.ull	= hmep->hme_obytes64;

		/*
		 * PSARC 1997/247 : RFC 1643
		 */
		hkp->hk_align_errors.value.ul = hmep->hme_align_errors;
		hkp->hk_fcs_errors.value.ul	= hmep->hme_fcs_errors;
		/* first_collisions */
		hkp->hk_multi_collisions.value.ul = hmep->hme_multi_collisions;
		hkp->hk_sqe_errors.value.ul	= hmep->hme_sqe_errors;
		hkp->hk_defer_xmts.value.ul	= hmep->hme_defer_xmts;
		/* tx_late_collisions */
		hkp->hk_ex_collisions.value.ul = hmep->hme_ex_collisions;
		hkp->hk_macxmt_errors.value.ul = hmep->hme_macxmt_errors;
		hkp->hk_carrier_errors.value.ul = hmep->hme_carrier_errors;
		hkp->hk_toolong_errors.value.ul = hmep->hme_toolong_errors;
		hkp->hk_macrcv_errors.value.ul = hmep->hme_macrcv_errors;

		/*
		 * RFE's (Request for Enhancements)
		 */
		hkp->hk_link_duplex.value.ul	= hmep->link_duplex;

		/*
		 * Debug kstats
		 */
		hkp->hk_inits.value.ul		= hmep->inits;
		hkp->hk_rxinits.value.ul	= hmep->rxinits;
		hkp->hk_txinits.value.ul	= hmep->txinits;
		hkp->hk_dmarh_inits.value.ul	= hmep->dmarh_init;
		hkp->hk_dmaxh_inits.value.ul	= hmep->dmaxh_init;
		hkp->hk_link_down_cnt.value.ul	= hmep->link_down_cnt;
		hkp->hk_phyfail.value.ul	= hmep->phyfail;

		/*
		 * I/O bus kstats
		 * hkp->hk_pci_speed.value.ul	= hmep->pci_speed;
		 */

		/*
		 * xcvr kstats
		 */
		hkp->hk_xcvr_vendor_id.value.ull = hmep->xcvr_vendor_id;
		hkp->hk_asic_rev.value.ul	= hmep->asic_rev;

		/*
		 * Link Status
		 */
		hkp->hk_link_up.value.ul	= hmep->hme_link_up;

	}
	return (0);
}

static void
hmestatinit(struct hme *hmep)
{
	struct	kstat	*ksp;
	struct	hmekstat	*hkp;
	int	instance;
	char	buf[16];

	instance = hmep->instance;

#ifdef	kstat
	if ((ksp = kstat_create("hme", instance,
		NULL, "net", KSTAT_TYPE_NAMED,
		sizeof (struct hmekstat) / sizeof (kstat_named_t),
		KSTAT_FLAG_PERSISTENT)) == NULL) {
#else
	if ((ksp = kstat_create("hme", instance,
	    NULL, "net", KSTAT_TYPE_NAMED,
	    sizeof (struct hmekstat) / sizeof (kstat_named_t), 0)) == NULL) {
#endif	/* kstat */
		HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, INIT_MSG,
				kstat_create_fail_msg);
		return;
	}

	(void) sprintf(buf, "hmec%d", instance);
	hmep->hme_intrstats = kstat_create("hme", instance, buf, "controller",
		KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT);
	if (hmep->hme_intrstats)
		kstat_install(hmep->hme_intrstats);

	hmep->hme_ksp = ksp;
	hkp = (struct hmekstat *)ksp->ks_data;
	kstat_named_init(&hkp->hk_ipackets,		"ipackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_ierrors,		"ierrors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_opackets,		"opackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_oerrors,		"oerrors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_coll,			"collisions",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_defer,		"defer",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_fram,			"framing",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_crc,			"crc",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_sqerr,		"sqe",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_cvc,			"code_violations",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_lenerr,		"len_errors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_ifspeed,		"ifspeed",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&hkp->hk_buff,			"buff",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_oflo,			"oflo",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_uflo,			"uflo",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_missed,		"missed",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_tlcol,		"tx_late_collisions",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_trtry,		"retry_error",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_fstcol,		"first_collisions",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_nocanput,		"nocanput",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_allocbfail,		"allocbfail",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_runt,			"runt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_jab,			"jabber",
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
	kstat_named_init(&hkp->hk_clsn,			"rx_late_collisions",
		KSTAT_DATA_ULONG);

	/*
	 * MIB II kstat variables
	 */
	kstat_named_init(&hkp->hk_rcvbytes,		"rbytes",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_xmtbytes,		"obytes",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_multircv,		"multircv",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_multixmt,		"multixmt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_brdcstrcv,		"brdcstrcv",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_brdcstxmt,		"brdcstxmt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_norcvbuf,		"norcvbuf",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_noxmtbuf,		"noxmtbuf",
		KSTAT_DATA_ULONG);


	kstat_named_init(&hkp->hk_newfree,		"newfree",
		KSTAT_DATA_ULONG);
	/*
	 * PSARC 1997/198
	 */
	kstat_named_init(&hkp->hk_ipackets64,		"ipackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&hkp->hk_opackets64,		"opackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&hkp->hk_rbytes64,		"rbytes64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&hkp->hk_obytes64,		"obytes64",
		KSTAT_DATA_ULONGLONG);

	/*
	 * PSARC 1997/247 : RFC 1643
	 */
	kstat_named_init(&hkp->hk_align_errors,		"align_errors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_fcs_errors,		"fcs_errors",
		KSTAT_DATA_ULONG);
	/* first_collisions */
	kstat_named_init(&hkp->hk_sqe_errors,		"sqe_errors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_defer_xmts,		"defer_xmts",
		KSTAT_DATA_ULONG);
	/* tx_late_collisions */
	kstat_named_init(&hkp->hk_ex_collisions,	"ex_collisions",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_macxmt_errors,	"macxmt_errors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_carrier_errors,	"carrier_errors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_toolong_errors,	"toolong_errors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_macrcv_errors,	"macrcv_errors",
		KSTAT_DATA_ULONG);

	/*
	 * RFE kstats
	 */
	kstat_named_init(&hkp->hk_link_duplex,		"link_duplex",
		KSTAT_DATA_ULONG);

	/*
	 * Debugging kstats
	 */
	kstat_named_init(&hkp->hk_inits,		"inits",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_rxinits,		"rxinits",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_txinits,		"txinits",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_dmarh_inits,		"dmarh_inits",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_dmaxh_inits,		"dmaxh_inits",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_link_down_cnt,	"link_down_cnt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&hkp->hk_phyfail,		"phy_failures",
		KSTAT_DATA_ULONG);

	/*
	 * I/O bus kstats
	 * kstat_named_init(&hkp->hk_pci_speed,		"pci_bus_speed",
	 *		KSTAT_DATA_ULONG);
	 * kstat_named_init(&hkp->hk_pci_size,		"pci_bus_width",
	 *		KSTAT_DATA_ULONG);
	 */

	/*
	 * xcvr kstats
	 */
	kstat_named_init(&hkp->hk_xcvr_vendor_id,	"xcvr_vendor",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&hkp->hk_asic_rev,		"asic_rev",
		KSTAT_DATA_ULONG);

	/*
	 * Link Status
	 */
	kstat_named_init(&hkp->hk_link_up,		"link_up",
		KSTAT_DATA_ULONG);

	ksp->ks_update = hmestat_kstat_update;
	ksp->ks_private = (void *) hmep;
	kstat_install(ksp);
}

/*
 * Assorted DLPI V2 routines.
 */
/* ARGSUSED */
static int
hmeopen(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	struct	hmestr	*sbp;
	struct	hmestr	**prevsbp;
	minor_t	minordev;

	ASSERT(sflag != MODOPEN);
	if (sflag == MODOPEN)
		return (EINVAL);

	TRACE_1(TR_FAC_BE, TR_BE_OPEN, "hmeopen:  rq %p", rq);

	/*
	 * Serialize all driver open and closes.
	 */
	rw_enter(&hmestruplock, RW_WRITER);
	mutex_enter(&hmewenlock);

	/*
	 * Determine minor device number.
	 */
	prevsbp = &hmestrup;
	if (sflag == CLONEOPEN) {
		minordev = 0;
		for (; (sbp = *prevsbp) != NULL; prevsbp = &sbp->sb_nextp) {
			if (minordev < sbp->sb_minor)
				break;
			minordev++;
		}
		*devp = makedevice(getmajor(*devp), minordev);
	} else
		minordev = getminor(*devp);

	if (rq->q_ptr) {
		goto done;
	}

	sbp = GETSTRUCT(struct hmestr, 1);

	HME_DEBUG_MSG2(NULL, SEVERITY_NONE, INIT_MSG,
			"hmeopen: sbp = %X\n", sbp);

	sbp->sb_minor = minordev;
	sbp->sb_rq = rq;
	sbp->sb_state = DL_UNATTACHED;
	sbp->sb_sap = 0;
	sbp->sb_flags = 0;
	sbp->sb_hmep = NULL;

	mutex_init(&sbp->sb_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Link new entry into the list of active entries.
	 */
	sbp->sb_nextp = *prevsbp;
	*prevsbp = sbp;

	rq->q_ptr = WR(rq)->q_ptr = (char *)sbp;

	/*
	 * Disable automatic enabling of our write service procedure.
	 * We control this explicitly.
	 */
	noenable(WR(rq));
done:
	mutex_exit(&hmewenlock);
	rw_exit(&hmestruplock);

	/* inform framework we are a good citizen */
	(void) qassociate(rq, -1);

	qprocson(rq);
	return (0);
}

static int
hmeclose(queue_t *rq)
{
	struct	hmestr	*sbp;
	struct	hmestr	**prevsbp;

	TRACE_1(TR_FAC_BE, TR_BE_CLOSE, "hmeclose:  rq %p", rq);
	ASSERT(rq->q_ptr);

	qprocsoff(rq);

	sbp = (struct hmestr *)rq->q_ptr;

	/*
	 * Implicit detach Stream from interface.
	 */
	if (sbp->sb_hmep) {
		hmedodetach(sbp);
		(void) qassociate(rq, -1);
	}

	rw_enter(&hmestruplock, RW_WRITER);
	mutex_enter(&hmewenlock);

	/*
	 * Unlink the per-Stream entry from the active list and free it.
	 */
	for (prevsbp = &hmestrup; (sbp = *prevsbp) != NULL;
		prevsbp = &sbp->sb_nextp)
		if (sbp == (struct hmestr *)rq->q_ptr)
			break;
	ASSERT(sbp);
	*prevsbp = sbp->sb_nextp;

	mutex_destroy(&sbp->sb_lock);
	kmem_free((char *)sbp, sizeof (struct hmestr));

	rq->q_ptr = WR(rq)->q_ptr = NULL;

	mutex_exit(&hmewenlock);
	rw_exit(&hmestruplock);
	return (0);
}

static int
hmewput(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp = (struct hmestr *)wq->q_ptr;
	struct	hme	*hmep;

	TRACE_1(TR_FAC_BE, TR_BE_WPUT_START,
		"hmewput start:  wq %p", wq);

	switch (DB_TYPE(mp)) {
	case M_DATA:		/* "fastpath" */
		hmep = sbp->sb_hmep;

		if (((sbp->sb_flags & (HMESFAST|HMESRAW)) == 0) ||
			(sbp->sb_state != DL_IDLE) ||
			(hmep == NULL)) {
			merror(wq, mp, EPROTO);
			break;
		}

		/*
		 * If any msgs already enqueued or the interface will
		 * loop back up the message (due to HMEPROMISC), then
		 * enqueue the msg.  Otherwise just xmit it directly.
		 */
		if (wq->q_first) {
			(void) putq(wq, mp);
			hmep->hme_wantw = 1;
			qenable(wq);
		} else if ((hmep->promisc_phys_cnt + hmep->promisc_multi_cnt)
		    != 0) {
			(void) putq(wq, mp);
			qenable(wq);
		} else
			(void) hmestart(wq, mp, hmep);
		break;

	case M_PROTO:
	case M_PCPROTO:
		/*
		 * Break the association between the current thread and
		 * the thread that calls hmeproto() to resolve the
		 * problem of hmeintr() threads which loop back around
		 * to call hmeproto and try to recursively acquire
		 * internal locks.
		 */
		(void) putq(wq, mp);
		qenable(wq);
		break;

	case M_IOCTL:
		hmeioctl(wq, mp);
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(wq, FLUSHALL);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR)
			qreply(wq, mp);
		else
			freemsg(mp);
		break;

	default:
		HME_DEBUG_MSG1(NULL, SEVERITY_HIGH, TX_MSG,
				"Default in message type");
		freemsg(mp);
		break;
	}
	TRACE_1(TR_FAC_BE, TR_BE_WPUT_END, "hmewput end:  wq %p", wq);
	return (0);
}

/*
 * Enqueue M_PROTO/M_PCPROTO (always) and M_DATA (sometimes) on the wq.
 *
 * Processing of some of the M_PROTO/M_PCPROTO msgs involves acquiring
 * internal locks that are held across upstream putnext calls.
 * Specifically there's the problem of hmeintr() holding hme_intrlock
 * and hmestruplock when it calls putnext() and that thread looping
 * back around to call hmewput and, eventually, hmeinit() to create a
 * recursive lock panic.  There are two obvious ways of solving this
 * problem: (1) have hmeintr() do putq instead of putnext which provides
 * the loopback "cutout" right at the rq, or (2) allow hmeintr() to putnext
 * and put the loopback "cutout" around hmeproto().  We choose the latter
 * for performance reasons.
 *
 * M_DATA messages are enqueued on the wq *only* when the xmit side
 * is out of tbufs or tmds.  Once the xmit resource is available again,
 * wsrv() is enabled and tries to xmit all the messages on the wq.
 */
static int
hmewsrv(queue_t *wq)
{
	mblk_t	*mp;
	struct	hmestr	*sbp;
	struct	hme	*hmep;

	TRACE_1(TR_FAC_BE, TR_BE_WSRV_START, "hmewsrv start:  wq %p", wq);

	sbp = (struct hmestr *)wq->q_ptr;
	hmep = sbp->sb_hmep;

	while (mp = getq(wq))
		switch (DB_TYPE(mp)) {
		case M_DATA:
			if (hmep) {
			    if (hmestart(wq, mp, hmep))
				return (0);
			} else
				freemsg(mp);
			break;

		case M_PROTO:
		case M_PCPROTO:
			hmeproto(wq, mp);
			break;

		default:
			ASSERT(0);
			freemsg(mp);
			break;
		}
	TRACE_1(TR_FAC_BE, TR_BE_WSRV_END, "hmewsrv end:  wq %p", wq);
	return (0);
}

static void
hmeproto(queue_t *wq, mblk_t  *mp)
{
	union	DL_primitives	*dlp;
	struct	hmestr	*sbp;
	t_uscalar_t prim;

	sbp = (struct hmestr *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;
	prim = dlp->dl_primitive;

	TRACE_2(TR_FAC_BE, TR_BE_PROTO_START,
		"hmeproto start:  wq %p dlprim %X", wq, prim);

	mutex_enter(&sbp->sb_lock);

	switch (prim) {
	case DL_UNITDATA_REQ:
		hmeudreq(wq, mp);
		break;

	case DL_ATTACH_REQ:
		hmeareq(wq, mp);
		break;

	case DL_DETACH_REQ:
		hmedreq(wq, mp);
		break;

	case DL_BIND_REQ:
		hmebreq(wq, mp);
		break;

	case DL_UNBIND_REQ:
		hmeubreq(wq, mp);
		break;

	case DL_INFO_REQ:
		hmeireq(wq, mp);
		break;

	case DL_PROMISCON_REQ:
		hmeponreq(wq, mp);
		break;

	case DL_PROMISCOFF_REQ:
		hmepoffreq(wq, mp);
		break;

	case DL_ENABMULTI_REQ:
		hmeemreq(wq, mp);
		break;

	case DL_DISABMULTI_REQ:
		hmedmreq(wq, mp);
		break;

	case DL_PHYS_ADDR_REQ:
		hmepareq(wq, mp);
		break;

	case DL_SET_PHYS_ADDR_REQ:
		hmespareq(wq, mp);
		break;

	case DL_NOTIFY_REQ:
		hmenreq(wq, mp);
		break;

	default:
		dlerrorack(wq, mp, prim, DL_UNSUPPORTED, 0);
		break;
	}

	TRACE_2(TR_FAC_BE, TR_BE_PROTO_END,
		"hmeproto end:  wq %p dlprim %X", wq, prim);

	mutex_exit(&sbp->sb_lock);
}

static struct hme *
hme_set_ppa(struct hmestr *sbp, queue_t *wq)
{
	struct	hme	*hmep = NULL;
	int instance;

	if (sbp->sb_hmep)	/* ppa has been selected */
		return (sbp->sb_hmep);

	instance = hme_device;
	if (hme_device == -1) {	/* select the first one found */
		mutex_enter(&hmelock);
		if (hmeup)
			instance = hmeup->instance;
		mutex_exit(&hmelock);
	}

	if (instance == -1 || qassociate(wq, instance) != 0) {
		return (NULL);
	}

	mutex_enter(&hmelock);
	for (hmep = hmeup; hmep; hmep = hmep->hme_nextp)
		if (instance == hmep->instance)
			break;
	ASSERT(hmep != NULL);
	mutex_exit(&hmelock);

	sbp->sb_hmep = hmep;
	return (hmep);
}

static void
hmeioctl(queue_t *wq, mblk_t  *mp)
{
	struct	iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	struct	hmestr	*sbp = (struct hmestr *)wq->q_ptr;
	struct	hme	*hmep = sbp->sb_hmep;
	struct	hme	*hmep1;
	hme_ioc_cmd_t	*ioccmdp;
	uint32_t old_ipg1, old_ipg2, old_use_int_xcvr, old_autoneg;
	int32_t old_device;
	int32_t  new_device;
	uint32_t old_100T4;
	uint32_t old_100fdx, old_100hdx, old_10fdx, old_10hdx;
	uint32_t old_ipg0, old_lance_mode;
	int error;

	switch (iocp->ioc_cmd) {
	case DLIOCRAW:		/* raw M_DATA mode */
		sbp->sb_flags |= HMESRAW;
		miocack(wq, mp, 0, 0);
		break;

	case DL_IOC_HDR_INFO:	/* M_DATA "fastpath" info request */
		hme_dl_ioc_hdr_info(wq, mp);
		break;

	case HME_ND_GET:
		hmep = hme_set_ppa(sbp, wq);
		if (hmep == NULL) {	/* no device present */
			miocnak(wq, mp, 0, EINVAL);
			return;
		}
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, NDD_MSG,
				"hmeioctl:ND_GET");
		mutex_enter(&hmelock);
		old_autoneg = hme_param_autoneg;
		old_100T4 = hme_param_anar_100T4;
		old_100fdx = hme_param_anar_100fdx;
		old_100hdx = hme_param_anar_100hdx;
		old_10fdx = hme_param_anar_10fdx;
		old_10hdx = hme_param_anar_10hdx;

		hme_param_autoneg = old_autoneg & ~HME_NOTUSR;
		hme_param_anar_100T4 = old_100T4 & ~HME_NOTUSR;
		hme_param_anar_100fdx = old_100fdx & ~HME_NOTUSR;
		hme_param_anar_100hdx = old_100hdx & ~HME_NOTUSR;
		hme_param_anar_10fdx = old_10fdx & ~HME_NOTUSR;
		hme_param_anar_10hdx = old_10hdx & ~HME_NOTUSR;

		if (!hme_nd_getset(wq, hmep->hme_g_nd, mp)) {
			hme_param_autoneg = old_autoneg;
			hme_param_anar_100T4 = old_100T4;
			hme_param_anar_100fdx = old_100fdx;
			hme_param_anar_100hdx = old_100hdx;
			hme_param_anar_10fdx = old_10fdx;
			hme_param_anar_10hdx = old_10hdx;
			mutex_exit(&hmelock);
			HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, NDD_MSG,
				"hmeioctl:false ret from hme_nd_getset");
			miocnak(wq, mp, 0, EINVAL);
			return;
		}
		hme_param_autoneg = old_autoneg;
		hme_param_anar_100T4 = old_100T4;
		hme_param_anar_100fdx = old_100fdx;
		hme_param_anar_100hdx = old_100hdx;
		hme_param_anar_10fdx = old_10fdx;
		hme_param_anar_10hdx = old_10hdx;

		mutex_exit(&hmelock);

		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, NDD_MSG,
				"hmeioctl:true ret from hme_nd_getset");
		qreply(wq, mp);
		break;

	case HME_ND_SET:
		hmep = hme_set_ppa(sbp, wq);
		if (hmep == NULL) {	/* no device present */
			miocnak(wq, mp, 0, EINVAL);
			return;
		}
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, NDD_MSG,
				"hmeioctl:ND_SET");
		old_device = hme_param_device;
		old_ipg0 = hme_param_ipg0;
		old_lance_mode = hme_param_lance_mode;
		old_ipg1 = hme_param_ipg1;
		old_ipg2 = hme_param_ipg2;
		old_use_int_xcvr = hme_param_use_intphy;
		old_autoneg = hme_param_autoneg;
		hme_param_autoneg = 0xff;

		mutex_enter(&hmelock);
		if (!hme_nd_getset(wq, hmep->hme_g_nd, mp)) {
			hme_param_autoneg = old_autoneg;
			mutex_exit(&hmelock);
			miocnak(wq, mp, 0, EINVAL);
			return;
		}
		mutex_exit(&hmelock);

		if (old_device != hme_param_device) {
			new_device = hme_param_device;
			hme_param_device = old_device;
			hme_param_autoneg = old_autoneg;
			if ((new_device == -1) ||
			    (qassociate(wq, new_device) != 0)) {
				miocnak(wq, mp, 0, EINVAL);
				return;
			}
			mutex_enter(&hmelock);
			for (hmep1 = hmeup; hmep1; hmep1 = hmep1->hme_nextp)
				if (new_device == hmep1->instance)
					break;
			mutex_exit(&hmelock);
			ASSERT(hmep1 != NULL);

			hme_device = new_device;
			sbp->sb_hmep = hmep1;
			qreply(wq, mp);
			return;
		}

		qreply(wq, mp);

		if (hme_param_autoneg != 0xff) {
			hmep->hme_linkcheck = 0;
			(void) hmeinit(hmep);
		} else {
			hme_param_autoneg = old_autoneg;
			if (old_use_int_xcvr != hme_param_use_intphy) {
				hmep->hme_linkcheck = 0;
				(void) hmeinit(hmep);
			} else if ((old_ipg1 != hme_param_ipg1) ||
					(old_ipg2 != hme_param_ipg2) ||
					(old_ipg0 != hme_param_ipg0) ||
				(old_lance_mode != hme_param_lance_mode)) {
				(void) hmeinit(hmep);
			}
		}
		break;

	case HME_IOC:
		error = miocpullup(mp, sizeof (hme_ioc_cmd_t));
		if (error != 0) {
			miocnak(wq, mp, 0, error);
			return;
		}

		ioccmdp = (hme_ioc_cmd_t *)mp->b_cont->b_rptr;
		switch (ioccmdp->hdr.cmd) {

		case HME_IOC_GET_SPEED:
			ioccmdp->mode = hmep->hme_mode;

			switch (hmep->hme_mode) {
			case HME_AUTO_SPEED:
				ioccmdp->speed = hmep->hme_tryspeed;
				break;
			case HME_FORCE_SPEED:
				ioccmdp->speed = hmep->hme_forcespeed;
				break;
			default:
				HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, NDD_MSG,
						"HME_IOC default get speed");
				break;
			}

			miocack(wq, mp, msgsize(mp->b_cont), 0);
			break;

		case HME_IOC_SET_SPEED:
			hmep->hme_mode = ioccmdp->mode;
			hmep->hme_linkup = 0;
			hmep->hme_delay = 0;
			hmep->hme_linkup_cnt = 0;
			hmep->hme_force_linkdown = HME_FORCE_LINKDOWN;
			ddi_dev_report_fault(hmep->dip, DDI_SERVICE_DEGRADED,
			    DDI_DEVICE_FAULT, link_down_msg);

			/* Enable display of linkup message */
			switch (hmep->hme_mode) {
			case HME_AUTO_SPEED:
				HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN,
				    IOCTL_MSG,
				    "ioctl: AUTO_SPEED");
				hmep->hme_linkup_10 = 0;
				hmep->hme_tryspeed = HME_SPEED_100;
				hmep->hme_ntries = HME_NTRIES_LOW;
				hmep->hme_nlasttries = HME_NTRIES_LOW;
				hme_try_speed(hmep);
				break;

			case HME_FORCE_SPEED:
				HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN,
				    IOCTL_MSG,
				    "ioctl: FORCE_SPEED");

				hmep->hme_forcespeed = ioccmdp->speed;
				hme_force_speed(hmep);
				break;
			default:
				HME_DEBUG_MSG1(hmep, SEVERITY_HIGH,
				    NDD_MSG,
				    "HME_IOC default set speed");
				miocnak(wq, mp, 0, EINVAL);
				return;
			}
			miocack(wq, mp, 0, 0);
			break;
		default:
			HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, NDD_MSG,
			    "HMEIOC default nor s/get speed");
			miocnak(wq, mp, 0, EINVAL);
			break;
		}
		break;

	default:
		HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, NDD_MSG,
				"HME_IOC default command");
		miocnak(wq, mp, 0, EINVAL);
		break;
	}
}

/*
 * M_DATA "fastpath" info request.
 * Following the M_IOCTL mblk should come a DL_UNITDATA_REQ mblk.
 * We ack with an M_IOCACK pointing to the original DL_UNITDATA_REQ mblk
 * followed by an mblk containing the raw ethernet header corresponding
 * to the destination address.  Subsequently, we may receive M_DATA
 * msgs which start with this header and may send up
 * up M_DATA msgs with b_rptr pointing to a (ulong_t) group address
 * indicator followed by the network-layer data (IP packet header).
 * This is all selectable on a per-Stream basis.
 */
static void
hme_dl_ioc_hdr_info(queue_t *wq, mblk_t *mp)
{
	mblk_t	*nmp;
	struct	hmestr	*sbp;
	struct	hmedladdr	*dlap;
	dl_unitdata_req_t	*dludp;
	struct	ether_header	*headerp;
	struct	hme	*hmep;
	t_uscalar_t off, len;
	int error;

	sbp = (struct hmestr *)wq->q_ptr;
	hmep = sbp->sb_hmep;
	if (hmep == NULL) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	error = miocpullup(mp, sizeof (dl_unitdata_req_t) + HMEADDRL);
	if (error != 0) {
		miocnak(wq, mp, 0, error);
		return;
	}

	/*
	 * Sanity check the DL_UNITDATA_REQ destination address
	 * offset and length values.
	 */
	dludp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;
	if (dludp->dl_primitive != DL_UNITDATA_REQ ||
	    !MBLKIN(mp->b_cont, off, len) || len != HMEADDRL) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	dlap = (struct hmedladdr *)(mp->b_cont->b_rptr + off);

	/*
	 * Allocate a new mblk to hold the ether header.
	 */
	if ((nmp = allocb(sizeof (struct ether_header), BPRI_MED)) == NULL) {
		miocnak(wq, mp, 0, ENOMEM);
		return;
	}
	nmp->b_wptr += sizeof (struct ether_header);

	/*
	 * Fill in the ether header.
	 */
	headerp = (struct ether_header *)nmp->b_rptr;
	ether_bcopy(&dlap->dl_phys, &headerp->ether_dhost);
	ether_bcopy(&hmep->hme_ouraddr, &headerp->ether_shost);
	put_ether_type(headerp, dlap->dl_sap);

	/*
	 * Link new mblk in after the "request" mblks.
	 */
	linkb(mp, nmp);

	sbp->sb_flags |= HMESFAST;
	miocack(wq, mp, msgsize(mp->b_cont), 0);
}

static void
hmeareq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;
	union	DL_primitives	*dlp;
	struct	hme	*hmep = NULL;
	t_uscalar_t ppa;
	uint32_t promisc_phys_cnt = 0, promisc_multi_cnt = 0;

	sbp = (struct hmestr *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;

	if (MBLKL(mp) < DL_ATTACH_REQ_SIZE) {
		dlerrorack(wq, mp, DL_ATTACH_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state != DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_ATTACH_REQ, DL_OUTSTATE, 0);
		return;
	}

	/*
	 * Count the number of snoop/promisc modes.
	 */
	if (sbp->sb_flags & HMESALLPHYS)
		promisc_phys_cnt++;
	if (sbp->sb_flags & HMESALLMULTI)
		promisc_multi_cnt++;

	ppa = dlp->attach_req.dl_ppa;

	/*
	 * Valid ppa?
	 */
	if (qassociate(wq, ppa) == 0) {
		mutex_enter(&hmelock);
		for (hmep = hmeup; hmep; hmep = hmep->hme_nextp) {
			if (ppa == hmep->instance) {
				hmep->promisc_phys_cnt += promisc_phys_cnt;
				hmep->promisc_multi_cnt += promisc_multi_cnt;
				break;
			}
		}
		mutex_exit(&hmelock);
		ASSERT(hmep != NULL);
	}

	if (hmep == NULL) {
		dlerrorack(wq, mp, dlp->dl_primitive, DL_BADPPA, 0);
		return;
	}

	/* Set link to device and update our state. */
	sbp->sb_hmep = hmep;
	sbp->sb_state = DL_UNBOUND;

	/*
	 * Has device been initialized?  Do so if necessary.
	 * Also check if promiscuous mode is set via the ALLPHYS and
	 * ALLMULTI flags, for the stream.  If so, initialize the
	 * interface.
	 */
	if (((hmep->hme_flags & HMERUNNING) == 0) ||
	    (((hmep->promisc_multi_cnt + hmep->promisc_phys_cnt) == 1) &&
	    ((promisc_multi_cnt + promisc_phys_cnt) > 0)) ||
	    ((hmep->promisc_phys_cnt == 1) && (promisc_phys_cnt == 1))) {
		/*
		 * Initialize the Interrupt mask
		 * The init will clear upon entry
		 * and reset upon success.
		 */
		hmep->intr_mask = HMEG_MASK_INTR;

		if (hmeinit(hmep)) {
			dlerrorack(wq, mp, dlp->dl_primitive, DL_INITFAILED, 0);
			sbp->sb_hmep = NULL;
			sbp->sb_state = DL_UNATTACHED;
			(void) qassociate(wq, -1);
			return;
		}

		if ((hmep->promisc_phys_cnt == 1) && (promisc_phys_cnt == 1))
			hmenotify_ind(hmep, DL_NOTE_PROMISC_ON_PHYS);
	}

	dlokack(wq, mp, DL_ATTACH_REQ);
}

static void
hmedreq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_DETACH_REQ_SIZE) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_DETACH_REQ, DL_OUTSTATE, 0);
		return;
	}

	hmedodetach(sbp);
	(void) qassociate(wq, -1);
	dlokack(wq, mp, DL_DETACH_REQ);
}

/*
 * Detach a Stream from an interface.
 */
static void
hmedodetach(struct  hmestr *sbp)
{
	struct	hmestr	*tsbp;
	struct	hme	*hmep;
	uint_t	reinit = 0;
	uint_t	i;
	uint32_t promisc_phys_cnt = 0, promisc_multi_cnt = 0;

	ASSERT(sbp->sb_hmep);

	hmep = sbp->sb_hmep;
	sbp->sb_hmep = NULL;

	/* Disable promiscuous mode if on. */
	if (sbp->sb_flags & HMESALLPHYS) {
		sbp->sb_flags &= ~HMESALLPHYS;
		promisc_phys_cnt++;
		reinit = 1;
	}

	/* Disable ALLSAP mode if on. */
	if (sbp->sb_flags & HMESALLSAP) {
		sbp->sb_flags &= ~HMESALLSAP;
		reinit = 1;
	}

	/* Disable ALLMULTI mode if on. */
	if (sbp->sb_flags & HMESALLMULTI) {
		sbp->sb_flags &= ~HMESALLMULTI;
		promisc_multi_cnt++;
		reinit = 1;
	}

	/* Disable any Multicast Addresses. */

	for (i = 0; i < NMCHASH; i++) {
		if (sbp->sb_mctab[i]) {
			reinit = 1;
			kmem_free(sbp->sb_mctab[i], sbp->sb_mcsize[i] *
			    sizeof (struct ether_addr));
			sbp->sb_mctab[i] = NULL;
		}
		sbp->sb_mccount[i] = sbp->sb_mcsize[i] = 0;
	}

	for (i = 0; i < 4; i++)
		sbp->sb_ladrf[i] = 0;

	for (i = 0; i < 64; i++)
		sbp->sb_ladrf_refcnt[i] = 0;

	sbp->sb_state = DL_UNATTACHED;

	/*
	 * Detach from device structure.
	 * Uninit the device
	 * when no other streams are attached to it.
	 */
	rw_enter(&hmestruplock, RW_READER);
	for (tsbp = hmestrup; tsbp; tsbp = tsbp->sb_nextp)
		if (tsbp->sb_hmep == hmep)
			break;
	rw_exit(&hmestruplock);

	hmep->promisc_phys_cnt -= promisc_phys_cnt;
	hmep->promisc_multi_cnt -= promisc_multi_cnt;
	if (tsbp == NULL)
		hmeuninit(hmep);
	else if (reinit) {
		if ((((hmep->promisc_multi_cnt + hmep->promisc_phys_cnt)
		    == 0) && ((promisc_phys_cnt + promisc_multi_cnt) > 0)) ||
		    ((hmep->promisc_phys_cnt == 0) && (promisc_phys_cnt == 1)))
			(void) hmeinit(hmep);

		if ((hmep->promisc_phys_cnt == 0) && (promisc_phys_cnt == 1))
			hmenotify_ind(hmep, DL_NOTE_PROMISC_OFF_PHYS);
	}
	hmesetipq(hmep);
}

static void
hmebreq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;
	union	DL_primitives	*dlp;
	struct	hme	*hmep;
	struct	hmedladdr	hmeaddr;
	t_uscalar_t sap;
	t_uscalar_t xidtest;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_BIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state != DL_UNBOUND) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	if (dlp->bind_req.dl_service_mode != hmeinfoack.dl_service_mode) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_UNSUPPORTED, 0);
		return;
	}

	hmep = sbp->sb_hmep;
	sap = dlp->bind_req.dl_sap;
	xidtest = dlp->bind_req.dl_xidtest_flg;

	ASSERT(hmep);

	if (xidtest) {
		dlerrorack(wq, mp, DL_BIND_REQ, DL_NOAUTO, 0);
		return;
	}

	if (sap > ETHERTYPE_MAX) {
		dlerrorack(wq, mp, dlp->dl_primitive, DL_BADSAP, 0);
		return;
	}

	/*
	 * Save SAP value for this Stream and change state.
	 */
	sbp->sb_sap = sap;
	sbp->sb_state = DL_IDLE;

	hmeaddr.dl_sap = sap;
	ether_bcopy(&hmep->hme_ouraddr, &hmeaddr.dl_phys);
	dlbindack(wq, mp, sap, &hmeaddr, HMEADDRL, 0, 0);
	hmesetipq(hmep);

}

static void
hmeubreq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_UNBIND_REQ_SIZE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state != DL_IDLE) {
		dlerrorack(wq, mp, DL_UNBIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	sbp->sb_state = DL_UNBOUND;
	sbp->sb_sap = 0;

	dlokack(wq, mp, DL_UNBIND_REQ);

	hmesetipq(sbp->sb_hmep);
}

static void
hmeireq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;
	dl_info_ack_t	*dlip;
	struct	hmedladdr	*dlap;
	struct	ether_addr	*ep;
	size_t	size;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_INFO_REQ_SIZE) {
		dlerrorack(wq, mp, DL_INFO_REQ, DL_BADPRIM, 0);
		return;
	}

	/* Exchange current msg for a DL_INFO_ACK. */
	size = sizeof (dl_info_ack_t) + HMEADDRL + ETHERADDRL;
	if ((mp = mexchange(wq, mp, size, M_PCPROTO, DL_INFO_ACK)) == NULL)
		return;

	/* Fill in the DL_INFO_ACK fields and reply. */
	dlip = (dl_info_ack_t *)mp->b_rptr;
	*dlip = hmeinfoack;
	dlip->dl_current_state = sbp->sb_state;
	dlap = (struct hmedladdr *)(mp->b_rptr + dlip->dl_addr_offset);
	dlap->dl_sap = sbp->sb_sap;
	if (sbp->sb_hmep) {
		ether_bcopy(&sbp->sb_hmep->hme_ouraddr, &dlap->dl_phys);
	} else {
		bzero(&dlap->dl_phys, ETHERADDRL);
	}
	ep = (struct ether_addr *)(mp->b_rptr + dlip->dl_brdcst_addr_offset);
	ether_bcopy(&etherbroadcastaddr, ep);

	qreply(wq, mp);
}

static void
hmeponreq(queue_t *wq, mblk_t *mp)
{
	struct hme *hmep;
	struct	hmestr	*sbp;
	uint32_t promisc_phys_cnt = 0, promisc_multi_cnt = 0;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCON_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PROMISCON_REQ, DL_BADPRIM, 0);
		return;
	}

	switch (((dl_promiscon_req_t *)mp->b_rptr)->dl_level) {
	case DL_PROMISC_PHYS:
		sbp->sb_flags |= HMESALLPHYS;
		promisc_phys_cnt++;
		break;

	case DL_PROMISC_SAP:
		sbp->sb_flags |= HMESALLSAP;
		break;

	case DL_PROMISC_MULTI:
		sbp->sb_flags |= HMESALLMULTI;
		promisc_multi_cnt++;
		break;

	default:
		dlerrorack(wq, mp, DL_PROMISCON_REQ,
					DL_NOTSUPPORTED, 0);
		return;
	}

	hmep = sbp->sb_hmep;
	if (hmep) {
		hmep->promisc_phys_cnt += promisc_phys_cnt;
		hmep->promisc_multi_cnt += promisc_multi_cnt;
		if ((((hmep->promisc_multi_cnt + hmep->promisc_phys_cnt)
		    == 1) && ((promisc_multi_cnt + promisc_phys_cnt) > 0)) ||
		    ((hmep->promisc_phys_cnt == 1) && (promisc_phys_cnt == 1)))
			(void) hmeinit(sbp->sb_hmep);

		if ((hmep->promisc_phys_cnt == 1) && (promisc_phys_cnt == 1))
			hmenotify_ind(hmep, DL_NOTE_PROMISC_ON_PHYS);

		hmesetipq(sbp->sb_hmep);
	}

	dlokack(wq, mp, DL_PROMISCON_REQ);
}

static void
hmepoffreq(queue_t *wq, mblk_t *mp)
{
	struct	hme	*hmep;
	struct	hmestr	*sbp;
	int	flag;
	uint32_t promisc_phys_cnt = 0, promisc_multi_cnt = 0;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCOFF_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_BADPRIM, 0);
		return;
	}

	switch (((dl_promiscoff_req_t *)mp->b_rptr)->dl_level) {
	case DL_PROMISC_PHYS:
		flag = HMESALLPHYS;
		promisc_phys_cnt++;
		break;

	case DL_PROMISC_SAP:
		flag = HMESALLSAP;
		break;

	case DL_PROMISC_MULTI:
		flag = HMESALLMULTI;
		promisc_multi_cnt++;
		break;

	default:
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ,
					DL_NOTSUPPORTED, 0);
		return;
	}

	if ((sbp->sb_flags & flag) == 0) {
		dlerrorack(wq, mp, DL_PROMISCOFF_REQ, DL_NOTENAB, 0);
		return;
	}

	sbp->sb_flags &= ~flag;
	hmep = sbp->sb_hmep;

	if (hmep) {
		hmep->promisc_phys_cnt -= promisc_phys_cnt;
		hmep->promisc_multi_cnt -= promisc_multi_cnt;
		if ((((hmep->promisc_multi_cnt + hmep->promisc_phys_cnt)
		    == 0) && ((promisc_multi_cnt + promisc_phys_cnt) > 0)) ||
		    ((hmep->promisc_phys_cnt == 0) && (promisc_phys_cnt == 1)))
			(void) hmeinit(hmep);

		if ((hmep->promisc_phys_cnt == 0) && (promisc_phys_cnt == 1))
			hmenotify_ind(hmep, DL_NOTE_PROMISC_OFF_PHYS);
		hmesetipq(hmep);
	}

	dlokack(wq, mp, DL_PROMISCOFF_REQ);
}

/*
 * This is to support unlimited number of members
 * is MC.
 */
static void
hmeemreq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;
	union	DL_primitives	*dlp;
	struct	ether_addr	*addrp;
	t_uscalar_t off;
	t_uscalar_t len;
	uint32_t	mchash;
	struct	ether_addr	*mcbucket;
	uint32_t	ladrf_bit;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_ENABMULTI_REQ_SIZE) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state == DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->enabmulti_req.dl_addr_length;
	off = dlp->enabmulti_req.dl_addr_offset;
	addrp = (struct ether_addr *)(mp->b_rptr + off);

	if ((len != ETHERADDRL) ||
		!MBLKIN(mp, off, len) ||
		((addrp->ether_addr_octet[0] & 01) == 0)) {
		dlerrorack(wq, mp, DL_ENABMULTI_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * Calculate hash value and bucket.
	 */

	mchash = MCHASH(addrp);
	mcbucket = sbp->sb_mctab[mchash];

	/*
	 * Allocate hash bucket if it's not there.
	 */

	if (mcbucket == NULL) {
		sbp->sb_mctab[mchash] = mcbucket =
		    kmem_alloc(INIT_BUCKET_SIZE * sizeof (struct ether_addr),
			KM_SLEEP);
		sbp->sb_mcsize[mchash] = INIT_BUCKET_SIZE;
	}

	/*
	 * We no longer bother checking to see if the address is already
	 * in the table (bugid 1209733).  We won't reinitialize the
	 * hardware, since we'll find the mc bit is already set.
	 */

	/*
	 * Expand table if necessary.
	 */
	if (sbp->sb_mccount[mchash] >= sbp->sb_mcsize[mchash]) {
		struct	ether_addr	*newbucket;
		uint32_t		newsize;

		newsize = sbp->sb_mcsize[mchash] * 2;

		newbucket = kmem_alloc(newsize * sizeof (struct ether_addr),
			KM_SLEEP);

		bcopy(mcbucket, newbucket,
		    sbp->sb_mcsize[mchash] * sizeof (struct ether_addr));
		kmem_free(mcbucket, sbp->sb_mcsize[mchash] *
		    sizeof (struct ether_addr));

		sbp->sb_mctab[mchash] = mcbucket = newbucket;
		sbp->sb_mcsize[mchash] = newsize;
	}

	/*
	 * Add address to the table.
	 */
	mcbucket[sbp->sb_mccount[mchash]++] = *addrp;

	/*
	 * If this address's bit was not already set in the local address
	 * filter, add it and re-initialize the Hardware.
	 */
	ladrf_bit = hmeladrf_bit(addrp);

	if (sbp->sb_ladrf_refcnt[ladrf_bit] == 0) {
		sbp->sb_ladrf[ladrf_bit >> 4] |= 1 << (ladrf_bit & 0xf);
		(void) hmeinit(sbp->sb_hmep);
	}
	sbp->sb_ladrf_refcnt[ladrf_bit]++;

	dlokack(wq, mp, DL_ENABMULTI_REQ);
}

static void
hmedmreq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;
	union	DL_primitives	*dlp;
	struct	ether_addr	*addrp;
	t_uscalar_t off;
	t_uscalar_t len;
	int	i;
	uint32_t		mchash;
	struct	ether_addr	*mcbucket;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_DISABMULTI_REQ_SIZE) {
		dlerrorack(wq, mp, DL_DISABMULTI_REQ, DL_BADPRIM, 0);
		return;
	}

	if (sbp->sb_state == DL_UNATTACHED) {
		dlerrorack(wq, mp, DL_DISABMULTI_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->disabmulti_req.dl_addr_length;
	off = dlp->disabmulti_req.dl_addr_offset;
	addrp = (struct ether_addr *)(mp->b_rptr + off);

	if ((len != ETHERADDRL) || !MBLKIN(mp, off, len)) {
		dlerrorack(wq, mp, DL_DISABMULTI_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * Calculate hash value, get pointer to hash bucket for this address.
	 */

	mchash = MCHASH(addrp);
	mcbucket = sbp->sb_mctab[mchash];

	/*
	 * Try and delete the address if we can find it.
	 */
	if (mcbucket) {
		for (i = 0; i < sbp->sb_mccount[mchash]; i++) {
			if (ether_cmp(addrp, &mcbucket[i]) == 0) {
				uint32_t ladrf_bit;

				/*
				 * If there's more than one address in this
				 * bucket, delete the unwanted one by moving
				 * the last one in the list over top of it;
				 * otherwise, just free the bucket.
				 */
				if (sbp->sb_mccount[mchash] > 1) {
					mcbucket[i] =
					    mcbucket[sbp->sb_mccount[mchash]-1];
				} else {
					kmem_free(mcbucket,
					    sbp->sb_mcsize[mchash] *
					    sizeof (struct ether_addr));
					sbp->sb_mctab[mchash] = NULL;
				}
				sbp->sb_mccount[mchash]--;

				/*
				 * If this address's bit should no longer be
				 * set in the local address filter, clear it and
				 * re-initialize the Hardware
				 */

				ladrf_bit = hmeladrf_bit(addrp);
				sbp->sb_ladrf_refcnt[ladrf_bit]--;

				if (sbp->sb_ladrf_refcnt[ladrf_bit] == 0) {
					sbp->sb_ladrf[ladrf_bit >> 4] &=
					    ~(1 << (ladrf_bit & 0xf));
					(void) hmeinit(sbp->sb_hmep);
				}

				dlokack(wq, mp, DL_DISABMULTI_REQ);
				return;
			}
		}
	}
	dlerrorack(wq, mp, DL_DISABMULTI_REQ, DL_NOTENAB, 0);
}

static void
hmepareq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;
	union	DL_primitives	*dlp;
	uint32_t	type;
	struct	hme	*hmep;
	struct	ether_addr	addr;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_PHYS_ADDR_REQ_SIZE) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	type = dlp->physaddr_req.dl_addr_type;
	hmep = sbp->sb_hmep;

	if (hmep == NULL) {
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	switch (type) {
	case DL_FACT_PHYS_ADDR:
		if (hmep->hme_addrflags & HME_FACTADDR_PRESENT)
			ether_bcopy(&hmep->hme_factaddr, &addr);
		else
			(void) localetheraddr((struct ether_addr *)NULL, &addr);
		break;

	case DL_CURR_PHYS_ADDR:
		ether_bcopy(&hmep->hme_ouraddr, &addr);
		break;

	default:
		dlerrorack(wq, mp, DL_PHYS_ADDR_REQ, DL_NOTSUPPORTED, 0);
			return;
	}
	dlphysaddrack(wq, mp, &addr, ETHERADDRL);
}

static void
hmespareq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;
	union	DL_primitives	*dlp;
	struct	ether_addr	*addrp;
	struct	hme	*hmep;
	t_uscalar_t off, len;

	sbp = (struct hmestr *)wq->q_ptr;

	if (MBLKL(mp) < DL_SET_PHYS_ADDR_REQ_SIZE) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->set_physaddr_req.dl_addr_length;
	off = dlp->set_physaddr_req.dl_addr_offset;

	if (!MBLKIN(mp, off, len)) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	addrp = (struct ether_addr *)(mp->b_rptr + off);

	/*
	 * Error if length of address isn't right or the address
	 * specified is a multicast or broadcast address.
	 */
	if ((len != ETHERADDRL) ||
		((addrp->ether_addr_octet[0] & 01) == 1) ||
		(ether_cmp(addrp, &etherbroadcastaddr) == 0)) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * Error if this stream is not attached to a device.
	 */
	if ((hmep = sbp->sb_hmep) == NULL) {
		dlerrorack(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	/*
	 * Set new interface local address and re-init device.
	 * This is destructive to any other streams attached
	 * to this device.
	 */
	ether_bcopy(addrp, &hmep->hme_ouraddr);
	(void) hmeinit(sbp->sb_hmep);

	dlokack(wq, mp, DL_SET_PHYS_ADDR_REQ);
}

static void
hmeudreq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr	*sbp;
	struct	hme	*hmep;
	dl_unitdata_req_t	*dludp;
	mblk_t	*nmp;
	struct	hmedladdr	*dlap;
	struct	ether_header	*headerp;
	t_uscalar_t off, len;
	t_uscalar_t sap;
	int	hdrlen;

	sbp = (struct hmestr *)wq->q_ptr;
	hmep = sbp->sb_hmep;

	if (sbp->sb_state != DL_IDLE) {
		dlerrorack(wq, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		return;
	}

	dludp = (dl_unitdata_req_t *)mp->b_rptr;

	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;

	/*
	 * Validate destination address format.
	 */
	if (!MBLKIN(mp, off, len) || (len != HMEADDRL)) {
		dluderrorind(wq, mp, mp->b_rptr + off, len, DL_BADADDR, 0);
		return;
	}

	/*
	 * Error if no M_DATA follows.
	 */
	nmp = mp->b_cont;
	if (nmp == NULL) {
		dluderrorind(wq, mp, mp->b_rptr + off, len, DL_BADDATA, 0);
		return;
	}

	dlap = (struct hmedladdr *)(mp->b_rptr + off);
	hdrlen = sizeof (struct ether_header);

	/*
	 * Create ethernet header by either prepending it onto the
	 * next mblk if possible, or reusing the M_PROTO block if not.
	 */
	if ((DB_REF(nmp) == 1) && (MBLKHEAD(nmp) >= hdrlen) &&
		(((uintptr_t)nmp->b_rptr & 0x1) == 0)) {
		/*
		 * Space available for ethernet hdr in M_DATA payload
		 */
		nmp->b_rptr -= hdrlen;
		headerp = (struct ether_header *)nmp->b_rptr;
		ether_bcopy(&dlap->dl_phys, &headerp->ether_dhost);
		ether_bcopy(&hmep->hme_ouraddr, &headerp->ether_shost);
		sap = (uint16_t)((((uchar_t *)(&dlap->dl_sap))[0] << 8) |
			((uchar_t *)(&dlap->dl_sap))[1]);
		freeb(mp);
	} else if ((DB_REF(mp) == 1) && (MBLKSIZE(mp) >= hdrlen)) {
		/*
		 * Space available in dl_unitdata_req M_PROTO blk. Reuse it.
		 */
		nmp = mp;
		DB_TYPE(nmp) = M_DATA;
		nmp->b_rptr = DB_BASE(nmp);
		nmp->b_wptr = nmp->b_rptr + hdrlen;
		headerp = (struct ether_header *)nmp->b_rptr;
		ether_bcopy(&dlap->dl_phys, &headerp->ether_dhost);
		ether_bcopy(&hmep->hme_ouraddr, &headerp->ether_shost);
		sap = (uint16_t)((((uchar_t *)(&dlap->dl_sap))[0] << 8) |
			((uchar_t *)(&dlap->dl_sap))[1]);

	} else {
		/*
		 * M_PROTO and M_DATA did not have space for ethernet hdr.
		 * Allocate new mblk.
		 */
		if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL) {
			HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, DISPLAY_MSG,
			    "allocb failed\n");
			return;
		}
		headerp = (struct ether_header *)nmp->b_rptr;
		ether_bcopy(&dlap->dl_phys, &headerp->ether_dhost);
		ether_bcopy(&hmep->hme_ouraddr, &headerp->ether_shost);
		sap = (uint16_t)((((uchar_t *)(&dlap->dl_sap))[0] << 8) |
			((uchar_t *)(&dlap->dl_sap))[1]);
		nmp->b_wptr = nmp->b_rptr + hdrlen;
		linkb(nmp, mp->b_cont);
		freeb(mp);
	}


	/*
	 * In 802.3 mode, the driver looks at the
	 * sap field of the DL_BIND_REQ being 0 in addition to the destination
	 * sap field in the range [0-1500]. If either is true, then the driver
	 * computes the length of the message, not including initial M_PROTO
	 * mblk (message block), of all subsequent DL_UNITDATA_REQ messages and
	 * transmits 802.3 frames that have this value in the MAC frame header
	 * length field.
	 */
	if (sap <= ETHERMTU || (sbp->sb_sap == 0)) {
		put_ether_type(headerp, (msgsize(nmp) - hdrlen));
	} else {
		put_ether_type(headerp, sap);
	}
	(void) hmestart(wq, nmp, hmep);
}

static void
hmenreq(queue_t *wq, mblk_t *mp)
{
	struct	hmestr		*sbp;
	dl_notify_req_t		*dlip;
	dl_notify_ind_t		*dlnip;
	struct	hme		*hmep = NULL;
	mblk_t			*nmp;
	uint32_t		dl_notification;

	if (MBLKL(mp) < DL_NOTIFY_REQ_SIZE) {
		dlerrorack(wq, mp, DL_NOTIFY_ACK, DL_BADPRIM, 0);
		return;
	}

	dlip = (dl_notify_req_t *)mp->b_rptr;

	dl_notification = dlip->dl_notifications & (
				DL_NOTE_PROMISC_ON_PHYS |
				DL_NOTE_PROMISC_OFF_PHYS |
				DL_NOTE_LINK_DOWN |
				DL_NOTE_LINK_UP |
				DL_NOTE_SPEED);

	sbp = (struct hmestr *)wq->q_ptr;

	if (sbp->sb_state != DL_IDLE) {
		dlerrorack(wq, mp, DL_NOTIFY_ACK, DL_BADPRIM, 0);
		return;
	}

	hmep = sbp->sb_hmep;

	sbp->sb_notifications |= dl_notification;

	dlip->dl_notifications = DL_NOTE_PROMISC_ON_PHYS |
				DL_NOTE_PROMISC_OFF_PHYS |
				DL_NOTE_LINK_DOWN |
				DL_NOTE_LINK_UP |
				DL_NOTE_SPEED;

	dlip->dl_primitive = DL_NOTIFY_ACK;
	mp->b_wptr = mp->b_rptr + sizeof (dl_notify_ack_t);
	qreply(wq, mp);

	while (dl_notification) {
		if ((nmp = allocb(DL_NOTIFY_IND_SIZE, BPRI_HI)) == NULL)
			break;
		nmp->b_datap->db_type = M_PROTO;
		dlnip = (dl_notify_ind_t *)nmp->b_rptr;
		dlnip->dl_primitive = DL_NOTIFY_IND;
		dlnip->dl_notification = 0;
		dlnip->dl_data = 0;
		dlnip->dl_addr_length = 0;
		dlnip->dl_addr_offset = 0;
		if (dl_notification & DL_NOTE_PROMISC_ON_PHYS) {
			dl_notification &= ~DL_NOTE_PROMISC_ON_PHYS;
			if (hmep->promisc_phys_cnt)
				dlnip->dl_notification =
				    DL_NOTE_PROMISC_ON_PHYS;
		} else if (dl_notification & DL_NOTE_PROMISC_OFF_PHYS) {
			dl_notification &= ~DL_NOTE_PROMISC_OFF_PHYS;
			if (hmep->promisc_phys_cnt == 0)
				dlnip->dl_notification =
				    DL_NOTE_PROMISC_OFF_PHYS;
		} else if (dl_notification & DL_NOTE_LINK_DOWN) {
			dl_notification &= ~DL_NOTE_LINK_DOWN;
			if (!hmep->hme_link_up)
				dlnip->dl_notification = DL_NOTE_LINK_DOWN;
		} else if (dl_notification & DL_NOTE_LINK_UP) {
			dl_notification &= ~DL_NOTE_LINK_UP;
			if (hmep->hme_link_up)
				dlnip->dl_notification = DL_NOTE_LINK_UP;
		} else if (dl_notification & DL_NOTE_SPEED) {
			dl_notification &= ~DL_NOTE_SPEED;
			/*
			 * Report interface speed in Kb/Sec
			 */
			dlnip->dl_data = hmep->hme_ifspeed * 1000;
			dlnip->dl_notification = DL_NOTE_SPEED;
		}
		if (dlnip->dl_notification) {
			nmp->b_wptr = nmp->b_rptr + sizeof (dl_notify_ind_t);
			qreply(wq, nmp);
		} else {
			freemsg(nmp);
		}
	}

}

static void
hmenotify_ind(struct hme *hmep, uint32_t notification)
{
	struct	hmestr		*sbp;
	mblk_t			*mp;
	dl_notify_ind_t *dlnip;

	for (sbp = hmestrup; sbp; sbp = sbp->sb_nextp) {
		/*
		 * Notify streams that are attached to *this* instance only.
		 */
		if (sbp->sb_hmep != hmep)
			continue;
		if (notification & sbp->sb_notifications) {
			if ((mp = allocb(DL_NOTIFY_IND_SIZE, BPRI_HI)) == NULL)
				break;
			mp->b_datap->db_type = M_PROTO;
			dlnip = (dl_notify_ind_t *)mp->b_rptr;
			dlnip->dl_primitive = DL_NOTIFY_IND;
			dlnip->dl_notification = notification;
			if (notification == DL_NOTE_SPEED)
				/*
				 * Report interface speed in Kb/Sec.
				 */
				dlnip->dl_data = hmep->hme_ifspeed * 1000;
			else
				dlnip->dl_data = 0;
			dlnip->dl_addr_length = 0;
			dlnip->dl_addr_offset = 0;
			mp->b_wptr = mp->b_rptr + sizeof (dl_notify_ind_t);
			qreply(WR(sbp->sb_rq), mp);
		}
	}
}

static int
hmestart_dma(queue_t *wq, mblk_t *mp, struct hme *hmep)
{
	volatile	struct	hme_tmd	*tmdp1 = NULL;
	volatile	struct	hme_tmd	*tmdp2 = NULL;
	volatile	struct	hme_tmd	*ntmdp = NULL;
	mblk_t	*nmp = NULL;
	mblk_t  *bp;
	uint32_t len1, len2;
	uint32_t temp_addr;
	int32_t	syncval;
	ulong_t i, j;
	ddi_dma_cookie_t c;
	uint_t cnt;
	time_t	now;

	TRACE_1(TR_FAC_BE, TR_BE_START_START, "hmestart: wq %p #0705", wq);

	if (!hmep->hme_linkup) {
		if ((hmep->hme_linkup_msg) &&
		    (((now = gethrestime_sec()) - hmep->hme_msg_time) > 10)) {
			HME_FAULT_MSG1(hmep, SEVERITY_UNKNOWN, TX_MSG,
			    link_down_msg);
			hmep->hme_msg_time = now;
		}
		freemsg(mp);
		return (0);
	}

	if ((hmep->promisc_phys_cnt + hmep->promisc_multi_cnt) != 0)
		if ((nmp = dupmsg(mp)) == NULL) {
			hmep->hme_allocbfail++;
			hmep->hme_noxmtbuf++;
		}

	mutex_enter(&hmep->hme_xmitlock);

	if (hmep->hme_tnextp > hmep->hme_tcurp) {
		if ((hmep->hme_tnextp - hmep->hme_tcurp) > HMETPENDING)
			hmereclaim(hmep);
	} else {
		i = hmep->hme_tcurp - hmep->hme_tnextp;
		if (i && (i < (HME_TMDMAX - HMETPENDING)))
			hmereclaim(hmep);
	}
	tmdp1 = hmep->hme_tnextp;
	if ((ntmdp = NEXTTMD(hmep, tmdp1)) == hmep->hme_tcurp)
		goto notmds;

	i = tmdp1 - hmep->hme_tmdp;

	/*
	 * here we deal with 3 cases.
	 *	1. pkt has exactly one mblk
	 *	2. pkt has exactly two mblks
	 *	3. pkt has more than 2 mblks. Since this almost
	 *		always never happens, we copy all of them
	 *		into a msh with one mblk.
	 * for each mblk in the message, we allocate a tmd and
	 * figure out the tmd index. The index is then used to bind
	 * a DMA handle to the mblk and set up an IO mapping..
	 */

	ASSERT(mp->b_wptr >= mp->b_rptr);
	len1 = mp->b_wptr - mp->b_rptr;
	bp = mp->b_cont;

	if (bp == NULL) {
		len2 = 0;

		HME_DEBUG_MSG3(hmep, SEVERITY_UNKNOWN, TX_MSG,
				"hmestart: 1 buf: len = %ld b_rptr = %p",
				len1, mp->b_rptr);
	} else if ((bp->b_cont == NULL) &&
	    ((len2 = bp->b_wptr - bp->b_rptr) >= 4)) {

		ASSERT(bp->b_wptr >= bp->b_rptr);

		tmdp2 = ntmdp;
		if ((ntmdp = NEXTTMD(hmep, tmdp2)) == hmep->hme_tcurp)
			goto notmds;
		j = tmdp2 - hmep->hme_tmdp;

		HME_DEBUG_MSG5(hmep, SEVERITY_UNKNOWN, TX_MSG,
				"hmestart: 2 buf: len = %ld b_rptr = %p, "
				"len = %ld b_rptr = %p",
				len1, mp->b_rptr, len2, bp->b_rptr);
	} else {
		len1 = msgsize(mp);
		if ((bp = hmeallocb(len1, BPRI_HI)) == NULL) {
			hmep->hme_allocbfail++;
			goto bad;
		}

		mcopymsg(mp, bp->b_rptr);
		mp = bp;

		bp = NULL;
		len2 = 0;

		HME_DEBUG_MSG3(hmep, SEVERITY_NONE, TX_MSG,
			"hmestart: > 1 buf: len = %ld b_rptr = %p",
			len1, mp->b_rptr);
	}



	if (ddi_dma_alloc_handle(hmep->dip, &hme_dma_attr, DDI_DMA_DONTWAIT,
	    NULL, &hmep->hme_dmaxh[i])) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, TX_MSG,
		    "ddi_dma_alloc_handle failed");
		goto done;
	}

	if (ddi_dma_addr_bind_handle(hmep->hme_dmaxh[i], NULL,
	    (caddr_t)mp->b_rptr, len1, DDI_DMA_RDWR, DDI_DMA_DONTWAIT,
	    NULL, &c, &cnt) != DDI_DMA_MAPPED) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, TX_MSG,
				"ddi_dma_addr_bind_handle failed");
		ddi_dma_free_handle(&hmep->hme_dmaxh[i]);
		goto done;
	}

	/* apparently they don't handle multiple cookies */
	if (cnt > 1) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		    "dmaxh crossed page boundary - failed");
		(void) ddi_dma_unbind_handle(hmep->hme_dmaxh[i]);
		ddi_dma_free_handle(&hmep->hme_dmaxh[i]);
		goto done;
	}

	syncval = ddi_dma_sync(hmep->hme_dmaxh[i], (off_t)0, len1,
		DDI_DMA_SYNC_FORDEV);
	if (syncval == DDI_FAILURE)
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, DDI_MSG,
				"ddi_dma_sync failed");

	if (bp) {
		temp_addr = c.dmac_address;
		if (ddi_dma_alloc_handle(hmep->dip, &hme_dma_attr,
		    DDI_DMA_DONTWAIT, NULL, &hmep->hme_dmaxh[j])) {
			HME_FAULT_MSG1(hmep, SEVERITY_HIGH, TX_MSG,
			    "ddi_dma_alloc_handle failed");
			goto done;
		}

		if (ddi_dma_addr_bind_handle(hmep->hme_dmaxh[j], NULL,
		    (caddr_t)bp->b_rptr, len2, DDI_DMA_RDWR, DDI_DMA_DONTWAIT,
		    NULL, &c, &cnt) != DDI_DMA_MAPPED) {
			HME_FAULT_MSG1(hmep, SEVERITY_HIGH, TX_MSG,
					"ddi_dma_addr_bind_handle failed");
			ddi_dma_free_handle(&hmep->hme_dmaxh[j]);
			ddi_dma_free_handle(&hmep->hme_dmaxh[i]);
			goto done;
		}

		/* apparently they don't handle multiple cookies */
		if (cnt > 1) {
			HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
			    "dmaxh crossed page boundary - failed");
			(void) ddi_dma_unbind_handle(hmep->hme_dmaxh[i]);
			ddi_dma_free_handle(&hmep->hme_dmaxh[i]);
			(void) ddi_dma_unbind_handle(hmep->hme_dmaxh[j]);
			ddi_dma_free_handle(&hmep->hme_dmaxh[j]);
			goto done;
		}

		syncval = ddi_dma_sync(hmep->hme_dmaxh[j], (off_t)0, len2,
			DDI_DMA_SYNC_FORDEV);
		if (syncval == DDI_FAILURE)
			HME_FAULT_MSG1(hmep, SEVERITY_HIGH, DDI_MSG,
					"ddi_dma_sync failed");
	}

	if (bp) {
		PUT_TMD(tmdp2, c.dmac_address, len2, HMETMD_EOP);
		HMESYNCIOPB(hmep, tmdp2, sizeof (struct hme_tmd),
			DDI_DMA_SYNC_FORDEV);

		PUT_TMD(tmdp1, temp_addr, len1, HMETMD_SOP);
		HMESYNCIOPB(hmep, tmdp1, sizeof (struct hme_tmd),
			DDI_DMA_SYNC_FORDEV);
		mp->b_cont = NULL;
		hmep->hme_tmblkp[i] = mp;
		hmep->hme_tmblkp[j] = bp;
	} else {
		PUT_TMD(tmdp1, c.dmac_address, len1,
		    HMETMD_SOP | HMETMD_EOP);
		HMESYNCIOPB(hmep, tmdp1, sizeof (struct hme_tmd),
		    DDI_DMA_SYNC_FORDEV);
		hmep->hme_tmblkp[i] = mp;
	}
	CHECK_IOPB();

	hmep->hme_tnextp = ntmdp;
	PUT_ETXREG(txpend, HMET_TXPEND_TDMD);
	CHECK_ETXREG();

	mutex_exit(&hmep->hme_xmitlock);
	TRACE_1(TR_FAC_BE, TR_BE_START_END, "hmestart end:  wq %p #0798", wq);

	if (((hmep->promisc_phys_cnt + hmep->promisc_multi_cnt) != 0) && nmp) {
		hmesendup(hmep, nmp, hmepaccept);
	} else if ((!(hmep->promisc_phys_cnt + hmep->promisc_multi_cnt)) &&
	    nmp) {
		freemsg(nmp);
	}

	hmep->hme_starts++;
	return (0);

bad:
	mutex_exit(&hmep->hme_xmitlock);
	if (nmp)
		freemsg(nmp);
	freemsg(mp);
	return (1);

notmds:
	hmep->hme_notmds++;
	hmep->hme_wantw = 1;
	hmep->hme_tnextp = tmdp1;
	hmereclaim(hmep);
done:
	mutex_exit(&hmep->hme_xmitlock);
	if (nmp)
		freemsg(nmp);

	if (!putbq(wq, mp))
		freemsg(mp);

	TRACE_1(TR_FAC_BE, TR_BE_START_END, "hmestart end:  wq %p #0799", wq);
	return (1);
}

/*
 * Start transmission.
 * Return zero on success,
 * otherwise put msg on wq, set 'want' flag and return nonzero.
 */
static int
hmestart(queue_t *wq, mblk_t *mp, struct hme *hmep)
{
	volatile struct hme_tmd *tmdp1 = NULL;
	volatile struct hme_tmd *tmdp2 = NULL;
	volatile struct hme_tmd *ntmdp = NULL;
	mblk_t  *nmp = NULL;
	mblk_t  *bp;
	uint32_t len1, len2;
	uint32_t temp_addr;
	uint32_t i, j;
	ddi_dma_cookie_t c;
	struct ether_header *ehp;
	time_t	now;

	TRACE_1(TR_FAC_BE, TR_BE_START_START, "hmestart start:  wq %p", wq);

	/*
	 * update MIB II statistics
	 */
	ehp = (struct ether_header *)mp->b_rptr;
	BUMP_OutNUcast(hmep, ehp);

	if (hmep->hme_dvmaxh == NULL)
		return (hmestart_dma(wq, mp, hmep));

	if (!hmep->hme_linkup) {
		if ((hmep->hme_linkup_msg) &&
		    (((now = gethrestime_sec()) - hmep->hme_msg_time) > 10)) {
			ddi_dev_report_fault(hmep->dip, DDI_SERVICE_DEGRADED,
			    DDI_DEVICE_FAULT, link_down_msg);
			hmep->hme_msg_time = now;
		}
		freemsg(mp);
		return (0);
	}

	if ((hmep->promisc_phys_cnt + hmep->promisc_multi_cnt) != 0)
		if ((nmp = dupmsg(mp)) == NULL) {
			hmep->hme_allocbfail++;
			hmep->hme_noxmtbuf++;
		}

	mutex_enter(&hmep->hme_xmitlock);

	/*
	 * reclaim if there are more than HMETPENDING descriptors
	 * to be reclaimed.
	 */
	if (hmep->hme_tnextp > hmep->hme_tcurp) {
		if ((hmep->hme_tnextp - hmep->hme_tcurp) > HMETPENDING) {
			hmereclaim(hmep);
		}
	} else {
		i = hmep->hme_tcurp - hmep->hme_tnextp;
		if (i && (i < (HME_TMDMAX - HMETPENDING))) {
			hmereclaim(hmep);
		}
	}

	tmdp1 = hmep->hme_tnextp;
	if ((ntmdp = NEXTTMD(hmep, tmdp1)) == hmep->hme_tcurp)
		goto notmds;

	i = tmdp1 - hmep->hme_tmdp;

	/*
	 * here we deal with 3 cases.
	 *	1. pkt has exactly one mblk
	 *	2. pkt has exactly two mblks
	 *	3. pkt has more than 2 mblks. Since this almost
	 *		always never happens, we copy all of them
	 *		into a msh with one mblk.
	 * for each mblk in the message, we allocate a tmd and
	 * figure out the tmd index. This index also passed to
	 * dvma_kaddr_load(), which establishes the IO mapping
	 * for the mblk data. This index is used as a index into
	 * the ptes reserved by dvma_reserve
	 */

	bp = mp->b_cont;

	len1 = mp->b_wptr - mp->b_rptr;
	if (bp == NULL) {
		(void) dvma_kaddr_load(hmep->hme_dvmaxh, (caddr_t)mp->b_rptr,
			len1, 2 * i, &c);
		(void) dvma_sync(hmep->hme_dvmaxh, 2 * i, DDI_DMA_SYNC_FORDEV);

		PUT_TMD(tmdp1, c.dmac_address, len1, HMETMD_SOP | HMETMD_EOP);

		HMESYNCIOPB(hmep, tmdp1, sizeof (struct hme_tmd),
			DDI_DMA_SYNC_FORDEV);
		hmep->hme_tmblkp[i] = mp;

	} else {

	if ((bp->b_cont == NULL) &&
		((len2 = bp->b_wptr - bp->b_rptr) >= 4)) {
	/*
	 * Check with HW: The minimum len restriction different
	 * for 64-bit burst ?
	 */
		tmdp2 = ntmdp;
		if ((ntmdp = NEXTTMD(hmep, tmdp2)) == hmep->hme_tcurp)
			goto notmds;
		j = tmdp2 - hmep->hme_tmdp;
		mp->b_cont = NULL;
		hmep->hme_tmblkp[i] = mp;
		hmep->hme_tmblkp[j] = bp;
		(void) dvma_kaddr_load(hmep->hme_dvmaxh, (caddr_t)mp->b_rptr,
			len1, 2 * i, &c);
		(void) dvma_sync(hmep->hme_dvmaxh, 2 * i, DDI_DMA_SYNC_FORDEV);

		temp_addr = c.dmac_address;
		(void) dvma_kaddr_load(hmep->hme_dvmaxh, (caddr_t)bp->b_rptr,
			len2, 2 * j, &c);
		(void) dvma_sync(hmep->hme_dvmaxh, 2 * j, DDI_DMA_SYNC_FORDEV);

		PUT_TMD(tmdp2, c.dmac_address, len2, HMETMD_EOP);

		HMESYNCIOPB(hmep, tmdp2, sizeof (struct hme_tmd),
			DDI_DMA_SYNC_FORDEV);

		PUT_TMD(tmdp1, temp_addr, len1, HMETMD_SOP);

		HMESYNCIOPB(hmep, tmdp1, sizeof (struct hme_tmd),
			DDI_DMA_SYNC_FORDEV);

	} else {
		len1 = msgsize(mp);

		if ((bp = hmeallocb(len1, BPRI_HI)) == NULL) {
			hmep->hme_allocbfail++;
			hmep->hme_noxmtbuf++;
			goto bad;
		}

		mcopymsg(mp, bp->b_rptr);
		mp = bp;
		hmep->hme_tmblkp[i] = mp;

		(void) dvma_kaddr_load(hmep->hme_dvmaxh,
			(caddr_t)mp->b_rptr, len1, 2 * i, &c);
		(void) dvma_sync(hmep->hme_dvmaxh, 2 * i,
			DDI_DMA_SYNC_FORDEV);
		PUT_TMD(tmdp1, c.dmac_address, len1,
			HMETMD_SOP | HMETMD_EOP);
		HMESYNCIOPB(hmep, tmdp1, sizeof (struct hme_tmd),
			DDI_DMA_SYNC_FORDEV);
		}
	}
	CHECK_IOPB();

	hmep->hme_tnextp = ntmdp;
	PUT_ETXREG(txpend, HMET_TXPEND_TDMD);
	CHECK_ETXREG();

	HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, TX_MSG,
			"hmestart:  Transmitted a frame");

	mutex_exit(&hmep->hme_xmitlock);
	TRACE_1(TR_FAC_BE, TR_BE_START_END, "hmestart end:  wq %p", wq);

	if ((hmep->promisc_phys_cnt + hmep->promisc_multi_cnt) && nmp) {
		hmesendup(hmep, nmp, hmepaccept);
	} else if ((!(hmep->promisc_phys_cnt + hmep->promisc_multi_cnt)) &&
	    nmp) {
		freemsg(nmp);
	}

	hmep->hme_starts++;
	return (0);
bad:
	mutex_exit(&hmep->hme_xmitlock);
	if (nmp)
		freemsg(nmp);
	freemsg(mp);
	return (1);
notmds:
	hmep->hme_notmds++;
	hmep->hme_wantw = 1;
	hmep->hme_tnextp = tmdp1;
	hmereclaim(hmep);
done:
	mutex_exit(&hmep->hme_xmitlock);
	if (nmp)
		freemsg(nmp);
	if (!putbq(wq, mp))
		freemsg(mp);

	TRACE_1(TR_FAC_BE, TR_BE_START_END, "hmestart end:  wq %p", wq);
	return (1);
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
	struct	hmestr	*sbp;
	mblk_t		*bp;
	uint16_t	ladrf[4];
	uint32_t	i;
	int		ret;
	int		alloc_ret;	/* hmeallocthings() return value   */
	ddi_dma_cookie_t dma_cookie;
	uint_t dmac_cnt;

	TRACE_1(TR_FAC_BE, TR_BE_INIT_START,
		"hmeinit start:  hmep %p #0805", hmep);

	while (hmep->hme_flags & HMESUSPENDED)
		(void) ddi_dev_is_needed(hmep->dip, 0, 1);

	HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, ENTER_MSG, "init:  Entered");

	/*
	 * This should prevent us from clearing any interrupts that may occur by
	 * temporarily stopping interrupts from occurring for a short time.
	 * We need to update the interrupt mask later in this function.
	 */
	PUT_GLOBREG(intmask, ~HMEG_MASK_MIF_INTR);

	/*
	 * Lock sequence:
	 *	hme_intrlock, hmestruplock and hme_xmitlock.
	 */

	mutex_enter(&hmep->hme_intrlock);
	rw_enter(&hmestruplock, RW_WRITER);

	/*
	 * Rearranged the mutex acquisition order to solve the deadlock
	 * situation as described in bug ID 4065896.
	 */

	hme_stop_timer(hmep);	/* acquire hme_linklock */
	mutex_enter(&hmep->hme_xmitlock);

	hmep->hme_flags = 0;
	hmep->hme_wantw = 0;
	hmep->hme_txhung = 0;

	/*
	 * Initializing 'hmep->hme_iipackets' to match current
	 * number of received packets.
	 */
	hmep->hme_iipackets = hmep->hme_ipackets;

	if (hmep->inits)
		hmesavecntrs(hmep);

	hme_stop_mifpoll(hmep);

	/*
	 * Perform Global reset of the Sbus/FEPS ENET channel.
	 */
	(void) hmestop(hmep);

	/*
	 * Allocate data structures.
	 */
	alloc_ret = hmeallocthings(hmep);
	if (alloc_ret) {
		/*
		 * Failed
		 */
		hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);
		goto init_fail;
	}

	hmefreebufs(hmep);

	/*
	 * Clear all descriptors.
	 */
	bzero(hmep->hme_rmdp, HME_RMDMAX * sizeof (struct hme_rmd));
	bzero(hmep->hme_tmdp, HME_TMDMAX * sizeof (struct hme_tmd));

	/*
	 * Hang out receive buffers.
	 */
	for (i = 0; i < HMERPENDING; i++) {
		if ((bp = hmeallocb(HMEBUFSIZE, BPRI_LO)) == NULL) {
			HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, INIT_MSG,
					"allocb failed");
			hme_start_timer(hmep, hme_check_link,
					HME_LINKCHECK_TIMER);
			goto init_fail;
		}

		/*
		 * dvma case
		 */
		if (hmep->hme_dvmarh) {
			(void) dvma_kaddr_load(hmep->hme_dvmarh,
				(caddr_t)bp->b_rptr,
				(uint_t)HMEBUFSIZE,
				2 * i, &dma_cookie);
		} else {
		/*
		 * dma case
		 */
			if (ddi_dma_alloc_handle(hmep->dip, &hme_dma_attr,
			    DDI_DMA_DONTWAIT, NULL, &hmep->hme_dmarh[i])
			    != DDI_SUCCESS) {
				HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
				"ddi_dma_alloc_handle of bufs failed");
				hme_start_timer(hmep, hme_check_link,
					HME_LINKCHECK_TIMER);
				goto init_fail;
			}

			if (ddi_dma_addr_bind_handle(hmep->hme_dmarh[i], NULL,
			    (caddr_t)bp->b_rptr, HMEBUFSIZE, DDI_DMA_RDWR,
			    DDI_DMA_DONTWAIT, NULL, &dma_cookie, &dmac_cnt)
			    != DDI_DMA_MAPPED) {
				HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
				"ddi_dma_addr_bind_handle of bufs failed");
				hme_start_timer(hmep, hme_check_link,
					HME_LINKCHECK_TIMER);
				goto init_fail;
			}
			/* apparently they don't handle multiple cookies */
			if (dmac_cnt > 1) {
				HME_DEBUG_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
				    "dmarh crossed page boundary - failed");
				hme_start_timer(hmep, hme_check_link,
					HME_LINKCHECK_TIMER);
				goto init_fail;
			}
		}
		PUT_RMD((&hmep->hme_rmdp[i]), dma_cookie.dmac_address);

		hmep->hme_rmblkp[i] = bp;	/* save for later use */
	}

	/*
	 * DMA sync descriptors.
	 */
	HMESYNCIOPB(hmep, hmep->hme_rmdp, (HME_RMDMAX * sizeof (struct hme_rmd)
		+ HME_TMDMAX * sizeof (struct hme_tmd)), DDI_DMA_SYNC_FORDEV);
	CHECK_IOPB();

	/*
	 * Reset RMD and TMD 'walking' pointers.
	 */
	hmep->hme_rnextp = hmep->hme_rmdp;
	hmep->hme_rlastp = hmep->hme_rmdp + HMERPENDING - 1;
	hmep->hme_tcurp = hmep->hme_tmdp;
	hmep->hme_tnextp = hmep->hme_tmdp;

	/*
	 * Determine if promiscuous mode.
	 */
	for (sbp = hmestrup; sbp; sbp = sbp->sb_nextp) {
		if ((sbp->sb_hmep == hmep) && (sbp->sb_flags & HMESALLPHYS)) {
			hmep->hme_flags |= HMEPROMISC;
			break;
		}
	}


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

	hme_check_transceiver(hmep);
	if (hmep->hme_transceiver == HME_NO_TRANSCEIVER) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, XCVR_MSG, no_xcvr_msg);
		hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);
		goto init_fail;	/* abort initialization */

	} else if (hmep->hme_transceiver == HME_INTERNAL_TRANSCEIVER)
		PUT_MACREG(xifc, 0);
	else
		PUT_MACREG(xifc, BMAC_XIFC_MIIBUFDIS);
				/* Isolate the Int. xcvr */
	/*
	 * Perform transceiver reset and speed selection only if
	 * the link is down.
	 */
	if (!hmep->hme_linkcheck)
		/*
		 * Reset the PHY and bring up the link
		 * If it fails we will then increment a kstat.
		 */
		hme_reset_transceiver(hmep);
	else {
		if (hmep->hme_linkup)
			hme_start_mifpoll(hmep);
		hme_start_timer(hmep, hme_check_link, HME_LINKCHECK_TIMER);
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

	PUT_MACREG(ipg1, hme_param_ipg1);
	PUT_MACREG(ipg2, hme_param_ipg2);

	HME_DEBUG_MSG3(hmep, SEVERITY_UNKNOWN, IPG_MSG,
			"hmeinit: ipg1 = %d ipg2 = %d", hme_param_ipg1,
			hme_param_ipg2);
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
	bzero(ladrf, 4 * sizeof (uint16_t));

	/*
	 * Here we initialize the MC Hash bits
	 */
	for (sbp = hmestrup; sbp; sbp = sbp->sb_nextp) {
		if (sbp->sb_hmep == hmep) {
			if (sbp->sb_flags & HMESALLMULTI) {
				for (i = 0; i < 4; i++) {
					ladrf[i] = 0xffff;
				}
				break;	/* All bits are already on */
			}
			for (i = 0; i < 4; i++)
				ladrf[i] |= sbp->sb_ladrf[i];
		}
	}

	PUT_MACREG(hash0, ladrf[0]);
	PUT_MACREG(hash1, ladrf[1]);
	PUT_MACREG(hash2, ladrf[2]);
	PUT_MACREG(hash3, ladrf[3]);

	/*
	 * Set up the address filter now?
	 */

	/*
	 * Initialize HME Global registers, ETX registers and ERX registers.
	 */

	PUT_ETXREG(txring, (uint32_t)HMEIOPBIOADDR(hmep, hmep->hme_tmdp));
	PUT_ERXREG(rxring, (uint32_t)HMEIOPBIOADDR(hmep, hmep->hme_rmdp));

	/*
	 * ERX registers can be written only if they have even no. of bits set.
	 * So, if the value written is not read back, set the lsb and write
	 * again.
	 * static	int	hme_erx_fix = 1;   : Use the fix for erx bug
	 */
	{
		uint32_t temp;
		temp  = ((uint32_t)HMEIOPBIOADDR(hmep, hmep->hme_rmdp));

		if (GET_ERXREG(rxring) != temp)
			PUT_ERXREG(rxring, (temp | 4));
	}

	HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, ERX_MSG,
			"rxring written = %X",
			((uint32_t)HMEIOPBIOADDR(hmep, hmep->hme_rmdp)));
	HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, ERX_MSG,
			"rxring read = %X",
			GET_ERXREG(rxring));

	PUT_GLOBREG(config,
	(hmep->hme_config | (hmep->hme_64bit_xfer << HMEG_CONFIG_64BIT_SHIFT)));

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
	PUT_ERXREG(config, i);

	HME_DEBUG_MSG2(hmep, SEVERITY_UNKNOWN, INIT_MSG,
			"erxp->config = %X", GET_ERXREG(config));
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
			((hmep->hme_flags & HMEPROMISC ? BMAC_RXCFG_PROMIS : 0)\
				| BMAC_RXCFG_MYOWN | BMAC_RXCFG_HASH));
	} else {
		PUT_MACREG(rxcfg,
			((hmep->hme_flags & HMEPROMISC ? BMAC_RXCFG_PROMIS : 0)\
				| BMAC_RXCFG_HASH));
	}

	drv_usecwait(10);	/* wait after setting Hash Enable bit */

	if (hme_ngu_enable)
		PUT_MACREG(txcfg, (hmep->hme_fdx ? BMAC_TXCFG_FDX: 0) |
								BMAC_TXCFG_NGU);
	else
		PUT_MACREG(txcfg, (hmep->hme_fdx ? BMAC_TXCFG_FDX: 0));
	hmep->hme_macfdx = hmep->hme_fdx;


	i = 0;
	if ((hme_param_lance_mode) && (hmep->hme_lance_mode_enable))
		i = ((hme_param_ipg0 & HME_MASK_5BIT) << BMAC_XIFC_IPG0_SHIFT)
					| BMAC_XIFC_LANCE_ENAB;
	if (hmep->hme_transceiver == HME_INTERNAL_TRANSCEIVER)
		PUT_MACREG(xifc, i | (BMAC_XIFC_ENAB));
	else
		PUT_MACREG(xifc, i | (BMAC_XIFC_ENAB | BMAC_XIFC_MIIBUFDIS));

	PUT_MACREG(rxcfg, GET_MACREG(rxcfg) | BMAC_RXCFG_ENAB);
	PUT_MACREG(txcfg, GET_MACREG(txcfg) | BMAC_TXCFG_ENAB);

	hmep->hme_flags |= (HMERUNNING | HMEINITIALIZED);
	/*
	 * Update the interrupt mask : this will re-allow interrupts to occur
	 */
	PUT_GLOBREG(intmask, hmep->intr_mask);
	hmewenable(hmep);

init_fail:
	/*
	 * Release the locks in reverse order
	 */
	mutex_exit(&hmep->hme_xmitlock);
	rw_exit(&hmestruplock);
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
 * NOTE: Do not use ddi_dma_alloc_handle(9f) then ddi_dma_burstsize(9f),
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

	HME_DEBUG_MSG2(hmep, SEVERITY_NONE, INIT_MSG,
			"hme_config = 0x%X", hmep->hme_config);
	return (DDI_SUCCESS);
}

static void
hmefreebufs(struct hme *hmep)
{
	int i;
	int32_t	freeval;

	/*
	 * Free and dvma_unload pending xmit and recv buffers.
	 * Maintaining the 1-to-1 ordered sequence of
	 * Always unload anything before loading it again.
	 * Never unload anything twice.  Always unload
	 * before freeing the buffer.  We satisfy these
	 * requirements by unloading only those descriptors
	 * which currently have an mblk associated with them.
	 */
	/*
	 * Keep the ddi_dma_free() before the freeb()
	 * with the dma handles.
	 * Race condition with snoop.
	 */
	if (hmep->hme_dmarh) {
		/* dma case */
		for (i = 0; i < HME_TMDMAX; i++) {
			if (hmep->hme_dmaxh[i]) {
				freeval = ddi_dma_unbind_handle(
				    hmep->hme_dmaxh[i]);
				if (freeval == DDI_FAILURE)
					HME_FAULT_MSG1(hmep, SEVERITY_HIGH,
							FREE_MSG,
							"ddi_dma_unbind_handle"
							" failed");
				ddi_dma_free_handle(&hmep->hme_dmaxh[i]);
				hmep->hme_dmaxh[i] = NULL;
			}
		}
		for (i = 0; i < HMERPENDING; i++) {
			if (hmep->hme_dmarh[i]) {
				freeval = ddi_dma_unbind_handle(
				    hmep->hme_dmarh[i]);
				if (freeval == DDI_FAILURE)
					HME_FAULT_MSG1(hmep, SEVERITY_HIGH,
							FREE_MSG,
							"ddi_dma_unbind_handle"
							" failure");
				ddi_dma_free_handle(&hmep->hme_dmarh[i]);
				hmep->hme_dmarh[i] = NULL;
			}
		}
	}
	/*
	 * This was generated when only a dma handle is expected.
	 * else HME_FAULT_MSG1(NULL, SEVERITY_HIGH, FREE_MSG,
	 *		"hme: Expected a dma read handle:failed");
	 */

	for (i = 0; i < HME_TMDMAX; i++) {
		if (hmep->hme_tmblkp[i]) {
			if (hmep->hme_dvmaxh)
				dvma_unload(hmep->hme_dvmaxh,
						2 * i, DONT_FLUSH);
			freeb(hmep->hme_tmblkp[i]);
			hmep->hme_tmblkp[i] = NULL;
		}
	}

	for (i = 0; i < HME_RMDMAX; i++) {
		if (hmep->hme_rmblkp[i]) {
			if (hmep->hme_dvmarh)
				dvma_unload(hmep->hme_dvmarh, 2 * HMERINDEX(i),
						DDI_DMA_SYNC_FORKERNEL);
			freeb(hmep->hme_rmblkp[i]);
			hmep->hme_rmblkp[i] = NULL;
		}
	}

}

/*
 * hme_start_mifpoll() - Enables the polling of the BMSR register of the PHY.
 * After enabling the poll, delay for atleast 62us for one poll to be done.
 * Then read the MIF status register to auto-clear the MIF status field.
 * Then program the MIF interrupt mask register to enable interrupts for the
 * LINK_STATUS and JABBER_DETECT bits.
 */

static void
hme_start_mifpoll(struct hme *hmep)
{
	uint32_t cfg;

	if (!hmep->hme_mifpoll_enable)
		return;

	cfg = (GET_MIFREG(mif_cfg) & ~(HME_MIF_CFGPD | HME_MIF_CFGPR));
	PUT_MIFREG(mif_cfg,
		(cfg = (cfg | (hmep->hme_phyad << HME_MIF_CFGPD_SHIFT) |
		(HME_PHY_BMSR << HME_MIF_CFGPR_SHIFT) | HME_MIF_CFGPE)));

	drv_usecwait(HME_MIF_POLL_DELAY);
	hmep->hme_polling_on =		1;
	hmep->hme_mifpoll_flag =	0;
	hmep->hme_mifpoll_data =	(GET_MIFREG(mif_bsts) >> 16);

	/* Do not poll for Jabber Detect for 100 Mbps speed */
	if (((hmep->hme_mode == HME_AUTO_SPEED) &&
		(hmep->hme_tryspeed == HME_SPEED_100)) ||
		((hmep->hme_mode == HME_FORCE_SPEED) &&
		(hmep->hme_forcespeed == HME_SPEED_100)))
		PUT_MIFREG(mif_imask, ((uint16_t)~(PHY_BMSR_LNKSTS)));
	else
		PUT_MIFREG(mif_imask,
			(uint16_t)~(PHY_BMSR_LNKSTS | PHY_BMSR_JABDET));

	CHECK_MIFREG();
	HME_DEBUG_MSG3(hmep, SEVERITY_UNKNOWN, MIFPOLL_MSG,
		"mifpoll started: mif_cfg = %X mif_bsts = %X",
		cfg, GET_MIFREG(mif_bsts));
}

static void
hme_stop_mifpoll(struct hme *hmep)
{
	if ((!hmep->hme_mifpoll_enable) || (!hmep->hme_polling_on))
		return;

	PUT_MIFREG(mif_imask, 0xffff);	/* mask interrupts */
	PUT_MIFREG(mif_cfg, (GET_MIFREG(mif_cfg) & ~HME_MIF_CFGPE));

	hmep->hme_polling_on = 0;
	drv_usecwait(HME_MIF_POLL_DELAY);
	CHECK_MIFREG();
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
	HMEDELAY((hmep->hme_tcurp == hmep->hme_tnextp), HMEDRAINTIME);

	hme_stop_timer(hmep);   /* acquire hme_linklock */
	mutex_exit(&hmep->hme_linklock);

	mutex_enter(&hmep->hme_intrlock);
	mutex_enter(&hmep->hme_xmitlock);

	hme_stop_mifpoll(hmep);

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
	uintptr_t a;
	int		size;
	int		rval;
	size_t		real_len;
	uint_t		cookiec;

	/*
	 * Return if resources are already allocated.
	 */
	if (hmep->hme_rmdp)
		return (0);

	/*
	 * Allocate the TMD and RMD descriptors and extra for page alignment.
	 */
	size = (HME_RMDMAX * sizeof (struct hme_rmd)
		+ HME_TMDMAX * sizeof (struct hme_tmd));
	size = ROUNDUP(size, hmep->pagesize) + hmep->pagesize;

	rval = ddi_dma_alloc_handle(hmep->dip, &hme_dma_attr,
			DDI_DMA_DONTWAIT, 0, &hmep->hme_md_h);
	if (rval != DDI_SUCCESS) {
	    HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		"cannot allocate rmd handle - failed");
	    return (1);
	}

	rval = ddi_dma_mem_alloc(hmep->hme_md_h, size, &hmep->hme_dev_attr,
			DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, 0,
			(caddr_t *)&hmep->hme_iopbkbase, &real_len,
			&hmep->hme_mdm_h);
	if (rval != DDI_SUCCESS) {
	    HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		"cannot allocate trmd dma mem - failed");
	    ddi_dma_free_handle(&hmep->hme_md_h);
	    return (1);
	}

	hmep->hme_iopbkbase = ROUNDUP(hmep->hme_iopbkbase, hmep->pagesize);
	size = (HME_RMDMAX * sizeof (struct hme_rmd)
		+ HME_TMDMAX * sizeof (struct hme_tmd));

	rval = ddi_dma_addr_bind_handle(hmep->hme_md_h, NULL,
			(caddr_t)hmep->hme_iopbkbase, size,
			DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
			DDI_DMA_DONTWAIT, 0,
			&hmep->hme_md_c, &cookiec);
	if (rval != DDI_DMA_MAPPED) {
	    HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		"cannot allocate trmd dma - failed");
	    ddi_dma_mem_free(&hmep->hme_mdm_h);
	    ddi_dma_free_handle(&hmep->hme_md_h);
	    return (1);
	}

	if (cookiec != 1) {
	    HME_FAULT_MSG1(hmep, SEVERITY_HIGH, INIT_MSG,
		"trmds crossed page boundary - failed");
	    if (ddi_dma_unbind_handle(hmep->hme_md_h) == DDI_FAILURE)
		return (2);
	    ddi_dma_mem_free(&hmep->hme_mdm_h);
	    ddi_dma_free_handle(&hmep->hme_md_h);
	    return (1);
	}

	hmep->hme_iopbiobase = hmep->hme_md_c.dmac_address;

	a = hmep->hme_iopbkbase;
	a = ROUNDUP(a, HME_HMDALIGN);
	hmep->hme_rmdp = (struct hme_rmd *)a;
	a += HME_RMDMAX * sizeof (struct hme_rmd);
	hmep->hme_tmdp = (struct hme_tmd *)a;
	/*
	 * dvma_reserve() reserves DVMA space for private man
	 * device driver.
	 */
	if ((dvma_reserve(hmep->dip, &hme_dma_limits, (HME_TMDMAX * 2),
		&hmep->hme_dvmaxh)) != DDI_SUCCESS) {
	/*
	 * Specifically we reserve n (HME_TMDMAX + HME_RMDMAX)
	 * pagetable entries. Therefore we have 2 ptes for each
	 * descriptor. Since the ethernet buffers are 1518 bytes
	 * so they can at most use 2 ptes.
	 * Will do a ddi_dma_addr_setup for each bufer
	 */
		/*
		 * We will now do a dma, due to the fact that
		 * dvma_reserve failied.
		 */
		hmep->hme_dmaxh = (ddi_dma_handle_t *)
		    kmem_zalloc(((HME_TMDMAX +  HMERPENDING) *
			(sizeof (ddi_dma_handle_t))), KM_SLEEP);
			hmep->hme_dmarh = hmep->hme_dmaxh + HME_TMDMAX;
			hmep->hme_dvmaxh = hmep->hme_dvmarh = NULL;
			hmep->dmaxh_init++;
			hmep->dmarh_init++;

	} else {
		/*
		 * Reserve dvma space for the receive side. If
		 * this call fails, we have to release the resources
		 * and fall back to the dma case.
		 */
		if ((dvma_reserve(hmep->dip, &hme_dma_limits,
		    (HMERPENDING * 2), &hmep->hme_dvmarh)) != DDI_SUCCESS) {
			(void) dvma_release(hmep->hme_dvmaxh);

			hmep->hme_dmaxh = (ddi_dma_handle_t *)
			kmem_zalloc(((HME_TMDMAX +  HMERPENDING) *
			(sizeof (ddi_dma_handle_t))), KM_SLEEP);
			hmep->hme_dmarh = hmep->hme_dmaxh + HME_TMDMAX;
			hmep->hme_dvmaxh = hmep->hme_dvmarh = NULL;
			hmep->dmaxh_init++;
			hmep->dmarh_init++;
		}
	}

	/*
	 * Keep handy limit values for RMD, TMD, and Buffers.
	 */
	hmep->hme_rmdlimp = &((hmep->hme_rmdp)[HME_RMDMAX]);
	hmep->hme_tmdlimp = &((hmep->hme_tmdp)[HME_TMDMAX]);

	/*
	 * Zero out xmit and rcv holders.
	 */
	bzero(hmep->hme_tmblkp, sizeof (hmep->hme_tmblkp));
	bzero(hmep->hme_rmblkp, sizeof (hmep->hme_rmblkp));

	return (0);
}


/*
 *	First check to see if it our device interrupting.
 */
static uint_t
hmeintr(struct hme *hmep)
{
	uint32_t	hmesbits;
	uint32_t	mif_status;
	uint32_t	dummy_read;
	uint32_t	serviced = DDI_INTR_UNCLAIMED;
	uint32_t	num_reads = 0;



	mutex_enter(&hmep->hme_intrlock);

	/*
	 * The status register auto-clears on read except for
	 * MIF Interrupt bit
	 */
	hmesbits = GET_GLOBREG(status);
	CHECK_GLOBREG();

	TRACE_1(TR_FAC_BE, TR_BE_INTR_START, "hmeintr start:  hmep %p", hmep);

	HME_DEBUG_MSG3(hmep, SEVERITY_NONE, INTR_MSG,
			"hmeintr: start:  hmep %X status = %X", hmep, hmesbits);
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
		TRACE_2(TR_FAC_BE, TR_BE_INTR_END,
		"hmeintr end: hmep %p serviced %d", hmep, serviced);
		return (serviced);
	}

	serviced = DDI_INTR_CLAIMED;

	if (!(hmep->hme_flags & HMERUNNING)) {
		if (hmep->hme_intrstats)
			KIOIP->intrs[KSTAT_INTR_HARD]++;
		mutex_exit(&hmep->hme_intrlock);
		hmeuninit(hmep);
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN,  INTR_MSG,
				"hmeintr: hme not running");
		return (serviced);
	}

	if (hmesbits & (HMEG_STATUS_FATAL_ERR | HMEG_STATUS_NONFATAL_ERR)) {
		if (hmesbits & HMEG_STATUS_FATAL_ERR) {

			HME_DEBUG_MSG2(hmep, SEVERITY_MID, INTR_MSG,
				"hmeintr: fatal error:hmesbits = %X", hmesbits);
			if (hmep->hme_intrstats)
				KIOIP->intrs[KSTAT_INTR_HARD]++;
			hme_fatal_err(hmep, hmesbits);

			HME_DEBUG_MSG2(hmep, SEVERITY_MID, INTR_MSG,
				"fatal %x: re-init MAC", hmesbits);

			mutex_exit(&hmep->hme_intrlock);
			hme_reinit_fatal++;
			(void) hmeinit(hmep);
			return (serviced);
		}
		HME_DEBUG_MSG2(hmep, SEVERITY_MID, INTR_MSG,
			"hmeintr: non-fatal error:hmesbits = %X", hmesbits);
		hme_nonfatal_err(hmep, hmesbits);
	}

	if (hmesbits & HMEG_STATUS_MIF_INTR) {
		mif_status = (GET_MIFREG(mif_bsts) >> 16);
		if (!(mif_status & PHY_BMSR_LNKSTS)) {

			HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, INTR_MSG,
				"hmeintr: mif interrupt: Link Down");

			if (hmep->hme_intrstats)
				KIOIP->intrs[KSTAT_INTR_HARD]++;

			hmep->hme_link_up = 0;
			hme_stop_mifpoll(hmep);
			hmep->hme_linkup_msg = 1;
			hmep->hme_mifpoll_flag = 1;
			mutex_exit(&hmep->hme_intrlock);
			hme_stop_timer(hmep);
			hme_start_timer(hmep, hme_check_link, MSECOND(1));
			return (serviced);
		}
		/*
		 *
		 * BugId 1261889 EscId 50699 ftp hangs @ 10 Mbps
		 *
		 * Here could be one cause:
		 * national PHY sees jabber, goes into "Jabber function",
		 * (see section 3.7.6 in PHY specs.), disables transmitter,
		 * and waits for internal transmit enable to be de-asserted
		 * for at least 750ms (the "unjab" time).  Also, the PHY
		 * has asserted COL, the collision detect signal.
		 *
		 * In the meantime, the Sbus/FEPS, in never-give-up mode,
		 * continually retries, backs off 16 times as per spec,
		 * and restarts the transmission, so TX_EN is never
		 * deasserted long enough, in particular TX_EN is turned
		 * on approximately once every 4 microseconds on the
		 * average.  PHY and MAC are deadlocked.
		 *
		 * Here is part of the fix:
		 * On seeing the jabber, treat it like a hme_fatal_err
		 * and reset both the Sbus/FEPS and the PHY.
		 */

		if (mif_status & (PHY_BMSR_JABDET)) {

			HME_DEBUG_MSG1(hmep, SEVERITY_LOW, INTR_MSG,
					"jabber detected");

			/* national phy only defines this at 10 Mbps */
			if (hme_param_speed == 0) { /* 10 Mbps speed ? */
				hmep->hme_jab++;

				HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, INTR_MSG,
				"hmeintr: mif interrupt: Jabber detected");

				/* treat jabber like a fatal error */
				hmep->hme_linkcheck = 0; /* force PHY reset */
				mutex_exit(&hmep->hme_intrlock);
				hme_reinit_jabber++;
				(void) hmeinit(hmep);

				HME_DEBUG_MSG1(hmep, SEVERITY_LOW, INTR_MSG,
						"jabber: re-init PHY & MAC");
				return (serviced);
			}
		}
		hme_start_mifpoll(hmep);
	}

	if (hmesbits & (HMEG_STATUS_TX_ALL | HMEG_STATUS_TINT)) {
		mutex_enter(&hmep->hme_xmitlock);

		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, TX_MSG,
				"hmeintr: packet transmitted");
		hmereclaim(hmep);
		mutex_exit(&hmep->hme_xmitlock);
	}

	if (hmesbits & HMEG_STATUS_RINT) {
		volatile struct	hme_rmd	*rmdp;

		/*
		 * This dummy PIO is required to flush the SBus
		 * Bridge buffers in QFE.
		 */
		dummy_read = GET_GLOBREG(config);
#ifdef	lint
		dummy_read = dummy_read;
#endif

		rmdp = hmep->hme_rnextp;

		HME_DEBUG_MSG2(hmep, SEVERITY_NONE, INTR_MSG,
				"hmeintr: packet received: rmdp = %X", rmdp);

		/*
		 * Sync RMD before looking at it.
		 */
		HMESYNCIOPB(hmep, rmdp, sizeof (struct hme_rmd),
			DDI_DMA_SYNC_FORCPU);

		/*
		 * Loop through each RMD.
		 */
		while (((GET_RMD_FLAGS(rmdp) & HMERMD_OWN) == 0) &&
			(num_reads++ < HMERPENDING)) {
			hmeread(hmep, rmdp);
			/*
			 * Increment to next RMD.
			 */
			hmep->hme_rnextp = rmdp = NEXTRMD(hmep, rmdp);

			/*
			 * Sync the next RMD before looking at it.
			 */
			HMESYNCIOPB(hmep, rmdp, sizeof (struct hme_rmd),
				DDI_DMA_SYNC_FORCPU);
		}
		CHECK_IOPB();
	}

	if (hmep->hme_intrstats)
		KIOIP->intrs[KSTAT_INTR_HARD]++;

	mutex_exit(&hmep->hme_intrlock);
	TRACE_2(TR_FAC_BE, TR_BE_INTR_END,
	    "hmeintr end:  hmep %p serviced %d", hmep, serviced);
	return (serviced);
}

/*
 * Transmit completion reclaiming.
 */
static void
hmereclaim(struct hme *hmep)
{
	volatile struct	hme_tmd	*tmdp;
	int	i;
	int32_t	freeval;
	int			nbytes;

	tmdp = hmep->hme_tcurp;

	/*
	 * Sync TMDs before looking at them.
	 */
	if (hmep->hme_tnextp > hmep->hme_tcurp) {
		nbytes = ((hmep->hme_tnextp - hmep->hme_tcurp)
				* sizeof (struct hme_tmd));
		HMESYNCIOPB(hmep, tmdp, nbytes, DDI_DMA_SYNC_FORCPU);
	} else {
		nbytes = ((hmep->hme_tmdlimp - hmep->hme_tcurp)
				* sizeof (struct hme_tmd));
		HMESYNCIOPB(hmep, tmdp, nbytes, DDI_DMA_SYNC_FORCPU);
		nbytes = ((hmep->hme_tnextp - hmep->hme_tmdp)
				* sizeof (struct hme_tmd));
		HMESYNCIOPB(hmep, hmep->hme_tmdp, nbytes, DDI_DMA_SYNC_FORCPU);
	}
	CHECK_IOPB();

	/*
	 * Loop through each TMD.
	 */
	while ((GET_TMD_FLAGS(tmdp) & (HMETMD_OWN)) == 0 &&
		(tmdp != hmep->hme_tnextp)) {

		/*
		 * count a chained packet only once.
		 */
		if (GET_TMD_FLAGS(tmdp) & (HMETMD_SOP)) {
			hmep->hme_opackets++;
			hmep->hme_opackets64++;
		}

		/*
		 * MIB II
		 */
		hmep->hme_xmtbytes += GET_TMD_FLAGS(tmdp) & HMETMD_BUFSIZE;
		hmep->hme_obytes64 += GET_TMD_FLAGS(tmdp) & HMETMD_BUFSIZE;

		i = tmdp - hmep->hme_tmdp;

		HME_DEBUG_MSG3(hmep, SEVERITY_UNKNOWN, TX_MSG,
			"reclaim: tmdp = %X index = %d", tmdp, i);
		/*
		 * dvma handle case.
		 */
		if (hmep->hme_dvmaxh)
			(void) dvma_unload(hmep->hme_dvmaxh, 2 * i,
						(uint_t)DONT_FLUSH);
		/*
		 * dma handle case.
		 */
		else if (hmep->hme_dmaxh) {
			CHECK_DMA(hmep->hme_dmaxh[i]);
			freeval = ddi_dma_unbind_handle(hmep->hme_dmaxh[i]);
			if (freeval == DDI_FAILURE)
				HME_FAULT_MSG1(hmep, SEVERITY_LOW, TX_MSG,
				"reclaim:ddi_dma_unbind_handle failure");
			ddi_dma_free_handle(&hmep->hme_dmaxh[i]);
			hmep->hme_dmaxh[i] = NULL;
		} else HME_FAULT_MSG1(hmep, SEVERITY_HIGH, TX_MSG,
					"reclaim: expected dmaxh");

		if (hmep->hme_tmblkp[i]) {
			freeb(hmep->hme_tmblkp[i]);
			hmep->hme_tmblkp[i] = NULL;
		}

		tmdp = NEXTTMD(hmep, tmdp);
	}

	if (tmdp != hmep->hme_tcurp) {
		/*
		 * we could reclaim some TMDs so turn off interrupts
		 */
		hmep->hme_tcurp = tmdp;
		if (hmep->hme_wantw) {
			PUT_GLOBREG(intmask,
			HMEG_MASK_INTR | HMEG_MASK_TINT | HMEG_MASK_TX_ALL);
			mutex_enter(&hmewenlock);
			hmewenable(hmep);
			mutex_exit(&hmewenlock);
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
 * Send packet upstream.
 * Assume mp->b_rptr points to ether_header.
 */
static void
hmesendup(struct hme *hmep, mblk_t *mp, struct hmestr *(*acceptfunc)())
{
	struct	ether_addr	*dhostp, *shostp;
	struct	hmestr	*sbp, *nsbp;
	mblk_t	*nmp;
	uint32_t isgroupaddr;
	int type;

	TRACE_0(TR_FAC_BE, TR_BE_SENDUP_START, "hmesendup start");

	dhostp = &((struct ether_header *)mp->b_rptr)->ether_dhost;
	shostp = &((struct ether_header *)mp->b_rptr)->ether_shost;
	type = get_ether_type(mp->b_rptr);

	isgroupaddr = dhostp->ether_addr_octet[0] & 01;

	/*
	 * While holding a reader lock on the linked list of streams structures,
	 * attempt to match the address criteria for each stream
	 * and pass up the raw M_DATA ("fastpath") or a DL_UNITDATA_IND.
	 */

	rw_enter(&hmestruplock, RW_READER);

	if ((sbp = (*acceptfunc)(hmestrup, hmep, type, dhostp)) == NULL) {
		rw_exit(&hmestruplock);
		freemsg(mp);
		TRACE_0(TR_FAC_BE, TR_BE_SENDUP_END, "hmesendup end");
		return;
	}

	/*
	 * Loop on matching open streams until (*acceptfunc)() returns NULL.
	 */
	for (; nsbp = (*acceptfunc)(sbp->sb_nextp, hmep, type, dhostp);
		sbp = nsbp)
		if (canputnext(sbp->sb_rq))
			if (nmp = dupmsg(mp)) {
				if ((sbp->sb_flags & HMESFAST) &&
							!isgroupaddr) {
					nmp->b_rptr +=
						sizeof (struct ether_header);
					putnext(sbp->sb_rq, nmp);
				} else if (sbp->sb_flags & HMESRAW)
					putnext(sbp->sb_rq, nmp);
				else if ((nmp = hmeaddudind(hmep, nmp, shostp,
						dhostp, type, isgroupaddr)))
						putnext(sbp->sb_rq, nmp);
			} else
				hmep->hme_allocbfail++;
		else
			hmep->hme_nocanput++;


	/*
	 * Do the last one.
	 */
	if (canputnext(sbp->sb_rq)) {
		if ((sbp->sb_flags & HMESFAST) && !isgroupaddr) {
			mp->b_rptr += sizeof (struct ether_header);
			putnext(sbp->sb_rq, mp);
		} else if (sbp->sb_flags & HMESRAW)
			putnext(sbp->sb_rq, mp);
		else if ((mp = hmeaddudind(hmep, mp, shostp, dhostp,
			type, isgroupaddr)))
			putnext(sbp->sb_rq, mp);
	} else {
		freemsg(mp);
		hmep->hme_nocanput++;
		hmep->hme_norcvbuf++;
	}

	rw_exit(&hmestruplock);
	TRACE_0(TR_FAC_BE, TR_BE_SENDUP_END, "hmesendup end");
}

/*
 * Test upstream destination sap and address match.
 */
static struct hmestr *
hmeaccept(struct hmestr *sbp, struct hme *hmep, int type,
	struct ether_addr *addrp)
{
	t_uscalar_t sap;
	uint32_t flags;

	for (; sbp; sbp = sbp->sb_nextp) {
		sap = sbp->sb_sap;
		flags = sbp->sb_flags;

		if ((sbp->sb_hmep == hmep) && HMESAPMATCH(sap, type, flags))
			if ((ether_cmp(addrp, &hmep->hme_ouraddr) == 0) ||
				(ether_cmp(addrp, &etherbroadcastaddr) == 0) ||
				(flags & HMESALLPHYS) ||
				hmemcmatch(sbp, addrp))
				return (sbp);
	}
	return (NULL);
}

/*
 * Test upstream destination sap and address match for HMESALLPHYS only.
 */
/* ARGSUSED3 */
static struct hmestr *
hmepaccept(struct  hmestr *sbp, struct hme *hmep, int type,
	struct ether_addr *addrp)
{
	t_uscalar_t sap;
	uint32_t flags;

	for (; sbp; sbp = sbp->sb_nextp) {
		sap = sbp->sb_sap;
		flags = sbp->sb_flags;

		if ((sbp->sb_hmep == hmep) &&
			HMESAPMATCH(sap, type, flags) &&
			(flags & HMESALLPHYS))
			return (sbp);
	}
	return (NULL);
}

/*
 * Set or clear the device ipq pointer.
 * Assumes IPv4 and IPv6 are HMESFAST.
 */
static void
hmesetipq(struct hme *hmep)
{
	struct	hmestr	*sbp;
	int	ok4 = 1;
	int	ok6 = 1;
	queue_t	*ip4q = NULL;
	queue_t	*ip6q = NULL;

	rw_enter(&hmestruplock, RW_READER);

	for (sbp = hmestrup; sbp; sbp = sbp->sb_nextp) {
		if (sbp->sb_hmep == hmep) {
			if (sbp->sb_flags & (HMESALLPHYS|HMESALLSAP)) {
				ok4 = 0;
				ok6 = 0;
				break;
			}
			if (sbp->sb_sap == ETHERTYPE_IP) {
				if (ip4q == NULL)
					ip4q = sbp->sb_rq;
				else
					ok4 = 0;
			}
			if (sbp->sb_sap == ETHERTYPE_IPV6) {
				if (ip6q == NULL)
					ip6q = sbp->sb_rq;
				else
					ok6 = 0;
			}
		}
	}

	rw_exit(&hmestruplock);

	if (ok4)
		hmep->hme_ip4q = ip4q;
	else
		hmep->hme_ip4q = NULL;
	if (ok6)
		hmep->hme_ip6q = ip6q;
	else
		hmep->hme_ip6q = NULL;
}

/*
 * Prefix msg with a DL_UNITDATA_IND mblk and return the new msg.
 */
static mblk_t *
hmeaddudind(struct hme *hmep, mblk_t *mp, struct ether_addr *shostp,
	struct ether_addr *dhostp, int type, uint32_t isgroupaddr)
{
	dl_unitdata_ind_t	*dludindp;
	struct	hmedladdr	*dlap;
	mblk_t	*nmp;
	int	size;

	TRACE_0(TR_FAC_BE, TR_BE_ADDUDIND_START, "hmeaddudind start");

	mp->b_rptr += sizeof (struct ether_header);

	/*
	 * Allocate an M_PROTO mblk for the DL_UNITDATA_IND.
	 */
	size = sizeof (dl_unitdata_ind_t) + HMEADDRL + HMEADDRL;
	if ((nmp = allocb(HMEHEADROOM + size, BPRI_LO)) == NULL) {
		hmep->hme_allocbfail++;
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, STREAMS_MSG,
				"allocb failed");
		freemsg(mp);
		TRACE_0(TR_FAC_BE, TR_BE_ADDUDIND_END, "hmeaddudind end");
		return (NULL);
	}
	DB_TYPE(nmp) = M_PROTO;
	nmp->b_wptr = nmp->b_datap->db_lim;
	nmp->b_rptr = nmp->b_wptr - size;

	/*
	 * Construct a DL_UNITDATA_IND primitive.
	 */
	dludindp = (dl_unitdata_ind_t *)nmp->b_rptr;
	dludindp->dl_primitive = DL_UNITDATA_IND;
	dludindp->dl_dest_addr_length = HMEADDRL;
	dludindp->dl_dest_addr_offset = sizeof (dl_unitdata_ind_t);
	dludindp->dl_src_addr_length = HMEADDRL;
	dludindp->dl_src_addr_offset = sizeof (dl_unitdata_ind_t) + HMEADDRL;
	dludindp->dl_group_address = isgroupaddr;

	dlap = (struct hmedladdr *)(nmp->b_rptr + sizeof (dl_unitdata_ind_t));
	ether_bcopy(dhostp, &dlap->dl_phys);
	dlap->dl_sap = (uint16_t)type;

	dlap = (struct hmedladdr *)(nmp->b_rptr + sizeof (dl_unitdata_ind_t)
		+ HMEADDRL);
	ether_bcopy(shostp, &dlap->dl_phys);
	dlap->dl_sap = (uint16_t)type;

	/*
	 * Link the M_PROTO and M_DATA together.
	 */
	nmp->b_cont = mp;
	TRACE_0(TR_FAC_BE, TR_BE_ADDUDIND_END, "hmeaddudind end");
	return (nmp);
}

/*
 * Return TRUE if the given multicast address is one
 * of those that this particular Stream is interested in.
 */
static int
hmemcmatch(struct hmestr *sbp, struct ether_addr *addrp)
{
	struct	ether_addr *mcbucket;
	uint32_t mccount;
	uint32_t mchash;
	uint32_t i;

	/*
	 * Return FALSE if not a multicast address.
	 */
	if (!(addrp->ether_addr_octet[0] & 01))
		return (0);

	/*
	 * Check if all multicasts have been enabled for this Stream
	 */
	if (sbp->sb_flags & HMESALLMULTI)
		return (1);

	/*
	 * Compute the hash value for the address and
	 * grab the bucket and the number of entries in the
	 * bucket.
	 */
	mchash = MCHASH(addrp);
	mcbucket = sbp->sb_mctab[mchash];
	mccount = sbp->sb_mccount[mchash];

	/*
	 * Return FALSE if no multicast addresses enabled for this Stream.
	 */

	if (mccount == 0)
		return (0);

	/*
	 * Otherwise, find it in the table.
	 */
	if (mcbucket)
		for (i = 0; i < mccount; i++)
			if (!ether_cmp(addrp, &mcbucket[i]))
				return (1);
	return (0);
}

/*
 * Handle interrupts for fatal errors
 * Need reinitialization of the ENET channel.
 */
static void
hme_fatal_err(struct hme *hmep, uint_t hmesbits)
{

	if (hmesbits & HMEG_STATUS_SLV_PAR_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"sbus slave parity error");
		hmep->hme_slvparerr++;
	}

	if (hmesbits & HMEG_STATUS_SLV_ERR_ACK) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"sbus slave error ack");
		hmep->hme_slverrack++;
	}

	if (hmesbits & HMEG_STATUS_TX_TAG_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"tx tag error");
		hmep->hme_txtagerr++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_TX_PAR_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"sbus tx parity error");
		hmep->hme_txparerr++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_TX_LATE_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"sbus tx late error");
		hmep->hme_txlaterr++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_TX_ERR_ACK) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"sbus tx error ack");
		hmep->hme_txerrack++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_EOP_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"chained packet descriptor error");
		hmep->hme_eoperr++;
	}

	if (hmesbits & HMEG_STATUS_RX_TAG_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"rx tag error");
		hmep->hme_rxtagerr++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_RX_PAR_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"sbus rx parity error");
		hmep->hme_rxparerr++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_RX_LATE_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"sbus rx late error");
		hmep->hme_rxlaterr++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_RX_ERR_ACK) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, FATAL_ERR_MSG,
				"sbus rx error ack");
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
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"rx pkt dropped/no free descriptor error");
		hmep->hme_missed++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_DEFTIMR_EXP) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"defer timer expired");
		hmep->hme_defer++;
		hmep->hme_defer_xmts++;
	}

	if (hmesbits & HMEG_STATUS_FSTCOLC_EXP) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"first collision counter expired");
		hmep->hme_fstcol += 256;
	}

	if (hmesbits & HMEG_STATUS_LATCOLC_EXP) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"late collision");
		hmep->hme_tlcol += 256;
		hmep->hme_oerrors += 256;
	}

	if (hmesbits & HMEG_STATUS_EXCOLC_EXP) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"retry error");
		hmep->hme_trtry += 256;
		hmep->hme_oerrors += 256;
	}

	if (hmesbits & HMEG_STATUS_NRMCOLC_EXP) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"first collision counter expired");
		hmep->hme_coll += 256;
	}

	if (hmesbits & HMEG_STATUS_MXPKTSZ_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"babble");
		hmep->hme_babl++;
		hmep->hme_oerrors++;
	}

	/*
	 * This error is fatal and the board needs to
	 * be reinitialized. Comments?
	 */
	if (hmesbits & HMEG_STATUS_TXFIFO_UNDR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"tx fifo underflow");
		hmep->hme_uflo++;
		hmep->hme_oerrors++;
	}

	if (hmesbits & HMEG_STATUS_SQE_TST_ERR) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"sqe test error");
		hmep->hme_sqerr++;
		hmep->hme_sqe_errors++;
	}

	if (hmesbits & HMEG_STATUS_RCV_CNT_EXP) {
		if (hmep->hme_rxcv_enable) {
			HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
					"code violation counter expired");
			hmep->hme_cvc += 256;
		}
	}

	if (hmesbits & HMEG_STATUS_RXFIFO_OVFL) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"rx fifo overflow");
		hmep->hme_oflo++;
		hmep->hme_ierrors++;
	}

	if (hmesbits & HMEG_STATUS_LEN_CNT_EXP) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"length error counter expired");
		hmep->hme_lenerr += 256;
		hmep->hme_ierrors += 256;
	}

	if (hmesbits & HMEG_STATUS_ALN_CNT_EXP) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"rx framing/alignment error");
		hmep->hme_fram += 256;
		hmep->hme_align_errors += 256;
		hmep->hme_ierrors += 256;
	}

	if (hmesbits & HMEG_STATUS_CRC_CNT_EXP) {
		HME_DEBUG_MSG1(hmep, SEVERITY_MID, NFATAL_ERR_MSG,
				"rx crc error");
		hmep->hme_crc += 256;
		hmep->hme_fcs_errors += 256;
		hmep->hme_ierrors += 256;
	}
}

static void
hmeread_dma(struct hme *hmep, volatile struct hme_rmd *rmdp)
{
	long rmdi;
	ulong_t	dvma_rmdi;
	mblk_t	*bp, *nbp;
	volatile struct	hme_rmd	*nrmdp;
	struct ether_header	*ehp;
	t_uscalar_t type;
	queue_t	*ip4q;
	queue_t	*ip6q;
	uint32_t len;
	int32_t	syncval;
	long	nrmdi;

	TRACE_0(TR_FAC_BE, TR_BE_READ_START, "hmeread start");

	rmdi = rmdp - hmep->hme_rmdp;
	bp = hmep->hme_rmblkp[rmdi];
	nrmdp = NEXTRMD(hmep, hmep->hme_rlastp);
	hmep->hme_rlastp = nrmdp;
	nrmdi = nrmdp - hmep->hme_rmdp;
	len = (GET_RMD_FLAGS(rmdp) & HMERMD_BUFSIZE) >> HMERMD_BUFSIZE_SHIFT;
	dvma_rmdi = HMERINDEX(rmdi);

	/*
	 * Check for short packet
	 * and check for overflow packet also. The processing is the
	 * same for both the cases - reuse the buffer. Update the Buffer
	 * overflow counter.
	 */
	if ((len < ETHERMIN) || (GET_RMD_FLAGS(rmdp) & HMERMD_OVFLOW) ||
					(len > ETHERMAX)) {
		if (len < ETHERMIN)
			hmep->hme_runt++;

		else {
			hmep->hme_buff++;
			hmep->hme_toolong_errors++;
		}
		hmep->hme_ierrors++;
		CLONE_RMD(rmdp, nrmdp);
		hmep->hme_rmblkp[nrmdi] = bp;
		hmep->hme_rmblkp[rmdi] = NULL;
		HMESYNCIOPB(hmep, nrmdp, sizeof (struct hme_rmd),
			DDI_DMA_SYNC_FORDEV);
		CHECK_IOPB();
		TRACE_0(TR_FAC_BE, TR_BE_READ_END, "hmeread end");
		return;
	}

	/*
	 * Sync the received buffer before looking at it.
	 */

	if (hmep->hme_dmarh[dvma_rmdi] == NULL) {
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, RX_MSG,
				"read: null handle!");
		return;
	}

	syncval = ddi_dma_sync(hmep->hme_dmarh[dvma_rmdi], 0,
	    len + HME_FSTBYTE_OFFSET, DDI_DMA_SYNC_FORCPU);
	if (syncval == DDI_FAILURE)
		HME_FAULT_MSG1(hmep, SEVERITY_HIGH, RX_MSG,
				"read: ddi_dma_sync failure");
	CHECK_DMA(hmep->hme_dmarh[dvma_rmdi]);

	/*
	 * copy the packet data and then recycle the descriptor.
	 */

	if ((nbp = allocb(len + HME_FSTBYTE_OFFSET, BPRI_HI)) != NULL) {

		DB_TYPE(nbp) = M_DATA;
		bcopy(bp->b_rptr, nbp->b_rptr, len + HME_FSTBYTE_OFFSET);

		CLONE_RMD(rmdp, nrmdp);
		hmep->hme_rmblkp[nrmdi] = bp;
		hmep->hme_rmblkp[rmdi] = NULL;
		HMESYNCIOPB(hmep, nrmdp, sizeof (struct hme_rmd),
			DDI_DMA_SYNC_FORDEV);
		CHECK_IOPB();

		hmep->hme_ipackets++;
		hmep->hme_ipackets64++;

		bp = nbp;

		/*  Add the First Byte offset to the b_rptr and copy */
		bp->b_rptr += HME_FSTBYTE_OFFSET;
		bp->b_wptr = bp->b_rptr + len;
		ehp = (struct ether_header *)bp->b_rptr;

		/*
		 * update MIB II statistics
		 */
		BUMP_InNUcast(hmep, ehp);
		hmep->hme_rcvbytes += len;
		hmep->hme_rbytes64 += len;

		type = get_ether_type(ehp);
		ip4q = hmep->hme_ip4q;
		ip6q = hmep->hme_ip6q;

		if ((type == ETHERTYPE_IP) &&
		    ((ehp->ether_dhost.ether_addr_octet[0] & 01) == 0) &&
		    (ip4q) && (((struct hmestr *)ip4q->q_ptr)->sb_flags &
			HMESFAST)) {
			if (canputnext(ip4q)) {
				bp->b_rptr += sizeof (struct ether_header);
				putnext(ip4q, bp);
			} else {
				freemsg(bp);
				hmep->hme_nocanput++;
				hmep->hme_newfree++;
			}
		} else if ((type == ETHERTYPE_IPV6) &&
		    ((ehp->ether_dhost.ether_addr_octet[0] & 01) == 0) &&
		    (ip6q) && (((struct hmestr *)ip6q->q_ptr)->sb_flags &
			HMESFAST)) {
			if (canputnext(ip6q)) {
				bp->b_rptr += sizeof (struct ether_header);
				putnext(ip6q, bp);
			} else {
				freemsg(bp);
				hmep->hme_nocanput++;
				hmep->hme_newfree++;
			}
		} else {
			/* Strip the PADs for 802.3 */
			if (type <= ETHERMTU)
				bp->b_wptr = bp->b_rptr
						+ sizeof (struct ether_header)
						+ type;
			hmesendup(hmep, bp, hmeaccept);
		}
	} else {
		CLONE_RMD(rmdp, nrmdp);
		hmep->hme_rmblkp[nrmdi] = bp;
		hmep->hme_rmblkp[rmdi] = NULL;
		HMESYNCIOPB(hmep, nrmdp, sizeof (struct hme_rmd),
					DDI_DMA_SYNC_FORDEV);
		CHECK_IOPB();

		hmep->hme_allocbfail++;
		hmep->hme_norcvbuf++;
		HME_DEBUG_MSG1(hmep, SEVERITY_UNKNOWN, RX_MSG,
				"allocb failure");
	}
	TRACE_0(TR_FAC_BE, TR_BE_READ_END, "hmeread end");
}

static void
hmeread(struct hme *hmep, volatile struct hme_rmd *rmdp)
{
	long    rmdi;
	mblk_t  *bp, *nbp;
	uint_t		dvma_rmdi, dvma_nrmdi;
	volatile	struct  hme_rmd *nrmdp;
	struct		ether_header    *ehp;
	queue_t		*ip4q;
	queue_t		*ip6q;
	t_uscalar_t	type;
	uint32_t len;
	long    nrmdi;
	ddi_dma_cookie_t	c;

	TRACE_0(TR_FAC_BE, TR_BE_READ_START, "hmeread start");
	if (hmep->hme_dvmaxh == NULL) {
		hmeread_dma(hmep, rmdp);
		return;
	}

	rmdi = rmdp - hmep->hme_rmdp;
	dvma_rmdi = HMERINDEX(rmdi);
	bp = hmep->hme_rmblkp[rmdi];
	nrmdp = NEXTRMD(hmep, hmep->hme_rlastp);
	hmep->hme_rlastp = nrmdp;
	nrmdi = nrmdp - hmep->hme_rmdp;
	dvma_nrmdi = HMERINDEX(rmdi);

	ASSERT(dvma_rmdi == dvma_nrmdi);

	/*
	 * HMERMD_OWN has been cleared by the Happymeal hardware.
	 */
	len = (GET_RMD_FLAGS(rmdp) & HMERMD_BUFSIZE) >> HMERMD_BUFSIZE_SHIFT;

	/*
	 * check for overflow packet also. The processing is the
	 * same for both the cases - reuse the buffer. Update the Buffer
	 * overflow counter.
	 */
	if ((len < ETHERMIN) || (GET_RMD_FLAGS(rmdp) & HMERMD_OVFLOW) ||
					(len > ETHERMAX)) {
		if (len < ETHERMIN)
			hmep->hme_runt++;

		else {
			hmep->hme_buff++;
			hmep->hme_toolong_errors++;
		}

		hmep->hme_ierrors++;
		CLONE_RMD(rmdp, nrmdp);
		HMESYNCIOPB(hmep, nrmdp, sizeof (struct hme_rmd),
			DDI_DMA_SYNC_FORDEV);
		CHECK_IOPB();
		hmep->hme_rmblkp[nrmdi] = bp;
		hmep->hme_rmblkp[rmdi] = NULL;
		TRACE_0(TR_FAC_BE, TR_BE_READ_END, "hmeread end");
		return;
	}

	/*
	 * Copy small incoming packets to reduce memory consumption. The
	 * performance loss is compensated by the reduced overhead for
	 * DMA setup. The extra bytes before the actual data are copied
	 * to maintain the alignment of the payload.
	 */
	if ((len <= hme_rx_bcopy_max) &&
	    ((nbp = allocb(len + HME_FSTBYTE_OFFSET, BPRI_LO)) != NULL)) {
		dvma_sync(hmep->hme_dvmarh, 2 * dvma_rmdi,
		    DDI_DMA_SYNC_FORKERNEL);

		bcopy(bp->b_rptr, nbp->b_wptr, len + HME_FSTBYTE_OFFSET);
		nbp->b_rptr += HME_FSTBYTE_OFFSET;
		nbp->b_wptr = nbp->b_rptr + len;

		CLONE_RMD(rmdp, nrmdp);
		HMESYNCIOPB(hmep, nrmdp, sizeof (struct hme_rmd),
			DDI_DMA_SYNC_FORDEV);
		CHECK_IOPB();
		hmep->hme_rmblkp[nrmdi] = bp;
		hmep->hme_rmblkp[rmdi] = NULL;
		hmep->hme_ipackets++;
		hmep->hme_ipackets64++;

		bp = nbp;
	} else {
		dvma_unload(hmep->hme_dvmarh, 2 * dvma_rmdi,
		    DDI_DMA_SYNC_FORKERNEL);

		if ((nbp = hmeallocb(HMEBUFSIZE, BPRI_LO))) {
			(void) dvma_kaddr_load(hmep->hme_dvmarh,
			    (caddr_t)nbp->b_rptr, HMEBUFSIZE, 2 * dvma_nrmdi,
			    &c);

			PUT_RMD(nrmdp, c.dmac_address);
			HMESYNCIOPB(hmep, nrmdp, sizeof (struct hme_rmd),
			    DDI_DMA_SYNC_FORDEV);
			CHECK_IOPB();

			hmep->hme_rmblkp[nrmdi] = nbp;
			hmep->hme_rmblkp[rmdi] = NULL;
			hmep->hme_ipackets++;
			hmep->hme_ipackets64++;

			/*
			 * Add the First Byte offset to the b_rptr
			 */
			bp->b_rptr += HME_FSTBYTE_OFFSET;
			bp->b_wptr = bp->b_rptr + len;
		} else {
			(void) dvma_kaddr_load(hmep->hme_dvmarh,
			    (caddr_t)bp->b_rptr, HMEBUFSIZE, 2 * dvma_nrmdi,
			    &c);
			PUT_RMD(nrmdp, c.dmac_address);
			hmep->hme_rmblkp[nrmdi] = bp;
			hmep->hme_rmblkp[rmdi] = NULL;
			HMESYNCIOPB(hmep, nrmdp, sizeof (struct hme_rmd),
			    DDI_DMA_SYNC_FORDEV);
			CHECK_IOPB();

			hmep->hme_allocbfail++;
			hmep->hme_norcvbuf++;
			HME_DEBUG_MSG1(hmep, SEVERITY_LOW, RX_MSG,
			    "allocb fail");

			bp = NULL;
		}
	}

	if (bp != NULL) {
		ehp = (struct ether_header *)bp->b_rptr;

		/*
		 * update MIB II statistics
		 */
		BUMP_InNUcast(hmep, ehp);
		hmep->hme_rcvbytes += len;
		hmep->hme_rbytes64 += len;

		type = get_ether_type(ehp);
		ip4q = hmep->hme_ip4q;
		ip6q = hmep->hme_ip6q;

		if ((type == ETHERTYPE_IP) &&
		    ((ehp->ether_dhost.ether_addr_octet[0] & 01) == 0) &&
		    (ip4q) && (((struct hmestr *)ip4q->q_ptr)->sb_flags &
			HMESFAST)) {
			if (canputnext(ip4q)) {
				bp->b_rptr += sizeof (struct ether_header);
				putnext(ip4q, bp);
			} else {
				freemsg(bp);
				hmep->hme_newfree++;
				hmep->hme_nocanput++;
			}
		} else if ((type == ETHERTYPE_IPV6) &&
		    ((ehp->ether_dhost.ether_addr_octet[0] & 01) == 0) &&
		    (ip6q) && (((struct hmestr *)ip6q->q_ptr)->sb_flags &
			HMESFAST)) {
			if (canputnext(ip6q)) {
				bp->b_rptr += sizeof (struct ether_header);
				putnext(ip6q, bp);
			} else {
				freemsg(bp);
				hmep->hme_newfree++;
				hmep->hme_nocanput++;
			}
		} else {
			/*
			 * Strip the PADs for 802.3
			 */
			if (type <= ETHERMTU)
				bp->b_wptr = bp->b_rptr
				    + sizeof (struct ether_header)
				    + type;
			hmesendup(hmep, bp, hmeaccept);
		}
	}
	TRACE_0(TR_FAC_BE, TR_BE_READ_END, "hmeread end");
}

/*
 * Start xmit on any msgs previously enqueued on any write queues.
 */
static void
hmewenable(struct hme *hmep)
{
	struct	hmestr	*sbp;
	queue_t	*wq;

	/*
	 * Order of wantw accesses is important.
	 */
	do {
		hmep->hme_wantw = 0;
		for (sbp = hmestrup; sbp; sbp = sbp->sb_nextp)
			if ((wq = WR(sbp->sb_rq))->q_first)
				qenable(wq);
	} while (hmep->hme_wantw);
}

#ifdef  HME_DEBUG
/*VARARGS*/
static void
hme_debug_msg(char *file, uint_t line, struct hme *hmep, uint_t severity,
		msg_t type, char *fmt, ...)
{
	char	msg_buffer[255];
	va_list	ap;

#ifdef	HIGH_SEVERITY
	if (severity != SEVERITY_HIGH)
		return;
#endif
	if (hme_debug_level >= type) {
		mutex_enter(&hmelock);
		va_start(ap, fmt);
		vsprintf(msg_buffer, fmt, ap);

		cmn_err(CE_CONT, "D: %s (%d): %s\n",
			msg_string[type], line, msg_buffer);
		va_end(ap);
		mutex_exit(&hmelock);
	}
}
#endif

/*VARARGS*/
/* ARGSUSED */
static void
hme_fault_msg(char *file, uint_t line, struct hme *hmep, uint_t severity,
		msg_t type, char *fmt, ...)
{
	char	msg_buffer[255];
	va_list	ap;

	mutex_enter(&hmelock);
	va_start(ap, fmt);
	(void) vsprintf(msg_buffer, fmt, ap);

	if (hmep == NULL)
		cmn_err(CE_NOTE, "hme : %s", msg_buffer);

	else if ((type == DISPLAY_MSG) && (!hmep->hme_linkup_msg))
		cmn_err(CE_CONT, "?%s%d : %s\n",
			ddi_get_name(hmep->dip),
			hmep->instance,
			msg_buffer);
	else if (severity == SEVERITY_HIGH)
		cmn_err(CE_WARN,
			"%s%d : %s, SEVERITY_HIGH, %s\n",
			ddi_get_name(hmep->dip),
			hmep->instance,
			msg_buffer, msg_string[type]);
	else
		cmn_err(CE_CONT, "%s%d : %s\n",
			ddi_get_name(hmep->dip),
			hmep->instance,
			msg_buffer);
	va_end(ap);
	mutex_exit(&hmelock);
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
	hmep->hme_fram += aecnt;
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
	hmep->hme_trtry += excnt;
	PUT_MACREG(excnt, 0);

	hmep->hme_crc += fecnt;
	hmep->hme_fcs_errors += fecnt;
	hmep->hme_ierrors += (fecnt + aecnt + lecnt);
	hmep->hme_oerrors += (ltcnt + excnt);
	hmep->hme_coll += (GET_MACREG(nccnt) + ltcnt);

	PUT_MACREG(nccnt, 0);
	CHECK_MACREG();
}

/*
 * ndd support functions to get/set parameters
 */
/* Free the Named Dispatch Table by calling hme_nd_free */
static void
hme_param_cleanup(struct hme *hmep)
{
	if (hmep->hme_g_nd)
		(void) hme_nd_free(&hmep->hme_g_nd);
}

/*
 * Extracts the value from the hme parameter array and prints the
 * parameter value. cp points to the required parameter.
 */
/* ARGSUSED */
static int
hme_param_get(queue_t *q, mblk_t *mp, caddr_t cp)
{
	hmeparam_t *hmepa = (hmeparam_t *)cp;

	(void) mi_mpprintf(mp, "%d", hmepa->hme_param_val);
	return (0);
}

/*
 * Register each element of the parameter array with the
 * named dispatch handler. Each element is loaded using
 * hme_nd_load()
 */
/* ARGSUSED */
static int
hme_param_register(struct hme *hmep, hmeparam_t *hmepa, int cnt)
{
	int i;

	/* First 4 elements are read-only */
	for (i = 0; i < 4; i++, hmepa++)
		if (!hme_nd_load(&hmep->hme_g_nd, hmepa->hme_param_name,
			(pfi_t)hme_param_get, (pfi_t)0, (caddr_t)hmepa)) {
			(void) hme_nd_free(&hmep->hme_g_nd);
			return (B_FALSE);
		}
	/* Next 10 elements are read and write */
	for (i = 0; i < 10; i++, hmepa++)
		if (hmepa->hme_param_name && hmepa->hme_param_name[0]) {
			if (!hme_nd_load(&hmep->hme_g_nd,
				hmepa->hme_param_name,
				(pfi_t)hme_param_get,
				(pfi_t)hme_param_set, (caddr_t)hmepa)) {
				(void) hme_nd_free(&hmep->hme_g_nd);
				return (B_FALSE);

			}
		}
	/* next 12 elements are read-only */
	for (i = 0; i < 12; i++, hmepa++)
		if (!hme_nd_load(&hmep->hme_g_nd, hmepa->hme_param_name,
			(pfi_t)hme_param_get, (pfi_t)0, (caddr_t)hmepa)) {
			(void) hme_nd_free(&hmep->hme_g_nd);
			return (B_FALSE);
		}
	/* Next 3  elements are read and write */
	for (i = 0; i < 3; i++, hmepa++)
		if (hmepa->hme_param_name && hmepa->hme_param_name[0]) {
			if (!hme_nd_load(&hmep->hme_g_nd,
				hmepa->hme_param_name,
				(pfi_t)hme_param_get,
				(pfi_t)hme_param_set, (caddr_t)hmepa)) {
				(void) hme_nd_free(&hmep->hme_g_nd);
				return (B_FALSE);
			}
		}

	return (B_TRUE);
}

/*
 * Sets the hme parameter to the value in the hme_param_register using
 * hme_nd_load().
 */
/* ARGSUSED */
static int
hme_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp)
{
	char *end;
	size_t new_value;
	hmeparam_t *hmepa = (hmeparam_t *)cp;

	new_value = mi_strtol(value, &end, 10);
	if (end == value || new_value < hmepa->hme_param_min ||
		new_value > hmepa->hme_param_max) {
			return (EINVAL);
	}
	hmepa->hme_param_val = new_value;
	return (0);

}

/* Free the table pointed to by 'ndp' */
static void
hme_nd_free(caddr_t *nd_pparam)
{
	ND	*nd;

	if ((nd = (ND *)(*nd_pparam)) != NULL) {
		if (nd->nd_tbl)
			mi_free((char *)nd->nd_tbl);
		mi_free((char *)nd);
		*nd_pparam = NULL;
	}
}

static int
hme_nd_getset(queue_t *q, caddr_t nd_param, MBLKP mp)
{
	int	err;
	IOCP	iocp;
	MBLKP	mp1;
	ND	*nd;
	NDE	*nde;
	char	*valp;
	size_t	avail;

	if (!nd_param)
		return (B_FALSE);

	nd = (ND *)nd_param;
	iocp = (IOCP)mp->b_rptr;
	if ((iocp->ioc_count == 0) || !(mp1 = mp->b_cont)) {
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_count = 0;
		iocp->ioc_error = EINVAL;
		return (B_TRUE);
	}

	/*
	 * NOTE - logic throughout nd_xxx assumes single data block for ioctl.
	 *	However, existing code sends in some big buffers.
	 */
	avail = iocp->ioc_count;
	if (mp1->b_cont) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}

	mp1->b_datap->db_lim[-1] = '\0';	/* Force null termination */
	valp = (char *)mp1->b_rptr;
	for (nde = nd->nd_tbl; /* */; nde++) {
		if (!nde->nde_name)
			return (B_FALSE);
		if (mi_strcmp(nde->nde_name, valp) == 0)
			break;
	}

	err = EINVAL;
	while (*valp++)
		;
	if (!*valp || valp >= (char *)mp1->b_wptr)
		valp = NULL;
	switch (iocp->ioc_cmd) {
	case ND_GET:
/*
 * (temporary) hack: "*valp" is size of user buffer for copyout. If result
 * of action routine is too big, free excess and return ioc_rval as buffer
 * size needed.  Return as many mblocks as will fit, free the rest.  For
 * backward compatibility, assume size of original ioctl buffer if "*valp"
 * bad or not given.
 */
		if (valp)
			avail = mi_strtol(valp, (char **)0, 10);
		/* We overwrite the name/value with the reply data */
		{
			mblk_t *mp2 = mp1;

			while (mp2) {
				mp2->b_wptr = mp2->b_rptr;
				mp2 = mp2->b_cont;
			}
		}
		err = (*nde->nde_get_pfi)(q, mp1, nde->nde_data, iocp->ioc_cr);
		if (!err) {
			size_t	size_out;
			ssize_t	excess;

			iocp->ioc_rval = 0;

			/* Tack on the null */
			(void) mi_mpprintf_putc((char *)mp1, '\0');
			size_out = msgdsize(mp1);
			excess = size_out - avail;
			if (excess > 0) {
				iocp->ioc_rval = (int)size_out;
				size_out -= excess;
				(void) adjmsg(mp1, -(excess + 1));
				(void) mi_mpprintf_putc((char *)mp1, '\0');
			}
			iocp->ioc_count = size_out;
		}
		break;

	case ND_SET:
		if (valp) {
			if ((iocp->ioc_cr != NULL) &&
			    ((err = secpolicy_net_config(iocp->ioc_cr, B_FALSE))
			    == 0)) {
				err = (*nde->nde_set_pfi)(q, mp1, valp,
				    nde->nde_data, iocp->ioc_cr);
			}
			iocp->ioc_count = 0;
			freemsg(mp1);
			mp->b_cont = NULL;
		}
		break;

	default:
		break;
	}

	iocp->ioc_error = err;
	mp->b_datap->db_type = M_IOCACK;
	return (B_TRUE);
}

/*
 * Load 'name' into the named dispatch table pointed to by 'ndp'.
 * 'ndp' should be the address of a char pointer cell.  If the table
 * does not exist (*ndp == 0), a new table is allocated and 'ndp'
 * is stuffed.  If there is not enough space in the table for a new
 * entry, more space is allocated.
 */
static boolean_t
hme_nd_load(caddr_t *nd_pparam, char *name, pfi_t get_pfi,
    pfi_t set_pfi, caddr_t data)
{
	ND	*nd;
	NDE	*nde;

	if (!nd_pparam)
		return (B_FALSE);

	if ((nd = (ND *)(*nd_pparam)) == NULL) {
		if ((nd = (ND *)mi_alloc(sizeof (ND), BPRI_MED)) == NULL)
			return (B_FALSE);
		bzero(nd, sizeof (ND));
		*nd_pparam = (caddr_t)nd;
	}

	if (nd->nd_tbl) {
		for (nde = nd->nd_tbl; nde->nde_name; nde++) {
			if (mi_strcmp(name, nde->nde_name) == 0)
				goto fill_it;
		}
	}

	if (nd->nd_free_count <= 1) {
		if ((nde = (NDE *)mi_alloc(nd->nd_size +
		    NDE_ALLOC_SIZE, BPRI_MED)) == NULL)
			return (B_FALSE);
		bzero(nde, nd->nd_size + NDE_ALLOC_SIZE);
		nd->nd_free_count += NDE_ALLOC_COUNT;
		if (nd->nd_tbl) {
			bcopy(nd->nd_tbl, nde, nd->nd_size);
			mi_free((char *)nd->nd_tbl);
		} else {
			nd->nd_free_count--;
			nde->nde_name = "?";
			nde->nde_get_pfi = nd_get_names;
			nde->nde_set_pfi = nd_set_default;
		}
		nde->nde_data = (caddr_t)nd;
		nd->nd_tbl = nde;
		nd->nd_size += NDE_ALLOC_SIZE;
	}

	for (nde = nd->nd_tbl; nde->nde_name; nde++)
		;
	nd->nd_free_count--;
fill_it:
	nde->nde_name = name;
	nde->nde_get_pfi = get_pfi ? get_pfi : nd_get_default;
	nde->nde_set_pfi = set_pfi ? set_pfi : nd_set_default;
	nde->nde_data = data;
	return (B_TRUE);
}

/*
 * Convert Ethernet address to printable (loggable) representation.
 */
char *
hme_ether_sprintf(struct ether_addr *addr)
{
	uchar_t *ap = (uchar_t *)addr;
	int i;
	static char etherbuf[18];
	char *cp = etherbuf;
	static char digits[] = "0123456789abcdef";

	for (i = 0; i < 6; i++) {
		if (*ap > 0x0f)
			*cp++ = digits[*ap >> 4];
		*cp++ = digits[*ap++ & 0xf];
		*cp++ = ':';
	}
	*--cp = 0;
	return (etherbuf);
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
	if (ddi_getlongprop(DDI_DEV_T_ANY,
		dip, DDI_PROP_DONTPASS, "local-mac-address",
		(caddr_t)&prop, &prop_len) == DDI_PROP_SUCCESS) {
		if (prop_len == ETHERADDRL) {
			hmep->hme_addrflags = HME_FACTADDR_PRESENT;
			ether_bcopy(prop, &hmep->hme_factaddr);
			HME_FAULT_MSG2(hmep, SEVERITY_NONE, DISPLAY_MSG,
				lether_addr_msg,
				hme_ether_sprintf(&hmep->hme_factaddr));
		}
		kmem_free(prop, prop_len);
	}

	/*
	 * Check if the adapter has published "mac-address" property.
	 * If it is present, use it as the mac address for this device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY,
		dip, DDI_PROP_DONTPASS, "mac-address",
		(caddr_t)&prop, &prop_len) == DDI_PROP_SUCCESS) {
		if (prop_len >= ETHERADDRL) {
			ether_bcopy(prop, &hmep->hme_ouraddr);
			kmem_free(prop, prop_len);
			return;
		}
		kmem_free(prop, prop_len);
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, 0, "local-mac-address?",
		(caddr_t)&prop, &prop_len) == DDI_PROP_SUCCESS) {
		if ((strncmp("true", prop, prop_len) == 0) &&
			(hmep->hme_addrflags & HME_FACTADDR_PRESENT)) {
			hmep->hme_addrflags |= HME_FACTADDR_USE;
			ether_bcopy(&hmep->hme_factaddr, &hmep->hme_ouraddr);
			kmem_free(prop, prop_len);
			HME_FAULT_MSG1(hmep, SEVERITY_NONE, DISPLAY_MSG,
					lmac_addr_msg);
			return;
		}
		kmem_free(prop, prop_len);
	}

	/*
	 * Get the system ethernet address.
	 */
	(void) localetheraddr((struct ether_addr *)NULL, &hmep->hme_ouraddr);
}

static void
hme_display_linkup(struct hme *hmep, uint32_t speed)
{
	char linkup_msg[64];

	if (speed == HME_SPEED_100)
		(void) sprintf(linkup_msg, "100 Mbps ");
	else if (speed == HME_SPEED_10)
		(void) sprintf(linkup_msg, "10 Mbps ");
	else
		linkup_msg[0] = '\0';

	if (hmep->hme_fdx)
		(void) strcat(linkup_msg, "full duplex link up");
	else
		(void) strcat(linkup_msg, "half duplex link up");

	ddi_dev_report_fault(hmep->dip, DDI_SERVICE_RESTORED,
	    DDI_EXTERNAL_FAULT, linkup_msg);
}

/* ARGSUSED */
static void
hme_check_acc_handle(char *file, uint_t line, struct hme *hmep,
    ddi_acc_handle_t handle)
{
}

/* ARGSUSED */
static void
hme_check_dma_handle(char *file, uint_t line, struct hme *hmep,
    ddi_dma_handle_t handle)
{
}

static void *
hmeallocb(size_t size, uint_t pri)
{
	mblk_t  *mp;

	if ((mp = allocb(size + 3 * HMEBURSTSIZE, pri)) == NULL) {
		return (NULL);
	}
	mp->b_wptr = (uchar_t *)ROUNDUP2(mp->b_wptr, HMEBURSTSIZE);
	mp->b_rptr = mp->b_wptr;

	return (mp);
}
