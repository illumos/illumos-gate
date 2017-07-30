/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver.
 *
 * Copyright (C) 2005-2017 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CHELSIO_COMMON_H
#define __CHELSIO_COMMON_H

#include "t4_hw.h"
#include "t4_chip_type.h"
#include "t4fw_version.h"
#include "t5fw_version.h"
#include "t6fw_version.h"

#define GLBL_INTR_MASK (F_CIM | F_MPS | F_PL | F_PCIE | F_MC0 | F_EDC0 | \
		F_EDC1 | F_LE | F_TP | F_MA | F_PM_TX | F_PM_RX | F_ULP_RX | \
		F_CPL_SWITCH | F_SGE | F_ULP_TX)

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __linux__
#define __force
#define usleep_range(_min, _max) msleep(_max / 1000)
#endif

/*
 * Firmware minimum version macros are used by t4_check_fw_version() to check
 * if the FW is supported by the driver.
 * Initially these macros were in t4fw_interface.h, but was removed, as the 
 * file is automatically replaced during a new FW commit. So untill these
 * macros moves to one of the firmware header files, it has to be here.
 */
#define T4FW_MIN_VERSION_MAJOR 0x01
#define T4FW_MIN_VERSION_MINOR 0x04
#define T4FW_MIN_VERSION_MICRO 0x00

#define T5FW_MIN_VERSION_MAJOR 0x00
#define T5FW_MIN_VERSION_MINOR 0x00
#define T5FW_MIN_VERSION_MICRO 0x00

#define T6FW_MIN_VERSION_MAJOR 0x00
#define T6FW_MIN_VERSION_MINOR 0x00
#define T6FW_MIN_VERSION_MICRO 0x00

enum {
	MAX_NPORTS     = 4,     /* max # of ports */
	SERNUM_LEN     = 24,    /* Serial # length */
	EC_LEN         = 16,    /* E/C length */
	ID_LEN         = 16,    /* ID length */
	PN_LEN         = 16,    /* Part Number length */
	MACADDR_LEN    = 12,    /* MAC Address length */
};

enum {
	T4_REGMAP_SIZE = (160 * 1024),
	T5_REGMAP_SIZE = (332 * 1024),
};

enum { MEM_EDC0, MEM_EDC1, MEM_MC, MEM_MC0 = MEM_MC, MEM_MC1 };

enum {
	MEMWIN0_APERTURE = 2048,
	MEMWIN0_BASE     = 0x1b800,

	MEMWIN1_APERTURE = 32768,
	MEMWIN1_BASE     = 0x28000,

	MEMWIN2_APERTURE = 65536,
	MEMWIN2_BASE     = 0x30000,

	MEMWIN2_APERTURE_T5 = 128 * 1024,
	MEMWIN2_BASE_T5     = 0x60000,
};

enum dev_master { MASTER_CANT, MASTER_MAY, MASTER_MUST };

enum dev_state { DEV_STATE_UNINIT, DEV_STATE_INIT, DEV_STATE_ERR };

enum {
	PAUSE_RX      = 1 << 0,
	PAUSE_TX      = 1 << 1,
	PAUSE_AUTONEG = 1 << 2
};

enum {
	FEC_AUTO	= 1 << 0,	/* IEEE 802.3 "automatic" */
	FEC_RS		= 1 << 1,	/* Reed-Solomon */
	FEC_BASER_RS	= 1 << 2,	/* BaseR/Reed-Solomon */
};

enum {
	ULP_T10DIF_ISCSI = 1 << 0,
	ULP_T10DIF_FCOE = 1 << 1
};

enum {
	ULP_CRYPTO_LOOKASIDE  = 1 << 0,
	ULP_CRYPTO_INLINE_TLS = 1 << 1
};

struct port_stats {
	u64 tx_octets;            /* total # of octets in good frames */
	u64 tx_frames;            /* all good frames */
	u64 tx_bcast_frames;      /* all broadcast frames */
	u64 tx_mcast_frames;      /* all multicast frames */
	u64 tx_ucast_frames;      /* all unicast frames */
	u64 tx_error_frames;      /* all error frames */

	u64 tx_frames_64;         /* # of Tx frames in a particular range */
	u64 tx_frames_65_127;
	u64 tx_frames_128_255;
	u64 tx_frames_256_511;
	u64 tx_frames_512_1023;
	u64 tx_frames_1024_1518;
	u64 tx_frames_1519_max;

	u64 tx_drop;              /* # of dropped Tx frames */
	u64 tx_pause;             /* # of transmitted pause frames */
	u64 tx_ppp0;              /* # of transmitted PPP prio 0 frames */
	u64 tx_ppp1;              /* # of transmitted PPP prio 1 frames */
	u64 tx_ppp2;              /* # of transmitted PPP prio 2 frames */
	u64 tx_ppp3;              /* # of transmitted PPP prio 3 frames */
	u64 tx_ppp4;              /* # of transmitted PPP prio 4 frames */
	u64 tx_ppp5;              /* # of transmitted PPP prio 5 frames */
	u64 tx_ppp6;              /* # of transmitted PPP prio 6 frames */
	u64 tx_ppp7;              /* # of transmitted PPP prio 7 frames */

	u64 rx_octets;            /* total # of octets in good frames */
	u64 rx_frames;            /* all good frames */
	u64 rx_bcast_frames;      /* all broadcast frames */
	u64 rx_mcast_frames;      /* all multicast frames */
	u64 rx_ucast_frames;      /* all unicast frames */
	u64 rx_too_long;          /* # of frames exceeding MTU */
	u64 rx_jabber;            /* # of jabber frames */
	u64 rx_fcs_err;           /* # of received frames with bad FCS */
	u64 rx_len_err;           /* # of received frames with length error */
	u64 rx_symbol_err;        /* symbol errors */
	u64 rx_runt;              /* # of short frames */

	u64 rx_frames_64;         /* # of Rx frames in a particular range */
	u64 rx_frames_65_127;
	u64 rx_frames_128_255;
	u64 rx_frames_256_511;
	u64 rx_frames_512_1023;
	u64 rx_frames_1024_1518;
	u64 rx_frames_1519_max;

	u64 rx_pause;             /* # of received pause frames */
	u64 rx_ppp0;              /* # of received PPP prio 0 frames */
	u64 rx_ppp1;              /* # of received PPP prio 1 frames */
	u64 rx_ppp2;              /* # of received PPP prio 2 frames */
	u64 rx_ppp3;              /* # of received PPP prio 3 frames */
	u64 rx_ppp4;              /* # of received PPP prio 4 frames */
	u64 rx_ppp5;              /* # of received PPP prio 5 frames */
	u64 rx_ppp6;              /* # of received PPP prio 6 frames */
	u64 rx_ppp7;              /* # of received PPP prio 7 frames */

	u64 rx_ovflow0;           /* drops due to buffer-group 0 overflows */
	u64 rx_ovflow1;           /* drops due to buffer-group 1 overflows */
	u64 rx_ovflow2;           /* drops due to buffer-group 2 overflows */
	u64 rx_ovflow3;           /* drops due to buffer-group 3 overflows */
	u64 rx_trunc0;            /* buffer-group 0 truncated packets */
	u64 rx_trunc1;            /* buffer-group 1 truncated packets */
	u64 rx_trunc2;            /* buffer-group 2 truncated packets */
	u64 rx_trunc3;            /* buffer-group 3 truncated packets */
};

struct lb_port_stats {
	u64 octets;
	u64 frames;
	u64 bcast_frames;
	u64 mcast_frames;
	u64 ucast_frames;
	u64 error_frames;

	u64 frames_64;
	u64 frames_65_127;
	u64 frames_128_255;
	u64 frames_256_511;
	u64 frames_512_1023;
	u64 frames_1024_1518;
	u64 frames_1519_max;

	u64 drop;

	u64 ovflow0;
	u64 ovflow1;
	u64 ovflow2;
	u64 ovflow3;
	u64 trunc0;
	u64 trunc1;
	u64 trunc2;
	u64 trunc3;
};

struct tp_tcp_stats {
	u32 tcp_out_rsts;
	u64 tcp_in_segs;
	u64 tcp_out_segs;
	u64 tcp_retrans_segs;
};

struct tp_usm_stats {
	u32 frames;
	u32 drops;
	u64 octets;
};

struct tp_fcoe_stats {
	u32 frames_ddp;
	u32 frames_drop;
	u64 octets_ddp;
};

struct tp_err_stats {
	u32 mac_in_errs[4];
	u32 hdr_in_errs[4];
	u32 tcp_in_errs[4];
	u32 tnl_cong_drops[4];
	u32 ofld_chan_drops[4];
	u32 tnl_tx_drops[4];
	u32 ofld_vlan_drops[4];
	u32 tcp6_in_errs[4];
	u32 ofld_no_neigh;
	u32 ofld_cong_defer;
};

struct tp_proxy_stats {
	u32 proxy[4];
};

struct tp_cpl_stats {
	u32 req[4];
	u32 rsp[4];
};

struct tp_rdma_stats {
	u32 rqe_dfr_pkt;
	u32 rqe_dfr_mod;
};

struct sge_params {
	u32 hps;			/* host page size for our PF/VF */
	u32 eq_qpp;			/* egress queues/page for our PF/VF */
	u32 iq_qpp;			/* egress queues/page for our PF/VF */
};

struct tp_params {
	unsigned int tre;            /* log2 of core clocks per TP tick */
	unsigned int dack_re;        /* DACK timer resolution */
	unsigned int la_mask;        /* what events are recorded by TP LA */
	unsigned short tx_modq[NCHAN];  /* channel to modulation queue map */

	u32 vlan_pri_map;		/* cached TP_VLAN_PRI_MAP */
	u32 ingress_config;		/* cached TP_INGRESS_CONFIG */
	/* cached TP_OUT_CONFIG compressed error vector
	 * and passing outer header info for encapsulated packets.
	 */
	int rx_pkt_encap;

	/*
	 * TP_VLAN_PRI_MAP Compressed Filter Tuple field offsets.  This is a
	 * subset of the set of fields which may be present in the Compressed
	 * Filter Tuple portion of filters and TCP TCB connections.  The
	 * fields which are present are controlled by the TP_VLAN_PRI_MAP.
	 * Since a variable number of fields may or may not be present, their
	 * shifted field positions within the Compressed Filter Tuple may
	 * vary, or not even be present if the field isn't selected in
	 * TP_VLAN_PRI_MAP.  Since some of these fields are needed in various
	 * places we store their offsets here, or a -1 if the field isn't
	 * present.
	 */
	int fcoe_shift;
	int port_shift;
	int vnic_shift;
	int vlan_shift;
	int tos_shift;
	int protocol_shift;
	int ethertype_shift;
	int macmatch_shift;
	int matchtype_shift;
	int frag_shift;
};

struct vpd_params {
	unsigned int cclk;
	u8 ec[EC_LEN + 1];
	u8 sn[SERNUM_LEN + 1];
	u8 id[ID_LEN + 1];
	u8 pn[PN_LEN + 1];
	u8 na[MACADDR_LEN + 1];
};

struct pci_params {
	uint16_t        vendor_id;
	uint16_t        device_id;
	uint32_t        vpd_cap_addr;
	uint16_t        speed;
	uint8_t         width;
};

/*
 * Firmware device log.
 */
struct devlog_params {
	u32 memtype;			/* which memory (EDC0, EDC1, MC) */
	u32 start;			/* start of log in firmware memory */
	u32 size;			/* size of log */
};

/* Stores chip specific parameters */
struct arch_specific_params {
	u8 nchan;
	u8 pm_stats_cnt;
	u8 cng_ch_bits_log;		/* congestion channel map bits width */
	u16 mps_rplc_size;
	u16 vfcount;
	u32 sge_fl_db;
	u16 mps_tcam_size;
};

struct adapter_params {
	struct sge_params sge;
	struct tp_params  tp;
	struct vpd_params vpd;
	struct pci_params pci;
	struct devlog_params devlog;
	enum pcie_memwin drv_memwin;

	unsigned int sf_size;             /* serial flash size in bytes */
	unsigned int sf_nsec;             /* # of flash sectors */

	unsigned int fw_vers;		/* firmware version */
	unsigned int bs_vers;		/* bootstrap version */
	unsigned int tp_vers;		/* TP microcode version */
	unsigned int er_vers;		/* expansion ROM version */
	unsigned int scfg_vers;		/* Serial Configuration version */
	unsigned int vpd_vers;		/* VPD version */

	unsigned short mtus[NMTUS];
	unsigned short a_wnd[NCCTRL_WIN];
	unsigned short b_wnd[NCCTRL_WIN];

	unsigned int mc_size;             /* MC memory size */
	unsigned int nfilters;            /* size of filter region */

	unsigned int cim_la_size;

	unsigned char nports;             /* # of ethernet ports */
	unsigned char portvec;
	unsigned char offload;

	unsigned char bypass;
	unsigned char hash_filter;

	enum chip_type chip;              /* chip code */
	struct arch_specific_params arch; /* chip specific params */

	unsigned int ofldq_wr_cred;

	unsigned int nsched_cls;          /* number of traffic classes */

	unsigned int max_ordird_qp;	  /* Max read depth per RDMA QP */
	unsigned int max_ird_adapter;	  /* Max read depth per adapter */
	bool ulptx_memwrite_dsgl;          /* use of T5 DSGL allowed */
	unsigned char ulp_t10dif;	  /* t10dif support for ulp */
	unsigned char ulp_crypto;	/* Crypto support */
	bool fr_nsmr_tpte_wr_support;     /* FW support for FR_NSMR_TPTE_WR */
	bool filter2_wr_support;	/* FW support for FILTER2_WR */
};

/*
 * State needed to monitor the forward progress of SGE Ingress DMA activities
 * and possible hangs.
 */
struct sge_idma_monitor_state {
	unsigned int idma_1s_thresh;	/* 1s threshold in Core Clock ticks */
	unsigned int idma_stalled[2];	/* synthesized stalled timers in HZ */
	unsigned int idma_state[2];	/* IDMA Hang detect state */
	unsigned int idma_qid[2];	/* IDMA Hung Ingress Queue ID */
	unsigned int idma_warn[2];	/* time to warning in HZ */
};

/*
 * Firmware Mailbox Command/Reply log.  All values are in Host-Endian format.
 * The access and execute times are signed in order to accommodate negative
 * error returns.
 */
struct mbox_cmd {
	u64 cmd[MBOX_LEN/8];		/* a Firmware Mailbox Command/Reply */
	u64 timestamp;			/* OS-dependent timestamp */
	u32 seqno;			/* sequence number */
	s16 access;			/* time (ms) to access mailbox */
	s16 execute;			/* time (ms) to execute */
};

struct mbox_cmd_log {
	unsigned int size;		/* number of entries in the log */
	unsigned int cursor;		/* next position in the log to write */
	u32 seqno;			/* next sequence number */
	/* variable length mailbox command log starts here */
};

/*
 * Given a pointer to a Firmware Mailbox Command Log and a log entry index,
 * return a pointer to the specified entry.
 */
static inline struct mbox_cmd *mbox_cmd_log_entry(struct mbox_cmd_log *log,
						  unsigned int entry_idx)
{
	return &((struct mbox_cmd *)&(log)[1])[entry_idx];
}

#include <t4fw_interface.h>

#define FW_VERSION(chip) ( \
	V_FW_HDR_FW_VER_MAJOR(chip##FW_VERSION_MAJOR) | \
	V_FW_HDR_FW_VER_MINOR(chip##FW_VERSION_MINOR) | \
	V_FW_HDR_FW_VER_MICRO(chip##FW_VERSION_MICRO) | \
	V_FW_HDR_FW_VER_BUILD(chip##FW_VERSION_BUILD))
#define FW_INTFVER(chip, intf) (FW_HDR_INTFVER_##intf)

struct fw_info {
	u8 chip;
	char *fs_name;
	char *fw_mod_name;
	struct fw_hdr fw_hdr;	/* XXX: waste of space, need a sparse struct */
};

struct trace_params {
	u32 data[TRACE_LEN / 4];
	u32 mask[TRACE_LEN / 4];
	unsigned short snap_len;
	unsigned short min_len;
	unsigned char skip_ofst;
	unsigned char skip_len;
	unsigned char invert;
	unsigned char port;
};

struct link_config {
	unsigned short supported;        /* link capabilities */
	unsigned short advertising;      /* advertised capabilities */
	unsigned short lp_advertising;   /* peer advertised capabilities */
	unsigned int   requested_speed;  /* speed user has requested */
	unsigned int   speed;            /* actual link speed */
	unsigned char  requested_fc;     /* flow control user has requested */
	unsigned char  fc;               /* actual link flow control */
	unsigned char  auto_fec;         /* Forward Error Correction: */
	unsigned char  requested_fec;    /*   "automatic" (IEEE 802.3), */
	unsigned char  fec;              /*   requested, and actual in use */
	unsigned char  autoneg;          /* autonegotiating? */
	unsigned char  link_ok;          /* link up? */
	unsigned char  link_down_rc;     /* link down reason */
};

/*
 * Partial EEPROM Vital Product Data structure.  Includes only the ID and
 * VPD-R sections.
 */
struct t4_vpd_hdr {
	u8  id_tag;
	u8  id_len[2];
	u8  id_data[ID_LEN];
	u8  vpdr_tag;
	u8  vpdr_len[2];
};

#include "adapter.h"

#ifndef PCI_VENDOR_ID_CHELSIO
# define PCI_VENDOR_ID_CHELSIO 0x1425
#endif

#define for_each_port(adapter, iter) \
	for (iter = 0; iter < (adapter)->params.nports; ++iter)

static inline int is_offload(const struct adapter *adap)
{
	return adap->params.offload;
}

static inline int is_crypto(const struct adapter *adap)
{
        return (adap->params.ulp_crypto & ULP_CRYPTO_LOOKASIDE);
}

static inline int is_hashfilter(const struct adapter *adap)
{
	return adap->params.hash_filter;
}

static inline int is_bypass(const adapter_t *adap)
{
	return adap->params.bypass;
}

static inline int is_bypass_device(int device)
{
	/* XXX - this should be set based upon device capabilities */
	switch(device) {
#ifdef CONFIG_CHELSIO_BYPASS
		case 0x440b:
		case 0x440c:
			return 1;
#endif

		default:
			return 0;
	}
}

static inline int is_10gbt_device(int device)
{
	/* XXX - this should be set based upon device capabilities */
	switch(device) {
		case 0x4409:
		case 0x4486:
			return 1;

		default:
			return 0;
	}
}

static inline unsigned int core_ticks_per_usec(const struct adapter *adap)
{
	return adap->params.vpd.cclk / 1000;
}

static inline unsigned int us_to_core_ticks(const struct adapter *adap,
					    unsigned int us)
{
	return (us * adap->params.vpd.cclk) / 1000;
}

static inline unsigned int core_ticks_to_us(const struct adapter *adapter,
					    unsigned int ticks)
{
	/* add Core Clock / 2 to round ticks to nearest uS */
	return ((ticks * 1000 + adapter->params.vpd.cclk/2) /
		adapter->params.vpd.cclk);
}

static inline unsigned int dack_ticks_to_usec(const struct adapter *adap,
					      unsigned int ticks)
{
	return (ticks << adap->params.tp.dack_re) / core_ticks_per_usec(adap);
}

void t4_set_reg_field(struct adapter *adap, unsigned int addr, u32 mask, u32 val);

void t4_record_mbox_marker(struct adapter *adapter,
			   const void *marker, unsigned int size);
int t4_wr_mbox_meat_timeout(struct adapter *adap, int mbox, const void *cmd,
			    int size, void *rpl, bool sleep_ok, int timeout);
int t4_wr_mbox_meat(struct adapter *adap, int mbox, const void *cmd, int size,
		    void *rpl, bool sleep_ok);

static inline int t4_wr_mbox_timeout(struct adapter *adap, int mbox,
				     const void *cmd, int size, void *rpl,
				     int timeout)
{
	return t4_wr_mbox_meat_timeout(adap, mbox, cmd, size, rpl, true,
				       timeout);
}

static inline int t4_wr_mbox(struct adapter *adap, int mbox, const void *cmd,
			     int size, void *rpl)
{
	return t4_wr_mbox_meat(adap, mbox, cmd, size, rpl, true);
}

static inline int t4_wr_mbox_ns(struct adapter *adap, int mbox, const void *cmd,
				int size, void *rpl)
{
	return t4_wr_mbox_meat(adap, mbox, cmd, size, rpl, false);
}

void t4_read_indirect(struct adapter *adap, unsigned int addr_reg,
		      unsigned int data_reg, u32 *vals, unsigned int nregs,
		      unsigned int start_idx);
void t4_write_indirect(struct adapter *adap, unsigned int addr_reg,
		       unsigned int data_reg, const u32 *vals,
		       unsigned int nregs, unsigned int start_idx);

void t4_hw_pci_read_cfg4(adapter_t *adapter, int reg, u32 *val);

struct fw_filter_wr;

void t4_intr_enable(struct adapter *adapter);
void t4_intr_disable(struct adapter *adapter);
int t4_slow_intr_handler(struct adapter *adapter);

int t4_hash_mac_addr(const u8 *addr);
int t4_link_l1cfg(struct adapter *adap, unsigned int mbox, unsigned int port,
		  struct link_config *lc);
int t4_restart_aneg(struct adapter *adap, unsigned int mbox, unsigned int port);
int t4_seeprom_read(struct adapter *adapter, u32 addr, u32 *data);
int t4_seeprom_write(struct adapter *adapter, u32 addr, u32 data);
int t4_eeprom_ptov(unsigned int phys_addr, unsigned int fn, unsigned int sz);
int t4_seeprom_wp(struct adapter *adapter, int enable);
int t4_get_raw_vpd_params(struct adapter *adapter, struct vpd_params *p);
int t4_get_vpd_params(struct adapter *adapter, struct vpd_params *p);
int t4_read_flash(struct adapter *adapter, unsigned int addr, unsigned int nwords,
		  u32 *data, int byte_oriented);
int t4_write_flash(struct adapter *adapter, unsigned int addr,
		   unsigned int n, const u8 *data, int byte_oriented);
int t4_load_fw(struct adapter *adapter, const u8 *fw_data, unsigned int size,
	       unsigned int bootstrap);
int t4_load_phy_fw(struct adapter *adap,
		   int win, t4_os_lock_t *lock,
		   int (*phy_fw_version)(const u8 *, size_t),
		   const u8 *phy_fw_data, size_t phy_fw_size);
int t4_phy_fw_ver(struct adapter *adap, int *phy_fw_ver);
int t4_fwcache(struct adapter *adap, enum fw_params_param_dev_fwcache op);
int t5_fw_init_extern_mem(struct adapter *adap);
#ifdef CHELSIO_T4_DIAGS
int t4_erase_sf(struct adapter *adapter);
#endif
int t4_load_bootcfg(struct adapter *adapter, const u8 *cfg_data, unsigned int size);
int t4_load_boot(struct adapter *adap, u8 *boot_data,
                 unsigned int boot_addr, unsigned int size);
int t4_flash_erase_sectors(struct adapter *adapter, int start, int end);
int t4_flash_cfg_addr(struct adapter *adapter);
int t4_check_fw_version(struct adapter *adap);
int t4_load_cfg(struct adapter *adapter, const u8 *cfg_data, unsigned int size);
int t4_get_fw_version(struct adapter *adapter, u32 *vers);
int t4_get_bs_version(struct adapter *adapter, u32 *vers);
int t4_get_tp_version(struct adapter *adapter, u32 *vers);
int t4_get_exprom_version(struct adapter *adapter, u32 *vers);
int t4_get_scfg_version(struct adapter *adapter, u32 *vers);
int t4_get_vpd_version(struct adapter *adapter, u32 *vers);
int t4_get_version_info(struct adapter *adapter);
void t4_dump_version_info(struct adapter *adapter);
int t4_prep_fw(struct adapter *adap, struct fw_info *fw_info,
	       const u8 *fw_data, unsigned int fw_size,
	       struct fw_hdr *card_fw, const int t4_fw_install,
	       enum dev_state state, int *reset);
int t4_wait_dev_ready(struct adapter *adapter);
enum chip_type t4_get_chip_type(struct adapter *adap, int ver);
int t4_prep_adapter(struct adapter *adapter, bool reset);
int t4_prep_pf(struct adapter *adapter);
int t4_prep_master_pf(struct adapter *adapter);
int t4_shutdown_adapter(struct adapter *adapter);

enum t4_bar2_qtype { T4_BAR2_QTYPE_EGRESS, T4_BAR2_QTYPE_INGRESS };
int t4_bar2_sge_qregs(struct adapter *adapter,
		      unsigned int qid,
		      enum t4_bar2_qtype qtype,
		      int user,
		      u64 *pbar2_qoffset,
		      unsigned int *pbar2_qid);

int t4_init_devlog_params(struct adapter *adapter, int fw_attach);
int t4_init_sge_params(struct adapter *adapter);
int t4_init_tp_params(struct adapter *adap, bool sleep_ok);
int t4_filter_field_shift(const struct adapter *adap, int filter_sel);
int t4_create_filter_info(const struct adapter *adapter,
			  u64 *filter_value, u64 *filter_mask,
			  int fcoe, int port, int vnic_id,
			  int vlan, int vlan_pcp, int vlan_dei,
			  int tos, int protocol, int ethertype,
			  int macmatch, int mpshittype, int fragmentation);
int t4_init_rss_mode(struct adapter *adap, int mbox);
int t4_init_portinfo(struct port_info *pi, int mbox,
		     int port, int pf, int vf, u8 mac[]);
int t4_port_init(struct adapter *adap, int mbox, int pf, int vf);
int t4_mirror_init(struct adapter *adap, int mbox, int pf, int vf);
void t4_fatal_err(struct adapter *adapter);
void t4_db_full(struct adapter *adapter);
void t4_db_dropped(struct adapter *adapter);
int t4_set_trace_filter(struct adapter *adapter, const struct trace_params *tp,
			int filter_index, int enable);
void t4_get_trace_filter(struct adapter *adapter, struct trace_params *tp,
			 int filter_index, int *enabled);
int t4_config_rss_range(struct adapter *adapter, int mbox, unsigned int viid,
			int start, int n, const u16 *rspq, unsigned int nrspq);
int t4_config_glbl_rss(struct adapter *adapter, int mbox, unsigned int mode,
		       unsigned int flags);
int t4_config_vi_rss(struct adapter *adapter, int mbox, unsigned int viid,
		     unsigned int flags, unsigned int defq, unsigned int skeyidx,
		     unsigned int skey);
int t4_read_rss(struct adapter *adapter, u16 *entries);
void t4_read_rss_key(struct adapter *adapter, u32 *key, bool sleep_ok);
void t4_write_rss_key(struct adapter *adap, const u32 *key, int idx,
		      bool sleep_ok);
void t4_read_rss_pf_config(struct adapter *adapter, unsigned int index,
			   u32 *valp, bool sleep_ok);
void t4_write_rss_pf_config(struct adapter *adapter, unsigned int index,
			    u32 val, bool sleep_ok);
void t4_read_rss_vf_config(struct adapter *adapter, unsigned int index,
			   u32 *vfl, u32 *vfh, bool sleep_ok);
u32 t4_read_rss_pf_map(struct adapter *adapter, bool sleep_ok);
u32 t4_read_rss_pf_mask(struct adapter *adapter, bool sleep_ok);
unsigned int t4_get_mps_bg_map(struct adapter *adapter, int pidx);
unsigned int t4_get_tp_e2c_map(struct adapter *adapter, int pidx);
unsigned int t4_get_tp_ch_map(struct adapter *adapter, int pidx);
int t4_mps_set_active_ports(struct adapter *adap, unsigned int port_mask);
int t4_read_tcb(struct adapter *adap, int win, int tid, u32 tcb[TCB_SIZE/4]);
void t4_pmtx_get_stats(struct adapter *adap, u32 cnt[], u64 cycles[]);
void t4_pmrx_get_stats(struct adapter *adap, u32 cnt[], u64 cycles[]);
void t4_read_cimq_cfg(struct adapter *adap, u16 *base, u16 *size, u16 *thres);
int t4_read_cim_ibq(struct adapter *adap, unsigned int qid, u32 *data, size_t n);
int t4_read_cim_obq(struct adapter *adap, unsigned int qid, u32 *data, size_t n);
int t4_cim_read(struct adapter *adap, unsigned int addr, unsigned int n,
		unsigned int *valp);
int t4_cim_write(struct adapter *adap, unsigned int addr, unsigned int n,
		 const unsigned int *valp);
int t4_cim_read_la(struct adapter *adap, u32 *la_buf, unsigned int *wrptr);
void t4_cim_read_pif_la(struct adapter *adap, u32 *pif_req, u32 *pif_rsp,
		unsigned int *pif_req_wrptr, unsigned int *pif_rsp_wrptr);
void t4_cim_read_ma_la(struct adapter *adap, u32 *ma_req, u32 *ma_rsp);
int t4_get_flash_params(struct adapter *adapter);

u32 t4_read_pcie_cfg4(struct adapter *adap, int reg, int drv_fw_attach);
int t4_get_util_window(struct adapter *adap, int drv_fw_attach);
void t4_setup_memwin(struct adapter *adap, u32 memwin_base, u32 window);
void t4_idma_monitor_init(struct adapter *adapter,
			  struct sge_idma_monitor_state *idma);
void t4_idma_monitor(struct adapter *adapter,
		     struct sge_idma_monitor_state *idma,
		     int hz, int ticks);
int t4_set_vf_mac_acl(struct adapter *adapter, unsigned int vf,
		      unsigned int naddr, u8 *addr);

#define T4_MEMORY_WRITE	0
#define T4_MEMORY_READ	1
int t4_memory_rw_addr(struct adapter *adap, int win,
		      u32 addr, u32 len,
		      void *hbuf, int dir);
int t4_memory_rw_mtype(struct adapter *adap, int win,
		       int mtype, u32 maddr, u32 len,
		       void *hbuf, int dir);

/* legacy compatibility routines */
static inline int t4_memory_rw(struct adapter *adap, int win,
			       int mtype, u32 maddr, u32 len,
			       void *hbuf, int dir)
{
	return t4_memory_rw_mtype(adap, win, mtype, maddr, len, hbuf, dir);
}

static inline int t4_memory_read(struct adapter *adap, int mtype, u32 addr,
				 u32 len, __be32 *buf)
{
	return t4_memory_rw(adap, MEMWIN_NIC, mtype, addr, len, buf, T4_MEMORY_READ);
}

static inline int t4_memory_write(struct adapter *adap, int mtype, u32 addr,
				  u32 len, __be32 *buf)
{
	return t4_memory_rw(adap, MEMWIN_NIC, mtype, addr, len, buf, T4_MEMORY_WRITE);
}

/**
 *	hash_mac_addr - return the hash value of a MAC address
 *	@addr: the 48-bit Ethernet MAC address
 *
 *	Hashes a MAC address according to the hash function used by hardware
 *	inexact (hash) address matching.  The description in the hardware
 *	documentation for the MPS says this:
 *
 *	    The hash function takes the 48 bit MAC address and hashes
 *	    it down to six bits.  Bit zero of the hash is the XOR of
 *	    bits 0, 6 ... 42 of the MAC address.  The other hash bits
 *	    are computed in a similar fashion ending with bit five of
 *	    the hash as the XOR of bits 5, 11 ... 47 of the MAC address.
 */
static inline int hash_mac_addr(const u8 *addr)
{
	u32 a = ((u32)addr[0] << 16) | ((u32)addr[1] << 8) | addr[2];
	u32 b = ((u32)addr[3] << 16) | ((u32)addr[4] << 8) | addr[5];

	a ^= b;
	a ^= (a >> 12);
	a ^= (a >> 6);
	return a & 0x3f;
}

extern unsigned int t4_get_regs_len(struct adapter *adapter);
extern void t4_get_regs(struct adapter *adap, void *buf, size_t buf_size);

const char *t4_get_port_type_description(enum fw_port_type port_type);
void t4_get_port_stats(struct adapter *adap, int idx, struct port_stats *p);
void t4_get_port_stats_offset(struct adapter *adap, int idx,
		struct port_stats *stats,
		struct port_stats *offset);
void t4_get_lb_stats(struct adapter *adap, int idx, struct lb_port_stats *p);
void t4_clr_port_stats(struct adapter *adap, int idx);

void t4_read_mtu_tbl(struct adapter *adap, u16 *mtus, u8 *mtu_log);
void t4_read_cong_tbl(struct adapter *adap, u16 incr[NMTUS][NCCTRL_WIN]);
void t4_read_pace_tbl(struct adapter *adap, unsigned int pace_vals[NTX_SCHED]);
void t4_get_tx_sched(struct adapter *adap, unsigned int sched, unsigned int *kbps,
		     unsigned int *ipg, bool sleep_ok);
void t4_tp_wr_bits_indirect(struct adapter *adap, unsigned int addr,
			    unsigned int mask, unsigned int val);
void t4_tp_read_la(struct adapter *adap, u64 *la_buf, unsigned int *wrptr);
void t4_tp_get_err_stats(struct adapter *adap, struct tp_err_stats *st,
			 bool sleep_ok);
void t4_tp_get_cpl_stats(struct adapter *adap, struct tp_cpl_stats *st,
			 bool sleep_ok);
void t4_tp_get_rdma_stats(struct adapter *adap, struct tp_rdma_stats *st,
			  bool sleep_ok);
void t4_get_usm_stats(struct adapter *adap, struct tp_usm_stats *st,
		      bool sleep_ok);
void t4_tp_get_tcp_stats(struct adapter *adap, struct tp_tcp_stats *v4,
			 struct tp_tcp_stats *v6, bool sleep_ok);
void t4_get_fcoe_stats(struct adapter *adap, unsigned int idx,
		       struct tp_fcoe_stats *st, bool sleep_ok);
void t4_load_mtus(struct adapter *adap, const unsigned short *mtus,
		  const unsigned short *alpha, const unsigned short *beta);

void t4_ulprx_read_la(struct adapter *adap, u32 *la_buf);

void t4_get_chan_txrate(struct adapter *adap, u64 *nic_rate, u64 *ofld_rate);
int t4_set_filter_mode(struct adapter *adap, unsigned int mode_map,
		       bool sleep_ok);
void t4_mk_filtdelwr(unsigned int ftid, struct fw_filter_wr *wr,
		     int rqtype, int qid);

int t4_fw_hello(struct adapter *adap, unsigned int mbox, unsigned int evt_mbox,
		enum dev_master master, enum dev_state *state);
int t4_fw_bye(struct adapter *adap, unsigned int mbox);
int t4_fw_reset(struct adapter *adap, unsigned int mbox, int reset);
int t4_fw_upgrade(struct adapter *adap, unsigned int mbox,
		  const u8 *fw_data, unsigned int size, int force);
int t4_fl_pkt_align(struct adapter *adap, bool is_packed);
int t4_fixup_host_params_compat(struct adapter *adap, unsigned int page_size,
				unsigned int cache_line_size,
				enum chip_type chip_compat);
int t4_fixup_host_params(struct adapter *adap, unsigned int page_size,
			 unsigned int cache_line_size);
int t4_fw_initialize(struct adapter *adap, unsigned int mbox);
int t4_query_params(struct adapter *adap, unsigned int mbox, unsigned int pf,
		    unsigned int vf, unsigned int nparams, const u32 *params,
		    u32 *val);
int t4_query_params_ns(struct adapter *adap, unsigned int mbox, unsigned int pf,
		       unsigned int vf, unsigned int nparams, const u32 *params,
		       u32 *val);
int t4_query_params_rw(struct adapter *adap, unsigned int mbox, unsigned int pf,
		       unsigned int vf, unsigned int nparams, const u32 *params,
		       u32 *val, int rw, bool sleep_ok);
int t4_set_params_timeout(struct adapter *adap, unsigned int mbox,
			  unsigned int pf, unsigned int vf,
			  unsigned int nparams, const u32 *params,
			  const u32 *val, int timeout);
int t4_set_params(struct adapter *adap, unsigned int mbox, unsigned int pf,
		  unsigned int vf, unsigned int nparams, const u32 *params,
		  const u32 *val);
int t4_cfg_pfvf(struct adapter *adap, unsigned int mbox, unsigned int pf,
		unsigned int vf, unsigned int txq, unsigned int txq_eth_ctrl,
		unsigned int rxqi, unsigned int rxq, unsigned int tc,
		unsigned int vi, unsigned int cmask, unsigned int pmask,
		unsigned int exactf, unsigned int rcaps, unsigned int wxcaps);
int t4_alloc_vi_func(struct adapter *adap, unsigned int mbox,
		     unsigned int port, unsigned int pf, unsigned int vf,
		     unsigned int nmac, u8 *mac, unsigned int *rss_size,
		     unsigned int portfunc, unsigned int idstype);
int t4_alloc_vi(struct adapter *adap, unsigned int mbox, unsigned int port,
		unsigned int pf, unsigned int vf, unsigned int nmac, u8 *mac,
		unsigned int *rss_size);
int t4_free_vi(struct adapter *adap, unsigned int mbox,
	       unsigned int pf, unsigned int vf,
	       unsigned int viid);
int t4_set_rxmode(struct adapter *adap, unsigned int mbox, unsigned int viid,
		  int mtu, int promisc, int all_multi, int bcast, int vlanex,
		  bool sleep_ok);
int t4_alloc_mac_filt(struct adapter *adap, unsigned int mbox, unsigned int viid,
		      bool free, unsigned int naddr, const u8 **addr, u16 *idx,
		      u64 *hash, bool sleep_ok);
int t4_free_mac_filt(struct adapter *adap, unsigned int mbox,
		      unsigned int viid, unsigned int naddr,
		      const u8 **addr, bool sleep_ok);
int t4_alloc_raw_mac_filt(struct adapter *adap, unsigned int viid,
			  const u8 *addr, const u8 *mask, unsigned int idx,
			  u8 lookup_type, bool sleep_ok);
int t4_change_mac(struct adapter *adap, unsigned int mbox, unsigned int viid,
		  int idx, const u8 *addr, bool persist, bool add_smt);
int t4_set_addr_hash(struct adapter *adap, unsigned int mbox, unsigned int viid,
		     bool ucast, u64 vec, bool sleep_ok);
int t4_enable_vi_params(struct adapter *adap, unsigned int mbox,
			unsigned int viid, bool rx_en, bool tx_en, bool dcb_en);
int t4_enable_vi(struct adapter *adap, unsigned int mbox, unsigned int viid,
		 bool rx_en, bool tx_en);
int t4_identify_port(struct adapter *adap, unsigned int mbox, unsigned int viid,
		     unsigned int nblinks);
int t4_mdio_rd(struct adapter *adap, unsigned int mbox, unsigned int phy_addr,
	       unsigned int mmd, unsigned int reg, unsigned int *valp);
int t4_mdio_wr(struct adapter *adap, unsigned int mbox, unsigned int phy_addr,
	       unsigned int mmd, unsigned int reg, unsigned int val);
int t4_i2c_rd(struct adapter *adap, unsigned int mbox,
	      int port, unsigned int devid,
	      unsigned int offset, unsigned int len,
	      u8 *buf);
int t4_i2c_wr(struct adapter *adap, unsigned int mbox,
	      int port, unsigned int devid,
	      unsigned int offset, unsigned int len,
	      u8 *buf);
int t4_iq_stop(struct adapter *adap, unsigned int mbox, unsigned int pf,
	       unsigned int vf, unsigned int iqtype, unsigned int iqid,
	       unsigned int fl0id, unsigned int fl1id);
int t4_iq_free(struct adapter *adap, unsigned int mbox, unsigned int pf,
	       unsigned int vf, unsigned int iqtype, unsigned int iqid,
	       unsigned int fl0id, unsigned int fl1id);
int t4_eth_eq_free(struct adapter *adap, unsigned int mbox, unsigned int pf,
		   unsigned int vf, unsigned int eqid);
int t4_ctrl_eq_free(struct adapter *adap, unsigned int mbox, unsigned int pf,
		    unsigned int vf, unsigned int eqid);
int t4_ofld_eq_free(struct adapter *adap, unsigned int mbox, unsigned int pf,
		    unsigned int vf, unsigned int eqid);
int t4_sge_ctxt_rd(struct adapter *adap, unsigned int mbox, unsigned int cid,
		   enum ctxt_type ctype, u32 *data);
int t4_sge_ctxt_rd_bd(struct adapter *adap, unsigned int cid, enum ctxt_type ctype,
		      u32 *data);
int t4_sge_ctxt_flush(struct adapter *adap, unsigned int mbox);
const char *t4_link_down_rc_str(unsigned char link_down_rc);
void t4_handle_get_port_info(struct port_info *pi, const __be64 *rpl);
int t4_update_port_info(struct port_info *pi);
int t4_handle_fw_rpl(struct adapter *adap, const __be64 *rpl);
int t4_fwaddrspace_write(struct adapter *adap, unsigned int mbox, u32 addr, u32 val);

int t4_sched_config(struct adapter *adapter, int type, int minmaxen);
int t4_sched_params(struct adapter *adapter, int type, int level, int mode,
		    int rateunit, int ratemode, int channel, int class,
		    int minrate, int maxrate, int weight, int pktsize);
int t4_config_watchdog(struct adapter *adapter, unsigned int mbox,
		       unsigned int pf, unsigned int vf,
		       unsigned int timeout, unsigned int action);
int t4_get_devlog_level(struct adapter *adapter, unsigned int *level);
int t4_set_devlog_level(struct adapter *adapter, unsigned int level);

void t4_sge_decode_idma_state(struct adapter *adapter, int state);

void t4_tp_pio_read(struct adapter *adap, u32 *buff, u32 nregs,
		    u32 start_index, bool sleep_ok);
void t4_tp_pio_write(struct adapter *adap, u32 *buff, u32 nregs,
		     u32 start_index, bool sleep_ok);
void t4_tp_tm_pio_read(struct adapter *adap, u32 *buff, u32 nregs,
		       u32 start_index, bool sleep_ok);
void t4_tp_mib_read(struct adapter *adap, u32 *buff, u32 nregs,
		    u32 start_index, bool sleep_ok);
#ifdef __cplusplus
}
#endif
#endif /* __CHELSIO_COMMON_H */
