/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Racktop Systems, Inc.
 */
#ifndef _MFI_EVT_H
#define	_MFI_EVT_H

#include <sys/types.h>
#include <sys/debug.h>

#include <sys/scsi/adapters/mfi/mfi.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct mfi_aen			mfi_aen_t;

typedef struct mfi_evt			mfi_evt_t;
typedef struct mfi_evt_log_info		mfi_evt_log_info_t;
typedef struct mfi_evt_detail		mfi_evt_detail_t;
typedef struct mfi_evt_list		mfi_evt_list_t;

typedef struct mfi_evtarg_cdb_sense	mfi_evtarg_cdb_sense_t;
typedef struct mfi_evtarg_ld		mfi_evtarg_ld_t;
typedef struct mfi_evtarg_ld_count	mfi_evtarg_ld_count_t;
typedef struct mfi_evtarg_ld_lba	mfi_evtarg_ld_lba_t;
typedef struct mfi_evtarg_ld_owner	mfi_evtarg_ld_owner_t;
typedef struct mfi_evtarg_ld_lba_pd_lba	mfi_evtarg_ld_lba_pd_lba_t;
typedef struct mfi_evtarg_ld_progress	mfi_evtarg_ld_progress_t;
typedef struct mfi_evtarg_ld_state	mfi_evtarg_ld_state_t;
typedef	struct mfi_evtarg_ld_strip	mfi_evtarg_ld_strip_t;
typedef struct mfi_evtarg_pd		mfi_evtarg_pd_t;
typedef struct mfi_evtarg_pd_err	mfi_evtarg_pd_err_t;
typedef struct mfi_evtarg_pd_lba	mfi_evtarg_pd_lba_t;
typedef struct mfi_evtarg_pd_lba_ld	mfi_evtarg_pd_lba_ld_t;
typedef struct mfi_evtarg_pd_progress	mfi_evtarg_pd_progress_t;
typedef struct mfi_evtarg_pd_state	mfi_evtarg_pd_state_t;
typedef struct mfi_evtarg_pci		mfi_evtarg_pci_t;
typedef struct mfi_evtarg_time		mfi_evtarg_time_t;
typedef struct mfi_evtarg_ecc		mfi_evtarg_ecc_t;


/*
 * Asynchronous Event Notifications
 */
#define	MFI_EVT_CFG_CLEARED			0x0004
#define	MFI_EVT_CTRL_PATROL_READ_COMPLETE	0x0023
#define	MFI_EVT_CTRL_PATROL_READ_RESUMED	0x0026
#define	MFI_EVT_CTRL_PATROL_READ_START		0x0027
#define	MFI_EVT_LD_BG_INIT_PROGRESS		0x0034
#define	MFI_EVT_LD_CC_COMPLETE			0x003a
#define	MFI_EVT_LD_CC_PROGRESS			0x0041
#define	MFI_EVT_LD_CC_STARTED			0x0042
#define	MFI_EVT_LD_INIT_ABORTED		0x0043
#define	MFI_EVT_LD_INIT_PROGRESS		0x0045
#define	MFI_EVT_LD_FAST_INIT_STARTED		0x0046
#define	MFI_EVT_LD_FULL_INIT_STARTED		0x0047
#define	MFI_EVT_LD_INIT_COMPLETE		0x0048
#define	MFI_EVT_LD_PROP_CHANGED		0x0049
#define	MFI_EVT_LD_STATE_CHANGE		0x0051
#define	MFI_EVT_PD_INSERTED			0x005b
#define	MFI_EVT_PD_PATROL_READ_PROGRESS	0x005e
#define	MFI_EVT_PD_REMOVED			0x0070
#define	MFI_EVT_PD_CHANGED			0x0072
#define	MFI_EVT_LD_CREATED			0x008a
#define	MFI_EVT_LD_DELETED			0x008b
#define	MFI_EVT_FOREIGN_CFG_IMPORTED		0x00db
#define	MFI_EVT_LD_OPTIMAL			0x00f9
#define	MFI_EVT_LD_OFFLINE			0x00fc
#define	MFI_EVT_PD_RESET			0x010c
#define	MFI_EVT_CTRL_PATROL_READ_CANT_START	0x0124
#define	MFI_EVT_CTRL_PROP_CHANGED		0x012f
#define	MFI_EVT_LD_BBT_CLEARED			0x014f
#define	MFI_EVT_CTRL_HOST_BUS_SCAN_REQD	0x0152
#define	MFI_EVT_LD_AVAILABLE			0x0172
#define	MFI_EVT_CTRL_PERF_COLLECTION		0x017e
#define	MFI_EVT_CTRL_BOOTDEV_SET		0x01ec
#define	MFI_EVT_CTRL_BOOTDEV_RESET		0x01f3
#define	MFI_EVT_CTRL_PERSONALITY_CHANGE	0x0206
#define	MFI_EVT_CTRL_PERSONALITY_CHANGE_PEND	0x0222
#define	MFI_EVT_CTRL_NR_OF_VALID_SNAPDUMP	0x024e

#define	MFI_EVT_CLASS_DEBUG			(int8_t)-2
#define	MFI_EVT_CLASS_PROGRESS			(int8_t)-1
#define	MFI_EVT_CLASS_INFO			0
#define	MFI_EVT_CLASS_WARNING			1
#define	MFI_EVT_CLASS_CRITICAL			2
#define	MFI_EVT_CLASS_FATAL			3
#define	MFI_EVT_CLASS_DEAD			4

#define	MFI_EVT_LOCALE_LD			0x0001
#define	MFI_EVT_LOCALE_PD			0x0002
#define	MFI_EVT_LOCALE_ENCL			0x0004
#define	MFI_EVT_LOCALE_BBU			0x0008
#define	MFI_EVT_LOCALE_SAS			0x0010
#define	MFI_EVT_LOCALE_CTRL			0x0020
#define	MFI_EVT_LOCALE_CONFIG			0x0040
#define	MFI_EVT_LOCALE_CLUSTER			0x0080
#define	MFI_EVT_LOCALE_ALL			0xffff

#define	MFI_EVT_ARGS_NONE			0
#define	MFI_EVT_ARGS_CDB_SENSE			1
#define	MFI_EVT_ARGS_LD				2
#define	MFI_EVT_ARGS_LD_COUNT			3
#define	MFI_EVT_ARGS_LD_LBA			4
#define	MFI_EVT_ARGS_LD_OWNER			5
#define	MFI_EVT_ARGS_LD_LBA_PD_LBA		6
#define	MFI_EVT_ARGS_LD_PROG			7
#define	MFI_EVT_ARGS_LD_STATE			8
#define	MFI_EVT_ARGS_LD_STRIP			9
#define	MFI_EVT_ARGS_PD				10
#define	MFI_EVT_ARGS_PD_ERR			11
#define	MFI_EVT_ARGS_PD_LBA			12
#define	MFI_EVT_ARGS_PD_LBA_LD			13
#define	MFI_EVT_ARGS_PD_PROG			14
#define	MFI_EVT_ARGS_PD_STATE			15
#define	MFI_EVT_ARGS_PCI			16
#define	MFI_EVT_ARGS_RATE			17
#define	MFI_EVT_ARGS_STR			18
#define	MFI_EVT_ARGS_TIME			19
#define	MFI_EVT_ARGS_ECC			20

#pragma pack(1)

struct mfi_aen {
	uint16_t	aen_host_no;
	uint16_t	aen_cmd_status;
	uint32_t	aen_seqnum;
	uint32_t	aen_class_locale_word;
};

struct mfi_evt {
	uint16_t	evt_locale;
	uint8_t		evt_rsvd;
	int8_t		evt_class;
};

struct mfi_evt_log_info {
	uint32_t	eli_newest_seqnum;
	uint32_t	eli_oldest_seqnum;
	uint32_t	eli_clear_seqnum;
	uint32_t	eli_shutdown_seqnum;
	uint32_t	eli_boot_seqnum;
};

struct mfi_evtarg_ld {
	uint16_t	el_tgtid;
	uint8_t		el_ld_id;
	uint8_t		el_rsvd;
};

struct mfi_evtarg_pd {
	uint16_t	ep_dev_id;
	uint8_t		ep_enc_idx;
	uint8_t		ep_slot;
};

struct mfi_evtarg_cdb_sense {
	mfi_evtarg_pd_t	cs_pd;
	uint8_t		cs_cdb_len;
	uint8_t		cs_sense_len;
	uint8_t		cs_rsvd[2];
	uint8_t		cs_cdb[16];
	uint8_t		cs_sense[64];
};

struct mfi_evtarg_ld_count {
	mfi_evtarg_ld_t	lc_ld;
	uint64_t	lc_count;
};

struct mfi_evtarg_ld_lba {
	uint64_t	ll_lba;
	mfi_evtarg_ld_t	ll_ld;
};

struct mfi_evtarg_ld_owner {
	mfi_evtarg_ld_t	lo_ld;
	uint32_t	lo_prev_owner;
	uint32_t	lo_new_owner;
};

struct mfi_evtarg_ld_lba_pd_lba {
	uint64_t	llpl_ld_lba;
	uint64_t	llpl_pd_lba;
	mfi_evtarg_ld_t	llpl_ld;
	mfi_evtarg_pd_t	llpl_pd;
};

struct mfi_evtarg_ld_progress {
	mfi_evtarg_ld_t	lp_ld;
	mfi_progress_t	lp_progress;
};

struct mfi_evtarg_ld_state {
	mfi_evtarg_ld_t	ls_ld;
	uint32_t	ls_prev_state;
	uint32_t	ls_new_state;
};

struct mfi_evtarg_ld_strip {
	uint64_t	ls_strip;
	mfi_evtarg_ld_t	ls_ld;
};

struct mfi_evtarg_pd_err {
	mfi_evtarg_pd_t	pe_pd;
	uint64_t	pe_err;
};

struct mfi_evtarg_pd_lba {
	uint64_t	pl_lba;
	mfi_evtarg_pd_t	pl_pd;
};

struct mfi_evtarg_pd_lba_ld {
	uint64_t	pll_lba;
	mfi_evtarg_pd_t	pll_pd;
	mfi_evtarg_ld_t	pll_ld;
};

struct mfi_evtarg_pd_progress {
	mfi_evtarg_pd_t	pp_pd;
	mfi_progress_t	pp_progress;
};

struct mfi_evtarg_pd_state {
	mfi_evtarg_pd_t	ps_pd;
	uint32_t	ps_prev_state;
	uint32_t	ps_new_state;
};

struct mfi_evtarg_pci {
	uint16_t	pci_vendor_id;
	uint16_t	pci_device_id;
	uint16_t	pci_sub_vendor_id;
	uint16_t	pci_sub_device_id;
};

struct mfi_evtarg_time {
	uint32_t	t_rtc;
	uint16_t	t_elapsed;
};

struct mfi_evtarg_ecc {
	uint32_t	ecc_ecar;
	uint32_t	ecc_elog;
	char		ecc_str[64];
};

struct mfi_evt_detail {
	uint32_t	evt_seqnum;
	uint32_t	evt_timestamp;
	uint32_t	evt_code;
	mfi_evt_t	evt_cl;
	uint8_t		evt_argtype;
	uint8_t		evt_rsvd2[15];
	union {
		mfi_evtarg_cdb_sense_t		evt_cdb_sense;
		mfi_evtarg_ld_t			evt_ld;
		mfi_evtarg_ld_count_t		evt_ld_count;
		mfi_evtarg_ld_lba_t		evt_ld_lba;
		mfi_evtarg_ld_owner_t		evt_ld_owner;
		mfi_evtarg_ld_lba_pd_lba_t	evt_ld_lba_pd_lba;
		mfi_evtarg_ld_progress_t	evt_ld_progress;
		mfi_evtarg_ld_state_t		evt_ld_state;
		mfi_evtarg_ld_strip_t		evt_ld_strip;
		mfi_evtarg_pd_t			evt_pd;
		mfi_evtarg_pd_err_t		evt_pd_err;
		mfi_evtarg_pd_lba_t		evt_pd_lba;
		mfi_evtarg_pd_lba_ld_t		evt_pd_lba_ld;
		mfi_evtarg_pd_progress_t	evt_pd_progress;
		mfi_evtarg_pd_state_t		evt_pd_state;
		mfi_evtarg_pci_t		evt_pci;
		uint32_t			evt_rebuild_rate;
		mfi_evtarg_time_t		evt_time;
		mfi_evtarg_ecc_t		evt_ecc;

		char				evt_str[96];
	};
	char		evt_descr[128];
};
CTASSERT(sizeof (mfi_evt_detail_t) == 256);

struct mfi_evt_list {
	uint32_t		el_count;
	uint32_t		el_rsvd;
	mfi_evt_detail_t	el_evt[0];
};

#pragma pack(0)


#ifdef __cplusplus
}
#endif

#endif	/* _MFI_EVT_H */
