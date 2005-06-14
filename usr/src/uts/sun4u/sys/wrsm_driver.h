/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_WRSM_DRIVER_H
#define	_SYS_WRSM_DRIVER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/wci_offsets.h>
#include <sys/wrsm_common.h>
#include <sys/wrsm_config.h>
#include <sys/wci_common.h>
#include <sys/wrsm.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * only wrsm_driver.c should include this header.
 * all others should include wrsm_lc.c
 */

/*
 * Timeout periods in seconds.  (Multiplied by MICROSEC to get the number
 * of microsecs for the requested number of seconds - for drv_to_hz().)
 */
#define	WRSM_POLL_TIMEOUT_USEC (1 * MICROSEC) /* interval for polling links */
#define	WRSM_RESTART_TIMEOUT_USEC (120 * MICROSEC) /* link restart timeout */
/* shortterm interval is given in minutes */
#define	WRSM_SHORTTERM_USEC (wrsm_shortterm_interval * 60 * MICROSEC)
#define	WRSM_LINK_MAX_WAIT_COUNT	60 /* Poll periods */
#define	WRSM_AVG_WEIGHT			10
#define	WRSM_SHORTTERM_INTERVAL		60
#define	WRSM_SHORTS_PER_LONGTERM	24


/*
 * index of register ranges in "registers" property
 */
#define	WRSM_REGS	0
#define	WRSM_SRAM	1
#define	ROUTEMAPRESET	0x0FFFFFFFFFFFFULL	/* set 16 link 3 bits = 0x7 */
#define	CE_CNTMAX	0xFF			/* reset value for ce_count */
#define	REGMASK		0x1F			/* mask for lower reg bits */

#define	UNMASKALL	0x0ULL			/* unmask all bit fields */
#define	MASKALL		0xFFFFFFFFFFFFFFFFULL

/*
 * WRSM  OBP properties
 */

#define	OBP_WRSM_PORTID	"portid"
#define	WRSM_RSM_CTR 	"rsm_controller"
#define	WRSM_ADMIN  	"admin"

#define	MAXERRORS	1000

typedef union {
	struct {
		boolean_t bad_linknum : 1;
		boolean_t bad_safari_port_id : 1;
		boolean_t bad_gnid : 1;
		boolean_t bad_cnode : 1;
		boolean_t bad_ctlr_version : 1;
		boolean_t bad_ctlr_id : 1;
		boolean_t bad_reachablewnode : 1;
		boolean_t bad_common_version : 1;
	} reasons;
	uint32_t val;
} wrsm_linkbadconfig_reasons_t;

typedef enum {
	wrsm_device,		/* a real WCI */
	wrsm_rsm_controller,	/* a pseudo dev for an RSM controller */
	wrsm_admin		/* the wrsm admin pseudo dev */
} wrsm_devi_type_t;


typedef struct {
	volatile uint64_t *wrsm_link_err_cnt_addr; /* pre-calc offset */
	wrsm_link_req_state_t link_req_state; /* link state */
	wrsm_linkbadconfig_reasons_t badconfig_reasons;
	boolean_t tell_mh_link_is_up;	/* if TRUE call call mh_link_is_up */
					/* for links just coming up */
	boolean_t user_down_requested;	/* user ioctl requested link down */
	boolean_t loopback_test_mode;
	wnodeid_t remote_wnode;
	uint32_t interval_count;
	uint32_t cont_errs;	/* # of times in a row polling found errors */
	uint32_t err_takedown_sum;
	uint32_t num_err_takedown;
	uint32_t last_err_takedown;
	uint32_t max_err_takedown;
	uint32_t avg_err_takedown;
	uint32_t num_cfg_takedown;
	uint32_t num_disconnected_takedown;
	uint32_t num_requested_bringups;
	uint32_t num_completed_bringups;
	uint32_t num_errors;
	uint32_t shortterm_errsum;
	uint32_t shortterm_last_errors;
	uint32_t shortterm_max_errors;
	uint32_t shortterm_avg_errors;
	uint32_t longterm_shortterms;
	uint32_t longterm_errsum;
	uint32_t longterm_last_errors;
	uint32_t longterm_max_errors;
	uint32_t longterm_avg_errors;
	uint16_t remote_gnids_active;
	uint32_t waiting_count;
	boolean_t poll_reachable;  /* remote end is wcx ready to be polled */
} link_t;

/* globals */
/* weight of old average in error average */
extern uint_t wrsm_avg_weight;
/* minutes in shortterm error interval */
extern uint_t wrsm_shortterm_interval;
/* number of shortterm intervals per long term interval */
extern uint_t wrsm_shorts_per_longterm;

/*
 * lc_mutex primarily is used to secure changes to the link states
 * however, in addition to protecting per link states changes, the counters:
 * oldlink_waitdown_cnt and newlink_waitup_cnt must also
 * be protected from changes of different threads. lc_mutex is also
 * used to protect any access to softsp->config.
 * newlink_waitup_cnt is important for keeping track of the NEW bringup
 * link requested initiated in lc_installconfig.
 * oldlink_waitdown_cnt is important for keeping track of the lc_cleanconfig
 * initiated takedown request.
 * the count of oldlink_waitdown_cnt & newlink_waitup_cnt is how the LC
 * differentiates between events in the LC forcing takedowns and bringup
 * and external events requesting takedown and bringups. These two counters
 * increment on request and they are decremented when the task is done.
 * They are both 0 when there are no pending external request.
 * Polling on a link starts in wciinit and ends in wcifini
 */
struct wrsm_soft_state {
	dev_info_t *dip;		/* dev info of myself */
	timeout_id_t err_timeout_id;	/* non-zero means link polling active */
	boolean_t need_err_timeout;	/* err timeout was DDI_SUSPENDED */
	timeout_id_t restart_timeout_id; /* timeout handle for link restart */
	boolean_t need_restart_timeout;	/* restart timeout was DDI_SUSPENDED */
	boolean_t suspended;		/* ddi-suspended */
	int instance;			/* DDI instance */
	int minor;			/* device minor number */
	int board;			/* Board number */
	cnodeid_t local_cnode;
	wnodeid_t local_wnode;
	gnid_t    local_gnid;
	wnodeid_t gnid_to_wnode[WRSM_MAX_WNODES];

	safari_port_t portid;		/* safari extended agent id */
	kmutex_t lc_mutex;		/* lock for link related task */
	kmutex_t wrsm_mutex;		/* mutex to protect open file flag */
	kmutex_t cmmu_mutex;		/* CMMU FLUSH mutex */
	kcondvar_t goinstallconfig;	/* condition var to signal */
					/* lc_installconfig clear to go */
	int oldlink_waitdown_cnt;	/* cnt of takedown request on old */
					/* links/existing links */
	int newlink_waitup_cnt;		/* cnt of new bringup link request */
	int open;			/* flag indicates if device is open */
	link_t links[WRSM_LINKS_PER_WCI];	/* optical links */
	clock_t shortterm_start;
	wrsm_devi_type_t type;		/* type of device  */

	off_t sramsize;
	unsigned char *wrsm_sram;	/* paddr for SRAM */
	volatile unsigned char *wrsm_regs;	/* vaddr WRSM regs */

	/*
	 * wci revision: wci1, wci2 or wci3 where
	 * wci 1 wci_id.parid = 0x4776
	 * wci 2 wci_id.parid =  0x4147
	 * wci 3 wci_id.parid =  0x4063
	 */
	int wci_rev;			/* wci1, wci2, wci3 .. ? */
	/* pre-calc offset of ecc registers */
	volatile uint64_t *wci_dco_ce_cnt_vaddr;
	volatile uint64_t *wci_dc_esr_vaddr;
	volatile uint64_t *wci_dco_state_vaddr;

	volatile uint64_t *wci_ca_esr_0_vaddr;
	volatile uint64_t *wci_ra_esr_1_vaddr;

	volatile uint64_t *wci_ca_ecc_addr_vaddr;
	volatile uint64_t *wci_ra_ecc_addr_vaddr;

	volatile uint64_t *wci_cci_esr_vaddr;

	wrsm_wci_data_t *config;	/* configuration data for wci */
	wrsm_controller_t *ctlr_config;	/* config for entire controller */
	ncwci_handle_t  nc;		/* opaque NC handles */

	/* WCI common soft state */
	struct wci_common_soft_state wci_common_softst;

	/* kstat structs */
	kstat_t *wrsm_wci_ksp;
	/* kstat saved values */
	uint32_t uc_sram_ecc_error;
	uint32_t sram_ecc_errsum;
	uint32_t num_sram_ecc_errors;
	uint32_t last_sram_ecc_errors;
	uint32_t max_sram_ecc_errors;
	uint32_t avg_sram_ecc_errors;	/* weighted average */
};


typedef struct wrsm_soft_state wrsm_softstate_t;

/* Use physical address for SRAM loads/stores */
#define	LOADPHYS(a, b) ((a) = lddphysio((uint64_t)(b)))
#define	STOREPHYS(a, b) stdphysio((uint64_t)(b), (a))

/*
 * wrsm open flag
 */
#define	WRSM_OPEN_EXCLUSIVE	(-1)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_WRSM_DRIVER_H */
