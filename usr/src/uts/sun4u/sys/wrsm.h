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

#ifndef _SYS_WRSM_H
#define	_SYS_WRSM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/kstat.h>
#include <sys/wrsm_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	WRSM_CLASS "wrsm"
#define	WRSM_SUBCLASS_LINKUP "link-up"
#define	WRSM_SUBCLASS_LINKDOWN "link-down"
#define	WRSM_SUBCLASS_NEW_NODE "new-node-route"
#define	WRSM_SUBCLASS_LOST_NODE "lost-node-route"
#define	WRSM_SUBCLASS_NEW_CONFIG "new-config"

/*
 * WRSM ioctl interface.
 */

#define	WRSM_IOC		('W'<<8)

/* Admin device ioctls */
#define	WRSM_CONTROLLERS	(WRSM_IOC|0)	/* # of registered rsmctlrs */
#define	WRSM_REPLACECFG		(WRSM_IOC|1)
#define	WRSM_CHECKCFG		(WRSM_IOC|2)
#define	WRSM_INSTALLCFG		(WRSM_IOC|3)
#define	WRSM_INITIALCFG		(WRSM_IOC|4)
#define	WRSM_REMOVECFG		(WRSM_IOC|5)
#define	WRSM_GETCFG		(WRSM_IOC|6)
#define	WRSM_ENABLECFG		(WRSM_IOC|7)
#define	WRSM_STARTCFG		(WRSM_IOC|8)
#define	WRSM_STOPCFG		(WRSM_IOC|9)

/* WCI device ioctls */
#define	WRSM_LC_READCSR		(WRSM_IOC|20)
#define	WRSM_LC_WRITECSR	(WRSM_IOC|21)
#define	WRSM_LC_READCESR	(WRSM_IOC|22)
#define	WRSM_LC_WRITECESR	(WRSM_IOC|23)
#define	WRSM_LC_UPDATECMMU	(WRSM_IOC|24)
#define	WRSM_LC_READCMMU	(WRSM_IOC|25)

/* RSM-controller device ioctls */
#define	WRSM_CTLR_PING		(WRSM_IOC|30)
#define	WRSM_CTLR_MBOX		(WRSM_IOC|31)
#define	WRSM_CTLR_SESS		(WRSM_IOC|38)

/* WCI device ioctl to support link loopback testing */
#define	WRSM_WCI_LOOPBACK_ON	(WRSM_IOC|40)  /* enable loopback link */
#define	WRSM_WCI_LOOPBACK_OFF	(WRSM_IOC|41)  /* disable loopback link */
#define	WRSM_WCI_LINKTEST	(WRSM_IOC|42)  /* test loopback link */
#define	WRSM_WCI_CLAIM		(WRSM_IOC|43)  /* reserve WCI for testing */
#define	WRSM_WCI_RELEASE	(WRSM_IOC|44)
#define	WRSM_WCI_LINKUP		(WRSM_IOC|45)
#define	WRSM_WCI_LINKDOWN	(WRSM_IOC|46)

#define	WRSM_CTLR_MEM_LOOPBACK	(WRSM_IOC|50)	/* memory loopback test */

/* Mailbox ioctl sub-commands */
#define	WRSM_CTLR_UPLINK	1
#define	WRSM_CTLR_DOWNLINK	2
#define	WRSM_CTLR_SET_LED	3
#define	WRSM_CTLR_ALLOC_SLICES	4
#define	WRSM_CTLR_SET_SEPROM	5

/* Plugin librsmwrsm.so ioctls to request small_puts of the driver */
#define	WRSM_CTLR_PLUGIN_SMALLPUT	7
#define	WRSM_CTLR_PLUGIN_GETLOCALNODE	8

/* Session ioctl sub-commands */
#define	WRSM_CTLR_SESS_START	1
#define	WRSM_CTLR_SESS_END	2
#define	WRSM_CTLR_SESS_ENABLE	3
#define	WRSM_CTLR_SESS_DISABLE	4
#define	WRSM_CTLR_SESS_GET	5

typedef struct wrsm_linktest_arg {
	uint16_t link_num;	/* link to test */
	uint32_t pattern;	/* data to send via user_data (max 18 bits) */
	uint64_t link_error_count; /* copy of wci_sw_link_error_count */
	uint64_t link_status;	/* copy of wci_sw_link_status */
	uint64_t link_esr;	/* copy of wci_link_esr */
	uint64_t sw_esr;	/* copy of wci_sw_esr */
	uint64_t link_control;	/* copy of wci_sw_link_control */
} wrsm_linktest_arg_t;


/*
 * 8 pages are allocated, exported through the WCI, and imported from the
 * local node.  Each requested pattern is written then read in sequential
 * 64 byte chunks, starting at offset 0, until the entire page has been
 * read/written.  (One pattern is completed across the entire page before
 * the next is started.) The starting physical address of the first
 * allocated page is stored in the paddr field of the arg parameter on
 * return from the ioctl.
 *
 * Around each pattern, a barrier is opened and closed to detect network
 * errors.  If a barrier close detects an error, the ioctl fails and errno
 * is set to ENETRESET.
 *
 * If a read does not return the written pattern, the ioctl fails and errno
 * is set to EIO.  The pattern encountering the error is stored in the
 * pattern_error field of the arg parameter, and the local physical address
 * of the exact 64 byte region with the error is stored in the paddr field.
 *
 * Other errnos may be returned; these typically indicate problems in the
 * OS or with the caller's input.
 *
 */

#define	WRSM_SSO_PATTERN	0x01
#define	WRSM_SLOWMARCH_PATTERN	0x02
#define	WRSM_FASTMARCH_PATTERN	0x04
#define	WRSM_XTALK_PATTERN	0x08

#define	WRSM_MAX_PATTERN	4		/* number of valid bits */


typedef struct wrsm_memloopback_arg {
	uint_t patterns;
	uint64_t paddr;
	uint64_t error_pattern;
	unsigned char expected_data[64];
	unsigned char actual_data[64];
} wrsm_memloopback_arg_t;

/*
 * There are 3 kstats associated with RSM:
 *    1. A WCI and its links (status)
 *    2. Routes
 *    3. RSM controller (rsmpi_stat)
 */

/* There are two kstat modules */
#define	WRSM_KSTAT_WRSM		"wrsm"
#define	WRSM_KSTAT_WRSM_ROUTE	"wrsm_route"

/* The following are the names for the kstats */
#define	WRSM_KSTAT_STATUS	"status"

/*
 * The name of the route kstat is defined dynamically
 * as "FM-node-name" -- this is a name of a remote node.
 */

/*
 * LC Link States
 */
typedef enum {
	lc_up,			/* lasers have been established */
	lc_down,		/* paroli present, lasers are not on */
	lc_not_there,		/* no paroli is present */
	sc_wait_down,		/* waiting for SC to take down link */
	sc_wait_up,		/* waiting for SC to bring up link */
	sc_wait_errdown		/* link down wait on sc due to error */
} wrsm_link_req_state_t;

/* event types for sys event daemon: syseventd */
typedef enum {
	link_up,
	link_down,
	new_node_route, /* new or modified routes to get to remote host */
	lost_node_route, /* driver removes route to a remote host */
	new_config /* new configuration has occured */
} wrsm_sys_event_t;


/*
 * Phys Link States
 */
typedef enum {
	phys_off,		/* link is off */
	phys_failover,		/* failover mode */
	phys_seek,		/* link is in seek state */
	phys_in_use		/* link is in use */
} wrsm_phys_link_state_t;

/* Names for fields in the status kstat */
#define	WRSMKS_WCI_VERSION_NAMED	"wci_version"
#define	WRSMKS_CONTROLLER_ID_NAMED	"controller_id"
#define	WRSMKS_PORTID			"portid"
#define	WRSMKS_ERROR_LIMIT		"error_limit"
#define	WRSMKS_ERRSTAT_INTERVAL		"errstat_interval"
#define	WRSMKS_INTERVALS_PER_LT		"intervals_per_lt"
#define	WRSMKS_AVG_WEIGHT		"avg_weight"
#define	WRSMKS_VALID_LINK		"valid_link_%d"
#define	WRSMKS_REMOTE_CNODE_ID		"remote_cnode_id_%d"
#define	WRSMKS_REMOTE_WNODE		"remote_wnode_id_%d"
#define	WRSMKS_REMOTE_WCI_PORTID	"remote_wci_portid_%d"
#define	WRSMKS_REMOTE_LINKNUM		"remote_linknum_%d"
#define	WRSMKS_LC_LINK_STATE		"LC_link_state_%d"
#define	WRSMKS_PHYS_LINK_STATE		"phys_link_state_%d"
#define	WRSMKS_PHYS_LASER_ENABLE	"laser enabled_%d"
#define	WRSMKS_PHYS_XMIT_ENABLE		"transmit enable_%d"
#define	WRSMKS_LINK_STATE		"link_state_%d"
#define	WRSMKS_LINK_ERR_TAKEDOWNS	"link_err_takedowns_%d"
#define	WRSMKS_LAST_LINK_ERR_TAKEDOWNS	"last_link_err_takedowns_%d"
#define	WRSMKS_MAX_LINK_ERR_TAKEDOWNS	"max_link_err_takedowns_%d"
#define	WRSMKS_AVG_LINK_ERR_TAKEDOWNS	"avg_link_err_takedowns_%d"
#define	WRSMKS_LINK_DISCON_TAKEDOWNS 	"link_disconnected_takedowns_%d"
#define	WRSMKS_LINK_CFG_TAKEDOWNS	"link_cfg_takedowns_%d"
#define	WRSMKS_LINK_FAILED_BRINGUPS	"link_failed_bringups_%d"
#define	WRSMKS_LINK_INTERVAL_COUNT	"link_interval_count_%d"
#define	WRSMKS_LINK_ENABLED		"link_enabled_%d"
#define	WRSMKS_LINK_ERRORS		"link_errors_%d"
#define	WRSMKS_LAST_LINK_ERRORS		"last_link_errors_%d"
#define	WRSMKS_MAX_LINK_ERRORS		"max_link_errors_%d"
#define	WRSMKS_AVG_LINK_ERRORS		"avg_link_errors_%d"
#define	WRSMKS_LAST_LT_LINK_ERRORS	"last_lt_link_errors_%d"
#define	WRSMKS_MAX_LT_LINK_ERRORS	"max_lt_link_errors_%d"
#define	WRSMKS_AVG_LT_LINK_ERRORS	"avg_lt_link_errors_%d"
#define	WRSMKS_AUTO_SHUTDOWN_EN		"auto_shutdown_en_%d"
#define	WRSMKS_CLUSTER_ERROR_COUNT	"cluster_error_count"
#define	WRSMKS_UC_SRAM_ECC_ERROR	"uc_sram_ecc_error"
#define	WRSMKS_SRAM_ECC_ERRORS		"sram_ecc_errors"
#define	WRSMKS_LAST_SRAM_ECC_ERRORS	"last_sram_ecc_errors"
#define	WRSMKS_MAX_SRAM_ECC_ERRORS	"max_sram_ecc_errors"
#define	WRSMKS_AVG_SRAM_ECC_ERRORS	"avg_sram_ecc_errors"

#define	WRSM_KSTAT_NO_CTRLR	-1
#define	WRSMKS_LINK_PRESENT	1
#define	WRSMKS_LINK_NOT_PRESENT	0

typedef struct wrsm_status_kstat {
	kstat_named_t ks_version;
	kstat_named_t controller_id;
	kstat_named_t portid;
	kstat_named_t error_limit;
	kstat_named_t errstat_interval;
	kstat_named_t intervals_per_lt;
	kstat_named_t avg_weight;
	kstat_named_t valid_link[WRSM_LINKS_PER_WCI];
	kstat_named_t remote_cnode_id[WRSM_LINKS_PER_WCI];
	kstat_named_t remote_wnode_id[WRSM_LINKS_PER_WCI];
	kstat_named_t remote_wci_portid[WRSM_LINKS_PER_WCI];
	kstat_named_t remote_linknum[WRSM_LINKS_PER_WCI];
	kstat_named_t state[WRSM_LINKS_PER_WCI];
	kstat_named_t laser[WRSM_LINKS_PER_WCI];
	kstat_named_t xmit_enable[WRSM_LINKS_PER_WCI];
	kstat_named_t link_state[WRSM_LINKS_PER_WCI];
	kstat_named_t link_err_takedowns[WRSM_LINKS_PER_WCI];
	kstat_named_t last_link_err_takedowns[WRSM_LINKS_PER_WCI];
	kstat_named_t max_link_err_takedowns[WRSM_LINKS_PER_WCI];
	kstat_named_t avg_link_err_takedowns[WRSM_LINKS_PER_WCI];
	kstat_named_t link_disconnected_takedowns[WRSM_LINKS_PER_WCI];
	kstat_named_t link_cfg_takedowns[WRSM_LINKS_PER_WCI];
	kstat_named_t link_failed_bringups[WRSM_LINKS_PER_WCI];
	kstat_named_t link_interval_count[WRSM_LINKS_PER_WCI];
	kstat_named_t link_enabled[WRSM_LINKS_PER_WCI];
	kstat_named_t link_errors[WRSM_LINKS_PER_WCI];
	kstat_named_t last_link_errors[WRSM_LINKS_PER_WCI];
	kstat_named_t max_link_errors[WRSM_LINKS_PER_WCI];
	kstat_named_t avg_link_errors[WRSM_LINKS_PER_WCI];
	kstat_named_t last_lt_link_errors[WRSM_LINKS_PER_WCI];
	kstat_named_t max_lt_link_errors[WRSM_LINKS_PER_WCI];
	kstat_named_t avg_lt_link_errors[WRSM_LINKS_PER_WCI];
	kstat_named_t auto_shutdown_en[WRSM_LINKS_PER_WCI];
	kstat_named_t cluster_error_count;
	kstat_named_t uc_sram_ecc_error;
	kstat_named_t sram_ecc_errors;
	kstat_named_t last_sram_ecc_errors;
	kstat_named_t max_sram_ecc_errors;
	kstat_named_t avg_sram_ecc_errors;
} wrsm_status_kstat_t;

/*
 * wrsm routes kstat names and struct
 */
#define	WRSMKS_CONFIG_VERSION_NAMED	"config-version"
#define	WRSMKS_ROUTE_TYPE_NAMED		"route-type"
#define	WRSMKS_NUM_WCIS			"num_wcis"
#define	WRSMKS_NUM_STRIPES		"num_stripes"
#define	WRSMKS_NUMCHANGES		"num_changes"
#define	WRSMKS_CNODEID			"cnodeid"
#define	WRSMKS_FMNODEID			"fmnodeid"
#define	WRSMKS_ROUTE_PORTID		"route%d_portid"
#define	WRSMKS_ROUTE_INSTANCE		"route%d_instance"
#define	WRSMKS_ROUTE_NUMHOPS		"route%d_numhops"
#define	WRSMKS_ROUTE_NUMLINKS		"route%d_numlinks"
#define	WRSMKS_ROUTE_LINKID		"route%d_linkid%d"
#define	WRSMKS_ROUTE_NODEID		"route%d_nodeid%d"
#define	WRSMKS_ROUTE_GNID		"route%d_gnid%d"

typedef struct wrsm_route_kstat {
	kstat_named_t version;
	kstat_named_t type;
	kstat_named_t num_wcis;
	kstat_named_t num_stripes;
	kstat_named_t num_changes;
	kstat_named_t cnodeid;
	kstat_named_t fmnodeid;
	kstat_named_t portid[WRSM_MAX_WCIS_PER_STRIPE];
	kstat_named_t instance[WRSM_MAX_WCIS_PER_STRIPE];
	kstat_named_t numhops[WRSM_MAX_WCIS_PER_STRIPE];
	kstat_named_t numlinks[WRSM_MAX_WCIS_PER_STRIPE];
	kstat_named_t linkid[WRSM_MAX_WCIS_PER_STRIPE][WRSM_MAX_DNIDS];
	kstat_named_t nodeid[WRSM_MAX_WCIS_PER_STRIPE][WRSM_MAX_DNIDS];
	kstat_named_t gnid[WRSM_MAX_WCIS_PER_STRIPE][WRSM_MAX_DNIDS];
} wrsm_route_kstat_t;

/*
 * rsmpi_stat kstat
 * plus four wrsm specific fields
 */

#define	WRSMKS_FREE_CMMU_ENTRIES	"free_cmmu_entries"
#define	WRSMKS_NUM_RECONFIGS		"num_reconfigs"
#define	WRSMKS_RSM_NUM_WCIS		"num_wcis"
#define	WRSMKS_RSM_AVAIL_WCIS		"avail_wcis"

typedef struct wrsm_rsmpi_stat {
	kstat_named_t num_reconfigs;
	kstat_named_t num_wcis;
	kstat_named_t avail_wcis;
	kstat_named_t free_cmmu_entries;
	kstat_named_t ctlr_state;		/* required by rsmpi */
	kstat_named_t addr;			/* required by rsmpi */
	kstat_named_t ex_memsegs;		/* required by rsmpi */
	kstat_named_t ex_memsegs_pub;		/* required by rsmpi */
	kstat_named_t ex_memsegs_con;		/* required by rsmpi */
	kstat_named_t bytes_bound;		/* required by rsmpi */
	kstat_named_t im_memsegs_con;		/* required by rsmpi */
	kstat_named_t sendqs;			/* required by rmspi */
	kstat_named_t handlers;			/* required by rsmpi */
} wrsm_rsmpi_stat_t;

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_WRSM_H */
