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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _WRSM_PLAT_H
#define	_WRSM_PLAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WildCat RSM driver platform-specific module interface
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/wrsm.h>
#include <sys/wrsm_types.h>
#include <sys/wrsm_common.h>

/* Possible per-link LED states */
#define	LEDBOTHOFF	0
#define	LEDLOWERON	1
#define	LEDUPPERON	2
#define	LEDBOTHON	3

/* Possible values for link_state */
#define	LINK_STATE_OFF		0
#define	LINK_STATE_SEEK		2
#define	LINK_STATE_IN_USE	3
#define	LINK_STATE_NO_CHANGE	4

#define	END_STATUS_NOT_READY	0
#define	END_STATUS_NEAR_READY	1
#define	END_STATUS_ALL_READY	3

/*
 * remote wnode argument to _uplink and _downlink to indicate link
 * should be in loopback mode
 */
#define	LOOPBACK_WNODE	WRSM_MAX_WNODES+1

/* I have no idea how big this should actually be */
#define	WIB_SEPROM_MSG_SIZE 64

/* Typedefs for ncslice programming */
typedef enum {
	WRSM_NCOWNER_NOT_CLAIMED = 0,
	WRSM_NCOWNER_NONE = 1,
	WRSM_NCOWNER_WCI = 2,
	WRSM_NCOWNER_STRIPEGROUP = 3
} wrsm_ncowner_t;

typedef enum {
	wrsm_node_serengeti,
	wrsm_node_wssm,
	wrsm_node_starcat
} wrsm_node_types_t;

typedef union {
	safari_port_t wci_id;
	wrsm_stripe_group_t *stripe_group;
} wrsm_ncowner_id_t;

typedef struct {
	wrsm_ncowner_t owner_type;
	wrsm_ncowner_id_t owner;
} wrsm_ncowner_map_t;

typedef struct wrsm_plat_ops {
	void (*link_up)(safari_port_t wci_id, uint32_t link_num,
	    fmnodeid_t remote_fmnodeid, gnid_t remote_gnid,
	    uint32_t remote_link_num, safari_port_t remote_port,
	    uint64_t remote_partition_version, uint32_t remote_partition_id);

	void (*link_down)(safari_port_t wci_id, uint32_t local_link_num);
	void (*sc_failed)();

	/* The following callbacks are for testing purposes only */
	struct wrsm_soft_state *(*get_softstate)(safari_port_t
	    wci_id);
	void (*get_remote_data)(safari_port_t wci_id,
	    uint32_t link_num, fmnodeid_t *remote_fmnodeid,
	    gnid_t *remote_gnid, linkid_t *remote_link,
	    safari_port_t *remote_port, volatile uchar_t **wrsm_regs);
} wrsm_plat_ops_t;

/* Format of data for wrsmplat_set_seprom data */
typedef struct wrsm_wib_ecc_error {
	uint32_t ce : 1;
	uint32_t syndrome : 7;
	uint32_t address : 24;
} wrsm_wib_ecc_error_t;

#define	WRSM_WIB_SEPROM_TYPE_ECCERR	1

typedef struct wrsm_seprom_data {
	uint32_t type;
	union {
		wrsm_wib_ecc_error_t eccerr;
	} data;

} wrsm_seprom_data_t;

int wrsmplat_reg_callbacks(wrsm_plat_ops_t *ops);
int wrsmplat_unreg_callbacks(void);
void wrsmplat_suspend(safari_port_t wci);
void wrsmplat_resume(safari_port_t wci);

int wrsmplat_uplink(safari_port_t wci, linkid_t link, gnid_t gnid,
    fmnodeid_t fmnodeid, uint64_t partition_version, uint32_t controller_id,
    boolean_t loopback);
int wrsmplat_downlink(safari_port_t wci, linkid_t link, boolean_t loopback);
int wrsmplat_set_led(safari_port_t wci, linkid_t link, int led_state);
int wrsmplat_alloc_slices(ncslice_bitmask_t requested,
    ncslice_bitmask_t *granted);
int wrsmplat_set_seprom(safari_port_t wci, uchar_t *seprom_data, size_t
    length);
int wrsmplat_linktest(safari_port_t wci, wrsm_linktest_arg_t *linktest);

int wrsmplat_stripegroup_verify(const wrsm_stripe_group_t *);
void wrsmplat_ncslice_setup(wrsm_ncowner_map_t owner[WRSM_MAX_NCSLICES]);
void wrsmplat_ncslice_enter(void);
void wrsmplat_ncslice_exit(void);

void wrsmplat_xt_sync(int cpu_id);
wrsm_node_types_t wrsmplat_get_node_type(void);
void wrsmplat_wci_init(volatile uchar_t *wrsm_regs);

void wrsmplat_set_asi_cesr_id(void);
void wrsmplat_clr_asi_cesr_id(void);

#ifdef __cplusplus
}
#endif

#endif /* _WRSM_PLAT_H */
