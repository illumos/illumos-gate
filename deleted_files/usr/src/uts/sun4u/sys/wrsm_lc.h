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

#ifndef _SYS_WRSM_LC_H
#define	_SYS_WRSM_LC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/wci_cmmu.h>
#include <sys/wrsm.h>
#include <sys/wrsm_driver.h>
#include <sys/wrsm_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * function return values
 */
#define	WRSM_LC_SUCCESS		0
#define	WRSM_LC_NOPAROLI	1
#define	WRSM_LC_INVALIDARG	2

typedef enum {
	CMMU_TYPE_CACHEABLE = 0,
	CMMU_TYPE_STICK = 1,
	CMMU_TYPE_INTERRUPT = 2,
	CMMU_TYPE_ATOMIC = 3
} wrsm_cmmu_type_t;

/* Declaration of abstract CMMU entry */
typedef struct {
	wci_sram_array_as_cmmu_0_u entry_0;
	union {
		struct wci_sram_array_as_cmmu_1_int intr;
		struct wci_sram_array_as_cmmu_1_addr addr;
		uint64_t val;
	} entry_1;
} wrsm_cmmu_t;

#define	WRSM_GNID_IS_WCX(w)	(w >= WRSM_MAX_WNODES)

/* cmmu_update flags */
#define	CMMU_UPDATE_MONDO	0x00001
#define	CMMU_UPDATE_FROMNODE	0x00002
#define	CMMU_UPDATE_TYPE	0x00004
#define	CMMU_UPDATE_VALID	0x00008
#define	CMMU_UPDATE_FROMALL	0x00010
#define	CMMU_UPDATE_WRITABLE	0x00020
#define	CMMU_UPDATE_USERERROR	0x00040
#define	CMMU_UPDATE_LARGEPAGE	0x00080
#define	CMMU_UPDATE_ENABLEPERF	0x00100
#define	CMMU_UPDATE_LPA		0x00200
#define	CMMU_UPDATE_INTRDEST	0x00400
#define	CMMU_UPDATE_FLUSH	0x08000
#define	CMMU_UPDATE_ALL		0x0FFFF
#define	CMMU_UPDATE_WRITEONLY	0x10000
#define	CMMU_UPDATE_WRITE_0	0x20000
#define	CMMU_UPDATE_WRITE_1	0x40000

typedef uint32_t wrsm_cmmu_flags_t;

int wrsm_lc_loopback_enable(wrsm_softstate_t *softsp,
    uint32_t local_link_num);
int wrsm_lc_loopback_disable(wrsm_softstate_t *softsp,
    uint32_t local_link_num);
int wrsm_lc_linktest(wrsm_softstate_t *softsp,
    wrsm_linktest_arg_t *local_link_num);
int wrsm_lc_user_linkdown(wrsm_softstate_t *softsp, int linkno);
int wrsm_lc_user_linkup(wrsm_softstate_t *softsp, int linkno);

void wrsm_lc_setup_timeout_speeds(void);
safari_port_t wrsm_lc_get_safid(lcwci_handle_t lcwci);
int wrsm_lc_get_instance(lcwci_handle_t lcwci);
boolean_t wrsm_lc_verifyconfig(lcwci_handle_t lcwci, wrsm_wci_data_t *config);
void wrsm_lc_replaceconfig(lcwci_handle_t lcwci, ncwci_handle_t nc,
	wrsm_wci_data_t *config, wrsm_controller_t *ctlr_config);
void wrsm_lc_cleanconfig(lcwci_handle_t lcwci);
void wrsm_lc_installconfig(lcwci_handle_t lcwci);
void wrsm_lc_enableconfig(lcwci_handle_t lcwci);

/* for DDI_SUSPEND, DDI_RESUME */
void wrsm_lc_suspend(wrsm_softstate_t *softsp);
void wrsm_lc_resume(wrsm_softstate_t *softsp);

/* register manipulation functions - read/write */
void wrsm_lc_cesr_read(lcwci_handle_t lc, safari_port_t dev_id,
    uint64_t *entry);
void wrsm_lc_cesr_write(lcwci_handle_t lc, safari_port_t dev_id,
    uint64_t entry);
void wrsm_lc_csr_read(lcwci_handle_t lc, uint64_t reg_offset, uint64_t *entry);
void wrsm_lc_csr_write(lcwci_handle_t lc, uint64_t reg_offset, uint64_t entry);

void wrsm_lc_cmmu_read(lcwci_handle_t lc, wrsm_cmmu_t *cmmu_entry,
    uint32_t index);
void wrsm_lc_cmmu_update(lcwci_handle_t lc, wrsm_cmmu_t *cmmu_entry,
    uint32_t index, wrsm_cmmu_flags_t flag);
int wrsm_lc_num_cmmu_entries_get(lcwci_handle_t lc);

void wrsm_lc_phys_link_up(safari_port_t local_port, uint32_t local_link_num,
    fmnodeid_t remote_fmnodeid, gnid_t remote_gnid,
    uint32_t remote_link_num, safari_port_t remote_port,
    uint64_t remote_partition_version, uint32_t remote_partition_id);
void wrsm_lc_phys_link_down(safari_port_t local_port, uint32_t local_link_num);
void wrsm_lc_sc_crash(lcwci_handle_t lc);

/* the following are supplied for the mh to modify the map registers */
void wrsm_lc_set_route(wrsm_softstate_t *softsp, wnodeid_t wnode,
    linkid_t linknum, int map);
linkid_t wrsm_lc_get_route(wrsm_softstate_t *softsp, wnodeid_t wnode, int map);

/* The following is for the interrupt trap handler only */
caddr_t wrsm_lc_get_sram_paddr(lcwci_handle_t lc);

/* the following is for standalone use, when system controller can't be used */
void get_remote_config_data(safari_port_t wci_id, uint32_t link_num,
    fmnodeid_t *remote_fmnodeid, gnid_t *remote_gnid, linkid_t *remote_link,
    safari_port_t *remote_port, volatile uchar_t **wrsm_regs);

/* the following handles ioctl requests to modify wci registers */
int wrsm_lc_register_ioctl(wrsm_softstate_t *softsp, int cmd,
    intptr_t arg, int flag, cred_t *cred_p, int *rval_p);


#ifdef __cplusplus
}
#endif

#endif /* _SYS_WRSM_LC_H */
