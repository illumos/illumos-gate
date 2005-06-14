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

#ifndef _WRSM_CF_H
#define	_WRSM_CF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines the interfaces between the config layer and
 * the other components of the wrsm driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/cred.h>
#include <sys/wrsm_config.h>
#include <sys/wrsm_common.h>

#define	WRSM_BAD_RSM_ID 0xffffffff
#define	WRSM_LOOPBACK_ID 0xfffffffe

/*
 * functions exported to the LC
 */
int wrsm_cf_newwci(lcwci_handle_t lcwci, safari_port_t port);
int wrsm_cf_remove_wci(lcwci_handle_t lcwci);
void wrsm_cf_is_enabled(uint32_t controller_id);
lcwci_handle_t wrsm_cf_lookup_wci(safari_port_t port);
int wrsm_cf_claim_wci(uint32_t controller_id, safari_port_t wci_id);
void wrsm_cf_release_wci(safari_port_t wci_id);
uint32_t wrsm_cf_wci_owner(safari_port_t wci_id);
boolean_t wrsm_cf_cnode_is_switch(wrsm_controller_t *cont);

/*
 * functions exported to the core driver (wrsm_driver.c)
 */
void wrsm_cf_init(void);
void wrsm_cf_fini(void);
int wrsm_cf_new_controller(int cont_id, dev_info_t *devi);
int wrsm_cf_remove_controller(int cont_id);
int wrsm_cf_admin_ioctl(struct wrsm_soft_state *softsp, int cmd,
    intptr_t arg, int flag, cred_t *cred_p, int *rval_p);
int wrsm_cf_ctlr_ioctl(int cont_id, int cmd, intptr_t arg, int flag,
    cred_t *cred_p, int *rval_p);
void *wrsm_cf_pack(wrsm_controller_t *cont, int *sizep);
wrsm_controller_t *wrsm_cf_unpack(char *data);
void wrsm_cf_sc_failed(void);


#ifdef __cplusplus
}
#endif

#endif /* _WRSM_CF_H */
