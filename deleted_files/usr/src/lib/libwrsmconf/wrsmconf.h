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

#ifndef _WRSMCONF_H
#define	_WRSMCONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/wrsm.h>
#include <sys/wrsm_config.h>

int wrsm_initial_config(wrsm_controller_t *cont);
int wrsm_start_config(int controller_id);
int wrsm_start_all_configs(void);
int wrsm_replace_config(wrsm_controller_t *cont);
int wrsm_enable_config(int controller_id, size_t num_wcis,
    wrsm_safari_port_t *wci_ids_in);
int wrsm_install_config(int controller_id, size_t num_wcis,
    wrsm_safari_port_t *wci_ids_in);
int wrsm_remove_config(int controller_id);
int wrsm_remove_all_configs(void);
int wrsm_stop_config(int controller_id);
int wrsm_stop_all_configs(void);
int wrsm_get_config(int controller_id, wrsm_controller_t **cont);
int wrsm_get_num_controllers(void);
int wrsm_save_config(char *path, wrsm_controller_t *config);
int wrsm_read_config(char *path, wrsm_controller_t **config);
int wrsm_read_config_for_host(char *path, wrsm_controller_t **config,
    char *hostname);
int wrsm_free_config(wrsm_controller_t *config);
int wrsm_memory_test(int controller_id, wrsm_memloopback_arg_t *memoryinfo);
int wrsm_link_test_setup(int wci_instance, int link_number);
int wrsm_link_test(int wci_instance, wrsm_linktest_arg_t *linkinfo);
int wrsm_link_test_teardown(int wci_instance, int link_number);
int wrsm_link_disable(wrsm_safari_port_t wci_id, int linkno);
int wrsm_link_enable(wrsm_safari_port_t wci_id, int linkno);

#ifdef __cplusplus
}
#endif

#endif /* _WRSMCONF_H */
