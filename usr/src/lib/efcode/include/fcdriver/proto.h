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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_FCDRIVER_PROTO_H
#define	_FCDRIVER_PROTO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	CURRENT_DEVICE(e)	(e)->current_device
#define	COMMON_PRIVATE(e)	(common_data_t *)((e)->private)
#define	DEVICE_PRIVATE(e)	(private_data_t *)(MYSELF->device->private)

void install_pci_methods(fcode_env_t *);
void install_property_vectors(fcode_env_t *, device_t *);
void install_node_data(fcode_env_t *, device_t *);
void build_tree(fcode_env_t *);
void install_dma_methods(fcode_env_t *);
void add_my_handle(fcode_env_t *, fc_phandle_t, device_t *);
void recurse_tree(fcode_env_t *, device_t *,
    void (*)(fcode_env_t *, device_t *));

int do_run_priv(common_data_t *, struct fc_client_interface *, int);
int fc_run_priv(common_data_t *, char *, int, int, ...);
int os_get_prop_common(common_data_t *, fc_phandle_t, char *, int, char **,
    int *);
fc_phandle_t fc_get_ap(common_data_t *);
int fc_get_request(common_data_t *);
void set_debug_level(common_data_t *, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif /* _FCDRIVER_PROTO_H */
