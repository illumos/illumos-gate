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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * Assembly language support for pci config space access on sun4v
 */

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>
#include <sys/dditypes.h>
#include <sys/pci_cfgacc.h>
#include <io/px/px_ioapi.h>
#include <io/px/px_lib4v.h>

	/*
	 * arg0 - devhandle
	 * arg1 - pci_device
	 * arg2 - pci_config_offset
	 * arg3 - pci_config_size (1, 2 or 4 byte)
	 *
	 * ret0 - status
	 * ret1 - error_flag
	 * ret2 - pci_cfg_data
	 */
	ENTRY(hvio_config_get)
	mov	HVIO_CONFIG_GET, %o5
	ta	FAST_TRAP
	sllx	%o1, 32, %o1
	or	%o0, %o1, %o0
	movrnz	%o1, -1, %o2
	stx	%o2, [%o4]
	retl
	nop
	SET_SIZE(hvio_config_get)

	/*
	 * arg0 - devhandle
	 * arg1 - pci_device
	 * arg2 - pci_config_offset
	 * arg3 - pci_config_size (1, 2 or 4 byte)
	 * arg4 - pci_cfg_data
	 *
	 * ret0 - status
	 * ret1 - error_flag
	 */
	ENTRY(hvio_config_put)
	mov	HVIO_CONFIG_PUT, %o5
	ta	FAST_TRAP
	sllx	%o1, 32, %o1
	or	%o0, %o1, %o0
	retl
	nop
	SET_SIZE(hvio_config_put)
