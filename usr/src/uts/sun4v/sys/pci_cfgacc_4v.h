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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PCI_CFGACC_4V_H
#define	_SYS_PCI_CFGACC_4V_H

#include <sys/pci.h>
#include <sys/pci_cfgacc.h>
#include "../../sun4/io/px/px_ioapi.h"

#ifdef	__cplusplus
extern "C" {
#endif

extern uint64_t hvio_config_get(devhandle_t, pci_device_t, pci_config_offset_t,
    pci_config_size_t, pci_cfg_data_t *);
extern uint64_t hvio_config_put(devhandle_t, pci_device_t, pci_config_offset_t,
    pci_config_size_t, pci_cfg_data_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_CFGACC_4V_H */
