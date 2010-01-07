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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_HOTPLUG_PCI_PCISHPC_H
#define	_SYS_HOTPLUG_PCI_PCISHPC_H

#ifdef	__cplusplus
extern "C" {
#endif

int pcishpc_init(dev_info_t *dip);
int pcishpc_uninit(dev_info_t *dip);
int pcishpc_intr(dev_info_t *dip);
int pcishpc_enable_irqs(pcie_hp_ctrl_t *ctrl_p);
int pcishpc_disable_irqs(pcie_hp_ctrl_t *ctrl_p);
int pcishpc_hp_ops(dev_info_t *dip, char *cn_name, ddi_hp_op_t op, void *arg,
    void *result);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HOTPLUG_PCI_PCISHPC_H */
