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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/pci/pci_obj.h>
#include <sys/pci.h>
#include <sys/pci_cap.h>

/*LINTLIBRARY*/

void
pcix_set_cmd_reg(dev_info_t *child, uint16_t value)
{
	uint16_t pcix_cap_ptr, pcix_cmd;
	ddi_acc_handle_t handle;

	if (pci_config_setup(child, &handle) != DDI_SUCCESS)
		return;

	/*
	 * Only modify the Command Register of non-bridge functions.
	 */
	if ((pci_config_get8(handle, PCI_CONF_HEADER) & PCI_HEADER_TYPE_M)
	    == PCI_HEADER_PPB)
		goto teardown;

	if (PCI_CAP_LOCATE(handle, PCI_CAP_ID_PCIX, &pcix_cap_ptr) ==
	    DDI_FAILURE)
		goto teardown;

	DEBUG1(DBG_INIT_CLD, child, "pcix_set_cmd_reg: pcix_cap_ptr = %x\n",
	    pcix_cap_ptr);

	/*
	 * Read the PCI-X Command Register.
	 */
	if ((pcix_cmd = PCI_CAP_GET16(handle, 0, pcix_cap_ptr, 2))
	    == PCI_CAP_EINVAL16)
		goto teardown;

	DEBUG1(DBG_INIT_CLD, child, "pcix_set_cmd_reg: PCI-X CMD Register "
	    "(Before) %x\n", pcix_cmd);

	pcix_cmd &= ~(0x1f << 2); /* clear bits 6-2 */
	pcix_cmd |= value;

	DEBUG1(DBG_INIT_CLD, child, "pcix_set_cmd_reg: PCI-X CMD Register "
	    "(After) %x\n", pcix_cmd);

	PCI_CAP_PUT16(handle, 0, pcix_cap_ptr, 2, pcix_cmd);

teardown:
	pci_config_teardown(&handle);
}
