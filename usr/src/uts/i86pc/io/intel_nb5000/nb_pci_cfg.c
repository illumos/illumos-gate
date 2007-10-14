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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <vm/seg_kmem.h>
#include <sys/machparam.h>
#include <sys/mman.h>
#include <sys/cpu_module.h>
#include "nb5000.h"

static ddi_acc_handle_t dev_16_hdl[NB_PCI_NFUNC];
static ddi_acc_handle_t dev_17_hdl[NB_PCI_NFUNC];
static ddi_acc_handle_t dev_pci_hdl[NB_PCI_DEV];

void
nb_pci_cfg_setup(dev_info_t *dip)
{
	pci_regspec_t reg;
	int i;

	reg.pci_phys_hi = 16 << PCI_REG_DEV_SHIFT; /* Bus=0, Dev=16, Func=0 */
	reg.pci_phys_mid = 0;
	reg.pci_phys_low = 0;
	reg.pci_size_hi = 0;
	reg.pci_size_low = PCIE_CONF_HDR_SIZE; /* overriden in pciex */

	for (i = 0; i < NB_PCI_NFUNC; i++) {
		if (ddi_prop_update_int_array(DDI_MAJOR_T_UNKNOWN, dip, "reg",
		    (int *)&reg, sizeof (reg)/sizeof (int)) != DDI_PROP_SUCCESS)
		cmn_err(CE_WARN,
		    "nb_pci_cfg_setup: cannot create reg property");

		if (pci_config_setup(dip, &dev_16_hdl[i]) != DDI_SUCCESS)
			cmn_err(CE_WARN,
			    "intel_nb5000: pci_config_setup failed");
		reg.pci_phys_hi += 1 << PCI_REG_FUNC_SHIFT;
	}
	reg.pci_phys_hi = 17 << PCI_REG_DEV_SHIFT; /* Bus=0, Dev=17, Func=0 */
	for (i = 0; i < NB_PCI_NFUNC; i++) {
		if (ddi_prop_update_int_array(DDI_MAJOR_T_UNKNOWN, dip, "reg",
		    (int *)&reg, sizeof (reg)/sizeof (int)) != DDI_PROP_SUCCESS)
		cmn_err(CE_WARN,
		    "nb_pci_cfg_setup: cannot create reg property");

		if (pci_config_setup(dip, &dev_17_hdl[i]) != DDI_SUCCESS)
			cmn_err(CE_WARN,
			    "intel_nb5000: pci_config_setup failed");
		reg.pci_phys_hi += 1 << PCI_REG_FUNC_SHIFT;
	}
	reg.pci_phys_hi = 0;		/* Bus=0, Dev=0, Func=0 */
	for (i = 0; i < NB_PCI_DEV; i++) {
		if (ddi_prop_update_int_array(DDI_MAJOR_T_UNKNOWN, dip, "reg",
		    (int *)&reg, sizeof (reg)/sizeof (int)) != DDI_PROP_SUCCESS)
		cmn_err(CE_WARN,
		    "nb_pci_cfg_setup: cannot create reg property");

		if (pci_config_setup(dip, &dev_pci_hdl[i]) != DDI_SUCCESS)
			cmn_err(CE_WARN,
			    "intel_nb5000: pci_config_setup failed");
		reg.pci_phys_hi += 1 << PCI_REG_DEV_SHIFT;
	}
}

void
nb_pci_cfg_free()
{
	int i;

	for (i = 0; i < NB_PCI_NFUNC; i++) {
		pci_config_teardown(&dev_16_hdl[i]);
	}
	for (i = 0; i < NB_PCI_NFUNC; i++) {
		pci_config_teardown(&dev_17_hdl[i]);
	}
	for (i = 0; i < NB_PCI_DEV; i++)
		pci_config_teardown(&dev_pci_hdl[i]);
}

static ddi_acc_handle_t
nb_get_hdl(int bus, int dev, int func)
{
	ddi_acc_handle_t hdl;

	if (bus == 0 && dev == 16 && func < NB_PCI_NFUNC) {
		hdl = dev_16_hdl[func];
	} else if (bus == 0 && dev == 17 && func < NB_PCI_NFUNC) {
		hdl = dev_17_hdl[func];
	} else if (bus == 0 && dev < NB_PCI_DEV && func == 0) {
		hdl = dev_pci_hdl[dev];
	} else {
		hdl = 0;
	}
	return (hdl);
}

uint8_t
nb_pci_getb(int bus, int dev, int func, int reg, int *interpose)
{
	ddi_acc_handle_t hdl;

	hdl = nb_get_hdl(bus, dev, func);
	return (cmi_pci_getb(bus, dev, func, reg, interpose, hdl));
}

uint16_t
nb_pci_getw(int bus, int dev, int func, int reg, int *interpose)
{
	ddi_acc_handle_t hdl;

	hdl = nb_get_hdl(bus, dev, func);
	return (cmi_pci_getw(bus, dev, func, reg, interpose, hdl));
}

uint32_t
nb_pci_getl(int bus, int dev, int func, int reg, int *interpose)
{
	ddi_acc_handle_t hdl;

	hdl = nb_get_hdl(bus, dev, func);
	return (cmi_pci_getl(bus, dev, func, reg, interpose, hdl));
}

void
nb_pci_putb(int bus, int dev, int func, int reg, uint8_t val)
{
	ddi_acc_handle_t hdl;

	hdl = nb_get_hdl(bus, dev, func);
	cmi_pci_putb(bus, dev, func, reg, hdl, val);
}

void
nb_pci_putw(int bus, int dev, int func, int reg, uint16_t val)
{
	ddi_acc_handle_t hdl;

	hdl = nb_get_hdl(bus, dev, func);
	cmi_pci_putw(bus, dev, func, reg, hdl, val);
}

void
nb_pci_putl(int bus, int dev, int func, int reg, uint32_t val)
{
	ddi_acc_handle_t hdl;

	hdl = nb_get_hdl(bus, dev, func);
	cmi_pci_putl(bus, dev, func, reg, hdl, val);
}
