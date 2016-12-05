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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/signal.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/map.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/cred.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <vm/page.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/seg.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/fs/snode.h>
#include <sys/pci.h>
#include <sys/modctl.h>
#include <sys/uio.h>
#include <sys/visual_io.h>
#include <sys/fbio.h>
#include <sys/ddidmareq.h>
#include <sys/tnf_probe.h>
#include <sys/kstat.h>
#include <sys/callb.h>
#include <sys/pci_cfgspace.h>
#include <sys/gfx_private.h>

typedef struct gfxp_pci_bsf {
	uint16_t	vendor;
	uint16_t	device;
	uint8_t		bus;
	uint8_t		slot;
	uint8_t		function;
	uint8_t		found;
	dev_info_t	*dip;
} gfxp_pci_bsf_t;

/* The use of pci_get?/put?_func() depends on misc/pci_autoconfig */

static int
gfxp_pci_get_bsf(dev_info_t *dip, uint8_t *bus, uint8_t *dev, uint8_t *func)
{
	pci_regspec_t   *pci_rp;
	uint32_t	length;
	int	rc;

	/* get "reg" property */
	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
		(uint_t *)&length);
	if ((rc != DDI_SUCCESS) || (length <
			(sizeof (pci_regspec_t) / sizeof (int)))) {
		return (DDI_FAILURE);
	}

	*bus = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
	*dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	*func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array().
	 */
	ddi_prop_free(pci_rp);

	return (DDI_SUCCESS);
}

static int
gfxp_pci_find_bsf(dev_info_t *dip, void *arg)
{
	int	rc;
	uint8_t bus, dev, func;
	gfxp_pci_bsf_t    *pci_bsf;
	int vendor_id, device_id, class_code;

	/*
	 * Look for vendor-id, device-id, class-code to verify
	 * this is some type of PCI child node.
	 */
	vendor_id = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
				"vendor-id", -1);
	device_id = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
				"device-id", -1);
	class_code = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
				"class-code", -1);
	if ((vendor_id == -1) || (device_id == -1) || (class_code == -1)) {
		return (DDI_WALK_CONTINUE);
	}

	if (gfxp_pci_get_bsf(dip, &bus, &dev, &func) != DDI_SUCCESS)
		return (DDI_WALK_TERMINATE);

	pci_bsf = (gfxp_pci_bsf_t *)arg;

	if ((bus == pci_bsf->bus) && (dev == pci_bsf->slot) &&
		(func == pci_bsf->function)) {
		pci_bsf->dip = dip;
		pci_bsf->vendor = vendor_id;
		pci_bsf->device = device_id;
		pci_bsf->found = 1;
		rc = DDI_WALK_TERMINATE;
	} else {
		rc = DDI_WALK_CONTINUE;
	}

	return (rc);
}

gfxp_acc_handle_t
gfxp_pci_init_handle(uint8_t bus, uint8_t slot, uint8_t function,
	uint16_t *vendor, uint16_t *device)
{
	dev_info_t	*dip;
	gfxp_pci_bsf_t	*pci_bsf;

	/*
	 * Find a PCI device based on its address, and return a unique handle
	 * to be used in subsequent calls to read from or write to the config
	 * space of this device.
	 */

	if ((pci_bsf = kmem_zalloc(sizeof (gfxp_pci_bsf_t), KM_SLEEP))
			== NULL) {
		return (NULL);
	}

	pci_bsf->bus = bus;
	pci_bsf->slot = slot;
	pci_bsf->function = function;

	ddi_walk_devs(ddi_root_node(), gfxp_pci_find_bsf, pci_bsf);

	if (pci_bsf->found) {
		dip = pci_bsf->dip;

		if (vendor) *vendor = pci_bsf->vendor;
		if (device) *device = pci_bsf->device;
	} else {
		dip = NULL;
		if (vendor) *vendor = 0x0000;
		if (device) *device = 0x0000;
	}

	kmem_free(pci_bsf, sizeof (gfxp_pci_bsf_t));

	return ((gfxp_acc_handle_t)dip);
}

uint8_t
gfxp_pci_read_byte(gfxp_acc_handle_t handle, uint16_t offset)
{
	dev_info_t	*dip = (dev_info_t *)handle;
	uint8_t	val;
	uint8_t	bus, dev, func;

	if (dip == NULL)
		return ((uint8_t)~0);

	if (gfxp_pci_get_bsf(dip, &bus, &dev, &func) != DDI_SUCCESS)
		return ((uint8_t)~0);

	val = (*pci_getb_func)(bus, dev, func, offset);
	return (val);
}

uint16_t
gfxp_pci_read_word(gfxp_acc_handle_t handle, uint16_t offset)
{
	dev_info_t	*dip = (dev_info_t *)handle;
	uint16_t	val;
	uint8_t 	bus, dev, func;

	if (dip == NULL)
		return ((uint16_t)~0);

	if (gfxp_pci_get_bsf(dip, &bus, &dev, &func) != DDI_SUCCESS)
		return ((uint16_t)~0);

	val = (*pci_getw_func)(bus, dev, func, offset);
	return (val);
}

uint32_t
gfxp_pci_read_dword(gfxp_acc_handle_t handle, uint16_t offset)
{
	dev_info_t	*dip = (dev_info_t *)handle;
	uint32_t	val;
	uint8_t		bus, dev, func;

	if (dip == NULL)
		return ((uint32_t)~0);

	if (gfxp_pci_get_bsf(dip, &bus, &dev, &func) != DDI_SUCCESS)
		return ((uint32_t)~0);

	val = (*pci_getl_func)(bus, dev, func, offset);
	return (val);
}

void
gfxp_pci_write_byte(gfxp_acc_handle_t handle, uint16_t offset, uint8_t value)
{
	dev_info_t	*dip = (dev_info_t *)handle;
	uint8_t		bus, dev, func;

	if (dip == NULL)
		return;

	if (gfxp_pci_get_bsf(dip, &bus, &dev, &func) != DDI_SUCCESS)
		return;

	(*pci_putb_func)(bus, dev, func, offset, value);
}

void
gfxp_pci_write_word(gfxp_acc_handle_t handle, uint16_t offset, uint16_t value)
{
	dev_info_t	*dip = (dev_info_t *)handle;
	uint8_t		bus, dev, func;

	if (dip == NULL)
		return;

	if (gfxp_pci_get_bsf(dip, &bus, &dev, &func) != DDI_SUCCESS)
		return;

	(*pci_putw_func)(bus, dev, func, offset, value);
}

void
gfxp_pci_write_dword(gfxp_acc_handle_t handle, uint16_t offset, uint32_t value)
{
	dev_info_t	*dip = (dev_info_t *)handle;
	uint8_t		bus, dev, func;

	if (dip == NULL)
		return;

	if (gfxp_pci_get_bsf(dip, &bus, &dev, &func) != DDI_SUCCESS)
		return;

	(*pci_putl_func)(bus, dev, func, offset, value);
}

static int
gfxp_pci_find_vd(dev_info_t *dip, void *arg)
{
	int		rc;
	gfxp_pci_bsf_t	*pci_bsf;
	int		vendor_id, device_id, class_code;

	/*
	 * Look for vendor-id, device-id, class-code to verify
	 * this is some type of PCI child node.
	 */
	vendor_id = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
			"vendor-id", -1);
	device_id = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
			"device-id", -1);
	class_code = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
			"class-code", -1);
	if ((vendor_id == -1) || (device_id == -1) || (class_code == -1)) {
		return (DDI_WALK_CONTINUE);
	}

	pci_bsf = (gfxp_pci_bsf_t *)arg;

	if ((vendor_id == pci_bsf->vendor) && (device_id == pci_bsf->device)) {
		pci_bsf->found = 1;
		rc = DDI_WALK_TERMINATE;
	} else {
		rc = DDI_WALK_CONTINUE;
	}

	return (rc);
}

int
gfxp_pci_device_present(uint16_t vendor, uint16_t device)
{
	gfxp_pci_bsf_t	*pci_bsf;
	int		rv;

	/*
	 * Find a PCI device based on its device and vendor id.
	 */

	if ((pci_bsf = kmem_zalloc(sizeof (gfxp_pci_bsf_t), KM_SLEEP)) == NULL)
	    return (0);

	pci_bsf->vendor = vendor;
	pci_bsf->device = device;
	ddi_walk_devs(ddi_root_node(), gfxp_pci_find_vd, pci_bsf);

	if (pci_bsf->found) {
		rv = 1;
	} else {
		rv = 0;
	}

	kmem_free(pci_bsf, sizeof (gfxp_pci_bsf_t));

	return (rv);
}
