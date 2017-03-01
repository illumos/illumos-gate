/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Collection of known and assembled quirks for devices. These are used while
 * attaching the controller.
 *
 * Please see the big theory statement in xhci.c for more information.
 */

#include <sys/usb/hcd/xhci/xhci.h>

typedef struct xhci_quirk_table {
	uint16_t xqt_vendor;
	uint16_t xqt_device;
	xhci_quirk_t xqt_quirks;
} xhci_quirk_table_t;

static xhci_quirk_table_t xhci_quirks[] = {
	{ 0x1b7e, 0x1000, XHCI_QUIRK_NO_MSI },
	{ 0x1033, 0x0194, XHCI_QUIRK_32_ONLY },
	{ 0x1912, 0x0014, XHCI_QUIRK_32_ONLY },
	{ 0x8086, 0x0f35, XHCI_QUIRK_INTC_EHCI },	/* BayTrail */
	{ 0x8086, 0x9c31, XHCI_QUIRK_INTC_EHCI },	/* Panther Point */
	{ 0x8086, 0x1e31, XHCI_QUIRK_INTC_EHCI },	/* Panther Point */
	{ 0x8086, 0x8c31, XHCI_QUIRK_INTC_EHCI },	/* Lynx Point */
	{ 0x8086, 0x8cb1, XHCI_QUIRK_INTC_EHCI },	/* Wildcat Point */
	{ 0x8086, 0x9cb1, XHCI_QUIRK_INTC_EHCI },	/* Wildcat Point-LP */
	{ 0xffff, 0xffff, 0 }
};

void
xhci_quirks_populate(xhci_t *xhcip)
{
	xhci_quirk_table_t *xqt;

	for (xqt = &xhci_quirks[0]; xqt->xqt_vendor != 0xffff; xqt++) {
		if (xqt->xqt_vendor == xhcip->xhci_vendor_id &&
		    xqt->xqt_device == xhcip->xhci_device_id) {
			xhcip->xhci_quirks = xqt->xqt_quirks;
			return;
		}
	}
}

/*
 * Various Intel Chipsets have shared ports that run under both EHCI and xHCI.
 * Whenever we reset the controller and its ports, we'll need to toggle these
 * settings on those platforms. Note that this is generally only needed for
 * client chipsets and even those have started to drop EHCI.
 */
void
xhci_reroute_intel(xhci_t *xhcip)
{
	uint32_t ports;

	ports = pci_config_get32(xhcip->xhci_cfg_handle,
	    PCI_XHCI_INTEL_USB3PRM);
	pci_config_put32(xhcip->xhci_cfg_handle, PCI_XHCI_INTEL_USB3_PSSEN,
	    ports);

	ports = pci_config_get32(xhcip->xhci_cfg_handle,
	    PCI_XHCI_INTEL_USB2PRM);
	pci_config_put32(xhcip->xhci_cfg_handle, PCI_XHCI_INTEL_XUSB2PR,
	    ports);
}
