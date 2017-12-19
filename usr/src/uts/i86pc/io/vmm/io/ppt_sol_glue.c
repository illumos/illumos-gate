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
 * Copyright 2017 Joyent, Inc.
 */

/*
 * PCI/PCIe interfaces needed by ppt
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>

#include <sys/bus.h>
#include <dev/pci/pcivar.h>

static bool
pcie_wait_for_pending_transactions(dev_info_t *dip, u_int max_delay)
{
	uint16_t cap_ptr, devsts;
	ddi_acc_handle_t hdl;

	if (pci_config_setup(dip, &hdl) != DDI_SUCCESS)
		return (false);

	if (PCI_CAP_LOCATE(hdl, PCI_CAP_ID_PCI_E, &cap_ptr) != DDI_SUCCESS) {
		pci_config_teardown(&hdl);
		return (false);
	}

	devsts = PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVSTS);
	while ((devsts & PCIE_DEVSTS_TRANS_PENDING) != 0) {
		if (max_delay == 0) {
			pci_config_teardown(&hdl);
			return (false);
		}

		/* Poll once every 100 milliseconds up to the timeout. */
		if (max_delay > 100) {
			delay(drv_usectohz(100 * 1000));
			max_delay -= 100;
		} else {
			delay(drv_usectohz(max_delay * 1000));
			max_delay = 0;
		}
		devsts = PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVSTS);
	}

	pci_config_teardown(&hdl);
	return (true);
}

int
pcie_get_max_completion_timeout(device_t dev)
{
	dev_info_t *dip = dev;
	int timo = 0;
	uint16_t cap_ptr;
	ddi_acc_handle_t hdl;
	int timo_ranges[] = {	/* timeout ranges */
		50000,		/* 50ms */
		100,		/* 100us */
		10000,		/* 10ms */
		0,
		0,
		55000,		/* 55ms */
		210000,		/* 210ms */
		0,
		0,
		900000,		/* 900ms */
		3500000,	/* 3.5s */
		0,
		0,
		13000000,	/* 13s */
		64000000,	/* 64s */
		0
	};

	if (pci_config_setup(dip, &hdl) != DDI_SUCCESS)
		return (50000); /* default 50ms */

	if (PCI_CAP_LOCATE(hdl, PCI_CAP_ID_PCI_E, &cap_ptr) != DDI_SUCCESS)
		goto out;

	if ((PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_PCIECAP) &
	    PCIE_PCIECAP_VER_MASK) < PCIE_PCIECAP_VER_2_0)
		goto out;

	if ((PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVCAP2) &
	    PCIE_DEVCTL2_COM_TO_RANGE_MASK) == 0)
		goto out;

	timo = timo_ranges[PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVCTL2) &
	    PCIE_DEVCAP2_COM_TO_RANGE_MASK];

out:
	if (timo == 0)
		timo = 50000; /* default 50ms */

	pci_config_teardown(&hdl);
	return (timo);
}

bool
pcie_flr(device_t dev, u_int max_delay, bool force)
{
	dev_info_t *dip = dev;
	bool ret = false;
	uint16_t cap_ptr, ctl, cmd;
	ddi_acc_handle_t hdl;
	int compl_delay;

	if (pci_config_setup(dip, &hdl) != DDI_SUCCESS)
		return (false);

	if (PCI_CAP_LOCATE(hdl, PCI_CAP_ID_PCI_E, &cap_ptr) != DDI_SUCCESS)
		goto fail;

	if ((PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVCAP) & PCIE_DEVCAP_FLR)
	    == 0)
		goto fail;

	/*
	 * Disable busmastering to prevent generation of new
	 * transactions while waiting for the device to go idle.  If
	 * the idle timeout fails, the command register is restored
	 * which will re-enable busmastering.
	 */
	cmd = pci_config_get16(hdl, PCI_CONF_COMM);
	pci_config_put16(hdl, PCI_CONF_COMM, cmd & ~PCI_COMM_ME);
	if (!pcie_wait_for_pending_transactions(dev, max_delay)) {
		if (!force) {
			pci_config_put16(hdl, PCI_CONF_COMM, cmd);
			goto fail;
		}
		dev_err(dip, CE_WARN,
		    "?Resetting with transactions pending after %d ms\n",
		    max_delay);

		/*
		 * Extend the post-FLR delay to cover the maximum
		 * Completion Timeout delay of anything in flight
		 * during the FLR delay.  Enforce a minimum delay of
		 * at least 10ms.
		 */
		compl_delay = pcie_get_max_completion_timeout(dev) / 1000;
		if (compl_delay < 10)
			compl_delay = 10;
	} else
		compl_delay = 0;

	/* Initiate the reset. */
	ctl = PCI_CAP_GET16(hdl, NULL, cap_ptr, PCIE_DEVCTL);
	(void) PCI_CAP_PUT16(hdl, NULL, cap_ptr, PCIE_DEVCTL,
	    ctl | PCIE_DEVCTL_INITIATE_FLR);

	/* Wait for at least 100ms */
	delay(drv_usectohz((100 + compl_delay) * 1000));

	pci_config_teardown(&hdl);
	return (true);

fail:
	pci_config_teardown(&hdl);
	return (ret);
}
