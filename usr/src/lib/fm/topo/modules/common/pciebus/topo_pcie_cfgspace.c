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
 * Copyright 2023 Oxide Computer Company
 */

#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/stat.h>
#include <sys/pci_tools.h>

#include "topo_pcie_impl.h"

static bool
read_cfgspace(topo_mod_t *mod, pcie_node_t *node,
    int fd, uint32_t off, uint8_t len, void *buf)
{
	pcitool_reg_t pci_reg;
	bool ret = true;

	bzero(&pci_reg, sizeof (pci_reg));
	pci_reg.user_version = PCITOOL_VERSION;
	pci_reg.bus_no = node->pn_bus;
	pci_reg.dev_no = node->pn_dev;
	pci_reg.func_no = node->pn_func;
	pci_reg.barnum = 0;
	pci_reg.offset = off;
	pci_reg.acc_attr = PCITOOL_ACC_ATTR_ENDN_LTL;

	switch (len) {
	case 1:
		pci_reg.acc_attr += PCITOOL_ACC_ATTR_SIZE_1;
		break;
	case 2:
		pci_reg.acc_attr += PCITOOL_ACC_ATTR_SIZE_2;
		break;
	case 4:
		pci_reg.acc_attr += PCITOOL_ACC_ATTR_SIZE_4;
		break;
	case 8:
		pci_reg.acc_attr += PCITOOL_ACC_ATTR_SIZE_8;
		break;
	default:
		abort();
	}

	if (ioctl(fd, PCITOOL_DEVICE_GET_REG, &pci_reg) != 0) {
		topo_mod_dprintf(mod, "ioctl(GET_REG) failed: %s",
		    strerror(errno));
		return (false);
	}

	switch (len) {
	case 1:
		*(uint8_t *)buf = (uint8_t)pci_reg.data;
		ret = (uint8_t)pci_reg.data != PCI_EINVAL8;
		break;
	case 2:
		*(uint16_t *)buf = (uint16_t)pci_reg.data;
		ret = (uint16_t)pci_reg.data != PCI_EINVAL16;
		break;
	case 4:
		*(uint32_t *)buf = (uint32_t)pci_reg.data;
		ret = (uint32_t)pci_reg.data != PCI_EINVAL32;
		break;
	case 8:
		*(uint64_t *)buf = (uint64_t)pci_reg.data;
		ret = (uint64_t)pci_reg.data != PCI_EINVAL64;
		break;
	}

	return (ret);
}

static int
open_nexus(topo_mod_t *mod, pcie_node_t *node)
{
	char nexus_reg[PATH_MAX];
	pcie_node_t *nexus;
	int fd;

	for (nexus = node; nexus->pn_type != PCIE_NODE_ROOTNEXUS; nexus =
	    nexus->pn_parent)
		;

	VERIFY3P(nexus, !=, NULL);

	if (snprintf(nexus_reg, sizeof (nexus_reg), "/devices%s:reg",
	    nexus->pn_path) >= sizeof (nexus_reg)) {
		topo_mod_dprintf(mod,
		    "failed to construct nexus reg path; overflow");
		return (-1);
	}

	if ((fd = open(nexus_reg, O_RDONLY)) < 0) {
		topo_mod_dprintf(mod, "failed to open %s: %s", nexus_reg,
		    strerror(errno));
		return (-1);
	}

	return (fd);
}

topo_pcie_link_status_t
topo_pcie_link_status(topo_mod_t *mod, pcie_node_t *node)
{
	int fd;
	uint8_t hdr, off;
	uint16_t status;
	uint32_t cap;
	uint_t ncaps;
	topo_pcie_link_status_t ret = PCI_LINK_UNKNOWN;

	if ((fd = open_nexus(mod, node)) == -1)
		return (ret);

	if (!read_cfgspace(mod, node, fd, PCI_CONF_STAT, 2, &status)) {
		topo_mod_dprintf(mod, "failed to read status register");
		goto out;
	}

	if ((status & PCI_STAT_CAP) == 0) {
		topo_mod_dprintf(mod, "capabilities not supported");
		goto out;
	}

	if (!read_cfgspace(mod, node, fd, PCI_CONF_HEADER, 1, &hdr)) {
		topo_mod_dprintf(mod, "failed to read header type");
		goto out;
	}

	switch (hdr & PCI_HEADER_TYPE_M) {
	case PCI_HEADER_ZERO:
		cap = PCI_CONF_CAP_PTR;
		break;
	case PCI_HEADER_PPB:
		cap = PCI_BCNF_CAP_PTR;
		break;
	default:
		topo_mod_dprintf(mod, "unhandled PCI header type %x", hdr);
		goto out;
	}

	if (!read_cfgspace(mod, node, fd, cap, 1, &off)) {
		topo_mod_dprintf(mod, "failed to read capabilities pointer");
		goto out;
	}

	ncaps = 0;
	while (off != 0 && off != PCI_EINVAL8) {
		uint8_t id, nxt;

		off &= PCI_CAP_PTR_MASK;
		if (!read_cfgspace(mod, node, fd,
		    off + PCI_CAP_ID, 1, &id)) {
			topo_mod_dprintf(mod, "failed to read capability ID");
			break;
		}

		if (id == PCI_CAP_ID_PCI_E) {
			uint16_t pciecap, status, pciever;
			uint32_t linkcap;

			topo_mod_dprintf(mod, "Found PCIe capability at %x",
			    off);

			if (!read_cfgspace(mod, node, fd,
			    off + PCIE_PCIECAP, 2, &pciecap)) {
				topo_mod_dprintf(mod, "failed to read PCIe "
				    "capabilities register");
				break;
			}

			pciever = pciecap & PCIE_PCIECAP_VER_MASK;
			if (pciever != PCIE_PCIECAP_VER_1_0 &&
			    pciever != PCIE_PCIECAP_VER_2_0) {
				topo_mod_dprintf(mod, "unsupported version "
				    "in PCIe capabilities register: 0x%x",
				    pciever);
				break;
			}

			/*
			 * In version 1 of the PCIe capability, devices were
			 * not required to implement the entire capability.
			 * Whilst most devices implemented the link status
			 * register, the v1 capability for an RC IEP does not
			 * include this, and stops short of the link status
			 * offset.
			 */
			if (pciever == PCIE_PCIECAP_VER_1_0 &&
			    (pciecap & PCIE_PCIECAP_DEV_TYPE_MASK) ==
			    PCIE_PCIECAP_DEV_TYPE_RC_IEP) {
				topo_mod_dprintf(mod, "RC IEP does not have "
				    "a link status register");
				break;
			}

			if (!read_cfgspace(mod, node, fd,
			    off + PCIE_LINKCAP, 4, &linkcap)) {
				topo_mod_dprintf(mod, "failed to read link "
				    "capabilities register");
				break;
			}

			if ((linkcap & PCIE_LINKCAP_DLL_ACTIVE_REP_CAPABLE) ==
			    0) {
				break;
			}

			if (!read_cfgspace(mod, node, fd,
			    off + PCIE_LINKSTS, 2, &status)) {
				topo_mod_dprintf(mod,
				    "failed to read link status register");
				break;
			}

			if ((status & PCIE_LINKSTS_DLL_LINK_ACTIVE) != 0)
				ret = PCI_LINK_UP;
			else
				ret = PCI_LINK_DOWN;
			break;
		}

		if (!read_cfgspace(mod, node, fd,
		    off + PCI_CAP_NEXT_PTR, 1, &nxt)) {
			topo_mod_dprintf(mod,
			    "failed to read next capability pointer");
			break;
		}

		off = nxt;
		ncaps++;
		if (ncaps >= PCI_CAP_MAX_PTR) {
			topo_mod_dprintf(mod, "encountered more PCI "
			    "capabilities than fit in configuration space");
			break;
		}
	}

out:
	topo_mod_dprintf(mod, "Reporting link as %s", ret ? "UP" : "DOWN");
	VERIFY0(close(fd));
	return (ret);
}
