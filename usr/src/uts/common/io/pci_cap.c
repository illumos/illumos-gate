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

#include <sys/note.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/bitmap.h>
#include <sys/autoconf.h>
#include <sys/sysmacros.h>
#include <sys/pci_cap.h>

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Generic PCI Capabilites Interface for all pci platforms
 */

#ifdef DEBUG
uint_t  pci_cap_debug = 0;
#endif

/* Cap Base Macro */
#define	PCI_CAP_BASE(h, id, base_p) (*base_p ? DDI_SUCCESS : \
	(id ? PCI_CAP_LOCATE(h, id, base_p) : DDI_FAILURE))

/*
 * pci_cap_probe: returns the capid and base based upon a given index
 */
int
pci_cap_probe(ddi_acc_handle_t h, uint16_t index,
	uint32_t *id_p, uint16_t *base_p)
{
	int i, search_ext = 0;
	uint16_t base, pcix_cmd, status;
	uint32_t id, xcaps_hdr; /* Extended Caps Header Word */

	status = pci_config_get16(h, PCI_CONF_STAT);

	if (status == PCI_CAP_EINVAL16 || !(status & PCI_STAT_CAP))
		return (DDI_FAILURE);

	/* PCIE and PCIX Version 2 contain Extended Config Space */
	for (i = 0, base = pci_config_get8(h, PCI_CONF_CAP_PTR);
		base && i < index; base = pci_config_get8(h, base
			+ PCI_CAP_NEXT_PTR), i++) {

		if ((id = pci_config_get8(h, base)) == 0xff)
			break;

		if (id == PCI_CAP_ID_PCI_E)
			search_ext = 1;
		else if (id == PCI_CAP_ID_PCIX) {
			if ((pcix_cmd = pci_config_get16(h, base +
				PCI_PCIX_COMMAND)) != PCI_CAP_EINVAL16)
				continue;
			if ((pcix_cmd & PCI_PCIX_VER_MASK) == PCI_PCIX_VER_2)
				search_ext = 1;
		}
	}

	if (base && i == index) {
		if ((id = pci_config_get8(h, base)) != 0xff)
			goto found;
	}

	if (!search_ext)
		return (DDI_FAILURE);

	for (base = PCIE_EXT_CAP; base && i < index; i++) {
		if ((xcaps_hdr = pci_config_get32(h, base)) == PCI_CAP_EINVAL32)
			break;

		id = (xcaps_hdr >> PCIE_EXT_CAP_ID_SHIFT)
			& PCIE_EXT_CAP_ID_MASK;
		base = (xcaps_hdr >> PCIE_EXT_CAP_NEXT_PTR_SHIFT)
			& PCIE_EXT_CAP_NEXT_PTR_MASK;
	}

	if (!base || i < index)
		return (DDI_FAILURE);

	if ((xcaps_hdr = pci_config_get32(h, base)) == PCI_CAP_EINVAL32)
		return (DDI_FAILURE);

	id = ((xcaps_hdr >> PCIE_EXT_CAP_ID_SHIFT) & PCIE_EXT_CAP_ID_MASK) |
			PCI_CAP_XCFG_FLAG;
found:
	PCI_CAP_DBG("pci_cap_probe: index=%x, id=%x, base=%x\n",
		index, id, base);

	*id_p = id;
	*base_p = base;
	return (DDI_SUCCESS);

}

/*
 * pci_lcap_locate: Helper function locates a base in conventional config space.
 */
int
pci_lcap_locate(ddi_acc_handle_t h, uint8_t id, uint16_t *base_p)
{
	uint16_t status, base;

	status = pci_config_get16(h, PCI_CONF_STAT);

	if (status == PCI_CAP_EINVAL16 || !(status & PCI_STAT_CAP))
		return (DDI_FAILURE);

	for (base = pci_config_get8(h, PCI_CONF_CAP_PTR); base;
		base = pci_config_get8(h, base + PCI_CAP_NEXT_PTR)) {
		if (pci_config_get8(h, base) == id) {
			*base_p = base;
			return (DDI_SUCCESS);
		}
	}

	*base_p = PCI_CAP_NEXT_PTR_NULL;
	return (DDI_FAILURE);


}

/*
 * pci_xcap_locate: Helper function locates a base in extended config space.
 */
int
pci_xcap_locate(ddi_acc_handle_t h, uint16_t id, uint16_t *base_p)
{
	uint16_t status, base;
	uint32_t xcaps_hdr;

	status = pci_config_get16(h, PCI_CONF_STAT);

	if (status == PCI_CAP_EINVAL16 || !(status & PCI_STAT_CAP))
		return (DDI_FAILURE);

	for (base = PCIE_EXT_CAP; base; base = (xcaps_hdr >>
		PCIE_EXT_CAP_NEXT_PTR_SHIFT) & PCIE_EXT_CAP_NEXT_PTR_MASK) {

		if ((xcaps_hdr = pci_config_get32(h, base)) == PCI_CAP_EINVAL32)
			break;

		if (((xcaps_hdr >> PCIE_EXT_CAP_ID_SHIFT) &
			PCIE_EXT_CAP_ID_MASK) == id) {
			*base_p = base;
			return (DDI_SUCCESS);
		}
	}

	*base_p = PCI_CAP_NEXT_PTR_NULL;
	return (DDI_FAILURE);
}

/*
 * pci_cap_get: This function uses the base or capid to get a byte, word,
 * or dword. If access by capid is requested, the function uses the capid to
 * locate the base. Access by a base results in better performance
 * because no cap list traversal is required.
 */
uint32_t
pci_cap_get(ddi_acc_handle_t h, pci_cap_config_size_t size,
	uint32_t id, uint16_t base, uint16_t offset)
{
	uint32_t data;

	if (PCI_CAP_BASE(h, id, &base) != DDI_SUCCESS)
		return (PCI_CAP_EINVAL32);

	/*
	 * Each access to a PCI Configuration Space should be checked
	 * by the calling function. A returned value of the 2's complement
	 * of -1 indicates that either the device is offlined or it does not
	 * exist.
	 */
	offset += base;

	switch (size) {
	case PCI_CAP_CFGSZ_8:
		data = pci_config_get8(h, offset);
		break;
	case PCI_CAP_CFGSZ_16:
		data = pci_config_get16(h, offset);
		break;
	case PCI_CAP_CFGSZ_32:
		data = pci_config_get32(h, offset);
		break;
	default:
		data = PCI_CAP_EINVAL32;
	}

	PCI_CAP_DBG("pci_cap_get: %p[x%x]=x%x\n", (void *)h, offset, data);
	return (data);
}

/*
 * pci_cap_put: This function uses the caps ptr or capid to put a byte, word,
 * or dword. If access by capid is requested, the function uses the capid to
 * locate the base. Access by base results in better performance
 * because no cap list traversal is required.
 */
int
pci_cap_put(ddi_acc_handle_t h, pci_cap_config_size_t size,
	uint32_t id, uint16_t base, uint16_t offset,
	uint32_t data)
{

	/*
	 * use the pci_config_size_t to switch for the appropriate read
	 */
	if (PCI_CAP_BASE(h, id, &base) != DDI_SUCCESS)
		return (DDI_FAILURE);

	offset += base;

	switch (size) {
	case PCI_CAP_CFGSZ_8:
		pci_config_put8(h, offset, data);
		break;
	case PCI_CAP_CFGSZ_16:
		pci_config_put16(h, offset, data);
		break;
	case PCI_CAP_CFGSZ_32:
		pci_config_put32(h, offset, data);
		break;
	default:
		return (DDI_FAILURE);
	}

	PCI_CAP_DBG("pci_cap_put: data=%x\n", data);
	return (DDI_SUCCESS);
}

/*
 * Cache the entire Cap Structure.  The caller is required to allocate and free
 * buffer.
 */
int
pci_cap_read(ddi_acc_handle_t h, uint32_t id, uint16_t base,
	uint32_t *buf_p, uint32_t nwords)
{

	int i;
	uint32_t *ptr;

	ASSERT(nwords < 1024);

	if (PCI_CAP_BASE(h, id, &base) != DDI_SUCCESS)
		return (DDI_FAILURE);

	for (ptr = buf_p, i = 0; i < nwords; i++, base += 4) {
		if ((*ptr++ = pci_config_get32(h, base)) == PCI_CAP_EINVAL32)
			return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}
