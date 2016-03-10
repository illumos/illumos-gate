/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/pcie.h>

/* PCIe 3.0 link speeds */
#ifndef PCIE_LINKCAP_MAX_SPEED_5
#define	PCIE_LINKCAP_MAX_SPEED_5	0x2
#endif
#ifndef PCIE_LINKSTS_SPEED_5
#define	PCIE_LINKSTS_SPEED_5		0x2
#endif
#ifndef PCIE_LINKCAP_MAX_SPEED_8
#define	PCIE_LINKCAP_MAX_SPEED_8	0x3
#endif
#ifndef PCIE_LINKSTS_SPEED_8
#define	PCIE_LINKSTS_SPEED_8		0x3
#endif

#include "sfxge.h"

int
sfxge_pci_cap_find(sfxge_t *sp, uint8_t cap_id, off_t *offp)
{
	off_t off;
	uint16_t stat;
	int rc;

	stat = pci_config_get16(sp->s_pci_handle, PCI_CONF_STAT);

	if (!(stat & PCI_STAT_CAP)) {
		rc = ENOTSUP;
		goto fail1;
	}

	for (off = pci_config_get8(sp->s_pci_handle, PCI_CONF_CAP_PTR);
	    off != PCI_CAP_NEXT_PTR_NULL;
	    off = pci_config_get8(sp->s_pci_handle, off + PCI_CAP_NEXT_PTR)) {
		if (cap_id == pci_config_get8(sp->s_pci_handle,
		    off + PCI_CAP_ID))
			goto done;
	}

	rc = ENOENT;
	goto fail2;

done:
	*offp = off;
	return (0);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

int
sfxge_pci_init(sfxge_t *sp)
{
	off_t off;
	uint16_t pciecap;
	uint16_t devctl;
	uint16_t linksts;
	uint16_t max_payload_size;
	uint16_t max_read_request;
	int rc;
#if EFSYS_OPT_MCDI_LOGGING
	int *pci_regs;
	uint_t pci_nregs = 0;

	/*
	 * We need the PCI bus address to format MCDI logging output in the
	 * same way as on other platforms.
	 * It appears there's no straightforward way to extract the address
	 * from a "dev_info_t" structure, though.
	 * The "reg" property is supported by all PCIe devices, and contains
	 * an arbitrary length array of elements describing logical
	 * resources. Each element contains a 5-tuple of 32bit values,
	 * where the first 32bit value contains the bus/dev/fn slot
	 * information.
	 * See pci(4) and the definition of "struct pci_phys_spec" in sys/pci.h
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_regs, &pci_nregs) !=
	    DDI_PROP_SUCCESS) {
		rc = ENODEV;
		goto fail1;
	}
	sp->s_bus_addr = pci_regs[0];
	ddi_prop_free(pci_regs);
#endif

	if (pci_config_setup(sp->s_dip, &(sp->s_pci_handle)) != DDI_SUCCESS) {
		rc = ENODEV;
		goto fail1;
	}

	sp->s_pci_venid = pci_config_get16(sp->s_pci_handle, PCI_CONF_VENID);
	sp->s_pci_devid = pci_config_get16(sp->s_pci_handle, PCI_CONF_DEVID);
	if ((rc = efx_family(sp->s_pci_venid, sp->s_pci_devid,
	    &sp->s_family)) != 0)
		goto fail2;

	if ((rc = sfxge_pci_cap_find(sp, PCI_CAP_ID_PCI_E, &off)) != 0)
		goto fail3;

	pciecap = pci_config_get16(sp->s_pci_handle, off + PCIE_PCIECAP);
	ASSERT3U((pciecap & PCIE_PCIECAP_VER_MASK), >=, PCIE_PCIECAP_VER_1_0);

	linksts = pci_config_get16(sp->s_pci_handle, off + PCIE_LINKSTS);
	switch (linksts & PCIE_LINKSTS_NEG_WIDTH_MASK) {
	case PCIE_LINKSTS_NEG_WIDTH_X1:
		sp->s_pcie_nlanes = 1;
		break;

	case PCIE_LINKSTS_NEG_WIDTH_X2:
		sp->s_pcie_nlanes = 2;
		break;

	case PCIE_LINKSTS_NEG_WIDTH_X4:
		sp->s_pcie_nlanes = 4;
		break;

	case PCIE_LINKSTS_NEG_WIDTH_X8:
		sp->s_pcie_nlanes = 8;
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}

	switch (linksts & PCIE_LINKSTS_SPEED_MASK) {
	case PCIE_LINKSTS_SPEED_2_5:
		sp->s_pcie_linkspeed = 1;
		break;

	case PCIE_LINKSTS_SPEED_5:
		sp->s_pcie_linkspeed = 2;
		break;

	case PCIE_LINKSTS_SPEED_8:
		sp->s_pcie_linkspeed = 3;
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}

	devctl = pci_config_get16(sp->s_pci_handle, off + PCIE_DEVCTL);

	max_payload_size = (devctl & PCIE_DEVCTL_MAX_PAYLOAD_MASK)
	    >> PCIE_DEVCTL_MAX_PAYLOAD_SHIFT;

	max_read_request = (devctl & PCIE_DEVCTL_MAX_READ_REQ_MASK)
	    >> PCIE_DEVCTL_MAX_READ_REQ_SHIFT;

	dev_err(sp->s_dip, CE_NOTE,
	    SFXGE_CMN_ERR "PCIe MRR: %d TLP: %d Link: %s Lanes: x%d",
	    128 << max_read_request,
	    128 << max_payload_size,
	    (sp->s_pcie_linkspeed == 1) ? "2.5G" :
	    (sp->s_pcie_linkspeed == 2) ? "5.0G" :
	    (sp->s_pcie_linkspeed == 3) ? "8.0G" :
	    "UNKNOWN",
	    sp->s_pcie_nlanes);

	return (0);

fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);

	pci_config_teardown(&(sp->s_pci_handle));
	sp->s_pci_handle = NULL;

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

void
sfxge_pcie_check_link(sfxge_t *sp, unsigned int full_nlanes,
    unsigned int full_speed)
{
	if ((sp->s_pcie_linkspeed < full_speed) ||
	    (sp->s_pcie_nlanes    < full_nlanes))
		dev_err(sp->s_dip, CE_NOTE,
		    SFXGE_CMN_ERR "This device requires %d PCIe lanes "
		    "at %s link speed to reach full bandwidth.",
		    full_nlanes,
		    (full_speed == 1) ? "2.5G" :
		    (full_speed == 2) ? "5.0G" :
		    (full_speed == 3) ? "8.0G" :
		    "UNKNOWN");
}

void
sfxge_pci_fini(sfxge_t *sp)
{
	sp->s_pcie_nlanes = 0;
	sp->s_pcie_linkspeed = 0;

	pci_config_teardown(&(sp->s_pci_handle));
	sp->s_pci_handle = NULL;
}
