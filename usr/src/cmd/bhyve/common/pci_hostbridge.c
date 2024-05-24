/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (c) 2018 Joyent, Inc.
 * Copyright 2021 Oxide Computer Company
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __FreeBSD__
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <err.h>
#endif

#include <stdlib.h>

#include "config.h"
#include "pci_emul.h"
#ifndef __FreeBSD__
#include "bhyverun.h"
#endif

#ifndef __FreeBSD__
static struct pci_hostbridge_model {
	const char	*phm_model;
	uint16_t	phm_vendor;
	uint16_t	phm_device;
} pci_hb_models[] = {
	{ "amd",	0x1022, 0x7432 }, /* AMD/made-up */
	{ "netapp",	0x1275, 0x1275 }, /* NetApp/NetApp */
	{ "i440fx",	0x8086, 0x1237 }, /* Intel/82441 */
	{ "q35",	0x8086, 0x29b0 }, /* Intel/Q35 HB */
};

#define	NUM_HB_MODELS	(sizeof (pci_hb_models) / sizeof (pci_hb_models[0]))
#endif

static int
pci_hostbridge_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	const char *value;
	u_int vendor, device;

#ifdef __FreeBSD__
	vendor = 0x1275;	/* NetApp */
	device = 0x1275;	/* NetApp */
#else
	vendor = device = 0;
#endif

	value = get_config_value_node(nvl, "vendor");
	if (value != NULL)
		vendor = strtol(value, NULL, 0);
	else
		vendor = pci_config_read_reg(NULL, nvl, PCIR_VENDOR, 2, vendor);
	value = get_config_value_node(nvl, "devid");
	if (value != NULL)
		device = strtol(value, NULL, 0);
	else
		device = pci_config_read_reg(NULL, nvl, PCIR_DEVICE, 2, device);

#ifndef __FreeBSD__
	const char *model = get_config_value_node(nvl, "model");

	if (model != NULL && (vendor != 0 || device != 0)) {
		warnx("pci_hostbridge: cannot specify model and vendor/device");
		return (-1);
	} else if ((vendor != 0 && device == 0) ||
	    (vendor == 0 && device != 0)) {
		warnx("pci_hostbridge: must specify both vendor and "
		    "device for custom hostbridge");
		return (-1);
	}
	if (model == NULL && vendor == 0 && device == 0)
		model = "netapp";

	if (model != NULL) {
		for (uint_t i = 0; i < NUM_HB_MODELS; i++) {
			if (strcmp(model, pci_hb_models[i].phm_model) != 0)
				continue;

			/* found a model match */
			vendor = pci_hb_models[i].phm_vendor;
			device = pci_hb_models[i].phm_device;
			break;
		}
		if (vendor == 0) {
			warnx("pci_hostbridge: invalid model '%s'", model);
			return (-1);
		}
	}

	/* Both i440fx and Q35 chipsets feature the concept of Programmable
	 * Address Memory (PAM), where certain physical address ranges can be
	 * configured to direct reads/writes to either DRAM, or to the PCI MMIO
	 * space instead.  At boot, they default to bypassing DRAM, so in order
	 * to cheaply paper over our lack of emulation, the memory in PAM0
	 * (0xf0000-0xfffff, the System BIOS segment) should be zeroed.
	 *
	 * If this emulation is expanded in the future to truly support PAM
	 * behavior, this hack can be removed.
	 */
	if (vendor == 0x8086 && (device == 0x1237 || device == 0x29b0)) {
		const uintptr_t start = 0xf0000;
		const size_t len = 0x10000;
		void *system_bios_region = paddr_guest2host(pi->pi_vmctx,
		    start, len);
		assert(system_bios_region != NULL);
		bzero(system_bios_region, len);
	}
#endif /* !__FreeBSD__ */

	/* config space */
	pci_set_cfgdata16(pi, PCIR_VENDOR, vendor);
	pci_set_cfgdata16(pi, PCIR_DEVICE, device);
	pci_set_cfgdata8(pi, PCIR_HDRTYPE, PCIM_HDRTYPE_NORMAL);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_BRIDGE);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_BRIDGE_HOST);

	pci_emul_add_pciecap(pi, PCIEM_TYPE_ROOT_PORT);

	return (0);
}

static int
pci_amd_hostbridge_legacy_config(nvlist_t *nvl, const char *opts __unused)
{
	nvlist_t *pci_regs;

	pci_regs = create_relative_config_node(nvl, "pcireg");
	if (pci_regs == NULL) {
		warnx("amd_hostbridge: failed to create pciregs node");
		return (-1);
	}
	set_config_value_node(pci_regs, "vendor", "0x1022");	/* AMD */
	set_config_value_node(pci_regs, "device", "0x7432");	/* made up */

	return (0);
}

static const struct pci_devemu pci_de_amd_hostbridge = {
	.pe_emu = "amd_hostbridge",
	.pe_legacy_config = pci_amd_hostbridge_legacy_config,
	.pe_alias = "hostbridge",
};
PCI_EMUL_SET(pci_de_amd_hostbridge);

static const struct pci_devemu pci_de_hostbridge = {
	.pe_emu = "hostbridge",
	.pe_init = pci_hostbridge_init,
};
PCI_EMUL_SET(pci_de_hostbridge);
