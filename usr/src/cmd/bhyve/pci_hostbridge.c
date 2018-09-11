/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (c) 2018 Joyent, Inc.
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
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
#ifndef __FreeBSD__
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#endif
__FBSDID("$FreeBSD$");

#include "pci_emul.h"

#ifdef __FreeBSD__
static int
pci_hostbridge_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{

	/* config space */
	pci_set_cfgdata16(pi, PCIR_VENDOR, 0x1275);	/* NetApp */
	pci_set_cfgdata16(pi, PCIR_DEVICE, 0x1275);	/* NetApp */
	pci_set_cfgdata8(pi, PCIR_HDRTYPE, PCIM_HDRTYPE_NORMAL);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_BRIDGE);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_BRIDGE_HOST);

	pci_emul_add_pciecap(pi, PCIEM_TYPE_ROOT_PORT);

	return (0);
}

static int
pci_amd_hostbridge_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	(void) pci_hostbridge_init(ctx, pi, opts);
	pci_set_cfgdata16(pi, PCIR_VENDOR, 0x1022);	/* AMD */
	pci_set_cfgdata16(pi, PCIR_DEVICE, 0x7432);	/* made up */

	return (0);
}
#else
static void
pci_hostbridge_setup(struct pci_devinst *pi, uint16_t vendor, uint16_t device)
{
	/* config space */
	pci_set_cfgdata16(pi, PCIR_VENDOR, vendor);
	pci_set_cfgdata16(pi, PCIR_DEVICE, device);
	pci_set_cfgdata8(pi, PCIR_HDRTYPE, PCIM_HDRTYPE_NORMAL);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_BRIDGE);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_BRIDGE_HOST);

	pci_emul_add_pciecap(pi, PCIEM_TYPE_ROOT_PORT);
}


static int
pci_hostbridge_parse_pci_val(const char *in, uint16_t *val)
{
	long num;
	char *endp = NULL;

	errno = 0;
	num = strtol(in, &endp, 0);
	if (errno != 0 || endp == NULL || *endp != '\0') {
		fprintf(stderr, "pci_hostbridge: invalid num '%s'", in);
		return (-1);
	} else if (num < 1 || num > UINT16_MAX) {
		fprintf(stderr, "pci_hostbridge: 0x%04lx out of range", num);
		return (-1);
	}
	*val = num;
	return (0);
}

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

static int
pci_hostbridge_parse_args(char *opts, uint16_t *vendorp, uint16_t *devicep)
{
	const char *model = NULL;
	char *next;
	uint16_t vendor = 0, device = 0;
	int err = 0;

	for (; opts != NULL && *opts != '\0'; opts = next) {
		char *val, *cp;

		if ((cp = strchr(opts, ',')) != NULL) {
			*cp = '\0';
			next = cp + 1;
		} else {
			next = NULL;
		}

		if ((cp = strchr(opts, '=')) == NULL) {
			fprintf(stderr,
			    "pci_hostbridge: expected value for param"
			    " (%s=VAL)", opts);
			err = -1;
			continue;
		}

		/* <param>=<value> handling */
		val = cp + 1;
		*cp = '\0';
		if (strcmp(opts, "model") == 0) {
			model = val;
		} else if (strcmp(opts, "vendor") == 0) {
			if (pci_hostbridge_parse_pci_val(val, &vendor) != 0) {
				err = -1;
				continue;
			}
		} else if (strcmp(opts, "device") == 0) {
			if (pci_hostbridge_parse_pci_val(val, &device) != 0) {
				err = -1;
				continue;
			}
		} else {
			fprintf(stderr,
			    "pci_hostbridge: unrecognized option '%s'", opts);
			err = -1;
			continue;
		}
	}
	if (err != 0) {
		return (err);
	}

	if (model != NULL && (vendor != 0 || device != 0)) {
		fprintf(stderr, "pci_hostbridge: cannot specify model "
		    "and vendor/device");
		return (-1);
	} else if ((vendor != 0 && device == 0) ||
	    (vendor == 0 && device != 0)) {
		fprintf(stderr, "pci_hostbridge: must specify both vendor and"
		    "device for custom hostbridge");
		return (-1);
	}
	if (model != NULL) {
		uint_t i;

		for (i = 0; i < NUM_HB_MODELS; i++) {
			if (strcmp(model, pci_hb_models[i].phm_model) != 0)
				continue;

			/* found a model match */
			*vendorp = pci_hb_models[i].phm_vendor;
			*devicep = pci_hb_models[i].phm_device;
			return (0);
		}
		fprintf(stderr, "pci_hostbridge: invalid model '%s'", model);
		return (-1);
	}

	/* custom hostbridge ID was specified */
	*vendorp = vendor;
	*devicep = device;
	return (0);
}

static int
pci_hostbridge_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	uint16_t vendor, device;

	if (opts == NULL) {
		/* Fall back to NetApp default if no options are specified */
		vendor = 0x1275;
		device = 0x1275;
	} else if (pci_hostbridge_parse_args(opts, &vendor, &device) != 0) {
		return (-1);
	}

	pci_hostbridge_setup(pi, vendor, device);
	return (0);
}

static int
pci_amd_hostbridge_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	pci_hostbridge_setup(pi, 0x1022, 0x7432);
	return (0);
}

#endif /* __FreeBSD__ */

struct pci_devemu pci_de_amd_hostbridge = {
	.pe_emu = "amd_hostbridge",
	.pe_init = pci_amd_hostbridge_init,
};
PCI_EMUL_SET(pci_de_amd_hostbridge);

struct pci_devemu pci_de_hostbridge = {
	.pe_emu = "hostbridge",
	.pe_init = pci_hostbridge_init,
};
PCI_EMUL_SET(pci_de_hostbridge);
