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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/log.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/errorq.h>
#include <sys/controlregs.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/sysevent.h>
#include <sys/pghw.h>
#include <sys/cyclic.h>
#include <sys/pci_cfgspace.h>
#include <sys/mc_intel.h>
#include <sys/cpu_module_impl.h>
#include <sys/smbios.h>
#include <sys/pci.h>
#include "intel_nhm.h"
#include "nhm_log.h"

errorq_t *nhm_queue;
kmutex_t nhm_mutex;
uint32_t nhm_chipset;

nhm_dimm_t **nhm_dimms;

uint64_t nhm_memory_on_ctl[MAX_MEMORY_CONTROLLERS];
int nhm_patrol_scrub;
int nhm_demand_scrub;
int nhm_no_smbios;
int nhm_smbios_serial;
int nhm_smbios_manufacturer;
int nhm_smbios_part_number;
int nhm_smbios_version;
int nhm_smbios_label;

extern char ecc_enabled;
extern void mem_reg_init(void);

static void
check_serial_number()
{
	nhm_dimm_t *dimmp, *tp;
	nhm_dimm_t **dimmpp, **tpp;
	nhm_dimm_t **end;
	int not_unique;

	end = &nhm_dimms[MAX_MEMORY_CONTROLLERS *
	    CHANNELS_PER_MEMORY_CONTROLLER * MAX_DIMMS_PER_CHANNEL];
	for (dimmpp = nhm_dimms; dimmpp < end; dimmpp++) {
		dimmp = *dimmpp;
		if (dimmp == NULL)
			continue;
		not_unique = 0;
		for (tpp = dimmpp + 1; tpp < end; tpp++) {
			tp = *tpp;
			if (tp == NULL)
				continue;
			if (strncmp(dimmp->serial_number, tp->serial_number,
			    sizeof (dimmp->serial_number)) == 0) {
				not_unique = 1;
				tp->serial_number[0] = 0;
			}
		}
		if (not_unique)
			dimmp->serial_number[0] = 0;
	}
}

static void
dimm_manufacture_data(smbios_hdl_t *shp, id_t id, nhm_dimm_t *dimmp)
{
	smbios_info_t cd;

	if (smbios_info_common(shp, id, &cd) == 0) {
		if (cd.smbi_serial && nhm_smbios_serial) {
			(void) strncpy(dimmp->serial_number, cd.smbi_serial,
			    sizeof (dimmp->serial_number));
		}
		if (cd.smbi_manufacturer && nhm_smbios_manufacturer) {
			(void) strncpy(dimmp->manufacturer,
			    cd.smbi_manufacturer,
			    sizeof (dimmp->manufacturer));
		}
		if (cd.smbi_part && nhm_smbios_part_number) {
			(void) strncpy(dimmp->part_number, cd.smbi_part,
			    sizeof (dimmp->part_number));
		}
		if (cd.smbi_version && nhm_smbios_version) {
			(void) strncpy(dimmp->revision, cd.smbi_version,
			    sizeof (dimmp->revision));
		}
	}
}

struct dimm_slot {
	int controller;
	int channel;
	int dimm;
	int max_dimm;
};

static int
dimm_label(smbios_hdl_t *shp, const smbios_struct_t *sp, void *arg)
{
	nhm_dimm_t *dimmp;
	smbios_memdevice_t md;
	int slot;
	int last_slot;
	struct dimm_slot *dsp = (struct dimm_slot *)arg;

	slot = (dsp->controller * CHANNELS_PER_MEMORY_CONTROLLER *
	    MAX_DIMMS_PER_CHANNEL) + (dsp->channel * MAX_DIMMS_PER_CHANNEL) +
	    dsp->dimm;
	last_slot = MAX_MEMORY_CONTROLLERS * CHANNELS_PER_MEMORY_CONTROLLER *
	    MAX_DIMMS_PER_CHANNEL;
	if (slot >= last_slot)
		return (0);
	dimmp = nhm_dimms[slot];
	if (sp->smbstr_type == SMB_TYPE_MEMDEVICE) {
		if (smbios_info_memdevice(shp, sp->smbstr_id,
		    &md) == 0 && md.smbmd_dloc != NULL) {
			if (dimmp == NULL && md.smbmd_size) {
				/* skip non existent slot */
				dsp->channel++;
				if (dsp->dimm == 2)
					dsp->max_dimm = 2;
				dsp->dimm = 0;
				slot = (dsp->controller *
				    CHANNELS_PER_MEMORY_CONTROLLER *
				    MAX_DIMMS_PER_CHANNEL) +
				    (dsp->channel * MAX_DIMMS_PER_CHANNEL);
				if (slot >= last_slot)
					return (0);

				dimmp = nhm_dimms[slot];

				if (dimmp == NULL) {
					dsp->channel++;
					if (dsp->channel ==
					    CHANNELS_PER_MEMORY_CONTROLLER) {
						dsp->channel = 0;
						dsp->controller++;
					}
					slot = (dsp->controller *
					    CHANNELS_PER_MEMORY_CONTROLLER *
					    MAX_DIMMS_PER_CHANNEL) +
					    (dsp->channel *
					    MAX_DIMMS_PER_CHANNEL);
					if (slot >= last_slot)
						return (0);
					dimmp = nhm_dimms[slot];
				}
			}
			if (dimmp) {
				if (nhm_smbios_label)
					(void) snprintf(dimmp->label,
					    sizeof (dimmp->label), "%s",
					    md.smbmd_dloc);
				dimm_manufacture_data(shp, sp->smbstr_id,
				    dimmp);
			}
		}
		dsp->dimm++;
		if (dsp->dimm == dsp->max_dimm) {
			dsp->dimm = 0;
			dsp->channel++;
			if (dsp->channel == CHANNELS_PER_MEMORY_CONTROLLER) {
				dsp->channel = 0;
				dsp->controller++;
			}
		}
	}
	return (0);
}

void
nhm_smbios()
{
	struct dimm_slot ds;

	if (ksmbios != NULL && nhm_no_smbios == 0) {
		ds.dimm = 0;
		ds.channel = 0;
		ds.controller = 0;
		ds.max_dimm = MAX_DIMMS_PER_CHANNEL;
		(void) smbios_iter(ksmbios, dimm_label, &ds);
		check_serial_number();
	}
}

static void
dimm_prop(nhm_dimm_t *dimmp, uint32_t dod)
{
	dimmp->dimm_size = DIMMSIZE(dod);
	dimmp->nranks = NUMRANK(dod);
	dimmp->nbanks = NUMBANK(dod);
	dimmp->ncolumn = NUMCOL(dod);
	dimmp->nrow = NUMROW(dod);
	dimmp->width = DIMMWIDTH;
}

void
nhm_scrubber_enable()
{
	uint32_t mc_ssrcontrol;
	uint32_t mc_dimm_clk_ratio_status;
	uint64_t cycle_time;
	uint32_t interval;
	int i;
	int hw_scrub = 0;

	if (ecc_enabled && (nhm_patrol_scrub || nhm_demand_scrub)) {
		for (i = 0; i < MAX_MEMORY_CONTROLLERS; i++) {
			if (nhm_memory_on_ctl[i] == 0)
				continue;
			mc_ssrcontrol = MC_SSR_CONTROL_RD(i);
			if (nhm_demand_scrub &&
			    (mc_ssrcontrol & DEMAND_SCRUB_ENABLE) == 0) {
				mc_ssrcontrol |= DEMAND_SCRUB_ENABLE;
				MC_SSR_CONTROL_WR(i, mc_ssrcontrol);
			}
			if (nhm_patrol_scrub == 0)
				continue;
			if (SSR_MODE(mc_ssrcontrol) == SSR_IDLE) {
				mc_dimm_clk_ratio_status =
				    MC_DIMM_CLK_RATIO_STATUS(i);
				cycle_time =
				    MAX_DIMM_CLK_RATIO(mc_dimm_clk_ratio_status)
				    * 80000000;
				interval = (uint32_t)((36400ULL * cycle_time) /
				    (nhm_memory_on_ctl[i]/64));
				MC_SCRUB_CONTROL_WR(i, STARTSCRUB | interval);
				MC_SSR_CONTROL_WR(i, mc_ssrcontrol | SSR_SCRUB);
			} else if (SSR_MODE(mc_ssrcontrol) == SSR_SPARE) {
				hw_scrub = 0;
				break;
			}
			hw_scrub = 1;
		}
		if (hw_scrub)
			cmi_mc_sw_memscrub_disable();
	}
}

void
init_dimms()
{
	int i, j, k;
	nhm_dimm_t **dimmpp;
	nhm_dimm_t *dimmp;
	uint32_t dod;

	nhm_dimms = (nhm_dimm_t **)kmem_zalloc(sizeof (nhm_dimm_t *) *
	    MAX_MEMORY_CONTROLLERS * CHANNELS_PER_MEMORY_CONTROLLER *
	    MAX_DIMMS_PER_CHANNEL, KM_SLEEP);
	dimmpp = nhm_dimms;
	for (i = 0; i < MAX_MEMORY_CONTROLLERS; i++) {
		if (CPU_ID_RD(i) != NHM_CPU) {
			dimmpp += CHANNELS_PER_MEMORY_CONTROLLER *
			    MAX_DIMMS_PER_CHANNEL;
			continue;
		}
		for (j = 0; j < CHANNELS_PER_MEMORY_CONTROLLER; j++) {
			for (k = 0; k < MAX_DIMMS_PER_CHANNEL; k++) {
				dod = MC_DOD_RD(i, j, k);
				if (DIMMPRESENT(dod)) {
					dimmp = (nhm_dimm_t *)
					    kmem_zalloc(sizeof (nhm_dimm_t),
					    KM_SLEEP);
					dimm_prop(dimmp, dod);
					(void) snprintf(dimmp->label,
					    sizeof (dimmp->label),
					    "Socket %d channel %d dimm %d",
					    i, j, k);
					*dimmpp = dimmp;
					nhm_memory_on_ctl[i] +=
					    dimmp->dimm_size;
				}
				dimmpp++;
			}
		}
	}
}


int
nhm_init(void)
{
	int slot;

	/* return ENOTSUP if there is no PCI config space support. */
	if (pci_getl_func == NULL)
		return (ENOTSUP);
	for (slot = 0; slot < MAX_CPU_NODES; slot++) {
		nhm_chipset = CPU_ID_RD(slot);
		if (nhm_chipset == NHM_CPU)
			break;
	}
	if (nhm_chipset != NHM_CPU) {
		return (ENOTSUP);
	}
	mem_reg_init();
	return (0);
}

int
nhm_reinit(void)
{
	mem_reg_init();
	return (0);
}

int
nhm_dev_init()
{
	return (0);
}

void
nhm_dev_reinit()
{
}

void
nhm_unload()
{
}
