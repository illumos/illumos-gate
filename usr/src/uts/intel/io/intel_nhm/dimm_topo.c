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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/nvpair.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/cyclic.h>
#include <sys/errorq.h>
#include <sys/stat.h>
#include <sys/cpuvar.h>
#include <sys/mc_intel.h>
#include <sys/mc.h>
#include <sys/fm/protocol.h>
#include "nhm_log.h"
#include "intel_nhm.h"

extern nvlist_t *inhm_mc_nvl[MAX_CPU_NODES];
extern char closed_page;
extern char ecc_enabled;
extern char lockstep[MAX_CPU_NODES];
extern char mirror_mode[MAX_CPU_NODES];
extern char spare_channel[MAX_CPU_NODES];

static void
inhm_vrank(nvlist_t *vrank, int num, uint64_t dimm_base, uint64_t limit,
    uint32_t sinterleave, uint32_t cinterleave, uint32_t rinterleave,
    uint32_t sway, uint32_t cway, uint32_t rway)
{
	char buf[128];

	(void) snprintf(buf, sizeof (buf), "dimm-rank-base-%d", num);
	(void) nvlist_add_uint64(vrank, buf, dimm_base);
	(void) snprintf(buf, sizeof (buf), "dimm-rank-limit-%d", num);
	(void) nvlist_add_uint64(vrank, buf, dimm_base + limit);
	if (sinterleave > 1) {
		(void) snprintf(buf, sizeof (buf), "dimm-socket-interleave-%d",
		    num);
		(void) nvlist_add_uint32(vrank, buf, sinterleave);
		(void) snprintf(buf, sizeof (buf),
		    "dimm-socket-interleave-way-%d", num);
		(void) nvlist_add_uint32(vrank, buf, sway);
	}
	if (cinterleave > 1) {
		(void) snprintf(buf, sizeof (buf), "dimm-channel-interleave-%d",
		    num);
		(void) nvlist_add_uint32(vrank, buf, cinterleave);
		(void) snprintf(buf, sizeof (buf),
		    "dimm-channel-interleave-way-%d", num);
		(void) nvlist_add_uint32(vrank, buf, cway);
	}
	if (rinterleave > 1) {
		(void) snprintf(buf, sizeof (buf), "dimm-rank-interleave-%d",
		    num);
		(void) nvlist_add_uint32(vrank, buf, rinterleave);
		(void) snprintf(buf, sizeof (buf),
		    "dimm-rank-interleave-way-%d", num);
		(void) nvlist_add_uint32(vrank, buf, rway);
	}
}

static void
inhm_rank(nvlist_t *newdimm, nhm_dimm_t *nhm_dimm, uint32_t node,
    uint8_t channel, uint32_t dimm, uint64_t rank_size)
{
	nvlist_t **newrank;
	int num;
	int i;
	uint64_t dimm_base;
	uint64_t vrank_sz;
	uint64_t rank_addr;
	uint64_t pa;
	uint32_t sinterleave, cinterleave, rinterleave;
	uint32_t sway, cway, rway;

	newrank = kmem_zalloc(sizeof (nvlist_t *) * nhm_dimm->nranks, KM_SLEEP);
	for (i = 0; i < nhm_dimm->nranks; i++) {
		(void) nvlist_alloc(&newrank[i], NV_UNIQUE_NAME, KM_SLEEP);
		rank_addr = 0;
		num = 0;
		while (rank_addr < rank_size) {
			pa = dimm_to_addr(node, channel, dimm * 4 + i,
			    rank_addr, &dimm_base, &vrank_sz, &sinterleave,
			    &cinterleave, &rinterleave, &sway, &cway, &rway);
			if (pa == -1 || vrank_sz == 0)
				break;
			inhm_vrank(newrank[i], num, dimm_base,
			    vrank_sz * sinterleave * cinterleave * rinterleave,
			    sinterleave, cinterleave, rinterleave, sway, cway,
			    rway);
			rank_addr += vrank_sz;
			num++;
		}

	}
	(void) nvlist_add_nvlist_array(newdimm, MCINTEL_NVLIST_RANKS, newrank,
	    nhm_dimm->nranks);
	for (i = 0; i < nhm_dimm->nranks; i++)
		nvlist_free(newrank[i]);
	kmem_free(newrank, sizeof (nvlist_t *) * nhm_dimm->nranks);
}

static nvlist_t *
inhm_dimm(nhm_dimm_t *nhm_dimm, uint32_t node, uint8_t channel, uint32_t dimm)
{
	nvlist_t *newdimm;
	uint8_t t;
	char sbuf[65];

	(void) nvlist_alloc(&newdimm, NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_uint32(newdimm, "dimm-number", dimm);

	if (nhm_dimm->dimm_size >= 1024*1024*1024) {
		(void) snprintf(sbuf, sizeof (sbuf), "%dG",
		    (int)(nhm_dimm->dimm_size / (1024*1024*1024)));
	} else {
		(void) snprintf(sbuf, sizeof (sbuf), "%dM",
		    (int)(nhm_dimm->dimm_size / (1024*1024)));
	}
	(void) nvlist_add_string(newdimm, "dimm-size", sbuf);
	(void) nvlist_add_uint64(newdimm, "size", nhm_dimm->dimm_size);
	(void) nvlist_add_uint32(newdimm, "nbanks", (uint32_t)nhm_dimm->nbanks);
	(void) nvlist_add_uint32(newdimm, "ncolumn",
	    (uint32_t)nhm_dimm->ncolumn);
	(void) nvlist_add_uint32(newdimm, "nrow", (uint32_t)nhm_dimm->nrow);
	(void) nvlist_add_uint32(newdimm, "width", (uint32_t)nhm_dimm->width);
	(void) nvlist_add_uint32(newdimm, "ranks", (uint32_t)nhm_dimm->nranks);
	inhm_rank(newdimm, nhm_dimm, node, channel, dimm,
	    nhm_dimm->dimm_size / nhm_dimm->nranks);
	if (nhm_dimm->manufacturer && nhm_dimm->manufacturer[0]) {
		t = sizeof (nhm_dimm->manufacturer);
		(void) strncpy(sbuf, nhm_dimm->manufacturer, t);
		sbuf[t] = 0;
		(void) nvlist_add_string(newdimm, "manufacturer", sbuf);
	}
	if (nhm_dimm->serial_number && nhm_dimm->serial_number[0]) {
		t = sizeof (nhm_dimm->serial_number);
		(void) strncpy(sbuf, nhm_dimm->serial_number, t);
		sbuf[t] = 0;
		(void) nvlist_add_string(newdimm, FM_FMRI_HC_SERIAL_ID, sbuf);
	}
	if (nhm_dimm->part_number && nhm_dimm->part_number[0]) {
		t = sizeof (nhm_dimm->part_number);
		(void) strncpy(sbuf, nhm_dimm->part_number, t);
		sbuf[t] = 0;
		(void) nvlist_add_string(newdimm, FM_FMRI_HC_PART, sbuf);
	}
	if (nhm_dimm->revision && nhm_dimm->revision[0]) {
		t = sizeof (nhm_dimm->revision);
		(void) strncpy(sbuf, nhm_dimm->revision, t);
		sbuf[t] = 0;
		(void) nvlist_add_string(newdimm, FM_FMRI_HC_REVISION, sbuf);
	}
	t = sizeof (nhm_dimm->label);
	(void) strncpy(sbuf, nhm_dimm->label, t);
	sbuf[t] = 0;
	(void) nvlist_add_string(newdimm, FM_FAULT_FRU_LABEL, sbuf);
	return (newdimm);
}

static void
inhm_dimmlist(uint32_t node, nvlist_t *nvl)
{
	nvlist_t **dimmlist;
	nvlist_t **newchannel;
	int nchannels = CHANNELS_PER_MEMORY_CONTROLLER;
	int nd;
	uint8_t i, j;
	nhm_dimm_t **dimmpp;
	nhm_dimm_t *dimmp;

	dimmlist =  kmem_zalloc(sizeof (nvlist_t *) * MAX_DIMMS_PER_CHANNEL,
	    KM_SLEEP);
	newchannel = kmem_zalloc(sizeof (nvlist_t *) * nchannels, KM_SLEEP);
	dimmpp = &nhm_dimms[node * CHANNELS_PER_MEMORY_CONTROLLER *
	    MAX_DIMMS_PER_CHANNEL];
	(void) nvlist_add_string(nvl, "memory-policy",
	    closed_page ? "closed-page" : "open-page");
	(void) nvlist_add_string(nvl, "memory-ecc",
	    ecc_enabled ? lockstep[node] ? "x8" : "x4" : "no");
	for (i = 0; i < nchannels; i++) {
		(void) nvlist_alloc(&newchannel[i], NV_UNIQUE_NAME, KM_SLEEP);
		(void) nvlist_add_string(newchannel[i], "channel-mode",
		    CHANNEL_DISABLED(MC_STATUS_RD(node), i) ? "disabled" :
		    i != 2 && lockstep[node] ? "lockstep" :
		    i != 2 && mirror_mode[node] ?
		    REDUNDANCY_LOSS(MC_RAS_STATUS_RD(node)) ?
		    "redundancy-loss" : "mirror" :
		    i == 2 && spare_channel[node] &&
		    !REDUNDANCY_LOSS(MC_RAS_STATUS_RD(node)) ? "spare" :
		    "independent");
		nd = 0;
		for (j = 0; j < MAX_DIMMS_PER_CHANNEL; j++) {
			dimmp = *dimmpp;
			if (dimmp != NULL) {
				dimmlist[nd] = inhm_dimm(dimmp, node, i,
				    (uint32_t)j);
				nd++;
			}
			dimmpp++;
		}
		if (nd) {
			(void) nvlist_add_nvlist_array(newchannel[i],
			    "memory-dimms", dimmlist, nd);
			for (j = 0; j < nd; j++)
				nvlist_free(dimmlist[j]);
		}
	}
	(void) nvlist_add_nvlist_array(nvl, MCINTEL_NVLIST_MC, newchannel,
	    nchannels);
	for (i = 0; i < nchannels; i++)
		nvlist_free(newchannel[i]);
	kmem_free(dimmlist, sizeof (nvlist_t *) * MAX_DIMMS_PER_CHANNEL);
	kmem_free(newchannel, sizeof (nvlist_t *) * nchannels);
}

char *
inhm_mc_name()
{
	return (NHM_INTERCONNECT);
}

void
inhm_create_nvl(int chip)
{
	nvlist_t *nvl;

	(void) nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_uint8(nvl, MCINTEL_NVLIST_VERSTR,
	    MCINTEL_NVLIST_VERS);
	(void) nvlist_add_string(nvl, MCINTEL_NVLIST_MEM, inhm_mc_name());
	(void) nvlist_add_uint8(nvl, MCINTEL_NVLIST_NMEM, 1);
	(void) nvlist_add_uint8(nvl, MCINTEL_NVLIST_NRANKS, 4);
	inhm_dimmlist(chip, nvl);

	nvlist_free(inhm_mc_nvl[chip]);
	inhm_mc_nvl[chip] = nvl;
}
