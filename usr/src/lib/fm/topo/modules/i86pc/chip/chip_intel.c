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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <alloca.h>
#include <kstat.h>
#include <fcntl.h>
#include <errno.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/processor.h>
#include <sys/param.h>
#include <sys/fm/protocol.h>
#include <sys/systeminfo.h>
#include <sys/mc.h>
#include <sys/mc_amd.h>
#include <sys/mc_intel.h>
#include <fm/topo_mod.h>

#include "chip.h"

#ifndef MAX
#define	MAX(a, b)	((a) > (b) ? (a) : (b))
#endif

static const topo_pgroup_info_t dimm_channel_pgroup =
	{ PGNAME(CHAN), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t dimm_pgroup =
	{ PGNAME(DIMM), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t rank_pgroup =
	{ PGNAME(RANK), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t mc_pgroup =
	{ PGNAME(MCT), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_method_t dimm_methods[] = {
	{ SIMPLE_DIMM_LBL, "Property method", 0, TOPO_STABILITY_INTERNAL,
	    simple_dimm_label},
	{ SIMPLE_DIMM_LBL_MP, "Property method", 0, TOPO_STABILITY_INTERNAL,
	    simple_dimm_label_mp},
	{ SEQ_DIMM_LBL, "Property method", 0, TOPO_STABILITY_INTERNAL,
	    seq_dimm_label},
	{ NULL }
};

extern const topo_method_t rank_methods[];
extern const topo_method_t ntv_page_retire_methods[];

static int mc_fd;

int
mc_offchip_open()
{
	mc_fd = open("/dev/mc/mc", O_RDONLY);
	return (mc_fd != -1);
}

static int
mc_onchip(topo_instance_t id)
{
	char path[64];

	(void) snprintf(path, sizeof (path), "/dev/mc/mc%d", id);
	mc_fd = open(path, O_RDONLY);
	return (mc_fd != -1);
}

static void
mc_add_ranks(topo_mod_t *mod, tnode_t *dnode, nvlist_t *auth, int dimm,
    nvlist_t **ranks_nvp, int start_rank, int nranks, char *serial, char *part,
    char *rev, int maxranks)
{
	int i;
	int rank;
	tnode_t *rnode;
	nvpair_t *nvp;
	nvlist_t *fmri;
	int err = 0;

	/*
	 * If start_rank is defined, it is assigned to the first rank of this
	 * dimm.
	 */
	rank = start_rank >= 0 ? start_rank : dimm * maxranks;
	if (topo_node_range_create(mod, dnode, RANK, rank,
	    rank + nranks - 1) < 0) {
		whinge(mod, NULL, "mc_add_ranks: node range create failed"
		    " for rank\n");
		return;
	}
	for (i = 0; i < nranks; i++) {
		fmri = topo_mod_hcfmri(mod, dnode, FM_HC_SCHEME_VERSION,
		    RANK, rank, NULL, auth, part, rev, serial);
		if (fmri == NULL) {
			whinge(mod, NULL,
			    "mc_add_ranks: topo_mod_hcfmri failed\n");
			return;
		}
		if ((rnode = topo_node_bind(mod, dnode, RANK, rank,
		    fmri)) == NULL) {
			nvlist_free(fmri);
			whinge(mod, NULL, "mc_add_ranks: node bind failed"
			    " for ranks\n");
			return;
		}
		(void) topo_node_fru_set(rnode, NULL, 0, &err);

		if (topo_method_register(mod, rnode, rank_methods) < 0)
			whinge(mod, &err, "rank_create: "
			    "topo_method_register failed");

		if (! is_xpv() && topo_method_register(mod, rnode,
		    ntv_page_retire_methods) < 0)
			whinge(mod, &err, "mc_add_ranks: "
			    "topo_method_register failed");

		(void) topo_node_asru_set(rnode, fmri, TOPO_ASRU_COMPUTE, &err);

		if (FM_AWARE_SMBIOS(mod))
			(void) topo_node_label_set(rnode, NULL, &err);

		nvlist_free(fmri);

		(void) topo_pgroup_create(rnode, &rank_pgroup, &err);
		for (nvp = nvlist_next_nvpair(ranks_nvp[i], NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(ranks_nvp[i], nvp)) {
			(void) nvprop_add(mod, nvp, PGNAME(RANK), rnode);
		}
		rank++;
	}
}

static void
mc_add_dimms(topo_mod_t *mod, uint16_t chip_smbid, tnode_t *pnode,
    nvlist_t *auth, nvlist_t **nvl, uint_t ndimms, int maxdimms, int maxranks)
{
	int i;
	nvlist_t *fmri;
	tnode_t *dnode;
	nvpair_t *nvp;
	int err;
	nvlist_t **ranks_nvp;
	int32_t start_rank = -1;
	uint_t nranks = 0;
	uint32_t dimm_number;
	char *serial = NULL;
	char *part = NULL;
	char *rev = NULL;
	char *label = NULL;
	char *name;
	id_t smbid;

	if (topo_node_range_create(mod, pnode, DIMM, 0,
	    maxdimms ? maxdimms-1 : ndimms-1) < 0) {
		whinge(mod, NULL,
		    "mc_add_dimms: node range create failed\n");
		return;
	}
	for (i = 0; i < ndimms; i++) {
		dimm_number = i;
		for (nvp = nvlist_next_nvpair(nvl[i], NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(nvl[i], nvp)) {
			name = nvpair_name(nvp);
			if (strcmp(name, MCINTEL_NVLIST_RANKS) == 0) {
				(void) nvpair_value_nvlist_array(nvp,
				    &ranks_nvp, &nranks);
			} else if (strcmp(name, MCINTEL_NVLIST_1ST_RANK) == 0) {
				(void) nvpair_value_int32(nvp, &start_rank);
			} else if (strcmp(name, FM_FMRI_HC_SERIAL_ID) == 0) {
				(void) nvpair_value_string(nvp, &serial);
			} else if (strcmp(name, FM_FMRI_HC_PART) == 0) {
				(void) nvpair_value_string(nvp, &part);
			} else if (strcmp(name, FM_FMRI_HC_REVISION) == 0) {
				(void) nvpair_value_string(nvp, &rev);
			} else if (strcmp(name, FM_FAULT_FRU_LABEL) == 0) {
				(void) nvpair_value_string(nvp, &label);
			} else if (strcmp(name, MCINTEL_NVLIST_DIMM_NUM) == 0) {
				(void) nvpair_value_uint32(nvp, &dimm_number);
			}
		}
		fmri = NULL;

		if (FM_AWARE_SMBIOS(mod)) {
			int channum;

			channum = topo_node_instance(pnode);
			smbid = memnode_to_smbiosid(mod, chip_smbid,
			    DIMM_NODE_NAME, i, &channum);
			if (serial == NULL)
				serial = (char *)chip_serial_smbios_get(mod,
				    smbid);
			if (part == NULL)
				part = (char *)chip_part_smbios_get(mod,
				    smbid);
			if (rev == NULL)
				rev = (char *)chip_rev_smbios_get(mod,
				    smbid);
		}

		fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
		    DIMM, dimm_number, NULL, auth, part, rev, serial);
		if (fmri == NULL) {
			whinge(mod, NULL,
			    "mc_add_dimms: topo_mod_hcfmri failed\n");
			return;
		}
		if ((dnode = topo_node_bind(mod, pnode, DIMM, dimm_number,
		    fmri)) == NULL) {
			nvlist_free(fmri);
			whinge(mod, NULL, "mc_add_dimms: node bind failed"
			    " for dimm\n");
			return;
		}

		if (!FM_AWARE_SMBIOS(mod))
			if (topo_method_register(mod, dnode, dimm_methods) < 0)
				whinge(mod, NULL, "mc_add_dimms: "
				    "topo_method_register failed");

		(void) topo_pgroup_create(dnode, &dimm_pgroup, &err);

		for (nvp = nvlist_next_nvpair(nvl[i], NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(nvl[i], nvp)) {
			name = nvpair_name(nvp);
			if (strcmp(name, MCINTEL_NVLIST_RANKS) != 0 &&
			    strcmp(name, FM_FAULT_FRU_LABEL) != 0 &&
			    strcmp(name, MCINTEL_NVLIST_1ST_RANK) != 0) {
				(void) nvprop_add(mod, nvp, PGNAME(DIMM),
				    dnode);
			}
		}

		if (FM_AWARE_SMBIOS(mod)) {
			nvlist_free(fmri);
			(void) topo_node_resource(dnode, &fmri, &err);
			/*
			 * We will use a full absolute parent/child label
			 */
			label = (char *)chip_label_smbios_get(mod,
			    pnode, smbid, label);
		}

		(void) topo_node_label_set(dnode, label, &err);

		if (FM_AWARE_SMBIOS(mod))
			topo_mod_strfree(mod, label);

		(void) topo_node_fru_set(dnode, fmri, 0, &err);
		(void) topo_node_asru_set(dnode, fmri, 0, &err);
		nvlist_free(fmri);

		if (nranks) {
			mc_add_ranks(mod, dnode, auth, dimm_number, ranks_nvp,
			    start_rank, nranks, serial, part, rev, maxranks);
		}
	}
}

static int
mc_add_channel(topo_mod_t *mod, uint16_t chip_smbid, tnode_t *pnode,
    int channel, nvlist_t *auth, nvlist_t *nvl, int maxdimms, int maxranks)
{
	tnode_t *mc_channel;
	nvlist_t *fmri;
	nvlist_t **dimm_nvl;
	nvpair_t *nvp;
	char *name;
	uint_t ndimms;
	int err;

	if (mkrsrc(mod, pnode, DRAMCHANNEL, channel, auth, &fmri) != 0) {
		whinge(mod, NULL, "mc_add_channel: mkrsrc failed\n");
		return (-1);
	}
	if ((mc_channel = topo_node_bind(mod, pnode, DRAMCHANNEL, channel,
	    fmri)) == NULL) {
		whinge(mod, NULL, "mc_add_channel: node bind failed for %s\n",
		    DRAMCHANNEL);
		nvlist_free(fmri);
		return (-1);
	}
	(void) topo_node_fru_set(mc_channel, NULL, 0, &err);
	nvlist_free(fmri);
	(void) topo_pgroup_create(mc_channel, &dimm_channel_pgroup, &err);

	if (FM_AWARE_SMBIOS(mod))
		(void) topo_node_label_set(mc_channel, NULL, &err);

	if (nvlist_lookup_nvlist_array(nvl, MCINTEL_NVLIST_DIMMS, &dimm_nvl,
	    &ndimms) == 0) {
		mc_add_dimms(mod, chip_smbid, mc_channel, auth, dimm_nvl,
		    ndimms, maxdimms, maxranks);
	}
	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		name = nvpair_name(nvp);
		if (strcmp(name, MCINTEL_NVLIST_DIMMS) != 0) {
			(void) nvprop_add(mod, nvp, PGNAME(CHAN),
			    mc_channel);
		}
	}

	return (0);
}

static int
mc_nb_create(topo_mod_t *mod, uint16_t chip_smbid, tnode_t *pnode,
    const char *name, nvlist_t *auth, nvlist_t *nvl)
{
	int err;
	int i, j;
	int channel;
	uint8_t nmc;
	uint8_t maxranks;
	uint8_t maxdimms;
	tnode_t *mcnode;
	nvlist_t *fmri;
	nvlist_t **channel_nvl;
	nvpair_t *nvp;
	char *pname;
	uint_t nchannels;

	if (nvlist_lookup_nvlist_array(nvl, MCINTEL_NVLIST_MC, &channel_nvl,
	    &nchannels) != 0) {
		whinge(mod, NULL,
		    "mc_nb_create: failed to find channel information\n");
		return (-1);
	}
	if (nvlist_lookup_uint8(nvl, MCINTEL_NVLIST_NMEM, &nmc) == 0) {
		/*
		 * Assume channels are evenly divided among the controllers.
		 * Convert nchannels to channels per controller
		 */
		nchannels = nchannels / nmc;
	} else {
		/*
		 * if number of memory controllers is not specified then there
		 * are two channels per controller and the nchannels is total
		 * we will set up nmc as number of controllers and convert
		 * nchannels to channels per controller
		 */
		nmc = nchannels / 2;
		nchannels = nchannels / nmc;
	}
	if (nvlist_lookup_uint8(nvl, MCINTEL_NVLIST_NRANKS, &maxranks) != 0)
		maxranks = 2;
	if (nvlist_lookup_uint8(nvl, MCINTEL_NVLIST_NDIMMS, &maxdimms) != 0)
		maxdimms = 0;
	if (topo_node_range_create(mod, pnode, name, 0, nmc-1) < 0) {
		whinge(mod, NULL,
		    "mc_nb_create: node range create failed\n");
		return (-1);
	}
	channel = 0;
	for (i = 0; i < nmc; i++) {
		if (mkrsrc(mod, pnode, name, i, auth, &fmri) != 0) {
			whinge(mod, NULL, "mc_nb_create: mkrsrc failed\n");
			return (-1);
		}
		if ((mcnode = topo_node_bind(mod, pnode, name, i,
		    fmri)) == NULL) {
			whinge(mod, NULL, "mc_nb_create: node bind failed"
			    " for memory-controller\n");
			nvlist_free(fmri);
			return (-1);
		}

		(void) topo_node_fru_set(mcnode, NULL, 0, &err);
		nvlist_free(fmri);
		(void) topo_pgroup_create(mcnode, &mc_pgroup, &err);

		if (FM_AWARE_SMBIOS(mod))
			(void) topo_node_label_set(mcnode, NULL, &err);

		if (topo_node_range_create(mod, mcnode, DRAMCHANNEL, channel,
		    channel + nchannels - 1) < 0) {
			whinge(mod, NULL,
			    "mc_nb_create: channel node range create failed\n");
			return (-1);
		}
		for (j = 0; j < nchannels; j++) {
			if (mc_add_channel(mod, chip_smbid, mcnode, channel,
			    auth, channel_nvl[channel], maxdimms,
			    maxranks) < 0) {
				return (-1);
			}
			channel++;
		}
		for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(nvl, nvp)) {
			pname = nvpair_name(nvp);
			if (strcmp(pname, MCINTEL_NVLIST_MC) != 0 &&
			    strcmp(pname, MCINTEL_NVLIST_NMEM) != 0 &&
			    strcmp(pname, MCINTEL_NVLIST_NRANKS) != 0 &&
			    strcmp(pname, MCINTEL_NVLIST_NDIMMS) != 0 &&
			    strcmp(pname, MCINTEL_NVLIST_VERSTR) != 0 &&
			    strcmp(pname, MCINTEL_NVLIST_MEM) != 0) {
				(void) nvprop_add(mod, nvp, PGNAME(MCT),
				    mcnode);
			}
		}
	}

	return (0);
}

int
mc_node_create(topo_mod_t *mod, uint16_t chip_smbid, tnode_t *pnode,
    const char *name, nvlist_t *auth)
{
	mc_snapshot_info_t mcs;
	void *buf = NULL;
	nvlist_t *nvl;
	uint8_t ver;
	int rc;

	if (ioctl(mc_fd, MC_IOC_SNAPSHOT_INFO, &mcs) == -1 ||
	    (buf = topo_mod_alloc(mod, mcs.mcs_size)) == NULL ||
	    ioctl(mc_fd, MC_IOC_SNAPSHOT, buf) == -1) {

		whinge(mod, NULL, "mc failed to snapshot %s\n",
		    strerror(errno));

		free(buf);
		(void) close(mc_fd);
		return (0);
	}
	(void) close(mc_fd);
	(void) nvlist_unpack(buf, mcs.mcs_size, &nvl, 0);
	topo_mod_free(mod, buf, mcs.mcs_size);

	if (nvlist_lookup_uint8(nvl, MCINTEL_NVLIST_VERSTR, &ver) != 0) {
		whinge(mod, NULL, "mc nvlist is not versioned\n");
		nvlist_free(nvl);
		return (0);
	} else if (ver != MCINTEL_NVLIST_VERS0) {
		whinge(mod, NULL, "mc nvlist version mismatch\n");
		nvlist_free(nvl);
		return (0);
	}

	rc = mc_nb_create(mod, chip_smbid, pnode, name, auth, nvl);

	nvlist_free(nvl);
	return (rc);
}

void
onchip_mc_create(topo_mod_t *mod, uint16_t chip_smbid, tnode_t *pnode,
    const char *name, nvlist_t *auth)
{
	if (mc_onchip(topo_node_instance(pnode)))
		(void) mc_node_create(mod, chip_smbid, pnode, name, auth);
}

int
mc_offchip_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    nvlist_t *auth)
{
	return (mc_node_create(mod, IGNORE_ID, pnode, name, auth));
}
