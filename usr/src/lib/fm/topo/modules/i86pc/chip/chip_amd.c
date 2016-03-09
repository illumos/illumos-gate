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

/*
 * AMD memory enumeration
 */

#include <sys/types.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/fm/protocol.h>
#include <sys/mc.h>
#include <sys/mc_amd.h>
#include <fm/topo_mod.h>
#include <strings.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "chip.h"

#define	MAX_CHANNUM	1
#define	MAX_DIMMNUM	7
#define	MAX_CSNUM	7

static const topo_pgroup_info_t cs_pgroup =
	{ PGNAME(CS), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t dimm_pgroup =
	{ PGNAME(DIMM), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t mc_pgroup =
	{ PGNAME(MCT), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t rank_pgroup =
	{ PGNAME(RANK), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t chan_pgroup =
	{ PGNAME(CHAN), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_method_t dimm_methods[] = {
	{ SIMPLE_DIMM_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, simple_dimm_label},
	{ SIMPLE_DIMM_LBL_MP, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, simple_dimm_label_mp},
	{ SEQ_DIMM_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, seq_dimm_label},
	{ G4_DIMM_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, g4_dimm_label},
	{ G12F_DIMM_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, g12f_dimm_label},
	{ GET_DIMM_SERIAL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, get_dimm_serial},
	{ NULL }
};

const topo_method_t rank_methods[] = {
	{ TOPO_METH_ASRU_COMPUTE, TOPO_METH_ASRU_COMPUTE_DESC,
	    TOPO_METH_ASRU_COMPUTE_VERSION, TOPO_STABILITY_INTERNAL,
	    mem_asru_compute },
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC,
	    TOPO_METH_PRESENT_VERSION, TOPO_STABILITY_INTERNAL,
	    rank_fmri_present },
	{ TOPO_METH_REPLACED, TOPO_METH_REPLACED_DESC,
	    TOPO_METH_REPLACED_VERSION, TOPO_STABILITY_INTERNAL,
	    rank_fmri_replaced },
	{ NULL }
};

const topo_method_t ntv_page_retire_methods[] = {
	{ TOPO_METH_RETIRE, TOPO_METH_RETIRE_DESC,
	    TOPO_METH_RETIRE_VERSION, TOPO_STABILITY_INTERNAL,
	    ntv_page_retire },
	{ TOPO_METH_UNRETIRE, TOPO_METH_UNRETIRE_DESC,
	    TOPO_METH_UNRETIRE_VERSION, TOPO_STABILITY_INTERNAL,
	    ntv_page_unretire },
	{ TOPO_METH_SERVICE_STATE, TOPO_METH_SERVICE_STATE_DESC,
	    TOPO_METH_SERVICE_STATE_VERSION, TOPO_STABILITY_INTERNAL,
	    ntv_page_service_state },
	{ NULL }
};

/*
 * Serials, Labels are obtained from SMBIOS, so
 * we leave out the related methods, any other
 * methods that will be added to gen_cs_methods
 * should be added to x86pi_gen_cs_methods too
 */
static const topo_method_t x86pi_gen_cs_methods[] = {
	{ TOPO_METH_ASRU_COMPUTE, TOPO_METH_ASRU_COMPUTE_DESC,
	    TOPO_METH_ASRU_COMPUTE_VERSION, TOPO_STABILITY_INTERNAL,
	    mem_asru_compute },
	{ NULL }
};

static const topo_method_t gen_cs_methods[] = {
	{ TOPO_METH_ASRU_COMPUTE, TOPO_METH_ASRU_COMPUTE_DESC,
	    TOPO_METH_ASRU_COMPUTE_VERSION, TOPO_STABILITY_INTERNAL,
	    mem_asru_compute },
	{ SIMPLE_CS_LBL_MP, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, simple_cs_label_mp},
	{ GET_DIMM_SERIAL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, get_dimm_serial},
	{ NULL }
};

static nvlist_t *cs_fmri[MC_CHIP_NCS];

/*
 * Called when there is no memory-controller driver to provide topology
 * information.  Generate a maximal memory topology that is appropriate
 * for the chip revision.  The memory-controller node has already been
 * bound as mcnode, and the parent of that is cnode.
 *
 * We create a tree of dram-channel and chip-select nodes below the
 * memory-controller node.  There will be two dram channels and 8 chip-selects
 * below each, regardless of actual socket type, processor revision and so on.
 * This is adequate for generic diagnosis up to family 0x10 revision D.
 */
/*ARGSUSED*/
static int
amd_generic_mc_create(topo_mod_t *mod, uint16_t smbid, tnode_t *cnode,
    tnode_t *mcnode, int family, int model, nvlist_t *auth)
{
	int chan, cs;

	/*
	 * Elsewhere we have already returned for families less than 0xf.
	 * This "generic" topology is adequate for all of family 0xf and
	 * for revisions A to E of family 0x10 (for the list of models
	 * in each revision, refer to usr/src/uts/i86pc/os/cpuid_subr.c).
	 * We cover all family 0x10 models, till model 10.
	 */
	if (family > 0x10 || (family == 0x10 && model > 10))
		return (1);

	if (topo_node_range_create(mod, mcnode, CHAN_NODE_NAME, 0,
	    MAX_CHANNUM) < 0) {
		whinge(mod, NULL, "amd_generic_mc_create: range create for "
		    "channels failed\n");
		return (-1);
	}

	for (chan = 0; chan <= MAX_CHANNUM; chan++) {
		tnode_t *chnode;
		nvlist_t *fmri;
		int err;

		if (mkrsrc(mod, mcnode, CHAN_NODE_NAME, chan, auth,
		    &fmri) != 0) {
			whinge(mod, NULL, "amd_generic_mc_create: mkrsrc "
			    "failed\n");
			return (-1);
		}

		if ((chnode = topo_node_bind(mod, mcnode, CHAN_NODE_NAME,
		    chan, fmri)) == NULL) {
			nvlist_free(fmri);
			whinge(mod, NULL, "amd_generic_mc_create: node "
			    "bind failed\n");
			return (-1);
		}

		nvlist_free(fmri);

		(void) topo_pgroup_create(chnode, &chan_pgroup, &err);

		(void) topo_prop_set_string(chnode, PGNAME(CHAN), "channel",
		    TOPO_PROP_IMMUTABLE, chan == 0 ? "A" : "B", &err);

		if (FM_AWARE_SMBIOS(mod)) {
			if (topo_node_label_set(chnode, NULL, &err) == -1)
				whinge(mod, NULL, "amd_generic_mc_create: "
				    "topo_node_label_set\n");
			if (topo_node_fru_set(chnode, NULL, 0, &err) != 0)
				whinge(mod, NULL, "amd_generic_mc_create: "
				    "topo_node_fru_set failed\n");
		}

		if (topo_node_range_create(mod, chnode, CS_NODE_NAME,
		    0, MAX_CSNUM) < 0) {
			whinge(mod, NULL, "amd_generic_mc_create: "
			    "range create for cs failed\n");
			return (-1);
		}

		for (cs = 0; cs <= MAX_CSNUM; cs++) {
			tnode_t *csnode;

			if (mkrsrc(mod, chnode, CS_NODE_NAME, cs, auth,
			    &fmri) != 0) {
				whinge(mod, NULL, "amd_generic_mc_create: "
				    "mkrsrc for cs failed\n");
				return (-1);
			}

			if ((csnode = topo_node_bind(mod, chnode, CS_NODE_NAME,
			    cs, fmri)) == NULL) {
				nvlist_free(fmri);
				whinge(mod, NULL, "amd_generic_mc_create: "
				    "bind for cs failed\n");
				return (-1);
			}

			/*
			 * Dynamic ASRU for page faults within a chip-select.
			 * The topology does not represent pages (there are
			 * too many) so when a page is faulted we generate
			 * an ASRU to represent the individual page.
			 * If SMBIOS meets FMA needs, derive labels & serials
			 * for DIMMS and apply to chip-select nodes.
			 * If deriving from SMBIOS, skip IPMI
			 */
			if (FM_AWARE_SMBIOS(mod)) {
				if (topo_method_register(mod, csnode,
				    x86pi_gen_cs_methods) < 0)
					whinge(mod, NULL,
					    "amd_generic_mc_create: "
					    "method registration failed\n");
			} else {
				if (topo_method_register(mod, csnode,
				    gen_cs_methods) < 0)
					whinge(mod, NULL,
					    "amd_generic_mc_create: method"
					    "registration failed\n");
			}

			(void) topo_node_asru_set(csnode, fmri,
			    TOPO_ASRU_COMPUTE, &err);
			nvlist_free(fmri);

			/*
			 * If SMBIOS meets FMA needs, set DIMM as the FRU for
			 * the chip-select node. Use the channel & chip-select
			 * numbers to get the DIMM instance.
			 * Send via inst : dram channel number
			 * Receive via inst : dimm instance
			 */
			if (FM_AWARE_SMBIOS(mod)) {
				int inst;
				id_t dimm_smbid;
				const char *serial;
				const char *part;
				const char *rev;
				char *label;

				(void) topo_pgroup_create(csnode,
				    &cs_pgroup, &err);
				inst = chan;
				dimm_smbid = memnode_to_smbiosid(mod, smbid,
				    CS_NODE_NAME, cs, &inst);
				serial = chip_serial_smbios_get(mod,
				    dimm_smbid);
				part = chip_part_smbios_get(mod,
				    dimm_smbid);
				rev = chip_rev_smbios_get(mod, dimm_smbid);
				label = (char *)chip_label_smbios_get(mod,
				    chnode, dimm_smbid, NULL);

				(void) topo_prop_set_string(csnode, PGNAME(CS),
				    FM_FMRI_HC_SERIAL_ID, TOPO_PROP_IMMUTABLE,
				    serial, &err);
				(void) topo_prop_set_string(csnode, PGNAME(CS),
				    FM_FMRI_HC_PART, TOPO_PROP_IMMUTABLE,
				    part, &err);
				(void) topo_prop_set_string(csnode, PGNAME(CS),
				    FM_FMRI_HC_REVISION, TOPO_PROP_IMMUTABLE,
				    rev, &err);

				/*
				 * We apply DIMM labels to chip-select nodes,
				 * FRU for chip-selects should be DIMMs, and
				 * we do not derive dimm nodes for Family 0x10
				 * so FRU fmri is NULL, but FRU Labels are set,
				 * the FRU labels point to the DIMM.
				 */
				(void) topo_node_label_set(csnode, label, &err);
				topo_mod_strfree(mod, label);
			}
		}
	}

	return (0);
}

static nvlist_t *
amd_lookup_by_mcid(topo_mod_t *mod, topo_instance_t id)
{
	mc_snapshot_info_t mcs;
	void *buf = NULL;
	uint8_t ver;

	nvlist_t *nvl = NULL;
	char path[64];
	int fd, err;

	(void) snprintf(path, sizeof (path), "/dev/mc/mc%d", id);
	fd = open(path, O_RDONLY);

	if (fd == -1) {
		/*
		 * Some v20z and v40z systems may have had the 3rd-party
		 * NWSnps packagae installed which installs a /dev/mc
		 * link.  So try again via /devices.
		 */
		(void) snprintf(path, sizeof (path),
		    "/devices/pci@0,0/pci1022,1102@%x,2:mc-amd",
		    MC_AMD_DEV_OFFSET + id);
		fd = open(path, O_RDONLY);
	}

	if (fd == -1)
		return (NULL);	/* do not whinge */

	if (ioctl(fd, MC_IOC_SNAPSHOT_INFO, &mcs) == -1 ||
	    (buf = topo_mod_alloc(mod, mcs.mcs_size)) == NULL ||
	    ioctl(fd, MC_IOC_SNAPSHOT, buf) == -1) {

		whinge(mod, NULL, "mc failed to snapshot %s: %s\n",
		    path, strerror(errno));

		free(buf);
		(void) close(fd);
		return (NULL);
	}

	(void) close(fd);
	err = nvlist_unpack(buf, mcs.mcs_size, &nvl, 0);
	topo_mod_free(mod, buf, mcs.mcs_size);

	if (nvlist_lookup_uint8(nvl, MC_NVLIST_VERSTR, &ver) != 0) {
		whinge(mod, NULL, "mc nvlist is not versioned\n");
		nvlist_free(nvl);
		return (NULL);
	} else if (ver != MC_NVLIST_VERS1) {
		whinge(mod, NULL, "mc nvlist version mismatch\n");
		nvlist_free(nvl);
		return (NULL);
	}

	return (err ? NULL : nvl);
}

int
amd_rank_create(topo_mod_t *mod, tnode_t *pnode, nvlist_t *dimmnvl,
    nvlist_t *auth)
{
	uint64_t *csnumarr;
	char **csnamearr;
	uint_t ncs, ncsname;
	tnode_t *ranknode;
	nvlist_t *fmri, *pfmri = NULL;
	uint64_t dsz, rsz;
	int nerr = 0;
	int err;
	int i;

	if (nvlist_lookup_uint64_array(dimmnvl, "csnums", &csnumarr,
	    &ncs) != 0 || nvlist_lookup_string_array(dimmnvl, "csnames",
	    &csnamearr, &ncsname) != 0 || ncs != ncsname) {
		whinge(mod, &nerr, "amd_rank_create: "
		    "csnums/csnames extraction failed\n");
		return (nerr);
	}

	if (topo_node_resource(pnode, &pfmri, &err) < 0) {
		whinge(mod, &nerr, "amd_rank_create: parent fmri lookup "
		    "failed\n");
		return (nerr);
	}

	if (topo_node_range_create(mod, pnode, RANK_NODE_NAME, 0, ncs) < 0) {
		whinge(mod, &nerr, "amd_rank_create: range create failed\n");
		nvlist_free(pfmri);
		return (nerr);
	}

	if (topo_prop_get_uint64(pnode, PGNAME(DIMM), "size", &dsz,
	    &err) == 0) {
		rsz = dsz / ncs;
	} else {
		whinge(mod, &nerr, "amd_rank_create: parent dimm has no "
		    "size\n");
		return (nerr);
	}

	for (i = 0; i < ncs; i++) {
		if (mkrsrc(mod, pnode, RANK_NODE_NAME, i, auth, &fmri) < 0) {
			whinge(mod, &nerr, "amd_rank_create: mkrsrc failed\n");
			continue;
		}

		if ((ranknode = topo_node_bind(mod, pnode, RANK_NODE_NAME, i,
		    fmri)) == NULL) {
			nvlist_free(fmri);
			whinge(mod, &nerr, "amd_rank_create: node bind "
			    "failed\n");
			continue;
		}

		nvlist_free(fmri);
		if (FM_AWARE_SMBIOS(mod))
			(void) topo_node_fru_set(ranknode, NULL, 0, &err);
		else
			(void) topo_node_fru_set(ranknode, pfmri, 0, &err);

		/*
		 * If a rank is faulted the asru is the associated
		 * chip-select, but if a page within a rank is faulted
		 * the asru is just that page.  Hence the dual preconstructed
		 * and computed ASRU.
		 */
		if (topo_method_register(mod, ranknode, rank_methods) < 0)
			whinge(mod, &nerr, "amd_rank_create: "
			    "topo_method_register failed");

		if (! is_xpv() && topo_method_register(mod, ranknode,
		    ntv_page_retire_methods) < 0)
			whinge(mod, &nerr, "amd_rank_create: "
			    "topo_method_register failed");

		(void) topo_node_asru_set(ranknode, cs_fmri[csnumarr[i]],
		    TOPO_ASRU_COMPUTE, &err);

		(void) topo_pgroup_create(ranknode, &rank_pgroup, &err);

		(void) topo_prop_set_uint64(ranknode, PGNAME(RANK), "size",
		    TOPO_PROP_IMMUTABLE, rsz, &err);

		(void) topo_prop_set_string(ranknode, PGNAME(RANK), "csname",
		    TOPO_PROP_IMMUTABLE, csnamearr[i], &err);

		(void) topo_prop_set_uint64(ranknode, PGNAME(RANK), "csnum",
		    TOPO_PROP_IMMUTABLE, csnumarr[i], &err);
	}

	nvlist_free(pfmri);

	return (nerr);
}

static int
amd_dimm_create(topo_mod_t *mod, uint16_t chip_smbid, tnode_t *pnode,
    const char *name, nvlist_t *mc, nvlist_t *auth)
{
	int i, err, nerr = 0;
	int perr = 0;
	nvpair_t *nvp;
	tnode_t *dimmnode;
	nvlist_t *fmri, **dimmarr = NULL;
	uint64_t num;
	uint_t ndimm;
	id_t smbid;
	const char *serial;
	const char *part;
	const char *rev;

	if (nvlist_lookup_nvlist_array(mc, "dimmlist", &dimmarr, &ndimm) != 0) {
		whinge(mod, NULL, "amd_dimm_create: dimmlist lookup failed\n");
		return (-1);
	}

	if (ndimm == 0)
		return (0);	/* no dimms present on this node */

	if (topo_node_range_create(mod, pnode, name, 0, MAX_DIMMNUM) < 0) {
		whinge(mod, NULL, "amd_dimm_create: range create failed\n");
		return (-1);
	}

	for (i = 0; i < ndimm; i++) {
		if (nvlist_lookup_uint64(dimmarr[i], "num", &num) != 0) {
			whinge(mod, &nerr, "amd_dimm_create: dimm num property "
			    "missing\n");
			continue;
		}

		if (mkrsrc(mod, pnode, name, num, auth, &fmri) < 0) {
			whinge(mod, &nerr, "amd_dimm_create: mkrsrc failed\n");
			continue;
		}
		if (FM_AWARE_SMBIOS(mod)) {
			smbid = memnode_to_smbiosid(mod, chip_smbid,
			    DIMM_NODE_NAME, i, NULL);
			serial = chip_serial_smbios_get(mod, smbid);
			part = chip_part_smbios_get(mod, smbid);
			rev = chip_rev_smbios_get(mod, smbid);
			perr += nvlist_add_string(fmri, FM_FMRI_HC_SERIAL_ID,
			    serial);
			perr += nvlist_add_string(fmri, FM_FMRI_HC_PART,
			    part);
			perr += nvlist_add_string(fmri, FM_FMRI_HC_REVISION,
			    rev);

			if (perr != 0)
				whinge(mod, NULL, "amd_dimm_create:"
				    "nvlist_add_string failed\n");
		}

		if ((dimmnode = topo_node_bind(mod, pnode, name, num, fmri))
		    == NULL) {
			nvlist_free(fmri);
			whinge(mod, &nerr, "amd_dimm_create: node bind "
			    "failed\n");
			continue;
		}

		if (!FM_AWARE_SMBIOS(mod))
			if (topo_method_register(mod,
			    dimmnode, dimm_methods) < 0)
				whinge(mod, &nerr, "amd_dimm_create: "
				    "topo_method_register failed");

		(void) topo_pgroup_create(dimmnode, &dimm_pgroup, &err);

		if (FM_AWARE_SMBIOS(mod)) {
			char *label;

			nvlist_free(fmri);
			(void) topo_node_resource(dimmnode,
			    &fmri, &err);

			label = (char *)chip_label_smbios_get(mod,
			    pnode, smbid, NULL);
			if (topo_node_label_set(dimmnode, label,
			    &perr) == -1)
				topo_mod_dprintf(mod, "Failed"
				    "to set label\n");
			topo_mod_strfree(mod, label);

			(void) topo_prop_set_string(dimmnode, PGNAME(DIMM),
			    FM_FMRI_HC_SERIAL_ID, TOPO_PROP_IMMUTABLE,
			    serial, &err);
			(void) topo_prop_set_string(dimmnode, PGNAME(DIMM),
			    FM_FMRI_HC_PART, TOPO_PROP_IMMUTABLE,
			    part, &err);
			(void) topo_prop_set_string(dimmnode, PGNAME(DIMM),
			    FM_FMRI_HC_REVISION, TOPO_PROP_IMMUTABLE,
			    rev, &err);
		}

		(void) topo_node_asru_set(dimmnode, fmri, 0, &err);
		(void) topo_node_fru_set(dimmnode, fmri, 0, &err);
		nvlist_free(fmri);

		for (nvp = nvlist_next_nvpair(dimmarr[i], NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(dimmarr[i], nvp)) {
			if (nvpair_type(nvp) == DATA_TYPE_UINT64_ARRAY &&
			    strcmp(nvpair_name(nvp), "csnums") == 0 ||
			    nvpair_type(nvp) == DATA_TYPE_STRING_ARRAY &&
			    strcmp(nvpair_name(nvp), "csnames") == 0)
				continue;	/* used in amd_rank_create() */

			nerr += nvprop_add(mod, nvp, PGNAME(DIMM), dimmnode);
		}

		nerr += amd_rank_create(mod, dimmnode, dimmarr[i], auth);
	}

	return (nerr == 0 ? 0 : -1);
}

static int
amd_cs_create(topo_mod_t *mod, tnode_t *pnode, const char *name, nvlist_t *mc,
    nvlist_t *auth)
{
	int i, err, nerr = 0;
	nvpair_t *nvp;
	tnode_t *csnode;
	nvlist_t *fmri, **csarr = NULL;
	uint64_t csnum;
	uint_t ncs;

	if (nvlist_lookup_nvlist_array(mc, "cslist", &csarr, &ncs) != 0)
		return (-1);

	if (ncs == 0)
		return (0);	/* no chip-selects configured on this node */

	if (topo_node_range_create(mod, pnode, name, 0, MAX_CSNUM) < 0)
		return (-1);

	for (i = 0; i < ncs; i++) {
		if (nvlist_lookup_uint64(csarr[i], "num", &csnum) != 0) {
			whinge(mod, &nerr, "amd_cs_create: cs num property "
			    "missing\n");
			continue;
		}

		if (mkrsrc(mod, pnode, name, csnum, auth, &fmri) != 0) {
			whinge(mod, &nerr, "amd_cs_create: mkrsrc failed\n");
			continue;
		}

		if ((csnode = topo_node_bind(mod, pnode, name, csnum, fmri))
		    == NULL) {
			nvlist_free(fmri);
			whinge(mod, &nerr, "amd_cs_create: node bind failed\n");
			continue;
		}

		cs_fmri[csnum] = fmri;	/* nvlist will be freed in mc_create */

		(void) topo_node_asru_set(csnode, fmri, 0, &err);

		(void) topo_node_fru_set(csnode, fmri, 0, &err);

		(void) topo_pgroup_create(csnode, &cs_pgroup, &err);

		for (nvp = nvlist_next_nvpair(csarr[i], NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(csarr[i], nvp)) {
			nerr += nvprop_add(mod, nvp, PGNAME(CS), csnode);
		}
	}

	return (nerr == 0 ? 0 : -1);
}

static int
amd_dramchan_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    nvlist_t *auth)
{
	tnode_t *chnode;
	nvlist_t *fmri;
	char *socket;
	int i, nchan;
	nvlist_t *pfmri = NULL;
	int err, nerr = 0;

	/*
	 * We will enumerate the number of channels present even if only
	 * channel A is in use (i.e., running in 64-bit mode).  Only
	 * the socket 754 package has a single channel.
	 */
	if (topo_prop_get_string(pnode, PGNAME(MCT), "socket",
	    &socket, &err) == 0 && strcmp(socket, "Socket 754") == 0)
		nchan = 1;
	else
		nchan = 2;

	topo_mod_strfree(mod, socket);

	if (topo_node_range_create(mod, pnode, name, 0, nchan - 1) < 0)
		return (-1);

	(void) topo_node_fru(pnode, &pfmri, NULL, &err);

	for (i = 0; i < nchan; i++) {
		if (mkrsrc(mod, pnode, name, i, auth, &fmri) != 0) {
			whinge(mod, &nerr, "amd_dramchan_create: mkrsrc "
			    "failed\n");
			continue;
		}

		if ((chnode = topo_node_bind(mod, pnode, name, i, fmri))
		    == NULL) {
			nvlist_free(fmri);
			whinge(mod, &nerr, "amd_dramchan_create: node bind "
			    "failed\n");
			continue;
		}

		(void) topo_node_asru_set(chnode, fmri, 0, &err);
		if (pfmri)
			(void) topo_node_fru_set(chnode, pfmri, 0, &err);

		nvlist_free(fmri);

		(void) topo_pgroup_create(chnode, &chan_pgroup, &err);

		(void) topo_prop_set_string(chnode, PGNAME(CHAN), "channel",
		    TOPO_PROP_IMMUTABLE, i == 0 ? "A" : "B", &err);
	}
	nvlist_free(pfmri);

	return (nerr == 0 ? 0 : -1);
}

static int
amd_htconfig(topo_mod_t *mod, tnode_t *cnode, nvlist_t *htnvl)
{
	nvpair_t *nvp;
	int nerr = 0;

	if (strcmp(topo_node_name(cnode), CHIP_NODE_NAME) != 0) {
		whinge(mod, &nerr, "amd_htconfig: must pass a chip node!");
		return (-1);
	}

	for (nvp = nvlist_next_nvpair(htnvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(htnvl, nvp)) {
		if (nvprop_add(mod, nvp, PGNAME(CHIP), cnode) != 0)
			nerr++;
	}

	return (nerr == 0 ? 0 : -1);
}

void
amd_mc_create(topo_mod_t *mod,  uint16_t smbid, tnode_t *pnode,
    const char *name, nvlist_t *auth, int32_t procnodeid,
    int32_t procnodes_per_pkg, int family,
    int model, int *nerrp)
{
	tnode_t *mcnode;
	nvlist_t *rfmri, *fmri;
	nvpair_t *nvp;
	nvlist_t *mc = NULL;
	int i, err;
	int mcnum = procnodeid % procnodes_per_pkg;
	char *serial = NULL;
	char *part = NULL;
	char *rev = NULL;

	/*
	 * Return with no error for anything before AMD family 0xf - we
	 * won't generate even a generic memory topology for earlier
	 * families.
	 */
	if (family < 0xf)
		return;

	if (topo_node_lookup(pnode, name, mcnum) != NULL)
		return;

	if (FM_AWARE_SMBIOS(mod)) {
		(void) topo_node_resource(pnode, &rfmri, &err);
		(void) nvlist_lookup_string(rfmri, "serial", &serial);
		(void) nvlist_lookup_string(rfmri, "part", &part);
		(void) nvlist_lookup_string(rfmri, "revision", &rev);
	}

	if (mkrsrc(mod, pnode, name, mcnum, auth, &fmri) != 0) {
		if (FM_AWARE_SMBIOS(mod))
			nvlist_free(rfmri);
		whinge(mod, nerrp, "mc_create: mkrsrc failed\n");
		return;
	}

	if (FM_AWARE_SMBIOS(mod)) {
		(void) nvlist_add_string(fmri, "serial", serial);
		(void) nvlist_add_string(fmri, "part", part);
		(void) nvlist_add_string(fmri, "revision", rev);
		nvlist_free(rfmri);
	}

	if ((mcnode = topo_node_bind(mod, pnode, name, mcnum,
	    fmri)) == NULL) {
		nvlist_free(fmri);
		whinge(mod, nerrp, "mc_create: mc bind failed\n");
		return;
	}
	if (topo_node_fru_set(mcnode, NULL, 0, &err) < 0)
		whinge(mod, nerrp, "mc_create: topo_node_fru_set failed\n");

	if (FM_AWARE_SMBIOS(mod)) {
		if (topo_node_label_set(mcnode, NULL, &err) == -1)
			topo_mod_dprintf(mod, "Failed to set label\n");
	}

	nvlist_free(fmri);

	if (topo_pgroup_create(mcnode, &mc_pgroup, &err) < 0)
		whinge(mod, nerrp, "mc_create: topo_pgroup_create failed\n");

	if (topo_prop_set_int32(mcnode, PGNAME(MCT), MCT_PROCNODE_ID,
	    TOPO_PROP_IMMUTABLE, procnodeid, nerrp) != 0)
		whinge(mod, nerrp, "mc_create: topo_prop_set_int32 failed to"
		    "add node id\n");

	if ((mc = amd_lookup_by_mcid(mod, topo_node_instance(pnode))) == NULL) {
		/*
		 * If a memory-controller driver exists for this chip model
		 * it has not attached or has otherwise malfunctioned;
		 * alternatively no memory-controller driver exists for this
		 * (presumably newly-released) cpu model.  We fallback to
		 * creating a generic maximal topology.
		 */
		if (amd_generic_mc_create(mod, smbid, pnode, mcnode,
		    family, model, auth) != 0)
			whinge(mod, nerrp,
			    "mc_create: amd_generic_mc_create failed\n");
		return;
	}

	/*
	 * Add memory controller properties
	 */
	for (nvp = nvlist_next_nvpair(mc, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(mc, nvp)) {
		char *name = nvpair_name(nvp);
		data_type_t type = nvpair_type(nvp);

		if (type == DATA_TYPE_NVLIST_ARRAY &&
		    (strcmp(name, "cslist") == 0 ||
		    strcmp(name, "dimmlist") == 0)) {
			continue;
		} else if (type == DATA_TYPE_UINT8 &&
		    strcmp(name, MC_NVLIST_VERSTR) == 0) {
			continue;
		} else if (type == DATA_TYPE_NVLIST &&
		    strcmp(name, "htconfig") == 0) {
			nvlist_t *htnvl;

			(void) nvpair_value_nvlist(nvp, &htnvl);
			if (amd_htconfig(mod, pnode, htnvl) != 0)
				whinge(mod, nerrp,
				    "mc_create: amd_htconfig failed\n");
		} else {
			if (nvprop_add(mod, nvp, PGNAME(MCT), mcnode) != 0)
				whinge(mod, nerrp,
				    "mc_create: nvprop_add failed\n");
		}
	}

	if (amd_dramchan_create(mod, mcnode, CHAN_NODE_NAME, auth) != 0 ||
	    amd_cs_create(mod, mcnode, CS_NODE_NAME, mc, auth) != 0 ||
	    amd_dimm_create(mod, smbid, mcnode, DIMM_NODE_NAME, mc, auth) != 0)
		whinge(mod, nerrp, "mc_create: create children failed\n");

	/*
	 * Free the fmris for the chip-selects allocated in amd_cs_create
	 */
	for (i = 0; i < MC_CHIP_NCS; i++) {
		if (cs_fmri[i] != NULL) {
			nvlist_free(cs_fmri[i]);
			cs_fmri[i] = NULL;
		}
	}

	nvlist_free(mc);
}
