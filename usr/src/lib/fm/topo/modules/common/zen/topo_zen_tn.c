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

/*
 * This file is focused upon building up the tree of information that we need to
 * build the module's various topology nodes as well as any methods that need to
 * operate on them.
 */

#include <sys/fm/protocol.h>
#include <fm/topo_hc.h>
#include <sys/devfm.h>
#include <assert.h>

#include "topo_zen_impl.h"

static const topo_pgroup_info_t topo_zen_chip_pgroup = {
	TOPO_PGROUP_CHIP,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t topo_zen_ccd_pgroup = {
	TOPO_PGROUP_CCD,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t topo_zen_ccx_pgroup = {
	TOPO_PGROUP_CCX,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t topo_zen_core_pgroup = {
	TOPO_PGROUP_CORE,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t topo_zen_strand_pgroup = {
	TOPO_PGROUP_STRAND,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t topo_zen_cache_pgroup = {
	TOPO_PGROUP_CACHE,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

/*
 * Common interface to create a topo node in our socket and bind it to its
 * parent. The following properties are commonly shared between all nodes in the
 * chip:
 *
 * o The serial and revision are part of the FMRI. We don't have a good way to
 *   get the orderable OPN for this. The brand string doesn't feel appropriate
 *   for this use case.
 * o The FRU is always set to the top-level chip.
 * o We do not set the ASRU given that it will vary from device to device.
 */
static tnode_t *
topo_zen_create_tn(topo_mod_t *mod, zen_topo_enum_sock_t *sock, tnode_t *pnode,
    topo_instance_t inst, const char *name)
{
	int ret, err;
	tnode_t *tn = NULL;
	nvlist_t *fmri = NULL, *auth = NULL;

	auth = topo_mod_auth(mod, pnode);
	if (auth == NULL) {
		topo_mod_dprintf(mod, "failed to get auth for %s[%" PRIu64 "]: "
		    "%s", name, inst, topo_mod_errmsg(mod));
		return (NULL);
	}

	fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION, name, inst,
	    NULL, auth, NULL, sock->ztes_cpu_rev, sock->ztes_cpu_serial);
	if (fmri == NULL) {
		topo_mod_dprintf(mod, "failed to create FMRI for %s[%" PRIu64
		    "]: %s", name, inst, topo_mod_errmsg(mod));
		nvlist_free(auth);
		return (NULL);
	}

	tn = topo_node_bind(mod, pnode, name, inst, fmri);
	nvlist_free(auth);
	if (tn == NULL) {
		topo_mod_dprintf(mod, "failed to bind node %s[%" PRIu64 "]: %s",
		    name, inst, topo_mod_errmsg(mod));
		nvlist_free(fmri);
		return (NULL);
	}

	if (sock->ztes_tn == NULL) {
		ret = topo_node_fru_set(tn, fmri, 0, &err);
	} else {
		ret = topo_node_fru_set(tn, NULL, 0, &err);
	}
	nvlist_free(fmri);

	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to set FRU for %s[%" PRIu64 "]: "
		    "%s", name, inst, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		topo_node_unbind(tn);
		return (NULL);
	}

	return (tn);
}

static tnode_t *
topo_zen_build_cache(topo_mod_t *mod, zen_topo_enum_sock_t *sock,
    tnode_t *pnode, topo_instance_t inst, nvlist_t *nvl)
{
	int err;
	uint32_t level, type, ways, line;
	uint64_t sets, size, id;
	const char *types[2];
	const char *flags[2];
	uint_t ntypes = 0, nflags = 0;

	tnode_t *tn = topo_zen_create_tn(mod, sock, pnode, inst, CACHE);
	if (tn == NULL) {
		return (NULL);
	}

	if (nvlist_lookup_pairs(nvl, 0,
	    FM_CACHE_INFO_LEVEL, DATA_TYPE_UINT32, &level,
	    FM_CACHE_INFO_TYPE, DATA_TYPE_UINT32, &type,
	    FM_CACHE_INFO_NWAYS, DATA_TYPE_UINT32, &ways,
	    FM_CACHE_INFO_LINE_SIZE, DATA_TYPE_UINT32, &line,
	    FM_CACHE_INFO_NSETS, DATA_TYPE_UINT64, &sets,
	    FM_CACHE_INFO_TOTAL_SIZE, DATA_TYPE_UINT64, &size,
	    FM_CACHE_INFO_ID, DATA_TYPE_UINT64, &id, NULL) != 0) {
		topo_mod_dprintf(mod, "internal cache nvlist missing expected "
		    "keys");
		goto err;
	}

	if ((type & FM_CACHE_INFO_T_DATA) != 0) {
		types[ntypes] = TOPO_PGROUP_CACHE_TYPES_DATA;
		ntypes++;
	}

	if ((type & FM_CACHE_INFO_T_INSTR) != 0) {
		types[ntypes] = TOPO_PGROUP_CACHE_TYPES_INSTR;
		ntypes++;
	}

	if ((type & FM_CACHE_INFO_T_UNIFIED) != 0) {
		flags[nflags] = TOPO_PGROUP_CACHE_FLAGS_UNIFIED;
		nflags++;
	}

	if (nvlist_lookup_boolean(nvl, FM_CACHE_INFO_FULLY_ASSOC) == 0) {
		flags[nflags] = TOPO_PGROUP_CACHE_FLAGS_FA;
		nflags++;
	}

	assert(ntypes > 0);
	if (topo_create_props(mod, tn, TOPO_PROP_IMMUTABLE,
	    &topo_zen_cache_pgroup,
	    TOPO_PGROUP_CACHE_LEVEL, TOPO_TYPE_UINT32, level,
	    TOPO_PGROUP_CACHE_WAYS, TOPO_TYPE_UINT32, ways,
	    TOPO_PGROUP_CACHE_SETS, TOPO_TYPE_UINT64, sets,
	    TOPO_PGROUP_CACHE_LINE_SIZE, TOPO_TYPE_UINT32, line,
	    TOPO_PGROUP_CACHE_SYSTEM_ID, TOPO_TYPE_UINT64, id,
	    TOPO_PGROUP_CACHE_SIZE, TOPO_TYPE_UINT64, size,
	    TOPO_PGROUP_CACHE_TYPES, TOPO_TYPE_STRING_ARRAY, types, ntypes,
	    NULL) != 0) {
		goto err;
	}

	if (nflags > 0 && topo_prop_set_string_array(tn, TOPO_PGROUP_CACHE,
	    TOPO_PGROUP_CACHE_FLAGS, TOPO_PROP_IMMUTABLE, flags, nflags,
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to create %s property: %s",
		    TOPO_PGROUP_CACHE_FLAGS, topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto err;
	}

	return (tn);

err:
	topo_node_unbind(tn);
	return (NULL);

}

/*
 * Build up an FMRI for the CPU scheme for this thread and set that as our ASRU
 * for the thread.
 */
static int
topo_zen_build_strand_asru(topo_mod_t *mod, zen_topo_enum_sock_t *sock,
    tnode_t *tn, uint32_t cpuid)
{
	int err, ret;
	nvlist_t *fmri;

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0) {
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	if (nvlist_add_uint8(fmri, FM_VERSION, FM_CPU_SCHEME_VERSION) != 0 ||
	    nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_CPU) != 0 ||
	    nvlist_add_uint32(fmri, FM_FMRI_CPU_ID, cpuid) != 0 ||
	    nvlist_add_string(fmri, FM_FMRI_CPU_SERIAL_ID,
	    sock->ztes_cpu_serial) != 0) {
		topo_mod_dprintf(mod, "failed to construct CPU FMRI\n");
		nvlist_free(fmri);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	ret = topo_node_asru_set(tn, fmri, 0, &err);
	nvlist_free(fmri);
	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to set ASRU for thread: %s\n",
		    topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}

	return (0);
}

static int
topo_zen_build_strand(topo_mod_t *mod, zen_topo_enum_sock_t *sock,
    const amdzen_topo_core_t *core, zen_topo_enum_core_t *zt_core, uint32_t tid)
{
	uint32_t cpuid;
	tnode_t *tn;

	tn = topo_zen_create_tn(mod, sock, zt_core->ztcore_tn, tid, STRAND);
	if (tn == NULL) {
		return (-1);
	}

	/*
	 * Strands (hardware threads) have an ASRU that relates to their logical
	 * CPU. Set that up now. We currently only opt to set it on the strand
	 * because if we want to offline the core, it seems like that needs
	 * better semantics and perhaps wants a better way to indicate that in
	 * the scheme.
	 */
	if (nvlist_lookup_pairs(zt_core->ztcore_nvls[tid], 0,
	    FM_PHYSCPU_INFO_CPU_ID, DATA_TYPE_INT32,
	    &cpuid, NULL) != 0) {
		topo_mod_dprintf(mod, "internal thread %u nvlist "
		    "missing expected keys", tid);
		topo_node_unbind(tn);
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	if (topo_zen_build_strand_asru(mod, sock, tn, cpuid) != 0) {
		topo_node_unbind(tn);
		return (-1);
	}

	if (topo_create_props(mod, tn, TOPO_PROP_IMMUTABLE,
	    &topo_zen_strand_pgroup,
	    TOPO_PGROUP_STRAND_CPUID, TOPO_TYPE_UINT32, cpuid,
	    TOPO_PGROUP_STRAND_APICID, TOPO_TYPE_UINT32,
	    core->atcore_apicids[tid], NULL) != 0) {
		topo_mod_dprintf(mod, "failed to set strand properties\n");
		topo_node_unbind(tn);
		return (-1);
	}

	zt_core->ztcore_thr_tn[tid] = tn;
	return (0);
}

static int
topo_zen_build_core(topo_mod_t *mod, zen_topo_enum_sock_t *sock,
    tnode_t *ccx_tn, const amdzen_topo_core_t *core,
    zen_topo_enum_core_t *zt_core)
{
	zt_core->ztcore_tn = topo_zen_create_tn(mod, sock, ccx_tn,
	    core->atcore_phys_no, CORE);
	if (zt_core->ztcore_tn == NULL) {
		return (-1);
	}

	if (topo_create_props(mod, zt_core->ztcore_tn, TOPO_PROP_IMMUTABLE,
	    &topo_zen_core_pgroup,
	    TOPO_PGROUP_CORE_LOGID, TOPO_TYPE_UINT32, core->atcore_log_no,
	    TOPO_PGROUP_CORE_PHYSID, TOPO_TYPE_UINT32, core->atcore_phys_no,
	    NULL) != 0) {
		return (-1);
	}

	if (topo_node_range_create(mod, zt_core->ztcore_tn, CACHE, 0, 2) != 0) {
		topo_mod_dprintf(mod, "failed to create cache range: %s\n",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	if (zt_core->ztcore_l2 != NULL) {
		zt_core->ztcore_l2_tn = topo_zen_build_cache(mod, sock,
		    zt_core->ztcore_tn, 2, zt_core->ztcore_l2);
		if (zt_core->ztcore_l2_tn == NULL) {
			return (-1);
		}
	}

	if (zt_core->ztcore_l1i != NULL) {
		zt_core->ztcore_l1i_tn = topo_zen_build_cache(mod, sock,
		    zt_core->ztcore_tn, 1, zt_core->ztcore_l1i);
		if (zt_core->ztcore_l1i_tn == NULL) {
			return (-1);
		}
	}

	if (zt_core->ztcore_l1d != NULL) {
		zt_core->ztcore_l1d_tn = topo_zen_build_cache(mod, sock,
		    zt_core->ztcore_tn, 0, zt_core->ztcore_l1d);
		if (zt_core->ztcore_l1d_tn == NULL) {
			return (-1);
		}
	}

	if (topo_node_range_create(mod, zt_core->ztcore_tn, STRAND, 0,
	    core->atcore_nthreads - 1) != 0) {
		topo_mod_dprintf(mod, "failed to create strand range: %s\n",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	for (uint32_t tid = 0; tid < core->atcore_nthreads; tid++) {
		int ret;

		if (core->atcore_thr_en[tid] == 0) {
			continue;
		}

		if ((ret = topo_zen_build_strand(mod, sock, core, zt_core,
		    tid)) != 0) {
			return (ret);
		}
	}

	return (0);
}

static int
topo_zen_build_ccx(topo_mod_t *mod, zen_topo_enum_sock_t *sock, tnode_t *ccd_tn,
    const amdzen_topo_ccx_t *ccx, zen_topo_enum_ccx_t *zt_ccx)
{
	zt_ccx->ztccx_tn = topo_zen_create_tn(mod, sock, ccd_tn,
	    ccx->atccx_phys_no, CCX);
	if (zt_ccx->ztccx_tn == NULL) {
		return (-1);
	}

	if (topo_create_props(mod, zt_ccx->ztccx_tn, TOPO_PROP_IMMUTABLE,
	    &topo_zen_ccx_pgroup,
	    TOPO_PGROUP_CCX_LOGID, TOPO_TYPE_UINT32, ccx->atccx_log_no,
	    TOPO_PGROUP_CCX_PHYSID, TOPO_TYPE_UINT32, ccx->atccx_phys_no,
	    NULL) != 0) {
		topo_node_unbind(zt_ccx->ztccx_tn);
		zt_ccx->ztccx_tn = NULL;
		return (-1);
	}

	if (topo_node_range_create(mod, zt_ccx->ztccx_tn, CACHE, 0, 0) != 0) {
		topo_mod_dprintf(mod, "failed to create cache range: %s\n",
		    topo_mod_errmsg(mod));
		topo_node_unbind(zt_ccx->ztccx_tn);
		zt_ccx->ztccx_tn = NULL;
		return (-1);
	}

	if (zt_ccx->ztccx_l3 != NULL) {
		zt_ccx->ztccx_l3_tn = topo_zen_build_cache(mod, sock,
		    zt_ccx->ztccx_tn, 0, zt_ccx->ztccx_l3);
		if (zt_ccx->ztccx_l3_tn == NULL) {
			return (-1);
		}
	}

	if (topo_node_range_create(mod, zt_ccx->ztccx_tn, CORE, 0,
	    ccx->atccx_nphys_cores - 1) != 0) {
		topo_mod_dprintf(mod, "failed to create cores range: %s\n",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	for (uint32_t coreno = 0; coreno < ccx->atccx_nphys_cores; coreno++) {
		int ret;

		if (ccx->atccx_core_en[coreno] == 0) {
			topo_mod_dprintf(mod, "skipping core %u\n", coreno);
			continue;
		}

		if ((ret = topo_zen_build_core(mod, sock, zt_ccx->ztccx_tn,
		    &ccx->atccx_cores[coreno], &zt_ccx->ztccx_core[coreno])) !=
		    0) {
			return (ret);
		}
	}

	return (0);
}

static int
topo_zen_build_ccds(topo_mod_t *mod, zen_topo_enum_sock_t *sock)
{
	tnode_t *chip = sock->ztes_tn;

	if (topo_node_range_create(mod, chip, CCD, 0, sock->ztes_nccd - 1) !=
	    0) {
		topo_mod_dprintf(mod, "failed to create CCD range: %s\n",
		    topo_mod_errmsg(mod));
		return (-1);
	}

	for (uint32_t ccdno = 0; ccdno < sock->ztes_nccd; ccdno++) {
		const amdzen_topo_ccd_t *ccd = &sock->ztes_ccd[ccdno];
		zen_topo_enum_ccd_t *zt_ccd = &sock->ztes_tn_ccd[ccdno];

		/*
		 * Make sure we skip any CCDs that don't actually exist.
		 */
		if (ccd->atccd_err != AMDZEN_TOPO_CCD_E_OK) {
			continue;
		}

		zt_ccd->ztccd_tn = topo_zen_create_tn(mod, sock, chip, ccdno,
		    CCD);
		if (zt_ccd->ztccd_tn == NULL) {
			return (-1);
		}

		if (topo_create_props(mod, zt_ccd->ztccd_tn,
		    TOPO_PROP_IMMUTABLE, &topo_zen_ccd_pgroup,
		    TOPO_PGROUP_CCD_LOGID, TOPO_TYPE_UINT32, ccd->atccd_log_no,
		    TOPO_PGROUP_CCD_PHYSID, TOPO_TYPE_UINT32,
		    ccd->atccd_phys_no, NULL) != 0) {
			topo_node_unbind(zt_ccd->ztccd_tn);
			zt_ccd->ztccd_tn = NULL;
			return (-1);
		}

		/*
		 * At this point we should go create any additional sensors
		 * (such as the per-CCD Tctl) and probably set some methods,
		 * etc.
		 */

		if (topo_node_range_create(mod, zt_ccd->ztccd_tn, CCX, 0,
		    ccd->atccd_nphys_ccx) != 0) {
			topo_mod_dprintf(mod, "failed to create CCD range: "
			    "%s\n", topo_mod_errmsg(mod));
			return (-1);
		}

		for (uint32_t ccxno = 0; ccxno < ccd->atccd_nphys_ccx;
		    ccxno++) {
			int ret;

			if (ccd->atccd_ccx_en[ccxno] == 0) {
				continue;
			}

			if ((ret = topo_zen_build_ccx(mod, sock,
			    zt_ccd->ztccd_tn, &ccd->atccd_ccx[ccxno],
			    &zt_ccd->ztccd_ccx[ccxno])) != 0) {
				return (ret);
			}
		}
	}

	return (0);
}

int
topo_zen_build_chip(topo_mod_t *mod, tnode_t *pnode, topo_instance_t inst,
    zen_topo_enum_sock_t *sock)
{
	int ret;
	tnode_t *chip;

	chip = topo_zen_create_tn(mod, sock, pnode, inst, CHIP);
	if (chip == NULL) {
		return (-1);
	}

	if (topo_create_props(mod, chip, TOPO_PROP_IMMUTABLE,
	    &topo_zen_chip_pgroup,
	    TOPO_PGROUP_CHIP_BRAND, TOPO_TYPE_STRING, sock->ztes_cpu_brand,
	    TOPO_PGROUP_CHIP_FAMILY, TOPO_TYPE_INT32, sock->ztes_cpu_fam,
	    TOPO_PGROUP_CHIP_MODEL, TOPO_TYPE_INT32, sock->ztes_cpu_model,
	    TOPO_PGROUP_CHIP_STEPPING, TOPO_TYPE_INT32, sock->ztes_cpu_step,
	    TOPO_PGROUP_CHIP_SOCKET, TOPO_TYPE_STRING, sock->ztes_cpu_sock,
	    TOPO_PGROUP_CHIP_REVISION, TOPO_TYPE_STRING, sock->ztes_cpu_rev,
	    NULL) != 0) {
		topo_node_unbind(chip);
		return (-1);
	}

	sock->ztes_tn = chip;
	ret = topo_zen_build_ccds(mod, sock);

	/*
	 * At this point we should flesh out the I/O die and all the UMCs, IOMS
	 * instances, and related. we would put the general thermal sensor that
	 * smntemp exposes as procnode.%u under the I/O die when we have it.
	 */

	return (ret);
}
