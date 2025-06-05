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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * This module implements a series of enumeration methods that tie into the
 * amdzen(4D) nexus driver. This module is currently built out of the various
 * x86 platform directories (though it'd be nice if we could just make this
 * ISA-specific rather than platform-specific).
 */

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <sys/devfm.h>
#include <sys/x86_archext.h>

#include "topo_zen_impl.h"

/*
 * This is the path to the device node that amdzen(4D) creates for us to ask it
 * questions.
 */
static const char *topo_zen_dev = "/devices/pseudo/amdzen@0:topo";

static inline boolean_t
topo_zen_df_at_least(const amdzen_topo_df_t *df, uint8_t major, uint8_t minor)
{
	return (df->atd_major > major || (df->atd_major == major &&
	    df->atd_minor >= minor));
}

/*
 * Helper to determine whether or not a given DF entity's type is that of a CCM
 * or not as this has changed across the various DF versions.
 */
static boolean_t
topo_zen_fabric_is_ccm(const amdzen_topo_df_t *df,
    const amdzen_topo_df_ent_t *ent)
{
	if (ent->atde_type != DF_TYPE_CCM) {
		return (B_FALSE);
	}

	if (df->atd_rev >= DF_REV_4 && topo_zen_df_at_least(df, 4, 1)) {
		return (ent->atde_subtype == DF_CCM_SUBTYPE_CPU_V4P1);
	} else {
		return (ent->atde_subtype == DF_CCM_SUBTYPE_CPU_V2);
	}
}

/*
 * Clean up all data that is associated with an attempt to enumerate the socket.
 * The structure itself is assumed to be on the stack or handled elsewhere. It
 * must have been initialized prior to calling this. Don't give us stack
 * garbage.
 */
static void
topo_zen_enum_cleanup_sock(topo_mod_t *mod, zen_topo_enum_sock_t *sock)
{
	if (sock->ztes_kstat != NULL) {
		(void) kstat_close(sock->ztes_kstat);
		sock->ztes_kstat = NULL;
	}

	if (sock->ztes_cpus != NULL) {
		for (uint_t i = 0; i < sock->ztes_ncpus; i++) {
			nvlist_free(sock->ztes_cpus[i]);
		}
		umem_free(sock->ztes_cpus, sizeof (nvlist_t *) *
		    sock->ztes_ncpus);
		sock->ztes_cpus = NULL;
	}

	if (sock->ztes_fm_agent != NULL) {
		fmd_agent_cache_info_free(sock->ztes_fm_agent,
		    &sock->ztes_cache);
		fmd_agent_close(sock->ztes_fm_agent);
		sock->ztes_fm_agent = NULL;
	}

	if (sock->ztes_tn_ccd != NULL) {
		topo_mod_free(mod, sock->ztes_tn_ccd, sock->ztes_nccd *
		    sizeof (zen_topo_enum_ccd_t));
		sock->ztes_tn_ccd = NULL;
	}

	if (sock->ztes_ccd != NULL) {
		topo_mod_free(mod, sock->ztes_ccd, sock->ztes_nccd *
		    sizeof (amdzen_topo_ccd_t));
		sock->ztes_ccd = NULL;
	}
}

static int
topo_zen_enum_chip_gather_ccd(topo_mod_t *mod, const zen_topo_t *zen,
    zen_topo_enum_sock_t *sock,
    const amdzen_topo_df_ent_t *dfe, uint32_t ccdno, uint32_t phys_ccdno)
{
	amdzen_topo_ccd_t *ccd;

	ccd = &sock->ztes_ccd[ccdno];
	ccd->atccd_dfno = sock->ztes_df->atd_dfno;
	ccd->atccd_instid = dfe->atde_inst_id;
	ccd->atccd_phys_no = phys_ccdno;
	if (ioctl(zen->zt_fd, AMDZEN_TOPO_IOCTL_CCD, ccd) != 0) {
		topo_mod_dprintf(mod, "failed to get CCD information "
		    "for DF/CCD 0x%x/0x%x: %s\n", sock->ztes_df->atd_dfno,
		    ccd->atccd_instid, strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	switch (ccd->atccd_err) {
	case AMDZEN_TOPO_CCD_E_OK:
		sock->ztes_nccd_valid++;
		break;
	/*
	 * We ignore errors about CCDs being missing. This is fine
	 * because on systems without a full CCD complement this will
	 * happen and is expected. We make sure we have at least one
	 * valid CCD before continuing.
	 */
	case AMDZEN_TOPO_CCD_E_CCD_MISSING:
		break;
	default:
		topo_mod_dprintf(mod, "DF CCM fabric 0x%x, CCD 0x%x "
		    "didn't give us valid info: found error 0x%x\n",
		    dfe->atde_fabric_id, phys_ccdno, ccd->atccd_err);
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	return (0);
}


/*
 * Go through all of our disparate sources and gather information that we'll
 * need to process and perform enumeration. We need to gather the following
 * disparate pieces of information:
 *
 * 1) We need to determine what's going on with all the CCDs and ask the
 * amdzen(4D) driver for information.
 *
 * 2) We need to use the FM agent to ask /dev/fm to get all the CPU information
 * for this system.
 *
 * 3) We use the same system to go get all the actual cache information for this
 * system.
 *
 * 4) We grab some of the chip-wide information such as the socket and brand
 * string information through kstats, with information about a valid CPU ID.
 */
static int
topo_zen_enum_chip_gather(topo_mod_t *mod, const zen_topo_t *zen,
    const amdzen_topo_df_t *df, zen_topo_enum_sock_t *sock)
{
	uint32_t nccd = 0;

	sock->ztes_df = df;
	for (uint32_t i = 0; i < df->atd_df_buf_nvalid; i++) {
		const amdzen_topo_df_ent_t *dfe = &df->atd_df_ents[i];
		if (topo_zen_fabric_is_ccm(df, dfe)) {
			nccd += dfe->atde_data.atded_ccm.atcd_nccds;
		}
	}

	if (nccd == 0) {
		topo_mod_dprintf(mod, "no CCDs found! Not much more we can "
		    "do... Something probably went wrong\n");
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	sock->ztes_nccd = nccd;
	sock->ztes_ccd = topo_mod_zalloc(mod, sizeof (amdzen_topo_ccd_t) *
	    sock->ztes_nccd);
	if (sock->ztes_ccd == NULL) {
		topo_mod_dprintf(mod, "failed to allocate memory for "
		    "ztes_ccd[]\n");
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	sock->ztes_tn_ccd = topo_mod_zalloc(mod, sizeof (zen_topo_enum_ccd_t) *
	    sock->ztes_nccd);

	for (uint32_t i = 0, ccdno = 0; i < df->atd_df_buf_nvalid; i++) {
		const amdzen_topo_df_ent_t *dfe = &df->atd_df_ents[i];
		const amdzen_topo_ccm_data_t *ccm;

		if (!topo_zen_fabric_is_ccm(df, dfe)) {
			continue;
		}

		ccm = &dfe->atde_data.atded_ccm;
		for (uint32_t ccm_ccdno = 0; ccm_ccdno < ccm->atcd_nccds;
		    ccm_ccdno++) {
			if (ccm->atcd_ccd_en[ccm_ccdno] == 0) {
				continue;
			}

			if (topo_zen_enum_chip_gather_ccd(mod, zen, sock, dfe,
			    ccdno, ccm->atcd_ccd_ids[ccm_ccdno]) != 0) {
				return (-1);
			}

			ccdno++;
		}
	}

	topo_mod_dprintf(mod, "found %u CCDs\n", sock->ztes_nccd_valid);
	if (sock->ztes_nccd_valid == 0) {
		topo_mod_dprintf(mod, "somehow we ended up with no CCDs with "
		    "valid topo information. Something went very wrong.\n");
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	sock->ztes_fm_agent = fmd_agent_open(FMD_AGENT_VERSION);
	if (sock->ztes_fm_agent == NULL) {
		topo_mod_dprintf(mod, "failed to open FMD agent: %s\n",
		    strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	if (fmd_agent_physcpu_info(sock->ztes_fm_agent, &sock->ztes_cpus,
	    &sock->ztes_ncpus) != 0) {
		topo_mod_dprintf(mod, "failed to get FM agent CPU "
		    "information: %s\n",
		    strerror(fmd_agent_errno(sock->ztes_fm_agent)));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	topo_mod_dprintf(mod, "got %u CPUs worth of data from the FM agent\n",
	    sock->ztes_ncpus);

	if (fmd_agent_cache_info(sock->ztes_fm_agent, &sock->ztes_cache) != 0) {
		topo_mod_dprintf(mod, "failed to get FM agent cache "
		    "information: %s\n",
		    strerror(fmd_agent_errno(sock->ztes_fm_agent)));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	if (sock->ztes_cache.fmc_ncpus != sock->ztes_ncpus) {
		topo_mod_dprintf(mod, "/dev/fm gave us %u CPUs, but %u CPUs "
		    "for cache information: cannot continue\n",
		    sock->ztes_ncpus, sock->ztes_cache.fmc_ncpus);
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	sock->ztes_kstat = kstat_open();
	if (sock->ztes_kstat == NULL) {
		topo_mod_dprintf(mod, "failed to open kstat driver: %s\n",
		    strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	return (0);
}

typedef enum {
	ZEN_TOPO_CACHE_UNKNOWN,
	ZEN_TOPO_CACHE_CORE_L1D,
	ZEN_TOPO_CACHE_CORE_L1I,
	ZEN_TOPO_CACHE_CORE_L2,
	ZEN_TOPO_CACHE_CCX_L3
} zen_topo_cache_type_t;

typedef struct {
	uint32_t		ztcm_level;
	fm_cache_info_type_t	ztcm_type;
	boolean_t		ztcm_core;
	zen_topo_cache_type_t	ztcm_cache;
} zen_topo_cache_map_t;

const zen_topo_cache_map_t zen_topo_cache_map[] = {
	{ 1, FM_CACHE_INFO_T_DATA, B_TRUE, ZEN_TOPO_CACHE_CORE_L1D },
	{ 1, FM_CACHE_INFO_T_INSTR, B_TRUE, ZEN_TOPO_CACHE_CORE_L1I },
	{ 2, FM_CACHE_INFO_T_DATA | FM_CACHE_INFO_T_INSTR |
	    FM_CACHE_INFO_T_UNIFIED, B_TRUE, ZEN_TOPO_CACHE_CORE_L2 },
	{ 3, FM_CACHE_INFO_T_DATA | FM_CACHE_INFO_T_INSTR |
	    FM_CACHE_INFO_T_UNIFIED, B_FALSE, ZEN_TOPO_CACHE_CCX_L3 }
};

static zen_topo_cache_type_t
zen_topo_determine_cache(topo_mod_t *mod, uint32_t level, uint32_t type,
    uint32_t shift)
{
	for (size_t i = 0; i < ARRAY_SIZE(zen_topo_cache_map); i++) {
		const zen_topo_cache_map_t *map = &zen_topo_cache_map[i];

		if (map->ztcm_level == level && map->ztcm_type == type) {
			return (map->ztcm_cache);
		}
	}

	return (ZEN_TOPO_CACHE_UNKNOWN);
}

/*
 * We have mapped a logical CPU to a position in the hierarchy. We must now walk
 * its caches and attempt to install them up the chain. We assume that there
 * there are four caches right now: an L1i, L1d, L2, and L3 cache.
 *
 * Note, AMD has mixed designs with 1 CCX and 2 CCXs. When there is only 1 CCX
 * then we often describe the CCX and CCD as equivalent though if you look at
 * the PPR it describes each CCD as having a single CCX. This is why the L3
 * cache lives on the CCX right now.
 *
 * Historically we tried to leverage the APIC shift information that the kernel
 * provides around the number of CPUs that shared a cache and map that to the
 * APIC ID decomposition information that we had. Unfortunately, this heuristic
 * was useful, but inaccurate. In particular the CPUID interface gives us a
 * count of logical CPUs that share something. If you had less CPUs in a CCD
 * than the APIC split would be at, then this would fail. A prime example is a
 * 32 CPU where there are 4 cores in each of 8 CCDs. This would result in 8
 * logical CPUs sharing the CPU; however, the APIC split was often shifting over
 * at 4 because the CCD design was for up to 8 cores.
 */
static boolean_t
topo_zen_map_caches(topo_mod_t *mod, zen_topo_enum_sock_t *sock,
    zen_topo_enum_ccx_t *ccx, zen_topo_enum_core_t *core, uint32_t cpuno)
{
	fmd_agent_cpu_cache_t *cpu_cache = &sock->ztes_cache.fmc_cpus[cpuno];
	if (cpu_cache->fmcc_ncaches == 0) {
		return (B_TRUE);
	}

	/*
	 * For each cache that we discover we need to do the following:
	 *
	 *  o Determine the type of cache that this is. While the upper layers
	 *    guarantee us the L1 caches come before L2 and L2 before L3, we
	 *    don't care.
	 *  o If a cache is already there, it should have the same ID as the one
	 *    that we already have.
	 */
	for (uint_t i = 0; i < cpu_cache->fmcc_ncaches; i++) {
		nvlist_t *nvl = cpu_cache->fmcc_caches[i];
		nvlist_t **cachep = NULL;
		zen_topo_cache_type_t ct;
		uint32_t level, type, shift;
		uint64_t id, alt_id;

		if (nvlist_lookup_pairs(nvl, 0,
		    FM_CACHE_INFO_LEVEL, DATA_TYPE_UINT32, &level,
		    FM_CACHE_INFO_TYPE, DATA_TYPE_UINT32, &type,
		    FM_CACHE_INFO_ID, DATA_TYPE_UINT64, &id,
		    FM_CACHE_INFO_X86_APIC_SHIFT, DATA_TYPE_UINT32, &shift,
		    NULL) != 0) {
			topo_mod_dprintf(mod, "missing required nvlist fields "
			    "from FM CPU %u cache %u\n", cpuno, i);
			return (B_FALSE);
		}

		ct = zen_topo_determine_cache(mod, level, type, shift);
		switch (ct) {
		case ZEN_TOPO_CACHE_UNKNOWN:
			topo_mod_dprintf(mod, "failed to map CPU %u cache %u "
			    "with id 0x%" PRIx64 " level %u, type 0x%x, APIC "
			    "shift 0x%x to a known type\n", cpuno, i, id, level,
			    type, shift);
			return (B_FALSE);
		case ZEN_TOPO_CACHE_CORE_L1D:
			cachep = &core->ztcore_l1d;
			break;
		case ZEN_TOPO_CACHE_CORE_L1I:
			cachep = &core->ztcore_l1i;
			break;
		case ZEN_TOPO_CACHE_CORE_L2:
			cachep = &core->ztcore_l2;
			break;
		case ZEN_TOPO_CACHE_CCX_L3:
			cachep = &ccx->ztccx_l3;
			break;
		}

		if (*cachep == NULL) {
			*cachep = nvl;
			continue;
		}

		alt_id = fnvlist_lookup_uint64(*cachep, FM_CACHE_INFO_ID);
		if (alt_id != id) {
			topo_mod_dprintf(mod, "wanted to map CPU %u cache %u "
			    "with id 0x%" PRIx64 " level %u, type 0x%x, APIC "
			    "shift 0x%x to Zen cache type 0x%x, but cache with "
			    "id 0x%" PRIx64 " already present", cpuno, i,
			    id, level, type, shift, ct, alt_id);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
topo_zen_map_logcpu_to_phys(topo_mod_t *mod, zen_topo_enum_sock_t *sock,
    nvlist_t *cpu_nvl, uint32_t cpuno, uint32_t apicid)
{
	for (uint32_t ccdno = 0; ccdno < sock->ztes_nccd; ccdno++) {
		amdzen_topo_ccd_t *ccd = &sock->ztes_ccd[ccdno];
		if (ccd->atccd_err != AMDZEN_TOPO_CCD_E_OK)
			continue;

		for (uint32_t ccxno = 0; ccxno < ccd->atccd_nphys_ccx;
		    ccxno++) {
			amdzen_topo_ccx_t *ccx;
			if (ccd->atccd_ccx_en[ccxno] == 0)
				continue;

			ccx = &ccd->atccd_ccx[ccxno];
			for (uint32_t coreno = 0;
			    coreno < ccx->atccx_nphys_cores; coreno++) {
				amdzen_topo_core_t *core;
				if (ccx->atccx_core_en[coreno] == 0)
					continue;

				core = &ccx->atccx_cores[coreno];
				for (uint32_t thrno = 0;
				    thrno < core->atcore_nthreads; thrno++) {
					zen_topo_enum_ccd_t *zt_ccd;
					zen_topo_enum_ccx_t *zt_ccx;
					zen_topo_enum_core_t *zt_core;

					if (core->atcore_thr_en[thrno] == 0)
						continue;

					if (core->atcore_apicids[thrno] !=
					    apicid) {
						continue;
					}

					/*
					 * We have a match. Make sure we haven't
					 * already used it.
					 */
					zt_ccd = &sock->ztes_tn_ccd[ccdno];
					zt_ccx = &zt_ccd->ztccd_ccx[ccxno];
					zt_core = &zt_ccx->ztccx_core[coreno];

					if (zt_core->ztcore_nvls[thrno] !=
					    NULL) {
						topo_mod_dprintf(mod, "APIC ID "
						    "0x%x mapped to CCD/CCX/"
						    "Core/Thread 0x%x/0x%x/"
						    "0x%x/0x%x, but found "
						    "another nvlist already "
						    "there\n", apicid, ccdno,
						    ccxno, coreno, thrno);
						return (B_FALSE);
					}

					zt_core->ztcore_nvls[thrno] = cpu_nvl;

					/*
					 * Now that we have successfully mapped
					 * a core into the tree go install the
					 * logical CPU's cache information up
					 * the tree.
					 */
					return (topo_zen_map_caches(mod, sock,
					    zt_ccx, zt_core, cpuno));
				}
			}
		}
	}

	topo_mod_dprintf(mod, "failed to find a CPU for apic 0x%x\n",
	    apicid);
	return (B_FALSE);
}

/*
 * Using information from the given logical CPU that we know is part of our
 * socket that we're enumerating, attempt to go through and load information
 * about the chip itself such as the family, model, stepping, brand string, etc.
 * This comes from both the /dev/fm information that we have in cpu_nvl and from
 * kstats.
 */
static int
topo_zen_map_common_chip_info(topo_mod_t *mod, zen_topo_enum_sock_t *sock,
    nvlist_t *cpu_nvl)
{
	char name[KSTAT_STRLEN];
	int32_t cpu_id;
	uint32_t sockid;
	char *rev, *ident;
	kstat_t *ks;
	const kstat_named_t *knp;

	if (nvlist_lookup_pairs(cpu_nvl, 0,
	    FM_PHYSCPU_INFO_CPU_ID, DATA_TYPE_INT32, &cpu_id,
	    FM_PHYSCPU_INFO_CHIP_REV, DATA_TYPE_STRING, &rev,
	    FM_PHYSCPU_INFO_SOCKET_TYPE, DATA_TYPE_UINT32, &sockid,
	    FM_PHYSCPU_INFO_FAMILY, DATA_TYPE_INT32, &sock->ztes_cpu_fam,
	    FM_PHYSCPU_INFO_MODEL, DATA_TYPE_INT32, &sock->ztes_cpu_model,
	    FM_PHYSCPU_INFO_STEPPING, DATA_TYPE_INT32, &sock->ztes_cpu_step,
	    NULL) != 0) {
		topo_mod_dprintf(mod, "missing required nvlist fields "
		    "from FM physcpu info chip ident\n");
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	/*
	 * Some CPUs have PPIN disabled so we look for it separately here. The
	 * rest of the aspects are required.
	 */
	if (nvlist_lookup_string(cpu_nvl, FM_PHYSCPU_INFO_CHIP_IDENTSTR,
	    &ident) != 0) {
		ident = NULL;
	}

	/*
	 * If we can not fully identify a revision, the kernel will indicate so
	 * with a '?' in the name where normally a stepping would show up. See
	 * amd_revmap[] in uts/intel/os/cpuid_subr.c. In such a case, we do not
	 * want to propagate such a revision.
	 */
	if (strchr(rev, '?') == NULL) {
		sock->ztes_cpu_rev = rev;
	}
	sock->ztes_cpu_serial = ident;

	if (snprintf(name, sizeof (name), "cpu_info%d", cpu_id) >=
	    sizeof (name)) {
		topo_mod_dprintf(mod, "failed to construct kstat name: "
		    "overflow");
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	ks = kstat_lookup(sock->ztes_kstat, "cpu_info", cpu_id, name);
	if (ks == NULL) {
		topo_mod_dprintf(mod, "failed to find 'cpu_info:%d:%s': %s",
		    cpu_id, name, strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	if (kstat_read(sock->ztes_kstat, ks, NULL) == -1) {
		topo_mod_dprintf(mod, "failed to read kstat 'cpu_info:%d:%s': "
		    "%s", cpu_id, name, strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	knp = kstat_data_lookup(ks, "brand");
	if (knp == NULL) {
		topo_mod_dprintf(mod, "failed to find 'cpu_info:%d:%s:brand\n",
		    cpu_id, name);
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));

	}
	sock->ztes_cpu_brand = KSTAT_NAMED_STR_PTR(knp);

	if (sockid == X86_SOCKET_UNKNOWN) {
		return (0);
	}

	knp = kstat_data_lookup(ks, "socket_type");
	if (knp == NULL) {
		topo_mod_dprintf(mod, "failed to find 'cpu_info:%d:%s:"
		    "socket_type\n", cpu_id, name);
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}
	sock->ztes_cpu_sock = KSTAT_NAMED_STR_PTR(knp);

	return (0);
}

static int
topo_zen_enum_chip_map(topo_mod_t *mod, zen_topo_enum_sock_t *sock)
{
	/*
	 * We have an arrray of information from /dev/fm that describes each
	 * logical CPU. We would like to map that to a given place in physical
	 * topology, which we do via the APIC ID. We will then also determine
	 * how caches are mapped together.
	 */
	for (uint_t i = 0; i < sock->ztes_ncpus; i++) {
		int32_t apicid, sockid;
		nvlist_t *cpu_nvl = sock->ztes_cpus[i];

		if (nvlist_lookup_pairs(cpu_nvl, 0,
		    FM_PHYSCPU_INFO_CHIP_ID, DATA_TYPE_INT32, &sockid,
		    FM_PHYSCPU_INFO_STRAND_APICID, DATA_TYPE_INT32, &apicid,
		    NULL) != 0) {
			topo_mod_dprintf(mod, "missing required nvlist fields "
			    "from FM physcpu info for CPU %u\n", i);
			return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
		}

		/*
		 * This logical CPU isn't for our socket, ignore it.
		 */
		if (sockid != sock->ztes_sockid) {
			continue;
		}

		if (!topo_zen_map_logcpu_to_phys(mod, sock, cpu_nvl, i,
		    (uint32_t)apicid)) {
			return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
		}
	}

	/*
	 * Now that we have each logical CPU taken care of, we want to fill in
	 * information about the common CPU.
	 */
	for (uint_t i = 0; i < sock->ztes_ncpus; i++) {
		int32_t sockid;
		nvlist_t *cpu_nvl = sock->ztes_cpus[i];

		if (nvlist_lookup_pairs(cpu_nvl, 0,
		    FM_PHYSCPU_INFO_CHIP_ID, DATA_TYPE_INT32, &sockid,
		    NULL) != 0) {
			topo_mod_dprintf(mod, "missing required nvlist fields "
			    "from FM physcpu info for CPU %u\n", i);
			return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
		}

		/*
		 * This logical CPU isn't for our socket, ignore it.
		 */
		if (sockid != sock->ztes_sockid) {
			continue;
		}

		return (topo_zen_map_common_chip_info(mod, sock, cpu_nvl));
	}

	topo_mod_dprintf(mod, "no logical CPUs match our target socket %u!\n",
	    sock->ztes_sockid);
	return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
}

static int
topo_zen_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *modarg, void *data)
{
	int ret;
	zen_topo_t *zen = topo_mod_getspecific(mod);
	amdzen_topo_df_t *df = NULL;
	topo_zen_chip_t *chip;
	zen_topo_enum_sock_t sock;

	topo_mod_dprintf(mod, "asked to enum %s [%" PRIu64 ", %" PRIu64 "] on "
	    "%s%" PRIu64 "\n", name, min, max, topo_node_name(pnode),
	    topo_node_instance(pnode));

	/*
	 * Currently we only support enumerating a given chip.
	 */
	if (strcmp(name, CHIP) != 0) {
		topo_mod_dprintf(mod, "cannot enumerate %s: unknown type\n",
		    name);
		return (-1);
	}

	if (data == NULL) {
		topo_mod_dprintf(mod, "cannot enumerate %s: missing required "
		    "data\n", name);
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	}

	if (min != max) {
		topo_mod_dprintf(mod, "cannot enumerate %s: multiple instances "
		    "requested\n", name);
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	}

	chip = data;
	for (uint32_t i = 0; i < zen->zt_base.atb_ndf; i++) {
		if (zen->zt_dfs[i].atd_sockid == chip->tzc_sockid) {
			df = &zen->zt_dfs[i];
			break;
		}
	}

	if (df == NULL) {
		topo_mod_dprintf(mod, "no matching DF with socket %u",
		    chip->tzc_sockid);
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	}

	/*
	 * In our supported platforms there is either a single DF instance per
	 * die (DFv3+ aka Zen 2+) or we have the older style Zen 1 (aka DFv2)
	 * systems where there are multiple dies within the package. We don't
	 * support Zen 1/DFv2 based systems right now.
	 */
	if (zen->zt_base.atb_rev == DF_REV_UNKNOWN) {
		topo_mod_dprintf(mod, "DF base revision is unknown, cannot "
		    "proceed\n");
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	if (zen->zt_base.atb_rev == DF_REV_2) {
		topo_mod_dprintf(mod, "DFv2 multiple dies are not currently "
		    "supported\n");
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
	}

	/*
	 * We want to create our "chip" node at the top of this. To do that,
	 * we'd like to know things like the CPU's PPIN and other information
	 * like the socket type and related. To do this we will start by getting
	 * information about the physical CPU information from devfm. That will
	 * be combined with our knowledge of how APIC IDs map to data fabric
	 * elements.
	 */
	bzero(&sock, sizeof (sock));
	sock.ztes_sockid = chip->tzc_sockid;
	if ((ret = topo_zen_enum_chip_gather(mod, zen, df, &sock)) != 0) {
		topo_zen_enum_cleanup_sock(mod, &sock);
		return (ret);
	}

	/*
	 * Determine the mapping of all the logical CPU entries and their data
	 * that we found to the CCD mapping.
	 */
	if ((ret = topo_zen_enum_chip_map(mod, &sock)) != 0) {
		return (ret);
	}

	ret = topo_zen_build_chip(mod, pnode, min, &sock);
	topo_zen_enum_cleanup_sock(mod, &sock);

	return (ret);
}

static const topo_modops_t topo_zen_ops = {
	topo_zen_enum, NULL
};

static topo_modinfo_t topo_zen_mod = {
	"AMD Zen Enumerator", FM_FMRI_SCHEME_HC, TOPO_MOD_ZEN_VERS,
	    &topo_zen_ops
};

static void
topo_zen_cleanup(topo_mod_t *mod, zen_topo_t *zen)
{
	if (zen->zt_dfs != NULL) {
		for (uint32_t i = 0; i < zen->zt_base.atb_ndf; i++) {
			size_t entsize;

			if (zen->zt_dfs[i].atd_df_ents == NULL)
				continue;
			entsize = sizeof (amdzen_topo_df_ent_t) *
			    zen->zt_base.atb_maxdfent;
			topo_mod_free(mod, zen->zt_dfs[i].atd_df_ents,
			    entsize);
		}
		topo_mod_free(mod, zen->zt_dfs, sizeof (amdzen_topo_df_t) *
		    zen->zt_base.atb_ndf);
	}

	if (zen->zt_fd >= 0) {
		(void) close(zen->zt_fd);
		zen->zt_fd = -1;
	}
	topo_mod_free(mod, zen, sizeof (zen_topo_t));
}

static int
topo_zen_init(topo_mod_t *mod, zen_topo_t *zen)
{
	zen->zt_fd = open(topo_zen_dev, O_RDONLY);
	if (zen->zt_fd < 0) {
		topo_mod_dprintf(mod, "failed to open %s: %s\n", topo_zen_dev,
		    strerror(errno));
		return (-1);
	}

	if (ioctl(zen->zt_fd, AMDZEN_TOPO_IOCTL_BASE, &zen->zt_base) != 0) {
		topo_mod_dprintf(mod, "failed to get base Zen topology "
		    "information: %s\n", strerror(errno));
		return (-1);
	}

	/*
	 * Get all of the basic DF information now.
	 */
	zen->zt_dfs = topo_mod_zalloc(mod, sizeof (amdzen_topo_df_t) *
	    zen->zt_base.atb_ndf);
	if (zen->zt_dfs == NULL) {
		topo_mod_dprintf(mod, "failed to allocate space for %u DF "
		    "entries: %s\n", zen->zt_base.atb_ndf,
		    topo_strerror(EMOD_NOMEM));
		return (-1);
	}

	for (uint32_t i = 0; i < zen->zt_base.atb_ndf; i++) {
		amdzen_topo_df_t *topo_df = &zen->zt_dfs[i];

		topo_df->atd_df_ents = topo_mod_zalloc(mod,
		    sizeof (amdzen_topo_df_ent_t) * zen->zt_base.atb_maxdfent);
		if (topo_df->atd_df_ents == NULL) {
			topo_mod_dprintf(mod, "failed to allocate space for "
			    "DF %u's DF ents: %s\n", i,
			    topo_strerror(EMOD_NOMEM));
			return (-1);
		}
		topo_df->atd_df_buf_nents = zen->zt_base.atb_maxdfent;
		topo_df->atd_dfno = i;

		if (ioctl(zen->zt_fd, AMDZEN_TOPO_IOCTL_DF, topo_df) != 0) {
			topo_mod_dprintf(mod, "failed to get information for "
			    "DF %u: %s", i, strerror(errno));
			return (-1);
		}
	}

	return (0);
}

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	zen_topo_t *zen = NULL;

	if (getenv("TOPOZENDEBUG") != NULL) {
		topo_mod_setdebug(mod);
	}
	topo_mod_dprintf(mod, "module initializing\n");

	zen = topo_mod_zalloc(mod, sizeof (zen_topo_t));
	if (zen == NULL) {
		topo_mod_dprintf(mod, "failed to allocate zen_topo_t: %s\n",
		    topo_strerror(EMOD_NOMEM));
		return (-1);
	}

	if (topo_zen_init(mod, zen) != 0) {
		topo_zen_cleanup(mod, zen);
		return (-1);
	}

	if (topo_mod_register(mod, &topo_zen_mod, TOPO_VERSION) != 0) {
		topo_zen_cleanup(mod, zen);
		return (-1);
	}

	topo_mod_setspecific(mod, zen);
	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	zen_topo_t *zen;

	if ((zen = topo_mod_getspecific(mod)) == NULL) {
		return;
	}

	topo_mod_setspecific(mod, NULL);
	topo_zen_cleanup(mod, zen);
	topo_mod_unregister(mod);
}
