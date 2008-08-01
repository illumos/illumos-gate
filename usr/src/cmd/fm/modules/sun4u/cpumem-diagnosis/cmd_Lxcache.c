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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support routines for managing per-Lxcache state.
 */

#include <cmd_Lxcache.h>
#include <cmd_mem.h>
#include <cmd_cpu.h>
#include <cmd.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/cheetahregs.h>
#include <sys/mem_cache.h>
#include <fmd_adm.h>


#define	PN_ECSTATE_NA	5
/*
 * These values are our threshold values for SERDing CPU's based on the
 * the # of times we have retired a cache line for each category.
 */

#define	CMD_CPU_SERD_AGG_1  	64
#define	CMD_CPU_SERD_AGG_2	64

static void
Lxcache_write(fmd_hdl_t *hdl, cmd_Lxcache_t *Lxcache)
{
	fmd_buf_write(hdl, NULL, Lxcache->Lxcache_bufname, Lxcache,
	    sizeof (cmd_Lxcache_pers_t));
}

char *
cmd_type_to_str(cmd_ptrsubtype_t pstype)
{
	switch (pstype) {
		case CMD_PTR_CPU_L2DATA:
			return ("l2data");
			break;
		case CMD_PTR_CPU_L3DATA:
			return ("l3data");
			break;
		case CMD_PTR_CPU_L2TAG:
			return ("l2tag");
			break;
		case CMD_PTR_CPU_L3TAG:
			return ("l3tag");
			break;
		default:
			return ("unknown");
			break;
	}
}
void
cmd_Lxcache_free(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_Lxcache_t *Lxcache,
    int destroy)
{
	cmd_case_t *cc = &Lxcache->Lxcache_case;

	fmd_hdl_debug(hdl, "Entering cmd_Lxcache_free for %s destroy = %d\n",
	    Lxcache->Lxcache_bufname, destroy);

	if (cc->cc_cp != NULL)
		cmd_case_fini(hdl, cc->cc_cp, destroy);
	if (cc->cc_serdnm != NULL) {
		if (fmd_serd_exists(hdl, cc->cc_serdnm) && destroy) {
			fmd_serd_destroy(hdl, cc->cc_serdnm);
			fmd_hdl_strfree(hdl, cc->cc_serdnm);
			cc->cc_serdnm = NULL;
		}
	}

	if (destroy)
		fmd_buf_destroy(hdl, NULL, Lxcache->Lxcache_bufname);
	cmd_fmri_fini(hdl, &Lxcache->Lxcache_asru, destroy);
	cmd_list_delete(&cpu->cpu_Lxcaches, Lxcache);
	fmd_hdl_free(hdl, Lxcache, sizeof (cmd_Lxcache_t));
}

void
cmd_Lxcache_destroy(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_Lxcache_t *Lxcache)
{
	cmd_Lxcache_free(hdl, cpu, Lxcache, FMD_B_TRUE);
}

static cmd_Lxcache_t *
Lxcache_lookup_by_type_index_way_bit(cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype,
				uint32_t index, uint32_t way, uint16_t bit)
{
	cmd_Lxcache_t *Lxcache;

	for (Lxcache = cmd_list_next(&cpu->cpu_Lxcaches); Lxcache != NULL;
	    Lxcache = cmd_list_next(Lxcache)) {
		if ((Lxcache->Lxcache_type == pstype) &&
		    (Lxcache->Lxcache_index == index) &&
		    (Lxcache->Lxcache_way == way) &&
		    (Lxcache->Lxcache_bit == bit))
			return (Lxcache);
	}

	return (NULL);
}

cmd_Lxcache_t *
cmd_Lxcache_create(fmd_hdl_t *hdl, cmd_xr_t *xr, cmd_cpu_t *cpu,
    nvlist_t *modasru, cmd_ptrsubtype_t pstype, uint32_t index,
    uint32_t way, uint16_t bit)
{
	cmd_Lxcache_t *Lxcache;
	nvlist_t *asru;
	const char	*pstype_name;
	uint8_t	fmri_Lxcache_type;

	fmd_hdl_debug(hdl,
	    "creating new Lxcache for cachetype=%d index=%lx way=%lx bit=%x\n",
	    pstype, index, way, bit);

	CMD_CPU_STAT_BUMP(cpu, Lxcache_creat);

	Lxcache = fmd_hdl_zalloc(hdl, sizeof (cmd_Lxcache_t), FMD_SLEEP);
	(void) strncpy(Lxcache->Lxcache_cpu_bufname,
	    cpu->cpu_bufname, CMD_BUFNMLEN);
	Lxcache->Lxcache_nodetype = CMD_NT_LxCACHE;
	Lxcache->Lxcache_version = CMD_LxCACHE_VERSION;
	Lxcache->Lxcache_type = pstype;
	Lxcache->Lxcache_index = index;
	Lxcache->Lxcache_way = way;
	Lxcache->Lxcache_bit = bit;
	Lxcache->Lxcache_reason = CMD_LXFUNCTIONING;
	Lxcache->xr = xr;
	switch (pstype) {
		case CMD_PTR_CPU_L2DATA:
			pstype_name = "l2data";
			fmri_Lxcache_type = FM_FMRI_CPU_CACHE_TYPE_L2;
			break;
		case CMD_PTR_CPU_L3DATA:
			pstype_name = "l3data";
			fmri_Lxcache_type = FM_FMRI_CPU_CACHE_TYPE_L3;
			break;
		case CMD_PTR_CPU_L2TAG:
			pstype_name = "l2tag";
			fmri_Lxcache_type = FM_FMRI_CPU_CACHE_TYPE_L2;
			break;
		case CMD_PTR_CPU_L3TAG:
			pstype_name = "l3tag";
			fmri_Lxcache_type = FM_FMRI_CPU_CACHE_TYPE_L3;
			break;
		default:
			pstype_name = "unknown";
			break;
	}

	cmd_bufname(Lxcache->Lxcache_bufname, sizeof (Lxcache->Lxcache_bufname),
	    "Lxcache_%s_%04d_%08d_%02d_%03d", pstype_name, cpu->cpu_cpuid,
	    index, way, bit);
	if ((errno = nvlist_dup(modasru, &asru, 0)) != 0 ||
	    (errno = nvlist_add_uint32(asru, FM_FMRI_CPU_CACHE_INDEX,
	    index)) != 0 ||
	    (errno = nvlist_add_uint32(asru, FM_FMRI_CPU_CACHE_WAY,
	    way)) != 0 ||
	    (errno = nvlist_add_uint16(asru, FM_FMRI_CPU_CACHE_BIT,
	    bit)) != 0 ||
	    (errno = nvlist_add_uint8(asru, FM_FMRI_CPU_CACHE_TYPE,
	    fmri_Lxcache_type)) != 0 ||
	    (errno = fmd_nvl_fmri_expand(hdl, asru)) != 0)
		fmd_hdl_abort(hdl, "failed to build Lxcache fmri");

	cmd_fmri_init(hdl, &Lxcache->Lxcache_asru, asru,
	    "%s_asru_%08x_%02x_%04x", pstype_name, index, way, bit);

	nvlist_free(asru);

	cmd_list_append(&cpu->cpu_Lxcaches, Lxcache);
	Lxcache_write(hdl, Lxcache);

	return (Lxcache);
}

cmd_Lxcache_t *
cmd_Lxcache_lookup_by_index_way(cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype,
    uint32_t index, uint32_t way)
{
	cmd_Lxcache_t *cache;

	for (cache = cmd_list_next(&cpu->cpu_Lxcaches); cache != NULL;
	    cache = cmd_list_next(cache)) {
	if ((cache->Lxcache_index == index) &&
	    (cache->Lxcache_way == way) &&
	    (cache->Lxcache_type == pstype)) {
		return (cache);
		}
	}

	return (NULL);
}
cmd_Lxcache_t *
cmd_Lxcache_lookup(cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype, uint32_t index,
		uint32_t way, uint16_t bit)
{

	return (Lxcache_lookup_by_type_index_way_bit(cpu, pstype, index, way,
	    bit));
}
ssize_t
cmd_fmri_nvl2str(fmd_hdl_t *hdl, nvlist_t *nvl, char *buf, size_t buflen)
{
	uint8_t type;
	uint32_t cpuid, index, way;
	char *serstr = NULL;
	char    missing_list[128];

	missing_list[0] = 0;
	if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID, &cpuid) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_ID);
	if (nvlist_lookup_string(nvl, FM_FMRI_CPU_SERIAL_ID, &serstr) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_SERIAL_ID);
	if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_CACHE_INDEX, &index) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_CACHE_INDEX);
	if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_CACHE_WAY, &way) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_CACHE_WAY);
	if (nvlist_lookup_uint8(nvl, FM_FMRI_CPU_CACHE_TYPE, &type) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_CACHE_TYPE);

	if (strlen(missing_list) != 0) {
		fmd_hdl_debug(hdl,
		    "\ncmd_fmri_nvl2str: missing %s in fmri\n",
		    missing_list);
		return (-1);
	}

	return (snprintf(buf, buflen,
	    "cpu:///%s=%u/%s=%s/%s=%u/%s=%u/%s=%d",
	    FM_FMRI_CPU_ID, cpuid,
	    FM_FMRI_CPU_SERIAL_ID, serstr,
	    FM_FMRI_CPU_CACHE_INDEX, index,
	    FM_FMRI_CPU_CACHE_WAY, way,
	    FM_FMRI_CPU_CACHE_TYPE, type));
}

static int
cmd_repair_fmri(fmd_hdl_t *hdl, char *buf)
{
	fmd_adm_t *ap;
	int err;

	if ((ap = fmd_adm_open(NULL, FMD_ADM_PROGRAM,
	    FMD_ADM_VERSION)) == NULL) {
		fmd_hdl_debug(hdl, "Could not contact fmadm to unretire\n");
		return (-1);
	}

	err = fmd_adm_rsrc_repair(ap, buf);
	if (err)
		err = -1;
	fmd_adm_close(ap);
	return (err);
}

static cmd_Lxcache_t *
Lxcache_wrapv1(fmd_hdl_t *hdl, cmd_Lxcache_pers_t *pers, size_t psz)
{
	cmd_Lxcache_t *Lxcache;

	if (psz != sizeof (cmd_Lxcache_pers_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 1 state (%u bytes).\n",
		    sizeof (cmd_Lxcache_pers_t));
	}

	Lxcache = fmd_hdl_zalloc(hdl, sizeof (cmd_Lxcache_t), FMD_SLEEP);
	bcopy(pers, Lxcache, sizeof (cmd_Lxcache_pers_t));
	fmd_hdl_free(hdl, pers, psz);
	return (Lxcache);
}

void *
cmd_Lxcache_restore(fmd_hdl_t *hdl, fmd_case_t *cp, cmd_case_ptr_t *ptr)
{
	cmd_Lxcache_t *Lxcache;
	cmd_Lxcache_t *recovered_Lxcache;
	cmd_cpu_t	*cpu;
	size_t		Lxcachesz;
	char		*serdnm;

	/*
	 * We need to first extract the cpu name by reading directly
	 * from fmd buffers in order to begin our search for Lxcache in
	 * the appropriate cpu list.
	 * After we identify the cpu list using buf name we could look
	 * in cpu list for our Lxcache states.
	 */
	fmd_hdl_debug(hdl, "restoring Lxcache from %s\n", ptr->ptr_name);

	if ((Lxcachesz = fmd_buf_size(hdl, NULL, ptr->ptr_name)) == 0) {
		fmd_hdl_abort(hdl, "Lxcache referenced by case %s does "
		    "not exist in saved state\n",
		    fmd_case_uuid(hdl, cp));
	} else if (Lxcachesz != sizeof (cmd_Lxcache_pers_t)) {
		fmd_hdl_abort(hdl, "Lxcache buffer referenced by case %s "
		    "is %d bytes. Expected size is %d bytes\n",
		    fmd_case_uuid(hdl, cp), Lxcachesz,
		    sizeof (cmd_Lxcache_pers_t));
	}

	if ((Lxcache = cmd_buf_read(hdl, NULL, ptr->ptr_name,
	    Lxcachesz)) == NULL) {
		fmd_hdl_abort(hdl, "failed to read Lxcache buf %s",
		    ptr->ptr_name);
	}

	fmd_hdl_debug(hdl, "found %d in version field\n",
	    Lxcache->Lxcache_version);
	cpu = cmd_restore_cpu_only(hdl, cp, Lxcache->Lxcache_cpu_bufname);
	recovered_Lxcache = Lxcache;	/* save the recovered Lxcache */

	for (Lxcache = cmd_list_next(&cpu->cpu_Lxcaches); Lxcache != NULL;
	    Lxcache = cmd_list_next(Lxcache)) {
		if (strcmp(Lxcache->Lxcache_bufname, ptr->ptr_name) == 0)
			break;
	}

	if (Lxcache == NULL) {

		switch (recovered_Lxcache->Lxcache_version) {
			case CMD_LxCACHE_VERSION_1:
				Lxcache = Lxcache_wrapv1(hdl,
				    (cmd_Lxcache_pers_t *)recovered_Lxcache,
				    Lxcachesz);
				break;
			default:
				fmd_hdl_abort(hdl, "unknown version (found %d) "
				"for Lxcache state referenced by case %s.\n",
				    recovered_Lxcache->Lxcache_version,
				    fmd_case_uuid(hdl, cp));
			break;
		}

		cmd_fmri_restore(hdl, &Lxcache->Lxcache_asru);

		cmd_list_append(&cpu->cpu_Lxcaches, Lxcache);
	}
	serdnm = cmd_Lxcache_serdnm_create(hdl, cpu->cpu_cpuid,
	    Lxcache->Lxcache_type, Lxcache->Lxcache_index,
	    Lxcache->Lxcache_way, Lxcache->Lxcache_bit);
	fmd_hdl_debug(hdl,
	    "cpu_id %d: serdname for the case is %s\n",
	    cpu->cpu_cpuid, serdnm);
	fmd_hdl_debug(hdl,
	    "cpu_id %d: restoring the case for index %d way %d bit %d\n",
	    cpu->cpu_cpuid, Lxcache->Lxcache_index,
	    Lxcache->Lxcache_way, Lxcache->Lxcache_bit);
	cmd_case_restore(hdl, &Lxcache->Lxcache_case, cp, serdnm);

	return (Lxcache);
}


/*ARGSUSED*/
void
cmd_Lxcache_validate(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	cmd_Lxcache_t *Lxcache, *next;

	for (Lxcache = cmd_list_next(&cpu->cpu_Lxcaches);
	    Lxcache != NULL; Lxcache = next) {
		next = cmd_list_next(Lxcache);

		if (fmd_nvl_fmri_unusable(hdl, Lxcache->Lxcache_asru_nvl)) {
			cmd_Lxcache_destroy(hdl, cpu, Lxcache);
		}
	}
}

void
cmd_Lxcache_dirty(fmd_hdl_t *hdl, cmd_Lxcache_t *Lxcache)
{
	if (fmd_buf_size(hdl, NULL, Lxcache->Lxcache_bufname) !=
	    sizeof (cmd_Lxcache_pers_t))
		fmd_buf_destroy(hdl, NULL, Lxcache->Lxcache_bufname);

	/* No need to rewrite the FMRIs in the Lxcache - they don't change */
	fmd_buf_write(hdl, NULL,
	    Lxcache->Lxcache_bufname, &Lxcache->Lxcache_pers,
	    sizeof (cmd_Lxcache_pers_t));
}

void
cmd_Lxcache_fini(fmd_hdl_t *hdl, cmd_cpu_t *cpu)
{
	cmd_Lxcache_t *Lxcache;

	while ((Lxcache = cmd_list_next(&cpu->cpu_Lxcaches)) != NULL)
		cmd_Lxcache_free(hdl, cpu, Lxcache, FMD_B_FALSE);
}
char *
cmd_Lxcache_serdnm_create(fmd_hdl_t *hdl, uint32_t cpu_id,
			    cmd_ptrsubtype_t pstype,
			    uint32_t index, uint32_t way, uint16_t bit)
{
	const char *fmt = "cpu_%d:%s_%08d_%02d_%03d_serd";
	const char *serdbase;
	size_t sz;
	char	*nm;

	switch (pstype) {
		case CMD_PTR_CPU_L2DATA:
			serdbase = "l2data";
			break;
		case CMD_PTR_CPU_L3DATA:
			serdbase = "l3data";
			break;
		case CMD_PTR_CPU_L2TAG:
			serdbase = "l2tag";
			break;
		case CMD_PTR_CPU_L3TAG:
			serdbase = "l3tag";
			break;
		default:
			serdbase = "unknown";
			break;
	}
	sz = (snprintf(NULL, 0, fmt, cpu_id, serdbase, index, way, bit) + 1);
	nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	(void) snprintf(nm, sz, fmt, cpu_id, serdbase, index, way, bit);
	return (nm);
}

/*
 * Count the number of SERD type 2 ways retired for a given cpu
 * These are defined to be L3 Cache data retirements
 */

uint32_t
cmd_Lx_index_count_type2_ways(cmd_cpu_t *cpu)
{
	cmd_Lxcache_t *cache = NULL;
	uint32_t ret_count = 0;

	for (cache = cmd_list_next(&cpu->cpu_Lxcaches); cache != NULL;
	    cache = cmd_list_next(cache)) {
		if (((cache->Lxcache_reason == CMD_LXCONVICTED) ||
		    (cache->Lxcache_reason == CMD_LXSUSPICOUS)) &&
		    (cache->Lxcache_type == CMD_PTR_CPU_L3DATA)) {
			ret_count++;
		}
	}
	return (ret_count);
}
/*
 * Count the number of SERD type 1 ways retired for a given cpu
 * These are defined to be L2 Data, tag and L3 Tag retirements
 */

uint32_t
cmd_Lx_index_count_type1_ways(cmd_cpu_t *cpu)
{
	cmd_Lxcache_t *cache = NULL;
	uint32_t ret_count = 0;

	for (cache = cmd_list_next(&cpu->cpu_Lxcaches); cache != NULL;
	    cache = cmd_list_next(cache)) {
		if (((cache->Lxcache_reason == CMD_LXCONVICTED) ||
		    (cache->Lxcache_reason == CMD_LXSUSPICOUS)) &&
		    ((cache->Lxcache_type == CMD_PTR_CPU_L2DATA) ||
		    (cache->Lxcache_type == CMD_PTR_CPU_L2TAG) ||
		    (cache->Lxcache_type == CMD_PTR_CPU_L3TAG))) {
			ret_count++;
		}
	}
	return (ret_count);
}

void
cmd_fault_the_cpu(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype,
    const char *fltnm)
{
	fmd_case_t	*cp;
	const char 	*uuid;

	cp = cmd_case_create(hdl, &cpu->cpu_header, pstype,
	    &uuid);

	if ((errno = fmd_nvl_fmri_expand(hdl, cpu->cpu_asru_nvl)) != 0)
		fmd_hdl_abort(hdl, "failed to build CPU fmri");

	cmd_cpu_create_faultlist(hdl, cp, cpu, fltnm, NULL, 100);
	fmd_case_solve(hdl, cp);
}
void
cmd_Lxcache_fault(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_Lxcache_t *Lxcache,
	const char *type, nvlist_t *rsrc, uint_t cert)
{
	char fltnm[64];
	nvlist_t *flt;
	int cpu_retired_1, cpu_retired_2;

	(void) snprintf(fltnm, sizeof (fltnm), "fault.cpu.%s.%s-line",
	    cmd_cpu_type2name(hdl, cpu->cpu_type), type);

	if (Lxcache->Lxcache_flags & CMD_LxCACHE_F_FAULTING) {
		return;
	}
	Lxcache->Lxcache_flags |= CMD_LxCACHE_F_FAULTING;
	flt = fmd_nvl_create_fault(hdl, fltnm, cert,
	    Lxcache->Lxcache_asru.fmri_nvl, cpu->cpu_fru_nvl, rsrc);

	if (nvlist_add_boolean_value(flt, FM_SUSPECT_MESSAGE, B_FALSE) != 0)
		fmd_hdl_abort(hdl, "failed to add no-message member to fault");

	fmd_case_add_suspect(hdl, Lxcache->Lxcache_case.cc_cp, flt);
	fmd_case_solve(hdl, Lxcache->Lxcache_case.cc_cp);

	if (Lxcache->Lxcache_retired_fmri[0] == 0) {
		if (cmd_fmri_nvl2str(hdl, Lxcache->Lxcache_asru.fmri_nvl,
		    Lxcache->Lxcache_retired_fmri,
		    sizeof (Lxcache->Lxcache_retired_fmri)) == -1)
				fmd_hdl_debug(hdl,
				    "\n%s:cpu_id %d: Failed to save the"
				    " retired fmri string\n",
				    fltnm, cpu->cpu_cpuid);
		else
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d:Saved the retired fmri string %s\n",
			    fltnm, cpu->cpu_cpuid,
			    Lxcache->Lxcache_retired_fmri);
	}
	/* Retrieve the number of retired ways for each category */

	cpu_retired_1 = cmd_Lx_index_count_type1_ways(cpu);
	cpu_retired_2 = cmd_Lx_index_count_type2_ways(cpu);
	fmd_hdl_debug(hdl, "CPU %d retired Type 1 way count is: %d\n",
	    cpu->cpu_cpuid, cpu_retired_1);
	fmd_hdl_debug(hdl, "CPU %d retired Type 2 way count is: %d\n",
	    cpu->cpu_cpuid, cpu_retired_2);

	if ((cpu_retired_1 > CMD_CPU_SERD_AGG_1) ||
	    (cpu_retired_2 > CMD_CPU_SERD_AGG_2) &&
	    (cpu->cpu_faulting != FMD_B_TRUE)) {
		cmd_fault_the_cpu(hdl, cpu, Lxcache->Lxcache_type,
		    type);
	}
}
void
cmd_Lxcache_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_cpu_t *cpu;
	cmd_Lxcache_t *Lxcache;
	cmd_case_t *cc;

	Lxcache = (cmd_Lxcache_t *)arg;
	fmd_hdl_debug(hdl, "closing Lxcache for %s\n",
	    Lxcache->Lxcache_bufname);
	cc = &Lxcache->Lxcache_case;

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL;
	    cpu = cmd_list_next(cpu)) {
		if (strcmp(cpu->cpu_bufname,
		    Lxcache->Lxcache_cpu_bufname) == 0)
			break;
	}
	if (cpu == NULL)
		fmd_hdl_abort(hdl, "failed to find the cpu %s for %s\n",
		    Lxcache->Lxcache_cpu_bufname,
		    Lxcache->Lxcache_bufname);
	/*
	 * We will destroy the case and serd engine.
	 * The rest will be destroyed when we retire the CPU
	 * until then we keep the Lxcache strutures alive.
	 */

	if (cc->cc_cp != NULL) {
		cmd_case_fini(hdl, cc->cc_cp, FMD_B_TRUE);
		cc->cc_cp = NULL;
	}
	if (cc->cc_serdnm != NULL) {
		if (fmd_serd_exists(hdl, cc->cc_serdnm))
			fmd_serd_destroy(hdl, cc->cc_serdnm);
		fmd_hdl_strfree(hdl, cc->cc_serdnm);
		cc->cc_serdnm = NULL;
	}

}

void
cmd_Lxcache_gc(fmd_hdl_t *hdl)
{
	cmd_cpu_t *cpu;

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL;
	    cpu = cmd_list_next(cpu))
		cmd_Lxcache_validate(hdl, cpu);
}

cmd_evdisp_t
get_tagdata(cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype,
	    uint32_t index, uint64_t	*tag_data)
{
	int		fd;
	cache_info_t	cache_info;

	fd = open(mem_cache_device, O_RDONLY);
	if (fd == -1) {
		(void) printf(
		    "cpu_id = %d could not open %s to read tag info.\n",
		    cpu->cpu_cpuid, mem_cache_device);
		return (CMD_EVD_BAD);
	}
	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
		case CMD_PTR_CPU_L2DATA:
			cache_info.cache = L2_CACHE_TAG;
			break;
		case CMD_PTR_CPU_L3TAG:
		case CMD_PTR_CPU_L3DATA:
			cache_info.cache = L3_CACHE_TAG;
			break;
	}
	cache_info.cpu_id = cpu->cpu_cpuid;
	cache_info.index = index;
	cache_info.datap = tag_data;
	cache_info.way = 0;

	if (test_mode) {

		if (ioctl(fd, MEM_CACHE_READ_ERROR_INJECTED_TAGS, &cache_info)
		    == -1) {
			(void) printf("cpu_id = %d ioctl"
			    " MEM_CACHE_READ_ERROR_INJECTED_TAGS failed"
			    " errno = %d\n",
			    cpu->cpu_cpuid, errno);
			(void) close(fd);
			return (CMD_EVD_BAD);
		}
	} else {
		if (ioctl(fd, MEM_CACHE_READ_TAGS, &cache_info)
		    == -1) {
			(void) printf("cpu_id = %d ioctl"
			    " MEM_CACHE_READ_TAGS failed"
			    " errno = %d\n",
			    cpu->cpu_cpuid, errno);
			(void) close(fd);
			return (CMD_EVD_BAD);
		}
	}
	(void) close(fd);
	return (CMD_EVD_OK);
}


int
get_cpu_retired_ways(cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype)
{
	int		index, index_size, i, retired_ways, fd;
	uint64_t	tag_data[PN_CACHE_NWAYS];
	cache_info_t	cache_info;

	fd = open(mem_cache_device, O_RDWR);
	if (fd == -1) {
		(void) printf("Error in opening file %s,Errno = %d\n",
		    mem_cache_device, errno);
		return (-1);
	}

	cache_info.cpu_id = cpu->cpu_cpuid;
	switch (pstype) {
		case CMD_PTR_CPU_L2TAG:
		case CMD_PTR_CPU_L2DATA:
			index_size = (PN_L2_SET_SIZE/PN_L2_LINESIZE);
			cache_info.cache = L2_CACHE_TAG;
			break;
		case CMD_PTR_CPU_L3TAG:
		case CMD_PTR_CPU_L3DATA:
			index_size = (PN_L3_SET_SIZE/PN_L3_LINESIZE);
			cache_info.cache = L3_CACHE_TAG;
			break;
	}
	retired_ways = 0;

	for (index = 0; index < index_size; index++) {
		cache_info.index = index;
		cache_info.way = 0;
		cache_info.datap = &tag_data;
		if (ioctl(fd, MEM_CACHE_READ_TAGS, &cache_info) == -1) {
			(void) printf("index = %d :", index);
			perror("ioctl MEM_CACHE_READ_TAGS failed\n");
			return (-1);
		}
		for (i = 0; i < PN_CACHE_NWAYS; i++) {
			if ((tag_data[i] & CH_ECSTATE_MASK) ==
			    PN_ECSTATE_NA)
				retired_ways++;
		}
	}
	return (retired_ways);
}

int
get_index_retired_ways(cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype, uint32_t index)
{
	int		i, retired_ways;
	uint64_t	tag_data[PN_CACHE_NWAYS];

	if (get_tagdata(cpu, pstype, index, tag_data) != 0) {
		return (-1);
	}
	retired_ways = 0;
	for (i = 0; i < PN_CACHE_NWAYS; i++) {
		if ((tag_data[i] & CH_ECSTATE_MASK) ==
		    PN_ECSTATE_NA)
			retired_ways++;
	}
	return (retired_ways);
}

int
is_index_way_retired(cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype, uint32_t index,
    uint32_t way)
{
	uint64_t	tag_data[PN_CACHE_NWAYS];

	if (get_tagdata(cpu, pstype, index, tag_data) != 0) {
		return (-1);
	}
	if ((tag_data[way] & CH_ECSTATE_MASK) == PN_ECSTATE_NA)
		return (1);
	return (0);
}
int
cmd_cache_way_retire(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_Lxcache_t *Lxcache)
{
	char		*fltnm;
	cache_info_t    cache_info;
	int ret, fd;

	fltnm = cmd_type_to_str(Lxcache->Lxcache_type);
	fd = open(mem_cache_device, O_RDWR);
	if (fd == -1) {
		fmd_hdl_debug(hdl,
		    "fltnm:cpu_id %d open of %s failed\n",
		    fltnm, cpu->cpu_cpuid, mem_cache_device);
		return (B_FALSE);
	}
	cache_info.cpu_id = cpu->cpu_cpuid;
	cache_info.way = Lxcache->Lxcache_way;
	cache_info.bit = Lxcache->Lxcache_bit;
	cache_info.index = Lxcache->Lxcache_index;

	switch (Lxcache->Lxcache_type) {
		case CMD_PTR_CPU_L2TAG:
			cache_info.cache = L2_CACHE_TAG;
			break;
		case CMD_PTR_CPU_L2DATA:
			cache_info.cache = L2_CACHE_DATA;
			break;
		case CMD_PTR_CPU_L3TAG:
			cache_info.cache = L3_CACHE_TAG;
			break;
		case CMD_PTR_CPU_L3DATA:
			cache_info.cache = L3_CACHE_DATA;
			break;
	}

	fmd_hdl_debug(hdl,
	    "\n%s:cpu %d: Retiring index %d, way %d bit %d\n",
	    fltnm, cpu->cpu_cpuid, cache_info.index, cache_info.way,
	    (int16_t)cache_info.bit);
	ret = ioctl(fd, MEM_CACHE_RETIRE, &cache_info);
	(void) close(fd);
	if (ret == -1) {
		fmd_hdl_debug(hdl,
		    "fltnm:cpu_id %d MEM_CACHE_RETIRE ioctl failed\n",
		    fltnm, cpu->cpu_cpuid);
		return (B_FALSE);
	}

	return (B_TRUE);
}

boolean_t
cmd_cache_way_unretire(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_Lxcache_t *Lxcache)
{
	char		*fltnm;
	cache_info_t    cache_info;
	int ret, fd;

	fltnm = cmd_type_to_str(Lxcache->Lxcache_type);
	fd = open(mem_cache_device, O_RDWR);
	if (fd == -1) {
		fmd_hdl_debug(hdl,
		    "fltnm:cpu_id %d open of %s failed\n",
		    fltnm, cpu->cpu_cpuid, mem_cache_device);
		return (B_FALSE);
	}
	cache_info.cpu_id = cpu->cpu_cpuid;
	cache_info.way = Lxcache->Lxcache_way;
	cache_info.bit = Lxcache->Lxcache_bit;
	cache_info.index = Lxcache->Lxcache_index;

	switch (Lxcache->Lxcache_type) {
		case CMD_PTR_CPU_L2TAG:
			cache_info.cache = L2_CACHE_TAG;
			break;
		case CMD_PTR_CPU_L2DATA:
			cache_info.cache = L2_CACHE_DATA;
			break;
		case CMD_PTR_CPU_L3TAG:
			cache_info.cache = L3_CACHE_TAG;
			break;
		case CMD_PTR_CPU_L3DATA:
			cache_info.cache = L3_CACHE_DATA;
			break;
	}

	fmd_hdl_debug(hdl,
	    "\n%s:cpu %d: Unretiring index %d, way %d bit %d\n",
	    fltnm, cpu->cpu_cpuid, cache_info.index, cache_info.way,
	    (int16_t)cache_info.bit);
	ret = ioctl(fd, MEM_CACHE_UNRETIRE, &cache_info);
	(void) close(fd);
	if (ret == -1) {
		fmd_hdl_debug(hdl,
		    "fltnm:cpu_id %d MEM_CACHE_UNRETIRE ioctl failed\n",
		    fltnm, cpu->cpu_cpuid);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static cmd_Lxcache_t *
cmd_Lxcache_lookup_by_type_index_way_flags(cmd_cpu_t *cpu,
    cmd_ptrsubtype_t type, uint32_t index, int8_t way, int32_t flags)
{
	cmd_Lxcache_t *cmd_Lxcache;

	for (cmd_Lxcache = cmd_list_next(&cpu->cpu_Lxcaches);
	    cmd_Lxcache != NULL;
	    cmd_Lxcache = cmd_list_next(cmd_Lxcache)) {
		if ((cmd_Lxcache->Lxcache_index == index) &&
		    (cmd_Lxcache->Lxcache_way == way) &&
		    (cmd_Lxcache->Lxcache_type == type) &&
		    (cmd_Lxcache->Lxcache_flags & flags))
			return (cmd_Lxcache);
	}
	return (NULL);
}
boolean_t
cmd_Lxcache_unretire(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_Lxcache_t *cmd_Lxcache,
    const char *fltnm)
{
	cmd_ptrsubtype_t data_type;
	cmd_Lxcache_t *retired_Lxcache;

	/*
	 * If we are unretiring a cacheline retired due to suspected TAG
	 * fault, then we must first check if we are using a cacheline
	 * that was retired earlier for DATA fault.
	 * If so we will not unretire the cacheline.
	 * We will change the flags to reflect the current condition.
	 * We will return success, though.
	 */
	if ((cmd_Lxcache->Lxcache_type == CMD_PTR_CPU_L2TAG) ||
	    (cmd_Lxcache->Lxcache_type == CMD_PTR_CPU_L3TAG)) {
		if (cmd_Lxcache->Lxcache_type == CMD_PTR_CPU_L2TAG)
			data_type = CMD_PTR_CPU_L2DATA;
		if (cmd_Lxcache->Lxcache_type == CMD_PTR_CPU_L3TAG)
			data_type = CMD_PTR_CPU_L3DATA;
		fmd_hdl_debug(hdl,
		    "\n%s:cpuid %d checking if there is a %s"
		    " cacheline re-retired at this index %d and way %d\n",
		    fltnm, cpu->cpu_cpuid, cmd_type_to_str(data_type),
		    cmd_Lxcache->Lxcache_index, cmd_Lxcache->Lxcache_way);
		retired_Lxcache = cmd_Lxcache_lookup_by_type_index_way_flags(
		    cpu, data_type, cmd_Lxcache->Lxcache_index,
		    cmd_Lxcache->Lxcache_way, CMD_LxCACHE_F_RERETIRED);
		if (retired_Lxcache) {
			retired_Lxcache->Lxcache_flags = CMD_LxCACHE_F_RETIRED;
			cmd_Lxcache->Lxcache_flags = CMD_LxCACHE_F_UNRETIRED;
			return (B_TRUE);
		}
	}
	if (cmd_cache_way_unretire(hdl, cpu, cmd_Lxcache) == B_FALSE)
		return (B_FALSE);
	cmd_Lxcache->Lxcache_flags = CMD_LxCACHE_F_UNRETIRED;
	/*
	 * We have unretired the cacheline. We need to inform the fmd
	 * that we have repaired the faulty fmri that we retired earlier.
	 * The cpumem agent will not unretire cacheline in response to
	 * the list.repair events it receives.
	 */
	if (cmd_Lxcache->Lxcache_retired_fmri[0] != 0) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpuid %d Repairing the retired fmri %s",
		    fltnm, cpu->cpu_cpuid,
		    cmd_Lxcache->Lxcache_retired_fmri);
			if (cmd_repair_fmri(hdl,
			    cmd_Lxcache->Lxcache_retired_fmri) != 0) {
				fmd_hdl_debug(hdl,
				    "\n%s:cpuid %d Failed to repair"
				    " retired fmri.",
				    fltnm, cpu->cpu_cpuid);
			/*
			 * We need to retire the cacheline that we just
			 * unretired.
			 */
			if (cmd_cache_way_retire(hdl, cpu, cmd_Lxcache)
			    == B_FALSE) {
				/*
				 * A hopeless situation.
				 * cannot maintain consistency of cacheline
				 * sate between fmd and DE.
				 * Aborting the DE.
				 */
				fmd_hdl_abort(hdl,
				    "\n%s:cpuid %d We are unable to repair"
				    " the fmri we just unretired and are"
				    " unable to restore the DE and fmd to"
				    " a sane state.\n",
				    fltnm, cpu->cpu_cpuid);
			}
			return (B_FALSE);
		} else {
			cmd_Lxcache->Lxcache_retired_fmri[0] = 0;
		}
	}
	return (B_TRUE);
}
