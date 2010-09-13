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

#define	PN_ECSTATE_NA	5
/*
 * These values are our threshold values for SERDing CPU's based on the
 * the # of times we have retired a cache line for each category.
 */

#define	CMD_CPU_SERD_AGG_1  	64
#define	CMD_CPU_SERD_AGG_2	64

static int8_t cmd_lowest_way[16] = {
/*	0x0 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8 0x9 0xa 0xb 0xc 0xd 0xe 0xf */
	-1,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0};
static int cmd_num_of_bits[16] = {
/*	0x0 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8 0x9 0xa 0xb 0xc 0xd 0xe 0xf */
	0,  1,  1,  2,  1,  2,  2,  3,  1,  2,  2,  3,  2,  3,  3,  4};


void
cmd_Lxcache_write(fmd_hdl_t *hdl, cmd_Lxcache_t *Lxcache)
{
	fmd_buf_write(hdl, NULL, Lxcache->Lxcache_bufname, Lxcache,
	    sizeof (cmd_Lxcache_pers_t));
}

const char *
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

const char *
cmd_flags_to_str(int flags)
{
	switch (flags) {
		case CMD_LxCACHE_F_ACTIVE:
			return ("ACTIVE");
		case CMD_LxCACHE_F_FAULTING:
			return ("FAULTING");
		case CMD_LxCACHE_F_RETIRED:
			return ("RETIRED");
		case CMD_LxCACHE_F_UNRETIRED:
			return ("UNRETIRED");
		case CMD_LxCACHE_F_RERETIRED:
			return ("RERETIRED");
		default:
			return ("Unknown_flags");
	}
}

const char *
cmd_reason_to_str(int reason)
{
	switch (reason) {
		case CMD_LXSUSPECT_DATA:
			return ("SUSPECT_DATA");
		case CMD_LXSUSPECT_0_TAG:
			return ("SUSPECT_0_TAG");
		case CMD_LXSUSPECT_1_TAG:
			return ("SUSPECT_1_TAG");
		case CMD_LXCONVICTED:
			return ("CONVICTED");
		case CMD_LXFUNCTIONING:
			return ("FUNCTIONING");
		default:
			return ("Unknown_reason");
	}
}

static void
cmd_pretty_print_Lxcache(fmd_hdl_t *hdl, cmd_Lxcache_t *Lxcache)
{
	fmd_hdl_debug(hdl,
	    "\n"
	    "	cpu	= %s\n"
	    "	type	= %s\n"
	    "	index	= %d\n"
	    "	way	= %d\n"
	    "	bit	= %d\n"
	    "	reason	= %s\n"
	    "	flags	= %s\n",
	    Lxcache->Lxcache_cpu_bufname,
	    cmd_type_to_str(Lxcache->Lxcache_type),
	    Lxcache->Lxcache_index,
	    Lxcache->Lxcache_way,
	    Lxcache->Lxcache_bit,
	    cmd_reason_to_str(Lxcache->Lxcache_reason),
	    cmd_flags_to_str(Lxcache->Lxcache_flags));
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
	if (Lxcache->Lxcache_nvl) {
		nvlist_free(Lxcache->Lxcache_nvl);
		Lxcache->Lxcache_nvl = NULL;
	}
	/*
	 * Clean up the SERD engine created to handle recheck of TAGS.
	 * This SERD engine was created to save the event pointer.
	 */
	if (Lxcache->Lxcache_serdnm != NULL) {
		if (fmd_serd_exists(hdl, Lxcache->Lxcache_serdnm) && destroy) {
			fmd_serd_destroy(hdl, Lxcache->Lxcache_serdnm);
			fmd_hdl_strfree(hdl, Lxcache->Lxcache_serdnm);
			Lxcache->Lxcache_serdnm = NULL;
		}
	}
	Lxcache->Lxcache_timeout_id = -1;
	Lxcache->Lxcache_ep = NULL;
	Lxcache->Lxcache_retry_count = 0;
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

cmd_Lxcache_t *
cmd_Lxcache_lookup_by_type_index_way_bit(cmd_cpu_t *cpu,
    cmd_ptrsubtype_t pstype, int32_t index, int8_t way, int16_t bit)
{
	cmd_Lxcache_t *Lxcache;

	for (Lxcache = cmd_list_next(&cpu->cpu_Lxcaches); Lxcache != NULL;
	    Lxcache = cmd_list_next(Lxcache)) {
		if ((Lxcache->Lxcache_type == pstype) &&
		    (Lxcache->Lxcache_index == (uint32_t)index) &&
		    (Lxcache->Lxcache_way == (uint32_t)way) &&
		    (Lxcache->Lxcache_bit == (uint16_t)bit))
			return (Lxcache);
	}

	return (NULL);
}

cmd_Lxcache_t *
cmd_Lxcache_create(fmd_hdl_t *hdl, cmd_xr_t *xr, cmd_cpu_t *cpu,
    nvlist_t *modasru, cmd_ptrsubtype_t pstype, int32_t index,
    int8_t way, int16_t bit)
{
	cmd_Lxcache_t *Lxcache;
	nvlist_t *asru;
	const char	*pstype_name;
	uint8_t	fmri_Lxcache_type;

	pstype_name = cmd_type_to_str(pstype);
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d:Creating new Lxcache for index=%d way=%d bit=%d\n",
	    pstype_name, cpu->cpu_cpuid, index, way, bit);

	CMD_CPU_STAT_BUMP(cpu, Lxcache_creat);

	Lxcache = fmd_hdl_zalloc(hdl, sizeof (cmd_Lxcache_t), FMD_SLEEP);
	(void) strncpy(Lxcache->Lxcache_cpu_bufname,
	    cpu->cpu_bufname, CMD_BUFNMLEN);
	Lxcache->Lxcache_nodetype = CMD_NT_LxCACHE;
	Lxcache->Lxcache_version = CMD_LxCACHE_VERSION;
	Lxcache->Lxcache_type = pstype;
	Lxcache->Lxcache_index = (uint32_t)index;
	Lxcache->Lxcache_way = (uint32_t)way;
	Lxcache->Lxcache_bit = (uint16_t)bit;
	Lxcache->Lxcache_reason = CMD_LXFUNCTIONING;
	Lxcache->Lxcache_flags = CMD_LxCACHE_F_ACTIVE;
	Lxcache->Lxcache_timeout_id = -1;
	Lxcache->Lxcache_retry_count = 0;
	Lxcache->Lxcache_nvl = NULL;
	Lxcache->Lxcache_ep = NULL;
	Lxcache->Lxcache_serdnm = NULL;
	Lxcache->Lxcache_clcode = 0;
	Lxcache->xr = xr;
	Lxcache->Lxcache_retired_fmri[0] = '\0';
	switch (pstype) {
		case CMD_PTR_CPU_L2DATA:
			fmri_Lxcache_type = FM_FMRI_CPU_CACHE_TYPE_L2;
			break;
		case CMD_PTR_CPU_L3DATA:
			fmri_Lxcache_type = FM_FMRI_CPU_CACHE_TYPE_L3;
			break;
		case CMD_PTR_CPU_L2TAG:
			fmri_Lxcache_type = FM_FMRI_CPU_CACHE_TYPE_L2;
			break;
		case CMD_PTR_CPU_L3TAG:
			fmri_Lxcache_type = FM_FMRI_CPU_CACHE_TYPE_L3;
			break;
		default:
			break;
	}

	cmd_bufname(Lxcache->Lxcache_bufname, sizeof (Lxcache->Lxcache_bufname),
	    "Lxcache_%s_%d_%d_%d_%d", pstype_name, cpu->cpu_cpuid,
	    index, way, bit);
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d: new Lxcache name is %s\n",
	    pstype_name, cpu->cpu_cpuid, Lxcache->Lxcache_bufname);
	if ((errno = nvlist_dup(modasru, &asru, 0)) != 0 ||
	    (errno = nvlist_add_uint32(asru, FM_FMRI_CPU_CACHE_INDEX,
	    index)) != 0 ||
	    (errno = nvlist_add_uint32(asru, FM_FMRI_CPU_CACHE_WAY,
	    (uint32_t)way)) != 0 ||
	    (errno = nvlist_add_uint16(asru, FM_FMRI_CPU_CACHE_BIT,
	    bit)) != 0 ||
	    (errno = nvlist_add_uint8(asru, FM_FMRI_CPU_CACHE_TYPE,
	    fmri_Lxcache_type)) != 0 ||
	    (errno = fmd_nvl_fmri_expand(hdl, asru)) != 0)
		fmd_hdl_abort(hdl, "failed to build Lxcache fmri");
	asru->nvl_nvflag |= NV_UNIQUE_NAME_TYPE;

	cmd_fmri_init(hdl, &Lxcache->Lxcache_asru, asru,
	    "%s_asru_%d_%d_%d", pstype_name, index, way, bit);

	nvlist_free(asru);

	cmd_list_append(&cpu->cpu_Lxcaches, Lxcache);
	cmd_Lxcache_write(hdl, Lxcache);

	return (Lxcache);
}

cmd_Lxcache_t *
cmd_Lxcache_lookup_by_index_way(cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype,
    int32_t index, int8_t way)
{
	cmd_Lxcache_t *cache;

	for (cache = cmd_list_next(&cpu->cpu_Lxcaches); cache != NULL;
	    cache = cmd_list_next(cache)) {
	if ((cache->Lxcache_index == (uint32_t)index) &&
	    (cache->Lxcache_way == (uint32_t)way) &&
	    (cache->Lxcache_type == pstype)) {
		return (cache);
		}
	}

	return (NULL);
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
	 * After we identify the cpu list using buf name we look
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
	cmd_pretty_print_Lxcache(hdl, Lxcache);

	fmd_hdl_debug(hdl, "found %d in version field\n",
	    Lxcache->Lxcache_version);
	cpu = cmd_restore_cpu_only(hdl, cp, Lxcache->Lxcache_cpu_bufname);
	if (cpu == NULL) {
		fmd_hdl_debug(hdl,
		    "\nCould not restore cpu %s\n",
		    Lxcache->Lxcache_cpu_bufname);
		return (NULL);
	}
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
		/*
		 * We need to cleanup the information associated with
		 * the timeout routine because these are not checkpointed
		 * and cannot be retored.
		 */
		Lxcache->Lxcache_timeout_id = -1;
		Lxcache->Lxcache_retry_count = 0;
		Lxcache->Lxcache_nvl = NULL;
		Lxcache->Lxcache_ep = NULL;
		Lxcache->Lxcache_serdnm = NULL;

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
			    int32_t index, int8_t way, int16_t bit)
{
	const char *fmt = "cpu_%d:%s_%d_%d_%d_serd";
	const char *serdbase;
	size_t sz;
	char	*nm;

	serdbase = cmd_type_to_str(pstype);
	sz = (snprintf(NULL, 0, fmt, cpu_id, serdbase, index, way, bit) + 1);
	nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	(void) snprintf(nm, sz, fmt, cpu_id, serdbase, index, way, bit);
	return (nm);
}

char *
cmd_Lxcache_anonymous_serdnm_create(fmd_hdl_t *hdl, uint32_t cpu_id,
			    cmd_ptrsubtype_t pstype,
			    int32_t index, int8_t way, int16_t bit)
{
	const char *fmt = "cpu_%d:%s_%d_%d_%d_anonymous_serd";
	const char *serdbase;
	size_t sz;
	char	*nm;

	serdbase = cmd_type_to_str(pstype);
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
		if ((cache->Lxcache_flags & CMD_LxCACHE_F_RETIRED) &&
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
		if ((cache->Lxcache_flags & CMD_LxCACHE_F_RETIRED) &&
		    ((cache->Lxcache_type == CMD_PTR_CPU_L2DATA) ||
		    IS_TAG(cache->Lxcache_type))) {
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
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d Created case %s to retire CPU\n",
	    fltnm, cpu->cpu_cpuid);

	if ((errno = fmd_nvl_fmri_expand(hdl, cpu->cpu_asru_nvl)) != 0)
		fmd_hdl_abort(hdl, "failed to build CPU fmri");

	cmd_cpu_create_faultlist(hdl, cp, cpu, fltnm, NULL, HUNDRED_PERCENT);
	fmd_case_solve(hdl, cp);
}

void
cmd_retire_cpu_if_limits_exceeded(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
    cmd_ptrsubtype_t pstype, const char *fltnm)
{
	int cpu_retired_1, cpu_retired_2;

	/* Retrieve the number of retired ways for each category */

	cpu_retired_1 = cmd_Lx_index_count_type1_ways(cpu);
	cpu_retired_2 = cmd_Lx_index_count_type2_ways(cpu);
	fmd_hdl_debug(hdl,
	    "\n%s:CPU %d retired Type 1 way count is: %d\n",
	    fltnm, cpu->cpu_cpuid, cpu_retired_1);
	fmd_hdl_debug(hdl, "\n%s:CPU %d retired Type 2 way count is: %d\n",
	    fltnm, cpu->cpu_cpuid, cpu_retired_2);

	if (((cpu_retired_1 > CMD_CPU_SERD_AGG_1) ||
	    (cpu_retired_2 > CMD_CPU_SERD_AGG_2)) &&
	    (cpu->cpu_faulting != FMD_B_TRUE)) {
		cmd_fault_the_cpu(hdl, cpu, pstype, fltnm);
	}
}

void
cmd_Lxcache_fault(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_Lxcache_t *Lxcache,
	const char *fltnm, nvlist_t *rsrc, uint_t cert)
{
	char fltmsg[64];
	nvlist_t *flt;

	(void) snprintf(fltmsg, sizeof (fltmsg), "fault.cpu.%s.%s-line",
	    cmd_cpu_type2name(hdl, cpu->cpu_type), fltnm);
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d: fltmsg = %s\n",
	    fltnm, cpu->cpu_cpuid, fltmsg);
	if (Lxcache->Lxcache_flags & CMD_LxCACHE_F_FAULTING) {
		return;
	}
	Lxcache->Lxcache_flags |= CMD_LxCACHE_F_FAULTING;
	flt = fmd_nvl_create_fault(hdl, fltmsg, cert,
	    Lxcache->Lxcache_asru.fmri_nvl, cpu->cpu_fru_nvl, rsrc);
	if (nvlist_add_boolean_value(flt, FM_SUSPECT_MESSAGE, B_FALSE) != 0)
		fmd_hdl_abort(hdl, "failed to add no-message member to fault");

	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d: adding suspect list to case %s\n",
	    fltnm, cpu->cpu_cpuid,
	    fmd_case_uuid(hdl, Lxcache->Lxcache_case.cc_cp));
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
	Lxcache->Lxcache_flags &= ~(CMD_LxCACHE_F_FAULTING);

}

void
cmd_Lxcache_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_cpu_t *cpu;
	cmd_Lxcache_t *Lxcache;
	cmd_case_t *cc;

	Lxcache = (cmd_Lxcache_t *)arg;
	fmd_hdl_debug(hdl, "cmd_Lxcache_close called  for %s\n",
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

cmd_Lxcache_t *
cmd_Lxcache_lookup_by_timeout_id(id_t id)
{
	cmd_cpu_t *cpu;
	cmd_Lxcache_t *cmd_Lxcache;

	for (cpu = cmd_list_next(&cmd.cmd_cpus); cpu != NULL;
	    cpu = cmd_list_next(cpu)) {
		for (cmd_Lxcache = cmd_list_next(&cpu->cpu_Lxcaches);
		    cmd_Lxcache != NULL;
		    cmd_Lxcache = cmd_list_next(cmd_Lxcache)) {
			if (cmd_Lxcache->Lxcache_timeout_id == id)
				return (cmd_Lxcache);
		}
	}
	return (NULL);
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
	    int32_t index, uint64_t	*tag_data)
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
get_index_retired_ways(cmd_cpu_t *cpu, cmd_ptrsubtype_t pstype, int32_t index)
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

boolean_t
cmd_cache_way_retire(fmd_hdl_t *hdl, cmd_cpu_t *cpu, cmd_Lxcache_t *Lxcache)
{
	const char		*fltnm;
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
	const char		*fltnm;
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
    cmd_ptrsubtype_t type, int32_t index, int8_t way, int32_t flags)
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

static int8_t
cmd_Lxcache_get_bit_array_of_available_ways(cmd_cpu_t *cpu,
    cmd_ptrsubtype_t type, int32_t index)
{
	uint8_t bit_array_of_unavailable_ways;
	uint8_t bit_array_of_available_ways;
	cmd_ptrsubtype_t match_type;
	cmd_Lxcache_t *cmd_Lxcache;
	uint8_t bit_array_of_retired_ways;


	/*
	 * We scan the Lxcache structures for this CPU and collect
	 * the following 2 information.
	 * - bit_array_of_retired_ways
	 * - bit_array_of_unavailable_ways
	 * If type is Lx_TAG then unavailable_ways will not include ways that
	 * were retired due to DATA faults, because these ways can still be
	 * re-retired for TAG faults.
	 * If 3 ways have been retired then we protect the only remaining
	 * unretired way by marking it as unavailable.
	 */
	bit_array_of_unavailable_ways = 0;
	bit_array_of_retired_ways = 0;
	switch (type) {
		case CMD_PTR_CPU_L2TAG:
			match_type = CMD_PTR_CPU_L2DATA;
			break;
		case CMD_PTR_CPU_L2DATA:
			match_type = CMD_PTR_CPU_L2TAG;
			break;
		case CMD_PTR_CPU_L3TAG:
			match_type = CMD_PTR_CPU_L3DATA;
			break;
		case CMD_PTR_CPU_L3DATA:
			match_type = CMD_PTR_CPU_L3TAG;
			break;
	}

	for (cmd_Lxcache = cmd_list_next(&cpu->cpu_Lxcaches);
	    cmd_Lxcache != NULL;
	    cmd_Lxcache = cmd_list_next(cmd_Lxcache)) {
		if ((cmd_Lxcache->Lxcache_index == index) &&
		    ((cmd_Lxcache->Lxcache_type == type) ||
		    (cmd_Lxcache->Lxcache_type == match_type)) &&
		    (cmd_Lxcache->Lxcache_flags &
		    (CMD_LxCACHE_F_RETIRED | CMD_LxCACHE_F_RERETIRED))) {
			bit_array_of_retired_ways |=
			    (1 << cmd_Lxcache->Lxcache_way);
			/*
			 * If we are calling this while handling TAG errors
			 * we can reretire the cachelines retired due to DATA
			 * errors. We will ignore the cachelnes that are
			 * retired due to DATA faults.
			 */
			if ((type == CMD_PTR_CPU_L2TAG) &&
			    (cmd_Lxcache->Lxcache_type == CMD_PTR_CPU_L2DATA))
				continue;
			if ((type == CMD_PTR_CPU_L3TAG) &&
			    (cmd_Lxcache->Lxcache_type == CMD_PTR_CPU_L3DATA))
				continue;
			bit_array_of_unavailable_ways |=
			    (1 << cmd_Lxcache->Lxcache_way);
		}
	}
	if (cmd_num_of_bits[bit_array_of_retired_ways & 0xf] == 3) {
		/*
		 * special case: 3 ways are already retired.
		 * The Lone unretired way is set as 1, rest are set as 0.
		 * We now OR this with bit_array_of_unavailable_ways
		 * so that this unretired way will not be allocated.
		 */
		bit_array_of_retired_ways ^= 0xf;
		bit_array_of_retired_ways &= 0xf;
		bit_array_of_unavailable_ways |= bit_array_of_retired_ways;
	}
	bit_array_of_available_ways =
	    ((bit_array_of_unavailable_ways ^ 0xf) & 0xf);
	return (bit_array_of_available_ways);
}


/*
 * Look for a way next to the specified way that is
 * not in a retired state.
 * We stop when way 3 is reached.
 */
int8_t
cmd_Lxcache_get_next_retirable_way(cmd_cpu_t *cpu,
    int32_t index, cmd_ptrsubtype_t pstype, int8_t specified_way)
{
	uint8_t bit_array_of_ways;
	int8_t mask;

	if (specified_way == 3)
		return (-1);
	bit_array_of_ways = cmd_Lxcache_get_bit_array_of_available_ways(
	    cpu,
	    pstype, index);
	if (specified_way == 2)
		mask = 0x8;
	else if (specified_way == 1)
		mask = 0xc;
	else
		mask = 0xe;
	return (cmd_lowest_way[bit_array_of_ways & mask]);
}

int8_t
cmd_Lxcache_get_lowest_retirable_way(cmd_cpu_t *cpu,
    int32_t index, cmd_ptrsubtype_t pstype)
{
	uint8_t bit_array_of_ways;

	bit_array_of_ways = cmd_Lxcache_get_bit_array_of_available_ways(
	    cpu,
	    pstype, index);
	return (cmd_lowest_way[bit_array_of_ways]);
}

cmd_Lxcache_t *
cmd_Lxcache_lookup_by_type_index_way_reason(cmd_cpu_t *cpu,
    cmd_ptrsubtype_t pstype, int32_t index, int8_t way, int32_t reason)
{
	cmd_Lxcache_t *cmd_Lxcache;

	for (cmd_Lxcache = cmd_list_next(&cpu->cpu_Lxcaches);
	    cmd_Lxcache != NULL;
	    cmd_Lxcache = cmd_list_next(cmd_Lxcache)) {
		if ((cmd_Lxcache->Lxcache_index == (uint32_t)index) &&
		    (cmd_Lxcache->Lxcache_way == (uint32_t)way) &&
		    (cmd_Lxcache->Lxcache_reason & reason) &&
		    (cmd_Lxcache->Lxcache_type == pstype)) {
			return (cmd_Lxcache);
		}
	}
	return (NULL);
}

cmd_Lxcache_t *
cmd_Lxcache_lookup_by_type_index_bit_reason(cmd_cpu_t *cpu,
    cmd_ptrsubtype_t pstype, int32_t index, int16_t bit, int32_t reason)
{
	cmd_Lxcache_t *cmd_Lxcache;

	for (cmd_Lxcache = cmd_list_next(&cpu->cpu_Lxcaches);
	    cmd_Lxcache != NULL;
	    cmd_Lxcache = cmd_list_next(cmd_Lxcache)) {
		if ((cmd_Lxcache->Lxcache_index == (uint32_t)index) &&
		    (cmd_Lxcache->Lxcache_bit == (uint16_t)bit) &&
		    (cmd_Lxcache->Lxcache_reason & reason) &&
		    (cmd_Lxcache->Lxcache_type == pstype)) {
			return (cmd_Lxcache);
		}
	}
	return (NULL);
}

void
cmd_Lxcache_destroy_anonymous_serd_engines(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
    cmd_ptrsubtype_t type, int32_t index, int16_t bit)
{
	cmd_Lxcache_t *cmd_Lxcache;
	cmd_case_t *cc;

	for (cmd_Lxcache = cmd_list_next(&cpu->cpu_Lxcaches);
	    cmd_Lxcache != NULL;
	    cmd_Lxcache = cmd_list_next(cmd_Lxcache)) {
		if ((cmd_Lxcache->Lxcache_type == type) &&
		    (cmd_Lxcache->Lxcache_index == (uint32_t)index) &&
		    (cmd_Lxcache->Lxcache_bit == (uint16_t)bit) &&
		    (cmd_Lxcache->Lxcache_way == (uint32_t)CMD_ANON_WAY)) {
			cc = &cmd_Lxcache->Lxcache_case;
			if (cc == NULL)
				continue;
			if (cc->cc_serdnm != NULL) {
				if (fmd_serd_exists(hdl, cc->cc_serdnm)) {
					fmd_hdl_debug(hdl,
					    "\n%s:cpu_id %d destroying SERD"
					    " engine %s\n",
					    cmd_type_to_str(type),
					    cpu->cpu_cpuid, cc->cc_serdnm);
					fmd_serd_destroy(hdl, cc->cc_serdnm);
				}
				fmd_hdl_strfree(hdl, cc->cc_serdnm);
				cc->cc_serdnm = NULL;
			}
		}
	}
}

ssize_t
cmd_fmri_nvl2str(fmd_hdl_t *hdl, nvlist_t *nvl, char *buf, size_t buflen)
{
	uint8_t type;
	uint32_t cpuid, way;
	uint32_t	index;
	uint16_t	bit;
	char *serstr = NULL;
	char	missing_list[128];

	missing_list[0] = 0;
	if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_ID, &cpuid) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_ID);
	if (nvlist_lookup_string(nvl, FM_FMRI_CPU_SERIAL_ID, &serstr) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_SERIAL_ID);
	if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_CACHE_INDEX, &index) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_CACHE_INDEX);
	if (nvlist_lookup_uint32(nvl, FM_FMRI_CPU_CACHE_WAY, &way) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_CACHE_WAY);
	if (nvlist_lookup_uint16(nvl, FM_FMRI_CPU_CACHE_BIT, &bit) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_CACHE_BIT);
	if (nvlist_lookup_uint8(nvl, FM_FMRI_CPU_CACHE_TYPE, &type) != 0)
		(void) strcat(missing_list, FM_FMRI_CPU_CACHE_TYPE);

	if (strlen(missing_list) != 0) {
		fmd_hdl_debug(hdl,
		    "\ncmd_fmri_nvl2str: missing %s in fmri\n",
		    missing_list);
		return (-1);
	}

	return (snprintf(buf, buflen,
	    "cpu:///%s=%u/%s=%s/%s=%u/%s=%u/%s=%d/%s=%d",
	    FM_FMRI_CPU_ID, cpuid,
	    FM_FMRI_CPU_SERIAL_ID, serstr,
	    FM_FMRI_CPU_CACHE_INDEX, index,
	    FM_FMRI_CPU_CACHE_WAY, way,
	    FM_FMRI_CPU_CACHE_BIT, bit,
	    FM_FMRI_CPU_CACHE_TYPE, type));
}

boolean_t
cmd_create_case_for_Lxcache(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
    cmd_Lxcache_t *cmd_Lxcache)
{
	const char *fltnm;
	const char *uuid;

	if (cmd_Lxcache->Lxcache_case.cc_cp != NULL)
		return (B_TRUE);
	cmd_Lxcache->Lxcache_case.cc_cp = cmd_case_create(hdl,
	    &cmd_Lxcache->Lxcache_header, CMD_PTR_LxCACHE_CASE,
	    &uuid);
	fltnm = cmd_type_to_str(cmd_Lxcache->Lxcache_type);
	if (cmd_Lxcache->Lxcache_case.cc_cp == NULL) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d:Failed to create a case for"
		    " index %d way %d bit %d\n",
		    fltnm, cpu->cpu_cpuid,
		    cmd_Lxcache->Lxcache_index,
		    cmd_Lxcache->Lxcache_way, cmd_Lxcache->Lxcache_bit);
		return (B_FALSE);
	}
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d: New case %s created.\n",
	    fltnm, cpu->cpu_cpuid, uuid);
	if (cmd_Lxcache->Lxcache_ep)
		fmd_case_add_ereport(hdl, cmd_Lxcache->Lxcache_case.cc_cp,
		    cmd_Lxcache->Lxcache_ep);
	return (B_TRUE);
}

static int
cmd_repair_fmri(fmd_hdl_t *hdl, char *buf)
{
	int err;

	err = fmd_repair_asru(hdl, buf);
	if (err) {
		fmd_hdl_debug(hdl,
		    "Failed to repair %s err = %d\n", buf, err);
	}
	return (err);
}

boolean_t
cmd_Lxcache_unretire(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
    cmd_Lxcache_t *unretire_this_Lxcache, const char *fltnm)
{
	cmd_ptrsubtype_t data_type;
	cmd_Lxcache_t *previously_retired_Lxcache;
	int	found_reretired_cacheline = 0;
	int	certainty;

	/*
	 * If we are unretiring a cacheline retired due to suspected TAG
	 * fault, then we must first check if we are using a cacheline
	 * that was retired earlier for DATA fault.
	 * If so we will not unretire the cacheline.
	 * We will change the flags to reflect the current condition.
	 * We will return success, though.
	 */
	if (IS_TAG(unretire_this_Lxcache->Lxcache_type)) {
		if (unretire_this_Lxcache->Lxcache_type == CMD_PTR_CPU_L2TAG)
			data_type = CMD_PTR_CPU_L2DATA;
		if (unretire_this_Lxcache->Lxcache_type == CMD_PTR_CPU_L3TAG)
			data_type = CMD_PTR_CPU_L3DATA;
		fmd_hdl_debug(hdl,
		    "\n%s:cpuid %d checking if there is a %s"
		    " cacheline re-retired at this index %d and way %d\n",
		    fltnm, cpu->cpu_cpuid, cmd_type_to_str(data_type),
		    unretire_this_Lxcache->Lxcache_index,
		    unretire_this_Lxcache->Lxcache_way);
		previously_retired_Lxcache =
		    cmd_Lxcache_lookup_by_type_index_way_flags(
		    cpu, data_type, unretire_this_Lxcache->Lxcache_index,
		    unretire_this_Lxcache->Lxcache_way,
		    CMD_LxCACHE_F_RERETIRED);
		if (previously_retired_Lxcache) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpuid %d Found a %s cacheline re-retired at"
			    " this index %d and way %d. Will mark this"
			    " RETIRED\n",
			    fltnm, cpu->cpu_cpuid, cmd_type_to_str(data_type),
			    unretire_this_Lxcache->Lxcache_index,
			    unretire_this_Lxcache->Lxcache_way);
			/*
			 * We call the cmd_Lxcache_fault to inform fmd
			 * about the suspect fmri. The cacheline is already
			 * retired but the existing suspect fmri is for TAG
			 * fault which will be removed in this routine.
			 */
			if (previously_retired_Lxcache->Lxcache_reason
			    == CMD_LXCONVICTED)
				certainty = HUNDRED_PERCENT;
			else
				certainty = SUSPECT_PERCENT;
			cmd_Lxcache_fault(hdl, cpu, previously_retired_Lxcache,
			    fltnm, cpu->cpu_fru_nvl, certainty);
			previously_retired_Lxcache->Lxcache_flags =
			    CMD_LxCACHE_F_RETIRED;
			/*
			 * Update persistent storage
			 */
			cmd_Lxcache_write(hdl, previously_retired_Lxcache);
			found_reretired_cacheline = 1;
		}
	} else {
		/*
		 * We have been called to unretire a cacheline retired
		 * earlier due to DATA errors.
		 * If this cacheline is marked RERETIRED then it means that
		 * the cacheline has been retired due to TAG errors and
		 * we should not be unretiring the cacheline.
		 */
		if (unretire_this_Lxcache->Lxcache_flags &
		    CMD_LxCACHE_F_RERETIRED) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpuid %d The cacheline at index %d and"
			    " way %d  which we are attempting to unretire"
			    " is in RERETIRED state. Therefore we will not"
			    " unretire it but will mark it as RETIRED.\n",
			    fltnm, cpu->cpu_cpuid,
			    unretire_this_Lxcache->Lxcache_index,
			    unretire_this_Lxcache->Lxcache_way);
			found_reretired_cacheline = 1;
		}
	}
	/*
	 * if we did not find a RERETIRED cacheline above
	 * unretire the cacheline.
	 */
	if (!found_reretired_cacheline) {
		if (cmd_cache_way_unretire(hdl, cpu, unretire_this_Lxcache)
		    == B_FALSE)
			return (B_FALSE);
	}
	unretire_this_Lxcache->Lxcache_flags = CMD_LxCACHE_F_UNRETIRED;
	/*
	 * We have exonerated the cacheline. We need to inform the fmd
	 * that we have repaired the suspect fmri that we retired earlier.
	 * The cpumem agent will not unretire cacheline in response to
	 * the list.repair events it receives.
	 */
	if (unretire_this_Lxcache->Lxcache_retired_fmri[0] != 0) {
		fmd_hdl_debug(hdl,
		    "\n%s:cpuid %d Repairing the retired fmri %s",
		    fltnm, cpu->cpu_cpuid,
		    unretire_this_Lxcache->Lxcache_retired_fmri);
		if (cmd_repair_fmri(hdl,
		    unretire_this_Lxcache->Lxcache_retired_fmri) != 0) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpuid %d Failed to repair retired fmri.",
			    fltnm, cpu->cpu_cpuid);
			/*
			 * We need to retire the cacheline that we just
			 * unretired.
			 */
			if (cmd_cache_way_retire(hdl, cpu,
			    unretire_this_Lxcache) == B_FALSE) {
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
			unretire_this_Lxcache->Lxcache_retired_fmri[0] = 0;
		}
	}
	return (B_TRUE);
}

boolean_t
cmd_Lxcache_retire(fmd_hdl_t *hdl, cmd_cpu_t *cpu,
    cmd_Lxcache_t *retire_this_Lxcache, const char *fltnm, uint_t cert)
{
	cmd_Lxcache_t *previously_retired_Lxcache;
	cmd_ptrsubtype_t data_type;
	const char	*uuid;
	char	suspect_list[128];

	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d: cmd_Lxcache_retire called for index %d"
	    " way %d bit %d\n",
	    fltnm, cpu->cpu_cpuid, retire_this_Lxcache->Lxcache_index,
	    retire_this_Lxcache->Lxcache_way, retire_this_Lxcache->Lxcache_bit);
	if (fmd_case_solved(hdl, retire_this_Lxcache->Lxcache_case.cc_cp)) {
		/*
		 * Case solved implies that the cache line is already
		 * retired as SUSPECT_0_TAG and we are here to retire this
		 * as SUSPECT_1_TAG.
		 * We will first repair the retired cacheline
		 * so that it does not get retired during replay for
		 *  wrong reason.
		 * If we are able to repair the retired cacheline we close the
		 * case and open a new case for it.
		 */
		if (retire_this_Lxcache->Lxcache_reason !=
		    CMD_LXSUSPECT_0_TAG) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d: Unexpected condition encountered."
			    " Expected the reason for retirement as"
			    " SUSPECT_0_TAG however found the reason"
			    " to be %s\n",
			    fltnm, cpu->cpu_cpuid,
			    cmd_reason_to_str(
			    retire_this_Lxcache->Lxcache_reason));
			return (B_FALSE);
		}
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d: We are re-retiring SUSPECT_0_TAG as"
		    " SUSPECT_1_TAG index %d way %d bit %d\n",
		    fltnm, cpu->cpu_cpuid,
		    retire_this_Lxcache->Lxcache_index,
		    retire_this_Lxcache->Lxcache_way,
		    retire_this_Lxcache->Lxcache_bit);
		fmd_hdl_debug(hdl,
		    "\n%s:cpu_id %d: The existing case for this Lxcache has"
		    " has been already solved. We will first repair the suspect"
		    " cacheline and if we are successful then close this case,"
		    " and open a new case.\n",
		    fltnm, cpu->cpu_cpuid);
		/*
		 * repair the retired cacheline.
		 */
		if (retire_this_Lxcache->Lxcache_retired_fmri[0] != 0) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpuid %d Repairing the retired suspect"
			    " cacheline %s\n",
			    fltnm, cpu->cpu_cpuid,
			    retire_this_Lxcache->Lxcache_retired_fmri);
			if (cmd_repair_fmri(hdl,
			    retire_this_Lxcache->Lxcache_retired_fmri) != 0) {
				fmd_hdl_debug(hdl,
				    "\n%s:cpuid %d Failed to repair the"
				    " retired fmri.",
				    fltnm, cpu->cpu_cpuid);
				return (B_FALSE);
			} else {
				retire_this_Lxcache->Lxcache_retired_fmri[0] =
				    0;
			}
		}
		uuid = fmd_case_uuid(hdl,
		    retire_this_Lxcache->Lxcache_case.cc_cp);
		fmd_hdl_debug(hdl,
		    "\n%s:cpuid %d: Closing the case %s\n",
		    fltnm, cpu->cpu_cpuid, uuid);
		cmd_case_fini(hdl, retire_this_Lxcache->Lxcache_case.cc_cp,
		    FMD_B_TRUE);
		retire_this_Lxcache->Lxcache_case.cc_cp = NULL;
		if (cmd_create_case_for_Lxcache(hdl, cpu, retire_this_Lxcache)
		    == B_FALSE)
			return (B_FALSE);
	} else {
		/*
		 * Not a SUSPECT_0_TAG.
		 * We should be entering this path if the cacheline is
		 * transitioning  from ACTIVE/UNRETIRED to RETIRED state.
		 * If the cacheline state is not as expected we print debug
		 * message and return failure.
		 */
		if ((retire_this_Lxcache->Lxcache_flags !=
		    CMD_LxCACHE_F_ACTIVE) &&
		    (retire_this_Lxcache->Lxcache_flags
		    != CMD_LxCACHE_F_UNRETIRED)) {
			/*
			 * Unexpected condition.
			 */
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d:Unexpected state %s for the"
			    " cacheline at index %d way %d encountered.\n",
			    fltnm, cpu->cpu_cpuid,
			    cmd_flags_to_str(
			    retire_this_Lxcache->Lxcache_flags),
			    retire_this_Lxcache->Lxcache_index,
			    retire_this_Lxcache->Lxcache_way);
			return (B_FALSE);
		}
	}
	suspect_list[0] = 0;
	(void) cmd_fmri_nvl2str(hdl, retire_this_Lxcache->Lxcache_asru.fmri_nvl,
	    suspect_list, sizeof (suspect_list));
	fmd_hdl_debug(hdl,
	    "\n%s:cpu_id %d:current suspect list is %s\n",
	    fltnm, cpu->cpu_cpuid, suspect_list);
	cmd_Lxcache_fault(hdl, cpu, retire_this_Lxcache, fltnm,
	    cpu->cpu_fru_nvl,
	    cert);
	retire_this_Lxcache->Lxcache_flags = CMD_LxCACHE_F_RETIRED;
	if (IS_TAG(retire_this_Lxcache->Lxcache_type)) {
		/*
		 * If the cacheline we just retired was retired earlier
		 * due to DATA faults we mark the Lxcache
		 * corresponding to DATA as RERETIRED.
		 */
		if (retire_this_Lxcache->Lxcache_type == CMD_PTR_CPU_L2TAG)
			data_type = CMD_PTR_CPU_L2DATA;
		if (retire_this_Lxcache->Lxcache_type == CMD_PTR_CPU_L3TAG)
			data_type = CMD_PTR_CPU_L3DATA;
		fmd_hdl_debug(hdl,
		    "\n%s:cpuid %d checking if there is a %s"
		    " cacheline retired at this index %d way %d\n",
		    fltnm, cpu->cpu_cpuid,
		    cmd_type_to_str(data_type),
		    retire_this_Lxcache->Lxcache_index,
		    retire_this_Lxcache->Lxcache_way);
		previously_retired_Lxcache =
		    cmd_Lxcache_lookup_by_type_index_way_flags(cpu,
		    data_type, retire_this_Lxcache->Lxcache_index,
		    retire_this_Lxcache->Lxcache_way, CMD_LxCACHE_F_RETIRED);
		if (previously_retired_Lxcache) {
			fmd_hdl_debug(hdl,
			    "\n%s:cpu_id %d: Found  index %d way %d"
			    " retired earlier. Will mark this Lxcache"
			    " as RERETIRED.\n",
			    fltnm, cpu->cpu_cpuid,
			    retire_this_Lxcache->Lxcache_index,
			    retire_this_Lxcache->Lxcache_way);
			/*
			 * First repair the retired cacheline and if successful
			 * close the existing case and create a new case.
			 */

			/*
			 * This cacheline has already been retired for
			 * TAG fault.
			 * Repair the previously retired DATA fault cacheline so
			 * that it does not get retired by fmd during replay.
			 */
			if (previously_retired_Lxcache->Lxcache_retired_fmri[0]
			    != 0) {
				fmd_hdl_debug(hdl,
				    "\n%s:cpuid %d Repairing the cacheline"
				    " retired due to data errors. %s\n",
				    fltnm, cpu->cpu_cpuid,
				    previously_retired_Lxcache->
				    Lxcache_retired_fmri);
				if (cmd_repair_fmri(hdl,
				    previously_retired_Lxcache->
				    Lxcache_retired_fmri)
				    != 0) {
					fmd_hdl_debug(hdl,
					    "\n%s:cpuid %d Failed to repair the"
					    " retired fmri.",
					    fltnm, cpu->cpu_cpuid);
					return (B_FALSE);
				} else {
					previously_retired_Lxcache->
					    Lxcache_retired_fmri[0] = 0;
				}
			}
			cmd_case_fini(hdl,
			    previously_retired_Lxcache->Lxcache_case.cc_cp,
			    FMD_B_TRUE);
			previously_retired_Lxcache->Lxcache_case.cc_cp = NULL;
			previously_retired_Lxcache->Lxcache_flags =
			    CMD_LxCACHE_F_RERETIRED;
			/*
			 * Update persistent storage
			 */
			cmd_Lxcache_write(hdl, previously_retired_Lxcache);
			/*
			 * Create a new case so that this Lxcache structure
			 * gets restored on replay.
			 */
			if (cmd_create_case_for_Lxcache(hdl, cpu,
			    previously_retired_Lxcache) == B_FALSE)
				return (B_FALSE);
		}
	}
	cmd_retire_cpu_if_limits_exceeded(hdl, cpu,
	    retire_this_Lxcache->Lxcache_type,
	    fltnm);
	return (B_TRUE);
}
