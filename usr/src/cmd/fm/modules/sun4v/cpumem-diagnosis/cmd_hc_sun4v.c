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


#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <sys/fm/protocol.h>
#include <cmd.h>
#include <string.h>
#include <cmd_hc_sun4v.h>

/* Using a global variable is safe because the DE is single threaded */

nvlist_t *dimm_nvl;
nvlist_t *mb_nvl;
nvlist_t *rsc_nvl;

nvlist_t *
cmd_fault_add_location(fmd_hdl_t *hdl, nvlist_t *flt, const char *locstr) {

	char *t, *s;

	if (nvlist_lookup_string(flt, FM_FAULT_LOCATION, &t) == 0)
		return (flt); /* already has location value */

	/* Replace occurrence of ": " with "/" to avoid confusing ILOM. */
	t = fmd_hdl_zalloc(hdl, strlen(locstr) + 1, FMD_SLEEP);
	s = strstr(locstr, ": ");
	if (s != NULL) {
		(void) strncpy(t, locstr, s - locstr);
		(void) strcat(t, "/");
		(void) strcat(t, s + 2);
	} else {
		(void) strcpy(t, locstr);
	}

	/* Also, remove any J number from end of this string. */
	s = strstr(t, "/J");
	if (s != NULL)
		*s = '\0';

	if (nvlist_add_string(flt, FM_FAULT_LOCATION, t) != 0)
		fmd_hdl_error(hdl, "unable to alloc location for fault\n");
	fmd_hdl_free(hdl, t, strlen(locstr) + 1);
	return (flt);
}

typedef struct tr_ent {
	const char *nac_component;
	const char *hc_component;
} tr_ent_t;

static tr_ent_t tr_tbl[] = {
	{ "MB",		"motherboard" },
	{ "CPU",	"cpuboard" },
	{ "MEM",	"memboard" },
	{ "CMP",	"chip" },
	{ "BR",		"branch" },
	{ "CH",		"dram-channel" },
	{ "R",		"rank" },
	{ "D",		"dimm" }
};

#define	tr_tbl_n	sizeof (tr_tbl) / sizeof (tr_ent_t)

int
map_name(const char *p) {
	int i;

	for (i = 0; i < tr_tbl_n; i++) {
		if (strncmp(p, tr_tbl[i].nac_component,
		    strlen(tr_tbl[i].nac_component)) == 0)
			return (i);
	}
	return (-1);
}

int
cmd_count_components(const char *str, char sep)
{
	int num = 0;
	const char *cptr = str;

	if (*cptr == sep) cptr++;		/* skip initial sep */
	if (strlen(cptr) > 0) num = 1;
	while ((cptr = strchr(cptr, sep)) != NULL) {
		cptr++;
		if (cptr == NULL || strcmp(cptr, "") == 0) break;
		if (map_name(cptr) >= 0) num++;
	}
	return (num);
}

/*
 * This version of breakup_components assumes that all component names which
 * it sees are of the form:  <nonnumeric piece><numeric piece>
 * i.e. no embedded numerals in component name which have to be spelled out.
 */

int
cmd_breakup_components(char *str, char *sep, nvlist_t **hc_nvl)
{
	char namebuf[64], instbuf[64];
	char *token, *tokbuf;
	int i, j, namelen, instlen;

	i = 0;
	for (token = strtok_r(str, sep, &tokbuf);
	    token != NULL;
	    token = strtok_r(NULL, sep, &tokbuf)) {
		namelen = strcspn(token, "0123456789");
		instlen = strspn(token+namelen, "0123456789");
		(void) strncpy(namebuf, token, namelen);
		namebuf[namelen] = '\0';

		if ((j = map_name(namebuf)) < 0)
			continue; /* skip names that don't map */

		if (instlen == 0) {
			(void) strncpy(instbuf, "0", 2);
		} else {
			(void) strncpy(instbuf, token+namelen, instlen);
			instbuf[instlen] = '\0';
		}
		if (nvlist_add_string(hc_nvl[i], FM_FMRI_HC_NAME,
		    tr_tbl[j].hc_component) != 0 ||
		    nvlist_add_string(hc_nvl[i], FM_FMRI_HC_ID, instbuf) != 0)
			return (-1);
		i++;
	}
	return (1);
}

char *
cmd_getfru_loc(fmd_hdl_t *hdl, nvlist_t *asru) {

	char *fru_loc, *cpufru;
	if (nvlist_lookup_string(asru, FM_FMRI_CPU_CPUFRU, &cpufru) == 0) {
		fru_loc = strstr(cpufru, "MB");
		if (fru_loc != NULL) {
			fmd_hdl_debug(hdl, "cmd_getfru_loc: fruloc=%s\n",
			    fru_loc);
			return (fmd_hdl_strdup(hdl, fru_loc, FMD_SLEEP));
		}
	}
	fmd_hdl_debug(hdl, "cmd_getfru_loc: Default fruloc=empty string\n");
	return (fmd_hdl_strdup(hdl, EMPTY_STR, FMD_SLEEP));
}

nvlist_t *
cmd_mkboard_fru(fmd_hdl_t *hdl, char *frustr, char *serialstr, char *partstr) {

	char *nac, *nac_name;
	int n, i, len;
	nvlist_t *fru, **hc_list;

	if (frustr == NULL)
		return (NULL);

	if ((nac_name = strstr(frustr, "MB")) == NULL)
		return (NULL);

	len = strlen(nac_name) + 1;

	nac = fmd_hdl_zalloc(hdl, len, FMD_SLEEP);
	(void) strcpy(nac, nac_name);

	n = cmd_count_components(nac, '/');

	fmd_hdl_debug(hdl, "cmd_mkboard_fru: nac=%s components=%d\n", nac, n);

	hc_list = fmd_hdl_zalloc(hdl, sizeof (nvlist_t *)*n, FMD_SLEEP);

	for (i = 0; i < n; i++) {
		(void) nvlist_alloc(&hc_list[i],
		    NV_UNIQUE_NAME|NV_UNIQUE_NAME_TYPE, 0);
	}

	if (cmd_breakup_components(nac, "/", hc_list) < 0) {
		for (i = 0; i < n; i++) {
			nvlist_free(hc_list[i]);
		}
		fmd_hdl_free(hdl, hc_list, sizeof (nvlist_t *)*n);
		fmd_hdl_free(hdl, nac, len);
		return (NULL);
	}

	if (nvlist_alloc(&fru, NV_UNIQUE_NAME, 0) != 0) {
		for (i = 0; i < n; i++) {
			nvlist_free(hc_list[i]);
		}
		fmd_hdl_free(hdl, hc_list, sizeof (nvlist_t *)*n);
		fmd_hdl_free(hdl, nac, len);
		return (NULL);
	}

	if (nvlist_add_uint8(fru, FM_VERSION, FM_HC_SCHEME_VERSION) != 0 ||
	    nvlist_add_string(fru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC) != 0 ||
	    nvlist_add_string(fru, FM_FMRI_HC_ROOT, "") != 0 ||
	    nvlist_add_uint32(fru, FM_FMRI_HC_LIST_SZ, n) != 0 ||
	    nvlist_add_nvlist_array(fru, FM_FMRI_HC_LIST, hc_list, n) != 0) {
		for (i = 0; i < n; i++) {
			nvlist_free(hc_list[i]);
		}
		fmd_hdl_free(hdl, hc_list, sizeof (nvlist_t *)*n);
		fmd_hdl_free(hdl, nac, len);
		nvlist_free(fru);
		return (NULL);
	}

	for (i = 0; i < n; i++) {
		nvlist_free(hc_list[i]);
	}
	fmd_hdl_free(hdl, hc_list, sizeof (nvlist_t *)*n);
	fmd_hdl_free(hdl, nac, len);

	if ((serialstr != NULL &&
	    nvlist_add_string(fru, FM_FMRI_HC_SERIAL_ID, serialstr) != 0) ||
	    (partstr != NULL &&
	    nvlist_add_string(fru, FM_FMRI_HC_PART, partstr) != 0)) {
		nvlist_free(fru);
		return (NULL);
	}

	return (fru);
}

nvlist_t *
cmd_boardfru_create_fault(fmd_hdl_t *hdl, nvlist_t *asru, const char *fltnm,
    uint_t cert, char *loc)
{
	nvlist_t *flt, *nvlfru;
	char *serialstr, *partstr;

	if ((loc == NULL) || (strcmp(loc, EMPTY_STR) == 0))
		return (NULL);

	if (nvlist_lookup_string(asru, FM_FMRI_HC_SERIAL_ID, &serialstr) != 0)
		serialstr = NULL;
	if (nvlist_lookup_string(asru, FM_FMRI_HC_PART, &partstr) != 0)
		partstr = NULL;

	nvlfru = cmd_mkboard_fru(hdl, loc, serialstr, partstr);
	if (nvlfru == NULL)
		return (NULL);

	flt = cmd_nvl_create_fault(hdl, fltnm, cert, nvlfru, nvlfru, NULL);
	flt = cmd_fault_add_location(hdl, flt, loc);
	nvlist_free(nvlfru);
	return (flt);
}

/* find_mb -- find hardware platform motherboard within libtopo */

/* ARGSUSED */
static int
find_mb(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err;
	nvlist_t *rsrc, **hcl;
	char *name;
	uint_t n;

	if (topo_node_resource(node, &rsrc, &err) < 0) {
		return (TOPO_WALK_NEXT);	/* no resource, try next */
	}

	if (nvlist_lookup_nvlist_array(rsrc, FM_FMRI_HC_LIST, &hcl, &n) < 0) {
		nvlist_free(rsrc);
		return (TOPO_WALK_NEXT);
	}

	if (nvlist_lookup_string(hcl[0], FM_FMRI_HC_NAME, &name) != 0) {
		nvlist_free(rsrc);
		return (TOPO_WALK_NEXT);
	}

	if (strcmp(name, "motherboard") != 0) {
		nvlist_free(rsrc);
		return (TOPO_WALK_NEXT); /* not MB hc list, try next */
	}

	(void) nvlist_dup(rsrc, &mb_nvl, NV_UNIQUE_NAME);

	nvlist_free(rsrc);
	return (TOPO_WALK_TERMINATE);	/* if no space, give up */
}

/* init_mb -- read hardware platform motherboard from libtopo */

nvlist_t *
init_mb(fmd_hdl_t *hdl)
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return (NULL);
	if ((twp = topo_walk_init(thp,
	    FM_FMRI_SCHEME_HC, find_mb, NULL, &err))
	    == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		return (NULL);
	}
	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);
	return (mb_nvl);
}

/*ARGSUSED*/
static int
find_dimm_sn_mem(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err;
	uint_t n;
	nvlist_t *rsrc;
	char **sn;

	if (topo_node_resource(node, &rsrc, &err) < 0) {
		return (TOPO_WALK_NEXT);	/* no resource, try next */
	}
	if (nvlist_lookup_string_array(rsrc,
	    FM_FMRI_HC_SERIAL_ID, &sn, &n) != 0) {
		nvlist_free(rsrc);
		return (TOPO_WALK_NEXT);
	}
	if (strcmp(*sn, (char *)arg) != 0) {
		nvlist_free(rsrc);
		return (TOPO_WALK_NEXT);
	}
	(void) nvlist_dup(rsrc, &dimm_nvl, NV_UNIQUE_NAME);
	nvlist_free(rsrc);
	return (TOPO_WALK_TERMINATE);	/* if no space, give up */
}

/*ARGSUSED*/
static int
find_dimm_sn_hc(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err;
	nvlist_t *fru;
	char *sn;

	if (topo_node_fru(node, &fru, 0,  &err) < 0) {
		return (TOPO_WALK_NEXT);	/* no fru, try next */
	}
	if (nvlist_lookup_string(fru, FM_FMRI_HC_SERIAL_ID, &sn) != 0) {
		nvlist_free(fru);
		return (TOPO_WALK_NEXT);
	}
	if (strcmp(sn, (char *)arg) != 0) {
		nvlist_free(fru);
		return (TOPO_WALK_NEXT);
	}
	(void) nvlist_dup(fru, &dimm_nvl, NV_UNIQUE_NAME);
	nvlist_free(fru);
	return (TOPO_WALK_TERMINATE);	/* if no space, give up */
}

/* cmd_find_dimm_by_sn -- find fmri by sn from libtopo */

nvlist_t *
cmd_find_dimm_by_sn(fmd_hdl_t *hdl, char *schemename, char *sn)
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;

	dimm_nvl = NULL;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return (NULL);
	if (strcmp(schemename, FM_FMRI_SCHEME_MEM) == 0) {
		if ((twp = topo_walk_init(thp,
		    schemename, find_dimm_sn_mem, sn, &err)) == NULL) {
			fmd_hdl_topo_rele(hdl, thp);
			return (NULL);
		}
	} else {
		if ((twp = topo_walk_init(thp,
		    schemename, find_dimm_sn_hc, sn, &err)) == NULL) {
			fmd_hdl_topo_rele(hdl, thp);
			return (NULL);
		}
	}
	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);
	return (dimm_nvl);
}

typedef struct cpuid {
	char serial[100];
	char id[10];
} cpuid_t;

/*ARGSUSED*/
static int
find_cpu_rsc_by_sn(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err;
	nvlist_t *rsc;
	cpuid_t *rscid = (cpuid_t *)arg;
	char *sn, *name, *id;
	nvlist_t **hcl;
	uint_t n;

	if (topo_node_resource(node, &rsc, &err) < 0) {
		return (TOPO_WALK_NEXT);	/* no rsc, try next */
	}

	if (nvlist_lookup_string(rsc, FM_FMRI_HC_SERIAL_ID, &sn) != 0) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}
	if (strcmp(rscid->serial, sn) != 0) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}

	if (nvlist_lookup_nvlist_array(rsc, FM_FMRI_HC_LIST, &hcl, &n) != 0) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}

	if ((nvlist_lookup_string(hcl[n - 1], FM_FMRI_HC_NAME, &name) != 0) ||
	    (nvlist_lookup_string(hcl[n - 1], FM_FMRI_HC_ID, &id) != 0)) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}

	if ((strcmp(name, "cpu") != 0) || (strcmp(rscid->id, id) != 0)) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}

	(void) nvlist_dup(rsc, &rsc_nvl, NV_UNIQUE_NAME);

	nvlist_free(rsc);
	return (TOPO_WALK_TERMINATE);	/* if no space, give up */
}

nvlist_t *
cmd_find_cpu_rsc_by_sn(fmd_hdl_t *hdl, cpuid_t *cpuid)
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;

	rsc_nvl = NULL;
	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return (NULL);
	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC,
	    find_cpu_rsc_by_sn, cpuid, &err)) == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		return (NULL);
	}
	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);
	return (rsc_nvl);
}

nvlist_t *
get_cpu_fault_resource(fmd_hdl_t *hdl, nvlist_t *asru)
{
	uint32_t cpu;
	uint64_t serint;
	char serial[64];
	nvlist_t *rsc = NULL;
	cpuid_t cpuid;
	char strid[10];

	if (nvlist_lookup_uint64(asru, FM_FMRI_CPU_SERIAL_ID, &serint) != 0 ||
	    nvlist_lookup_uint32(asru, FM_FMRI_CPU_ID, &cpu) != 0)
		return (rsc);

	(void) snprintf(serial, sizeof (serial), "%llx", serint);
	(void) snprintf(strid, sizeof (strid), "%d", cpu);

	(void) strcpy(cpuid.serial, serial);
	(void) strcpy(cpuid.id, strid);

	rsc = cmd_find_cpu_rsc_by_sn(hdl, &cpuid);
	return (rsc);
}

/*ARGSUSED*/
static int
find_mem_rsc_hc(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int err;
	nvlist_t *rsc;
	char *sn;

	if (topo_node_resource(node, &rsc, &err) < 0) {
		return (TOPO_WALK_NEXT);	/* no rsc, try next */
	}
	if (nvlist_lookup_string(rsc, FM_FMRI_HC_SERIAL_ID, &sn) != 0) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}
	if (strcmp(sn, (char *)arg) != 0) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}
	(void) nvlist_dup(rsc, &rsc_nvl, NV_UNIQUE_NAME);
	nvlist_free(rsc);
	return (TOPO_WALK_TERMINATE);	/* if no space, give up */
}

nvlist_t *
cmd_find_mem_rsc_by_sn(fmd_hdl_t *hdl, char *sn)
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;

	rsc_nvl = NULL;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return (NULL);
	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC,
	    find_mem_rsc_hc, sn, &err)) == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		return (NULL);
	}
	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);
	return (rsc_nvl);
}

nvlist_t *
get_mem_fault_resource(fmd_hdl_t *hdl, nvlist_t *fru)
{
	char *sn;
	uint_t n;
	char **snarray;

	if (nvlist_lookup_string(fru, FM_FMRI_HC_SERIAL_ID, &sn) == 0)
		return (cmd_find_mem_rsc_by_sn(hdl, sn));

	/*
	 * T1 platform fru is in mem scheme
	 */
	if (nvlist_lookup_string_array(fru, FM_FMRI_MEM_SERIAL_ID,
	    &snarray, &n) == 0)
		return (cmd_find_mem_rsc_by_sn(hdl, snarray[0]));

	return (NULL);
}

int
is_T1_platform(nvlist_t *asru)
{
	char *unum;
	if (nvlist_lookup_string(asru, FM_FMRI_MEM_UNUM, &unum) == 0) {
		if (strstr(unum, "BR") == NULL)
			return (1);
	}
	return (0);
}

nvlist_t *
cmd_nvl_create_fault(fmd_hdl_t *hdl, const char *class, uint8_t cert,
    nvlist_t *asru, nvlist_t *fru, nvlist_t *rsrc)
{
	nvlist_t *fllist;
	uint64_t offset, phyaddr;
	nvlist_t *hsp = NULL;

	rsrc = NULL;
	(void) nvlist_add_nvlist(fru, FM_FMRI_AUTHORITY,
	    cmd.cmd_auth); /* not an error if this fails */

	if (strstr(class, "fault.memory.") != NULL) {
		/*
		 * For T1 platform fault.memory.bank and fault.memory.dimm,
		 * do not issue the hc schmem for resource and fru
		 */
		if (is_T1_platform(asru) && (strstr(class, ".page") == NULL)) {
			fllist = fmd_nvl_create_fault(hdl, class, cert, asru,
			    fru, fru);
			return (fllist);
		}

		rsrc = get_mem_fault_resource(hdl, fru);
		/*
		 * Need to append the phyaddr & offset into the
		 * hc-specific of the fault.memory.page resource
		 */
		if ((rsrc != NULL) && strstr(class, ".page") != NULL) {
			if (nvlist_alloc(&hsp, NV_UNIQUE_NAME, 0) == 0) {
				if (nvlist_lookup_uint64(asru,
				    FM_FMRI_MEM_PHYSADDR, &phyaddr) == 0)
					(void) (nvlist_add_uint64(hsp,
					    FM_FMRI_MEM_PHYSADDR,
					    phyaddr));

				if (nvlist_lookup_uint64(asru,
				    FM_FMRI_MEM_OFFSET, &offset) == 0)
					(void) nvlist_add_uint64(hsp,
					    FM_FMRI_HC_SPECIFIC_OFFSET, offset);

				(void) nvlist_add_nvlist(rsrc,
				    FM_FMRI_HC_SPECIFIC, hsp);
			}
		}
		fllist = fmd_nvl_create_fault(hdl, class, cert, asru,
		    fru, rsrc);
		nvlist_free(hsp);
	} else {
		rsrc = get_cpu_fault_resource(hdl, asru);
		fllist = fmd_nvl_create_fault(hdl, class, cert, asru,
		    fru, rsrc);
	}

	nvlist_free(rsrc);

	return (fllist);
}
