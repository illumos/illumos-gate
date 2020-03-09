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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * platform.c -- interfaces to the platform's configuration information
 *
 * this platform.c allows eft to run on Solaris systems.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <dirent.h>
#include <libnvpair.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/filio.h>
#include <sys/param.h>
#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>
#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include "alloc.h"
#include "out.h"
#include "tree.h"
#include "itree.h"
#include "ipath.h"
#include "ptree.h"
#include "fme.h"
#include "stable.h"
#include "eval.h"
#include "config.h"
#include "platform.h"

extern fmd_hdl_t *Hdl;		/* handle from eft.c */

/*
 * Lastcfg points to the last configuration snapshot we made.
 */
static struct cfgdata *Lastcfg;
static fmd_hdl_t *Lasthdl;
static fmd_case_t *Lastfmcase;
static const char *lastcomp;
static int in_getpath;
extern struct lut *Usednames;
int prune_raw_config = 0;

static topo_hdl_t *Eft_topo_hdl;

void *
topo_use_alloc(size_t bytes)
{
	void *p = alloc_malloc(bytes, NULL, 0);

	bzero(p, bytes);
	return (p);
}

void
topo_use_free(void *p)
{
	alloc_free(p, NULL, 0);
}

/*ARGSUSED*/
static void *
alloc_nv_alloc(nv_alloc_t *nva, size_t size)
{
	return (alloc_malloc(size, NULL, 0));
}

/*ARGSUSED*/
static void
alloc_nv_free(nv_alloc_t *nva, void *p, size_t sz)
{
	alloc_free(p, NULL, 0);
}

const nv_alloc_ops_t Eft_nv_alloc_ops = {
	NULL,		/* nv_ao_init() */
	NULL,		/* nv_ao_fini() */
	alloc_nv_alloc,	/* nv_ao_alloc() */
	alloc_nv_free,	/* nv_ao_free() */
	NULL		/* nv_ao_reset() */
};

nv_alloc_t Eft_nv_hdl;

static char *Root;
static char *Mach;
static char *Plat;
static char tmpbuf[MAXPATHLEN];
static char numbuf[MAXPATHLEN];

/*
 * platform_globals -- set global variables based on sysinfo() calls
 */
static void
platform_globals()
{
	Root = fmd_prop_get_string(Hdl, "fmd.rootdir");
	Mach = fmd_prop_get_string(Hdl, "fmd.machine");
	Plat = fmd_prop_get_string(Hdl, "fmd.platform");
}

static void
platform_free_globals()
{
	fmd_prop_free_string(Hdl, Root);
	fmd_prop_free_string(Hdl, Mach);
	fmd_prop_free_string(Hdl, Plat);
}

/*
 * platform_init -- perform any platform-specific initialization
 */
void
platform_init(void)
{
	(void) nv_alloc_init(&Eft_nv_hdl, &Eft_nv_alloc_ops);
	Eft_topo_hdl = fmd_hdl_topo_hold(Hdl, TOPO_VERSION);
	platform_globals();

	out(O_ALTFP, "platform_init() sucessful");
}

void
platform_fini(void)
{
	if (Lastcfg != NULL) {
		config_free(Lastcfg);
		Lastcfg = NULL;
	}
	fmd_hdl_topo_rele(Hdl, Eft_topo_hdl);
	platform_free_globals();
	(void) nv_alloc_fini(&Eft_nv_hdl);

	out(O_ALTFP, "platform_fini() sucessful");
}

/*
 * hc_fmri_nodeize -- convert hc-scheme FMRI to eft compatible format
 *
 * this is an internal platform.c helper routine
 */
static struct node *
hc_fmri_nodeize(nvlist_t *hcfmri)
{
	struct node *pathtree = NULL;
	struct node *tmpn;
	nvlist_t **hc_prs;
	uint_t hc_nprs;
	const char *sname;
	char *ename;
	char *eid;
	int e, r;

	/*
	 * What to do with/about hc-root?  Would we have any clue what
	 * to do with it if it weren't /?  For now, we don't bother
	 * even looking it up.
	 */

	/*
	 * Get the hc-list of elements in the FMRI
	 */
	if (nvlist_lookup_nvlist_array(hcfmri, FM_FMRI_HC_LIST,
	    &hc_prs, &hc_nprs) != 0) {
		out(O_ALTFP, "XFILE: hc FMRI missing %s", FM_FMRI_HC_LIST);
		return (NULL);
	}

	for (e = 0; e < hc_nprs; e++) {
		ename = NULL;
		eid = NULL;
		r = nvlist_lookup_string(hc_prs[e], FM_FMRI_HC_NAME, &ename);
		r |= nvlist_lookup_string(hc_prs[e], FM_FMRI_HC_ID, &eid);
		if (r != 0) {
			/* probably should bail */
			continue;
		}
		sname = stable(ename);
		tmpn = tree_name_iterator(
		    tree_name(sname, IT_VERTICAL, NULL, 0),
		    tree_num(eid, NULL, 0));

		if (pathtree == NULL)
			pathtree = tmpn;
		else
			(void) tree_name_append(pathtree, tmpn);
	}

	return (pathtree);
}

/*
 * platform_getpath -- extract eft-compatible path from ereport
 */
struct node *
platform_getpath(nvlist_t *nvl)
{
	struct node	*ret;
	nvlist_t	*dfmri, *real_fmri, *resource;
	char		*scheme;
	char		*path;
	char		*devid;
	char		*tp;
	uint32_t	cpuid;
	int		err;
	enum {DT_HC, DT_DEVID, DT_TP, DT_DEV, DT_CPU, DT_UNKNOWN} type =
		DT_UNKNOWN;

	/* Find the detector */
	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &dfmri) != 0) {
		out(O_ALTFP, "XFILE: ereport has no detector FMRI");
		return (NULL);
	}

	/* get the scheme from the detector */
	if (nvlist_lookup_string(dfmri, FM_FMRI_SCHEME, &scheme) != 0) {
		out(O_ALTFP, "XFILE: detector FMRI missing scheme");
		return (NULL);
	}

	/* based on scheme, determine type */
	if (strcmp(scheme, FM_FMRI_SCHEME_HC) == 0) {
		/* already in hc scheme */
		type = DT_HC;
	} else if (strcmp(scheme, FM_FMRI_SCHEME_DEV) == 0) {
		/*
		 * devid takes precedence over tp which takes precedence over
		 * path
		 */
		if (nvlist_lookup_string(dfmri,
		    FM_FMRI_DEV_ID, &devid) == 0)
			type = DT_DEVID;
		else if (nvlist_lookup_string(dfmri,
		    TOPO_STORAGE_TARGET_PORT_L0ID, &tp) == 0)
			type = DT_TP;
		else if (nvlist_lookup_string(dfmri,
		    FM_FMRI_DEV_PATH, &path) == 0)
			type = DT_DEV;
		else {
			out(O_ALTFP, "XFILE: detector FMRI missing %s or %s",
			    FM_FMRI_DEV_ID, FM_FMRI_DEV_PATH);
			return (NULL);
		}
	} else if (strcmp(scheme, FM_FMRI_SCHEME_CPU) == 0) {
		if (nvlist_lookup_uint32(dfmri, FM_FMRI_CPU_ID, &cpuid) == 0)
			type = DT_CPU;
		else {
			out(O_ALTFP, "XFILE: detector FMRI missing %s",
			    FM_FMRI_CPU_ID);
			return (NULL);
		}
	} else {
		out(O_ALTFP, "XFILE: detector FMRI not recognized "
		    "(scheme is %s, expect %s or %s or %s)",
		    scheme, FM_FMRI_SCHEME_HC, FM_FMRI_SCHEME_DEV,
		    FM_FMRI_SCHEME_CPU);
		return (NULL);
	}

	out(O_ALTFP|O_VERB, "Received ereport in scheme %s", scheme);

	/* take a config snapshot */
	lut_free(Usednames, NULL, NULL);
	Usednames = NULL;
	in_getpath = 1;
	if (config_snapshot() == NULL) {
		if (type == DT_HC) {
			/*
			 * If hc-scheme use the fmri that was passed in.
			 */
			in_getpath = 0;
			return (hc_fmri_nodeize(dfmri));
		}
		out(O_ALTFP, "XFILE: cannot snapshot configuration");
		in_getpath = 0;
		return (NULL);
	}

	/*
	 * For hc scheme, if we can find the resource from the tolopogy, use
	 * that - otherwise use the fmri that was passed in. For other schemes
	 * look up the path, cpuid, tp or devid in the topology.
	 */
	switch (type) {
	case DT_HC:
		if (topo_fmri_getprop(Eft_topo_hdl, dfmri, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_RESOURCE, NULL, &resource, &err) == -1) {
			ret = hc_fmri_nodeize(dfmri);
			break;
		} else if (nvlist_lookup_nvlist(resource,
		    TOPO_PROP_VAL_VAL, &real_fmri) != 0)
			ret = hc_fmri_nodeize(dfmri);
		else
			ret = hc_fmri_nodeize(real_fmri);

		nvlist_free(resource);
		break;

	case DT_DEV:
		if ((ret = config_bydev_lookup(Lastcfg, path)) == NULL)
			out(O_ALTFP, "platform_getpath: no configuration node "
			    "has device path matching \"%s\".", path);

		break;

	case DT_TP:
		if ((ret = config_bytp_lookup(Lastcfg, tp)) == NULL)
			out(O_ALTFP, "platform_getpath: no configuration node "
			    "has tp matching \"%s\".", tp);
		break;

	case DT_DEVID:
		if ((ret = config_bydevid_lookup(Lastcfg, devid)) == NULL)
			out(O_ALTFP, "platform_getpath: no configuration node "
			    "has devid matching \"%s\".", devid);
		break;

	case DT_CPU:
		if ((ret = config_bycpuid_lookup(Lastcfg, cpuid)) == NULL)
			out(O_ALTFP, "platform_getpath: no configuration node "
			    "has cpu-id matching %u.", cpuid);
		break;
	}

	/* free the snapshot */
	structconfig_free(Lastcfg->cooked);
	config_free(Lastcfg);
	in_getpath = 0;
	return (ret);
}

/* Allocate space for raw config strings in chunks of this size */
#define	STRSBUFLEN	512

/*
 * cfgadjust -- Make sure the amount we want to add to the raw config string
 *		buffer will fit, and if not, increase the size of the buffer.
 */
static void
cfgadjust(struct cfgdata *rawdata, int addlen)
{
	int curnext, newlen;

	if (rawdata->nextfree + addlen >= rawdata->end) {
		newlen = (((rawdata->nextfree - rawdata->begin + 1 + addlen)
		    / STRSBUFLEN) + 1) * STRSBUFLEN;
		curnext = rawdata->nextfree - rawdata->begin;
		rawdata->begin = REALLOC(rawdata->begin, newlen);
		rawdata->nextfree = rawdata->begin + curnext;
		rawdata->end = rawdata->begin + newlen;
	}
}

static char *
hc_path(tnode_t *node)
{
	int i, err;
	char *name, *instance, *estr;
	nvlist_t *fmri, **hcl;
	ulong_t ul;
	uint_t nhc;

	if (topo_prop_get_fmri(node, TOPO_PGROUP_PROTOCOL, TOPO_PROP_RESOURCE,
	    &fmri, &err) < 0)
		return (NULL);

	if (nvlist_lookup_nvlist_array(fmri, FM_FMRI_HC_LIST, &hcl, &nhc)
	    != 0) {
		nvlist_free(fmri);
		return (NULL);
	}

	tmpbuf[0] = '\0';
	for (i = 0; i < nhc; ++i) {
		err = nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &name);
		err |= nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &instance);
		if (err) {
			nvlist_free(fmri);
			return (NULL);
		}

		ul = strtoul(instance, &estr, 10);
		/* conversion to number failed? */
		if (estr == instance) {
			nvlist_free(fmri);
			return (NULL);
		}

		(void) strlcat(tmpbuf, "/", MAXPATHLEN);
		(void) strlcat(tmpbuf, name, MAXPATHLEN);
		(void) snprintf(numbuf, MAXPATHLEN, "%lu", ul);
		(void) strlcat(tmpbuf, numbuf, MAXPATHLEN);
		lastcomp = stable(name);
	}

	nvlist_free(fmri);

	return (tmpbuf);
}

static void
add_prop_val(topo_hdl_t *thp, struct cfgdata *rawdata, char *propn,
    nvpair_t *pv_nvp)
{
	int addlen, err;
	char *propv, *fmristr = NULL;
	nvlist_t *fmri;
	uint32_t ui32;
	int64_t i64;
	int32_t i32;
	boolean_t bool;
	uint64_t ui64;
	char buf[32];	/* big enough for any 64-bit int */
	uint_t nelem;
	int i, j, sz;
	char **propvv;

	/*
	 * malformed prop nvpair
	 */
	if (propn == NULL)
		return;

	switch (nvpair_type(pv_nvp)) {
	case DATA_TYPE_STRING_ARRAY:
		/*
		 * Convert string array into single space-separated string
		 */
		(void) nvpair_value_string_array(pv_nvp, &propvv, &nelem);
		for (sz = 0, i = 0; i < nelem; i++)
			sz += strlen(propvv[i]) + 1;
		propv = MALLOC(sz);
		for (j = 0, i = 0; i < nelem; j++, i++) {
			(void) strcpy(&propv[j], propvv[i]);
			j += strlen(propvv[i]);
			if (i < nelem - 1)
				propv[j] = ' ';
		}
		break;

	case DATA_TYPE_STRING:
		(void) nvpair_value_string(pv_nvp, &propv);
		break;

	case DATA_TYPE_NVLIST:
		/*
		 * At least try to collect the protocol
		 * properties
		 */
		(void) nvpair_value_nvlist(pv_nvp, &fmri);
		if (topo_fmri_nvl2str(thp, fmri, &fmristr, &err) < 0) {
			out(O_ALTFP, "cfgcollect: failed to convert fmri to "
			    "string");
			return;
		} else {
			propv = fmristr;
		}
		break;

	case DATA_TYPE_UINT64:
		/*
		 * Convert uint64 to hex strings
		 */
		(void) nvpair_value_uint64(pv_nvp, &ui64);
		(void) snprintf(buf, sizeof (buf), "0x%llx", ui64);
		propv = buf;
		break;

	case DATA_TYPE_BOOLEAN_VALUE:
		/*
		 * Convert boolean_t to hex strings
		 */
		(void) nvpair_value_boolean_value(pv_nvp, &bool);
		(void) snprintf(buf, sizeof (buf), "0x%llx", (uint64_t)bool);
		propv = buf;
		break;

	case DATA_TYPE_INT32:
		/*
		 * Convert int32 to hex strings
		 */
		(void) nvpair_value_int32(pv_nvp, &i32);
		(void) snprintf(buf, sizeof (buf), "0x%llx",
		    (uint64_t)(int64_t)i32);
		propv = buf;
		break;

	case DATA_TYPE_INT64:
		/*
		 * Convert int64 to hex strings
		 */
		(void) nvpair_value_int64(pv_nvp, &i64);
		(void) snprintf(buf, sizeof (buf), "0x%llx", (uint64_t)i64);
		propv = buf;
		break;

	case DATA_TYPE_UINT32:
		/*
		 * Convert uint32 to hex strings
		 */
		(void) nvpair_value_uint32(pv_nvp, &ui32);
		(void) snprintf(buf, sizeof (buf), "0x%llx", (uint64_t)ui32);
		propv = buf;
		break;

	default:
		out(O_ALTFP, "cfgcollect: failed to get property value for "
		    "%s", propn);
		return;
	}

	/* = & NULL */
	addlen = strlen(propn) + strlen(propv) + 2;
	cfgadjust(rawdata, addlen);
	(void) snprintf(rawdata->nextfree,
	    rawdata->end - rawdata->nextfree, "%s=%s",
	    propn, propv);
	if (strcmp(propn, TOPO_PROP_RESOURCE) == 0)
		out(O_ALTFP|O_VERB3, "cfgcollect: %s", propv);

	if (nvpair_type(pv_nvp) == DATA_TYPE_STRING_ARRAY)
		FREE(propv);

	rawdata->nextfree += addlen;

	if (fmristr != NULL)
		topo_hdl_strfree(thp, fmristr);
}

/*
 * cfgcollect -- Assemble raw configuration data in string form suitable
 *		 for checkpointing.
 */
static int
cfgcollect(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	struct cfgdata *rawdata = (struct cfgdata *)arg;
	int err, addlen;
	char *propn, *path = NULL;
	nvlist_t *p_nv, *pg_nv, *pv_nv;
	nvpair_t *nvp, *pg_nvp, *pv_nvp;

	if (topo_node_flags(node) == TOPO_NODE_FACILITY)
		return (TOPO_WALK_NEXT);

	path = hc_path(node);
	if (path == NULL)
		return (TOPO_WALK_ERR);

	addlen = strlen(path) + 1;

	cfgadjust(rawdata, addlen);
	(void) strcpy(rawdata->nextfree, path);
	rawdata->nextfree += addlen;

	/*
	 * If the prune_raw_config flag is set then we will only include in the
	 * raw config those nodes that are used by the rules remaining after
	 * prune_propagations() has been run - ie only those that could possibly
	 * be relevant to the incoming ereport given the current rules. This
	 * means that any other parts of the config will not get saved to the
	 * checkpoint file (even if they may theoretically be used if the
	 * rules are subsequently modified).
	 *
	 * For now prune_raw_config is 0 for Solaris, though it is expected to
	 * be set to 1 for fmsp.
	 *
	 * Note we only prune the raw config like this if we have been called
	 * from newfme(), not if we have been called when handling dev or cpu
	 * scheme ereports from platform_getpath(), as this is called before
	 * prune_propagations() - again this is not an issue on fmsp as the
	 * ereports are all in hc scheme.
	 */
	if (!in_getpath && prune_raw_config &&
	    lut_lookup(Usednames, (void *)lastcomp, NULL) == NULL)
		return (TOPO_WALK_NEXT);

	/*
	 * Collect properties
	 *
	 * eversholt should support alternate property types
	 * Better yet, topo properties could be represented as
	 * a packed nvlist
	 */
	p_nv = topo_prop_getprops(node, &err);
	for (nvp = nvlist_next_nvpair(p_nv, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(p_nv, nvp)) {
		if (strcmp(TOPO_PROP_GROUP, nvpair_name(nvp)) != 0 ||
		    nvpair_type(nvp) != DATA_TYPE_NVLIST)
			continue;

		(void) nvpair_value_nvlist(nvp, &pg_nv);

		for (pg_nvp = nvlist_next_nvpair(pg_nv, NULL); pg_nvp != NULL;
		    pg_nvp = nvlist_next_nvpair(pg_nv, pg_nvp)) {

			if (strcmp(TOPO_PROP_VAL, nvpair_name(pg_nvp)) != 0 ||
			    nvpair_type(pg_nvp) != DATA_TYPE_NVLIST)
				continue;

			(void) nvpair_value_nvlist(pg_nvp, &pv_nv);

			propn = NULL;
			for (pv_nvp = nvlist_next_nvpair(pv_nv, NULL);
			    pv_nvp != NULL;
			    pv_nvp = nvlist_next_nvpair(pv_nv, pv_nvp)) {

				/* Get property name */
				if (strcmp(TOPO_PROP_VAL_NAME,
				    nvpair_name(pv_nvp)) == 0)
					(void) nvpair_value_string(pv_nvp,
					    &propn);

				/*
				 * Get property value
				 */
				if (strcmp(TOPO_PROP_VAL_VAL,
				    nvpair_name(pv_nvp)) == 0)
					add_prop_val(thp, rawdata, propn,
					    pv_nvp);
			}

		}
	}

	nvlist_free(p_nv);

	return (TOPO_WALK_NEXT);
}

void
platform_restore_config(fmd_hdl_t *hdl, fmd_case_t *fmcase)
{
	if (hdl == Lasthdl && fmcase == Lastfmcase) {
		size_t cfglen;

		fmd_buf_read(Lasthdl, Lastfmcase, WOBUF_CFGLEN, (void *)&cfglen,
		    sizeof (size_t));
		Lastcfg->begin = MALLOC(cfglen);
		Lastcfg->end = Lastcfg->nextfree = Lastcfg->begin + cfglen;
		fmd_buf_read(Lasthdl, Lastfmcase, WOBUF_CFG, Lastcfg->begin,
		    cfglen);
		Lasthdl = NULL;
		Lastfmcase = NULL;
	}
}

void
platform_save_config(fmd_hdl_t *hdl, fmd_case_t *fmcase)
{
	size_t cfglen;

	/*
	 * Put the raw config into an fmd_buf. Then we can free it to
	 * save space.
	 */
	Lastfmcase = fmcase;
	Lasthdl = hdl;
	cfglen = Lastcfg->nextfree - Lastcfg->begin;
	fmd_buf_create(hdl, fmcase, WOBUF_CFGLEN, sizeof (cfglen));
	fmd_buf_write(hdl, fmcase, WOBUF_CFGLEN, (void *)&cfglen,
	    sizeof (cfglen));
	if (cfglen != 0) {
		fmd_buf_create(hdl, fmcase, WOBUF_CFG, cfglen);
		fmd_buf_write(hdl, fmcase, WOBUF_CFG, Lastcfg->begin, cfglen);
	}
	FREE(Lastcfg->begin);
	Lastcfg->begin = NULL;
	Lastcfg->end = NULL;
	Lastcfg->nextfree = NULL;
}

/*
 * platform_config_snapshot -- gather a snapshot of the current configuration
 */
struct cfgdata *
platform_config_snapshot(void)
{
	int err;
	topo_walk_t *twp;
	static uint64_t lastgen;
	uint64_t curgen;

	/*
	 * If the DR generation number has changed,
	 * we need to grab a new snapshot, otherwise we
	 * can simply point them at the last config.
	 */
	if (prune_raw_config == 0 && (curgen = fmd_fmri_get_drgen()) <=
	    lastgen && Lastcfg != NULL) {
		Lastcfg->raw_refcnt++;
		/*
		 * if config has been backed away to an fmd_buf, restore it
		 */
		if (Lastcfg->begin == NULL)
			platform_restore_config(Lasthdl, Lastfmcase);
		return (Lastcfg);
	}

	lastgen = curgen;
	/* we're getting a new config, so clean up the last one */
	if (Lastcfg != NULL) {
		config_free(Lastcfg);
	}

	Lastcfg = MALLOC(sizeof (struct cfgdata));
	Lastcfg->raw_refcnt = 2;	/* caller + Lastcfg */
	Lastcfg->begin = Lastcfg->nextfree = Lastcfg->end = NULL;
	Lastcfg->cooked = NULL;
	Lastcfg->devcache = NULL;
	Lastcfg->devidcache = NULL;
	Lastcfg->tpcache = NULL;
	Lastcfg->cpucache = NULL;


	fmd_hdl_topo_rele(Hdl, Eft_topo_hdl);
	Eft_topo_hdl = fmd_hdl_topo_hold(Hdl, TOPO_VERSION);

	if ((twp = topo_walk_init(Eft_topo_hdl, FM_FMRI_SCHEME_HC, cfgcollect,
	    Lastcfg, &err)) == NULL) {
		out(O_DIE, "platform_config_snapshot: NULL topology tree: %s",
		    topo_strerror(err));
	}

	if (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR) {
		topo_walk_fini(twp);
		out(O_DIE, "platform_config_snapshot: error walking topology "
		    "tree");
	}

	topo_walk_fini(twp);
	out(O_ALTFP|O_STAMP, "raw config complete");


	return (Lastcfg);
}

static const char *
cfgstrprop_lookup(struct config *croot, char *path, const char *pname)
{
	struct config *cresource;
	const char *fmristr;

	/*
	 * The first order of business is to find the resource in the
	 * config database so we can examine properties associated with
	 * that node.
	 */
	if ((cresource = config_lookup(croot, path, 0)) == NULL) {
		out(O_ALTFP, "Cannot find config info for %s.", path);
		return (NULL);
	}
	if ((fmristr = config_getprop(cresource, pname)) == NULL) {
		out(O_ALTFP, "Cannot find %s property for %s resource "
		    "re-write", pname, path);
		return (NULL);
	}
	return (fmristr);
}

/*
 * Get FMRI for a particular unit from libtopo. The unit is specified by the
 * "path" argument (a stringified ipath). "prop" argument should be one
 * of the constants TOPO_PROP_RESOURCE, TOPO_PROP_ASRU, TOPO_PROP_FRU, etc.
 */
/*ARGSUSED*/
void
platform_unit_translate(int isdefect, struct config *croot, const char *prop,
    nvlist_t **fmrip, char *path)
{
	const char *fmristr;
	char *serial;
	nvlist_t *fmri;
	int err;

	fmristr = cfgstrprop_lookup(croot, path, prop);
	if (fmristr == NULL) {
		out(O_ALTFP, "Cannot rewrite unit FMRI for %s.", path);
		return;
	}
	if (topo_fmri_str2nvl(Eft_topo_hdl, fmristr, &fmri, &err) < 0) {
		out(O_ALTFP, "Can not convert config info: %s",
		    topo_strerror(err));
		out(O_ALTFP, "Cannot rewrite unit FMRI for %s.", path);
		return;
	}

	/*
	 * If we don't have a serial number in the unit then check if it
	 * is available as a separate property and if so then add it.
	 */
	if (nvlist_lookup_string(fmri, FM_FMRI_HC_SERIAL_ID, &serial) != 0) {
		serial = (char *)cfgstrprop_lookup(croot, path,
		    FM_FMRI_HC_SERIAL_ID);
		if (serial != NULL)
			(void) nvlist_add_string(fmri, FM_FMRI_HC_SERIAL_ID,
			    serial);
	}

	*fmrip = fmri;
}

/*
 * platform_get_files -- return names of all files we should load
 *
 * search directories in dirname[] for all files with names ending with the
 * substring fnstr.  dirname[] should be a NULL-terminated array.  fnstr
 * may be set to "*" to indicate all files in a directory.
 *
 * if nodups is non-zero, then the first file of a given name found is
 * the only file added to the list of names.  for example if nodups is
 * set and we're looking for .efts, and find a pci.eft in the dirname[0],
 * then no pci.eft found in any of the other dirname[] entries will be
 * included in the final list of names.
 *
 * this routine doesn't return NULL, even if no files are found (in that
 * case, a char ** is returned with the first element NULL).
 */
static char **
platform_get_files(const char *dirname[], const char *fnstr, int nodups)
{
	DIR *dirp;
	struct dirent *dp;
	struct lut *foundnames = NULL;
	char **files = NULL;	/* char * array of filenames found */
	int nfiles = 0;		/* files found so far */
	int slots = 0;		/* char * slots allocated in files */
	size_t fnlen, d_namelen;
	size_t totlen;
	int i;
	static char *nullav;

	ASSERT(fnstr != NULL);
	fnlen = strlen(fnstr);

	for (i = 0; dirname[i] != NULL; i++) {
		out(O_VERB, "Looking for %s files in %s", fnstr, dirname[i]);
		if ((dirp = opendir(dirname[i])) == NULL) {
			out(O_DEBUG|O_SYS,
			    "platform_get_files: opendir failed for %s",
			    dirname[i]);
			continue;
		}
		while ((dp = readdir(dirp)) != NULL) {
			if ((fnlen == 1 && *fnstr == '*') ||
			    ((d_namelen = strlen(dp->d_name)) >= fnlen &&
			    strncmp(dp->d_name + d_namelen - fnlen,
			    fnstr, fnlen) == 0)) {

				if (nodups != 0) {
					const char *snm = stable(dp->d_name);

					if (lut_lookup(foundnames,
					    (void *)snm,
					    NULL) != NULL) {
						out(O_VERB,
						    "platform_get_files: "
						    "skipping repeated name "
						    "%s/%s",
						    dirname[i],
						    snm);
						continue;
					}
					foundnames = lut_add(foundnames,
					    (void *)snm,
					    (void *)snm,
					    NULL);
				}

				if (nfiles > slots - 2) {
					/* allocate ten more slots */
					slots += 10;
					files = (char **)REALLOC(files,
					    slots * sizeof (char *));
				}
				/* prepend directory name and / */
				totlen = strlen(dirname[i]) + 1;
				totlen += strlen(dp->d_name) + 1;
				files[nfiles] = MALLOC(totlen);
				out(O_VERB, "File %d: \"%s/%s\"", nfiles,
				    dirname[i], dp->d_name);
				(void) snprintf(files[nfiles++], totlen,
				    "%s/%s", dirname[i], dp->d_name);
			}
		}
		(void) closedir(dirp);
	}

	if (foundnames != NULL)
		lut_free(foundnames, NULL, NULL);

	if (nfiles == 0)
		return (&nullav);

	files[nfiles] = NULL;
	return (files);
}

/*
 * search for files in a standard set of directories
 */
static char **
platform_get_files_stddirs(char *fname, int nodups)
{
	const char *dirlist[4];
	char **flist;
	char *eftgendir, *eftmachdir, *eftplatdir;

	eftgendir = MALLOC(MAXPATHLEN);
	eftmachdir = MALLOC(MAXPATHLEN);
	eftplatdir = MALLOC(MAXPATHLEN);

	/* Generic files that apply to any machine */
	(void) snprintf(eftgendir, MAXPATHLEN, "%s/usr/lib/fm/eft", Root);

	(void) snprintf(eftmachdir,
	    MAXPATHLEN, "%s/usr/platform/%s/lib/fm/eft", Root, Mach);

	(void) snprintf(eftplatdir,
	    MAXPATHLEN, "%s/usr/platform/%s/lib/fm/eft", Root, Plat);

	dirlist[0] = eftplatdir;
	dirlist[1] = eftmachdir;
	dirlist[2] = eftgendir;
	dirlist[3] = NULL;

	flist = platform_get_files(dirlist, fname, nodups);

	FREE(eftplatdir);
	FREE(eftmachdir);
	FREE(eftgendir);

	return (flist);
}

/*
 * platform_run_poller -- execute a poller
 *
 * when eft needs to know if a polled ereport exists this routine
 * is called so the poller code may be run in a platform-specific way.
 * there's no return value from this routine -- either the polled ereport
 * is generated (and delivered *before* this routine returns) or not.
 * any errors, like "poller unknown" are considered platform-specific
 * should be handled here rather than passing an error back up.
 */
/*ARGSUSED*/
void
platform_run_poller(const char *poller)
{
}

/*
 * fork and execve path with argument array argv and environment array
 * envp.  data from stdout and stderr are placed in outbuf and errbuf,
 * respectively.
 *
 * see execve(2) for more descriptions for path, argv and envp.
 */
static int
forkandexecve(const char *path, char *const argv[], char *const envp[],
	char *outbuf, size_t outbuflen, char *errbuf, size_t errbuflen)
{
	pid_t pid;
	int outpipe[2], errpipe[2];
	int rt = 0;

	/*
	 * run the cmd and see if it failed.  this function is *not* a
	 * generic command runner -- we depend on some knowledge we
	 * have about the commands we run.  first of all, we expect
	 * errors to spew something to stdout, and that something is
	 * typically short enough to fit into a pipe so we can wait()
	 * for the command to complete and then fetch the error text
	 * from the pipe.
	 */
	if (pipe(outpipe) < 0)
		if (strlcat(errbuf, ": pipe(outpipe) failed",
		    errbuflen) >= errbuflen)
			return (1);
	if (pipe(errpipe) < 0)
		if (strlcat(errbuf, ": pipe(errpipe) failed",
		    errbuflen) >= errbuflen)
			return (1);

	if ((pid = fork()) < 0) {
		rt = (int)strlcat(errbuf, ": fork() failed", errbuflen);
	} else if (pid) {
		int wstat, count;

		/* parent */
		(void) close(errpipe[1]);
		(void) close(outpipe[1]);

		/* PHASE2 need to guard against hang in child? */
		if (waitpid(pid, &wstat, 0) < 0)
			if (strlcat(errbuf, ": waitpid() failed",
			    errbuflen) >= errbuflen)
				return (1);

		/* check for stderr contents */
		if (ioctl(errpipe[0], FIONREAD, &count) >= 0 && count) {
			if (read(errpipe[0], errbuf, errbuflen) <= 0) {
				/*
				 * read failed even though ioctl indicated
				 * that nonzero bytes were available for
				 * reading
				 */
				if (strlcat(errbuf, ": read(errpipe) failed",
				    errbuflen) >= errbuflen)
					return (1);
			}
			/*
			 * handle case where errbuf is not properly
			 * terminated
			 */
			if (count > errbuflen - 1)
				count = errbuflen - 1;
			if (errbuf[count - 1] != '\0' &&
			    errbuf[count - 1] != '\n')
				errbuf[count] = '\0';
		} else if (WIFSIGNALED(wstat))
			if (strlcat(errbuf, ": signaled",
			    errbuflen) >= errbuflen)
				return (1);
		else if (WIFEXITED(wstat) && WEXITSTATUS(wstat))
			if (strlcat(errbuf, ": abnormal exit",
			    errbuflen) >= errbuflen)
				return (1);

		/* check for stdout contents */
		if (ioctl(outpipe[0], FIONREAD, &count) >= 0 && count) {
			if (read(outpipe[0], outbuf, outbuflen) <= 0) {
				/*
				 * read failed even though ioctl indicated
				 * that nonzero bytes were available for
				 * reading
				 */
				if (strlcat(errbuf, ": read(outpipe) failed",
				    errbuflen) >= errbuflen)
					return (1);
			}
			/*
			 * handle case where outbuf is not properly
			 * terminated
			 */
			if (count > outbuflen - 1)
				count = outbuflen - 1;
			if (outbuf[count - 1] != '\0' &&
			    outbuf[count - 1] != '\n')
				outbuf[count] = '\0';
		}

		(void) close(errpipe[0]);
		(void) close(outpipe[0]);
	} else {
		/* child */
		(void) dup2(errpipe[1], fileno(stderr));
		(void) close(errpipe[0]);
		(void) dup2(outpipe[1], fileno(stdout));
		(void) close(outpipe[0]);

		if (execve(path, argv, envp))
			perror(path);
		_exit(1);
	}

	return (rt);
}

#define	MAXDIGITIDX	23

static int
arglist2argv(struct node *np, struct lut **globals, struct config *croot,
	struct arrow *arrowp, char ***argv, int *argc, int *argvlen)
{
	struct node *namep;
	char numbuf[MAXDIGITIDX + 1];
	char *numstr, *nullbyte;
	char *addthisarg = NULL;

	if (np == NULL)
		return (0);

	switch (np->t) {
	case T_QUOTE:
		addthisarg = STRDUP(np->u.func.s);
		break;
	case T_LIST:
		if (arglist2argv(np->u.expr.left, globals, croot, arrowp,
		    argv, argc, argvlen))
			return (1);
		/*
		 * only leftmost element of a list can provide the command
		 * name (after which *argc becomes 1)
		 */
		ASSERT(*argc > 0);
		if (arglist2argv(np->u.expr.right, globals, croot, arrowp,
		    argv, argc, argvlen))
			return (1);
		break;
	case T_FUNC:
	case T_GLOBID:
	case T_ASSIGN:
	case T_CONDIF:
	case T_CONDELSE:
	case T_EQ:
	case T_NE:
	case T_LT:
	case T_LE:
	case T_GT:
	case T_GE:
	case T_BITAND:
	case T_BITOR:
	case T_BITXOR:
	case T_BITNOT:
	case T_LSHIFT:
	case T_RSHIFT:
	case T_AND:
	case T_OR:
	case T_NOT:
	case T_ADD:
	case T_SUB:
	case T_MUL:
	case T_DIV:
	case T_MOD: {
		struct evalue value;

		if (!eval_expr(np, NULL, NULL, globals, croot, arrowp,
		    0, &value))
			return (1);

		switch (value.t) {
		case UINT64:
			numbuf[MAXDIGITIDX] = '\0';
			nullbyte = &numbuf[MAXDIGITIDX];
			numstr = ulltostr(value.v, nullbyte);
			addthisarg = STRDUP(numstr);
			break;
		case STRING:
			addthisarg = STRDUP((const char *)(uintptr_t)value.v);
			break;
		case NODEPTR :
			namep = (struct node *)(uintptr_t)value.v;
			addthisarg = ipath2str(NULL, ipath(namep));
			break;
		default:
			out(O_ERR,
			    "call: arglist2argv: unexpected result from"
			    " operation %s",
			    ptree_nodetype2str(np->t));
			return (1);
		}
		break;
	}
	case T_NUM:
	case T_TIMEVAL:
		numbuf[MAXDIGITIDX] = '\0';
		nullbyte = &numbuf[MAXDIGITIDX];
		numstr = ulltostr(np->u.ull, nullbyte);
		addthisarg = STRDUP(numstr);
		break;
	case T_NAME:
		addthisarg = ipath2str(NULL, ipath(np));
		break;
	case T_EVENT:
		addthisarg = ipath2str(np->u.event.ename->u.name.s,
		    ipath(np->u.event.epname));
		break;
	default:
		out(O_ERR, "call: arglist2argv: node type %s is unsupported",
		    ptree_nodetype2str(np->t));
		return (1);
		/*NOTREACHED*/
		break;
	}

	if (*argc == 0 && addthisarg != NULL) {
		/*
		 * first argument added is the command name.
		 */
		char **files;

		files = platform_get_files_stddirs(addthisarg, 0);

		/* do not proceed if number of files found != 1 */
		if (files[0] == NULL)
			out(O_DIE, "call: function %s not found", addthisarg);
		if (files[1] != NULL)
			out(O_DIE, "call: multiple functions %s found",
			    addthisarg);
		FREE(addthisarg);

		addthisarg = STRDUP(files[0]);
		FREE(files[0]);
		FREE(files);
	}

	if (addthisarg != NULL) {
		if (*argc >= *argvlen - 2) {
			/*
			 * make sure argv is long enough so it has a
			 * terminating element set to NULL
			 */
			*argvlen += 10;
			*argv = (char **)REALLOC(*argv,
			    sizeof (char *) * *argvlen);
		}
		(*argv)[*argc] = addthisarg;
		(*argc)++;
		(*argv)[*argc] = NULL;
	}

	return (0);
}

static int
generate_envp(struct arrow *arrowp, char ***envp, int *envc, int *envplen)
{
	char *envnames[] = { "EFT_FROM_EVENT", "EFT_TO_EVENT",
			    "EFT_FILE", "EFT_LINE", NULL };
	char *envvalues[4];
	char *none = "(none)";
	size_t elen;
	int i;

	*envc = 4;

	/*
	 * make sure envp is long enough so it has a terminating element
	 * set to NULL
	 */
	*envplen = *envc + 1;
	*envp = (char **)MALLOC(sizeof (char *) * *envplen);

	envvalues[0] = ipath2str(
	    arrowp->tail->myevent->enode->u.event.ename->u.name.s,
	    arrowp->tail->myevent->ipp);
	envvalues[1] = ipath2str(
	    arrowp->head->myevent->enode->u.event.ename->u.name.s,
	    arrowp->head->myevent->ipp);

	if (arrowp->head->myevent->enode->file == NULL) {
		envvalues[2] = STRDUP(none);
		envvalues[3] = STRDUP(none);
	} else {
		envvalues[2] = STRDUP(arrowp->head->myevent->enode->file);

		/* large enough for max int */
		envvalues[3] = MALLOC(sizeof (char) * 25);
		(void) snprintf(envvalues[3], sizeof (envvalues[3]), "%d",
		    arrowp->head->myevent->enode->line);
	}

	for (i = 0; envnames[i] != NULL && i < *envc; i++) {
		elen = strlen(envnames[i]) + strlen(envvalues[i]) + 2;
		(*envp)[i] = MALLOC(elen);
		(void) snprintf((*envp)[i], elen, "%s=%s",
		    envnames[i], envvalues[i]);
		FREE(envvalues[i]);
	}
	(*envp)[*envc] = NULL;

	return (0);
}

/*
 * platform_call -- call an external function
 *
 * evaluate a user-defined function and place result in valuep.  return 0
 * if function evaluation was successful; 1 if otherwise.
 */
int
platform_call(struct node *np, struct lut **globals, struct config *croot,
	struct arrow *arrowp, struct evalue *valuep)
{
	/*
	 * use rather short buffers.  only the first string on outbuf[] is
	 * taken as output from the called function.  any message in
	 * errbuf[] is echoed out as an error message.
	 */
	char outbuf[256], errbuf[512];
	struct stat buf;
	char **argv, **envp;
	int argc, argvlen, envc, envplen;
	int i, ret;

	/*
	 * np is the argument list.  the user-defined function is the first
	 * element of the list.
	 */
	ASSERT(np->t == T_LIST);

	argv = NULL;
	argc = 0;
	argvlen = 0;
	if (arglist2argv(np, globals, croot, arrowp, &argv, &argc, &argvlen) ||
	    argc == 0)
		return (1);

	/*
	 * make sure program has executable bit set
	 */
	if (stat(argv[0], &buf) == 0) {
		int exec_bit_set = 0;

		if (buf.st_uid == geteuid() && buf.st_mode & S_IXUSR)
			exec_bit_set = 1;
		else if (buf.st_gid == getegid() && buf.st_mode & S_IXGRP)
			exec_bit_set = 1;
		else if (buf.st_mode & S_IXOTH)
			exec_bit_set = 1;

		if (exec_bit_set == 0)
			out(O_DIE, "call: executable bit not set on %s",
			    argv[0]);
	} else {
		out(O_DIE, "call: failure in stat(), errno = %d\n", errno);
	}

	envp = NULL;
	envc = 0;
	envplen = 0;
	if (generate_envp(arrowp, &envp, &envc, &envplen))
		return (1);

	outbuf[0] = '\0';
	errbuf[0] = '\0';

	ret = forkandexecve((const char *) argv[0], (char *const *) argv,
	    (char *const *) envp, outbuf, sizeof (outbuf),
	    errbuf, sizeof (errbuf));

	for (i = 0; i < envc; i++)
		FREE(envp[i]);
	if (envp)
		FREE(envp);

	if (ret) {
		outfl(O_OK, np->file, np->line,
		    "call: failure in fork + exec of %s", argv[0]);
	} else {
		char *ptr;

		/* chomp the result */
		for (ptr = outbuf; *ptr; ptr++)
			if (*ptr == '\n' || *ptr == '\r') {
				*ptr = '\0';
				break;
			}
		valuep->t = STRING;
		valuep->v = (uintptr_t)stable(outbuf);
	}

	if (errbuf[0] != '\0') {
		ret = 1;
		outfl(O_OK, np->file, np->line,
		    "call: unexpected stderr output from %s: %s",
		    argv[0], errbuf);
	}

	for (i = 0; i < argc; i++)
		FREE(argv[i]);
	FREE(argv);

	return (ret);
}

/*
 * platform_confcall -- call a configuration database function
 *
 * returns result in *valuep, return 0 on success
 */
/*ARGSUSED*/
int
platform_confcall(struct node *np, struct lut **globals, struct config *croot,
	struct arrow *arrowp, struct evalue *valuep)
{
	outfl(O_ALTFP|O_VERB, np->file, np->line, "unknown confcall");
	return (0);
}

/*
 * platform_get_eft_files -- return names of all eft files we should load
 *
 * this routine doesn't return NULL, even if no files are found (in that
 * case, a char ** is returned with the first element NULL).
 */
char **
platform_get_eft_files(void)
{
	return (platform_get_files_stddirs(".eft", 1));
}

void
platform_free_eft_files(char **flist)
{
	char **f;

	if (flist == NULL || *flist == NULL)
		return;	/* no files were found so we're done */

	f = flist;
	while (*f != NULL) {
		FREE(*f);
		f++;
	}
	FREE(flist);
}

static nvlist_t *payloadnvp = NULL;

void
platform_set_payloadnvp(nvlist_t *nvlp)
{
	/*
	 * cannot replace a non-NULL payloadnvp with a non-NULL nvlp
	 */
	ASSERT(payloadnvp != NULL ? nvlp == NULL : 1);
	payloadnvp = nvlp;
}

/*
 * given array notation in inputstr such as "foo[1]" or "foo [ 1 ]" (spaces
 * allowed), figure out the array name and index.  return 0 if successful,
 * nonzero if otherwise.
 */
static int
get_array_info(const char *inputstr, const char **name, unsigned int *index)
{
	char *indexptr, *indexend, *dupname, *endname;

	if (strchr(inputstr, '[') == NULL)
		return (1);

	dupname = STRDUP(inputstr);
	indexptr = strchr(dupname, '[');
	indexend = strchr(dupname, ']');

	/*
	 * return if array notation is not complete or if index is negative
	 */
	if (indexend == NULL || indexptr >= indexend ||
	    strchr(indexptr, '-') != NULL) {
		FREE(dupname);
		return (1);
	}

	/*
	 * search past any spaces between the name string and '['
	 */
	endname = indexptr;
	while (isspace(*(endname - 1)) && dupname < endname)
		endname--;
	*endname = '\0';
	ASSERT(dupname < endname);

	/*
	 * search until indexptr points to the first digit and indexend
	 * points to the last digit
	 */
	while (!isdigit(*indexptr) && indexptr < indexend)
		indexptr++;
	while (!isdigit(*indexend) && indexptr <= indexend)
		indexend--;

	*(indexend + 1) = '\0';
	*index = (unsigned int)atoi(indexptr);

	*name = stable(dupname);
	FREE(dupname);

	return (0);
}

/*
 * platform_payloadprop -- fetch a payload value
 *
 * XXX this function should be replaced and eval_func() should be
 * XXX changed to use the more general platform_payloadprop_values().
 */
int
platform_payloadprop(struct node *np, struct evalue *valuep)
{
	nvlist_t *basenvp;
	nvlist_t *embnvp = NULL;
	nvpair_t *nvpair;
	const char *nameptr, *propstr, *lastnameptr;
	int not_array = 0;
	unsigned int index = 0;
	uint_t nelem;
	char *nvpname, *nameslist = NULL;
	char *scheme = NULL;

	ASSERT(np->t == T_QUOTE);

	propstr = np->u.quote.s;
	if (payloadnvp == NULL) {
		out(O_ALTFP | O_VERB2, "platform_payloadprop: no nvp for %s",
		    propstr);
		return (1);
	}
	basenvp = payloadnvp;

	/*
	 * first handle any embedded nvlists.  if propstr is "foo.bar[2]"
	 * then lastnameptr should end up being "bar[2]" with basenvp set
	 * to the nvlist for "foo".  (the search for "bar" within "foo"
	 * will be done later.)
	 */
	if (strchr(propstr, '.') != NULL) {
		nvlist_t **arraynvp;
		uint_t nelem;
		char *w;
		int ier;

		nameslist = STRDUP(propstr);
		lastnameptr = strtok(nameslist, ".");

		/*
		 * decompose nameslist into its component names while
		 * extracting the embedded nvlist
		 */
		while ((w = strtok(NULL, ".")) != NULL) {
			if (get_array_info(lastnameptr, &nameptr, &index)) {
				ier = nvlist_lookup_nvlist(basenvp,
				    lastnameptr, &basenvp);
			} else {
				/* handle array of nvlists */
				ier = nvlist_lookup_nvlist_array(basenvp,
				    nameptr, &arraynvp, &nelem);
				if (ier == 0) {
					if ((uint_t)index > nelem - 1)
						ier = 1;
					else
						basenvp = arraynvp[index];
				}
			}

			if (ier) {
				out(O_ALTFP, "platform_payloadprop: "
				    " invalid list for %s (in %s)",
				    lastnameptr, propstr);
				FREE(nameslist);
				return (1);
			}

			lastnameptr = w;
		}
	} else {
		lastnameptr = propstr;
	}

	/* if property is an array reference, extract array name and index */
	not_array = get_array_info(lastnameptr, &nameptr, &index);
	if (not_array)
		nameptr = stable(lastnameptr);

	if (nameslist != NULL)
		FREE(nameslist);

	/* search for nvpair entry */
	nvpair = NULL;
	while ((nvpair = nvlist_next_nvpair(basenvp, nvpair)) != NULL) {
		nvpname = nvpair_name(nvpair);
		ASSERT(nvpname != NULL);

		if (nameptr == stable(nvpname))
			break;
	}

	if (nvpair == NULL) {
		out(O_ALTFP, "platform_payloadprop: no entry for %s", propstr);
		return (1);
	} else if (valuep == NULL) {
		/*
		 * caller is interested in the existence of a property with
		 * this name, regardless of type or value
		 */
		return (0);
	}

	valuep->t = UNDEFINED;

	/*
	 * get to this point if we found an entry.  figure out its data
	 * type and copy its value.
	 */
	(void) nvpair_value_nvlist(nvpair, &embnvp);
	if (nvlist_lookup_string(embnvp, FM_FMRI_SCHEME, &scheme) == 0) {
		if (strcmp(scheme, FM_FMRI_SCHEME_HC) == 0) {
			valuep->t = NODEPTR;
			valuep->v = (uintptr_t)hc_fmri_nodeize(embnvp);
			return (0);
		}
	}
	switch (nvpair_type(nvpair)) {
	case DATA_TYPE_BOOLEAN:
	case DATA_TYPE_BOOLEAN_VALUE: {
		boolean_t val;
		(void) nvpair_value_boolean_value(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}
	case DATA_TYPE_BYTE: {
		uchar_t val;
		(void) nvpair_value_byte(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}
	case DATA_TYPE_STRING: {
		char *val;
		valuep->t = STRING;
		(void) nvpair_value_string(nvpair, &val);
		valuep->v = (uintptr_t)stable(val);
		break;
	}

	case DATA_TYPE_INT8: {
		int8_t val;
		(void) nvpair_value_int8(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}
	case DATA_TYPE_UINT8: {
		uint8_t val;
		(void) nvpair_value_uint8(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}

	case DATA_TYPE_INT16: {
		int16_t val;
		(void) nvpair_value_int16(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}
	case DATA_TYPE_UINT16: {
		uint16_t val;
		(void) nvpair_value_uint16(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}

	case DATA_TYPE_INT32: {
		int32_t val;
		(void) nvpair_value_int32(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}
	case DATA_TYPE_UINT32: {
		uint32_t val;
		(void) nvpair_value_uint32(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}

	case DATA_TYPE_INT64: {
		int64_t val;
		(void) nvpair_value_int64(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}
	case DATA_TYPE_UINT64: {
		uint64_t val;
		(void) nvpair_value_uint64(nvpair, &val);
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val;
		break;
	}

	case DATA_TYPE_BOOLEAN_ARRAY: {
		boolean_t *val;
		(void) nvpair_value_boolean_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}
	case DATA_TYPE_BYTE_ARRAY: {
		uchar_t *val;
		(void) nvpair_value_byte_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}
	case DATA_TYPE_STRING_ARRAY: {
		char **val;
		(void) nvpair_value_string_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = STRING;
		valuep->v = (uintptr_t)stable(val[index]);
		break;
	}

	case DATA_TYPE_INT8_ARRAY: {
		int8_t *val;
		(void) nvpair_value_int8_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}
	case DATA_TYPE_UINT8_ARRAY: {
		uint8_t *val;
		(void) nvpair_value_uint8_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}
	case DATA_TYPE_INT16_ARRAY: {
		int16_t *val;
		(void) nvpair_value_int16_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}
	case DATA_TYPE_UINT16_ARRAY: {
		uint16_t *val;
		(void) nvpair_value_uint16_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}
	case DATA_TYPE_INT32_ARRAY: {
		int32_t *val;
		(void) nvpair_value_int32_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}
	case DATA_TYPE_UINT32_ARRAY: {
		uint32_t *val;
		(void) nvpair_value_uint32_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}
	case DATA_TYPE_INT64_ARRAY: {
		int64_t *val;
		(void) nvpair_value_int64_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}
	case DATA_TYPE_UINT64_ARRAY: {
		uint64_t *val;
		(void) nvpair_value_uint64_array(nvpair, &val, &nelem);
		if (not_array == 1 || index >= nelem)
			goto invalid;
		valuep->t = UINT64;
		valuep->v = (unsigned long long)val[index];
		break;
	}

	default :
		out(O_ALTFP|O_VERB2,
		    "platform_payloadprop: unsupported data type for %s",
		    propstr);
		return (1);
	}

	return (0);

invalid:
	out(O_ALTFP|O_VERB2,
	    "platform_payloadprop: invalid array reference for %s", propstr);
	return (1);
}

/*ARGSUSED*/
int
platform_path_exists(nvlist_t *fmri)
{
	return (fmd_nvl_fmri_present(Hdl, fmri));
}

struct evalue *
platform_payloadprop_values(const char *propstr, int *nvals)
{
	struct evalue *retvals;
	nvlist_t *basenvp;
	nvpair_t *nvpair;
	char *nvpname;

	*nvals = 0;

	if (payloadnvp == NULL)
		return (NULL);

	basenvp = payloadnvp;

	/* search for nvpair entry */
	nvpair = NULL;
	while ((nvpair = nvlist_next_nvpair(basenvp, nvpair)) != NULL) {
		nvpname = nvpair_name(nvpair);
		ASSERT(nvpname != NULL);

		if (strcmp(propstr, nvpname) == 0)
			break;
	}

	if (nvpair == NULL)
		return (NULL);	/* property not found */

	switch (nvpair_type(nvpair)) {
	case DATA_TYPE_NVLIST: {
		nvlist_t *embnvp = NULL;
		char *scheme = NULL;

		(void) nvpair_value_nvlist(nvpair, &embnvp);
		if (nvlist_lookup_string(embnvp, FM_FMRI_SCHEME,
		    &scheme) == 0) {
			if (strcmp(scheme, FM_FMRI_SCHEME_HC) == 0) {
				*nvals = 1;
				retvals = MALLOC(sizeof (struct evalue));
				retvals->t = NODEPTR;
				retvals->v =
				    (uintptr_t)hc_fmri_nodeize(embnvp);
				return (retvals);
			}
		}
		return (NULL);
	}
	case DATA_TYPE_NVLIST_ARRAY: {
		char *scheme = NULL;
		nvlist_t **nvap;
		uint_t nel;
		int i;
		int hccount;

		/*
		 * since we're only willing to handle hc fmri's, we
		 * must count them first before allocating retvals.
		 */
		if (nvpair_value_nvlist_array(nvpair, &nvap, &nel) != 0)
			return (NULL);

		hccount = 0;
		for (i = 0; i < nel; i++) {
			if (nvlist_lookup_string(nvap[i], FM_FMRI_SCHEME,
			    &scheme) == 0 &&
			    strcmp(scheme, FM_FMRI_SCHEME_HC) == 0) {
				hccount++;
			}
		}

		if (hccount == 0)
			return (NULL);

		*nvals = hccount;
		retvals = MALLOC(sizeof (struct evalue) * hccount);

		hccount = 0;
		for (i = 0; i < nel; i++) {
			if (nvlist_lookup_string(nvap[i], FM_FMRI_SCHEME,
			    &scheme) == 0 &&
			    strcmp(scheme, FM_FMRI_SCHEME_HC) == 0) {
				retvals[hccount].t = NODEPTR;
				retvals[hccount].v = (uintptr_t)
				    hc_fmri_nodeize(nvap[i]);
				hccount++;
			}
		}
		return (retvals);
	}
	case DATA_TYPE_BOOLEAN:
	case DATA_TYPE_BOOLEAN_VALUE: {
		boolean_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_boolean_value(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}
	case DATA_TYPE_BYTE: {
		uchar_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_byte(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}
	case DATA_TYPE_STRING: {
		char *val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		retvals->t = STRING;
		(void) nvpair_value_string(nvpair, &val);
		retvals->v = (uintptr_t)stable(val);
		return (retvals);
	}

	case DATA_TYPE_INT8: {
		int8_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_int8(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}
	case DATA_TYPE_UINT8: {
		uint8_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_uint8(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}

	case DATA_TYPE_INT16: {
		int16_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_int16(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}
	case DATA_TYPE_UINT16: {
		uint16_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_uint16(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}

	case DATA_TYPE_INT32: {
		int32_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_int32(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}
	case DATA_TYPE_UINT32: {
		uint32_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_uint32(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}

	case DATA_TYPE_INT64: {
		int64_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_int64(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}
	case DATA_TYPE_UINT64: {
		uint64_t val;

		*nvals = 1;
		retvals = MALLOC(sizeof (struct evalue));
		(void) nvpair_value_uint64(nvpair, &val);
		retvals->t = UINT64;
		retvals->v = (unsigned long long)val;
		return (retvals);
	}

	case DATA_TYPE_BOOLEAN_ARRAY: {
		boolean_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_boolean_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}
	case DATA_TYPE_BYTE_ARRAY: {
		uchar_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_byte_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}
	case DATA_TYPE_STRING_ARRAY: {
		char **val;
		uint_t nel;
		int i;

		(void) nvpair_value_string_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = STRING;
			retvals[i].v = (uintptr_t)stable(val[i]);
		}
		return (retvals);
	}

	case DATA_TYPE_INT8_ARRAY: {
		int8_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_int8_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}
	case DATA_TYPE_UINT8_ARRAY: {
		uint8_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_uint8_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}
	case DATA_TYPE_INT16_ARRAY: {
		int16_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_int16_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}
	case DATA_TYPE_UINT16_ARRAY: {
		uint16_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_uint16_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}
	case DATA_TYPE_INT32_ARRAY: {
		int32_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_int32_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}
	case DATA_TYPE_UINT32_ARRAY: {
		uint32_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_uint32_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}
	case DATA_TYPE_INT64_ARRAY: {
		int64_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_int64_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}
	case DATA_TYPE_UINT64_ARRAY: {
		uint64_t *val;
		uint_t nel;
		int i;

		(void) nvpair_value_uint64_array(nvpair, &val, &nel);
		*nvals = nel;
		retvals = MALLOC(sizeof (struct evalue) * nel);
		for (i = 0; i < nel; i++) {
			retvals[i].t = UINT64;
			retvals[i].v = (unsigned long long)val[i];
		}
		return (retvals);
	}

	}

	return (NULL);
}

/*
 * When a list.repaired event is seen the following is called for
 * each fault in the associated fault list to convert the given FMRI
 * to an instanced path.  Only hc scheme is supported.
 */
const struct ipath *
platform_fault2ipath(nvlist_t *flt)
{
	nvlist_t *rsrc;
	struct node *np;
	char *scheme;
	const struct ipath *ip;

	if (nvlist_lookup_nvlist(flt, FM_FAULT_RESOURCE, &rsrc) != 0) {
		out(O_ALTFP, "platform_fault2ipath: no resource member");
		return (NULL);
	} else if (nvlist_lookup_string(rsrc, FM_FMRI_SCHEME, &scheme) != 0) {
		out(O_ALTFP, "platform_fault2ipath: no scheme type for rsrc");
		return (NULL);
	}

	if (strncmp(scheme, FM_FMRI_SCHEME_HC,
	    sizeof (FM_FMRI_SCHEME_HC) - 1) != 0) {
		out(O_ALTFP, "platform_fault2ipath: returning NULL for non-hc "
		"scheme %s", scheme);
		return (NULL);
	}

	if ((np = hc_fmri_nodeize(rsrc)) == NULL)
		return (NULL);		/* nodeize will already have whinged */

	ip = ipath(np);
	tree_free(np);
	return (ip);
}
