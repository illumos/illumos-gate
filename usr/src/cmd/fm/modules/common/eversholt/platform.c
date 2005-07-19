/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * platform.c -- interfaces to the platform's configuration information
 *
 * this platform.c allows eft to run on Solaris systems.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <fm/libtopo_enum.h>
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
 * Lastcfg points to the last configuration snapshot we made.  If we
 * need to make a dev to hc scheme conversion of an event path, we use
 * the last snapshot as a best guess.  If we don't have a last snapshot
 * we take one and save it in Initcfg below.
 */
static struct cfgdata *Lastcfg;

/*
 * Initcfg points to any config snapshot we have to make prior
 * to starting our first fme.
 */
static struct cfgdata *Initcfg;

void
topo_use_out(const char *obuf)
{
	out(O_ALTFP, "topo: %s", obuf);
}

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

static void
platform_topo_paths(int *n, const char ***p)
{
	const char **cp;
	char *tmpbuf;

	*n = 2;
	cp = *p = MALLOC(2 * sizeof (const char *));

	tmpbuf = MALLOC(MAXPATHLEN);
	(void) snprintf(tmpbuf,
	    MAXPATHLEN, "%s/usr/lib/fm/topo/%s", Root, Plat);
	*cp++ = STRDUP(tmpbuf);
	(void) snprintf(tmpbuf, MAXPATHLEN, "%s/usr/lib/fm/topo", Root);
	*cp = STRDUP(tmpbuf);
	FREE(tmpbuf);
}

void
platform_free_paths(int n, const char **p)
{
	int i;

	for (i = 0; i < n; i++)
		FREE((void *)p[i]);
	FREE(p);
}

/*
 * platform_init -- perform any platform-specific initialization
 */
void
platform_init(void)
{
	const char **paths;
	int npaths;

	(void) nv_alloc_init(&Eft_nv_hdl, &Eft_nv_alloc_ops);
	topo_set_mem_methods(topo_use_alloc, topo_use_free);
	topo_set_out_method(topo_use_out);

	platform_globals();
	platform_topo_paths(&npaths, &paths);
	topo_init(npaths, (const char **)paths);
	platform_free_paths(npaths, paths);
}

void
platform_fini(void)
{
	if (Lastcfg != NULL) {
		config_free(Lastcfg);
		Lastcfg = NULL;
	}
	if (Initcfg != NULL) {
		config_free(Initcfg);
		Initcfg = NULL;
	}

	platform_free_globals();
	(void) nv_alloc_fini(&Eft_nv_hdl);
	topo_fini();
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
	struct node *ret;
	nvlist_t *dfmri = NULL;
	char *scheme = NULL;
	char *path = NULL;

	/*
	 * For now we assume the "path" part of the error report is
	 * the detector FMRI
	 */
	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &dfmri) != 0) {
		out(O_ALTFP, "XFILE: ereport has no detector FMRI");
		return (NULL);
	}

	if (nvlist_lookup_string(dfmri, FM_FMRI_SCHEME, &scheme) != 0) {
		out(O_ALTFP, "XFILE: detector FMRI missing scheme");
		return (NULL);
	}

	if (strcmp(scheme, FM_FMRI_SCHEME_HC) != 0) {
		/*
		 *  later, if FM_FMRI_SCHEME_DEV or FM_FMRI_SCHEME_CPU
		 *  we can look and perform a reverse translation into
		 *  an hc node
		 */
		uint32_t id;
		int isdev = 0;

		out(O_ALTFP|O_VERB, "Received ereport in scheme %s", scheme);
		if (strcmp(scheme, FM_FMRI_SCHEME_DEV) == 0) {
			isdev = 1;
		} else if (strcmp(scheme, FM_FMRI_SCHEME_CPU) != 0) {
			out(O_ALTFP, "XFILE: detector FMRI not recognized "
			    "(scheme is %s, expect %s or %s or %s)",
			    scheme, FM_FMRI_SCHEME_HC, FM_FMRI_SCHEME_DEV,
			    FM_FMRI_SCHEME_CPU);
			return (NULL);
		}

		if (isdev == 1 &&
		    nvlist_lookup_string(dfmri, FM_FMRI_DEV_PATH, &path) != 0) {
			out(O_ALTFP, "XFILE: detector FMRI missing %s",
			    FM_FMRI_DEV_PATH);
			return (NULL);
		} else if (isdev == 0 &&
		    nvlist_lookup_uint32(dfmri, FM_FMRI_CPU_ID, &id) != 0) {
			out(O_ALTFP, "XFILE: detector FMRI missing %s",
			    FM_FMRI_CPU_ID);
			return (NULL);
		}

		/*
		 * If we haven't taken a config snapshot yet, we need
		 * to do so now.  The call to config_snapshot() has the
		 * side-effect of setting Lastcfg.  We squirrel away the
		 * pointer to this snapshot so we may free it later.
		 */
		if (Lastcfg == NULL)
			if ((Initcfg = config_snapshot()) == NULL) {
				out(O_ALTFP,
				    "XFILE: cannot snapshot configuration");
				return (NULL);
			}

		/*
		 * Look up the path or cpu id in the last config snapshot.
		 */
		if (isdev == 1 &&
		    (ret = config_bydev_lookup(Lastcfg, path)) == NULL)
			out(O_ALTFP, "XFILE: no configuration node has "
			    "device path matching %s.", path);
		else if (isdev == 0 &&
		    (ret = config_bycpuid_lookup(Lastcfg, id)) == NULL)
			out(O_ALTFP, "XFILE: no configuration node has "
			    "cpu-id matching %u.", id);

		return (ret);
	}

	return (hc_fmri_nodeize(dfmri));
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

/*
 * cfgcollect -- Assemble raw configuration data in string form suitable
 *		 for checkpointing.
 */
static void
cfgcollect(tnode_t *node, void *arg)
{
	struct cfgdata *rawdata = (struct cfgdata *)arg;
	const char *propn, *propv;
	char *path;
	int addlen;

	path = topo_hc_path(node);
	addlen = strlen(path) + 1;

	cfgadjust(rawdata, addlen);
	(void) strcpy(rawdata->nextfree, path);
	rawdata->nextfree += addlen;

	propn = NULL;
	while ((propn = topo_next_prop(node, propn)) != NULL) {
		propv = topo_get_prop(node, propn);
		addlen = strlen(propn) + strlen(propv) + 2; /* = & NULL */
		cfgadjust(rawdata, addlen);
		(void) snprintf(rawdata->nextfree,
		    rawdata->end - rawdata->nextfree, "%s=%s", propn, propv);
		rawdata->nextfree += addlen;
	}
	topo_free_path(path);
}

/*
 * platform_config_snapshot -- gather a snapshot of the current configuration
 */
struct cfgdata *
platform_config_snapshot(void)
{
	tnode_t *root;

	/*
	 *
	 * If the DR generation number has changed,
	 * we need to grab a new snapshot, otherwise we
	 * can simply point them at the last config.
	 *
	 *	svgen = DRgen;
	 *	if (svgen == (Drgen = fmd_drgen_get()) && Lastcfg != NULL) {
	 *		Lastcfg->refcnt++;
	 *		return (Lastcfg);
	 *	}
	 */

	/* we're getting a new config, so clean up the last one */
	if (Lastcfg != NULL)
		config_free(Lastcfg);

	Lastcfg = MALLOC(sizeof (struct cfgdata));
	Lastcfg->refcnt = 2;	/* caller + Lastcfg */
	Lastcfg->begin = Lastcfg->nextfree = Lastcfg->end = NULL;
	Lastcfg->cooked = NULL;
	Lastcfg->devcache = NULL;
	Lastcfg->cpucache = NULL;

	if ((root = topo_next_sibling(NULL, NULL)) == NULL)
		out(O_DIE, "NULL topology tree");

	topo_walk(root, TOPO_VISIT_SELF_FIRST, Lastcfg, cfgcollect);
	topo_tree_release(root);
	topo_reset();

	return (Lastcfg);
}

static nvlist_t **
make_hc_pairs(char *fromstr, int *num)
{
	nvlist_t **pa;
	char *starti, *startn, *endi, *endi2;
	char *ne, *ns;
	char *cname;
	char *find;
	char *cid;
	int nslashes = 0;
	int npairs = 0;
	int i, e;

	/*
	 * Count equal signs and slashes to determine how many
	 * hc-pairs will be present in the final FMRI.  There should
	 * be at least as many slashes as equal signs.  There can be
	 * more, though if the string after an = includes them.
	 */
	find = fromstr;
	while ((ne = strchr(find, '=')) != NULL) {
		find = ne + 1;
		npairs++;
	}

	find = fromstr;
	while ((ns = strchr(find, '/')) != NULL) {
		find = ns + 1;
		nslashes++;
	}

	/*
	 * Do we appear to have a well-formed string version of the FMRI?
	 */
	if (nslashes < npairs || npairs == 0)
		return (NULL);

	*num = npairs;

	find = fromstr;
	pa = MALLOC(npairs * sizeof (nvlist_t *));
	/*
	 * We go through a pretty complicated procedure to find the
	 * name and id for each pair.  That's because, unfortunately,
	 * we have some ids that can have slashes within them.  So
	 * we can't just search for the next slash after the equal sign
	 * and decide that starts a new pair.  Instead we have to find
	 * an equal sign for the next pair and work our way back to the
	 * slash from there.
	 */
	for (i = 0; i < npairs; i++) {
		pa[i] = NULL;
		startn = strchr(find, '/');
		if (startn == NULL)
			break;
		startn++;
		starti = strchr(find, '=');
		if (starti == NULL)
			break;
		*starti = '\0';
		cname = STRDUP(startn);
		*starti++ = '=';
		endi = strchr(starti, '=');
		if (endi != NULL) {
			*endi = '\0';
			endi2 = strrchr(starti, '/');
			if (endi2 == NULL)
				break;
			*endi = '=';
			*endi2 = '\0';
			cid = STRDUP(starti);
			*endi2 = '/';
			find = endi2;
		} else {
			cid = STRDUP(starti);
			find = starti + strlen(starti);
		}
		e = nvlist_xalloc(&pa[i], NV_UNIQUE_NAME, &Eft_nv_hdl);
		if (e != 0)
			out(O_DIE|O_SYS, "alloc of an fmri nvl failed");
		e = nvlist_add_string(pa[i], FM_FMRI_HC_NAME, cname);
		e |= nvlist_add_string(pa[i], FM_FMRI_HC_ID, cid);
		FREE(cname);
		FREE(cid);
		if (e != 0) {
			out(O_DEBUG|O_SYS,
			    "Construction of new hc-pair nvl failed");
			break;
		}
	}
	if (i < npairs) {
		while (i >= 0)
			if (pa[i--] != NULL)
				nvlist_free(pa[i + 1]);
		FREE(pa);
		return (NULL);
	}
	return (pa);
}

static nvlist_t *
hc_fmri_fromstr(const char *str)
{
	nvlist_t **pa = NULL;
	nvlist_t *na = NULL;
	nvlist_t *nf = NULL;
	char *copy;
	int npairs;
	int i, e;

	/* We're expecting a string version of an hc scheme FMRI */
	if (strncmp(str, "hc:///", 6) != 0)
		return (NULL);

	copy = STRDUP(str + 5);
	if ((pa = make_hc_pairs(copy, &npairs)) == NULL) {
		FREE(copy);
		return (NULL);
	}

	FREE(copy);
	if ((e = nvlist_xalloc(&na, NV_UNIQUE_NAME, &Eft_nv_hdl)) != 0) {
		out(O_DEBUG|O_SYS, "alloc of an fmri nvl failed");
		goto hcfmbail;
	}
	e = nvlist_add_string(na, FM_FMRI_AUTH_PRODUCT, Plat);
	if (e != 0) {
		out(O_DEBUG|O_SYS, "Construction of new authority nvl failed");
		goto hcfmbail;
	}

	if ((e = nvlist_xalloc(&nf, NV_UNIQUE_NAME, &Eft_nv_hdl)) != 0) {
		out(O_DEBUG|O_SYS, "alloc of an fmri nvl failed");
		goto hcfmbail;
	}
	e = nvlist_add_string(nf, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC);
	e |= nvlist_add_nvlist(nf, FM_FMRI_AUTHORITY, na);
	e |= nvlist_add_uint8(nf, FM_VERSION, FM_HC_SCHEME_VERSION);
	e |= nvlist_add_string(nf, FM_FMRI_HC_ROOT, "");
	e |= nvlist_add_uint32(nf, FM_FMRI_HC_LIST_SZ, npairs);
	if (e == 0)
		e = nvlist_add_nvlist_array(nf, FM_FMRI_HC_LIST, pa, npairs);
	if (e != 0) {
		out(O_DEBUG|O_SYS, "Construction of new hc nvl failed");
		goto hcfmbail;
	}
	nvlist_free(na);
	for (i = 0; i < npairs; i++)
		nvlist_free(pa[i]);
	FREE(pa);
	return (nf);

hcfmbail:
	if (nf != NULL)
		nvlist_free(nf);
	if (na != NULL)
		nvlist_free(na);
	for (i = 0; i < npairs; i++)
		nvlist_free(pa[i]);
	FREE(pa);
	return (NULL);
}

static nvlist_t *
cpu_fmri(struct config *cpu, int cpu_id)
{
	nvlist_t *na = NULL;
	const char *propv;
	uint64_t ser_id;
	int e;

	if ((propv = config_getprop(cpu, "SERIAL-ID")) == NULL) {
		out(O_DEBUG|O_SYS, "cpu serial id missing");
		return (NULL);
	}
	ser_id = strtoll(propv, NULL, 0);

	if ((e = nvlist_xalloc(&na, NV_UNIQUE_NAME, &Eft_nv_hdl)) != 0)
		out(O_DIE|O_SYS, "alloc of an fmri nvl failed");

	e = nvlist_add_string(na, FM_FMRI_SCHEME, FM_FMRI_SCHEME_CPU);
	e |= nvlist_add_uint8(na, FM_VERSION, FM_CPU_SCHEME_VERSION);
	e |= nvlist_add_uint32(na, FM_FMRI_CPU_ID, cpu_id);
	e |= nvlist_add_uint64(na, FM_FMRI_CPU_SERIAL_ID, ser_id);
	if (e != 0) {
		out(O_DEBUG|O_SYS, "Construction of new ASRU nvl failed");
		nvlist_free(na);
		return (NULL);
	}
	return (na);
}

static nvlist_t *
dev_fmri(const char *devpath)
{
	nvlist_t *na = NULL;
	int e;

	if (strcmp(devpath, "none") == 0)
		return (NULL);

	if ((e = nvlist_xalloc(&na, NV_UNIQUE_NAME, &Eft_nv_hdl)) != 0)
		out(O_DIE|O_SYS, "alloc of an fmri nvl failed");
	e = nvlist_add_string(na, FM_FMRI_SCHEME, FM_FMRI_SCHEME_DEV);
	e |= nvlist_add_uint8(na, FM_VERSION, FM_DEV_SCHEME_VERSION);
	e |= nvlist_add_string(na, FM_FMRI_DEV_PATH, devpath);
	if (e != 0) {
		out(O_DEBUG|O_SYS, "Construction of new ASRU nvl failed");
		nvlist_free(na);
		return (NULL);
	}
	return (na);
}

static void
rewrite_asru(nvlist_t **ap, struct config *croot, char *path)
{
	struct config *casru;
	nvlist_t *na = NULL;
	const char *propv;
	char *cname;
	int cinst;

	/*
	 * The first order of business is to find the ASRU in the
	 * config database so we can examine properties associated with
	 * that node.
	 */
	if ((casru = config_lookup(croot, path, 0)) == NULL) {
		out(O_DEBUG, "Cannot find config info for %s.", path);
		return;
	}

	/*
	 * CPUs have their own scheme.
	 */
	config_getcompname(casru, &cname, &cinst);
	if (cname == NULL) {
		out(O_DEBUG,
		    "Final component of ASRU path (%s) has no name ?", path);
		return;
	} else if (strcmp(cname, "cpu") == 0) {
		if ((na = cpu_fmri(casru, cinst)) != NULL)
			*ap = na;
		return;
	}

	/*
	 * Look for a PLAT-ASRU property.
	 */
	if ((propv = config_getprop(casru, PLATASRU)) != NULL) {
		if ((na = hc_fmri_fromstr(propv)) != NULL)
			*ap = na;
		return;
	}
	out(O_DEBUG, "No " PLATASRU " prop for constructing "
	    "rewritten version of %s.", path);

	/*
	 * No, PLAT-ASRU, how about DEV?
	 */
	if ((propv = config_getprop(casru, DEV)) == NULL) {
		out(O_DEBUG, "No " DEV " prop for constructing "
		    "dev scheme version of %s.", path);
		return;
	}
	if ((na = dev_fmri(propv)) != NULL)
		*ap = na;
}

static void
rewrite_fru(nvlist_t **fp, struct config *croot, char *path)
{
	struct config *cfru;
	const char *propv;
	nvlist_t *na = NULL;

	/*
	 * The first order of business is to find the FRU in the
	 * config database so we can examine properties associated with
	 * that node.
	 */
	if ((cfru = config_lookup(croot, path, 0)) == NULL) {
		out(O_DEBUG, "Cannot find config info for %s.", path);
		return;
	}

	/*
	 * Look first for a PLAT-FRU property.
	 */
	if ((propv = config_getprop(cfru, PLATFRU)) != NULL) {
		if ((na = hc_fmri_fromstr(propv)) != NULL)
			*fp = na;
		return;
	}
	out(O_DEBUG, "No " PLATFRU " prop for constructing "
	    "rewritten version of %s.", path);
}

static void
defect_units(nvlist_t **ap, nvlist_t **fp, struct config *croot, char *path)
{
	struct config *cnode;
	const char *drvname;
	nvlist_t *nf = NULL;
	nvlist_t *na;

	/*
	 * Defects aren't required to have ASRUs and FRUs defined with
	 * them in the eversholt fault tree, so usually we'll be
	 * creating original FMRIs here.  If either the ASRU or FRU
	 * is defined when we get here, we won't replace it.
	 */
	if (*ap != NULL && *fp != NULL)
		return;

	/*
	 * In order to find an ASRU and FRU for the defect we need
	 * the name of the driver.
	 */
	if ((cnode = config_lookup(croot, path, 0)) == NULL) {
		out(O_DEBUG, "Cannot find config info for %s.", path);
		return;
	}
	if ((drvname = config_getprop(cnode, DRIVER)) == NULL) {
		out(O_DEBUG, "No " DRIVER "prop for constructing "
		    "mod scheme version of %s.", path);
		return;
	}
	if ((na = topo_driver_asru(drvname, &nf)) == NULL)
		return;

	if (*ap == NULL)
		*ap = na;

	if (*fp == NULL)
		*fp = nf;
}

/*
 * platform_units_translate
 *	This routines offers a chance for platform-specific rewrites of
 *	the hc scheme FRU and ASRUs associated with a suspect fault.
 */
/*ARGSUSED*/
void
platform_units_translate(int isdefect, struct config *croot,
    nvlist_t **dfltasru, nvlist_t **dfltfru, nvlist_t **dfltrsrc, char *path)
{
	nvlist_t *sva;
	nvlist_t *svf;

	out(O_DEBUG, "platform_units_translate(%d, ....)", isdefect);

	sva = *dfltasru;
	svf = *dfltfru;

	/*
	 * If there's room, keep a copy of our original ASRU as the rsrc
	 */
	if (*dfltrsrc == NULL)
		*dfltrsrc = *dfltasru;

	/*
	 * If it is a defect we want to re-write the FRU as the pkg
	 * scheme fmri of the package containing the buggy driver, and
	 * the ASRU as the mod scheme fmri of the driver's kernel
	 * module.
	 */
	if (isdefect) {
		defect_units(dfltasru, dfltfru, croot, path);
		if (sva != *dfltasru && sva != *dfltrsrc && sva != NULL)
			nvlist_free(sva);
		if (svf != *dfltfru && svf != NULL)
			nvlist_free(svf);
		return;
	}

	if (*dfltasru != NULL) {
		/*
		 * The ASRU will be re-written per the following rules:
		 *
		 * 1) If there's a PLAT-ASRU property, we convert it into
		 *	a real hc FMRI nvlist.
		 * 2) Otherwise, if we find a DEV property, we make a DEV
		 *	scheme FMRI of it
		 * 3) Otherwise, we leave the ASRU as is.
		 */
		rewrite_asru(dfltasru, croot, path);
	}

	if (*dfltfru != NULL) {
		/*
		 * The FRU will be re-written per the following rules:
		 *
		 * 1) If there's a PLAT-FRU property, we convert it into
		 *	a real hc FMRI nvlist.
		 * 2) Otherwise, we leave the ASRU as is, but include a
		 *	FRU label property if possible.
		 */
		rewrite_fru(dfltfru, croot, path);
	}

	if (sva != *dfltasru && sva != *dfltrsrc && sva != NULL)
		nvlist_free(sva);
	if (svf != *dfltfru && svf != NULL)
		nvlist_free(svf);
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
		out(O_DEBUG, "Looking for %s files in %s", fnstr, dirname[i]);
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
						out(O_DEBUG,
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

	if ((pid = fork()) < 0)
		rt = (int)strlcat(errbuf, ": fork() failed", errbuflen);
	else if (pid) {
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

/*
 * extract the first string in outbuf, either
 *   a) convert it to a number, or
 *   b) convert it to an address via stable()
 * and place the result (number or address) in valuep.
 *
 * return 0 if conversion was successful, nonzero if otherwise
 */
static int
string2number(char *outbuf, size_t outbuflen, struct evalue *valuep)
{
	char *ptr, *startptr, *endptr;
	int spval;
	size_t nchars, i, ier;

	/* determine start and length of first string */
	nchars = 0;
	for (i = 0; i < outbuflen && *(outbuf + i) != '\0'; i++) {
		spval = isspace((int)*(outbuf + i));
		if (spval != 0 && nchars > 0)
			break;
		if (spval == 0) {
			/* startptr: first nonspace character */
			if (nchars == 0)
				startptr = outbuf + i;
			nchars++;
		}
	}
	if (nchars == 0)
		return (1);

	ptr = MALLOC(sizeof (char) * (nchars + 1));
	(void) strncpy(ptr, startptr, nchars);
	*(ptr + nchars) = '\0';

	/* attempt conversion to number */
	errno = 0;
	valuep->t = UINT64;
	valuep->v = strtoull(ptr, &endptr, 0);
	ier = errno;

	/*
	 * test for endptr since the call to strtoull() should be
	 * considered a success only if the whole string was converted
	 */
	if (ier != 0 || endptr != (ptr + nchars)) {
		valuep->t = STRING;
		valuep->v = (unsigned long long)stable(ptr);
	}
	FREE(ptr);

	return (0);
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
			addthisarg = STRDUP((const char *)value.v);
			break;
		case NODEPTR :
			namep = (struct node *)value.v;
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
		ret = string2number(outbuf, sizeof (outbuf), valuep);
		if (ret)
			outfl(O_OK, np->file, np->line,
				"call: no result from %s", argv[0]);
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

int
platform_payloadprop(struct node *np, struct evalue *valuep)
{
	nvlist_t *basenvp;
	nvpair_t *nvpair;
	const char *nameptr, *propstr, *lastnameptr;
	int not_array = 0;
	unsigned int index = 0;
	uint_t nelem;
	char *nvpname, *nameslist = NULL;

	ASSERT(np->t == T_QUOTE);
	valuep->t = UNDEFINED;

	propstr = np->u.quote.s;
	if (payloadnvp == NULL) {
		out(O_ALTFP, "platform_payloadprop: no nvp for %s",
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
	}

	/*
	 * get to this point if we found an entry.  figure out its data
	 * type and copy its value.
	 */
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
		valuep->v = (unsigned long long)stable(val);
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
		valuep->v = (unsigned long long)stable(val[index]);
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
		out(O_DEBUG,
		    "platform_payloadprop: unsupported data type for %s",
		    propstr);
		return (1);
	}

	return (0);

invalid:
	out(O_DEBUG, "platform_payloadprop: invalid array reference for %s",
	    propstr);
	return (1);
}
