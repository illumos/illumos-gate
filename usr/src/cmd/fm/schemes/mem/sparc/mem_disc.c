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
 * DIMM unum/device map construction
 *
 * The map is constructed from PICL configuration files, which contain a map
 * between a form of the unum and the device to be used for serial number
 * retrieval.  We massage the PICL unum into a form that matches the one used
 * by mem FMRIs, creating a map entry from the munged version.  As described
 * below, two configuration files must be correlated to determine the correct
 * device path, and thus to build the mem_dimm_map_t list.  While platforms
 * without PICL configuration files are acceptable (some platforms, like
 * Serengeti and Starcat, don't have configuration files as of this writing),
 * platforms with only one or the other aren't.
 *
 * On Sun4v platforms, we read the 'mdesc' machine description file in order
 * to obtain the mapping between dimm unum+jnum strings (which denote slot
 * names) and the serial numbers of the dimms occupying those slots.
 */

#include <sys/param.h>
#include <sys/mdesc.h>

#include <mem.h>
#include <fm/fmd_fmri.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <sys/mem.h>
#include <sys/fm/ldom.h>

extern ldom_hdl_t *mem_scheme_lhp;

#define	PICL_FRUTREE_PATH \
	"%s/usr/platform/%s/lib/picl/plugins/piclfrutree.conf"

#define	PICL_FRUDATA_PATH \
	"%s/usr/platform/%s/lib/picl/plugins/libpiclfrudata.conf"

typedef struct mem_path_map {
	struct mem_path_map *pm_next;
	char *pm_path;
	char *pm_fullpath;
} mem_path_map_t;

typedef struct label_xlators {
	const char *lx_infmt;
	uint_t lx_matches;
	const char *lx_outfmt;
} label_xlators_t;

/*
 * PICL configuration files use a different format for the DIMM name (unum)
 * than that used in mem FMRIs.  The following patterns and routine are used
 * to convert between the PICL and unum formats.
 */
static const label_xlators_t label_xlators[] = {
	{ "/system-board/mem-slot?Label=J%4d%5$n", 1,
	    "J%04d" },
	{ "/system-board/mem-slot?Label=DIMM%1d%5$n", 1,
	    "DIMM%d" },
	{ "/system-board/cpu-mem-slot?Label=%4$c/mem-slot?Label=J%1$4d%5$n", 2,
	    "Slot %4$c: J%1$4d" },
	{ "/MB/system-board/mem-slot?Label=DIMM%1d%5$n", 1,
	    "DIMM%d" },
	{ "/MB/system-board/P%1d/cpu/B%1d/bank/D%1d%5$n", 3,
	    "MB/P%d/B%d/D%d" },
	{ "/MB/system-board/C%1d/cpu-module/P0/cpu/B%1d/bank/D%1d%5$n", 3,
	    "MB/C%d/P0/B%d/D%d" },
	{ "/MB/system-board/DIMM%1d%5$n", 1,
	    "MB/DIMM%d" },
	{ "/C%1d/system-board/P0/cpu/B%1d/bank/D%1d%5$n", 3,
	    "C%d/P0/B%d/D%d" },
	{ NULL }
};

static int
label_xlate(char *buf)
{
	const label_xlators_t *xlator;

	if (strncmp(buf, "/frutree/chassis", 16) != 0)
		return (0);

	for (xlator = label_xlators; xlator->lx_infmt != NULL; xlator++) {
		uint_t len, a1, a2, a3;
		char a4;

		if (sscanf(buf + 16, xlator->lx_infmt, &a1, &a2, &a3, &a4,
		    &len) == xlator->lx_matches && len == strlen(buf + 16)) {
			(void) sprintf(buf, xlator->lx_outfmt, a1, a2, a3, a4);
			return (0);
		}
	}

	return (fmd_fmri_set_errno(EINVAL));
}

/*
 * Match two paths taken from picl files.  This is a normal component-based path
 * comparison, but for the fact that components `foo' and `foo@1,2' are assumed
 * to be equal.  `foo@1,2' and `foo@3,4', however, are not assumed to be equal.
 */
static int
picl_path_eq(const char *p1, const char *p2)
{
	for (;;) {
		if (*p1 == *p2) {
			if (*p1 == '\0')
				return (1);
			else {
				p1++;
				p2++;
				continue;
			}
		}

		if (*p1 == '@' && (*p2 == '/' || *p2 == '\0')) {
			while (*p1 != '/' && *p1 != '\0')
				p1++;
			continue;
		}

		if ((*p1 == '/' || *p1 == '\0') && *p2 == '@') {
			while (*p2 != '/' && *p2 != '\0')
				p2++;
			continue;
		}

		return (0);
	}
}

/*
 * PICL paths begin with `/platform' instead of `/devices', as they are
 * intended to reference points in the PICL tree, rather than places in the
 * device tree.  Furthermore, some paths use the construct `?UnitAddress=a,b'
 * instead of `@a,b' to indicate unit number and address.  This routine
 * replaces both constructs with forms more appropriate for /devices path
 * lookup.
 */
static void
path_depicl(char *path)
{
	char *c;

	if (strncmp(path, "name:", 4) == 0)
		bcopy(path + 5, path, strlen(path + 5) + 1);

	for (c = path; (c = strstr(c, "?UnitAddress=")) != NULL; c++) {
		uint_t len = 0;

		(void) sscanf(c + 13, "%*x,%*x%n", &len);
		if (len == 0)
			continue;

		*c = '@';
		bcopy(c + 13, c + 1, strlen(c + 13) + 1);
	}
}

/*
 * The libpiclfrudata configuration file contains a map between the generic
 * (minor-less) device and the specific device to be used for SPD/SEEPROM
 * data access.
 *
 * Entries are of the form:
 *
 * name:/platform/generic-path
 * PROP FRUDevicePath string r 0 "full-path"
 *
 * Where `generic-path' is the path, sans minor name, to be used for DIMM
 * data access, and `full-path' is the path with the minor name.
 */
static int
picl_frudata_parse(char *buf, char *path, void *arg)
{
	mem_path_map_t **mapp = arg;
	mem_path_map_t *pm = NULL;
	char fullpath[BUFSIZ];
	uint_t len;

	if (sscanf(buf, " PROP FRUDevicePath string r 0 \"%[^\"]\" \n%n",
	    fullpath, &len) != 1 || fullpath[0] == '\0' || len != strlen(buf))
		return (0);

	path_depicl(path);

	pm = fmd_fmri_alloc(sizeof (mem_path_map_t));
	pm->pm_path = fmd_fmri_strdup(path);
	pm->pm_fullpath = fmd_fmri_strdup(fullpath);

	pm->pm_next = *mapp;
	*mapp = pm;

	return (1);
}

/*
 * The piclfrutree configuration file contains a map between a form of the
 * DIMM's unum and the generic (minor-less) device used for SPD/SEEPROM data
 * access.
 *
 * Entries are of the form:
 *
 * name:/frutree/chassis/picl-unum
 * REFNODE mem-module fru WITH /platform/generic-path
 *
 * Where `picl-unum' is the PICL form of the unum, which we'll massage into
 * the form compatible with FMRIs (see label_xlate), and `generic-path' is
 * the minor-less path into the PICL tree for the device used to access the
 * DIMM.  It is this path that will be used as the key in the frudata
 * configuration file to determine the proper /devices path.
 */
typedef struct dimm_map_arg {
	mem_path_map_t *dma_pm;
	mem_dimm_map_t *dma_dm;
} dimm_map_arg_t;

static int
picl_frutree_parse(char *buf, char *label, void *arg)
{
	dimm_map_arg_t *dma = arg;
	mem_dimm_map_t *dm = NULL;
	mem_path_map_t *pm;
	char path[BUFSIZ];
	uint_t len;

	/* LINTED - sscanf cannot exceed sizeof (path) */
	if (sscanf(buf, " REFNODE mem-module fru WITH %s \n%n",
	    path, &len) != 1 || path[0] == '\0' || len != strlen(buf))
		return (0);

	if (label_xlate(label) < 0)
		return (-1); /* errno is set for us */

	path_depicl(path);

	for (pm = dma->dma_pm; pm != NULL; pm = pm->pm_next) {
		if (picl_path_eq(pm->pm_path, path)) {
			(void) strcpy(path, pm->pm_fullpath);
			break;
		}
	}

	dm = fmd_fmri_zalloc(sizeof (mem_dimm_map_t));
	dm->dm_label = fmd_fmri_strdup(label);
	dm->dm_device = fmd_fmri_strdup(path);

	dm->dm_next = dma->dma_dm;
	dma->dma_dm = dm;

	return (1);
}

/*
 * Both configuration files use the same format, thus allowing us to use the
 * same parser to process them.
 */
static int
picl_conf_parse(const char *pathpat, int (*func)(char *, char *, void *),
    void *arg)
{
	char confpath[MAXPATHLEN];
	char buf[BUFSIZ], label[BUFSIZ];
	int line, len, rc;
	FILE *fp;

	(void) snprintf(confpath, sizeof (confpath), pathpat,
	    fmd_fmri_get_rootdir(), fmd_fmri_get_platform());

	if ((fp = fopen(confpath, "r")) == NULL)
		return (-1); /* errno is set for us */

	label[0] = '\0';
	for (line = 1; fgets(buf, sizeof (buf), fp) != NULL; line++) {
		if (buf[0] == '#')
			continue;

		if (buf[0] == '\n') {
			label[0] = '\0';
			continue;
		}

		/* LINTED - label length cannot exceed length of buf */
		if (sscanf(buf, " name:%s \n%n", label, &len) == 1 &&
		    label[0] != '\0' && len == strlen(buf))
			continue;

		if (label[0] != '\0') {
			if ((rc = func(buf, label, arg)) < 0) {
				int err = errno;
				(void) fclose(fp);
				return (fmd_fmri_set_errno(err));
			} else if (rc != 0) {
				label[0] = '\0';
			}
		}
	}

	(void) fclose(fp);
	return (0);
}

static void
path_map_destroy(mem_path_map_t *pm)
{
	mem_path_map_t *next;

	for (/* */; pm != NULL; pm = next) {
		next = pm->pm_next;

		fmd_fmri_strfree(pm->pm_path);
		fmd_fmri_strfree(pm->pm_fullpath);
		fmd_fmri_free(pm, sizeof (mem_path_map_t));
	}
}

uint16_t
mem_log2(uint64_t v)
{
	uint16_t i;
	for (i = 0; v > 1; i++) {
		v = v >> 1;
	}
	return (i);
}

static mem_dimm_map_t *
get_dimm_by_sn(char *sn)
{
	mem_dimm_map_t *dp;

	for (dp = mem.mem_dm; dp != NULL; dp = dp->dm_next) {
		if (strcmp(sn, dp->dm_serid) == 0)
			return (dp);
	}

	return (NULL);
}

#define	MEM_BYTES_PER_CACHELINE	64

static void
mdesc_init_n1(md_t *mdp, mde_cookie_t *listp)
{
	int idx, mdesc_dimm_count;
	mem_dimm_map_t *dm, *d;
	uint64_t sysmem_size, i, drgen = fmd_fmri_get_drgen();
	int dimms, min_chan, max_chan, min_rank, max_rank;
	int chan, rank, dimm, chans, chan_step;
	uint64_t mask, chan_mask, chan_value;
	uint64_t rank_mask, rank_value;
	char *unum, *serial, *part;
	mem_seg_map_t *seg;
	char s[20];

	/*
	 * Find first 'memory' node -- there should only be one.
	 * Extract 'memory-generation-id#' value from it.
	 */
	mdesc_dimm_count = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE, md_find_name(mdp, "memory"),
	    md_find_name(mdp, "fwd"), listp);

	if (md_get_prop_val(mdp, listp[0], "memory-generation-id#",
	    &mem.mem_memconfig))
		mem.mem_memconfig = 0;

	mdesc_dimm_count = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE, md_find_name(mdp, "dimm_data"),
	    md_find_name(mdp, "fwd"), listp);

	for (idx = 0; idx < mdesc_dimm_count; idx++) {

		if (md_get_prop_str(mdp, listp[idx], "nac", &unum) < 0)
			unum = "";
		if (md_get_prop_str(mdp, listp[idx], "serial#",
		    &serial) < 0)
			serial = "";
		if (md_get_prop_str(mdp, listp[idx], "part#",
		    &part) < 0)
			part = "";

		dm = fmd_fmri_zalloc(sizeof (mem_dimm_map_t));
		dm->dm_label = fmd_fmri_strdup(unum);
		(void) strncpy(dm->dm_serid, serial,
		    MEM_SERID_MAXLEN - 1);
		dm->dm_part = fmd_fmri_strdup(part);
		dm->dm_drgen = drgen;

		dm->dm_next = mem.mem_dm;
		mem.mem_dm = dm;
	}
	/* N1 (MD) specific segment initialization */

	dimms = 0;
	min_chan = 99;
	max_chan = -1;
	min_rank = 99;
	max_rank = -1;

	for (d = mem.mem_dm; d != NULL; d = d->dm_next) {
		if (sscanf(d->dm_label, "MB/CMP0/CH%d/R%d/D%d",
		    &chan, &rank, &dimm) != 3) /* didn't scan all 3 values */
			return;
		min_chan = MIN(min_chan, chan);
		max_chan = MAX(max_chan, chan);
		min_rank = MIN(min_rank, rank);
		max_rank = MAX(max_rank, rank);
		dimms++;
	}

	mdesc_dimm_count = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "mblock"),
	    md_find_name(mdp, "fwd"),
	    listp);
	sysmem_size = 0;
	for (idx = 0; idx < mdesc_dimm_count; idx++) {
		uint64_t size = 0;
		if (md_get_prop_val(mdp, listp[idx], "size", &size) == 0)
			sysmem_size += size;
	}

	for (i = 1 << 30; i < sysmem_size; i = i << 1)
		;
	if (max_rank > min_rank) {
		chans = dimms/4;
		rank_mask = i >> 1;
	} else {
		chans = dimms/2;
		rank_mask = 0;
	}

	chan_mask = (uint64_t)((chans - 1) * MEM_BYTES_PER_CACHELINE);
	mask = rank_mask | chan_mask;

	if (chans > 2)
		chan_step = 1;
	else
		chan_step = max_chan - min_chan;

	for (rank = min_rank, rank_value = 0;
	    rank <= max_rank;
	    rank++, rank_value += rank_mask) {
		for (chan = min_chan, chan_value = 0;
		    chan <= max_chan;
		    chan += chan_step,
		    chan_value += MEM_BYTES_PER_CACHELINE) {
			seg = fmd_fmri_zalloc(sizeof (mem_seg_map_t));
			seg->sm_next = mem.mem_seg;
			mem.mem_seg = seg;
			seg->sm_base = 0;
			seg->sm_size = sysmem_size;
			seg->sm_mask = mask;
			seg->sm_match = chan_value | rank_value;
			seg->sm_shift = 1;
			(void) sprintf(s, "MB/CMP0/CH%1d/R%1d", chan, rank);
			for (d = mem.mem_dm; d != NULL; d = d->dm_next) {
				if (strncmp(s, d->dm_label, strlen(s)) == 0)
					d->dm_seg = seg;
			}
		}
	}
}

static void
mdesc_init_n2(md_t *mdp, mde_cookie_t *listp, int num_comps)
{
	mde_cookie_t *dl, t;
	int idx, mdesc_dimm_count, mdesc_bank_count;
	mem_dimm_map_t *dm, *dp;
	uint64_t i, drgen = fmd_fmri_get_drgen();
	int n;
	uint64_t mask, match, base, size;
	char *unum, *serial, *part, *dash;
	mem_seg_map_t *smp;
	char *type, *sp, *jnum, *nac;
	size_t ss;

	mdesc_dimm_count = 0;
	for (idx = 0; idx < num_comps; idx++) {
		if (md_get_prop_str(mdp, listp[idx], "type", &type) < 0)
			continue;
		if (strcmp(type, "dimm") == 0) {
			mdesc_dimm_count++;
			if (md_get_prop_str(mdp, listp[idx], "nac",
			    &nac) < 0)
				nac = "";
			if (md_get_prop_str(mdp, listp[idx], "label",
			    &jnum) < 0)
				jnum = "";
			if (md_get_prop_str(mdp, listp[idx],
			    "serial_number", &serial) < 0)
				serial = "";
			if (md_get_prop_str(mdp, listp[idx],
			    "part_number", &part) < 0)
				part = "";
			if (md_get_prop_str(mdp, listp[idx],
			    "dash_number", &dash) < 0)
				dash = "";

			ss = strlen(part) + strlen(dash) + 1;
			sp = fmd_fmri_alloc(ss);
			sp = strcpy(sp, part);
			sp = strncat(sp, dash, strlen(dash) + 1);

			dm = fmd_fmri_zalloc(sizeof (mem_dimm_map_t));

			if ((strcmp(nac, "") != 0) &&
			    (strcmp(jnum, "") != 0)) {
				ss = strlen(nac) + strlen(jnum) + 2;
				unum = fmd_fmri_alloc(ss);
				(void) snprintf(unum, ss, "%s/%s", nac,
				    jnum);
				dm->dm_label = unum;
			} else {
				unum = "";
				dm->dm_label = fmd_fmri_strdup(unum);
			}

			(void) strncpy(dm->dm_serid, serial,
			    MEM_SERID_MAXLEN - 1);
			dm->dm_part = sp;
			dm->dm_drgen = drgen;

			dm->dm_next = mem.mem_dm;
			mem.mem_dm = dm;
		}
	}

	/* N2 (PRI) specific segment initialization occurs here */

	mdesc_bank_count = md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "memory-bank"),
	    md_find_name(mdp, "fwd"),
	    listp);

	dl = fmd_fmri_zalloc(mdesc_dimm_count * sizeof (mde_cookie_t));

	for (idx = 0; idx < mdesc_bank_count; idx++) {
		if (md_get_prop_val(mdp, listp[idx], "mask", &mask) < 0)
			mask = 0;
		if (md_get_prop_val(mdp, listp[idx], "match", &match) < 0)
			match = 0;
		n = md_scan_dag(mdp, listp[idx],
		    md_find_name(mdp, "memory-segment"),
		    md_find_name(mdp, "back"),
		    &t); /* only 1 "back" arc, so n must equal 1 here */
		if (md_get_prop_val(mdp, t, "base", &base) < 0)
			base = 0;
		if (md_get_prop_val(mdp, t, "size", &size) < 0)
			size = 0;
		smp = fmd_fmri_zalloc(sizeof (mem_seg_map_t));
		smp->sm_next = mem.mem_seg;
		mem.mem_seg = smp;
		smp->sm_base = base;
		smp->sm_size = size;
		smp->sm_mask = mask;
		smp->sm_match = match;

		n = md_scan_dag(mdp, listp[idx],
		    md_find_name(mdp, "component"),
		    md_find_name(mdp, "fwd"),
		    dl);
		smp->sm_shift = mem_log2(n);

		for (i = 0; i < n; i++) {
			if (md_get_prop_str(mdp, dl[i],
			    "serial_number", &serial) < 0)
				continue;
			if ((dp = get_dimm_by_sn(serial)) == NULL)
				continue;
			dp->dm_seg = smp;
		}
	}
	fmd_fmri_free(dl, mdesc_dimm_count * sizeof (mde_cookie_t));
}

int
mem_discover_mdesc(md_t *mdp, size_t mdbufsz)
{
	mde_cookie_t *listp;
	int num_nodes;
	int num_comps = 0;

	num_nodes = md_node_count(mdp);
	listp = fmd_fmri_alloc(sizeof (mde_cookie_t) * num_nodes);

	num_comps = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "component"),
	    md_find_name(mdp, "fwd"),
	    listp);
	if (num_comps == 0)
		mdesc_init_n1(mdp, listp);
	else
		mdesc_init_n2(mdp, listp, num_comps);

	fmd_fmri_free(listp, sizeof (mde_cookie_t) * num_nodes);
	fmd_fmri_free(*mdp, mdbufsz);

	(void) md_fini(mdp);
	return (0);
}

int
mem_discover_picl(void)
{
	mem_path_map_t *path_map = NULL;
	dimm_map_arg_t dma;
	int rc;

	if (picl_conf_parse(PICL_FRUDATA_PATH, picl_frudata_parse,
	    &path_map) < 0 && errno != ENOENT)
		return (-1); /* errno is set for us */

	dma.dma_pm = path_map;
	dma.dma_dm = NULL;

	if ((rc = picl_conf_parse(PICL_FRUTREE_PATH, picl_frutree_parse,
	    &dma)) < 0 && errno == ENOENT && path_map == NULL) {
		/*
		 * This platform doesn't support serial number retrieval via
		 * PICL mapping files.  Unfortunate, but not an error.
		 */
		return (0);
	}

	path_map_destroy(path_map);

	if (rc < 0)
		return (-1); /* errno is set for us */

	if (dma.dma_dm == NULL) {
		/*
		 * This platform should support DIMM serial numbers, but we
		 * weren't able to derive the paths.  Return an error.
		 */
		return (fmd_fmri_set_errno(EIO));
	}

	mem.mem_dm = dma.dma_dm;
	return (0);
}

/*
 * Initialize sun4v machine descriptor file for subsequent use.
 * If the open fails (most likely because file doesn't exist), or if
 * initialization fails, return NULL.
 *
 * If the open succeeds and initialization also succeeds, the returned value is
 * a pointer to an md_impl_t, whose 1st element points to the buffer where
 * the full mdesc has been read in.  The size of this buffer is returned
 * as 'bufsiz'.  Caller is responsible for deallocating BOTH of these objects.
 */
static md_t *
mdesc_devinit(size_t *bufsiz)
{
	uint64_t *bufp;
	ssize_t size;

	if ((size = ldom_get_core_md(mem_scheme_lhp, &bufp)) > 0) {
		*bufsiz = (size_t)size;
		return (md_init_intern(bufp, fmd_fmri_alloc, fmd_fmri_free));
	}

	return (NULL);
}

/*
 * Sun4v: if a valid 'mdesc' machine description file exists,
 * read the mapping of dimm unum+jnum to serial number from it.
 */
int
mem_discover(void)
{
	size_t mdbufsz = 0;
	md_t *mdp = mdesc_devinit(&mdbufsz);

	if (mdp == NULL)
		return (mem_discover_picl());
	else
		return (mem_discover_mdesc(mdp, mdbufsz));
}

int
mem_update_mdesc(void)
{
	size_t mdbufsz = 0;
	md_t *mdp = mdesc_devinit(&mdbufsz);

	if (mdp == NULL) {
		return (1);
	} else {
		mem_dimm_map_t *dm, *next;

		for (dm = mem.mem_dm; dm != NULL; dm = next) {
			next = dm->dm_next;
			fmd_fmri_strfree(dm->dm_label);
			fmd_fmri_strfree(dm->dm_part);
			fmd_fmri_free(dm, sizeof (mem_dimm_map_t));
		}
		mem.mem_dm = NULL;

		return (mem_discover_mdesc(mdp, mdbufsz));
	}
}

/*
 * Retry values for handling the case where the kernel is not yet ready
 * to provide DIMM serial ids.  Some platforms acquire DIMM serial id
 * information from their System Controller via a mailbox interface.
 * The values chosen are for 10 retries 3 seconds apart to approximate the
 * possible 30 second timeout length of a mailbox message request.
 */
#define	MAX_MEM_SID_RETRIES	10
#define	MEM_SID_RETRY_WAIT	3

/*
 * The comparison is asymmetric. It compares up to the length of the
 * argument unum.
 */
static mem_dimm_map_t *
dm_lookup(const char *name)
{
	mem_dimm_map_t *dm;

	for (dm = mem.mem_dm; dm != NULL; dm = dm->dm_next) {
		if (strncmp(name, dm->dm_label, strlen(name)) == 0)
			return (dm);
	}

	return (NULL);
}

/*
 * Returns 0 with serial numbers if found, -1 (with errno set) for errors.  If
 * the unum (or a component of same) wasn't found, -1 is returned with errno
 * set to ENOENT.  If the kernel doesn't have support for serial numbers,
 * -1 is returned with errno set to ENOTSUP.
 */
static int
mem_get_serids_from_kernel(const char *unum, char ***seridsp, size_t *nseridsp)
{
	char **dimms, **serids;
	size_t ndimms, nserids;
	int i, rc = 0;
	int fd;
	int retries = MAX_MEM_SID_RETRIES;
	mem_name_t mn;
	struct timespec rqt;

	if ((fd = open("/dev/mem", O_RDONLY)) < 0)
		return (-1);

	if (mem_unum_burst(unum, &dimms, &ndimms) < 0) {
		(void) close(fd);
		return (-1); /* errno is set for us */
	}

	serids = fmd_fmri_zalloc(sizeof (char *) * ndimms);
	nserids = ndimms;

	bzero(&mn, sizeof (mn));

	for (i = 0; i < ndimms; i++) {
		mn.m_namelen = strlen(dimms[i]) + 1;
		mn.m_sidlen = MEM_SERID_MAXLEN;

		mn.m_name = fmd_fmri_alloc(mn.m_namelen);
		mn.m_sid = fmd_fmri_alloc(mn.m_sidlen);

		(void) strcpy(mn.m_name, dimms[i]);

		do {
			rc = ioctl(fd, MEM_SID, &mn);

			if (rc >= 0 || errno != EAGAIN)
				break;

			if (retries == 0) {
				errno = ETIMEDOUT;
				break;
			}

			/*
			 * EAGAIN indicates the kernel is
			 * not ready to provide DIMM serial
			 * ids.  Sleep MEM_SID_RETRY_WAIT seconds
			 * and try again.
			 * nanosleep() is used instead of sleep()
			 * to avoid interfering with fmd timers.
			 */
			rqt.tv_sec = MEM_SID_RETRY_WAIT;
			rqt.tv_nsec = 0;
			(void) nanosleep(&rqt, NULL);

		} while (retries--);

		if (rc < 0) {
			/*
			 * ENXIO can happen if the kernel memory driver
			 * doesn't have the MEM_SID ioctl (e.g. if the
			 * kernel hasn't been patched to provide the
			 * support).
			 *
			 * If the MEM_SID ioctl is available but the
			 * particular platform doesn't support providing
			 * serial ids, ENOTSUP will be returned by the ioctl.
			 */
			if (errno == ENXIO)
				errno = ENOTSUP;
			fmd_fmri_free(mn.m_name, mn.m_namelen);
			fmd_fmri_free(mn.m_sid, mn.m_sidlen);
			mem_strarray_free(serids, nserids);
			mem_strarray_free(dimms, ndimms);
			(void) close(fd);
			return (-1);
		}

		serids[i] = fmd_fmri_strdup(mn.m_sid);

		fmd_fmri_free(mn.m_name, mn.m_namelen);
		fmd_fmri_free(mn.m_sid, mn.m_sidlen);
	}

	mem_strarray_free(dimms, ndimms);

	(void) close(fd);

	*seridsp = serids;
	*nseridsp = nserids;

	return (0);
}

/*
 * Returns 0 with serial numbers if found, -1 (with errno set) for errors.  If
 * the unum (or a component of same) wasn't found, -1 is returned with errno
 * set to ENOENT.
 */
static int
mem_get_serids_from_cache(const char *unum, char ***seridsp, size_t *nseridsp)
{
	uint64_t drgen = fmd_fmri_get_drgen();
	char **dimms, **serids;
	size_t ndimms, nserids;
	mem_dimm_map_t *dm;
	int i, rc = 0;

	if (mem_unum_burst(unum, &dimms, &ndimms) < 0)
		return (-1); /* errno is set for us */

	serids = fmd_fmri_zalloc(sizeof (char *) * ndimms);
	nserids = ndimms;

	for (i = 0; i < ndimms; i++) {
		if ((dm = dm_lookup(dimms[i])) == NULL) {
			rc = fmd_fmri_set_errno(EINVAL);
			break;
		}

		if (*dm->dm_serid == '\0' || dm->dm_drgen != drgen) {
			/*
			 * We don't have a cached copy, or the copy we've got is
			 * out of date.  Look it up again.
			 */
			if (mem_get_serid(dm->dm_device, dm->dm_serid,
			    sizeof (dm->dm_serid)) < 0) {
				rc = -1; /* errno is set for us */
				break;
			}

			dm->dm_drgen = drgen;
		}

		serids[i] = fmd_fmri_strdup(dm->dm_serid);
	}

	mem_strarray_free(dimms, ndimms);

	if (rc == 0) {
		*seridsp = serids;
		*nseridsp = nserids;
	} else {
		mem_strarray_free(serids, nserids);
	}

	return (rc);
}

/*
 * Returns 0 with serial numbers if found, -1 (with errno set) for errors.  If
 * the unum (or a component of same) wasn't found, -1 is returned with errno
 * set to ENOENT.
 */
static int
mem_get_serids_from_mdesc(const char *unum, char ***seridsp, size_t *nseridsp)
{
	uint64_t drgen = fmd_fmri_get_drgen();
	char **dimms, **serids;
	size_t ndimms, nserids;
	mem_dimm_map_t *dm;
	int i, rc = 0;

	if (mem_unum_burst(unum, &dimms, &ndimms) < 0)
		return (-1); /* errno is set for us */

	serids = fmd_fmri_zalloc(sizeof (char *) * ndimms);
	nserids = ndimms;

	/*
	 * first go through dimms and see if dm_drgen entries are outdated
	 */
	for (i = 0; i < ndimms; i++) {
		if ((dm = dm_lookup(dimms[i])) == NULL ||
		    dm->dm_drgen != drgen)
			break;
	}

	if (i < ndimms && mem_update_mdesc() != 0) {
		mem_strarray_free(dimms, ndimms);
		return (-1);
	}

	/*
	 * get to this point if an up-to-date mdesc (and corresponding
	 * entries in the global mem list) exists
	 */
	for (i = 0; i < ndimms; i++) {
		if ((dm = dm_lookup(dimms[i])) == NULL) {
			rc = fmd_fmri_set_errno(EINVAL);
			break;
		}

		if (dm->dm_drgen != drgen)
			dm->dm_drgen = drgen;

		/*
		 * mdesc and dm entry was updated by an earlier call to
		 * mem_update_mdesc, so we go ahead and dup the serid
		 */
		serids[i] = fmd_fmri_strdup(dm->dm_serid);
	}

	mem_strarray_free(dimms, ndimms);

	if (rc == 0) {
		*seridsp = serids;
		*nseridsp = nserids;
	} else {
		mem_strarray_free(serids, nserids);
	}

	return (rc);
}

/*
 * Returns 0 with part numbers if found, returns -1 for errors.
 */
static int
mem_get_parts_from_mdesc(const char *unum, char ***partsp, uint_t *npartsp)
{
	uint64_t drgen = fmd_fmri_get_drgen();
	char **dimms, **parts;
	size_t ndimms, nparts;
	mem_dimm_map_t *dm;
	int i, rc = 0;

	if (mem_unum_burst(unum, &dimms, &ndimms) < 0)
		return (-1); /* errno is set for us */

	parts = fmd_fmri_zalloc(sizeof (char *) * ndimms);
	nparts = ndimms;

	/*
	 * first go through dimms and see if dm_drgen entries are outdated
	 */
	for (i = 0; i < ndimms; i++) {
		if ((dm = dm_lookup(dimms[i])) == NULL ||
		    dm->dm_drgen != drgen)
			break;
	}

	if (i < ndimms && mem_update_mdesc() != 0) {
		mem_strarray_free(dimms, ndimms);
		mem_strarray_free(parts, nparts);
		return (-1);
	}

	/*
	 * get to this point if an up-to-date mdesc (and corresponding
	 * entries in the global mem list) exists
	 */
	for (i = 0; i < ndimms; i++) {
		if ((dm = dm_lookup(dimms[i])) == NULL) {
			rc = fmd_fmri_set_errno(EINVAL);
			break;
		}

		if (dm->dm_drgen != drgen)
			dm->dm_drgen = drgen;

		/*
		 * mdesc and dm entry was updated by an earlier call to
		 * mem_update_mdesc, so we go ahead and dup the part
		 */
		if (dm->dm_part == NULL) {
			rc = -1;
			break;
		}
		parts[i] = fmd_fmri_strdup(dm->dm_part);
	}

	mem_strarray_free(dimms, ndimms);

	if (rc == 0) {
		*partsp = parts;
		*npartsp = nparts;
	} else {
		mem_strarray_free(parts, nparts);
	}

	return (rc);
}

static int
mem_get_parts_by_unum(const char *unum, char ***partp, uint_t *npartp)
{
	if (mem.mem_dm == NULL)
		return (-1);
	else
		return (mem_get_parts_from_mdesc(unum, partp, npartp));
}

static int
get_seg_by_sn(char *sn, mem_seg_map_t **segmap)
{
	mem_dimm_map_t *dm;

	for (dm = mem.mem_dm; dm != NULL; dm = dm->dm_next) {
		if (strcmp(sn, dm->dm_serid) == 0) {
			*segmap = dm->dm_seg;
			return (0);
		}
	}
	return (-1);
}

/*
 * Niagara-1, Niagara-2, and Victoria Falls all have physical address
 * spaces of 40 bits.
 */

#define	MEM_PHYS_ADDRESS_LIMIT	0x10000000000ULL

/*
 * The 'mask' argument to extract_bits has 1's in those bit positions of
 * the physical address used to select the DIMM (or set of DIMMs) which will
 * store the contents of the physical address.  If we extract those bits, ie.
 * remove them and collapse the holes, the result is the 'address' within the
 * DIMM or set of DIMMs where the contents are stored.
 */

static uint64_t
extract_bits(uint64_t paddr, uint64_t mask)
{
	uint64_t from, to;
	uint64_t result = 0;

	to = 1;
	for (from = 1; from <= MEM_PHYS_ADDRESS_LIMIT; from <<= 1) {
		if ((from & mask) == 0) {
			if ((from & paddr) != 0)
				result |= to;
			to <<= 1;
		}
	}
	return (result);
}

/*
 * insert_bits is the reverse operation to extract_bits.  Where extract_bits
 * removes from the physical address those bits which select a DIMM or set
 * of DIMMs, insert_bits reconstitutes a physical address given the DIMM
 * selection 'mask' and the 'value' for the address bits denoted by 1s in
 * the 'mask'.
 */
static uint64_t
insert_bits(uint64_t offset, uint64_t mask, uint64_t value)
{
	uint64_t result = 0;
	uint64_t from, to;

	from = 1;
	for (to = 1; to <= MEM_PHYS_ADDRESS_LIMIT; to <<= 1) {
		if ((to & mask) == 0) {
			if ((offset & from) != 0)
				result |= to;
			from <<= 1;
		} else {
			result |= to & value;
		}
	}
	return (result);
}

int
mem_get_serids_by_unum(const char *unum, char ***seridsp, size_t *nseridsp)
{
	/*
	 * Some platforms do not support the caching of serial ids by the
	 * mem scheme plugin but instead support making serial ids available
	 * via the kernel.
	 */
	if (mem.mem_dm == NULL)
		return (mem_get_serids_from_kernel(unum, seridsp, nseridsp));
	else if (mem_get_serids_from_mdesc(unum, seridsp, nseridsp) == 0)
		return (0);
	else
		return (mem_get_serids_from_cache(unum, seridsp, nseridsp));
}

void
mem_expand_opt(nvlist_t *nvl, char *unum, char **serids)
{
	mem_seg_map_t *seg;
	uint64_t offset, physaddr;
	char **parts;
	uint_t nparts;

	/*
	 * The following additional expansions are all optional.
	 * Failure to retrieve a data value, or failure to add it
	 * successfully to the FMRI, does NOT cause a failure of
	 * fmd_fmri_expand.  All optional expansions will be attempted
	 * once expand_opt is entered.
	 */

	if ((mem.mem_seg != NULL) &&
	    (get_seg_by_sn(*serids, &seg) == 0) &&
	    (seg != NULL)) { /* seg can be NULL if segment missing from PRI */

		if (nvlist_lookup_uint64(nvl,
		    FM_FMRI_MEM_OFFSET, &offset) == 0) {
			physaddr = insert_bits((offset<<seg->sm_shift),
			    seg->sm_mask, seg->sm_match);
			(void) nvlist_add_uint64(nvl, FM_FMRI_MEM_PHYSADDR,
			    physaddr); /* displaces any previous physaddr */
		} else if (nvlist_lookup_uint64(nvl,
		    FM_FMRI_MEM_PHYSADDR, &physaddr) == 0) {
			offset = extract_bits(physaddr,
			    seg->sm_mask) >> seg->sm_shift;
			(void) (nvlist_add_uint64(nvl, FM_FMRI_MEM_OFFSET,
			    offset));
		}
	}

	if (nvlist_lookup_string_array(nvl, FM_FMRI_HC_PART,
	    &parts, &nparts) != 0) {
		if (mem_get_parts_by_unum(unum, &parts, &nparts) == 0) {
			(void) nvlist_add_string_array(nvl,
			    FM_FMRI_HC_PART, parts, nparts);
			mem_strarray_free(parts, nparts);
		}
	}
}
