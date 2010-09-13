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

int
mem_discover(void)
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
	else
		return (mem_get_serids_from_cache(unum, seridsp, nseridsp));
}
