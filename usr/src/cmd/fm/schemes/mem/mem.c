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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mem.h>
#include <fm/fmd_fmri.h>

#include <string.h>
#include <strings.h>
#include <sys/mem.h>

/*
 * The scheme plugin for mem FMRIs.
 */

mem_t mem;

static mem_dimm_map_t *
dm_lookup(const char *name)
{
	mem_dimm_map_t *dm;

	for (dm = mem.mem_dm; dm != NULL; dm = dm->dm_next) {
		if (strcmp(name, dm->dm_label) == 0)
			return (dm);
	}

	return (NULL);
}

/*
 * Returns 0 with serial numbers if found, -1 (with errno set) for errors.  If
 * the unum (or a component of same) wasn't found, -1 is returned with errno
 * set to ENOENT.
 */
static int
mem_get_serids_by_unum(const char *unum, char ***seridsp, size_t *nseridsp)
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

	if (i == ndimms) {
		*seridsp = serids;
		*nseridsp = nserids;
	} else {
		mem_strarray_free(serids, nserids);
	}

	return (rc);
}

static int
mem_fmri_get_unum(nvlist_t *nvl, char **unump)
{
	uint8_t version;
	char *unum;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_MEM_SCHEME_VERSION ||
	    nvlist_lookup_string(nvl, FM_FMRI_MEM_UNUM, &unum) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	*unump = unum;

	return (0);
}

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	const char *fmt = "mem:///component=%1$s";
	ssize_t size, presz;
	uint64_t pa;
	char *rawunum, *preunum, *escunum;
	int i;

	if (mem_fmri_get_unum(nvl, &rawunum) < 0)
		return (-1); /* errno is set for us */

	if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_PHYSADDR, &pa) == 0)
		fmt = "mem:///pa=%2$llx/component=%1$s";

	/*
	 * If we leave the unum as-is, the spaces and colons will be escaped,
	 * rendering the resulting FMRI pretty much unreadable.  We're therefore
	 * going to do some escaping of our own first.
	 */
	preunum = fmd_fmri_strdup(rawunum);
	presz = strlen(preunum) + 1;

	for (i = 0; i < presz - 1; i++) {
		if (preunum[i] == ':' && preunum[i + 1] == ' ') {
			bcopy(preunum + i + 2, preunum + i + 1,
			    presz - (i + 2));
		} else if (preunum[i] == ' ') {
			preunum[i] = ',';
		}
	}

	escunum = fmd_fmri_strescape(preunum);
	fmd_fmri_free(preunum, presz);

	size = snprintf(buf, buflen, fmt, escunum, (u_longlong_t)pa);
	fmd_fmri_strfree(escunum);

	return (size);
}

int
fmd_fmri_expand(nvlist_t *nvl)
{
	char *unum, **serids;
	uint_t nserids;
	int rc;

	if (mem.mem_dm == NULL)
		return (0); /* nothing to add - no s/n support here */

	if (mem_fmri_get_unum(nvl, &unum) < 0)
		return (fmd_fmri_set_errno(EINVAL));

	if ((rc = nvlist_lookup_string_array(nvl, FM_FMRI_MEM_SERIAL_ID,
	    &serids, &nserids)) == 0)
		return (0); /* fmri is already expanded */
	else if (rc != ENOENT)
		return (fmd_fmri_set_errno(EINVAL));

	if (mem_get_serids_by_unum(unum, &serids, &nserids) < 0)
		return (-1); /* errno is set for us */

	rc = nvlist_add_string_array(nvl, FM_FMRI_MEM_SERIAL_ID, serids,
	    nserids);

	mem_strarray_free(serids, nserids);

	if (rc != 0)
		return (fmd_fmri_set_errno(EINVAL));

	return (0);
}

static int
serids_eq(char **serids1, uint_t nserids1, char **serids2, uint_t nserids2)
{
	int i;

	if (nserids1 != nserids2)
		return (0);

	for (i = 0; i < nserids1; i++) {
		if (strcmp(serids1[i], serids2[i]) != 0)
			return (0);
	}

	return (1);
}

int
fmd_fmri_present(nvlist_t *nvl)
{
	char *unum, **nvlserids, **serids;
	uint_t nnvlserids, nserids;
	int rc;

	if (mem.mem_dm == NULL)
		return (1); /* assume it's there - no s/n support here */

	if (mem_fmri_get_unum(nvl, &unum) < 0)
		return (-1); /* errno is set for us */

	if (nvlist_lookup_string_array(nvl, FM_FMRI_MEM_SERIAL_ID, &nvlserids,
	    &nnvlserids) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if (mem_get_serids_by_unum(unum, &serids, &nserids) < 0) {
		if (errno != ENOENT) {
			/*
			 * Errors are only signalled to the caller if they're
			 * the caller's fault.  This isn't - it's a failure on
			 * our part to burst or read the serial numbers.  We'll
			 * whine about it, and tell the caller the named
			 * module(s) isn't/aren't there.
			 */
			fmd_fmri_warn("failed to retrieve serial number for "
			    "unum %s", unum);
		}
		return (0);
	}

	rc = serids_eq(serids, nserids, nvlserids, nnvlserids);

	mem_strarray_free(serids, nserids);

	return (rc);
}

int
fmd_fmri_contains(nvlist_t *er, nvlist_t *ee)
{
	char *erunum, *eeunum;
	uint64_t erpa = 0, eepa = 0;

	if (mem_fmri_get_unum(er, &erunum) < 0 ||
	    mem_fmri_get_unum(ee, &eeunum) < 0)
		return (-1); /* errno is set for us */

	if (mem_unum_contains(erunum, eeunum) <= 0)
		return (0); /* can't parse/match, so assume no containment */

	if (nvlist_lookup_uint64(er, FM_FMRI_MEM_PHYSADDR, &erpa) == 0) {
		/* container has a PA; only match if containee has same PA */
		return (nvlist_lookup_uint64(ee, FM_FMRI_MEM_PHYSADDR,
		    &eepa) == 0 && erpa == eepa);
	}

	return (1);
}

int
fmd_fmri_unusable(nvlist_t *nvl)
{
	uint64_t pageaddr;
	uint8_t version;
	int rc, err;

	/*
	 * We can only make a usable/unusable determination for pages.  FMRIs
	 * without page addresses will be reported as usable.
	 */

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_MEM_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	if ((err = nvlist_lookup_uint64(nvl, FM_FMRI_MEM_PHYSADDR,
	    &pageaddr)) == ENOENT)
		return (0); /* no page, so assume it's still usable */
	else if (err != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if ((rc = mem_page_cmd(MEM_PAGE_ISRETIRED, pageaddr)) < 0 &&
	    errno == EIO) {
		return (0); /* the page wonders, "why all the fuss?" */
	} else if (rc == 0 || errno == EAGAIN || errno == EINVAL) {
		/*
		 * The page has been retired, is in the process of being
		 * retired, or doesn't exist.  The latter is valid if the page
		 * existed in the past but has been DR'd out.
		 */
		return (1);
	} else {
		/*
		 * Errors are only signalled to the caller if they're the
		 * caller's fault.  This isn't - it's a failure of the
		 * retirement-check code.  We'll whine about it and tell
		 * the caller the page is unusable.
		 */
		fmd_fmri_warn("failed to determine usability of page %llx",
		    pageaddr);
		return (1);
	}
}

int
fmd_fmri_init(void)
{
	bzero(&mem, sizeof (mem_t));
	return (mem_discover());
}

void
fmd_fmri_fini(void)
{
	mem_destroy();
}
