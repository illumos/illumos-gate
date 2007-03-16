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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mem.h>
#include <fm/fmd_fmri.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/mem.h>

#ifdef	sparc
#include <sys/fm/ldom.h>
ldom_hdl_t *mem_scheme_lhp;
#endif	/* sparc */

mem_t mem;

#ifdef	sparc

extern int mem_update_mdesc(void);

/*
 * Retry values for handling the case where the kernel is not yet ready
 * to provide DIMM serial ids.  Some platforms acquire DIMM serial id
 * information from their System Controller via a mailbox interface.
 * The values chosen are for 10 retries 3 seconds apart to approximate the
 * possible 30 second timeout length of a mailbox message request.
 */
#define	MAX_MEM_SID_RETRIES	10
#define	MEM_SID_RETRY_WAIT	3

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
mem_get_parts_from_mdesc(const char *unum, char ***partsp, size_t *npartsp)
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
mem_get_parts_by_unum(const char *unum, char ***partp, size_t *npartp)
{
	if (mem.mem_dm == NULL)
		return (-1);
	else
		return (mem_get_parts_from_mdesc(unum, partp, npartp));
}

#endif	/* sparc */

/*ARGSUSED*/

static int
mem_get_serids_by_unum(const char *unum, char ***seridsp, size_t *nseridsp)
{
	/*
	 * Some platforms do not support the caching of serial ids by the
	 * mem scheme plugin but instead support making serial ids available
	 * via the kernel.
	 */
#ifdef	sparc
	if (mem.mem_dm == NULL)
		return (mem_get_serids_from_kernel(unum, seridsp, nseridsp));
	else if (mem_get_serids_from_mdesc(unum, seridsp, nseridsp) == 0)
		return (0);
	else
		return (mem_get_serids_from_cache(unum, seridsp, nseridsp));
#else
	errno = ENOTSUP;
	return (-1);
#endif	/* sparc */
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
	char format[64];
	ssize_t size, presz;
	char *rawunum, *preunum, *escunum, *prefix;
	uint64_t val;
	int i;

	if (mem_fmri_get_unum(nvl, &rawunum) < 0)
		return (-1); /* errno is set for us */

	/*
	 * If we have a well-formed unum (hc-FMRI), use the string verbatim
	 * to form the initial mem:/// components.  Otherwise use unum=%s.
	 */
	if (strncmp(rawunum, "hc://", 5) != 0)
		prefix = FM_FMRI_MEM_UNUM "=";
	else
		prefix = "";

	/*
	 * If we have a DIMM offset, include it in the string.  If we have a PA
	 * then use that.  Otherwise just format the unum element.
	 */
	if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_OFFSET, &val) == 0) {
		(void) snprintf(format, sizeof (format),
		    "%s:///%s%%1$s/%s=%%2$llx",
		    FM_FMRI_SCHEME_MEM, prefix, FM_FMRI_MEM_OFFSET);
	} else if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_PHYSADDR, &val) == 0) {
		(void) snprintf(format, sizeof (format),
		    "%s:///%s%%1$s/%s=%%2$llx",
		    FM_FMRI_SCHEME_MEM, prefix, FM_FMRI_MEM_PHYSADDR);
	} else {
		(void) snprintf(format, sizeof (format),
		    "%s:///%s%%1$s", FM_FMRI_SCHEME_MEM, prefix);
	}

	/*
	 * If we have a well-formed unum (hc-FMRI), we skip over the
	 * the scheme and authority prefix.
	 * Otherwise, the spaces and colons will be escaped,
	 * rendering the resulting FMRI pretty much unreadable.
	 * We're therefore going to do some escaping of our own first.
	 */
	if (strncmp(rawunum, "hc://", 5) == 0) {
		rawunum += 5;
		rawunum = strchr(rawunum, '/');
		++rawunum;
		/* LINTED: variable format specifier */
		size = snprintf(buf, buflen, format, rawunum, val);
	} else {
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

		/* LINTED: variable format specifier */
		size = snprintf(buf, buflen, format, escunum, val);
		fmd_fmri_strfree(escunum);
	}

	return (size);
}

int
fmd_fmri_expand(nvlist_t *nvl)
{
	char *unum, **serids;
	uint_t nnvlserids;
	size_t nserids;
#ifdef sparc
	char **parts;
	size_t nparts;
#endif
	int rc;

	if (mem_fmri_get_unum(nvl, &unum) < 0)
		return (fmd_fmri_set_errno(EINVAL));

	if ((rc = nvlist_lookup_string_array(nvl, FM_FMRI_MEM_SERIAL_ID,
	    &serids, &nnvlserids)) == 0)
		return (0); /* fmri is already expanded */
	else if (rc != ENOENT)
		return (fmd_fmri_set_errno(EINVAL));

	if (mem_get_serids_by_unum(unum, &serids, &nserids) < 0) {
		/* errno is set for us */
		if (errno == ENOTSUP)
			return (0); /* nothing to add - no s/n support */
		else
			return (-1);
	}

	rc = nvlist_add_string_array(nvl, FM_FMRI_MEM_SERIAL_ID, serids,
	    nserids);

	mem_strarray_free(serids, nserids);

	if (rc != 0)
		return (fmd_fmri_set_errno(EINVAL));

#ifdef sparc
	/*
	 * Continue with the process if there are no part numbers.
	 */
	if (mem_get_parts_by_unum(unum, &parts, &nparts) < 0)
		return (0);

	rc = nvlist_add_string_array(nvl, FM_FMRI_HC_PART, parts, nparts);

	mem_strarray_free(parts, nparts);
#endif
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
	uint_t nnvlserids;
	size_t nserids;
	uint64_t memconfig;
	int rc;

	if (mem_fmri_get_unum(nvl, &unum) < 0)
		return (-1); /* errno is set for us */

	if (nvlist_lookup_string_array(nvl, FM_FMRI_MEM_SERIAL_ID, &nvlserids,
	    &nnvlserids) != 0) {
		/*
		 * Some mem scheme FMRIs don't have serial ids because
		 * either the platform does not support them, or because
		 * the FMRI was created before support for serial ids was
		 * introduced.  If this is the case, assume it is there.
		 */
		if (mem.mem_dm == NULL)
			return (1);
		else
			return (fmd_fmri_set_errno(EINVAL));
	}

	/*
	 * Hypervisor will change the memconfig value when the mapping of
	 * pages to DIMMs changes, e.g. for change in DIMM size or interleave.
	 * If we detect such a change, we discard ereports associated with a
	 * previous memconfig value as invalid.
	 *
	 * The test (mem.mem_memconfig != 0) means we run on a system that
	 * actually suplies a memconfig value.
	 */

	if ((nvlist_lookup_uint64(nvl, FM_FMRI_MEM_MEMCONFIG,
	    &memconfig) == 0) && (mem.mem_memconfig != 0) &&
	    (memconfig != mem.mem_memconfig))
		return (0);

	if (mem_get_serids_by_unum(unum, &serids, &nserids) < 0) {
		if (errno == ENOTSUP)
			return (1); /* assume it's there, no s/n support here */
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
	uint64_t erval = 0, eeval = 0;

	if (mem_fmri_get_unum(er, &erunum) < 0 ||
	    mem_fmri_get_unum(ee, &eeunum) < 0)
		return (-1); /* errno is set for us */

	if (mem_unum_contains(erunum, eeunum) <= 0)
		return (0); /* can't parse/match, so assume no containment */

	if (nvlist_lookup_uint64(er, FM_FMRI_MEM_OFFSET, &erval) == 0) {
		return (nvlist_lookup_uint64(ee,
		    FM_FMRI_MEM_OFFSET, &eeval) == 0 && erval == eeval);
	}

	if (nvlist_lookup_uint64(er, FM_FMRI_MEM_PHYSADDR, &erval) == 0) {
		return (nvlist_lookup_uint64(ee,
		    FM_FMRI_MEM_PHYSADDR, &eeval) == 0 && erval == eeval);
	}

	return (1);
}

/*
 * We can only make a usable/unusable determination for pages.  Mem FMRIs
 * without page addresses will be reported as usable since Solaris has no
 * way at present to dynamically disable an entire DIMM or DIMM pair.
 */
int
fmd_fmri_unusable(nvlist_t *nvl)
{
	uint64_t val;
	uint8_t version;
	int rc, err1, err2;
	nvlist_t *nvlcp = NULL;
	int retval;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_MEM_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	err1 = nvlist_lookup_uint64(nvl, FM_FMRI_MEM_OFFSET, &val);
	err2 = nvlist_lookup_uint64(nvl, FM_FMRI_MEM_PHYSADDR, &val);

	if (err1 == ENOENT && err2 == ENOENT)
		return (0); /* no page, so assume it's still usable */

	if ((err1 != 0 && err1 != ENOENT) || (err2 != 0 && err2 != ENOENT))
		return (fmd_fmri_set_errno(EINVAL));

	if ((err1 = mem_unum_rewrite(nvl, &nvlcp)) != 0)
		return (fmd_fmri_set_errno(err1));

	/*
	 * Ask the kernel if the page is retired, using either the rewritten
	 * hc FMRI or the original mem FMRI with the specified offset or PA.
	 * Refer to the kernel's page_retire_check() for the error codes.
	 */
	rc = mem_page_cmd(MEM_PAGE_FMRI_ISRETIRED, nvlcp ? nvlcp : nvl);

	if (rc == -1 && errno == EIO) {
		/*
		 * The page is not retired and is not scheduled for retirement
		 * (i.e. no request pending and has not seen any errors)
		 */
		retval = 0;
	} else if (rc == 0 || errno == EAGAIN || errno == EINVAL) {
		/*
		 * The page has been retired, is in the process of being
		 * retired, or doesn't exist.  The latter is valid if the page
		 * existed in the past but has been DR'd out.
		 */
		retval = 1;
	} else {
		/*
		 * Errors are only signalled to the caller if they're the
		 * caller's fault.  This isn't - it's a failure of the
		 * retirement-check code.  We'll whine about it and tell
		 * the caller the page is unusable.
		 */
		fmd_fmri_warn("failed to determine page %s=%llx usability: "
		    "rc=%d errno=%d\n", err1 == 0 ? FM_FMRI_MEM_OFFSET :
		    FM_FMRI_MEM_PHYSADDR, (u_longlong_t)val, rc, errno);
		retval = 1;
	}

	if (nvlcp)
		nvlist_free(nvlcp);

	return (retval);
}

int
fmd_fmri_init(void)
{
#ifdef	sparc
	mem_scheme_lhp = ldom_init(fmd_fmri_alloc, fmd_fmri_free);
#endif	/* sparc */
	return (mem_discover());
}

void
fmd_fmri_fini(void)
{
	mem_dimm_map_t *dm, *em;

	for (dm = mem.mem_dm; dm != NULL; dm = em) {
		em = dm->dm_next;
		fmd_fmri_strfree(dm->dm_label);
		fmd_fmri_strfree(dm->dm_device);
		fmd_fmri_free(dm, sizeof (mem_dimm_map_t));
	}
#ifdef	sparc
	ldom_fini(mem_scheme_lhp);
#endif	/* sparc */
}
