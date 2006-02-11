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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Page retirement can be an extended process due to the fact that a retirement
 * may not be possible when the original request is made.  The kernel will
 * repeatedly attempt to retire a given page, but will not let us know when the
 * page has been retired.  We therefore have to poll to see if the retirement
 * has been completed.  This poll is implemented with a bounded exponential
 * backoff to reduce the burden which we impose upon the system.
 *
 * To reduce the burden on fmd in the face of retirement storms, we schedule
 * all retries as a group.  In the simplest case, we attempt to retire a single
 * page.  When forced to retry, we initially schedule a retry at a configurable
 * interval t.  If the retry fails, we schedule another at 2 * t, and so on,
 * until t reaches the maximum interval (also configurable).  Future retries
 * for that page will occur with t equal to the maximum interval value.  We
 * will never give up on a retirement.
 *
 * With multiple retirements, the situation gets slightly more complicated.  As
 * indicated above, we schedule retries as a group.  We don't want to deny new
 * pages their short retry intervals, so we'll (re)set the retry interval to the
 * value appropriate for the newest page.
 */

#include <cma.h>

#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <sys/fm/protocol.h>
#include <sys/mem.h>

static int
cma_page_cmd(fmd_hdl_t *hdl, int cmd, nvlist_t *nvl)
{
	mem_page_t mpage;
	char *fmribuf;
	size_t fmrisz;
	int fd, rc, err;

	if ((fd = open("/dev/mem", O_RDONLY)) < 0)
		return (-1); /* errno is set for us */

	if ((errno = nvlist_size(nvl, &fmrisz, NV_ENCODE_NATIVE)) != 0 ||
	    fmrisz > MEM_FMRI_MAX_BUFSIZE ||
	    (fmribuf = fmd_hdl_alloc(hdl, fmrisz, FMD_SLEEP)) == NULL) {
		(void) close(fd);
		return (-1); /* errno is set for us */
	}

	if ((errno = nvlist_pack(nvl, &fmribuf, &fmrisz,
	    NV_ENCODE_NATIVE, 0)) != 0) {
		fmd_hdl_free(hdl, fmribuf, fmrisz);
		(void) close(fd);
		return (-1); /* errno is set for us */
	}

	mpage.m_fmri = fmribuf;
	mpage.m_fmrisz = fmrisz;

	if ((rc = ioctl(fd, cmd, &mpage)) < 0)
		err = errno;

	fmd_hdl_free(hdl, fmribuf, fmrisz);

	(void) close(fd);

	if (rc < 0) {
		errno = err;
		return (-1);
	}

	return (0);
}

static void
cma_page_free(fmd_hdl_t *hdl, cma_page_t *page)
{
	if (page->pg_fmri != NULL)
		nvlist_free(page->pg_fmri);
	fmd_hdl_free(hdl, page, sizeof (cma_page_t));
}

/*
 * Retire the specified ASRU, referring to a memory page by PA or by DIMM
 * offset (i.e. the encoded coordinates internal bank, row, and column).
 * In the initial FMA implementation, fault.memory.page exported an ASRU
 * with an explicit physical address, which is valid at the initial time of
 * diagnosis but may not be later following DR, DIMM removal, or interleave
 * changes.  On SPARC, this issue was solved by exporting the DIMM offset
 * and pushing the entire FMRI to the platform memory controller through
 * /dev/mem so it can derive the current PA from the DIMM and offset.
 * On x64, we also use DIMM and offset, but the mem:/// unum string is an
 * encoded hc:/// FMRI that is then used by the x64 memory controller driver.
 * At some point these three approaches need to be rationalized: all platforms
 * should use the same scheme, either with decoding in the kernel or decoding
 * in userland (i.e. with a libtopo method to compute and update the PA).
 */
/*ARGSUSED*/
void
cma_page_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru, const char *uuid)
{
	cma_page_t *page;
	uint64_t pageaddr;
	char *unumstr;
	nvlist_t *asrucp = NULL;

	/* It should already be expanded, but we'll do it again anyway */
	if (fmd_nvl_fmri_expand(hdl, asru) < 0) {
		fmd_hdl_debug(hdl, "failed to expand page asru\n");
		cma_stats.bad_flts.fmds_value.ui64++;
		return;
	}

	if (nvlist_lookup_uint64(asru, FM_FMRI_MEM_PHYSADDR, &pageaddr) != 0) {
		fmd_hdl_debug(hdl, "mem fault missing '%s'\n",
		    FM_FMRI_MEM_PHYSADDR);
		cma_stats.bad_flts.fmds_value.ui64++;
		return;
	}

	if (!cma.cma_page_doretire) {
		fmd_hdl_debug(hdl, "suppressed retire of page %llx\n",
		    (u_longlong_t)pageaddr);
		cma_stats.page_supp.fmds_value.ui64++;
		return;
	}

	if (!fmd_nvl_fmri_present(hdl, asru)) {
		fmd_hdl_debug(hdl, "page retire overtaken by events\n");
		cma_stats.page_nonent.fmds_value.ui64++;
		if (uuid != NULL)
			fmd_case_uuclose(hdl, uuid);
		return;
	}

	/*
	 * If the unum is an hc fmri string expand it to an fmri and include
	 * that in a modified asru nvlist.
	 */
	if (nvlist_lookup_string(asru, FM_FMRI_MEM_UNUM, &unumstr) == 0 &&
	    strncmp(unumstr, "hc:/", 4) == 0) {
		int err;
		nvlist_t *unumfmri;
		struct topo_hdl *thp = fmd_hdl_topology(hdl, TOPO_VERSION);

		if (topo_fmri_str2nvl(thp, unumstr, &unumfmri, &err) != 0) {
			fmd_hdl_debug(hdl, "page retire str2nvl failed: %s\n",
			    topo_strerror(err));
			return;
		}

		if (nvlist_dup(asru, &asrucp, 0) != 0) {
			fmd_hdl_debug(hdl, "page retire nvlist dup failed\n");
			nvlist_free(unumfmri);
			return;
		}

		if (nvlist_add_nvlist(asrucp, FM_FMRI_MEM_UNUM "-fmri",
		    unumfmri) != 0) {
			fmd_hdl_debug(hdl, "page retire failed to add "
			    "unumfmri to modified asru");
			nvlist_free(unumfmri);
			nvlist_free(asrucp);
			return;
		}
		nvlist_free(unumfmri);
	}

	if (cma_page_cmd(hdl, MEM_PAGE_FMRI_RETIRE,
	    asrucp ? asrucp : asru) == 0) {
		fmd_hdl_debug(hdl, "retired page 0x%llx\n",
		    (u_longlong_t)pageaddr);
		cma_stats.page_flts.fmds_value.ui64++;
		if (uuid != NULL)
			fmd_case_uuclose(hdl, uuid);
		if (asrucp)
			nvlist_free(asrucp);
		return;
	} else if (errno != EAGAIN) {
		fmd_hdl_debug(hdl, "retire of page 0x%llx failed, will not "
		    "retry: %s\n", (u_longlong_t)pageaddr, strerror(errno));
		if (asrucp)
			nvlist_free(asrucp);
		return;
	}

	/*
	 * The page didn't immediately retire.  We'll need to periodically
	 * check to see if it has been retired.
	 */
	fmd_hdl_debug(hdl, "page didn't retire - sleeping\n");

	page = fmd_hdl_zalloc(hdl, sizeof (cma_page_t), FMD_SLEEP);
	page->pg_addr = pageaddr;
	if (asrucp) {
		page->pg_fmri = asrucp;
	} else {
		(void) nvlist_dup(asru, &page->pg_fmri, 0);
	}
	if (uuid != NULL)
		page->pg_uuid = fmd_hdl_strdup(hdl, uuid, FMD_SLEEP);

	page->pg_next = cma.cma_pages;
	cma.cma_pages = page;

	if (cma.cma_page_timerid != 0)
		fmd_timer_remove(hdl, cma.cma_page_timerid);

	cma.cma_page_curdelay = cma.cma_page_mindelay;

	cma.cma_page_timerid =
	    fmd_timer_install(hdl, NULL, NULL, cma.cma_page_curdelay);
}

static int
page_retry(fmd_hdl_t *hdl, cma_page_t *page)
{
	if (page->pg_fmri != NULL && !fmd_nvl_fmri_present(hdl,
	    page->pg_fmri)) {
		fmd_hdl_debug(hdl, "page retire overtaken by events");
		cma_stats.page_nonent.fmds_value.ui64++;

		if (page->pg_uuid != NULL)
			fmd_case_uuclose(hdl, page->pg_uuid);
		return (1); /* no longer a page to retire */
	}

	if (cma_page_cmd(hdl, MEM_PAGE_FMRI_ISRETIRED, page->pg_fmri) == 0) {
		fmd_hdl_debug(hdl, "retired page 0x%llx on retry %u\n",
		    page->pg_addr, page->pg_nretries);
		cma_stats.page_flts.fmds_value.ui64++;

		if (page->pg_uuid != NULL)
			fmd_case_uuclose(hdl, page->pg_uuid);
		return (1); /* page retired */
	}

	if (errno == EAGAIN) {
		fmd_hdl_debug(hdl, "scheduling another retry for 0x%llx\n",
		    page->pg_addr);
		return (0); /* schedule another retry */
	} else {
		if (errno == EIO) {
			fmd_hdl_debug(hdl, "failed to retry page 0x%llx "
			    "retirement: page isn't scheduled for retirement\n",
			    page->pg_addr);
		} else {
			fmd_hdl_debug(hdl, "failed to retry page 0x%llx "
			    "retirement: %s\n", page->pg_addr,
			    strerror(errno));
		}

		cma_stats.page_fails.fmds_value.ui64++;
		return (1); /* give up */
	}
}

void
cma_page_retry(fmd_hdl_t *hdl)
{
	cma_page_t **pagep;

	cma.cma_page_timerid = 0;

	fmd_hdl_debug(hdl, "page_retry: timer fired\n");

	pagep = &cma.cma_pages;
	while (*pagep != NULL) {
		cma_page_t *page = *pagep;

		if (page_retry(hdl, page)) {
			/*
			 * Successful retry or we're giving up - remove from
			 * the list
			 */
			*pagep = page->pg_next;

			if (page->pg_uuid != NULL)
				fmd_hdl_strfree(hdl, page->pg_uuid);

			cma_page_free(hdl, page);
		} else if (cma.cma_page_maxretries == 0 ||
		    page->pg_nretries < cma.cma_page_maxretries) {
			page->pg_nretries++;
			pagep = &page->pg_next;
		} else {
			/*
			 * Tunable maxretries was set and we reached
			 * the max, so just close the case.
			 */
			fmd_hdl_debug(hdl,
			    "giving up page retire 0x%llx on retry %u\n",
			    page->pg_addr, page->pg_nretries);
			cma_stats.page_retmax.fmds_value.ui64++;

			if (page->pg_uuid != NULL) {
				fmd_case_uuclose(hdl, page->pg_uuid);
				fmd_hdl_strfree(hdl, page->pg_uuid);
			}

			*pagep = page->pg_next;

			cma_page_free(hdl, page);
		}
	}

	if (cma.cma_pages == NULL)
		return; /* no more retirements */

	/*
	 * We still have retirements that haven't completed.  Back the delay
	 * off, and schedule a retry.
	 */
	cma.cma_page_curdelay = MIN(cma.cma_page_curdelay * 2,
	    cma.cma_page_maxdelay);

	fmd_hdl_debug(hdl, "scheduled page retirement retry for %llu secs\n",
	    (u_longlong_t)(cma.cma_page_curdelay / NANOSEC));

	cma.cma_page_timerid =
	    fmd_timer_install(hdl, NULL, NULL, cma.cma_page_curdelay);
}

void
cma_page_fini(fmd_hdl_t *hdl)
{
	cma_page_t *page;

	while ((page = cma.cma_pages) != NULL) {
		cma.cma_pages = page->pg_next;
		cma_page_free(hdl, page);
	}
}
