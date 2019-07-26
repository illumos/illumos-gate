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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <procfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include "rcapd.h"
#include "rcapd_rfd.h"
#include "rcapd_mapping.h"
#include "utils.h"

static int lpc_xmap_update(lprocess_t *);
#ifdef DEBUG
extern int lmapping_dump_diff(lmapping_t *lm1, lmapping_t *lm2);
#endif /* DEBUG */

/*
 * The number of file descriptors required to grab a process and create an
 * agent in it.
 */
#define	PGRAB_FD_COUNT		10

/*
 * Record a position in an address space as it corresponds to a prpageheader_t
 * and affiliated structures.
 */
typedef struct prpageheader_cur {
	int pr_nmap;		/* number of mappings in address space */
	int pr_map;		/* number of this mapping */
	uint64_t pr_pgoff;	/* page offset into mapping */
	uint64_t pr_npage;	/* number of pages in mapping */
	uint64_t pr_pagesize;	/* page size of mapping */
	uintptr_t pr_addr;	/* base of mapping */
	prpageheader_t *pr_prpageheader;	/* associated page header */
	void *pr_pdaddr;	/* address of page's byte in pagedata */
	prxmap_t *pr_xmap;	/* array containing per-segment information */
	int pr_nxmap;		/* number of xmaps in array */
	int64_t pr_rss;		/* number of resident pages in mapping, */
				/* or -1 if xmap is out of sync */
	int64_t pr_pg_rss;	/* number of pageable pages in mapping, or -1 */
} prpageheader_cur_t;

static struct ps_prochandle *scan_pr;	/* currently-scanned process's handle */

typedef enum {
	STDL_NORMAL,
	STDL_HIGH
} st_debug_level_t;

/*
 * Output a scanning-related debug message.
 */
/*PRINTFLIKE3*/ /*ARGSUSED*/
static void
st_debug(st_debug_level_t level, lcollection_t *lcol, char *msg, ...)
{
#ifdef DEBUG_MSG
	va_list alist;
	char *buf;
	size_t len;

	if (get_message_priority() < ((level == STDL_HIGH) ? RCM_DEBUG_HIGH
	    : RCM_DEBUG))
		return;

	len = strlen(msg) + LINELEN;
	buf = malloc(len);
	if (buf == NULL)
		return;
	(void) snprintf(buf, len, "%s %s scanner %s",
	    (lcol->lcol_id.rcid_type == RCIDT_PROJECT ? "project" : "zone"),
	    lcol->lcol_name, msg);

	va_start(alist, msg);
	vdprintfe(RCM_DEBUG, buf, alist);
	va_end(alist);

	free(buf);
#endif /* DEBUG_MSG */
}

/*
 * Determine the collection's current victim, based on its last.  The last will
 * be returned, or, if invalid, any other valid process, if the collection has
 * any.
 */
static lprocess_t *
get_valid_victim(lcollection_t *lcol, lprocess_t *lpc)
{
	if (lpc == NULL || !lcollection_member(lcol, lpc))
		lpc = lcol->lcol_lprocess;

	/*
	 * Find the next scannable process, and make it the victim.
	 */
	while (lpc != NULL && lpc->lpc_unscannable != 0)
		lpc = lpc->lpc_next;

	return (lpc);
}

/*
 * Get a process's combined current pagedata (per-page referenced and modified
 * bits) and set the supplied pointer to it.  The caller is responsible for
 * freeing the data.  If the pagedata is unreadable, a nonzero value is
 * returned, and errno is set.  Otherwise, 0 is returned.
 */
static int
get_pagedata(prpageheader_t **pghpp, int fd)
{
	int res;
	struct stat st;

redo:
	errno = 0;
	if (fstat(fd, &st) != 0) {
		debug("cannot stat pagedata\n");
		return (-1);
	}

	errno = 0;
	*pghpp = malloc(st.st_size);
	if (*pghpp == NULL) {
		debug("cannot malloc() %ld bytes for pagedata", st.st_size);
		return (-1);
	}
	(void) bzero(*pghpp, st.st_size);

	errno = 0;
	if ((res = read(fd, *pghpp, st.st_size)) != st.st_size) {
		free(*pghpp);
		*pghpp = NULL;
		if (res > 0 || errno == E2BIG) {
			debug("pagedata changed size, retrying\n");
			goto redo;
		} else {
			debug("cannot read pagedata");
			return (-1);
		}
	}

	return (0);
}

/*
 * Return the count of kilobytes of pages represented by the given pagedata
 * which meet the given criteria, having pages which are in all of the states
 * specified by the mask, and in none of the states in the notmask.  If the
 * CP_CLEAR flag is set, the pagedata will also be cleared.
 */
#define	CP_CLEAR	1
static uint64_t
count_pages(prpageheader_t *pghp, int flags, int mask, int notmask)
{
	int map;
	caddr_t cur, end;
	prpageheader_t pgh = *pghp;
	prasmap_t *asmapp;
	uint64_t count = 0;

	cur = (caddr_t)pghp + sizeof (*pghp);
	for (map = 0; map < pgh.pr_nmap; map++) {
		asmapp = (prasmap_t *)(uintptr_t)cur;
		cur += sizeof (*asmapp);
		end = cur + asmapp->pr_npage;
		while (cur < end) {
			if ((*cur & mask) == mask && (*cur & notmask) == 0)
				count += asmapp->pr_pagesize / 1024;
			if ((flags & CP_CLEAR) != 0)
				*cur = 0;
			cur++;
		}

		/*
		 * Skip to next 64-bit-aligned address to get the next
		 * prasmap_t.
		 */
		cur = (caddr_t)((intptr_t)(cur + 7) & ~7);
	}

	return (count);
}

/*
 * Return the amount of memory (in kilobytes) that hasn't been referenced or
 * modified, which memory which will be paged out first.  Should be written to
 * exclude nonresident pages when sufficient interfaces exist.
 */
static uint64_t
unrm_size(lprocess_t *lpc)
{
	return (count_pages(lpc->lpc_prpageheader, CP_CLEAR,
	    0, PG_MODIFIED | PG_REFERENCED));
}

/*
 * Advance a prpageheader_cur_t to the address space's next mapping, returning
 * its address, or NULL if there is none.  Any known nonpageable or nonresident
 * mappings will be skipped over.
 */
static uintptr_t
advance_prpageheader_cur_nextmapping(prpageheader_cur_t *pcp)
{
	prasmap_t *pap;
	int i;

next:
	ASSERT(pcp->pr_map < pcp->pr_nmap);
	if ((pcp->pr_map + 1) == pcp->pr_nmap)
		return ((uintptr_t)NULL);
	pcp->pr_map++;
	if (pcp->pr_pgoff < pcp->pr_npage) {
		pcp->pr_pdaddr = (caddr_t)(uintptr_t)
		    ((uintptr_t)pcp->pr_pdaddr +
		    (pcp->pr_npage - pcp->pr_pgoff));
		pcp->pr_pgoff = pcp->pr_npage;
	}
	/*
	 * Skip to next 64-bit-aligned address to get the next prasmap_t.
	 */
	pcp->pr_pdaddr = (caddr_t)(((uintptr_t)pcp->pr_pdaddr + 7) & ~7);
	pap = (prasmap_t *)pcp->pr_pdaddr;
	pcp->pr_pgoff = 0;
	pcp->pr_npage = pap->pr_npage;
	pcp->pr_pagesize = pap->pr_pagesize;
	pcp->pr_addr = pap->pr_vaddr;
	pcp->pr_pdaddr = pap + 1;

	/*
	 * Skip any known nonpageable mappings.  Currently, the only one
	 * detected is the schedctl page.
	 */
	if ((pap->pr_mflags ^ (MA_SHARED | MA_READ | MA_WRITE | MA_EXEC |
	    MA_ANON)) == 0 && pap->pr_npage == 1) {
		debug("identified nonpageable schedctl mapping at %p\n",
		    (void *)pcp->pr_addr);
		goto next;
	}

	/*
	 * Skip mappings with no resident pages.  If the xmap does not
	 * correspond to the pagedata for any reason, it will be ignored.
	 */
	pcp->pr_rss = -1;
	pcp->pr_pg_rss = -1;
	for (i = 0; i < pcp->pr_nxmap; i++) {
		prxmap_t *xmap = &pcp->pr_xmap[i];

		if (pcp->pr_addr == xmap->pr_vaddr && xmap->pr_size ==
		    (pcp->pr_npage * pcp->pr_pagesize)) {
			pcp->pr_rss = xmap->pr_rss;
			/*
			 * Remove COW pages from the pageable RSS count.
			 */
			if ((xmap->pr_mflags & MA_SHARED) == 0)
				pcp->pr_pg_rss = xmap->pr_anon;
			break;
		}
	}
	if (pcp->pr_rss == 0) {
		debug("identified nonresident mapping at 0x%p\n",
		    (void *)pcp->pr_addr);
		goto next;
	} else if (pcp->pr_pg_rss == 0) {
		debug("identified unpageable mapping at 0x%p\n",
		    (void *)pcp->pr_addr);
		goto next;
	}

	return (pcp->pr_addr);
}

/*
 * Advance a prpageheader_cur_t to the mapping's next page, returning its
 * address, or NULL if there is none.
 */
static void *
advance_prpageheader_cur(prpageheader_cur_t *pcp)
{
	ASSERT(pcp->pr_pgoff < pcp->pr_npage);
	if ((pcp->pr_pgoff + 1) == pcp->pr_npage)
		return (NULL);
	pcp->pr_pdaddr = (caddr_t)pcp->pr_pdaddr + 1;
	pcp->pr_pgoff++;

	ASSERT((*(char *)pcp->pr_pdaddr & ~(PG_MODIFIED | PG_REFERENCED)) == 0);
	return ((caddr_t)pcp->pr_addr + pcp->pr_pgoff * pcp->pr_pagesize);
}

/*
 * Initialize a prpageheader_cur_t, positioned at the first page of the mapping
 * of an address space.
 */
static void *
set_prpageheader_cur(prpageheader_cur_t *pcp, prpageheader_t *php,
    prxmap_t *xmap, int nxmap)
{
	bzero(pcp, sizeof (*pcp));
	pcp->pr_nmap = php->pr_nmap;
	pcp->pr_map = -1;
	pcp->pr_prpageheader = php;
	pcp->pr_xmap = xmap;
	pcp->pr_nxmap = nxmap;
	pcp->pr_pdaddr = (prpageheader_t *)php + 1;

	return ((void *)advance_prpageheader_cur_nextmapping(pcp));
}

/*
 * Position a prpageheader_cur_t to the mapped address greater or equal to the
 * given value.
 */
static void *
set_prpageheader_cur_addr(prpageheader_cur_t *pcp, prpageheader_t *php,
    prxmap_t *xmap, int nxmap, void *naddr)
{
	void *addr = set_prpageheader_cur(pcp, php, xmap, nxmap);

	while (addr != NULL && addr <= naddr)
		if (naddr < (void *)((caddr_t)pcp->pr_addr +
		    pcp->pr_pagesize * pcp->pr_npage)) {
			uint64_t pgdiff = ((uintptr_t)naddr -
			    (uintptr_t)pcp->pr_addr) / pcp->pr_pagesize;
			pcp->pr_pgoff += pgdiff;
			pcp->pr_pdaddr = (caddr_t)pcp->pr_pdaddr + pgdiff;
			addr = (caddr_t)pcp->pr_addr + pcp->pr_pagesize *
			    pcp->pr_pgoff;
			break;
		} else
			addr =
			    (void *)advance_prpageheader_cur_nextmapping(pcp);

	return (addr);
}

static void
revoke_pagedata(rfd_t *rfd)
{
	lprocess_t *lpc = rfd->rfd_data;

	st_debug(STDL_NORMAL, lpc->lpc_collection, "revoking pagedata for"
	    " process %d\n", (int)lpc->lpc_pid);
	ASSERT(lpc->lpc_pgdata_fd != -1);
	lpc->lpc_pgdata_fd = -1;
}

#ifdef DEBUG
static void
mklmapping(lmapping_t **lm, prpageheader_t *pgh)
{
	prpageheader_cur_t cur;
	void *addr;

	addr = set_prpageheader_cur(&cur, pgh, NULL, -1);
	ASSERT(*lm == NULL);
	while (addr != NULL) {
		(void) lmapping_insert(lm, cur.pr_addr, cur.pr_npage *
		    cur.pr_pagesize);
		addr = (void *)advance_prpageheader_cur_nextmapping(&cur);
	}
}

static void
lmapping_dump(lmapping_t *lm)
{
	debug("lm: %p\n", (void *)lm);
	while (lm != NULL) {
		debug("\t(%p, %llx\n", (void *)lm->lm_addr,
		    (unsigned long long)lm->lm_size);
		lm = lm->lm_next;
	}
}
#endif /* DEBUG */

/*
 * OR two prpagedata_t which are supposedly snapshots of the same address
 * space.  Intersecting mappings with different page sizes are tolerated but
 * not normalized (not accurate).  If the mappings of the two snapshots differ
 * in any regard, the supplied mappings_changed flag will be set.
 */
static void
OR_pagedata(prpageheader_t *src, prpageheader_t *dst, int *mappings_changedp)
{
	prpageheader_cur_t src_cur;
	prpageheader_cur_t dst_cur;
	uintptr_t src_addr;
	uintptr_t dst_addr;
	int mappings_changed = 0;

	/*
	 * OR source pagedata with the destination, for pages of intersecting
	 * mappings.
	 */
	src_addr = (uintptr_t)set_prpageheader_cur(&src_cur, src, NULL, -1);
	dst_addr = (uintptr_t)set_prpageheader_cur(&dst_cur, dst, NULL, -1);
	while (src_addr != (uintptr_t)NULL && dst_addr != (uintptr_t)NULL) {
		while (src_addr == dst_addr && src_addr != (uintptr_t)NULL) {
			*(char *)dst_cur.pr_pdaddr |=
			    *(char *)src_cur.pr_pdaddr;
			src_addr = (uintptr_t)advance_prpageheader_cur(
			    &src_cur);
			dst_addr = (uintptr_t)advance_prpageheader_cur(
			    &dst_cur);
		}
		if (src_addr != dst_addr)
			mappings_changed = 1;
		src_addr = advance_prpageheader_cur_nextmapping(&src_cur);
		dst_addr = advance_prpageheader_cur_nextmapping(&dst_cur);
		while (src_addr != dst_addr && src_addr != (uintptr_t)NULL &&
		    dst_addr != (uintptr_t)NULL) {
			mappings_changed = 1;
			if (src_addr < dst_addr)
				src_addr = advance_prpageheader_cur_nextmapping(
				    &src_cur);
			else
				dst_addr = advance_prpageheader_cur_nextmapping(
				    &dst_cur);
		}
	}

	*mappings_changedp = mappings_changed;
}

/*
 * Merge the current pagedata with that on hand.  If the pagedata is
 * unretrievable for any reason, such as the process having exited or being a
 * zombie, a nonzero value is returned, the process should be marked
 * unscannable, and future attempts to scan it should be avoided, since the
 * symptom is probably permament.  If the mappings of either pagedata
 * differ in any respect, the supplied callback will be invoked once.
 */
static int
merge_current_pagedata(lprocess_t *lpc,
    void(*mappings_changed_cb) (lprocess_t *))
{
	prpageheader_t *pghp;
	int mappings_changed = 0;
	uint64_t cnt;

	if (lpc->lpc_pgdata_fd < 0 || get_pagedata(&pghp, lpc->lpc_pgdata_fd) !=
	    0) {
		char pathbuf[PROC_PATH_MAX];

		(void) snprintf(pathbuf, sizeof (pathbuf), "/proc/%d/pagedata",
		    (int)lpc->lpc_pid);
		if ((lpc->lpc_pgdata_fd = rfd_open(pathbuf, 1, RFD_PAGEDATA,
		    revoke_pagedata, lpc, O_RDONLY, 0)) < 0 ||
		    get_pagedata(&pghp, lpc->lpc_pgdata_fd) != 0)
			return (-1);
		debug("starting/resuming pagedata collection for %d\n",
		    (int)lpc->lpc_pid);
	}

	cnt = count_pages(pghp, 0, PG_MODIFIED | PG_REFERENCED, 0);
	if (cnt != 0 || lpc->lpc_rss != 0)
		debug("process %d: %llu/%llukB rfd/mdfd since last read\n",
		    (int)lpc->lpc_pid, (unsigned long long)cnt,
		    (unsigned long long)lpc->lpc_rss);
	if (lpc->lpc_prpageheader != NULL) {
		/*
		 * OR the two snapshots.
		 */
#ifdef DEBUG
		lmapping_t *old = NULL;
		lmapping_t *new = NULL;

		mklmapping(&new, pghp);
		mklmapping(&old, lpc->lpc_prpageheader);
#endif /* DEBUG */
		OR_pagedata(lpc->lpc_prpageheader, pghp, &mappings_changed);
#ifdef DEBUG
		if (((mappings_changed != 0) ^
		    (lmapping_dump_diff(old, new) != 0))) {
			debug("lmapping_changed inconsistent with lmapping\n");
			debug("old\n");
			lmapping_dump(old);
			debug("new\n");
			lmapping_dump(new);
			debug("ignored\n");
			lmapping_dump(lpc->lpc_ignore);
			ASSERT(0);
		}
		lmapping_free(&new);
		lmapping_free(&old);
#endif /* DEBUG */
		free(lpc->lpc_prpageheader);
	} else
		mappings_changed = 1;
	lpc->lpc_prpageheader = pghp;

	cnt = count_pages(pghp, 0, PG_MODIFIED | PG_REFERENCED, 0);
	if (cnt != 0 || lpc->lpc_rss != 0)
		debug("process %d: %llu/%llukB rfd/mdfd since hand swept\n",
		    (int)lpc->lpc_pid, (unsigned long long)cnt,
		    (unsigned long long)lpc->lpc_rss);
	if (mappings_changed != 0) {
		debug("process %d: mappings changed\n", (int)lpc->lpc_pid);
		if (mappings_changed_cb != NULL)
			mappings_changed_cb(lpc);
	}
	return (0);
}

/*
 * Attempt to page out a region of the given process's address space.  May
 * return nonzero if not all of the pages may are pageable, for any reason.
 */
static int
pageout(pid_t pid, struct ps_prochandle *Pr, caddr_t start, caddr_t end)
{
	int res;

	if (end <= start)
		return (0);

	errno = 0;
	res = pr_memcntl(Pr, start, (end - start), MC_SYNC,
	    (caddr_t)(MS_ASYNC | MS_INVALCURPROC), 0, 0);
	debug_high("pr_memcntl [%p-%p): %d", (void *)start, (void *)end, res);

	/*
	 * EBUSY indicates none of the pages have backing store allocated, or
	 * some pages were locked, which are less interesting than other
	 * conditions, which are noted.
	 */
	if (res != 0)
		if (errno == EBUSY)
			res = 0;
		else
			debug("%d: can't pageout %p+%llx (errno %d)", (int)pid,
			    (void *)start, (long long)(end - start), errno);

	return (res);
}

/*
 * Compute the delta of the victim process's RSS since the last call.  If the
 * psinfo cannot be obtained, no work is done, and no error is returned; it is
 * up to the caller to detect the process' termination via other means.
 */
static int64_t
rss_delta(psinfo_t *new_psinfo, psinfo_t *old_psinfo, lprocess_t *vic)
{
	int64_t d_rss = 0;

	if (get_psinfo(vic->lpc_pid, new_psinfo, vic->lpc_psinfo_fd,
	    lprocess_update_psinfo_fd_cb, vic, vic) == 0) {
		d_rss = (int64_t)new_psinfo->pr_rssize -
		    (int64_t)old_psinfo->pr_rssize;
		if (d_rss < 0)
			vic->lpc_collection->lcol_stat.lcols_pg_eff +=
			    (- d_rss);
		*old_psinfo = *new_psinfo;
	}

	return (d_rss);
}

static void
unignore_mappings(lprocess_t *lpc)
{
	lmapping_free(&lpc->lpc_ignore);
}

static void
unignore_referenced_mappings(lprocess_t *lpc)
{
	prpageheader_cur_t cur;
	void *vicaddr;

	vicaddr = set_prpageheader_cur(&cur, lpc->lpc_prpageheader, NULL, -1);
	while (vicaddr != NULL) {
		if (((*(char *)cur.pr_pdaddr) & (PG_REFERENCED | PG_MODIFIED))
		    != 0) {
			if (lmapping_remove(&lpc->lpc_ignore, cur.pr_addr,
			    cur.pr_npage * cur.pr_pagesize) == 0)
				debug("removed mapping 0x%p+0t%llukB from"
				    " ignored set\n", (void *)cur.pr_addr,
				    (unsigned long long)(cur.pr_npage *
				    cur.pr_pagesize / 1024));
			vicaddr = (void *)advance_prpageheader_cur_nextmapping(
			    &cur);
		} else if ((vicaddr = advance_prpageheader_cur(&cur)) == NULL)
			vicaddr = (void *)advance_prpageheader_cur_nextmapping(
			    &cur);
	}
}

/*
 * Resume scanning, starting with the last victim, if it is still valid, or any
 * other one, otherwise.
 */
void
scan(lcollection_t *lcol, int64_t excess)
{
	lprocess_t *vic, *lpc;
	void *vicaddr, *endaddr, *nvicaddr;
	prpageheader_cur_t cur;
	psinfo_t old_psinfo, new_psinfo;
	hrtime_t scan_start;
	int res, resumed;
	uint64_t col_unrm_size;

	st_debug(STDL_NORMAL, lcol, "starting to scan, excess %lldk\n",
	    (long long)excess);

	/*
	 * Determine the address to start scanning at, depending on whether
	 * scanning can be resumed.
	 */
	endaddr = NULL;
	if ((vic = get_valid_victim(lcol, lcol->lcol_victim)) ==
	    lcol->lcol_victim && lcol->lcol_resaddr != NULL) {
		vicaddr = lcol->lcol_resaddr;
		st_debug(STDL_NORMAL, lcol, "resuming process %d\n",
		    (int)vic->lpc_pid);
		resumed = 1;
	} else {
		vicaddr = NULL;
		resumed = 0;
	}

	scan_start = gethrtime();
	/*
	 * Obtain the most current pagedata for the processes that might be
	 * scanned, and remove from the ignored set any mappings which have
	 * referenced or modified pages (in the hopes that the pageability of
	 * the mapping's pages may have changed).  Determine if the
	 * unreferenced and unmodified portion is impossibly small to suffice
	 * to reduce the excess completely.  If so, ignore these bits so that
	 * even working set will be paged out.
	 */
	col_unrm_size = 0;
	lpc = vic;
	while (lpc != NULL && should_run) {
		if (merge_current_pagedata(lpc, unignore_mappings) != 0) {
			st_debug(STDL_NORMAL, lcol, "process %d:"
			    " exited/temporarily unscannable",
			    (int)lpc->lpc_pid);
			goto next;
		}
		debug("process %d: %llu/%llukB scannable\n", (int)lpc->lpc_pid,
		    (unsigned long long)(lpc->lpc_unrm = unrm_size(lpc)),
		    (unsigned long long)lpc->lpc_size);
		col_unrm_size += lpc->lpc_unrm = unrm_size(lpc);

		if ((lcol->lcol_stat.lcols_scan_count %
		    RCAPD_IGNORED_SET_FLUSH_IVAL) == 0) {
			/*
			 * Periodically clear the set of ignored mappings.
			 * This will allow processes whose ignored segments'
			 * pageability have changed (without a corresponding
			 * reference or modification to a page) to be
			 * recognized.
			 */
			if (lcol->lcol_stat.lcols_scan_count > 0)
				unignore_mappings(lpc);
		} else {
			/*
			 * Ensure mappings with referenced or modified pages
			 * are not in the ignored set.  Their usage might mean
			 * the condition which made them unpageable is gone.
			 */
			unignore_referenced_mappings(lpc);
		}
next:
		lpc = lpc->lpc_next != NULL ? get_valid_victim(lcol,
		    lpc->lpc_next) : NULL;
	}
	if (col_unrm_size < excess) {
		lpc = vic;
		debug("will not reduce excess with only unreferenced pages\n");
		while (lpc != NULL && should_run) {
			if (lpc->lpc_prpageheader != NULL) {
				(void) count_pages(lpc->lpc_prpageheader,
				    CP_CLEAR, 0, 0);
				if (lpc->lpc_pgdata_fd >= 0) {
					if (rfd_close(lpc->lpc_pgdata_fd) != 0)
						debug("coud not close %d"
						    " lpc_pgdata_fd %d",
						    (int)lpc->lpc_pid,
						    lpc->lpc_pgdata_fd);
					lpc->lpc_pgdata_fd = -1;
				}
			}
			lpc = lpc->lpc_next != NULL ? get_valid_victim(lcol,
			    lpc->lpc_next) : NULL;
		}
	}

	/*
	 * Examine each process for pages to remove until the excess is
	 * reduced.
	 */
	while (vic != NULL && excess > 0 && should_run) {
		/*
		 * Skip processes whose death was reported when the merging of
		 * pagedata was attempted.
		 */
		if (vic->lpc_prpageheader == NULL)
			goto nextproc;

		/*
		 * Obtain optional segment residency information.
		 */
		if (lpc_xmap_update(vic) != 0)
			st_debug(STDL_NORMAL, lcol, "process %d: xmap"
			    " unreadable; ignoring", (int)vic->lpc_pid);

#ifdef DEBUG_MSG
		{
			void *ovicaddr = vicaddr;
#endif /* DEBUG_MSG */
		vicaddr = set_prpageheader_cur_addr(&cur, vic->lpc_prpageheader,
		    vic->lpc_xmap, vic->lpc_nxmap, vicaddr);
#ifdef DEBUG_MSG
			st_debug(STDL_NORMAL, lcol, "trying to resume from"
			    " 0x%p, next 0x%p\n", ovicaddr, vicaddr);
		}
#endif /* DEBUG_MSG */

		/*
		 * Take control of the victim.
		 */
		if (get_psinfo(vic->lpc_pid, &old_psinfo,
		    vic->lpc_psinfo_fd, lprocess_update_psinfo_fd_cb,
		    vic, vic) != 0) {
			st_debug(STDL_NORMAL, lcol, "cannot get %d psinfo",
			    (int)vic->lpc_pid);
			goto nextproc;
		}
		(void) rfd_reserve(PGRAB_FD_COUNT);
		if ((scan_pr = Pgrab(vic->lpc_pid, 0, &res)) == NULL) {
			st_debug(STDL_NORMAL, lcol, "cannot grab %d (%d)",
			    (int)vic->lpc_pid, res);
			goto nextproc;
		}
		if (Pcreate_agent(scan_pr) != 0) {
			st_debug(STDL_NORMAL, lcol, "cannot control %d",
			    (int)vic->lpc_pid);
			goto nextproc;
		}
		/*
		 * Be very pessimistic about the state of the agent LWP --
		 * verify it's actually stopped.
		 */
		errno = 0;
		while (Pstate(scan_pr) == PS_RUN)
			(void) Pwait(scan_pr, 0);
		if (Pstate(scan_pr) != PS_STOP) {
			st_debug(STDL_NORMAL, lcol, "agent not in expected"
			    " state (%d)", Pstate(scan_pr));
			goto nextproc;
		}

		/*
		 * Within the victim's address space, find contiguous ranges of
		 * unreferenced pages to page out.
		 */
		st_debug(STDL_NORMAL, lcol, "paging out process %d\n",
		    (int)vic->lpc_pid);
		while (excess > 0 && vicaddr != NULL && should_run) {
			/*
			 * Skip mappings in the ignored set.  Mappings get
			 * placed in the ignored set when all their resident
			 * pages are unreference and unmodified, yet unpageable
			 * -- such as when they are locked, or involved in
			 * asynchronous I/O.  They will be scanned again when
			 * some page is referenced or modified.
			 */
			if (lmapping_contains(vic->lpc_ignore, cur.pr_addr,
			    cur.pr_npage * cur.pr_pagesize)) {
				debug("ignored mapping at 0x%p\n",
				    (void *)cur.pr_addr);
				/*
				 * Update statistics.
				 */
				lcol->lcol_stat.lcols_pg_att +=
				    cur.pr_npage * cur.pr_pagesize / 1024;

				vicaddr = (void *)
				    advance_prpageheader_cur_nextmapping(&cur);
				continue;
			}

			/*
			 * Determine a range of unreferenced pages to page out,
			 * and clear the R/M bits in the preceding referenced
			 * range.
			 */
			st_debug(STDL_HIGH, lcol, "start from mapping at 0x%p,"
			    " npage %llu\n", vicaddr,
			    (unsigned long long)cur.pr_npage);
			while (vicaddr != NULL &&
			    *(caddr_t)cur.pr_pdaddr != 0) {
				*(caddr_t)cur.pr_pdaddr = 0;
				vicaddr = advance_prpageheader_cur(&cur);
			}
			st_debug(STDL_HIGH, lcol, "advance, vicaddr %p, pdaddr"
			    " %p\n", vicaddr, cur.pr_pdaddr);
			if (vicaddr == NULL) {
				/*
				 * The end of mapping was reached before any
				 * unreferenced pages were seen.
				 */
				vicaddr = (void *)
				    advance_prpageheader_cur_nextmapping(&cur);
				continue;
			}
			do
				endaddr = advance_prpageheader_cur(&cur);
			while (endaddr != NULL &&
			    *(caddr_t)cur.pr_pdaddr == 0 &&
			    (((intptr_t)endaddr - (intptr_t)vicaddr) /
			    1024) < excess)
				;
			st_debug(STDL_HIGH, lcol, "endaddr %p, *cur %d\n",
			    endaddr, *(caddr_t)cur.pr_pdaddr);

			/*
			 * Page out from vicaddr to the end of the mapping, or
			 * endaddr if set, then continue scanning after
			 * endaddr, or the next mapping, if not set.
			 */
			nvicaddr = endaddr;
			if (endaddr == NULL)
				endaddr = (caddr_t)cur.pr_addr +
				    cur.pr_pagesize * cur.pr_npage;
			if (pageout(vic->lpc_pid, scan_pr, vicaddr, endaddr) ==
			    0) {
				int64_t d_rss, att;
				int willignore = 0;

				excess += (d_rss = rss_delta(
				    &new_psinfo, &old_psinfo, vic));

				/*
				 * If this pageout attempt was unsuccessful
				 * (the resident portion was not affected), and
				 * was for the whole mapping, put it in the
				 * ignored set, so it will not be scanned again
				 * until some page is referenced or modified.
				 */
				if (d_rss >= 0 && (void *)cur.pr_addr ==
				    vicaddr && (cur.pr_pagesize * cur.pr_npage)
				    == ((uintptr_t)endaddr -
				    (uintptr_t)vicaddr)) {
					if (lmapping_insert(
					    &vic->lpc_ignore,
					    cur.pr_addr,
					    cur.pr_pagesize *
					    cur.pr_npage) != 0)
						debug("not enough memory to add"
						    " mapping at %p to ignored"
						    " set\n",
						    (void *)cur.pr_addr);
					willignore = 1;
				}

				/*
				 * Update statistics.
				 */
				lcol->lcol_stat.lcols_pg_att += (att =
				    ((intptr_t)endaddr - (intptr_t)vicaddr) /
				    1024);
				st_debug(STDL_NORMAL, lcol, "paged out 0x%p"
				    "+0t(%llu/%llu)kB%s\n", vicaddr,
				    (unsigned long long)((d_rss <
				    0) ? - d_rss : 0), (unsigned long long)att,
				    willignore ? " (will ignore)" : "");
			} else {
				st_debug(STDL_NORMAL, lcol,
				    "process %d: exited/unscannable\n",
				    (int)vic->lpc_pid);
				vic->lpc_unscannable = 1;
				goto nextproc;
			}

			/*
			 * Update the statistics file, if it's time.
			 */
			check_update_statistics();

			vicaddr = (nvicaddr != NULL) ? nvicaddr : (void
			    *)advance_prpageheader_cur_nextmapping(&cur);
		}
		excess += rss_delta(&new_psinfo, &old_psinfo, vic);
		st_debug(STDL_NORMAL, lcol, "done, excess %lld\n",
		    (long long)excess);
nextproc:
		/*
		 * If a process was grabbed, release it, destroying its agent.
		 */
		if (scan_pr != NULL) {
			(void) Prelease(scan_pr, 0);
			scan_pr = NULL;
		}
		lcol->lcol_victim = vic;
		/*
		 * Scan the collection at most once.  Only if scanning was not
		 * aborted for any reason, and the end of lprocess has not been
		 * reached, determine the next victim and scan it.
		 */
		if (vic != NULL) {
			if (vic->lpc_next != NULL) {
				/*
				 * Determine the next process to be scanned.
				 */
				if (excess > 0) {
					vic = get_valid_victim(lcol,
					    vic->lpc_next);
					vicaddr = 0;
				}
			} else {
				/*
				 * A complete scan of the collection was made,
				 * so tick the scan counter and stop scanning
				 * until the next request.
				 */
				lcol->lcol_stat.lcols_scan_count++;
				lcol->lcol_stat.lcols_scan_time_complete
				    = lcol->lcol_stat.lcols_scan_time;
				/*
				 * If an excess still exists, tick the
				 * "ineffective scan" counter, signalling that
				 * the cap may be uneforceable.
				 */
				if (resumed == 0 && excess > 0)
					lcol->lcol_stat
					    .lcols_scan_ineffective++;
				/*
				 * Scanning should start at the beginning of
				 * the process list at the next request.
				 */
				if (excess > 0)
					vic = NULL;
			}
		}
	}
	lcol->lcol_stat.lcols_scan_time += (gethrtime() - scan_start);
	st_debug(STDL_HIGH, lcol, "done scanning; excess %lld\n",
	    (long long)excess);

	lcol->lcol_resaddr = vicaddr;
	if (lcol->lcol_resaddr == NULL && lcol->lcol_victim != NULL) {
		lcol->lcol_victim = get_valid_victim(lcol,
		    lcol->lcol_victim->lpc_next);
	}
}

/*
 * Abort the scan in progress, and destroy the agent LWP of any grabbed
 * processes.
 */
void
scan_abort(void)
{
	if (scan_pr != NULL)
		(void) Prelease(scan_pr, 0);
}

static void
revoke_xmap(rfd_t *rfd)
{
	lprocess_t *lpc = rfd->rfd_data;

	debug("revoking xmap for process %d\n", (int)lpc->lpc_pid);
	ASSERT(lpc->lpc_xmap_fd != -1);
	lpc->lpc_xmap_fd = -1;
}

/*
 * Retrieve the process's current xmap , which is used to determine the size of
 * the resident portion of its segments.  Return zero if successful.
 */
static int
lpc_xmap_update(lprocess_t *lpc)
{
	int res;
	struct stat st;

	free(lpc->lpc_xmap);
	lpc->lpc_xmap = NULL;
	lpc->lpc_nxmap = -1;

	if (lpc->lpc_xmap_fd == -1) {
		char pathbuf[PROC_PATH_MAX];

		(void) snprintf(pathbuf, sizeof (pathbuf), "/proc/%d/xmap",
		    (int)lpc->lpc_pid);
		if ((lpc->lpc_xmap_fd = rfd_open(pathbuf, 1, RFD_XMAP,
		    revoke_xmap, lpc, O_RDONLY, 0)) < 0)
			return (-1);
	}

redo:
	errno = 0;
	if (fstat(lpc->lpc_xmap_fd, &st) != 0) {
		debug("cannot stat xmap\n");
		(void) rfd_close(lpc->lpc_xmap_fd);
		lpc->lpc_xmap_fd = -1;
		return (-1);
	}

	if ((st.st_size % sizeof (*lpc->lpc_xmap)) != 0) {
		debug("xmap wrong size\n");
		(void) rfd_close(lpc->lpc_xmap_fd);
		lpc->lpc_xmap_fd = -1;
		return (-1);
	}

	lpc->lpc_xmap = malloc(st.st_size);
	if (lpc->lpc_xmap == NULL) {
		debug("cannot malloc() %ld bytes for xmap", st.st_size);
		(void) rfd_close(lpc->lpc_xmap_fd);
		lpc->lpc_xmap_fd = -1;
		return (-1);
	}

	if ((res = pread(lpc->lpc_xmap_fd, lpc->lpc_xmap, st.st_size, 0)) !=
	    st.st_size) {
		free(lpc->lpc_xmap);
		lpc->lpc_xmap = NULL;
		if (res > 0) {
			debug("xmap changed size, retrying\n");
			goto redo;
		} else {
			debug("cannot read xmap");
			return (-1);
		}
	}
	lpc->lpc_nxmap = st.st_size / sizeof (*lpc->lpc_xmap);

	return (0);
}
