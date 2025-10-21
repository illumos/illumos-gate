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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_whatis.h>
#include <mdb/mdb_whatis_impl.h>
#include <limits.h>

static int whatis_debug = 0;

/* for bsearch;  r is an array of {base, size}, e points into w->w_addrs */
static int
find_range(const void *r, const void *e)
{
	const uintptr_t *range = r;
	uintptr_t el = *(const uintptr_t *)e;

	if (el < range[0])
		return (1);

	if ((el - range[0]) >= range[1])
		return (-1);

	return (0);
}

/* for qsort; simple uintptr comparator */
static int
uintptr_cmp(const void *l, const void *r)
{
	uintptr_t lhs = *(const uintptr_t *)l;
	uintptr_t rhs = *(const uintptr_t *)r;

	if (lhs < rhs)
		return (-1);
	if (lhs > rhs)
		return (1);
	return (0);
}

static const uintptr_t *
mdb_whatis_search(mdb_whatis_t *w, uintptr_t base, size_t size)
{
	uintptr_t range[2];

	range[0] = base;
	range[1] = size;

	return (bsearch(range, w->w_addrs, w->w_naddrs, sizeof (*w->w_addrs),
	    find_range));
}

/*
 * Returns non-zero if and only if there is at least one address of interest
 * in the range [base, base+size).
 */
int
mdb_whatis_overlaps(mdb_whatis_t *w, uintptr_t base, size_t size)
{
	const uintptr_t *f;
	uint_t offset, cur;

	if (whatis_debug && w->w_magic != WHATIS_MAGIC) {
		mdb_warn(
		    "mdb_whatis_overlaps(): bogus mdb_whatis_t pointer\n");
		return (0);
	}

	if (w->w_done || size == 0)
		return (0);

	if (base + size - 1 < base) {
		mdb_warn("mdb_whatis_overlaps(): [%p, %p+%p) overflows\n",
		    base, base, size);
		return (0);
	}

	f = mdb_whatis_search(w, base, size);
	if (f == NULL)
		return (0);

	cur = offset = f - w->w_addrs;

	/*
	 * We only return success if there's an address we'll actually
	 * match in the range.  We can quickly check for the ALL flag
	 * or a non-found address at our match point.
	 */
	if ((w->w_flags & WHATIS_ALL) || !w->w_addrfound[cur])
		return (1);

	/* Search backwards then forwards for a non-found address */
	while (cur > 0) {
		cur--;

		if (w->w_addrs[cur] < base)
			break;

		if (!w->w_addrfound[cur])
			return (1);
	}

	for (cur = offset + 1; cur < w->w_naddrs; cur++) {
		if ((w->w_addrs[cur] - base) >= size)
			break;

		if (!w->w_addrfound[cur])
			return (1);
	}

	return (0);			/* everything has already been seen */
}

/*
 * Iteratively search our list of addresses for matches in [base, base+size).
 */
int
mdb_whatis_match(mdb_whatis_t *w, uintptr_t base, size_t size, uintptr_t *out)
{
	size_t offset;

	if (whatis_debug) {
		if (w->w_magic != WHATIS_MAGIC) {
			mdb_warn(
			    "mdb_whatis_match(): bogus mdb_whatis_t pointer\n");
			goto done;
		}
	}

	if (w->w_done || size == 0)
		goto done;

	if (base + size - 1 < base) {
		mdb_warn("mdb_whatis_match(): [%p, %p+%x) overflows\n",
		    base, base, size);
		return (0);
	}

	if ((offset = w->w_match_next) != 0 &&
	    (base != w->w_match_base || size != w->w_match_size)) {
		mdb_warn("mdb_whatis_match(): new range [%p, %p+%p) "
		    "while still searching [%p, %p+%p)\n",
		    base, base, size,
		    w->w_match_base, w->w_match_base, w->w_match_size);
		offset = 0;
	}

	if (offset == 0) {
		const uintptr_t *f = mdb_whatis_search(w, base, size);

		if (f == NULL)
			goto done;

		offset = (f - w->w_addrs);

		/* Walk backwards until we reach the first match */
		while (offset > 0 && w->w_addrs[offset - 1] >= base)
			offset--;

		w->w_match_base = base;
		w->w_match_size = size;
	}

	for (; offset < w->w_naddrs && ((w->w_addrs[offset] - base) < size);
	    offset++) {

		*out = w->w_addrs[offset];
		w->w_match_next = offset + 1;

		if (w->w_addrfound[offset]) {
			/* if we're not seeing everything, skip it */
			if (!(w->w_flags & WHATIS_ALL))
				continue;

			return (1);
		}

		/* We haven't seen this address yet. */
		w->w_found++;
		w->w_addrfound[offset] = 1;

		/* If we've found them all, we're done */
		if (w->w_found == w->w_naddrs && !(w->w_flags & WHATIS_ALL))
			w->w_done = 1;

		return (1);
	}

done:
	w->w_match_next = 0;
	w->w_match_base = 0;
	w->w_match_size = 0;
	return (0);
}

/*
 * Report a pointer (addr) in an object beginning at (base) in standard
 * whatis-style.  (format, ...) are mdb_printf() arguments, to be printed
 * after the address information.  The caller is responsible for printing
 * a newline (either in format or after the call returns)
 */
/*ARGSUSED*/
void
mdb_whatis_report_object(mdb_whatis_t *w,
    uintptr_t addr, uintptr_t base, const char *format, ...)
{
	va_list alist;

	if (whatis_debug) {
		if (mdb_whatis_search(w, addr, 1) == NULL)
			mdb_warn("mdb_whatis_report_object(): addr "
			    "%p is not a pointer of interest.\n", addr);
	}

	if (addr < base)
		mdb_warn("whatis: addr (%p) is less than base (%p)\n",
		    addr, base);

	if (addr == base)
		mdb_printf("%p is ", addr);
	else
		mdb_printf("%p is %p+%p, ", addr, base, addr - base);

	if (format == NULL)
		return;

	va_start(alist, format);
	mdb_iob_vprintf(mdb.m_out, format, alist);
	va_end(alist);
}

/*
 * Report an address (addr), with symbolic information if available, in
 * standard whatis-style.  (format, ...) are mdb_printf() arguments, to be
 * printed after the address information.  The caller is responsible for
 * printing a newline (either in format or after the call returns)
 */
/*ARGSUSED*/
void
mdb_whatis_report_address(mdb_whatis_t *w, uintptr_t addr,
    const char *format, ...)
{
	GElf_Sym sym;
	va_list alist;

	if (whatis_debug) {
		if (mdb_whatis_search(w, addr, 1) == NULL)
			mdb_warn("mdb_whatis_report_adddress(): addr "
			    "%p is not a pointer of interest.\n", addr);
	}

	mdb_printf("%p is ", addr);

	if (mdb_lookup_by_addr(addr, MDB_SYM_FUZZY, NULL, 0, &sym) != -1 &&
	    (addr - (uintptr_t)sym.st_value) < sym.st_size) {
		mdb_printf("%a, ", addr);
	}

	va_start(alist, format);
	mdb_iob_vprintf(mdb.m_out, format, alist);
	va_end(alist);
}

uint_t
mdb_whatis_flags(mdb_whatis_t *w)
{
	/* Mask out the internal-only flags */
	return (w->w_flags & WHATIS_PUBLIC);
}

uint_t
mdb_whatis_done(mdb_whatis_t *w)
{
	return (w->w_done);
}

/*
 * Whatis callback list management
 */
typedef struct whatis_callback {
	uint64_t	wcb_index;
	mdb_module_t	*wcb_module;
	const char	*wcb_modname;
	char		*wcb_name;
	mdb_whatis_cb_f	*wcb_func;
	void		*wcb_arg;
	uint_t		wcb_prio;
	uint_t		wcb_flags;
} whatis_callback_t;

static whatis_callback_t builtin_whatis[] = {
	{ 0, NULL, "mdb", "mappings", whatis_run_mappings, NULL,
	    WHATIS_PRIO_MIN, WHATIS_REG_NO_ID }
};
#define	NBUILTINS	(sizeof (builtin_whatis) / sizeof (*builtin_whatis))

static whatis_callback_t *whatis_cb_start[NBUILTINS];
static whatis_callback_t **whatis_cb = NULL;	/* callback array */
static size_t whatis_cb_count;			/* count of callbacks */
static size_t whatis_cb_size;			/* size of whatis_cb array */
static uint64_t whatis_cb_index;		/* global count */

#define	WHATIS_CB_SIZE_MIN	8	/* initial allocation size */

static int
whatis_cbcmp(const void *lhs, const void *rhs)
{
	whatis_callback_t *l = *(whatis_callback_t * const *)lhs;
	whatis_callback_t *r = *(whatis_callback_t * const *)rhs;
	int ret;

	/* First, handle NULLs; we want them at the end */
	if (l == NULL && r == NULL)
		return (0);
	if (l == NULL)
		return (1);
	if (r == NULL)
		return (-1);

	/* Next, compare priorities */
	if (l->wcb_prio < r->wcb_prio)
		return (-1);
	if (l->wcb_prio > r->wcb_prio)
		return (1);

	/* then module name */
	if ((ret = strcmp(l->wcb_modname, r->wcb_modname)) != 0)
		return (ret);

	/* and finally insertion order */
	if (l->wcb_index < r->wcb_index)
		return (-1);
	if (l->wcb_index > r->wcb_index)
		return (1);

	mdb_warn("whatis_cbcmp(): can't happen: duplicate indices\n");
	return (0);
}

static void
whatis_init(void)
{
	int idx;

	for (idx = 0; idx < NBUILTINS; idx++) {
		whatis_cb_start[idx] = &builtin_whatis[idx];
		whatis_cb_start[idx]->wcb_index = idx;
	}
	whatis_cb_index = idx;

	whatis_cb = whatis_cb_start;
	whatis_cb_count = whatis_cb_size = NBUILTINS;

	qsort(whatis_cb, whatis_cb_count, sizeof (*whatis_cb), whatis_cbcmp);
}

void
mdb_whatis_register(const char *name, mdb_whatis_cb_f *func, void *arg,
    uint_t prio, uint_t flags)
{
	whatis_callback_t *wcp;

	if (mdb.m_lmod == NULL) {
		mdb_warn("mdb_whatis_register(): can only be called during "
		    "module load\n");
		return;
	}

	if (strbadid(name)) {
		mdb_warn("mdb_whatis_register(): whatis name '%s' contains "
		    "illegal characters\n");
		return;
	}

	if ((flags & ~(WHATIS_REG_NO_ID|WHATIS_REG_ID_ONLY)) != 0) {
		mdb_warn("mdb_whatis_register(): flags (%x) contain unknown "
		    "flags\n", flags);
		return;
	}
	if ((flags & WHATIS_REG_NO_ID) && (flags & WHATIS_REG_ID_ONLY)) {
		mdb_warn("mdb_whatis_register(): flags (%x) contains both "
		    "NO_ID and ID_ONLY.\n", flags);
		return;
	}

	if (prio > WHATIS_PRIO_MIN)
		prio = WHATIS_PRIO_MIN;

	if (whatis_cb == NULL)
		whatis_init();

	wcp = mdb_zalloc(sizeof (*wcp), UM_SLEEP);

	wcp->wcb_index = whatis_cb_index++;
	wcp->wcb_prio = prio;
	wcp->wcb_module = mdb.m_lmod;
	wcp->wcb_modname = mdb.m_lmod->mod_name;
	wcp->wcb_name = strdup(name);
	wcp->wcb_func = func;
	wcp->wcb_arg = arg;
	wcp->wcb_flags = flags;

	/*
	 * See if we need to grow the array;  note that at initialization
	 * time, whatis_cb_count is greater than whatis_cb_size; this clues
	 * us in to the fact that the array doesn't need to be freed.
	 */
	if (whatis_cb_count == whatis_cb_size) {
		size_t nsize = MAX(2 * whatis_cb_size, WHATIS_CB_SIZE_MIN);

		size_t obytes = sizeof (*whatis_cb) * whatis_cb_size;
		size_t nbytes = sizeof (*whatis_cb) * nsize;

		whatis_callback_t **narray = mdb_zalloc(nbytes, UM_SLEEP);

		bcopy(whatis_cb, narray, obytes);

		if (whatis_cb != whatis_cb_start)
			mdb_free(whatis_cb, obytes);
		whatis_cb = narray;
		whatis_cb_size = nsize;
	}

	/* add it into the table and re-sort */
	whatis_cb[whatis_cb_count++] = wcp;
	qsort(whatis_cb, whatis_cb_count, sizeof (*whatis_cb), whatis_cbcmp);
}

void
mdb_whatis_unregister_module(mdb_module_t *mod)
{
	int found = 0;
	int idx;

	if (mod == NULL)
		return;

	for (idx = 0; idx < whatis_cb_count; idx++) {
		whatis_callback_t *cur = whatis_cb[idx];

		if (cur->wcb_module == mod) {
			found++;
			whatis_cb[idx] = NULL;

			strfree(cur->wcb_name);
			mdb_free(cur, sizeof (*cur));
		}
	}
	/* If any were removed, compact the array */
	if (found != 0) {
		qsort(whatis_cb, whatis_cb_count, sizeof (*whatis_cb),
		    whatis_cbcmp);
		whatis_cb_count -= found;
	}
}

int
cmd_whatis(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_whatis_t w;
	size_t idx;
	int ret;
	int keep = 0;
	int list = 0;

	if (flags & DCMD_PIPE_OUT) {
		mdb_warn("whatis: cannot be output into a pipe\n");
		return (DCMD_ERR);
	}

	if (mdb.m_lmod != NULL) {
		mdb_warn("whatis: cannot be called during module load\n");
		return (DCMD_ERR);
	}

	if (whatis_cb == NULL)
		whatis_init();

	bzero(&w, sizeof (w));
	w.w_magic = WHATIS_MAGIC;

	whatis_debug = 0;

	if (mdb_getopts(argc, argv,
	    'D', MDB_OPT_SETBITS, TRUE, &whatis_debug,		/* hidden */
	    'b', MDB_OPT_SETBITS, WHATIS_BUFCTL, &w.w_flags,	/* hidden */
	    'l', MDB_OPT_SETBITS, TRUE, &list,			/* hidden */
	    'a', MDB_OPT_SETBITS, WHATIS_ALL, &w.w_flags,
	    'i', MDB_OPT_SETBITS, WHATIS_IDSPACE, &w.w_flags,
	    'k', MDB_OPT_SETBITS, TRUE, &keep,
	    'q', MDB_OPT_SETBITS, WHATIS_QUIET, &w.w_flags,
	    'v', MDB_OPT_SETBITS, WHATIS_VERBOSE, &w.w_flags,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (list) {
		mdb_printf("%<u>%-16s %-12s %4s %?s %?s %8s%</u>\n",
		    "NAME", "MODULE", "PRIO", "FUNC", "ARG", "FLAGS");

		for (idx = 0; idx < whatis_cb_count; idx++) {
			whatis_callback_t *cur = whatis_cb[idx];

			const char *curfl =
			    (cur->wcb_flags & WHATIS_REG_NO_ID) ? "NO_ID" :
			    (cur->wcb_flags & WHATIS_REG_ID_ONLY) ? "ID_ONLY" :
			    "none";

			mdb_printf("%-16s %-12s %4d %-?p %-?p %8s\n",
			    cur->wcb_name, cur->wcb_modname, cur->wcb_prio,
			    cur->wcb_func, cur->wcb_arg, curfl);
		}
		return (DCMD_OK);
	}

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	w.w_addrs = &addr;
	w.w_naddrs = 1;

	/* If our input is a pipe, try to slurp it all up. */
	if (!keep && (flags & DCMD_PIPE)) {
		mdb_pipe_t p;
		mdb_get_pipe(&p);

		if (p.pipe_len != 0) {
			w.w_addrs = p.pipe_data;
			w.w_naddrs = p.pipe_len;

			/* sort the address list */
			qsort(w.w_addrs, w.w_naddrs, sizeof (*w.w_addrs),
			    uintptr_cmp);
		}
	}
	w.w_addrfound = mdb_zalloc(w.w_naddrs * sizeof (*w.w_addrfound),
	    UM_SLEEP | UM_GC);

	if (whatis_debug) {
		mdb_printf("Searching for:\n");
		for (idx = 0; idx < w.w_naddrs; idx++)
			mdb_printf("    %p", w.w_addrs[idx]);
		mdb_printf("\n");
	}

	ret = 0;

	/* call in to the registered handlers */
	for (idx = 0; idx < whatis_cb_count; idx++) {
		whatis_callback_t *cur = whatis_cb[idx];
		mdb_idcmd_t *dcmd = NULL;
		mdb_module_t *mod;

		/* Honor the ident flags */
		if (w.w_flags & WHATIS_IDSPACE) {
			if (cur->wcb_flags & WHATIS_REG_NO_ID)
				continue;
		} else {
			if (cur->wcb_flags & WHATIS_REG_ID_ONLY)
				continue;
		}

		if (w.w_flags & WHATIS_VERBOSE) {
			mdb_printf("Searching %s`%s...\n",
			    cur->wcb_modname, cur->wcb_name);
		}

		/*
		 * We need to run each whatis callback in the context of the
		 * module that added it. That means that it will be able to
		 * access things relevant to that module such as, for example,
		 * CTF data. We do this by updating the "whatis" command
		 * structure in place and restoring the original module
		 * afterwards.
		 */
		if (mdb.m_frame->f_cp != NULL) {
			dcmd = mdb.m_frame->f_cp->c_dcmd;
			if (dcmd != NULL) {
				mod = dcmd->idc_modp;
				dcmd->idc_modp = cur->wcb_module;
			}
		}
		if (cur->wcb_func(&w, cur->wcb_arg) != 0)
			ret = 1;
		if (dcmd != NULL)
			dcmd->idc_modp = mod;

		/* reset the match state for the next callback */
		w.w_match_next = 0;
		w.w_match_base = 0;
		w.w_match_size = 0;

		if (w.w_done)
			break;
	}

	/* Report any unexplained pointers */
	for (idx = 0; idx < w.w_naddrs; idx++) {
		uintptr_t addr = w.w_addrs[idx];

		if (w.w_addrfound[idx])
			continue;

		mdb_whatis_report_object(&w, addr, addr, "unknown\n");
	}

	return ((ret != 0) ? DCMD_ERR : DCMD_OK);
}

void
whatis_help(void)
{
	int idx;

	mdb_printf("%s\n",
"Given a virtual address (with -i, an identifier), report where it came\n"
"from.\n"
"\n"
"When fed from a pipeline, ::whatis will not maintain the order the input\n"
"comes in; addresses will be reported as it finds them. (-k prevents this;\n"
"the output will be in the same order as the input)\n");
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf("%s",
"  -a  Report all information about each address/identifier.  The default\n"
"      behavior is to report only the first (most specific) source for each\n"
"      address/identifier.\n"
"  -i  addr is an identifier, not a virtual address.\n"
"  -k  Do not re-order the input. (may be slower)\n"
"  -q  Quiet; don't print multi-line reports. (stack traces, etc.)\n"
"  -v  Verbose output; display information about the progress of the search\n");

	if (mdb.m_lmod != NULL)
		return;

	(void) mdb_dec_indent(2);
	mdb_printf("\n%<b>SOURCES%</b>\n\n");
	(void) mdb_inc_indent(2);
	mdb_printf("The following information sources will be used:\n\n");

	(void) mdb_inc_indent(2);
	for (idx = 0; idx < whatis_cb_count; idx++) {
		whatis_callback_t *cur = whatis_cb[idx];

		mdb_printf("%s`%s\n", cur->wcb_modname, cur->wcb_name);
	}
	(void) mdb_dec_indent(2);
}
