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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/cpr.h>
#include <sys/promimpl.h>
#include <sys/privregs.h>
#include <sys/stack.h>
#include <sys/bitmap.h>
#include "cprboot.h"


#define	TIMEOUT_MSECS	1000


/*
 * globals
 */
int cpr_test_mode;
csu_md_t mdinfo;
caddr_t tmp_stack;
uint_t cb_mid;
uint_t cb_clock_freq;
uint_t cpu_delay;


/*
 * file scope
 */
typedef void (*tlb_func_t)(int, caddr_t, tte_t *);
static uint_t mdlen;
static ulong_t slave_set[BT_BITOUL(NCPU)];
static int has_scbc;


/*
 * check machdep desc and cpr_machdep info
 *
 * sets globals:
 *	mdinfo
 *	mdlen
 */
int
cb_check_machdep(void)
{
	uint16_t wst32, wst64;
	char *fmt, *str;
	cmd_t cmach;

	str = "cb_check_machdep";
	CB_VPRINTF((ent_fmt, str, entry));

	/*
	 * get machdep desc and set length of prom words
	 */
	SF_DCOPY(cmach);
	if (cmach.md_magic != CPR_MACHDEP_MAGIC) {
		prom_printf("%s: bad machdep magic 0x%x, expect 0x%x\n",
		    str, cmach.md_magic, CPR_MACHDEP_MAGIC);
		return (ERR);
	}
	mdlen = cmach.md_size - sizeof (csu_md_t);

	/*
	 * get machep info, check for valid stack bias and wstate
	 */
	SF_DCOPY(mdinfo);
	fmt = "found bad statefile data: %s (0x%x), expect 0x%x or 0x%x\n";
	if (mdinfo.ksb != 0x0 && mdinfo.ksb != V9BIAS64) {
		prom_printf(fmt, "stack bias", mdinfo.ksb, 0, V9BIAS64);
		return (ERR);
	}
	wst32 = WSTATE(WSTATE_U32, WSTATE_K32);
	wst64 = WSTATE(WSTATE_U32, WSTATE_K64);
	if (mdinfo.kwstate != wst32 && mdinfo.kwstate != wst64) {
		prom_printf(fmt, "wstate", mdinfo.kwstate, wst32, wst64);
		return (ERR);
	}

	return (0);
}


/*
 * interpret saved prom words
 */
int
cb_interpret(void)
{
	int bytes, wlen, s;
	char minibuf[60];
	char *words;

	CB_VENTRY(cb_interpret);

	/*
	 * The variable length machdep section for sun4u consists of
	 * a sequence of null-terminated strings stored contiguously.
	 *
	 * The first string defines Forth words which help the prom
	 * handle kernel translations.
	 *
	 * The second string defines Forth words required by kadb to
	 * interface with the prom when a trap is taken.
	 */
	words = SF_DATA();
	bytes = mdlen;
	while (bytes) {
		wlen = prom_strlen(words) + 1;	/* include the null */
		if (verbose) {
			s = sizeof (minibuf) - 4;
			(void) prom_strncpy(minibuf, words, s);
			if (wlen > s)
				(void) prom_strcpy(&minibuf[s], "...");
			prom_printf("    interpret \"%s\"\n", minibuf);
		}
		prom_interpret(words, 0, 0, 0, 0, 0);
		words += wlen;
		bytes -= wlen;
	}

	/* advance past prom words */
	SF_ADV(mdlen);

	return (0);
}


/*
 * write dtlb/itlb entries
 */
static void
restore_tlb(struct sun4u_tlb *utp, int cpu_id)
{
	struct sun4u_tlb *tail;
	tlb_func_t tfunc;
	caddr_t virt;
	char tname;

	if (utp == mdinfo.dtte) {
		tfunc = set_dtlb_entry;
		tname = 'd';
	} else if (utp == mdinfo.itte) {
		tfunc = set_itlb_entry;
		tname = 'i';
	}

	for (tail = utp + CPR_MAX_TLB; utp < tail; utp++) {
		if (utp->va_tag == NULL)
			continue;
		virt = (caddr_t)utp->va_tag;
		(*tfunc)(utp->index, virt, &utp->tte);
		if (verbose || CPR_DBG(4)) {
			prom_printf("    cpu_id %d: write %ctlb "
			    "(index %x, virt 0x%lx, size 0x%x)\n",
			    cpu_id, tname, utp->index, utp->va_tag,
			    TTEBYTES(utp->tte.tte_size));
		}
	}
}


/*
 * install locked tlb entries for the kernel and cpr module;
 * also sets up the tmp stack
 */
int
cb_ksetup(void)
{
	CB_VENTRY(cb_ksetup);

	restore_tlb(mdinfo.dtte, cb_mid);
	restore_tlb(mdinfo.itte, cb_mid);
	tmp_stack = (caddr_t)(mdinfo.tmp_stack + mdinfo.tmp_stacksize);

	return (0);
}


static void
cb_park_err(int cpu_id)
{
	prom_printf("\ncpu_id %d did not stop!...\n", cpu_id);
	cb_exit_to_mon();
}


/*
 * local copy of an older interface for OBP revs < 4.6
 */
static int
cb_prom_stop_self(void)
{
	cell_t ci[3];

	ci[0] = p1275_ptr2cell("SUNW,stop-self");	/* Service name */
	ci[1] = (cell_t)0;			/* #argument cells */
	ci[2] = (cell_t)0;			/* #result cells */
	(void) p1275_cif_handler(&ci);		/* Do NOT lock */
	return (0);
}


/*
 * install locked tlb entries and spin or park in a prom idle-loop
 */
void
slave_init(int cpu_id)
{
	restore_tlb(mdinfo.dtte, cpu_id);
	restore_tlb(mdinfo.itte, cpu_id);
	BT_SET(slave_set, cpu_id);
	membar_stld();
	if (has_scbc) {
		/* just spin, master will park this cpu */
		/* CONSTCOND */
		while (1);
	} else {
		(void) cb_prom_stop_self();
		cb_park_err(cpu_id);
	}
}


/*
 * when any cpu is started, they naturally rely on the prom for all
 * text/data translations until switching to the kernel trap table.
 * to jump back into the cpr module and to restart slave cpus, cprboot
 * needs to reinstall translations for the nucleus and some cpr pages.
 *
 * the easy method is creating one set of global translations available
 * to all cpus with prom_map(); unfortunately, a 4MB "map" request will
 * allocate and overwrite a few pages, and these are often kernel pages
 * that were just restored.
 *
 * to solve the "map" problem, all cpus install their own set of locked
 * tlb entries to translate the nucleus and parts of the cpr module;
 * after all cpus have switched to kernel traps, any of these locked
 * tlb entries for pages outside the nucleus will be cleared.
 */
int
cb_mpsetup(void)
{
	struct sun4u_cpu_info *scip, *tail;
	int timeout, ncpu;
	char *str, *intf;

	intf = "SUNW,stop-cpu-by-cpuid";
	has_scbc = (prom_test(intf) == 0);
	CB_VPRINTF(("\n\"%s\" test %d\n", intf, has_scbc));

	str = "cb_mp_setup";
	CB_VPRINTF((ent_fmt, str, entry));

	/*
	 * launch any slave cpus from the .sci array into cprboot text
	 * and wait about a second for them to checkin with slave_set
	 */
	ncpu = 0;
	bzero(slave_set, sizeof (slave_set));
	for (scip = mdinfo.sci, tail = scip + NCPU; scip < tail; scip++) {
		if (scip->node == 0 || scip->cpu_id == cb_mid)
			continue;
		(void) prom_startcpu(scip->node,
		    (caddr_t)cpu_launch, scip->cpu_id);

		for (timeout = TIMEOUT_MSECS; timeout; timeout--) {
			if (BT_TEST(slave_set, scip->cpu_id))
				break;
			cb_usec_wait(MILLISEC);
		}

		if (timeout == 0) {
			prom_printf("\n%s: cpu did not start, "
			    "cpu_id %d, node 0x%x\n",
			    prog, scip->cpu_id, scip->node);
			return (ERR);
		}

		if (has_scbc && prom_stopcpu_bycpuid(scip->cpu_id))
			cb_park_err(scip->cpu_id);

		ncpu++;
	}

	if (verbose && ncpu)
		prom_printf("\n%s: slave cpu count: %d\n", str, ncpu);

	return (0);
}
