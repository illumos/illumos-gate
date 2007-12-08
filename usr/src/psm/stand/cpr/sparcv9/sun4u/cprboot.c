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

/*
 * cprboot - prom client that restores kadb/kernel pages
 *
 * simple cprboot overview:
 *	reset boot-file/boot-device to their original values
 * 	open cpr statefile, usually "/.CPR"
 *	read in statefile
 *	close statefile
 *	restore kernel pages
 *	jump back into kernel text
 *
 *
 * cprboot supports a restartable statefile for FAA/STARS,
 * Federal Aviation Administration
 * Standard Terminal Automation Replacement System
 */

#include <sys/types.h>
#include <sys/cpr.h>
#include <sys/promimpl.h>
#include <sys/ddi.h>
#include "cprboot.h"


/*
 * local defs
 */
#define	CB_MAXPROP	256
#define	CB_MAXARGS	8


/*
 * globals
 */
struct statefile sfile;

char cpr_statefile[OBP_MAXPATHLEN];
char cpr_filesystem[OBP_MAXPATHLEN];

int cpr_debug;				/* cpr debug, set with uadmin 3 10x */
uint_t cb_msec;				/* cprboot start runtime */
uint_t cb_dents;			/* number of dtlb entries */

int do_halt = 0;			/* halt (enter mon) after load */
int verbose = 0;			/* verbose, traces cprboot ops */

char rsvp[] = "please reboot";
char prog[] = "cprboot";
char entry[] = "ENTRY";
char ent_fmt[] = "\n%s %s\n";


/*
 * file scope
 */
static char cb_argbuf[CB_MAXPROP];
static char *cb_args[CB_MAXARGS];

static int reusable;
char *specialstate;


static int
cb_intro(void)
{
	static char cstr[] = "\014" "\033[1P" "\033[18;21H";

	CB_VENTRY(cb_intro);

	/*
	 * build/debug aid; this condition should not occur
	 */
	if ((uintptr_t)_end > CB_SRC_VIRT) {
		prom_printf("\ndata collision:\n"
		    "(_end=0x%p > CB_LOW_VIRT=0x%x), recompile...\n",
		    _end, CB_SRC_VIRT);
		return (ERR);
	}

	/* clear console */
	prom_printf(cstr);

	prom_printf("Restoring the System. Please Wait... ");
	return (0);
}


/*
 * read bootargs and convert to arg vector
 *
 * sets globals:
 *	cb_argbuf
 *	cb_args
 */
static void
get_bootargs(void)
{
	char *cp, *tail, *argp, **argv;

	CB_VENTRY(get_bootargs);

	(void) prom_strcpy(cb_argbuf, prom_bootargs());
	tail = cb_argbuf + prom_strlen(cb_argbuf);

	/*
	 * scan to the trailing NULL so the last arg
	 * will be found without any special-case code
	 */
	argv = cb_args;
	for (cp = argp = cb_argbuf; cp <= tail; cp++) {
		if (prom_strchr(" \t\n\r", *cp) == NULL)
			continue;
		*cp = '\0';
		if (cp - argp) {
			*argv++ = argp;
			if ((argv - cb_args) == (CB_MAXARGS - 1))
				break;
		}
		argp = cp + 1;
	}
	*argv = NULLP;

	if (verbose) {
		for (argv = cb_args; *argv; argv++) {
			prom_printf("    %ld: \"%s\"\n",
			    (argv - cb_args), *argv);
		}
	}
}


static void
usage(char *expect, char *got)
{
	if (got == NULL)
		got = "(NULL)";
	prom_printf("\nbad OBP boot args: expect %s, got %s\n"
	    "Usage: boot -F %s [-R] [-S <diskpath>]\n%s\n\n",
	    expect, got, prog, rsvp);
	prom_exit_to_mon();
}


/*
 * bootargs should start with "-F cprboot"
 *
 * may set globals:
 *	specialstate
 *	reusable
 *	do_halt
 *	verbose
 */
static void
check_bootargs(void)
{
	char **argv, *str, *cp;

	argv = cb_args;

	/* expect "-F" */
	str = "-F";
	if (*argv == NULL || prom_strcmp(*argv, str))
		usage(str, *argv);
	argv++;

	/* expect "cprboot*" */
	if (*argv == NULL || prom_strncmp(*argv, prog, sizeof (prog) - 1))
		usage(prog, *argv);

	/*
	 * optional args
	 */
	str = "-[SR]";
	for (argv++; *argv; argv++) {
		cp = *argv;
		if (*cp != '-')
			usage(str, *argv);

		switch (*++cp) {
		case 'R':
		case 'r':
			reusable = 1;
			break;
		case 'S':
		case 's':
			if (*++argv)
				specialstate = *argv;
			else
				usage("statefile-path", *argv);
			break;
		case 'h':
			do_halt = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage(str, *argv);
			break;
		}
	}
}


/*
 * reset prom props and get statefile info
 *
 * sets globals:
 *	cpr_filesystem
 *	cpr_statefile
 */
static int
cb_startup(void)
{
	CB_VENTRY(cb_startup);

	if (!reusable) {
		/*
		 * Restore the original values of the nvram properties modified
		 * during suspend.  Note: if we can't get this info from the
		 * defaults file, the state file may be obsolete or bad, so we
		 * abort.  However, failure to restore one or more properties
		 * is NOT fatal (better to continue the resume).
		 */
		if (cpr_reset_properties() == -1) {
			prom_printf("\n%s: cannot read saved "
			    "nvram info, %s\n", prog, rsvp);
			return (ERR);
		}
	}

	/*
	 * simple copy if using specialstate,
	 * otherwise read in fs and statefile from a config file
	 */
	if (specialstate)
		(void) prom_strcpy(cpr_statefile, specialstate);
	else if (cpr_locate_statefile(cpr_statefile, cpr_filesystem) == -1) {
		prom_printf("\n%s: cannot find cpr statefile, %s\n",
		    prog, rsvp);
		return (ERR);
	}

	return (0);
}


static int
cb_open_sf(void)
{
	CB_VENTRY(cb_open_sf);

	sfile.fd = cpr_statefile_open(cpr_statefile, cpr_filesystem);
	if (sfile.fd == -1) {
		prom_printf("\n%s: can't open %s", prog, cpr_statefile);
		if (specialstate)
			prom_printf(" on %s", cpr_filesystem);
		prom_printf("\n%s\n", rsvp);
		return (ERR);
	}

	/*
	 * for block devices, seek past the disk label and bootblock
	 */
	if (specialstate)
		(void) prom_seek(sfile.fd, CPR_SPEC_OFFSET);

	return (0);
}


static int
cb_close_sf(void)
{
	CB_VENTRY(cb_close_sf);

	/*
	 * close the device so the prom will free up 20+ pages
	 */
	(void) cpr_statefile_close(sfile.fd);
	return (0);
}


/*
 * to restore kernel pages, we have to open a prom device to read-in
 * the statefile contents; a prom "open" request triggers the driver
 * and various packages to allocate 20+ pages; unfortunately, some or
 * all of those pages always clash with kernel pages, and we cant write
 * to them without corrupting the prom.
 *
 * to solve that problem, the only real solution is to close the device
 * to free up those pages; this means we need to open, read-in the entire
 * statefile, and close; and to store the statefile, we need to allocate
 * plenty of space, usually around 2 to 60 MB.
 *
 * the simplest alloc means is prom_alloc(), which will "claim" both
 * virt and phys pages, and creates mappings with a "map" request;
 * "map" also causes the prom to alloc pages, and again these clash
 * with kernel pages...
 *
 * to solve the "map" problem, we just reserve virt and phys pages and
 * manage the translations by creating our own tlb entries instead of
 * relying on the prom.
 *
 * sets globals:
 *	cpr_test_mode
 *	sfile.kpages
 *	sfile.size
 * 	sfile.buf
 * 	sfile.low_ppn
 * 	sfile.high_ppn
 */
static int
cb_read_statefile(void)
{
	size_t alsize, len, resid;
	physaddr_t phys, dst_phys;
	char *str, *dst_virt;
	int err, cnt, mmask;
	uint_t dtlb_index;
	ssize_t nread;
	cdd_t cdump;

	str = "cb_read_statefile";
	CB_VPRINTF((ent_fmt, str, entry));

	/*
	 * read-in and check cpr dump header
	 */
	if (cpr_read_cdump(sfile.fd, &cdump, CPR_MACHTYPE_4U))
		return (ERR);
	if (cpr_debug)
		prom_printf("\n");
	cb_nbitmaps = cdump.cdd_bitmaprec;
	cpr_test_mode = cdump.cdd_test_mode;
	sfile.kpages = cdump.cdd_dumppgsize;
	CPR_DEBUG(CPR_DEBUG4, "%s: total kpages %d\n", prog, sfile.kpages);

	/*
	 * alloc virt and phys space with 512K alignment;
	 * alloc size should be (n * tte size);
	 */
	sfile.size = PAGE_ROUNDUP(cdump.cdd_filesize);
	alsize = (cdump.cdd_filesize + MMU_PAGEOFFSET512K) &
	    MMU_PAGEMASK512K;
	phys = 0;
	err = cb_alloc(alsize, MMU_PAGESIZE512K, &sfile.buf, &phys);
	CB_VPRINTF(("%s:\n    alloc size 0x%lx, buf size 0x%lx\n"
	    "    virt 0x%p, phys 0x%llx\n",
	    str, alsize, sfile.size, sfile.buf, phys));
	if (err) {
		prom_printf("%s: cant alloc statefile buf, size 0x%lx\n%s\n",
		    str, sfile.size, rsvp);
		return (ERR);
	}

	/*
	 * record low and high phys page numbers for sfile.buf
	 */
	sfile.low_ppn = ADDR_TO_PN(phys);
	sfile.high_ppn = sfile.low_ppn + mmu_btop(sfile.size) - 1;

	/*
	 * setup destination virt and phys addrs for reads;
	 * mapin-mask tells when to create a new tlb entry for the
	 * next set of reads;  NB: the read and tlb method needs
	 * ((big-pagesize % read-size) == 0)
	 */
	dst_phys = phys;
	mmask = (MMU_PAGESIZE512K / PROM_MAX_READ) - 1;

	cnt = 0;
	dtlb_index = cb_dents - 1;
	if (specialstate)
		(void) prom_seek(sfile.fd, CPR_SPEC_OFFSET);
	else
		(void) cpr_fs_seek(sfile.fd, 0);
	CPR_DEBUG(CPR_DEBUG1, "%s: reading statefile... ", prog);
	for (resid = cdump.cdd_filesize; resid; resid -= len) {
		/*
		 * do a full spin (4 spin chars)
		 * for every MB read (8 reads = 256K)
		 */
		if ((cnt & 0x7) == 0)
			cb_spin();

		/*
		 * map-in statefile buf pages in 512K blocks;
		 * see MMU_PAGESIZE512K above
		 */
		if ((cnt & mmask) == 0) {
			dst_virt = sfile.buf;
			cb_mapin(dst_virt, ADDR_TO_PN(dst_phys),
			    TTE512K, TTE_HWWR_INT, dtlb_index);
		}

		cnt++;

		len = min(PROM_MAX_READ, resid);
		nread = cpr_read(sfile.fd, dst_virt, len);
		if (nread != (ssize_t)len) {
			prom_printf("\n%s: prom read error, "
			    "expect %ld, got %ld\n", str, len, nread);
			return (ERR);
		}
		dst_virt += len;
		dst_phys += len;
	}
	CPR_DEBUG(CPR_DEBUG1, " \b\n");

	/*
	 * free up any unused phys pages trailing the statefile buffer;
	 * these pages will later appear on the physavail list
	 */
	if (alsize > sfile.size) {
		len = alsize - sfile.size;
		prom_free_phys(len, phys + sfile.size);
		CB_VPRINTF(("%s: freed %ld phys pages (0x%lx - 0x%lx)\n",
		    str, mmu_btop(len), phys + sfile.size, phys + alsize));
	}

	/*
	 * start the statefile buffer offset at the base of
	 * the statefile buffer and skip past the dump header
	 */
	sfile.buf_offset = 0;
	SF_ADV(sizeof (cdump));

	/*
	 * finish with the first block mapped-in to provide easy virt access
	 * to machdep structs and the bitmap; for 2.8, the combined size of
	 * (cdd_t + cmd_t + csu_md_t + prom_words + cbd_t) is about 1K,
	 * leaving room for a bitmap representing nearly 32GB
	 */
	cb_mapin(sfile.buf, sfile.low_ppn,
	    TTE512K, TTE_HWWR_INT, dtlb_index);

	return (0);
}


/*
 * cprboot first stage worklist
 */
static int (*first_worklist[])(void) = {
	cb_intro,
	cb_mountroot,
	cb_startup,
	cb_get_props,
	cb_usb_setup,
	cb_unmountroot,
	cb_open_sf,
	cb_read_statefile,
	cb_close_sf,
	cb_check_machdep,
	cb_interpret,
	cb_get_physavail,
	cb_set_bitmap,
	cb_get_newstack,
	NULL
};

/*
 * cprboot second stage worklist
 */
static int (*second_worklist[])(void) = {
	cb_relocate,
	cb_tracking_setup,
	cb_restore_kpages,
	cb_terminator,
	cb_ksetup,
	cb_mpsetup,
	NULL
};


/*
 * simple loop driving major cprboot operations;
 * exits to prom if any error is returned
 */
static void
cb_drive(int (**worklist)(void))
{
	int i;

	for (i = 0; worklist[i] != NULL; i++) {
		if (worklist[i]())
			cb_exit_to_mon();
	}
}


/*
 * debugging support: drop to prom if do_halt is set
 */
static void
check_halt(char *str)
{
	if (do_halt) {
		prom_printf("\n%s halted by -h flag\n==> before %s\n\n",
		    prog, str);
		cb_enter_mon();
	}
}


/*
 * main is called twice from "cb_srt0.s", args are:
 *	cookie	  ieee1275 cif handle
 *	first	  (true): first stage, (false): second stage
 *
 * first stage summary:
 *	various setup
 *	allocate a big statefile buffer
 *	read in the statefile
 *	setup the bitmap
 *	create a new stack
 *
 * return to "cb_srt0.s", switch to new stack
 *
 * second stage summary:
 *	relocate cprboot phys pages
 *	setup tracking for statefile buffer pages
 *	restore kernel pages
 *	various cleanup
 *	install tlb entries for the nucleus and cpr module
 *	restore registers and jump into cpr module
 */
int
main(void *cookie, int first)
{
	if (first) {
		prom_init(prog, cookie);
		cb_msec = prom_gettime();
		get_bootargs();
		check_bootargs();
		check_halt("first_worklist");
		cb_drive(first_worklist);
		return (0);
	} else {
		cb_drive(second_worklist);
		if (verbose || CPR_DBG(1)) {
			prom_printf("%s: milliseconds %d\n",
			    prog, prom_gettime() - cb_msec);
			prom_printf("%s: resume pc 0x%lx\n",
			    prog, mdinfo.func);
			prom_printf("%s: exit_to_kernel(0x%p, 0x%p)\n\n",
			    prog, cookie, &mdinfo);
		}
		check_halt("exit_to_kernel");
		exit_to_kernel(cookie, &mdinfo);
		return (ERR);
	}
}
