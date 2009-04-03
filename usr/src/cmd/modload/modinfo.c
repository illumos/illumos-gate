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

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/modctl.h>
#include <sys/errno.h>

static int wide;
static int count = 0;
static int first_mod = 1;

/*
 * When printing module load addresses on 32-bit kernels, the 8 hex
 * character field width is obviously adequate. On sparcv9 kernels
 * solely by virtue of the choice of code model enabled by the separate
 * kernel context, the text addresses are currently in the lower 4G
 * address range, and so -still- fit in 8 hex characters.
 *
 * However, amd64 kernels live at the top of the 64-bit address space, and
 * so as to be honest about the addresses (and since this is a tool for
 * humans to parse), we have to print out a 16 hex character address.
 *
 * We assume that we will print out all 16 hex characters on future
 * 64-bit kernel ports too.
 */
static const char header[] =
	" Id "
#if defined(_LP64) && !defined(__sparcv9)
	"        "
#endif
	"Loadaddr   Size Info Rev Module Name\n";

static char *cheader  =
	" Id    Loadcnt Module Name                            State\n";


static void usage();
static void print_info(struct modinfo *mi);
static void print_cinfo(struct modinfo *mi);

/*
 * These functions are in modsubr.c
 */
void fatal(char *fmt, ...);
void error(char *fmt, ...);

/*
 * Display information of all loaded modules
 */
int
main(int argc, char *argv[])
{
	struct modinfo modinfo;
	int info_all = 1;
	int id;
	int opt;

	id = -1;	/* assume we're getting all loaded modules */

	while ((opt = getopt(argc, argv, "i:wc")) != EOF) {
		switch (opt) {
		case 'i':
			if (sscanf(optarg, "%d", &id) != 1)
				fatal("Invalid id %s\n", optarg);
			if (id == -1)
				id = 0;
			info_all = 0;
			break;
		case 'w':
			wide++;
			break;
		case 'c':
			count++;
			break;
		case '?':
		default:
			usage();
			break;
		}
	}


	/*
	 * Next id of -1 means we're getting info on all modules.
	 */
	modinfo.mi_id = modinfo.mi_nextid = id;
	modinfo.mi_info = (info_all) ? MI_INFO_ALL : MI_INFO_ONE;

	if (count)
		modinfo.mi_info |= MI_INFO_CNT;

	do {
		/*
		 * Get module information.
		 * If modinfo.mi_nextid == -1, get info about the
		 * next installed module with id > "id."
		 * Otherwise, get info about the module with id == "id."
		 */
		if (modctl(MODINFO, id, &modinfo) < 0) {
			if (!info_all)
				error("can't get module information");
			break;
		}

		if (first_mod) {
			first_mod = 0;
			(void) printf("%s", count ? cheader : header);
		}
		if (count)
			print_cinfo(&modinfo);
		else
			print_info(&modinfo);
		/*
		 * If we're getting info about all modules, the next one
		 * we want is the one with an id greater than this one.
		 */
		id = modinfo.mi_id;
	} while (info_all);

	return (0);
}

/*
 * Display loadcounts.
 */
static void
print_cinfo(struct modinfo *mi)
{
	(void) printf("%3d %10d %-32s", mi->mi_id, mi->mi_loadcnt, mi->mi_name);
	(void) printf(" %s/%s\n",
	    mi->mi_state & MI_LOADED ? "LOADED" : "UNLOADED",
	    mi->mi_state & MI_INSTALLED ? "INSTALLED" : "UNINSTALLED");
}

/*
 * Display info about a loaded module.
 *
 * The sparc kernel resides in its own address space, with modules
 * loaded at low addresses.  The low 32-bits of a module's base
 * address is sufficient but does put a cap at 4gb here.
 * The x86 64-bit kernel is loaded in high memory with the full
 * address provided.
 */
static void
print_info(struct modinfo *mi)
{
	int n, p0;
	char namebuf[256];

	for (n = 0; n < MODMAXLINK; n++) {
		if (n > 0 && mi->mi_msinfo[n].msi_linkinfo[0] == '\0')
			break;

		(void) printf("%3d ", mi->mi_id);
#if defined(_LP64) && !defined(__sparcv9)
		(void) printf("%16lx ", (uintptr_t)mi->mi_base);
#elif defined(_LP64)
		(void) printf("%8lx ", (uintptr_t)mi->mi_base);
#else
		(void) printf("%8x ", (uintptr_t)mi->mi_base);
#endif
#if defined(_LP64)
		(void) printf("%6lx ", mi->mi_size);
#else
		(void) printf("%6x ", mi->mi_size);
#endif

		p0 = mi->mi_msinfo[n].msi_p0;

		if (p0 != -1)
			(void) printf("%3d ", p0);
		else
			(void) printf("  - ");

		(void) printf("  %d  ", mi->mi_rev);

		mi->mi_name[MODMAXNAMELEN - 1] = '\0';
		mi->mi_msinfo[n].msi_linkinfo[MODMAXNAMELEN - 1] = '\0';

		if (wide) {
			(void) printf("%s (%s)\n", mi->mi_name,
			    mi->mi_msinfo[n].msi_linkinfo);
		} else {
			/* snprintf(3c) will always append a null character */
			(void) snprintf(namebuf, sizeof (namebuf), "%s (%s)",
			    mi->mi_name, mi->mi_msinfo[n].msi_linkinfo);
#if defined(_LP64) && !defined(__sparcv9)
			(void) printf("%.43s\n", namebuf);
#else
			(void) printf("%.51s\n", namebuf);
#endif
		}
	}
}

static void
usage()
{
	fatal("usage:  modinfo [-w] [-c] [-i module-id]\n");
}
