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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2020 Peter Tribble.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <kvm.h>
#include <varargs.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/dkio.h>
#include "pdevinfo.h"
#include "display.h"
#include "pdevinfo_sun4u.h"
#include "display_sun4u.h"
#include "libprtdiag.h"


#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

extern	int sys_clk;

int
display(Sys_tree *tree,
	Prom_node *root,
	struct system_kstat_data *kstats,
	int syserrlog)
{
	int exit_code = 0;	/* init to all OK */
	void *value;		/* used for opaque PROM data */
	struct mem_total memory_total;	/* Total memory in system */

	sys_clk = -1;  /* System clock freq. (in MHz) */

	/*
	 * silently check for any types of machine errors
	 */
	exit_code = error_check(tree, kstats);

	/*
	 * Now display the machine's configuration. We do this if we
	 * are not logging or exit_code is set (machine is broke).
	 */
	if (!logging || exit_code) {
		struct utsname uts_buf;

		/*
		 * Display system banner
		 */
		(void) uname(&uts_buf);

		log_printf(dgettext(TEXT_DOMAIN, "System Configuration:  "
		    "Oracle Corporation  %s %s\n"), uts_buf.machine,
		    get_prop_val(find_prop(root, "banner-name")), 0);

		/* display system clock frequency */
		value = get_prop_val(find_prop(root, "clock-frequency"));
		if (value != NULL) {
			sys_clk = ((*((int *)value)) + 500000) / 1000000;
			log_printf(dgettext(TEXT_DOMAIN, "System clock "
			    "frequency: %d MHz\n"), sys_clk, 0);
		}

		/* Display the Memory Size */
		display_memorysize(tree, kstats, &memory_total);

		/* Display platform specific configuration info */
		display_platform_specific_header();

		/* Display the CPU devices */
		display_cpu_devices(tree);

		/* Display the Memory configuration */
		display_memoryconf(tree);

		/* Display all the IO cards. */
		(void) display_io_devices(tree);


		/*
		 * Display any Hot plugged, disabled and failed board(s)
		 * where appropriate.
		 */
		display_hp_fail_fault(tree, kstats);

		display_diaginfo((syserrlog || (logging && exit_code)),
		    root, tree, kstats);
	}

	return (exit_code);
}


int
error_check(Sys_tree *tree, struct system_kstat_data *kstats)
{
#ifdef	lint
	tree = tree;
	kstats = kstats;
#endif
	/*
	 * This function is intentionally empty
	 */
	return (0);
}

int
disp_fail_parts(Sys_tree *tree)
{
#ifdef	lint
	tree = tree;
#endif
	/*
	 * This function is intentionally empty
	 */
	return (0);
}


void
display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats)
{
#ifdef	lint
	tree = tree;
	kstats = kstats;
#endif
	/*
	 * This function is intentionally empty
	 */
}

void
display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
			struct system_kstat_data *kstats)
{
#ifdef	lint
	flag = flag;
	root = root;
	tree = tree;
	kstats = kstats;
#endif
	/*
	 * This function is intentionally empty
	 */
}


void
resolve_board_types(Sys_tree *tree)
{
#ifdef	lint
	tree = tree;
#endif
	/*
	 * This function is intentionally empty
	 */
}

void
display_boardnum(int num)
{
	log_printf("%2d   ", num, 0);
}


/*
 * The various platforms can over-ride this function to
 * return any platform specific configuration information
 * they may wish to return in addition to the generic output.
 */
void
display_platform_specific_header(void)
{
	/*
	 * This function is intentionally empty
	 */
}
