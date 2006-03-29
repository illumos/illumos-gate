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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Starfire Platform specific functions.
 *
 * 	called when :
 *	machine_type == MTYPE_STARFIRE
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (starfire systems only)
 */
int	error_check(Sys_tree *tree, struct system_kstat_data *kstats);
void	display_memoryconf(Sys_tree *tree, struct grp_info *grps);
void	display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
				struct system_kstat_data *kstats);
void	display_mid(int mid);
void	display_pci(Board_node *);
Prom_node	*find_device(Board_node *, int, char *);

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif


int
error_check(Sys_tree *tree, struct system_kstat_data *kstats)
{
#ifdef lint
	tree = tree;
	kstats = kstats;
#endif
	return (0);
}

void
display_memoryconf(Sys_tree *tree, struct grp_info *grps)
{
	Board_node *bnode;
	char indent_str[] = "           ";

#ifdef lint
	grps = grps;
#endif

	/* Print the header for the memory section. */
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(dgettext(TEXT_DOMAIN, " Memory "), 0);
	log_printf("=========================", 0);
	log_printf("\n\n", 0);

	/* Print the header for the memory section. */
	log_printf(indent_str, 0);
	log_printf("Memory Units: Size \n", 0);
	log_printf(indent_str, 0);
	log_printf("0: MB   1: MB   2: MB   3: MB\n", 0);
	log_printf(indent_str, 0);
	log_printf("-----   -----   -----   ----- \n", 0);

	/* Run thru the board and display its memory if any */
	bnode = tree->bd_list;
	while (bnode != NULL) {
		Prom_node *pnode;
		unsigned int *memsize;
		unsigned int mbyte = 1024*1024;

		/*
		 * Find the mem-unit of the board.
		 * If the board has memory, a mem-unit pnode should
		 * be there.
		 */
		pnode = dev_find_node(bnode->nodes, "mem-unit");

		if (pnode != NULL) {
			/* there is a mem-unit in the board */

			/* Print the board header */
			log_printf("Board%2d  ", bnode->board_num, 0);

			memsize = get_prop_val(find_prop(pnode, "size"));

			log_printf("   %4d    %4d    %4d    %4d \n",
				memsize[0]/mbyte, memsize[1]/mbyte,
				memsize[2]/mbyte, memsize[3]/mbyte, 0);
		}
		bnode = bnode->next;
	}
	log_printf("\n", 0);
}

void
display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats)
{
#ifdef lint
	tree = tree;
	kstats = kstats;
#endif
}

void
display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
	struct system_kstat_data *kstats)
{

	char hostname[128];	/* used for starfire output */
	struct utsname uts_buf;

#ifdef lint
	flag = flag;
	root = root;
	tree = tree;
	kstats = kstats;
#endif

	/*
	 * Get hostname from system Banner
	 */
	(void) uname(&uts_buf);
	strcpy(hostname, uts_buf.nodename);

	/*
	 * We can't display diagnostic/env information for starfire.
	 * The diagnostic information may be displayed through
	 * commands in ssp.
	 */
	log_printf(dgettext(TEXT_DOMAIN,
		"\nFor diagnostic information,"), 0);
	log_printf("\n", 0);
	log_printf(dgettext(TEXT_DOMAIN, "see /var/opt/SUNWssp/adm/%s/messages "
		"on the SSP."), hostname, 0);
	log_printf("\n", 0);
}

void
display_mid(int mid)
{
	log_printf("  %2d     ", mid % 4, 0);
}

/*
 * display_pci
 * Call the generic psycho version of this function.
 */
void
display_pci(Board_node *board)
{
	display_psycho_pci(board);
}

/*
 * Find the device on the current board with the requested device ID
 * and name. If this rountine is passed a NULL pointer, it simply returns
 * NULL.
 */
Prom_node *
find_device(Board_node *board, int id, char *name)
{
	Prom_node *pnode;
	int mask;

	/* find the first cpu node */
	pnode = dev_find_node(board->nodes, name);

	mask = 0x7F;
	while (pnode != NULL) {
		if ((get_id(pnode) & mask) == id)
			return (pnode);

		pnode = dev_next_node(pnode, name);
	}
	return (NULL);
}
