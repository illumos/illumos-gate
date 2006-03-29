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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <varargs.h>
#include <errno.h>
#include <unistd.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <kstat.h>
#include <libintl.h>
#include "pdevinfo.h"
#include "pdevinfo_sun4u.h"
#include "display.h"
#include "display_sun4u.h"
#include "libprtdiag.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/*
 * Global variables
 */
char	*progname;
char	*promdev = "/dev/openprom";
int	print_flag = 1;
int	logging = 0;

/*
 * This file represents the splitting out of some functionality
 * of prtdiag due to the port to the sun4u platform. The PROM
 * tree-walking functions which contain sun4u specifics were moved
 * into this module.
 */

extern int get_id(Prom_node *);

/* Function prototypes */
Prom_node	*walk(Sys_tree *, Prom_node *, int);

/*
 * do_prominfo() is called from main() in usr/src/cmd/prtdiag/main.c
 *
 * This is the starting point for all platforms. However, this function
 * can be overlayed by writing a do_prominfo() function
 * in the libprtdiag_psr for a particular platform.
 *
 */
int
do_prominfo(int syserrlog, char *pgname, int log_flag, int prt_flag)
{
	Sys_tree sys_tree;		/* system information */
	Prom_node *root_node;		/* root node of OBP device tree */
	struct system_kstat_data sys_kstat; /* kstats for non-OBP data */


	/* set the global flags */
	progname = pgname;
	logging = log_flag;
	print_flag = prt_flag;

	/* set the the system tree fields */
	sys_tree.sys_mem = NULL;
	sys_tree.boards = NULL;
	sys_tree.bd_list = NULL;
	sys_tree.board_cnt = 0;

	if (promopen(O_RDONLY))  {
		exit(_error(dgettext(TEXT_DOMAIN, "openeepr device "
			"open failed")));
	}

	if (is_openprom() == 0)  {
		(void) fprintf(stderr, "%s",
			dgettext(TEXT_DOMAIN, "System architecture "
			    "does not support this option of this "
			    "command.\n"));
		return (2);
	}

	if (next(0) == 0) {
		return (2);
	}

	root_node = walk(&sys_tree, NULL, next(0));
	promclose();

	/* resolve the board types now */
	resolve_board_types(&sys_tree);

	read_sun4u_kstats(&sys_tree, &sys_kstat);

	return (display(&sys_tree, root_node, &sys_kstat, syserrlog));

}

int
get_id(Prom_node *node)
{
	int *value;

	/*
	 * check for upa-portid on UI and UII systems
	 */
	if ((value = (int *)get_prop_val(find_prop(node, "upa-portid")))
	    == NULL) {
		/*
		 * check for portid on UIII systems
		 */
		if ((value = (int *)get_prop_val(find_prop(node, "portid")))
		    == NULL) {
			return (-1);
		}
	}
	return (*value);
}



/*
 * Walk the PROM device tree and build the system tree and root tree.
 * Nodes that have a board number property are placed in the board
 * structures for easier processing later. Child nodes are placed
 * under their parents. ffb (Fusion Frame Buffer) nodes are handled
 * specially, because they do not contain board number properties.
 * This was requested from OBP, but was not granted. So this code
 * must parse the MID of the FFB to find the board#.
 *
 */
Prom_node *
walk(Sys_tree *tree, Prom_node *root, int id)
{
	register int curnode;
	Prom_node *pnode;
	char *name;
	char *type;
	char *model;
	int board_node = 0;

	/* allocate a node for this level */
	if ((pnode = (Prom_node *) malloc(sizeof (struct prom_node))) ==
	    NULL) {
		perror("malloc");
		exit(2);	/* program errors cause exit 2 */
	}

	/* assign parent Prom_node */
	pnode->parent = root;
	pnode->sibling = NULL;
	pnode->child = NULL;

	/* read properties for this node */
	dump_node(pnode);

	/*
	 * Place a node in a 'board' if it has 'board'-ness. The definition
	 * is that all nodes that are children of root should have a
	 * board# property. But the PROM tree does not exactly follow
	 * this. This is where we start hacking. The name 'ffb' can
	 * change, so watch out for this.
	 *
	 * The UltraSPARC, sbus, pci and ffb nodes will exit in
	 * the desktops and will not have board# properties. These
	 * cases must be handled here.
	 *
	 * PCI to PCI bridges also have the name "pci", but with different
	 * model property values.  They should not be put under 'board'.
	 */
	name = get_node_name(pnode);
	type = get_node_type(pnode);
	model = (char *)get_prop_val(find_prop(pnode, "model"));
#ifdef DEBUG
	if (name != NULL)
		printf("name=%s ", name);
	if (type != NULL)
		printf("type=%s ", type);
	if (model != NULL)
		printf("model=%s", model);
	printf("\n");
#endif
	if (model == NULL)
		model = "";
	if (type == NULL)
		type = "";
	if (name != NULL) {
		if (has_board_num(pnode)) {
			add_node(tree, pnode);
			board_node = 1;
#ifdef DEBUG
			printf("ADDED BOARD name=%s type=%s model=%s\n",
				name, type, model);
#endif
		} else if ((strcmp(name, FFB_NAME)  == 0)	||
		    (strcmp(name, AFB_NAME) == 0)		||
		    (strcmp(type, "cpu") == 0)			||

		    ((strcmp(type, "memory-controller") == 0) &&
			(strcmp(name, "ac") != 0))			||

		    ((strcmp(name, "pci") == 0) &&
			(strcmp(model, "SUNW,psycho") == 0))		||

		    ((strcmp(name, "pci") == 0) &&
			(strcmp(model, "SUNW,sabre") == 0))		||

		    ((strcmp(name, "pci") == 0) &&
			(strcmp(model, "SUNW,schizo") == 0))		||

		    ((strcmp(name, "pci") == 0) &&
			(strcmp(model, "SUNW,xmits") == 0))		||

		    (strcmp(name, "counter-timer") == 0)		||
		    (strcmp(name, "sbus") == 0)) {
			add_node(tree, pnode);
			board_node = 1;
#ifdef DEBUG
			printf("ADDED BOARD name=%s type=%s model=%s\n",
				name, type, model);
#endif
		}
#ifdef DEBUG
		else
			printf("node not added: name=%s type=%s\n", name, type);
#endif
	}

	if (curnode = child(id)) {
		pnode->child = walk(tree, pnode, curnode);
	}

	if (curnode = next(id)) {
		if (board_node) {
			return (walk(tree, root, curnode));
		} else {
			pnode->sibling = walk(tree, root, curnode);
		}
	}

	if (board_node) {
		return (NULL);
	} else {
		return (pnode);
	}
}
