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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <varargs.h>
#include <errno.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <kstat.h>
#include <libintl.h>
#include "pdevinfo.h"
#include "display.h"
#include "display_sun4v.h"
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
 * of prtdiag due to the port to the sun4v platform. The PROM
 * tree-walking functions which contain sun4v specifics were moved
 * into this module.
 */

extern int get_id(Prom_node *);

/* Function prototypes */
Prom_node *sun4v_walk(Sys_tree *, Prom_node *, int);
picl_errno_t sun4v_get_node_by_name(picl_nodehdl_t, char *, picl_nodehdl_t *);

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
	picl_nodehdl_t	rooth;		/* root PICL node for IO display */
	picl_nodehdl_t plafh;		/* Platform PICL node for IO display */

	picl_errno_t err;

	err = picl_initialize();
	if (err != PICL_SUCCESS) {
		(void) fprintf(stderr, EM_INIT_FAIL, picl_strerror(err));
		exit(1);
	}

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

	root_node = sun4v_walk(&sys_tree, NULL, next(0));
	promclose();

	err = picl_get_root(&rooth);
	if (err != PICL_SUCCESS) {
		(void) fprintf(stderr, EM_GET_ROOT_FAIL, picl_strerror(err));
		exit(1);
	}

	err = sun4v_get_node_by_name(rooth, PICL_NODE_PLATFORM, &plafh);
	if (err != PICL_SUCCESS)
		return (err);

	return (sun4v_display(&sys_tree, root_node, syserrlog, plafh));

}

/*
 * sun4v_Walk the PROM device tree and build the system tree and root tree.
 * Nodes that have a board number property are placed in the board
 * structures for easier processing later. Child nodes are placed
 * under their parents.
 */
Prom_node *
sun4v_walk(Sys_tree *tree, Prom_node *root, int id)
{
	register int curnode;
	Prom_node *pnode;
	char *name;
	char *type;
	char *compatible;
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
	 * this. This is where we start hacking.
	 *
	 * PCI to PCI bridges also have the name "pci", but with different
	 * model property values.  They should not be put under 'board'.
	 */
	name = get_node_name(pnode);
	type = get_node_type(pnode);
	compatible = (char *)get_prop_val(find_prop(pnode, "compatible"));

#ifdef DEBUG
	if (name != NULL)
		printf("name=%s ", name);
	if (type != NULL)
		printf("type=%s ", type);
	printf("\n");
#endif
	if (compatible == NULL)
		compatible = "";
	if (type == NULL)
		type = "";
	if (name != NULL) {
		if (has_board_num(pnode)) {
			add_node(tree, pnode);
			board_node = 1;
#ifdef DEBUG
			printf("ADDED BOARD name=%s type=%s compatible=%s\n",
				name, type, compatible);
#endif
		} else if (strcmp(type, "cpu") == 0) {
			add_node(tree, pnode);
			board_node = 1;
#ifdef DEBUG
			printf("ADDED BOARD name=%s type=%s compatible=%s\n",
				name, type, compatible);
#endif
		}
#ifdef DEBUG
		else
			printf("node not added: name=%s type=%s\n", name, type);
#endif
	}

	if (curnode = child(id)) {
		pnode->child = sun4v_walk(tree, pnode, curnode);
	}

	if (curnode = next(id)) {
		if (board_node) {
			return (sun4v_walk(tree, root, curnode));
		} else {
			pnode->sibling = sun4v_walk(tree, root, curnode);
		}
	}

	if (board_node) {
		return (NULL);
	} else {
		return (pnode);
	}
}

/*
 * search children to get the node by the nodename
 */
picl_errno_t
sun4v_get_node_by_name(picl_nodehdl_t rooth, char *name,
    picl_nodehdl_t *nodeh)
{
	picl_nodehdl_t	childh;
	int		err;
	char		*nodename;

	nodename = alloca(strlen(name) + 1);
	if (nodename == NULL)
		return (PICL_FAILURE);

	err = picl_get_propval_by_name(rooth, PICL_PROP_CHILD, &childh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(childh, PICL_PROP_NAME,
		    nodename, (strlen(name) + 1));
		if (err != PICL_SUCCESS) {
			err = picl_get_propval_by_name(childh, PICL_PROP_PEER,
				&childh, sizeof (picl_nodehdl_t));
			continue;
		}

		if (strcmp(nodename, name) == 0) {
			*nodeh = childh;
			return (PICL_SUCCESS);
		}

		err = picl_get_propval_by_name(childh, PICL_PROP_PEER,
		    &childh, sizeof (picl_nodehdl_t));
	}

	return (err);
}

int
get_id(Prom_node *node)
{
#ifdef	lint
	node = node;
#endif

	/*
	 * This function is intentionally empty
	 */
	return (0);
}
