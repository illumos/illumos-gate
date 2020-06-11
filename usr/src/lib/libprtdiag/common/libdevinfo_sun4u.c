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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <libdevinfo.h>

#include "pdevinfo.h"
#include "pdevinfo_sun4u.h"
#include "display.h"
#include "display_sun4u.h"
#include "libprtdiag.h"

/*
 * This file contains the functions that are to be called when
 * a platform wants to use libdevinfo for it's device information
 * instead of OBP. This will allow prtdiag to support hot-plug
 * events on platforms whose OBP doesn't get updated to reflect
 * the hot-plug changes to the system.
 */

int	do_devinfo(int syserrlog, char *pgname, int log_flag,
    int prt_flag);
static void dump_di_node(Prom_node *pnode, di_node_t di_node);
static Prom_node *walk_di_tree(Sys_tree *tree, Prom_node *root,
    di_node_t di_node);
static int match_compatible_name(char *, int, char *);

/*
 * Global variables
 */
di_prom_handle_t	ph;	/* Handle for using di_prom interface */
extern  char		*progname;



/*
 * Used instead of the walk() function when a platform wants to
 * walk libdevinfo's device tree instead of walking OBP's
 * device tree.
 */
static Prom_node*
walk_di_tree(Sys_tree *tree, Prom_node *root, di_node_t di_node)
{
	di_node_t	curnode;
	Prom_node	*pnode;
	char		*name, *type, *model, *compatible_array;
	int		board_node = 0;
	int		*int_val;
	int		is_schizo = 0, n_names;
#ifdef DEBUG
	int		portid;
#endif

	/* allocate a node for this level */
	if ((pnode = (Prom_node *) malloc(sizeof (struct prom_node))) ==
	    NULL) {
		perror("malloc");
		exit(2);
	}

	/* assign parent Prom_node */
	pnode->parent = root;
	pnode->sibling = NULL;
	pnode->child = NULL;

	/* read properties for this node */
	dump_di_node(pnode, di_node);

	name = get_node_name(pnode);
	type = get_node_type(pnode);
	if (type == NULL)
		type = "";
	model = (char *)get_prop_val(find_prop(pnode, "model"));
	if (model == NULL)
		model = "";

	/*
	 * For identifying Schizo nodes we need to check if the
	 * compatible property contains the string 'pci108e,8001'.
	 * This property contains an array of strings so we need
	 * search all strings.
	 */
	if ((n_names = di_compatible_names(di_node, &compatible_array)) > 0) {
		if (match_compatible_name(compatible_array, n_names,
		    "pci108e,8001"))
			is_schizo = 1;
	}

#ifdef DEBUG
	if (int_val = (int *)get_prop_val(find_prop(pnode, "portid")))
		portid = *int_val;
	else if ((strcmp(type, "cpu") == 0) &&
	    (int_val = (int *)get_prop_val(find_prop(pnode->parent, "portid"))))
		portid = *int_val;
	else
		portid = -1;

	if (name != NULL)
		printf("name=%s\n", name);
	if (type != NULL)
		printf("type=%s\n", type);
	if (model != NULL)
		printf("model=%s\n", model);
	printf("portid=%d\n", portid);
#endif

	if (name != NULL) {
		if (has_board_num(pnode)) {
			add_node(tree, pnode);
			board_node = 1;
			D_PRINTF("\n---\nnodename = %s [ %s ] \n",
			    di_node_name(di_node), di_devfs_path(di_node));
			D_PRINTF("ADDED BOARD name=%s type=%s model=%s "
			    "portid =%d\n", name, type, model, portid);
		} else if ((strcmp(name, FFB_NAME) == 0) ||
		    (strcmp(type, "cpu") == 0) ||

		    ((strcmp(type, "memory-controller") == 0) &&
		    (strcmp(name, "ac") != 0)) ||

		    ((strcmp(name, "pci") == 0) &&
		    (strcmp(model, "SUNW,psycho") == 0)) ||

		    ((strcmp(name, "pci") == 0) &&
		    (strcmp(model, "SUNW,sabre") == 0)) ||

		    ((strcmp(name, "pci") == 0) && (is_schizo)) ||

		    (strcmp(name, "counter-timer") == 0) ||
		    (strcmp(name, "sbus") == 0)) {
			add_node(tree, pnode);
			board_node = 1;
			D_PRINTF("\n---\nnodename = %s [ %s ] \n",
			    di_node_name(di_node), di_devfs_path(di_node));
			D_PRINTF("ADDED BOARD name=%s type=%s model=%s\n",
			    name, type, model);
		}
	} else {
		D_PRINTF("node not added: type=%s portid =%d\n", type, portid);
	}

	if (curnode = di_child_node(di_node)) {
		pnode->child = walk_di_tree(tree, pnode, curnode);
	}

	if (curnode = di_sibling_node(di_node)) {
		if (board_node) {
			return (walk_di_tree(tree, root, curnode));
		} else {
			pnode->sibling = walk_di_tree(tree, root, curnode);
		}
	}

	/*
	 * This check is needed in case the "board node" occurs at the
	 * end of the sibling chain as opposed to the middle or front.
	 */
	if (board_node)
		return (NULL);

	return (pnode);
}

/*
 * Dump all the devinfo properties and then the obp properties for
 * the specified devinfo node into the Prom_node structure.
 */
static void
dump_di_node(Prom_node *pnode, di_node_t di_node)
{
	Prop *prop = NULL;	/* tail of properties list */

	Prop		*temp;	/* newly allocated property */
	di_prop_t	di_prop;
	di_prom_prop_t	p_prop;
	int		retval = 0;
	int		i;

	/* clear out pointers in pnode */
	pnode->props = NULL;

	D_PRINTF("\n\n ------- Dumping devinfo properties for node ------\n");

	/*
	 * get all the devinfo properties first
	 */
	for (di_prop = di_prop_next(di_node, DI_PROP_NIL);
	    di_prop != DI_PROP_NIL;
	    di_prop = di_prop_next(di_node, di_prop)) {

		char		*di_name;
		void		*di_data;
		int		di_ptype;

		di_name = di_prop_name(di_prop);
		if (di_name == (char *)NULL)
			continue;

		di_ptype = di_prop_type(di_prop);
		D_PRINTF("DEVINFO Properties  %s: ", di_name);

		switch (di_ptype) {
		case DI_PROP_TYPE_INT:
			retval = di_prop_lookup_ints(DDI_DEV_T_ANY,
			    di_node, di_name, (int **)&di_data);
			if (retval > 0) {
				D_PRINTF("0x%x\n", *(int *)di_data);
			}
			break;
		case DI_PROP_TYPE_STRING:
			retval = di_prop_lookup_strings(DDI_DEV_T_ANY,
			    di_node, di_name, (char **)&di_data);
			if (retval > 0) {
				D_PRINTF("%s\n", (char *)di_data);
			}
			break;
		case DI_PROP_TYPE_BYTE:
			retval = di_prop_lookup_bytes(DDI_DEV_T_ANY,
			    di_node, di_name, (uchar_t **)&di_data);
			if (retval > 0) {
				D_PRINTF("%s\n", (char *)di_data);
			}
			break;
		case DI_PROP_TYPE_UNKNOWN:
			retval = di_prop_lookup_bytes(DDI_DEV_T_ANY,
			    di_node, di_name, (uchar_t **)&di_data);
			if (retval > 0) {
				D_PRINTF("%s\n", (char *)di_data);
			}
			break;
		case DI_PROP_TYPE_BOOLEAN:
			di_data = NULL;
			retval = 1;
			break;
		default:
			D_PRINTF(" Skipping property\n");
			retval = -1;
		}

		if (retval <= 0)
			continue;

		/* allocate space for the property */
		if ((temp = (Prop *) malloc(sizeof (Prop))) == NULL) {
			perror("malloc");
			exit(1);
		}

		/*
		 * Given that we're using libdevinfo rather than OBP,
		 * the chances are that future accesses to di_name and
		 * di_data will be via temp->name.val_ptr and
		 * temp->value.val_ptr respectively. However, this may
		 * not be the case, so we have to suitably fill in
		 * temp->name.opp and temp->value.opp.
		 *
		 * di_name is char * and non-NULL if we've made it to
		 * here, so we can simply point
		 * temp->name.opp.oprom_array to temp->name.val_ptr.
		 *
		 * di_data could be NULL, char * or int * at this point.
		 * If it's non-NULL, a 1st char of '\0' indicates int *.
		 * We thus set temp->value.opp.oprom_node[] (although
		 * interest in any element other than 0 is rare, all
		 * elements must be set to ensure compatibility with
		 * OBP), and holds_array is set to 0.
		 *
		 * If di_data is NULL, or the 1st char is not '\0', we set
		 * temp->value.opp.oprom_array. If di_ptype is
		 * DI_PROP_TYPE_BOOLEAN, holds_array is set to 0, else it
		 * is set to 1.
		 */
		temp->name.val_ptr = (void *)di_name;
		temp->name.opp.oprom_array = temp->name.val_ptr;
		temp->name.opp.holds_array = 1;

		temp->value.val_ptr = (void *)di_data;
		if ((di_data != NULL) && (*((char *)di_data) == '\0')) {
			for (i = 0; i < OPROM_NODE_SIZE; i++)
				temp->value.opp.oprom_node[i] =
				    *((int *)di_data+i);

			temp->value.opp.holds_array = 0;
		} else {
			temp->value.opp.oprom_array = temp->value.val_ptr;
			if (di_ptype == DI_PROP_TYPE_BOOLEAN)
				temp->value.opp.holds_array = 0;
			else
				temp->value.opp.holds_array = 1;
		}

		temp->size = retval;

		/* everything worked so link the property list */
		if (pnode->props == NULL)
			pnode->props = temp;
		else if (prop != NULL)
			prop->next = temp;
		prop = temp;
		prop->next = NULL;
	}

	/*
	 * Then get all the OBP properties.
	 */
	for (p_prop = di_prom_prop_next(ph, di_node, DI_PROM_PROP_NIL);
	    p_prop != DI_PROM_PROP_NIL;
	    p_prop = di_prom_prop_next(ph, di_node, p_prop)) {

		char		*p_name;
		unsigned char	*p_data;

		p_name = di_prom_prop_name(p_prop);
		if (p_name == (char *)NULL)
			retval = -1;
		else
			retval = di_prom_prop_data(p_prop, &p_data);

		if (retval <= 0)
			continue;

		/* allocate space for the property */
		if ((temp = (Prop *) malloc(sizeof (Prop))) == NULL) {
			perror("malloc");
			exit(1);
		}

		/*
		 * As above, p_name is char * and non-NULL if we've made
		 * it to here, so we can simply point
		 * temp->name.opp.oprom_array to temp->name.val_ptr.
		 *
		 * p_data could be NULL, a character or a number at this
		 * point. If it's non-NULL, a 1st char of '\0' indicates a
		 * number, so we set temp->value.opp.oprom_node[] (again
		 * setting every element to ensure OBP compatibility).
		 * These assignments create a lint error, hence the LINTED
		 * comment.
		 *
		 * If p_data is NULL, or the 1st char is not '\0', we set
		 * temp->value.opp.oprom_array.
		 */
		temp->name.val_ptr = (void *)p_name;
		temp->name.opp.oprom_array = temp->name.val_ptr;
		temp->name.opp.holds_array = 1;

		temp->value.val_ptr = (void *)p_data;
		if ((p_data != NULL) && (*p_data == '\0')) {
			for (i = 0; i < OPROM_NODE_SIZE; i++)
				temp->value.opp.oprom_node[i] =
				    *((int *)p_data+i);

			temp->value.opp.holds_array = 0;
		} else {
			temp->value.opp.oprom_array = temp->value.val_ptr;
			temp->value.opp.holds_array = 1;
		}

		temp->size = retval;

		/* everything worked so link the property list */
		if (pnode->props == NULL) {
			pnode->props = temp;
		} else if (prop != NULL) {
			prop->next = temp;
		}
		prop = temp;
		prop->next = NULL;
	}
}

/*
 * Used in place of do_prominfo() when a platform wants to use
 * libdevinfo for getting the device tree instead of OBP.
 */
int
do_devinfo(int syserrlog, char *pgname, int log_flag, int prt_flag)
{
	Sys_tree sys_tree;		/* system information */
	Prom_node *root_node;		/* root node of OBP device tree */
	di_node_t di_root_node;		/* root of the devinfo tree */
	struct system_kstat_data sys_kstat; /* kstats for non-OBP data */
	int retval = -1;

	/* set the global flags */
	progname = pgname;
	logging = log_flag;
	print_flag = prt_flag;

	/* set the the system tree fields */
	sys_tree.sys_mem = NULL;
	sys_tree.boards = NULL;
	sys_tree.bd_list = NULL;
	sys_tree.board_cnt = 0;

	/*
	 * create a snapshot of the kernel device tree
	 * and return a handle to it.
	 */
	if ((di_root_node = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		exit(_error("di_init() failed"));
	}

	/*
	 * create a handle to the PROM device tree.
	 */
	if ((ph = di_prom_init()) == NULL) {
		exit(_error("di_prom_init() failed"));
	}

	/*
	 * walk the devinfo tree and build up a list of all
	 * nodes and properties.
	 */
	root_node = walk_di_tree(&sys_tree, NULL, di_root_node);

	/* resolve the board types now */
	resolve_board_types(&sys_tree);

	read_sun4u_kstats(&sys_tree, &sys_kstat);
	retval = display(&sys_tree, root_node, &sys_kstat, syserrlog);

	di_fini(di_root_node);
	di_prom_fini(ph);
	return (retval);
}

/*
 * check to see if the name shows up in the compatible array
 */
static int
match_compatible_name(char *compatible_array, int n_names, char *name)
{
	int	i, ret = 0;

	/* parse the compatible list */
	for (i = 0; i < n_names; i++) {
		if (strcmp(compatible_array, name) == 0) {
			ret = 1;
			break;
		}
		compatible_array += strlen(compatible_array) + 1;
	}
	return (ret);
}
