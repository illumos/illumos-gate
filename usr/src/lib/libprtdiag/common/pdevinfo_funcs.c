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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <libintl.h>
#include "pdevinfo.h"
#include "display.h"
#include "pdevinfo_sun4u.h"

/*
 * For machines that support the openprom, fetch and print the list
 * of devices that the kernel has fetched from the prom or conjured up.
 *
 */


static int prom_fd;
extern char *progname;
extern char *promdev;
extern void getppdata();
extern void printppdata();

/*
 * Define DPRINT for run-time debugging printf's...
 * #define DPRINT	1
 */

#ifdef	DPRINT
static	char    vdebug_flag = 1;
#define	dprintf	if (vdebug_flag) printf
static void dprint_dev_info(caddr_t, dev_info_t *);
#endif	/* DPRINT */

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/*VARARGS1*/
int
_error(char *fmt, ...)
{
	int saved_errno;
	va_list ap;
	extern int errno;
	saved_errno = errno;

	if (progname)
		(void) fprintf(stderr, "%s: ", progname);

	va_start(ap, fmt);

	(void) vfprintf(stderr, fmt, ap);

	va_end(ap);

	(void) fprintf(stderr, ": ");
	errno = saved_errno;
	perror("");

	return (2);
}

int
is_openprom(void)
{
	Oppbuf	oppbuf;
	register struct openpromio *opp = &(oppbuf.opp);
	register unsigned int i;

	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETCONS, opp) < 0)
		exit(_error("OPROMGETCONS"));

	i = (unsigned int)((unsigned char)opp->oprom_array[0]);
	return ((i & OPROMCONS_OPENPROM) == OPROMCONS_OPENPROM);
}

/*
 * Read all properties and values from nodes.
 * Copy the properties read into the prom_node passsed in.
 */
void
dump_node(Prom_node *node)
{
	Oppbuf oppbuf;
	register struct openpromio *opp = &oppbuf.opp;
	Prop *prop = NULL;	/* tail of properties list */
	StaticProp *temp;

	/* clear out pointers in pnode */
	node->props = NULL;

	/* get first prop by asking for null string */
	(void) memset((void *) oppbuf.buf, 0, BUFSIZE);

	/* allocate space for the property */
	if ((temp = malloc(sizeof (StaticProp))) == NULL) {
		perror("malloc");
		exit(1);
	}

	opp->oprom_size = MAXPROPSIZE;
	while (opp->oprom_size != 0) {
		Prop *new;
		int i;
		char *tempp, *newp;

		/*
		 * get property
		 */
		opp->oprom_size = MAXPROPSIZE;

		if (ioctl(prom_fd, OPROMNXTPROP, opp) < 0)
			exit(_error("OPROMNXTPROP"));

		if (opp->oprom_size != 0) {
			temp->name.opp.oprom_size = opp->oprom_size;
			(void) strcpy(temp->name.opp.oprom_array,
				opp->oprom_array);

			(void) strcpy(temp->value.opp.oprom_array,
				temp->name.opp.oprom_array);
			getpropval(&temp->value.opp);
			temp->size = temp->value.opp.oprom_size;

			/* Now copy over temp's data to new. */
			if ((new = malloc(sizeof (Prop))) == NULL) {
				perror("malloc");
				exit(1);
			}

			/*
			 * First copy over temp->name's data. The
			 * temp->name.opp.opio_u union always contains char[]
			 * (as opposed to an int or int []).
			 */
			new->name.opp.oprom_size = temp->name.opp.oprom_size;

			if ((new->name.opp.oprom_array =
			    malloc(new->name.opp.oprom_size)) == NULL) {
				perror("malloc");
				exit(1);
			}
			(void) strcpy(new->name.opp.oprom_array,
			    temp->name.opp.oprom_array);

			new->name.opp.holds_array = 1;

			/*
			 * Then copy over temp->value's data.
			 * temp->value.opp.opio_u could contain char[], int or
			 * int []. If *(temp->value.opp.oprom_array) is '\0',
			 * this indicates int or int []. int is the norm, but
			 * to be safe we assume int [] and copy over
			 * OPROM_NODE_SIZE int elements.
			 */
			new->value.opp.oprom_size = temp->value.opp.oprom_size;

			if (*(temp->value.opp.oprom_array) == '\0') {
				for (i = 0; i < OPROM_NODE_SIZE; i++)
					new->value.opp.oprom_node[i] =
					    *(&temp->value.opp.oprom_node+i);

				new->value.opp.holds_array = 0;
			} else {
				if ((new->value.opp.oprom_array =
				    malloc(new->value.opp.oprom_size))
				    == NULL) {
					perror("malloc");
					exit(1);
				}

				/*
				 * temp->value.opp.oprom_array can contain one
				 * or more embedded NULLs. These trip-up the
				 * standard string copying functions, so we do
				 * the copy by hand. temp->value.opp.oprom_array
				 * will be NULL-terminated. oprom_size includes
				 * this terminating NULL.
				 */
				newp = new->value.opp.oprom_array;
				tempp = temp->value.opp.oprom_array;
				for (i = new->value.opp.oprom_size; i > 0; i--)
					*newp++ = *tempp++;

				new->value.opp.holds_array = 1;
			}

			new->size = temp->size;

			/* everything worked so link the property list */
			if (node->props == NULL)
				node->props = new;
			else if (prop != NULL)
				prop->next = new;
			prop = new;
			prop->next = NULL;
		}
	}
	free(temp);
}

int
promopen(int oflag)
{
	/*CONSTCOND*/
	while (1)  {
		if ((prom_fd = open(promdev, oflag)) < 0)  {
			if (errno == EAGAIN)   {
				(void) sleep(5);
				continue;
			}
			if (errno == ENXIO)
				return (-1);
			exit(_error(dgettext(TEXT_DOMAIN, "cannot open %s"),
				promdev));
		} else
			return (0);
	}
	/*NOTREACHED*/
}

void
promclose(void)
{
	if (close(prom_fd) < 0)
		exit(_error(dgettext(TEXT_DOMAIN, "close error on %s"),
			promdev));
}

/*
 * Read the value of the property from the PROM device tree
 */
void
getpropval(struct openpromio *opp)
{
	opp->oprom_size = MAXVALSIZE;

	if (ioctl(prom_fd, OPROMGETPROP, opp) < 0)
		exit(_error("OPROMGETPROP"));
}

int
next(int id)
{
	Oppbuf	oppbuf;
	register struct openpromio *opp = &(oppbuf.opp);
	/* LINTED */
	int *ip = (int *)(opp->oprom_array);

	(void) memset((void *) oppbuf.buf, 0, BUFSIZE);

	opp->oprom_size = MAXVALSIZE;
	*ip = id;
	if (ioctl(prom_fd, OPROMNEXT, opp) < 0)
		return (_error("OPROMNEXT"));
	/* LINTED */
	return (*(int *)opp->oprom_array);
}

int
child(int id)
{
	Oppbuf	oppbuf;
	register struct openpromio *opp = &(oppbuf.opp);
	/* LINTED */
	int *ip = (int *)(opp->oprom_array);

	(void) memset((void *) oppbuf.buf, 0, BUFSIZE);
	opp->oprom_size = MAXVALSIZE;
	*ip = id;
	if (ioctl(prom_fd, OPROMCHILD, opp) < 0)
		return (_error("OPROMCHILD"));
	/* LINTED */
	return (*(int *)opp->oprom_array);
}

/*
 * Check if the Prom node passed in contains a property called
 * "board#".
 */
int
has_board_num(Prom_node *node)
{
	Prop *prop = node->props;

	/*
	 * walk thru all properties in this PROM node and look for
	 * board# prop
	 */
	while (prop != NULL) {
		if (strcmp(prop->name.opp.oprom_array, "board#") == 0)
		    return (1);

		prop = prop->next;
	}

	return (0);
}	/* end of has_board_num() */

/*
 * Retrieve the value of the board number property from this Prom
 * node. It has the type of int.
 */
int
get_board_num(Prom_node *node)
{
	Prop *prop = node->props;

	/*
	 * walk thru all properties in this PROM node and look for
	 * board# prop
	 */
	while (prop != NULL) {
		if (strcmp(prop->name.opp.oprom_array, "board#") == 0)
			return (prop->value.opp.oprom_node[0]);

		prop = prop->next;
	}

	return (-1);
}	/* end of get_board_num() */

/*
 * Find the requested board struct in the system device tree.
 */
Board_node *
find_board(Sys_tree *root, int board)
{
	Board_node *bnode = root->bd_list;

	while ((bnode != NULL) && (board != bnode->board_num))
		bnode = bnode->next;

	return (bnode);
}	/* end of find_board() */

/*
 * Add a board to the system list in order. Initialize all pointer
 * fields to NULL.
 */
Board_node *
insert_board(Sys_tree *root, int board)
{
	Board_node *bnode;
	Board_node *temp = root->bd_list;

	if ((bnode = (Board_node *) malloc(sizeof (Board_node))) == NULL) {
		perror("malloc");
		exit(1);
	}
	bnode->nodes = NULL;
	bnode->next = NULL;
	bnode->board_num = board;

	if (temp == NULL)
		root->bd_list = bnode;
	else if (temp->board_num > board) {
		bnode->next = temp;
		root->bd_list = bnode;
	} else {
		while ((temp->next != NULL) && (board > temp->next->board_num))
			temp = temp->next;
		bnode->next = temp->next;
		temp->next = bnode;
	}
	root->board_cnt++;

	return (bnode);
}	/* end of insert_board() */

/*
 * This function searches through the properties of the node passed in
 * and returns a pointer to the value of the name property.
 */
char *
get_node_name(Prom_node *pnode)
{
	Prop *prop;

	if (pnode == NULL) {
		return (NULL);
	}

	prop = pnode->props;
	while (prop != NULL) {
		if (strcmp("name", prop->name.opp.oprom_array) == 0)
			return (prop->value.opp.oprom_array);
		prop = prop->next;
	}
	return (NULL);
}	/* end of get_node_name() */

/*
 * This function searches through the properties of the node passed in
 * and returns a pointer to the value of the name property.
 */
char *
get_node_type(Prom_node *pnode)
{
	Prop *prop;

	if (pnode == NULL) {
		return (NULL);
	}

	prop = pnode->props;
	while (prop != NULL) {
		if (strcmp("device_type", prop->name.opp.oprom_array) == 0)
			return (prop->value.opp.oprom_array);
		prop = prop->next;
	}
	return (NULL);
}	/* end of get_node_type() */

/*
 * Do a depth-first walk of a device tree and
 * return the first node with the name matching.
 */

Prom_node *
dev_find_node(Prom_node *root, char *name)
{
	Prom_node *node;

	node = dev_find_node_by_type(root, "name", name);

	return (node);
}

Prom_node *
dev_next_node(Prom_node *root, char *name)
{
	Prom_node *node;

	node = dev_next_node_by_type(root, "name", name);

	return (node);
}

/*
 * Search for and return a node of the required type. If no node is found,
 * then return NULL.
 */
Prom_node *
dev_find_type(Prom_node *root, char *type)
{
	Prom_node *node;

	node = dev_find_node_by_type(root, "device_type", type);

	return (node);  /* not found */
}

/*
 * Start from the current node and return the next node besides the
 * current one which has the requested type property.
 */
Prom_node *
dev_next_type(Prom_node *root, char *type)
{
	Prom_node *node;

	node = dev_next_node_by_type(root, "device_type", type);

	return (node);  /* not found */
}

/*
 * Search a device tree and return the first failed node that is found.
 * (has a 'status' property)
 */
Prom_node *
find_failed_node(Prom_node * root)
{
	Prom_node *pnode;

	if (root == NULL)
		return (NULL);

	if (node_failed(root)) {
		return (root);
	}

	/* search the child */
	if ((pnode = find_failed_node(root->child)) != NULL)
		return (pnode);

	/* search the siblings */
	if ((pnode = find_failed_node(root->sibling)) != NULL)
		return (pnode);

	return (NULL);
}	/* end of find_failed_node() */

/*
 * Start from the current node and return the next node besides
 * the current one which is failed. (has a 'status' property)
 */
Prom_node *
next_failed_node(Prom_node * root)
{
	Prom_node *pnode;
	Prom_node *parent;

	if (root == NULL)
		return (NULL);

	/* search the child */
	if ((pnode = find_failed_node(root->child)) != NULL) {
		return (pnode);
	}

	/* search the siblings */
	if ((pnode = find_failed_node(root->sibling)) != NULL) {
		return (pnode);
	}

	/* backtracking the search up through parents' siblings */
	parent = root->parent;
	while (parent != NULL) {
		if ((pnode = find_failed_node(parent->sibling)) != NULL)
			return (pnode);
		else
			parent = parent->parent;
	}

	return (NULL);
}	/* end of find_failed_node() */

/*
 * node_failed
 *
 * This function determines if the current Prom node is failed. This
 * is defined by having a status property containing the token 'fail'.
 */
int
node_failed(Prom_node *node)
{
	return (node_status(node, "fail"));
}

int
node_status(Prom_node *node, char *status)
{
	void *value;

	if (status == NULL)
		return (0);

	/* search the local node */
	if ((value = get_prop_val(find_prop(node, "status"))) != NULL) {
		if ((value != NULL) && strstr((char *)value, status))
			return (1);
	}
	return (0);
}

/*
 * Get a property's value. Must be void * since the property can
 * be any data type. Caller must know the *PROPER* way to use this
 * data.
 */
void *
get_prop_val(Prop *prop)
{
	if (prop == NULL)
		return (NULL);

	if (prop->value.opp.holds_array)
		return ((void *)(prop->value.opp.oprom_array));
	else
		return ((void *)(&prop->value.opp.oprom_node[0]));
}	/* end of get_prop_val() */

/*
 * Search a Prom node and retrieve the property with the correct
 * name.
 */
Prop *
find_prop(Prom_node *pnode, char *name)
{
	Prop *prop;

	if (pnode  == NULL) {
		return (NULL);
	}

	if (pnode->props == NULL) {
		(void) printf("%s", dgettext(TEXT_DOMAIN, "Prom node has "
			"no properties\n"));
		return (NULL);
	}

	prop = pnode->props;
	while ((prop != NULL) && (strcmp(prop->name.opp.oprom_array, name)))
		prop = prop->next;

	return (prop);
}

/*
 * This function adds a board node to the board structure where that
 * that node's physical component lives.
 */
void
add_node(Sys_tree *root, Prom_node *pnode)
{
	int board;
	Board_node *bnode;
	Prom_node *p;

	/* add this node to the Board list of the appropriate board */
	if ((board = get_board_num(pnode)) == -1) {
		/* board is 0 if not on Sunfire */
		board = 0;
	}

	/* find the node with the same board number */
	if ((bnode = find_board(root, board)) == NULL) {
		bnode = insert_board(root, board);
		bnode->board_type = UNKNOWN_BOARD;
	}

	/* now attach this prom node to the board list */
	/* Insert this node at the end of the list */
	pnode->sibling = NULL;
	if (bnode->nodes == NULL)
		bnode->nodes = pnode;
	else {
		p = bnode->nodes;
		while (p->sibling != NULL)
			p = p->sibling;
		p->sibling = pnode;
	}

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

	mask = 0x1F;
	while (pnode != NULL) {
		if ((get_id(pnode) & mask) == id)
			return (pnode);

		pnode = dev_next_node(pnode, name);
	}
	return (NULL);
}

Prom_node *
dev_find_node_by_type(Prom_node *root, char *type, char *property)
{
	Prom_node *node;
	char *type_prop;

	if (root == NULL || property == NULL)
		return (NULL);

	type_prop = (char *)get_prop_val(find_prop(root, type));

	if (type_prop != NULL) {
		if (strcmp(type_prop, property) == 0) {
			return (root);
		}
	}

	/* look at your children first */
	if ((node = dev_find_node_by_type(root->child, type,
	    property)) != NULL)
		return (node);

	/* now look at your siblings */
	if ((node = dev_find_node_by_type(root->sibling, type,
	    property)) != NULL)
		return (node);

	return (NULL);	/* not found */
}

Prom_node *
dev_next_node_by_type(Prom_node *root, char *type, char *property)
{
	Prom_node *node;

	if (root == NULL || property == NULL)
		return (NULL);

	/* look at your children first */
	if ((node = dev_find_node_by_type(root->child, type,
	    property)) != NULL)
		return (node);

	/* now look at your siblings */
	if ((node = dev_find_node_by_type(root->sibling, type,
	    property)) != NULL)
		return (node);

	/* now look at papa's siblings */
	if ((node = dev_find_node_by_type(root->parent->sibling,
	    type, property)) != NULL)
		return (node);

	return (NULL);  /* not found */
}

/*
 * Do a depth-first walk of a device tree and
 * return the first node with the matching compatible.
 */
Prom_node *
dev_find_node_by_compatible(Prom_node *root, char *compatible)
{
	Prom_node *node;
	Prop	*prop;
	char	*compatible_array;
	int	size, nbytes;

	if (root == NULL || compatible == NULL)
		return (NULL);

	if ((prop = find_prop(root, "compatible")) != NULL &&
	    (compatible_array = (char *)get_prop_val(prop)) != NULL) {
		/*
		 * The Prop structure returned by find_prop() is supposed
		 * to contain an indication of how big the value of the
		 * compatible property is.  Since it is an array of strings
		 * this is our only means of determining just how many
		 * strings might be in this property.  However, this size
		 * is often left as zero even though there is at least one
		 * string present.  When this is the case, all we can do
		 * is examine the first string in the compatible property.
		 */

		for (size = prop->size; size >= 0; size -= nbytes) {
			if (strcmp(compatible_array, compatible) == 0)
				return (root);		/* found a match */

			nbytes = strlen(compatible_array) + 1;
			compatible_array += nbytes;
		}
	}

	node = dev_find_node_by_compatible(root->child, compatible);
	if (node != NULL)
		return (node);

	/*
	 * Note the very deliberate use of tail recursion here.	 A good
	 * compiler (such as Sun's) will recognize this and generate code
	 * that does not allocate another stack frame.	Instead, it will
	 * overlay the existing stack frame with the new one, the only change
	 * having been to replace the original root with its sibling.
	 * This has the potential to create some confusion for anyone
	 * trying to debug this code from a core dump, since the stack
	 * trace will not reveal recursion on siblings, only on children.
	 */

	return (dev_find_node_by_compatible(root->sibling, compatible));
}

/*
 * Start from the current node and return the next node besides
 * the current one which has the requested compatible property.
 */
Prom_node *
dev_next_node_by_compatible(Prom_node *root, char *compatible)
{
	Prom_node *node;

	if (root == NULL || compatible == NULL)
		return (NULL);

	node = dev_find_node_by_compatible(root->child, compatible);
	if (node != NULL)
		return (node);

	/*
	 * More tail recursion.	 Even though it is a different function,
	 * this will overlay the current stack frame.  Caveat exterminator.
	 */

	node = dev_find_node_by_compatible(root->sibling, compatible);
	if (node != NULL)
		return (node);

	return (dev_find_node_by_compatible(root->parent->sibling, compatible));
}
