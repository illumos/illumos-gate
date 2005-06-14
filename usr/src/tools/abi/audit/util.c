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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "abi_audit.h"

#define	get_index(x)	(x % RELMAX)

int			Debug;
char			*program;

/* Internal functions */
static char *		bv_chunktos(ull_t, char *, int);
static liblist_t *	list_insert(liblist_t *, liblist_t *, int);
static rellist_t *	find_rel_node(int);
static tree_t		*rotate_left(tree_t *);
static tree_t		*rotate_right(tree_t *);
static tree_t		*right_balance(tree_t *, int *);
static tree_t		*left_balance(tree_t *, int *);
static tree_t		*tree_insert(tree_t *, tree_t *, int *, int);
static ull_t		stobv_chunk(char *);
static verlist_t *	find_verlist(liblist_t *, int);
static void		list_traverse(symbol_t *, FILE *);

/*
 * Creates and assigns symbol information to a tree node.
 * Insertion of this symbol node to the Sym_List tree will result in either
 * updating an existing node or creating a new node on the tree.
 */

int
add_symbol(symbol_t *sym, liblist_t *lib, category_t *cat, int rel_num)
{
	int	taller;
	tree_t	*tree_node;

	if ((tree_node = calloc(1, sizeof (tree_t))) == NULL) {
		(void) fprintf(stderr, "%s: add_symbol: calloc: treenode: %s\n",
		    program, strerror(errno));
		return (FAIL);
	}

	/* Assign tree elements */
	tree_node->tt_sym = sym;
	tree_node->tt_sym->st_lib = lib;
	tree_node->tt_sym->st_lib->lt_cat = cat;
	tree_node->tt_left = tree_node->tt_right = NULL;

	/* initialize taller variable */
	taller = FALSE;

	Sym_List = tree_insert(Sym_List, tree_node, &taller, rel_num);
	return (SUCCEED);
}

/*
 * Trim off the leading and trailing blanks or tabs for a char string
 */

char *
trimmer(char *str)
{
	char	*end;
	char	*start;

	if (str[0] == '\0')
		return (NULL);
	end = str + strlen(str) - 1;
	while (end != str) {
		if (isspace(*end))
			*(end --) = '\0';
		else
			break;
	}
	for (start = str; isspace(*start); start ++);
	(void) memcpy(str, start, strlen(start) + 1);
	return (str);
}

/*
 * To convert ascii string to bv_chunk
 */

static ull_t
stobv_chunk(char *str)
{
	ull_t	num;

	if (!str)
		return ((ull_t)0);
	else {
		num = strtoull(str, (char **)NULL, 2);
		return ((ull_t)num);
	}
}

/*
 * Wrapper to convert ascii string to a linked list of bv_chunk (bvlist_t)
 */

bvlist_t
*stobv(char *str, int rel)
{
	bvlist_t	*bv;
	bvlist_t	*bv_ptr;
	int		num_nodes;
	char		substr[RELMAX + 1];
	char		*str_ptr, *tmp_ptr;
	int		i;

	if ((bv = calloc(1, sizeof (bvlist_t))) == NULL) {
		(void) fprintf(stderr,
		    "%s: atobv: calloc: bv: %s\n",
		    program, strerror(errno));
		return (NULL);
	}
	bv_ptr = bv;
	str_ptr = str;
	num_nodes = find_num_nodes(rel);
	for (i = 0; i < num_nodes; i ++) {
		if (i == num_nodes - 1)
			break;
		(void) memset(substr, 0, RELMAX + 1);
		(void) strncpy(substr, str_ptr, RELMAX);
		bv_ptr->bt_bitvector = stobv_chunk(substr);
		tmp_ptr = str_ptr + RELMAX;
		if (tmp_ptr) {
			str_ptr = tmp_ptr;
		}
		if ((bv_ptr->bt_next = calloc(1, sizeof (bvlist_t))) == NULL) {
			(void) fprintf(stderr,
			    "%s: atobv: calloc: bv_ptr: %s\n",
			    program, strerror(errno));
			return (NULL);
		}
		bv_ptr = bv_ptr->bt_next;
	}
	(void) memset(substr, 0, RELMAX + 1);
	(void) strncpy(substr, str_ptr, RELMAX);
	/*
	 * Now, needs to pad the rest of the substr with zeros
	 * to form substr with a length of RELMAX.  In this way,
	 * the str to bv_chunk translation will be accurate.
	 */
	for (i = strlen(substr); i < RELMAX; i ++) {
		substr[i] = '0';
	}
	substr[i] = '\0';
	bv_ptr->bt_bitvector = stobv_chunk(substr);
	bv_ptr->bt_next = NULL;

	return (bv);
}

/*
 * Convert bv_chunk to character string
 */

static char *
bv_chunktos(ull_t num, char *string, int idx)
{
	int	i;
	int	size;

	size = idx;
	for (i = size - 1; i >= 0; i --, num >>= 1)
		string[i] = (01 & num) + '0';
	string[size] = '\0';

	return (string);
}

/*
 * Wrapper to convert a linked list of bv_chunk (bvlist_t) to character string
 */

char *
bvtos(bvlist_t *bv)
{
	char	bin_str[RELMAX];
	char	*string;
	char	*str;
	int	num_nodes;
	int	i;

	if ((string = calloc(1, Total_relcnt)) == NULL) {
		(void) fprintf(stderr,
			"%s: bvtos: calloc: %s\n",
			program, strerror(errno));
		return (NULL);
	}

	num_nodes = find_num_nodes(Total_relcnt);

	for (i = 0; i < num_nodes - 1; i ++) {
		str = bv_chunktos(bv->bt_bitvector, bin_str, RELMAX);
		string = strncat(string, str, strlen(str));
		if (bv->bt_next)
			bv = bv->bt_next;
	}
	str = bv_chunktos(bv->bt_bitvector, bin_str, RELMAX);
	str[Total_relcnt % RELMAX] = '\0';
	string = strncat(string, str, strlen(str));
	return (string);
}

/*
 * Construct the category bitvectors
 * based on the number of builds/releases abi_audit to check
 * against and the version name associated with the symbol
 * from the "pvs -dosl" output, classifies the symbol into
 * public, private, unexported and scoped.  We consider the
 * symbol as private if its version name contains "private"
 * string or "sunwabi_", otherwise the symbol is considered
 * to be public.
 */

int
build_cat_bits(bvlist_t *release, char *ver_str, category_t *cat)
{
	char		*cat_str;
	int		i;

	if ((cat_str = strdup(ver_str)) == NULL) {
		(void) fprintf(stderr,
		    "%s: build_cat_bits: strdup: cat_str: %s\n",
		    program, strerror(errno));
		return (FAIL);
	}

	for (i = 0; cat_str[i] != '\0'; i ++)
		cat_str[i] = tolower(cat_str[i]);

	if (!cat->ct_public)
		cat->ct_public = create_bv_list(Total_relcnt);
	if (!cat->ct_private)
		cat->ct_private = create_bv_list(Total_relcnt);
	if (!cat->ct_scoped)
		cat->ct_scoped = create_bv_list(Total_relcnt);
	if (!cat->ct_unexported)
		cat->ct_unexported = create_bv_list(Total_relcnt);
	if (!cat->ct_evolving)
		cat->ct_evolving = create_bv_list(Total_relcnt);
	if (!cat->ct_obsolete)
		cat->ct_obsolete = create_bv_list(Total_relcnt);
	if (!cat->ct_unclassified)
		cat->ct_unclassified = create_bv_list(Total_relcnt);

	if ((strstr(cat_str, CAT_PRIVATE) != NULL) ||
	    (strstr(cat_str, CAT_SUNWABI) != NULL)) {
		bv_assign(cat->ct_private, release);
	} else if (strstr(cat_str, CAT_LOCAL) != NULL) {
		bv_assign(cat->ct_scoped, release);
	} else if (strstr(cat_str, CAT_EVOLVING) != NULL) {
		bv_assign(cat->ct_evolving, release);
	} else if (strstr(cat_str, CAT_OBSOLETE) != NULL) {
		bv_assign(cat->ct_obsolete, release);
	} else {
		bv_assign(cat->ct_public, release);
	}
	free(cat_str);
	return (SUCCEED);
}

/*
 * Store the symbol name, its type (FUNCTION or OBJECT) and size
 * if the symbol is an OBJECT.
 * For example; _pagesize (4)
 */

void
build_sym_tag(char *name, symbol_t *sym)
{
	char	*token;

	if (strchr(name, (int)'(') != NULL) {
		token = strtok(name, (const char *)"(");
		sym->st_sym_name = strdup(token);
		if (!sym->st_sym_name) {
			(void) fprintf(stderr,
			    "%s: build_sym_tag: strdup: token: %s\n",
			    program, strerror(errno));
			return;
		}
		sym->st_sym_name = trimmer(sym->st_sym_name);
		sym->st_type = OBJECT;
		token = strtok(NULL, (const char *)")");
		sym->st_size = atoi(token);
	} else {
		sym->st_sym_name = strdup(name);
		if (!sym->st_sym_name) {
			(void) fprintf(stderr,
			    "%s: build_sym_tag: strdup: name: %s\n",
			    program, strerror(errno));
			return;
		}
		sym->st_sym_name = trimmer(sym->st_sym_name);
		sym->st_type = FUNCTION;
		sym->st_size = 0;
	}
}

/*
 * Store the library name associated with the release/build information,
 * and also the symbol version name and highest version name for that
 * library.
 */

int
build_lib_tag(bvlist_t *release, char *name, char *sym_ver,
		liblist_t *lib, int rel_num)
{
	if (add_verlist(lib, rel_num) == FAIL) {
		return (FAIL);
	}

	/*
	 * sym_ver and lib_ver start off at the same version.  They will
	 * get reassigned if necessary in assign_versions()
	 */
	assign_lib_ver(lib, sym_ver, rel_num);
	assign_sym_ver(lib, sym_ver, rel_num);
	if (get_lib_ver(lib, rel_num) == NULL) {
		(void) fprintf(stderr,
			"%s: build_lib_tag: strdup: lib_ver: %s\n",
			program, strerror(errno));
		return (FAIL);
	}

	lib->lt_lib_name = strdup(name);
	if (!lib->lt_lib_name) {
		(void) fprintf(stderr,
			"%s: build_lib_tag: strdup: lib_name: %s\n",
			program, strerror(errno));
		return (FAIL);
	}

	lib->lt_release = create_bv_list(Total_relcnt);
	lib->lt_trans_bits = create_bv_list(Total_relcnt);

	bv_assign(lib->lt_release, release);

	lib->lt_check_me |= TRUE;
	lib->lt_libc_migrate = FALSE;

	lib->lt_next = NULL;
	return (SUCCEED);
}

/*
 * It is used when a duplicate symbol name is found while trying to
 * add a new node onto the AVL tree.  If the linked list for that
 * particular tree node is not created, it will first create a new one,
 * and then add that new node to the list.  If there is an existing
 * linked list, it will try to match the new node's attributes.
 * If there is a match, the existing linked list node information will
 * be updated, otherwise, the new node will be added to the end of the
 * linked list.
 */

static liblist_t *
list_insert(liblist_t *p, liblist_t *node, int rel_num)
{
	int		found = FALSE;
	liblist_t	*loc;

	if (!p) {
		p = node;
	} else {
		loc = p;
		/*
		 * walk through the linked list of
		 * that symbol. If the library-symbol
		 * pair matches, update symbol's info
		 */
		while (loc && found == FALSE) {
			if (strcmp(loc->lt_lib_name, node->lt_lib_name) == 0) {
				found = TRUE;
				set_bv_or(loc->lt_release, node->lt_release);

				loc->lt_check_me |= node->lt_check_me;
				set_bv_or(loc->lt_cat->ct_public,
				    node->lt_cat->ct_public);
				set_bv_or(loc->lt_cat->ct_private,
				    node->lt_cat->ct_private);
				set_bv_or(loc->lt_cat->ct_scoped,
				    node->lt_cat->ct_scoped);
				set_bv_or(loc->lt_cat->ct_unexported,
				    node->lt_cat->ct_unexported);
				set_bv_or(loc->lt_cat->ct_obsolete,
				    node->lt_cat->ct_obsolete);
				assign_versions(loc, node, rel_num);
				/* free the memory allocated for node */
				free_bv_list(node->lt_release);
				free_bv_list(node->lt_cat->ct_public);
				free_bv_list(node->lt_cat->ct_private);
				free_bv_list(node->lt_cat->ct_scoped);
				free_bv_list(node->lt_cat->ct_unexported);
				free_bv_list(node->lt_cat->ct_obsolete);
				free(node->lt_lib_name);
				free(node->lt_cat);
				free(node);
				break;
			} else {
				if (loc->lt_next)
					loc = loc->lt_next;
				else
					break;
			}
		}
		if (found == FALSE) {
			loc->lt_next = node;
		}
	}
	return (p);
}

/*
 * Walk through the linked list, and write out the symbol information
 * onto a ABI database file.
 */

static void
list_traverse(symbol_t *node_ptr, FILE *fp)
{

	symbol_t	*p = node_ptr;
	liblist_t	*head = p->st_lib;

	if (!p)
		return;
	while (p->st_lib) {
		generate_db(p, fp);
		p->st_lib = p->st_lib->lt_next;
	}
	p->st_lib = head;
}

/*
 * Destroy a linked list of sequence_t structure
 */

void
sequence_list_destroy(sequence_t *listptr)
{
	sequence_t	*p;

	while (listptr) {
		p = listptr->s_next;
		free(listptr);
		listptr = p;
	}
}

/*
 * Tree balancing routine for single left rotation.
 */

static tree_t *
rotate_left(tree_t *p)
{
	tree_t	*temp = p;

	if (!p) {
		if (Debug)
			(void) fprintf(stderr,
				"%s: rotate_left: Tree is NULL\n", program);
	} else if (!p->tt_right) {
		if (Debug)
			(void) fprintf(stderr,
				"%s: rotate_left: Cannot rotate to left...\n",
				program);
	} else {
		temp = p->tt_right;
		p->tt_right = temp->tt_left;
		temp->tt_left = p;
	}
	return (temp);
}

/*
 * Tree balancing routine for single right rotation.
 */

static tree_t *
rotate_right(tree_t *p)
{
	tree_t	*temp = p;

	if (!p) {
		if (Debug)
			(void) fprintf(stderr,
				"%s: rotate_right: Tree is NULL\n",
				program);
	} else if (!p->tt_left) {
		if (Debug)
			(void) fprintf(stderr,
				"%s: rotate_right: Cannot rotate to right...\n",
				program);
	} else {
		temp = p->tt_left;
		p->tt_left = temp->tt_right;
		temp->tt_right = p;
	}
	return (temp);
}

/*
 * Right balance of AVL tree if right subtree is higher than
 * the left subtree.
 */

static tree_t *
right_balance(tree_t *p, int *taller)
{
	tree_t	*rs = p->tt_right;	/* right subtree of root */
	tree_t	*ls;			/* left subtree of right subtree */

	switch (rs->tt_bf) {
	case RH:
		p->tt_bf = rs->tt_bf = EH;
		/* single rotation left */
		p = rotate_left(p);
		*taller = FALSE;
		break;
	case EH:
		/* tree is already balanced */
		break;
	case LH:
		/* double rotation left */
		ls = rs->tt_left;
		switch (ls->tt_bf) {
		case RH:
			p->tt_bf = LH;
			rs->tt_bf = EH;
			break;
		case EH:
			p->tt_bf = rs->tt_bf = EH;
			break;
		case LH:
			p->tt_bf = EH;
			rs->tt_bf = RH;
		}
		ls->tt_bf = EH;
		p->tt_right = rotate_right(rs);
		p = rotate_left(p);
		*taller = FALSE;
	}
	return (p);
}

/*
 * Left balance of AVL tree if left subtree is higher
 * than the right subtree.
 */

static tree_t *
left_balance(tree_t *p, int *taller)
{
	tree_t	*ls = p->tt_left;	/* left subtree of root */
	tree_t	*rs;			/* right subtree of left subtree */

	switch (ls->tt_bf) {
	case LH:
		p->tt_bf = ls->tt_bf = EH;
		/* single rotation right */
		p = rotate_right(p);
		*taller = FALSE;
		break;
	case EH:
		/* tree is already balanced */
		break;
	case RH:
		/* double rotation right */
		rs = ls->tt_right;
		switch (rs->tt_bf) {
		case LH:
			p->tt_bf = RH;
			ls->tt_bf = EH;
			break;
		case EH:
			p->tt_bf = ls->tt_bf = EH;
			break;
		case RH:
			p->tt_bf = EH;
			ls->tt_bf = LH;
		}
		rs->tt_bf = EH;
		p->tt_left = rotate_left(ls);
		p = rotate_right(p);
		*taller = FALSE;
	}
	return (p);
}

/*
 * Inserts a new tree node into the AVL tree.  If a duplicate symbol
 * is found, inserts or updates its associated linked list.
 */

static tree_t *
tree_insert(tree_t *p, tree_t *new, int *taller, int rel_num)
{
	if (p == NULL) {
		p = new;
		p->tt_bf = EH;
		*taller = TRUE;
	} else {
		if (strcmp(new->tt_sym->st_sym_name,
		    p->tt_sym->st_sym_name) < 0) {
			p->tt_left =
			    tree_insert(p->tt_left, new, taller, rel_num);
			if (*taller)    /* Left subtree is taller */
				switch (p->tt_bf) {
				case LH:
					/* Node was left high */
					p = left_balance(p, taller);
					break;
				case EH:
					/* Node is now left high */
					p->tt_bf = LH;
					break;
				case RH:
					/* Node now has balanced height */
					p->tt_bf = EH;
					*taller = FALSE;
					break;
				}
		} else if (strcmp(new->tt_sym->st_sym_name,
		    p->tt_sym->st_sym_name) > 0) {
			p->tt_right =
			    tree_insert(p->tt_right, new, taller, rel_num);
			if (*taller)    /* Right subtree is taller */
				switch (p->tt_bf) {
				case LH:
					/* Node now has balanced height */
					p->tt_bf = EH;
					*taller = FALSE;
					break;
				case EH:
					/* Node is right high */
					p->tt_bf = RH;
					break;
				case RH:
					/* Node is right high */
					p = right_balance(p, taller);
					break;
				}
		} else {
			/*
			 * In this case, same symbol exists in
			 * different libraries
			 */
			p->tt_sym->st_lib =
			    list_insert(p->tt_sym->st_lib,
			    new->tt_sym->st_lib, rel_num);

			/*
			 * now, free the memory previously allocated
			 * in build_sym_tag()
			 */
			free(new->tt_sym->st_sym_name);
			free(new->tt_sym);
			free(new);
		}
	}
	return (p);
}

/*
 * It will do a inorder tree traversal to output the symbol information
 */

void
tree_traverse(tree_t *rootptr)
{
	if (rootptr) {
		tree_traverse(rootptr->tt_left);
		list_traverse(rootptr->tt_sym, Db);
		tree_traverse(rootptr->tt_right);
	}
}

/*
 * Reads in the library information for those need to be checked
 * and store them onto the simple linked list.
 */

list_t *
store_lib_info(list_t *p, char *lib_name)
{
	int		found = FALSE;
	list_t		*loc;

	if (!p) {
		if ((p = calloc(1, sizeof (list_t))) == NULL) {
			(void) fprintf(stderr,
				"%s: store_lib_info: calloc: %s\n",
				program, strerror(errno));
			return (NULL);
		}
		p->lt_name = strdup(lib_name);
		if (!p->lt_name) {
			(void) fprintf(stderr,
			    "%s: store_lib_info: strdup: p->lt_name: %s\n",
			program, strerror(errno));
			return (NULL);
		}
		p->lt_next = NULL;
	} else {
		loc = p;
		while (loc && found == FALSE) {
			if (strcmp(loc->lt_name, lib_name) == 0) {
				found = TRUE;
			} else {
				if (loc->lt_next)
					loc = loc->lt_next;
				else
					break;
			}
		}
		if (found == FALSE) {
			loc->lt_next = calloc(1, sizeof (list_t));
			if (!loc->lt_next) {
				(void) fprintf(stderr,
				    "%s: store_lib_info: calloc: %s\n",
				    program, strerror(errno));
				return (NULL);
			}
			loc = loc->lt_next;
			loc->lt_name = strdup(lib_name);
			if (!loc->lt_name) {
				(void) fprintf(stderr,
				    "%s: store_lib_info: strdup: "
				    "loc->lt_name: %s\n",
				    program, strerror(errno));
				return (NULL);
			}
			loc->lt_next = NULL;
		}
	}
	return (p);
}

/*
 * Checks if the library name is on the linked list, returns TRUE.
 * otherwise, returns FALSE.
 */

int
check_lib_info(list_t *p, char *lib_name)
{
	list_t	*loc = p;

	while (loc) {
		if (strcmp(loc->lt_name, lib_name) == 0)
			return (TRUE);
		loc = loc->lt_next;
	}
	return (FALSE);
}

/*
 * To find out the number of items on the linked list if there are more than
 * 64 releases to keep track.
 */

int
find_num_nodes(int index)
{
	if ((index % RELMAX) != 0)
		return ((index / RELMAX) + 1);
	else
		return (index / RELMAX);
}

/*
 * To perform AND operation on two linked lists of bv_chunk
 * (bvlist_t).  If the result of AND operation is != 0 return TRUE
 * else FALSE.
 */

int
bv_and(bvlist_t *bv1, bvlist_t *bv2)
{
	bvlist_t	*tmp_bv1 = bv1;
	bvlist_t	*tmp_bv2 = bv2;

	while (tmp_bv1) {
		if ((tmp_bv1->bt_bitvector & tmp_bv2->bt_bitvector) != 0)
			return (TRUE);
		tmp_bv1 = tmp_bv1->bt_next;
		tmp_bv2 = tmp_bv2->bt_next;
	}
	return (FALSE);
}

/*
 * To perform OR operation on two linked lists of bv_chunk (bvlist_t).
 */

void
set_bv_or(bvlist_t *bv1, bvlist_t *bv2)
{
	bvlist_t	*tmp_bv1 = bv1;
	bvlist_t	*tmp_bv2 = bv2;

	while (tmp_bv1) {
		tmp_bv1->bt_bitvector |= tmp_bv2->bt_bitvector;
		tmp_bv1 = tmp_bv1->bt_next;
		tmp_bv2 = tmp_bv2->bt_next;
	}
}

/*
 * To perform left SHIFT operation on a linked list of ull_t (bvlist_t)
 */

bvlist_t
*bv_bitmask_lshift(bvlist_t *bv)
{
	bvlist_t	*bv_ptr = bv;
	bvlist_t	*bv_before = NULL;
	int		num_nodes;
	int		i;

	num_nodes = find_num_nodes(Total_relcnt);
	for (i = 0; i < num_nodes; i ++) {
		if (bv_ptr->bt_bitvector == 0) {
			bv_before = bv_ptr;
			if (bv_ptr->bt_next)
				bv_ptr = bv_ptr->bt_next;
		} else
			break;
	}
	bv_ptr->bt_bitvector = bv_ptr->bt_bitvector << 1;
	if ((bv_ptr->bt_bitvector == 0) && (bv_before != NULL)) {
		bv_before->bt_bitvector = 1;
	}
	return (bv);
}

/*
 * To perform right SHIFT operation on a linked list of ull_t (bvlist_t)
 */

bvlist_t
*bv_bitmask_rshift(bvlist_t *bv)
{
	bvlist_t	*bv_ptr = bv;
	int		num_nodes;
	int		i;

	num_nodes = find_num_nodes(Total_relcnt);

	for (i = 0; i < num_nodes; i ++) {
		if (bv_ptr->bt_bitvector == 0) {
			if (bv_ptr->bt_next)
				bv_ptr = bv_ptr->bt_next;
		} else
			break;
	}
	bv_ptr->bt_bitvector = bv_ptr->bt_bitvector >> 1;
	if ((bv_ptr->bt_bitvector == 0) && (bv_ptr->bt_next != NULL)) {
		bv_ptr->bt_next->bt_bitvector = 1;
		bv_ptr->bt_next->bt_bitvector =
		    bv_ptr->bt_next->bt_bitvector << (RELMAX - 1);
	}
	return (bv);
}

/*
 * To perform bitvector comparison on two linked list of ull_t (bvlist_t)
 * and return TRUE or FALSE appropriately
 */

int
bv_compare(bvlist_t *bv1, bvlist_t *bv2)
{
	bvlist_t	*tmp_bv1 = bv1;
	bvlist_t	*tmp_bv2 = bv2;

	while (tmp_bv1) {
		if (tmp_bv1->bt_bitvector != tmp_bv2->bt_bitvector) {
			return (FALSE);
		}
		tmp_bv1 = tmp_bv1->bt_next;
		tmp_bv2 = tmp_bv2->bt_next;
	}
	return (TRUE);
}

/*
 * To check if all the values of a linked list of ull_t (bvlist_t) are
 * zero and return TRUE or FALSE appropriately
 */

int
bv_all_zero(bvlist_t *bv)
{
	bvlist_t	*tmp_bv = bv;

	while (tmp_bv) {
		if (tmp_bv->bt_bitvector != 0)
			return (FALSE);
		tmp_bv = tmp_bv->bt_next;
	}
	return (TRUE);
}

/*
 * To check if linked list A of ull_t is greater or equal to linked list B
 * of ullt_t.
 * i.e., list A >= list B
 */

int
bv_earlier_than(bvlist_t *bv1, bvlist_t *bv2)
{
	bvlist_t	*tmp_bv1 = bv1;
	bvlist_t	*tmp_bv2 = bv2;
	int		i, num_nodes;

	num_nodes = find_num_nodes(Total_relcnt);
	for (i = 0; i < num_nodes; i ++) {
		if (tmp_bv1->bt_bitvector > tmp_bv2->bt_bitvector) {
			return (TRUE);
		} else if (tmp_bv1->bt_bitvector == tmp_bv2->bt_bitvector) {
				if (tmp_bv2->bt_bitvector != 0) {
						return (TRUE);
				} else {
					tmp_bv1 = tmp_bv1->bt_next;
					tmp_bv2 = tmp_bv1->bt_next;
				}
		} else {
			return (FALSE);
		}
	}
	return (FALSE);
}

/*
 * To copy all the values of linked list B to linked list A
 * i.e., list A = list B
 */

void
bv_assign(bvlist_t *bv1, bvlist_t *bv2)
{
	bvlist_t	*tmp_bv1 = bv1;
	bvlist_t	*tmp_bv2 = bv2;

	while (tmp_bv1) {
		tmp_bv1->bt_bitvector = tmp_bv2->bt_bitvector;
		tmp_bv1 = tmp_bv1->bt_next;
		tmp_bv2 = tmp_bv2->bt_next;
	}
}

/*
 * Given an index, to return an appropriate node referencing the index
 */

static verlist_t *
find_verlist(liblist_t *lib, int index)
{
	verlist_t	*tmp_verlist = lib->lt_version;
	int		num_nodes;
	int		i;

	num_nodes = find_num_nodes(index);

	for (i = 0; i < num_nodes; i ++) {
		if (index >= ((i + 1) * RELMAX)) {
			if (tmp_verlist->vlt_next)
				tmp_verlist = tmp_verlist->vlt_next;
			else
				break;
		} else
			break;
	}
	return (tmp_verlist);
}

/*
 * Given an index and library name, assign the library name to the appropriate
 * position in liblist_t->verlist_t->vlt_rel_ver[position].vt_lib_ver
 */

void
assign_lib_ver(liblist_t *lib, char *lib_ver_name, int index)
{
	verlist_t	*tmp_verlist;

	tmp_verlist = find_verlist(lib, index);
	if (lib_ver_name) {
		tmp_verlist->vlt_rel_ver[get_index(index)].vt_lib_ver =
		    strdup(lib_ver_name);
		if (!tmp_verlist->vlt_rel_ver[get_index(index)].vt_lib_ver) {
			(void) fprintf(stderr,
			    "%s: assign_lib_ver: strdup: lib_ver_name: %s\n",
			    program, strerror(errno));
			tmp_verlist->vlt_rel_ver[get_index(index)].vt_lib_ver =
			    NULL;
		}
	} else
		tmp_verlist->vlt_rel_ver[get_index(index)].vt_lib_ver =
		    NULL;
}

/*
 * Given an index and symbol name, assign the symbol name to the appropriate
 * position in liblist_t->verlist_t->vlt_rel_ver[position].vt_sym_ver
 */

void
assign_sym_ver(liblist_t *lib, char *sym_ver_name, int index)
{
	verlist_t	*tmp_verlist;

	tmp_verlist = find_verlist(lib, index);
	if (sym_ver_name) {
		tmp_verlist->vlt_rel_ver[get_index(index)].vt_sym_ver =
		    strdup(sym_ver_name);
		if (!tmp_verlist->vlt_rel_ver[get_index(index)].vt_sym_ver) {
			(void) fprintf(stderr,
			    "%s: assign_sym_ver: strdup: sym_ver_name: %s\n",
			    program, strerror(errno));
			tmp_verlist->vlt_rel_ver[get_index(index)].vt_sym_ver =
			    NULL;
		}
	} else
		tmp_verlist->vlt_rel_ver[get_index(index)].vt_sym_ver =
		    NULL;
}

/*
 * Given an index and a liblist_t, return the appropriate library name
 * liblist_t->verlist_t->vlt_rel_ver[position].vt_lib_ver
 */

char *
get_lib_ver(liblist_t *lib, int index)
{
	verlist_t	*tmp_verlist;

	tmp_verlist = find_verlist(lib, index);
	return (tmp_verlist->vlt_rel_ver[get_index(index)].vt_lib_ver);
}

/*
 * Given an index and a liblist_t, return the appropriate symbol name
 * liblist_t->verlist_t->vlt_rel_ver[position].vt_sym_ver
 */

char *
get_sym_ver(liblist_t *lib, int index)
{
	verlist_t	*tmp_verlist;

	tmp_verlist = find_verlist(lib, index);
	return (tmp_verlist->vlt_rel_ver[get_index(index)].vt_sym_ver);
}

/*
 * Create if not exist or add new node onto a linked list of verlist_t.
 */

int
add_verlist(liblist_t *lib, int cnt)
{
	verlist_t	*end_verlist;
	verlist_t	*new_verlist;
	int		i, j;
	int		nodes_needed = 0;
	int		num_nodes = 0;

	/* count number of nodes currently present on linked list of versions */
	end_verlist = lib->lt_version;
	while (end_verlist != NULL) {
		num_nodes ++;
		if (end_verlist->vlt_next != NULL)
			end_verlist = end_verlist->vlt_next;
		else
			break;
	}

	nodes_needed = find_num_nodes(cnt) - num_nodes;

	for (i = 0; i < nodes_needed; i ++) {
		if ((new_verlist = calloc(1, sizeof (verlist_t))) == NULL) {
			(void) fprintf(stderr,
			    "%s: add_verlist: calloc: new_verlist: %s\n",
			    program, strerror(errno));
			return (FAIL);
		}

		for (j = 0; j < RELMAX; j ++) {
			new_verlist->vlt_rel_ver[j].vt_lib_ver = NULL;
			new_verlist->vlt_rel_ver[j].vt_sym_ver = NULL;
		}
		/* add new_verlist to end of verlist */
		if (!lib->lt_version) {
			lib->lt_version = new_verlist;
			end_verlist = new_verlist;
		} else {
			end_verlist->vlt_next = new_verlist;
			end_verlist = end_verlist->vlt_next;
		}
	}
	return (SUCCEED);
}

/*
 * Return the appropriate node of Rel (the linked list of rellist_t)
 * referencing the index
 */

static rellist_t *
find_rel_node(int index)
{
	rellist_t	*tmp_rellist;
	int		num_nodes;
	int		i;

	num_nodes = find_num_nodes(index);
	tmp_rellist = Rel;

	for (i = 0; i < num_nodes; i ++) {
		if (index >= ((i + 1) * RELMAX)) {
			if (tmp_rellist->rt_next)
				tmp_rellist = tmp_rellist->rt_next;
			else
				break;
		} else
			break;
	}
	return (tmp_rellist);
}

/*
 * Given an index, to return the appropriate linked list of ull_t (bvlist_t)
 * which contains the release information referencing the index.
 */

bvlist_t *
get_rel_bitmask(int index)
{
	rellist_t	*tmp_rellist;
	bvlist_t	*node, *node_ptr;
	int		i;
	int		num_nodes;

	num_nodes = find_num_nodes(index);
	tmp_rellist = find_rel_node(index);
	node = create_bv_list(Total_relcnt);
	node_ptr = node;
	for (i = 0; i < num_nodes; i ++) {
		if (index >= ((i + 1) * RELMAX)) {
			if (node_ptr->bt_next)
				node_ptr = node_ptr->bt_next;
		} else
			break;
	}
	node_ptr->bt_bitvector =
	    tmp_rellist->rt_release[get_index(index)].rt_rel_bitmask;
	return (node);
}

/*
 * Given an index, to return the name of a release
 */

char *
get_rel_name(int index)
{
	rellist_t	*tmp_rellist;

	tmp_rellist = find_rel_node(index);
	if (tmp_rellist)
		return (tmp_rellist->rt_release[get_index(index)].rt_rel_name);
	else
		return (NULL);
}

/*
 * To assign the name of a release associated with a proper index
 * to rellist_t->rt_release[proper index].rt_rel_name
 */

void
assign_rel_name(char *rel_name, int index)
{
	rellist_t	*tmp_rellist;

	tmp_rellist = find_rel_node(index);
	if (rel_name) {
		tmp_rellist->rt_release[get_index(index)].rt_rel_name =
		    strdup(rel_name);
		if (!tmp_rellist->rt_release[get_index(index)].rt_rel_name) {
			(void) fprintf(stderr,
			    "%s: assign_rel_name: strdup: rt_rel_name: %s\n",
			    program, strerror(errno));
			tmp_rellist->rt_release[get_index(index)].rt_rel_name =
			    NULL;
		}
	}
}

/*
 * Create if not exist or add new node onto a linked list of rellist_t.
 */

int
add_rellist(int cnt)
{
	rellist_t	*end_rellist;
	rellist_t	*new_rellist;
	int		i;
	int		nodes_needed = 0;
	int		num_nodes = 0;

	/* count number of nodes currently present on linked list of versions */
	end_rellist = Rel;
	while (end_rellist != NULL) {
		num_nodes ++;
		if (end_rellist->rt_next != NULL)
			end_rellist = end_rellist->rt_next;
		else
			break;
	}
	nodes_needed = find_num_nodes(cnt) - num_nodes;

	for (i = 0; i < nodes_needed; i ++) {
		if ((new_rellist = calloc(1, sizeof (rellist_t))) == NULL) {
			(void) fprintf(stderr,
			    "%s: add_rellist: calloc: new_rellist: %s\n",
			    program, strerror(errno));
			return (FAIL);
		}

		/* add new_rellist to end of Rel */
		if (!Rel) {
			Rel = new_rellist;
			end_rellist = new_rellist;
		} else {
			end_rellist->rt_next = new_rellist;
			end_rellist = end_rellist->rt_next;
		}
	}
	return (SUCCEED);
}

/*
 * To create a linked list of ull_t (bvlist_t) and initialize each ull_t
 * value to zero
 */

bvlist_t *
create_bv_list(int cnt)
{
	bvlist_t	*list;
	bvlist_t	*tmp;
	int		num_nodes;
	int		i;

	num_nodes = find_num_nodes(cnt);

	if ((list = calloc(1, sizeof (bvlist_t))) == NULL) {
		(void) fprintf(stderr,
			    "%s: create_bv_list: calloc: list: %s\n",
			    program, strerror(errno));
		return (NULL);
	}
	tmp = list;
	for (i = 0; i < num_nodes; i ++) {
		if (i == num_nodes - 1)
			break;
		tmp->bt_next = calloc(1, sizeof (bvlist_t));
		if (!tmp->bt_next) {
			(void) fprintf(stderr,
				    "%s: create_bv_list: calloc: tmp: %s\n",
				    program, strerror(errno));
			return (NULL);
		}
		tmp = tmp->bt_next;
		tmp->bt_bitvector = 0;
	}
	tmp->bt_next = NULL;
	return (list);
}

/*
 * To destroy the linked list of ull_t (bvlist_t)
 */

void
free_bv_list(bvlist_t *bv)
{
	bvlist_t	*p;

	while (bv) {
		p = bv->bt_next;
		free(bv);
		bv = p;
	}
}
