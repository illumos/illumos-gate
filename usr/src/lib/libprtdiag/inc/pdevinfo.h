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

#ifndef	_PDEVINFO_H
#define	_PDEVINFO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* structures necessary to hold Openprom data */

/*
 * 128 is the size of the largest (currently) property name
 * 4096 - MAXPROPSIZE - sizeof (int) is the size of the largest
 * (currently) property value that is allowed.
 * the sizeof (u_int) is from struct openpromio
 */
#define	MAXPROPSIZE	128
#define	MAXVALSIZE	(4096 - MAXPROPSIZE - sizeof (uint_t))
#define	BUFSIZE		(MAXPROPSIZE + MAXVALSIZE + sizeof (uint_t))
typedef union {
	char buf[BUFSIZE];
	struct openpromio opp;
	void	*val_ptr;
} Oppbuf;

/*
 * The prop structures associated with a Prom_node were formerly statically
 * sized - via the buf element of the Oppbuf union. This was highly memory
 * inefficient, so dynamic sizing capabilities have been introduced.
 *
 * This has been achieved via the creation of dynopenpromio and dynOppbuf
 * structs, and altering the prop structure. The prop structure's name and value
 * elements are now typed as dynOppbuf instead of Oppbuf.
 *
 * For legacy purposes, static_prop has been created. It is essentially the same
 * as the former prop structure, but the *next element now points to a
 * static_prop structure instead of a prop structure.
 */
typedef struct static_prop StaticProp;
struct static_prop {
	StaticProp *next;
	Oppbuf name;
	Oppbuf value;
	int size;	/* size of data in bytes */
};

/*
 * dynopenpromio structs are similar to openpromio structs, but with 2 major
 * differences. The first is that the opio_u.b element is char * instead of
 * char [], which allows for dynamic sizing.
 *
 * The second regards opio_u.i, which was an int, but is now int []. In almost
 * all cases, only opio_u.i (opio_u.i[0]) will be referenced. However, certain
 * platforms rely on the fact that Prop structures formerly contained Oppbuf
 * unions, the buf element of which was statically sized at 4k. In theory, this
 * enabled those platforms to validly reference any part of the union up to 4k
 * from the start. In reality, no element greater than opio_u.i[4] is currently
 * referenced, hence OPROM_NODE_SIZE (named because opio_u.i is usually
 * referenced as oprom_node) being set to 5.
 *
 * A minor difference is that the holds_array element has been added, which
 * affords an easy way to determine whether opio_u contains char * or int.
 */
#define	OPROM_NODE_SIZE		5
struct dynopenpromio {
	uint_t oprom_size;
	union {
		char *b;
		int i[OPROM_NODE_SIZE];
	} opio_u;
	uint_t holds_array;
};

/*
 * dynOppbuf structs are a dynamic alternative to Oppbuf unions. The statically
 * sized Oppbuf.buf element has been removed, and the opp element common to both
 * is of type struct dynopenpromio instead of struct openpromio. This allows us
 * to take advantage of dynopenpromio's dynamic sizing capabilities.
 */
typedef struct dynoppbuf dynOppbuf;
struct dynoppbuf {
	struct dynopenpromio opp;
	char *val_ptr;
};

typedef struct prop Prop;
struct prop {
	Prop *next;
	dynOppbuf name;
	dynOppbuf value;
	int size;	/* size of data in bytes */
};

typedef struct prom_node Prom_node;
struct prom_node {
	Prom_node *parent;	/* points to parent node */
	Prom_node *child;	/* points to child PROM node */
	Prom_node *sibling;	/* point to next sibling */
	Prop *props;		/* points to list of properties */
};

/*
 * Defines for board types.
 */

typedef struct board_node Board_node;
struct board_node {
	int node_id;
	int board_num;
	int board_type;
	Prom_node *nodes;
	Board_node *next;  /* link for list */
};

typedef struct system_tree Sys_tree;
struct system_tree {
	Prom_node *sys_mem;	/* System memory node */
	Prom_node *boards;	/* boards node holds bif info if present */
	Board_node *bd_list;	/* node holds list of boards */
	int board_cnt;		/* number of boards in the system */
};

int do_prominfo(int, char *, int, int);
int is_openprom(void);
void promclose(void);
int promopen(int);
extern char *badarchmsg;
int _error(char *fmt, ...);

/* Functions for building the user copy of the device tree. */
Board_node *find_board(Sys_tree *, int);
Board_node *insert_board(Sys_tree *, int);

/* functions for searching for Prom nodes */
char *get_node_name(Prom_node *);
char *get_node_type(Prom_node *);
Prom_node *dev_find_node(Prom_node *, char *);
Prom_node *dev_next_node(Prom_node *, char *);
Prom_node *dev_find_node_by_type(Prom_node *root, char *type, char *property);
Prom_node *dev_next_node_by_type(Prom_node *root, char *type, char *property);
Prom_node *dev_find_type(Prom_node *, char *);
Prom_node *dev_next_type(Prom_node *, char *);
Prom_node *sys_find_node(Sys_tree *, int, char *);
Prom_node *find_failed_node(Prom_node *);
Prom_node *next_failed_node(Prom_node *);
Prom_node *dev_find_node_by_compatible(Prom_node *root, char *compat);
Prom_node *dev_next_node_by_compatible(Prom_node *root, char *compat);
int node_failed(Prom_node *);
int node_status(Prom_node *node, char *status);
void dump_node(Prom_node *);
int next(int);
int has_board_num(Prom_node *);
int get_board_num(Prom_node *);
int child(int);

/* functions for searching for properties, extracting data from them */
void *get_prop_val(Prop *);
void getpropval(struct openpromio *);
Prop *find_prop(Prom_node *, char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PDEVINFO_H */
