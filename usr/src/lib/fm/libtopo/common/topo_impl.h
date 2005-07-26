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
 *
 */

#ifndef	_TOPO_IMPL_H
#define	_TOPO_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libnvpair.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct tnode;

struct tprop {
	const char *p_name;
	const char *p_val;
	struct tprop *p_next;
};

struct tnode_hashent {
	struct tnode *e_node;
	struct tnode_hashent *e_next;
};

struct tnode_hash {
	struct tnode_hashent **tn_hash;	/* hash bucket array */
	uint_t tn_hashlen;		/* size of hash bucket array */
	uint_t tn_nelems;		/* number of nodes in the hash */
};

struct tprop_hash {
	struct tprop **tp_hash;		/* hash bucket array */
	uint_t tp_hashlen;		/* size of hash bucket array */
	uint_t tp_nelems;		/* number of nodes in the hash */
};

struct tenum_alias {
	struct tenum_alias *tea_next;
	const char *tea_type;
	char *tea_share;
};

struct t_extend {
	struct tnode_hash *te_index;
	struct tenum_alias *te_aliases;
};

struct tnode {
	const char *name;
	enum { TOPO_ROOT = -2, TOPO_LIMBO = -1, TOPO_RANGE, TOPO_INST } state;
	union {
		struct {
			int min;
			int max;
		} range;	/* TOPO_RANGE only */
		int inst;	/* TOPO_INST only */
	} u;
	struct tnode_list {
		int visited;
		struct tnode *tnode;
		struct tnode_list *next;
	} *children;
	struct tprop_hash *props;
	struct tnode *parent;
	struct tnode *root;	/* quick access to root node for indexes */
	/* extended info */
	void *extend;
};

struct tnode *topo_set_instance_range(struct tnode *node, int min, int max);
struct tnode *topo_create(struct tnode *parent, const char *nodename);

struct tnode *topo_parse(struct tnode *appendto, const char *filename);
void topo_enum(struct tnode *root);

struct tnode_list *tnode_del_child(struct tnode *node, struct tnode *child);
struct tnode *tnode_dup(struct tnode *src);
struct tnode *tnode_add_child(struct tnode *node, struct tnode *child);
void tnode_destroy(struct tnode *node);
void tnode_print(struct tnode *node, void *ignore);
uint_t tnode_depth(struct tnode *node);

/* This creates a topo tree */
struct tnode *topo_root(void);

/* This returns the root of an EXISTING topo tree */
struct tnode *topo_getroot(struct tnode *);

void topo_mem_init(void);
void topo_mem_fini(void);
void topo_indent(void);

void topo_paths_init(int, const char **);
void topo_paths_fini(void);

void topo_driver_fini(void);

/* private topo_walk() categories */
#define	TOPO_REVISIT_SELF	4
#define	TOPO_DESTRUCTIVE_WALK	8

ulong_t topo_strhash(const char *);

struct tprop_hash *tprop_hash_create(void);
struct tprop *tprop_hash_lookup_next(struct tprop_hash *, const char *,
    struct tprop *);
struct tprop *tprop_hash_lookup(struct tprop_hash *, const char *);
struct tprop *tprop_create(const char *name, const char *val);
void tprop_hash_insert(struct tprop_hash *, const char *, struct tprop *);
void tprop_hash_destroy(struct tprop_hash *);
void tprop_destroy(struct tprop *);

void tprop_index(struct tnode *node, const char *propname);

struct tnode_hash *tnode_hash_create(void);
void tnode_hash_destroy(struct tnode_hash *);

void tealias_add(struct tnode *, char *);
const char *tealias_find(struct tnode *);

/* Common usage between hc_path and hc_fmri routines */
#define	MAXINSTLEN	256

void *topo_zalloc(size_t bytes);
char *topo_strdup(const char *str);
void topo_free(void *ptr);

FILE *topo_open(const char *);
void topo_close(FILE *);
void *topo_dlopen(const char *);
void topo_dlclose(void *);

/* parsing utilities */
char *topo_whiteskip(char *);
char *topo_component_from_path(char *, char **, char **);
int topo_inst_from_str(char *, int *, int *, int *);

/* private TOPO_OUT categories */
#define	TOPO_INFO	0x4
#define	TOPO_HASH	0x8
#define	TOPO_BUFONLY	0x10	/* don't call Outmethod, even if one exists */

extern void (*Outmethod)(const char *);
extern unsigned int Topo_out_mask;

extern nv_alloc_t Topo_nv_alloc_hdl;

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_IMPL_H */
