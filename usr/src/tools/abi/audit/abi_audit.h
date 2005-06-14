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

#ifndef	_ABI_AUDIT_H
#define	_ABI_AUDIT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * include headers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <libgen.h>
#include <unistd.h>
#include <time.h>
#include <sys/varargs.h>
#include <errno.h>

/*
 * global variable declarations
 */

#define	TRUE	1
#define	FALSE	0
#define	SUCCEED	0
#define	FAIL	-1

#define	CAT_PRIVATE  "private"
#define	CAT_SUNWABI  "sunwabi_"
#define	CAT_LOCAL    "_local_"
#define	CAT_EVOLVING "sunwevolving"
#define	CAT_OBSOLETE "sunwobsolete"

/*
 * RELMAX is set to be the max. number of releases captured at a single
 * node on a linked list of bitvectors
 */

#define	RELMAX	(8*(sizeof (uint64_t)))

/*
 * On a 32-bit machine, the ull_t is 64 bits long, and on a 64-bit machine
 * ull_t is 128 bits long.
 */

typedef uint64_t	ull_t;

typedef struct bvlist_tag {
	ull_t			bt_bitvector;
	struct bvlist_tag	*bt_next;
} bvlist_t;

/*
 * struct of a simple linked list of library names to be checked
 */

typedef struct list_tag {
	char			*lt_name;
	struct	list_tag	*lt_next;
} list_t;

/*
 * data structures to capture symbol information
 */

typedef struct release_tag {
	char		*rt_rel_name;	  /* release or build name */
	ull_t		rt_rel_bitmask;  /* bitmask for a particular release */
} release_t;

typedef struct rellist_tag {
	release_t		rt_release[RELMAX];
	struct rellist_tag	*rt_next;
} rellist_t;

typedef enum {FUNCTION, OBJECT} SymbolType_t;

/*
 * The categories are chosen as the ull_t type.  Each bit in an ull_t will
 * correlate with a release.
 * 	- a "0" bit indicates the symbol did not exist
 * 	- a "1" bit indicates the Symbol exists and belongs to the
 *	  corresponding category
 */
typedef struct category_tag {
	bvlist_t	*ct_evolving;		/* SUNWevolving */
	bvlist_t	*ct_obsolete;		/* SUNWobsolete */
	bvlist_t	*ct_public;		/* SUNW_m.n */
	bvlist_t	*ct_private;		/* SUNWprivate */
	bvlist_t	*ct_scoped;		/* in REDUCED file */
	bvlist_t	*ct_unclassified;
	bvlist_t	*ct_unexported;		/* sym disappear */
} category_t;

typedef struct version_tag {
	char			*vt_lib_ver;	/* highest version of pvs -d */
	char			*vt_sym_ver;	/* base version of pvs -dovs */
} version_t;

typedef struct verlist_tag {
	version_t		vlt_rel_ver[RELMAX];
	struct verlist_tag	*vlt_next;
} verlist_t;

typedef enum {
	SCENARIO_NONE,
	SCENARIO_01,    /* new public symbol introduced */
	SCENARIO_02,    /* public symbol in all builds */
	SCENARIO_03,    /* previous public symbol becomes private */
	SCENARIO_04,    /* previous public symbol is now unexported */
	SCENARIO_05,    /* new private symbol introduced */
	SCENARIO_06,    /* previous private symbol becomes public */
	SCENARIO_07,    /* private symbol in all builds */
	SCENARIO_08,    /* previous private symbol is now unexported */
	SCENARIO_09,    /* previously unexported symbol is now public */
	SCENARIO_10,    /* previously unexported symbol is now private */
	SCENARIO_11,    /* previously unexported symbol stays as it was */
	SCENARIO_12,    /* >1 mixed sequences of public & private symbol */
	SCENARIO_13,    /* >1 mixed sequences of public & unexported symbol */
	SCENARIO_14,    /* >1 mixed sequences of private & unexported symbol */
	SCENARIO_15,    /* =2 mixed public, private & unexported symbol */
	SCENARIO_16,    /* =2 mixed public, private & unexported symbol */
	SCENARIO_17,    /* =2 mixed public, private & unexported symbol */
	SCENARIO_18,    /* >2 mixed public, private & unexported symbol */
	SCENARIO_19	/* >2 mixed public, private & unexported symbol */
} scenario_t;

typedef struct lib_tag {
	bvlist_t	*lt_release;		/* 0 or 1 bitvector */
	bvlist_t	*lt_trans_bits;		/* transition bitvector */
	category_t	*lt_cat;		/* symbol class in lib */
	char		*lt_lib_name;		/* with location */
	int		lt_check_me;		/* = 1: check me */
	int		lt_libc_migrate;	/* is a libc_migrate or not */
	scenario_t	lt_scenario;		/* unique num from 1-19 */
	verlist_t	*lt_version;		/* vers for release */
	struct lib_tag	*lt_next;
} liblist_t;

typedef struct sym_tag {
	SymbolType_t	st_type;	/* FUNCTION or OBJECT */
	char		*st_sym_name;	/* symbol name */
	int		st_size;	/* size of object */
	liblist_t	*st_lib;	/* lib info symbol belongs to */
} symbol_t;

typedef enum {
	NO_CLASS,
	PUBLIC,
	PRIVATE,
	UNEXPORTED
} class_t;

typedef struct sequence {
	bvlist_t	*s_pos;
	class_t		s_class;
	struct sequence	*s_next;
} sequence_t;

/*
 * data structure for AVL tree
 */

typedef enum BalanceFactor_tag { LH, EH, RH } BalanceFactor_t;

typedef struct tree_tag {
	symbol_t		*tt_sym;
	BalanceFactor_t		tt_bf;
	struct tree_tag		*tt_left;
	struct tree_tag		*tt_right;
} tree_t;

/* declaration of global variables */
extern FILE		*Db;		/* ABI datafile read/write fd */
extern FILE		*Msgout;	/* abi_audit output fd */
extern char		*program;	/* program name for error messages */
extern int		Debug;		/* flag for debugging use */
extern int		Total_relcnt;	/* # of releases read in */
extern int		iflag;		/* version checking */
extern rellist_t	*Rel;		/* store all release info */
extern tree_t		*Sym_List;	/* info storage of symbols */

/* abi_audit.c functions */
int		count_num_char(const char, char *);
void		generate_db(symbol_t *, FILE *);

/* util.c functions */
char		*trimmer(char *);
int		add_symbol(symbol_t *, liblist_t *, category_t *, int);
int		build_cat_bits(bvlist_t *, char *, category_t *);
int		build_lib_tag(bvlist_t *, char *, char *, liblist_t *, int);
int		check_lib_info(list_t *, char *);
list_t		*store_lib_info(list_t *, char *);
void		build_sym_tag(char *, symbol_t *);
void		sequence_list_destroy(sequence_t *);
void		tree_traverse(tree_t *);

/* bvlist data abstraction */
bvlist_t	*bv_bitmask_lshift(bvlist_t *);
bvlist_t	*bv_bitmask_rshift(bvlist_t *);
bvlist_t	*create_bv_list(int);
bvlist_t	*stobv(char *, int);
char		*bvtos(bvlist_t *);
int		bv_all_zero(bvlist_t *);
int		bv_and(bvlist_t *, bvlist_t *);
void		bv_assign(bvlist_t *, bvlist_t *);
int		bv_compare(bvlist_t *, bvlist_t *);
int		bv_earlier_than(bvlist_t *, bvlist_t *);
void		free_bv_list(bvlist_t *);
void		set_bv_or(bvlist_t *, bvlist_t *);

/* verlist data abstraction */
char		*get_lib_ver(liblist_t *, int);
char		*get_sym_ver(liblist_t *, int);
int		add_verlist(liblist_t *, int);
void		assign_lib_ver(liblist_t *, char *, int);
void		assign_sym_ver(liblist_t *, char *, int);

/* rellist data abstraction */
bvlist_t	*get_rel_bitmask(int);
char		*get_rel_name(int);
int		add_rellist(int);
int		find_num_nodes(int);
void		assign_rel_name(char *, int);

/* verschk.c functions */
int		find_exported_release(liblist_t *, int);
void		assign_versions(liblist_t *, liblist_t *, int);
void		version_checker(tree_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _ABI_AUDIT_H */
