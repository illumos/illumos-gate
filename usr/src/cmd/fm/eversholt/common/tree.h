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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * tree.h -- public definitions for tree module
 *
 * the parse tree is made up of struct node's.  the struct is
 * a "variant record" with a type, the filename and line number
 * related to the node, and then type-specific node data.
 */

#ifndef	_ESC_COMMON_TREE_H
#define	_ESC_COMMON_TREE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct node {
	enum nodetype {
		T_NOTHING,		/* used to keep going on error cases */
		T_NAME,			/* identifiers, sometimes chained */
		T_GLOBID,		/* globals (e.g. $a) */
		T_EVENT,		/* class@path{expr} */
		T_ENGINE,		/* upset threshold engine (e.g. SERD) */
		T_ASRU,			/* ASRU declaration */
		T_FRU,			/* FRU declaration */
		T_TIMEVAL,		/* num w/time suffix (ns internally) */
		T_NUM,			/* num (ull internally) */
		T_QUOTE,		/* quoted string */
		T_FUNC,			/* func(arglist) */
		T_NVPAIR,		/* name=value pair in decl */
		T_ASSIGN,		/* assignment statement */
		T_CONDIF,		/* a and T_CONDELSE in (a ? b : c ) */
		T_CONDELSE,		/* lists b and c in (a ? b : c ) */
		T_NOT,			/* boolean ! operator */
		T_AND,			/* boolean && operator */
		T_OR,			/* boolean || operator */
		T_EQ,			/* boolean == operator */
		T_NE,			/* boolean != operator */
		T_SUB,			/* integer - operator */
		T_ADD,			/* integer + operator */
		T_MUL,			/* integer * operator */
		T_DIV,			/* integer / operator */
		T_MOD,			/* integer % operator */
		T_LT,			/* boolean < operator */
		T_LE,			/* boolean <= operator */
		T_GT,			/* boolean > operator */
		T_GE,			/* boolean >= operator */
		T_BITAND,		/* bitwise & operator */
		T_BITOR,		/* bitwise | operator */
		T_BITXOR,		/* bitwise ^ operator */
		T_BITNOT,		/* bitwise ~ operator */
		T_LSHIFT,		/* bitwise << operator */
		T_RSHIFT,		/* bitwise >> operator */
		T_ARROW,		/* lhs (N)->(K) rhs */
		T_LIST,			/* comma-separated list */
		T_FAULT,		/* fault declaration */
		T_UPSET,		/* upset declaration */
		T_DEFECT,		/* defect declaration */
		T_ERROR,		/* error declaration */
		T_EREPORT,		/* ereport declaration */
		T_SERD,			/* SERD engine declaration */
		T_STAT,			/* STAT engine declaration */
		T_PROP,			/* prop statement */
		T_MASK,			/* mask statement */
		T_CONFIG		/* config statement */
	} t:8;

	/*
	 * regardless of the type of node, filename and line number
	 * information from the original .esc file is tracked here.
	 */
	int line:24;
	const char *file;

	/*
	 * the variant part of a struct node...
	 */
	union {
		struct {
			/*
			 * info kept for T_NAME, used in several ways:
			 *
			 *	1 for simple variable names.
			 *		example: j
			 *
			 *	2 for event class names, with component
			 *	  names chained together via the "next"
			 *	  pointers.
			 *		example: fault.fan.broken
			 *
			 *	3 for component pathnames, with component
			 *	  names chained together via the "next"
			 *	  pointers and iterators or instance numbers
			 *	  attached via the "child" pointers.
			 *		example: sysboard[0]/cpu[n]
			 *
			 * case 3 is the most interesting.
			 *	- if child is set, there's an iterator
			 *	- if child is a T_NAME, it is x[j] or x<j> and
			 *	  iterator type tells you vertical or horizontal
			 *	- if child is a T_NUM, it is x[0] or x<0> or
			 *	  x0 and iterator type tells you which one
			 *	- if cp pointer is set, then we recently
			 *	  matched it to a config cache entry and one
			 *	  can ignore child for now because it still
			 *	  represents the *pattern* you're matching.
			 *	  cp represents what you matched.  ptree()
			 *	  knows that if cp is set, to print that number
			 *	  instead of following child.
			 *
			 * when T_NAME nodes are chained:
			 * the "last" pointer takes you to the end of the
			 * chain, but only the first component's last pointer
			 * is kept up to date.  it is used to determine
			 * where to append newly-created T_NAME nodes (see
			 * tree_name_append()).
			 */
			const char *s;		/* the name itself */

			struct node *child;
			struct node *next;
			struct node *last;

			/* opaque pointer used during config matching */
			struct config *cp;

			/*
			 * note nametype is also declared as a three bit enum
			 * in itree.h, so if this ever needs expanding that
			 * will need changing too.
			 */
			enum nametype {
				N_UNSPEC,
				N_FAULT,
				N_UPSET,
				N_DEFECT,
				N_ERROR,
				N_EREPORT,
				N_SERD,
				N_STAT
			} t:3;
			enum itertype {
				IT_NONE,
				IT_VERTICAL,
				IT_HORIZONTAL,
				IT_ENAME
			} it:2;
			unsigned childgen:1;	/* child was auto-generated */
		} name;

		struct {
			/*
			 * info kept for T_GLOBID
			 */
			const char *s;		/* the name itself */
		} globid;

		/*
		 * info kept for T_TIMEVAL and T_NUM
		 *
		 * timevals are kept in nanoseconds.
		 */
		unsigned long long ull;

		struct {
			/*
			 * info kept for T_QUOTE
			 */
			const char *s;		/* the quoted string */
		} quote;

		struct {
			/*
			 * info kept for T_FUNC
			 */
			const char *s;		/* name of function */
			struct node *arglist;
		} func;

		struct {
			/*
			 * info kept for T_PROP and T_MASK statements
			 * as well as declarations for:
			 *	T_FAULT
			 *	T_UPSET
			 *	T_DEFECT
			 *	T_ERROR
			 *	T_EREPORT
			 *	T_ASRU
			 *	T_FRU
			 *	T_CONFIG
			 */
			struct node *np;
			struct node *nvpairs;	/* for declarations */
			struct lut *lutp;	/* for declarations */
			struct node *next;	/* for Props & Masks lists */
			struct node *expr;	/* for if statements */
			unsigned char flags;	/* see STMT_ flags below */
		} stmt;			/* used for stmt */

		struct {
			/*
			 * info kept for T_EVENT
			 */
			struct node *ename;	/* event class name */
			struct node *epname;	/* component path name */
			struct node *oldepname;	/* unwildcarded path name */
			struct node *ewname;	/* wildcarded portion */
			struct node *eexprlist;	/* constraint expression */
			struct node *declp;	/* event declaration */
		} event;

		struct {
			/*
			 * info kept for T_ARROW
			 */
			struct node *lhs;	/* left side of arrow */
			struct node *rhs;	/* right side of arrow */
			struct node *nnp;	/* N value */
			struct node *knp;	/* K value */
			struct node *prop;	/* arrow is part of this prop */
			int needed;
			struct node *parent;
		} arrow;

		struct {
			/*
			 * info kept for everything else (T_ADD, T_LIST, etc.)
			 */
			struct node *left;
			struct node *right;
			int temp;
		} expr;
	} u;
	/*
	 * Note to save memory the nodesize() function trims the end of this
	 * structure, so best not to add anything after this point
	 */
};

/* flags we keep with stmts */
#define	STMT_REF	0x01	/* declared item is referenced */
#define	STMT_CYMARK	0x02	/* declared item is marked for cycle check */
#define	STMT_CYCLE	0x04	/* cycle detected and already reported */

#define	TIMEVAL_EVENTUALLY (1000000000ULL*60*60*24*365*100)	/* 100 years */

void tree_init(void);
void tree_fini(void);
struct node *newnode(enum nodetype t, const char *file, int line);
void tree_free(struct node *root);
struct node *tree_root(struct node *np);
struct node *tree_nothing(void);
struct node *tree_expr(enum nodetype t, struct node *left, struct node *right);
struct node *tree_event(struct node *ename, struct node *epname,
    struct node *eexprlist);
struct node *tree_if(struct node *expr, struct node *stmts,
    const char *file, int line);
struct node *tree_name(const char *s, enum itertype it,
    const char *file, int line);
struct node *tree_iname(const char *s, const char *file, int line);
struct node *tree_globid(const char *s, const char *file, int line);
struct node *tree_name_append(struct node *np1, struct node *np2);
struct node *tree_name_repairdash(struct node *np1, const char *s);
struct node *tree_name_repairdash2(const char *s, struct node *np1);
struct node *tree_name_iterator(struct node *np1, struct node *np2);
struct node *tree_timeval(const char *s, const char *suffix,
    const char *file, int line);
struct node *tree_num(const char *s, const char *file, int line);
struct node *tree_quote(const char *s, const char *file, int line);
struct node *tree_func(const char *s, struct node *np,
    const char *file, int line);
struct node *tree_pname(struct node *np);
struct node *tree_arrow(struct node *lhs, struct node *nnp, struct node *knp,
    struct node *rhs);
struct lut *tree_s2np_lut_add(struct lut *root, const char *s, struct node *np);
struct node *tree_s2np_lut_lookup(struct lut *root, const char *s);
struct lut *tree_name2np_lut_add(struct lut *root,
    struct node *namep, struct node *np);
struct node *tree_name2np_lut_lookup(struct lut *root, struct node *namep);
struct node *tree_name2np_lut_lookup_name(struct lut *root, struct node *namep);
struct lut *tree_event2np_lut_add(struct lut *root,
    struct node *enp, struct node *np);
struct node *tree_event2np_lut_lookup(struct lut *root, struct node *enp);
struct node *tree_event2np_lut_lookup_event(struct lut *root,
    struct node *enp);
struct node *tree_decl(enum nodetype t, struct node *enp, struct node *nvpairs,
    const char *file, int line);
struct node *tree_stmt(enum nodetype t, struct node *np,
    const char *file, int line);
void tree_report();
int tree_namecmp(struct node *np1, struct node *np2);
int tree_eventcmp(struct node *np1, struct node *np2);

struct lut *Faults;
struct lut *Upsets;
struct lut *Defects;
struct lut *Errors;
struct lut *Ereports;
struct lut *Ereportenames;
struct lut *Ereportenames_discard;
struct lut *SERDs;
struct lut *STATs;
struct lut *ASRUs;
struct lut *FRUs;
struct lut *Configs;
struct node *Props;
struct node *Lastprops;
struct node *Masks;
struct node *Lastmasks;
struct node *Problems;
struct node *Lastproblems;

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_TREE_H */
