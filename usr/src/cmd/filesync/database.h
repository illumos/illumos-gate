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
 * Copyright (c) 1996 Sun Microsystems, Inc.  All Rights Reserved
 *
 * module:
 *	database.h
 *
 * purpose:
 *	definition of the baseline and rules data structures
 */

#ifndef	_DATABASE_H
#define	_DATABASE_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/stat.h>
#include <sys/acl.h>

#define	ACL_UID_BUG	1	/* acl:SETACL sets owner to be caller	*/

/*
 * flag bits describing what we know about an individual file, or in
 * some cases an entire base pair.  These flags are found in the
 * base and file stuctures.
 */
typedef int fflags_t;			/* type for file flags		*/

#define	F_NEW		0x01		/* newly allocated		*/
#define	F_IN_BASELINE	0x02		/* file found in baseline	*/
#define	F_IN_SOURCE	0x04		/* file found in source tree	*/
#define	F_IN_DEST	0x08		/* file found in dest tree	*/
#define	F_EVALUATE	0x10		/* include in analysis		*/
#define	F_SPARSE	0x20		/* don't walk this directory	*/
#define	F_REMOVE	0x40		/* remove from baseline		*/
#define	F_CONFLICT	0x80		/* unresolvable conflict	*/
#define	F_LISTED	0x100		/* file came from LIST		*/
#define	F_STAT_ERROR	0x200		/* unable to stat file		*/

#define	F_WHEREFOUND	(F_IN_BASELINE|F_IN_SOURCE|F_IN_DEST)

/*
 * a base is a pair of directories to be kept in sync
 * 	all rules and baseline data is stored beneath some base
 */
struct base {
	struct base *b_next;		/* pointer to next base		*/
	fflags_t   b_flags;		/* what I know about this base	*/
	int   b_ident;			/* base sequence # (DBG)	*/
	char *b_src_spec;		/* spec name of source dir	*/
	char *b_dst_spec;		/* spec name of dest dir	*/
	char *b_src_name;		/* expanded name of source dir	*/
	char *b_dst_name;		/* expanded name of dest dir	*/

	struct rule *b_includes;	/* chain of include rules	*/
	struct rule *b_excludes;	/* chain of exclude rules	*/
	struct rule *b_restrictions;	/* chain of restrictions	*/

	struct file *b_files;		/* chain of files		*/

	/* statistics for wrap-up summary				*/
	int b_totfiles;			/* total files found in tree	*/
	int b_src_copies;		/* files copied to source	*/
	int b_src_deletes;		/* files deleted from source	*/
	int b_src_misc;			/* ownership changes on source	*/
	int b_dst_copies;		/* files copied to dest		*/
	int b_dst_deletes;		/* files deleted from dest	*/
	int b_dst_misc;			/* ownership changes on source	*/
	int b_unresolved;		/* unresolved conflicts		*/
};

/*
 * flag bits describing what we know about a particular rule.
 * These flags are found in the rule structure
 */
typedef	int rflags_t;			/* type for rule flags		*/

#define	R_NEW		0x01		/* newly added rule (=OPT_NEW)	*/
#define	R_PROGRAM	0x02		/* program (vs literal names)	*/
#define	R_IGNORE	0x04		/* IGNORE (vs INCLUDE)		*/
#define	R_RESTRICT	0x08		/* restriction (-r argument)	*/
#define	R_WILD		0x10		/* name involves wild cards	*/
#define	R_BOGUS		0x20		/* fabricated rule		*/

/*
 * a rule describes files to be included or excluded
 *	they are stored under bases
 */
struct rule {
	struct rule *r_next;		/* pointer to next rule in base	*/
	rflags_t r_flags;		/* flags associated with rule	*/
	char   *r_file;			/* file for this rule		*/
};


/*
 * this is the information we keep track of for a file
 */
struct fileinfo {
	ino_t	f_ino;			/* inode number of this file	*/
	long	f_d_maj;		/* maj dev on which it lives	*/
	long	f_d_min;		/* minj dev on which it lives	*/

	int 	f_type;			/* file/dir/special ...		*/
	int	f_mode;			/* protection			*/
	int	f_nlink;		/* number of links to file	*/

	uid_t	f_uid;			/* owning UID			*/
	gid_t	f_gid;			/* owning GID			*/

	off_t	f_size;			/* length in bytes		*/
	long	f_modtime;		/* last modification time	*/
	long	f_modns;		/* low order bits of modtime	*/

	long	f_rd_maj;		/* major dev for specials	*/
	long	f_rd_min;		/* minor dev for specials	*/

	int	f_numacls;		/* number of entries in acls	*/
	aclent_t *f_acls;		/* acl list (if any)		*/
};

/*
 * flag bits describing the differences we have detected between a file
 * and the last time it was in sync (based on the baseline).
 * These flags are used in the srcdiffs and dstdiffs fields of the
 * file structure
 */
typedef int diffmask_t;			/* type for difference masks	*/

#define	D_CREATE	0x01		/* file has been created	*/
#define	D_DELETE	0x02		/* file has been deleted	*/
#define	D_MTIME		0x04		/* file has been modified	*/
#define	D_SIZE		0x08		/* file has changed size	*/
#define	D_UID		0x10		/* file has changed user id	*/
#define	D_GID		0x20		/* file has changed group id	*/
#define	D_PROT		0x40		/* file has changed protection	*/
#define	D_LINKS		0x80		/* file has changed link count	*/
#define	D_TYPE		0x100		/* file has changed type	*/
#define	D_FACLS		0x200		/* file has changed facls	*/
#define	D_RENAME_TO	0x400		/* file came from a rename	*/
#define	D_RENAME_FROM	0x800		/* file has been renamed	*/

/*
 * these masks are used to determine how important potential changes are.
 *
 *	D_CONTENTS	there may be changes to the file's contents
 *	D_ADMIN		there may be changes to the ownership and protection
 *	D_IMPORTANT	there may be changes that should block a deletion
 *
 * Note:
 *	I am torn on whether or not to include modtime in D_IMPORTANT.
 *	Experience suggests that deleting one of many links affects the
 *	file modification time.
 */
#define	D_ADMIN		(D_UID|D_GID|D_PROT|D_FACLS)
#define	D_CONTENTS	(D_SIZE|D_TYPE|D_CREATE|D_MTIME)
#define	D_IMPORTANT	(D_SIZE|D_TYPE|D_CREATE|D_MTIME|D_ADMIN)

/*
 * a file is an instance that follows (under a base) from a rule
 * (for that base).  A file structure may exist because of any
 * combination of a file under the source, destination, in a
 * baseline for historical reasons, or merely because a rule
 * calls it out (whether it exists or not).
 */
struct file {
	struct file *f_next;		/* pointer to next file in base	*/
	struct file *f_files;		/* pointer to files in subdir	*/
	struct base *f_base;		/* pointer to owning base	*/
	fflags_t f_flags;		/* flags associated with file	*/
	int	f_depth;		/* directory depth for file	*/
	char   *f_name;			/* name of this file		*/

	/*
	 * these fields capture information, gleaned from the baseline
	 * that is side-specific, and should not be expected to be in
	 * agreement between the two sides.  As a result, this info can
	 * not be properly captured in f_info[OPT_BASE] and needs to
	 * be kept somewhere else.
	 */
	long	f_s_modtime;		/* baseline source mod time	*/
	ino_t	f_s_inum;		/* baseline source inode #	*/
	long	f_s_nlink;		/* baseline source link count	*/
	long	f_s_maj;		/* baseline source dev maj	*/
	long	f_s_min;		/* baseline source dev min	*/
	long	f_d_modtime;		/* baseline target mod time	*/
	ino_t	f_d_inum;		/* baseline target inode #	*/
	long	f_d_nlink;		/* baseline target link count	*/
	long	f_d_maj;		/* baseline target dev maj	*/
	long	f_d_min;		/* baseline target dev min	*/

	/* stat information from baseline file and evaluation		*/
	struct fileinfo f_info[3];	/* baseline, source, dest	*/

	/* summary of changes discovered in analysis			*/
	diffmask_t f_srcdiffs;		/* changes on source side	*/
	diffmask_t f_dstdiffs;		/* changes on dest side		*/

	/* this field is only valid for a renamed file			*/
	struct file * f_previous;	/* node for previous filename	*/

	/*
	 * these fields are only valid for a file that has been added
	 * to the reconciliation list
	 */
	struct file *f_rnext;		/* reconciliation chain ptr	*/
	char	*f_fullname;		/* full name for reconciling	*/
	long	f_modtime;		/* modtime for ordering purpose	*/
	long	f_modns;		/* low order modtime 		*/

	/* this field is only valid for a file with a hard conflict	*/
	char 	*f_problem;		/* description of conflict	*/
};

/*
 * globals
 */
extern struct base omnibase;		/* base for global rules	*/
extern struct base *bases;		/* base for the main list	*/
extern int inum_changes;		/* LISTed dirs with i# changes	*/

/* routines to manage base nodes, file nodes, and file infor	*/
errmask_t read_baseline(char *);
errmask_t write_baseline(char *);
struct file *add_file_to_base(struct base *, const char *);
struct file *add_file_to_dir(struct file *, const char *);
struct base *add_base(const char *src, const char *dst);
void note_info(struct file *, const struct stat *, side_t);
void update_info(struct file *, side_t);

/* routines to manage rules					*/
errmask_t read_rules(char *);
errmask_t write_rules(char *);
errmask_t add_include(struct base *, char *);
errmask_t add_ignore(struct base *, char *);

/* routines to manage and querry restriction lists		*/
errmask_t add_restr(char *);
bool_t check_restr(struct base *, const char *);

/* routines for dealing with ignore lists			*/
void ignore_reset();
void ignore_pgm(const char *);
void ignore_expr(const char *);
void ignore_file(const char *);
bool_t ignore_check(const char *);

/* database processing routines for the primary passes		*/
errmask_t evaluate(struct base *, side_t, bool_t);
errmask_t analyze(void);
errmask_t find_renames(struct file *);
errmask_t reconcile(struct file *);
int prune(void);
void summary(void);
char *full_name(struct file *, side_t, side_t);

/* routines in action.c to carry out reconciliation		*/
errmask_t do_copy(struct file *, side_t);
errmask_t do_remove(struct file *, side_t);
errmask_t do_rename(struct file *, side_t);
errmask_t do_like(struct file *, side_t, bool_t);

/* routines to deal with links in the reconciliation list	*/
struct file *find_link(struct file *, side_t);
void link_update(struct file *, side_t);
bool_t has_other_links(struct file *, side_t);

/* maintain a name stack during directory tree traversal	*/
void push_name(const char *);
void pop_name();
char *get_name(struct file *);

/* acl manipulation functions					*/
int get_acls(const char *, struct fileinfo *);
int set_acls(const char *, struct fileinfo *);
int cmp_acls(struct fileinfo *, struct fileinfo *);
char *show_acls(int, aclent_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DATABASE_H */
