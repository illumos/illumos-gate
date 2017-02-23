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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 *
 * module:
 *	filesync.h
 *
 * purpose:
 *	general defines for use throughout the program
 */

#ifndef	_FILESYNC_H
#define	_FILESYNC_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * arbitrary limits
 */
#define	MAX_NAME	256		/* longest path component	*/
#define	MAX_PATH	1024		/* longest total path length	*/
#define	MAX_RLIST	32		/* max number of -r arguments	*/
#define	MAX_LINE	1024		/* longest input line		*/
#define	MAX_DEPTH	20		/* how deep to recurse		*/
#define	COPY_BSIZE	8192		/* block size for file copies	*/
#define	MIN_HOLE	1024		/* minimum hole in sparse file	*/
#define	HASH_SIZE	99		/* ignore list hash table	*/

/*
 * sanity check limits
 */
#define	CONFIRM_MIN	4		/* min # deletetes to confirm	*/
#define	CONFIRM_PCT	25		/* min pctg of files to confirm	*/

/*
 * special types used in the program
 */
typedef enum {
	FALSE = 0,
	TRUE  = 1,
	MAYBE = 2			/* only partially true		*/
} bool_t;

typedef enum {
	OPT_BASE = 0,			/* use the baseline data	*/
	OPT_SRC = 1,			/* use the source side		*/
	OPT_DST = 2,			/* use the destination side	*/
	OPT_OLD = 3,			/* use the old one		*/
	OPT_NEW = 4			/* use the new one		*/
} side_t;

/*
 * values for debug mask
 */
typedef	long dbgmask_t;			/* type for debug masks		*/
#define	DBG_BASE	0x0001		/* baseline changes		*/
#define	DBG_RULE	0x0002		/* rule base changes		*/
#define	DBG_STAT	0x0004		/* file stats			*/
#define	DBG_ANAL	0x0008		/* analysis tracing		*/
#define	DBG_RECON	0x0010		/* reconciliation tracing	*/
#define	DBG_VARS	0x0020		/* variable tracing		*/
#define	DBG_FILES	0x0040		/* file reading/writing		*/
#define	DBG_LIST	0x0080		/* include list building	*/
#define	DBG_EVAL	0x0100		/* evaluation tracing		*/
#define	DBG_IGNORE	0x0200		/* ignore tracing		*/
#define	DBG_MISC	0x0400		/* catch-all everything else	*/

/*
 * values for error codes
 */
typedef int errmask_t;			/* type for error masks		*/
#define	ERR_OK		0		/* everything is fine		*/
#define	ERR_RESOLVABLE	1		/* resolvable conflicts		*/
#define	ERR_UNRESOLVED	2		/* unresolvable conflicts	*/
#define	ERR_MISSING	4		/* some files missing		*/
#define	ERR_PERM	8		/* insufficient access		*/
#define	ERR_FILES	16		/* file format or I/O errors	*/
#define	ERR_INVAL	32		/* invalid arguments		*/
#define	ERR_NOBASE	64		/* inaccessable base directory	*/
#define	ERR_OTHER	128		/* anything else		*/

/* errors that will prevent reconciliation from taking place		*/
#define	ERR_FATAL	(ERR_FILES|ERR_INVAL|ERR_NOBASE|ERR_OTHER)

/* errors that will cause reconciliation to stop with -h specified	*/
#define	ERR_ABORT	(ERR_FILES|ERR_PERM)

/*
 * program defaults
 */
#define	DFLT_PRFX	"$HOME/"		/* default location/pfx	*/
#define	SUFX_RULES	".packingrules"		/* rules v1.1 location	*/
#define	SUFX_BASE	".filesync-base"	/* baseline location	*/
#define	SUFX_OLD	".filesync-rules"	/* rules v1.0 location	*/

/*
 * global variables for command line options
 */
extern bool_t  opt_acls;	/* enable acl checking/preservation	*/
extern bool_t  opt_mtime;	/* preserve modification times		*/
extern bool_t  opt_notouch;	/* don't actually make any changes	*/
extern side_t  opt_force;	/* designated winner for conflicts	*/
extern side_t  opt_oneway;	/* one way only propagation		*/
extern side_t  opt_onesided;	/* permit one sided analysis		*/
extern bool_t  opt_everything;	/* everything must agree (modes/uid/gid) */
extern bool_t  opt_quiet;	/* stiffle reconciliaton descriptions	*/
extern bool_t  opt_verbose;	/* generate analysis commentary		*/
extern bool_t  opt_errors;	/* simulate errors on specified files	*/
extern bool_t  opt_halt;	/* halt on any propagation error	*/
extern dbgmask_t opt_debug;	/* debugging options			*/

/*
 * information gained during startup that other people may need
 */
extern uid_t my_uid;	/* User ID for files I create			*/
extern gid_t my_gid;	/* Group ID for files I create			*/

/* error and warning routines						*/
void confirm(char *);		/* ask user if they're sure		*/
void nomem(char *);		/* die from malloc failure		*/

/* routines for dealing with strings and file names			*/
const char *prefix(const char *, const char *); /* does s1 begin with s2 */
char *qualify(char *);		/* validate and fully qualify		*/
char *expand(char *);		/* expand variables in name		*/
char *lex(FILE *);		/* lex off one token			*/
extern int lex_linenum;		/* current input file line number	*/
const char *noblanks(const char *);	/* escape strings for embedded blanks */
bool_t wildcards(const char *);	/* does name contain wildcards		*/
bool_t suffix(const char *, const char *);	/* does s1 end with s2	*/
bool_t contains(const char *, const char *);	/* does s1 contain s2	*/

#ifdef	__cplusplus
}
#endif

#endif	/* _FILESYNC_H */
