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
 * Copyright 1995-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * module:
 *	eval.c
 *
 * purpose:
 *	routines to ascertain the current status of all of the files
 *	described by a set of rules.  Some of the routines that update
 *	file status information are also called later (during reconcilation)
 *	to reflect the changes that have been made to files.
 *
 * contents:
 *	evaluate	top level - evaluate one side of one base
 *	add_file_arg	(static) add a file to the list of files to evaluate
 *	eval_file	(static) stat a specific file, recurse on directories
 *	walker		(static) node visitor for recursive descent
 *	note_info	update a file_info structure from a stat structure
 *	do_update	(static) update one file_info structure from another
 *	update_info	update the baseline file_info from the prevailng side
 *	fakedata	(static) make it look like one side hasn't changed
 *	check_inum	(static) sanity check to detect wrong-dir errors
 *	add_glob	(static) expand a wildcard in an include rule
 *	add_run		(static) run a program to generate an include list
 *
 * notes:
 *	pay careful attention to the use of the LISTED and EVALUATE
 *	flags in each file description structure.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <string.h>
#include <glob.h>
#include <ftw.h>
#include <sys/mkdev.h>
#include <errno.h>

#include "filesync.h"
#include "database.h"
#include "messages.h"
#include "debug.h"

/*
 * routines:
 */
static errmask_t eval_file(struct base *, struct file *);
static errmask_t add_file_arg(struct base *, char *);
static int walker(const char *, const struct stat *, int, struct FTW *);
static errmask_t add_glob(struct base *, char *);
static errmask_t add_run(struct base *, char *);
static void check_inum(struct file *, int);
static void fakedata(struct file *, int);

/*
 * globals
 */
static bool_t usingsrc;	/* this pass is on the source side		*/
static int walk_errs;	/* errors found in tree walk			*/
static struct file *cur_dir;	/* base directory for this pass		*/
static struct base *cur_base;	/* base pointer for this pass		*/

/*
 * routine:
 *	evaluate
 *
 * purpose:
 *	to build up a baseline description for all of the files
 *	under one side of one base pair (as specified by the rules
 *	for that base pair).
 *
 * parameters:
 *	pointer to the base to be evaluated
 *	source/destination indication
 *	are we restricted to new rules
 *
 * returns:
 *	error mask
 *
 * notes:
 *	we evaluate source and destination separately, and
 *	reinterpret the include rules on each side (since there
 *	may be wild cards and programs that must be evaluated
 *	in a specific directory context).  Similarly the ignore
 *	rules must be interpreted anew for each base.
 */
errmask_t
evaluate(struct base *bp, side_t srcdst, bool_t newrules)
{	errmask_t errs = 0;
	char *dir;
	struct rule *rp;
	struct file *fp;

	/* see if this base is still relevant		*/
	if ((bp->b_flags & F_LISTED) == 0)
		return (0);

	/* figure out what this pass is all about	*/
	usingsrc = (srcdst == OPT_SRC);

	/*
	 * the ignore engine maintains considerable per-base-directory
	 * state, and so must be reset at the start of a new tree.
	 */
	ignore_reset();

	/* all evaluation must happen from the appropriate directory */
	dir = usingsrc ? bp->b_src_name : bp->b_dst_name;
	if (chdir(dir) < 0) {
		fprintf(stderr, gettext(ERR_chdir), dir);

		/*
		 * if we have -n -o we are actually willing to
		 * pretend that nothing has changed on the missing
		 * side.  This is actually useful on a disconnected
		 * notebook to ask what has been changed so far.
		 */
		if (opt_onesided == (usingsrc ? OPT_DST : OPT_SRC)) {
			for (fp = bp->b_files; fp; fp = fp->f_next)
				fakedata(fp, srcdst);

			if (opt_debug & DBG_EVAL)
				fprintf(stderr, "EVAL: FAKE DATA %s dir=%s\n",
					usingsrc ? "SRC" : "DST", dir);
			return (0);
		} else
			return (ERR_NOBASE);
	}

	if (opt_debug & DBG_EVAL)
		fprintf(stderr, "EVAL: base=%d, %s dir=%s\n",
			bp->b_ident, usingsrc ? "SRC" : "DST", dir);

	/* assemble the include list			*/
	for (rp = bp->b_includes; rp; rp = rp->r_next) {

		/* see if we are skipping old rules	*/
		if (newrules && ((rp->r_flags & R_NEW) == 0))
			continue;

		if (rp->r_flags & R_PROGRAM)
			errs |= add_run(bp, rp->r_file);
		else if (rp->r_flags & R_WILD)
			errs |= add_glob(bp, rp->r_file);
		else
			errs |= add_file_arg(bp, rp->r_file);
	}

	/* assemble the base-specific exclude list		*/
	for (rp = bp->b_excludes; rp; rp = rp->r_next)
		if (rp->r_flags & R_PROGRAM)
			ignore_pgm(rp->r_file);
		else if (rp->r_flags & R_WILD)
			ignore_expr(rp->r_file);
		else
			ignore_file(rp->r_file);

	/* add in the global excludes				*/
	for (rp = omnibase.b_excludes; rp; rp = rp->r_next)
		if (rp->r_flags & R_WILD)
			ignore_expr(rp->r_file);
		else
			ignore_file(rp->r_file);

	/*
	 * because of restriction lists and new-rules, the baseline
	 * may contain many more files than we are actually supposed
	 * to look at during the impending evaluation/analysis phases
	 *
	 * when LIST arguments are encountered within a rule, we turn
	 * on the LISTED flag for the associated files.  We only evaluate
	 * files that have the LISTED flag.  We turn the LISTED flag off
	 * after evaluating them because just because a file was enumerated
	 * in the source doesn't mean that will necessarily be enumerated
	 * in the destination.
	 */
	for (fp = bp->b_files; fp; fp = fp->f_next)
		if (fp->f_flags & F_LISTED) {
			errs |= eval_file(bp, fp);
			fp->f_flags &= ~F_LISTED;
		}

	/* note that this base has been evaluated	*/
	bp->b_flags |= F_EVALUATE;

	return (errs);
}

/*
 * routine:
 *	add_file_arg
 *
 * purpose:
 *	to create file node(s) under a specified base for an explictly
 *	included file.
 *
 * parameters:
 *	pointer to associated base
 *	name of the file
 *
 * returns:
 *	error mask
 *
 * notes:
 *	the trick is that an include LIST argument need not be a file
 *	in the base directory, but may be a path passing through
 *	several intermediate directories.  If this is the case we
 *	need to ensure that all of those directories are added to
 *	the tree SPARSELY since it is not intended that they be
 *	expanded during the course of evaluation.
 *
 *	we ignore arguments that end in .. because they have the
 *	potential to walk out of the base tree, because it can
 *	result in different names for a single file, and because
 *	should never be necessary to specify files that way.
 */
static errmask_t
add_file_arg(struct base *bp, char *path)
{	int i;
	errmask_t errs = 0;
	struct file *dp = 0;
	struct file *fp;
	char *s, *p;
	char name[ MAX_NAME ];

	/*
	 * see if someone is trying to feed us a ..
	 */
	if (strcmp(path, "..") == 0 || prefix(path, "../") ||
	    suffix(path, "/..") || contains(path, "/../")) {
		fprintf(stderr, gettext(WARN_ignore), path);
		return (ERR_MISSING);
	}

	/*
	 * strip off any trailing "/." or "/"
	 *	since noone will miss these, it is safe to actually
	 *	take them off the name.  When we fall out of this
	 *	loop, s will point where the null belongs.  We don't
	 *	actually null the end of string yet because we want
	 *	to leave it pristine for error messages.
	 */
	for (s = path; *s; s++);
	while (s > path) {
		if (s[-1] == '/') {
			s--;
			continue;
		}
		if (s[-1] == '.' && s > &path[1] && s[-2] == '/') {
			s -= 2;
			continue;
		}
		break;
	}

	/*
	 * skip over leading "/" and "./" (but not over a lone ".")
	 */
	for (p = path; p < s; ) {
		if (*p == '/') {
			p++;
			continue;
		}
		if (*p == '.' && s > &p[1] && p[1] == '/') {
			p += 2;
			continue;
		}
		break;
	}

	/*
	 * if there is nothing left, we're miffed, but done
	 */
	if (p >= s) {
		fprintf(stderr, gettext(WARN_ignore), path);
		return (ERR_MISSING);
	} else {
		/*
		 * this is actually storing a null into the argument,
		 * but it is OK to do this because the stuff we are
		 * truncating really is garbage that noone will ever
		 * want to see.
		 */
		*s = 0;
		path = p;
	}

	/*
	 * see if there are any restrictions that would force
	 * us to ignore this argument
	 */
	if (check_restr(bp, path) == 0)
		return (0);

	while (*path) {
		/* lex off the next name component	*/
		for (i = 0; path[i] && path[i] != '/'; i++)
			name[i] = path[i];
		name[i] = 0;

		/* add it into the database		*/
		fp = (dp == 0)  ? add_file_to_base(bp, name)
				: add_file_to_dir(dp, name);

		/* see if this was an intermediate directory	*/
		if (path[i] == '/') {
			fp->f_flags |= F_LISTED | F_SPARSE;
			path += i+1;
		} else {
			fp->f_flags |= F_LISTED;
			path += i;
		}

		dp = fp;
	}

	return (errs);
}

/*
 * routine:
 *	eval_file
 *
 * purpose:
 *	to evaluate one named file under a particular directory
 *
 * parameters:
 *	pointer to base structure
 *	pointer to file structure
 *
 * returns:
 *	error mask
 *	filled in evaluations in the baseline
 *
 * note:
 *	due to new rules and other restrictions we may not be expected
 *	to evaluate the entire tree.  We should only be called on files
 *	that are LISTed, and we should only invoke ourselves recursively
 *	on such files.
 */
static errmask_t
eval_file(struct base *bp, struct file *fp)
{	errmask_t errs = 0;
	int rc;
	char *name;
	struct file *cp;
	struct stat statb;

	if (opt_debug & DBG_EVAL)
		fprintf(stderr, "EVAL: FILE, flags=%s, name=%s\n",
			showflags(fileflags, fp->f_flags), fp->f_name);

	/* stat the file and fill in the file structure information	*/
	name = get_name(fp);

#ifdef 	DBG_ERRORS
	/* see if we should simulated a stat error on this file	*/
	if (opt_errors && (errno = dbg_chk_error(name, usingsrc ? 's' : 'S')))
		rc = -1;
	else
#endif
	rc = lstat(name, &statb);

	if (rc < 0) {
		if (opt_debug & DBG_EVAL)
			fprintf(stderr, "EVAL: FAIL lstat, errno=%d\n", errno);
		switch (errno) {
		    case EACCES:
			fp->f_flags |= F_STAT_ERROR;
			return (ERR_PERM);
		    case EOVERFLOW:
			fp->f_flags |= F_STAT_ERROR;
			return (ERR_UNRESOLVED);
		    default:
			return (ERR_MISSING);
		}
	}

	/* record the information we've just gained			*/
	note_info(fp, &statb, usingsrc ? OPT_SRC : OPT_DST);

	/*
	 * checking for ACLs is expensive, so we only do it if we
	 * have been asked to, or if we have reason to believe that
	 * the file has an ACL
	 */
	if (opt_acls || fp->f_info[OPT_BASE].f_numacls)
		(void) get_acls(name,
				&fp->f_info[usingsrc ? OPT_SRC : OPT_DST]);


	/* note that this file has been evaluated			*/
	fp->f_flags |= F_EVALUATE;

	/* if it is not a directory, a simple stat will suffice	*/
	if ((statb.st_mode & S_IFMT) != S_IFDIR)
		return (0);

	/*
	 * as a sanity check, we look for changes in the I-node
	 * numbers associated with LISTed directories ... on the
	 * assumption that these are high-enough up on the tree
	 * that they aren't likely to change, and so a change
	 * might indicate trouble.
	 */
	if (fp->f_flags & F_LISTED)
		check_inum(fp, usingsrc);

	/*
	 * sparse directories are on the path between a base and
	 * a listed directory.  As such, we don't walk these
	 * directories.  Rather, we just enumerate the LISTed
	 * files.
	 */
	if (fp->f_flags & F_SPARSE) {
		push_name(fp->f_name);

		/* this directory isn't supposed to be fully walked	*/
		for (cp = fp->f_files; cp; cp = cp->f_next)
			if (cp->f_flags & F_LISTED) {
				errs |= eval_file(bp, cp);
				cp->f_flags &= ~F_LISTED;
			}
		pop_name();
	} else {
		/* fully walk the tree beneath this directory		*/
		walk_errs = 0;
		cur_base = bp;
		cur_dir = fp;
		nftw(get_name(fp), &walker, MAX_DEPTH, FTW_PHYS|FTW_MOUNT);
		errs |= walk_errs;
	}

	return (errs);
}

/*
 * routine:
 *	walker
 *
 * purpose:
 *	node visitor for recursive directory enumeration
 *
 * parameters:
 *	name of file
 *	pointer to stat buffer for file
 *	file type
 *	FTW structure (base name offset, walk-depth)
 *
 * returns:
 *	0 	continue
 *	-1	stop
 *
 * notes:
 *	Ignoring files is easy, but ignoring directories is harder.
 *	Ideally we would just decline to walk the trees beneath
 *	ignored directories, but ftw doesn't allow the walker to
 *	tell it to "don't enter this directory, but continue".
 *
 *	Instead, we have to set a global to tell us to ignore
 *	everything under that tree.  The variable ignore_level
 *	is set to a level, below which, everything should be
 *	ignored.  Once the enumeration rises above that level
 *	again, we clear it.
 */
static int
walker(const char *name, const struct stat *sp, int type,
		struct FTW *ftwx)
{	const char *path;
	struct file *fp;
	int level;
	int which;
	bool_t restr;
	static struct file *dirstack[ MAX_DEPTH + 1 ];
	static int ignore_level = 0;

	path = &name[ftwx->base];
	level = ftwx->level;
	which = usingsrc ? OPT_SRC : OPT_DST;

	/*
	 * see if we are ignoring all files in this sub-tree
	 */
	if (ignore_level > 0 && level >= ignore_level) {
		if (opt_debug & DBG_EVAL)
			fprintf(stderr, "EVAL: SKIP file=%s\n", name);
		return (0);
	} else
		ignore_level = 0;	/* we're through ignoring	*/

#ifdef 	DBG_ERRORS
	/* see if we should simulated a stat error on this file	*/
	if (opt_errors && dbg_chk_error(name, usingsrc ? 'n' : 'N'))
		type = FTW_NS;
#endif

	switch (type) {
	case FTW_F:	/* file 		*/
	case FTW_SL:	/* symbolic link	*/
		/*
		 * filter out files of inappropriate types
		 */
		switch (sp->st_mode & S_IFMT) {
			default:	/* anything else we ignore	*/
				return (0);

			case S_IFCHR:
			case S_IFBLK:
			case S_IFREG:
			case S_IFLNK:
				if (opt_debug & DBG_EVAL)
					fprintf(stderr,
						"EVAL: WALK lvl=%d, file=%s\n",
						level, path);

				/* see if we were told to ignore this one */
				if (ignore_check(path))
					return (0);

				fp = add_file_to_dir(dirstack[level-1], path);
				note_info(fp, sp, which);

				/* note that this file has been evaluated */
				fp->f_flags |= F_EVALUATE;

				/* see if we should check ACLs		*/
				if ((sp->st_mode & S_IFMT) == S_IFLNK)
					return (0);

				if (fp->f_info[OPT_BASE].f_numacls || opt_acls)
					(void) get_acls(name,
							&fp->f_info[which]);

				return (0);
		}

	case FTW_D:	/* enter directory 		*/
		if (opt_debug & DBG_EVAL)
			fprintf(stderr, "EVAL: WALK lvl=%d, dir=%s\n",
				level, name);

		/*
		 * if we have been told to ignore this directory, we should
		 * ignore all files under it.  Similarly, if we are outside
		 * of our restrictions, we should ignore the entire subtree
		 */
		restr = check_restr(cur_base, name);
		if (restr == FALSE || ignore_check(path)) {
			ignore_level = level + 1;
			return (0);
		}

		fp = (level == 0) ?  cur_dir :
		    add_file_to_dir(dirstack[level-1], path);

		note_info(fp, sp, which);

		/* see if we should be checking ACLs	*/
		if (opt_acls || fp->f_info[OPT_BASE].f_numacls)
			(void) get_acls(name, &fp->f_info[which]);

		/* note that this file has been evaluated */
		fp->f_flags |= F_EVALUATE;

		/* note the parent of the children to come	*/
		dirstack[ level ] = fp;

		/*
		 * PROBLEM: given the information that nftw provides us with,
		 *	    how do we know that we have confirmed the fact
		 *	    that a file no longer exists.  Or to rephrase
		 *	    this in filesync terms, how do we know when to
		 *	    set the EVALUATE flag for a file we didn't find.
		 *
		 * if we are going to fully scan this directory (we
		 * are completely within our restrictions) then we
		 * will be confirming the non-existance of files that
		 * used to be here.  Thus any file that was in the
		 * base line under this directory should be considered
		 * to have been evaluated (whether we found it or not).
		 *
		 * if, however, we are only willing to scan selected
		 * files (due to restrictions), or the file was not
		 * in the baseline, then we should not assume that this
		 * pass will evaluate it.
		 */
		if (restr == TRUE)
			for (fp = fp->f_files; fp; fp = fp->f_next) {
				if ((fp->f_flags & F_IN_BASELINE) == 0)
					continue;
				fp->f_flags |= F_EVALUATE;
			}

		return (0);

	case FTW_DP:	/* end of directory	*/
		dirstack[ level ] = 0;
		break;

	case FTW_DNR:	/* unreadable directory	*/
		walk_errs |= ERR_PERM;
		/* FALLTHROUGH	*/
	case FTW_NS:	/* unstatable file	*/
		if (opt_debug & DBG_EVAL)
			fprintf(stderr, "EVAL: walker can't stat/read %s\n",
				name);
		fp = (level == 0) ?  cur_dir :
			add_file_to_dir(dirstack[level-1], path);
		fp->f_flags |= F_STAT_ERROR;
		walk_errs |= ERR_UNRESOLVED;
		break;
	}

	return (0);
}

/*
 * routine:
 *	note_info
 *
 * purpose:
 * 	to record information about a file in its file node
 *
 * parameters
 *	file node pointer
 *	stat buffer
 *	which file info structure to fill in (0-2)
 *
 * returns
 *	void
 */
void
note_info(struct file *fp, const struct stat *sp, side_t which)
{	struct fileinfo *ip;
	static int flags[3] = { F_IN_BASELINE, F_IN_SOURCE, F_IN_DEST };

	ip = &fp->f_info[ which ];

	ip->f_ino	= sp->st_ino;
	ip->f_d_maj	= major(sp->st_dev);
	ip->f_d_min	= minor(sp->st_dev);
	ip->f_type	= sp->st_mode & S_IFMT;
	ip->f_size	= sp->st_size;
	ip->f_mode	= sp->st_mode & S_IAMB;
	ip->f_uid	= sp->st_uid;
	ip->f_gid	= sp->st_gid;
	ip->f_modtime	= sp->st_mtim.tv_sec;
	ip->f_modns	= sp->st_mtim.tv_nsec;
	ip->f_nlink	= sp->st_nlink;
	ip->f_rd_maj	= major(sp->st_rdev);
	ip->f_rd_min	= minor(sp->st_rdev);

	/* indicate where this file has been found	*/
	fp->f_flags |= flags[which];

	if (opt_debug & DBG_STAT)
		fprintf(stderr,
			"STAT: list=%d, file=%s, mod=%08lx.%08lx, nacl=%d\n",
			which, fp->f_name, ip->f_modtime, ip->f_modns,
			ip->f_numacls);
}

/*
 * routine:
 *	do_update
 *
 * purpose:
 * 	to copy information from one side into the baseline in order
 *	to reflect the effects of recent reconciliation actions
 *
 * parameters
 *	fileinfo structure to be updated
 *	fileinfo structure to be updated from
 *
 * returns
 *	void
 *
 * note:
 *	we play fast and loose with the copying of acl chains
 *	here, but noone is going to free or reuse any of this
 * 	memory anyway.  None the less, I do feel embarassed.
 */
static void
do_update(struct fileinfo *np, struct fileinfo *ip)
{
	/* get most of the fields from the designated "right" copy */
	np->f_type	= ip->f_type;
	np->f_size	= ip->f_size;
	np->f_mode	= ip->f_mode;
	np->f_uid	= ip->f_uid;
	np->f_gid	= ip->f_gid;
	np->f_rd_maj	= ip->f_rd_maj;
	np->f_rd_min	= ip->f_rd_min;

	/* see if facls have to be propagated	*/
	np->f_numacls = ip->f_numacls;
	np->f_acls = ip->f_acls;
}

/*
 * routine:
 *	update_info
 *
 * purpose:
 * 	to update the baseline to reflect recent reconcliations
 *
 * parameters
 *	file node pointer
 *	which file info structure to trust (1/2)
 *
 * returns
 *	void
 *
 * note:
 *	after we update this I-node we run down the entire
 *	change list looking for links and update them too.
 *	This is to ensure that when subsequent links get
 *	reconciled, they are already found to be up-to-date.
 */
void
update_info(struct file *fp, side_t which)
{
	/* first update the specified fileinfo structure	*/
	do_update(&fp->f_info[ OPT_BASE ], &fp->f_info[ which ]);

	if (opt_debug & DBG_STAT)
		fprintf(stderr,
			"STAT: UPDATE from=%d, file=%s, mod=%08lx.%08lx\n",
			which, fp->f_name, fp->f_info[ which ].f_modtime,
			fp->f_info[ which ].f_modns);
}

/*
 * routine:
 *	fakedata
 *
 * purpose:
 *	to populate a tree we cannot analyze with information from the baseline
 *
 * parameters:
 *	file to be faked
 *	which side to fake
 *
 * notes:
 *	We would never use this for real reconciliation, but it is useful
 *	if a disconnected notebook user wants to find out what has been
 *	changed so far.  We only do this if we are notouch and oneway.
 */
static void
fakedata(struct file *fp, int which)
{	struct file *lp;

	/* pretend we actually found the file			*/
	fp->f_flags |= (which == OPT_SRC) ? F_IN_SOURCE : F_IN_DEST;

	/* update the specified side from the baseline		*/
	do_update(&fp->f_info[ which ], &fp->f_info[ OPT_BASE ]);
	fp->f_info[which].f_nlink = (which == OPT_SRC) ? fp->f_s_nlink :
							fp->f_d_nlink;
	fp->f_info[which].f_modtime = (which == OPT_SRC) ? fp->f_s_modtime :
							fp->f_d_modtime;

	for (lp = fp->f_files; lp; lp = lp->f_next)
		fakedata(lp, which);
}

/*
 * routine:
 *	check_inum
 *
 * purpose:
 *	sanity check inode #s on directories that are unlikely to change
 *
 * parameters:
 *	pointer to file node
 *	are we using the source
 *
 * note:
 *	the purpose of this sanity check is to catch a case where we
 *	have somehow been pointed at a directory that is not the one
 *	we expected to be reconciling against.  It could happen if a
 *	variable wasn't properly set, or if we were in a new domain
 *	where an old path no longer worked.  This could result in
 *	bazillions of inappropriate propagations and deletions.
 */
void
check_inum(struct file *fp, int src)
{	struct fileinfo *ip;

	/*
	 * we validate the inode number and the major device numbers ... minor
	 * device numbers for NFS devices are arbitrary
	 */
	if (src) {
		ip = &fp->f_info[ OPT_SRC ];
		if (ip->f_ino == fp->f_s_inum && ip->f_d_maj == fp->f_s_maj)
			return;

		/* if file was newly created/deleted, this isn't warnable */
		if (fp->f_s_inum == 0 || ip->f_ino == 0)
			return;

		if (opt_verbose)
			fprintf(stdout, V_change, fp->f_name, TXT_src,
				fp->f_s_maj, fp->f_s_min, fp->f_s_inum,
				ip->f_d_maj, ip->f_d_min, ip->f_ino);
	} else {
		ip = &fp->f_info[ OPT_DST ];
		if (ip->f_ino == fp->f_d_inum && ip->f_d_maj == fp->f_d_maj)
			return;

		/* if file was newly created/deleted, this isn't warnable */
		if (fp->f_d_inum == 0 || ip->f_ino == 0)
			return;

		if (opt_verbose)
			fprintf(stdout, V_change, fp->f_name, TXT_dst,
				fp->f_d_maj, fp->f_d_min, fp->f_d_inum,
				ip->f_d_maj, ip->f_d_min, ip->f_ino);
	}

	/* note that something has changed	*/
	inum_changes++;
}

/*
 * routine:
 *	add_glob
 *
 * purpose:
 *	to evaluate a wild-carded expression into names, and add them
 *	to the evaluation list.
 *
 * parameters:
 *	base
 *	expression
 *
 * returns:
 * 	error mask
 *
 * notes:
 *	we don't want to allow any patterns to expand to a . because
 *	that could result in re-evaluation of a tree under a different
 *	name.  The real thing we are worried about here is ".*" which
 *	is meant to pick up . files, but shouldn't pick up . and ..
 */
static errmask_t
add_glob(struct base *bp, char *expr)
{	int i;
	errmask_t errs = 0;
#ifndef BROKEN_GLOB
	glob_t gt;
	char *s;

	/* expand the regular expression	*/
	i = glob(expr, GLOB_NOSORT, 0, &gt);
	if (i == GLOB_NOMATCH)
		return (ERR_MISSING);
	if (i) {
		/* this shouldn't happen, so it's cryptic message time	*/
		fprintf(stderr, "EVAL: add_glob globfail expr=%s, ret=%d\n",
				expr, i);
		return (ERR_OTHER);
	}

	for (i = 0; i < gt.gl_pathc; i++) {
		/* make sure we don't let anything expand to a . */
		s = basename(gt.gl_pathv[i]);
		if (strcmp(s, ".") == 0) {
			fprintf(stderr, gettext(WARN_ignore), gt.gl_pathv[i]);
			errs |= ERR_MISSING;
			continue;
		}

		errs |= add_file_arg(bp, gt.gl_pathv[i]);
	}

	globfree(&gt);
#else
	/*
	 * in 2.4 the glob function was completely broken.  The
	 * easiest way to get around this problem is to just ask
	 * the shell to do the work for us.  This is much slower
	 * but produces virtually identical results.  Given that
	 * the 2.4 version is internal use only, I probably won't
	 * worry about the performance difference (less than 2
	 * seconds for a typical filesync command, and no hit
	 * at all if they don't use regular expressions in
	 * their LIST rules).
	 */
	char cmdbuf[MAX_LINE];

	sprintf(cmdbuf, "ls -d %s 2> /dev/null", expr);
	errs |= add_run(bp, cmdbuf);
#endif

	return (errs);
}


/*
 * routine:
 *	add_run
 *
 * purpose:
 *	to run a command and capture the names it outputs in the
 *	evaluation list.
 *
 * parameters
 *	base
 *	command
 *
 * returns:
 *	error mask
 */
static errmask_t
add_run(struct base *bp, char *cmd)
{	char *s, *p;
	FILE *fp;
	char inbuf[ MAX_LINE ];
	errmask_t errs = 0;
	int added = 0;

	if (opt_debug & DBG_EVAL)
		fprintf(stderr, "EVAL: RUN %s\n", cmd);

	/* run the command and collect its ouput	*/
	fp = popen(cmd, "r");
	if (fp == NULL) {
		fprintf(stderr, gettext(ERR_badrun), cmd);
		return (ERR_OTHER);
	}

	while (fgets(inbuf, sizeof (inbuf), fp) != 0) {
		/* strip off any trailing newline	*/
		for (s = inbuf; *s && *s != '\n'; s++);
		*s = 0;

		/* skip any leading white space		*/
		for (s = inbuf; *s == ' ' || *s == '\t'; s++);

		/* make sure we don't let anything expand to a . */
		p = basename(s);
		if (strcmp(p, ".") == 0) {
			fprintf(stderr, gettext(WARN_ignore), s);
			errs |= ERR_MISSING;
			continue;
		}

		/* add this file to the list		*/
		if (*s) {
			errs |= add_file_arg(bp, s);
			added++;
		}
	}

	pclose(fp);

#ifdef	BROKEN_GLOB
	/*
	 * if we are being used to simulate libc glob, and we didn't
	 * return anything, we should probably assume that the regex
	 * was unable to match anything
	 */
	if (added == 0)
		errs |= ERR_MISSING;
#endif
	return (errs);
}
