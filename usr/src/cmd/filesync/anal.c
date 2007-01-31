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
 * Copyright (c) 1995 Sun Microsystems, Inc.  All Rights Reserved
 *
 * module:
 *	anal.c
 *
 * purpose:
 *	routines to analyze the file trees and figure out what has changed
 *	and queue files for reconciliation.  It also contains tree enumeration
 *	routines to for other purposes (pruning and link location).
 *
 * contents:
 *
 *  change analysis:
 *	analyze .... (top level) analyze all files in the tree for changes
 *	summary .... print out change/reconciliation statistics for each base
 *	check_file . (static) look for changes and queue file for reconciliation
 *	check_changes (static) figure out if a particular file has changed
 *	queue_file . (static) add a file to the reconciliation list
 *
 *  other tree enumeration functions:
 *	prune_file . (static) recursive descent and actual pruning
 *	prune ...... (top level) initiate pruning analysis for nonexistant files
 *	find_link .. look for other files to which a file may be a link
 *	link_update. propagate changed stat info to all other links
 *	same_name .. (static) figure out if two nodes describe same file
 *
 *  misc:
 *	push_name .. maintain a running full pathname as we descend
 *	pop_name ... maintain a running full pathname as we pop back
 *	get_name ... return full pathname for the current file
 *
 * notes:
 *	analysis is limited to files that were evaluated in the previous
 *	pass ... since we don't have complete information about files that
 *	were not evaluated in the previous pass.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include "messages.h"
#include "filesync.h"
#include "database.h"
#include "debug.h"

/*
 * routines:
 */
void push_name(const char *);
void pop_name();
char *get_name(struct file *);
static errmask_t check_file(struct file *fp);
static diffmask_t check_changes(struct file *fp, int first, int second);
static int prune_file(struct file *fp);
static void queue_file(struct file *fp);

/*
 * globals
 */
static struct file *changes;	/* list of files to be reconciled	*/

static long total_files;	/* total number of files being considered  */
static long est_deletes;	/* estimated number of files to be deleted */
static long est_rmdirs;		/* est rmdirs of non-empty directories	   */

int inum_changes;		/* LISTed directories whose I#s changed	   */

/*
 * routine:
 *	analyze
 *
 * purpose:
 *	top level routine for the analysis/reconciliation process
 *
 * parameters:
 *	none
 *
 * returns:
 *	error mask
 *
 * notes:
 *	a critical side effect of this routine is the creation of
 *	the reconciliation list, an ordered list of files that
 *	needed to be processed in the subsequent reconciliation pass
 */
errmask_t
analyze()
{	struct base *bp;
	struct file *fp;
	int errs = 0;
	int err;
	int percentage;
	bool_t aborted = FALSE;
	char msgbuf[MAX_LINE];

	/*
	 * run through all bases and directories looking for files
	 * that have been renamed.  This must be done before the
	 * difference analysis because a directory rename can introduce
	 * radical restructuring into a name-based tree.
	 */
	for (bp = bases; bp; bp = bp->b_next) {
		for (fp = bp->b_files; fp; fp = fp->f_next)
			if (fp->f_flags & F_EVALUATE)
				errs |= find_renames(fp);
	}

	/*
	 * run through all bases and files looking for candidates
	 * note, however that we only descend into trees that have
	 * the evaluate flag turned on.  As a result of new rules or
	 * restriction arguments, we may be deliberatly ignoring
	 * large amounts of the baseline.   This means we won't do
	 * any stats to update the information in those nodes, and
	 * they will be written back just as they were.
	 *
	 * note that there is code to prune out baseline nodes for
	 * files that no longer exist, but that code is in reconcile
	 * and will never get a chance to run on nodes that aren't
	 * analyzed.
	 *
	 * we also want to run though all nodes with STAT errors
	 * so that we can put them on the reconciliation list.
	 */
	for (bp = bases; bp; bp = bp->b_next) {
		for (fp = bp->b_files; fp; fp = fp->f_next)
			if (fp->f_flags & (F_EVALUATE|F_STAT_ERROR))
				errs |= check_file(fp);
	}

	/*
	 * my greatest fear is that someday, somehow, by messing with
	 * variables or baselines or who-knows-what, that someone will
	 * run a reconciliation against a large tree that doesn't correspond
	 * to the baseline, and I will infer that a bazillion files have
	 * been deleted and will propagate the slaughter before anyone
	 * can say somebody stop that maniac.
	 *
	 * in order to prevent such a possibility, we have a few different
	 * sanity checks.  There is, of course, a tradeoff here between
	 * danger and irritation.  The current set of heuristics for whether
	 * or not to generate a warning are (any of)
	 *
	 *	at least CONFIRM_MIN files have been deleted AND
	 *	CONFIRM_PCT of all files have been deleted
	 *
	 *	the inode number on a LISTed directory has changed
	 *
	 *	a non-empty directory has been deleted.
	 */
	msgbuf[0] = 0;

	percentage = (est_deletes * 100) / (total_files ? total_files : 1);
	if (est_deletes >= CONFIRM_MIN && percentage >= CONFIRM_PCT)
		sprintf(msgbuf, gettext(WARN_deletes), est_deletes);
	else if (inum_changes > 0)
		sprintf(msgbuf, gettext(WARN_ichange), inum_changes);
	else if (est_rmdirs)
		sprintf(msgbuf, gettext(WARN_rmdirs), est_rmdirs);

	if (msgbuf[0])
		confirm(msgbuf);

	/*
	 * TRICK:
	 *	the change list contains both files that have changed
	 *	(and probably warrant reconciliation) and files that
	 *	we couldn't get up-to-date stat information on.  The
	 *	latter files should just be flagged as being in conflict
	 *	so they can be reported in the summary.  The same is
	 *	true of all subsequent files if we abort reconciliation.
	 */
	for (fp = changes; fp; fp = fp->f_rnext)
		if (aborted || (fp->f_flags & F_STAT_ERROR)) {
			fp->f_flags |= F_CONFLICT;
			/* if it isn't in the baseline yet, don't add it */
			if ((fp->f_flags & F_IN_BASELINE) == 0)
				fp->f_flags |= F_REMOVE;
			fp->f_problem = aborted ? PROB_aborted : PROB_restat;
			(fp->f_base)->b_unresolved++;
			errs |= ERR_UNRESOLVED;
			if (opt_verbose)
				fprintf(stdout,
					gettext(aborted ? V_suppressed
							: V_nostat),
					fp->f_fullname);
		} else {
			err = reconcile(fp);
			errs |= err;
			if (opt_halt && (err & ERR_ABORT)) {
				fprintf(stderr, gettext(ERR_abort_h));
				aborted = TRUE;
			}
		}

	return (errs);
}

/*
 * routine:
 *	prune_file
 *
 * purpose:
 *	to look for file entries that should be pruned from baseline
 *	prune the current file if it needs pruning, and recursively
 *	descend if it is a directory.
 *
 * parameters:
 *	pointer to file node
 */
static int
prune_file(struct file *fp)
{	struct file *cp;
	int prunes = 0;

	/* if node hasn't been evaluated, mark it for removal	*/
	if ((fp->f_flags & (F_EVALUATE|F_STAT_ERROR)) == 0) {
		fp->f_flags |= F_REMOVE;
		prunes++;
		if (opt_debug & DBG_ANAL)
			fprintf(stderr, "ANAL: PRUNE %s\n", fp->f_name);
	}

	/* now check our children				*/
	for (cp = fp->f_files; cp; cp = cp->f_next)
		prunes += prune_file(cp);

	return (prunes);
}

/*
 * routine:
 *	prune
 *
 * purpose:
 *	to prune the baseline of entries that no longer correspond to
 *	existing rules.
 *
 * notes:
 *	This routine just calls prune_file on the top of each base tree.
 */
int
prune()
{	struct base *bp;
	struct file *fp;
	int prunes = 0;

	for (bp = bases; bp; bp = bp->b_next) {
		for (fp = bp->b_files; fp; fp = fp->f_next)
			prunes += prune_file(fp);

		if ((bp->b_flags & F_EVALUATE) == 0)
			bp->b_flags |= F_REMOVE;
	}

	return (prunes);
}

/*
 * routine:
 *	summary
 *
 * purpose:
 *	to print out statics and conflict lists
 */
void
summary()
{	struct base *bp;
	struct file *fp;
	extern bool_t need_super;

	(void) fflush(stdout);

	for (bp = bases; bp; bp = bp->b_next) {

		/* see if this base was irrelevant	*/
		if ((bp->b_flags & F_EVALUATE) == 0)
			continue;

		/* print out a summary for this base	*/
		fprintf(stderr, gettext(SUM_hd),
			bp->b_src_spec, bp->b_dst_spec, bp->b_totfiles);
		fprintf(stderr, gettext(SUM_dst),
			bp->b_dst_copies, bp->b_dst_deletes, bp->b_dst_misc);
		fprintf(stderr, gettext(SUM_src),
			bp->b_src_copies, bp->b_src_deletes, bp->b_src_misc);
		if (bp->b_unresolved)
			fprintf(stderr, gettext(SUM_unresolved),
				bp->b_unresolved);


		/* print out a list of unreconciled files for this base	*/
		for (fp = changes; fp; fp = fp->f_rnext) {
			if (fp->f_base != bp)
				continue;
			if ((fp->f_flags & F_CONFLICT) == 0)
				continue;
			fprintf(stderr, "\t\t%s (%s)\n", fp->f_fullname,
				fp->f_problem ? fp->f_problem : "???");
		}

		fprintf(stderr, "\n");
	}

	if (need_super)
		fprintf(stderr, gettext(WARN_super));
}

/*
 * routine:
 *	check_file
 *
 * purpose:
 *	figure out if a file requires reconciliation and recursively
 *	descend into all sub-files and directories
 *
 * parameters:
 *	base pointer
 *	file pointer
 *
 * returns:
 *	error mask
 *	built up changes needed list
 *	updated statistics
 *
 * notes:
 *	this routine builds up a path name as it descends through
 *	the tree (see push_name, pop_name, get_name).
 */
static errmask_t
check_file(struct file *fp)
{	struct file *cp;
	int errs = 0;

	if ((fp->f_flags & F_STAT_ERROR) == 0) {
		/* see if the source has changed	*/
		fp->f_info[OPT_BASE].f_modtime	= fp->f_s_modtime;
		fp->f_info[OPT_BASE].f_ino	= fp->f_s_inum;
		fp->f_info[OPT_BASE].f_d_maj	= fp->f_s_maj;
		fp->f_info[OPT_BASE].f_d_min	= fp->f_s_min;
		fp->f_info[OPT_BASE].f_nlink	= fp->f_s_nlink;
		fp->f_srcdiffs |= check_changes(fp, OPT_BASE, OPT_SRC);

		/* see if the destination has changed	*/
		fp->f_info[OPT_BASE].f_modtime	= fp->f_d_modtime;
		fp->f_info[OPT_BASE].f_ino    	= fp->f_d_inum;
		fp->f_info[OPT_BASE].f_d_maj    = fp->f_d_maj;
		fp->f_info[OPT_BASE].f_d_min    = fp->f_d_min;
		fp->f_info[OPT_BASE].f_nlink	= fp->f_d_nlink;
		fp->f_dstdiffs |= check_changes(fp, OPT_BASE, OPT_DST);

		/* if nobody thinks the file exists, baseline needs pruning */
		if ((fp->f_flags & (F_IN_SOURCE|F_IN_DEST)) == 0) {
			fp->f_srcdiffs |= D_DELETE;
			fp->f_dstdiffs |= D_DELETE;
		}

		/* keep track of possible deletions to look for trouble	*/
		if ((fp->f_dstdiffs | fp->f_srcdiffs) & D_DELETE) {
			est_deletes++;

			/* see if file is (or has been) a non-empty directory */
			if (fp->f_files)
				est_rmdirs++;
		}
	}

	/* if we found differences, queue the file for reconciliation 	*/
	if (fp->f_srcdiffs || fp->f_dstdiffs || fp->f_flags & F_STAT_ERROR) {
		queue_file(fp);

		if (opt_debug & DBG_ANAL) {
			fprintf(stderr, "ANAL: src=%s",
				showflags(diffmap, fp->f_srcdiffs));
			fprintf(stderr, " dst=%s",
				showflags(diffmap, fp->f_dstdiffs));
			fprintf(stderr, " flgs=%s",
				showflags(fileflags, fp->f_flags));
			fprintf(stderr, " name=%s\n", fp->f_fullname);
		}
	}

	/* bump the total file count	*/
	fp->f_base->b_totfiles++;
	total_files++;

	/* if this is not a directory, we're done	*/
	if (fp->f_files == 0)
		return (errs);

	/*
	 * If this is a directory, we need to recursively analyze
	 * our children, but only children who have been evaluated.
	 * If a node has not been evaluated, then we don't have
	 * updated stat information and there is nothing to analyze.
	 *
	 * we also want to run though all nodes with STAT errors
	 * so that we can put them on the reconciliation list.
	 * If a directory is unreadable on one side, all files
	 * under that directory (ON BOTH SIDES) must be marked as
	 * blocked by stat errors.
	 */
	push_name(fp->f_name);

	for (cp = fp->f_files; cp; cp = cp->f_next) {
		if (fp->f_flags & F_STAT_ERROR)
			cp->f_flags |= F_STAT_ERROR;
		if (cp->f_flags & (F_EVALUATE|F_STAT_ERROR))
			errs |= check_file(cp);
	}

	pop_name();

	return (errs);
}

/*
 * routine:
 *	check_changes
 *
 * purpose:
 *	to figure out what has changed for a specific file
 *
 * parameters:
 *	file pointer
 *	the reference info
 *	the info to be checked for changes
 *
 * returns:
 *	diff mask
 *
 * notes:
 *	this routine doesn't pretend to understand what happened.
 *	it merely enumerates the ways in which the files differ.
 */
static diffmask_t
check_changes(struct file *fp, int ref, int new)
{	struct fileinfo *rp, *np;
	int mask = 0;
	int type;

	rp = &fp->f_info[ref];
	np = &fp->f_info[new];

	if (np->f_uid != rp->f_uid)
		mask |= D_UID;

	if (np->f_gid != rp->f_gid)
		mask |= D_GID;

	if (np->f_mode != rp->f_mode)
		mask |= D_PROT;

	type = np->f_type;
	if (type != rp->f_type) {
		if (type == 0)
			mask |= D_DELETE;
		else if (rp->f_type == 0)
			mask |= D_CREATE;
		else
			mask |= D_TYPE;
	} else if (type == S_IFBLK || type == S_IFCHR) {
		/*
		 * for special files, we only look at the maj/min
		 */
		if (np->f_rd_maj != rp->f_rd_maj)
			mask |= D_SIZE;
		if (np->f_rd_min != rp->f_rd_min)
			mask |= D_SIZE;
	} else if (type != S_IFDIR) {
		/*
		 * for directories, we don't look directly at
		 * the contents, so these fields don't mean
		 * anything.  If the directories have changed
		 * in any interesting way, we'll find it by
		 * walking the tree.
		 */
		if (np->f_modtime > rp->f_modtime)
			mask |= D_MTIME;

		if (np->f_size != rp->f_size)
			mask |= D_SIZE;

		if (np->f_nlink != rp->f_nlink)
			mask |= D_LINKS;
	}

	if (cmp_acls(rp, np) == 0)
		mask |= D_FACLS;

	return (mask);
}

/*
 * routine:
 *	same_name
 *
 * purpose:
 *	to figure out whether or not two databsae nodes actually refer to
 *	the same file.
 *
 * parameters:
 *	pointers to two file description nodes
 *	which side we should check
 *
 * returns:
 *	TRUE/FALSE
 *
 * notes:
 *	if a single directory is specified in multiple base pairs, it
 *	is possible to have multiple nodes in the database describing
 *	the same file.  This routine is supposed to detect those cases.
 *
 *	what should be a trivial string comparison is complicated by
 *	the possibility that the two nodes might describe the same file
 *	from base directories at different depths.  Thus, rather than
 *	comparing two strings, we really want to compare the concatenation
 *	of two pairs of strings.  Unfortunately calling full_name would
 *	be awkward right now, so instead we have our own comparison
 *	routine that automatically skips from the first string to
 *	the second.
 */
static bool_t
same_name(struct file *f1, struct file *f2, side_t srcdst)
{
	char *s1, *s2, *x1, *x2;

	if (srcdst == OPT_SRC) {
		s1 = (f1->f_base)->b_src_name;
		s2 = (f2->f_base)->b_src_name;
	} else {
		s1 = (f1->f_base)->b_dst_name;
		s2 = (f2->f_base)->b_dst_name;
	}
	x1 = f1->f_fullname;
	x2 = f2->f_fullname;

	/*
	 * Compare the two names, and if they differ before they end
	 * this is a non-match.  If they both end at the same time,
	 * this is a match.
	 *
	 * The trick here is that each string is actually the logical
	 * concatenation of two strings, and we need to automatically
	 * wrap from the first to the second string in each pair.  There
	 * is no requirement that the two (concatenated) strings be
	 * broken at the same point, so we have a slightly baroque
	 * comparsion loop.
	 */
	while (*s1 && *s1 == *s2) {

		/*
		 * strings have been identical so far, so advance the
		 * pointers and continue the comparison.  The trick
		 * is that when either string ends, we have to wrap
		 * over to its extension.
		 */
		s1++; s2++;
		if (*s1 && *s2)
			continue;

		/*
		 * at least one of the strings has ended.
		 * there is an implicit slash between the string
		 * and its extension, and this has to be matched
		 * against the other string.
		 */
		if (*s1 != *s2) {
			if (*s1 == 0 && *s2 == '/')
				s2++;
			else if (*s2 == 0 && *s1 == '/')
				s1++;
			else
				/* the disagreement doesn't come at a slash */
				break;
		}

		/*
		 * if either string has ended, wrap to its extension
		 */
		if (*s1 == 0 && x1 != 0) {
			s1 = x1;
			x1 = 0;
		}
		if (*s2 == 0 && x2 != 0) {
			s2 = x2;
			x2 = 0;
		}
	}

	return (*s1 == *s2);
}

/*
 * routine:
 *	find_link
 *
 * purpose:
 *	to figure out if there is a file to which we should
 *	be creating a link (rather than making a copy)
 *
 * parameters:
 *	file node for the file to be created (that we hope is merely a link)
 *	which side is to be changed (src/dst)
 *
 * return:
 *	0	no link is appropriate
 *	else	pointer to file node for link referent
 *
 * notes:
 *	there are a few strange heuristics in this routine and I
 *	wouldn't bet my soul that I got all of them right.  The general
 *	theory is that when a new file is created, we look to see if it
 *	is a link to another file on the changed side, and if it is, we
 *	find the corresponding file on the unchanged side.
 *
 *	cases we want to be able to handle:
 *	    1.	one or more links are created to a prexisting file
 *	    2.	a preexisting only link is renamed
 *	    3.  a rename of one of multiple links to a preexisting file
 *	    4.	a single file is created with multiple links
 */
struct file *
find_link(struct file *fp, side_t srcdst)
{	struct file *lp;
	side_t chgside, tgtside;
	struct fileinfo *chgp, *tgtp, *basp, *fcp, *ftp;

	/* chg = side on which the change was noticed		*/
	/* tgt = side to which the change is to be propagated	*/
	chgside = (srcdst == OPT_SRC) ? OPT_DST : OPT_SRC;
	tgtside = (srcdst == OPT_SRC) ? OPT_SRC : OPT_DST;
	fcp = &fp->f_info[chgside];
	ftp = &fp->f_info[tgtside];

	/*
	 * cases 1 and 3
	 *
	 * When a new link is created, we should be able to find
	 * another file in the changed hierarchy that has the same
	 * I-node number.  We expect it to be on the changed list
	 * because the link count will have gone up or because all
	 * of the copies are new.  If we find one, then the new file
	 * on the receiving file should be a link to the corresponding
	 * existing file.
	 *
	 * case 4
	 *
	 * the first link will be dealt with as a copy, but all
	 * subsequent links should find an existing file analogous
	 * to one of the links on the changed side, and create
	 * corresponding links on the other side.
	 *
	 * in each of these cases, there should be multiple links
	 * on the changed side.  If the linkcount on the changed
	 * side is one, we needn't bother searching for other links.
	 */
	if (fcp->f_nlink > 1)
	for (lp = changes; lp; lp = lp->f_rnext) {
		/* finding the same node doesn't count	*/
		if (fp == lp)
			continue;

		tgtp = &lp->f_info[tgtside];
		chgp = &lp->f_info[chgside];

		/*
		 * if the file doesn't already exist on the target side
		 * we cannot make a link to it
		 */
		if (tgtp->f_mode == 0)
			continue;

		/*
		 * if this is indeed a link, then the prospective file on
		 * the changed side will have the same dev/inum as the file
		 * we are looking for
		 */
		if (fcp->f_d_maj != chgp->f_d_maj)
			continue;
		if (fcp->f_d_min != chgp->f_d_min)
			continue;
		if (fcp->f_ino != chgp->f_ino)
			continue;

		/*
		 * if the target side is already a link to this file,
		 * then there is no new link to be created
		 * FIX: how does this interact with copies over links
		 */
		if ((ftp->f_d_maj == tgtp->f_d_maj) &&
		    (ftp->f_d_min == tgtp->f_d_min) &&
		    (ftp->f_ino   == tgtp->f_ino))
			continue;

		/*
		 * there is a pathological situation where a single file
		 * might appear under multiple base directories.  This is
		 * damned awkward to detect in any other way, so we must
		 * check to see if we have just found another database
		 * instance for the same file (on the changed side).
		 */
		if ((fp->f_base != lp->f_base) && same_name(fp, lp, chgside))
			continue;

		if (opt_debug & DBG_ANAL)
			fprintf(stderr, "ANAL: FIND LINK %s and %s\n",
				fp->f_fullname, lp->f_fullname);

		return (lp);
	}

	/*
	 * case 2: a simple rename of the only link
	 *
	 * In this case, there may not be any other existing file on
	 * the changed side that has the same I-node number.  There
	 * might, however, be a record of such a file in the baseline.
	 * If we can find an identical file with a different name that
	 * has recently disappeared, we have a likely rename.
	 */
	for (lp = changes; lp; lp = lp->f_rnext) {

		/* finding the same node doesn't count			*/
		if (fp == lp)
			continue;

		tgtp = &lp->f_info[tgtside];
		chgp = &lp->f_info[chgside];

		/*
		 * if the file still exists on the changed side this is
		 * not a simple rename, and in fact the previous pass
		 * would have found it.
		 */
		if (chgp->f_mode != 0)
			continue;

		/*
		 * the inode number for the new link on the changed
		 * side must match the inode number for the old link
		 * from the baseline.
		 */
		if (fcp->f_d_maj != ((srcdst == OPT_SRC) ? lp->f_d_maj
							: lp->f_s_maj))
			continue;
		if (fcp->f_d_min != ((srcdst == OPT_SRC) ? lp->f_d_min
							: lp->f_s_min))
			continue;
		if (fcp->f_ino != ((srcdst == OPT_SRC) ? lp->f_d_inum
							: lp->f_s_inum))
			continue;

		/* finding a file we are already linked to doesn't help	*/
		if ((ftp->f_d_maj == tgtp->f_d_maj) &&
		    (ftp->f_d_min == tgtp->f_d_min) &&
		    (ftp->f_ino   == tgtp->f_ino))
			continue;

		/*
		 * there is a danger that we will confuse an
		 * inode reallocation with a rename.  We should
		 * only consider this to be a rename if the
		 * new file is identical to the old one
		 */
		basp = &lp->f_info[OPT_BASE];
		if (fcp->f_type != basp->f_type)
			continue;
		if (fcp->f_size != basp->f_size)
			continue;
		if (fcp->f_mode != basp->f_mode)
			continue;
		if (fcp->f_uid != basp->f_uid)
			continue;
		if (fcp->f_gid != basp->f_gid)
			continue;

		if (opt_debug & DBG_ANAL)
			fprintf(stderr, "ANAL: FIND RENAME %s and %s\n",
				fp->f_fullname, lp->f_fullname);

		return (lp);
	}

	return (0);
}

/*
 * routine:
 *	has_other_links
 *
 * purpose:
 *	to determine whether or not there is more that one link to a
 *	particular file.  We are willing to delete a link to a file
 *	that has changed if we will still have other links to it.
 *	The trick here is that we only care about links under our
 *	dominion.
 *
 * parameters:
 *	file pointer to node we are interested in
 *	which side we are looking to additional links on
 *
 * returns:
 *	TRUE if there are multiple links
 *	FALSE if this is the only one we know of
 */
bool_t
has_other_links(struct file *fp, side_t srcdst)
{	struct file *lp;
	struct fileinfo *fip, *lip;

	fip = &fp->f_info[srcdst];

	/* if the link count is one, there couldn't be others	*/
	if (fip->f_nlink < 2)
		return (FALSE);

	/* look for any other files for the same inode		*/
	for (lp = changes; lp; lp = lp->f_rnext) {
		/* finding the same node doesn't count	*/
		if (fp == lp)
			continue;

		lip = &lp->f_info[srcdst];

		/*
		 * file must still exist on this side
		 */
		if (lip->f_mode == 0)
			continue;

		/*
		 * if this is indeed a link, then the prospective file on
		 * the changed side will have the same dev/inum as the file
		 * we are looking for
		 */
		if (lip->f_d_maj != fip->f_d_maj)
			continue;
		if (lip->f_d_min != fip->f_d_min)
			continue;
		if (lip->f_ino != fip->f_ino)
			continue;

		/*
		 * we have found at least one other link
		 */
		return (TRUE);
	}

	return (FALSE);
}

/*
 * routine:
 *	link_update
 *
 * purpose:
 *	to propoagate a stat change to all other file nodes that
 *	correspond to the same I-node on the changed side
 *
 * parameters:
 *	file pointer for the updated file
 *	which side was changed
 *
 * returns:
 *	void
 *
 * notes:
 *	if we have copied onto a file, we have copied onto all
 *	of its links, but since we do all stats before we do any
 *	copies, the stat information recently collected for links
 *	is no longer up-to-date, and this would result in incorrect
 *	reconciliation (redundant copies).
 *
 *	There is an assumption here that all links to a changed
 *	file will be in the change list.  This is true for almost
 *	all cases not involving restriction.  If we do fail to
 *	update the baseline for a file that was off the change list,
 *	the worst that is likely to happen is that we will think
 *	it changed later (but will almost surely find that both
 *	copies agree).
 */
void
link_update(struct file *fp, side_t which)
{	struct file *lp;

	for (lp = changes; lp; lp = lp->f_rnext) {
		/* finding the current entry doesn't count	*/
		if (lp == fp)
			continue;

		/* look for same i#, maj, min on changed side	*/
		if (lp->f_info[which].f_ino != fp->f_info[which].f_ino)
			continue;
		if (lp->f_info[which].f_d_maj != fp->f_info[which].f_d_maj)
			continue;
		if (lp->f_info[which].f_d_min != fp->f_info[which].f_d_min)
			continue;

		/*
		 * this appears to be another link to the same file
		 * so the updated stat information for one must be
		 * correct for the other.
		 */
		lp->f_info[which].f_type	= fp->f_info[which].f_type;
		lp->f_info[which].f_size	= fp->f_info[which].f_size;
		lp->f_info[which].f_mode	= fp->f_info[which].f_mode;
		lp->f_info[which].f_uid		= fp->f_info[which].f_uid;
		lp->f_info[which].f_gid		= fp->f_info[which].f_gid;
		lp->f_info[which].f_modtime	= fp->f_info[which].f_modtime;
		lp->f_info[which].f_modns	= fp->f_info[which].f_modns;
		lp->f_info[which].f_nlink	= fp->f_info[which].f_nlink;
		lp->f_info[which].f_rd_maj	= fp->f_info[which].f_rd_maj;
		lp->f_info[which].f_rd_min	= fp->f_info[which].f_rd_min;

		if (opt_debug & DBG_STAT)
			fprintf(stderr,
				"STAT: UPDATE LINK, file=%s, mod=%08lx.%08lx\n",
				lp->f_name, lp->f_info[which].f_modtime,
				lp->f_info[which].f_modns);
	}
}

/*
 * routine:
 *	queue_file
 *
 * purpose:
 *	append a file to the list of needed reconciliations
 *
 * parameters:
 *	pointer to file
 *
 * notes:
 *	when a request is appended to the reconciliation list,
 *	we fill in the full name.  We delayed this in hopes that
 *	it wouldn't be necessary (saving cycles and memory)
 *
 *	There is some funny business with modification times.
 *	In general, we queue files in order of the latest modification
 *	time so that propagations preserve relative ordering.  There
 *	are, however, a few important exceptions:
 *	    1.	all directory creations happen at time zero,
 *		so that they are created before any files can
 *		be added to them.
 *	    2.	all directory deletions happen at time infinity-depth,
 *		so that everything else can be removed before the
 *		directories themselves are removed.
 *	    3.	all file deletions happen at time infinity-depth
 *		so that (in renames) the links will preceed the unlinks.
 */
static void
queue_file(struct file *fp)
{	struct file **pp, *np;

#define	TIME_ZERO	0L		/* the earliest possible time	*/
#define	TIME_LONG	0x7FFFFFFF	/* the latest possible time	*/

	/*
	 * figure out the modification time for sequencing purposes
	 */
	if ((fp->f_srcdiffs|fp->f_dstdiffs) & D_DELETE) {
		/*
		 * deletions are performed last, and depth first
		 */
		fp->f_modtime = TIME_LONG - fp->f_depth;
	} else if (fp->f_info[OPT_SRC].f_type != S_IFDIR &&
	    fp->f_info[OPT_DST].f_type != S_IFDIR) {
		/*
		 * for most files we use the latest mod time
		 */
		fp->f_modtime = fp->f_info[OPT_SRC].f_modtime;
		fp->f_modns   = fp->f_info[OPT_SRC].f_modns;
		if (fp->f_modtime < fp->f_info[OPT_DST].f_modtime) {
			fp->f_modtime = fp->f_info[OPT_DST].f_modtime;
			fp->f_modns   = fp->f_info[OPT_DST].f_modns;
		}
	} else {
		/*
		 * new directory creations need to happen before anything
		 * else and are automatically sequenced in traversal order
		 */
		fp->f_modtime = TIME_ZERO;
	}

	/*
	 * insertion is time ordered, and for equal times,
	 * insertions is in (pre-order) traversal order
	 */
	for (pp = &changes; (np = *pp) != 0; pp = &np->f_rnext) {
		if (fp->f_modtime > np->f_modtime)
			continue;
		if (fp->f_modtime < np->f_modtime)
			break;
		if (fp->f_modns < np->f_modns)
			break;
	}

	fp->f_fullname = strdup(get_name(fp));
	fp->f_rnext = np;
	*pp = fp;
}


/*
 * routines:
 *	push_name/pop_name/get_name
 *
 * purpose:
 *	maintain a name stack so we can form name of a particular file
 *	as the concatenation of all of the names between it and the
 *	(know to be fully qualified) base directory.
 *
 * notes:
 *	we go to this trouble because most files never change and
 *	so we don't need to associate full names with every one.
 *	This stack is maintained during analysis, and if we decide
 *	to add a file to the reconciliation list, we can use the
 *	stack to generate a fully qualified name at that time.
 *
 *	we compress out '/./' when we return a name.  Given that the
 *	stack was built by a tree walk, the only place a /./ should
 *	appear is at the first level after the base ... but there
 *	are legitimate ways for them to appear there.
 *
 *	these names can get deep, so we dynamically size our name buffer
 */
static const char *namestack[ MAX_DEPTH + 1 ];
static int namedepth = 0;
static int namelen = 0;

void
push_name(const char *name)
{
	namestack[ namedepth++ ] = name;
	namelen += 2 + strlen(name);

	/* make sure we don't overflow our name stack	*/
	if (namedepth >= MAX_DEPTH) {
		fprintf(stderr, gettext(ERR_deep), name);
		exit(ERR_OTHER);
	}
}

void
pop_name(void)
{
	namelen -= 2 + strlen(namestack[--namedepth]);
	namestack[ namedepth ] = 0;

#ifdef	DBG_ERRORS
	/* just a little sanity check here	*/
	if (namedepth <= 0) {
		if (namedepth < 0) {
			fprintf(stderr, "ASSERTION FAILURE: namedepth < 0\n");
			exit(ERR_OTHER);
		} else if (namelen != 0) {
			fprintf(stderr, "ASSERTION FAILURE: namelen != 0\n");
			exit(ERR_OTHER);
		}
	}
#endif
}

char
*get_name(struct file *fp)
{	int i;
	static char *namebuf = 0;
	static int buflen = 0;

	/* make sure we have an adequate buffer	*/
	i = namelen + 1 + strlen(fp->f_name);
	if (buflen < i) {
		for (buflen = MAX_PATH; buflen < i; buflen += MAX_NAME);
		namebuf = (char *) realloc(namebuf, buflen);
	}

	/* assemble the name	*/
	namebuf[0] = 0;
	for (i = 0; i < namedepth; i++) {
		if (strcmp(namestack[i], ".")) {
			strcat(namebuf, namestack[i]);
			strcat(namebuf, "/");
		}
	}

	strcat(namebuf, fp->f_name);

	return (namebuf);
}
