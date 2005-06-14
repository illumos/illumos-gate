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
 *	recon.c
 *
 * purpose:
 *	process the reconciliation list, figure out exactly what the
 *	changes were, and what we should do about them.
 *
 * contents:
 *	reconcile ... (top level) process the reconciliation list
 *	samedata .... (static) do two files have the same contents
 *	samestuff ... (static) do two files have the same ownership/protection
 *	samecompare . (static) actually read and compare the contents
 *	samelink .... (static) do two symlinks have the same contents
 *	truncated ... (static) was one of the two copies truncted
 *	older ....... (static) which copy is older
 *	newer ....... (static) which copy is newer
 *	full_name ... generate a full path name for a file
 *
 * notes:
 *	If you only study one routine in this whole program, reconcile
 *	is that routine.  Everything else is just book keeping.
 *
 *	things were put onto the reconciliation list because analyze
 *	thought that they might have changed ... but up until now
 *	nobody has figured out what the changes really were, or even
 *	if there really were any changes.
 *
 *	queue_file has ordered the reconciliation list with directory
 *	creations first (depth ordered) and deletions last (inversely
 *	depth ordered).  all other changes have been ordered by mod time.
 */
#ident	"%W%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "filesync.h"
#include "database.h"
#include "messages.h"
#include "debug.h"

/*
 * local routines to figure out how the files really differ
 */
static bool_t samedata(struct file *);
static bool_t samestuff(struct file *);
static bool_t samecompare(struct file *);
static bool_t truncated(struct file *);
static bool_t samelink();
static side_t newer(struct file *);
static side_t older(struct file *);

/*
 * globals
 */
char	*srcname;	/* file we are emulating		*/
char	*dstname;	/* file we are updating			*/

/*
 * routine:
 *	reconcile
 *
 * purpose:
 *	to perform the reconciliation action associated with a file
 *
 * parameters:
 *	file pointer
 *
 * returns:
 *	built up error mask
 *	updated statistics
 *
 * notes:
 *	The switch statement handles the obvious stuff.
 *	The TRUE side of the samedata test handles minor differences.
 *	The interesting stuff is in the FALSE side of the samedata test.
 *
 *	The desparation heuristics (in the diffmask&CONTENTS test) are
 *	not rigorously correct ... but they always try do the right thing
 *	with data, and only lose mode/ownership changes in relatively
 *	pathological cases.  But I claim that the benefits outweigh the
 *	risks, and most users will be pleased with the resulting decisions.
 *
 *	Another trick is in the deletion cases of the switch.  We
 *	normally won't allow an unlink that conflicts with data
 *	changes.  If there are multiple links to the file, however,
 * 	we can make the changes and do the deletion.
 *
 *	The action routines do_{remove,rename,like,copy} handle all
 *	of their own statistics and status updating.  This routine
 *	only has to handle its own reconciliation failures (when we
 *	can't decide what to do).
 */
errmask_t
reconcile(struct file *fp)
{	errmask_t errs = 0;
	diffmask_t diffmask;

	if (opt_debug & DBG_RECON)
		fprintf(stderr, "RECO: %s flgs=%s, mtime=%08lx.%08lx\n",
			fp->f_fullname,
			showflags(fileflags, fp->f_flags),
			fp->f_modtime, fp->f_modns);

	/*
	 * form the fully qualified names for both files
	 */
	srcname = full_name(fp, OPT_SRC, OPT_SRC);
	dstname = full_name(fp, OPT_DST, OPT_DST);

	/*
	 * because they are so expensive to read and so troublesome
	 * to set, we try to put off reading ACLs as long as possible.
	 * If we haven't read them yet, we must read them now (so that
	 * samestuff can compare them).
	 */
	if (opt_acls == 0 && fp->f_info[ OPT_BASE ].f_numacls == 0) {
		if (get_acls(srcname, &fp->f_info[ OPT_SRC ]))
			fp->f_srcdiffs |= D_FACLS;
		if (get_acls(dstname, &fp->f_info[ OPT_DST ]))
			fp->f_dstdiffs |= D_FACLS;
	}

	/*
	 * If a rename has been detected, we don't have to figure
	 * it out, since both the rename-to and rename-from files
	 * have already been designated.  When we encounter a rename-to
	 * we should carry it out.  When we encounter a rename-from
	 * we can ignore it, since it should be dealt with as a side
	 * effect of processing the rename-to.
	 */
	if ((fp->f_srcdiffs|fp->f_dstdiffs) & D_RENAME_FROM)
		return (0);

	if ((fp->f_srcdiffs|fp->f_dstdiffs) & D_RENAME_TO) {

		if (opt_verbose)
			fprintf(stdout, gettext(V_renamed),
				fp->f_previous->f_fullname, fp->f_name);

		if (fp->f_srcdiffs & D_RENAME_TO) {
			errs = do_rename(fp, OPT_DST);
			fp->f_srcdiffs &= D_MTIME | D_SIZE;
		} else if (fp->f_dstdiffs & D_RENAME_TO) {
			errs = do_rename(fp, OPT_SRC);
			fp->f_dstdiffs &= D_MTIME | D_SIZE;
		}

		if (errs != ERR_RESOLVABLE)
			goto done;

		/*
		 * if any differences remain, then we may be dealing
		 * with contents changes in addition to a rename
		 */
		if ((fp->f_srcdiffs | fp->f_dstdiffs) == 0)
			goto done;

		/*
		 * fall through to reconcile the data changes
		 */
	}

	/*
	 * pull of the easy cases (non-conflict creations & deletions)
	 */
	switch (fp->f_flags & (F_WHEREFOUND)) {
		case F_IN_BASELINE:	/* only exists in baseline	*/
		case 0:			/* only exists in rules		*/
			if (opt_verbose)
				fprintf(stdout, gettext(V_nomore),
					fp->f_fullname);
			fp->f_flags |= F_REMOVE;	/* fix baseline	*/
			return (0);

		case F_IN_BASELINE|F_IN_SOURCE:	/* deleted from dest	*/
			/*
			 * the basic principle here is that we are willing
			 * to do the deletion if:
			 *	no changes were made on the other side
			 * OR
			 *	we have been told to force in this direction
			 *
			 * we do, however, make an exception for files that
			 * will still have other links.  In this case, the
			 * (changed) data will still be accessable through
			 * another link and so we are willing to do the unlink
			 * inspite of conflicting changes (which may well
			 * have been introduced through another link.
			 *
			 * The jury is still out on this one
			 */
			if (((fp->f_srcdiffs&D_IMPORTANT) == 0) ||
				(opt_force == OPT_DST)		||
				has_other_links(fp, OPT_SRC)) {
				if (opt_verbose)
					fprintf(stdout, gettext(V_deleted),
						fp->f_fullname, "dst");
				errs = do_remove(fp, OPT_SRC);
				goto done;
			}

			/* a deletion combined with changes		*/
			if (opt_verbose)
				fprintf(stdout, gettext(V_delconf),
					fp->f_fullname);

			/* if we are to resolve in favor of source	*/
			if (opt_force == OPT_SRC) {
				errs = do_copy(fp, OPT_DST);
				goto done;
			}

			fp->f_problem = gettext(PROB_del_change);
			goto cant;

		case F_IN_BASELINE|F_IN_DEST:	/* deleted from src	*/
			/* just like previous case, w/sides reversed	*/
			if (((fp->f_dstdiffs&D_IMPORTANT) == 0) ||
				(opt_force == OPT_SRC)		||
				has_other_links(fp, OPT_DST)) {
				if (opt_verbose)
					fprintf(stdout, gettext(V_deleted),
						fp->f_fullname, "src");
				errs = do_remove(fp, OPT_DST);
				goto done;
			}

			/* a deletion combined with changes		*/
			if (opt_verbose)
				fprintf(stdout, gettext(V_delconf),
					fp->f_fullname);

			/* if we are to resolve in favor of destination	*/
			if (opt_force == OPT_DST) {
				errs = do_copy(fp, OPT_SRC);
				goto done;
			}

			fp->f_problem = gettext(PROB_del_change);
			goto cant;

		/*
		 * if something new shows up, and for some reason we cannot
		 * propagate it to the other side, we should suppress the
		 * file from the baseline, so it will show up as a new
		 * creation next time too.
		 */
		case F_IN_SOURCE:		/* created in src	*/
			if (opt_verbose)
				fprintf(stdout, gettext(V_created),
					fp->f_fullname, "src");
			errs = do_copy(fp, OPT_DST);
			goto done;

		case F_IN_DEST:			/* created in dest	*/
			if (opt_verbose)
				fprintf(stdout, gettext(V_created),
					fp->f_fullname, "dst");
			errs = do_copy(fp, OPT_SRC);
			goto done;

		case F_IN_SOURCE|F_IN_DEST:	/* not in baseline	*/
			/*
			 * since we don't have a baseline, we cannot
			 * know which of the two copies should prevail
			 */
			break;

		case F_IN_BASELINE|F_IN_SOURCE|F_IN_DEST:
			/*
			 * we have a baseline where the two copies agreed,
			 * so maybe we can determine that only one of the
			 * two copies have changed ... but before we decide
			 * who should be the winner we should determine
			 * that the two copies are actually different.
			 */
			break;
	}

	/*
	 * if we have fallen out of the case statement, it is because
	 * we have discovered a non-obvious situation where potentially
	 * changed versions of the file exist on both sides.
	 *
	 * if the two copies turn out to be identical, this is simple
	 */
	if (samedata(fp)) {
		if (samestuff(fp)) {
			/* files are identical, just update baseline	*/
			if (opt_verbose)
				fprintf(stdout, gettext(V_unchanged),
					fp->f_fullname);
			update_info(fp, OPT_SRC);
			goto done;
		} else {
			/*
			 * contents agree but ownership/protection does
			 * not agree, so we have to bring these into
			 * agreement.  We can pick a winner if one
			 * side hasn't changed, or if the user has
			 * specified a force flag.
			 */
			if (opt_verbose)
				fprintf(stdout, gettext(V_modes),
					fp->f_fullname);

			if (((fp->f_srcdiffs & D_ADMIN) == 0) ||
					(opt_force == OPT_DST)) {
				errs = do_like(fp, OPT_SRC, TRUE);
				goto done;
			}

			if (((fp->f_dstdiffs & D_ADMIN) == 0) ||
					(opt_force == OPT_SRC)) {
				errs = do_like(fp, OPT_DST, TRUE);
				goto done;
			}
		}
		/* falls down to cant	*/
	} else {
		/*
		 * The two files have different contents, so we have
		 * a potential conflict here.  If we know that only one
		 * side has changed, we go with that side.
		 */
		if (fp->f_dstdiffs == 0 || fp->f_srcdiffs == 0) {
			if (opt_verbose)
				fprintf(stdout, gettext(V_changed),
					fp->f_fullname);
			errs = do_copy(fp, fp->f_srcdiffs ? OPT_DST : OPT_SRC);
			goto done;
		}

		/*
		 * Both sides have changed, so we have a real conflict.
		 */
		if (opt_verbose)
			fprintf(stdout,
				gettext(truncated(fp) ?
						V_trunconf : V_different),
				fp->f_fullname);

		/*
		 * See if the user has given us explicit instructions
		 * on how to resolve conflicts.  We may have been told
		 * to favor the older, the newer, the source, or the
		 * destination ... but the default is to leave the
		 * conflict unresolved.
		 */
		if (opt_force == OPT_OLD) {
			errs = do_copy(fp, newer(fp));
			goto done;
		}

		if (opt_force == OPT_NEW) {
			errs = do_copy(fp, older(fp));
			goto done;
		}

		if (opt_force != 0) {
			errs = do_copy(fp, (opt_force == OPT_SRC) ?
							OPT_DST : OPT_SRC);
			goto done;
		}


		/*
		 * This is our last chance before giving up.
		 *
		 * We know that the files have different contents and
		 * that there were changes on both sides.  The only way
		 * we can safely handle this is if there were pure contents
		 * changes on one side and pure ownership changes on the
		 * other side.  In this case we can propagate the ownership
		 * one way and the contents the other way.
		 *
		 * We decide whether or not this is possible by ANDing
		 * together the changes on the two sides, and seeing
		 * if the changes were all orthogonal (none of the same
		 * things changed on both sides).
		 */
		diffmask = fp->f_srcdiffs & fp->f_dstdiffs;
		if ((diffmask & D_CONTENTS) == 0) {
			/*
			 * if ownership changes were only made on one side
			 * (presumably the side that didn't have data changes)
			 * we can handle them separately.  In this case,
			 * ownership changes must be fixed first, because
			 * the subsequent do_copy will overwrite them.
			 */
			if ((diffmask & D_ADMIN) == 0)
				errs |= do_like(fp, (fp->f_srcdiffs&D_ADMIN) ?
							OPT_DST : OPT_SRC,
						TRUE);

			/*
			 * Now we can deal with the propagation of the data
			 * changes.  Note that any ownership/protection
			 * changes (from the other side) that have not been
			 * propagated yet are about to be lost.  The cases
			 * in which this might happen are all pathological
			 * and the consequences of losing the protection
			 * changes are (IMHO) minor when compared to the
			 * obviously correct data propagation.
			 */
			errs |= do_copy(fp, (fp->f_srcdiffs&D_CONTENTS) ?
						OPT_DST : OPT_SRC);
			goto done;
		}

		/*
		 * there are conflicting changes, nobody has told us how to
		 * resolve conflicts, and we cannot figure out how to merge
		 * the differences.
		 */
		fp->f_problem = gettext(PROB_different);
	}

cant:
	/*
	 * I'm not smart enough to resolve this conflict automatically,
	 * so I have no choice but to bounce it back to the user.
	 */
	fp->f_flags |= F_CONFLICT;
	fp->f_base->b_unresolved++;
	errs |= ERR_UNRESOLVED;

done:
	/*
	 * if we have a conflict and the file is not in the baseline,
	 * then there was never any point at which the two copies were
	 * in agreement, and we want to preserve the conflict for future
	 * resolution.
	 */
	if ((errs&ERR_UNRESOLVED) && (fp->f_flags & F_IN_BASELINE) == 0)
		if (fp->f_files == 0)
			/*
			 * in most cases, this is most easily done by just
			 * excluding the file in question from the baseline
			 */
			fp->f_flags |= F_REMOVE;
		else
			/*
			 * but ... if the file in question is a directory
			 * with children, excluding it from the baseline
			 * would keep all of its children (even those with
			 * no conflicts) out of the baseline as well.  In
			 * This case, it is better to tell a lie and to
			 * manufacture a point of imaginary agreement
			 * in the baseline ... but one that is absurd enough
			 * that we will still see conflicts each time we run.
			 *
			 * recording a type of directory, and everything
			 * else as zero should be absurd enough.
			 */
			fp->f_info[ OPT_BASE ].f_type = S_IFDIR;

	if (opt_debug & DBG_MISC)
		fprintf(stderr, "MISC: %s ERRS=%s\n", fp->f_fullname,
			showflags(errmap, errs));

	return (errs);
}

/*
 * routine:
 *	newer
 *
 * purpose:
 *	determine which of two files is newer
 *
 * parameters:
 *	struct file
 *
 * returns:
 *	side_t (src/dest)
 */
static side_t
newer(struct file *fp)
{
	struct fileinfo *sp, *dp;

	sp = &fp->f_info[OPT_SRC];
	dp = &fp->f_info[OPT_DST];

	if (sp->f_modtime > dp->f_modtime)
		return (OPT_SRC);

	if (sp->f_modtime < dp->f_modtime)
		return (OPT_DST);

	if (sp->f_modns >= dp->f_modns)
		return (OPT_SRC);

	return (OPT_DST);
}

/*
 * routine:
 *	older
 *
 * purpose:
 *	determine which of two files is older
 *
 * parameters:
 *	struct file
 *
 * returns:
 *	side_t (src/dest)
 */
static side_t
older(struct file *fp)
{
	struct fileinfo *sp, *dp;

	sp = &fp->f_info[OPT_SRC];
	dp = &fp->f_info[OPT_DST];

	if (sp->f_modtime < dp->f_modtime)
		return (OPT_SRC);

	if (sp->f_modtime > dp->f_modtime)
		return (OPT_DST);

	if (sp->f_modns <= dp->f_modns)
		return (OPT_SRC);

	return (OPT_DST);
}

/*
 * routine:
 *	samedata
 *
 * purpose:
 *	determine whether or not two files contain the same data
 *
 * parameters:
 *	struct file
 *
 * returns:
 *	bool_t (true/false)
 */
static bool_t
samedata(struct file *fp)
{
	struct fileinfo *sp, *dp;

	sp = &fp->f_info[OPT_SRC];
	dp = &fp->f_info[OPT_DST];

	/* cheap test: types are different		*/
	if (sp->f_type != dp->f_type)
		return (FALSE);

	/* cheap test: directories have same contents	*/
	if (sp->f_type == S_IFDIR)
		return (TRUE);

	/* special files are compared via their maj/min	*/
	if ((sp->f_type == S_IFBLK) || (sp->f_type == S_IFCHR)) {
		if (sp->f_rd_maj != dp->f_rd_maj)
			return (FALSE);
		if (sp->f_rd_min != dp->f_rd_min)
			return (FALSE);
		return (TRUE);
	}

	/* symlinks are the same if their contents are the same	*/
	if (sp->f_type == S_IFLNK)
		return (samelink());

	/* cheap test: sizes are different		*/
	if (fp->f_info[OPT_SRC].f_size != fp->f_info[OPT_DST].f_size)
		return (FALSE);

	/* expensive test: byte for byte comparison	*/
	if (samecompare(fp) == 0)
		return (FALSE);

	return (TRUE);
}

/*
 * routine:
 *	samestuff
 *
 * purpose:
 *	determine whether or not two files have same owner/protection
 *
 * parameters:
 *	struct file
 *
 * returns:
 *	bool_t (true/false)
 */
static bool_t
samestuff(struct file *fp)
{	int same_mode, same_uid, same_gid, same_acl;
	struct fileinfo *sp, *dp;

	sp = &fp->f_info[OPT_SRC];
	dp = &fp->f_info[OPT_DST];

	same_mode = (sp->f_mode == dp->f_mode);
	same_uid = (sp->f_uid == dp->f_uid);
	same_gid = (sp->f_gid == dp->f_gid);
	same_acl = cmp_acls(sp, dp);

	/* if the are all the same, it is easy to tell the truth	*/
	if (same_uid && same_gid && same_mode && same_acl)
		return (TRUE);

	/* note the nature of the conflict				*/
	if (!same_uid || !same_gid || !same_acl)
		fp->f_problem = gettext(PROB_ownership);
	else
		fp->f_problem = gettext(PROB_protection);

	return (FALSE);
}

/*
 * routine:
 *	samecompare
 *
 * purpose:
 *	do a byte-for-byte comparison of two files
 *
 * parameters:
 *	struct file
 *
 * returns:
 *	bool_t (true/false)
 */
static bool_t
samecompare(struct file *fp)
{	int sfd, dfd;
	int i, count;
	char srcbuf[ COPY_BSIZE ], dstbuf[ COPY_BSIZE ];
	bool_t same = TRUE;


	sfd = open(srcname, 0);
	if (sfd < 0)
		return (FALSE);

	dfd = open(dstname, 0);
	if (dfd < 0) {
		close(sfd);
		return (FALSE);
	}

	for (
	count = read(sfd, srcbuf, COPY_BSIZE);
	count > 0;
	count = read(sfd, srcbuf, COPY_BSIZE)) {

		/* do a matching read				*/
		if (read(dfd, dstbuf, COPY_BSIZE) != count) {
			same = FALSE;
			goto done;
		}

		/* do the comparison for this block		*/
		for (i = 0; i < count; i++) {
			if (srcbuf[i] != dstbuf[i]) {
				same = FALSE;
				goto done;
			}
		}
	}

done:
	if (opt_debug & DBG_ANAL)
		fprintf(stderr, "ANAL: SAME=%d %s\n", same, fp->f_fullname);

	close(sfd);
	close(dfd);
	return (same);
}

/*
 * routine:
 *	truncated
 *
 * purpose:
 *	to determine whether or not a file has been truncated
 *
 * parameters:
 *	pointer to file structure
 *
 * returns:
 *	true/false
 */
static bool_t
truncated(struct file *fp)
{
	/* either source or destination must now be zero length	*/
	if (fp->f_info[OPT_SRC].f_size && fp->f_info[OPT_DST].f_size)
		return (FALSE);

	/* file must have originally had a non-zero length	*/
	if (fp->f_info[OPT_BASE].f_size == 0)
		return (FALSE);

	/* file type must "normal" all around		*/
	if (fp->f_info[OPT_BASE].f_type != S_IFREG)
		return (FALSE);
	if (fp->f_info[OPT_SRC].f_type != S_IFREG)
		return (FALSE);
	if (fp->f_info[OPT_DST].f_type != S_IFREG)
		return (FALSE);


	return (TRUE);
}

/*
 * routine:
 *	samelink
 *
 * purpose:
 *	to determine whether or not two symbolic links agree
 *
 * parameters:
 *	pointer to file structure
 *
 * returns:
 *	true/false
 */
static bool_t
samelink()
{	int i, srclen, dstlen;
	char srcbuf[ MAX_PATH ], dstbuf[ MAX_PATH ];


	/* read both copies of the link			*/
	srclen = readlink(srcname, srcbuf, sizeof (srcbuf));
	dstlen = readlink(dstname, dstbuf, sizeof (dstbuf));

	/* if they aren't the same length, they disagree	*/
	if (srclen < 0 || dstlen < 0 || srclen != dstlen)
		return (FALSE);

	/* look for differences in contents			*/
	for (i = 0; i < srclen; i++)
		if (srcbuf[i] != dstbuf[i])
			return (FALSE);

	return (TRUE);
}

/*
 * routine:
 *	full_name
 *
 * purpose:
 *	to figure out the fully qualified path name to a file on the
 *	reconciliation list.
 *
 * parameters:
 *	pointer to the file structure
 *	side indication for which base to use
 *	side indication for which buffer to use
 *
 * returns:
 *	pointer to a clobberable buffer
 *
 * notes:
 *	the zero'th buffer is used for renames and links, where
 *	we need the name of another file on the same side.
 */
char *
full_name(struct file *fp, side_t srcdst, side_t whichbuf)
{	static char *buffers[3];
	static int buflen = 0;
	char *p, *b;
	int l;

	/* see if the existing buffer is long enough	*/
	b = (srcdst == OPT_SRC) ? fp->f_base->b_src_name
				: fp->f_base->b_dst_name;

	/* see if the allocated buffer is long enough		*/
	l = strlen(b) + strlen(fp->f_fullname) + 2;
	if (l > buflen) {
		/* figure out the next "nice" size to use	*/
		for (buflen = MAX_PATH; buflen < l; buflen += MAX_NAME);

		/* reallocate all buffers to this size		*/
		for (l = 0; l < 3; l++) {
			buffers[l] = (char *) realloc(buffers[l], buflen);
			if (buffers[l] == 0)
				nomem("full name");
		}
	}

	/* assemble the name in the buffer and reurn it	*/
	p = buffers[whichbuf];
	strcpy(p, b);
	strcat(p, "/");
	strcat(p, fp->f_fullname);
	return (p);
}
