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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 *
 * module:
 *	action.c
 *
 * purpose:
 *	routines to carryout reconciliation actions and make the
 *	appropriate updates to the database file structure.
 *
 * contents:
 *	do_like ... change ownership and protection
 *	do_copy ... copy a file from one side to the other
 *	do_remove . remove a file from one side
 *	do_rename . rename a file on one side
 *	copy ...... (static) do the actual copy
 *	checksparse (static) figure out if a file is sparse
 *
 * ASSERTIONS:
 *	any of these action routines is responsible for all baseline
 *	and statistics updates associated with the reconciliation
 *	actions.  If notouch is specified, they should fake the
 *	updates well enough so that link tests will still work.
 *
 *	success:
 *		bump bp->b_{src,dst}_{copies,deletes,misc}
 *		update fp->f_info[srcdst]
 *		update fp->f_info[OPT_BASE] from fp->f_info[srcdst]
 *		if there might be multiple links, call link_update
 *		return ERR_RESOLVABLE
 *
 *	failure:
 *		set fp->f_flags |= F_CONFLICT
 *		set fp->f_problem
 *		bump bp->b_unresolved
 *		return ERR_UNRESOLVED
 *
 *	pretend this never happened:
 *		return 0, and baseline will be unchanged
 *
 * notes:
 *	Action routines can be called in virtually any order
 *	or combination, and it is certainly possible for an
 *	earlier action to succeed while a later action fails.
 *	If each successful action results in a completed baseline
 *	update, a subsequent failure will force the baseline to
 *	roll back to the last success ... which is appropriate.
 */
#ident	"%W%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <utime.h>
#include <errno.h>
#include <sys/mkdev.h>
#include <sys/statvfs.h>

#include "filesync.h"
#include "database.h"
#include "messages.h"
#include "debug.h"

/*
 * globals and importeds
 */
bool_t need_super;	/* warn user that we can't fix ownership	*/
extern char *srcname;	/* file we are emulating			*/
extern char *dstname;	/* file we are updating				*/

/*
 * locals
 */
static errmask_t copy(char *, char *, int);
static int checksparse(int);
static char *copy_err_str;		/* what went wrong w/copy	*/

/*
 * routine:
 *	do_like
 *
 * purpose:
 *	to propagate ownership and protection changes between
 *	one existing file and another.
 *
 * parameters:
 *	file pointer
 *	src/dst indication for who needs to change
 *	whether or not to update statistics (there may be a copy and a like)
 *
 * returns:
 *	error mask
 *
 * notes:
 *	if we are called from reconcile, we should update
 *	the statistics, but if we were called from do_copy
 *	that routine will do the honors.
 */
errmask_t
do_like(struct file *fp, side_t srcdst, bool_t do_stats)
{	char *dst;
	int rc = 0;
	int do_chown, do_chmod, do_chgrp, do_acls;
	errmask_t errs = 0;
	char *errstr = 0;
	struct base *bp;
	struct fileinfo *sp;
	struct fileinfo *dp;
	struct fileinfo *ip;
	extern int errno;

	bp = fp->f_base;

	/* see if this is a forbidden propagation */
	if (srcdst == opt_oneway) {
		fp->f_flags |= F_CONFLICT;
		fp->f_problem = gettext(PROB_prohibited);
		bp->b_unresolved++;
		return (ERR_UNRESOLVED);
	}


	/* get info about source and target files		*/
	if (srcdst == OPT_SRC) {
		sp = &fp->f_info[ OPT_DST ];
		dp = &fp->f_info[ OPT_SRC ];
		dst = srcname;
	} else {
		sp = &fp->f_info[ OPT_SRC ];
		dp = &fp->f_info[ OPT_DST ];
		dst = dstname;
	}
	ip = &fp->f_info[ OPT_BASE ];

	/* figure out what needs fixing				*/
	do_chmod = (sp->f_mode != dp->f_mode);
	do_chown = (sp->f_uid != dp->f_uid);
	do_chgrp = (sp->f_gid != dp->f_gid);
	do_acls  = ((fp->f_srcdiffs|fp->f_dstdiffs) & D_FACLS);

	/*
	 * try to anticipate things that we might not be able to
	 * do, and return appropriate errorst if the calling user
	 * cannot safely perform the requiested updates.
	 */
	if (my_uid != 0) {
		if (do_chown)
			errstr = gettext(PROB_chown);
		else if (my_uid != dp->f_uid) {
			if (do_chmod)
				errstr = gettext(PROB_chmod);
			else if (do_acls)
				errstr = gettext(PROB_chacl);
			else if (do_chgrp)
				errstr = gettext(PROB_chgrp);
		}
#ifdef	ACL_UID_BUG
		else if (do_acls && my_gid != dp->f_gid)
			errstr = gettext(PROB_botch);
#endif

		if (errstr) {
			need_super = TRUE;

			/* if the user doesn't care, shine it on	*/
			if (opt_everything == 0)
				return (0);

			/* if the user does care, return the error	*/
			rc = -1;
			goto nogood;
		}
	}

	if (opt_debug & DBG_RECON) {
		fprintf(stderr, "RECO: do_like %s (", dst);
		if (do_chmod)
			fprintf(stderr, "chmod ");
		if (do_acls)
			fprintf(stderr, "acls ");
		if (do_chown)
			fprintf(stderr, "chown ");
		if (do_chgrp)
			fprintf(stderr, "chgrp ");
		fprintf(stderr, ")\n");
	}

	if (do_chmod) {
		if (!opt_quiet)
			fprintf(stdout, "chmod %o %s\n", sp->f_mode,
						noblanks(dst));

#ifdef	DBG_ERRORS
		/* should we simulate a chmod failure	*/
		if (errno = dbg_chk_error(dst, 'p'))
			rc = -1;
		else
#endif
		rc = opt_notouch ? 0 : chmod(dst, sp->f_mode);

		if (opt_debug & DBG_RECON)
			fprintf(stderr, "RECO: do_chmod %o -> %d(%d)\n",
				sp->f_mode, rc, errno);

		/* update dest and baseline to reflect the change */
		if (rc == 0) {
			dp->f_mode = sp->f_mode;
			ip->f_mode = sp->f_mode;
		} else
			errstr = gettext(PROB_chmod);
	}

	/*
	 * see if we need to fix the acls
	 */
	if (rc == 0 && do_acls) {
		if (!opt_quiet)
			fprintf(stdout, "setfacl %s %s\n",
				show_acls(sp->f_numacls, sp->f_acls),
				noblanks(dst));

#ifdef	DBG_ERRORS
		/* should we simulate a set acl failure	*/
		if (errno = dbg_chk_error(dst, 'a'))
			rc = -1;
		else
#endif
		rc = opt_notouch ? 0 : set_acls(dst, sp);

		if (opt_debug & DBG_RECON)
			fprintf(stderr, "RECO: do_acls %d -> %d(%d)\n",
				sp->f_numacls, rc, errno);

		/* update dest and baseline to reflect the change */
		if (rc == 0) {
			dp->f_numacls = sp->f_numacls;
			dp->f_acls = sp->f_acls;
			ip->f_numacls = sp->f_numacls;
			ip->f_acls = sp->f_acls;
#ifdef	ACL_UID_BUG
			/* SETFACL changes a file's UID/GID	*/
			if (my_uid != dp->f_uid) {
				do_chown = 1;
				dp->f_uid = my_uid;
			}
			if (my_gid != dp->f_gid) {
				do_chgrp = 1;
				dp->f_gid = my_gid;
			}
#endif
		} else if (errno == ENOSYS) {
			/*
			 * if the file system doesn't support ACLs
			 * we should just pretend we never saw them
			 */
			fprintf(stderr, gettext(WARN_noacls), dst);
			ip->f_numacls = 0;
			sp->f_numacls = 0;
			dp->f_numacls = 0;
			rc = 0;
		} else
			errstr = gettext(PROB_chacl);
	}

	/*
	 * see if we need to fix the ownership
	 */
	if (rc == 0 && (do_chown || do_chgrp)) {
		if (do_chown)
			fprintf(stdout, "chown %ld %s; ",
				sp->f_uid, noblanks(dst));
		if (do_chgrp)
			fprintf(stdout, "chgrp %ld %s",
				sp->f_gid, noblanks(dst));

		fprintf(stdout, "\n");

#ifdef	DBG_ERRORS
		/* should we simulate a chown failure	*/
		if (errno = dbg_chk_error(dst, 'O'))
			rc = -1;
		else
#endif
		rc = opt_notouch ? 0 : lchown(dst, sp->f_uid, sp->f_gid);

		if (opt_debug & DBG_RECON)
			fprintf(stderr, "RECO: do_chown %ld %ld -> %d(%d)\n",
					sp->f_uid, sp->f_gid, rc, errno);

		/* update the destination to reflect changes */
		if (rc == 0) {
			dp->f_uid = sp->f_uid;
			dp->f_gid = sp->f_gid;
			ip->f_uid = sp->f_uid;
			ip->f_gid = sp->f_gid;
		} else {
			if (errno == EPERM) {
				need_super = TRUE;
				if (opt_everything == 0)
					return (0);
			}

			if (rc != 0)
				errstr = gettext(do_chown ?
						PROB_chown : PROB_chgrp);
		}
	}

	/*
	 * if we were successful, we should make sure the other links
	 * see the changes.  If we were called from do_copy, we don't
	 * want to do the link_updates either because do_copy will
	 * handle them too.
	 */
	if (rc == 0 && do_stats)
		link_update(fp, srcdst);

nogood:
	if (!do_stats)
		return (errs);

	if (rc != 0) {
		fprintf(stderr, gettext(ERR_cannot), errstr, dst);
		fp->f_problem = errstr;
		fp->f_flags |= F_CONFLICT;
		bp->b_unresolved++;
		errs |= ERR_PERM | ERR_UNRESOLVED;
	} else {
		/*
		 * it worked, so update the baseline and statistics
		 */
		if (srcdst == OPT_SRC)
			bp->b_src_misc++;
		else
			bp->b_dst_misc++;

		fp->f_problem = 0;
		errs |= ERR_RESOLVABLE;
	}

	return (errs);
}

/*
 * routine:
 *	do_copy
 *
 * purpose:
 *	to propagate a creation or change
 *
 * parameters:
 *	file pointer
 *	src/dst indication for who gets the copy
 *
 * returns:
 *	error mask
 *
 * note:
 *	after any successful operation we update the stat/info
 *	structure for the updated file.  This is somewhat redundant
 *	because we will restat at the end of the routine, but these
 *	anticipatory updates help to ensure that the link finding
 *	code will still behave properly in notouch mode (when restats
 *	cannot be done).
 */
errmask_t
do_copy(struct file *fp, side_t srcdst)
{	char *src, *dst;
	char cmdbuf[ MAX_PATH + MAX_NAME ];
	int mode, maj, min, type;
	uid_t uid;
	gid_t gid;
	int rc;
	long mtime;
	int do_chmod = 0;
	int do_chown = 0;
	int do_chgrp = 0;
	int do_unlink = 0;
	int do_acls = 0;
	int do_create = 0;
	char *errstr = "???";
	errmask_t errs = 0;
	struct base *bp;
	struct file *lp;
	struct fileinfo *sp, *dp;
	struct utimbuf newtimes;
	struct stat statb;

	bp = fp->f_base;

	/* see if this is a forbidden propagation */
	if (srcdst == opt_oneway) {
		fp->f_problem = gettext(PROB_prohibited);
		fp->f_flags |= F_CONFLICT;
		bp->b_unresolved++;
		return (ERR_UNRESOLVED);
	}

	/* figure out who is the source and who is the destination	*/
	if (srcdst == OPT_SRC) {
		sp = &fp->f_info[ OPT_DST ];
		dp = &fp->f_info[ OPT_SRC ];
		src = dstname;
		dst = srcname;
	} else {
		sp = &fp->f_info[ OPT_SRC ];
		dp = &fp->f_info[ OPT_DST ];
		src = srcname;
		dst = dstname;
	}

	/* note information about the file to be created		*/
	type  = sp->f_type;		/* type of the new file		*/
	uid   = sp->f_uid;		/* owner of the new file	*/
	gid   = sp->f_gid;		/* group of the new file	*/
	mode  = sp->f_mode;		/* modes for the new file	*/
	mtime = sp->f_modtime;		/* modtime (if preserving)	*/
	maj   = sp->f_rd_maj;		/* major (if it is a device)	*/
	min   = sp->f_rd_min;		/* minor (if it is a device)	*/

	/*
	 * creating a file does not guarantee it will get the desired
	 * modes, uid and gid.  If the file already exists, it will
	 * retain its old ownership and protection.  If my UID/GID
	 * are not the desired ones, the new file will also require
	 * manual correction.  If the file has the wrong type, we will
	 * need to delete it and recreate it.  If the file is not writable,
	 * it is easier to delete it than to chmod it to permit overwrite
	 */
	if ((dp->f_type == S_IFREG && sp->f_type == S_IFREG) &&
	    (dp->f_mode & 0200)) {
		/* if the file already exists		*/
		if (dp->f_uid != uid)
			do_chown = 1;

		if (dp->f_gid != gid)
			do_chgrp = 1;

		if (dp->f_mode != mode)
			do_chmod = 1;
	} else {
		/* if we will be creating a new file	*/
		do_create = 1;
		if (dp->f_type)
			do_unlink = 1;
		if (uid != my_uid)
			do_chown = 1;
		if (gid != my_gid)
			do_chgrp = 1;
	}

	/*
	 * if the source has acls, we will surely have to set them for dest
	 */
	if (sp->f_numacls)
		do_acls = 1;

	/*
	 * for any case other than replacing a normal file with a normal
	 * file, we need to delete the existing file before creating
	 * the new one.
	 */
	if (do_unlink) {
		if (dp->f_type == S_IFDIR) {
			if (!opt_quiet)
				fprintf(stdout, "rmdir %s\n", noblanks(dst));

			errstr = gettext(PROB_rmdir);
#ifdef	DBG_ERRORS
			/* should we simulate a rmdir failure	*/
			if (errno = dbg_chk_error(dst, 'D'))
				rc = -1;
			else
#endif
			rc = opt_notouch ? 0 : rmdir(dst);
		} else {
			if (!opt_quiet)
				fprintf(stdout, "rm %s\n", noblanks(dst));

			errstr = gettext(PROB_unlink);
#ifdef	DBG_ERRORS
			/* should we simulate a unlink failure	*/
			if (errno = dbg_chk_error(dst, 'u'))
				rc = -1;
			else
#endif
			rc = opt_notouch ? 0 : unlink(dst);
		}

		if (rc != 0)
			goto cant;

		/* note that this file no longer exists		*/
		dp->f_type = 0;
		dp->f_mode = 0;
	}

	if (opt_debug & DBG_RECON) {
		fprintf(stderr, "RECO: do_copy %s %s (", src, dst);
		if (do_unlink)
			fprintf(stderr, "unlink ");
		if (do_chmod)
			fprintf(stderr, "chmod ");
		if (do_acls)
			fprintf(stderr, "acls ");
		if (do_chown)
			fprintf(stderr, "chown ");
		if (do_chgrp)
			fprintf(stderr, "chgrp ");
		fprintf(stderr, ")\n");
	}

	/*
	 * how we go about copying a file depends on what type of file
	 * it is that we are supposed to copy
	 */
	switch (type) {
	    case S_IFDIR:
		if (!opt_quiet) {
			fprintf(stdout, "mkdir %s;", noblanks(dst));
			fprintf(stdout, " chmod %o %s;\n", mode, noblanks(dst));
		}

		errstr = gettext(PROB_mkdir);

#ifdef	DBG_ERRORS
		/* should we simulate a mkdir failure	*/
		if (errno = dbg_chk_error(dst, 'd'))
			rc = -1;
		else
#endif
		rc = opt_notouch ? 0 : mkdir(dst, mode);

		/* update stat with what we have just created	*/
		if (rc == 0) {
			dp->f_type = S_IFDIR;
			dp->f_uid = my_uid;
			dp->f_gid = my_gid;
			dp->f_mode = mode;
		}

		break;

	    case S_IFLNK:
		errstr = gettext(PROB_readlink);
#ifdef	DBG_ERRORS
		/* should we simulate a symlink read failure	*/
		if (errno = dbg_chk_error(dst, 'r'))
			rc = -1;
		else
#endif
		rc = readlink(src, cmdbuf, sizeof (cmdbuf));
		if (rc > 0) {
			cmdbuf[rc] = 0;
			if (!opt_quiet) {
				fprintf(stdout, "ln -s %s", noblanks(cmdbuf));
				fprintf(stdout, " %s;\n", noblanks(dst));
			}
			errstr = gettext(PROB_symlink);
#ifdef	DBG_ERRORS
			/* should we simulate a symlink failure	*/
			if (errno = dbg_chk_error(dst, 'l'))
				rc = -1;
			else
#endif
			rc = opt_notouch ? 0 : symlink(cmdbuf, dst);

			if (rc == 0)
				dp->f_type = S_IFLNK;
		}
		break;

	    case S_IFBLK:
	    case S_IFCHR:
		if (!opt_quiet)
			fprintf(stdout, "mknod %s %s %d %d\n", noblanks(dst),
				(type == S_IFBLK) ? "b" : "c", maj, min);

		errstr = gettext(PROB_mknod);
#ifdef	DBG_ERRORS
		/* should we simulate a mknod failure	*/
		if (errno = dbg_chk_error(dst, 'd'))
			rc = -1;
		else
#endif
		rc = opt_notouch ? 0
				: mknod(dst, mode|type, makedev(maj, min));

		/* update stat with what we have just created	*/
		if (rc == 0) {
			dp->f_type = type;
			dp->f_uid = my_uid;
			dp->f_gid = my_gid;
			dp->f_mode = 0666;

			if (dp->f_mode != mode)
				do_chmod = 1;
		}
		break;

	    case S_IFREG:
		/*
		 * The first thing to do is ascertain whether or not
		 * the alleged new copy might in fact be a new link.
		 * We trust find_link to weigh all the various factors,
		 * so if it says make a link, we'll do it.
		 */
		lp = find_link(fp, srcdst);
		if (lp) {
			/* figure out name of existing file	*/
			src = full_name(lp, srcdst, OPT_BASE);

			/*
			 * if file already exists, it must be deleted
			 */
			if (dp->f_type) {
				if (!opt_quiet)
					fprintf(stdout, "rm %s\n",
						noblanks(dst));

				errstr = gettext(PROB_unlink);
#ifdef	DBG_ERRORS
				/* should we simulate a unlink failure	*/
				if (errno = dbg_chk_error(dst, 'u'))
					rc = -1;
				else
#endif
				rc = opt_notouch ? 0 : unlink(dst);

				/*
				 * if we couldn't do the unlink, we must
				 * mark the linkee in conflict as well
				 * so its reference count remains the same
				 * in the baseline and it continues to show
				 * up on the change list.
				 */
				if (rc != 0) {
					lp->f_flags |= F_CONFLICT;
					lp->f_problem = gettext(PROB_link);
					goto cant;
				}
			}

			if (!opt_quiet) {
				fprintf(stdout, "ln %s", noblanks(src));
				fprintf(stdout, " %s\n", noblanks(dst));
			}
			errstr = gettext(PROB_link);

#ifdef	DBG_ERRORS
			/* should we simulate a link failure	*/
			if (errno = dbg_chk_error(dst, 'l'))
				rc = -1;
			else
#endif
			rc = opt_notouch ? 0 : link(src, dst);

			/*
			 * if this is a link, there is no reason to worry
			 * about ownership and modes, they are automatic
			 */
			do_chown = 0; do_chgrp = 0; do_chmod = 0; do_acls = 0;
			if (rc == 0) {
				dp->f_type = type;
				dp->f_uid = uid;
				dp->f_gid = gid;
				dp->f_mode = mode;
				break;
			} else {
				/*
				 * if we failed to make a link, we want to
				 * mark the linkee in conflict too, so that
				 * its reference count remains the same in
				 * the baseline, and it shows up on the change
				 * list again next time.
				 */
				lp->f_flags |= F_CONFLICT;
				lp->f_problem = errstr;
				break;
			}

			/*
			 * in some situation we haven't figured out yet
			 * we might want to fall through and try a copy
			 * if the link failed.
			 */
		}

		/* we are going to resolve this by making a copy	*/
		if (!opt_quiet) {
			fprintf(stdout, "cp %s", noblanks(src));
			fprintf(stdout, " %s\n", noblanks(dst));
		}
		rc = opt_notouch ? 0 : copy(src, dst, mode);
		if (rc != 0) {
			errs |= rc;
			if (copy_err_str)
				errstr = copy_err_str;
			else
				errstr = gettext(PROB_copy);

			/*
			 * The new copy (if it exists at all) is a botch.
			 * If this was a new create or a remove and copy
			 * we should get rid of the botched copy so that
			 * it doesn't show up as two versions next time.
			 */
			if (do_create)
				unlink(dst);
		} else if (dp->f_mode == 0) {
			dp->f_type = S_IFREG;
			dp->f_uid = my_uid;
			dp->f_gid = my_gid;
			dp->f_mode = mode;

			/* FIX: inode number is still wrong	*/
		}

		/* for normal files we have an option to preserve mod time  */
		if (rc == 0 && opt_notouch == 0 && opt_mtime) {
			newtimes.actime = mtime;
			newtimes.modtime = mtime;

			/* ignore the error return on this one	*/
			(void) utime(dst, &newtimes);
		}
		break;

	    default:
		errstr = gettext(PROB_deal);
		rc = -1;
	}

	/*
	 * if any of the file's attributes need attention, I should let
	 * do_like take care of them, since it knows all rules for who
	 * can and cannot make what types of changes.
	 */
	if (rc == 0 && (do_chmod || do_chown || do_chgrp || do_acls)) {
		rc = do_like(fp, srcdst, FALSE);
		errstr = fp->f_problem;
		errs |= rc;
	}

	/*
	 * finish off by re-stating the destination and using that to
	 * update the baseline.  If we were completely successful in
	 * our chowns/chmods, stating the destination will confirm it.
	 * If we were unable to make all the necessary changes, stating
	 * the destination will make the source appear to have changed,
	 * so that the differences will continue to reappear as new
	 * changes (inconsistancies).
	 */
	if (rc == 0)
		if (!opt_notouch) {
			errstr = gettext(PROB_restat);

#ifdef	DBG_ERRORS
			/* should we simulate a restat failure	*/
			if (errno = dbg_chk_error(dst, 'R'))
				rc = -1;
			else
#endif
			rc = lstat(dst, &statb);

			if (rc == 0) {
				note_info(fp, &statb, srcdst);
				link_update(fp, srcdst);
				if (do_acls)
					(void) get_acls(dst, dp);
				update_info(fp, srcdst);
			}
		} else {
			/*
			 * BOGOSITY ALERT
			 *	we are in notouch mode and haven't really
			 *	done anything, but if we want link detection
			 *	to work and be properly reflected in the
			 *	what-I-would-do output for a case where
			 *	multiple links are created to a new file,
			 *	we have to make the new file appear to
			 *	have been created.  Since we didn't create
			 *	the new file we can't stat it, but if
			 *	no file exists, we can't make a link to
			 *	it, so we will pretend we created a file.
			 */
			if (dp->f_ino == 0 || dp->f_nlink == 0) {
				dp->f_ino = sp->f_ino;
				dp->f_nlink = 1;
			}
		}

cant:	if (rc != 0) {
		fprintf(stderr, gettext(ERR_cannot), errstr, dst);
		bp->b_unresolved++;
		fp->f_flags |= F_CONFLICT;
		fp->f_problem = errstr;
		if (errs == 0)
			errs = ERR_PERM;
		errs |= ERR_UNRESOLVED;
	} else {
		/* update the statistics			*/
		if (srcdst == OPT_SRC)
			bp->b_src_copies++;
		else
			bp->b_dst_copies++;
		errs |= ERR_RESOLVABLE;
	}

	return (errs);
}

/*
 * routine:
 *	do_remove
 *
 * purpose:
 *	to propagate a deletion
 *
 * parameters:
 *	file pointer
 *	src/dst indication for which side gets changed
 *
 * returns:
 *	error mask
 */
errmask_t
do_remove(struct file *fp, side_t srcdst)
{	char *name;
	int rc;
	struct base *bp = fp->f_base;
	errmask_t errs = 0;
	char *errstr = "???";

	/* see if this is a forbidden propagation */
	if (srcdst == opt_oneway) {
		fp->f_problem = gettext(PROB_prohibited);
		fp->f_flags |= F_CONFLICT;
		bp->b_unresolved++;
		return (ERR_UNRESOLVED);
	}

	name = (srcdst == OPT_SRC) ? srcname : dstname;

	if (fp->f_info[0].f_type == S_IFDIR) {
		if (!opt_quiet)
			fprintf(stdout, "rmdir %s\n", noblanks(name));

		errstr = gettext(PROB_rmdir);

#ifdef	DBG_ERRORS
		/* should we simulate a rmdir failure	*/
		if (errno = dbg_chk_error(name, 'D'))
			rc = -1;
		else
#endif
		rc = opt_notouch ? 0 : rmdir(name);
	} else {
		if (!opt_quiet)
			fprintf(stdout, "rm %s\n", noblanks(name));

		errstr = gettext(PROB_unlink);

#ifdef	DBG_ERRORS
		/* should we simulate an unlink failure	*/
		if (errno = dbg_chk_error(name, 'u'))
			rc = -1;
		else
#endif
		rc = opt_notouch ? 0 : unlink(name);
	}

	if (opt_debug & DBG_RECON)
		fprintf(stderr, "RECO: do_remove %s -> %d(%d)\n",
			name, rc, errno);

	if (rc == 0) {
		/* tell any other hard links that one has gone away	*/
		fp->f_info[srcdst].f_nlink--;
		link_update(fp, srcdst);

		fp->f_flags |= F_REMOVE;
		if (srcdst == OPT_SRC)
			fp->f_base->b_src_deletes++;
		else
			fp->f_base->b_dst_deletes++;
		errs |= ERR_RESOLVABLE;
	} else {
		fprintf(stderr, gettext(ERR_cannot), errstr, name);
		fp->f_problem = errstr;
		fp->f_flags |= F_CONFLICT;
		bp->b_unresolved++;
		errs |= ERR_PERM | ERR_UNRESOLVED;
	}

	return (errs);
}

/*
 * routine:
 *	do_rename
 *
 * purpose:
 *	to propagate a rename
 *
 * parameters:
 *	file pointer for the new name
 *	src/dst indication for which side gets changed
 *
 * returns:
 *	error mask
 */
errmask_t
do_rename(struct file *fp, side_t srcdst)
{	int rc;
	struct file *pp = fp->f_previous;
	struct base *bp = fp->f_base;
	errmask_t errs = 0;
	char *errstr = "???";
	char *newname;
	char *oldname;
	struct stat statb;

	/* see if this is a forbidden propagation */
	if (srcdst == opt_oneway) {
		fp->f_problem = gettext(PROB_prohibited);

		/* if we can't resolve the TO, the FROM is also unresolved */
		pp->f_problem = gettext(PROB_prohibited);
		pp->f_flags |= F_CONFLICT;
		bp->b_unresolved++;
		return (ERR_UNRESOLVED);
	}

	newname = (srcdst == OPT_SRC) ? srcname : dstname;
	oldname = full_name(pp, srcdst, OPT_BASE);

	if (!opt_quiet)
		fprintf(stdout, "%s %s %s\n",
			(fp->f_info[0].f_type == S_IFDIR) ? "mvdir" : "mv",
			noblanks(oldname), noblanks(newname));

#ifdef	DBG_ERRORS
	/* should we simulate a rename failure	*/
	if (errno = dbg_chk_error(oldname, 'm'))
		rc = -1;
	else
#endif
	rc = opt_notouch ? 0 : rename(oldname, newname);

	if (opt_debug & DBG_RECON)
		fprintf(stderr, "RECO: do_rename %s %s -> %d(%d)\n",
			oldname, newname, rc, errno);

	/* if we succeed, update the baseline			*/
	if (rc == 0)
		if (!opt_notouch) {
			errstr = gettext(PROB_restat);

#ifdef	DBG_ERRORS
			/* should we simulate a restat failure	*/
			if (errno = dbg_chk_error(newname, 'S'))
				rc = -1;
			else
#endif
			rc = lstat(newname, &statb);

			if (rc == 0) {
				note_info(fp, &statb, srcdst);
				link_update(fp, srcdst);
				update_info(fp, srcdst);
			}
		} else {
			/*
			 * BOGOSITY ALERT
			 * in order for link tests to work in notouch
			 * mode we have to dummy up some updated status
			 */
			fp->f_info[srcdst].f_ino = pp->f_info[srcdst].f_ino;
			fp->f_info[srcdst].f_nlink = pp->f_info[srcdst].f_nlink;
			fp->f_info[srcdst].f_type = pp->f_info[srcdst].f_type;
			fp->f_info[srcdst].f_size = pp->f_info[srcdst].f_size;
			fp->f_info[srcdst].f_mode = pp->f_info[srcdst].f_mode;
			fp->f_info[srcdst].f_uid = pp->f_info[srcdst].f_uid;
			fp->f_info[srcdst].f_gid = pp->f_info[srcdst].f_gid;
			update_info(fp, srcdst);
		}
	else
		errstr = gettext(PROB_rename2);

	if (rc == 0) {
		pp->f_flags |= F_REMOVE;

		if (srcdst == OPT_SRC) {
			bp->b_src_copies++;
			bp->b_src_deletes++;
		} else {
			bp->b_dst_copies++;
			bp->b_dst_deletes++;
		}
		errs |= ERR_RESOLVABLE;
	} else {
		fprintf(stderr, gettext(ERR_cannot), errstr, oldname);

		bp->b_unresolved++;
		fp->f_flags |= F_CONFLICT;
		pp->f_flags |= F_CONFLICT;

		fp->f_problem = errstr;
		pp->f_problem = gettext(PROB_rename);

		errs |= ERR_PERM | ERR_UNRESOLVED;
	}

	return (errs);
}

/*
 * routine:
 *	copy
 *
 * purpose:
 *	to copy one file to another
 *
 * parameters:
 *	source file name
 *	destination file name
 *	desired modes
 *
 * returns:
 *	0	OK
 *	else	error mask, and a setting of copy_err_str
 *
 * notes:
 *	We try to preserve the holes in sparse files, by skipping over
 *	any holes that are at least MIN_HOLE bytes long.  There are
 *	pathological cases where the hole detection test could become
 *	expensive, but for most blocks of most files we will fall out
 *	of the zero confirming loop in the first couple of bytes.
 */
static errmask_t
copy(char *src, char *dst, int mode)
{	int ifd, ofd, count, ret;
	long *p, *e;
	long long length;		/* total size of file	*/
	errmask_t errs = 0;
	int bsize;			/* block-size for file	*/
	bool_t sparse;			/* file may be sparse	*/
	bool_t was_hole = FALSE;		/* file ends with hole	*/
	long inbuf[ COPY_BSIZE/4 ];	/* long to speed checks	*/
	struct stat statbuf;		/* info on source file	*/
	struct statvfs statvsbuf;	/* info on target fs	*/

	copy_err_str = 0;

	/* open the input file			*/
#ifdef	DBG_ERRORS
	if (opt_errors && dbg_chk_error(src, 'o'))
		ifd = -1;
	else
#endif
	ifd = open(src, O_RDONLY);

	if (ifd < 0) {
		copy_err_str = gettext(PROB_copyin);
		return (ERR_PERM);
	}

	/*
	 * if we suspect a file may be sparse, we must process it
	 * a little more carefully, looking for holes and skipping
	 * over them in the output.  If a file is not sparse, we
	 * can move through it at greater speed.
	 */
	bsize = checksparse(ifd);
	if (bsize > 0 && bsize <= COPY_BSIZE)
		sparse = TRUE;
	else {
		sparse = FALSE;
		bsize = COPY_BSIZE;
	}

	/*
	 * if the target file already exists and we overwrite it without
	 * first ascertaining that there is enough room, we could wind
	 * up actually losing data.  Try to determine how much space is
	 * available on the target file system, and if that is not enough
	 * for the source file, fail without even trying.  If, however,
	 * the target file does not already exist, we have nothing to
	 * lose by just doing the copy without checking the space.
	 */
	ret = statvfs(dst, &statvsbuf);
	if (ret == 0 && statvsbuf.f_frsize != 0) {
#ifdef	DBG_ERRORS
		/* should we simulate an out-of-space situation	*/
		if ((length = dbg_chk_error(dst, 'Z')) == 0)
#endif
		length = statvsbuf.f_bavail * statvsbuf.f_frsize;

		ret = fstat(ifd, &statbuf);
		if (ret == 0) {
			length /= 512;		/* st_blocks in 512s	*/
			if (length < statbuf.st_blocks) {
				copy_err_str = gettext(PROB_space);
				close(ifd);
				return (ERR_FILES);
			}
		} else {
			copy_err_str = gettext(PROB_restat);
			close(ifd);
			return (ERR_FILES);
		}
	}

	/* create the output file		*/
#ifdef	DBG_ERRORS
	if (opt_errors && dbg_chk_error(dst, 'c'))
		ofd = -1;
	else
#endif
	ofd = creat(dst, mode);

	if (ofd < 0) {
		close(ifd);
		copy_err_str = gettext(PROB_copyout);
		return (ERR_PERM);
	}

	/* copy the data from the input file to the output file	*/
	for (;;) {
#ifdef	DBG_ERRORS
		if (opt_errors && dbg_chk_error(dst, 'r'))
			count = -1;
		else
#endif
		count = read(ifd, (char *) inbuf, bsize);
		if (count <= 0)
			break;

		/*
		 * if the file might be sparse and we got an entire block,
		 * we should see if the block is all zeros
		 */
		if (sparse && count == bsize) {
			p = inbuf; e = &inbuf[count/4];
			while (p < e && *p == 0)
				p++;
			if (p == e) {
				(void) lseek(ofd, (off_t) count, SEEK_CUR);
				was_hole = TRUE;
				continue;
			}
		}
		was_hole = FALSE;

#ifdef	DBG_ERRORS
		if (opt_errors && dbg_chk_error(dst, 'w'))
			ret = -1;
		else
#endif
		ret = write(ofd, (char *) inbuf, count);

		if (ret != count) {
			errs = ERR_FILES;
			copy_err_str = gettext(PROB_write);
			break;
		}
	}

	if (count < 0) {
		copy_err_str = gettext(PROB_read);
		errs = ERR_FILES;
	} else if (was_hole) {
		/*
		 * if we skipped the last write because of a hole, we
		 * need to make sure that we write a single byte of null
		 * at the end of the file to update the file length.
		 */
		(void) lseek(ofd, (off_t)-1, SEEK_CUR);
		(void) write(ofd, "", 1);
	}

	/*
	 * if the output file was botched, free up its space
	 */
	if (errs)
		ftruncate(ofd, (off_t) 0);

	close(ifd);
	close(ofd);
	return (errs);
}

/*
 * routine:
 *	checksparse
 *
 * purpose:
 *	to determine whether or not a file might be sparse, and if
 *	it is sparse, what the granularity of the holes is likely
 *	to be.
 *
 * parameters:
 *	file descriptor for file in question
 *
 * returns:
 *	0	file does not appear to be sparse
 *	else	block size for this file
 */
static int
checksparse(int fd)
{
	struct stat statb;

	/*
	 * unable to stat the file is very strange (since we got it
	 * open) but it probably isn't worth causing a fuss over.
	 * Return the conservative answer
	 */
	if (fstat(fd, &statb) < 0)
		return (MIN_HOLE);

	/*
	 * if the file doesn't have enough blocks to account for
	 * all of its bytes, there is a reasonable chance that it
	 * is sparse.  This test is not perfect, in that it will
	 * fail to find holes in cases where the holes aren't
	 * numerous enough to componsent for the indirect blocks
	 * ... but losing those few holes is not going to be a
	 * big deal.
	 */
	if (statb.st_size > 512 * statb.st_blocks)
		return (statb.st_blksize);
	else
		return (0);
}
