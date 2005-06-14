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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*LINTLIBRARY*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<dirent.h>
#include	<string.h>
#include	<errno.h>
#include	<limits.h>
#include	<unistd.h>
#include	<volmgt.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/vol.h>

#include	"volmgt_private.h"



#define	ALIAS_DIR	"dev/aliases"
#define	HACKNAME_MAX	5		/* max aliases to try */
#define	NUMBUF_SZ	10		/* big enough for HACKNAME */


/* a shortcut for checkinf for absolute pathnames */
#define	IS_ABS_PATH(p)	(*(p) == '/')


/*
 * arc approved interface (pending)
 *	- can not be modified without approval from an arc
 *
 * committment level:
 *	public
 *
 * description:
 *	media_findname: try to come up with the character device when
 *	provided with a starting point.  This interface provides the
 *	application programmer to provide "user friendly" names and
 *	easily determine the "/vol" name.
 *
 * arguments:
 *	start - a string describing a device.  This string can be:
 *		- a full path name to a device (insures it's a
 *		  character device by using getfullrawname()).
 *		- a full path name to a volume management media name
 *		  with partitions (will return the lowest numbered
 *		  raw partition.
 *		- the name of a piece of media (e.g. "fred").
 *		- a symbolic device name (e.g. floppy0, cdrom0, etc)
 *		- a name like "floppy" or "cdrom".  Will pick the lowest
 *		  numbered device with media in it.
 *
 * return value(s):
 *	A pointer to a string that contains the character device
 *	most appropriate to the "start" argument.
 *
 *	NULL indicates that we were unable to find media based on "start".
 *
 *	The string must be free(3)'d.
 *
 * preconditions:
 *	none.
 */
char *
media_findname(char *start)
{
	static char 	*media_findname_work(char *);
	char		*s = NULL;


	/*
	 * This is just a wrapper to implement the volmgt_check nastyness.
	 */
#ifdef	DEBUG
	denter("media_findname(%s): entering\n", start ? start : "<null ptr>");
#endif

	if (start == NULL) {
		errno = EFAULT;
		goto dun;
	}

	/*
	 * If we don't get positive results, we kick volume management
	 * to ask it to look in the floppy drive.
	 *
	 * XXX: maybe this should be configurable ???
	 */
	if ((s = media_findname_work(start)) == NULL) {
#ifdef	DEBUG
		dprintf("media_findname: calling volcheck and trying again\n");
#endif
		(void) volmgt_check(NULL);
		s = media_findname_work(start);
	}

dun:
#ifdef	DEBUG
	dexit("media_findname: returning \"%s\"\n", s ? s : "<null ptr>");
#endif
	return (s);
}


/*
 * Return a raw name, given a starting point.
 *
 * Assume: input string ptr is not null
 */
static char *
media_findname_work(char *start)
{
	extern char		*vol_basename(char *);
	static void		volmgt_deref_link(char *, char *, char *);
	char			pathbuf[MAXPATHLEN+1];
	char			*rv;
	char			*s;
	char			linkbuf[MAXNAMELEN+1];
	char			*nameptr;
	struct stat64		sb;
	int			n;
	int			i;
	static const char	*vold_root = NULL;
	static char		vold_alias_dir[MAXPATHLEN+1];
	char			*res = NULL;
	DIR			*dirp = NULL;
	struct dirent64		*dp;



#ifdef	DEBUG
	denter("media_findname_work(%s): entering\n", start);
#endif

	if (vold_root == NULL) {
		vold_root = volmgt_root();
		(void) concat_paths(vold_alias_dir, (char *)vold_root,
		    (char *)ALIAS_DIR, NULL);
	}

	/*
	 * if this is an absolute path name then
	 *  if it's a symlink deref it
	 *  if it's a raw device then we're done
	 *  else if it's a directory then look for a dev under it
	 */
	if (IS_ABS_PATH(start)) {

		/* try to get data on name passed in */
		if (lstat64(start, &sb) < 0) {
#ifdef	DEBUG
			dprintf(
			"media_findname_work: lstat of \"%s\" (errno %d)\n",
			    start, errno);
#endif
			goto dun;		/* error exit */
		}

		/*
		 * if is this a link to something else (e.g. ".../floppy0")
		 * and it's in the volmgt namespace, then deref it
		 */
		if (S_ISLNK(sb.st_mode) && (strncmp(start, vold_alias_dir,
		    strlen(vold_alias_dir)) == 0)) {

			/* it's a symlink */
			if ((n = readlink(start, linkbuf, MAXNAMELEN)) <= 0) {
				/* we can't read the link */
#ifdef	DEBUG
				dprintf(
		"media_findname_work: readlink(\"%s\") failed (errno %d)\n",
				    start, errno);
#endif
				goto dun;	/* error exit */
			}
			linkbuf[n] = NULLC;

			/* dereference the link */
			volmgt_deref_link(pathbuf, start, linkbuf);

			/* stat where "start" pointed at */
			if (stat64(pathbuf, &sb) < 0) {
#ifdef	DEBUG
				dprintf(
		"media_findname_work: stat failed on \"%s\" (errno %d)\n",
				    pathbuf, errno);
#endif
				goto dun;	/* error exit */
			}
			nameptr = pathbuf;

		} else {
			nameptr = start;
		}

		/* do we already have a char-spcl device ?? */
		if (S_ISCHR(sb.st_mode)) {
			/*
			 * absoluate pathname of a char-spcl device passed in
			 */
			res = strdup(nameptr);
			goto dun;		/* success */
		}

		/* not a char-spcl device -- is it a dir ?? */
		if (S_ISDIR(sb.st_mode)) {
			/* open the dir and find first char-spcl device */
			if ((s = getrawpart0(nameptr)) != NULL) {
				/*
				 * absoluate pathname to a directory passed
				 * in, under which there is at least one
				 * char-spcl device
				 */
				free(s);
				res = strdup(nameptr);
				goto dun;	/* success */
			}
		}

		/*
		 * try to get the char-spcl name if this is a blk-spcl
		 *
		 * XXX: shouldn't we ensure this is a blk spcl device?
		 */
		rv = volmgt_getfullrawname(nameptr);
		if ((rv == NULL) || (*rv == NULLC)) {
			goto dun;		/* error exit */
		}

		/* stat the fullrawname device (to see if it's char-spcl) */
		if (stat64(rv, &sb) < 0) {
#ifdef	DEBUG
			dprintf(
			    "media_findname_work: stat of \"%s\" (errno %d)\n",
			    rv, errno);
#endif
			goto dun;		/* error exit */
		}

		/* have we found the char-spcl device ?? */
		if (S_ISCHR(sb.st_mode)) {
			/*
			 * absolute pathname to block device supplied and
			 * converted to an absoluate pathname to a char device
			 */
			res = rv;		/* already malloc'ed */
			goto dun;		/* success */
		}

		/*
		 * fullrawname not a char-spcl device -- is it a dir ??
		 *
		 * XXX: didn't we already check for a directory name
		 * being supplied above?
		 */
		if (S_ISDIR(sb.st_mode)) {
			/* open dir and find first char-spcl device */
			if ((s = getrawpart0(rv)) != NULL) {
				/*
				 * the absolute pathname of directory
				 * containing at least one char-spcl device
				 * was passed in
				 */
				free(s);
				res = strdup(rv);
				goto dun;	/* success */
			}
		}

		/* having a full pathname didn't help us */
		goto dun;	/* failure -- pathname not found */
	}

	/*
	 * Ok, now we check to see if it's an alias.
	 * Note here that in the case of an alias, we prefer
	 * to return what the alias (symbolic link) points
	 * at, rather than the symbolic link.  Makes for
	 * nicer printouts and such.
	 */
	(void) concat_paths(pathbuf, vold_alias_dir, start, NULL);

#ifdef	DEBUG
	dprintf("media_findname_work: looking for \"%s\"\n", pathbuf);
#endif

	if (stat64(pathbuf, &sb) == 0) {
#ifdef	DEBUG
		dprintf("media_findname_work: is \"%s\" a chr-spcl dev?\n",
		    pathbuf);
#endif
		/* is this a char-spcl device ?? */
		if (S_ISCHR(sb.st_mode)) {
			/* it's probably a link, so ... */
			if ((n = readlink(pathbuf,
			    linkbuf, MAXNAMELEN)) <= 0) {
				/*
				 * error (since we are in the symlink
				 * directory) not a link, but just punt
				 * anyway
				 */
				res = strdup(pathbuf);
			} else {
				/* it was a link */
				linkbuf[n] = NULLC;
				res = strdup(linkbuf);
			}
			goto dun;		/* success */
		}

#ifdef	DEBUG
		dprintf("media_findname_work: not chr-spcl -- is it a dir?\n");
#endif
		/* not a char-spcl device -- is it a dir ?? */
		if (S_ISDIR(sb.st_mode)) {
			/* it's probably a link, so ... */
			if ((n = readlink(pathbuf,
			    linkbuf, MAXNAMELEN)) <= 0) {
				/*
				 * error, but just punt anyway
				 */
				nameptr = pathbuf;
				s = getrawpart0(pathbuf);
			} else {
				/* it was a link */
				linkbuf[n] = NULLC;
				/* open dir, finding first char-spcl dev */
				nameptr = linkbuf;
				s = getrawpart0(linkbuf);
			}
			if (s != NULL) {
				free(s);
				res = strdup(nameptr);
				goto dun;
			}
		}
	}

	/*
	 * check all aliases in the alias dir, to see if any match
	 */
	if ((dirp = opendir(vold_alias_dir)) == NULL) {
		goto try_hack;
	}

	while (dp = readdir64(dirp)) {

		/* skip uninteresting entries */
		if (strcmp(dp->d_name, ".") == 0) {
			continue;
		}
		if (strcmp(dp->d_name, "..") == 0) {
			continue;
		}

#ifdef	DEBUG
		dprintf("media_findname_work: scanning alias \"%s\" ...\n",
		    dp->d_name);
#endif
		/*
		 * open the link and see if it points at our entry
		 */
		(void) concat_paths(pathbuf, vold_alias_dir, dp->d_name,
		    NULL);
		if ((n = readlink(pathbuf, linkbuf, MAXNAMELEN)) <= 0) {
#ifdef	DEBUG
				dprintf(
		"media_findname_work: readlink(\"%s\") failed (errno %d)\n",
				    pathbuf, errno);
#endif
			continue;
		}
		linkbuf[n] = NULLC;

#ifdef	DEBUG
		dprintf("media_findname_work: scanning link \"%s\" ...\n",
		    linkbuf);
#endif
		if (strcmp(vol_basename(linkbuf), start) == 0) {

			/* we *think* we've found a match */

			if (stat64(linkbuf, &sb) == 0) {

				if (S_ISCHR(sb.st_mode)) {
					res = strdup(linkbuf);
					goto dun;
				}

				if (S_ISDIR(sb.st_mode)) {
					res = getrawpart0(linkbuf);
					if (res != NULL) {
						free(res);
						res = strdup(linkbuf);
					}
					goto dun;
				}

			}

		}
	}

try_hack:

	/*
	 * Ok, well maybe that's not it.  Let's try the
	 * hackname alias.
	 */

	/*
	 * This creates the "hack" name.  The model
	 * is that xx# has the alias xx.  So, cdrom#
	 * and floppy# (the most frequent case) can
	 * be referred to as cdrom and floppy.
	 * We poke at what we consider to be a reasonable number of
	 * devices (currently 5) before giving up.
	 */

	for (i = 0; i < HACKNAME_MAX; i++) {
		char	num_buf[NUMBUF_SZ];


		(void) sprintf(num_buf, "%d", i);
		(void) concat_paths(pathbuf, vold_alias_dir, start, num_buf);

		if (stat64(pathbuf, &sb) == 0) {

			/* is it a char-spcl device ?? */
			if (S_ISCHR(sb.st_mode)) {
				/* it's probably a link, so... */
				if ((n = readlink(pathbuf,
				    linkbuf, MAXNAMELEN)) <= 0) {
					/* it wasn't a link */
					res = strdup(pathbuf);
				} else {
					/* it was a link */
					linkbuf[n] = NULLC;
					res = strdup(linkbuf);
				}
				goto dun;
			}

			/* not a char-spcl device -- is it a dir ?? */
			if (S_ISDIR(sb.st_mode)) {
				/* it's probably a link, so ... */
				if ((n = readlink(pathbuf,
				    linkbuf, MAXNAMELEN)) <= 0) {
					/* get fist char-spcl dev in dir */
					nameptr = pathbuf;
					s = getrawpart0(pathbuf);
				} else {
					/* it was a link */
					linkbuf[n] = NULLC;
					/* get fist char-spcl dev in dir */
					nameptr = linkbuf;
					s = getrawpart0(linkbuf);
				}
				if (s != NULL) {
					free(s);
					res = strdup(nameptr);
					goto dun;
				}
			}
		}
	}

#ifdef	DEBUG
	dprintf("media_findname_work: %s didn't match any test!\n", start);
#endif

dun:
	if (dirp != NULL) {
		(void) closedir(dirp);
	}

#ifdef	DEBUG
	dexit("media_findname_work: returning \"%s\"\n",
	    res ? res : "<null ptr>");
#endif
	return (res);
}


/*
 * deref the link (in link_buf) read from path_buf into res_buf
 *
 * if there's any problem then just return the contents of the link buffer
 */
static void
volmgt_deref_link(char *res_buf, char *path_buf, char *link_buf)
{
	static char	*vol_dirname(char *);
	char		buf[MAXPATHLEN+1];
	char		*path_dirname;


	if (IS_ABS_PATH(link_buf)) {

		/* degenerate case -- link is okay the way it is */
		(void) strncpy(res_buf, link_buf, MAXPATHLEN);

	} else {

		/* link pathname is relative */

		/* get a writable copy of the orig path */
		(void) strncpy(buf, path_buf, MAXPATHLEN);

		/* get the dir from the orig path */
		if ((path_dirname = vol_dirname(buf)) == NULL) {

			/* oh oh -- just use the link contents */
			(void) strncpy(res_buf, link_buf, MAXPATHLEN);

		} else {

			/* concat the orig dir with the link path (if room) */
			(void) concat_paths(res_buf, path_dirname, link_buf,
			    NULL);
		}
	}
}


/*
 * return the dirname part of a path (i.e. all but last component)
 *
 * NOTE: may destuctively change "path" (i.e. it may write a null over
 *	the last slash in the path to convert it into a dirname)
 */
static char *
vol_dirname(char *path)
{
	char	*cp;


	/* find the last seperator in the path */
	if ((cp = strrchr(path, '/')) == NULL) {
		/* must be just a local name -- use the local dir */
		return (".");
	}

	/* replace the last slash with a null */
	*cp = NULLC;

	/* return all but the last component */
	return (path);
}


/*
 * This function runs through the list of "old" aliases to
 * see if someone is calling a device by an old name before
 * the glory of volume management.
 */

struct alias {
	char	*alias;
	char	*name;
};

static struct alias volmgt_aliases[] = {
	{ "fd", "floppy0" },
	{ "fd0", "floppy0" },
	{ "fd1", "floppy1" },
	{ "diskette", "floppy0" },
	{ "diskette0", "floppy0" },
	{ "diskette1", "floppy1" },
	{ "rdiskette", "floppy0" },
	{ "rdiskette0", "floppy0" },
	{ "rdiskette1", "floppy1" },
	{ "cd", "cdrom0" },
	{ "cd0", "cdrom0" },
	{ "cd1", "cdrom1" },
	{ "sr", "cdrom0" },
	{ "sr0", "cdrom0" },
	{ "/dev/sr0", "cdrom0" },
	{ "/dev/rsr0", "cdrom0" },
	{ "", ""}
};


/*
 * "old" aliases -- XXX: only make sense if vold not running?
 */
static struct alias device_aliases[] = {
	{ "fd", "/dev/rdiskette" },
	{ "fd0", "/dev/rdiskette" },
	{ "fd1", "/dev/rdiskette1" },
	{ "diskette", "/dev/rdiskette" },
	{ "diskette0", "/dev/rdiskette0" },
	{ "diskette1", "/dev/rdiskette1" },
	{ "rdiskette", "/dev/rdiskette" },
	{ "rdiskette0", "/dev/rdiskette0" },
	{ "rdiskette1", "/dev/rdiskette1" },
	{ "floppy", "/dev/rdiskette" },
	{ "floppy0", "/dev/rdiskette0" },
	{ "floppy1", "/dev/rdiskette1" },
	{ "cd", "cdrom0" },
	{ "cd0", "cdrom0" },
	{ "cd1", "cdrom1" },
	{ "", ""}
};


/*
 * This is an ON Consolidation Private interface.
 */
char *
_media_oldaliases(char *start)
{
	struct alias	*s, *ns;
	char		*p;
	char		*res;



#ifdef	DEBUG
	denter("_media_oldaliases(%s): entering\n", start);
#endif

	for (s = device_aliases; *s->alias != NULLC; s++) {
		if (strcmp(start, s->alias) == 0) {
			break;
		}
	}

	/* we don't recognize that alias at all */
	if (*s->alias == NULLC) {
#ifdef	DEBUG
		dprintf("_media_oldaliases: failed\n");
#endif
		res = NULL;
		goto dun;
	}

	/* if volume management isn't running at all, give him back the name */
	if (!volmgt_running()) {
#ifdef	DEBUG
		dprintf("_media_oldaliases: no vold!\n");
#endif
		res = strdup(s->name);
		goto dun;
	}
	/*
	 * If volume management is managing that device, look up the
	 * volume management name.
	 */
	if (volmgt_inuse(s->name)) {
		for (s = volmgt_aliases; *s->alias != NULLC; s++) {
			if (strcmp(start, s->alias) == 0) {
				res = strdup(s->name);
				goto dun;
			}
		}
#ifdef	DEBUG
		dprintf("_media_oldaliases: failed\n");
#endif
		res = NULL;
		goto dun;
	}

	/*
	 * If volume management isn't managing the device, it's possible
	 * that he's given us an alias that we should recognize, but the
	 * default name is wrong.  For example a user might have his
	 * cdrom on controller 1, being managed by volume management,
	 * but we would think it isn't because volmgt_inuse just told
	 * us that c0t6d0s2 isn't being managed.  So, before we return
	 * the /dev name, we'll test the alias out using media_findname.
	 * If media_findname can't make sense out of the alias, it probably
	 * means that we really, really aren't managing the device and
	 * should just return the /dev name.  Whew.  Isn't this grody?
	 */

	for (ns = volmgt_aliases; *ns->alias != NULLC; ns++) {
		if (strcmp(start, ns->alias) == 0) {
			if ((p = media_findname_work(ns->name))) {
				res = p;
				goto dun;
			} else {
				break;
			}
		}
	}

	res = strdup(s->name);
dun:
#ifdef	DEBUG
	dexit("_media_oldaliases: returning %s\n", res ? res : "<null ptr>");
#endif
	return (res);
}


/*
 * This is an ON Consolidation Private interface.
 *
 * Print out the aliases available to the program user.  Changes
 * depending in whether volume management is running.
 */
void
_media_printaliases(void)
{
	struct alias		*s;
	DIR			*dirp;
	struct dirent64		*dp;
	char			pathbuf[MAXPATHLEN+1];
	char			*p;
	static const char	*vold_root = NULL;



	if (vold_root == NULL) {
		vold_root = volmgt_root();
	}

	if (!volmgt_running()) {
		/* no volume management */
		for (s = device_aliases; *s->alias != NULLC; s++) {
			(void) printf("\t%s -> %s\n", s->alias, s->name);
		}
		return;
	}

	for (s = volmgt_aliases; *s->alias != NULLC; s++) {
		(void) printf("\t%s -> %s\n", s->alias, s->name);
	}

	(void) concat_paths(pathbuf, (char *)vold_root, ALIAS_DIR, NULL);

	if ((dirp = opendir(pathbuf)) == NULL) {
		return;
	}
	while (dp = readdir64(dirp)) {
		if (strcmp(dp->d_name, ".") == 0) {
			continue;
		}
		if (strcmp(dp->d_name, "..") == 0) {
			continue;
		}
		if ((p = media_findname(dp->d_name)) != NULL) {
			(void) printf("\t%s -> %s\n", dp->d_name, p);
		}
	}
	(void) closedir(dirp);
}
