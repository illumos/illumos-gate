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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * routines in this module are meant to be called by other libvolmgt
 * routines only
 */

#include	<stdio.h>
#include	<string.h>
#include	<dirent.h>
#include	<fcntl.h>
#include	<string.h>
#ifdef	DEBUG
#include	<errno.h>
#endif
#include	<libintl.h>
#include	<limits.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<volmgt.h>
#include	<sys/types.h>
#include	<sys/mkdev.h>
#include	<sys/stat.h>
#include	<sys/dkio.h>
#include	<sys/param.h>
#include	<sys/wait.h>
#include	<sys/mnttab.h>
#include	"volmgt_private.h"


#define	NULL_PATH		"/dev/null"


static int	vol_getmntdev(FILE *, struct mnttab *, dev_t,
			    struct dk_cinfo *);

/*
 * This is an ON Consolidation Private interface.
 *
 * Is the specified path mounted?
 *
 * This function is really inadequate for ejection testing.  For example,
 * I could have /dev/fd0a mounted and eject /dev/fd0c, and it would be
 * ejected.  There needs to be some better way to make this check, although
 * short of looking up the mounted dev_t in the kernel mount table and
 * building in all kinds of knowledge into this function,  I'm not sure
 * how to do it.
 */
int
_dev_mounted(char *path)
{
	int		fd = -1;
	struct dk_cinfo	info;
	static FILE 	*fp = NULL;		/* mnttab file pointer */
	struct mnttab	mnt;			/* set bug not used */
	char		*cn = NULL;		/* char spcl pathname */
	struct stat64	sb;
	int		ret_val = 0;


	/* ensure we have the block spcl pathname */
	if ((cn = (char *)volmgt_getfullrawname(path)) == NULL) {
		goto dun;
	}

	if ((fp = fopen(MNTTAB, "rF")) == NULL) {
		/* mtab is gone... let it go */
		goto dun;
	}

	if ((fd = open(cn, O_RDONLY|O_NDELAY)) < 0) {
		goto dun;
	}

	if (fstat64(fd, &sb) < 0) {
		goto dun;
	}

	if (ioctl(fd, DKIOCINFO, &info) != 0) {
		goto dun;
	}

	if (vol_getmntdev(fp, &mnt, sb.st_rdev, &info) != 0) {
		ret_val = 1;			/* match found! */
	}

dun:
	if (cn != NULL) {
		free(cn);
	}
	if (fp != NULL) {
		(void) fclose(fp);
	}
	if (fd >= 0) {
		(void) close(fd);
	}
	return (ret_val);
}


static int	call_unmount_prog(int, int, char *, int, char *,
			    char *);
static int	get_media_info(char *, char **, int *, char **);
/*
 * This is an ON Consolidation Private interface.
 *
 * Forks off rmmount and (in essence) returns the result
 *
 * a return value of 0 (FALSE) means failure, non-zero (TRUE) means success
 */
int
_dev_unmount(char *path)
{
	char		*bn = NULL;		/* block name */
	char		*mtype = NULL;		/* media type */
	char		*spcl = NULL;		/* special dev. path */
	char		*spcl_failed = NULL;	/* spcl that failed */
	int		ret_val = FALSE;	/* what we return */
	char		*vr;			/* volmgt root dir */
	int		media_info_gotten = 0;
	int		mnum = 0;
	int		volume_is_not_managed;
	char		*pathbuf, *absname;


	if ((bn = (char *)volmgt_getfullblkname(path)) == NULL) {
		goto dun;
	}

	if ((pathbuf = malloc(PATH_MAX+1)) == NULL)
		goto dun;

	absname = bn;
	if (realpath(bn, pathbuf) != NULL)
		absname = pathbuf;

	volume_is_not_managed = !volmgt_running() ||
	    (!volmgt_ownspath(absname) && volmgt_symname(bn) == NULL);

	free(pathbuf);

	/* decide of we should use rmmount to unmount the media */
	if (!volume_is_not_managed) {
		int		use_rmm = FALSE;	/* use rmmount??  */

		/* at least volmgt is running */
		vr = (char *)volmgt_root();
		if (strncmp(bn, vr, strlen(vr)) == 0) {
			/* the block path is rooted in /vol */
			use_rmm = TRUE;
		}

		/* try to get info about media */
		media_info_gotten = get_media_info(bn, &mtype, &mnum, &spcl);

		ret_val = call_unmount_prog(media_info_gotten, use_rmm, mtype,
		    mnum, spcl, bn);

	} else {

		/* volmgt is *not* running */

		if (get_media_info(bn, &mtype, &mnum, &spcl)) {

			/*
			 * volmgt is off and get_media_info() has returned
			 * info on the media -- soo (this is kinda' a hack)
			 * ... we iterate, looking for multiple slices
			 * of (say) a floppy being mounted
			 *
			 * note: if an unmount fails we don't want to try
			 * to unmount the same device on the next try, so
			 * we try to watch for that
			 */

			do {
				/*
				 * don't call the unmount program is we're just
				 * trying to unmount the same device that
				 * failed last time -- if that's the case,
				 * then bail
				 */
				if (spcl_failed != NULL) {
					if (strcmp(spcl, spcl_failed) == 0) {
						break;
					}
				}
				ret_val = call_unmount_prog(TRUE, FALSE,
				    mtype, mnum, spcl, bn);

				if (!ret_val) {
					/* save spcl device name that failed */
					spcl_failed = strdup(spcl);
				} else {
					/*
					 * unmount succeeded, so clean up
					 */
					if (spcl_failed != NULL) {
						free(spcl_failed);
						spcl_failed = NULL;
					}
				}

			} while (get_media_info(bn, &mtype, &mnum, &spcl));

		} else {

			/* just do the unmmount cycle once */
			ret_val = call_unmount_prog(FALSE, FALSE, NULL, 0,
			    NULL, bn);
		}

	}

	if (mtype != NULL) {
		free(mtype);
	}
	if (spcl != NULL) {
		free(spcl);
	}
	if (spcl_failed != NULL) {
		free(spcl_failed);
	}
	if (bn != NULL) {
		free(bn);
	}

dun:

	return (ret_val);
}


/*
 * find a mnttab entry that has the same dev as the supplied dev,
 *  returning it and a non-zero value if found, else returning 0
 *
 * this is just like getmntany(), except that it scans based on st_rdev,
 * and it even finds different slices on the same device/unit (thanx to
 * code copied from format.c)
 */
static int
vol_getmntdev(FILE *fp, struct mnttab *mp, dev_t dev, struct dk_cinfo *ip)
{
	int		fd;		/* dev-in-question fd */
	struct stat64	sb;		/* dev-in-question stat struct */
	int		ret_val = 0;	/* default value: no match found */
	char		*cn;		/* char pathname */
	struct dk_cinfo	dkinfo;		/* for testing for slices */


#ifdef	DEBUG
	denter(
	    "vol_getmntdev: entering for %d.%d, ctype/cnum/unit = %d/%d/%d\n",
	    (int)major(dev), (int)minor(dev), ip->dki_ctype, ip->dki_cnum,
	    ip->dki_unit);
#endif

	/* reset the mnttab -- just in case */
	rewind(fp);

	/* scan each entry in mnttab */
	while (getmntent(fp, mp) == 0) {

		/* don't even try unless it's a local pathname */
		if (mp->mnt_special[0] != '/') {
			continue;
		}

		/* get char pathname */
		if ((cn = volmgt_getfullrawname(mp->mnt_special)) == NULL) {
			continue;
		}
		if (cn[0] == NULLC) {
			free(cn);
			continue;	/* couldn't get raw name */
		}

		/* open the device */
		if ((fd = open(cn, O_RDONLY|O_NDELAY)) < 0) {
			/* if we can't open it *assume* it's not a match */
			free(cn);
			continue;
		}

		/* stat the device */
		if (fstat64(fd, &sb) < 0) {
			free(cn);
			(void) close(fd);
			continue;	/* ain't there: can't be a match */
		}

		/* ensure we have a spcl device (a double check) */
		if (!S_ISBLK(sb.st_mode) && !S_ISCHR(sb.st_mode)) {
			free(cn);
			(void) close(fd);
			continue;
		}

		/* (almost) finally -- check the dev_t for equality */
		if (sb.st_rdev == dev) {
			ret_val = 1;		/* match found! */
			free(cn);
			(void) close(fd);
			break;
		}

		/*
		 * check that the major numbers match, since if they
		 * don't then there's no reason to use the DKIOCINFO
		 * ioctl to see if we have to major/minor pairs that
		 * really point to the same device
		 */
		if (major(sb.st_rdev) != major(dev)) {
			/* no use continuing, since major devs are different */
			free(cn);
			(void) close(fd);
			continue;
		}

		/* one last check -- for diff. slices of the same dev/unit */
		if (ioctl(fd, DKIOCINFO, &dkinfo) < 0) {
			free(cn);
			(void) close(fd);
			continue;
		}

		free(cn);		/* all done with raw pathname */
		(void) close(fd);	/* all done with file descriptor */

		/* if ctrler type/number and unit match, it's a match */
		if ((ip->dki_ctype == dkinfo.dki_ctype) &&
		    (ip->dki_cnum == dkinfo.dki_cnum) &&
		    (ip->dki_unit == dkinfo.dki_unit)) {
			/*
			 * even though minor numbers differ we have a
			 * match
			 */
			ret_val = 1;
			break;
		}

		/* go around again */
	}

	return (ret_val);
}


char *
vol_basename(char *path)
{
	char	*cp;


	/* check for the degenerate case */
	if (strcmp(path, "/") == 0) {
		return (path);
	}

	/* look for the last slash in the name */
	if ((cp = strrchr(path, '/')) == NULL) {
		/* no slash */
		return (path);
	}

	/* ensure something is after the slash */
	if (*++cp != NULLC) {
		return (cp);
	}

	/* a name that ends in slash -- back up until previous slash */
	while (cp != path) {
		if (*--cp == '/') {
			return (--cp);
		}
	}

	/* the only slash is the end of the name */
	return (path);
}

static int	vol_getmntdev(FILE *, struct mnttab *, dev_t,
			    struct dk_cinfo *);

static int
get_media_info(char *path, char **mtypep, int *mnump, char **spclp)
{
	FILE		*fp = NULL;
	int		fd = -1;
	char		*cn = NULL;		/* char spcl pathname */
	struct stat64	sb;
	struct dk_cinfo	info;
	struct mnttab	mnt;
	int		ret_val = FALSE;

	if ((fp = fopen(MNTTAB, "rF")) == NULL) {
		/* mtab is gone... let it go */
		goto dun;
	}

	/* get char spcl pathname */
	if ((cn = volmgt_getfullrawname(path)) == NULL) {
		goto dun;
	}
	if (cn[0] == NULLC) {
		goto dun;
	}

	if ((fd = open(cn, O_RDONLY|O_NDELAY)) < 0) {
		goto dun;
	}

	if (fstat64(fd, &sb) < 0) {
		goto dun;
	}

	if (ioctl(fd, DKIOCINFO, &info) != 0) {
		goto dun;
	}

	/* if we found the entry then disect it */
	if (vol_getmntdev(fp, &mnt, sb.st_rdev, &info) != 0) {
		char		*cp;
		char		*mtype;
		char		*mnt_dir;
		int		mtype_len;
		DIR		*dirp = NULL;
		struct dirent64	*dp;
		char		*volname;


		/* return the spcl device name found */
		*spclp = strdup(mnt.mnt_special);

		/*
		 * try to get the media type (e.g. "floppy") from the mount
		 * point (e.g. "/floppy/NAME") if vold is running
		 */

		if (!volmgt_running() ||
		    (!volmgt_ownspath(*spclp) &&
		    volmgt_symname(*spclp) == NULL)) {
			ret_val = TRUE;		/* success (if limited) */
			goto dun;
		}

		/* get the first part of the mount point (e.g. "floppy") */
		cp = mnt.mnt_mountp;
		if (*cp++ != '/') {
			goto dun;
		}
		mtype = cp;
		if ((cp = strchr(mtype, '/')) == NULL) {
			goto dun;
		}
		*cp++ = NULLC;
		mnt_dir = mnt.mnt_mountp;	/* save dir path */

		/* get the volume name (e.g. "unnamed_floppy") */
		volname = cp;

		/* scan for the symlink that points to our volname */
		if ((dirp = opendir(mnt_dir)) == NULL) {
			goto dun;
		}
		mtype_len = strlen(mtype);
		while ((dp = readdir64(dirp)) != NULL) {
			char		lpath[2 * (MAXNAMELEN+1)];
			char		linkbuf[MAXPATHLEN+4];
			int		lb_len;
			struct stat64	sb;


			if (strncmp(dp->d_name, mtype, mtype_len) != 0) {
				continue;	/* not even close */
			}

			(void) sprintf(lpath, "%s/%s", mnt_dir,
			    dp->d_name);
			if (lstat64(lpath, &sb) < 0) {
				continue;	/* what? */
			}
			if (!S_ISLNK(sb.st_mode)) {
				continue;	/* not our baby */
			}
			if ((lb_len = readlink(lpath, linkbuf,
			    sizeof (linkbuf))) < 0) {
				continue;
			}
			linkbuf[lb_len] = NULLC; /* null terminate */
			if ((cp = vol_basename(linkbuf)) == NULL) {
				continue;
			}
			/* now we have the name! */
			if (strcmp(cp, volname) == 0) {
				/* found it !! */
				if (sscanf(dp->d_name + mtype_len, "%d",
				    mnump) == 1) {
					*mtypep = strdup(mtype);
					ret_val = TRUE;
				}
				break;
			}
		}
		(void) closedir(dirp);
	}

dun:
	if (fp != NULL) {
		(void) fclose(fp);
	}
	if (fd >= 0) {
		(void) close(fd);
	}
	if (cn != NULL) {
		free(cn);
	}
#ifdef	DEBUG
	if (ret_val) {
		dexit("get_media_info: returning mtype=%s, mnum=%d, spcl=%s\n",
		    *mtypep == NULL ? "<null ptr>" : *mtypep,
		    *mnump,
		    *spclp == NULL ? "<null ptr>" : *spclp);
	} else {
		dexit("get_media_info: FAILED\n");
	}
#endif
	return (ret_val);
}


/*
 * call the appropriate unmount program, returning its success (TRUE)
 * or failure (FALSE)
 */
static int
call_unmount_prog(int mi_gotten, int use_rmm, char *mtype, int mnum,
    char *spcl, char *bn)
{
	pid_t		pid;			/* forked proc's pid */
	int		ret_val = FALSE;
	const char	*etc_umount = "/etc/umount";
	const char	*rmm = "/usr/sbin/rmmount";
	int		rval;			/* proc's return value */


#ifdef	DEBUG
	denter(
	"call_unmount_prog(%s, %s, \"%s\", %d, \"%s\", \"%s\"): entering\n",
	    mi_gotten ? "TRUE" : "FALSE", use_rmm ? "TRUE" : "FALSE",
	    mtype ? mtype : "<null ptr>", mnum, spcl ? spcl : "<null ptr>",
	    bn);
#endif
	/* create a child to unmount the path */
	if ((pid = fork()) < 0) {
		goto dun;
	}

	if (pid == 0) {
		/* the child */
#ifndef	DEBUG
		int		xfd;
#endif
		char		env_buf[MAXPATHLEN];

#ifndef	DEBUG
		/* get rid of those nasty err messages */
		if ((xfd = open(NULL_PATH, O_RDWR)) >= 0) {
			(void) dup2(xfd, fileno(stdin));
			(void) dup2(xfd, fileno(stdout));
			(void) dup2(xfd, fileno(stderr));
		}
#endif

		if (use_rmm) {
			/* set up environment vars */
			(void) putenv("VOLUME_ACTION=eject");
			(void) putenv(strdup(env_buf));
			if (mi_gotten) {
				(void) sprintf(env_buf,
				    "VOLUME_MEDIATYPE=%s", mtype);
				(void) putenv(strdup(env_buf));
				(void) sprintf(env_buf, "VOLUME_SYMDEV=%s%d",
				    mtype, mnum);
				(void) putenv(strdup(env_buf));
				(void) sprintf(env_buf, "VOLUME_PATH=%s",
				    spcl);
				(void) putenv(strdup(env_buf));
				(void) sprintf(env_buf, "VOLUME_NAME=%s",
				    vol_basename(spcl));
				(void) putenv(strdup(env_buf));
			} else {
				(void) sprintf(env_buf, "VOLUME_PATH=%s", bn);
				(void) putenv(strdup(env_buf));
				(void) sprintf(env_buf, "VOLUME_NAME=%s",
				    vol_basename(bn));
				(void) putenv(strdup(env_buf));
			}
#ifdef	DEBUG
			dprintf("call_unmount_prog: calling \"%s -D\"\n", rmm);
			(void) execl(rmm, rmm, "-D", NULL);
#else
			(void) execl(rmm, rmm, NULL);
#endif
		} else {
#ifdef	DEBUG
			dprintf("call_unmount_prog: calling \"%s %s\"\n",
			    etc_umount, mi_gotten ? spcl : bn);
#endif
			(void) execl(etc_umount, etc_umount,
			    mi_gotten ? spcl : bn,
			    NULL);
		}
		exit(-1);
		/*NOTREACHED*/
	}

	/* wait for the umount command to exit */
	if (waitpid(pid, &rval, 0) == pid) {
		if (WIFEXITED(rval)) {
			if (WEXITSTATUS(rval) == 0) {
				ret_val = TRUE;	/* success */
			}
		}
	}

dun:
	return (ret_val);
}
