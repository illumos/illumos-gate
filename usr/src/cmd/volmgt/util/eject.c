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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Program to eject oen or more pieces of media.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	<rpc/types.h>
#include	<sys/stat.h>
#include	<sys/fdio.h>
#include	<sys/dkio.h>
#include	<sys/param.h>
#include	<sys/wait.h>
#include	<dirent.h>
#include	<fcntl.h>
#include	<string.h>
#include	<errno.h>
#include	<locale.h>
#include	<libintl.h>
#include	<unistd.h>
#include	<pwd.h>
#include	<volmgt.h>
#include	<sys/mnttab.h>
#include	<signal.h>



static char	*prog_name = NULL;
static bool_t	force_eject = FALSE;
static bool_t	do_query = FALSE;
static bool_t	no_popup = FALSE;
static uid_t	myuid;

static int	work(char *);
static void	usage(void);
static char	*getdefault(void);
static int	ejectit(char *, bool_t);
static bool_t	query(char *, bool_t);
static bool_t	winsysck(struct passwd *);
static bool_t	popup_msg(struct passwd *, char *);
static bool_t	floppy_in_drive(char *, int);
static bool_t	manually_ejectable(char *);
static bool_t	display_busy(char *, bool_t);
static char	*eject_getfullblkname(char *, bool_t);
extern char	*getfullrawname(char *);

/*
 * ON-private libvolmgt routines
 */
extern int	_dev_mounted(char *);
extern int	_dev_unmount(char *);
extern char	*_media_oldaliases(char *);
extern void	_media_printaliases(void);


/*
 * Hold over from old eject.
 * returns exit codes:	(KEEP THESE - especially important for query)
 *	0 = -n, -d or eject operation was ok, -q = media in drive
 *	1 = -q only = media not in drive
 *	2 = various parameter errors, etc.
 *	3 = eject ioctl failed
 * New Value (2/94)
 *	4 = eject partially succeeded, but now manually remove media
 */

#define	EJECT_OK		0
#define	EJECT_NO_MEDIA		1
#define	EJECT_PARM_ERR		2
#define	EJECT_IOCTL_ERR		3
#define	EJECT_MAN_EJ		4

#define	CONSOLE			"/dev/console"
#define	BIT_BUCKET		"/dev/null"

#define	EJECT_POPUP_PATH	"/usr/dt/lib/eject_popup"
#define	EJECT_POPUP		"eject_popup"

#define	OW_WINSYSCK_PATH	"/usr/openwin/bin/winsysck"
#define	OW_WINSYSCK		"winsysck"
#define	OW_WINSYSCK_PROTOCOL	"x11"

#define	AVAIL_MSG		"%s is available\n"
#define	NOT_AVAIL_MSG		"%s is not available\n"

#define	OK_TO_EJECT_MSG		"%s can now be manually ejected\n"

#define	FLOPPY_MEDIA_TYPE	"floppy"
#define	CDROM_MEDIA_TYPE	"cdrom"

#define	MEJECT_PROP		"s-mejectable"
#define	PROP_TRUE		"true"

/*
 * the call to winsysck() may hang if the xserver is running
 * and there are no x-protocalls to be identified. This
 * timeout is to break parent off of the waitpid() waiting on
 * return of winsysck() which will never arrive
 */
#define	TIMEOUT_ON_WAITPID	2


void
main(int argc, char **argv)
{
	int		c;
	const char	*opts = "dqfnp";
	char		*s;
	int		excode;
	int		res;
	bool_t		err_seen = FALSE;
	bool_t		man_eject_seen = FALSE;
	bool_t		do_pdefault = FALSE;
	bool_t		do_paliases = FALSE;



	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	myuid = getuid();
	(void) seteuid(myuid);

	prog_name = argv[0];

	/* process arguments */
	while ((c = getopt(argc, argv, opts)) != EOF) {
		switch (c) {
		case 'd':
			do_pdefault = TRUE;
			break;
		case 'q':
			do_query = TRUE;
			break;
		case 'n':
			do_paliases = TRUE;
			break;
		case 'f':
			force_eject = TRUE;
			break;
		case 'p':
			no_popup = TRUE;
			break;
		default:
			usage();
			exit(EJECT_PARM_ERR);
		}
	}

	if (do_pdefault) {
		s = getdefault();
		(void) fprintf(stderr,
		    gettext("Default device is: %s\n"),
		    ((s == NULL) ? gettext("nothing inserted") : s));
		exit(EJECT_OK);
	}

	if (do_paliases) {
		_media_printaliases();
		exit(EJECT_OK);
	}

	if (argc == optind) {
		/* no argument -- use the default */
		if ((s = getdefault()) == NULL) {
			(void) fprintf(stderr,
			    gettext("No default media available\n"));
			exit(EJECT_NO_MEDIA);
		}
		/* (try to) eject default media */
		excode = work(s);
	} else {
		/* multiple things to eject */
		for (; optind < argc; optind++) {
			res = work(argv[optind]);
			if (res == 4) {
				man_eject_seen = TRUE;
			} else if (res != EJECT_OK) {
				err_seen = TRUE;
			}
		}
		if (err_seen) {
			if (do_query)
				excode = res;
			else
				excode = EJECT_IOCTL_ERR;
		} else if (man_eject_seen) {
			excode = EJECT_MAN_EJ;
		} else {
			excode = EJECT_OK;
		}
	}

	exit(excode);
}

/*
 * eject's sig alarm
 * This is to knock the parent process off of waitpid(), because
 * if waitpid() fails to return within a couple seconds it never
 * will.
 * Therefor, we do nothing - just return...
 */
static void
ej_sig_alrm(int signo)
{
#ifdef lint
	signo = signo;
#endif
	/* do nothing, return to interrupt the waitpid */
}


/*
 * given a directory name find the first char- or block-spcl device under
 * it
 *
 * return the supplied path if no spcl device found
 *
 * NOTE: return value points to a status area overwritten with
 * each call
 */
static char *
getrawpart0(char *path)
{
	static char		res[MAXPATHLEN+1];
	int			len;
	char			wbuf[MAXPATHLEN+1];
	int			len_avail;
	char			*wptr;
	DIR			*dirp;
	struct dirent64		*dp;
	struct stat64		sb;



	/* set up the default and the work buffer */
	if ((len = strlen(path)) >= MAXPATHLEN) {
		return (NULL);
	}
	len_avail = (MAXPATHLEN - len) - 1;
	(void) strcpy(res, path);
	(void) strcpy(wbuf, path);
	wptr = wbuf + len;
	*wptr++ = '/';

	/* scan directory */
	if ((dirp = opendir(path)) != NULL) {
		while ((dp = readdir64(dirp)) != NULL) {
			if ((strcmp(dp->d_name, ".") == 0) ||
			    (strcmp(dp->d_name, "..") == 0)) {
				continue;
			}
			if (strlen(dp->d_name) > len_avail) {
				/* XXX: just skip this entry?? */
				continue;
			}
			(void) strcpy(wptr, dp->d_name);
			if (stat64(wbuf, &sb) == 0) {
				if (S_ISCHR(sb.st_mode) ||
				    S_ISBLK(sb.st_mode)) {
					/* success!! */
					(void) strcpy(res, wbuf);
					break;
				}
			}
		}
		(void) closedir(dirp);
	}

	return (res);

}


/*
 * the the real work of ejecting (and notifying)
 */
static int
work(char *arg)
{
	char 		*name;
	char 		*name1;
	int		excode = EJECT_OK;
	bool_t		volmgt_is_running;
	struct stat64	sb;



	/* keep track of if vold is or isn't running */
	volmgt_is_running = (volmgt_running() != 0) ? TRUE : FALSE;

	/*
	 * NOTE: media_findname (effectively) does a "volcheck all" if the
	 *  name passed in isn't an absolute pathname, or a name under
	 *  /vol/rdsk. This is not good when the user runs something
	 *  like "eject fd cd" on an intel, since the cd is "all but manually
	 *  ejected" (as it should be), but then "cd" is not found, so
	 *  a "volcheck all" is done, which remounts the floppy!
	 *
	 *  So, we run media_olaliases() first, to try to find the name before
	 *  running volcheck.
	 *
	 * on the other hand, if vold is *not* running, then we *just* do the
	 * old aliases
	 */

	/* check to see if name is an alias (e.g. "fd" or "flopy") */
	if ((name1 = _media_oldaliases(arg)) == NULL) {
		name1 = arg;
	}

	if (volmgt_is_running) {

		/*
		 * name is not an alias -- check for abs. path or
		 * /vol/rdsk name
		 */
		if ((name = media_findname(name1)) == NULL) {
			/*
			 * name is not an alias, an absolute path, or a name
			 *  under /vol/rdsk -- let's just use the name given
			 */
			name = name1;
		} else {
			/*
			 * we have to check for a directory name being
			 * returned from media_findname(), changing it
			 * to a devname if it is
			 */
			if (stat64(name, &sb) == 0) {
				if (S_ISDIR(sb.st_mode)) {
					if ((name1 = getrawpart0(name)) !=
					    NULL) {
						name = name1;
					}
				}
			}
		}

	} else {

		/* vold *not* running -- try to do what we can */
		name = name1;
	}

	/*
	 * Since eject is a suid root program, we must make sure
	 * that the user running us is allowed to eject the media.
	 * All a user has to do to issue the eject ioctl is open
	 * the file for reading, so that's as restrictive as we'll be.
	 */

	/*
	 * Two cases for name. One is like "floppy", access() will fail
	 * for sure.  If do_query==1, we should return EJECT_NO_MEDIA instead
	 * of EJECT_PARM_ERR. The other is like /vol/dev/rdiskette0 and
	 * access() will be ok since it is a directory
	 * in the schema of things for volmgmt, we should fail that the same
	 * way too.
	 */
	if (access(name, R_OK) != 0) {
		if (do_query) {
			(void) fprintf(stderr, gettext("%s: no media\n"), name);
			return (EJECT_NO_MEDIA);
		} else {
			perror(name);
			return (EJECT_PARM_ERR);
		}
	}

	if (do_query) {
		if ((stat64(name, &sb) == 0) && S_ISDIR(sb.st_mode)) {
			/* don' t let directory name go through query() code */
			(void) fprintf(stderr, gettext("%s: no media\n"), name);
			return (EJECT_NO_MEDIA);
		}
		if (!query(name, TRUE)) {
			excode = EJECT_NO_MEDIA;
		}
	} else {
		excode = ejectit(name, volmgt_is_running);
	}
	return (excode);
}


static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: %s [-fndq] [name | nickname]\n"),
	    prog_name);
	(void) fprintf(stderr,
	    gettext("options:\t-f force eject\n"));
	(void) fprintf(stderr,
	    gettext("\t\t-n show nicknames\n"));
	(void) fprintf(stderr,
	    gettext("\t\t-d show default device\n"));
	(void) fprintf(stderr,
	    gettext("\t\t-q query for media present\n"));
	(void) fprintf(stderr,
	    gettext("\t\t-p do not call eject_popup\n"));
}


static int
ejectit(char *name, bool_t volmgt_is_running)
{
	int 		fd, r;
	FILE  		*console_fp;
	bool_t		mejectable = FALSE;	/* manually ejectable */
	int		result = EJECT_OK;
	struct passwd	*pw = NULL;
	bool_t		do_manual_console_message = FALSE;
	bool_t		volume_is_not_managed;
	char		path[MAXPATHLEN];
	char		*absname = name;

	if (realpath(name, path) != NULL)
		absname = path;

	volume_is_not_managed = !volmgt_is_running ||
		(!volmgt_ownspath(absname) && volmgt_symname(name) == NULL);

	/*
	 * If volume management is either not running or not being managed by
	 * vold, and the device is mounted, we try to umount the device.  If we
	 * fail, we give up, unless he used the -f flag.
	 */

	if (volume_is_not_managed && _dev_mounted(name)) {
		(void) seteuid(0);
		r = _dev_unmount(name);
		(void) seteuid(myuid);
		if (r == 0) {
			if (!force_eject) {
				(void) fprintf(stderr,
gettext("WARNING: can not unmount %s, the file system is (probably) busy\n"),
					name);
				return (EJECT_PARM_ERR);
			} else {
				(void) fprintf(stderr,
gettext("WARNING: %s has a mounted filesystem, ejecting anyway\n"),
					name);
			}
		}
	}

	/*
	 * Require O_NDELAY for when floppy is not formatted
	 * will still id floppy in drive
	 */

	if (volume_is_not_managed) {
		/*
		 * make sure we are dealing with a raw device
		 *
		 * XXX: NOTE: results from getfullrawname()
		 * really should be free()d when no longer
		 * in use
		 */
		name = getfullrawname(name);
	}

	if ((fd = open(name, O_RDONLY | O_NDELAY)) < 0) {
		if (errno == EBUSY) {
			(void) fprintf(stderr,
gettext("%s is busy (try 'eject floppy' or 'eject cdrom'?)\n"),
			    name);
			return (EJECT_PARM_ERR);
		}
		perror(name);
		return (EJECT_PARM_ERR);
	}

	/* see if media is manually ejectable (i.e. we can't do it) */
	if (volume_is_not_managed == FALSE) {
		mejectable = manually_ejectable(name);
	}

	/* try to eject the volume */
	if (ioctl(fd, DKIOCEJECT, 0) < 0) {

		/* check on why eject failed */

		/* check for no floppy in manually ejectable drive */
		if ((errno == ENOSYS) && volume_is_not_managed &&
		    !floppy_in_drive(name, fd)) {
			/* use code below to handle "not present" */
			errno = ENXIO;
		}

		/*
		 * Dump this message to stderr. This handles the
		 * case where the window system is not running
		 * and also works in case the user has run this
		 * via an rlogin to the remote volmgt console.
		 */
		if (errno == ENOSYS || errno == ENOTSUP) {
			(void) fprintf(stderr, gettext(OK_TO_EJECT_MSG), name);
		}

		if ((errno == ENOSYS || errno == ENOTSUP) &&
		    (volume_is_not_managed || mejectable)) {
			/*
			 * Make sure we know who *really* fired up this
			 * command. We'll need this information to connect
			 * to the user X display.
			 */

			pw = getpwuid(myuid);

#ifdef DEBUG
			if (pw != NULL) {
				(void) fprintf(stderr,
				    "DEBUG: ejectit: username = '%s'\n",
				    pw->pw_name);
				(void) fprintf(stderr,
				    "DEBUG: ejectit: uid = %d\n", pw->pw_uid);
				(void) fprintf(stderr,
				    "DEBUG: ejectit: gid = %d\n", pw->pw_gid);
				(void) fprintf(stderr,
				    "DEBUG: ejectit: euid = %ld\n", geteuid());
				(void) fprintf(stderr,
				    "DEBUG: ejectit: egid = %ld\n", getegid());
			} else {
				(void) fprintf(stderr,
				    "DEBUG: ejectit: getpwuid() failed\n");
			}
#endif

			/* if user doesn't want popup then stop here */
			if (no_popup) {
				do_manual_console_message = TRUE;
			}

			/*
			 * If user is running some X windows system
			 * we'll display a popup to the console.
			 * If not, dump message to console.
			 *
			 * (To keep from having to actually check for X
			 * running, we'll just try to run the popup, assuming
			 * it will fail if windows are not running.)
			 */
			if (!do_manual_console_message) {
				if ((access(EJECT_POPUP_PATH, X_OK) != 0) ||
				    (access(OW_WINSYSCK_PATH, X_OK) != 0) ||
				    (pw == NULL)) {
					do_manual_console_message = TRUE;
				}
			}

			if (!do_manual_console_message) {
				if (!winsysck(pw)) {
					do_manual_console_message = TRUE;
				}
			}

			if (!do_manual_console_message) {
				if (!popup_msg(pw, name)) {
					do_manual_console_message = TRUE;
				}
			}
			/*
			 * only output to console if requested and it's
			 * not the same as stderr
			 */
			if (do_manual_console_message) {
				char	*ttynm = ttyname(fileno(stderr));

				if ((ttynm != NULL) &&
				    (strcmp(ttynm, CONSOLE) != 0)) {
					(void) seteuid(0);
					console_fp = fopen(CONSOLE, "a");
					(void) seteuid(myuid);
					if (console_fp != NULL) {
						(void) fprintf(console_fp,
						    gettext(OK_TO_EJECT_MSG),
						    name);
						(void) fclose(console_fp);
					}
				}
			}

			/*
			 * keep track of the fact that this is a manual
			 * ejection
			 */
			result = EJECT_MAN_EJ;

		} else if (errno == EBUSY) {
			/*
			 * if our pathname is s slice (UFS is great) then
			 * check to see what really is busy
			 */
			if (!display_busy(name, volmgt_is_running)) {
				perror(name);
			}
			result = EJECT_IOCTL_ERR;

		} else if ((errno == EAGAIN) || (errno == ENODEV) ||
		    (errno == ENXIO)) {
			(void) fprintf(stderr,
			    gettext("%s not present in a drive\n"),
			    name);
			result = EJECT_OK;
		} else {
			perror(name);
			result = EJECT_IOCTL_ERR;
		}
	}

	(void) close(fd);
	return (result);
}


/*
 * return TRUE if a floppy is in the drive, FALSE otherwise
 *
 * this routine assumes that the file descriptor passed in is for
 * a floppy disk.  this works because it's only called if the device
 * is "manually ejectable", which only (currently) occurs for floppies.
 */
static bool_t
floppy_in_drive(char *name, int fd)
{
	int	ival = 0;			/* ioctl return value */
	bool_t	rval = FALSE;			/* return value */


	if (ioctl(fd, FDGETCHANGE, &ival) >= 0) {
		if (!(ival & FDGC_CURRENT)) {
			rval = TRUE;		/* floppy is present */
		}
	} else {
		/* oh oh -- the ioctl failed -- it's not a floppy */
		(void) fprintf(stderr, gettext("%s is not a floppy disk\n"),
		    name);
	}

	return (rval);
}


/*
 * display a "busy" message for the supplied pathname
 *
 * if the pathname is not a slice, then just display a busy message
 * else if the pathname is some slice subdirectory then look for the
 * *real* culprits
 *
 * if this is not done then the user can get a message like
 *	/vol/dev/rdsk/c0t6d0/solaris_2_5_sparc/s5: Device busy
 * when they try to eject "cdrom0", but "s0" (e.g.) may be the only busy
 * slice
 *
 * return TRUE iff we printed the appropriate error message, else
 * return FALSE (and caller will print error message itself)
 */
static bool_t
display_busy(char *path, bool_t vm_running)
{
	int		errno_save = errno;	/* to save errno */
	char		*blk;			/* block name */
	extern char	*sys_errlist[];		/* see perror(3) */
	FILE		*fp = NULL;		/* for scanning mnttab */
	struct mnttab	mref;			/* for scanning mnttab */
	struct mnttab	mp;			/* for scanning mnttab */
	bool_t		res = FALSE;		/* return value */
	char		busy_base[MAXPATHLEN];	/* for keeping base dir name */
	uint_t		bblen;			/* busy_base string length */
	char		*cp;			/* for truncating path */



#ifdef	DEBUG
	(void) fprintf(stderr, "display_busy(\"%s\"): entering\n", path);
#endif

	/*
	 * get the block pathname.
	 * eject_getfullblkname returns NULL or pathname which
	 * has length < MAXPATHLEN.
	 */
	blk = eject_getfullblkname(path, vm_running);
	if (blk == NULL)
		goto dun;

	/* open mnttab for scanning */
	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		/* can't open mnttab!? -- give up */
		goto dun;
	}

	(void) memset((void *)&mref, '\0', sizeof (struct mnttab));
	mref.mnt_special = blk;
	if (getmntany(fp, &mp, &mref) == 0) {
		/* we found our entry -- we're done */
		goto dun;
	}

	/* perhaps we have a sub-slice (which is what we exist to test for) */

	/* create a base pathname */
	(void) strcpy(busy_base, blk);
	if ((cp = strrchr(busy_base, '/')) == NULL) {
		/* no last slash in pathname!!?? -- give up */
		goto dun;
	}
	*cp = '\0';
	bblen = strlen(busy_base);
	/* bblen = (uint)(cp - busy_base); */

	/* scan for matches */
	rewind(fp);				/* rescan mnttab */
	while (getmntent(fp, &mp) == 0) {
		/*
		 * work around problem where '-' in /etc/mnttab for
		 * special device turns to NULL which isn't expected
		 */
		if (mp.mnt_special == NULL)
			mp.mnt_special = "-";
		if (strncmp(busy_base, mp.mnt_special, bblen) == 0) {
			res = TRUE;
			(void) fprintf(stderr, "%s: %s\n", mp.mnt_special,
			    sys_errlist[EBUSY]);
		}
	}

dun:
	if (fp != NULL) {
		(void) fclose(fp);
	}
#ifdef	DEBUG
	(void) fprintf(stderr, "display_busy: returning %s\n",
	    res ? "TRUE" : "FALSE");
#endif
	errno = errno_save;
	return (res);
}


/*
 * In my experience with removable media drivers so far... the
 * most reliable way to tell if a piece of media is in a drive
 * is simply to open it.  If the open works, there's something there,
 * if it fails, there's not.  We check for two errnos which we
 * want to interpret for the user,  ENOENT and EPERM.  All other
 * errors are considered to be "media isn't there".
 *
 * return TRUE if media found, else FALSE (XXX: was 0 and -1)
 */
static bool_t
query(char *name, bool_t doprint)
{
	int		fd;
	int		rval;			/* FDGETCHANGE return value */
	enum dkio_state	state;

	if ((fd = open(name, O_RDONLY|O_NONBLOCK)) < 0) {
		if ((errno == EPERM) || (errno == ENOENT)) {
			if (doprint) {
				perror(name);
			}
		} else {
			if (doprint) {
				(void) fprintf(stderr, gettext(NOT_AVAIL_MSG),
				    name);
			}
		}
		return (FALSE);
	}

	rval = 0;
	if (ioctl(fd, FDGETCHANGE, &rval) >= 0) {
		/* hey, it worked, what a deal, it must be a floppy */
		(void) close(fd);
		if (!(rval & FDGC_CURRENT)) {
			if (doprint) {
				(void) fprintf(stderr, gettext(AVAIL_MSG),
				    name);
			}
			return (TRUE);
		}
		if (rval & FDGC_CURRENT) {
			if (doprint) {
				(void) fprintf(stderr,	gettext(NOT_AVAIL_MSG),
				    name);
			}
			return (FALSE);
		}
	}

again:
	state = DKIO_NONE;
	if (ioctl(fd, DKIOCSTATE, &state) >= 0) {
		/* great, the fancy ioctl is supported. */
		if (state == DKIO_INSERTED) {
			if (doprint) {
				(void) fprintf(stderr, gettext(AVAIL_MSG),
				    name);
			}
			(void) close(fd);
			return (TRUE);
		}
		if (state == DKIO_EJECTED) {
			if (doprint) {
				(void) fprintf(stderr,	gettext(NOT_AVAIL_MSG),
				    name);
			}
			(void) close(fd);
			return (FALSE);
		}
		/*
		 * Silly retry loop.
		 */
		(void) sleep(1);
		goto again;
	}
	(void) close(fd);

	/*
	 * Ok, we've tried the non-blocking/ioctl route.  The
	 * device doesn't support any of our nice ioctls, so
	 * we'll just say that if it opens it's there, if it
	 * doesn't, it's not.
	 */
	if ((fd = open(name, O_RDONLY)) < 0) {
		if (doprint) {
			(void) fprintf(stderr, gettext(NOT_AVAIL_MSG), name);
		}
		return (FALSE);
	}

	(void) close(fd);
	if (doprint) {
		(void) fprintf(stderr, gettext(AVAIL_MSG), name);
	}
	return (TRUE);	/* success */
}


/*
 * The assumption is that someone typed eject to eject some piece
 * of media that's currently in a drive.  So, what we do is
 * check for floppy then cdrom.  If there's nothing in either,
 * we just return NULL.
 */
static char *
getdefault(void)
{
	char		*s;


	/* if vold running then ask it about a floppy, then a cdrom */
	if (volmgt_running()) {
		if ((s = media_findname(FLOPPY_MEDIA_TYPE)) != NULL) {
			if (query(s, FALSE)) {
				return (s);
			}
		}
		if ((s = media_findname(CDROM_MEDIA_TYPE)) != NULL) {
			if (query(s, FALSE)) {
				return (s);
			}
		}
	}

	/* no match yet -- try non-volmgt guesses */
	if ((s = _media_oldaliases(FLOPPY_MEDIA_TYPE)) != NULL) {
		if (query(s, FALSE)) {
			return (s);
		}
	}

	/* no default device */
	return (NULL);
}


/*
 * Check to see if the specified device is manually ejectable, using
 * the media_getattr() call
 */
static bool_t
manually_ejectable(char *dev_path)
{
	char		*eprop;


	if ((eprop = media_getattr(dev_path, MEJECT_PROP)) == 0) {
		/* equivalent to FALSE ? */
		return (FALSE);
	}

	/* return result based on string returned */
	return ((strcmp(eprop, PROP_TRUE) == 0) ? TRUE : FALSE);

}


/*
 * Use a popup window to display the "manually ejectable"
 * message for X86 machines.
 *
 * return flase if the popup fails, else return TRUE
 */
static bool_t
popup_msg(struct passwd *pw, char *name)
{
	pid_t		pid;
	int		exit_code = -1;
	bool_t		ret_val = FALSE;
	int		fd;
	char		ld_lib_path[MAXPATHLEN];
	char		*home_dir;

	/*
	 * fork a simple X Windows program to display gui for
	 * notifying the user that the specified media must be
	 * manually removed.
	 */

	if ((pid = fork()) < 0) {
		(void) fprintf(stderr,
		    gettext("error: can't fork a process (errno %d)\n"),
		    errno);
		goto dun;
	}

	if (pid == 0) {

		/*
		 * Error messages to console
		 */

		(void) seteuid(0);
		fd = open(CONSOLE, O_RDWR);
		(void) seteuid(myuid);
		if (fd >= 0) {
			(void) dup2(fd, fileno(stdin));
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
		}

		/*
		 * Set up the users environment.
		 */

		(void) putenv("DISPLAY=:0.0");
		(void) putenv("OPENWINHOME=/usr/openwin");

		(void) sprintf(ld_lib_path, "LD_LIBRARY_PATH=%s",
		    "/usr/openwin/lib");
		(void) putenv(ld_lib_path);

		/*
		 * We need to set $HOME so the users .Xauthority file
		 * can be located. This is especially needed for a user
		 * user MIT Magic Cookie authentication security.
		 */

		home_dir = malloc(strlen(pw->pw_dir) + 6);
		if (home_dir == NULL) {
			perror("malloc");
			exit(1);
		}
		(void) strcpy(home_dir, "HOME=");
		(void) strcat(home_dir, pw->pw_dir);
		(void) putenv(home_dir);

		/*
		 * We need the X application to be able to connect to
		 * the user's display so we better run as if we are
		 * the user (effectively).
		 * Don't want x program doing anything nasty.
		 *
		 * Note - have to set gid stuff first as effective uid
		 *	  must belong to root for this to work correctly.
		 */

		(void) seteuid(0);
		(void) setgid(pw->pw_gid);
		(void) setegid(pw->pw_gid);
		(void) setuid(pw->pw_uid);
		(void) seteuid(pw->pw_uid);

#ifdef DEBUG
		(void) fprintf(stderr,
		    "DEBUG: \"%s\" being execl'ed with name = \"%s\"\n",
		    EJECT_POPUP_PATH, name);
#endif

		(void) execl(EJECT_POPUP_PATH, EJECT_POPUP, "-n", name, NULL);

		(void) fprintf(stderr,
		    gettext("error: exec of \"%s\" failed (errno = %d)\n"),
		    EJECT_POPUP_PATH, errno);
		exit(-1);

	}

	/* the parent -- wait for the child */
	if (waitpid(pid, &exit_code, 0) == pid) {
		if (WIFEXITED(exit_code)) {
			if (WEXITSTATUS(exit_code) == 0) {
				ret_val = TRUE;
			}
		}
	}

dun:
	/* all done */
#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: popup_msg() returning %s\n",
	    ret_val ? "TRUE" : "FALSE");
#endif
	return (ret_val);
}

/*
 * Use a popup window to display the "manually ejectable"
 * message for X86 machines.
 *
 * return flase if the popup fails, else return TRUE
 */
static bool_t
winsysck(struct passwd *pw)
{
	pid_t		pid;
	int		exit_code = -1;
	bool_t		ret_val = FALSE;
	int		fd;
	char		*home_dir;
	char		ld_lib_path[MAXPATHLEN];

	if ((pid = fork()) < 0) {
		(void) fprintf(stderr,
		    gettext("error: can't fork a process (errno %d)\n"),
		    errno);
		goto dun;
	}

	if (pid == 0) {

		/*
		 * error messages to console
		 */

#ifndef	DEBUG
		if ((fd = open(BIT_BUCKET, O_RDWR)) >= 0) {
			(void) dup2(fd, fileno(stdin));
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
		}
#endif

		/*
		 * set up the users environment
		 */
		(void) putenv("DISPLAY=:0.0");
		(void) putenv("OPENWINHOME=/usr/openwin");

		(void) sprintf(ld_lib_path, "LD_LIBRARY_PATH=%s",
		    "/usr/openwin/lib");
		(void) putenv(ld_lib_path);

		/*
		 * we need to set $HOME so the users .Xauthority file
		 * can be located. This is especially needed for a user
		 * user MIT Magic Cookie authentication security
		 */
		home_dir = malloc(strlen(pw->pw_dir) + 6);
		if (home_dir == NULL) {
			perror("malloc");
			exit(-1);
		}
		(void) strcpy(home_dir, "HOME=");
		(void) strcat(home_dir, pw->pw_dir);
		(void) putenv(home_dir);

		/*
		 * We need the X application to be able to connect to
		 * the user's display so we better run as if we are
		 * the user (effectively).
		 * Don't want x program doing anything nasty.
		 *
		 * Note - have to set gid stuff first as effective uid
		 *	  must belong to root for this to work correctly.
		 */
		(void) seteuid(0);
		(void) setgid(pw->pw_gid);
		(void) setegid(pw->pw_gid);
		(void) setuid(pw->pw_uid);
		(void) seteuid(pw->pw_uid);

#ifdef DEBUG
		(void) fprintf(stderr,
		    "DEBUG: \"%s\" being execl'ed with protocol = \"%s\"\n",
		    OW_WINSYSCK_PATH, OW_WINSYSCK_PROTOCOL);
#endif

		(void) execl(OW_WINSYSCK_PATH, OW_WINSYSCK,
		    OW_WINSYSCK_PROTOCOL, NULL);

		(void) fprintf(stderr,
		    gettext("error: exec of \"%s\" failed (errno = %d)\n"),
		    OW_WINSYSCK_PATH, errno);
		exit(-1);

	}

	/*
	 * parent:
	 * set up an alarm because the child may block forever
	 * when an x-protocol cannot be identified. This can
	 * happen on headless darwins (because they have a
	 * video board intergrated into its mother board).
	 */
	/* LINTED */
	if (signal(SIGALRM, ej_sig_alrm) == SIG_ERR) {
		perror("signal(SIGALRM) error ");
		return (ret_val);
	}

	alarm(TIMEOUT_ON_WAITPID);

	/* the parent -- wait for the child or the alarm */
	if (waitpid(pid, &exit_code, 0) == pid) {
		alarm(0);
		if (WIFEXITED(exit_code)) {
			if (WEXITSTATUS(exit_code) == 0) {
				ret_val = TRUE;
			}
		}
	} else {
		/* alarm went off, kill pid */
		if (kill(pid, SIGKILL) != 0) {
			perror("kill(pid, SIGKILL) failed:\n");
		}
	}

dun:
	/* all done */
#ifdef	DEBUG
	(void) fprintf(stderr, "DEBUG: winsysck() returning %s\n",
	    ret_val ? "TRUE" : "FALSE");
#endif
	return (ret_val);
}


/*
 * this routine will return the volmgt block name given the volmgt
 *  raw (char spcl) name
 *
 * if anything but a volmgt raw pathname is supplied that pathname will
 *  be returned
 *
 * NOTE: non-null return value will point to static data, overwritten with
 *  each call
 *
 * e.g. names starting with "/vol/r" will be changed to start with "/vol/",
 * and names starting with "vol/dev/r" will be changed to start with
 * "/vol/dev/"
 */
static char *
eject_getfullblkname(char *path, bool_t vm_running)
{
	char		raw_root[MAXPATHLEN];
	const char	*vm_root;
	static char	res_buf[MAXPATHLEN];
	uint_t		raw_root_len;

#ifdef	DEBUG
	(void) fprintf(stderr, "eject_getfullblkname(\"%s\", %s): entering\n",
	    path, vm_running ? "TRUE" : "FALSE");
#endif
	/*
	 * try different strategies based on whether or not vold is running
	 */
	if (vm_running) {

		/* vold IS running -- look in /vol (or its alternate) */

		/* get vm root dir */
		vm_root = volmgt_root();

		/* get first volmgt root dev directory (and its length) */
		(void) sprintf(raw_root, "%s/r", vm_root);
		raw_root_len = strlen(raw_root);

		/* see if we have a raw volmgt pathname (e.g. "/vol/r*") */
		if (strncmp(path, raw_root, raw_root_len) == 0) {
			if (snprintf(res_buf, sizeof (res_buf), "%s/%s",
				vm_root, path + raw_root_len)
				>= sizeof (res_buf)) {
				return (NULL);
			}
			goto dun;		/* found match in /vol */
		}

		/* get second volmgt root dev directory (and its length) */
		(void) sprintf(raw_root, "%s/dev/r", vm_root);
		raw_root_len = strlen(raw_root);

		/* see if we have a raw volmgt pathname (e.g. "/vol/dev/r*") */
		if (strncmp(path, raw_root, raw_root_len) == 0) {
			if (snprintf(res_buf, sizeof (res_buf), "%s/dev/%s",
				vm_root, path + raw_root_len)
				>= sizeof (res_buf)) {
				return (NULL);
			}
			goto dun;		/* found match in /vol/dev */
		}

	} else {

		/* vold is NOT running -- look in /dev */

		(void) strcpy(raw_root, "/dev/r");
		raw_root_len = strlen(raw_root);
		if (strncmp(path, raw_root, raw_root_len) == 0) {
			if (snprintf(res_buf, sizeof (res_buf), "/dev/%s",
			    path + raw_root_len) >= sizeof (res_buf)) {
				return (NULL);
			}
			goto dun;		/* found match in /dev */
		}
	}

	/* no match -- return what we got */
	(void) strcpy(res_buf, path);

dun:
#ifdef	DEBUG
	(void) fprintf(stderr, "eject_getfullblkname: returning %s\n",
	    res_buf ? res_buf : "<null ptr>");
#endif
	return (res_buf);
}
