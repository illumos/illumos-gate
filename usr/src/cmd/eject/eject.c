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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Program to eject one or more pieces of media.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/fdio.h>
#include	<sys/dkio.h>
#include	<sys/cdio.h>
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

static char		*prog_name = NULL;
static boolean_t	do_default = B_FALSE;
static boolean_t	do_list = B_FALSE;
static boolean_t	do_closetray = B_FALSE;
static boolean_t 	force_eject = B_FALSE;
static boolean_t	do_query = B_FALSE;
static boolean_t	is_direct = B_FALSE;

static int		work(char *, char *);
static void		usage(void);
static int		ejectit(char *);
static boolean_t	query(char *, boolean_t);
static boolean_t	floppy_in_drive(char *, int, boolean_t *);
static boolean_t	display_busy(char *, boolean_t);
static char		*eject_getfullblkname(char *, boolean_t);
extern char		*getfullrawname(char *);

/*
 * ON-private libvolmgt routines
 */
int		_dev_mounted(char *path);
int		_dev_unmount(char *path);
char		*_media_oldaliases(char *name);
void		_media_printaliases(void);


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

#define	AVAIL_MSG		"%s is available\n"
#define	NOT_AVAIL_MSG		"%s is not available\n"

#define	OK_TO_EJECT_MSG		"%s can now be manually ejected\n"

#define	FLOPPY_MEDIA_TYPE	"floppy"
#define	CDROM_MEDIA_TYPE	"cdrom"


int
main(int argc, char **argv)
{
	int		c;
	const char	*opts = "dqflt";
	int		excode;
	int		res;
	boolean_t	err_seen = B_FALSE;
	boolean_t	man_eject_seen = B_FALSE;
	char		*rmmount_opt = NULL;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	prog_name = argv[0];

	is_direct = (getenv("EJECT_DIRECT") != NULL);

	/* process arguments */
	while ((c = getopt(argc, argv, opts)) != EOF) {
		switch (c) {
		case 'd':
			do_default = B_TRUE;
			rmmount_opt = "-d";
			break;
		case 'q':
			do_query = B_TRUE;
			break;
		case 'l':
			do_list = B_TRUE;
			rmmount_opt = "-l";
			break;
		case 'f':
			force_eject = B_TRUE;
			break;
		case 't':
			do_closetray = B_TRUE;
			break;
		default:
			usage();
			exit(EJECT_PARM_ERR);
		}
	}

	if (argc == optind) {
		/* no argument -- use the default */
		excode = work(NULL, rmmount_opt);
	} else {
		/* multiple things to eject */
		for (; optind < argc; optind++) {
			res = work(argv[optind], rmmount_opt);
			if (res == EJECT_MAN_EJ) {
				man_eject_seen = B_TRUE;
			} else if (res != EJECT_OK) {
				err_seen = B_TRUE;
			}
		}
		if (err_seen) {
			if (!is_direct) {
				excode = res;
			} else {
				excode = EJECT_IOCTL_ERR;
			}
		} else if (man_eject_seen) {
			excode = EJECT_MAN_EJ;
		} else {
			excode = EJECT_OK;
		}
	}

	return (excode);
}

/*
 * the the real work of ejecting (and notifying)
 */
static int
work(char *arg, char *rmmount_opt)
{
	char 		*name;
	int		excode = EJECT_OK;
	struct stat64	sb;
	char		*arg1, *arg2;
	pid_t		pid;
	int		status = 1;

	if (!is_direct) {
		/* exec rmmount */
		if (do_closetray) {
			(void) putenv("EJECT_CLOSETRAY=1");
		}
		if (do_query) {
			(void) putenv("EJECT_QUERY=1");
		}
		pid = fork();
		if (pid < 0) {
			exit(1);
		} else if (pid == 0) {
			/* child */
			if (rmmount_opt != NULL) {
				arg1 = rmmount_opt;
				arg2 = arg;
			} else {
				arg1 = arg;
				arg2 = NULL;
			}

			if (execl("/usr/bin/rmmount", "eject",
			    arg1, arg2, 0) < 0) {
				excode = 99;
			} else {
				exit(0);
			}
		} else {
			/* parent */
			if (waitpid(pid, &status, 0) != pid) {
				excode = 1;
			} else if (WIFEXITED(status) &&
			    (WEXITSTATUS(status) != 0)) {
				excode = WEXITSTATUS(status);
			} else {
				excode = 0;
			}
		}
	}

	/*
	 * rmmount returns 99 if HAL not running -
	 * fallback to direct in that case
	 */
	if (is_direct || (excode == 99)) {
		excode = EJECT_OK;

		if (arg == NULL) {
			arg = "floppy";
		}
		if ((name = _media_oldaliases(arg)) == NULL) {
			name = arg;
		}
		if (do_default) {
			(void) printf("%s\n", name);
			goto out;
		}
		if (do_list) {
			(void) printf("%s\t%s\n", name, arg);
			goto out;
		}
		if (access(name, R_OK) != 0) {
			if (do_query) {
				(void) fprintf(stderr,
				    gettext("%s: no media\n"), name);
				return (EJECT_NO_MEDIA);
			} else {
				perror(name);
				return (EJECT_PARM_ERR);
			}
		}

		if (do_query) {
			if ((stat64(name, &sb) == 0) && S_ISDIR(sb.st_mode)) {
				(void) fprintf(stderr,
				    gettext("%s: no media\n"), name);
				return (EJECT_NO_MEDIA);
			}
			if (!query(name, B_TRUE)) {
				excode = EJECT_NO_MEDIA;
			}
		} else {
			excode = ejectit(name);
		}
	}
out:
	return (excode);
}


static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: %s [-fldqt] [name | nickname]\n"),
	    prog_name);
	(void) fprintf(stderr,
	    gettext("options:\t-f force eject\n"));
	(void) fprintf(stderr,
	    gettext("\t\t-l list ejectable devices\n"));
	(void) fprintf(stderr,
	    gettext("\t\t-d show default device\n"));
	(void) fprintf(stderr,
	    gettext("\t\t-q query for media present\n"));
	(void) fprintf(stderr,
	    gettext("\t\t-t close tray\n"));
}


static int
ejectit(char *name)
{
	int 		fd, r;
	boolean_t	mejectable = B_FALSE;	/* manually ejectable */
	int		result = EJECT_OK;

	/*
	 * If volume management is either not running or not being managed by
	 * vold, and the device is mounted, we try to umount the device.  If we
	 * fail, we give up, unless it used the -f flag.
	 */

	if (_dev_mounted(name)) {
		r = _dev_unmount(name);
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

	/*
	 * make sure we are dealing with a raw device
	 *
	 * XXX: NOTE: results from getfullrawname()
	 * really should be free()d when no longer
	 * in use
	 */
	name = getfullrawname(name);

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

	if (do_closetray) {
		if (ioctl(fd, CDROMCLOSETRAY) < 0) {
			result = EJECT_IOCTL_ERR;
		}
	} else if (ioctl(fd, DKIOCEJECT, 0) < 0) {
		/* check on why eject failed */

		/* check for no floppy in manually ejectable drive */
		if ((errno == ENOSYS) &&
		    !floppy_in_drive(name, fd, &mejectable)) {
			/* use code below to handle "not present" */
			errno = ENXIO;
		}

		if (errno == ENOSYS || errno == ENOTSUP) {
			(void) fprintf(stderr, gettext(OK_TO_EJECT_MSG), name);
		}

		if ((errno == ENOSYS || errno == ENOTSUP) && mejectable) {
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
			if (!display_busy(name, B_FALSE)) {
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
 * return B_TRUE if a floppy is in the drive, B_FALSE otherwise
 *
 * this routine assumes that the file descriptor passed in is for
 * a floppy disk.  this works because it's only called if the device
 * is "manually ejectable", which only (currently) occurs for floppies.
 */
static boolean_t
floppy_in_drive(char *name, int fd, boolean_t *is_floppy)
{
	int	ival = 0;
	boolean_t rval = B_FALSE;


	if (ioctl(fd, FDGETCHANGE, &ival) >= 0) {
		if (!(ival & FDGC_CURRENT)) {
			rval = B_TRUE;
		}
		*is_floppy = B_TRUE;
	} else {
		*is_floppy = B_FALSE;
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
 * return B_TRUE iff we printed the appropriate error message, else
 * return B_FALSE (and caller will print error message itself)
 */
static boolean_t
display_busy(char *path, boolean_t vm_running)
{
	int		errno_save = errno;	/* to save errno */
	char		*blk;			/* block name */
	FILE		*fp = NULL;		/* for scanning mnttab */
	struct mnttab	mref;			/* for scanning mnttab */
	struct mnttab	mp;			/* for scanning mnttab */
	boolean_t	res = B_FALSE;		/* return value */
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
			res = B_TRUE;
			(void) fprintf(stderr, "%s: %s\n", mp.mnt_special,
			    strerror(EBUSY));
		}
	}

dun:
	if (fp != NULL) {
		(void) fclose(fp);
	}
#ifdef	DEBUG
	(void) fprintf(stderr, "display_busy: returning %s\n",
	    res ? "B_TRUE" : "B_FALSE");
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
 * return B_TRUE if media found, else B_FALSE (XXX: was 0 and -1)
 */
static boolean_t
query(char *name, boolean_t doprint)
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
		return (B_FALSE);
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
			return (B_TRUE);
		}
		if (rval & FDGC_CURRENT) {
			if (doprint) {
				(void) fprintf(stderr,	gettext(NOT_AVAIL_MSG),
				    name);
			}
			return (B_FALSE);
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
			return (B_TRUE);
		}
		if (state == DKIO_EJECTED) {
			if (doprint) {
				(void) fprintf(stderr,	gettext(NOT_AVAIL_MSG),
				    name);
			}
			(void) close(fd);
			return (B_FALSE);
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
		return (B_FALSE);
	}

	(void) close(fd);
	if (doprint) {
		(void) fprintf(stderr, gettext(AVAIL_MSG), name);
	}
	return (B_TRUE);	/* success */
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
eject_getfullblkname(char *path, boolean_t vm_running)
{
	char		raw_root[MAXPATHLEN];
	const char	*vm_root;
	static char	res_buf[MAXPATHLEN];
	uint_t		raw_root_len;

#ifdef	DEBUG
	(void) fprintf(stderr, "eject_getfullblkname(\"%s\", %s): entering\n",
	    path, vm_running ? "B_TRUE" : "B_FALSE");
#endif
	/*
	 * try different strategies based on whether or not vold is running
	 */
	if (vm_running) {

		/* vold IS running -- look in /vol (or its alternate) */

		/* get vm root dir */
		vm_root = volmgt_root();

		/* get first volmgt root dev directory (and its length) */
		(void) snprintf(raw_root, sizeof (raw_root), "%s/r", vm_root);
		raw_root_len = strlen(raw_root);

		/* see if we have a raw volmgt pathname (e.g. "/vol/r*") */
		if (strncmp(path, raw_root, raw_root_len) == 0) {
			if (snprintf(res_buf, sizeof (res_buf), "%s/%s",
			    vm_root, path + raw_root_len) >= sizeof (res_buf)) {
				return (NULL);
			}
			goto dun;		/* found match in /vol */
		}

		/* get second volmgt root dev directory (and its length) */
		(void) snprintf(raw_root, sizeof (raw_root),
		    "%s/dev/r", vm_root);
		raw_root_len = strlen(raw_root);

		/* see if we have a raw volmgt pathname (e.g. "/vol/dev/r*") */
		if (strncmp(path, raw_root, raw_root_len) == 0) {
			if (snprintf(res_buf, sizeof (res_buf), "%s/dev/%s",
			    vm_root, path + raw_root_len) >= sizeof (res_buf)) {
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
