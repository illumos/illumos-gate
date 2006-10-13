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
 * Copyright 1995, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Program to to allow non-root users to call rmmount
 *
 * XXX: much of this program is copied from eject.c.  It would be nice
 *	to combine the common code in these two programs (in libvolgmt)
 */

/*
 * System include files
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <rpc/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dkio.h>
#include <sys/fdio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vol.h>
#include <sys/wait.h>
#include <unistd.h>
#include <volmgt.h>

/*
 * Local include files
 */

#include "vold.h"

/*
 * ON-private libvolmgt routines
 */
extern char	*_media_oldaliases(char *);

/*
 * Private attribute types and attributes
 */

typedef enum {
	REMOUNT_MEDIUM,
	UNMOUNT_FILESYSTEMS,
	NO_ACTION
}
action_t;

static const char *action_strings[] = {
	"clear_mounts",
	"unmount"
};

/*
 * volmgt name for floppy and cdrom types of media
 */

#define	FLOPPY_MEDIA_TYPE	"floppy"
#define	CDROM_MEDIA_TYPE	"cdrom"

/*
 * for environment variables
 * (room for a pathname and some padding)
 */

#define	ENV_VAR_BUFLEN		(MAXPATHLEN + 20)

/*
 * path for the rmmount program
 */

#define	RMMOUNT_PATH		"/usr/sbin/rmmount"
#define	RMMOUNT_PROG		"rmmount"

/*
 * maximum number of arguments that can be passed to rmmount
 */

#define	RMM_MAX_ARGS		25

#ifdef DEBUG
char		*rmm_config = NULL;		/* from "-c" */
#endif /* DEBUG */

/*
 * Declarations of private functions.
 */
static bool_t	access_ok(char *);
static bool_t	call_rmmount(bool_t);
static char	*getdefault(void);
static char	*get_raw_partition_path(char *pathp);
static char	*get_symname(char *, char *);
static int	my_putenv(char *);
static char	*my_strdup(char *);
static char	*name_deref(char *, char **);
static bool_t	query(char *);
static bool_t	remount_medium(char *raw_pathp);
static bool_t	setup_env(action_t, char *, char *);
static char	*symname_to_mt(char *);
static void	usage(char *);
static char	*vol_basename(char *);
static char	*vol_dirname(char *);
static char	*volrmm_getfullblkname(char *);
static bool_t	work(action_t, char *, bool_t);

int
main(int argc, char **argv)
{
	int		c;			/* for getopt() */
	bool_t		do_pdefault;		/* from "-d" */
	bool_t		do_debug;		/* from "-D" */
#ifdef DEBUG
	const char 	*opts = "iedDc:";	/* for getopt() */
#else
	const char	*opts = "iedD";		/* for getopt() */
#endif /* DEBUG */
	char		*prog_name;
	int		ret_val;
	action_t	user_act;		/* from "-i" or "-e" */
	char		*vol;

	do_debug = FALSE;
	do_pdefault = FALSE;
	prog_name = vol_basename(argv[0]);
	ret_val = 0;
	user_act = NO_ACTION;
	vol = NULL;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, opts)) != EOF) {
		switch (c) {
		case 'i':
			user_act = REMOUNT_MEDIUM;
			break;
		case 'e':
			user_act = UNMOUNT_FILESYSTEMS;
			break;
		case 'd':
			do_pdefault = TRUE;
			break;
		case 'D':
			do_debug = TRUE;
			break;
#ifdef DEBUG
		case 'c':
			rmm_config = (char *)optarg;
			break;
#endif /* DEBUG */
		default:
			usage(prog_name);
			return (1);
		}
	}

	if (!volmgt_running()) {
		(void) fprintf(stderr,
		    gettext("error: Volume Management must be running\n"));
		return (1);
	}

	if (do_pdefault) {
		if ((vol = getdefault()) == NULL) {
			(void) fprintf(stderr,
			    gettext("Default device is: nothing inserted\n"));
		} else {
			(void) fprintf(stderr,
			    gettext("Default device is: %s\n"), vol);
		}
		return (0);
	}

	if (user_act == NO_ACTION) {
		(void) fprintf(stderr,
		    gettext("error: must specify an action\n"));
		usage(prog_name);
		return (1);
	}

	if (argc == optind) {
		/*
		 * If no symbolic name or path name was passed in,
		 * use the default symbolic name.
		 */
		if ((vol = getdefault()) == NULL) {
			(void) fprintf(stderr,
			    gettext("No default media available\n"));
			return (1);
		}
		if (!work(user_act, vol, do_debug)) {
			ret_val = 1;
		}
	} else {
		/*
		 * At least one symbolic name or path name was
		 * passed in.
		 */
		for (; optind < argc; optind++) {
			if (!work(user_act, argv[optind], do_debug)) {
				ret_val = 1;
			}
		}
	}

	return (ret_val);
}

static bool_t
access_ok(char *path)
{
	/*
	 * Since volrmmount is a suid root program, we must make sure
	 * that the user running us is allowed to access the media.
	 * All a user has to do to request an action is open
	 * the file for reading, so that's as restrictive as we'll be.
	 */

	bool_t	result;

	result = TRUE;
	if (access(path, R_OK) != 0) {
		(void) fprintf(stderr,
		    gettext("error: can't access \"%s\": %s\n"),
		    path, strerror(errno));
		result = FALSE;
	}
	return (result);
}



static bool_t
call_rmmount(bool_t do_debug)
{
	pid_t	fork_pid;
	char	*args[RMM_MAX_ARGS + 1];	/* a little extra room */
	int	arg_ind = 0;
	int	exit_val;



	if ((fork_pid = fork()) < 0) {
		(void) fprintf(stderr,
		    gettext("error: can't fork to call \"%s\": %s\n"),
		    RMMOUNT_PATH, strerror(errno));
		return (FALSE);
	}

	/* get name of program */
	if (fork_pid == 0) {
		/* the child */

		/* set up the arg list */
		args[arg_ind++] = RMMOUNT_PROG;
		if (do_debug) {
			args[arg_ind++] = "-D";
		}
#ifdef DEBUG
		if (rmm_config != NULL) {
			args[arg_ind++] = "-c";
			args[arg_ind++] = rmm_config;
		}
#endif /* DEBUG */
		args[arg_ind] = NULL;

		(void) execv(RMMOUNT_PATH, args);

		(void) fprintf(stderr,
		    gettext("error: can't exec \"%s\": %s\n"),
		    RMMOUNT_PATH, strerror(errno));
		_exit(1);
	}

	/* the parent -- wait for that darned child */
	if (waitpid(fork_pid, &exit_val, 0) < 0) {
		/* signal ?? */
#ifdef	WE_SHOULD_BE_VERBOSE
		/*
		 * XXX: should user really get an error message for
		 * interrupting rmmount ??
		 */
		if (errno == EINTR) {
			(void) fprintf(stderr,
			    gettext("error: \"%s\" was interrupted\n"),
			    RMMOUNT_PATH);
		} else {
			(void) fprintf(stderr,
			    gettext("error: running \"%s\": %s\n"),
			    RMMOUNT_PATH, strerror(errno));
		}
#endif
		return (FALSE);
	}

	/* evaluate return status */
	if (WIFEXITED(exit_val)) {
		if (WEXITSTATUS(exit_val) == 0) {
			return (TRUE);		/* success */
		}
		(void) fprintf(stderr, gettext("error: \"%s\" failed\n"),
		    RMMOUNT_PATH);
	} else if (WIFSIGNALED(exit_val)) {
		(void) fprintf(stderr,
		    gettext("error: \"%s\" terminated by signal %d\n"),
		    RMMOUNT_PATH, WSTOPSIG(exit_val));
	} else if (WCOREDUMP(exit_val)) {
		(void) fprintf(stderr, gettext("error: \"%s\" core dumped\n"));
	}
	return (FALSE);
}

static char *
getdefault(void)
{
	/*
	 * The assumption is that someone typed volrmmount to handle
	 * some medium that's currently in a drive.  So, what we do is
	 * check for floppy then cdrom.  If there's nothing in either,
	 * we just return NULL.
	 */

	char		*s = NULL;

	/* look for floppy, then CD-ROM, using new naming */
	if ((s = media_findname(FLOPPY_MEDIA_TYPE)) != NULL) {
		if (query(s)) {
			goto dun;
		}
	}
	if ((s = media_findname(CDROM_MEDIA_TYPE)) != NULL) {
		if (query(s)) {
			goto dun;
		}
	}
	/* look for floppy, then CD-ROM, using old naming */
	if ((s = _media_oldaliases(FLOPPY_MEDIA_TYPE)) != NULL) {
		if (query(s)) {
			goto dun;
		}
	}
	if ((s = _media_oldaliases(CDROM_MEDIA_TYPE)) != NULL) {
		if (query(s)) {
			goto dun;
		}
	}

	s = NULL;	/* no match */
dun:
	return (s);
}

static char *
get_raw_partition_path(char *pathp)
{
	/*
	 * Given a path, check to see if it's a path to a raw
	 * partition.  If so, simply return a copy of it.
	 * If it's a directory path, read the directory and
	 * return a copy of the first raw partition pathname
	 * found there.  Don't read subdirectories.  Assume
	 * that there's at least one raw partition file in
	 * the directory.
	 */

	DIR *		directoryp;
	dirent_t	*directory_entryp;
	char		*filenamep;
	char		pathname_bufferp[MAXPATHLEN];
	char		*raw_partition_pathnamep;
	struct stat	stat_buffer;
	int		stat_result;

	raw_partition_pathnamep = NULL;
	stat_result = stat(pathp, &stat_buffer);
	if (stat_result != 0) {
		(void) fprintf(stderr,
			gettext("volrmmount: error: can't stat %s: %s\n"),
			pathp, strerror(errno));
	} else if (S_ISCHR(stat_buffer.st_mode)) {
		raw_partition_pathnamep = my_strdup(pathp);
	} else if (S_ISDIR(stat_buffer.st_mode)) {

		directoryp = opendir(pathp);
		if (directoryp == NULL)
			return (NULL);

		while ((stat_result == 0) &&
			!S_ISCHR(stat_buffer.st_mode)) {

			errno = 0;
			directory_entryp = readdir(directoryp);
			if (directory_entryp == NULL) {
				if (errno != 0) {
					(void) fprintf(stderr,
						gettext(
				"volrmmount: error: can't read %s: %s\n"),
						pathp, strerror(errno));
				}
				break;
			}
			filenamep = directory_entryp->d_name;
			if (strcmp(filenamep, ".") == 0 ||
			    strcmp(filenamep, "..") == 0) {
				continue;
			}

			if (snprintf(pathname_bufferp,
			    sizeof (pathname_bufferp),
			    "%s/%s", pathp, filenamep)
			    >= sizeof (pathname_bufferp)) {
				continue;
			}
			stat_result = stat(pathname_bufferp, &stat_buffer);
			if (stat_result != 0) {
				(void) fprintf(stderr,
					gettext(
			"volrmmount: error: can't stat %s: %s\n"),
					pathname_bufferp, strerror(errno));
			} else if (S_ISCHR(stat_buffer.st_mode)) {
				raw_partition_pathnamep =
					my_strdup(pathname_bufferp);
			}
		}
		closedir(directoryp);
	}
	return (raw_partition_pathnamep);
}

/*
 * given a raw device path in /vol/dev, return the symbolic name.
 * Also, pathname which represents media will be returned via media_path.
 * It is typically a path name to a directory which contains devices for
 * each partitions in the media.
 */
static char *
get_symname(char *vol_path, char *media_path)
{
	const char	*vm_root = volmgt_root();
	char		vol_symdir[MAXPATHLEN];
	char		*basen;
	DIR		*dirp, *dirp2;
	struct dirent64	*dp = NULL, *dp2;
	char		lpath[MAXPATHLEN];
	char		link_buf[MAXPATHLEN];
	int		lb_len;
	char		*res = NULL;
	struct	stat	rst, st;

	/* get path of alias directory */
	(void) sprintf(vol_symdir, "%s/dev/aliases", vm_root);

	/* scan for aliases that might match */
	if ((dirp = opendir(vol_symdir)) == NULL) {
		(void) fprintf(stderr, gettext(
		    "error: can't open volmgt symlink directory \"%s\"; %s\n"),
		    vol_symdir, strerror(errno));
		goto dun;
	}

	if (stat(vol_path, &rst) == -1)
		goto dun;

	basen = vol_basename(vol_path);

	while ((dp = readdir64(dirp)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		/* this is *probably* a link, so proceed as if it is */
		if (snprintf(lpath, sizeof (lpath), "%s/%s",
		    vol_symdir, dp->d_name) >= sizeof (lpath)) {
			continue;
		}

		if ((lb_len = readlink(lpath, link_buf, MAXPATHLEN)) < 0) {
			continue;		/* not a link ?? */
		}
		link_buf[lb_len] = '\0';

		if (stat(link_buf, &st) == -1) {
			/* path does not exist */
			continue;
		}

		/*
		 * If not a directory, just check the device id see if
		 * it's the one.
		 */
		if (!S_ISDIR(st.st_mode)) {
			if (rst.st_rdev == st.st_rdev) {
				/* found a match! */
				res = my_strdup(dp->d_name);
				(void) strcpy(media_path, link_buf);
				break;
			}
			continue;
		}

		/*
		 * If given pathname is a directory, we only check directory
		 * name.
		 */
		if (S_ISDIR(rst.st_mode)) {
			if (strcmp(basen, vol_basename(link_buf)) == 0) {
				/* found a match! */
				res = my_strdup(dp->d_name);
				(void) strcpy(media_path, link_buf);
				break;
			}
			continue;
		}

		/*
		 * symbol name in aliases points to directory. go through the
		 * directory contents see if there is a device match.
		 */
		if ((dirp2 = opendir(link_buf)) == NULL)
			continue;

		while ((dp2 = readdir64(dirp2)) != NULL) {
			if (strcmp(dp2->d_name, ".") == 0 ||
			    strcmp(dp2->d_name, "..") == 0)
				continue;

			if ((MAXPATHLEN - lb_len) < strlen(dp2->d_name) + 2) {
				/* pathname goes too long */
				continue;
			}

			link_buf[lb_len] = '/';
			(void) strcpy(&link_buf[lb_len + 1], dp2->d_name);

			if (stat(link_buf, &st) == -1)
				continue;

			if (!S_ISCHR(st.st_mode))
				continue;

			if (rst.st_rdev == st.st_rdev) {
				/* found a match! */
				(void) closedir(dirp2);
				res = my_strdup(dp->d_name);
				link_buf[lb_len] = '\0';
				(void) strcpy(media_path, link_buf);
				goto dun;
			}
		}
		(void) closedir(dirp2);
	}

dun:
	if (dirp != NULL) {
		(void) closedir(dirp);
	}
	return (res);
}

static int
my_putenv(char *e)
{
	int	res;
	char	*env;


	if ((env = my_strdup(e)) == NULL) {
		return (1);
	}
	if ((res = putenv(env)) != 0) {
		(void) fprintf(stderr,
		gettext("error: can't allocate memory for environment: %s\n"),
		    strerror(errno));
	}

	return (res);
}

static char *
my_strdup(char *s)
{
	register char	*cp;


	if ((cp = strdup(s)) == NULL) {
		(void) fprintf(stderr,
		    gettext("error: can't allocate memory: %s\n"),
		    strerror(errno));
	}

	return (cp);
}


static char *
name_deref(char *name, char **symnamep)
{
	/*
	 * dereference (if needed) the user-supplied name
	 */

	char	*name1;
	char	*res;
	char	media_path[MAXPATHLEN];

	/*
	 * Check to see if name is an old alias (e.g. "fd" or "cd").
	 */

	name1 = _media_oldaliases(name);
	if (name1 == NULL) {
		/*
		 * name isn't an old alias.  Duplicate it as is.
		 */
		name1 = my_strdup(name);
	}

	/*
	 * Check for an absolute pathname or a /vol/rdsk name.
	 */

	res = media_findname(name1);
	if (res == NULL) {
		/*
		 * name isn't an old alias, an absolute path, or a name
		 * under /vol/rdsk.  Use the name supplied as the call
		 * parameter.
		 */
		res = my_strdup(name1);
	}
	if (name1 != NULL) {
		free(name1);
	}

	if ((*symnamep = get_symname(res, media_path)) != NULL) {
		free(res);
		res = my_strdup(media_path);
	}
	return (res);
}

static bool_t
query(char *path)
{
	/*
	 * In my experience with removable media drivers so far... the
	 * most reliable way to tell if a piece of media is in a drive
	 * is simply to open it.  If the open works, there's something
	 * there, if it fails, there's not.  We check for two errnos
	 * which we want to interpret for the user,  ENOENT and EPERM.
	 *  All other errors are considered to be "media isn't there".
	 * (halt, 1993)
	 *
	 * return TRUE if media found, else FALSE
	 */

	int		fd = -1;
	int		rval;			/* FDGETCHANGE return value */
	enum dkio_state	state;
	bool_t		res = FALSE;		/* return value */



	/* open the specifed path */
	if ((fd = open(path, O_RDONLY|O_NONBLOCK)) < 0) {
		goto dun;
	}

	rval = 0;
	if (ioctl(fd, FDGETCHANGE, &rval) >= 0) {
		/* hey, it worked, what a deal, it must be a floppy */
		if (!(rval & FDGC_CURRENT)) {
			res = TRUE;
		}
		goto dun;
	}

again:
	state = DKIO_NONE;
	if (ioctl(fd, DKIOCSTATE, &state) >= 0) {
		/* great, the fancy ioctl is supported. */
		if (state == DKIO_INSERTED) {
			res = TRUE;
			goto dun;
		}
		if (state == DKIO_EJECTED) {
			goto dun;
		}
		/* state must be DKIO_NONE: do a silly retry loop */
		(void) sleep(1);
		goto again;		/* how many times? */
	}
	(void) close(fd);

	/*
	 * Ok, we've tried the non-blocking/ioctl route.  The
	 * device doesn't support any of our nice ioctls, so
	 * we'll just say that if it opens it's there, if it
	 * doesn't, it's not.
	 */
	if ((fd = open(path, O_RDONLY)) < 0) {
		goto dun;
	}

	res = TRUE;			/* success */
dun:
	if (fd >= 0) {
		(void) close(fd);
	}
	return (res);
}

static bool_t
remount_medium(char *raw_pathp)
{
	/*
	 * Remount the file systems on a medium that
	 * has been repartitioned.
	 */

	int		file_descriptor;
	char		*raw_partition_pathp;
	bool_t		result;

	file_descriptor = -1;
	raw_partition_pathp = get_raw_partition_path(raw_pathp);
	result = TRUE;

	if (raw_partition_pathp == NULL) {
		(void) fprintf(stderr,
			gettext("volrmmount: error: no raw path for %s\n"),
				raw_pathp);
		result = FALSE;
	} else {
		file_descriptor = open(raw_partition_pathp, O_RDONLY);
		if (file_descriptor < 0) {
			(void) fprintf(stderr,
				gettext(
				"volrmmount: error: can't open %s: %s\n"),
				raw_partition_pathp, strerror(errno));
			result = FALSE;
		} else if (ioctl(file_descriptor, VOLIOCREMOUNT) != 0) {
			(void) fprintf(stderr,
				gettext(
		"volrmmount: error: VOLIOCREMOUNT ioctl failed on %s: %s\n"),
				raw_partition_pathp, strerror(errno));
			result = FALSE;
		}
	}
	if (raw_partition_pathp != NULL) {
		free(raw_partition_pathp);
	}
	if (file_descriptor >= 0) {
		close(file_descriptor);
	}
	return (result);
}

static bool_t
setup_env(action_t act, char *raw_pathp, char *symbolic_namep)
{
	/*
	 * Set up the following environment variables for rmmount:
	 *
	 * VOLUME_NAME		- the volume's name
	 * VOLUME_PATH		- /vol/dev pathname to the volume
	 * VOLUME_ACTION	- "clear_mounts" or "unmount"
	 * VOLUME_MEDIATYPE	- medium type (e.g. "floppy", "cdrom")
	 * VOLUME_SYMDEV	- the symname (e.g. "floppy0", "cdrom1")
	 *
	 * Return FALSE if a fatal error occurs.
	 */

	char		env_buf[ENV_VAR_BUFLEN+1];
	bool_t		result;
	char		*blk;

	result = TRUE;

	/*
	 * Set VOLUME_FDISK to the null string
	 * to avoid leaving it uninitialized.
	 */
	(void) sprintf(env_buf, "VOLUME_FDSK=");
	if (my_putenv(env_buf) != 0) {
		result = FALSE;
	}
	if (result == TRUE) {
		/*
		 * The calls to rmmount that this function sets
		 * up only unmount file systems, so the mount
		 * mode is irrelevant here.  Set it to "rw".
		 */
		(void) sprintf(env_buf, "VOLUME_MOUNT_MODE=rw");
		if (my_putenv(env_buf) != 0) {
			result = FALSE;
		}
	}
	if (result == TRUE) {
		(void) sprintf(env_buf, "VOLUME_ACTION=%s",
				action_strings[act]);
		if (my_putenv(env_buf) != 0) {
			result = FALSE;
		}
	}
	if (result == TRUE) {
		/*
		 * Pass the block /vol pathname.
		 */
		if ((blk = volrmm_getfullblkname(raw_pathp)) == NULL)
			result = FALSE;
		if (result == TRUE &&
		    snprintf(env_buf, sizeof (env_buf),
			"VOLUME_PATH=%s", blk) >= sizeof (env_buf)) {
			result = FALSE;
		}
		if (result == TRUE && my_putenv(env_buf) != 0) {
			result = FALSE;
		}
	}
	if (result == TRUE) {
		/*
		 * Pass the bare volume name without the path
		 */
		(void) sprintf(env_buf, "VOLUME_NAME=%s",
			vol_basename(raw_pathp));
		if (my_putenv(env_buf) != 0) {
			result = FALSE;
		}
	}
	if (result == TRUE) {
		/*
		 * Pass the symbolic device name, e.g. "floppy0", "cdrom2".
		 */
		if (symbolic_namep == NULL) {
			result = FALSE;
		} else {
			(void) sprintf(env_buf, "VOLUME_SYMDEV=%s",
				symbolic_namep);
			if (my_putenv(env_buf) != 0) {
				result = FALSE;
			}
		}
	}
	if (result == TRUE) {
		/*
		 * Pass the medium type.
		 */
		(void) sprintf(env_buf, "VOLUME_MEDIATYPE=%s",
			symname_to_mt(symbolic_namep));
		if (my_putenv(env_buf) != 0) {
			result = FALSE;
		}
	}
	if (result == TRUE) {
		/*
		 * Pass the /vol pathname of the raw device directory.
		 */
		if (snprintf(env_buf, sizeof (env_buf), "VOLUME_DEVICE=%s",
			vol_dirname(raw_pathp)) >= sizeof (env_buf)) {
			result = FALSE;
		}
		if (result == TRUE && my_putenv(env_buf) != 0) {
			result = FALSE;
		}
	}

	if (result == TRUE) {
		/*
		 * Always prevent forced ejection of the medium,
		 * since volrmmount only unmounts a medium's file
		 * systems or rereads the medium and reconstructs
		 * and remounts its file systems.
		 */
		(void) strcpy(env_buf, "VOLUME_FORCEDEJECT=false");
		if (my_putenv(env_buf) != 0) {
			result = FALSE;
		}
	}
	return (result);
}


static char *
symname_to_mt(char *sn)
{
	/*
	 * return media type given symname (by removing number at end)
	 */

	static char	mt[MAXNAMELEN];
	char		*cpi;
	char		*cpo;


	for (cpi = sn, cpo = mt; *cpi != '\0'; cpi++, cpo++) {
		if (isdigit(*cpi)) {
			break;
		}
		*cpo = *cpi;
	}
	*cpo = '\0';

	/*
	 * Now check this against KNOWN media types volmgt
	 * supports. If it does not match one of the following
	 * 'floppy, cdrom, pcmem, rmdisk' set it to rmdisk. This
	 * is because what mt contains is the synname with numeric
	 * values removed and can have such names as 'zip', 'jaz'
	 * and items that belong to rmdisk that we do not know about
	 */
	if (strcmp(mt, CDROM_MTYPE) == 0 ||
		strcmp(mt, FLOPPY_MTYPE) == 0 ||
		strcmp(mt, PCMEM_MTYPE) == 0 ||
		strcmp(mt, RMDISK_MTYPE) == 0 ||
		strcmp(mt, TEST_MTYPE) == 0) {
		return (mt);
	}

	/*
	 * we don't know the type, set it to rmidsk
	 */
	(void) strcpy(mt, RMDISK_MTYPE);

	return (mt);
}

static void
usage(char *prog_name)
{
	(void) fprintf(stderr,
	    gettext(
	    "\nusage: %s [-D] [-i | -e] [NAME | NICKNAME]\n"),
	    prog_name);
	(void) fprintf(stderr,
	    gettext("or:    %s -d\n"), prog_name);
	(void) fprintf(stderr,
	    gettext(
	    "options:\t-i        simulate volume being put in/inserted\n"));
	(void) fprintf(stderr,
	    gettext(
	    "options:\t-e        simulate volume being taken out/ejected\n"));
	(void) fprintf(stderr,
	    gettext("options:\t-D        call rmmount in debug mode\n"));
#ifdef DEBUG
	(void) fprintf(stderr,
	    gettext("options:\t-c CONFIG call rmmount in debug mode\n"));
#endif /* DEBUG */
	(void) fprintf(stderr,
	    gettext("options:\t-d        show default device\n"));
	(void) fprintf(stderr, gettext("\nFor example:\n"));
	(void) fprintf(stderr, gettext("\n\t%s -e floppy0\n"), prog_name);
	(void) fprintf(stderr,
	    gettext("\nmight tell %s to unmount the floppy (if mounted))\n\n"),
	    prog_name);
}

static char *
vol_basename(char *path)
{
	register char	*cp;


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
	if (*++cp != '\0') {
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


/*
 * returns a malloced string
 */
static char *
vol_dirname(char *path)
{
	register char	*cp;
	size_t		len;
	char		*new;



	/* check for degenerates */
	if (strcmp(path, "/") == 0) {
		return (my_strdup("/"));
	}
	if (*path == '\0') {
		return (my_strdup("."));
	}

	/* find the last seperator in the path */
	if ((cp = strrchr(path, '/')) == NULL) {
		/* must be just a local name -- use the local dir */
		return (my_strdup("."));
	}

	/* allocate room for the new dirname string */
	/*LINTED*/
	len = (size_t)(cp - path);
	if ((new = malloc(len + 1)) == NULL) {
		(void) fprintf(stderr,
		    gettext("error: can't allocate memory: %s\n"),
		    strerror(errno));
		return (NULL);
	}

	/* copy the string in */
	(void) memcpy(new, path, len);
	new[len] = '\0';

	/* return all but the last component */
	return (new);
}

static char *
volrmm_getfullblkname(char *path)
{
	/*
	 * This routine will return the volmgt block name given the volmgt
	 * raw (char spcl) name, i.e. names starting with "/vol/r" will
	 * be changed to start with "/vol/", and names starting with
	 * "vol/dev/r" will be changed to start with "/vol/dev/".
	 *
	 * If anything but a volmgt raw pathname is supplied that
	 * pathname will be returned.
	 *
	 * NOTE: non-null return value will point to static data,
	 *	overwritten with each call
	 *
	 */
	char		vm_raw_root[MAXPATHLEN];
	const char	*vm_root = volmgt_root();
	static char	res_buf[MAXPATHLEN];
	uint_t		vm_raw_root_len;

	/* get first volmgt root dev directory (and its length) */
	(void) sprintf(vm_raw_root, "%s/r", vm_root);
	vm_raw_root_len = strlen(vm_raw_root);

	/* see if we have a raw volmgt pathname (e.g. "/vol/r*") */
	if (strncmp(path, vm_raw_root, vm_raw_root_len) == 0) {
		if (snprintf(res_buf, sizeof (res_buf), "%s/%s", vm_root,
			path + vm_raw_root_len) >= sizeof (res_buf)) {
			return (NULL);
		}
		goto dun;
	}

	/* get second volmgt root dev directory (and its length) */
	(void) sprintf(vm_raw_root, "%s/dev/r", vm_root);
	vm_raw_root_len = strlen(vm_raw_root);

	/* see if we have a raw volmgt pathname (e.g. "/vol/dev/r*") */
	if (strncmp(path, vm_raw_root, vm_raw_root_len) == 0) {
		if (snprintf(res_buf, sizeof (res_buf), "%s/dev/%s", vm_root,
			path + vm_raw_root_len) >= sizeof (res_buf)) {
			return (NULL);
		}
		goto dun;
	}

	/* no match -- return what we got */
	if (strlcpy(res_buf, path, sizeof (res_buf)) >= sizeof (res_buf))
		return (NULL);

dun:
	return (res_buf);
}

static bool_t
work(action_t user_act, char *path, bool_t do_debug)
{
	char		*raw_pathp;
	bool_t		result;
	char		*symbolic_namep = NULL;
	/*
	 * If necessary, convert path from a symbolic pathname
	 * or device alias to an actual raw path name.
	 */

	raw_pathp = name_deref(path, &symbolic_namep);

	/*
	 * Make sure that the process has the right to access
	 * the volume.
	 */
	if (raw_pathp != NULL) {
		result = access_ok(raw_pathp);
	} else {
		result = FALSE;
	}

	if (result == TRUE) {
		/*
		 * Set the environment variables for rmmount.
		 */
		result = setup_env(user_act, raw_pathp, symbolic_namep);
	}
	if (result == TRUE) {
		result = call_rmmount(do_debug);
	}
	if ((result == TRUE) && (user_act == REMOUNT_MEDIUM)) {
		result = remount_medium(raw_pathp);
	}
	if (raw_pathp != NULL) {
		free(raw_pathp);
	}
	return (result);
}
