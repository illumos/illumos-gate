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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms..
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<malloc.h>
#include	<sys/types.h>
#include	<sys/dkio.h>
#include	<sys/cdio.h>
#include	<sys/vtoc.h>
#include	<sys/param.h>
#include	<sys/systeminfo.h>
#include	<sys/stat.h>
#include	<rpc/types.h>
#include	<errno.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<dirent.h>
#include	<pwd.h>
#include	<limits.h>
#include	<signal.h>
#include	<string.h>
#include	<libintl.h>
#include	<rmmount.h>
#include	<volmgt.h>

#define	DEFAULT_DSODIR	"/usr/lib/rmmount"

/*
 * the number of video files to be found to meet dvd standards
 */
#define	VFILE_NUM	3

extern void	dprintf(const char *fmt, ...);

typedef	enum	result_code {
	ACTION_FAILURE = 0,
	ACTION_SUCCESS
} action_result_t;

static action_result_t
start_player(struct action_arg **, int, char **);

static void
setup_user(void);

static int
setup_user_environment(void);

static bool_t
video_present(struct action_arg **);

/*
 * action_dvdvideo.c is a shared library loaded by rmmount. The interface
 * is private with rmmount and all input parameters are assumed to
 * be valid.
 *
 *    struct action_arg {
 *       char    *aa_path;        path to vol's block special file
 *       char    *aa_rawpath;     path to vol's character special file
 *       char    *aa_type;        file system type
 *       char    *aa_media;       class of media
 *       char    *aa_partname;    iff a partition, partition name
 *       char    *aa_mountpoint;  path this file system mounted on
 *       int     aa_clean;        is the file system stable
 *       int     aa_mnt;          is it mounted (TRUE/FALSE)
 *    };
 *
 *    argc: the number of items passed in the argv list
 *    argv: the program and it's arguments to be started
 *
 *  Returns:
 *      FAILURE 0
 *      SUCCESS 1
 *
 *  action() is an external public interface that follows the action.so
 *  interface spec. action() is the entry point for action_dvdvideo.so
 */
int
action(struct action_arg **action_arg, int argc, char **argv)
{
	action_result_t		action_result = TRUE;
	int			result;
	char			*actiontype = getenv("VOLUME_ACTION");
	bool_t			have_video;

	/*
	 * if this is an eject, get out
	 */
	if (strcmp(actiontype, "insert") != 0) {
		dprintf("%s[%d]: don't start video unless inserting\n",
			__FILE__, __LINE__);
		action_result = ACTION_FAILURE;
	}
	/*
	 * We are provided a mount point only if media or a partition
	 * has been mounted. If there is not one, we fail right away
	 */
	if ((action_result == ACTION_SUCCESS) &&
	    (action_arg[0]->aa_mountpoint == NULL)) {
		action_result = ACTION_FAILURE;
	}

	/*
	 * Determine if the mounted file system has
	 * video files based on the dvd standard.
	 */

	if (action_result == ACTION_SUCCESS) {
		have_video = video_present(action_arg);
		if (have_video == FALSE) {
			action_result = ACTION_FAILURE;
		}
	}

	/*
	 * If this .so is being called because of an eject, we needed
	 * to check for valid video files. If we found them we do not want
	 * to start the video player.
	 *
	 * We only want to start the video player when we find the correct
	 * video files and the action is an 'insert'.
	 */

	if (action_result == ACTION_SUCCESS) {
		/*
		 * Start the video player.
		 */
		dprintf("%s[%d]: Found video files, starting player\n",
			__FILE__, __LINE__);
		action_result = start_player(action_arg, argc, argv);
		/*
		 * if player failed, we still want to stop future actions
		 * so we need to change action_result to ACTION_SUCCESS
		 */
		if (action_result == ACTION_FAILURE) {
			dprintf("%s[%d]:Failed to start video, However\
				the media contains video\n",
				__FILE__, __LINE__);
			action_result = ACTION_SUCCESS;
		}

	}

	if (action_result == ACTION_SUCCESS) {
		result = TRUE;
	} else {
		result = FALSE;
	}

	return (result);
}

/*
 * setup_user_environment():
 * 	no parameters.
 *
 * 	Sets up basic user environment to run the player
 * 	Sets up the DISPLAY, setup library path,
 * 	the X file search path, the X user files search path.
 *
 * 	Finally sets the xwindow home
 *
 * 	The only failure within this function is not enough memory
 * 	resulting from calls to 'putenv()'.
 */

static int
setup_user_environment(void)
{
	int	rc;

	/*
	 * Set DISPLAY environment variable to ":0.0"
	 *
	 * cde sets DISPLAY, however, we still set it because
	 * cde may not be running.
	 *
	 * If the user set the display in the argv list,
	 * the user's setting will override this setting of DISPLAY
	 */
	rc = putenv("DISPLAY=:0.0");

	/*
	 * Set up the library path so the player can find any required
	 * runtine libraries.
	 */
	if (rc == 0) {
		rc = putenv("LD_LIBRARY_PATH=\
			    /usr/lib, /usr/openwin/lib, \
			    /usr/ucblib");
	}

	/*
	 * Set up the X files search path so the window application
	 * can be found.
	 */
	if (rc == 0) {
		rc = putenv("XFILESEARCHPATH=\
				/usr/openwin/lib/app-defaults/%L/%N, \
				/usr/opwnwin/lib/app-defaults/%N");

	}

	/*
	 * Set up the X user File search path, it happens that
	 * it value is the same as the previous variable. However,
	 * window applications still use this variable.
	 */
	if (rc == 0) {
		rc = putenv("XUSERFILESEARCHPATH=\
			/usr/openwin/lib/app-defaults/%L/%N, \
			/usr/opwnwin/lib/app-defaults/%N");
	}

	/*
	 * Set the openwin home environment variable.
	 */

	if (rc == 0) {
		rc = putenv("OPENWINHOME=/usr/openwin");
	}

	return (rc);
}

/*
 * setup_user()
 * 	no parameters
 *
 * 	This process runs as root and when the player is started
 * 	it should not be owned by root. However, if we are not able
 * 	to get the uid of the user, we allow the root uid to be set.
 *
 * 	Therefor this procedure sets the uid to the user that
 * 	owns the console and resets the gid also.
 *
 * 	The users home environment variable is set as well.
 */
static void
setup_user(void)
{
	struct stat	stat_buf;
	uid_t		uid = 1;  /* daemon */
	gid_t		gid = 1;  /* other */
	struct passwd	*passwd_ent;
	static char	env_buf[MAXNAMELEN];

	/*
	 * Want to get the uid of the user who has
	 * the console. The assumption is the console
	 * owner is the user wanting to play the video
	 */

	if (stat("/dev/console", &stat_buf) == 0) {
		if (stat_buf.st_uid != 0) {
			uid = stat_buf.st_uid;
		}
	}

	/*
	 * Set the home environment variable to
	 * the users home.
	 */

	if ((passwd_ent = getpwuid(uid)) != NULL) {
		gid = passwd_ent->pw_gid;
		(void) sprintf(env_buf, "HOME=%s", passwd_ent->pw_dir);
		(void) putenv(env_buf);
	} else {
		/* uid is left to be root, use /tmp as home */
		(void) putenv("HOME=/tmp");
	}

	if (setgid(gid) < 0) {
		perror("Failed to set gid");
	}

	if (setuid(uid) < 0) {
		perror("Failed to set uid");
	}

}

/*
 * start_player
 * 	input: acton_arg (from rmm.c) and the argv list used
 *		when starting the player.
 *
 *  forks
 *     Child: calls the fcns that set up the appropriate env var's
 *     and user values.
 *
 *     We need to append the mount point of the dvd media to the
 *     arg list. Because argv[0] points to the name of this dso,
 *     the argv list is moved up 1 and the mountpoint is added
 *     at argv[argc -1].
 *
 *     Parent: Checks if the exec'd process is alive and if so
 *     return ACTION_SUCCESS otherwise returns ACTION_FAILURE
 */
static action_result_t
start_player(struct action_arg **aa, int argc, char **argv)
{
	pid_t		child_pid;
	action_result_t	action_result = ACTION_SUCCESS;
	/*
	 * Set the ENXIO eject attribute so the video
	 * player will get an ENXIO when/if an eject is typed
	 * into another window.
	 */
	media_setattr(aa[0]->aa_rawpath, "s-enxio", "true");

	if ((child_pid = fork()) == 0) {
		/* child */
		int	fd;
		int	rc;
		int	i;

		/*
		 * Change our running dir to /tmp directory
		 */
		(void) chdir("/tmp");

		/*
		 * Redirect all output to go to the console.
		 */
		if ((fd = open("/dev/console", O_RDWR)) >= 0) {
			(void) dup2(fd, fileno(stdin));
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
		}

		/*
		 * Set user's id and group id
		 * change 'HOME' to the users home directory.
		 */
		(void) setup_user();

		/*
		 * Set up the user environment for running
		 * the video player.
		 */
		rc = setup_user_environment();

		/*
		 * The first arg in argv is this dso, and we want to
		 * append the mountpoint at then end of the argv.
		 * We shift up all args, replacing argv[0] with the
		 * player name. The last argv entry will point to the
		 * path to the dvd mount point.
		 */

		if (rc == 0) {
			for (i = 0; i < (argc -1); i++) {
				argv[i] = argv[i+1];
			}
			argv[argc -1] = (char *)(aa[0]->aa_mountpoint);

			rc = execv(argv[0], argv);
		} else {
			fprintf(stderr, "%s[%d]: Out of memory\n",
				__FILE__, __LINE__);
		}

		/*
		 * If we get this far, the execv failed
		 * and we must exit.
		 */

		(void) fprintf(stderr,
				gettext("exec of '%s' failed: %s\n"),
				argv[0], strerror(errno));

		exit(1);

		/* NOTREACHED */
	}

	/*
	 * Sleep for a brief moment to give the player time to
	 * start and fail.
	 */

	(void) sleep(1);

	/* Check to see if the program is running */
	if (kill(child_pid, 0) == -1) {
		dprintf("DVD player '%s' failed to run\n", argv[0]);
		action_result = ACTION_FAILURE;
	}

	return (action_result);
}



static bool_t
video_present(struct action_arg **aa)
{
	int		required_files = 0;
	char		video_dirname[PATH_MAX];
	DIR		*video_dir;
	struct dirent	*dp;

	/*
	 * Lets make sure we have a mount point to work with.
	 */
	if (aa[0]->aa_mountpoint == NULL) {
		return (FALSE);
	}

	(void) snprintf(video_dirname, sizeof (video_dirname),
	    "%s/VIDEO_TS", aa[0]->aa_mountpoint);

	if ((video_dir = opendir(video_dirname)) == NULL) {
		dprintf("No VIDEO_TS director found\n");
		return (FALSE);
	}

	/*
	 * We need an .IFO a .BUP and at least one .VOB file.
	 */
	while ((dp = readdir(video_dir)) != NULL ||
	    required_files == VFILE_NUM) {
		if (strcmp(dp->d_name, "VIDEO_TS.IFO") == 0)
			required_files++;
		else if (strcmp(dp->d_name, "VIDEO_TS.BUP") == 0)
			required_files++;
		else if (strstr(dp->d_name, ".VOB") != NULL)
			required_files++;
	}

	(void) closedir(video_dir);
	return (required_files >= VFILE_NUM);
}
