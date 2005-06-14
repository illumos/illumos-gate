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
 * action_filemgr.so - filemgr interface routines for rmmount
 *
 * This shared object allows rmmount to communicate with filemgr.
 * This is done by communicating over a named pipe that filemgr
 * creates in directory NOTIFY_DIR.  The name of the pipe must
 * begin with NOTIFY_NAME.  This source file contains #define
 * compiler directives set the values of NOTIFY_DIR and NOTIFY_NAME.
 *
 * After a partition on a medium has been mounted as a result of
 * either insertion or remounting of the medium, the action()
 * method creates a file named with the symbolic name of the
 * device in which the medium is inserted and the partition name
 * (e.g. "jaz0-s2") in NOTIFY_DIR.  The file consists of one text
 * line containing a string naming the mount point of the partition,
 * a string giving the raw device path to the partition, and a
 * string naming the file system type on the partition.  The action()
 * method then sends a single character ('i' for insertion, 'r' for
 * remounting) through the named pipe NOTIFY_NAME to tell filemgr to
 * look for new files in NOTIFY_DIR.
 *
 * If a medium containing no mountable partitions is inserted
 * or remounted in a device, the action() method creates a file
 * named with the symbolic name of the device in NOTIFY_DIR.
 * The file consists of one text line containing a string
 * giving the symbolic name of the device and a string naming
 * the reason that the medium couldn't be mounted.  The action
 * method then sends either an 'i' or an 'r' through the named
 * pipe to tell filemgr to look for new files in NOTIFY_DIR.
 *
 * When a medium is ejected or unmounted, the action() method
 * removes the files that were created in NOTIFY_DIR when the medium
 * was inserted or remounted and sends a single character ('e' for
 * ejection, 'u' for unmounting) through the named pipe.
 *
 * The following environment variables must be set before calling action():
 *
 *	VOLUME_ACTION		action that occurred (e.g. "insert", "eject")
 *	VOLUME_SYMDEV		symbolic name (e.g. "cdrom0", "floppy1")
 *	VOLUME_NAME		volume name (e.g. "unnamed_cdrom", "s2")
 */


#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/dkio.h>
#include	<sys/cdio.h>
#include	<sys/vtoc.h>
#include	<sys/param.h>
#include	<rpc/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<string.h>
#include	<dirent.h>
#include	<rmmount.h>
#include	<signal.h>

/*
 * Tell file manager about the new medium.
 */


/* for debug messages -- from rmmount */

extern char	*not_mountable(char *);
extern void	dprintf(const char *, ...);
extern int	makepath(char *, mode_t);

/*
 * Notifies action() that it's handling an audio CD.
 */

extern	int	audio_cd;

/*
 * Private attribute types and attributes.
 */

typedef enum {
	EJECT,
	INSERT,
	REMOUNT,
	UNMOUNT
} action_t;

static const char notify_characters[] = {
	'e',
	'i',
	'r',
	'u'
};

static const char *result_strings[] = {
	"FALSE",
	"TRUE"
};

#define	NOTIFY_DIR	"/tmp/.removable"	/* dir where filemgr looks */
#define	NOTIFY_NAME	"notify"		/* named pipe to talk over */


/*
 * Declarations of private methods
 */

static int create_one_notify_file(char *fstype,
				char *mount_point,
				char *notify_file,
				char *raw_partitionp,
				char *reason,
				char *symdev);
static int	create_notify_files(struct action_arg **aa);
static int	notify_clients(action_t action, int do_notify);
static void	popdir(int fd);
static int	pushdir(const char *dir);
static int	remove_notify_files(struct action_arg **aa);

/*
 * Definition of the externally visible action() method.
 */

/*
 * Neither argc nor argv is used in action(), but unfortunately
 * action()'s signature must include them as formal parameters
 * in order to conform to the definition of the public interface
 * to "action" dynamic shared objects.
 */

/* ARGSUSED1 */
int
action(struct action_arg **aa, int argc, char **argv)
{
	char 		*action;
	int		result;
	int		do_notify = FALSE;
	action_t	notify_act = EJECT;

	dprintf("%s[%d]: entering action()\n", __FILE__, __LINE__);

	action = getenv("VOLUME_ACTION");

	if (strcmp(action, "clear_mounts") == 0) {
		/*
		 * Remove the notifications files, but don't
		 * notify the client.  The "clear_mounts" action
		 * simply clears all existing mounts of a medium's
		 * partitions after a medium has been repartitioned.
		 * Then vold builds a new file system that reflects
		 * the medium's new partition structure and mounts
		 * the new partitions by calling rmmount, and therefore
		 * action(), with the VOLUME_ACTION environment variable
		 * set to "remount".
		 */
		result = remove_notify_files(aa);
		result = TRUE;
	} else if (strcmp(action, "eject") == 0) {
		result = remove_notify_files(aa);
		if (result == TRUE) {
			do_notify = TRUE;
			notify_act = EJECT;
		}
	} else if (strcmp(action, "insert") == 0) {
		result = create_notify_files(aa);
		if (result == TRUE) {
			do_notify = TRUE;
			notify_act = INSERT;
		}
	} else if (strcmp(action, "remount") == 0) {
		result = create_notify_files(aa);
		if (result == TRUE) {
			do_notify = TRUE;
			notify_act = REMOUNT;
		}
	} else if (strcmp(action, "unmount") == 0) {
		result = remove_notify_files(aa);
		if (result == TRUE) {
			do_notify = TRUE;
			notify_act = UNMOUNT;
		}
	} else {
		dprintf("%s[%d]: action(): invalid action: %s\n",
			__FILE__, __LINE__, action);
		result = FALSE;
	}

	if (result == TRUE) {
		result = notify_clients(notify_act, do_notify);
	}

	dprintf("%s[%d]: leaving action(), result = %s\n",
		__FILE__, __LINE__, result_strings[result]);

	if (result == TRUE) {
		/*
		 * File Manager is running. return 0.
		 * see man page rmmount.conf(4).
		 */
		return (0);
	} else {
		return (1);
	}
}

/*
 * Definitions of private methods.
 */

static int
create_notify_files(struct action_arg **aa)
{
	int	ai;
	char	*fstype;
	char	*mount_point;
	char	notify_file[64];
	char	*raw_partitionp;
	char	*reason; /* Why the medium wasn't mounted */
	int	result;
	char	*symdev;

	dprintf("%s[%d]: entering create_notify_files()\n", __FILE__, __LINE__);

	ai = 0;
	result = FALSE;
	symdev = getenv("VOLUME_SYMDEV");
	while ((aa[ai] != NULL) && (aa[ai]->aa_path != NULL)) {
		if (aa[ai]->aa_mountpoint != NULL) {
			if (aa[ai]->aa_type) {
				fstype = aa[ai]->aa_type;
			} else {
				fstype = "unknown";
			}
			mount_point = strdup(aa[ai]->aa_mountpoint);
			if (aa[ai]->aa_partname != NULL) {
				/*
				 * Is aa_partname ever NULL?
				 * When time permits, check.
				 * If it is, the action taken
				 * in the else clause could produce
				 * file name conflicts.
				 */
				sprintf(notify_file, "%s-%s", symdev,
						aa[ai]->aa_partname);
			} else {
				sprintf(notify_file, "%s-0", symdev);
			}
			reason = NULL;
		} else {
			/*
			 * The partition isn't mounted.
			 */
			fstype = "none";
			mount_point = "none";
			reason = not_mountable(getenv("VOLUME_NAME"));
			if (reason != NULL) {
				sprintf(notify_file, "%s-0", symdev);
			} else {
				/*
				 * Either the partition is a backup slice, or
				 * rmmount tried to mount the partition, but
				 * idenf_fs couldn't identify the file system
				 * type; that can occur when rmmount is
				 * trying to mount all the slices in a Solaris
				 * VTOC, and one or more partitions don't have
				 * file systems in them.
				 */
				if (aa[0]->aa_partname != NULL) {
					/*
					 * Is aa_partname ever NULL?
					 * When time permits, check.
					 * If it is, the action taken
					 * in the else clause could produce
					 * file name conflicts.
					 */
					sprintf(notify_file, "%s-%s", symdev,
							aa[0]->aa_partname);
				} else {
					sprintf(notify_file, "%s-0", symdev);
				}
				if ((aa[0]->aa_type != NULL) &&
					(strcmp(aa[0]->aa_type, "backup_slice")
						== 0)) {
					reason = "backup_slice";
				} else {
					reason = "unformatted_media";
				}
				/*
				 * "unformatted_media" should be
				 * changed to "unformmated_medium" for
				 * grammatical correctness, but
				 * "unformatted_media" is now specified
				 * in the interface to filemgr, so the
				 * change can't be made without the
				 * approval of the CDE group.
				 */
			}
		}
		raw_partitionp = aa[0]->aa_rawpath;
		result = create_one_notify_file(fstype,
				mount_point,
				notify_file,
				raw_partitionp,
				reason,
				symdev);
		ai++;
	}
	dprintf("%s[%d]: leaving create_notify_files(), result = %s\n",
		__FILE__, __LINE__, result_strings[result]);
	return (result);
}

static int
create_one_notify_file(char *fstype,
	char *mount_point,
	char *notify_file,
	char *raw_partitionp,
	char *reason,
	char *symdev)
{
	/*
	 * For a mounted partition, create a notification file
	 * indicating the mount point,  the raw device pathname
	 * of the partition, and the partition's file system
	 * type.  For an unmounted partition, create a
	 * notification file containing the reason that the
	 * partition wasn't mounted and the raw device pathname
	 * of the partition.
	 *
	 * Create the file as root in a world-writable
	 * directory that resides in a world-writable directory.
	 *
	 * Handle two possible race conditions that could
	 * allow security breaches.
	 */

	int	current_working_dir_fd;
	int	file_descriptor;
	FILE	*filep;
	int	result;

	dprintf("%s[%d]:Entering create_one_notify_file()\n",
		__FILE__, __LINE__);
	dprintf("\tcreate_one_notify_file(): fstype = %s\n", fstype);
	dprintf("\tcreate_one_notify_file(): mount_point = %s\n", mount_point);
	dprintf("\tcreate_one_notify_file(): notify_file = %s\n", notify_file);
	dprintf("\tcreate_one_notify_file(): raw_partitionp = %s\n",
		raw_partitionp);
	if (reason != NULL) {
		dprintf("\tcreate_one_notify_file(): reason = %s\n", reason);
	} else {
		dprintf("\tcreate_one_notify_file(): reason = NULL\n");
	}
	dprintf("\tcreate_one_notify_file(): symdev = %s\n", symdev);

	result = TRUE;
	/*
	 * Handle Race Condition One:
	 *
	 *   If NOTIFY_DIR exists, make sure it is not a symlink.
	 *   if it is, remove it and try to create it.  Check
	 *   again to make sure NOTIFY_DIR isn't a symlink.
	 *   If it is, remove it and return without creating
	 *   a notification file.  The condition can only occur if
	 *   someone is trying to break into the system by running
	 *   a program that repeatedly creates NOTIFY_DIR as a
	 *   symlink.  If NOTIFY_DIR exists and isn't a symlink,
	 *   change the working directory to NOTIFY_DIR.
	 */
	current_working_dir_fd = pushdir(NOTIFY_DIR);
	if (current_working_dir_fd < 0) {
		(void) makepath(NOTIFY_DIR, 0777);
		current_working_dir_fd = pushdir(NOTIFY_DIR);
		if (current_working_dir_fd < 0) {
			result = FALSE;
		}
	}
	/*
	 * Handle Race Condition Two:
	 *
	 * Create the notification file in NOTIFY_DIR.
	 * Remove any files with the same name that may already be
	 * there, using remove(), as it safely removes directories.
	 * Then open the file O_CREAT|O_EXCL, which doesn't follow
	 * symlinks and requires that the file not exist already,
	 * so the new file actually resides in the current working
	 * directory.  Create the file with access mode 644, which
	 * renders it unusable by anyone trying to break into the
	 * system.
	 */
	if (result == TRUE) {
		/*
		 * The current working directory is now NOTIFY_DIR.
		 */
		(void) remove(notify_file);
		file_descriptor =
			open(notify_file, O_CREAT|O_EXCL|O_WRONLY, 0644);
		if (file_descriptor < 0) {
			dprintf("%s[%d]: can't create %s/%s; %m\n",
				__FILE__, __LINE__, NOTIFY_DIR, notify_file);
			result = FALSE;
		} else {
			filep = fdopen(file_descriptor, "w");
			if (filep != NULL) {
				if (reason == NULL) {
					(void) fprintf(filep, "%s %s %s",
						mount_point,
						raw_partitionp,
						fstype);
					(void) fclose(filep);
				dprintf("%s[%d]: Just wrote %s %s %s to %s\n",
						__FILE__,
						__LINE__,
						mount_point,
						raw_partitionp,
						fstype,
						notify_file);
				} else {
					(void) fprintf(filep, "%s %s",
						reason, raw_partitionp);
					(void) fclose(filep);
				dprintf("%s[%d]: Just wrote %s %s to %s\n",
						__FILE__,
						__LINE__,
						reason,
						raw_partitionp,
						notify_file);
				}
			} else {
				dprintf("%s[%d]: can't write %s/%s; %m\n",
					__FILE__, __LINE__,
					NOTIFY_DIR, notify_file);
				(void) close(file_descriptor);
				result = FALSE;
			}
		}
		popdir(current_working_dir_fd);
	}
	dprintf("%s[%d]: leaving create_one_notify_file, result = %s\n",
		__FILE__, __LINE__, result_strings[result]);
	return (result);
}

static bool_t
notify_clients(action_t action, int do_notify)
{
	/*
	 * Notify interested applications of changes in the state
	 * of removable media.  Interested applications are those
	 * that create a named pipe in NOTIFY_DIR with a name that
	 * begins with "notify".  Open the pipe and write a
	 * character through it that indicates the type of state
	 * change = 'e' for ejections, 'i' for insertions, 'r'
	 * for remounts of the file systems on repartitioned media,
	 * and 'u' for unmounts of file systems.
	 */

	int		current_working_dir_fd;
	DIR		*dirp;
	struct dirent	*dir_entryp;
	size_t		len;
	int		fd;
	char		namebuf[MAXPATHLEN];
	char		notify_character;
	void		(*old_signal_handler)();
	int		result;
	struct stat	sb;

	dprintf("%s[%d]: entering notify_clients()\n", __FILE__,
		__LINE__);

	result = TRUE;
	/*
	 * Use relative pathnames after changing the
	 * working directory to the notification directory.
	 * Check to make sure that each "notify" file is a
	 * named pipe to make sure that it hasn't changed
	 * its file type, which could mean that someone is
	 * trying to use "notify" files to break into the
	 * system.
	 */
	if ((current_working_dir_fd = pushdir(NOTIFY_DIR)) < 0) {
		result = FALSE;
	}
	if (result == TRUE) {
		dirp = opendir(".");
		if (dirp == NULL) {
			dprintf("%s[%d]:opendir failed on '.'; %m\n",
				__FILE__, __LINE__);
			popdir(current_working_dir_fd);
			result = FALSE;
		}
	}
	if (result == TRUE) {
		/*
		 * Read through the directory and write a notify
		 * character to all files whose names start with "notify".
		 */
		result = FALSE;
		old_signal_handler = signal(SIGPIPE, SIG_IGN);
		len = strlen(NOTIFY_NAME);
		while (dir_entryp = readdir(dirp)) {
			if (strncmp(dir_entryp->d_name, NOTIFY_NAME, len)
			    != 0) {
				continue;
			}
			result = TRUE;
			if (do_notify != TRUE) {
				continue;
			}
			(void) sprintf(namebuf, "%s/%s",
				NOTIFY_DIR, dir_entryp->d_name);
			if ((fd = open(namebuf, O_WRONLY|O_NDELAY)) < 0) {
				dprintf("%s[%d]: open failed for %s; %m\n",
				    __FILE__, __LINE__, namebuf);
				continue;
			}
			/*
			 * Check to be sure that the entry is a named pipe.
			 * That closes a small security hole that could
			 * enable unauthorized access to the system root.
			 */
			if ((fstat(fd, &sb) < 0) || (!S_ISFIFO(sb.st_mode))) {
				dprintf("%s[%d]: %s isn't a named pipe\n",
					__FILE__, __LINE__, namebuf);

				(void) close(fd);
				continue;
			}
			notify_character = notify_characters[action];
			if (write(fd, &notify_character, 1) < 0) {
				dprintf("%s[%d]: write failed for %s; %m\n",
				    __FILE__, __LINE__, namebuf);
				(void) close(fd);
				continue;
			}
			(void) close(fd);
		}
		(void) closedir(dirp);
		(void) signal(SIGPIPE, old_signal_handler);
		popdir(current_working_dir_fd);
	}
	dprintf("%s[%d]: leaving notify_clients(), result = %s\n",
		__FILE__, __LINE__, result_strings[result]);
	return (result);
}

static void
popdir(int fd)
{
	/*
	 * Change the current working directory to the directory
	 * specified by fd and close the fd.  Exit the program
	 * on failure.
	 */
	if (fchdir(fd) < 0) {
		dprintf("%s[%d]: popdir() failed\n", __FILE__, __LINE__);
		exit(1);
	}
	(void) close(fd);
}

static int
pushdir(const char *dir)
{
	/*
	 * Change the current working directory to dir and
	 * return a file descriptor for the old working
	 * directory.
	 *
	 * Exception handling:
	 *
	 * If dir doesn't exist, leave the current working
	 * directory the same and return -1.
	 *
	 * If dir isn't a directory, remove it, leave the
	 * current working directory the same, and return -1.
	 *
	 * If open() fails on the current working directory
	 * or the chdir operation fails on dir, leave the
	 * current working directory the same and return -1.
	 */

	int		current_working_dir_fd;
	struct stat	stat_buf;

	if (lstat(dir, &stat_buf) < 0) {
		dprintf("%s[%d]: push_dir_and_check(): %s does not exist\n",
			__FILE__, __LINE__, dir);
		return (-1);
	}

	if (!(S_ISDIR(stat_buf.st_mode))) {
	dprintf("%s[%d]: push_dir_and_check(): %s is not a directory.\n",
			__FILE__, __LINE__, dir);
		(void) remove(dir);
		return (-1);
	}
	if ((current_working_dir_fd = open(".", O_RDONLY)) < 0) {
		dprintf("%s[%d]: push_dir_and_check(): can't open %s.\n",
			__FILE__, __LINE__, dir);
		return (-1);
	}
	if (chdir(dir) < 0) {
		(void) close(current_working_dir_fd);
		dprintf("%s[%d]: push_dir_and_check(): can't chdir() to %s.\n",
			__FILE__, __LINE__, dir);
		return (-1);
	}
	return (current_working_dir_fd);
}

static int
remove_notify_files(struct action_arg **aa)
{
	int	ai;
	int	current_working_dir_fd;
	char	notify_file[64];
	int	result;
	char	*symdev;

	dprintf("%s[%d]: entering remove_notify_files()\n", __FILE__, __LINE__);

	ai = 0;
	result = TRUE;
	symdev = getenv("VOLUME_SYMDEV");
	while ((result == TRUE) &&
		(aa[ai] != NULL) &&
		(aa[ai]->aa_path != NULL)) {

		if (not_mountable(getenv("VOLUME_NAME"))) {
			sprintf(notify_file, "%s-0", symdev);
		} else if (aa[ai]->aa_partname != NULL) {
			/*
			 * Is aa_partname ever NULL?
			 * When time permits, check.
			 * If it is, the action taken
			 * in the else clause could produce
			 * file name conflicts.
			 */
			sprintf(notify_file, "%s-%s",
				symdev, aa[0]->aa_partname);
		} else {
			sprintf(notify_file, "%s-0", symdev);
		}

		current_working_dir_fd = pushdir(NOTIFY_DIR);
		if (current_working_dir_fd < 0) {
			result = FALSE;
		}
		if ((result == TRUE) && (remove(notify_file) < 0)) {
			dprintf("%s[%d]: remove %s/%s; %m\n",
				__FILE__, __LINE__, NOTIFY_DIR, notify_file);
			result = FALSE;
		}
		if (current_working_dir_fd != -1) {
			popdir(current_working_dir_fd);
		}
		ai++;
	}
	dprintf("%s[%d]: leaving remove_notify_files(), result = %s\n",
		__FILE__, __LINE__, result_strings[result]);

	return (result);
}
