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
 */

/*
 * Vold compatibility for rmvolmgr: emulate old commands as well as
 * action_filemgr.so to notify legacy apps via /tmp/.removable pipes.
 * A lot of this code is copied verbatim from vold sources.
 *
 * Here's the original description of action_filemgr.so:
 *
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


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <libintl.h>
#include <zone.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <sys/cdio.h>
#include <sys/vtoc.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <libcontract.h>
#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <tsol/label.h>

#include "vold.h"
#include "rmm_common.h"

int		rmm_debug = 0;
boolean_t	rmm_vold_actions_enabled = B_FALSE;
boolean_t	rmm_vold_mountpoints_enabled = B_FALSE;

static char	*prog_name = NULL;
static pid_t	prog_pid = 0;
static int	system_labeled = 0;
static uid_t	mnt_uid = (uid_t)-1;
static gid_t	mnt_gid = (gid_t)-1;
static zoneid_t	mnt_zoneid = -1;
static char	mnt_zoneroot[MAXPATHLEN];
static char	mnt_userdir[MAXPATHLEN];

/*
 * Private attribute types and attributes.
 */
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

static void	volrmmount_usage();
static void	volcheck_usage();
static int	vold_action(struct action_arg *aap);
static void	vold_update_mountpoints(struct action_arg *aap);
static char	*not_mountable(struct action_arg *aa);
static int	create_one_notify_file(char *fstype,
				char *mount_point,
				char *notify_file,
				char *raw_partitionp,
				char *reason,
				char *symdev);
static int	create_notify_files(struct action_arg **aa);
static boolean_t notify_clients(action_t action, int do_notify);
static void	popdir(int fd);
static int	pushdir(const char *dir);
static boolean_t remove_notify_files(struct action_arg **aa);

/*
 * should be called once from main()
 */
/* ARGSUSED */
void
vold_init(int argc, char **argv)
{
	system_labeled = is_system_labeled();
}

/*
 * Old version of rmmount(8)
 */
/* ARGSUSED */
int
vold_rmmount(int argc, char **argv)
{
	char		*volume_action;
	char		*volume_mediatype;
	char		*volume_mount_mode;
	char		*volume_name;
	char		*volume_path;
	char		*volume_pcfs_id;
	char		*volume_symdev;
	char		*volume_zonename;
	char		*volume_user;
	action_t	action;
	char		mountpoint[MAXPATHLEN];
	char		*zonemountpoint;
	char		*arg_mountpoint = NULL;
	LibHalContext	*hal_ctx;
	DBusError	error;
	rmm_error_t	rmm_error;
	int		ret;

	prog_name = argv[0];
	prog_pid = getpid();

	mnt_zoneroot[0] = '\0';
	mnt_userdir[0] = '\0';

	volume_action = getenv("VOLUME_ACTION");
	volume_mediatype = getenv("VOLUME_MEDIATYPE");
	volume_mount_mode = getenv("VOLUME_MOUNT_MODE");
	volume_name = getenv("VOLUME_NAME");
	volume_path = getenv("VOLUME_PATH");
	volume_pcfs_id = getenv("VOLUME_PCFS_ID");
	volume_symdev = getenv("VOLUME_SYMDEV");

	if (system_labeled) {
		volume_zonename = getenv("VOLUME_ZONE_NAME");
		volume_user = getenv("VOLUME_USER");
	}
	if (volume_action == NULL) {
		dbgprintf("%s(%ld): VOLUME_ACTION was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}
	if (volume_mediatype == NULL) {
		dbgprintf("%s(%ld): VOLUME_MEDIATYPE was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}
	if (volume_mount_mode == NULL) {
		volume_mount_mode = "rw";
	}
	if (volume_name == NULL) {
		dbgprintf("%s(%ld): VOLUME_NAME was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}
	if (volume_path == NULL) {
		dbgprintf("%s(%ld): VOLUME_PATH was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}
	if (volume_pcfs_id == NULL) {
		volume_pcfs_id = "";
	}
	if (volume_symdev == NULL) {
		dbgprintf("%s(%ld): VOLUME_SYMDEV was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}

	if (system_labeled) {
		if (volume_zonename != NULL &&
		    strcmp(volume_zonename, GLOBAL_ZONENAME) != 0) {
			if ((mnt_zoneid =
			    getzoneidbyname(volume_zonename)) != -1) {
				if (zone_getattr(mnt_zoneid, ZONE_ATTR_ROOT,
				    mnt_zoneroot, MAXPATHLEN) == -1) {
					dbgprintf("%s(%ld): NO ZONEPATH!!\n",
					    prog_name, prog_pid);
					return (-1);
				}
			}
		} else {
			mnt_zoneid = GLOBAL_ZONEID;
			mnt_zoneroot[0] = '\0';
		}
		if (volume_user != NULL) {
			struct passwd	 *pw;

			if ((pw = getpwnam(volume_user)) == NULL) {
				dbgprintf("%s(%ld) %s\n", prog_name, prog_pid,
				    ": VOLUME_USER was not a valid user!");
				return (-1);
			}
			mnt_uid = pw->pw_uid;
			mnt_gid = pw->pw_gid;

			if (snprintf(mnt_userdir, sizeof (mnt_userdir),
			    "/%s-%s", volume_user, volume_symdev) >=
			    sizeof (mnt_userdir))
				return (-1);
		} else {
			mnt_uid = 0;
			mnt_userdir[0] = '\0';
		}

		rmm_vold_mountpoints_enabled = B_FALSE;
		rmm_vold_actions_enabled = B_TRUE;
	} else {
		rmm_vold_mountpoints_enabled = B_TRUE;
		rmm_vold_actions_enabled = B_TRUE;
	}

	if ((hal_ctx = rmm_hal_init(0, 0, 0, 0, &error, &rmm_error)) == NULL) {
		rmm_dbus_error_free(&error);

		/* if HAL's not running, must be root */
		if (geteuid() != 0) {
			(void) fprintf(stderr,
			    gettext("%s(%ld) error: must be root to execute\n"),
			    prog_name, prog_pid);
			return (-1);
		}
	}

	if (strcmp(volume_action, "eject") == 0) {
		action = EJECT;
	} else if (strcmp(volume_action, "insert") == 0) {
		action = INSERT;

		if (system_labeled) {
			/*
			 * create mount point
			 */
			if (strlen(mnt_userdir) > 0) {
				if (snprintf(mountpoint, MAXPATHLEN,
				    "%s/%s%s", mnt_zoneroot, volume_mediatype,
				    mnt_userdir) > MAXPATHLEN) {
					return (-1);

				}
				(void) makepath(mountpoint, 0700);
				(void) chown(mountpoint, mnt_uid, mnt_gid);
				/*
				 * set the top level directory bits to 0755
				 * so user can access it.
				 */
				if (snprintf(mountpoint, MAXPATHLEN,
				    "%s/%s", mnt_zoneroot,
				    volume_mediatype) <= MAXPATHLEN) {
					(void) chmod(mountpoint, 0755);
				}
			}
			if (snprintf(mountpoint, MAXPATHLEN,
			    "%s/%s%s/%s", mnt_zoneroot, volume_mediatype,
			    mnt_userdir, volume_name) > MAXPATHLEN) {
				(void) fprintf(stderr,
				    gettext("%s(%ld) error: path too long\n"),
				    prog_name, prog_pid);
				return (-1);
			}

			/* make our mountpoint */
			(void) makepath(mountpoint, 0755);

			arg_mountpoint = mountpoint;
		}
	} else if (strcmp(volume_action, "remount") == 0) {
		action = REMOUNT;
	} else if (strcmp(volume_action, "unmount") == 0) {
		action = UNMOUNT;
	}

	ret = rmm_action(hal_ctx, volume_symdev, action, 0, 0, 0,
	    arg_mountpoint) ? 0 : 1;

	if (hal_ctx != NULL) {
		rmm_hal_fini(hal_ctx);
	}

	return (ret);
}


/*
 * this should be called after rmm_hal_{mount,unmount,eject}
 */
int
vold_postprocess(LibHalContext *hal_ctx, const char *udi,
    struct action_arg *aap)
{
	int	ret = 0;

	/* valid mountpoint required */
	if ((aap->aa_action == INSERT) || (aap->aa_action == REMOUNT)) {
		rmm_volume_aa_update_mountpoint(hal_ctx, udi, aap);
		if ((aap->aa_mountpoint == NULL) ||
		    (strlen(aap->aa_mountpoint) == 0)) {
			return (1);
		}
	}

	if (rmm_vold_mountpoints_enabled) {
		vold_update_mountpoints(aap);
	}
	if (rmm_vold_actions_enabled) {
		ret = vold_action(aap);
	}

	return (ret);
}

/*
 * update legacy symlinks
 *
 * For cdrom:
 *
 *	/cdrom/<name> -> original mountpoint
 *	/cdrom/cdrom0 -> ./<name>
 *	/cdrom/cdrom -> cdrom0  (only for cdrom0)
 *
 * If it's a slice or partition, /cdrom/<name> becomes a directory:
 *
 *	/cdrom/<name>/s0
 *
 * Same for rmdisk and floppy.
 *
 * On labeled system (Trusted Solaris), links are in a user directory.
 */
static void
vold_update_mountpoints(struct action_arg *aap)
{
	boolean_t	is_partition;
	char		part_dir[2 * MAXNAMELEN];
	char		symname_mp[2 * MAXNAMELEN];
	char		symcontents_mp[MAXNAMELEN];
	char		symname[2 * MAXNAMELEN];
	char		symcontents[MAXNAMELEN];

	is_partition = (aap->aa_partname != NULL);

	if (!system_labeled) {
		if (!is_partition) {
			/* /cdrom/<name> -> original mountpoint */
			(void) snprintf(symcontents_mp, sizeof (symcontents_mp),
			    "%s", aap->aa_mountpoint);
			(void) snprintf(symname_mp, sizeof (symname_mp),
			    "/%s/%s", aap->aa_media, aap->aa_name);
		} else {
			/* /cdrom/<name>/slice -> original mountpoint */
			(void) snprintf(part_dir, sizeof (part_dir),
			    "/%s/%s", aap->aa_media, aap->aa_name);
			(void) snprintf(symcontents_mp, sizeof (symcontents_mp),
			    "%s", aap->aa_mountpoint);
			(void) snprintf(symname_mp, sizeof (symname_mp),
			    "/%s/%s/%s", aap->aa_media, aap->aa_name,
			    aap->aa_partname);

		}
		/* /cdrom/cdrom0 -> ./<name> */
		(void) snprintf(symcontents, sizeof (symcontents),
		    "./%s", aap->aa_name);
		(void) snprintf(symname, sizeof (symname),
		    "/%s/%s", aap->aa_media, aap->aa_symdev);
	} else {
		if (!is_partition) {
			/* /cdrom/<user>/<name> -> original mountpoint */
			(void) snprintf(symcontents_mp, sizeof (symcontents_mp),
			    "%s", aap->aa_mountpoint);
			(void) snprintf(symname_mp, sizeof (symname_mp),
			    "%s/%s/%s", mnt_zoneroot, aap->aa_media,
			    aap->aa_symdev);
		} else {
			/* /cdrom/<user>/<name>/slice -> original mountpoint */
			(void) snprintf(symcontents_mp, sizeof (symcontents_mp),
			    "%s", aap->aa_mountpoint);
			(void) snprintf(symname_mp, sizeof (symname_mp),
			    "%s/%s/%s", mnt_zoneroot, aap->aa_media,
			    aap->aa_symdev, aap->aa_partname);
		}

		/* /cdrom/<user>/cdrom0 -> ./<user>/<name> */
		(void) snprintf(symcontents, sizeof (symcontents),
		    ".%s/%s", mnt_userdir, aap->aa_name);
		(void) snprintf(symname, sizeof (symname), "%s/%s/%s",
		    mnt_zoneroot, aap->aa_media, aap->aa_symdev);
	}

	(void) unlink(symname);
	(void) unlink(symname_mp);
	if (is_partition) {
		(void) rmdir(part_dir);
	}

	if ((aap->aa_action == INSERT) || (aap->aa_action == REMOUNT)) {
		(void) mkdir(aap->aa_media, 0755);
		if (is_partition) {
			(void) mkdir(part_dir, 0755);
		}
		(void) symlink(symcontents_mp, symname_mp);
		(void) symlink(symcontents, symname);
	}
}


static int
vold_action(struct action_arg *aap)
{
	action_t	action;
	int		result;
	int		do_notify = FALSE;
	action_t	notify_act = EJECT;
	struct action_arg *aa[2];
	struct action_arg a1;

	dbgprintf("%s[%d]: entering action()\n", __FILE__, __LINE__);

	/*
	 * on Trusted Extensions, actions are executed in the user's zone
	 */
	if (mnt_zoneid > GLOBAL_ZONEID) {
		pid_t	pid;
		int	status;
		int	ifx;
		int	tmpl_fd;
		int	err = 0;

		tmpl_fd = open64(CTFS_ROOT "/process/template",
		    O_RDWR);
		if (tmpl_fd == -1)
			return (1);

		/*
		 * Deliver no events, don't inherit,
		 * and allow it to be orphaned.
		 */
		err |= ct_tmpl_set_critical(tmpl_fd, 0);
		err |= ct_tmpl_set_informative(tmpl_fd, 0);
		err |= ct_pr_tmpl_set_fatal(tmpl_fd,
		    CT_PR_EV_HWERR);
		err |= ct_pr_tmpl_set_param(tmpl_fd,
		    CT_PR_PGRPONLY |
		    CT_PR_REGENT);
		if (err || ct_tmpl_activate(tmpl_fd)) {
			(void) close(tmpl_fd);
			return (1);
		}
		switch (pid = fork1()) {
		case 0:
			(void) ct_tmpl_clear(tmpl_fd);
			for (ifx = 0; ifx < _NFILE; ifx++)
				(void) close(ifx);

			if (zone_enter(mnt_zoneid) == -1)
				_exit(0);

			/* entered zone, proceed to action */
			break;
		case -1:
			dbgprintf("fork1 failed \n ");
			return (1);
		default :
			(void) ct_tmpl_clear(tmpl_fd);
			(void) close(tmpl_fd);
			if (waitpid(pid, &status, 0) < 0) {
				dbgprintf("%s(%ld): waitpid() "
				    "failed (errno %d) \n",
				    prog_name, prog_pid, errno);
				return (1);
			}
		}
	}

	/* only support one action at a time XXX */
	a1.aa_path = NULL;
	aa[0] = aap;
	aa[1] = &a1;

	action = aa[0]->aa_action;

	if (action == CLEAR_MOUNTS) {
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
	} else if (action == EJECT) {
		result = remove_notify_files(aa);
		if (result == TRUE) {
			do_notify = TRUE;
			notify_act = EJECT;
		}
	} else if (action = INSERT) {
		result = create_notify_files(aa);
		if (result == TRUE) {
			do_notify = TRUE;
			notify_act = INSERT;
		}
	} else if (action == REMOUNT) {
		result = create_notify_files(aa);
		if (result == TRUE) {
			do_notify = TRUE;
			notify_act = REMOUNT;
		}
	} else if (action == UNMOUNT) {
		result = remove_notify_files(aa);
		if (result == TRUE) {
			do_notify = TRUE;
			notify_act = UNMOUNT;
		}
	} else {
		dbgprintf("%s[%d]: action(): invalid action: %s\n",
		    __FILE__, __LINE__, action);
		result = FALSE;
	}

	if (result == TRUE) {
		result = notify_clients(notify_act, do_notify);
	}

	dbgprintf("%s[%d]: leaving action(), result = %s\n",
	    __FILE__, __LINE__, result_strings[result]);

	if (mnt_zoneid > GLOBAL_ZONEID) {
		/* exit forked local zone process */
		_exit(0);
	}

	if (result == TRUE) {
		/*
		 * File Manager is running. return 0.
		 * see man page rmmount.conf(5).
		 */
		return (0);
	} else {
		return (1);
	}
}


/*
 * Returns NULL if a medium or partition is mountable
 * and a string stating the reason the medium or partition
 * can't be mounted if the medium or partition isn't mountable.
 *
 * If the volume_name of the medium or partition is one of the
 * following, the medium or partition isn't mountable.
 *
 * unlabeled_<media_type>
 * unknown_format
 * password_protected
 */
/* ARGSUSED */
static char *
not_mountable(struct action_arg *aa)
{
	return (NULL);
}

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

	dbgprintf("%s[%d]: entering create_notify_files()\n",
	    __FILE__, __LINE__);

	ai = 0;
	result = FALSE;
	symdev = aa[ai]->aa_symdev;
	while ((aa[ai] != NULL) && (aa[ai]->aa_path != NULL)) {
		if (aa[ai]->aa_mountpoint != NULL) {
			if (aa[ai]->aa_type) {
				fstype = aa[ai]->aa_type;
			} else {
				fstype = "unknown";
			}
			mount_point = aa[ai]->aa_mountpoint;
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
			reason = not_mountable(aa[ai]);
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
	dbgprintf("%s[%d]: leaving create_notify_files(), result = %s\n",
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

	dbgprintf("%s[%d]:Entering create_one_notify_file()\n",
	    __FILE__, __LINE__);
	dbgprintf("\tcreate_one_notify_file(): fstype = %s\n", fstype);
	dbgprintf("\tcreate_one_notify_file(): mount_point = %s\n",
	    mount_point);
	dbgprintf("\tcreate_one_notify_file(): notify_file = %s\n",
	    notify_file);
	dbgprintf("\tcreate_one_notify_file(): raw_partitionp = %s\n",
	    raw_partitionp);
	if (reason != NULL) {
		dbgprintf("\tcreate_one_notify_file(): reason = %s\n", reason);
	} else {
		dbgprintf("\tcreate_one_notify_file(): reason = NULL\n");
	}
	dbgprintf("\tcreate_one_notify_file(): symdev = %s\n", symdev);

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
			dbgprintf("%s[%d]: can't create %s/%s; %m\n",
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
				dbgprintf("%s[%d]: Just wrote %s %s %s to %s\n",
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
				dbgprintf("%s[%d]: Just wrote %s %s to %s\n",
				    __FILE__,
				    __LINE__,
				    reason,
				    raw_partitionp,
				    notify_file);
				}
			} else {
				dbgprintf("%s[%d]: can't write %s/%s; %m\n",
				    __FILE__, __LINE__,
				    NOTIFY_DIR, notify_file);
				(void) close(file_descriptor);
				result = FALSE;
			}
		}
		popdir(current_working_dir_fd);
	}
	dbgprintf("%s[%d]: leaving create_one_notify_file, result = %s\n",
	    __FILE__, __LINE__, result_strings[result]);
	return (result);
}

static boolean_t
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

	dbgprintf("%s[%d]: entering notify_clients()\n", __FILE__, __LINE__);

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
			dbgprintf("%s[%d]:opendir failed on '.'; %m\n",
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
				dbgprintf("%s[%d]: open failed for %s; %m\n",
				    __FILE__, __LINE__, namebuf);
				continue;
			}
			/*
			 * Check to be sure that the entry is a named pipe.
			 * That closes a small security hole that could
			 * enable unauthorized access to the system root.
			 */
			if ((fstat(fd, &sb) < 0) || (!S_ISFIFO(sb.st_mode))) {
				dbgprintf("%s[%d]: %s isn't a named pipe\n",
				    __FILE__, __LINE__, namebuf);

				(void) close(fd);
				continue;
			}
			notify_character = notify_characters[action];
			if (write(fd, &notify_character, 1) < 0) {
				dbgprintf("%s[%d]: write failed for %s; %m\n",
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
	dbgprintf("%s[%d]: leaving notify_clients(), result = %s\n",
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
		dbgprintf("%s[%d]: popdir() failed\n", __FILE__, __LINE__);
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
		dbgprintf("%s[%d]: push_dir_and_check(): %s does not exist\n",
		    __FILE__, __LINE__, dir);
		return (-1);
	}

	if (!(S_ISDIR(stat_buf.st_mode))) {
		dbgprintf("%s[%d]: push_dir_and_check(): %s not a directory.\n",
		    __FILE__, __LINE__, dir);
		(void) remove(dir);
		return (-1);
	}
	if ((current_working_dir_fd = open(".", O_RDONLY)) < 0) {
		dbgprintf("%s[%d]: push_dir_and_check(): can't open %s.\n",
		    __FILE__, __LINE__, dir);
		return (-1);
	}
	if (chdir(dir) < 0) {
		(void) close(current_working_dir_fd);
		dbgprintf("%s[%d]: push_dir_and_check(): "
		    "can't chdir() to %s.\n", __FILE__, __LINE__, dir);
		return (-1);
	}
	return (current_working_dir_fd);
}

static boolean_t
remove_notify_files(struct action_arg **aa)
{
	int	ai;
	int	current_working_dir_fd;
	char	notify_file[64];
	int	result;
	char	*symdev;

	dbgprintf("%s[%d]: entering remove_notify_files()\n",
	    __FILE__, __LINE__);

	ai = 0;
	result = TRUE;
	symdev = aa[ai]->aa_symdev;
	while ((result == TRUE) &&
	    (aa[ai] != NULL) &&
	    (aa[ai]->aa_path != NULL)) {

		if (not_mountable(aa[ai])) {
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
			dbgprintf("%s[%d]: remove %s/%s; %m\n",
			    __FILE__, __LINE__, NOTIFY_DIR, notify_file);
			result = FALSE;
		}
		if (current_working_dir_fd != -1) {
			popdir(current_working_dir_fd);
		}
		ai++;
	}
	dbgprintf("%s[%d]: leaving remove_notify_files(), result = %s\n",
	    __FILE__, __LINE__, result_strings[result]);

	return (result);
}
