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

#include	<stdio.h>
#include	<stdlib.h>
#include	<fcntl.h>
#include	<dirent.h>
#include	<string.h>
#include	<errno.h>
#include	<rmmount.h>
#include	<locale.h>
#include	<libintl.h>
#include	<sys/vtoc.h>
#include	<sys/dkio.h>
#include	<rpc/types.h>
#include	<sys/param.h>
#include	<sys/stat.h>
#include	<sys/wait.h>
#include	<sys/types.h>
#include	<unistd.h>
#include	<string.h>
#include	<regex.h>
#include	<ctype.h>
#include	"rmm_int.h"

extern int	audio_only(struct action_arg *);
extern char	*rawpath(char *);

#define	FSCK_CMD		"/etc/fsck"
#define	MOUNT_CMD		"/etc/mount"
#define	UMOUNT_CMD		"/etc/umount"
#define	MAX_PARTITIONS		50

#define	IDENT_VERS	1
#define	ACT_VERS	1

#define	AUDIO_CD_STRLEN	8

struct ident_list **	ident_list = NULL;
struct action_list **	action_list = NULL;
char			*prog_name = NULL;
pid_t			prog_pid = 0;

#define	DEFAULT_CONFIG	"/etc/rmmount.conf"
#define	DEFAULT_DSODIR	"/usr/lib/rmmount"

char	*rmm_dsodir = DEFAULT_DSODIR;
char	*rmm_config = DEFAULT_CONFIG;

bool_t	rmm_debug = FALSE;

#define	SHARE_CMD	"/usr/sbin/share"
#define	UNSHARE_CMD	"/usr/sbin/unshare"

/*
 * length of the option string for a mount
 */

#define	RMM_OPTSTRLEN		128


/*
 * Declarations of methods visible to the action() methods
 * in the "action" DSOs.
 */

char	*not_mountable(char *);

/*
 * Names of the slices in a Solaris or HSFS VTOC
 */

static const char *slice_names[] = {
	"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
	"s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15"
};

/*
 * Declarations of private methods.
 */

static struct action_arg **	build_actargs(char *);
static void			clean_fs(struct action_arg *aa,
					struct mount_args *ma);
static void			exec_actions(struct action_arg **,
						bool_t);
static int			exec_mounts(struct action_arg **);
static int			exec_umounts(struct action_arg **);
static void			find_fstypes(struct action_arg **);
static bool_t			hard_mount(struct action_arg *aa,
						struct mount_args *ma,
						bool_t *rdonly);
static bool_t			is_backup_slice(char *raw_path);
static int			read_directory(char *,
						int *,
						struct action_arg **);

static void			share_mount(struct action_arg *,
						struct mount_args *,
						bool_t);
static bool_t			umount_fork(char *);
static void			unshare_mount(struct action_arg *aa,
						struct mount_args *ma);
static void			usage(void);

/*
 * global - required to maintain the definition of the public interface
 * to the "action" DSOs; refers to music CDs played by action_workman.so
 */

int	audio_cd = FALSE;

/*
 * Definition of the main() function.
 */

/*
 * Production (i.e. non-DEBUG) mode is very, very, quiet.  The
 * -D flag will turn on dprintf()s.
 */

int
main(int argc, char **argv)
{
	int			ai;
	int			c;
	int			exval;
	struct action_arg	**aa;
	char 			*reason;
	struct action_arg	*send_aa[2];
	char 			*volume_action;
	char			*volume_mediatype;
	char			*volume_mount_mode;
	char			*volume_name;
	char			*volume_path;
	char			*volume_pcfs_id;
	char			*volume_symdev;

	/*
	 * Make sure core files appear in a volmgt directory.
	 */
	(void) chdir(rmm_dsodir);

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	prog_name = argv[0];
	prog_pid = getpid();

#ifdef VOLD_DEBUG
	fprintf(stderr, "%s(%d) started\n", prog_name, prog_pid);
	fflush(stderr);
	sleep(30);
#endif

	if (geteuid() != 0) {
		(void) fprintf(stderr,
		    gettext("%s(%ld) error: must be root to execute\n"),
		    prog_name, prog_pid);
		return (-1);
	}

	while ((c = getopt(argc, argv, "d:c:D")) != EOF) {
		switch (c) {
		case 'D':
			rmm_debug = TRUE;
			break;
		case 'd':
			rmm_dsodir = (char *)optarg;
			break;
		case 'c':
			rmm_config = (char *)optarg;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	exval = 0;
	volume_action = getenv("VOLUME_ACTION");
	volume_mediatype = getenv("VOLUME_MEDIATYPE");
	volume_mount_mode = getenv("VOLUME_MOUNT_MODE");
	volume_name = getenv("VOLUME_NAME");
	volume_path = getenv("VOLUME_PATH");
	volume_pcfs_id = getenv("VOLUME_PCFS_ID");
	volume_symdev = getenv("VOLUME_SYMDEV");

	if (volume_action == NULL) {
		dprintf("%s(%ld): VOLUME_ACTION was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}
	if (volume_mediatype == NULL) {
		dprintf("%s(%ld): VOLUME_MEDIATYPE was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}
	if (volume_mount_mode == NULL) {
		volume_mount_mode = "rw";
	}
	if (volume_name == NULL) {
		dprintf("%s(%ld): VOLUME_NAME was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}
	if (volume_path == NULL) {
		dprintf("%s(%ld): VOLUME_PATH was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}
	if (volume_pcfs_id == NULL) {
		volume_pcfs_id = "";
	}
	if (volume_symdev == NULL) {
		dprintf("%s(%ld): VOLUME_SYMDEV was null!!\n",
		    prog_name, prog_pid);
		return (-1);
	}

	dprintf("%s[%d]: VOLUME_NAME = %s\n", __FILE__, __LINE__, volume_name);
	dprintf("%s[%d]: VOLUME_PATH = %s\n", __FILE__, __LINE__, volume_path);
	dprintf("%s[%d]: VOLUME_ACTION = %s\n", __FILE__, __LINE__,
		volume_action);
	dprintf("%s[%d]: VOLUME_MEDIATYPE = %s\n", __FILE__, __LINE__,
		volume_mediatype);
	dprintf("%s[%d]: VOLUME_SYMDEV = %s\n", __FILE__, __LINE__,
		volume_symdev);
	dprintf("%s[%d]: VOLUME_MOUNT_MODE = %s\n", __FILE__, __LINE__,
		volume_mount_mode);
	dprintf("%s[%d]: VOLUME_PCFS_ID = %s\n", __FILE__, __LINE__,
		volume_pcfs_id);

	/*
	 * Read in the configuration file to build
	 * the action_list data structure used by
	 * exec_actions() and the ident_list data
	 * structure used by find_fstypes().
	 */
	config_read();

	if ((aa = build_actargs(volume_path)) == NULL) {
		return (0);
	}
	if ((strcmp(volume_action, "insert") == 0) ||
		(strcmp(volume_action, "remount") == 0)) {
		if ((strcmp(volume_mediatype, "cdrom") == 0) &&
			(audio_only(aa[0]) != FALSE)) {

			audio_cd = TRUE;
		}
		reason = not_mountable(volume_name);
		if (reason == NULL) {
			/*
			 * If the value of reason is NULL, the
			 * medium's partitions are mountable.
			 * Otherwise reason points to a string
			 * that explains why the medium's partitions
			 * aren't mountable.
			 */
			find_fstypes(aa);
		} else {
			/*
			 * Set aa_type to the reason a
			 * medium or partition can't be mounted,
			 * e.g. "password_protected" or
			 * "unformatted_media" (sic).
			 */
			ai = 0;
			while ((aa[ai] != NULL) && (aa[ai]->aa_path != NULL)) {
				aa[ai]->aa_type = reason;
				ai++;
			}
		}
	} else {
		/*
		 * Since rmmount is unmounting the file systems,
		 * it doesn't need to know their file system types.
		 * If the medium is read password protected, trying
		 * to read it to determine the file system types of
		 * its partitions will generate SCSI and ident_fs()
		 * errors.
		 */
		if ((strcmp(volume_mediatype, "cdrom") == 0) &&
			(audio_only(aa[0]) != FALSE)) {

			audio_cd = TRUE;
		}
		ai = 0;
		while ((aa[ai] != NULL) && (aa[ai]->aa_path != NULL)) {
			aa[ai]->aa_type = "unknown";
			ai++;
		}
	}
	/*
	 * The following is a hack.  When time permits
	 * the code needs to be changed to use the action_arg
	 * array correctly.  The current code creates a
	 * two-element array called send_aa, with an empty
	 * second element, so the action() method in
	 * action_filemgr.c only handles one element
	 * of the action_arg array at a time.  That's
	 * not necessary now, since the action() method
	 * in action_filemgr.c has been changed to handle
	 * an array of action_arg elements instead of
	 * just one.  When changing this code, change
	 * the exec_actions(), exec_mounts(), and
	 * exec_umounts() methods to handle the
	 * action_args array correctly as well.
	 */
	send_aa[1] = (struct action_arg *)calloc(1,
			sizeof (struct action_arg));

	dprintf("%s[%d]: executing action %s\n",
		__FILE__, __LINE__, volume_action);

	if ((strcmp(volume_action, "insert") == 0) ||
		(strcmp(volume_action, "remount") == 0))  {

		ai = 0;
		while ((aa[ai] != NULL) && (aa[ai]->aa_path != NULL)) {

			dprintf("%s[%d]: aa[%d]->aa_path = %s\n",
				__FILE__, __LINE__, ai, aa[ai]->aa_path);
			dprintf("%s[%d]: aa[%d]->aa_rawpath = %s\n",
				__FILE__, __LINE__, ai, aa[ai]->aa_rawpath);
			dprintf("%s[%d]: aa[%d]->aa_type = %s\n",
				__FILE__, __LINE__, ai, aa[ai]->aa_type);
			dprintf("%s[%d]: aa[%d]->aa_media = %s\n",
				__FILE__, __LINE__, ai, aa[ai]->aa_media);
			dprintf("%s[%d]: aa[%d]->aa_clean = %s\n",
				__FILE__, __LINE__, ai,
				(aa[ai]->aa_clean == TRUE) ? "TRUE" : "FALSE");

			send_aa[0] = aa[ai];

			if (action_list != NULL) {
				/*
				 * Execute the premount actions.
				 */
				exec_actions(send_aa, TRUE);
			}
			/*
			 * If the value of reason is NULL and
			 * the file system type is known, the
			 * medium or partition is mountable.
			 */
			if (reason == NULL) {
				if ((strcmp(aa[ai]->aa_type, "unknown") != 0) &&
					(strcmp(aa[ai]->aa_type, "backup_slice")
						!= 0)) {
					exval = exec_mounts(send_aa);
				} else {
					exval = 0;
				}
			}
			/*
			 * The actions are executed even if the mount fails
			 * so that the removable media manager will indicate
			 * the presence of the media, allowing for it to be
			 * ejected, formatted, etc.
			 */
			if (action_list != NULL) {
				exec_actions(send_aa, FALSE);
			}
			ai++;
		}
	} else if ((strcmp(volume_action, "clear_mounts") == 0) ||
			(strcmp(volume_action, "eject") == 0) ||
			(strcmp(volume_action, "unmount") == 0)) {

		ai = 0;
		while ((aa[ai] != NULL) && (aa[ai]->aa_path != NULL)) {

			dprintf("%s[%d]: aa[%d]->aa_path = %s\n",
				__FILE__, __LINE__, ai, aa[ai]->aa_path);
			dprintf("%s[%d]: aa[%d]->aa_rawpath = %s\n",
				__FILE__, __LINE__, ai, aa[ai]->aa_rawpath);
			dprintf("%s[%d]: aa[%d]->aa_type = %s\n",
				__FILE__, __LINE__, ai, aa[ai]->aa_type);
			dprintf("%s[%d]: aa[%d]->aa_media = %s\n",
				__FILE__, __LINE__, ai, aa[ai]->aa_media);

			send_aa[0] = aa[ai];

			if (action_list != NULL) {
				/*
				 * Execute the preunmount actions.
				 */
				exec_actions(send_aa, TRUE);
			}

			if ((strcmp(volume_name, "unformatted") != 0) &&
			(strcmp(volume_name, "password_protected") != 0)) {
				/*
				 * try to unmount the file system
				 */
				exval = exec_umounts(send_aa);
			} else {
				exval = 0;
			}
			if ((exval == 0) && (action_list != NULL)) {
				/*
				 * If the unmounts were successful
				 * execute the postunmount actions.
				 */
				exec_actions(send_aa, FALSE);
			}
			ai++;
		}
	} else {
		dprintf("%s(%ld): unknown action type %s\n",
			prog_name, prog_pid, volume_action);
		exval = 0;
	}
	return (exval);
}

/*
 * Definitions of methods visible to the action() methods
 * in the "action" DSOs.
 */

char *
not_mountable(char *vol_name)
{

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
	 *
	 * If the value of the global variable audio_cd is TRUE, the
	 * medium isn't mountable.
	 */

	char *reason;

	reason = (char *)calloc(1, 64);

	if (strcmp(vol_name, "unknown_format") == 0) {
		sprintf(reason, "%s", "unformatted_media");
		return (reason);
	}

	if (strcmp(vol_name, "password_protected") == 0) {
		sprintf(reason, "%s", vol_name);
		return (reason);
	}

	if ((strncmp(vol_name, "audio_cd", AUDIO_CD_STRLEN) == 0) &&
		(audio_cd == TRUE)) {
		sprintf(reason, "%s", "audio_only");
		return (reason);
	}
	/*
	 * When later versions of the software can mount
	 * file systems located on CDs that also contain
	 * audio data, the conditional operation below
	 * will have to change.
	 */
	if (audio_cd == TRUE) {
		sprintf(reason, "%s", "audio_only");
		return (reason);
	}
	if (strcmp(vol_name, "dvd_vedio") == 0) {
		/*
		 * The medium contains DVD video data.
		 * It has been mounted, but shouldn't
		 * be accessed by the filemgr application.
		 *
		 * "vedio" is misspelled, but needs to be left
		 * that way until we can correct it everywhere
		 * it's used.
		 */
		sprintf(reason, "%s", "dvd_video");
		return (reason);
	}
	free(reason);
	return (NULL);
}

/*
 * Definitions of private methods
 */

static struct action_arg **
build_actargs(char *path)
{
	struct action_arg	**aa_tab;
	int			aaidx;
	int			result;
	char			*volume_namep;


	/*
	 * lets get a hunk... we can have 40 special files
	 * so lets make sure we enough. 40 is an assumption
	 * that with fdisk it is possible to have c-z, and
	 * also have a vtoc with 16. So I'm alloc'ing 50
	 */

	aa_tab = (struct action_arg **)
		calloc(MAX_PARTITIONS, sizeof (struct action_arg *));
	/*
	 * need to allocate at least one... this will cover
	 * if there are no special files to mount. The
	 * find_fstypes stops when it finds aa_path NULL
	 */
	aaidx = 0;
	aa_tab[aaidx] = (struct action_arg *)
		calloc(1, sizeof (struct action_arg));
	if (aa_tab[aaidx] != NULL) {
		volume_namep = getenv("VOLUME_NAME");
		if (strcmp(volume_namep, "password_protected") == 0) {
			aa_tab[aaidx]->aa_path = strdup(path);
			aa_tab[aaidx]->aa_rawpath = strdup(rawpath(path));
			aa_tab[aaidx]->aa_type = NULL;
			aa_tab[aaidx]->aa_media =
				strdup(getenv("VOLUME_MEDIATYPE"));
			aa_tab[aaidx]->aa_partname = NULL;
			aa_tab[aaidx]->aa_mountpoint = NULL;
			aa_tab[aaidx]->aa_clean = TRUE;
			aa_tab[aaidx]->aa_mnt = FALSE;
			/*
			 * allocate another action_arg structure with
			 * aa_path == NULL to signal the end of the
			 * action_arg array.
			 */
			aaidx++;
			aa_tab[aaidx] = (struct action_arg *)
				calloc(1, sizeof (struct action_arg));
			if (aa_tab[aaidx] != NULL) {
				result = 1;
			} else {
				result = 0;
			}
		} else {
			result = read_directory(path, &aaidx, aa_tab);
		}
	} else {
		result = 0;
	}
	if (result != 0) {
		return (aa_tab);
	} else {
		return (NULL);
	}
}

static void
clean_fs(struct action_arg *aa, struct mount_args *ma)
{
	pid_t  		pid;
	int		rval;
	struct stat	sb;


	if (stat(aa->aa_path, &sb)) {
		dprintf("%s(%ld): %s; %m\n",
		    prog_name, prog_pid, aa->aa_path);
		return;
	}

	/*
	 * Here, we assume that the owners permissions are the
	 * most permissive.  If no "write" permission on
	 * device, it should be mounted readonly.
	 */
	if ((sb.st_mode & S_IWUSR) == 0) {
		dprintf("%s(%ld): %s is dirty but read-only (no fsck)\n",
		    prog_name, prog_pid, aa->aa_path);
		return;
	}

	if (aa->aa_clean == FALSE) {
		(void) fprintf(stderr, gettext("%s(%ld) warning: %s is dirty, "
						"cleaning (please wait)\n"),
				prog_name, prog_pid, aa->aa_path);
	} else {
		(void) fprintf(stderr, gettext("%s(%ld) note: fsck of %s "
						"requested (please wait)\n"),
				prog_name, prog_pid, aa->aa_path);
	}

	if ((pid = fork()) == 0) {
		int	fd;

		/* get rid of those nasty err messages */
		if ((fd = open("/dev/null", O_RDWR)) >= 0) {
			(void) dup2(fd, 0);
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			if (fd > 2)
				(void) close(fd);
		}
		if (ma && ma->ma_options[0] != NULLC) {
			(void) execl(FSCK_CMD, FSCK_CMD, "-F", aa->aa_type,
			    "-o", ma->ma_options, aa->aa_path, NULL);
		} else {
			(void) execl(FSCK_CMD, FSCK_CMD, "-F", aa->aa_type,
			    "-o", "p", aa->aa_path, NULL);
		}
		(void) fprintf(stderr,
		    gettext("%s(%ld) error: exec of %s failed; %s\n"),
		    prog_name, prog_pid, FSCK_CMD, strerror(errno));
		_exit(-1);
	}

	/* wait for the fsck command to exit */
	if (waitpid(pid, &rval, 0) < 0) {
		(void) fprintf(stderr,
		    gettext("%s(%ld) warning: can't wait for pid %d (%s)\n"),
		    prog_name, prog_pid, pid, FSCK_CMD);
		return;
	}

	if (WEXITSTATUS(rval) != 0) {
		(void) fprintf(stderr, gettext(
		    "%s(%ld) warning: fsck of \"%s\" failed, returning %d\n"),
		    prog_name, prog_pid, aa->aa_path, WEXITSTATUS(rval));
	} else {
		aa->aa_clean = TRUE;
	}
}


static void
exec_actions(struct action_arg **aa, bool_t premount)
{
	bool_t		(*act_func)(struct action_arg **, int, char **);
	int		i;
	int		retval;

	i = 0;
	while (action_list[i] != NULL) {
		if ((strcmp(aa[0]->aa_media, action_list[i]->a_media) == 0) &&
			(premount == (action_list[i]->a_flag & A_PREMOUNT))) {
			/*
			 * If the medium type of the partition matches
			 * the medium type of the action in action_list,
			 * and the premount flag matches the premount
			 * flag in the action, load the "action" shared
			 * object and execute its action() method.
			 */
			if ((act_func = action_list[i]->a_action) == NULL) {
				act_func = (bool_t (*)(struct action_arg **,
				    int, char **))
				    dso_load(action_list[i]->a_dsoname,
				    "action", ACT_VERS);
				action_list[i]->a_action = act_func;
			}
			if (act_func != NULL) {
				dprintf("%s[%d]: executing action() in %s\n",
					__FILE__, __LINE__,
					action_list[i]->a_dsoname);
				retval = (*act_func)(aa,
					action_list[i]->a_argc,
					action_list[i]->a_argv);
				dprintf("%s[%d]: action() returns %d\n",
					__FILE__, __LINE__, retval);
				/*
				 * If action returns 0, no further actions
				 * will be executed. (see rmmount.conf(4))
				 */
				if (retval == 0)
					break;
			}
		}
		i++;
	}
}

static int
exec_mounts(struct action_arg **aa)
{
	/*
	 * Return 0 if all goes well.
	 * Otherwise return the number of problems.
	 */
	int			ai;
	int			mnt_ai = -1;
	char			symname[2 * MAXNAMELEN];
	char			symcontents[MAXNAMELEN];
#ifdef	OLD_SLICE_HANDLING_CODE
	char			*mountname;
	char			*s;
#endif
	char			*symdev = getenv("VOLUME_SYMDEV");
	char			*name = getenv("VOLUME_NAME");
	struct mount_args	*ma[3] = {NULL, NULL, NULL};
				/*
				 * The "mount arguments" are stored in an array
				 * indexed by the actual command they are
				 * applied to: "fsck", "mount", and "share"
				 */
	int			i, j;
	int			ret_val = 0;
	char			*mntpt;
	bool_t			rdonly;
	char			*volume_mount_mode;

	volume_mount_mode = getenv("VOLUME_MOUNT_MODE");
	if ((volume_mount_mode != NULL) &&
		(strcmp(volume_mount_mode, "rw") != 0)) {
		dprintf("%s(%d): mount mode '%s', mounting read only\n",
			__FILE__, __LINE__, volume_mount_mode);
		rdonly = TRUE;
	} else {
		rdonly = FALSE;
	}

	for (ai = 0; aa[ai]->aa_path; ai++) {

		/*
		 * If a premount action indicated that the partition
		 * isn't to be mounted, don't mount it.
		 */
		if (aa[ai]->aa_mnt == FALSE) {
			dprintf("%s(%ld): not supposed to mount %s\n",
			    prog_name, prog_pid, aa[ai]->aa_path);
			continue;
		}

		/* if audio don't mount it */

		if (audio_cd) {
			dprintf("%s(%d): don't mount audio\n",
					__FILE__, __LINE__);
			/*
			 * for now rather than 'continue'
			 * we will use 'break' because
			 * the ident_hsfs is broken
			 *
			 * When it is fixed, change back to
			 * 'continue'
			 */
			break;
		}
		dprintf("%s(%ld): %s is type %s\n", prog_name, prog_pid,
		    aa[ai]->aa_path, aa[ai]->aa_type?aa[ai]->aa_type:"data");

		if (aa[ai]->aa_type != NULL) {	/* assuming we have a type */

			/* no need to try to clean/mount if already mounted */
			if (mntpt = getmntpoint(aa[ai]->aa_path)) {
				/* already mounted on! */

				dprintf("DEBUG: "
					"%s already mounted on (%s dirty)\n",
					aa[ai]->aa_path,
					aa[ai]->aa_clean ? "NOT" : "IS");

				free(mntpt);
				ret_val++;
				continue;
			}

			dprintf("DEBUG: %s NOT already mounted\n",
				aa[ai]->aa_path);

			/*
			 * find the right mount arguments for this device
			 */
			for (j = 0; j < 3; j++) {
			    if (cmd_args[j] != NULL) {
				for (i = 0; cmd_args[j][i] != NULL; i++) {

					/* try to match name against RE */

					dprintf("exec_mounts (%d,%d): "
						"regexec(\"%s\", \"%s\") ...\n",
						j, i, cmd_args[j][i]->ma_namere,
						name);

					if (regexec(&(cmd_args[j][i]->ma_re),
						    name, 0L, NULL, 0) == 0 &&
					    fs_supported(aa[ai]->aa_type,
							cmd_args[j][i])) {
						ma[j] = cmd_args[j][i];

						dprintf("exec_mounts: "
						    "found a NAME match!\n");

						break;
					}

					/* try to match symname against RE */

					dprintf("exec_mounts (%d,%d): "
						"regexec(\"%s\", \"%s\") ...\n",
						j, i, cmd_args[j][i]->ma_namere,
						symdev);

					if (regexec(&(cmd_args[j][i]->ma_re),
						    symdev, 0L, NULL, 0) == 0 &&
					    fs_supported(aa[ai]->aa_type,
							cmd_args[j][i])) {
						ma[j] = cmd_args[j][i];

						dprintf("exec_mounts: "
						    "found a SYMNAME match!\n");

						break;
					}
				}
			    }
			}


			if (ma[CMD_MOUNT] == NULL) {
				dprintf("exec_mounts: no mount args!\n");
			}


			/*
			 * If the file system is not read-only and not
			 * clean, or if it's not read-only and there's
			 * an explicit fsck option for this file system,
			 * run fsck.
			 */
			if ((rdonly == FALSE) &&
				(strcmp(aa[ai]->aa_media, "cdrom") != 0) &&
				(aa[ai]->aa_clean == FALSE ||
				ma[CMD_FSCK] != NULL)) {

				clean_fs(aa[ai], ma[CMD_FSCK]);
			}

			if (hard_mount(aa[ai], ma[CMD_MOUNT], &rdonly)
				== FALSE) {
				ret_val++;
			}

			/* remember if we mount one of these guys */
			if (mnt_ai == -1) {
				if (aa[ai]->aa_mountpoint)
					mnt_ai = ai;
			}

			if (ma[CMD_SHARE] != NULL) {
				/*
				 * export the file system.
				 */
				share_mount(aa[ai], ma[CMD_SHARE], rdonly);
			}
		}
	}

	if (mnt_ai != -1) {
#ifdef OLD_SLICE_HANDLING_CODE
		/*
		 * XXX: did we used to do something here having to do with
		 * the slices mounted for a volume??? (lduncan)
		 */
		(void) sprintf(symname, "/%s/%s", aa[mnt_ai]->aa_media,
		    symdev);
		if (aa[0]->aa_partname) {
			mountname = strdup(aa[mnt_ai]->aa_mountpoint);
			if ((s = strrchr(mountname, '/')) != NULL) {
				*s = NULLC;
			}
			(void) unlink(symname);
			(void) symlink(mountname, symname);
		} else {
			(void) unlink(symname);
			(void) symlink(aa[mnt_ai]->aa_mountpoint, symname);
		}
#else	/* !OLD_SLICE_HANDLING_CODE */
		(void) snprintf(symcontents, sizeof (symcontents),
			"./%s", name);
		(void) snprintf(symname, sizeof (symname),
			"/%s/%s", aa[mnt_ai]->aa_media, symdev);
		(void) unlink(symname);
		(void) symlink(symcontents, symname);
#endif	/* !OLD_SLICE_HANDLING_CODE */
	}

	return (ret_val);
}

static int
exec_umounts(struct action_arg **aa)
{
	/*
	 * Unmount all umountable file systems described in as
	 * and return failure if any filesystem described in aa
	 * can't be unmounted.
	 */

	int			ai;
	char			*dos_partition_letterp;
	int			i;
	bool_t			success;
	char			mnt_path[MAXPATHLEN];
	char			*mountpoint;
	char			*oldmountpoint; /* saved previous mount point */
	char			*symdev;
	char			*s;
	struct mount_args	*ma = NULL;
	char			*volume_name;

	dprintf("%s[%d]: entering exec_umounts()\n", __FILE__, __LINE__);

	ma = NULL;
	oldmountpoint = NULL;
	success = TRUE;
	symdev = getenv("VOLUME_SYMDEV");
	volume_name = getenv("VOLUME_NAME");

	for (ai = 0; aa[ai]->aa_path; ai++) {
		/*
		 * If it's not in the mount table, assume it's
		 * not mounted.
		 */
		if (strlcpy(mnt_path, aa[ai]->aa_path, sizeof (mnt_path))
		    >= sizeof (mnt_path)) {
			continue;
		}

		dprintf("%s[%d]: mount path = %s\n",
			__FILE__, __LINE__, mnt_path);

		if ((mountpoint = getmntpoint(mnt_path)) == NULL) {
			continue;
		}
		/*
		 * find the right mount arguments for this device
		 */
		if (cmd_args[CMD_SHARE] != NULL) {
			for (i = 0; cmd_args[CMD_SHARE][i] != NULL; i++) {

				/* try to match volume_name against RE */

				dprintf("exec_mounts: "
				    "regexec(\"%s\", \"%s\") ...\n",
				    cmd_args[CMD_SHARE][i]->ma_namere,
					volume_name);

				if (regexec(&(cmd_args[CMD_SHARE][i]->ma_re),
					    volume_name, 0L, NULL, 0) == 0) {
					ma = cmd_args[CMD_SHARE][i];

					dprintf("exec_umounts: "
						"found a NAME match!\n");

					break;
				}

				/* try to match symname against RE */

				dprintf("exec_mounts: "
				    "regexec(\"%s\", \"%s\") ...\n",
				    cmd_args[CMD_SHARE][i]->ma_namere, symdev);

				if (regexec(&(cmd_args[CMD_SHARE][i]->ma_re),
					    symdev, 0L, NULL, 0) == 0) {
					ma = cmd_args[CMD_SHARE][i];

					dprintf("exec_umounts: "
						"found a SYMNAME match!\n");

					break;
				}
			}
		}

		/* unshare the mount before umounting */
		if (ma != NULL) {
			unshare_mount(aa[ai], ma);
		}

		/*
		 * do the actual umount
		 */
		if (umount_fork(mountpoint) == FALSE) {
			success = FALSE;
		}

		/* remove the mountpoint, if it's a partition */
		if (aa[ai]->aa_partname) {
			(void) rmdir(mountpoint);
		}

		/* save a good mountpoint */
		if (oldmountpoint == NULL) {
			oldmountpoint = strdup(mountpoint);
		}
		free(mountpoint);
		mountpoint = NULL;
	}

	/*
	 * clean up our directories and such if all went well
	 */
	if (success) {
		char		rmm_mountpoint[MAXPATHLEN];

		/*
		 * if we have partitions, we'll need to remove the last
		 * component of the path
		 */
		if (aa[0]->aa_partname != NULL) {
			if ((oldmountpoint != NULL) &&
			    ((s = strrchr(oldmountpoint, '/')) != NULL)) {
				*s = NULLC;
			}
		}

		/*
		 * we only want to remove the directory (and symlink)
		 * if we're dealing with the directory we probably created
		 * when we were called to mount the media
		 * i.e. if the direcoty is "/floppy/NAME", then remove it
		 * but if it's /SOME/GENERAL/PATH then don't remove it *or*
		 * try to remove the symlink
		 */

		if (snprintf(rmm_mountpoint, sizeof (rmm_mountpoint),
			"/%s/%s", aa[0]->aa_media, volume_name)
				>= sizeof (rmm_mountpoint))
			success = FALSE;

		if (success && (oldmountpoint != NULL) &&
		    (strcmp(oldmountpoint, rmm_mountpoint) == 0)) {
			char    symname[MAXNAMELEN];

			/* remove volmgt mount point */
			(void) rmdir(oldmountpoint);

			/* remove symlink (what harm if it does not exist?) */
			if (snprintf(symname, sizeof (symname), "/%s/%s",
				aa[0]->aa_media, symdev) >= sizeof (symname)) {
				success = FALSE;
			}
			if (success)
				(void) unlink(symname);
		}
	}

	if (oldmountpoint != NULL) {
		free(oldmountpoint);
	}

	return (success ? 0 : 1);
}

static void
find_fstypes(struct action_arg **aa)
{
	int		ai;
	int		fd;
	int		i, j;
	int		foundfs, foundmedium, ishsfs;
	int		clean, hsfs_clean;
	int		first_partition = 0;
	int		is_pcfs;
	char		*mtype  = getenv("VOLUME_MEDIATYPE");
	char		*fstype = getenv("VOLUME_FSTYPE");

	dprintf("%s[%d]: entering find_fstypes()\n", __FILE__, __LINE__);

	if (ident_list == NULL) {
		dprintf("%s[%d]: find_fstypes(): no ident list\n",
			__FILE__, __LINE__);
		return;
	}

	/*
	 * If it's a cdrom and it only has audio on it,
	 * the cd may have a file system also, so set
	 * global flag (ugh)
	 */
	if (strcmp(mtype, "cdrom") == 0) {
		if (audio_only(aa[0]) == TRUE) {
			audio_cd = TRUE;
			dprintf("%s[%d]: find_fstypes(): audio CD\n",
				__FILE__, __LINE__);
			return;
		}
	}

	is_pcfs = (fstype != NULL && strcmp(fstype, "PCFS") == 0);
	/*
	 * We leave the file descriptor open on purpose so that
	 * the blocks that we've read in don't get invalidated
	 * on close, thus wasting i/o.  The mount (or attempted mount)
	 * command later on will have access to the blocks we have
	 * read as part of identification through the buffer cache.
	 * The only *real* difficulty here is that reading from the
	 * block device means that we always read 8k, even if we
	 * really don't need to.
	 */
	for (ai = first_partition; aa[ai]->aa_path; ai++) {
		/*
		 * if we're not supposed to mount it, just move along.
		 */
		if (aa[ai]->aa_mnt == FALSE) {
			if (aa[ai]->aa_type == NULL) {
				/*
				 * It could be a backup slice.
				 * If so, read_directory() has
				 * has already written "backup_slice"
				 * to aa[ai]->aa_type.
				 */
				aa[ai]->aa_type = "unknown";
			}
			continue;
		}

		/*
		 * If the filesystem was known to be PCFS, then
		 * we don't nead to set aa_partname or anything.
		 * Those have been set by read_directory().
		 */
		if (is_pcfs) {
			aa[ai]->aa_type = "pcfs";
			aa[ai]->aa_clean = TRUE;
			dprintf("%s[%d]: find_fstypes(): fdisk partition: %s\n",
				__FILE__, __LINE__, aa[ai]->aa_path);
			continue;
		}

		dprintf("%s[%d]: find_fstypes(): "
		    "checking the file system type of %s\n",
		    __FILE__, __LINE__, aa[ai]->aa_path);

		if ((fd = open(aa[ai]->aa_path, O_RDONLY)) < 0) {
			dprintf("%s[%d]: find_fstypes(): %s; %m\n",
				__FILE__, __LINE__, aa[ai]->aa_path);
			aa[ai]->aa_type = "unknown";
			continue;
		}

		foundfs = FALSE;
		ishsfs = FALSE;

		for (i = 0; ident_list[i]; i++) {
			/*
			 * Check for each file system type in the
			 * list of file system types that the medium
			 * can contain.  If the ident_fs() function
			 * for a file system type returns TRUE, set
			 * aa[ai]->aa_type to the name of that file
			 * system type break out of the for loop.
			 */
			foundmedium = FALSE;

			for (j = 0; ident_list[i]->i_media[j]; j++) {
				if (strcmp(aa[ai]->aa_media,
				    ident_list[i]->i_media[j]) == 0) {
					foundmedium = TRUE;
		dprintf("%s[%d]: find_fstypes():found medium type: %s\n",
			__FILE__, __LINE__, aa[ai]->aa_media);
					break;
				}
			}
			if ((foundmedium == TRUE) &&
				(ident_list[i]->i_ident == NULL)) {
				/*
				 * Get the id function and call it.
				 */
				ident_list[i]->i_ident =
				    (bool_t (*)(int, char *, int *, int))
				    dso_load(ident_list[i]->i_dsoname,
				    "ident_fs", IDENT_VERS);
			}
			if (ident_list[i]->i_ident != NULL) {
		dprintf("%s[%d]: find_fstypes() calling ident_fs() in %s\n",
			__FILE__, __LINE__, ident_list[i]->i_dsoname);
				foundfs = (*ident_list[i]->i_ident)(fd,
						aa[ai]->aa_rawpath,
						&clean, 0);
			}
			if (foundfs == TRUE) {
				/*
				 * If we have identified this as a hsfs
				 * there could be a chance that this
				 * actualy is a udfs.  We flag if hsfs
				 * then continue testing.
				 */
				if (strcmp(ident_list[i]->i_type,
				    "hsfs") == 0) {
					ishsfs = TRUE;
					hsfs_clean = clean;
					continue;
				}
				break;
			}
		}
		if (foundfs) {
			aa[ai]->aa_type = ident_list[i]->i_type;
			aa[ai]->aa_clean = clean;
		} else if (ishsfs) {
			aa[ai]->aa_type = "hsfs";
			aa[ai]->aa_clean = hsfs_clean;
		} else {
			aa[ai]->aa_type = "unknown";
		}
		dprintf("%s[%d]: find_fstypes() %s: fstype = %s; clean = %s\n",
			__FILE__, __LINE__,
			aa[ai]->aa_path, aa[ai]->aa_type,
			(aa[ai]->aa_clean == TRUE) ? "TRUE" : "FALSE");
	}
}

static bool_t
hard_mount(struct action_arg *aa, struct mount_args *ma, bool_t *rdonly)
{
	/*
	 * Mount a filesystem.
	 */
	char		*targ_dir;
	char		options[RMM_OPTSTRLEN];	/* mount option string */
	char		*mountpoint = NULL;
	int		mountpoint_bufcount = 0;
	struct stat 	sb;
	mode_t		mpmode;
	bool_t		ret_val;
	char		*pcfs_part_id = getenv("VOLUME_PCFS_ID");
	char		*volume_mount_mode;
	char		dev_path[MAXPATHLEN];
	char		*av[12];
	pid_t   	pid;
	int		status, cnt;

	if (*rdonly == TRUE) {
		volume_mount_mode = "ro";
	} else {
		volume_mount_mode = "rw";
	}
	dprintf("%s(%d): entering hard_mount(): volume_mount_mode = %s\n",
		__FILE__, __LINE__, volume_mount_mode);

	if (stat(aa->aa_path, &sb)) {
		dprintf("%s(%ld): %s; %m\n", prog_name, prog_pid, aa->aa_path);
		return (FALSE);
	}
	/*
	 * Here, we assume that the owners permissions are the
	 * most permissive and that if he can't "write" to the
	 * device it should be mounted readonly.
	 */
	if (sb.st_mode & S_IWUSR) {
		/*
		 * If he wants it mounted readonly, give it to him.  The
		 * default is that if the device can be written, we mount
		 * it read/write.
		 */
		if (ma != NULL && (ma->ma_key & MA_READONLY)) {
			/* user has requested RO for this fs type */
			*rdonly = TRUE;
			volume_mount_mode = "ro";
		dprintf("%s(%d): hard_mount(), MA_READONLY: mount_mode = %s\n",
				__FILE__, __LINE__, volume_mount_mode);
		}
	} else {
		*rdonly = TRUE;
		volume_mount_mode = "ro";
		dprintf("%s(%d): hard_mount(), not owner: mount_mode = %s\n",
			__FILE__, __LINE__, volume_mount_mode);
	}

	/*
	 * "hsfs" file systems must be mounted readonly
	 */

	if (strcmp(aa->aa_type, "hsfs") == 0) {
		*rdonly = TRUE;
		volume_mount_mode = "ro";
	}
	dprintf("%s(%d): hard_mount(), fstype checked: mount_mode = %s\n",
		__FILE__, __LINE__, volume_mount_mode);

	/*
	 * If the file system isn't clean, we attempt a ro mount.
	 * We already tried the fsck.
	 */

	if (aa->aa_clean == FALSE) {
		*rdonly = TRUE;
		volume_mount_mode = "ro";
	}
	dprintf("%s(%d): hard_mount(), clean bit checked: mount_mode = %s\n",
		__FILE__, __LINE__, volume_mount_mode);

	targ_dir = getenv("VOLUME_NAME");

	if (targ_dir == NULL) {
		(void) fprintf(stderr,
		    gettext("%s(%ld) error: VOLUME_NAME not set for %s\n"),
		    prog_name, prog_pid, aa->aa_path);
		return (FALSE);
	}

	if (aa->aa_partname) {
		mountpoint_bufcount = strlen(aa->aa_media) +
			strlen(targ_dir) + strlen(aa->aa_partname) + 3 + 1;
		/* 1 - for NULL terminator, 3 - for "/"s */
		mountpoint = malloc(mountpoint_bufcount);
		if (mountpoint == NULL) {
			(void) fprintf(stderr,
				gettext("%s(%ld) error: malloc failed\n"),
				prog_name, prog_pid);
			return (FALSE);
		}
		(void) sprintf(mountpoint, "/%s/%s/%s", aa->aa_media,
		    targ_dir, aa->aa_partname);
	} else {
		mountpoint_bufcount = strlen(aa->aa_media) +
			strlen(targ_dir) + 2 + 1;
		/* 1 - for NULL terminator, 2 - for "/"s */
		mountpoint = malloc(mountpoint_bufcount);
		if (mountpoint == NULL) {
			(void) fprintf(stderr,
				gettext("%s(%ld) error: malloc failed\n"),
				prog_name, prog_pid);
			return (FALSE);
		}
		(void) sprintf(mountpoint, "/%s/%s", aa->aa_media, targ_dir);
	}

	/* make our mountpoint */
	(void) makepath(mountpoint, 0755);

	if (ma == NULL || ma->ma_options == NULL) {
		options[0] = NULLC;
	} else {
		(void) strlcpy(options, ma->ma_options, sizeof (options));
	}

	/* add in readonly option if necessary */
	if (*rdonly) {
		if (options[0] == NULLC)
			(void) strlcat(options, "ro", sizeof (options));
		else
			(void) strlcat(options, ",ro", sizeof (options));
	}


	if (strlcpy(dev_path, aa->aa_path, sizeof (dev_path))
		>= sizeof (dev_path)) {
		return (FALSE);
	}

	if (strcmp(aa->aa_type, "pcfs") == 0) {
		if ((pcfs_part_id != NULL) &&
			(isalpha(pcfs_part_id[0]))) {
			/* have pcfs with fdisk, append aa_partname */
			if (strlcat(dev_path, ":", sizeof (dev_path))
				>= sizeof (dev_path)) {
				return (FALSE);
			}
			if (aa->aa_partname == NULL) {
				/*
				 * PCFS with a single partition.
				 * Use the partition letter provided by
				 * vold.
				 */
				if (strlcat(dev_path, pcfs_part_id,
					sizeof (dev_path))
					>= sizeof (dev_path)) {
					return (FALSE);
				}
			} else {
				/*
				 * multiple pcfs partitions, use
				 * 'letters' hung by vold
				 */
				if (strlcat(dev_path, aa->aa_partname,
					sizeof (dev_path))
					>= sizeof (dev_path)) {
					return (FALSE);
				}
			}
			dprintf("the device path  being mounted is: '%s'\n",
					dev_path);
		}
	}


	switch (pid = fork1()) {
	case 0:
		cnt = 0;
		av[cnt++] = MOUNT_CMD;
		av[cnt++] = "-F";
		av[cnt++] = aa->aa_type;
		if (options[0] != NULLC) {
			av[cnt++] = "-o";
			av[cnt++] = options;
		}
		av[cnt++] = dev_path;
		av[cnt++] = mountpoint;
		av[cnt] = NULL;

		(void) execv(MOUNT_CMD, av);
		(void) fprintf(stderr,
			gettext("%s(%ld) error: exec of %s failed; %s\n"),
			prog_name, prog_pid, MOUNT_CMD, strerror(errno));
		_exit(-1);
	case -1:
		dprintf("fork1 failed \n ");
		return (FALSE);
	default :
		if (waitpid(pid, &status, 0) < 0) {
			dprintf("%s(%ld): waitpid() failed (errno %d) \n",
				prog_name, prog_pid, errno);
			return (FALSE);
		}
	}

	if (status == 0) {
		if (options[0] == NULLC) {
			dprintf("%s(%ld): \"%s\" mounted\n",
			    prog_name, prog_pid, mountpoint);
		} else {
			dprintf("%s(%ld): \"%s\" mounted (%s)\n",
			    prog_name, prog_pid, mountpoint, options);
		}
		aa->aa_mnt = TRUE;
		aa->aa_mountpoint = strdup(mountpoint);
		dprintf(
		"\nDEBUG: Setting u.g of \"%s\" to %d.%d (me=%d.%d)\n\n",
		    mountpoint, sb.st_uid, sb.st_gid, getuid(), getgid());
		/*
		 * set owner and modes.
		 */
		(void) chown(mountpoint, sb.st_uid, sb.st_gid);

		mpmode = (sb.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO));
		/* read implies execute */
		if (mpmode & S_IRUSR) {
			mpmode |= S_IXUSR;
		}
		if (mpmode & S_IRGRP) {
			mpmode |= S_IXGRP;
		}
		if (mpmode & S_IROTH) {
			mpmode |= S_IXOTH;
		}
		dprintf("DEBUG: Setting mode of \"%s\" to %05o\n\n",
		    mountpoint, mpmode);
		(void) chmod(mountpoint, mpmode);

		ret_val = TRUE;

	} else {
		/* if there was an error, print out the mount message */
		dprintf("%s(%ld) mount error: %s -F %s %s\n",
			prog_name, prog_pid, MOUNT_CMD, aa->aa_type, options);
		aa->aa_mnt = FALSE;
		(void) rmdir(mountpoint);			/* cleanup */
		ret_val = FALSE;
	}
	if (mountpoint != NULL)
		free(mountpoint);

	return (ret_val);
}

static bool_t
is_backup_slice(char *raw_path)
{
	int		file_descriptor;
	bool_t		result;
	char		*slice_namep;
	int		slice_number;
	struct vtoc	vtoc;

	file_descriptor = -1;
	result = FALSE;
	slice_namep = strrchr(raw_path, '/') + 1;
	slice_number = 0;
	while ((slice_number < V_NUMPAR) &&
		(strcmp(slice_namep, slice_names[slice_number]) != 0)) {
		slice_number++;
	}
	if (slice_number < V_NUMPAR) {
		file_descriptor = open(raw_path, O_RDONLY);
		if (file_descriptor >= 0) {
			if ((ioctl(file_descriptor, DKIOCGVTOC, &vtoc) >= 0) &&
				(vtoc.v_sanity == VTOC_SANE) &&
				(vtoc.v_part[slice_number].p_tag == V_BACKUP)) {
					result = TRUE;
			}
			(void) close(file_descriptor);
		}
	}
	return (result);
}

static int
read_directory(char *dirname,
		int *aaidx,
		struct action_arg **aa_tab)
{
	DIR		*dirp;
	dirent_t	*dp;
	char		*filename;
	char		*medium_type;
	char		*pathname;
	int		result;
	struct stat	sb;

	result = 1;

	dprintf("%s[%d]: entering read_directory()\n", __FILE__, __LINE__);
	dprintf("%s[%d]: dirname = %s\n", __FILE__, __LINE__, dirname);

	dirp = NULL;
	dp = NULL;
	medium_type = getenv("VOLUME_MEDIATYPE");
	result = 1;

	pathname = (char *)calloc(1, MAXPATHLEN);
	if (pathname == NULL) {
		dprintf("%s[%d]: couldn't calloc pathname\n",
			__FILE__, __LINE__);
		result = 0;
	}

	if ((result == 1) && ((*aaidx) >= MAX_PARTITIONS)) {
		dprintf("%s[%d]: read_directory() too many partitions\n",
			__FILE__, __LINE__);
		result = 0;
	}

	if ((result == 1) && (stat(dirname, &sb) < 0)) {
		dprintf("%s(%d): fstat %s; %m\n", __FILE__, __LINE__, dirname);
		result = 0;
	}
	if ((result == 1) && ((sb.st_mode & S_IFMT) == S_IFBLK)) {
		/*
		 * The path passed in as dirname is a
		 * a block special file.  Load its
		 * attributes into the action_arg.
		 */
		dprintf("%s[%d]: %s is a block special file\n",
			__FILE__, __LINE__, dirname);
		aa_tab[*aaidx]->aa_path = strdup(dirname);
		aa_tab[*aaidx]->aa_media = strdup(medium_type);
		aa_tab[*aaidx]->aa_rawpath =
				strdup(rawpath(dirname));
		aa_tab[*aaidx]->aa_mnt = TRUE;

		(*aaidx)++;
		/*
		 * Allocate another action_arg
		 * to end the aa_tab array with
		 * an action_arg with aa_path == NULL;
		 */
		aa_tab[*aaidx] = (struct action_arg *)
			calloc(1, sizeof (struct action_arg));
		if (aa_tab[*aaidx] == NULL) {
			dprintf("%s[%d]: couldn't calloc an action arg\n",
				__FILE__, __LINE__);
			result = 0;
		}
	} else if ((result == 1) && ((sb.st_mode & S_IFMT) == S_IFDIR)) {
		dirp = opendir(dirname);
		if (dirp == NULL) {
			dprintf("%s[%d]: couldn't open %s as a directory\n",
				__FILE__, __LINE__, dirname);
			result = 0;
		}
	}
	if ((result == 1) && (dirp != NULL)) {
		while ((dp = readdir(dirp)) != NULL) {
			filename = dp->d_name;
			if ((strcmp(filename, ".") == 0) ||
				(strcmp(filename, "..")	== 0))
				continue;

			if (snprintf(pathname, MAXPATHLEN, "%s/%s",
				dirname, filename) >= MAXPATHLEN)
				continue;

			if (stat(pathname, &sb) < 0) {
				dprintf("%s[%]: %s does not exist\n",
					__FILE__, __LINE__, pathname);
				free(pathname);
				exit(1);
			}
			if ((sb.st_mode & S_IFMT) == S_IFDIR) {
				result = read_directory(pathname,
						aaidx,
						aa_tab);
			} else if ((sb.st_mode & S_IFMT) == S_IFBLK) {
				aa_tab[*aaidx]->aa_path =
					strdup(pathname);
				aa_tab[*aaidx]->aa_media =
					strdup(medium_type);
				aa_tab[*aaidx]->aa_partname =
					strdup(filename);
				aa_tab[*aaidx]->aa_rawpath =
					strdup(rawpath(pathname));
				if (is_backup_slice(
					aa_tab[*aaidx]->aa_rawpath) !=
					TRUE) {
					aa_tab[*aaidx]->aa_mnt = TRUE;
				} else {
					aa_tab[*aaidx]->aa_mnt = FALSE;
					aa_tab[*aaidx]->aa_type =
						"backup_slice";
				}

				(*aaidx)++;
				/*
				 * Allocate another action_arg
				 * to end the aa_tab array with
				 * an action_arg with aa_path == NULL;
				 */
				aa_tab[*aaidx] = (struct action_arg *)
				calloc(1, sizeof (struct action_arg));
				if (aa_tab[*aaidx] == NULL) {
					dprintf(
				"%s[%d]: couldn't calloc an action arg\n",
						__FILE__, __LINE__);
					result = 0;
				}
			}
		}
	}
	if (dirp != NULL) {
		closedir(dirp);
	}
	if (pathname != NULL) {
		free(pathname);
	}
	dprintf("%s[%d]: leaving read_directory, result = %d\n",
		__FILE__, __LINE__, result);
	return (result);
}

static void
share_mount(struct action_arg *aa, struct mount_args *ma, bool_t rdonly)
{
	/*
	 * export the filesystem
	 */

	extern void	share_readonly(struct mount_args *);
	extern void	quote_clean(int, char **);
	extern void	makeargv(int *, char **, char *);
	pid_t  		pid;
	int		pfd[2];
	int		rval;
	int		ac;
	char		*av[MAX_ARGC];
	char		*buf = NULL;
	int		n, buf_count = 0;

	if (aa->aa_mnt == FALSE) {
		return;
	}

	/* if it's a readonly thing, make sure the share args are right */
	if (rdonly || ma->ma_key & MA_READONLY) {
		share_readonly(ma);
	}

	buf_count = strlen(SHARE_CMD) + strlen(ma->ma_options) +
		strlen(aa->aa_mountpoint) + 3;
	/* 3 - 2 spaces and a NULL terminator */

	if ((buf = malloc(buf_count)) == NULL) {
		(void) fprintf(stderr,
			gettext("%s(%ld) error: malloc failed\n"),
			prog_name, prog_pid);
		return;
	}

	/* build our command line into buf */
	(void) sprintf(buf, "%s %s %s", SHARE_CMD, ma->ma_options,
		aa->aa_mountpoint);

	makeargv(&ac, av, buf);
	quote_clean(ac, av);	/* clean up quotes from -d stuff... yech */

	(void) pipe(pfd);
	if ((pid = fork()) == 0) {

		(void) close(pfd[1]);
		(void) dup2(pfd[0], fileno(stdin));
		(void) dup2(pfd[0], fileno(stdout));
		(void) dup2(pfd[0], fileno(stderr));

		(void) execv(SHARE_CMD, av);

		(void) fprintf(stderr,
		    gettext("%s(%ld) error: exec of %s failed; %s\n"),
		    prog_name, prog_pid, SHARE_CMD, strerror(errno));
		_exit(-1);
	}
	(void) close(pfd[0]);
	free(buf);

	/* wait for the share command to exit */
	if (waitpid(pid, &rval, 0) < 0) {
		dprintf("%s(%ld): waitpid() failed (errno %d)\n",
		    prog_name, prog_pid, errno);
		return;
	}

	if (WEXITSTATUS(rval) != 0) {
		char errbuf[BUFSIZ];
		/* if there was an error, print out the mount message */
		(void) fprintf(stderr, gettext("%s(%ld) share error:\n\t"),
		    prog_name, prog_pid);
		(void) fflush(stderr);
		while ((n = read(pfd[1], errbuf, sizeof (errbuf))) > 0) {
			(void) write(fileno(stderr), errbuf, n);
		}
	} else {
		(void) dprintf("%s(%ld): %s shared\n", prog_name, prog_pid,
		    aa->aa_mountpoint);
	}
}

static bool_t
umount_fork(char *path)
{
	pid_t	pid;
	int	rval;


	if ((pid = fork()) == 0) {
		int	fd;

		/* get rid of those nasty err messages */
		if ((fd = open("/dev/null", O_RDWR)) >= 0) {
			(void) dup2(fd, fileno(stdin));
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
		}

		(void) execl(UMOUNT_CMD, UMOUNT_CMD, path, NULL);

		(void) fprintf(stderr,
		    gettext("%s(%ld) error: exec of %s failed; %s\n"),
		    prog_name, prog_pid, UMOUNT_CMD, strerror(errno));
		_exit(-1);
		/*NOTREACHED*/
	}

	/* wait for the umount command to exit */
	(void) waitpid(pid, &rval, 0);

	if (WEXITSTATUS(rval) != 0) {
		(void) fprintf(stderr, gettext(
		"%s(%ld) error: \"umount\" of \"%s\" failed, returning %d\n"),
		    prog_name, prog_pid, path, WEXITSTATUS(rval));
		return (FALSE);
	}
	return (TRUE);
}

/*ARGSUSED*/
static void
unshare_mount(struct action_arg *aa, struct mount_args *ma)
{
	/*
	 * unexport the filesystem.
	 */

	extern void	makeargv(int *, char **, char *);
	pid_t  		pid;
	int		pfd[2];
	int		rval;
	int		ac;
	char		*av[MAX_ARGC];
	char		*buf = NULL;
	int		n, buf_count = 0;
	int		mountpoint_bufcount = 0;
	char		*mountpoint = NULL;
	char		*targ_dir = getenv("VOLUME_NAME");

	/*
	 * reconstruct the mount point and hope the media's still
	 * mounted there. :-(
	 */
	if (aa->aa_partname != NULL) {
		mountpoint_bufcount = strlen(aa->aa_media) +
			strlen(targ_dir) + strlen(aa->aa_partname) + 3 + 1;
		/* 1 - for NULL terminator, 3 - for "/"s */
		mountpoint = malloc(mountpoint_bufcount);
		if (mountpoint == NULL) {
			(void) fprintf(stderr,
				gettext("%s(%ld) error: malloc failed\n"),
				prog_name, prog_pid);
			return;
		}
		(void) sprintf(mountpoint, "/%s/%s/%s", aa->aa_media,
		    targ_dir, aa->aa_partname);
	} else {
		mountpoint_bufcount = strlen(aa->aa_media) +
			strlen(targ_dir) + 2 + 1;
		/* 1 - for NULL terminator, 2 - for "/"s */
		mountpoint = malloc(mountpoint_bufcount);
		if (mountpoint == NULL) {
			(void) fprintf(stderr,
				gettext("%s(%ld) error: malloc failed\n"),
				prog_name, prog_pid);
			return;
		}
		(void) sprintf(mountpoint, "/%s/%s", aa->aa_media, targ_dir);
	}

	/* build our command line into buf */
	buf_count = strlen(UNSHARE_CMD) + strlen(mountpoint) + 2;

	if ((buf = malloc(buf_count)) == NULL) {
		(void) fprintf(stderr,
			gettext("%s(%ld) error: malloc failed\n"),
			prog_name, prog_pid);
		return;
	}
	(void) sprintf(buf, "%s %s", UNSHARE_CMD, mountpoint);
	free(mountpoint);

	makeargv(&ac, av, buf);

	(void) pipe(pfd);
	if ((pid = fork()) == 0) {

		(void) close(pfd[1]);

		(void) dup2(pfd[0], fileno(stdin));
		(void) dup2(pfd[0], fileno(stdout));
		(void) dup2(pfd[0], fileno(stderr));

		(void) execv(UNSHARE_CMD, av);

		(void) fprintf(stderr,
		    gettext("%s(%ld) error: exec of %s failed; %s\n"),
		    prog_name, prog_pid, UNSHARE_CMD, strerror(errno));
		_exit(-1);
	}
	(void) close(pfd[0]);
	free(buf);

	/* wait for the share command to exit */
	if (waitpid(pid, &rval, 0) < 0) {
		dprintf("%s(%ld): waitpid() failed (errno %d)\n",
		    prog_name, prog_pid, errno);
		return;
	}

	if (WEXITSTATUS(rval) != 0) {
		char errbuf[BUFSIZ];
		/* if there was an error, print out the message */
		(void) fprintf(stderr, gettext("%s(%ld) unshare error:\n\t"),
		    prog_name, prog_pid);
		(void) fflush(stderr);
		while ((n = read(pfd[1], errbuf, sizeof (errbuf))) > 0) {
			(void) write(fileno(stderr), errbuf, n);
		}
	}

}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "%s(%ld) usage: %s [-D] [-c config_file] [-d filesystem_dev]\n"),
	    prog_name, prog_pid, prog_name);

	exit(-1);
}
