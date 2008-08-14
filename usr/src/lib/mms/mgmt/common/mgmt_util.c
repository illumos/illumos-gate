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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

static char *_SrcFile = __FILE__; /* Using __FILE__ makes duplicate strings */

/*
 * various utility functions
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/mnttab.h>
#include <libgen.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <procfs.h>
#include <dirent.h>
#include <auth_attr.h>
#include <secdb.h>

#include "mgmt_util.h"
#include "mmp_defs.h"
#include "mms_cfg.h"

/* forward declarations */
static int file_chown(char *file, struct stat64 *statbuf, char *user,
	char *group);
static int file_chown_id(char *file, struct stat64 *statbuf, uid_t uid,
	gid_t gid);
static void
filter_on_var(char *varname, char **varray, int count, nvlist_t *nvl);

/*
 * mms_gen_taskid()
 *
 * Parameters:
 *      - tid           unique task identifier.
 *
 * This function returns a task identifier (TID). All responses to an MMP
 * command will include the TID of the initiating command. The TID will be
 * unique in the context of a session so that the client can determine which
 * responses go with which command.
 */
int
mms_gen_taskid(char *tid)
{
	if (!tid) {
		return (MMS_MGMT_NOARG);
	}

	(void) sprintf(tid, "%d-%ld", (int)getpid(), time(NULL));

	return (0);
}

/*
 * create the directory dir. This function will not fail if the directory
 * already exists.
 */
int
create_dir(char *dir, mode_t perms, char *user, uid_t uid, char *group,
	gid_t gid)
{

	struct stat64	dir_stat;
	int		st = 0;

	if (!dir) {
		return (MMS_MGMT_NOARG);
	}

	if (perms == 0) {
		/* make the dir rwx by owner, and rx by other and group */
		perms = 0 | S_IRWXU | S_IROTH | S_IXOTH | S_IRGRP | S_IXGRP;
	}

	mms_trace(MMS_INFO, "creating directory %s", dir);
	errno = 0;
	if (stat64(dir, &dir_stat) == 0) {
		if (!S_ISDIR(dir_stat.st_mode)) {

			/* TBD: set errno and errmsg */
			return (ENOTDIR);
		}
	} else if (errno == ENOENT) {
		errno = 0;
		st = mkdirp(dir, perms);
		if (st != 0) {
			return (errno);
		}
		(void) stat64(dir, &dir_stat);
	}

	if (uid == 0) {
		st = file_chown(dir, &dir_stat, user, group);
	} else {
		st = file_chown_id(dir, &dir_stat, uid, gid);
	}

	return (st);
}

static int
file_chown(char *file, struct stat64 *statbuf, char *user, char *group)
{
	struct passwd	pwd;
	struct passwd	*pwdp;
	struct group	gr;
	struct group	*grp;
	char		buf[1024];
	uid_t		uid = 0;
	gid_t		gid = 0;
	int		st;

	if ((file == NULL) || (statbuf == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	if (user == NULL) {
		/* nothing to do */
		return (0);
	}

	(void) getpwnam_r(user, &pwd, buf, sizeof (buf), &pwdp);
	if (pwdp == NULL) {
		return (MMS_MGMT_ERR_USER);
	}
	uid = pwdp->pw_uid;
	gid = pwdp->pw_gid;	/* default to user's default group */

	if (group != NULL) {
		(void) getgrnam_r(group, &gr, buf, sizeof (buf), &grp);
		if (grp == NULL) {
			return (MMS_MGMT_ERR_GROUP);
		}
		gid = grp->gr_gid;
	}

	st = file_chown_id(file, statbuf, uid, gid);

	return (st);
}

static int
file_chown_id(char *file, struct stat64 *statbuf, uid_t uid, gid_t gid)
{
	int	st;

	if ((file == NULL) || (statbuf == NULL)) {
		return (MMS_MGMT_NOARG);
	}

	if ((uid == 0) && (gid == 0)) {
		/* nothing to do */
		return (0);
	}

	if ((statbuf->st_uid == uid) && (statbuf->st_gid == gid)) {
		/* nothing to do */
		return (0);
	}

	st = chown(file, uid, gid);

	return (st);
}

int cp_file(
	const char *old,
	const char *new)
{
	int		oldfd = -1;
	int		newfd = -1;
	struct stat	oldstatbuf;
	struct stat	newstatbuf;
	int		res;
	int		saverr = 0;
	struct timeval	oldtimes[2];
	char		buf[8192];
	int		wlen;
	ssize_t		oldlen;

	mms_trace(MMS_DEBUG, "copying file %s to %s", old, new);

	/* make sure old exists */
	res = stat(old, &oldstatbuf);
	if (res != 0) {
		return (errno);
	}

	/* if the target exists, remove it */
	res = stat(new, &newstatbuf);
	if (res == 0) {
		mms_trace(MMS_DEBUG, "cp_file: removing %s", new);
		(void) unlink(new);
	}

	/* save the access & mod times so they can be reset */
	oldtimes[0].tv_sec = oldstatbuf.st_atim.tv_sec;
	oldtimes[0].tv_usec = oldstatbuf.st_atim.tv_nsec / 1000;
	oldtimes[1].tv_sec = oldstatbuf.st_mtim.tv_sec;
	oldtimes[1].tv_usec = oldstatbuf.st_mtim.tv_nsec / 1000;

	oldfd = open(old, O_RDONLY, oldstatbuf.st_mode);
	if (oldfd == -1) {
		res = errno;
		mms_trace(MMS_ERR, "Error opening %s, %d", old, res);
		return (res);
	}
	newfd = open(new, O_WRONLY|O_CREAT|O_EXCL, oldstatbuf.st_mode);
	if (newfd == -1) {
		res = errno;
		(void) close(oldfd);
		mms_trace(MMS_ERR, "Error opening %s, %d", new, res);
		return (res);
	}

	/* finally, copy the file */
	res = 0;
	oldlen = oldstatbuf.st_size;

	while (oldlen > 0) {
		if (oldlen < 8192) {
			wlen = oldlen;
		} else {
			wlen = 8192;
		}

		res = readbuf(oldfd, buf, wlen);
		if (res == -1) {
			saverr = errno;
			mms_trace(MMS_ERR, "Error reading file %s, %d",
			    old, saverr);
			break;
		}

		res = write_buf(newfd, buf, wlen);
		if (res == -1) {
			saverr = errno;
			mms_trace(MMS_ERR, "Error writing file %s, %d",
			    new, saverr);
			break;
		}

		oldlen -= wlen;
	}

	(void) close(newfd);
	(void) close(oldfd);

	/* set acccess & modify times to match original file */
	if (saverr == 0) {
		(void) utimes(new, oldtimes);
		(void) utimes(old, oldtimes);
		res = 0;
	} else {
		res = saverr;
	}

	return (res);
}

/* helper function to use read() correctly */
int
readbuf(int fd, void* buffer, int len)
{
	int	numread = 0;
	int	ret;
	char	*bufp;

	if ((buffer == NULL) || (len < 1) || (fd == -1)) {
		return (-1);
	}

	bufp = buffer;

	while (numread < len) {
		ret = read(fd, bufp, (len - numread));

		if (ret == 0) {
			/* reached EOF */
			break;
		} else if (ret == -1) {
			if (errno == EAGAIN) {
				continue;
			}
			numread = -1;
			break;
		}

		numread += ret;
		bufp += ret;
	}

	return (numread);
}

/* helper function to use write() correctly */
int
write_buf(int fd, void* buffer, int len)
{
	int	written = 0;
	int	ret;
	char	*bufp;

	if ((buffer == NULL) || (fd == -1)) {
		return (-1);
	}

	bufp = buffer;

	while (written < len) {
		ret = write(fd, bufp, (len - written));

		if (ret == -1) {
			if (errno == EAGAIN) {
				continue;
			}
			written = -1;
			break;
		}

		written += ret;
		bufp += written;
	}

	return (written);
}

/*
 * mk_wc_path()
 *
 * Function to generate a path name for working copies of
 * files and creates the file.
 */
int
mk_wc_path(
	char *original, 	/* IN - path to original file */
	char *tmppath, 		/* IN/OUT - buffer to hold new file path */
	size_t buflen)		/* IN - length of buffer */
{
	char		*copypath;
	char		template[MAXPATHLEN+1];
	char		buf[MAXPATHLEN+1];
	char		*fname;
	int		ret;
	struct stat64	statbuf;

	if (!original || !tmppath) {
		return (MMS_MGMT_NOARG);
	}

	/* make sure target directory exists */
	ret = create_dir(default_tmpfile_dir, 0, NULL, geteuid(),
	    NULL, getegid());
	if (ret != 0) {
		return (ret);
	}

	ret = stat64(original, &statbuf);

	/*
	 * not an error if the original doesn't exist.  In this
	 * case, dummy up a mode to be used for the later mknod.
	 */
	if (ret != 0) {
		statbuf.st_mode = S_IFREG;
		statbuf.st_mode |= S_IRWXU|S_IRGRP|S_IROTH;
	}

	/* create the template name */
	(void) strlcpy(buf, original, MAXPATHLEN+1);
	fname = basename(buf);
	(void) snprintf(template, MAXPATHLEN+1, "%s/%s_XXXXXX",
	    default_tmpfile_dir, fname);

	copypath = mktemp(template);

	if (copypath == NULL) {
		return (-1);
	} else {
		(void) strlcpy(tmppath, copypath, buflen);
	}

	/* make sure an old version isn't hanging around */
	(void) unlink(tmppath);

	/* create the target file */
	ret = mknod(tmppath, statbuf.st_mode, 0);

	return (ret);
}

/*
 * make_working_copy()
 *
 * Copies a file to the default temporary location and returns
 * the pathname of the copy.
 *
 */
int
make_working_copy(char *path, char *wc_path, int pathlen)
{
	int		ret;

	if (!path || !wc_path) {
		return (-1);
	}

	ret = mk_wc_path(path, wc_path, pathlen);
	if (ret != 0) {
		return (ret);
	}

	ret = cp_file(path, wc_path);

	return (ret);
}


typedef struct proclist proclist_t;
struct proclist {
	mms_list_node_t	next_proc;
	psinfo_t	*proc;
};

/*
 * The find_process() function reads through /proc and finds all processes with
 * the specified executable name.
 *
 * PARAM
 * exename	- INPUT - 	name of executable
 * procs	- OUTPUT - 	list of psinfo_t structs
 *
 * ERRORS
 */
int
find_process(char *exename, mms_list_t *procs)
{
	DIR		*dirp;
	dirent64_t	*dent;
	dirent64_t	*dentp;
	char		pname[MAXPATHLEN];
	char		*ptr;
	int		procfd;	/* filedescriptor for /proc/nnnnn/psinfo */
	psinfo_t 	info;	/* process information from /proc */
	int		ret = 0;
	int		len = sizeof (info);

	if (!exename || !procs) {
		return (MMS_MGMT_NOARG);
	}

	mms_trace(MMS_INFO, "finding all %s processes", exename);

	if ((dirp = opendir(PROCDIR)) == NULL) {
		ret = errno;
		mms_trace(MMS_ERR, "Could not open %s, %d", PROCDIR, ret);
		return (ret);
	}

	mms_list_create(procs, sizeof (proclist_t),
	    offsetof(proclist_t, next_proc));

	/* allocate the dirent structure */
	dent = malloc(MAXPATHLEN + sizeof (dirent64_t));
	if (dent == NULL) {
		(void) closedir(dirp);
		mms_list_destroy(procs);
		return (ENOMEM);
	}

	/* find each active process --- */
	while ((ret = readdir64_r(dirp, dent, &dentp)) == 0) {

		if (dentp == NULL) {
			break;
		}

		/* skip . and .. */
		if (dentp->d_name[0] == '.') {
			continue;
		}

		(void) snprintf(pname, MAXPATHLEN, "%s/%s/%s", PROCDIR,
		    dentp->d_name, "psinfo");

		procfd = open64(pname, O_RDONLY);
		if (procfd == -1) {
			/* process may have ended while we were processing */
			continue;
		}

		/*
		 * Get the info structure for the process and close quickly.
		 */
		ret = readbuf(procfd, &info, len);

		(void) close(procfd);

		if (ret == -1) {
			break;
		}

		if (info.pr_lwp.pr_state == 0)		/* can't happen? */
			continue;

		/* ensure cmd buffers properly terminated */
		info.pr_psargs[PRARGSZ-1] = '\0';
		info.pr_fname[PRFNSZ-1] = '\0';

		/* is it the proc we're looking for? */
		if (strncmp(info.pr_psargs, exename, strlen(exename)) != 0) {
			continue;
		}

		ptr = malloc(len);
		if (ptr == NULL) {
			ret = ENOMEM;
			break;
		}
		(void) memcpy(ptr, &info, len);
		mms_list_insert_tail(procs, ptr);
	}

	(void) closedir(dirp);
	free(dent);
	return (ret);
}

/*
 * exec_mgmt_cmd()
 *
 * Helper functino to exec an external program, optionally returning
 * messages written to stdout/stderr and exec()ing as a different UID.
 *
 * The 'cmd' array must have the executable as the first entry, and *must*
 * have a NULL as the last entry.
 */
int
exec_mgmt_cmd(
	FILE		**outstr,
	FILE		**errstr,
	uid_t		euid,
	gid_t		egid,
	boolean_t	daemon,
	char		*cmd[])
{
	int		fdo[2] = {-1, -1}; /* pipe for reading stdout */
	int		fde[2] = {-1, -1}; /* pipe for reading stderr */
	pid_t		pid;

	/* The path to the executable must be fully-qualified */
	if ((cmd == NULL) || (cmd[0] == NULL) || (cmd[0][0] != '/')) {
		return (-1);
	}

	if (outstr != NULL) {
		if (pipe(fdo) < 0) {
			return (-1);
		}
	}

	if (errstr != NULL) {
		if (pipe(fde) < 0) {
			(void) close(fdo[0]);
			(void) close(fdo[1]);
			return (-1);
		}
	}

	if ((pid = fork()) < 0) {
		(void) close(fdo[0]);
		(void) close(fdo[1]);
		(void) close(fde[0]);
		(void) close(fde[1]);
		return (-1);
	}

	if (pid == 0) {		/* child */
		/* redirect stdout and stderr */
		int	ret;

		if (!outstr) {
			fdo[1] = open("/dev/null", O_WRONLY);
		}

		if (!errstr) {
			fde[1] = open("/dev/null", O_WRONLY);
		}

		if ((fde[1] == -1) || (fdo[1] == -1)) {
			exit(9);
		}

		(void) dup2(fdo[1], STDOUT_FILENO);
		(void) dup2(fde[1], STDERR_FILENO);

		(void) close(fdo[0]);
		(void) close(fde[0]);

		(void) close(STDIN_FILENO);

		(void) closefrom(3);

		/* set UID if requested */
		if (euid != 0) {
			(void) setuid(euid);
		}

		if (egid != 0) {
			(void) setgid(egid);
		}

		if (daemon) {
			(void) setsid();	 /* become session leader */
			pid = fork();
			if (pid < 0) {
				exit(1);
			} else if (pid > 0) {
				/* parent */
				exit(0);
			}
		}

		ret = execv(cmd[0], cmd);

		if (0 != ret) {
			return (ret);
		}
	}

	/* parent */
	if (outstr) {
		(void) close(fdo[1]);
		*outstr = fdopen(fdo[0], "r");
	}

	if (errstr) {
		(void) close(fde[1]);
		*errstr = fdopen(fde[0], "r");
	}

	return (pid);
}

/* configuration functions */
void
mgmt_unsetall_cfgvar(void)
{
	(void) mms_cfg_unsetvar(MMS_CFG_CONFIG_TYPE);
	(void) mms_cfg_unsetvar(MMS_CFG_MGR_HOST);
	(void) mms_cfg_unsetvar(MMS_CFG_MGR_PORT);
	(void) mms_cfg_unsetvar(MMS_CFG_SSL_ENABLED);
	(void) mms_cfg_unsetvar(MMS_CFG_SSL_CERT_FILE);
	(void) mms_cfg_unsetvar(MMS_CFG_SSL_PASS_FILE);
	(void) mms_cfg_unsetvar(MMS_CFG_SSL_DH_FILE);
	(void) mms_cfg_unsetvar(MMS_CFG_SSL_CRL_FILE);
	(void) mms_cfg_unsetvar(MMS_CFG_SSL_PEER_FILE);
	(void) mms_cfg_unsetvar(MMS_CFG_SSL_CIPHER);
	(void) mms_cfg_unsetvar(MMS_CFG_SSL_VERIFY);
	(void) mms_cfg_unsetvar(MMS_CFG_DB_DATA);
	(void) mms_cfg_unsetvar(MMS_CFG_DB_LOG);
	(void) mms_cfg_unsetvar(MMS_CFG_MM_DB_HOST);
	(void) mms_cfg_unsetvar(MMS_CFG_MM_DB_PORT);
	(void) mms_cfg_unsetvar(MMS_CFG_MM_DB_NAME);
	(void) mms_cfg_unsetvar(MMS_CFG_MM_DB_USER);
	(void) mms_cfg_unsetvar(MMS_CFG_SSI_PATH);
}

int
mgmt_set_svc_state(
	char		*fmri,
	mms_svcstate_t	targetState,
	char		**original)
{
	char		*startState = NULL;
	char		*endState = NULL;
	int		st = 0;
	const char	*cmpState;
	struct timespec	ts;
	int		i;

	if (fmri == NULL) {
		return (MMS_MGMT_NOARG);
	}

	startState = smf_get_state(fmri);
	if (startState == NULL) {
		st = scf_error();
		/*
		 * Not an error if request to disable or degrade a
		 * non-existent svc
		 */
		if ((targetState == DISABLE) || (targetState == DEGRADE)) {
			if (st == SCF_ERROR_NOT_FOUND) {
				st = 0;
			}
		}
		return (st);
	}

	if (original != NULL) {
		*original = startState;
	}

	switch (targetState) {
		case ENABLE:
			cmpState = SCF_STATE_STRING_ONLINE;
			if (strcmp(startState, cmpState) != 0) {
				st = smf_enable_instance(fmri, 0);
			}
			break;
		case DISABLE:
			cmpState = SCF_STATE_STRING_DISABLED;
			/*
			 * can't go directly from maintenance to disabled,
			 * though I can't see why.
			 */
			if (strcmp(startState, SCF_STATE_STRING_MAINT) == 0) {
				st = mgmt_set_svc_state(fmri, RESTORE, NULL);
				st = smf_disable_instance(fmri, 0);
			}
			if (strcmp(startState, cmpState) != 0) {
				st = smf_disable_instance(fmri, 0);
			}
			break;
		case REFRESH:
			/* refresh shouldn't change the current state */
			cmpState = startState;
			st = smf_refresh_instance(fmri);
			break;
		case RESTART:
			cmpState = SCF_STATE_STRING_ONLINE;
			st = smf_restart_instance(fmri);
			break;
		case MAINTAIN:
			cmpState = SCF_STATE_STRING_MAINT;
			st = smf_maintain_instance(fmri, SMF_IMMEDIATE);
			break;
		case DEGRADE:
			/* only available if 'online' */
			if (strcmp(startState, SCF_STATE_STRING_ONLINE) == 0) {
				cmpState = SCF_STATE_STRING_DEGRADED;
				st = smf_degrade_instance(fmri, 0);
			} else {
				cmpState = startState;
			}
			break;
		case RESTORE:
			/*
			 * if disabled, returns to online.  If maintenance,
			 * returns to disabled.
			 */
			if (strcmp(startState, SCF_STATE_STRING_DISABLED)
			    == 0) {
				cmpState = SCF_STATE_STRING_ONLINE;
			} else if (strcmp(startState, SCF_STATE_STRING_MAINT)
			    == 0) {
				cmpState = SCF_STATE_STRING_DISABLED;
			} else {
				/* invalid operation */
				st = EINVAL;
				break;
			}
			st = smf_restore_instance(fmri);
			break;
		default:
			st = -1;
			break;
	}

	if (st == 0) {
		/*
		 * Changing state sometimes takes a while, so
		 * loop for up to 5 seconds.
		 */
		ts.tv_sec = 0;
		ts.tv_nsec = 500 * 1000000;

		for (i = 1; i < 10; i++) {
			st = 1;
			endState = smf_get_state(fmri);
			if (endState == NULL) {
				st = scf_error();
				break;
			} else if (strcmp(endState, cmpState) == 0) {
				st = 0;
				break;
			}
			free(endState);
			endState = NULL;
			(void) nanosleep(&ts, NULL);
		}
	} else {
		st = scf_error();
	}

	if ((startState != NULL) && (original == NULL)) {
		free(startState);
	}
	if (endState != NULL) {
		free(endState);
	}

	return (st);
}

int
check_exit(pid_t pid, int *signo)
{
	pid_t	wpid;
	int	pst;
	int	st = EINVAL;

	if (pid == (pid_t)-1) {
		return (st);
	}

	wpid = waitpid(pid, &pst, 0);

	if (wpid != pid) {
		st = errno;
	} else {
		if (WIFEXITED(pst)) {
			st = WEXITSTATUS(pst);
		} else if (WIFSIGNALED(pst)) {
			st = EINTR;
			if (signo) {
				*signo = WTERMSIG(pst);
			}
		} else if (WCOREDUMP(pst)) {
			st = EINTR;
			if (signo) {
				*signo = SIGSEGV;
			}
		}
	}

	return (st);
}

/* Helper function for MMS lists */
void
mms_list_free_and_destroy(mms_list_t *list, void (*free_func)(void *))
{
	mms_list_node_t	*node;

	if (!list || !free_func || (list->list_size == 0)) {
		return;
	}

	while (! mms_list_empty(list)) {
		node = mms_list_head(list);

		mms_list_remove(list, node);
		free_func(node);
	}

	mms_list_destroy(list);
}

/* helper functions to validate option values */
int
val_numonly(char *val)
{
	int	st = 0;
	char	*bufp;

	if (!val) {
		return (MMS_MGMT_NOARG);
	}

	for (bufp = val; *bufp != '\0'; bufp++) {
		if (*bufp == '-') {
			/* negative number */
			continue;
		}
		if (!isdigit(*bufp)) {
			st = EINVAL;
			break;
		}
	}

	return (st);
}

int
val_passwd(char *val)
{
	if (!val) {
		return (MMS_MGMT_NOARG);
	} else if (strlen(val) < 8) {
		return (EINVAL);
	} else {
		return (0);
	}
}

int
val_objtype(char *val)
{
	if (!val) {
		return (MMS_MGMT_NOARG);
	}

	if ((strcmp(val, "client") == 0) ||
	    (strcmp(val, "server") == 0) ||
	    (strcmp(val, "library") == 0) ||
	    (strcmp(val, "dkdrive") == 0) ||
	    (strcmp(val, "drive") == 0) ||
	    (strcmp(val, "mpool") == 0) ||
	    (strcmp(val, "app") == 0) ||
	    (strcmp(val, "alarm") == 0) ||
	    (strcmp(val, "vol") == 0) ||
	    (strcmp(val, "voltype") == 0) ||
	    (strcmp(val, "dkvol") == 0)) {
		return (0);
	} else {
		return (EINVAL);
	}
}

int
val_path(char *val)
{
	if (!val) {
		return (MMS_MGMT_NOARG);
	}

	if (*val != '/') {
		return (EINVAL);
	}

	return (0);
}

int
val_level(char *val)
{
	if (!val) {
		return (MMS_MGMT_NOARG);
	}

	if ((strcmp(val, "emergency") == 0) ||
	    (strcmp(val, "alert") == 0) ||
	    (strcmp(val, "critical") == 0) ||
	    (strcmp(val, "error") == 0) ||
	    (strcmp(val, "warning") == 0) ||
	    (strcmp(val, "notice") == 0) ||
	    (strcmp(val, "information") == 0) ||
	    (strcmp(val, "debug") == 0)) {
		return (0);
	} else {
		return (EINVAL);
	}
}

int
val_yesno(char *val)
{
	if (!val) {
		return (MMS_MGMT_NOARG);
	}

	if (*val == 'y' || *val == 'Y' || *val == 'n' || *val == 'N') {
		return (0);
	} else {
		return (EINVAL);
	}
}

int
val_truefalse(char *val)
{
	if (!val) {
		return (MMS_MGMT_NOARG);
	}

	if ((strcmp(val, "true") == 0) || (strcmp(val, "false") == 0)) {
		return (0);
	} else {
		return (EINVAL);
	}
}

int
val_mms_size(char *val)
{
	return (do_val_mms_size(val, NULL));
}

int
do_val_mms_size(char *val, uint64_t *bytes)
{
	uint64_t	sz = 0;
	char		*unit = NULL;
	uint64_t	mult = 1;

	if (!val) {
		return (MMS_MGMT_NOARG);
	}

	sz = strtoll(val, &unit, 10);
	if ((sz == LONG_MAX) || (sz == LONG_MIN)) {
		return (EINVAL);
	}

	if (unit) {
		switch (*unit) {
			case 'b':
			case 'B':
				mult = 1;
				break;
			case 'k':
			case 'K':
				mult = KILO;
				break;
			case 'm':
			case 'M':
				mult = MEGA;
				break;
			case 'g':
			case 'G':
				mult = GIGA;
				break;
			case 't':
			case 'T':
				mult = TERA;
				break;
			case 'p':
			case 'P':
				mult = PETA;
				break;
			default:
				return (EINVAL);
				break;
		}
	}

	if (bytes) {
		*bytes = sz * mult;
	}

	return (0);
}

int
val_density(char *val)
{
	if (!val) {
		return (MMS_MGMT_NOARG);
	}

	if ((strcmp(val, "den_9840C") == 0) ||
	    (strcmp(val, "den_9840") == 0) ||
	    (strcmp(val, "den_LTO4") == 0) ||
	    (strcmp(val, "den_LTO3") == 0) ||
	    (strcmp(val, "den_LTO2") == 0) ||
	    (strcmp(val, "den_LTO1") == 0)) {
		return (0);
	}

	return (EINVAL);
}

int
mms_mgmt_get_pwd(char *pwfile, char *key, char *phrase[2], nvlist_t *nvl,
    nvlist_t *errs)
{
	int		st = 0;
	char		*mpwp;
	char		*chkpw;
	char		buf[512];
	int		fd;
	size_t		sz;

	if (!key || !nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (pwfile != NULL) {
		fd = open(pwfile, O_RDONLY);
		if (fd == -1) {
			st = errno;
			if (errs) {
				(void) nvlist_add_int32(errs, pwfile, st);
			}
			return (st);
		}

		sz = readbuf(fd, buf, sizeof (buf));
		(void) close(fd);

		buf[sz] = '\0';

		while ((sz > 1) && (isspace(buf[sz - 1]))) {
			buf[sz -1] = '\0';
			sz--;
		}

		mpwp = buf;
		if (strlen(mpwp) < 8) {
			return (MMS_MGMT_PASSTOOSHORT);
		}
	} else {
		if ((!phrase) || (!phrase[0])) {
			return (MMS_MGMT_NOARG);
		}

		mpwp = getpassphrase(phrase[0]);
		if (mpwp == NULL) {
			return (MMS_MGMT_GETPASS_FAILED);
		} else if (strlen(mpwp) < 8) {
			return (MMS_MGMT_PASSTOOSHORT);
		}

		/* getpassphrase overwrites previous result, so save first */
		(void) strlcpy(buf, mpwp, sizeof (buf));
		mpwp = buf;

		/* verify entered password if required */
		if (phrase[1]) {
			chkpw = getpassphrase(phrase[1]);
			if ((chkpw == NULL) || (strcmp(mpwp, chkpw) != 0)) {
				return (MMS_MGMT_PASSWD_MISMATCH);
			}
		}
	}

	st = nvlist_add_string(nvl, key, mpwp);
	return (0);
}

/*
 *  Helper function to generate the MMP 'create' clause for the specified
 *  object.
 */
int
create_mmp_clause(char *objtype, mms_mgmt_setopt_t *opts, nvlist_t *inopts,
    nvlist_t *errs, char *cmd, size_t cmdlen)
{
	int		st = 0;
	int		ost = 0;
	char		tid[64];
	char		buf[1024];
	char		*val;
	int		i;

	if (!objtype || !opts || !buf || !inopts) {
		return (MMS_MGMT_NOARG);
	}

	(void) mms_gen_taskid(tid);

	(void) snprintf(cmd, cmdlen, "create task['%s'] type[%s]", tid,
	    objtype);

	for (i = 0; opts[i].name != NULL; i++) {
		if (opts[i].mmpopt == NULL) {
			continue;
		}
		ost = nvlist_lookup_string(inopts, opts[i].name, &val);
		if (ost == ENOENT) {
			if (opts[i].required) {
				if (opts[i].defval) {
					val = opts[i].defval;
					ost = 0;
				}
			} else {
				ost = 0;
				continue;
			}
		}
		if (ost != 0) {
			MGMT_ADD_OPTERR(errs, opts[i].name, ost);
			if (st == 0) {
				st = ost;
			}
			continue;
		}
		(void) snprintf(buf, sizeof (buf), " set[%s.'%s' '%s']",
		    objtype, opts[i].mmpopt, val);
		(void) strlcat(cmd, buf, cmdlen);
	}

	(void) strlcat(cmd, ";\n", cmdlen);

	return (st);
}

int
mms_add_object(void *session, char *objtype, mms_mgmt_setopt_t *objopts,
    nvlist_t *nvl, nvlist_t *errs)
{
	void	*response = NULL;
	int	st;
	char	tid[64];
	char	cmd[8192];
	void	*sess = NULL;
	void	*sessp = session;

	if (!objtype || !objopts || !nvl) {
		return (MMS_MGMT_NOARG);
	}

	if (session == NULL) {
		st = create_mm_clnt(NULL, NULL, NULL, NULL, &sess);
		if (st != 0) {
			return (st);
		}
		sessp = sess;
	}

	st = create_mmp_clause(objtype, objopts, nvl, errs, cmd, sizeof (cmd));
	if (st == 0) {
		st = mms_mgmt_send_cmd(sessp, tid, cmd, "mms_add_object()",
		    &response);

		mms_free_rsp(response);
	}

	if (sess) {
		(void) mms_goodbye(sess, 0);
	}

	return (st);
}

int
mms_mgmt_send_cmd(void *sess, char *tid, char *cmd, char *pfx, void **response)
{
	int		st = 0;

	if (!sess || !tid || !cmd || !pfx || !response) {
		return (MMS_MGMT_NOARG);
	}

	mms_trace(MMS_DEBUG, "%s request command: %s", pfx, cmd);

	if ((st = mms_send_cmd(sess, cmd, response)) != 0) {
		st = MMS_MGMT_MMP_PARSE_ERR;
		mms_trace(MMS_ERR, "%s send command failed with %d", pfx,
		    st);
	} else {
		mms_trace(MMS_DEBUG, "Response[%s]: %s",
		    tid, ((mms_rsp_ele_t *)(*response))->mms_rsp_str);

		if ((st = mms_client_handle_rsp(*response)) != MMS_API_OK) {
			mms_trace(MMS_ERR, "%s response failed", pfx);
		}
	}

	return (st);
}

int
mgmt_find_changed_attrs(char *objtype, mms_mgmt_setopt_t *opts,
    nvlist_t *nvl, char **carray, int *count, nvlist_t *errs)
{
	int		st = 0;
	int		ost = 0;
	int		i;

	if (!objtype || !opts || !nvl || !carray || !count) {
		return (MMS_MGMT_NOARG);
	}

	*count = 0;

	for (i = 0; opts[i].name != NULL; i++) {
		if (strcmp(opts[i].name, "name") == 0) {
			continue;
		}
		ost = nvlist_lookup_string(nvl, opts[i].name, &carray[i]);
		if (ost == 0) {
			if (opts[i].validate_func) {
				ost = (opts[i].validate_func)(carray[i]);
				if (ost != 0) {
					if (st == 0) {
						st = ost;
					}
					MGMT_ADD_OPTERR(errs, opts[i].name,
					    ost);
					carray[i] = NULL;
					continue;
				}
			}
			(*count)++;
		}
	}

	return (st);
}

void
cmp_mmp_opts(mms_mgmt_setopt_t *opts, char **carray, nvlist_t *nva, int *count)
{
	int	i;
	int	ost;
	char	*val;

	if (!opts || !carray || !nva || !count) {
		return;
	}

	for (i = 0; opts[i].name != NULL; i++) {
		if (carray[i] == NULL) {
			continue;
		}
		ost = nvlist_lookup_string(nva, opts[i].mmpopt, &val);
		if (ost != 0) {
			continue;
		}
		if (strcmp(val, carray[i]) == 0) {
			/* value identical */
			carray[i] = NULL;
			(*count)--;
		}
	}
}

void
mk_set_clause(char *objtype, mms_mgmt_setopt_t *opts, char **carray,
    char *buf, int buflen)
{
	int	i;
	char	phrase[1024];

	if (!objtype || !opts || !carray || !buf) {
		return;
	}

	for (i = 0; opts[i].name != NULL; i++) {
		if (carray[i] == NULL) {
			continue;
		}
		(void) snprintf(phrase, sizeof (phrase),
		    " set[%s.'%s' '%s']",
		    objtype, opts[i].mmpopt, carray[i]);
		(void) strlcat(buf, phrase, buflen);
	}
}

char **
var_to_array(nvlist_t *nvl, char *optname, int *count)
{
	int		st;
	data_type_t	nvt;
	nvpair_t	*nvp = NULL;
	char		**arr = NULL;
	char		*val = NULL;
	char		**aval = NULL;
	int		i;

	if (!nvl || !optname || !count) {
		return (NULL);
	}

	*count = 0;

	st = nvlist_lookup_nvpair(nvl, optname, &nvp);
	if (nvp == NULL) {
		return (NULL);
	}

	nvt = nvpair_type(nvp);

	if (nvt == DATA_TYPE_STRING) {
		st = nvpair_value_string(nvp, &val);
		if (st == 0) {
			*count = 1;
			arr = malloc(sizeof (char *));
			if (arr != NULL) {
				arr[0] = strdup(val);
			}
		}
	} else if (nvt == DATA_TYPE_STRING_ARRAY) {
		st = nvpair_value_string_array(nvp, &aval, (uint_t *)count);
		if ((st == 0) && (*count > 0)) {
			arr = malloc(sizeof (char *) * *count);
			if (arr != NULL) {
				for (i = 0; i < *count; i++) {
					arr[i] = strdup(aval[i]);
				}
			}
		}
	}

	return (arr);
}

void
mgmt_free_str_arr(char **inarr, int count)
{
	int	i;

	if (!inarr) {
		return;
	}

	for (i = 0; i < count; i++) {
		if (inarr[i]) {
			free(inarr[i]);
		}
	}

	free(inarr);
}

int
mgmt_opt_to_var(char *in_str, boolean_t allow_empty, nvlist_t *nvl)
{
	int	st;
	char	*bufp;
	char	*wstr;

	if (!in_str || !nvl) {
		return (MMS_MGMT_NOARG);
	}

	wstr = strdup(in_str);
	if (!wstr) {
		return (ENOMEM);
	}

	bufp = strchr(wstr, '=');
	if (!bufp) {
		return (MMS_MGMT_NOARG);
	}
	*bufp++ = '\0';

	st = mgmt_set_str_or_arr(bufp, wstr, nvl);
	if (st != 0) {
		if (st == ENOENT) {
			if (allow_empty) {
				/* common for 'list' options */
				st = 0;
				(void) nvlist_add_string(nvl, wstr, "");
			}
		}
	}

	free(wstr);

	return (st);
}

int
mgmt_set_str_or_arr(char *inargs, char *key, nvlist_t *nvl)
{
	int		st;
	char		*bufp;
	int		count;
	char		**tmparr;

	if (!inargs || !key || !nvl) {
		return (MMS_MGMT_NOARG);
	}

	bufp = inargs;
	count = 1;

	for (;;) {
		bufp = strchr(bufp, ',');
		if (bufp == NULL) {
			break;
		}
		bufp++;
		count++;
	}

	if (count == 1) {
		st = nvlist_add_string(nvl, key, inargs);
	} else {
		tmparr = calloc(count, sizeof (char *));
		if (tmparr == NULL) {
			return (ENOMEM);
		}
		bufp = inargs;
		/* set delimiter to comma */
		(void) bufsplit(",", 0, NULL);

		(void) bufsplit(bufp, count, tmparr);
		st = nvlist_add_string_array(nvl, key, tmparr, count);
		free(tmparr);
	}

	return (st);
}

int
mgmt_xlate_cfgerr(scf_error_t in_err)
{
	int		st;

	switch (in_err) {
		case SCF_ERROR_NOT_SET:
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_DELETED:
			st = ENOENT;
			break;
		case SCF_ERROR_NO_MEMORY:
			st = ENOMEM;
			break;
		case SCF_ERROR_TYPE_MISMATCH:
			st = EINVAL;
			break;
		default:
			st = in_err;
			break;
	}

	return (st);
}

int
mgmt_get_mntpt(struct statvfs64 *in, char **mntpt)
{
	int		st = ENOENT;
	FILE		*fp;
	struct mnttab	mntfs;
	struct statvfs	sbuf;

	if (!in || !mntpt) {
		return (MMS_MGMT_NOARG);
	}

	(void) memset(&mntfs, 0, sizeof (struct mnttab));

	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		return (EIO);
	}

	while ((getmntent(fp, &mntfs)) == 0) {
		if (strcmp(in->f_basetype, mntfs.mnt_fstype) != 0) {
			continue;
		}

		if (statvfs(mntfs.mnt_mountp, &sbuf) != 0) {
			/* should never happen */
			continue;
		}
		if (sbuf.f_fsid == in->f_fsid) {
			*mntpt = strdup(mntfs.mnt_mountp);
			if (*mntpt == NULL) {
				st = ENOMEM;
			} else {
				st = 0;
			}
			break;
		}
	}
	(void) fclose(fp);

	return (st);
}

int
mgmt_compare_hosts(char *host1, char *host2)
{
	int			st;
	struct addrinfo		*res1 = NULL;
	struct addrinfo		*res2 = NULL;
	struct addrinfo		*p1 = NULL;
	struct addrinfo		*p2 = NULL;
	boolean_t		match = B_FALSE;
	int			a;

	if (!host1 || !host2) {
		return (MMS_MGMT_NOARG);
	}

	st = getaddrinfo(host1, NULL, NULL, &res1);
	if (st != 0) {
		return (st);
	}

	st = getaddrinfo(host2, NULL, NULL, &res2);
	if (st != 0) {
		freeaddrinfo(res1);
		return (st);
	}

	for (p1 = res1; p1 != NULL; p1 = p1->ai_next) {
		for (p2 = res2; p2 != NULL; p2 = p2->ai_next) {
			a = memcmp(p1->ai_addr, p2->ai_addr,
			    sizeof (struct sockaddr));
			if (a == 0) {
				match = B_TRUE;
				break;
			}
			if (memcmp(p1->ai_addr, p2->ai_addr,
			    sizeof (struct sockaddr)) == 0) {
				match = B_TRUE;
				break;
			}
		}
	}

	if (res1) {
		freeaddrinfo(res1);
	}
	if (res2) {
		freeaddrinfo(res2);
	}

	if (match) {
		return (0);
	}

	return (1);
}

/* error messages */
static char *mms_mgmt_errs[] = {
	NULL,
	"Internal error; missing argument",
	"Could not exec ACSLS ssi daemon",
	"Could not communicate with ACSLS server",
	"Received invalid response from ACSLS server",
	"Could not parse response from ACSLS server",
	"Missing required option",
	"Could not determine MM host",
	"Volume in use",
	"Could not access database backup",
	"Unknown response type",
	"Request cancelled",
	"Request not accepted",
	"Could not determine group",
	"Could not determine user",
	"Option applies to MM server host only",
	"Volume not unique",
	"Partition not unique",
	"Volume not labeled",
	"No usable volume found",
	"Could not find ACSLS client libraries",
	"MMS is not initialized or not running",
	"Drives on remote systems cannot be configured at this time",
	"Operation requires a password",
	"Volume not mounted",
	"Not authorized.  Use the correct application/password combination.",
	"Password validation failed",
	"Failed to get the password",
	"Password must be 8 characters or longer.",
	"Internal error:  MMP parsing failed",
	"Application is still using one or more volumes.",
	"Not a valid MMS database backup file",
	"Database Administrator user account not found"
};

const char *
mms_mgmt_get_errstr(int errcode)
{
	int max_err = sizeof (mms_mgmt_errs) / sizeof (char *);

	/* standard errors */
	if (errcode < 256) {
		return (strerror(errcode));
	}

	/* SCF errors */
	if ((errcode >= 1000) && (errcode < 1020)) {
		return (scf_strerror(errcode));
	}

	if ((errcode >= 2000) && (errcode < (2000 + max_err))) {
		return (mms_mgmt_errs[errcode - 2000]);
	}

	if (errcode >= MMS_ERR_BIAS) {
		return (mms_sym_code_to_str(errcode));
	}

	return (NULL);
}

int
mgmt_chk_auth(char *authname)
{
	int		st;
	struct passwd	pwd;
	struct passwd	*pwdp;
	char		buf[1024];

	if (!authname) {
		return (1);
	}

	st = getpwuid_r(getuid(), &pwd, buf, sizeof (buf), &pwdp);

	if (st != 0) {
		/* fail if we can't determine the username */
		return (0);
	}

	st = chkauthattr(authname, pwdp->pw_name);

	return (st);
}

void
mgmt_filter_results(nvlist_t *filter, nvlist_t *nvl)
{
	int		st;
	int		count;
	char		**varray;
	nvpair_t	*nvp;
	char		*key;
	data_type_t	nvt;
	boolean_t	do_filter = B_FALSE;

	if (!filter || !nvl) {
		/* not a failure if nothing to do */
		return;
	}

	st = nvlist_lookup_boolean_value(filter, "filter", &do_filter);
	if ((st != 0) || !do_filter) {
		return;
	}

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(filter, nvp)) != NULL) {
		key = nvpair_name(nvp);

		if ((strcmp(key, "printopts") == 0) ||
		    (strcmp(key, "name") == 0) ||
		    (strcmp(key, "objtype") == 0)) {
			continue;
		}

		nvt = nvpair_type(nvp);
		if ((nvt != DATA_TYPE_STRING_ARRAY) &&
		    (nvt != DATA_TYPE_STRING)) {
			continue;
		}

		varray = var_to_array(filter, key, &count);
		filter_on_var(key, varray, count, nvl);
		mgmt_free_str_arr(varray, count);
	}
}

static void
filter_on_var(char *varname, char **varray, int count, nvlist_t *nvl)
{
	int		st;
	uint_t		vcount;
	char		**arr;
	nvpair_t	*nvp = NULL;
	nvlist_t	*attrs;
	char		*val;
	data_type_t	nvt;
	int		i;
	int		j;
	nvpair_t	*fnvp;
	char		*attrname;
	nvpair_t	*lastnvp = NULL;
	boolean_t	keep;

	if (!varname || (count == 0) || !nvl) {
		return;
	}


	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		st = nvpair_value_nvlist(nvp, &attrs);
		if (st != 0) {
			continue;
		}

		attrname = nvpair_name(nvp);

		st = nvlist_lookup_nvpair(attrs, varname, &fnvp);
		if (st != 0) {
			/* no match, remove it */
			(void) nvlist_remove_all(nvl, attrname);
			nvp = lastnvp;
			continue;
		}

		keep = B_FALSE;

		nvt = nvpair_type(fnvp);

		val = NULL;
		if (nvt == DATA_TYPE_STRING) {
			(void) nvpair_value_string(fnvp, &val);
			if (val) {
				for (i = 0; i < count; i++) {
					if (strcmp(val, varray[i]) == 0) {
						/* a keeper */
						keep = B_TRUE;
						break;
					}
				}
			}
		} else if (nvt == DATA_TYPE_STRING_ARRAY) {
			st = nvpair_value_string_array(fnvp, &arr, &vcount);
			if (st == 0) {
				for (j = 0; j < vcount; j++) {
					for (i = 0; i < count; i++) {
						if (strcmp(val, varray[i])
						    == 0) {
							/* a keeper */
							keep = B_TRUE;
							break;
						}
					}
					if (keep) {
						break;
					}
				}
			}
		}

		if (keep) {
			lastnvp = nvp;
		} else {
			(void) nvlist_remove_all(nvl, attrname);
			nvp = lastnvp;
		}
	}
}
