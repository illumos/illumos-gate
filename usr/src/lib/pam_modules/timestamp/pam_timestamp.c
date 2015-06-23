/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>

#define	TIMESTAMP_DIR		"/var/run/tty_timestamps"
#define	TIMESTAMP_TIMEOUT	5 /* default timeout */
#define	ROOT_UID		0 /* root uid */
#define	ROOT_GID		0 /* root gid */

struct user_info {
	dev_t dev;		/* ID of device tty resides on */
	dev_t rdev;		/* tty device ID */
	ino_t ino;		/* tty inode number */
	uid_t uid;		/* user's uid */
	pid_t ppid;		/* parent pid */
	pid_t sid;		/* session ID associated with tty/ppid */
	timestruc_t ts;		/* time of tty last status change */
};

int debug = 0;

int
validate_basic(
	pam_handle_t		*pamh,
	char			*user_tty,
	char 			*timestampfile)
{
	char			*user;
	char			*auser;
	char			*ttyn;

	/* get user, auser and users's tty */
	(void) pam_get_item(pamh, PAM_USER, (void **)&user);
	(void) pam_get_item(pamh, PAM_AUSER, (void **)&auser);
	(void) pam_get_item(pamh, PAM_TTY, (void **)&ttyn);

	if (user == NULL || *user == '\0') {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		"PAM_USER NULL or empty");
		return (PAM_IGNORE);
	}

	if (auser == NULL || *auser == '\0') {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		"PAM_AUSER NULL or empty");
		return (PAM_IGNORE);
	}

	if (ttyn == NULL || *ttyn == '\0') {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		"PAM_TTY NULL or empty");
		return (PAM_IGNORE);
	}

	if (debug)
		syslog(LOG_AUTH | LOG_DEBUG, "pam_timestamp: "
		"user = %s, auser = %s, tty = %s", user, auser, ttyn);

	(void) strlcpy(user_tty, ttyn, MAXPATHLEN);

	if (strchr(ttyn, '/') == NULL || strncmp(ttyn, "/dev/", 5) == 0) {
		ttyn = strrchr(ttyn, '/') + 1;
	} else {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		"invalid tty: %s", ttyn);
		return (PAM_IGNORE);
	}

	/* format timestamp file name */
	(void) snprintf(timestampfile, MAXPATHLEN, "%s/%s/%s:%s", TIMESTAMP_DIR,
	    auser, ttyn, user);

	return (PAM_SUCCESS);
}

int
validate_dir(const char *dir)
{
	struct		stat sb;

	/*
	 * check that the directory exist and has
	 * right owner and permissions.
	 */
	if (lstat(dir, &sb) < 0) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "directory %s does not exist", dir);
		return (PAM_IGNORE);
	}

	if (!S_ISDIR(sb.st_mode)) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "%s is not a directory", dir);
		return (PAM_IGNORE);
	}

	if (S_ISLNK(sb.st_mode)) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "%s is a symbolic link", dir);
		return (PAM_IGNORE);
	}

	if (sb.st_uid != 0 || sb.st_gid != 0) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "%s is not owned by root", dir);
		return (PAM_IGNORE);
	}

	if (sb.st_mode & (S_IWGRP | S_IWOTH | S_IROTH)) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "%s has wrong permissions", dir);
		return (PAM_IGNORE);
	}

	return (PAM_SUCCESS);
}

int
create_dir(char *dir)
{
	/*
	 * create directory if it doesn't exist and attempt to set
	 * the owner to root.
	 */
	if (mkdir(dir, S_IRWXU) < 0) {
		if (errno != EEXIST) {
			syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
			    "can't create directory %s", dir);
			return (PAM_IGNORE);
		}
	} else if (lchown(dir, ROOT_UID, ROOT_GID) < 0) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "can't set permissions on directory %s", dir);
		return (PAM_IGNORE);
	}
	return (PAM_SUCCESS);
}

/*
 * pam_sm_authenticate
 *
 * Read authentication from user, using cached successful authentication
 * attempts.
 *
 * returns PAM_SUCCESS on success, otherwise always returns PAM_IGNORE:
 * while this module has "sufficient" control value, in case of any failure
 * user will be authenticated with the pam_unix_auth module.
 * options -
 *	debug
 *	timeout=	timeout in min, default is 5
 */
/*ARGSUSED*/
int
pam_sm_authenticate(
	pam_handle_t		*pamh,
	int 			flags,
	int			argc,
	const char		**argv)
{
	struct			user_info info;
	struct			stat sb, tty;
	time_t			timeout = 0;
	long			tmp = 0;
	int			result = PAM_IGNORE;
	int			i;
	int			fd = -1;
	char			*p;
	char			user_tty[MAXPATHLEN];
	char			timestampdir[MAXPATHLEN];
	char			timestampfile[MAXPATHLEN];
	char			*sudir;

	timeout = TIMESTAMP_TIMEOUT;

	/* check options passed to this module */
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		} else if (strncmp(argv[i], "timeout=", 8) == 0) {
			tmp = strtol(argv[i] + 8, &p, 0);
			if ((p != NULL) && (*p == '\0') && tmp > 0) {
				timeout = tmp;
			}
		}
	}

	if (validate_basic(pamh, user_tty, timestampfile) != PAM_SUCCESS)
		return (result);

	sudir = TIMESTAMP_DIR;
	if (validate_dir(sudir) != PAM_SUCCESS)
		return (result);

	(void) strlcpy(timestampdir, timestampfile, MAXPATHLEN);

	if (validate_dir(dirname(timestampdir)) != PAM_SUCCESS)
		return (result);

	/*
	 * check that timestamp file is exist and has right owner
	 * and permissions.
	 */
	if (lstat(timestampfile, &sb) == 0 && sb.st_size != 0) {
		if (!S_ISREG(sb.st_mode)) {
			(void) unlink(timestampfile);
			syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
			    "timestamp file %s is not a regular file",
			    timestampfile);
			return (result);
		}

		if (sb.st_uid != 0 || sb.st_gid != 0) {
			(void) unlink(timestampfile);
			syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
			    "timestamp file %s is not owned by root",
			    timestampfile);
			return (result);
		}

		if (sb.st_nlink != 1 || S_ISLNK(sb.st_mode)) {
			(void) unlink(timestampfile);
			syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
			    "timestamp file %s is a symbolic link",
			    timestampfile);
			return (result);
		}

		if (sb.st_mode & (S_IRWXG | S_IRWXO)) {
			(void) unlink(timestampfile);
			syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
			    "timestamp file %s has wrong permissions",
			    timestampfile);
			return (result);
		}
	} else {
		if (debug)
			syslog(LOG_AUTH | LOG_DEBUG, "pam_timestamp: "
			    "timestamp file %s does not exist: %m",
			    timestampfile);
		return (result);
	}


	if (stat(user_tty, &tty) < 0) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "can't stat tty: %m");
		return (result);
	}

	if ((fd = open(timestampfile, O_RDONLY)) < 0) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "can't open timestamp file %s for reading: %m",
		    timestampfile);
		return (result);
	}

	if (read(fd, &info, sizeof (info)) != sizeof (info)) {
		(void) close(fd);
		(void) unlink(timestampfile);
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "timestamp file '%s' is corrupt: %m", timestampfile);
		return (result);
	}

	if (info.dev != tty.st_dev || info.ino != tty.st_ino ||
	    info.rdev != tty.st_rdev || info.sid != getsid(getpid()) ||
	    info.uid != getuid() || info.ts.tv_sec != tty.st_ctim.tv_sec ||
	    info.ts.tv_nsec != tty.st_ctim.tv_nsec) {
		(void) close(fd);
		(void) unlink(timestampfile);
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "the content of the timestamp file '%s' is not valid",
		    timestampfile);
		return (result);
	}

	if (time((time_t *)0) - sb.st_mtime > 60 * timeout) {
		(void) unlink(timestampfile);
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "timestamp file '%s' has expired, disallowing access",
		    timestampfile);
		return (result);
	} else {
		if (debug)
			syslog(LOG_AUTH | LOG_DEBUG, "pam_timestamp: "
			    "timestamp file %s is not expired, "
			    "allowing access ", timestampfile);
		result = PAM_SUCCESS;
	}

	return (result);
}

/*
 * pam_sm_setcred
 *
 * Creates timestamp directory and writes
 * timestamp file if it doesn't exist.
 *
 * returns PAM_SUCCESS on success, otherwise PAM_IGNORE
 */
/*ARGSUSED*/
int
pam_sm_setcred(
	pam_handle_t		*pamh,
	int			flags,
	int			argc,
	const char		**argv)
{
	struct			stat sb;
	struct			stat tty;
	struct			user_info info;
	int			result = PAM_IGNORE;
	int			fd = -1;
	char			user_tty[MAXPATHLEN];
	char			timestampdir[MAXPATHLEN];
	char			timestampfile[MAXPATHLEN];

	/* validate flags */
	if (flags && !(flags & PAM_ESTABLISH_CRED) &&
	    !(flags & PAM_REINITIALIZE_CRED) &&
	    !(flags & PAM_REFRESH_CRED) &&
	    !(flags & PAM_DELETE_CRED) &&
	    !(flags & PAM_SILENT)) {
		syslog(LOG_ERR, "pam_timestamp: illegal flag %d", flags);
		return (result);
	}

	if (validate_basic(pamh, user_tty, timestampfile) != PAM_SUCCESS)
		return (result);

	/*
	 * user doesn't need to authenticate for PAM_DELETE_CRED
	 */
	if (flags & PAM_DELETE_CRED) {
		(void) unlink(timestampfile);
		return (result);
	}

	/* if the timestamp file exist, there is nothing to do */
	if (lstat(timestampfile, &sb) == 0) {
		if (debug)
			syslog(LOG_AUTH | LOG_DEBUG, "pam_timestamp: "
			    "timestamp file %s is not expired", timestampfile);
		return (result);
	}

	if (create_dir(TIMESTAMP_DIR) != PAM_SUCCESS)
		return (result);

	(void) strlcpy(timestampdir, timestampfile, MAXPATHLEN);

	if (create_dir(dirname(timestampdir)) != PAM_SUCCESS)
		return (result);

	if (stat(user_tty, &tty) < 0) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "can't stat tty: %m");
		return (result);
	}

	info.dev = tty.st_dev;
	info.ino = tty.st_ino;
	info.rdev = tty.st_rdev;
	info.sid = getsid(getpid());
	info.uid = getuid();
	info.ts = tty.st_ctim;

	if ((fd = open(timestampfile, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR)) < 0) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "can't open timestamp file %s for writing: %m",
		    timestampfile);
		return (result);
	} else if (fchown(fd, ROOT_UID, ROOT_GID) != 0) {
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "can't set permissions on timestamp file %s: %m",
		    timestampfile);
		(void) close(fd);
		return (result);
	}

	if (write(fd, &info, sizeof (info)) != sizeof (info)) {
		(void) close(fd);
		syslog(LOG_AUTH | LOG_ERR, "pam_timestamp: "
		    "can't write timestamp file %s: %m", timestampfile);
		return (result);
	}
	(void) close(fd);

	return (PAM_SUCCESS);
}
