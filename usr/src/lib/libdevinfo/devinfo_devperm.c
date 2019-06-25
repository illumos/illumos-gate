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
 * Copyright (c) 2011 Gary Mills
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#define	_POSIX_PTHREAD_SEMANTICS	/* for getgrnam_r */
#ifdef lint
#define	_REENTRANT			/* for strtok_r */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <nss_dbdefs.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/acl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/devinfo_impl.h>
#include <sys/hwconf.h>
#include <sys/modctl.h>
#include <libnvpair.h>
#include <device_info.h>
#include <regex.h>
#include <strings.h>
#include <libdevinfo.h>
#include <zone.h>
#include <fcntl.h>
#include <utmpx.h>

extern int is_minor_node(const char *, const char **);

static int is_login_user(uid_t);
static int logindevperm(const char *, uid_t, gid_t, void (*)());
static int dir_dev_acc(char *, char *, uid_t, gid_t, mode_t, char *line,
	void (*)());
static int setdevaccess(char *, uid_t, gid_t, mode_t, void (*)());
static void logerror(char *);

static int is_blank(char *);

#define	MAX_LINELEN	256
#define	LOGINDEVPERM	"/etc/logindevperm"
#define	DIRWILD		"/*"			/* directory wildcard */
#define	DIRWLDLEN	2			/* strlen(DIRWILD) */

/*
 * Revoke all access to a device node and make sure that there are
 * no interposed streams devices attached.  Must be called before a
 * device is actually opened.
 * When fdetach is called, the underlying device node is revealed; it
 * will have the previous owner and that owner can re-attach; so we
 * retry until we win.
 * Ignore non-existent devices.
 */
static int
setdevaccess(char *dev, uid_t uid, gid_t gid, mode_t mode,
    void (*errmsg)(char *))
{
	int err = 0, local_errno;
	char errstring[MAX_LINELEN];
	struct stat st;

	if (chown(dev, uid, gid) == -1) {
		if (errno == ENOENT)	/* no such file */
			return (0);
		err = -1;
		local_errno = errno;
	}

	/*
	 * don't fdetach block devices, as it will unmount them
	 */
	if (!((stat(dev, &st) == 0) && ((st.st_mode & S_IFMT) == S_IFBLK))) {
		while (fdetach(dev) == 0) {
			if (chown(dev, uid, gid) == -1) {
				err = -1;
				local_errno = errno;
			}
		}
		if (err && errmsg) {
			(void) snprintf(errstring, MAX_LINELEN,
			    "failed to chown device %s: %s\n",
			    dev, strerror(local_errno));
			(*errmsg)(errstring);
		}
	}

	/*
	 * strip_acl sets an acl and changes the files owner/group
	 */
	err = acl_strip(dev, uid, gid, mode);

	if (err != 0) {
		/*
		 * If the file system returned ENOSYS, we know that it
		 * doesn't support ACLs, therefore, we must assume that
		 * there were no ACLs to remove in the first place.
		 */
		err = 0;
		if (errno != ENOSYS) {
			err = -1;

			if (errmsg) {
				(void) snprintf(errstring, MAX_LINELEN,
				    "failed to set acl on device %s: %s\n",
				    dev, strerror(errno));
				(*errmsg)(errstring);
			}
		}
		if (chmod(dev, mode) == -1) {
			err = -1;
			if (errmsg) {
				(void) snprintf(errstring, MAX_LINELEN,
				    "failed to chmod device %s: %s\n",
				    dev, strerror(errno));
				(*errmsg)(errstring);
			}
		}
	}

	return (err);
}

/*
 * logindevperm - change owner/group/permissions of devices
 * list in /etc/logindevperm.
 */
static int
logindevperm(const char *ttyn, uid_t uid, gid_t gid, void (*errmsg)(char *))
{
	int err = 0, lineno = 0;
	const char *field_delims = " \t\n";
	char line[MAX_LINELEN], errstring[MAX_LINELEN];
	char saveline[MAX_LINELEN];
	char *console;
	char *mode_str;
	char *dev_list;
	char *device;
	char *ptr;
	int mode;
	FILE *fp;
	char ttyn_path[PATH_MAX + 1];
	int n;

	if ((fp = fopen(LOGINDEVPERM, "r")) == NULL) {
		if (errmsg) {
			(void) snprintf(errstring, MAX_LINELEN,
			    LOGINDEVPERM ": open failed: %s\n",
			    strerror(errno));
			(*errmsg)(errstring);
		}
		return (-1);
	}

	if ((n = resolvepath(ttyn, ttyn_path, PATH_MAX)) == -1)
		return (-1);
	ttyn_path[n] = '\0';

	while (fgets(line, MAX_LINELEN, fp) != NULL) {
		char *last;
		char tmp[PATH_MAX + 1];

		lineno++;

		if ((ptr = strchr(line, '#')) != NULL)
			*ptr = '\0';	/* handle comments */

		(void) strcpy(saveline, line);

		console = strtok_r(line, field_delims, &last);
		if (console == NULL)
			continue;	/* ignore blank lines */

		if ((n = resolvepath(console, tmp, PATH_MAX)) == -1)
			continue;
		tmp[n] = '\0';

		if (strcmp(ttyn_path, tmp) != 0)
			continue;

		mode_str = strtok_r(last, field_delims, &last);
		if (mode_str == NULL) {
			err = -1;	/* invalid entry, skip */
			if (errmsg) {
				(void) snprintf(errstring, MAX_LINELEN,
				    LOGINDEVPERM
				    ": line %d, invalid entry -- %s\n",
				    lineno, line);
				(*errmsg)(errstring);
			}
			continue;
		}

		/* convert string to octal value */
		mode = strtol(mode_str, &ptr, 8);
		if (mode < 0 || mode > 0777 || *ptr != '\0') {
			err = -1;	/* invalid mode, skip */
			if (errmsg) {
				(void) snprintf(errstring, MAX_LINELEN,
				    LOGINDEVPERM
				    ": line %d, invalid mode -- %s\n",
				    lineno, mode_str);
				(*errmsg)(errstring);
			}
			continue;
		}

		dev_list = strtok_r(last, field_delims, &last);
		if (dev_list == NULL) {
			err = -1;	/* empty device list, skip */
			if (errmsg) {
				(void) snprintf(errstring, MAX_LINELEN,
				    LOGINDEVPERM
				    ": line %d, empty device list -- %s\n",
				    lineno, line);
				(*errmsg)(errstring);
			}
			continue;
		}

		device = strtok_r(dev_list, ":", &last);
		while (device != NULL) {
			if ((device[0] != '/') || (strlen(device) <= 1))  {
				err = -1;
			} else if (dir_dev_acc("/", &device[1], uid, gid, mode,
			    saveline, errmsg)) {
				err = -1;
			}
			device = strtok_r(last, ":", &last);
		}
	}
	(void) fclose(fp);
	return (err);
}

/*
 * returns 0 if resolved, -1 otherwise.
 * devpath: Absolute path to /dev link
 * devfs_path: Returns malloced string: /devices path w/out "/devices"
 */
int
devfs_resolve_link(char *devpath, char **devfs_path)
{
	char contents[PATH_MAX + 1];
	char stage_link[PATH_MAX + 1];
	char *ptr;
	int linksize;
	char *slashdev = "/dev/";

	if (devfs_path) {
		*devfs_path = NULL;
	}

	linksize = readlink(devpath, contents, PATH_MAX);

	if (linksize <= 0) {
		return (-1);
	} else {
		contents[linksize] = '\0';
	}

	/*
	 * if the link contents is not a minor node assume
	 * that link contents is really a pointer to another
	 * link, and if so recurse and read its link contents.
	 */
	if (is_minor_node((const char *)contents, (const char **)&ptr) !=
	    1) {
		if (strncmp(contents, slashdev, strlen(slashdev)) == 0)  {
			/* absolute path, starting with /dev */
			(void) strcpy(stage_link, contents);
		} else {
			/* relative path, prefix devpath */
			if ((ptr = strrchr(devpath, '/')) == NULL) {
				/* invalid link */
				return (-1);
			}
			*ptr = '\0';
			(void) strcpy(stage_link, devpath);
			*ptr = '/';
			(void) strcat(stage_link, "/");
			(void) strcat(stage_link, contents);

		}
		return (devfs_resolve_link(stage_link, devfs_path));
	}

	if (devfs_path) {
		*devfs_path = strdup(ptr);
		if (*devfs_path == NULL) {
			return (-1);
		}
	}

	return (0);
}

/*
 * check a logindevperm line for a driver list and match this against
 * the driver of the minor node
 * returns 0 if no drivers were specified or a driver match
 */
static int
check_driver_match(char *path, char *line)
{
	char *drv, *driver, *lasts;
	char *devfs_path = NULL;
	char saveline[MAX_LINELEN];
	char *p;

	if (devfs_resolve_link(path, &devfs_path) == 0) {
		char *p;
		char pwd_buf[PATH_MAX];
		di_node_t node;

		/* truncate on : so we can take a snapshot */
		(void) strcpy(pwd_buf, devfs_path);
		p = strrchr(pwd_buf, ':');
		*p = '\0';

		node = di_init(pwd_buf, DINFOMINOR);
		free(devfs_path);

		if (node) {
			drv = di_driver_name(node);
			di_fini(node);
		} else {
			return (0);
		}
	} else {
		return (0);
	}

	(void) strcpy(saveline, line);

	p = strstr(saveline, "driver");
	if (p == NULL) {
		return (0);
	}

	driver = strtok_r(p, "=", &lasts);
	if (driver) {
		if (strcmp(driver, "driver") == 0) {
			driver = strtok_r(NULL, ", \t\n", &lasts);
			while (driver) {
				if (strcmp(driver, drv) == 0) {
					return (0);
				}
				driver = strtok_r(NULL, ", \t\n", &lasts);
			}
		}
	}

	return (-1);
}

/*
 * Check whether the user has logged onto "/dev/console" or "/dev/vt/#".
 */
static int
is_login_user(uid_t uid)
{
	int changed = 0;
	struct passwd pwd, *ppwd;
	char pwd_buf[NSS_BUFLEN_PASSWD];
	struct utmpx *utx;

	if ((getpwuid_r(uid, &pwd, pwd_buf, NSS_BUFLEN_PASSWD, &ppwd) != 0) ||
	    (ppwd == NULL)) {
		return (0);
	}

	setutxent();
	while ((utx = getutxent()) != NULL) {
		if (utx->ut_type == USER_PROCESS &&
		    strncmp(utx->ut_user, ppwd->pw_name,
		    strlen(ppwd->pw_name)) == 0 && (strncmp(utx->ut_line,
		    "console", strlen("console")) == 0 || strncmp(utx->ut_line,
		    "vt", strlen("vt")) == 0)) {

			changed = 1;
			break;
		}
	}
	endutxent();

	return (changed);
}

/*
 * Apply owner/group/perms to all files (except "." and "..")
 * in a directory.
 * This function is recursive. We start with "/" and the rest of the pathname
 * in left_to_do argument, and we walk the entire pathname which may contain
 * regular expressions or '*' for each directory name or basename.
 */
static int
dir_dev_acc(char *path, char *left_to_do, uid_t uid, gid_t gid, mode_t mode,
    char *line, void (*errmsg)(char *))
{
	struct stat stat_buf;
	int err = 0;
	char errstring[MAX_LINELEN];
	char *p;
	regex_t regex;
	int alwaysmatch = 0;
	char *match;
	char *name, *newpath, *remainder_path;
	finddevhdl_t handle;

	/*
	 * Determine if the search needs to be performed via finddev,
	 * which returns only persisted names in the global /dev, or
	 * readdir, for paths other than /dev and non-global zones.
	 * This use of finddev avoids triggering potential implicit
	 * reconfig for names managed by logindevperm but not present
	 * on the system.
	 */
	if (!device_exists(path)) {
		return (-1);
	}
	if (stat(path, &stat_buf) == -1) {
		/*
		 * ENOENT errors are expected errors when there are
		 * dangling /dev device links. Ignore them silently
		 */
		if (errno == ENOENT) {
			return (0);
		}
		if (errmsg) {
			(void) snprintf(errstring, MAX_LINELEN,
			    "failed to stat %s: %s\n", path,
			    strerror(errno));
			(*errmsg)(errstring);
		}
		return (-1);
	} else {
		if (!S_ISDIR(stat_buf.st_mode)) {
			if (strlen(left_to_do) == 0) {
				/* finally check the driver matches */
				if (check_driver_match(path, line) == 0) {
					/*
					 * if the owner of device has been
					 * login, the ownership and mode
					 * should be set already. in
					 * this case, do not set the
					 * permissions.
					 */
					if (is_login_user(stat_buf.st_uid)) {

						return (0);
					}
					/* we are done, set the permissions */
					if (setdevaccess(path,
					    uid, gid, mode, errmsg)) {

						return (-1);
					}
				}
			}
			return (0);
		}
	}

	if (finddev_readdir(path, &handle) != 0)
		return (0);

	p = strchr(left_to_do, '/');
	alwaysmatch = 0;

	newpath = (char *)malloc(MAXPATHLEN);
	if (newpath == NULL) {
		finddev_close(handle);
		return (-1);
	}
	match = (char *)calloc(MAXPATHLEN + 2, 1);
	if (match == NULL) {
		finddev_close(handle);
		free(newpath);
		return (-1);
	}

	/* transform pattern into ^pattern$ for exact match */
	if (snprintf(match, MAXPATHLEN + 2, "^%.*s$",
	    p ? (p - left_to_do) : strlen(left_to_do), left_to_do) >=
	    MAXPATHLEN + 2) {
		finddev_close(handle);
		free(newpath);
		free(match);
		return (-1);
	}

	if (strcmp(match, "^*$") == 0) {
		alwaysmatch = 1;
	} else {
		if (regcomp(&regex, match, REG_EXTENDED) != 0) {
			free(newpath);
			free(match);
			finddev_close(handle);
			return (-1);
		}
	}

	while ((name = (char *)finddev_next(handle)) != NULL) {
		if (alwaysmatch ||
		    regexec(&regex, name, 0, NULL, 0) == 0) {
			if (strcmp(path, "/") == 0) {
				(void) snprintf(newpath,
				    MAXPATHLEN, "%s%s", path, name);
			} else {
				(void) snprintf(newpath,
				    MAXPATHLEN, "%s/%s", path, name);
			}

			/*
			 * recurse but adjust what is still left to do
			 */
			remainder_path = (p ?
			    left_to_do + (p - left_to_do) + 1 :
			    &left_to_do[strlen(left_to_do)]);
			if (dir_dev_acc(newpath, remainder_path,
			    uid, gid, mode, line, errmsg)) {
				err = -1;
			}
		}
	}

	finddev_close(handle);
	free(newpath);
	free(match);
	if (!alwaysmatch) {
		regfree(&regex);
	}

	return (err);
}

/*
 * di_devperm_login - modify access of devices in /etc/logindevperm
 * by changing owner/group/permissions to that of ttyn.
 */
int
di_devperm_login(const char *ttyn, uid_t uid, gid_t gid,
    void (*errmsg)(char *))
{
	int err;
	struct group grp, *grpp;
	gid_t tty_gid;
	char grbuf[NSS_BUFLEN_GROUP];

	if (errmsg == NULL)
		errmsg = logerror;

	if (ttyn == NULL) {
		(*errmsg)("di_devperm_login: NULL tty device\n");
		return (-1);
	}

	if (getgrnam_r("tty", &grp, grbuf, NSS_BUFLEN_GROUP, &grpp) != 0) {
		tty_gid = grpp->gr_gid;
	} else {
		/*
		 * this should never happen, but if it does set
		 * group to tty's traditional value.
		 */
		tty_gid = 7;
	}

	/* set the login console device permission */
	err = setdevaccess((char *)ttyn, uid, tty_gid,
	    S_IRUSR|S_IWUSR|S_IWGRP, errmsg);
	if (err) {
		return (err);
	}

	/* set the device permissions */
	return (logindevperm(ttyn, uid, gid, errmsg));
}

/*
 * di_devperm_logout - clean up access of devices in /etc/logindevperm
 * by resetting owner/group/permissions.
 */
int
di_devperm_logout(const char *ttyn)
{
	struct passwd *pwd;
	uid_t root_uid;
	gid_t root_gid;

	if (ttyn == NULL)
		return (-1);

	pwd = getpwnam("root");
	if (pwd != NULL) {
		root_uid = pwd->pw_uid;
		root_gid = pwd->pw_gid;
	} else {
		/*
		 * this should never happen, but if it does set user
		 * and group to root's traditional values.
		 */
		root_uid = 0;
		root_gid = 0;
	}

	return (logindevperm(ttyn, root_uid, root_gid, NULL));
}

static void
logerror(char *errstring)
{
	syslog(LOG_AUTH | LOG_CRIT, "%s", errstring);
}


/*
 * Tokens are separated by ' ', '\t', ':', '=', '&', '|', ';', '\n', or '\0'
 */
static int
getnexttoken(char *next, char **nextp, char **tokenpp, char *tchar)
{
	char *cp;
	char *cp1;
	char *tokenp;

	cp = next;
	while (*cp == ' ' || *cp == '\t') {
		cp++;			/* skip leading spaces */
	}
	tokenp = cp;			/* start of token */
	while (*cp != '\0' && *cp != '\n' && *cp != ' ' && *cp != '\t' &&
	    *cp != ':' && *cp != '=' && *cp != '&' &&
	    *cp != '|' && *cp != ';') {
		cp++;			/* point to next character */
	}
	/*
	 * If terminating character is a space or tab, look ahead to see if
	 * there's another terminator that's not a space or a tab.
	 * (This code handles trailing spaces.)
	 */
	if (*cp == ' ' || *cp == '\t') {
		cp1 = cp;
		while (*++cp1 == ' ' || *cp1 == '\t')
			;
		if (*cp1 == '=' || *cp1 == ':' || *cp1 == '&' || *cp1 == '|' ||
		    *cp1 == ';' || *cp1 == '\n' || *cp1 == '\0') {
			*cp = '\0';	/* terminate token */
			cp = cp1;
		}
	}
	if (tchar != NULL) {
		*tchar = *cp;		/* save terminating character */
		if (*tchar == '\0') {
			*tchar = '\n';
		}
	}
	*cp++ = '\0';			/* terminate token, point to next */
	*nextp = cp;			/* set pointer to next character */
	if (cp - tokenp - 1 == 0) {
		return (0);
	}
	*tokenpp = tokenp;
	return (1);
}

/*
 * get a decimal octal or hex number. Handle '~' for one's complement.
 */
static int
getvalue(char *token, int *valuep)
{
	int radix;
	int retval = 0;
	int onescompl = 0;
	int negate = 0;
	char c;

	if (*token == '~') {
		onescompl++; /* perform one's complement on result */
		token++;
	} else if (*token == '-') {
		negate++;
		token++;
	}
	if (*token == '0') {
		token++;
		c = *token;

		if (c == '\0') {
			*valuep = 0;	/* value is 0 */
			return (0);
		}

		if (c == 'x' || c == 'X') {
			radix = 16;
			token++;
		} else {
			radix = 8;
		}
	} else
		radix = 10;

	while ((c = *token++)) {
		switch (radix) {
		case 8:
			if (c >= '0' && c <= '7') {
				c -= '0';
			} else {
				/* invalid number */
				return (0);
			}
			retval = (retval << 3) + c;
			break;
		case 10:
			if (c >= '0' && c <= '9') {
				c -= '0';
			} else {
				/* invalid number */
				return (0);
			}
			retval = (retval * 10) + c;
			break;
		case 16:
			if (c >= 'a' && c <= 'f') {
				c = c - 'a' + 10;
			} else if (c >= 'A' && c <= 'F') {
				c = c - 'A' + 10;
			} else if (c >= '0' && c <= '9') {
				c -= '0';
			} else {
				/* invalid number */
				return (0);
			}
			retval = (retval << 4) + c;
			break;
		}
	}
	if (onescompl) {
		retval = ~retval;
	}
	if (negate) {
		retval = -retval;
	}
	*valuep = retval;
	return (1);
}

/*
 * Read /etc/minor_perm, return mperm list of entries
 */
struct mperm *
i_devfs_read_minor_perm(char *drvname, void (*errcb)(minorperm_err_t, int))
{
	FILE *pfd;
	struct mperm *mp;
	char line[MAX_MINOR_PERM_LINE];
	char *cp, *p, t;
	struct mperm *minor_perms = NULL;
	struct mperm *mptail = NULL;
	struct passwd *pw;
	struct group *gp;
	uid_t root_uid;
	gid_t sys_gid;
	int ln = 0;

	/*
	 * Get root/sys ids, these being the most common
	 */
	if ((pw = getpwnam(DEFAULT_DEV_USER)) != NULL) {
		root_uid = pw->pw_uid;
	} else {
		(*errcb)(MP_CANT_FIND_USER_ERR, 0);
		root_uid = (uid_t)0;	/* assume 0 is root */
	}
	if ((gp = getgrnam(DEFAULT_DEV_GROUP)) != NULL) {
		sys_gid = gp->gr_gid;
	} else {
		(*errcb)(MP_CANT_FIND_GROUP_ERR, 0);
		sys_gid = (gid_t)3;	/* assume 3 is sys */
	}

	if ((pfd = fopen(MINOR_PERM_FILE, "r")) == NULL) {
		(*errcb)(MP_FOPEN_ERR, errno);
		return (NULL);
	}
	while (fgets(line, MAX_MINOR_PERM_LINE, pfd) != NULL) {
		ln++;
		/* cut off comments starting with '#' */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(line))
			continue;
		mp = (struct mperm *)calloc(1, sizeof (struct mperm));
		if (mp == NULL) {
			(*errcb)(MP_ALLOC_ERR, sizeof (struct mperm));
			continue;
		}
		cp = line;
		/* sanity-check */
		if (getnexttoken(cp, &cp, &p, &t) == 0) {
			(*errcb)(MP_IGNORING_LINE_ERR, ln);
			devfs_free_minor_perm(mp);
			continue;
		}
		mp->mp_drvname = strdup(p);
		if (mp->mp_drvname == NULL) {
			(*errcb)(MP_ALLOC_ERR, strlen(p)+1);
			devfs_free_minor_perm(mp);
			continue;
		} else if (t == '\n' || t == '\0') {
			(*errcb)(MP_IGNORING_LINE_ERR, ln);
			devfs_free_minor_perm(mp);
			continue;
		}
		if (t == ':') {
			if (getnexttoken(cp, &cp, &p, &t) == 0) {
				(*errcb)(MP_IGNORING_LINE_ERR, ln);
				devfs_free_minor_perm(mp);
			}
			mp->mp_minorname = strdup(p);
			if (mp->mp_minorname == NULL) {
				(*errcb)(MP_ALLOC_ERR, strlen(p)+1);
				devfs_free_minor_perm(mp);
				continue;
			}
		} else {
			mp->mp_minorname = NULL;
		}

		if (t == '\n' || t == '\0') {
			devfs_free_minor_perm(mp);
			(*errcb)(MP_IGNORING_LINE_ERR, ln);
			continue;
		}
		if (getnexttoken(cp, &cp, &p, &t) == 0) {
			goto link;
		}
		if (getvalue(p, (int *)&mp->mp_mode) == 0) {
			goto link;
		}
		if (t == '\n' || t == '\0') {	/* no owner or group */
			goto link;
		}
		if (getnexttoken(cp, &cp, &p, &t) == 0) {
			goto link;
		}
		mp->mp_owner = strdup(p);
		if (mp->mp_owner == NULL) {
			(*errcb)(MP_ALLOC_ERR, strlen(p)+1);
			devfs_free_minor_perm(mp);
			continue;
		} else if (t == '\n' || t == '\0') {	/* no group */
			goto link;
		}
		if (getnexttoken(cp, &cp, &p, 0) == 0) {
			goto link;
		}
		mp->mp_group = strdup(p);
		if (mp->mp_group == NULL) {
			(*errcb)(MP_ALLOC_ERR, strlen(p)+1);
			devfs_free_minor_perm(mp);
			continue;
		}
link:
		if (drvname != NULL) {
			/*
			 * We only want the minor perm entry for a
			 * the named driver.  The driver name is the
			 * minor in the clone case.
			 */
			if (strcmp(mp->mp_drvname, "clone") == 0) {
				if (mp->mp_minorname == NULL ||
				    strcmp(drvname, mp->mp_minorname) != 0) {
					devfs_free_minor_perm(mp);
					continue;
				}
			} else {
				if (strcmp(drvname, mp->mp_drvname) != 0) {
					devfs_free_minor_perm(mp);
					continue;
				}
			}
		}
		if (minor_perms == NULL) {
			minor_perms = mp;
		} else {
			mptail->mp_next = mp;
		}
		mptail = mp;

		/*
		 * Compute the uid's and gid's here - there are
		 * fewer lines in the /etc/minor_perm file than there
		 * are devices to be stat(2)ed.  And almost every
		 * device is 'root sys'.  See 1135520.
		 */
		if (mp->mp_owner == NULL ||
		    strcmp(mp->mp_owner, DEFAULT_DEV_USER) == 0 ||
		    (pw = getpwnam(mp->mp_owner)) == NULL) {
			mp->mp_uid = root_uid;
		} else {
			mp->mp_uid = pw->pw_uid;
		}

		if (mp->mp_group == NULL ||
		    strcmp(mp->mp_group, DEFAULT_DEV_GROUP) == 0 ||
		    (gp = getgrnam(mp->mp_group)) == NULL) {
			mp->mp_gid = sys_gid;
		} else {
			mp->mp_gid = gp->gr_gid;
		}
	}

	if (fclose(pfd) == EOF) {
		(*errcb)(MP_FCLOSE_ERR, errno);
	}

	return (minor_perms);
}

struct mperm *
devfs_read_minor_perm(void (*errcb)(minorperm_err_t, int))
{
	return (i_devfs_read_minor_perm(NULL, errcb));
}

static struct mperm *
i_devfs_read_minor_perm_by_driver(char *drvname,
    void (*errcb)(minorperm_err_t mp_err, int key))
{
	return (i_devfs_read_minor_perm(drvname, errcb));
}

/*
 * Free mperm list of entries
 */
void
devfs_free_minor_perm(struct mperm *mplist)
{
	struct mperm *mp, *next;

	for (mp = mplist; mp != NULL; mp = next) {
		next = mp->mp_next;

		if (mp->mp_drvname)
			free(mp->mp_drvname);
		if (mp->mp_minorname)
			free(mp->mp_minorname);
		if (mp->mp_owner)
			free(mp->mp_owner);
		if (mp->mp_group)
			free(mp->mp_group);
		free(mp);
	}
}

static int
i_devfs_add_perm_entry(nvlist_t *nvl, struct mperm *mp)
{
	int err;

	err = nvlist_add_string(nvl, mp->mp_drvname, mp->mp_minorname);
	if (err != 0)
		return (err);

	err = nvlist_add_int32(nvl, "mode", (int32_t)mp->mp_mode);
	if (err != 0)
		return (err);

	err = nvlist_add_uint32(nvl, "uid", mp->mp_uid);
	if (err != 0)
		return (err);

	err = nvlist_add_uint32(nvl, "gid", mp->mp_gid);
	return (err);
}

static nvlist_t *
i_devfs_minor_perm_nvlist(struct mperm *mplist,
    void (*errcb)(minorperm_err_t, int))
{
	int err;
	struct mperm *mp;
	nvlist_t *nvl = NULL;

	if ((err = nvlist_alloc(&nvl, 0, 0)) != 0) {
		(*errcb)(MP_NVLIST_ERR, err);
		return (NULL);
	}

	for (mp = mplist; mp != NULL; mp = mp->mp_next) {
		if ((err = i_devfs_add_perm_entry(nvl, mp)) != 0) {
			(*errcb)(MP_NVLIST_ERR, err);
			nvlist_free(nvl);
			return (NULL);
		}
	}

	return (nvl);
}

/*
 * Load all minor perm entries into the kernel
 * Done at boot time via devfsadm
 */
int
devfs_load_minor_perm(struct mperm *mplist, void (*errcb)(minorperm_err_t, int))
{
	int err;
	char *buf = NULL;
	size_t buflen;
	nvlist_t *nvl;

	nvl = i_devfs_minor_perm_nvlist(mplist, errcb);
	if (nvl == NULL)
		return (-1);

	if (nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_NATIVE, 0) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

	err = modctl(MODLOADMINORPERM, buf, buflen);
	nvlist_free(nvl);
	free(buf);

	return (err);
}

/*
 * Add/remove minor perm entry for a driver
 */
static int
i_devfs_update_minor_perm(char *drv, int ctl,
    void (*errcb)(minorperm_err_t, int))
{
	int err;
	char *buf;
	size_t buflen;
	nvlist_t *nvl;
	struct mperm *mplist;

	mplist = i_devfs_read_minor_perm_by_driver(drv, errcb);

	nvl = i_devfs_minor_perm_nvlist(mplist, errcb);
	if (nvl == NULL)
		return (-1);

	buf = NULL;
	if (nvlist_pack(nvl, &buf, &buflen, NV_ENCODE_NATIVE, 0) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

	err = modctl(ctl, buf, buflen);
	nvlist_free(nvl);
	devfs_free_minor_perm(mplist);
	free(buf);

	return (err);
}

int
devfs_add_minor_perm(char *drv, void (*errcb)(minorperm_err_t, int))
{
	return (i_devfs_update_minor_perm(drv, MODADDMINORPERM, errcb));
}

int
devfs_rm_minor_perm(char *drv, void (*errcb)(minorperm_err_t, int))
{
	return (i_devfs_update_minor_perm(drv, MODREMMINORPERM, errcb));
}

/*
 * is_blank() returns 1 (true) if a line specified is composed of
 * whitespace characters only. otherwise, it returns 0 (false).
 *
 * Note. the argument (line) must be null-terminated.
 */
static int
is_blank(char *line)
{
	for (/* nothing */; *line != '\0'; line++)
		if (!isspace(*line))
			return (0);
	return (1);
}
