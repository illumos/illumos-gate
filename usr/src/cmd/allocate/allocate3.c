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
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <auth_attr.h>
#include <auth_list.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bsm/devices.h>
#include <bsm/audit_uevents.h>

#include <sys/acl.h>
#include <sys/file.h>
#include <sys/procfs.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "allocate.h"

#ifdef	DEBUG
#define	dprintf(s, a) (void) fprintf(stderr, s, a)
#define	dperror(s) perror(s)
#else	/* !DEBUG */
#define	dprintf(s, a)
#define	dperror(s)
#endif	/* DEBUG */

#define	EXIT(number) { \
	if (optflg & FORCE) \
		error = number; \
	else \
		return (number); \
}

#define	DEV_ALLOCATED(sbuf)	((sbuf).st_uid != ALLOC_UID || \
				((sbuf).st_mode & ~S_IFMT) == ALLOC_MODE)

#define	DEVICE_AUTH_SEPARATOR	","
#define	PROCFS	"/proc/"

extern void audit_allocate_list(char *);
extern void audit_allocate_device(char *);

extern char	*newenv[];

/*
 * Checks if the specified user has any of the authorizations in the
 * list of authorizations
 */

static int
is_authorized(char *auth_list, uid_t uid)
{
	char	*auth;
	struct passwd *pw;

	pw = getpwuid(uid);
	if (pw == NULL) {
		dprintf("Can't get user info for uid=%d\n", (int)uid);
		return (0);
	}

	auth = strtok(auth_list, DEVICE_AUTH_SEPARATOR);
	while (auth != NULL) {
		if (chkauthattr(auth, pw->pw_name))
			return (1);
		auth = strtok(NULL, DEVICE_AUTH_SEPARATOR);
	}
	return (0);
}

static int
check_devs(char *list)
{
	char	*file;

	file = strtok(list, " ");
	while (file != NULL) {

		if (access(file, F_OK) == -1) {
			dprintf("Unable to access file %s\n", file);
			return (-1);
		}
		file = strtok(NULL, " ");
	}
	return (0);
}

static void
print_dev(devmap_t *dev_list)
{
	char	*file;

	(void) printf(gettext("device: %s "), dev_list->dmap_devname);
	(void) printf(gettext("type: %s "), dev_list->dmap_devtype);
	(void) printf(gettext("files: "));

	file = strtok(dev_list->dmap_devlist, " ");
	while (file != NULL) {
		(void) printf("%s ", file);
		file = strtok(NULL, " ");
	}
	(void) printf("\n");
}

static int
list_device(int optflg, uid_t uid, char *device)
{
	devalloc_t *dev_ent;
	devmap_t *dev_list;
	char	file_name[MAXPATHLEN];
	struct	stat stat_buf;
	char	*list;
	int	bytes_formated;

	if ((dev_ent = getdanam(device)) == NULL) {
		if ((dev_list = getdmapdev(device)) == NULL) {
			dprintf("Unable to find %s in the allocate database\n",
			    device);
			return (NODMAPENT);
		} else if ((dev_ent = getdanam(dev_list->dmap_devname)) ==
		    NULL) {
			dprintf("Unable to find %s in the allocate database\n",
			    device);
			return (NODAENT);
		}
	} else if ((dev_list = getdmapnam(device)) == NULL) {
		dprintf("Unable to find %s in the allocate database\n", device);
		return (NODMAPENT);
	}

	bytes_formated = snprintf(file_name, MAXPATHLEN, "%s/%s", DAC_DIR,
	    dev_ent->da_devname);
	if (bytes_formated <= 0) {
		return (DEVNAME_ERR);
	} else if (bytes_formated >= MAXPATHLEN) {
		dprintf("device name %s is too long.\n", dev_ent->da_devname);
		return (DEVNAME_TOOLONG);
	}

	if (stat(file_name, &stat_buf)) {
		dprintf("Unable to stat %s\n", file_name);
		dperror("Error:");
		return (DACACC);
	}

	if ((optflg & FREE) && DEV_ALLOCATED(stat_buf))
		return (ALLOC);

	if ((optflg & LIST) && DEV_ALLOCATED(stat_buf) &&
	    (stat_buf.st_uid != uid))
		return (ALLOC_OTHER);

	if ((optflg & CURRENT) && (stat_buf.st_uid != uid))
		return (NALLOC);

	if ((stat_buf.st_mode & ~S_IFMT) == ALLOC_ERR_MODE)
		return (ALLOCERR);

	if ((list = strdup(dev_list->dmap_devlist)) == NULL)
		return (SYSERROR);

	if (check_devs(list) == -1) {
		free(list);
		return (DSPMISS);
	}

	print_dev(dev_list);

	free(list);
	return (0);
}

int
list_devices(int optflg, uid_t uid, char *device)
{
	DIR   * dev_dir;
	struct dirent *dac_file;
	int	error = 0, ret_code = 1;

	if (optflg & USERID) {
		if (!is_authorized(DEVICE_REVOKE_AUTH, getuid()))
			return (NOTAUTH);
	}
	setdaent();

	if (device) {
		return (list_device(optflg, uid, device));
	}

	if ((dev_dir = opendir(DAC_DIR)) == NULL) {

		dperror("Can't open DAC_DIR");
		return (DACACC);
	}

	while ((dac_file = readdir(dev_dir)) != NULL) {
		if ((strcmp(dac_file->d_name, ".") == 0) ||
		    (strcmp(dac_file->d_name, "..") == 0)) {
			continue;
		} else {
			error = list_device(optflg, uid, dac_file->d_name);
			ret_code = ret_code ? error : ret_code;
		}
	}
	(void) closedir(dev_dir);
	enddaent();
	return (ret_code);
}

/*
 * Set the DAC characteristics of the file.
 * This uses a fancy chmod() by setting a minimal ACL which sets the mode
 * and discards any existing ACL.
 */

static int
newdac(char *file, uid_t owner, gid_t group, o_mode_t mode)
{
	int		err = 0;

	do {
		if (chown(file, owner, group) == -1) {
			dperror("newdac, unable to chown");
			err = CHOWN_PERR;
		}
	} while (fdetach(file) == 0);

	err = acl_strip(file, owner, group, (mode_t)mode);

	if (err != 0) {
		dperror("newdac, unable to setacl");
		err = SETACL_PERR;
	}

	return (err);
}

static int
lock_dev(char *file)
{
	int	fd;

	dprintf("locking %s\n", file);
	if ((fd = open(file, O_RDWR)) == -1) {
		dperror("lock_dev, cannot open DAC file");
		return (DACACC);
	}

	if (lockf(fd, F_TLOCK, 0) == -1) {
		dperror("lock_dev, cannot set lock");
		return (DACLCK);
	}

	return (0);
}

static int
mk_alloc(char *list, uid_t uid)
{
	char	*file;
	int	err;

	file = strtok(list, " ");
	while (file != NULL) {

		dprintf("Allocating %s\n", file);
		if ((err = newdac(file, uid, getgid(), ALLOC_MODE)) != 0) {
			(void) newdac(file, ALLOC_UID, ALLOC_GID,
			    ALLOC_ERR_MODE);
			return (err);
		}

		file = strtok(NULL, " ");
	}
	return (0);
}

/*
 * mk_revoke() is used instead of system("/usr/sbin/fuser -k file")
 * because "/usr/sbin/fuser -k file" kills all processes
 * working with the file, even "vold" (bug #4095152).
 */
static int
mk_revoke(int optflg, char *file)
{
	char buf[MAXPATHLEN];
	int r = 0, p[2], fp, lock;
	FILE *ptr;
	prpsinfo_t info;
	pid_t pid, c_pid;

	(void) strcpy(buf, PROCFS);

	/*
	 * vfork() and execle() just to make the same output
	 * as before fixing of bug #4095152.
	 * The problem is that the "fuser" command prints
	 * one part of output into stderr and another into stdout,
	 * but user sees them mixed. Of course, better to change "fuser"
	 * or to intercept and not to print its output.
	 */
	if (!(optflg & SILENT)) {
		c_pid = vfork();
		if (c_pid == -1)
			return (-1);
		if (c_pid == 0) {
			dprintf("first exec fuser %s\n", file);
			(void) execle("/usr/sbin/fuser", "fuser", file, NULL,
			    newenv);
			dperror("first exec fuser");
			_exit(1);
		}

		(void) waitpid(c_pid, &lock, 0);
		dprintf("exit status %x\n", lock);
		if (WEXITSTATUS(lock) != 0)
			return (-1);
	}
	dprintf("first continuing c_pid=%d\n", c_pid);

	if (pipe(p)) {
		dperror("pipe");
		return (-1);
	}

	/* vfork() and execle() to catch output and to process it */
	c_pid = vfork();
	if (c_pid == -1) {
		dperror("second vfork");
		return (-1);
	}
	dprintf("second continuing c_pid=%d\n", c_pid);

	if (c_pid == 0) {
		(void) close(p[0]);
		(void) close(1);
		(void) fcntl(p[1], F_DUPFD, 1);
		(void) close(p[1]);
		(void) close(2);
		dprintf("second exec fuser %s\n", file);
		(void) execle("/usr/sbin/fuser", "fuser", file, NULL, newenv);
		dperror("second exec fuser");
		_exit(1);
	}

	(void) close(p[1]);
	if ((ptr = fdopen(p[0], "r")) != NULL) {
		while (!feof(ptr)) {
			if (fscanf(ptr, "%d", &pid) > 0) {
				(void) sprintf(buf + strlen(PROCFS), "%d", pid);
				if ((fp = open(buf, O_RDONLY)) == -1) {
					dperror(buf);
					continue;
				}
				if (ioctl(fp, PIOCPSINFO, (char *)&info)
				    == -1) {
					dprintf("%d psinfo failed", pid);
					dperror("");
					(void) close(fp);
					continue;
				}
				(void) close(fp);
				if (strcmp(info.pr_fname, "vold") == NULL) {
					dprintf("%d matched vold name\n", pid);
					continue;
				}
				dprintf("killing %s", info.pr_fname);
				dprintf("(%d)\n", pid);
				if ((r = kill(pid, SIGKILL)) == -1) {
					dprintf("kill %d", pid);
					dperror("");
					break;
				}
			}
		}
		dprintf("eof reached %x\n", ptr);
	} else {
		dperror("fdopen(p[0])");
		r = -1;
	}

	(void) fclose(ptr);
	return (r);
}

static int
mk_unalloc(int optflg, char *list)
{
	char	*file;
	int	error = 0;
	int child, status;

	audit_allocate_list(list);

	child = vfork();
	switch (child) {
	case -1:
		return (-1);
	case 0:
		(void) setuid(0);
		file = strtok(list, " ");
		while (file != NULL) {
			dprintf("Deallocating %s\n", file);
			if (mk_revoke(optflg, file) < 0) {
				dprintf("mk_unalloc: unable to revoke %s\n",
				    file);
				dperror("");
				error = CNTFRC;
				break;
			}
			error = newdac(file, ALLOC_UID, ALLOC_GID,
			    DEALLOC_MODE);
			file = strtok(NULL, " ");
		}
		exit(error);
	default:
		while (wait(&status) != child);
		if (WIFEXITED(status)) {
			return (WEXITSTATUS(status));
		}
		return (-1);
	}
}

static int
exec_clean(int optflg, char *name, char *path)
{
	char	*mode, *cmd;
	int	status;
	int	c;

	if ((optflg & (FORCE_ALL | SILENT)) == (FORCE_ALL | SILENT))
		mode = "-I";
	else if (optflg & FORCE_ALL)
		mode = "-i";
	else if (optflg & FORCE)
		mode = "-f";
	else
		mode = "-s";
	if ((cmd = strrchr(path, '/')) == NULL)
		cmd = path;
	else
		cmd++;	/* skip leading '/' */

	c = vfork();
	switch (c) {
	case -1:
		return (-1);
	case 0:
		(void) setuid(0);
		dprintf("clean script: %s, ", path);
		dprintf("cmd=%s, ", cmd);
		dprintf("mode=%s, ", mode);
		dprintf("name=%s\n", name);
		(void) execle(path, cmd, mode, name, NULL, newenv);
		dprintf("Unable to execute clean up script %s\n", path);
		dperror("");
		exit(CNTDEXEC);
	default:
		while (wait(&status) != c);
		if (WIFEXITED(status))
			return (WEXITSTATUS(status));
		dprintf("exit status %d\n", status);
		return (-1);
	}
}

static int
deallocate_dev(int optflg, devalloc_t *dev_ent, uid_t uid)
{
	devmap_t *dev_list;
	char	file_name[MAXPATHLEN];
	struct stat stat_buf;
	char	*list;
	int	error = 0, err;
	int	bytes_formated;

	bytes_formated = snprintf(file_name, MAXPATHLEN, "%s/%s", DAC_DIR,
	    dev_ent->da_devname);
	if (bytes_formated <= 0) {
		return (DEVNAME_ERR);
	} else if (bytes_formated >= MAXPATHLEN) {
		dprintf("device name %s is too long.\n", dev_ent->da_devname);
		return (DEVNAME_TOOLONG);
	}

	audit_allocate_device(file_name);

	if (stat(file_name, &stat_buf)) {
		dprintf("Unable to stat %s\n", file_name);
		dperror("Error:");
		return (DACACC);
	}

	if (!(optflg & FORCE) && stat_buf.st_uid != uid &&
	    DEV_ALLOCATED(stat_buf)) {
		return (NALLOCU);
	}

	if (!(optflg & FORCE_ALL) && !DEV_ALLOCATED(stat_buf)) {
		if ((stat_buf.st_mode & ~S_IFMT) == ALLOC_ERR_MODE) {
			if (!(optflg & FORCE))
				return (ALLOCERR);
		} else
			return (NALLOC);
	}

	/* All checks passed, time to lock and deallocate */
	if ((error = lock_dev(file_name)) != 0)
		return (error);

	if ((err = newdac(file_name, ALLOC_UID, ALLOC_GID, DEALLOC_MODE))
	    != 0) {
		(void) newdac(file_name, ALLOC_UID, ALLOC_GID, ALLOC_ERR_MODE);
		EXIT(err);
	}

	if ((dev_list = getdmapnam(dev_ent->da_devname)) == NULL) {
		dprintf("Unable to find %s in the device map database\n",
		    dev_ent->da_devname);
		EXIT(NODMAPENT);
	} else {
		if ((list = strdup(dev_list->dmap_devlist)) == NULL) {
			EXIT(SYSERROR)
		} else {
			if (mk_unalloc(optflg, list) != 0) {
				(void) newdac(file_name, ALLOC_UID, ALLOC_GID,
				    ALLOC_ERR_MODE);
				free(list);
				list = NULL;
				EXIT(DEVLST);
			}
		}
	}

	if (list != NULL)
		free(list);
	if (exec_clean(optflg, dev_ent->da_devname, dev_ent->da_devexec))
		EXIT(CLEAN_ERR);
	return (error);
}

static int
allocate_dev(int optflg, uid_t uid, devalloc_t *dev_ent)
{
	devmap_t *dev_list;
	char	file_name[MAXPATHLEN];
	struct stat stat_buf;
	char	*list;
	int	error = 0;
	int	bytes_formated;

	bytes_formated = snprintf(file_name, MAXPATHLEN, "%s/%s", DAC_DIR,
	    dev_ent->da_devname);
	if (bytes_formated <= 0) {
		return (DEVNAME_ERR);
	} else if (bytes_formated >= MAXPATHLEN) {
		dprintf("device name %s is too long.\n", dev_ent->da_devname);
		return (DEVNAME_TOOLONG);
	}

	audit_allocate_device(file_name);

	if (stat(file_name, &stat_buf)) {
		dprintf("Unable to stat %s\n", file_name);
		dperror("Error:");
		return (DACACC);
	}

	if (DEV_ALLOCATED(stat_buf)) {
		if (optflg & FORCE) {
			if (deallocate_dev(FORCE, dev_ent, uid)) {
				dprintf("Couldn't force deallocate device %s\n",
				    dev_ent->da_devname);
				return (CNTFRC);
			}
		} else if (stat_buf.st_uid == uid) {
			return (ALLOC);
		} else
			return (ALLOC_OTHER);
	}
	if ((stat_buf.st_mode & ~S_IFMT) == ALLOC_ERR_MODE)
		return (ALLOCERR);

	if (strcmp(dev_ent->da_devauth, "*") == 0) {
		dprintf("Device %s is not allocatable\n", dev_ent->da_devname);
		return (AUTHERR);
	}

	if (strcmp(dev_ent->da_devauth, "@")) {
		if (!is_authorized(dev_ent->da_devauth, uid)) {
			dprintf("User %d is unauthorized to allocate\n",
			    (int)uid);
			return (IMPORT_ERR);
		}
	}

	if ((dev_list = getdmapnam(dev_ent->da_devname)) == NULL) {
		dprintf("Unable to find %s in device map database\n",
		    dev_ent->da_devname);
		return (NODMAPENT);
	}

	if ((list = strdup(dev_list->dmap_devlist)) == NULL)
		return (SYSERROR);

	if (check_devs(list) == -1) {
		free(list);
		return (DSPMISS);
	}

	/* All checks passed, time to lock and allocate */
	if ((error = lock_dev(file_name)) != 0) {
		free(list);
		return (error);
	}

	if ((error = newdac(file_name, uid, getgid(), ALLOC_MODE)) != 0) {
		(void) newdac(file_name, ALLOC_UID, ALLOC_GID, ALLOC_ERR_MODE);
		free(list);
		return (error);
	}

	/* refresh list from check_devs overwritting it */
	(void) strcpy(list, dev_list->dmap_devlist);
	audit_allocate_list(list);

	if (mk_alloc(list, uid) != 0) {
		/* refresh list from mk_alloc overwritting it */
		(void) strcpy(list, dev_list->dmap_devlist);
		(void) mk_unalloc(optflg, list);
		free(list);
		return (DEVLST);
	}

	free(list);
	return (0);
}

int
allocate(int optflg, uid_t uid, char *device)
{
	devalloc_t	*dev_ent;
	devmap_t	*dev_list;

	if (((optflg & FORCE) || uid != getuid()) &&
	    !is_authorized(DEVICE_REVOKE_AUTH, getuid()))
		return (NOTAUTH);

	setdaent();
	setdmapent();

	if (!(optflg & TYPE)) {
		if ((dev_ent = getdanam(device)) == NULL) {
			if ((dev_list = getdmapdev(device)) == NULL)
				return (NODMAPENT);
			else if ((dev_ent = getdanam(dev_list->dmap_devname))
			    == NULL)
				return (NODAENT);
		}
		return (allocate_dev(optflg, uid, dev_ent));
	}

	while ((dev_ent = getdatype(device)) != NULL) {
		dprintf("trying to allocate %s\n", dev_ent->da_devname);
		if (!allocate_dev(optflg, uid, dev_ent)) {
			return (0);
		}
	}
	enddaent();
	return (NO_DEVICE);
}

int
deallocate(int optflg, uid_t uid, char *device)
{
	DIR	*dev_dir;
	struct dirent	*dac_file;
	devalloc_t	*dev_ent;
	devmap_t	*dev_list;
	int	error = NODAENT;

	if (optflg & (FORCE | FORCE_ALL) &&
	    !is_authorized(DEVICE_REVOKE_AUTH, getuid()))
		return (NOTAUTH);
	if (optflg & FORCE_ALL)
		optflg |= FORCE;

	setdaent();
	setdmapent();

	if (!(optflg & FORCE_ALL)) {
		if ((dev_ent = getdanam(device)) == NULL) {
			if ((dev_list = getdmapdev(device)) == NULL)
				return (NODMAPENT);
			else if ((dev_ent = getdanam(dev_list->dmap_devname))
			    == NULL)
				return (NODAENT);
		}

		return (deallocate_dev(optflg, dev_ent, uid));
	}

	if ((dev_dir = opendir(DAC_DIR)) == NULL) {
		dperror("Can't open DAC_DIR");
		return (DACACC);
	}

	while ((dac_file = readdir(dev_dir)) != NULL) {
		if ((strcmp(dac_file->d_name, ".") == 0) ||
		    (strcmp(dac_file->d_name, "..") == 0)) {
			continue;
		} else {
			if ((dev_ent = getdanam(dac_file->d_name)) == NULL) {
				continue;
			}
			error = deallocate_dev(optflg, dev_ent, uid);
		}
	}
	(void) closedir(dev_dir);
	enddaent();
	return (error);
}
