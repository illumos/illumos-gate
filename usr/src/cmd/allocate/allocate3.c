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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <strings.h>
#include <unistd.h>
#include <bsm/devices.h>
#include <sys/acl.h>
#include <tsol/label.h>
#include <syslog.h>
#include <limits.h>
#include <user_attr.h>
#include <secdb.h>
#include <sys/mkdev.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/procfs.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <utime.h>
#include <libgen.h>
#include <zone.h>
#include <nss_dbdefs.h>
#include <bsm/devalloc.h>
#include <libdevinfo.h>
#include "allocate.h"

extern void print_error(int, char *);

#if	defined(DEBUG) || defined(lint)
#define	dprintf(s, a) (void) fprintf(stderr, s, a)
#define	dperror(s) perror(s)
#else	/* !DEBUG */
#define	dprintf(s, a)	0
#define	dperror(s)	0
#endif	/* DEBUG */

#define	DEV_ERRORED(sbuf)	(((sbuf).st_mode & ~S_IFMT) == ALLOC_ERR_MODE)
#define	DEV_ALLOCATED(sbuf)	((sbuf).st_uid != DA_UID || \
			!(((sbuf).st_mode & ~S_IFMT) == DEALLOC_MODE || \
			DEV_ERRORED(sbuf)))

#define	ALLOC_CLEAN		"-A"
#define	DEALLOC_CLEAN		"-D"
#define	DAC_DIR			"/etc/security/dev"
#define	DEVICE_AUTH_SEPARATOR	","
#define	LOCALDEVICE		"/dev/console"
#define	PROCFS			"/proc/"
#define	SFF_NO_ERROR		0x1

#define	ALLOC_BY_NONE		-1
#define	CHECK_DRANGE		1
#define	CHECK_URANGE		2
#define	CHECK_ZLABEL		3

extern void audit_allocate_list(char *);
extern void audit_allocate_device(char *);

extern int	system_labeled;
extern char	*newenv[];

struct state_file {
	int	sf_flags;
	char	sf_path[MAXPATHLEN];
};

struct file_info {
	struct stat	fi_stat;
	char		*fi_message;
};

struct zone_path {
	int	count;
	char	**path;
};

struct dev_names {
	char **dnames;
};

static int _dev_file_name(struct state_file *, devmap_t *);
static int lock_dev(char *, struct stat *);
static int _check_label(devalloc_t *, char *, uid_t, int);
static int create_znode(char *, struct zone_path *, devmap_t *);
static int remove_znode(char *, devmap_t *);
static int update_device(char **, char *, int);

/*
 * checks if the invoking user is local to the device
 */
/*ARGSUSED*/
int
_is_local(uid_t uid)
{
	struct stat	statbuf;

	if (stat(LOCALDEVICE, &statbuf) == 0 &&
	    statbuf.st_uid == uid)
		return (1);

	return (0);
}

/*
 * Checks if the user with the specified uid has the specified authorization
 */
int
_is_authorized(char *auths, uid_t uid)
{
	char		*dcp, *authlist, *lasts;
	char		pw_buf[NSS_BUFLEN_PASSWD];
	struct passwd	pw_ent;

	/*
	 * first, the easy cases
	 */
	if (strcmp(auths, "@") == 0)
		return (1);
	if (strcmp(auths, "*") == 0)
		return (ALLOC_BY_NONE);
	if (getpwuid_r(uid, &pw_ent, pw_buf, sizeof (pw_buf)) == NULL)
		return (0);
	if (strpbrk(auths, DEVICE_AUTH_SEPARATOR) == NULL)
		return (chkauthattr(auths, pw_ent.pw_name));
	authlist = strdup(auths);
	if (authlist == NULL)
		return (0);
	for (dcp = authlist;
	    (dcp = strtok_r(dcp, DEVICE_AUTH_SEPARATOR, &lasts)) != NULL;
	    dcp = NULL) {
		if (chkauthattr(dcp, pw_ent.pw_name))
			break;
	}
	free(authlist);

	return (dcp != NULL);
}

/*
 * Checks if the specified user has authorization for the device
 */
int
_is_dev_authorized(devalloc_t *da, uid_t uid)
{
	int	ares;
	char	*auth_list, *dcp, *subauth = NULL;

	auth_list = da->da_devauth;
	if (auth_list == NULL)
		return (0);
	dcp = strpbrk(auth_list, KV_TOKEN_DELIMIT);
	if (dcp == NULL)
		return (_is_authorized(auth_list, uid));
	if (_is_local(uid)) {
		/* the local authorization is before the separator */
		ares = dcp - auth_list;
		subauth = malloc(ares + 1);
		if (subauth == NULL)
			return (0);
		(void) strlcpy(subauth, auth_list, (ares + 1));
		auth_list = subauth;
	} else
		auth_list = dcp + 1;
	ares = _is_authorized(auth_list, uid);
	if (subauth != NULL)
		free(subauth);

	return (ares);
}

int
check_devs(devmap_t *dm)
{
	int	status = 0;
	char	**file;

	if (dm->dmap_devarray == NULL)
		return (NODMAPERR);
	for (file = dm->dmap_devarray; *file != NULL; file++) {
		if ((status = access(*file, F_OK)) == -1) {
			dprintf("Unable to access file %s\n", *file);
			break;
		}
	}

	return (status);
}

int
print_da_defs(da_defs_t *da_defs)
{
	char	optbuf[BUFSIZ];
	char	*p = NULL;

	if (da_defs->devopts == NULL) {
		dprintf("No default attributes for %s\n", da_defs->devtype);
		return (DEFATTRSERR);
	}
	(void) printf("dev_type=%s\n", da_defs->devtype);
	if (_kva2str(da_defs->devopts, optbuf, sizeof (optbuf), KV_ASSIGN,
	    KV_TOKEN_DELIMIT) == 0) {
		if (p = rindex(optbuf, ':'))
			*p = '\0';
		(void) printf("\t%s\n", optbuf);
	}

	return (0);
}

void
print_dev_attrs(int optflag, devalloc_t *da, devmap_t *dm,
    struct file_info *fip)
{
	char	*p = NULL;
	char	optbuf[BUFSIZ];

	(void) printf("device=%s%s", dm->dmap_devname, KV_DELIMITER);
	(void) printf("type=%s%s", dm->dmap_devtype, KV_DELIMITER);
	(void) printf("auths=%s%s",
	    (da->da_devauth ? da->da_devauth : ""), KV_DELIMITER);
	(void) printf("clean=%s%s",
	    (da->da_devexec ? da->da_devexec : ""), KV_DELIMITER);
	if (da->da_devopts != NULL) {
		if (_kva2str(da->da_devopts, optbuf, sizeof (optbuf),
		    KV_ASSIGN, KV_TOKEN_DELIMIT) == 0) {
			if (p = rindex(optbuf, ':'))
				*p = '\0';
			(void) printf("%s", optbuf);
		}
	}
	(void) printf("%s", KV_DELIMITER);
	if (optflag & WINDOWING) {
		if ((fip->fi_message != NULL) &&
		    (strcmp(fip->fi_message, DAOPT_CLASS) == 0))
			(void) printf("owner=/FREE%s", KV_DELIMITER);
		else if (DEV_ERRORED(fip->fi_stat))
			(void) printf("owner=/ERROR%s", KV_DELIMITER);
		else if (!DEV_ALLOCATED(fip->fi_stat))
			(void) printf("owner=/FREE%s", KV_DELIMITER);
		else
			(void) printf("owner=%u%s", fip->fi_stat.st_uid,
			    KV_DELIMITER);
	}
	(void) printf("files=%s", dm->dmap_devlist);
	(void) printf("\n");
}

void
print_dev(devmap_t *dm)
{
	char	**file;

	(void) printf(gettext("device: %s "), dm->dmap_devname);
	(void) printf(gettext("type: %s "), dm->dmap_devtype);
	(void) printf(gettext("files:"));
	file = dm->dmap_devarray;
	if (file != NULL) {
		for (; *file != NULL; file++)
			(void) printf(" %s", *file);
	}
	(void) printf("\n");
}

/* ARGSUSED */
int
_list_device(int optflag, uid_t uid, devalloc_t *da, char *zonename)
{
	int			bytes = 0;
	int			error = 0;
	int			is_authorized = 0;
	char			*fname = NULL;
	char			file_name[MAXPATHLEN];
	devmap_t		*dm;
	struct file_info	fi;
	struct state_file	sf;

	fi.fi_message = NULL;
	setdmapent();
	if ((dm = getdmapnam(da->da_devname)) == NULL) {
		enddmapent();
		dprintf("Unable to find %s in the maps database\n",
		    da->da_devname);
		return (NODMAPERR);
	}
	enddmapent();

	if ((optflag & CLASS) &&
	    (!(optflag & (LISTALL | LISTFREE | LISTALLOC)))) {
		fi.fi_message = DAOPT_CLASS;
		if (optflag & LISTATTRS)
			print_dev_attrs(optflag, da, dm, &fi);
		else
			print_dev(dm);
		goto out;
	}

	if (system_labeled) {
		if ((error = _dev_file_name(&sf, dm)) != 0) {
			freedmapent(dm);
			dprintf("Unable to find %s device files\n",
			    da->da_devname);
			error = NODMAPERR;
			goto out;
		}
		fname = sf.sf_path;
	} else {
		bytes = snprintf(file_name, MAXPATHLEN, "%s/%s", DAC_DIR,
		    da->da_devname);
		if (bytes <= 0) {
			error = DEVNAMEERR;
			goto out;
		} else if (bytes >= MAXPATHLEN) {
			dprintf("device name %s is too long.\n",
			    da->da_devname);
			error = DEVLONGERR;
			goto out;
		}
		fname = file_name;
	}
	if (stat(fname, &fi.fi_stat) != 0) {
		dprintf("Unable to stat %s\n", fname);
		dperror("Error:");
		error = DACACCERR;
		goto out;
	}
	is_authorized = _is_dev_authorized(da, uid);
	if (optflag & LISTFREE) {	/* list_devices -n */
		/*
		 * list all free devices
		 */
		if (DEV_ALLOCATED(fi.fi_stat)) {
				error = PREALLOCERR;
				goto out;
		}
		if (system_labeled) {
			/*
			 * for this free device, check if -
			 * 1. user has authorization to allocate
			 * 2. the zone label is within the label range of the
			 *    device
			 */
			if (is_authorized == ALLOC_BY_NONE) {
				error = DAUTHERR;
				goto out;
			} else if (is_authorized == 0) {
				error = UAUTHERR;
				goto out;
			}
			if (_check_label(da, zonename, uid,
			    CHECK_DRANGE) != 0) {
				error = LABELRNGERR;
				goto out;
			}
		}
	} else if (optflag & LISTALLOC) {	/*  list_devices -u */
		/*
		 * list all allocated devices
		 */
		if (!DEV_ALLOCATED(fi.fi_stat)) {
			error = DEVNALLOCERR;
			goto out;
		}
		if (fi.fi_stat.st_uid != uid) {
			error = DEVSTATEERR;
			goto out;
		}
		if (system_labeled) {
			/*
			 * check if the zone label equals the label at which
			 * the device is allocated.
			 */
			if (_check_label(da, zonename, uid,
			    CHECK_ZLABEL) != 0) {
				error = LABELRNGERR;
				goto out;
			}
		}
	} else if (optflag & LISTALL) {		/* list_devices -l */
		/*
		 * list all devices - free and allocated - available
		 */
		if (DEV_ALLOCATED(fi.fi_stat)) {
			if (optflag & WINDOWING &&
			    (is_authorized == ALLOC_BY_NONE)) {
				/*
				 * don't complain if we're here for the GUI.
				 */
				error = 0;
			} else if (fi.fi_stat.st_uid != uid) {
				if (!(optflag & WINDOWING)) {
					error = ALLOCUERR;
					goto out;
				}
			}
			if (system_labeled && !(optflag & WINDOWING)) {
				/*
				 * if we're not displaying in the GUI,
				 * check if the zone label equals the label
				 * at which the device is allocated.
				 */
				if (_check_label(da, zonename, uid,
				    CHECK_ZLABEL) != 0) {
					error = LABELRNGERR;
					goto out;
				}
			}
		} else if (system_labeled && !(optflag & WINDOWING)) {
			/*
			 * if we're not displaying in the GUI,
			 * for this free device, check if -
			 * 1. user has authorization to allocate
			 * 2. the zone label is within the label range of the
			 *    device
			 */
			if (is_authorized == ALLOC_BY_NONE) {
				error = DAUTHERR;
				goto out;
			} else if (is_authorized == 0) {
				error = UAUTHERR;
				goto out;
			}
			if (_check_label(da, zonename, uid,
			    CHECK_DRANGE) != 0) {
				error = LABELRNGERR;
				goto out;
			}
		}
	}
	if (system_labeled && DEV_ERRORED(fi.fi_stat) && !(optflag & LISTALL)) {
		error = DEVSTATEERR;
		goto out;
	}
	if (check_devs(dm) == -1) {
		error = DSPMISSERR;
		goto out;
	}
	if (optflag & LISTATTRS)
		print_dev_attrs(optflag, da, dm, &fi);
	else
		print_dev(dm);

	error = 0;

out:
	freedmapent(dm);
	return (error);
}

/* ARGSUSED */
int
list_devices(int optflag, uid_t uid, char *device, char *zonename)
{
	int		error = 0;
	char		*class = NULL;
	da_defs_t	*da_defs;
	devalloc_t	*da;

	if (system_labeled && optflag & WINDOWING && !(optflag & LISTATTRS)) {
		/*
		 * Private interface for GUI.
		 */
		(void) puts(DA_DB_LOCK);
		return (0);
	}
	if (optflag & USERID) {
		/*
		 * we need device.revoke to list someone else's devices
		 */
		if (!_is_authorized(DEVICE_REVOKE_AUTH, getuid()))
			return (UAUTHERR);
	}
	if (system_labeled) {
		if (!(optflag & USERID) &&
		    !_is_authorized(DEFAULT_DEV_ALLOC_AUTH, uid))
			/*
			 * we need device.allocate to list our devices
			 */
			return (UAUTHERR);
		if (optflag & LISTDEFS) {
			/*
			 * list default attrs from devalloc_defaults
			 */
			setdadefent();
			if (device) {
				/*
				 * list default attrs for this device type
				 */
				da_defs = getdadeftype(device);
				if (da_defs == NULL) {
					enddadefent();
					dprintf("No default attributes for "
					    "%s\n", device);
					return (DEFATTRSERR);
				}
				error = print_da_defs(da_defs);
				freedadefent(da_defs);
			} else {
				/*
				 * list everything in devalloc_defaults
				 */
				while ((da_defs = getdadefent()) != NULL) {
					(void) print_da_defs(da_defs);
					freedadefent(da_defs);
				}
			}
			enddadefent();
			return (error);
		}
	}
	/*
	 * Lock the database to make sure no body writes to it while we are
	 * reading.
	 */
	(void) lock_dev(NULL, NULL);
	setdaent();
	if (device) {
		if (optflag & CLASS) {
			/*
			 * list all devices of this class.
			 */
			while ((da = getdaent()) != NULL) {
				class =	 kva_match(da->da_devopts, DAOPT_CLASS);
				if (class && (strcmp(class, device) == 0)) {
					(void) _list_device(optflag, uid, da,
					    zonename);
				}
				freedaent(da);
			}
		} else {
			/*
			 * list this device
			 */
			if ((da = getdanam(device)) == NULL) {
				enddaent();
				return (NODAERR);
			}
			error = _list_device(optflag, uid, da, zonename);
			freedaent(da);
		}
	} else {
		/*
		 * list all devices
		 */
		while ((da = getdaent()) != NULL) {
			(void) _list_device(optflag, uid, da, zonename);
			freedaent(da);
		}
	}
	enddaent();

	return (error);
}

/*
 * Set the DAC characteristics of the file.
 * This uses a fancy chmod() by setting a minimal ACL which sets the mode
 * and discards any existing ACL.
 */
int
_newdac(char *file, uid_t owner, gid_t group, o_mode_t mode)
{
	int	err = 0;

	if (mode == ALLOC_MODE) {
		if (chown(file, owner, group) == -1) {
			dperror("newdac: unable to chown");
			err = CHOWNERR;
		}
	} else do {
		if (chown(file, owner, group) == -1) {
			dperror("newdac: unable to chown");
			err = CHOWNERR;
		}
	} while (fdetach(file) == 0);

	if (err)
		return (err);

	if (strncmp(file, "/dev/", strlen("/dev/")) != 0) {
		/*
		 * This could be a SunRay device that is in /tmp.
		 */
		if (chmod(file, mode) == -1) {
			dperror("newdac: unable to chmod");
			err = SETACLERR;
		}
	} else {
		err = acl_strip(file, owner, group, (mode_t)mode);
	}

	if (err != 0) {
		dperror("newdac: unable to setacl");
		err = SETACLERR;
	}

	return (err);
}

/*
 * lock_dev -
 *	locks a section of DA_DB_LOCK.
 *	returns lock fd if successful, else -1 on error.
 */
static int
lock_dev(char *file, struct stat *statbuf)
{
	static int	lockfd = -1;
	int		ret;
	int		count = 0;
	int		retry = 10;
	off_t		size = 0;
	off_t		offset;
	char		*lockfile;

	if (system_labeled)
		lockfile = DA_DB_LOCK;
	else
		lockfile = file;

	if (statbuf) {
		offset = statbuf->st_rdev;
		dprintf("locking %s\n", file);
	} else {
		offset = 0;
		dprintf("locking %s\n", lockfile);
	}
	if ((lockfd == -1) &&
	    (lockfd = open(lockfile, O_RDWR | O_CREAT, 0600)) == -1) {
		dperror("lock_dev: cannot open lock file");
		return (-1);
	}
	if (system_labeled) {
		(void) _newdac(lockfile, DA_UID, DA_GID, 0600);
		if (lseek(lockfd, offset, SEEK_SET) == -1) {
			dperror("lock_dev: cannot position lock file");
			return (-1);
		}
		size = 1;
	}
	errno = 0;
	while (retry) {
		count++;
		ret = lockf(lockfd, F_TLOCK, size);
		if (ret == 0)
			return (lockfd);
		if ((errno != EACCES) && (errno != EAGAIN)) {
			dperror("lock_dev: cannot set lock");
			return (-1);
		}
		retry--;
		(void) sleep(count);
		errno = 0;
	}

	return (-1);
}

int
mk_alloc(devmap_t *list, uid_t uid, struct zone_path *zpath)
{
	int	i;
	int	error = 0;
	char	**file;
	gid_t	gid = getgid();
	mode_t	mode = ALLOC_MODE;

	file = list->dmap_devarray;
	if (file == NULL)
		return (NODMAPERR);
	for (; *file != NULL; file++) {
		dprintf("Allocating %s\n", *file);
		if ((error = _newdac(*file, uid, gid, mode)) != 0) {
			(void) _newdac(*file, ALLOC_ERRID, DA_GID,
			    ALLOC_ERR_MODE);
			break;
		}
	}
	if (system_labeled && zpath->count && (error == 0)) {
		/*
		 * mark as allocated any new device nodes that we
		 * created in local zone
		 */
		for (i = 0; i < zpath->count; i++) {
			dprintf("Allocating %s\n", zpath->path[i]);
			if ((error = _newdac(zpath->path[i], uid, gid,
			    mode)) != 0) {
				(void) _newdac(zpath->path[i], ALLOC_ERRID,
				    DA_GID, ALLOC_ERR_MODE);
				break;
			}
		}
	}

	return (error);
}

/*
 * mk_revoke() is used instead of system("/usr/sbin/fuser -k file")
 * because "/usr/sbin/fuser -k file" kills all processes
 * working with the file, even "vold" (bug #4095152).
 */
int
mk_revoke(int optflag, char *file)
{
	int		r = 0, p[2], fp, lock;
	int		fuserpid;
	char		buf[MAXPATHLEN];
	FILE		*ptr;
	pid_t		c_pid;
	prpsinfo_t	info;

	(void) strcpy(buf, PROCFS);
	/*
	 * vfork() and execl() just to make the same output
	 * as before fixing of bug #4095152.
	 * The problem is that the "fuser" command prints
	 * one part of output into stderr and another into stdout,
	 * but user sees them mixed. Of course, better to change "fuser"
	 * or to intercept and not to print its output.
	 */
	if (!(optflag & SILENT)) {
		c_pid = vfork();
		if (c_pid == -1)
			return (-1);
		if (c_pid == 0) {
			dprintf("first exec fuser %s\n", file);
			(void) execl("/usr/sbin/fuser", "fuser", file, NULL);
			dperror("first exec fuser");
			_exit(1);
		}

		(void) waitpid(c_pid, &lock, 0);
		dprintf("exit status %x\n", lock);
		if (WEXITSTATUS(lock) != 0)
			return (-1);
	}
	dprintf("first continuing c_pid=%d\n", (int)c_pid);
	if (pipe(p)) {
		dperror("pipe");
		return (-1);
	}
	/* vfork() and execl() to catch output and to process it */
	c_pid = vfork();
	if (c_pid == -1) {
		dperror("second vfork");
		return (-1);
	}
	dprintf("second continuing c_pid=%d\n", (int)c_pid);
	if (c_pid == 0) {
		(void) close(p[0]);
		(void) close(1);
		(void) fcntl(p[1], F_DUPFD, 1);
		(void) close(p[1]);
		(void) close(2);
		dprintf("second exec fuser %s\n", file);
		(void) execl("/usr/sbin/fuser", "fuser", file, NULL);
		dperror("second exec fuser");
		_exit(1);
	}
	(void) close(p[1]);
	if ((ptr = fdopen(p[0], "r")) != NULL) {
		while (!feof(ptr)) {
			if (fscanf(ptr, "%d", &fuserpid) > 0) {
				(void) sprintf(buf + strlen(PROCFS), "%d",
				    fuserpid);
				if ((fp = open(buf, O_RDONLY)) == -1) {
					dperror(buf);
					continue;
				}
				if (ioctl(fp, PIOCPSINFO,
				    (char *)&info) == -1) {
					dprintf("%d psinfo failed", fuserpid);
					dperror("");
					(void) close(fp);
					continue;
				}
				(void) close(fp);
				if (strcmp(info.pr_fname, "vold") == 0) {
					dprintf("%d matched vold name\n",
					    fuserpid);
					continue;
				}
				if (strcmp(info.pr_fname, "deallocate") == 0) {
					dprintf("%d matched deallocate name\n",
					    fuserpid);
					continue;
				}
				dprintf("killing %s", info.pr_fname);
				dprintf("(%d)\n", fuserpid);
				if ((r =
				    kill((pid_t)fuserpid, SIGKILL)) == -1) {
					dprintf("kill %d", fuserpid);
					dperror("");
					break;
				}
			}
		}
	} else {
		dperror("fdopen(p[0], r)");
		r = -1;
	}
	(void) fclose(ptr);

	return (r);
}

int
mk_unalloc(int optflag, devmap_t *list)
{
	int	error = 0;
	int	status;
	char	**file;

	audit_allocate_list(list->dmap_devlist);
	file = list->dmap_devarray;
	if (file == NULL)
		return (NODMAPERR);
	for (; *file != NULL; file++) {
		dprintf("Deallocating %s\n", *file);
		if (mk_revoke(optflag, *file) < 0) {
			dprintf("mk_unalloc: unable to revoke %s\n", *file);
			dperror("");
			error = CNTFRCERR;
		}
		status = _newdac(*file, DA_UID, DA_GID, DEALLOC_MODE);
		if (error == 0)
			error = status;

	}

	return (error);
}

int
mk_error(devmap_t *list)
{
	int	status = 0;
	char	**file;

	audit_allocate_list(list->dmap_devlist);
	file = list->dmap_devarray;
	if (file == NULL)
		return (NODMAPERR);
	for (; *file != NULL; file++) {
		dprintf("Putting %s in error state\n", *file);
		status = _newdac(*file, ALLOC_ERRID, DA_GID, ALLOC_ERR_MODE);
	}

	return (status);
}

int
exec_clean(int optflag, char *devname, char *path, uid_t uid, char *zonename,
    char *clean_arg)
{
	int		c;
	int		status = 0, exit_status;
	char		*mode, *cmd, *wdwcmd, *zoneroot;
	char		*devzone = zonename;
	char		wdwpath[PATH_MAX];
	char		zonepath[MAXPATHLEN];
	char		title[100];
	char		pw_buf[NSS_BUFLEN_PASSWD];
	struct passwd	pw_ent;

	zonepath[0] = '\0';
	if (system_labeled) {
		if ((zoneroot = getzonerootbyname(zonename)) == NULL) {
			if (strcmp(clean_arg, ALLOC_CLEAN) == 0) {
				return (-1);
			} else if (optflag & FORCE) {
				(void) strcpy(zonepath, "/");
				devzone = GLOBAL_ZONENAME;
			} else {
				dprintf("unable to get label for %s zone\n",
				    zonename);
				return (-1);
			}
		} else {
			(void) strcpy(zonepath, zoneroot);
			free(zoneroot);
		}
	}
	if (getpwuid_r(uid, &pw_ent, pw_buf, sizeof (pw_buf)) == NULL)
		return (-1);
	if (optflag & FORCE_ALL)
		mode = "-I";
	else if (optflag & FORCE)
		mode = "-f";
	else
		mode = "-s";
	if (path == NULL)
		return (0);
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
		if (system_labeled && (optflag & WINDOWING)) {
			/* First try .windowing version of script */
			(void) strncpy(wdwpath, path, PATH_MAX);
			(void) strncat(wdwpath, ".windowing", PATH_MAX);
			if ((wdwcmd = strrchr(wdwpath, '/')) == NULL)
				wdwcmd = wdwpath;
			(void) execl(wdwpath, wdwcmd, mode, devname, clean_arg,
			    pw_ent.pw_name, devzone, zonepath, NULL);
			/* If that failed, run regular version via dtterm */
			(void) snprintf(title, sizeof (title),
			    "Device %s for %s",
			    strcmp(clean_arg, ALLOC_CLEAN) == 0 ?
			    "allocation" : "deallocation", devname);
			(void) execl("/usr/dt/bin/dtterm", "dtterm",
			    "-title", title, "-geometry", "x10+100+400",
			    "-e", "/etc/security/lib/wdwwrapper",
			    path, mode, devname, clean_arg, pw_ent.pw_name,
			    devzone, zonepath, NULL);
			/*
			 * And if that failed, continue on to try
			 * running regular version directly.
			 */
		}
		dprintf("clean script: %s, ", path);
		dprintf("cmd=%s, ", cmd);
		dprintf("mode=%s, ", mode);
		if (system_labeled) {
			dprintf("devname=%s ", devname);
			dprintf("zonename=%s ", devzone);
			dprintf("zonepath=%s ", zonepath);
			dprintf("username=%s\n", pw_ent.pw_name);
			(void) execl(path, cmd, mode, devname, clean_arg,
			    pw_ent.pw_name, devzone, zonepath, NULL);
		} else {
			dprintf("devname=%s\n", devname);
			(void) execle(path, cmd, mode, devname, NULL, newenv);
		}
		dprintf("Unable to execute clean up script %s\n", path);
		dperror("");
		exit(CNTDEXECERR);
	default:
		(void) waitpid(c, &status, 0);
		dprintf("Child %d", c);
		if (WIFEXITED(status)) {
			exit_status = WEXITSTATUS(status);
			dprintf(" exited, status: %d\n", exit_status);
			return (exit_status);
		} else if (WIFSIGNALED(status)) {
			dprintf(" killed, signal %d\n", WTERMSIG(status));
		} else {
			dprintf(": exit status %d\n", status);
		}
		return (-1);
	}
}

int
_deallocate_dev(int optflag, devalloc_t *da, devmap_t *dm_in, uid_t uid,
    char *zonename, int *lock_fd)
{
	int			bytes = 0;
	int			error = 0;
	int			is_authorized = 0;
	uid_t			nuid;
	char			*fname = NULL;
	char			file_name[MAXPATHLEN];
	char			*devzone = NULL;
	devmap_t		*dm = NULL, *dm_new = NULL;
	struct stat		stat_buf;
	struct state_file	sf;

	if (dm_in == NULL) {
		setdmapent();
		if ((dm_new = getdmapnam(da->da_devname)) == NULL) {
			enddmapent();
			dprintf("Unable to find %s in device map database\n",
			    da->da_devname);
			return (NODMAPERR);
		}
		enddmapent();
		dm = dm_new;
	} else {
		dm = dm_in;
	}
	if (system_labeled) {
		if (_dev_file_name(&sf, dm) != 0) {
			if (dm_new)
				freedmapent(dm_new);
			dprintf("Unable to find %s device files\n",
			    da->da_devname);
			error = NODMAPERR;
			goto out;
		}
		fname = sf.sf_path;
	} else {
		bytes = snprintf(file_name,  MAXPATHLEN, "%s/%s", DAC_DIR,
		    da->da_devname);
		if (bytes <= 0) {
			error = DEVNAMEERR;
			goto out;
		} else if (bytes >= MAXPATHLEN) {
			dprintf("device name %s is too long.\n",
			    da->da_devname);
			error = DEVLONGERR;
			goto out;
		}
		fname = file_name;
	}

	audit_allocate_device(fname);

	if (stat(fname, &stat_buf) != 0) {
		dprintf("Unable to stat %s\n", fname);
		error = DACACCERR;
		goto out;
	}
	is_authorized = _is_dev_authorized(da, uid);
	if (is_authorized == ALLOC_BY_NONE) {
		dprintf("Not deallocating %s, not allocatable\n",
		    da->da_devname);
		goto out;
	}
	if (!(optflag & (FORCE | FORCE_ALL)) && !is_authorized) {
		dprintf("User %d is unauthorized to deallocate\n", (int)uid);
		error = UAUTHERR;
		goto out;
	}
	if (system_labeled) {
		/*
		 * unless we're here to deallocate by force, check if the
		 * label at which the device is currently allocated is
		 * within the user label range.
		 */
		if (!(optflag & FORCE) &&
		    _check_label(da, zonename, uid, CHECK_URANGE) != 0) {
			error = LABELRNGERR;
			goto out;
		}
	}
	if (!(optflag & FORCE) && stat_buf.st_uid != uid &&
	    DEV_ALLOCATED(stat_buf)) {
		error = ALLOCUERR;
		goto out;
	}
	if (!DEV_ALLOCATED(stat_buf)) {
		if (DEV_ERRORED(stat_buf)) {
			if (!(optflag & FORCE)) {
				error = DEVSTATEERR;
				goto out;
			}
		} else {
			error = DEVNALLOCERR;
			goto out;
		}
	}
	/* All checks passed, time to lock and deallocate */
	if ((*lock_fd = lock_dev(fname, &stat_buf)) == -1) {
		error = DEVLKERR;
		goto out;
	}
	if (system_labeled) {
		devzone = kva_match(da->da_devopts, DAOPT_ZONE);
		if (devzone == NULL) {
			devzone = GLOBAL_ZONENAME;
		} else if (strcmp(devzone, GLOBAL_ZONENAME) != 0) {
			if ((remove_znode(devzone, dm) != 0) &&
			    !(optflag & FORCE)) {
				error = ZONEERR;
				goto out;
			}
		}
	}
	if ((error = mk_unalloc(optflag, dm)) != 0) {
		if (!(optflag & FORCE))
			goto out;
	}
	if (system_labeled == 0) {
		if ((error = _newdac(fname, DA_UID, DA_GID,
		    DEALLOC_MODE)) != 0) {
			(void) _newdac(file_name, DA_UID, DA_GID,
			    ALLOC_ERR_MODE);
			goto out;
		}
	}
	/*
	 * if we are deallocating device owned by someone else,
	 * pass the owner's uid to the cleaning script.
	 */
	nuid = (stat_buf.st_uid == uid) ? uid : stat_buf.st_uid;
	error = exec_clean(optflag, da->da_devname, da->da_devexec, nuid,
	    devzone, DEALLOC_CLEAN);
	if (error != 0) {
		if (!(optflag & (FORCE | FORCE_ALL))) {
			error = CLEANERR;
			(void) mk_error(dm);
		} else {
			error = 0;
		}
	}

out:
	if (dm_new)
		freedmapent(dm_new);
	return (error);
}

int
_allocate_dev(int optflag, uid_t uid, devalloc_t *da, char *zonename,
    int *lock_fd)
{
	int			i;
	int			bytes = 0;
	int			error = 0;
	int			is_authorized = 0;
	int			dealloc_optflag = 0;
	char			*fname = NULL;
	char			file_name[MAXPATHLEN];
	devmap_t		*dm;
	struct stat		stat_buf;
	struct state_file	sf;
	struct zone_path	zpath;

	zpath.count = 0;
	zpath.path = NULL;
	setdmapent();
	if ((dm = getdmapnam(da->da_devname)) == NULL) {
		enddmapent();
		dprintf("Unable to find %s in device map database\n",
		    da->da_devname);
		return (NODMAPERR);
	}
	enddmapent();
	if (system_labeled) {
		if (_dev_file_name(&sf, dm) != 0) {
			freedmapent(dm);
			dprintf("Unable to find %s device files\n",
			    da->da_devname);
			error = NODMAPERR;
			goto out;
		}
		fname = sf.sf_path;
	} else {
		bytes = snprintf(file_name,  MAXPATHLEN, "%s/%s", DAC_DIR,
		    da->da_devname);
		if (bytes <= 0) {
			error = DEVNAMEERR;
			goto out;
		} else if (bytes >= MAXPATHLEN) {
			dprintf("device name %s is too long.\n",
			    da->da_devname);
			error = DEVLONGERR;
			goto out;
		}
		fname = file_name;
	}

	(void) audit_allocate_device(fname);

	if (stat(fname, &stat_buf) != 0) {
		dprintf("Unable to stat %s\n", fname);
		dperror("Error:");
		error = DACACCERR;
		goto out;
	}
	if (DEV_ERRORED(stat_buf)) {
		error = DEVSTATEERR;
		goto out;
	}
	is_authorized = _is_dev_authorized(da, uid);
	if (is_authorized == ALLOC_BY_NONE) {
		dprintf("Device %s is not allocatable\n", da->da_devname);
		error = UAUTHERR;
		goto out;
	} else if (!is_authorized && !(optflag & USERNAME)) {
		dprintf("User %d is unauthorized to allocate\n", (int)uid);
		error = UAUTHERR;
		goto out;
	}
	if (system_labeled) {
		/*
		 * check if label of the zone to which the device is being
		 * allocated is within the device label range.
		 */
		if (_check_label(da, zonename, uid, CHECK_DRANGE) != 0) {
			error = LABELRNGERR;
			goto out;
		}
	}
	if (check_devs(dm) == -1) {
		error = DSPMISSERR;
		goto out;
	}
	if (DEV_ALLOCATED(stat_buf)) {
		if (optflag & FORCE) {
			if (optflag & SILENT)
				dealloc_optflag = FORCE|SILENT;
			else
				dealloc_optflag = FORCE;
			if (_deallocate_dev(dealloc_optflag, da, dm, uid,
			    zonename, lock_fd)) {
				dprintf("Couldn't force deallocate device %s\n",
				    da->da_devname);
				error = CNTFRCERR;
				goto out;
			}
		} else if (stat_buf.st_uid == uid) {
			error = PREALLOCERR;
			goto out;
		} else {
			error = ALLOCUERR;
			goto out;
		}
	}
	/* All checks passed, time to lock and allocate */
	if ((*lock_fd = lock_dev(fname, &stat_buf)) == -1) {
		error = DEVLKERR;
		goto out;
	}
	if (system_labeled) {
		/*
		 * Run the cleaning program; it also mounts allocated
		 * device if required.
		 */
		error = exec_clean(optflag, da->da_devname, da->da_devexec, uid,
		    zonename, ALLOC_CLEAN);
		if (error != DEVCLEAN_OK) {
			switch (error) {
			case DEVCLEAN_ERROR:
			case DEVCLEAN_SYSERR:
				dprintf("allocate: "
				    "Error in device clean program %s\n",
				    da->da_devexec);
				error = CLEANERR;
				(void) mk_error(dm);
				goto out;
			case DEVCLEAN_BADMOUNT:
				dprintf("allocate: Failed to mount device %s\n",
				    da->da_devexec);
				goto out;
			case DEVCLEAN_MOUNTOK:
				break;
			default:
				error = 0;
				goto out;
			}
		}
		/*
		 * If not mounted, create zonelinks, if this is not the
		 * global zone.
		 */
		if ((strcmp(zonename, GLOBAL_ZONENAME) != 0) &&
		    (error != DEVCLEAN_MOUNTOK)) {
			if (create_znode(zonename, &zpath, dm) != 0) {
				error = ZONEERR;
				goto out;
			}
		}
	}

	(void) audit_allocate_list(dm->dmap_devlist);

	if ((error = mk_alloc(dm, uid, &zpath)) != 0) {
		(void) mk_unalloc(optflag, dm);
		goto out;
	}

	if (system_labeled == 0) {
		if ((error = _newdac(file_name, uid, getgid(),
		    ALLOC_MODE)) != 0) {
			(void) _newdac(file_name, DA_UID, DA_GID,
			    ALLOC_ERR_MODE);
			goto out;
		}
	}
	error = 0;
out:
	if (zpath.count) {
		for (i = 0; i < zpath.count; i++)
			free(zpath.path[i]);
		free(zpath.path);
	}
	freedmapent(dm);
	return (error);
}

void
_store_devnames(int *count, struct dev_names *dnms, char *zonename,
    devalloc_t *da, int flag)
{
	int i;

	dnms->dnames = (char **)realloc(dnms->dnames,
	    (*count + 1) * sizeof (char *));
	if (da) {
		dnms->dnames[*count] = strdup(da->da_devname);
		(*count)++;
	} else {
		dnms->dnames[*count] = NULL;
		if (flag == DA_ADD_ZONE)
			(void) update_device(dnms->dnames, zonename,
			    DA_ADD_ZONE);
		else if (flag == DA_REMOVE_ZONE)
			(void) update_device(dnms->dnames, NULL,
			    DA_REMOVE_ZONE);
		for (i = 0; i < *count; i++)
			free(dnms->dnames[i]);
		free(dnms->dnames);
	}
}

int
allocate(int optflag, uid_t uid, char *device, char *zonename)
{
	int		count = 0;
	int		error = 0;
	int		lock_fd = -1;
	devalloc_t	*da;
	struct dev_names dnms;

	if (optflag & (FORCE | USERID | USERNAME)) {
		if (!_is_authorized(DEVICE_REVOKE_AUTH, getuid()))
			return (UAUTHERR);
	}
	dnms.dnames = NULL;
	setdaent();
	if (optflag & TYPE) {
		/*
		 * allocate devices of this type
		 */
		while ((da = getdatype(device)) != NULL) {
			if (system_labeled &&
			    da_check_logindevperm(da->da_devname)) {
				freedaent(da);
				continue;
			}
			dprintf("trying to allocate %s\n", da->da_devname);
			error = _allocate_dev(optflag, uid, da, zonename,
			    &lock_fd);
			if (system_labeled && (error == 0)) {
				/*
				 * we need to record in device_allocate the
				 * label (zone name) at which this device is
				 * being allocated. store this device entry.
				 */
				_store_devnames(&count, &dnms, zonename, da, 0);
			}
			freedaent(da);
			error = 0;
		}
	} else {
		/*
		 * allocate this device
		 */
		if ((da = getdanam(device)) == NULL) {
			enddaent();
			return (NODAERR);
		}
		if (system_labeled && da_check_logindevperm(device)) {
			freedaent(da);
			return (LOGINDEVPERMERR);
		}
		dprintf("trying to allocate %s\n", da->da_devname);
		error = _allocate_dev(optflag, uid, da, zonename, &lock_fd);
		/*
		 * we need to record in device_allocate the label (zone name)
		 * at which this device is being allocated. store this device
		 * entry.
		 */
		if (system_labeled && (error == 0))
			_store_devnames(&count, &dnms, zonename, da, 0);
		freedaent(da);
		if (error == DEVCLEAN_BADMOUNT)
			error = 0;
	}
	enddaent();
	if (lock_fd != -1)
		(void) close(lock_fd);
	/*
	 * add to device_allocate labels (zone names) for the devices we
	 * allocated.
	 */
	if (dnms.dnames)
		_store_devnames(&count, &dnms, zonename, NULL, DA_ADD_ZONE);

	return (error);
}

/* ARGSUSED */
int
deallocate(int optflag, uid_t uid, char *device, char *zonename)
{
	int		count = 0;
	int		error = 0;
	int		lock_fd = -1;
	char		*class = NULL;
	devalloc_t	*da;
	struct dev_names dnms;

	if (optflag & (FORCE | FORCE_ALL)) {
		if (!_is_authorized(DEVICE_REVOKE_AUTH, getuid()))
		return (UAUTHERR);
	}
	if (optflag & FORCE_ALL)
		optflag |= FORCE;
	dnms.dnames = NULL;
	setdaent();
	if (optflag & FORCE_ALL) {
		/*
		 * deallocate all devices
		 */
		while ((da = getdaent()) != NULL) {
			if (system_labeled &&
			    da_check_logindevperm(da->da_devname)) {
				freedaent(da);
				continue;
			}
			dprintf("trying to deallocate %s\n", da->da_devname);
			error = _deallocate_dev(optflag, da, NULL, uid,
			    zonename, &lock_fd);
			if (system_labeled && (error == 0)) {
				/*
				 * we need to remove this device's allocation
				 * label (zone name) from device_allocate.
				 * store this device name.
				 */
				_store_devnames(&count, &dnms, zonename, da, 0);
			}
			freedaent(da);
			error = 0;
		}
	} else if (system_labeled && (optflag & TYPE)) {
		/*
		 * deallocate all devices of this type
		 */
		while ((da = getdatype(device)) != NULL) {
			if (da_check_logindevperm(da->da_devname)) {
				freedaent(da);
				continue;
			}
			dprintf("trying to deallocate %s\n", da->da_devname);
			error = _deallocate_dev(optflag, da, NULL, uid,
			    zonename, &lock_fd);
			if (error == 0) {
				/*
				 * we need to remove this device's allocation
				 * label (zone name) from device_allocate.
				 * store this device name.
				 */
				_store_devnames(&count, &dnms, zonename, da, 0);
			}
			freedaent(da);
			error = 0;
		}
	} else if (system_labeled && (optflag & CLASS)) {
		/*
		 * deallocate all devices of this class (for sunray)
		 */
		while ((da = getdaent()) != NULL) {
			class =  kva_match(da->da_devopts, DAOPT_CLASS);
			if (class && (strcmp(class, device) == 0)) {
				dprintf("trying to deallocate %s\n",
				    da->da_devname);
				error = _deallocate_dev(optflag, da, NULL, uid,
				    zonename, &lock_fd);
				if (error == 0) {
					/*
					 * we need to remove this device's
					 * allocation label (zone name) from
					 * device_allocate. store this device
					 * name.
					 */
					_store_devnames(&count, &dnms, zonename,
					    da, 0);
				}
				error = 0;
			}
			freedaent(da);
		}
	} else if (!(optflag & TYPE)) {
		/*
		 * deallocate this device
		 */
		if ((da = getdanam(device)) == NULL) {
			enddaent();
			return (NODAERR);
		}
		if (system_labeled && da_check_logindevperm(da->da_devname)) {
			freedaent(da);
			return (LOGINDEVPERMERR);
		}
		dprintf("trying to deallocate %s\n", da->da_devname);
		error = _deallocate_dev(optflag, da, NULL, uid, zonename,
		    &lock_fd);
		if (system_labeled && (error == 0)) {
			/*
			 * we need to remove this device's allocation label
			 * (zone name) from device_allocate. store this
			 * device name.
			 */
			_store_devnames(&count, &dnms, zonename, da, 0);
		}
		freedaent(da);
		if (error == DEVCLEAN_BADMOUNT)
			error = 0;
	}
	enddaent();
	if (lock_fd != -1)
		(void) close(lock_fd);
	/*
	 * remove from device_allocate labels (zone names) for the devices we
	 * deallocated.
	 */
	if (dnms.dnames)
		_store_devnames(&count, &dnms, zonename, NULL, DA_REMOVE_ZONE);

	return (error);
}

static int
_dev_file_name(struct state_file *sfp, devmap_t *dm)
{
	sfp->sf_flags = 0;
	/* if devlist is generated, never leave device in error state */
	if (dm->dmap_devlist[0] == '`')
		sfp->sf_flags |= SFF_NO_ERROR;
	if (dm->dmap_devarray == NULL ||
	    dm->dmap_devarray[0] == NULL)
		return (NODMAPERR);
	(void) strncpy(sfp->sf_path, dm->dmap_devarray[0],
	    sizeof (sfp->sf_path));
	sfp->sf_path[sizeof (sfp->sf_path) - 1] = '\0';
	if (sfp->sf_path[0] == '\0') {
		dprintf("dev_file_name: no device list for %s\n",
		    dm->dmap_devname);
		return (NODMAPERR);
	}

	return (0);
}

/*
 * _check_label -
 *	checks the device label range against zone label, which is also
 *	user's current label.
 *	returns 0 if in range, -1 for all other conditions.
 *
 */

static int
_check_label(devalloc_t *da, char *zonename, uid_t uid, int flag)
{
	int		err;
	int		in_range = 0;
	char		*alloczone, *lstr;
	char		pw_buf[NSS_BUFLEN_PASSWD];
	blrange_t	*range;
	m_label_t	*zlabel;
	struct passwd	pw_ent;

	if ((da == NULL) || (zonename == NULL))
		return (-1);

	if ((zlabel = getzonelabelbyname(zonename)) == NULL) {
		dprintf("unable to get label for %s zone\n", zonename);
		return (-1);
	}
	if (flag == CHECK_DRANGE) {
		blrange_t	drange;

		drange.lower_bound = blabel_alloc();
		lstr = kva_match(da->da_devopts, DAOPT_MINLABEL);
		if (lstr == NULL) {
			bsllow(drange.lower_bound);
		} else if (stobsl(lstr, drange.lower_bound, NO_CORRECTION,
		    &err) == 0) {
			dprintf("bad min_label for device %s\n",
			    da->da_devname);
			free(zlabel);
			blabel_free(drange.lower_bound);
			return (-1);
		}
		drange.upper_bound = blabel_alloc();
		lstr = kva_match(da->da_devopts, DAOPT_MAXLABEL);
		if (lstr == NULL) {
			bslhigh(drange.upper_bound);
		} else if (stobsl(lstr, drange.upper_bound, NO_CORRECTION,
		    &err) == 0) {
			dprintf("bad max_label for device %s\n",
			    da->da_devname);
			free(zlabel);
			blabel_free(drange.lower_bound);
			blabel_free(drange.upper_bound);
			return (-1);
		}
		if (blinrange(zlabel, &drange) == 0) {
			char	*zlbl = NULL, *min = NULL, *max = NULL;

			(void) bsltos(zlabel, &zlbl, 0, 0);
			(void) bsltos(drange.lower_bound, &min, 0, 0);
			(void) bsltos(drange.upper_bound, &max, 0, 0);
			dprintf("%s zone label ", zonename);
			dprintf("%s outside device label range: ", zlbl);
			dprintf("min - %s, ", min);
			dprintf("max - %s\n", max);
			free(zlabel);
			blabel_free(drange.lower_bound);
			blabel_free(drange.upper_bound);
			return (-1);
		}
	} else if (flag == CHECK_URANGE) {
		if (getpwuid_r(uid, &pw_ent, pw_buf, sizeof (pw_buf)) == NULL) {
			dprintf("Unable to get passwd entry for userid %d\n",
			    (int)uid);
			free(zlabel);
			return (-1);
		}
		if ((range = getuserrange(pw_ent.pw_name)) == NULL) {
			dprintf("Unable to get label range for userid %d\n",
			    (int)uid);
			free(zlabel);
			return (-1);
		}
		in_range = blinrange(zlabel, range);
		free(zlabel);
		blabel_free(range->lower_bound);
		blabel_free(range->upper_bound);
		free(range);
		if (in_range == 0) {
			dprintf("%s device label ", da->da_devname);
			dprintf("out of user %d label range\n", (int)uid);
			return (-1);
		}
	} else if (flag == CHECK_ZLABEL) {
		alloczone = kva_match(da->da_devopts, DAOPT_ZONE);
		if (alloczone == NULL) {
			free(zlabel);
			return (-1);
		}
		if (strcmp(zonename, alloczone) != 0) {
			dprintf("%s zone is different than ", zonename);
			dprintf("%s zone to which the device ", alloczone);
			dprintf("%s is allocated\n", da->da_devname);
			free(zlabel);
			return (-1);
		}
	}
	free(zlabel);

	return (0);
}

int
create_znode(char *zonename, struct zone_path *zpath, devmap_t *list)
{
	int		size;
	int		len = 0;
	int		fcount = 0;
	char		*p, *tmpfile, *zoneroot;
	char		**file;
	char		zonepath[MAXPATHLEN];
	di_prof_t	prof = NULL;

	file = list->dmap_devarray;
	if (file == NULL)
		return (NODMAPERR);
	if ((zoneroot = getzonerootbyname(zonename)) == NULL) {
		dprintf("unable to get label for %s zone\n", zonename);
		return (1);
	}
	(void) strcpy(zonepath, zoneroot);
	free(zoneroot);
	len = strlen(zonepath);
	size = sizeof (zonepath);
	(void) strlcat(zonepath, "/dev", size);
	if (di_prof_init(zonepath, &prof)) {
		dprintf("failed to initialize dev profile at %s\n", zonepath);
		return (1);
	}
	zonepath[len] = '\0';
	for (; *file != NULL; file++) {
		/*
		 * First time initialization
		 */
		tmpfile = strdup(*file);

		/*
		 * Most devices have pathnames starting in /dev
		 * but SunRay devices do not. In SRRS 3.1 they use /tmp.
		 *
		 * If the device pathname is not in /dev then create
		 * a symbolic link to it and put the device in /dev
		 */
		if (strncmp(tmpfile, "/dev/", strlen("/dev/")) != 0) {
			char	*linkdir;
			char	srclinkdir[MAXPATHLEN];
			char	dstlinkdir[MAXPATHLEN];

			linkdir = strchr(tmpfile + 1, '/');
			p = strchr(linkdir + 1, '/');
			*p = '\0';
			(void) strcpy(dstlinkdir, "/dev");
			(void) strncat(dstlinkdir, linkdir, MAXPATHLEN);
			(void) snprintf(srclinkdir, MAXPATHLEN, "%s/root%s",
			    zonepath, tmpfile);
			(void) symlink(dstlinkdir, srclinkdir);
			*p = '/';
			(void) strncat(dstlinkdir, p, MAXPATHLEN);
			free(tmpfile);
			tmpfile = strdup(dstlinkdir);
		}
		if (di_prof_add_dev(prof, tmpfile)) {
			dprintf("failed to add %s to profile\n", tmpfile);
			di_prof_fini(prof);
			return (1);
		}
		if (strlcat(zonepath, tmpfile, size) >= size) {
			dprintf("Buffer overflow in create_znode for %s\n",
			    *file);
			free(tmpfile);
			di_prof_fini(prof);
			return (1);
		}
		free(tmpfile);
		fcount++;
		if ((zpath->path = (char **)realloc(zpath->path,
		    (fcount * sizeof (char *)))) == NULL) {
			di_prof_fini(prof);
			return (1);
		}
		zpath->path[zpath->count] = strdup(zonepath);
		zpath->count = fcount;
		zonepath[len] = '\0';
	}

	if (di_prof_commit(prof))
		dprintf("failed to add devices to zone %s\n", zonename);
	di_prof_fini(prof);

	return (0);
}

int
remove_znode(char *zonename, devmap_t *dm)
{
	int		len = 0;
	char		*zoneroot;
	char		**file;
	char		zonepath[MAXPATHLEN];
	di_prof_t	prof = NULL;

	file = dm->dmap_devarray;
	if (file == NULL)
		return (NODMAPERR);
	if ((zoneroot = getzonerootbyname(zonename)) == NULL) {
		(void) snprintf(zonepath, MAXPATHLEN, "/zone/%s", zonename);
	} else {
		(void)  strcpy(zonepath, zoneroot);
		free(zoneroot);
	}
	/*
	 * To support SunRay we will just deal with the
	 * file in /dev, not the symlinks.
	 */
	(void) strncat(zonepath, "/dev", MAXPATHLEN);
	len = strlen(zonepath);
	if (di_prof_init(zonepath, &prof)) {
		dprintf("failed to initialize dev profile at %s\n", zonepath);
		return (1);
	}
	for (; *file != NULL; file++) {
		char *devrelpath;

		/*
		 * remove device node from zone.
		 *
		 * SunRay devices don't start with /dev
		 * so skip over first directory to make
		 * sure it is /dev. SunRay devices in zones
		 * will have a symlink into /dev but
		 * we don't ever delete it.
		 */
		devrelpath = strchr(*file + 1, '/');

		if (di_prof_add_exclude(prof, devrelpath + 1)) {
			dprintf("Failed exclude %s in dev profile\n", *file);
			di_prof_fini(prof);
			return (1);
		}
		zonepath[len] = '\0';
	}

	if (di_prof_commit(prof))
		dprintf("failed to remove devices from zone %s\n", zonename);
	di_prof_fini(prof);
	return (0);
}

int
update_device(char **devnames, char *zonename, int flag)
{
	int		len, rc;
	char		*optstr = NULL;
	da_args		dargs;
	devinfo_t	devinfo;

	dargs.optflag = flag;
	dargs.optflag |= DA_UPDATE|DA_ALLOC_ONLY;
	dargs.rootdir = NULL;
	dargs.devnames = devnames;
	devinfo.devname = devinfo.devtype = devinfo.devauths = devinfo.devexec =
	    devinfo.devlist = NULL;
	if (dargs.optflag & DA_ADD_ZONE) {
		len = strlen(DAOPT_ZONE) + strlen(zonename) + 3;
		if ((optstr = (char *)malloc(len)) == NULL)
			return (-1);
		(void) snprintf(optstr, len, "%s%s%s", DAOPT_ZONE, KV_ASSIGN,
		    zonename);
		devinfo.devopts = optstr;
	}
	dargs.devinfo = &devinfo;

	rc = da_update_device(&dargs);

	if (optstr)
		free(optstr);

	return (rc);
}
