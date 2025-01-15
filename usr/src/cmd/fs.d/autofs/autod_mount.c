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
 *	autod_mount.c
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>
#include <pwd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/tiuser.h>
#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/fs/autofs.h>
#include <nfs/nfs.h>
#include <thread.h>
#include <limits.h>
#include <assert.h>
#include <fcntl.h>
#include <strings.h>

#include "automount.h"
#include "replica.h"

static int unmount_mntpnt(struct mnttab *);
static int call_fork_exec(char *, char *, char **, int);
static void remove_browse_options(char *);
static int inherit_options(char *, char **);

int
do_mount1(
	char *mapname,
	char *key,
	char *subdir,
	char *mapopts,
	char *path,
	uint_t isdirect,
	uid_t uid,
	action_list **alpp,
	int flags)
{
	struct mapline ml;
	struct mapent *me, *mapents = NULL;
	char mntpnt[MAXPATHLEN];
	char spec_mntpnt[MAXPATHLEN];
	int err = 0;
	char *private;	/* fs specific data. eg prevhost in case of nfs */
	int mount_ok = 0;
	ssize_t len;
	action_list *alp, *prev, *tmp;
	char root[MAXPATHLEN];
	int overlay = 1;
	char next_subdir[MAXPATHLEN];
	bool_t mount_access = TRUE;
	bool_t iswildcard;
	bool_t isrestricted = hasrestrictopt(mapopts);
	char *stack[STACKSIZ];
	char **stkptr = stack;

retry:
	iswildcard = FALSE;

	/* initialize the stack of open files for this thread */
	stack_op(INIT, NULL, stack, &stkptr);

	err = getmapent(key, mapname, &ml, stack, &stkptr, &iswildcard,
		isrestricted);
	if (err == 0) {
		mapents = parse_entry(key, mapname, mapopts, &ml,
				    subdir, isdirect, mount_access);
	}

	if (trace) {
		struct mapfs *mfs;
		trace_prt(1, "  do_mount1:\n");
		for (me = mapents; me; me = me->map_next) {
			trace_prt(1, "  (%s,%s)\t%s%s%s\n",
			me->map_fstype ? me->map_fstype : "",
			me->map_mounter ? me->map_mounter : "",
			path ? path : "",
			me->map_root  ? me->map_root : "",
			me->map_mntpnt ? me->map_mntpnt : "");
			trace_prt(0, "\t\t-%s\n",
			me->map_mntopts ? me->map_mntopts : "");

			for (mfs = me->map_fs; mfs; mfs = mfs->mfs_next)
				trace_prt(0, "\t\t%s:%s\tpenalty=%d\n",
					mfs->mfs_host ? mfs->mfs_host: "",
					mfs->mfs_dir ? mfs->mfs_dir : "",
					mfs->mfs_penalty);
		}
	}

	*alpp = NULL;

	/*
	 * Each mapent in the list describes a mount to be done.
	 * Normally there's just a single entry, though in the
	 * case of /net mounts there may be many entries, that
	 * must be mounted as a hierarchy.  For each mount the
	 * automountd must make sure the required mountpoint
	 * exists and invoke the appropriate mount command for
	 * the fstype.
	 */
	private = "";
	for (me = mapents; me && !err; me = me->map_next) {
		len = snprintf(mntpnt, sizeof (mntpnt), "%s%s%s", path,
		    mapents->map_root, me->map_mntpnt);

		if (len >= sizeof (mntpnt)) {
			free_mapent(mapents);
			return (ENAMETOOLONG);
		}
		/*
		 * remove trailing /'s from mountpoint to avoid problems
		 * stating a directory with two or more trailing slashes.
		 * This will let us mount directories from machines
		 * which export with two or more slashes (apollo for instance).
		 */
		len -= 1;
		while (mntpnt[len] == '/')
			mntpnt[len--] = '\0';

		(void) strcpy(spec_mntpnt, mntpnt);

		if (isrestricted &&
		    inherit_options(mapopts, &me->map_mntopts) != 0) {
			syslog(LOG_ERR, "malloc of options failed");
			free_mapent(mapents);
			return (EAGAIN);
		}

		if (strcmp(me->map_fstype, MNTTYPE_NFS) == 0) {
			remove_browse_options(me->map_mntopts);
			if (flags == DOMOUNT_KERNEL) {
				alp = (action_list *)malloc(
					sizeof (action_list));
				if (alp == NULL) {
					syslog(LOG_ERR,
						"malloc of alp failed");
					continue;
				}
				memset(alp, 0, sizeof (action_list));
			} else
				alp = NULL;
			err =
			    mount_nfs(me, spec_mntpnt, private, overlay, uid,
				    &alp);
			/*
			 * We must retry if we don't have access to the
			 * root file system and there are other
			 * following mapents. The reason we can't
			 * continue because the rest of the mapent list
			 * depends on whether mount_access is TRUE or FALSE.
			 */
			if (err == NFSERR_ACCES && me->map_next != NULL) {
				/*
				 * don't expect mount_access to be
				 * FALSE here, but we do a check
				 * anyway.
				 */
				if (mount_access == TRUE) {
					mount_access = FALSE;
					err = 0;
					free_mapent(mapents);
					if (alp) {
						free(alp);
						alp = NULL;
					}
					goto retry;
				}
			}
			if (alp) {
				if (*alpp == NULL)
					*alpp = alp;
				else {
					for (tmp = *alpp; tmp != NULL;
						tmp = tmp->next)
						prev = tmp;
					prev->next = alp;
				}
			}
			mount_ok = !err;
		} else if (strcmp(me->map_fstype, MNTTYPE_AUTOFS) == 0) {
			if (isdirect) {
				len = strlcpy(root, path, sizeof (root));
			} else {
				len = snprintf(root, sizeof (root), "%s/%s",
				    path, key);
			}
			if (len >= sizeof (root)) {
				free_mapent(mapents);
				return (ENAMETOOLONG);
			}

			alp = (action_list *)malloc(sizeof (action_list));
			if (alp == NULL) {
				syslog(LOG_ERR, "malloc of alp failed");
				continue;
			}
			memset(alp, 0, sizeof (action_list));

			/*
			 * get the next subidr, but only if its a modified
			 * or faked autofs mount
			 */
			if (me->map_modified || me->map_faked) {
				len = snprintf(next_subdir,
					sizeof (next_subdir), "%s%s", subdir,
					me->map_mntpnt);
			} else {
				next_subdir[0] = '\0';
				len = 0;
			}

			if (trace > 2)
				trace_prt(1, "  root=%s\t next_subdir=%s\n",
						root, next_subdir);
			if (len < sizeof (next_subdir)) {
				err = mount_autofs(me, spec_mntpnt, alp,
					root, next_subdir, key);
			} else {
				err = ENAMETOOLONG;
			}
			if (err == 0) {
				/*
				 * append to action list
				 */
				mount_ok++;
				if (*alpp == NULL)
					*alpp = alp;
				else {
					for (tmp = *alpp; tmp != NULL;
					    tmp = tmp->next)
						prev = tmp;
					prev->next = alp;
				}
			} else {
				free(alp);
				mount_ok = 0;
			}
		} else if (strcmp(me->map_fstype, MNTTYPE_LOFS) == 0) {
			remove_browse_options(me->map_mntopts);
			err = loopbackmount(me->map_fs->mfs_dir, spec_mntpnt,
					    me->map_mntopts, overlay);
			mount_ok = !err;
		} else {
			remove_browse_options(me->map_mntopts);
			err = mount_generic(me->map_fs->mfs_dir,
					    me->map_fstype, me->map_mntopts,
					    spec_mntpnt, overlay);
			mount_ok = !err;
		}
	}
	if (mapents)
		free_mapent(mapents);

	/*
	 * If an error occurred,
	 * the filesystem doesn't exist, or could not be
	 * mounted.  Return EACCES to autofs indicating that
	 * the mountpoint can not be accessed if this is not
	 * a wildcard access.  If it is a wildcard access we
	 * return ENOENT since the lookup that triggered
	 * this mount request will fail and the entry will not
	 * be available.
	 */
	if (mount_ok) {
		/*
		 * No error occurred, return 0 to indicate success.
		 */
		err = 0;
	} else {
		/*
		 * The filesystem does not exist or could not be mounted.
		 * Return ENOENT if the lookup was triggered by a wildcard
		 * access.  Wildcard entries only exist if they can be
		 * mounted.  They can not be listed otherwise (through
		 * a readdir(3C)).
		 * Return EACCES if the lookup was not triggered by a
		 * wildcard access.  Map entries that are explicitly defined
		 * in maps are visible via readdir(3C), therefore we return
		 * EACCES to indicate that the entry exists, but the directory
		 * can not be opened.  This is the same behavior of a Unix
		 * directory that exists, but has its execute bit turned off.
		 * The directory is there, but the user does not have access
		 * to it.
		 */
		if (iswildcard)
			err = ENOENT;
		else
			err = EACCES;
	}
	return (err);
}

#define	ARGV_MAX	16
#define	VFS_PATH	"/usr/lib/fs"

int
mount_generic(special, fstype, opts, mntpnt, overlay)
	char *special, *fstype, *opts, *mntpnt;
	int overlay;
{
	struct mnttab m;
	struct stat stbuf;
	int i, res;
	char *newargv[ARGV_MAX];

	if (trace > 1) {
		trace_prt(1, "  mount: %s %s %s %s\n",
			special, mntpnt, fstype, opts);
	}

	if (stat(mntpnt, &stbuf) < 0) {
		syslog(LOG_ERR, "Couldn't stat %s: %m", mntpnt);
		return (ENOENT);
	}

	i = 2;

	if (overlay)
		newargv[i++] = "-O";

	/*
	 *  Use "quiet" option to suppress warnings about unsupported
	 *  mount options.
	 */
	newargv[i++] = "-q";

	if (opts && *opts) {
		m.mnt_mntopts = opts;
		if (hasmntopt(&m, MNTOPT_RO) != NULL)
			newargv[i++] = "-r";
		newargv[i++] = "-o";
		newargv[i++] = opts;
	}
	newargv[i++] = "--";
	newargv[i++] = special;
	newargv[i++] = mntpnt;
	newargv[i] = NULL;
	res = call_fork_exec(fstype, "mount", newargv, verbose);
	if (res == 0 && trace > 1) {
		if (stat(mntpnt, &stbuf) == 0) {
			trace_prt(1, "  mount of %s dev=%x rdev=%x OK\n",
				mntpnt, stbuf.st_dev, stbuf.st_rdev);
		} else {
			trace_prt(1, "  failed to stat %s\n", mntpnt);
		}
	}
	return (res);
}

void
automountd_do_fork_exec(void *cookie, char *argp, size_t arg_size,
		door_desc_t *dfd, uint_t n_desc)
{
	int stat_loc;
	int fd = 0;
	struct stat stbuf;
	int res;
	int child_pid;
	command_t *command;
	char *newargv[ARGV_MAX];
	int i;


	command = (command_t *)argp;
	if (sizeof (*command) != arg_size) {
		res = EINVAL;
		door_return((char *)&res, sizeof (res), NULL, 0);
	}

	switch ((child_pid = fork1())) {
	case -1:
		syslog(LOG_ERR, "Cannot fork: %m");
		res = errno;
		break;
	case 0:
		/*
		 * Child
		 */
		(void) setsid();
		fd = open(command->console ? "/dev/console" : "/dev/null",
			    O_WRONLY);
		if (fd != -1) {
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
			(void) close(fd);
		}

		for (i = 0; *command->argv[i]; i++) {
			newargv[i] = strdup(command->argv[i]);
			if (newargv[i] == (char *)NULL) {
				syslog(LOG_ERR, "failed to copy argument '%s'"
				    " of %s: %m", command->argv[i],
				    command->file);
				_exit(errno);
			}
		}
		newargv[i] = NULL;

		(void) execv(command->file, newargv);
		if (errno == EACCES)
			syslog(LOG_ERR, "exec %s: %m", command->file);

		_exit(errno);
	default:
		/*
		 * Parent
		 */
		(void) waitpid(child_pid, &stat_loc, WUNTRACED);

		if (WIFEXITED(stat_loc)) {
			if (trace > 1) {
				trace_prt(1,
				    "  fork_exec: returns exit status %d\n",
				    WEXITSTATUS(stat_loc));
			}

			res = WEXITSTATUS(stat_loc);
		} else if (WIFSIGNALED(stat_loc)) {
			if (trace > 1)
				trace_prt(1,
				    "  fork_exec: returns signal status %d\n",
				    WTERMSIG(stat_loc));
			res = 1;
		} else {
			if (trace > 1)
				trace_prt(1,
				    "  fork_exec: returns unknown status\n");
			res = 1;
		}

	}
	door_return((char *)&res, sizeof (res), NULL, 0);
	trace_prt(1, "automountd_do_fork_exec, door return failed %s, %s\n",
	    command->file, strerror(errno));
	door_return(NULL, 0, NULL, 0);
}

int
do_unmount1(ur)
	umntrequest *ur;
{

	struct mnttab m;
	int res = 0;

	m.mnt_special = ur->mntresource;
	m.mnt_mountp = ur->mntpnt;
	m.mnt_fstype = ur->fstype;
	m.mnt_mntopts = ur->mntopts;
	/*
	 * Special case for NFS mounts.
	 * Don't want to attempt unmounts from
	 * a dead server.  If any member of a
	 * hierarchy belongs to a dead server
	 * give up (try later).
	 */
	if (strcmp(ur->fstype, MNTTYPE_NFS) == 0) {
		struct replica *list;
		int i, n;
		bool_t pubopt = FALSE;
		int nfs_port;
		int got_port;

		/*
		 * See if a port number was specified.  If one was
		 * specified that is too large to fit in 16 bits, truncate
		 * the high-order bits (for historical compatibility).  Use
		 * zero to indicate "no port specified".
		 */
		got_port = nopt(&m, MNTOPT_PORT, &nfs_port);
		if (!got_port)
			nfs_port = 0;
		nfs_port &= USHRT_MAX;

		if (hasmntopt(&m, MNTOPT_PUBLIC))
			pubopt = TRUE;

		list = parse_replica(ur->mntresource, &n);
		if (list == NULL) {
			if (n >= 0)
				syslog(LOG_ERR, "Memory allocation failed: %m");
			res = 1;
			goto done;
		}

		for (i = 0; i < n; i++) {
			if (pingnfs(list[i].host, 1, NULL, 0, nfs_port,
			    pubopt, list[i].path, NULL) != RPC_SUCCESS) {
				res = 1;
				free_replica(list, n);
				goto done;
			}
		}
		free_replica(list, n);
	}

	res = unmount_mntpnt(&m);

done:	return (res);
}

static int
unmount_mntpnt(mnt)
	struct mnttab *mnt;
{
	char *fstype = mnt->mnt_fstype;
	char *mountp = mnt->mnt_mountp;
	char *newargv[ARGV_MAX];
	int res;

	if (strcmp(fstype, MNTTYPE_NFS) == 0) {
		res = nfsunmount(mnt);
	} else if (strcmp(fstype, MNTTYPE_LOFS) == 0) {
		if ((res = umount(mountp)) < 0)
			res = errno;
	} else {
		newargv[2] = mountp;
		newargv[3] = NULL;

		res = call_fork_exec(fstype, "umount", newargv, verbose);
		if (res == ENOENT) {
			/*
			 * filesystem specific unmount command not found
			 */
			if ((res = umount(mountp)) < 0)
				res = errno;
		}
	}

	if (trace > 1)
		trace_prt(1, "  unmount %s %s\n",
			mountp, res ? "failed" : "OK");
	return (res);
}

/*
 * Remove the autofs specific options 'browse', 'nobrowse' and
 * 'restrict' from 'opts'.
 */
static void
remove_browse_options(char *opts)
{
	char *p, *pb;
	char buf[MAXOPTSLEN], new[MAXOPTSLEN];
	char *placeholder;

	new[0] = '\0';
	(void) strcpy(buf, opts);
	pb = buf;
	while (p = (char *)strtok_r(pb, ",", &placeholder)) {
		pb = NULL;
		if (strcmp(p, MNTOPT_NOBROWSE) != 0 &&
		    strcmp(p, MNTOPT_BROWSE) != 0 &&
		    strcmp(p, MNTOPT_RESTRICT) != 0) {
			if (new[0] != '\0')
				(void) strcat(new, ",");
			(void) strcat(new, p);
		}
	}
	(void) strcpy(opts, new);
}

static const char *restropts[] = {
	RESTRICTED_MNTOPTS
};
#define	NROPTS	(sizeof (restropts)/sizeof (restropts[0]))

static int
inherit_options(char *opts, char **mapentopts)
{
	int i;
	char *new;
	struct mnttab mtmap;
	struct mnttab mtopt;

	size_t len = strlen(*mapentopts);

	for (i = 0; i < NROPTS; i++)
		len += strlen(restropts[i]);

	/* "," for each new option plus the trailing NUL */
	len += NROPTS + 1;

	new = malloc(len);
	if (new == 0)
		return (-1);

	(void) strcpy(new, *mapentopts);

	mtmap.mnt_mntopts = *mapentopts;
	mtopt.mnt_mntopts = opts;

	for (i = 0; i < NROPTS; i++) {
		if (hasmntopt(&mtopt, (char *)restropts[i]) != NULL &&
		    hasmntopt(&mtmap, (char *)restropts[i]) == NULL) {
			if (*new != '\0')
				(void) strcat(new, ",");
			(void) strcat(new, restropts[i]);
		}
	}
	free(*mapentopts);
	*mapentopts = new;
	return (0);
}

bool_t
hasrestrictopt(char *opts)
{
	struct mnttab mt;

	mt.mnt_mntopts = opts;

	return (hasmntopt(&mt, MNTOPT_RESTRICT) != NULL);
}

static int
call_fork_exec(fstype, cmd, newargv, console)
	char *fstype;
	char *cmd;
	char **newargv;
	int console;
{
	command_t command;
	door_arg_t darg;
	char path[MAXPATHLEN];
	struct stat stbuf;
	int ret;
	int sz;
	int status;
	int i;

	bzero(&command, sizeof (command));
	/* build the full path name of the fstype dependent command */
	(void) snprintf(path, MAXPATHLEN, "%s/%s/%s", VFS_PATH, fstype, cmd);

	if (stat(path, &stbuf) != 0) {
		ret = errno;
		return (ret);
	}

	strlcpy(command.file, path, MAXPATHLEN);
	strlcpy(command.argv[0], path, MAXOPTSLEN);
	for (i = 2; newargv[i]; i++) {
		strlcpy(command.argv[i-1], newargv[i], MAXOPTSLEN);
	}
	if (trace > 1) {
		trace_prt(1, "  call_fork_exec: %s ", command.file);
		for (i = 0; *command.argv[i]; i++)
			trace_prt(0, "%s ", command.argv[i]);
		trace_prt(0, "\n");
	}

	command.console = console;

	darg.data_ptr = (char *)&command;
	darg.data_size = sizeof (command);
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = (char *)&status;
	darg.rsize = sizeof (status);

	ret = door_call(did_fork_exec, &darg);
	if (trace > 1) {
		trace_prt(1, "  call_fork_exec: door_call failed %d\n", ret);
	}

	return (status);
}
