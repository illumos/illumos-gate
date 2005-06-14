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

/*
 * This module contains functions used to bring up and tear down the
 * Virtual Platform: [un]mounting file-systems, [un]plumbing network
 * interfaces, [un]configuring devices, establishing resource controls,
 * and creating/destroying the zone in the kernel.  These actions, on
 * the way up, ready the zone; on the way down, they halt the zone.
 * See the much longer block comment at the beginning of zoneadmd.c
 * for a bigger picture of how the whole program functions.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sockio.h>
#include <sys/stropts.h>
#include <sys/conf.h>

#include <inet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/route.h>
#include <netdb.h>

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <rctl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wait.h>
#include <limits.h>
#include <libgen.h>
#include <zone.h>
#include <assert.h>

#include <sys/mntio.h>
#include <sys/mnttab.h>
#include <sys/fs/autofs.h>	/* for _autofssys() */
#include <sys/fs/lofs_info.h>

#include <pool.h>
#include <sys/pool.h>

#include <libzonecfg.h>
#include "zoneadmd.h"

#define	V4_ADDR_LEN	32
#define	V6_ADDR_LEN	128

/* 0755 is the default directory mode. */
#define	DEFAULT_DIR_MODE \
	(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

#define	IPD_DEFAULT_OPTS \
	MNTOPT_RO "," MNTOPT_LOFS_NOSUB "," MNTOPT_NODEVICES

#define	DFSTYPES	"/etc/dfs/fstypes"

/*
 * A list of directories which should be created.
 */

struct dir_info {
	char *dir_name;
	mode_t dir_mode;
};

/*
 * The pathnames below are relative to the zonepath
 */
static struct dir_info dev_dirs[] = {
	{ "/dev",	0755 },
	{ "/dev/dsk",	0755 },
	{ "/dev/fd",	0555 },
	{ "/dev/pts",	0755 },
	{ "/dev/rdsk",	0755 },
	{ "/dev/rmt",	0755 },
	{ "/dev/sad",	0755 },
	{ "/dev/swap",	0755 },
	{ "/dev/term",	0755 },
};

/*
 * A list of devices which should be symlinked to /dev/zconsole.
 */

struct symlink_info {
	char *sl_source;
	char *sl_target;
};

/*
 * The "source" paths are relative to the zonepath
 */
static struct symlink_info dev_symlinks[] = {
	{ "/dev/stderr",	"./fd/2" },
	{ "/dev/stdin",		"./fd/0" },
	{ "/dev/stdout",	"./fd/1" },
	{ "/dev/dtremote",	"/dev/null" },
	{ "/dev/console",	"zconsole" },
	{ "/dev/syscon",	"zconsole" },
	{ "/dev/sysmsg",	"zconsole" },
	{ "/dev/systty",	"zconsole" },
	{ "/dev/msglog",	"zconsole" },
};

/* for routing socket */
static int rts_seqno = 0;

/* from libsocket, not in any header file */
extern int getnetmaskbyaddr(struct in_addr, struct in_addr *);

/*
 * Private autofs system call
 */
extern int _autofssys(int, void *);

static int
autofs_cleanup(zoneid_t zoneid)
{
	/*
	 * Ask autofs to unmount all trigger nodes in the given zone.
	 */
	return (_autofssys(AUTOFS_UNMOUNTALL, (void *)zoneid));
}

static int
make_one_dir(zlog_t *zlogp, const char *prefix, const char *subdir, mode_t mode)
{
	char path[MAXPATHLEN];
	struct stat st;

	if (snprintf(path, sizeof (path), "%s%s", prefix, subdir) >
	    sizeof (path)) {
		zerror(zlogp, B_FALSE, "pathname %s%s is too long", prefix,
		    subdir);
		return (-1);
	}

	if (lstat(path, &st) == 0) {
		/*
		 * We don't check the file mode since presumably the zone
		 * administrator may have had good reason to change the mode,
		 * and we don't need to second guess him.
		 */
		if (!S_ISDIR(st.st_mode)) {
			zerror(zlogp, B_FALSE, "%s is not a directory", path);
			return (-1);
		}
	} else if (mkdirp(path, mode) != 0) {
		if (errno == EROFS)
			zerror(zlogp, B_FALSE, "Could not mkdir %s.\nIt is on "
			    "a read-only file system in this local zone.\nMake "
			    "sure %s exists in the global zone.", path, subdir);
		else
			zerror(zlogp, B_TRUE, "mkdirp of %s failed", path);
		return (-1);
	}
	return (0);
}

/*
 * Make /dev and various directories underneath it.
 */
static int
make_dev_dirs(zlog_t *zlogp, const char *zonepath)
{
	int i;

	for (i = 0; i < sizeof (dev_dirs) / sizeof (struct dir_info); i++) {
		if (make_one_dir(zlogp, zonepath, dev_dirs[i].dir_name,
		    dev_dirs[i].dir_mode) != 0)
			return (-1);
	}
	return (0);
}

/*
 * Make various sym-links underneath /dev.
 */
static int
make_dev_links(zlog_t *zlogp, char *zonepath)
{
	int i;

	for (i = 0; i < sizeof (dev_symlinks) / sizeof (struct symlink_info);
	    i++) {
		char dev[MAXPATHLEN];
		struct stat st;

		(void) snprintf(dev, sizeof (dev), "%s%s", zonepath,
		    dev_symlinks[i].sl_source);
		if (lstat(dev, &st) == 0) {
			/*
			 * Try not to call unlink(2) on directories, since that
			 * makes UFS unhappy.
			 */
			if (S_ISDIR(st.st_mode)) {
				zerror(zlogp, B_FALSE, "symlink path %s is a "
				    "directory", dev_symlinks[i].sl_source);
				return (-1);
			}
			(void) unlink(dev);
		}
		if (symlink(dev_symlinks[i].sl_target, dev) != 0) {
			zerror(zlogp, B_TRUE, "could not setup %s symlink",
			    dev_symlinks[i].sl_source);
			return (-1);
		}
	}
	return (0);
}

/*
 * Create various directories and sym-links under /dev.
 */
static int
create_dev_files(zlog_t *zlogp)
{
	char zonepath[MAXPATHLEN];

	if (zone_get_zonepath(zone_name, zonepath, sizeof (zonepath)) != Z_OK) {
		zerror(zlogp, B_TRUE, "unable to determine zone root");
		return (-1);
	}

	if (make_dev_dirs(zlogp, zonepath) != 0)
		return (-1);
	if (make_dev_links(zlogp, zonepath) != 0)
		return (-1);
	return (0);
}

static void
free_remote_fstypes(char **types)
{
	uint_t i;

	if (types == NULL)
		return;
	for (i = 0; types[i] != NULL; i++)
		free(types[i]);
	free(types);
}

static char **
get_remote_fstypes(zlog_t *zlogp)
{
	char **types = NULL;
	FILE *fp;
	char buf[MAXPATHLEN];
	char fstype[MAXPATHLEN];
	uint_t lines = 0;
	uint_t i;

	if ((fp = fopen(DFSTYPES, "r")) == NULL) {
		zerror(zlogp, B_TRUE, "failed to open %s", DFSTYPES);
		return (NULL);
	}
	/*
	 * Count the number of lines
	 */
	while (fgets(buf, sizeof (buf), fp) != NULL)
		lines++;
	if (lines == 0)	/* didn't read anything; empty file */
		goto out;
	rewind(fp);
	/*
	 * Allocate enough space for a NULL-terminated array.
	 */
	types = calloc(lines + 1, sizeof (char *));
	if (types == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		goto out;
	}
	i = 0;
	while (fgets(buf, sizeof (buf), fp) != NULL) {
		/* LINTED - fstype is big enough to hold buf */
		if (sscanf(buf, "%s", fstype) == 0) {
			zerror(zlogp, B_FALSE, "unable to parse %s", DFSTYPES);
			free_remote_fstypes(types);
			types = NULL;
			goto out;
		}
		types[i] = strdup(fstype);
		if (types[i] == NULL) {
			zerror(zlogp, B_TRUE, "memory allocation failed");
			free_remote_fstypes(types);
			types = NULL;
			goto out;
		}
		i++;
	}
out:
	(void) fclose(fp);
	return (types);
}

static boolean_t
is_remote_fstype(const char *fstype, char *const *remote_fstypes)
{
	uint_t i;

	if (remote_fstypes == NULL)
		return (B_FALSE);
	for (i = 0; remote_fstypes[i] != NULL; i++) {
		if (strcmp(remote_fstypes[i], fstype) == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

static void
free_mnttable(struct mnttab *mnt_array, uint_t nelem)
{
	uint_t i;

	if (mnt_array == NULL)
		return;
	for (i = 0; i < nelem; i++) {
		free(mnt_array[i].mnt_mountp);
		free(mnt_array[i].mnt_fstype);
		assert(mnt_array[i].mnt_special == NULL);
		assert(mnt_array[i].mnt_mntopts == NULL);
		assert(mnt_array[i].mnt_time == NULL);
	}
	free(mnt_array);
}

/*
 * Build the mount table for the zone rooted at "zroot", storing the resulting
 * array of struct mnttabs in "mnt_arrayp" and the number of elements in the
 * array in "nelemp".
 */
static int
build_mnttable(zlog_t *zlogp, const char *zroot, size_t zrootlen, FILE *mnttab,
    struct mnttab **mnt_arrayp, uint_t *nelemp)
{
	struct mnttab mnt;
	struct mnttab *mnts;
	struct mnttab *mnp;
	uint_t nmnt;

	rewind(mnttab);
	resetmnttab(mnttab);
	nmnt = 0;
	mnts = NULL;
	while (getmntent(mnttab, &mnt) == 0) {
		struct mnttab *tmp_array;

		if (strncmp(mnt.mnt_mountp, zroot, zrootlen) != 0)
			continue;
		nmnt++;
		tmp_array = realloc(mnts, nmnt * sizeof (*mnts));
		if (tmp_array == NULL) {
			nmnt--;
			free_mnttable(mnts, nmnt);
			return (-1);
		}
		mnts = tmp_array;
		mnp = &mnts[nmnt - 1];
		/*
		 * Zero out the fields we won't be using.
		 */
		mnp->mnt_special = NULL;
		mnp->mnt_mntopts = NULL;
		mnp->mnt_time = NULL;

		mnp->mnt_mountp = strdup(mnt.mnt_mountp);
		mnp->mnt_fstype = strdup(mnt.mnt_fstype);
		if (mnp->mnt_mountp == NULL ||
		    mnp->mnt_fstype == NULL) {
			zerror(zlogp, B_TRUE, "memory allocation failed");
			free_mnttable(mnts, nmnt);
			return (-1);
		}
	}
	*mnt_arrayp = mnts;
	*nelemp = nmnt;
	return (0);
}

/*
 * The general strategy for unmounting filesystems is as follows:
 *
 * - Remote filesystems may be dead, and attempting to contact them as
 * part of a regular unmount may hang forever; we want to always try to
 * forcibly unmount such filesystems and only fall back to regular
 * unmounts if the filesystem doesn't support forced unmounts.
 *
 * - We don't want to unnecessarily corrupt metadata on local
 * filesystems (ie UFS), so we want to start off with graceful unmounts,
 * and only escalate to doing forced unmounts if we get stuck.
 *
 * We start off walking backwards through the mount table.  This doesn't
 * give us strict ordering but ensures that we try to unmount submounts
 * first.  We thus limit the number of failed umount2(2) calls.
 *
 * The mechanism for determining if we're stuck is to count the number
 * of failed unmounts each iteration through the mount table.  This
 * gives us an upper bound on the number of filesystems which remain
 * mounted (autofs trigger nodes are dealt with separately).  If at the
 * end of one unmount+autofs_cleanup cycle we still have the same number
 * of mounts that we started out with, we're stuck and try a forced
 * unmount.  If that fails (filesystem doesn't support forced unmounts)
 * then we bail and are unable to teardown the zone.  If it succeeds,
 * we're no longer stuck so we continue with our policy of trying
 * graceful mounts first.
 *
 * Zone must be down (ie, no processes or threads active).
 */
static int
unmount_filesystems(zlog_t *zlogp)
{
	zoneid_t zoneid;
	int error = 0;
	FILE *mnttab;
	struct mnttab *mnts;
	uint_t nmnt;
	char zroot[MAXPATHLEN + 1];
	size_t zrootlen;
	uint_t oldcount = UINT_MAX;
	boolean_t stuck = B_FALSE;
	char **remote_fstypes = NULL;

	if ((zoneid = getzoneidbyname(zone_name)) == -1) {
		zerror(zlogp, B_TRUE, "unable to find zoneid");
		return (-1);
	}

	if (zone_get_rootpath(zone_name, zroot, sizeof (zroot)) != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to determine zone root");
		return (-1);
	}

	(void) strcat(zroot, "/");
	zrootlen = strlen(zroot);

	if ((mnttab = fopen(MNTTAB, "r")) == NULL) {
		zerror(zlogp, B_TRUE, "failed to open %s", MNTTAB);
		return (-1);
	}
	/*
	 * Use our hacky mntfs ioctl so we see everything, even mounts with
	 * MS_NOMNTTAB.
	 */
	if (ioctl(fileno(mnttab), MNTIOC_SHOWHIDDEN, NULL) < 0) {
		zerror(zlogp, B_TRUE, "unable to configure %s", MNTTAB);
		error++;
		goto out;
	}

	/*
	 * Build the list of remote fstypes so we know which ones we
	 * should forcibly unmount.
	 */
	remote_fstypes = get_remote_fstypes(zlogp);
	for (; /* ever */; ) {
		uint_t newcount = 0;
		boolean_t unmounted;
		struct mnttab *mnp;
		char *path;
		uint_t i;

		mnts = NULL;
		nmnt = 0;
		/*
		 * MNTTAB gives us a way to walk through mounted
		 * filesystems; we need to be able to walk them in
		 * reverse order, so we build a list of all mounted
		 * filesystems.
		 */
		if (build_mnttable(zlogp, zroot, zrootlen, mnttab, &mnts,
		    &nmnt) != 0) {
			error++;
			goto out;
		}
		for (i = 0; i < nmnt; i++) {
			mnp = &mnts[nmnt - i - 1]; /* access in reverse order */
			path = mnp->mnt_mountp;
			unmounted = B_FALSE;
			/*
			 * Try forced unmount first for remote filesystems.
			 *
			 * Not all remote filesystems support forced unmounts,
			 * so if this fails (ENOTSUP) we'll continue on
			 * and try a regular unmount.
			 */
			if (is_remote_fstype(mnp->mnt_fstype, remote_fstypes)) {
				if (umount2(path, MS_FORCE) == 0)
					unmounted = B_TRUE;
			}
			/*
			 * Try forced unmount if we're stuck.
			 */
			if (stuck) {
				if (umount2(path, MS_FORCE) == 0) {
					unmounted = B_TRUE;
					stuck = B_FALSE;
				} else {
					/*
					 * The first failure indicates a
					 * mount we won't be able to get
					 * rid of automatically, so we
					 * bail.
					 */
					error++;
					zerror(zlogp, B_FALSE,
					    "unable to unmount '%s'", path);
					free_mnttable(mnts, nmnt);
					goto out;
				}
			}
			/*
			 * Try regular unmounts for everything else.
			 */
			if (!unmounted && umount2(path, 0) != 0)
				newcount++;
		}
		free_mnttable(mnts, nmnt);

		if (newcount == 0)
			break;
		if (newcount >= oldcount) {
			/*
			 * Last round didn't unmount anything; we're stuck and
			 * should start trying forced unmounts.
			 */
			stuck = B_TRUE;
		}
		oldcount = newcount;

		/*
		 * Autofs doesn't let you unmount its trigger nodes from
		 * userland so we have to tell the kernel to cleanup for us.
		 */
		if (autofs_cleanup(zoneid) != 0) {
			zerror(zlogp, B_TRUE, "unable to remove autofs nodes");
			error++;
			goto out;
		}
	}

out:
	free_remote_fstypes(remote_fstypes);
	(void) fclose(mnttab);
	return (error ? -1 : 0);
}

static int
fs_compare(const void *m1, const void *m2)
{
	struct zone_fstab *i = (struct zone_fstab *)m1;
	struct zone_fstab *j = (struct zone_fstab *)m2;

	return (strcmp(i->zone_fs_dir, j->zone_fs_dir));
}

/*
 * Fork and exec (and wait for) the mentioned binary with the provided
 * arguments.  Returns (-1) if something went wrong with fork(2) or exec(2),
 * returns the exit status otherwise.
 *
 * If we were unable to exec the provided pathname (for whatever
 * reason), we return the special token ZEXIT_EXEC.  The current value
 * of ZEXIT_EXEC doesn't conflict with legitimate exit codes of the
 * consumers of this function; any future consumers must make sure this
 * remains the case.
 */
static int
forkexec(zlog_t *zlogp, const char *path, char *const argv[])
{
	pid_t child_pid;
	int child_status = 0;

	/*
	 * Do not let another thread localize a message while we are forking.
	 */
	(void) mutex_lock(&msglock);
	child_pid = fork();
	(void) mutex_unlock(&msglock);
	if (child_pid == -1) {
		zerror(zlogp, B_TRUE, "could not fork for %s", argv[0]);
		return (-1);
	} else if (child_pid == 0) {
		closefrom(0);
		(void) execv(path, argv);
		/*
		 * Since we are in the child, there is no point calling zerror()
		 * since there is nobody waiting to consume it.  So exit with a
		 * special code that the parent will recognize and call zerror()
		 * accordingly.
		 */

		_exit(ZEXIT_EXEC);
	} else {
		(void) waitpid(child_pid, &child_status, 0);
	}

	if (WIFSIGNALED(child_status)) {
		zerror(zlogp, B_FALSE, "%s unexpectedly terminated due to "
		    "signal %d", path, WTERMSIG(child_status));
		return (-1);
	}
	assert(WIFEXITED(child_status));
	if (WEXITSTATUS(child_status) == ZEXIT_EXEC) {
		zerror(zlogp, B_FALSE, "failed to exec %s", path);
		return (-1);
	}
	return (WEXITSTATUS(child_status));
}

static int
dofsck(zlog_t *zlogp, const char *fstype, const char *rawdev)
{
	char cmdbuf[MAXPATHLEN];
	char *argv[4];
	int status;

	/*
	 * We could alternatively have called /usr/sbin/fsck -F <fstype>, but
	 * that would cost us an extra fork/exec without buying us anything.
	 */
	if (snprintf(cmdbuf, sizeof (cmdbuf), "/usr/lib/fs/%s/fsck", fstype)
	    > sizeof (cmdbuf)) {
		zerror(zlogp, B_FALSE, "file-system type %s too long", fstype);
		return (-1);
	}

	argv[0] = "fsck";
	argv[1] = "-m";
	argv[2] = (char *)rawdev;
	argv[3] = NULL;

	status = forkexec(zlogp, cmdbuf, argv);
	if (status == 0 || status == -1)
		return (status);
	zerror(zlogp, B_FALSE, "fsck of '%s' failed with exit status %d; "
	    "run fsck manually", rawdev, status);
	return (-1);
}

static int
domount(zlog_t *zlogp, const char *fstype, const char *opts,
    const char *special, const char *directory)
{
	char cmdbuf[MAXPATHLEN];
	char *argv[6];
	int status;

	/*
	 * We could alternatively have called /usr/sbin/mount -F <fstype>, but
	 * that would cost us an extra fork/exec without buying us anything.
	 */
	if (snprintf(cmdbuf, sizeof (cmdbuf), "/usr/lib/fs/%s/mount", fstype)
	    > sizeof (cmdbuf)) {
		zerror(zlogp, B_FALSE, "file-system type %s too long", fstype);
		return (-1);
	}
	argv[0] = "mount";
	if (opts[0] == '\0') {
		argv[1] = (char *)special;
		argv[2] = (char *)directory;
		argv[3] = NULL;
	} else {
		argv[1] = "-o";
		argv[2] = (char *)opts;
		argv[3] = (char *)special;
		argv[4] = (char *)directory;
		argv[5] = NULL;
	}

	status = forkexec(zlogp, cmdbuf, argv);
	if (status == 0 || status == -1)
		return (status);
	if (opts[0] == '\0')
		zerror(zlogp, B_FALSE, "\"%s %s %s\" "
		    "failed with exit code %d",
		    cmdbuf, special, directory, status);
	else
		zerror(zlogp, B_FALSE, "\"%s -o %s %s %s\" "
		    "failed with exit code %d",
		    cmdbuf, opts, special, directory, status);
	return (-1);
}

/*
 * Make sure if a given path exists, it is not a sym-link, and is a directory.
 */
static int
check_path(zlog_t *zlogp, const char *path)
{
	struct stat statbuf;
	char respath[MAXPATHLEN];
	int res;

	if (lstat(path, &statbuf) != 0) {
		if (errno == ENOENT)
			return (0);
		zerror(zlogp, B_TRUE, "can't stat %s", path);
		return (-1);
	}
	if (S_ISLNK(statbuf.st_mode)) {
		zerror(zlogp, B_FALSE, "%s is a symlink", path);
		return (-1);
	}
	if (!S_ISDIR(statbuf.st_mode)) {
		zerror(zlogp, B_FALSE, "%s is not a directory", path);
		return (-1);
	}
	if ((res = resolvepath(path, respath, sizeof (respath))) == -1) {
		zerror(zlogp, B_TRUE, "unable to resolve path %s", path);
		return (-1);
	}
	respath[res] = '\0';
	if (strcmp(path, respath) != 0) {
		/*
		 * We don't like ".."s and "."s throwing us off
		 */
		zerror(zlogp, B_FALSE, "%s is not a canonical path", path);
		return (-1);
	}
	return (0);
}

/*
 * Check every component of rootpath/relpath.  If any component fails (ie,
 * exists but isn't the canonical path to a directory), it is returned in
 * badpath, which is assumed to be at least of size MAXPATHLEN.
 *
 * Relpath must begin with '/'.
 */
static boolean_t
valid_mount_path(zlog_t *zlogp, const char *rootpath, const char *relpath)
{
	char abspath[MAXPATHLEN], *slashp;

	/*
	 * Make sure abspath has at least one '/' after its rootpath
	 * component, and ends with '/'.
	 */
	if (snprintf(abspath, sizeof (abspath), "%s%s/", rootpath, relpath) >
	    sizeof (abspath)) {
		zerror(zlogp, B_FALSE, "pathname %s%s is too long", rootpath,
		    relpath);
		return (B_FALSE);
	}

	slashp = &abspath[strlen(rootpath)];
	assert(*slashp == '/');
	do {
		*slashp = '\0';
		if (check_path(zlogp, abspath) != 0)
			return (B_FALSE);
		*slashp = '/';
		slashp++;
	} while ((slashp = strchr(slashp, '/')) != NULL);
	return (B_TRUE);
}

static int
mount_one(zlog_t *zlogp, struct zone_fstab *fsptr, const char *rootpath)
{
	char    path[MAXPATHLEN];
	char    optstr[MAX_MNTOPT_STR];
	zone_fsopt_t *optptr;

	if (!valid_mount_path(zlogp, rootpath, fsptr->zone_fs_dir)) {
		zerror(zlogp, B_FALSE, "%s%s is not a valid mount point",
		    rootpath, fsptr->zone_fs_dir);
		return (-1);
	}

	if (make_one_dir(zlogp, rootpath, fsptr->zone_fs_dir,
	    DEFAULT_DIR_MODE) != 0)
		return (-1);

	(void) snprintf(path, sizeof (path), "%s%s", rootpath,
	    fsptr->zone_fs_dir);

	if (strlen(fsptr->zone_fs_special) == 0) {
		/*
		 * A zero-length special is how we distinguish IPDs from
		 * general-purpose FSs.
		 */
		if (domount(zlogp, MNTTYPE_LOFS, IPD_DEFAULT_OPTS,
		    fsptr->zone_fs_dir, path) != 0) {
			zerror(zlogp, B_TRUE, "failed to loopback mount %s",
			    fsptr->zone_fs_dir);
			return (-1);
		}
		return (0);
	}

	/*
	 * In general the strategy here is to do just as much verification as
	 * necessary to avoid crashing or otherwise doing something bad; if the
	 * administrator initiated the operation via zoneadm(1m), he'll get
	 * auto-verification which will let him know what's wrong.  If he
	 * modifies the zone configuration of a running zone and doesn't attempt
	 * to verify that it's OK we won't crash but won't bother trying to be
	 * too helpful either.  zoneadm verify is only a couple keystrokes away.
	 */
	if (!zonecfg_valid_fs_type(fsptr->zone_fs_type)) {
		zerror(zlogp, B_FALSE, "cannot mount %s on %s: "
		    "invalid file-system type %s", fsptr->zone_fs_special,
		    fsptr->zone_fs_dir, fsptr->zone_fs_type);
		return (-1);
	}

	/*
	 * Run 'fsck -m' if there's a device to fsck.
	 */
	if (fsptr->zone_fs_raw[0] != '\0' &&
	    dofsck(zlogp, fsptr->zone_fs_type, fsptr->zone_fs_raw) != 0)
		return (-1);

	/*
	 * Build up mount option string.
	 */
	optstr[0] = '\0';
	if (fsptr->zone_fs_options != NULL) {
		(void) strlcpy(optstr, fsptr->zone_fs_options->zone_fsopt_opt,
		    sizeof (optstr));
		for (optptr = fsptr->zone_fs_options->zone_fsopt_next;
		    optptr != NULL; optptr = optptr->zone_fsopt_next) {
			(void) strlcat(optstr, ",", sizeof (optstr));
			(void) strlcat(optstr, optptr->zone_fsopt_opt,
			    sizeof (optstr));
		}
	}
	return (domount(zlogp, fsptr->zone_fs_type, optstr,
	    fsptr->zone_fs_special, path));
}

static void
free_fs_data(struct zone_fstab *fsarray, uint_t nelem)
{
	uint_t i;

	if (fsarray == NULL)
		return;
	for (i = 0; i < nelem; i++)
		zonecfg_free_fs_option_list(fsarray[i].zone_fs_options);
	free(fsarray);
}

static int
mount_filesystems(zlog_t *zlogp)
{
	char	rootpath[MAXPATHLEN];
	char	zonepath[MAXPATHLEN];
	int	num_fs = 0, i;
	struct zone_fstab fstab, *fs_ptr = NULL, *tmp_ptr;
	struct zone_fstab *fsp;
	zone_dochandle_t handle = NULL;
	zone_state_t zstate;

	if (zone_get_state(zone_name, &zstate) != Z_OK ||
	    zstate != ZONE_STATE_READY) {
		zerror(zlogp, B_FALSE,
		    "zone must be in '%s' state to mount file-systems",
		    zone_state_str(ZONE_STATE_READY));
		goto bad;
	}

	if (zone_get_zonepath(zone_name, zonepath, sizeof (zonepath)) != Z_OK) {
		zerror(zlogp, B_TRUE, "unable to determine zone path");
		goto bad;
	}

	if (zone_get_rootpath(zone_name, rootpath, sizeof (rootpath)) != Z_OK) {
		zerror(zlogp, B_TRUE, "unable to determine zone root");
		goto bad;
	}

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE,
		    "could not get zone configuration handle");
		goto bad;
	}
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK ||
	    zonecfg_setfsent(handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		goto bad;
	}

	/*
	 * /dev in the zone is loopback'd from the external /dev repository,
	 * in order to provide a largely read-only semantic.  But because
	 * processes in the zone need to be able to chown, chmod, etc. zone
	 * /dev files, we can't use a 'ro' lofs mount.  Instead we use a
	 * special mode just for zones, "zonedevfs".
	 *
	 * In the future we should front /dev with a full-fledged filesystem.
	 */
	num_fs++;
	if ((tmp_ptr = realloc(fs_ptr, num_fs * sizeof (*tmp_ptr))) == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		num_fs--;
		goto bad;
	}
	fs_ptr = tmp_ptr;
	fsp = &fs_ptr[num_fs - 1];
	(void) strlcpy(fsp->zone_fs_dir, "/dev", sizeof (fsp->zone_fs_dir));
	(void) snprintf(fsp->zone_fs_special, sizeof (fsp->zone_fs_special),
	    "%s/dev", zonepath);
	fsp->zone_fs_raw[0] = '\0';
	(void) strlcpy(fsp->zone_fs_type, MNTTYPE_LOFS,
	    sizeof (fsp->zone_fs_type));
	fsp->zone_fs_options = NULL;
	if (zonecfg_add_fs_option(fsp, MNTOPT_LOFS_ZONEDEVFS) != Z_OK) {
		zerror(zlogp, B_FALSE, "error adding property");
		goto bad;
	}

	/*
	 * Iterate through the rest of the filesystems, first the IPDs, then
	 * the general FSs.  Sort them all, then mount them in sorted order.
	 * This is to make sure the higher level directories (e.g., /usr)
	 * get mounted before any beneath them (e.g., /usr/local).
	 */
	if (zonecfg_setipdent(handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		goto bad;
	}
	while (zonecfg_getipdent(handle, &fstab) == Z_OK) {
		num_fs++;
		if ((tmp_ptr = realloc(fs_ptr,
		    num_fs * sizeof (*tmp_ptr))) == NULL) {
			zerror(zlogp, B_TRUE, "memory allocation failed");
			num_fs--;
			(void) zonecfg_endipdent(handle);
			goto bad;
		}
		fs_ptr = tmp_ptr;
		fsp = &fs_ptr[num_fs - 1];
		/*
		 * IPDs logically only have a mount point; all other properties
		 * are implied.
		 */
		(void) strlcpy(fsp->zone_fs_dir,
		    fstab.zone_fs_dir, sizeof (fsp->zone_fs_dir));
		fsp->zone_fs_special[0] = '\0';
		fsp->zone_fs_raw[0] = '\0';
		fsp->zone_fs_type[0] = '\0';
		fsp->zone_fs_options = NULL;
	}
	(void) zonecfg_endipdent(handle);

	if (zonecfg_setfsent(handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		goto bad;
	}
	while (zonecfg_getfsent(handle, &fstab) == Z_OK) {
		num_fs++;
		if ((tmp_ptr = realloc(fs_ptr,
		    num_fs * sizeof (*tmp_ptr))) == NULL) {
			zerror(zlogp, B_TRUE, "memory allocation failed");
			num_fs--;
			(void) zonecfg_endfsent(handle);
			goto bad;
		}
		fs_ptr = tmp_ptr;
		fsp = &fs_ptr[num_fs - 1];
		(void) strlcpy(fsp->zone_fs_dir,
		    fstab.zone_fs_dir, sizeof (fsp->zone_fs_dir));
		(void) strlcpy(fsp->zone_fs_special, fstab.zone_fs_special,
		    sizeof (fsp->zone_fs_special));
		(void) strlcpy(fsp->zone_fs_raw, fstab.zone_fs_raw,
		    sizeof (fsp->zone_fs_raw));
		(void) strlcpy(fsp->zone_fs_type, fstab.zone_fs_type,
		    sizeof (fsp->zone_fs_type));
		fsp->zone_fs_options = fstab.zone_fs_options;
	}
	(void) zonecfg_endfsent(handle);
	zonecfg_fini_handle(handle);
	handle = NULL;

	qsort(fs_ptr, num_fs, sizeof (*fs_ptr), fs_compare);
	for (i = 0; i < num_fs; i++) {
		if (mount_one(zlogp, &fs_ptr[i], rootpath) != 0)
			goto bad;
	}
	free_fs_data(fs_ptr, num_fs);

	/*
	 * Everything looks fine.
	 */
	return (0);

bad:
	if (handle != NULL)
		zonecfg_fini_handle(handle);
	free_fs_data(fs_ptr, num_fs);
	return (-1);
}

/* caller makes sure neither parameter is NULL */
static int
addr2netmask(char *prefixstr, int maxprefixlen, uchar_t *maskstr)
{
	int prefixlen;

	prefixlen = atoi(prefixstr);
	if (prefixlen < 0 || prefixlen > maxprefixlen)
		return (1);
	while (prefixlen > 0) {
		if (prefixlen >= 8) {
			*maskstr++ = 0xFF;
			prefixlen -= 8;
			continue;
		}
		*maskstr |= 1 << (8 - prefixlen);
		prefixlen--;
	}
	return (0);
}

/*
 * Tear down all interfaces belonging to the given zone.  This should
 * be called with the zone in a state other than "running", so that
 * interfaces can't be assigned to the zone after this returns.
 *
 * If anything goes wrong, log an error message and return an error.
 */
static int
unconfigure_network_interfaces(zlog_t *zlogp, zoneid_t zone_id)
{
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq *lifrp, lifrl;
	int64_t lifc_flags = LIFC_NOXMIT | LIFC_ALLZONES;
	int num_ifs, s, i, ret_code = 0;
	uint_t bufsize;
	char *buf = NULL;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		zerror(zlogp, B_TRUE, "could not get socket");
		ret_code = -1;
		goto bad;
	}
	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = (int)lifc_flags;
	if (ioctl(s, SIOCGLIFNUM, (char *)&lifn) < 0) {
		zerror(zlogp, B_TRUE,
		    "could not determine number of interfaces");
		ret_code = -1;
		goto bad;
	}
	num_ifs = lifn.lifn_count;
	bufsize = num_ifs * sizeof (struct lifreq);
	if ((buf = malloc(bufsize)) == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		ret_code = -1;
		goto bad;
	}
	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = (int)lifc_flags;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;
	if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) < 0) {
		zerror(zlogp, B_TRUE, "could not get configured interfaces");
		ret_code = -1;
		goto bad;
	}
	lifrp = lifc.lifc_req;
	for (i = lifc.lifc_len / sizeof (struct lifreq); i > 0; i--, lifrp++) {
		(void) close(s);
		if ((s = socket(lifrp->lifr_addr.ss_family, SOCK_DGRAM, 0)) <
		    0) {
			zerror(zlogp, B_TRUE, "%s: could not get socket",
			    lifrl.lifr_name);
			ret_code = -1;
			continue;
		}
		(void) memset(&lifrl, 0, sizeof (lifrl));
		(void) strncpy(lifrl.lifr_name, lifrp->lifr_name,
		    sizeof (lifrl.lifr_name));
		if (ioctl(s, SIOCGLIFZONE, (caddr_t)&lifrl) < 0) {
			zerror(zlogp, B_TRUE,
			    "%s: could not determine zone interface belongs to",
			    lifrl.lifr_name);
			ret_code = -1;
			continue;
		}
		if (lifrl.lifr_zoneid == zone_id) {
			if (ioctl(s, SIOCLIFREMOVEIF, (caddr_t)&lifrl) < 0) {
				zerror(zlogp, B_TRUE,
				    "%s: could not remove interface",
				    lifrl.lifr_name);
				ret_code = -1;
				continue;
			}
		}
	}
bad:
	if (s > 0)
		(void) close(s);
	if (buf)
		free(buf);
	return (ret_code);
}

static union	sockunion {
	struct	sockaddr sa;
	struct	sockaddr_in sin;
	struct	sockaddr_dl sdl;
	struct	sockaddr_in6 sin6;
} so_dst, so_ifp;

static struct {
	struct	rt_msghdr hdr;
	char	space[512];
} rtmsg;

static int
salen(struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (sizeof (struct sockaddr_in));
	case AF_LINK:
		return (sizeof (struct sockaddr_dl));
	case AF_INET6:
		return (sizeof (struct sockaddr_in6));
	default:
		return (sizeof (struct sockaddr));
	}
}

#define	ROUNDUP_LONG(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof (long) - 1))) : sizeof (long))

/*
 * Look up which zone is using a given IP address.  The address in question
 * is expected to have been stuffed into the structure to which lifr points
 * via a previous SIOCGLIFADDR ioctl().
 *
 * This is done using black router socket magic.
 *
 * Return the name of the zone on success or NULL on failure.
 *
 * This is a lot of code for a simple task; a new ioctl request to take care
 * of this might be a useful RFE.
 */

static char *
who_is_using(zlog_t *zlogp, struct lifreq *lifr)
{
	static char answer[ZONENAME_MAX];
	pid_t pid;
	int s, rlen, l, i;
	char *cp = rtmsg.space;
	struct sockaddr_dl *ifp = NULL;
	struct sockaddr *sa;
	char save_if_name[LIFNAMSIZ];

	answer[0] = '\0';

	pid = getpid();
	if ((s = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		zerror(zlogp, B_TRUE, "could not get routing socket");
		return (NULL);
	}

	if (lifr->lifr_addr.ss_family == AF_INET) {
		struct sockaddr_in *sin4;

		so_dst.sa.sa_family = AF_INET;
		sin4 = (struct sockaddr_in *)&lifr->lifr_addr;
		so_dst.sin.sin_addr = sin4->sin_addr;
	} else {
		struct sockaddr_in6 *sin6;

		so_dst.sa.sa_family = AF_INET6;
		sin6 = (struct sockaddr_in6 *)&lifr->lifr_addr;
		so_dst.sin6.sin6_addr = sin6->sin6_addr;
	}

	so_ifp.sa.sa_family = AF_LINK;

	(void) memset(&rtmsg, 0, sizeof (rtmsg));
	rtmsg.hdr.rtm_type = RTM_GET;
	rtmsg.hdr.rtm_flags = RTF_UP | RTF_HOST;
	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_seq = ++rts_seqno;
	rtmsg.hdr.rtm_addrs = RTA_IFP | RTA_DST;

	l = ROUNDUP_LONG(salen(&so_dst.sa));
	(void) memmove(cp, &(so_dst), l);
	cp += l;
	l = ROUNDUP_LONG(salen(&so_ifp.sa));
	(void) memmove(cp, &(so_ifp), l);
	cp += l;

	rtmsg.hdr.rtm_msglen = l = cp - (char *)&rtmsg;

	if ((rlen = write(s, &rtmsg, l)) < 0) {
		zerror(zlogp, B_TRUE, "writing to routing socket");
		return (NULL);
	} else if (rlen < (int)rtmsg.hdr.rtm_msglen) {
		zerror(zlogp, B_TRUE,
		    "write to routing socket got only %d for len\n", rlen);
		return (NULL);
	}
	do {
		l = read(s, &rtmsg, sizeof (rtmsg));
	} while (l > 0 && (rtmsg.hdr.rtm_seq != rts_seqno ||
	    rtmsg.hdr.rtm_pid != pid));
	if (l < 0) {
		zerror(zlogp, B_TRUE, "reading from routing socket");
		return (NULL);
	}

	if (rtmsg.hdr.rtm_version != RTM_VERSION) {
		zerror(zlogp, B_FALSE,
		    "routing message version %d not understood",
		    rtmsg.hdr.rtm_version);
		return (NULL);
	}
	if (rtmsg.hdr.rtm_msglen != (ushort_t)l) {
		zerror(zlogp, B_FALSE, "message length mismatch, "
		    "expected %d bytes, returned %d bytes",
		    rtmsg.hdr.rtm_msglen, l);
		return (NULL);
	}
	if (rtmsg.hdr.rtm_errno != 0)  {
		errno = rtmsg.hdr.rtm_errno;
		zerror(zlogp, B_TRUE, "RTM_GET routing socket message");
		return (NULL);
	}
	if ((rtmsg.hdr.rtm_addrs & RTA_IFP) == 0) {
		zerror(zlogp, B_FALSE, "interface not found");
		return (NULL);
	}
	cp = ((char *)(&rtmsg.hdr + 1));
	for (i = 1; i != 0; i <<= 1) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sa = (struct sockaddr *)cp;
		if (i != RTA_IFP) {
			if ((i & rtmsg.hdr.rtm_addrs) != 0)
				cp += ROUNDUP_LONG(salen(sa));
			continue;
		}
		if (sa->sa_family == AF_LINK &&
		    ((struct sockaddr_dl *)sa)->sdl_nlen != 0)
			ifp = (struct sockaddr_dl *)sa;
		break;
	}
	if (ifp == NULL) {
		zerror(zlogp, B_FALSE, "interface could not be determined");
		return (NULL);
	}

	/*
	 * We need to set the I/F name to what we got above, then do the
	 * appropriate ioctl to get its zone name.  But lifr->lifr_name is
	 * used by the calling function to do a REMOVEIF, so if we leave the
	 * "good" zone's I/F name in place, *that* I/F will be removed instead
	 * of the bad one.  So we save the old (bad) I/F name before over-
	 * writing it and doing the ioctl, then restore it after the ioctl.
	 */
	(void) strlcpy(save_if_name, lifr->lifr_name, sizeof (save_if_name));
	(void) strncpy(lifr->lifr_name, ifp->sdl_data, ifp->sdl_nlen);
	lifr->lifr_name[ifp->sdl_nlen] = '\0';
	i = ioctl(s, SIOCGLIFZONE, lifr);
	(void) strlcpy(lifr->lifr_name, save_if_name, sizeof (save_if_name));
	if (i < 0) {
		zerror(zlogp, B_TRUE,
		    "%s: could not determine the zone interface belongs to",
		    lifr->lifr_name);
		return (NULL);
	}
	if (getzonenamebyid(lifr->lifr_zoneid, answer, sizeof (answer)) < 0)
		(void) snprintf(answer, sizeof (answer), "%d",
		    lifr->lifr_zoneid);

	if (strlen(answer) > 0)
		return (answer);
	return (NULL);
}

typedef struct mcast_rtmsg_s {
	struct rt_msghdr	m_rtm;
	union {
		struct {
			struct sockaddr_in	m_dst;
			struct sockaddr_in	m_gw;
			struct sockaddr_in	m_netmask;
		} m_v4;
		struct {
			struct sockaddr_in6	m_dst;
			struct sockaddr_in6	m_gw;
			struct sockaddr_in6	m_netmask;
		} m_v6;
	} m_u;
} mcast_rtmsg_t;
#define	m_dst4		m_u.m_v4.m_dst
#define	m_dst6		m_u.m_v6.m_dst
#define	m_gw4		m_u.m_v4.m_gw
#define	m_gw6		m_u.m_v6.m_gw
#define	m_netmask4	m_u.m_v4.m_netmask
#define	m_netmask6	m_u.m_v6.m_netmask

/*
 * Configures a single interface: a new virtual interface is added, based on
 * the physical interface nwiftabptr->zone_nwif_physical, with the address
 * specified in nwiftabptr->zone_nwif_address, for zone zone_id.  Note that
 * the "address" can be an IPv6 address (with a /prefixlength required), an
 * IPv4 address (with a /prefixlength optional), or a name; for the latter,
 * an IPv4 name-to-address resolution will be attempted.
 *
 * A default interface route for multicast is created on the first IPv4 and
 * IPv6 interfaces (that have the IFF_MULTICAST flag set), respectively.
 * This should really be done in the init scripts if we ever allow zones to
 * modify the routing tables.
 *
 * If anything goes wrong, we log an detailed error message, attempt to tear
 * down whatever we set up and return an error.
 */
static int
configure_one_interface(zlog_t *zlogp, zoneid_t zone_id,
    struct zone_nwiftab *nwiftabptr, boolean_t *mcast_rt_v4_setp,
    boolean_t *mcast_rt_v6_setp)
{
	struct lifreq lifr;
	struct sockaddr_in netmask4;
	struct sockaddr_in6 netmask6;
	struct in_addr in4;
	struct in6_addr in6;
	sa_family_t af;
	char *slashp = strchr(nwiftabptr->zone_nwif_address, '/');
	mcast_rtmsg_t mcast_rtmsg;
	int s;
	int rs;
	int rlen;
	boolean_t got_netmask = B_FALSE;
	char addrstr4[INET_ADDRSTRLEN];
	int res;

	res = zonecfg_valid_net_address(nwiftabptr->zone_nwif_address, &lifr);
	if (res != Z_OK) {
		zerror(zlogp, B_FALSE, "%s: %s", zonecfg_strerror(res),
		    nwiftabptr->zone_nwif_address);
		return (-1);
	}
	af = lifr.lifr_addr.ss_family;
	if (af == AF_INET)
		in4 = ((struct sockaddr_in *)(&lifr.lifr_addr))->sin_addr;
	else
		in6 = ((struct sockaddr_in6 *)(&lifr.lifr_addr))->sin6_addr;

	if ((s = socket(af, SOCK_DGRAM, 0)) < 0) {
		zerror(zlogp, B_TRUE, "could not get socket");
		return (-1);
	}

	(void) strlcpy(lifr.lifr_name, nwiftabptr->zone_nwif_physical,
	    sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCLIFADDIF, (caddr_t)&lifr) < 0) {
		zerror(zlogp, B_TRUE, "%s: could not add interface",
		    lifr.lifr_name);
		(void) close(s);
		return (-1);
	}

	if (ioctl(s, SIOCSLIFADDR, (caddr_t)&lifr) < 0) {
		zerror(zlogp, B_TRUE,
		    "%s: could not set IP address to %s",
		    lifr.lifr_name, nwiftabptr->zone_nwif_address);
		goto bad;
	}

	/* Preserve literal IPv4 address for later potential printing. */
	if (af == AF_INET)
		(void) inet_ntop(AF_INET, &in4, addrstr4, INET_ADDRSTRLEN);

	lifr.lifr_zoneid = zone_id;
	if (ioctl(s, SIOCSLIFZONE, (caddr_t)&lifr) < 0) {
		zerror(zlogp, B_TRUE, "%s: could not place interface into zone",
		    lifr.lifr_name);
		goto bad;
	}

	if (strcmp(nwiftabptr->zone_nwif_physical, "lo0") == 0) {
		got_netmask = B_TRUE;	/* default setting will be correct */
	} else {
		if (af == AF_INET) {
			/*
			 * The IPv4 netmask can be determined either
			 * directly if a prefix length was supplied with
			 * the address or via the netmasks database.  Not
			 * being able to determine it is a common failure,
			 * but it often is not fatal to operation of the
			 * interface.  In that case, a warning will be
			 * printed after the rest of the interface's
			 * parameters have been configured.
			 */
			(void) memset(&netmask4, 0, sizeof (netmask4));
			if (slashp != NULL) {
				if (addr2netmask(slashp + 1, V4_ADDR_LEN,
				    (uchar_t *)&netmask4.sin_addr) != 0) {
					*slashp = '/';
					zerror(zlogp, B_FALSE,
					    "%s: invalid prefix length in %s",
					    lifr.lifr_name,
					    nwiftabptr->zone_nwif_address);
					goto bad;
				}
				got_netmask = B_TRUE;
			} else if (getnetmaskbyaddr(in4,
			    &netmask4.sin_addr) == 0) {
				got_netmask = B_TRUE;
			}
			if (got_netmask) {
				netmask4.sin_family = af;
				(void) memcpy(&lifr.lifr_addr, &netmask4,
				    sizeof (netmask4));
			}
		} else {
			(void) memset(&netmask6, 0, sizeof (netmask6));
			if (addr2netmask(slashp + 1, V6_ADDR_LEN,
			    (uchar_t *)&netmask6.sin6_addr) != 0) {
				*slashp = '/';
				zerror(zlogp, B_FALSE,
				    "%s: invalid prefix length in %s",
				    lifr.lifr_name,
				    nwiftabptr->zone_nwif_address);
				goto bad;
			}
			got_netmask = B_TRUE;
			netmask6.sin6_family = af;
			(void) memcpy(&lifr.lifr_addr, &netmask6,
			    sizeof (netmask6));
		}
		if (got_netmask &&
		    ioctl(s, SIOCSLIFNETMASK, (caddr_t)&lifr) < 0) {
			zerror(zlogp, B_TRUE, "%s: could not set netmask",
			    lifr.lifr_name);
			goto bad;
		}

		/*
		 * This doesn't set the broadcast address at all. Rather, it
		 * gets, then sets the interface's address, relying on the fact
		 * that resetting the address will reset the broadcast address.
		 */
		if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
			zerror(zlogp, B_TRUE, "%s: could not get address",
			    lifr.lifr_name);
			goto bad;
		}
		if (ioctl(s, SIOCSLIFADDR, (caddr_t)&lifr) < 0) {
			zerror(zlogp, B_TRUE,
			    "%s: could not reset broadcast address",
			    lifr.lifr_name);
			goto bad;
		}
	}

	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		zerror(zlogp, B_TRUE, "%s: could not get flags",
		    lifr.lifr_name);
		goto bad;
	}
	lifr.lifr_flags |= IFF_UP;
	if (ioctl(s, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
		int save_errno = errno;
		char *zone_using;

		/*
		 * If we failed with something other than EADDRNOTAVAIL,
		 * then skip to the end.  Otherwise, look up our address,
		 * then call a function to determine which zone is already
		 * using that address.
		 */
		if (errno != EADDRNOTAVAIL) {
			zerror(zlogp, B_TRUE,
			    "%s: could not bring interface up", lifr.lifr_name);
			goto bad;
		}
		if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
			zerror(zlogp, B_TRUE, "%s: could not get address",
			    lifr.lifr_name);
			goto bad;
		}
		zone_using = who_is_using(zlogp, &lifr);
		errno = save_errno;
		if (zone_using == NULL)
			zerror(zlogp, B_TRUE,
			    "%s: could not bring interface up", lifr.lifr_name);
		else
			zerror(zlogp, B_TRUE, "%s: could not bring interface "
			    "up: address in use by zone '%s'", lifr.lifr_name,
			    zone_using);
		goto bad;
	}
	if ((lifr.lifr_flags & IFF_MULTICAST) && ((af == AF_INET &&
	    mcast_rt_v4_setp != NULL && *mcast_rt_v4_setp == B_FALSE) ||
	    (af == AF_INET6 &&
	    mcast_rt_v6_setp != NULL && *mcast_rt_v6_setp == B_FALSE))) {
		rs = socket(PF_ROUTE, SOCK_RAW, 0);
		if (rs < 0) {
			zerror(zlogp, B_TRUE, "%s: could not create "
			    "routing socket", lifr.lifr_name);
			goto bad;
		}
		(void) shutdown(rs, 0);
		(void) memset((void *)&mcast_rtmsg, 0, sizeof (mcast_rtmsg_t));
		mcast_rtmsg.m_rtm.rtm_msglen =  sizeof (struct rt_msghdr) +
		    3 * (af == AF_INET ? sizeof (struct sockaddr_in) :
		    sizeof (struct sockaddr_in6));
		mcast_rtmsg.m_rtm.rtm_version = RTM_VERSION;
		mcast_rtmsg.m_rtm.rtm_type = RTM_ADD;
		mcast_rtmsg.m_rtm.rtm_flags = RTF_UP;
		mcast_rtmsg.m_rtm.rtm_addrs =
		    RTA_DST | RTA_GATEWAY | RTA_NETMASK;
		mcast_rtmsg.m_rtm.rtm_seq = ++rts_seqno;
		if (af == AF_INET) {
			mcast_rtmsg.m_dst4.sin_family = AF_INET;
			mcast_rtmsg.m_dst4.sin_addr.s_addr =
			    htonl(INADDR_UNSPEC_GROUP);
			mcast_rtmsg.m_gw4.sin_family = AF_INET;
			mcast_rtmsg.m_gw4.sin_addr = in4;
			mcast_rtmsg.m_netmask4.sin_family = AF_INET;
			mcast_rtmsg.m_netmask4.sin_addr.s_addr =
			    htonl(IN_CLASSD_NET);
		} else {
			mcast_rtmsg.m_dst6.sin6_family = AF_INET6;
			mcast_rtmsg.m_dst6.sin6_addr.s6_addr[0] = 0xffU;
			mcast_rtmsg.m_gw6.sin6_family = AF_INET6;
			mcast_rtmsg.m_gw6.sin6_addr = in6;
			mcast_rtmsg.m_netmask6.sin6_family = AF_INET6;
			mcast_rtmsg.m_netmask6.sin6_addr.s6_addr[0] = 0xffU;
		}
		rlen = write(rs, (char *)&mcast_rtmsg,
		    mcast_rtmsg.m_rtm.rtm_msglen);
		if (rlen < mcast_rtmsg.m_rtm.rtm_msglen) {
			if (rlen < 0) {
				zerror(zlogp, B_TRUE, "%s: could not set "
				    "default interface for multicast",
				    lifr.lifr_name);
			} else {
				zerror(zlogp, B_FALSE, "%s: write to routing "
				    "socket returned %d", lifr.lifr_name, rlen);
			}
			(void) close(rs);
			goto bad;
		}
		if (af == AF_INET) {
			*mcast_rt_v4_setp = B_TRUE;
		} else {
			*mcast_rt_v6_setp = B_TRUE;
		}
		(void) close(rs);
	}

	if (!got_netmask) {
		/*
		 * A common, but often non-fatal problem, is that the system
		 * cannot find the netmask for an interface address. This is
		 * often caused by it being only in /etc/inet/netmasks, but
		 * /etc/nsswitch.conf says to use NIS or NIS+ and it's not
		 * in that. This doesn't show up at boot because the netmask
		 * is obtained from /etc/inet/netmasks when no network
		 * interfaces are up, but isn't consulted when NIS/NIS+ is
		 * available. We warn the user here that something like this
		 * has happened and we're just running with a default and
		 * possible incorrect netmask.
		 */
		char buffer[INET6_ADDRSTRLEN];
		void  *addr;

		if (af == AF_INET)
			addr = &((struct sockaddr_in *)
			    (&lifr.lifr_addr))->sin_addr;
		else
			addr = &((struct sockaddr_in6 *)
			    (&lifr.lifr_addr))->sin6_addr;

		/* Find out what netmask interface is going to be using */
		if (ioctl(s, SIOCGLIFNETMASK, (caddr_t)&lifr) < 0 ||
		    inet_ntop(af, addr, buffer, sizeof (buffer)) == NULL)
			goto bad;
		zerror(zlogp, B_FALSE,
		    "WARNING: %s: no matching subnet found in netmasks(4) for "
		    "%s; using default of %s.",
		    lifr.lifr_name, addrstr4, buffer);
	}

	(void) close(s);
	return (Z_OK);
bad:
	(void) ioctl(s, SIOCLIFREMOVEIF, (caddr_t)&lifr);
	(void) close(s);
	return (-1);
}

/*
 * Sets up network interfaces based on information from the zone configuration.
 * An IPv4 loopback interface is set up "for free", modeling the global system.
 * If any of the configuration interfaces were IPv6, then an IPv6 loopback
 * address is set up as well.
 *
 * If anything goes wrong, we log a general error message, attempt to tear down
 * whatever we set up, and return an error.
 */
static int
configure_network_interfaces(zlog_t *zlogp)
{
	zone_dochandle_t handle;
	struct zone_nwiftab nwiftab, loopback_iftab;
	boolean_t saw_v6 = B_FALSE;
	boolean_t mcast_rt_v4_set = B_FALSE;
	boolean_t mcast_rt_v6_set = B_FALSE;
	zoneid_t zoneid;

	if ((zoneid = getzoneidbyname(zone_name)) == ZONE_ID_UNDEFINED) {
		zerror(zlogp, B_TRUE, "unable to get zoneid");
		return (-1);
	}

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		return (-1);
	}
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		zonecfg_fini_handle(handle);
		return (-1);
	}
	if (zonecfg_setnwifent(handle) == Z_OK) {
		for (;;) {
			struct in6_addr in6;

			if (zonecfg_getnwifent(handle, &nwiftab) != Z_OK)
				break;
			if (configure_one_interface(zlogp, zoneid,
			    &nwiftab, &mcast_rt_v4_set, &mcast_rt_v6_set) !=
			    Z_OK) {
				(void) zonecfg_endnwifent(handle);
				zonecfg_fini_handle(handle);
				return (-1);
			}
			if (inet_pton(AF_INET6, nwiftab.zone_nwif_address,
			    &in6) == 1)
				saw_v6 = B_TRUE;
		}
		(void) zonecfg_endnwifent(handle);
	}
	zonecfg_fini_handle(handle);
	(void) strlcpy(loopback_iftab.zone_nwif_physical, "lo0",
	    sizeof (loopback_iftab.zone_nwif_physical));
	(void) strlcpy(loopback_iftab.zone_nwif_address, "127.0.0.1",
	    sizeof (loopback_iftab.zone_nwif_address));
	if (configure_one_interface(zlogp, zoneid, &loopback_iftab, NULL, NULL)
	    != Z_OK) {
		return (-1);
	}
	if (saw_v6) {
		(void) strlcpy(loopback_iftab.zone_nwif_address, "::1/128",
		    sizeof (loopback_iftab.zone_nwif_address));
		if (configure_one_interface(zlogp, zoneid,
		    &loopback_iftab, NULL, NULL) != Z_OK) {
			return (-1);
		}
	}
	return (0);
}

static int
tcp_abort_conn(zlog_t *zlogp, zoneid_t zoneid,
    const struct sockaddr_storage *local, const struct sockaddr_storage *remote)
{
	int fd;
	struct strioctl ioc;
	tcp_ioc_abort_conn_t conn;
	int error;

	conn.ac_local = *local;
	conn.ac_remote = *remote;
	conn.ac_start = TCPS_SYN_SENT;
	conn.ac_end = TCPS_TIME_WAIT;
	conn.ac_zoneid = zoneid;

	ioc.ic_cmd = TCP_IOC_ABORT_CONN;
	ioc.ic_timout = -1; /* infinite timeout */
	ioc.ic_len = sizeof (conn);
	ioc.ic_dp = (char *)&conn;

	if ((fd = open("/dev/tcp", O_RDONLY)) < 0) {
		zerror(zlogp, B_TRUE, "unable to open %s", "/dev/tcp");
		return (-1);
	}

	error = ioctl(fd, I_STR, &ioc);
	(void) close(fd);
	if (error == 0 || errno == ENOENT)	/* ENOENT is not an error */
		return (0);
	return (-1);
}

static int
tcp_abort_connections(zlog_t *zlogp, zoneid_t zoneid)
{
	struct sockaddr_storage l, r;
	struct sockaddr_in *local, *remote;
	struct sockaddr_in6 *local6, *remote6;
	int error;

	/*
	 * Abort IPv4 connections.
	 */
	bzero(&l, sizeof (*local));
	local = (struct sockaddr_in *)&l;
	local->sin_family = AF_INET;
	local->sin_addr.s_addr = INADDR_ANY;
	local->sin_port = 0;

	bzero(&r, sizeof (*remote));
	remote = (struct sockaddr_in *)&r;
	remote->sin_family = AF_INET;
	remote->sin_addr.s_addr = INADDR_ANY;
	remote->sin_port = 0;

	if ((error = tcp_abort_conn(zlogp, zoneid, &l, &r)) != 0)
		return (error);

	/*
	 * Abort IPv6 connections.
	 */
	bzero(&l, sizeof (*local6));
	local6 = (struct sockaddr_in6 *)&l;
	local6->sin6_family = AF_INET6;
	local6->sin6_port = 0;
	local6->sin6_addr = in6addr_any;

	bzero(&r, sizeof (*remote6));
	remote6 = (struct sockaddr_in6 *)&r;
	remote6->sin6_family = AF_INET6;
	remote6->sin6_port = 0;
	remote6->sin6_addr = in6addr_any;

	if ((error = tcp_abort_conn(zlogp, zoneid, &l, &r)) != 0)
		return (error);
	return (0);
}

static int
devfsadm_call(zlog_t *zlogp, const char *arg)
{
	char *argv[4];
	int status;

	argv[0] = DEVFSADM;
	argv[1] = (char *)arg;
	argv[2] = zone_name;
	argv[3] = NULL;
	status = forkexec(zlogp, DEVFSADM_PATH, argv);
	if (status == 0 || status == -1)
		return (status);
	zerror(zlogp, B_FALSE, "%s call (%s %s %s) unexpectedly returned %d",
	    DEVFSADM, DEVFSADM_PATH, arg, zone_name, status);
	return (-1);
}

static int
devfsadm_register(zlog_t *zlogp)
{
	/*
	 * Ready the zone's devices.
	 */
	return (devfsadm_call(zlogp, "-z"));
}

static int
devfsadm_unregister(zlog_t *zlogp)
{
	return (devfsadm_call(zlogp, "-Z"));
}

static int
get_rctls(zlog_t *zlogp, char **bufp, size_t *bufsizep)
{
	nvlist_t *nvl = NULL;
	char *nvl_packed = NULL;
	size_t nvl_size = 0;
	nvlist_t **nvlv = NULL;
	int rctlcount = 0;
	int error = -1;
	zone_dochandle_t handle;
	struct zone_rctltab rctltab;
	rctlblk_t *rctlblk = NULL;

	*bufp = NULL;
	*bufsizep = 0;

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		return (-1);
	}
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		zonecfg_fini_handle(handle);
		return (-1);
	}

	rctltab.zone_rctl_valptr = NULL;
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		zerror(zlogp, B_TRUE, "%s failed", "nvlist_alloc");
		goto out;
	}

	if (zonecfg_setrctlent(handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "%s failed", "zonecfg_setrctlent");
		goto out;
	}

	if ((rctlblk = malloc(rctlblk_size())) == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		goto out;
	}
	while (zonecfg_getrctlent(handle, &rctltab) == Z_OK) {
		struct zone_rctlvaltab *rctlval;
		uint_t i, count;
		const char *name = rctltab.zone_rctl_name;

		/* zoneadm should have already warned about unknown rctls. */
		if (!zonecfg_is_rctl(name)) {
			zonecfg_free_rctl_value_list(rctltab.zone_rctl_valptr);
			rctltab.zone_rctl_valptr = NULL;
			continue;
		}
		count = 0;
		for (rctlval = rctltab.zone_rctl_valptr; rctlval != NULL;
		    rctlval = rctlval->zone_rctlval_next) {
			count++;
		}
		if (count == 0) {	/* ignore */
			continue;	/* Nothing to free */
		}
		if ((nvlv = malloc(sizeof (*nvlv) * count)) == NULL)
			goto out;
		i = 0;
		for (rctlval = rctltab.zone_rctl_valptr; rctlval != NULL;
		    rctlval = rctlval->zone_rctlval_next, i++) {
			if (nvlist_alloc(&nvlv[i], NV_UNIQUE_NAME, 0) != 0) {
				zerror(zlogp, B_TRUE, "%s failed",
				    "nvlist_alloc");
				goto out;
			}
			if (zonecfg_construct_rctlblk(rctlval, rctlblk)
			    != Z_OK) {
				zerror(zlogp, B_FALSE, "invalid rctl value: "
				    "(priv=%s,limit=%s,action=%s)",
				    rctlval->zone_rctlval_priv,
				    rctlval->zone_rctlval_limit,
				    rctlval->zone_rctlval_action);
				goto out;
			}
			if (!zonecfg_valid_rctl(name, rctlblk)) {
				zerror(zlogp, B_FALSE,
				    "(priv=%s,limit=%s,action=%s) is not a "
				    "valid value for rctl '%s'",
				    rctlval->zone_rctlval_priv,
				    rctlval->zone_rctlval_limit,
				    rctlval->zone_rctlval_action,
				    name);
				goto out;
			}
			if (nvlist_add_uint64(nvlv[i], "privilege",
				    rctlblk_get_privilege(rctlblk)) != 0) {
				zerror(zlogp, B_FALSE, "%s failed",
				    "nvlist_add_uint64");
				goto out;
			}
			if (nvlist_add_uint64(nvlv[i], "limit",
				    rctlblk_get_value(rctlblk)) != 0) {
				zerror(zlogp, B_FALSE, "%s failed",
				    "nvlist_add_uint64");
				goto out;
			}
			if (nvlist_add_uint64(nvlv[i], "action",
			    (uint_t)rctlblk_get_local_action(rctlblk, NULL))
			    != 0) {
				zerror(zlogp, B_FALSE, "%s failed",
				    "nvlist_add_uint64");
				goto out;
			}
		}
		zonecfg_free_rctl_value_list(rctltab.zone_rctl_valptr);
		rctltab.zone_rctl_valptr = NULL;
		if (nvlist_add_nvlist_array(nvl, (char *)name, nvlv, count)
		    != 0) {
			zerror(zlogp, B_FALSE, "%s failed",
			    "nvlist_add_nvlist_array");
			goto out;
		}
		for (i = 0; i < count; i++)
			nvlist_free(nvlv[i]);
		free(nvlv);
		nvlv = NULL;
		rctlcount++;
	}
	(void) zonecfg_endrctlent(handle);

	if (rctlcount == 0) {
		error = 0;
		goto out;
	}
	if (nvlist_pack(nvl, &nvl_packed, &nvl_size, NV_ENCODE_NATIVE, 0)
	    != 0) {
		zerror(zlogp, B_FALSE, "%s failed", "nvlist_pack");
		goto out;
	}

	error = 0;
	*bufp = nvl_packed;
	*bufsizep = nvl_size;

out:
	free(rctlblk);
	zonecfg_free_rctl_value_list(rctltab.zone_rctl_valptr);
	if (error && nvl_packed != NULL)
		free(nvl_packed);
	if (nvl != NULL)
		nvlist_free(nvl);
	if (nvlv != NULL)
		free(nvlv);
	if (handle != NULL)
		zonecfg_fini_handle(handle);
	return (error);
}

static int
get_zone_pool(zlog_t *zlogp, char *poolbuf, size_t bufsz)
{
	zone_dochandle_t handle;
	int error;

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		return (-1);
	}
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		zonecfg_fini_handle(handle);
		return (-1);
	}
	error = zonecfg_get_pool(handle, poolbuf, bufsz);
	zonecfg_fini_handle(handle);
	return (error);
}

static int
bind_to_pool(zlog_t *zlogp, zoneid_t zoneid)
{
	pool_conf_t *poolconf;
	pool_t *pool;
	char poolname[MAXPATHLEN];
	int status;
	int error;

	/*
	 * Find the pool mentioned in the zone configuration, and bind to it.
	 */
	error = get_zone_pool(zlogp, poolname, sizeof (poolname));
	if (error == Z_NO_ENTRY || (error == Z_OK && strlen(poolname) == 0)) {
		/*
		 * The property is not set on the zone, so the pool
		 * should be bound to the default pool.  But that's
		 * already done by the kernel, so we can just return.
		 */
		return (0);
	}
	if (error != Z_OK) {
		/*
		 * Not an error, even though it shouldn't be happening.
		 */
		zerror(zlogp, B_FALSE,
		    "WARNING: unable to retrieve default pool.");
		return (0);
	}
	/*
	 * Don't do anything if pools aren't enabled.
	 */
	if (pool_get_status(&status) != PO_SUCCESS || status != POOL_ENABLED) {
		zerror(zlogp, B_FALSE, "WARNING: pools facility not active; "
		    "zone will not be bound to pool '%s'.", poolname);
		return (0);
	}
	/*
	 * Try to provide a sane error message if the requested pool doesn't
	 * exist.
	 */
	if ((poolconf = pool_conf_alloc()) == NULL) {
		zerror(zlogp, B_FALSE, "%s failed", "pool_conf_alloc");
		return (-1);
	}
	if (pool_conf_open(poolconf, pool_dynamic_location(), PO_RDONLY) !=
	    PO_SUCCESS) {
		zerror(zlogp, B_FALSE, "%s failed", "pool_conf_open");
		pool_conf_free(poolconf);
		return (-1);
	}
	pool = pool_get_pool(poolconf, poolname);
	(void) pool_conf_close(poolconf);
	pool_conf_free(poolconf);
	if (pool == NULL) {
		zerror(zlogp, B_FALSE, "WARNING: pool '%s' not found; "
		    "using default pool.", poolname);
		return (0);
	}
	/*
	 * Bind the zone to the pool.
	 */
	if (pool_set_binding(poolname, P_ZONEID, zoneid) != PO_SUCCESS) {
		zerror(zlogp, B_FALSE, "WARNING: unable to bind to pool '%s'; "
		    "using default pool.", poolname);
	}
	return (0);
}

int
prtmount(const char *fs, void *x) {
	zerror((zlog_t *)x, B_FALSE, "  %s", fs);
	return (0);
}

int
vplat_create(zlog_t *zlogp)
{
	int rval = -1;
	priv_set_t *privs;
	char rootpath[MAXPATHLEN];
	char *rctlbuf = NULL;
	size_t rctlbufsz;
	zoneid_t zoneid;
	int xerr;

	if (zone_get_rootpath(zone_name, rootpath, sizeof (rootpath)) != Z_OK) {
		zerror(zlogp, B_TRUE, "unable to determine zone root");
		return (-1);
	}

	if ((privs = priv_allocset()) == NULL) {
		zerror(zlogp, B_TRUE, "%s failed", "priv_allocset");
		return (-1);
	}
	priv_emptyset(privs);
	if (zonecfg_get_privset(privs) != Z_OK) {
		zerror(zlogp, B_TRUE, "Failed to initialize privileges");
		goto error;
	}
	if (get_rctls(zlogp, &rctlbuf, &rctlbufsz) != 0) {
		zerror(zlogp, B_FALSE, "Unable to get list of rctls");
		goto error;
	}

	xerr = 0;
	if ((zoneid = zone_create(zone_name, rootpath, privs, rctlbuf,
	    rctlbufsz, &xerr)) == -1) {
		if (xerr == ZE_AREMOUNTS) {
			if (zonecfg_find_mounts(rootpath, NULL, NULL) < 1) {
				zerror(zlogp, B_FALSE,
				    "An unknown file-system is mounted on "
				    "a subdirectory of %s", rootpath);
			} else {

				zerror(zlogp, B_FALSE,
				    "These file-systems are mounted on "
				    "subdirectories of %s:", rootpath);
				(void) zonecfg_find_mounts(rootpath,
				    prtmount, zlogp);
			}
		} else if (xerr == ZE_CHROOTED) {
			zerror(zlogp, B_FALSE, "%s: "
			    "cannot create a zone from a chrooted "
			    "environment", "zone_create");
		} else {
			zerror(zlogp, B_TRUE, "%s failed", "zone_create");
		}
		goto error;
	}
	/*
	 * The following is a warning, not an error.
	 */
	if (bind_to_pool(zlogp, zoneid) != 0)
		zerror(zlogp, B_FALSE, "WARNING: unable to bind zone to "
		    "requested pool; using default pool.");
	rval = 0;
error:
	if (rctlbuf != NULL)
		free(rctlbuf);
	priv_freeset(privs);
	return (rval);
}

int
vplat_bringup(zlog_t *zlogp)
{
	if (create_dev_files(zlogp) != 0)
		return (-1);
	if (mount_filesystems(zlogp) != 0)
		return (-1);
	if (devfsadm_register(zlogp) != 0)
		return (-1);
	if (configure_network_interfaces(zlogp) != 0)
		return (-1);
	return (0);
}

int
vplat_teardown(zlog_t *zlogp)
{
	zoneid_t zoneid;

	if ((zoneid = getzoneidbyname(zone_name)) == ZONE_ID_UNDEFINED) {
		if (!bringup_failure_recovery)
			zerror(zlogp, B_TRUE, "unable to get zoneid");
		goto error;
	}

	if (zone_shutdown(zoneid) != 0) {
		zerror(zlogp, B_TRUE, "unable to shutdown zone");
		goto error;
	}

	if (devfsadm_unregister(zlogp) != 0)
		goto error;

	if (unconfigure_network_interfaces(zlogp, zoneid) != 0) {
		zerror(zlogp, B_FALSE,
		    "unable to unconfigure network interfaces in zone");
		goto error;
	}

	if (tcp_abort_connections(zlogp, zoneid) != 0) {
		zerror(zlogp, B_TRUE, "unable to abort TCP connections");
		goto error;
	}

	if (unmount_filesystems(zlogp) != 0) {
		zerror(zlogp, B_FALSE,
		    "unable to unmount file systems in zone");
		goto error;
	}

	if (zone_destroy(zoneid) != 0) {
		zerror(zlogp, B_TRUE, "unable to destroy zone");
		goto error;
	}
	destroy_console_slave();

	return (0);

error:
	return (-1);
}
