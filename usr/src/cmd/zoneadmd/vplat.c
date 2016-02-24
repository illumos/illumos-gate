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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Joyent Inc. All rights reserved.
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This module contains functions used to bring up and tear down the
 * Virtual Platform: [un]mounting file-systems, [un]plumbing network
 * interfaces, [un]configuring devices, establishing resource controls,
 * and creating/destroying the zone in the kernel.  These actions, on
 * the way up, ready the zone; on the way down, they halt the zone.
 * See the much longer block comment at the beginning of zoneadmd.c
 * for a bigger picture of how the whole program functions.
 *
 * This module also has primary responsibility for the layout of "scratch
 * zones."  These are mounted, but inactive, zones that are used during
 * operating system upgrade and potentially other administrative action.  The
 * scratch zone environment is similar to the miniroot environment.  The zone's
 * actual root is mounted read-write on /a, and the standard paths (/usr,
 * /sbin, /lib) all lead to read-only copies of the running system's binaries.
 * This allows the administrative tools to manipulate the zone using "-R /a"
 * without relying on any binaries in the zone itself.
 *
 * If the scratch zone is on an alternate root (Live Upgrade [LU] boot
 * environment), then we must resolve the lofs mounts used there to uncover
 * writable (unshared) resources.  Shared resources, though, are always
 * read-only.  In addition, if the "same" zone with a different root path is
 * currently running, then "/b" inside the zone points to the running zone's
 * root.  This allows LU to synchronize configuration files during the upgrade
 * process.
 *
 * To construct this environment, this module creates a tmpfs mount on
 * $ZONEPATH/lu.  Inside this scratch area, the miniroot-like environment as
 * described above is constructed on the fly.  The zone is then created using
 * $ZONEPATH/lu as the root.
 *
 * Note that scratch zones are inactive.  The zone's bits are not running and
 * likely cannot be run correctly until upgrade is done.  Init is not running
 * there, nor is SMF.  Because of this, the "mounted" state of a scratch zone
 * is not a part of the usual halt/ready/boot state machine.
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
#include <sys/systeminfo.h>

#include <libdlpi.h>
#include <libdllink.h>
#include <libdlvlan.h>

#include <inet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/route.h>

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
#include <libzfs.h>
#include <libdevinfo.h>
#include <zone.h>
#include <assert.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <uuid/uuid.h>

#include <sys/mntio.h>
#include <sys/mnttab.h>
#include <sys/fs/autofs.h>	/* for _autofssys() */
#include <sys/fs/lofs_info.h>
#include <sys/fs/zfs.h>

#include <pool.h>
#include <sys/pool.h>
#include <sys/priocntl.h>

#include <libbrand.h>
#include <sys/brand.h>
#include <libzonecfg.h>
#include <synch.h>

#include "zoneadmd.h"
#include <tsol/label.h>
#include <libtsnet.h>
#include <sys/priv.h>
#include <libinetutil.h>

#define	V4_ADDR_LEN	32
#define	V6_ADDR_LEN	128

#define	RESOURCE_DEFAULT_OPTS \
	MNTOPT_RO "," MNTOPT_LOFS_NOSUB "," MNTOPT_NODEVICES

#define	DFSTYPES	"/etc/dfs/fstypes"
#define	MAXTNZLEN	2048

#define	ALT_MOUNT(mount_cmd) 	((mount_cmd) != Z_MNT_BOOT)

/* a reasonable estimate for the number of lwps per process */
#define	LWPS_PER_PROCESS	10

/* for routing socket */
static int rts_seqno = 0;

/* mangled zone name when mounting in an alternate root environment */
static char kernzone[ZONENAME_MAX];

/* array of cached mount entries for resolve_lofs */
static struct mnttab *resolve_lofs_mnts, *resolve_lofs_mnt_max;

/* for Trusted Extensions */
static tsol_zcent_t *get_zone_label(zlog_t *, priv_set_t *);
static int tsol_mounts(zlog_t *, char *, char *);
static void tsol_unmounts(zlog_t *, char *);

static m_label_t *zlabel = NULL;
static m_label_t *zid_label = NULL;
static priv_set_t *zprivs = NULL;

static const char *DFLT_FS_ALLOWED = "hsfs,smbfs,nfs,nfs3,nfs4,nfsdyn";

/* from libsocket, not in any header file */
extern int getnetmaskbyaddr(struct in_addr, struct in_addr *);

/* from zoneadmd */
extern char query_hook[];

/*
 * For each "net" resource configured in zonecfg, we track a zone_addr_list_t
 * node in a linked list that is sorted by linkid.  The list is constructed as
 * the xml configuration file is parsed, and the information
 * contained in each node is added to the kernel before the zone is
 * booted, to be retrieved and applied from within the exclusive-IP NGZ
 * on boot.
 */
typedef struct zone_addr_list {
	struct zone_addr_list *za_next;
	datalink_id_t za_linkid;	/* datalink_id_t of interface */
	struct zone_nwiftab za_nwiftab; /* address, defrouter properties */
} zone_addr_list_t;

/*
 * An optimization for build_mnttable: reallocate (and potentially copy the
 * data) only once every N times through the loop.
 */
#define	MNTTAB_HUNK	32

/* some handy macros */
#define	SIN(s)	((struct sockaddr_in *)s)
#define	SIN6(s)	((struct sockaddr_in6 *)s)

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

static void
free_mnttable(struct mnttab *mnt_array, uint_t nelem)
{
	uint_t i;

	if (mnt_array == NULL)
		return;
	for (i = 0; i < nelem; i++) {
		free(mnt_array[i].mnt_mountp);
		free(mnt_array[i].mnt_fstype);
		free(mnt_array[i].mnt_special);
		free(mnt_array[i].mnt_mntopts);
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
		if (nmnt % MNTTAB_HUNK == 0) {
			tmp_array = realloc(mnts,
			    (nmnt + MNTTAB_HUNK) * sizeof (*mnts));
			if (tmp_array == NULL) {
				free_mnttable(mnts, nmnt);
				return (-1);
			}
			mnts = tmp_array;
		}
		mnp = &mnts[nmnt++];

		/*
		 * Zero out any fields we're not using.
		 */
		(void) memset(mnp, 0, sizeof (*mnp));

		if (mnt.mnt_special != NULL)
			mnp->mnt_special = strdup(mnt.mnt_special);
		if (mnt.mnt_mntopts != NULL)
			mnp->mnt_mntopts = strdup(mnt.mnt_mntopts);
		mnp->mnt_mountp = strdup(mnt.mnt_mountp);
		mnp->mnt_fstype = strdup(mnt.mnt_fstype);
		if ((mnt.mnt_special != NULL && mnp->mnt_special == NULL) ||
		    (mnt.mnt_mntopts != NULL && mnp->mnt_mntopts == NULL) ||
		    mnp->mnt_mountp == NULL || mnp->mnt_fstype == NULL) {
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
 * This is an optimization.  The resolve_lofs function is used quite frequently
 * to manipulate file paths, and on a machine with a large number of zones,
 * there will be a huge number of mounted file systems.  Thus, we trigger a
 * reread of the list of mount points
 */
static void
lofs_discard_mnttab(void)
{
	free_mnttable(resolve_lofs_mnts,
	    resolve_lofs_mnt_max - resolve_lofs_mnts);
	resolve_lofs_mnts = resolve_lofs_mnt_max = NULL;
}

static int
lofs_read_mnttab(zlog_t *zlogp)
{
	FILE *mnttab;
	uint_t nmnts;

	if ((mnttab = fopen(MNTTAB, "r")) == NULL)
		return (-1);
	if (build_mnttable(zlogp, "", 0, mnttab, &resolve_lofs_mnts,
	    &nmnts) == -1) {
		(void) fclose(mnttab);
		return (-1);
	}
	(void) fclose(mnttab);
	resolve_lofs_mnt_max = resolve_lofs_mnts + nmnts;
	return (0);
}

/*
 * This function loops over potential loopback mounts and symlinks in a given
 * path and resolves them all down to an absolute path.
 */
void
resolve_lofs(zlog_t *zlogp, char *path, size_t pathlen)
{
	int len, arlen;
	const char *altroot;
	char tmppath[MAXPATHLEN];
	boolean_t outside_altroot;

	if ((len = resolvepath(path, tmppath, sizeof (tmppath))) == -1)
		return;
	tmppath[len] = '\0';
	(void) strlcpy(path, tmppath, sizeof (tmppath));

	/* This happens once per zoneadmd operation. */
	if (resolve_lofs_mnts == NULL && lofs_read_mnttab(zlogp) == -1)
		return;

	altroot = zonecfg_get_root();
	arlen = strlen(altroot);
	outside_altroot = B_FALSE;
	for (;;) {
		struct mnttab *mnp;

		/* Search in reverse order to find longest match */
		for (mnp = resolve_lofs_mnt_max - 1; mnp >= resolve_lofs_mnts;
		    mnp--) {
			if (mnp->mnt_fstype == NULL ||
			    mnp->mnt_mountp == NULL ||
			    mnp->mnt_special == NULL)
				continue;
			len = strlen(mnp->mnt_mountp);
			if (strncmp(mnp->mnt_mountp, path, len) == 0 &&
			    (path[len] == '/' || path[len] == '\0'))
				break;
		}
		if (mnp < resolve_lofs_mnts)
			break;
		/* If it's not a lofs then we're done */
		if (strcmp(mnp->mnt_fstype, MNTTYPE_LOFS) != 0)
			break;
		if (outside_altroot) {
			char *cp;
			int olen = sizeof (MNTOPT_RO) - 1;

			/*
			 * If we run into a read-only mount outside of the
			 * alternate root environment, then the user doesn't
			 * want this path to be made read-write.
			 */
			if (mnp->mnt_mntopts != NULL &&
			    (cp = strstr(mnp->mnt_mntopts, MNTOPT_RO)) !=
			    NULL &&
			    (cp == mnp->mnt_mntopts || cp[-1] == ',') &&
			    (cp[olen] == '\0' || cp[olen] == ',')) {
				break;
			}
		} else if (arlen > 0 &&
		    (strncmp(mnp->mnt_special, altroot, arlen) != 0 ||
		    (mnp->mnt_special[arlen] != '\0' &&
		    mnp->mnt_special[arlen] != '/'))) {
			outside_altroot = B_TRUE;
		}
		/* use temporary buffer because new path might be longer */
		(void) snprintf(tmppath, sizeof (tmppath), "%s%s",
		    mnp->mnt_special, path + len);
		if ((len = resolvepath(tmppath, path, pathlen)) == -1)
			break;
		path[len] = '\0';
	}
}

/*
 * For a regular mount, check if a replacement lofs mount is needed because the
 * referenced device is already mounted somewhere.
 */
static int
check_lofs_needed(zlog_t *zlogp, struct zone_fstab *fsptr)
{
	struct mnttab *mnp;
	zone_fsopt_t *optptr, *onext;

	/* This happens once per zoneadmd operation. */
	if (resolve_lofs_mnts == NULL && lofs_read_mnttab(zlogp) == -1)
		return (-1);

	/*
	 * If this special node isn't already in use, then it's ours alone;
	 * no need to worry about conflicting mounts.
	 */
	for (mnp = resolve_lofs_mnts; mnp < resolve_lofs_mnt_max;
	    mnp++) {
		if (strcmp(mnp->mnt_special, fsptr->zone_fs_special) == 0)
			break;
	}
	if (mnp >= resolve_lofs_mnt_max)
		return (0);

	/*
	 * Convert this duplicate mount into a lofs mount.
	 */
	(void) strlcpy(fsptr->zone_fs_special, mnp->mnt_mountp,
	    sizeof (fsptr->zone_fs_special));
	(void) strlcpy(fsptr->zone_fs_type, MNTTYPE_LOFS,
	    sizeof (fsptr->zone_fs_type));
	fsptr->zone_fs_raw[0] = '\0';

	/*
	 * Discard all but one of the original options and set that to our
	 * default set of options used for resources.
	 */
	optptr = fsptr->zone_fs_options;
	if (optptr == NULL) {
		optptr = malloc(sizeof (*optptr));
		if (optptr == NULL) {
			zerror(zlogp, B_TRUE, "cannot mount %s",
			    fsptr->zone_fs_dir);
			return (-1);
		}
	} else {
		while ((onext = optptr->zone_fsopt_next) != NULL) {
			optptr->zone_fsopt_next = onext->zone_fsopt_next;
			free(onext);
		}
	}
	(void) strcpy(optptr->zone_fsopt_opt, RESOURCE_DEFAULT_OPTS);
	optptr->zone_fsopt_next = NULL;
	fsptr->zone_fs_options = optptr;
	return (0);
}

int
make_one_dir(zlog_t *zlogp, const char *prefix, const char *subdir, mode_t mode,
    uid_t userid, gid_t groupid)
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
			if (S_ISREG(st.st_mode)) {
				/*
				 * Allow readonly mounts of /etc/ files; this
				 * is needed most by Trusted Extensions.
				 */
				if (strncmp(subdir, "/etc/",
				    strlen("/etc/")) != 0) {
					zerror(zlogp, B_FALSE,
					    "%s is not in /etc", path);
					return (-1);
				}
			} else {
				zerror(zlogp, B_FALSE,
				    "%s is not a directory", path);
				return (-1);
			}
		}
		return (0);
	}

	if (mkdirp(path, mode) != 0) {
		if (errno == EROFS)
			zerror(zlogp, B_FALSE, "Could not mkdir %s.\nIt is on "
			    "a read-only file system in this local zone.\nMake "
			    "sure %s exists in the global zone.", path, subdir);
		else
			zerror(zlogp, B_TRUE, "mkdirp of %s failed", path);
		return (-1);
	}

	(void) chown(path, userid, groupid);
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

/*
 * This converts a zone root path (normally of the form .../root) to a Live
 * Upgrade scratch zone root (of the form .../lu).
 */
static void
root_to_lu(zlog_t *zlogp, char *zroot, size_t zrootlen, boolean_t isresolved)
{
	if (!isresolved && zonecfg_in_alt_root())
		resolve_lofs(zlogp, zroot, zrootlen);
	(void) strcpy(strrchr(zroot, '/') + 1, "lu");
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
unmount_filesystems(zlog_t *zlogp, zoneid_t zoneid, boolean_t unmount_cmd)
{
	int error = 0;
	FILE *mnttab;
	struct mnttab *mnts;
	uint_t nmnt;
	char zroot[MAXPATHLEN + 1];
	size_t zrootlen;
	uint_t oldcount = UINT_MAX;
	boolean_t stuck = B_FALSE;
	char **remote_fstypes = NULL;

	if (zone_get_rootpath(zone_name, zroot, sizeof (zroot)) != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to determine zone root");
		return (-1);
	}
	if (unmount_cmd)
		root_to_lu(zlogp, zroot, sizeof (zroot), B_FALSE);

	(void) strcat(zroot, "/");
	zrootlen = strlen(zroot);

	/*
	 * For Trusted Extensions unmount each higher level zone's mount
	 * of our zone's /export/home
	 */
	if (!unmount_cmd)
		tsol_unmounts(zlogp, zone_name);

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
		/* redirect stdin, stdout & stderr to /dev/null */
		(void) open("/dev/null", O_RDONLY);	/* stdin */
		(void) open("/dev/null", O_WRONLY);	/* stdout */
		(void) open("/dev/null", O_WRONLY);	/* stderr */
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
isregfile(const char *path)
{
	struct stat64 st;

	if (stat64(path, &st) == -1)
		return (-1);

	return (S_ISREG(st.st_mode));
}

static int
dofsck(zlog_t *zlogp, const char *fstype, const char *rawdev)
{
	char cmdbuf[MAXPATHLEN];
	char *argv[5];
	int status;

	/*
	 * We could alternatively have called /usr/sbin/fsck -F <fstype>, but
	 * that would cost us an extra fork/exec without buying us anything.
	 */
	if (snprintf(cmdbuf, sizeof (cmdbuf), "/usr/lib/fs/%s/fsck", fstype)
	    >= sizeof (cmdbuf)) {
		zerror(zlogp, B_FALSE, "file-system type %s too long", fstype);
		return (-1);
	}

	/*
	 * If it doesn't exist, that's OK: we verified this previously
	 * in zoneadm.
	 */
	if (isregfile(cmdbuf) == -1)
		return (0);

	argv[0] = "fsck";
	argv[1] = "-o";
	argv[2] = "p";
	argv[3] = (char *)rawdev;
	argv[4] = NULL;

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
	    >= sizeof (cmdbuf)) {
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
 * Check if a given mount point path exists.
 * If it does, make sure it doesn't contain any symlinks.
 * Note that if "leaf" is false we're checking an intermediate
 * component of the mount point path, so it must be a directory.
 * If "leaf" is true, then we're checking the entire mount point
 * path, so the mount point itself can be anything aside from a
 * symbolic link.
 *
 * If the path is invalid then a negative value is returned.  If the
 * path exists and is a valid mount point path then 0 is returned.
 * If the path doesn't exist return a positive value.
 */
static int
valid_mount_point(zlog_t *zlogp, const char *path, const boolean_t leaf)
{
	struct stat statbuf;
	char respath[MAXPATHLEN];
	int res;

	if (lstat(path, &statbuf) != 0) {
		if (errno == ENOENT)
			return (1);
		zerror(zlogp, B_TRUE, "can't stat %s", path);
		return (-1);
	}
	if (S_ISLNK(statbuf.st_mode)) {
		zerror(zlogp, B_FALSE, "%s is a symlink", path);
		return (-1);
	}
	if (!leaf && !S_ISDIR(statbuf.st_mode)) {
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
		 * We don't like ".."s, "."s, or "//"s throwing us off
		 */
		zerror(zlogp, B_FALSE, "%s is not a canonical path", path);
		return (-1);
	}
	return (0);
}

/*
 * Validate a mount point path.  A valid mount point path is an
 * absolute path that either doesn't exist, or, if it does exists it
 * must be an absolute canonical path that doesn't have any symbolic
 * links in it.  The target of a mount point path can be any filesystem
 * object.  (Different filesystems can support different mount points,
 * for example "lofs" and "mntfs" both support files and directories
 * while "ufs" just supports directories.)
 *
 * If the path is invalid then a negative value is returned.  If the
 * path exists and is a valid mount point path then 0 is returned.
 * If the path doesn't exist return a positive value.
 */
int
valid_mount_path(zlog_t *zlogp, const char *rootpath, const char *spec,
    const char *dir, const char *fstype)
{
	char abspath[MAXPATHLEN], *slashp, *slashp_next;
	int rv;

	/*
	 * Sanity check the target mount point path.
	 * It must be a non-null string that starts with a '/'.
	 */
	if (dir[0] != '/') {
		/* Something went wrong. */
		zerror(zlogp, B_FALSE, "invalid mount directory, "
		    "type: \"%s\", special: \"%s\", dir: \"%s\"",
		    fstype, spec, dir);
		return (-1);
	}

	/*
	 * Join rootpath and dir.  Make sure abspath ends with '/', this
	 * is added to all paths (even non-directory paths) to allow us
	 * to detect the end of paths below.  If the path already ends
	 * in a '/', then that's ok too (although we'll fail the
	 * cannonical path check in valid_mount_point()).
	 */
	if (snprintf(abspath, sizeof (abspath),
	    "%s%s/", rootpath, dir) >= sizeof (abspath)) {
		zerror(zlogp, B_FALSE, "pathname %s%s is too long",
		    rootpath, dir);
		return (-1);
	}

	/*
	 * Starting with rootpath, verify the mount path one component
	 * at a time.  Continue until we've evaluated all of abspath.
	 */
	slashp = &abspath[strlen(rootpath)];
	assert(*slashp == '/');
	do {
		slashp_next = strchr(slashp + 1, '/');
		*slashp = '\0';
		if (slashp_next != NULL) {
			/* This is an intermediary mount path component. */
			rv = valid_mount_point(zlogp, abspath, B_FALSE);
		} else {
			/* This is the last component of the mount path. */
			rv = valid_mount_point(zlogp, abspath, B_TRUE);
		}
		if (rv < 0)
			return (rv);
		*slashp = '/';
	} while ((slashp = slashp_next) != NULL);
	return (rv);
}

static int
mount_one_dev_device_cb(void *arg, const char *match, const char *name)
{
	di_prof_t prof = arg;

	if (name == NULL)
		return (di_prof_add_dev(prof, match));
	return (di_prof_add_map(prof, match, name));
}

static int
mount_one_dev_symlink_cb(void *arg, const char *source, const char *target)
{
	di_prof_t prof = arg;

	return (di_prof_add_symlink(prof, source, target));
}

int
vplat_get_iptype(zlog_t *zlogp, zone_iptype_t *iptypep)
{
	zone_dochandle_t handle;

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		return (-1);
	}
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		zonecfg_fini_handle(handle);
		return (-1);
	}
	if (zonecfg_get_iptype(handle, iptypep) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid ip-type configuration");
		zonecfg_fini_handle(handle);
		return (-1);
	}
	zonecfg_fini_handle(handle);
	return (0);
}

/*
 * Apply the standard lists of devices/symlinks/mappings and the user-specified
 * list of devices (via zonecfg) to the /dev filesystem.  The filesystem will
 * use these as a profile/filter to determine what exists in /dev.
 */
static int
mount_one_dev(zlog_t *zlogp, char *devpath, zone_mnt_t mount_cmd)
{
	char			brand[MAXNAMELEN];
	zone_dochandle_t	handle = NULL;
	brand_handle_t		bh = NULL;
	struct zone_devtab	ztab;
	di_prof_t		prof = NULL;
	int			err;
	int			retval = -1;
	zone_iptype_t		iptype;
	const char 		*curr_iptype;

	if (di_prof_init(devpath, &prof)) {
		zerror(zlogp, B_TRUE, "failed to initialize profile");
		goto cleanup;
	}

	/*
	 * Get a handle to the brand info for this zone.
	 * If we are mounting the zone, then we must always use the default
	 * brand device mounts.
	 */
	if (ALT_MOUNT(mount_cmd)) {
		(void) strlcpy(brand, default_brand, sizeof (brand));
	} else {
		(void) strlcpy(brand, brand_name, sizeof (brand));
	}

	if ((bh = brand_open(brand)) == NULL) {
		zerror(zlogp, B_FALSE, "unable to determine zone brand");
		goto cleanup;
	}

	if (vplat_get_iptype(zlogp, &iptype) < 0) {
		zerror(zlogp, B_TRUE, "unable to determine ip-type");
		goto cleanup;
	}
	switch (iptype) {
	case ZS_SHARED:
		curr_iptype = "shared";
		break;
	case ZS_EXCLUSIVE:
		curr_iptype = "exclusive";
		break;
	}

	if (brand_platform_iter_devices(bh, zone_name,
	    mount_one_dev_device_cb, prof, curr_iptype) != 0) {
		zerror(zlogp, B_TRUE, "failed to add standard device");
		goto cleanup;
	}

	if (brand_platform_iter_link(bh,
	    mount_one_dev_symlink_cb, prof) != 0) {
		zerror(zlogp, B_TRUE, "failed to add standard symlink");
		goto cleanup;
	}

	/* Add user-specified devices and directories */
	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_FALSE, "can't initialize zone handle");
		goto cleanup;
	}
	if (err = zonecfg_get_handle(zone_name, handle)) {
		zerror(zlogp, B_FALSE, "can't get handle for zone "
		    "%s: %s", zone_name, zonecfg_strerror(err));
		goto cleanup;
	}
	if (err = zonecfg_setdevent(handle)) {
		zerror(zlogp, B_FALSE, "%s: %s", zone_name,
		    zonecfg_strerror(err));
		goto cleanup;
	}
	while (zonecfg_getdevent(handle, &ztab) == Z_OK) {
		if (di_prof_add_dev(prof, ztab.zone_dev_match)) {
			zerror(zlogp, B_TRUE, "failed to add "
			    "user-specified device");
			goto cleanup;
		}
	}
	(void) zonecfg_enddevent(handle);

	/* Send profile to kernel */
	if (di_prof_commit(prof)) {
		zerror(zlogp, B_TRUE, "failed to commit profile");
		goto cleanup;
	}

	retval = 0;

cleanup:
	if (bh != NULL)
		brand_close(bh);
	if (handle != NULL)
		zonecfg_fini_handle(handle);
	if (prof)
		di_prof_fini(prof);
	return (retval);
}

static int
mount_one(zlog_t *zlogp, struct zone_fstab *fsptr, const char *rootpath,
    zone_mnt_t mount_cmd)
{
	char path[MAXPATHLEN];
	char optstr[MAX_MNTOPT_STR];
	zone_fsopt_t *optptr;
	int rv;

	if ((rv = valid_mount_path(zlogp, rootpath, fsptr->zone_fs_special,
	    fsptr->zone_fs_dir, fsptr->zone_fs_type)) < 0) {
		zerror(zlogp, B_FALSE, "%s%s is not a valid mount point",
		    rootpath, fsptr->zone_fs_dir);
		return (-1);
	} else if (rv > 0) {
		/* The mount point path doesn't exist, create it now. */
		if (make_one_dir(zlogp, rootpath, fsptr->zone_fs_dir,
		    DEFAULT_DIR_MODE, DEFAULT_DIR_USER,
		    DEFAULT_DIR_GROUP) != 0) {
			zerror(zlogp, B_FALSE, "failed to create mount point");
			return (-1);
		}

		/*
		 * Now this might seem weird, but we need to invoke
		 * valid_mount_path() again.  Why?  Because it checks
		 * to make sure that the mount point path is canonical,
		 * which it can only do if the path exists, so now that
		 * we've created the path we have to verify it again.
		 */
		if ((rv = valid_mount_path(zlogp, rootpath,
		    fsptr->zone_fs_special, fsptr->zone_fs_dir,
		    fsptr->zone_fs_type)) < 0) {
			zerror(zlogp, B_FALSE,
			    "%s%s is not a valid mount point",
			    rootpath, fsptr->zone_fs_dir);
			return (-1);
		}
	}

	(void) snprintf(path, sizeof (path), "%s%s", rootpath,
	    fsptr->zone_fs_dir);

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
	 * If we're looking at an alternate root environment, then construct
	 * read-only loopback mounts as necessary.  Note that any special
	 * paths for lofs zone mounts in an alternate root must have
	 * already been pre-pended with any alternate root path by the
	 * time we get here.
	 */
	if (zonecfg_in_alt_root()) {
		struct stat64 st;

		if (stat64(fsptr->zone_fs_special, &st) != -1 &&
		    S_ISBLK(st.st_mode)) {
			/*
			 * If we're going to mount a block device we need
			 * to check if that device is already mounted
			 * somewhere else, and if so, do a lofs mount
			 * of the device instead of a direct mount
			 */
			if (check_lofs_needed(zlogp, fsptr) == -1)
				return (-1);
		} else if (strcmp(fsptr->zone_fs_type, MNTTYPE_LOFS) == 0) {
			/*
			 * For lofs mounts, the special node is inside the
			 * alternate root.  We need lofs resolution for
			 * this case in order to get at the underlying
			 * read-write path.
			 */
			resolve_lofs(zlogp, fsptr->zone_fs_special,
			    sizeof (fsptr->zone_fs_special));
		}
	}

	/*
	 * Run 'fsck -m' if there's a device to fsck.
	 */
	if (fsptr->zone_fs_raw[0] != '\0' &&
	    dofsck(zlogp, fsptr->zone_fs_type, fsptr->zone_fs_raw) != 0) {
		return (-1);
	} else if (isregfile(fsptr->zone_fs_special) == 1 &&
	    dofsck(zlogp, fsptr->zone_fs_type, fsptr->zone_fs_special) != 0) {
		return (-1);
	}

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

	if ((rv = domount(zlogp, fsptr->zone_fs_type, optstr,
	    fsptr->zone_fs_special, path)) != 0)
		return (rv);

	/*
	 * The mount succeeded.  If this was not a mount of /dev then
	 * we're done.
	 */
	if (strcmp(fsptr->zone_fs_type, MNTTYPE_DEV) != 0)
		return (0);

	/*
	 * We just mounted an instance of a /dev filesystem, so now we
	 * need to configure it.
	 */
	return (mount_one_dev(zlogp, path, mount_cmd));
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

/*
 * This function initiates the creation of a small Solaris Environment for
 * scratch zone. The Environment creation process is split up into two
 * functions(build_mounted_pre_var() and build_mounted_post_var()). It
 * is done this way because:
 * 	We need to have both /etc and /var in the root of the scratchzone.
 * 	We loopback mount zone's own /etc and /var into the root of the
 * 	scratch zone. Unlike /etc, /var can be a seperate filesystem. So we
 * 	need to delay the mount of /var till the zone's root gets populated.
 *	So mounting of localdirs[](/etc and /var) have been moved to the
 * 	build_mounted_post_var() which gets called only after the zone
 * 	specific filesystems are mounted.
 *
 * Note that the scratch zone we set up for updating the zone (Z_MNT_UPDATE)
 * does not loopback mount the zone's own /etc and /var into the root of the
 * scratch zone.
 */
static boolean_t
build_mounted_pre_var(zlog_t *zlogp, char *rootpath,
    size_t rootlen, const char *zonepath, char *luroot, size_t lurootlen)
{
	char tmp[MAXPATHLEN], fromdir[MAXPATHLEN];
	const char **cpp;
	static const char *mkdirs[] = {
		"/system", "/system/contract", "/system/object", "/proc",
		"/dev", "/tmp", "/a", NULL
	};
	char *altstr;
	FILE *fp;
	uuid_t uuid;

	resolve_lofs(zlogp, rootpath, rootlen);
	(void) snprintf(luroot, lurootlen, "%s/lu", zonepath);
	resolve_lofs(zlogp, luroot, lurootlen);
	(void) snprintf(tmp, sizeof (tmp), "%s/bin", luroot);
	(void) symlink("./usr/bin", tmp);

	/*
	 * These are mostly special mount points; not handled here.  (See
	 * zone_mount_early.)
	 */
	for (cpp = mkdirs; *cpp != NULL; cpp++) {
		(void) snprintf(tmp, sizeof (tmp), "%s%s", luroot, *cpp);
		if (mkdir(tmp, 0755) != 0) {
			zerror(zlogp, B_TRUE, "cannot create %s", tmp);
			return (B_FALSE);
		}
	}
	/*
	 * This is here to support lucopy.  If there's an instance of this same
	 * zone on the current running system, then we mount its root up as
	 * read-only inside the scratch zone.
	 */
	(void) zonecfg_get_uuid(zone_name, uuid);
	altstr = strdup(zonecfg_get_root());
	if (altstr == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		return (B_FALSE);
	}
	zonecfg_set_root("");
	(void) strlcpy(tmp, zone_name, sizeof (tmp));
	(void) zonecfg_get_name_by_uuid(uuid, tmp, sizeof (tmp));
	if (zone_get_rootpath(tmp, fromdir, sizeof (fromdir)) == Z_OK &&
	    strcmp(fromdir, rootpath) != 0) {
		(void) snprintf(tmp, sizeof (tmp), "%s/b", luroot);
		if (mkdir(tmp, 0755) != 0) {
			zerror(zlogp, B_TRUE, "cannot create %s", tmp);
			return (B_FALSE);
		}
		if (domount(zlogp, MNTTYPE_LOFS, RESOURCE_DEFAULT_OPTS, fromdir,
		    tmp) != 0) {
			zerror(zlogp, B_TRUE, "cannot mount %s on %s", tmp,
			    fromdir);
			return (B_FALSE);
		}
	}
	zonecfg_set_root(altstr);
	free(altstr);

	if ((fp = zonecfg_open_scratch(luroot, B_TRUE)) == NULL) {
		zerror(zlogp, B_TRUE, "cannot open zone mapfile");
		return (B_FALSE);
	}
	(void) ftruncate(fileno(fp), 0);
	if (zonecfg_add_scratch(fp, zone_name, kernzone, "/") == -1) {
		zerror(zlogp, B_TRUE, "cannot add zone mapfile entry");
	}
	zonecfg_close_scratch(fp);
	(void) snprintf(tmp, sizeof (tmp), "%s/a", luroot);
	if (domount(zlogp, MNTTYPE_LOFS, "", rootpath, tmp) != 0)
		return (B_FALSE);
	(void) strlcpy(rootpath, tmp, rootlen);
	return (B_TRUE);
}


static boolean_t
build_mounted_post_var(zlog_t *zlogp, zone_mnt_t mount_cmd, char *rootpath,
    const char *luroot)
{
	char tmp[MAXPATHLEN], fromdir[MAXPATHLEN];
	const char **cpp;
	const char **loopdirs;
	const char **tmpdirs;
	static const char *localdirs[] = {
		"/etc", "/var", NULL
	};
	static const char *scr_loopdirs[] = {
		"/etc/lib", "/etc/fs", "/lib", "/sbin", "/platform",
		"/usr", NULL
	};
	static const char *upd_loopdirs[] = {
		"/etc", "/kernel", "/lib", "/opt", "/platform", "/sbin",
		"/usr", "/var", NULL
	};
	static const char *scr_tmpdirs[] = {
		"/tmp", "/var/run", NULL
	};
	static const char *upd_tmpdirs[] = {
		"/tmp", "/var/run", "/var/tmp", NULL
	};
	struct stat st;

	if (mount_cmd == Z_MNT_SCRATCH) {
		/*
		 * These are mounted read-write from the zone undergoing
		 * upgrade.  We must be careful not to 'leak' things from the
		 * main system into the zone, and this accomplishes that goal.
		 */
		for (cpp = localdirs; *cpp != NULL; cpp++) {
			(void) snprintf(tmp, sizeof (tmp), "%s%s", luroot,
			    *cpp);
			(void) snprintf(fromdir, sizeof (fromdir), "%s%s",
			    rootpath, *cpp);
			if (mkdir(tmp, 0755) != 0) {
				zerror(zlogp, B_TRUE, "cannot create %s", tmp);
				return (B_FALSE);
			}
			if (domount(zlogp, MNTTYPE_LOFS, "", fromdir, tmp)
			    != 0) {
				zerror(zlogp, B_TRUE, "cannot mount %s on %s",
				    tmp, *cpp);
				return (B_FALSE);
			}
		}
	}

	if (mount_cmd == Z_MNT_UPDATE)
		loopdirs = upd_loopdirs;
	else
		loopdirs = scr_loopdirs;

	/*
	 * These are things mounted read-only from the running system because
	 * they contain binaries that must match system.
	 */
	for (cpp = loopdirs; *cpp != NULL; cpp++) {
		(void) snprintf(tmp, sizeof (tmp), "%s%s", luroot, *cpp);
		if (mkdir(tmp, 0755) != 0) {
			if (errno != EEXIST) {
				zerror(zlogp, B_TRUE, "cannot create %s", tmp);
				return (B_FALSE);
			}
			if (lstat(tmp, &st) != 0) {
				zerror(zlogp, B_TRUE, "cannot stat %s", tmp);
				return (B_FALSE);
			}
			/*
			 * Ignore any non-directories encountered.  These are
			 * things that have been converted into symlinks
			 * (/etc/fs and /etc/lib) and no longer need a lofs
			 * fixup.
			 */
			if (!S_ISDIR(st.st_mode))
				continue;
		}
		if (domount(zlogp, MNTTYPE_LOFS, RESOURCE_DEFAULT_OPTS, *cpp,
		    tmp) != 0) {
			zerror(zlogp, B_TRUE, "cannot mount %s on %s", tmp,
			    *cpp);
			return (B_FALSE);
		}
	}

	if (mount_cmd == Z_MNT_UPDATE)
		tmpdirs = upd_tmpdirs;
	else
		tmpdirs = scr_tmpdirs;

	/*
	 * These are things with tmpfs mounted inside.
	 */
	for (cpp = tmpdirs; *cpp != NULL; cpp++) {
		(void) snprintf(tmp, sizeof (tmp), "%s%s", luroot, *cpp);
		if (mount_cmd == Z_MNT_SCRATCH && mkdir(tmp, 0755) != 0 &&
		    errno != EEXIST) {
			zerror(zlogp, B_TRUE, "cannot create %s", tmp);
			return (B_FALSE);
		}

		/*
		 * We could set the mode for /tmp when we do the mkdir but
		 * since that can be modified by the umask we will just set
		 * the correct mode for /tmp now.
		 */
		if (strcmp(*cpp, "/tmp") == 0 && chmod(tmp, 01777) != 0) {
			zerror(zlogp, B_TRUE, "cannot chmod %s", tmp);
			return (B_FALSE);
		}

		if (domount(zlogp, MNTTYPE_TMPFS, "", "swap", tmp) != 0) {
			zerror(zlogp, B_TRUE, "cannot mount swap on %s", *cpp);
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

typedef struct plat_gmount_cb_data {
	zlog_t			*pgcd_zlogp;
	struct zone_fstab	**pgcd_fs_tab;
	int			*pgcd_num_fs;
} plat_gmount_cb_data_t;

/*
 * plat_gmount_cb() is a callback function invoked by libbrand to iterate
 * through all global brand platform mounts.
 */
int
plat_gmount_cb(void *data, const char *spec, const char *dir,
    const char *fstype, const char *opt)
{
	plat_gmount_cb_data_t	*cp = data;
	zlog_t			*zlogp = cp->pgcd_zlogp;
	struct zone_fstab	*fs_ptr = *cp->pgcd_fs_tab;
	int			num_fs = *cp->pgcd_num_fs;
	struct zone_fstab	*fsp, *tmp_ptr;

	num_fs++;
	if ((tmp_ptr = realloc(fs_ptr, num_fs * sizeof (*tmp_ptr))) == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		return (-1);
	}

	fs_ptr = tmp_ptr;
	fsp = &fs_ptr[num_fs - 1];

	/* update the callback struct passed in */
	*cp->pgcd_fs_tab = fs_ptr;
	*cp->pgcd_num_fs = num_fs;

	fsp->zone_fs_raw[0] = '\0';
	(void) strlcpy(fsp->zone_fs_special, spec,
	    sizeof (fsp->zone_fs_special));
	(void) strlcpy(fsp->zone_fs_dir, dir, sizeof (fsp->zone_fs_dir));
	(void) strlcpy(fsp->zone_fs_type, fstype, sizeof (fsp->zone_fs_type));
	fsp->zone_fs_options = NULL;
	if ((opt != NULL) &&
	    (zonecfg_add_fs_option(fsp, (char *)opt) != Z_OK)) {
		zerror(zlogp, B_FALSE, "error adding property");
		return (-1);
	}

	return (0);
}

static int
mount_filesystems_fsent(zone_dochandle_t handle, zlog_t *zlogp,
    struct zone_fstab **fs_tabp, int *num_fsp, zone_mnt_t mount_cmd)
{
	struct zone_fstab *tmp_ptr, *fs_ptr, *fsp, fstab;
	int num_fs;

	num_fs = *num_fsp;
	fs_ptr = *fs_tabp;

	if (zonecfg_setfsent(handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		return (-1);
	}
	while (zonecfg_getfsent(handle, &fstab) == Z_OK) {
		/*
		 * ZFS filesystems will not be accessible under an alternate
		 * root, since the pool will not be known.  Ignore them in this
		 * case.
		 */
		if (ALT_MOUNT(mount_cmd) &&
		    strcmp(fstab.zone_fs_type, MNTTYPE_ZFS) == 0)
			continue;

		num_fs++;
		if ((tmp_ptr = realloc(fs_ptr,
		    num_fs * sizeof (*tmp_ptr))) == NULL) {
			zerror(zlogp, B_TRUE, "memory allocation failed");
			(void) zonecfg_endfsent(handle);
			return (-1);
		}
		/* update the pointers passed in */
		*fs_tabp = tmp_ptr;
		*num_fsp = num_fs;

		fs_ptr = tmp_ptr;
		fsp = &fs_ptr[num_fs - 1];
		(void) strlcpy(fsp->zone_fs_dir,
		    fstab.zone_fs_dir, sizeof (fsp->zone_fs_dir));
		(void) strlcpy(fsp->zone_fs_raw, fstab.zone_fs_raw,
		    sizeof (fsp->zone_fs_raw));
		(void) strlcpy(fsp->zone_fs_type, fstab.zone_fs_type,
		    sizeof (fsp->zone_fs_type));
		fsp->zone_fs_options = fstab.zone_fs_options;

		/*
		 * For all lofs mounts, make sure that the 'special'
		 * entry points inside the alternate root.  The
		 * source path for a lofs mount in a given zone needs
		 * to be relative to the root of the boot environment
		 * that contains the zone.  Note that we don't do this
		 * for non-lofs mounts since they will have a device
		 * as a backing store and device paths must always be
		 * specified relative to the current boot environment.
		 */
		fsp->zone_fs_special[0] = '\0';
		if (strcmp(fsp->zone_fs_type, MNTTYPE_LOFS) == 0) {
			(void) strlcat(fsp->zone_fs_special, zonecfg_get_root(),
			    sizeof (fsp->zone_fs_special));
		}
		(void) strlcat(fsp->zone_fs_special, fstab.zone_fs_special,
		    sizeof (fsp->zone_fs_special));
	}
	(void) zonecfg_endfsent(handle);
	return (0);
}

static int
mount_filesystems(zlog_t *zlogp, zone_mnt_t mount_cmd)
{
	char rootpath[MAXPATHLEN];
	char zonepath[MAXPATHLEN];
	char brand[MAXNAMELEN];
	char luroot[MAXPATHLEN];
	int i, num_fs = 0;
	struct zone_fstab *fs_ptr = NULL;
	zone_dochandle_t handle = NULL;
	zone_state_t zstate;
	brand_handle_t bh;
	plat_gmount_cb_data_t cb;

	if (zone_get_state(zone_name, &zstate) != Z_OK ||
	    (zstate != ZONE_STATE_READY && zstate != ZONE_STATE_MOUNTED)) {
		zerror(zlogp, B_FALSE,
		    "zone must be in '%s' or '%s' state to mount file-systems",
		    zone_state_str(ZONE_STATE_READY),
		    zone_state_str(ZONE_STATE_MOUNTED));
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
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		goto bad;
	}
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK ||
	    zonecfg_setfsent(handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		goto bad;
	}

	/*
	 * If we are mounting the zone, then we must always use the default
	 * brand global mounts.
	 */
	if (ALT_MOUNT(mount_cmd)) {
		(void) strlcpy(brand, default_brand, sizeof (brand));
	} else {
		(void) strlcpy(brand, brand_name, sizeof (brand));
	}

	/* Get a handle to the brand info for this zone */
	if ((bh = brand_open(brand)) == NULL) {
		zerror(zlogp, B_FALSE, "unable to determine zone brand");
		zonecfg_fini_handle(handle);
		return (-1);
	}

	/*
	 * Get the list of global filesystems to mount from the brand
	 * configuration.
	 */
	cb.pgcd_zlogp = zlogp;
	cb.pgcd_fs_tab = &fs_ptr;
	cb.pgcd_num_fs = &num_fs;
	if (brand_platform_iter_gmounts(bh, zonepath,
	    plat_gmount_cb, &cb) != 0) {
		zerror(zlogp, B_FALSE, "unable to mount filesystems");
		brand_close(bh);
		zonecfg_fini_handle(handle);
		return (-1);
	}
	brand_close(bh);

	/*
	 * Iterate through the rest of the filesystems. Sort them all,
	 * then mount them in sorted order. This is to make sure the
	 * higher level directories (e.g., /usr) get mounted before
	 * any beneath them (e.g., /usr/local).
	 */
	if (mount_filesystems_fsent(handle, zlogp, &fs_ptr, &num_fs,
	    mount_cmd) != 0)
		goto bad;

	zonecfg_fini_handle(handle);
	handle = NULL;

	/*
	 * Normally when we mount a zone all the zone filesystems
	 * get mounted relative to rootpath, which is usually
	 * <zonepath>/root.  But when mounting a zone for administration
	 * purposes via the zone "mount" state, build_mounted_pre_var()
	 * updates rootpath to be <zonepath>/lu/a so we'll mount all
	 * the zones filesystems there instead.
	 *
	 * build_mounted_pre_var() and build_mounted_post_var() will
	 * also do some extra work to create directories and lofs mount
	 * a bunch of global zone file system paths into <zonepath>/lu.
	 *
	 * This allows us to be able to enter the zone (now rooted at
	 * <zonepath>/lu) and run the upgrade/patch tools that are in the
	 * global zone and have them upgrade the to-be-modified zone's
	 * files mounted on /a.  (Which mirrors the existing standard
	 * upgrade environment.)
	 *
	 * There is of course one catch.  When doing the upgrade
	 * we need <zoneroot>/lu/dev to be the /dev filesystem
	 * for the zone and we don't want to have any /dev filesystem
	 * mounted at <zoneroot>/lu/a/dev.  Since /dev is specified
	 * as a normal zone filesystem by default we'll try to mount
	 * it at <zoneroot>/lu/a/dev, so we have to detect this
	 * case and instead mount it at <zoneroot>/lu/dev.
	 *
	 * All this work is done in three phases:
	 *   1) Create and populate lu directory (build_mounted_pre_var()).
	 *   2) Mount the required filesystems as per the zone configuration.
	 *   3) Set up the rest of the scratch zone environment
	 *	(build_mounted_post_var()).
	 */
	if (ALT_MOUNT(mount_cmd) && !build_mounted_pre_var(zlogp,
	    rootpath, sizeof (rootpath), zonepath, luroot, sizeof (luroot)))
		goto bad;

	qsort(fs_ptr, num_fs, sizeof (*fs_ptr), fs_compare);

	for (i = 0; i < num_fs; i++) {
		if (ALT_MOUNT(mount_cmd) &&
		    strcmp(fs_ptr[i].zone_fs_dir, "/dev") == 0) {
			size_t slen = strlen(rootpath) - 2;

			/*
			 * By default we'll try to mount /dev as /a/dev
			 * but /dev is special and always goes at the top
			 * so strip the trailing '/a' from the rootpath.
			 */
			assert(strcmp(&rootpath[slen], "/a") == 0);
			rootpath[slen] = '\0';
			if (mount_one(zlogp, &fs_ptr[i], rootpath, mount_cmd)
			    != 0)
				goto bad;
			rootpath[slen] = '/';
			continue;
		}
		if (mount_one(zlogp, &fs_ptr[i], rootpath, mount_cmd) != 0)
			goto bad;
	}
	if (ALT_MOUNT(mount_cmd) &&
	    !build_mounted_post_var(zlogp, mount_cmd, rootpath, luroot))
		goto bad;

	/*
	 * For Trusted Extensions cross-mount each lower level /export/home
	 */
	if (mount_cmd == Z_MNT_BOOT &&
	    tsol_mounts(zlogp, zone_name, rootpath) != 0)
		goto bad;

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
unconfigure_shared_network_interfaces(zlog_t *zlogp, zoneid_t zone_id)
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
		    "could not determine number of network interfaces");
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
		zerror(zlogp, B_TRUE, "could not get configured network "
		    "interfaces");
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
			if (errno == ENXIO)
				/*
				 * Interface may have been removed by admin or
				 * another zone halting.
				 */
				continue;
			zerror(zlogp, B_TRUE,
			    "%s: could not determine the zone to which this "
			    "network interface is bound", lifrl.lifr_name);
			ret_code = -1;
			continue;
		}
		if (lifrl.lifr_zoneid == zone_id) {
			if (ioctl(s, SIOCLIFREMOVEIF, (caddr_t)&lifrl) < 0) {
				zerror(zlogp, B_TRUE,
				    "%s: could not remove network interface",
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
		zerror(zlogp, B_FALSE, "network interface not found");
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
		zerror(zlogp, B_FALSE, "network interface could not be "
		    "determined");
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
		    "%s: could not determine the zone network interface "
		    "belongs to", lifr->lifr_name);
		return (NULL);
	}
	if (getzonenamebyid(lifr->lifr_zoneid, answer, sizeof (answer)) < 0)
		(void) snprintf(answer, sizeof (answer), "%d",
		    lifr->lifr_zoneid);

	if (strlen(answer) > 0)
		return (answer);
	return (NULL);
}

/*
 * Configures a single interface: a new virtual interface is added, based on
 * the physical interface nwiftabptr->zone_nwif_physical, with the address
 * specified in nwiftabptr->zone_nwif_address, for zone zone_id.  Note that
 * the "address" can be an IPv6 address (with a /prefixlength required), an
 * IPv4 address (with a /prefixlength optional), or a name; for the latter,
 * an IPv4 name-to-address resolution will be attempted.
 *
 * If anything goes wrong, we log an detailed error message, attempt to tear
 * down whatever we set up and return an error.
 */
static int
configure_one_interface(zlog_t *zlogp, zoneid_t zone_id,
    struct zone_nwiftab *nwiftabptr)
{
	struct lifreq lifr;
	struct sockaddr_in netmask4;
	struct sockaddr_in6 netmask6;
	struct sockaddr_storage laddr;
	struct in_addr in4;
	sa_family_t af;
	char *slashp = strchr(nwiftabptr->zone_nwif_address, '/');
	int s;
	boolean_t got_netmask = B_FALSE;
	boolean_t is_loopback = B_FALSE;
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
	if ((s = socket(af, SOCK_DGRAM, 0)) < 0) {
		zerror(zlogp, B_TRUE, "could not get socket");
		return (-1);
	}

	/*
	 * This is a similar kind of "hack" like in addif() to get around
	 * the problem of SIOCLIFADDIF.  The problem is that this ioctl
	 * does not include the netmask when adding a logical interface.
	 * To get around this problem, we first add the logical interface
	 * with a 0 address.  After that, we set the netmask if provided.
	 * Finally we set the interface address.
	 */
	laddr = lifr.lifr_addr;
	(void) strlcpy(lifr.lifr_name, nwiftabptr->zone_nwif_physical,
	    sizeof (lifr.lifr_name));
	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));

	if (ioctl(s, SIOCLIFADDIF, (caddr_t)&lifr) < 0) {
		/*
		 * Here, we know that the interface can't be brought up.
		 * A similar warning message was already printed out to
		 * the console by zoneadm(1M) so instead we log the
		 * message to syslog and continue.
		 */
		zerror(&logsys, B_TRUE, "WARNING: skipping network interface "
		    "'%s' which may not be present/plumbed in the "
		    "global zone.", lifr.lifr_name);
		(void) close(s);
		return (Z_OK);
	}

	/* Preserve literal IPv4 address for later potential printing. */
	if (af == AF_INET)
		(void) inet_ntop(AF_INET, &in4, addrstr4, INET_ADDRSTRLEN);

	lifr.lifr_zoneid = zone_id;
	if (ioctl(s, SIOCSLIFZONE, (caddr_t)&lifr) < 0) {
		zerror(zlogp, B_TRUE, "%s: could not place network interface "
		    "into zone", lifr.lifr_name);
		goto bad;
	}

	/*
	 * Loopback interface will use the default netmask assigned, if no
	 * netmask is found.
	 */
	if (strcmp(nwiftabptr->zone_nwif_physical, "lo0") == 0) {
		is_loopback = B_TRUE;
	}
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

	/* Set the interface address */
	lifr.lifr_addr = laddr;
	if (ioctl(s, SIOCSLIFADDR, (caddr_t)&lifr) < 0) {
		zerror(zlogp, B_TRUE,
		    "%s: could not set IP address to %s",
		    lifr.lifr_name, nwiftabptr->zone_nwif_address);
		goto bad;
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
			    "%s: could not bring network interface up",
			    lifr.lifr_name);
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
			    "%s: could not bring network interface up",
			    lifr.lifr_name);
		else
			zerror(zlogp, B_TRUE, "%s: could not bring network "
			    "interface up: address in use by zone '%s'",
			    lifr.lifr_name, zone_using);
		goto bad;
	}

	if (!got_netmask && !is_loopback) {
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
		const char *nomatch = "no matching subnet found in netmasks(4)";

		if (af == AF_INET)
			addr = &((struct sockaddr_in *)
			    (&lifr.lifr_addr))->sin_addr;
		else
			addr = &((struct sockaddr_in6 *)
			    (&lifr.lifr_addr))->sin6_addr;

		/*
		 * Find out what netmask the interface is going to be using.
		 * If we just brought up an IPMP data address on an underlying
		 * interface above, the address will have already migrated, so
		 * the SIOCGLIFNETMASK won't be able to find it (but we need
		 * to bring the address up to get the actual netmask).  Just
		 * omit printing the actual netmask in this corner-case.
		 */
		if (ioctl(s, SIOCGLIFNETMASK, (caddr_t)&lifr) < 0 ||
		    inet_ntop(af, addr, buffer, sizeof (buffer)) == NULL) {
			zerror(zlogp, B_FALSE, "WARNING: %s; using default.",
			    nomatch);
		} else {
			zerror(zlogp, B_FALSE,
			    "WARNING: %s: %s: %s; using default of %s.",
			    lifr.lifr_name, nomatch, addrstr4, buffer);
		}
	}

	/*
	 * If a default router was specified for this interface
	 * set the route now. Ignore if already set.
	 */
	if (strlen(nwiftabptr->zone_nwif_defrouter) > 0) {
		int status;
		char *argv[7];

		argv[0] = "route";
		argv[1] = "add";
		argv[2] = "-ifp";
		argv[3] = nwiftabptr->zone_nwif_physical;
		argv[4] = "default";
		argv[5] = nwiftabptr->zone_nwif_defrouter;
		argv[6] = NULL;

		status = forkexec(zlogp, "/usr/sbin/route", argv);
		if (status != 0 && status != EEXIST)
			zerror(zlogp, B_FALSE, "Unable to set route for "
			    "interface %s to %s\n",
			    nwiftabptr->zone_nwif_physical,
			    nwiftabptr->zone_nwif_defrouter);
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
 * IPv4 and IPv6 loopback interfaces are set up "for free", modeling the global
 * system.
 *
 * If anything goes wrong, we log a general error message, attempt to tear down
 * whatever we set up, and return an error.
 */
static int
configure_shared_network_interfaces(zlog_t *zlogp)
{
	zone_dochandle_t handle;
	struct zone_nwiftab nwiftab, loopback_iftab;
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
			if (zonecfg_getnwifent(handle, &nwiftab) != Z_OK)
				break;
			if (configure_one_interface(zlogp, zoneid, &nwiftab) !=
			    Z_OK) {
				(void) zonecfg_endnwifent(handle);
				zonecfg_fini_handle(handle);
				return (-1);
			}
		}
		(void) zonecfg_endnwifent(handle);
	}
	zonecfg_fini_handle(handle);
	if (is_system_labeled()) {
		/*
		 * Labeled zones share the loopback interface
		 * so it is not plumbed for shared stack instances.
		 */
		return (0);
	}
	(void) strlcpy(loopback_iftab.zone_nwif_physical, "lo0",
	    sizeof (loopback_iftab.zone_nwif_physical));
	(void) strlcpy(loopback_iftab.zone_nwif_address, "127.0.0.1",
	    sizeof (loopback_iftab.zone_nwif_address));
	loopback_iftab.zone_nwif_defrouter[0] = '\0';
	if (configure_one_interface(zlogp, zoneid, &loopback_iftab) != Z_OK)
		return (-1);

	/* Always plumb up the IPv6 loopback interface. */
	(void) strlcpy(loopback_iftab.zone_nwif_address, "::1/128",
	    sizeof (loopback_iftab.zone_nwif_address));
	if (configure_one_interface(zlogp, zoneid, &loopback_iftab) != Z_OK)
		return (-1);
	return (0);
}

static void
zdlerror(zlog_t *zlogp, dladm_status_t err, const char *dlname, const char *str)
{
	char errmsg[DLADM_STRSIZE];

	(void) dladm_status2str(err, errmsg);
	zerror(zlogp, B_FALSE, "%s '%s': %s", str, dlname, errmsg);
}

static int
add_datalink(zlog_t *zlogp, char *zone_name, datalink_id_t linkid, char *dlname)
{
	dladm_status_t err;
	boolean_t cpuset, poolset;
	char *poolp;

	/* First check if it's in use by global zone. */
	if (zonecfg_ifname_exists(AF_INET, dlname) ||
	    zonecfg_ifname_exists(AF_INET6, dlname)) {
		zerror(zlogp, B_FALSE, "WARNING: skipping network interface "
		    "'%s' which is used in the global zone", dlname);
		return (-1);
	}

	/* Set zoneid of this link. */
	err = dladm_set_linkprop(dld_handle, linkid, "zone", &zone_name, 1,
	    DLADM_OPT_ACTIVE);
	if (err != DLADM_STATUS_OK) {
		zdlerror(zlogp, err, dlname,
		    "WARNING: unable to add network interface");
		return (-1);
	}

	/*
	 * Set the pool of this link if the zone has a pool and
	 * neither the cpus nor the pool datalink property is
	 * already set.
	 */
	err = dladm_linkprop_is_set(dld_handle, linkid, DLADM_PROP_VAL_CURRENT,
	    "cpus", &cpuset);
	if (err != DLADM_STATUS_OK) {
		zdlerror(zlogp, err, dlname,
		    "WARNING: unable to check if cpus link property is set");
	}
	err = dladm_linkprop_is_set(dld_handle, linkid, DLADM_PROP_VAL_CURRENT,
	    "pool", &poolset);
	if (err != DLADM_STATUS_OK) {
		zdlerror(zlogp, err, dlname,
		    "WARNING: unable to check if pool link property is set");
	}

	if ((strlen(pool_name) != 0) && !cpuset && !poolset) {
		poolp = pool_name;
		err = dladm_set_linkprop(dld_handle, linkid, "pool",
		    &poolp, 1, DLADM_OPT_ACTIVE);
		if (err != DLADM_STATUS_OK) {
			zerror(zlogp, B_FALSE, "WARNING: unable to set "
			    "pool %s to datalink %s", pool_name, dlname);
			bzero(pool_name, sizeof (pool_name));
		}
	} else {
		bzero(pool_name, sizeof (pool_name));
	}
	return (0);
}

static boolean_t
sockaddr_to_str(sa_family_t af, const struct sockaddr *sockaddr,
    char *straddr, size_t len)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	const char *str = NULL;

	if (af == AF_INET) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin = SIN(sockaddr);
		str = inet_ntop(AF_INET, (void *)&sin->sin_addr, straddr, len);
	} else if (af == AF_INET6) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6 = SIN6(sockaddr);
		str = inet_ntop(AF_INET6, (void *)&sin6->sin6_addr, straddr,
		    len);
	}

	return (str != NULL);
}

static int
ipv4_prefixlen(struct sockaddr_in *sin)
{
	struct sockaddr_in *m;
	struct sockaddr_storage mask;

	m = SIN(&mask);
	m->sin_family = AF_INET;
	if (getnetmaskbyaddr(sin->sin_addr, &m->sin_addr) == 0) {
		return (mask2plen((struct sockaddr *)&mask));
	} else if (IN_CLASSA(htonl(sin->sin_addr.s_addr))) {
		return (8);
	} else if (IN_CLASSB(ntohl(sin->sin_addr.s_addr))) {
		return (16);
	} else if (IN_CLASSC(ntohl(sin->sin_addr.s_addr))) {
		return (24);
	}
	return (0);
}

static int
zone_setattr_network(int type, zoneid_t zoneid, datalink_id_t linkid,
    void *buf, size_t bufsize)
{
	zone_net_data_t *zndata;
	size_t znsize;
	int err;

	znsize = sizeof (*zndata) + bufsize;
	zndata = calloc(1, znsize);
	if (zndata == NULL)
		return (ENOMEM);
	zndata->zn_type = type;
	zndata->zn_len = bufsize;
	zndata->zn_linkid = linkid;
	bcopy(buf, zndata->zn_val, zndata->zn_len);
	err = zone_setattr(zoneid, ZONE_ATTR_NETWORK, zndata, znsize);
	free(zndata);
	return (err);
}

static int
add_net_for_linkid(zlog_t *zlogp, zoneid_t zoneid, zone_addr_list_t *start)
{
	struct lifreq lifr;
	char **astr, *address;
	dladm_status_t dlstatus;
	char *ip_nospoof = "ip-nospoof";
	int nnet, naddr, err = 0, j;
	size_t zlen, cpleft;
	zone_addr_list_t *ptr, *end;
	char  tmp[INET6_ADDRSTRLEN], *maskstr;
	char *zaddr, *cp;
	struct in6_addr *routes = NULL;
	boolean_t is_set;
	datalink_id_t linkid;

	assert(start != NULL);
	naddr = 0; /* number of addresses */
	nnet = 0; /* number of net resources */
	linkid = start->za_linkid;
	for (ptr = start; ptr != NULL && ptr->za_linkid == linkid;
	    ptr = ptr->za_next) {
		nnet++;
	}
	end = ptr;
	zlen = nnet * (INET6_ADDRSTRLEN + 1);
	astr = calloc(1, nnet * sizeof (uintptr_t));
	zaddr = calloc(1, zlen);
	if (astr == NULL || zaddr == NULL) {
		err = ENOMEM;
		goto done;
	}
	cp = zaddr;
	cpleft = zlen;
	j = 0;
	for (ptr = start; ptr != end; ptr = ptr->za_next) {
		address = ptr->za_nwiftab.zone_nwif_allowed_address;
		if (address[0] == '\0')
			continue;
		(void) snprintf(tmp, sizeof (tmp), "%s", address);
		/*
		 * Validate the data. zonecfg_valid_net_address() clobbers
		 * the /<mask> in the address string.
		 */
		if (zonecfg_valid_net_address(address, &lifr) != Z_OK) {
			zerror(zlogp, B_FALSE, "invalid address [%s]\n",
			    address);
			err = EINVAL;
			goto done;
		}
		/*
		 * convert any hostnames to numeric address strings.
		 */
		if (!sockaddr_to_str(lifr.lifr_addr.ss_family,
		    (const struct sockaddr *)&lifr.lifr_addr, cp, cpleft)) {
			err = EINVAL;
			goto done;
		}
		/*
		 * make a copy of the numeric string for the data needed
		 * by the "allowed-ips" datalink property.
		 */
		astr[j] = strdup(cp);
		if (astr[j] == NULL) {
			err = ENOMEM;
			goto done;
		}
		j++;
		/*
		 * compute the default netmask from the address, if necessary
		 */
		if ((maskstr = strchr(tmp, '/')) == NULL) {
			int prefixlen;

			if (lifr.lifr_addr.ss_family == AF_INET) {
				prefixlen = ipv4_prefixlen(
				    SIN(&lifr.lifr_addr));
			} else {
				struct sockaddr_in6 *sin6;

				sin6 = SIN6(&lifr.lifr_addr);
				if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
					prefixlen = 10;
				else
					prefixlen = 64;
			}
			(void) snprintf(tmp, sizeof (tmp), "%d", prefixlen);
			maskstr = tmp;
		} else {
			maskstr++;
		}
		/* append the "/<netmask>" */
		(void) strlcat(cp, "/", cpleft);
		(void) strlcat(cp, maskstr, cpleft);
		(void) strlcat(cp, ",", cpleft);
		cp += strnlen(cp, zlen);
		cpleft = &zaddr[INET6_ADDRSTRLEN] - cp;
	}
	naddr = j; /* the actual number of addresses in the net resource */
	assert(naddr <= nnet);

	/*
	 * zonecfg has already verified that the defrouter property can only
	 * be set if there is at least one address defined for the net resource.
	 * If j is 0, there are no addresses defined, and therefore no routers
	 * to configure, and we are done at that point.
	 */
	if (j == 0)
		goto done;

	/* over-write last ',' with '\0' */
	zaddr[strnlen(zaddr, zlen) + 1] = '\0';

	/*
	 * First make sure L3 protection is not already set on the link.
	 */
	dlstatus = dladm_linkprop_is_set(dld_handle, linkid, DLADM_OPT_ACTIVE,
	    "protection", &is_set);
	if (dlstatus != DLADM_STATUS_OK) {
		err = EINVAL;
		zerror(zlogp, B_FALSE, "unable to check if protection is set");
		goto done;
	}
	if (is_set) {
		err = EINVAL;
		zerror(zlogp, B_FALSE, "Protection is already set");
		goto done;
	}
	dlstatus = dladm_linkprop_is_set(dld_handle, linkid, DLADM_OPT_ACTIVE,
	    "allowed-ips", &is_set);
	if (dlstatus != DLADM_STATUS_OK) {
		err = EINVAL;
		zerror(zlogp, B_FALSE, "unable to check if allowed-ips is set");
		goto done;
	}
	if (is_set) {
		zerror(zlogp, B_FALSE, "allowed-ips is already set");
		err = EINVAL;
		goto done;
	}

	/*
	 * Enable ip-nospoof for the link, and add address to the allowed-ips
	 * list.
	 */
	dlstatus = dladm_set_linkprop(dld_handle, linkid, "protection",
	    &ip_nospoof, 1, DLADM_OPT_ACTIVE);
	if (dlstatus != DLADM_STATUS_OK) {
		zerror(zlogp, B_FALSE, "could not set protection\n");
		err = EINVAL;
		goto done;
	}
	dlstatus = dladm_set_linkprop(dld_handle, linkid, "allowed-ips",
	    astr, naddr, DLADM_OPT_ACTIVE);
	if (dlstatus != DLADM_STATUS_OK) {
		zerror(zlogp, B_FALSE, "could not set allowed-ips\n");
		err = EINVAL;
		goto done;
	}

	/* now set the address in the data-store */
	err = zone_setattr_network(ZONE_NETWORK_ADDRESS, zoneid, linkid,
	    zaddr, strnlen(zaddr, zlen) + 1);
	if (err != 0)
		goto done;

	/*
	 * add the defaultrouters
	 */
	routes = calloc(1, nnet * sizeof (*routes));
	j = 0;
	for (ptr = start; ptr != end; ptr = ptr->za_next) {
		address = ptr->za_nwiftab.zone_nwif_defrouter;
		if (address[0] == '\0')
			continue;
		if (strchr(address, '/') == NULL && strchr(address, ':') != 0) {
			/*
			 * zonecfg_valid_net_address() expects numeric IPv6
			 * addresses to have a CIDR format netmask.
			 */
			(void) snprintf(tmp, sizeof (tmp), "/%d", V6_ADDR_LEN);
			(void) strlcat(address, tmp, INET6_ADDRSTRLEN);
		}
		if (zonecfg_valid_net_address(address, &lifr) != Z_OK) {
			zerror(zlogp, B_FALSE,
			    "invalid router [%s]\n", address);
			err = EINVAL;
			goto done;
		}
		if (lifr.lifr_addr.ss_family == AF_INET6) {
			routes[j] = SIN6(&lifr.lifr_addr)->sin6_addr;
		} else {
			IN6_INADDR_TO_V4MAPPED(&SIN(&lifr.lifr_addr)->sin_addr,
			    &routes[j]);
		}
		j++;
	}
	assert(j <= nnet);
	if (j > 0) {
		err = zone_setattr_network(ZONE_NETWORK_DEFROUTER, zoneid,
		    linkid, routes, j * sizeof (*routes));
	}
done:
	free(routes);
	for (j = 0; j < naddr; j++)
		free(astr[j]);
	free(astr);
	free(zaddr);
	return (err);

}

static int
add_net(zlog_t *zlogp, zoneid_t zoneid, zone_addr_list_t *zalist)
{
	zone_addr_list_t *ptr;
	datalink_id_t linkid;
	int err;

	if (zalist == NULL)
		return (0);

	linkid = zalist->za_linkid;

	err = add_net_for_linkid(zlogp, zoneid, zalist);
	if (err != 0)
		return (err);

	for (ptr = zalist; ptr != NULL; ptr = ptr->za_next) {
		if (ptr->za_linkid == linkid)
			continue;
		linkid = ptr->za_linkid;
		err = add_net_for_linkid(zlogp, zoneid, ptr);
		if (err != 0)
			return (err);
	}
	return (0);
}

/*
 * Add "new" to the list of network interfaces to be configured  by
 * add_net on zone boot in "old". The list of interfaces in "old" is
 * sorted by datalink_id_t, with interfaces sorted FIFO for a given
 * datalink_id_t.
 *
 * Returns the merged list of IP interfaces containing "old" and "new"
 */
static zone_addr_list_t *
add_ip_interface(zone_addr_list_t *old, zone_addr_list_t *new)
{
	zone_addr_list_t *ptr, *next;
	datalink_id_t linkid = new->za_linkid;

	assert(old != new);

	if (old == NULL)
		return (new);
	for (ptr = old; ptr != NULL; ptr = ptr->za_next) {
		if (ptr->za_linkid == linkid)
			break;
	}
	if (ptr == NULL) {
		/* linkid does not already exist, add to the beginning */
		new->za_next = old;
		return (new);
	}
	/*
	 * adding to the middle of the list; ptr points at the first
	 * occurrence of linkid. Find the last occurrence.
	 */
	while ((next = ptr->za_next) != NULL) {
		if (next->za_linkid != linkid)
			break;
		ptr = next;
	}
	/* insert new after ptr */
	new->za_next = next;
	ptr->za_next = new;
	return (old);
}

void
free_ip_interface(zone_addr_list_t *zalist)
{
	zone_addr_list_t *ptr, *new;

	for (ptr = zalist; ptr != NULL; ) {
		new = ptr;
		ptr = ptr->za_next;
		free(new);
	}
}

/*
 * Add the kernel access control information for the interface names.
 * If anything goes wrong, we log a general error message, attempt to tear down
 * whatever we set up, and return an error.
 */
static int
configure_exclusive_network_interfaces(zlog_t *zlogp, zoneid_t zoneid)
{
	zone_dochandle_t handle;
	struct zone_nwiftab nwiftab;
	char rootpath[MAXPATHLEN];
	char path[MAXPATHLEN];
	datalink_id_t linkid;
	di_prof_t prof = NULL;
	boolean_t added = B_FALSE;
	zone_addr_list_t *zalist = NULL, *new;

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		return (-1);
	}
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		zonecfg_fini_handle(handle);
		return (-1);
	}

	if (zonecfg_setnwifent(handle) != Z_OK) {
		zonecfg_fini_handle(handle);
		return (0);
	}

	for (;;) {
		if (zonecfg_getnwifent(handle, &nwiftab) != Z_OK)
			break;

		if (prof == NULL) {
			if (zone_get_devroot(zone_name, rootpath,
			    sizeof (rootpath)) != Z_OK) {
				(void) zonecfg_endnwifent(handle);
				zonecfg_fini_handle(handle);
				zerror(zlogp, B_TRUE,
				    "unable to determine dev root");
				return (-1);
			}
			(void) snprintf(path, sizeof (path), "%s%s", rootpath,
			    "/dev");
			if (di_prof_init(path, &prof) != 0) {
				(void) zonecfg_endnwifent(handle);
				zonecfg_fini_handle(handle);
				zerror(zlogp, B_TRUE,
				    "failed to initialize profile");
				return (-1);
			}
		}

		/*
		 * Create the /dev entry for backward compatibility.
		 * Only create the /dev entry if it's not in use.
		 * Note that the zone still boots when the assigned
		 * interface is inaccessible, used by others, etc.
		 * Also, when vanity naming is used, some interface do
		 * do not have corresponding /dev node names (for example,
		 * vanity named aggregations).  The /dev entry is not
		 * created in that case.  The /dev/net entry is always
		 * accessible.
		 */
		if (dladm_name2info(dld_handle, nwiftab.zone_nwif_physical,
		    &linkid, NULL, NULL, NULL) == DLADM_STATUS_OK &&
		    add_datalink(zlogp, zone_name, linkid,
		    nwiftab.zone_nwif_physical) == 0) {
			added = B_TRUE;
		} else {
			(void) zonecfg_endnwifent(handle);
			zonecfg_fini_handle(handle);
			zerror(zlogp, B_TRUE, "failed to add network device");
			return (-1);
		}
		/* set up the new IP interface, and add them all later */
		new = malloc(sizeof (*new));
		if (new == NULL) {
			zerror(zlogp, B_TRUE, "no memory for %s",
			    nwiftab.zone_nwif_physical);
			zonecfg_fini_handle(handle);
			free_ip_interface(zalist);
		}
		bzero(new, sizeof (*new));
		new->za_nwiftab = nwiftab;
		new->za_linkid = linkid;
		zalist = add_ip_interface(zalist, new);
	}
	if (zalist != NULL) {
		if ((errno = add_net(zlogp, zoneid, zalist)) != 0) {
			(void) zonecfg_endnwifent(handle);
			zonecfg_fini_handle(handle);
			zerror(zlogp, B_TRUE, "failed to add address");
			free_ip_interface(zalist);
			return (-1);
		}
		free_ip_interface(zalist);
	}
	(void) zonecfg_endnwifent(handle);
	zonecfg_fini_handle(handle);

	if (prof != NULL && added) {
		if (di_prof_commit(prof) != 0) {
			zerror(zlogp, B_TRUE, "failed to commit profile");
			return (-1);
		}
	}
	if (prof != NULL)
		di_prof_fini(prof);

	return (0);
}

static int
remove_datalink_pool(zlog_t *zlogp, zoneid_t zoneid)
{
	ushort_t flags;
	zone_iptype_t iptype;
	int i, dlnum = 0;
	datalink_id_t *dllink, *dllinks = NULL;
	dladm_status_t err;

	if (strlen(pool_name) == 0)
		return (0);

	if (zone_getattr(zoneid, ZONE_ATTR_FLAGS, &flags,
	    sizeof (flags)) < 0) {
		if (vplat_get_iptype(zlogp, &iptype) < 0) {
			zerror(zlogp, B_FALSE, "unable to determine ip-type");
			return (-1);
		}
	} else {
		if (flags & ZF_NET_EXCL)
			iptype = ZS_EXCLUSIVE;
		else
			iptype = ZS_SHARED;
	}

	if (iptype == ZS_EXCLUSIVE) {
		/*
		 * Get the datalink count and for each datalink,
		 * attempt to clear the pool property and clear
		 * the pool_name.
		 */
		if (zone_list_datalink(zoneid, &dlnum, NULL) != 0) {
			zerror(zlogp, B_TRUE, "unable to count network "
			    "interfaces");
			return (-1);
		}

		if (dlnum == 0)
			return (0);

		if ((dllinks = malloc(dlnum * sizeof (datalink_id_t)))
		    == NULL) {
			zerror(zlogp, B_TRUE, "memory allocation failed");
			return (-1);
		}
		if (zone_list_datalink(zoneid, &dlnum, dllinks) != 0) {
			zerror(zlogp, B_TRUE, "unable to list network "
			    "interfaces");
			return (-1);
		}

		bzero(pool_name, sizeof (pool_name));
		for (i = 0, dllink = dllinks; i < dlnum; i++, dllink++) {
			err = dladm_set_linkprop(dld_handle, *dllink, "pool",
			    NULL, 0, DLADM_OPT_ACTIVE);
			if (err != DLADM_STATUS_OK) {
				zerror(zlogp, B_TRUE,
				    "WARNING: unable to clear pool");
			}
		}
		free(dllinks);
	}
	return (0);
}

static int
remove_datalink_protect(zlog_t *zlogp, zoneid_t zoneid)
{
	ushort_t flags;
	zone_iptype_t iptype;
	int i, dlnum = 0;
	dladm_status_t dlstatus;
	datalink_id_t *dllink, *dllinks = NULL;

	if (zone_getattr(zoneid, ZONE_ATTR_FLAGS, &flags,
	    sizeof (flags)) < 0) {
		if (vplat_get_iptype(zlogp, &iptype) < 0) {
			zerror(zlogp, B_FALSE, "unable to determine ip-type");
			return (-1);
		}
	} else {
		if (flags & ZF_NET_EXCL)
			iptype = ZS_EXCLUSIVE;
		else
			iptype = ZS_SHARED;
	}

	if (iptype != ZS_EXCLUSIVE)
		return (0);

	/*
	 * Get the datalink count and for each datalink,
	 * attempt to clear the pool property and clear
	 * the pool_name.
	 */
	if (zone_list_datalink(zoneid, &dlnum, NULL) != 0) {
		zerror(zlogp, B_TRUE, "unable to count network interfaces");
		return (-1);
	}

	if (dlnum == 0)
		return (0);

	if ((dllinks = malloc(dlnum * sizeof (datalink_id_t))) == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		return (-1);
	}
	if (zone_list_datalink(zoneid, &dlnum, dllinks) != 0) {
		zerror(zlogp, B_TRUE, "unable to list network interfaces");
		free(dllinks);
		return (-1);
	}

	for (i = 0, dllink = dllinks; i < dlnum; i++, dllink++) {
		char dlerr[DLADM_STRSIZE];

		dlstatus = dladm_set_linkprop(dld_handle, *dllink,
		    "protection", NULL, 0, DLADM_OPT_ACTIVE);
		if (dlstatus == DLADM_STATUS_NOTFOUND) {
			/* datalink does not belong to the GZ */
			continue;
		}
		if (dlstatus != DLADM_STATUS_OK) {
			zerror(zlogp, B_FALSE,
			    dladm_status2str(dlstatus, dlerr));
			free(dllinks);
			return (-1);
		}
		dlstatus = dladm_set_linkprop(dld_handle, *dllink,
		    "allowed-ips", NULL, 0, DLADM_OPT_ACTIVE);
		if (dlstatus != DLADM_STATUS_OK) {
			zerror(zlogp, B_FALSE,
			    dladm_status2str(dlstatus, dlerr));
			free(dllinks);
			return (-1);
		}
	}
	free(dllinks);
	return (0);
}

static int
unconfigure_exclusive_network_interfaces(zlog_t *zlogp, zoneid_t zoneid)
{
	int dlnum = 0;

	/*
	 * The kernel shutdown callback for the dls module should have removed
	 * all datalinks from this zone.  If any remain, then there's a
	 * problem.
	 */
	if (zone_list_datalink(zoneid, &dlnum, NULL) != 0) {
		zerror(zlogp, B_TRUE, "unable to list network interfaces");
		return (-1);
	}
	if (dlnum != 0) {
		zerror(zlogp, B_FALSE,
		    "datalinks remain in zone after shutdown");
		return (-1);
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
get_privset(zlog_t *zlogp, priv_set_t *privs, zone_mnt_t mount_cmd)
{
	int error = -1;
	zone_dochandle_t handle;
	char *privname = NULL;

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		return (-1);
	}
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		zonecfg_fini_handle(handle);
		return (-1);
	}

	if (ALT_MOUNT(mount_cmd)) {
		zone_iptype_t	iptype;
		const char	*curr_iptype;

		if (zonecfg_get_iptype(handle, &iptype) != Z_OK) {
			zerror(zlogp, B_TRUE, "unable to determine ip-type");
			zonecfg_fini_handle(handle);
			return (-1);
		}

		switch (iptype) {
		case ZS_SHARED:
			curr_iptype = "shared";
			break;
		case ZS_EXCLUSIVE:
			curr_iptype = "exclusive";
			break;
		}

		if (zonecfg_default_privset(privs, curr_iptype) == Z_OK) {
			zonecfg_fini_handle(handle);
			return (0);
		}
		zerror(zlogp, B_FALSE,
		    "failed to determine the zone's default privilege set");
		zonecfg_fini_handle(handle);
		return (-1);
	}

	switch (zonecfg_get_privset(handle, privs, &privname)) {
	case Z_OK:
		error = 0;
		break;
	case Z_PRIV_PROHIBITED:
		zerror(zlogp, B_FALSE, "privilege \"%s\" is not permitted "
		    "within the zone's privilege set", privname);
		break;
	case Z_PRIV_REQUIRED:
		zerror(zlogp, B_FALSE, "required privilege \"%s\" is missing "
		    "from the zone's privilege set", privname);
		break;
	case Z_PRIV_UNKNOWN:
		zerror(zlogp, B_FALSE, "unknown privilege \"%s\" specified "
		    "in the zone's privilege set", privname);
		break;
	default:
		zerror(zlogp, B_FALSE, "failed to determine the zone's "
		    "privilege set");
		break;
	}

	free(privname);
	zonecfg_fini_handle(handle);
	return (error);
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
	uint64_t maxlwps;
	uint64_t maxprocs;

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

	/*
	 * Allow the administrator to control both the maximum number of
	 * process table slots and the maximum number of lwps with just the
	 * max-processes property.  If only the max-processes property is set,
	 * we add a max-lwps property with a limit derived from max-processes.
	 */
	if (zonecfg_get_aliased_rctl(handle, ALIAS_MAXPROCS, &maxprocs)
	    == Z_OK &&
	    zonecfg_get_aliased_rctl(handle, ALIAS_MAXLWPS, &maxlwps)
	    == Z_NO_ENTRY) {
		if (zonecfg_set_aliased_rctl(handle, ALIAS_MAXLWPS,
		    maxprocs * LWPS_PER_PROCESS) != Z_OK) {
			zerror(zlogp, B_FALSE, "unable to set max-lwps alias");
			goto out;
		}
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
	nvlist_free(nvl);
	if (nvlv != NULL)
		free(nvlv);
	if (handle != NULL)
		zonecfg_fini_handle(handle);
	return (error);
}

static int
get_implicit_datasets(zlog_t *zlogp, char **retstr)
{
	char cmdbuf[2 * MAXPATHLEN];

	if (query_hook[0] == '\0')
		return (0);

	if (snprintf(cmdbuf, sizeof (cmdbuf), "%s datasets", query_hook)
	    > sizeof (cmdbuf))
		return (-1);

	if (do_subproc(zlogp, cmdbuf, retstr) != 0)
		return (-1);

	return (0);
}

static int
get_datasets(zlog_t *zlogp, char **bufp, size_t *bufsizep)
{
	zone_dochandle_t handle;
	struct zone_dstab dstab;
	size_t total, offset, len;
	int error = -1;
	char *str = NULL;
	char *implicit_datasets = NULL;
	int implicit_len = 0;

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

	if (get_implicit_datasets(zlogp, &implicit_datasets) != 0) {
		zerror(zlogp, B_FALSE, "getting implicit datasets failed");
		goto out;
	}

	if (zonecfg_setdsent(handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "%s failed", "zonecfg_setdsent");
		goto out;
	}

	total = 0;
	while (zonecfg_getdsent(handle, &dstab) == Z_OK)
		total += strlen(dstab.zone_dataset_name) + 1;
	(void) zonecfg_enddsent(handle);

	if (implicit_datasets != NULL)
		implicit_len = strlen(implicit_datasets);
	if (implicit_len > 0)
		total += implicit_len + 1;

	if (total == 0) {
		error = 0;
		goto out;
	}

	if ((str = malloc(total)) == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		goto out;
	}

	if (zonecfg_setdsent(handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "%s failed", "zonecfg_setdsent");
		goto out;
	}
	offset = 0;
	while (zonecfg_getdsent(handle, &dstab) == Z_OK) {
		len = strlen(dstab.zone_dataset_name);
		(void) strlcpy(str + offset, dstab.zone_dataset_name,
		    total - offset);
		offset += len;
		if (offset < total - 1)
			str[offset++] = ',';
	}
	(void) zonecfg_enddsent(handle);

	if (implicit_len > 0)
		(void) strlcpy(str + offset, implicit_datasets, total - offset);

	error = 0;
	*bufp = str;
	*bufsizep = total;

out:
	if (error != 0 && str != NULL)
		free(str);
	if (handle != NULL)
		zonecfg_fini_handle(handle);
	if (implicit_datasets != NULL)
		free(implicit_datasets);

	return (error);
}

static int
validate_datasets(zlog_t *zlogp)
{
	zone_dochandle_t handle;
	struct zone_dstab dstab;
	zfs_handle_t *zhp;
	libzfs_handle_t *hdl;

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		return (-1);
	}
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		zonecfg_fini_handle(handle);
		return (-1);
	}

	if (zonecfg_setdsent(handle) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		zonecfg_fini_handle(handle);
		return (-1);
	}

	if ((hdl = libzfs_init()) == NULL) {
		zerror(zlogp, B_FALSE, "opening ZFS library");
		zonecfg_fini_handle(handle);
		return (-1);
	}

	while (zonecfg_getdsent(handle, &dstab) == Z_OK) {

		if ((zhp = zfs_open(hdl, dstab.zone_dataset_name,
		    ZFS_TYPE_FILESYSTEM)) == NULL) {
			zerror(zlogp, B_FALSE, "cannot open ZFS dataset '%s'",
			    dstab.zone_dataset_name);
			zonecfg_fini_handle(handle);
			libzfs_fini(hdl);
			return (-1);
		}

		/*
		 * Automatically set the 'zoned' property.  We check the value
		 * first because we'll get EPERM if it is already set.
		 */
		if (!zfs_prop_get_int(zhp, ZFS_PROP_ZONED) &&
		    zfs_prop_set(zhp, zfs_prop_to_name(ZFS_PROP_ZONED),
		    "on") != 0) {
			zerror(zlogp, B_FALSE, "cannot set 'zoned' "
			    "property for ZFS dataset '%s'\n",
			    dstab.zone_dataset_name);
			zonecfg_fini_handle(handle);
			zfs_close(zhp);
			libzfs_fini(hdl);
			return (-1);
		}

		zfs_close(zhp);
	}
	(void) zonecfg_enddsent(handle);

	zonecfg_fini_handle(handle);
	libzfs_fini(hdl);

	return (0);
}

/*
 * Return true if the path is its own zfs file system.  We determine this
 * by stat-ing the path to see if it is zfs and stat-ing the parent to see
 * if it is a different fs.
 */
boolean_t
is_zonepath_zfs(char *zonepath)
{
	int res;
	char *path;
	char *parent;
	struct statvfs64 buf1, buf2;

	if (statvfs64(zonepath, &buf1) != 0)
		return (B_FALSE);

	if (strcmp(buf1.f_basetype, "zfs") != 0)
		return (B_FALSE);

	if ((path = strdup(zonepath)) == NULL)
		return (B_FALSE);

	parent = dirname(path);
	res = statvfs64(parent, &buf2);
	free(path);

	if (res != 0)
		return (B_FALSE);

	if (buf1.f_fsid == buf2.f_fsid)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Verify the MAC label in the root dataset for the zone.
 * If the label exists, it must match the label configured for the zone.
 * Otherwise if there's no label on the dataset, create one here.
 */

static int
validate_rootds_label(zlog_t *zlogp, char *rootpath, m_label_t *zone_sl)
{
	int		error = -1;
	zfs_handle_t	*zhp;
	libzfs_handle_t	*hdl;
	m_label_t	ds_sl;
	char		zonepath[MAXPATHLEN];
	char		ds_hexsl[MAXNAMELEN];

	if (!is_system_labeled())
		return (0);

	if (zone_get_zonepath(zone_name, zonepath, sizeof (zonepath)) != Z_OK) {
		zerror(zlogp, B_TRUE, "unable to determine zone path");
		return (-1);
	}

	if (!is_zonepath_zfs(zonepath))
		return (0);

	if ((hdl = libzfs_init()) == NULL) {
		zerror(zlogp, B_FALSE, "opening ZFS library");
		return (-1);
	}

	if ((zhp = zfs_path_to_zhandle(hdl, rootpath,
	    ZFS_TYPE_FILESYSTEM)) == NULL) {
		zerror(zlogp, B_FALSE, "cannot open ZFS dataset for path '%s'",
		    rootpath);
		libzfs_fini(hdl);
		return (-1);
	}

	/* Get the mlslabel property if it exists. */
	if ((zfs_prop_get(zhp, ZFS_PROP_MLSLABEL, ds_hexsl, MAXNAMELEN,
	    NULL, NULL, 0, B_TRUE) != 0) ||
	    (strcmp(ds_hexsl, ZFS_MLSLABEL_DEFAULT) == 0)) {
		char		*str2 = NULL;

		/*
		 * No label on the dataset (or default only); create one.
		 * (Only do this automatic labeling for the labeled brand.)
		 */
		if (strcmp(brand_name, LABELED_BRAND_NAME) != 0) {
			error = 0;
			goto out;
		}

		error = l_to_str_internal(zone_sl, &str2);
		if (error)
			goto out;
		if (str2 == NULL) {
			error = -1;
			goto out;
		}
		if ((error = zfs_prop_set(zhp,
		    zfs_prop_to_name(ZFS_PROP_MLSLABEL), str2)) != 0) {
			zerror(zlogp, B_FALSE, "cannot set 'mlslabel' "
			    "property for root dataset at '%s'\n", rootpath);
		}
		free(str2);
		goto out;
	}

	/* Convert the retrieved dataset label to binary form. */
	error = hexstr_to_label(ds_hexsl, &ds_sl);
	if (error) {
		zerror(zlogp, B_FALSE, "invalid 'mlslabel' "
		    "property on root dataset at '%s'\n", rootpath);
		goto out;			/* exit with error */
	}

	/*
	 * Perform a MAC check by comparing the zone label with the
	 * dataset label.
	 */
	error = (!blequal(zone_sl, &ds_sl));
	if (error)
		zerror(zlogp, B_FALSE, "Rootpath dataset has mismatched label");
out:
	zfs_close(zhp);
	libzfs_fini(hdl);

	return (error);
}

/*
 * Mount lower level home directories into/from current zone
 * Share exported directories specified in dfstab for zone
 */
static int
tsol_mounts(zlog_t *zlogp, char *zone_name, char *rootpath)
{
	zoneid_t *zids = NULL;
	priv_set_t *zid_privs;
	const priv_impl_info_t *ip = NULL;
	uint_t nzents_saved;
	uint_t nzents;
	int i;
	char readonly[] = "ro";
	struct zone_fstab lower_fstab;
	char *argv[4];

	if (!is_system_labeled())
		return (0);

	if (zid_label == NULL) {
		zid_label = m_label_alloc(MAC_LABEL);
		if (zid_label == NULL)
			return (-1);
	}

	/* Make sure our zone has an /export/home dir */
	(void) make_one_dir(zlogp, rootpath, "/export/home",
	    DEFAULT_DIR_MODE, DEFAULT_DIR_USER, DEFAULT_DIR_GROUP);

	lower_fstab.zone_fs_raw[0] = '\0';
	(void) strlcpy(lower_fstab.zone_fs_type, MNTTYPE_LOFS,
	    sizeof (lower_fstab.zone_fs_type));
	lower_fstab.zone_fs_options = NULL;
	(void) zonecfg_add_fs_option(&lower_fstab, readonly);

	/*
	 * Get the list of zones from the kernel
	 */
	if (zone_list(NULL, &nzents) != 0) {
		zerror(zlogp, B_TRUE, "unable to list zones");
		zonecfg_free_fs_option_list(lower_fstab.zone_fs_options);
		return (-1);
	}
again:
	if (nzents == 0) {
		zonecfg_free_fs_option_list(lower_fstab.zone_fs_options);
		return (-1);
	}

	zids = malloc(nzents * sizeof (zoneid_t));
	if (zids == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		return (-1);
	}
	nzents_saved = nzents;

	if (zone_list(zids, &nzents) != 0) {
		zerror(zlogp, B_TRUE, "unable to list zones");
		zonecfg_free_fs_option_list(lower_fstab.zone_fs_options);
		free(zids);
		return (-1);
	}
	if (nzents != nzents_saved) {
		/* list changed, try again */
		free(zids);
		goto again;
	}

	ip = getprivimplinfo();
	if ((zid_privs = priv_allocset()) == NULL) {
		zerror(zlogp, B_TRUE, "%s failed", "priv_allocset");
		zonecfg_free_fs_option_list(
		    lower_fstab.zone_fs_options);
		free(zids);
		return (-1);
	}

	for (i = 0; i < nzents; i++) {
		char zid_name[ZONENAME_MAX];
		zone_state_t zid_state;
		char zid_rpath[MAXPATHLEN];
		struct stat stat_buf;

		if (zids[i] == GLOBAL_ZONEID)
			continue;

		if (getzonenamebyid(zids[i], zid_name, ZONENAME_MAX) == -1)
			continue;

		/*
		 * Do special setup for the zone we are booting
		 */
		if (strcmp(zid_name, zone_name) == 0) {
			struct zone_fstab autofs_fstab;
			char map_path[MAXPATHLEN];
			int fd;

			/*
			 * Create auto_home_<zone> map for this zone
			 * in the global zone. The non-global zone entry
			 * will be created by automount when the zone
			 * is booted.
			 */

			(void) snprintf(autofs_fstab.zone_fs_special,
			    MAXPATHLEN, "auto_home_%s", zid_name);

			(void) snprintf(autofs_fstab.zone_fs_dir, MAXPATHLEN,
			    "/zone/%s/home", zid_name);

			(void) snprintf(map_path, sizeof (map_path),
			    "/etc/%s", autofs_fstab.zone_fs_special);
			/*
			 * If the map file doesn't exist create a template
			 */
			if ((fd = open(map_path, O_RDWR | O_CREAT | O_EXCL,
			    S_IRUSR | S_IWUSR | S_IRGRP| S_IROTH)) != -1) {
				int len;
				char map_rec[MAXPATHLEN];

				len = snprintf(map_rec, sizeof (map_rec),
				    "+%s\n*\t-fstype=lofs\t:%s/export/home/&\n",
				    autofs_fstab.zone_fs_special, rootpath);
				(void) write(fd, map_rec, len);
				(void) close(fd);
			}

			/*
			 * Mount auto_home_<zone> in the global zone if absent.
			 * If it's already of type autofs, then
			 * don't mount it again.
			 */
			if ((stat(autofs_fstab.zone_fs_dir, &stat_buf) == -1) ||
			    strcmp(stat_buf.st_fstype, MNTTYPE_AUTOFS) != 0) {
				char optstr[] = "indirect,ignore,nobrowse";

				(void) make_one_dir(zlogp, "",
				    autofs_fstab.zone_fs_dir, DEFAULT_DIR_MODE,
				    DEFAULT_DIR_USER, DEFAULT_DIR_GROUP);

				/*
				 * Mount will fail if automounter has already
				 * processed the auto_home_<zonename> map
				 */
				(void) domount(zlogp, MNTTYPE_AUTOFS, optstr,
				    autofs_fstab.zone_fs_special,
				    autofs_fstab.zone_fs_dir);
			}
			continue;
		}


		if (zone_get_state(zid_name, &zid_state) != Z_OK ||
		    (zid_state != ZONE_STATE_READY &&
		    zid_state != ZONE_STATE_RUNNING))
			/* Skip over zones without mounted filesystems */
			continue;

		if (zone_getattr(zids[i], ZONE_ATTR_SLBL, zid_label,
		    sizeof (m_label_t)) < 0)
			/* Skip over zones with unspecified label */
			continue;

		if (zone_getattr(zids[i], ZONE_ATTR_ROOT, zid_rpath,
		    sizeof (zid_rpath)) == -1)
			/* Skip over zones with bad path */
			continue;

		if (zone_getattr(zids[i], ZONE_ATTR_PRIVSET, zid_privs,
		    sizeof (priv_chunk_t) * ip->priv_setsize) == -1)
			/* Skip over zones with bad privs */
			continue;

		/*
		 * Reading down is valid according to our label model
		 * but some customers want to disable it because it
		 * allows execute down and other possible attacks.
		 * Therefore, we restrict this feature to zones that
		 * have the NET_MAC_AWARE privilege which is required
		 * for NFS read-down semantics.
		 */
		if ((bldominates(zlabel, zid_label)) &&
		    (priv_ismember(zprivs, PRIV_NET_MAC_AWARE))) {
			/*
			 * Our zone dominates this one.
			 * Create a lofs mount from lower zone's /export/home
			 */
			(void) snprintf(lower_fstab.zone_fs_dir, MAXPATHLEN,
			    "%s/zone/%s/export/home", rootpath, zid_name);

			/*
			 * If the target is already an LOFS mount
			 * then don't do it again.
			 */
			if ((stat(lower_fstab.zone_fs_dir, &stat_buf) == -1) ||
			    strcmp(stat_buf.st_fstype, MNTTYPE_LOFS) != 0) {

				if (snprintf(lower_fstab.zone_fs_special,
				    MAXPATHLEN, "%s/export",
				    zid_rpath) > MAXPATHLEN)
					continue;

				/*
				 * Make sure the lower-level home exists
				 */
				if (make_one_dir(zlogp,
				    lower_fstab.zone_fs_special, "/home",
				    DEFAULT_DIR_MODE, DEFAULT_DIR_USER,
				    DEFAULT_DIR_GROUP) != 0)
					continue;

				(void) strlcat(lower_fstab.zone_fs_special,
				    "/home", MAXPATHLEN);

				/*
				 * Mount can fail because the lower-level
				 * zone may have already done a mount up.
				 */
				(void) mount_one(zlogp, &lower_fstab, "",
				    Z_MNT_BOOT);
			}
		} else if ((bldominates(zid_label, zlabel)) &&
		    (priv_ismember(zid_privs, PRIV_NET_MAC_AWARE))) {
			/*
			 * This zone dominates our zone.
			 * Create a lofs mount from our zone's /export/home
			 */
			if (snprintf(lower_fstab.zone_fs_dir, MAXPATHLEN,
			    "%s/zone/%s/export/home", zid_rpath,
			    zone_name) > MAXPATHLEN)
				continue;

			/*
			 * If the target is already an LOFS mount
			 * then don't do it again.
			 */
			if ((stat(lower_fstab.zone_fs_dir, &stat_buf) == -1) ||
			    strcmp(stat_buf.st_fstype, MNTTYPE_LOFS) != 0) {

				(void) snprintf(lower_fstab.zone_fs_special,
				    MAXPATHLEN, "%s/export/home", rootpath);

				/*
				 * Mount can fail because the higher-level
				 * zone may have already done a mount down.
				 */
				(void) mount_one(zlogp, &lower_fstab, "",
				    Z_MNT_BOOT);
			}
		}
	}
	zonecfg_free_fs_option_list(lower_fstab.zone_fs_options);
	priv_freeset(zid_privs);
	free(zids);

	/*
	 * Now share any exported directories from this zone.
	 * Each zone can have its own dfstab.
	 */

	argv[0] = "zoneshare";
	argv[1] = "-z";
	argv[2] = zone_name;
	argv[3] = NULL;

	(void) forkexec(zlogp, "/usr/lib/zones/zoneshare", argv);
	/* Don't check for errors since they don't affect the zone */

	return (0);
}

/*
 * Unmount lofs mounts from higher level zones
 * Unshare nfs exported directories
 */
static void
tsol_unmounts(zlog_t *zlogp, char *zone_name)
{
	zoneid_t *zids = NULL;
	uint_t nzents_saved;
	uint_t nzents;
	int i;
	char *argv[4];
	char path[MAXPATHLEN];

	if (!is_system_labeled())
		return;

	/*
	 * Get the list of zones from the kernel
	 */
	if (zone_list(NULL, &nzents) != 0) {
		return;
	}

	if (zid_label == NULL) {
		zid_label = m_label_alloc(MAC_LABEL);
		if (zid_label == NULL)
			return;
	}

again:
	if (nzents == 0)
		return;

	zids = malloc(nzents * sizeof (zoneid_t));
	if (zids == NULL) {
		zerror(zlogp, B_TRUE, "memory allocation failed");
		return;
	}
	nzents_saved = nzents;

	if (zone_list(zids, &nzents) != 0) {
		free(zids);
		return;
	}
	if (nzents != nzents_saved) {
		/* list changed, try again */
		free(zids);
		goto again;
	}

	for (i = 0; i < nzents; i++) {
		char zid_name[ZONENAME_MAX];
		zone_state_t zid_state;
		char zid_rpath[MAXPATHLEN];

		if (zids[i] == GLOBAL_ZONEID)
			continue;

		if (getzonenamebyid(zids[i], zid_name, ZONENAME_MAX) == -1)
			continue;

		/*
		 * Skip the zone we are halting
		 */
		if (strcmp(zid_name, zone_name) == 0)
			continue;

		if ((zone_getattr(zids[i], ZONE_ATTR_STATUS, &zid_state,
		    sizeof (zid_state)) < 0) ||
		    (zid_state < ZONE_IS_READY))
			/* Skip over zones without mounted filesystems */
			continue;

		if (zone_getattr(zids[i], ZONE_ATTR_SLBL, zid_label,
		    sizeof (m_label_t)) < 0)
			/* Skip over zones with unspecified label */
			continue;

		if (zone_getattr(zids[i], ZONE_ATTR_ROOT, zid_rpath,
		    sizeof (zid_rpath)) == -1)
			/* Skip over zones with bad path */
			continue;

		if (zlabel != NULL && bldominates(zid_label, zlabel)) {
			/*
			 * This zone dominates our zone.
			 * Unmount the lofs mount of our zone's /export/home
			 */

			if (snprintf(path, MAXPATHLEN,
			    "%s/zone/%s/export/home", zid_rpath,
			    zone_name) > MAXPATHLEN)
				continue;

			/* Skip over mount failures */
			(void) umount(path);
		}
	}
	free(zids);

	/*
	 * Unmount global zone autofs trigger for this zone
	 */
	(void) snprintf(path, MAXPATHLEN, "/zone/%s/home", zone_name);
	/* Skip over mount failures */
	(void) umount(path);

	/*
	 * Next unshare any exported directories from this zone.
	 */

	argv[0] = "zoneunshare";
	argv[1] = "-z";
	argv[2] = zone_name;
	argv[3] = NULL;

	(void) forkexec(zlogp, "/usr/lib/zones/zoneunshare", argv);
	/* Don't check for errors since they don't affect the zone */

	/*
	 * Finally, deallocate any devices in the zone.
	 */

	argv[0] = "deallocate";
	argv[1] = "-Isz";
	argv[2] = zone_name;
	argv[3] = NULL;

	(void) forkexec(zlogp, "/usr/sbin/deallocate", argv);
	/* Don't check for errors since they don't affect the zone */
}

/*
 * Fetch the Trusted Extensions label and multi-level ports (MLPs) for
 * this zone.
 */
static tsol_zcent_t *
get_zone_label(zlog_t *zlogp, priv_set_t *privs)
{
	FILE *fp;
	tsol_zcent_t *zcent = NULL;
	char line[MAXTNZLEN];

	if ((fp = fopen(TNZONECFG_PATH, "r")) == NULL) {
		zerror(zlogp, B_TRUE, "%s", TNZONECFG_PATH);
		return (NULL);
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		/*
		 * Check for malformed database
		 */
		if (strlen(line) == MAXTNZLEN - 1)
			break;
		if ((zcent = tsol_sgetzcent(line, NULL, NULL)) == NULL)
			continue;
		if (strcmp(zcent->zc_name, zone_name) == 0)
			break;
		tsol_freezcent(zcent);
		zcent = NULL;
	}
	(void) fclose(fp);

	if (zcent == NULL) {
		zerror(zlogp, B_FALSE, "zone requires a label assignment. "
		    "See tnzonecfg(4)");
	} else {
		if (zlabel == NULL)
			zlabel = m_label_alloc(MAC_LABEL);
		/*
		 * Save this zone's privileges for later read-down processing
		 */
		if ((zprivs = priv_allocset()) == NULL) {
			zerror(zlogp, B_TRUE, "%s failed", "priv_allocset");
			return (NULL);
		} else {
			priv_copyset(privs, zprivs);
		}
	}
	return (zcent);
}

/*
 * Add the Trusted Extensions multi-level ports for this zone.
 */
static void
set_mlps(zlog_t *zlogp, zoneid_t zoneid, tsol_zcent_t *zcent)
{
	tsol_mlp_t *mlp;
	tsol_mlpent_t tsme;

	if (!is_system_labeled())
		return;

	tsme.tsme_zoneid = zoneid;
	tsme.tsme_flags = 0;
	for (mlp = zcent->zc_private_mlp; !TSOL_MLP_END(mlp); mlp++) {
		tsme.tsme_mlp = *mlp;
		if (tnmlp(TNDB_LOAD, &tsme) != 0) {
			zerror(zlogp, B_TRUE, "cannot set zone-specific MLP "
			    "on %d-%d/%d", mlp->mlp_port,
			    mlp->mlp_port_upper, mlp->mlp_ipp);
		}
	}

	tsme.tsme_flags = TSOL_MEF_SHARED;
	for (mlp = zcent->zc_shared_mlp; !TSOL_MLP_END(mlp); mlp++) {
		tsme.tsme_mlp = *mlp;
		if (tnmlp(TNDB_LOAD, &tsme) != 0) {
			zerror(zlogp, B_TRUE, "cannot set shared MLP "
			    "on %d-%d/%d", mlp->mlp_port,
			    mlp->mlp_port_upper, mlp->mlp_ipp);
		}
	}
}

static void
remove_mlps(zlog_t *zlogp, zoneid_t zoneid)
{
	tsol_mlpent_t tsme;

	if (!is_system_labeled())
		return;

	(void) memset(&tsme, 0, sizeof (tsme));
	tsme.tsme_zoneid = zoneid;
	if (tnmlp(TNDB_FLUSH, &tsme) != 0)
		zerror(zlogp, B_TRUE, "cannot flush MLPs");
}

int
prtmount(const struct mnttab *fs, void *x)
{
	zerror((zlog_t *)x, B_FALSE, "  %s", fs->mnt_mountp);
	return (0);
}

/*
 * Look for zones running on the main system that are using this root (or any
 * subdirectory of it).  Return B_TRUE and print an error if a conflicting zone
 * is found or if we can't tell.
 */
static boolean_t
duplicate_zone_root(zlog_t *zlogp, const char *rootpath)
{
	zoneid_t *zids = NULL;
	uint_t nzids = 0;
	boolean_t retv;
	int rlen, zlen;
	char zroot[MAXPATHLEN];
	char zonename[ZONENAME_MAX];

	for (;;) {
		nzids += 10;
		zids = malloc(nzids * sizeof (*zids));
		if (zids == NULL) {
			zerror(zlogp, B_TRUE, "memory allocation failed");
			return (B_TRUE);
		}
		if (zone_list(zids, &nzids) == 0)
			break;
		free(zids);
	}
	retv = B_FALSE;
	rlen = strlen(rootpath);
	while (nzids > 0) {
		/*
		 * Ignore errors; they just mean that the zone has disappeared
		 * while we were busy.
		 */
		if (zone_getattr(zids[--nzids], ZONE_ATTR_ROOT, zroot,
		    sizeof (zroot)) == -1)
			continue;
		zlen = strlen(zroot);
		if (zlen > rlen)
			zlen = rlen;
		if (strncmp(rootpath, zroot, zlen) == 0 &&
		    (zroot[zlen] == '\0' || zroot[zlen] == '/') &&
		    (rootpath[zlen] == '\0' || rootpath[zlen] == '/')) {
			if (getzonenamebyid(zids[nzids], zonename,
			    sizeof (zonename)) == -1)
				(void) snprintf(zonename, sizeof (zonename),
				    "id %d", (int)zids[nzids]);
			zerror(zlogp, B_FALSE,
			    "zone root %s already in use by zone %s",
			    rootpath, zonename);
			retv = B_TRUE;
			break;
		}
	}
	free(zids);
	return (retv);
}

/*
 * Search for loopback mounts that use this same source node (same device and
 * inode).  Return B_TRUE if there is one or if we can't tell.
 */
static boolean_t
duplicate_reachable_path(zlog_t *zlogp, const char *rootpath)
{
	struct stat64 rst, zst;
	struct mnttab *mnp;

	if (stat64(rootpath, &rst) == -1) {
		zerror(zlogp, B_TRUE, "can't stat %s", rootpath);
		return (B_TRUE);
	}
	if (resolve_lofs_mnts == NULL && lofs_read_mnttab(zlogp) == -1)
		return (B_TRUE);
	for (mnp = resolve_lofs_mnts; mnp < resolve_lofs_mnt_max; mnp++) {
		if (mnp->mnt_fstype == NULL ||
		    strcmp(MNTTYPE_LOFS, mnp->mnt_fstype) != 0)
			continue;
		/* We're looking at a loopback mount.  Stat it. */
		if (mnp->mnt_special != NULL &&
		    stat64(mnp->mnt_special, &zst) != -1 &&
		    rst.st_dev == zst.st_dev && rst.st_ino == zst.st_ino) {
			zerror(zlogp, B_FALSE,
			    "zone root %s is reachable through %s",
			    rootpath, mnp->mnt_mountp);
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * Set memory cap and pool info for the zone's resource management
 * configuration.
 */
static int
setup_zone_rm(zlog_t *zlogp, char *zone_name, zoneid_t zoneid)
{
	int res;
	uint64_t tmp;
	struct zone_mcaptab mcap;
	char sched[MAXNAMELEN];
	zone_dochandle_t handle = NULL;
	char pool_err[128];

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		return (Z_BAD_HANDLE);
	}

	if ((res = zonecfg_get_snapshot_handle(zone_name, handle)) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		zonecfg_fini_handle(handle);
		return (res);
	}

	/*
	 * If a memory cap is configured, set the cap in the kernel using
	 * zone_setattr() and make sure the rcapd SMF service is enabled.
	 */
	if (zonecfg_getmcapent(handle, &mcap) == Z_OK) {
		uint64_t num;
		char smf_err[128];

		num = (uint64_t)strtoull(mcap.zone_physmem_cap, NULL, 10);
		if (zone_setattr(zoneid, ZONE_ATTR_PHYS_MCAP, &num, 0) == -1) {
			zerror(zlogp, B_TRUE, "could not set zone memory cap");
			zonecfg_fini_handle(handle);
			return (Z_INVAL);
		}

		if (zonecfg_enable_rcapd(smf_err, sizeof (smf_err)) != Z_OK) {
			zerror(zlogp, B_FALSE, "enabling system/rcap service "
			    "failed: %s", smf_err);
			zonecfg_fini_handle(handle);
			return (Z_INVAL);
		}
	}

	/* Get the scheduling class set in the zone configuration. */
	if (zonecfg_get_sched_class(handle, sched, sizeof (sched)) == Z_OK &&
	    strlen(sched) > 0) {
		if (zone_setattr(zoneid, ZONE_ATTR_SCHED_CLASS, sched,
		    strlen(sched)) == -1)
			zerror(zlogp, B_TRUE, "WARNING: unable to set the "
			    "default scheduling class");

	} else if (zonecfg_get_aliased_rctl(handle, ALIAS_SHARES, &tmp)
	    == Z_OK) {
		/*
		 * If the zone has the zone.cpu-shares rctl set then we want to
		 * use the Fair Share Scheduler (FSS) for processes in the
		 * zone.  Check what scheduling class the zone would be running
		 * in by default so we can print a warning and modify the class
		 * if we wouldn't be using FSS.
		 */
		char class_name[PC_CLNMSZ];

		if (zonecfg_get_dflt_sched_class(handle, class_name,
		    sizeof (class_name)) != Z_OK) {
			zerror(zlogp, B_FALSE, "WARNING: unable to determine "
			    "the zone's scheduling class");

		} else if (strcmp("FSS", class_name) != 0) {
			zerror(zlogp, B_FALSE, "WARNING: The zone.cpu-shares "
			    "rctl is set but\nFSS is not the default "
			    "scheduling class for\nthis zone.  FSS will be "
			    "used for processes\nin the zone but to get the "
			    "full benefit of FSS,\nit should be the default "
			    "scheduling class.\nSee dispadmin(1M) for more "
			    "details.");

			if (zone_setattr(zoneid, ZONE_ATTR_SCHED_CLASS, "FSS",
			    strlen("FSS")) == -1)
				zerror(zlogp, B_TRUE, "WARNING: unable to set "
				    "zone scheduling class to FSS");
		}
	}

	/*
	 * The next few blocks of code attempt to set up temporary pools as
	 * well as persistent pools.  In all cases we call the functions
	 * unconditionally.  Within each funtion the code will check if the
	 * zone is actually configured for a temporary pool or persistent pool
	 * and just return if there is nothing to do.
	 *
	 * If we are rebooting we want to attempt to reuse any temporary pool
	 * that was previously set up.  zonecfg_bind_tmp_pool() will do the
	 * right thing in all cases (reuse or create) based on the current
	 * zonecfg.
	 */
	if ((res = zonecfg_bind_tmp_pool(handle, zoneid, pool_err,
	    sizeof (pool_err))) != Z_OK) {
		if (res == Z_POOL || res == Z_POOL_CREATE || res == Z_POOL_BIND)
			zerror(zlogp, B_FALSE, "%s: %s\ndedicated-cpu setting "
			    "cannot be instantiated", zonecfg_strerror(res),
			    pool_err);
		else
			zerror(zlogp, B_FALSE, "could not bind zone to "
			    "temporary pool: %s", zonecfg_strerror(res));
		zonecfg_fini_handle(handle);
		return (Z_POOL_BIND);
	}

	/*
	 * Check if we need to warn about poold not being enabled.
	 */
	if (zonecfg_warn_poold(handle)) {
		zerror(zlogp, B_FALSE, "WARNING: A range of dedicated-cpus has "
		    "been specified\nbut the dynamic pool service is not "
		    "enabled.\nThe system will not dynamically adjust the\n"
		    "processor allocation within the specified range\n"
		    "until svc:/system/pools/dynamic is enabled.\n"
		    "See poold(1M).");
	}

	/* The following is a warning, not an error. */
	if ((res = zonecfg_bind_pool(handle, zoneid, pool_err,
	    sizeof (pool_err))) != Z_OK) {
		if (res == Z_POOL_BIND)
			zerror(zlogp, B_FALSE, "WARNING: unable to bind to "
			    "pool '%s'; using default pool.", pool_err);
		else if (res == Z_POOL)
			zerror(zlogp, B_FALSE, "WARNING: %s: %s",
			    zonecfg_strerror(res), pool_err);
		else
			zerror(zlogp, B_FALSE, "WARNING: %s",
			    zonecfg_strerror(res));
	}

	/* Update saved pool name in case it has changed */
	(void) zonecfg_get_poolname(handle, zone_name, pool_name,
	    sizeof (pool_name));

	zonecfg_fini_handle(handle);
	return (Z_OK);
}

static void
report_prop_err(zlog_t *zlogp, const char *name, const char *value, int res)
{
	switch (res) {
	case Z_TOO_BIG:
		zerror(zlogp, B_FALSE, "%s property value is too large.", name);
		break;

	case Z_INVALID_PROPERTY:
		zerror(zlogp, B_FALSE, "%s property value \"%s\" is not valid",
		    name, value);
		break;

	default:
		zerror(zlogp, B_TRUE, "fetching property %s: %d", name, res);
		break;
	}
}

/*
 * Sets the hostid of the new zone based on its configured value.  The zone's
 * zone_t structure must already exist in kernel memory.  'zlogp' refers to the
 * log used to report errors and warnings and must be non-NULL.  'zone_namep'
 * is the name of the new zone and must be non-NULL.  'zoneid' is the numeric
 * ID of the new zone.
 *
 * This function returns zero on success and a nonzero error code on failure.
 */
static int
setup_zone_hostid(zone_dochandle_t handle, zlog_t *zlogp, zoneid_t zoneid)
{
	int res;
	char hostidp[HW_HOSTID_LEN];
	unsigned int hostid;

	res = zonecfg_get_hostid(handle, hostidp, sizeof (hostidp));

	if (res == Z_BAD_PROPERTY) {
		return (Z_OK);
	} else if (res != Z_OK) {
		report_prop_err(zlogp, "hostid", hostidp, res);
		return (res);
	}

	hostid = (unsigned int)strtoul(hostidp, NULL, 16);
	if ((res = zone_setattr(zoneid, ZONE_ATTR_HOSTID, &hostid,
	    sizeof (hostid))) != 0) {
		zerror(zlogp, B_TRUE,
		    "zone hostid is not valid: %s: %d", hostidp, res);
		return (Z_SYSTEM);
	}

	return (res);
}

static int
setup_zone_fs_allowed(zone_dochandle_t handle, zlog_t *zlogp, zoneid_t zoneid)
{
	char fsallowed[ZONE_FS_ALLOWED_MAX];
	char *fsallowedp = fsallowed;
	int len = sizeof (fsallowed);
	int res;

	res = zonecfg_get_fs_allowed(handle, fsallowed, len);

	if (res == Z_BAD_PROPERTY) {
		/* No value, set the defaults */
		(void) strlcpy(fsallowed, DFLT_FS_ALLOWED, len);
	} else if (res != Z_OK) {
		report_prop_err(zlogp, "fs-allowed", fsallowed, res);
		return (res);
	} else if (fsallowed[0] == '-') {
		/* dropping default privs - use remaining list */
		if (fsallowed[1] != ',')
			return (Z_OK);
		fsallowedp += 2;
		len -= 2;
	} else {
		/* Has a value, append the defaults */
		if (strlcat(fsallowed, ",", len) >= len ||
		    strlcat(fsallowed, DFLT_FS_ALLOWED, len) >= len) {
			report_prop_err(zlogp, "fs-allowed", fsallowed,
			    Z_TOO_BIG);
			return (Z_TOO_BIG);
		}
	}

	if (zone_setattr(zoneid, ZONE_ATTR_FS_ALLOWED, fsallowedp, len) != 0) {
		zerror(zlogp, B_TRUE,
		    "fs-allowed couldn't be set: %s: %d", fsallowedp, res);
		return (Z_SYSTEM);
	}

	return (Z_OK);
}

static int
setup_zone_attrs(zlog_t *zlogp, char *zone_namep, zoneid_t zoneid)
{
	zone_dochandle_t handle;
	int res = Z_OK;

	if ((handle = zonecfg_init_handle()) == NULL) {
		zerror(zlogp, B_TRUE, "getting zone configuration handle");
		return (Z_BAD_HANDLE);
	}
	if ((res = zonecfg_get_snapshot_handle(zone_namep, handle)) != Z_OK) {
		zerror(zlogp, B_FALSE, "invalid configuration");
		goto out;
	}

	if ((res = setup_zone_hostid(handle, zlogp, zoneid)) != Z_OK)
		goto out;

	if ((res = setup_zone_fs_allowed(handle, zlogp, zoneid)) != Z_OK)
		goto out;

out:
	zonecfg_fini_handle(handle);
	return (res);
}

zoneid_t
vplat_create(zlog_t *zlogp, zone_mnt_t mount_cmd)
{
	zoneid_t rval = -1;
	priv_set_t *privs;
	char rootpath[MAXPATHLEN];
	char *rctlbuf = NULL;
	size_t rctlbufsz = 0;
	char *zfsbuf = NULL;
	size_t zfsbufsz = 0;
	zoneid_t zoneid = -1;
	int xerr;
	char *kzone;
	FILE *fp = NULL;
	tsol_zcent_t *zcent = NULL;
	int match = 0;
	int doi = 0;
	int flags;
	zone_iptype_t iptype;

	if (zone_get_rootpath(zone_name, rootpath, sizeof (rootpath)) != Z_OK) {
		zerror(zlogp, B_TRUE, "unable to determine zone root");
		return (-1);
	}
	if (zonecfg_in_alt_root())
		resolve_lofs(zlogp, rootpath, sizeof (rootpath));

	if (vplat_get_iptype(zlogp, &iptype) < 0) {
		zerror(zlogp, B_TRUE, "unable to determine ip-type");
		return (-1);
	}
	switch (iptype) {
	case ZS_SHARED:
		flags = 0;
		break;
	case ZS_EXCLUSIVE:
		flags = ZCF_NET_EXCL;
		break;
	}

	if ((privs = priv_allocset()) == NULL) {
		zerror(zlogp, B_TRUE, "%s failed", "priv_allocset");
		return (-1);
	}
	priv_emptyset(privs);
	if (get_privset(zlogp, privs, mount_cmd) != 0)
		goto error;

	if (mount_cmd == Z_MNT_BOOT &&
	    get_rctls(zlogp, &rctlbuf, &rctlbufsz) != 0) {
		zerror(zlogp, B_FALSE, "Unable to get list of rctls");
		goto error;
	}

	if (get_datasets(zlogp, &zfsbuf, &zfsbufsz) != 0) {
		zerror(zlogp, B_FALSE, "Unable to get list of ZFS datasets");
		goto error;
	}

	if (mount_cmd == Z_MNT_BOOT && is_system_labeled()) {
		zcent = get_zone_label(zlogp, privs);
		if (zcent != NULL) {
			match = zcent->zc_match;
			doi = zcent->zc_doi;
			*zlabel = zcent->zc_label;
		} else {
			goto error;
		}
		if (validate_rootds_label(zlogp, rootpath, zlabel) != 0)
			goto error;
	}

	kzone = zone_name;

	/*
	 * We must do this scan twice.  First, we look for zones running on the
	 * main system that are using this root (or any subdirectory of it).
	 * Next, we reduce to the shortest path and search for loopback mounts
	 * that use this same source node (same device and inode).
	 */
	if (duplicate_zone_root(zlogp, rootpath))
		goto error;
	if (duplicate_reachable_path(zlogp, rootpath))
		goto error;

	if (ALT_MOUNT(mount_cmd)) {
		root_to_lu(zlogp, rootpath, sizeof (rootpath), B_TRUE);

		/*
		 * Forge up a special root for this zone.  When a zone is
		 * mounted, we can't let the zone have its own root because the
		 * tools that will be used in this "scratch zone" need access
		 * to both the zone's resources and the running machine's
		 * executables.
		 *
		 * Note that the mkdir here also catches read-only filesystems.
		 */
		if (mkdir(rootpath, 0755) != 0 && errno != EEXIST) {
			zerror(zlogp, B_TRUE, "cannot create %s", rootpath);
			goto error;
		}
		if (domount(zlogp, "tmpfs", "", "swap", rootpath) != 0)
			goto error;
	}

	if (zonecfg_in_alt_root()) {
		/*
		 * If we are mounting up a zone in an alternate root partition,
		 * then we have some additional work to do before starting the
		 * zone.  First, resolve the root path down so that we're not
		 * fooled by duplicates.  Then forge up an internal name for
		 * the zone.
		 */
		if ((fp = zonecfg_open_scratch("", B_TRUE)) == NULL) {
			zerror(zlogp, B_TRUE, "cannot open mapfile");
			goto error;
		}
		if (zonecfg_lock_scratch(fp) != 0) {
			zerror(zlogp, B_TRUE, "cannot lock mapfile");
			goto error;
		}
		if (zonecfg_find_scratch(fp, zone_name, zonecfg_get_root(),
		    NULL, 0) == 0) {
			zerror(zlogp, B_FALSE, "scratch zone already running");
			goto error;
		}
		/* This is the preferred name */
		(void) snprintf(kernzone, sizeof (kernzone), "SUNWlu-%s",
		    zone_name);
		srandom(getpid());
		while (zonecfg_reverse_scratch(fp, kernzone, NULL, 0, NULL,
		    0) == 0) {
			/* This is just an arbitrary name; note "." usage */
			(void) snprintf(kernzone, sizeof (kernzone),
			    "SUNWlu.%08lX%08lX", random(), random());
		}
		kzone = kernzone;
	}

	xerr = 0;
	if ((zoneid = zone_create(kzone, rootpath, privs, rctlbuf,
	    rctlbufsz, zfsbuf, zfsbufsz, &xerr, match, doi, zlabel,
	    flags)) == -1) {
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
		} else if (xerr == ZE_LABELINUSE) {
			char zonename[ZONENAME_MAX];
			(void) getzonenamebyid(getzoneidbylabel(zlabel),
			    zonename, ZONENAME_MAX);
			zerror(zlogp, B_FALSE, "The zone label is already "
			    "used by the zone '%s'.", zonename);
		} else {
			zerror(zlogp, B_TRUE, "%s failed", "zone_create");
		}
		goto error;
	}

	if (zonecfg_in_alt_root() &&
	    zonecfg_add_scratch(fp, zone_name, kernzone,
	    zonecfg_get_root()) == -1) {
		zerror(zlogp, B_TRUE, "cannot add mapfile entry");
		goto error;
	}

	/*
	 * The following actions are not performed when merely mounting a zone
	 * for administrative use.
	 */
	if (mount_cmd == Z_MNT_BOOT) {
		brand_handle_t bh;
		struct brand_attr attr;
		char modname[MAXPATHLEN];

		if (setup_zone_attrs(zlogp, zone_name, zoneid) != Z_OK)
			goto error;

		if ((bh = brand_open(brand_name)) == NULL) {
			zerror(zlogp, B_FALSE,
			    "unable to determine brand name");
			goto error;
		}

		if (!is_system_labeled() &&
		    (strcmp(brand_name, LABELED_BRAND_NAME) == 0)) {
			brand_close(bh);
			zerror(zlogp, B_FALSE,
			    "cannot boot labeled zone on unlabeled system");
			goto error;
		}

		/*
		 * If this brand requires any kernel support, now is the time to
		 * get it loaded and initialized.
		 */
		if (brand_get_modname(bh, modname, MAXPATHLEN) < 0) {
			brand_close(bh);
			zerror(zlogp, B_FALSE,
			    "unable to determine brand kernel module");
			goto error;
		}
		brand_close(bh);

		if (strlen(modname) > 0) {
			(void) strlcpy(attr.ba_brandname, brand_name,
			    sizeof (attr.ba_brandname));
			(void) strlcpy(attr.ba_modname, modname,
			    sizeof (attr.ba_modname));
			if (zone_setattr(zoneid, ZONE_ATTR_BRAND, &attr,
			    sizeof (attr) != 0)) {
				zerror(zlogp, B_TRUE,
				    "could not set zone brand attribute.");
				goto error;
			}
		}

		if (setup_zone_rm(zlogp, zone_name, zoneid) != Z_OK)
			goto error;

		set_mlps(zlogp, zoneid, zcent);
	}

	rval = zoneid;
	zoneid = -1;

error:
	if (zoneid != -1) {
		(void) zone_shutdown(zoneid);
		(void) zone_destroy(zoneid);
	}
	if (rctlbuf != NULL)
		free(rctlbuf);
	priv_freeset(privs);
	if (fp != NULL)
		zonecfg_close_scratch(fp);
	lofs_discard_mnttab();
	if (zcent != NULL)
		tsol_freezcent(zcent);
	return (rval);
}

/*
 * Enter the zone and write a /etc/zones/index file there.  This allows
 * libzonecfg (and thus zoneadm) to report the UUID and potentially other zone
 * details from inside the zone.
 */
static void
write_index_file(zoneid_t zoneid)
{
	FILE *zef;
	FILE *zet;
	struct zoneent *zep;
	pid_t child;
	int tmpl_fd;
	ctid_t ct;
	int fd;
	char uuidstr[UUID_PRINTABLE_STRING_LENGTH];

	/* Locate the zone entry in the global zone's index file */
	if ((zef = setzoneent()) == NULL)
		return;
	while ((zep = getzoneent_private(zef)) != NULL) {
		if (strcmp(zep->zone_name, zone_name) == 0)
			break;
		free(zep);
	}
	endzoneent(zef);
	if (zep == NULL)
		return;

	if ((tmpl_fd = init_template()) == -1) {
		free(zep);
		return;
	}

	if ((child = fork()) == -1) {
		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);
		free(zep);
		return;
	}

	/* parent waits for child to finish */
	if (child != 0) {
		free(zep);
		if (contract_latest(&ct) == -1)
			ct = -1;
		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);
		(void) waitpid(child, NULL, 0);
		(void) contract_abandon_id(ct);
		return;
	}

	/* child enters zone and sets up index file */
	(void) ct_tmpl_clear(tmpl_fd);
	if (zone_enter(zoneid) != -1) {
		(void) mkdir(ZONE_CONFIG_ROOT, ZONE_CONFIG_MODE);
		(void) chown(ZONE_CONFIG_ROOT, ZONE_CONFIG_UID,
		    ZONE_CONFIG_GID);
		fd = open(ZONE_INDEX_FILE, O_WRONLY|O_CREAT|O_TRUNC,
		    ZONE_INDEX_MODE);
		if (fd != -1 && (zet = fdopen(fd, "w")) != NULL) {
			(void) fchown(fd, ZONE_INDEX_UID, ZONE_INDEX_GID);
			if (uuid_is_null(zep->zone_uuid))
				uuidstr[0] = '\0';
			else
				uuid_unparse(zep->zone_uuid, uuidstr);
			(void) fprintf(zet, "%s:%s:/:%s\n", zep->zone_name,
			    zone_state_str(zep->zone_state),
			    uuidstr);
			(void) fclose(zet);
		}
	}
	_exit(0);
}

int
vplat_bringup(zlog_t *zlogp, zone_mnt_t mount_cmd, zoneid_t zoneid)
{
	char zonepath[MAXPATHLEN];

	if (mount_cmd == Z_MNT_BOOT && validate_datasets(zlogp) != 0) {
		lofs_discard_mnttab();
		return (-1);
	}

	/*
	 * Before we try to mount filesystems we need to create the
	 * attribute backing store for /dev
	 */
	if (zone_get_zonepath(zone_name, zonepath, sizeof (zonepath)) != Z_OK) {
		lofs_discard_mnttab();
		return (-1);
	}
	resolve_lofs(zlogp, zonepath, sizeof (zonepath));

	/* Make /dev directory owned by root, grouped sys */
	if (make_one_dir(zlogp, zonepath, "/dev", DEFAULT_DIR_MODE,
	    0, 3) != 0) {
		lofs_discard_mnttab();
		return (-1);
	}

	if (mount_filesystems(zlogp, mount_cmd) != 0) {
		lofs_discard_mnttab();
		return (-1);
	}

	if (mount_cmd == Z_MNT_BOOT) {
		zone_iptype_t iptype;

		if (vplat_get_iptype(zlogp, &iptype) < 0) {
			zerror(zlogp, B_TRUE, "unable to determine ip-type");
			lofs_discard_mnttab();
			return (-1);
		}

		switch (iptype) {
		case ZS_SHARED:
			/* Always do this to make lo0 get configured */
			if (configure_shared_network_interfaces(zlogp) != 0) {
				lofs_discard_mnttab();
				return (-1);
			}
			break;
		case ZS_EXCLUSIVE:
			if (configure_exclusive_network_interfaces(zlogp,
			    zoneid) !=
			    0) {
				lofs_discard_mnttab();
				return (-1);
			}
			break;
		}
	}

	write_index_file(zoneid);

	lofs_discard_mnttab();
	return (0);
}

static int
lu_root_teardown(zlog_t *zlogp)
{
	char zroot[MAXPATHLEN];

	if (zone_get_rootpath(zone_name, zroot, sizeof (zroot)) != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to determine zone root");
		return (-1);
	}
	root_to_lu(zlogp, zroot, sizeof (zroot), B_FALSE);

	/*
	 * At this point, the processes are gone, the filesystems (save the
	 * root) are unmounted, and the zone is on death row.  But there may
	 * still be creds floating about in the system that reference the
	 * zone_t, and which pin down zone_rootvp causing this call to fail
	 * with EBUSY.  Thus, we try for a little while before just giving up.
	 * (How I wish this were not true, and umount2 just did the right
	 * thing, or tmpfs supported MS_FORCE This is a gross hack.)
	 */
	if (umount2(zroot, MS_FORCE) != 0) {
		if (errno == ENOTSUP && umount2(zroot, 0) == 0)
			goto unmounted;
		if (errno == EBUSY) {
			int tries = 10;

			while (--tries >= 0) {
				(void) sleep(1);
				if (umount2(zroot, 0) == 0)
					goto unmounted;
				if (errno != EBUSY)
					break;
			}
		}
		zerror(zlogp, B_TRUE, "unable to unmount '%s'", zroot);
		return (-1);
	}
unmounted:

	/*
	 * Only zones in an alternate root environment have scratch zone
	 * entries.
	 */
	if (zonecfg_in_alt_root()) {
		FILE *fp;
		int retv;

		if ((fp = zonecfg_open_scratch("", B_FALSE)) == NULL) {
			zerror(zlogp, B_TRUE, "cannot open mapfile");
			return (-1);
		}
		retv = -1;
		if (zonecfg_lock_scratch(fp) != 0)
			zerror(zlogp, B_TRUE, "cannot lock mapfile");
		else if (zonecfg_delete_scratch(fp, kernzone) != 0)
			zerror(zlogp, B_TRUE, "cannot delete map entry");
		else
			retv = 0;
		zonecfg_close_scratch(fp);
		return (retv);
	} else {
		return (0);
	}
}

int
vplat_teardown(zlog_t *zlogp, boolean_t unmount_cmd, boolean_t rebooting)
{
	char *kzone;
	zoneid_t zoneid;
	int res;
	char pool_err[128];
	char zpath[MAXPATHLEN];
	char cmdbuf[MAXPATHLEN];
	brand_handle_t bh = NULL;
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	ushort_t flags;

	kzone = zone_name;
	if (zonecfg_in_alt_root()) {
		FILE *fp;

		if ((fp = zonecfg_open_scratch("", B_FALSE)) == NULL) {
			zerror(zlogp, B_TRUE, "unable to open map file");
			goto error;
		}
		if (zonecfg_find_scratch(fp, zone_name, zonecfg_get_root(),
		    kernzone, sizeof (kernzone)) != 0) {
			zerror(zlogp, B_FALSE, "unable to find scratch zone");
			zonecfg_close_scratch(fp);
			goto error;
		}
		zonecfg_close_scratch(fp);
		kzone = kernzone;
	}

	if ((zoneid = getzoneidbyname(kzone)) == ZONE_ID_UNDEFINED) {
		if (!bringup_failure_recovery)
			zerror(zlogp, B_TRUE, "unable to get zoneid");
		if (unmount_cmd)
			(void) lu_root_teardown(zlogp);
		goto error;
	}

	if (remove_datalink_pool(zlogp, zoneid) != 0) {
		zerror(zlogp, B_FALSE, "unable clear datalink pool property");
		goto error;
	}

	if (remove_datalink_protect(zlogp, zoneid) != 0) {
		zerror(zlogp, B_FALSE,
		    "unable clear datalink protect property");
		goto error;
	}

	/*
	 * The datalinks assigned to the zone will be removed from the NGZ as
	 * part of zone_shutdown() so that we need to remove protect/pool etc.
	 * before zone_shutdown(). Even if the shutdown itself fails, the zone
	 * will not be able to violate any constraints applied because the
	 * datalinks are no longer available to the zone.
	 */
	if (zone_shutdown(zoneid) != 0) {
		zerror(zlogp, B_TRUE, "unable to shutdown zone");
		goto error;
	}

	/* Get the zonepath of this zone */
	if (zone_get_zonepath(zone_name, zpath, sizeof (zpath)) != Z_OK) {
		zerror(zlogp, B_FALSE, "unable to determine zone path");
		goto error;
	}

	/* Get a handle to the brand info for this zone */
	if ((bh = brand_open(brand_name)) == NULL) {
		zerror(zlogp, B_FALSE, "unable to determine zone brand");
		return (-1);
	}
	/*
	 * If there is a brand 'halt' callback, execute it now to give the
	 * brand a chance to cleanup any custom configuration.
	 */
	(void) strcpy(cmdbuf, EXEC_PREFIX);
	if (brand_get_halt(bh, zone_name, zpath, cmdbuf + EXEC_LEN,
	    sizeof (cmdbuf) - EXEC_LEN) < 0) {
		brand_close(bh);
		zerror(zlogp, B_FALSE, "unable to determine branded zone's "
		    "halt callback.");
		goto error;
	}
	brand_close(bh);

	if ((strlen(cmdbuf) > EXEC_LEN) &&
	    (do_subproc(zlogp, cmdbuf, NULL) != Z_OK)) {
		zerror(zlogp, B_FALSE, "%s failed", cmdbuf);
		goto error;
	}

	if (!unmount_cmd) {
		zone_iptype_t iptype;

		if (zone_getattr(zoneid, ZONE_ATTR_FLAGS, &flags,
		    sizeof (flags)) < 0) {
			if (vplat_get_iptype(zlogp, &iptype) < 0) {
				zerror(zlogp, B_TRUE, "unable to determine "
				    "ip-type");
				goto error;
			}
		} else {
			if (flags & ZF_NET_EXCL)
				iptype = ZS_EXCLUSIVE;
			else
				iptype = ZS_SHARED;
		}

		switch (iptype) {
		case ZS_SHARED:
			if (unconfigure_shared_network_interfaces(zlogp,
			    zoneid) != 0) {
				zerror(zlogp, B_FALSE, "unable to unconfigure "
				    "network interfaces in zone");
				goto error;
			}
			break;
		case ZS_EXCLUSIVE:
			if (unconfigure_exclusive_network_interfaces(zlogp,
			    zoneid) != 0) {
				zerror(zlogp, B_FALSE, "unable to unconfigure "
				    "network interfaces in zone");
				goto error;
			}
			status = dladm_zone_halt(dld_handle, zoneid);
			if (status != DLADM_STATUS_OK) {
				zerror(zlogp, B_FALSE, "unable to notify "
				    "dlmgmtd of zone halt: %s",
				    dladm_status2str(status, errmsg));
			}
			break;
		}
	}

	if (!unmount_cmd && tcp_abort_connections(zlogp, zoneid) != 0) {
		zerror(zlogp, B_TRUE, "unable to abort TCP connections");
		goto error;
	}

	if (unmount_filesystems(zlogp, zoneid, unmount_cmd) != 0) {
		zerror(zlogp, B_FALSE,
		    "unable to unmount file systems in zone");
		goto error;
	}

	/*
	 * If we are rebooting then we normally don't want to destroy an
	 * existing temporary pool at this point so that we can just reuse it
	 * when the zone boots back up.  However, it is also possible we were
	 * running with a temporary pool and the zone configuration has been
	 * modified to no longer use a temporary pool.  In that case we need
	 * to destroy the temporary pool now.  This case looks like the case
	 * where we never had a temporary pool configured but
	 * zonecfg_destroy_tmp_pool will do the right thing either way.
	 */
	if (!unmount_cmd) {
		boolean_t destroy_tmp_pool = B_TRUE;

		if (rebooting) {
			struct zone_psettab pset_tab;
			zone_dochandle_t handle;

			if ((handle = zonecfg_init_handle()) != NULL &&
			    zonecfg_get_handle(zone_name, handle) == Z_OK &&
			    zonecfg_lookup_pset(handle, &pset_tab) == Z_OK)
				destroy_tmp_pool = B_FALSE;

			zonecfg_fini_handle(handle);
		}

		if (destroy_tmp_pool) {
			if ((res = zonecfg_destroy_tmp_pool(zone_name, pool_err,
			    sizeof (pool_err))) != Z_OK) {
				if (res == Z_POOL)
					zerror(zlogp, B_FALSE, pool_err);
			}
		}
	}

	remove_mlps(zlogp, zoneid);

	if (zone_destroy(zoneid) != 0) {
		zerror(zlogp, B_TRUE, "unable to destroy zone");
		goto error;
	}

	/*
	 * Special teardown for alternate boot environments: remove the tmpfs
	 * root for the zone and then remove it from the map file.
	 */
	if (unmount_cmd && lu_root_teardown(zlogp) != 0)
		goto error;

	lofs_discard_mnttab();
	return (0);

error:
	lofs_discard_mnttab();
	return (-1);
}
