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
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <libzonecfg.h>
#include <link.h>
#include <string.h>
#include <strings.h>
#include <sys/list.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/mman.h>
#include <sys/mnttab.h>

#include "Pcontrol.h"

struct path_node {
	struct path_node	*pn_next;
	char			*pn_path;
};
typedef struct path_node path_node_t;

/*
 * Parameters of the lofs lookup cache.
 */
static struct stat64 lofs_mstat; /* last stat() of MNTTAB */
static struct lofs_mnttab {	/* linked list of all lofs mount points */
	struct lofs_mnttab *l_next;
	char	*l_special;	/* extracted from MNTTAB */
	char	*l_mountp;	/* ditto */
} *lofs_mnttab = NULL;
static mutex_t lofs_lock = DEFAULTMUTEX;	/* protects the lofs cache */

static void
rebuild_lofs_cache(void)
{
	struct mnttab mt;
	struct mnttab mt_find;
	struct lofs_mnttab *lmt;
	struct lofs_mnttab *next;
	FILE *fp;

	assert(MUTEX_HELD(&lofs_lock));

	/* destroy the old cache */
	for (lmt = lofs_mnttab; lmt != NULL; lmt = next) {
		next = lmt->l_next;
		free(lmt->l_special);
		free(lmt->l_mountp);
		free(lmt);
	}
	lofs_mnttab = NULL;

	/* prepare to create the new cache */
	if ((fp = fopen(MNTTAB, "r")) == NULL)
		return;

	/*
	 * We only care about lofs mount points.  But we need to
	 * ignore lofs mounts where the source path is the same
	 * as the target path.  (This can happen when a non-global
	 * zone has a lofs mount of a global zone filesystem, since
	 * the source path can't expose information about global
	 * zone paths to the non-global zone.)
	 */
	bzero(&mt_find, sizeof (mt_find));
	mt_find.mnt_fstype = "lofs";
	while (getmntany(fp, &mt, &mt_find) == 0 &&
	    (strcmp(mt.mnt_fstype, "lofs") == 0) &&
	    (strcmp(mt.mnt_special, mt.mnt_mountp) != 0)) {
		if ((lmt = malloc(sizeof (struct lofs_mnttab))) == NULL)
			break;
		lmt->l_special = strdup(mt.mnt_special);
		lmt->l_mountp = strdup(mt.mnt_mountp);
		lmt->l_next = lofs_mnttab;
		lofs_mnttab = lmt;
	}

	(void) fclose(fp);
}

static const char *
lookup_lofs_mount_point(const char *mountp)
{
	struct lofs_mnttab *lmt;

	assert(MUTEX_HELD(&lofs_lock));

	for (lmt = lofs_mnttab; lmt != NULL; lmt = lmt->l_next) {
		if (strcmp(lmt->l_mountp, mountp) == 0)
			return (lmt->l_special);
	}
	return (NULL);
}

static path_node_t *
pn_push(path_node_t **pnp, char *path)
{
	path_node_t *pn;

	if ((pn = calloc(sizeof (path_node_t), 1)) == NULL)
		return (NULL);

	if ((pn->pn_path = strdup(path)) == NULL) {
		free(pn);
		return (NULL);
	}
	pn->pn_next = *pnp;
	return (*pnp = pn);
}

static void
pn_free(path_node_t **pnp)
{
	path_node_t *pn;

	while (*pnp != NULL) {
		pn = *pnp;
		*pnp = pn->pn_next;
		free(pn->pn_path);
		free(pn);
	}
}

static void
pn_free2(path_node_t **pn1, path_node_t **pn2)
{
	pn_free(pn1);
	pn_free(pn2);
}

static char *
pn_pop(path_node_t **pnp, char *path)
{
	path_node_t *pn;

	if (*pnp == NULL)
		return (NULL);

	pn = *pnp;
	*pnp = pn->pn_next;
	pn->pn_next = NULL;

	if (path == NULL) {
		pn_free(&pn);
		return (NULL);
	}
	(void) strlcpy(path, pn->pn_path, PATH_MAX);
	pn_free(&pn);
	return (path);
}


/*
 * Libzonecfg.so links against libproc, so libproc can't link against
 * libzonecfg.so.  Also, libzonecfg.so is optional and might not be
 * installed.  Hence instead of relying on linking to access libzonecfg.so,
 * we'll try dlopening it here.  This trick is borrowed from
 * libc`zone_get_id(), see that function for more detailed comments.
 */
static int
i_zone_get_zonepath(char *zone_name, char *zonepath, size_t rp_sz)
{
	typedef	int (*zone_get_zonepath_t)(char *, char *, size_t);
	static zone_get_zonepath_t zone_get_zonepath_fp = NULL;

	if (zone_get_zonepath_fp == NULL) {
		/* There's no harm in doing this multiple times. */
		void *dlhandle = dlopen("libzonecfg.so.1", RTLD_LAZY);
		void *sym = (void *)(-1);
		if (dlhandle != NULL &&
		    (sym = dlsym(dlhandle, "zone_get_zonepath")) == NULL) {
			sym = (void *)(-1);
			(void) dlclose(dlhandle);
		}
		zone_get_zonepath_fp = (zone_get_zonepath_t)sym;
	}

	/* If we've successfully loaded it, call the real function */
	if (zone_get_zonepath_fp != (zone_get_zonepath_t)(-1))
		return (zone_get_zonepath_fp(zone_name, zonepath, rp_sz));
	return (Z_NO_ZONE);
}

char *
Pbrandname(struct ps_prochandle *P, char *buf, size_t buflen)
{
	long	addr;

	if ((addr = Pgetauxval(P, AT_SUN_BRANDNAME)) == -1)
		return (NULL);

	if (Pread_string(P, buf, buflen, addr) == -1)
		return (NULL);

	return (buf);
}

/*
 * Get the zone name from the core file if we have it; look up the
 * name based on the zone id if this is a live process.
 */
char *
Pzonename(struct ps_prochandle *P, char *s, size_t n)
{
	return (P->ops.pop_zonename(P, s, n, P->data));
}

char *
Pzoneroot(struct ps_prochandle *P, char *s, size_t n)
{
	char zname[ZONENAME_MAX], zpath[PATH_MAX], tmp[PATH_MAX];
	int rv;

	if (P->zoneroot != NULL) {
		(void) strlcpy(s, P->zoneroot, n);
		return (s);
	}

	if ((Pzonename(P, zname, sizeof (zname)) == NULL) ||
	    (strcmp(zname, GLOBAL_ZONENAME) == 0)) {
		if ((P->zoneroot = strdup("")) == NULL) {
			errno = ENOMEM;
			return (NULL);
		}
		dprintf("Pzoneroot defaulting to '%s'\n", GLOBAL_ZONENAME);
		(void) strlcpy(s, P->zoneroot, n);
		return (s);
	}

	if (i_zone_get_zonepath(zname, zpath, sizeof (zpath)) != Z_OK) {
		if ((P->zoneroot = strdup("")) == NULL) {
			errno = ENOMEM;
			return (NULL);
		}
		dprintf(
		    "Pzoneroot zone not found '%s', defaulting to '%s'\n",
		    zname, GLOBAL_ZONENAME);
		(void) strlcpy(s, P->zoneroot, n);
		return (s);
	}
	(void) strlcat(zpath, "/root", sizeof (zpath));

	if ((rv = resolvepath(zpath, tmp, sizeof (tmp) - 1)) < 0) {
		if ((P->zoneroot = strdup("")) == NULL) {
			errno = ENOMEM;
			return (NULL);
		}
		dprintf(
		    "Pzoneroot can't access '%s:%s', defaulting to '%s'\n",
		    zname, zpath, GLOBAL_ZONENAME);
		(void) strlcpy(s, P->zoneroot, n);
		return (s);
	}
	tmp[rv] = '\0';
	(void) strlcpy(zpath, tmp, sizeof (zpath));

	if ((P->zoneroot = strdup(zpath)) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}
	dprintf("Pzoneroot found zone root '%s:%s'\n", zname, zpath);
	(void) strlcpy(s, P->zoneroot, n);
	return (s);
}

/*
 * Plofspath() takes a path, "path",  and removes any lofs components from
 * that path.  The resultant path (if different from the starting path)
 * is placed in "s", which is limited to "n" characters, and the return
 * value is the pointer s.  If there are no lofs components in the path
 * the NULL is returned and s is not modified.  It's ok for "path" and
 * "s" to be the same pointer.  (ie, the results can be stored directly
 * in the input buffer.)  The path that is passed in must be an absolute
 * path.
 *
 * Example:
 *	if "path" == "/foo/bar", and "/candy/" is lofs mounted on "/foo/"
 *	then "/candy/bar/" will be written into "s" and "s" will be returned.
 */
char *
Plofspath(const char *path, char *s, size_t n)
{
	char tmp[PATH_MAX + 1];
	struct stat64 statb;
	const char *special;
	char *p, *p2;
	int rv;

	dprintf("Plofspath path '%s'\n", path);

	/* We only deal with absolute paths */
	if (path[0] != '/')
		return (NULL);

	/* Make a copy of the path so that we can muck with it */
	(void) strlcpy(tmp, path, sizeof (tmp) - 1);

	/*
	 * Use resolvepath() to make sure there are no consecutive or
	 * trailing '/'s in the path.
	 */
	if ((rv = resolvepath(tmp, tmp, sizeof (tmp) - 1)) >= 0)
		tmp[rv] = '\0';

	(void) mutex_lock(&lofs_lock);

	/*
	 * If /etc/mnttab has been modified since the last time
	 * we looked, then rebuild the lofs lookup cache.
	 */
	if (stat64(MNTTAB, &statb) == 0 &&
	    (statb.st_mtim.tv_sec != lofs_mstat.st_mtim.tv_sec ||
	    statb.st_mtim.tv_nsec != lofs_mstat.st_mtim.tv_nsec ||
	    statb.st_ctim.tv_sec != lofs_mstat.st_ctim.tv_sec ||
	    statb.st_ctim.tv_nsec != lofs_mstat.st_ctim.tv_nsec)) {
		lofs_mstat = statb;
		rebuild_lofs_cache();
	}

	/*
	 * So now we're going to search the path for any components that
	 * might be lofs mounts.  We'll start out search from the full
	 * path and then step back through each parent directly till
	 * we reach the root.  If we find a lofs mount point in the path
	 * then we'll replace the initial portion of the path (up
	 * to that mount point) with the source of that mount point
	 * and then start our search over again.
	 *
	 * Here's some of the variables we're going to use:
	 *
	 *	tmp - A pointer to our working copy of the path.  Sometimes
	 *		this path will be divided into two strings by a
	 *		'\0' (NUL) character.  The first string is the
	 *		component we're currently checking and the second
	 *		string is the path components we've already checked.
	 *
	 *	p - A pointer to the last '/' seen in the string.
	 *
	 *	p[1] - A pointer to the component of the string we've already
	 *		checked.
	 *
	 * Initially, p will point to the end of our path and p[1] will point
	 * to an extra '\0' (NUL) that we'll append to the end of the string.
	 * (This is why we declared tmp with a size of PATH_MAX + 1).
	 */
	p = &tmp[strlen(tmp)];
	p[1] = '\0';
	for (;;) {
		if ((special = lookup_lofs_mount_point(tmp)) != NULL) {
			char tmp2[PATH_MAX + 1];

			/*
			 * We found a lofs mount.  Update the path that we're
			 * checking and start over.  This means append the
			 * portion of the path we've already checked to the
			 * source of the lofs mount and re-start this entire
			 * lofs resolution loop.  Use resolvepath() to make
			 * sure there are no consecutive or trailing '/'s
			 * in the path.
			 */
			(void) strlcpy(tmp2, special, sizeof (tmp2) - 1);
			(void) strlcat(tmp2, "/", sizeof (tmp2) - 1);
			(void) strlcat(tmp2, &p[1], sizeof (tmp2) - 1);
			(void) strlcpy(tmp, tmp2, sizeof (tmp) - 1);
			if ((rv = resolvepath(tmp, tmp, sizeof (tmp) - 1)) >= 0)
				tmp[rv] = '\0';
			p = &tmp[strlen(tmp)];
			p[1] = '\0';
			continue;
		}

		/* No lofs mount found */
		if ((p2 = strrchr(tmp, '/')) == NULL) {
			char tmp2[PATH_MAX];

			(void) mutex_unlock(&lofs_lock);

			/*
			 * We know that tmp was an absolute path, so if we
			 * made it here we know that (p == tmp) and that
			 * (*p == '\0').  This means that we've managed
			 * to check the whole path and so we're done.
			 */
			assert(p == tmp);
			assert(p[0] == '\0');

			/* Restore the leading '/' in the path */
			p[0] = '/';

			if (strcmp(tmp, path) == 0) {
				/* The path didn't change */
				return (NULL);
			}

			/*
			 * It's possible that lofs source path we just
			 * obtained contains a symbolic link.  Use
			 * resolvepath() to clean it up.
			 */
			(void) strlcpy(tmp2, tmp, sizeof (tmp2));
			if ((rv = resolvepath(tmp, tmp, sizeof (tmp) - 1)) >= 0)
				tmp[rv] = '\0';

			/*
			 * It's always possible that our lofs source path is
			 * actually another lofs mount.  So call ourselves
			 * recursively to resolve that path.
			 */
			(void) Plofspath(tmp, tmp, PATH_MAX);

			/* Copy out our final resolved lofs source path */
			(void) strlcpy(s, tmp, n);
			dprintf("Plofspath path result '%s'\n", s);
			return (s);
		}

		/*
		 * So the path we just checked is not a lofs mount.  Next we
		 * want to check the parent path component for a lofs mount.
		 *
		 * First, restore any '/' that we replaced with a '\0' (NUL).
		 * We can determine if we should do this by looking at p[1].
		 * If p[1] points to a '\0' (NUL) then we know that p points
		 * to the end of the string and there is no '/' to restore.
		 * if p[1] doesn't point to a '\0' (NUL) then it points to
		 * the part of the path that we've already verified so there
		 * is a '/' to restore.
		 */
		if (p[1] != '\0')
			p[0] = '/';

		/*
		 * Second, replace the last '/' in the part of the path
		 * that we've already checked with a '\0' (NUL) so that
		 * when we loop around we check the parent component of the
		 * path.
		 */
		p2[0] = '\0';
		p = p2;
	}
	/*NOTREACHED*/
}

/*
 * Pzonepath() - Way too much code to attempt to derive the full path of
 * an object within a zone.
 *
 * Pzonepath() takes a path and attempts to resolve it relative to the
 * root associated with the current process handle.  If it fails it will
 * not update the results string.  It is safe to specify the same pointer
 * for the file string and the results string.
 *
 * Doing this resolution is more difficult than it initially sounds.
 * We can't simply append the file path to the zone root, because in
 * a root directory, '..' is treated the same as '.'.  Also, symbolic
 * links that specify an absolute path need to be interpreted relative
 * to the zone root.
 *
 * It seems like perhaps we could do a chroot(<zone root>) followed by a
 * resolvepath().  But we can't do this because chroot requires special
 * privileges and affects the entire process.  Perhaps if there was a
 * special version of resolvepath() which took an addition root path
 * we could use that, but this isn't ideal either.  The reason is
 * that we want to have special handling for native paths.  (A native path
 * is a path that begins with "/native/" or "/.SUNWnative/".)  Native
 * paths could be passed explicity to this function or could be embedded
 * in a symlink that is part of the path passed into this function.
 * These paths are always lofs mounts of global zone paths, but lofs
 * mounts only exist when a zone is booted.  So if we were to try to do
 * a resolvepath() on a native path when the zone wasn't booted the
 * resolvepath() would fail even though we know that the components
 * exists in the global zone.
 *
 * Given all these constraints, we just implement a path walking function
 * that resolves a file path relative to a zone root by manually inspecting
 * each of the path components and verifying its existence.  This means that
 * we must have access to the zone and that all the components of the
 * path must exist for this operation to succeed.
 */
char *
Pzonepath(struct ps_prochandle *P, const char *path, char *s, size_t n)
{
	char zroot[PATH_MAX], zpath[PATH_MAX], tmp[PATH_MAX], link[PATH_MAX];
	path_node_t *pn_stack = NULL, *pn_links = NULL, *pn;
	struct stat64 sb;
	char *p;
	int i, rv;

	dprintf("Pzonepath lookup '%s'\n", path);

	/* First lookup the zone root */
	if (Pzoneroot(P, zroot, sizeof (zroot)) == NULL)
		return (NULL);

	/*
	 * Make a temporary copy of the path specified.
	 * If it's a relative path then make it into an absolute path.
	 */
	tmp[0] = '\0';
	if (path[0] != '/')
		(void) strlcat(tmp, "/", sizeof (tmp));
	(void) strlcat(tmp, path, sizeof (tmp));

	/*
	 * If the path that was passed in is the zone root, we're done.
	 * If the path that was passed in already contains the zone root
	 * then strip the zone root out and verify the rest of the path.
	 */
	if (strcmp(tmp, zroot) == 0) {
		(void) Plofspath(zroot, zroot, sizeof (zroot));
		dprintf("Pzonepath found zone path (1) '%s'\n", zroot);
		(void) strlcpy(s, zroot, n);
		return (s);
	}
	i = strlen(zroot);
	if ((strncmp(tmp, zroot, i) == 0) && (tmp[i] == '/'))
		(void) memmove(tmp, tmp + i, strlen(tmp + i) + 1);

	/* If no path is passed in, then it maps to the zone root */
	if (strlen(tmp) == 0) {
		(void) Plofspath(zroot, zroot, sizeof (zroot));
		dprintf("Pzonepath found zone path (2) '%s'\n", zroot);
		(void) strlcpy(s, zroot, n);
		return (s);
	}

	/*
	 * Push each path component that we plan to verify onto a stack of
	 * path components, with parent components at the top of the stack.
	 * So for example, if we're going to verify the path /foo/bar/bang
	 * then our stack will look like:
	 *	foo	(top)
	 *	bar
	 *	bang	(bottom)
	 */
	while ((p = strrchr(tmp, '/')) != NULL) {
		*p = '\0';
		if (pn_push(&pn_stack, &p[1]) != NULL)
			continue;
		pn_free(&pn_stack);
		return (NULL);
	}

	/* We're going to store the final zone relative path in zpath */
	*zpath = '\0';

	while (pn_pop(&pn_stack, tmp) != NULL) {
		/*
		 * Drop zero length path components (which come from
		 * consecutive '/'s) and '.' path components.
		 */
		if ((strlen(tmp) == 0) || (strcmp(tmp, ".") == 0))
			continue;

		/*
		 * Check the current path component for '..', if found
		 * drop any previous path component.
		 */
		if (strcmp(tmp, "..") == 0) {
			if ((p = strrchr(zpath, '/')) != NULL)
				*p = '\0';
			continue;
		}

		/* The path we want to verify now is zpath + / + tmp. */
		(void) strlcat(zpath, "/", sizeof (zpath));
		(void) strlcat(zpath, tmp, sizeof (zpath));

		/*
		 * Check if this is a native object.  A native object is an
		 * object from the global zone that is running in a branded
		 * zone.  These objects are lofs mounted into a zone.  So if a
		 * branded zone is not booted then lofs mounts won't be setup
		 * so we won't be able to find these objects.  Luckily, we know
		 * that they exist in the global zone with the same path sans
		 * the initial native component, so we'll just strip out the
		 * native component here.
		 */
		if ((strncmp(zpath, "/native", sizeof ("/native")) == 0) ||
		    (strncmp(zpath, "/.SUNWnative",
		    sizeof ("/.SUNWnative")) == 0)) {

			/* Free any cached symlink paths */
			pn_free(&pn_links);

			/* Reconstruct the path from our path component stack */
			*zpath = '\0';
			while (pn_pop(&pn_stack, tmp) != NULL) {
				(void) strlcat(zpath, "/", sizeof (zpath));
				(void) strlcat(zpath, tmp, sizeof (zpath));
			}

			/* Verify that the path actually exists */
			rv = resolvepath(zpath, tmp, sizeof (tmp) - 1);
			if (rv < 0) {
				dprintf("Pzonepath invalid native path '%s'\n",
				    zpath);
				return (NULL);
			}
			tmp[rv] = '\0';

			/* Return the path */
			dprintf("Pzonepath found native path '%s'\n", tmp);
			(void) Plofspath(tmp, tmp, sizeof (tmp));
			(void) strlcpy(s, tmp, n);
			return (s);
		}

		/*
		 * Check if the path points to a symlink.  We do this
		 * explicitly since any absolute symlink needs to be
		 * interpreted relativly to the zone root and not "/".
		 */
		(void) strlcpy(tmp, zroot, sizeof (tmp));
		(void) strlcat(tmp, zpath, sizeof (tmp));
		if (lstat64(tmp, &sb) != 0) {
			pn_free2(&pn_stack, &pn_links);
			return (NULL);
		}
		if (!S_ISLNK(sb.st_mode)) {
			/*
			 * Since the lstat64() above succeeded we know that
			 * zpath exists, since this is not a symlink loop
			 * around and check the next path component.
			 */
			continue;
		}

		/*
		 * Symlink allow for paths with loops.  Make sure
		 * we're not stuck in a loop.
		 */
		for (pn = pn_links; pn != NULL; pn = pn->pn_next) {
			if (strcmp(zpath, pn->pn_path) != 0)
				continue;

			/* We have a loop.  Fail. */
			dprintf("Pzonepath symlink loop '%s'\n", zpath);
			pn_free2(&pn_stack, &pn_links);
			return (NULL);
		}

		/* Save this symlink path for future loop checks */
		if (pn_push(&pn_links, zpath) == NULL) {
			/* Out of memory */
			pn_free2(&pn_stack, &pn_links);
			return (NULL);
		}

		/* Now follow the contents of the symlink */
		bzero(link, sizeof (link));
		if (readlink(tmp, link, sizeof (link)) == -1) {
			pn_free2(&pn_stack, &pn_links);
			return (NULL);
		}

		dprintf("Pzonepath following symlink '%s' -> '%s'\n",
		    zpath, link);

		/*
		 * Push each path component of the symlink target onto our
		 * path components stack since we need to verify each one.
		 */
		while ((p = strrchr(link, '/')) != NULL) {
			*p = '\0';
			if (pn_push(&pn_stack, &p[1]) != NULL)
				continue;
			pn_free2(&pn_stack, &pn_links);
			return (NULL);
		}

		/* absolute or relative symlink? */
		if (*link == '\0') {
			/* Absolute symlink, nuke existing zpath. */
			*zpath = '\0';
			continue;
		}

		/*
		 * Relative symlink.  Push the first path component of the
		 * symlink target onto our stack for verification and then
		 * remove the current path component from zpath.
		 */
		if (pn_push(&pn_stack, link) == NULL) {
			pn_free2(&pn_stack, &pn_links);
			return (NULL);
		}
		p = strrchr(zpath, '/');
		assert(p != NULL);
		*p = '\0';
		continue;
	}
	pn_free(&pn_links);

	/* Place the final result in zpath */
	(void) strlcpy(tmp, zroot, sizeof (tmp));
	(void) strlcat(tmp, zpath, sizeof (tmp));
	(void) strlcpy(zpath, tmp, sizeof (zpath));

	(void) Plofspath(zpath, zpath, sizeof (zpath));
	dprintf("Pzonepath found zone path (3) '%s'\n", zpath);

	(void) strlcpy(s, zpath, n);
	return (s);
}

char *
Pfindobj(struct ps_prochandle *P, const char *path, char *s, size_t n)
{
	int len;

	dprintf("Pfindobj '%s'\n", path);

	/* We only deal with absolute paths */
	if (path[0] != '/')
		return (NULL);

	/* First try to resolve the path to some zone */
	if (Pzonepath(P, path, s, n) != NULL)
		return (s);

	/* If that fails resolve any lofs links in the path */
	if (Plofspath(path, s, n) != NULL)
		return (s);

	/* If that fails then just see if the path exists */
	if ((len = resolvepath(path, s, n)) > 0) {
		s[len] = '\0';
		return (s);
	}

	return (NULL);
}

char *
Pfindmap(struct ps_prochandle *P, map_info_t *mptr, char *s, size_t n)
{
	file_info_t *fptr = mptr->map_file;
	char buf[PATH_MAX];
	int len;

	/* If it's already been explicity set return that */
	if ((fptr != NULL) && (fptr->file_rname != NULL)) {
		(void) strlcpy(s, fptr->file_rname, n);
		return (s);
	}

	/* If it's the a.out segment, defer to the magical Pexecname() */
	if ((P->map_exec == mptr) ||
	    (strcmp(mptr->map_pmap.pr_mapname, "a.out") == 0) ||
	    ((fptr != NULL) && (fptr->file_lname != NULL) &&
	    (strcmp(fptr->file_lname, "a.out") == 0))) {
		if (Pexecname(P, buf, sizeof (buf)) != NULL) {
			(void) strlcpy(s, buf, n);
			return (s);
		}
	}

	/* Try /proc first to get the real object name */
	if ((Pstate(P) != PS_DEAD) && (mptr->map_pmap.pr_mapname[0] != '\0')) {
		(void) snprintf(buf, sizeof (buf), "%s/%d/path/%s",
		    procfs_path, (int)P->pid, mptr->map_pmap.pr_mapname);
		if ((len = readlink(buf, buf, sizeof (buf))) > 0) {
			buf[len] = '\0';
			(void) Plofspath(buf, buf, sizeof (buf));
			(void) strlcpy(s, buf, n);
			return (s);
		}
	}

	/*
	 * If we couldn't get the name from /proc, take the lname and
	 * try to expand it on the current system to a real object path.
	 */
	fptr = mptr->map_file;
	if ((fptr != NULL) && (fptr->file_lname != NULL)) {
		(void) strlcpy(buf, fptr->file_lname, sizeof (buf));
		if (Pfindobj(P, buf, buf, sizeof (buf)) == NULL)
			return (NULL);
		(void) strlcpy(s, buf, n);
		return (s);
	}

	return (NULL);
}
