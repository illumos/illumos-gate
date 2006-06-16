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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/fstyp.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>
#include <libnvpair.h>
#include <libfstyp.h>
#include <libfstyp_module.h>

/* default module directory */
const char *default_libfs_dir = "/usr/lib/fs";

#define	FSTYP_VERSION	1

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

typedef struct fstyp_ops {
	int		(*fstyp_init)(int fd, off64_t offset,
			fstyp_mod_handle_t *handle);
	void		(*fstyp_fini)(fstyp_mod_handle_t handle);
	int		(*fstyp_ident)(fstyp_mod_handle_t handle);
	int		(*fstyp_get_attr)(fstyp_mod_handle_t handle,
			nvlist_t **attr);
	int		(*fstyp_dump)(fstyp_mod_handle_t handle,
			FILE *fout, FILE *ferr);
} fstyp_ops_t;

typedef struct fstyp_module {
	struct fstyp_module *next;
	char		fsname[FSTYPSZ + 1];
	char		*pathname;	/* absolute module pathname */
	void		*dl_handle;	/* can be NULL if not loaded */
	fstyp_ops_t	ops;
	fstyp_mod_handle_t mod_handle;
} fstyp_module_t;

struct fstyp_handle {
	char		*libfs_dir;	/* directory to look for modules */
	char		*module_dir;	/* specific module directory */
	fstyp_module_t	*modules;	/* list of modules */
	fstyp_module_t	*modules_tail;	/* last module in the list */
	fstyp_module_t	*ident;		/* identified module */
	int		fd;
	off64_t		offset;
	long		name_max;
};

#define	NELEM(a)	sizeof (a) / sizeof (*(a))

/* local functions */
static int	fstyp_ident_all(struct fstyp_handle *h, const char **ident);
static int	fstyp_ident_one(struct fstyp_handle *h, const char *fsname,
		const char **ident);
static fstyp_module_t *fstyp_find_module_by_name(struct fstyp_handle *h,
		const char *fsname);
static int	fstyp_init_module(struct fstyp_handle *h,
		char *mdir, char *fsname, fstyp_module_t **mpp);
static void	fstyp_fini_module(struct fstyp_handle *h,
		fstyp_module_t *mp);
static int	fstyp_init_all_modules(struct fstyp_handle *h);
static void	fstyp_fini_all_modules(struct fstyp_handle *h);
static int	fstyp_load_module(struct fstyp_handle *h,
		fstyp_module_t *mp);
static void	fstyp_unload_module(struct fstyp_handle *h,
		fstyp_module_t *);

/*
 * Locate and initialize all modules.
 * If 'module_dir' is specified, only initialize module from this dir.
 */
int
fstyp_init(int fd, off64_t offset, char *module_dir, fstyp_handle_t *handle)
{
	struct fstyp_handle *h;
	int		error;

	if ((h = calloc(1, sizeof (struct fstyp_handle))) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}
	if ((module_dir != NULL) &&
	    ((h->module_dir = strdup(module_dir)) == NULL)) {
		free(h);
		return (FSTYP_ERR_NOMEM);
	}

	h->fd = fd;
	h->offset = offset;
	h->libfs_dir = (char *)default_libfs_dir;

	if ((h->name_max = pathconf(h->libfs_dir, _PC_NAME_MAX)) < 0) {
		h->name_max = MAXNAMELEN;
	}
	h->name_max++;

	if (h->module_dir == NULL) {
		error = fstyp_init_all_modules(h);
	} else {
		error = fstyp_init_module(h, h->module_dir, "", NULL);
	}
	if (error != 0) {
		fstyp_fini(h);
		return (error);
	}

	*handle = h;
	return (0);
}

void
fstyp_fini(struct fstyp_handle *h)
{
	if (h != NULL) {
		fstyp_fini_all_modules(h);
		if (h->module_dir != NULL) {
			free(h->module_dir);
		}
		free(h);
	}
}

/*
 * Identify the filesystem, return result in 'ident'.
 * If 'fsname' is specified, only attempt that filesystem.
 */
int
fstyp_ident(struct fstyp_handle *h, const char *fsname, const char **ident)
{
	if (fsname == NULL) {
		return (fstyp_ident_all(h, ident));
	} else {
		return (fstyp_ident_one(h, fsname, ident));
	}
}

/*
 * use all modules for identification
 */
static int
fstyp_ident_all(struct fstyp_handle *h, const char **ident)
{
	fstyp_module_t	*mp;

	if (h->ident != NULL) {
		*ident = &h->ident->fsname[0];
		return (0);
	}

	for (mp = h->modules; mp != NULL; mp = mp->next) {
		if ((fstyp_load_module(h, mp) == 0) &&
		    (mp->ops.fstyp_ident(mp->mod_handle) == 0)) {
			if (h->ident != NULL) {
				h->ident = NULL;
				*ident = NULL;
				return (FSTYP_ERR_MULT_MATCH);
			} else {
				h->ident = mp;
				*ident = &mp->fsname[0];
				return (0);
			}
		}
	}
	return (FSTYP_ERR_NO_MATCH);
}

/*
 * use only the specified module for identification
 */
static int
fstyp_ident_one(struct fstyp_handle *h, const char *fsname, const char **ident)
{
	fstyp_module_t	*mp;
	int		error = FSTYP_ERR_NO_MATCH;

	if (h->ident != NULL) {
		if (strcmp(h->ident->fsname, fsname) == 0) {
			*ident = (char *)fsname;
			return (0);
		} else {
			return (FSTYP_ERR_NO_MATCH);
		}
	}

	if (strlen(fsname) > FSTYPSZ) {
		return (FSTYP_ERR_NAME_TOO_LONG);
	}
	if (h->module_dir == NULL) {
		mp = fstyp_find_module_by_name(h, fsname);
	} else {
		mp = h->modules;
	}
	if (mp == NULL) {
		return (FSTYP_ERR_MOD_NOT_FOUND);
	}

	if (((error = fstyp_load_module(h, mp)) == 0) &&
	    ((error = mp->ops.fstyp_ident(mp->mod_handle)) == 0)) {
		h->ident = mp;
		*ident = (char *)fsname;
		return (0);
	}
	return (error);
}

/*
 * Get the list of fs attributes.
 */
int
fstyp_get_attr(struct fstyp_handle *h, nvlist_t **attr)
{
	fstyp_module_t	*mp = h->ident;

	if (mp == NULL) {
		return (FSTYP_ERR_NO_MATCH);
	}

	return (mp->ops.fstyp_get_attr(mp->mod_handle, attr));
}

/*
 * Dump free-form filesystem information.
 */
int
fstyp_dump(struct fstyp_handle *h, FILE *fout, FILE *ferr)
{
	fstyp_module_t	*mp = h->ident;

	if (mp == NULL) {
		return (FSTYP_ERR_NO_MATCH);
	}

	if (mp->ops.fstyp_dump == NULL) {
		return (FSTYP_ERR_NOP);
	}

	return (mp->ops.fstyp_dump(mp->mod_handle, fout, ferr));
}

/* ARGSUSED */
const char *
fstyp_strerror(struct fstyp_handle *h, int error)
{
	char *str;

	switch (error) {
	case FSTYP_ERR_OK:
		str = dgettext(TEXT_DOMAIN, "success");
		break;
	case FSTYP_ERR_NO_MATCH:
		str = dgettext(TEXT_DOMAIN, "no matches");
		break;
	case FSTYP_ERR_MULT_MATCH:
		str = dgettext(TEXT_DOMAIN, "multiple matches");
		break;
	case FSTYP_ERR_HANDLE:
		str = dgettext(TEXT_DOMAIN, "invalid handle");
		break;
	case FSTYP_ERR_OFFSET:
		str = dgettext(TEXT_DOMAIN, "invalid or unsupported offset");
		break;
	case FSTYP_ERR_NO_PARTITION:
		str = dgettext(TEXT_DOMAIN, "partition not found");
		break;
	case FSTYP_ERR_NOP:
		str = dgettext(TEXT_DOMAIN, "no such operation");
		break;
	case FSTYP_ERR_DEV_OPEN:
		str = dgettext(TEXT_DOMAIN, "cannot open device");
		break;
	case FSTYP_ERR_IO:
		str = dgettext(TEXT_DOMAIN, "i/o error");
		break;
	case FSTYP_ERR_NOMEM:
		str = dgettext(TEXT_DOMAIN, "out of memory");
		break;
	case FSTYP_ERR_MOD_NOT_FOUND:
		str = dgettext(TEXT_DOMAIN, "module not found");
		break;
	case FSTYP_ERR_MOD_DIR_OPEN:
		str = dgettext(TEXT_DOMAIN, "cannot open module directory");
		break;
	case FSTYP_ERR_MOD_OPEN:
		str = dgettext(TEXT_DOMAIN, "cannot open module");
		break;
	case FSTYP_ERR_MOD_VERSION:
		str = dgettext(TEXT_DOMAIN, "invalid module version");
		break;
	case FSTYP_ERR_MOD_INVALID:
		str = dgettext(TEXT_DOMAIN, "invalid module");
		break;
	case FSTYP_ERR_NAME_TOO_LONG:
		str = dgettext(TEXT_DOMAIN, "filesystem name too long");
		break;
	default:
		str = dgettext(TEXT_DOMAIN, "undefined error");
		break;
	}

	return (str);
}


static fstyp_module_t *
fstyp_find_module_by_name(struct fstyp_handle *h, const char *fsname)
{
	fstyp_module_t	*mp;

	for (mp = h->modules; mp != NULL; mp = mp->next) {
		if (strcmp(mp->fsname, fsname) == 0) {
			return (mp);
		}
	}
	return (NULL);
}

/*
 * Allocate and initialize module structure. Do not load just yet.
 * A pointer to the existing module is returned, if such is found.
 */
static int
fstyp_init_module(struct fstyp_handle *h, char *mdir, char *fsname,
    fstyp_module_t **mpp)
{
	char		*pathname;
	struct stat	sb;
	fstyp_module_t	*mp;

	/* if it's already inited, just return the pointer */
	if ((mp = fstyp_find_module_by_name(h, fsname)) != NULL) {
		if (mpp != NULL) {
			*mpp = mp;
		}
		return (0);
	}

	/* allocate pathname buffer */
	if ((pathname = calloc(1, h->name_max)) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}

	/* locate module */
	(void) snprintf(pathname, h->name_max, "%s/fstyp.so.%d", mdir,
	    FSTYP_VERSION);
	if (stat(pathname, &sb) < 0) {
		return (FSTYP_ERR_MOD_NOT_FOUND);
	}

	if ((mp = calloc(1, sizeof (fstyp_module_t))) == NULL) {
		free(pathname);
		return (FSTYP_ERR_NOMEM);
	}

	mp->pathname = pathname;
	(void) strlcpy(mp->fsname, fsname, sizeof (mp->fsname));

	/* append to list */
	if (h->modules_tail == NULL) {
		h->modules = h->modules_tail = mp;
	} else {
		h->modules_tail->next = mp;
		h->modules_tail = mp;
	}

	if (mpp != NULL) {
		*mpp = mp;
	}
	return (0);
}

/*
 * Free module resources. NOTE: this does not update the module list.
 */
static void
fstyp_fini_module(struct fstyp_handle *h, fstyp_module_t *mp)
{
	if (h->ident == mp) {
		h->ident = NULL;
	}
	fstyp_unload_module(h, mp);
	if (mp->pathname != NULL) {
		free(mp->pathname);
	}
	free(mp);
}

/*
 * Look for .so's and save them in the list.
 */
static int
fstyp_init_all_modules(struct fstyp_handle *h)
{
	char		*mdir;
	DIR		*dirp;
	struct dirent	*dp_mem, *dp;

	if ((mdir = calloc(1, h->name_max)) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}
	dp = dp_mem = calloc(1, sizeof (struct dirent) + h->name_max + 1);
	if (dp == NULL) {
		return (FSTYP_ERR_NOMEM);
	}
	if ((dirp = opendir(h->libfs_dir)) == NULL) {
		free(mdir);
		free(dp_mem);
		return (FSTYP_ERR_MOD_DIR_OPEN);
	}

	while ((readdir_r(dirp, dp, &dp) == 0) && (dp != NULL)) {
		if (dp->d_name[0] == '.') {
			continue;
		}
		(void) snprintf(mdir, h->name_max,
		    "%s/%s", h->libfs_dir, dp->d_name);
		(void) fstyp_init_module(h, mdir, dp->d_name, NULL);
	}

	free(mdir);
	free(dp_mem);
	(void) closedir(dirp);
	return (0);
}

static void
fstyp_fini_all_modules(struct fstyp_handle *h)
{
	fstyp_module_t	*mp, *mp_next;

	for (mp = h->modules; mp != NULL; mp = mp_next) {
		mp_next = mp->next;
		fstyp_fini_module(h, mp);
	}
	h->modules = h->modules_tail = h->ident = NULL;
}


/*
 * Load the .so module.
 */
static int
fstyp_load_module(struct fstyp_handle *h, fstyp_module_t *mp)
{
	int	error;

	if (mp->dl_handle != NULL) {
		return (0);
	}

	if ((mp->dl_handle = dlopen(mp->pathname, RTLD_LAZY)) == NULL) {
		return (FSTYP_ERR_MOD_OPEN);
	}

	mp->ops.fstyp_init = (int (*)(int, off64_t, fstyp_mod_handle_t *))
	    dlsym(mp->dl_handle, "fstyp_mod_init");
	mp->ops.fstyp_fini = (void (*)(fstyp_mod_handle_t))
	    dlsym(mp->dl_handle, "fstyp_mod_fini");
	mp->ops.fstyp_ident = (int (*)(fstyp_mod_handle_t))
	    dlsym(mp->dl_handle, "fstyp_mod_ident");
	mp->ops.fstyp_get_attr = (int (*)(fstyp_mod_handle_t, nvlist_t **))
	    dlsym(mp->dl_handle, "fstyp_mod_get_attr");
	mp->ops.fstyp_dump = (int (*)(fstyp_mod_handle_t, FILE *, FILE *))
	    dlsym(mp->dl_handle, "fstyp_mod_dump");

	if (((mp->ops.fstyp_init) == NULL) ||
	    ((mp->ops.fstyp_fini) == NULL) ||
	    ((mp->ops.fstyp_ident) == NULL) ||
	    ((mp->ops.fstyp_get_attr) == NULL)) {
		fstyp_unload_module(h, mp);
		return (FSTYP_ERR_MOD_INVALID);
	}

	error = mp->ops.fstyp_init(h->fd, h->offset, &mp->mod_handle);
	if (error != 0) {
		fstyp_unload_module(h, mp);
		return (error);
	}

	return (0);
}

/*ARGSUSED*/
static void
fstyp_unload_module(struct fstyp_handle *h, fstyp_module_t *mp)
{
	if (mp->mod_handle != NULL) {
		mp->ops.fstyp_fini(mp->mod_handle);
		mp->mod_handle = NULL;
	}
	if (mp->dl_handle != NULL) {
		(void) dlclose(mp->dl_handle);
		mp->dl_handle = NULL;
	}
}
