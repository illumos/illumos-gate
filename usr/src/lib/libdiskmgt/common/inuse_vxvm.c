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

/*
 * Attempt to dynamically link in the Veritas libvxvmsc.so so that we can
 * see if there are any Veritas volumes on any of the slices.
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <thread.h>
#include <synch.h>
#include <dlfcn.h>
#include <link.h>
#include <ctype.h>

#include "libdiskmgt.h"
#include "disks_private.h"

#define	VXVM_LIB_NAME	"libvxvmsc.so"

#define	VXVM_NAME_SIZE	1
#define	VXVM_PATH_SIZE	2

typedef char	*vm_name_t;
typedef char	*vm_path_t;

/*
 * Pointers to libvxvmsc.so functions that we dynamically resolve.
 */
static int (*vxdl_libvxvm_get_version)(int version);
static int (*vxdl_libvxvm_get_conf)(int param);
static int (*vxdl_libvxvm_get_dgs)(int len, vm_name_t namep[]);
static int (*vxdl_libvxvm_get_disks)(vm_name_t dgname, int len,
		vm_path_t pathp[]);

#define	MAX_DISK_GROUPS 128
#define	MAX_DISKS_DG 1024

struct vxvm_list {
	struct vxvm_list	*next;
	char			*slice;
};

static struct vxvm_list	*vxvm_listp = NULL;
static time_t		timestamp = 0;
static mutex_t		vxvm_lock = DEFAULTMUTEX;

static int	add_use_record(char *devname);
static void	free_vxvm();
static void	*init_vxvm();
static int	is_ctds(char *name);
static int	load_vxvm();

int
inuse_vxvm(char *slice, nvlist_t *attrs, int *errp)
{
	int		found = 0;
	time_t		curr_time;
	char		*sp = NULL;

	*errp = 0;
	if (slice == NULL) {
		return (found);
	}

	/*
	 * Since vxvm "encapsulates" the disk we need to match on any
	 * slice passed in.  Strip the slice component from the devname.
	 */
	if (is_ctds(slice)) {
		if ((sp = strrchr(slice, '/')) == NULL)
			sp = slice;

		while (*sp && *sp != 's')
			sp++;

		if (*sp)
			*sp = 0;
		else
			sp = NULL;
	}

	(void) mutex_lock(&vxvm_lock);

	curr_time = time(NULL);
	if (timestamp < curr_time && (curr_time - timestamp) > 60) {
		free_vxvm();		/* free old entries */
		*errp = load_vxvm();	/* load the cache */

		timestamp = curr_time;
	}

	if (*errp == 0) {
		struct vxvm_list	*listp;

		listp = vxvm_listp;
		while (listp != NULL) {
			if (strcmp(slice, listp->slice) == 0) {
				libdiskmgt_add_str(attrs, DM_USED_BY,
				    DM_USE_VXVM, errp);
				libdiskmgt_add_str(attrs, DM_USED_NAME,
				    "", errp);
				found = 1;
				break;
			}
			listp = listp->next;
		}
	}

	(void) mutex_unlock(&vxvm_lock);

	/* restore slice name to orignal value */
	if (sp != NULL)
		*sp = 's';

	return (found);
}

static int
add_use_record(char *devname)
{
	struct vxvm_list *sp;

	sp = (struct vxvm_list *)malloc(sizeof (struct vxvm_list));
	if (sp == NULL) {
		return (ENOMEM);
	}

	if ((sp->slice = strdup(devname)) == NULL) {
		free(sp);
		return (ENOMEM);
	}

	sp->next = vxvm_listp;
	vxvm_listp = sp;

	/*
	 * Since vxvm "encapsulates" the disk we need to match on any
	 * slice passed in.  Strip the slice component from the devname.
	 */
	if (is_ctds(sp->slice)) {
		char	*dp;

		if ((dp = strrchr(sp->slice, '/')) == NULL)
			dp = sp->slice;

		while (*dp && *dp != 's')
			dp++;
		*dp = 0;
	}

	return (0);
}

/*
 * If the input name is in c[t]ds format then return 1, otherwise return 0.
 */
static int
is_ctds(char *name)
{
	char	*p;

	if ((p = strrchr(name, '/')) == NULL)
		p = name;
	else
		p++;

	if (*p++ != 'c') {
		return (0);
	}
	/* skip controller digits */
	while (isdigit(*p)) {
		p++;
	}

	/* handle optional target */
	if (*p == 't') {
		p++;
		/* skip over target */
		while (isdigit(*p) || isupper(*p)) {
			p++;
		}
	}

	if (*p++ != 'd') {
		return (0);
	}
	while (isdigit(*p)) {
		p++;
	}

	if (*p++ != 's') {
		return (0);
	}

	/* check the slice number */
	while (isdigit(*p)) {
		p++;
	}

	if (*p != 0) {
		return (0);
	}

	return (1);
}

/*
 * Free the list of vxvm entries.
 */
static void
free_vxvm()
{
	struct vxvm_list	*listp = vxvm_listp;
	struct vxvm_list	*nextp;

	while (listp != NULL) {
		nextp = listp->next;
		free((void *)listp->slice);
		free((void *)listp);
		listp = nextp;
	}

	vxvm_listp = NULL;
}

/*
 * Try to dynamically link the vxvm functions we need.
 */
static void *
init_vxvm()
{
	void	*lh;

	if ((lh = dlopen(VXVM_LIB_NAME, RTLD_NOW)) == NULL) {
		return (NULL);
	}

	if ((vxdl_libvxvm_get_version = (int (*)(int))dlsym(lh,
	    "libvxvm_get_version")) == NULL) {
		(void) dlclose(lh);
		return (NULL);
	}

	if ((vxdl_libvxvm_get_conf = (int (*)(int))dlsym(lh,
	    "libvxvm_get_conf")) == NULL) {
		(void) dlclose(lh);
		return (NULL);
	}

	if ((vxdl_libvxvm_get_dgs = (int (*)(int, vm_name_t []))dlsym(lh,
	    "libvxvm_get_dgs")) == NULL) {
		(void) dlclose(lh);
		return (NULL);
	}

	if ((vxdl_libvxvm_get_disks = (int (*)(vm_name_t, int, vm_path_t []))
	    dlsym(lh, "libvxvm_get_disks")) == NULL) {
		(void) dlclose(lh);
		return (NULL);
	}

	return (lh);
}

static int
load_vxvm()
{
	void		*lh;
	int		vers;
	int		nsize;
	int		psize;
	int		n_disk_groups;
	vm_name_t	*namep;
	char		*pnp;
	vm_path_t	*pathp;
	int		i;

	if ((lh = init_vxvm()) == NULL) {
		/* No library. */
		return (0);
	}

	vers = (vxdl_libvxvm_get_version)(1 << 8);
	if (vers == -1) {
		/* unsupported version */
		(void) dlclose(lh);
		return (0);
	}

	nsize = (vxdl_libvxvm_get_conf)(VXVM_NAME_SIZE);
	psize = (vxdl_libvxvm_get_conf)(VXVM_PATH_SIZE);

	if (nsize == -1 || psize == -1) {
		(void) dlclose(lh);
		return (0);
	}

	namep = (vm_name_t *)calloc(MAX_DISK_GROUPS, nsize);
	if (namep == NULL) {
		(void) dlclose(lh);
		return (ENOMEM);
	}

	pathp = (vm_path_t *)calloc(MAX_DISKS_DG, psize);
	if (pathp == NULL) {
		(void) dlclose(lh);
		free(namep);
		return (ENOMEM);
	}

	n_disk_groups = (vxdl_libvxvm_get_dgs)(MAX_DISK_GROUPS, namep);
	if (n_disk_groups < 0) {
		(void) dlclose(lh);
		free(namep);
		free(pathp);
		return (0);
	}

	pnp = (char *)namep;
	for (i = 0; i < n_disk_groups; i++) {
		int n_disks;

		n_disks = (vxdl_libvxvm_get_disks)(pnp, MAX_DISKS_DG, pathp);

		if (n_disks >= 0) {
			int	j;
			char	*ppp;

			ppp = (char *)pathp;
			for (j = 0; j < n_disks; j++) {

				if (strncmp(ppp, "/dev/vx/", 8) == 0) {
					char	*pslash;
					char	nm[MAXPATHLEN];

					pslash = strrchr(ppp, '/');
					pslash++;

					(void) snprintf(nm, sizeof (nm),
					    "/dev/dsk/%s", pslash);
					if (add_use_record(nm)) {
						(void) dlclose(lh);
						free(pathp);
						free(namep);
						return (ENOMEM);
					}
				} else {
					if (add_use_record(ppp)) {
						(void) dlclose(lh);
						free(pathp);
						free(namep);
						return (ENOMEM);
					}
				}

				ppp += psize;
			}
		}

		pnp += nsize;
	}

	(void) dlclose(lh);
	free(pathp);
	free(namep);

	return (0);
}
