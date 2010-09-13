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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <kvm.h>
#include <kstat.h>
#include <sys/types.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <sys/mkdev.h>
#include <inttypes.h>
#include <sys/stat.h>


#include "libfsmgt.h"
#include "replica.h"

#define	IGNORE	0
#define	DEV	1

/*
 * Private variables
 */

static char *mntopts[] = { MNTOPT_IGNORE, MNTOPT_DEV, NULL };

/*
 * Private method declarations
 */

static int ignore(char *);
static int get_kstat_info(nfs_mntlist_t *, int *);
static nfs_mntlist_t *get_mount_data(fs_mntlist_t *, int *);
static nfs_mntlist_t *get_nfs_info(fs_mntlist_t *, int *);
static nfs_mntlist_t *kstat_mount(nfs_mntlist_t *, kstat_t *);
static int load_kstat_data(kstat_ctl_t *, nfs_mntlist_t *, kstat_t *, int *);
static kid_t safe_kstat_read(kstat_ctl_t *, kstat_t *, void *, int *);

/*
 * Public methods
 */

void
nfs_free_mntinfo_list(nfs_mntlist_t *list)
{
	nfs_mntlist_t *tmp;
	int i;

	while (list != NULL) {
		free(list->nml_resource);
		free(list->nml_mountp);
		free(list->nml_fstype);
		free(list->nml_mntopts);
		free(list->nml_time);
		for (i = 0; i < list->nml_failovercount; i++) {
			if (list->nml_failoverlist[i] != NULL)
				free(list->nml_failoverlist[i]);
		}
		free(list->nml_failoverlist);
		free(list->nml_securitymode);
		tmp = list->next;
		free(list);
		list = tmp;
	}
} /* nfs_free_mntinfo_list */

nfs_mntlist_t *
nfs_get_filtered_mount_list(char *resource, char *mountp, char *mntopts,
	char *time, boolean_t find_overlays, int *errp) {

	fs_mntlist_t	*fs_mount_list;
	nfs_mntlist_t	*nfs_mount_list;

	fs_mount_list = fs_get_filtered_mount_list(resource, mountp,
		MNTTYPE_NFS, mntopts, time, find_overlays, errp);
	if (fs_mount_list == NULL) {
		return (NULL);
	}

	if ((nfs_mount_list = get_nfs_info(fs_mount_list, errp)) == NULL) {
		fs_free_mount_list(fs_mount_list);
		return (NULL);
	}

	fs_free_mount_list(fs_mount_list);
	return (nfs_mount_list);
} /* nfs_get_filtered_mount_list */

nfs_mntlist_t *
nfs_get_mounts_by_mntopt(char *mntopt, boolean_t find_overlays, int *errp)
{
	fs_mntlist_t	*fs_mount_list;
	nfs_mntlist_t	*nfs_mount_list;

	fs_mount_list = fs_get_mounts_by_mntopt(mntopt, find_overlays, errp);
	if (fs_mount_list == NULL) {
		return (NULL);
	}

	if ((nfs_mount_list = get_nfs_info(fs_mount_list, errp)) == NULL) {
		fs_free_mount_list(fs_mount_list);
		return (NULL);
	}

	fs_free_mount_list(fs_mount_list);
	return (nfs_mount_list);
} /* nfs_get_mount_by_mntopt */

nfs_mntlist_t *
nfs_get_mount_list(int *errp)
{
	fs_mntlist_t *fs_mount_list;
	nfs_mntlist_t *nfs_mount_list;
	boolean_t find_overlays = B_TRUE;

	if ((fs_mount_list = fs_get_mount_list(find_overlays, errp)) == NULL) {
		fprintf(stderr, "nfs_mntinfo: Can't access mnttab. %s\n",
		    strerror(*errp));
		return (NULL);
	}

	if ((nfs_mount_list = get_nfs_info(fs_mount_list, errp)) == NULL) {
		fs_free_mount_list(fs_mount_list);
		return (NULL);
	}

	fs_free_mount_list(fs_mount_list);
	return (nfs_mount_list);
} /* nfs_get_mount_list */

/*
 * Private methods
 */

static int
get_kstat_info(nfs_mntlist_t *nfs_mntinfo, int *errp)
{
	kstat_ctl_t *libkstat_cookie = NULL;
	nfs_mntlist_t *mrp;
	kstat_t *ksp;

	if ((libkstat_cookie = kstat_open()) == NULL) {
		*errp = errno;
		fprintf(stderr,
		    "nfs_mntinfo: kstat_open(): can't open /dev/kstat.\n");
		return (-1);
	}
	/*
	 * Each kstat consists of header and data sections that are
	 * connected as a "chain" or linked list of kstat stuctures.
	 * The kc_chain used here is the pointer to the global kstat
	 * chain (or the head of the chain of kstat's).
	 */
	for (ksp = libkstat_cookie->kc_chain; ksp; ksp = ksp->ks_next) {
		if ((ksp->ks_type == KSTAT_TYPE_RAW) &&
		    (strcmp(ksp->ks_module, "nfs") == 0) &&
		    (strcmp(ksp->ks_name, "mntinfo") == 0) &&
		    ((mrp = kstat_mount(nfs_mntinfo, ksp)) != NULL)) {
			if (load_kstat_data(libkstat_cookie, mrp, ksp, errp)
			    == -1) {
				nfs_free_mntinfo_list(mrp);
				return (-1);
			}
		}
	}
	return (0);
} /* get_kstat_info */

static int
load_kstat_data(kstat_ctl_t *libkstat_cookie, nfs_mntlist_t *mrp,
    kstat_t *ksp, int *errp)
{
	struct mntinfo_kstat mik;
	seconfig_t nfs_sec;

	if (mrp == 0) {
		return (0);
	}

	if (safe_kstat_read(libkstat_cookie, ksp, &mik, errp) == -1) {
		return (-1);
	}

	if (strlcpy(mrp->nml_proto, mik.mik_proto, KNC_STRSIZE)
	    >= KNC_STRSIZE) {
		*errp = errno;
		return (-1);
	}
	if (strlcpy(mrp->nml_curserver, mik.mik_curserver, SYS_NMLN)
	    >= SYS_NMLN) {
		*errp = errno;
		return (-1);
	}
	mrp->nml_vers = mik.mik_vers;
	/*
	 *  get the secmode name from /etc/nfssec.conf.
	 */
	if (!nfs_getseconfig_bynumber(mik.mik_secmod, &nfs_sec)) {
		mrp->nml_securitymode = strdup(nfs_sec.sc_name);
	} else {
		mrp->nml_securitymode = NULL;
	}
	mrp->nml_curread = mik.mik_curread;
	mrp->nml_curwrite = mik.mik_curwrite;
	mrp->nml_timeo = mik.mik_timeo;
	mrp->nml_retrans = mik.mik_retrans;
	mrp->nml_acregmin = mik.mik_acregmin;
	mrp->nml_acregmax = mik.mik_acregmax;
	mrp->nml_acdirmin = mik.mik_acdirmin;
	mrp->nml_acdirmax = mik.mik_acdirmax;
	mrp->nml_hard =
	    ((mik.mik_flags & MI_HARD) ? B_TRUE : B_FALSE);
	mrp->nml_intr =
	    ((mik.mik_flags & MI_INT) ? B_TRUE : B_FALSE);
	mrp->nml_noac =
	    ((mik.mik_flags & MI_NOAC) ? B_TRUE : B_FALSE);
	mrp->nml_nocto =
	    ((mik.mik_flags & MI_NOCTO) ? B_TRUE : B_FALSE);
	mrp->nml_grpid =
	    ((mik.mik_flags & MI_GRPID) ? B_TRUE : B_FALSE);
	mrp->nml_directio =
	    ((mik.mik_flags & MI_DIRECTIO) ? B_TRUE : B_FALSE);
	mrp->nml_xattr =
	    ((mik.mik_flags & MI_EXTATTR) ? B_TRUE : B_FALSE);
	return (0);
}

nfs_mntlist_t *
kstat_mount(nfs_mntlist_t *nfs_mntinfo, kstat_t *ksp) {
	nfs_mntlist_t *mrp;
	/*
	 * MAXMIN is used to retrieve the minor number
	 * which is compared to the kstat instance.
	 * If they are the same then this is an instance
	 * for which mount information is needed.
	 * MAXMIN is the maximum minor number and is
	 * defined in mkdev.h.
	 */
	mrp = nfs_mntinfo;
	while ((mrp != NULL) &&
	    ((mrp->nml_fsid & MAXMIN) != ksp->ks_instance)) {
		mrp = mrp->next;
	}
	return (mrp);
}

static nfs_mntlist_t *
get_nfs_info(fs_mntlist_t *fslist, int *errp) {
	nfs_mntlist_t *mrp = NULL;
	nfs_mntlist_t *headptr = NULL;
	nfs_mntlist_t *tailptr = NULL;
	fs_mntlist_t *fsmnt_list;

	for (fsmnt_list = fslist; fsmnt_list; fsmnt_list = fsmnt_list->next) {
		/* ignore non "nfs" and the "ignore" entries */

		if ((strcmp(fsmnt_list->fstype, MNTTYPE_NFS) != 0) ||
		    (ignore(fsmnt_list->mntopts))) {
			continue;
		}

		if ((mrp = get_mount_data(fsmnt_list, errp)) == NULL) {
			nfs_free_mntinfo_list(headptr);
			return (NULL);
		}
		if (tailptr == NULL) {
			headptr = mrp;
			tailptr = mrp;
			tailptr->next = NULL;
		} else {
			tailptr->next = mrp;
			tailptr = mrp;
			tailptr->next = NULL;
		}
	}

	if (get_kstat_info(headptr, errp) == -1) {
		nfs_free_mntinfo_list(mrp);
		return (NULL);
	}
	return (headptr);

} /* get_nfs_info */


static nfs_mntlist_t *
get_mount_data(fs_mntlist_t *fsmnt_list, int *errp) {
	struct replica *rep_list; /* defined in replica.h */
	nfs_mntlist_t *mrp;
	int i, server_count = 0;
	struct stat	stat_buf;

	if ((mrp = malloc(sizeof (nfs_mntlist_t))) == 0) {
		*errp = errno;
		return (NULL);
	}

	if ((stat(fsmnt_list->mountp, &stat_buf) == 0)) {
		mrp->nml_fsid = stat_buf.st_dev;
	} else {
		*errp = errno;
		nfs_free_mntinfo_list(mrp);
		return (NULL);
	}

	if ((mrp->nml_resource = strdup(fsmnt_list->resource))
	    == NULL) {
		*errp = errno;
		nfs_free_mntinfo_list(mrp);
		return (NULL);
	}
	if ((rep_list =
	    parse_replica(mrp->nml_resource, &server_count)) == NULL) {
		nfs_free_mntinfo_list(mrp);
		return (NULL);
	}
	if ((mrp->nml_failoverlist =
	    calloc(server_count, sizeof (char *))) == NULL) {
		nfs_free_mntinfo_list(mrp);
		return (NULL);
	}
	for (i = 0; i < server_count; i++) {
		mrp->nml_failoverlist[i] =
		    malloc(strlen(rep_list[i].host) + strlen(":") +
		    strlen(rep_list[i].path) + 2);
		if (!mrp->nml_failoverlist[i]) {
			nfs_free_mntinfo_list(mrp);
			return (NULL);
		}
		sprintf(mrp->nml_failoverlist[i], "%s%s%s",
		    rep_list[i].host, ":", rep_list[i].path);
	}
	/*
	 * If the number of servers is not 1 then resource is
	 * either a failover list or there is an error. In either
	 * case the path can't be determined and curpath is set to
	 * unknown".
	 */
	if (server_count == 1) {
		if (strcmp(rep_list[0].host, "nfs") == 0) {
			char *path;
			char *last;
			path = strdup(rep_list[0].path);
			if ((path = (char *)strtok_r(path, "//",
			    &last)) != NULL) {
				strcpy(mrp->nml_curpath,
				    strcat("/", last));
			} else {
				/*
				 * If NULL is returned this is an
				 * invalid path entry. no path can
				 * be determined.
				 */
				strcpy(mrp->nml_curpath, "unknown");
			}
		} else {
			strcpy(mrp->nml_curpath,
			    (strchr(mrp->nml_failoverlist[0],
			    ':') + 1));
		}
	} else {
		/*
		 * more than one server in the failover list
		 * path can't be determined.
		 */
		strcpy(mrp->nml_curpath, "unknown");
	}

	mrp->nml_failovercount = server_count;

	for (i = 0; i < server_count; i++) {
		if (rep_list[i].host) {
			free(rep_list[i].host);
		}
		if (rep_list[i].path) {
			free(rep_list[i].path);
		}
	}
	free(rep_list);

	if ((mrp->nml_mountp = strdup(fsmnt_list->mountp)) == NULL) {
		*errp = errno;
		nfs_free_mntinfo_list(mrp);
		return (NULL);
	}
	if ((mrp->nml_fstype = strdup(fsmnt_list->fstype)) == NULL) {
		*errp = errno;
		nfs_free_mntinfo_list(mrp);
		return (NULL);
	}
	if ((mrp->nml_mntopts = strdup(fsmnt_list->mntopts)) == NULL) {
		*errp = errno;
		nfs_free_mntinfo_list(mrp);
		return (NULL);
	}
	if ((mrp->nml_time = strdup(fsmnt_list->time)) == NULL) {
		*errp = errno;
		nfs_free_mntinfo_list(mrp);
		return (NULL);
	}
	if (fsmnt_list->overlayed) {
		mrp->nml_overlayed = B_TRUE;
	} else {
		mrp->nml_overlayed = B_FALSE;
	}
	return (mrp);
} /* get_mount_data */

kid_t
safe_kstat_read(
	kstat_ctl_t *libkstat_cookie,
	kstat_t *ksp,
	void *data,
	int *errp)
{

	kid_t kstat_chain_id = kstat_read(libkstat_cookie, ksp, data);

	if (kstat_chain_id == -1) {
		*errp = errno;
		return (-1);
	}
	return (kstat_chain_id);
} /* safe_kstat_read */


/*
 * ignore - Checks for the ignore mount option in the mount opts string.
 * Returns 1 if the ignore option is found and 0 if not.
 */
static int
ignore(char *opts)
{
	char *value;
	char *s;
	char *tmp;

	if (opts == NULL)
		return (0);
	s = strdup(opts);
	if (s == NULL)
		return (0);

	tmp = s;

	while (*s != '\0') {
		if (getsubopt(&s, mntopts, &value) == IGNORE) {
			free(tmp);
			return (1);
		}
	}
	free(tmp);
	return (0);
} /* ignore */
