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

#include <sys/types.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <sys/param.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnsctl.h"
#include <nsctl.h>
#include <sys/ncall/ncall.h>



/*
 * Internal routine to fetch all the current nodes that are
 * considered 'up'.
 * Returns the number of ncall_info structures that are valid
 * returned via the nodelist pointer, or -1 on an error.
 * If the call succeeds, then the memory returned via the
 * nodelist pointer needs to be freed by the caller.
 */

static int
nsc_getcurrentnodes(ncall_node_t **nodelist)
{
	ncall_node_t *mynodelist;
	int size;
	int fd;
	int rc = -1;
	int save_errno = 0;
	int ioctlcmd;

	if (nodelist == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*nodelist = NULL;
	if ((fd = open("/dev/ncall", O_RDONLY)) < 0) {
		return (-1);
	}
	if ((size = ioctl(fd, NC_IOC_GETNETNODES, NULL)) < 1) {
		size = 1;
		ioctlcmd = NC_IOC_GETNODE;
	} else {
		ioctlcmd = NC_IOC_GETNETNODES;
	}

	mynodelist = malloc(size * sizeof (*mynodelist));
	if (mynodelist == NULL) {
		save_errno = ENOMEM;
	} else {
		rc = ioctl(fd, ioctlcmd, mynodelist);
		if (rc < 0) {
			save_errno = errno;
			free(mynodelist);
		} else {
			/* fixup return value for single node ioctl */
			if (ioctlcmd == NC_IOC_GETNODE)
				rc = 1;
			*nodelist = mynodelist;
		}
	}
	close(fd);
	errno = save_errno;
	return (rc);
}


/*
 * return the system id (the current value in the kernel
 * currently running).
 *
 * on error return -1 and set errno.
 */
int
nsc_getsystemid(int *id)
{
	ncall_node_t node;
	int rval = 0;
	int save_errno = 0;
	int fd;

	*id = 0;

	fd = open("/dev/ncall", O_RDONLY);
	if (fd < 0)
		return (-1);

	memset(&node, 0, sizeof (node));

	rval = ioctl(fd, NC_IOC_GETNODE, &node);
	if (rval < 0)
		save_errno = errno;
	else {
		*id = node.nc_nodeid;
		/*
		 * Return 0, not the mirror node id as returned
		 * from the ioctl.
		 */
		rval = 0;
	}

	close(fd);

	errno = save_errno;
	return (rval);
}


/*
 * Runtime Solaris release checking.
 *
 * Compare the build release to the runtime release to check for an
 * acceptable match.
 *
 * Arguments:
 *	build_ver   - the string Solaris build release (e.g. "5.8")
 *	map         - optional array of nsc_release_t defining
 *			acceptable build release / runtime release
 *			matches. If supplied, must end will a NULL
 *			array element.  See src/head/nsctl.h for info.
 *	reqd        - used to return the required OS versions if the
 *			return value is not -1.  The returned string
 *			is readonly.
 *
 * Returns:
 *	TRUE	- acceptable match
 *	FALSE	- no match (component should not continue to run)
 *	-1	- error (errno is set)
 */

int
nsc_check_release(const char *build_rel, nsc_release_t *map, char **reqd)
{
	struct utsname uts;
	nsc_release_t *mp;
	const char *sep = ", ";
	char *cp, *tofree, *last;
	int rc;

	if (reqd)
		*reqd = NULL;

	if (build_rel == NULL || *build_rel == '\0') {
		errno = EINVAL;
		return (-1);
	}

	/* assume that build_rel is the required release for now */
	if (reqd)
		*reqd = (char *)build_rel;

	if (uname(&uts) < 0)
		return (-1);

	/* build release == runtime release is always acceptable */
	if (strcmp(build_rel, uts.release) == 0)
		return (TRUE);

	if (map == NULL)
		return (FALSE);

	rc = FALSE;
	tofree = NULL;

	for (mp = map; mp->build != NULL && mp->runtime != NULL; mp++) {
		if (strcmp(mp->build, build_rel) == 0) {
			/*
			 * found an entry for this build release
			 * - search for a match in the runtime releases
			 */

			/* reset reqd to this entry */
			if (reqd)
				*reqd = (char *)mp->runtime;

			/*
			 * operate on a copy of the string since strtok
			 * is destructive.
			 */
			tofree = cp = strdup(mp->runtime);
			if (cp == NULL) {
				errno = ENOMEM;
				rc = -1;
				break;
			}

			cp = strtok_r(cp, sep, &last);
			while (cp != NULL) {
				if (strcmp(cp, uts.release) == 0) {
					rc = TRUE;
					break;
				}

				cp = strtok_r(NULL, sep, &last);
			}

			break;
		}
	}

	if (tofree)
		free(tofree);

	return (rc);
}


/*
 * return the system id corresponding to name
 *
 * on error return -1 and set errno.
 */
int
nsc_name_to_id(char *name, int *id)
{
	ncall_node_t *nodes;
	int rval = 0;
	int nodecnt;
	int slot;

	*id = 0;

	nodecnt = nsc_getcurrentnodes(&nodes);
	if (nodecnt < 0) {
		rval = -1;
	} else {
		for (slot = 0; slot < nodecnt; slot++) {
			if (strcmp(name, nodes[slot].nc_nodename) == 0) {
				*id = nodes[slot].nc_nodeid;
				break;
			}
		}
		if (slot >= nodecnt) {
			errno = ENOENT;
			rval = -1;
		}
		free(nodes);
	}
	return (rval);
}

/*
 * return the node name corresponding to system id
 *
 * on error return -1 and set errno.
 * The returned string has been strdup() and needs
 * to be freed by the caller.
 */
int
nsc_id_to_name(char **name, int id)
{
	ncall_node_t *nodes;
	int rval = 0;
	int nodecnt;
	int slot;
	char *foundname;

	*name = 0;
	foundname = NULL;

	nodecnt = nsc_getcurrentnodes(&nodes);
	if (nodecnt < 0) {
		rval = -1;
	} else {
		for (slot = 0; slot < nodecnt; slot++) {
			if (nodes[slot].nc_nodeid == id) {
				foundname = strdup(nodes[slot].nc_nodename);
				if (foundname) {
					*name = foundname;
				} else {
					errno = ENOMEM;
					rval = -1;
				}
				break;
			}
		}
		if (slot >= nodecnt) {
			errno = ENOENT;
			rval = -1;
		}
		free(nodes);
	}
	return (rval);
}
