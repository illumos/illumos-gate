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
 * This file contains the glue code that allows the NWS software to
 * determine whether a cluster disk service is local to this node or
 * not.
 *
 * See PSARC/1999/462 for more information on the interfaces from
 * suncluster that are used here.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>

#include <sys/ncall/ncall.h>
#include <sys/nsctl/nsc_hash.h>

#include "cfg_cluster.h"
#include "cfg_impl.h"
#include "cfg.h"

/*
 * Static variables
 */

static scconf_nodeid_t cl_nodeid = (uint_t)0xffff;
static char *cl_nodename = NULL;

static void *libscstat;
static void *libscconf;

static hash_node_t **schash;
static int init_sc_entry();

typedef struct hash_data_s {
	scstat_node_name_t	scstat_node_name;
} hash_data_t;

/*
 * Global variables
 */
int cl_initialized = 0;


/*
 * Tell the linker to keep quiet.
 */

#pragma weak scconf_get_nodename
#pragma weak scconf_strerr
#pragma weak scconf_get_ds_by_devt

#pragma weak scstat_get_ds_status
#pragma weak scstat_free_ds_status
#pragma weak scstat_strerr


/*
 * Initialise the library if we have not done so before.
 *
 * - IMPORTANT -
 *
 * This must -never- be called from any command that can be started
 * from /usr/cluster/lib/sc/run_reserve (and hence
 * /usr/cluster/sbin/reconfig) or the system will deadlock
 * during switchover.  This includes:
 *
 *       - svadm (no options, "print") -- called during sv switchover
 *       - all boot commands
 *
 * - grab this node's cluster nodeid
 * - attempt to dlopen() the suncluster shared libraries we need
 * - grab this node's cluster nodename
 *
 * Returns:
 *   0   - success
 *  -1   - error, errno is set
 */

int
cfg_cluster_init(void)
{
	const char *scconf = "/usr/cluster/lib/libscconf.so.1";
	const char *scstat = "/usr/cluster/lib/libscstat.so.1";
#ifdef DEBUG
	char errbuf[SCCONF_MAXSTRINGLEN];
#endif
	scconf_nodeid_t id;
	scconf_errno_t err;
	char *name;
	FILE *pipe;
	int rc;

	/*
	 * First check to see if we really are a cluster as clinfo -n can lie
	 */
	if (cl_nodeid == 0xffff) {
		rc = system("/usr/sbin/clinfo");
		if (rc != -1 && WEXITSTATUS(rc) == 1) {
			/* not a cluster */
			cl_initialized = 1;
			cl_nodeid = 0;
			return (0);
		}

		pipe = popen("/usr/sbin/clinfo -n 2>/dev/null || echo 0", "r");
		if (pipe == NULL) {
#ifdef DEBUG
			fprintf(stderr, "unable to get nodeid: %s\n",
				strerror(errno));
#endif
			return (-1);
		}

		if ((rc = fscanf(pipe, "%d", &id)) != 1) {
#ifdef DEBUG
			fprintf(stderr, "unable to get nodeid: %s\n",
				strerror(errno));
#endif
			return (-1);
		}

		pclose(pipe);

		cl_nodeid = id;
	}

	/* Already loaded the Sun Cluster device tree */
	if (cl_initialized)
		return (0);

	/*
	 * Try and dlopen the various libraries that we need
	 */

	libscconf = dlopen(scconf, RTLD_LAZY | RTLD_GLOBAL);
	if (libscconf == NULL)
		goto error;

	libscstat = dlopen(scstat, RTLD_LAZY | RTLD_GLOBAL);
	if (libscstat == NULL)
		goto error;

	err = scconf_get_nodename(id, &name);
	if (err == SCCONF_EPERM) {
		cl_nodename = NULL;
	} else if (err != SCCONF_NOERR) {
#ifdef DEBUG
		scconf_strerr(errbuf, err);
		fprintf(stderr, "scconf_get_nodename: %d: %s\n", err, errbuf);
#endif
		goto error;
	} else
		cl_nodename = name;

	/* Load the Sun Cluster device tree */
	init_sc_entry();
	cl_initialized = 1;
	return (0);

error:	/* error cleanup */
	if (libscconf)
		dlclose(libscconf);

	if (libscstat)
		dlclose(libscstat);

	libscconf = NULL;
	libscstat = NULL;

	errno = ENOSYS;
	return (-1);
}


/*
 * cfg_issuncluster()
 *
 * Description:
 *  Return the SunCluster nodeid of this node.
 *
 * Returns:
 *  >0   - running in a SunCluster (value is nodeid of this node)
 *   0   - not running in a cluster
 *  -1   - failure; errno is set
 */

int
cfg_issuncluster()
{
	if (cfg_cluster_init() >= 0)
		return ((int)cl_nodeid);
	else
		return (-1);
}
int
cfg_iscluster()
{
	return (cfg_issuncluster());
}

/*
 * cfg_l_dgname_islocal()
 * Check if disk group is local on a non-SunCluster.
 *
 * Returns as cfg_dgname_islocal().
 */
#ifndef lint
static int
cfg_l_dgname_islocal(char *dgname, char **othernode)
{
	const char *metaset = "/usr/sbin/metaset -s %s -o > /dev/null 2>&1";
	char command[1024];
	int rc;

	if (snprintf(command, sizeof (command), metaset, dgname) >=
	    sizeof (command)) {
		errno = ENOMEM;
		return (-1);
	}

	rc = system(command);
	if (rc < 0) {
		return (-1);
	}

	if (WEXITSTATUS(rc) != 0) {
		if (othernode) {
			/* metaset doesn't tell us */
			*othernode = "unknown";
		}

		return (0);
	}

	return (1);
}
#endif

/*
 * cfg_dgname_islocal(char *dgname, char **othernode)
 * -- determine if the named disk service is mastered on this node
 *
 * If the disk service is mastered on another node, that nodename
 * will be returned in othernode (if not NULL).  It is up to the
 * calling program to call free() on this value at a later time to
 * free the memory allocated.
 *
 * Returns:
 *   1   - disk service is mastered on this node
 *   0   - disk service is not mastered on this node (*othernode set)
 *   -1  - error (errno will be set)
 */

int
cfg_dgname_islocal(char *dgname, char **othernode)
{
	hash_data_t *data;

	if (dgname == NULL || *dgname == '\0' || othernode == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* Handle non-cluster configurations */
	if (cfg_cluster_init() < 0) {
		return (-1);
	} else 	if (cl_nodeid == 0) {
		/* it has to be local */
		return (1);
	}

	/*
	 * lookup the current diskgroup name
	 */
	if (data = (hash_data_t *)nsc_lookup(schash, dgname)) {
		if (strcmp(data->scstat_node_name, cl_nodename)) {
			if (othernode)
			    *othernode = strdup(data->scstat_node_name);
			return (0);
		} else {
			return (1);
		}
	} else {
		errno = ENODEV;
		return (-1);
	}
}

/*
 * cfg_l_dgname()
 * parse the disk group name from the a device pathname on a non-SunCluster.
 *
 * Returns as cfg_dgname().
 */

char *
cfg_l_dgname(const char *pathname, char *buffer, size_t buflen)
{
	const char *dev = "/dev/";
	const char *vx = "vx/";
	const char *md = "md/";
	const char *dsk = "dsk/";
	const char *start, *cp;
	int ll, len, chkdsk;

	bzero(buffer, buflen);
	chkdsk = 0;

	ll = strlen(dev);
	if (strncmp(pathname, dev, ll) != 0) {
		/* not a device pathname */
		errno = EINVAL;
		return ((char *)NULL);
	}

	start = pathname + ll;

	if (strncmp(start, vx, (ll = strlen(vx))) == 0) {
		/*
		 * Veritas --
		 * /dev/vx/{r}dsk/dgname/partition
		 */

		start += ll;

		ll = strlen(dsk);

		if (*start == 'r' && strncmp((start + 1), dsk, ll) == 0)
			start += ll + 1;
		else if (strncmp(start, dsk, ll) == 0)
			start += ll;
		else {
			/* no dgname */
			return (buffer);
		}
	} else {
		/* no dgname */
		return (buffer);
	}

	for (cp = start, len = 0; *cp != '\0' && *cp != '/'; cp++)
		len++;	/* count length of dgname */

	if (*cp == '\0') {
		/* no dgname */
		return (buffer);
	}

#ifdef DEBUG
	if (*cp != '/') {
		fprintf(stderr,
		    "cfg_dgname: parse error: *cp = '%c', expected '/'\n", *cp);
		errno = EPROTO;
		return ((char *)NULL);
	}
#endif

	if (chkdsk) {
		cp++;	/* skip the NULL */

		ll = strlen(dsk);

		if ((*cp != 'r' || strncmp((cp + 1), dsk, ll) != 0) &&
		    strncmp(cp, dsk, ll) != 0) {
			/* no dgname */
			return (buffer);
		}
	}

	if (len >= buflen) {
		errno = E2BIG;
		return ((char *)NULL);
	}

	(void) strncpy(buffer, start, len);
	return (buffer);
}


/*
 * cfg_dgname()
 * determine which cluster resource group the pathname belongs to, if any
 *
 * Returns:
 *	NULL			- error (errno is set)
 *	ptr to NULL-string	- no dgname
 *	pointer to string	- dgname
 */

char *
cfg_dgname(const char *pathname, char *buffer, size_t buflen)
{
	scconf_errno_t conferr;
	char *dsname = NULL;
	struct stat stb;
#ifdef DEBUG
	char errbuf[SCCONF_MAXSTRINGLEN];
#endif

	bzero(buffer, buflen);

	if (pathname == NULL || *pathname == '\0') {
		errno = EINVAL;
		return ((char *)NULL);
	}

	/* Handle non-cluster configurations */
	if (cfg_cluster_init() < 0) {
		errno = EINVAL;
		return ((char *)NULL);
	} else 	if (cl_nodeid == 0) {
		/* must be local - return NULL-string dgname */
		return (buffer);
	}

	if (stat(pathname, &stb) < 0) {
		errno = EINVAL;
		return ((char *)NULL);
	}

	conferr = scconf_get_ds_by_devt(major(stb.st_rdev),
	    minor(stb.st_rdev), &dsname);

	if (conferr == SCCONF_ENOEXIST) {
		return (buffer);
	} else if (conferr != SCCONF_NOERR) {
#ifdef DEBUG
		scconf_strerr(errbuf, conferr);
		fprintf(stderr,
		    "scconf_get_ds_by_devt: %d: %s\n", conferr, errbuf);
#endif
		errno = EINVAL;
		return ((char *)NULL);
	}

	strncpy(buffer, dsname, buflen);
	free(dsname);

	return (buffer);
}


/*
 * init_sc_entry
 *
 * Add an entry into the sclist and the schash for future lookups.
 *
 * - IMPORTANT -
 *
 * This must -never- be called from any command that can be started
 * from /usr/cluster/lib/sc/run_reserve (and hence
 * /usr/cluster/sbin/reconfig) or the system will deadlock
 * during switchover.  This includes:
 *
 *       - svadm (no options, "print") -- called during sv switchover
 *       - all boot commands
 *
 * Return values:
 *  -1  An error occurred.
 *   0  Entry added
 *   1  Entry already exists.
 */
static int
init_sc_entry()
{
	scstat_ds_node_state_t *dsn;
	scstat_ds_name_t dsname;
	scstat_ds_t *dsstatus, *dsp;
	scstat_errno_t err;
#ifdef DEBUG
	char errbuf[SCCONF_MAXSTRINGLEN];
#endif

	hash_data_t *hdp;

	/*
	 * Allocate a hash table
	 */
	if ((schash = nsc_create_hash()) == NULL)
		return (-1);

	/*
	 * the API is broken here - the function is written to expect
	 * the first argument to be (scstat_ds_name_t), but the function
	 * declaration in scstat.h requires (scstat_ds_name_t *).
	 *
	 * We just cast it to get rid of the compiler warnings.
	 * If "dsname" is NULL, information for all device services is returned
	 */
	dsstatus = NULL;
	dsname = NULL;
	/* LINTED pointer alignment */
	err = scstat_get_ds_status((scstat_ds_name_t *)dsname, &dsstatus);
	if (err != SCSTAT_ENOERR) {
#ifdef DEBUG
		scstat_strerr(err, errbuf);
		fprintf(stderr, "scstat_get_ds_status(): %d: %s\n",
		    err, errbuf);
#endif
		errno = ENOSYS;
		return (-1);
	}

	if (dsstatus == NULL) {
		errno = ENODEV;
		return (-1);
	}

	/*
	 * Traverse scstat_ds list, saving away resource in out hash table
	 */
	for (dsp = dsstatus; dsp; dsp = dsp->scstat_ds_next) {

		/* Skip over NULL scstat_ds_name's */
		if ((dsp->scstat_ds_name == NULL) ||
		    (dsp->scstat_ds_name[0] == '\0'))
			continue;

		/* See element exits already, error if so */
		if (nsc_lookup(schash, dsp->scstat_ds_name)) {
			fprintf(stderr, "scstat_get_ds_status: duplicate %s",
				dsp->scstat_ds_name);
			errno = EEXIST;
			return (-1);
		}

		/* Traverse the node status list */
		for (dsn = dsp->scstat_node_state_list; dsn;
					dsn = dsn->scstat_node_next) {
			/*
			 * Only keep trace of primary nodes
			 */
			if (dsn->scstat_node_state != SCSTAT_PRIMARY)
				continue;

			/* Create an element to insert */
			hdp = (hash_data_t *)malloc(sizeof (hash_data_t));
			hdp->scstat_node_name = strdup(dsn->scstat_node_name);
			nsc_insert_node(schash, hdp, dsp->scstat_ds_name);
		}
	}

	/*
	 * Free up scstat resources
	 */
	scstat_free_ds_status(dsstatus);
	return (0);
}
