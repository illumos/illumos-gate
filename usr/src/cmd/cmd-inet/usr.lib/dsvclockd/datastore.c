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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <synch.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <dhcp_svc_private.h>
#include <sys/time.h>
#include <dhcpmsg.h>

#include "dsvclockd.h"
#include "datastore.h"

static uint32_t		ds_hash(const char *);

/*
 * Create a datastore named `ds_name' and a door which will service requests
 * for this datastore.  When the door is called, callback `ds_callback'.
 * Returns the created datastore.
 */
dsvcd_datastore_t *
ds_create(const char *ds_name, dsvcd_svc_t *ds_callback)
{
	char			door_path[MAXPATHLEN];
	dsvcd_datastore_t	*ds = NULL;
	int			fd;
	unsigned int		i;
	door_info_t		info;

	dhcpmsg(MSG_VERBOSE, "managing locks for datastore `%s'", ds_name);

	ds = malloc(sizeof (dsvcd_datastore_t));
	if (ds == NULL) {
		dhcpmsg(MSG_ERR, "cannot manage locks for datastore `%s'",
		    ds_name);
		return (NULL);
	}

	ds->ds_name = strdup(ds_name);
	if (ds->ds_name == NULL) {
		dhcpmsg(MSG_ERR, "cannot manage locks for datastore `%s'",
		    ds_name);
		free(ds);
		return (NULL);
	}

	ds->ds_doorfd = door_create((void (*)())ds_callback, ds,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
	if (ds->ds_doorfd == -1) {
		dhcpmsg(MSG_ERR, "cannot create door for datastore `%s'",
		    ds_name);
		free(ds->ds_name);
		free(ds);
		return (NULL);
	}

	for (i = 0; i < DSVCD_DS_HASH_SIZE; i++) {
		ds->ds_hash[i].cl_head = NULL;
		(void) mutex_init(&ds->ds_hash[i].cl_lock, USYNC_THREAD, 0);
	}

	/*
	 * Create the door name in the filesystem.  First, check to see if
	 * a door already exists at the specified pathname.  If it does,
	 * and the server process (no doubt another copy of us) is already
	 * running, then fail.  Otherwise, unlink the old door and fattach
	 * a new one.
	 */
	(void) snprintf(door_path, sizeof (door_path), DSVCD_DOOR_FMT, ds_name);

	fd = open(door_path, O_RDWR);
	if (fd != -1) {
		if (door_info(fd, &info) == 0 && info.di_target != -1) {
			dhcpmsg(MSG_ERROR, "%s is in use by process %lu",
			    door_path, info.di_target);
			(void) close(fd);
			(void) close(ds->ds_doorfd);
			free(ds->ds_name);
			free(ds);
			return (NULL);
		}
		(void) close(fd);
		(void) unlink(door_path);
	}

	fd = open(door_path, O_CREAT|O_EXCL|O_RDWR, 0644);
	if (fd == -1) {
		dhcpmsg(MSG_ERR, "cannot create door rendezvous for datastore "
		    "`%s'", ds_name);
		(void) close(ds->ds_doorfd);
		free(ds->ds_name);
		free(ds);
		return (NULL);
	}
	(void) close(fd);

	/*
	 * Attach the door onto the name
	 */
	if (fattach(ds->ds_doorfd, door_path) == -1) {
		dhcpmsg(MSG_ERR, "cannot fattach door rendezvous for datastore "
		    "`%s'", ds_name);
		(void) close(ds->ds_doorfd);
		free(ds->ds_name);
		free(ds);
		return (NULL);
	}

	return (ds);
}

/*
 * Destroy a datastore `ds' and its associated containers, and remove
 * its door from the filesystem.
 */
void
ds_destroy(dsvcd_datastore_t *ds)
{
	unsigned int		i;
	char			door_path[MAXPATHLEN];
	dsvcd_container_t	*cn, *cn_next;

	dhcpmsg(MSG_VERBOSE, "stopping lock management for datastore `%s'",
	    ds->ds_name);

	/*
	 * Detach and revoke access to the door.  The detach makes it so
	 * new callers who open the door will fail; the revoke makes it
	 * so that callers that already have a door descriptor will fail.
	 * We do this prior to calling cn_destroy() to make it easier for
	 * the container lockcount to drain.
	 */
	(void) snprintf(door_path, MAXPATHLEN, DSVCD_DOOR_FMT, ds->ds_name);
	(void) fdetach(door_path);
	(void) unlink(door_path);
	(void) door_revoke(ds->ds_doorfd);
	(void) close(ds->ds_doorfd);

	/*
	 * Destroy all the underlying containers.  We're single-threaded at
	 * this point, so don't worry about locks.
	 */
	for (i = 0; i < DSVCD_DS_HASH_SIZE; i++) {
		for (cn = ds->ds_hash[i].cl_head; cn != NULL; cn = cn_next) {
			cn_next = cn->cn_next;
			cn_destroy(cn);
		}
		(void) mutex_destroy(&ds->ds_hash[i].cl_lock);
	}

	free(ds->ds_name);
	free(ds);
}

/*
 * Get a container with id `cn_id' from datastore `ds'; create the
 * container if it does not exist.  If `crosshost' is set and the container
 * does not yet exist, then the container will synchronize across hosts.  .
 * If the container cannot be found or created, NULL is returned.  When the
 * calling thread is done with the container, ds_release_container() must
 * be called.
 */
dsvcd_container_t *
ds_get_container(dsvcd_datastore_t *ds, const char *cn_id, boolean_t crosshost)
{
	dsvcd_container_list_t	*cn_list;
	dsvcd_container_t	*cn;
	uint32_t		idhash = ds_hash(cn_id);

	cn_list = &ds->ds_hash[idhash % DSVCD_DS_HASH_SIZE];
	(void) mutex_lock(&cn_list->cl_lock);

	for (cn = cn_list->cl_head; cn != NULL; cn = cn->cn_next) {
		if (idhash == cn->cn_idhash && strcmp(cn_id, cn->cn_id) == 0)
			break;
	}

	if (cn == NULL) {
		cn = cn_create(cn_id, crosshost);
		if (cn != NULL) {
			if (cn_list->cl_head != NULL)
				cn_list->cl_head->cn_prev = cn;

			cn->cn_next	 = cn_list->cl_head;
			cn->cn_prev	 = NULL;
			cn_list->cl_head = cn;
			cn->cn_idhash	 = idhash;
			cn->cn_nout	 = 0;
			cn->cn_lastrel	 = 0;
		}
	}

	if (cn != NULL)
		cn->cn_nout++;

	(void) mutex_unlock(&cn_list->cl_lock);
	return (cn);
}

/*
 * Release a container `cn' belonging to datastore `ds'.  Once a container
 * has been released, it can no longer be used by the releasing thread.
 * Used to track the number of active instances of a container.
 */
void
ds_release_container(dsvcd_datastore_t *ds, dsvcd_container_t *cn)
{
	dsvcd_container_list_t	*cn_list;
	uint32_t		idhash = ds_hash(cn->cn_id);

	cn_list = &ds->ds_hash[idhash % DSVCD_DS_HASH_SIZE];

	(void) mutex_lock(&cn_list->cl_lock);

	cn->cn_nout--;
	cn->cn_lastrel = time(NULL);

	(void) mutex_unlock(&cn_list->cl_lock);
}

/*
 * Destroy any containers in datastore `ds' that have not been accessed in
 * the last `idle' seconds.  Return the number of destroyed (reaped)
 * containers.
 */
unsigned int
ds_reap_containers(dsvcd_datastore_t *ds, unsigned int idle)
{
	dsvcd_container_list_t	*cn_list;
	dsvcd_container_t	*cn, *cn_next;
	unsigned int		i, nreaped = 0;

	for (i = 0; i < DSVCD_DS_HASH_SIZE; i++) {
		cn_list = &ds->ds_hash[i];

		(void) mutex_lock(&cn_list->cl_lock);
		for (cn = cn_list->cl_head; cn != NULL; cn = cn_next) {
			cn_next = cn->cn_next;

			/*
			 * Since a container is not checked out across a
			 * lock operation, we must check if the lock is
			 * held as well as the number of instances checked
			 * out.
			 */
			if (cn->cn_nout != 0 ||
			    cn_locktype(cn) != DSVCD_NOLOCK ||
			    cn->cn_lastrel + idle >= time(NULL))
				continue;

			if (cn == cn_list->cl_head)
				cn_list->cl_head = cn->cn_next;
			else
				cn->cn_prev->cn_next = cn->cn_next;

			if (cn->cn_next != NULL)
				cn->cn_next->cn_prev = cn->cn_prev;

			cn_destroy(cn);
			nreaped++;
		}
		(void) mutex_unlock(&cn_list->cl_lock);
	}

	return (nreaped);
}

/*
 * Hash a container identified by `cn_id' into a 32-bit unsigned integer
 * suitable for use as a key in a hash table.
 */
static uint32_t
ds_hash(const char *cn_id)
{
	uint32_t	result = 0;
	unsigned int	i;

	for (i = 0; cn_id[i] != '\0'; i++)
		result += cn_id[i] << i;

	return (result);
}
