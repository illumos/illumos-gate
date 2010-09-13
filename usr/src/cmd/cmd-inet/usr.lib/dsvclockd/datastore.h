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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	DSVCD_DATASTORE_H
#define	DSVCD_DATASTORE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <synch.h>
#include <door.h>

#include "container.h"

/*
 * Datastore-related data structures, functions and constants.  See
 * comments in datastore.c for a description of how to use the exported
 * functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	DSVCD_DS_HASH_SIZE	100

/*
 * A linked list of dsvcd_container_t structures.  Contains a lock,
 * `cl_lock', which is used for controlling manipulation of `cl_head'.
 */
typedef struct {
	mutex_t			cl_lock;	/* protects the list */
	dsvcd_container_t	*cl_head;	/* linked list of containers */
	uint8_t			cl_pad[8];	/* prevent false sharing */
} dsvcd_container_list_t;

/*
 * Describes the underlying datastore itself.  There is exactly one
 * dsvcd_datastore_t per datastore using doors (so currently, there are
 * two: one for `ds_files' and one for `ds_data').  Contains per-datastore
 * information, like the door descriptor being used by dsvclockd to listen
 * to requests for this datastore, the datastore name, and a list of all
 * open containers for this datastore.  Instances of this data structure
 * are allocated when dsvclockd is started.
 */
typedef struct dsvcd_datastore {
	char			*ds_name;	/* datastore name */
	int			ds_doorfd;	/* datastore door */

	/*
	 * This hash is used to speed up the open() routine so that a given
	 * container can be located quicker.  Hash based on the filename,
	 * and use it as an index into the array..
	 */
	dsvcd_container_list_t	ds_hash[DSVCD_DS_HASH_SIZE];
} dsvcd_datastore_t;

typedef void dsvcd_svc_t(void *, dsvcd_request_t *, size_t, door_desc_t *,
	uint_t);

extern dsvcd_datastore_t *ds_create(const char *, dsvcd_svc_t *);
extern void ds_destroy(dsvcd_datastore_t *);
extern unsigned int ds_reap_containers(dsvcd_datastore_t *, unsigned int);
extern void ds_release_container(dsvcd_datastore_t *, dsvcd_container_t *);
extern dsvcd_container_t *ds_get_container(dsvcd_datastore_t *, const char *,
    boolean_t);

#ifdef	__cplusplus
}
#endif

#endif	/* DSVCD_DATASTORE_H */
