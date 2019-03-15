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
 * Copyright 2015, Joyent Inc. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Simulating just one zone here (the global zone)
 */

#include <sys/types.h>
#include <sys/zone.h>
#include <sys/debug.h>

static void *zone_specific_val;
static void *(*zkey_create)(zoneid_t);
// static void (*zkey_shutdown)(zoneid_t, void *);
// static void (*zkey_destroy)(zoneid_t, void *);

/* ARGSUSED */
void
zone_key_create(zone_key_t *keyp, void *(*create)(zoneid_t),
    void (*shutdown)(zoneid_t, void *), void (*destroy)(zoneid_t, void *))
{

	zkey_create = create;
	// zkey_shutdown = shutdown;
	// zkey_destroy = destroy;
	*keyp = 1;
}

/* ARGSUSED */
int
zone_key_delete(zone_key_t key)
{
	return (-1);
}

/* ARGSUSED */
int
zone_setspecific(zone_key_t key, zone_t *zone, const void *data)
{
	return (-1);
}

/* ARGSUSED */
void *
zone_getspecific(zone_key_t key, zone_t *zone)
{
	ASSERT(key == 1);
	if (zone_specific_val == NULL)
		zone_specific_val = (*zkey_create)(zone->zone_id);
	return (zone_specific_val);
}
