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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SYS_ZONE_H
#define	_SYS_ZONE_H

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/rctl.h>
#include <sys/ksynch.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NOTE
 *
 * The contents of this file are private to the implementation of
 * Solaris and are subject to change at any time without notice.
 * Applications and drivers using these interfaces may fail to
 * run on future releases.
 */

#define	GLOBAL_ZONEID	0
#define	ZONENAME_MAX	64

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

#include <sys/list.h>

typedef struct zone_ref {
	struct zone	*zref_zone; /* the zone to which the reference refers */
	list_node_t	zref_linkage; /* linkage for zone_t::zone_ref_list */
} zone_ref_t;

typedef struct zone {
	char		*zone_name;	/* zone's configuration name */
	zoneid_t	zone_id;	/* ID of zone */
	struct proc	*zone_zsched;	/* Dummy kernel "zsched" process */
	time_t		zone_boot_time;
	struct vnode	*zone_rootvp;	/* zone's root vnode */
	char		*zone_rootpath;	/* Path to zone's root + '/' */
	int fake_zone[10];
} zone_t;

extern zone_t zone0;
extern zone_t *global_zone;
extern uint_t maxzones;

/*
 * Zone-specific data (ZSD) APIs
 */
/*
 * The following is what code should be initializing its zone_key_t to if it
 * calls zone_getspecific() without necessarily knowing that zone_key_create()
 * has been called on the key.
 */
#define	ZONE_KEY_UNINITIALIZED	0

typedef uint_t zone_key_t;

extern void	zone_key_create(zone_key_t *, void *(*)(zoneid_t),
    void (*)(zoneid_t, void *), void (*)(zoneid_t, void *));
extern int 	zone_key_delete(zone_key_t);
extern void	*zone_getspecific(zone_key_t, zone_t *);
extern int	zone_setspecific(zone_key_t, zone_t *, const void *);

extern zoneid_t getzoneid(void);

#endif	/* _KERNEL || _FAKE_KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZONE_H */
