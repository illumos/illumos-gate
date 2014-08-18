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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ZDOOR_INT_H
#define	_ZDOOR_INT_H

#pragma ident "%Z%%M% %I% %E% SMI"

#include <pthread.h>
#include <zdoor.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum zdoor_action_t {
	ZDOOR_ACTION_NOOP,
	ZDOOR_ACTION_STOP,
	ZDOOR_ACTION_START
} zdoor_action_t;

struct zdoor_handle {
	pthread_mutex_t zdh_lock;
	void *zdh_zonecfg_handle;
	void *zdh_ztree;
};

zdoor_cookie_t *zdoor_cookie_create(const char *zonename, const char *service,
	const void *biscuit);

void zdoor_cookie_free(zdoor_cookie_t *cookie);

boolean_t zdoor_zone_is_running(zoneid_t zoneid);

int zdoor_fattach(zoneid_t zoneid, const char *service, int door,
	int detach_only);

#ifdef __cplusplus
}
#endif

#endif /* _ZDOOR_INT_H */
