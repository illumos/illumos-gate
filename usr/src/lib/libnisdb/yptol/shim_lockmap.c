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
 * Copyright 2015 Gary Mills
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * DESCRIPTION: Contains a front end to the map locking code. These are called
 *		when a map, or its map_ctrl structure, needs to be locked
 *		for a short time for internal modification. This lock should
 *		not be held between DBM operations.
 *
 * NOTE :	This is not the same mechanism as the `update lock` which is
 *		held for a relatively long period when a map is being update
 *		from the DIT.
 */

#include <unistd.h>
#include <syslog.h>
#include <sys/mman.h>
#include <thread.h>
#include <synch.h>
#include <ndbm.h>
#include "ypsym.h"
#include "shim.h"
#include "stubs.h"

/*
 * FUNCTION : 	lock_map_ctrl()
 *
 * DESCRIPTION: Front end to the lock routine taking map_ctrl structure as
 *		argument. Saves cost of a hash operation.
 *
 * GIVEN :	Map_ctrl structure .
 *
 * RETURNS :	Same as lock core
 */
int
lock_map_ctrl(map_ctrl *map)
{
	int ret;

	ret = lock_core(map->hash_val);

	return (ret);
}

/*
 * FUNCTION : 	unlock_map_ctrl()
 *
 * DESCRIPTION: Front end to the unlock routine taking map_ctrl structure as
 *		argument. Saves cost of a hash operation.
 *
 * GIVEN :	Map_ctrl structure .
 *
 * RETURNS :	Same as lock core
 */
int
unlock_map_ctrl(map_ctrl *map)
{
	int ret;

	ret = unlock_core(map->hash_val);
	return (ret);
}
