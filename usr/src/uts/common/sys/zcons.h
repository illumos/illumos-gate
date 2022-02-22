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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ZCONS_H
#define	_SYS_ZCONS_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Minor node name of the global zone side (often called the "manager" side)
 * of the zcons driver.
 */
#define	ZCONS_MANAGER_NAME	"globalconsole"

/*
 * Minor node name of the non-global zone side (often called the "subsidiary"
 * side) of the zcons driver.  We name it "zoneconsole" since that name
 * will show up in 'ps' output, and will make some sense to the global zone
 * user.  Inside the zone, it will simply show up as "console" due to the
 * links we create.
 */
#define	ZCONS_SUBSIDIARY_NAME	"zoneconsole"

/*
 * ZC_IOC forms the base for all zcons ioctls.
 */
#define	ZC_IOC		(('Z' << 24) | ('o' << 16) | ('n' << 8))

/*
 * These ioctls instruct the manager side of the console to hold or release
 * a reference to the subsidiary side's vnode.  They are meant to be issued by
 * zoneadmd after the console device node is created and before it is destroyed
 * so that the subsidiary's STREAMS anchor, ptem, is preserved when ttymon
 * starts popping STREAMS modules from within the associated zone.  This
 * guarantees that the zone subsidiary console will always have terminal
 * semantics while the zone is running.
 *
 * A more detailed description can be found in uts/common/io/zcons.c.
 */
#define	ZC_HOLDSUBSID		(ZC_IOC | 0)
#define	ZC_RELEASESUBSID	(ZC_IOC | 1)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZCONS_H */
