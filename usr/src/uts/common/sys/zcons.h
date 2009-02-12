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
 * Minor node name of the global zone side (often called the "master" side)
 * of the zcons driver.
 */
#define	ZCONS_MASTER_NAME	"masterconsole"

/*
 * Minor node name of the non-global zone side (often called the "slave"
 * side) of the zcons driver.  We name it "zoneconsole" since that nameo
 * will show up in 'ps' output, and will make some sense to the global zone
 * user.  Inside the zone, it will simply show up as "console" due to the
 * links we create.
 */
#define	ZCONS_SLAVE_NAME	"zoneconsole"

/*
 * ZC_IOC forms the base for all zcons ioctls.
 */
#define	ZC_IOC		(('Z' << 24) | ('o' << 16) | ('n' << 8))

/*
 * These ioctls instruct the master side of the console to hold or release
 * a reference to the slave side's vnode.  They are meant to be issued by
 * zoneadmd after the console device node is created and before it is destroyed
 * so that the slave's STREAMS anchor, ptem, is preserved when ttymon starts
 * popping STREAMS modules from within the associated zone.  This guarantees
 * that the zone slave console will always have terminal semantics while the
 * zone is running.
 *
 * A more detailed description can be found in uts/common/io/zcons.c.
 */
#define	ZC_HOLDSLAVE	(ZC_IOC | 0)	/* get and save slave side reference */
#define	ZC_RELEASESLAVE	(ZC_IOC | 1)	/* release slave side reference */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZCONS_H */
