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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ZCONS_H
#define	_SYS_ZCONS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Minor node name of the global zone side (often called the "master" side)
 * of the zcons driver.
 *
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

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZCONS_H */
