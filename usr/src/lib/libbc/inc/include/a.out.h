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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _a_out_h
#define _a_out_h

#if !defined(_CROSS_TARGET_ARCH)

   /* The usual, native case.  Usage:
    *      #include <a.out.h>
    */

#include <machine/a.out.h>

#else /*defined(_CROSS_TARGET_ARCH)*/

   /* Used when building a cross-tool, with the target system architecture
    * determined by the _CROSS_TARGET_ARCH preprocessor variable at compile
    * time.  Usage:
    *      #include <a.out.h>
    * ...plus compilation with command (e.g. for Sun-4 target architecture):
    *      cc  -DSUN2=2 -DSUN3=3 -DSUN3X=31 -DSUN4=4 \
    *		-D_CROSS_TARGET_ARCH=SUN4  ...
    * Note: this may go away in a future release.
    */
#  if   _CROSS_TARGET_ARCH == SUN2
#    include "sun2/a.out.h"
#  elif _CROSS_TARGET_ARCH == SUN3
#    include "sun3/a.out.h"
#  elif _CROSS_TARGET_ARCH == SUN3X
#    include "sun3x/a.out.h"
#  elif _CROSS_TARGET_ARCH == SUN4
#    include "sun4/a.out.h"
#  elif _CROSS_TARGET_ARCH == VAX
#    include "vax/a.out.h"
#  endif

#endif /*defined(_CROSS_TARGET_ARCH)*/

/*
 * Usage when building a cross-tool with a fixed target system architecture
 * (Sun-4 in this example), bypassing this file:
 *      #include <sun4/a.out.h>
 */

#endif /*!_a_out_h*/
