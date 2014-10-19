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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*LINTLIBRARY*/

/*
 * See /ws/unix200x-gate/usr/src/lib/libc/port/gen/xpg6.c for libc default.
 * __xpg6 (C99/SUSv3) is first included in Solaris 10 libc and libm
 * as well as the K2 (S1S8) libsunmath and libmopt.
 *
 * The default setting, _C99SUSv3_mode_OFF, means to retain current Solaris
 * behavior which is NOT C99/SUSv3 compliant.  This is normal.  These libraries
 * determine which standard to use based on how applications are built.  These
 * libraries at runtime determine which behavior to choose based on the value
 * of __xpg6.  By default they retain their original Solaris behavior.
 *
 * __xpg6 is used to control certain behaviors between the C99 standard, the
 * SUSv3 standard, and Solaris.  More explanation in lib/libc/inc/xpg6.h.
 * The XPG6 C compiler utility (c99) will add an object file that contains
 * an alternate definition for __xpg6.  The symbol interposition provided
 * by the linker will allow these libraries to find that symbol instead.
 *
 * Possible settings are available and documented in lib/libc/inc/xpg6.h.
 */

#include "xpg6.h"

unsigned int __xpg6 = _C99SUSv3_mode_OFF;
