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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * __xpg6 (C99/SUSv3) was first introduced in Solaris 10.
 *
 * This file is NOT linked into libc.  See xpg6.c.
 * This value is linked into an application when the application is
 * requesting conforming C99/SUSv3 behavior.  This is usually done
 * with the c99 utility.
 *
 * __xpg6 is used to control certain behaviors between the C99 standard,
 * the SUSv3 standard, and Solaris.  More explanation in inc/xpg6.h.
 * The XPG6 C compiler utility (c99) will add an object file that contains an
 * alternate definition for __xpg6.  The symbol interposition provided
 * by the linker will allow libc to find that symbol instead.
 *
 * Possible settings are available and documented in inc/xpg6.h.
 */

/*
 * This setting enables strictly conforming C99/SUSv3 behavior.
 */

#include "xpg6.h"

unsigned int __xpg6 = _C99SUSv3_mode_ON;

/*
 * Also turn on XPG4 mode.
 */
int __xpg4 = 1;
