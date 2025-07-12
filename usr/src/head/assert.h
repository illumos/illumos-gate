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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2016 Joyent, Inc.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2023 Oxide Computer Company
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Note that the ANSI C Standard requires all headers to be idempotent except
 * <assert.h> which is explicitly required not to be idempotent (section 4.1.2).
 * We split up the idempotent sections into <iso/assert_iso.h> and leave the
 * rest of this that should be impacted by NDEBUG here. There is no header
 * guard.  This is intentional. For more information on the split, see
 * <iso/assert_iso.h>.
 */

#include <iso/assert_iso.h>

#undef	assert

#ifdef	NDEBUG

#define	assert(EX) ((void)0)

#else

#if __STDC_VERSION__ - 0 >= 199901L
#define	assert(EX) (void)((EX) || \
	(__assert_c99(#EX, __FILE__, __LINE__, __func__), 0))
#else
#define	assert(EX) (void)((EX) || (__assert(#EX, __FILE__, __LINE__), 0))
#endif /* __STDC_VERSION__ - 0 >= 199901L */

#endif	/* NDEBUG */
