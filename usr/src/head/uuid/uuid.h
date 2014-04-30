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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2014 Andrew Stormont.
 */

#ifndef	_UUID_H
#define	_UUID_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The copyright in this file is taken from the original Leach & Salz
 * UUID specification, from which this implementation is derived.
 */

/*
 * Copyright (c) 1990- 1993, 1996 Open Software Foundation, Inc.
 * Copyright (c) 1989 by Hewlett-Packard Company, Palo Alto, Ca. &
 * Digital Equipment Corporation, Maynard, Mass.  Copyright (c) 1998
 * Microsoft.  To anyone who acknowledges that this file is provided
 * "AS IS" without any express or implied warranty: permission to use,
 * copy, modify, and distribute this file for any purpose is hereby
 * granted without fee, provided that the above copyright notices and
 * this notice appears in all source code copies, and that none of the
 * names of Open Software Foundation, Inc., Hewlett-Packard Company,
 * or Digital Equipment Corporation be used in advertising or
 * publicity pertaining to distribution of the software without
 * specific, written prior permission.  Neither Open Software
 * Foundation, Inc., Hewlett-Packard Company, Microsoft, nor Digital
 * Equipment Corporation makes any representations about the
 * suitability of this software for any purpose.
 */

#include <sys/types.h>
#include <sys/uuid.h>

extern void uuid_generate(uuid_t);
extern void uuid_generate_random(uuid_t);
extern void uuid_generate_time(uuid_t);
extern void uuid_copy(uuid_t, uuid_t);
extern void uuid_clear(uuid_t);
extern void uuid_unparse(uuid_t, char *);
extern void uuid_unparse_lower(uuid_t, char *);
extern void uuid_unparse_upper(uuid_t, char *);
extern int uuid_compare(uuid_t, uuid_t);
extern int uuid_is_null(uuid_t);
extern int uuid_parse(char *, uuid_t);
extern time_t uuid_time(uuid_t, struct timeval *);

#ifdef __cplusplus
}
#endif

#endif /* _UUID_H */
