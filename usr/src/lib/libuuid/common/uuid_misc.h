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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_UUID_MISC_H
#define	_UUID_MISC_H

/*
 * The copyright in this file is taken from the original Leach
 * & Salz UUID specification, from which this implementation
 * is derived.
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

#ifdef	__cplusplus
extern "C" {
#endif

#include <uuid/uuid.h>
#include <sys/types.h>
#include <thread.h>

typedef uint64_t		uuid_time_t;

/*
 * data type for UUID generator persistent state
 */
typedef struct {
	uuid_time_t		ts;	/* saved timestamp */
	uuid_node_t		node;	/* saved node ID */
	uint16_t		clock;	/* saved clock sequence */
} uuid_state_t;

typedef struct {
	mutex_t			lock;
	uuid_state_t		state;
} shared_buffer_t;

#define	STATE_LOCATION		"/var/sadm/system/uuid_state"
#define	URANDOM_PATH		"/dev/urandom"
#define	MAX_RETRY		8
#define	VER1_MASK		0xefff

#define	STATE_FILE		1
#define	TEMP_FILE		2

#ifdef	__cplusplus
}
#endif

#endif /* _UUID_MISC_H */
