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
 * Copyright (c) 2015, Joyent, Inc.
 */

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

#include <uuid/uuid.h>
#include <stdlib.h>
#include <strings.h>
#include "uuid_misc.h"

#define	UUCMP(u1, u2)		if (u1 != u2) return ((u1 < u2) ? -1 : 1)
#define	UUIDS_PER_TOD_CALL	10	/* tv_usec is multiplied by 10 */

void		struct_to_string(uuid_t, struct uuid *);
void		string_to_struct(struct uuid *, uuid_t);
void		get_system_time(uuid_time_t *);

/*
 * Name:	get_current_time
 *
 * Description:	get-current_time -- get time as 60 bit 100ns ticks
 *		since the beginning of unix time.
 *		Compensate for the fact that real clock resolution is
 *		less than 100ns.
 *
 * Returns:	None.
 *
 */
void
get_current_time(uuid_time_t *timestamp)
{
	uuid_time_t		time_now;
	static uuid_time_t	time_last = 0;
	static uint16_t		uuids_this_tick = 0;
	int			done;

	done = 0;
	while (!done) {
		get_system_time(&time_now);

		/*
		 * if clock reading changed since last UUID generated...
		 */
		if (time_last != time_now) {
			/*
			 * reset count of uuids generated with
			 * this clock reading
			 */
			uuids_this_tick = 0;
			done = 1;
		} else {
			uuids_this_tick++;
			if (uuids_this_tick < UUIDS_PER_TOD_CALL)
				done = 1;
		}
		/*
		 * too many UUIDs for this gettimeofday call; spin
		 */
	}
	time_last = time_now;
	/*
	 * add the count of uuids to low order bits of the clock reading
	 */
	*timestamp = time_now + uuids_this_tick;
}

/*
 * Name:	get_random
 *
 * Description:	Gets a random number.
 *
 * Returns:	nbytes of random information.
 *
 */
uint16_t
get_random(void)
{
	return (arc4random_uniform(UINT16_MAX));
}

/*
 * Name:	uuid_compare
 *
 * Description: Compares 2 uuid strings
 *
 * Returns:	-1 if u1 < u2, 1 if u1 > u2 and 0 if both are equal
 */
int
uuid_compare(uuid_t uu1, uuid_t uu2)
{

	struct uuid	uuid1, uuid2;

	string_to_struct(&uuid1, uu1);
	string_to_struct(&uuid2, uu2);
	UUCMP(uuid1.time_low, uuid2.time_low);
	UUCMP(uuid1.time_mid, uuid2.time_mid);
	UUCMP(uuid1.time_hi_and_version, uuid2.time_hi_and_version);
	UUCMP(uuid1.clock_seq_hi_and_reserved, uuid2.clock_seq_hi_and_reserved);
	UUCMP(uuid1.clock_seq_low, uuid2.clock_seq_low);
	return (memcmp(uuid1.node_addr, uuid2.node_addr, 6));
}

/*
 * Name:	get_system_time
 *
 * Description:	system dependent call to get the current system time.
 *		Returned as 100ns ticks since Oct 15, 1582, but
 *		resolution may be less than 100ns.
 *
 * Returns:	None
 */
void
get_system_time(uuid_time_t *uuid_time)
{
	struct timeval tp;

	(void) gettimeofday(&tp, (struct timezone *)0);

	/*
	 * Offset between UUID formatted times and Unix formatted times.
	 * UUID UTC base time is October 15, 1582.
	 * Unix base time is January 1, 1970.
	 */
	*uuid_time = (uint64_t)tp.tv_sec * 10000000;
	*uuid_time += tp.tv_usec * 10;
	*uuid_time += 0x01B21DD213814000ULL;
}
