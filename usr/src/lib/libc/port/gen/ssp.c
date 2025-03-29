/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

#include <upanic.h>
#include <sys/random.h>

/*
 * This provides an implementation of the stack protector functions that are
 * expected by gcc's ssp implementation.
 *
 * We attempt to initialize the stack guard with random data, which is our best
 * protection. If that fails, we'd like to have a guard that is still meaningful
 * and not totally predictable. The original StackGuard paper suggests using a
 * terminator canary. To make this a little more difficult, we also use a
 * portion of the data from gethrtime().
 *
 * In a 32-bit environment, we only have four bytes worth of data. We use the
 * lower two bytes of the gethrtime() value and then use pieces of the
 * terminator canary, '\n\0'. In a 64-bit environment we use the full four byte
 * terminator canary and then four bytes of gethrtime.
 */

/*
 * Use an array here so it's easier to get the length at compile time.
 */
static const char ssp_msg[] = "*** stack smashing detected";

uintptr_t __stack_chk_guard;

void
ssp_init(void)
{
	if (getrandom(&__stack_chk_guard, sizeof (__stack_chk_guard), 0) !=
	    sizeof (__stack_chk_guard)) {
		/*
		 * This failed, attempt to get some data that might let us get
		 * off the ground.
		 */
		hrtime_t t = gethrtime();
#ifdef	_ILP32
		const uint16_t guard = '\n' << 8 | '\0';
		__stack_chk_guard = guard  << 16 | (uint16_t)t;
#else
		const uint32_t guard = '\r' << 24 | '\n' << 16 | '\0' << 8 |
		    '\xff';
		__stack_chk_guard = (uint64_t)guard << 32 | (uint32_t)t;
#endif
	}
}

void
__stack_chk_fail(void)
{
	upanic(ssp_msg, sizeof (ssp_msg));
}
