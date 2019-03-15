/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smbfs_subr.c,v 1.18 2005/02/02 00:22:23 lindak Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Time conversion functions (to/from DOS, NT times)
 * From BSD/Darwin smbfs_subr.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/sunddi.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>

/*
 * Number of seconds between 1970 and 1601 year
 * (134774 days)
 */
const uint64_t DIFF1970TO1601 = 11644473600ULL;
const uint32_t TEN_MIL = 10000000UL;

/*
 * Convert NT time (tenths of microseconds since 1601)
 * to Unix seconds+nanoseconds since 1970.  Any time
 * earlier than 1970 is converted to Unix time zero.
 * Both are GMT-based (no time zone adjustments).
 */
void
smb_time_NT2local(uint64_t nt_time, struct timespec *tsp)
{
	uint64_t nt_sec;	/* seconds */
	uint64_t nt_tus;	/* tenths of uSec. */

	/* Optimize time zero. */
	if (nt_time == 0) {
		tsp->tv_sec = 0;
		tsp->tv_nsec = 0;
		return;
	}

	nt_sec = nt_time / TEN_MIL;
	nt_tus = nt_time % TEN_MIL;

	if (nt_sec <= DIFF1970TO1601) {
		tsp->tv_sec = 0;
		tsp->tv_nsec = 0;
		return;
	}
	tsp->tv_sec = nt_sec - DIFF1970TO1601;
	tsp->tv_nsec = nt_tus * 100;
}

/*
 * Convert Unix time (seconds+nanoseconds since 1970)
 * to NT time (tenths of microseconds since 1601).
 * Exception: Convert time zero (really any time in
 * the first second of 1970) to NT time zero.
 * Both are GMT-based (no time zone adjustments).
 */
void
smb_time_local2NT(struct timespec *tsp, uint64_t *nt_time)
{
	uint64_t nt_sec;	/* seconds */
	uint64_t nt_tus;	/* tenths of uSec. */

	if (tsp->tv_sec == 0) {
		*nt_time = 0;
		return;
	}

	nt_sec = tsp->tv_sec + DIFF1970TO1601;
	nt_tus = tsp->tv_nsec / 100;

	*nt_time = (uint64_t)nt_sec * TEN_MIL + nt_tus;
}

/*
 * Time zone conversion stuff, only used in old dialects.
 * Don't adjust time zero for either conversion.
 */
void
smb_time_local2server(struct timespec *tsp, int tzoff, long *seconds)
{
	if (tsp->tv_sec <= (tzoff * 60))
		*seconds = 0;
	else
		*seconds = tsp->tv_sec - (tzoff * 60);
}

void
smb_time_server2local(ulong_t seconds, int tzoff, struct timespec *tsp)
{
	if (seconds == 0)
		tsp->tv_sec = 0;
	else
		tsp->tv_sec = seconds + tzoff * 60;
	tsp->tv_nsec = 0;
}
