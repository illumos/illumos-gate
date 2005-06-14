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
 *	rpc_trace.c
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"rpc_mt.h"
#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/time.h>
#include	<sys/fcntl.h>
#include	<rpc/trace.h>
#include	<synch.h>

#ifdef	TRACE

int rpc_trace_on = 1;

void
__rpc_trace(ev, d0, d1, d2, d3, d4, d5)
	u_long	ev, d0, d1, d2, d3, d4, d5;
{
	struct timeval	t;
	static struct trace_record	tr;
	static FILE	*fp = (FILE *) NULL;
	static time_t	last_time_written = (time_t) 0;
	extern mutex_t	libnsl_trace_lock;

	mutex_lock(&libnsl_trace_lock);
	if (! rpc_trace_on) {
		if (fp != (FILE *) NULL) {
			if (last_time_written != (time_t) 0) {
				last_time_written = (time_t) 0;
				fflush(fp);
			}
		}
		mutex_unlock(&libnsl_trace_lock);
		return;
	}

	if (fp == (FILE *) NULL) {
		fp = fopen("/tmp/rpc.trace", "w");
		if (fp == (FILE *) NULL) {
			mutex_unlock(&libnsl_trace_lock);
			return;
		}

		tr.tr_pid	= getpid();
	}

	gettimeofday(&t, NULL);
	tr.tr_time	= pack(t.tv_sec & 0xffff, (t.tv_usec >> 16) & 0xffff);
	tr.tr_tag	= ev;
	tr.tr_datum0	= d0;
	tr.tr_datum1	= d1;
	tr.tr_datum2	= d2;
	tr.tr_datum3	= d3;
	tr.tr_datum4	= d4;
	tr.tr_datum5	= d5;
	fwrite((char *) &tr, sizeof (tr), 1, fp);
	if (last_time_written < t.tv_sec) {
		last_time_written = t.tv_sec;
		fflush(fp);
	}
	mutex_unlock(&libnsl_trace_lock);
}
#endif	/* TRACE */
