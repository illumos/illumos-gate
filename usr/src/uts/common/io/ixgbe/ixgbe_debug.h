/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2010 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *      http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When using or redistributing this file, you may do so under the
 * License only. No other modification of this header is permitted.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2016 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef	_IXGBE_DEBUG_H
#define	_IXGBE_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif


#ifdef DEBUG
#define	IXGBE_DEBUG
#endif

#ifdef IXGBE_DEBUG

#define	IXGBE_DEBUGLOG_0(adapter, fmt)	\
	ixgbe_log((adapter), (fmt))
#define	IXGBE_DEBUGLOG_1(adapter, fmt, d1)	\
	ixgbe_log((adapter), (fmt), (d1))
#define	IXGBE_DEBUGLOG_2(adapter, fmt, d1, d2)	\
	ixgbe_log((adapter), (fmt), (d1), (d2))
#define	IXGBE_DEBUGLOG_3(adapter, fmt, d1, d2, d3)	\
	ixgbe_log((adapter), (fmt), (d1), (d2), (d3))
#define	IXGBE_DEBUGLOG_6(adapter, fmt, d1, d2, d3, d4, d5, d6)	\
	ixgbe_log((adapter), (fmt), (d1), (d2), (d3), (d4), (d5), (d6))

#else

#define	IXGBE_DEBUGLOG_0(adapter, fmt)
#define	IXGBE_DEBUGLOG_1(adapter, fmt, d1)
#define	IXGBE_DEBUGLOG_2(adapter, fmt, d1, d2)
#define	IXGBE_DEBUGLOG_3(adapter, fmt, d1, d2, d3)
#define	IXGBE_DEBUGLOG_6(adapter, fmt, d1, d2, d3, d4, d5, d6)

#endif	/* IXGBE_DEBUG */

#ifdef IXGBE_DEBUG
void ixgbe_pci_dump(void *);
void ixgbe_dump_interrupt(void *, char *);
void ixgbe_dump_addr(void *, char *, const uint8_t *);

#define	DEBUGOUT(S)	\
	IXGBE_DEBUGLOG_0(NULL, S)
#define	DEBUGOUT1(S, A)	\
	IXGBE_DEBUGLOG_1(NULL, S, A)
#define	DEBUGOUT2(S, A, B)	\
	IXGBE_DEBUGLOG_2(NULL, S, A, B)
#define	DEBUGOUT3(S, A, B, C)	\
	IXGBE_DEBUGLOG_3(NULL, S, A, B, C)
#define	DEBUGOUT6(S, A, B, C, D, E, F)	\
	IXGBE_DEBUGLOG_6(NULL, S, A, B, C, D, E, F)

#define	IXGBE_ERROR_INVALID_STATE	"INVALID STATE"
#define	IXGBE_ERROR_POLLING		"POLLING ERROR"
#define	IXGBE_ERROR_CAUTION		"CAUTION"
#define	IXGBE_ERROR_SOFTWARE		"SOFTWARE ERROR"
#define	IXGBE_ERROR_ARGUMENT		"BAD ARGUMENT"
#define	IXGBE_ERROR_UNSUPPORTED		"UNSUPPORTED"

#define	ERROR_REPORT1(S, A)		DEBUGOUT(S ":" A)
#define	ERROR_REPORT2(S, A, B)		DEBUGOUT1(S ":" A, B)
#define	ERROR_REPORT3(S, A, B, C)	DEBUGOUT2(S ":" A, B, C)

#else

#define	DEBUGOUT(S)
#define	DEBUGOUT1(S, A)
#define	DEBUGOUT2(S, A, B)
#define	DEBUGOUT3(S, A, B, C)
#define	DEBUGOUT6(S, A, B, C, D, E, F)

#define	ERROR_REPORT1(S, A)
#define	ERROR_REPORT2(S, A, B)
#define	ERROR_REPORT3(S, A, B, C)

#endif	/* IXGBE_DEBUG */

/*
 * DEBUGFUNC() is used to print the function call information, however since
 * DTrace in illumos can be used to trace function calls, this function is
 * not useful in illumos, and DEBUGFUNC() can spam a large number of
 * function call system logs (see CR6918426). We sould eliminate
 * DEBUGFUNC(), but since DEBUGFUNC() is used by the shared code
 * (maintained by Intel) which is used and shared by ixgbe drivers in
 * different OSes, we can not remove it, so in illumos just simply define
 * it as blank.
 */
#define	DEBUGFUNC(F)

extern void ixgbe_log(void *, const char *, ...);

#ifdef __cplusplus
}
#endif

#endif	/* _IXGBE_DEBUG_H */
