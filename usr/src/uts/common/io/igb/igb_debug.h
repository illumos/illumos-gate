/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2009 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *	http://www.opensolaris.org/os/licensing.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

#ifndef	_IGB_DEBUG_H
#define	_IGB_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif


#ifdef DEBUG
#define	IGB_DEBUG
#endif

typedef enum {
	IGB_LOG_NONE =	0,
	IGB_LOG_ERROR =	1,
	IGB_LOG_INFO =	2,
	IGB_LOG_TRACE =	4
} igb_debug_t;

#define	IGB_DEBUGLOG_0(adapter, fmt)	\
	igb_log((adapter), (IGB_LOG_INFO), (fmt))
#define	IGB_DEBUGLOG_1(adapter, fmt, d1)	\
	igb_log((adapter), (IGB_LOG_INFO), (fmt), (d1))
#define	IGB_DEBUGLOG_2(adapter, fmt, d1, d2)	\
	igb_log((adapter), (IGB_LOG_INFO), (fmt), (d1), (d2))
#define	IGB_DEBUGLOG_3(adapter, fmt, d1, d2, d3)	\
	igb_log((adapter), (IGB_LOG_INFO), (fmt), (d1), (d2), (d3))

#ifdef IGB_DEBUG
#define	IGB_DEBUGFUNC(fmt)		igb_log((NULL), (IGB_LOG_TRACE), (fmt))
#define	IGB_DEBUG_STAT_COND(val, cond)	if (cond) (val)++
#define	IGB_DEBUG_STAT(val)		(val)++
#else
#define	IGB_DEBUGFUNC(fmt)
#define	IGB_DEBUG_STAT_COND(val, cond)
#define	IGB_DEBUG_STAT(val)
#endif	/* IGB_DEBUG */

#define	IGB_STAT(val)		(val)++

#ifdef IGB_DEBUG
void pci_dump(void *);
#endif	/* IGB_DEBUG */

void igb_log(void *, igb_debug_t, const char *, ...);

#ifdef __cplusplus
}
#endif

#endif	/* _IGB_DEBUG_H */
