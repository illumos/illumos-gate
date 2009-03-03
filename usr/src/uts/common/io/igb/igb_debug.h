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

#ifdef IGB_DEBUG

#define	IGB_DEBUGLOG_0(adapter, fmt)	\
	igb_log((adapter), (fmt))
#define	IGB_DEBUGLOG_1(adapter, fmt, d1)	\
	igb_log((adapter), (fmt), (d1))
#define	IGB_DEBUGLOG_2(adapter, fmt, d1, d2)	\
	igb_log((adapter), (fmt), (d1), (d2))
#define	IGB_DEBUGLOG_3(adapter, fmt, d1, d2, d3)	\
	igb_log((adapter), (fmt), (d1), (d2), (d3))

#define	IGB_DEBUG_STAT_COND(val, cond)	if (cond) (val)++
#define	IGB_DEBUG_STAT(val)		(val)++

#else

#define	IGB_DEBUGLOG_0(adapter, fmt)
#define	IGB_DEBUGLOG_1(adapter, fmt, d1)
#define	IGB_DEBUGLOG_2(adapter, fmt, d1, d2)
#define	IGB_DEBUGLOG_3(adapter, fmt, d1, d2, d3)

#define	IGB_DEBUG_STAT_COND(val, cond)
#define	IGB_DEBUG_STAT(val)

#endif	/* IGB_DEBUG */

#define	IGB_STAT(val)		(val)++

#ifdef IGB_DEBUG

void pci_dump(void *);

#endif	/* IGB_DEBUG */

extern void igb_log(void *, const char *, ...);

#ifdef __cplusplus
}
#endif

#endif	/* _IGB_DEBUG_H */
