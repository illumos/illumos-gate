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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_debug.h
 *
 * PURPOSE: defines common deuggging flags & data for the DAPL reference
 * implemenation
 *
 * Description:
 *
 *
 * $Id: dapl_debug.h,v 1.4 2003/07/31 13:55:18 hobie16 Exp $
 */

#ifndef _DAPL_DEBUG_H_
#define	_DAPL_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Debug level switches
 *
 * Use these bits to enable various tracing/debug options. Each bit
 * represents debugging in a particular subsystem or area of the code.
 *
 * The ERR bit should always be on unless someone disables it for a
 * reason: The ERR flag is used sparingly and will print useful
 * information if it fires.
 */
typedef enum
{
	DAPL_DBG_TYPE_ERR		= 0x0001,
	DAPL_DBG_TYPE_WARN		= 0x0002,
	DAPL_DBG_TYPE_EVD		= 0x0004,
	DAPL_DBG_TYPE_CM		= 0x0008,
	DAPL_DBG_TYPE_EP		= 0x0010,
	DAPL_DBG_TYPE_UTIL		= 0x0020,
	DAPL_DBG_TYPE_CALLBACK		= 0x0040,
	DAPL_DBG_TYPE_DTO_COMP_ERR	= 0x0080,
	DAPL_DBG_TYPE_API		= 0x0100,
	DAPL_DBG_TYPE_RTN		= 0x0200,
	DAPL_DBG_TYPE_EXCEPTION		= 0x0400
} DAPL_DBG_TYPE;

typedef enum
{
    DAPL_DBG_DEST_STDOUT  	= 0x0001,
    DAPL_DBG_DEST_SYSLOG  	= 0x0002
} DAPL_DBG_DEST;


extern void dapl_internal_dbg_log(DAPL_DBG_TYPE type, const char *fmt,  ...);
#if defined(DAPL_DBG)

extern DAPL_DBG_TYPE 	g_dapl_dbg_type;
extern DAPL_DBG_DEST 	g_dapl_dbg_dest;

#define	dapl_dbg_log	g_dapl_dbg_type == 0 ? (void) 1 : dapl_internal_dbg_log

#else  /* !DAPL_DBG */

#define	dapl_dbg_log	if (0) dapl_internal_dbg_log

#endif /* !DAPL_DBG */

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_DEBUG_H_ */
