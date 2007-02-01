/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2007 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#ifndef _E1000G_DEBUG_H
#define	_E1000G_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * **********************************************************************
 *									*
 * Module Name:								*
 *   e1000g_debug.h							*
 *									*
 * Abstract:								*
 *									*
 *   This driver runs on the following hardware:			*
 *   - Wiseman based PCI gigabit ethernet adapters			*
 *									*
 * Environment:								*
 *   Kernel Mode -							*
 *									*
 * **********************************************************************
 */

/*
 * Debug message control
 * Debug Levels:
 *	0x000 - (0)   no messages
 *	0x001 - (1)   Errors
 *	0x002 - (2)   Warnings
 *	0x004 - (4)   Information
 *	0x008 - (8)   Subroutine calls and control flow
 *	0x010 - (16)  I/O Data (verbose!)
 * Speacialised Debug Levels:
 *	0x020 - (32)  Receive Debug Info
 *	0x040 - (64)  Send Debug Info
 *	0x080 - (128) Interrupt Debug Info
 *	0x100 - (256) DDI Debug Info
 * Variables can be set with entries in the /etc/system file with
 * "set e1000g:e1000g_debug=<value>"
 * "set e1000g:e1000g_debug_hw=<value>"
 * "set e1000g:e1000g_display_only=<value>"
 * "set e1000g:e1000g_print_only=<value>"
 * Alternatively, you can use adb to set variables and debug as
 * follows:
 * # adb -kw /dev/ksyms /dev/mem
 * The /etc/system file is read only once at boot time, if you change
 * it you must reboot for the change to take effect.
 *
 * It turns on diagnostics if DEBUG is defined (DEBUG also
 * enables other debugging code as ASSERT statements...
 */

#ifdef e1000g_DEBUG

static int e1000g_debug = DEFAULTDEBUGLEVEL;
static int e1000g_display_only = DEFAULTDISPLAYONLY;
static int e1000g_print_only = DEFAULTPRINTONLY;
static int e1000g_debug_hw = 1;

#define	e1000g_ERRS_LEVEL	0x001	/* (1)	Errors */
#define	e1000g_WARN_LEVEL	0x002	/* (2)	Warnings */
#define	e1000g_INFO_LEVEL	0x004	/* (4)	Information */
#define	e1000g_CALLTRACE_LEVEL	0x008	/* (8)	Subroutine calls and */
					/*	control flow */
#define	e1000g_VERBOSE_LEVEL	0x010	/* (16)	I/O Data (verbose!) */
#define	e1000g_RECV_LEVEL	0x020	/* (32)	Receive Debug Info */
#define	e1000g_SEND_LEVEL	0x040	/* (64)	Send Debug Info */
#define	e1000g_INT_LEVEL	0x080	/* (128) Interrupt Debug Info */
#define	e1000g_DDI_LEVEL	0x100	/* (256) DDI Debug Info */

#define	e1000g_DEBUGLOG_0(Adapter, Level, fmt)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt))

#define	e1000g_DEBUGLOG_1(Adapter, Level, fmt, d1)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1))

#define	e1000g_DEBUGLOG_2(Adapter, Level, fmt, d1, d2)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1), (d2))

#define	e1000g_DEBUGLOG_3(Adapter, Level, fmt, d1, d2, d3)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1),\
		(d2), (d3))

#define	e1000g_DEBUGLOG_4(Adapter, Level, fmt, d1, d2, d3, d4)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1),\
		(d2), (d3), (d4))

#define	e1000g_DEBUGLOG_5(Adapter, Level, fmt, d1, d2, d3, d4, d5)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1),\
		(d2), (d3), (d4), (d5))

#define	e1000g_HW_DEBUGLOG	if (e1000g_debug_hw) e1000g_log_hw

#else

static int e1000g_debug = 0;
static int e1000g_display_only = 1;	/* 1 - Yes Display, */
					/* 0 - Don't Display */
static int e1000g_print_only = 1;	/* 1 - Yes Print to Msg Log, */
					/* 0 - Don't Print to Msg Log */
static int e1000g_debug_hw = 0;

#define	e1000g_DEBUGLOG_0(Adapter, Level, fmt)
#define	e1000g_DEBUGLOG_1(Adapter, Level, fmt, d1)
#define	e1000g_DEBUGLOG_2(Adapter, Level, fmt, d1, d2)
#define	e1000g_DEBUGLOG_3(Adapter, Level, fmt, d1, d2, d3)
#define	e1000g_DEBUGLOG_4(Adapter, Level, fmt, d1, d2, d3, d4)
#define	e1000g_DEBUGLOG_5(Adapter, Level, fmt, d1, d2, d3, d4, d5)
#define	e1000g_HW_DEBUGLOG

#endif	/* e1000g_DEBUG */

#define	NAMELEN		31
#define	BUFSZ		256

void e1000g_log(struct e1000g *Adapter, int level, char *fmt, ...);
void e1000g_log_hw(char *msg, void *cptr, int length);

#ifdef __cplusplus
}
#endif

#endif	/* _E1000G_DEBUG_H */
