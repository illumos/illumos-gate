/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2008 Intel Corporation. All rights reserved.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#ifndef _E1000G_DEBUG_H
#define	_E1000G_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Debug message control
 * Debug Levels:
 *	0x000 - (0)   no messages
 *	0x001 - (1)   Errors
 *	0x002 - (2)   Warnings
 *	0x004 - (4)   Information
 *	0x008 - (8)   Subroutine calls and control flow
 *	0x010 - (16)  I/O Data (verbose!)
 * Variables can be set with entries in the /etc/system file with
 *	"set e1000g:e1000g_debug=<value>"
 *	"set e1000g:e1000g_log_mode=<value>"
 * The /etc/system file is read only once at boot time, if you change
 * it you must reboot for the change to take effect.
 *
 * It turns on diagnostics if DEBUG is defined (DEBUG also
 * enables other debugging code as ASSERT statements...
 */

#include <sys/types.h>

#ifdef DEBUG
#define	E1000G_DEBUG
#endif

/*
 * By default it will print only to log
 */
#define	E1000G_LOG_DISPLAY	0x1
#define	E1000G_LOG_PRINT	0x2
#define	E1000G_LOG_ALL		0x3

#ifdef E1000G_DEBUG

#define	E1000G_ERRS_LEVEL	0x001	/* (1)	Errors */
#define	E1000G_WARN_LEVEL	0x002	/* (2)	Warnings */
#define	E1000G_INFO_LEVEL	0x004	/* (4)	Information */
#define	E1000G_TRACE_LEVEL	0x008	/* (8)	Subroutine calls */
#define	E1000G_VERBOSE_LEVEL	0x010	/* (16)	I/O Data (verbose!) */

#define	E1000G_DEBUGLOG_0(Adapter, Level, fmt)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt))

#define	E1000G_DEBUGLOG_1(Adapter, Level, fmt, d1)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1))

#define	E1000G_DEBUGLOG_2(Adapter, Level, fmt, d1, d2)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1), (d2))

#define	E1000G_DEBUGLOG_3(Adapter, Level, fmt, d1, d2, d3)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1),\
		(d2), (d3))

#define	E1000G_DEBUGLOG_4(Adapter, Level, fmt, d1, d2, d3, d4)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1),\
		(d2), (d3), (d4))

#define	E1000G_DEBUGLOG_5(Adapter, Level, fmt, d1, d2, d3, d4, d5)	\
	if (e1000g_debug) e1000g_log((Adapter), (Level), (fmt), (d1),\
		(d2), (d3), (d4), (d5))

#define	E1000G_DEBUG_STAT_COND(val, cond)	if (cond) (val)++;
#define	E1000G_DEBUG_STAT(val)			(val)++;

#else

#define	E1000G_DEBUGLOG_0(Adapter, Level, fmt)
#define	E1000G_DEBUGLOG_1(Adapter, Level, fmt, d1)
#define	E1000G_DEBUGLOG_2(Adapter, Level, fmt, d1, d2)
#define	E1000G_DEBUGLOG_3(Adapter, Level, fmt, d1, d2, d3)
#define	E1000G_DEBUGLOG_4(Adapter, Level, fmt, d1, d2, d3, d4)
#define	E1000G_DEBUGLOG_5(Adapter, Level, fmt, d1, d2, d3, d4, d5)

#define	E1000G_DEBUG_STAT_COND(val, cond)
#define	E1000G_DEBUG_STAT(val)

#endif	/* E1000G_DEBUG */

#define	NAMELEN		31
#define	BUFSZ		256

#define	E1000G_STAT(val)	(val)++;

void e1000g_log(void *, int, char *, ...);

#ifdef E1000G_DEBUG
void eeprom_dump(void *);
void phy_dump(void *);
void mac_dump(void *);
void pciconfig_dump(void *);
void pciconfig_bar(void *, uint32_t, char *);
#endif

#ifdef E1000G_DEBUG
extern int e1000g_debug;
#endif
extern int e1000g_log_mode;

#ifdef __cplusplus
}
#endif

#endif	/* _E1000G_DEBUG_H */
