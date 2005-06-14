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
 *
 * Copyright 1996 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

#ifndef _MADMAN_TRAP_H_
#define _MADMAN_TRAP_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/***** GLOBAL CONSTANTS *****/


/* specific trap numbers */

#define TRAP_APPL_ALARM			1
#define TRAP_MTA_ALARM			2
#define TRAP_MSG_ALARM			3


/* alarm severity */

#define SEVERITY_LOW			1
#define SEVERITY_MEDIUM			2
#define SEVERITY_HIGH			3


/***** GLOBAL FUNCTIONS ******/

extern void send_trap_appl_status_changed(int applIndex, char *applName, int applOperStatus);
extern void send_trap_appl_alarm(int applIndex, char *applName, int alarmId, int alarmSeverity, char *alarmDescr);

extern char *alarmSeverity_string(int severity);


#endif
