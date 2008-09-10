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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef __MMS_API_MSG_H
#define	__MMS_API_MSG_H

#include <libintl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	MMS_API_MSG
#define	MMS_API_MSG(n, s)
#endif

/* API Messages 3000-3999 */

#define	MMS_API_3000_MSG 3000
MMS_API_MSG(MMS_API_3000_MSG,
	gettext("MMS API session pointer is set to NULL."))

#define	MMS_API_3001_MSG 3001
MMS_API_MSG(MMS_API_3001_MSG, gettext("MMS API has encountered a previous " \
	"internal processing error, unable to process API commands."))

#define	MMS_API_3002_MSG 3002
MMS_API_MSG(MMS_API_3002_MSG, gettext("MMS API has encountered a thread " \
	"lock failure of $name$ mutex, errno - $errno$."))

#define	MMS_API_3003_MSG 3003
MMS_API_MSG(MMS_API_3003_MSG, gettext("MMS API has encountered a thread " \
	"unlock failure of $name$ mutex, errno - $errno$."))

#define	MMS_API_3005_MSG 3005
MMS_API_MSG(MMS_API_3005_MSG, gettext("MMS API encountered a socket write " \
	"failure trying to send command with task id $taskid$ to MMS."))

#define	MMS_API_3006_MSG 3006
MMS_API_MSG(MMS_API_3006_MSG, gettext("MMS API received an invalid response " \
	"from MMS for command with task id $taskid$."))

#define	MMS_API_3008_MSG 3008
MMS_API_MSG(MMS_API_3008_MSG, gettext("MMS API has encountered a taskid " \
	"mismatch on an accept-unaccept response, expected - $expected$, " \
	"received - $received$."))

#define	MMS_API_3010_MSG 3010
MMS_API_MSG(MMS_API_3010_MSG,
	gettext("MMS API session socket to MMS is not open."))

#define	MMS_API_3011_MSG 3011
MMS_API_MSG(MMS_API_3011_MSG, gettext("MMS API encountered a select failure " \
	"on socket to MMS with errno - $errno$."))

#define	MMS_API_3012_MSG 3012
MMS_API_MSG(MMS_API_3012_MSG,
	gettext("MMS API detected that MMS has disconnect from client."))

#define	MMS_API_3013_MSG 3013
MMS_API_MSG(MMS_API_3013_MSG,
	gettext("MMS API encountered a response read failure."))

#define	MMS_API_3014_MSG 3014
MMS_API_MSG(MMS_API_3014_MSG,
	gettext("MMS API encountered a missing $part$ in input from MMS."))

#define	MMS_API_3015_MSG 3015
MMS_API_MSG(MMS_API_3015_MSG, gettext("MMS API could not find and entry in " \
	"$list$ with taskid $taskid$."))

#define	MMS_API_3017_MSG 3017
MMS_API_MSG(MMS_API_3017_MSG, gettext("MMS API encountered a parse error on " \
	"input from MMS: $errmsg$."))

#define	MMS_API_3018_MSG 3018
MMS_API_MSG(MMS_API_3018_MSG, gettext("MMS API has been told to shutdown."))

#define	MMS_API_3019_MSG 3019
MMS_API_MSG(MMS_API_3019_MSG, gettext("MMS API session is configured in a " \
	"mode that does not support this API command."))

#define	MMS_API_3051_MSG 3051
MMS_API_MSG(MMS_API_3051_MSG,
	gettext("MMS API failed to connect to MMS due to $error$ error."))

#define	MMS_API_3052_MSG 3052
MMS_API_MSG(MMS_API_3052_MSG,
	gettext("MMS API goodbye command failed to be sent to MMS."))

#ifdef	__cplusplus
}
#endif

#endif /* __MMS_API_MSG_H */
