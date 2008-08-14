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

#define	MMS_API_3000_MSG "message [id [\"IEEE\" \"1244\" \"3000\"] \
loctext [\"EN\" \"MMS API session pointer is set to NULL.\"]]"

#define	MMS_API_3001_MSG "message [id [\"IEEE\" \"1244\" \"3001\"] \
loctext [\"EN\" \"MMS API has encountered a previous internal processing \
error, unable to process API commands.\"]]"

#define	MMS_API_3002_MSG "message [id [\"IEEE\" \"1244\" \"3002\"] \
arguments [\"name\" \"%s\" \"errno\" \"%s\"] \
loctext [\"EN\" \"MMS API has encountered a thread lock failure of %s \
mutex, errno - %s.\"]]"

#define	MMS_API_3003_MSG "message [id [\"IEEE\" \"1244\" \"3003\"] \
arguments [\"name\" \"%s\" \"errno\" \"%s\"] \
loctext [\"EN\" \"MMS API has encountered a thread unlock failure of %s \
mutex, errno - %s.\"]]"

#define	MMS_API_3004_MSG "message [id [\"IEEE\" \"1244\" \"3004\"] \
arguments [\"name\" \"%s\" \"errno\" \"%s\"] \
loctext [\"EN\" \"MMS API has encountered a memory malloc failure for \
a new %s, errno - %s.\"]]"

#define	MMS_API_3005_MSG "message [id [\"IEEE\" \"1244\" \"3005\"] \
arguments [\"taskid\" \"%s\"] \
loctext [\"EN\" \"MMS API encountered a socket write failure trying \
to send command with task id %s to MMS.\"]]"

#define	MMS_API_3006_MSG "message [id [\"IEEE\" \"1244\" \"3006\"] \
arguments [\"taskid\" \"%s\"] \
loctext [\"EN\" \"MMS API recevied an invalid response from MMS for \
command with task id %s.\"]]"

#define	MMS_API_3007_MSG "message [id [\"IEEE\" \"1244\" \"3007\"] \
arguments [\"name\" \"%s\" \"errno\" \"%s\"] \
loctext [\"EN\" \"MMS API has encountered a broadcast failure for \
%s condition variable, errno - %s.\"]]"

#define	MMS_API_3008_MSG "message [id [\"IEEE\" \"1244\" \"3008\"] \
arguments [\"expected\" \"%s\" \"received\" \"%s\"] \
loctext [\"EN\" \"MMS API has encountered a taskid mismatch on an \
accept-unaccept response, expected - %s, received - %s.\"]]"

#define	MMS_API_3009_MSG "message [id [\"IEEE\" \"1244\" \"3009\"] \
arguments [\"name\" \"%s\" \"errno\" \"%s\"] \
loctext [\"EN\" \"MMS API has encountered a thread wait \
failure on %s condition wait variable, errno - %s.\"]]"

#define	MMS_API_3010_MSG "message [id [\"IEEE\" \"1244\" \"3010\"] \
loctext [\"EN\" \"MMS API session socket to MMS is not open.\"]]"

#define	MMS_API_3011_MSG "message [id [\"IEEE\" \"1244\" \"3011\"] \
arguments [\"errno\" \"%s\"] \
loctext [\"EN\" \"MMS API encountered a select failure on socket to MMS \
with errno - %s.\"]]"

#define	MMS_API_3012_MSG "message [id [\"IEEE\" \"1244\" \"3012\"] \
loctext [\"EN\" \"MMS API detected that MMS has disconnect from client.\"]]"

#define	MMS_API_3013_MSG "message [id [\"IEEE\" \"1244\" \"3013\"] \
loctext [\"EN\" \"MMS API encountered a response read failure.\"]]"

#define	MMS_API_3014_MSG "message [id [\"IEEE\" \"1244\" \"3014\"] \
arguments [\"part\" \"%s\"] \
loctext [\"EN\" \"MMS API encountered a missing %s in input from MMS.\"]]"

#define	MMS_API_3015_MSG "message [id [\"IEEE\" \"1244\" \"3015\"] \
arguments [\"list\" \"%s\" \"taskid\" \"%s\"] \
loctext [\"EN\" \"MMS API could not find and entry in %s with taskid %s.\"]]"

#define	MMS_API_3016_MSG "message [id [\"IEEE\" \"1244\" \"3016\"] \
loctext [\"EN\" \"MMS API async reader thread could not obtain reading \
lock.\"]]"

#define	MMS_API_3017_MSG "message [id [\"IEEE\" \"1244\" \"3017\"] \
loctext [\"EN\" \"MMS API encountered a parse error on input from MMS: \
%s.\"]]"

#define	MMS_API_3018_MSG "message [id [\"IEEE\" \"1244\" \"3018\"] \
loctext [\"EN\" \"MMS API has been told to shutdown.\"]]"

#define	MMS_API_3019_MSG "message [id [\"IEEE\" \"1244\" \"3019\"] \
loctext [\"EN\" \"MMS API session is configured in a mode that does not \
support this API command.\"]]"


#define	MMS_API_3050_MSG "message [id [\"IEEE\" \"1244\" \"3050\"] \
arguments [\"file\" \"%s\"] \
loctext [\"EN\" \"MMS API could not read clients network configuration \
file %s.\"]]"

#define	MMS_API_3051_MSG "message [id [\"IEEE\" \"1244\" \"3051\"] \
arguments [\"error\" \"%s\"] \
loctext [\"EN\" \"MMS API failed to connect to MMS due to %s error.\"]]"

#define	MMS_API_3052_MSG "message [id [\"IEEE\" \"1244\" \"3052\"] \
loctext [\"EN\" \"MMS API goodbye command failed to be sent to MMS.\"]]"


#define	MMS_API_3100_MSG "message [id [\"IEEE\" \"1244\" \"3100\"] \
loctext [\"EN\" \"MMS session is not configured to handle events in a \
asyncrhonous manner.\"]]"

#define	MMS_API_3101_MSG "message [id [\"IEEE\" \"1244\" \"3101\"] \
arguments [\"event\" \"%s\"] \
loctext [\"EN\" \"Event with %s tag is already registered with MMS.\"]]"

#define	MMS_API_3102_MSG "message [id [\"IEEE\" \"1244\" \"3102\"] \
arguments [\"type\" \"%s\" \"tag\" \"%s\"] \
loctext [\"EN\" \"MMS API received an unacceptable response for a %s notify \
command with %s tag.\"]]"

#define	MMS_API_3103_MSG "message [id [\"IEEE\" \"1244\" \"3103\"] \
loctext [\"EN\" \"MMS API received a event, but was unable to cleanly \
obtain the tag clause.\"]]"

#define	MMS_API_3104_MSG "message [id [\"IEEE\" \"1244\" \"3104\"] \
loctext [\"EN\" \"MMS API was unable to process notify command to obtain \
tag and object clauses. See API mms_trace for exact error\"]]"

#define	MMS_API_3105_MSG "message [id [\"IEEE\" \"1244\" \"3105\"] \
arguments [\"error\" \"%s\" \"tag\" \"%s\"] \
loctext [\"EN\" \"MMS API received a %s error trying to register for event \
with %s tag.\"]]"

#define	MMS_API_3106_MSG "message [id [\"IEEE\" \"1244\" \"3106\"] \
arguments [\"error\" \"%s\" \"tag\" \"%s\"] \
loctext [\"EN\" \"MMS API received a %s error trying to unregister for event \
with %s tag.\"]]"

#endif /* __MMS_API_MSG_H */
