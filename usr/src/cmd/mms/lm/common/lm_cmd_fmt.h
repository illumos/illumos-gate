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

#ifndef __LM_CMD_FMT_H
#define	__LM_CMD_FMT_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	LM_UNACC_RESP "response unacceptable %s;"
#define	LM_ACC_RESP "response task [\"%s\"] accepted;"

#define	LM_TEXT_MNT "text [\"%s\" \"%s\" \"%s\" \"%s\"]"
#define	LM_TEXT_CLS "text [%s]"

#define	LM_SUC_FINAL "response task [\"%s\"] success %s %s;"
#define	LM_CANCEL_FINAL "response task [\"%s\"] cancelled %s;"
#define	LM_ERR_FINAL "response task [\"%s\"] error [%s %s] %s;"

#define	LM_MSG_PARSE "message task [\"7998\"] who [operator] \
severity [error] %s; "
#define	LM_MSG_EXIT "message task [\"7999\"] who [operator] \
severity [error] %s; "
#define	LM_MSG_CMD "message task [\"%d\"] who [\"%s\"] severity [\"%s\"] %s; "
#define	LM_DRIVEDISABLED_CMD "attribute task[\"%d\"] \
match[streq(DRIVE.\"DriveName\" \"%s\")]set[DRIVE.\"DriveDisabled\" \"%s\"]; "

#define	PRIVATE_CMD "private task [\"%d\"] %s;"
#define	PRI_GET_LIB "get [LIBRARY \"LibraryName\" LIBRARY \"LibraryType\" \
LIBRARY \"LibraryConnection\"]"
#define	PRI_GET_ACSLS "get [LIBRARY \"LibraryACS\" LIBRARY \"LibraryLSM\""\
" LM \"LMSSIPort\"]"

#define	LM_READY_R "ready task [\"%d\"];"
#define	LM_READY_N "ready task [\"%d\"] not %s;"
#define	LM_READY_D "ready task [\"%d\"] disconnected %s;"
#define	LM_READY_B "ready task [\"%d\"] broken %s;"
#define	LM_READY_P "ready task [\"%d\"] present;"

#define	LM_EVENT_CMD "notify task[\"%d\"] \
receive[\"NotifyNewDrive\" \"NotifyNewCartridge\"] \
scope[global]; "

#define	LM_SEND_CANCEL "internal \"cancel\" \"%d\";"

#define	LM_DRIVE_SERIAL "attribute task[\"%d\"] \
match[and(streq(LIBRARY.\"LibraryName\" \"%s\") \
streq(DRIVE.\"DriveGeometry\" \"%d,%d,%d,%d\"))] \
set[DRIVE.\"DriveSerialNum\" \"%s\"]; "

#define	LM_CANCEL_CMD "cancel task[\"%d\"] whichtask[\"%s\"]; "

#ifdef	__cplusplus
}
#endif

#endif /* __LM_CMD_FMT_H */
