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
 */
/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "snmp_msg.h"
#include "madman_api.h"

/***** GLOBAL VARIABLES *****/

/* SMTP */

static Subid smtp_subids[] = { 1, 3, 6, 1, 2, 1, 27, 4, 25 };
Oid smtp_name = { smtp_subids, 9 };
char smtp_string[] = "1.3.6.1.2.1.27.4.25";

/* P1 */

static Subid id_ac_mts_transfer_subids[] = { 2, 6, 0, 1, 6 };
Oid id_ac_mts_transfer_name = { id_ac_mts_transfer_subids, 5 };
char id_ac_mts_transfer_string[] = "2.6.0.1.6";


/* P3 */

static Subid id_ac_mts_access_subids[] = { 2, 6, 0, 1, 0 };
Oid id_ac_mts_access_name = { id_ac_mts_access_subids, 5 };

static Subid id_ac_mts_forced_access_subids[] = { 2, 6, 0, 1, 1 };
Oid id_ac_mts_forced_access_name = { id_ac_mts_forced_access_subids, 5 };

static Subid id_ac_mts_reliable_access_subids[] = { 2, 6, 0, 1, 2 };
Oid id_ac_mts_reliable_access_name = { id_ac_mts_reliable_access_subids, 5 };

static Subid id_ac_mts_forced_reliable_access_subids[] = { 2, 6, 0, 1, 3 };
Oid id_ac_mts_forced_reliable_access_name = { id_ac_mts_forced_reliable_access_subids, 5 };


/* P7 */

static Subid id_ac_ms_access_subids[] = { 2, 6, 0, 1, 4 };
Oid id_ac_ms_access_name = { id_ac_ms_access_subids, 5 };

static Subid id_ac_ms_reliable_access_subids[] = { 2, 6, 0, 1, 5 };
Oid id_ac_ms_reliable_access_name = { id_ac_ms_reliable_access_subids, 5 };


/***** LOCAL CONSTANTS *****/

#define MAX_LABEL_LEN		50
#define MAX_COLUMNS		30

#define TO_INTEGER		1
#define TO_STRING		2
#define TO_ASCII		3
#define TO_OID			4


/***** LOCAL TYPES *****/

typedef struct _SNMP_object {
	char label[MAX_LABEL_LEN + 1];
	Oid *name;
	u_char type;
	int translator;
} SNMP_object;

typedef struct _SNMP_column {
	char label[MAX_LABEL_LEN + 1];
	Oid *name;
	u_char type;
	int translator;
} SNMP_column;

typedef struct _SNMP_table {
	int column_num;
	SNMP_column *columns[MAX_COLUMNS];
} SNMP_table;


/***** LOCAL VARIABLES *****/


/**********/
/* MIB II */
/**********/

static Subid sysUpTime_subids[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
static Oid sysUpTime_name = { sysUpTime_subids, 9 };

static SNMP_object sysUpTime_object
	= { "syUpTime", &sysUpTime_name, TIMETICKS, TO_INTEGER };


/************/
/* RFC 1565 */
/************/

static Subid applName_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 2 };
static Oid applName_name = { applName_subids, 10 };

static Subid applDirectoryName_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 3 };
static Oid applDirectoryName_name = { applDirectoryName_subids, 10 };

static Subid applVersion_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 4 };
static Oid applVersion_name = { applVersion_subids, 10 };

static Subid applUptime_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 5 };
static Oid applUptime_name = { applUptime_subids, 10 };

static Subid applOperStatus_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 6 };
static Oid applOperStatus_name = { applOperStatus_subids, 10 };

static Subid applLastChange_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 7 };
static Oid applLastChange_name = { applLastChange_subids, 10 };

static Subid applInboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 8 };
static Oid applInboundAssociations_name = { applInboundAssociations_subids, 10 };

static Subid applOutboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 9 };
static Oid applOutboundAssociations_name = { applOutboundAssociations_subids, 10 };

static Subid applAccumulatedInboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 10 };
static Oid applAccumulatedInboundAssociations_name = { applAccumulatedInboundAssociations_subids, 10 };

static Subid applAccumulatedOutboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 11 };
static Oid applAccumulatedOutboundAssociations_name = { applAccumulatedOutboundAssociations_subids, 10 };

static Subid applLastInboundActivity_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 12 };
static Oid applLastInboundActivity_name = { applLastInboundActivity_subids, 10 };

static Subid applLastOutboundActivity_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 13 };
static Oid applLastOutboundActivity_name = { applLastOutboundActivity_subids, 10 };

static Subid applRejectedInboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 14 };
static Oid applRejectedInboundAssociations_name = { applRejectedInboundAssociations_subids, 10 };

static Subid applFailedOutboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 27, 1, 1, 15 };
static Oid applFailedOutboundAssociations_name = { applFailedOutboundAssociations_subids, 10 };


static SNMP_column applName_column
	= { "applName", &applName_name, STRING, TO_ASCII };
static SNMP_column applDirectoryName_column
	= { "applDirecoryName", &applDirectoryName_name, STRING, TO_ASCII };
static SNMP_column applVersion_column
	= { "applVersion", &applVersion_name, STRING, TO_ASCII };
static SNMP_column applUptime_column
	= { "applUptime", &applUptime_name, TIMETICKS, TO_INTEGER };
static SNMP_column applOperStatus_column
	= { "applOperStatus", &applOperStatus_name, INTEGER, TO_INTEGER };
static SNMP_column applLastChange_column
	= { "applLastChange", &applLastChange_name, TIMETICKS, TO_INTEGER };
static SNMP_column applInboundAssociations_column
	= { "applInboundAssociations", &applInboundAssociations_name, GAUGE, TO_INTEGER };
static SNMP_column applOutboundAssociations_column
	= { "applOutboundAssociations", &applOutboundAssociations_name, GAUGE, TO_INTEGER };
static SNMP_column applAccumulatedInboundAssociations_column
	= { "applAccumulatedInboundAssociations", &applAccumulatedInboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column applAccumulatedOutboundAssociations_column
	= { "applAccumulatedOutboundAssociations", &applAccumulatedOutboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column applLastInboundActivity_column
	= { "applLastInboundActivity", &applLastInboundActivity_name, TIMETICKS, TO_INTEGER };
static SNMP_column applLastOutboundActivity_column
	= { "applLastOutboundActivity", &applLastOutboundActivity_name, TIMETICKS, TO_INTEGER };
static SNMP_column applRejectedInboundAssociations_column
	= { "applRejectedInboundAssociations", &applRejectedInboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column applFailedOutboundAssociations_column
	= { "applFailedOutboundAssociations", &applFailedOutboundAssociations_name, COUNTER, TO_INTEGER };

static SNMP_table applTable = {
	14,
	{
		&applName_column,
		&applDirectoryName_column,
		&applVersion_column,
		&applUptime_column,
		&applOperStatus_column,
		&applLastChange_column,
		&applInboundAssociations_column,
		&applOutboundAssociations_column,
		&applAccumulatedInboundAssociations_column,
		&applAccumulatedOutboundAssociations_column,
		&applLastInboundActivity_column,
		&applLastOutboundActivity_column,
		&applRejectedInboundAssociations_column,
		&applFailedOutboundAssociations_column
	}
};


static Subid assocRemoteApplication_subids[] = { 1, 3, 6, 1, 2, 1, 27, 2, 1, 2 };
static Oid assocRemoteApplication_name = { assocRemoteApplication_subids, 10 };

static Subid assocApplicationProtocol_subids[] = { 1, 3, 6, 1, 2, 1, 27, 2, 1, 3 };
static Oid assocApplicationProtocol_name = { assocApplicationProtocol_subids, 10 };

static Subid assocApplicationType_subids[] = { 1, 3, 6, 1, 2, 1, 27, 2, 1, 4 };
static Oid assocApplicationType_name = { assocApplicationType_subids, 10 };

static Subid assocDuration_subids[] = { 1, 3, 6, 1, 2, 1, 27, 2, 1, 5 };
static Oid assocDuration_name = { assocDuration_subids, 10 };

static SNMP_column assocRemoteApplication_column
	= { "assocRemoteApplication", &assocRemoteApplication_name, STRING, TO_ASCII };
static SNMP_column assocApplicationProtocol_column
	= { "assocApplicationProtocol", &assocApplicationProtocol_name, OBJID, TO_OID };
static SNMP_column assocApplicationType_column
	= { "assocApplicationType", &assocApplicationType_name, INTEGER, TO_INTEGER };
static SNMP_column assocDuration_column
	= { "assocDuration", &assocDuration_name, TIMETICKS, TO_INTEGER };

static SNMP_table assocTable = {
	4,
	{
		&assocRemoteApplication_column,
		&assocApplicationProtocol_column,
		&assocApplicationType_column,
		&assocDuration_column,
	}
};


/************/
/* RFC 1566 */
/************/

static Subid mtaReceivedMessages_subids[] = { 1, 3, 6, 1, 2, 1, 28, 1, 1, 1 };
static Oid mtaReceivedMessages_name = { mtaReceivedMessages_subids, 10 };

static Subid mtaStoredMessages_subids[] = { 1, 3, 6, 1, 2, 1, 28, 1, 1, 2 };
static Oid mtaStoredMessages_name = { mtaStoredMessages_subids, 10 };

static Subid mtaTransmittedMessages_subids[] = { 1, 3, 6, 1, 2, 1, 28, 1, 1, 3 };
static Oid mtaTransmittedMessages_name = { mtaTransmittedMessages_subids, 10 };

static Subid mtaReceivedVolume_subids[] = { 1, 3, 6, 1, 2, 1, 28, 1, 1, 4 };
static Oid mtaReceivedVolume_name = { mtaReceivedVolume_subids, 10 };

static Subid mtaStoredVolume_subids[] = { 1, 3, 6, 1, 2, 1, 28, 1, 1, 5 };
static Oid mtaStoredVolume_name = { mtaStoredVolume_subids, 10 };

static Subid mtaTransmittedVolume_subids[] = { 1, 3, 6, 1, 2, 1, 28, 1, 1, 6 };
static Oid mtaTransmittedVolume_name = { mtaTransmittedVolume_subids, 10 };

static Subid mtaReceivedRecipients_subids[] = { 1, 3, 6, 1, 2, 1, 28, 1, 1, 7 };
static Oid mtaReceivedRecipients_name = { mtaReceivedRecipients_subids, 10 };

static Subid mtaStoredRecipients_subids[] = { 1, 3, 6, 1, 2, 1, 28, 1, 1, 8 };
static Oid mtaStoredRecipients_name = { mtaStoredRecipients_subids, 10 };

static Subid mtaTransmittedRecipients_subids[] = { 1, 3, 6, 1, 2, 1, 28, 1, 1, 9 };
static Oid mtaTransmittedRecipients_name = { mtaTransmittedRecipients_subids, 10 };

static SNMP_column mtaReceivedMessages_column
	= { "mtaReceivedMessages", &mtaReceivedMessages_name, COUNTER, TO_INTEGER };
static SNMP_column mtaStoredMessages_column
	= { "mtaStoredMessages", &mtaStoredMessages_name, GAUGE, TO_INTEGER };
static SNMP_column mtaTransmittedMessages_column
	= { "mtaTransmittedMessages", &mtaTransmittedMessages_name, COUNTER, TO_INTEGER };
static SNMP_column mtaReceivedVolume_column
	= { "mtaReceivedVolume", &mtaReceivedVolume_name, COUNTER, TO_INTEGER };
static SNMP_column mtaStoredVolume_column
	= { "mtaStoredVolume", &mtaStoredVolume_name, GAUGE, TO_INTEGER };
static SNMP_column mtaTransmittedVolume_column
	= { "mtaTransmittedVolume", &mtaTransmittedVolume_name, COUNTER, TO_INTEGER };
static SNMP_column mtaReceivedRecipients_column
	= { "mtaReceivedRecipients", &mtaReceivedRecipients_name, COUNTER, TO_INTEGER };
static SNMP_column mtaStoredRecipients_column
	= { "mtaStoredRecipients", &mtaStoredRecipients_name, GAUGE, TO_INTEGER };
static SNMP_column mtaTransmittedRecipients_column
	= { "mtaTransmittedRecipients", &mtaTransmittedRecipients_name, COUNTER, TO_INTEGER };

static SNMP_table mtaTable = {
	9,
	{
		&mtaReceivedMessages_column,
		&mtaStoredMessages_column,
		&mtaTransmittedMessages_column,
		&mtaReceivedVolume_column,
		&mtaStoredVolume_column,
		&mtaTransmittedVolume_column,
		&mtaReceivedRecipients_column,
		&mtaStoredRecipients_column,
		&mtaTransmittedRecipients_column
	}
};


static Subid mtaGroupReceivedMessages_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 2 };
static Oid mtaGroupReceivedMessages_name = { mtaGroupReceivedMessages_subids, 10 };

static Subid mtaGroupRejectedMessages_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 3 };
static Oid mtaGroupRejectedMessages_name = { mtaGroupRejectedMessages_subids, 10 };

static Subid mtaGroupStoredMessages_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 4 };
static Oid mtaGroupStoredMessages_name = { mtaGroupStoredMessages_subids, 10 };

static Subid mtaGroupTransmittedMessages_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 5 };
static Oid mtaGroupTransmittedMessages_name = { mtaGroupTransmittedMessages_subids, 10 };

static Subid mtaGroupReceivedVolume_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 6 };
static Oid mtaGroupReceivedVolume_name = { mtaGroupReceivedVolume_subids, 10 };

static Subid mtaGroupStoredVolume_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 7 };
static Oid mtaGroupStoredVolume_name = { mtaGroupStoredVolume_subids, 10 };

static Subid mtaGroupTransmittedVolume_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 8 };
static Oid mtaGroupTransmittedVolume_name = { mtaGroupTransmittedVolume_subids, 10 };

static Subid mtaGroupReceivedRecipients_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 9 };
static Oid mtaGroupReceivedRecipients_name = { mtaGroupReceivedRecipients_subids, 10 };

static Subid mtaGroupStoredRecipients_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 10 };
static Oid mtaGroupStoredRecipients_name = { mtaGroupStoredRecipients_subids, 10 };

static Subid mtaGroupTransmittedRecipients_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 11 };
static Oid mtaGroupTransmittedRecipients_name = { mtaGroupTransmittedRecipients_subids, 10 };

static Subid mtaGroupOldestMessageStored_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 12 };
static Oid mtaGroupOldestMessageStored_name = { mtaGroupOldestMessageStored_subids, 10 };

static Subid mtaGroupInboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 13 };
static Oid mtaGroupInboundAssociations_name = { mtaGroupInboundAssociations_subids, 10 };

static Subid mtaGroupOutboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 14 };
static Oid mtaGroupOutboundAssociations_name = { mtaGroupOutboundAssociations_subids, 10 };

static Subid mtaGroupAccumulatedInboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 15 };
static Oid mtaGroupAccumulatedInboundAssociations_name = { mtaGroupAccumulatedInboundAssociations_subids, 10 };

static Subid mtaGroupAccumulatedOutboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 16 };
static Oid mtaGroupAccumulatedOutboundAssociations_name = { mtaGroupAccumulatedOutboundAssociations_subids, 10 };

static Subid mtaGroupLastInboundActivity_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 17 };
static Oid mtaGroupLastInboundActivity_name = { mtaGroupLastInboundActivity_subids, 10 };

static Subid mtaGroupLastOutboundActivity_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 18 };
static Oid mtaGroupLastOutboundActivity_name = { mtaGroupLastOutboundActivity_subids, 10 };

static Subid mtaGroupRejectedInboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 19 };
static Oid mtaGroupRejectedInboundAssociations_name = { mtaGroupRejectedInboundAssociations_subids, 10 };

static Subid mtaGroupFailedOutboundAssociations_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 20 };
static Oid mtaGroupFailedOutboundAssociations_name = { mtaGroupFailedOutboundAssociations_subids, 10 };

static Subid mtaGroupInboundRejectionReason_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 21 };
static Oid mtaGroupInboundRejectionReason_name = { mtaGroupInboundRejectionReason_subids, 10 };

static Subid mtaGroupOutboundConnectFailureReason_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 22 };
static Oid mtaGroupOutboundConnectFailureReason_name = { mtaGroupOutboundConnectFailureReason_subids, 10 };

static Subid mtaGroupScheduledRetry_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 23 };
static Oid mtaGroupScheduledRetry_name = { mtaGroupScheduledRetry_subids, 10 };

static Subid mtaGroupMailProtocol_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 24 };
static Oid mtaGroupMailProtocol_name = { mtaGroupMailProtocol_subids, 10 };

static Subid mtaGroupName_subids[] = { 1, 3, 6, 1, 2, 1, 28, 2, 1, 25 };
static Oid mtaGroupName_name = { mtaGroupName_subids, 10 };

static SNMP_column mtaGroupReceivedMessages_column
	= { "mtaGroupReceivedMessages", &mtaGroupReceivedMessages_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupRejectedMessages_column
	= { "mtaGroupRejectedMessages", &mtaGroupRejectedMessages_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupStoredMessages_column
	= { "mtaGroupStoredMessages", &mtaGroupStoredMessages_name, GAUGE, TO_INTEGER };
static SNMP_column mtaGroupTransmittedMessages_column
	= { "mtaGroupTransmittedMessages", &mtaGroupTransmittedMessages_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupReceivedVolume_column
	= { "mtaGroupReceivedVolume", &mtaGroupReceivedVolume_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupStoredVolume_column
	= { "mtaGroupStoredVolume", &mtaGroupStoredVolume_name, GAUGE, TO_INTEGER };
static SNMP_column mtaGroupTransmittedVolume_column
	= { "mtaGroupTransmittedVolume", &mtaGroupTransmittedVolume_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupReceivedRecipients_column
	= { "mtaGroupReceivedRecipients", &mtaGroupReceivedRecipients_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupStoredRecipients_column
	= { "mtaGroupStoredRecipients", &mtaGroupStoredRecipients_name, GAUGE, TO_INTEGER };
static SNMP_column mtaGroupTransmittedRecipients_column
	= { "mtaGroupTransmittedRecipients", &mtaGroupTransmittedRecipients_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupOldestMessageStored_column
	= { "mtaGroupOldestMessageStored", &mtaGroupOldestMessageStored_name, INTEGER, TO_INTEGER };
static SNMP_column mtaGroupInboundAssociations_column
	= { "mtaGroupInboundAssociations", &mtaGroupInboundAssociations_name, GAUGE, TO_INTEGER };
static SNMP_column mtaGroupOutboundAssociations_column
	= { "mtaGroupOutboundAssociations", &mtaGroupOutboundAssociations_name, GAUGE, TO_INTEGER };
static SNMP_column mtaGroupAccumulatedInboundAssociations_column
	= { "mtaGroupAccumulatedInboundAssociations", &mtaGroupAccumulatedInboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupAccumulatedOutboundAssociations_column
	= { "mtaGroupAccumulatedOutboundAssociations", &mtaGroupAccumulatedOutboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupLastInboundActivity_column
	= { "mtaGroupLastInboundActivity", &mtaGroupLastInboundActivity_name, INTEGER, TO_INTEGER };
static SNMP_column mtaGroupLastOutboundActivity_column
	= { "mtaGroupLastOutboundActivity", &mtaGroupLastOutboundActivity_name, INTEGER, TO_INTEGER };
static SNMP_column mtaGroupRejectedInboundAssociations_column
	= { "mtaGroupRejectedInboundAssociations", &mtaGroupRejectedInboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupFailedOutboundAssociations_column
	= { "mtaGroupFailedOutboundAssociations", &mtaGroupFailedOutboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column mtaGroupInboundRejectionReason_column
	= { "mtaGroupInboundRejectionReason", &mtaGroupInboundRejectionReason_name, STRING, TO_ASCII };
static SNMP_column mtaGroupOutboundConnectFailureReason_column
	= { "mtaGroupOutboundConnectFailureReason", &mtaGroupOutboundConnectFailureReason_name, STRING, TO_ASCII };
static SNMP_column mtaGroupScheduledRetry_column
	= { "mtaGroupScheduledRetry", &mtaGroupScheduledRetry_name, INTEGER, TO_INTEGER };
static SNMP_column mtaGroupMailProtocol_column
	= { "mtaGroupMailProtocol", &mtaGroupMailProtocol_name, OBJID, TO_OID };
static SNMP_column mtaGroupName_column
	= { "mtaGroupName", &mtaGroupName_name, STRING, TO_ASCII };


static SNMP_table mtaGroupTable = {
	24,
	{
		&mtaGroupReceivedMessages_column,
		&mtaGroupRejectedMessages_column,
		&mtaGroupStoredMessages_column,
		&mtaGroupTransmittedMessages_column,
		&mtaGroupReceivedVolume_column,
		&mtaGroupStoredVolume_column,
		&mtaGroupTransmittedVolume_column,
		&mtaGroupReceivedRecipients_column,
		&mtaGroupStoredRecipients_column,
		&mtaGroupTransmittedRecipients_column,
		&mtaGroupOldestMessageStored_column,
		&mtaGroupInboundAssociations_column,
		&mtaGroupOutboundAssociations_column,
		&mtaGroupAccumulatedInboundAssociations_column,
		&mtaGroupAccumulatedOutboundAssociations_column,
		&mtaGroupLastInboundActivity_column,
		&mtaGroupLastOutboundActivity_column,
		&mtaGroupRejectedInboundAssociations_column,
		&mtaGroupFailedOutboundAssociations_column,
		&mtaGroupInboundRejectionReason_column,
		&mtaGroupOutboundConnectFailureReason_column,
		&mtaGroupScheduledRetry_column,
		&mtaGroupMailProtocol_column,
		&mtaGroupName_column
	}
};


static Subid mtaGroupAssociationIndex_subids[] = { 1, 3, 6, 1, 2, 1, 28, 3, 1, 1 };
static Oid mtaGroupAssociationIndex_name = { mtaGroupAssociationIndex_subids, 10 };

static SNMP_column mtaGroupAssociationIndex_column
	= { "mtaGroupAssociationIndex", &mtaGroupAssociationIndex_name, INTEGER, TO_INTEGER };

static SNMP_table mtaGroupAssociationTable = {
	1,
	{
		&mtaGroupAssociationIndex_column
	}
};


/************/
/* RFC 1567 */
/************/

static Subid dsaAnonymousBinds_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 1 };
static Oid dsaAnonymousBinds_name = { dsaAnonymousBinds_subids, 10 };
static Subid dsaUnauthBinds_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 2 };
static Oid dsaUnauthBinds_name = { dsaUnauthBinds_subids, 10 };
static Subid dsaSimpleAuthBinds_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 3 };
static Oid dsaSimpleAuthBinds_name = { dsaSimpleAuthBinds_subids, 10 };
static Subid dsaStrongAuthBinds_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 4 };
static Oid dsaStrongAuthBinds_name = { dsaStrongAuthBinds_subids, 10 };
static Subid dsaBindSecurityErrors_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 5 };
static Oid dsaBindSecurityErrors_name = { dsaBindSecurityErrors_subids, 10 };
static Subid dsaInOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 6 };
static Oid dsaInOps_name = { dsaInOps_subids, 10 };
static Subid dsaReadOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 7 };
static Oid dsaReadOps_name = { dsaReadOps_subids, 10 };
static Subid dsaCompareOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 8 };
static Oid dsaCompareOps_name = { dsaCompareOps_subids, 10 };
static Subid dsaAddEntryOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 9 };
static Oid dsaAddEntryOps_name = { dsaAddEntryOps_subids, 10 };
static Subid dsaRemoveEntryOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 10 };
static Oid dsaRemoveEntryOps_name = { dsaRemoveEntryOps_subids, 10 };
static Subid dsaModifyEntryOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 11 };
static Oid dsaModifyEntryOps_name = { dsaModifyEntryOps_subids, 10 };
static Subid dsaModifyRDNOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 12 };
static Oid dsaModifyRDNOps_name = { dsaModifyRDNOps_subids, 10 };
static Subid dsaListOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 13 };
static Oid dsaListOps_name = { dsaListOps_subids, 10 };
static Subid dsaSearchOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 14 };
static Oid dsaSearchOps_name = { dsaSearchOps_subids, 10 };
static Subid dsaOneLevelSearchOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 15 };
static Oid dsaOneLevelSearchOps_name = { dsaOneLevelSearchOps_subids, 10 };
static Subid dsaWholeTreeSearchOps_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 16 };
static Oid dsaWholeTreeSearchOps_name = { dsaWholeTreeSearchOps_subids, 10 };
static Subid dsaReferrals_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 17 };
static Oid dsaReferrals_name = { dsaReferrals_subids, 10 };
static Subid dsaChainings_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 18 };
static Oid dsaChainings_name = { dsaChainings_subids, 10 };
static Subid dsaSecurityErrors_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 19 };
static Oid dsaSecurityErrors_name = { dsaSecurityErrors_subids, 10 };
static Subid dsaErrors_subids[] = { 1, 3, 6, 1, 2, 1, 29, 1, 1, 20 };
static Oid dsaErrors_name = { dsaErrors_subids, 10 };

static SNMP_column dsaAnonymousBinds_column
	= { "dsaAnonymousBinds", &dsaAnonymousBinds_name, COUNTER, TO_INTEGER };
static SNMP_column dsaUnauthBinds_column
	= { "dsaUnauthBinds", &dsaUnauthBinds_name, COUNTER, TO_INTEGER };
static SNMP_column dsaSimpleAuthBinds_column
	= { "dsaSimpleAuthBinds", &dsaSimpleAuthBinds_name, COUNTER, TO_INTEGER };
static SNMP_column dsaStrongAuthBinds_column
	= { "dsaStrongAuthBinds", &dsaStrongAuthBinds_name, COUNTER, TO_INTEGER };
static SNMP_column dsaBindSecurityErrors_column
	= { "dsaBindSecurityErrors", &dsaBindSecurityErrors_name, COUNTER, TO_INTEGER };
static SNMP_column dsaInOps_column
	= { "dsaInOps", &dsaInOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaReadOps_column
	= { "dsaReadOps", &dsaReadOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaCompareOps_column
	= { "dsaCompareOps", &dsaCompareOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaAddEntryOps_column
	= { "dsaAddEntryOps", &dsaAddEntryOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaRemoveEntryOps_column
	= { "dsaRemoveEntryOps", &dsaRemoveEntryOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaModifyEntryOps_column
	= { "dsaModifyEntryOps", &dsaModifyEntryOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaModifyRDNOps_column
	= { "dsaModifyRDNOps", &dsaModifyRDNOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaListOps_column
	= { "dsaListOps", &dsaListOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaSearchOps_column
	= { "dsaSearchOps", &dsaSearchOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaOneLevelSearchOps_column
	= { "dsaOneLevelSearchOps", &dsaOneLevelSearchOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaWholeTreeSearchOps_column
	= { "dsaWholeTreeSearchOps", &dsaWholeTreeSearchOps_name, COUNTER, TO_INTEGER };
static SNMP_column dsaReferrals_column
	= { "dsaReferrals", &dsaReferrals_name, COUNTER, TO_INTEGER };
static SNMP_column dsaChainings_column
	= { "dsaChainings", &dsaChainings_name, COUNTER, TO_INTEGER };
static SNMP_column dsaSecurityErrors_column
	= { "dsaSecurityErrors", &dsaSecurityErrors_name, COUNTER, TO_INTEGER };
static SNMP_column dsaErrors_column
	= { "dsaErrors", &dsaErrors_name, COUNTER, TO_INTEGER };

static SNMP_table dsaOpsTable = {
	20,
	{
		&dsaAnonymousBinds_column,
		&dsaUnauthBinds_column,
		&dsaSimpleAuthBinds_column,
		&dsaStrongAuthBinds_column,
		&dsaBindSecurityErrors_column,
		&dsaInOps_column,
		&dsaReadOps_column,
		&dsaCompareOps_column,
		&dsaAddEntryOps_column,
		&dsaRemoveEntryOps_column,
		&dsaModifyEntryOps_column,
		&dsaModifyRDNOps_column,
		&dsaListOps_column,
		&dsaSearchOps_column,
		&dsaOneLevelSearchOps_column,
		&dsaWholeTreeSearchOps_column,
		&dsaReferrals_column,
		&dsaChainings_column,
		&dsaSecurityErrors_column,
		&dsaErrors_column
	}
};


static Subid dsaMasterEntries_subids[] = { 1, 3, 6, 1, 2, 1, 29, 2, 1, 1 };
static Oid dsaMasterEntries_name = { dsaMasterEntries_subids, 10 };
static Subid dsaCopyEntries_subids[] = { 1, 3, 6, 1, 2, 1, 29, 2, 1, 2 };
static Oid dsaCopyEntries_name = { dsaCopyEntries_subids, 10 };
static Subid dsaCacheEntries_subids[] = { 1, 3, 6, 1, 2, 1, 29, 2, 1, 3 };
static Oid dsaCacheEntries_name = { dsaCacheEntries_subids, 10 };
static Subid dsaCacheHits_subids[] = { 1, 3, 6, 1, 2, 1, 29, 2, 1, 4 };
static Oid dsaCacheHits_name = { dsaCacheHits_subids, 10 };
static Subid dsaSlaveHits_subids[] = { 1, 3, 6, 1, 2, 1, 29, 2, 1, 5 };
static Oid dsaSlaveHits_name = { dsaSlaveHits_subids, 10 };

static SNMP_column dsaMasterEntries_column
	= { "dsaMasterEntries", &dsaMasterEntries_name, GAUGE, TO_INTEGER };
static SNMP_column dsaCopyEntries_column
	= { "dsaCopyEntries", &dsaCopyEntries_name, GAUGE, TO_INTEGER };
static SNMP_column dsaCacheEntries_column
	= { "dsaCacheEntries", &dsaCacheEntries_name, GAUGE, TO_INTEGER };
static SNMP_column dsaCacheHits_column
	= { "dsaCacheHits", &dsaCacheHits_name, COUNTER, TO_INTEGER };
static SNMP_column dsaSlaveHits_column
	= { "dsaSlaveHits", &dsaSlaveHits_name, COUNTER, TO_INTEGER };

static SNMP_table dsaEntriesTable = {
	5,
	{
		&dsaMasterEntries_column,
		&dsaCopyEntries_column,
		&dsaCacheEntries_column,
		&dsaCacheHits_column,
		&dsaSlaveHits_column
	}
};


static Subid dsaName_subids[] = { 1, 3, 6, 1, 2, 1, 29, 3, 1, 2 };
static Oid dsaName_name = { dsaName_subids, 10 };
static Subid dsaTimeOfCreation_subids[] = { 1, 3, 6, 1, 2, 1, 29, 3, 1, 3 };
static Oid dsaTimeOfCreation_name = { dsaTimeOfCreation_subids, 10 };
static Subid dsaTimeOfLastAttempt_subids[] = { 1, 3, 6, 1, 2, 1, 29, 3, 1, 4 };
static Oid dsaTimeOfLastAttempt_name = { dsaTimeOfLastAttempt_subids, 10 };
static Subid dsaTimeOfLastSuccess_subids[] = { 1, 3, 6, 1, 2, 1, 29, 3, 1, 5 };
static Oid dsaTimeOfLastSuccess_name = { dsaTimeOfLastSuccess_subids, 10 };
static Subid dsaFailuresSinceLastSuccess_subids[] = { 1, 3, 6, 1, 2, 1, 29, 3, 1, 6 };
static Oid dsaFailuresSinceLastSuccess_name = { dsaFailuresSinceLastSuccess_subids, 10 };
static Subid dsaFailures_subids[] = { 1, 3, 6, 1, 2, 1, 29, 3, 1, 7 };
static Oid dsaFailures_name = { dsaFailures_subids, 10 };
static Subid dsaSuccesses_subids[] = { 1, 3, 6, 1, 2, 1, 29, 3, 1, 8 };
static Oid dsaSuccesses_name = { dsaSuccesses_subids, 10 };

static SNMP_column dsaName_column
	= { "dsaName", &dsaName_name, STRING, TO_ASCII };
static SNMP_column dsaTimeOfCreation_column
	= { "dsaTimeOfCreation", &dsaTimeOfCreation_name, TIMETICKS, TO_INTEGER };
static SNMP_column dsaTimeOfLastAttempt_column
	= { "dsaTimeOfLastAttempt", &dsaTimeOfLastAttempt_name, TIMETICKS, TO_INTEGER };
static SNMP_column dsaTimeOfLastSuccess_column
	= { "dsaTimeOfLastSuccess", &dsaTimeOfLastSuccess_name, TIMETICKS, TO_INTEGER };
static SNMP_column dsaFailuresSinceLastSuccess_column
	= { "dsaFailuresSinceLastSuccess", &dsaFailuresSinceLastSuccess_name, COUNTER, TO_INTEGER };
static SNMP_column dsaFailures_column
	= { "dsaFailures", &dsaFailures_name, COUNTER, TO_INTEGER };
static SNMP_column dsaSuccesses_column
	= { "dsaSuccesses", &dsaSuccesses_name, COUNTER, TO_INTEGER };

static SNMP_table dsaIntTable = {
	7,
	{
		&dsaName_column,
		&dsaTimeOfCreation_column,
		&dsaTimeOfLastAttempt_column,
		&dsaTimeOfLastSuccess_column,
		&dsaFailuresSinceLastSuccess_column,
		&dsaFailures_column,
		&dsaSuccesses_column
	}
};


/************/
/* X4MS MIB */
/************/

static Subid x4msMtaName_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 1, 1, 2 };
static Oid x4msMtaName_name = { x4msMtaName_subids, 14 };

static SNMP_column x4msMtaName_column
	= { "x4msMtaName", &x4msMtaName_name, STRING, TO_ASCII };

static SNMP_table x4msMtaTable = {
	1,
	{
		&x4msMtaName_column
	}
};


static Subid x4msUserTotalMessages_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 2, 1, 2 };
static Oid x4msUserTotalMessages_name = { x4msUserTotalMessages_subids, 14 };

static Subid x4msUserTotalVolume_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 2, 1, 3 };
static Oid x4msUserTotalVolume_name = { x4msUserTotalVolume_subids, 14 };

static Subid x4msUserP3Associations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 2, 1, 4 };
static Oid x4msUserP3Associations_name = { x4msUserP3Associations_subids, 14 };

static Subid x4msUserP7Associations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 2, 1, 5 };
static Oid x4msUserP7Associations_name = { x4msUserP7Associations_subids, 14 };

static Subid x4msUserLastP7Association_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 2, 1, 6 };
static Oid x4msUserLastP7Association_name = { x4msUserLastP7Association_subids, 14 };

static Subid x4msUserAuthentificationFailures_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 2, 1, 7 };
static Oid x4msUserAuthentificationFailures_name = { x4msUserAuthentificationFailures_subids, 14 };

static Subid x4msUserAuthentificationFailureReason_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 2, 1, 8 };
static Oid x4msUserAuthentificationFailureReason_name = { x4msUserAuthentificationFailureReason_subids, 14 };

static Subid x4msUserName_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 2, 1, 9 };
static Oid x4msUserName_name = { x4msUserName_subids, 14 };

static SNMP_column x4msUserTotalMessages_column
	= { "x4msUserTotalMessages", &x4msUserTotalMessages_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserTotalVolume_column
	= { "x4msUserTotalVolume", &x4msUserTotalVolume_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserP3Associations_column
	= { "x4msUserP3Associations", &x4msUserP3Associations_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserP7Associations_column
	= { "x4msUserP7Associations", &x4msUserP7Associations_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserLastP7Association_column
	= { "x4msUserLastP7Association", &x4msUserLastP7Association_name, INTEGER, TO_INTEGER };
static SNMP_column x4msUserAuthentificationFailures_column
	= { "x4msUserAuthentificationFailures", &x4msUserAuthentificationFailures_name, COUNTER, TO_INTEGER };
static SNMP_column x4msUserAuthentificationFailureReason_column
	= { "x4msUserAuthentificationFailureReason", &x4msUserAuthentificationFailureReason_name, STRING, TO_ASCII };
static SNMP_column x4msUserName_column
	= { "x4msUserName", &x4msUserName_name, STRING, TO_ASCII };

static SNMP_table x4msUserTablePart1 = {
	8,
	{
		&x4msUserTotalMessages_column,
		&x4msUserTotalVolume_column,
		&x4msUserP3Associations_column,
		&x4msUserP7Associations_column,
		&x4msUserLastP7Association_column,
		&x4msUserAuthentificationFailures_column,
		&x4msUserAuthentificationFailureReason_column,
		&x4msUserName_column
	}
};


static Subid x4msUserNewMessages_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 1 };
static Oid x4msUserNewMessages_name = { x4msUserNewMessages_subids, 14 };

static Subid x4msUserNewVolume_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 2 };
static Oid x4msUserNewVolume_name = { x4msUserNewVolume_subids, 14 };

static Subid x4msUserListedMessages_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 3 };
static Oid x4msUserListedMessages_name = { x4msUserListedMessages_subids, 14 };

static Subid x4msUserListedVolume_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 4 };
static Oid x4msUserListedVolume_name = { x4msUserListedVolume_subids, 14 };

static Subid x4msUserProcessedMessages_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 5 };
static Oid x4msUserProcessedMessages_name = { x4msUserProcessedMessages_subids, 14 };

static Subid x4msUserProcessedVolume_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 6 };
static Oid x4msUserProcessedVolume_name = { x4msUserProcessedVolume_subids, 14 };

static Subid x4msUserMessagesOlderThanWeek_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 7 };
static Oid x4msUserMessagesOlderThanWeek_name = { x4msUserMessagesOlderThanWeek_subids, 14 };

static Subid x4msUserVolumeOlderThanWeek_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 8 };
static Oid x4msUserVolumeOlderThanWeek_name = { x4msUserVolumeOlderThanWeek_subids, 14 };

static Subid x4msUserMessagesOlderThanMonth_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 9 };
static Oid x4msUserMessagesOlderThanMonth_name = { x4msUserMessagesOlderThanMonth_subids, 14 };

static Subid x4msUserVolumeOlderThanMonth_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 10 };
static Oid x4msUserVolumeOlderThanMonth_name = { x4msUserVolumeOlderThanMonth_subids, 14 };

static Subid x4msUserMessagesOlderThanYear_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 11 };
static Oid x4msUserMessagesOlderThanYear_name = { x4msUserMessagesOlderThanYear_subids, 14 };

static Subid x4msUserVolumeOlderThanYear_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 12 };
static Oid x4msUserVolumeOlderThanYear_name = { x4msUserVolumeOlderThanYear_subids, 14 };

static Subid x4msUserP3InboundAssociations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 13 };
static Oid x4msUserP3InboundAssociations_name = { x4msUserP3InboundAssociations_subids, 14 };

static Subid x4msUserP7InboundAssociations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 14 };
static Oid x4msUserP7InboundAssociations_name = { x4msUserP7InboundAssociations_subids, 14 };

static Subid x4msUserP3OutboundAssociations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 15 };
static Oid x4msUserP3OutboundAssociations_name = { x4msUserP3OutboundAssociations_subids, 14 };

static Subid x4msUserAccumulatedP3InboundAssociations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 16 };
static Oid x4msUserAccumulatedP3InboundAssociations_name = { x4msUserAccumulatedP3InboundAssociations_subids, 14 };

static Subid x4msUserAccumulatedP7InboundAssociations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 17 };
static Oid x4msUserAccumulatedP7InboundAssociations_name = { x4msUserAccumulatedP7InboundAssociations_subids, 14 };

static Subid x4msUserAccumulatedP3OutboundAssociations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 18 };
static Oid x4msUserAccumulatedP3OutboundAssociations_name = { x4msUserAccumulatedP3OutboundAssociations_subids, 14 };

static Subid x4msUserLastP3InboundActivity_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 19 };
static Oid x4msUserLastP3InboundActivity_name = { x4msUserLastP3InboundActivity_subids, 14 };

static Subid x4msUserLastP7InboundActivity_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 20 };
static Oid x4msUserLastP7InboundActivity_name = { x4msUserLastP7InboundActivity_subids, 14 };

static Subid x4msUserLastP3OutboundActivity_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 21 };
static Oid x4msUserLastP3OutboundActivity_name = { x4msUserLastP3OutboundActivity_subids, 14 };

static Subid x4msUserRejectedP3InboundAssociations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 22 };
static Oid x4msUserRejectedP3InboundAssociations_name = { x4msUserRejectedP3InboundAssociations_subids, 14 };

static Subid x4msUserRejectedP7InboundAssociations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 23 };
static Oid x4msUserRejectedP7InboundAssociations_name = { x4msUserRejectedP7InboundAssociations_subids, 14 };

static Subid x4msUserFailedP3OutboundAssociations_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 24 };
static Oid x4msUserFailedP3OutboundAssociations_name = { x4msUserFailedP3OutboundAssociations_subids, 14 };

static Subid x4msUserP3InboundRejectionReason_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 25 };
static Oid x4msUserP3InboundRejectionReason_name = { x4msUserP3InboundRejectionReason_subids, 14 };

static Subid x4msUserP7InboundRejectionReason_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 26 };
static Oid x4msUserP7InboundRejectionReason_name = { x4msUserP7InboundRejectionReason_subids, 14 };

static Subid x4msUserP3OutboundConnectFailureReason_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 27 };
static Oid x4msUserP3OutboundConnectFailureReason_name = { x4msUserP3OutboundConnectFailureReason_subids, 14 };

static Subid x4msUserMtaIndex_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 28 };
static Oid x4msUserMtaIndex_name = { x4msUserMtaIndex_subids, 14 };

static Subid x4msUserORName_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 3, 1, 29 };
static Oid x4msUserORName_name = { x4msUserORName_subids, 14 };

static SNMP_column x4msUserNewMessages_column
	= { "x4msUserNewMessages", &x4msUserNewMessages_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserNewVolume_column
	= { "x4msUserNewVolume", &x4msUserNewVolume_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserListedMessages_column
	= { "x4msUserListedMessages", &x4msUserListedMessages_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserListedVolume_column
	= { "x4msUserListedVolume", &x4msUserListedVolume_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserProcessedMessages_column
	= { "x4msUserProcessedMessages", &x4msUserProcessedMessages_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserProcessedVolume_column
	= { "x4msUserProcessedVolume", &x4msUserProcessedVolume_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserMessagesOlderThanWeek_column
	= { "x4msUserMessagesOlderThanWeek", &x4msUserMessagesOlderThanWeek_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserVolumeOlderThanWeek_column
	= { "x4msUserVolumeOlderThanWeek", &x4msUserVolumeOlderThanWeek_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserMessagesOlderThanMonth_column
	= { "x4msUserMessagesOlderThanMonth", &x4msUserMessagesOlderThanMonth_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserVolumeOlderThanMonth_column
	= { "x4msUserVolumeOlderThanMonth", &x4msUserVolumeOlderThanMonth_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserMessagesOlderThanYear_column
	= { "x4msUserMessagesOlderThanYear", &x4msUserMessagesOlderThanYear_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserVolumeOlderThanYear_column
	= { "x4msUserVolumeOlderThanYear", &x4msUserVolumeOlderThanYear_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserP3InboundAssociations_column
	= { "x4msUserP3InboundAssociations", &x4msUserP3InboundAssociations_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserP7InboundAssociations_column
	= { "x4msUserP7InboundAssociations", &x4msUserP7InboundAssociations_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserP3OutboundAssociations_column
	= { "x4msUserP3OutboundAssociations", &x4msUserP3OutboundAssociations_name, GAUGE, TO_INTEGER };
static SNMP_column x4msUserAccumulatedP3InboundAssociations_column
	= { "x4msUserAccumulatedP3InboundAssociations", &x4msUserAccumulatedP3InboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column x4msUserAccumulatedP7InboundAssociations_column
	= { "x4msUserAccumulatedP7InboundAssociations", &x4msUserAccumulatedP7InboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column x4msUserAccumulatedP3OutboundAssociations_column
	= { "x4msUserAccumulatedP3OutboundAssociations", &x4msUserAccumulatedP3OutboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column x4msUserLastP3InboundActivity_column
	= { "x4msUserLastP3InboundActivity", &x4msUserLastP3InboundActivity_name, INTEGER, TO_INTEGER };
static SNMP_column x4msUserLastP7InboundActivity_column
	= { "x4msUserLastP7InboundActivity", &x4msUserLastP7InboundActivity_name, INTEGER, TO_INTEGER };
static SNMP_column x4msUserLastP3OutboundActivity_column
	= { "x4msUserLastP3OutboundActivity", &x4msUserLastP3OutboundActivity_name, INTEGER, TO_INTEGER };
static SNMP_column x4msUserRejectedP3InboundAssociations_column
	= { "x4msUserRejectedP3InboundAssociations", &x4msUserRejectedP3InboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column x4msUserRejectedP7InboundAssociations_column
	= { "x4msUserRejectedP7InboundAssociations", &x4msUserRejectedP7InboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column x4msUserFailedP3OutboundAssociations_column
	= { "x4msUserFailedP3OutboundAssociations", &x4msUserFailedP3OutboundAssociations_name, COUNTER, TO_INTEGER };
static SNMP_column x4msUserP3InboundRejectionReason_column
	= { "x4msUserP3InboundRejectionReason", &x4msUserP3InboundRejectionReason_name, STRING, TO_ASCII };
static SNMP_column x4msUserP7InboundRejectionReason_column
	= { "x4msUserP7InboundRejectionReason", &x4msUserP7InboundRejectionReason_name, STRING, TO_ASCII };
static SNMP_column x4msUserP3OutboundConnectFailureReason_column
	= { "x4msUserP3OutboundConnectFailureReason", &x4msUserP3OutboundConnectFailureReason_name, STRING, TO_ASCII };
static SNMP_column x4msUserMtaIndex_column
	= { "x4msUserMtaIndex", &x4msUserMtaIndex_name, INTEGER, TO_INTEGER };
static SNMP_column x4msUserORName_column
	= { "x4msUserORName", &x4msUserORName_name, STRING, TO_ASCII };

static SNMP_table x4msUserTablePart2 = {
	29,
	{
		&x4msUserNewMessages_column,
		&x4msUserNewVolume_column,
		&x4msUserListedMessages_column,
		&x4msUserListedVolume_column,
		&x4msUserProcessedMessages_column,
		&x4msUserProcessedVolume_column,
		&x4msUserMessagesOlderThanWeek_column,
		&x4msUserVolumeOlderThanWeek_column,
		&x4msUserMessagesOlderThanMonth_column,
		&x4msUserVolumeOlderThanMonth_column,
		&x4msUserMessagesOlderThanYear_column,
		&x4msUserVolumeOlderThanYear_column,
		&x4msUserP3InboundAssociations_column,
		&x4msUserP7InboundAssociations_column,
		&x4msUserP3OutboundAssociations_column,
		&x4msUserAccumulatedP3InboundAssociations_column,
		&x4msUserAccumulatedP7InboundAssociations_column,
		&x4msUserAccumulatedP3OutboundAssociations_column,
		&x4msUserLastP3InboundActivity_column,
		&x4msUserLastP7InboundActivity_column,
		&x4msUserLastP3OutboundActivity_column,
		&x4msUserRejectedP3InboundAssociations_column,
		&x4msUserRejectedP7InboundAssociations_column,
		&x4msUserFailedP3OutboundAssociations_column,
		&x4msUserP3InboundRejectionReason_column,
		&x4msUserP7InboundRejectionReason_column,
		&x4msUserP3OutboundConnectFailureReason_column,
		&x4msUserMtaIndex_column,
		&x4msUserORName_column
	}
};


static Subid x4msUserAssociationIndex_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 1, 4, 1, 1 };
static Oid x4msUserAssociationIndex_name = { x4msUserAssociationIndex_subids, 14 };

static SNMP_column x4msUserAssociationIndex_column
	= { "x4msUserAssociationIndex", &x4msUserAssociationIndex_name, INTEGER, TO_INTEGER };

static SNMP_table x4msUserAssociationTable = {
	1,
	{
		&x4msUserAssociationIndex_column
	}
};


/*************/
/* X4GRP MIB */
/*************/

static Subid x4grpName_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 2, 1, 1, 2 };
static Oid x4grpName_name = { x4grpName_subids, 14 };

static SNMP_column x4grpName_column
	= { "x4grpName", &x4grpName_name, STRING, TO_ASCII };

static SNMP_table x4grpTable = {
	1,
	{
		&x4grpName_column
	}
};


static Subid x4grpMappingMSIndex_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 2, 2, 1, 1 };
static Oid x4grpMappingMSIndex_name = { x4grpMappingMSIndex_subids, 14 };

static Subid x4grpMappingMTAIndex_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 2, 2, 1, 2 };
static Oid x4grpMappingMTAIndex_name = { x4grpMappingMTAIndex_subids, 14 };

static SNMP_column x4grpMappingMSIndex_column
	= { "x4grpMappingMSIndex", &x4grpMappingMSIndex_name, INTEGER, TO_INTEGER };
static SNMP_column x4grpMappingMTAIndex_column
	= { "x4grpMappingMTAIndex", &x4grpMappingMTAIndex_name, INTEGER, TO_INTEGER };

static SNMP_table x4grpMappingTable = {
	2,
	{
		&x4grpMappingMSIndex_column,
		&x4grpMappingMTAIndex_column
	}
};


/*************/
/* X5DSA MIB */
/*************/

static Subid x5dsaReferenceType_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 4, 1, 1, 2 };
static Oid x5dsaReferenceType_name = { x5dsaReferenceType_subids, 14 };
static Subid x5dsaReferenceNamingContext_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 4, 1, 1, 3 };
static Oid x5dsaReferenceNamingContext_name = { x5dsaReferenceNamingContext_subids, 14 };
static Subid x5dsaReferenceSubordinate_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 4, 1, 1, 4 };
static Oid x5dsaReferenceSubordinate_name = { x5dsaReferenceSubordinate_subids, 14 };
static Subid x5dsaReferenceName_subids[] = { 1, 3, 6, 1, 4, 1, 42, 2, 8, 2, 4, 1, 1, 5 };
static Oid x5dsaReferenceName_name = { x5dsaReferenceName_subids, 14 };

static SNMP_column x5dsaReferenceType_column
	= { "x5dsaReferenceType", &x5dsaReferenceType_name, INTEGER, TO_INTEGER };
static SNMP_column x5dsaReferenceNamingContext_column
	= { "x5dsaReferenceNamingContext", &x5dsaReferenceNamingContext_name, STRING, TO_ASCII };
static SNMP_column x5dsaReferenceSubordinate_column
	= { "x5dsaReferenceSubordinate", &x5dsaReferenceSubordinate_name, STRING, TO_ASCII };
static SNMP_column x5dsaReferenceName_column
	= { "x5dsaReferenceName", &x5dsaReferenceName_name, STRING, TO_ASCII };

static SNMP_table x5dsaReferenceTable = {
	4,
	{
		&x5dsaReferenceType_column,
		&x5dsaReferenceNamingContext_column,
		&x5dsaReferenceSubordinate_column,
		&x5dsaReferenceName_column
	}
};



/***** LOCAL FUNCTIONS *****/

static int translate_variable(SNMP_variable *variable, int translator,
	uintptr_t pointer, char *error_label);
static int extract_one_index_from_column(Oid *instance, Oid *object, int32_t * index);
static int extract_two_indexes_from_column(Oid *instance, Oid *object,
	int32_t *index1, int32_t *index2);
static int extract_three_indexes_from_column(Oid *instance, Oid *object,
	int32_t *index1, int32_t *index2, int32_t *index3);

/***************************************************************/

int sysUpTime_send_request(SNMP_session *session, char *error_label)
{
	SNMP_pdu *request;
	SNMP_object *object = &sysUpTime_object;


	error_label[0] = '\0';


	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = GET_REQ_MSG;

	if(snmp_pdu_append_null_variable(request, object->name, error_label) == NULL)
	{
		snmp_pdu_free(request);
		return -1;
	}

	if(snmp_session_send(session, SYSUPTIME_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
SysUpTime *sysUpTime_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	SysUpTime *sysUpTime;
	SNMP_variable *variable;
	SNMP_object *object = &sysUpTime_object;
	uintptr_t pointer;

	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: sysUpTime_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	sysUpTime = (SysUpTime *) malloc(sizeof(SysUpTime));
	if(sysUpTime == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(sysUpTime, 0, sizeof(SysUpTime));

	pointer = (uintptr_t)sysUpTime;
	variable = response->first_variable;

	if(variable == NULL)
	{
		sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
		sysUpTime_free(sysUpTime);
		return NULL;
	}

	/* check oid */
	if(SSAOidCmp(&(variable->name), object->name))
	{
		snmp_errno = SNMP_ERR_NOSUCHNAME;
		sysUpTime_free(sysUpTime);
		return NULL;
	}

	/* check type */
	if(variable->type != object->type)
	{
		sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
			variable->type, object->label);
		sysUpTime_free(sysUpTime);
		return NULL;
	}

	if(translate_variable(variable, object->translator, pointer, error_label))
	{
		sysUpTime_free(sysUpTime);
		return NULL;
	}


	return sysUpTime;
}


/***************************************************************/

void sysUpTime_free(SysUpTime *sysUpTime)
{
	if(sysUpTime == NULL)
	{
		return;
	}

	free(sysUpTime);
}


/***************************************************************/

void sysUpTime_print(SysUpTime *sysUpTime)
{
	printf("sysUpTime:                            %ld\n",
		sysUpTime);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int applEntry_send_request(SNMP_session *session, u_char type, int32_t applIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: applEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < applTable.column_num; i++)
	{
		column = applTable.columns[i];

		if(applIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = applIndex;
			oid.len = column->name->len + 1;
			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, APPL_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
ApplEntry *applEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	ApplEntry *applEntry;
	int32_t applIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: applEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	applEntry = (ApplEntry *) malloc(sizeof(ApplEntry));
	if(applEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(applEntry, 0, sizeof(ApplEntry));

	pointer = (uintptr_t)&(applEntry->applName);
	variable = response->first_variable;
	for(i = 0; i < applTable.column_num; i++)
	{
		column = applTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			applEntry_free(applEntry);
			return NULL;
		}

		/* check oid and extract applIndex */
		if(extract_one_index_from_column(&(variable->name), column->name, &applIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			applEntry_free(applEntry);
			return NULL;
		}

		/* check if all applIndex are equal ??? */
		applEntry->applIndex = applIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			applEntry_free(applEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			applEntry_free(applEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return applEntry;
}


/***************************************************************/

void applEntry_free(ApplEntry *applEntry)
{
	if(applEntry == NULL)
	{
		return;
	}

	if(applEntry->applName)
	{
		free(applEntry->applName);
	}
	if(applEntry->applDirectoryName)
	{
		free(applEntry->applDirectoryName);
	}
	if(applEntry->applVersion)
	{
		free(applEntry->applVersion);
	}
	free(applEntry);
}


/***************************************************************/

void applEntry_print(ApplEntry *applEntry)
{
	printf("applIndex:                            %ld\n",
		applEntry->applIndex);
	printf("applName:                             %s\n",
		applEntry->applName);
	printf("applDirectoryName:                    %s\n",
		applEntry->applDirectoryName);
	printf("applVersion:                          %s\n",
		applEntry->applVersion);
	printf("applUptime:                           %ld\n",
		applEntry->applUptime);
	printf("applOperStatus:                       %s\n",
		applOperStatus_string(applEntry->applOperStatus));
	printf("applLastChange:                       %ld\n",
		applEntry->applLastChange);
	printf("applInboundAssociations:              %ld\n",
		applEntry->applInboundAssociations);
	printf("applOutboundAssociations:             %ld\n",
		applEntry->applOutboundAssociations);
	printf("applAccumulatedInboundAssociations:   %ld\n",
		applEntry->applAccumulatedInboundAssociations);
	printf("applAccumulatedOutboundAssociations:  %ld\n",
		applEntry->applAccumulatedOutboundAssociations);
	printf("applLastInboundActivity:              %ld\n",
		applEntry->applLastInboundActivity);
	printf("applLastOutboundActivity:             %ld\n",
		applEntry->applLastOutboundActivity);
	printf("applRejectedInboundAssociations:      %ld\n",
		applEntry->applRejectedInboundAssociations);
	printf("applFailedOutboundAssociations:       %ld\n",
		applEntry->applFailedOutboundAssociations);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int
assocEntry_send_request(SNMP_session *session, u_char type, int32_t applIndex, int32_t assocIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: assocEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < assocTable.column_num; i++)
	{
		column = assocTable.columns[i];

		if(applIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = applIndex;
			oid.len = column->name->len + 1;

			if(assocIndex >= 0)
			{
				subids[column->name->len + 1] = assocIndex;
				oid.len = column->name->len + 2;
			}

			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, ASSOC_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
AssocEntry *assocEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	AssocEntry *assocEntry;
	int32_t applIndex;
	int32_t assocIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: assocEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	assocEntry = (AssocEntry *) malloc(sizeof(AssocEntry));
	if(assocEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(assocEntry, 0, sizeof(AssocEntry));

	pointer = (uintptr_t)&(assocEntry->assocRemoteApplication);
	variable = response->first_variable;
	for(i = 0; i < assocTable.column_num; i++)
	{
		column = assocTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			assocEntry_free(assocEntry);
			return NULL;
		}

		/* check oid and extract applIndex */
		if(extract_two_indexes_from_column(&(variable->name), column->name, &applIndex, &assocIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			assocEntry_free(assocEntry);
			return NULL;
		}

		/* check if all applIndex + assocIndex are equal ??? */
		assocEntry->applIndex = applIndex;
		assocEntry->assocIndex = assocIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			assocEntry_free(assocEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			assocEntry_free(assocEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return assocEntry;
}


/***************************************************************/

void assocEntry_free(AssocEntry *assocEntry)
{
	if(assocEntry == NULL)
	{
		return;
	}

	if(assocEntry->assocRemoteApplication)
	{
		free(assocEntry->assocRemoteApplication);
	}
	if(assocEntry->assocApplicationProtocol)
	{
		SSAOidFree(assocEntry->assocApplicationProtocol);
	}
	free(assocEntry);
}


/***************************************************************/

void assocEntry_print(AssocEntry *assocEntry)
{
	printf("applIndex:                            %ld\n",
		assocEntry->applIndex);
	printf("assocIndex:                           %ld\n",
		assocEntry->assocIndex);
	printf("assocRemoteApplication:               %s\n",
		assocEntry->assocRemoteApplication);
	printf("assocApplicationProtocol:             %s\n",
		SSAOidString(assocEntry->assocApplicationProtocol));
	printf("assocApplicationType:                 %s\n",
		assocApplicationType_string(assocEntry->assocApplicationType));
	printf("assocDuration:                        %ld\n",
		assocEntry->assocDuration);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int
mtaEntry_send_request(SNMP_session *session, u_char type, int32_t applIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: mtaEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < mtaTable.column_num; i++)
	{
		column = mtaTable.columns[i];

		if(applIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = applIndex;
			oid.len = column->name->len + 1;
			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, MTA_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
MtaEntry *mtaEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	MtaEntry *mtaEntry;
	int32_t applIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: mtaEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	mtaEntry = (MtaEntry *) malloc(sizeof(MtaEntry));
	if(mtaEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(mtaEntry, 0, sizeof(MtaEntry));

	pointer = (uintptr_t)&(mtaEntry->mtaReceivedMessages);
	variable = response->first_variable;
	for(i = 0; i < mtaTable.column_num; i++)
	{
		column = mtaTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			mtaEntry_free(mtaEntry);
			return NULL;
		}

		/* check oid and extract applIndex */
		if(extract_one_index_from_column(&(variable->name), column->name, &applIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			mtaEntry_free(mtaEntry);
			return NULL;
		}

		/* check if all applIndex are equal ??? */
		mtaEntry->applIndex = applIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			mtaEntry_free(mtaEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			mtaEntry_free(mtaEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return mtaEntry;
}


/***************************************************************/

void mtaEntry_free(MtaEntry *mtaEntry)
{
	if(mtaEntry == NULL)
	{
		return;
	}
	free(mtaEntry);
}


/***************************************************************/

void mtaEntry_print(MtaEntry *mtaEntry)
{
	printf("applIndex:                            %ld\n",
		mtaEntry->applIndex);
	printf("mtaReceivedMessages:                  %ld\n",
		mtaEntry->mtaReceivedMessages);
	printf("mtaStoredMessages:                    %ld\n",
		mtaEntry->mtaStoredMessages);
	printf("mtaTransmittedMessages:               %ld\n",
		mtaEntry->mtaTransmittedMessages);
	printf("mtaReceivedVolume:                    %ld\n",
		mtaEntry->mtaReceivedVolume);
	printf("mtaStoredVolume:                      %ld\n",
		mtaEntry->mtaStoredVolume);
	printf("mtaTransmittedVolume:                 %ld\n",
		mtaEntry->mtaTransmittedVolume);
	printf("mtaReceivedRecipients:                %ld\n",
		mtaEntry->mtaReceivedRecipients);
	printf("mtaStoredRecipients:                  %ld\n",
		mtaEntry->mtaStoredRecipients);
	printf("mtaTransmittedRecipients:             %ld\n",
		mtaEntry->mtaTransmittedRecipients);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int mtaGroupEntry_send_request(SNMP_session *session, u_char type, int32_t applIndex, int32_t mtaGroupIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: mtaGroupEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < mtaGroupTable.column_num; i++)
	{
		column = mtaGroupTable.columns[i];

		if(applIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = applIndex;
			oid.len = column->name->len + 1;

			if(mtaGroupIndex >= 0)
			{
				subids[column->name->len + 1] = mtaGroupIndex;
				oid.len = column->name->len + 2;
			}

			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, MTA_GROUP_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
MtaGroupEntry *mtaGroupEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	MtaGroupEntry *mtaGroupEntry;
	int32_t applIndex;
	int32_t mtaGroupIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: mtaGroupEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	mtaGroupEntry = (MtaGroupEntry *) malloc(sizeof(MtaGroupEntry));
	if(mtaGroupEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(mtaGroupEntry, 0, sizeof(MtaGroupEntry));

	pointer = (uintptr_t)&(mtaGroupEntry->mtaGroupReceivedMessages);
	variable = response->first_variable;
	for(i = 0; i < mtaGroupTable.column_num; i++)
	{
		column = mtaGroupTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			mtaGroupEntry_free(mtaGroupEntry);
			return NULL;
		}

		/* check oid and extract applIndex and mtaGroupIndex */
		if(extract_two_indexes_from_column(&(variable->name), column->name, &applIndex, &mtaGroupIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			mtaGroupEntry_free(mtaGroupEntry);
			return NULL;
		}

		/* check if all applIndex + mtaGroupIndex are equal ??? */
		mtaGroupEntry->applIndex = applIndex;
		mtaGroupEntry->mtaGroupIndex = mtaGroupIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			mtaGroupEntry_free(mtaGroupEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			mtaGroupEntry_free(mtaGroupEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return mtaGroupEntry;
}


/***************************************************************/

void mtaGroupEntry_free(MtaGroupEntry *mtaGroupEntry)
{
	if(mtaGroupEntry == NULL)
	{
		return;
	}

	if(mtaGroupEntry->mtaGroupInboundRejectionReason)
	{
		free(mtaGroupEntry->mtaGroupInboundRejectionReason);
	}
	if(mtaGroupEntry->mtaGroupOutboundConnectFailureReason)
	{
		free(mtaGroupEntry->mtaGroupOutboundConnectFailureReason);
	}
	if(mtaGroupEntry->mtaGroupMailProtocol)
	{
		SSAOidFree(mtaGroupEntry->mtaGroupMailProtocol);
	}
	if(mtaGroupEntry->mtaGroupName)
	{
		free(mtaGroupEntry->mtaGroupName);
	}
	free(mtaGroupEntry);
}


/***************************************************************/

void mtaGroupEntry_print(MtaGroupEntry *mtaGroupEntry)
{
	printf("applIndex:                            %ld\n",
		mtaGroupEntry->applIndex);
	printf("mtaGroupIndex:                        %ld\n",
		mtaGroupEntry->mtaGroupIndex);
	printf("mtaGroupReceivedMessages:             %ld\n",
		mtaGroupEntry->mtaGroupReceivedMessages);
	printf("mtaGroupRejectedMessages:             %ld\n",
		mtaGroupEntry->mtaGroupRejectedMessages);
	printf("mtaGroupStoredMessages:               %ld\n",
		mtaGroupEntry->mtaGroupStoredMessages);
	printf("mtaGroupTransmittedMessages:          %ld\n",
		mtaGroupEntry->mtaGroupTransmittedMessages);
	printf("mtaGroupReceivedVolume:               %ld\n",
		mtaGroupEntry->mtaGroupReceivedVolume);
	printf("mtaGroupStoredVolume:                 %ld\n",
		mtaGroupEntry->mtaGroupStoredVolume);
	printf("mtaGroupTransmittedVolume:            %ld\n",
		mtaGroupEntry->mtaGroupTransmittedVolume);
	printf("mtaGroupOldestMessageStored:          %ld\n",
		mtaGroupEntry->mtaGroupOldestMessageStored);
	printf("mtaGroupInboundAssociations:          %ld\n",
		mtaGroupEntry->mtaGroupInboundAssociations);
	printf("mtaGroupOutboundAssociations:         %ld\n",
		mtaGroupEntry->mtaGroupOutboundAssociations);
	printf("mtaGroupAccumulatedInboundAssoc.:     %ld\n",
		mtaGroupEntry->mtaGroupAccumulatedInboundAssociations);
	printf("mtaGroupAccumulatedOutboundAssoc.:    %ld\n",
		mtaGroupEntry->mtaGroupAccumulatedOutboundAssociations);
	printf("mtaGroupLastInboundActivity:          %ld\n",
		mtaGroupEntry->mtaGroupLastInboundActivity);
	printf("mtaGroupLastOutboundActivity:         %ld\n",
		mtaGroupEntry->mtaGroupLastOutboundActivity);
	printf("mtaGroupRejectedInboundAssociations:  %ld\n",
		mtaGroupEntry->mtaGroupRejectedInboundAssociations);
	printf("mtaGroupFailedOutboundAssociations:   %ld\n",
		mtaGroupEntry->mtaGroupFailedOutboundAssociations);
	printf("mtaGroupInboundRejectionReason:       %s\n",
		mtaGroupEntry->mtaGroupInboundRejectionReason);
	printf("mtaGroupOutboundConnectFailureReason: %s\n",
		mtaGroupEntry->mtaGroupOutboundConnectFailureReason);
	printf("mtaGroupScheduledRetry:               %ld\n",
		mtaGroupEntry->mtaGroupScheduledRetry);
	printf("mtaGroupMailProtocol:                 %s\n",
		SSAOidString(mtaGroupEntry->mtaGroupMailProtocol));
	printf("mtaGroupName:                         %s\n",
		mtaGroupEntry->mtaGroupName);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int mtaGroupAssociationEntry_send_request(SNMP_session *session, u_char type, int32_t applIndex, int32_t mtaGroupIndex, int32_t mtaGroupAssociationIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: mtaGroupAssociationEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < mtaGroupAssociationTable.column_num; i++)
	{
		column = mtaGroupAssociationTable.columns[i];

		if(applIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = applIndex;
			oid.len = column->name->len + 1;

			if(mtaGroupIndex >= 0)
			{
				subids[column->name->len + 1] = mtaGroupIndex;
				oid.len = column->name->len + 2;

				if(mtaGroupAssociationIndex >= 0)
				{
					subids[column->name->len + 2] = mtaGroupAssociationIndex;
					oid.len = column->name->len + 3;
				}
			}

			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, MTA_GROUP_ASSOCIATION_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
MtaGroupAssociationEntry *mtaGroupAssociationEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	MtaGroupAssociationEntry *mtaGroupAssociationEntry;
	int32_t applIndex;
	int32_t mtaGroupIndex;
	int32_t mtaGroupAssociationIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: mtaGroupAssociationEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	mtaGroupAssociationEntry = (MtaGroupAssociationEntry *) malloc(sizeof(MtaGroupAssociationEntry));
	if(mtaGroupAssociationEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(mtaGroupAssociationEntry, 0, sizeof(MtaGroupAssociationEntry));

	pointer = (uintptr_t)&(mtaGroupAssociationEntry->mtaGroupAssociationIndex);
	variable = response->first_variable;
	for(i = 0; i < mtaGroupAssociationTable.column_num; i++)
	{
		column = mtaGroupAssociationTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			mtaGroupAssociationEntry_free(mtaGroupAssociationEntry);
			return NULL;
		}

		/* check oid and extract applIndex and mtaGroupIndex */
		if(extract_three_indexes_from_column(&(variable->name), column->name, &applIndex, &mtaGroupIndex, &mtaGroupAssociationIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			mtaGroupAssociationEntry_free(mtaGroupAssociationEntry);
			return NULL;
		}

		/* check if all applIndex + mtaGroupIndex + mtaGroupAssociationIndex are equal ??? */
		mtaGroupAssociationEntry->applIndex = applIndex;
		mtaGroupAssociationEntry->mtaGroupIndex = mtaGroupIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			mtaGroupAssociationEntry_free(mtaGroupAssociationEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			mtaGroupAssociationEntry_free(mtaGroupAssociationEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return mtaGroupAssociationEntry;
}


/***************************************************************/

void mtaGroupAssociationEntry_free(MtaGroupAssociationEntry *mtaGroupAssociationEntry)
{
	if(mtaGroupAssociationEntry == NULL)
	{
		return;
	}

	free(mtaGroupAssociationEntry);
}


/***************************************************************/

void mtaGroupAssociationEntry_print(MtaGroupAssociationEntry *mtaGroupAssociationEntry)
{
	printf("applIndex:                            %ld\n",
		mtaGroupAssociationEntry->applIndex);
	printf("mtaGroupIndex:                        %ld\n",
		mtaGroupAssociationEntry->mtaGroupIndex);
	printf("mtaGroupAssociationIndex:             %ld\n",
		mtaGroupAssociationEntry->mtaGroupAssociationIndex);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int dsaOpsEntry_send_request(SNMP_session *session, u_char type, int32_t applIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: dsaOpsEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < dsaOpsTable.column_num; i++)
	{
		column = dsaOpsTable.columns[i];

		if(applIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = applIndex;
			oid.len = column->name->len + 1;
			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, DSA_OPS_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
DsaOpsEntry *dsaOpsEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	DsaOpsEntry *dsaOpsEntry;
	int32_t applIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: dsaOpsEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	dsaOpsEntry = (DsaOpsEntry *) malloc(sizeof(DsaOpsEntry));
	if(dsaOpsEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(dsaOpsEntry, 0, sizeof(dsaOpsEntry));

	pointer = (uintptr_t)&(dsaOpsEntry->dsaAnonymousBinds);
	variable = response->first_variable;
	for(i = 0; i < dsaOpsTable.column_num; i++)
	{
		column = dsaOpsTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			dsaOpsEntry_free(dsaOpsEntry);
			return NULL;
		}

		/* check oid and extract applIndex */
		if(extract_one_index_from_column(&(variable->name), column->name, &applIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			dsaOpsEntry_free(dsaOpsEntry);
			return NULL;
		}

		/* check if all applIndex are equal ??? */
		dsaOpsEntry->applIndex = applIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			dsaOpsEntry_free(dsaOpsEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			dsaOpsEntry_free(dsaOpsEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return dsaOpsEntry;
}


/***************************************************************/

void dsaOpsEntry_free(DsaOpsEntry *dsaOpsEntry)
{
	if(dsaOpsEntry == NULL)
	{
		return;
	}

	free(dsaOpsEntry);
}


/***************************************************************/

void dsaOpsEntry_print(DsaOpsEntry *dsaOpsEntry)
{
	printf("applIndex:                            %ld\n",
		dsaOpsEntry->applIndex);
	printf("dsaAnonymousBinds:                    %ld\n",
		dsaOpsEntry->dsaAnonymousBinds);
	printf("dsaUnauthBinds:                       %ld\n",
		dsaOpsEntry->dsaUnauthBinds);
	printf("dsaSimpleAuthBinds:                   %ld\n",
		dsaOpsEntry->dsaSimpleAuthBinds);
	printf("dsaStrongAuthBinds:                   %ld\n",
		dsaOpsEntry->dsaStrongAuthBinds);
	printf("dsaBindSecurityErrors:                %ld\n",
		dsaOpsEntry->dsaBindSecurityErrors);
	printf("dsaInOps:                             %ld\n",
		dsaOpsEntry->dsaInOps);
	printf("dsaReadOps:                           %ld\n",
		dsaOpsEntry->dsaReadOps);
	printf("dsaCompareOps:                        %ld\n",
		dsaOpsEntry->dsaCompareOps);
	printf("dsaAddEntryOps:                       %ld\n",
		dsaOpsEntry->dsaAddEntryOps);
	printf("dsaRemoveEntryOps:                    %ld\n",
		dsaOpsEntry->dsaRemoveEntryOps);
	printf("dsaModifyEntryOps:                    %ld\n",
		dsaOpsEntry->dsaModifyEntryOps);
	printf("dsaModifyRDNOps:                      %ld\n",
		dsaOpsEntry->dsaModifyRDNOps);
	printf("dsaListOps:                           %ld\n",
		dsaOpsEntry->dsaListOps);
	printf("dsaSearchOps:                         %ld\n",
		dsaOpsEntry->dsaSearchOps);
	printf("dsaOneLevelSearchOps:                 %ld\n",
		dsaOpsEntry->dsaOneLevelSearchOps);
	printf("dsaWholeTreeSearchOps:                %ld\n",
		dsaOpsEntry->dsaWholeTreeSearchOps);
	printf("dsaReferrals:                         %ld\n",
		dsaOpsEntry->dsaReferrals);
	printf("dsaChainings:                         %ld\n",
		dsaOpsEntry->dsaChainings);
	printf("dsaSecurityErrors:                    %ld\n",
		dsaOpsEntry->dsaSecurityErrors);
	printf("dsaErrors:                            %ld\n",
		dsaOpsEntry->dsaErrors);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int dsaEntriesEntry_send_request(SNMP_session *session, u_char type, int32_t applIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: dsaEntriesEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < dsaEntriesTable.column_num; i++)
	{
		column = dsaEntriesTable.columns[i];

		if(applIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = applIndex;
			oid.len = column->name->len + 1;
			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, DSA_ENTRIES_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
DsaEntriesEntry *dsaEntriesEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	DsaEntriesEntry *dsaEntriesEntry;
	int32_t applIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: dsaEntriesEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	dsaEntriesEntry = (DsaEntriesEntry *) malloc(sizeof(DsaEntriesEntry));
	if(dsaEntriesEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(dsaEntriesEntry, 0, sizeof(dsaEntriesEntry));

	pointer = (uintptr_t)&(dsaEntriesEntry->dsaMasterEntries);
	variable = response->first_variable;
	for(i = 0; i < dsaEntriesTable.column_num; i++)
	{
		column = dsaEntriesTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			dsaEntriesEntry_free(dsaEntriesEntry);
			return NULL;
		}

		/* check oid and extract applIndex */
		if(extract_one_index_from_column(&(variable->name), column->name, &applIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			dsaEntriesEntry_free(dsaEntriesEntry);
			return NULL;
		}

		/* check if all applIndex are equal ??? */
		dsaEntriesEntry->applIndex = applIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			dsaEntriesEntry_free(dsaEntriesEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			dsaEntriesEntry_free(dsaEntriesEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return dsaEntriesEntry;
}


/***************************************************************/

void dsaEntriesEntry_free(DsaEntriesEntry *dsaEntriesEntry)
{
	if(dsaEntriesEntry == NULL)
	{
		return;
	}

	free(dsaEntriesEntry);
}


/***************************************************************/

void dsaEntriesEntry_print(DsaEntriesEntry *dsaEntriesEntry)
{
	printf("applIndex:                            %ld\n",
		dsaEntriesEntry->applIndex);
	printf("dsaMasterEntries:                     %ld\n",
		dsaEntriesEntry->dsaMasterEntries);
	printf("dsaCopyEntries:                       %ld\n",
		dsaEntriesEntry->dsaCopyEntries);
	printf("dsaCacheEntries:                      %ld\n",
		dsaEntriesEntry->dsaCacheEntries);
	printf("dsaCacheHits:                         %ld\n",
		dsaEntriesEntry->dsaCacheHits);
	printf("dsaSlaveHits:                         %ld\n",
		dsaEntriesEntry->dsaSlaveHits);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int dsaIntEntry_send_request(SNMP_session *session, u_char type, int32_t applIndex, int32_t dsaIntIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: dsaIntEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < dsaIntTable.column_num; i++)
	{
		column = dsaIntTable.columns[i];

		if(applIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = applIndex;
			oid.len = column->name->len + 1;

			if(dsaIntIndex >= 0)
			{
				subids[column->name->len + 1] = dsaIntIndex;
				oid.len = column->name->len + 2;
			}

			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, DSA_INT_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
DsaIntEntry *dsaIntEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	DsaIntEntry *dsaIntEntry;
	int32_t applIndex;
	int32_t dsaIntIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: dsaIntEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	dsaIntEntry = (DsaIntEntry *) malloc(sizeof(DsaIntEntry));
	if(dsaIntEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(dsaIntEntry, 0, sizeof(DsaIntEntry));

	pointer = (uintptr_t)&(dsaIntEntry->dsaName);
	variable = response->first_variable;
	for(i = 0; i < dsaIntTable.column_num; i++)
	{
		column = dsaIntTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			dsaIntEntry_free(dsaIntEntry);
			return NULL;
		}

		/* check oid and extract applIndex and mtaGroupIndex */
		if(extract_two_indexes_from_column(&(variable->name), column->name, &applIndex, &dsaIntIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			dsaIntEntry_free(dsaIntEntry);
			return NULL;
		}

		/* check if all applIndex + dsaIntIndex are equal ??? */
		dsaIntEntry->applIndex = applIndex;
		dsaIntEntry->dsaIntIndex = dsaIntIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			dsaIntEntry_free(dsaIntEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			dsaIntEntry_free(dsaIntEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return dsaIntEntry;
}


/***************************************************************/

void dsaIntEntry_free(DsaIntEntry *dsaIntEntry)
{
	if(dsaIntEntry == NULL)
	{
		return;
	}

	if(dsaIntEntry->dsaName)
	{
		free(dsaIntEntry->dsaName);
	}
	free(dsaIntEntry);
}


/***************************************************************/

void dsaIntEntry_print(DsaIntEntry *dsaIntEntry)
{
	printf("applIndex:                            %ld\n",
		dsaIntEntry->applIndex);
	printf("dsaIntIndex:                          %ld\n",
		dsaIntEntry->dsaIntIndex);
	printf("dsaName:                              %s\n",
		dsaIntEntry->dsaName);
	printf("dsaTimeOfCreation:                    %s\n",
		dsaIntEntry->dsaTimeOfCreation);
	printf("dsaTimeOfLastAttempt:                 %ld\n",
		dsaIntEntry->dsaTimeOfLastAttempt);
	printf("dsaTimeOfLastSuccess:                 %ld\n",
		dsaIntEntry->dsaTimeOfLastSuccess);
	printf("dsaFailuresSinceLastSuccess:          %ld\n",
		dsaIntEntry->dsaFailuresSinceLastSuccess);
	printf("dsaFailures:                          %ld\n",
		dsaIntEntry->dsaFailures);
	printf("dsaSuccesses:                         %ld\n",
		dsaIntEntry->dsaSuccesses);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int x4msMtaEntry_send_request(SNMP_session *session, u_char type, int32_t x4msMtaIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: x4msMtaEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < x4msMtaTable.column_num; i++)
	{
		column = x4msMtaTable.columns[i];

		if(x4msMtaIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = x4msMtaIndex;
			oid.len = column->name->len + 1;
			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, X4MS_MTA_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
X4msMtaEntry *x4msMtaEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	X4msMtaEntry *x4msMtaEntry;
	int32_t x4msMtaIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: x4msMtaEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	x4msMtaEntry = (X4msMtaEntry *) malloc(sizeof(X4msMtaEntry));
	if(x4msMtaEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(x4msMtaEntry, 0, sizeof(X4msMtaEntry));

	pointer = (uintptr_t)&(x4msMtaEntry->x4msMtaName);
	variable = response->first_variable;
	for(i = 0; i < x4msMtaTable.column_num; i++)
	{
		column = x4msMtaTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			x4msMtaEntry_free(x4msMtaEntry);
			return NULL;
		}

		/* check oid and extract x4msMtaIndex */
		if(extract_one_index_from_column(&(variable->name), column->name, &x4msMtaIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			x4msMtaEntry_free(x4msMtaEntry);
			return NULL;
		}

		/* check if all x4msMtaIndex are equal ??? */
		x4msMtaEntry->x4msMtaIndex = x4msMtaIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			x4msMtaEntry_free(x4msMtaEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			x4msMtaEntry_free(x4msMtaEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return x4msMtaEntry;
}


/***************************************************************/

void x4msMtaEntry_free(X4msMtaEntry *x4msMtaEntry)
{
	if(x4msMtaEntry == NULL)
	{
		return;
	}

	if(x4msMtaEntry->x4msMtaName)
	{
		free(x4msMtaEntry->x4msMtaName);
	}
	free(x4msMtaEntry);
}


/***************************************************************/

void x4msMtaEntry_print(X4msMtaEntry *x4msMtaEntry)
{
	printf("x4msMtaIndex:                         %ld\n",
		x4msMtaEntry->x4msMtaIndex);
	printf("x4msMtaName                           %s\n",
		x4msMtaEntry->x4msMtaName);
	printf("\n");
}


/***************************************************************/
/***************************************************************/

int x4msUserEntryPart1_send_request(SNMP_session *session, u_char type, int32_t x4msUserIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: x4msUserEntryPart1_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < x4msUserTablePart1.column_num; i++)
	{
		column = x4msUserTablePart1.columns[i];

		if(x4msUserIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = x4msUserIndex;
			oid.len = column->name->len + 1;
			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, X4MS_USER_ENTRY_PART1_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}


/***************************************************************/

/* ARGSUSED */
X4msUserEntryPart1 *x4msUserEntryPart1_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	X4msUserEntryPart1 *x4msUserEntryPart1;
	int32_t x4msUserIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: x4msUserEntryPart1_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	x4msUserEntryPart1 = (X4msUserEntryPart1 *) malloc(sizeof(X4msUserEntryPart1));
	if(x4msUserEntryPart1 == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(x4msUserEntryPart1, 0, sizeof(X4msUserEntryPart1));

	pointer = (uintptr_t) &(x4msUserEntryPart1->x4msUserTotalMessages);
	variable = response->first_variable;
	for(i = 0; i < x4msUserTablePart1.column_num; i++)
	{
		column = x4msUserTablePart1.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			x4msUserEntryPart1_free(x4msUserEntryPart1);
			return NULL;
		}

		/* check oid and extract x4msMtaIndex */
		if(extract_one_index_from_column(&(variable->name), column->name, &x4msUserIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			x4msUserEntryPart1_free(x4msUserEntryPart1);
			return NULL;
		}

		/* check if all x4msUserIndex are equal ??? */
		x4msUserEntryPart1->x4msUserIndex = x4msUserIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			x4msUserEntryPart1_free(x4msUserEntryPart1);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			x4msUserEntryPart1_free(x4msUserEntryPart1);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return x4msUserEntryPart1;
}


/***************************************************************/

void x4msUserEntryPart1_free(X4msUserEntryPart1 *x4msUserEntryPart1)
{
	if(x4msUserEntryPart1 == NULL)
	{
		return;
	}

	if(x4msUserEntryPart1->x4msUserAuthentificationFailureReason)
	{
		free(x4msUserEntryPart1->x4msUserAuthentificationFailureReason);
	}
	if(x4msUserEntryPart1->x4msUserName)
	{
		free(x4msUserEntryPart1->x4msUserName);
	}
	free(x4msUserEntryPart1);
}


/***************************************************************/

void x4msUserEntryPart1_print(X4msUserEntryPart1 *x4msUserEntryPart1)
{
	printf("x4msUserIndex:                        %ld\n",
		x4msUserEntryPart1->x4msUserIndex);
	printf("x4msUserTotalMessages:                %ld\n",
		x4msUserEntryPart1->x4msUserTotalMessages);
	printf("x4msUserTotalVolume:                  %ld\n",
		x4msUserEntryPart1->x4msUserTotalVolume);
	printf("x4msUserP3Associations:               %ld\n",
		x4msUserEntryPart1->x4msUserP3Associations);
	printf("x4msUserP7Associations:               %ld\n",
		x4msUserEntryPart1->x4msUserP7Associations);
	printf("x4msUserLastP7Association:            %ld\n",
		x4msUserEntryPart1->x4msUserLastP7Association);
	printf("x4msUserAuthentificationFailures:     %ld\n",
		x4msUserEntryPart1->x4msUserAuthentificationFailures);
	printf("x4msUserAuthentificationFailureReason:%s\n",
		x4msUserEntryPart1->x4msUserAuthentificationFailureReason);
	printf("x4msUserName:                         %s\n",
		x4msUserEntryPart1->x4msUserName);
	printf("\n");
}


/***************************************************************/
/***************************************************************/

int x4msUserEntryPart2_send_request(SNMP_session *session, u_char type, int32_t x4msUserIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: x4msUserEntryPart2_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < x4msUserTablePart2.column_num; i++)
	{
		column = x4msUserTablePart2.columns[i];

		if(x4msUserIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = x4msUserIndex;
			oid.len = column->name->len + 1;
			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, X4MS_USER_ENTRY_PART2_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}

/* ARGSUSED */
X4msUserEntryPart2 *x4msUserEntryPart2_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	X4msUserEntryPart2 *x4msUserEntryPart2;
	int32_t x4msUserIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: x4msUserEntryPart2_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	x4msUserEntryPart2 = (X4msUserEntryPart2 *) malloc(sizeof(X4msUserEntryPart2));
	if(x4msUserEntryPart2 == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(x4msUserEntryPart2, 0, sizeof(X4msUserEntryPart2));

	pointer = (uintptr_t) &(x4msUserEntryPart2->x4msUserNewMessages);
	variable = response->first_variable;
	for(i = 0; i < x4msUserTablePart2.column_num; i++)
	{
		column = x4msUserTablePart2.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			x4msUserEntryPart2_free(x4msUserEntryPart2);
			return NULL;
		}

		/* check oid and extract x4msUserIndex */
		if(extract_one_index_from_column(&(variable->name), column->name, &x4msUserIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			x4msUserEntryPart2_free(x4msUserEntryPart2);
			return NULL;
		}

		/* check if all x4msUserIndex are equal ??? */
		x4msUserEntryPart2->x4msUserIndex = x4msUserIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			x4msUserEntryPart2_free(x4msUserEntryPart2);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			x4msUserEntryPart2_free(x4msUserEntryPart2);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return x4msUserEntryPart2;
}


/***************************************************************/

void x4msUserEntryPart2_free(X4msUserEntryPart2 *x4msUserEntryPart2)
{
	if(x4msUserEntryPart2 == NULL)
	{
		return;
	}

	if(x4msUserEntryPart2->x4msUserP3InboundRejectionReason)
	{
		free(x4msUserEntryPart2->x4msUserP3InboundRejectionReason);
	}
	if(x4msUserEntryPart2->x4msUserP7InboundRejectionReason)
	{
		free(x4msUserEntryPart2->x4msUserP7InboundRejectionReason);
	}
	if(x4msUserEntryPart2->x4msUserP3OutboundConnectFailureReason)
	{
		free(x4msUserEntryPart2->x4msUserP3OutboundConnectFailureReason);
	}
	if(x4msUserEntryPart2->x4msUserORName)
	{
		free(x4msUserEntryPart2->x4msUserORName);
	}
	free(x4msUserEntryPart2);
}


/***************************************************************/

void x4msUserEntryPart2_print(X4msUserEntryPart2 *x4msUserEntryPart2)
{
	printf("x4msUserIndex:                        %ld\n",
		x4msUserEntryPart2->x4msUserIndex);
	printf("x4msUserNewMessages:                  %ld\n",
		x4msUserEntryPart2->x4msUserNewMessages);
	printf("x4msUserNewVolume:                    %ld\n",
		x4msUserEntryPart2->x4msUserNewVolume);
	printf("x4msUserListedMessages:               %ld\n",
		x4msUserEntryPart2->x4msUserListedMessages);
	printf("x4msUserListedVolume:                 %ld\n",
		x4msUserEntryPart2->x4msUserListedVolume);
	printf("x4msUserProcessedMessages:            %ld\n",
		x4msUserEntryPart2->x4msUserProcessedMessages);
	printf("x4msUserProcessedVolume:              %ld\n",
		x4msUserEntryPart2->x4msUserProcessedVolume);
	printf("x4msUserMessagesOlderThanWeek:        %ld\n",
		x4msUserEntryPart2->x4msUserMessagesOlderThanWeek);
	printf("x4msUserVolumeOlderThanWeek:          %ld\n",
		x4msUserEntryPart2->x4msUserVolumeOlderThanWeek);
	printf("x4msUserMessagesOlderThanMonth:       %ld\n",
		x4msUserEntryPart2->x4msUserMessagesOlderThanMonth);
	printf("x4msUserVolumeOlderThanMonth:         %ld\n",
		x4msUserEntryPart2->x4msUserVolumeOlderThanMonth);
	printf("x4msUserMessagesOlderThanYear:        %ld\n",
		x4msUserEntryPart2->x4msUserMessagesOlderThanYear);
	printf("x4msUserP3InboundAssociations:        %ld\n",
		x4msUserEntryPart2->x4msUserP3InboundAssociations);
	printf("x4msUserP7InboundAssociations:        %ld\n",
		x4msUserEntryPart2->x4msUserP7InboundAssociations);
	printf("x4msUserP3OutboundAssociations:       %ld\n",
		x4msUserEntryPart2->x4msUserP3OutboundAssociations);
	printf("x4msUserAccumulatedP3InboundAssoc.:   %ld\n",
		x4msUserEntryPart2->x4msUserAccumulatedP3InboundAssociations);
	printf("x4msUserAccumulatedP7InboundAssoc.:   %ld\n",
		x4msUserEntryPart2->x4msUserAccumulatedP7InboundAssociations);
	printf("x4msUserAccumulatedP3OutboundAssoc.:  %ld\n",
		x4msUserEntryPart2->x4msUserAccumulatedP3OutboundAssociations);
	printf("x4msUserLastP3InboundActivity:        %ld\n",
		x4msUserEntryPart2->x4msUserLastP3InboundActivity);
	printf("x4msUserLastP7InboundActivity:        %ld\n",
		x4msUserEntryPart2->x4msUserLastP7InboundActivity);
	printf("x4msUserLastP3OutboundActivity:       %ld\n",
		x4msUserEntryPart2->x4msUserLastP3OutboundActivity);
	printf("x4msUserRejectedP3InboundAssoc.:      %ld\n",
		x4msUserEntryPart2->x4msUserRejectedP3InboundAssociations);
	printf("x4msUserRejectedP7InboundAssoc.:      %ld\n",
		x4msUserEntryPart2->x4msUserRejectedP7InboundAssociations);
	printf("x4msUserFailedP3OutboundAssociations: %ld\n",
		x4msUserEntryPart2->x4msUserFailedP3OutboundAssociations);
	printf("x4msUserP3InboundRejectionReason:     %s\n",
		x4msUserEntryPart2->x4msUserP3InboundRejectionReason);
	printf("x4msUserP7InboundRejectionReason:     %s\n",
		x4msUserEntryPart2->x4msUserP7InboundRejectionReason);
	printf("x4msUserP3OutboundConnectFailureRea.: %s\n",
		x4msUserEntryPart2->x4msUserP3OutboundConnectFailureReason);
	printf("x4msUserMtaIndex:                     %ld\n",
		x4msUserEntryPart2->x4msUserMtaIndex);
	printf("x4msUserORName:                       %s\n",
		x4msUserEntryPart2->x4msUserORName);
	printf("\n");
}


/***************************************************************/
/***************************************************************/

int x4msUserAssociationEntry_send_request(SNMP_session *session, u_char type, int32_t x4msUserIndex, int32_t x4msUserAssociationIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: x4msUserAssociationEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < x4msUserAssociationTable.column_num; i++)
	{
		column = x4msUserAssociationTable.columns[i];

		if(x4msUserIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = x4msUserIndex;
			oid.len = column->name->len + 1;

			if(x4msUserAssociationIndex >= 0)
			{
				subids[column->name->len + 1] = x4msUserAssociationIndex;
				oid.len = column->name->len + 2;
			}

			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, X4MS_USER_ASSOCIATION_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}

/* ARGSUSED */
X4msUserAssociationEntry *x4msUserAssociationEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	X4msUserAssociationEntry *x4msUserAssociationEntry;
	int32_t x4msUserIndex;
	int32_t x4msUserAssociationIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: x4msUserAssociationEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	x4msUserAssociationEntry = (X4msUserAssociationEntry *) malloc(sizeof(X4msUserAssociationEntry));
	if(x4msUserAssociationEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(x4msUserAssociationEntry, 0, sizeof(X4msUserAssociationEntry));

	pointer = (uintptr_t) &(x4msUserAssociationEntry->x4msUserAssociationIndex);
	variable = response->first_variable;
	for(i = 0; i < x4msUserAssociationTable.column_num; i++)
	{
		column = x4msUserAssociationTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			x4msUserAssociationEntry_free(x4msUserAssociationEntry);
			return NULL;
		}

		/* check oid and extract x4msUserIndex and x4msUserAssociationIndex */
		if(extract_two_indexes_from_column(&(variable->name), column->name, &x4msUserIndex, &x4msUserAssociationIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			x4msUserAssociationEntry_free(x4msUserAssociationEntry);
			return NULL;
		}

		/* check if all x4msUserIndex are equal ??? */
		x4msUserAssociationEntry->x4msUserIndex = x4msUserIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			x4msUserAssociationEntry_free(x4msUserAssociationEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			x4msUserAssociationEntry_free(x4msUserAssociationEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return x4msUserAssociationEntry;
}


/***************************************************************/

void x4msUserAssociationEntry_free(X4msUserAssociationEntry *x4msUserAssociationEntry)
{
	if(x4msUserAssociationEntry == NULL)
	{
		return;
	}

	free(x4msUserAssociationEntry);
}


/***************************************************************/

void x4msUserAssociationEntry_print(X4msUserAssociationEntry *x4msUserAssociationEntry)
{
	printf("x4msUserIndex:                        %ld\n",
		x4msUserAssociationEntry->x4msUserIndex);
	printf("x4msUserAssociationIndex:             %ld\n",
		x4msUserAssociationEntry->x4msUserAssociationIndex);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int x4grpEntry_send_request(SNMP_session *session, u_char type, int32_t x4grpIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: x4grpEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < x4grpTable.column_num; i++)
	{
		column = x4grpTable.columns[i];

		if(x4grpIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = x4grpIndex;
			oid.len = column->name->len + 1;
			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, X4GRP_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}

/* ARGSUSED */
X4grpEntry *x4grpEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	X4grpEntry *x4grpEntry;
	int32_t x4grpIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: x4grpEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	x4grpEntry = (X4grpEntry *) malloc(sizeof(X4grpEntry));
	if(x4grpEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(x4grpEntry, 0, sizeof(X4grpEntry));

	pointer = (uintptr_t) &(x4grpEntry->x4grpName);
	variable = response->first_variable;
	for(i = 0; i < x4grpTable.column_num; i++)
	{
		column = x4grpTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			x4grpEntry_free(x4grpEntry);
			return NULL;
		}

		/* check oid and extract x4grpIndex */
		if(extract_one_index_from_column(&(variable->name), column->name, &x4grpIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			x4grpEntry_free(x4grpEntry);
			return NULL;
		}

		/* check if all x4grpIndex are equal ??? */
		x4grpEntry->x4grpIndex = x4grpIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			x4grpEntry_free(x4grpEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			x4grpEntry_free(x4grpEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return x4grpEntry;
}


/***************************************************************/

void x4grpEntry_free(X4grpEntry *x4grpEntry)
{
	if(x4grpEntry == NULL)
	{
		return;
	}

	if(x4grpEntry->x4grpName)
	{
		free(x4grpEntry->x4grpName);
	}
	free(x4grpEntry);
}


/***************************************************************/

void x4grpEntry_print(X4grpEntry *x4grpEntry)
{
	printf("x4grpIndex:                           %ld\n",
		x4grpEntry->x4grpIndex);
	printf("x4grpName:                            %s\n",
		x4grpEntry->x4grpName);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int x4grpMappingEntry_send_request(SNMP_session *session, u_char type, int32_t x4grpIndex, int32_t x4grpMappingMSIndex, int32_t x4grpMappingMTAIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: x4grpMappingEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < x4grpMappingTable.column_num; i++)
	{
		column = x4grpMappingTable.columns[i];

		if(x4grpIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = x4grpIndex;
			oid.len = column->name->len + 1;

			if(x4grpMappingMSIndex >= 0)
			{
				subids[column->name->len + 1] = x4grpMappingMSIndex;
				oid.len = column->name->len + 2;

				if(x4grpMappingMTAIndex >= 0)
				{
					subids[column->name->len + 2] = x4grpMappingMTAIndex;
					oid.len = column->name->len + 3;
				}
			}

			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, X4GRP_MAPPING_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}

/* ARGSUSED */
X4grpMappingEntry *x4grpMappingEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	X4grpMappingEntry *x4grpMappingEntry;
	int32_t x4grpIndex;
	int32_t x4grpMappingMSIndex;
	int32_t x4grpMappingMTAIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: x4grpMappingEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	x4grpMappingEntry = (X4grpMappingEntry *) malloc(sizeof(X4grpMappingEntry));
	if(x4grpMappingEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(x4grpMappingEntry, 0, sizeof(X4grpMappingEntry));

	pointer = (uintptr_t) &(x4grpMappingEntry->x4grpMappingMSIndex);
	variable = response->first_variable;
	for(i = 0; i < x4grpMappingTable.column_num; i++)
	{
		column = x4grpMappingTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			x4grpMappingEntry_free(x4grpMappingEntry);
			return NULL;
		}

		/* check oid and extract x4grpIndex, x4grpMappingMSIndex and x4grpMappingMTAIndex */
		if(extract_three_indexes_from_column(&(variable->name), column->name, &x4grpIndex, &x4grpMappingMSIndex, &x4grpMappingMTAIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			x4grpMappingEntry_free(x4grpMappingEntry);
			return NULL;
		}

		/* check if all x4grpIndex are equal ??? */
		x4grpMappingEntry->x4grpIndex = x4grpIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			x4grpMappingEntry_free(x4grpMappingEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			x4grpMappingEntry_free(x4grpMappingEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return x4grpMappingEntry;
}


/***************************************************************/

void x4grpMappingEntry_free(X4grpMappingEntry *x4grpMappingEntry)
{
	if(x4grpMappingEntry == NULL)
	{
		return;
	}

	free(x4grpMappingEntry);
}


/***************************************************************/

void x4grpMappingEntry_print(X4grpMappingEntry *x4grpMappingEntry)
{
	printf("x4grpIndex:                           %ld\n",
		x4grpMappingEntry->x4grpIndex);
	printf("x4grpMappingMSIndex:                  %ld\n",
		x4grpMappingEntry->x4grpMappingMSIndex);
	printf("x4grpMappingMTAIndex:                 %ld\n",
		x4grpMappingEntry->x4grpMappingMTAIndex);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

int x5dsaReferenceEntry_send_request(SNMP_session *session, u_char type, int32_t x5dsaReferenceIndex, char *error_label)
{
	SNMP_pdu *request;
	int i;
	SNMP_column *column;
	Subid subids[100] = { 0 };
	Oid oid;
	Oid *oidp;


	error_label[0] = '\0';

	if( (type != GET_REQ_MSG) && (type != GETNEXT_REQ_MSG) )
	{
		sprintf(error_label, "BUG: x5dsaReferenceEntry_send_request(): bad type (0x%x)", type);
		return -1;
	}

	request = snmp_pdu_new(error_label);
	if(request == NULL)
	{
		return -1;
	}
	request->type = type;

	for(i = 0; i < x5dsaReferenceTable.column_num; i++)
	{
		column = x5dsaReferenceTable.columns[i];

		if(x5dsaReferenceIndex >= 0)
		{
			memcpy(subids, column->name->subids, column->name->len*sizeof(Subid));
			subids[column->name->len] = x5dsaReferenceIndex;
			oid.len = column->name->len + 1;
			oid.subids = subids;
			oidp = &oid;
		}
		else
		{
			oidp = column->name;
		}

		if(snmp_pdu_append_null_variable(request, oidp, error_label) == NULL)
		{
			snmp_pdu_free(request);
			return -1;
		}
	}

	if(snmp_session_send(session, X5DSA_REFERENCE_ENTRY_REQ, request, error_label))
	{
		/* we have to free the request */

		snmp_pdu_free(request);
		return -1;
	}


	return 0;
}

/* ARGSUSED */
X5dsaReferenceEntry *x5dsaReferenceEntry_process_response(SNMP_session *session, SNMP_pdu *response, char *error_label)
{
	X5dsaReferenceEntry *x5dsaReferenceEntry;
	int32_t x5dsaReferenceIndex;
	SNMP_variable *variable;
	uintptr_t pointer;
	int i;
	SNMP_column *column;


	snmp_errno = SNMP_ERR_NOERROR;
	error_label[0] = '\0';

	if(response == NULL)
	{
		sprintf(error_label, "BUG: x5dsaReferenceEntry_process_response(): response is NULL");
		return NULL;
	}

	if(response->error_status != SNMP_ERR_NOERROR)
	{
		sprintf(error_label, ERR_MSG_ERROR_STATUS,
			error_status_string(response->error_status),
			response->error_index);
		snmp_errno = response->error_status;
		return NULL;
	}

	x5dsaReferenceEntry = (X5dsaReferenceEntry *) malloc(sizeof(X5dsaReferenceEntry));
	if(x5dsaReferenceEntry == NULL)
	{
		sprintf(error_label, ERR_MSG_ALLOC);
		return NULL;
	}
	memset(x5dsaReferenceEntry, 0, sizeof(X5dsaReferenceEntry));

	pointer = (uintptr_t) &(x5dsaReferenceEntry->x5dsaReferenceType);
	variable = response->first_variable;
	for(i = 0; i < x5dsaReferenceTable.column_num; i++)
	{
		column = x5dsaReferenceTable.columns[i];

		if(variable == NULL)
		{
			sprintf(error_label, ERR_MSG_MISSING_VARIABLES);
			x5dsaReferenceEntry_free(x5dsaReferenceEntry);
			return NULL;
		}

		/* check oid and extract x5dsaReferenceIndex */
		if(extract_one_index_from_column(&(variable->name), column->name, &x5dsaReferenceIndex))
		{
			snmp_errno = SNMP_ERR_NOSUCHNAME;
			x5dsaReferenceEntry_free(x5dsaReferenceEntry);
			return NULL;
		}

		/* check if all x5dsaReferenceIndex are equal ??? */
		x5dsaReferenceEntry->x5dsaReferenceIndex = x5dsaReferenceIndex;

		/* check type */
		if(variable->type != column->type)
		{
			sprintf(error_label, ERR_MSG_BAD_VARIABLE_TYPE,
				variable->type, column->label);
			x5dsaReferenceEntry_free(x5dsaReferenceEntry);
			return NULL;
		}

		if(translate_variable(variable, column->translator, pointer, error_label))
		{
			x5dsaReferenceEntry_free(x5dsaReferenceEntry);
			return NULL;
		}

		variable = variable->next_variable;
		pointer++;
	}


	return x5dsaReferenceEntry;
}


/***************************************************************/

void x5dsaReferenceEntry_free(X5dsaReferenceEntry *x5dsaReferenceEntry)
{
	if(x5dsaReferenceEntry == NULL)
	{
		return;
	}

	if(x5dsaReferenceEntry->x5dsaReferenceNamingContext)
	{
		free(x5dsaReferenceEntry->x5dsaReferenceNamingContext);
	}
	if(x5dsaReferenceEntry->x5dsaReferenceSubordinate)
	{
		free(x5dsaReferenceEntry->x5dsaReferenceSubordinate);
	}
	if(x5dsaReferenceEntry->x5dsaReferenceName)
	{
		free(x5dsaReferenceEntry->x5dsaReferenceName);
	}
	free(x5dsaReferenceEntry);
}


/***************************************************************/

void x5dsaReferenceEntry_print(X5dsaReferenceEntry *x5dsaReferenceEntry)
{
	printf("x5dsaReferenceIndex:                  %ld\n",
		x5dsaReferenceEntry->x5dsaReferenceIndex);
	printf("x5dsaReferenceType:                   %s\n",
		x5dsaReferenceType_string(x5dsaReferenceEntry->x5dsaReferenceType));
	printf("x5dsaReferenceNamingContext:          %s\n",
		x5dsaReferenceEntry->x5dsaReferenceNamingContext);
	printf("x5dsaReferenceSubordinate:            %s\n",
		x5dsaReferenceEntry->x5dsaReferenceSubordinate);
	printf("x5dsaReferenceName:                   %s\n",
		x5dsaReferenceEntry->x5dsaReferenceName);
	printf("\n");
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

char *
applOperStatus_string(int32_t applOperStatus)
{
	static char buffer[20];

	switch(applOperStatus)
	{
		case APPL_UP:
			sprintf(buffer, "up");
			break;
		case APPL_DOWN:
			sprintf(buffer, "down");
			break;
		case APPL_HALTED:
			sprintf(buffer, "halted");
			break;
		case APPL_CONGESTED:
			sprintf(buffer, "congested");
			break;
		case APPL_RESTARTING:
			sprintf(buffer, "restarting");
			break;
		default:
			sprintf(buffer, "unknown(%ld)", applOperStatus);
			break;
	}

	return buffer;
}


/***************************************************************/

char *
assocApplicationType_string(int32_t assocApplicationType)
{
	static char buffer[20];

	switch(assocApplicationType)
	{
		case ASSOC_UA_INITIATOR:
			sprintf(buffer, "ua-initiator");
			break;
		case ASSOC_UA_RESPONDER:
			sprintf(buffer, "ua-responder");
			break;
		case ASSOC_PEER_INITIATOR:
			sprintf(buffer, "peer-initiator");
			break;
		case ASSOC_PEER_RESPONDER:
			sprintf(buffer, "peer-responder");
			break;
		default:
			sprintf(buffer, "unknown(%ld)", assocApplicationType);
			break;
	}

	return buffer;
}


/***************************************************************/

char *x5dsaReferenceType_string(int32_t x5dsaReferenceType)
{
	static char buffer[30];

	switch(x5dsaReferenceType)
	{
		case REFERENCE_SUPERIOR:
			sprintf(buffer, "superior");
			break;
		case REFERENCE_CROSS:
			sprintf(buffer, "cross");
			break;
		case REFERENCE_SUBORDINATE:
			sprintf(buffer, "subordinate");
			break;
		case REFERENCE_NON_SPECIFIC_SUBORDINATE:
			sprintf(buffer, "non-specific-subordinate");
			break;
		default:
			sprintf(buffer, "unknown(%ld)", x5dsaReferenceType);
			break;
	}

	return buffer;
}


/***************************************************************/
/***************************************************************/
/***************************************************************/

char *predefined_request_string(int predefined_id)
{
	static char buffer[50];

	switch(predefined_id)
	{
		case SYSUPTIME_REQ:
			sprintf(buffer, "sysUpTime");
			break;
		case APPL_ENTRY_REQ:
			sprintf(buffer, "applEntry");
			break;
		case ASSOC_ENTRY_REQ:
			sprintf(buffer, "assocEntry");
			break;
		case MTA_ENTRY_REQ:
			sprintf(buffer, "mtaEntry");
			break;
		case MTA_GROUP_ENTRY_REQ:
			sprintf(buffer, "mtaGroupEntry");
			break;
		case MTA_GROUP_ASSOCIATION_ENTRY_REQ:
			sprintf(buffer, "mtaGroupAssociationEntry");
			break;
		case DSA_OPS_ENTRY_REQ:
			sprintf(buffer, "dsaOpsEntry");
			break;
		case DSA_ENTRIES_ENTRY_REQ:
			sprintf(buffer, "dsaEntriesEntry");
			break;
		case DSA_INT_ENTRY_REQ:
			sprintf(buffer, "dsaIntEntry");
			break;
		case X4MS_MTA_ENTRY_REQ:
			sprintf(buffer, "x4msMtaEntry");
			break;
		case X4MS_USER_ENTRY_PART1_REQ:
			sprintf(buffer, "x4msUserEntryPart1");
			break;
		case X4MS_USER_ENTRY_PART2_REQ:
			sprintf(buffer, "x4msUserEntryPart2");
			break;
		case X4MS_USER_ASSOCIATION_ENTRY_REQ:
			sprintf(buffer, "x4msUserAssociationEntry");
			break;
		case X4GRP_ENTRY_REQ:
			sprintf(buffer, "x4grpEntry");
			break;
		case X4GRP_MAPPING_ENTRY_REQ:
			sprintf(buffer, "x4grpMappingEntry");
			break;
		case X5DSA_REFERENCE_ENTRY_REQ:
			sprintf(buffer, "x5dsaReferenceEntry");
			break;
		default:
			sprintf(buffer, "error(%d)", predefined_id);
			break;
	}

	return buffer;
}

static int
translate_variable(SNMP_variable *variable, int translator, uintptr_t pointer, char *error_label)
{
	error_label[0] = '\0';

	switch(translator)
	{
		case TO_INTEGER:
			*(long *)pointer = (long) *(variable->val.integer);
			break;

		case TO_ASCII: {
			char ** ptr = ((char **)pointer);

			*ptr = malloc(variable->val_len + 1);
			if(*ptr == NULL) {
				sprintf(error_label, ERR_MSG_ALLOC);
				return -1;
			}
			memcpy(*ptr, variable->val.string, variable->val_len);
			((char *) (*ptr))[variable->val_len] = '\0';
			if(variable->val.string)
			{
				free(variable->val.string);
				variable->val.string = NULL;
			}
			variable->val_len = NULL;
			}

			break;

		case TO_STRING: {
			char ** ptr = ((char **)pointer);

			*ptr = malloc(sizeof(String));
			if(*ptr == NULL)
			{
				sprintf(error_label, ERR_MSG_ALLOC);
				return -1;
			}
			((String *) *ptr)->len = variable->val_len;
			((String *) *ptr)->chars = variable->val.string;
			variable->val_len = 0;
			variable->val.string = NULL;
			}

			break;

		case TO_OID: {
			Oid ** ptr = (Oid **)pointer;
			*ptr = (Oid *)malloc(sizeof(Oid));
			if(*ptr == NULL)
			{
				sprintf(error_label, ERR_MSG_ALLOC);
				return -1;
			}
			((Oid *) *ptr)->len = (variable->val_len) /
				(int32_t)sizeof(Subid);
			((Oid *) *ptr)->subids = variable->val.objid;
			variable->val_len = 0;
			variable->val.string = NULL;
			}

			break;
	}

	return 0;
}


/***************************************************************/

static int
extract_one_index_from_column(Oid *instance, Oid *object, int32_t * index)
{
	if(instance->len != object->len + 1)
		return -1;

	if(memcmp(instance->subids, object->subids, object->len * (int32_t)sizeof(Subid)))
		return -1;

	*index = instance->subids[object->len];

	return 0;
}


/***************************************************************/

static int
extract_two_indexes_from_column(Oid *instance, Oid *object, int32_t *index1, int32_t *index2)
{
	if(instance->len != object->len + 2)
		return -1;

	if(memcmp(instance->subids, object->subids, object->len * sizeof(Subid)))
		return -1;

	*index1 = instance->subids[object->len];
	*index2 = instance->subids[object->len + 1];

	return 0;
}


/***************************************************************/

static int
extract_three_indexes_from_column(Oid *instance, Oid *object, int32_t *index1, int32_t *index2, int32_t *index3)
{
	if(instance->len != object->len + 3)
		return -1;

	if(memcmp(instance->subids, object->subids, object->len * sizeof(Subid)))
		return -1;

	*index1 = instance->subids[object->len];
	*index2 = instance->subids[object->len + 1];
	*index3 = instance->subids[object->len + 2];

	return 0;
}

