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

#ifndef _MADMAN_API_H_
#define _MADMAN_API_H_

#include <sys/types.h>
#include "snmp_api.h"


/***** GLOBAL CONSTANTS *****/


/* predefined request values */

#define SYSUPTIME_REQ			1

#define APPL_ENTRY_REQ			11
#define ASSOC_ENTRY_REQ			12

#define MTA_ENTRY_REQ			21
#define MTA_GROUP_ENTRY_REQ		22
#define MTA_GROUP_ASSOCIATION_ENTRY_REQ	23

#define DSA_OPS_ENTRY_REQ		31
#define DSA_ENTRIES_ENTRY_REQ		32
#define DSA_INT_ENTRY_REQ		33

#define X4MS_MTA_ENTRY_REQ		101
#define X4MS_USER_ENTRY_PART1_REQ	102
#define X4MS_USER_ENTRY_PART2_REQ	103
#define X4MS_USER_ASSOCIATION_ENTRY_REQ	104

#define X4GRP_ENTRY_REQ			201
#define X4GRP_MAPPING_ENTRY_REQ		202

#define X5DSA_REFERENCE_ENTRY_REQ	401


/* applStatus values */

#define APPL_UP			1
#define APPL_DOWN		2
#define APPL_HALTED		3
#define APPL_CONGESTED		4
#define APPL_RESTARTING		5


/* assocApplicationType values */

#define ASSOC_UA_INITIATOR	1
#define ASSOC_UA_RESPONDER	2
#define ASSOC_PEER_INITIATOR	3
#define ASSOC_PEER_RESPONDER	4


/* x5dsaReferenceType values */

#define REFERENCE_SUPERIOR			1
#define REFERENCE_CROSS				2
#define REFERENCE_SUBORDINATE			3
#define REFERENCE_NON_SPECIFIC_SUBORDINATE	4


/***** GLOBAL TYPES *****/

/**********/
/* MIB II */
/**********/

typedef int32_t SysUpTime;


/************/
/* RFC 1565 */
/************/

typedef struct _ApplEntry {
	int32_t	applIndex;
	char	*applName;
	char	*applDirectoryName;
	char	*applVersion;
	int32_t	applUptime;
	int32_t	applOperStatus;
	int32_t	applLastChange;
	int32_t	applInboundAssociations;
	int32_t	applOutboundAssociations;
	int32_t	applAccumulatedInboundAssociations;
	int32_t	applAccumulatedOutboundAssociations;
	int32_t	applLastInboundActivity;
	int32_t	applLastOutboundActivity;
	int32_t	applRejectedInboundAssociations;
	int32_t	applFailedOutboundAssociations;
} ApplEntry;

typedef struct _AssocEntry {
	int32_t	applIndex;
	int32_t	assocIndex;
	char	*assocRemoteApplication;
	Oid	*assocApplicationProtocol;
	int32_t	assocApplicationType;
	int32_t	assocDuration;
} AssocEntry;


/************/
/* RFC 1566 */
/************/

typedef struct _MtaEntry {
	int32_t	applIndex;
	int32_t	mtaReceivedMessages;
	int32_t	mtaStoredMessages;
	int32_t	mtaTransmittedMessages;
	int32_t	mtaReceivedVolume;
	int32_t	mtaStoredVolume;
	int32_t	mtaTransmittedVolume;
	int32_t	mtaReceivedRecipients;
	int32_t	mtaStoredRecipients;
	int32_t	mtaTransmittedRecipients;
} MtaEntry;

typedef struct _MtaGroupEntry {
	int32_t	applIndex;
	int32_t	mtaGroupIndex;
	int32_t	mtaGroupReceivedMessages;
	int32_t	mtaGroupRejectedMessages;
	int32_t	mtaGroupStoredMessages;
	int32_t	mtaGroupTransmittedMessages;
	int32_t	mtaGroupReceivedVolume;
	int32_t	mtaGroupStoredVolume;
	int32_t	mtaGroupTransmittedVolume;
	int32_t	mtaGroupReceivedRecipients;
	int32_t	mtaGroupStoredRecipients;
	int32_t	mtaGroupTransmittedRecipients;
	int32_t	mtaGroupOldestMessageStored;
	int32_t	mtaGroupInboundAssociations;
	int32_t	mtaGroupOutboundAssociations;
	int32_t	mtaGroupAccumulatedInboundAssociations;
	int32_t	mtaGroupAccumulatedOutboundAssociations;
	int32_t	mtaGroupLastInboundActivity;
	int32_t	mtaGroupLastOutboundActivity;
	int32_t	mtaGroupRejectedInboundAssociations;
	int32_t	mtaGroupFailedOutboundAssociations;
	char	*mtaGroupInboundRejectionReason;
	char	*mtaGroupOutboundConnectFailureReason;
	int32_t	mtaGroupScheduledRetry;
	Oid	*mtaGroupMailProtocol;
	char	*mtaGroupName;
} MtaGroupEntry;

typedef struct _MtaGroupAssociationEntry {
	int32_t	applIndex;
	int32_t	mtaGroupIndex;
	int32_t	mtaGroupAssociationIndex;
} MtaGroupAssociationEntry;


/************/
/* RFC 1567 */
/************/

typedef struct _DsaOpsEntry {
	int32_t	applIndex;
	int32_t	dsaAnonymousBinds;
	int32_t	dsaUnauthBinds;
	int32_t	dsaSimpleAuthBinds;
	int32_t	dsaStrongAuthBinds;
	int32_t	dsaBindSecurityErrors;
	int32_t	dsaInOps;
	int32_t	dsaReadOps;
	int32_t	dsaCompareOps;
	int32_t	dsaAddEntryOps;
	int32_t	dsaRemoveEntryOps;
	int32_t	dsaModifyEntryOps;
	int32_t	dsaModifyRDNOps;
	int32_t	dsaListOps;
	int32_t	dsaSearchOps;
	int32_t	dsaOneLevelSearchOps;
	int32_t	dsaWholeTreeSearchOps;
	int32_t	dsaReferrals;
	int32_t	dsaChainings;
	int32_t	dsaSecurityErrors;
	int32_t	dsaErrors;
} DsaOpsEntry;

typedef struct _DsaEntriesEntry {
	int32_t	applIndex;
	int32_t	dsaMasterEntries;
	int32_t	dsaCopyEntries;
	int32_t	dsaCacheEntries;
	int32_t	dsaCacheHits;
	int32_t	dsaSlaveHits;
} DsaEntriesEntry;

typedef struct _DsaIntEntry {
	int32_t	applIndex;
	int32_t	dsaIntIndex;
	char	*dsaName;
	int32_t	dsaTimeOfCreation;
	int32_t	dsaTimeOfLastAttempt;
	int32_t	dsaTimeOfLastSuccess;
	int32_t	dsaFailuresSinceLastSuccess;
	int32_t	dsaFailures;
	int32_t	dsaSuccesses;
} DsaIntEntry;


/************/
/* X4MS MIB */
/************/

typedef struct _X4msMtaEntry {
	int32_t	x4msMtaIndex;
	char	*x4msMtaName;
} X4msMtaEntry;


typedef struct _X4msUserTablePart1 {
	int32_t	x4msUserIndex;
	int32_t	x4msUserTotalMessages;
	int32_t	x4msUserTotalVolume;
	int32_t	x4msUserP3Associations;
	int32_t	x4msUserP7Associations;
	int32_t	x4msUserLastP7Association;
	int32_t	x4msUserAuthentificationFailures;
	char	*x4msUserAuthentificationFailureReason;
	char	*x4msUserName;
} X4msUserEntryPart1;

typedef struct _X4msUserEntryPart2 {
	int32_t	x4msUserIndex;
	int32_t	x4msUserNewMessages;
	int32_t	x4msUserNewVolume;
	int32_t	x4msUserListedMessages;
	int32_t	x4msUserListedVolume;
	int32_t	x4msUserProcessedMessages;
	int32_t	x4msUserProcessedVolume;
	int32_t	x4msUserMessagesOlderThanWeek;
	int32_t	x4msUserVolumeOlderThanWeek;
	int32_t	x4msUserMessagesOlderThanMonth;
	int32_t	x4msUserVolumeOlderThanMonth;
	int32_t	x4msUserMessagesOlderThanYear;
	int32_t	x4msUserVolumeOlderThanYear;
	int32_t	x4msUserP3InboundAssociations;
	int32_t	x4msUserP7InboundAssociations;
	int32_t	x4msUserP3OutboundAssociations;
	int32_t	x4msUserAccumulatedP3InboundAssociations;
	int32_t	x4msUserAccumulatedP7InboundAssociations;
	int32_t	x4msUserAccumulatedP3OutboundAssociations;
	int32_t	x4msUserLastP3InboundActivity;
	int32_t	x4msUserLastP7InboundActivity;
	int32_t	x4msUserLastP3OutboundActivity;
	int32_t	x4msUserRejectedP3InboundAssociations;
	int32_t	x4msUserRejectedP7InboundAssociations;
	int32_t	x4msUserFailedP3OutboundAssociations;
	char	*x4msUserP3InboundRejectionReason;
	char	*x4msUserP7InboundRejectionReason;
	char	*x4msUserP3OutboundConnectFailureReason;
	int32_t	x4msUserMtaIndex;
	char	*x4msUserORName;
} X4msUserEntryPart2;

typedef struct _X4msUserAssociationEntry {
	int32_t	x4msUserIndex;
	int32_t	x4msUserAssociationIndex;
} X4msUserAssociationEntry;


/*************/
/* X4GRP MIB */
/*************/

typedef struct _X4grpEntry {
	int32_t	x4grpIndex;
	char	*x4grpName;
} X4grpEntry;


typedef struct _X4grpMappingEntry {
	int32_t	x4grpIndex;
	int32_t	x4grpMappingMSIndex;
	int32_t	x4grpMappingMTAIndex;
} X4grpMappingEntry;


/*************/
/* X5DSA MIB */
/*************/

typedef struct _X5dsaReferenceEntry {
	int32_t	x5dsaReferenceIndex;
	int32_t	x5dsaReferenceType;
	char	*x5dsaReferenceNamingContext;
	char	*x5dsaReferenceSubordinate;
	char	*x5dsaReferenceName;
} X5dsaReferenceEntry;


/***** GLOBAL VARIABLES *****/

/* SMTP */
extern Oid smtp_name;
extern char smtp_string[];

/* P1 */
extern Oid id_ac_mts_transfer_name;
extern char id_ac_mts_transfer_string[];

/* P3 */
extern Oid id_ac_mts_access_name;
extern Oid id_ac_mts_forced_access_name;
extern Oid id_ac_mts_reliable_access_name;
extern Oid id_ac_mts_forced_reliable_access_name;

/* P7 */
extern Oid id_ac_ms_access_name;
extern Oid id_ac_ms_reliable_access_name;


/***** GLOBAL FUNCTIONS *****/

/**********/
/* MIB II */
/**********/

/* SysUpTime */

int sysUpTime_send_request(SNMP_session *session, char *error_label);
SysUpTime *sysUpTime_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void sysUpTime_free(SysUpTime *sysUpTime);
void sysUpTime_print(SysUpTime *sysUpTime);


/************/
/* RFC 1565 */
/************/

/* ApplEntry */

int applEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t applIndex, char *error_label);
ApplEntry *applEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void applEntry_free(ApplEntry *applEntry);
void applEntry_print(ApplEntry *applEntry);

/* AssocEntry */

int assocEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t applIndex, int32_t assocIndex, char *error_label);
AssocEntry *assocEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void assocEntry_free(AssocEntry *assocEntry);
void assocEntry_print(AssocEntry *assocEntry);

/* miscellaneous */

char *applOperStatus_string(int32_t applStatus);
char *assocApplicationType_string(int32_t applStatus);


/************/
/* RFC 1566 */
/************/

/* MtaEntry */

int mtaEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t applIndex, char *error_label);
MtaEntry *mtaEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void mtaEntry_free(MtaEntry *mtaEntry);
void mtaEntry_print(MtaEntry *mtaEntry);

/* MtaGroupEntry */

int mtaGroupEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t applIndex, int32_t mtaGroupIndex, char *error_label);
MtaGroupEntry *mtaGroupEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void mtaGroupEntry_free(MtaGroupEntry *mtaGroupEntry);
void mtaGroupEntry_print(MtaGroupEntry *mtaGroupEntry);

/* MtaGroupAssociationEntry */

int mtaGroupAssociationEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t applIndex, int32_t mtaGroupIndex,
	int32_t mtaGroupAssociationIndex, char *error_label);
MtaGroupAssociationEntry *mtaGroupAssociationEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void mtaGroupAssociationEntry_free(MtaGroupAssociationEntry *mtaGroupAssociationEntry);
void mtaGroupAssociationEntry_print(MtaGroupAssociationEntry *mtaGroupAssociationEntry);


/************/
/* RFC 1567 */
/************/

/* DsaOpsEntry */

int dsaOpsEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t applIndex, char *error_label);
DsaOpsEntry *dsaOpsEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void dsaOpsEntry_free(DsaOpsEntry *dsaOpsEntry);
void dsaOpsEntry_print(DsaOpsEntry *dsaOpsEntry);

/* DsaEntriesEntry */

int dsaEntriesEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t applIndex, char *error_label);
DsaEntriesEntry *dsaEntriesEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void dsaEntriesEntry_free(DsaEntriesEntry *dsaEntriesEntry);
void dsaEntriesEntry_print(DsaEntriesEntry *dsaEntriesEntry);

/* DsaIntEntry */

int dsaIntEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t applIndex, int32_t dsaIntIndex, char *error_label);
DsaIntEntry *dsaIntEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void dsaIntEntry_free(DsaIntEntry *dsaIntEntry);
void dsaIntEntry_print(DsaIntEntry *dsaIntEntry);


/************/
/* X4MS MIB */
/************/

/* X4msMtaEntry */

int x4msMtaEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t x4msMtaIndex, char *error_label);
X4msMtaEntry *x4msMtaEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void x4msMtaEntry_free(X4msMtaEntry *x4msMtaEntry);
void x4msMtaEntry_print(X4msMtaEntry *x4msMtaEntry);

/* X4msUserEntryPart1 */

int x4msUserEntryPart1_send_request(SNMP_session *session,
	u_char request_type, int32_t x4msUserIndex, char *error_label);
X4msUserEntryPart1 *x4msUserEntryPart1_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void x4msUserEntryPart1_free(X4msUserEntryPart1 *x4msUserEntryPart1);
void x4msUserEntryPart1_print(X4msUserEntryPart1 *x4msUserEntryPart1);


/* X4msUserEntryPart2 */

int x4msUserEntryPart2_send_request(SNMP_session *session,
	u_char request_type, int32_t x4msUserIndex, char *error_label);
X4msUserEntryPart2 *x4msUserEntryPart2_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void x4msUserEntryPart2_free(X4msUserEntryPart2 *x4msUserEntryPart2);
void x4msUserEntryPart2_print(X4msUserEntryPart2 *x4msUserEntryPart2);


/* X4msUserAssociationEntry */

int x4msUserAssociationEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t x4msUserIndex, int32_t x4msUserAssociationIndex, char *error_label);
X4msUserAssociationEntry *x4msUserAssociationEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void x4msUserAssociationEntry_free(X4msUserAssociationEntry *x4msUserAssociationEntry);
void x4msUserAssociationEntry_print(X4msUserAssociationEntry *x4msUserAssociationEntry);


/*************/
/* X4GRP MIB */
/*************/

/* X4grpEntry */

int x4grpEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t x4grpIndex, char *error_label);
X4grpEntry *x4grpEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void x4grpEntry_free(X4grpEntry *x4grpEntry);
void x4grpEntry_print(X4grpEntry *x4grpEntry);

/* X4grpMappingEntry */

int x4grpMappingEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t x4grpIndex, int32_t x4grpMappingMSIndex,
	int32_t x4grpMappingMTAIndex, char *error_label);
X4grpMappingEntry *x4grpMappingEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void x4grpMappingEntry_free(X4grpMappingEntry *x4grpMappingEntry);
void x4grpMappingEntry_print(X4grpMappingEntry *x4grpMappingEntry);


/*************/
/* X5DSA MIB */
/*************/

/* X5dsaReferenceEntry */

int x5dsaReferenceEntry_send_request(SNMP_session *session,
	u_char request_type, int32_t x5dsaReferenceIndex, char *error_label);
X5dsaReferenceEntry *x5dsaReferenceEntry_process_response(SNMP_session *session,
	SNMP_pdu *response, char *error_label);
void x5dsaReferenceEntry_free(X5dsaReferenceEntry *x5dsaReferenceEntry);
void x5dsaReferenceEntry_print(X5dsaReferenceEntry *x5dsaReferenceEntry);

/* miscellaneous */

char *x5dsaReferenceType_string(int32_t x5dsaReferenceType);


/*****************/
/* miscellaneous */
/*****************/

char *predefined_request_string(int predefined_id);


#endif

