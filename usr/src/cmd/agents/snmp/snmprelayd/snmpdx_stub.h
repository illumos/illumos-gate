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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _SNMPDX_STUB_H_
#define _SNMPDX_STUB_H_


typedef struct _AgentEntry_t {
	Integer agentID;
	Integer agentStatus;
	Integer agentTimeOut;
	Integer agentPortNumber;
	String agentPersonalFile;
	String agentConfigFile;
	String agentExecutable;
	String agentVersionNum;
	Integer agentProcessID;
	String agentName;
	Integer agentSystemUpTime;
	Integer agentWatchDogTime;
} AgentEntry_t;

typedef struct _RegTblEntry_t {
	Integer regTblIndex;
	Integer regTblAgentID;
	Oid regTblOID;
	Integer regTblStartColumn;
	Integer regTblEndColumn;
	Integer regTblStartRow;
	Integer regTblEndRow;
	Integer regTblStatus;
} RegTblEntry_t;

typedef struct _RegTreeEntry_t {
	Integer regTreeIndex;
	Integer regTreeAgentID;
	Oid regTreeOID;
	Integer regTreeStatus;
} RegTreeEntry_t;

extern int get_relayProcessIDFile(String *relayProcessIDFile);
extern int set_relayProcessIDFile(int pass, String *relayProcessIDFile);
extern void free_relayProcessIDFile(String *relayProcessIDFile);
extern int get_relayResourceFile(String *relayResourceFile);
extern int set_relayResourceFile(int pass, String *relayResourceFile);
extern void free_relayResourceFile(String *relayResourceFile);
extern int get_relayPersonalFileDir(String *relayPersonalFileDir);
extern int set_relayPersonalFileDir(int pass, String *relayPersonalFileDir);
extern void free_relayPersonalFileDir(String *relayPersonalFileDir);
extern int get_relayTrapPort(Integer *relayTrapPort);
extern int get_relayCheckPoint(String *relayCheckPoint);
extern int set_relayCheckPoint(int pass, String *relayCheckPoint);
extern void free_relayCheckPoint(String *relayCheckPoint);
extern int get_relayPollInterval(Integer *relayPollInterval);
extern int get_relayMaxAgentTimeOut(Integer *relayMaxAgentTimeOut);
extern int get_agentEntry(int search_type, AgentEntry_t **agentEntry_data, IndexType *index);
extern void free_agentEntry(AgentEntry_t *agentEntry);
extern int get_agentID(int search_type, Integer *agentID, IndexType *index);
extern int get_agentStatus(int search_type, Integer *agentStatus, IndexType *index);
extern int set_agentStatus(int pass, IndexType index, Integer *agentStatus);
extern int get_agentTimeOut(int search_type, Integer *agentTimeOut, IndexType *index);
extern int set_agentTimeOut(int pass, IndexType index, Integer *agentTimeOut);
extern int get_agentPortNumber(int search_type, Integer *agentPortNumber, IndexType *index);
extern int set_agentPortNumber(int pass, IndexType index, Integer *agentPortNumber);
extern int get_agentPersonalFile(int search_type, String *agentPersonalFile, IndexType *index);
extern int set_agentPersonalFile(int pass, IndexType index, String *agentPersonalFile);
extern void free_agentPersonalFile(String *agentPersonalFile);
extern int get_agentConfigFile(int search_type, String *agentConfigFile, IndexType *index);
extern int set_agentConfigFile(int pass, IndexType index, String *agentConfigFile);
extern void free_agentConfigFile(String *agentConfigFile);
extern int get_agentExecutable(int search_type, String *agentExecutable, IndexType *index);
extern int set_agentExecutable(int pass, IndexType index, String *agentExecutable);
extern void free_agentExecutable(String *agentExecutable);
extern int get_agentVersionNum(int search_type, String *agentVersionNum, IndexType *index);
extern int set_agentVersionNum(int pass, IndexType index, String *agentVersionNum);
extern void free_agentVersionNum(String *agentVersionNum);
extern int get_agentProcessID(int search_type, Integer *agentProcessID, IndexType *index);
extern int set_agentProcessID(int pass, IndexType index, Integer *agentProcessID);
extern int get_agentName(int search_type, String *agentName, IndexType *index);
extern int set_agentName(int pass, IndexType index, String *agentName);
extern void free_agentName(String *agentName);
extern int get_agentSystemUpTime(int search_type, Integer *agentSystemUpTime, IndexType *index);
extern int set_agentSystemUpTime(int pass, IndexType index, Integer *agentSystemUpTime);
extern int get_agentWatchDogTime(int search_type, Integer *agentWatchDogTime, IndexType *index);
extern int set_agentWatchDogTime(int pass, IndexType index, Integer *agentWatchDogTime);
extern int get_agentTableIndex(Integer *agentTableIndex);
extern int set_agentTableIndex(int pass, Integer* agentTableIndex);
extern int get_regTblEntry(int search_type, RegTblEntry_t **regTblEntry_data, IndexType *index);
extern void free_regTblEntry(RegTblEntry_t *regTblEntry);
extern int get_regTblIndex(int search_type, Integer *regTblIndex, IndexType *index);
extern int get_regTblAgentID(int search_type, Integer *regTblAgentID, IndexType *index);
extern int get_regTblOID(int search_type, Oid *regTblOID, IndexType *index);
extern int set_regTblOID(int pass, IndexType index, Oid *regTblOID);
extern void free_regTblOID(Oid *regTblOID);
extern int get_regTblStartColumn(int search_type, Integer *regTblStartColumn, IndexType *index);
extern int set_regTblStartColumn(int pass, IndexType index, Integer *regTblStartColumn);
extern int get_regTblEndColumn(int search_type, Integer *regTblEndColumn, IndexType *index);
extern int set_regTblEndColumn(int pass, IndexType index, Integer *regTblEndColumn);
extern int get_regTblStartRow(int search_type, Integer *regTblStartRow, IndexType *index);
extern int set_regTblStartRow(int pass, IndexType index, Integer *regTblStartRow);
extern int get_regTblEndRow(int search_type, Integer *regTblEndRow, IndexType *index);
extern int set_regTblEndRow(int pass, IndexType index, Integer *regTblEndRow);
extern int get_regTblStatus(int search_type, Integer *regTblStatus, IndexType *index);
extern int set_regTblStatus(int pass, IndexType index, Integer *regTblStatus);
extern int get_regTblTableIndex(Integer *regTblTableIndex);
extern int get_regTreeEntry(int search_type, RegTreeEntry_t **regTreeEntry_data, IndexType *index);
extern void free_regTreeEntry(RegTreeEntry_t *regTreeEntry);
extern int get_regTreeIndex(int search_type, Integer *regTreeIndex, IndexType *index);
extern int get_regTreeAgentID(int search_type, Integer *regTreeAgentID, IndexType *index);
extern int get_regTreeOID(int search_type, Oid *regTreeOID, IndexType *index);
extern int set_regTreeOID(int pass, IndexType index, Oid *regTreeOID);
extern void free_regTreeOID(Oid *regTreeOID);
extern int get_regTreeStatus(int search_type, Integer *regTreeStatus, IndexType *index);
extern int set_regTreeStatus(int pass, IndexType index, Integer *regTreeStatus);
extern int get_regTreeTableIndex(Integer *regTreeTableIndex);

extern int SSAGetTrapPort();
#endif
