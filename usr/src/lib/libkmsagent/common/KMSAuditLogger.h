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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/**
 * \file KMSAuditLogger.h
 */

#ifndef KMSAuditLogger_h
#define KMSAuditLogger_h

#ifndef METAWARE
#ifdef WIN32
#pragma warning(disable: 4786)
#endif

// SYSCommon.h needs the following include
#include <stdio.h>

#include "SYSCommon.h"
#include "AutoMutex.h"
#endif // METAWARE

#include "ApplianceParameters.h"


#define MAX_LOG_FILE_LINE_LENGTH    MAXIMUM_UTF8_STRING_VALUE_LENGTH + 128
#define MAX_LOG_FILE_NAME_LENGTH    256

/**
 *  Opens a logging file for appending, or creation, 
 *  with the name "KMSAgentLog.log" beneath the specified directory.
 *  @return true on success
 */
int InitializeFileLogging( const char* const i_sWorkingDirectory );

/**
 *  closes the log file
 *  @return true if successful close
 */
int FinalizeFileLogging();

/**
 *  write a log entry to the log file
 *  @return true if successful
 */
extern "C" int LogToFile( int i_iErrno,
                          const char* const i_sLogLine );

/**
 *  Formats a message and to the log file using <code>LogToFile</code>, 
 *  generating a ISO8601UTC timestamp and
 *  appending the various function arguments together.
 *  @param i_sOperation optional, an operation and error condition string
 *  @param i_sEntityID optional, the name of the entity performing the operation
 *  @param i_sNetworkAddress optional, the address of the KMS involved in the operation
 *  @param i_sMessage optional, the error message details
 *  @return 0 if successful
 */
int Log_function(
   int i_iErrno,
   const char* const i_sOperation,
   const char* const i_sEntityID,
   const char* const i_sNetworkAddress,
   const char* const i_sMessage );

// helper macro to convert value to a string
#define Log(a,b,c,d) Log_function(a, #a, b, c, d)

#define AUDIT_CLIENT_LOG_BASE 0x200

#define AUDIT_CLIENT_LOAD_PROFILE_CREATE_DIRECTORY_FAILED           (AUDIT_CLIENT_LOG_BASE + 0x0)
#define AUDIT_CLIENT_LOAD_PROFILE_CREATE_PROFILE_CONFIG_FAILED      (AUDIT_CLIENT_LOG_BASE + 0x1)
#define AUDIT_CLIENT_LOAD_PROFILE_CREATE_PROFILE_CONFIG_SUCCEEDED   (AUDIT_CLIENT_LOG_BASE + 0x2)
#define AUDIT_CLIENT_SAVE_CLUSTER_INFORMATION_SUCCEEDED             (AUDIT_CLIENT_LOG_BASE + 0x3)

#define AUDIT_CLIENT_GET_ROOT_CA_CERTIFICATE_SUCCESS                (AUDIT_CLIENT_LOG_BASE + 0x4)
#define AUDIT_CLIENT_GET_CERTIFICATE_SUCCESS                        (AUDIT_CLIENT_LOG_BASE + 0x5)
#define AUDIT_CLIENT_LOAD_PROFILE                                   (AUDIT_CLIENT_LOG_BASE + 0x6)
#define AUDIT_CLIENT_GetClusterInformation                          (AUDIT_CLIENT_LOG_BASE + 0x7)

#define AGENT_LOADBALANCER_FAILOVER                                 (AUDIT_CLIENT_LOG_BASE + 0x8)

#define AUDIT_CLIENT_AGENT_GET_CLUSTER_INFORMATION_INVALID_PARAMETERS      (AUDIT_CLIENT_LOG_BASE + 0x9)
#define AUDIT_CLIENT_AGENT_SELECT_APPLIANCE_INVALID_PARAMETERS             (AUDIT_CLIENT_LOG_BASE + 0xa)
#define AUDIT_CLIENT_AGENT_LOAD_PROFILE_INVALID_PARAMETERS                 (AUDIT_CLIENT_LOG_BASE + 0xc)
#define AUDIT_CLIENT_AGENT_UNLOAD_PROFILE_INVALID_PARAMETERS               (AUDIT_CLIENT_LOG_BASE + 0xd)
#define AUDIT_CLIENT_AGENT_LIST_KEY_GROUPS_INVALID_PARAMETERS              (AUDIT_CLIENT_LOG_BASE + 0xe)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_PARAMETERS                   (AUDIT_CLIENT_LOG_BASE + 0xf)
#define AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_INVALID_PARAMETERS             (AUDIT_CLIENT_LOG_BASE + 0x10)
#define AUDIT_CLIENT_AGENT_DISASSOCIATE_DATA_UNIT_KEYS_INVALID_PARAMETERS  (AUDIT_CLIENT_LOG_BASE + 0x11)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_PARAMETERS                 (AUDIT_CLIENT_LOG_BASE + 0x12)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_INVALID_PARAMETERS           (AUDIT_CLIENT_LOG_BASE + 0x13)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_INVALID_PARAMETERS      (AUDIT_CLIENT_LOG_BASE + 0x14)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_PARAMETERS      (AUDIT_CLIENT_LOG_BASE + 0x15)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_PARAMETERS      (AUDIT_CLIENT_LOG_BASE + 0x16)
#define AUDIT_CLIENT_AGENT_CREATE_AUDIT_LOG_INVALID_PARAMETERS              (AUDIT_CLIENT_LOG_BASE + 0x17)
#define AUDIT_CLIENT_AGENT_CREATED_AUDIT_LOG_INVALID_PARAMETERS             (AUDIT_CLIENT_LOG_BASE + 0x18)
#define AUDIT_CLIENT_AGENT_LOAD_PROFILE_PROFILE_ALREADY_LOADED              (AUDIT_CLIENT_LOG_BASE + 0x19)
#define AGENT_LOADBALANCER_AESKEYUNWRAP_GETKWK_RETURNED_NULL                (AUDIT_CLIENT_LOG_BASE + 0x1a)
#define AGENT_LOADBALANCER_AESKEYUNWRAP_KEY_UNWRAP_FAILED                   (AUDIT_CLIENT_LOG_BASE + 0x1b)
#define AUDIT_CLIENT_FILTER_CLUSTER_FAILED                                  (AUDIT_CLIENT_LOG_BASE + 0x1c)
#define AUDIT_CLIENT_FILTER_CLUSTER                                         (AUDIT_CLIENT_LOG_BASE + 0x1d)






int Log_function(int i_iErrno,
                 const char* const i_sOperation,
                 const char* const i_sEntityID,
                 const char* const i_sNetworkAddress,
                 const char* const i_sMessage );

/**
 * Log generically 2 parameters (presumably to the screen,
 * but could be to a file
 */
extern "C" int Log2(char* msg1,
                    char* msg2);

#endif //KMSAuditLogger_h
