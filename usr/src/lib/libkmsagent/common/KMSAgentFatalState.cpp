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
 * \file KMSAgentFatalState.cpp
 */
#include <stdio.h>
#include <string.h>

#include "SYSCommon.h"
#include "KMSAgentStringUtilities.h"
#include "KMSAuditLogger.h"

#define MAX_TIME_STAMP_LENGTH 30

#ifndef METAWARE
/**
 *  append the state of the application in the <KMSAgentAuditLogger> log file. 
 */
void process_fatal_application_state(const char* sFile, 
                                     const char* sFunction, 
                                     int iLine,
									 const char* sAdditionalText)
{
	
   // File format: <date/time>,<operation>,<retention>,<audit id>,<network adddress>,<message>
   char sFileLogEntry[MAX_LOG_FILE_LINE_LENGTH];
   char sTimeStamp[MAX_TIME_STAMP_LENGTH];
   char sLine[20];
   
   GetCurrentDateTimeISO8601UTC(sTimeStamp, MAX_TIME_STAMP_LENGTH);
   Int64ToUTF8(sLine, iLine, false, false);

   strncpy(sFileLogEntry, "A fatal application error has occurred. Date: ", sizeof(sFileLogEntry));

   sFileLogEntry[sizeof(sFileLogEntry)-1] = '\0';
   
   strncat(sFileLogEntry, sTimeStamp, MAX_LOG_FILE_LINE_LENGTH - strlen(sFileLogEntry));
    
   strncat(sFileLogEntry, " File: ", MAX_LOG_FILE_LINE_LENGTH - strlen(sFileLogEntry));

   strncat(sFileLogEntry, sFile, MAX_LOG_FILE_LINE_LENGTH - strlen(sFileLogEntry));

   strncat(sFileLogEntry, " Function: ", MAX_LOG_FILE_LINE_LENGTH - strlen(sFileLogEntry));

   strncat(sFileLogEntry, sFunction, MAX_LOG_FILE_LINE_LENGTH - strlen(sFileLogEntry));

   strncat(sFileLogEntry, " Line: ", MAX_LOG_FILE_LINE_LENGTH - strlen(sFileLogEntry));

   strncat(sFileLogEntry, sLine, MAX_LOG_FILE_LINE_LENGTH - strlen(sFileLogEntry));

   LogToFile( 0, sFileLogEntry );

   exit( -1 );
}

#endif
