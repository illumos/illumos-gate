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
 * \file KMSAuditLogger_meta.cpp
 * HISTORY:
 * 9/14/07  BJB   changed to log to file even if DEBUG is off
 */

#include "KMSAuditLogger.h"
#include <stdio.h>
#include <string.h>
#include <snprintf.h>
#include "strnlen.h"
#include "debug.h"


extern "C" void ecpt_trace_msg(ECPT_TRACE_ENTRY*, char*, ...);

/**
 * InitializeFileLogging
 * @returns success/failure (0=fail, 1=success)
 */
int InitializeFileLogging( const char* const i_sLogFilename )
{
   // do nothing
   return 1;
}

int FinalizeFileLogging()
{
   // do nothing
   return 1;
}

int TruncateLogFile()
{
   // do nothing
   return 1;
}


/**
 * LogToFile
 * @returns success/failure (0=fail, 1=success)
 */

extern "C" void
tnMsg( const char *format, ... );


int LogToFile(int i_iErrno,
              const char* const i_sLogLine )
{
   ECPT_TRACE_ENTRY   *trace = NULL;
   ECPT_TRACE    ( trace, LogToFile );

   ecpt_trace_msg( trace, "%i:%s", i_iErrno, i_sLogLine );

   return 1;
}

/**
 * Log
 * @returns success/failure (0=fail, 1=success)
 */
int Log_function(int i_iErrno,
                 const char* const i_sOperation,
                 const char* const i_sEntityID,
                 const char* const i_sNetworkAddress,
                 const char* const i_sMessage )
{
   
   ECPT_TRACE_ENTRY   *trace = NULL;

   ECPT_TRACE    ( trace, Log_function );

   ecpt_trace_msg( trace, "%i:%s:%s:", 
                   i_iErrno, 
                   i_sOperation );
   
   trace = NULL;
   ECPT_TRACE    ( trace, Log_function );
   ecpt_trace_msg( trace, "%s:%s:%s", 
                   i_sMessage,
                   i_sEntityID, 
                   i_sNetworkAddress);   

   return 1;
}



/**
 * Log2
 * @returns success/failure (0=fail, 1=success)
 */
extern "C" int Log2(char* msg1,
                    char* msg2)
{
   // does nothing anymore
   return 1;   
}



