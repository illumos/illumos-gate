/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 	File:		mDNSDebug.c

 	Contains:	Implementation of debugging utilities. Requires a POSIX environment.

 	Version:	1.0

    Change History (most recent first):

$Log: mDNSDebug.c,v $
Revision 1.7  2006/08/14 23:24:56  cheshire
Re-licensed mDNSResponder daemon source code under Apache License, Version 2.0

Revision 1.6  2005/01/27 22:57:56  cheshire
Fix compile errors on gcc4

Revision 1.5  2004/09/17 01:08:55  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.4  2004/06/11 22:36:51  cheshire
Fixes for compatibility with Windows

Revision 1.3  2004/01/28 21:14:23  cheshire
Reconcile debug_mode and gDebugLogging into a single flag (mDNS_DebugMode)

Revision 1.2  2003/12/09 01:30:40  rpantos
Fix usage of ARGS... macros to build properly on Windows.

Revision 1.1  2003/12/08 21:11:42;  rpantos
Changes necessary to support mDNSResponder on Linux.

*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mDNSDebug.h"

#include <stdio.h>

#if defined(WIN32)
// Need to add Windows syslog support here
#define LOG_PID 0x01
#define LOG_CONS 0x02
#define LOG_PERROR 0x20
#define openlog(A,B,C) (void)(A); (void)(B)
#define syslog(A,B,C)
#define closelog()
#else
#include <syslog.h>
#endif

#include "mDNSEmbeddedAPI.h"

#if MDNS_DEBUGMSGS
mDNSexport int mDNS_DebugMode = mDNStrue;
#else
mDNSexport int mDNS_DebugMode = mDNSfalse;
#endif

// Note, this uses mDNS_vsnprintf instead of standard "vsnprintf", because mDNS_vsnprintf knows
// how to print special data types like IP addresses and length-prefixed domain names
#if MDNS_DEBUGMSGS
mDNSexport void debugf_(const char *format, ...)
	{
	unsigned char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
	fprintf(stderr,"%s\n", buffer);
	fflush(stderr);
	}
#endif

#if MDNS_DEBUGMSGS > 1
mDNSexport void verbosedebugf_(const char *format, ...)
	{
	unsigned char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
	fprintf(stderr,"%s\n", buffer);
	fflush(stderr);
	}
#endif

mDNSlocal void WriteLogMsg(const char *ident, const char *buffer, int logoptflags, int logpriority)
	{
	if (mDNS_DebugMode)	// In debug mode we write to stderr
		{
		fprintf(stderr,"%s\n", buffer);
		fflush(stderr);
		}
	else				// else, in production mode, we write to syslog
		{
		openlog(ident, LOG_PERROR | logoptflags, LOG_DAEMON);
		syslog(logpriority, "%s", buffer);
		closelog();
		}
	}

// Log message with default "mDNSResponder" ident string at the start
mDNSexport void LogMsg(const char *format, ...)
	{
	char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
	WriteLogMsg("mDNSResponder", buffer, 0, LOG_ERR);
	}

// Log message with specified ident string at the start
mDNSexport void LogMsgIdent(const char *ident, const char *format, ...)
	{
	char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
	WriteLogMsg(ident, buffer, ident && *ident ? LOG_PID : 0, LOG_INFO);
	}

// Log message with no ident string at the start
mDNSexport void LogMsgNoIdent(const char *format, ...)
	{
	char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr)] = 0;
	va_end(ptr);
	WriteLogMsg("", buffer, 0, LOG_INFO);
	}
