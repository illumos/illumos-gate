/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2003-2004, Apple Computer, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer. 
 * 2.  Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution. 
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of its 
 *     contributors may be used to endorse or promote products derived from this 
 *     software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY 
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Change History (most recent first):

$Log: dnssd_ipc.h,v $
Revision 1.23  2006/08/14 23:05:53  cheshire
Added "tab-width" emacs header line

Revision 1.22  2006/06/28 08:56:26  cheshire
Added "_op" to the end of the operation code enum values,
to differentiate them from the routines with the same names

Revision 1.21  2005/09/29 06:38:13  herscher
Remove #define MSG_WAITALL on Windows.  We don't use this macro anymore, and it's presence causes warnings to be emitted when compiling against the latest Microsoft Platform SDK.

Revision 1.20  2005/03/21 00:39:31  shersche
<rdar://problem/4021486> Fix build warnings on Win32 platform

Revision 1.19  2005/02/02 02:25:22  cheshire
<rdar://problem/3980388> /var/run/mDNSResponder should be /var/run/mdnsd on Linux

Revision 1.18  2005/01/27 22:57:56  cheshire
Fix compile errors on gcc4

Revision 1.17  2004/11/23 03:39:47  cheshire
Let interface name/index mapping capability live directly in JNISupport.c,
instead of having to call through to the daemon via IPC to get this information.

Revision 1.16  2004/11/12 03:21:41  rpantos
rdar://problem/3809541 Add DNSSDMapIfIndexToName, DNSSDMapNameToIfIndex.

Revision 1.15  2004/10/06 02:22:20  cheshire
Changed MacRoman copyright symbol (should have been UTF-8 in any case :-) to ASCII-compatible "(c)"

Revision 1.14  2004/10/01 22:15:55  rpantos
rdar://problem/3824265: Replace APSL in client lib with BSD license.

Revision 1.13  2004/09/16 23:14:25  cheshire
Changes for Windows compatibility

Revision 1.12  2004/09/16 21:46:38  ksekar
<rdar://problem/3665304> Need SPI for LoginWindow to associate a UID with a Wide Area domain

Revision 1.11  2004/08/10 06:24:56  cheshire
Use types with precisely defined sizes for 'op' and 'reg_index', for better
compatibility if the daemon and the client stub are built using different compilers

Revision 1.10  2004/07/07 17:39:25  shersche
Change MDNS_SERVERPORT from 5533 to 5354.

Revision 1.9  2004/06/25 00:26:27  rpantos
Changes to fix the Posix build on Solaris.

Revision 1.8  2004/06/18 04:56:51  rpantos
Add layer for platform code

Revision 1.7  2004/06/12 01:08:14  cheshire
Changes for Windows compatibility

Revision 1.6  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef DNSSD_IPC_H
#define DNSSD_IPC_H

#include "dns_sd.h"


//
// Common cross platform services
//
#if defined(WIN32)
#	include <winsock2.h>
#	define dnssd_InvalidSocket	INVALID_SOCKET
#	define dnssd_EWOULDBLOCK	WSAEWOULDBLOCK
#	define dnssd_EINTR			WSAEINTR
#	define dnssd_sock_t			SOCKET
#	define dnssd_socklen_t		int
#	define dnssd_sockbuf_t		const char*
#	define dnssd_close(sock)	closesocket(sock)
#	define dnssd_errno()		WSAGetLastError()
#	define ssize_t				int
#	define getpid				_getpid
#else
#	include <sys/types.h>
#	include <unistd.h>
#	include <sys/un.h>
#	include <string.h>
#	include <stdio.h>
#	include <stdlib.h>
#	include <sys/stat.h>
#	include <sys/socket.h>
#	include <netinet/in.h>
#	define dnssd_InvalidSocket	-1
#	define dnssd_EWOULDBLOCK	EWOULDBLOCK
#	define dnssd_EINTR			EINTR
#	define dnssd_EPIPE			EPIPE
#	define dnssd_sock_t			int
#	define dnssd_socklen_t		unsigned int
#	define dnssd_sockbuf_t		const char*
#	define dnssd_close(sock)	close(sock)
#	define dnssd_errno()		errno
#endif

#if defined(USE_TCP_LOOPBACK)
#	define AF_DNSSD				AF_INET
#	define MDNS_TCP_SERVERADDR	"127.0.0.1"
#	define MDNS_TCP_SERVERPORT	5354
#	define LISTENQ				5
#	define dnssd_sockaddr_t		struct sockaddr_in
#else
#	define AF_DNSSD				AF_LOCAL
#	ifndef MDNS_UDS_SERVERPATH
#		define MDNS_UDS_SERVERPATH	"/var/run/mDNSResponder"
#	endif
#	define LISTENQ				100
    // longest legal control path length
#	define MAX_CTLPATH			256	
#	define dnssd_sockaddr_t		struct sockaddr_un
#endif


//#define UDSDEBUG  // verbose debug output

// Compatibility workaround
#ifndef AF_LOCAL
#define	AF_LOCAL	AF_UNIX
#endif

// General UDS constants
#define TXT_RECORD_INDEX ((uint32_t)(-1))	// record index for default text record

// IPC data encoding constants and types
#define VERSION 1
#define IPC_FLAGS_NOREPLY 1	// set flag if no asynchronous replies are to be sent to client
#define IPC_FLAGS_REUSE_SOCKET 2 // set flag if synchronous errors are to be sent via the primary socket
                                // (if not set, first string in message buffer must be path to error socket

typedef enum
    {
    connection = 1,           // connected socket via DNSServiceConnect()
    reg_record_request,	  // reg/remove record only valid for connected sockets
    remove_record_request,
    enumeration_request,
    reg_service_request,
    browse_request,
    resolve_request,
    query_request,
    reconfirm_record_request,
    add_record_request,
    update_record_request,
    setdomain_request
    } request_op_t;

typedef enum
    {
    enumeration_reply_op = 64,
    reg_service_reply_op,
    browse_reply_op,
    resolve_reply_op,
    query_reply_op,
    reg_record_reply_op
    } reply_op_t;

typedef struct ipc_msg_hdr_struct ipc_msg_hdr;

// client stub callback to process message from server and deliver results to
// client application

typedef void (*process_reply_callback)
    (
    DNSServiceRef sdr,
    ipc_msg_hdr *hdr,
    char *msg
    );

// allow 64-bit client to interoperate w/ 32-bit daemon
typedef union
    {
    void *context;
    uint32_t ptr64[2];
    } client_context_t;

typedef struct ipc_msg_hdr_struct
    {
    uint32_t version;
    uint32_t datalen;
    uint32_t flags;
    uint32_t op;		// request_op_t or reply_op_t
    client_context_t client_context; // context passed from client, returned by server in corresponding reply
    uint32_t reg_index;            // identifier for a record registered via DNSServiceRegisterRecord() on a
    // socket connected by DNSServiceConnect().  Must be unique in the scope of the connection, such that and
    // index/socket pair uniquely identifies a record.  (Used to select records for removal by DNSServiceRemoveRecord())
    uint32_t padbytes;
    } ipc_msg_hdr_struct;

// it is advanced to point to the next field, or the end of the message
// routines to write to and extract data from message buffers.
// caller responsible for bounds checking.
// ptr is the address of the pointer to the start of the field.
// it is advanced to point to the next field, or the end of the message

void put_long(const uint32_t l, char **ptr);
uint32_t get_long(char **ptr);

void put_short(uint16_t s, char **ptr);
uint16_t get_short(char **ptr);

#define put_flags put_long
#define get_flags get_long

#define put_error_code put_long
#define get_error_code get_long

int put_string(const char *str, char **ptr);
int get_string(char **ptr, char *buffer, int buflen);

void put_rdata(const int rdlen, const unsigned char *rdata, char **ptr);
char *get_rdata(char **ptr, int rdlen);  // return value is rdata pointed to by *ptr -
                                         // rdata is not copied from buffer.

void ConvertHeaderBytes(ipc_msg_hdr *hdr);

#endif // DNSSD_IPC_H
