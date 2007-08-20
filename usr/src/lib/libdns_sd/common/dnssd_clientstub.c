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

$Log: dnssd_clientstub.c,v $
Revision 1.53  2006/09/07 04:43:12  herscher
Fix compile error on Win32 platform by moving inclusion of syslog.h

Revision 1.52  2006/08/15 23:04:21  mkrochma
<rdar://problem/4090354> Client should be able to specify service name w/o callback

Revision 1.51  2006/07/24 23:45:55  cheshire
<rdar://problem/4605276> DNSServiceReconfirmRecord() should return error code

Revision 1.50  2006/06/28 08:22:27  cheshire
<rdar://problem/4605264> dnssd_clientstub.c needs to report unlink failures in syslog

Revision 1.49  2006/06/28 07:58:59  cheshire
Minor textual tidying

Revision 1.48  2005/06/30 18:01:00  shersche
<rdar://problem/4096913> Clients shouldn't wait ten seconds to connect to mDNSResponder

Revision 1.47  2005/03/31 02:19:56  cheshire
<rdar://problem/4021486> Fix build warnings
Reviewed by: Scott Herscher

Revision 1.46  2005/03/21 00:39:31  shersche
<rdar://problem/4021486> Fix build warnings on Win32 platform

Revision 1.45  2005/02/01 01:25:06  shersche
Define sleep() to be Sleep() for Windows compatibility

Revision 1.44  2005/01/27 22:57:56  cheshire
Fix compile errors on gcc4

Revision 1.43  2005/01/27 00:02:29  cheshire
<rdar://problem/3947461> Handle case where client runs before daemon has finished launching

Revision 1.42  2005/01/11 02:01:02  shersche
Use dnssd_close() rather than close() for Windows compatibility

Revision 1.41  2004/12/23 17:34:26  ksekar
<rdar://problem/3931319> Calls leak sockets if mDNSResponder is not running

Revision 1.40  2004/11/23 03:39:47  cheshire
Let interface name/index mapping capability live directly in JNISupport.c,
instead of having to call through to the daemon via IPC to get this information.

Revision 1.39  2004/11/12 03:22:00  rpantos
rdar://problem/3809541 Add DNSSDMapIfIndexToName, DNSSDMapNameToIfIndex.

Revision 1.38  2004/11/02 02:51:23  cheshire
<rdar://problem/3526342> Remove overly-restrictive flag checks

Revision 1.37  2004/10/14 01:43:35  cheshire
Fix opaque port passing problem

Revision 1.36  2004/10/06 02:22:19  cheshire
Changed MacRoman copyright symbol (should have been UTF-8 in any case :-) to ASCII-compatible "(c)"

Revision 1.35  2004/10/01 22:15:55  rpantos
rdar://problem/3824265: Replace APSL in client lib with BSD license.

Revision 1.34  2004/09/17 22:36:13  cheshire
Add comment explaining that deliver_request frees the message it sends

Revision 1.33  2004/09/17 01:17:31  ksekar
Remove double-free of msg header, freed automatically by deliver_request()

Revision 1.32  2004/09/17 01:08:55  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.31  2004/09/16 23:37:19  cheshire
Free hdr before returning

Revision 1.30  2004/09/16 23:14:24  cheshire
Changes for Windows compatibility

Revision 1.29  2004/09/16 21:46:38  ksekar
<rdar://problem/3665304> Need SPI for LoginWindow to associate a UID with a Wide Area domain

Revision 1.28  2004/08/11 17:10:04  cheshire
Fix signed/unsigned warnings

Revision 1.27  2004/08/11 00:54:16  cheshire
Change "hdr->op.request_op" to just "hdr->op"

Revision 1.26  2004/07/26 06:07:27  shersche
fix bugs when using an error socket to communicate with the daemon

Revision 1.25  2004/07/26 05:54:02  shersche
DNSServiceProcessResult() returns NoError if socket read returns EWOULDBLOCK

Revision 1.24  2004/07/20 06:46:21  shersche
<rdar://problem/3730123> fix endless loop in read_all() if recv returns 0
Bug #: 3730123

Revision 1.23  2004/06/29 00:48:38  cheshire
Don't use "MSG_WAITALL"; it returns "Invalid argument" on some Linux versions;
use an explicit while() loop instead.

Revision 1.22  2004/06/26 03:16:34  shersche
clean up warning messages on Win32 platform

Submitted by: herscher

Revision 1.21  2004/06/18 04:53:56  rpantos
Use platform layer for socket types. Introduce USE_TCP_LOOPBACK. Remove dependency on mDNSEmbeddedAPI.h.

Revision 1.20  2004/06/12 00:50:22  cheshire
Changes for Windows compatibility

Revision 1.19  2004/05/25 18:29:33  cheshire
Move DNSServiceConstructFullName() from dnssd_clientstub.c to dnssd_clientlib.c,
so that it's also accessible to dnssd_clientshim.c (single address space) clients.

Revision 1.18  2004/05/18 23:51:27  cheshire
Tidy up all checkin comments to use consistent "<rdar://problem/xxxxxxx>" format for bug numbers

Revision 1.17  2004/05/06 18:42:58  ksekar
General dns_sd.h API cleanup, including the following radars:
<rdar://problem/3592068>: Remove flags with zero value
<rdar://problem/3479569>: Passing in NULL causes a crash.

Revision 1.16  2004/03/12 22:00:37  cheshire
Added: #include <sys/socket.h>

Revision 1.15  2004/01/20 18:36:29  ksekar
Propagated Libinfo fix for <rdar://problem/3483971>: SU:
DNSServiceUpdateRecord() doesn't allow you to update the TXT record
into TOT mDNSResponder.

Revision 1.14  2004/01/19 22:39:17  cheshire
Don't use "MSG_WAITALL"; it makes send() return "Invalid argument" on Linux;
use an explicit while() loop instead. (In any case, this should only make a difference
with non-blocking sockets, which we don't use on the client side right now.)

Revision 1.13  2004/01/19 21:46:52  cheshire
Fix compiler warning

Revision 1.12  2003/12/23 20:46:47  ksekar
<rdar://problem/3497428>: sync dnssd files between libinfo & mDNSResponder

Revision 1.11  2003/12/08 21:11:42  rpantos
Changes necessary to support mDNSResponder on Linux.

Revision 1.10  2003/10/13 23:50:53  ksekar
Updated dns_sd clientstub files to bring copies in synch with
top-of-tree Libinfo:  A memory leak in dnssd_clientstub.c is fixed,
and comments in dns_sd.h are improved.

Revision 1.9  2003/08/15 21:30:39  cheshire
Bring up to date with LibInfo version

Revision 1.8  2003/08/13 23:54:52  ksekar
Bringing dnssd_clientstub.c up to date with Libinfo, per radar 3376640

Revision 1.7  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <stdlib.h>

#include "dnssd_ipc.h"

#if defined(_WIN32)

#include <winsock2.h>
#include <windows.h>

#define sockaddr_mdns sockaddr_in
#define AF_MDNS AF_INET

// disable warning: "'type cast' : from data pointer 'void *' to function pointer"
#pragma warning(disable:4055)

// disable warning: "nonstandard extension, function/data pointer conversion in expression"
#pragma warning(disable:4152)

extern BOOL IsSystemServiceDisabled();

#define sleep(X) Sleep((X) * 1000)

static int g_initWinsock = 0;

#else

#include <sys/time.h>
#include <sys/socket.h>
#include <syslog.h>

#define sockaddr_mdns sockaddr_un
#define AF_MDNS AF_LOCAL

#endif

// <rdar://problem/4096913> Specifies how many times we'll try and connect to the
// server.

#define DNSSD_CLIENT_MAXTRIES 4

#define CTL_PATH_PREFIX "/tmp/dnssd_clippath."
// error socket (if needed) is named "dnssd_clipath.[pid].xxx:n" where xxx are the
// last 3 digits of the time (in seconds) and n is the 6-digit microsecond time

// general utility functions
typedef struct _DNSServiceRef_t
    {
    dnssd_sock_t sockfd;  // connected socket between client and daemon
    uint32_t op;          // request_op_t or reply_op_t
    process_reply_callback process_reply;
    void *app_callback;
    void *app_context;
    uint32_t max_index;  //largest assigned record index - 0 if no additl. recs registered
    } _DNSServiceRef_t;

typedef struct _DNSRecordRef_t
    {
    void *app_context;
    DNSServiceRegisterRecordReply app_callback;
    DNSRecordRef recref;
    uint32_t record_index;  // index is unique to the ServiceDiscoveryRef
    DNSServiceRef sdr;
    } _DNSRecordRef_t;

// exported functions

// write len bytes.  return 0 on success, -1 on error
static int write_all(dnssd_sock_t sd, char *buf, int len)
    {
    // Don't use "MSG_WAITALL"; it returns "Invalid argument" on some Linux versions; use an explicit while() loop instead.
    //if (send(sd, buf, len, MSG_WAITALL) != len)   return -1;
    while (len)
    	{
    	ssize_t num_written = send(sd, buf, len, 0);
    	if (num_written < 0 || num_written > len) return -1;
    	buf += num_written;
    	len -= num_written;
    	}
    return 0;
    }

// read len bytes.  return 0 on success, -1 on error
static int read_all(dnssd_sock_t sd, char *buf, int len)
    {
    // Don't use "MSG_WAITALL"; it returns "Invalid argument" on some Linux versions; use an explicit while() loop instead.
    //if (recv(sd, buf, len, MSG_WAITALL) != len)  return -1;
    while (len)
    	{
    	ssize_t num_read = recv(sd, buf, len, 0);
	if ((num_read == -1) && (errno == EINTR))
		continue;
	if ((num_read < 0) || (num_read > len)) return -1;
	// Return error -2 when no data received and errno is not set
	if (num_read == 0) return -2;
    	buf += num_read;
    	len -= num_read;
    	}
    return 0;
    }

/* create_hdr
 *
 * allocate and initialize an ipc message header.  value of len should initially be the
 * length of the data, and is set to the value of the data plus the header.  data_start
 * is set to point to the beginning of the data section.  reuse_socket should be non-zero
 * for calls that can receive an immediate error return value on their primary socket.
 * if zero, the path to a control socket is appended at the beginning of the message buffer.
 * data_start is set past this string.
 */

static ipc_msg_hdr *create_hdr(uint32_t op, size_t *len, char **data_start, int reuse_socket)
    {
    char *msg = NULL;
    ipc_msg_hdr *hdr;
    int datalen;
#if !defined(USE_TCP_LOOPBACK)
    char ctrl_path[256];
#endif

    if (!reuse_socket)
        {
#if defined(USE_TCP_LOOPBACK)
		*len += 2;  // Allocate space for two-byte port number
#else
		struct timeval time;
		if (gettimeofday(&time, NULL) < 0) return NULL;
		sprintf(ctrl_path, "%s%d-%.3lx-%.6lu", CTL_PATH_PREFIX, (int)getpid(),
			(unsigned long)(time.tv_sec & 0xFFF), (unsigned long)(time.tv_usec));
        *len += strlen(ctrl_path) + 1;
#endif
        }

    datalen = (int) *len;
    *len += sizeof(ipc_msg_hdr);

    // write message to buffer
    msg = malloc(*len);
    if (!msg) return NULL;

    bzero(msg, *len);
    hdr = (void *)msg;
    hdr->datalen = datalen;
    hdr->version = VERSION;
    hdr->op = op;
    if (reuse_socket) hdr->flags |= IPC_FLAGS_REUSE_SOCKET;
    *data_start = msg + sizeof(ipc_msg_hdr);
#if defined(USE_TCP_LOOPBACK)
	// Put dummy data in for the port, since we don't know what
	// it is yet.  The data will get filled in before we
	// send the message. This happens in deliver_request().
	if (!reuse_socket)  put_short(0, data_start);
#else
    if (!reuse_socket)  put_string(ctrl_path, data_start);
#endif
    return hdr;
    }

    // return a connected service ref (deallocate with DNSServiceRefDeallocate)
static DNSServiceRef connect_to_server(void)
    {
	dnssd_sockaddr_t saddr;
	DNSServiceRef sdr;
	int NumTries = 0;

#if defined(_WIN32)
	if (!g_initWinsock)
		{
		WSADATA wsaData;
		DNSServiceErrorType err;
		
		g_initWinsock = 1;

		err = WSAStartup( MAKEWORD( 2, 2 ), &wsaData );

		if (err != 0) return NULL;
		}

	// <rdar://problem/4096913> If the system service is disabled, we only want to try 
	// to connect once

	if ( IsSystemServiceDisabled() )
		{
		NumTries = DNSSD_CLIENT_MAXTRIES;
		}

#endif

	sdr = malloc(sizeof(_DNSServiceRef_t));
	if (!sdr) return(NULL);
	sdr->sockfd = socket(AF_DNSSD, SOCK_STREAM, 0);
	if (sdr->sockfd == dnssd_InvalidSocket) { free(sdr); return NULL; }
#if defined(USE_TCP_LOOPBACK)
	saddr.sin_family      = AF_INET;
	saddr.sin_addr.s_addr = inet_addr(MDNS_TCP_SERVERADDR);
	saddr.sin_port        = htons(MDNS_TCP_SERVERPORT);
#else
	saddr.sun_family = AF_LOCAL;
	strcpy(saddr.sun_path, MDNS_UDS_SERVERPATH);
#endif
	while (1)
		{
		int err = connect(sdr->sockfd, (struct sockaddr *) &saddr, sizeof(saddr));
		if (!err) break; // If we succeeded, return sdr
		// If we failed, then it may be because the daemon is still launching.
		// This can happen for processes that launch early in the boot process, while the
		// daemon is still coming up. Rather than fail here, we'll wait a bit and try again.
		// If, after four seconds, we still can't connect to the daemon,
		// then we give up and return a failure code.
		if (++NumTries < DNSSD_CLIENT_MAXTRIES)
			sleep(1); // Sleep a bit, then try again
		else
			{
			dnssd_close(sdr->sockfd);
			sdr->sockfd = dnssd_InvalidSocket;
			free(sdr);
			return NULL;
			}
		}
    return sdr;
	}

static DNSServiceErrorType deliver_request(void *msg, DNSServiceRef sdr, int reuse_sd)
    {
    ipc_msg_hdr *hdr = msg;
    uint32_t datalen = hdr->datalen;
    dnssd_sockaddr_t caddr, daddr;  // (client and daemon address structs)
    char *const data = (char *)msg + sizeof(ipc_msg_hdr);
    dnssd_sock_t listenfd = dnssd_InvalidSocket, errsd = dnssd_InvalidSocket;
	int ret;
	dnssd_socklen_t len = (dnssd_socklen_t) sizeof(caddr);
    DNSServiceErrorType err = kDNSServiceErr_Unknown;

    if (!hdr || sdr->sockfd < 0) return kDNSServiceErr_Unknown;

	if (!reuse_sd)
		{
        // setup temporary error socket
        if ((listenfd = socket(AF_DNSSD, SOCK_STREAM, 0)) < 0)
            goto cleanup;
        bzero(&caddr, sizeof(caddr));

#if defined(USE_TCP_LOOPBACK)
			{
			union { uint16_t s; u_char b[2]; } port;
			caddr.sin_family      = AF_INET;
			caddr.sin_port        = 0;
			caddr.sin_addr.s_addr = inet_addr(MDNS_TCP_SERVERADDR);
			ret = bind(listenfd, (struct sockaddr*) &caddr, sizeof(caddr));
			if (ret < 0) goto cleanup;
			if (getsockname(listenfd, (struct sockaddr*) &caddr, &len) < 0) goto cleanup;
			listen(listenfd, 1);
			port.s = caddr.sin_port;
			data[0] = port.b[0];  // don't switch the byte order, as the
			data[1] = port.b[1];  // daemon expects it in network byte order
			}
#else
			{
			mode_t mask = umask(0);
			caddr.sun_family = AF_LOCAL;
// According to Stevens (section 3.2), there is no portable way to
// determine whether sa_len is defined on a particular platform.
#ifndef NOT_HAVE_SA_LEN
			caddr.sun_len = sizeof(struct sockaddr_un);
#endif
			//syslog(LOG_WARNING, "deliver_request: creating UDS: %s\n", data);
			strcpy(caddr.sun_path, data);
			ret = bind(listenfd, (struct sockaddr *)&caddr, sizeof(caddr));
			umask(mask);
			if (ret < 0) goto cleanup;
			listen(listenfd, 1);
			}
#endif
		}

	ConvertHeaderBytes(hdr);
	//syslog(LOG_WARNING, "deliver_request writing %ld bytes\n", datalen + sizeof(ipc_msg_hdr));
	//syslog(LOG_WARNING, "deliver_request name is %s\n", (char *)msg + sizeof(ipc_msg_hdr));
    if (write_all(sdr->sockfd, msg, datalen + sizeof(ipc_msg_hdr)) < 0)
        goto cleanup;
    free(msg);
    msg = NULL;

    if (reuse_sd) errsd = sdr->sockfd;
    else
        {
		//syslog(LOG_WARNING, "deliver_request: accept\n");
        len = sizeof(daddr);
        errsd = accept(listenfd, (struct sockaddr *)&daddr, &len);
		//syslog(LOG_WARNING, "deliver_request: accept returned %d\n", errsd);
        if (errsd < 0)  goto cleanup;
        }

    if (read_all(errsd, (char*)&err, (int)sizeof(err)) < 0)
        err = kDNSServiceErr_Unknown;
    else
    	err = ntohl(err);

	//syslog(LOG_WARNING, "deliver_request: retrieved error code %d\n", err);

cleanup:
	if (!reuse_sd)
		{
		if (listenfd > 0) dnssd_close(listenfd);
		if (errsd    > 0) dnssd_close(errsd);
#if !defined(USE_TCP_LOOPBACK)
		// syslog(LOG_WARNING, "deliver_request: removing UDS: %s\n", data);
		if (unlink(data) != 0)
			syslog(LOG_WARNING, "WARNING: unlink(\"%s\") failed errno %d (%s)", data, errno, strerror(errno));
		// else syslog(LOG_WARNING, "deliver_request: removed UDS: %s\n", data);
#endif
		}
    if (msg) free(msg);
    return err;
    }

int DNSSD_API DNSServiceRefSockFD(DNSServiceRef sdRef)
    {
    if (!sdRef) return -1;
    return (int) sdRef->sockfd;
    }

// handle reply from server, calling application client callback.  If there is no reply
// from the daemon on the socket contained in sdRef, the call will block.
DNSServiceErrorType DNSSD_API DNSServiceProcessResult(DNSServiceRef sdRef)
    {
    ipc_msg_hdr hdr;
    char *data;
    int rderr;

    if (!sdRef || sdRef->sockfd < 0 || !sdRef->process_reply)
        return kDNSServiceErr_BadReference;

    rderr = read_all(sdRef->sockfd, (void *)&hdr, sizeof(hdr));
    if (rderr < 0) {
		// return NoError on EWOULDBLOCK. This will handle the case
		// where a non-blocking socket is told there is data, but
		// it was a false positive. Can check errno when error
		// code returned is -1
		if ((rderr == -1) && (dnssd_errno() == dnssd_EWOULDBLOCK))
				return kDNSServiceErr_NoError;
	        return kDNSServiceErr_Unknown;
    }
	ConvertHeaderBytes(&hdr);
    if (hdr.version != VERSION)
        return kDNSServiceErr_Incompatible;
    data = malloc(hdr.datalen);
    if (!data) return kDNSServiceErr_NoMemory;
    if (read_all(sdRef->sockfd, data, hdr.datalen) < 0)
        return kDNSServiceErr_Unknown;
    sdRef->process_reply(sdRef, &hdr, data);
    free(data);
    return kDNSServiceErr_NoError;
    }

void DNSSD_API DNSServiceRefDeallocate(DNSServiceRef sdRef)
    {
    if (!sdRef) return;
    if (sdRef->sockfd > 0) dnssd_close(sdRef->sockfd);
    free(sdRef);
    }

static void handle_resolve_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    char fullname[kDNSServiceMaxDomainName];
    char target[kDNSServiceMaxDomainName];
    uint16_t txtlen;
    union { uint16_t s; u_char b[2]; } port;
    uint32_t ifi;
    DNSServiceErrorType err;
    unsigned char *txtrecord;
    int str_error = 0;
    (void)hdr; 		//unused

    flags = get_flags(&data);
    ifi = get_long(&data);
    err = get_error_code(&data);
    if (get_string(&data, fullname, kDNSServiceMaxDomainName) < 0) str_error = 1;
    if (get_string(&data, target, kDNSServiceMaxDomainName) < 0) str_error = 1;
    port.b[0] = *data++;
    port.b[1] = *data++;
    txtlen = get_short(&data);
    txtrecord = (unsigned char *)get_rdata(&data, txtlen);

	if (!err && str_error) err = kDNSServiceErr_Unknown;
    ((DNSServiceResolveReply)sdr->app_callback)(sdr, flags, ifi, err, fullname, target, port.s, txtlen, txtrecord, sdr->app_context);
    }

DNSServiceErrorType DNSSD_API DNSServiceResolve
    (
    DNSServiceRef                  	*sdRef,
    DNSServiceFlags               flags,
    uint32_t                      interfaceIndex,
    const char                         	*name,
    const char                         	*regtype,
    const char                         	*domain,
    DNSServiceResolveReply        callBack,
    void                               	*context
    )
    {
    char *msg = NULL, *ptr;
    size_t len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;

    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;

	if (!name || !regtype || !domain || !callBack) return kDNSServiceErr_BadParam;

    // calculate total message length
    len = sizeof(flags);
    len += sizeof(interfaceIndex);
    len += strlen(name) + 1;
    len += strlen(regtype) + 1;
    len += strlen(domain) + 1;

    hdr = create_hdr(resolve_request, &len, &ptr, 1);
    if (!hdr) goto error;
    msg = (void *)hdr;

    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(name, &ptr);
    put_string(regtype, &ptr);
    put_string(domain, &ptr);

    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }
    sdr->op = resolve_request;
    sdr->process_reply = handle_resolve_response;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;

    return err;

error:
    if (msg) free(msg);
    if (*sdRef) { free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }

static void handle_query_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    uint32_t interfaceIndex, ttl;
    DNSServiceErrorType errorCode;
    char name[kDNSServiceMaxDomainName];
    uint16_t rrtype, rrclass, rdlen;
    char *rdata;
    int str_error = 0;
    (void)hdr;//Unused

    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    errorCode = get_error_code(&data);
    if (get_string(&data, name, kDNSServiceMaxDomainName) < 0) str_error = 1;
    rrtype = get_short(&data);
    rrclass = get_short(&data);
    rdlen = get_short(&data);
    rdata = get_rdata(&data, rdlen);
	ttl = get_long(&data);

	if (!errorCode && str_error) errorCode = kDNSServiceErr_Unknown;
	((DNSServiceQueryRecordReply)sdr->app_callback)(sdr, flags, interfaceIndex, errorCode, name, rrtype, rrclass,
													rdlen, rdata, ttl, sdr->app_context);
    return;
    }

DNSServiceErrorType DNSSD_API DNSServiceQueryRecord
    (
    DNSServiceRef              *sdRef,
    DNSServiceFlags             flags,
    uint32_t                    interfaceIndex,
    const char                 *name,
    uint16_t                    rrtype,
    uint16_t                    rrclass,
    DNSServiceQueryRecordReply  callBack,
    void                       *context
    )
    {
    char *msg = NULL, *ptr;
    size_t len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;

    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;

    if (!name) name = "\0";

    // calculate total message length
    len = sizeof(flags);
    len += sizeof(uint32_t);  //interfaceIndex
    len += strlen(name) + 1;
    len += 2 * sizeof(uint16_t);  // rrtype, rrclass

    hdr = create_hdr(query_request, &len, &ptr, 1);
    if (!hdr) goto error;
    msg = (void *)hdr;

    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(name, &ptr);
    put_short(rrtype, &ptr);
    put_short(rrclass, &ptr);

    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }

    sdr->op = query_request;
    sdr->process_reply = handle_query_response;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;
    return err;

error:
    if (msg) free(msg);
    if (*sdRef) { free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }

static void handle_browse_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags      flags;
    uint32_t                      interfaceIndex;
    DNSServiceErrorType      errorCode;
    char replyName[256], replyType[kDNSServiceMaxDomainName],
        replyDomain[kDNSServiceMaxDomainName];
    int str_error = 0;
	(void)hdr;//Unused

    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    errorCode = get_error_code(&data);
    if (get_string(&data, replyName, 256) < 0) str_error = 1;
    if (get_string(&data, replyType, kDNSServiceMaxDomainName) < 0) str_error = 1;
    if (get_string(&data, replyDomain, kDNSServiceMaxDomainName) < 0) str_error = 1;
	if (!errorCode && str_error) errorCode = kDNSServiceErr_Unknown;
	((DNSServiceBrowseReply)sdr->app_callback)(sdr, flags, interfaceIndex, errorCode, replyName, replyType, replyDomain, sdr->app_context);
    }

DNSServiceErrorType DNSSD_API DNSServiceBrowse
	(
	DNSServiceRef         *sdRef,
	DNSServiceFlags        flags,
	uint32_t               interfaceIndex,
	const char            *regtype,
	const char            *domain,
	DNSServiceBrowseReply  callBack,
	void                  *context
	)
    {
    char *msg = NULL, *ptr;
    size_t len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;

    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;

    if (!domain) domain = "";

    len = sizeof(flags);
    len += sizeof(interfaceIndex);
    len += strlen(regtype) + 1;
    len += strlen(domain) + 1;

    hdr = create_hdr(browse_request, &len, &ptr, 1);
    if (!hdr) goto error;
    msg = (char *)hdr;
    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(regtype, &ptr);
    put_string(domain, &ptr);

    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }
    sdr->op = browse_request;
    sdr->process_reply = handle_browse_response;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;
    return err;

error:
    if (msg) free(msg);
    if (*sdRef) { free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }

DNSServiceErrorType DNSSD_API DNSServiceSetDefaultDomainForUser
	(
	DNSServiceFlags  flags,
	const char      *domain
	)
    {
    DNSServiceRef sdr;
    DNSServiceErrorType err;
    char *ptr = NULL;
    size_t len = sizeof(flags) + strlen(domain) + 1;
    ipc_msg_hdr *hdr = create_hdr(setdomain_request, &len, &ptr, 1);

    if (!hdr) return kDNSServiceErr_Unknown;
    put_flags(flags, &ptr);
    put_string(domain, &ptr);

    sdr = connect_to_server();
    if (!sdr) { free(hdr); return kDNSServiceErr_Unknown; }
    err = deliver_request((char *)hdr, sdr, 1); // deliver_request frees the message for us
	DNSServiceRefDeallocate(sdr);
	return err;
    }


static void handle_regservice_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    uint32_t interfaceIndex;
    DNSServiceErrorType errorCode;
    char name[256], regtype[kDNSServiceMaxDomainName], domain[kDNSServiceMaxDomainName];
    int str_error = 0;
	(void)hdr;//Unused

    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    errorCode = get_error_code(&data);
    if (get_string(&data, name, 256) < 0) str_error = 1;
    if (get_string(&data, regtype, kDNSServiceMaxDomainName) < 0) str_error = 1;
    if (get_string(&data, domain, kDNSServiceMaxDomainName) < 0) str_error = 1;
	if (!errorCode && str_error) errorCode = kDNSServiceErr_Unknown;
    ((DNSServiceRegisterReply)sdr->app_callback)(sdr, flags, errorCode, name, regtype, domain, sdr->app_context);
    }

DNSServiceErrorType DNSSD_API DNSServiceRegister
    (
    DNSServiceRef                       *sdRef,
    DNSServiceFlags                     flags,
    uint32_t                            interfaceIndex,
    const char                          *name,
    const char                          *regtype,
    const char                          *domain,
    const char                          *host,
    uint16_t                            PortInNetworkByteOrder,
    uint16_t                            txtLen,
    const void                          *txtRecord,
    DNSServiceRegisterReply             callBack,
    void                                *context
    )
    {
    char *msg = NULL, *ptr;
    size_t len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;
    union { uint16_t s; u_char b[2]; } port = { PortInNetworkByteOrder };

    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;

    if (!name) name = "";
    if (!regtype) return kDNSServiceErr_BadParam;
    if (!domain) domain = "";
    if (!host) host = "";
    if (!txtRecord) txtRecord = (void*)"";

    // auto-name must also have auto-rename
    if (!name[0]  && (flags & kDNSServiceFlagsNoAutoRename))
        return kDNSServiceErr_BadParam;

    // no callback must have auto-rename
    if (!callBack && (flags & kDNSServiceFlagsNoAutoRename)) return kDNSServiceErr_BadParam;

    len = sizeof(DNSServiceFlags);
    len += sizeof(uint32_t);  // interfaceIndex
    len += strlen(name) + strlen(regtype) + strlen(domain) + strlen(host) + 4;
    len += 2 * sizeof(uint16_t);  // port, txtLen
    len += txtLen;

    hdr = create_hdr(reg_service_request, &len, &ptr, 1);
    if (!hdr) goto error;
    if (!callBack) hdr->flags |= IPC_FLAGS_NOREPLY;
    msg = (char *)hdr;
    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(name, &ptr);
    put_string(regtype, &ptr);
    put_string(domain, &ptr);
    put_string(host, &ptr);
    *ptr++ = port.b[0];
    *ptr++ = port.b[1];
    put_short(txtLen, &ptr);
    put_rdata(txtLen, txtRecord, &ptr);

    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }

    sdr->op = reg_service_request;
    sdr->process_reply = callBack ? handle_regservice_response : NULL;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;

    return err;

error:
    if (msg) free(msg);
    if (*sdRef) 	{ free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }

static void handle_enumeration_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    uint32_t interfaceIndex;
    DNSServiceErrorType err;
    char domain[kDNSServiceMaxDomainName];
    int str_error = 0;
	(void)hdr;//Unused

    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    err = get_error_code(&data);
    if (get_string(&data, domain, kDNSServiceMaxDomainName) < 0) str_error = 1;
	if (!err && str_error) err = kDNSServiceErr_Unknown;
    ((DNSServiceDomainEnumReply)sdr->app_callback)(sdr, flags, interfaceIndex, err, domain, sdr->app_context);
    }

DNSServiceErrorType DNSSD_API DNSServiceEnumerateDomains
	(
	DNSServiceRef             *sdRef,
	DNSServiceFlags            flags,
	uint32_t                   interfaceIndex,
	DNSServiceDomainEnumReply  callBack,
	void                      *context
	)
    {
    char *msg = NULL, *ptr;
    size_t len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;
    int f1 = (flags & kDNSServiceFlagsBrowseDomains) != 0;
    int f2 = (flags & kDNSServiceFlagsRegistrationDomains) != 0;
    if (f1 + f2 != 1) return kDNSServiceErr_BadParam;

    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;

	len = sizeof(DNSServiceFlags);
    len += sizeof(uint32_t);

    hdr = create_hdr(enumeration_request, &len, &ptr, 1);
    if (!hdr) goto error;
    msg = (void *)hdr;

    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);

    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }

    sdr->op = enumeration_request;
    sdr->process_reply = handle_enumeration_response;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;
    return err;

error:
    if (msg) free(msg);
    if (*sdRef) { free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }

static void handle_regrecord_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    uint32_t interfaceIndex;
    DNSServiceErrorType errorCode;
    DNSRecordRef rref = hdr->client_context.context;

    if (sdr->op != connection)
        {
        rref->app_callback(rref->sdr, rref, 0, kDNSServiceErr_Unknown, rref->app_context);
        return;
        }
    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    errorCode = get_error_code(&data);

    rref->app_callback(rref->sdr, rref, flags, errorCode, rref->app_context);
    }

DNSServiceErrorType DNSSD_API DNSServiceCreateConnection(DNSServiceRef *sdRef)
    {
    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = connect_to_server();
    if (!*sdRef)
            return kDNSServiceErr_Unknown;
    (*sdRef)->op = connection;
    (*sdRef)->process_reply = handle_regrecord_response;
    return 0;
    }

DNSServiceErrorType DNSSD_API DNSServiceRegisterRecord
    (
    DNSServiceRef                  sdRef,
    DNSRecordRef                  *RecordRef,
    DNSServiceFlags                flags,
    uint32_t                       interfaceIndex,
    const char                    *fullname,
    uint16_t                       rrtype,
    uint16_t                       rrclass,
    uint16_t                       rdlen,
    const void                    *rdata,
    uint32_t                       ttl,
    DNSServiceRegisterRecordReply  callBack,
    void                          *context
    )
    {
    char *msg = NULL, *ptr;
    size_t len;
    ipc_msg_hdr *hdr = NULL;
    DNSServiceRef tmp = NULL;
    DNSRecordRef rref = NULL;
    int f1 = (flags & kDNSServiceFlagsShared) != 0;
    int f2 = (flags & kDNSServiceFlagsUnique) != 0;
    if (f1 + f2 != 1) return kDNSServiceErr_BadParam;

    if (!sdRef || sdRef->op != connection || sdRef->sockfd < 0)
        return kDNSServiceErr_BadReference;
    *RecordRef = NULL;

	len = sizeof(DNSServiceFlags);
    len += 2 * sizeof(uint32_t);  // interfaceIndex, ttl
    len += 3 * sizeof(uint16_t);  // rrtype, rrclass, rdlen
    len += strlen(fullname) + 1;
    len += rdlen;

    hdr = create_hdr(reg_record_request, &len, &ptr, 0);
    if (!hdr) goto error;
    msg = (char *)hdr;
    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(fullname, &ptr);
    put_short(rrtype, &ptr);
    put_short(rrclass, &ptr);
    put_short(rdlen, &ptr);
    put_rdata(rdlen, rdata, &ptr);
    put_long(ttl, &ptr);

    rref = malloc(sizeof(_DNSRecordRef_t));
    if (!rref) goto error;
    rref->app_context = context;
    rref->app_callback = callBack;
    rref->record_index = sdRef->max_index++;
    rref->sdr = sdRef;
    *RecordRef = rref;
    hdr->client_context.context = rref;
    hdr->reg_index = rref->record_index;

    return deliver_request(msg, sdRef, 0);

error:
    if (rref) free(rref);
    if (tmp) free(tmp);
    if (hdr) free(hdr);
    return kDNSServiceErr_Unknown;
    }

//sdRef returned by DNSServiceRegister()
DNSServiceErrorType DNSSD_API DNSServiceAddRecord
    (
    DNSServiceRef    sdRef,
    DNSRecordRef    *RecordRef,
    DNSServiceFlags  flags,
    uint16_t         rrtype,
    uint16_t         rdlen,
    const void      *rdata,
    uint32_t         ttl
    )
    {
    ipc_msg_hdr *hdr;
    size_t len = 0;
    char *ptr;
    DNSRecordRef rref;

    if (!sdRef || (sdRef->op != reg_service_request) || !RecordRef)
        return kDNSServiceErr_BadReference;
    *RecordRef = NULL;

    len += 2 * sizeof(uint16_t);  //rrtype, rdlen
    len += rdlen;
    len += sizeof(uint32_t);
    len += sizeof(DNSServiceFlags);

    hdr = create_hdr(add_record_request, &len, &ptr, 0);
    if (!hdr) return kDNSServiceErr_Unknown;
    put_flags(flags, &ptr);
    put_short(rrtype, &ptr);
    put_short(rdlen, &ptr);
    put_rdata(rdlen, rdata, &ptr);
    put_long(ttl, &ptr);

    rref = malloc(sizeof(_DNSRecordRef_t));
    if (!rref) goto error;
    rref->app_context = NULL;
    rref->app_callback = NULL;
    rref->record_index = sdRef->max_index++;
    rref->sdr = sdRef;
    *RecordRef = rref;
    hdr->client_context.context = rref;
    hdr->reg_index = rref->record_index;
    return deliver_request((char *)hdr, sdRef, 0);

error:
    if (hdr) free(hdr);
    if (rref) free(rref);
    if (*RecordRef) *RecordRef = NULL;
    return kDNSServiceErr_Unknown;
}

//DNSRecordRef returned by DNSServiceRegisterRecord or DNSServiceAddRecord
DNSServiceErrorType DNSSD_API DNSServiceUpdateRecord
    (
    DNSServiceRef    sdRef,
    DNSRecordRef     RecordRef,
    DNSServiceFlags  flags,
    uint16_t         rdlen,
    const void      *rdata,
    uint32_t         ttl
    )
    {
    ipc_msg_hdr *hdr;
    size_t len = 0;
    char *ptr;

	if (!sdRef) return kDNSServiceErr_BadReference;

    len += sizeof(uint16_t);
    len += rdlen;
    len += sizeof(uint32_t);
    len += sizeof(DNSServiceFlags);

    hdr = create_hdr(update_record_request, &len, &ptr, 0);
    if (!hdr) return kDNSServiceErr_Unknown;
    hdr->reg_index = RecordRef ? RecordRef->record_index : TXT_RECORD_INDEX;
    put_flags(flags, &ptr);
    put_short(rdlen, &ptr);
    put_rdata(rdlen, rdata, &ptr);
    put_long(ttl, &ptr);
    return deliver_request((char *)hdr, sdRef, 0);
    }

DNSServiceErrorType DNSSD_API DNSServiceRemoveRecord
	(
	DNSServiceRef    sdRef,
	DNSRecordRef     RecordRef,
	DNSServiceFlags  flags
	)
    {
    ipc_msg_hdr *hdr;
    size_t len = 0;
    char *ptr;
    DNSServiceErrorType err;

    if (!sdRef || !RecordRef || !sdRef->max_index)
        return kDNSServiceErr_BadReference;

    len += sizeof(flags);
    hdr = create_hdr(remove_record_request, &len, &ptr, 0);
    if (!hdr) return kDNSServiceErr_Unknown;
    hdr->reg_index = RecordRef->record_index;
    put_flags(flags, &ptr);
    err = deliver_request((char *)hdr, sdRef, 0);
    if (!err) free(RecordRef);
    return err;
    }

DNSServiceErrorType DNSSD_API DNSServiceReconfirmRecord
	(
	DNSServiceFlags  flags,
	uint32_t         interfaceIndex,
	const char      *fullname,
	uint16_t         rrtype,
	uint16_t         rrclass,
	uint16_t         rdlen,
	const void      *rdata
	)
    {
    char *ptr;
    size_t len;
    ipc_msg_hdr *hdr;
    DNSServiceRef tmp;

    len = sizeof(DNSServiceFlags);
    len += sizeof(uint32_t);
    len += strlen(fullname) + 1;
    len += 3 * sizeof(uint16_t);
    len += rdlen;
    tmp = connect_to_server();
    if (!tmp) return(kDNSServiceErr_Unknown);
    hdr = create_hdr(reconfirm_record_request, &len, &ptr, 1);
    if (!hdr) return(kDNSServiceErr_Unknown);

    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(fullname, &ptr);
    put_short(rrtype, &ptr);
    put_short(rrclass, &ptr);
    put_short(rdlen, &ptr);
    put_rdata(rdlen, rdata, &ptr);
	ConvertHeaderBytes(hdr);
    write_all(tmp->sockfd, (char *)hdr, (int) len);
    free(hdr);
    DNSServiceRefDeallocate(tmp);
    return(kDNSServiceErr_NoError);
    }

