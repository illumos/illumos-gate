/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
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

 	File:		uds_daemon.h

 	Contains:	Interfaces necessary to talk to uds_daemon.c.

 	Version:	1.0

    Change History (most recent first):

$Log: uds_daemon.h,v $
Revision 1.15  2006/08/14 23:24:57  cheshire
Re-licensed mDNSResponder daemon source code under Apache License, Version 2.0

Revision 1.14  2005/01/27 17:48:39  cheshire
Added comment about CFSocketInvalidate closing the underlying socket

Revision 1.13  2004/12/10 05:27:26  cheshire
<rdar://problem/3909147> Guard against multiple autoname services of the same type on the same machine

Revision 1.12  2004/12/10 04:28:28  cheshire
<rdar://problem/3914406> User not notified of name changes for services using new UDS API

Revision 1.11  2004/12/06 21:15:23  ksekar
<rdar://problem/3884386> mDNSResponder crashed in CheckServiceRegistrations

Revision 1.10  2004/10/26 04:31:44  cheshire
Rename CountSubTypes() as ChopSubTypes()

Revision 1.9  2004/09/30 00:25:00  ksekar
<rdar://problem/3695802> Dynamically update default registration domains on config change

Revision 1.8  2004/09/21 21:05:11  cheshire
Move duplicate code out of mDNSMacOSX/daemon.c and mDNSPosix/PosixDaemon.c,
into mDNSShared/uds_daemon.c

Revision 1.7  2004/09/17 01:08:55  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.6  2004/08/11 01:58:49  cheshire
Remove "mDNS *globalInstance" parameter from udsserver_init()

Revision 1.5  2004/06/18 04:44:58  rpantos
Use platform layer for socket types

Revision 1.4  2004/06/12 00:51:58  cheshire
Changes for Windows compatibility

Revision 1.3  2004/01/25 00:03:21  cheshire
Change to use mDNSVal16() instead of private PORT_AS_NUM() macro

Revision 1.2  2004/01/24 08:46:26  bradley
Added InterfaceID<->Index platform interfaces since they are now used by all platforms for the DNS-SD APIs.

Revision 1.1  2003/12/08 21:11:42  rpantos;
Changes necessary to support mDNSResponder on Linux.

*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mDNSEmbeddedAPI.h"
#include "dnssd_ipc.h"


/* Client interface: */

#define SRS_PORT(S) mDNSVal16((S)->RR_SRV.resrec.rdata->u.srv.port)

extern int udsserver_init(void);

// takes the next scheduled event time, does idle work, and returns the updated nextevent time
extern mDNSs32 udsserver_idle(mDNSs32 nextevent);

extern void udsserver_info(mDNS *const m);	// print out info about current state

extern void udsserver_handle_configchange(void);

extern int udsserver_exit(void);	// should be called prior to app exit

extern void udsserver_default_reg_domain_changed(const domainname *d, mDNSBool add);
extern void udsserver_default_browse_domain_changed(const domainname *d, mDNSBool add);

/* Routines that uds_daemon expects to link against: */

typedef	void (*udsEventCallback)(void *context);

extern mStatus udsSupportAddFDToEventLoop(dnssd_sock_t fd, udsEventCallback callback, void *context);
extern mStatus udsSupportRemoveFDFromEventLoop(dnssd_sock_t fd); // Note: This also CLOSES the file descriptor as well

// RecordUpdatedNiceLabel() can be a no-op on platforms that don't care about updating the machine's
// global default service name (was OS X calls the "Computer Name") in response to name conflicts.
extern void RecordUpdatedNiceLabel(mDNS *const m, mDNSs32 delay);

// Globals and functions defined in uds_daemon.c and also shared with the old "daemon.c" on OS X
extern mDNS mDNSStorage;
extern mDNSs32 ChopSubTypes(char *regtype);
extern AuthRecord *AllocateSubTypes(mDNSs32 NumSubTypes, char *p);
extern int CountExistingRegistrations(domainname *srv, mDNSIPPort port);
extern void FreeExtraRR(mDNS *const m, AuthRecord *const rr, mStatus result);
extern int CountPeerRegistrations(mDNS *const m, ServiceRecordSet *const srs);
