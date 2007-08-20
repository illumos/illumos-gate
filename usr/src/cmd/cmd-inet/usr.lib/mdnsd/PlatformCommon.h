/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

    Change History (most recent first):

$Log: PlatformCommon.h,v $
Revision 1.4  2006/08/14 23:24:56  cheshire
Re-licensed mDNSResponder daemon source code under Apache License, Version 2.0

Revision 1.3  2005/01/19 19:19:21  ksekar
<rdar://problem/3960191> Need a way to turn off domain discovery

Revision 1.2  2004/12/01 03:30:29  cheshire
<rdar://problem/3889346> Add Unicast DNS support to mDNSPosix

Revision 1.1  2004/12/01 01:51:35  cheshire
Move ReadDDNSSettingsFromConfFile() from mDNSMacOSX.c to PlatformCommon.c

 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

extern void FindDefaultRouteIP(mDNSAddr *a);
extern void ReadDDNSSettingsFromConfFile(mDNS *const m, const char *const filename, domainname *const hostname, domainname *const domain, mDNSBool *DomainDiscoveryDisabled);
