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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SUN_FC_H
#define	_SUN_FC_H



#include <hbaapi.h>
#include <vendorhbaapi.h>

#define HR_SECOND	1000000000

#ifdef	__cplusplus
extern "C" {
#endif


// Public External routines
extern HBA_STATUS HBA_RegisterLibrary(PHBA_ENTRYPOINTS);
extern HBA_UINT32 Sun_fcGetVersion();
extern HBA_STATUS Sun_fcLoadLibrary();
extern HBA_STATUS Sun_fcFreeLibrary();
extern HBA_UINT32 Sun_fcGetNumberOfAdapters();
extern HBA_STATUS Sun_fcGetAdapterName(HBA_UINT32, char *);
extern HBA_HANDLE Sun_fcOpenAdapter(char *);
extern void Sun_fcCloseAdapter(HBA_HANDLE);
extern HBA_STATUS Sun_fcGetAdapterAttributes(HBA_HANDLE,
    PHBA_ADAPTERATTRIBUTES);
extern HBA_STATUS Sun_fcGetAdapterPortAttributes(HBA_HANDLE, HBA_UINT32,
    PHBA_PORTATTRIBUTES);
extern HBA_STATUS Sun_fcGetPortStatistics(HBA_HANDLE, HBA_UINT32,
    PHBA_PORTSTATISTICS);
extern HBA_STATUS Sun_fcGetDiscoveredPortAttributes(HBA_HANDLE, HBA_UINT32,
    HBA_UINT32, PHBA_PORTATTRIBUTES);
extern HBA_STATUS Sun_fcGetPortAttributesByWWN(HBA_HANDLE, HBA_WWN,
    PHBA_PORTATTRIBUTES);
extern HBA_STATUS Sun_fcSendCTPassThru(HBA_HANDLE, void *, HBA_UINT32, void *,
    HBA_UINT32);
extern void Sun_fcRefreshInformation(HBA_HANDLE);
extern void Sun_fcResetStatistics(HBA_HANDLE handle, HBA_UINT32 port);
extern HBA_STATUS Sun_fcGetFcpTargetMapping(HBA_HANDLE, PHBA_FCPTARGETMAPPING);
extern HBA_STATUS Sun_fcGetFcpPersistentBinding(HBA_HANDLE, PHBA_FCPBINDING);
extern HBA_STATUS Sun_fcGetEventBuffer(HBA_HANDLE, PHBA_EVENTINFO,
    HBA_UINT32 *);
extern HBA_STATUS Sun_fcSetRNIDMgmtInfo(HBA_HANDLE, HBA_MGMTINFO);
extern HBA_STATUS Sun_fcGetRNIDMgmtInfo(HBA_HANDLE, PHBA_MGMTINFO);
extern HBA_STATUS Sun_fcSendRNID(HBA_HANDLE, HBA_WWN, HBA_WWNTYPE,
    void *, HBA_UINT32 *);
extern HBA_STATUS Sun_fcSendScsiInquiry(HBA_HANDLE, HBA_WWN, HBA_UINT64,
    HBA_UINT8, HBA_UINT32, void *, HBA_UINT32, void *, HBA_UINT32);
extern HBA_STATUS Sun_fcSendReportLUNs(HBA_HANDLE, HBA_WWN, void *, HBA_UINT32,
    void *, HBA_UINT32);
extern HBA_STATUS Sun_fcSendReadCapacity(HBA_HANDLE, HBA_WWN, HBA_UINT64,
    void *, HBA_UINT32, void *, HBA_UINT32);

// V2 external routines
extern HBA_STATUS Sun_fcOpenAdapterByWWN(HBA_HANDLE *, HBA_WWN);
extern HBA_STATUS Sun_fcGetFcpTargetMappingV2(HBA_HANDLE, HBA_WWN,
    HBA_FCPTARGETMAPPINGV2 *);
extern HBA_STATUS Sun_fcSendCTPassThruV2(HBA_HANDLE, HBA_WWN, void *,
    HBA_UINT32, void *, HBA_UINT32 *);
extern void Sun_fcRefreshAdapterConfiguration(void);
extern HBA_STATUS Sun_fcGetBindingCapability(HBA_HANDLE, HBA_WWN,
    HBA_BIND_CAPABILITY *);
extern HBA_STATUS Sun_fcGetBindingSupport(HBA_HANDLE, HBA_WWN,
    HBA_BIND_CAPABILITY *);
extern HBA_STATUS Sun_fcSetBindingSupport(HBA_HANDLE, HBA_WWN,
    HBA_BIND_CAPABILITY);
extern HBA_STATUS Sun_fcSetPersistentBindingV2(HBA_HANDLE, HBA_WWN,
    const HBA_FCPBINDING2 *);
extern HBA_STATUS Sun_fcGetPersistentBindingV2(HBA_HANDLE, HBA_WWN,
    HBA_FCPBINDING2 *);
extern HBA_STATUS Sun_fcRemovePersistentBinding(HBA_HANDLE, HBA_WWN,
    const HBA_FCPBINDING2 *);
extern HBA_STATUS Sun_fcRemoveAllPersistentBindings(HBA_HANDLE, HBA_WWN);
extern HBA_STATUS Sun_fcSendRNIDV2(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32,
    HBA_UINT32, void *, HBA_UINT32*);
extern HBA_STATUS Sun_fcScsiInquiryV2(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT64,
    HBA_UINT8, HBA_UINT8, void *, HBA_UINT32 *, HBA_UINT8 *, void *,
    HBA_UINT32 *);
extern HBA_STATUS Sun_fcScsiReportLUNsV2(HBA_HANDLE, HBA_WWN, HBA_WWN, void *,
    HBA_UINT32 *, HBA_UINT8 *, void *, HBA_UINT32 *);
extern HBA_STATUS Sun_fcScsiReadCapacityV2(HBA_HANDLE, HBA_WWN, HBA_WWN,
    HBA_UINT64, void *, HBA_UINT32 *, HBA_UINT8 *, void *, HBA_UINT32 *);
extern HBA_UINT32 Sun_fcGetVendorLibraryAttributes(HBA_LIBRARYATTRIBUTES *);
extern HBA_STATUS Sun_fcRemoveCallback(HBA_CALLBACKHANDLE);
extern HBA_STATUS Sun_fcRegisterForAdapterAddEvents(void (*)(void *, HBA_WWN,
    HBA_UINT32), void *, HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_fcRegisterForAdapterEvents(void (*)(void *, HBA_WWN,
    HBA_UINT32), void *, HBA_HANDLE, HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_fcRegisterForAdapterPortEvents(void (*)(void *, HBA_WWN,
    HBA_UINT32, HBA_UINT32), void *, HBA_HANDLE, HBA_WWN, HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_fcRegisterForAdapterPortStatEvents(void (*)(void *,
	    HBA_WWN, HBA_UINT32), void *, HBA_HANDLE, HBA_WWN,
    HBA_PORTSTATISTICS, HBA_UINT32, HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_fcRegisterForTargetEvents(void (*)(void *, HBA_WWN,
	    HBA_WWN, HBA_UINT32), void *, HBA_HANDLE, HBA_WWN, HBA_WWN,
    HBA_CALLBACKHANDLE *, HBA_UINT32);
extern HBA_STATUS Sun_fcRegisterForLinkEvents(void (*)(void *, HBA_WWN,
    HBA_UINT32, void *, HBA_UINT32), void *, void *, HBA_UINT32, HBA_HANDLE,
    HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_fcSendRLS(HBA_HANDLE, HBA_WWN, HBA_WWN,
    void *, HBA_UINT32 *);
extern HBA_STATUS Sun_fcSendRPL(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32,
    HBA_UINT32, void *, HBA_UINT32 *);
extern HBA_STATUS Sun_fcSendRPS(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32,
    HBA_WWN, HBA_UINT32, void *, HBA_UINT32 *);
extern HBA_STATUS Sun_fcSendSRL(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32,
    void *, HBA_UINT32 *);
extern HBA_STATUS Sun_fcSendLIRR(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT8,
    HBA_UINT8, void *, HBA_UINT32 *);
extern HBA_STATUS Sun_fcGetFC4Statistics(HBA_HANDLE, HBA_WWN, HBA_UINT8,
    HBA_FC4STATISTICS *);
extern HBA_STATUS Sun_fcGetFCPStatistics(HBA_HANDLE, const HBA_SCSIID *,
    HBA_FC4STATISTICS *);

#ifdef	__cplusplus
}
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#ifdef _BIG_ENDIAN
#define htonll(x)   (x)
#define ntohll(x)   (x)
#else
#define htonll(x)   ((((uint64_t)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x)   ((((uint64_t)ntohl(x)) << 32) + ntohl(x >> 32))
#endif



#include <string.h>
inline u_longlong_t
wwnConversion(uchar_t *wwn) {
	u_longlong_t tmp;
	memcpy(&tmp, wwn, sizeof (u_longlong_t));
	return (ntohll(tmp));
}

#ifndef SCMD_REPORT_LUNS
#define	    SCMD_REPORT_LUNS       0xA0
#endif



#endif /* _SUN_FC_H */
