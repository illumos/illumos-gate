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



#include    "sun_fc.h"
#include    "Trace.h"

/**
 * @memo	    Set up entry points for V1 API
 * @return	    HBA_STATUS_OK if the entry points were filled in
 * @param	    entrypoints user allocated buffer to store entry points
 * 
 */
HBA_STATUS HBA_RegisterLibrary(PHBA_ENTRYPOINTS entrypoints) {
    Trace log("HBA_RegisterLibrary");
    entrypoints->GetVersionHandler = Sun_fcGetVersion;
    entrypoints->LoadLibraryHandler = Sun_fcLoadLibrary;
    entrypoints->FreeLibraryHandler = Sun_fcFreeLibrary;
    entrypoints->GetNumberOfAdaptersHandler = Sun_fcGetNumberOfAdapters;
    entrypoints->GetAdapterNameHandler = Sun_fcGetAdapterName;
    entrypoints->OpenAdapterHandler = Sun_fcOpenAdapter;
    entrypoints->CloseAdapterHandler = Sun_fcCloseAdapter;
    entrypoints->GetAdapterAttributesHandler = Sun_fcGetAdapterAttributes;
    entrypoints->GetAdapterPortAttributesHandler =
	    Sun_fcGetAdapterPortAttributes;
    entrypoints->GetPortStatisticsHandler = Sun_fcGetPortStatistics;
    entrypoints->GetDiscoveredPortAttributesHandler =
	    Sun_fcGetDiscoveredPortAttributes;
    entrypoints->GetPortAttributesByWWNHandler = Sun_fcGetPortAttributesByWWN;
    entrypoints->SendCTPassThruHandler = Sun_fcSendCTPassThru;
    entrypoints->RefreshInformationHandler = Sun_fcRefreshInformation;
    entrypoints->ResetStatisticsHandler = Sun_fcResetStatistics;
    entrypoints->GetFcpTargetMappingHandler = Sun_fcGetFcpTargetMapping;
    entrypoints->GetFcpPersistentBindingHandler = Sun_fcGetFcpPersistentBinding;
    entrypoints->GetEventBufferHandler = Sun_fcGetEventBuffer;
    entrypoints->SetRNIDMgmtInfoHandler = Sun_fcSetRNIDMgmtInfo;
    entrypoints->GetRNIDMgmtInfoHandler = Sun_fcGetRNIDMgmtInfo;
    entrypoints->SendRNIDHandler = Sun_fcSendRNID;
    entrypoints->ScsiInquiryHandler = Sun_fcSendScsiInquiry;
    entrypoints->ReportLUNsHandler = Sun_fcSendReportLUNs;
    entrypoints->ReadCapacityHandler = Sun_fcSendReadCapacity;
    return (HBA_STATUS_OK);
}
