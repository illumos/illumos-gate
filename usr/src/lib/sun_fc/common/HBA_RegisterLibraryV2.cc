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



#include "sun_fc.h"
#include "Trace.h"

/**
 * @memo	    Entry points for the V2 API
 * @postcondition   entrypoints contains the function pointers to this API
 * @return	    HBA_STATUS_OK if entrypoints updated
 * @param	    entrypoints The user-allocated buffer to store the API
 * 
 */
HBA_STATUS HBA_RegisterLibraryV2(PHBA_ENTRYPOINTSV2 entrypoints) {
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
    entrypoints->OpenAdapterByWWNHandler = Sun_fcOpenAdapterByWWN;
    entrypoints->GetFcpTargetMappingV2Handler = Sun_fcGetFcpTargetMappingV2;
    entrypoints->SendCTPassThruV2Handler = Sun_fcSendCTPassThruV2;
    entrypoints->RefreshAdapterConfigurationHandler =
	Sun_fcRefreshAdapterConfiguration;
    entrypoints->GetBindingCapabilityHandler = Sun_fcGetBindingCapability;
    entrypoints->GetBindingSupportHandler = Sun_fcGetBindingSupport;
    entrypoints->SetBindingSupportHandler = Sun_fcSetBindingSupport;
    entrypoints->SetPersistentBindingV2Handler = Sun_fcSetPersistentBindingV2;
    entrypoints->GetPersistentBindingV2Handler = Sun_fcGetPersistentBindingV2;
    entrypoints->RemovePersistentBindingHandler = Sun_fcRemovePersistentBinding;
    entrypoints->RemoveAllPersistentBindingsHandler =
	Sun_fcRemoveAllPersistentBindings;
    entrypoints->SendRNIDV2Handler = Sun_fcSendRNIDV2;
    entrypoints->ScsiInquiryV2Handler = Sun_fcScsiInquiryV2;
    entrypoints->ScsiReportLUNsV2Handler = Sun_fcScsiReportLUNsV2;
    entrypoints->ScsiReadCapacityV2Handler = Sun_fcScsiReadCapacityV2;
    entrypoints->GetVendorLibraryAttributesHandler =
	Sun_fcGetVendorLibraryAttributes;
    entrypoints->RemoveCallbackHandler = Sun_fcRemoveCallback;
    entrypoints->RegisterForAdapterAddEventsHandler =
	Sun_fcRegisterForAdapterAddEvents;
    entrypoints->RegisterForAdapterEventsHandler =
	Sun_fcRegisterForAdapterEvents;
    entrypoints->RegisterForAdapterPortEventsHandler =
	Sun_fcRegisterForAdapterPortEvents;
    entrypoints->RegisterForAdapterPortStatEventsHandler =
	Sun_fcRegisterForAdapterPortStatEvents;
    entrypoints->RegisterForTargetEventsHandler = Sun_fcRegisterForTargetEvents;
    entrypoints->RegisterForLinkEventsHandler = Sun_fcRegisterForLinkEvents;
    entrypoints->SendRLSHandler = Sun_fcSendRLS;
    entrypoints->SendRPLHandler = Sun_fcSendRPL;
    entrypoints->SendRPSHandler = Sun_fcSendRPS;
    entrypoints->SendSRLHandler = Sun_fcSendSRL;
    entrypoints->SendLIRRHandler = Sun_fcSendLIRR;
    entrypoints->GetFC4StatisticsHandler = Sun_fcGetFC4Statistics;
    entrypoints->GetFCPStatisticsHandler = Sun_fcGetFCPStatistics;
    return (HBA_STATUS_OK);
}
