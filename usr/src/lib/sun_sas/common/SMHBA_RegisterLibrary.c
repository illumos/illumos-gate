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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include    <sun_sas.h>

HBA_STATUS
SMHBA_RegisterLibrary(PSMHBA_ENTRYPOINTS entrypoints)
{
	entrypoints->GetVersionHandler = Sun_sasGetVersion;
	entrypoints->LoadLibraryHandler = Sun_sasLoadLibrary;
	entrypoints->FreeLibraryHandler = Sun_sasFreeLibrary;
	entrypoints->GetNumberOfAdaptersHandler = Sun_sasGetNumberOfAdapters;
	entrypoints->RefreshInformationHandler = Sun_sasRefreshInformation;
	entrypoints->GetVendorLibraryAttributesHandler =
	    Sun_sasGetVendorLibraryAttributes;
	entrypoints->GetAdapterNameHandler = Sun_sasGetAdapterName;
	entrypoints->OpenAdapterHandler = Sun_sasOpenAdapter;
	entrypoints->CloseAdapterHandler = Sun_sasCloseAdapter;
	entrypoints->GetAdapterAttributesHandler = Sun_sasGetAdapterAttributes;
	entrypoints->GetNumberOfPortsHandler = Sun_sasGetNumberOfPorts;
	entrypoints->GetPortTypeHandler = Sun_sasGetPortType;
	entrypoints->GetAdapterPortAttributesHandler =
	    Sun_sasGetAdapterPortAttributes;
	entrypoints->GetDiscoveredPortAttributesHandler =
	    Sun_sasGetDiscoveredPortAttributes;
	entrypoints->GetPortAttributesByWWNHandler =
	    Sun_sasGetPortAttributesByWWN;
	entrypoints->GetFCPhyAttributesHandler = NULL;
	entrypoints->GetSASPhyAttributesHandler = Sun_sasGetSASPhyAttributes;
	entrypoints->GetProtocolStatisticsHandler =
	    Sun_sasGetProtocolStatistics;
	entrypoints->GetPhyStatisticsHandler = Sun_sasGetPhyStatistics;
	entrypoints->SendCTPassThruV2Handler = NULL;
	entrypoints->SetRNIDMgmtInfoHandler = NULL;
	entrypoints->GetRNIDMgmtInfoHandler = NULL;
	entrypoints->SendRNIDV2Handler = NULL;
	entrypoints->SendRPLHandler = NULL;
	entrypoints->SendRPSHandler = NULL;
	entrypoints->SendSRLHandler = NULL;
	entrypoints->SendLIRRHandler = NULL;
	entrypoints->SendRLSHandler = NULL;
	entrypoints->SendTESTHandler = NULL;
	entrypoints->SendECHOHandler = NULL;
	entrypoints->SendSMPPassThruHandler = Sun_sasSendSMPPassThru;
	entrypoints->GetBindingCapabilityHandler = NULL;
		/* Sun_sasGetBindingCapability; */
	entrypoints->GetBindingSupportHandler = NULL;
	entrypoints->SetBindingSupportHandler = NULL;
		/* Sun_sasSetBindingSupport; */
	entrypoints->GetTargetMappingHandler = Sun_sasGetTargetMapping;
	entrypoints->SetPersistentBindingHandler = Sun_sasSetPersistentBinding;
	entrypoints->GetPersistentBindingHandler = Sun_sasGetPersistentBinding;
	entrypoints->RemovePersistentBindingHandler = NULL;
		/* Sun_sasRemovePersistentBinding; */
	entrypoints->RemoveAllPersistentBindingsHandler = NULL;
		/* Sun_sasRemoveAllPersistentBindings; */
	entrypoints->GetLUNStatisticsHandler = Sun_sasGetLUNStatistics;
	entrypoints->ScsiInquiryHandler = Sun_sasScsiInquiry;
	entrypoints->ScsiReportLUNsHandler = Sun_sasScsiReportLUNs;
	entrypoints->ScsiReadCapacityHandler = Sun_sasScsiReadCapacity;
	entrypoints->RegisterForAdapterAddEventsHandler = NULL;
		/* Sun_sasRegisterForAdapterAddEvents; */
	entrypoints->RegisterForAdapterEventsHandler = NULL;
		/* Sun_sasRegisterForAdapterEvents; */
	entrypoints->RegisterForAdapterPortEventsHandler = NULL;
		/* Sun_sasRegisterForAdapterPortEvents; */
	entrypoints->RegisterForAdapterPortStatEventsHandler = NULL;
		/* Sun_sasRegisterForAdapterPortStatEvents; */
	entrypoints->RegisterForAdapterPhyStatEventsHandler = NULL;
		/* Sun_sasRegisterForAdapterPhyStatEvents; */
	entrypoints->RegisterForTargetEventsHandler = NULL;
		/* Sun_sasRegisterForTargetEvents; */
	entrypoints->RegisterForLinkEventsHandler = NULL;
		/* Sun_sasRegisterForLinkEvents; */
	entrypoints->RemoveCallbackHandler = NULL; /* Sun_sasRemoveCallback; */
	return (HBA_STATUS_OK);
}
