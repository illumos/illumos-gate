/*
 * ****************************************************************************
 *
 * Description
 *	vendorhbaapi.h - incombination with hbaapi.h, defines interface to
 *		vendor specific API
 *
 * License:
 *	The contents of this file are subject to the SNIA Public License
 *	Version 1.0 (the "License"); you may not use this file except in
 *	compliance with the License. You may obtain a copy of the License at
 *
 *	/http://www.snia.org/English/Resources/Code/OpenSource.html
 *
 *	Software distributed under the License is distributed on an "AS IS"
 *	basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *	the License for the specific language governing rights and limitations
 *	under the License.
 *
 * The Original Code is  SNIA HBA API general header file
 *
 * The Initial Developer of the Original Code is:
 *	Benjamin F. Kuo, Troika Networks, Inc. (benk@troikanetworks.com)
 *
 * Contributor(s):
 *	Tuan Lam, QLogic Corp. (t_lam@qlc.com)
 *	Dan Willie, Emulex Corp. (Dan.Willie@emulex.com)
 *	Dixon Hutchinson, Legato Systems, Inc. (dhutchin@legato.com)
 *	David Dillard, VERITAS Software Corp. (david.dillard@veritas.com)
 *
 * ****************************************************************************
 *
 *   Changes:
 *	12/12/2001 Original revision, code split out of hbaapi.h
 *	(for other changes... see the CVS logs)
 * ****************************************************************************
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VENDORSMHBAAPI_H_
#define	_VENDORSMHBAAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <vendorhbaapi.h>

/* SM-HBA-2 6.9.2 Function Prototypes */
typedef HBA_UINT32 (* SMHBAGetVersionFunc)();
typedef HBA_UINT32 (* SMHBAGetWrapperLibraryAttributesFunc)
	(HBA_UINT32, SMHBA_LIBRARYATTRIBUTES *);
typedef HBA_UINT32 (* SMHBAGetVendorLibraryAttributesFunc)
	(SMHBA_LIBRARYATTRIBUTES *);
typedef HBA_STATUS (* SMHBAGetAdapterAttributesFunc)
	(HBA_HANDLE, SMHBA_ADAPTERATTRIBUTES *);
typedef HBA_STATUS (* SMHBAGetNumberOfPortsFunc)
	(HBA_HANDLE, HBA_UINT32 *);
typedef HBA_STATUS (* SMHBAGetPortTypeFunc)
	(HBA_HANDLE, HBA_UINT32, HBA_PORTTYPE *);
typedef HBA_STATUS (* SMHBAGetAdapterPortAttributesFunc)
	(HBA_HANDLE, HBA_UINT32, SMHBA_PORTATTRIBUTES *);
typedef HBA_STATUS (* SMHBAGetDiscoveredPortAttributesFunc)
	(HBA_HANDLE, HBA_UINT32, HBA_UINT32, SMHBA_PORTATTRIBUTES *);
typedef HBA_STATUS (* SMHBAGetPortAttributesByWWNFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, SMHBA_PORTATTRIBUTES *);
typedef HBA_STATUS (* SMHBAGetFCPhyAttributesFunc)
	(HBA_HANDLE, HBA_UINT32, HBA_UINT32, SMHBA_FC_PHY *);
typedef HBA_STATUS (* SMHBAGetSASPhyAttributesFunc)
	(HBA_HANDLE, HBA_UINT32, HBA_UINT32, SMHBA_SAS_PHY *);
typedef HBA_STATUS (* SMHBAGetProtocolStatisticsFunc)
	(HBA_HANDLE, HBA_UINT32, HBA_UINT32, SMHBA_PROTOCOLSTATISTICS *);
typedef HBA_STATUS (* SMHBAGetPhyStatisticsFunc)
	(HBA_HANDLE, HBA_UINT32, HBA_UINT32, SMHBA_PHYSTATISTICS *);
typedef HBA_STATUS (* SMHBASendTESTFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32, void *, HBA_UINT32);
typedef HBA_STATUS (* SMHBASendECHOFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32, void *, HBA_UINT32,
	void *, HBA_UINT32 *);
typedef HBA_STATUS (* SMHBASendSMPPassThruFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_WWN, void *, HBA_UINT32, void *,
	HBA_UINT32 *);
typedef HBA_STATUS (* SMHBAGetBindingCapabilityFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, SMHBA_BIND_CAPABILITY *);
typedef HBA_STATUS (* SMHBAGetBindingSupportFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, SMHBA_BIND_CAPABILITY *);
typedef HBA_STATUS (* SMHBASetBindingSupportFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, SMHBA_BIND_CAPABILITY);
typedef HBA_STATUS (* SMHBAGetTargetMappingFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, SMHBA_TARGETMAPPING *);
typedef HBA_STATUS (* SMHBAGetPersistentBindingFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, SMHBA_BINDING *);
typedef HBA_STATUS (* SMHBASetPersistentBindingFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, const SMHBA_BINDING *);
typedef HBA_STATUS (* SMHBARemovePersistentBindingFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, const SMHBA_BINDING *);
typedef HBA_STATUS (* SMHBARemoveAllPersistentBindingsFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN);
typedef HBA_STATUS (* SMHBAGetLUNStatisticsFunc)
	(HBA_HANDLE, const HBA_SCSIID *, SMHBA_PROTOCOLSTATISTICS *);
typedef HBA_STATUS (* SMHBARegisterForAdapterAddEventsFunc)
	(void (*)(void *, HBA_WWN, HBA_UINT32), void *, HBA_CALLBACKHANDLE *);
typedef HBA_STATUS (* SMHBARegisterForAdapterEventsFunc)
	(void (*)(void *, HBA_WWN, HBA_UINT32),
	void *, HBA_HANDLE, HBA_CALLBACKHANDLE *);
typedef HBA_STATUS    (* SMHBARegisterForAdapterPortEventsFunc)
	(void (*)(void *, HBA_WWN, HBA_UINT32, HBA_UINT32),
	void *, HBA_HANDLE, HBA_WWN, HBA_UINT32, HBA_CALLBACKHANDLE *);
typedef HBA_STATUS    (* SMHBARegisterForAdapterPortStatEventsFunc)
	(void (*)(void *, HBA_WWN, HBA_UINT32, HBA_UINT32),
	void *, HBA_HANDLE, HBA_WWN, HBA_UINT32, SMHBA_PROTOCOLSTATISTICS,
	HBA_UINT32, HBA_CALLBACKHANDLE *);
typedef HBA_STATUS    (* SMHBARegisterForAdapterPhyStatEventsFunc)
	(void (*)(void *, HBA_WWN, HBA_UINT32, HBA_UINT32),
	void *, HBA_HANDLE, HBA_WWN, HBA_UINT32, SMHBA_PHYSTATISTICS,
	HBA_UINT32, HBA_CALLBACKHANDLE *);
typedef HBA_STATUS    (* SMHBARegisterForTargetEventsFunc)
	(void (*)(void *, HBA_WWN, HBA_WWN, HBA_WWN, HBA_UINT32),
	void *, HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_WWN,
	HBA_CALLBACKHANDLE *, HBA_UINT32);
typedef HBA_STATUS    (* SMHBAScsiInquiryFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_WWN, SMHBA_SCSILUN, HBA_UINT8,
	HBA_UINT8, void *, HBA_UINT32 *, HBA_UINT8 *, void *, HBA_UINT32 *);
typedef HBA_STATUS    (* SMHBAScsiReportLUNsFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_WWN, void *, HBA_UINT32 *,
	HBA_UINT8 *, void *, HBA_UINT32 *);
typedef HBA_STATUS    (* SMHBAScsiReadCapacityFunc)
	(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_WWN, SMHBA_SCSILUN, void *,
	HBA_UINT32 *, HBA_UINT8 *, void *, HBA_UINT32 *);

/* SM-HBA-2 6.9.3 Entry Point Data Declarations */
typedef struct SMHBA_EntryPoints {
	SMHBAGetVersionFunc			GetVersionHandler;
	HBALoadLibraryFunc			LoadLibraryHandler;
	HBAFreeLibraryFunc			FreeLibraryHandler;
	HBAGetNumberOfAdaptersFunc		GetNumberOfAdaptersHandler;
	HBARefreshInformationFunc		RefreshInformationHandler;
	SMHBAGetVendorLibraryAttributesFunc
		GetVendorLibraryAttributesHandler;
	HBAGetAdapterNameFunc			GetAdapterNameHandler;
	HBAOpenAdapterFunc			OpenAdapterHandler;
	HBACloseAdapterFunc			CloseAdapterHandler;
	SMHBAGetAdapterAttributesFunc		GetAdapterAttributesHandler;
	SMHBAGetNumberOfPortsFunc		GetNumberOfPortsHandler;
	SMHBAGetPortTypeFunc			GetPortTypeHandler;
	SMHBAGetAdapterPortAttributesFunc
		GetAdapterPortAttributesHandler;
	SMHBAGetDiscoveredPortAttributesFunc
		GetDiscoveredPortAttributesHandler;
	SMHBAGetPortAttributesByWWNFunc		GetPortAttributesByWWNHandler;
	SMHBAGetFCPhyAttributesFunc		GetFCPhyAttributesHandler;
	SMHBAGetSASPhyAttributesFunc		GetSASPhyAttributesHandler;
	SMHBAGetProtocolStatisticsFunc		GetProtocolStatisticsHandler;
	SMHBAGetPhyStatisticsFunc		GetPhyStatisticsHandler;
	HBASendCTPassThruV2Func			SendCTPassThruV2Handler;
	HBASetRNIDMgmtInfoFunc			SetRNIDMgmtInfoHandler;
	HBAGetRNIDMgmtInfoFunc			GetRNIDMgmtInfoHandler;
	HBASendRNIDV2Func			SendRNIDV2Handler;
	HBASendRPLFunc				SendRPLHandler;
	HBASendRPSFunc				SendRPSHandler;
	HBASendSRLFunc				SendSRLHandler;
	HBASendLIRRFunc				SendLIRRHandler;
	HBASendRLSFunc				SendRLSHandler;
	SMHBASendTESTFunc			SendTESTHandler;
	SMHBASendECHOFunc			SendECHOHandler;
	SMHBASendSMPPassThruFunc		SendSMPPassThruHandler;
	SMHBAGetBindingCapabilityFunc		GetBindingCapabilityHandler;
	SMHBAGetBindingSupportFunc		GetBindingSupportHandler;
	SMHBASetBindingSupportFunc		SetBindingSupportHandler;
	SMHBAGetTargetMappingFunc		GetTargetMappingHandler;
	SMHBAGetPersistentBindingFunc		GetPersistentBindingHandler;
	SMHBASetPersistentBindingFunc		SetPersistentBindingHandler;
	SMHBARemovePersistentBindingFunc	RemovePersistentBindingHandler;
	SMHBARemoveAllPersistentBindingsFunc
		RemoveAllPersistentBindingsHandler;
	SMHBAGetLUNStatisticsFunc		GetLUNStatisticsHandler;
	SMHBAScsiInquiryFunc			ScsiInquiryHandler;
	SMHBAScsiReportLUNsFunc			ScsiReportLUNsHandler;
	SMHBAScsiReadCapacityFunc		ScsiReadCapacityHandler;
	SMHBARegisterForAdapterAddEventsFunc
		RegisterForAdapterAddEventsHandler;
	SMHBARegisterForAdapterEventsFunc	RegisterForAdapterEventsHandler;
	SMHBARegisterForAdapterPortEventsFunc
		RegisterForAdapterPortEventsHandler;
	SMHBARegisterForAdapterPortStatEventsFunc
		RegisterForAdapterPortStatEventsHandler;
	SMHBARegisterForAdapterPhyStatEventsFunc
		RegisterForAdapterPhyStatEventsHandler;
	SMHBARegisterForTargetEventsFunc	RegisterForTargetEventsHandler;
	HBARegisterForLinkEventsFunc		RegisterForLinkEventsHandler;
	HBARemoveCallbackFunc			RemoveCallbackHandler;
} SMHBA_ENTRYPOINTS, *PSMHBA_ENTRYPOINTS;

typedef HBA_UINT32 (* SMHBARegisterLibraryFunc)(SMHBA_ENTRYPOINTS *);

HBA_STATUS SMHBA_RegisterLibrary(
	SMHBA_ENTRYPOINTS	*functionTable
);

#ifdef __cplusplus
}
#endif

#endif /* _VENDORSMHBAAPI_H_ */
