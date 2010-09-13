/******************************************************************************
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
 *******************************************************************************
 *
 *   Changes:
 *	12/12/2001 Original revision, code split out of hbaapi.h
 *	(for other changes... see the CVS logs)
 ******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


#ifndef VENDOR_HBA_API_H
#define VENDOR_HBA_API_H


/* 4.2.12 HBA Library Function Table */
typedef HBA_UINT32	(* HBAGetVersionFunc)();
typedef HBA_STATUS	(* HBALoadLibraryFunc)();
typedef HBA_STATUS	(* HBAFreeLibraryFunc)();
typedef HBA_UINT32	(* HBAGetNumberOfAdaptersFunc)();
typedef HBA_STATUS	(* HBAGetAdapterNameFunc)(HBA_UINT32, char *);
/*
 * Open Adapter.... the vendor function is limmited to 16 bits,
 * the wrapper library will mask off the upper 16.
 * Maybe typedef should be:
 * typedef HBA_UINT16	(* HBAOpenAdapterFunc)(char *);
 */
typedef HBA_HANDLE	(* HBAOpenAdapterFunc)(char *);
typedef HBA_STATUS	(* HBAOpenAdapterByWWNFunc)
    (HBA_HANDLE *, HBA_WWN);
typedef void		(* HBACloseAdapterFunc)(HBA_HANDLE);
typedef HBA_STATUS	(* HBAGetAdapterAttributesFunc)
    (HBA_HANDLE, HBA_ADAPTERATTRIBUTES *);
typedef HBA_STATUS	(* HBAGetAdapterPortAttributesFunc)
    (HBA_HANDLE, HBA_UINT32, HBA_PORTATTRIBUTES *);
typedef HBA_STATUS	(* HBAGetPortStatisticsFunc)
    (HBA_HANDLE, HBA_UINT32, HBA_PORTSTATISTICS *);
typedef HBA_STATUS	(* HBAGetDiscoveredPortAttributesFunc)
    (HBA_HANDLE, HBA_UINT32, HBA_UINT32, HBA_PORTATTRIBUTES *);
typedef HBA_STATUS	(* HBAGetPortAttributesByWWNFunc)
    (HBA_HANDLE, HBA_WWN, HBA_PORTATTRIBUTES *);
typedef HBA_STATUS	(* HBASendCTPassThruV2Func)
    (HBA_HANDLE, HBA_WWN, void *, HBA_UINT32, void *, HBA_UINT32 *);
typedef void		(* HBARefreshInformationFunc)(HBA_HANDLE);
typedef void		(* HBARefreshAdapterConfigurationFunc) ();
typedef void		(* HBAResetStatisticsFunc)(HBA_HANDLE, HBA_UINT32);
typedef HBA_STATUS	(* HBAGetFcpTargetMappingV2Func)
    (HBA_HANDLE, HBA_WWN, HBA_FCPTARGETMAPPINGV2 *);
typedef HBA_STATUS	(* HBAGetBindingCapabilityFunc)
    (HBA_HANDLE, HBA_WWN, HBA_BIND_CAPABILITY *);
typedef HBA_STATUS	(* HBAGetBindingSupportFunc)
    (HBA_HANDLE, HBA_WWN, HBA_BIND_CAPABILITY *);
typedef HBA_STATUS	(* HBASetBindingSupportFunc)
    (HBA_HANDLE, HBA_WWN, HBA_BIND_CAPABILITY);
typedef HBA_STATUS	(* HBASetPersistentBindingV2Func)
    (HBA_HANDLE, HBA_WWN, const HBA_FCPBINDING2 *);
typedef HBA_STATUS	(* HBAGetPersistentBindingV2Func)
    (HBA_HANDLE, HBA_WWN, HBA_FCPBINDING2 *);
typedef HBA_STATUS	(* HBARemovePersistentBindingFunc)
    (HBA_HANDLE, HBA_WWN, const HBA_FCPBINDING2 *);
typedef HBA_STATUS	(* HBARemoveAllPersistentBindingsFunc)
    (HBA_HANDLE, HBA_WWN);
typedef HBA_STATUS	(* HBAGetEventBufferFunc)
    (HBA_HANDLE, HBA_EVENTINFO *, HBA_UINT32 *);
typedef HBA_STATUS	(* HBASetRNIDMgmtInfoFunc)
    (HBA_HANDLE, HBA_MGMTINFO);
typedef HBA_STATUS	(* HBAGetRNIDMgmtInfoFunc)
    (HBA_HANDLE, HBA_MGMTINFO *);
typedef HBA_STATUS	(* HBASendRNIDV2Func)
    (HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32, HBA_UINT32, void *, HBA_UINT32*);
typedef HBA_STATUS	(* HBAScsiInquiryV2Func)
    (HBA_HANDLE,HBA_WWN,HBA_WWN, HBA_UINT64, HBA_UINT8, HBA_UINT8,
     void *, HBA_UINT32 *, HBA_UINT8 *, void *, HBA_UINT32 *);
typedef HBA_STATUS	(* HBAScsiReportLUNsV2Func)
    (HBA_HANDLE, HBA_WWN, HBA_WWN, void *, HBA_UINT32 *, HBA_UINT8 *,
     void *, HBA_UINT32 *);
typedef HBA_STATUS	(* HBAScsiReadCapacityV2Func)
    (HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT64, void *, HBA_UINT32 *,
     HBA_UINT8 *, void *, HBA_UINT32 *);
typedef HBA_UINT32	(* HBAGetVendorLibraryAttributesFunc)
    (HBA_LIBRARYATTRIBUTES *);
typedef HBA_STATUS	(* HBARemoveCallbackFunc) (HBA_CALLBACKHANDLE);
typedef HBA_STATUS	(* HBARegisterForAdapterAddEventsFunc)
    (void (*)(void *, HBA_WWN, HBA_UINT32), void *, HBA_CALLBACKHANDLE *);
typedef HBA_STATUS	(* HBARegisterForAdapterEventsFunc)
    (void (*)(void *, HBA_WWN, HBA_UINT32), void *, HBA_HANDLE,
     HBA_CALLBACKHANDLE *);
typedef HBA_STATUS	(* HBARegisterForAdapterPortEventsFunc)
    (void (*)(void *, HBA_WWN, HBA_UINT32, HBA_UINT32), void *, HBA_HANDLE,
     HBA_WWN, HBA_CALLBACKHANDLE *);
typedef HBA_STATUS	(* HBARegisterForAdapterPortStatEventsFunc)
    (void (*)(void *, HBA_WWN, HBA_UINT32), void *, HBA_HANDLE, HBA_WWN,
     HBA_PORTSTATISTICS, HBA_UINT32, HBA_CALLBACKHANDLE *);
typedef HBA_STATUS	(* HBARegisterForTargetEventsFunc)
    (void (*)(void *, HBA_WWN, HBA_WWN, HBA_UINT32), void *, HBA_HANDLE,
     HBA_WWN, HBA_WWN, HBA_CALLBACKHANDLE *,
     HBA_UINT32 );
typedef HBA_STATUS	(* HBARegisterForLinkEventsFunc)
    (void (*)(void *, HBA_WWN, HBA_UINT32, void *, HBA_UINT32), void *, void *,
     HBA_UINT32, HBA_HANDLE, HBA_CALLBACKHANDLE *);
typedef HBA_STATUS	(* HBASendRPLFunc)
    (HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32, HBA_UINT32, void *, HBA_UINT32 *);
typedef HBA_STATUS	(* HBASendRPSFunc)
    (HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32, HBA_WWN, HBA_UINT32, void *,
     HBA_UINT32 *);
typedef HBA_STATUS	(* HBASendSRLFunc)
    (HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT32, void *, HBA_UINT32 *);
typedef HBA_STATUS	(* HBASendLIRRFunc)
    (HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_UINT8, HBA_UINT8, void *, HBA_UINT32 *);
typedef HBA_STATUS	(* HBAGetFC4StatisticsFunc)
    (HBA_HANDLE, HBA_WWN, HBA_UINT8, HBA_FC4STATISTICS *);
typedef HBA_STATUS	(* HBAGetFCPStatisticsFunc)
    (HBA_HANDLE, const HBA_SCSIID *, HBA_FC4STATISTICS *);
typedef HBA_STATUS	(* HBASendRLSFunc)
    (HBA_HANDLE, HBA_WWN, HBA_WWN, void *, HBA_UINT32 *);


/* Deprecated, but still supported functions */
typedef HBA_STATUS	(* HBAGetFcpTargetMappingFunc)
    (HBA_HANDLE, HBA_FCPTARGETMAPPING *);
typedef HBA_STATUS	(* HBAGetFcpPersistentBindingFunc)
    (HBA_HANDLE, HBA_FCPBINDING *);
typedef HBA_STATUS	(* HBASendCTPassThruFunc)
    (HBA_HANDLE, void *, HBA_UINT32, void *, HBA_UINT32);
typedef HBA_STATUS	(* HBASendScsiInquiryFunc)
    (HBA_HANDLE, HBA_WWN,HBA_UINT64, HBA_UINT8, HBA_UINT32, void *,
     HBA_UINT32, void *, HBA_UINT32);
typedef HBA_STATUS	(* HBASendReportLUNsFunc)
    (HBA_HANDLE, HBA_WWN, void *, HBA_UINT32, void *, HBA_UINT32);
typedef HBA_STATUS	(* HBASendReadCapacityFunc)
    (HBA_HANDLE, HBA_WWN, HBA_UINT64, void *, HBA_UINT32, void *,
     HBA_UINT32);
typedef HBA_STATUS	(* HBASendRNIDFunc)
    (HBA_HANDLE, HBA_WWN, HBA_WWNTYPE, void *, HBA_UINT32 *);

/*
 * This structure is needed since a Rev2 vendor library must still implement the
 * Rev1 Register function in case it is called by a Rev1 wapper library.  Still
 * not STRICTLY neccesary, it provides clarity and keeps compilers happier
 */
typedef struct HBA_EntryPoints {
    HBAGetVersionFunc			GetVersionHandler;
    HBALoadLibraryFunc			LoadLibraryHandler;
    HBAFreeLibraryFunc			FreeLibraryHandler;
    HBAGetNumberOfAdaptersFunc		GetNumberOfAdaptersHandler;
    HBAGetAdapterNameFunc		GetAdapterNameHandler;
    HBAOpenAdapterFunc			OpenAdapterHandler;
    HBACloseAdapterFunc			CloseAdapterHandler;
    HBAGetAdapterAttributesFunc		GetAdapterAttributesHandler;
    HBAGetAdapterPortAttributesFunc	GetAdapterPortAttributesHandler;
    HBAGetPortStatisticsFunc		GetPortStatisticsHandler;
    HBAGetDiscoveredPortAttributesFunc	GetDiscoveredPortAttributesHandler;
    HBAGetPortAttributesByWWNFunc	GetPortAttributesByWWNHandler;
    HBASendCTPassThruFunc		SendCTPassThruHandler;
    HBARefreshInformationFunc		RefreshInformationHandler;
    HBAResetStatisticsFunc		ResetStatisticsHandler;
    HBAGetFcpTargetMappingFunc		GetFcpTargetMappingHandler;
    HBAGetFcpPersistentBindingFunc	GetFcpPersistentBindingHandler;
    HBAGetEventBufferFunc		GetEventBufferHandler;
    HBASetRNIDMgmtInfoFunc		SetRNIDMgmtInfoHandler;
    HBAGetRNIDMgmtInfoFunc		GetRNIDMgmtInfoHandler;
    HBASendRNIDFunc			SendRNIDHandler;
    HBASendScsiInquiryFunc		ScsiInquiryHandler;
    HBASendReportLUNsFunc		ReportLUNsHandler;
    HBASendReadCapacityFunc		ReadCapacityHandler;
} HBA_ENTRYPOINTS, *PHBA_ENTRYPOINTS;

typedef struct HBA_EntryPointsV2 {
    /* These first elements MUST MUST MUST match HBA_ENTRYPOINTS */
    HBAGetVersionFunc			GetVersionHandler;
    HBALoadLibraryFunc			LoadLibraryHandler;
    HBAFreeLibraryFunc			FreeLibraryHandler;
    HBAGetNumberOfAdaptersFunc		GetNumberOfAdaptersHandler;
    HBAGetAdapterNameFunc		GetAdapterNameHandler;
    HBAOpenAdapterFunc			OpenAdapterHandler;
    HBACloseAdapterFunc			CloseAdapterHandler;
    HBAGetAdapterAttributesFunc		GetAdapterAttributesHandler;
    HBAGetAdapterPortAttributesFunc	GetAdapterPortAttributesHandler;
    HBAGetPortStatisticsFunc		GetPortStatisticsHandler;
    HBAGetDiscoveredPortAttributesFunc	GetDiscoveredPortAttributesHandler;
    HBAGetPortAttributesByWWNFunc	GetPortAttributesByWWNHandler;
    /* Next function depricated but still supported */
    HBASendCTPassThruFunc		SendCTPassThruHandler;
    HBARefreshInformationFunc		RefreshInformationHandler;
    HBAResetStatisticsFunc		ResetStatisticsHandler;
    /* Next function depricated but still supported */
    HBAGetFcpTargetMappingFunc		GetFcpTargetMappingHandler;
    /* Next function depricated but still supported */
    HBAGetFcpPersistentBindingFunc	GetFcpPersistentBindingHandler;
    HBAGetEventBufferFunc		GetEventBufferHandler;
    HBASetRNIDMgmtInfoFunc		SetRNIDMgmtInfoHandler;
    HBAGetRNIDMgmtInfoFunc		GetRNIDMgmtInfoHandler;
    /* Next function depricated but still supported */
    HBASendRNIDFunc			SendRNIDHandler;
    /* Next function depricated but still supported */
    HBASendScsiInquiryFunc		ScsiInquiryHandler;
    /* Next function depricated but still supported */
    HBASendReportLUNsFunc		ReportLUNsHandler;
    /* Next function depricated but still supported */
    HBASendReadCapacityFunc		ReadCapacityHandler;

    /* Rev 2 Functions */
    HBAOpenAdapterByWWNFunc		OpenAdapterByWWNHandler;
    HBAGetFcpTargetMappingV2Func	GetFcpTargetMappingV2Handler;
    HBASendCTPassThruV2Func		SendCTPassThruV2Handler;
    HBARefreshAdapterConfigurationFunc	RefreshAdapterConfigurationHandler;
    HBAGetBindingCapabilityFunc		GetBindingCapabilityHandler;
    HBAGetBindingSupportFunc		GetBindingSupportHandler;
    HBASetBindingSupportFunc		SetBindingSupportHandler;
    HBASetPersistentBindingV2Func	SetPersistentBindingV2Handler;
    HBAGetPersistentBindingV2Func	GetPersistentBindingV2Handler;
    HBARemovePersistentBindingFunc	RemovePersistentBindingHandler;
    HBARemoveAllPersistentBindingsFunc	RemoveAllPersistentBindingsHandler;
    HBASendRNIDV2Func			SendRNIDV2Handler;
    HBAScsiInquiryV2Func		ScsiInquiryV2Handler;
    HBAScsiReportLUNsV2Func		ScsiReportLUNsV2Handler;
    HBAScsiReadCapacityV2Func		ScsiReadCapacityV2Handler;
    HBAGetVendorLibraryAttributesFunc	GetVendorLibraryAttributesHandler;
    HBARemoveCallbackFunc		RemoveCallbackHandler;
    HBARegisterForAdapterAddEventsFunc	RegisterForAdapterAddEventsHandler;
    HBARegisterForAdapterEventsFunc	RegisterForAdapterEventsHandler;
    HBARegisterForAdapterPortEventsFunc RegisterForAdapterPortEventsHandler;
    HBARegisterForAdapterPortStatEventsFunc
					RegisterForAdapterPortStatEventsHandler;
    HBARegisterForTargetEventsFunc	RegisterForTargetEventsHandler;
    HBARegisterForLinkEventsFunc	RegisterForLinkEventsHandler;
    HBASendRPLFunc			SendRPLHandler;
    HBASendRPSFunc			SendRPSHandler;
    HBASendSRLFunc			SendSRLHandler;
    HBASendLIRRFunc			SendLIRRHandler;
    HBAGetFC4StatisticsFunc		GetFC4StatisticsHandler;
    HBAGetFCPStatisticsFunc		GetFCPStatisticsHandler;
    HBASendRLSFunc			SendRLSHandler;
} HBA_ENTRYPOINTSV2, *PHBA_ENTRYPOINTSV2;

typedef HBA_STATUS	(* HBARegisterLibraryFunc)(HBA_ENTRYPOINTS *);
typedef HBA_STATUS	(* HBARegisterLibraryV2Func)(HBA_ENTRYPOINTSV2 *);

/* Function Prototypes */
HBA_API HBA_STATUS HBA_RegisterLibrary(
    HBA_ENTRYPOINTS	*functionTable
    );

HBA_API HBA_STATUS HBA_RegisterLibraryV2(
    HBA_ENTRYPOINTSV2	*functionTable
    );

#endif /* VENDOR_HBA_API_H */

#ifdef __cplusplus
}
#endif


