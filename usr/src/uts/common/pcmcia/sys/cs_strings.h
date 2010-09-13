/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1995-1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _CS_STRINGS_H
#define	_CS_STRINGS_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These values depend on the size of the cs_ss_event_text_t array
 *	and on the number of CS events that we want the client to
 *	be able to display.
 * XXX - this should be determined automatically
 */
#define	MAX_SS_EVENTS	9	/* maximum SS events */
#define	MAX_CS_EVENTS	28	/* maximum CS events */

/*
 * The cs_ss_event_text_t structure is used to support the Event2Text
 *	and cs_event2text function.  MAX_SS_EVENTS and MAX_CS_EVENTS
 *	are defined in the cs_priv.h header file.  If the size of this
 *	array or strctures changes, the MAX_CS_EVENT_BUFSIZE define
 *	which is in cs.h might need to be changed as well.
 */
cs_ss_event_text_t cs_ss_event_text[MAX_CS_EVENTS+1] = {
	{ PCE_CARD_REMOVAL, CS_EVENT_CARD_REMOVAL, "CARD_REMOVAL" },
	{ PCE_CARD_INSERT, CS_EVENT_CARD_INSERTION, "CARD_INSERTION" },
	{ PCE_CARD_READY, CS_EVENT_CARD_READY, "CARD_READY" },
	{ PCE_CARD_BATTERY_WARN, CS_EVENT_BATTERY_LOW, "BATTERY_WARN" },
	{ PCE_CARD_BATTERY_DEAD, CS_EVENT_BATTERY_DEAD, "BATTERY_DEAD" },
	{ PCE_CARD_STATUS_CHANGE, 0, "STATUS_CHANGE" },
	{ PCE_CARD_WRITE_PROTECT, CS_EVENT_WRITE_PROTECT, "WRITE_PROTECT" },
	{ PCE_PM_RESUME, CS_EVENT_PM_RESUME, "PM_RESUME" },
	{ PCE_PM_SUSPEND, CS_EVENT_PM_SUSPEND, "PM_SUSPEND" },
	{ 0, CS_EVENT_REGISTRATION_COMPLETE, "REGISTRATION_COMPLETE" },
	{ 0, CS_EVENT_CARD_LOCK, "CARD_LOCK" },
	{ 0, CS_EVENT_CARD_RESET, "CARD_RESET" },
	{ 0, CS_EVENT_CARD_UNLOCK, "CARD_UNLOCK" },
	{ 0, CS_EVENT_EJECTION_COMPLETE, "EJECTION_COMPLETE" },
	{ 0, CS_EVENT_EJECTION_REQUEST, "EJECTION_REQUEST" },
	{ 0, CS_EVENT_ERASE_COMPLETE, "ERASE_COMPLETE" },
	{ 0, CS_EVENT_EXCLUSIVE_COMPLETE, "EXCLUSIVE_COMPLETE" },
	{ 0, CS_EVENT_EXCLUSIVE_REQUEST, "EXCLUSIVE_REQUEST" },
	{ 0, CS_EVENT_INSERTION_COMPLETE, "INSERTION_COMPLETE" },
	{ 0, CS_EVENT_INSERTION_REQUEST, "INSERTION_REQUEST" },
	{ 0, CS_EVENT_RESET_COMPLETE, "RESET_COMPLETE" },
	{ 0, CS_EVENT_RESET_PHYSICAL, "RESET_PHYSICAL" },
	{ 0, CS_EVENT_RESET_REQUEST, "RESET_REQUEST" },
	{ 0, CS_EVENT_MTD_REQUEST, "MTD_REQUEST" },
	{ 0, CS_EVENT_CLIENT_INFO, "CLIENT_INFO" },
	{ 0, CS_EVENT_TIMER_EXPIRED, "TIMER_EXPIRED" },
	{ 0, CS_EVENT_SS_UPDATED, "SS_UPDATED" },
	{ 0, CS_EVENT_CARD_REMOVAL_LOWP, "CARD_REMOVAL_LOWP" },
	{ MAX_SS_EVENTS, 0, "{undefined}" },
};

cs_csfunc2text_strings_t cs_csfunc2text_funcstrings[] = {
	{ CISRegister, "CISRegister" },
	{ CISUnregister, "CISUnregister" },
	{ InitCISWindow, "InitCISWindow" },
	{ GetCardServicesInfo, "GetCardServicesInfo" },
	{ RegisterClient, "RegisterClient" },
	{ DeregisterClient, "DeregisterClient" },
	{ GetStatus, "GetStatus" },
	{ ResetFunction, "ResetFunction" },
	{ SetEventMask, "SetEventMask" },
	{ GetEventMask, "GetEventMask" },
	{ RequestIO, "RequestIO" },
	{ ReleaseIO, "ReleaseIO" },
	{ RequestIRQ, "RequestIRQ" },
	{ ReleaseIRQ, "ReleaseIRQ" },
	{ RequestWindow, "RequestWindow" },
	{ ReleaseWindow, "ReleaseWindow" },
	{ ModifyWindow, "ModifyWindow" },
	{ MapMemPage, "MapMemPage" },
	{ RequestSocketMask, "RequestSocketMask" },
	{ ReleaseSocketMask, "ReleaseSocketMask" },
	{ RequestConfiguration, "RequestConfiguration" },
	{ GetConfigurationInfo, "GetConfigurationInfo" },
	{ ModifyConfiguration, "ModifyConfiguration" },
	{ ReleaseConfiguration, "ReleaseConfiguration" },
	{ OpenMemory, "OpenMemory" },
	{ ReadMemory, "ReadMemory" },
	{ WriteMemory, "WriteMemory" },
	{ CopyMemory, "CopyMemory" },
	{ RegisterEraseQueue, "RegisterEraseQueue" },
	{ CheckEraseQueue, "CheckEraseQueue" },
	{ DeregisterEraseQueue, "DeregisterEraseQueue" },
	{ CloseMemory, "CloseMemory" },
	{ GetFirstRegion, "GetFirstRegion" },
	{ GetNextRegion, "GetNextRegion" },
	{ GetFirstPartition, "GetFirstPartition" },
	{ GetNextPartition, "GetNextPartition" },
	{ ReturnSSEntry, "ReturnSSEntry" },
	{ MapLogSocket, "MapLogSocket" },
	{ MapPhySocket, "MapPhySocket" },
	{ MapLogWindow, "MapLogWindow" },
	{ MapPhyWindow, "MapPhyWindow" },
	{ RegisterMTD, "RegisterMTD" },
	{ RegisterTimer, "RegisterTimer" },
	{ SetRegion, "SetRegion" },
	{ RequestExclusive, "RequestExclusive" },
	{ ReleaseExclusive, "ReleaseExclusive" },
	{ GetFirstClient, "GetFirstClient" },
	{ GetNextClient, "GetNextClient" },
	{ GetClientInfo, "GetClientInfo" },
	{ AddSocketServices, "AddSocketServices" },
	{ ReplaceSocketServices, "ReplaceSocketServices" },
	{ VendorSpecific, "VendorSpecific" },
	{ AdjustResourceInfo, "AdjustResourceInfo" },
	{ ValidateCIS, "ValidateCIS" },
	{ GetFirstTuple, "GetFirstTuple" },
	{ GetNextTuple, "GetNextTuple" },
	{ GetTupleData, "GetTupleData" },
	{ ParseTuple, "ParseTuple" },
	{ MakeDeviceNode, "MakeDeviceNode" },
	{ RemoveDeviceNode, "RemoveDeviceNode" },
	{ ConvertSpeed, "ConvertSpeed" },
	{ ConvertSize, "ConvertSize" },
	{ Event2Text, "Event2Text" },
	{ Error2Text, "Error2Text" },
	{ AccessConfigurationRegister, "AccessConfigurationRegister" },
	{ CS_DDI_Info, "CS_DDI_Info" },
	{ CS_Sys_Ctl, "CS_Sys_Ctl" },
	{ CSFuncListEnd, "{unknown Card Services function}" },
};

cs_csfunc2text_strings_t cs_csfunc2text_returnstrings[] = {
	{ CS_SUCCESS, "CS_SUCCESS" },
	{ CS_BAD_ADAPTER, "CS_BAD_ADAPTER" },
	{ CS_BAD_ATTRIBUTE, "CS_BAD_ATTRIBUTE" },
	{ CS_BAD_BASE, "CS_BAD_BASE" },
	{ CS_BAD_EDC, "CS_BAD_EDC" },
	{ CS_BAD_IRQ, "CS_BAD_IRQ" },
	{ CS_BAD_OFFSET, "CS_BAD_OFFSET" },
	{ CS_BAD_PAGE, "CS_BAD_PAGE" },
	{ CS_READ_FAILURE, "CS_READ_FAILURE" },
	{ CS_BAD_SIZE, "CS_BAD_SIZE" },
	{ CS_BAD_SOCKET, "CS_BAD_SOCKET" },
	{ CS_BAD_TYPE, "CS_BAD_TYPE" },
	{ CS_BAD_VCC, "CS_BAD_VCC" },
	{ CS_BAD_VPP, "CS_BAD_VPP" },
	{ CS_BAD_WINDOW, "CS_BAD_WINDOW" },
	{ CS_WRITE_FAILURE, "CS_WRITE_FAILURE" },
	{ CS_NO_CARD, "CS_NO_CARD" },
	{ CS_UNSUPPORTED_FUNCTION, "CS_UNSUPPORTED_FUNCTION" },
	{ CS_UNSUPPORTED_MODE, "CS_UNSUPPORTED_MODE" },
	{ CS_BAD_SPEED, "CS_BAD_SPEED" },
	{ CS_BUSY, "CS_BUSY" },
	{ CS_GENERAL_FAILURE, "CS_GENERAL_FAILURE" },
	{ CS_WRITE_PROTECTED, "CS_WRITE_PROTECTED" },
	{ CS_BAD_ARG_LENGTH, "CS_BAD_ARG_LENGTH" },
	{ CS_BAD_ARGS, "CS_BAD_ARGS" },
	{ CS_CONFIGURATION_LOCKED, "CS_CONFIGURATION_LOCKED" },
	{ CS_IN_USE, "CS_IN_USE" },
	{ CS_NO_MORE_ITEMS, "CS_NO_MORE_ITEMS" },
	{ CS_OUT_OF_RESOURCE, "CS_OUT_OF_RESOURCE" },
	{ CS_BAD_HANDLE, "CS_BAD_HANDLE" },
	{ CS_NO_CIS, "CS_NO_CIS" },
	{ CS_BAD_CIS, "CS_BAD_CIS" },
	{ CS_UNKNOWN_TUPLE, "CS_UNKNOWN_TUPLE" },
	{ CS_BAD_VERSION, "CS_BAD_VERSION" },
	{ CS_UNSUPPORTED_EVENT, "CS_UNSUPPORTED_EVENT" },
	{ CS_CSI_ERROR, "CS_CSI_ERROR" },
	{ CS_CSI_NOT_INIT, "CS_CSI_NOT_INIT" },
	{ CS_NO_TUPLE_PARSER, "CS_NO_TUPLE_PARSER" },
	{ CS_ERRORLIST_END, "{unknown Card Services return code}" },
};

#ifdef	__cplusplus
}
#endif

#endif /* _CS_STRINGS_H */
