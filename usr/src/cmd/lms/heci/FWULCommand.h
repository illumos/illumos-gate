/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corp. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifndef __FWUL_COMMAND_H__
#define __FWUL_COMMAND_H__

#include "HECIUnix.h"
#include "StatusCodeDefinitions.h"

#pragma pack(1)

typedef struct _FWU_VERSION
{
	UINT16      Major;
	UINT16      Minor;
	UINT16      Hotfix;
	UINT16      Build;
} FWU_VERSION;

typedef enum
{
	FWU_GET_VERSION = 0,
	FWU_GET_VERSION_REPLY,
	FWU_START,
	FWU_START_REPLY,
	FWU_DATA,
	FWU_DATA_REPLY,
	FWU_END,
	FWU_END_REPLY,
	FWU_GET_INFO,
	FWU_GET_INFO_REPLY
} FWU_HECI_MESSAGE_TYPE;

typedef struct _ME_GET_FW_UPDATE_INFO_REQUEST
{
	UINT32      MessageID;
} ME_GET_FW_UPDATE_INFO_REQUEST;

typedef struct _FWU_MSG_REPLY_HEADER
{
	UINT32      MessageType;
	UINT32      Status;
} FWU_MSG_REPLY_HEADER;

typedef struct _FWU_MSG_REPLY_HEADER_V3
{
	UINT8       MessageType;
	UINT32      Status;
} FWU_MSG_REPLY_HEADER_V3;

typedef struct _FWU_GET_VERSION_MSG_REPLY
{
	UINT32      MessageType;
	UINT32      Status;
	UINT32      Sku;
	UINT32      ICHVer;
	UINT32      MCHVer;
	UINT32      Vendor;
	UINT32      LastFwUpdateStatus;
	UINT32      HwSku;
	FWU_VERSION CodeVersion;
	FWU_VERSION AMTVersion;
	UINT16      EnabledUpdateInterfaces;
	UINT16      Reserved;
} FWU_GET_VERSION_MSG_REPLY;

typedef struct _FWU_GET_VERSION_MSG_REPLY_V3
{
	UINT8       MessageType;
	UINT32      Status;
	UINT32      Sku;
	UINT32      ICHVer;
	UINT32      MCHVer;
	UINT32      Vendor;
	FWU_VERSION CodeVersion;
	FWU_VERSION RcvyVersion;
	UINT16      EnabledUpdateInterfaces;
	UINT32      LastFwUpdateStatus;
	UINT32      Reserved;
} FWU_GET_VERSION_MSG_REPLY_V3;

typedef struct _FWU_GET_INFO_MSG_REPLY
{
	UINT32      MessageType;
	UINT32      Status;
	FWU_VERSION MEBxVersion;
	UINT32      FlashOverridePolicy;
	UINT32      ManageabilityMode;
	UINT32      BiosBootState;
	struct {
		UINT32          CryptoFuse   :1;
		UINT32          FlashProtection:1;
		UINT32          FwOverrideQualifier:2;
		UINT32          MeResetReason:2;
		UINT32          FwOverrideCounter:8;
		UINT32          reserved:18;
	} Fields;
	UINT8       BiosVersion[20];
} FWU_GET_INFO_MSG_REPLY;

#pragma pack(0)

class FWULCommand
{
public:
	FWULCommand(bool verbose = false);
	~FWULCommand();

	HECI_STATUS GetFWUVersionAndInfo(FWU_GET_VERSION_MSG_REPLY &verMsg, FWU_GET_INFO_MSG_REPLY &infoMsg);

	HECILinux FWULClient;

private:
	HECI_STATUS _call(const unsigned char *command, UINT32 command_size, UINT8 **readBuffer, UINT32 *outBuffSize);

	bool _verbose;
};

#endif //__FWUL_COMMAND_H__

