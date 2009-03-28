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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <cstdio>
#include <cstdlib>

#ifdef __sun
#include <stdio.h>
#include <stdlib.h>
#endif	// __sun

#include "FWULCommand.h"

FWULCommand::FWULCommand(bool verbose) :
FWULClient(FW_UPDATE_GUID, verbose)
{
	_verbose = verbose;
}

FWULCommand::~FWULCommand(void)
{
}

HECI_STATUS FWULCommand::_call(const unsigned char *command, UINT32 command_size, UINT8 **readBuffer, UINT32 *outBuffSize)
{
	UINT32 inBuffSize;
	*outBuffSize = 0;

	inBuffSize = FWULClient.GetBufferSize();
	if (NULL == *readBuffer)
	{
		*readBuffer = (UINT8 *)malloc(sizeof(UINT8) * inBuffSize);
		if (NULL == *readBuffer)
		{
			if (_verbose)
			{
				fprintf(stderr, "Error: Malloc failed\n");
			}
			return HECI_STATUS_MEMORY_ALLOCATION_ERROR;
		}
	}
	memset(*readBuffer, 0, inBuffSize);

	int bytesWritten = FWULClient.SendMessage(command, command_size);
	if ((UINT32)bytesWritten != command_size)
	{
		if (_verbose)
		{
			fprintf(stderr, "Error: Could not send data to FWUpdate client through MEI\n");
		}
		return HECI_STATUS_MSG_TRANSMISSION_ERROR;
	}
	*outBuffSize = FWULClient.ReceiveMessage(*readBuffer, inBuffSize, 15000);
	if (0 == *outBuffSize)
	{
		if (_verbose)
		{
			fprintf(stderr, "Error: Could not read data from FWUpdate client through MEI\n");
		}
		return HECI_STATUS_UNEXPECTED_RESPONSE;
	}
	if (_verbose)
	{
		fprintf(stdout, "Data received from FWUpdate Client. %d bytes read\n", *outBuffSize);
	}
	return HECI_STATUS_OK;
}


/*
 * Get ME data information from FW update client using AMTCommunication class
 */
HECI_STATUS
FWULCommand::GetFWUVersionAndInfo(FWU_GET_VERSION_MSG_REPLY &verMsg, FWU_GET_INFO_MSG_REPLY &infoMsg)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(ME_GET_FW_UPDATE_INFO_REQUEST);
	UINT32 replySize = 0;
	ME_GET_FW_UPDATE_INFO_REQUEST msg;
	HECI_STATUS status;

	msg.MessageID = FWU_GET_VERSION;
	status = _call((const unsigned char *)&msg, command_size,
			&readBuffer, &replySize);
	if (status != HECI_STATUS_OK)
	{
		goto fwuvend;
	}
	if (replySize == sizeof(FWU_GET_VERSION_MSG_REPLY))
	{
		if (((FWU_MSG_REPLY_HEADER *)readBuffer)->MessageType != FWU_GET_VERSION_REPLY)
		{
			if (_verbose)
			{
				fprintf(stderr, "Error: MessageType in MEI response is not as expected\n");
			}
			status = HECI_STATUS_UNEXPECTED_RESPONSE;
			goto fwuvend;
		}
		if (((FWU_MSG_REPLY_HEADER *)readBuffer)->Status != PT_STATUS_SUCCESS)
		{
			if (_verbose)
			{
				fprintf(stderr, "Error: Status in MEI response is not as expected\n");
			}
			status = HECI_STATUS_UNEXPECTED_RESPONSE;
			goto fwuvend;
		}

		memcpy(&verMsg, readBuffer, sizeof(FWU_GET_VERSION_MSG_REPLY));

		msg.MessageID = FWU_GET_INFO;
		status = _call((const unsigned char *)&msg, command_size,
				&readBuffer, &replySize);
		if (status != HECI_STATUS_OK)
		{
			goto fwuvend;
		}
		if (replySize != sizeof(FWU_GET_INFO_MSG_REPLY))
		{
			if (_verbose)
			{
				fprintf(stderr, "Error: MEI response size is not as expected\n");
			}
			status = HECI_STATUS_UNEXPECTED_RESPONSE;
			goto fwuvend;
		}
		if (((FWU_MSG_REPLY_HEADER *)readBuffer)->MessageType != FWU_GET_INFO_REPLY)
		{
			if (_verbose)
			{
				fprintf(stderr, "Error: MessageType in MEI response is not as expected\n");
			}
			status = HECI_STATUS_UNEXPECTED_RESPONSE;
			goto fwuvend;
		}
		if (((FWU_MSG_REPLY_HEADER *)readBuffer)->Status != PT_STATUS_SUCCESS)
		{
			if (_verbose)
			{
				fprintf(stderr, "Error: Status in MEI response is not as expected\n");
			}
			status = HECI_STATUS_UNEXPECTED_RESPONSE;
			goto fwuvend;
		}

		memcpy(&infoMsg, readBuffer, sizeof(FWU_GET_INFO_MSG_REPLY));

	}
	else if (replySize == sizeof(FWU_GET_VERSION_MSG_REPLY_V3))
	{
		if (((FWU_MSG_REPLY_HEADER_V3 *)readBuffer)->MessageType != FWU_GET_VERSION_REPLY)
		{
			if (_verbose)
			{
				fprintf(stderr, "Error: MessageType in MEI response is not as expected\n");
			}
			status = HECI_STATUS_UNEXPECTED_RESPONSE;
			goto fwuvend;
		}
		if (((FWU_MSG_REPLY_HEADER_V3 *)readBuffer)->Status != PT_STATUS_SUCCESS)
		{
			if (_verbose)
			{
				fprintf(stderr, "Error: Status in MEI response is not as expected\n");
			}
			status = HECI_STATUS_UNEXPECTED_RESPONSE;
			goto fwuvend;
		}

		FWU_GET_VERSION_MSG_REPLY_V3 *rep = (FWU_GET_VERSION_MSG_REPLY_V3 *)readBuffer;
		verMsg.MessageType = FWU_GET_VERSION_REPLY;
		verMsg.Status = rep->Status;
		verMsg.Sku    = rep->Sku;
		verMsg.ICHVer = rep->ICHVer;
		verMsg.MCHVer = rep->MCHVer;
		verMsg.Vendor = rep->Vendor;
		verMsg.LastFwUpdateStatus = rep->LastFwUpdateStatus;
		verMsg.HwSku  = rep->Sku;
		memcpy(&verMsg.CodeVersion, &(rep->CodeVersion), sizeof(verMsg.CodeVersion));
		memset(&verMsg.AMTVersion, 0, sizeof(verMsg.AMTVersion));
		verMsg.EnabledUpdateInterfaces = rep->EnabledUpdateInterfaces;
		verMsg.Reserved = 0;

		memset(&infoMsg, 0, sizeof(infoMsg));
	} else {
		if (_verbose)
		{
			fprintf(stderr, "Error: MEI response size is not as expected\n");
		}
		status = HECI_STATUS_UNEXPECTED_RESPONSE;
		goto fwuvend;
	}

fwuvend:

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}

	return status;
}
