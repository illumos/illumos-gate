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

#include "MNGCommand.h"

MNGCommand::MNGCommand(bool verbose) :
MNGClient(WD_GUID, verbose)
{
	_verbose = verbose;
}

MNGCommand::~MNGCommand(void)
{
}

HECI_STATUS MNGCommand::_call(const unsigned char *command, UINT32 command_size, UINT8 **readBuffer, UINT32 *outBuffSize)
{
	UINT32 inBuffSize;
	*outBuffSize = 0;

	inBuffSize = MNGClient.GetBufferSize();
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

	int bytesWritten = MNGClient.SendMessage(command, command_size);
	if ((UINT32)bytesWritten != command_size)
	{
		if (_verbose)
		{
			fprintf(stderr, "Error: Could not send data to MNG client through MEI\n");
		}
		return HECI_STATUS_MSG_TRANSMISSION_ERROR;
	}
	*outBuffSize = MNGClient.ReceiveMessage(*readBuffer, inBuffSize, 15000);
	if (0 == *outBuffSize)
	{
		if (_verbose)
		{
			fprintf(stderr, "Error: Could not read data from MNG client through MEI\n");
		}
		return HECI_STATUS_UNEXPECTED_RESPONSE;
	}
	if (_verbose)
	{
		fprintf(stdout, "Data received from MNG Client. %d bytes read\n", *outBuffSize);
	}
	return HECI_STATUS_OK;
}


/*
 * Get ME data information from MNG client
 */
HECI_STATUS
MNGCommand::GetMEInfo(MNG_GET_ME_INFORMATION_RESPONSE &infoMsg)
{
	UINT8 *readBuffer = NULL;
	UINT32 command_size = sizeof(MNG_GET_ME_INFO_HEADER);
	UINT32 replySize = 0;
	MNG_REQUEST msg = MNG_GET_ME_INFO_HEADER;
	HECI_STATUS status;

	status = _call((const unsigned char *)&msg, command_size,
			&readBuffer, &replySize);

	if (status != HECI_STATUS_OK)
	{
		goto mngend;
	}
	if (replySize != sizeof(MNG_GET_ME_INFORMATION_RESPONSE))
	{
		if (_verbose)
		{
			fprintf(stderr, "Error: Size of MEI response is not as expected\n");
		}
		status = HECI_STATUS_UNEXPECTED_RESPONSE;
		goto mngend;
	}
	if (((MNG_GET_ME_INFORMATION_RESPONSE *)readBuffer)->Version != MNG_GET_ME_INFO_Version)
	{
		if (_verbose)
		{
			fprintf(stderr, "Error: MEI response size is not as expected\n");
		}
		status = HECI_STATUS_UNEXPECTED_RESPONSE;
		goto mngend;
	}
	memcpy(&infoMsg, readBuffer, sizeof(MNG_GET_ME_INFORMATION_RESPONSE));

mngend:

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}

	return status;
}
