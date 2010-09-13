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

#ifndef __MNG_COMMAND_H__
#define __MNG_COMMAND_H__

#include "HECIUnix.h"
#include "StatusCodeDefinitions.h"

#pragma pack(1)

typedef struct _MNG_REQUEST
{
	UINT8   Cmd;
	UINT8   ByteCount;
	UINT8   SubCmd;
	UINT8   Version;
} MNG_REQUEST;

typedef struct _MNG_GET_ME_INFORMATION_RESPONSE
{
	UINT32         Version;
	MEFWCAPS_SKU   Sku;
	MEFWCAPS_MANAGEABILITY_SUPP  MngMode;
} MNG_GET_ME_INFORMATION_RESPONSE;

#pragma pack(0)

class MNGCommand
{
public:
	MNGCommand(bool verbose = false);
	~MNGCommand();

	HECI_STATUS GetMEInfo(MNG_GET_ME_INFORMATION_RESPONSE &infoMsg);

	HECILinux MNGClient;

private:
	HECI_STATUS _call(const unsigned char *command, UINT32 command_size, UINT8 **readBuffer, UINT32 *outBuffSize);

	bool _verbose;

};

const MNG_REQUEST MNG_GET_ME_INFO_HEADER = {0x07, 0x02, 0x01, 0x10};
const UINT32      MNG_GET_ME_INFO_Version = 0x00010000;


#endif //__MNG_COMMAND_H__

