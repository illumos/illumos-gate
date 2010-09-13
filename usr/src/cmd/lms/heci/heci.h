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

#ifndef __HECI_H__
#define __HECI_H__

#include <cstring>

#ifdef __sun
#include <string.h>
#endif	// __sun

#ifndef GUID_DEFINED
#define GUID_DEFINED

typedef struct guid {
	unsigned int   data1;
	unsigned short data2;
	unsigned short data3;
	unsigned char  data4[8];
} GUID;

#endif

#include "HECI_if.h"

class HECI
{
public:
	HECI(const GUID guid, bool verbose = true) :
	    _initialized(false),
	    _verbose(verbose),
	    _bufSize(0),
	    _protocolVersion(0)
	{
		memcpy(&_guid, &guid, sizeof(_guid));
	}
	virtual ~HECI() {}

	virtual bool Init(unsigned char maxProtocolVersion = 0) = 0;
	virtual void Deinit() = 0;
	virtual int ReceiveMessage(unsigned char *buffer, int len, unsigned long timeout = 2000) = 0;
	virtual int SendMessage(const unsigned char *buffer, int len, unsigned long timeout = 2000) = 0;
	virtual unsigned int GetBufferSize() const = 0;
	virtual unsigned char GetProtocolVersion() const = 0;
	virtual bool GetHeciVersion(HECI_VERSION &version) const = 0;
	virtual bool IsInitialized() const = 0;

protected:
	GUID _guid;
	bool _initialized;
	bool _verbose;
	unsigned int  _bufSize;
	unsigned char _protocolVersion;
};

#endif
