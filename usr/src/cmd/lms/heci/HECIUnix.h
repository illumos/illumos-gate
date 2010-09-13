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

#ifndef __HECI_UNIX_H__
#define __HECI_UNIX_H__

#include "heci.h"

class HECILinux : public HECI
{
public:
	HECILinux(const GUID guid, bool verbose = false);
	virtual ~HECILinux();

	virtual bool Init(unsigned char reqProtocolVersion = 0);
	virtual void Deinit();
	virtual int ReceiveMessage(unsigned char *buffer, int len, unsigned long timeout = 2000);
	virtual int SendMessage(const unsigned char *buffer, int len, unsigned long timeout = 2000);
	virtual unsigned int GetBufferSize() const { return _bufSize; }
	virtual unsigned char GetProtocolVersion() const { return _protocolVersion; }
	virtual bool GetHeciVersion(HECI_VERSION &version) const;
	virtual bool IsInitialized() const { return _initialized; }

private:
	int _fd;
	bool m_haveHeciVersion;
	HECI_VERSION m_heciVersion;
};

#endif	// __HECI_UNIX_H__
