/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2003-2004, Apple Computer, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer. 
 * 2.  Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution. 
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of its 
 *     contributors may be used to endorse or promote products derived from this 
 *     software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY 
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	Change History (most recent first):

$Log: dnssd_ipc.c,v $
Revision 1.16  2006/08/14 23:05:53  cheshire
Added "tab-width" emacs header line

Revision 1.15  2005/01/27 22:57:56  cheshire
Fix compile errors on gcc4

Revision 1.14  2004/10/06 02:22:20  cheshire
Changed MacRoman copyright symbol (should have been UTF-8 in any case :-) to ASCII-compatible "(c)"

Revision 1.13  2004/10/01 22:15:55  rpantos
rdar://problem/3824265: Replace APSL in client lib with BSD license.

Revision 1.12  2004/09/16 23:14:24  cheshire
Changes for Windows compatibility

Revision 1.11  2004/06/18 04:56:09  rpantos
casting goodness

Revision 1.10  2004/06/12 01:08:14  cheshire
Changes for Windows compatibility

Revision 1.9  2004/05/18 23:51:27  cheshire
Tidy up all checkin comments to use consistent "<rdar://problem/xxxxxxx>" format for bug numbers

Revision 1.8  2003/11/05 22:44:57  ksekar
<rdar://problem/3335230>: No bounds checking when reading data from client
Reviewed by: Stuart Cheshire

Revision 1.7  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dnssd_ipc.h"

void put_long(const uint32_t l, char **ptr)
	{
	(*ptr)[0] = (char)((l >> 24) &  0xFF);
	(*ptr)[1] = (char)((l >> 16) &  0xFF);
	(*ptr)[2] = (char)((l >>  8) &  0xFF);
	(*ptr)[3] = (char)((l      ) &  0xFF);
	*ptr += sizeof(uint32_t);
	}

uint32_t get_long(char **ptr)
	{
	uint8_t *p = (uint8_t*) *ptr;
	*ptr += sizeof(uint32_t);
	return((uint32_t) ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]));
	}

void put_short(uint16_t s, char **ptr)
	{
	(*ptr)[0] = (char)((s >>  8) &  0xFF);
	(*ptr)[1] = (char)((s      ) &  0xFF);
	*ptr += sizeof(uint16_t);
	}

uint16_t get_short(char **ptr)
	{
	uint8_t *p = (uint8_t*) *ptr;
	*ptr += sizeof(uint16_t);
	return((uint16_t) ((uint16_t)p[0] << 8 | p[1]));
	}

int put_string(const char *str, char **ptr)
	{
	if (!str) str = "";
	strcpy(*ptr, str);
	*ptr += strlen(str) + 1;
	return 0;
	}

int get_string(char **ptr, char *buffer, int buflen)
	{
	int overrun = (int)strlen(*ptr) <  buflen ? 0 : -1;
	strncpy(buffer, *ptr,  buflen - 1);
	buffer[buflen - 1] = '\0';
	*ptr += strlen(buffer) + 1;
	return overrun;
	}

void put_rdata(const int rdlen, const unsigned char *rdata, char **ptr)
	{
	memcpy(*ptr, rdata, rdlen);
	*ptr += rdlen;
	}

char *get_rdata(char **ptr, int rdlen)
	{
	char *rd = *ptr;
	*ptr += rdlen;
	return rd;
	}

void ConvertHeaderBytes(ipc_msg_hdr *hdr)
	{
	hdr->version   = htonl(hdr->version);
	hdr->datalen   = htonl(hdr->datalen);
	hdr->flags     = htonl(hdr->flags);
	hdr->op        = htonl(hdr->op );
	hdr->reg_index = htonl(hdr->reg_index);
	}
