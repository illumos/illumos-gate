/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2004, Apple Computer, Inc. All rights reserved.
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

$Log: dnssd_clientlib.c,v $
Revision 1.11  2006/08/14 23:05:53  cheshire
Added "tab-width" emacs header line

Revision 1.10  2005/04/06 02:06:56  shersche
Add DNSSD_API macro to TXTRecord API calls

Revision 1.9  2004/10/06 02:22:19  cheshire
Changed MacRoman copyright symbol (should have been UTF-8 in any case :-) to ASCII-compatible "(c)"

Revision 1.8  2004/10/01 22:15:55  rpantos
rdar://problem/3824265: Replace APSL in client lib with BSD license.

Revision 1.7  2004/06/26 03:16:34  shersche
clean up warning messages on Win32 platform

Submitted by: herscher

Revision 1.6  2004/06/12 01:09:45  cheshire
To be callable from the broadest range of clients on Windows (e.g. Visual Basic, C#, etc.)
API routines have to be declared as "__stdcall", instead of the C default, "__cdecl"

Revision 1.5  2004/05/25 18:29:33  cheshire
Move DNSServiceConstructFullName() from dnssd_clientstub.c to dnssd_clientlib.c,
so that it's also accessible to dnssd_clientshim.c (single address space) clients.

Revision 1.4  2004/05/25 17:08:55  cheshire
Fix compiler warning (doesn't make sense for function return type to be const)

Revision 1.3  2004/05/21 21:41:35  cheshire
Add TXT record building and parsing APIs

Revision 1.2  2004/05/20 22:22:21  cheshire
Enable code that was bracketed by "#if 0"

Revision 1.1  2004/03/12 21:30:29  cheshire
Build a System-Context Shared Library from mDNSCore, for the benefit of developers
like Muse Research who want to be able to use mDNS/DNS-SD from GPL-licensed code.

 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <string.h>

#include "dns_sd.h"

#if MDNS_BUILDINGSHAREDLIBRARY || MDNS_BUILDINGSTUBLIBRARY
#pragma export on
#endif

#if defined(_WIN32)
// disable warning "conversion from <data> to uint16_t"
#pragma warning(disable:4244)
#endif

/*********************************************************************************************
 *
 *  Supporting Functions
 *
 *********************************************************************************************/

#define mdnsIsDigit(X)     ((X) >= '0' && (X) <= '9')

static int DomainEndsInDot(const char *dom)
	{
	while (dom[0] && dom[1])
		{
		if (dom[0] == '\\') // advance past escaped byte sequence
			{
			if (mdnsIsDigit(dom[1]) && mdnsIsDigit(dom[2]) && mdnsIsDigit(dom[3]))
				dom += 4;			// If "\ddd"    then skip four
			else dom += 2;			// else if "\x" then skip two
			}
		else dom++;					// else goto next character
		}
	return (dom[0] == '.');
	}

static uint8_t *InternalTXTRecordSearch
	(
	uint16_t         txtLen,
	const void       *txtRecord,
	const char       *key,
	unsigned long    *keylen
	)
	{
	uint8_t *p = (uint8_t*)txtRecord;
	uint8_t *e = p + txtLen;
	*keylen = (unsigned long) strlen(key);
	while (p<e)
		{
		uint8_t *x = p;
		p += 1 + p[0];
		if (p <= e && *keylen <= x[0] && !strncmp(key, (char*)x+1, *keylen))
			if (*keylen == x[0] || x[1+*keylen] == '=') return(x);
		}
	return(NULL);
	}

/*********************************************************************************************
 *
 *  General Utility Functions
 *
 *********************************************************************************************/

int DNSSD_API DNSServiceConstructFullName
	(
	char                      *fullName,
	const char                *service,      /* may be NULL */
	const char                *regtype,
	const char                *domain
	)
	{
	unsigned long len;
	unsigned char c;
	char *fn = fullName;
	const char *s = service;
	const char *r = regtype;
	const char *d = domain;

	if (service)
		{
		while(*s)
			{
			c = (unsigned char)*s++;
			if (c == '.' || (c == '\\')) *fn++ = '\\'; // escape dot and backslash literals
			else if (c <= ' ') // escape non-printable characters
				{
				*fn++ = '\\';
				*fn++ = (char) ('0' + (c / 100));
				*fn++ = (char) ('0' + (c / 10) % 10);
				c = (unsigned char)('0' + (c % 10));
				}
			*fn++ = (char)c;
			}
		*fn++ = '.';
		}

	if (!regtype) return -1;
	len = (unsigned long) strlen(regtype);
	if (DomainEndsInDot(regtype)) len--;
	if (len < 6) return -1; // regtype must be at least "x._udp" or "x._tcp"
	if (strncmp((regtype + len - 4), "_tcp", 4) && strncmp((regtype + len - 4), "_udp", 4)) return -1;
	while(*r) *fn++ = *r++;
	if (!DomainEndsInDot(regtype)) *fn++ = '.';

	if (!domain || !domain[0]) return -1;
	while(*d) *fn++ = *d++;
	if (!DomainEndsInDot(domain)) *fn++ = '.';
	*fn = '\0';
	return 0;
	}

/*********************************************************************************************
 *
 *   TXT Record Construction Functions
 *
 *********************************************************************************************/

typedef struct _TXTRecordRefRealType
	{
	uint8_t  *buffer;		// Pointer to data
	uint16_t buflen;		// Length of buffer
	uint16_t datalen;		// Length currently in use
	uint16_t malloced;	// Non-zero if buffer was allocated via malloc()
	} TXTRecordRefRealType;

#define txtRec ((TXTRecordRefRealType*)txtRecord)

// The opaque storage defined in the public dns_sd.h header is 16 bytes;
// make sure we don't exceed that.
struct dnssd_clientlib_CompileTimeAssertionCheck
	{
	char assert0[(sizeof(TXTRecordRefRealType) <= 16) ? 1 : -1];
	};

void DNSSD_API TXTRecordCreate
	(
	TXTRecordRef     *txtRecord,
	uint16_t         bufferLen,
	void             *buffer
	)
	{
	txtRec->buffer   = buffer;
	txtRec->buflen   = buffer ? bufferLen : (uint16_t)0;
	txtRec->datalen  = 0;
	txtRec->malloced = 0;
	}

void DNSSD_API TXTRecordDeallocate(TXTRecordRef *txtRecord)
	{
	if (txtRec->malloced) free(txtRec->buffer);
	}

DNSServiceErrorType DNSSD_API TXTRecordSetValue
	(
	TXTRecordRef     *txtRecord,
	const char       *key,
	uint8_t          valueSize,
	const void       *value
	)
	{
	uint8_t *start, *p;
	const char *k;
	unsigned long keysize, keyvalsize;

	for (k = key; *k; k++) if (*k < 0x20 || *k > 0x7E || *k == '=') return(kDNSServiceErr_Invalid);
	keysize = (unsigned long)(k - key);
	keyvalsize = 1 + keysize + (value ? (1 + valueSize) : 0);
	if (keysize < 1 || keyvalsize > 255) return(kDNSServiceErr_Invalid);
	(void)TXTRecordRemoveValue(txtRecord, key);
	if (txtRec->datalen + keyvalsize > txtRec->buflen)
		{
		unsigned char *newbuf;
		unsigned long newlen = txtRec->datalen + keyvalsize;
		if (newlen > 0xFFFF) return(kDNSServiceErr_Invalid);
		newbuf = malloc((size_t)newlen);
		if (!newbuf) return(kDNSServiceErr_NoMemory);
		memcpy(newbuf, txtRec->buffer, txtRec->datalen);
		if (txtRec->malloced) free(txtRec->buffer);
		txtRec->buffer = newbuf;
		txtRec->buflen = (uint16_t)(newlen);
		txtRec->malloced = 1;
		}
	start = txtRec->buffer + txtRec->datalen;
	p = start + 1;
	memcpy(p, key, keysize);
	p += keysize;
	if (value)
		{
		*p++ = '=';
		memcpy(p, value, valueSize);
		p += valueSize;
		}
	*start = (uint8_t)(p - start - 1);
	txtRec->datalen += p - start;
	return(kDNSServiceErr_NoError);
	}

DNSServiceErrorType DNSSD_API TXTRecordRemoveValue
	(
	TXTRecordRef     *txtRecord,
	const char       *key
	)
	{
	unsigned long keylen, itemlen, remainder;
	uint8_t *item = InternalTXTRecordSearch(txtRec->datalen, txtRec->buffer, key, &keylen);
	if (!item) return(kDNSServiceErr_NoSuchKey);
	itemlen   = (unsigned long)(1 + item[0]);
	remainder = (unsigned long)((txtRec->buffer + txtRec->datalen) - (item + itemlen));
	// Use memmove because memcpy behaviour is undefined for overlapping regions
	memmove(item, item + itemlen, remainder);
	txtRec->datalen -= itemlen;
	return(kDNSServiceErr_NoError);
	}

uint16_t DNSSD_API TXTRecordGetLength  (const TXTRecordRef *txtRecord) { return(txtRec->datalen); }
const void * DNSSD_API TXTRecordGetBytesPtr(const TXTRecordRef *txtRecord) { return(txtRec->buffer); }

/*********************************************************************************************
 *
 *   TXT Record Parsing Functions
 *
 *********************************************************************************************/

int DNSSD_API TXTRecordContainsKey
	(
	uint16_t         txtLen,
	const void       *txtRecord,
	const char       *key
	)
	{
	unsigned long keylen;
	return (InternalTXTRecordSearch(txtLen, txtRecord, key, &keylen) ? 1 : 0);
	}

const void * DNSSD_API TXTRecordGetValuePtr
	(
	uint16_t         txtLen,
	const void       *txtRecord,
	const char       *key,
	uint8_t          *valueLen
	)
	{
	unsigned long keylen;
	uint8_t *item = InternalTXTRecordSearch(txtLen, txtRecord, key, &keylen);
	if (!item || item[0] <= keylen) return(NULL);	// If key not found, or found with no value, return NULL
	*valueLen = (uint8_t)(item[0] - (keylen + 1));
	return (item + 1 + keylen + 1);
	}

uint16_t DNSSD_API TXTRecordGetCount
	(
	uint16_t         txtLen,
	const void       *txtRecord
	)
	{
	uint16_t count = 0;
	uint8_t *p = (uint8_t*)txtRecord;
	uint8_t *e = p + txtLen;
	while (p<e) { p += 1 + p[0]; count++; }
	return((p>e) ? (uint16_t)0 : count);
	}

DNSServiceErrorType DNSSD_API TXTRecordGetItemAtIndex
	(
	uint16_t         txtLen,
	const void       *txtRecord,
	uint16_t         index,
	uint16_t         keyBufLen,
	char             *key,
	uint8_t          *valueLen,
	const void       **value
	)
	{
	uint16_t count = 0;
	uint8_t *p = (uint8_t*)txtRecord;
	uint8_t *e = p + txtLen;
	while (p<e && count<index) { p += 1 + p[0]; count++; }	// Find requested item
	if (p<e && p + 1 + p[0] <= e)	// If valid
		{
		uint8_t *x = p+1;
		unsigned long len = 0;
		e = p + 1 + p[0];
		while (x+len<e && x[len] != '=') len++;
		if (len >= keyBufLen) return(kDNSServiceErr_NoMemory);
		memcpy(key, x, len);
		key[len] = 0;
		if (x+len<e)		// If we found '='
			{
			*value = x + len + 1;
			*valueLen = (uint8_t)(p[0] - (len + 1));
			}
		else
			{
			*value = NULL;
			*valueLen = 0;
			}
		return(kDNSServiceErr_NoError);
		}
	return(kDNSServiceErr_Invalid);
	}
