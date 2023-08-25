/*
 * Copyright (c) 2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 *
 * @APPLE_LICENSE_HEADER_END@
 */
/* CSTYLED */
/*
 *      @(#)charsets.c      *
 *      (c) 2004   Apple Computer, Inc.  All Rights Reserved
 *
 *
 *      charsets.c -- Routines converting between UTF-8, 16-bit
 *			little-endian Unicode, and various Windows
 *			code pages.
 *
 *      MODIFICATION HISTORY:
 *       28-Nov-2004     Guy Harris	New today
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <iconv.h>
#include <langinfo.h>
#include <strings.h>
#include <libintl.h>

#include <sys/isa_defs.h>
#include <netsmb/smb_lib.h>
#include <netsmb/mchain.h>

#include "charsets.h"

/*
 * On Solaris, we will need to do some rewriting to use our iconv
 * routines for the conversions.  For now, we're effectively
 * stubbing out code, leaving the details of what happens on
 * Darwin in case it's useful as a guide later.
 */

static unsigned
xtoi(char u)
{
	if (isdigit(u))
		return (u - '0');
	else if (islower(u))
		return (10 + u - 'a');
	else if (isupper(u))
		return (10 + u - 'A');
	return (16);
}


/*
 * Removes the "%" escape sequences from a URL component.
 * See IETF RFC 2396.
 */
char *
unpercent(char *component)
{
	char c, *s;
	unsigned hi, lo;

	if (component == NULL)
		return (component);

	for (s = component; (c = *s) != 0; s++) {
		if (c != '%')
			continue;
		if ((hi = xtoi(s[1])) > 15 || (lo = xtoi(s[2])) > 15)
			continue; /* ignore invalid escapes */
		s[0] = hi*16 + lo;
		/*
		 * This was strcpy(s + 1, s + 3);
		 * But nowadays leftward overlapping copies are
		 * officially undefined in C.  Ours seems to
		 * work or not depending upon alignment.
		 */
		memmove(s+1, s+3, strlen(s+3) + 1);
	}
	return (component);
}

/* BEGIN CSTYLED */
#ifdef NOTPORTED
static CFStringEncoding
get_windows_encoding_equivalent( void )
{

	CFStringEncoding encoding;
	uint32_t index,region;

	/* important! use root ID so you can read the config file! */
	seteuid(eff_uid);
	__CFStringGetInstallationEncodingAndRegion(&index,&region);
	seteuid(real_uid);

	switch ( index )
	{
		case	kCFStringEncodingMacRoman:
			if (region) /* anything nonzero is not US */
				encoding = kCFStringEncodingDOSLatin1;
			else /* US region */
				encoding = kCFStringEncodingDOSLatinUS;
			break;

		case	kCFStringEncodingMacJapanese:
			encoding = kCFStringEncodingDOSJapanese;
			break;

		case	kCFStringEncodingMacChineseTrad:
			encoding = kCFStringEncodingDOSChineseTrad;
			break;

		case	kCFStringEncodingMacKorean:
			encoding = kCFStringEncodingDOSKorean;
			break;

		case	kCFStringEncodingMacArabic:
			encoding = kCFStringEncodingDOSArabic;
			break;

		case	kCFStringEncodingMacHebrew:
			encoding = kCFStringEncodingDOSHebrew;
			break;

		case	kCFStringEncodingMacGreek:
			encoding = kCFStringEncodingDOSGreek;
			break;

		case	kCFStringEncodingMacCyrillic:
			encoding = kCFStringEncodingDOSCyrillic;
			break;

		case	kCFStringEncodingMacThai:
			encoding = kCFStringEncodingDOSThai;
			break;

		case	kCFStringEncodingMacChineseSimp:
			encoding = kCFStringEncodingDOSChineseSimplif;
			break;

		case	kCFStringEncodingMacCentralEurRoman:
			encoding = kCFStringEncodingDOSLatin2;
			break;

		case	kCFStringEncodingMacTurkish:
			encoding = kCFStringEncodingDOSTurkish;
			break;

		case	kCFStringEncodingMacCroatian:
			encoding = kCFStringEncodingDOSLatin2;
			break;

		case	kCFStringEncodingMacIcelandic:
			encoding = kCFStringEncodingDOSIcelandic;
			break;

		case	kCFStringEncodingMacRomanian:
			encoding = kCFStringEncodingDOSLatin2;
			break;

		case	kCFStringEncodingMacFarsi:
			encoding = kCFStringEncodingDOSArabic;
			break;

		case	kCFStringEncodingMacUkrainian:
			encoding = kCFStringEncodingDOSCyrillic;
			break;

		default:
			encoding = kCFStringEncodingDOSLatin1;
			break;
	}

	return encoding;
}
#endif /* NOTPORTED */

/*
 * XXX - NLS, or CF?  We should probably use the same routine for all
 * conversions.
 */
char *
convert_wincs_to_utf8(const char *windows_string)
{
#ifdef NOTPORTED
	CFStringRef s;
	CFIndex maxlen;
	char *result;

	s = CFStringCreateWithCString(NULL, windows_string,
		get_windows_encoding_equivalent());
	if (s == NULL) {
		smb_error("CFStringCreateWithCString for Windows code page failed on \"%s\" ", -1,
		    windows_string);

		/* kCFStringEncodingMacRoman should always succeed */
		s = CFStringCreateWithCString(NULL, windows_string,
		    kCFStringEncodingMacRoman);
		if (s == NULL) {
			smb_error("CFStringCreateWithCString for Windows code page failed on \"%s\" with kCFStringEncodingMacRoman - skipping",
			    -1, windows_string);
			return NULL;
		}
	}

	maxlen = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s),
	    kCFStringEncodingUTF8) + 1;
	result = malloc(maxlen);
	if (result == NULL) {
		smb_error("Couldn't allocate buffer for UTF-8 string for \"%s\" - skipping", -1,
		    windows_string);
		CFRelease(s);
		return NULL;
	}
	if (!CFStringGetCString(s, result, maxlen, kCFStringEncodingUTF8)) {
		smb_error("CFStringGetCString for UTF-8 failed on \"%s\" - skipping",
		    -1, windows_string);
		CFRelease(s);
		return NULL;
	}
	CFRelease(s);
	return result;
#else /* NOTPORTED */
	return (strdup((char*)windows_string));
#endif /* NOTPORTED */
}

/*
 * XXX - NLS, or CF?  We should probably use the same routine for all
 * conversions.
 */
char *
convert_utf8_to_wincs(const char *utf8_string)
{
#ifdef NOTPORTED
	CFStringRef s;
	CFIndex maxlen;
	char *result;

	s = CFStringCreateWithCString(NULL, utf8_string,
	    kCFStringEncodingUTF8);
	if (s == NULL) {
		smb_error("CFStringCreateWithCString for UTF-8 failed on \"%s\"", -1,
		    utf8_string);
		return NULL;
	}

	maxlen = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s),
	    get_windows_encoding_equivalent()) + 1;
	result = malloc(maxlen);
	if (result == NULL) {
		smb_error("Couldn't allocate buffer for Windows code page string for \"%s\" - skipping", -1,
		    utf8_string);
		CFRelease(s);
		return NULL;
	}
	if (!CFStringGetCString(s, result, maxlen,
	    get_windows_encoding_equivalent())) {
		smb_error("CFStringGetCString for Windows code page failed on \"%s\" - skipping",
		    -1, utf8_string);
		CFRelease(s);
		return NULL;
	}
	CFRelease(s);
	return result;
#else /* NOTPORTED */
	return (strdup((char*)utf8_string));
#endif /* NOTPORTED */
}
/* END CSTYLED */

/*
 * We replaced these routines for Solaris:
 *	convert_leunicode_to_utf8
 *	convert_unicode_to_utf8
 *	convert_utf8_to_leunicode
 * with new code in: utf_str.c
 */
