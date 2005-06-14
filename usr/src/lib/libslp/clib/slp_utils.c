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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Miscellaneous Utilities
 *
 * slp_err:		Error and information message dispatch, i18n'd
 * slp_start_call:	Marks a SLP handle as in-use
 * slp_end_call:	Marks a SLP handle as available
 * slp_map_err:		protocol to API error mapping
 * slp_onlist:		determines if a token is on a list
 * slp_add2list:	adds a token to a list
 * slp_list_subtract:	removes a token from a list
 * slp_add_header:	creates a SLP message header
 * slp_get_length:	gets the length field from a SLP header
 * slp_set_length:	sets the length field in a SLP header
 * slp_header_get_sht:	gets a 16 bit integer from a SLP header
 * slp_header_set_sht:	sets a 16 bit interger in a SLP header
 * slp_header_length:	calculates the length of a header, including the
 *				language tag
 * slp_get_errcode:	returns the error code from a SLP message
 * slp_add_byte:	encodes a byte into the given buffer
 * slp_add_sht:		encodes a 16-bit integer into the given buffer
 * slp_add_string:	encodes the given string into the given buffer
 * slp_get_byte:	decodes a byte from the given buffer
 * slp_get_sht:		decodes a 16-bit integer from the given buffer
 * slp_get_string:	decodes a string from the given buffer
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <libintl.h>
#include <slp-internal.h>

#define	SLP_ERR_BUF_LEN	1024UL

/*
 * Outputs an error message. priority is a syslog(3) priority.
 */
/*ARGSUSED1*/
/* PRINTFLIKE4 */
void slp_err(int priority, int id, char *func, char *inmsg, ...) {
	static char buf[SLP_ERR_BUF_LEN];
	char *p, *msg;
	size_t len;
	va_list ap;
	static mutex_t loglock = DEFAULTMUTEX;
	va_start(ap, inmsg);

	(void) mutex_lock(&loglock);

	/* i18n mapping */
	msg = dgettext("libslp", inmsg);

	(void) snprintf(buf, sizeof (buf), "libslp: %s: ", func);
	len = strlen(buf);
	p = &(buf[len]);
	(void) vsnprintf(p, SLP_ERR_BUF_LEN - len, msg, ap);
	va_end(ap);
	syslog(priority, buf);
	(void) mutex_unlock(&loglock);
}

/*
 * Start and end slp calls
 * slp_start_call returns SLP_HANDLE_IN_USE if the handle is already
 * being used, otherwise SLP_OK.
 */
SLPError slp_start_call(slp_handle_impl_t *hp) {
	(void) mutex_lock(&(hp->outcall_lock));
	if (hp->pending_outcall) {
	    (void) mutex_unlock(&(hp->outcall_lock));
	    return (SLP_HANDLE_IN_USE);
	}
	hp->pending_outcall = SLP_TRUE;
	(void) mutex_unlock(&(hp->outcall_lock));

	hp->cancel = 0;
	return (SLP_OK);
}

void slp_end_call(slp_handle_impl_t *hp) {
	(void) mutex_lock(&(hp->outcall_lock));
	if (hp->close_on_end) {
	    /* SLPClose() called from callback */
	    (void) mutex_unlock(&(hp->outcall_lock));
	    slp_cleanup_handle(hp);
	    return;
	}

	hp->pending_outcall = SLP_FALSE;
	(void) cond_signal(&(hp->outcall_cv));
	(void) mutex_unlock(&(hp->outcall_lock));
}

/*
 * Map a protocol error code to an API error code.
 */
SLPError slp_map_err(unsigned short proto_err) {
	switch (proto_err) {
	case 0:	return (SLP_OK);
	case 1:	return (SLP_LANGUAGE_NOT_SUPPORTED);
	case 2:	return (SLP_PARSE_ERROR);
	case 3:	return (SLP_INVALID_REGISTRATION);
	case 4:	return (SLP_SCOPE_NOT_SUPPORTED);
	case 6:	return (SLP_AUTHENTICATION_ABSENT);
	case 7:	return (SLP_AUTHENTICATION_FAILED);
	case 13:	return (SLP_INVALID_UPDATE);
		/*
		 * 9 (VER_NOT_SUPPORTED), 10 (INTERNAL_ERROR),
		 * 11 (DA_BUSY_NOW), 12 (OPTION_NOT_UNDERSTOOD),
		 * and 14 (RQST_NOT_SUPPORTED)
		 * should be handled internally by the API.
		 */
	default:	return (SLP_INTERNAL_SYSTEM_ERROR);
	}
}

/*
 * SLP List Management:
 * SLP lists are comma separated lists of tokens. The following routines
 * manage SLP lists, ensuring proper UTF-8 parsing.
 */

/*
 * If 'item' is on 'list', returns 1, otherwise 0.
 */
int slp_onlist(const char *item, const char *list) {
	char *p;
	for (p = (char *)list; p; p++) {
		char *s;
		size_t span;

		s = p;
		p = slp_utf_strchr(p, ',');
		span = (p ? (size_t)(p - s): strlen(s));

		if (strlen(item) != span) {
			if (!p)
				break;
			else
				continue;
		}

		if (strncasecmp(item, s, span) == 0)
			return (1);
		if (!p)
			break;
	}
	return (0);
}

/*
 * Adds item to *list if it is not already on it. If *list == NULL,
 * creates a new list. When it grows the list, it will free *list,
 * so *list must not be on the caller's stack. 'check_onlist' specifies
 * whether to look to item on the current list. This is a small
 * optimization for callers which are that item is not on *list, or
 * which don't care about duplicates.
 */
void slp_add2list(const char *item, char **list, SLPBoolean check_onlist) {
	if (!(*list)) {
		if (!(*list = strdup(item)))
			slp_err(LOG_CRIT, 0, "slp_add2list", "out of memory");
		return;
	}

	if (check_onlist)
		/* no duplicates */
		if (slp_onlist(item, *list))
			return;

	if (!(*list = realloc(*list, strlen(*list) + strlen(item) + 2))) {
		slp_err(LOG_CRIT, 0, "slp_add2list", "out of memory");
		return;
	}
	(void) strcat(*list, ",");
	(void) strcat(*list, item);
}

/*
 * Removes the first instance of item from *list.
 * When it shrinks the list, it may free *list, so *list must not be on
 * the caller's stack.
 */
void slp_list_subtract(const char *item, char **list) {
	char *p, *s;

	if (!*list || !slp_onlist(item, *list))
		return;
	/* find item's location on the list */
	for (p = *list; p; p++) {
		size_t span;

		s = p;
		p = slp_utf_strchr(p, ',');
		span = (p ? (size_t)(p - s) : strlen(s));
		if (strlen(item) != span)
			continue;
		if (strncasecmp(item, s, span) == 0)
			break;
		if (!p)
			break;
	}
	if (!p && s == *list) {
		/* item is only one on list */
		free(*list);
		*list = NULL;
		return;
	}
	if (!p) {
		/* last one on list; just chop it off */
		s--;
		*s = 0;
		return;
	}
	/* either first on list, or somewhere in the middle */
	(void) strcpy(s, p + 1);
}

/* SLPv2 header management */

/*
 * Lays a SLP header into pcSendBuf, performing byte-ordering and bounds
 * checking where necessary.
 * pcLangTag: Language tag
 * pcSendBuf: a buffer into which to write the composed header
 * iSendBufSz: the size of pcSendBuf in bytes
 * iFun: SLP V2 function number
 * iLen: The length of the whole SLP message, in bytes
 * piLen: a pointer to an int into which will be written the size of the
 *	  header + the language tag (i.e. the offset at which the rest of
 *	  the message should be written into pcSendBuf).
 */
SLPError slp_add_header(const char *pcLangTag, char *pcSendBuf,
			size_t iSendBufSz, int iFun,
			size_t iLen, size_t *piLen) {
	unsigned short us, xid;
	static unsigned short xid_seeded = 0;

	if (!xid_seeded) {
		static mutex_t lock = DEFAULTMUTEX;
		(void) mutex_lock(&lock);
		if (!xid_seeded) {
			/* generate a seed based on our PID */
			long long pid = getpid();
			pid *= UINT_MAX;
			(void) seed48((unsigned short *) &pid);
			xid_seeded = 1;
		}
		(void) mutex_unlock(&lock);
	}
	/* squish the random value into an unsigned short */
	xid = (unsigned short) (lrand48() % USHRT_MAX);
	xid = xid ? xid : 1;	/* 0 is for DAs only */

	us = (unsigned short) strlen(pcLangTag);
	if ((SLP_HDRLEN + us) > iSendBufSz)
		return (SLP_PARAMETER_BAD);

	(void) memset(pcSendBuf, 0, SLP_HDRLEN);

	slp_set_version(pcSendBuf, SLP_VERSION);
	slp_set_function(pcSendBuf, (char)iFun);
	slp_set_length(pcSendBuf, iLen);
	slp_set_xid(pcSendBuf, xid);
	slp_set_langlen(pcSendBuf, us);
	(void) memcpy(&pcSendBuf[SLP_HDRLEN], pcLangTag, us);

	*piLen = SLP_HDRLEN + us;
	return (SLP_OK);
}

/*
 * Retrieves the 24 bit int stored at 'off' offset into 'header'.
 * Assumes 'header' is a valid SLP message header.
 */
unsigned int slp_header_get_int24(const char *header, size_t off) {
	unsigned int len;

	len = ((unsigned int)(header[off] & 0xff)) << 16;
	len += ((unsigned int)(header[off + 1] & 0xff)) << 8;
	len += ((unsigned int)(header[off + 2] & 0xff));

	return (len);
}

/*
 * Sets a 24 bit int at the location in 'header' 'off' bytes
 * offset into the header.
 * Assumes 'header' is a valid SLP message header.
 */
void slp_header_set_int24(char *header, unsigned int len, size_t off) {
	header[off] = (unsigned char) ((len & 0xff0000) >> 16);
	header[off + 1] = (unsigned char) ((len & 0xff00) >> 8);
	header[off + 2] = (unsigned char) (len & 0xff);
}

/*
 * Retrieves the 16 bit integer stored at 'off' offset into 'header'.
 * Assumes 'header' is a valid SLP message header.
 */
unsigned short slp_header_get_sht(const char *header, size_t off) {
	unsigned short answer = 0;
	(void) slp_get_sht(header, SLP_HDRLEN, &off, &answer);
	return (answer);
}

/*
 * Sets a 16 bit interger at the location in 'header' 'off' bytes
 * offset into the header.
 * Assumes 'header' is a valid SLP message header.
 */
void slp_header_set_sht(char *header, unsigned short len, size_t off) {
	(void) slp_add_sht(header, SLP_HDRLEN, len, &off);
}

/*
 * Returns the total length of a SLP header associated with the SLP
 * handle 'hp', including the language tag.
 */
size_t slp_header_length(slp_handle_impl_t *hp) {
	return (SLP_HDRLEN + strlen(hp->locale));
}

/*
 * Retrieves the error code for UA replies -- the errcode is always
 * the first short after the header for these functions. 'msg' points to
 * the beginning of a SLP header.
 */
slp_proto_err slp_get_errcode(char *msg) {
	unsigned short langlen, errcode;
	size_t off, msglen;

	/* make sure the reply is long enough */
	msglen = slp_get_length(msg);
	if (msglen < (SLP_LANGLEN + 2))
		return (SLP_MSG_PARSE_ERROR);
	langlen = slp_get_langlen(msg);
	off = SLP_HDRLEN + langlen;

	if (slp_get_sht(msg, msglen, &off, &errcode) != SLP_OK)
		return (SLP_MSG_PARSE_ERROR);

	return (errcode);
}

/*
 * Primitive Encoding and Decoding Routines.
 * All perform byte-ordering coversions and bounds checking.
 */

SLPError slp_add_byte(char *pcBuf, size_t iBufSz, int iVal,
			size_t *piLen) {
	if ((*piLen + 1) > iBufSz)
		return (SLP_PARAMETER_BAD);

	pcBuf[(*piLen)++] = (unsigned char) iVal;
	return (SLP_OK);
}

SLPError slp_add_sht(char *pcBuf, size_t iBufSz, unsigned short iVal,
			size_t *piLen) {
	if ((*piLen + 2) > iBufSz)
		return (SLP_PARAMETER_BAD);

	pcBuf[(*piLen)++] = (unsigned char) ((iVal & 0xFF00) >> 8);
	pcBuf[(*piLen)++] = (unsigned char) (iVal & 0xFF);
	return (SLP_OK);
}

SLPError slp_add_int32(char *pcBuf, size_t iBufSz, unsigned int iVal,
			size_t *piLen) {
	if ((*piLen + 4) > iBufSz)
		return (SLP_PARAMETER_BAD);

	pcBuf[(*piLen)++] = (unsigned char) ((iVal & 0xFF000000) >> 24);
	pcBuf[(*piLen)++] = (unsigned char) ((iVal & 0xFF0000) >> 16);
	pcBuf[(*piLen)++] = (unsigned char) ((iVal & 0xFF00) >> 8);
	pcBuf[(*piLen)++] = (unsigned char) (iVal & 0xFF);

	return (SLP_OK);
}

SLPError slp_add_string(char *pcBuf, size_t iBufSz, const char *pcStr,
			size_t *piLen) {
	size_t iStrLen = strlen(pcStr);
	SLPError err = 0;

	if (iStrLen > USHRT_MAX)
		/* SLP strings are limited to 16-bit len */
		return (SLP_PARAMETER_BAD);
	if ((iStrLen + *piLen + 2) > iBufSz)
		return (SLP_PARAMETER_BAD);

	if ((err = slp_add_sht(pcBuf, iBufSz, (unsigned short)iStrLen, piLen))
	    != SLP_OK)
		return (err);

	(void) memcpy(&(pcBuf[*piLen]), pcStr, iStrLen);
	*piLen += iStrLen;
	return (SLP_OK);
}

SLPError slp_get_byte(const char *pcBuf, size_t maxlen,
			size_t *piOffset, int *piByte) {
	size_t offset = 0;

	if (piOffset != NULL) {
		if ((*piOffset+1) > maxlen)
			return (SLP_PARSE_ERROR);
		offset = *piOffset;
		*piOffset += 1;
	}

	*piByte = (int)pcBuf[offset];
	return (SLP_OK);
}

SLPError slp_get_sht(const char *pcBuf, size_t maxlen,
			size_t *piOffset, unsigned short *piSht) {
	size_t offset = 0;

	if (piOffset != NULL) {
		if ((*piOffset+2) > maxlen)
			return (SLP_PARSE_ERROR);
		offset = *piOffset;
		*piOffset += 2;
	}

	*piSht = (unsigned short)
		((unsigned char)pcBuf[offset] & (unsigned char)0xFF);
	*piSht <<= 8;
	*piSht += (unsigned short)
		((unsigned char)pcBuf[offset+1] & (unsigned char)0xFF);

	return (SLP_OK);
}

SLPError slp_get_int32(const char *pcBuf, size_t maxlen,
			size_t *piOffset, unsigned int *piInt) {
	size_t offset = 0;

	if (piOffset != NULL) {
		if ((*piOffset+4) > maxlen)
			return (SLP_PARSE_ERROR);
		offset = *piOffset;
		*piOffset += 4;
	}

	*piInt = ((unsigned int)(pcBuf[offset] & 0xff)) << 24;
	*piInt += ((unsigned int)(pcBuf[offset+1] & 0xff)) << 16;
	*piInt += ((unsigned int)(pcBuf[offset+2] & 0xff)) << 8;
	*piInt += ((unsigned int)(pcBuf[offset+3] & 0xff));

	return (SLP_OK);
}

SLPError slp_get_string(const char *pcBuf, size_t iMaxLen,
		    size_t *piOffset, char **ppcString) {
	SLPError err;
	unsigned short iLen;

	*ppcString = NULL;
	err = slp_get_sht(pcBuf, iMaxLen, piOffset, &iLen);
	if (err)
		return (err);
	if ((iLen+*piOffset) > iMaxLen)
		return (SLP_PARSE_ERROR);

	if (!(*ppcString = malloc(iLen + 1))) {
		slp_err(LOG_CRIT, 0, "slp_get_string", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	(void) memcpy(*ppcString, pcBuf + *piOffset, iLen);
	(*ppcString)[iLen] = 0;
	*piOffset += iLen;
	return (SLP_OK);
}
