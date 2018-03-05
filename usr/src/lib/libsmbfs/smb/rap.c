/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: rap.c,v 1.5 2004/12/13 00:25:23 lindak Exp $
 *
 * This is very simple implementation of RAP protocol.
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/isa_defs.h>

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <libintl.h>
#include <sysexits.h>

#include <netsmb/mchain.h>
#include <netsmb/smb_lib.h>
#include <netsmb/smb_rap.h>
#include "private.h"

static int
smb_rap_parserqparam(const char *s, char **next, int *rlen)
{
	char *np;
	int len;

	switch (*s++) {
	case 'L':
	case 'T':
	case 'W':
		len = 2;
		break;
	case 'D':
	case 'O':
		len = 4;
		break;
	case 'b':
	case 'F':
		len = 1;
		break;
	case 'r':
	case 's':
		len = 0;
		break;
	default:
		return (EINVAL);
	}
	if (isdigit(*s)) {
		len *= strtoul(s, &np, 10);
		s = np;
	}
	*rlen = len;
	*(const char **)next = s;
	return (0);
}

static int
smb_rap_parserpparam(const char *s, char **next, int *rlen)
{
	char *np;
	int len = 0;

	switch (*s++) {
	case 'e':
	case 'h':
		len = 2;
		break;
	case 'i':
		len = 4;
		break;
	case 'g':
		len = 1;
		break;
	default:
		return (EINVAL);
	}
	if (isdigit(*s)) {
		len *= strtoul(s, &np, 10);
		s = np;
	}
	*rlen = len;
	*(const char **)next = s;
	return (0);
}

static int
smb_rap_parserpdata(const char *s, char **next, int *rlen)
{
	char *np;
	int len;

	switch (*s++) {
	case 'B':
		len = 1;
		break;
	case 'W':
		len = 2;
		break;
	case 'D':
	case 'O':
	case 'z':
		len = 4;
		break;
	default:
		return (EINVAL);
	}
	if (isdigit(*s)) {
		len *= strtoul(s, &np, 10);
		s = np;
	}
	*rlen = len;
	*(const char **)next = s;
	return (0);
}

static int
smb_rap_rqparam_z(struct smb_rap *rap, const char *value)
{
	int len = strlen(value) + 1;

	bcopy(value, rap->r_npbuf, len);
	rap->r_npbuf += len;
	rap->r_plen += len;
	return (0);
}

/*
 * Marshal RAP request parameters.
 * Note: value is in host order.
 */
static int
smb_rap_rqparam(struct smb_rap *rap, char ptype, char plen, int value)
{
	int len = 0;
	uint_t uv = (uint_t)value;
	uint32_t *lp;
	uint16_t *sp;
	char *p;

	switch (ptype) {
	case 'L':
	case 'W':
		/* LINTED */
		sp = (uint16_t *)rap->r_npbuf;
		*sp = htoles(uv);
		len = sizeof (*sp);
		break;
	case 'D':
		/* LINTED */
		lp = (uint32_t *)rap->r_npbuf;
		*lp = htolel(uv);
		len = sizeof (*lp);
		break;
	case 'b':
		p = rap->r_npbuf;
		memset(p, uv, plen);
		len = plen;
		break;
	default:
		return (EINVAL);
	}
	rap->r_npbuf += len;
	rap->r_plen += len;
	return (0);
}

int
smb_rap_create(int fn, const char *param, const char *data,
    struct smb_rap **rapp)
{
	struct smb_rap *rap;
	char *p;
	int plen = 0, len = 0;

	rap = malloc(sizeof (*rap));
	if (rap == NULL)
		return (ENOMEM);
	bzero(rap, sizeof (*rap));
	p = rap->r_sparam = rap->r_nparam = strdup(param);
	rap->r_sdata = rap->r_ndata = strdup(data);

	/*
	 * Calculate length of request parameter block
	 */
	len = 2 + strlen(param) + 1 + strlen(data) + 1;
	while (*p) {
		if (smb_rap_parserqparam(p, &p, &plen) != 0)
			break;
		len += plen;
	}
	rap->r_pbuf = rap->r_npbuf = malloc(len);
	if (rap->r_pbuf == NULL)
		return (ENOMEM);
	(void) smb_rap_rqparam(rap, 'W', 1, fn);
	(void) smb_rap_rqparam_z(rap, rap->r_sparam);
	(void) smb_rap_rqparam_z(rap, rap->r_sdata);
	*rapp = rap;
	return (0);
}

void
smb_rap_done(struct smb_rap *rap)
{
	if (rap->r_sparam)
		free(rap->r_sparam);
	if (rap->r_sdata)
		free(rap->r_sdata);
	if (rap->r_pbuf)
		free(rap->r_pbuf);
#ifdef NOTYETDEFINED
	if (rap->r_npbuf)
		free(rap->r_npbuf);
	if (rap->r_dbuf)
		free(rap->r_dbuf);
	if (rap->r_rcvbuf)
		free(rap->r_rcvbuf);
#endif
	free(rap);
}

int
smb_rap_setNparam(struct smb_rap *rap, int value)
{
	char *p = rap->r_nparam;
	char ptype = *p;
	int error, plen;

	error = smb_rap_parserqparam(p, &p, &plen);
	if (error)
		return (error);
	switch (ptype) {
	case 'L':
		rap->r_rcvbuflen = value;
		/* FALLTHROUGH */
	case 'W':
	case 'D':
	case 'b':
		error = smb_rap_rqparam(rap, ptype, plen, value);
		break;
	default:
		return (EINVAL);
	}
	rap->r_nparam = p;
	return (0);
}

int
smb_rap_setPparam(struct smb_rap *rap, void *value)
{
	char *p = rap->r_nparam;
	char ptype = *p;
	int error, plen;

	error = smb_rap_parserqparam(p, &p, &plen);
	if (error)
		return (error);
	switch (ptype) {
	case 'r':
		rap->r_rcvbuf = value;
		break;
	default:
		return (EINVAL);
	}
	rap->r_nparam = p;
	return (0);
}

int
smb_rap_getNparam(struct smb_rap *rap, long *value)
{
	char *p = rap->r_nparam;
	char ptype = *p;
	int error, plen;
	uint16_t	*te;

	error = smb_rap_parserpparam(p, &p, &plen);
	if (error)
		return (error);
	switch (ptype) {
	case 'h':
		/* LINTED */
		te = (uint16_t *)rap->r_npbuf;
		*value = letohs(*te);
		break;
	default:
		return (EINVAL);
	}
	rap->r_npbuf += plen;
	rap->r_nparam = p;
	return (0);
}

int
smb_rap_request(struct smb_rap *rap, struct smb_ctx *ctx)
{
	uint16_t *rp, conv, *tmp;
	uint32_t *p32;
	char *dp, *p = rap->r_nparam;
	char ptype;
	int error, rdatacnt, rparamcnt, entries, done, dlen, buffer_oflow;

	rdatacnt = rap->r_rcvbuflen;
	rparamcnt = rap->r_plen;
	error = smb_t2_request(ctx->ct_dev_fd,
	    0, NULL, "\\PIPE\\LANMAN",
	    rap->r_plen, rap->r_pbuf,		/* int tparamcnt,void *tparam */
	    0, NULL,				/* int tdatacnt, void *tdata */
	    &rparamcnt, rap->r_pbuf,		/* rparamcnt, void *rparam */
	    &rdatacnt, rap->r_rcvbuf,		/* int *rdatacnt, void *rdata */
	    &buffer_oflow);
	if (error)
		return (error);

	/* LINTED */
	rp = (uint16_t *)rap->r_pbuf;

	/*
	 * Note: First is a "LanMan API" error code.
	 * See: usr/src/uts/common/smbsrv/lmerr.h
	 */
	if (rparamcnt < 2)
		return (EBADRPC);
	rap->r_result = letohs(*rp);
	rp++; rparamcnt -= 2;

	if (rap->r_result != 0) {
		/*
		 * Could also return zero and let the caller
		 * come get r_result via smb_rap_error(),
		 * but in case they dont...
		 */
		return (rap->r_result | SMB_RAP_ERROR);
	}

	if (rparamcnt < 2)
		return (EBADRPC);
	conv = letohs(*rp);
	rp++; rparamcnt -= 2;

	rap->r_npbuf = (char *)rp;
	rap->r_entries = entries = 0;
	/* Save the returned data length */
	rap->r_rcvbuflen = rdatacnt;
	done = 0;

	while (!done && *p) {
		ptype = *p;
		switch (ptype) {
		case 'e':
			if (rparamcnt < 2)
				return (EBADRPC);
			/* LINTED */
			tmp = (uint16_t *)rap->r_npbuf;
			rap->r_entries = entries = letohs(*tmp);
			rap->r_npbuf += 2;
			rparamcnt -= 2;
			p++;
			break;
		default:
			done = 1;
		}
#if 0	/* commented out in Darwin. Why? */
		error = smb_rap_parserpparam(p, &p, &plen);
		if (error) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "reply parameter mismatch %s"), 0, p);
			return (EBADRPC);
		}
#endif
	}
	rap->r_nparam = p;
	/*
	 * In general, unpacking entries we may need to relocate
	 * entries for proper aligning. For now use them as is.
	 */
	dp = rap->r_rcvbuf;
	while (entries--) {
		p = rap->r_sdata;
		while (*p) {
			ptype = *p;
			error = smb_rap_parserpdata(p, &p, &dlen);
			if (error) {
				smb_error(dgettext(TEXT_DOMAIN,
				    "reply data mismatch %s"), 0, p);
				return (EBADRPC);
			}
			if (rdatacnt < dlen)
				return (EBADRPC);
			switch (ptype) {
			case 'z':
				/* LINTED */
				p32 = (uint32_t *)dp;
				*p32 = (letohl(*p32) & 0xffff) - conv;
				break;
			}
			dp += dlen;
			rdatacnt -= dlen;
		}
	}
	return (error);
}

int
smb_rap_error(struct smb_rap *rap, int error)
{
	if (error)
		return (error);
	if (rap->r_result == 0)
		return (0);
	return (rap->r_result | SMB_RAP_ERROR);
}
