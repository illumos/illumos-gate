/*
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
 * $Id: mbuf.c,v 1.3 2004/12/13 00:25:22 lindak Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <assert.h>

#include <netsmb/smb_lib.h>
#include <netsmb/mchain.h>

#include "private.h"
#include "charsets.h"

static int
m_get(size_t len, struct mbuf **mpp)
{
	struct mbuf *m;

	assert(len < 0x100000); /* sanity */

	len = M_ALIGN(len);
	if (len < M_MINSIZE)
		len = M_MINSIZE;
	m = malloc(M_BASESIZE + len);
	if (m == NULL)
		return (ENOMEM);
	bzero(m, M_BASESIZE + len);
	m->m_maxlen = len;
	m->m_data = M_TOP(m);
	*mpp = m;
	return (0);
}

static void
m_free(struct mbuf *m)
{
	free(m);
}

void
m_freem(struct mbuf *m0)
{
	struct mbuf *m;

	while (m0) {
		m = m0->m_next;
		m_free(m0);
		m0 = m;
	}
}

size_t
m_totlen(struct mbuf *m0)
{
	struct mbuf *m = m0;
	int len = 0;

	while (m) {
		len += m->m_len;
		m = m->m_next;
	}
	return (len);
}

int
m_lineup(struct mbuf *m0, struct mbuf **mpp)
{
	struct mbuf *nm, *m;
	char *dp;
	size_t len;
	int error;

	if (m0->m_next == NULL) {
		*mpp = m0;
		return (0);
	}
	if ((error = m_get(m_totlen(m0), &nm)) != 0)
		return (error);
	dp = mtod(nm, char *);
	while (m0) {
		len = m0->m_len;
		bcopy(m0->m_data, dp, len);
		dp += len;
		m = m0->m_next;
		m_free(m0);
		m0 = m;
	}
	*mpp = nm;
	return (0);
}

int
mb_init(struct mbdata *mbp, size_t size)
{
	struct mbuf *m;
	int error;

	if ((error = m_get(size, &m)) != 0)
		return (error);
	return (mb_initm(mbp, m));
}

int
mb_initm(struct mbdata *mbp, struct mbuf *m)
{
	bzero(mbp, sizeof (*mbp));
	mbp->mb_top = mbp->mb_cur = m;
	mbp->mb_pos = mtod(m, char *);
	return (0);
}

int
mb_done(struct mbdata *mbp)
{
	if (mbp->mb_top) {
		m_freem(mbp->mb_top);
		mbp->mb_top = NULL;
	}
	return (0);
}

int
m_getm(struct mbuf *top, size_t len, struct mbuf **mpp)
{
	struct mbuf *m, *mp;
	int  error, ts;

	for (mp = top; ; mp = mp->m_next) {
		ts = M_TRAILINGSPACE(mp);
		if (len <= ts)
			goto out;
		len -= ts;
		if (mp->m_next == NULL)
			break;

	}
	if (len > 0) {
		if ((error = m_get(len, &m)) != 0)
			return (error);
		mp->m_next = m;
	}
out:
	*mpp = top;
	return (0);
}

/*
 * Routines to put data in a buffer
 */

/*
 * Check if object of size 'size' fit to the current position and
 * allocate new mbuf if not. Advance pointers and increase length of mbuf(s).
 * Return pointer to the object placeholder or NULL if any error occured.
 */
int
mb_fit(struct mbdata *mbp, size_t size, char **pp)
{
	struct mbuf *m, *mn;
	int error;

	m = mbp->mb_cur;
	if (M_TRAILINGSPACE(m) < (int)size) {
		if ((error = m_get(size, &mn)) != 0)
			return (error);
		mbp->mb_pos = mtod(mn, char *);
		mbp->mb_cur = m->m_next = mn;
		m = mn;
	}
	m->m_len += size;
	*pp = mbp->mb_pos;
	mbp->mb_pos += size;
	mbp->mb_count += size;
	return (0);
}

int
mb_put_uint8(struct mbdata *mbp, uint8_t x)
{
	uint8_t y = x;
	return (mb_put_mem(mbp, &y, sizeof (y)));
}

int
mb_put_uint16be(struct mbdata *mbp, uint16_t x)
{
	uint16_t y = htobes(x);
	return (mb_put_mem(mbp, &y, sizeof (y)));
}

int
mb_put_uint16le(struct mbdata *mbp, uint16_t x)
{
	uint16_t y = htoles(x);
	return (mb_put_mem(mbp, &y, sizeof (y)));
}

int
mb_put_uint32be(struct mbdata *mbp, uint32_t x)
{
	uint32_t y = htobel(x);
	return (mb_put_mem(mbp, &y, sizeof (y)));
}

int
mb_put_uint32le(struct mbdata *mbp, uint32_t x)
{
	uint32_t y = htolel(x);
	return (mb_put_mem(mbp, &y, sizeof (y)));
}

int
mb_put_uint64be(struct mbdata *mbp, uint64_t x)
{
	uint64_t y = htobeq(x);
	return (mb_put_mem(mbp, &y, sizeof (y)));
}

int
mb_put_uint64le(struct mbdata *mbp, uint64_t x)
{
	uint64_t y = htoleq(x);
	return (mb_put_mem(mbp, &y, sizeof (y)));
}

int
mb_put_mem(struct mbdata *mbp, const void *vmem, size_t size)
{
	struct mbuf *m;
	const char *src;
	char  *dst;
	size_t cplen;
	int error;

	if (size == 0)
		return (0);

	src = vmem;
	m = mbp->mb_cur;
	if ((error = m_getm(m, size, &m)) != 0)
		return (error);
	while (size > 0) {
		cplen = M_TRAILINGSPACE(m);
		if (cplen == 0) {
			m = m->m_next;
			continue;
		}
		if (cplen > size)
			cplen = size;
		dst = mtod(m, char *) + m->m_len;
		if (src) {
			bcopy(src, dst, cplen);
			src += cplen;
		} else
			bzero(dst, cplen);
		size -= cplen;
		m->m_len += cplen;
		mbp->mb_count += cplen;
	}
	mbp->mb_pos = mtod(m, char *) + m->m_len;
	mbp->mb_cur = m;
	return (0);
}

/*
 * Append another mbuf to the mbuf chain.
 * If what we're appending is smaller than
 * the current trailing space, just copy.
 * This always consumes the passed mbuf.
 */
int
mb_put_mbuf(struct mbdata *mbp, struct mbuf *m)
{
	struct mbuf *cm = mbp->mb_cur;
	int ts = M_TRAILINGSPACE(cm);

	if (m->m_next == NULL && m->m_len <= ts) {
		/* just copy */
		mb_put_mem(mbp, m->m_data, m->m_len);
		m_freem(m);
		return (0);
	}

	cm->m_next = m;
	while (m) {
		mbp->mb_count += m->m_len;
		if (m->m_next == NULL)
			break;
		m = m->m_next;
	}
	mbp->mb_pos = mtod(m, char *) + m->m_len;
	mbp->mb_cur = m;
	return (0);
}

/*
 * Convenience function to put an OEM or Unicode string,
 * null terminated, and aligned if necessary.
 */
int
mb_put_dstring(struct mbdata *mbp, const char *s, int uc)
{
	int err;

	if (uc) {
		/* Put Unicode.  align(2) first. */
		if (mbp->mb_count & 1)
			mb_put_uint8(mbp, 0);
		err = mb_put_ustring(mbp, s);
	} else {
		/* Put ASCII (really OEM) */
		err = mb_put_astring(mbp, s);
	}

	return (err);
}

/*
 * Put an ASCII string (really OEM), given a UTF-8 string.
 */
int
mb_put_astring(struct mbdata *mbp, const char *s)
{
	char *abuf;
	int err, len;

	abuf = convert_utf8_to_wincs(s);
	if (abuf == NULL)
		return (ENOMEM);
	len = strlen(abuf) + 1;
	err = mb_put_mem(mbp, abuf, len);
	free(abuf);
	return (err);
}

/*
 * Put UCS-2LE, given a UTF-8 string.
 */
int
mb_put_ustring(struct mbdata *mbp, const char *s)
{
	uint16_t *ubuf;
	int err, len;

	ubuf = convert_utf8_to_leunicode(s);
	if (ubuf == NULL)
		return (ENOMEM);
	len = unicode_strlen(ubuf) + 1;
	err = mb_put_mem(mbp, ubuf, (len << 1));
	free(ubuf);
	return (err);
}

/*
 * Routines for fetching data from an mbuf chain
 */
#define	mb_left(m, p)	(mtod(m, char *) + (m)->m_len - (p))

int
mb_get_uint8(struct mbdata *mbp, uint8_t *x)
{
	return (mb_get_mem(mbp, x, 1));
}

int
mb_get_uint16(struct mbdata *mbp, uint16_t *x)
{
	return (mb_get_mem(mbp, x, 2));
}

int
mb_get_uint16le(struct mbdata *mbp, uint16_t *x)
{
	uint16_t v;
	int err;

	if ((err = mb_get_mem(mbp, &v, 2)) != 0)
		return (err);
	if (x != NULL)
		*x = letohs(v);
	return (0);
}

int
mb_get_uint16be(struct mbdata *mbp, uint16_t *x) {
	uint16_t v;
	int err;

	if ((err = mb_get_mem(mbp, &v, 2)) != 0)
		return (err);
	if (x != NULL)
		*x = betohs(v);
	return (0);
}

int
mb_get_uint32(struct mbdata *mbp, uint32_t *x)
{
	return (mb_get_mem(mbp, x, 4));
}

int
mb_get_uint32be(struct mbdata *mbp, uint32_t *x)
{
	uint32_t v;
	int err;

	if ((err = mb_get_mem(mbp, &v, 4)) != 0)
		return (err);
	if (x != NULL)
		*x = betohl(v);
	return (0);
}

int
mb_get_uint32le(struct mbdata *mbp, uint32_t *x)
{
	uint32_t v;
	int err;

	if ((err = mb_get_mem(mbp, &v, 4)) != 0)
		return (err);
	if (x != NULL)
		*x = letohl(v);
	return (0);
}

int
mb_get_uint64(struct mbdata *mbp, uint64_t *x)
{
	return (mb_get_mem(mbp, x, 8));
}

int
mb_get_uint64be(struct mbdata *mbp, uint64_t *x)
{
	uint64_t v;
	int err;

	if ((err = mb_get_mem(mbp, &v, 8)) != 0)
		return (err);
	if (x != NULL)
		*x = betohq(v);
	return (0);
}

int
mb_get_uint64le(struct mbdata *mbp, uint64_t *x)
{
	uint64_t v;
	int err;

	if ((err = mb_get_mem(mbp, &v, 8)) != 0)
		return (err);
	if (x != NULL)
		*x = letohq(v);
	return (0);
}

int
mb_get_mem(struct mbdata *mbp, void *vmem, size_t size)
{
	struct mbuf *m = mbp->mb_cur;
	char *dst = vmem;
	uint_t count;

	while (size > 0) {
		if (m == NULL) {
			/* DPRINT("incomplete copy"); */
			return (EBADRPC);
		}
		count = mb_left(m, mbp->mb_pos);
		if (count == 0) {
			mbp->mb_cur = m = m->m_next;
			if (m)
				mbp->mb_pos = mtod(m, char *);
			continue;
		}
		if (count > size)
			count = size;
		size -= count;
		if (dst) {
			if (count == 1) {
				*dst++ = *mbp->mb_pos;
			} else {
				bcopy(mbp->mb_pos, dst, count);
				dst += count;
			}
		}
		mbp->mb_pos += count;
	}
	return (0);
}

/*
 * Get the next SIZE bytes as a separate mblk.
 * Nothing fancy here - just copy.
 */
int
mb_get_mbuf(struct mbdata *mbp, int size, struct mbuf **ret)
{
	mbuf_t *m;
	int err;

	err = m_get(size, &m);
	if (err)
		return (err);

	err = mb_get_mem(mbp, m->m_data, size);
	if (err) {
		m_freem(m);
		return (err);
	}
	m->m_len = size;
	*ret = m;

	return (0);
}

/*
 * Get a string from the mbuf chain,
 * either Unicode or OEM chars.
 */
int
mb_get_string(struct mbdata *mbp, char **str_pp, int uc)
{
	int err;

	if (uc)
		err = mb_get_ustring(mbp, str_pp);
	else
		err = mb_get_astring(mbp, str_pp);
	return (err);
}

/*
 * Get an ASCII (really OEM) string from the mbuf chain
 * and convert it to UTF-8
 * Similar to mb_get_ustring below.
 */
int
mb_get_astring(struct mbdata *real_mbp, char **str_pp)
{
	struct mbdata tmp_mb, *mbp;
	char *tstr, *ostr;
	int err, i, slen;
	uint8_t ch;

	/*
	 * First, figure out the string length.
	 * Use a copy of the real_mbp so we don't
	 * actually consume it here, then search for
	 * the null (or end of data).
	 */
	bcopy(real_mbp, &tmp_mb, sizeof (tmp_mb));
	mbp = &tmp_mb;
	slen = 0;
	for (;;) {
		err = mb_get_uint8(mbp, &ch);
		if (err)
			break;
		if (ch == 0)
			break;
		slen++;
	}

	/*
	 * Now read the (OEM) string for real.
	 * No need to re-check errors.
	 */
	tstr = malloc(slen + 1);
	if (tstr == NULL)
		return (ENOMEM);
	mbp = real_mbp;
	for (i = 0; i < slen; i++) {
		mb_get_uint8(mbp, &ch);
		tstr[i] = ch;
	}
	tstr[i] = 0;
	mb_get_uint8(mbp, NULL);

	/*
	 * Convert OEM to UTF-8
	 */
	ostr = convert_wincs_to_utf8(tstr);
	free(tstr);
	if (ostr == NULL)
		return (ENOMEM);

	*str_pp = ostr;
	return (0);
}

/*
 * Get a UCS-2LE string from the mbuf chain, and
 * convert it to UTF-8.
 *
 * Similar to mb_get_astring below.
 */
int
mb_get_ustring(struct mbdata *real_mbp, char **str_pp)
{
	struct mbdata tmp_mb, *mbp;
	uint16_t *tstr;
	char *ostr;
	int err, i, slen;
	uint16_t ch;

	/*
	 * First, align(2) on the real_mbp
	 */
	if (((uintptr_t)real_mbp->mb_pos) & 1)
		mb_get_uint8(real_mbp, NULL);

	/*
	 * Next, figure out the string length.
	 * Use a copy of the real_mbp so we don't
	 * actually consume it here, then search for
	 * the null (or end of data).
	 */
	bcopy(real_mbp, &tmp_mb, sizeof (tmp_mb));
	mbp = &tmp_mb;
	slen = 0;
	for (;;) {
		err = mb_get_uint16le(mbp, &ch);
		if (err)
			break;
		if (ch == 0)
			break;
		slen++;
	}

	/*
	 * Now read the (UCS-2) string for real.
	 * No need to re-check errors.  Note:
	 * This puts the UCS-2 in NATIVE order!
	 */
	tstr = calloc(slen + 1, 2);
	if (tstr == NULL)
		return (ENOMEM);
	mbp = real_mbp;
	for (i = 0; i < slen; i++) {
		mb_get_uint16le(mbp, &ch);
		tstr[i] = ch;
	}
	tstr[i] = 0;
	mb_get_uint16le(mbp, NULL);

	/*
	 * Convert UCS-2 (native!) to UTF-8
	 */
	ostr = convert_unicode_to_utf8(tstr);
	free(tstr);
	if (ostr == NULL)
		return (ENOMEM);

	*str_pp = ostr;
	return (0);
}
