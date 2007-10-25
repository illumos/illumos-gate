/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SMB mbuf marshaling encode/decode.
 */

#include <smbsrv/smb_incl.h>

#define	MALLOC_QUANTUM	80

#define	DECODE_NO_ERROR		0
#define	DECODE_NO_MORE_DATA	1
#define	DECODE_ALLOCATION_ERROR	2
#define	DECODE_CONVERSION_ERROR	3


/*
 * Put data into mbuf chain allocating as needed.
 * Adds room to end of mbuf chain if needed.
 */

int
mbc_marshal_make_room(struct mbuf_chain *mbc, int32_t bytes_needed)
{
	struct mbuf	*m;
	struct mbuf	*l;
	int32_t		bytes_available;

	bytes_needed += mbc->chain_offset;
	if (bytes_needed > mbc->max_bytes)
		return (EMSGSIZE);

	if ((m = mbc->chain) == 0) {
		MGET(m, M_WAIT, MT_DATA);
		m->m_len = 0;
		if (mbc->max_bytes > MLEN)
			MCLGET(m, M_WAIT);
		mbc->chain = m;
		/* xxxx */
		/* ^    */
	}

	/* ---- ----- --xx ---xxx */
	/* ^			  */

	l = 0;
	while ((m != 0) && (bytes_needed >= m->m_len)) {
		l = m;
		bytes_needed -= m->m_len;
		m = m->m_next;
	}

	if ((bytes_needed == 0) || (m != 0)) {
		/* We have enough room already */
		return (0);
	}

	/* ---- ----- --xx ---xxx */
	/*			 ^ */
	/* Back up to start of last mbuf */
	m = l;
	bytes_needed += m->m_len;

	/* ---- ----- --xx ---xxx */
	/*		   ^	  */

	bytes_available = (m->m_flags & M_EXT) ?
	    m->m_ext.ext_size : MLEN;

	/* ---- ----- --xx ---xxx */
	/*		   ^	  */
	while ((bytes_needed != 0) && (bytes_needed > bytes_available)) {
		m->m_len = bytes_available;
		bytes_needed -= m->m_len;
		/* ---- ----- --xx ------ */
		/*		   ^	  */

		MGET(m->m_next, M_WAIT, MT_DATA);
		m = m->m_next;
		m->m_len = 0;
		if (bytes_needed > MLEN)
			MCLGET(m, M_WAIT);

		bytes_available = (m->m_flags & M_EXT) ?
		    m->m_ext.ext_size : MLEN;

		/* ---- ----- --xx ------ xxxx */
		/*			  ^    */
	}

	/* ---- ----- --xx ------ xxxx */
	/*			  ^    */
	/* Expand last tail as needed */
	if (m->m_len <= bytes_needed) {
		m->m_len = bytes_needed;
		/* ---- ----- --xx ------ --xx */
		/*			   ^   */
	}

	return (0);
}


void
mbc_marshal_store_byte(struct mbuf_chain *mbc, unsigned char data)
{
	struct mbuf	*m = mbc->chain;
	int32_t		cur_offset = mbc->chain_offset;

	/*
	 * Scan forward looking for the last data currently in chain.
	 */
	while (cur_offset >= m->m_len) {
		cur_offset -= m->m_len;
		m = m->m_next;
	}
	((char *)m->m_data)[cur_offset] = data;
	mbc->chain_offset++;
}


int
mbc_marshal_put_char(struct mbuf_chain *mbc, unsigned char data)
{
	if (mbc_marshal_make_room(mbc, sizeof (char)) != 0)
		return (DECODE_NO_MORE_DATA);
	mbc_marshal_store_byte(mbc, data);
	return (0);
}


int
mbc_marshal_put_short(struct mbuf_chain *mbc, unsigned short data)
{
	if (mbc_marshal_make_room(mbc, sizeof (short)))
		return (DECODE_NO_MORE_DATA);
	mbc_marshal_store_byte(mbc, data);
	mbc_marshal_store_byte(mbc, data >> 8);
	return (0);
}


int
mbc_marshal_put_long(struct mbuf_chain *mbc, uint32_t data)
{
	if (mbc_marshal_make_room(mbc, sizeof (int32_t)))
		return (DECODE_NO_MORE_DATA);
	mbc_marshal_store_byte(mbc, data);
	mbc_marshal_store_byte(mbc, data >> 8);
	mbc_marshal_store_byte(mbc, data >> 16);
	mbc_marshal_store_byte(mbc, data >> 24);
	return (0);
}


int
mbc_marshal_put_long_long(struct mbuf_chain *mbc, uint64_t data)
{
	if (mbc_marshal_make_room(mbc, sizeof (int64_t)))
		return (DECODE_NO_MORE_DATA);

	mbc_marshal_store_byte(mbc, data);
	mbc_marshal_store_byte(mbc, data >> 8);
	mbc_marshal_store_byte(mbc, data >> 16);
	mbc_marshal_store_byte(mbc, data >> 24);
	mbc_marshal_store_byte(mbc, data >> 32);
	mbc_marshal_store_byte(mbc, data >> 40);
	mbc_marshal_store_byte(mbc, data >> 48);
	mbc_marshal_store_byte(mbc, data >> 56);
	return (0);
}


/*
 * When need to convert from UTF-8 (internal format) to a single
 * byte string (external format ) when marshalling a string.
 */
int
mbc_marshal_put_ascii_string(struct mbuf_chain *mbc, char *mbs, int repc)
{
	mts_wchar_t wide_char;
	int nbytes;
	int	length;

	if ((length = mts_sbequiv_strlen(mbs)) == -1)
		return (DECODE_NO_MORE_DATA);

	length += sizeof (char);

	if ((repc > 1) && (repc < length))
		length = repc;
	if (mbc_marshal_make_room(mbc, length))
		return (DECODE_NO_MORE_DATA);

	while (*mbs) {
		/*
		 * We should restore oem chars here.
		 */
		nbytes = mts_mbtowc(&wide_char, mbs, MTS_MB_CHAR_MAX);
		if (nbytes == -1)
			return (DECODE_NO_MORE_DATA);

		mbc_marshal_store_byte(mbc, (unsigned char)wide_char);

		if (wide_char & 0xFF00)
			mbc_marshal_store_byte(mbc, wide_char >> 8);

		mbs += nbytes;
	}

	mbc_marshal_store_byte(mbc, 0);
	return (0);
}


int
mbc_marshal_put_alignment(struct mbuf_chain *mbc, unsigned int align)
{
	int32_t		delta = mbc->chain_offset % align;

	if (delta != 0) {
		align -= delta;
		if (mbc_marshal_make_room(mbc, align))
			return (DECODE_NO_MORE_DATA);
		while (align-- > 0)
			mbc_marshal_store_byte(mbc, 0);
	}
	return (0);
}


int
mbc_marshal_put_unicode_string(struct mbuf_chain *mbc, char *ascii, int repc)
{
	mts_wchar_t	wchar;
	int	consumed;
	int	length;

	if ((length = mts_wcequiv_strlen(ascii)) == -1)
		return (DECODE_NO_MORE_DATA);

	length += sizeof (mts_wchar_t);

#if 0
	if (mbc_marshal_put_alignment(mbc, sizeof (mts_wchar_t)) != 0)
		return (DECODE_NO_MORE_DATA);
#endif
	if ((repc > 1) && (repc < length))
		length = repc;

	if (mbc_marshal_make_room(mbc, length))
		return (DECODE_NO_MORE_DATA);
	while (length > 0) {
		consumed = mts_mbtowc(&wchar, ascii, MTS_MB_CHAR_MAX);
		if (consumed == -1)
			break;	/* Invalid sequence */
		/*
		 * Note that consumed will be 0 when the null terminator
		 * is encountered and ascii will not be advanced beyond
		 * that point. Length will continue to be decremented so
		 * we won't get stuck here.
		 */
		ascii += consumed;
		mbc_marshal_store_byte(mbc, wchar);
		mbc_marshal_store_byte(mbc, wchar >> 8);
		length -= sizeof (mts_wchar_t);
	}
	return (0);
}


int
mbc_marshal_put_uio(struct mbuf_chain *mbc, struct uio *uio)
{
	struct mbuf	**t;
	struct mbuf	*m = 0;
	struct iovec	*iov = uio->uio_iov;
	int32_t		i, iov_cnt = uio->uio_iovcnt;

	iov = uio->uio_iov;
	t = &mbc->chain;
	for (i = 0; i < iov_cnt; i++) {
		MGET(m, M_WAIT, MT_DATA);
		m->m_ext.ext_buf = iov->iov_base;
		m->m_ext.ext_ref = smb_noop;
		m->m_data = m->m_ext.ext_buf;
		m->m_flags |= M_EXT;
		m->m_len = m->m_ext.ext_size = iov->iov_len;
		mbc->max_bytes += m->m_len;
		m->m_next = 0;
		*t = m;
		t = &m->m_next;
		iov++;
	}
	return (0);
}

int
mbc_marshal_put_mbufs(struct mbuf_chain *mbc, struct mbuf *m)
{
	struct mbuf	*mt;
	struct mbuf	**t;
	int		bytes;

	if (m != 0) {
		mt = m;
		bytes = mt->m_len;
		while (mt->m_next != 0) {
			mt = mt->m_next;
			bytes += mt->m_len;
		}
		if (bytes != 0) {
			t = &mbc->chain;
			while (*t != 0) {
				bytes += (*t)->m_len;
				t = &(*t)->m_next;
			}
			*t = m;
			mbc->chain_offset = bytes;
		} else {
			m_freem(m);
		}
	}
	return (0);
}

int
mbc_marshal_put_mbuf_chain(struct mbuf_chain *mbc, struct mbuf_chain *nmbc)
{
	if (nmbc->chain != 0) {
		if (mbc_marshal_put_mbufs(mbc, nmbc->chain))
			return (DECODE_NO_MORE_DATA);
		MBC_SETUP(nmbc, nmbc->max_bytes);
	}
	return (0);
}

int
mbc_marshal_put_SID(struct mbuf_chain *mbc, nt_sid_t *pSid)
{
	int	i;

	if (mbc_marshal_put_char(mbc, pSid->Revision) != 0)
		return (DECODE_NO_MORE_DATA);

	if (mbc_marshal_put_char(mbc, pSid->SubAuthCount) != 0)
		return (DECODE_NO_MORE_DATA);

	for (i = 0; i < 6; i++) {
		if (mbc_marshal_put_char(mbc,
		    pSid->Authority[i]) != 0)
			return (DECODE_NO_MORE_DATA);

	}

	for (i = 0; i < pSid->SubAuthCount; i++) {
		if (mbc_marshal_put_long(mbc, pSid->SubAuthority[i]) != 0)
			return (DECODE_NO_MORE_DATA);
	}
	return (0);
}


int
mbc_marshal_put_skip(struct mbuf_chain *mbc, unsigned int skip)
{
	if (mbc_marshal_make_room(mbc, skip))
		return (DECODE_NO_MORE_DATA);
	while (skip-- > 0)
		mbc_marshal_store_byte(mbc, 0);
	return (0);
}

unsigned char
mbc_marshal_fetch_byte(struct mbuf_chain *mbc)
{
	unsigned char	data;
	struct mbuf	*m = mbc->chain;
	int32_t		offset = mbc->chain_offset;

	while (offset >= m->m_len) {
		offset -= m->m_len;
		m = m->m_next;
	}
	data = ((unsigned char *)m->m_data)[offset];
	mbc->chain_offset++;
	return (data);
}


int
mbc_marshal_get_char(struct mbuf_chain *mbc, unsigned char *data)
{
	if (MBC_ROOM_FOR(mbc, sizeof (char)) == 0) {
		/* Data will never be available */
		return (DECODE_NO_MORE_DATA);
	}
	*data = mbc_marshal_fetch_byte(mbc);
	return (0);
}


int
mbc_marshal_get_short(struct mbuf_chain *mbc, unsigned short *data)
{
	unsigned short	tmp;
	struct mbuf	*m = mbc->chain;
	int32_t		offset = mbc->chain_offset;

	if (MBC_ROOM_FOR(mbc, sizeof (short)) == 0) {
		/* Data will never be available */
		return (DECODE_NO_MORE_DATA);
	}

	while (offset >= m->m_len) {
		offset -= m->m_len;
		m = m->m_next;
	}
	if ((m->m_len - offset) >= sizeof (short)) {
		*data = LE_IN16(m->m_data + offset);
		mbc->chain_offset += sizeof (short);
	} else {
		tmp = (unsigned short)mbc_marshal_fetch_byte(mbc);
		tmp |= ((unsigned short)mbc_marshal_fetch_byte(mbc)) << 8;
		*data = tmp;
	}
	return (0);
}


int
mbc_marshal_get_long(struct mbuf_chain *mbc, uint32_t *data)
{
	uint32_t	tmp;
	struct mbuf	*m = mbc->chain;
	int32_t		offset = mbc->chain_offset;

	if (MBC_ROOM_FOR(mbc, sizeof (int32_t)) == 0) {
		/* Data will never be available */
		return (DECODE_NO_MORE_DATA);
	}
	while (offset >= m->m_len) {
		offset -= m->m_len;
		m = m->m_next;
	}
	if ((m->m_len - offset) >= sizeof (int32_t)) {
		*data = LE_IN32(m->m_data + offset);
		mbc->chain_offset += sizeof (int32_t);
	} else {
		tmp = (uint32_t)mbc_marshal_fetch_byte(mbc);
		tmp |= ((uint32_t)mbc_marshal_fetch_byte(mbc)) << 8;
		tmp |= ((uint32_t)mbc_marshal_fetch_byte(mbc)) << 16;
		tmp |= ((uint32_t)mbc_marshal_fetch_byte(mbc)) << 24;
		*data = tmp;
	}
	return (0);
}

uint64_t
qswap(uint64_t ll)
{
	uint64_t v;

	v = ll >> 32;
	v |= ll << 32;

	return (v);
}

int
mbc_marshal_get_odd_long_long(struct mbuf_chain *mbc, uint64_t *data)
{
	uint64_t  tmp;
	struct mbuf *m = mbc->chain;
	int32_t offset = mbc->chain_offset;

	if (MBC_ROOM_FOR(mbc, sizeof (int64_t)) == 0) {
		/* Data will never be available */
		return (DECODE_NO_MORE_DATA);
	}
	while (offset >= m->m_len) {
		offset -= m->m_len;
		m = m->m_next;
	}

	if ((m->m_len - offset) >= sizeof (int64_t)) {
		*data = qswap(LE_IN64(m->m_data + offset));
		mbc->chain_offset += sizeof (int64_t);
	} else {
		tmp = (uint64_t)mbc_marshal_fetch_byte(mbc) << 32;
		tmp |= (uint64_t)mbc_marshal_fetch_byte(mbc) << 40;
		tmp |= (uint64_t)mbc_marshal_fetch_byte(mbc) << 48;
		tmp |= (uint64_t)mbc_marshal_fetch_byte(mbc) << 56;
		tmp |= (uint64_t)mbc_marshal_fetch_byte(mbc);
		tmp |= (uint64_t)mbc_marshal_fetch_byte(mbc) << 8;
		tmp |= (uint64_t)mbc_marshal_fetch_byte(mbc) << 16;
		tmp |= (uint64_t)mbc_marshal_fetch_byte(mbc) << 24;

		*(uint64_t *)data = tmp;
	}
	return (0);
}

int
mbc_marshal_get_long_long(struct mbuf_chain *mbc, uint64_t *data)
{
	uint64_t tmp;
	struct mbuf *m = mbc->chain;
	int32_t		offset = mbc->chain_offset;

	if (MBC_ROOM_FOR(mbc, sizeof (int64_t)) == 0) {
		/* Data will never be available */
		return (DECODE_NO_MORE_DATA);
	}
	while (offset >= m->m_len) {
		offset -= m->m_len;
		m = m->m_next;
	}
	if ((m->m_len - offset) >= sizeof (int64_t)) {
		*data = LE_IN64(m->m_data + offset);
		mbc->chain_offset += sizeof (int64_t);
	} else {
		tmp = (uint32_t)mbc_marshal_fetch_byte(mbc);
		tmp |= ((uint64_t)mbc_marshal_fetch_byte(mbc)) << 8;
		tmp |= ((uint64_t)mbc_marshal_fetch_byte(mbc)) << 16;
		tmp |= ((uint64_t)mbc_marshal_fetch_byte(mbc)) << 24;
		tmp |= ((uint64_t)mbc_marshal_fetch_byte(mbc)) << 32;
		tmp |= ((uint64_t)mbc_marshal_fetch_byte(mbc)) << 40;
		tmp |= ((uint64_t)mbc_marshal_fetch_byte(mbc)) << 48;
		tmp |= ((uint64_t)mbc_marshal_fetch_byte(mbc)) << 56;
		*(uint64_t *)data = tmp;
	}
	return (0);
}

/*
 * mbc_marshal_get_ascii_string
 *
 * The ascii string in smb includes oem chars. Since the
 * system needs utf8 encodes unicode char, conversion is
 * required to convert the oem char to unicode and then
 * to encode the converted wchars to utf8 format.
 * Therefore, the **ascii returned will be in such format
 * instead of the real ASCII format.
 */
static int
mbc_marshal_get_ascii_string(
    struct smb_malloc_list	*ml,
    struct mbuf_chain		*mbc,
    unsigned char		**ascii,
    int				max_ascii)
{
	char		*rcvbuf;
	char		*ch;
	mts_wchar_t	*wtmpbuf;
	int		max;
	int		length = 0;
	unsigned int	cpid = oem_get_smb_cpid();

	max = MALLOC_QUANTUM;
	rcvbuf = smbsr_malloc(ml, max);

	if (max_ascii == 0)
		max_ascii = 0xffff;

	ch = rcvbuf;
	for (;;) {
		while (length < max) {
			if (max_ascii-- <= 0) {
				*ch++ = 0;
				goto multibyte_encode;
			}
			if (MBC_ROOM_FOR(mbc, sizeof (char)) == 0) {
				/* Data will never be available */
				return (DECODE_NO_MORE_DATA);
			}
			if ((*ch++ = mbc_marshal_fetch_byte(mbc)) == 0)
				goto multibyte_encode;
			length++;
		}
		max += MALLOC_QUANTUM;
		rcvbuf = smbsr_realloc(rcvbuf, max);
		ch = rcvbuf + length;
	}

multibyte_encode:
	/*
	 * UTF-8 encode the string for internal system use.
	 */
	length = strlen(rcvbuf) + 1;
	wtmpbuf = smbsr_malloc(ml, length*sizeof (mts_wchar_t));
	*ascii = smbsr_malloc(ml, length * MTS_MB_CHAR_MAX);

	if (oemstounicodes(wtmpbuf, rcvbuf, length, cpid) > 0)
		(void) mts_wcstombs((char *)*ascii, wtmpbuf,
		    length * MTS_MB_CHAR_MAX);
	else
		(void) mts_stombs((char *)*ascii, rcvbuf, length * 2);
	return (0);
}


int
mbc_marshal_get_unicode_string(struct smb_malloc_list *ml,
    struct mbuf_chain *mbc, unsigned char **ascii, int max_unicode)
{
	int		max;
	unsigned short	wchar;
	char		*ch;
	int		emitted;
	int		length = 0;

	if (max_unicode == 0)
		max_unicode = 0xffff;

	max = MALLOC_QUANTUM;
	*ascii = smbsr_malloc(ml, max);

	ch = (char *)*ascii;
	for (;;) {
		while ((length + MTS_MB_CHAR_MAX) < max) {
			if (max_unicode <= 0)
				goto done;
			max_unicode -= 2;

			if (mbc_marshal_get_short(mbc, &wchar) != 0)
				return (DECODE_NO_MORE_DATA);

			if (wchar == 0)	goto done;

			emitted = mts_wctomb(ch, wchar);
			length += emitted;
			ch += emitted;
		}
		max += MALLOC_QUANTUM;
		*ascii = smbsr_realloc(*ascii, max);
		ch = (char *)*ascii + length;
	}
done:	*ch = 0;
	return (0);
}


int /*ARGSUSED*/
mbc_marshal_get_mbufs(struct mbuf_chain *mbc, int32_t bytes, struct mbuf **m)
{
	if (MBC_ROOM_FOR(mbc, bytes) == 0) {
		/* Data will never be available */
		return (DECODE_NO_MORE_DATA);
	}
	return (0);
}

int
mbc_marshal_get_mbuf_chain(struct mbuf_chain *mbc,
    int32_t bytes, struct mbuf_chain *nmbc)
{
	int		rc;
	struct mbuf	*m;

	if (bytes == 0) {
		/* Get all the rest */
		bytes = mbc->max_bytes - mbc->chain_offset;
	}

	MBC_SETUP(nmbc, mbc->max_bytes);
	if ((rc = mbc_marshal_get_mbufs(mbc, bytes, &m)) != 0) {
		if (m)
			m_freem(m);
		return (rc);
	}
	nmbc->chain = m;
	while (m != 0) {
		bytes += m->m_len;
		m = m->m_next;
	}
	nmbc->max_bytes = bytes;
	return (0);
}


int
mbc_marshal_get_uio(struct mbuf_chain *mbc, struct uio *uio)
{
	int		i, offset;
	int32_t		bytes = uio->uio_resid;
	int32_t		remainder;
	struct iovec	*iov;
	struct mbuf	*m;

	/*
	 * The residual count is tested because in the case of write requests
	 * with no data (smbtorture RAW-WRITE test will generate that type of
	 * request) this function is called with a residual count of zero
	 * bytes.
	 */
	if (bytes) {
		iov = uio->uio_iov;
		uio->uio_segflg = UIO_SYSSPACE;

		if (MBC_ROOM_FOR(mbc, bytes) == 0) {
			/* Data will never be available */
			return (DECODE_NO_MORE_DATA);
		}

		m = mbc->chain;
		offset = mbc->chain_offset;
		while (offset >= m->m_len) {
			offset -= m->m_len;
			m = m->m_next;
			ASSERT((offset == 0) || (offset && m));
		}

		for (i = 0; (bytes > 0) && (i < uio->uio_iovcnt); i++) {
			iov[i].iov_base = &m->m_data[offset];
			remainder = m->m_len - offset;
			if (remainder >= bytes) {
				iov[i].iov_len = bytes;
				mbc->chain_offset += bytes;
				break;
			}
			iov[i].iov_len = remainder;
			mbc->chain_offset += remainder;
			bytes -= remainder;
			m = m->m_next;
			offset = 0;
		}
		if (i == uio->uio_iovcnt) {
			return (DECODE_NO_MORE_DATA);
		}
		uio->uio_iovcnt = i;
	}
	return (0);
}


int
mbc_marshal_get_SID(struct mbuf_chain *mbc, nt_sid_t *pSid)
{
	int	i;

	if (mbc_marshal_get_char(mbc, &pSid->Revision) != 0)
		return (DECODE_NO_MORE_DATA);

	if (mbc_marshal_get_char(mbc, &pSid->SubAuthCount) != 0)
		return (DECODE_NO_MORE_DATA);

	for (i = 0; i < 6; i++) {
		if (mbc_marshal_get_char(mbc,
		    &pSid->Authority[i]) != 0)
			return (DECODE_NO_MORE_DATA);
	}

	for (i = 0; i < pSid->SubAuthCount; i++) {
		if (mbc_marshal_get_long(mbc, &pSid->SubAuthority[i]) != 0)
			return (DECODE_NO_MORE_DATA);
	}
	return (0);
}

int
mbc_marshal_get_skip(struct mbuf_chain *mbc, unsigned int skip)
{
	if (MBC_ROOM_FOR(mbc, skip) == 0)
		return (DECODE_NO_MORE_DATA);
	mbc->chain_offset += skip;
	return (0);
}

int
mbc_marshal_get_alignment(struct mbuf_chain *mbc, unsigned int align)
{
	int32_t		delta = mbc->chain_offset % align;

	if (delta != 0) {
		align -= delta;
		return (mbc_marshal_get_skip(mbc, delta));
	}
	return (0);
}

/*
 * The mbuf chain passed in contains the data to be decoded.
 *
 * The format string provides a description of the parameters passed in as well
 * as an action to be taken by smb_mbc_decode().
 *
 *	\b	Restore the mbuf chain offset to its initial value.
 *
 *	%	Pointer to an SMB request structure (smb_request_t *). There
 *		should be only one of these in the string.
 *
 *	C	Pointer to an mbuf chain. Copy to that mbuf chain the number of
 *		bytes specified (number preceding C).
 *
 *	m	Pointer to an mbuf. Copy to that mbuf the number of bytes
 *		specified (number preceding m).
 *
 *	M	Read the 32 bit value at the current location of the mbuf chain
 *		and check if it matches the signature of an SMB request (SMBX).
 *
 *	b	Pointer to a buffer. Copy to that buffer the number of bytes
 *		specified (number preceding b).
 *
 *	c	Same as 'b'.
 *
 *	w	Pointer to a word (16bit value). Copy the next 16bit value into
 *		that location.
 *
 *	l	Pointer to a long (32bit value). Copy the next 32bit value into
 *		that location.
 *
 *	q	Pointer to a quad (64bit value). Copy the next 64bit value into
 *		that location.
 *
 *	Q	Same as above with a call to qswap().
 *
 *	B	Pointer to a vardata_block structure. That structure is used to
 *		retrieve data from the mbuf chain (an iovec type structure is
 *		embedded in a vardata_block).
 *
 *	D	Pointer to a vardata_block structure. That structure is used to
 *		retrieve data from the mbuf chain, however, two fields of the
 *		vardata_block structure (tag and len) are first initialized
 *		using the mbuf chain itself.
 *
 *	V	Same as 'D'.
 *
 *	L
 *
 *	A
 *
 *	P	Same as 'A'
 *
 *	S	Same as 'A'
 *
 *	u	Pointer to a string pointer. Allocate memory and retrieve the
 *		string at the current location in the mbuf chain. Store the
 *		address to the buffer allocated at the address specified by
 *		the pointer. In addition if an sr was passed and it indicates
 *		that the string is an unicode string, convert it.
 *
 *	s	Same as 'u' without convertion.
 *
 *	U	Same as 'u'. The string to retrieve is unicode.
 *
 *	R	Not used anymore.
 *
 *	y	Pointer to a 32bit value. Read the dos time at the current mbuf
 *		chain location, convert it to unix time and store it at the
 *		location indicated by the pointer.
 *
 *	Y	Same as 'y' bt the dos time coded in the mbuf chain is inverted.
 *
 *	.	Skip the number of bytes indicated by the number preceding '.'.
 *
 *	,	Same as '.' but take in account it is an unicode string.
 *
 * The parameters can be named in the format string. They have to appear between
 * parenthesis (indicating they should be ignored bu the decoder).
 */
int
smb_mbc_decode(struct mbuf_chain *mbc, char *fmt, va_list ap)
{
	unsigned char		c, cval;
	unsigned char		*cvalp;
	unsigned char		**cvalpp;
	unsigned short		*wvalp;
	unsigned int		*ivalp;
	uint32_t		*lvalp;
	uint64_t		*llvalp;
	struct vardata_block	*vdp;
	unsigned char		name[32];
	struct smb_request	*sr = NULL;
	uint32_t		lval;
	int			unicode = 0;
	int			repc;
	/*LINTED E_FUNC_SET_NOT_USED*/
	enum {EVEN, UNALIGNED, ODD} alignment;
	int32_t			saved_chain_offset = mbc->chain_offset;

	name[0] = 0;
	while ((c = *fmt++) != 0) {
		repc = 1;
		alignment = EVEN;

		if (c == ' ' || c == '\t') continue;
		if (c == '(') {
			char *nm = (char *)name;

			while (((c = *fmt++) != 0) && c != ')') {
				*nm++ = c;
			}
			*nm = 0;
			if (!c) fmt--;
			continue;
		}

		if (c == '{') {
			unsigned char	op[8];
			char *nm = (char *)op;

			while (((c = *fmt++) != 0) && c != '}') {
				*nm++ = c;
			}
			*nm = 0;
			if (!c) fmt--;
			if (strcmp((char *)op, "SID") == 0) {
				nt_sid_t *sidp;

				sidp = va_arg(ap, nt_sid_t *);
				(void) mbc_marshal_get_SID(mbc, sidp);
			}
			continue;
		}

		if ('0' <= c && c <= '9') {
			repc = 0;
			do {
				repc = repc * 10 + c - '0';
				c = *fmt++;
			} while ('0' <= c && c <= '9');
		} else if (c == '*') {
			ivalp = va_arg(ap, unsigned int *);
			repc = *(ivalp++);
			c = *fmt++;
		} else if (c == '!') {
			alignment = ODD;
			c = *fmt++;
		} else if (c == '^') {
			alignment = UNALIGNED;
			c = *fmt++;
		} else if (c == '#') {
			repc = va_arg(ap, int);
			c = *fmt++;
		}

		switch (c) {
		default:
			goto format_mismatch;

		case '\b':
			mbc->chain_offset = saved_chain_offset;
			break;

		case '%':
			sr = va_arg(ap, struct smb_request *);
			unicode = sr->smb_flg2 & SMB_FLAGS2_UNICODE;
			break;

		case 'C':	/* Mbuf_chain */
			if (mbc_marshal_get_mbuf_chain(mbc, repc,
			    va_arg(ap, struct mbuf_chain *)) != 0)
				goto underflow;
			break;

		case 'm':	/* struct_mbuf */
			if (mbc_marshal_get_mbufs(mbc, repc,
			    va_arg(ap, struct mbuf **)) != 0)
				goto underflow;
			break;

		case 'M':
			if (mbc_marshal_get_long(mbc, &lval) != 0) {
				/* Data will never be available */
				goto underflow;
			}
			if (lval != 0x424D53FF) /* 0xFF S M B */
				goto underflow;
			break;

		case 'b':
		case 'c':
			cvalp = va_arg(ap, unsigned char *);
			if (MBC_ROOM_FOR(mbc, repc) == 0) {
				/* Data will never be available */
				goto underflow;
			}
			while (repc-- > 0)
				*cvalp++ = mbc_marshal_fetch_byte(mbc);
			break;

		case 'w':
			wvalp = va_arg(ap, unsigned short *);
			while (repc-- > 0)
				if (mbc_marshal_get_short(mbc, wvalp++) != 0)
					goto underflow;
			break;

		case 'l':
			lvalp = va_arg(ap, uint32_t *);
			while (repc-- > 0)
				if (mbc_marshal_get_long(mbc, lvalp++) != 0)
					goto underflow;
			break;

		case 'q':
			llvalp = va_arg(ap, uint64_t *);
			while (repc-- > 0)
				if (mbc_marshal_get_long_long(
				    mbc, llvalp++) != 0)
					goto underflow;
			break;

		case 'Q':
			llvalp = va_arg(ap, uint64_t *);
			while (repc-- > 0)
				if (mbc_marshal_get_odd_long_long(
				    mbc, llvalp++) != 0)
					goto underflow;
			break;

		case 'B':
			vdp = va_arg(ap, struct vardata_block *);
			vdp->tag = 0;

			/*LINTED E_ASSIGN_NARROW_CONV (BYTE)*/
			vdp->len = repc;
			vdp->uio.uio_iov = &vdp->iovec[0];
			vdp->uio.uio_iovcnt = MAX_IOVEC;
			vdp->uio.uio_resid = repc;
			if (mbc_marshal_get_uio(mbc, &vdp->uio) != 0)
				goto underflow;
			break;

		case 'D': case 'V':
			vdp = va_arg(ap, struct vardata_block *);
			if (mbc_marshal_get_char(mbc, &vdp->tag) != 0)
				goto underflow;
			if (mbc_marshal_get_short(mbc, &vdp->len) != 0)
				goto underflow;
			vdp->uio.uio_iov = &vdp->iovec[0];
			vdp->uio.uio_iovcnt = MAX_IOVEC;
			vdp->uio.uio_resid = vdp->len;
			if (vdp->len != 0) {
				if (mbc_marshal_get_uio(mbc, &vdp->uio) != 0)
					goto underflow;
			}
			break;

		case 'L':
			if (mbc_marshal_get_char(mbc, &cval) != 0)
				goto underflow;
			if (cval != 2)
				goto format_mismatch;
			goto ascii_conversion;

		case 'A': case 'P': case 'S':
			if (mbc_marshal_get_char(mbc, &cval) != 0)
				goto underflow;
			if (((c == 'A' || c == 'S') && cval != 4) ||
			    (c == 'L' && cval != 2) || (c == 'P' && cval != 3))
				goto format_mismatch;
			/* FALLTHROUGH */

		case 'u': /* Convert from unicode if flags are set */
			if (unicode)
				goto unicode_translation;
			/* FALLTHROUGH */

		case 's':
ascii_conversion:
			ASSERT(sr != NULL);
			cvalpp = va_arg(ap, unsigned char **);
			if (repc <= 1)
				repc = 0;
			if (mbc_marshal_get_ascii_string(&sr->request_storage,
			    mbc, cvalpp, repc) != 0)
				goto underflow;
			break;

		case 'U': /* Convert from unicode */
unicode_translation:
			ASSERT(sr != 0);
			cvalpp = va_arg(ap, unsigned char **);
			if (repc <= 1)
				repc = 0;
			if (mbc->chain_offset & 1)
				mbc->chain_offset++;
			if (mbc_marshal_get_unicode_string(&sr->request_storage,
			    mbc, cvalpp, repc) != 0)
				goto underflow;
			break;

		case 'R':
			/*
			 * This was used to decode RPC format unicode strings
			 * prior to having a DCE RPC support. It is no longer
			 * required.
			 */
			ASSERT(0);
			break;

		case 'Y': /* dos time to unix time tt/dd */
			lvalp = va_arg(ap, uint32_t *);
			while (repc-- > 0) {
				short	d, t;

				if (mbc_marshal_get_short(mbc,
				    (unsigned short *)&t) != 0)
					goto underflow;
				if (mbc_marshal_get_short(mbc,
				    (unsigned short *)&d) != 0)
					goto underflow;
				*lvalp++ = dosfs_dos_to_ux_time(d, t);
			}
			break;

		case 'y': /* dos time to unix time dd/tt */
			lvalp = va_arg(ap, uint32_t *);
			while (repc-- > 0) {
				short	d, t;

				if (mbc_marshal_get_short(mbc,
				    (unsigned short *)&d) != 0)
					goto underflow;
				if (mbc_marshal_get_short(mbc,
				    (unsigned short *)&t) != 0)
					goto underflow;
				*lvalp++ = dosfs_dos_to_ux_time(d, t);
			}
			break;

		case ',':
			if (unicode)
				repc *= 2;
			/* FALLTHROUGH */

		case '.':
			if (mbc_marshal_get_skip(mbc, repc) != 0)
				goto underflow;
			break;
		}
	}
	return (0);


format_mismatch:
	return (-1);

underflow:
	return (-1);
}


int
smb_decode_mbc(struct  mbuf_chain *mbc, char *fmt, ...)
{
	int xx;
	va_list ap;

	va_start(ap, fmt);
	xx = smb_mbc_decode(mbc, fmt, ap);
	va_end(ap);
	return (xx);
}


int
smb_decode_buf(unsigned char *buf, int n_buf, char *fmt, ...)
{
	int			rc;
	struct mbuf_chain	mbc;
	va_list ap;

	va_start(ap, fmt);

	MBC_ATTACH_BUF(&mbc, buf, n_buf);
	rc = smb_mbc_decode(&mbc, fmt, ap);
	m_freem(mbc.chain);
	va_end(ap);
	return (rc);
}

/*
 * The mbuf chain passed in will receive the encoded data.
 *
 * The format string provides a description of the parameters passed in as well
 * as an action to be taken by smb_mbc_encode().
 *
 *	\b	Restore the mbuf chain offset to its initial value.
 *
 *	%	Pointer to an SMB request structure (smb_request_t *). There
 *		should be only one of these in the string. If an sr in present
 *		it will be used to determine if unicode conversion should be
 *		applied to the strings.
 *
 *	C	Pointer to an mbuf chain. Copy that mbuf chain into the
 *		destination mbuf chain.
 *
 *	D	Pointer to a vardata_block structure. Copy the data described
 *		by that structure into the mbuf chain. The tag field is hard
 *		coded to '1'.
 *
 *	M	Write the SMB request signature ('SMBX') into the mbuf chain.
 *
 *	T	Pointer to a timestruc_t. Convert the content of the structure
 *		into NT time and store the result of the conversion in the
 *		mbuf chain.
 *
 *	V	Same as 'D' but the tag field is hard coded to '5'.
 *
 *	b	Byte. Store the byte or the nymber of bytes specified into the
 *		the mbuf chain. A format string like this "2b" would require 2
 *		bytes to be passed in.
 *
 *	m	Pointer to an mbuf. Copy the contents of the mbuf into the mbuf
 *		chain.
 *
 *	c	Pointer to a buffer. Copy the buffer into the mbuf chain. The
 *		size of the buffer is indicated by the number preceding 'c'.
 *
 *	w	Word (16bit value). Store the word or the number of words
 *              specified into the the mbuf chain. A format string like this
 *		"2w" would require 2 words to be passed in.
 *
 *	l	Long (32bit value). Store the long or the number of longs
 *		specified into the the mbuf chain. A format string like this
 *		"2l" would require 2 longs to be passed in.
 *
 *	q	Quad (64bit value). Store the quad or the number of quads
 *		specified into the the mbuf chain. A format string like this
 *		"2q" would require 2 quads to be passed in.
 *
 *	L	Pointer to a string. Store the string passed in into the mbuf
 *		chain preceded with a tag value of '2'.
 *
 *	S	Pointer to a string. Store the string passed in into the mbuf
 *		chain preceded with a tag value of '4'. Applied a unicode
 *		conversion is appropriate.
 *
 *	A	Same as 'S'
 *
 *	P	Pointer to a string. Store the string passed in into the mbuf
 *		chain preceded with a tag value of '5'. Applied a unicode
 *		conversion is appropriate.
 *
 *	u	Pointer to a string. Store the string passed in into the mbuf
 *		chain. Applied a unicode conversion is appropriate.
 *
 *	s	Pointer to a string. Store the string passed in into the mbuf
 *		chain.
 *
 *	Y	Date/Time.  Store the Date/Time or the number of Date/Time(s)
 *		specified into the the mbuf chain. A format string like this
 *		"2Y" would require 2 Date/Time values. The Date/Time is
 *		converted to DOS before storing.
 *
 *	y	Same as 'Y'. The order of Date and Time is reversed.
 *
 *	,	Character. Store the character or number of character specified
 *		into the mbuf chain.  A format string like this "2c" would
 *		require 2 characters to be passed in. A unicode conversion is
 *		applied if appropriate.
 *
 *	.	Same as '`' without unicode conversion.
 *
 *	U	Align the offset of the mbuf chain on a 16bit boundary.
 *
 *	Z	Unicode string. Store the unicode string into the mbuf chain
 *		without alignment considerations.
 *
 * The parameters can be named in the format string. They have to appear between
 * parenthesis (indicating they should be ignored bu the encoder).
 */
int
smb_mbc_encode(struct mbuf_chain *mbc, char *fmt, va_list ap)
{
	unsigned char		name[32];
	unsigned char		cval, c;
	unsigned short		wval;
	uint64_t	llval;
	uint32_t		lval;
	unsigned int		tag;
	unsigned char		*cvalp;
	unsigned int		*ivalp;
	timestruc_t		*tvp;
	int64_t			nt_time;
	struct vardata_block	*vdp;
	struct smb_request	*sr = 0;
	int			unicode = 0;
	int			repc = 1;
	/*LINTED E_FUNC_SET_NOT_USED*/
	enum {EVEN, UNALIGNED, ODD} alignment;

	while ((c = *fmt++) != 0) {
		name[0] = 0;
		repc = 1;
		alignment = EVEN;
		if (c == ' ' || c == '\t') continue;
		if (c == '(') {
			char *nm = (char *)name;

			while (((c = *fmt++) != 0) && c != ')') {
				*nm++ = c;
			}
			*nm = 0;
			if (!c) fmt--;
			continue;
		}

		if (c == '{') {
			unsigned char	op[8];
			char *nm = (char *)op;

			while (((c = *fmt++) != 0) && c != '}') {
				*nm++ = c;
			}
			*nm = 0;
			if (!c) fmt--;
			if (strcmp((char *)op, "SID") == 0) {
				nt_sid_t *sidp;

				sidp = va_arg(ap, nt_sid_t *);
				(void) mbc_marshal_put_SID(mbc, sidp);
			}
			continue;
		}

		if ('0' <= c && c <= '9') {
			repc = 0;
			do {
				repc = repc * 10 + c - '0';
				c = *fmt++;
			} while ('0' <= c && c <= '9');
		} else if (c == '*') {
			ivalp = va_arg(ap, unsigned int *);

			repc = *ivalp;
			c = *fmt++;
		} else if (c == '!') {
			alignment = ODD;
			c = *fmt++;
		} else if (c == '^') {
			alignment = UNALIGNED;
			c = *fmt++;
		} else if (c == '#') {
			repc = va_arg(ap, int);
			c = *fmt++;
		}

		switch (c) {
		default:
			goto format_mismatch;

		case '%':
			sr = va_arg(ap, struct smb_request *);
			unicode = sr->smb_flg2 & SMB_FLAGS2_UNICODE;
			break;

		case 'C':	/* Mbuf_chain */
			if (mbc_marshal_put_mbuf_chain(mbc,
			    va_arg(ap, struct mbuf_chain *)) != 0)
				return (DECODE_NO_MORE_DATA);
			break;

		case 'D':
			vdp = va_arg(ap, struct vardata_block *);

			if (mbc_marshal_put_char(mbc, 1) != 0)
				return (DECODE_NO_MORE_DATA);
			if (mbc_marshal_put_short(mbc, vdp->len) != 0)
				return (DECODE_NO_MORE_DATA);
			if (mbc_marshal_put_uio(mbc, &vdp->uio) != 0)
				return (DECODE_NO_MORE_DATA);
			break;

		case 'M':
			/* 0xFF S M B */
			if (mbc_marshal_put_long(mbc, 0x424D53FF))
				return (DECODE_NO_MORE_DATA);
			break;

		case 'T':
			tvp = va_arg(ap, timestruc_t *);
			nt_time = unix_to_nt_time(tvp);
			if (mbc_marshal_put_long_long(mbc, nt_time) != 0)
				return (DECODE_NO_MORE_DATA);
			break;

		case 'V':
			vdp = va_arg(ap, struct vardata_block *);

			if (mbc_marshal_put_char(mbc, 5) != 0)
				return (DECODE_NO_MORE_DATA);
			if (mbc_marshal_put_short(mbc, vdp->len) != 0)
				return (DECODE_NO_MORE_DATA);
			if (mbc_marshal_put_uio(mbc, &vdp->uio) != 0)
				return (DECODE_NO_MORE_DATA);
			break;

		case 'b':
			while (repc-- > 0) {
				cval = va_arg(ap, int);
				if (mbc_marshal_put_char(mbc, cval) != 0)
					return (DECODE_NO_MORE_DATA);
			}
			break;

		case 'm':	/* struct_mbuf */
			if (mbc_marshal_put_mbufs(mbc,
			    va_arg(ap, struct mbuf *)) != 0)
				return (DECODE_NO_MORE_DATA);
			break;

		case 'c':
			cvalp = va_arg(ap, unsigned char *);
			while (repc-- > 0) {
				if (mbc_marshal_put_char(mbc,
				    *cvalp++) != 0)
					return (DECODE_NO_MORE_DATA);
			}
			break;

		case 'w':
			while (repc-- > 0) {
				wval = va_arg(ap, int);
				if (mbc_marshal_put_short(mbc, wval) != 0)
					return (DECODE_NO_MORE_DATA);
			}
			break;

		case 'l':
			while (repc-- > 0) {
				lval = va_arg(ap, uint32_t);
				if (mbc_marshal_put_long(mbc, lval) != 0)
					return (DECODE_NO_MORE_DATA);
			}
			break;

		case 'q':
			while (repc-- > 0) {
				llval = va_arg(ap, uint64_t);
				if (mbc_marshal_put_long_long(mbc, llval) != 0)
					return (DECODE_NO_MORE_DATA);
			}
			break;


		case 'L':
			tag = 2;
			goto ascii_conversion;

		case 'S':
		case 'A': tag = 4; goto tagged_str;
		case 'P': tag = 3; goto tagged_str;
		tagged_str:
			if (mbc_marshal_put_char(mbc, tag) != 0)
				return (DECODE_NO_MORE_DATA);
			/* FALLTHROUGH */

		case 'u':	/* Convert from unicode if flags are set */
			if (unicode)
				goto unicode_translation;
			/* FALLTHROUGH */

		case 's':	/* ASCII/multibyte string */
ascii_conversion:	cvalp = va_arg(ap, unsigned char *);
			if (mbc_marshal_put_ascii_string(mbc,
			    (char *)cvalp, repc) != 0)
				return (DECODE_NO_MORE_DATA);
			break;

		case 'Y':		/* int32_t, encode dos date/time */
			while (repc-- > 0) {
				unsigned short	d, t;

				lval = va_arg(ap, uint32_t);
				(void) dosfs_ux_to_dos_time(lval,
				    (short *)&d, (short *)&t);
				if (mbc_marshal_put_short(mbc, t) != 0)
					return (DECODE_NO_MORE_DATA);
				if (mbc_marshal_put_short(mbc, d) != 0)
					return (DECODE_NO_MORE_DATA);
			}
			break;

		case 'y':		/* int32_t, encode dos date/time */
			while (repc-- > 0) {
				unsigned short	d, t;

				lval = va_arg(ap, uint32_t);
				(void) dosfs_ux_to_dos_time(lval,
				    (short *)&d, (short *)&t);
				if (mbc_marshal_put_short(mbc, d) != 0)
					return (DECODE_NO_MORE_DATA);
				if (mbc_marshal_put_short(mbc, t) != 0)
					return (DECODE_NO_MORE_DATA);
			}
			break;

		case ',':
			if (unicode)
				repc *= 2;
			/* FALLTHROUGH */

		case '.':
			while (repc-- > 0)
				if (mbc_marshal_put_char(mbc, 0) != 0)
					return (DECODE_NO_MORE_DATA);
			break;

		case 'R':
			/*
			 * This was used to encode RPC format unicode strings
			 * prior to having a DCE RPC support. It is no longer
			 * required.
			 */
			ASSERT(0);
			break;

		case 'U': /* Convert to unicode, align to word boundary */
unicode_translation:
			if (mbc->chain_offset & 1)
				mbc->chain_offset++;
			/* FALLTHROUGH */

		case 'Z': /* Convert to unicode, no alignment adjustment */
			cvalp = va_arg(ap, unsigned char *);
			if (mbc_marshal_put_unicode_string(mbc,
			    (char *)cvalp, repc) != 0)
				return (DECODE_NO_MORE_DATA);
			break;
		}
	}
	return (0);

format_mismatch:
	return (-1);
}


int
smb_encode_mbc(struct mbuf_chain *mbc, char *fmt, ...)
{
	int rc;
	va_list ap;

	va_start(ap, fmt);
	rc = smb_mbc_encode(mbc, fmt, ap);
	va_end(ap);
	return (rc);
}


int
smb_encode_buf(unsigned char *buf, int n_buf, char *fmt, ...)
{
	int			rc;
	struct mbuf_chain	mbc;
	va_list ap;

	va_start(ap, fmt);

	MBC_ATTACH_BUF(&mbc, buf, n_buf);
	rc = smb_mbc_encode(&mbc, fmt, ap);
	m_freem(mbc.chain);
	va_end(ap);
	return (rc);
}


int
smb_decode_vwv(struct smb_request *sr, char *fmt, ...)
{
	int rc;
	va_list ap;

	va_start(ap, fmt);
	rc = smb_mbc_decode(&sr->smb_vwv, fmt, ap);
	va_end(ap);
	return (rc);
}


int
smb_decode_data(struct smb_request *sr, char *fmt, ...)
{
	if (smb_decode_mbc(&sr->smb_data, fmt, (int *)(&fmt + 1)) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}
	return (0);
}


void
smb_encode_header(struct smb_request *sr, int wct,
    int bcc, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (smb_mbc_encode(&sr->reply, fmt, ap) != 0) {
		va_end(ap);
		smbsr_encode_error(sr);
		/* NOTREACHED */
	}
	va_end(ap);
	/*LINTED E_ASSIGN_NARROW_CONV*/
	sr->smb_wct = wct;
	/*LINTED E_ASSIGN_NARROW_CONV*/
	sr->smb_bcc = bcc;
}

int
smb_peek_mbc(struct mbuf_chain *mbc, int offset, char *fmt, ...)
{
	int xx;
	struct mbuf_chain	tmp;
	va_list ap;

	va_start(ap, fmt);

	(void) MBC_SHADOW_CHAIN(&tmp, mbc, offset, mbc->max_bytes - offset);
	xx = smb_mbc_decode(&tmp, fmt, ap);
	va_end(ap);
	return (xx);
}


int
smb_poke_mbc(struct mbuf_chain *mbc, int offset, char *fmt, ...)
{
	int xx;
	struct mbuf_chain	tmp;
	va_list ap;

	(void) MBC_SHADOW_CHAIN(&tmp, mbc, offset, mbc->max_bytes - offset);
	va_start(ap, fmt);
	xx = smb_mbc_encode(&tmp, fmt, ap);
	va_end(ap);
	return (xx);
}
