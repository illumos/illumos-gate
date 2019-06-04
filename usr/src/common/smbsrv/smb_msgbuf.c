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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Msgbuf buffer management implementation. The smb_msgbuf interface is
 * typically used to encode or decode SMB data using sprintf/scanf
 * style operations. It contains special handling for the SMB header.
 * It can also be used for general purpose encoding and decoding.
 */

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/byteorder.h>
#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#else
#include <sys/sunddi.h>
#include <sys/kmem.h>
#endif
#include <smbsrv/string.h>
#include <smbsrv/msgbuf.h>
#include <smbsrv/smb.h>

static int buf_decode(smb_msgbuf_t *, char *, va_list ap);
static int buf_encode(smb_msgbuf_t *, char *, va_list ap);
static void *smb_msgbuf_malloc(smb_msgbuf_t *, size_t);
static int smb_msgbuf_chkerc(char *text, int erc);

static int msgbuf_get_oem_string(smb_msgbuf_t *, char **, int);
static int msgbuf_get_unicode_string(smb_msgbuf_t *, char **, int);
static int msgbuf_put_oem_string(smb_msgbuf_t *, char *, int);
static int msgbuf_put_unicode_string(smb_msgbuf_t *, char *, int);


/*
 * Returns the offset or number of bytes used within the buffer.
 */
size_t
smb_msgbuf_used(smb_msgbuf_t *mb)
{
	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (mb->scan - mb->base);
}

/*
 * Returns the actual buffer size.
 */
size_t
smb_msgbuf_size(smb_msgbuf_t *mb)
{
	return (mb->max);
}

uint8_t *
smb_msgbuf_base(smb_msgbuf_t *mb)
{
	return (mb->base);
}

/*
 * Ensure that the scan is aligned on a word (16-bit) boundary.
 */
void
smb_msgbuf_word_align(smb_msgbuf_t *mb)
{
	mb->scan = (uint8_t *)((uintptr_t)(mb->scan + 1) & ~1);
}

/*
 * Ensure that the scan is aligned on a dword (32-bit) boundary.
 */
void
smb_msgbuf_dword_align(smb_msgbuf_t *mb)
{
	mb->scan = (uint8_t *)((uintptr_t)(mb->scan + 3) & ~3);
}

/*
 * Checks whether or not the buffer has space for the amount of data
 * specified. Returns 1 if there is space, otherwise returns 0.
 */
int
smb_msgbuf_has_space(smb_msgbuf_t *mb, size_t size)
{
	if (size > mb->max || (mb->scan + size) > mb->end)
		return (0);

	return (1);
}

/*
 * Set flags the smb_msgbuf.
 */
void
smb_msgbuf_fset(smb_msgbuf_t *mb, uint32_t flags)
{
	mb->flags |= flags;
}

/*
 * Clear flags the smb_msgbuf.
 */
void
smb_msgbuf_fclear(smb_msgbuf_t *mb, uint32_t flags)
{
	mb->flags &= ~flags;
}

/*
 * smb_msgbuf_init
 *
 * Initialize a smb_msgbuf_t structure based on the buffer and size
 * specified. Both scan and base initially point to the beginning
 * of the buffer and end points to the limit of the buffer. As
 * data is added scan should be incremented to point to the next
 * offset at which data will be written. Max and count are set
 * to the actual buffer size.
 */
void
smb_msgbuf_init(smb_msgbuf_t *mb, uint8_t *buf, size_t size, uint32_t flags)
{
	mb->scan = mb->base = buf;
	mb->max = mb->count = size;
	mb->end = &buf[size];
	mb->flags = flags;
	mb->mlist.next = 0;
}


/*
 * smb_msgbuf_term
 *
 * Destruct a smb_msgbuf_t. Free any memory hanging off the mlist.
 */
void
smb_msgbuf_term(smb_msgbuf_t *mb)
{
	smb_msgbuf_mlist_t *item = mb->mlist.next;
	smb_msgbuf_mlist_t *tmp;

	while (item) {
		tmp = item;
		item = item->next;
#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
		free(tmp);
#else
		kmem_free(tmp, tmp->size);
#endif
	}
}


/*
 * smb_msgbuf_decode
 *
 * Decode a smb_msgbuf buffer as indicated by the format string into
 * the variable arg list. This is similar to a scanf operation.
 *
 * On success, returns the number of bytes decoded. Otherwise
 * returns a -ve error code.
 */
int
smb_msgbuf_decode(smb_msgbuf_t *mb, char *fmt, ...)
{
	int rc;
	uint8_t *orig_scan;
	va_list ap;

	va_start(ap, fmt);
	orig_scan = mb->scan;
	rc = buf_decode(mb, fmt, ap);
	va_end(ap);

	if (rc != SMB_MSGBUF_SUCCESS) {
		(void) smb_msgbuf_chkerc("smb_msgbuf_decode", rc);
		mb->scan = orig_scan;
		return (rc);
	}

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (mb->scan - orig_scan);
}


/*
 * buf_decode
 *
 * Private decode function, where the real work of decoding the smb_msgbuf
 * is done. This function should only be called via smb_msgbuf_decode to
 * ensure correct behaviour and error handling.
 */
static int
buf_decode(smb_msgbuf_t *mb, char *fmt, va_list ap)
{
	uint8_t c;
	uint8_t *bvalp;
	uint16_t *wvalp;
	uint32_t *lvalp;
	uint64_t *llvalp;
	char **cvalpp;
	boolean_t repc_specified;
	int repc;
	int rc;

	while ((c = *fmt++) != 0) {
		repc_specified = B_FALSE;
		repc = 1;

		if (c == ' ' || c == '\t')
			continue;

		if (c == '(') {
			while (((c = *fmt++) != 0) && c != ')')
				;

			if (!c)
				return (SMB_MSGBUF_SUCCESS);

			continue;
		}

		if ('0' <= c && c <= '9') {
			repc = 0;
			do {
				repc = repc * 10 + c - '0';
				c = *fmt++;
			} while ('0' <= c && c <= '9');
			repc_specified = B_TRUE;
		} else if (c == '#') {
			repc = va_arg(ap, int);
			c = *fmt++;
			repc_specified = B_TRUE;
		}

		switch (c) {
		case '.':
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			mb->scan += repc;
			break;

		case 'c': /* get char */
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			bvalp = va_arg(ap, uint8_t *);
			bcopy(mb->scan, bvalp, repc);
			mb->scan += repc;
			break;

		case 'b': /* get byte */
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			bvalp = va_arg(ap, uint8_t *);
			while (repc-- > 0) {
				*bvalp++ = *mb->scan++;
			}
			break;

		case 'w': /* get word */
			rc = smb_msgbuf_has_space(mb, repc * sizeof (uint16_t));
			if (rc == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			wvalp = va_arg(ap, uint16_t *);
			while (repc-- > 0) {
				*wvalp++ = LE_IN16(mb->scan);
				mb->scan += sizeof (uint16_t);
			}
			break;

		case 'l': /* get long */
			rc = smb_msgbuf_has_space(mb, repc * sizeof (int32_t));
			if (rc == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			lvalp = va_arg(ap, uint32_t *);
			while (repc-- > 0) {
				*lvalp++ = LE_IN32(mb->scan);
				mb->scan += sizeof (int32_t);
			}
			break;

		case 'q': /* get quad */
			rc = smb_msgbuf_has_space(mb, repc * sizeof (int64_t));
			if (rc == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			llvalp = va_arg(ap, uint64_t *);
			while (repc-- > 0) {
				*llvalp++ = LE_IN64(mb->scan);
				mb->scan += sizeof (int64_t);
			}
			break;

		case 'u': /* Convert from unicode if flags are set */
			if (mb->flags & SMB_MSGBUF_UNICODE)
				goto unicode_translation;
			/*FALLTHROUGH*/

		case 's': /* get OEM string */
			cvalpp = va_arg(ap, char **);
			if (!repc_specified)
				repc = 0;
			rc = msgbuf_get_oem_string(mb, cvalpp, repc);
			if (rc != 0)
				return (rc);
			break;

		case 'U': /* get UTF-16 string */
unicode_translation:
			cvalpp = va_arg(ap, char **);
			if (!repc_specified)
				repc = 0;
			rc = msgbuf_get_unicode_string(mb, cvalpp, repc);
			if (rc != 0)
				return (rc);
			break;

		case 'M':
			if (smb_msgbuf_has_space(mb, 4) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			if (mb->scan[0] != 0xFF ||
			    mb->scan[1] != 'S' ||
			    mb->scan[2] != 'M' ||
			    mb->scan[3] != 'B') {
				return (SMB_MSGBUF_INVALID_HEADER);
			}
			mb->scan += 4;
			break;

		default:
			return (SMB_MSGBUF_INVALID_FORMAT);
		}
	}

	return (SMB_MSGBUF_SUCCESS);
}

/*
 * msgbuf_get_oem_string
 *
 * Decode an OEM string, returning its UTF-8 form in strpp,
 * allocated using smb_msgbuf_malloc (automatically freed).
 * If max_bytes != 0, consume at most max_bytes of the mb.
 * See also: mbc_marshal_get_oem_string
 */
static int
msgbuf_get_oem_string(smb_msgbuf_t *mb, char **strpp, int max_bytes)
{
	char		*mbs;
	uint8_t		*oembuf = NULL;
	int		oemlen;		// len of OEM string, w/o null
	int		datalen;	// OtW data len
	int		mbsmax;		// max len of ret str
	int		rlen;

	if (max_bytes == 0)
		max_bytes = 0xffff;

	/*
	 * Determine the OtW data length and OEM string length
	 * Note: oemlen is the string length (w/o null) and
	 * datalen is how much we move mb->scan
	 */
	datalen = 0;
	oemlen = 0;
	for (;;) {
		if (datalen >= max_bytes)
			break;
		/* in-line smb_msgbuf_has_space */
		if ((mb->scan + datalen) >= mb->end)
			return (SMB_MSGBUF_UNDERFLOW);
		datalen++;
		if (mb->scan[datalen - 1] == 0)
			break;
		oemlen++;
	}

	/*
	 * Get datalen bytes into a temp buffer
	 * sized with room to add a null.
	 * Free oembuf in smb_msgbuf_term
	 */
	oembuf = smb_msgbuf_malloc(mb, datalen + 1);
	if (oembuf == NULL)
		return (SMB_MSGBUF_UNDERFLOW);
	bcopy(mb->scan, oembuf, datalen);
	mb->scan += datalen;
	oembuf[oemlen] = '\0';

	/*
	 * Get the buffer we'll return and convert to UTF-8.
	 * May take as much as double the space.
	 */
	mbsmax = oemlen * 2;
	mbs = smb_msgbuf_malloc(mb, mbsmax + 1);
	if (mbs == NULL)
		return (SMB_MSGBUF_UNDERFLOW);
	rlen = smb_oemtombs(mbs, oembuf, mbsmax);
	if (rlen < 0)
		return (SMB_MSGBUF_UNDERFLOW);
	if (rlen > mbsmax)
		rlen = mbsmax;
	mbs[rlen] = '\0';
	*strpp = mbs;
	return (0);
}

/*
 * msgbuf_get_unicode_string
 *
 * Decode a UTF-16 string, returning its UTF-8 form in strpp,
 * allocated using smb_msgbuf_malloc (automatically freed).
 * If max_bytes != 0, consume at most max_bytes of the mb.
 * See also: mbc_marshal_get_unicode_string
 */
static int
msgbuf_get_unicode_string(smb_msgbuf_t *mb, char **strpp, int max_bytes)
{
	char		*mbs;
	uint16_t	*wcsbuf = NULL;
	int		wcslen;		// wchar count
	int		datalen;	// OtW data len
	size_t		mbsmax;		// max len of ret str
	size_t		rlen;

	if (max_bytes == 0)
		max_bytes = 0xffff;

	/*
	 * Unicode strings are always word aligned.
	 */
	smb_msgbuf_word_align(mb);

	/*
	 * Determine the OtW data length and (WC) string length
	 * Note: wcslen counts 16-bit wide_chars (w/o null),
	 * and datalen is how much we move mb->scan
	 */
	datalen = 0;
	wcslen = 0;
	for (;;) {
		if (datalen >= max_bytes)
			break;
		/* in-line smb_msgbuf_has_space */
		if ((mb->scan + datalen) >= mb->end)
			return (SMB_MSGBUF_UNDERFLOW);
		datalen += 2;
		if (mb->scan[datalen - 2] == 0 &&
		    mb->scan[datalen - 1] == 0)
			break;
		wcslen++;
	}

	/*
	 * Get datalen bytes into a temp buffer
	 * sized with room to add a (WC) null.
	 * Note: wcsbuf has little-endian order
	 */
	wcsbuf = smb_msgbuf_malloc(mb, datalen + 2);
	if (wcsbuf == NULL)
		return (SMB_MSGBUF_UNDERFLOW);
	bcopy(mb->scan, wcsbuf, datalen);
	mb->scan += datalen;
	wcsbuf[wcslen] = 0;

	/*
	 * Get the buffer we'll return and convert to UTF-8.
	 * May take as much 4X number of wide chars.
	 */
	mbsmax = wcslen * MTS_MB_CUR_MAX;
	mbs = smb_msgbuf_malloc(mb, mbsmax + 1);
	if (mbs == NULL)
		return (SMB_MSGBUF_UNDERFLOW);
	rlen = smb_wcstombs(mbs, wcsbuf, mbsmax);
	if (rlen == (size_t)-1)
		return (SMB_MSGBUF_UNDERFLOW);
	if (rlen > mbsmax)
		rlen = mbsmax;
	mbs[rlen] = '\0';
	*strpp = mbs;
	return (0);
}

/*
 * smb_msgbuf_encode
 *
 * Encode a smb_msgbuf buffer as indicated by the format string using
 * the variable arg list. This is similar to a sprintf operation.
 *
 * On success, returns the number of bytes encoded. Otherwise
 * returns a -ve error code.
 */
int
smb_msgbuf_encode(smb_msgbuf_t *mb, char *fmt, ...)
{
	int rc;
	uint8_t *orig_scan;
	va_list ap;

	va_start(ap, fmt);
	orig_scan = mb->scan;
	rc = buf_encode(mb, fmt, ap);
	va_end(ap);

	if (rc != SMB_MSGBUF_SUCCESS) {
		(void) smb_msgbuf_chkerc("smb_msgbuf_encode", rc);
		mb->scan = orig_scan;
		return (rc);
	}

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (mb->scan - orig_scan);
}


/*
 * buf_encode
 *
 * Private encode function, where the real work of encoding the smb_msgbuf
 * is done. This function should only be called via smb_msgbuf_encode to
 * ensure correct behaviour and error handling.
 */
static int
buf_encode(smb_msgbuf_t *mb, char *fmt, va_list ap)
{
	uint8_t cval;
	uint16_t wval;
	uint32_t lval;
	uint64_t llval;
	uint8_t *bvalp;
	char *cvalp;
	uint8_t c;
	boolean_t repc_specified;
	int repc;
	int rc;

	while ((c = *fmt++) != 0) {
		repc_specified = B_FALSE;
		repc = 1;

		if (c == ' ' || c == '\t')
			continue;

		if (c == '(') {
			while (((c = *fmt++) != 0) && c != ')')
				;

			if (!c)
				return (SMB_MSGBUF_SUCCESS);

			continue;
		}

		if ('0' <= c && c <= '9') {
			repc = 0;
			do {
				repc = repc * 10 + c - '0';
				c = *fmt++;
			} while ('0' <= c && c <= '9');
			repc_specified = B_TRUE;
		} else if (c == '#') {
			repc = va_arg(ap, int);
			c = *fmt++;
			repc_specified = B_TRUE;
		}

		switch (c) {
		case '.':
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_OVERFLOW);

			while (repc-- > 0)
				*mb->scan++ = 0;
			break;

		case 'c': /* put char */
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_OVERFLOW);

			bvalp = va_arg(ap, uint8_t *);
			bcopy(bvalp, mb->scan, repc);
			mb->scan += repc;
			break;

		case 'b': /* put byte */
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_OVERFLOW);

			while (repc-- > 0) {
				cval = va_arg(ap, int);
				*mb->scan++ = cval;
			}
			break;

		case 'w': /* put word */
			rc = smb_msgbuf_has_space(mb, repc * sizeof (uint16_t));
			if (rc == 0)
				return (SMB_MSGBUF_OVERFLOW);

			while (repc-- > 0) {
				wval = va_arg(ap, int);
				LE_OUT16(mb->scan, wval);
				mb->scan += sizeof (uint16_t);
			}
			break;

		case 'l': /* put long */
			rc = smb_msgbuf_has_space(mb, repc * sizeof (int32_t));
			if (rc == 0)
				return (SMB_MSGBUF_OVERFLOW);

			while (repc-- > 0) {
				lval = va_arg(ap, uint32_t);
				LE_OUT32(mb->scan, lval);
				mb->scan += sizeof (int32_t);
			}
			break;

		case 'q': /* put quad */
			rc = smb_msgbuf_has_space(mb, repc * sizeof (int64_t));
			if (rc == 0)
				return (SMB_MSGBUF_OVERFLOW);

			while (repc-- > 0) {
				llval = va_arg(ap, uint64_t);
				LE_OUT64(mb->scan, llval);
				mb->scan += sizeof (uint64_t);
			}
			break;

		case 'u': /* conditional unicode */
			if (mb->flags & SMB_MSGBUF_UNICODE)
				goto unicode_translation;
			/* FALLTHROUGH */

		case 's': /* put OEM string */
			cvalp = va_arg(ap, char *);
			if (!repc_specified)
				repc = 0;
			rc = msgbuf_put_oem_string(mb, cvalp, repc);
			if (rc != 0)
				return (rc);
			break;

		case 'U': /* put UTF-16 string */
unicode_translation:
			cvalp = va_arg(ap, char *);
			if (!repc_specified)
				repc = 0;
			rc = msgbuf_put_unicode_string(mb, cvalp, repc);
			if (rc != 0)
				return (rc);
			break;

		case 'M':
			if (smb_msgbuf_has_space(mb, 4) == 0)
				return (SMB_MSGBUF_OVERFLOW);

			*mb->scan++ = 0xFF;
			*mb->scan++ = 'S';
			*mb->scan++ = 'M';
			*mb->scan++ = 'B';
			break;

		default:
			return (SMB_MSGBUF_INVALID_FORMAT);
		}
	}

	return (SMB_MSGBUF_SUCCESS);
}

/*
 * Marshal a UTF-8 string (str) into mbc, converting to OEM codeset.
 * Also write a null unless the repc count limits the length we put.
 * When (repc > 0) the length we marshal must be exactly repc, and
 * truncate or pad the mb data as necessary.
 * See also: mbc_marshal_put_oem_string
 */
static int
msgbuf_put_oem_string(smb_msgbuf_t *mb, char *mbs, int repc)
{
	uint8_t		*oembuf = NULL;
	uint8_t		*s;
	int		oemlen;
	int		rlen;

	/*
	 * Compute length of converted OEM string,
	 * NOT including null terminator
	 */
	if ((oemlen = smb_sbequiv_strlen(mbs)) == -1)
		return (SMB_MSGBUF_DATA_ERROR);

	/*
	 * If repc not specified, put whole string + NULL,
	 * otherwise will truncate or pad as needed.
	 */
	if (repc <= 0) {
		repc = oemlen;
		if ((mb->flags & SMB_MSGBUF_NOTERM) == 0)
			repc += sizeof (char);
	}
	if (smb_msgbuf_has_space(mb, repc) == 0)
		return (SMB_MSGBUF_OVERFLOW);

	/*
	 * Convert into a temporary buffer
	 * Free oembuf in smb_msgbuf_term.
	 */
	oembuf = smb_msgbuf_malloc(mb, oemlen + 1);
	if (oembuf == NULL)
		return (SMB_MSGBUF_UNDERFLOW);
	rlen = smb_mbstooem(oembuf, mbs, oemlen);
	if (rlen < 0)
		return (SMB_MSGBUF_DATA_ERROR);
	if (rlen > oemlen)
		rlen = oemlen;
	oembuf[rlen] = '\0';

	/*
	 * Copy the converted string into the message,
	 * truncated or paded as required.
	 */
	s = oembuf;
	while (repc > 0) {
		*mb->scan++ = *s;
		if (*s != '\0')
			s++;
		repc--;
	}

	return (0);
}

/*
 * Marshal a UTF-8 string (str) into mbc, converting to UTF-16.
 * Also write a null unless the repc count limits the length.
 * When (repc > 0) the length we marshal must be exactly repc,
 * and truncate or pad the mb data as necessary.
 * See also: mbc_marshal_put_unicode_string
 */
static int
msgbuf_put_unicode_string(smb_msgbuf_t *mb, char *mbs, int repc)
{
	smb_wchar_t	*wcsbuf = NULL;
	smb_wchar_t	*wp;
	size_t		wcslen, wcsbytes;
	size_t		rlen;

	/* align to word boundary */
	smb_msgbuf_word_align(mb);

	/*
	 * Compute length of converted UTF-16 string,
	 * NOT including null terminator (in bytes).
	 */
	wcsbytes = smb_wcequiv_strlen(mbs);
	if (wcsbytes == (size_t)-1)
		return (SMB_MSGBUF_DATA_ERROR);

	/*
	 * If repc not specified, put whole string + NULL,
	 * otherwise will truncate or pad as needed.
	 */
	if (repc <= 0) {
		repc = (int)wcsbytes;
		if ((mb->flags & SMB_MSGBUF_NOTERM) == 0)
			repc += sizeof (smb_wchar_t);
	}
	if (smb_msgbuf_has_space(mb, repc) == 0)
		return (SMB_MSGBUF_OVERFLOW);

	/*
	 * Convert into a temporary buffer
	 * Free wcsbuf in smb_msgbuf_term
	 */
	wcslen = wcsbytes / 2;
	wcsbuf = smb_msgbuf_malloc(mb, wcsbytes + 2);
	if (wcsbuf == NULL)
		return (SMB_MSGBUF_UNDERFLOW);
	rlen = smb_mbstowcs(wcsbuf, mbs, wcslen);
	if (rlen == (size_t)-1)
		return (SMB_MSGBUF_DATA_ERROR);
	if (rlen > wcslen)
		rlen = wcslen;
	wcsbuf[rlen] = 0;

	/*
	 * Copy the converted string into the message,
	 * truncated or paded as required.  Preserve
	 * little-endian order while copying.
	 */
	wp = wcsbuf;
	while (repc > 1) {
		smb_wchar_t wchar = LE_IN16(wp);
		LE_OUT16(mb->scan, wchar);
		mb->scan += 2;
		if (wchar != 0)
			wp++;
		repc -= sizeof (smb_wchar_t);
	}
	if (repc > 0)
		*mb->scan++ = '\0';

	return (0);
}

/*
 * smb_msgbuf_malloc
 *
 * Allocate some memory for use with this smb_msgbuf. We increase the
 * requested size to hold the list pointer and return a pointer
 * to the area for use by the caller.
 */
static void *
smb_msgbuf_malloc(smb_msgbuf_t *mb, size_t size)
{
	smb_msgbuf_mlist_t *item;

	size += sizeof (smb_msgbuf_mlist_t);

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
	if ((item = malloc(size)) == NULL)
		return (NULL);
#else
	item = kmem_alloc(size, KM_SLEEP);
#endif
	item->next = mb->mlist.next;
	item->size = size;
	mb->mlist.next = item;

	/*
	 * The caller gets a pointer to the address
	 * immediately after the smb_msgbuf_mlist_t.
	 */
	return ((void *)(item + 1));
}


/*
 * smb_msgbuf_chkerc
 *
 * Diagnostic function to write an appropriate message to the system log.
 */
static int
smb_msgbuf_chkerc(char *text, int erc)
{
	static struct {
		int erc;
		char *name;
	} etable[] = {
		{ SMB_MSGBUF_SUCCESS,		"success" },
		{ SMB_MSGBUF_UNDERFLOW,		"overflow/underflow" },
		{ SMB_MSGBUF_INVALID_FORMAT,	"invalid format" },
		{ SMB_MSGBUF_INVALID_HEADER,	"invalid header" },
		{ SMB_MSGBUF_DATA_ERROR,	"data error" }
	};

	int i;

	for (i = 0; i < sizeof (etable)/sizeof (etable[0]); ++i) {
		if (etable[i].erc == erc) {
			if (text == 0)
				text = "smb_msgbuf_chkerc";
			break;
		}
	}
	return (erc);
}
