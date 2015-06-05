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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
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
static void buf_decode_wcs(smb_wchar_t *, smb_wchar_t *, int wcstrlen);

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
 * On success, returns the number of bytes encoded. Otherwise
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
	uint32_t ival;
	uint8_t c;
	uint8_t *cvalp;
	uint8_t **cvalpp;
	uint16_t *wvalp;
	uint32_t *lvalp;
	uint64_t *llvalp;
	smb_wchar_t *wcs;
	int repc;
	int rc;

	while ((c = *fmt++) != 0) {
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
		} else if (c == '#') {
			repc = va_arg(ap, int);
			c = *fmt++;
		}

		switch (c) {
		case '.':
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			mb->scan += repc;
			break;

		case 'c':
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			cvalp = va_arg(ap, uint8_t *);
			bcopy(mb->scan, cvalp, repc);
			mb->scan += repc;
			break;

		case 'b':
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			cvalp = va_arg(ap, uint8_t *);
			while (repc-- > 0) {
				*cvalp++ = *mb->scan++;
			}
			break;

		case 'w':
			rc = smb_msgbuf_has_space(mb, repc * sizeof (uint16_t));
			if (rc == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			wvalp = va_arg(ap, uint16_t *);
			while (repc-- > 0) {
				*wvalp++ = LE_IN16(mb->scan);
				mb->scan += sizeof (uint16_t);
			}
			break;

		case 'l':
			rc = smb_msgbuf_has_space(mb, repc * sizeof (int32_t));
			if (rc == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			lvalp = va_arg(ap, uint32_t *);
			while (repc-- > 0) {
				*lvalp++ = LE_IN32(mb->scan);
				mb->scan += sizeof (int32_t);
			}
			break;

		case 'q':
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

		case 's':
			ival = strlen((const char *)mb->scan) + 1;
			if (smb_msgbuf_has_space(mb, ival) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			if ((cvalp = smb_msgbuf_malloc(mb, ival * 2)) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			if ((ival = smb_stombs((char *)cvalp,
			    (char *)mb->scan, ival * 2)) ==
			    (uint32_t)-1) {
				return (SMB_MSGBUF_DATA_ERROR);
			}

			cvalpp = va_arg(ap, uint8_t **);
			*cvalpp = cvalp;
			mb->scan += (ival+1);
			break;

		case 'U': /* Convert from unicode */
unicode_translation:
			/*
			 * Unicode strings are always word aligned.
			 * The malloc'd area is larger than the
			 * original string because the UTF-8 chars
			 * may be longer than the wide-chars.
			 */
			smb_msgbuf_word_align(mb);
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			wcs = (smb_wchar_t *)mb->scan;

			/* count the null wchar */
			repc = sizeof (smb_wchar_t);
			while (*wcs++)
				repc += sizeof (smb_wchar_t);

			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			/* Decode wchar string into host byte-order */
			if ((wcs = smb_msgbuf_malloc(mb, repc)) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			buf_decode_wcs(wcs, (smb_wchar_t *)mb->scan,
			    repc / sizeof (smb_wchar_t));

			/* Get space for translated string */
			if ((cvalp = smb_msgbuf_malloc(mb, repc * 2)) == 0)
				return (SMB_MSGBUF_UNDERFLOW);

			/* Translate string */
			(void) smb_wcstombs((char *)cvalp, wcs, repc * 2);

			cvalpp = va_arg(ap, uint8_t **);
			*cvalpp = cvalp;
			mb->scan += repc;
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
	uint32_t ival;
	uint8_t *cvalp;
	uint8_t c;
	smb_wchar_t wcval;
	int count;
	int repc = 1;
	int rc;

	while ((c = *fmt++) != 0) {
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
		} else if (c == '#') {
			repc = va_arg(ap, int);
			c = *fmt++;
		}

		switch (c) {
		case '.':
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_OVERFLOW);

			while (repc-- > 0)
				*mb->scan++ = 0;
			break;

		case 'c':
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_OVERFLOW);

			cvalp = va_arg(ap, uint8_t *);
			bcopy(cvalp, mb->scan, repc);
			mb->scan += repc;
			break;

		case 'b':
			if (smb_msgbuf_has_space(mb, repc) == 0)
				return (SMB_MSGBUF_OVERFLOW);

			while (repc-- > 0) {
				cval = va_arg(ap, int);
				*mb->scan++ = cval;
			}
			break;

		case 'w':
			rc = smb_msgbuf_has_space(mb, repc * sizeof (uint16_t));
			if (rc == 0)
				return (SMB_MSGBUF_OVERFLOW);

			while (repc-- > 0) {
				wval = va_arg(ap, int);
				LE_OUT16(mb->scan, wval);
				mb->scan += sizeof (uint16_t);
			}
			break;

		case 'l':
			rc = smb_msgbuf_has_space(mb, repc * sizeof (int32_t));
			if (rc == 0)
				return (SMB_MSGBUF_OVERFLOW);

			while (repc-- > 0) {
				lval = va_arg(ap, uint32_t);
				LE_OUT32(mb->scan, lval);
				mb->scan += sizeof (int32_t);
			}
			break;

		case 'q':
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

		case 's':
			cvalp = va_arg(ap, uint8_t *);
			ival = strlen((const char *)cvalp) + 1;

			if (smb_msgbuf_has_space(mb, ival) == 0)
				return (SMB_MSGBUF_OVERFLOW);

			ival =
			    smb_mbstos((char *)mb->scan, (const char *)cvalp);
			mb->scan += ival + 1;
			break;

		case 'U': /* unicode */
unicode_translation:
			/*
			 * Unicode strings are always word aligned.
			 */
			smb_msgbuf_word_align(mb);
			cvalp = va_arg(ap, uint8_t *);

			for (;;) {
				rc = smb_msgbuf_has_space(mb,
				    sizeof (smb_wchar_t));
				if (rc == 0)
					return (SMB_MSGBUF_OVERFLOW);

				count = smb_mbtowc(&wcval, (const char *)cvalp,
				    MTS_MB_CHAR_MAX);

				if (count < 0) {
					return (SMB_MSGBUF_DATA_ERROR);
				} else if (count == 0) {
					/*
					 * No longer need to do this now that
					 * mbtowc correctly writes the null
					 * before returning zero but paranoia
					 * wins.
					 */
					wcval = 0;
					count = 1;
				}

				/* Write wchar in wire-format */
				LE_OUT16(mb->scan, wcval);

				if (*cvalp == 0) {
					/*
					 * End of string. Check to see whether
					 * or not to include the null
					 * terminator.
					 */
					if ((mb->flags & SMB_MSGBUF_NOTERM) ==
					    0)
						mb->scan +=
						    sizeof (smb_wchar_t);
					break;
				}

				mb->scan += sizeof (smb_wchar_t);
				cvalp += count;
			}
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

static void
buf_decode_wcs(smb_wchar_t *dst_wcstr, smb_wchar_t *src_wcstr, int wcstrlen)
{
	int i;

	for (i = 0; i < wcstrlen; i++) {
		*dst_wcstr = LE_IN16(src_wcstr);
		dst_wcstr++;
		src_wcstr++;
	}
}
