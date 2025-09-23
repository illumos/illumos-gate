/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Jakub Klama <jceel@FreeBSD.org>.
 * Copyright (c) 2018 Alexander Motin <mav@FreeBSD.org>
 * Copyright (c) 2026 Hans Rosenfeld
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <errno.h>
#include "iov.h"

/*
 * Given an array of iovecs iov, the number of valid iovecs niov, and an
 * offset, truncate iov at offset. If necessary, split the final iovec,
 * moving the remaining iovecs up by one in iov. Return a pointer to the
 * iovec beginning at offset, and the total number of remaining iovecs.
 *
 * The caller must take care that iov contains enough space for at least
 * niov+1 iovecs so the remainder of the iovec array may be moved up by one.
 */
struct iovec *
split_iov(struct iovec *iov, size_t *niov, size_t offset, size_t *niov_rem)
{
	size_t remainder = 0;
	struct iovec *iov_rem;
	size_t i;

	/*
	 * Handle the special case of offset == 0: Return the whole iovec array
	 * as the remainder.
	 */
	if (offset == 0) {
		*niov_rem = *niov;
		*niov = 0;
		return (iov);
	}

	/* Seek to the requested offset and truncate the final iovec. */
	for (i = 0; i < *niov && offset > iov[i].iov_len; i++) {
		/*
		 * We're seeking past this iovec. Adjust the offset and move on.
		 */
		offset -= iov[i].iov_len;
	}

	/* We've reached the end of the array without reaching the offset. */
	if (i == *niov) {
		*niov_rem = 0;
		return (NULL);
	}

	/*
	 * We found the iovec covering offset. Calculate the remainder and
	 * truncate at offset.
	 */
	remainder = iov[i].iov_len - offset;
	iov[i].iov_len = offset;
	*niov_rem = *niov - i - 1;
	*niov = i + 1;
	iov_rem = &iov[*niov];

	/*
	 * If there's no remainder in this iovec, we're done. Return the
	 * pointer to the next iovec after the offset, or NULL if there
	 * are no more iovecs beyond offset.
	 */
	if (remainder == 0) {
		if (*niov_rem == 0)
			iov_rem = NULL;

		return (iov_rem);
	}

	/*
	 * In the (unlikely, ideally) case where there is a remainder from the
	 * final iovec before the split, make room for a new iovec covering the
	 * remainder by moving all following iovecs up. It is the caller's
	 * responsibility that there is enough spare space for this extra iovec.
	 */
	for (struct iovec *tmp = &iov_rem[*niov_rem];
	    tmp != iov_rem;
	    tmp[0] = tmp[-1], tmp--) {
		;
	}

	/*
	 * Fill in the new first iovec, covering the remainder from the split.
	 */
	iov_rem[0].iov_len = remainder;
	iov_rem[0].iov_base = (char *)iov[i].iov_base + offset;
	(*niov_rem)++;

	return (iov_rem);
}

size_t
count_iov(const struct iovec *iov, size_t niov)
{
	size_t total = 0;
	size_t i;

	for (i = 0; i < niov; i++)
		total += iov[i].iov_len;

	return (total);
}

bool
check_iov_len(const struct iovec *iov, size_t niov, size_t len)
{
	size_t total = 0;
	size_t i;

	for (i = 0; i < niov; i++) {
		total += iov[i].iov_len;
		if (total >= len)
			return (true);
	}

	return (false);
}

ssize_t
iov_to_buf(const struct iovec *iov, size_t niov, void **buf)
{
	size_t ptr, total;
	size_t i;

	total = count_iov(iov, niov);
	*buf = reallocf(*buf, total);
	if (*buf == NULL)
		return (-1);

	for (i = 0, ptr = 0; i < niov; i++) {
		memcpy((uint8_t *)*buf + ptr, iov[i].iov_base, iov[i].iov_len);
		ptr += iov[i].iov_len;
	}

	return (total);
}

ssize_t
buf_to_iov(const void *buf, size_t buflen, const struct iovec *iov, size_t niov)
{
	size_t off = 0, len;
	size_t  i;

	for (i = 0; i < niov && off < buflen; i++) {
		len = MIN(iov[i].iov_len, buflen - off);
		memcpy(iov[i].iov_base, (const uint8_t *)buf + off, len);
		off += len;
	}

	return ((ssize_t)off);
}

size_t
iov_bunch_init(iov_bunch_t *iob, struct iovec *iov, int niov)
{
	bzero(iob, sizeof (*iob));
	iob->ib_iov = iov;
	iob->ib_remain = count_iov(iov, niov);

	return (iob->ib_remain);
}

/*
 * Copy `sz` bytes from iovecs contained in `iob` to `dst`.
 *
 * Returns `true` if copy was successful (implying adequate data was remaining
 * in the iov_bunch_t).
 */
bool
iov_bunch_copy(iov_bunch_t *iob, void *dst, size_t sz)
{
	if (sz > iob->ib_remain)
		return (false);
	if (sz == 0)
		return (true);

	caddr_t dest = dst;
	do {
		struct iovec *iov = iob->ib_iov;

		ASSERT3U(iov->iov_len, !=, 0);

		/* ib_offset is the offset within the current head of ib_iov */
		const size_t iov_avail = iov->iov_len - iob->ib_offset;
		const size_t to_copy = MIN(sz, iov_avail);

		if (to_copy != 0 && dest != NULL) {
			bcopy((caddr_t)iov->iov_base + iob->ib_offset, dest,
			    to_copy);
			dest += to_copy;
		}

		sz -= to_copy;
		iob->ib_remain -= to_copy;
		iob->ib_offset += to_copy;

		ASSERT3U(iob->ib_offset, <=, iov->iov_len);

		if (iob->ib_offset == iov->iov_len) {
			iob->ib_iov++;
			iob->ib_offset = 0;
		}
	} while (sz > 0);

	return (true);
}

/*
 * Skip `sz` bytes from iovecs contained in `iob`.
 *
 * Returns `true` if the skip was successful (implying adequate data was
 * remaining in the iov_bunch_t).
 */
bool
iov_bunch_skip(iov_bunch_t *iob, size_t sz)
{
	return (iov_bunch_copy(iob, NULL, sz));
}

/*
 * Get the data pointer and length of the current head iovec, less any
 * offsetting from prior copy operations. This will advance the iov_bunch_t as
 * if the caller had performed a copy of that chunk length.
 *
 * Returns `true` if the iov_bunch_t had at least one iovec (unconsumed bytes)
 * remaining, setting `chunk` and `chunk_sz` to the chunk pointer and size,
 * respectively.
 */
bool
iov_bunch_next_chunk(iov_bunch_t *iob, caddr_t *chunk, size_t *chunk_sz)
{
	if (iob->ib_remain == 0) {
		*chunk = NULL;
		*chunk_sz = 0;
		return (false);
	}

	*chunk_sz = iob->ib_iov->iov_len - iob->ib_offset;
	*chunk = (caddr_t)iob->ib_iov->iov_base + iob->ib_offset;
	iob->ib_remain -= *chunk_sz;
	iob->ib_iov++;
	iob->ib_offset = 0;
	return (true);
}

/*
 * Extract the remaining data in an iov_bunch_t into a new iovec.
 */
void
iov_bunch_to_iov(iov_bunch_t *iob, struct iovec *iov, int *niov, uint_t size)
{
	*niov = 0;

	while (size-- > 0) {
		caddr_t chunk;
		size_t sz;

		if (!iov_bunch_next_chunk(iob, &chunk, &sz))
			break;

		iov->iov_base = chunk;
		iov->iov_len = sz;
		iov++;
		(*niov)++;
	}
}

/*
 * Extract the remaining data in an iov_bunch_t into a buffer, reallocating it
 * to the required size. If there are no bytes remaining in the iov_bunch_t any
 * supplied buffer will be freed and this function will return 0.
 */
ssize_t
iov_bunch_to_buf(iov_bunch_t *iob, void **buf)
{
	size_t total = iob->ib_remain;

	if (total == 0) {
		free(*buf);
		*buf = NULL;
		return (0);
	}

	*buf = reallocf(*buf, total);
	if (*buf == NULL)
		return (-1);

	if (!iov_bunch_copy(iob, buf, total))
		return (-1);

	if (total > SSIZE_MAX) {
		errno = EOVERFLOW;
		return (-1);
	}

	return (total);
}

/*
 * Copy data from a buffer into an iob_bunch_t. Returns true if there was
 * sufficient space for the data, false otherwise.
 */
bool
buf_to_iov_bunch(iov_bunch_t *iob, const void *buf, size_t len)
{
	const char *src = buf;

	if (iob->ib_remain < len)
		return (false);

	do {
		struct iovec *iov = iob->ib_iov;

		/* ib_offset is the offset within the current head of ib_iov */
		const size_t iov_avail = iov->iov_len - iob->ib_offset;
		const size_t to_copy = MIN(len, iov_avail);

		if (to_copy != 0) {
			bcopy(src, (caddr_t)iov->iov_base + iob->ib_offset,
			    to_copy);
		}

		src += to_copy;
		len -= to_copy;
		iob->ib_remain -= to_copy;
		iob->ib_offset += to_copy;

		ASSERT3U(iob->ib_offset, <=, iov->iov_len);

		if (iob->ib_offset == iov->iov_len) {
			iob->ib_iov++;
			iob->ib_offset = 0;
		}
	} while (len > 0);

	return (true);
}
