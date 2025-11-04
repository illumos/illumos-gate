/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Jakub Klama <jceel@FreeBSD.org>.
 * Copyright (c) 2018 Alexander Motin <mav@FreeBSD.org>
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

#ifndef _IOV_H_
#define	_IOV_H_

#include <sys/stdbool.h>

void seek_iov(const struct iovec *iov1, int niov1, struct iovec *iov2,
    int *niov2, size_t seek);
void truncate_iov(struct iovec *iov, int *niov, size_t length);
size_t count_iov(const struct iovec *iov, int niov);
ssize_t iov_to_buf(const struct iovec *iov, int niov, void **buf);
ssize_t buf_to_iov(const void *buf, size_t buflen, const struct iovec *iov,
    int niov, size_t seek);

/*
 * Helpers for performing operations on an array of iovec entries.
 */
typedef struct iov_bunch {
	/*
	 * The current head of an array of iovec entries, which have an iov_len
	 * sum covering ib_remain bytes. This moves as the bunch is traversed.
	 */
	struct iovec	*ib_iov;
	/*
	 * Byte offset in current ib_iov entry.
	 */
	size_t		ib_offset;
	/*
	 * Bytes remaining in entries covered by ib_iov entries, not including
	 * the offset specified by ib_offset
	 */
	size_t		ib_remain;
} iov_bunch_t;

extern size_t iov_bunch_init(iov_bunch_t *, struct iovec *, int);
extern bool iov_bunch_copy(iov_bunch_t *, void *, size_t);
extern bool iov_bunch_skip(iov_bunch_t *, size_t);
extern bool iov_bunch_next_chunk(iov_bunch_t *, caddr_t *, size_t *);
extern void iov_bunch_to_iov(iov_bunch_t *, struct iovec *, int *, uint_t);
extern ssize_t iov_bunch_to_buf(iov_bunch_t *iob, void **);
extern bool buf_to_iov_bunch(iov_bunch_t *, const void *, size_t);

#endif	/* _IOV_H_ */
