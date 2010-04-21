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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <sys/rds.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>

/*
 * This file implements a getsockopt() call which copies a set of fixed
 * sized structs into a user-specified buffer as a means of providing
 * read-only information about RDS.
 *
 * For a given information source there are a given number of fixed sized
 * structs at a given time.  The structs are only copied if the user-specified
 * buffer is big enough.  The destination pages that make up the buffer
 * are pinned for the duration of the copy.
 *
 * This gives us the following benefits:
 *
 * - simple implementation, no copy "position" across multiple calls
 * - consistent snapshot of an info source
 * - atomic copy works well with whatever locking info source has
 * - one portable tool to get rds info across implementations
 * - long-lived tool can get info without allocating
 *
 * at the following costs:
 *
 * - info source copy must be pinned, may be "large"
 */

static kmutex_t rdsv3_info_lock;
static rdsv3_info_func rdsv3_info_funcs[RDSV3_INFO_LAST - RDSV3_INFO_FIRST + 1];

void
rdsv3_info_register_func(int optname, rdsv3_info_func func)
{
	int offset = optname - RDSV3_INFO_FIRST;

	ASSERT(optname >= RDSV3_INFO_FIRST && optname <= RDSV3_INFO_LAST);

	mutex_enter(&rdsv3_info_lock);
	rdsv3_info_funcs[offset] = func;
	mutex_exit(&rdsv3_info_lock);
}

/* ARGSUSED */
void
rdsv3_info_deregister_func(int optname, rdsv3_info_func func)
{
	int offset = optname - RDSV3_INFO_FIRST;

	ASSERT(optname >= RDSV3_INFO_FIRST && optname <= RDSV3_INFO_LAST);

	mutex_enter(&rdsv3_info_lock);
	rdsv3_info_funcs[offset] = NULL;
	mutex_exit(&rdsv3_info_lock);
}

/*
 * @optval points to the userspace buffer that the information snapshot
 * will be copied into.
 *
 * @optlen on input is the size of the buffer in userspace.  @optlen
 * on output is the size of the requested snapshot in bytes.
 *
 * This function returns -errno if there is a failure, particularly -ENOSPC
 * if the given userspace buffer was not large enough to fit the snapshot.
 * On success it returns the positive number of bytes of each array element
 * in the snapshot.
 */
int
rdsv3_info_getsockopt(struct rsock *sock, int optname, char *optval,
    socklen_t *optlen)
{
	struct rdsv3_info_iterator iter;
	struct rdsv3_info_lengths lens;
	rdsv3_info_func func;

	func = rdsv3_info_funcs[optname - RDSV3_INFO_FIRST];
	if (func == NULL) {
		return (-ENOPROTOOPT);
	}

	if (*optlen == sizeof (struct rdsv3_info_lengths)) {
		iter.addr = NULL;
	} else {
		iter.addr = optval;
	}

	iter.offset = 0;

	func(sock, *optlen, &iter, &lens);
	ASSERT(lens.each != 0);

	if (iter.addr == NULL) {
		bcopy(&lens, optval, sizeof (struct rdsv3_info_lengths));
	} else {
		*optlen = lens.nr * lens.each;
	}

	return (0);
}
