/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file info.c
 * Oracle elects to have and use the contents of info.c under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
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
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

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
static rdsv3_info_func rdsv3_info_funcs[RDS_INFO_LAST - RDS_INFO_FIRST + 1];

void
rdsv3_info_register_func(int optname, rdsv3_info_func func)
{
	int offset = optname - RDS_INFO_FIRST;

	ASSERT(optname >= RDS_INFO_FIRST && optname <= RDS_INFO_LAST);

	mutex_enter(&rdsv3_info_lock);
	ASSERT(!rdsv3_info_funcs[offset]);
	rdsv3_info_funcs[offset] = func;
	mutex_exit(&rdsv3_info_lock);
}

/* ARGSUSED */
void
rdsv3_info_deregister_func(int optname, rdsv3_info_func func)
{
	int offset = optname - RDS_INFO_FIRST;

	ASSERT(optname >= RDS_INFO_FIRST && optname <= RDS_INFO_LAST);

	mutex_enter(&rdsv3_info_lock);
	rdsv3_info_funcs[offset] = NULL;
	mutex_exit(&rdsv3_info_lock);
}

/*
 * @optval points to the userspace buffer that the information snapshot
 * will be copied into.
 *
 * This function returns -errno if there is a failure, particularly -ENOSPC
 * if the given userspace buffer was not large enough to fit the snapshot.
 * On success it returns the positive number of bytes of each array element
 * in the snapshot.
 */
int
rdsv3_info_ioctl(struct rsock *sock, int optname, char *optval,
    int32_t *rvalp)
{
	struct rdsv3_info_iterator iter;
	struct rdsv3_info_lengths lens;
	rdsv3_info_func func;
	struct rds_info_arg arg;
	uint32_t ulen = 0, klen;

	func = rdsv3_info_funcs[optname - RDS_INFO_FIRST];
	if (func == NULL) {
		RDSV3_DPRINTF2("rdsv3_info_ioctl",
		    "No Info Function, optname: %d", optname);
		return (ENOPROTOOPT);
	}

	if (optval == NULL) {
		RDSV3_DPRINTF2("rdsv3_info_ioctl", "optval is NULL");
		return (EINVAL);
	}
	if (ddi_copyin(optval, &arg, sizeof (struct rds_info_arg), 0) != 0) {
		RDSV3_DPRINTF2("rdsv3_info_ioctl",
		    "ddi_copyin for address: 0x%p failed", optval);
		return (EFAULT);
	}

	RDSV3_DPRINTF4("rdsv3_info_ioctl",
	    "optname: %d lenp: %llx datap: %llx", optname, arg.lenp, arg.datap);

	if (arg.lenp == (uintptr_t)NULL) {
		RDSV3_DPRINTF2("rdsv3_info_ioctl", "arg.lenp is NULL");
		return (EFAULT);
	}

	if (ddi_copyin((void *)(uintptr_t)arg.lenp, &ulen,
	    sizeof (uint32_t), 0) != 0) {
		RDSV3_DPRINTF2("rdsv3_info_ioctl",
		    "ddi_copyin for address, lenp: 0x%p failed", arg.lenp);
		return (EFAULT);
	}

	RDSV3_DPRINTF3("rdsv3_info_ioctl", "optname: %d len: %d datap: %p",
	    optname, ulen, arg.datap);

	bzero(&iter, sizeof (struct rdsv3_info_iterator));
	/* a 0 len call is just trying to probe its length */
	if (ulen == 0) {
		iter.addr = NULL;
	} else if (arg.datap == (uintptr_t)NULL) {
		RDSV3_DPRINTF2("rdsv3_info_ioctl",
		    "arg.datap is NULL, ulen set to: %d", ulen);
		return (EINVAL);
	} else {
		iter.addr = (char *)(uintptr_t)arg.datap;
	}
	iter.offset = 0;

	bzero(&lens, sizeof (struct rdsv3_info_lengths));
	func(sock, ulen, &iter, &lens);

	klen = lens.nr * lens.each;

	if (ddi_copyout(&klen, (void *)(uintptr_t)arg.lenp,
	    sizeof (uint32_t), 0) != 0) {
		RDSV3_DPRINTF2("rdsv3_info_ioctl",
		    "ddi_copyout(%p %p) failed", &klen, arg.lenp);
		return (EFAULT);
	}

	RDSV3_DPRINTF3("rdsv3_info_ioctl",
	    "optname: %d ulen: %d klen: %d each: %d", optname, ulen, klen,
	    lens.each);

	if (ulen < klen) {
		return (ENOSPC);
	}

	RDSV3_DPRINTF4("rdsv3_info_ioctl", "Return optname: %d", optname);

	*rvalp = lens.each;
	return (0);
}
