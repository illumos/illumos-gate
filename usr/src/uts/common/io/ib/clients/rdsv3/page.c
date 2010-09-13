/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file page.c
 * Oracle elects to have and use the contents of page.c under and governed
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
 * @bytes - the number of bytes needed.
 *
 * XXX - This is different from Linux.
 */
int
rdsv3_page_remainder_alloc(struct rdsv3_scatterlist *scat, unsigned long bytes,
    int gfp)
{
	caddr_t	page;
	int ret;

	ASSERT(rdsv3_sg_page(scat) == NULL);

	if (bytes >= PAGE_SIZE) {
		page = kmem_alloc(PAGE_SIZE, gfp);
		if (!page) {
			ret = -ENOMEM;
		} else {
			rdsv3_sg_set_page(scat, page, PAGE_SIZE, 0);
			ret = 0;
		}
		goto out;
	}

	/*
	 * XXX - This is not same as linux.
	 */
	page = kmem_alloc(bytes, KM_NOSLEEP);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	rdsv3_sg_set_page(scat, page, bytes, 0);
	ret = 0;
out:
	RDSV3_DPRINTF5("rdsv3_page_remainder_alloc", "bytes %lu %p %u",
	    bytes, rdsv3_sg_page(scat), scat->length);
	return (ret);
}
