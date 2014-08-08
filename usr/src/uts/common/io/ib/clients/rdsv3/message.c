/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file message.c
 * Oracle elects to have and use the contents of message.c under and governed
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
#include <sys/ib/clients/rdsv3/rdma.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

#ifndef __lock_lint
static unsigned int	rdsv3_exthdr_size[__RDSV3_EXTHDR_MAX] = {
[RDSV3_EXTHDR_NONE]	= 0,
[RDSV3_EXTHDR_VERSION]	= sizeof (struct rdsv3_ext_header_version),
[RDSV3_EXTHDR_RDMA]	= sizeof (struct rdsv3_ext_header_rdma),
[RDSV3_EXTHDR_RDMA_DEST]	= sizeof (struct rdsv3_ext_header_rdma_dest),
};
#else
static unsigned int	rdsv3_exthdr_size[__RDSV3_EXTHDR_MAX] = {
			0,
			sizeof (struct rdsv3_ext_header_version),
			sizeof (struct rdsv3_ext_header_rdma),
			sizeof (struct rdsv3_ext_header_rdma_dest),
};
#endif

void
rdsv3_message_addref(struct rdsv3_message *rm)
{
	RDSV3_DPRINTF5("rdsv3_message_addref", "addref rm %p ref %d",
	    rm, atomic_get(&rm->m_refcount));
	atomic_inc_32(&rm->m_refcount);
}

/*
 * This relies on dma_map_sg() not touching sg[].page during merging.
 */
static void
rdsv3_message_purge(struct rdsv3_message *rm)
{
	unsigned long i;

	RDSV3_DPRINTF4("rdsv3_message_purge", "Enter(rm: %p)", rm);

	if (test_bit(RDSV3_MSG_PAGEVEC, &rm->m_flags))
		return;

	for (i = 0; i < rm->m_nents; i++) {
		RDSV3_DPRINTF5("rdsv3_message_purge", "putting data page %p\n",
		    (void *)rdsv3_sg_page(&rm->m_sg[i]));
		/* XXX will have to put_page for page refs */
		kmem_free(rdsv3_sg_page(&rm->m_sg[i]),
		    rdsv3_sg_len(&rm->m_sg[i]));
	}

	if (rm->m_rdma_op)
		rdsv3_rdma_free_op(rm->m_rdma_op);
	if (rm->m_rdma_mr) {
		struct rdsv3_mr *mr = rm->m_rdma_mr;
		if (mr->r_refcount == 0) {
			RDSV3_DPRINTF4("rdsv3_message_purge ASSERT 0",
			    "rm %p mr %p", rm, mr);
			return;
		}
		if (mr->r_refcount == 0xdeadbeef) {
			RDSV3_DPRINTF4("rdsv3_message_purge ASSERT deadbeef",
			    "rm %p mr %p", rm, mr);
			return;
		}
		if (atomic_dec_and_test(&mr->r_refcount)) {
			rm->m_rdma_mr = NULL;
			__rdsv3_put_mr_final(mr);
		}
	}

	RDSV3_DPRINTF4("rdsv3_message_purge", "Return(rm: %p)", rm);

}

void
rdsv3_message_put(struct rdsv3_message *rm)
{
	RDSV3_DPRINTF5("rdsv3_message_put",
	    "put rm %p ref %d\n", rm, atomic_get(&rm->m_refcount));

	if (atomic_dec_and_test(&rm->m_refcount)) {
		ASSERT(!list_link_active(&rm->m_sock_item));
		ASSERT(!list_link_active(&rm->m_conn_item));
		rdsv3_message_purge(rm);

		kmem_free(rm, sizeof (struct rdsv3_message) +
		    (rm->m_nents * sizeof (struct rdsv3_scatterlist)));
	}
}

void
rdsv3_message_inc_free(struct rdsv3_incoming *inc)
{
	struct rdsv3_message *rm =
	    container_of(inc, struct rdsv3_message, m_inc);
	rdsv3_message_put(rm);
}

void
rdsv3_message_populate_header(struct rdsv3_header *hdr, uint16_be_t sport,
    uint16_be_t dport, uint64_t seq)
{
	hdr->h_flags = 0;
	hdr->h_sport = sport;
	hdr->h_dport = dport;
	hdr->h_sequence = htonll(seq);
	hdr->h_exthdr[0] = RDSV3_EXTHDR_NONE;
}

int
rdsv3_message_add_extension(struct rdsv3_header *hdr,
    unsigned int type, const void *data, unsigned int len)
{
	unsigned int ext_len = sizeof (uint8_t) + len;
	unsigned char *dst;

	RDSV3_DPRINTF4("rdsv3_message_add_extension", "Enter");

	/* For now, refuse to add more than one extension header */
	if (hdr->h_exthdr[0] != RDSV3_EXTHDR_NONE)
		return (0);

	if (type >= __RDSV3_EXTHDR_MAX ||
	    len != rdsv3_exthdr_size[type])
		return (0);

	if (ext_len >= RDSV3_HEADER_EXT_SPACE)
		return (0);
	dst = hdr->h_exthdr;

	*dst++ = type;
	(void) memcpy(dst, data, len);

	dst[len] = RDSV3_EXTHDR_NONE;

	RDSV3_DPRINTF4("rdsv3_message_add_extension", "Return");
	return (1);
}

/*
 * If a message has extension headers, retrieve them here.
 * Call like this:
 *
 * unsigned int pos = 0;
 *
 * while (1) {
 *	buflen = sizeof(buffer);
 *	type = rdsv3_message_next_extension(hdr, &pos, buffer, &buflen);
 *	if (type == RDSV3_EXTHDR_NONE)
 *		break;
 *	...
 * }
 */
int
rdsv3_message_next_extension(struct rdsv3_header *hdr,
    unsigned int *pos, void *buf, unsigned int *buflen)
{
	unsigned int offset, ext_type, ext_len;
	uint8_t *src = hdr->h_exthdr;

	RDSV3_DPRINTF4("rdsv3_message_next_extension", "Enter");

	offset = *pos;
	if (offset >= RDSV3_HEADER_EXT_SPACE)
		goto none;

	/*
	 * Get the extension type and length. For now, the
	 * length is implied by the extension type.
	 */
	ext_type = src[offset++];

	if (ext_type == RDSV3_EXTHDR_NONE || ext_type >= __RDSV3_EXTHDR_MAX)
		goto none;
	ext_len = rdsv3_exthdr_size[ext_type];
	if (offset + ext_len > RDSV3_HEADER_EXT_SPACE)
		goto none;

	*pos = offset + ext_len;
	if (ext_len < *buflen)
		*buflen = ext_len;
	(void) memcpy(buf, src + offset, *buflen);
	return (ext_type);

none:
	*pos = RDSV3_HEADER_EXT_SPACE;
	*buflen = 0;
	return (RDSV3_EXTHDR_NONE);
}

int
rdsv3_message_add_version_extension(struct rdsv3_header *hdr,
    unsigned int version)
{
	struct rdsv3_ext_header_version ext_hdr;

	ext_hdr.h_version = htonl(version);
	return (rdsv3_message_add_extension(hdr, RDSV3_EXTHDR_VERSION,
	    &ext_hdr, sizeof (ext_hdr)));
}

int
rdsv3_message_get_version_extension(struct rdsv3_header *hdr,
    unsigned int *version)
{
	struct rdsv3_ext_header_version ext_hdr;
	unsigned int pos = 0, len = sizeof (ext_hdr);

	RDSV3_DPRINTF4("rdsv3_message_get_version_extension", "Enter");

	/*
	 * We assume the version extension is the only one present
	 */
	if (rdsv3_message_next_extension(hdr, &pos, &ext_hdr, &len) !=
	    RDSV3_EXTHDR_VERSION)
		return (0);
	*version = ntohl(ext_hdr.h_version);
	return (1);
}

int
rdsv3_message_add_rdma_dest_extension(struct rdsv3_header *hdr, uint32_t r_key,
    uint32_t offset)
{
	struct rdsv3_ext_header_rdma_dest ext_hdr;

	ext_hdr.h_rdma_rkey = htonl(r_key);
	ext_hdr.h_rdma_offset = htonl(offset);
	return (rdsv3_message_add_extension(hdr, RDSV3_EXTHDR_RDMA_DEST,
	    &ext_hdr, sizeof (ext_hdr)));
}

struct rdsv3_message *
rdsv3_message_alloc(unsigned int nents, int gfp)
{
	struct rdsv3_message *rm;

	RDSV3_DPRINTF4("rdsv3_message_alloc", "Enter(nents: %d)", nents);

	rm = kmem_zalloc(sizeof (struct rdsv3_message) +
	    (nents * sizeof (struct rdsv3_scatterlist)), gfp);
	if (!rm)
		goto out;

	rm->m_refcount = 1;
	list_link_init(&rm->m_sock_item);
	list_link_init(&rm->m_conn_item);
	mutex_init(&rm->m_rs_lock, NULL, MUTEX_DRIVER, NULL);
	rdsv3_init_waitqueue(&rm->m_flush_wait);

	RDSV3_DPRINTF4("rdsv3_message_alloc", "Return(rm: %p)", rm);
out:
	return (rm);
}

struct rdsv3_message *
rdsv3_message_map_pages(unsigned long *page_addrs, unsigned int total_len)
{
	struct rdsv3_message *rm;
	unsigned int i;

	RDSV3_DPRINTF4("rdsv3_message_map_pages", "Enter(len: %d)", total_len);

#ifndef __lock_lint
	rm = rdsv3_message_alloc(ceil(total_len, PAGE_SIZE), KM_NOSLEEP);
#else
	rm = NULL;
#endif
	if (rm == NULL)
		return (ERR_PTR(-ENOMEM));

	set_bit(RDSV3_MSG_PAGEVEC, &rm->m_flags);
	rm->m_inc.i_hdr.h_len = htonl(total_len);
#ifndef __lock_lint
	rm->m_nents = ceil(total_len, PAGE_SIZE);
#else
	rm->m_nents = 0;
#endif

	for (i = 0; i < rm->m_nents; ++i) {
		rdsv3_sg_set_page(&rm->m_sg[i],
		    page_addrs[i],
		    PAGE_SIZE, 0);
	}

	return (rm);
}

struct rdsv3_message *
rdsv3_message_copy_from_user(struct uio *uiop,
    size_t total_len)
{
	struct rdsv3_message *rm;
	struct rdsv3_scatterlist *sg;
	int ret;

	RDSV3_DPRINTF4("rdsv3_message_copy_from_user", "Enter: %d", total_len);

#ifndef __lock_lint
	rm = rdsv3_message_alloc(ceil(total_len, PAGE_SIZE), KM_NOSLEEP);
#else
	rm = NULL;
#endif
	if (rm == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	rm->m_inc.i_hdr.h_len = htonl(total_len);

	/*
	 * now allocate and copy in the data payload.
	 */
	sg = rm->m_sg;

	while (total_len) {
		if (rdsv3_sg_page(sg) == NULL) {
			ret = rdsv3_page_remainder_alloc(sg, total_len, 0);
			if (ret)
				goto out;
			rm->m_nents++;
		}

		ret = uiomove(rdsv3_sg_page(sg), rdsv3_sg_len(sg), UIO_WRITE,
		    uiop);
		if (ret) {
			RDSV3_DPRINTF2("rdsv3_message_copy_from_user",
			    "uiomove failed");
			ret = -ret;
			goto out;
		}

		total_len -= rdsv3_sg_len(sg);
		sg++;
	}
	ret = 0;
out:
	if (ret) {
		if (rm)
			rdsv3_message_put(rm);
		rm = ERR_PTR(ret);
	}
	return (rm);
}

int
rdsv3_message_inc_copy_to_user(struct rdsv3_incoming *inc,
    uio_t *uiop, size_t size)
{
	struct rdsv3_message *rm;
	struct rdsv3_scatterlist *sg;
	unsigned long to_copy;
	unsigned long vec_off;
	int copied;
	int ret;
	uint32_t len;

	rm = container_of(inc, struct rdsv3_message, m_inc);
	len = ntohl(rm->m_inc.i_hdr.h_len);

	RDSV3_DPRINTF4("rdsv3_message_inc_copy_to_user",
	    "Enter(rm: %p, len: %d)", rm, len);

	sg = rm->m_sg;
	vec_off = 0;
	copied = 0;

	while (copied < size && copied < len) {

		to_copy = min(len - copied, sg->length - vec_off);
		to_copy = min(size - copied, to_copy);

		RDSV3_DPRINTF5("rdsv3_message_inc_copy_to_user",
		    "copying %lu bytes to user iov %p from sg [%p, %u] + %lu\n",
		    to_copy, uiop,
		    rdsv3_sg_page(sg), sg->length, vec_off);

		ret = uiomove(rdsv3_sg_page(sg), to_copy, UIO_READ, uiop);
		if (ret)
			break;

		vec_off += to_copy;
		copied += to_copy;

		if (vec_off == sg->length) {
			vec_off = 0;
			sg++;
		}
	}

	return (copied);
}

/*
 * If the message is still on the send queue, wait until the transport
 * is done with it. This is particularly important for RDMA operations.
 */
/* ARGSUSED */
void
rdsv3_message_wait(struct rdsv3_message *rm)
{
	rdsv3_wait_event(&rm->m_flush_wait,
	    !test_bit(RDSV3_MSG_MAPPED, &rm->m_flags));
}

void
rdsv3_message_unmapped(struct rdsv3_message *rm)
{
	clear_bit(RDSV3_MSG_MAPPED, &rm->m_flags);
	rdsv3_wake_up_all(&rm->m_flush_wait);
}
