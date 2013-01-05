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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Server-side NDR stream (PDU) operations. Stream operations should
 * return TRUE (non-zero) on success or FALSE (zero or a null pointer)
 * on failure. When an operation returns FALSE, including ndo_malloc()
 * returning NULL, it should set the nds->error to indicate what went
 * wrong.
 *
 * When available, the relevant ndr reference is passed to the
 * operation but keep in mind that it may be a null pointer.
 *
 * Functions ndo_get_pdu(), ndo_put_pdu(), and ndo_pad_pdu()
 * must never grow the PDU data. A request for out-of-bounds data is
 * an error. The swap_bytes flag is 1 if NDR knows that the byte-
 * order in the PDU is different from the local system.
 */

#include <sys/types.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <assert.h>

#include <libmlrpc.h>

#define	NDOBUFSZ		128

#define	NDR_PDU_BLOCK_SIZE	(4*1024)
#define	NDR_PDU_BLOCK_MASK	(NDR_PDU_BLOCK_SIZE - 1)
#define	NDR_PDU_ALIGN(N) \
	(((N) + NDR_PDU_BLOCK_SIZE) & ~NDR_PDU_BLOCK_MASK)
#define	NDR_PDU_MAX_SIZE		(64*1024*1024)

static char *ndo_malloc(ndr_stream_t *, unsigned, ndr_ref_t *);
static int ndo_free(ndr_stream_t *, char *, ndr_ref_t *);
static int ndo_grow_pdu(ndr_stream_t *, unsigned long, ndr_ref_t *);
static int ndo_pad_pdu(ndr_stream_t *, unsigned long, unsigned long,
    ndr_ref_t *);
static int ndo_get_pdu(ndr_stream_t *, unsigned long, unsigned long,
    char *, int, ndr_ref_t *);
static int ndo_put_pdu(ndr_stream_t *, unsigned long, unsigned long,
    char *, int, ndr_ref_t *);
static void ndo_tattle(ndr_stream_t *, char *, ndr_ref_t *);
static void ndo_tattle_error(ndr_stream_t *, ndr_ref_t *);
static int ndo_reset(ndr_stream_t *);
static void ndo_destruct(ndr_stream_t *);
static void ndo_hexfmt(uint8_t *, int, int, char *, int);

/*
 * The ndr stream operations table.
 */
static ndr_stream_ops_t nds_ops = {
    ndo_malloc,
    ndo_free,
    ndo_grow_pdu,
    ndo_pad_pdu,
    ndo_get_pdu,
    ndo_put_pdu,
    ndo_tattle,
    ndo_tattle_error,
    ndo_reset,
    ndo_destruct
};

/*
 * nds_bswap
 *
 * Copies len bytes from src to dst such that dst contains the bytes
 * from src in reverse order.
 *
 * We expect to be dealing with bytes, words, dwords etc. So the
 * length must be non-zero and a power of 2.
 */
void
nds_bswap(void *srcbuf, void *dstbuf, size_t len)
{
	uint8_t *src = (uint8_t *)srcbuf;
	uint8_t *dst = (uint8_t *)dstbuf;

	if ((len != 0) && ((len & (len - 1)) == 0)) {
		src += len;

		while (len--)
			*dst++ = *(--src);
	}
}

/*
 * nds_initialize
 *
 * Initialize a stream. Sets up the PDU parameters and assigns the stream
 * operations and the reference to the heap. An external heap is provided
 * to the stream, rather than each stream creating its own heap.
 */
int
nds_initialize(ndr_stream_t *nds, unsigned pdu_size_hint,
    int composite_op, ndr_heap_t *heap)
{
	unsigned size;

	assert(nds);
	assert(heap);

	bzero(nds, sizeof (*nds));
	nds->ndo = &nds_ops;
	nds->heap = (struct ndr_heap *)heap;

	if (pdu_size_hint > NDR_PDU_MAX_SIZE) {
		nds->error = NDR_ERR_BOUNDS_CHECK;
		nds->error_ref = __LINE__;
		NDS_TATTLE_ERROR(nds, NULL, NULL);
		return (NDR_DRC_FAULT_RESOURCE_1);
	}

	size = (pdu_size_hint == 0) ? NDR_PDU_BLOCK_SIZE : pdu_size_hint;

	if ((nds->pdu_base_addr = malloc(size)) == NULL) {
		nds->error = NDR_ERR_MALLOC_FAILED;
		nds->error_ref = __LINE__;
		NDS_TATTLE_ERROR(nds, NULL, NULL);
		return (NDR_DRC_FAULT_OUT_OF_MEMORY);
	}

	nds->pdu_max_size = size;
	nds->pdu_size = 0;
	nds->pdu_base_offset = (unsigned long)nds->pdu_base_addr;

	nds->m_op = NDR_MODE_TO_M_OP(composite_op);
	nds->dir  = NDR_MODE_TO_DIR(composite_op);

	nds->outer_queue_tailp = &nds->outer_queue_head;
	return (0);
}

/*
 * nds_destruct
 *
 * Destroy a stream. This is an external interface to provide access to
 * the stream's destruct operation.
 */
void
nds_destruct(ndr_stream_t *nds)
{
	if ((nds == NULL) || (nds->ndo == NULL))
		return;

	NDS_DESTRUCT(nds);
}

/*
 * Print NDR stream state.
 */
void
nds_show_state(ndr_stream_t *nds)
{
	if (nds == NULL) {
		ndo_printf(NULL, NULL, "nds: <null");
		return;
	}

	ndo_printf(NULL, NULL, "nds: base=0x%x, size=%d, max=%d, scan=%d",
	    nds->pdu_base_offset, nds->pdu_size, nds->pdu_max_size,
	    nds->pdu_scan_offset);
}

/*
 * ndo_malloc
 *
 * Allocate memory from the stream heap.
 */
/*ARGSUSED*/
static char *
ndo_malloc(ndr_stream_t *nds, unsigned len, ndr_ref_t *ref)
{
	return (ndr_heap_malloc((ndr_heap_t *)nds->heap, len));
}

/*
 * ndo_free
 *
 * Always succeeds: cannot free individual stream allocations.
 */
/*ARGSUSED*/
static int
ndo_free(ndr_stream_t *nds, char *p, ndr_ref_t *ref)
{
	return (1);
}

/*
 * ndo_grow_pdu
 *
 * This is the only place that should change the size of the PDU. If the
 * desired offset is beyond the current PDU size, we realloc the PDU
 * buffer to accommodate the request. For efficiency, the PDU is always
 * extended to a NDR_PDU_BLOCK_SIZE boundary. Requests to grow the PDU
 * beyond NDR_PDU_MAX_SIZE are rejected.
 *
 * Returns 1 to indicate success. Otherwise 0 to indicate failure.
 */
static int
ndo_grow_pdu(ndr_stream_t *nds, unsigned long want_end_offset, ndr_ref_t *ref)
{
	unsigned char *pdu_addr;
	unsigned pdu_max_size;

	ndo_printf(nds, ref, "grow %d", want_end_offset);

	pdu_max_size = nds->pdu_max_size;

	if (want_end_offset > pdu_max_size) {
		pdu_max_size = NDR_PDU_ALIGN(want_end_offset);

		if (pdu_max_size >= NDR_PDU_MAX_SIZE)
			return (0);

		pdu_addr = realloc(nds->pdu_base_addr, pdu_max_size);
		if (pdu_addr == 0)
			return (0);

		nds->pdu_max_size = pdu_max_size;
		nds->pdu_base_addr = pdu_addr;
		nds->pdu_base_offset = (unsigned long)pdu_addr;
	}

	nds->pdu_size = want_end_offset;
	return (1);
}

static int
ndo_pad_pdu(ndr_stream_t *nds, unsigned long pdu_offset,
    unsigned long n_bytes, ndr_ref_t *ref)
{
	unsigned char *data;

	data = (unsigned char *)nds->pdu_base_offset;
	data += pdu_offset;

	ndo_printf(nds, ref, "pad %d@%-3d", n_bytes, pdu_offset);

	bzero(data, n_bytes);
	return (1);
}

/*
 * ndo_get_pdu
 *
 * The swap flag is 1 if NDR knows that the byte-order in the PDU
 * is different from the local system.
 *
 * Returns 1 on success or 0 to indicate failure.
 */
static int
ndo_get_pdu(ndr_stream_t *nds, unsigned long pdu_offset,
    unsigned long n_bytes, char *buf, int swap_bytes, ndr_ref_t *ref)
{
	unsigned char *data;
	char hexbuf[NDOBUFSZ];

	data = (unsigned char *)nds->pdu_base_offset;
	data += pdu_offset;

	ndo_hexfmt(data, n_bytes, swap_bytes, hexbuf, NDOBUFSZ);

	ndo_printf(nds, ref, "get %d@%-3d = %s",
	    n_bytes, pdu_offset, hexbuf);

	if (!swap_bytes)
		bcopy(data, buf, n_bytes);
	else
		nds_bswap(data, (unsigned char *)buf, n_bytes);

	return (1);
}

/*
 * ndo_put_pdu
 *
 * This is a receiver makes right protocol. So we do not need
 * to be concerned about the byte-order of an outgoing PDU.
 */
/*ARGSUSED*/
static int
ndo_put_pdu(ndr_stream_t *nds, unsigned long pdu_offset,
    unsigned long n_bytes, char *buf, int swap_bytes, ndr_ref_t *ref)
{
	unsigned char *data;
	char hexbuf[NDOBUFSZ];

	data = (unsigned char *)nds->pdu_base_offset;
	data += pdu_offset;

	ndo_hexfmt((uint8_t *)buf, n_bytes, 0, hexbuf, NDOBUFSZ);

	ndo_printf(nds, ref, "put %d@%-3d = %s",
	    n_bytes, pdu_offset, hexbuf);

	bcopy(buf, data, n_bytes);
	return (1);
}

static void
ndo_tattle(ndr_stream_t *nds, char *what, ndr_ref_t *ref)
{
	ndo_printf(nds, ref, what);
}

static void
ndo_tattle_error(ndr_stream_t *nds, ndr_ref_t *ref)
{
	unsigned char *data;
	char hexbuf[NDOBUFSZ];

	if (nds->pdu_base_addr != NULL) {
		data = (unsigned char *)nds->pdu_base_offset;
		if (ref)
			data += ref->pdu_offset;
		else
			data += nds->pdu_scan_offset;

		ndo_hexfmt(data, 16, 0, hexbuf, NDOBUFSZ);
	} else {
		bzero(hexbuf, NDOBUFSZ);
	}

	ndo_printf(nds, ref, "ERROR=%d REF=%d OFFSET=%d SIZE=%d/%d",
	    nds->error, nds->error_ref, nds->pdu_scan_offset,
	    nds->pdu_size, nds->pdu_max_size);
	ndo_printf(nds, ref, "      %s", hexbuf);
}

/*
 * ndo_reset
 *
 * Reset a stream: zap the outer_queue. We don't need to tamper
 * with the stream heap: it's handled externally to the stream.
 */
static int
ndo_reset(ndr_stream_t *nds)
{
	ndo_printf(nds, 0, "reset");

	nds->pdu_size = 0;
	nds->pdu_scan_offset = 0;
	nds->outer_queue_head = 0;
	nds->outer_current = 0;
	nds->outer_queue_tailp = &nds->outer_queue_head;

	return (1);
}

/*
 * ndo_destruct
 *
 * Destruct a stream: zap the outer_queue.
 * Note: heap management (creation/destruction) is external to the stream.
 */
static void
ndo_destruct(ndr_stream_t *nds)
{

	ndo_printf(nds, 0, "destruct");

	if (nds == NULL)
		return;

	if (nds->pdu_base_addr != NULL) {
		free(nds->pdu_base_addr);
		nds->pdu_base_addr = NULL;
		nds->pdu_base_offset = 0;
	}

	nds->outer_queue_head = 0;
	nds->outer_current = 0;
	nds->outer_queue_tailp = &nds->outer_queue_head;
}

/*
 * Printf style formatting for NDR operations.
 */
void
ndo_printf(ndr_stream_t *nds, ndr_ref_t *ref, const char *fmt, ...)
{
	va_list ap;
	char buf[NDOBUFSZ];

	va_start(ap, fmt);
	(void) vsnprintf(buf, NDOBUFSZ, fmt, ap);
	va_end(ap);

	if (nds)
		ndo_fmt(nds, ref, buf);
	else
		ndo_trace(buf);
}

/*
 * Main output formatter for NDR operations.
 *
 *	UI 03 ... rpc_vers           get 1@0   =    5 {05}
 *	UI 03 ... rpc_vers_minor     get 1@1   =    0 {00}
 *
 *	U       Marshalling flag (M=marshal, U=unmarshal)
 *	I       Direction flag (I=in, O=out)
 *	...     Field name
 *	get     PDU operation (get or put)
 *	1@0	Bytes @ offset (i.e. 1 byte at offset 0)
 *	{05}    Value
 */
void
ndo_fmt(ndr_stream_t *nds, ndr_ref_t *ref, char *note)
{
	ndr_ref_t	*p;
	int		indent;
	char		ref_name[NDOBUFSZ];
	char		buf[NDOBUFSZ];
	int		m_op_c = '?', dir_c = '?';

	switch (nds->m_op) {
	case 0:				m_op_c = '-';	break;
	case NDR_M_OP_MARSHALL:		m_op_c = 'M';	break;
	case NDR_M_OP_UNMARSHALL:	m_op_c = 'U';	break;
	default:			m_op_c = '?';	break;
	}

	switch (nds->dir) {
	case 0:				dir_c = '-';	break;
	case NDR_DIR_IN:		dir_c = 'I';	break;
	case NDR_DIR_OUT:		dir_c = 'O';	break;
	default:			dir_c = '?';	break;
	}

	for (indent = 0, p = ref; p; p = p->enclosing)
		indent++;

	if (ref && ref->name) {
		if (*ref->name == '[' && ref->enclosing) {
			indent--;
			(void) snprintf(ref_name, NDOBUFSZ, "%s%s",
			    ref->enclosing->name, ref->name);
		} else {
			(void) strlcpy(ref_name, ref->name, NDOBUFSZ);
		}
	} else {
		(void) strlcpy(ref_name, "----", NDOBUFSZ);
	}

	(void) snprintf(buf, NDOBUFSZ, "%c%c %-.*s %-*s  %s",
	    m_op_c, dir_c, indent,
	    "....+....+....+....+....+....",
	    20 - indent, ref_name, note);

	ndo_trace(buf);
}

/*ARGSUSED*/
void
ndo_trace(const char *s)
{
	/*
	 * Temporary fbt for dtrace until user space sdt enabled.
	 */
}

/*
 * Format data as hex bytes (limit is 10 bytes):
 *
 *	1188689424 {10 f6 d9 46}
 *
 * If the input data is greater than 10 bytes, an ellipsis will
 * be inserted before the closing brace.
 */
static void
ndo_hexfmt(uint8_t *data, int size, int swap_bytes, char *buf, int len)
{
	char *p = buf;
	int interp = 1;
	uint32_t c;
	int n;
	int i;

	n = (size > 10) ? 10 : size;
	if (n > len-1)
		n = len-1;

	switch (size) {
	case 1:
		c = *(uint8_t *)data;
		break;
	case 2:
		if (swap_bytes == 0) /*LINTED E_BAD_PTR_CAST_ALIGN*/
			c = *(uint16_t *)data;
		else
			c = (data[0] << 8) | data[1];
		break;
	case 4:
		if (swap_bytes == 0) { /*LINTED E_BAD_PTR_CAST_ALIGN*/
			c = *(uint32_t *)data;
		} else {
			c = (data[0] << 24) | (data[1] << 16)
			    | (data[2] << 8) | data[3];
		}
		break;
	default:
		c = 0;
		interp = 0;
		break;
	}

	if (interp)
		p += sprintf(p, "%4u {", c);
	else
		p += sprintf(p, " {");

	p += sprintf(p, "%02x", data[0]);
	for (i = 1; i < n; i++)
		p += sprintf(p, " %02x", data[i]);
	if (size > 10)
		p += sprintf(p, " ...}");
	else
		p += sprintf(p, "}");

	/*
	 * Show c if it's a printable character or wide-char.
	 */
	if (size < 4 && isprint((uint8_t)c))
		(void) sprintf(p, " %c", (uint8_t)c);
}
