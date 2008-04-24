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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MLRPC server-side NDR stream (PDU) operations. Stream operations
 * should return TRUE (non-zero) on success or FALSE (zero or a null
 * pointer) on failure. When an operation returns FALSE, including
 * mlndo_malloc() returning NULL, it should set the mlnds->error to
 * indicate what went wrong.
 *
 * When available, the relevant ndr_reference is passed to the
 * operation but keep in mind that it may be a null pointer.
 *
 * Functions mlndo_get_pdu(), mlndo_put_pdu(), and mlndo_pad_pdu()
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

#include <smbsrv/libsmb.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/ndr.h>
#include <smbsrv/ntstatus.h>

#define	NDOBUFSZ		128

#define	NDR_PDU_BLOCK_SIZE	(4*1024)
#define	NDR_PDU_BLOCK_MASK	(NDR_PDU_BLOCK_SIZE - 1)
#define	NDR_PDU_ALIGN(N) \
	(((N) + NDR_PDU_BLOCK_SIZE) & ~NDR_PDU_BLOCK_MASK)
#define	NDR_PDU_MAX_SIZE		(64*1024*1024)

static char *mlndo_malloc(struct mlndr_stream *, unsigned,
    struct ndr_reference *);
static int mlndo_free(struct mlndr_stream *, char *, struct ndr_reference *);
static int mlndo_grow_pdu(struct mlndr_stream *, unsigned long,
    struct ndr_reference *);
static int mlndo_pad_pdu(struct mlndr_stream *, unsigned long, unsigned long,
    struct ndr_reference *);
static int mlndo_get_pdu(struct mlndr_stream *, unsigned long, unsigned long,
    char *, int, struct ndr_reference *);
static int mlndo_put_pdu(struct mlndr_stream *, unsigned long, unsigned long,
    char *, int, struct ndr_reference *);
static void mlndo_tattle(struct mlndr_stream *, char *, struct ndr_reference *);
static void mlndo_tattle_error(struct mlndr_stream *, struct ndr_reference *);
static int mlndo_reset(struct mlndr_stream *);
static void mlndo_destruct(struct mlndr_stream *);
static void mlndo_hexfmt(uint8_t *, int, int, char *, int);

/*
 * The mlndr stream operations table.
 */
static struct mlndr_stream_ops mlnds_ops = {
    mlndo_malloc,
    mlndo_free,
    mlndo_grow_pdu,
    mlndo_pad_pdu,
    mlndo_get_pdu,
    mlndo_put_pdu,
    mlndo_tattle,
    mlndo_tattle_error,
    mlndo_reset,
    mlndo_destruct
};

/*
 * mlnds_bswap
 *
 * Copies len bytes from src to dst such that dst contains the bytes
 * from src in reverse order.
 *
 * We expect to be dealing with bytes, words, dwords etc. So the
 * length must be non-zero and a power of 2.
 */
void
mlnds_bswap(void *srcbuf, void *dstbuf, size_t len)
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
 * mlnds_initialize
 *
 * Initialize a stream. Sets up the PDU parameters and assigns the stream
 * operations and the reference to the heap. An external heap is provided
 * to the stream, rather than each stream creating its own heap.
 */
int
mlnds_initialize(struct mlndr_stream *mlnds, unsigned pdu_size_hint,
    int composite_op, mlrpc_heap_t *heap)
{
	unsigned size;

	assert(mlnds);
	assert(heap);

	bzero(mlnds, sizeof (*mlnds));

	if (pdu_size_hint > NDR_PDU_MAX_SIZE)
		return (0);

	size = (pdu_size_hint == 0) ? NDR_PDU_BLOCK_SIZE : pdu_size_hint;
	mlnds->pdu_base_addr = malloc(size);
	assert(mlnds->pdu_base_addr);

	mlnds->pdu_max_size = size;
	mlnds->pdu_size = 0;
	mlnds->pdu_base_offset = (unsigned long)mlnds->pdu_base_addr;

	mlnds->mlndo = &mlnds_ops;
	mlnds->heap = (struct mlrpc_heap *)heap;

	mlnds->m_op = composite_op & 0x0F;
	mlnds->dir  = composite_op & 0xF0;

	mlnds->outer_queue_tailp = &mlnds->outer_queue_head;
	return (1);
}

int
mlnds_finalize(struct mlndr_stream *mlnds, uint8_t *buf, uint32_t buflen)
{
	ndr_frag_t *frag;
	uint32_t size = 0;

	for (frag = mlnds->head; frag; frag = frag->next)
		size += frag->len;

	if (size == 0 || size >= NDR_PDU_MAX_SIZE || size > buflen)
		return (0);

	for (frag = mlnds->head; frag; frag = frag->next) {
		bcopy(frag->buf, buf, frag->len);
		buf += frag->len;
	}

	return (size);
}

/*
 * mlnds_destruct
 *
 * Destroy a stream. This is an external interface to provide access to
 * the stream's destruct operation.
 */
void
mlnds_destruct(struct mlndr_stream *mlnds)
{
	MLNDS_DESTRUCT(mlnds);
}

/*
 * mlndo_malloc
 *
 * Allocate memory from the stream heap.
 */
/*ARGSUSED*/
static char *
mlndo_malloc(struct mlndr_stream *mlnds, unsigned len,
    struct ndr_reference *ref)
{
	return (mlrpc_heap_malloc((mlrpc_heap_t *)mlnds->heap, len));
}

/*
 * mlndo_free
 *
 * Always succeeds: cannot free individual stream allocations.
 */
/*ARGSUSED*/
static int
mlndo_free(struct mlndr_stream *mlnds, char *p, struct ndr_reference *ref)
{
	return (1);
}

/*
 * mlndo_grow_pdu
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
mlndo_grow_pdu(struct mlndr_stream *mlnds, unsigned long want_end_offset,
    struct ndr_reference *ref)
{
	unsigned char *pdu_addr;
	unsigned pdu_max_size;

	mlndo_printf(mlnds, ref, "grow %d", want_end_offset);

	pdu_max_size = mlnds->pdu_max_size;

	if (want_end_offset > pdu_max_size) {
		pdu_max_size = NDR_PDU_ALIGN(want_end_offset);

		if (pdu_max_size >= NDR_PDU_MAX_SIZE)
			return (0);

		pdu_addr = realloc(mlnds->pdu_base_addr, pdu_max_size);
		if (pdu_addr == 0)
			return (0);

		mlnds->pdu_max_size = pdu_max_size;
		mlnds->pdu_base_addr = pdu_addr;
		mlnds->pdu_base_offset = (unsigned long)pdu_addr;
	}

	mlnds->pdu_size = want_end_offset;
	return (1);
}

static int
mlndo_pad_pdu(struct mlndr_stream *mlnds, unsigned long pdu_offset,
    unsigned long n_bytes, struct ndr_reference *ref)
{
	unsigned char *data;

	data = (unsigned char *)mlnds->pdu_base_offset;
	data += pdu_offset;

	mlndo_printf(mlnds, ref, "pad %d@%-3d", n_bytes, pdu_offset);

	bzero(data, n_bytes);
	return (1);
}

/*
 * mlndo_get_pdu
 *
 * The swap flag is 1 if NDR knows that the byte-order in the PDU
 * is different from the local system.
 *
 * Returns 1 on success or 0 to indicate failure.
 */
static int
mlndo_get_pdu(struct mlndr_stream *mlnds, unsigned long pdu_offset,
    unsigned long n_bytes, char *buf, int swap_bytes,
    struct ndr_reference *ref)
{
	unsigned char *data;
	char hexbuf[NDOBUFSZ];

	data = (unsigned char *)mlnds->pdu_base_offset;
	data += pdu_offset;

	mlndo_hexfmt(data, n_bytes, swap_bytes, hexbuf, NDOBUFSZ);

	mlndo_printf(mlnds, ref, "get %d@%-3d = %s",
	    n_bytes, pdu_offset, hexbuf);

	if (!swap_bytes)
		bcopy(data, buf, n_bytes);
	else
		mlnds_bswap(data, (unsigned char *)buf, n_bytes);

	return (1);
}

/*
 * mlndo_put_pdu
 *
 * This is a receiver makes right protocol. So we do not need
 * to be concerned about the byte-order of an outgoing PDU.
 */
/*ARGSUSED*/
static int
mlndo_put_pdu(struct mlndr_stream *mlnds, unsigned long pdu_offset,
    unsigned long n_bytes, char *buf, int swap_bytes,
    struct ndr_reference *ref)
{
	unsigned char *data;
	char hexbuf[NDOBUFSZ];

	data = (unsigned char *)mlnds->pdu_base_offset;
	data += pdu_offset;

	mlndo_hexfmt((uint8_t *)buf, n_bytes, 0, hexbuf, NDOBUFSZ);

	mlndo_printf(mlnds, ref, "put %d@%-3d = %s",
	    n_bytes, pdu_offset, hexbuf);

	bcopy(buf, data, n_bytes);
	return (1);
}

static void
mlndo_tattle(struct mlndr_stream *mlnds, char *what,
    struct ndr_reference *ref)
{
	mlndo_printf(mlnds, ref, what);
}

static void
mlndo_tattle_error(struct mlndr_stream *mlnds, struct ndr_reference *ref)
{
	unsigned char *data;
	char hexbuf[NDOBUFSZ];

	data = (unsigned char *)mlnds->pdu_base_offset;
	if (ref)
		data += ref->pdu_offset;
	else
		data += mlnds->pdu_scan_offset;

	mlndo_hexfmt(data, 16, 0, hexbuf, NDOBUFSZ);

	mlndo_printf(mlnds, ref, "ERROR=%d REF=%d OFFSET=%d SIZE=%d/%d",
	    mlnds->error, mlnds->error_ref, mlnds->pdu_scan_offset,
	    mlnds->pdu_size, mlnds->pdu_max_size);
	mlndo_printf(mlnds, ref, "      %s", hexbuf);
}

/*
 * mlndo_reset
 *
 * Reset a stream: zap the outer_queue. We don't need to tamper
 * with the stream heap: it's handled externally to the stream.
 */
static int
mlndo_reset(struct mlndr_stream *mlnds)
{
	mlndo_printf(mlnds, 0, "reset");

	mlnds->pdu_size = 0;
	mlnds->pdu_scan_offset = 0;
	mlnds->outer_queue_head = 0;
	mlnds->outer_current = 0;
	mlnds->outer_queue_tailp = &mlnds->outer_queue_head;

	return (1);
}

/*
 * mlndo_destruct
 *
 * Destruct a stream: zap the outer_queue.
 * Note: heap management (creation/destruction) is external to the stream.
 */
static void
mlndo_destruct(struct mlndr_stream *mlnds)
{
	ndr_frag_t *frag;

	mlndo_printf(mlnds, 0, "destruct");

	if (mlnds->pdu_base_addr != NULL) {
		free(mlnds->pdu_base_addr);
		mlnds->pdu_base_addr = NULL;
		mlnds->pdu_base_offset = 0;
	}

	while ((frag = mlnds->head) != NULL) {
		mlnds->head = frag->next;
		free(frag);
	}

	mlnds->head = NULL;
	mlnds->tail = NULL;
	mlnds->outer_queue_head = 0;
	mlnds->outer_current = 0;
	mlnds->outer_queue_tailp = &mlnds->outer_queue_head;
}

/*
 * Printf style formatting for NDR operations.
 */
void
mlndo_printf(struct mlndr_stream *mlnds, struct ndr_reference *ref,
    const char *fmt, ...)
{
	va_list ap;
	char buf[NDOBUFSZ];

	va_start(ap, fmt);
	(void) vsnprintf(buf, NDOBUFSZ, fmt, ap);
	va_end(ap);

	if (mlnds)
		mlndo_fmt(mlnds, ref, buf);
	else
		mlndo_trace(buf);
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
mlndo_fmt(struct mlndr_stream *mlnds, struct ndr_reference *ref, char *note)
{
	struct ndr_reference *p;
	int			indent;
	char			ref_name[NDOBUFSZ];
	char			buf[NDOBUFSZ];
	int			m_op_c = '?', dir_c = '?';

	switch (mlnds->m_op) {
	case 0:				m_op_c = '-';	break;
	case NDR_M_OP_MARSHALL:		m_op_c = 'M';	break;
	case NDR_M_OP_UNMARSHALL:	m_op_c = 'U';	break;
	default:			m_op_c = '?';	break;
	}

	switch (mlnds->dir) {
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

	(void) snprintf(buf, NDOBUFSZ, "%c%c %02d %-.*s %-*s  %s",
	    m_op_c, dir_c, indent, indent,
	    "....+....+....+....+....+....",
	    20 - indent, ref_name, note);

	mlndo_trace(buf);
}

/*ARGSUSED*/
void
mlndo_trace(const char *s)
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
mlndo_hexfmt(uint8_t *data, int size, int swap_bytes, char *buf, int len)
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
