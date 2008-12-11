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

/*
 * NDR heap management. The heap is used for temporary storage by
 * both the client and server side library routines.  In order to
 * support the different requirements of the various RPCs, the heap
 * can grow dynamically if required.  We start with a single block
 * and perform sub-allocations from it.  If an RPC requires more space
 * we will continue to add it a block at a time.  This means that we
 * don't hog lots of memory on every call to support the few times
 * that we actually need a lot heap space.
 *
 * Note that there is no individual free function.  Once space has been
 * allocated, it remains allocated until the heap is destroyed.  This
 * shouldn't be an issue because the heap is being filled with data to
 * be marshalled or unmarshalled and we need it all to be there until
 * the point that the entire heap is no longer required.
 */

#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/uio.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/smb_sid.h>

/*
 * Allocate a heap structure and the first heap block.  For many RPC
 * operations this will be the only time we need to malloc memory
 * in this instance of the heap.  The only point of note here is that
 * we put the heap management data in the first block to avoid a
 * second malloc. Make sure that sizeof(ndr_heap_t) is smaller
 * than NDR_HEAP_BLKSZ.
 *
 * Note that the heap management data is at the start of the first block.
 *
 * Returns a pointer to the newly created heap, which is used like an
 * opaque handle with the rest of the heap management interface..
 */
ndr_heap_t *
ndr_heap_create(void)
{
	ndr_heap_t *heap;
	char *base;

	if ((base = (char *)malloc(NDR_HEAP_BLKSZ)) == NULL)
		return (NULL);

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	heap = (ndr_heap_t *)base;
	bzero(heap, sizeof (ndr_heap_t));

	heap->iovcnt = NDR_HEAP_MAXIOV;
	heap->iov = heap->iovec;
	heap->iov->iov_base = base;
	heap->iov->iov_len = sizeof (ndr_heap_t);
	heap->top = base + NDR_HEAP_BLKSZ;
	heap->next = base + sizeof (ndr_heap_t);

	return (heap);
}

/*
 * Deallocate all of the memory associated with a heap.  This is the
 * only way to deallocate heap memory, it isn't possible to free the
 * space obtained by individual malloc calls.
 *
 * Note that the first block contains the heap management data, which
 * is deleted last.
 */
void
ndr_heap_destroy(ndr_heap_t *heap)
{
	int i;
	char *p;

	if (heap) {
		for (i = 1; i < NDR_HEAP_MAXIOV; ++i) {
			if ((p = heap->iovec[i].iov_base) != NULL)
				free(p);
		}

		free(heap);
	}
}

/*
 * Allocate space in the specified heap.  All requests are padded, if
 * required, to ensure dword alignment.  If the current iov will be
 * exceeded, we allocate a new block and setup the next iov.  Otherwise
 * all we have to do is move the next pointer and update the current
 * iov length.
 *
 * On success, a pointer to the allocated (dword aligned) area is
 * returned.  Otherwise a null pointer is returned.
 */
void *
ndr_heap_malloc(ndr_heap_t *heap, unsigned size)
{
	char *p;
	int incr_size;

	size += NDR_ALIGN4(size);

	if (heap == NULL || size == 0)
		return (NULL);

	p = heap->next;

	if (p + size > heap->top) {
		if ((heap->iovcnt == 0) || ((--heap->iovcnt) == 0))
			return (NULL);

		incr_size = (size < NDR_HEAP_BLKSZ) ? NDR_HEAP_BLKSZ : size;

		if ((p = (char *)malloc(incr_size)) == NULL)
			return (NULL);

		++heap->iov;
		heap->iov->iov_base = p;
		heap->iov->iov_len = 0;
		heap->top = p + incr_size;
	}

	heap->next = p + size;
	heap->iov->iov_len += size;
	return ((void *)p);
}

/*
 * Convenience function to do heap strdup.
 */
void *
ndr_heap_strdup(ndr_heap_t *heap, const char *s)
{
	int len;
	void *p;

	if (s == NULL)
		return (NULL);

	/*
	 * We don't need to clutter the heap with empty strings.
	 */
	if ((len = strlen(s)) == 0)
		return ("");

	if ((p = ndr_heap_malloc(heap, len+1)) != NULL)
		(void) strcpy((char *)p, s);

	return (p);
}

/*
 * Make an ndr_mstring_t from a regular string.
 */
int
ndr_heap_mstring(ndr_heap_t *heap, const char *s, ndr_mstring_t *out)
{
	if (s == NULL || out == NULL)
		return (-1);

	out->length = mts_wcequiv_strlen(s);
	out->allosize = out->length + sizeof (mts_wchar_t);

	if ((out->str = ndr_heap_strdup(heap, s)) == NULL)
		return (-1);

	return (0);
}

/*
 * Our regular string marshalling always creates null terminated strings
 * but some Windows clients and servers are pedantic about the string
 * formats they will accept and require non-null terminated strings.
 * This function can be used to build a wide-char, non-null terminated
 * string in the heap as a varying/conformant array.  We need to do the
 * wide-char conversion here because the marshalling code won't be
 * aware that this is really a string.
 */
void
ndr_heap_mkvcs(ndr_heap_t *heap, char *s, ndr_vcstr_t *vc)
{
	int mlen;

	vc->wclen = mts_wcequiv_strlen(s);
	vc->wcsize = vc->wclen;

	mlen = sizeof (ndr_vcs_t) + vc->wcsize + sizeof (mts_wchar_t);

	vc->vcs = ndr_heap_malloc(heap, mlen);

	if (vc->vcs) {
		vc->vcs->vc_first_is = 0;
		vc->vcs->vc_length_is = vc->wclen / sizeof (mts_wchar_t);
		(void) mts_mbstowcs((mts_wchar_t *)vc->vcs->buffer, s,
		    vc->vcs->vc_length_is);
	}
}

void
ndr_heap_mkvcb(ndr_heap_t *heap, uint8_t *data, uint32_t datalen,
    ndr_vcbuf_t *vcbuf)
{
	int mlen;

	if (data == NULL || datalen == 0) {
		bzero(vcbuf, sizeof (ndr_vcbuf_t));
		return;
	}

	vcbuf->len = datalen;
	vcbuf->size = datalen;

	mlen = sizeof (ndr_vcbuf_t) + datalen;

	vcbuf->vcb = ndr_heap_malloc(heap, mlen);

	if (vcbuf->vcb) {
		vcbuf->vcb->vc_first_is = 0;
		vcbuf->vcb->vc_length_is = datalen;
		bcopy(data, vcbuf->vcb->buffer, datalen);
	}
}

/*
 * Duplcate a SID in the heap.
 */
smb_sid_t *
ndr_heap_siddup(ndr_heap_t *heap, smb_sid_t *sid)
{
	smb_sid_t *new_sid;
	unsigned size;

	if (sid == NULL)
		return (NULL);

	size = smb_sid_len(sid);

	if ((new_sid = ndr_heap_malloc(heap, size)) == NULL)
		return (NULL);

	bcopy(sid, new_sid, size);
	return (new_sid);
}

int
ndr_heap_used(ndr_heap_t *heap)
{
	int used = 0;
	int i;

	for (i = 0; i < NDR_HEAP_MAXIOV; ++i)
		used += heap->iovec[i].iov_len;

	return (used);
}

int
ndr_heap_avail(ndr_heap_t *heap)
{
	int avail;
	int count;

	count = (heap->iovcnt == 0) ? 0 : (heap->iovcnt - 1);

	avail = count * NDR_HEAP_BLKSZ;
	avail += (heap->top - heap->next);

	return (avail);
}
