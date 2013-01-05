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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
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

#include <libmlrpc.h>
#include <ndr_wchar.h>

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
	size_t allocsize = sizeof (ndr_heap_t) + NDR_HEAP_BLKSZ;

	if ((heap = malloc(allocsize)) == NULL)
		return (NULL);

	base = (char *)heap;
	bzero(heap, sizeof (ndr_heap_t));

	heap->iovcnt = NDR_HEAP_MAXIOV;
	heap->iov = heap->iovec;
	heap->iov->iov_base = base;
	heap->iov->iov_len = sizeof (ndr_heap_t);
	heap->top = base + allocsize;
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
 * Convenience function to copy some memory into the heap.
 */
void *
ndr_heap_dupmem(ndr_heap_t *heap, const void *mem, size_t len)
{
	void *p;

	if (mem == NULL)
		return (NULL);

	if ((p = ndr_heap_malloc(heap, len)) != NULL)
		(void) memcpy(p, mem, len);

	return (p);
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

	p = ndr_heap_dupmem(heap, s, len+1);

	return (p);
}

/*
 * Make an ndr_mstring_t from a regular string.
 */
int
ndr_heap_mstring(ndr_heap_t *heap, const char *s, ndr_mstring_t *out)
{
	size_t slen;

	if (s == NULL || out == NULL)
		return (-1);

	/*
	 * Determine the WC strlen of s
	 * Was ndr__wcequiv_strlen(s)
	 */
	slen = ndr__mbstowcs(NULL, s, NDR_STRING_MAX);
	if (slen == (size_t)-1)
		return (-1);

	out->length = slen * sizeof (ndr_wchar_t);
	out->allosize = out->length + sizeof (ndr_wchar_t);

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
	size_t slen;
	int mlen;

	/*
	 * Determine the WC strlen of s
	 * Was ndr__wcequiv_strlen(s)
	 */
	slen = ndr__mbstowcs(NULL, s, NDR_STRING_MAX);
	if (slen == (size_t)-1)
		slen = 0;

	vc->wclen = slen * sizeof (ndr_wchar_t);
	vc->wcsize = vc->wclen;

	/*
	 * alloc one extra wchar for a null
	 * See slen + 1 arg for mbstowcs
	 */
	mlen = sizeof (ndr_vcs_t) + vc->wcsize + sizeof (ndr_wchar_t);
	vc->vcs = ndr_heap_malloc(heap, mlen);

	if (vc->vcs) {
		vc->vcs->vc_first_is = 0;
		vc->vcs->vc_length_is = slen;
		(void) ndr__mbstowcs(vc->vcs->buffer, s, slen + 1);
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
 * Removed ndr_heap_siddup(), now using ndr_heap_dupmem().
 */

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
