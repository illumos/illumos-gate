/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1991-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * zmalloc	- use mmap(2) to allocate memory from /dev/zero.
 * zfree	- use munmap(2) to unmap (free) memory.
 *
 * These functions should be better than malloc(3) for large memory allocation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <zmalloc.h>

/*
 * a utility structure to keep track of the (possibly) multiple mmaps
 * that we have done...
 */
struct buffer_map {
	struct buffer_map *bm_next;
	char *bm_buffer;
	int bm_size;
};

static  void *bm_empty = (void *) "";		/* special buffer */
static	struct buffer_map *bm_list;		/* NULL by default */

static struct buffer_map *
insert_bm(char *buf, size_t size)
{
	struct buffer_map *bm;

	bm = (struct buffer_map *)malloc(sizeof (struct buffer_map));
	bm->bm_buffer = buf;
	bm->bm_size = size;
	bm->bm_next = bm_list;

	bm_list = bm;

	return (bm_list);
}

static size_t
delete_bm(char *buf)
{
	size_t size;
	register struct buffer_map *p_curr;
	register struct buffer_map *p_prev;

	p_prev = NULL;
	p_curr = bm_list;
	while (p_curr != NULL) {
		if (p_curr->bm_buffer == buf) {
			if (p_prev == NULL)
				bm_list = p_curr->bm_next;
			else
				p_prev->bm_next = p_curr->bm_next;
			size = p_curr->bm_size;
			free(p_curr);
			return (size);
		}

		p_prev = p_curr;
		p_curr = p_curr->bm_next;
	}
	return (0);
}

void *
zmalloc(size_t size)
{
	int	fd;
	caddr_t	mbuf;

	/* XXX - Special case: never allocate 0 bytes, use a special buffer */
	if (size == 0)
	    return ((void *)NULL); /* return (bm_empty); */

	if ((fd = open("/dev/zero", O_RDWR)) < 0) {
		perror("/dev/zero");
		return ((void *) NULL);
	}

	mbuf = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	(void) close(fd);

	if (mbuf == (caddr_t)-1) {
		perror("zmalloc: mmap");
		return ((void *) NULL);
	}

	(void) insert_bm(mbuf, size);

	return ((void *) mbuf);
}

void
zfree(void* mbuf)
{
	size_t size;

	if (mbuf == bm_empty)
	    return;

	if (mbuf != NULL) {
		if ((size = delete_bm((caddr_t)mbuf)) != 0) {
			if (munmap((char *)mbuf, size) < 0)
			    perror("zfree: munmap");
		}
	}
}
