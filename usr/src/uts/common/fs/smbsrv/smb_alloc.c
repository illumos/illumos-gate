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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <smbsrv/alloc.h>

#define	MEM_HDR_SIZE	8
static uint32_t mem_get_size(void *ptr);

void *
mem_malloc(uint32_t size)
{
	uint8_t *p;

	size += MEM_HDR_SIZE;
	p = kmem_alloc(size, KM_SLEEP);
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	*(uint32_t *)p = size;
	p += MEM_HDR_SIZE;

	return (p);
}

void *
mem_zalloc(uint32_t size)
{
	uint8_t *p;

	p = mem_malloc(size);
	(void) memset(p, 0, size);
	return (p);
}

char *
mem_strdup(const char *ptr)
{
	char *p;
	size_t size;

	size = strlen(ptr) + 1;
	p = mem_malloc(size);
	(void) memcpy(p, ptr, size);
	return (p);
}

static uint32_t
mem_get_size(void *ptr)
{
	uint32_t *p;

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	p = (uint32_t *)((uint8_t *)ptr - MEM_HDR_SIZE);

	return (*p);
}

void *
mem_realloc(void *ptr, uint32_t size)
{
	void *new_ptr;

	if (ptr == NULL)
		return (mem_malloc(size));

	if (size == 0) {
		smb_mem_free(ptr);
		return (NULL);
	}

	new_ptr = mem_malloc(size);
	(void) memcpy(new_ptr, ptr, mem_get_size(ptr));
	smb_mem_free(ptr);

	return (new_ptr);
}

void
smb_mem_free(void *ptr)
{
	uint8_t *p;

	if (ptr == 0)
		return;

	p = (uint8_t *)ptr - MEM_HDR_SIZE;
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	kmem_free(p, *(uint32_t *)p);
}
