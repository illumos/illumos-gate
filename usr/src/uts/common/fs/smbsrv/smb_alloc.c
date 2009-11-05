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
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/alloc.h>

#define	MEM_HDR_SIZE	8
static uint32_t smb_memsize(void *);

void *
smb_malloc(uint32_t size)
{
	uint32_t	*hdr;
	uint8_t		*p;

	size += MEM_HDR_SIZE;
	hdr = kmem_zalloc(size, KM_SLEEP);
	*hdr = size;

	p = (uint8_t *)hdr;
	p += MEM_HDR_SIZE;
	return (p);
}

char *
smb_strdup(const char *ptr)
{
	char	*p;
	size_t	size;

	size = strlen(ptr) + 1;
	p = smb_malloc(size);
	(void) memcpy(p, ptr, size);
	return (p);
}

static uint32_t
smb_memsize(void *ptr)
{
	uint32_t	*p;

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	p = (uint32_t *)((uint8_t *)ptr - MEM_HDR_SIZE);

	return (*p);
}

void *
smb_realloc(void *ptr, uint32_t size)
{
	void		*new_ptr;
	uint32_t	current_size;


	if (ptr == NULL)
		return (smb_malloc(size));

	if (size == 0) {
		smb_mfree(ptr);
		return (NULL);
	}

	current_size = smb_memsize(ptr) - MEM_HDR_SIZE;
	if (size <= current_size)
		return (ptr);

	new_ptr = smb_malloc(size);
	(void) memcpy(new_ptr, ptr, current_size);
	smb_mfree(ptr);

	return (new_ptr);
}

void
smb_mfree(void *ptr)
{
	uint8_t	*p;

	if (ptr == NULL)
		return;

	p = (uint8_t *)ptr - MEM_HDR_SIZE;
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	kmem_free(p, *(uint32_t *)p);
}

/*
 * Initialize the list for request-specific temporary storage.
 */
void
smb_srm_init(smb_request_t *sr)
{
	list_create(&sr->sr_storage, sizeof (smb_srm_t),
	    offsetof(smb_srm_t, srm_lnd));
}

/*
 * Free everything on the request-specific temporary storage list
 * and destroy the list.
 */
void
smb_srm_fini(smb_request_t *sr)
{
	smb_srm_t	*srm;

	while ((srm = list_head(&sr->sr_storage)) != NULL) {
		list_remove(&sr->sr_storage, srm);
		smb_mfree(srm);
	}

	list_destroy(&sr->sr_storage);
}

/*
 * Allocate memory and associate it with the specified request.
 * Memory allocated here can only be used for the duration of
 * this request; it will be freed automatically on completion
 * of the request
 */
void *
smb_srm_alloc(smb_request_t *sr, size_t size)
{
	smb_srm_t	*srm;

	size += sizeof (smb_srm_t);
	srm = smb_malloc(size);
	srm->srm_size = size;
	srm->srm_sr = sr;
	list_insert_tail(&sr->sr_storage, srm);

	/*
	 * The memory allocated for use be the caller is
	 * immediately after our storage context area.
	 */
	return (void *)(srm + 1);
}

/*
 * Allocate or resize memory previously allocated for the specified
 * request.
 */
void *
smb_srm_realloc(smb_request_t *sr, void *p, size_t size)
{
	smb_srm_t 	*old_srm = (smb_srm_t *)p;
	smb_srm_t 	*new_srm;

	if (old_srm == NULL)
		return (smb_srm_alloc(sr, size));

	old_srm--;
	list_remove(&sr->sr_storage, old_srm);

	size += sizeof (smb_srm_t);
	new_srm = smb_realloc(old_srm, size);
	new_srm->srm_size = smb_memsize(new_srm);
	new_srm->srm_sr = sr;
	list_insert_tail(&sr->sr_storage, new_srm);

	/*
	 * The memory allocated for use be the caller is
	 * immediately after our storage context area.
	 */
	return (void *)(new_srm + 1);
}
