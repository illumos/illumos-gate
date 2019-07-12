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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/alloc.h>

#define	SMB_SMH_MAGIC		0x534D485F	/* 'SMH_' */
#define	SMB_SMH_VALID(_smh_)	ASSERT((_smh_)->smh_magic == SMB_SMH_MAGIC)
#define	SMB_MEM2SMH(_mem_)	((smb_mem_header_t *)(_mem_) - 1)

typedef struct smb_mem_header {
	uint32_t	smh_magic;
	size_t		smh_size;
	smb_request_t	*smh_sr;
	list_node_t	smh_lnd;
} smb_mem_header_t;

static void *smb_alloc(smb_request_t *, size_t, boolean_t);
static void smb_free(smb_request_t *, void *, boolean_t);
static void *smb_realloc(smb_request_t *, void *, size_t, boolean_t);

/*
 * Allocate memory.
 */
void *
smb_mem_alloc(size_t size)
{
	return (smb_alloc(NULL, size, B_FALSE));
}

/*
 * Allocate memory and zero it out.
 */
void *
smb_mem_zalloc(size_t size)
{
	return (smb_alloc(NULL, size, B_TRUE));
}

/*
 * Allocate or resize memory previously allocated.
 *
 * The address passed in MUST be considered invalid when this function returns.
 */
void *
smb_mem_realloc(void *ptr, size_t size)
{
	return (smb_realloc(NULL, ptr, size, B_FALSE));
}

/*
 * Allocate or resize memory previously allocated. If the new size is greater
 * than the current size, the extra space is zeroed out. If the new size is less
 * then the current size the space truncated is zeroed out.
 *
 * The address passed in MUST be considered invalid when this function returns.
 */
void *
smb_mem_rezalloc(void *ptr, size_t size)
{
	return (smb_realloc(NULL, ptr, size, B_TRUE));
}

/*
 * Free memory previously allocated with smb_malloc(), smb_zalloc(),
 * smb_remalloc() or smb_rezalloc().
 */
void
smb_mem_free(void *ptr)
{
	smb_free(NULL, ptr, B_FALSE);
}

/*
 * Free memory previously allocated with smb_mem_malloc(), smb_mem_zalloc(),
 * smb_mem_remalloc() or smb_mem_rezalloc() or smb_mem_strdup(). The memory will
 * be zeroed out before being actually freed.
 */
void
smb_mem_zfree(void *ptr)
{
	smb_free(NULL, ptr, B_TRUE);
}

/*
 * Duplicate a string.
 */
char *
smb_mem_strdup(const char *ptr)
{
	char	*p;
	size_t	size;

	size = strlen(ptr) + 1;
	p = smb_alloc(NULL, size, B_FALSE);
	bcopy(ptr, p, size);
	return (p);
}

/*
 * Initialize the list for request-specific temporary storage.
 */
void
smb_srm_init(smb_request_t *sr)
{
	list_create(&sr->sr_storage, sizeof (smb_mem_header_t),
	    offsetof(smb_mem_header_t, smh_lnd));
}

/*
 * Free everything on the request-specific temporary storage list and destroy
 * the list.
 */
void
smb_srm_fini(smb_request_t *sr)
{
	smb_mem_header_t	*smh;

	while ((smh = list_head(&sr->sr_storage)) != NULL)
		smb_free(sr, ++smh, B_FALSE);
	list_destroy(&sr->sr_storage);
}

/*
 * Allocate memory and associate it with the specified request.
 * Memory allocated here can only be used for the duration of this request; it
 * will be freed automatically on completion of the request.
 */
void *
smb_srm_alloc(smb_request_t *sr, size_t size)
{
	return (smb_alloc(sr, size, B_FALSE));
}

/*
 * Allocate memory, zero it out and associate it with the specified request.
 * Memory allocated here can only be used for the duration of this request; it
 * will be freed automatically on completion of the request.
 */
void *
smb_srm_zalloc(smb_request_t *sr, size_t size)
{
	return (smb_alloc(sr, size, B_TRUE));
}

/*
 * Allocate or resize memory previously allocated for the specified request.
 *
 * The address passed in MUST be considered invalid when this function returns.
 */
void *
smb_srm_realloc(smb_request_t *sr, void *p, size_t size)
{
	return (smb_realloc(sr, p, size, B_FALSE));
}

/*
 * Allocate or resize memory previously allocated for the specified request. If
 * the new size is greater than the current size, the extra space is zeroed out.
 * If the new size is less then the current size the space truncated is zeroed
 * out.
 *
 * The address passed in MUST be considered invalid when this function returns.
 */
void *
smb_srm_rezalloc(smb_request_t *sr, void *p, size_t size)
{
	return (smb_realloc(sr, p, size, B_TRUE));
}

char *
smb_srm_strdup(smb_request_t *sr, const char *s)
{
	char	*p;
	size_t	size;

	size = strlen(s) + 1;
	p = smb_srm_alloc(sr, size);
	bcopy(s, p, size);
	return (p);
}

/*
 * Allocate memory.
 *
 * sr	If not NULL, request the memory allocated must be associated with.
 *
 * size	Size of the meory to allocate.
 *
 * zero	If true the memory allocated will be zeroed out.
 */
static void *
smb_alloc(smb_request_t *sr, size_t size, boolean_t zero)
{
	smb_mem_header_t	*smh;

	if (zero) {
		smh = kmem_zalloc(size + sizeof (smb_mem_header_t), KM_SLEEP);
	} else {
		smh = kmem_alloc(size + sizeof (smb_mem_header_t), KM_SLEEP);
		smh->smh_sr = NULL;
		bzero(&smh->smh_lnd, sizeof (smh->smh_lnd));
	}
	smh->smh_sr = sr;
	smh->smh_size = size;
	smh->smh_magic = SMB_SMH_MAGIC;
	if (sr != NULL) {
		SMB_REQ_VALID(sr);
		list_insert_tail(&sr->sr_storage, smh);
	}
	return (++smh);
}

/*
 * Free memory.
 *
 * sr	If not NULL, request the memory to free is associated with.
 *
 * ptr	Memory address
 *
 * zero	If true the memory is zeroed out before being freed.
 */
static void
smb_free(smb_request_t *sr, void *ptr, boolean_t zero)
{
	smb_mem_header_t	*smh;

	if (ptr != NULL) {
		smh = SMB_MEM2SMH(ptr);
		SMB_SMH_VALID(smh);
		ASSERT(sr == smh->smh_sr);
		if (sr != NULL) {
			SMB_REQ_VALID(sr);
			list_remove(&sr->sr_storage, smh);
		}
		if (zero)
			bzero(ptr, smh->smh_size);

		smh->smh_magic = 0;
		kmem_free(smh, smh->smh_size + sizeof (smb_mem_header_t));
	}
}

/*
 * Allocate or resize memory previously allocated.
 *
 * sr	If not NULL, request the memory is associated with.
 *
 * ptr	Memory address
 *
 * size	New size
 *
 * zero	If true zero out the extra space or the truncated space.
 */
static void *
smb_realloc(smb_request_t *sr, void *ptr, size_t size, boolean_t zero)
{
	smb_mem_header_t	*smh;
	void			*new_ptr;

	if (ptr == NULL)
		return (smb_alloc(sr, size, zero));

	smh = SMB_MEM2SMH(ptr);
	SMB_SMH_VALID(smh);
	ASSERT(sr == smh->smh_sr);

	if (size == 0) {
		smb_free(sr, ptr, zero);
		return (NULL);
	}
	if (smh->smh_size >= size) {
		if ((zero) && (smh->smh_size > size))
			bzero((caddr_t)ptr + size, smh->smh_size - size);
		return (ptr);
	}
	new_ptr = smb_alloc(sr, size, B_FALSE);
	bcopy(ptr, new_ptr, smh->smh_size);
	if (zero)
		bzero((caddr_t)new_ptr + smh->smh_size, size - smh->smh_size);

	smb_free(sr, ptr, zero);
	return (new_ptr);
}
