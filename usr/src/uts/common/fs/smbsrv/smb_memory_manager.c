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

/*
 * Memory management functions.
 */

#include <smbsrv/smb_incl.h>

/*
 * smbsr_malloc
 *
 * allocate a block of memory with the given size and
 * add it to the given linked list. This function is
 * used to allocate temporary memories which are needed
 * during processing of a SMB request. These memories
 * get freed when request processing is finished.
 */
void *
smbsr_malloc(smb_malloc_list *list, size_t size)
{
	smb_malloc_list *element;

	size += sizeof (smb_malloc_list);
	element = MEM_MALLOC("smb", size);
	element->forw = list->forw;
	element->back = list;
	list->forw->back = element;
	list->forw = element;
	return (void *)(element + 1); /* return address of data */
}

/*
 * smbsr_realloc
 *
 * This function is used in conjunction with smbsr_malloc to
 * resize an already allocated entity.
 */
void *
smbsr_realloc(void *mem, size_t size)
{
	smb_malloc_list 	*element = (smb_malloc_list *)mem;
	smb_malloc_list 	*new_entry;
	smb_malloc_list 	*list;

	element--;
	list = element->back;
	QUEUE_CLIP(element);
	size += sizeof (smb_malloc_list);

	new_entry = MEM_REALLOC("smb", element, size);
	new_entry->forw = list->forw;
	new_entry->back = list;
	list->forw->back = new_entry;
	list->forw = new_entry;
	return (void *)(new_entry + 1); /* return address of new data */
}

/*
 * smbsr_free_malloc_list
 *
 * Frees all memory block in the given linked list.
 */
void
smbsr_free_malloc_list(smb_malloc_list *root)
{
	smb_malloc_list	*element;

	/*
	 * we initialize smb_request structure in smb_nt_notify_change
	 * function, so we should check root->forw to make sure it's
	 * not NULL.
	 */
	while (root->forw && root->forw != root) {
		element = root->forw;

		element->forw->back = element->back;
		element->back->forw = element->forw;

		/* and release it... */
		MEM_FREE("smb", element);
	}
}
