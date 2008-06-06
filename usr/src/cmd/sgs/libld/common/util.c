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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utility functions
 */
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <sgs.h>
#include <libintl.h>
#include <debug.h>
#include "msg.h"
#include "_libld.h"

/*
 * libld_malloc() and dz_map() are used for both performance and for ease of
 * programming:
 *
 * Performance:
 *	The link-edit is a short lived process which doesn't really free much
 *	of the dynamic memory that it requests.  Because of this, it is more
 *	important to optimize for quick memory allocations than the
 *	re-usability of the memory.
 *
 *	By also mmaping blocks of pages in from /dev/zero we don't need to
 *	waste the overhead of zeroing out these pages for calloc() requests.
 *
 * Memory Management:
 *	By doing all libld memory management through the ld_malloc routine
 *	it's much easier to free up all memory at the end by simply unmaping
 *	all of the blocks that were mapped in through dz_map().  This is much
 *	simpler then trying to track all of the libld structures that were
 *	dynamically allocate and are actually pointers into the ELF files.
 *
 *	It's important that we can free up all of our dynamic memory because
 *	libld is used by ld.so.1 when it performs dlopen()'s of relocatable
 *	objects.
 *
 * Format:
 *	The memory blocks for each allocation store the size of the allocation
 *	in the first 8 bytes of the block.  The pointer that is returned by
 *	libld_malloc() is actually the address of (block + 8):
 *
 *		(addr - 8)	block_size
 *		(addr)		<allocated block>
 *
 *	The size is retained in order to implement realloc(), and to perform
 *	the required memcpy().  8 bytes are uses, as the memory area returned
 *	by libld_malloc() must be 8 byte-aligned.  Even in a 32-bit environment,
 *	u_longlog_t pointers are employed.
 *
 * MAP_ANON arrived in Solaris 8, thus a fall-back is provided for older
 * systems.
 */
static void *
dz_map(size_t size)
{
	void	*addr;
	int	err;

#if	defined(MAP_ANON)
	static int	noanon = 0;

	if (noanon == 0) {
		if ((addr = mmap(0, size, (PROT_READ | PROT_WRITE | PROT_EXEC),
		    (MAP_PRIVATE | MAP_ANON), -1, 0)) != MAP_FAILED)
			return (addr);

		if ((errno != EBADF) && (errno != EINVAL)) {
			err = errno;
			eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_MMAPANON),
			    MSG_ORIG(MSG_PTH_DEVZERO), strerror(err));
			return (MAP_FAILED);
		} else
			noanon = 1;
	}
#endif
	if (dz_fd == -1) {
		if ((dz_fd = open(MSG_ORIG(MSG_PTH_DEVZERO), O_RDONLY)) == -1) {
			err = errno;
			eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN),
			    MSG_ORIG(MSG_PTH_DEVZERO), strerror(err));
			return (MAP_FAILED);
		}
	}

	if ((addr = mmap(0, size, (PROT_READ | PROT_WRITE | PROT_EXEC),
	    MAP_PRIVATE, dz_fd, 0)) == MAP_FAILED) {
		err = errno;
		eprintf(0, ERR_FATAL, MSG_INTL(MSG_SYS_MMAP),
		    MSG_ORIG(MSG_PTH_DEVZERO), strerror(err));
		return (MAP_FAILED);
	}
	return (addr);
}

void *
libld_malloc(size_t size)
{
	Ld_heap		*chp = ld_heap;
	void		*vptr;
	size_t		asize = size + HEAPALIGN;

	/*
	 * If this is the first allocation, or the allocation request is greater
	 * than the current free space available, allocate a new heap.
	 */
	if ((chp == 0) ||
	    (((size_t)chp->lh_end - (size_t)chp->lh_free) <= asize)) {
		Ld_heap	*nhp;
		size_t	hsize = (size_t)S_ROUND(sizeof (Ld_heap), HEAPALIGN);
		size_t	tsize = (size_t)S_ROUND((asize + hsize), HEAPALIGN);

		/*
		 * Allocate a block that is at minimum 'HEAPBLOCK' size
		 */
		if (tsize < HEAPBLOCK)
			tsize = HEAPBLOCK;

		if ((nhp = dz_map(tsize)) == MAP_FAILED)
			return (0);

		nhp->lh_next = chp;
		nhp->lh_free = (void *)((size_t)nhp + hsize);
		nhp->lh_end = (void *)((size_t)nhp + tsize);

		ld_heap = chp = nhp;
	}
	vptr = chp->lh_free;

	/*
	 * Assign size to head of allocated block (used by realloc), and
	 * memory arena as then next 8-byte aligned offset.
	 */
	*((size_t *)vptr) = size;
	vptr = (void *)((size_t)vptr + HEAPALIGN);

	/*
	 * Increment free to point to next available block
	 */
	chp->lh_free = (void *)S_ROUND((size_t)chp->lh_free + asize,
	    HEAPALIGN);

	return (vptr);
}

void *
libld_realloc(void *ptr, size_t size)
{
	size_t	psize;
	void	*vptr;

	if (ptr == NULL)
		return (libld_malloc(size));

	/*
	 * Size of the allocated blocks is stored *just* before the blocks
	 * address.
	 */
	psize = *((size_t *)((size_t)ptr - HEAPALIGN));

	/*
	 * If the block actually fits then just return.
	 */
	if (size <= psize)
		return (ptr);

	if ((vptr = libld_malloc(size)) != 0)
		(void) memcpy(vptr, ptr, psize);

	return (vptr);
}

void
/* ARGSUSED 0 */
libld_free(void *ptr)
{
}

/*
 * Append an item to the specified list, and return a pointer to the list
 * node created.
 */
Listnode *
list_appendc(List *lst, const void *item)
{
	Listnode	*_lnp;

	if ((_lnp = libld_malloc(sizeof (Listnode))) == 0)
		return (0);

	_lnp->data = (void *)item;
	_lnp->next = NULL;

	if (lst->head == NULL)
		lst->tail = lst->head = _lnp;
	else {
		lst->tail->next = _lnp;
		lst->tail = lst->tail->next;
	}
	return (_lnp);
}

/*
 * Add an item after the specified listnode, and return a pointer to the list
 * node created.
 */
Listnode *
list_insertc(List *lst, const void *item, Listnode *lnp)
{
	Listnode	*_lnp;

	if ((_lnp = libld_malloc(sizeof (Listnode))) == 0)
		return (0);

	_lnp->data = (void *)item;
	_lnp->next = lnp->next;
	if (_lnp->next == NULL)
		lst->tail = _lnp;
	lnp->next = _lnp;
	return (_lnp);
}

/*
 * Prepend an item to the specified list, and return a pointer to the
 * list node created.
 */
Listnode *
list_prependc(List *lst, const void *item)
{
	Listnode	*_lnp;

	if ((_lnp = libld_malloc(sizeof (Listnode))) == 0)
		return (0);

	_lnp->data = (void *)item;

	if (lst->head == NULL) {
		_lnp->next = NULL;
		lst->tail = lst->head = _lnp;
	} else {
		_lnp->next = lst->head;
		lst->head = _lnp;
	}
	return (_lnp);
}

/*
 * Find out where to insert the node for reordering.  List of insect structures
 * is traversed and the is_txtndx field of the insect structure is examined
 * and that determines where the new input section should be inserted.
 * All input sections which have a non zero is_txtndx value will be placed
 * in ascending order before sections with zero is_txtndx value.  This
 * implies that any section that does not appear in the map file will be
 * placed at the end of this list as it will have a is_txtndx value of 0.
 * Returns:  NULL if the input section should be inserted at beginning
 * of list else A pointer to the entry AFTER which this new section should
 * be inserted.
 */
Listnode *
list_where(List *lst, Word num)
{
	Listnode	*ln, *pln;	/* Temp list node ptr */
	Is_desc		*isp;		/* Temp Insect structure */
	Word		n;

	/*
	 * No input sections exist, so add at beginning of list
	 */
	if (lst->head == NULL)
		return (NULL);

	for (ln = lst->head, pln = ln; ln != NULL; pln = ln, ln = ln->next) {
		isp = (Is_desc *)ln->data;
		/*
		 *  This should never happen, but if it should we
		 *  try to do the right thing.  Insert at the
		 *  beginning of list if no other items exist, else
		 *  end of already existing list, prior to this null
		 *  item.
		 */
		if (isp == NULL) {
			if (ln == pln) {
				return (NULL);
			} else {
				return (pln);
			}
		}
		/*
		 *  We have reached end of reorderable items.  All
		 *  following items have is_txtndx values of zero
		 *  So insert at end of reorderable items.
		 */
		if ((n = isp->is_txtndx) > num || n == 0) {
			if (ln == pln) {
				return (NULL);
			} else {
				return (pln);
			}
		}
		/*
		 *  We have reached end of list, so insert
		 *  at the end of this list.
		 */
		if ((n != 0) && (ln->next == NULL))
			return (ln);
	}
	return (NULL);
}

/*
 * Determine if a shared object definition structure already exists and if
 * not create one.  These definitions provide for recording information
 * regarding shared objects that are still to be processed.  Once processed
 * shared objects are maintained on the ofl_sos list.  The information
 * recorded in this structure includes:
 *
 *  o	DT_USED requirements.  In these cases definitions are added during
 *	mapfile processing of `-' entries (see map_dash()).
 *
 *  o	implicit NEEDED entries.  As shared objects are processed from the
 *	command line so any of their dependencies are recorded in these
 *	structures for later processing (see process_dynamic()).
 *
 *  o	version requirements.  Any explicit shared objects that have version
 *	dependencies on other objects have their version requirements recorded.
 *	In these cases definitions are added during mapfile processing of `-'
 *	entries (see map_dash()).  Also, shared objects may have versioning
 *	requirements on their NEEDED entries.  These cases are added during
 *	their version processing (see vers_need_process()).
 *
 *	Note: Both process_dynamic() and vers_need_process() may generate the
 *	initial version definition structure because you can't rely on what
 *	section (.dynamic or .SUNW_version) may be processed first from	any
 *	input file.
 */
Sdf_desc *
sdf_find(const char *name, List *lst)
{
	Listnode	*lnp;
	Sdf_desc	*sdf;

	for (LIST_TRAVERSE(lst, lnp, sdf))
		if (strcmp(name, sdf->sdf_name) == 0)
			return (sdf);

	return (0);
}

Sdf_desc *
sdf_add(const char *name, List *lst)
{
	Sdf_desc	*sdf;

	if (!(sdf = libld_calloc(sizeof (Sdf_desc), 1)))
		return ((Sdf_desc *)S_ERROR);

	sdf->sdf_name = name;

	if (list_appendc(lst, sdf) == 0)
		return ((Sdf_desc *)S_ERROR);
	else
		return (sdf);
}

/*
 * Add a string, separated by a colon, to an existing string.  Typically used
 * to maintain filter, rpath and audit names, of which there is normally only
 * one string supplied anyway.
 */
char *
add_string(char *old, char *str)
{
	char	*new;

	if (old) {
		char	*_str;
		size_t	len;

		/*
		 * If an original string exists, make sure this new string
		 * doesn't get duplicated.
		 */
		if ((_str = strstr(old, str)) != NULL) {
			if (((_str == old) ||
			    (*(_str - 1) == *(MSG_ORIG(MSG_STR_COLON)))) &&
			    (_str += strlen(str)) &&
			    ((*_str == '\0') ||
			    (*_str == *(MSG_ORIG(MSG_STR_COLON)))))
				return (old);
		}

		len = strlen(old) + strlen(str) + 2;
		if ((new = libld_calloc(1, len)) == 0)
			return ((char *)S_ERROR);
		(void) snprintf(new, len, MSG_ORIG(MSG_FMT_COLPATH), old, str);
	} else {
		if ((new = libld_malloc(strlen(str) + 1)) == 0)
			return ((char *)S_ERROR);
		(void) strcpy(new, str);
	}

	return (new);
}

/*
 * Messaging support - funnel everything through dgettext().
 */

const char *
_libld_msg(Msg mid)
{
	return (dgettext(MSG_ORIG(MSG_SUNW_OST_SGS), MSG_ORIG(mid)));
}

/*
 * Determine whether a symbol name should be demangled.
 */
const char *
demangle(const char *name)
{
	if (demangle_flag)
		return (Elf_demangle_name(name));
	else
		return (name);
}
