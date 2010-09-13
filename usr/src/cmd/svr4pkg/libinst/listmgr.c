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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libintl.h>
#include "pkglib.h"

/*
 * This is the module responsible for allocating and maintaining lists that
 * require allocation of memory. For certain lists, large chunks are
 * allocated once to contain a large number of entries in each chunk (bl_*
 * for block list). The other approach involves the augmentation of linked
 * lists, each entry of which is alloc'd individually.
 */
#define	ERR_CS_ALLOC	"ERROR: Cannot allocate control structure for %s array."
#define	ERR_MEM_ALLOC	"ERROR: Cannot allocate memory for %s array."

#define	MAX_ARRAYS	50

#define	ARRAY_END(x)	(bl_cs_array[x]->cur_segment->avail_ptr)
#define	REC_SIZE(x)	(bl_cs_array[x]->struct_size)
#define	EOSEG(x)	(bl_cs_array[x]->cur_segment->eoseg_ptr)
#define	GET_AVAIL(x)	(ARRAY_END(x) + REC_SIZE(x))

struct alloc_seg {
	char *seg_ptr;		/* ptr to the allocated block */
	char *avail_ptr;	/* ptr to the next available list element */
	char *eoseg_ptr;	/* last byte in the segment */
	int full;		/* segment has no available space */
	struct alloc_seg *next;	/* next record */
};

struct blk_list_cs {
	int struct_size;		/* size of a single list element */
	int count_per_block;		/* number of list elements per block */
	int block_size;			/* just to save time - alloc size */
	int data_handle;		/* list_handle for pointer array */
	struct alloc_seg *alloc_segs;	/* memory pool */

	struct alloc_seg *cur_segment;	/* the current allocated segment */
	int total_elem;			/* total elements stored */
	int contiguous;			/* use realloc to grow */
	char *desc;			/* description of the list */
};

static struct blk_list_cs *bl_cs_array[MAX_ARRAYS];
static int next_array_elem;

/* Support functions */
static int
invalid_handle(int list_handle)
{
	if (list_handle < 0 || list_handle >= next_array_elem)
		return (1);

	return (0);
}

static int
invalid_record(int list_handle, int recno)
{
	if (invalid_handle(list_handle))
		return (1);

	if (recno < 0 || recno > bl_cs_array[list_handle]->total_elem)
		return (1);

	return (0);
}

static void
free_list(int list_handle)
{
	struct blk_list_cs *bl_ptr;
	struct alloc_seg *segstr_ptr, *nextstr_ptr;

	/* Make sure this wasn't free'd earlier */
	if (bl_cs_array[list_handle] == NULL)
		return;

	bl_ptr = bl_cs_array[list_handle];

	/* First free the alloc_seg list. */
	segstr_ptr = bl_ptr->alloc_segs;

	if (segstr_ptr) {
		do {
			nextstr_ptr = segstr_ptr->next;

			/* Free the memory block. */
			free((void *)segstr_ptr->seg_ptr);

			/* Free the control structure. */
			free((void *)segstr_ptr);
			segstr_ptr = nextstr_ptr;
		} while (segstr_ptr);
	}

	/* Free the block control structure. */
	free((void *)bl_ptr->desc);
	free((void *)bl_ptr);

	bl_cs_array[list_handle] = NULL;
}

/* Allocate another alloc_seg structure. */
static int
alloc_next_seg(struct blk_list_cs *bl_ptr)
{
	struct alloc_seg *new_alloc_cs;

	if (bl_ptr->contiguous) {
		int offset_to_avail, seg_size, new_size;
		struct alloc_seg *alloc_segment;

		if (bl_ptr->alloc_segs) {
			alloc_segment = bl_ptr->alloc_segs;

			offset_to_avail = (alloc_segment->avail_ptr -
			    alloc_segment->seg_ptr);
			seg_size = (alloc_segment->eoseg_ptr -
			    alloc_segment->seg_ptr);
			new_size = (seg_size + bl_ptr->block_size);
		} else {
			if ((bl_ptr->alloc_segs =
			    (struct alloc_seg *)calloc(1,
			    sizeof (struct alloc_seg))) == NULL) {
				logerr(gettext(ERR_CS_ALLOC), (bl_ptr->desc ?
				    bl_ptr->desc : "an unknown"));
				return (0);
			}

			alloc_segment = bl_ptr->alloc_segs;

			offset_to_avail = 0;
			seg_size = 0;
			new_size = bl_ptr->block_size;
		}

		bl_ptr->cur_segment = alloc_segment;

		if ((alloc_segment->seg_ptr =
		    (char *)realloc((void *)alloc_segment->seg_ptr,
		    (unsigned)new_size)) == NULL) {
			logerr(gettext(ERR_MEM_ALLOC), (bl_ptr->desc ?
			    bl_ptr->desc : "an unknown"));
			return (0);
		}

		alloc_segment->next = NULL;

		/* reset the status */
		alloc_segment->full = 0;

		/* readjust the original pointers */
		alloc_segment->avail_ptr = alloc_segment->seg_ptr +
		    offset_to_avail;
		alloc_segment->eoseg_ptr = alloc_segment->seg_ptr + new_size;

		(void) memset(alloc_segment->avail_ptr, '\000',
		    bl_ptr->block_size);
	} else {
		/* Allocate the control structure and link it into the list. */
		if ((new_alloc_cs = (struct alloc_seg *)malloc(
		    sizeof (struct alloc_seg))) == NULL) {
			logerr(gettext(ERR_CS_ALLOC), (bl_ptr->desc ?
			    bl_ptr->desc : "an unknown"));
			return (0);
		}

		if (bl_ptr->alloc_segs == NULL) {
			/*
			 * If this is the first allocation, then initialize
			 * the head pointer and set cur_segment to this first
			 * block of memory.
			 */
			bl_ptr->alloc_segs = new_alloc_cs;
		} else {
			/*
			 * Otherwise, point the current cur_segment to the
			 * next one and then point to the new one.
			 */
			bl_ptr->cur_segment->next = new_alloc_cs;
		}

		new_alloc_cs->next = NULL;
		bl_ptr->cur_segment = new_alloc_cs;

		new_alloc_cs->full = 0;

		/* Now allocate the block of memory that this controls. */
		if ((new_alloc_cs->seg_ptr = calloc(bl_ptr->count_per_block,
		    bl_ptr->struct_size)) == NULL) {
			logerr(gettext(ERR_MEM_ALLOC), (bl_ptr->desc ?
			    bl_ptr->desc : "an unknown"));
			return (0);
		}

		new_alloc_cs->avail_ptr = new_alloc_cs->seg_ptr;
		new_alloc_cs->eoseg_ptr = (new_alloc_cs->seg_ptr +
		    bl_ptr->block_size);
	}

	return (1);
}

/*
 * These first functions (beginning with bl_*) manage simple block lists. The
 * pointers returned, may get lost if they aren't assigned to an array or
 * something. While individual records can be obtained by record number, the
 * process isn't very efficient. Look to the array management section
 * (ar_*)for an easily administrable list.
 */

/*
 * Create a block list. Allocate memory for a block list structure and
 * initialize that structure. This doesn't actually allocate memory for the
 * list yet, just the controlling data structure. Returns -1 on failure and a
 * valid block list handle otherwise.
 *
 * NOTE: At the time of writing, it was not seen as important to recover block
 * pointers made available with a bl_free() (two of these at most in
 * pkginstall). If this became important later, we could trade efficiency for
 * speed by ignoring next_array_elem and actually scanning through the array
 * for a NULL pointer and then return that.
 */
int
bl_create(int count_per_block, int struct_size, char *desc)
{
	struct blk_list_cs *bl_ptr;
	int retval;

	if ((bl_cs_array[next_array_elem] =
	    (struct blk_list_cs *)calloc(1, sizeof (struct blk_list_cs))) ==
	    NULL) {
		logerr(gettext(ERR_CS_ALLOC), (desc ? desc : "an unknown"));
		return (-1);
	}

	bl_ptr = bl_cs_array[next_array_elem];
	retval = next_array_elem++;

	bl_ptr->data_handle = -1;
	bl_ptr->struct_size = struct_size;
	bl_ptr->count_per_block = count_per_block;
	bl_ptr->block_size = (count_per_block * struct_size);
	bl_ptr->desc = strdup((desc ? desc : "unknown"));

	return (retval);
}

/*
 * Get the next available entry in the list. This will allocate memory as
 * required based on the initialization values in bl_create(). Returns a
 * pointer to the allocated memory segment or NULL if operation was not
 * possible.
 */
char *
bl_next_avail(int list_handle)
{
	struct blk_list_cs *bl_ptr;
	char *retval;

	if (invalid_handle(list_handle))
		return (NULL);

	bl_ptr = bl_cs_array[list_handle];

	/*
	 * Allocate more memory if none is allocated yet or our last access
	 * filled the allotted segment.
	 */
	if (bl_ptr->cur_segment == NULL || bl_ptr->cur_segment->full)
		if (!alloc_next_seg(bl_ptr))
			return (NULL);

	/* Get the correct pointer. */
	retval = bl_ptr->cur_segment->avail_ptr;

	/* Advance it and mark if full. */
	bl_ptr->cur_segment->avail_ptr += bl_ptr->struct_size;
	bl_ptr->total_elem++;

	if (bl_ptr->cur_segment->avail_ptr >= bl_ptr->cur_segment->eoseg_ptr)
		bl_ptr->cur_segment->full = 1;

	return (retval);
}

char *
bl_get_record(int list_handle, int recno)
{
	struct blk_list_cs *bl_ptr;
	struct alloc_seg *cur_as_ptr;
	int cur_rec = 0;

	if (invalid_record(list_handle, recno))
		return (NULL);

	bl_ptr = bl_cs_array[list_handle];

	cur_as_ptr = bl_ptr->alloc_segs;

	while (recno > (cur_rec + bl_ptr->count_per_block)) {
		cur_as_ptr = cur_as_ptr->next;

		if (cur_as_ptr == NULL)
			return (NULL);

		cur_rec += bl_ptr->count_per_block;
	}

	/*
	 * Now cur_as_ptr points to the allocated segment bearing the
	 * intended record and all we do now is move down that by the
	 * remaining record lengths.
	 */

	return ((char *)cur_as_ptr + ((recno - cur_rec) * bl_ptr->struct_size));
}

void
bl_free(int list_handle)
{
	int cur_handle;

	if (list_handle == -1) {
		for (cur_handle = 0; cur_handle < next_array_elem;
		    cur_handle++) {
			free_list(cur_handle);
		}
	} else {
		if (invalid_handle(list_handle))
			return;

		free_list(list_handle);
	}
}

/*
 * These are the array management functions. They insert into (and can return
 * a pointer to) a contiguous list of pointers to stuff. This keeps
 * everything together in a very handy package and is very similar in
 * appearance to the arrays created by the old AT&T code. The method for
 * presenting the interface is entirely different, however.
 */

/*
 * This constructs, maintains and returns pointers into a growable array of
 * pointers to structures of the form
 *	struct something *array[n]
 * The last element in the array is always NULL.
 */
int
ar_create(int count_per_block, int struct_size, char *desc)
{
	int data_handle, retval;
	char ar_desc[60];
	struct blk_list_cs *array_ptr;

	if ((data_handle = bl_create(count_per_block, struct_size, desc)) == -1)
		return (-1);

	sprintf(ar_desc, "%s pointer", desc);
	if ((retval = bl_create(count_per_block, sizeof (char *),
	    ar_desc)) == -1)
		return (-1);

	array_ptr = bl_cs_array[retval];

	array_ptr->contiguous = 1;
	array_ptr->data_handle = data_handle;

	return (retval);
}

/* Return a pointer to the first element in the array. */
char **
ar_get_head(int list_handle)
{
	if (invalid_handle(list_handle) ||
	    bl_cs_array[list_handle]->alloc_segs == NULL)
		return (NULL);

	return ((char **)bl_cs_array[list_handle]->alloc_segs->seg_ptr);
}

/*
 * Free up the entry in the array indicated by index, but hold onto it for
 * future use.
 */
int
ar_delete(int list_handle, int index)
{
	char **array;
	char *deleted_rec;
	int i;
	struct blk_list_cs *list_ptr, *data_ptr;

	if ((array = ar_get_head(list_handle)) == NULL)
		return (0);

	if (invalid_record(list_handle, index))
		return (0);

	/* Get the pointer to the array control structure. */
	list_ptr = bl_cs_array[list_handle];

	if (!(list_ptr->contiguous))
		return (0);	/* This isn't an array. */

	data_ptr = bl_cs_array[list_ptr->data_handle];

	/*
	 * Since this looks just like an array. Record the pointer being
	 * deleted for insertion into the avail list at the end and move all
	 * elements below it up one.
	 */
	deleted_rec = array[index];

	for (i = index; array[i] != NULL; i++)
		array[i] = array[i+1];

	/*
	 * Now insert the deleted entry into the avails list after the NULL
	 * and adjust the avail_ptr to point to the NULL again.
	 */
	array[i] = deleted_rec;
	list_ptr->alloc_segs->avail_ptr -= list_ptr->struct_size;

	/* Adjust other entries in the control structure. */
	list_ptr->alloc_segs->full = 0;
	list_ptr->total_elem -= 1;

	/* Clear the deleted data area. */
	(void) memset(deleted_rec, '\000', data_ptr->struct_size);

	return (1);
}

/*
 * Return a new pointer to a structure pointer. Find an available element in
 * the array and point it at an available element in the data pool
 * constructed of block lists. Allocate new memory as necessary.
 */
char **
ar_next_avail(int list_handle)
{
	struct blk_list_cs *array_ptr;
	char *data_area, **pointer_area;

	if (invalid_handle(list_handle) ||
	    !(bl_cs_array[list_handle]->contiguous) ||
	    invalid_handle(bl_cs_array[list_handle]->data_handle))
		return (NULL);

	array_ptr = bl_cs_array[list_handle];

	/*
	 * First see if an avail has already been allocated (it will be right
	 * after the NULL termination of the array if it exists). Return
	 * that, if found.
	 */
	if ((bl_cs_array[list_handle]->cur_segment != NULL) &&
	    (ARRAY_END(list_handle) + REC_SIZE(list_handle) <
	    EOSEG(list_handle)) &&
	    (*(pointer_area = (char **) GET_AVAIL(list_handle)) != NULL)) {
		/* We can reclaim a previous deletion. */
		data_area = *pointer_area;

		*(char **)(ARRAY_END(list_handle)) = data_area;	/* reactivate */
		*pointer_area-- = NULL;	/* new end */

		array_ptr->cur_segment->avail_ptr += array_ptr->struct_size;
		array_ptr->total_elem++;
	} else {
		/*
		 * Get the data area first. This is the record we're pointing
		 * to from the array.
		 */
		data_area = bl_next_avail(array_ptr->data_handle);

		/* Now get the next pointer from the pointer array. */
		pointer_area = (char **) bl_next_avail(list_handle);

		*pointer_area = data_area;

		/*
		 * The array must be NULL terminated. So, if the block list
		 * structure is full, we have to grow it without resetting
		 * the avail pointer. NOTE: This will only work for a
		 * contiguous list!
		 */
		if (bl_cs_array[list_handle]->alloc_segs->full) {
			char **old_list_pointer, **new_list_pointer;

			/*
			 * First grab the old numbers in case realloc() moves
			 * everything.
			 */
			old_list_pointer = ar_get_head(list_handle);

			/*
			 * Now allocate additional contiguous memory, moving
			 * the original block if necessary.
			 */
			if (!alloc_next_seg(array_ptr))
				return (NULL);

			/*
			 * Now determine if everything moved and readjust the
			 * pointer_area if required.
			 */
			new_list_pointer = ar_get_head(list_handle);

			if (old_list_pointer != new_list_pointer) {
				pointer_area += (new_list_pointer -
				    old_list_pointer);
			}
		}
	}

	return (pointer_area);
}

/*
 * Relinquish the array back to the memory pool. Note that there is no method
 * provided to free *all* arrays.
 */
void
ar_free(int list_handle)
{
	if (invalid_handle(list_handle))
		return;

	bl_free(bl_cs_array[list_handle]->data_handle);
	bl_free(list_handle);
}
