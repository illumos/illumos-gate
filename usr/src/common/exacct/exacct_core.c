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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/exacct.h>
#include <sys/exacct_catalog.h>
#include <sys/exacct_impl.h>

#ifndef	_KERNEL
#include <limits.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <strings.h>
#else
#include <sys/systm.h>
#endif

/*
 * extended accounting file core routines
 *
 *   Routines shared by libexacct and the kernel for the definition,
 *   construction and packing of extended accounting (exacct) records.
 *
 * Locking
 *   All routines in this file use ea_alloc(), which is a malloc() wrapper
 *   in userland and a kmem_alloc(..., KM_SLEEP) wrapper in the kernel.
 *   Accordingly, all routines require a context suitable for KM_SLEEP
 *   allocations.
 */

#define	DEFAULT_ENTRIES 4

/*
 * ea_alloc() and ea_free() provide a wrapper for the common
 * exacct code offering access to either the kmem allocator, or to libc's
 * malloc.
 */
void *
ea_alloc(size_t size)
{
#ifndef _KERNEL
	void *p;

	while ((p = malloc(size)) == NULL && errno == EAGAIN)
		(void) poll(NULL, 0, 10 * MILLISEC);
	if (p == NULL) {
		EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
	} else {
		EXACCT_SET_ERR(EXR_OK);
	}
	return (p);
#else
	return (kmem_alloc(size, KM_SLEEP));
#endif
}

#ifndef _KERNEL
/*ARGSUSED*/
#endif
void
ea_free(void *ptr, size_t size)
{
#ifndef _KERNEL
	free(ptr);
#else
	kmem_free(ptr, size);
#endif
}

/*
 * ea_strdup() returns a pointer that, if non-NULL, must be freed using
 * ea_strfree() once its useful life ends.
 */
char *
ea_strdup(const char *ptr)
{
	/* Sets exacct_errno. */
	char *p = ea_alloc(strlen(ptr) + 1);
	if (p != NULL) {
		bcopy(ptr, p, strlen(ptr) + 1);
	}
	return (p);
}

/*
 * ea_strfree() frees a string allocated with ea_strdup().
 */
void
ea_strfree(char *ptr)
{
#ifndef _KERNEL
	free(ptr);
#else
	kmem_free(ptr, strlen(ptr) + 1);
#endif
}

/*
 * ea_cond_memcpy_at_offset() provides a simple conditional memcpy() that allows
 * us to write a pack routine that returns a valid buffer size, copying only in
 * the case that a non-NULL buffer is provided.
 */
static void
ea_cond_memcpy_at_offset(void *dst, size_t offset, size_t dstsize, void *src,
    size_t size)
{
	char *cdst = dst;
	char *csrc = src;

	if (dst == NULL || src == NULL || size == 0 || offset + size > dstsize)
		return;

	bcopy(csrc, cdst + offset, size);
}

/*
 * exacct_order{16,32,64}() are byte-swapping routines that place the native
 * data indicated by the input pointer in big-endian order.  Each exacct_order
 * function is its own inverse.
 */
#ifndef _LITTLE_ENDIAN
/*ARGSUSED*/
#endif /* _LITTLE_ENDIAN */
void
exacct_order16(uint16_t *in)
{
#ifdef _LITTLE_ENDIAN
	uint8_t s;
	union {
		uint16_t agg;
		uint8_t arr[2];
	} t;

	t.agg = *in;

	s = t.arr[0];
	t.arr[0] = t.arr[1];
	t.arr[1] = s;

	*in = t.agg;
#endif /* _LITTLE_ENDIAN */
}

#ifndef _LITTLE_ENDIAN
/*ARGSUSED*/
#endif /* _LITTLE_ENDIAN */
void
exacct_order32(uint32_t *in)
{
#ifdef _LITTLE_ENDIAN
	uint16_t s;
	union {
		uint32_t agg;
		uint16_t arr[2];
	} t;

	t.agg = *in;
	exacct_order16(&t.arr[0]);
	exacct_order16(&t.arr[1]);

	s = t.arr[0];
	t.arr[0] = t.arr[1];
	t.arr[1] = s;

	*in = t.agg;
#endif /* _LITTLE_ENDIAN */
}

#ifndef _LITTLE_ENDIAN
/*ARGSUSED*/
#endif /* _LITTLE_ENDIAN */
void
exacct_order64(uint64_t *in)
{
#ifdef _LITTLE_ENDIAN
	uint32_t s;
	union {
		uint64_t agg;
		uint32_t arr[2];
	} t;

	t.agg = *in;
	exacct_order32(&t.arr[0]);
	exacct_order32(&t.arr[1]);

	s = t.arr[0];
	t.arr[0] = t.arr[1];
	t.arr[1] = s;

	*in = t.agg;
#endif /* _LITTLE_ENDIAN */
}

int
ea_match_object_catalog(ea_object_t *obj, ea_catalog_t catmask)
{
	ea_catalog_t catval = obj->eo_catalog;

#define	EM_MATCH(v, m, M)	((m & M) == 0 || (v & M) == (m & M))
	return (EM_MATCH(catval, catmask, EXT_TYPE_MASK) &&
	    EM_MATCH(catval, catmask, EXC_CATALOG_MASK) &&
	    EM_MATCH(catval, catmask, EXD_DATA_MASK));
#undef EM_MATCH
}

int
ea_set_item(ea_object_t *obj, ea_catalog_t tag,
    const void *value, size_t valsize)
{
	ea_item_t *item = &obj->eo_item;

	if ((tag & EXT_TYPE_MASK) == EXT_GROUP) {
		EXACCT_SET_ERR(EXR_INVALID_OBJ);
		return (-1);
	}

	bzero(obj, sizeof (ea_object_t));
	obj->eo_type = EO_ITEM;
	obj->eo_catalog = tag;

	switch (obj->eo_catalog & EXT_TYPE_MASK) {
	case EXT_UINT8:
		item->ei_u.ei_u_uint8 = *(uint8_t *)value;
		item->ei_size = sizeof (uint8_t);
		break;
	case EXT_UINT16:
		item->ei_u.ei_u_uint16 = *(uint16_t *)value;
		item->ei_size = sizeof (uint16_t);
		break;
	case EXT_UINT32:
		item->ei_u.ei_u_uint32 = *(uint32_t *)value;
		item->ei_size = sizeof (uint32_t);
		break;
	case EXT_UINT64:
		item->ei_u.ei_u_uint64 = *(uint64_t *)value;
		item->ei_size = sizeof (uint64_t);
		break;
	case EXT_DOUBLE:
		item->ei_u.ei_u_double = *(double *)value;
		item->ei_size = sizeof (double);
		break;
	case EXT_STRING:
		if ((item->ei_string = ea_strdup((char *)value)) == NULL) {
			/* exacct_errno set above. */
			return (-1);
		}
		item->ei_size = strlen(item->ei_string) + 1;
		break;
	case EXT_EXACCT_OBJECT:
		if ((item->ei_object = ea_alloc(valsize)) == NULL) {
			/* exacct_errno set above. */
			return (-1);
		}
		bcopy(value, item->ei_object, valsize);
		item->ei_size = valsize;
		break;
	case EXT_RAW:
		if ((item->ei_raw = ea_alloc(valsize)) == NULL) {
			/* exacct_errno set above. */
			return (-1);
		}
		bcopy(value, item->ei_raw, valsize);
		item->ei_size = valsize;
		break;
	default:
		EXACCT_SET_ERR(EXR_INVALID_OBJ);
		return (-1);
	}

	EXACCT_SET_ERR(EXR_OK);
	return (0);
}

int
ea_set_group(ea_object_t *obj, ea_catalog_t tag)
{
	if ((tag & EXT_TYPE_MASK) != EXT_GROUP) {
		EXACCT_SET_ERR(EXR_INVALID_OBJ);
		return (-1);
	}

	bzero(obj, sizeof (ea_object_t));

	obj->eo_type = EO_GROUP;
	obj->eo_catalog = tag;
	obj->eo_u.eo_u_group.eg_nobjs = 0;
	obj->eo_u.eo_u_group.eg_objs = NULL;

	EXACCT_SET_ERR(EXR_OK);
	return (0);
}

void
ea_free_object(ea_object_t *obj, int flag)
{
	ea_object_t *next = obj;
	ea_object_t *save;

	while (next != NULL) {
		if (next->eo_type == EO_GROUP) {
			ea_free_object(next->eo_group.eg_objs, flag);
		} else if (next->eo_type == EO_ITEM) {
			switch (next->eo_catalog & EXT_TYPE_MASK) {
			case EXT_STRING:
				if (flag == EUP_ALLOC)
					ea_strfree(next->eo_item.ei_string);
				break;
			case EXT_RAW:
			case EXT_EXACCT_OBJECT:
				if (flag == EUP_ALLOC)
					ea_free(next->eo_item.ei_raw,
					    next->eo_item.ei_size);
				break;
			default:
				/* No action required for other types. */
				break;
			}
		}
		/* No action required for EO_NONE. */

		save = next;
		next = next->eo_next;
#ifdef _KERNEL
		kmem_cache_free(exacct_object_cache, save);
#else
		ea_free(save, sizeof (ea_object_t));
#endif /* _KERNEL */
	}
}

int
ea_free_item(ea_object_t *obj, int flag)
{
	if (obj->eo_type != EO_ITEM) {
		EXACCT_SET_ERR(EXR_INVALID_OBJ);
		return (-1);
	}

	switch (obj->eo_catalog & EXT_TYPE_MASK) {
	case EXT_STRING:
		if (flag == EUP_ALLOC)
			ea_strfree(obj->eo_item.ei_string);
		break;
	case EXT_RAW:
	case EXT_EXACCT_OBJECT:
		if (flag == EUP_ALLOC)
			ea_free(obj->eo_item.ei_raw, obj->eo_item.ei_size);
		break;
	default:
		/* No action required for other types. */
		break;
	}

	obj->eo_catalog = 0;
	obj->eo_type = EO_NONE;
	EXACCT_SET_ERR(EXR_OK);
	return (0);
}

static void
ea_attach_object(ea_object_t **objp, ea_object_t *obj)
{
	ea_object_t *tp;

	tp = *objp;
	*objp = obj;
	obj->eo_next = tp;
}

int
ea_attach_to_object(ea_object_t *root, ea_object_t *obj)
{
	if (obj->eo_type == EO_GROUP || obj->eo_type == EO_ITEM) {
		ea_attach_object(&root->eo_next, obj);
		EXACCT_SET_ERR(EXR_OK);
		return (0);
	} else {
		EXACCT_SET_ERR(EXR_INVALID_OBJ);
		return (-1);
	}
}

/*
 * ea_attach_to_group() takes a group object and an additional exacct object and
 * attaches the latter to the object list of the former.  The attached exacct
 * object can be the head of a chain of objects.  If group isn't actually an
 * object of type EO_GROUP, do nothing, such that we don't destroy its contents.
 */
int
ea_attach_to_group(ea_object_t *group, ea_object_t *obj)
{
	uint_t n = 0;
	ea_object_t *next;
	ea_object_t **nextp;

	if (group->eo_type != EO_GROUP) {
		EXACCT_SET_ERR(EXR_INVALID_OBJ);
		return (-1);
	}

	for (next = obj; next != NULL; next = next->eo_next)
		n++;

	group->eo_group.eg_nobjs += n;

	for (nextp = &group->eo_group.eg_objs; *nextp != NULL;
	    nextp = &(*nextp)->eo_next)
		continue;

	ea_attach_object(nextp, obj);
	EXACCT_SET_ERR(EXR_OK);
	return (0);
}

/*
 * ea_pack_object takes the given exacct object series beginning with obj and
 * places it in buf.  Since ea_pack_object needs to be runnable in kernel
 * context, we construct it to use its own stack of state.  Specifically, we
 * store the locations of the sizes of open records (records whose construction
 * is in progress).  curr_frame is used to indicate the current frame.  Just
 * prior to decrementing curr_frame, we must ensure that the correct size for
 * that frame is placed in the given offset.
 */
struct es_frame {
	ea_object_t	*esf_obj;
	ea_size_t	esf_size;
	ea_size_t	esf_bksize;
	ea_size_t	esf_offset;
};

static void
incr_parent_frames(struct es_frame *base, int n, size_t amt)
{
	int i;

	for (i = 0; i <= n; i++) {
		base[i].esf_size += amt;
		base[i].esf_bksize += amt;
	}
}

size_t
ea_pack_object(ea_object_t *obj, void *buf, size_t bufsize)
{
	struct es_frame *estack;
	uint_t neframes;
	ea_object_t *curr_obj = obj;
	int curr_frame = 0;
	size_t curr_pos = 0;
	ea_size_t placeholder = 0;
	int end_of_group = 0;
	uint32_t gp_backskip = sizeof (ea_catalog_t) + sizeof (ea_size_t) +
	    sizeof (uint32_t) + sizeof (uint32_t);
	uint32_t lge_backskip;

	exacct_order32(&gp_backskip);
	estack = ea_alloc(sizeof (struct es_frame) * DEFAULT_ENTRIES);
	if (estack == NULL) {
		/* exacct_errno set above. */
		return ((size_t)-1);
	}
	bzero(estack, sizeof (struct es_frame) * DEFAULT_ENTRIES);
	neframes = DEFAULT_ENTRIES;

	/*
	 * 1.  Start with the current object.
	 */
	for (;;) {
		void *src;
		size_t size;

		/*
		 * 1a.  If at the bottom of the stack, we are done.
		 * If at the end of a group, place the correct size at the head
		 * of the chain, the correct backskip amount in the next
		 * position in the buffer, and retreat to the previous frame.
		 */
		if (end_of_group) {
			if (--curr_frame < 0) {
				break;
			}

			exacct_order64(&estack[curr_frame].esf_size);
			ea_cond_memcpy_at_offset(buf,
			    estack[curr_frame].esf_offset, bufsize,
			    &estack[curr_frame].esf_size, sizeof (ea_size_t));
			exacct_order64(&estack[curr_frame].esf_size);

			/*
			 * Note that the large backskip is only 32 bits, whereas
			 * an object can be up to 2^64 bytes long.  If an object
			 * is greater than 2^32 bytes long set the large
			 * backskip to 0.  This will  prevent the file being
			 * read backwards by causing EOF to be returned when the
			 * big object is encountered, but reading forwards will
			 * still be OK as it ignores the large backskip field.
			 */
			estack[curr_frame].esf_bksize += sizeof (uint32_t);

			lge_backskip =
			    estack[curr_frame].esf_bksize > UINT_MAX
			    ? 0 : (uint32_t)estack[curr_frame].esf_bksize;
			exacct_order32(&lge_backskip);
			ea_cond_memcpy_at_offset(buf, curr_pos, bufsize,
			    &lge_backskip, sizeof (lge_backskip));

			curr_pos += sizeof (uint32_t);
			incr_parent_frames(estack, curr_frame,
			    sizeof (uint32_t));

			if ((curr_obj = estack[curr_frame].esf_obj) != NULL) {
				end_of_group = 0;
				estack[curr_frame].esf_obj = NULL;
				estack[curr_frame].esf_size = 0;
				estack[curr_frame].esf_bksize = 0;
			} else {
				continue;
			}
		}

		/*
		 * 2.  Write the catalog tag.
		 */
		exacct_order32(&curr_obj->eo_catalog);
		ea_cond_memcpy_at_offset(buf, curr_pos, bufsize,
		    &curr_obj->eo_catalog, sizeof (ea_catalog_t));
		exacct_order32(&curr_obj->eo_catalog);

		incr_parent_frames(estack, curr_frame, sizeof (ea_catalog_t));
		estack[curr_frame].esf_size -= sizeof (ea_catalog_t);
		curr_pos += sizeof (ea_catalog_t);
		estack[curr_frame].esf_offset = curr_pos;

		/*
		 * 2a. If this type is of variable size, reserve space for the
		 * size field.
		 */
		switch (curr_obj->eo_catalog & EXT_TYPE_MASK) {
		case EXT_GROUP:
		case EXT_STRING:
		case EXT_EXACCT_OBJECT:
		case EXT_RAW:
			exacct_order64(&placeholder);
			ea_cond_memcpy_at_offset(buf, curr_pos, bufsize,
			    &placeholder, sizeof (ea_size_t));
			exacct_order64(&placeholder);

			incr_parent_frames(estack, curr_frame,
			    sizeof (ea_size_t));
			estack[curr_frame].esf_size -= sizeof (ea_size_t);
			curr_pos += sizeof (ea_size_t);
			break;
		default:
			break;
		}

		if (curr_obj->eo_type == EO_GROUP) {
			/*
			 * 3A.  If it's a group put its next pointer, size, and
			 * size position on the stack, add 1 to the stack,
			 * set the current object to eg_objs, and goto 1.
			 */
			estack[curr_frame].esf_obj = curr_obj->eo_next;

			/*
			 * 3Aa. Insert the number of objects in the group.
			 */
			exacct_order32(&curr_obj->eo_group.eg_nobjs);
			ea_cond_memcpy_at_offset(buf, curr_pos, bufsize,
			    &curr_obj->eo_group.eg_nobjs,
			    sizeof (uint32_t));
			exacct_order32(&curr_obj->eo_group.eg_nobjs);

			incr_parent_frames(estack, curr_frame,
			    sizeof (uint32_t));
			curr_pos += sizeof (uint32_t);

			/*
			 * 3Ab. Insert a backskip of the appropriate size.
			 */
			ea_cond_memcpy_at_offset(buf, curr_pos, bufsize,
			    &gp_backskip, sizeof (uint32_t));

			incr_parent_frames(estack, curr_frame,
			    sizeof (uint32_t));
			curr_pos += sizeof (uint32_t);

			curr_frame++;

			if (curr_frame >= neframes) {
				/*
				 * Expand the eframe stack to handle the
				 * requested depth.
				 */
				uint_t new_neframes = 2 * neframes;
				struct es_frame *new_estack =
				    ea_alloc(new_neframes *
				    sizeof (struct es_frame));
				if (new_estack == NULL) {
					ea_free(estack, neframes *
					    sizeof (struct es_frame));
					/* exacct_errno set above. */
					return ((size_t)-1);
				}

				bzero(new_estack, new_neframes *
				    sizeof (struct es_frame));
				bcopy(estack, new_estack, neframes *
				    sizeof (struct es_frame));

				ea_free(estack, neframes *
				    sizeof (struct es_frame));
				estack = new_estack;
				neframes = new_neframes;
			} else {
				bzero(&estack[curr_frame],
				    sizeof (struct es_frame));
			}

			estack[curr_frame].esf_offset = curr_pos;
			if ((curr_obj = curr_obj->eo_group.eg_objs) == NULL) {
				end_of_group = 1;
			}

			continue;
		}

		/*
		 * 3B. Otherwise we're considering an item: add its ei_size to
		 * all sizes on the stack, and copy its size into position.
		 */
		switch (curr_obj->eo_catalog & EXT_TYPE_MASK) {
		case EXT_UINT8:
			src = &curr_obj->eo_item.ei_uint8;
			size = sizeof (uint8_t);
			break;
		case EXT_UINT16:
			src = &curr_obj->eo_item.ei_uint16;
			size = sizeof (uint16_t);
			exacct_order16(src);
			break;
		case EXT_UINT32:
			src = &curr_obj->eo_item.ei_uint32;
			size = sizeof (uint32_t);
			exacct_order32(src);
			break;
		case EXT_UINT64:
			src = &curr_obj->eo_item.ei_uint64;
			size = sizeof (uint64_t);
			exacct_order64(src);
			break;
		case EXT_DOUBLE:
			src = &curr_obj->eo_item.ei_double;
			size = sizeof (double);
			exacct_order64((uint64_t *)src);
			break;
		case EXT_STRING:
			src = curr_obj->eo_item.ei_string;
			size = curr_obj->eo_item.ei_size;
			break;
		case EXT_EXACCT_OBJECT:
			src = curr_obj->eo_item.ei_object;
			size = curr_obj->eo_item.ei_size;
			break;
		case EXT_RAW:
			src = curr_obj->eo_item.ei_raw;
			size = curr_obj->eo_item.ei_size;
			break;
		case EXT_NONE:
		default:
			src = NULL;
			size = 0;
			break;
		}

		ea_cond_memcpy_at_offset(buf, curr_pos, bufsize, src, size);
		incr_parent_frames(estack, curr_frame, size);
		curr_pos += size;

		/*
		 * 4. Write the large backskip amount into the buffer.
		 * See above for note about why this may be set to 0.
		 */
		incr_parent_frames(estack, curr_frame, sizeof (uint32_t));

		lge_backskip = estack[curr_frame].esf_bksize > UINT_MAX
		    ? 0 : (uint32_t)estack[curr_frame].esf_bksize;
		exacct_order32(&lge_backskip);
		ea_cond_memcpy_at_offset(buf, curr_pos, bufsize,
		    &lge_backskip, sizeof (lge_backskip));

		curr_pos += sizeof (uint32_t);

		switch (curr_obj->eo_catalog & EXT_TYPE_MASK) {
		case EXT_RAW:
		case EXT_STRING:
		case EXT_EXACCT_OBJECT:
			exacct_order64(&estack[curr_frame].esf_size);
			ea_cond_memcpy_at_offset(buf,
			    estack[curr_frame].esf_offset, bufsize,
			    &estack[curr_frame].esf_size, sizeof (ea_size_t));
			exacct_order64(&estack[curr_frame].esf_size);
			break;
		case EXT_UINT16:
			exacct_order16(src);
			break;
		case EXT_UINT32:
			exacct_order32(src);
			break;
		case EXT_UINT64:
			exacct_order64(src);
			break;
		case EXT_DOUBLE:
			exacct_order64((uint64_t *)src);
			break;
		default:
			break;
		}

		/*
		 * 5.  If ei_next is NULL, we are at the end of a group.a  If
		 * not, move on to the next item on the list.
		 */
		if (curr_obj->eo_next == NULL) {
			end_of_group = 1;
		} else {
			curr_obj = curr_obj->eo_next;
			estack[curr_frame].esf_obj = NULL;
			estack[curr_frame].esf_size = 0;
			estack[curr_frame].esf_bksize = 0;
		}
	}

	ea_free(estack, neframes * sizeof (struct es_frame));
	EXACCT_SET_ERR(EXR_OK);
	return (curr_pos);
}
