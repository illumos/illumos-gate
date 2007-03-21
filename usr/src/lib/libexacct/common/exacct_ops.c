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

#include <sys/systeminfo.h>

#include <exacct.h>
#include <exacct_impl.h>
#include <sys/exacct_impl.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <thread.h>
#include <pthread.h>

#define	EXACCT_HDR_STR	"exacct"
#define	EXACCT_HDR_LEN	7

#define	DEFAULT_ENTRIES	4
#define	SYSINFO_BUFSIZE	256

static thread_key_t	errkey = THR_ONCE_KEY;
static int		exacct_errval = 0;

/*
 * extended accounting file access routines
 *
 *   exacct_ops.c implements the library-specific routines of libexacct:  the
 *   operations associated with file access and record traversal.  (The
 *   complementary routines which permit hierarchy building and record packing
 *   are provided in exacct_core.c, which is used by both libexacct and the
 *   kernel.) At its heart are the unpack, get, and next routines, which
 *   navigate the packed records produced by ea_pack_object.
 */

/*
 * Group stack manipulation code.  As groups can be nested, we need a mechanism
 * for saving and restoring the current position within the outer groups.  This
 * state stack is stored within the ea_file_impl_t structure, in the ef_depth,
 * ef_ndeep and ef_mxdeep members.  On error all these functions set
 * exacct_error and return -1.
 */

/*
 * If the stack is NULL, create and initialise it.
 * If is is not NULL, check it still has space - if not, double its size.
 */
static int stack_check(ea_file_impl_t *f)
{
	if (f->ef_depth == NULL) {
		if ((f->ef_depth =
		    ea_alloc(DEFAULT_ENTRIES * sizeof (ea_file_depth_t)))
		    == NULL) {
			/* exacct_errno set above. */
			return (-1);
		}
		bzero(f->ef_depth, DEFAULT_ENTRIES * sizeof (ea_file_depth_t));
		f->ef_mxdeep = DEFAULT_ENTRIES;
		f->ef_ndeep = -1;
	} else if (f->ef_ndeep + 1 >= f->ef_mxdeep) {
		ea_file_depth_t *newstack;

		if ((newstack =
		    ea_alloc(f->ef_mxdeep * 2 * sizeof (ea_file_depth_t)))
		    == NULL) {
			/* exacct_errno set above. */
			return (-1);
		}
		bcopy(f->ef_depth, newstack,
		    f->ef_mxdeep * sizeof (ea_file_depth_t));
		bzero(newstack + f->ef_mxdeep,
		    f->ef_mxdeep * sizeof (ea_file_depth_t));
		ea_free(f->ef_depth, f->ef_mxdeep * sizeof (ea_file_depth_t));
		f->ef_mxdeep *= 2;
		f->ef_depth = newstack;
	}
	return (0);
}

/*
 * Free a stack.
 */
static void stack_free(ea_file_impl_t *f)
{
	if (f->ef_depth != NULL) {
		ea_free(f->ef_depth, f->ef_mxdeep * sizeof (ea_file_depth_t));
		f->ef_depth = NULL;
	}
	f->ef_mxdeep = 0;
	f->ef_ndeep = -1;
}

/*
 * Add a new group onto the stack, pushing down one frame.  nobj is the number
 * of items in the group.  We have to read this many objects before popping
 * back up to an enclosing group - see next_object() and previous_object()
 * below.
 */
static int stack_new_group(ea_file_impl_t *f, int nobjs)
{
	if (stack_check(f) != 0) {
		stack_free(f);
		/* exacct_errno set above. */
		return (-1);
	}
	f->ef_ndeep++;
	f->ef_depth[f->ef_ndeep].efd_obj = 0;
	f->ef_depth[f->ef_ndeep].efd_nobjs = nobjs;
	return (0);
}

/*
 * Step forwards along the objects within the current group.  If we are still
 * within a group, return 1.  If we have reached the end of the current group,
 * unwind the stack back up to the nearest enclosing group that still has
 * unprocessed objects and return 0.  On EOF or error, set exacct_error
 * accordingly and return -1.  xread() is required so that this function can
 * work either on files or memory buffers.
 */
static int
stack_next_object(
    ea_file_impl_t *f,
    size_t (*xread)(ea_file_impl_t *, void *, size_t))
{
	uint32_t scratch32;

	/*
	 * If the stack is empty we are not in a group, so there will be no
	 * stack manipulation to do and no large backskips to step over.
	 */
	if (f->ef_ndeep < 0) {
		return (0);
	}

	/*
	 * Otherwise we must be in a group.  If there are objects left in the
	 * group, move onto the next one in the group and return.
	 */
	if (++f->ef_depth[f->ef_ndeep].efd_obj <
	    f->ef_depth[f->ef_ndeep].efd_nobjs) {
		return (1);

	/*
	 * If we are at the end of a group we need to move backwards up the
	 * stack, consuming the large backskips as we go, until we find a group
	 * that still contains unprocessed items, or until we have unwound back
	 * off the bottom of the stack (i.e. out of all the groups).
	 */
	} else {
		while (f->ef_ndeep >= 0 &&
		    ++f->ef_depth[f->ef_ndeep].efd_obj >=
		    f->ef_depth[f->ef_ndeep].efd_nobjs) {
			/* Read the large backskip. */
			f->ef_ndeep--;
			if (xread(f, &scratch32, sizeof (scratch32)) !=
			    sizeof (scratch32)) {
				EXACCT_SET_ERR(EXR_CORRUPT_FILE);
				return (-1);
			}
		}
		return (0);
	}
}

/*
 * Step backwards along the objects within the current group.  If we are still
 * within a group, return 1.  If we have reached the end of the current group,
 * unwind the stack back up to the enclosing group and return 0.
 */
static int stack_previous_object(ea_file_impl_t *f)
{
	/*
	 * If the stack is empty we are not in a group, so there will be no
	 * stack manipulation to do.
	 */
	if (f->ef_ndeep < 0) {
		return (0);
	}

	/*
	 * Otherwise we must be in a group.  If there are objects left in the
	 * group, move onto the previous one in the group and return.
	 */
	if (--f->ef_depth[f->ef_ndeep].efd_obj >= 0) {
		return (1);

	/* Otherwise, step one level back up the group stack. */
	} else {
		f->ef_ndeep--;
		return (0);
	}
}

/*
 * read/seek/pos virtualisation wrappers.  Because objects can come either from
 * a file or memory, the read/seek/pos functions need to be wrapped to allow
 * them to be used on either a file handle or a memory buffer.
 */

static size_t
fread_wrapper(ea_file_impl_t *f, void *buf, size_t sz)
{
	size_t retval;

	retval = fread(buf, 1, sz, f->ef_fp);
	if (retval == 0 && ferror(f->ef_fp)) {
		retval = (size_t)-1;
	}
	return (retval);
}

static size_t
bufread_wrapper(ea_file_impl_t *f, void *buf, size_t sz)
{
	if (f->ef_bufsize == 0 && sz != 0)
		return ((size_t)0);

	if (f->ef_bufsize < sz)
		sz = f->ef_bufsize;

	bcopy(f->ef_buf, buf, sz);
	f->ef_buf += sz;
	f->ef_bufsize -= sz;

	return (sz);
}

static off_t
fseek_wrapper(ea_file_impl_t *f, off_t adv)
{
	return (fseeko(f->ef_fp, adv, SEEK_CUR));
}

static off_t
bufseek_wrapper(ea_file_impl_t *f, off_t adv)
{
	if (f->ef_bufsize == 0 && adv != 0)
		return (-1);

	if (f->ef_bufsize < adv)
		adv = f->ef_bufsize;

	f->ef_buf += adv;
	f->ef_bufsize -= adv;

	return (0);
}

/*ARGSUSED*/
static void *
fpos_wrapper(ea_file_impl_t *f)
{
	return (NULL);
}

static void *
bufpos_wrapper(ea_file_impl_t *f)
{
	return (f->ef_buf);
}

/*
 * Public API
 */

void
exacct_seterr(int errval)
{
	if (thr_main()) {
		exacct_errval = errval;
		return;
	}
	(void) thr_keycreate_once(&errkey, 0);
	(void) thr_setspecific(errkey, (void *)(intptr_t)errval);
}

int
ea_error(void)
{
	if (thr_main())
		return (exacct_errval);
	if (errkey == THR_ONCE_KEY)
		return (EXR_OK);
	return ((int)(uintptr_t)pthread_getspecific(errkey));
}

/*
 * ea_next_object(), ea_previous_object(), and ea_get_object() are written such
 * that the file cursor is always located on an object boundary.
 */
ea_object_type_t
ea_next_object(ea_file_t *ef, ea_object_t *obj)
{
	ea_file_impl_t *f = (ea_file_impl_t *)ef;
	ea_size_t len;
	off_t backup;
	size_t ret;

	/*
	 * If ef_advance is zero, then we are executing after a get or previous
	 * operation and do not move to the next or previous object.  Otherwise,
	 * advance to the next available item.  Note that ef_advance does NOT
	 * include the large backskip at the end of a object, this being dealt
	 * with by the depth stack handling in stack_next_object.
	 */
	if (f->ef_advance != 0) {
		if (fseeko(f->ef_fp, (off_t)f->ef_advance, SEEK_CUR) == -1) {
			EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
			return (EO_ERROR);
		}
		if (stack_next_object(f, fread_wrapper) == -1) {
			/* exacct_error set above. */
			return (EO_ERROR);
		}
	}
	f->ef_advance = 0;

	/* Read the catalog tag */
	ret = fread(&obj->eo_catalog, 1, sizeof (ea_catalog_t), f->ef_fp);
	if (ret == 0) {
		EXACCT_SET_ERR(EXR_EOF);
		return (EO_ERROR);
	} else if (ret < sizeof (ea_catalog_t)) {
		EXACCT_SET_ERR(EXR_CORRUPT_FILE);
		return (EO_ERROR);
	}
	exacct_order32(&obj->eo_catalog);

	backup = sizeof (ea_catalog_t);
	obj->eo_type = EO_ITEM;

	/* Figure out the offset to just before the large backskip. */
	switch (obj->eo_catalog & EXT_TYPE_MASK) {
	case EXT_GROUP:
		obj->eo_type = EO_GROUP;
		f->ef_advance = sizeof (uint32_t);
	/* FALLTHROUGH */
	case EXT_STRING:
	case EXT_EXACCT_OBJECT:
	case EXT_RAW:
		if (fread(&len, 1, sizeof (ea_size_t), f->ef_fp)
		    < sizeof (ea_size_t)) {
			obj->eo_type = EO_NONE;
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}
		exacct_order64(&len);
		/* Note: len already includes the size of the backskip. */
		f->ef_advance += sizeof (ea_catalog_t) +
		    sizeof (ea_size_t) + len;
		backup += sizeof (ea_size_t);
		break;
	case EXT_UINT8:
		f->ef_advance = sizeof (ea_catalog_t) + sizeof (uint8_t) +
		    sizeof (uint32_t);
		break;
	case EXT_UINT16:
		f->ef_advance = sizeof (ea_catalog_t) + sizeof (uint16_t) +
		    sizeof (uint32_t);
		break;
	case EXT_UINT32:
		f->ef_advance = sizeof (ea_catalog_t) + sizeof (uint32_t) +
		    sizeof (uint32_t);
		break;
	case EXT_UINT64:
		f->ef_advance = sizeof (ea_catalog_t) + sizeof (uint64_t) +
		    sizeof (uint32_t);
		break;
	case EXT_DOUBLE:
		f->ef_advance = sizeof (ea_catalog_t) + sizeof (double) +
		    sizeof (uint32_t);
		break;
	default:
		obj->eo_type = EO_NONE;
		EXACCT_SET_ERR(EXR_CORRUPT_FILE);
		return (EO_ERROR);
	}

	/* Reposition to the start of this object. */
	if (fseeko(f->ef_fp, -backup, SEEK_CUR) == -1) {
		obj->eo_type = EO_NONE;
		f->ef_advance = 0;
		EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
		return (EO_ERROR);
	}

	EXACCT_SET_ERR(EXR_OK);
	return (obj->eo_type);
}

ea_object_type_t
ea_previous_object(ea_file_t *ef, ea_object_t *obj)
{
	ea_file_impl_t *f = (ea_file_impl_t *)ef;
	uint32_t bkskip;
	int r;

	if (fseeko(f->ef_fp, -((off_t)sizeof (uint32_t)), SEEK_CUR) == -1) {
		if (errno == EINVAL) {
			EXACCT_SET_ERR(EXR_EOF);
		} else {
			EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
		}
		return (EO_ERROR);
	}

	if ((r = fread(&bkskip, 1, sizeof (uint32_t), f->ef_fp)) !=
	    sizeof (uint32_t)) {
		if (r == 0) {
			EXACCT_SET_ERR(EXR_EOF);
		} else {
			EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
		}
		return (EO_ERROR);
	}
	exacct_order32(&bkskip);

	/*
	 * A backskip of 0 means that the current record can't be skipped over.
	 * This will be true for the header record, and for records longer than
	 * 2^32.
	 */
	if (bkskip == 0) {
		EXACCT_SET_ERR(EXR_EOF);
		return (EO_ERROR);
	}
	(void) stack_previous_object(f);

	if (fseeko(f->ef_fp, -((off_t)bkskip), SEEK_CUR) == -1) {
		if (errno == EINVAL) {
			/*
			 * If we attempted to seek past BOF, then the file was
			 * corrupt, as we can only trust the backskip we read.
			 */
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
		} else {
			EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
		}
		return (EO_ERROR);
	}

	f->ef_advance = 0;
	return (ea_next_object(ef, obj));
}

/*
 * xget_object() contains the logic for extracting an individual object from a
 * packed buffer, which it consumes using xread() and xseek() operations
 * provided by the caller.  flags may be set to either EUP_ALLOC, in which case
 * new memory is allocated for the variable length items unpacked, or
 * EUP_NOALLOC, in which case item data pointer indicate locations within the
 * buffer, using the provided xpos() function.  EUP_NOALLOC is generally not
 * useful for callers representing interaction with actual file streams, and
 * should not be specified thereby.
 */
static ea_object_type_t
xget_object(
    ea_file_impl_t *f,
    ea_object_t *obj,
    size_t (*xread)(ea_file_impl_t *, void *, size_t),
    off_t (*xseek)(ea_file_impl_t *, off_t),
    void *(*xpos)(ea_file_impl_t *),
    int flags)
{
	ea_size_t sz;
	uint32_t gp_backskip, scratch32;
	void *buf;
	size_t r;

	/* Read the catalog tag. */
	if ((r = xread(f, &obj->eo_catalog, sizeof (ea_catalog_t))) == 0) {
		EXACCT_SET_ERR(EXR_EOF);
		return (EO_ERROR);
	} else if (r != sizeof (ea_catalog_t)) {
		EXACCT_SET_ERR(EXR_CORRUPT_FILE);
		return (EO_ERROR);
	}
	exacct_order32(&obj->eo_catalog);

	/*
	 * If this is a record group, we treat it separately:  only record
	 * groups cause us to allocate new depth frames.
	 */
	if ((obj->eo_catalog & EXT_TYPE_MASK) == EXT_GROUP) {
		obj->eo_type = EO_GROUP;

		/* Read size field, and number of objects. */
		if (xread(f, &sz, sizeof (ea_size_t)) != sizeof (ea_size_t)) {
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}
		exacct_order64(&sz);
		if (xread(f, &obj->eo_group.eg_nobjs, sizeof (uint32_t)) !=
		    sizeof (uint32_t)) {
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}
		exacct_order32(&obj->eo_group.eg_nobjs);

		/* Now read the group's small backskip. */
		if (xread(f, &gp_backskip, sizeof (uint32_t)) !=
		    sizeof (uint32_t)) {
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}

		/* Push a new depth stack frame. */
		if (stack_new_group(f, obj->eo_group.eg_nobjs) != 0) {
			/* exacct_error set above */
			return (EO_ERROR);
		}

		/*
		 * If the group has no items, we now need to position to the
		 * end of the group, because there will be no subsequent calls
		 * to process the group, it being empty.
		 */
		if (obj->eo_group.eg_nobjs == 0) {
			if (stack_next_object(f, xread) == -1) {
				/* exacct_error set above. */
				return (EO_ERROR);
			}
		}

		f->ef_advance = 0;
		EXACCT_SET_ERR(EXR_OK);
		return (obj->eo_type);
	}

	/*
	 * Otherwise we are reading an item.
	 */
	obj->eo_type = EO_ITEM;
	switch (obj->eo_catalog & EXT_TYPE_MASK) {
	case EXT_STRING:
	case EXT_EXACCT_OBJECT:
	case EXT_RAW:
		if (xread(f, &sz, sizeof (ea_size_t)) != sizeof (ea_size_t)) {
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}
		exacct_order64(&sz);
		/*
		 * Subtract backskip value from size.
		 */
		sz -= sizeof (uint32_t);
		if ((flags & EUP_ALLOC_MASK) == EUP_NOALLOC) {
			buf = xpos(f);
			if (xseek(f, sz) == -1) {
				EXACCT_SET_ERR(EXR_CORRUPT_FILE);
				return (EO_ERROR);
			}
		} else {
			if ((buf = ea_alloc(sz)) == NULL)
				/* exacct_error set above. */
				return (EO_ERROR);
			if (xread(f, buf, sz) != sz) {
				ea_free(buf, sz);
				EXACCT_SET_ERR(EXR_CORRUPT_FILE);
				return (EO_ERROR);
			}
		}
		obj->eo_item.ei_string = buf;
		/*
		 * Maintain our consistent convention that string lengths
		 * include the terminating NULL character.
		 */
		obj->eo_item.ei_size = sz;
		break;
	case EXT_UINT8:
		if (xread(f, &obj->eo_item.ei_uint8, sizeof (uint8_t)) !=
		    sizeof (uint8_t)) {
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}
		obj->eo_item.ei_size = sizeof (uint8_t);
		break;
	case EXT_UINT16:
		if (xread(f, &obj->eo_item.ei_uint16, sizeof (uint16_t)) !=
		    sizeof (uint16_t)) {
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}
		exacct_order16(&obj->eo_item.ei_uint16);
		obj->eo_item.ei_size = sizeof (uint16_t);
		break;
	case EXT_UINT32:
		if (xread(f, &obj->eo_item.ei_uint32, sizeof (uint32_t)) !=
		    sizeof (uint32_t)) {
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}
		exacct_order32(&obj->eo_item.ei_uint32);
		obj->eo_item.ei_size = sizeof (uint32_t);
		break;
	case EXT_UINT64:
		if (xread(f, &obj->eo_item.ei_uint64, sizeof (uint64_t)) !=
		    sizeof (uint64_t)) {
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}
		exacct_order64(&obj->eo_item.ei_uint64);
		obj->eo_item.ei_size = sizeof (uint64_t);
		break;
	case EXT_DOUBLE:
		if (xread(f, &obj->eo_item.ei_double, sizeof (double)) !=
		    sizeof (double)) {
			EXACCT_SET_ERR(EXR_CORRUPT_FILE);
			return (EO_ERROR);
		}
		exacct_order64((uint64_t *)&obj->eo_item.ei_double);
		obj->eo_item.ei_size = sizeof (double);
		break;
	default:
		/*
		 * We've encountered an unknown type value.  Flag the error and
		 * exit.
		 */
		EXACCT_SET_ERR(EXR_CORRUPT_FILE);
		return (EO_ERROR);
	}

	/*
	 * Advance over current large backskip value,
	 * and position at the start of the next object.
	 */
	if (xread(f, &scratch32, sizeof (scratch32)) != sizeof (scratch32)) {
		EXACCT_SET_ERR(EXR_CORRUPT_FILE);
		return (EO_ERROR);
	}
	if (stack_next_object(f, xread) == -1) {
		/* exacct_error set above. */
		return (EO_ERROR);
	}

	f->ef_advance = 0;
	EXACCT_SET_ERR(EXR_OK);
	return (obj->eo_type);
}

ea_object_type_t
ea_get_object(ea_file_t *ef, ea_object_t *obj)
{
	obj->eo_next = NULL;
	return (xget_object((ea_file_impl_t *)ef, obj, fread_wrapper,
		    fseek_wrapper, fpos_wrapper, EUP_ALLOC));
}

/*
 * unpack_group() recursively unpacks record groups from the buffer tucked
 * within the passed ea_file, and attaches them to grp.
 */
static int
unpack_group(ea_file_impl_t *f, ea_object_t *grp, int flag)
{
	ea_object_t *obj;
	uint_t nobjs = grp->eo_group.eg_nobjs;
	int i;

	/*
	 * Set the group's object count to zero, as we will rebuild it via the
	 * individual object attachments.
	 */
	grp->eo_group.eg_nobjs = 0;
	grp->eo_group.eg_objs = NULL;

	for (i = 0; i < nobjs; i++) {
		if ((obj = ea_alloc(sizeof (ea_object_t))) == NULL) {
			/* exacct_errno set above. */
			return (-1);
		}
		obj->eo_next = NULL;
		if (xget_object(f, obj, bufread_wrapper, bufseek_wrapper,
			    bufpos_wrapper, flag) == -1) {
			ea_free(obj, sizeof (ea_object_t));
			/* exacct_errno set above. */
			return (-1);
		}

		(void) ea_attach_to_group(grp, obj);

		if (obj->eo_type == EO_GROUP &&
		    unpack_group(f, obj, flag) == -1) {
			/* exacct_errno set above. */
			return (-1);
		}
	}

	if (nobjs != grp->eo_group.eg_nobjs) {
		EXACCT_SET_ERR(EXR_CORRUPT_FILE);
		return (-1);
	}
	EXACCT_SET_ERR(EXR_OK);
	return (0);
}

/*
 * ea_unpack_object() can be considered as a finite series of get operations on
 * a given buffer, that rebuilds the hierarchy of objects compacted by a pack
 * operation.  Because there is complex state associated with the group depth,
 * ea_unpack_object() must complete as one operation on a given buffer.
 */
ea_object_type_t
ea_unpack_object(ea_object_t **objp, int flag, void *buf, size_t bufsize)
{
	ea_file_impl_t fake;
	ea_object_t *obj;
	ea_object_type_t first_obj_type;

	*objp = NULL;
	if (buf == NULL) {
		EXACCT_SET_ERR(EXR_INVALID_BUF);
		return (EO_ERROR);
	}

	/* Set up the structures needed for unpacking */
	bzero(&fake, sizeof (ea_file_impl_t));
	if (stack_check(&fake) == -1) {
		/* exacct_errno set above. */
		return (EO_ERROR);
	}
	fake.ef_buf = buf;
	fake.ef_bufsize = bufsize;

	/* Unpack the first object in the buffer - this should succeed. */
	if ((obj = ea_alloc(sizeof (ea_object_t))) == NULL) {
		stack_free(&fake);
		/* exacct_errno set above. */
		return (EO_ERROR);
	}
	obj->eo_next = NULL;
	if ((first_obj_type = xget_object(&fake, obj, bufread_wrapper,
	    bufseek_wrapper, bufpos_wrapper, flag)) == -1) {
		stack_free(&fake);
		ea_free(obj, sizeof (ea_object_t));
		/* exacct_errno set above. */
		return (EO_ERROR);
	}

	if (obj->eo_type == EO_GROUP && unpack_group(&fake, obj, flag) == -1) {
		stack_free(&fake);
		ea_free_object(obj, flag);
		/* exacct_errno set above. */
		return (EO_ERROR);
	}
	*objp = obj;

	/*
	 * There may be other objects in the buffer - if so, chain them onto
	 * the end of the list.  We have reached the end of the list when
	 * xget_object() returns -1 with exacct_error set to EXR_EOF.
	 */
	for (;;) {
		if ((obj = ea_alloc(sizeof (ea_object_t))) == NULL) {
			stack_free(&fake);
			ea_free_object(*objp, flag);
			*objp = NULL;
			/* exacct_errno set above. */
			return (EO_ERROR);
		}
		obj->eo_next = NULL;
		if (xget_object(&fake, obj, bufread_wrapper, bufseek_wrapper,
			    bufpos_wrapper, flag) == -1) {
			stack_free(&fake);
			ea_free(obj, sizeof (ea_object_t));
			if (ea_error() == EXR_EOF) {
				EXACCT_SET_ERR(EXR_OK);
				return (first_obj_type);
			} else {
				ea_free_object(*objp, flag);
				*objp = NULL;
				/* exacct_error set above. */
				return (EO_ERROR);
			}
		}

		(void) ea_attach_to_object(*objp, obj);

		if (obj->eo_type == EO_GROUP &&
		    unpack_group(&fake, obj, flag) == -1) {
			stack_free(&fake);
			ea_free(obj, sizeof (ea_object_t));
			ea_free_object(*objp, flag);
			*objp = NULL;
			/* exacct_errno set above. */
			return (EO_ERROR);
		}
	}
}

int
ea_write_object(ea_file_t *ef, ea_object_t *obj)
{
	ea_size_t sz;
	void *buf;
	ea_file_impl_t *f = (ea_file_impl_t *)ef;

	/*
	 * If we weren't opened for writing, this call fails.
	 */
	if ((f->ef_oflags & O_RDWR) == 0 &&
	    (f->ef_oflags & O_WRONLY) == 0) {
		EXACCT_SET_ERR(EXR_NOTSUPP);
		return (-1);
	}

	/* Pack with a null buffer to get the size. */
	sz = ea_pack_object(obj, NULL, 0);
	if (sz == -1 || (buf = ea_alloc(sz)) == NULL) {
		/* exacct_error set above. */
		return (-1);
	}
	if (ea_pack_object(obj, buf, sz) == (size_t)-1) {
		ea_free(buf, sz);
		/* exacct_error set above. */
		return (-1);
	}
	if (fwrite(buf, sizeof (char), sz, f->ef_fp) != sz) {
		ea_free(buf, sz);
		EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
		return (-1);
	}
	ea_free(buf, sz);
	EXACCT_SET_ERR(EXR_OK);
	return (0);
}

/*
 * validate_header() must be kept in sync with write_header(), given below, and
 * exacct_create_header(), in uts/common/os/exacct.c.
 */
static int
validate_header(ea_file_t *ef, const char *creator)
{
	ea_object_t hdr_grp;
	ea_object_t scratch_obj;
	int error = EXR_OK;
	int saw_creator = 0;
	int saw_version = 0;
	int saw_type = 0;
	int saw_hostname = 0;
	int n;
	ea_file_impl_t *f = (ea_file_impl_t *)ef;

	bzero(&hdr_grp, sizeof (ea_object_t));

	if (ea_get_object(ef, &hdr_grp) != EO_GROUP) {
		error = ea_error();
		goto error_case;
	}

	if (hdr_grp.eo_catalog !=
	    (EXT_GROUP | EXC_DEFAULT | EXD_GROUP_HEADER)) {
		error = EXR_CORRUPT_FILE;
		goto error_case;
	}

	for (n = 0; n < hdr_grp.eo_group.eg_nobjs; n++) {
		bzero(&scratch_obj, sizeof (ea_object_t));
		if (ea_get_object(ef, &scratch_obj) == -1) {
			error = ea_error();
			goto error_case;
		}

		switch (scratch_obj.eo_catalog) {
		case EXT_UINT32 | EXC_DEFAULT | EXD_VERSION:
			if (scratch_obj.eo_item.ei_uint32 != EXACCT_VERSION) {
				error = EXR_UNKN_VERSION;
				goto error_case;
			}
			saw_version++;
			break;
		case EXT_STRING | EXC_DEFAULT | EXD_FILETYPE:
			if (strcmp(scratch_obj.eo_item.ei_string,
			    EXACCT_HDR_STR) != 0) {
				error = EXR_CORRUPT_FILE;
				goto error_case;
			}
			saw_type++;
			break;
		case EXT_STRING | EXC_DEFAULT | EXD_CREATOR:
			f->ef_creator =
			    ea_strdup(scratch_obj.eo_item.ei_string);
			if (f->ef_creator == NULL) {
				error = ea_error();
				goto error_case;
			}
			saw_creator++;
			break;
		/* The hostname is an optional field. */
		case EXT_STRING | EXC_DEFAULT | EXD_HOSTNAME:
			f->ef_hostname =
			    ea_strdup(scratch_obj.eo_item.ei_string);
			if (f->ef_hostname == NULL) {
				error = ea_error();
				goto error_case;
			}
			saw_hostname++;
			break;
		default:
			/* ignore unrecognized header members */
			break;
		}
		(void) ea_free_item(&scratch_obj, EUP_ALLOC);
	}

	if (saw_version && saw_type && saw_creator) {
		if (creator && strcmp(f->ef_creator, creator) != 0) {
			error = EXR_NO_CREATOR;
			goto error_case;
		}
		EXACCT_SET_ERR(EXR_OK);
		return (0);
	}

error_case:
	(void) ea_free_item(&scratch_obj, EUP_ALLOC);
	if (saw_hostname)
		ea_strfree(f->ef_hostname);
	if (saw_creator)
		ea_strfree(f->ef_creator);
	EXACCT_SET_ERR(error);
	return (-1);
}

static int
write_header(ea_file_t *ef)
{
	ea_object_t hdr_grp;
	ea_object_t vers_obj;
	ea_object_t creator_obj;
	ea_object_t filetype_obj;
	ea_object_t hostname_obj;
	uint32_t bskip;
	const uint32_t version = EXACCT_VERSION;
	ea_file_impl_t *f = (ea_file_impl_t *)ef;
	void *buf;
	size_t bufsize;
	char hostbuf[SYSINFO_BUFSIZE];
	int error = EXR_OK;

	bzero(&hdr_grp, sizeof (ea_object_t));
	bzero(&vers_obj, sizeof (ea_object_t));
	bzero(&creator_obj, sizeof (ea_object_t));
	bzero(&filetype_obj, sizeof (ea_object_t));
	bzero(&hostname_obj, sizeof (ea_object_t));
	bzero(hostbuf, SYSINFO_BUFSIZE);

	(void) sysinfo(SI_HOSTNAME, hostbuf, SYSINFO_BUFSIZE);

	if (ea_set_item(&vers_obj, EXT_UINT32 | EXC_DEFAULT | EXD_VERSION,
		    (void *)&version, 0) == -1 ||
	    ea_set_item(&creator_obj, EXT_STRING | EXC_DEFAULT | EXD_CREATOR,
		    f->ef_creator, strlen(f->ef_creator)) == -1 ||
	    ea_set_item(&filetype_obj, EXT_STRING | EXC_DEFAULT | EXD_FILETYPE,
		    EXACCT_HDR_STR, strlen(EXACCT_HDR_STR)) == -1 ||
	    ea_set_item(&hostname_obj, EXT_STRING | EXC_DEFAULT | EXD_HOSTNAME,
		    hostbuf, strlen(hostbuf)) == -1) {
		error = ea_error();
		goto cleanup1;
	}

	(void) ea_set_group(&hdr_grp,
	    EXT_GROUP | EXC_DEFAULT | EXD_GROUP_HEADER);
	(void) ea_attach_to_group(&hdr_grp, &vers_obj);
	(void) ea_attach_to_group(&hdr_grp, &creator_obj);
	(void) ea_attach_to_group(&hdr_grp, &filetype_obj);
	(void) ea_attach_to_group(&hdr_grp, &hostname_obj);

	/* Get the required size by passing a null buffer. */
	bufsize = ea_pack_object(&hdr_grp, NULL, 0);
	if ((buf = ea_alloc(bufsize)) == NULL) {
		error = ea_error();
		goto cleanup1;
	}

	if (ea_pack_object(&hdr_grp, buf, bufsize) == (size_t)-1) {
		error = ea_error();
		goto cleanup2;
	}

	/*
	 * To prevent reading the header when reading the file backwards,
	 * set the large backskip of the header group to 0 (last 4 bytes).
	 */
	bskip = 0;
	exacct_order32(&bskip);
	bcopy(&bskip, (char *)buf + bufsize - sizeof (bskip),
	    sizeof (bskip));

	if (fwrite(buf, sizeof (char), bufsize, f->ef_fp) != bufsize ||
	    fflush(f->ef_fp) == EOF) {
		error = EXR_SYSCALL_FAIL;
		goto cleanup2;
	}

cleanup2:
	ea_free(buf, bufsize);
cleanup1:
	(void) ea_free_item(&vers_obj, EUP_ALLOC);
	(void) ea_free_item(&creator_obj, EUP_ALLOC);
	(void) ea_free_item(&filetype_obj, EUP_ALLOC);
	(void) ea_free_item(&hostname_obj, EUP_ALLOC);
	EXACCT_SET_ERR(error);
	return (error == EXR_OK ? 0 : -1);
}

const char *
ea_get_creator(ea_file_t *ef)
{
	return ((const char *)((ea_file_impl_t *)ef)->ef_creator);
}

const char *
ea_get_hostname(ea_file_t *ef)
{
	return ((const char *)((ea_file_impl_t *)ef)->ef_hostname);
}

int
ea_fdopen(ea_file_t *ef, int fd, const char *creator, int aflags, int oflags)
{
	ea_file_impl_t *f = (ea_file_impl_t *)ef;

	bzero(f, sizeof (*f));
	f->ef_oflags = oflags;
	f->ef_fd = fd;

	/* Initialize depth stack. */
	if (stack_check(f) == -1) {
		/* exacct_error set above. */
		goto error1;
	}

	/*
	 * 1.  If we are O_CREAT, then we will need to write a header
	 * after opening name.
	 */
	if (oflags & O_CREAT) {
		if (creator == NULL) {
			EXACCT_SET_ERR(EXR_NO_CREATOR);
			goto error2;
		}
		if ((f->ef_creator = ea_strdup(creator)) == NULL) {
			/* exacct_error set above. */
			goto error2;
		}
		if ((f->ef_fp = fdopen(f->ef_fd, "w")) == NULL) {
			EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
			goto error3;
		}
		if (write_header(ef) == -1) {
			/* exacct_error set above. */
			goto error3;
		}

	/*
	 * 2.  If we are not O_CREAT, but are RDWR or WRONLY, we need to
	 * seek to EOF so that appends will succeed.
	 */
	} else if (oflags & O_RDWR || oflags & O_WRONLY) {
		if ((f->ef_fp = fdopen(f->ef_fd, "r+")) == NULL) {
			EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
			goto error2;
		}

		if ((aflags & EO_VALIDATE_MSK) == EO_VALID_HDR) {
			if (validate_header(ef, creator) < 0) {
				/* exacct_error set above. */
				goto error2;
			}
		}

		if (fseeko(f->ef_fp, 0, SEEK_END) == -1) {
			EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
			goto error2;
		}

	/*
	 * 3. This is an undefined manner for opening an exacct file.
	 */
	} else if (oflags != O_RDONLY) {
		EXACCT_SET_ERR(EXR_NOTSUPP);
		goto error2;

	/*
	 * 4a.  If we are RDONLY, then we are in a position such that
	 * either a ea_get_object or an ea_next_object will succeed.  If
	 * aflags was set to EO_TAIL, seek to the end of the file.
	 */
	} else {
		if ((f->ef_fp = fdopen(f->ef_fd, "r")) == NULL) {
			EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
			goto error2;
		}

		if ((aflags & EO_VALIDATE_MSK) == EO_VALID_HDR) {
			if (validate_header(ef, creator) == -1) {
				/* exacct_error set above. */
				goto error2;
			}
		}

		/*
		 * 4b.  Handle the "open at end" option, for consumers who want
		 * to go backwards through the file (i.e. lastcomm).
		 */
		if ((aflags & EO_POSN_MSK) == EO_TAIL) {
			if (fseeko(f->ef_fp, 0, SEEK_END) < 0) {
				EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
				goto error2;
			}
		}
	}

	EXACCT_SET_ERR(EXR_OK);
	return (0);

	/* Error cleanup code */
error3:
	ea_strfree(f->ef_creator);
error2:
	stack_free(f);
error1:
	bzero(f, sizeof (*f));
	return (-1);
}

int
ea_open(ea_file_t *ef, const char *name, const char *creator,
    int aflags, int oflags, mode_t mode)
{
	int fd;

	/*
	 * If overwriting an existing file, make sure to truncate it
	 * to prevent the file being created corrupt.
	 */
	if (oflags & O_CREAT)
		oflags |= O_TRUNC;

	if ((fd = open(name, oflags, mode)) == -1) {
		EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
		return (-1);
	}

	if (ea_fdopen(ef, fd, creator, aflags, oflags) == -1) {
		(void) close(fd);
		return (-1);
	}

	return (0);
}

/*
 * ea_close() performs all appropriate close operations on the open exacct file,
 * including releasing any memory allocated while parsing the file.
 */
int
ea_close(ea_file_t *ef)
{
	ea_file_impl_t *f = (ea_file_impl_t *)ef;

	if (f->ef_creator != NULL)
		ea_strfree(f->ef_creator);
	if (f->ef_hostname != NULL)
		ea_strfree(f->ef_hostname);

	ea_free(f->ef_depth, f->ef_mxdeep * sizeof (ea_file_depth_t));

	if (fclose(f->ef_fp)) {
		EXACCT_SET_ERR(EXR_SYSCALL_FAIL);
		return (-1);
	}

	EXACCT_SET_ERR(EXR_OK);
	return (0);
}

/*
 * Empty the input buffer and clear any underlying EOF or error bits set on the
 * underlying FILE.  This can be used by any library clients who wish to handle
 * files that are in motion or who wish to seek the underlying file descriptor.
 */
void
ea_clear(ea_file_t *ef)
{
	ea_file_impl_t *f = (ea_file_impl_t *)ef;

	(void) fflush(f->ef_fp);
	clearerr(f->ef_fp);
}

/*
 * Copy an ea_object_t.  Note that in the case of a group, just the group
 * object will be copied, and not its list of members.  To recursively copy
 * a group or a list of items use ea_copy_tree().
 */
ea_object_t *
ea_copy_object(const ea_object_t *src)
{
	ea_object_t *dst;

	/* Allocate a new object and copy to it. */
	if ((dst = ea_alloc(sizeof (ea_object_t))) == NULL) {
		return (NULL);
	}
	bcopy(src, dst, sizeof (ea_object_t));
	dst->eo_next = NULL;

	switch (src->eo_type) {
	case EO_GROUP:
		dst->eo_group.eg_nobjs = 0;
		dst->eo_group.eg_objs = NULL;
		break;
	case EO_ITEM:
		/* Items containing pointers need special treatment. */
		switch (src->eo_catalog & EXT_TYPE_MASK) {
		case EXT_STRING:
			if (src->eo_item.ei_string != NULL) {
				dst->eo_item.ei_string =
				    ea_strdup(src->eo_item.ei_string);
				if (dst->eo_item.ei_string == NULL) {
					ea_free_object(dst, EUP_ALLOC);
					return (NULL);
				}
			}
			break;
		case EXT_RAW:
			if (src->eo_item.ei_raw != NULL) {
				dst->eo_item.ei_raw =
				    ea_alloc(src->eo_item.ei_size);
				if (dst->eo_item.ei_raw == NULL) {
					ea_free_object(dst, EUP_ALLOC);
					return (NULL);
				}
				bcopy(src->eo_item.ei_raw, dst->eo_item.ei_raw,
				    (size_t)src->eo_item.ei_size);
			}
			break;
		case EXT_EXACCT_OBJECT:
			if (src->eo_item.ei_object != NULL) {
				dst->eo_item.ei_object =
				    ea_alloc(src->eo_item.ei_size);
				if (dst->eo_item.ei_object == NULL) {
					ea_free_object(dst, EUP_ALLOC);
					return (NULL);
				}
				bcopy(src->eo_item.ei_raw, dst->eo_item.ei_raw,
				    (size_t)src->eo_item.ei_size);
			}
			break;
		default:
			/* Other item types require no special handling. */
			break;
		}
		break;
	default:
		ea_free_object(dst, EUP_ALLOC);
		EXACCT_SET_ERR(EXR_INVALID_OBJ);
		return (NULL);
	}
	EXACCT_SET_ERR(EXR_OK);
	return (dst);
}

/*
 * Recursively copy a list of ea_object_t.  All the elements in the eo_next
 * list will be copied, and any group objects will be recursively copied.
 */
ea_object_t *
ea_copy_object_tree(const ea_object_t *src)
{
	ea_object_t *ret_obj, *dst, *last;

	for (ret_obj = last = NULL; src != NULL;
	    last = dst, src = src->eo_next) {

		/* Allocate a new object and copy to it. */
		if ((dst = ea_copy_object(src)) == NULL) {
			ea_free_object(ret_obj, EUP_ALLOC);
			return (NULL);
		}

		/* Groups need the object list copying. */
		if (src->eo_type == EO_GROUP) {
			dst->eo_group.eg_objs =
			    ea_copy_object_tree(src->eo_group.eg_objs);
			if (dst->eo_group.eg_objs == NULL) {
				ea_free_object(ret_obj, EUP_ALLOC);
				return (NULL);
			}
			dst->eo_group.eg_nobjs = src->eo_group.eg_nobjs;
		}

		/* Remember the list head the first time round. */
		if (ret_obj == NULL) {
			ret_obj = dst;
		}

		/* Link together if not at the list head. */
		if (last != NULL) {
			last->eo_next = dst;
		}
	}
	EXACCT_SET_ERR(EXR_OK);
	return (ret_obj);
}

/*
 * Read in the specified number of objects, returning the same data
 * structure that would have originally been passed to ea_write().
 */
ea_object_t *
ea_get_object_tree(ea_file_t *ef, uint32_t nobj)
{
	ea_object_t *first_obj, *prev_obj, *obj;

	first_obj = prev_obj = NULL;
	while (nobj--) {
		/* Allocate space for the new object. */
		obj = ea_alloc(sizeof (ea_object_t));
		bzero(obj, sizeof (*obj));

		/* Read it in. */
		if (ea_get_object(ef, obj) == -1) {
			ea_free(obj, sizeof (ea_object_t));
			if (first_obj != NULL) {
				ea_free_object(first_obj, EUP_ALLOC);
			}
			return (NULL);
		}

		/* Link it into the list. */
		if (first_obj == NULL) {
			first_obj = obj;
		}
		if (prev_obj != NULL) {
			prev_obj->eo_next = obj;
		}
		prev_obj = obj;

		/* Recurse if the object is a group with contents. */
		if (obj->eo_type == EO_GROUP && obj->eo_group.eg_nobjs > 0) {
			if ((obj->eo_group.eg_objs = ea_get_object_tree(ef,
			    obj->eo_group.eg_nobjs)) == NULL) {
				/* exacct_error set above. */
				ea_free_object(first_obj, EUP_ALLOC);
				return (NULL);
			}
		}
	}
	EXACCT_SET_ERR(EXR_OK);
	return (first_obj);
}
