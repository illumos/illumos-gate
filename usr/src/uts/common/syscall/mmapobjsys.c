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

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/cred.h>
#include <sys/model.h>
#include <sys/vnode.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/mmapobj.h>

/*
 * We will "allocate" this many mmapobj_result_t segments on the stack
 * in an attempt to avoid the need to call kmem_alloc. This value should
 * cover 99% of the known ELF libraries as well as AOUT (4.x) libraries.
 */
#define	MOBJ_STACK_SEGS	6

static void
mmapobj_copy_64to32(mmapobj_result_t *source, mmapobj_result32_t *dest, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		dest[i].mr_addr = (caddr32_t)(uintptr_t)source[i].mr_addr;
		dest[i].mr_msize = (size32_t)source[i].mr_msize;
		dest[i].mr_fsize = (size32_t)source[i].mr_fsize;
		dest[i].mr_offset = (size32_t)source[i].mr_offset;
		dest[i].mr_prot = source[i].mr_prot;
		dest[i].mr_flags = source[i].mr_flags;
	}
}

int
mmapobjsys(int fd, uint_t flags, mmapobj_result_t *storage,
    uint_t *elements, void *arg)
{
	uint_t num_mapped;
	uint_t num_in;
	int error;
	int old_error;
	size_t padding = 0;
	mmapobj_result_t stack_mr[MOBJ_STACK_SEGS];
	mmapobj_result_t *mrp = stack_mr;
	struct file *fp;
	struct vnode *vp;
	model_t model;
	int convert_64to32 = 0;
	uint_t alloc_num = 0;


	/* Verify flags */
	if ((flags & ~MMOBJ_ALL_FLAGS) != 0) {
		return (set_errno(EINVAL));
	}

	if (((flags & MMOBJ_PADDING) == 0) && arg != NULL) {
		return (set_errno(EINVAL));
	}

	fp = getf(fd);
	if (fp == NULL) {
		return (set_errno(EBADF));
	}
	vp = fp->f_vnode;

	if ((fp->f_flag & FREAD) == 0) {
		error = EACCES;
		goto out;
	}

	error = copyin(elements, &num_mapped, sizeof (uint_t));
	if (error) {
		error = EFAULT;
		goto out;
	}

	num_in = num_mapped;
	model = get_udatamodel();
	if (model != DATAMODEL_NATIVE) {
		ASSERT(model == DATAMODEL_ILP32);
		convert_64to32 = 1;
	}

	if (flags & MMOBJ_PADDING) {
		if (convert_64to32) {
			size32_t padding32;
			error = copyin(arg, &padding32, sizeof (padding32));
			padding = padding32;
		} else {
			error = copyin(arg, &padding, sizeof (padding));
		}
		if (error) {
			error = EFAULT;
			goto out;
		}

		/*
		 * Need to catch overflow here for the 64 bit case.  For the
		 * 32 bit case, overflow would round up to 4G which would
		 * not be able to fit in any address space and thus ENOMEM
		 * would be returned after calling into mmapobj.
		 */
		if (padding) {
			padding = P2ROUNDUP(padding, PAGESIZE);
			if (padding == 0) {
				error = ENOMEM;
				goto out;
			}
		}
		/* turn off padding if no bytes were requested */
		if (padding == 0) {
			flags = flags & (~MMOBJ_PADDING);
		}
	}

	if (num_mapped > MOBJ_STACK_SEGS) {
		num_mapped = MOBJ_STACK_SEGS;
	}
retry:
	error = mmapobj(vp, flags, mrp, &num_mapped, padding, fp->f_cred);

	if (error == E2BIG && alloc_num == 0) {
		if (num_mapped > MOBJ_STACK_SEGS && num_mapped <= num_in) {
			mrp = kmem_alloc(sizeof (mmapobj_result_t) * num_mapped,
			    KM_SLEEP);
			alloc_num = num_mapped;
			goto retry;
		}
	}

	old_error = error;
	if (error == 0 || error == E2BIG) {
		error = copyout(&num_mapped, elements, sizeof (uint_t));
		if (error) {
			error = EFAULT;
			/*
			 * We only mapped in segments if the mmapobj call
			 * succeeded, so only unmap for that case.
			 */
			if (old_error == 0) {
				mmapobj_unmap(mrp, num_mapped, num_mapped, 0);
			}
		} else if (num_in < num_mapped) {
			ASSERT(old_error == E2BIG);
			error = E2BIG;
		} else {
			if (convert_64to32) {
				mmapobj_result32_t *mrp32;
				/* Need to translate from 64bit to 32bit */
				mrp32 = kmem_alloc(num_mapped * sizeof (*mrp32),
				    KM_SLEEP);
				mmapobj_copy_64to32(mrp, mrp32, num_mapped);
				error = copyout(mrp32, (void *)storage,
				    num_mapped * sizeof (mmapobj_result32_t));
				kmem_free(mrp32, num_mapped * sizeof (*mrp32));
			} else {
				error = copyout(mrp, (void *)storage,
				    num_mapped * sizeof (mmapobj_result_t));
			}
			if (error) {
				error = EFAULT;
				mmapobj_unmap(mrp, num_mapped, num_mapped, 0);
			}
		}
	}

	/*
	 * If stack_mr was not large enough, then we had to allocate
	 * a larger piece of memory to hold the mmapobj_result array.
	 */
	if (alloc_num != 0) {
		ASSERT(mrp != stack_mr);
		ASSERT(num_mapped > MOBJ_STACK_SEGS);
		kmem_free(mrp,
		    alloc_num * sizeof (mmapobj_result_t));
	}

out:
	releasef(fd);
	if (error) {
		return (set_errno(error));
	} else {
		return (0);
	}
}
