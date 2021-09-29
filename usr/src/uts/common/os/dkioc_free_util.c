/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2020 Joyent, Inc.
 */

/* needed when building libzpool */
#ifndef	_KERNEL
#include <sys/zfs_context.h>
#endif

#include <sys/sunddi.h>
#include <sys/dkio.h>
#include <sys/dkioc_free_util.h>
#include <sys/sysmacros.h>
#include <sys/file.h>
#include <sys/sdt.h>

static int adjust_exts(dkioc_free_list_t *, const dkioc_free_info_t *,
    uint64_t len_blk);
static int split_extent(dkioc_free_list_t *, const dkioc_free_info_t *,
    uint64_t, dfl_iter_fn_t, void *, int);
static int process_range(dkioc_free_list_t *, uint64_t, uint64_t,
    dfl_iter_fn_t, void *, int);

/*
 * Copy-in convenience function for variable-length dkioc_free_list_t
 * structures. The pointer to be copied from is in `arg' (may be a pointer
 * to userspace). A new buffer is allocated and a pointer to it is placed
 * in `out'. `ddi_flags' indicates whether the pointer is from user-
 * or kernelspace (FKIOCTL) and `kmflags' are the flags passed to
 * kmem_zalloc when allocating the new structure.
 * Returns 0 on success, or an errno on failure.
 */
int
dfl_copyin(void *arg, dkioc_free_list_t **out, int ddi_flags, int kmflags)
{
	dkioc_free_list_t *dfl;

	if (ddi_flags & FKIOCTL) {
		dkioc_free_list_t *dfl_in = arg;

		if (dfl_in->dfl_num_exts == 0 ||
		    dfl_in->dfl_num_exts > DFL_COPYIN_MAX_EXTS)
			return (SET_ERROR(EINVAL));
		dfl = kmem_alloc(DFL_SZ(dfl_in->dfl_num_exts), kmflags);
		if (dfl == NULL)
			return (SET_ERROR(ENOMEM));
		bcopy(dfl_in, dfl, DFL_SZ(dfl_in->dfl_num_exts));
	} else {
		uint64_t num_exts;

		if (ddi_copyin(((uint8_t *)arg) + offsetof(dkioc_free_list_t,
		    dfl_num_exts), &num_exts, sizeof (num_exts),
		    ddi_flags) != 0)
			return (SET_ERROR(EFAULT));
		if (num_exts == 0 || num_exts > DFL_COPYIN_MAX_EXTS)
			return (SET_ERROR(EINVAL));
		dfl = kmem_alloc(DFL_SZ(num_exts), kmflags);
		if (dfl == NULL)
			return (SET_ERROR(ENOMEM));
		if (ddi_copyin(arg, dfl, DFL_SZ(num_exts), ddi_flags) != 0 ||
		    dfl->dfl_num_exts != num_exts) {
			kmem_free(dfl, DFL_SZ(num_exts));
			return (SET_ERROR(EFAULT));
		}
	}

	*out = dfl;
	return (0);
}

/* Frees a variable-length dkioc_free_list_t structure. */
void
dfl_free(dkioc_free_list_t *dfl)
{
	kmem_free(dfl, DFL_SZ(dfl->dfl_num_exts));
}

/*
 * Convenience function to resize and segment the array of extents in
 * a DKIOCFREE request as required by a driver.
 *
 * Some devices that implement DKIOCFREE (e.g. vioblk) have limits
 * on either the number of extents that can be submitted in a single request,
 * or the total number of blocks that can be submitted in a single request.
 * In addition, devices may have alignment requirements on the starting
 * address stricter than the device block size.
 *
 * Since there is currently no mechanism for callers of DKIOCFREE to discover
 * such restrictions, instead of rejecting any requests that do not conform to
 * some undiscoverable (to the caller) set of requirements, a driver can use
 * dfl_iter() to adjust and resegment the extents from a DKIOCFREE call as
 * required to conform to its requirements.
 *
 * The original request is passed as 'dfl' and the alignment requirements
 * are passed in 'dfi'. Additionally the maximum offset of the device allowed
 * in bytes) is passed as max_off -- this allows a driver with
 * multiple instances of different sizes but similar requirements (e.g.
 * a partitioned blkdev device) to not construct a separate dkioc_free_info_t
 * struct for each device.
 *
 * dfl_iter() will call 'func' with a dkioc_free_list_t and the value of
 * arg passed to it as needed. If the extents in the dkioc_free_list_t passed
 * to dfl_iter() meet all the requirements in 'dfi', the dkioc_free_list_t will
 * be passed on to 'func' unmodified. If any of the extents passed to dfl_iter()
 * do not meet the requirements, dfl_iter() will allocate new dkioc_free_list_t
 * instances and populate them with the adjusted extents that do conform to the
 * requirements in 'dfi'. dfl_iter() will also free the dkioc_free_list_t
 * passed to it when this occurs. The net result is that 'func' can always
 * assume it will be called with a dkioc_free_list_t with extents that
 * comply with the requirements in 'dfi'. 'func' is also responsible for
 * freeing the dkioc_free_list_t passed to it (likely via a completion
 * callback).
 *
 * Combined with the behavior described above, dfl_iter() can be viewed as
 * consuming the dkioc_free_list_t passed to it. Either it will pass it along
 * to 'func' (and let 'func' handle freeing it), or it will free it and
 * allocate one or more new dkioc_free_list_ts to pass to 'func' (while still
 * letting 'func' handle freeing the new instances). This way neither the
 * dfl_iter() caller nor nor the driver need to worry about treating
 * conforming and non-conforming requests differently.
 *
 * Unfortunately, the DKIOCFREE ioctl provides no method for communicating
 * any notion of partial completion -- either it returns success (0) or
 * an error. It's not clear if such a notion would even be possible while
 * supporting multiple types of devices (NVMe, SCSI, etc.) with the same
 * interface. As such, there's little benefit to providing more detailed error
 * semantics beyond what DKIOCFREE can handle.
 *
 * Due to this, a somewhat simplistic approach is taken to error handling. The
 * original list of extents is first checked to make sure they all appear
 * valid -- that is they do not start or extend beyond the end of the device.
 * Any request that contains such extents is always rejected in it's entirety.
 * It is possible after applying any needed adjustments to the original list
 * of extents that the result is not acceptable to the driver. For example,
 * a device with a 512 byte block size that tries to free the range 513-1023
 * (bytes) would not be able to be processed. Such extents will be silently
 * ignored. If the original request consists of nothing but such requests,
 * dfl_iter() will never call 'func' and will merely return 0.
 */
int
dfl_iter(dkioc_free_list_t *dfl, const dkioc_free_info_t *dfi, uint64_t max_off,
    dfl_iter_fn_t func, void *arg, int kmflag)
{
	dkioc_free_list_ext_t *ext;
	uint64_t n_bytes, n_segs, start_idx, i;
	uint_t bsize = 1U << dfi->dfi_bshift;
	int r = 0;
	boolean_t need_copy = B_FALSE;

	/*
	 * Make sure the block size derived from dfi_bshift is at least 512
	 * (1U << DEV_BSHIFT) bytes and less than 2^30. The lower bound is
	 * to prevent any problems with other parts of the system that might
	 * assume a minimum block size of 512, and the upper bound is just
	 * to prevent overflow when creating the block size from dfi_bshift
	 * (though it seems unlikely we'll have _block_ sizes near a GiB
	 * any time soon).
	 */
	if (dfi->dfi_bshift < DEV_BSHIFT || dfi->dfi_bshift > 30) {
		r = SET_ERROR(EINVAL);
		goto done;
	}

	/* Max bytes must be a multiple of the block size */
	if (!IS_P2ALIGNED(dfi->dfi_max_bytes, bsize)) {
		r = SET_ERROR(EINVAL);
		goto done;
	}

	/* Start offset alignment must also be a multiple of the block size */
	if (dfi->dfi_align == 0 || !IS_P2ALIGNED(dfi->dfi_align, bsize)) {
		r = SET_ERROR(EINVAL);
		goto done;
	}

	/* Max bytes in an extent must be a multiple of the block size */
	if (!IS_P2ALIGNED(dfi->dfi_max_ext_bytes, bsize)) {
		r = SET_ERROR(EINVAL);
		goto done;
	}

	/*
	 * It makes no sense to allow a single extent to be larger than the
	 * total allowed for an entire request.
	 */
	if (dfi->dfi_max_ext_bytes > 0 &&
	    dfi->dfi_max_ext_bytes > dfi->dfi_max_bytes) {
		r = SET_ERROR(EINVAL);
		goto done;
	}

	/*
	 * The first pass, align everything as needed and make sure all the
	 * extents look valid.
	 */
	if ((r = adjust_exts(dfl, dfi, max_off)) != 0) {
		goto done;
	}

	/*
	 * Go through and split things up as needed. The general idea is to
	 * split along the original extent boundaries when needed. We only
	 * split an extent from the original request into multiple extents
	 * if the original extent is by itself too big for the device to
	 * process in a single request.
	 */
	start_idx = 0;
	n_bytes = n_segs = 0;
	ext = dfl->dfl_exts;
	for (i = 0; i < dfl->dfl_num_exts; i++, ext++) {
		uint64_t start = dfl->dfl_offset + ext->dfle_start;
		uint64_t len = ext->dfle_length;

		if (len == 0) {
			/*
			 * If we encounter a zero length extent, we're going
			 * to create a new copy of dfl no matter what --
			 * the size of dfl is determined by dfl_num_exts so
			 * we cannot do things like shift the contents and
			 * reduce dfl_num_exts to get a contiguous array
			 * of non-zero length extents.
			 */
			need_copy = B_TRUE;
			continue;
		}

		if (dfi->dfi_max_ext_bytes > 0 &&
		    len > dfi->dfi_max_ext_bytes) {
			/*
			 * An extent that's too large. Dispatch what we've
			 * accumulated, and then split this extent into
			 * smaller ones the device can accept.
			 */
			if ((r = process_range(dfl, start_idx, i - start_idx,
			    func, arg, kmflag)) != 0) {
				goto done;
			}

			if ((r = split_extent(dfl, dfi, i, func, arg,
			    kmflag)) != 0) {
				goto done;
			}
			start_idx = i + 1;
			n_segs = 0;
			n_bytes = 0;
			continue;
		}

		if (dfi->dfi_max_bytes > 0 &&
		    n_bytes + len > dfi->dfi_max_bytes) {
			/*
			 * This extent would put us over the limit for total
			 * bytes that can be trimmed in one request.
			 * Dispatch what we've accumulated. Then deal
			 * with this extent.
			 */
			if ((r = process_range(dfl, start_idx, i - start_idx,
			    func, arg, kmflag)) != 0) {
				goto done;
			}

			if (len < dfi->dfi_max_bytes) {
				/*
				 * After dispatching what we've accumulated,
				 * this extent can fit in a new request
				 * Just add it to the accumulated list of
				 * extents and move on.
				 */
				start_idx = i;
				n_segs = 1;
				n_bytes = len;
				continue;
			}

			/*
			 * Even after starting a new request, this extent
			 * is too big. Split it until it fits.
			 */
			if ((r = split_extent(dfl, dfi, i, func, arg,
			    kmflag)) != 0) {
				goto done;
			}

			start_idx = i + 1;
			n_segs = 0;
			n_bytes = 0;
			continue;
		}

		if (dfi->dfi_max_ext > 0 && n_segs + 1 > dfi->dfi_max_ext) {
			/*
			 * This extent will put us over the limit on the number
			 * of extents the device can accept. Dispatch what
			 * we've accumulated so far.
			 */
			if ((r = process_range(dfl, start_idx, i - start_idx,
			    func, arg, kmflag)) != 0) {
				goto done;
			}

			start_idx = i;
			n_segs = 1;
			n_bytes = len;
			continue;
		}

		n_segs++;
		n_bytes += len;
	}

	/*
	 * If a copy wasn't required, and we haven't processed a subset of
	 * the extents already, we can just use the original request.
	 */
	if (!need_copy && start_idx == 0) {
		return (func(dfl, arg, kmflag));
	}

	r = process_range(dfl, start_idx, i - start_idx, func, arg, kmflag);

done:
	dfl_free(dfl);
	return (r);
}

/*
 * Adjust the start and length of each extent in dfl so that it conforms to
 * the requirements in dfi. It also verifies that no extent extends beyond
 * the end of the device (given by len_blk).
 *
 * Returns 0 on success, or an error value.
 */
static int
adjust_exts(dkioc_free_list_t *dfl, const dkioc_free_info_t *dfi,
    uint64_t max_off)
{
	dkioc_free_list_ext_t *exts = dfl->dfl_exts;
	/*
	 * These must be uint64_t to prevent the P2 macros from truncating
	 * the result.
	 */
	const uint64_t align = dfi->dfi_align;
	const uint64_t bsize = (uint64_t)1 << dfi->dfi_bshift;

	for (uint64_t i = 0; i < dfl->dfl_num_exts; i++, exts++) {
		/*
		 * Since there are no known requirements on the value of
		 * dfl_offset, it's possible (though odd) to have a scenario
		 * where dfl_offset == 1, and dfle_start == 511 (resulting
		 * in an actual start offset of 512). As such, we always
		 * apply the offset and find the resulting starting offset
		 * and length (in bytes) first, then apply any rounding
		 * and alignment.
		 */
		uint64_t start = exts->dfle_start + dfl->dfl_offset;
		uint64_t end = start + exts->dfle_length;

		/*
		 * Make sure after applying dfl->dfl_offset and any alignment
		 * adjustments that the results don't overflow.
		 */
		if (start < dfl->dfl_offset || start > (UINT64_MAX - bsize)) {
			return (SET_ERROR(EOVERFLOW));
		}

		if (end < start) {
			return (SET_ERROR(EOVERFLOW));
		}

		/*
		 * Make sure we don't extend past the end of the device
		 */
		if (end > max_off) {
			return (SET_ERROR(EINVAL));
		}

		start = P2ROUNDUP(start, align);
		end = P2ALIGN(end, bsize);

		/*
		 * Remove the offset so that when it's later applied again,
		 * the correct start value is obtained.
		 */
		exts->dfle_start = start - dfl->dfl_offset;

		/*
		 * If the original length was less than the block size
		 * of the device, we can end up with end < start. If that
		 * happens we just set the length to zero.
		 */
		exts->dfle_length = (end < start) ? 0 : end - start;
	}

	return (0);
}

/*
 * Take a subset of extents from dfl (starting at start_idx, with n entries)
 * and create a new dkioc_free_list_t, passing that to func.
 */
static int
process_range(dkioc_free_list_t *dfl, uint64_t start_idx, uint64_t n,
    dfl_iter_fn_t func, void *arg, int kmflag)
{
	dkioc_free_list_t *new_dfl = NULL;
	dkioc_free_list_ext_t *new_exts = NULL;
	dkioc_free_list_ext_t *exts = dfl->dfl_exts + start_idx;
	size_t actual_n = n;
	int r = 0;

	if (n == 0) {
		return (0);
	}

	/*
	 * Ignore any zero length extents. No known devices attach any
	 * semantic meaning to such extents, and are likely just a result of
	 * narrowing the range of the extent to fit the device alignment
	 * requirements. It is possible the original caller submitted a
	 * zero length extent, but we ignore those as well. Since we can't
	 * communicate partial results back to the caller anyway, it's
	 * unclear whether reporting that one of potentially many exents was
	 * too small (without being able to identify which one) to the caller
	 * of the DKIOCFREE request would be useful.
	 */
	for (uint64_t i = 0; i < n; i++) {
		if (exts[i].dfle_length == 0 && --actual_n == 0) {
			return (0);
		}
	}

	new_dfl = kmem_zalloc(DFL_SZ(actual_n), kmflag);
	if (new_dfl == NULL) {
		return (SET_ERROR(ENOMEM));
	}

	new_dfl->dfl_flags = dfl->dfl_flags;
	new_dfl->dfl_num_exts = actual_n;
	new_dfl->dfl_offset = dfl->dfl_offset;
	new_exts = new_dfl->dfl_exts;

	for (uint64_t i = 0; i < n; i++) {
		if (exts[i].dfle_length == 0) {
			continue;
		}

		*new_exts++ = exts[i];
	}

	return (func(new_dfl, arg, kmflag));
}

/*
 * If dfi_max_ext_bytes is set, use as the max segment length,
 * otherwise use dfi_max_bytes if set, otherwise fallback to UINT64_MAX
 */
#define	MAX_SEGLEN(dfi) \
	(((dfi)->dfi_max_ext_bytes > 0) ? (dfi)->dfi_max_ext_bytes :	\
	((dfi)->dfi_max_bytes > 0) ? (dfi)->dfi_max_bytes : UINT64_MAX)

/*
 * Split the extent at idx into multiple lists (calling func for each one).
 */
static int
split_extent(dkioc_free_list_t *dfl, const dkioc_free_info_t *dfi, uint64_t idx,
    dfl_iter_fn_t func, void *arg, int kmflag)
{
	ASSERT3U(idx, <, dfl->dfl_num_exts);

	const uint64_t		maxlen = MAX_SEGLEN(dfi);
	dkioc_free_list_ext_t	*ext = dfl->dfl_exts + idx;
	uint64_t		remain = ext->dfle_length;
	int			r;

	/*
	 * Break the extent into as many single requests as needed. While it
	 * would be possible in some circumstances to combine the final chunk
	 * of the extent (after splitting) with the remaining extents in the
	 * original request, it's not clear there's much benefit from the
	 * added complexity. Such behavior could be added in the future if
	 * it's determined to be worthwhile.
	 */
	while (remain > 0) {
		uint64_t start = dfl->dfl_offset + ext->dfle_start;
		uint64_t len = remain;

		/*
		 * If we know we have at least one more segment left after
		 * the current iteration of this loop, split it so that
		 * the next segment starts on an aligned boundary.
		 */
		if (len > maxlen) {
			uint64_t end = P2ALIGN(start + maxlen, dfi->dfi_align);
			len = end - start;
		}

		ext->dfle_length = len;

		if ((r = process_range(dfl, idx, 1, func, arg, kmflag)) != 0) {
			return (r);
		}

		ext->dfle_start += len;
		remain -= len;
	}

	return (0);
}
