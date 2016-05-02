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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Support functions for smb2_ioctl/fsctl codes:
 * FSCTL_SET_SPARSE
 * FSCTL_SET_ZERO_DATA
 * FSCTL_QUERY_ALLOCATED_RANGES
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smb/winioctl.h>

/*
 * FSCTL_SET_SPARSE
 *
 * In args: one byte flag (optional: default TRUE)
 */
uint32_t
smb2_fsctl_set_sparse(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	smb_attr_t attr;
	smb_ofile_t *ofile = sr->fid_ofile;
	cred_t *kcr;
	uint32_t amask;
	uint32_t status;
	uint8_t flag;
	int rc;

	rc = smb_mbc_decodef(fsctl->in_mbc, "b", &flag);
	if (rc != 0)
		flag = 0xff;

	if (!smb_node_is_file(ofile->f_node))
		return (NT_STATUS_INVALID_PARAMETER);

	/*
	 * Allow if we have any of FILE_WRITE_ATTRIBUTES,
	 * FILE_WRITE_DATA, FILE_APPEND_DATA
	 */
	amask = FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_APPEND_DATA;
	if ((ofile->f_granted_access & amask) == 0)
		return (NT_STATUS_ACCESS_DENIED);

	/*
	 * Need the current DOS attributes
	 */
	bzero(&attr, sizeof (attr));
	attr.sa_mask = SMB_AT_DOSATTR;
	kcr = zone_kcred();
	status = smb_node_getattr(sr, ofile->f_node, kcr, ofile, &attr);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	if (flag != 0) {
		/* Set "sparse" */
		if (attr.sa_dosattr & FILE_ATTRIBUTE_SPARSE_FILE)
			return (0);
		attr.sa_dosattr |= FILE_ATTRIBUTE_SPARSE_FILE;
	} else {
		/* Clear "sparse" */
		if ((attr.sa_dosattr & FILE_ATTRIBUTE_SPARSE_FILE) == 0)
			return (0);
		attr.sa_dosattr &= ~FILE_ATTRIBUTE_SPARSE_FILE;
	}

	attr.sa_mask = SMB_AT_DOSATTR;
	status = smb_node_setattr(sr, ofile->f_node, kcr, ofile, &attr);
	return (status);
}

/*
 * FSCTL_SET_ZERO_DATA
 *
 * In args: uint64_t start_off, end_off
 */
uint32_t
smb2_fsctl_set_zero_data(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	smb_attr_t attr;
	smb_ofile_t *ofile = sr->fid_ofile;
	uint64_t start_off, end_off, zero_len;
	uint32_t status;
	int rc;

	rc = smb_mbc_decodef(fsctl->in_mbc, "qq",
	    &start_off, &end_off);
	if (rc != 0)
		return (NT_STATUS_BUFFER_TOO_SMALL);

	/*
	 * The given offsets are actually int64_t (signed).
	 */
	if (start_off > INT64_MAX ||
	    end_off > INT64_MAX ||
	    start_off > end_off)
		return (NT_STATUS_INVALID_PARAMETER);

	if (!smb_node_is_file(ofile->f_node))
		return (NT_STATUS_INVALID_PARAMETER);

	/*
	 * This operation is effectively a write (of zeros)
	 */
	status = smb_ofile_access(ofile, ofile->f_cr, FILE_WRITE_DATA);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	/*
	 * Need the file size
	 */
	bzero(&attr, sizeof (attr));
	attr.sa_mask = SMB_AT_SIZE;
	status = smb_node_getattr(sr, ofile->f_node, ofile->f_cr,
	    ofile, &attr);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	/*
	 * Ignore any zero-ing beyond EOF
	 */
	if (end_off > attr.sa_vattr.va_size)
		end_off = attr.sa_vattr.va_size;
	if (start_off >= end_off)
		return (0);
	zero_len = end_off - start_off;

	/*
	 * Check for lock conflicting with the write.
	 */
	status = smb_lock_range_access(sr, ofile->f_node,
	    start_off, zero_len, B_TRUE);
	if (status != 0)
		return (status); /* == FILE_LOCK_CONFLICT */

	rc = smb_fsop_freesp(sr, ofile->f_cr, ofile,
	    start_off, zero_len);
	if (rc != 0)
		status = smb_errno2status(rc);

	return (status);
}

/*
 * FSCTL_QUERY_ALLOCATED_RANGES
 *
 * Incoming args: uint64_t start_off, end_off
 */
struct alloc_range {
	off64_t off;
	off64_t len;
};
uint32_t
smb2_fsctl_query_alloc_ranges(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	smb_attr_t attr;
	cred_t *kcr;
	smb_ofile_t *ofile = sr->fid_ofile;
	struct alloc_range arg, res;
	off64_t cur_off, end_off;
	uint32_t status;
	int err, rc;

	/*
	 * Most ioctls return NT_STATUS_BUFFER_TOO_SMALL for
	 * short in/out buffers, but for this one, MS-FSA
	 * says short input returns invalid parameter.
	 */
	rc = smb_mbc_decodef(fsctl->in_mbc, "qq", &arg.off, &arg.len);
	if (rc != 0)
		return (NT_STATUS_INVALID_PARAMETER);

	/*
	 * The given offsets are actually int64_t (signed).
	 */
	end_off = arg.off + arg.len;
	if (arg.off > INT64_MAX || arg.len < 0 ||
	    end_off > INT64_MAX || end_off < arg.off)
		return (NT_STATUS_INVALID_PARAMETER);

	if (!smb_node_is_file(ofile->f_node))
		return (NT_STATUS_INVALID_PARAMETER);

	/*
	 * This operation is effectively a read
	 */
	status = smb_ofile_access(ofile, ofile->f_cr, FILE_READ_DATA);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	if (arg.len == 0) {
		/* MS-FSA says empty result for this. */
		return (0);
	}

	/*
	 * Need the file size and dosattr
	 */
	bzero(&attr, sizeof (attr));
	attr.sa_mask = SMB_AT_SIZE | SMB_AT_DOSATTR;
	kcr = zone_kcred();
	status = smb_node_getattr(sr, ofile->f_node, kcr, ofile, &attr);
	if (status != NT_STATUS_SUCCESS)
		return (status);
	if (end_off > attr.sa_vattr.va_size)
		end_off = attr.sa_vattr.va_size;

	/*
	 * Only sparse files should present un-allocated ranges.
	 * If non-sparse, MS-FSA says (just return one range).
	 */
	if ((attr.sa_dosattr & FILE_ATTRIBUTE_SPARSE_FILE) == 0) {
		if (arg.off < end_off) {
			res.off = arg.off;
			res.len = end_off - arg.off;
			rc = smb_mbc_encodef(fsctl->out_mbc, "qq",
			    res.off, res.len);
			if (rc != 0)
				return (NT_STATUS_BUFFER_TOO_SMALL);
		}
		return (0);
	}

	cur_off = arg.off;
	while (cur_off < end_off) {
		off64_t data, hole;

		data = cur_off;
		err = smb_fsop_next_alloc_range(kcr, ofile->f_node,
		    &data, &hole);
		if (err != 0)
			break;

		/* sanity check data (ensure progress) */
		if (data < cur_off) {
			ASSERT(0);
			data = cur_off;
		}

		/* Normal termination */
		if (data >= end_off)
			break;

		/* sanity check hole (ensure progress) */
		if (hole <= data)
			hole = end_off;

		/* Trim this range as needed. */
		if (hole > end_off)
			hole = end_off;

		res.off = data;
		res.len = hole - data;

		if (res.len > 0) {
			rc = smb_mbc_encodef(fsctl->out_mbc, "qq",
			    res.off, res.len);
			if (rc != 0)
				return (NT_STATUS_BUFFER_TOO_SMALL);
		}

		cur_off = hole;
	}

	return (0);
}

/*
 * Copy a segment of a file, preserving sparseness.
 * Uses a caller-provided buffer for read/write.
 * Caller should already have checked for locks.
 *
 * On entry, *residp is the length to copy.
 * On return, it's the "resid" (amount not copied)
 *
 * If this gets an error from any I/O, return it, even if some data
 * have already been copied.  The caller should normally ignore an
 * error when some data have been copied.
 */
uint32_t
smb2_sparse_copy(
	smb_request_t *sr,
	smb_ofile_t *src_ofile, smb_ofile_t *dst_ofile,
	off64_t src_off, off64_t dst_off, uint32_t *residp,
	void *buffer, size_t bufsize)
{
	iovec_t iov;
	uio_t uio;
	off64_t data, hole;
	uint32_t xfer;
	uint32_t status = 0;
	int rc;

	while (*residp > 0) {

		data = src_off;
		rc = smb_fsop_next_alloc_range(src_ofile->f_cr,
		    src_ofile->f_node, &data, &hole);
		switch (rc) {
		case 0:
			/* Found data, hole */
			break;
		case ENXIO:
			/* No data after here (will skip below). */
			data = hole = (src_off + *residp);
			break;
		default:
			cmn_err(CE_NOTE,
			    "smb_fsop_next_alloc_range: rc=%d", rc);
			/* FALLTHROUGH */
		case ENOSYS:	/* FS does not support VOP_IOCTL... */
		case ENOTTY:	/* ... or _FIO_SEEK_DATA, _HOLE */
			data = src_off;
			hole = src_off + *residp;
			break;
		}

		/*
		 * Don't try to go past (src_off + *residp)
		 */
		if (hole > (src_off + *residp))
			hole = src_off + *residp;
		if (data > hole)
			data = hole;

		/*
		 * If there's a gap (src_off .. data)
		 * skip in src_ofile, zero in dst_ofile
		 */
		if (src_off < data) {
			off64_t skip = data - src_off;
			rc = smb_fsop_freesp(sr, dst_ofile->f_cr,
			    dst_ofile, dst_off, skip);
			if (rc == 0) {
				src_off += skip;
				dst_off += skip;
				*residp -= (uint32_t)skip;
			} else {
				/* Fall back to regular copy */
				data = src_off;
			}
		}
		ASSERT(src_off == data);

		/*
		 * Copy this segment: src_off .. hole
		 */
		while (src_off < hole) {
			ssize_t tsize = hole - src_off;
			if (tsize > bufsize)
				tsize = bufsize;

			/*
			 * Read src_ofile into buffer
			 */
			iov.iov_base = buffer;
			iov.iov_len  = tsize;
			bzero(&uio, sizeof (uio));
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_resid = tsize;
			uio.uio_loffset = src_off;
			uio.uio_segflg = UIO_SYSSPACE;
			uio.uio_extflg = UIO_COPY_DEFAULT;

			rc = smb_fsop_read(sr, src_ofile->f_cr,
			    src_ofile->f_node, src_ofile, &uio);
			if (rc != 0) {
				status = smb_errno2status(rc);
				return (status);
			}
			/* Note: Could be partial read. */
			tsize -= uio.uio_resid;
			ASSERT(tsize > 0);

			/*
			 * Write buffer to dst_ofile
			 */
			iov.iov_base = buffer;
			iov.iov_len  = tsize;
			bzero(&uio, sizeof (uio));
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_resid = tsize;
			uio.uio_loffset = dst_off;
			uio.uio_segflg = UIO_SYSSPACE;
			uio.uio_extflg = UIO_COPY_DEFAULT;

			rc = smb_fsop_write(sr, dst_ofile->f_cr,
			    dst_ofile->f_node, dst_ofile, &uio, &xfer, 0);
			if (rc != 0) {
				status = smb_errno2status(rc);
				return (status);
			}
			ASSERT(xfer <= tsize);

			src_off += xfer;
			dst_off += xfer;
			*residp -= xfer;
		}
		ASSERT(src_off == hole);
	}

	return (status);
}
