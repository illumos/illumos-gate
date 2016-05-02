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
 * FSCTL_SRV_COPYCHUNK
 * FSCTL_SRV_COPYCHUNK_WRITE
 * (and related)
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smb/winioctl.h>

typedef struct chunk {
	uint64_t src_off;
	uint64_t dst_off;
	uint32_t length;
	uint32_t _reserved;
} chunk_t;

struct copychunk_resp {
	uint32_t ChunksWritten;
	uint32_t ChunkBytesWritten;
	uint32_t TotalBytesWritten;
};

typedef struct copychunk_args {
	smb_attr_t src_attr;
	void *buffer;
	size_t bufsize;
	uint32_t ccnt;
	chunk_t cvec[1]; /* actually longer */
} copychunk_args_t;

uint32_t smb2_copychunk_max_cnt = 256;
uint32_t smb2_copychunk_max_seg = (1<<20); /* 1M, == smb2_max_rwsize */
uint32_t smb2_copychunk_max_total = (1<<24); /* 16M */

static uint32_t smb2_fsctl_copychunk_decode(smb_request_t *, mbuf_chain_t *);
static uint32_t smb2_fsctl_copychunk_array(smb_request_t *, smb_ofile_t *,
	struct copychunk_resp *);
static uint32_t smb2_fsctl_copychunk_aapl(smb_request_t *, smb_ofile_t *,
	struct copychunk_resp *);
static uint32_t smb2_fsctl_copychunk_1(smb_request_t *, smb_ofile_t *,
	struct chunk *);
static int smb2_fsctl_copychunk_meta(smb_request_t *, smb_ofile_t *);

/*
 * FSCTL_SRV_COPYCHUNK
 * FSCTL_SRV_COPYCHUNK_WRITE
 *
 * Copies from a source file identified by a "resume key"
 * (previously returned by FSCTL_SRV_REQUEST_RESUME_KEY)
 * to the file on which the ioctl is issues.
 *
 * The fsctl appears to _always_ respond with a data payload
 * (struct copychunk_resp), even on fatal errors.  Note that
 * smb2_ioctl also has special handling to allow that.
 */
uint32_t
smb2_fsctl_copychunk(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	struct copychunk_resp ccr;
	smb_ofile_t *dst_of = sr->fid_ofile;
	smb_ofile_t *src_of = NULL;
	copychunk_args_t *args = NULL;
	smb2fid_t smb2fid;
	uint32_t status = NT_STATUS_INVALID_PARAMETER;
	uint32_t desired_access; /* for dest */
	uint32_t chunk_cnt;
	int rc;
	boolean_t aapl_copyfile = B_FALSE;

	bzero(&ccr, sizeof (ccr));
	if (fsctl->MaxOutputResp < sizeof (ccr)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * Make sure dst_of is open on a regular file, and
	 * granted access is sufficient for this operation.
	 * FSCTL_SRV_COPYCHUNK requires READ+WRITE
	 * FSCTL_SRV_COPYCHUNK_WRITE just WRITE
	 */
	if (!smb_node_is_file(dst_of->f_node)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}
	desired_access = FILE_WRITE_DATA;
	if (fsctl->CtlCode == FSCTL_SRV_COPYCHUNK)
		desired_access |= FILE_READ_DATA;
	status = smb_ofile_access(dst_of, dst_of->f_cr, desired_access);
	if (status != NT_STATUS_SUCCESS)
		goto out;

	/*
	 * Decode the resume key (src file ID) and length of the
	 * "chunks" array.  Note the resume key is 24 bytes of
	 * opaque data from FSCTL_SRV_REQUEST_RESUME_KEY, but
	 * here know it's an smb2fid plus 8 bytes of padding.
	 */
	rc = smb_mbc_decodef(
	    fsctl->in_mbc, "qq8.l4.",
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal,		/* q */
	    /* pad			  8. */
	    &chunk_cnt);		/* l */
	/*			reserved  4. */
	if (rc != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * Lookup the source ofile using the resume key,
	 * which smb2_fsctl_get_resume_key encoded as an
	 * smb2fid_t.  Similar to smb2sr_lookup_fid(),
	 * but different error code.
	 */
	src_of = smb_ofile_lookup_by_fid(sr, (uint16_t)smb2fid.temporal);
	if (src_of == NULL ||
	    src_of->f_persistid != smb2fid.persistent) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}

	/*
	 * Make sure src_of is open on a regular file, and
	 * granted access includes READ_DATA
	 */
	if (!smb_node_is_file(src_of->f_node)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}
	status = smb_ofile_access(src_of, src_of->f_cr, FILE_READ_DATA);
	if (status != NT_STATUS_SUCCESS)
		goto out;

	/*
	 * Before decoding the chunks array, check the size.  Note:
	 * When we offer the AAPL extensions, MacOS clients assume
	 * they can use chunk_cnt==0 to mean "copy the whole file".
	 */
	if (chunk_cnt == 0) {
		if ((sr->session->s_flags & SMB_SSN_AAPL_CCEXT) != 0) {
			aapl_copyfile = B_TRUE;
		} else {
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
	}
	if (chunk_cnt > smb2_copychunk_max_cnt) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * Get some memory for the array of chunks and decode it.
	 * Also checks the per-chunk and total size limits.
	 * Note that chunk_cnt may be zero here (MacOS).
	 */
	args = smb_srm_zalloc(sr, sizeof (*args) +
	    (chunk_cnt * sizeof (args->cvec)));
	args->ccnt = chunk_cnt;
	sr->arg.other = args;
	if (chunk_cnt > 0) {
		status = smb2_fsctl_copychunk_decode(sr, fsctl->in_mbc);
		if (status != 0)
			goto out;
	}

	/*
	 * Normally need just the source file size, etc.  If doing
	 * Apple server-side copy, we want all the attributes.
	 */
	if (aapl_copyfile)
		args->src_attr.sa_mask = SMB_AT_ALL;
	else
		args->src_attr.sa_mask = SMB_AT_STANDARD;
	status = smb2_ofile_getattr(sr, src_of, &args->src_attr);
	if (status != 0)
		goto out;

	/*
	 * Get a buffer used for copying, always
	 * smb2_copychunk_max_seg (1M)
	 *
	 * Rather than sleep for this relatively large allocation,
	 * allow the allocation to fail and return an error.
	 * The client should then fall back to normal copy.
	 */
	args->bufsize = smb2_copychunk_max_seg;
	args->buffer = kmem_alloc(args->bufsize, KM_NOSLEEP | KM_NORMALPRI);
	if (args->buffer == NULL) {
		status = NT_STATUS_INSUFF_SERVER_RESOURCES;
		goto out;
	}

	/*
	 * Finally, do the I/O
	 */
	if (aapl_copyfile) {
		status = smb2_fsctl_copychunk_aapl(sr, src_of, &ccr);
	} else {
		status = smb2_fsctl_copychunk_array(sr, src_of, &ccr);
	}

out:
	if (args != NULL) {
		if (args->buffer != NULL) {
			kmem_free(args->buffer, args->bufsize);
		}
	}

	if (src_of != NULL)
		smb_ofile_release(src_of);

	if (status == NT_STATUS_INVALID_PARAMETER) {
		/*
		 * Tell the client our max chunk cnt, size, etc.
		 */
		ccr.ChunksWritten	= smb2_copychunk_max_cnt;
		ccr.ChunkBytesWritten	= smb2_copychunk_max_seg;
		ccr.TotalBytesWritten	= smb2_copychunk_max_total;
	}

	/* Checked MaxOutputResp above, so ignore errors here */
	(void) smb_mbc_encodef(
	    fsctl->out_mbc, "lll",
	    ccr.ChunksWritten,
	    ccr.ChunkBytesWritten,
	    ccr.TotalBytesWritten);

	sr->arg.other = NULL;
	/* smb_srm_fini will free args */

	return (status);
}

/*
 * Decode the list of chunks and check each.
 */
static uint32_t
smb2_fsctl_copychunk_decode(smb_request_t *sr, mbuf_chain_t *mbc)
{
	copychunk_args_t *args = sr->arg.other;
	chunk_t *cc;
	uint32_t status = NT_STATUS_INVALID_PARAMETER;
	uint32_t total_len = 0;
	int i, rc;

	for (i = 0; i < args->ccnt; i++) {
		cc = &args->cvec[i];
		rc = smb_mbc_decodef(
		    mbc, "qqll",
		    &cc->src_off,	/* q */
		    &cc->dst_off,	/* q */
		    &cc->length,	/* l */
		    &cc->_reserved);	/* l */
		if (rc != 0 || cc->length == 0 ||
		    cc->length > smb2_copychunk_max_seg)
			goto out;
		total_len += cc->length;
	}
	if (total_len > smb2_copychunk_max_total)
		goto out;
	status = 0;

out:
	return (status);
}

/*
 * Run the actual I/O described by the copychunks array.
 * (normal, non-apple case)
 */
static uint32_t
smb2_fsctl_copychunk_array(smb_request_t *sr, smb_ofile_t *src_of,
	struct copychunk_resp *ccr)
{
	copychunk_args_t *args = sr->arg.other;
	chunk_t *cc;
	uint64_t src_size = args->src_attr.sa_vattr.va_size;
	uint32_t save_len;
	uint32_t copied;
	uint32_t status = 0;
	int i;

	for (i = 0; i < args->ccnt; i++) {
		cc = &args->cvec[i];

		/* Chunk must be entirely within file bounds. */
		if (cc->src_off > src_size ||
		    (cc->src_off + cc->length) < cc->src_off ||
		    (cc->src_off + cc->length) > src_size) {
			status = NT_STATUS_INVALID_VIEW_SIZE;
			goto out;
		}

		save_len = cc->length;
		status = smb2_fsctl_copychunk_1(sr, src_of, cc);
		if (status != 0) {
			/* no part of this chunk written */
			break;
		}
		/*
		 * All or part of the chunk written.
		 * cc->length is now the resid count.
		 */
		copied = save_len - cc->length;
		ccr->TotalBytesWritten += copied;
		if (cc->length != 0) {
			/* Did not write the whole chunk */
			ccr->ChunkBytesWritten = copied;
			break;
		}
		/* Whole chunk moved. */
		ccr->ChunksWritten++;
	}
	if (ccr->ChunksWritten > 0)
		status = NT_STATUS_SUCCESS;

out:
	return (status);
}

/*
 * Helper for smb2_fsctl_copychunk, where MacOS uses chunk_cnt==0
 * to mean "copy the whole file".  This interface does not have any
 * way to report a partial copy (client ignores copychunk_resp) so
 * if that happens we just report an error.
 *
 * This extension makes no provision for the server to impose any
 * bound on the amount of data moved by one SMB copychunk request.
 * We could impose a total size, but it's hard to know what size
 * would be an appropriate limit because performance of various
 * storage subsystems can vary quite a bit.  The best we can do is
 * limit the time we spend in this copy, and allow cancellation.
 */
int smb2_fsctl_copychunk_aapl_timeout = 10;	/* sec */
static uint32_t
smb2_fsctl_copychunk_aapl(smb_request_t *sr, smb_ofile_t *src_of,
	struct copychunk_resp *ccr)
{
	copychunk_args_t *args = sr->arg.other;
	chunk_t *cc = args->cvec; /* always at least one element */
	uint64_t src_size = args->src_attr.sa_vattr.va_size;
	uint64_t off;
	uint32_t xfer;
	uint32_t status = 0;
	hrtime_t end_time = sr->sr_time_active +
	    (smb2_fsctl_copychunk_aapl_timeout * NANOSEC);

	off = 0;
	while (off < src_size) {
		/*
		 * Check that (a) the request has not been cancelled,
		 * and (b) we've not run past the timeout.
		 */
		if (sr->sr_state != SMB_REQ_STATE_ACTIVE)
			return (NT_STATUS_CANCELLED);
		if (gethrtime() > end_time)
			return (NT_STATUS_IO_TIMEOUT);

		xfer = smb2_copychunk_max_seg;
		if (off + xfer > src_size)
			xfer = (uint32_t)(src_size - off);
		cc->src_off = off;
		cc->dst_off = off;
		cc->length = xfer;
		status = smb2_fsctl_copychunk_1(sr, src_of, cc);
		if (status != 0)
			break;
		if (cc->length != 0) {
			status = NT_STATUS_PARTIAL_COPY;
			break;
		}
		/*
		 * Whole chunk moved.  It appears that MacOS clients
		 * ignore the response here, but let's put something
		 * meaningful in it anyway, so one can see how far
		 * the copy went by looking at a network trace.
		 */
		ccr->TotalBytesWritten += xfer;
		ccr->ChunksWritten++;
		off += xfer;
	}

	/*
	 * MacOS servers also copy meta-data from the old to new file.
	 * We need to do this because Finder does not set the meta-data
	 * when copying a file with this interface.  If we fail to copy
	 * the meta-data, just log.  We'd rather not fail the entire
	 * copy job if this fails.
	 */
	if (status == 0) {
		int rc = smb2_fsctl_copychunk_meta(sr, src_of);
		if (rc != 0) {
			cmn_err(CE_NOTE, "smb2 copychunk meta, rc=%d", rc);
		}
	}

	return (status);
}

/*
 * Helper for Apple copychunk, to copy meta-data
 */
static int
smb2_fsctl_copychunk_meta(smb_request_t *sr, smb_ofile_t *src_of)
{
	smb_fssd_t fs_sd;
	copychunk_args_t *args = sr->arg.other;
	smb_ofile_t *dst_of = sr->fid_ofile;
	uint32_t sd_flags = 0;
	uint32_t secinfo = SMB_DACL_SECINFO;
	int error;

	/*
	 * Copy attributes.  We obtained SMB_AT_ALL above.
	 * Now correct the mask for what's settable.
	 */
	args->src_attr.sa_mask = SMB_AT_MODE | SMB_AT_SIZE |
	    SMB_AT_ATIME | SMB_AT_MTIME | SMB_AT_CTIME |
	    SMB_AT_DOSATTR | SMB_AT_ALLOCSZ;
	error = smb_node_setattr(sr, dst_of->f_node, sr->user_cr,
	    dst_of, &args->src_attr);
	if (error != 0)
		return (error);

	/*
	 * Copy the ACL.  Unfortunately, the ofiles used by the Mac
	 * here don't generally have WRITE_DAC access (sigh) so we
	 * have to bypass ofile access checks for this operation.
	 * The file-system level still does its access checking.
	 */
	smb_fssd_init(&fs_sd, secinfo, sd_flags);
	sr->fid_ofile = NULL;
	error = smb_fsop_sdread(sr, sr->user_cr, src_of->f_node, &fs_sd);
	if (error == 0) {
		error = smb_fsop_sdwrite(sr, sr->user_cr, dst_of->f_node,
		    &fs_sd, 1);
	}
	sr->fid_ofile = dst_of;
	smb_fssd_term(&fs_sd);

	return (error);
}

/*
 * Copy one chunk from src_of to sr->fid_ofile,
 * with offsets and length from chunk *cc
 */
static uint32_t
smb2_fsctl_copychunk_1(smb_request_t *sr, smb_ofile_t *src_ofile,
    struct chunk *cc)
{
	copychunk_args_t *args = sr->arg.other;
	smb_ofile_t *dst_ofile = sr->fid_ofile;
	uint32_t status;

	if (cc->length > args->bufsize)
		return (NT_STATUS_INTERNAL_ERROR);

	/*
	 * Check for lock conflicting with the read.
	 */
	status = smb_lock_range_access(sr, src_ofile->f_node,
	    cc->src_off, cc->length, B_FALSE);
	if (status != 0)
		return (status);

	/*
	 * Check for lock conflicting with the write.
	 */
	status = smb_lock_range_access(sr, dst_ofile->f_node,
	    cc->dst_off, cc->length, B_TRUE);
	if (status != 0)
		return (status);

	/*
	 * Copy src to dst for cc->length
	 */
	status = smb2_sparse_copy(sr, src_ofile, dst_ofile,
	    cc->src_off, cc->dst_off, &cc->length,
	    args->buffer, args->bufsize);

	return (status);
}
