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
 * FSCTL_SRV_OFFLOAD_READ
 * FSCTL_SRV_OFFLOAD_WRITE
 * (and related)
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smb/winioctl.h>

/*
 * Summary of how offload data transfer works:
 *
 * The client drives a server-side copy.  Outline:
 * 1: open src_file
 * 2: create dst_file and set its size
 * 3: while src_file not all copied {
 *        offload_read(src_file, &token);
 *        while token not all copied {
 *	      offload_write(dst_file, token);
 *        }
 *    }
 *
 * Each "offload read" request returns a "token" representing some
 * portion of the source file.  The server decides what kind of
 * token to use, and how much of the source file it should cover.
 * The length represented may be less then the client requested.
 * No data are copied during offload_read (just meta-data).
 *
 * Each "offload write" request copies some portion of the data
 * represented by the "token" into the output file.  The amount
 * of data copied may be less than the client requested, and the
 * client keeps sending offload write requests until they have
 * copied all the data represented by the current token.
 */

/* [MS-FSA] OFFLOAD_READ_FLAG_ALL_ZERO_BEYOND_CURRENT_RANGE */
#define	OFFLOAD_READ_FLAG_ALL_ZERO_BEYOND	1

/*
 * [MS-FSCC] 2.3.79 STORAGE_OFFLOAD_TOKEN
 * Note reserved: 0xFFFF0002 – 0xFFFFFFFF
 *
 * ...TOKEN_TYPE_ZERO_DATA:  A well-known Token that indicates ...
 * (offload write should just zero to the destination)
 * The payload (tok_other) is ignored with this type.
 */
#define	STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA	0xFFFF0001

/* Our vendor-specific token type: struct tok_native1 */
#define	STORAGE_OFFLOAD_TOKEN_TYPE_NATIVE1	0x10001

#define	TOKEN_TOTAL_SIZE	512
#define	TOKEN_MAX_PAYLOAD	504	/* 512 - 8 */

/* This mask is for sanity checking offsets etc. */
#define	OFFMASK		((uint64_t)DEV_BSIZE-1)

typedef struct smb_odx_token {
	uint32_t	tok_type;	/* big-endian on the wire */
	uint16_t	tok_reserved;	/* zero */
	uint16_t	tok_len;	/* big-endian on the wire */
	union {
		uint8_t u_tok_other[TOKEN_MAX_PAYLOAD];
		struct tok_native1 {
			smb2fid_t	tn1_fid;
			uint64_t	tn1_off;
			uint64_t	tn1_eof;
		} u_tok_native1;
	} tok_u;
} smb_odx_token_t;

typedef struct odx_write_args {
	uint32_t in_struct_size;
	uint32_t in_flags;
	uint64_t in_dstoff;
	uint64_t in_xlen;
	uint64_t in_xoff;
	uint32_t out_struct_size;
	uint32_t out_flags;
	uint64_t out_xlen;
	uint64_t wa_eof;
} odx_write_args_t;

static int smb_odx_get_token(mbuf_chain_t *, smb_odx_token_t *);
static int smb_odx_get_token_native1(mbuf_chain_t *, struct tok_native1 *);
static int smb_odx_put_token(mbuf_chain_t *, smb_odx_token_t *);
static int smb_odx_put_token_native1(mbuf_chain_t *, struct tok_native1 *);

static uint32_t smb2_fsctl_odx_write_zeros(smb_request_t *, odx_write_args_t *);
static uint32_t smb2_fsctl_odx_write_native1(smb_request_t *,
    odx_write_args_t *, smb_odx_token_t *);


/* We can disable this feature for testing etc. */
int smb2_odx_enable = 1;

/*
 * These two variables determine the intervals of offload_read and
 * offload_write calls (respectively) during an offload copy.
 *
 * For the offload read token we could offer a token representing
 * the whole file, but we'll have the client come back for a new
 * "token" after each 256M so we have a chance to look for "holes".
 * This lets us use the special "zero" token while we're in any
 * un-allocated parts of the file, so offload_write can use the
 * (more efficient) smb_fsop_freesp instead of copying.
 *
 * We limit the size of offload_write to 16M per request so we
 * don't end up taking so long with I/O that the client might
 * time out the request.  Keep: write_max <= read_max
 */
uint32_t smb2_odx_read_max = (1<<28); /* 256M */
uint32_t smb2_odx_write_max = (1<<24); /* 16M */

/*
 * This buffer size determines the I/O size for the copy during
 * offoad write, where it will read/write using this buffer.
 * Note: We kmem_alloc this, so don't make it HUGE.  It only
 * needs to be large enough to allow the copy to proceed with
 * reasonable efficiency.  1M is currently the largest possible
 * block size with ZFS, so that's what we'll use here.
 */
uint32_t smb2_odx_buf_size = (1<<20); /* 1M */


/*
 * FSCTL_OFFLOAD_READ
 * [MS-FSCC] 2.3.77
 *
 * Similar (in concept) to FSCTL_SRV_REQUEST_RESUME_KEY
 *
 * The returned data is an (opaque to the client) 512-byte "token"
 * that represents the specified range (offset, length) of the
 * source file.  The "token" we return here comes back to us in an
 * FSCTL_OFFLOAD_READ.  We must stash whatever we'll need then in
 * the token we return here.
 *
 * We want server-side copy to be able to copy "holes" efficiently,
 * but would rather avoid the complexity of encoding a list of all
 * allocated ranges into our returned token, so this compromise:
 *
 * When the current range is entirely within a "hole", we'll return
 * the special "zeros" token, and the offload write using that token
 * will use the simple and very efficient smb_fsop_freesp.  In this
 * scenario, we'll have a copy stride of smb2_odx_read_max (256M).
 *
 * When there's any data in the range to copy, we'll return our
 * "native" token, and the subsequent offload_write will walk the
 * allocated ranges copying and/or zeroing as needed.  In this
 * scenario, we'll have a copy stride of smb2_odx_write_max (16M).
 *
 * One additional optimization allowed by the protocol is that when
 * we discover that there's no more data after the current range,
 * we can set the flag ..._ALL_ZERO_BEYOND which tells that client
 * they can stop copying here if they like.
 */
uint32_t
smb2_fsctl_odx_read(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	smb_attr_t src_attr;
	smb_odx_token_t *tok = NULL;
	struct tok_native1 *tn1;
	smb_ofile_t *ofile = sr->fid_ofile;
	uint64_t src_size, src_rnd_size;
	off64_t data, hole;
	uint32_t in_struct_size;
	uint32_t in_flags;
	uint32_t in_ttl;
	uint64_t in_file_off;
	uint64_t in_copy_len;
	uint64_t out_xlen;
	uint32_t out_struct_size = TOKEN_TOTAL_SIZE + 16;
	uint32_t out_flags = 0;
	uint32_t status;
	uint32_t tok_type;
	int rc;

	if (smb2_odx_enable == 0)
		return (NT_STATUS_NOT_SUPPORTED);

	/*
	 * Make sure the (src) ofile granted access allows read.
	 * [MS-FSA] didn't mention this, so it's not clear where
	 * this should happen relative to other checks.  Usually
	 * access checks happen early.
	 */
	status = smb_ofile_access(ofile, ofile->f_cr, FILE_READ_DATA);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	/*
	 * Decode FSCTL_OFFLOAD_READ_INPUT struct,
	 * and do in/out size checks.
	 */
	rc = smb_mbc_decodef(
	    fsctl->in_mbc, "lll4.qq",
	    &in_struct_size,	/* l */
	    &in_flags,		/* l */
	    &in_ttl,		/* l */
	    /* reserved		4. */
	    &in_file_off,	/* q */
	    &in_copy_len);	/* q */
	if (rc != 0)
		return (NT_STATUS_BUFFER_TOO_SMALL);
	if (fsctl->MaxOutputResp < out_struct_size)
		return (NT_STATUS_BUFFER_TOO_SMALL);

	/*
	 * More arg checking per MS-FSA
	 */
	if ((in_file_off & OFFMASK) != 0 ||
	    (in_copy_len & OFFMASK) != 0)
		return (NT_STATUS_INVALID_PARAMETER);
	if (in_struct_size != 32)
		return (NT_STATUS_INVALID_PARAMETER);
	if (in_file_off > INT64_MAX ||
	    (in_file_off + in_copy_len) < in_file_off)
		return (NT_STATUS_INVALID_PARAMETER);

	/*
	 * [MS-FSA] (summarizing)
	 * If not data stream, or if sparse, encrypted, compressed...
	 * return STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED.
	 *
	 * We'll ignore most of those except to require:
	 * Plain file, not a stream.
	 */
	if (!smb_node_is_file(ofile->f_node))
		return (NT_STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED);
	if (SMB_IS_STREAM(ofile->f_node))
		return (NT_STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED);

	/*
	 * [MS-FSA] If Open.Stream.IsDeleted ...
	 * We don't really have this.
	 */

	/*
	 * If CopyLength == 0, "return immediately success".
	 */
	if (in_copy_len == 0) {
		out_xlen = 0;
		tok_type = STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA;
		goto done;
	}

	/*
	 * Check for lock conflicting with the read.
	 */
	status = smb_lock_range_access(sr, ofile->f_node,
	    in_file_off, in_copy_len, B_FALSE);
	if (status != 0)
		return (status); /* == FILE_LOCK_CONFLICT */

	/*
	 * Get the file size (rounded to a full block)
	 * and check the requested offset.
	 */
	bzero(&src_attr, sizeof (src_attr));
	src_attr.sa_mask = SMB_AT_SIZE;
	status = smb2_ofile_getattr(sr, ofile, &src_attr);
	if (status != NT_STATUS_SUCCESS)
		return (status);
	src_size = src_attr.sa_vattr.va_size;
	if (in_file_off >= src_size)
		return (NT_STATUS_END_OF_FILE);

	/*
	 * Limit the transfer length based on (rounded) EOF.
	 * Clients expect ranges of whole disk blocks.
	 * If we get a read in this rounded-up range,
	 * we'll supply zeros.
	 */
	src_rnd_size = (src_size + OFFMASK) & ~OFFMASK;
	out_xlen = in_copy_len;
	if ((in_file_off + out_xlen) > src_rnd_size)
		out_xlen = src_rnd_size - in_file_off;

	/*
	 * Also, have the client come back for a new token after every
	 * smb2_odx_read_max bytes, so we'll have opportunities to
	 * recognize "holes" in the source file.
	 */
	if (out_xlen > smb2_odx_read_max)
		out_xlen = smb2_odx_read_max;

	/*
	 * Ask the filesystem if there are any allocated regions in
	 * the requested range, and return either the "zeros" token
	 * or our "native" token as appropriate (details above).
	 */
	data = in_file_off;
	tok_type = STORAGE_OFFLOAD_TOKEN_TYPE_NATIVE1;
	rc = smb_fsop_next_alloc_range(ofile->f_cr, ofile->f_node,
	    &data, &hole);
	switch (rc) {
	case 0:
		/* Found some data.  Is it beyond this range? */
		if (data >= (in_file_off + out_xlen))
			tok_type = STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA;
		break;
	case ENXIO:
		/* No data here or following. */
		tok_type = STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA;
		out_flags |= OFFLOAD_READ_FLAG_ALL_ZERO_BEYOND;
		break;
	case ENOSYS:	/* FS does not support VOP_IOCTL... */
	case ENOTTY:	/* ... or _FIO_SEEK_DATA, _HOLE */
		break;
	default:
		cmn_err(CE_NOTE, "smb_fsop_next_alloc_range: rc=%d", rc);
		break;
	}

done:
	/* Already checked MaxOutputResp */
	(void) smb_mbc_encodef(
	    fsctl->out_mbc, "llq",
	    out_struct_size,	/* l */
	    out_flags,		/* l */
	    out_xlen);		/* q */

	/*
	 * Build the ODX token to return
	 */
	tok = smb_srm_zalloc(sr, sizeof (*tok));
	tok->tok_type = tok_type;
	tok->tok_reserved = 0;
	if (tok_type == STORAGE_OFFLOAD_TOKEN_TYPE_NATIVE1) {
		tok->tok_len = sizeof (*tn1);
		tn1 = &tok->tok_u.u_tok_native1;
		tn1->tn1_fid.persistent = ofile->f_persistid;
		tn1->tn1_fid.temporal = ofile->f_fid;
		tn1->tn1_off = in_file_off;
		tn1->tn1_eof = src_size;
	}

	rc = smb_odx_put_token(fsctl->out_mbc, tok);
	if (rc != 0)
		return (NT_STATUS_BUFFER_TOO_SMALL);

	return (NT_STATUS_SUCCESS);
}

/*
 * FSCTL_SRV_OFFLOAD_WRITE
 * [MS-FSCC] 2.3.80
 *
 * Similar (in concept) to FSCTL_COPYCHUNK_WRITE
 *
 * Copies from a source file identified by a "token"
 * (previously returned by FSCTL_OFFLOAD_READ)
 * to the file on which the ioctl is issued.
 */
uint32_t
smb2_fsctl_odx_write(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	smb_attr_t dst_attr;
	odx_write_args_t args;
	smb_odx_token_t *tok = NULL;
	smb_ofile_t *ofile = sr->fid_ofile;
	uint64_t dst_rnd_size;
	uint32_t status = NT_STATUS_INVALID_PARAMETER;
	int rc;

	bzero(&args, sizeof (args));
	args.out_struct_size = 16;

	if (smb2_odx_enable == 0)
		return (NT_STATUS_NOT_SUPPORTED);

	/*
	 * Make sure the (dst) ofile granted_access allows write.
	 * [MS-FSA] didn't mention this, so it's not clear where
	 * this should happen relative to other checks.  Usually
	 * access checks happen early.
	 */
	status = smb_ofile_access(ofile, ofile->f_cr, FILE_WRITE_DATA);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	/*
	 * Decode FSCTL_OFFLOAD_WRITE_INPUT struct,
	 * and do in/out size checks.
	 */
	rc = smb_mbc_decodef(
	    fsctl->in_mbc, "llqqq",
	    &args.in_struct_size,	/* l */
	    &args.in_flags,		/* l */
	    &args.in_dstoff,		/* q */
	    &args.in_xlen,		/* q */
	    &args.in_xoff);		/* q */
	if (rc != 0)
		return (NT_STATUS_BUFFER_TOO_SMALL);
	tok = smb_srm_zalloc(sr, sizeof (*tok));
	rc = smb_odx_get_token(fsctl->in_mbc, tok);
	if (rc != 0)
		return (NT_STATUS_BUFFER_TOO_SMALL);
	if (fsctl->MaxOutputResp < args.out_struct_size)
		return (NT_STATUS_BUFFER_TOO_SMALL);

	/*
	 * More arg checking per MS-FSA
	 */
	if ((args.in_dstoff & OFFMASK) != 0 ||
	    (args.in_xoff & OFFMASK) != 0 ||
	    (args.in_xlen & OFFMASK) != 0)
		return (NT_STATUS_INVALID_PARAMETER);
	if (args.in_struct_size != (TOKEN_TOTAL_SIZE + 32))
		return (NT_STATUS_INVALID_PARAMETER);
	if (args.in_dstoff > INT64_MAX ||
	    (args.in_dstoff + args.in_xlen) < args.in_dstoff)
		return (NT_STATUS_INVALID_PARAMETER);

	/*
	 * If CopyLength == 0, "return immediately success".
	 */
	if (args.in_xlen == 0) {
		status = 0;
		goto done;
	}

	/*
	 * [MS-FSA] (summarizing)
	 * If not data stream, or if sparse, encrypted, compressed...
	 * return STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED.
	 *
	 * We'll ignore most of those except to require:
	 * Plain file, not a stream.
	 */
	if (!smb_node_is_file(ofile->f_node))
		return (NT_STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED);
	if (SMB_IS_STREAM(ofile->f_node))
		return (NT_STATUS_OFFLOAD_WRITE_FILE_NOT_SUPPORTED);

	/*
	 * [MS-FSA] If Open.Stream.IsDeleted ...
	 * We don't really have such a thing.
	 * Also skip Volume.MaxFileSize check.
	 */

	/*
	 * Check for lock conflicting with the write.
	 */
	status = smb_lock_range_access(sr, ofile->f_node,
	    args.in_dstoff, args.in_xlen, B_TRUE);
	if (status != 0)
		return (status); /* == FILE_LOCK_CONFLICT */

	/*
	 * Need the file size
	 */
	bzero(&dst_attr, sizeof (dst_attr));
	dst_attr.sa_mask = SMB_AT_SIZE;
	status = smb2_ofile_getattr(sr, ofile, &dst_attr);
	if (status != NT_STATUS_SUCCESS)
		return (status);
	args.wa_eof = dst_attr.sa_vattr.va_size;
	dst_rnd_size = (args.wa_eof + OFFMASK) & ~OFFMASK;

	/*
	 * Destination offset vs. EOF
	 */
	if (args.in_dstoff >= args.wa_eof)
		return (NT_STATUS_END_OF_FILE);

	/*
	 * Destination offset+len vs. EOF
	 *
	 * The spec. is silent about copying when the file length is
	 * not block aligned, but clients appear to ask us to copy a
	 * range that's rounded up to a block size.  We'll limit the
	 * transfer size to the rounded up file size, but the actual
	 * copy will stop at EOF (args.wa_eof).
	 */
	if ((args.in_dstoff + args.in_xlen) > dst_rnd_size)
		args.in_xlen = dst_rnd_size - args.in_dstoff;

	/*
	 * Finally, run the I/O
	 */
	switch (tok->tok_type) {
	case STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA:
		status = smb2_fsctl_odx_write_zeros(sr, &args);
		break;
	case STORAGE_OFFLOAD_TOKEN_TYPE_NATIVE1:
		status = smb2_fsctl_odx_write_native1(sr, &args, tok);
		break;
	default:
		status = NT_STATUS_INVALID_TOKEN;
		break;
	}

done:
	/*
	 * Checked MaxOutputResp above, so we can ignore errors
	 * from mbc_encodef here.
	 */
	if (status == NT_STATUS_SUCCESS) {
		(void) smb_mbc_encodef(
		    fsctl->out_mbc, "llq",
		    args.out_struct_size,
		    args.out_flags,
		    args.out_xlen);
	}

	return (status);
}

/*
 * Handle FSCTL_OFFLOAD_WRITE with token type
 * STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA
 *
 * In this handler, the "token" represents a source of zeros.
 */
static uint32_t
smb2_fsctl_odx_write_zeros(smb_request_t *sr, odx_write_args_t *args)
{
	smb_ofile_t *dst_ofile = sr->fid_ofile;
	uint64_t xlen = args->in_xlen;
	uint32_t status = 0;
	int rc;

	ASSERT(args->in_xlen > 0);

	/*
	 * Limit the I/O size.  In here we're just doing freesp,
	 * which is assumed to require only meta-data I/O, so
	 * we'll allow up to smb2_odx_read_max (256M) per call.
	 * This is essentially just a double-check of the range
	 * we gave the client at the offload_read call, making
	 * sure they can't use a zero token for longer ranges
	 * than offload_read would allow.
	 */
	if (xlen > smb2_odx_read_max)
		xlen = smb2_odx_read_max;

	/*
	 * Also limit to the actual file size, which may be
	 * smaller than the (block-aligned) transfer size.
	 * Report the rounded up size to the caller at EOF.
	 */
	args->out_xlen = xlen;
	if ((args->in_dstoff + xlen) > args->wa_eof)
		xlen = args->wa_eof - args->in_dstoff;

	/*
	 * Arrange for zeros to appear in the range:
	 * in_dstoff, (in_dstoff + in_xlen)
	 *
	 * Just "free" the range and let it allocate as needed
	 * when someone later writes in this range.
	 */
	rc = smb_fsop_freesp(sr, dst_ofile->f_cr, dst_ofile,
	    args->in_dstoff, xlen);
	if (rc != 0) {
		status = smb_errno2status(rc);
		if (status == NT_STATUS_INVALID_PARAMETER ||
		    status == NT_STATUS_NOT_SUPPORTED)
			status = NT_STATUS_INVALID_DEVICE_REQUEST;
		args->out_xlen = 0;
	} else {
		status = 0;
	}

	return (status);
}

/*
 * Handle FSCTL_OFFLOAD_WRITE with token type
 * STORAGE_OFFLOAD_TOKEN_TYPE_NATIVE1
 */
static uint32_t
smb2_fsctl_odx_write_native1(smb_request_t *sr,
    odx_write_args_t *args, smb_odx_token_t *tok)
{
	struct tok_native1 *tn1;
	smb_ofile_t *dst_ofile = sr->fid_ofile;
	smb_ofile_t *src_ofile = NULL;
	void *buffer = NULL;
	size_t bufsize = smb2_odx_buf_size;
	uint64_t src_offset;
	uint32_t resid;
	uint32_t xlen;
	uint32_t status;

	/*
	 * Lookup the source ofile using the resume key,
	 * which smb2_fsctl_offload_read encoded as an
	 * smb2fid_t.  Similar to smb2sr_lookup_fid(),
	 * but different error code.
	 */
	tn1 = &tok->tok_u.u_tok_native1;
	src_ofile = smb_ofile_lookup_by_fid(sr,
	    (uint16_t)tn1->tn1_fid.temporal);
	if (src_ofile == NULL ||
	    src_ofile->f_persistid != tn1->tn1_fid.persistent) {
		status = NT_STATUS_INVALID_TOKEN;
		goto out;
	}

	/*
	 * Make sure src_ofile is open on a regular file, and
	 * granted access includes READ_DATA
	 */
	if (!smb_node_is_file(src_ofile->f_node)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto out;
	}
	status = smb_ofile_access(src_ofile, src_ofile->f_cr, FILE_READ_DATA);
	if (status != NT_STATUS_SUCCESS)
		goto out;

	/*
	 * Limit the I/O size.  In here we're actually copying,
	 * so limit to smb2_odx_write_max (16M) per call.
	 * Note that xlen is a 32-bit value here.
	 */
	if (args->in_xlen > smb2_odx_write_max)
		xlen = smb2_odx_write_max;
	else
		xlen = (uint32_t)args->in_xlen;

	/*
	 * Also limit to the actual file size, which may be
	 * smaller than the (block-aligned) transfer size.
	 * Report the rounded up size to the caller at EOF.
	 */
	args->out_xlen = xlen;
	if ((args->in_dstoff + xlen) > args->wa_eof)
		xlen = (uint32_t)(args->wa_eof - args->in_dstoff);

	/*
	 * Note: in_xoff is relative to the beginning of the "token"
	 * (a range of the source file tn1_off, tn1_eof).  Make sure
	 * in_xoff is within the range represented by this token.
	 */
	src_offset = tn1->tn1_off + args->in_xoff;
	if (src_offset >= tn1->tn1_eof ||
	    src_offset < tn1->tn1_off) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * Get a buffer used for copying, always
	 * smb2_odx_buf_size (1M)
	 *
	 * Rather than sleep for this relatively large allocation,
	 * allow the allocation to fail and return an error.
	 * The client should then fall back to normal copy.
	 */
	buffer = kmem_alloc(bufsize, KM_NOSLEEP | KM_NORMALPRI);
	if (buffer == NULL) {
		status = NT_STATUS_INSUFF_SERVER_RESOURCES;
		goto out;
	}

	/*
	 * Copy src to dst for xlen
	 */
	resid = xlen;
	status = smb2_sparse_copy(sr, src_ofile, dst_ofile,
	    src_offset, args->in_dstoff, &resid, buffer, bufsize);

	/*
	 * If the result was a partial copy, round down the
	 * reported transfer size to a block boundary.
	 */
	if (resid != 0) {
		xlen -= resid;
		xlen &= ~OFFMASK;
		args->out_xlen = xlen;
	}

	/*
	 * If we did any I/O, ignore the error that stopped us.
	 * We'll report this error during the next call.
	 */
	if (args->out_xlen > 0)
		status = 0;

out:
	if (src_ofile != NULL)
		smb_ofile_release(src_ofile);

	if (buffer != NULL)
		kmem_free(buffer, bufsize);

	return (status);
}

/*
 * Get an smb_odx_token_t from the (input) mbuf chain.
 * Consumes exactly TOKEN_TOTAL_SIZE bytes.
 */
static int
smb_odx_get_token(mbuf_chain_t *mbc, smb_odx_token_t *tok)
{
	mbuf_chain_t tok_mbc;
	int start_pos = mbc->chain_offset;
	int rc;

	if (MBC_ROOM_FOR(mbc, TOKEN_TOTAL_SIZE) == 0)
		return (-1);

	/*
	 * No big-endian support in smb_mbc_encodef, so swap
	 * the big-endian fields: tok_type (32-bits),
	 * (reserved is 16-bit zero, so no swap),
	 * and tok_len (16-bits)
	 */
	rc = smb_mbc_decodef(
	    mbc, "l..w",
	    &tok->tok_type,
	    /* tok_reserved */
	    &tok->tok_len);
	if (rc != 0)
		return (rc);
	tok->tok_type = BSWAP_32(tok->tok_type);
	tok->tok_len = BSWAP_16(tok->tok_len);

	if (tok->tok_len > TOKEN_MAX_PAYLOAD)
		return (-1);
	rc = MBC_SHADOW_CHAIN(&tok_mbc, mbc,
	    mbc->chain_offset, tok->tok_len);
	if (rc != 0)
		return (rc);

	switch (tok->tok_type) {
	case STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA:
		/* no payload */
		break;
	case STORAGE_OFFLOAD_TOKEN_TYPE_NATIVE1:
		rc = smb_odx_get_token_native1(&tok_mbc,
		    &tok->tok_u.u_tok_native1);
		break;
	default:
		/* caller will error out */
		break;
	}

	if (rc == 0) {
		/* Advance past what we shadowed. */
		mbc->chain_offset = start_pos + TOKEN_TOTAL_SIZE;
	}

	return (rc);
}

static int
smb_odx_get_token_native1(mbuf_chain_t *mbc, struct tok_native1 *tn1)
{
	int rc;

	rc = smb_mbc_decodef(
	    mbc, "qqqq",
	    &tn1->tn1_fid.persistent,
	    &tn1->tn1_fid.temporal,
	    &tn1->tn1_off,
	    &tn1->tn1_eof);

	return (rc);
}

/*
 * Put an smb_odx_token_t into the (output) mbuf chain,
 * padded to TOKEN_TOTAL_SIZE bytes.
 */
static int
smb_odx_put_token(mbuf_chain_t *mbc, smb_odx_token_t *tok)
{
	int rc, padlen;
	int start_pos = mbc->chain_offset;
	int end_pos = start_pos + TOKEN_TOTAL_SIZE;

	if (tok->tok_len > TOKEN_MAX_PAYLOAD)
		return (-1);

	/*
	 * No big-endian support in smb_mbc_encodef, so swap
	 * the big-endian fields: tok_type (32-bits),
	 * (reserved is 16-bit zero, so no swap),
	 * and tok_len (16-bits)
	 */
	rc = smb_mbc_encodef(
	    mbc, "lww",
	    BSWAP_32(tok->tok_type),
	    0, /* tok_reserved */
	    BSWAP_16(tok->tok_len));
	if (rc != 0)
		return (rc);

	switch (tok->tok_type) {
	case STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA:
		/* no payload */
		break;
	case STORAGE_OFFLOAD_TOKEN_TYPE_NATIVE1:
		rc = smb_odx_put_token_native1(mbc,
		    &tok->tok_u.u_tok_native1);
		break;
	default:
		ASSERT(0);
		return (-1);
	}

	/* Pad out to TOKEN_TOTAL_SIZE bytes. */
	if (mbc->chain_offset < end_pos) {
		padlen = end_pos - mbc->chain_offset;
		(void) smb_mbc_encodef(mbc, "#.", padlen);
	}
	ASSERT(mbc->chain_offset == end_pos);

	return (rc);
}

static int
smb_odx_put_token_native1(mbuf_chain_t *mbc, struct tok_native1 *tn1)
{
	int rc;

	rc = smb_mbc_encodef(
	    mbc, "qqqq",
	    tn1->tn1_fid.persistent,
	    tn1->tn1_fid.temporal,
	    tn1->tn1_off,
	    tn1->tn1_eof);

	return (rc);
}
