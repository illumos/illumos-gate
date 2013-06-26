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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_CREATE
 * [MS-SMB2] 2.2.13
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>

/*
 * Some flags used locally to keep track of which Create Context
 * names have been provided and/or requested.
 */
#define	CCTX_EA_BUFFER			1
#define	CCTX_SD_BUFFER			2
#define	CCTX_DH_REQUEST			4
#define	CCTX_DH_RECONNECT		8
#define	CCTX_ALLOCATION_SIZE		0x10
#define	CCTX_QUERY_MAX_ACCESS		0x20
#define	CCTX_TIMEWARP_TOKEN		0x40
#define	CCTX_QUERY_ON_DISK_ID		0x80
#define	CCTX_REQUEST_LEASE		0x100


typedef struct smb2_create_ctx_elem {
	uint32_t cce_len;
	mbuf_chain_t cce_mbc;
} smb2_create_ctx_elem_t;

typedef struct smb2_create_ctx {
	uint_t	cc_in_flags;	/* CCTX_... */
	uint_t	cc_out_flags;	/* CCTX_... */
	/* Elements we may see in the request. */
	smb2_create_ctx_elem_t cc_in_ext_attr;
	smb2_create_ctx_elem_t cc_in_sec_desc;
	smb2_create_ctx_elem_t cc_in_dh_request;
	smb2_create_ctx_elem_t cc_in_dh_reconnect;
	smb2_create_ctx_elem_t cc_in_alloc_size;
	smb2_create_ctx_elem_t cc_in_time_warp;
	smb2_create_ctx_elem_t cc_in_req_lease;
	/* Elements we my place in the response */
	smb2_create_ctx_elem_t cc_out_max_access;
	smb2_create_ctx_elem_t cc_out_file_id;
} smb2_create_ctx_t;

static uint32_t smb2_decode_create_ctx(
	mbuf_chain_t *,	smb2_create_ctx_t *);
static uint32_t smb2_encode_create_ctx(
	mbuf_chain_t *, smb2_create_ctx_t *);
static int smb2_encode_create_ctx_elem(
	mbuf_chain_t *, smb2_create_ctx_elem_t *, uint32_t);
static void smb2_free_create_ctx(smb2_create_ctx_t *);

smb_sdrc_t
smb2_create(smb_request_t *sr)
{
	smb_attr_t *attr;
	smb2_create_ctx_elem_t *cce;
	smb2_create_ctx_t cctx;
	mbuf_chain_t cc_mbc;
	smb_arg_open_t *op = &sr->arg.open;
	smb_ofile_t *of = NULL;
	uint16_t StructSize;
	uint8_t SecurityFlags;
	uint8_t OplockLevel;
	uint32_t ImpersonationLevel;
	uint64_t SmbCreateFlags;
	uint64_t Reserved4;
	uint16_t NameOffset;
	uint16_t NameLength;
	uint32_t CreateCtxOffset;
	uint32_t CreateCtxLength;
	smb2fid_t smb2fid;
	uint32_t status;
	int skip;
	int rc = 0;

	bzero(&cctx, sizeof (cctx));
	bzero(&cc_mbc, sizeof (cc_mbc));

	/*
	 * Paranoia.  This will set sr->fid_ofile, so
	 * if we already have one, release it now.
	 */
	if (sr->fid_ofile != NULL) {
		smb_ofile_request_complete(sr->fid_ofile);
		smb_ofile_release(sr->fid_ofile);
		sr->fid_ofile = NULL;
	}

	/*
	 * SMB2 Create request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wbblqqlllllwwll",
	    &StructSize,		/* w */
	    &SecurityFlags,		/* b */
	    &OplockLevel,		/* b */
	    &ImpersonationLevel,	/* l */
	    &SmbCreateFlags,		/* q */
	    &Reserved4,			/* q */
	    &op->desired_access,	/* l */
	    &op->dattr,			/* l */
	    &op->share_access,		/* l */
	    &op->create_disposition,	/* l */
	    &op->create_options,	/* l */
	    &NameOffset,		/* w */
	    &NameLength,		/* w */
	    &CreateCtxOffset,		/* l */
	    &CreateCtxLength);		/* l */
	if (rc != 0 || StructSize != 57)
		return (SDRC_ERROR);

	/*
	 * We're normally positioned at the path name now,
	 * but there could be some padding before it.
	 */
	skip = (NameOffset + sr->smb2_cmd_hdr) -
	    sr->smb_data.chain_offset;
	if (skip < 0) {
		status = NT_STATUS_OBJECT_PATH_INVALID;
		goto errout;
	}
	if (skip > 0)
		(void) smb_mbc_decodef(&sr->smb_data, "#.", skip);

	/*
	 * Get the path name
	 */
	if (NameLength >= SMB_MAXPATHLEN) {
		status = NT_STATUS_OBJECT_PATH_INVALID;
		goto errout;
	}
	if (NameLength == 0) {
		op->fqi.fq_path.pn_path = "\\";
	} else {
		rc = smb_mbc_decodef(&sr->smb_data, "%#U", sr,
		    NameLength, &op->fqi.fq_path.pn_path);
		if (rc) {
			status = NT_STATUS_OBJECT_PATH_INVALID;
			goto errout;
		}
	}
	op->fqi.fq_dnode = sr->tid_tree->t_snode;

	switch (OplockLevel) {
	case SMB2_OPLOCK_LEVEL_NONE:
		op->op_oplock_level = SMB_OPLOCK_NONE;
		break;
	case SMB2_OPLOCK_LEVEL_II:
		op->op_oplock_level = SMB_OPLOCK_LEVEL_II;
		break;
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
		op->op_oplock_level = SMB_OPLOCK_EXCLUSIVE;
		break;
	case SMB2_OPLOCK_LEVEL_BATCH:
		op->op_oplock_level = SMB_OPLOCK_BATCH;
		break;
	case SMB2_OPLOCK_LEVEL_LEASE:
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}
	op->op_oplock_levelII = B_TRUE;

	/*
	 * ImpersonationLevel (spec. says ignore)
	 * SmbCreateFlags (spec. says ignore)
	 */

	if ((op->create_options & FILE_DELETE_ON_CLOSE) &&
	    !(op->desired_access & DELETE)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}
	if (op->create_disposition > FILE_MAXIMUM_DISPOSITION) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto errout;
	}

	if (op->dattr & FILE_FLAG_WRITE_THROUGH)
		op->create_options |= FILE_WRITE_THROUGH;
	if (op->dattr & FILE_FLAG_DELETE_ON_CLOSE)
		op->create_options |= FILE_DELETE_ON_CLOSE;
	if (op->dattr & FILE_FLAG_BACKUP_SEMANTICS)
		op->create_options |= FILE_OPEN_FOR_BACKUP_INTENT;
	if (op->create_options & FILE_OPEN_FOR_BACKUP_INTENT)
		sr->user_cr = smb_user_getprivcred(sr->uid_user);

	/*
	 * If there is a "Create Context" payload, decode it.
	 * This may carry things like a security descriptor,
	 * extended attributes, etc. to be used in create.
	 *
	 * The create ctx buffer must start after the headers
	 * and file name, and must be 8-byte aligned.
	 */
	if (CreateCtxLength != 0) {
		if ((CreateCtxOffset & 7) != 0 ||
		    (CreateCtxOffset + sr->smb2_cmd_hdr) <
		    sr->smb_data.chain_offset) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}

		rc = MBC_SHADOW_CHAIN(&cc_mbc, &sr->smb_data,
		    sr->smb2_cmd_hdr + CreateCtxOffset, CreateCtxLength);
		if (rc) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}
		status = smb2_decode_create_ctx(&cc_mbc, &cctx);
		if (status)
			goto errout;

		if (cctx.cc_in_flags & CCTX_EA_BUFFER) {
			status = NT_STATUS_EAS_NOT_SUPPORTED;
			goto errout;
		}

		if (cctx.cc_in_flags & CCTX_SD_BUFFER) {
			smb_sd_t sd;
			cce = &cctx.cc_in_sec_desc;
			status = smb_decode_sd(
			    &cce->cce_mbc, &sd);
			if (status)
				goto errout;
			op->sd = kmem_alloc(sizeof (sd), KM_SLEEP);
			*op->sd = sd;
		}

		if (cctx.cc_in_flags & CCTX_ALLOCATION_SIZE) {
			cce = &cctx.cc_in_alloc_size;
			rc = smb_mbc_decodef(&cce->cce_mbc, "q", &op->dsize);
			if (rc) {
				status = NT_STATUS_INVALID_PARAMETER;
				goto errout;
			}
		}

		/*
		 * Support for opening "Previous Versions".
		 * [MS-SMB2] 2.2.13.2.7  Data is an NT time.
		 */
		if (cctx.cc_in_flags & CCTX_TIMEWARP_TOKEN) {
			uint64_t timewarp;
			cce = &cctx.cc_in_time_warp;
			status = smb_mbc_decodef(&cce->cce_mbc,
			    "q", &timewarp);
			if (status)
				goto errout;
			smb_time_nt_to_unix(timewarp, &op->timewarp);
			op->create_timewarp = B_TRUE;
		}
	}

	/*
	 * The real open call.   Note: this gets attributes into
	 * op->fqi.fq_fattr (SMB_AT_ALL).  We need those below.
	 */
	status = smb_common_open(sr);
	if (status != NT_STATUS_SUCCESS)
		goto errout;
	attr = &op->fqi.fq_fattr;

	/*
	 * Convert the negotiate Oplock level back into
	 * SMB2 encoding form.
	 */
	switch (op->op_oplock_level) {
	default:
	case SMB_OPLOCK_NONE:
		OplockLevel = SMB2_OPLOCK_LEVEL_NONE;
		break;
	case SMB_OPLOCK_LEVEL_II:
		OplockLevel = SMB2_OPLOCK_LEVEL_II;
		break;
	case SMB_OPLOCK_EXCLUSIVE:
		OplockLevel = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
		break;
	case SMB_OPLOCK_BATCH:
		OplockLevel = SMB2_OPLOCK_LEVEL_BATCH;
		break;
	}

	/*
	 * NB: after the above smb_common_open() success,
	 * we have a handle allocated (sr->fid_ofile).
	 * If we don't return success, we must close it.
	 *
	 * Using sr->smb_fid as the file handle for now,
	 * though it could later be something larger,
	 * (16 bytes) similar to an NFSv4 open handle.
	 */
	of = sr->fid_ofile;
	smb2fid.persistent = 0;
	smb2fid.temporal = sr->smb_fid;

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
	case STYPE_PRINTQ:
		if (op->create_options & FILE_DELETE_ON_CLOSE)
			smb_ofile_set_delete_on_close(of);
		break;
	}

	/*
	 * Build the Create Context to return; first the
	 * per-element parts, then the aggregated buffer.
	 *
	 * No response for these:
	 *	CCTX_EA_BUFFER
	 *	CCTX_SD_BUFFER
	 *	CCTX_ALLOCATION_SIZE
	 *	CCTX_TIMEWARP_TOKEN
	 *
	 * We don't handle these yet.
	 *	CCTX_DH_REQUEST
	 *	CCTX_DH_RECONNECT
	 *	CCTX_REQUEST_LEASE
	 */
	if (cctx.cc_in_flags & CCTX_QUERY_MAX_ACCESS) {
		cce = &cctx.cc_out_max_access;
		uint32_t MaxAccess = 0;
		if (of->f_node != NULL) {
			smb_fsop_eaccess(sr, of->f_cr, of->f_node, &MaxAccess);
		}
		MaxAccess |= of->f_granted_access;
		cce->cce_len = 8;
		cce->cce_mbc.max_bytes = 8;
		(void) smb_mbc_encodef(&cce->cce_mbc,
		    "ll", 0, MaxAccess);
		cctx.cc_out_flags |= CCTX_QUERY_MAX_ACCESS;
	}
	if ((cctx.cc_in_flags & CCTX_QUERY_ON_DISK_ID) != 0 &&
	    of->f_node != NULL) {
		cce = &cctx.cc_out_file_id;
		fsid_t fsid;

		fsid = SMB_NODE_FSID(of->f_node);

		cce->cce_len = 32;
		cce->cce_mbc.max_bytes = 32;
		(void) smb_mbc_encodef(
		    &cce->cce_mbc, "qll.15.",
		    op->fileid,		/* q */
		    fsid.val[0],	/* l */
		    fsid.val[1]);	/* l */
		/* reserved (16 bytes)  .15. */
		cctx.cc_out_flags |= CCTX_QUERY_ON_DISK_ID;
	}
	if (cctx.cc_out_flags) {
		sr->raw_data.max_bytes = smb2_max_trans;
		status = smb2_encode_create_ctx(&sr->raw_data, &cctx);
		if (status)
			goto errout;
	}

	/*
	 * SMB2 Create reply
	 */
	rc = smb_mbc_encodef(
	    &sr->reply,
	    "wb.lTTTTqqllqqll",
	    89,	/* StructSize */	/* w */
	    OplockLevel,		/* b */
	    op->action_taken,		/* l */
	    &attr->sa_crtime,		/* T */
	    &attr->sa_vattr.va_atime,	/* T */
	    &attr->sa_vattr.va_mtime,	/* T */
	    &attr->sa_vattr.va_ctime,	/* T */
	    attr->sa_allocsz,		/* q */
	    attr->sa_vattr.va_size,	/* q */
	    attr->sa_dosattr,		/* l */
	    0, /* reserved2 */		/* l */
	    smb2fid.persistent,		/* q */
	    smb2fid.temporal,		/* q */
	    0,  /* CreateCtxOffset	   l */
	    0); /* CreateCtxLength	   l */
	if (rc != 0) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto errout;
	}

	CreateCtxOffset = sr->reply.chain_offset - sr->smb2_reply_hdr;
	CreateCtxLength = MBC_LENGTH(&sr->raw_data);
	if (CreateCtxLength != 0) {
		/*
		 * Overwrite CreateCtxOffset, CreateCtxLength, pad
		 */
		sr->reply.chain_offset -= 8;
		rc = smb_mbc_encodef(
		    &sr->reply,
		    "ll#C",
		    CreateCtxOffset,	/* l */
		    CreateCtxLength,	/* l */
		    CreateCtxLength,	/* # */
		    &sr->raw_data);	/* C */
		if (rc != 0) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto errout;
		}
	} else {
		(void) smb_mbc_encodef(&sr->reply, ".");
	}
	return (SDRC_SUCCESS);

errout:
	if (of != NULL)
		smb_ofile_close(of, 0);
	if (cctx.cc_out_flags)
		smb2_free_create_ctx(&cctx);
	smb2sr_put_error(sr, status);
	return (SDRC_SUCCESS);
}

/*
 * Decode an SMB2 Create Context buffer into our internal form.
 * No policy decisions about what's supported here, just decode.
 */
static uint32_t
smb2_decode_create_ctx(mbuf_chain_t *in_mbc, smb2_create_ctx_t *cc)
{
	smb2_create_ctx_elem_t *cce;
	mbuf_chain_t name_mbc;
	union {
		uint32_t i;
		char ch[4];
	} cc_name;
	uint32_t status;
	int32_t next_off;
	uint32_t data_len;
	uint16_t data_off;
	uint16_t name_off;
	uint16_t name_len;
	int top_offset;
	int rc;

	status = NT_STATUS_INVALID_PARAMETER;
	for (;;) {
		cce = NULL;
		top_offset = in_mbc->chain_offset;
		rc = smb_mbc_decodef(
		    in_mbc,
		    "lww..wl",
		    &next_off,	/* l */
		    &name_off,	/* w */
		    &name_len,	/* w */
		    /* reserved	  .. */
		    &data_off,	/* w */
		    &data_len); /* l */
		if (rc)
			break;

		/*
		 * The Create Context "name", per [MS-SMB] 2.2.13.2
		 * They're defined as network-order integers for our
		 * switch below.  We don't have routines to decode
		 * native order, so read as char[4] then ntohl.
		 * NB: in SMB3, some of these are 8 bytes.
		 */
		if ((top_offset + name_off) < in_mbc->chain_offset)
			break;
		rc = MBC_SHADOW_CHAIN(&name_mbc, in_mbc,
		    top_offset + name_off, name_len);
		if (rc)
			break;
		rc = smb_mbc_decodef(&name_mbc, "4c", &cc_name);
		if (rc)
			break;
		cc_name.i = ntohl(cc_name.i);

		switch (cc_name.i) {
		case SMB2_CREATE_EA_BUFFER:		/* ("ExtA") */
			cc->cc_in_flags |= CCTX_EA_BUFFER;
			cce = &cc->cc_in_ext_attr;
			break;
		case SMB2_CREATE_SD_BUFFER:		/* ("SecD") */
			cc->cc_in_flags |= CCTX_SD_BUFFER;
			cce = &cc->cc_in_sec_desc;
			break;
		case SMB2_CREATE_DURABLE_HANDLE_REQUEST: /* ("DHnQ") */
			cc->cc_in_flags |= CCTX_DH_REQUEST;
			cce = &cc->cc_in_dh_request;
			break;
		case SMB2_CREATE_DURABLE_HANDLE_RECONNECT: /* ("DHnC") */
			cc->cc_in_flags |= CCTX_DH_RECONNECT;
			cce = &cc->cc_in_dh_reconnect;
			break;
		case SMB2_CREATE_ALLOCATION_SIZE:	/* ("AISi") */
			cc->cc_in_flags |= CCTX_ALLOCATION_SIZE;
			cce = &cc->cc_in_alloc_size;
			break;
		case SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQ: /* ("MxAc") */
			cc->cc_in_flags |= CCTX_QUERY_MAX_ACCESS;
			/* no input data for this */
			break;
		case SMB2_CREATE_TIMEWARP_TOKEN:	/* ("TWrp") */
			cc->cc_in_flags |= CCTX_TIMEWARP_TOKEN;
			cce = &cc->cc_in_time_warp;
			break;
		case SMB2_CREATE_QUERY_ON_DISK_ID:	/* ("QFid") */
			cc->cc_in_flags |= CCTX_QUERY_ON_DISK_ID;
			/* no input data for this */
			break;
		case SMB2_CREATE_REQUEST_LEASE:		/* ("RqLs") */
			cc->cc_in_flags |= CCTX_REQUEST_LEASE;
			cce = &cc->cc_in_req_lease;
			break;
		default:
			/*
			 * Unknown create context values are normal, and
			 * should be ignored.  However, in debug mode,
			 * let's log them so we know which ones we're
			 * not handling (and may want to add).
			 */
#ifdef	DEBUG
			cmn_err(CE_NOTE, "unknown create context ID 0x%x",
			    cc_name.i);
#endif
			cce = NULL;
			break;
		}

		if (cce != NULL && data_len != 0) {
			if ((data_off & 7) != 0)
				break;
			if ((top_offset + data_off) < in_mbc->chain_offset)
				break;
			rc = MBC_SHADOW_CHAIN(&cce->cce_mbc, in_mbc,
			    top_offset + data_off, data_len);
			if (rc)
				break;
			cce->cce_len = data_len;
		}

		if (next_off == 0) {
			/* Normal loop termination */
			status = 0;
			break;
		}

		if ((next_off & 7) != 0)
			break;
		if ((top_offset + next_off) < in_mbc->chain_offset)
			break;
		if ((top_offset + next_off) > in_mbc->max_bytes)
			break;
		in_mbc->chain_offset = top_offset + next_off;
	}

	return (status);
}

/*
 * Encode an SMB2 Create Context buffer from our internal form.
 */
/* ARGSUSED */
static uint32_t
smb2_encode_create_ctx(mbuf_chain_t *mbc, smb2_create_ctx_t *cc)
{
	smb2_create_ctx_elem_t *cce;
	int last_top = -1;
	int rc;

	if (cc->cc_out_flags & CCTX_QUERY_MAX_ACCESS) {
		cce = &cc->cc_out_max_access;
		last_top = mbc->chain_offset;
		rc = smb2_encode_create_ctx_elem(mbc, cce,
		    SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQ);
		if (rc)
			return (NT_STATUS_INTERNAL_ERROR);
		(void) smb_mbc_poke(mbc, last_top, "l",
		    mbc->chain_offset - last_top);
	}

	if (cc->cc_out_flags & CCTX_QUERY_ON_DISK_ID) {
		cce = &cc->cc_out_file_id;
		last_top = mbc->chain_offset;
		rc = smb2_encode_create_ctx_elem(mbc, cce,
		    SMB2_CREATE_QUERY_ON_DISK_ID);
		if (rc)
			return (NT_STATUS_INTERNAL_ERROR);
		(void) smb_mbc_poke(mbc, last_top, "l",
		    mbc->chain_offset - last_top);
	}

	if (last_top >= 0)
		(void) smb_mbc_poke(mbc, last_top, "l", 0);

	return (0);
}

static int
smb2_encode_create_ctx_elem(mbuf_chain_t *out_mbc,
	smb2_create_ctx_elem_t *cce, uint32_t id)
{
	union {
		uint32_t i;
		char ch[4];
	} cc_name;
	int rc;

	/* as above */
	cc_name.i = htonl(id);

	/*
	 * This is the header, per [MS-SMB2] 2.2.13.2
	 * Sorry about the fixed offsets.  We know we'll
	 * layout the data part as [name, payload] and
	 * name is a fixed length, so this easy.
	 * The final layout looks like this:
	 * 	a: this header (16 bytes)
	 *	b: the name (4 bytes, 4 pad)
	 *	c: the payload (variable)
	 *
	 * Note that "Next elem." is filled in later.
	 */
	rc = smb_mbc_encodef(
	    out_mbc, "lwwwwl",
	    0,		/* Next offset	l */
	    16,		/* NameOffset	w */
	    4,		/* NameLength	w */
	    0,		/* Reserved	w */
	    24,		/* DataOffset	w */
	    cce->cce_len);	/*	l */
	if (rc)
		return (rc);

	/*
	 * Now the "name" and payload.
	 */
	rc = smb_mbc_encodef(
	    out_mbc, "4c4.#C",
	    cc_name.ch,		/* 4c4. */
	    cce->cce_len,	/* # */
	    &cce->cce_mbc);	/* C */

	return (rc);
}

static void
smb2_free_create_ctx(smb2_create_ctx_t *cc)
{
	smb2_create_ctx_elem_t *cce;

	if (cc->cc_out_flags & CCTX_QUERY_MAX_ACCESS) {
		cce = &cc->cc_out_max_access;
		MBC_FLUSH(&cce->cce_mbc);
	}
	if (cc->cc_out_flags & CCTX_QUERY_ON_DISK_ID) {
		cce = &cc->cc_out_file_id;
		MBC_FLUSH(&cce->cce_mbc);
	}
}
