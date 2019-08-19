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
 * Dispatch function for SMB2_CREATE
 * [MS-SMB2] 2.2.13
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>

#define	DH_PERSISTENT	SMB2_DHANDLE_FLAG_PERSISTENT

/*
 * Compile-time check that the SMB2_LEASE_... definitions
 * match the (internal) equivalents from ntifs.h
 */
#if SMB2_LEASE_NONE != OPLOCK_LEVEL_NONE
#error "SMB2_LEASE_NONE"
#endif
#if SMB2_LEASE_READ_CACHING != OPLOCK_LEVEL_CACHE_READ
#error "SMB2_LEASE_READ_CACHING"
#endif
#if SMB2_LEASE_HANDLE_CACHING != OPLOCK_LEVEL_CACHE_HANDLE
#error "SMB2_LEASE_HANDLE_CACHING"
#endif
#if SMB2_LEASE_WRITE_CACHING != OPLOCK_LEVEL_CACHE_WRITE
#error "SMB2_LEASE_WRITE_CACHING"
#endif

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
#define	CCTX_AAPL_EXT			0x200
#define	CCTX_DH_REQUEST_V2		0x400
#define	CCTX_DH_RECONNECT_V2		0x800

typedef struct smb2_create_ctx_elem {
	uint32_t cce_len;
	mbuf_chain_t cce_mbc;
} smb2_create_ctx_elem_t;

typedef struct smb2_create_ctx {
	mbuf_chain_t cc_in_mbc;
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
	smb2_create_ctx_elem_t cc_in_aapl;
	smb2_create_ctx_elem_t cc_in_dh_request_v2;
	smb2_create_ctx_elem_t cc_in_dh_reconnect_v2;
	/* Elements we my place in the response */
	smb2_create_ctx_elem_t cc_out_max_access;
	smb2_create_ctx_elem_t cc_out_file_id;
	smb2_create_ctx_elem_t cc_out_aapl;
	smb2_create_ctx_elem_t cc_out_req_lease;
	smb2_create_ctx_elem_t cc_out_dh_request;
	smb2_create_ctx_elem_t cc_out_dh_request_v2;
} smb2_create_ctx_t;

static uint32_t smb2_decode_create_ctx(
	smb_request_t *, smb2_create_ctx_t *);
static uint32_t smb2_encode_create_ctx(
	smb_request_t *, smb2_create_ctx_t *);
static int smb2_encode_create_ctx_elem(
	mbuf_chain_t *, smb2_create_ctx_elem_t *, uint32_t);
static void smb2_free_create_ctx(smb2_create_ctx_t *);

int smb2_enable_dh = 1;

smb_sdrc_t
smb2_create(smb_request_t *sr)
{
	smb_attr_t *attr;
	smb2_create_ctx_elem_t *cce;
	smb2_create_ctx_t cctx;
	smb_arg_open_t *op = &sr->arg.open;
	smb_ofile_t *of = NULL;
	uint16_t StructSize;
	uint8_t SecurityFlags;
	uint32_t ImpersonationLevel;
	uint64_t SmbCreateFlags;
	uint64_t Reserved4;
	uint16_t NameOffset;
	uint16_t NameLength;
	uint32_t CreateCtxOffset;
	uint32_t CreateCtxLength;
	smb2fid_t smb2fid = { 0, 0 };
	uint32_t status;
	int dh_flags;
	int skip;
	int rc = 0;

	bzero(&cctx, sizeof (cctx));
	op->create_ctx = &cctx;	/* for debugging */

	/*
	 * Paranoia.  This will set sr->fid_ofile, so
	 * if we already have one, release it now.
	 */
	if (sr->fid_ofile != NULL) {
		smb_ofile_release(sr->fid_ofile);
		sr->fid_ofile = NULL;
	}

	/*
	 * Decode the SMB2 Create request
	 *
	 * Most decode errors return SDRC_ERROR, but
	 * for some we give a more specific error.
	 *
	 * In the "decode section" (starts here) any
	 * errors should either return SDRC_ERROR, or
	 * if any cleanup is needed, goto errout.
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data, "wbblqqlllllwwll",
	    &StructSize,		/* w */
	    &SecurityFlags,		/* b */
	    &op->op_oplock_level,	/* b */
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
	if (skip < 0)
		return (SDRC_ERROR);
	if (skip > 0)
		(void) smb_mbc_decodef(&sr->smb_data, "#.", skip);

	/*
	 * Get the path name
	 *
	 * Name too long is not technically a decode error,
	 * but it's very rare, so we'll just skip the
	 * dtrace probes for this error case.
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

		rc = MBC_SHADOW_CHAIN(&cctx.cc_in_mbc, &sr->smb_data,
		    sr->smb2_cmd_hdr + CreateCtxOffset, CreateCtxLength);
		if (rc) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto errout;
		}
		status = smb2_decode_create_ctx(sr, &cctx);
		if (status)
			goto errout;
	}

	/*
	 * Everything is decoded into some internal form, so
	 * in this probe one can look at sr->arg.open etc.
	 *
	 * This marks the end of the "decode" section and the
	 * beginning of the "body" section.  Any errors in
	 * this section should use: goto cmd_done (which is
	 * just before the dtrace "done" probe).
	 */
	DTRACE_SMB2_START(op__Create, smb_request_t *, sr); /* arg.open */

	/*
	 * Process the incoming create contexts (already decoded),
	 * that need action before the open, starting with the
	 * Durable Handle ones, which may override others.
	 */

	/*
	 * Only disk trees get durable handles.
	 */
	if (smb2_enable_dh == 0 ||
	    (sr->tid_tree->t_res_type & STYPE_MASK) != STYPE_DISKTREE) {
		cctx.cc_in_flags &=
		    ~(CCTX_DH_REQUEST | CCTX_DH_REQUEST_V2 |
		    CCTX_DH_RECONNECT | CCTX_DH_RECONNECT_V2);
	}

	/*
	 * DH v2 is only valid in SMB3.0 and later.
	 * If seen in earlier dialects, ignore.
	 */
	if (sr->session->dialect < SMB_VERS_3_0) {
		cctx.cc_in_flags &=
		    ~(CCTX_DH_REQUEST_V2|CCTX_DH_RECONNECT_V2);
	}

	/*
	 * It is an error to specify more than one Durable Handle
	 * operation in a single create, except when only the v1
	 * REQUEST and RECONNECT operations are specified. In that
	 * case, the v1 REQUEST is ignored.
	 */
	dh_flags = cctx.cc_in_flags &
	    (CCTX_DH_REQUEST | CCTX_DH_REQUEST_V2 |
	    CCTX_DH_RECONNECT | CCTX_DH_RECONNECT_V2);
	if ((dh_flags & (dh_flags - 1)) != 0 &&
	    dh_flags != (CCTX_DH_REQUEST|CCTX_DH_RECONNECT)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto cmd_done;
	}

	/*
	 * Reconnect is special in MANY ways, including the
	 * somewhat surprising (specified) behavior that
	 * most other creat parameters are ignored, and
	 * many create context types are ignored too.
	 */
	op->dh_vers = SMB2_NOT_DURABLE;
	if ((cctx.cc_in_flags &
	    (CCTX_DH_RECONNECT|CCTX_DH_RECONNECT_V2)) != 0) {

		if ((cctx.cc_in_flags & CCTX_DH_RECONNECT_V2) != 0)
			op->dh_vers = SMB2_DURABLE_V2;
		else
			op->dh_vers = SMB2_DURABLE_V1;

		/* Ignore these create contexts. */
		cctx.cc_in_flags &=
		    ~(CCTX_DH_REQUEST |
		    CCTX_DH_REQUEST_V2 |
		    CCTX_EA_BUFFER |
		    CCTX_SD_BUFFER |
		    CCTX_ALLOCATION_SIZE |
		    CCTX_TIMEWARP_TOKEN |
		    CCTX_QUERY_ON_DISK_ID);

		/*
		 * Reconnect check needs to know if a lease was requested.
		 * The requested oplock level is ignored in reconnect, so
		 * using op_oplock_level to convey this info.
		 */
		if (cctx.cc_in_flags & CCTX_REQUEST_LEASE)
			op->op_oplock_level = SMB2_OPLOCK_LEVEL_LEASE;
		else
			op->op_oplock_level = 0;

		status = smb2_dh_reconnect(sr);
		if (status != NT_STATUS_SUCCESS)
			goto cmd_done;

		/*
		 * Skip most open execution during reconnect,
		 * but need (reclaimed) oplock state in *op.
		 */
		of = sr->fid_ofile;
		smb2_oplock_reconnect(sr);
		goto reconnect_done;
	}

	/*
	 * Real create (of a new handle, not reconnect)
	 */

	/*
	 * Validate the requested oplock level.
	 * Conversion to internal form is in smb2_oplock_acquire()
	 */
	switch (op->op_oplock_level) {
	case SMB2_OPLOCK_LEVEL_NONE:		/* OPLOCK_LEVEL_NONE */
	case SMB2_OPLOCK_LEVEL_II:		/* OPLOCK_LEVEL_TWO */
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:	/* OPLOCK_LEVEL_ONE */
	case SMB2_OPLOCK_LEVEL_BATCH:		/* OPLOCK_LEVEL_BATCH */
		/*
		 * Ignore lease create context (if any)
		 */
		cctx.cc_in_flags &= ~CCTX_REQUEST_LEASE;
		break;

	case SMB2_OPLOCK_LEVEL_LEASE:		/* OPLOCK_LEVEL_GRANULAR */
		/*
		 * Require a lease create context.
		 */
		if ((cctx.cc_in_flags & CCTX_REQUEST_LEASE) == 0) {
			cmn_err(CE_NOTE, "smb2:create, oplock=ff and no lease");
			status = NT_STATUS_INVALID_PARAMETER;
			goto cmd_done;
		}

		/*
		 * Validate lease request state
		 * Only a few valid combinations.
		 */
		switch (op->lease_state) {
		case SMB2_LEASE_NONE:
		case SMB2_LEASE_READ_CACHING:
		case SMB2_LEASE_READ_CACHING | SMB2_LEASE_HANDLE_CACHING:
		case SMB2_LEASE_READ_CACHING | SMB2_LEASE_WRITE_CACHING:
		case SMB2_LEASE_READ_CACHING | SMB2_LEASE_WRITE_CACHING |
		    SMB2_LEASE_HANDLE_CACHING:
			break;

		default:
			/*
			 * Invalid lease state flags
			 * Just force to "none".
			 */
			op->lease_state = SMB2_LEASE_NONE;
			break;
		}
		break;

	default:
		/* Unknown SMB2 oplock level. */
		status = NT_STATUS_INVALID_PARAMETER;
		goto cmd_done;
	}

	/*
	 * Only disk trees get oplocks or leases.
	 */
	if ((sr->tid_tree->t_res_type & STYPE_MASK) != STYPE_DISKTREE) {
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		cctx.cc_in_flags &= ~CCTX_REQUEST_LEASE;
	}

	if ((sr->tid_tree->t_flags & SMB_TREE_CA) == 0)
		op->dh_v2_flags &= ~DH_PERSISTENT;

	if ((cctx.cc_in_flags &
	    (CCTX_DH_REQUEST|CCTX_DH_REQUEST_V2)) != 0) {
		if ((cctx.cc_in_flags & CCTX_DH_REQUEST_V2) != 0)
			op->dh_vers = SMB2_DURABLE_V2;
		else
			op->dh_vers = SMB2_DURABLE_V1;
	}

	if (cctx.cc_in_flags & CCTX_EA_BUFFER) {
		status = NT_STATUS_EAS_NOT_SUPPORTED;
		goto cmd_done;
	}

	/*
	 * ImpersonationLevel (spec. says validate + ignore)
	 * SmbCreateFlags (spec. says ignore)
	 */

	if ((op->create_options & FILE_DELETE_ON_CLOSE) &&
	    !(op->desired_access & DELETE)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto cmd_done;
	}

	if (op->dattr & FILE_FLAG_WRITE_THROUGH)
		op->create_options |= FILE_WRITE_THROUGH;
	if (op->dattr & FILE_FLAG_DELETE_ON_CLOSE)
		op->create_options |= FILE_DELETE_ON_CLOSE;
	if (op->dattr & FILE_FLAG_BACKUP_SEMANTICS)
		op->create_options |= FILE_OPEN_FOR_BACKUP_INTENT;
	if (op->create_options & FILE_OPEN_FOR_BACKUP_INTENT)
		sr->user_cr = smb_user_getprivcred(sr->uid_user);
	if (op->create_disposition > FILE_MAXIMUM_DISPOSITION) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto cmd_done;
	}

	/*
	 * The real open call.   Note: this gets attributes into
	 * op->fqi.fq_fattr (SMB_AT_ALL).  We need those below.
	 * When of != NULL, goto errout closes it.
	 */
	status = smb_common_open(sr);
	if (status != NT_STATUS_SUCCESS)
		goto cmd_done;
	of = sr->fid_ofile;

	/*
	 * Set the "persistent" part of the file ID
	 * (only for DISK shares).  Need this even for
	 * non-durable handles in case we get the ioctl
	 * to set "resiliency" on this handle.
	 */
	if (of->f_ftype == SMB_FTYPE_DISK) {
		if ((op->dh_v2_flags & DH_PERSISTENT) != 0)
			smb_ofile_set_persistid_ph(of);
		else
			smb_ofile_set_persistid_dh(of);
	}

	/*
	 * [MS-SMB2] 3.3.5.9.8
	 * Handling the SMB2_CREATE_REQUEST_LEASE Create Context
	 */
	if ((cctx.cc_in_flags & CCTX_REQUEST_LEASE) != 0) {
		status = smb2_lease_create(sr, sr->session->clnt_uuid);
		if (status != NT_STATUS_SUCCESS) {
			if (op->action_taken == SMB_OACT_CREATED) {
				smb_ofile_set_delete_on_close(sr, of);
			}
			goto cmd_done;
		}
	}
	if (op->op_oplock_level == SMB2_OPLOCK_LEVEL_LEASE) {
		smb2_lease_acquire(sr);
	} else if (op->op_oplock_level != SMB2_OPLOCK_LEVEL_NONE) {
		smb2_oplock_acquire(sr);
	}

	/*
	 * Make this a durable open, but only if:
	 * (durable handle requested and...)
	 *
	 * 1. op_oplock_level == SMB2_OPLOCK_LEVEL_BATCH
	 * 2. A lease is requested with handle caching
	 *    - for v1, the lease must not be on a directory
	 * 3. For v2, flags has "persistent" (tree is CA)
	 *    (when tree not CA, turned off persist above)
	 *
	 * Otherwise, DH requests are ignored, so we set
	 * dh_vers = not durable
	 */
	if ((cctx.cc_in_flags &
	    (CCTX_DH_REQUEST|CCTX_DH_REQUEST_V2)) != 0 &&
	    smb_node_is_file(of->f_node) &&
	    ((op->dh_v2_flags & DH_PERSISTENT) != 0 ||
	    (op->op_oplock_level == SMB2_OPLOCK_LEVEL_BATCH) ||
	    (op->op_oplock_level == SMB2_OPLOCK_LEVEL_LEASE &&
	    (op->lease_state & OPLOCK_LEVEL_CACHE_HANDLE) != 0))) {
		/*
		 * OK, make this handle "durable"
		 */
		if (op->dh_vers == SMB2_DURABLE_V2) {
			(void) memcpy(of->dh_create_guid,
			    op->create_guid, UUID_LEN);

			if ((op->dh_v2_flags & DH_PERSISTENT) != 0) {
				if (smb2_dh_make_persistent(sr, of) == 0) {
					of->dh_persist = B_TRUE;
				} else {
					op->dh_v2_flags = 0;
				}
			}
		}
		if (op->dh_vers != SMB2_NOT_DURABLE) {
			uint32_t msto;

			of->dh_vers = op->dh_vers;
			of->dh_expire_time = 0;

			/*
			 * Client may provide timeout=0 to request
			 * the default timeout (in mSec.)
			 */
			msto = op->dh_timeout;
			if (msto == 0) {
				msto = (of->dh_persist) ?
				    smb2_persist_timeout :
				    smb2_dh_def_timeout;
			}
			if (msto > smb2_dh_max_timeout)
				msto = smb2_dh_max_timeout;
			op->dh_timeout = msto;
			of->dh_timeout_offset = MSEC2NSEC(msto);
		}
	} else {
		op->dh_vers = SMB2_NOT_DURABLE;
		op->dh_v2_flags = 0;
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
reconnect_done:
	smb2fid.persistent = of->f_persistid;
	smb2fid.temporal = sr->smb_fid;

	switch (sr->tid_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
	case STYPE_PRINTQ:
		if (op->create_options & FILE_DELETE_ON_CLOSE)
			smb_ofile_set_delete_on_close(sr, of);
		break;
	}

	/*
	 * Process any outgoing create contexts that need work
	 * after the open succeeds.  Encode happens later.
	 */
	if (cctx.cc_in_flags & CCTX_QUERY_MAX_ACCESS) {
		op->maximum_access = 0;
		if (of->f_node != NULL) {
			smb_fsop_eaccess(sr, of->f_cr, of->f_node,
			    &op->maximum_access);
		}
		op->maximum_access |= of->f_granted_access;
		cctx.cc_out_flags |= CCTX_QUERY_MAX_ACCESS;
	}

	if ((cctx.cc_in_flags & CCTX_QUERY_ON_DISK_ID) != 0 &&
	    of->f_node != NULL) {
		op->op_fsid = SMB_NODE_FSID(of->f_node);
		cctx.cc_out_flags |= CCTX_QUERY_ON_DISK_ID;
	}

	if ((cctx.cc_in_flags & CCTX_AAPL_EXT) != 0) {
		cce = &cctx.cc_out_aapl;
		/*
		 * smb2_aapl_crctx has a variable response depending on
		 * what the incoming context looks like, so it does all
		 * the work of building cc_out_aapl, including setting
		 * cce_len, cce_mbc.max_bytes, and smb_mbc_encode.
		 * If we see errors getting this, simply omit it from
		 * the collection of returned create contexts.
		 */
		status = smb2_aapl_crctx(sr,
		    &cctx.cc_in_aapl.cce_mbc, &cce->cce_mbc);
		if (status == 0) {
			cce->cce_len = cce->cce_mbc.chain_offset;
			cctx.cc_out_flags |= CCTX_AAPL_EXT;
		}
		status = 0;
	}

	/*
	 * If a lease was requested, and we got one...
	 */
	if ((cctx.cc_in_flags & CCTX_REQUEST_LEASE) != 0 &&
	    op->op_oplock_level == SMB2_OPLOCK_LEVEL_LEASE)
		cctx.cc_out_flags |= CCTX_REQUEST_LEASE;

	/*
	 * If a durable handle was requested and we got one...
	 */
	if ((cctx.cc_in_flags & CCTX_DH_REQUEST) != 0 &&
	    of->dh_vers == SMB2_DURABLE_V1) {
		cctx.cc_out_flags |= CCTX_DH_REQUEST;
	}
	if ((cctx.cc_in_flags & CCTX_DH_REQUEST_V2) != 0 &&
	    of->dh_vers == SMB2_DURABLE_V2) {
		cctx.cc_out_flags |= CCTX_DH_REQUEST_V2;
	}

	/*
	 * This marks the end of the "body" section and the
	 * beginning of the "encode" section.  Any errors
	 * encoding the response should use: goto errout
	 */
cmd_done:
	/* Want status visible in the done probe. */
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__Create, smb_request_t *, sr);
	if (status != NT_STATUS_SUCCESS)
		goto errout;

	/*
	 * Encode all the create contexts to return.
	 */
	if (cctx.cc_out_flags) {
		sr->raw_data.max_bytes = smb2_max_trans;
		status = smb2_encode_create_ctx(sr, &cctx);
		if (status)
			goto errout;
	}

	/*
	 * Encode the SMB2 Create reply
	 */
	attr = &op->fqi.fq_fattr;
	rc = smb_mbc_encodef(
	    &sr->reply,
	    "wb.lTTTTqqllqqll",
	    89,	/* StructSize */	/* w */
	    op->op_oplock_level,	/* b */
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

	if (status != 0) {
	errout:
		if (of != NULL)
			smb_ofile_close(of, 0);
		smb2sr_put_error(sr, status);
	}
	if (op->sd != NULL) {
		smb_sd_term(op->sd);
		kmem_free(op->sd, sizeof (*op->sd));
	}
	if (cctx.cc_out_flags)
		smb2_free_create_ctx(&cctx);

	return (SDRC_SUCCESS);
}

/*
 * Decode an SMB2 Create Context buffer into our internal form.
 * Avoid policy decisions about what's supported here, just decode.
 */
static uint32_t
smb2_decode_create_ctx(smb_request_t *sr, smb2_create_ctx_t *cc)
{
	smb_arg_open_t *op = &sr->arg.open;
	smb2_create_ctx_elem_t *cce;
	mbuf_chain_t *in_mbc = &cc->cc_in_mbc;
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

	/*
	 * Any break from the loop below before we've decoded
	 * the entire create context means it was malformatted,
	 * so we should return INVALID_PARAMETER.
	 */
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
		case SMB2_CREATE_CTX_AAPL:		/* ("AAPL") */
			cc->cc_in_flags |= CCTX_AAPL_EXT;
			cce = &cc->cc_in_aapl;
			break;
		case SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2: /* ("DH2Q") */
			cc->cc_in_flags |= CCTX_DH_REQUEST_V2;
			cce = &cc->cc_in_dh_request_v2;
			break;
		case SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2: /* ("DH2C") */
			cc->cc_in_flags |= CCTX_DH_RECONNECT_V2;
			cce = &cc->cc_in_dh_reconnect_v2;
			break;
		case 0x9ccbcf9e: /* SVHDX_OPEN_DEVICE_CONTEXT */
			/* 9ccbcf9e 04c1e643 980e158d a1f6ec83 */
			/* silently ignore */
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

		if (cce == NULL || data_len == 0)
			goto next_cc;

		if ((data_off & 7) != 0)
			break;
		if ((top_offset + data_off) < in_mbc->chain_offset)
			break;
		rc = MBC_SHADOW_CHAIN(&cce->cce_mbc, in_mbc,
		    top_offset + data_off, data_len);
		if (rc)
			break;
		cce->cce_len = data_len;

		/*
		 * Additonal decoding for some create contexts.
		 */
		switch (cc_name.i) {
			uint64_t nttime;

		case SMB2_CREATE_SD_BUFFER:		/* ("SecD") */
			op->sd = kmem_alloc(sizeof (smb_sd_t), KM_SLEEP);
			if (smb_decode_sd(&cce->cce_mbc, op->sd) != 0)
				goto errout;
			break;

		case SMB2_CREATE_ALLOCATION_SIZE:	/* ("AISi") */
			rc = smb_mbc_decodef(&cce->cce_mbc, "q", &op->dsize);
			if (rc != 0)
				goto errout;
			break;

		case SMB2_CREATE_TIMEWARP_TOKEN:	/* ("TWrp") */
			/*
			 * Support for opening "Previous Versions".
			 * [MS-SMB2] 2.2.13.2.7  Data is an NT time.
			 */
			rc = smb_mbc_decodef(&cce->cce_mbc,
			    "q", &nttime);
			if (rc != 0)
				goto errout;
			smb_time_nt_to_unix(nttime, &op->timewarp);
			op->create_timewarp = B_TRUE;
			break;

		/*
		 * Note: This handles both V1 and V2 leases,
		 * which differ only by their length.
		 */
		case SMB2_CREATE_REQUEST_LEASE:		/* ("RqLs") */
			if (data_len == 52) {
				op->lease_version = 2;
			} else if (data_len == 32) {
				op->lease_version = 1;
			} else {
				cmn_err(CE_NOTE, "Cctx RqLs bad len=0x%x",
				    data_len);
			}
			rc = smb_mbc_decodef(&cce->cce_mbc, "#cllq",
			    UUID_LEN,			/* # */
			    op->lease_key,		/* c */
			    &op->lease_state,		/* l */
			    &op->lease_flags,		/* l */
			    &nttime);	/* (ignored)	   q */
			if (rc != 0)
				goto errout;
			if (op->lease_version == 2) {
				rc = smb_mbc_decodef(&cce->cce_mbc,
				    "#cw..",
				    UUID_LEN,
				    op->parent_lease_key,
				    &op->lease_epoch);
				if (rc != 0)
					goto errout;
			} else {
				bzero(op->parent_lease_key, UUID_LEN);
			}
			break;

		case SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2: /* ("DH2C") */
			rc = smb_mbc_decodef(&cce->cce_mbc, "qq#cl",
			    &op->dh_fileid.persistent,	/* q */
			    &op->dh_fileid.temporal,	/* q */
			    UUID_LEN,			/* # */
			    op->create_guid,		/* c */
			    &op->dh_v2_flags);		/* l */
			if (rc != 0)
				goto errout;
			break;

		case SMB2_CREATE_DURABLE_HANDLE_RECONNECT: /* ("DHnC") */
			rc = smb_mbc_decodef(&cce->cce_mbc, "qq",
			    &op->dh_fileid.persistent, /* q */
			    &op->dh_fileid.temporal); /* q */
			if (rc != 0)
				goto errout;
			bzero(op->create_guid, UUID_LEN);
			op->dh_v2_flags = 0;
			break;

		case SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2: /* ("DH2Q") */
			rc = smb_mbc_decodef(&cce->cce_mbc,
			    "ll8.#c",
			    &op->dh_timeout,	/* l */
			    &op->dh_v2_flags,	/* l */
			    /* reserved */	/* 8. */
			    UUID_LEN, /* # */
			    op->create_guid); /* c */
			if (rc != 0)
				goto errout;
			break;

		case SMB2_CREATE_DURABLE_HANDLE_REQUEST: /* ("DHnQ") */
			rc = smb_mbc_decodef(&cce->cce_mbc,
			    "16."); /* reserved */
			if (rc != 0)
				goto errout;
			op->dh_timeout = 0;	/* default */
			op->dh_v2_flags = 0;
			break;
		}

	next_cc:
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

errout:
	return (status);
}

/*
 * Encode an SMB2 Create Context buffer from our internal form.
 *
 * Build the Create Context to return; first the
 * per-element parts, then the aggregated buffer.
 *
 * No response for these:
 *	CCTX_EA_BUFFER
 *	CCTX_SD_BUFFER
 *	CCTX_ALLOCATION_SIZE
 *	CCTX_TIMEWARP_TOKEN
 *
 * Remember to add code sections to smb2_free_create_ctx()
 * for each section here that encodes a context element.
 */
static uint32_t
smb2_encode_create_ctx(smb_request_t *sr, smb2_create_ctx_t *cc)
{
	smb_arg_open_t *op = &sr->arg.open;
	smb2_create_ctx_elem_t *cce;
	mbuf_chain_t *mbc = &sr->raw_data;
	int last_top = -1;
	int rc;

	if (cc->cc_out_flags & CCTX_QUERY_MAX_ACCESS) {
		cce = &cc->cc_out_max_access;

		cce->cce_mbc.max_bytes = cce->cce_len = 8;
		(void) smb_mbc_encodef(&cce->cce_mbc,
		    "ll", 0, op->maximum_access);

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

		cce->cce_mbc.max_bytes = cce->cce_len = 32;
		(void) smb_mbc_encodef(
		    &cce->cce_mbc, "qll.15.",
		    op->fileid,			/* q */
		    op->op_fsid.val[0],		/* l */
		    op->op_fsid.val[1]);	/* l */
		    /* reserved (16 bytes)	.15. */

		last_top = mbc->chain_offset;
		rc = smb2_encode_create_ctx_elem(mbc, cce,
		    SMB2_CREATE_QUERY_ON_DISK_ID);
		if (rc)
			return (NT_STATUS_INTERNAL_ERROR);
		(void) smb_mbc_poke(mbc, last_top, "l",
		    mbc->chain_offset - last_top);
	}

	if (cc->cc_out_flags & CCTX_AAPL_EXT) {
		cce = &cc->cc_out_aapl;
		/* cc_out_aapl already encoded */

		last_top = mbc->chain_offset;
		rc = smb2_encode_create_ctx_elem(mbc, cce,
		    SMB2_CREATE_CTX_AAPL);
		if (rc)
			return (NT_STATUS_INTERNAL_ERROR);
		(void) smb_mbc_poke(mbc, last_top, "l",
		    mbc->chain_offset - last_top);
	}

	if (cc->cc_out_flags & CCTX_REQUEST_LEASE) {
		cce = &cc->cc_out_req_lease;

		cce->cce_mbc.max_bytes = cce->cce_len = 32;
		(void) smb_mbc_encodef(&cce->cce_mbc, "#cllq",
		    UUID_LEN,			/* # */
		    op->lease_key,		/* c */
		    op->lease_state,		/* l */
		    op->lease_flags,		/* l */
		    0LL);			/* q */
		if (op->lease_version == 2) {
			cce->cce_mbc.max_bytes = cce->cce_len = 52;
			(void) smb_mbc_encodef(&cce->cce_mbc,
			    "#cw..",
			    UUID_LEN,
			    op->parent_lease_key,
			    op->lease_epoch);
		}

		last_top = mbc->chain_offset;
		rc = smb2_encode_create_ctx_elem(mbc, cce,
		    SMB2_CREATE_REQUEST_LEASE);
		if (rc)
			return (NT_STATUS_INTERNAL_ERROR);
		(void) smb_mbc_poke(mbc, last_top, "l",
		    mbc->chain_offset - last_top);
	}

	if (cc->cc_out_flags & CCTX_DH_REQUEST) {
		cce = &cc->cc_out_dh_request;

		cce->cce_mbc.max_bytes = cce->cce_len = 8;
		(void) smb_mbc_encodef(&cce->cce_mbc, "q", 0LL);

		last_top = mbc->chain_offset;
		rc = smb2_encode_create_ctx_elem(mbc, cce,
		    SMB2_CREATE_DURABLE_HANDLE_REQUEST);
		if (rc)
			return (NT_STATUS_INTERNAL_ERROR);
		(void) smb_mbc_poke(mbc, last_top, "l",
		    mbc->chain_offset - last_top);
	}

	if (cc->cc_out_flags & CCTX_DH_REQUEST_V2) {
		cce = &cc->cc_out_dh_request_v2;

		cce->cce_mbc.max_bytes = cce->cce_len = 8;
		(void) smb_mbc_encodef(&cce->cce_mbc, "ll",
		    op->dh_timeout, op->dh_v2_flags);

		last_top = mbc->chain_offset;
		rc = smb2_encode_create_ctx_elem(mbc, cce,
		    SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2);
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
	 *	a: this header (16 bytes)
	 *	b: the name (4 bytes, 4 pad)
	 *	c: the payload (variable)
	 *	d: padding (to align 8)
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
	    cce->cce_len); /* DataLen	l */
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

	(void) smb_mbc_put_align(out_mbc, 8);

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
	if (cc->cc_out_flags & CCTX_AAPL_EXT) {
		cce = &cc->cc_out_aapl;
		MBC_FLUSH(&cce->cce_mbc);
	}
	if (cc->cc_out_flags & CCTX_REQUEST_LEASE) {
		cce = &cc->cc_out_req_lease;
		MBC_FLUSH(&cce->cce_mbc);
	}
	if (cc->cc_out_flags & CCTX_DH_REQUEST) {
		cce = &cc->cc_out_dh_request;
		MBC_FLUSH(&cce->cce_mbc);
	}
	if (cc->cc_out_flags & CCTX_DH_REQUEST_V2) {
		cce = &cc->cc_out_dh_request_v2;
		MBC_FLUSH(&cce->cce_mbc);
	}
}
