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
 * Copyright 2015-2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Dispatch function for SMB2_READ
 * MS-SMB2 sec. 3.3.5.12
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>

extern boolean_t smb_allow_unbuffered;

int smb2_read_zcopy = 1;

/*
 * Copy Reduction support.
 * xuio_t wrapper with additional private data.
 */
typedef struct smb_xuio {
	xuio_t su_xuio;		// keep first!
	smb_node_t *su_node;
	uint_t su_ref;
} smb_xuio_t;

/*
 * Allocate an smb_xuio_t object.  This survives long enough
 * to keep track of buffers loaned to us from the VFS layer.
 * We'll construct mbufs with "external" buffers setup to
 * point to the loaned VFS buffers, incrementing the su_ref
 * count for each.  Each such message when free'd will call
 * the smb_xuio_free function below.
 */
smb_xuio_t *
smb_xuio_alloc(smb_node_t *node)
{
	smb_xuio_t *su;

	su = kmem_zalloc(sizeof (*su), KM_SLEEP);
	su->su_node = node;
	smb_node_ref(node);

	/*
	 * Initial ref count set to 1, later incremented
	 * for the mbufs that refer to borrowed buffers
	 * owned by this xuio.  See smb_xuio_to_mbuf().
	 */
	su->su_ref = 1;
	su->su_xuio.xu_type = UIOTYPE_ZEROCOPY;

	return (su);
}

/*
 * Callback function to return the loaned buffers.
 * Calls VOP_RETZCBUF() only after all messages with
 * references to this xuio are free'd.
 */
void
smb_xuio_free(void *varg)
{
	uint_t ref;
	smb_xuio_t *su = (smb_xuio_t *)varg;
	xuio_t *xu = &su->su_xuio;

	ref = atomic_dec_uint_nv(&su->su_ref);
	if (ref != 0)
		return;

	/* The XUIO flag is set by VOP_REQZCBUF */
	if (xu->xu_uio.uio_extflg & UIO_XUIO) {
		(void) smb_fsop_retzcbuf(su->su_node, xu, CRED());
	}

	smb_node_release(su->su_node);
	kmem_free(su, sizeof (*su));
}

/*
 * Wrapper for smb_mbuf_alloc_ext free function because the
 * free function is passed a pointer to the mbuf, not arg1.
 */
static void
smb_xuio_mbuf_free(mbuf_t *m)
{
	ASSERT((m->m_flags & M_EXT) != 0);
	smb_xuio_free(m->m_ext.ext_arg1);
	/* caller clears m_ext.ext_buf */
}

/*
 * Build list of mbufs pointing to the loaned xuio buffers.
 * Note these are not visible yet to other threads, so
 * not using atomics to adjust su_ref.
 */
static mbuf_t *
smb_xuio_to_mbuf(smb_xuio_t *su)
{
	uio_t *uiop;
	struct iovec *iovp;
	mbuf_t *mp, *mp1;
	int i;

	uiop = &su->su_xuio.xu_uio;
	if (uiop->uio_iovcnt == 0)
		return (NULL);

	iovp = uiop->uio_iov;

	mp = smb_mbuf_alloc_ext(iovp->iov_base, iovp->iov_len,
	    smb_xuio_mbuf_free, su);
	ASSERT(mp != NULL);
	su->su_ref++;

	mp1 = mp;
	for (i = 1; i < uiop->uio_iovcnt; i++) {
		iovp = (uiop->uio_iov + i);

		mp1->m_next = smb_mbuf_alloc_ext(iovp->iov_base,
		    iovp->iov_len, smb_xuio_mbuf_free, su);

		mp1 = mp1->m_next;
		ASSERT(mp1 != NULL);
		su->su_ref++;
	}

	return (mp);
}

smb_sdrc_t
smb2_read(smb_request_t *sr)
{
	smb_rw_param_t *param = NULL;
	smb_ofile_t *of = NULL;
	smb_vdb_t *vdb = NULL;
	struct mbuf *m = NULL;
	smb_xuio_t *su = NULL;
	uio_t *uio = NULL;
	uint16_t StructSize;
	uint8_t Padding;
	uint8_t Flags;
	uint8_t DataOff;
	uint32_t Length;
	uint64_t Offset;
	smb2fid_t smb2fid;
	uint32_t MinCount;
	uint32_t Channel;
	uint32_t Remaining;
	uint16_t ChanInfoOffset;
	uint16_t ChanInfoLength;
	uint32_t XferCount = 0;
	uint32_t status;
	int rc = 0;
	int ioflag = 0;
	boolean_t unbuffered = B_FALSE;
	boolean_t zcopy = B_FALSE;

	/*
	 * SMB2 Read request
	 */
	rc = smb_mbc_decodef(
	    &sr->smb_data,
	    "wbblqqqlllww",
	    &StructSize,		/* w */
	    &Padding,			/* b */
	    &Flags,			/* b */
	    &Length,			/* l */
	    &Offset,			/* q */
	    &smb2fid.persistent,	/* q */
	    &smb2fid.temporal,		/* q */
	    &MinCount,			/* l */
	    &Channel,			/* l */
	    &Remaining,			/* l */
	    &ChanInfoOffset,		/* w */
	    &ChanInfoLength);		/* w */
	if (rc)
		return (SDRC_ERROR);
	if (StructSize != 49)
		return (SDRC_ERROR);

	/*
	 * Setup an smb_rw_param_t which contains the VDB we need.
	 * This is automatically free'd.
	 */
	param = smb_srm_zalloc(sr, sizeof (*param));
	param->rw_offset = Offset;
	param->rw_count = Length;
	/* Note that the dtrace provider uses sr->arg.rw */
	sr->arg.rw = param;

	/*
	 * Want FID lookup before the start probe.
	 */
	status = smb2sr_lookup_fid(sr, &smb2fid);
	of = sr->fid_ofile;

	DTRACE_SMB2_START(op__Read, smb_request_t *, sr); /* arg.rw */

	if (status != 0)
		goto done; /* Bad FID */

	/*
	 * Short-circuit zero-byte read, otherwise could panic
	 * setting up buffers in smb_mbuf_allocate etc.
	 */
	if (Length == 0)
		goto done;

	if (Length > smb2_max_rwsize) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}
	if (MinCount > Length)
		MinCount = Length;

	vdb = &param->rw_vdb;
	vdb->vdb_tag = 0;
	vdb->vdb_uio.uio_iov = &vdb->vdb_iovec[0];
	vdb->vdb_uio.uio_iovcnt = MAX_IOVEC;
	vdb->vdb_uio.uio_resid = Length;
	vdb->vdb_uio.uio_loffset = (offset_t)Offset;
	vdb->vdb_uio.uio_segflg = UIO_SYSSPACE;
	vdb->vdb_uio.uio_extflg = UIO_COPY_DEFAULT;

	/*
	 * Unbuffered refers to the MS-FSA Read argument by the same name.
	 * It indicates that the cache for this range should be flushed to disk,
	 * and data read directly from disk, bypassing the cache.
	 * We don't allow that degree of cache management.
	 * Translate this directly as FRSYNC,
	 * which should at least flush the cache first.
	 */

	if (smb_allow_unbuffered &&
	    (Flags & SMB2_READFLAG_READ_UNBUFFERED) != 0) {
		unbuffered = B_TRUE;
		ioflag = FRSYNC;
	}

	switch (of->f_tree->t_res_type & STYPE_MASK) {
	case STYPE_DISKTREE:
		if (smb_node_is_dir(of->f_node)) {
			rc = EISDIR;
			break;
		}
		/* Check for conflicting locks. */
		rc = smb_lock_range_access(sr, of->f_node,
		    Offset, Length, B_FALSE);
		if (rc) {
			rc = ERANGE;
			break;
		}

		zcopy = (smb2_read_zcopy != 0);
		if (zcopy) {
			su = smb_xuio_alloc(of->f_node);
			uio = &su->su_xuio.xu_uio;
			uio->uio_segflg = UIO_SYSSPACE;
			uio->uio_loffset = (offset_t)Offset;
			uio->uio_resid = Length;

			rc = smb_fsop_reqzcbuf(of->f_node, &su->su_xuio,
			    UIO_READ, of->f_cr);
			if (rc == 0) {
				ASSERT((uio->uio_extflg & UIO_XUIO) != 0);
			} else {
				ASSERT((uio->uio_extflg & UIO_XUIO) == 0);
				smb_xuio_free(su);
				su = NULL;
				uio = NULL;
				zcopy = B_FALSE;
			}
		}
		if (!zcopy) {
			sr->raw_data.max_bytes = Length;
			m = smb_mbuf_allocate(&vdb->vdb_uio);
			uio = &vdb->vdb_uio;
		}

		rc = smb_fsop_read(sr, of->f_cr, of->f_node, of, uio, ioflag);
		if (rc != 0) {
			if (zcopy) {
				smb_xuio_free(su);
				su = NULL;
				uio = NULL;
			}
			m_freem(m);
			m = NULL;
			break;
		}

		/* How much data we moved. */
		XferCount = Length - uio->uio_resid;

		if (zcopy) {
			/*
			 * Build mblk chain of messages pointing to
			 * the loaned buffers in su->su_xuio
			 * Done with su (and uio) after this.
			 * NB: uio points into su->su_xuio
			 */
			ASSERT(m == NULL);
			m = smb_xuio_to_mbuf(su);
			smb_xuio_free(su);
			su = NULL;
			uio = NULL;
		}

		sr->raw_data.max_bytes = XferCount;
		smb_mbuf_trim(m, XferCount);
		MBC_ATTACH_MBUF(&sr->raw_data, m);

		break;

	case STYPE_IPC:
		if (unbuffered) {
			rc = EINVAL;
			break;
		}
		sr->raw_data.max_bytes = Length;
		m = smb_mbuf_allocate(&vdb->vdb_uio);

		rc = smb_opipe_read(sr, &vdb->vdb_uio);

		/* How much data we moved. */
		XferCount = Length - vdb->vdb_uio.uio_resid;
		sr->raw_data.max_bytes = XferCount;
		smb_mbuf_trim(m, XferCount);
		MBC_ATTACH_MBUF(&sr->raw_data, m);
		break;

	default:
	case STYPE_PRINTQ:
		rc = EACCES;
		break;
	}
	status = smb_errno2status(rc);

	/*
	 * [MS-SMB2] If the read returns fewer bytes than specified by
	 * the MinimumCount field of the request, the server MUST fail
	 * the request with STATUS_END_OF_FILE
	 */
	if (status == 0 && XferCount < MinCount)
		status = NT_STATUS_END_OF_FILE;

	/*
	 * Checking the error return _after_ dealing with
	 * the returned data so that if m was allocated,
	 * it will be free'd via sr->raw_data cleanup.
	 */
done:
	sr->smb2_status = status;
	DTRACE_SMB2_DONE(op__Read, smb_request_t *, sr); /* arg.rw */
	if (status) {
		smb2sr_put_error(sr, status);
		return (SDRC_SUCCESS);
	}

	/*
	 * SMB2 Read reply
	 */
	DataOff = SMB2_HDR_SIZE + 16;
	rc = smb_mbc_encodef(
	    &sr->reply,
	    "wb.lllC",
	    17,	/* StructSize */	/* w */
	    DataOff,			/* b. */
	    XferCount,			/* l */
	    0, /* DataRemaining */	/* l */
	    0, /* reserved */		/* l */
	    &sr->raw_data);		/* C */
	if (rc) {
		sr->smb2_status = NT_STATUS_INTERNAL_ERROR;
		return (SDRC_ERROR);
	}

	mutex_enter(&of->f_mutex);
	of->f_seek_pos = Offset + XferCount;
	mutex_exit(&of->f_mutex);

	return (SDRC_SUCCESS);
}
