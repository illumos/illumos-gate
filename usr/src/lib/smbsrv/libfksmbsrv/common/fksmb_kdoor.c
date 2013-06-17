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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * "Upcall" glue for the fake (user-mode) smbsrv module.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/door.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_door.h>

static int smb_kdoor_encode(smb_doorarg_t *);
static int smb_kdoor_decode(smb_doorarg_t *);
static void smb_kdoor_sethdr(smb_doorarg_t *, uint32_t);
static boolean_t smb_kdoor_chkhdr(smb_doorarg_t *, smb_doorhdr_t *);
static void smb_kdoor_free(door_arg_t *);

void
smb_kdoor_init(smb_server_t *sv)
{
	sv->sv_kdoor_id = -1;
	mutex_init(&sv->sv_kdoor_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sv->sv_kdoor_cv, NULL, CV_DEFAULT, NULL);
}

void
smb_kdoor_fini(smb_server_t *sv)
{
	smb_kdoor_close(sv);
	cv_destroy(&sv->sv_kdoor_cv);
	mutex_destroy(&sv->sv_kdoor_mutex);
}

/*
 * In the "fake kernen", our "upcalls" don't use the
 * real door, but just call via a function pointer.
 * This is where we setup that pointer, which is
 * fksmbd_door_dispatch()
 */
void
fksmb_kdoor_open(smb_server_t *sv, void *varg)
{
	sv->sv_kdoor_hd = varg;
}

void
smb_kdoor_close(smb_server_t *sv)
{
	sv->sv_kdoor_hd = NULL;
	sv->sv_kdoor_id = -1;
}

/* ARGSUSED */
int
smb_kdoor_upcall(smb_server_t *sv, uint32_t cmd,
    void *req_data, xdrproc_t req_xdr,
    void *rsp_data, xdrproc_t rsp_xdr)
{
	smb_doorarg_t	da;
	fksmb_kdoor_disp_func_t *func;
	int rc;

	bzero(&da, sizeof (smb_doorarg_t));
	da.da_opcode = cmd;
	da.da_opname = smb_doorhdr_opname(cmd);
	da.da_req_xdr = req_xdr;
	da.da_rsp_xdr = rsp_xdr;
	da.da_req_data = req_data;
	da.da_rsp_data = rsp_data;

	if ((req_data == NULL && req_xdr != NULL) ||
	    (rsp_data == NULL && rsp_xdr != NULL)) {
		cmn_err(CE_WARN, "smb_kdoor_upcall[%s]: invalid param",
		    da.da_opname);
		return (-1);
	}

	/* NB: no ASYNC, nor event stuff */

	func = (fksmb_kdoor_disp_func_t *)(sv->sv_kdoor_hd);
	if (func == NULL)
		return (EFAULT);

	if ((rc = smb_kdoor_encode(&da)) != 0)
		goto out;

	/*
	 * The "upcall" (just call via function pointer)
	 * i.e. see: fksmbd_door_dispatch()
	 */
	if ((rc = (*func)(&da)) != 0)
		goto out;

	rc = smb_kdoor_decode(&da);
out:
	smb_kdoor_free(&da.da_arg);

	return (rc);
}

/* no smb_kdoor_send, smb_kdoor_receive */
/* no smb_kdoor_upcall_private */

static int
smb_kdoor_encode(smb_doorarg_t *da)
{
	XDR		xdrs;
	char		*buf;
	uint32_t	len;

	len = xdr_sizeof(smb_doorhdr_xdr, &da->da_hdr);
	if (da->da_req_xdr != NULL)
		len += xdr_sizeof(da->da_req_xdr, da->da_req_data);

	smb_kdoor_sethdr(da, len);

	buf = kmem_zalloc(len, KM_SLEEP);
	xdrmem_create(&xdrs, buf, len, XDR_ENCODE);

	if (!smb_doorhdr_xdr(&xdrs, &da->da_hdr)) {
		cmn_err(CE_WARN, "smb_kdoor_encode[%s]: header encode failed",
		    da->da_opname);
		kmem_free(buf, len);
		xdr_destroy(&xdrs);
		return (-1);
	}

	if (da->da_req_xdr != NULL) {
		if (!da->da_req_xdr(&xdrs, da->da_req_data)) {
			cmn_err(CE_WARN, "smb_kdoor_encode[%s]: encode failed",
			    da->da_opname);
			kmem_free(buf, len);
			xdr_destroy(&xdrs);
			return (-1);
		}
	}

	da->da_arg.data_ptr = buf;
	da->da_arg.data_size = len;
	da->da_arg.desc_ptr = NULL;
	da->da_arg.desc_num = 0;
	da->da_arg.rbuf = buf;
	da->da_arg.rsize = len;

	xdr_destroy(&xdrs);
	return (0);
}

/*
 * Decode the response in rbuf and rsize.
 */
static int
smb_kdoor_decode(smb_doorarg_t *da)
{
	XDR		xdrs;
	smb_doorhdr_t	hdr;
	char		*rbuf = da->da_arg.rbuf;
	uint32_t	rsize = da->da_arg.rsize;

	if (rbuf == NULL || rsize == 0) {
		cmn_err(CE_WARN, "smb_kdoor_decode[%s]: invalid param",
		    da->da_opname);
		return (-1);
	}

	xdrmem_create(&xdrs, rbuf, rsize, XDR_DECODE);

	if (!smb_doorhdr_xdr(&xdrs, &hdr)) {
		cmn_err(CE_WARN, "smb_kdoor_decode[%s]: header decode failed",
		    da->da_opname);
		xdr_destroy(&xdrs);
		return (-1);
	}

	if (!smb_kdoor_chkhdr(da, &hdr)) {
		xdr_destroy(&xdrs);
		return (-1);
	}

	if (hdr.dh_datalen != 0 && da->da_rsp_xdr != NULL) {
		if (!da->da_rsp_xdr(&xdrs, da->da_rsp_data)) {
			cmn_err(CE_WARN, "smb_kdoor_decode[%s]: decode failed",
			    da->da_opname);
			xdr_destroy(&xdrs);
			return (-1);
		}
	}

	xdr_destroy(&xdrs);
	return (0);
}

static void
smb_kdoor_sethdr(smb_doorarg_t *da, uint32_t datalen)
{
	smb_doorhdr_t	*hdr = &da->da_hdr;

	bzero(hdr, sizeof (smb_doorhdr_t));
	hdr->dh_magic = SMB_DOOR_HDR_MAGIC;
	hdr->dh_flags = da->da_flags | SMB_DF_FAKE_KERNEL;
	hdr->dh_op = da->da_opcode;
	/* hdr->dh_txid = 0 (not used) */
	hdr->dh_datalen = datalen;
	hdr->dh_door_rc = SMB_DOP_NOT_CALLED;
}

static boolean_t
smb_kdoor_chkhdr(smb_doorarg_t *da, smb_doorhdr_t *hdr)
{
	if ((hdr->dh_magic != SMB_DOOR_HDR_MAGIC) ||
	    (hdr->dh_op != da->da_hdr.dh_op) ||
	    (hdr->dh_txid != da->da_hdr.dh_txid)) {
		cmn_err(CE_WARN, "smb_kdoor_chkhdr[%s]: invalid header",
		    da->da_opname);
		return (B_FALSE);
	}

	switch (hdr->dh_door_rc) {
	case SMB_DOP_SUCCESS:
		break;

	/* SMB_DOP_EMPTYBUF is a "normal" error (silent). */
	case SMB_DOP_EMPTYBUF:
		return (B_FALSE);

	default:
		cmn_err(CE_WARN, "smb_kdoor_chkhdr[%s]: call failed: %u",
		    da->da_opname, hdr->dh_door_rc);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Free both the argument and result door buffers regardless of the status
 * of the up-call.  The doorfs allocates a new buffer if the result buffer
 * passed by the client is too small.
 */
static void
smb_kdoor_free(door_arg_t *arg)
{
	if (arg->rbuf != NULL && arg->rbuf != arg->data_ptr)
		kmem_free(arg->rbuf, arg->rsize);

	if (arg->data_ptr != NULL)
		kmem_free(arg->data_ptr, arg->data_size);
}
