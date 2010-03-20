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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/door.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_door.h>

static int smb_kdoor_send(smb_doorarg_t *);
static int smb_kdoor_receive(smb_doorarg_t *);
static int smb_kdoor_upcall_private(smb_doorarg_t *);
static int smb_kdoor_encode(smb_doorarg_t *);
static int smb_kdoor_decode(smb_doorarg_t *);
static void smb_kdoor_sethdr(smb_doorarg_t *, uint32_t);
static boolean_t smb_kdoor_chkhdr(smb_doorarg_t *, smb_doorhdr_t *);
static void smb_kdoor_free(door_arg_t *);

door_handle_t smb_kdoor_hd = NULL;
static int smb_kdoor_id = -1;
static uint64_t smb_kdoor_ncall = 0;
static kmutex_t smb_kdoor_mutex;
static kcondvar_t smb_kdoor_cv;

void
smb_kdoor_init(void)
{
	mutex_init(&smb_kdoor_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&smb_kdoor_cv, NULL, CV_DEFAULT, NULL);
}

void
smb_kdoor_fini(void)
{
	smb_kdoor_close();
	cv_destroy(&smb_kdoor_cv);
	mutex_destroy(&smb_kdoor_mutex);
}

/*
 * Open the door.  If the door is already open, close it first
 * because the door-id has probably changed.
 */
int
smb_kdoor_open(int door_id)
{
	int rc;

	smb_kdoor_close();

	mutex_enter(&smb_kdoor_mutex);
	smb_kdoor_ncall = 0;

	if (smb_kdoor_hd == NULL) {
		smb_kdoor_id = door_id;
		smb_kdoor_hd = door_ki_lookup(door_id);
	}

	rc = (smb_kdoor_hd == NULL)  ? -1 : 0;
	mutex_exit(&smb_kdoor_mutex);
	return (rc);
}

/*
 * Close the door.
 */
void
smb_kdoor_close(void)
{
	mutex_enter(&smb_kdoor_mutex);

	if (smb_kdoor_hd != NULL) {
		while (smb_kdoor_ncall > 0)
			cv_wait(&smb_kdoor_cv, &smb_kdoor_mutex);

		door_ki_rele(smb_kdoor_hd);
		smb_kdoor_hd = NULL;
	}

	mutex_exit(&smb_kdoor_mutex);
}

/*
 * Wrapper to handle door call reference counting.
 */
int
smb_kdoor_upcall(uint32_t cmd, void *req_data, xdrproc_t req_xdr,
    void *rsp_data, xdrproc_t rsp_xdr)
{
	smb_doorarg_t	da;
	int		rc;

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

	if (rsp_data != NULL && rsp_xdr != NULL)
		da.da_flags = SMB_DF_ASYNC;

	if ((da.da_event = smb_event_create()) == NULL)
		return (-1);

	mutex_enter(&smb_kdoor_mutex);

	if (smb_kdoor_hd == NULL) {
		mutex_exit(&smb_kdoor_mutex);

		if (smb_kdoor_open(smb_kdoor_id) != 0) {
			smb_event_destroy(da.da_event);
			return (-1);
		}

		mutex_enter(&smb_kdoor_mutex);
	}

	++smb_kdoor_ncall;
	mutex_exit(&smb_kdoor_mutex);

	if (da.da_flags & SMB_DF_ASYNC) {
		if ((rc = smb_kdoor_send(&da)) == 0) {
			if (smb_event_wait(da.da_event) != 0)
				rc = -1;
			else
				rc = smb_kdoor_receive(&da);
		}
	} else {
		if ((rc = smb_kdoor_encode(&da)) == 0) {
			if ((rc = smb_kdoor_upcall_private(&da)) == 0)
				rc = smb_kdoor_decode(&da);
		}
		smb_kdoor_free(&da.da_arg);
	}

	smb_event_destroy(da.da_event);

	mutex_enter(&smb_kdoor_mutex);
	if ((--smb_kdoor_ncall) == 0)
		cv_signal(&smb_kdoor_cv);
	mutex_exit(&smb_kdoor_mutex);
	return (rc);
}

/*
 * Send the request half of the consumer's door call.
 */
static int
smb_kdoor_send(smb_doorarg_t *outer_da)
{
	smb_doorarg_t	da;
	int		rc;

	bcopy(outer_da, &da, sizeof (smb_doorarg_t));
	da.da_rsp_xdr = NULL;
	da.da_rsp_data = NULL;

	if (smb_kdoor_encode(&da) != 0)
		return (-1);

	if ((rc = smb_kdoor_upcall_private(&da)) == 0)
		rc = smb_kdoor_decode(&da);

	smb_kdoor_free(&da.da_arg);
	return (rc);
}

/*
 * Get the response half for the consumer's door call.
 */
static int
smb_kdoor_receive(smb_doorarg_t *outer_da)
{
	smb_doorarg_t	da;
	int		rc;

	bcopy(outer_da, &da, sizeof (smb_doorarg_t));
	da.da_opcode = SMB_DR_ASYNC_RESPONSE;
	da.da_opname = smb_doorhdr_opname(da.da_opcode);
	da.da_flags &= ~SMB_DF_ASYNC;
	da.da_req_xdr = NULL;
	da.da_req_data = NULL;

	if (smb_kdoor_encode(&da) != 0)
		return (-1);

	if ((rc = smb_kdoor_upcall_private(&da)) == 0)
		rc = smb_kdoor_decode(&da);

	smb_kdoor_free(&da.da_arg);
	return (rc);
}

/*
 * We use a copy of the door arg because doorfs may change data_ptr
 * and we want to detect that when freeing the door buffers.  After
 * this call, response data must be referenced via rbuf and rsize.
 */
static int
smb_kdoor_upcall_private(smb_doorarg_t *da)
{
	door_arg_t	door_arg;
	int		i;
	int		rc;

	bcopy(&da->da_arg, &door_arg, sizeof (door_arg_t));

	for (i = 0; i < SMB_DOOR_CALL_RETRIES; ++i) {
		if (smb_server_is_stopping())
			return (-1);

		if ((rc = door_ki_upcall_limited(smb_kdoor_hd, &door_arg,
		    NULL, SIZE_MAX, 0)) == 0)
			break;

		if (rc != EAGAIN && rc != EINTR)
			return (-1);
	}

	if (rc != 0 || door_arg.data_size == 0 || door_arg.rsize == 0)
		return (-1);

	da->da_arg.rbuf = door_arg.data_ptr;
	da->da_arg.rsize = door_arg.rsize;
	return (0);
}

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
	hdr->dh_flags = da->da_flags | SMB_DF_SYSSPACE;
	hdr->dh_op = da->da_opcode;
	hdr->dh_txid = smb_event_txid(da->da_event);
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

	if (hdr->dh_door_rc != SMB_DOP_SUCCESS) {
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
