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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Kernel door service
 * It has dependency on the kernel door client interface because the downcall
 * descriptor is required to be passed up to SMB daemon via door up-call.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/door.h>
#include <sys/kmem.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>

door_handle_t smb_kdoor_hdl = NULL;

/*
 * Since the action performed by smb_kdoor_srv_callback might vary
 * according to request type/opcode, the smb_kdoor_cookie will
 * be set to the request type in the server procedure
 * (i.e. smb_kdoor_svc). It will then be passed to the callback
 * function when the kernel is done with the copyout operation.
 */
int smb_kdoor_cookie = -1;

extern smb_kdr_op_t smb_kdoorsrv_optab[];

/* forward declaration */
void smb_kdoor_svc(void *data, door_arg_t *dap, void (**destfnp)(void *,
    void *), void **destarg, int *error);

/*
 * smb_kdoor_srv_start
 *
 * When driver is opened, this function should be called to create the
 * kernel door. The door descriptor will then be passed up to the
 * user-space SMB daemon.
 *
 * Returns 0 upon success otherwise non-zero
 */
int
smb_kdoor_srv_start()
{
	door_desc_t smb_kdoor_desc;
	int err;
	int res;
	int opcode = SMB_DR_SET_DWNCALL_DESC;

	if ((err = door_ki_create(smb_kdoor_svc,
	    &smb_kdoor_cookie, 0, &smb_kdoor_hdl)) != 0) {
		cmn_err(CE_WARN, "SmbKdoorInit: door_create"
		    " failed(%d)", err);
		return (err);
	}

	smb_kdoor_desc.d_attributes = DOOR_HANDLE;
	smb_kdoor_desc.d_data.d_handle = smb_kdoor_hdl;

	res = smb_upcall_set_dwncall_desc(opcode, &smb_kdoor_desc, 1);
	if (res != SMB_DR_OP_SUCCESS) {
		cmn_err(CE_WARN, "SmbKdoorInit: smbd failed to set the"
		    " downcall descriptor res=%d", res);
		smb_kdoor_srv_stop();
		return (EIO);
	}

	return (0);
}

/*
 * smb_kdoor_srv_stop
 *
 * This function will stop the kernel door service when the driver is closed.
 */
void
smb_kdoor_srv_stop()
{
	if (smb_kdoor_hdl) {
		door_ki_rele(smb_kdoor_hdl);
		smb_kdoor_hdl = NULL;
	}
}

/*
 * smb_kdoor_srv_callback
 *
 * This callback function will be executed by the kernel after copyout()
 * completes. Currently, this function only free the server buffer that
 * was previously allocated in the smb_kdoor_srv(). It can be enhanced
 * to perform any action based on the opcode if there is a need in the
 * future.
 */
static void
smb_kdoor_srv_callback(void *cookie, void *arg)
{
	/*LINTED E_FUNC_VAR_UNUSED*/
	int *opcode;
	smb_kdoor_cb_arg_t *cbarg;

	if (cookie)
		opcode = (int *)cookie;

	if (!arg)
		return;

	cbarg = (smb_kdoor_cb_arg_t *)arg;
	if (cbarg->rbuf)
		kmem_free(cbarg->rbuf, cbarg->rbuf_size);

	kmem_free(cbarg, sizeof (smb_kdoor_cb_arg_t));
}


void
smb_kdoor_svc(void *cookie, door_arg_t *dap, void (**destfnp)(void *,
    void *), void **destarg, int *error)
{
	int opcode;
	smb_kdoor_cb_arg_t *cbarg;
	size_t arg_size;
	char *argp = NULL;
	smb_kdr_op_t smbop;

	/*
	 * Be aware that *destfnp cannot be NULL even if there isn't
	 * any additional work after the kernel completes copyout() operation.
	 */
	*destfnp = smb_kdoor_srv_callback;
	*destarg = NULL;
	*error = 0;

	if (!dap) {
		cmn_err(CE_WARN, "SmbKdoorSvc: invalid arguments");
		*error = EINVAL;
		return;
	}

	arg_size = dap->data_size;
	argp = kmem_alloc(arg_size, KM_SLEEP);
	/* The data_ptr points to user data */
	(void) copyin(dap->data_ptr, argp, dap->data_size);
	/* initialize the returned data size to be 0 */
	dap->data_size = 0;

	opcode = smb_dr_get_opcode(argp, arg_size);
	*((int *)cookie) = opcode;

	if (smb_kdr_is_valid_opcode(opcode) != 0) {
		cmn_err(CE_WARN, "SmbKdoorSvc: invalid opcode(%d)", opcode);
		*error = EINVAL;
		kmem_free(argp, arg_size);
		return;

	}

	smbop = smb_kdoorsrv_optab[opcode];
	cbarg = kmem_alloc(sizeof (smb_kdoor_cb_arg_t), KM_SLEEP);
	if ((cbarg->rbuf = smbop(argp + sizeof (opcode),
	    arg_size - sizeof (opcode), &cbarg->rbuf_size, error)) == NULL) {
		cmn_err(CE_WARN, "SmbKdoorSvc: door op failed");

		switch (*error) {
		case SMB_DR_OP_ERR_ENCODE:
			*error = EINVAL;
			cmn_err(CE_WARN, "SmbKdoorSvc: encode error");
			break;
		case SMB_DR_OP_ERR_DECODE:
			*error = EINVAL;
			cmn_err(CE_WARN, "SmbKdoorSvc: decode error");
			break;
		case SMB_DR_OP_ERR_EMPTYBUF:
			if ((cbarg->rbuf = smb_dr_set_res_stat(
			    SMB_DR_OP_ERR_EMPTYBUF, &cbarg->rbuf_size))
			    == NULL) {
				cmn_err(CE_WARN, "SmbKdoorSvc: return nothing");
				*error = EINVAL;
			}
			*error = 0;
			break;
		default:
			cmn_err(CE_WARN, "SmbKdoorSvc: unknown error");
		}
	}

	kmem_free(argp, arg_size);
	dap->data_size = cbarg->rbuf_size;
	dap->rbuf = cbarg->rbuf;
	*destarg = cbarg;
}
