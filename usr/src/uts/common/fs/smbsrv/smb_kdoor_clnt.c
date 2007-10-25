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

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/door.h>
#include <smbsrv/alloc.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>

door_handle_t smb_kdoor_clnt_dh;

/*
 * smb_kdoor_clnt_free
 *
 * This function should be invoked to free both the argument/result door buffer
 * regardless of the status of the up-call.
 *
 * The doorfs allocates a new buffer if the result buffer passed by the client
 * is too small. This function will deallocate that buffer as well.
 */
void
smb_kdoor_clnt_free(char *argp, size_t arg_size, char *rbufp, size_t rbuf_size)
{
	if (argp) {
		if (argp == rbufp) {
			kmem_free(argp, arg_size);
		} else if (rbufp) {
			kmem_free(argp, arg_size);
			kmem_free(rbufp, rbuf_size);
		}
	} else {
		if (rbufp)
			kmem_free(rbufp, rbuf_size);
	}
}

/*
 * smb_kdoor_clnt_start
 *
 * The SMB kernel module should invoke this function upon startup.
 */
int
smb_kdoor_clnt_start()
{
	int rc = 0;

	rc = door_ki_open(SMB_DR_SVC_NAME, &smb_kdoor_clnt_dh);

	return (rc);
}

/*
 * smb_kdoor_clnt_stop
 *
 * The SMB kernel module should invoke this function upon unload.
 */
void
smb_kdoor_clnt_stop()
{
	door_ki_rele(smb_kdoor_clnt_dh);
}

/*
 * smb_kdoor_clnt_upcall
 *
 * This function will make a door up-call to the server function
 * associated with the door descriptor fp. The specified door
 * request buffer (i.e. argp) will be passed as the argument to the
 * door_ki_upcall(). Upon success, the result buffer is returned. Otherwise,
 * NULL pointer is returned. The size of the result buffer is returned
 * via rbufsize.
 */
char *
smb_kdoor_clnt_upcall(char *argp, size_t arg_size, door_desc_t *dp,
    uint_t desc_num, size_t *rbufsize)
{
	door_arg_t door_arg;
	int err;

	if (!argp) {
		cmn_err(CE_WARN, "smb_kdoor_clnt_upcall: invalid parameter");
		return (NULL);
	}

	door_arg.data_ptr = argp;
	door_arg.data_size = arg_size;
	door_arg.desc_ptr = dp;
	door_arg.desc_num = desc_num;
	door_arg.rbuf = argp;
	door_arg.rsize = arg_size;

	if ((err = door_ki_upcall(smb_kdoor_clnt_dh, &door_arg)) != 0) {
		cmn_err(CE_WARN, "smb_kdoor_clnt_upcall: failed(%d)", err);
		kmem_free(argp, arg_size);
		argp = NULL;
		return (NULL);
	}

	if (smb_dr_get_res_stat(door_arg.data_ptr, door_arg.rsize) !=
	    SMB_DR_OP_SUCCESS) {
		smb_kdoor_clnt_free(argp, arg_size, door_arg.rbuf,
		    door_arg.rsize);
		*rbufsize = 0;
		return (NULL);
	}
	*rbufsize = door_arg.rsize;
	return (door_arg.data_ptr);

}
