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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/door.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>

#define	SMB_KDOOR_RETRIES	3

static char *smb_kdoor_upcall(char *, size_t, door_desc_t *, uint_t, size_t *);

door_handle_t smb_kdoor_clnt_hd = NULL;
static int smb_kdoor_clnt_id = -1;
static uint64_t smb_kdoor_clnt_ncall = 0;
static kmutex_t smb_kdoor_clnt_mutex;
static kcondvar_t smb_kdoor_clnt_cv;

void
smb_kdoor_clnt_init(void)
{
	mutex_init(&smb_kdoor_clnt_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&smb_kdoor_clnt_cv, NULL, CV_DEFAULT, NULL);
}

void
smb_kdoor_clnt_fini(void)
{
	smb_kdoor_clnt_close();
	cv_destroy(&smb_kdoor_clnt_cv);
	mutex_destroy(&smb_kdoor_clnt_mutex);
}

/*
 * Open the door.  If the door is already open, close it first
 * because the door-id has probably changed.
 */
int
smb_kdoor_clnt_open(int door_id)
{
	int rc;

	smb_kdoor_clnt_close();

	mutex_enter(&smb_kdoor_clnt_mutex);
	smb_kdoor_clnt_ncall = 0;

	if (smb_kdoor_clnt_hd == NULL) {
		smb_kdoor_clnt_id = door_id;
		smb_kdoor_clnt_hd = door_ki_lookup(door_id);
	}

	rc = (smb_kdoor_clnt_hd == NULL)  ? -1 : 0;
	mutex_exit(&smb_kdoor_clnt_mutex);
	return (rc);
}

/*
 * Close the door.
 */
void
smb_kdoor_clnt_close(void)
{
	mutex_enter(&smb_kdoor_clnt_mutex);

	if (smb_kdoor_clnt_hd != NULL) {
		while (smb_kdoor_clnt_ncall > 0)
			cv_wait(&smb_kdoor_clnt_cv, &smb_kdoor_clnt_mutex);

		door_ki_rele(smb_kdoor_clnt_hd);
		smb_kdoor_clnt_hd = NULL;
	}

	mutex_exit(&smb_kdoor_clnt_mutex);
}

/*
 * smb_kdoor_clnt_upcall
 *
 * Wrapper to handle door call reference counting.
 */
char *
smb_kdoor_clnt_upcall(char *argp, size_t arg_size, door_desc_t *dp,
    uint_t desc_num, size_t *rbufsize)
{
	char *rbufp;

	if (argp == NULL)
		return (NULL);

	mutex_enter(&smb_kdoor_clnt_mutex);

	if (smb_kdoor_clnt_hd == NULL) {
		mutex_exit(&smb_kdoor_clnt_mutex);

		if (smb_kdoor_clnt_open(smb_kdoor_clnt_id) != 0)
			return (NULL);

		mutex_enter(&smb_kdoor_clnt_mutex);
	}

	++smb_kdoor_clnt_ncall;
	mutex_exit(&smb_kdoor_clnt_mutex);

	rbufp = smb_kdoor_upcall(argp, arg_size, dp, desc_num, rbufsize);

	mutex_enter(&smb_kdoor_clnt_mutex);
	--smb_kdoor_clnt_ncall;
	cv_signal(&smb_kdoor_clnt_cv);
	mutex_exit(&smb_kdoor_clnt_mutex);
	return (rbufp);
}

/*
 * On success, the result buffer is returned, with rbufsize set to the
 * size of the result buffer.  Otherwise, a NULL pointer is returned.
 */
static char *
smb_kdoor_upcall(char *argp, size_t arg_size, door_desc_t *dp,
    uint_t desc_num, size_t *rbufsize)
{
	door_arg_t door_arg;
	int i;
	int rc;

	door_arg.data_ptr = argp;
	door_arg.data_size = arg_size;
	door_arg.desc_ptr = dp;
	door_arg.desc_num = desc_num;
	door_arg.rbuf = argp;
	door_arg.rsize = arg_size;

	for (i = 0; i < SMB_KDOOR_RETRIES; ++i) {
		if ((rc = door_ki_upcall_limited(smb_kdoor_clnt_hd, &door_arg,
		    NULL, SIZE_MAX, 0)) == 0)
			break;

		if (rc != EAGAIN && rc != EINTR)
			return (NULL);
	}

	if (rc != 0)
		return (NULL);

	rc = smb_dr_get_res_stat(door_arg.data_ptr, door_arg.rsize);
	if (rc != SMB_DR_OP_SUCCESS)
		return (NULL);

	*rbufsize = door_arg.rsize;
	return (door_arg.data_ptr);
}

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
	if (argp)
		kmem_free(argp, arg_size);

	if (rbufp && rbufp != argp)
		kmem_free(rbufp, rbuf_size);
}
