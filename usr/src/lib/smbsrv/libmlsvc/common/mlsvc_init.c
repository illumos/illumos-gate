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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <rpc/xdr.h>
#include <synch.h>
#include <pthread.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <mlsvc.h>

static void *mlsvc_keepalive(void *);

static pthread_t mlsvc_keepalive_thr;
#define	MLSVC_KEEPALIVE_INTERVAL	(10 * 60)	/* 10 minutes */

/*
 * All NDR RPC service initialization is invoked from here.
 * Returns 0 upon success.  Otherwise, returns -1.
 */
int
mlsvc_init(void)
{
	pthread_attr_t tattr;
	int rc;

	if (smb_logon_init() != NT_STATUS_SUCCESS)
		return (-1);

	if ((rc = smb_dclocator_init()) != 0)
		return (rc);

	srvsvc_initialize();
	wkssvc_initialize();
	lsarpc_initialize();
	netr_initialize();
	dssetup_initialize();
	samr_initialize();
	svcctl_initialize();
	winreg_initialize();
	logr_initialize();
	msgsvcsend_initialize();
	spoolss_initialize();

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&mlsvc_keepalive_thr, &tattr,
	    mlsvc_keepalive, 0);
	(void) pthread_attr_destroy(&tattr);
	return (rc);
}

void
mlsvc_fini(void)
{
	smb_logon_fini();
}

/*ARGSUSED*/
static void *
mlsvc_keepalive(void *arg)
{
	unsigned long t;

	for (;;) {
		(void) sleep(MLSVC_KEEPALIVE_INTERVAL);

		if (smb_config_get_secmode() == SMB_SECMODE_DOMAIN)
			(void) srvsvc_gettime(&t);
	}

	/*NOTREACHED*/
	return (NULL);
}

uint64_t
mlsvc_get_num_users(void)
{
	uint32_t n_users = 0;

	(void) smb_kmod_get_usernum(&n_users);
	return ((uint64_t)n_users);
}

/*
 * The calling function must free the output parameter 'users'.
 */
int
mlsvc_get_user_list(smb_ulist_t *ulist)
{
	return (smb_kmod_get_userlist(ulist));
}

/*
 * Downcall to the kernel that is executed upon share enable and disable.
 */
int
mlsvc_set_share(int shrop, char *path, char *name)
{
	int rc;

	switch (shrop) {
	case SMB_SHROP_ADD:
		rc = smb_kmod_share(path, name);
		break;
	case SMB_SHROP_DELETE:
		rc = smb_kmod_unshare(path, name);
		break;
	default:
		rc = EINVAL;
		break;
	}
	return (rc);
}
