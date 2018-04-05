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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/errno.h>
#include <sys/tzfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <rpc/xdr.h>
#include <synch.h>
#include <pthread.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <mlsvc.h>

static void *mlsvc_timecheck(void *);

#define	MLSVC_TIMECHECK_INTERVAL	(10 * SECSPERMIN) /* 10 minutes */

/*
 * All NDR RPC service initialization is invoked from here.
 * Returns 0 upon success.  Otherwise, returns -1.
 */
int
mlsvc_init(void)
{
	pthread_t tid;
	pthread_attr_t tattr;
	int rc;

	smb_proc_initsem();

	if (smb_logon_init() != NT_STATUS_SUCCESS)
		return (-1);

	if ((rc = smb_dclocator_init()) != 0)
		return (rc);

	smb_quota_init();
	smbrdr_initialize();
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
	netdfs_initialize();

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&tid, &tattr, mlsvc_timecheck, 0);
	(void) pthread_attr_destroy(&tattr);
	return (rc);
}

void
mlsvc_fini(void)
{
	smb_logon_fini();
	spoolss_finalize();
	svcctl_finalize();
	logr_finalize();
	netdfs_finalize();
	smb_quota_fini();
}

/*ARGSUSED*/
static void *
mlsvc_timecheck(void *arg)
{
	smb_domainex_t di;

	for (;;) {
		(void) sleep(MLSVC_TIMECHECK_INTERVAL);

		if (smb_config_get_secmode() != SMB_SECMODE_DOMAIN)
			continue;

		/* Avoid interfering with DC discovery. */
		if (smb_ddiscover_wait() != 0)
			continue;

		if (!smb_domain_getinfo(&di))
			continue;

		srvsvc_timecheck(di.d_dci.dc_name,
		    di.d_primary.di_nbname);
	}

	/*NOTREACHED*/
	return (NULL);
}
