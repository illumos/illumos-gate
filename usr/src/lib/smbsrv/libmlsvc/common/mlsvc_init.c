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

#pragma ident	"@(#)mlsvc_init.c	1.5	08/07/22 SMI"

#include <unistd.h>
#include <pthread.h>
#include <smbsrv/libmlsvc.h>

void dssetup_initialize(void);
void srvsvc_initialize(void);
void wkssvc_initialize(void);
void lsarpc_initialize(void);
void logr_initialize(void);
void netr_initialize(void);
void samr_initialize(void);
void svcctl_initialize(void);
void winreg_initialize(void);
int srvsvc_gettime(unsigned long *);

static void *mlsvc_keepalive(void *);

static pthread_t mlsvc_keepalive_thr;
#define	MLSVC_KEEPALIVE_INTERVAL	(10 * 60)	/* 10 minutes */

/*
 * All mlrpc initialization is invoked from here.
 * Returns 0 upon success.  Otherwise, returns -1.
 */
int
mlsvc_init(void)
{
	pthread_attr_t tattr;
	int rc;

	srvsvc_initialize();
	wkssvc_initialize();
	lsarpc_initialize();
	netr_initialize();
	dssetup_initialize();
	samr_initialize();
	svcctl_initialize();
	winreg_initialize();
	logr_initialize();

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&mlsvc_keepalive_thr, &tattr,
	    mlsvc_keepalive, 0);
	(void) pthread_attr_destroy(&tattr);
	return (rc);
}

/*ARGSUSED*/
static void *
mlsvc_keepalive(void *arg)
{
	unsigned long t;
	nt_domain_t *domain;

	for (;;) {
		(void) sleep(MLSVC_KEEPALIVE_INTERVAL);

		if (smb_config_get_secmode() == SMB_SECMODE_DOMAIN) {
			domain = nt_domain_lookupbytype(NT_DOMAIN_PRIMARY);
			if (domain == NULL)
				(void) lsa_query_primary_domain_info();
			(void) srvsvc_gettime(&t);
		}
	}

	/*NOTREACHED*/
	return (NULL);
}
