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
 * Door fd for downcalls to the smbsrv kernel door service.
 * smbsrv will make an upcall to smbd during initialization to
 * provide this file descriptor.
 */
static int mlsvc_door_fd = -1;
static mutex_t mlsvc_fd_mutex;

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

void
mlsvc_set_door_fd(int fd)
{
	(void) mutex_lock(&mlsvc_fd_mutex);
	mlsvc_door_fd = fd;
	(void) mutex_unlock(&mlsvc_fd_mutex);
}

int
mlsvc_get_door_fd(void)
{
	int fd;

	(void) mutex_lock(&mlsvc_fd_mutex);
	fd = mlsvc_door_fd;
	(void) mutex_unlock(&mlsvc_fd_mutex);

	return (fd);
}

uint64_t
mlsvc_get_num_users(void)
{
	door_arg_t arg;
	char *buf;
	size_t len;
	int64_t n_users = 0;
	int fd;

	if ((fd = mlsvc_get_door_fd()) < 0)
		return (0);

	if ((buf = smb_dr_set_opcode(SMB_KDR_USER_NUM, &len)) == NULL)
		return (0);

	smb_dr_clnt_setup(&arg, buf, len);

	if (smb_dr_clnt_call(fd, &arg) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;

		if (smb_dr_decode_common(buf, len, xdr_uint32_t, &n_users) != 0)
			n_users = 0;
	}

	smb_dr_clnt_cleanup(&arg);
	return (n_users);
}

/*
 * The calling function must free the output parameter 'users'.
 */
int
mlsvc_get_user_list(int offset, smb_dr_ulist_t *users)
{
	door_arg_t arg;
	char *buf;
	size_t len;
	uint_t opcode = SMB_KDR_USER_LIST;
	int fd, rc = -1;

	bzero(users, sizeof (smb_dr_ulist_t));

	if ((fd = mlsvc_get_door_fd()) < 0)
		return (-1);

	buf = smb_dr_encode_common(opcode, &offset, xdr_uint32_t, &len);
	if (buf == NULL)
		return (-1);

	smb_dr_clnt_setup(&arg, buf, len);

	if (smb_dr_clnt_call(fd, &arg) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;

		rc = smb_dr_decode_common(buf, len, xdr_smb_dr_ulist_t, users);
		if (rc == 0)
			rc = users->dul_cnt;
	}

	smb_dr_clnt_cleanup(&arg);
	return (rc);
}

/*
 * Downcall to the kernel that is executed upon share enable and disable.
 */
int
mlsvc_set_share(int shrop, char *path, char *sharename)
{
	door_arg_t arg;
	char *buf;
	size_t len;
	smb_dr_kshare_t kshare;
	int fd, rc = 0;

	if ((shrop != SMB_SHROP_ADD) && (shrop != SMB_SHROP_DELETE))
		return (EINVAL);

	if ((fd = mlsvc_get_door_fd()) < 0)
		return (EBADF);

	kshare.k_op = shrop;
	kshare.k_path = strdup(path);
	kshare.k_sharename = strdup(sharename);

	buf = smb_dr_encode_kshare(&kshare, &len);
	free(kshare.k_path);
	free(kshare.k_sharename);

	if (buf == NULL)
		return (ENOMEM);

	smb_dr_clnt_setup(&arg, buf, len);

	if (smb_dr_clnt_call(fd, &arg) == 0) {
		buf = arg.rbuf + SMB_DR_DATA_OFFSET;
		len = arg.rsize - SMB_DR_DATA_OFFSET;

		if (smb_dr_decode_common(buf, len, xdr_int32_t, &rc) != 0)
			rc = ENOMEM;
	}

	smb_dr_clnt_cleanup(&arg);
	return (rc);
}
