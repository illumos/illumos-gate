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

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/cred.h>
#include <sys/disp.h>
#include <sys/ioccom.h>
#include <sys/policy.h>
#include <sys/cmn_err.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_ioctl.h>

/*
 * *****************************************************************************
 * ****************************** Global Variables *****************************
 * *****************************************************************************
 *
 * These variables can only be changed through the /etc/system file.
 */

/*
 * Maximum buffer size for NT: configurable based on the client environment.
 * IR104720 Experiments with Windows 2000 indicate that we achieve better
 * SmbWriteX performance with a buffer size of 64KB instead of the 37KB used
 * with Windows NT4.0. Previous experiments with NT4.0 resulted in directory
 * listing problems so this buffer size is configurable based on the end-user
 * environment. When in doubt use 37KB.
 *
 * smb_raw_mode: read_raw and write_raw supported (1) or NOT supported (0).
 */
int	smb_maxbufsize = SMB_NT_MAXBUF;
int	smb_oplock_levelII = 1;
int	smb_oplock_timeout = OPLOCK_STD_TIMEOUT;
int	smb_oplock_min_timeout = OPLOCK_MIN_TIMEOUT;
int	smb_flush_required = 1;
int	smb_dirsymlink_enable = 1;
int	smb_sign_debug = 0;
int	smb_raw_mode = 0;
int	smb_shortnames = 1;
uint_t	smb_audit_flags =
#ifdef	DEBUG
    SMB_AUDIT_NODE;
#else
    0;
#endif

/*
 * Maximum number of simultaneous authentication, share mapping, pipe open
 * requests to be processed.
 */
int	smb_ssetup_threshold = 256;
int	smb_tcon_threshold = 1024;
int	smb_opipe_threshold = 1024;

/*
 * Number of milliseconds that a request will be stalled if it comes in after
 * the maximum number of inflight operations are being proccessed.
 */
int	smb_ssetup_timeout = (30 * 1000);
int	smb_tcon_timeout = (30 * 1000);
int	smb_opipe_timeout = (30 * 1000);

int	smb_threshold_debug = 0;

/*
 * Thread priorities used in smbsrv.  Our threads spend most of their time
 * blocked on various conditions.  However, if the system gets heavy load,
 * the scheduler has to choose an order to run these.  We want the order:
 * (a) timers, (b) notifications, (c) workers, (d) receivers (and etc.)
 * where notifications are oplock and change notify work.  Aside from this
 * relative ordering, smbsrv threads should run with a priority close to
 * that of normal user-space threads (thus minclsyspri below), just like
 * NFS and other "file service" kinds of processing.
 */
int smbsrv_base_pri	= MINCLSYSPRI;
int smbsrv_listen_pri	= MINCLSYSPRI;
int smbsrv_receive_pri	= MINCLSYSPRI;
int smbsrv_worker_pri	= MINCLSYSPRI + 1;
int smbsrv_notify_pri	= MINCLSYSPRI + 2;
int smbsrv_timer_pri	= MINCLSYSPRI + 5;

/*
 * These are the (open,close,ioctl) entry points into this
 * (fake) "driver".  They are declared in smb_ioctl.h
 */

static int g_init_done = 0;

int fksmbsrv_vfs_init(void);

int
fksmbsrv_drv_open(void)
{
	int rc;

	if (g_init_done == 0) {
		if ((rc = fksmbsrv_vfs_init()) != 0) {
			cmn_err(CE_WARN, "fksmbsrv_vfs_init, rc=%d", rc);
			return (rc);
		}
		if ((rc = smb_server_g_init()) != 0) {
			cmn_err(CE_WARN, "smb_server_g_init, rc=%d", rc);
			return (rc);
		}
		g_init_done = 1;
	}

	rc = smb_server_create();
	return (rc);
}

int
fksmbsrv_drv_close(void)
{
	int rc;

	rc = smb_server_delete();

	if (g_init_done != 0) {
		smb_server_g_fini();
		g_init_done = 0;
	}

	return (rc);
}

/*
 * This is the primary entry point into this library, called by
 * fksmbd (user-level debug version of smbsrv).
 */
int
fksmbsrv_drv_ioctl(int cmd, void *varg)
{
	smb_ioc_t	*ioc = varg;
	int		rc = 0;

	switch (cmd) {
	case SMB_IOC_CONFIG:
		rc = smb_server_configure(&ioc->ioc_cfg);
		break;
	case SMB_IOC_START:
		rc = smb_server_start(&ioc->ioc_start);
		break;
	case SMB_IOC_STOP:
		rc = smb_server_stop();
		break;
	case SMB_IOC_EVENT:
		rc = smb_server_notify_event(&ioc->ioc_event);
		break;
	case SMB_IOC_GMTOFF:
		rc = smb_server_set_gmtoff(&ioc->ioc_gmt);
		break;
	case SMB_IOC_SHARE:
		rc = smb_kshare_export_list(&ioc->ioc_share);
		break;
	case SMB_IOC_UNSHARE:
		rc = smb_kshare_unexport_list(&ioc->ioc_share);
		break;
	case SMB_IOC_SHAREINFO:
		rc = smb_kshare_info(&ioc->ioc_shareinfo);
		break;
	case SMB_IOC_NUMOPEN:
		rc = smb_server_numopen(&ioc->ioc_opennum);
		break;
	case SMB_IOC_SVCENUM:
		rc = smb_server_enum(&ioc->ioc_svcenum);
		break;
	case SMB_IOC_SESSION_CLOSE:
		rc = smb_server_session_close(&ioc->ioc_session);
		break;
	case SMB_IOC_FILE_CLOSE:
		rc = smb_server_file_close(&ioc->ioc_fileid);
		break;
	case SMB_IOC_SPOOLDOC:
		rc = smb_server_spooldoc(&ioc->ioc_spooldoc);
		break;
	default:
		rc = ENOTTY;
		break;
	}

	return (rc);
}

/*
 * This function intentionally does nothing.  It's used only to
 * force libfksmbsrv to load when fksmbd starts so one can set
 * breakpoints etc. without debugger "force load" tricks.
 */
void
fksmbsrv_drv_load(void)
{
}
