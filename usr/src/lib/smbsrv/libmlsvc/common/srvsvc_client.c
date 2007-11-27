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
 * Server Service (srvsvc) client side RPC library interface. The
 * srvsvc interface allows a client to query a server for information
 * on shares, sessions, connections and files on the server. Some
 * functions are available via anonymous IPC while others require
 * administrator privilege. Also, some functions return NT status
 * values while others return Win32 errors codes.
 */

#include <sys/errno.h>
#include <stdio.h>
#include <time.h>
#include <strings.h>
#include <time.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/ndl/srvsvc.ndl>
#include <smbsrv/mlsvc_util.h>

/*
 * Information level for NetShareGetInfo.
 */
DWORD srvsvc_info_level = 1;

static int srvsvc_net_remote_tod(char *, char *, struct timeval *, struct tm *);

/*
 * Ensure that an appropriate session and logon exists for the srvsvc
 * client calls. Open and bind the RPC interface.
 *
 * If username argument is NULL, an anonymous connection will be established.
 * Otherwise, an authenticated connection will be established.
 *
 * On success 0 is returned. Otherwise a -ve error code.
 */
static int
srvsvc_open(char *server, char *domain, char *username,
    mlsvc_handle_t *handle, mlrpc_heapref_t *heapref)
{
	smb_ntdomain_t *di;
	int fid;
	int rc;

	if (server == NULL || domain == NULL) {
		if ((di = smb_getdomaininfo(0)) == NULL)
			return (-1);

		server = di->server;
		domain = di->domain;
	}

	if (username == NULL)
		username = MLSVC_ANON_USER;

	rc = mlsvc_logon(server, domain, username);

	if (rc != 0)
		return (-1);

	fid = mlsvc_open_pipe(server, domain, username, "\\srvsvc");
	if (fid < 0)
		return (-1);

	if ((rc = mlsvc_rpc_bind(handle, fid, "SRVSVC")) < 0) {
		(void) mlsvc_close_pipe(fid);
		return (rc);
	}

	rc = mlsvc_rpc_init(heapref);
	return (rc);
}

/*
 * Close the srvsvc pipe and free the associated context. This function
 * should only be called if the open was successful.
 */
void
srvsvc_close(mlsvc_handle_t *handle, mlrpc_heapref_t *heapref)
{
	mlsvc_rpc_free(handle->context, heapref);
	(void) mlsvc_close_pipe(handle->context->fid);
	free(handle->context);
}

/*
 * This is a client side routine for NetShareGetInfo.
 * Levels 0 and 1 work with an anonymous connection but
 * level 2 requires administrator access.
 */
int
srvsvc_net_share_get_info(char *server, char *domain, char *netname)
{
	struct mlsm_NetShareGetInfo arg;
	mlsvc_handle_t handle;
	mlrpc_heapref_t heap;
	int rc;
	int opnum;
	struct mslm_NetShareGetInfo0 *info0;
	struct mslm_NetShareGetInfo1 *info1;
	struct mslm_NetShareGetInfo2 *info2;
	int len;
	char *user = NULL;

	if (netname == NULL)
		return (-1);

	if (srvsvc_info_level == 2)
		user = smbrdr_ipc_get_user();

	rc = srvsvc_open(server, domain, user, &handle, &heap);
	if (rc != 0)
		return (-1);

	opnum = SRVSVC_OPNUM_NetShareGetInfo;
	bzero(&arg, sizeof (struct mlsm_NetShareGetInfo));

	len = strlen(server) + 4;
	arg.servername = mlrpc_heap_malloc(heap.heap, len);
	if (arg.servername == NULL) {
		srvsvc_close(&handle, &heap);
		return (-1);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.netname = (LPTSTR)netname;
	arg.level = srvsvc_info_level; /* share information level */

	rc = mlsvc_rpc_call(handle.context, opnum, &arg, &heap);
	if ((rc != 0) || (arg.status != 0)) {
		srvsvc_close(&handle, &heap);
		return (-1);
	}

	switch (arg.result.switch_value) {
	case 0:
		info0 = arg.result.ru.info0;
		smb_tracef("srvsvc shi0_netname=%s", info0->shi0_netname);
		break;

	case 1:
		info1 = arg.result.ru.info1;
		smb_tracef("srvsvc shi1_netname=%s", info1->shi1_netname);
		smb_tracef("srvsvc shi1_type=%u", info1->shi1_type);

		if (info1->shi1_comment)
			smb_tracef("srvsvc shi1_comment=%s",
			    info1->shi1_comment);
		break;

	case 2:
		info2 = arg.result.ru.info2;
		smb_tracef("srvsvc shi2_netname=%s", info2->shi2_netname);
		smb_tracef("srvsvc shi2_type=%u", info2->shi2_type);

		if (info2->shi2_comment)
			smb_tracef("srvsvc shi2_comment=%s",
			    info2->shi2_comment);

		smb_tracef("srvsvc shi2_perms=%d", info2->shi2_permissions);
		smb_tracef("srvsvc shi2_max_use=%d", info2->shi2_max_uses);
		smb_tracef("srvsvc shi2_cur_use=%d", info2->shi2_current_uses);

		if (info2->shi2_path)
			smb_tracef("srvsvc shi2_path=%s", info2->shi2_path);

		if (info2->shi2_passwd)
			smb_tracef("srvsvc shi2_passwd=%s", info2->shi2_passwd);
		break;

	default:
		smb_tracef("srvsvc: unknown level");
		break;
	}

	srvsvc_close(&handle, &heap);
	return (0);
}

/*
 * This is a client side routine for NetSessionEnum.
 * NetSessionEnum requires administrator rights.
 */
int
srvsvc_net_session_enum(char *server, char *domain, char *netname)
{
	struct mslm_NetSessionEnum arg;
	mlsvc_handle_t handle;
	mlrpc_heapref_t heap;
	int rc;
	int opnum;
	struct mslm_infonres infonres;
	struct mslm_SESSION_INFO_1 *nsi1;
	int len;
	char *user = smbrdr_ipc_get_user();

	if (netname == NULL)
		return (-1);

	rc = srvsvc_open(server, domain, user, &handle, &heap);
	if (rc != 0)
		return (-1);

	opnum = SRVSVC_OPNUM_NetSessionEnum;
	bzero(&arg, sizeof (struct mslm_NetSessionEnum));

	len = strlen(server) + 4;
	arg.servername = mlrpc_heap_malloc(heap.heap, len);
	if (arg.servername == NULL) {
		srvsvc_close(&handle, &heap);
		return (-1);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	infonres.entriesread = 0;
	infonres.entries = 0;
	arg.level = 1;
	arg.result.level = 1;
	arg.result.bufptr.p = &infonres;
	arg.resume_handle = 0;
	arg.pref_max_len = 0xFFFFFFFF;

	rc = mlsvc_rpc_call(handle.context, opnum, &arg, &heap);
	if ((rc != 0) || (arg.status != 0)) {
		srvsvc_close(&handle, &heap);
		return (-1);
	}

	/* Only the first session info is dereferenced. */
	nsi1 = ((struct mslm_infonres *)arg.result.bufptr.p)->entries;

	smb_tracef("srvsvc switch_value=%d", arg.level);
	smb_tracef("srvsvc sesi1_cname=%s", nsi1->sesi1_cname);
	smb_tracef("srvsvc sesi1_uname=%s", nsi1->sesi1_uname);
	smb_tracef("srvsvc sesi1_nopens=%u", nsi1->sesi1_nopens);
	smb_tracef("srvsvc sesi1_time=%u", nsi1->sesi1_time);
	smb_tracef("srvsvc sesi1_itime=%u", nsi1->sesi1_itime);
	smb_tracef("srvsvc sesi1_uflags=%u", nsi1->sesi1_uflags);

	srvsvc_close(&handle, &heap);
	return (0);
}

/*
 * This is a client side routine for NetConnectEnum.
 * NetConnectEnum requires administrator rights.
 * Level 0 and level 1 requests are supported.
 */
int
srvsvc_net_connect_enum(char *server, char *domain, char *netname, int level)
{
	struct mslm_NetConnectEnum arg;
	mlsvc_handle_t handle;
	mlrpc_heapref_t heap;
	int rc;
	int opnum;
	struct mslm_NetConnectInfo1 info1;
	struct mslm_NetConnectInfo0 info0;
	struct mslm_NetConnectInfoBuf1 *cib1;
	int len;
	char *user = smbrdr_ipc_get_user();

	if (netname == NULL)
		return (-1);

	rc = srvsvc_open(server, domain, user, &handle, &heap);
	if (rc != 0)
		return (-1);

	opnum = SRVSVC_OPNUM_NetConnectEnum;
	bzero(&arg, sizeof (struct mslm_NetConnectEnum));

	len = strlen(server) + 4;
	arg.servername = mlrpc_heap_malloc(heap.heap, len);
	if (arg.servername == NULL) {
		srvsvc_close(&handle, &heap);
		return (-1);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.qualifier = (LPTSTR)netname;

	switch (level) {
	case 0:
		arg.info.level = 0;
		arg.info.switch_value = 0;
		arg.info.ru.info0 = &info0;
		info0.entries_read = 0;
		info0.ci0 = 0;
		break;
	case 1:
		arg.info.level = 1;
		arg.info.switch_value = 1;
		arg.info.ru.info1 = &info1;
		info1.entries_read = 0;
		info1.ci1 = 0;
		break;
	default:
		srvsvc_close(&handle, &heap);
		return (-1);
	}

	arg.resume_handle = 0;
	arg.pref_max_len = 0xFFFFFFFF;

	rc = mlsvc_rpc_call(handle.context, opnum, &arg, &heap);
	if ((rc != 0) || (arg.status != 0)) {
		srvsvc_close(&handle, &heap);
		return (-1);
	}

	smb_tracef("srvsvc switch_value=%d", arg.info.switch_value);

	switch (level) {
	case 0:
		if (arg.info.ru.info0 && arg.info.ru.info0->ci0) {
			smb_tracef("srvsvc coni0_id=%x",
			    arg.info.ru.info0->ci0->coni0_id);
		}
		break;
	case 1:
		if (arg.info.ru.info1 && arg.info.ru.info1->ci1) {
			cib1 = arg.info.ru.info1->ci1;

			smb_tracef("srvsvc coni_uname=%s",
			    cib1->coni1_username ?
			    (char *)cib1->coni1_username : "(null)");
			smb_tracef("srvsvc coni1_netname=%s",
			    cib1->coni1_netname ?
			    (char *)cib1->coni1_netname : "(null)");
			smb_tracef("srvsvc coni1_nopens=%u",
			    cib1->coni1_num_opens);
			smb_tracef("srvsvc coni1_time=%u", cib1->coni1_time);
			smb_tracef("srvsvc coni1_num_users=%u",
			    cib1->coni1_num_users);
		}
		break;

	default:
		smb_tracef("srvsvc: unknown level");
		break;
	}

	srvsvc_close(&handle, &heap);
	return (0);
}

/*
 * Synchronize the local system clock with the domain controller.
 */
void
srvsvc_timesync(void)
{
	smb_ntdomain_t *di;
	struct timeval tv;
	struct tm tm;
	time_t tsecs;

	if ((di = smb_getdomaininfo(0)) == NULL)
		return;

	if (srvsvc_net_remote_tod(di->server, di->domain, &tv, &tm) != 0)
		return;

	if (settimeofday(&tv, 0))
		smb_tracef("unable to set system time");

	tsecs = time(0);
	(void) localtime_r(&tsecs, &tm);
	smb_tracef("SrvsvcTimeSync %s", ctime((time_t *)&tv.tv_sec));
}

/*
 * NetRemoteTOD to get the current GMT time from a Windows NT server.
 */
int
srvsvc_gettime(unsigned long *t)
{
	smb_ntdomain_t *di;
	struct timeval tv;
	struct tm tm;

	if ((di = smb_getdomaininfo(0)) == NULL)
		return (-1);

	if (srvsvc_net_remote_tod(di->server, di->domain, &tv, &tm) != 0)
		return (-1);

	*t = tv.tv_sec;
	return (0);
}

/*
 * This is a client side routine for NetRemoteTOD, which gets the time
 * and date from a remote system. The time information is returned in
 * the timeval and tm.
 *
 * typedef struct _TIME_OF_DAY_INFO {
 *	DWORD tod_elapsedt;  // seconds since 00:00:00 January 1 1970 GMT
 *	DWORD tod_msecs;     // arbitrary milliseconds (since reset)
 *	DWORD tod_hours;     // current hour [0-23]
 *	DWORD tod_mins;      // current minute [0-59]
 *	DWORD tod_secs;      // current second [0-59]
 *	DWORD tod_hunds;     // current hundredth (0.01) second [0-99]
 *	LONG tod_timezone;   // time zone of the server
 *	DWORD tod_tinterval; // clock tick time interval
 *	DWORD tod_day;       // day of the month [1-31]
 *	DWORD tod_month;     // month of the year [1-12]
 *	DWORD tod_year;      // current year
 *	DWORD tod_weekday;   // day of the week since sunday [0-6]
 * } TIME_OF_DAY_INFO;
 *
 * The time zone of the server is calculated in minutes from Greenwich
 * Mean Time (GMT). For time zones west of Greenwich, the value is
 * positive; for time zones east of Greenwich, the value is negative.
 * A value of -1 indicates that the time zone is undefined.
 *
 * The clock tick value represents a resolution of one ten-thousandth
 * (0.0001) second.
 */
int
srvsvc_net_remote_tod(char *server, char *domain, struct timeval *tv,
    struct tm *tm)
{
	char timebuf[64];
	struct mslm_NetRemoteTOD arg;
	struct mslm_TIME_OF_DAY_INFO *tod;
	mlsvc_handle_t handle;
	mlrpc_heapref_t heap;
	int rc;
	int opnum;
	int len;
	char *user = smbrdr_ipc_get_user();

	rc = srvsvc_open(server, domain, user, &handle, &heap);
	if (rc != 0)
		return (-1);

	opnum = SRVSVC_OPNUM_NetRemoteTOD;
	bzero(&arg, sizeof (struct mslm_NetRemoteTOD));

	len = strlen(server) + 4;
	arg.servername = mlrpc_heap_malloc(heap.heap, len);
	if (arg.servername == NULL) {
		srvsvc_close(&handle, &heap);
		return (-1);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);

	rc = mlsvc_rpc_call(handle.context, opnum, &arg, &heap);
	if ((rc != 0) || (arg.status != 0)) {
		srvsvc_close(&handle, &heap);
		return (-1);
	}

	/*
	 * We're assigning milliseconds to microseconds
	 * here but the value's not really relevant.
	 */
	tod = arg.bufptr;

	if (tv) {
		tv->tv_sec = tod->tod_elapsedt;
		tv->tv_usec = tod->tod_msecs;
		smb_tracef("RemoteTime: %s", ctime(&tv->tv_sec));
	}

	if (tm) {
		tm->tm_sec = tod->tod_secs;
		tm->tm_min = tod->tod_mins;
		tm->tm_hour = tod->tod_hours;
		tm->tm_mday = tod->tod_day;
		tm->tm_mon = tod->tod_month - 1;
		tm->tm_year = tod->tod_year - 1900;
		tm->tm_wday = tod->tod_weekday;

		(void) strftime(timebuf, sizeof (timebuf),
		    "NetRemoteTOD: %D %T", tm);
		smb_tracef("NetRemoteTOD: %s", timebuf);
	}

	srvsvc_close(&handle, &heap);
	return (0);
}

void
srvsvc_net_test(char *server, char *domain, char *netname)
{
	smb_ntdomain_t *di;

	(void) smb_tracef("%s %s %s", server, domain, netname);

	if ((di = smb_getdomaininfo(0)) != NULL) {
		server = di->server;
		domain = di->domain;
	}

	(void) srvsvc_net_share_get_info(server, domain, netname);
#if 0
	/*
	 * The NetSessionEnum server-side definition was updated.
	 * Disabled until the client-side has been updated.
	 */
	(void) srvsvc_net_session_enum(server, domain, netname);
#endif
	(void) srvsvc_net_connect_enum(server, domain, netname, 0);
	(void) srvsvc_net_connect_enum(server, domain, netname, 1);
}
