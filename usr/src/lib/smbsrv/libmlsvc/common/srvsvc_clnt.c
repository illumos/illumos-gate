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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

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

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ndl/srvsvc.ndl>

/*
 * Information level for NetShareGetInfo.
 */
DWORD srvsvc_info_level = 1;

/*
 * Bind to the the SRVSVC.
 *
 * If username argument is NULL, an anonymous connection will be established.
 * Otherwise, an authenticated connection will be established.
 */
static int
srvsvc_open(char *server, char *domain, char *username, mlsvc_handle_t *handle)
{
	smb_domainex_t di;

	if (server == NULL || domain == NULL) {
		if (!smb_domain_getinfo(&di))
			return (-1);

		server = di.d_dci.dc_name;
		domain = di.d_primary.di_nbname;
	}

	if (username == NULL)
		username = MLSVC_ANON_USER;

	if (ndr_rpc_bind(handle, server, domain, username, "SRVSVC") != 0)
		return (-1);

	return (0);
}

/*
 * Unbind the SRVSVC connection.
 */
static void
srvsvc_close(mlsvc_handle_t *handle)
{
	ndr_rpc_unbind(handle);
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
	int rc;
	int opnum;
	struct mslm_NetShareInfo_0 *info0;
	struct mslm_NetShareInfo_1 *info1;
	struct mslm_NetShareInfo_2 *info2;
	int len;
	char user[SMB_USERNAME_MAXLEN];

	if (netname == NULL)
		return (-1);

	if (srvsvc_info_level == 2)
		smb_ipc_get_user(user, SMB_USERNAME_MAXLEN);

	if (srvsvc_open(server, domain, user, &handle) != 0)
		return (-1);

	opnum = SRVSVC_OPNUM_NetShareGetInfo;
	bzero(&arg, sizeof (struct mlsm_NetShareGetInfo));

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(&handle, len);
	if (arg.servername == NULL) {
		srvsvc_close(&handle);
		return (-1);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.netname = (LPTSTR)netname;
	arg.level = srvsvc_info_level; /* share information level */

	rc = ndr_rpc_call(&handle, opnum, &arg);
	if ((rc != 0) || (arg.status != 0)) {
		srvsvc_close(&handle);
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

	srvsvc_close(&handle);
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
	int rc;
	int opnum;
	struct mslm_infonres infonres;
	struct mslm_SESSION_INFO_1 *nsi1;
	int len;
	char user[SMB_USERNAME_MAXLEN];

	if (netname == NULL)
		return (-1);

	smb_ipc_get_user(user, SMB_USERNAME_MAXLEN);

	rc = srvsvc_open(server, domain, user, &handle);
	if (rc != 0)
		return (-1);

	opnum = SRVSVC_OPNUM_NetSessionEnum;
	bzero(&arg, sizeof (struct mslm_NetSessionEnum));

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(&handle, len);
	if (arg.servername == NULL) {
		srvsvc_close(&handle);
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

	rc = ndr_rpc_call(&handle, opnum, &arg);
	if ((rc != 0) || (arg.status != 0)) {
		srvsvc_close(&handle);
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

	srvsvc_close(&handle);
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
	int rc;
	int opnum;
	struct mslm_NetConnectInfo1 info1;
	struct mslm_NetConnectInfo0 info0;
	struct mslm_NetConnectInfoBuf1 *cib1;
	int len;
	char user[SMB_USERNAME_MAXLEN];

	if (netname == NULL)
		return (-1);

	smb_ipc_get_user(user, SMB_USERNAME_MAXLEN);

	rc = srvsvc_open(server, domain, user, &handle);
	if (rc != 0)
		return (-1);

	opnum = SRVSVC_OPNUM_NetConnectEnum;
	bzero(&arg, sizeof (struct mslm_NetConnectEnum));

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(&handle, len);
	if (arg.servername == NULL) {
		srvsvc_close(&handle);
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
		srvsvc_close(&handle);
		return (-1);
	}

	arg.resume_handle = 0;
	arg.pref_max_len = 0xFFFFFFFF;

	rc = ndr_rpc_call(&handle, opnum, &arg);
	if ((rc != 0) || (arg.status != 0)) {
		srvsvc_close(&handle);
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

	srvsvc_close(&handle);
	return (0);
}

/*
 * Windows 95+ and Windows NT4.0 both report the version as 4.0.
 * Windows 2000+ reports the version as 5.x.
 */
int
srvsvc_net_server_getinfo(char *server, char *domain,
    srvsvc_server_info_t *svinfo)
{
	mlsvc_handle_t handle;
	struct mslm_NetServerGetInfo arg;
	struct mslm_SERVER_INFO_101 *sv101;
	int len, opnum, rc;
	char user[SMB_USERNAME_MAXLEN];

	smb_ipc_get_user(user, SMB_USERNAME_MAXLEN);

	if (srvsvc_open(server, domain, user, &handle) != 0)
		return (-1);

	opnum = SRVSVC_OPNUM_NetServerGetInfo;
	bzero(&arg, sizeof (arg));

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(&handle, len);
	if (arg.servername == NULL)
		return (-1);

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);
	arg.level = 101;

	rc = ndr_rpc_call(&handle, opnum, &arg);
	if ((rc != 0) || (arg.status != 0)) {
		srvsvc_close(&handle);
		return (-1);
	}

	sv101 = arg.result.bufptr.bufptr101;

	bzero(svinfo, sizeof (srvsvc_server_info_t));
	svinfo->sv_platform_id = sv101->sv101_platform_id;
	svinfo->sv_version_major = sv101->sv101_version_major;
	svinfo->sv_version_minor = sv101->sv101_version_minor;
	svinfo->sv_type = sv101->sv101_type;
	if (sv101->sv101_name)
		svinfo->sv_name = strdup((char *)sv101->sv101_name);
	if (sv101->sv101_comment)
		svinfo->sv_comment = strdup((char *)sv101->sv101_comment);

	if (svinfo->sv_type & SV_TYPE_WFW)
		svinfo->sv_os = NATIVE_OS_WIN95;
	if (svinfo->sv_type & SV_TYPE_WINDOWS)
		svinfo->sv_os = NATIVE_OS_WIN95;
	if ((svinfo->sv_type & SV_TYPE_NT) ||
	    (svinfo->sv_type & SV_TYPE_SERVER_NT))
		svinfo->sv_os = NATIVE_OS_WINNT;
	if (svinfo->sv_version_major > 4)
		svinfo->sv_os = NATIVE_OS_WIN2000;

	srvsvc_close(&handle);
	return (0);
}

/*
 * Synchronize the local system clock with the domain controller.
 */
void
srvsvc_timesync(void)
{
	smb_domainex_t di;
	struct timeval tv;
	struct tm tm;
	time_t tsecs;

	if (!smb_domain_getinfo(&di))
		return;

	if (srvsvc_net_remote_tod(di.d_dci.dc_name, di.d_primary.di_nbname,
	    &tv, &tm) != 0)
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
	smb_domainex_t di;
	struct timeval tv;
	struct tm tm;

	if (!smb_domain_getinfo(&di))
		return (-1);

	if (srvsvc_net_remote_tod(di.d_dci.dc_name, di.d_primary.di_nbname,
	    &tv, &tm) != 0)
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
	struct mslm_NetRemoteTOD	arg;
	struct mslm_TIME_OF_DAY_INFO	*tod;
	mlsvc_handle_t			handle;
	int				rc;
	int				opnum;
	int				len;
	char				user[SMB_USERNAME_MAXLEN];

	smb_ipc_get_user(user, SMB_USERNAME_MAXLEN);

	rc = srvsvc_open(server, domain, user, &handle);
	if (rc != 0)
		return (-1);

	opnum = SRVSVC_OPNUM_NetRemoteTOD;
	bzero(&arg, sizeof (struct mslm_NetRemoteTOD));

	len = strlen(server) + 4;
	arg.servername = ndr_rpc_malloc(&handle, len);
	if (arg.servername == NULL) {
		srvsvc_close(&handle);
		return (-1);
	}

	(void) snprintf((char *)arg.servername, len, "\\\\%s", server);

	rc = ndr_rpc_call(&handle, opnum, &arg);
	if ((rc != 0) || (arg.status != 0)) {
		srvsvc_close(&handle);
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
	}

	if (tm) {
		tm->tm_sec = tod->tod_secs;
		tm->tm_min = tod->tod_mins;
		tm->tm_hour = tod->tod_hours;
		tm->tm_mday = tod->tod_day;
		tm->tm_mon = tod->tod_month - 1;
		tm->tm_year = tod->tod_year - 1900;
		tm->tm_wday = tod->tod_weekday;
	}

	srvsvc_close(&handle);
	return (0);
}

void
srvsvc_net_test(char *server, char *domain, char *netname)
{
	smb_domainex_t di;
	srvsvc_server_info_t svinfo;

	(void) smb_tracef("%s %s %s", server, domain, netname);

	if (smb_domain_getinfo(&di)) {
		server = di.d_dci.dc_name;
		domain = di.d_primary.di_nbname;
	}

	if (srvsvc_net_server_getinfo(server, domain, &svinfo) == 0) {
		smb_tracef("NetServerGetInfo: %s %s (%d.%d) id=%d type=0x%08x",
		    svinfo.sv_name ? svinfo.sv_name : "NULL",
		    svinfo.sv_comment ? svinfo.sv_comment : "NULL",
		    svinfo.sv_version_major, svinfo.sv_version_minor,
		    svinfo.sv_platform_id, svinfo.sv_type);

		free(svinfo.sv_name);
		free(svinfo.sv_comment);
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
