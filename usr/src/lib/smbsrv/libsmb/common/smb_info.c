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

#include <assert.h>
#include <sys/types.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <synch.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/netbios.h>
#include <smbsrv/libsmb.h>

static mutex_t seqnum_mtx;

/*
 * IPC connection information that may be passed to the SMB Redirector.
 */
typedef struct {
	char	user[SMB_USERNAME_MAXLEN];
	uint8_t	passwd[SMBAUTH_HASH_SZ];
} smb_ipc_t;

static smb_ipc_t	ipc_info;
static smb_ipc_t	ipc_orig_info;
static rwlock_t		smb_ipc_lock;

/*
 * Some older clients (Windows 98) only handle the low byte
 * of the max workers value. If the low byte is less than
 * SMB_PI_MAX_WORKERS_MIN set it to SMB_PI_MAX_WORKERS_MIN.
 */
void
smb_load_kconfig(smb_kmod_cfg_t *kcfg)
{
	int64_t citem;

	bzero(kcfg, sizeof (smb_kmod_cfg_t));

	(void) smb_config_getnum(SMB_CI_MAX_WORKERS, &citem);
	kcfg->skc_maxworkers = (uint32_t)citem;
	if ((kcfg->skc_maxworkers & 0xFF) < SMB_PI_MAX_WORKERS_MIN) {
		kcfg->skc_maxworkers &= ~0xFF;
		kcfg->skc_maxworkers += SMB_PI_MAX_WORKERS_MIN;
	}

	(void) smb_config_getnum(SMB_CI_KEEPALIVE, &citem);
	kcfg->skc_keepalive = (uint32_t)citem;
	if ((kcfg->skc_keepalive != 0) &&
	    (kcfg->skc_keepalive < SMB_PI_KEEP_ALIVE_MIN))
		kcfg->skc_keepalive = SMB_PI_KEEP_ALIVE_MIN;

	(void) smb_config_getnum(SMB_CI_MAX_CONNECTIONS, &citem);
	kcfg->skc_maxconnections = (uint32_t)citem;
	kcfg->skc_restrict_anon = smb_config_getbool(SMB_CI_RESTRICT_ANON);
	kcfg->skc_signing_enable = smb_config_getbool(SMB_CI_SIGNING_ENABLE);
	kcfg->skc_signing_required = smb_config_getbool(SMB_CI_SIGNING_REQD);
	kcfg->skc_netbios_enable = smb_config_getbool(SMB_CI_NETBIOS_ENABLE);
	kcfg->skc_ipv6_enable = smb_config_getbool(SMB_CI_IPV6_ENABLE);
	kcfg->skc_print_enable = smb_config_getbool(SMB_CI_PRINT_ENABLE);
	kcfg->skc_oplock_enable = smb_config_getbool(SMB_CI_OPLOCK_ENABLE);
	kcfg->skc_sync_enable = smb_config_getbool(SMB_CI_SYNC_ENABLE);
	kcfg->skc_traverse_mounts = smb_config_getbool(SMB_CI_TRAVERSE_MOUNTS);
	kcfg->skc_secmode = smb_config_get_secmode();
	(void) smb_getdomainname(kcfg->skc_nbdomain,
	    sizeof (kcfg->skc_nbdomain));
	(void) smb_getfqdomainname(kcfg->skc_fqdn,
	    sizeof (kcfg->skc_fqdn));
	(void) smb_getnetbiosname(kcfg->skc_hostname,
	    sizeof (kcfg->skc_hostname));
	(void) smb_config_getstr(SMB_CI_SYS_CMNT, kcfg->skc_system_comment,
	    sizeof (kcfg->skc_system_comment));
	smb_config_get_version(&kcfg->skc_version);
	kcfg->skc_execflags = smb_config_get_execinfo(NULL, NULL, 0);
}

/*
 * Get the current system NetBIOS name.  The hostname is truncated at
 * the first `.` or 15 bytes, whichever occurs first, and converted
 * to uppercase (by smb_gethostname).  Text that appears after the
 * first '.' is considered to be part of the NetBIOS scope.
 *
 * Returns 0 on success, otherwise -1 to indicate an error.
 */
int
smb_getnetbiosname(char *buf, size_t buflen)
{
	if (smb_gethostname(buf, buflen, SMB_CASE_UPPER) != 0)
		return (-1);

	if (buflen >= NETBIOS_NAME_SZ)
		buf[NETBIOS_NAME_SZ - 1] = '\0';

	return (0);
}

/*
 * Get the SAM account of the current system.
 * Returns 0 on success, otherwise, -1 to indicate an error.
 */
int
smb_getsamaccount(char *buf, size_t buflen)
{
	if (smb_getnetbiosname(buf, buflen - 1) != 0)
		return (-1);

	(void) strlcat(buf, "$", buflen);
	return (0);
}

/*
 * Get the current system node name.  The returned name is guaranteed
 * to be null-terminated (gethostname may not null terminate the name).
 * If the hostname has been fully-qualified for some reason, the domain
 * part will be removed.  The returned hostname is converted to the
 * specified case (lower, upper, or preserved).
 *
 * If gethostname fails, the returned buffer will contain an empty
 * string.
 */
int
smb_gethostname(char *buf, size_t buflen, smb_caseconv_t which)
{
	char *p;

	if (buf == NULL || buflen == 0)
		return (-1);

	if (gethostname(buf, buflen) != 0) {
		*buf = '\0';
		return (-1);
	}

	buf[buflen - 1] = '\0';

	if ((p = strchr(buf, '.')) != NULL)
		*p = '\0';

	switch (which) {
	case SMB_CASE_LOWER:
		(void) smb_strlwr(buf);
		break;

	case SMB_CASE_UPPER:
		(void) smb_strupr(buf);
		break;

	case SMB_CASE_PRESERVE:
	default:
		break;
	}

	return (0);
}

/*
 * Obtain the fully-qualified name for this machine in lower case.  If
 * the hostname is fully-qualified, accept it.  Otherwise, try to find an
 * appropriate domain name to append to the hostname.
 */
int
smb_getfqhostname(char *buf, size_t buflen)
{
	char hostname[MAXHOSTNAMELEN];
	char domain[MAXHOSTNAMELEN];

	hostname[0] = '\0';
	domain[0] = '\0';

	if (smb_gethostname(hostname, MAXHOSTNAMELEN,
	    SMB_CASE_LOWER) != 0)
		return (-1);

	if (smb_getfqdomainname(domain, MAXHOSTNAMELEN) != 0)
		return (-1);

	if (hostname[0] == '\0')
		return (-1);

	if (domain[0] == '\0') {
		(void) strlcpy(buf, hostname, buflen);
		return (0);
	}

	(void) snprintf(buf, buflen, "%s.%s", hostname, domain);
	return (0);
}

/*
 * smb_getdomainname
 *
 * Returns NETBIOS name of the domain if the system is in domain
 * mode. Or returns workgroup name if the system is in workgroup
 * mode.
 */
int
smb_getdomainname(char *buf, size_t buflen)
{
	int rc;

	if (buf == NULL || buflen == 0)
		return (-1);

	*buf = '\0';
	rc = smb_config_getstr(SMB_CI_DOMAIN_NAME, buf, buflen);

	if ((rc != SMBD_SMF_OK) || (*buf == '\0'))
		return (-1);

	return (0);
}

/*
 * smb_getfqdomainname
 *
 * In the system is in domain mode, the dns_domain property value
 * is returned. Otherwise, it returns the local domain obtained via
 * resolver.
 *
 * Returns 0 upon success.  Otherwise, returns -1.
 */
int
smb_getfqdomainname(char *buf, size_t buflen)
{
	struct __res_state res_state;
	int rc;

	if (buf == NULL || buflen == 0)
		return (-1);

	*buf = '\0';
	if (smb_config_get_secmode() == SMB_SECMODE_DOMAIN) {
		rc = smb_config_getstr(SMB_CI_DOMAIN_FQDN, buf, buflen);

		if ((rc != SMBD_SMF_OK) || (*buf == '\0'))
			return (-1);
	} else {
		bzero(&res_state, sizeof (struct __res_state));
		if (res_ninit(&res_state))
			return (-1);

		if (*res_state.defdname == '\0') {
			res_ndestroy(&res_state);
			return (-1);
		}

		(void) strlcpy(buf, res_state.defdname, buflen);
		res_ndestroy(&res_state);
		rc = 0;
	}

	return (rc);
}


/*
 * smb_set_machine_passwd
 *
 * This function should be used when setting the machine password property.
 * The associated sequence number is incremented.
 */
static int
smb_set_machine_passwd(char *passwd)
{
	int64_t num;
	int rc = -1;

	if (smb_config_set(SMB_CI_MACHINE_PASSWD, passwd) != SMBD_SMF_OK)
		return (-1);

	(void) mutex_lock(&seqnum_mtx);
	(void) smb_config_getnum(SMB_CI_KPASSWD_SEQNUM, &num);
	if (smb_config_setnum(SMB_CI_KPASSWD_SEQNUM, ++num)
	    == SMBD_SMF_OK)
		rc = 0;
	(void) mutex_unlock(&seqnum_mtx);
	return (rc);
}

static int
smb_get_machine_passwd(uint8_t *buf, size_t buflen)
{
	char pwd[SMB_PASSWD_MAXLEN + 1];
	int rc;

	if (buflen < SMBAUTH_HASH_SZ)
		return (-1);

	rc = smb_config_getstr(SMB_CI_MACHINE_PASSWD, pwd, sizeof (pwd));
	if ((rc != SMBD_SMF_OK) || *pwd == '\0')
		return (-1);

	if (smb_auth_ntlm_hash(pwd, buf) != 0)
		return (-1);

	return (rc);
}

/*
 * Set up IPC connection credentials.
 */
void
smb_ipc_init(void)
{
	int rc;

	(void) rw_wrlock(&smb_ipc_lock);
	bzero(&ipc_info, sizeof (smb_ipc_t));
	bzero(&ipc_orig_info, sizeof (smb_ipc_t));

	(void) smb_getsamaccount(ipc_info.user, SMB_USERNAME_MAXLEN);
	rc = smb_get_machine_passwd(ipc_info.passwd, SMBAUTH_HASH_SZ);
	if (rc != 0)
		*ipc_info.passwd = 0;
	(void) rw_unlock(&smb_ipc_lock);

}

/*
 * Set the IPC username and password hash in memory.  If the domain
 * join succeeds, the credentials will be committed for use with
 * authenticated IPC.  Otherwise, they should be rolled back.
 */
void
smb_ipc_set(char *plain_user, uint8_t *passwd_hash)
{
	(void) rw_wrlock(&smb_ipc_lock);
	(void) strlcpy(ipc_info.user, plain_user, sizeof (ipc_info.user));
	(void) memcpy(ipc_info.passwd, passwd_hash, SMBAUTH_HASH_SZ);
	(void) rw_unlock(&smb_ipc_lock);

}

/*
 * Save the host credentials to be used for authenticated IPC.
 * The credentials are also saved to the original IPC info as
 * rollback data in case the join domain process fails later.
 */
void
smb_ipc_commit(void)
{
	(void) rw_wrlock(&smb_ipc_lock);
	(void) smb_getsamaccount(ipc_info.user, SMB_USERNAME_MAXLEN);
	(void) smb_get_machine_passwd(ipc_info.passwd, SMBAUTH_HASH_SZ);
	(void) memcpy(&ipc_orig_info, &ipc_info, sizeof (smb_ipc_t));
	(void) rw_unlock(&smb_ipc_lock);
}

/*
 * Restore the original credentials
 */
void
smb_ipc_rollback(void)
{
	(void) rw_wrlock(&smb_ipc_lock);
	(void) strlcpy(ipc_info.user, ipc_orig_info.user,
	    sizeof (ipc_info.user));
	(void) memcpy(ipc_info.passwd, ipc_orig_info.passwd,
	    sizeof (ipc_info.passwd));
	(void) rw_unlock(&smb_ipc_lock);
}

void
smb_ipc_get_user(char *buf, size_t buflen)
{
	(void) rw_rdlock(&smb_ipc_lock);
	(void) strlcpy(buf, ipc_info.user, buflen);
	(void) rw_unlock(&smb_ipc_lock);
}

void
smb_ipc_get_passwd(uint8_t *buf, size_t buflen)
{
	if (buflen < SMBAUTH_HASH_SZ)
		return;

	(void) rw_rdlock(&smb_ipc_lock);
	(void) memcpy(buf, ipc_info.passwd, SMBAUTH_HASH_SZ);
	(void) rw_unlock(&smb_ipc_lock);
}

/*
 * smb_match_netlogon_seqnum
 *
 * A sequence number is associated with each machine password property
 * update and the netlogon credential chain setup. If the
 * sequence numbers don't match, a NETLOGON credential chain
 * establishment is required.
 *
 * Returns 0 if kpasswd_seqnum equals to netlogon_seqnum. Otherwise,
 * returns -1.
 */
boolean_t
smb_match_netlogon_seqnum(void)
{
	int64_t setpasswd_seqnum;
	int64_t netlogon_seqnum;

	(void) mutex_lock(&seqnum_mtx);
	(void) smb_config_getnum(SMB_CI_KPASSWD_SEQNUM, &setpasswd_seqnum);
	(void) smb_config_getnum(SMB_CI_NETLOGON_SEQNUM, &netlogon_seqnum);
	(void) mutex_unlock(&seqnum_mtx);
	return (setpasswd_seqnum == netlogon_seqnum);
}

/*
 * smb_setdomainprops
 *
 * This function should be called after joining an AD to
 * set all the domain related SMF properties.
 *
 * The kpasswd_domain property is the AD domain to which the system
 * is joined via kclient. If this function is invoked by the SMB
 * daemon, fqdn should be set to NULL.
 */
int
smb_setdomainprops(char *fqdn, char *server, char *passwd)
{
	if (server == NULL || passwd == NULL)
		return (-1);

	if ((*server == '\0') || (*passwd == '\0'))
		return (-1);

	if (fqdn && (smb_config_set(SMB_CI_KPASSWD_DOMAIN, fqdn) != 0))
		return (-1);

	if (smb_config_set(SMB_CI_KPASSWD_SRV, server) != 0)
		return (-1);

	if (smb_set_machine_passwd(passwd) != 0) {
		syslog(LOG_ERR, "smb_setdomainprops: failed to set"
		    " machine account password");
		return (-1);
	}

	/*
	 * If we successfully create a trust account, we mark
	 * ourselves as a domain member in the environment so
	 * that we use the SAMLOGON version of the NETLOGON
	 * PDC location protocol.
	 */
	(void) smb_config_setbool(SMB_CI_DOMAIN_MEMB, B_TRUE);

	return (0);
}

/*
 * smb_update_netlogon_seqnum
 *
 * This function should only be called upon a successful netlogon
 * credential chain establishment to set the sequence number of the
 * netlogon to match with that of the kpasswd.
 */
void
smb_update_netlogon_seqnum(void)
{
	int64_t num;

	(void) mutex_lock(&seqnum_mtx);
	(void) smb_config_getnum(SMB_CI_KPASSWD_SEQNUM, &num);
	(void) smb_config_setnum(SMB_CI_NETLOGON_SEQNUM, num);
	(void) mutex_unlock(&seqnum_mtx);
}


/*
 * Temporary fbt for dtrace until user space sdt enabled.
 */
void
smb_tracef(const char *fmt, ...)
{
	va_list ap;
	char buf[128];

	va_start(ap, fmt);
	(void) vsnprintf(buf, 128, fmt, ap);
	va_end(ap);

	smb_trace(buf);
}

/*
 * Temporary fbt for dtrace until user space sdt enabled.
 *
 * This function is designed to be used with dtrace, i.e. see:
 * usr/src/cmd/smbsrv/dtrace/smbd-all.d
 *
 * Outside of dtrace, the messages passed to this function usually
 * lack sufficient context to be useful, so we don't log them.
 */
/* ARGSUSED */
void
smb_trace(const char *s)
{
}

/*
 * smb_tonetbiosname
 *
 * Creates a NetBIOS name based on the given name and suffix.
 * NetBIOS name is 15 capital characters, padded with space if needed
 * and the 16th byte is the suffix.
 */
void
smb_tonetbiosname(char *name, char *nb_name, char suffix)
{
	char tmp_name[NETBIOS_NAME_SZ];
	smb_wchar_t wtmp_name[NETBIOS_NAME_SZ];
	int len;
	size_t rc;

	len = 0;
	rc = smb_mbstowcs(wtmp_name, (const char *)name, NETBIOS_NAME_SZ);

	if (rc != (size_t)-1) {
		wtmp_name[NETBIOS_NAME_SZ - 1] = 0;
		rc = ucstooem(tmp_name, wtmp_name, NETBIOS_NAME_SZ,
		    OEM_CPG_850);
		if (rc > 0)
			len = strlen(tmp_name);
	}

	(void) memset(nb_name, ' ', NETBIOS_NAME_SZ - 1);
	if (len) {
		(void) smb_strupr(tmp_name);
		(void) memcpy(nb_name, tmp_name, len);
	}
	nb_name[NETBIOS_NAME_SZ - 1] = suffix;
}

int
smb_get_nameservers(smb_inaddr_t *ips, int sz)
{
	union res_sockaddr_union set[MAXNS];
	int i, cnt;
	struct __res_state res_state;
	char ipstr[INET6_ADDRSTRLEN];

	if (ips == NULL)
		return (0);

	bzero(&res_state, sizeof (struct __res_state));
	if (res_ninit(&res_state) < 0)
		return (0);

	cnt = res_getservers(&res_state, set, MAXNS);
	for (i = 0; i < cnt; i++) {
		if (i >= sz)
			break;
		ips[i].a_family = AF_INET;
		bcopy(&set[i].sin.sin_addr, &ips[i].a_ipv4, NS_INADDRSZ);
		if (inet_ntop(AF_INET, &ips[i].a_ipv4, ipstr,
		    INET_ADDRSTRLEN)) {
			syslog(LOG_DEBUG, "Found %s name server\n", ipstr);
			continue;
		}
		ips[i].a_family = AF_INET6;
		bcopy(&set[i].sin.sin_addr, &ips[i].a_ipv6, NS_IN6ADDRSZ);
		if (inet_ntop(AF_INET6, &ips[i].a_ipv6, ipstr,
		    INET6_ADDRSTRLEN)) {
			syslog(LOG_DEBUG, "Found %s name server\n", ipstr);
		}
	}
	res_ndestroy(&res_state);
	return (i);
}

/*
 * smb_gethostbyname
 *
 * Looks up a host by the given name. The host entry can come
 * from any of the sources for hosts specified in the
 * /etc/nsswitch.conf and the NetBIOS cache.
 *
 * XXX Invokes nbt_name_resolve API once the NBTD is integrated
 * to look in the NetBIOS cache if getipnodebyname fails.
 *
 * Caller should invoke freehostent to free the returned hostent.
 */
struct hostent *
smb_gethostbyname(const char *name, int *err_num)
{
	struct hostent *h;

	h = getipnodebyname(name, AF_INET, 0, err_num);
	if ((h == NULL) || h->h_length != INADDRSZ)
		h = getipnodebyname(name, AF_INET6, AI_DEFAULT, err_num);
	return (h);
}

/*
 * smb_gethostbyaddr
 *
 * Looks up a host by the given IP address. The host entry can come
 * from any of the sources for hosts specified in the
 * /etc/nsswitch.conf and the NetBIOS cache.
 *
 * XXX Invokes nbt API to resolve name by IP once the NBTD is integrated
 * to look in the NetBIOS cache if getipnodebyaddr fails.
 *
 * Caller should invoke freehostent to free the returned hostent.
 */
struct hostent *
smb_gethostbyaddr(const char *addr, int len, int type, int *err_num)
{
	struct hostent *h;

	h = getipnodebyaddr(addr, len, type, err_num);

	return (h);
}
