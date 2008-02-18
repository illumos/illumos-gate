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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <smbsrv/smbinfo.h>
#include <smbsrv/netbios.h>
#include <smbsrv/libsmb.h>

static smb_ntdomain_t smbpdc_cache;
static mutex_t smbpdc_mtx;
static cond_t smbpdc_cv;

extern int getdomainname(char *, int);

/*
 * smb_getdomaininfo
 *
 * Returns a pointer to the cached domain data. The caller can specify
 * whether or not he is prepared to wait if the cache is not yet valid
 * and for how long. The specified timeout is in seconds.
 */
smb_ntdomain_t *
smb_getdomaininfo(uint32_t timeout)
{
	timestruc_t to;
	int err;

	if (timeout != 0) {
		(void) mutex_lock(&smbpdc_mtx);
		while (smbpdc_cache.ipaddr == 0) {
			to.tv_sec = timeout;
			to.tv_nsec = 0;
			err = cond_reltimedwait(&smbpdc_cv, &smbpdc_mtx, &to);
			if (err == ETIME)
				break;
		}
		(void) mutex_unlock(&smbpdc_mtx);
	}

	if (smbpdc_cache.ipaddr != 0)
		return (&smbpdc_cache);
	else
		return (0);
}

void
smb_logdomaininfo(smb_ntdomain_t *di)
{
	char ipstr[16];

	(void) inet_ntop(AF_INET, (const void *)&di->ipaddr, ipstr,
	    sizeof (ipstr));
	syslog(LOG_DEBUG, "smbd: %s (%s:%s)", di->domain, di->server, ipstr);
}

/*
 * smb_setdomaininfo
 *
 * Set the information for the specified domain. If the information is
 * non-null, the notification event is raised to wakeup any threads
 * blocking on the cache.
 */
void
smb_setdomaininfo(char *domain, char *server, uint32_t ipaddr)
{
	char *p;

	bzero(&smbpdc_cache, sizeof (smb_ntdomain_t));

	if (domain && server && ipaddr) {
		(void) strlcpy(smbpdc_cache.domain, domain, SMB_PI_MAX_DOMAIN);
		(void) strlcpy(smbpdc_cache.server, server, SMB_PI_MAX_DOMAIN);

		/*
		 * Remove DNS domain name extension
		 * to avoid confusing NetBIOS.
		 */
		if ((p = strchr(smbpdc_cache.domain, '.')) != 0)
			*p = '\0';

		if ((p = strchr(smbpdc_cache.server, '.')) != 0)
			*p = '\0';

		(void) mutex_lock(&smbpdc_mtx);
		smbpdc_cache.ipaddr = ipaddr;
		(void) cond_broadcast(&smbpdc_cv);
		(void) mutex_unlock(&smbpdc_mtx);
	}
}

void
smb_load_kconfig(smb_kmod_cfg_t *kcfg)
{
	int64_t citem;

	bzero(kcfg, sizeof (smb_kmod_cfg_t));

	(void) smb_config_getnum(SMB_CI_MAX_BUFSIZE, &citem);
	kcfg->skc_maxbufsize = (uint32_t)citem;
	(void) smb_config_getnum(SMB_CI_MAX_WORKERS, &citem);
	kcfg->skc_maxworkers = (uint32_t)citem;
	(void) smb_config_getnum(SMB_CI_KEEPALIVE, &citem);
	kcfg->skc_keepalive = (uint32_t)citem;
	if ((kcfg->skc_keepalive != 0) &&
	    (kcfg->skc_keepalive < SMB_PI_KEEP_ALIVE_MIN))
		kcfg->skc_keepalive = SMB_PI_KEEP_ALIVE_MIN;

	(void) smb_config_getnum(SMB_CI_OPLOCK_TIMEOUT, &citem);
	kcfg->skc_oplock_timeout = (uint32_t)citem;
	(void) smb_config_getnum(SMB_CI_MAX_CONNECTIONS, &citem);
	kcfg->skc_maxconnections = (uint32_t)citem;
	kcfg->skc_restrict_anon = smb_config_getbool(SMB_CI_RESTRICT_ANON);
	kcfg->skc_signing_enable = smb_config_getbool(SMB_CI_SIGNING_ENABLE);
	kcfg->skc_signing_required = smb_config_getbool(SMB_CI_SIGNING_REQD);
	kcfg->skc_signing_check = smb_config_getbool(SMB_CI_SIGNING_CHECK);
	kcfg->skc_oplock_enable = smb_config_getbool(SMB_CI_OPLOCK_ENABLE);
	kcfg->skc_flush_required = smb_config_getbool(SMB_CI_FLUSH_REQUIRED);
	kcfg->skc_sync_enable = smb_config_getbool(SMB_CI_SYNC_ENABLE);
	kcfg->skc_dirsymlink_enable =
	    !smb_config_getbool(SMB_CI_DIRSYMLINK_DISABLE);
	kcfg->skc_announce_quota = smb_config_getbool(SMB_CI_ANNONCE_QUOTA);
	kcfg->skc_secmode = smb_config_get_secmode();
	(void) smb_getdomainname(kcfg->skc_resource_domain,
	    sizeof (kcfg->skc_resource_domain));
	(void) smb_gethostname(kcfg->skc_hostname, sizeof (kcfg->skc_hostname),
	    1);
	(void) smb_config_getstr(SMB_CI_SYS_CMNT, kcfg->skc_system_comment,
	    sizeof (kcfg->skc_system_comment));
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
	if (smb_gethostname(buf, buflen, 1) != 0)
		return (-1);

	if (buflen >= NETBIOS_NAME_SZ)
		buf[NETBIOS_NAME_SZ - 1] = '\0';

	return (0);
}

/*
 * Get the current system node name.  The returned name is guaranteed
 * to be null-terminated (gethostname may not null terminate the name).
 * If the hostname has been fully-qualified for some reason, the domain
 * part will be removed.  If the caller would like the name in upper
 * case, it is folded to uppercase.
 *
 * If gethostname fails, the returned buffer will contain an empty
 * string.
 */
int
smb_gethostname(char *buf, size_t buflen, int upcase)
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

	if (upcase)
		(void) utf8_strupr(buf);

	return (0);
}

/*
 * Obtain the fully-qualified name for this machine.  If the
 * hostname is fully-qualified, accept it.  Otherwise, try to
 * find an appropriate domain name to append to the hostname.
 */
int
smb_getfqhostname(char *buf, size_t buflen)
{
	char hostname[MAXHOSTNAMELEN];
	char domain[MAXHOSTNAMELEN];

	hostname[0] = '\0';
	domain[0] = '\0';

	if (smb_gethostname(hostname, MAXHOSTNAMELEN, 0) != 0)
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
 * smb_resolve_netbiosname
 *
 * Convert the fully-qualified domain name (i.e. fqdn) to a NETBIOS name.
 * Upon success, the NETBIOS name will be returned via buf parameter.
 * Returns 0 upon success.  Otherwise, returns -1.
 */
int
smb_resolve_netbiosname(char *fqdn, char *buf, size_t buflen)
{
	char *p;

	if (!buf)
		return (-1);

	*buf = '\0';
	if (!fqdn)
		return (-1);

	(void) strlcpy(buf, fqdn, buflen);
	if ((p = strchr(buf, '.')) != NULL)
		*p = 0;

	if (strlen(buf) >= NETBIOS_NAME_SZ)
		buf[NETBIOS_NAME_SZ - 1] = '\0';

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
	char domain[MAXHOSTNAMELEN];
	int rc;

	if (buf == NULL || buflen == 0)
		return (-1);

	*buf = '\0';
	rc = smb_config_getstr(SMB_CI_DOMAIN_NAME, domain,
	    sizeof (domain));

	if ((rc != SMBD_SMF_OK) || (*domain == '\0'))
		return (-1);

	(void) smb_resolve_netbiosname(domain, buf, buflen);
	return (0);
}

/*
 * smb_resolve_fqdn
 *
 * Converts the NETBIOS name of the domain (i.e. nbt_domain) to a fully
 * qualified domain name. The domain from either the domain field or
 * search list field of the /etc/resolv.conf will be returned via the
 * buf parameter if the first label of the domain matches the given
 * NETBIOS name.
 *
 * Returns -1 upon error. If a match is found, returns 1. Otherwise,
 * returns 0.
 */
int
smb_resolve_fqdn(char *nbt_domain, char *buf, size_t buflen)
{
	struct __res_state res_state;
	int i, found = 0;
	char *p;
	int dlen;

	if (!buf)
		return (-1);

	*buf = '\0';
	if (!nbt_domain)
		return (-1);

	bzero(&res_state, sizeof (struct __res_state));
	if (res_ninit(&res_state))
		return (-1);

	if (*nbt_domain == '\0') {
		if (*res_state.defdname == '\0') {
			res_ndestroy(&res_state);
			return (0);
		}

		(void) strlcpy(buf, res_state.defdname, buflen);
		res_ndestroy(&res_state);
		return (1);
	}

	dlen = strlen(nbt_domain);
	if (!strncasecmp(nbt_domain, res_state.defdname, dlen)) {
		(void) strlcpy(buf, res_state.defdname, buflen);
		res_ndestroy(&res_state);
		return (1);
	}

	for (i = 0; (p = res_state.dnsrch[i]) != NULL; i++) {
		if (!strncasecmp(nbt_domain, p, dlen)) {
			(void) strlcpy(buf, p, buflen);
			found = 1;
			break;
		}

	}

	res_ndestroy(&res_state);
	return (found);
}

/*
 * smb_getfqdomainname
 *
 * If the domain_name property value is FQDN, it will be returned.
 * In domain mode, the domain from either the domain field or
 * search list field of the /etc/resolv.conf will be returned via the
 * buf parameter if the first label of the domain matches the
 * domain_name property. In workgroup mode, it returns the local
 * domain.
 *
 * Returns 0 upon success.  Otherwise, returns -1.
 */
int
smb_getfqdomainname(char *buf, size_t buflen)
{
	char domain[MAXHOSTNAMELEN];
	int rc = 0;

	if (buf == NULL || buflen == 0)
		return (-1);

	*buf = '\0';
	if (smb_config_get_secmode() == SMB_SECMODE_DOMAIN) {
		rc = smb_config_getstr(SMB_CI_DOMAIN_NAME, domain,
		    sizeof (domain));

		if ((rc != SMBD_SMF_OK) || (*domain == '\0'))
			return (-1);

		if (strchr(domain, '.') == NULL) {
			if (smb_resolve_fqdn(domain, buf, buflen) != 1)
				rc = -1;
		} else {
			(void) strlcpy(buf, domain, buflen);
		}
	} else {
		if (smb_resolve_fqdn("", buf, buflen) != 1)
			rc = -1;
	}

	return (rc);
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
 */
void
smb_trace(const char *s)
{
	syslog(LOG_DEBUG, "%s", s);
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
	mts_wchar_t wtmp_name[NETBIOS_NAME_SZ];
	unsigned int cpid;
	int len;
	size_t rc;

	len = 0;
	rc = mts_mbstowcs(wtmp_name, (const char *)name, NETBIOS_NAME_SZ);

	if (rc != (size_t)-1) {
		wtmp_name[NETBIOS_NAME_SZ - 1] = 0;
		cpid = oem_get_smb_cpid();
		rc = unicodestooems(tmp_name, wtmp_name, NETBIOS_NAME_SZ, cpid);
		if (rc > 0)
			len = strlen(tmp_name);
	}

	(void) memset(nb_name, ' ', NETBIOS_NAME_SZ - 1);
	if (len) {
		(void) utf8_strupr(tmp_name);
		(void) memcpy(nb_name, tmp_name, len);
	}
	nb_name[NETBIOS_NAME_SZ - 1] = suffix;
}

int
smb_get_nameservers(struct in_addr *ips, int sz)
{
	union res_sockaddr_union set[MAXNS];
	int i, cnt;
	struct __res_state res_state;

	if (ips == NULL)
		return (0);

	bzero(&res_state, sizeof (struct __res_state));
	if (res_ninit(&res_state) < 0)
		return (0);

	cnt = res_getservers(&res_state, set, MAXNS);
	for (i = 0; i < cnt; i++) {
		if (i >= sz)
			break;
		ips[i] = set[i].sin.sin_addr;
		syslog(LOG_DEBUG, "NS Found %s name server\n",
		    inet_ntoa(ips[i]));
	}
	syslog(LOG_DEBUG, "NS Found %d name servers\n", i);
	res_ndestroy(&res_state);
	return (i);
}
