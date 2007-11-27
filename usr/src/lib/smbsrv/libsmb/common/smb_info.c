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
#include <sys/sockio.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/netbios.h>
#include <smbsrv/libsmb.h>

static smb_ntdomain_t smbpdc_cache;
static mutex_t smbpdc_mtx;
static cond_t smbpdc_cv;

extern int getdomainname(char *, int);

uint32_t
smb_get_security_mode()
{
	uint32_t mode;

	smb_config_rdlock();
	mode = smb_config_get_secmode();
	smb_config_unlock();

	return (mode);
}

/*
 * smb_purge_domain_info
 *
 * Clean out the environment in preparation for joining a domain.
 * This ensures that we don't have any old information lying around.
 */
void
smb_purge_domain_info(void)
{
	smb_config_wrlock();
	(void) smb_config_set(SMB_CI_DOMAIN_NAME, 0);
	(void) smb_config_set(SMB_CI_DOMAIN_SID, 0);
	(void) smb_config_set(SMB_CI_DOMAIN_MEMB, 0);
	smb_config_unlock();
}

int
smb_is_domain_member(void)
{
	int is_memb;

	smb_config_rdlock();
	is_memb = smb_config_getyorn(SMB_CI_DOMAIN_MEMB);
	smb_config_unlock();

	return (is_memb);
}

uint8_t
smb_get_fg_flag(void)
{
	uint8_t run_fg;

	smb_config_rdlock();
	run_fg = smb_config_get_fg_flag();
	smb_config_unlock();

	return (run_fg);
}

void
smb_set_domain_member(int set)
{
	char *member;

	smb_config_wrlock();
	member = (set) ? "true" : "false";
	(void) smb_config_set(SMB_CI_DOMAIN_MEMB, member);
	smb_config_unlock();
}

/*
 * smb_set_machine_pwd
 *
 * Returns 0 upon success.  Otherwise, returns 1.
 */
int
smb_set_machine_pwd(char *pwd)
{
	int rc;

	smb_config_wrlock();
	rc = smb_config_set(SMB_CI_MACHINE_PASSWD, pwd);
	smb_config_unlock();
	return (rc);
}

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
	smb_config_rdlock();
	bzero(kcfg, sizeof (smb_kmod_cfg_t));

	kcfg->skc_maxbufsize = smb_config_getnum(SMB_CI_MAX_BUFSIZE);
	kcfg->skc_maxworkers = smb_config_getnum(SMB_CI_MAX_WORKERS);
	kcfg->skc_keepalive = smb_config_getnum(SMB_CI_KEEPALIVE);
	if ((kcfg->skc_keepalive != 0) &&
	    (kcfg->skc_keepalive < SMB_PI_KEEP_ALIVE_MIN))
		kcfg->skc_keepalive = SMB_PI_KEEP_ALIVE_MIN;
	kcfg->skc_restrict_anon = smb_config_getyorn(SMB_CI_RESTRICT_ANON);

	kcfg->skc_signing_enable = smb_config_getyorn(SMB_CI_SIGNING_ENABLE);
	kcfg->skc_signing_required = smb_config_getyorn(SMB_CI_SIGNING_REQD);
	kcfg->skc_signing_check = smb_config_getyorn(SMB_CI_SIGNING_CHECK);

	kcfg->skc_oplock_enable = smb_config_getyorn(SMB_CI_OPLOCK_ENABLE);
	kcfg->skc_oplock_timeout = smb_config_getnum(SMB_CI_OPLOCK_TIMEOUT);

	kcfg->skc_flush_required = smb_config_getyorn(SMB_CI_FLUSH_REQUIRED);
	kcfg->skc_sync_enable = smb_config_getyorn(SMB_CI_SYNC_ENABLE);
	kcfg->skc_dirsymlink_enable =
	    !smb_config_getyorn(SMB_CI_DIRSYMLINK_DISABLE);
	kcfg->skc_announce_quota = smb_config_getyorn(SMB_CI_ANNONCE_QUOTA);
	kcfg->skc_announce_quota = smb_config_getyorn(SMB_CI_ANNONCE_QUOTA);

	kcfg->skc_secmode = smb_config_get_secmode();
	kcfg->skc_lmlevel = smb_config_getnum(SMB_CI_LM_LEVEL);
	kcfg->skc_maxconnections = smb_config_getnum(SMB_CI_MAX_CONNECTIONS);

	(void) strlcpy(kcfg->skc_resource_domain,
	    smb_config_getstr(SMB_CI_DOMAIN_NAME),
	    sizeof (kcfg->skc_resource_domain));

	(void) smb_gethostname(kcfg->skc_hostname,
	    sizeof (kcfg->skc_hostname), 1);

	(void) strlcpy(kcfg->skc_system_comment,
	    smb_config_getstr(SMB_CI_SYS_CMNT),
	    sizeof (kcfg->skc_system_comment));

	smb_config_unlock();
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
 * The ADS domain is often the same as the DNS domain but they can be
 * different - one might be a sub-domain of the other.
 *
 * If an ADS domain name has been configured, return it.  Otherwise,
 * return the DNS domain name.
 *
 * If getdomainname fails, the returned buffer will contain an empty
 * string.
 */
int
smb_getdomainname(char *buf, size_t buflen)
{
	char *domain;

	if (buf == NULL || buflen == 0)
		return (-1);

	smb_config_rdlock();

	domain = smb_config_getstr(SMB_CI_ADS_DOMAIN);
	if ((domain != NULL) && (*domain != '\0')) {
		(void) strlcpy(buf, domain, buflen);
		smb_config_unlock();
		return (0);
	}

	smb_config_unlock();

	if (getdomainname(buf, buflen) != 0) {
		*buf = '\0';
		return (-1);
	}

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

	if (smb_getdomainname(domain, MAXHOSTNAMELEN) != 0)
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
