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

/*
 * This module handles the primary domain controller location protocol.
 * The document claims to be version 1.15 of the browsing protocol. It also
 * claims to specify the mailslot protocol.
 *
 * The NETLOGON protocol uses \MAILSLOT\NET mailslots. The protocol
 * specification is incomplete, contains errors and is out-of-date but
 * it does provide some useful background information. The document
 * doesn't mention the NETLOGON_SAMLOGON version of the protocol.
 */

#include <stdlib.h>
#include <syslog.h>
#include <alloca.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <smbsrv/mailslot.h>
#include <smbsrv/libsmbns.h>
#include <smbns_ads.h>
#include <smbns_browser.h>
#include <smbns_netbios.h>

static void smb_netlogon_query(struct name_entry *server, char *mailbox,
    char *domain);

static void smb_netlogon_samlogon(struct name_entry *server, char *mailbox,
    char *domain);

static void smb_netlogon_send(struct name_entry *name, char *domain,
    unsigned char *buffer, int count);

static void smb_netlogon_rdc_rsp(char *src_name, uint32_t src_ipaddr);
static int better_dc(uint32_t cur_ip, uint32_t new_ip);

static char resource_domain[SMB_PI_MAX_DOMAIN];

/*
 * smb_netlogon_request
 *
 * This is the entry point locating the resource domain PDC. A netlogon
 * request is sent using the specified protocol on the specified network.
 * Note that we need to know the domain SID in order to use the samlogon
 * format.
 *
 * Netlogon responses are received asynchronously and eventually handled
 * in smb_netlogon_receive.
 */
void
smb_netlogon_request(struct name_entry *server, int protocol, char *domain)
{
	nt_domain_t *ntdp;

	if (domain == NULL || *domain == '\0')
		return;

	(void) strlcpy(resource_domain, domain, sizeof (resource_domain));

	ntdp = nt_domain_lookup_name(resource_domain);
	if (ntdp && (protocol == NETLOGON_PROTO_SAMLOGON))
		smb_netlogon_samlogon(server,
		    MAILSLOT_NETLOGON_SAMLOGON_RDC,
		    resource_domain);
	else
		smb_netlogon_query(server,
		    MAILSLOT_NETLOGON_RDC,
		    resource_domain);
}

/*
 * smb_netlogon_receive
 *
 * This is where we handle all incoming NetLogon messages. Currently, we
 * ignore requests from anyone else. We are only interested in responses
 * to our own requests. The NetLogonResponse provides the name of the PDC.
 * If we don't already have a controller name, we use the name provided
 * in the message. Otherwise we use the name already in the environment.
 */
void
smb_netlogon_receive(struct datagram *datagram,
				char *mailbox,
				unsigned char *data,
				int datalen)
{
	struct netlogon_opt {
		char *mailslot;
		void (*handler)();
	} netlogon_opt[] = {
		{ MAILSLOT_NETLOGON_RDC, smb_netlogon_rdc_rsp },
		{ MAILSLOT_NETLOGON_SAMLOGON_RDC, smb_netlogon_rdc_rsp },
	};

	smb_msgbuf_t mb;
	unsigned short opcode;
	char src_name[SMB_PI_MAX_HOST];
	mts_wchar_t unicode_src_name[SMB_PI_MAX_HOST];
	unsigned int cpid = oem_get_smb_cpid();
	uint32_t src_ipaddr;
	char *junk;
	char *primary;
	char *domain;
	int i;
	char ipstr[16];
	int rc;

	src_ipaddr = datagram->src.addr_list.sin.sin_addr.s_addr;

	/*
	 * The datagram->src.name is in oem codepage format.
	 * Therefore, we need to convert it to unicode and
	 * store it in multi-bytes format.
	 */
	(void) oemstounicodes(unicode_src_name, (char *)datagram->src.name,
	    SMB_PI_MAX_HOST, cpid);
	(void) mts_wcstombs(src_name, unicode_src_name, SMB_PI_MAX_HOST);

	(void) trim_whitespace(src_name);

	(void) inet_ntop(AF_INET, (const void *)(&src_ipaddr), ipstr,
	    sizeof (ipstr));
	syslog(LOG_DEBUG, "NetLogonReceive: src=%s [%s], mbx=%s",
	    src_name, ipstr, mailbox);

	smb_msgbuf_init(&mb, data, datalen, 0);

	if (smb_msgbuf_decode(&mb, "w", &opcode) < 0) {
		syslog(LOG_ERR, "NetLogonReceive: decode error");
		smb_msgbuf_term(&mb);
		return;
	}

	switch (opcode) {
	case LOGON_PRIMARY_RESPONSE:
		/*
		 * Message contains:
		 * PDC name (MBS), PDC name (Unicode), Domain name (unicode)
		 */
		rc = smb_msgbuf_decode(&mb, "sUU", &junk, &primary, &domain);
		if (rc < 0) {
			syslog(LOG_ERR,
			    "NetLogonResponse: opcode %d decode error",
			    opcode);
			smb_msgbuf_term(&mb);
			return;
		}
		break;

	case LOGON_SAM_LOGON_RESPONSE:
	case LOGON_SAM_USER_UNKNOWN:
		/*
		 * Message contains:
		 * PDC name, User name, Domain name (all unicode)
		 */
		rc = smb_msgbuf_decode(&mb, "UUU", &primary, &junk, &domain);
		if (rc < 0) {
			syslog(LOG_ERR,
			    "NetLogonResponse: opcode %d decode error",
			    opcode);
			smb_msgbuf_term(&mb);
			return;
		}

		/*
		 * skip past the "\\" prefix
		 */
		primary += strspn(primary, "\\");
		break;

	default:
		/*
		 * We don't respond to PDC discovery requests.
		 */
		syslog(LOG_DEBUG, "NetLogonReceive: opcode 0x%04x", opcode);
		smb_msgbuf_term(&mb);
		return;
	}

	if (domain == 0 || primary == 0) {
		syslog(LOG_ERR, "NetLogonResponse: malformed packet");
		smb_msgbuf_term(&mb);
		return;
	}

	syslog(LOG_DEBUG, "DC Offer Dom=%s PDC=%s From=%s",
	    domain, primary, src_name);

	if (strcasecmp(domain, resource_domain)) {
		syslog(LOG_DEBUG, "NetLogonResponse: other domain "
		    "%s, requested %s", domain, resource_domain);
		smb_msgbuf_term(&mb);
		return;
	}

	for (i = 0; i < sizeof (netlogon_opt)/sizeof (netlogon_opt[0]); ++i) {
		if (strcasecmp(netlogon_opt[i].mailslot, mailbox) == 0) {
			syslog(LOG_DEBUG, "NetLogonReceive: %s", mailbox);
			(*netlogon_opt[i].handler)(primary, src_ipaddr);
			smb_msgbuf_term(&mb);
			return;
		}
	}

	syslog(LOG_DEBUG, "NetLogonReceive[%s]: unknown mailslot", mailbox);
	smb_msgbuf_term(&mb);
}



/*
 * smb_netlogon_query
 *
 * Build and send a LOGON_PRIMARY_QUERY to the MAILSLOT_NETLOGON. At some
 * point we should receive a LOGON_PRIMARY_RESPONSE in the mailslot we
 * specify in the request.
 *
 *  struct NETLOGON_QUERY {
 *	unsigned short Opcode;		# LOGON_PRIMARY_QUERY
 *	char ComputerName[];		# ASCII hostname. The response
 *					# is sent to <ComputerName>(00).
 *	char MailslotName[];		# MAILSLOT_NETLOGON
 *	char Pad[];			# Pad to short
 *	wchar_t ComputerName[]		# UNICODE hostname
 *	DWORD NT_Version;		# 0x00000001
 *	WORD LmNTToken;			# 0xffff
 *	WORD Lm20Token;			# 0xffff
 *  };
 */
static void
smb_netlogon_query(struct name_entry *server,
			char *mailbox,
			char *domain)
{
	smb_msgbuf_t mb;
	int offset, announce_len, data_length, name_lengths;
	unsigned char buffer[MAX_DATAGRAM_LENGTH];
	char hostname[MAXHOSTNAMELEN];

	if (smb_gethostname(hostname, MAXHOSTNAMELEN, 1) != 0)
		return;

	name_lengths = strlen(mailbox)+1+strlen(hostname)+1;

	/*
	 * The (name_lengths & 1) part is to word align the name_lengths
	 * before the wc equiv strlen and the "+ 2" is to cover the two
	 * zero bytes that terminate the wchar string.
	 */
	data_length = sizeof (short) + name_lengths + (name_lengths & 1) +
	    mts_wcequiv_strlen(hostname) + 2 + sizeof (long) + sizeof (short) +
	    sizeof (short);

	offset = smb_browser_load_transact_header(buffer,
	    sizeof (buffer), data_length, ONE_WAY_TRANSACTION,
	    MAILSLOT_NETLOGON);

	if (offset < 0)
		return;

	smb_msgbuf_init(&mb, buffer + offset, sizeof (buffer) - offset, 0);

	announce_len = smb_msgbuf_encode(&mb, "wssUlww",
	    (short)LOGON_PRIMARY_QUERY,
	    hostname,
	    mailbox,
	    hostname,
	    0x1,
	    0xffff,
	    0xffff);

	if (announce_len <= 0) {
		smb_msgbuf_term(&mb);
		syslog(LOG_ERR, "NetLogonQuery: encode error");
		return;
	}

	smb_netlogon_send(server, domain, buffer, offset + announce_len);
	smb_msgbuf_term(&mb);
}


/*
 * smb_netlogon_samlogon
 *
 * The SamLogon version of the NetLogon request uses the workstation trust
 * account and, I think, may be a prerequisite to the challenge/response
 * netr authentication. The trust account username is the hostname with a
 * $ appended. The mailslot for this request is MAILSLOT_NTLOGON. At some
 * we should receive a LOGON_SAM_LOGON_RESPONSE in the mailslot we
 * specify in the request.
 *
 * struct NETLOGON_SAM_LOGON {
 *	unsigned short Opcode;			# LOGON_SAM_LOGON_REQUEST
 *	unsigned short RequestCount;		# 0
 *	wchar_t UnicodeComputerName;		# hostname
 *	wchar_t UnicodeUserName;		# hostname$
 *	char *MailslotName;			# response mailslot
 *	DWORD AllowableAccountControlBits;	# 0x80 = WorkstationTrustAccount
 *	DWORD DomainSidSize;			# domain sid length in bytes
 *	BYTE *DomainSid;			# domain sid
 *	uint32_t   NT_Version;		# 0x00000001
 *	unsigned short  LmNTToken;		# 0xffff
 *	unsigned short  Lm20Token;		# 0xffff
 * };
 */
static void
smb_netlogon_samlogon(struct name_entry *server,
			char *mailbox,
			char *domain)
{
	smb_msgbuf_t mb;
	nt_domain_t *ntdp;
	smb_sid_t *domain_sid;
	unsigned domain_sid_len;
	char *username;
	unsigned char buffer[MAX_DATAGRAM_LENGTH];
	int offset;
	int announce_len;
	int data_length;
	int name_length;
	char hostname[MAXHOSTNAMELEN];

	syslog(LOG_DEBUG, "NetLogonSamLogonReq: %s", domain);

	if ((ntdp = nt_domain_lookup_name(domain)) == 0) {
		syslog(LOG_ERR, "NetLogonSamLogonReq[%s]: no sid", domain);
		return;
	}

	domain_sid = ntdp->sid;
	domain_sid_len = smb_sid_len(domain_sid);

	if (smb_gethostname(hostname, MAXHOSTNAMELEN, 1) != 0)
		return;

	/*
	 * The username will be the trust account name on the PDC.
	 */
	name_length = strlen(hostname) + 2;
	username = alloca(name_length);
	(void) snprintf(username, name_length, "%s$", hostname);

	/*
	 * Add 2 to wide-char equivalent strlen to cover the
	 * two zero bytes that terminate the wchar string.
	 */
	name_length = strlen(mailbox)+1;

	data_length = sizeof (short)
	    + sizeof (short)
	    + mts_wcequiv_strlen(hostname) + 2
	    + mts_wcequiv_strlen(username) + 2
	    + name_length
	    + sizeof (long)
	    + sizeof (long)
	    + domain_sid_len + 3 /* padding */
	    + sizeof (long)
	    + sizeof (short)
	    + sizeof (short);

	offset = smb_browser_load_transact_header(buffer,
	    sizeof (buffer), data_length, ONE_WAY_TRANSACTION,
	    MAILSLOT_NTLOGON);

	if (offset < 0) {
		syslog(LOG_ERR, "NetLogonSamLogonReq: header error");
		return;
	}

	/*
	 * The domain SID is padded with 3 leading zeros.
	 */
	smb_msgbuf_init(&mb, buffer + offset, sizeof (buffer) - offset, 0);
	announce_len = smb_msgbuf_encode(&mb, "wwUUsll3.#clww",
	    (short)LOGON_SAM_LOGON_REQUEST,
	    0,				/* RequestCount */
	    hostname,	/* UnicodeComputerName */
	    username,			/* UnicodeUserName */
	    mailbox,			/* MailslotName */
	    0x00000080,			/* AllowableAccountControlBits */
	    domain_sid_len,		/* DomainSidSize */
	    domain_sid_len, domain_sid,	/* DomainSid */
	    0x00000001,			/* NT_Version */
	    0xffff,			/* LmNTToken */
	    0xffff);			/* Lm20Token */

	if (announce_len <= 0) {
		syslog(LOG_ERR, "NetLogonSamLogonReq: encode error");
		smb_msgbuf_term(&mb);
		return;
	}

	smb_netlogon_send(server, domain, buffer, offset + announce_len);
	smb_msgbuf_term(&mb);
}


/*
 * Send a query for each version of the protocol.
 */
static void
smb_netlogon_send(struct name_entry *name,
			char *domain,
			unsigned char *buffer,
			int count)
{
	static char suffix[] = { 0x1B, 0x1C };
	struct name_entry dname;
	struct name_entry *dest;
	struct name_entry *dest_dup;
	int i;

	for (i = 0; i < sizeof (suffix)/sizeof (suffix[0]); i++) {
		smb_init_name_struct((unsigned char *)domain, suffix[i],
		    0, 0, 0, 0, 0, &dname);

		syslog(LOG_DEBUG, "smb_netlogon_send");
		smb_netbios_name_dump(&dname);
		if ((dest = smb_name_find_name(&dname)) != 0) {
			dest_dup = smb_netbios_name_dup(dest, 1);
			smb_name_unlock_name(dest);
			if (dest_dup) {
				(void) smb_netbios_datagram_send(name, dest_dup,
				    buffer, count);
				free(dest_dup);
			}
		} else {
			syslog(LOG_DEBUG, "smbd: NBNS couldn't find %s<0x%X>",
			    domain, suffix[i]);
		}
	}
}

/*
 * smb_netlogon_rdc_rsp
 *
 * This is where we process netlogon responses for the resource domain.
 * The src_name is the real name of the remote machine.
 */
static void
smb_netlogon_rdc_rsp(char *src_name, uint32_t src_ipaddr)
{
	static int initialized = 0;
	smb_ntdomain_t *pi;
	uint32_t ipaddr;
	uint32_t prefer_ipaddr = 0;
	char ipstr[16];
	char srcip[16];
	int rc;

	(void) inet_ntop(AF_INET, (const void *)(&src_ipaddr),
	    srcip, sizeof (srcip));

	rc = smb_config_getstr(SMB_CI_DOMAIN_SRV, ipstr, sizeof (ipstr));
	if (rc == SMBD_SMF_OK) {
		rc = inet_pton(AF_INET, ipstr, &prefer_ipaddr);
		if (rc == 0)
			prefer_ipaddr = 0;

		if (!initialized) {
			syslog(LOG_DEBUG, "SMB DC Preference: %s", ipstr);
			initialized = 1;
		}
	}

	syslog(LOG_DEBUG, "DC Offer [%s]: %s [%s]",
	    resource_domain, src_name, srcip);

	if ((pi = smb_getdomaininfo(0)) != 0) {
		if (prefer_ipaddr != 0 && prefer_ipaddr == pi->ipaddr) {
			syslog(LOG_DEBUG, "DC for %s: %s [%s]",
			    resource_domain, src_name, srcip);
			return;
		}

		ipaddr = pi->ipaddr;
	} else
		ipaddr = 0;

	if (better_dc(ipaddr, src_ipaddr) ||
	    (prefer_ipaddr != 0 && prefer_ipaddr == src_ipaddr)) {
		smb_setdomaininfo(resource_domain, src_name,
		    src_ipaddr);
		syslog(LOG_DEBUG, "DC discovered for %s: %s [%s]",
		    resource_domain, src_name, srcip);
	}
}

static int
better_dc(uint32_t cur_ip, uint32_t new_ip)
{
	/*
	 * If we don't have any current DC,
	 * then use the new one of course.
	 */
	if (cur_ip == 0)
		return (1);

	if (smb_nic_exists(cur_ip, B_TRUE))
		return (0);

	if (smb_nic_exists(new_ip, B_TRUE))
		return (1);
	/*
	 * Otherwise, just keep the old one.
	 */
	return (0);
}

/*
 * msdcs_lookup_ads
 *
 * Try to find a domain controller in ADS.
 *
 * Parameter:
 *    nbt_domain - NETBIOS name of the domain
 *    server - the ADS server to be sought.
 *
 * Returns 1 if a domain controller was found and its name and IP address
 * have been updated. Otherwise returns 0.
 */
int
msdcs_lookup_ads(char *nbt_domain, char *server)
{
	ADS_HOST_INFO *hinfo = 0;
	int ads_port = 0;
	char ads_domain[MAXHOSTNAMELEN];
	char site_service[MAXHOSTNAMELEN];
	char service[MAXHOSTNAMELEN];
	char site[MAXHOSTNAMELEN];
	char *p;
	char *ip_addr;
	char *nbt_hostname;
	struct in_addr ns_list[MAXNS];
	int i, cnt, go_next;

	if (!nbt_domain)
		return (0);

	(void) strlcpy(resource_domain, nbt_domain, SMB_PI_MAX_DOMAIN);
	if (smb_resolve_fqdn(nbt_domain, ads_domain, MAXHOSTNAMELEN) != 1)
		return (0);

	(void) smb_config_getstr(SMB_CI_ADS_SITE, site, sizeof (site));
	if (*site != '\0') {
		(void) snprintf(site_service, MAXHOSTNAMELEN,
		    "_ldap._tcp.%s._sites.dc._msdcs.%s",
		    site, ads_domain);
	}

	(void) snprintf(service, MAXHOSTNAMELEN,
	    "_ldap._tcp.dc._msdcs.%s", ads_domain);

	cnt = smb_get_nameservers(ns_list, MAXNS);

	go_next = 0;
	for (i = 0; i < cnt; i++) {
		ip_addr = inet_ntoa(ns_list[i]);

		hinfo = ads_find_host(ip_addr, ads_domain, server, &ads_port,
		    site_service, &go_next);

		if (hinfo == NULL) {
			hinfo = ads_find_host(ip_addr, ads_domain, server,
			    &ads_port, service, &go_next);
		}

		if ((hinfo != NULL) || (go_next == 0))
			break;
	}

	if (hinfo == NULL) {
		syslog(LOG_DEBUG, "msdcsLookupADS: unable to find host");
		return (0);
	}

	syslog(LOG_DEBUG, "msdcsLookupADS: %s [%I]", hinfo->name,
	    hinfo->ip_addr);

	/*
	 * Remove the domain extension - the
	 * NetBIOS browser can't handle it.
	 */
	nbt_hostname = strdup(hinfo->name);
	if ((p = strchr(nbt_hostname, '.')) != 0)
		*p = '\0';

	smb_netlogon_rdc_rsp(nbt_hostname, hinfo->ip_addr);
	free(nbt_hostname);

	return (1);
}
