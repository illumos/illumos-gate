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
 */

#include <sys/types.h>
#include <errno.h>
#include <synch.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <fcntl.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <bsm/audit_uevents.h>
#include <pwd.h>
#include <nss_dbdefs.h>
#include <sys/idmap.h>
#include "smbd.h"


/*
 * An audit session is established at user logon and terminated at user
 * logoff.
 *
 * SMB audit handles are allocated when users logon (SmbSessionSetupX)
 * and deallocted when a user logs off (SmbLogoffX).  Each time an SMB
 * audit handle is allocated it is added to a global list.
 */
typedef struct smb_audit {
	struct smb_audit *sa_next;
	adt_session_data_t *sa_handle;
	uid_t sa_uid;
	gid_t sa_gid;
	uint32_t sa_audit_sid;
	uint32_t sa_refcnt;
	char *sa_domain;
	char *sa_username;
} smb_audit_t;

static smb_audit_t *smbd_audit_list;
static mutex_t smbd_audit_lock;

/*
 * Unique identifier for audit sessions in the audit list.
 * Used to lookup an audit session on logoff.
 */
static uint32_t smbd_audit_sid;

static void smbd_audit_link(smb_audit_t *);
static smb_audit_t *smbd_audit_unlink(uint32_t);


/*
 * Invoked at user logon due to SmbSessionSetupX.  Authenticate the
 * user, start an audit session and audit the event.
 */
smb_token_t *
smbd_user_auth_logon(smb_logon_t *user_info)
{
	smb_token_t *token;
	smb_audit_t *entry;
	adt_session_data_t *ah;
	adt_event_data_t *event;
	au_tid_addr_t termid;
	char sidbuf[SMB_SID_STRSZ];
	char *username;
	char *domain;
	uid_t uid;
	gid_t gid;
	char *sid;
	int status;
	int retval;

	if ((token = smb_logon(user_info)) == NULL) {
		uid = ADT_NO_ATTRIB;
		gid = ADT_NO_ATTRIB;
		sid = NT_NULL_SIDSTR;
		username = user_info->lg_e_username;
		domain = user_info->lg_e_domain;
		status = ADT_FAILURE;
		retval = ADT_FAIL_VALUE_AUTH;
	} else {
		uid = token->tkn_user.i_id;
		gid = token->tkn_primary_grp.i_id;
		smb_sid_tostr(token->tkn_user.i_sid, sidbuf);
		sid = sidbuf;
		username = token->tkn_account_name;
		domain = token->tkn_domain_name;
		status = ADT_SUCCESS;
		retval = ADT_SUCCESS;
	}

	if (adt_start_session(&ah, NULL, 0)) {
		syslog(LOG_AUTH | LOG_ALERT, "adt_start_session: %m");
		smb_token_destroy(token);
		return (NULL);
	}

	if ((event = adt_alloc_event(ah, ADT_smbd_session)) == NULL) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_alloc_event(ADT_smbd_session): %m");
		(void) adt_end_session(ah);
		smb_token_destroy(token);
		return (NULL);
	}

	(void) memset(&termid, 0, sizeof (au_tid_addr_t));
	termid.at_port = user_info->lg_local_port;

	if (user_info->lg_clnt_ipaddr.a_family == AF_INET) {
		termid.at_addr[0] = user_info->lg_clnt_ipaddr.a_ipv4;
		termid.at_type = AU_IPv4;
	} else {
		bcopy(&user_info->lg_clnt_ipaddr.a_ip, termid.at_addr,
		    sizeof (in6_addr_t));
		termid.at_type = AU_IPv6;
	}
	adt_set_termid(ah, &termid);

	if (adt_set_user(ah, uid, gid, uid, gid, NULL, ADT_NEW)) {
		syslog(LOG_AUTH | LOG_ALERT, "adt_set_user: %m");
		adt_free_event(event);
		(void) adt_end_session(ah);
		smb_token_destroy(token);
		return (NULL);
	}

	event->adt_smbd_session.domain = domain;
	event->adt_smbd_session.username = username;
	event->adt_smbd_session.sid = sid;

	if (adt_put_event(event, status, retval))
		syslog(LOG_AUTH | LOG_ALERT, "adt_put_event: %m");

	adt_free_event(event);

	if (token) {
		if ((entry = malloc(sizeof (smb_audit_t))) == NULL) {
			syslog(LOG_ERR, "smbd_user_auth_logon: %m");
			(void) adt_end_session(ah);
			smb_token_destroy(token);
			return (NULL);
		}

		entry->sa_handle = ah;
		entry->sa_uid = uid;
		entry->sa_gid = gid;
		entry->sa_username = strdup(username);
		entry->sa_domain = strdup(domain);

		smb_autohome_add(token);
		smbd_audit_link(entry);
		token->tkn_audit_sid = entry->sa_audit_sid;
	}

	return (token);
}

/*
 * Logon due to a subsequent SmbSessionSetupX on an existing session.
 * The user was authenticated during the initial session setup.
 */
void
smbd_user_nonauth_logon(uint32_t audit_sid)
{
	smb_audit_t *entry;

	(void) mutex_lock(&smbd_audit_lock);
	entry = smbd_audit_list;

	while (entry) {
		if (entry->sa_audit_sid == audit_sid) {
			++entry->sa_refcnt;
			break;
		}

		entry = entry->sa_next;
	}

	(void) mutex_unlock(&smbd_audit_lock);
}

/*
 * Invoked at user logoff due to SmbLogoffX.  If this is the final
 * logoff for this user on the session, audit the event and terminate
 * the audit session.
 */
void
smbd_user_auth_logoff(uint32_t audit_sid)
{
	smb_audit_t *entry;
	adt_session_data_t *ah;
	adt_event_data_t *event;
	struct passwd pw;
	char buf[NSS_LINELEN_PASSWD];

	if ((entry = smbd_audit_unlink(audit_sid)) == NULL)
		return;

	if (IDMAP_ID_IS_EPHEMERAL(entry->sa_uid)) {
		smb_autohome_remove(entry->sa_username);
	} else {
		if (getpwuid_r(entry->sa_uid, &pw, buf, sizeof (buf)) == NULL)
			return;

		smb_autohome_remove(pw.pw_name);
	}

	ah = entry->sa_handle;

	if ((event = adt_alloc_event(ah, ADT_smbd_logoff)) == NULL) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_alloc_event(ADT_smbd_logoff): %m");
	} else {
		event->adt_smbd_logoff.domain = entry->sa_domain;
		event->adt_smbd_logoff.username = entry->sa_username;

		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS))
			syslog(LOG_AUTH | LOG_ALERT, "adt_put_event: %m");

		adt_free_event(event);
	}

	(void) adt_end_session(ah);

	free(entry->sa_username);
	free(entry->sa_domain);
	free(entry);
}

/*
 * Allocate an id and link an audit handle onto the global list.
 */
static void
smbd_audit_link(smb_audit_t *entry)
{
	(void) mutex_lock(&smbd_audit_lock);

	do {
		++smbd_audit_sid;
	} while ((smbd_audit_sid == 0) || (smbd_audit_sid == (uint32_t)-1));

	entry->sa_audit_sid = smbd_audit_sid;
	entry->sa_refcnt = 1;
	entry->sa_next = smbd_audit_list;
	smbd_audit_list = entry;

	(void) mutex_unlock(&smbd_audit_lock);
}

/*
 * Unlink an audit handle.  If the reference count reaches 0, the entry
 * is removed from the list and returned.  Otherwise the entry remains
 * on the list and a null pointer is returned.
 */
static smb_audit_t *
smbd_audit_unlink(uint32_t audit_sid)
{
	smb_audit_t *entry;
	smb_audit_t **ppe;

	(void) mutex_lock(&smbd_audit_lock);
	ppe = &smbd_audit_list;

	while (*ppe) {
		entry = *ppe;

		if (entry->sa_audit_sid == audit_sid) {
			if (entry->sa_refcnt == 0)
				break;

			if ((--entry->sa_refcnt) != 0)
				break;

			*ppe = entry->sa_next;
			(void) mutex_unlock(&smbd_audit_lock);
			return (entry);
		}

		ppe = &(*ppe)->sa_next;
	}

	(void) mutex_unlock(&smbd_audit_lock);
	return (NULL);
}
