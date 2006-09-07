/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <bsm/audit.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <bsm/audit_private.h>
#include <netinet/in.h>
#include <generic.h>
#include <pwd.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef C2_DEBUG
#define	dprintf(x) {printf x; }
#else
#define	dprintf(x)
#endif

static void audit_inetd_session_setup(struct passwd *);
static au_tid_addr_t audit_inetd_tid;
static int auditingisoff;
static au_class_t eventclass;
static int preselected;
static au_mask_t kmask;

int
audit_inetd_config(void)
{
	struct au_event_ent *ee;

	/*
	 * If auditing is turned off, then don't do anything.
	 * Especially don't return an error
	 */
	if (auditingisoff = cannot_audit(0)) {
		return (0);
	}
	aug_save_event(AUE_inetd_connect);
	if (cacheauevent(&ee, AUE_inetd_connect) != 1)
		return (1);

	eventclass = ee->ae_class;

	return (0);
}

/*
 * save terminal ID for user level audit record generation
 */
int
audit_inetd_termid(int fd)
{
	struct sockaddr_in6 peer;
	struct sockaddr_in6 sock;
	int peerlen = sizeof (peer);
	int socklen = sizeof (sock);
	uint_t port;
	uint32_t *addr;
	auditinfo_addr_t ai;

	if (auditingisoff) {
		return (0);
	}

	(void) aug_save_namask();

	/* quick preslection */
	if (auditon(A_GETKMASK, (caddr_t)&kmask, sizeof (kmask)) < 0) {
		/* should generate syslog message here or in inetd.c */
		preselected = 0;
		return (1);
	}

	/* now see if we're preselected. Ignore success/failure for now */
	if ((kmask.am_success|kmask.am_failure) & eventclass) {
		preselected = 1;
	} else {
		preselected = 0;
		return (0);
	}

	/* get peer name (use local termid if not a socket) */
	if (getpeername(fd, (struct sockaddr *)&peer, (socklen_t *)&peerlen)
		< 0) {

		/* use machine terminal address if unknown ports */
		if (auditon(A_GETKAUDIT, (caddr_t)&ai, sizeof (ai)) < 0) {
			return (1);
		}

		/* termid unset, make it legal (0.0.0.0) */
		if (ai.ai_termid.at_type == 0)
			ai.ai_termid.at_type = AU_IPv4;

		audit_inetd_tid = ai.ai_termid;
		aug_save_tid_ex(ai.ai_termid.at_port,
				(uint32_t *)&ai.ai_termid.at_addr,
				(uint32_t)ai.ai_termid.at_type);
		return (0);
	}

	addr = (uint32_t *)&peer.sin6_addr;

	/* get sock name (use local termid if not a socket) */
	if (getsockname(fd, (struct sockaddr *)&sock, (socklen_t *)&socklen)
		< 0) {
		/* have everything but local port. make it 0 for now */
		bzero(&sock, sizeof (sock));
	}

	bzero(&audit_inetd_tid, sizeof (audit_inetd_tid));

	port = ((peer.sin6_port<<16) | (sock.sin6_port));
	audit_inetd_tid.at_port = port;

	if (peer.sin6_family == AF_INET6) {
		aug_save_tid_ex(port, (uint32_t *)&peer.sin6_addr, AU_IPv6);

		audit_inetd_tid.at_type = AU_IPv6;
		audit_inetd_tid.at_addr[0] = addr[0];
		audit_inetd_tid.at_addr[1] = addr[1];
		audit_inetd_tid.at_addr[2] = addr[2];
		audit_inetd_tid.at_addr[3] = addr[3];
	} else {
		struct sockaddr_in *ppeer = (struct sockaddr_in *)&peer;
		aug_save_tid(port, (int)ppeer->sin_addr.s_addr);

		audit_inetd_tid.at_type = AU_IPv4;
		audit_inetd_tid.at_addr[0] = (uint32_t)ppeer->sin_addr.s_addr;
	}
	return (0);
}

int
audit_inetd_service(
		char *service_name,	/* name of service */
		struct passwd *pwd)		/* password */
{
	int	set_audit = 0;	/* flag - set audit characteristics */
	auditinfo_addr_t ai;

	dprintf(("audit_inetd_service()\n"));

	if (auditingisoff)
		return (0);

	if (preselected == 0)
		return (0);

	/*
	 * set default values. We will overwrite them when appropriate.
	 */
	if (getaudit_addr(&ai, sizeof (ai))) {
		perror("inetd");
		exit(1);
	}
	aug_save_auid(ai.ai_auid);	/* Audit ID */
	aug_save_uid(getuid());		/* User ID */
	aug_save_euid(geteuid());	/* Effective User ID */
	aug_save_gid(getgid());		/* Group ID */
	aug_save_egid(getegid());	/* Effective Group ID */
	aug_save_pid(getpid());		/* process ID */
	aug_save_asid(getpid());	/* session ID */

	/*
	 * do the best we can. We have no way to determine if the
	 * request is from a system service or from the root user.
	 * We will consider all root requests to be system service
	 * operations for now. We'll readdress this when we devise a
	 * better algorithm.
	 */
	if (pwd != NULL && (pwd->pw_uid)) {
		aug_save_auid(pwd->pw_uid);	/* Audit ID */
		aug_save_uid(pwd->pw_uid);	/* User ID */
		aug_save_euid(pwd->pw_uid);	/* Effective User ID */
		aug_save_gid(pwd->pw_gid);	/* Group ID */
		aug_save_egid(pwd->pw_gid);	/* Effective Group ID */
		set_audit = 1;
	}

	aug_save_text(service_name);
	aug_save_sorf(0);

	(void) aug_audit();

	/*
	 * Note that we will only do this if non-attributable auditing set.
	 * we might want to change things so this is always called.
	 */
	if (set_audit)
		audit_inetd_session_setup(pwd);

	return (0);
}

/*
 * set the audit characteristics for the inetd started process.
 * inetd is setting the uid.
 */
void
audit_inetd_session_setup(struct passwd *pwd)
{
	struct auditinfo_addr info;
	au_mask_t mask;

	info.ai_auid = pwd->pw_uid;

	mask.am_success = 0;
	mask.am_failure = 0;
	(void) au_user_mask(pwd->pw_name, &mask);
	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_asid = getpid();

	info.ai_termid = audit_inetd_tid;

	if (setaudit_addr(&info, sizeof (info)) < 0) {
		perror("inetd: setaudit_addr");
		exit(1);
	}
}
