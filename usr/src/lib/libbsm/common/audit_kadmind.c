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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */
#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <rpc/rpc.h>
#include <tiuser.h>
#include <unistd.h>
#include <generic.h>
#include <note.h>

#ifdef C2_DEBUG2
#define	dprintf(x) { (void) printf x; }
#else
#define	dprintf(x)
#endif

/*
 * netbuf2pm()
 *
 * Given an endpt in netbuf form,  return the port and machine.
 * kadmind (currently) only works over IPv4, so only handle IPv4 addresses.
 */
static void
netbuf2pm(
	struct netbuf *addr,
	in_port_t *port,
	uint32_t *machine)
{
	struct sockaddr_in sin4;

	if (!addr) {
		syslog(LOG_DEBUG, "netbuf2pm: addr == NULL");
		return;
	}

	if (!addr->buf) {
		syslog(LOG_DEBUG, "netbuf2pm: addr->buf == NULL");
		return;
	}

	(void) memcpy(&sin4, addr->buf, sizeof (struct sockaddr_in));
	if (sin4.sin_family == AF_INET) {
		if (machine)
			*machine = sin4.sin_addr.s_addr;
		if (port)
			*port = sin4.sin_port;
	} else {
		dprintf(("netbuf2pm: unknown caller IP address family %d",
		    sin4.sin_family));
		syslog(LOG_DEBUG,
		    "netbuf2pm: unknown caller IP address family %d",
		    sin4.sin_family);
	}
}

#define	AUD_NULL_STR(s)		((s) ? (s) : "(null)")

static void
common_audit(
	au_event_t event,	/* audit event */
	SVCXPRT *xprt,		/* net transport handle */
	in_port_t l_port,	/* local port */
	char *op,		/* requested operation */
	char *prime_arg,	/* argument for op */
	char *clnt_name,	/* client principal name */
	int sorf) 		/* flag for success or failure */

{
	auditinfo_t ai;
	in_port_t r_port = 0;
	dev_t port;
	uint32_t machine = 0;
	char text_buf[512];

	dprintf(("common_audit() start\n"));

	/* if auditing turned off, then don't do anything */
	if (cannot_audit(0))
		return;

	(void) aug_save_namask();

	/*
	 * set default values. We will overwrite them if appropriate.
	 */
	if (getaudit(&ai)) {
		perror("kadmind");
		return;
	}
	aug_save_auid(ai.ai_auid);	/* Audit ID */
	aug_save_uid(getuid());		/* User ID */
	aug_save_euid(geteuid());	/* Effective User ID */
	aug_save_gid(getgid());		/* Group ID */
	aug_save_egid(getegid());	/* Effective Group ID */
	aug_save_pid(getpid());		/* process ID */
	aug_save_asid(getpid());	/* session ID */

	aug_save_event(event);
	aug_save_sorf(sorf);

	(void) snprintf(text_buf, sizeof (text_buf), "Op: %s",
		AUD_NULL_STR(op));
	aug_save_text(text_buf);
	(void) snprintf(text_buf, sizeof (text_buf), "Arg: %s",
		AUD_NULL_STR(prime_arg));
	aug_save_text1(text_buf);
	(void) snprintf(text_buf, sizeof (text_buf), "Client: %s",
		AUD_NULL_STR(clnt_name));
	aug_save_text2(text_buf);

	netbuf2pm(svc_getrpccaller(xprt), &r_port, &machine);

	dprintf(("common_audit(): l_port=%d, r_port=%d,\n",
		ntohs(l_port), ntohs(r_port)));

	port = (r_port<<16 | l_port);

	aug_save_tid_ex(port,  &machine, AU_IPv4);

	(void) aug_audit();
}

void
audit_kadmind_auth(
	SVCXPRT *xprt,
	in_port_t l_port,
	char *op,
	char *prime_arg,
	char *clnt_name,
	int sorf)
{
	common_audit(AUE_kadmind_auth, xprt, l_port, op, prime_arg,
	    clnt_name, sorf);
}

void
audit_kadmind_unauth(
	SVCXPRT *xprt,
	in_port_t l_port,
	char *op,
	char *prime_arg,
	char *clnt_name)
{
	common_audit(AUE_kadmind_unauth, xprt, l_port, op, prime_arg,
	    clnt_name, 1);
}
