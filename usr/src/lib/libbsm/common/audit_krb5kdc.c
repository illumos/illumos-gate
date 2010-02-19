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
#include <unistd.h>
#include <generic.h>

#ifdef C2_DEBUG2
#define	dprintf(x) { (void) printf x; }
#else
#define	dprintf(x)
#endif

#define	AUD_NULL_STR(s)	((s) ? (s) : "(null)")

void
audit_krb5kdc_setup()
{
	dprintf(("audit_krb5kdc_setup()\n"));

}

static void
common_audit(
	au_event_t event,		/* audit event */
	struct in_addr *r_addr,		/* remote ipv4 addr */
	in_port_t r_port,		/* remote port */
	in_port_t l_port,		/* local port */
	char *cname,			/* client principal name */
	char *sname,			/* requested service name */
	int sorf)			/* flag for success or failure */
{
	auditinfo_t ai;
	dev_t port = 0;
	uint32_t machine;
	char text_buf[512];

	dprintf(("common_audit() start\n"));

	/* if auditing turned off, then don't do anything */
	if (cannot_audit(0))
		return;

	(void) aug_save_namask();

	if (getaudit(&ai)) {
		perror("krb5kdc");
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

	(void) snprintf(text_buf, sizeof (text_buf), "Client: %s",
	    AUD_NULL_STR(cname));
	aug_save_text1(text_buf);
	(void) snprintf(text_buf, sizeof (text_buf), "Service: %s",
	    AUD_NULL_STR(sname));
	aug_save_text2(text_buf);

	dprintf(("audit_krb5kdc: r_port=%d, l_port=%d\n", r_port, l_port));
	port = (htons(r_port)<<16 | htons(l_port));

	machine = r_addr ? (uint32_t)r_addr->s_addr : 0;

	aug_save_tid_ex(port, &machine, AU_IPv4);

	(void) aug_audit();
}

void
audit_krb5kdc_as_req(
	struct in_addr *r_addr,		/* remote ipv4 addr */
	in_port_t r_port,		/* remote port */
	in_port_t l_port,		/* local port */
	char *cname,			/* client principal name */
	char *sname,			/* requested service name */
	int sorf)			/* flag for success or failure */
{
	common_audit(AUE_krb5kdc_as_req, r_addr, r_port, l_port, cname,
	    sname, sorf);
}

void
audit_krb5kdc_tgs_req(
	struct in_addr *r_addr,		/* remote ipv4 addr */
	in_port_t r_port,		/* remote port */
	in_port_t l_port,		/* local port */
	char *cname,			/* client principal name */
	char *sname,			/* requested service name */
	int sorf)			/* flag for success or failure */
{
	common_audit(AUE_krb5kdc_tgs_req, r_addr, r_port, l_port, cname,
	    sname, sorf);
}

void
audit_krb5kdc_tgs_req_2ndtktmm(
	struct in_addr *r_addr,		/* remote ipv4 addr */
	in_port_t r_port,		/* remote port */
	in_port_t l_port,		/* local port */
	char *cname,			/* client principal name */
	char *sname)			/* requested service name */
{
	common_audit(AUE_krb5kdc_tgs_req_2ndtktmm, r_addr, r_port, l_port,
	    cname, sname, 1);
}

void
audit_krb5kdc_tgs_req_alt_tgt(
	struct in_addr *r_addr,		/* remote ipv4 addr */
	in_port_t r_port,		/* remote port */
	in_port_t l_port,		/* local port */
	char *cname,			/* client principal name */
	char *sname,			/* requested service name */
	int sorf)			/* flag for success or failure */
{
	common_audit(AUE_krb5kdc_tgs_req_alt_tgt, r_addr, r_port, l_port,
	    cname, sname, sorf);
}
