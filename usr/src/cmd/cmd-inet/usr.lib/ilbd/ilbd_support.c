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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stropts.h>
#include <sys/sockio.h>
#include <errno.h>
#include <sys/list.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <secdb.h>
#include <libilb.h>
#include "libilb_impl.h"
#include "ilbd.h"

/*
 * logs error messages, either to stderr or syslog, depending on
 * the -d option
 */
static boolean_t	ilbd_debugging = B_FALSE;

/* Socket to issue ioctl() to the kernel */
static	int	ksock = -1;

void
ilbd_enable_debug(void)
{
	ilbd_debugging = B_TRUE;
}

boolean_t
is_debugging_on(void)
{
	return (ilbd_debugging);
}

/*
 * All routines log to syslog, unless the daemon is running in
 * the foreground, in which case the logging goes to stderr.
 * The following logging functions are available:
 *
 *
 *      logdebug(): A printf-like function for outputting debug messages
 *      (messages at LOG_DEBUG) that are only of use to developers.
 *
 *      logerr(): A printf-like function for outputting error messages
 *      (messages at LOG_ERR) from the daemon.
 *
 *      logperror*(): A set of functions used to output error messages
 *      (messages at LOG_ERR); these automatically append strerror(errno)
 *      and a newline to the message passed to them.
 *
 * NOTE: since the logging functions write to syslog, the messages passed
 *      to them are not eligible for localization.  Thus, gettext() must
 *      *not* be used.
 *
 */
/* PRINTFLIKE2 */
void
ilbd_log(int pri, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (ilbd_debugging == B_TRUE) {
		(void) vfprintf(stderr, fmt, ap);
		(void) fprintf(stderr, "\n");
	} else {
		vsyslog(pri, fmt, ap);
	}
	va_end(ap);

}

/* PRINTFLIKE1 */
void
logperror(const char *str)
{
	if (ilbd_debugging == B_TRUE)
		(void) fprintf(stderr, "%s: %s\n", str, strerror(errno));
	else
		syslog(LOG_ERR, "%s: %m", str);
}


ilb_status_t
ilbd_check_client_config_auth(const struct passwd *pwd)
{
	if (chkauthattr(NET_ILB_CONFIG_AUTH, pwd->pw_name) == 0) {
		logdebug("user %s is not authorized for"
		    " configuration operation", pwd->pw_name);
		return (ILB_STATUS_CFGAUTH);
	}
	return (ILB_STATUS_OK);

}

ilb_status_t
ilbd_check_client_enable_auth(const struct passwd *pwd)
{
	if (chkauthattr(NET_ILB_ENABLE_AUTH, pwd->pw_name) == 0) {
		logdebug("user %s is not authorized for"
		    " enable/disable operation", pwd->pw_name);
		return (ILB_STATUS_CFGAUTH);
	}
	return (ILB_STATUS_OK);

}

/*
 * input param. "err" should be one of the errnos defined in
 * /usr/include/sys/errno.h
 * this list is NOT complete.
 */
ilb_status_t
ilb_map_errno2ilbstat(int err)
{
	ilb_status_t	rc = ILB_STATUS_INTERNAL;

	switch (err) {
	case 0:
		rc = ILB_STATUS_OK; /* for completeness' sake */
		break;
	case EINVAL:
		rc = ILB_STATUS_EINVAL;
		break;
	case ENOENT:
		rc = ILB_STATUS_ENOENT;
		break;
	case ENOMEM:
		rc = ILB_STATUS_ENOMEM;
		break;
	case EINPROGRESS:
		rc = ILB_STATUS_INPROGRESS;
		break;
	case EEXIST:
		rc = ILB_STATUS_EEXIST;
		break;
	}
	return (rc);
}

static int
i_get_kcmd_sz(void *cmdp)
{
	int		sz;

	switch (((ilb_rule_cmd_t *)cmdp)->cmd) {
	case ILB_DESTROY_RULE:
	case ILB_ENABLE_RULE:
	case ILB_DISABLE_RULE:
		sz = sizeof (ilb_name_cmd_t);
		break;
	case ILB_CREATE_RULE:
	case ILB_LIST_RULE:
		sz = sizeof (ilb_rule_cmd_t);
		break;
	case ILB_NUM_RULES:
		sz = sizeof (ilb_num_rules_cmd_t);
		break;
	case ILB_NUM_SERVERS:
		sz = sizeof (ilb_num_servers_cmd_t);
		break;
	case ILB_ADD_SERVERS: {
		ilb_servers_info_cmd_t *kcmd = (ilb_servers_info_cmd_t *)cmdp;

		sz = sizeof (*kcmd) + ((kcmd->num_servers - 1) *
		    sizeof (kcmd->servers));
		break;
	}
	case ILB_RULE_NAMES: {
		ilb_rule_names_cmd_t *kcmd = (ilb_rule_names_cmd_t *)cmdp;

		sz = sizeof (*kcmd) +
		    ((kcmd->num_names - 1) * sizeof (kcmd->buf));
		break;
	}
	case ILB_DEL_SERVERS:
	case ILB_ENABLE_SERVERS:
	case ILB_DISABLE_SERVERS: {
		ilb_servers_cmd_t *kcmd = (ilb_servers_cmd_t *)cmdp;

		sz = sizeof (*kcmd) +
		    ((kcmd->num_servers - 1) * sizeof (kcmd->servers));
		break;
	}
	default: sz = -1;
		break;
	}
	return (sz);
}

/*
 * parameter 'sz' is optional (indicated by == 0); if it's not set
 * we try to derive it from cmdp->cmd
 */
ilb_status_t
do_ioctl(void *cmdp, ssize_t sz)
{
	struct strioctl	ioc;
	int		i_rc;

	if (ksock == -1) {
		ksock = socket(AF_INET, SOCK_DGRAM, 0);
		if (ksock == -1) {
			logperror("do_ioctl: AF_INET socket call"
			    "  failed");
			return (ILB_STATUS_INTERNAL);
		}
	}

	(void) memset(&ioc, 0, sizeof (ioc));
	ioc.ic_cmd = SIOCILB;
	ioc.ic_timout = 0;
	ioc.ic_dp = cmdp;

	if (sz == 0) {
		sz = i_get_kcmd_sz(cmdp);

		if (sz == -1) {
			logdebug("do_ioctl: unknown command");
			return (ILB_STATUS_INVAL_CMD);
		}
	}

	ioc.ic_len = sz;

	i_rc = ioctl(ksock, I_STR, (caddr_t)&ioc);
	if (i_rc == -1) {
		logdebug("do_ioctl: SIOCILB ioctl (%d) failed: %s",
		    *(ilb_cmd_t *)cmdp, strerror(errno));
		return (ilb_map_errno2ilbstat(errno));
	}

	return (ILB_STATUS_OK);
}

/*
 * Create an OK reply to a client request.  It is assumed that the passed
 * in buffer is large enough to hold the reply.
 */
void
ilbd_reply_ok(uint32_t *rbuf, size_t *rbufsz)
{
	ilb_comm_t *ic = (ilb_comm_t *)rbuf;

	ic->ic_cmd = ILBD_CMD_OK;
	/* Default is one exchange of request/response. */
	ic->ic_flags = ILB_COMM_END;
	*rbufsz = sizeof (ilb_comm_t);
}

/*
 * Create an error reply to a client request.  It is assumed that the passed
 * in buffer is large enough to hold the reply.
 */
void
ilbd_reply_err(uint32_t *rbuf, size_t *rbufsz, ilb_status_t status)
{
	ilb_comm_t *ic = (ilb_comm_t *)rbuf;

	ic->ic_cmd = ILBD_CMD_ERROR;
	/* Default is one exchange of request/response. */
	ic->ic_flags = ILB_COMM_END;
	*(ilb_status_t *)&ic->ic_data = status;
	*rbufsz = sizeof (ilb_comm_t) + sizeof (ilb_status_t);
}
