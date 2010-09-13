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

#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <assert.h>
#include <libilb.h>
#include <libilb_impl.h>
#include <locale.h>

typedef enum {
	internal,
	external
} ip_addr_type_t;

static int
sign64(int64_t n)
{
	if (n >= 0)
		return (1);
	return (-1);
}

static int
sign32(int32_t n)
{
	if (n >= 0)
		return (1);
	return (-1);
}

/*
 * since the difference between two uint64_ts can be greater than
 * what a int64_t can hold, we need to cap the result at +/- INT64_MAX
 * return: < 0: x < y, 0: x == y, > 0: x > y
 */
static int64_t
signed_diff64(uint64_t x, uint64_t y)
{
	uint64_t	ud;
	int		s = -1;

	if (x == y)
		return (0);

	/* make sure we have x < y */
	if (x > y) {
		uint64_t	t;

		s = 1;
		t = x; x = y; y = t;
	}

	ud = y - x;
	if (ud > INT64_MAX)
		return (INT64_MAX * s);

	return ((int64_t)ud * s);
}

static uint64_t
unsigned_diff64(uint64_t x, uint64_t y, int *sgn)
{
	int		s = -1;

	if (x == y)
		return (0);

	/* make sure we have x < y */
	if (x > y) {
		uint64_t	t;

		s = 1;
		t = x; x = y; y = t;
	}
	*sgn = s;
	return (y - x);
}

/*
 * compare ip addresses ip1 and ip2 (as unsigned integers)
 * return: -1: ip1 < ip2, 0: ip1 == ip2, 1: ip1 > ip2
 * input addresses are assumed to be in network byte order
 * diff contains the difference between the two with the same
 * sign as the comparison result;
 * NOTE: since ipv6 address (difference)s can be more than a 64bit
 * value can express, the difference is capped at +/- INT64_MAX
 */
static int
i_cmp_addr_impl(void *ip1, void *ip2, ip_addr_type_t atype, int64_t *diff)
{
	struct in6_addr	*a6_1, *a6_2;
	uint32_t	i1, i2;
	uint32_t	l1, l2;
	int		af, sgn;
	int64_t		d;

	if (atype == internal) {
		af = GET_AF((struct in6_addr *)ip1);
		if (af == AF_INET) {
			IN6_V4MAPPED_TO_IPADDR((struct in6_addr *)ip1, i1);
			IN6_V4MAPPED_TO_IPADDR((struct in6_addr *)ip2, i2);

			l1 = ntohl(i1);
			l2 = ntohl(i2);
		} else {
			a6_1 = (struct in6_addr *)ip1;
			a6_2 = (struct in6_addr *)ip2;
		}
	} else {
		af = ((ilb_ip_addr_t *)ip1)->ia_af;
		if (af == AF_INET) {
			struct in_addr	*a1, *a2;

			a1 = &((ilb_ip_addr_t *)ip1)->ia_v4;
			a2 = &((ilb_ip_addr_t *)ip2)->ia_v4;

			l1 = ntohl((uint32_t)a1->s_addr);
			l2 = ntohl((uint32_t)a2->s_addr);
		} else {
			a6_1 = &((ilb_ip_addr_t *)ip1)->ia_v6;
			a6_2 = &((ilb_ip_addr_t *)ip2)->ia_v6;
		}
	}

	if (af == AF_INET) {
		d = l1 - l2;
		sgn = sign32((int32_t)d);
	} else {
		/*
		 * we're facing the dilemma that 128-bit ipv6 addresses are
		 * larger than the largest integer type - int64_t.
		 * we handle this thus:
		 * 1. seperate high-order and low-order bits (64 each) into
		 *    *h and *l variables (unsigned).
		 * 2. calculate difference for *h and *l:
		 *    low: unsigned
		 *    high: signed
		 * 3. if high-order diff == 0, we can take low-order
		 *    diff, if necessary cap it, convert it to signed
		 *    and be done
		 * 4. if high-order and low-order signs are the same, the low-
		 *    order bits won't significantly impact high-order
		 *    difference, so we know that we've overflowed an int64_t;
		 *    if high-order diff is > 1, any low-order difference won't
		 *    change the overflow.
		 * 5. (dh == 1 and l_sign <= 0) or (dh == -1 and l_sign > 0),
		 *    ie, dh == +/- 2^64
		 *  5a. if dl < INT64_MAX, the result is still > INT64_MAX, so
		 *    we cap again.
		 *  5b. dl >= INT64_MAX
		 *    we need to express (for dh == 1):
		 *    (2^64) + x	(where x < 0).
		 *    Since the largest number we have is
		 *    2^64 - 1 == UINT64_MAX
		 *    we  use
		 *    (2^64 - 1) + x + 1
		 *
		 *    for dh == -1, all we have is
		 *    -(2^63 - 1), so to express
		 *    -(2^64) + x,
		 *    we first do (dl - (2^63-1)) (which is then also < 2^63),
		 *    si we can then add that to  -(2^63 - 1);
		 */
		uint64_t	i1h, i1l;
		uint64_t	i2h, i2l;
		uint64_t	dl;
		int64_t		dh;
		int		l_sign;

		/* 1. */
		i1h = INV6_N2H_MSB64(a6_1);
		i1l = INV6_N2H_LSB64(a6_1);
		i2h = INV6_N2H_MSB64(a6_2);
		i2l = INV6_N2H_LSB64(a6_2);

		/* 2. */
		dh = signed_diff64(i1h, i2h);
		dl = unsigned_diff64(i1l, i2l, &l_sign);

		/* 3. */
		if (dh == 0) {
			if (dl > INT64_MAX)
				dl = INT64_MAX;

			d = dl * l_sign;
		/* 4, */
		} else if (l_sign == sign64(dh) || abs(dh) > 1) {
			if (dh > 0)
				d = INT64_MAX;
			else
				d = -INT64_MAX;
		/* 5. */
		} else {
			if (dl < INT64_MAX) {
				d = INT64_MAX;
			} else {
				if (dh == 1)
					d = UINT64_MAX - dl + 1;
				else
					d = -INT64_MAX - (dl - INT64_MAX) - 1;
			}
		}
		sgn = sign64(d);
	}
	if (diff != NULL)
		*diff = d;
	if (d == 0)
		return (0);
	return (sgn);
}

int
ilb_cmp_in6_addr(struct in6_addr *ip1, struct in6_addr *ip2, int64_t *diff)
{
	int res;

	res = i_cmp_addr_impl(ip1, ip2, internal, diff);
	return (res);
}

int
ilb_cmp_ipaddr(ilb_ip_addr_t *ip1, ilb_ip_addr_t *ip2, int64_t *diff)
{
	int res;

	res = i_cmp_addr_impl(ip1, ip2, external, diff);
	return (res);
}

/*
 * Error strings for error values returned by libilb functions
 */
const char *
ilb_errstr(ilb_status_t rc)
{
	switch (rc) {
	case ILB_STATUS_OK:
		return (dgettext(TEXT_DOMAIN, "no error"));
	case ILB_STATUS_INTERNAL:
		return (dgettext(TEXT_DOMAIN, "error internal to the library"));
	case ILB_STATUS_EINVAL:
		return (dgettext(TEXT_DOMAIN, "invalid argument(s) - see"
		    " man page"));
	case ILB_STATUS_ENOMEM:
		return (dgettext(TEXT_DOMAIN, "not enough memory"
		    " for operation"));
	case ILB_STATUS_ENOENT:
		return (dgettext(TEXT_DOMAIN, "no such/no more element(s)"));
	case ILB_STATUS_SOCKET:
		return (dgettext(TEXT_DOMAIN, "socket() failed"));
	case ILB_STATUS_READ:
		return (dgettext(TEXT_DOMAIN, "read() failed"));
	case ILB_STATUS_WRITE:
		return (dgettext(TEXT_DOMAIN, "fflush() or send() failed"));
	case ILB_STATUS_TIMER:
		return (dgettext(TEXT_DOMAIN, "health check timer"
		    " create/setup error"));
	case ILB_STATUS_INUSE:
		return (dgettext(TEXT_DOMAIN, "object is in use,"
		    " cannot destroy"));
	case ILB_STATUS_EEXIST:
		return (dgettext(TEXT_DOMAIN, "object already exists"));
	case ILB_STATUS_PERMIT:
		return (dgettext(TEXT_DOMAIN, "no scf permit"));
	case ILB_STATUS_CALLBACK:
		return (dgettext(TEXT_DOMAIN, "scf callback error"));
	case ILB_STATUS_INPROGRESS:
		return (dgettext(TEXT_DOMAIN, "operation is progress"));
	case ILB_STATUS_SEND:
		return (dgettext(TEXT_DOMAIN, "send() failed"));
	case ILB_STATUS_ENOHCINFO:
		return (dgettext(TEXT_DOMAIN, "missing healthcheck info"));
	case ILB_STATUS_INVAL_HCTESTTYPE:
		return (dgettext(TEXT_DOMAIN, "invalid  health check"
		    " test type"));
	case ILB_STATUS_INVAL_CMD:
		return (dgettext(TEXT_DOMAIN, "invalid command"));
	case ILB_STATUS_DUP_RULE:
		return (dgettext(TEXT_DOMAIN, "specified rule name already"
		    " exists"));
	case ILB_STATUS_ENORULE:
		return (dgettext(TEXT_DOMAIN, "specified rule does not exist"));
	case ILB_STATUS_MISMATCHSG:
		return (dgettext(TEXT_DOMAIN, "address family mismatch with"
		    " servergroup"));
	case ILB_STATUS_MISMATCHH:
		return (dgettext(TEXT_DOMAIN, "address family mismatch"
		    " with previous hosts in servergroup or with rule"));
	case ILB_STATUS_SGUNAVAIL:
		return (dgettext(TEXT_DOMAIN, "cannot find specified"
		    " server group"));
	case ILB_STATUS_SGINUSE:
		return (dgettext(TEXT_DOMAIN, "cannot remove server"
		    " group - its in use with other active rules"));
	case ILB_STATUS_SGEXISTS:
		return (dgettext(TEXT_DOMAIN, "servergroup already exists"));
	case ILB_STATUS_SGFULL:
		return (dgettext(TEXT_DOMAIN, "servergroup is full - cannot"
		    " add any more servers to this servergroup"));
	case ILB_STATUS_SGEMPTY:
		return (dgettext(TEXT_DOMAIN, "servergroup does not contain"
		    " any servers"));
	case ILB_STATUS_NAMETOOLONG:
		return (dgettext(TEXT_DOMAIN, "servergroup name can"
		    " only contain a maximum of 14 characters"));
	case ILB_STATUS_CFGAUTH:
		return (dgettext(TEXT_DOMAIN, "user is not authorized to"
		    " execute command"));
	case ILB_STATUS_CFGUPDATE:
		return (dgettext(TEXT_DOMAIN, "a failure occurred while trying"
		    " to update persistent config. Panic?"));
	case ILB_STATUS_BADSG:
		return (dgettext(TEXT_DOMAIN, "the rule's port range"
		    " does not match that of the servers' in associated"
		    " servergroup"));
	case ILB_STATUS_INVAL_SRVR:
		return (dgettext(TEXT_DOMAIN, "server cannot be added to the"
		    " servergroup, as the servergroup is associated to rule(s)"
		    " with port/port range that is incompatible"
		    "with the server's port"));
	case ILB_STATUS_INVAL_ENBSRVR:
		return (dgettext(TEXT_DOMAIN, "server cannot be enabled"
		    " because it's not associated with any rule"));
	case ILB_STATUS_BADPORT:
		return (dgettext(TEXT_DOMAIN, "the rule's port value does"
		    " not match that of the servers' in"
		    " associated servergroup"));
	case ILB_STATUS_SRVUNAVAIL:
		return (dgettext(TEXT_DOMAIN, "cannot find specified server"));
	case ILB_STATUS_RULE_NO_HC:
		return (dgettext(TEXT_DOMAIN, "rule does not have health "
		    "check enabled"));
	case ILB_STATUS_RULE_HC_MISMATCH:
		return (dgettext(TEXT_DOMAIN, "protocol used in rule and "
		    "health check does not match"));
	case ILB_STATUS_HANDLE_CLOSING:
		return (dgettext(TEXT_DOMAIN, "handle is being closed"));

	default:
		return (dgettext(TEXT_DOMAIN, "unknown error"));
	}
}

/* Allocate space for a specified request to be sent to ilbd. */
ilb_comm_t *
i_ilb_alloc_req(ilbd_cmd_t cmd, size_t *ic_sz)
{
	ilb_comm_t	*ic;
	size_t		sz;

	sz = sizeof (ilb_comm_t);

	switch (cmd) {
	case ILBD_CREATE_RULE:
		sz += sizeof (ilb_rule_info_t);
		break;

	case ILBD_RETRIEVE_RULE:
	case ILBD_DESTROY_RULE:
	case ILBD_ENABLE_RULE:
	case ILBD_DISABLE_RULE:
	case ILBD_RETRIEVE_SG_HOSTS:
	case ILBD_DESTROY_SERVERGROUP:
	case ILBD_CREATE_SERVERGROUP:
	case ILBD_DESTROY_HC:
	case ILBD_GET_HC_INFO:
	case ILBD_GET_HC_SRVS:
		sz += sizeof (ilbd_name_t);
		break;

	case ILBD_ENABLE_SERVER:
	case ILBD_DISABLE_SERVER:
	case ILBD_ADD_SERVER_TO_GROUP:
	case ILBD_REM_SERVER_FROM_GROUP:
	case ILBD_SRV_ADDR2ID:
	case ILBD_SRV_ID2ADDR:
		sz += sizeof (ilb_sg_info_t) + sizeof (ilb_sg_srv_t);
		break;

	case ILBD_CREATE_HC:
		sz += sizeof (ilb_hc_info_t);
		break;

	default:
		/* Should not reach here. */
		assert(0);
		break;
	}

	if ((ic = calloc(1, sz)) == NULL)
		return (NULL);

	*ic_sz = sz;
	ic->ic_cmd = cmd;
	ic->ic_flags = 0;
	return (ic);
}
