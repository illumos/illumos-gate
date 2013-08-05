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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

/*
 * This file contains routines that are used to modify/retrieve protocol or
 * interface property values. It also holds all the supported properties for
 * both IP interface and protocols in `ipadm_prop_desc_t'. Following protocols
 * are supported: IP, IPv4, IPv6, TCP, SCTP, UDP and ICMP.
 *
 * This file also contains walkers, which walks through the property table and
 * calls the callback function, of the form `ipadm_prop_wfunc_t' , for every
 * property in the table.
 */

#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <strings.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sockio.h>
#include <assert.h>
#include <libdllink.h>
#include <zone.h>
#include "libipadm_impl.h"
#include <inet/tunables.h>

#define	IPADM_NONESTR		"none"
#define	DEF_METRIC_VAL		0	/* default metric value */

#define	A_CNT(arr)	(sizeof (arr) / sizeof (arr[0]))

static ipadm_status_t	i_ipadm_validate_if(ipadm_handle_t, const char *,
			    uint_t, uint_t);

/*
 * Callback functions to retrieve property values from the kernel. These
 * functions, when required, translate the values from the kernel to a format
 * suitable for printing. For example: boolean values will be translated
 * to on/off. They also retrieve DEFAULT, PERM and POSSIBLE values for
 * a given property.
 */
static ipadm_pd_getf_t	i_ipadm_get_prop, i_ipadm_get_ifprop_flags,
			i_ipadm_get_mtu, i_ipadm_get_metric,
			i_ipadm_get_usesrc, i_ipadm_get_forwarding,
			i_ipadm_get_ecnsack, i_ipadm_get_hostmodel;

/*
 * Callback function to set property values. These functions translate the
 * values to a format suitable for kernel consumption, allocates the necessary
 * ioctl buffers and then invokes ioctl().
 */
static ipadm_pd_setf_t	i_ipadm_set_prop, i_ipadm_set_mtu,
			i_ipadm_set_ifprop_flags,
			i_ipadm_set_metric, i_ipadm_set_usesrc,
			i_ipadm_set_forwarding, i_ipadm_set_eprivport,
			i_ipadm_set_ecnsack, i_ipadm_set_hostmodel;

/* array of protocols we support */
static int protocols[] = { MOD_PROTO_IP, MOD_PROTO_RAWIP,
			    MOD_PROTO_TCP, MOD_PROTO_UDP,
			    MOD_PROTO_SCTP };

/*
 * Supported IP protocol properties.
 */
static ipadm_prop_desc_t ipadm_ip_prop_table[] = {
	{ "arp", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV4, 0,
	    i_ipadm_set_ifprop_flags, i_ipadm_get_onoff,
	    i_ipadm_get_ifprop_flags },

	{ "forwarding", NULL, IPADMPROP_CLASS_MODIF, MOD_PROTO_IPV4, 0,
	    i_ipadm_set_forwarding, i_ipadm_get_onoff,
	    i_ipadm_get_forwarding },

	{ "metric", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV4, 0,
	    i_ipadm_set_metric, NULL, i_ipadm_get_metric },

	{ "mtu", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV4, 0,
	    i_ipadm_set_mtu, i_ipadm_get_mtu, i_ipadm_get_mtu },

	{ "exchange_routes", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV4, 0,
	    i_ipadm_set_ifprop_flags, i_ipadm_get_onoff,
	    i_ipadm_get_ifprop_flags },

	{ "usesrc", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV4, 0,
	    i_ipadm_set_usesrc, NULL, i_ipadm_get_usesrc },

	{ "ttl", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_IPV4, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "forwarding", NULL, IPADMPROP_CLASS_MODIF, MOD_PROTO_IPV6, 0,
	    i_ipadm_set_forwarding, i_ipadm_get_onoff,
	    i_ipadm_get_forwarding },

	{ "hoplimit", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_IPV6, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "metric", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV6, 0,
	    i_ipadm_set_metric, NULL, i_ipadm_get_metric },

	{ "mtu", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV6, 0,
	    i_ipadm_set_mtu, i_ipadm_get_mtu, i_ipadm_get_mtu },

	{ "nud", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV6, 0,
	    i_ipadm_set_ifprop_flags, i_ipadm_get_onoff,
	    i_ipadm_get_ifprop_flags },

	{ "exchange_routes", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV6, 0,
	    i_ipadm_set_ifprop_flags, i_ipadm_get_onoff,
	    i_ipadm_get_ifprop_flags },

	{ "usesrc", NULL, IPADMPROP_CLASS_IF, MOD_PROTO_IPV6, 0,
	    i_ipadm_set_usesrc, NULL, i_ipadm_get_usesrc },

	{ "hostmodel", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_IPV6, 0,
	    i_ipadm_set_hostmodel, i_ipadm_get_hostmodel,
	    i_ipadm_get_hostmodel },

	{ "hostmodel", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_IPV4, 0,
	    i_ipadm_set_hostmodel, i_ipadm_get_hostmodel,
	    i_ipadm_get_hostmodel },

	{ NULL, NULL, 0, 0, 0, NULL, NULL, NULL }
};

/* possible values for TCP properties `ecn' and `sack' */
static const char *ecn_sack_vals[] = {"never", "passive", "active", NULL};

/* Supported TCP protocol properties */
static ipadm_prop_desc_t ipadm_tcp_prop_table[] = {
	{ "ecn", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_TCP, 0,
	    i_ipadm_set_ecnsack, i_ipadm_get_ecnsack, i_ipadm_get_ecnsack },

	{ "extra_priv_ports", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_TCP,
	    IPADMPROP_MULVAL, i_ipadm_set_eprivport, i_ipadm_get_prop,
	    i_ipadm_get_prop },

	{ "largest_anon_port", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_TCP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "max_buf", "_max_buf", IPADMPROP_CLASS_MODULE, MOD_PROTO_TCP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "recv_buf", "recv_maxbuf", IPADMPROP_CLASS_MODULE, MOD_PROTO_TCP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "sack", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_TCP, 0,
	    i_ipadm_set_ecnsack, i_ipadm_get_ecnsack, i_ipadm_get_ecnsack },

	{ "send_buf", "send_maxbuf", IPADMPROP_CLASS_MODULE, MOD_PROTO_TCP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "smallest_anon_port", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_TCP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "smallest_nonpriv_port", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_TCP,
	    0, i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ NULL, NULL, 0, 0, 0, NULL, NULL, NULL }
};

/* Supported UDP protocol properties */
static ipadm_prop_desc_t ipadm_udp_prop_table[] = {
	{ "extra_priv_ports", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_UDP,
	    IPADMPROP_MULVAL, i_ipadm_set_eprivport, i_ipadm_get_prop,
	    i_ipadm_get_prop },

	{ "largest_anon_port", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_UDP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "max_buf", "_max_buf", IPADMPROP_CLASS_MODULE, MOD_PROTO_UDP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "recv_buf", "recv_maxbuf", IPADMPROP_CLASS_MODULE, MOD_PROTO_UDP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "send_buf", "send_maxbuf", IPADMPROP_CLASS_MODULE, MOD_PROTO_UDP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "smallest_anon_port", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_UDP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "smallest_nonpriv_port", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_UDP,
	    0, i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ NULL, NULL, 0, 0, 0, NULL, NULL, NULL }
};

/* Supported SCTP protocol properties */
static ipadm_prop_desc_t ipadm_sctp_prop_table[] = {
	{ "extra_priv_ports", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_SCTP,
	    IPADMPROP_MULVAL, i_ipadm_set_eprivport, i_ipadm_get_prop,
	    i_ipadm_get_prop },

	{ "largest_anon_port", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_SCTP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "max_buf", "_max_buf", IPADMPROP_CLASS_MODULE, MOD_PROTO_SCTP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "recv_buf", "recv_maxbuf", IPADMPROP_CLASS_MODULE, MOD_PROTO_SCTP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "send_buf", "send_maxbuf", IPADMPROP_CLASS_MODULE, MOD_PROTO_SCTP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "smallest_anon_port", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_SCTP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "smallest_nonpriv_port", NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_SCTP,
	    0, i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ NULL, NULL, 0, 0, 0, NULL, NULL, NULL }
};

/* Supported ICMP protocol properties */
static ipadm_prop_desc_t ipadm_icmp_prop_table[] = {
	{ "max_buf", "_max_buf", IPADMPROP_CLASS_MODULE, MOD_PROTO_RAWIP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "recv_buf", "recv_maxbuf", IPADMPROP_CLASS_MODULE, MOD_PROTO_RAWIP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ "send_buf", "send_maxbuf", IPADMPROP_CLASS_MODULE, MOD_PROTO_RAWIP, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop },

	{ NULL, NULL, 0, 0, 0, NULL, NULL, NULL }
};

/*
 * A dummy private property structure, used while handling private
 * protocol properties (properties not yet supported by libipadm).
 */
static ipadm_prop_desc_t ipadm_privprop =
	{ NULL, NULL, IPADMPROP_CLASS_MODULE, MOD_PROTO_NONE, 0,
	    i_ipadm_set_prop, i_ipadm_get_prop, i_ipadm_get_prop };

/*
 * Returns the property description table, for the given protocol
 */
static ipadm_prop_desc_t *
i_ipadm_get_propdesc_table(uint_t proto)
{
	switch (proto) {
	case MOD_PROTO_IP:
	case MOD_PROTO_IPV4:
	case MOD_PROTO_IPV6:
		return (ipadm_ip_prop_table);
	case MOD_PROTO_RAWIP:
		return (ipadm_icmp_prop_table);
	case MOD_PROTO_TCP:
		return (ipadm_tcp_prop_table);
	case MOD_PROTO_UDP:
		return (ipadm_udp_prop_table);
	case MOD_PROTO_SCTP:
		return (ipadm_sctp_prop_table);
	}

	return (NULL);
}

static ipadm_prop_desc_t *
i_ipadm_get_prop_desc(const char *pname, uint_t proto, int *errp)
{
	int		err = 0;
	boolean_t	matched_name = B_FALSE;
	ipadm_prop_desc_t *ipdp = NULL, *ipdtbl;

	if ((ipdtbl = i_ipadm_get_propdesc_table(proto)) == NULL) {
		err = EINVAL;
		goto ret;
	}

	for (ipdp = ipdtbl; ipdp->ipd_name != NULL; ipdp++) {
		if (strcmp(pname, ipdp->ipd_name) == 0 ||
		    (ipdp->ipd_old_name != NULL &&
		    strcmp(pname, ipdp->ipd_old_name) == 0)) {
			matched_name = B_TRUE;
			if (ipdp->ipd_proto == proto)
				break;
		}
	}

	if (ipdp->ipd_name == NULL) {
		err = ENOENT;
		/* if we matched name, but failed protocol check */
		if (matched_name)
			err = EPROTO;
		ipdp = NULL;
	}
ret:
	if (errp != NULL)
		*errp = err;
	return (ipdp);
}

char *
ipadm_proto2str(uint_t proto)
{
	switch (proto) {
	case MOD_PROTO_IP:
		return ("ip");
	case MOD_PROTO_IPV4:
		return ("ipv4");
	case MOD_PROTO_IPV6:
		return ("ipv6");
	case MOD_PROTO_RAWIP:
		return ("icmp");
	case MOD_PROTO_TCP:
		return ("tcp");
	case MOD_PROTO_UDP:
		return ("udp");
	case MOD_PROTO_SCTP:
		return ("sctp");
	}

	return (NULL);
}

uint_t
ipadm_str2proto(const char *protostr)
{
	if (protostr == NULL)
		return (MOD_PROTO_NONE);
	if (strcmp(protostr, "tcp") == 0)
		return (MOD_PROTO_TCP);
	else if (strcmp(protostr, "udp") == 0)
		return (MOD_PROTO_UDP);
	else if (strcmp(protostr, "ip") == 0)
		return (MOD_PROTO_IP);
	else if (strcmp(protostr, "ipv4") == 0)
		return (MOD_PROTO_IPV4);
	else if (strcmp(protostr, "ipv6") == 0)
		return (MOD_PROTO_IPV6);
	else if (strcmp(protostr, "icmp") == 0)
		return (MOD_PROTO_RAWIP);
	else if (strcmp(protostr, "sctp") == 0)
		return (MOD_PROTO_SCTP);
	else if (strcmp(protostr, "arp") == 0)
		return (MOD_PROTO_IP);

	return (MOD_PROTO_NONE);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_mtu(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t proto, uint_t flags)
{
	struct lifreq	lifr;
	char		*endp;
	uint_t		mtu;
	int		s;
	const char	*ifname = arg;
	char		val[MAXPROPVALLEN];

	/* to reset MTU first retrieve the default MTU and then set it */
	if (flags & IPADM_OPT_DEFAULT) {
		ipadm_status_t	status;
		uint_t		size = MAXPROPVALLEN;

		status = i_ipadm_get_prop(iph, arg, pdp, val, &size,
		    proto, MOD_PROP_DEFAULT);
		if (status != IPADM_SUCCESS)
			return (status);
		pval = val;
	}

	errno = 0;
	mtu = (uint_t)strtol(pval, &endp, 10);
	if (errno != 0 || *endp != '\0')
		return (IPADM_INVALID_ARG);

	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	lifr.lifr_mtu = mtu;

	s = (proto == MOD_PROTO_IPV6 ? iph->iph_sock6 : iph->iph_sock);
	if (ioctl(s, SIOCSLIFMTU, (caddr_t)&lifr) < 0)
		return (ipadm_errno2status(errno));

	return (IPADM_SUCCESS);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_metric(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t proto, uint_t flags)
{
	struct lifreq	lifr;
	char		*endp;
	int		metric;
	const char	*ifname = arg;
	int		s;

	/* if we are resetting, set the value to its default value */
	if (flags & IPADM_OPT_DEFAULT) {
		metric = DEF_METRIC_VAL;
	} else {
		errno = 0;
		metric = (uint_t)strtol(pval, &endp, 10);
		if (errno != 0 || *endp != '\0')
			return (IPADM_INVALID_ARG);
	}

	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	lifr.lifr_metric = metric;

	s = (proto == MOD_PROTO_IPV6 ? iph->iph_sock6 : iph->iph_sock);

	if (ioctl(s, SIOCSLIFMETRIC, (caddr_t)&lifr) < 0)
		return (ipadm_errno2status(errno));

	return (IPADM_SUCCESS);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_usesrc(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t proto, uint_t flags)
{
	struct lifreq	lifr;
	const char	*ifname = arg;
	int		s;
	uint_t		ifindex = 0;

	/* if we are resetting, set the value to its default value */
	if (flags & IPADM_OPT_DEFAULT)
		pval = IPADM_NONESTR;

	/*
	 * cannot specify logical interface name. We can also filter out other
	 * bogus interface names here itself through i_ipadm_validate_ifname().
	 */
	if (strcmp(pval, IPADM_NONESTR) != 0 &&
	    !i_ipadm_validate_ifname(iph, pval))
		return (IPADM_INVALID_ARG);

	bzero(&lifr, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));

	s = (proto == MOD_PROTO_IPV6 ? iph->iph_sock6 : iph->iph_sock);

	if (strcmp(pval, IPADM_NONESTR) != 0) {
		if ((ifindex = if_nametoindex(pval)) == 0)
			return (ipadm_errno2status(errno));
		lifr.lifr_index = ifindex;
	} else {
		if (ioctl(s, SIOCGLIFUSESRC, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
		lifr.lifr_index = 0;
	}
	if (ioctl(s, SIOCSLIFUSESRC, (caddr_t)&lifr) < 0)
		return (ipadm_errno2status(errno));

	return (IPADM_SUCCESS);
}

static struct hostmodel_strval {
	char *esm_str;
	ip_hostmodel_t esm_val;
} esm_arr[] = {
	{"weak", IP_WEAK_ES},
	{"src-priority", IP_SRC_PRI_ES},
	{"strong", IP_STRONG_ES},
	{"custom", IP_MAXVAL_ES}
};

static ip_hostmodel_t
i_ipadm_hostmodel_str2val(const char *pval)
{
	int i;

	for (i = 0; i < A_CNT(esm_arr); i++) {
		if (esm_arr[i].esm_str != NULL &&
		    strcmp(pval, esm_arr[i].esm_str) == 0) {
			return (esm_arr[i].esm_val);
		}
	}
	return (IP_MAXVAL_ES);
}

static char *
i_ipadm_hostmodel_val2str(ip_hostmodel_t pval)
{
	int i;

	for (i = 0; i < A_CNT(esm_arr); i++) {
		if (esm_arr[i].esm_val == pval)
			return (esm_arr[i].esm_str);
	}
	return (NULL);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_hostmodel(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t proto, uint_t flags)
{
	ip_hostmodel_t hostmodel;
	char val[11]; /* covers uint32_max as a string */

	if ((flags & IPADM_OPT_DEFAULT) == 0) {
		hostmodel = i_ipadm_hostmodel_str2val(pval);
		if (hostmodel == IP_MAXVAL_ES)
			return (IPADM_INVALID_ARG);
		(void) snprintf(val, sizeof (val), "%d", hostmodel);
		pval = val;
	}
	return (i_ipadm_set_prop(iph, NULL, pdp, pval, proto, flags));
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_hostmodel(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t proto,
    uint_t valtype)
{
	ip_hostmodel_t hostmodel;
	char *cp;
	size_t nbytes;
	ipadm_status_t status;

	switch (valtype) {
	case MOD_PROP_PERM:
		nbytes = snprintf(buf, *bufsize, "%d", MOD_PROP_PERM_RW);
		break;
	case MOD_PROP_DEFAULT:
		nbytes = snprintf(buf, *bufsize, "weak");
		break;
	case MOD_PROP_ACTIVE:
		status = i_ipadm_get_prop(iph, arg, pdp, buf, bufsize, proto,
		    valtype);
		if (status != IPADM_SUCCESS)
			return (status);
		bcopy(buf, &hostmodel, sizeof (hostmodel));
		cp = i_ipadm_hostmodel_val2str(hostmodel);
		nbytes = snprintf(buf, *bufsize, "%s",
		    (cp != NULL ? cp : "?"));
		break;
	case MOD_PROP_POSSIBLE:
		nbytes = snprintf(buf, *bufsize, "strong,src-priority,weak");
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}
	return (IPADM_SUCCESS);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_ifprop_flags(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t proto, uint_t flags)
{
	ipadm_status_t	status = IPADM_SUCCESS;
	const char	*ifname = arg;
	uint64_t	on_flags = 0, off_flags = 0;
	boolean_t	on = B_FALSE;
	sa_family_t	af = (proto == MOD_PROTO_IPV6 ? AF_INET6 : AF_INET);

	/* if we are resetting, set the value to its default value */
	if (flags & IPADM_OPT_DEFAULT) {
		if (strcmp(pdp->ipd_name, "exchange_routes") == 0 ||
		    strcmp(pdp->ipd_name, "arp") == 0 ||
		    strcmp(pdp->ipd_name, "nud") == 0) {
			pval = IPADM_ONSTR;
		} else if (strcmp(pdp->ipd_name, "forwarding") == 0) {
			pval = IPADM_OFFSTR;
		} else {
			return (IPADM_PROP_UNKNOWN);
		}
	}

	if (strcmp(pval, IPADM_ONSTR) == 0)
		on = B_TRUE;
	else if (strcmp(pval, IPADM_OFFSTR) == 0)
		on = B_FALSE;
	else
		return (IPADM_INVALID_ARG);

	if (strcmp(pdp->ipd_name, "exchange_routes") == 0) {
		if (on)
			off_flags = IFF_NORTEXCH;
		else
			on_flags = IFF_NORTEXCH;
	} else if (strcmp(pdp->ipd_name, "arp") == 0) {
		if (on)
			off_flags = IFF_NOARP;
		else
			on_flags = IFF_NOARP;
	} else if (strcmp(pdp->ipd_name, "nud") == 0) {
		if (on)
			off_flags = IFF_NONUD;
		else
			on_flags = IFF_NONUD;
	} else if (strcmp(pdp->ipd_name, "forwarding") == 0) {
		if (on)
			on_flags = IFF_ROUTER;
		else
			off_flags = IFF_ROUTER;
	}

	if (on_flags || off_flags)  {
		status = i_ipadm_set_flags(iph, ifname, af, on_flags,
		    off_flags);
	}
	return (status);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_eprivport(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t proto, uint_t flags)
{
	nvlist_t	*portsnvl = NULL;
	nvpair_t	*nvp;
	ipadm_status_t	status = IPADM_SUCCESS;
	int		err;
	uint_t		count = 0;

	if (flags & IPADM_OPT_DEFAULT) {
		assert(pval == NULL);
		return (i_ipadm_set_prop(iph, arg, pdp, pval, proto, flags));
	}

	if ((err = ipadm_str2nvlist(pval, &portsnvl, IPADM_NORVAL)) != 0)
		return (ipadm_errno2status(err));

	/* count the number of ports */
	for (nvp = nvlist_next_nvpair(portsnvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(portsnvl, nvp)) {
		++count;
	}

	if (iph->iph_flags & IPH_INIT) {
		flags |= IPADM_OPT_APPEND;
	} else if (count > 1) {
		/*
		 * We allow only one port to be added, removed or
		 * assigned at a time.
		 *
		 * However on reboot, while initializing protocol
		 * properties, extra_priv_ports might have multiple
		 * values. Only in that case we allow setting multiple
		 * values.
		 */
		nvlist_free(portsnvl);
		return (IPADM_INVALID_ARG);
	}

	for (nvp = nvlist_next_nvpair(portsnvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(portsnvl, nvp)) {
		status = i_ipadm_set_prop(iph, arg, pdp, nvpair_name(nvp),
		    proto, flags);
		if (status != IPADM_SUCCESS)
			break;
	}
	nvlist_free(portsnvl);
	return (status);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_forwarding(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t proto, uint_t flags)
{
	const char	*ifname = arg;
	ipadm_status_t	status;

	/*
	 * if interface name is provided, then set forwarding using the
	 * IFF_ROUTER flag
	 */
	if (ifname != NULL) {
		status = i_ipadm_set_ifprop_flags(iph, ifname, pdp, pval,
		    proto, flags);
	} else {
		char	*val = NULL;

		/*
		 * if the caller is IPH_LEGACY, `pval' already contains
		 * numeric values.
		 */
		if (!(flags & IPADM_OPT_DEFAULT) &&
		    !(iph->iph_flags & IPH_LEGACY)) {

			if (strcmp(pval, IPADM_ONSTR) == 0)
				val = "1";
			else if (strcmp(pval, IPADM_OFFSTR) == 0)
				val = "0";
			else
				return (IPADM_INVALID_ARG);
			pval = val;
		}

		status = i_ipadm_set_prop(iph, ifname, pdp, pval, proto, flags);
	}

	return (status);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_set_ecnsack(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t proto, uint_t flags)
{
	uint_t		i;
	char		val[MAXPROPVALLEN];

	/* if IPH_LEGACY is set, `pval' already contains numeric values */
	if (!(flags & IPADM_OPT_DEFAULT) && !(iph->iph_flags & IPH_LEGACY)) {
		for (i = 0; ecn_sack_vals[i] != NULL; i++) {
			if (strcmp(pval, ecn_sack_vals[i]) == 0)
				break;
		}
		if (ecn_sack_vals[i] == NULL)
			return (IPADM_INVALID_ARG);
		(void) snprintf(val, MAXPROPVALLEN, "%d", i);
		pval = val;
	}

	return (i_ipadm_set_prop(iph, arg, pdp, pval, proto, flags));
}

/* ARGSUSED */
ipadm_status_t
i_ipadm_get_ecnsack(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t proto,
    uint_t valtype)
{
	ipadm_status_t	status = IPADM_SUCCESS;
	uint_t		i, nbytes = 0;

	switch (valtype) {
	case MOD_PROP_POSSIBLE:
		for (i = 0; ecn_sack_vals[i] != NULL; i++) {
			if (i == 0)
				nbytes += snprintf(buf + nbytes,
				    *bufsize - nbytes, "%s", ecn_sack_vals[i]);
			else
				nbytes += snprintf(buf + nbytes,
				    *bufsize - nbytes, ",%s", ecn_sack_vals[i]);
			if (nbytes >= *bufsize)
				break;
		}
		break;
	case MOD_PROP_PERM:
	case MOD_PROP_DEFAULT:
	case MOD_PROP_ACTIVE:
		status = i_ipadm_get_prop(iph, arg, pdp, buf, bufsize, proto,
		    valtype);

		/*
		 * If IPH_LEGACY is set, do not convert the value returned
		 * from kernel,
		 */
		if (iph->iph_flags & IPH_LEGACY)
			break;

		/*
		 * For current and default value, convert the value returned
		 * from kernel to more discrete representation.
		 */
		if (status == IPADM_SUCCESS && (valtype == MOD_PROP_ACTIVE ||
		    valtype == MOD_PROP_DEFAULT)) {
			i = atoi(buf);
			assert(i < 3);
			nbytes = snprintf(buf, *bufsize, "%s",
			    ecn_sack_vals[i]);
		}
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}

	return (status);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_forwarding(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t proto,
    uint_t valtype)
{
	const char	*ifname = arg;
	ipadm_status_t	status = IPADM_SUCCESS;

	/*
	 * if interface name is provided, then get forwarding status using
	 * SIOCGLIFFLAGS
	 */
	if (ifname != NULL) {
		status = i_ipadm_get_ifprop_flags(iph, ifname, pdp,
		    buf, bufsize, pdp->ipd_proto, valtype);
	} else {
		status = i_ipadm_get_prop(iph, ifname, pdp, buf,
		    bufsize, proto, valtype);
		/*
		 * If IPH_LEGACY is set, do not convert the value returned
		 * from kernel,
		 */
		if (iph->iph_flags & IPH_LEGACY)
			goto ret;
		if (status == IPADM_SUCCESS && (valtype == MOD_PROP_ACTIVE ||
		    valtype == MOD_PROP_DEFAULT)) {
			uint_t	val = atoi(buf);

			(void) snprintf(buf, *bufsize,
			    (val == 1 ? IPADM_ONSTR : IPADM_OFFSTR));
		}
	}

ret:
	return (status);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_mtu(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t proto,
    uint_t valtype)
{
	struct lifreq	lifr;
	const char	*ifname = arg;
	size_t		nbytes;
	int		s;

	switch (valtype) {
	case MOD_PROP_PERM:
		nbytes = snprintf(buf, *bufsize, "%d", MOD_PROP_PERM_RW);
		break;
	case MOD_PROP_DEFAULT:
	case MOD_PROP_POSSIBLE:
		return (i_ipadm_get_prop(iph, arg, pdp, buf, bufsize,
		    proto, valtype));
	case MOD_PROP_ACTIVE:
		bzero(&lifr, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
		s = (proto == MOD_PROTO_IPV6 ? iph->iph_sock6 : iph->iph_sock);

		if (ioctl(s, SIOCGLIFMTU, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
		nbytes = snprintf(buf, *bufsize, "%u", lifr.lifr_mtu);
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}
	return (IPADM_SUCCESS);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_metric(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t proto,
    uint_t valtype)
{
	struct lifreq	lifr;
	const char	*ifname = arg;
	size_t		nbytes;
	int		s, val;

	switch (valtype) {
	case MOD_PROP_PERM:
		val = MOD_PROP_PERM_RW;
		break;
	case MOD_PROP_DEFAULT:
		val = DEF_METRIC_VAL;
		break;
	case MOD_PROP_ACTIVE:
		bzero(&lifr, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));

		s = (proto == MOD_PROTO_IPV6 ? iph->iph_sock6 : iph->iph_sock);
		if (ioctl(s, SIOCGLIFMETRIC, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
		val = lifr.lifr_metric;
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	nbytes = snprintf(buf, *bufsize, "%d", val);
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}

	return (IPADM_SUCCESS);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_usesrc(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *ipd, char *buf, uint_t *bufsize, uint_t proto,
    uint_t valtype)
{
	struct lifreq	lifr;
	const char	*ifname = arg;
	int		s;
	char 		if_name[IF_NAMESIZE];
	size_t		nbytes;

	switch (valtype) {
	case MOD_PROP_PERM:
		nbytes = snprintf(buf, *bufsize, "%d", MOD_PROP_PERM_RW);
		break;
	case MOD_PROP_DEFAULT:
		nbytes = snprintf(buf, *bufsize, "%s", IPADM_NONESTR);
		break;
	case MOD_PROP_ACTIVE:
		bzero(&lifr, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));

		s = (proto == MOD_PROTO_IPV6 ? iph->iph_sock6 : iph->iph_sock);
		if (ioctl(s, SIOCGLIFUSESRC, (caddr_t)&lifr) < 0)
			return (ipadm_errno2status(errno));
		if (lifr.lifr_index == 0) {
			/* no src address was set, so print 'none' */
			(void) strlcpy(if_name, IPADM_NONESTR,
			    sizeof (if_name));
		} else if (if_indextoname(lifr.lifr_index, if_name) == NULL) {
			return (ipadm_errno2status(errno));
		}
		nbytes = snprintf(buf, *bufsize, "%s", if_name);
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		return (IPADM_NO_BUFS);
	}
	return (IPADM_SUCCESS);
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_ifprop_flags(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t proto,
    uint_t valtype)
{
	uint64_t 	intf_flags;
	char 		*val;
	size_t		nbytes;
	const char	*ifname = arg;
	sa_family_t	af;
	ipadm_status_t	status = IPADM_SUCCESS;

	switch (valtype) {
	case MOD_PROP_PERM:
		nbytes = snprintf(buf, *bufsize, "%d", MOD_PROP_PERM_RW);
		break;
	case MOD_PROP_DEFAULT:
		if (strcmp(pdp->ipd_name, "exchange_routes") == 0 ||
		    strcmp(pdp->ipd_name, "arp") == 0 ||
		    strcmp(pdp->ipd_name, "nud") == 0) {
			val = IPADM_ONSTR;
		} else if (strcmp(pdp->ipd_name, "forwarding") == 0) {
			val = IPADM_OFFSTR;
		} else {
			return (IPADM_PROP_UNKNOWN);
		}
		nbytes = snprintf(buf, *bufsize, "%s", val);
		break;
	case MOD_PROP_ACTIVE:
		af = (proto == MOD_PROTO_IPV6 ? AF_INET6 : AF_INET);
		status = i_ipadm_get_flags(iph, ifname, af, &intf_flags);
		if (status != IPADM_SUCCESS)
			return (status);

		val = IPADM_OFFSTR;
		if (strcmp(pdp->ipd_name, "exchange_routes") == 0) {
			if (!(intf_flags & IFF_NORTEXCH))
				val = IPADM_ONSTR;
		} else if (strcmp(pdp->ipd_name, "forwarding") == 0) {
			if (intf_flags & IFF_ROUTER)
				val = IPADM_ONSTR;
		} else if (strcmp(pdp->ipd_name, "arp") == 0) {
			if (!(intf_flags & IFF_NOARP))
				val = IPADM_ONSTR;
		} else if (strcmp(pdp->ipd_name, "nud") == 0) {
			if (!(intf_flags & IFF_NONUD))
				val = IPADM_ONSTR;
		}
		nbytes = snprintf(buf, *bufsize, "%s", val);
		break;
	default:
		return (IPADM_INVALID_ARG);
	}
	if (nbytes >= *bufsize) {
		/* insufficient buffer space */
		*bufsize = nbytes + 1;
		status = IPADM_NO_BUFS;
	}

	return (status);
}

static void
i_ipadm_perm2str(char *buf, uint_t *bufsize)
{
	uint_t perm = atoi(buf);

	(void) snprintf(buf, *bufsize, "%c%c",
	    ((perm & MOD_PROP_PERM_READ) != 0) ? 'r' : '-',
	    ((perm & MOD_PROP_PERM_WRITE) != 0) ? 'w' : '-');
}

/* ARGSUSED */
static ipadm_status_t
i_ipadm_get_prop(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, char *buf, uint_t *bufsize, uint_t proto,
    uint_t valtype)
{
	ipadm_status_t	status = IPADM_SUCCESS;
	const char	*ifname = arg;
	mod_ioc_prop_t	*mip;
	char 		*pname = pdp->ipd_name;
	uint_t		iocsize;

	/* allocate sufficient ioctl buffer to retrieve value */
	iocsize = sizeof (mod_ioc_prop_t) + *bufsize - 1;
	if ((mip = calloc(1, iocsize)) == NULL)
		return (IPADM_NO_BUFS);

	mip->mpr_version = MOD_PROP_VERSION;
	mip->mpr_flags = valtype;
	mip->mpr_proto = proto;
	if (ifname != NULL) {
		(void) strlcpy(mip->mpr_ifname, ifname,
		    sizeof (mip->mpr_ifname));
	}
	(void) strlcpy(mip->mpr_name, pname, sizeof (mip->mpr_name));
	mip->mpr_valsize = *bufsize;

	if (i_ipadm_strioctl(iph->iph_sock, SIOCGETPROP, (char *)mip,
	    iocsize) < 0) {
		if (errno == ENOENT)
			status = IPADM_PROP_UNKNOWN;
		else
			status = ipadm_errno2status(errno);
	} else {
		bcopy(mip->mpr_val, buf, *bufsize);
	}

	free(mip);
	return (status);
}

/*
 * Populates the ipmgmt_prop_arg_t based on the class of property.
 *
 * For private protocol properties, while persisting information in ipadm
 * data store, to ensure there is no collision of namespace between ipadm
 * private nvpair names (which also starts with '_', see ipadm_ipmgmt.h)
 * and private protocol property names, we will prepend IPADM_PRIV_PROP_PREFIX
 * to property names.
 */
static void
i_ipadm_populate_proparg(ipmgmt_prop_arg_t *pargp, ipadm_prop_desc_t *pdp,
    const char *pval, const void *object)
{
	const struct ipadm_addrobj_s *ipaddr;
	uint_t		class = pdp->ipd_class;
	uint_t		proto = pdp->ipd_proto;

	(void) strlcpy(pargp->ia_pname, pdp->ipd_name,
	    sizeof (pargp->ia_pname));
	if (pval != NULL)
		(void) strlcpy(pargp->ia_pval, pval, sizeof (pargp->ia_pval));

	switch (class) {
	case IPADMPROP_CLASS_MODULE:
		/* if it's a private property then add the prefix. */
		if (pdp->ipd_name[0] == '_') {
			(void) snprintf(pargp->ia_pname,
			    sizeof (pargp->ia_pname), "_%s", pdp->ipd_name);
		}
		(void) strlcpy(pargp->ia_module, object,
		    sizeof (pargp->ia_module));
		break;
	case IPADMPROP_CLASS_MODIF:
		/* check if object is protostr or an ifname */
		if (ipadm_str2proto(object) != MOD_PROTO_NONE) {
			(void) strlcpy(pargp->ia_module, object,
			    sizeof (pargp->ia_module));
			break;
		}
		/* it's an interface property, fall through */
		/* FALLTHRU */
	case IPADMPROP_CLASS_IF:
		(void) strlcpy(pargp->ia_ifname, object,
		    sizeof (pargp->ia_ifname));
		(void) strlcpy(pargp->ia_module, ipadm_proto2str(proto),
		    sizeof (pargp->ia_module));
		break;
	case IPADMPROP_CLASS_ADDR:
		ipaddr = object;
		(void) strlcpy(pargp->ia_ifname, ipaddr->ipadm_ifname,
		    sizeof (pargp->ia_ifname));
		(void) strlcpy(pargp->ia_aobjname, ipaddr->ipadm_aobjname,
		    sizeof (pargp->ia_aobjname));
		break;
	}
}

/*
 * Common function to retrieve property value for a given interface `ifname' or
 * for a given protocol `proto'. The property name is in `pname'.
 *
 * `valtype' determines the type of value that will be retrieved.
 * 	IPADM_OPT_ACTIVE -	current value of the property (active config)
 *	IPADM_OPT_PERSIST -	value of the property from persistent store
 *	IPADM_OPT_DEFAULT -	default hard coded value (boot-time value)
 *	IPADM_OPT_PERM -	read/write permissions for the value
 *	IPADM_OPT_POSSIBLE -	range of values
 */
static ipadm_status_t
i_ipadm_getprop_common(ipadm_handle_t iph, const char *ifname,
    const char *pname, char *buf, uint_t *bufsize, uint_t proto,
    uint_t valtype)
{
	ipadm_status_t		status = IPADM_SUCCESS;
	ipadm_prop_desc_t	*pdp;
	char			priv_propname[MAXPROPNAMELEN];
	boolean_t		is_if = (ifname != NULL);
	int			err = 0;

	pdp = i_ipadm_get_prop_desc(pname, proto, &err);
	if (err == EPROTO)
		return (IPADM_BAD_PROTOCOL);
	/* there are no private interface properties */
	if (is_if && err == ENOENT)
		return (IPADM_PROP_UNKNOWN);

	if (pdp != NULL) {
		/*
		 * check whether the property can be
		 * applied on an interface
		 */
		if (is_if && !(pdp->ipd_class & IPADMPROP_CLASS_IF))
			return (IPADM_INVALID_ARG);
		/*
		 * check whether the property can be
		 * applied on a module
		 */
		if (!is_if && !(pdp->ipd_class & IPADMPROP_CLASS_MODULE))
			return (IPADM_INVALID_ARG);

	} else {
		/* private protocol properties, pass it to kernel directly */
		pdp = &ipadm_privprop;
		(void) strlcpy(priv_propname, pname, sizeof (priv_propname));
		pdp->ipd_name = priv_propname;
	}

	switch (valtype) {
	case IPADM_OPT_PERM:
		status = pdp->ipd_get(iph, ifname, pdp, buf, bufsize, proto,
		    MOD_PROP_PERM);
		if (status == IPADM_SUCCESS)
			i_ipadm_perm2str(buf, bufsize);
		break;
	case IPADM_OPT_ACTIVE:
		status = pdp->ipd_get(iph, ifname, pdp, buf, bufsize, proto,
		    MOD_PROP_ACTIVE);
		break;
	case IPADM_OPT_DEFAULT:
		status = pdp->ipd_get(iph, ifname, pdp, buf, bufsize, proto,
		    MOD_PROP_DEFAULT);
		break;
	case IPADM_OPT_POSSIBLE:
		if (pdp->ipd_get_range != NULL) {
			status = pdp->ipd_get_range(iph, ifname, pdp, buf,
			    bufsize, proto, MOD_PROP_POSSIBLE);
			break;
		}
		buf[0] = '\0';
		break;
	case IPADM_OPT_PERSIST:
		/* retrieve from database */
		if (is_if)
			status = i_ipadm_get_persist_propval(iph, pdp, buf,
			    bufsize, ifname);
		else
			status = i_ipadm_get_persist_propval(iph, pdp, buf,
			    bufsize, ipadm_proto2str(proto));
		break;
	default:
		status = IPADM_INVALID_ARG;
		break;
	}
	return (status);
}

/*
 * Get protocol property of the specified protocol.
 */
ipadm_status_t
ipadm_get_prop(ipadm_handle_t iph, const char *pname, char *buf,
    uint_t *bufsize, uint_t proto, uint_t valtype)
{
	/*
	 * validate the arguments of the function.
	 */
	if (iph == NULL || pname == NULL || buf == NULL ||
	    bufsize == NULL || *bufsize == 0) {
		return (IPADM_INVALID_ARG);
	}
	/*
	 * Do we support this proto, if not return error.
	 */
	if (ipadm_proto2str(proto) == NULL)
		return (IPADM_NOTSUP);

	return (i_ipadm_getprop_common(iph, NULL, pname, buf, bufsize,
	    proto, valtype));
}

/*
 * Get interface property of the specified interface.
 */
ipadm_status_t
ipadm_get_ifprop(ipadm_handle_t iph, const char *ifname, const char *pname,
    char *buf, uint_t *bufsize, uint_t proto, uint_t valtype)
{
	/* validate the arguments of the function. */
	if (iph == NULL || pname == NULL || buf == NULL ||
	    bufsize == NULL || *bufsize == 0) {
		return (IPADM_INVALID_ARG);
	}

	/* Do we support this proto, if not return error. */
	if (ipadm_proto2str(proto) == NULL)
		return (IPADM_NOTSUP);

	/*
	 * check if interface name is provided for interface property and
	 * is valid.
	 */
	if (!i_ipadm_validate_ifname(iph, ifname))
		return (IPADM_INVALID_ARG);

	return (i_ipadm_getprop_common(iph, ifname, pname, buf, bufsize,
	    proto, valtype));
}

/*
 * Allocates sufficient ioctl buffers and copies property name and the
 * value, among other things. If the flag IPADM_OPT_DEFAULT is set, then
 * `pval' will be NULL and it instructs the kernel to reset the current
 * value to property's default value.
 */
static ipadm_status_t
i_ipadm_set_prop(ipadm_handle_t iph, const void *arg,
    ipadm_prop_desc_t *pdp, const void *pval, uint_t proto, uint_t flags)
{
	ipadm_status_t	status = IPADM_SUCCESS;
	const char	*ifname = arg;
	mod_ioc_prop_t 	*mip;
	char 		*pname = pdp->ipd_name;
	uint_t 		valsize, iocsize;
	uint_t		iocflags = 0;

	if (flags & IPADM_OPT_DEFAULT) {
		iocflags |= MOD_PROP_DEFAULT;
	} else if (flags & IPADM_OPT_ACTIVE) {
		iocflags |= MOD_PROP_ACTIVE;
		if (flags & IPADM_OPT_APPEND)
			iocflags |= MOD_PROP_APPEND;
		else if (flags & IPADM_OPT_REMOVE)
			iocflags |= MOD_PROP_REMOVE;
	}

	if (pval != NULL) {
		valsize = strlen(pval);
		iocsize = sizeof (mod_ioc_prop_t) + valsize - 1;
	} else {
		valsize = 0;
		iocsize = sizeof (mod_ioc_prop_t);
	}

	if ((mip = calloc(1, iocsize)) == NULL)
		return (IPADM_NO_BUFS);

	mip->mpr_version = MOD_PROP_VERSION;
	mip->mpr_flags = iocflags;
	mip->mpr_proto = proto;
	if (ifname != NULL) {
		(void) strlcpy(mip->mpr_ifname, ifname,
		    sizeof (mip->mpr_ifname));
	}

	(void) strlcpy(mip->mpr_name, pname, sizeof (mip->mpr_name));
	mip->mpr_valsize = valsize;
	if (pval != NULL)
		bcopy(pval, mip->mpr_val, valsize);

	if (i_ipadm_strioctl(iph->iph_sock, SIOCSETPROP, (char *)mip,
	    iocsize) < 0) {
		if (errno == ENOENT)
			status = IPADM_PROP_UNKNOWN;
		else
			status = ipadm_errno2status(errno);
	}
	free(mip);
	return (status);
}

/*
 * Common function for modifying both protocol/interface property.
 *
 * If:
 *   IPADM_OPT_PERSIST is set then the value is persisted.
 *   IPADM_OPT_DEFAULT is set then the default value for the property will
 *		       be applied.
 */
static ipadm_status_t
i_ipadm_setprop_common(ipadm_handle_t iph, const char *ifname,
    const char *pname, const char *buf, uint_t proto, uint_t pflags)
{
	ipadm_status_t		status = IPADM_SUCCESS;
	boolean_t 		persist = (pflags & IPADM_OPT_PERSIST);
	boolean_t		reset = (pflags & IPADM_OPT_DEFAULT);
	ipadm_prop_desc_t	*pdp;
	boolean_t		is_if = (ifname != NULL);
	char			priv_propname[MAXPROPNAMELEN];
	int			err = 0;

	/* Check that property value is within the allowed size */
	if (!reset && strnlen(buf, MAXPROPVALLEN) >= MAXPROPVALLEN)
		return (IPADM_INVALID_ARG);

	pdp = i_ipadm_get_prop_desc(pname, proto, &err);
	if (err == EPROTO)
		return (IPADM_BAD_PROTOCOL);
	/* there are no private interface properties */
	if (is_if && err == ENOENT)
		return (IPADM_PROP_UNKNOWN);

	if (pdp != NULL) {
		/* do some sanity checks */
		if (is_if) {
			if (!(pdp->ipd_class & IPADMPROP_CLASS_IF))
				return (IPADM_INVALID_ARG);
		} else {
			if (!(pdp->ipd_class & IPADMPROP_CLASS_MODULE))
				return (IPADM_INVALID_ARG);
		}
		/*
		 * if the property is not multi-valued and IPADM_OPT_APPEND or
		 * IPADM_OPT_REMOVE is specified, return IPADM_INVALID_ARG.
		 */
		if (!(pdp->ipd_flags & IPADMPROP_MULVAL) && (pflags &
		    (IPADM_OPT_APPEND|IPADM_OPT_REMOVE))) {
			return (IPADM_INVALID_ARG);
		}
	} else {
		/* private protocol property, pass it to kernel directly */
		pdp = &ipadm_privprop;
		(void) strlcpy(priv_propname, pname, sizeof (priv_propname));
		pdp->ipd_name = priv_propname;
	}

	status = pdp->ipd_set(iph, ifname, pdp, buf, proto, pflags);
	if (status != IPADM_SUCCESS)
		return (status);

	if (persist) {
		if (is_if)
			status = i_ipadm_persist_propval(iph, pdp, buf, ifname,
			    pflags);
		else
			status = i_ipadm_persist_propval(iph, pdp, buf,
			    ipadm_proto2str(proto), pflags);
	}
	return (status);
}

/*
 * Sets the property value of the specified interface
 */
ipadm_status_t
ipadm_set_ifprop(ipadm_handle_t iph, const char *ifname, const char *pname,
    const char *buf, uint_t proto, uint_t pflags)
{
	boolean_t	reset = (pflags & IPADM_OPT_DEFAULT);
	ipadm_status_t	status;

	/* check for solaris.network.interface.config authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);
	/*
	 * validate the arguments of the function.
	 */
	if (iph == NULL || pname == NULL || (!reset && buf == NULL) ||
	    pflags == 0 || pflags == IPADM_OPT_PERSIST ||
	    (pflags & ~(IPADM_COMMON_OPT_MASK|IPADM_OPT_DEFAULT))) {
		return (IPADM_INVALID_ARG);
	}

	/*
	 * Do we support this protocol, if not return error.
	 */
	if (ipadm_proto2str(proto) == NULL)
		return (IPADM_NOTSUP);

	/*
	 * Validate the interface and check if a persistent
	 * operation is performed on a temporary object.
	 */
	status = i_ipadm_validate_if(iph, ifname, proto, pflags);
	if (status != IPADM_SUCCESS)
		return (status);

	return (i_ipadm_setprop_common(iph, ifname, pname, buf, proto,
	    pflags));
}

/*
 * Sets the property value of the specified protocol.
 */
ipadm_status_t
ipadm_set_prop(ipadm_handle_t iph, const char *pname, const char *buf,
    uint_t proto, uint_t pflags)
{
	boolean_t	reset = (pflags & IPADM_OPT_DEFAULT);

	/* check for solaris.network.interface.config authorization */
	if (!ipadm_check_auth())
		return (IPADM_EAUTH);
	/*
	 * validate the arguments of the function.
	 */
	if (iph == NULL || pname == NULL ||(!reset && buf == NULL) ||
	    pflags == 0 || pflags == IPADM_OPT_PERSIST ||
	    (pflags & ~(IPADM_COMMON_OPT_MASK|IPADM_OPT_DEFAULT|
	    IPADM_OPT_APPEND|IPADM_OPT_REMOVE))) {
		return (IPADM_INVALID_ARG);
	}

	/*
	 * Do we support this proto, if not return error.
	 */
	if (ipadm_proto2str(proto) == NULL)
		return (IPADM_NOTSUP);

	return (i_ipadm_setprop_common(iph, NULL, pname, buf, proto,
	    pflags));
}

/* helper function for ipadm_walk_proptbl */
static void
i_ipadm_walk_proptbl(ipadm_prop_desc_t *pdtbl, uint_t proto, uint_t class,
    ipadm_prop_wfunc_t *func, void *arg)
{
	ipadm_prop_desc_t	*pdp;

	for (pdp = pdtbl; pdp->ipd_name != NULL; pdp++) {
		if (!(pdp->ipd_class & class))
			continue;

		if (proto != MOD_PROTO_NONE && !(pdp->ipd_proto & proto))
			continue;

		/*
		 * we found a class specific match, call the
		 * user callback function.
		 */
		if (func(arg, pdp->ipd_name, pdp->ipd_proto) == B_FALSE)
			break;
	}
}

/*
 * Walks through all the properties, for a given protocol and property class
 * (protocol or interface).
 *
 * Further if proto == MOD_PROTO_NONE, then it walks through all the supported
 * protocol property tables.
 */
ipadm_status_t
ipadm_walk_proptbl(uint_t proto, uint_t class, ipadm_prop_wfunc_t *func,
    void *arg)
{
	ipadm_prop_desc_t	*pdtbl;
	ipadm_status_t		status = IPADM_SUCCESS;
	int			i;
	int			count = A_CNT(protocols);

	if (func == NULL)
		return (IPADM_INVALID_ARG);

	switch (class) {
	case IPADMPROP_CLASS_ADDR:
		pdtbl = ipadm_addrprop_table;
		break;
	case IPADMPROP_CLASS_IF:
	case IPADMPROP_CLASS_MODULE:
		pdtbl = i_ipadm_get_propdesc_table(proto);
		if (pdtbl == NULL && proto != MOD_PROTO_NONE)
			return (IPADM_INVALID_ARG);
		break;
	default:
		return (IPADM_INVALID_ARG);
	}

	if (pdtbl != NULL) {
		/*
		 * proto will be MOD_PROTO_NONE in the case of
		 * IPADMPROP_CLASS_ADDR.
		 */
		i_ipadm_walk_proptbl(pdtbl, proto, class, func, arg);
	} else {
		/* Walk thru all the protocol tables, we support */
		for (i = 0; i < count; i++) {
			pdtbl = i_ipadm_get_propdesc_table(protocols[i]);
			i_ipadm_walk_proptbl(pdtbl, protocols[i], class, func,
			    arg);
		}
	}
	return (status);
}

/*
 * Given a property name, walks through all the instances of a property name.
 * Some properties have two instances one for v4 interfaces and another for v6
 * interfaces. For example: MTU. MTU can have different values for v4 and v6.
 * Therefore there are two properties for 'MTU'.
 *
 * This function invokes `func' for every instance of property `pname'
 */
ipadm_status_t
ipadm_walk_prop(const char *pname, uint_t proto, uint_t class,
    ipadm_prop_wfunc_t *func, void *arg)
{
	ipadm_prop_desc_t	*pdtbl, *pdp;
	ipadm_status_t		status = IPADM_SUCCESS;
	boolean_t		matched = B_FALSE;

	if (pname == NULL || func == NULL)
		return (IPADM_INVALID_ARG);

	switch (class) {
	case IPADMPROP_CLASS_ADDR:
		pdtbl = ipadm_addrprop_table;
		break;
	case IPADMPROP_CLASS_IF:
	case IPADMPROP_CLASS_MODULE:
		pdtbl = i_ipadm_get_propdesc_table(proto);
		break;
	default:
		return (IPADM_INVALID_ARG);
	}

	if (pdtbl == NULL)
		return (IPADM_INVALID_ARG);

	for (pdp = pdtbl; pdp->ipd_name != NULL; pdp++) {
		if (strcmp(pname, pdp->ipd_name) != 0)
			continue;
		if (!(pdp->ipd_proto & proto))
			continue;
		matched = B_TRUE;
		/* we found a match, call the callback function */
		if (func(arg, pdp->ipd_name, pdp->ipd_proto) == B_FALSE)
			break;
	}
	if (!matched)
		status = IPADM_PROP_UNKNOWN;
	return (status);
}

/* ARGSUSED */
ipadm_status_t
i_ipadm_get_onoff(ipadm_handle_t iph, const void *arg, ipadm_prop_desc_t *dp,
    char *buf, uint_t *bufsize, uint_t proto, uint_t valtype)
{
	(void) snprintf(buf, *bufsize, "%s,%s", IPADM_ONSTR, IPADM_OFFSTR);
	return (IPADM_SUCCESS);
}

/*
 * Makes a door call to ipmgmtd to retrieve the persisted property value
 */
ipadm_status_t
i_ipadm_get_persist_propval(ipadm_handle_t iph, ipadm_prop_desc_t *pdp,
    char *gbuf, uint_t *gbufsize, const void *object)
{
	ipmgmt_prop_arg_t	parg;
	ipmgmt_getprop_rval_t	rval, *rvalp;
	size_t			nbytes;
	int			err = 0;

	bzero(&parg, sizeof (parg));
	parg.ia_cmd = IPMGMT_CMD_GETPROP;
	i_ipadm_populate_proparg(&parg, pdp, NULL, object);

	rvalp = &rval;
	err = ipadm_door_call(iph, &parg, sizeof (parg), (void **)&rvalp,
	    sizeof (rval), B_FALSE);
	if (err == 0) {
		/* assert that rvalp was not reallocated */
		assert(rvalp == &rval);

		/* `ir_pval' contains the property value */
		nbytes = snprintf(gbuf, *gbufsize, "%s", rvalp->ir_pval);
		if (nbytes >= *gbufsize) {
			/* insufficient buffer space */
			*gbufsize = nbytes + 1;
			err = ENOBUFS;
		}
	}
	return (ipadm_errno2status(err));
}

/*
 * Persists the property value for a given property in the data store
 */
ipadm_status_t
i_ipadm_persist_propval(ipadm_handle_t iph, ipadm_prop_desc_t *pdp,
    const char *pval, const void *object, uint_t flags)
{
	ipmgmt_prop_arg_t	parg;
	int			err = 0;

	bzero(&parg, sizeof (parg));
	i_ipadm_populate_proparg(&parg, pdp, pval, object);
	/*
	 * Check if value to be persisted need to be appended or removed. This
	 * is required for multi-valued property.
	 */
	if (flags & IPADM_OPT_APPEND)
		parg.ia_flags |= IPMGMT_APPEND;
	if (flags & IPADM_OPT_REMOVE)
		parg.ia_flags |= IPMGMT_REMOVE;

	if (flags & (IPADM_OPT_DEFAULT|IPADM_OPT_REMOVE))
		parg.ia_cmd = IPMGMT_CMD_RESETPROP;
	else
		parg.ia_cmd = IPMGMT_CMD_SETPROP;

	err = ipadm_door_call(iph, &parg, sizeof (parg), NULL, 0, B_FALSE);

	/*
	 * its fine if there were no entry in the DB to delete. The user
	 * might be changing property value, which was not changed
	 * persistently.
	 */
	if (err == ENOENT)
		err = 0;
	return (ipadm_errno2status(err));
}

/*
 * This is called from ipadm_set_ifprop() to validate the set operation.
 * It does the following steps:
 * 1. Validates the interface name.
 * 2. Fails if it is an IPMP meta-interface or an underlying interface.
 * 3. In case of a persistent operation, verifies that the
 *	interface is persistent.
 */
static ipadm_status_t
i_ipadm_validate_if(ipadm_handle_t iph, const char *ifname,
    uint_t proto, uint_t flags)
{
	sa_family_t	af, other_af;
	ipadm_status_t	status;
	boolean_t	p_exists;
	boolean_t	af_exists, other_af_exists, a_exists;

	/* Check if the interface name is valid. */
	if (!i_ipadm_validate_ifname(iph, ifname))
		return (IPADM_INVALID_ARG);

	af = (proto == MOD_PROTO_IPV6 ? AF_INET6 : AF_INET);
	/*
	 * Setting properties on an IPMP meta-interface or underlying
	 * interface is not supported.
	 */
	if (i_ipadm_is_ipmp(iph, ifname) || i_ipadm_is_under_ipmp(iph, ifname))
		return (IPADM_NOTSUP);

	/* Check if interface exists in the persistent configuration. */
	status = i_ipadm_if_pexists(iph, ifname, af, &p_exists);
	if (status != IPADM_SUCCESS)
		return (status);

	/* Check if interface exists in the active configuration. */
	af_exists = ipadm_if_enabled(iph, ifname, af);
	other_af = (af == AF_INET ? AF_INET6 : AF_INET);
	other_af_exists = ipadm_if_enabled(iph, ifname, other_af);
	a_exists = (af_exists || other_af_exists);
	if (!a_exists && p_exists)
		return (IPADM_OP_DISABLE_OBJ);
	if (!af_exists)
		return (IPADM_ENXIO);

	/*
	 * If a persistent operation is requested, check if the underlying
	 * IP interface is persistent.
	 */
	if ((flags & IPADM_OPT_PERSIST) && !p_exists)
		return (IPADM_TEMPORARY_OBJ);
	return (IPADM_SUCCESS);
}

/*
 * Private protocol properties namespace scheme:
 *
 * PSARC 2010/080 identified the private protocol property names to be the
 * leading protocol names. For e.g. tcp_strong_iss, ip_strict_src_multihoming,
 * et al,. However to be consistent with private data-link property names,
 * which starts with '_', private protocol property names will start with '_'.
 * For e.g. _strong_iss, _strict_src_multihoming, et al,.
 */

/* maps new private protocol property name to the old private property name */
typedef struct ipadm_oname2nname_map {
	char	*iom_oname;
	char	*iom_nname;
	uint_t	iom_proto;
} ipadm_oname2nname_map_t;

/*
 * IP is a special case. It isn't straight forward to derive the legacy name
 * from the new name and vice versa. No set standard was followed in naming
 * the properties and hence we need a table to capture the mapping.
 */
static ipadm_oname2nname_map_t name_map[] = {
	{ "arp_probe_delay",		"_arp_probe_delay",
	    MOD_PROTO_IP },
	{ "arp_fastprobe_delay",	"_arp_fastprobe_delay",
	    MOD_PROTO_IP },
	{ "arp_probe_interval",		"_arp_probe_interval",
	    MOD_PROTO_IP },
	{ "arp_fastprobe_interval",	"_arp_fastprobe_interval",
	    MOD_PROTO_IP },
	{ "arp_probe_count",		"_arp_probe_count",
	    MOD_PROTO_IP },
	{ "arp_fastprobe_count",	"_arp_fastprobe_count",
	    MOD_PROTO_IP },
	{ "arp_defend_interval",	"_arp_defend_interval",
	    MOD_PROTO_IP },
	{ "arp_defend_rate",		"_arp_defend_rate",
	    MOD_PROTO_IP },
	{ "arp_defend_period",		"_arp_defend_period",
	    MOD_PROTO_IP },
	{ "ndp_defend_interval",	"_ndp_defend_interval",
	    MOD_PROTO_IP },
	{ "ndp_defend_rate",		"_ndp_defend_rate",
	    MOD_PROTO_IP },
	{ "ndp_defend_period",		"_ndp_defend_period",
	    MOD_PROTO_IP },
	{ "igmp_max_version",		"_igmp_max_version",
	    MOD_PROTO_IP },
	{ "mld_max_version",		"_mld_max_version",
	    MOD_PROTO_IP },
	{ "ipsec_override_persocket_policy", "_ipsec_override_persocket_policy",
	    MOD_PROTO_IP },
	{ "ipsec_policy_log_interval",	"_ipsec_policy_log_interval",
	    MOD_PROTO_IP },
	{ "icmp_accept_clear_messages",	"_icmp_accept_clear_messages",
	    MOD_PROTO_IP },
	{ "igmp_accept_clear_messages",	"_igmp_accept_clear_messages",
	    MOD_PROTO_IP },
	{ "pim_accept_clear_messages",	"_pim_accept_clear_messages",
	    MOD_PROTO_IP },
	{ "ip_respond_to_echo_multicast", "_respond_to_echo_multicast",
	    MOD_PROTO_IPV4 },
	{ "ip_send_redirects",		"_send_redirects",
	    MOD_PROTO_IPV4 },
	{ "ip_forward_src_routed",	"_forward_src_routed",
	    MOD_PROTO_IPV4 },
	{ "ip_icmp_return_data_bytes",	"_icmp_return_data_bytes",
	    MOD_PROTO_IPV4 },
	{ "ip_ignore_redirect",		"_ignore_redirect",
	    MOD_PROTO_IPV4 },
	{ "ip_strict_dst_multihoming",	"_strict_dst_multihoming",
	    MOD_PROTO_IPV4 },
	{ "ip_reasm_timeout",		"_reasm_timeout",
	    MOD_PROTO_IPV4 },
	{ "ip_strict_src_multihoming",	"_strict_src_multihoming",
	    MOD_PROTO_IPV4 },
	{ "ipv4_dad_announce_interval",	"_dad_announce_interval",
	    MOD_PROTO_IPV4 },
	{ "ipv4_icmp_return_pmtu",	"_icmp_return_pmtu",
	    MOD_PROTO_IPV4 },
	{ "ipv6_dad_announce_interval",	"_dad_announce_interval",
	    MOD_PROTO_IPV6 },
	{ "ipv6_icmp_return_pmtu",	"_icmp_return_pmtu",
	    MOD_PROTO_IPV6 },
	{ NULL, NULL, MOD_PROTO_NONE }
};

/*
 * Following API returns a new property name in `nname' for the given legacy
 * property name in `oname'.
 */
int
ipadm_legacy2new_propname(const char *oname, char *nname, uint_t nnamelen,
    uint_t *proto)
{
	const char	*str;
	ipadm_oname2nname_map_t *ionmp;

	/* if it's a public property, there is nothing to return */
	if (i_ipadm_get_prop_desc(oname, *proto, NULL) != NULL)
		return (-1);

	/*
	 * we didn't find the `oname' in the table, check if the property
	 * name begins with a leading protocol.
	 */
	str = oname;
	switch (*proto) {
	case MOD_PROTO_TCP:
		if (strstr(oname, "tcp_") == oname)
			str += strlen("tcp");
		break;
	case MOD_PROTO_SCTP:
		if (strstr(oname, "sctp_") == oname)
			str += strlen("sctp");
		break;
	case MOD_PROTO_UDP:
		if (strstr(oname, "udp_") == oname)
			str += strlen("udp");
		break;
	case MOD_PROTO_RAWIP:
		if (strstr(oname, "icmp_") == oname)
			str += strlen("icmp");
		break;
	case MOD_PROTO_IP:
	case MOD_PROTO_IPV4:
	case MOD_PROTO_IPV6:
		if (strstr(oname, "ip6_") == oname) {
			*proto = MOD_PROTO_IPV6;
			str += strlen("ip6");
		} else {
			for (ionmp = name_map; ionmp->iom_oname != NULL;
			    ionmp++) {
				if (strcmp(oname, ionmp->iom_oname) == 0) {
					str = ionmp->iom_nname;
					*proto = ionmp->iom_proto;
					break;
				}
			}
			if (ionmp->iom_oname != NULL)
				break;

			if (strstr(oname, "ip_") == oname) {
				*proto = MOD_PROTO_IP;
				str += strlen("ip");
			}
		}
		break;
	default:
		return (-1);
	}
	(void) snprintf(nname, nnamelen, "%s", str);
	return (0);
}

/*
 * Following API is required for ndd.c alone. To maintain backward
 * compatibility with ndd output, we need to print the legacy name
 * for the new name.
 */
int
ipadm_new2legacy_propname(const char *oname, char *nname,
    uint_t nnamelen, uint_t proto)
{
	char	*prefix;
	ipadm_oname2nname_map_t *ionmp;

	/* if it's a public property, there is nothing to prepend */
	if (i_ipadm_get_prop_desc(oname, proto, NULL) != NULL)
		return (-1);

	switch (proto) {
	case MOD_PROTO_TCP:
		prefix = "tcp";
		break;
	case MOD_PROTO_SCTP:
		prefix = "sctp";
		break;
	case MOD_PROTO_UDP:
		prefix = "udp";
		break;
	case MOD_PROTO_RAWIP:
		prefix = "icmp";
		break;
	case MOD_PROTO_IP:
	case MOD_PROTO_IPV4:
	case MOD_PROTO_IPV6:
		/* handle special case for IP */
		for (ionmp = name_map; ionmp->iom_oname != NULL; ionmp++) {
			if (strcmp(oname, ionmp->iom_nname) == 0 &&
			    ionmp->iom_proto == proto) {
				(void) strlcpy(nname, ionmp->iom_oname,
				    nnamelen);
				return (0);
			}
		}
		if (proto == MOD_PROTO_IPV6)
			prefix = "ip6";
		else
			prefix = "ip";
		break;
	default:
		return (-1);
	}
	(void) snprintf(nname, nnamelen, "%s%s", prefix, oname);
	return (0);
}
