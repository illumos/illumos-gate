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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>
#include <libilb.h>
#include <libilb_impl.h>
#include "ilbadm.h"

#define	PORT_SEP	':'

typedef enum {
	numeric = 1,
	non_numeric
} addr_type_t;

ilbadm_val_type_t algo_types[] = {
	{(int)ILB_ALG_ROUNDROBIN, "roundrobin", "rr"},
	{(int)ILB_ALG_HASH_IP, "hash-ip", "hip"},
	{(int)ILB_ALG_HASH_IP_SPORT, "hash-ip-port", "hipp"},
	{(int)ILB_ALG_HASH_IP_VIP, "hash-ip-vip", "hipv"},
	{ILBD_BAD_VAL, 0, 0}
};

ilbadm_val_type_t topo_types[] = {
	{(int)ILB_TOPO_DSR, "DSR", "d"},
	{(int)ILB_TOPO_NAT, "NAT", "n"},
	{(int)ILB_TOPO_HALF_NAT, "HALF-NAT", "h"},
	{ILBD_BAD_VAL, 0, 0}
};

void
ip2str(ilb_ip_addr_t *ip, char *buf, size_t sz, int flags)
{
	int	len;

	switch (ip->ia_af) {
	case AF_INET:
		if (*(uint32_t *)&ip->ia_v4 == 0)
			buf[0] = '\0';
		else
			(void) inet_ntop(AF_INET, (void *)&ip->ia_v4, buf, sz);
		break;
	case AF_INET6:
		if (IN6_IS_ADDR_UNSPECIFIED(&ip->ia_v6)) {
			buf[0] = '\0';
			break;
		}
		if (!(flags & V6_ADDRONLY))
			*buf++ = '[';
		sz--;
		(void) inet_ntop(ip->ia_af, (void *)&ip->ia_v6, buf, sz);
		if (!(flags & V6_ADDRONLY)) {
			len = strlen(buf);
			buf[len] = ']';
			buf[++len] = '\0';
		}
		break;
	default: buf[0] = '\0';
	}
}

char *
i_str_from_val(int val, ilbadm_val_type_t *types)
{
	ilbadm_val_type_t	*v;

	for (v = types; v->v_type != ILBD_BAD_VAL; v++) {
		if (v->v_type == val)
			break;
	}
	/* we return this in all cases */
	return (v->v_name);
}

int
i_val_from_str(char *name, ilbadm_val_type_t *types)
{
	ilbadm_val_type_t	*v;

	for (v = types; v->v_type != ILBD_BAD_VAL; v++) {
		if (strncasecmp(name, v->v_name, sizeof (v->v_name)) == 0 ||
		    strncasecmp(name, v->v_alias, sizeof (v->v_alias)) == 0)
			break;
	}
	/* we return this in all cases */
	return (v->v_type);
}

ilbadm_key_code_t
i_match_key(char *key, ilbadm_key_name_t *keylist)
{
	ilbadm_key_name_t	*t_key;

	for (t_key = keylist; t_key->k_key != ILB_KEY_BAD; t_key++) {
		if (strncasecmp(key, t_key->k_name,
		    sizeof (t_key->k_name)) == 0 ||
		    strncasecmp(key, t_key->k_alias,
		    sizeof (t_key->k_alias)) == 0)
			break;
	}
	return (t_key->k_key);
}

/*
 * try to match:
 * 1) IPv4 address
 * 2) IPv6 address
 * 3) a hostname
 */
static ilbadm_status_t
i_match_onehost(const char *val, ilb_ip_addr_t *ip, addr_type_t *a_type)
{
	struct addrinfo *ai = NULL;
	struct addrinfo hints;
	addr_type_t	at = numeric;

	(void) memset((void *)&hints, 0, sizeof (hints));
	hints.ai_flags |= AI_NUMERICHOST;

	/*
	 * if *a_type == numeric, we only want to check whether this
	 * is a (valid) numeric IP address. If we do and it is NOT,
	 * we return _ENOENT.
	 */
	if (getaddrinfo(val, NULL, &hints, &ai) != 0) {
		if (a_type != NULL && (*a_type == numeric))
			return (ILBADM_INVAL_ADDR);

		at = non_numeric;
		if (getaddrinfo(val, NULL, NULL, &ai) != 0)
			return (ILBADM_INVAL_ADDR);
	}

	ip->ia_af = ai->ai_family;
	switch (ip->ia_af) {
	case AF_INET: {
		struct sockaddr_in	sa;

		assert(ai->ai_addrlen == sizeof (sa));
		(void) memcpy(&sa, ai->ai_addr, sizeof (sa));
		ip->ia_v4 = sa.sin_addr;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6	sa;

		assert(ai->ai_addrlen == sizeof (sa));
		(void) memcpy(&sa, ai->ai_addr, sizeof (sa));
		ip->ia_v6 = sa.sin6_addr;
		break;
	}
	default:
		return (ILBADM_INVAL_AF);
	}

	if (a_type != NULL)
		*a_type = at;
	return (ILBADM_OK);
}

static ilbadm_status_t
i_store_serverID(void *store, char *val)
{
	ilbadm_servnode_t	*s = (ilbadm_servnode_t *)store;
	ilb_server_data_t	*sn = &s->s_spec;

	/*
	 * we shouldn't need to check for length here, as a name that's
	 * too long won't exist in the system anyway.
	 */
	(void) strlcpy(sn->sd_srvID, val, sizeof (sn->sd_srvID));
	return (ILBADM_OK);
}

static struct in_addr
i_next_in_addr(struct in_addr *a, int dir)
{
	struct in_addr	new_in;
	uint32_t	iah;

	iah = ntohl(a->s_addr);
	if (dir == 1)
		iah++;
	else
		iah--;
	new_in.s_addr = htonl(iah);
	return (new_in);
}

static ilbadm_status_t
i_expand_ipv4range(ilbadm_sgroup_t *sg, ilb_server_data_t *srv,
    ilb_ip_addr_t *ip1, ilb_ip_addr_t *ip2)
{
	struct in_addr	*a1;
	ilbadm_servnode_t	*sn_new;
	ilb_ip_addr_t	new_ip;

	a1 = &ip1->ia_v4;

	new_ip.ia_af = AF_INET;
	new_ip.ia_v4 = i_next_in_addr(a1, 1);
	while (ilb_cmp_ipaddr(&new_ip, ip2, NULL) < 1) {
		sn_new = i_new_sg_elem(sg);
		sn_new->s_spec.sd_addr = new_ip;
		sn_new->s_spec.sd_minport = srv->sd_minport;
		sn_new->s_spec.sd_maxport = srv->sd_maxport;
		new_ip.ia_v4 = i_next_in_addr(&new_ip.ia_v4, 1);
	}
	return (ILBADM_OK);
}

static struct in6_addr
i_next_in6_addr(struct in6_addr *a, int dir)
{
	struct in6_addr	ia6;
	uint64_t	al, ah;

	ah = INV6_N2H_MSB64(a);
	al = INV6_N2H_LSB64(a);

	if (dir == 1) {
		/* overflow */
		if (++al == 0)
			ah++;
	} else {
		/* underflow */
		if (--al == 0xffffffff)
			ah--;
	}

	INV6_H2N_MSB64(&ia6, ah);
	INV6_H2N_LSB64(&ia6, al);
	return (ia6);
}


static ilbadm_status_t
i_expand_ipv6range(ilbadm_sgroup_t *sg, ilb_server_data_t *srv,
    ilb_ip_addr_t *ip1, ilb_ip_addr_t *ip2)
{
	struct in6_addr	*a1;
	ilbadm_servnode_t	*sn_new;
	ilb_ip_addr_t	new_ip;

	a1 = &ip1->ia_v6;

	new_ip.ia_af = AF_INET6;
	new_ip.ia_v6 = i_next_in6_addr(a1, 1);
	while (ilb_cmp_ipaddr(&new_ip, ip2, NULL) < 1) {
		sn_new = i_new_sg_elem(sg);
		sn_new->s_spec.sd_addr = new_ip;
		sn_new->s_spec.sd_minport = srv->sd_minport;
		sn_new->s_spec.sd_maxport = srv->sd_maxport;
		new_ip.ia_v6 = i_next_in6_addr(&new_ip.ia_v6, 1);
	}
	return (ILBADM_OK);
}


/*
 * we create a list node in the servergroup for every ip address
 * in the range [ip1, ip2], where we interpret the ip addresses as
 * numbers
 * the first ip address is already stored in "sn"
 */
static ilbadm_status_t
i_expand_iprange(ilbadm_sgroup_t *sg, ilb_server_data_t *sr,
    ilb_ip_addr_t *ip1, ilb_ip_addr_t *ip2)
{
	int		cmp;
	int64_t		delta;

	if (ip2->ia_af == 0)
		return (ILBADM_OK);

	if (ip1->ia_af != ip2->ia_af) {
		ilbadm_err(gettext("IP address mismatch"));
		return (ILBADM_LIBERR);
	}

	/* if ip addresses are the same, we're done */
	if ((cmp = ilb_cmp_ipaddr(ip1, ip2, &delta)) == 0)
		return (ILBADM_OK);
	if (cmp == 1) {
		ilbadm_err(gettext("starting IP address is must be less"
		    " than ending ip address in ip range specification"));
		return (ILBADM_LIBERR);
	}

	/* if the implicit number of IPs is too large, stop */
	if (abs((int)delta) > MAX_IP_SPREAD)
		return (ILBADM_TOOMANYIPADDR);

	switch (ip1->ia_af) {
	case AF_INET:
		return (i_expand_ipv4range(sg, sr, ip1, ip2));
	case AF_INET6:
		return (i_expand_ipv6range(sg, sr, ip1, ip2));
	}
	return (ILBADM_INVAL_AF);
}

/*
 * parse a port spec (number or by service name) and
 * return the numeric port in *host* byte order
 *
 * Upon return, *flags contains ILB_FLAGS_SRV_PORTNAME if a service name matches
 */
static int
i_parseport(char *port, char *proto, int *flags)
{
	struct servent	*se;

	/* assumption: port names start with a non-digit */
	if (isdigit(port[0])) {
		if (flags != NULL)
			*flags &= ~ILB_FLAGS_SRV_PORTNAME;
		return ((int)strtol(port, NULL, 10));
	}

	se = getservbyname(port, proto);
	if (se == NULL)
		return (-1);

	if (flags != NULL)
		*flags |= ILB_FLAGS_SRV_PORTNAME;

	/*
	 * we need to convert to host byte order to be in sync with
	 * numerical ports. since result needs to be compared, this
	 * is preferred to returning NW byte order
	 */
	return ((int)(ntohs(se->s_port)));
}

/*
 * matches one hostname or IP address and stores it in "store".
 * space must have been pre-allocated to accept data
 * "sg" != NULL only for cases where ip ranges may be coming in.
 */
static ilbadm_status_t
i_match_hostorip(void *store, ilbadm_sgroup_t *sg, char *val,
    int flags, ilbadm_key_code_t keyword)
{
	boolean_t	is_ip_range_ok = flags & OPT_IP_RANGE;
	boolean_t	is_addr_numeric = flags & OPT_NUMERIC_ONLY;
	boolean_t	is_ports_ok = flags & OPT_PORTS;
	boolean_t	ports_only = flags & OPT_PORTS_ONLY;
	boolean_t	is_nat_src = flags & OPT_NAT;
	char		*port_pref, *dash;
	char		*port1p, *port2p, *host2p, *host1p;
	char		*close1, *close2;
	ilb_ip_addr_t	ip2store;
	ilb_ip_addr_t	*ip1, *ip2;
	int		p1, p2;
	ilb_server_data_t	*s = NULL;
	ilbadm_status_t	rc = ILBADM_OK;
	int		af = AF_INET;
	addr_type_t	at = 0;
	int		p_flg;
	struct in6_addr v6nameaddr;

	port1p = port2p = host2p = host1p =  NULL;
	port_pref = dash = NULL;
	close1 = close2 = NULL;
	errno = 0;

	if (is_nat_src) {
		ilb_rule_data_t *rd = (ilb_rule_data_t *)store;

		ip1 = &rd->r_nat_src_start;
		ip2 = &rd->r_nat_src_end;
	} else {
		ilbadm_servnode_t *sn = (ilbadm_servnode_t *)store;

		s = &sn->s_spec;
		ip1 = &s->sd_addr;
		ip2 = &ip2store;
		bzero(ip2, sizeof (*ip2));
	}

	if (ports_only) {
		is_ports_ok = B_TRUE;
		port_pref = val - 1; /* we increment again later on */
		goto ports;
	}

	/*
	 * we parse the syntax ip[-ip][:port[-port]]
	 * since IPv6 addresses contain ':'s as well, they need to be
	 * enclosed in "[]" to be distinct from a potential port spec.
	 * therefore, we need to first check whether we're dealing with
	 * IPv6 addresses before we can go search for the port seperator
	 * and ipv6 range could look like this: [ff::0]-[ff::255]:80
	 */
	if ((keyword == ILB_KEY_SERVER) && (strchr(val, ':') != NULL) &&
	    (*val != '[') && ((inet_pton(AF_INET6, val, &v6nameaddr)) != 0)) {
			/*
			 * V6 addresses must be enclosed within
			 * brackets when specifying server addresses
			 */
			rc = ILBADM_INVAL_SYNTAX;
			goto err_out;
	}

	if (*val == '[') {
		af = AF_INET6;

		val++;
		host1p = val;

		close1 = strchr(val, (int)']');
		if (close1 == NULL) {
			rc = ILBADM_INVAL_SYNTAX;
			goto err_out;
		}
		*close1 = '\0';
		at = 0;
		rc = i_match_onehost(host1p, ip1, &at);
		if (rc != ILBADM_OK)
			goto err_out;
		if (at != numeric) {
			rc = ILBADM_INVAL_ADDR;
			goto err_out;
		}
		if (ip1->ia_af != af) {
			rc = ILBADM_INVAL_AF;
			goto err_out;
		}
		val = close1 + 1;

		if (*val == PORT_SEP) {
			port_pref = val;
			goto ports;
		}
		if (*val == '-') {
			dash = val;
			if (!is_ip_range_ok) {
				ilbadm_err(gettext("port ranges not allowed"));
				rc = ILBADM_LIBERR;
				goto err_out;
			}
			val++;
			if (*val != '[') {
				rc = ILBADM_INVAL_SYNTAX;
				goto err_out;
			}
			val++;
			close2 = strchr(val, (int)']');
			if (close2 == NULL) {
				rc = ILBADM_INVAL_SYNTAX;
				goto err_out;
			}
			*close2 = '\0';
			host2p = val;
			at = 0;
			rc = i_match_onehost(host2p, ip2, &at);
			if (rc != ILBADM_OK)
				goto err_out;
			if (at != numeric) {
				rc = ILBADM_INVAL_ADDR;
				goto err_out;
			}
			if (ip2->ia_af != af) {
				rc = ILBADM_INVAL_AF;
				goto err_out;
			}
			val = close2+1;
		}
	}

	/* ports always potentially allow ranges - XXXms: check? */
	port_pref = strchr(val, (int)PORT_SEP);
ports:
	if (port_pref != NULL && is_ports_ok) {
		port1p = port_pref + 1;
		*port_pref = '\0';

		dash = strchr(port1p, (int)'-');
		if (dash != NULL) {
			port2p = dash + 1;
			*dash = '\0';
		}
		if (port1p != NULL) {
			p1 = i_parseport(port1p, NULL, &p_flg);
			if (p1 == -1 || p1 == 0 || p1 > ILB_MAX_PORT) {
				ilbadm_err(gettext("invalid port value %s"
				    " specified"), port1p);
				rc = ILBADM_LIBERR;
				goto err_out;
			}
			s->sd_minport = htons((in_port_t)p1);
			if (p_flg & ILB_FLAGS_SRV_PORTNAME)
				s->sd_flags |= ILB_FLAGS_SRV_PORTNAME;
		}
		if (port2p != NULL) {
			/* ranges are only allowed for numeric ports */
			if (p_flg & ILB_FLAGS_SRV_PORTNAME) {
				ilbadm_err(gettext("ranges are only allowed"
				    " for numeric ports"));
				rc = ILBADM_LIBERR;
				goto err_out;
			}
			p2 = i_parseport(port2p, NULL, &p_flg);
			if (p2 == -1 || p2 <= p1 || p2 > ILB_MAX_PORT ||
			    (p_flg & ILB_FLAGS_SRV_PORTNAME) ==
			    ILB_FLAGS_SRV_PORTNAME) {
				ilbadm_err(gettext("invalid port value %s"
				    " specified"), port2p);
				rc = ILBADM_LIBERR;
				goto err_out;
			}
			s->sd_maxport = htons((in_port_t)p2);
		}
		/*
		 * we fill the '-' back in, but not the port seperator,
		 * as the \0 in its place terminates the ip address(es)
		 */
		if (dash != NULL)
			*dash = '-';
		if (ports_only)
			goto out;
	}

	if (af == AF_INET6)
		goto out;

	/*
	 * we need to handle these situations for hosts:
	 *   a. ip address
	 *   b. ip address range (ip1-ip2)
	 *   c. a hostname (may include '-' or start with a digit)
	 *
	 * We want to do hostname lookup only if we're quite sure that
	 * we actually are looking at neither a single IP address nor a
	 * range of same, as this can hang if name service is not set up
	 * (sth. likely in a LB environment).
	 *
	 * here's how we proceed:
	 * 1. try to match numeric only. If that succeeds, we're done.
	 *    (getaddrinfo, which we call in i_match_onehost(), fails if
	 *    it encounters a '-')
	 * 2. search for a '-'; if we find one, try numeric match for
	 *    both sides. if this fails:
	 * 3. re-insert '-' and try for a legal hostname.
	 */
	/* 1. */
	at = numeric;
	rc = i_match_onehost(val, ip1, &at);
	if (rc == ILBADM_OK)
		goto out;

	/* 2. */
	dash = strchr(val, (int)'-');
	if (dash != NULL && is_ip_range_ok) {
		host2p = dash + 1;
		*dash = '\0';
		at = numeric;
		rc = i_match_onehost(host2p, ip2, &at);
		if (rc != ILBADM_OK || at != numeric) {
			*dash = '-';
			dash = NULL;
			bzero(ip2, sizeof (*ip2));
			goto hostname;
		}
		/*
		 * if the RHS of '-' is an IP but LHS is not, we might
		 * have a hostname of form x-y where y is just a number
		 * (this seems a valid IPv4 address), so we need to
		 * try a complete hostname
		 */
		rc = i_match_onehost(val, ip1, &at);
		if (rc != ILBADM_OK || at != numeric) {
			*dash = '-';
			dash = NULL;
			goto hostname;
		}
		goto out;
	}
hostname:
	/* 3. */

	if (is_addr_numeric)
		at = numeric;
	else
		at = 0;
	rc = i_match_onehost(val, ip1, &at);
	if (rc != ILBADM_OK) {
		goto out;
	}
	if (s != NULL) {
		s->sd_flags |= ILB_FLAGS_SRV_HOSTNAME;
		/* XXX: todo: save hostname for re-display for admin */
	}

out:
	if (dash != NULL && !is_nat_src) {
		rc = i_expand_iprange(sg, s, ip1, ip2);
		if (rc != ILBADM_OK)
			goto err_out;
	}

	if (is_nat_src && host2p == NULL)
		*ip2 = *ip1;

err_out:
	/*
	 * we re-insert what we overwrote, especially in the error case
	 */
	if (close2 != NULL)
		*close2 = ']';
	if (close1 != NULL)
		*close1 = '[';
	if (dash != NULL)
		*dash = '-';
	if (port_pref != NULL && !ports_only)
		*port_pref = PORT_SEP;

	return (rc);
}

/*
 * type-agnostic helper function to return a pointer to a
 * pristine (and maybe freshly allocated) piece of storage
 * ready for something fitting "key"
 */
static void *
i_new_storep(void *store, ilbadm_key_code_t key)
{
	void	*res;

	switch (key) {
	case ILB_KEY_SERVER:
	case ILB_KEY_SERVRANGE:
	case ILB_KEY_SERVERID:
		res = (void *) i_new_sg_elem(store);
		break;
	default: res = NULL;
		break;
	}

	return (res);
}

/*
 * make sure everything that needs to be there is there
 */
ilbadm_status_t
i_check_rule_spec(ilb_rule_data_t *rd)
{
	int32_t		vip_af = rd->r_vip.ia_af;
	ilb_ip_addr_t	*prxy_src;

	if (vip_af != AF_INET && vip_af != AF_INET6)
		return (ILBADM_INVAL_AF);

	if (*rd->r_sgname == '\0')
		return (ILBADM_ENOSGNAME);

	if (rd->r_algo == 0 || rd->r_topo == 0) {
		ilbadm_err(gettext("lbalg or type is unspecified"));
		return (ILBADM_LIBERR);
	}

	if (rd->r_topo == ILB_TOPO_NAT) {
		prxy_src = &rd->r_nat_src_start;
		if (prxy_src->ia_af != vip_af) {
			ilbadm_err(gettext("proxy-src is either missing"
			    " or its address family does not"
			    " match that of the VIP address"));
			return (ILBADM_LIBERR);
		}
	}
	/* extend as necessary */

	return (ILBADM_OK);
}

/*
 * in parameter "sz" describes size (in bytes) of mask
 */
static int
mask_to_prefixlen(const uchar_t *mask, const int sz)
{
	uchar_t	c;
	int	i, j;
	int	len = 0;
	int	tmask;

	/*
	 * for every byte in the mask, we start with most significant
	 * bit and work our way down to the least significant bit; as
	 * long as we find the bit set, we add 1 to the length. the
	 * first unset bit we encounter terminates this process
	 */
	for (i = 0; i < sz; i++) {
		c = mask[i];
		tmask = 1 << 7;
		for (j = 7; j >= 0; j--) {
			if ((c & tmask) == 0)
				return (len);
			len++;
			tmask >>= 1;
		}
	}
	return (len);
}

int
ilbadm_mask_to_prefixlen(ilb_ip_addr_t *ip)
{
	int af = ip->ia_af;
	int len = 0;

	assert(af == AF_INET || af == AF_INET6);
	switch (af) {
	case AF_INET:
		len = mask_to_prefixlen((uchar_t *)&ip->ia_v4.s_addr,
		    sizeof (ip->ia_v4));
		break;
	case AF_INET6:
		len = mask_to_prefixlen((uchar_t *)&ip->ia_v6.s6_addr,
		    sizeof (ip->ia_v6));
		break;
	}
	return (len);
}

/* copied from ifconfig.c, changed to return symbolic constants */
/*
 * Convert a prefix length to a mask.
 * Returns 1 if ok. 0 otherwise.
 * Assumes the mask array is zero'ed by the caller.
 */
static boolean_t
in_prefixlentomask(int prefixlen, int maxlen, uchar_t *mask)
{
	if (prefixlen < 0 || prefixlen > maxlen)
		return (B_FALSE);

	while (prefixlen > 0) {
		if (prefixlen >= 8) {
			*mask++ = 0xFF;
			prefixlen -= 8;
			continue;
		}
		*mask |= 1 << (8 - prefixlen);
		prefixlen--;
	}
	return (B_TRUE);
}

ilbadm_status_t
ilbadm_set_netmask(char *val, ilb_ip_addr_t *ip, int af)
{
	int	prefixlen, maxval;
	boolean_t	r;
	char	*end;

	assert(af == AF_INET || af == AF_INET6);

	maxval = (af == AF_INET) ? 32 : 128;

	if (*val == '/')
		val++;
	prefixlen = strtol(val, &end, 10);
	if ((val == end) || (*end != '\0')) {
		ilbadm_err(gettext("invalid pmask provided"));
		return (ILBADM_LIBERR);
	}

	if (prefixlen < 1 || prefixlen > maxval) {
		ilbadm_err(gettext("invalid pmask provided (AF mismatch?)"));
		return (ILBADM_LIBERR);
	}

	switch (af) {
	case AF_INET:
		r = in_prefixlentomask(prefixlen, maxval,
		    (uchar_t *)&ip->ia_v4.s_addr);
		break;
	case AF_INET6:
		r = in_prefixlentomask(prefixlen, maxval,
		    (uchar_t *)&ip->ia_v6.s6_addr);
		break;
	}
	if (r != B_TRUE) {
		ilbadm_err(gettext("cannot convert %s to a netmask"), val);
		return (ILBADM_LIBERR);
	}
	ip->ia_af = af;
	return (ILBADM_OK);
}

static ilbadm_status_t
i_store_val(char *val, void *store, ilbadm_key_code_t keyword)
{
	ilbadm_status_t	rc = ILBADM_OK;
	void		*storep = store;
	ilb_rule_data_t	*rd = NULL;
	ilbadm_sgroup_t	*sg = NULL;
	ilb_hc_info_t	*hc_info = NULL;
	struct protoent	*pe;
	int64_t		tmp_val;

	if (*val == '\0')
		return (ILBADM_NOKEYWORD_VAL);

	/* some types need new storage, others don't */
	switch (keyword) {
	case ILB_KEY_SERVER:
	case ILB_KEY_SERVERID:
		sg = (ilbadm_sgroup_t *)store;
		storep = i_new_storep(store, keyword);
		break;
	case ILB_KEY_HEALTHCHECK:
	case ILB_KEY_SERVERGROUP:
		rd = (ilb_rule_data_t *)store;
		break;
	case ILB_KEY_VIP:	/* fallthrough */
	case ILB_KEY_PORT:	/* fallthrough */
	case ILB_KEY_HCPORT:	/* fallthrough */
	case ILB_KEY_CONNDRAIN:	/* fallthrough */
	case ILB_KEY_NAT_TO:	/* fallthrough */
	case ILB_KEY_STICKY_TO:	/* fallthrough */
	case ILB_KEY_PROTOCOL:	/* fallthrough */
	case ILB_KEY_ALGORITHM:	/* fallthrough */
	case ILB_KEY_STICKY:	/* fallthrough */
	case ILB_KEY_TYPE:	/* fallthrough */
	case ILB_KEY_SRC:	/* fallthrough */
		rd = (ilb_rule_data_t *)store;
		break;
	case ILB_KEY_HC_TEST:
	case ILB_KEY_HC_COUNT:
	case ILB_KEY_HC_INTERVAL:
	case ILB_KEY_HC_TIMEOUT:
		hc_info = (ilb_hc_info_t *)store;
	default: /* do nothing */
		;
	}

	switch (keyword) {
	case ILB_KEY_SRC:
		/*
		 * the proxy-src keyword is only valid for full NAT topology
		 * the value is either a single or a range of IP addresses.
		 */
		if (rd->r_topo != ILB_TOPO_NAT) {
			rc = ILBADM_INVAL_PROXY;
			break;
		}
		rc = i_match_hostorip(storep, sg, val, OPT_NUMERIC_ONLY |
		    OPT_IP_RANGE | OPT_NAT, ILB_KEY_SRC);
		break;
	case ILB_KEY_SERVER:
		rc = i_match_hostorip(storep, sg, val,
		    OPT_IP_RANGE | OPT_PORTS, ILB_KEY_SERVER);
		break;
	case ILB_KEY_SERVERID:
		if (val[0] != ILB_SRVID_PREFIX)
			rc = ILBADM_INVAL_SRVID;
		else
			rc = i_store_serverID(storep, val);
		break;
	case ILB_KEY_VIP: {
		ilb_ip_addr_t	*vip = &rd->r_vip;
		addr_type_t	at = numeric;
		char		*close = NULL;

		/*
		 * we duplicate some functionality of i_match_hostorip
		 * here; that function is geared to mandate '[]' for IPv6
		 * addresses, which we want to relax here, so as not to
		 * make i_match_hostorip even longer, we do what we need
		 * here.
		 */
		if (*val == '[') {
			val++;
			if ((close = strchr(val, (int)']')) == NULL) {
				rc = ILBADM_INVAL_SYNTAX;
				break;
			}
			*close = '\0';
		}
		rc = i_match_onehost(val, vip, &at);
		/* re-assemble string as we found it */
		if (close != NULL) {
			*close = ']';
			if (rc == ILBADM_OK && vip->ia_af != AF_INET6) {
				ilbadm_err(gettext("use of '[]' only valid"
				    " with IPv6 addresses"));
				rc = ILBADM_LIBERR;
			}
		}
		break;
	}
	case ILB_KEY_CONNDRAIN:
		tmp_val = strtoll(val, NULL, 10);
		if (tmp_val <= 0 || tmp_val > UINT_MAX) {
			rc = ILBADM_EINVAL;
			break;
		}
		rd->r_conndrain = tmp_val;
		break;
	case ILB_KEY_NAT_TO:
		tmp_val = strtoll(val, NULL, 10);
		if (tmp_val < 0 || tmp_val > UINT_MAX) {
			rc = ILBADM_EINVAL;
			break;
		}
		rd->r_nat_timeout = tmp_val;
		break;
	case ILB_KEY_STICKY_TO:
		tmp_val = strtoll(val, NULL, 10);
		if (tmp_val <= 0 || tmp_val > UINT_MAX) {
			rc = ILBADM_EINVAL;
			break;
		}
		rd->r_sticky_timeout = tmp_val;
		break;
	case ILB_KEY_PORT:
		if (isdigit(*val)) {
			ilbadm_servnode_t	sn;

			bzero(&sn, sizeof (sn));
			rc = i_match_hostorip((void *)&sn, sg, val,
			    OPT_PORTS_ONLY, ILB_KEY_PORT);
			if (rc != ILBADM_OK)
				break;
			rd->r_minport = sn.s_spec.sd_minport;
			rd->r_maxport = sn.s_spec.sd_maxport;
		} else {
			struct servent	*se;

			se = getservbyname(val, NULL);
			if (se == NULL) {
				rc = ILBADM_ENOSERVICE;
				break;
			}
			rd->r_minport = se->s_port;
			rd->r_maxport = 0;
		}
		break;
	case ILB_KEY_HCPORT:
		if (isdigit(*val)) {
			int hcport = atoi(val);

			if (hcport < 1 || hcport > 65535) {
				ilbadm_err(gettext("illegal number for"
				    " hcport %s"), val);
				rc = ILBADM_LIBERR;
				break;
			}
			rd->r_hcport = htons(hcport);
			rd->r_hcpflag = ILB_HCI_PROBE_FIX;
		} else if (strcasecmp(val, "ANY") == 0) {
			rd->r_hcport = 0;
			rd->r_hcpflag = ILB_HCI_PROBE_ANY;
		} else {
			return (ILBADM_EINVAL);
		}
		break;
	case ILB_KEY_PROTOCOL:
		pe = getprotobyname(val);
		if (pe == NULL)
			rc = ILBADM_ENOPROTO;
		else
			rd->r_proto = pe->p_proto;
		break;
	case ILB_KEY_ALGORITHM:
		rd->r_algo = i_val_from_str(val, &algo_types[0]);
		if (rd->r_algo == ILBD_BAD_VAL)
			rc = ILBADM_INVAL_ALG;
		break;
	case ILB_KEY_STICKY:
		rd->r_flags |= ILB_FLAGS_RULE_STICKY;
		/*
		 * CAVEAT: the use of r_vip.ia_af implies that the VIP
		 * *must* be specified on the commandline *before*
		 * the sticky mask.
		 */
		if (AF_UNSPEC == rd->r_vip.ia_af) {
			ilbadm_err(gettext("option '%s' requires that VIP be "
			    "specified first"), ilbadm_key_to_opt(keyword));
			rc = ILBADM_LIBERR;
			break;
		}
		rc = ilbadm_set_netmask(val, &rd->r_stickymask,
		    rd->r_vip.ia_af);
		break;
	case ILB_KEY_TYPE:
		rd->r_topo = i_val_from_str(val, &topo_types[0]);
		if (rd->r_topo == ILBD_BAD_VAL)
			rc = ILBADM_INVAL_OPER;
		break;
	case ILB_KEY_SERVERGROUP:
		(void) strlcpy(rd->r_sgname, (char *)val,
		    sizeof (rd->r_sgname));
		break;
	case ILB_KEY_HEALTHCHECK:
		(void) strlcpy(rd->r_hcname, (char *)val,
		    sizeof (rd->r_hcname));
		break;
	case ILB_KEY_HC_TEST:
		(void) strlcpy(hc_info->hci_test, (char *)val,
		    sizeof (hc_info->hci_test));
		break;
	case ILB_KEY_HC_COUNT:
		if (isdigit(*val))
			hc_info->hci_count = atoi(val);
		else
			return (ILBADM_EINVAL);
		break;
	case ILB_KEY_HC_INTERVAL:
		if (isdigit(*val))
			hc_info->hci_interval = atoi(val);
		else
			return (ILBADM_EINVAL);
		break;
	case ILB_KEY_HC_TIMEOUT:
		if (isdigit(*val))
			hc_info->hci_timeout = atoi(val);
		else
			return (ILBADM_EINVAL);
		break;
	default: rc = ILBADM_INVAL_KEYWORD;
		break;
	}

	return (rc);
}

/*
 * generic parsing function.
 * parses "key=value[,value]" strings in "arg". keylist determines the
 * list of valid keys in the LHS. keycode determines interpretation and
 * storage in store
 * XXXms: looks like "key=value[,value]" violates spec. needs a fix
 */
ilbadm_status_t
i_parse_optstring(char *arg, void *store, ilbadm_key_name_t *keylist,
    int flags, int *count)
{
	ilbadm_status_t	rc = ILBADM_OK;
	char		*comma = NULL, *equals = NULL;
	char		*key, *nextkey, *val;
	ilbadm_key_code_t	keyword;
	boolean_t	is_value_list = flags & OPT_VALUE_LIST;
	boolean_t	assign_seen = B_FALSE;
	int		n;

	key = arg;
	n = 1;
	/*
	 * Algorithm:
	 * 1. find any commas indicating and seperating current value
	 *    from a following value
	 * 2. if we're expecting a list of values (seperated by commas)
	 *	and have already seen the assignment, then
	 *	get the next "value"
	 * 3. else (we're looking at the first element of the RHS)
	 *	4. find the '='
	 *	5. match the keyword to the list we were passed in
	 * 6. store the value.
	 */
	while (key != NULL && *key != '\0') {
		comma = equals = NULL;

		/* 2 */
		nextkey = strchr(key, (int)',');
		if (nextkey != NULL) {
			comma = nextkey++;
			*comma = '\0';
		}

		/* 3a */
		if (is_value_list && assign_seen) {
			val = key;
		/* 3b */
		} else {
			/* 4 */
			equals = strchr(key, (int)'=');
			if (equals == NULL) {
				ilbadm_err("%s: %s", key,
				    ilbadm_errstr(ILBADM_ASSIGNREQ));
				rc = ILBADM_LIBERR;
				goto out;
			}
			val = equals + 1;
			*equals = '\0';
			assign_seen = B_TRUE;

			/* 5 */
			keyword = i_match_key(key, keylist);
			if (keyword == ILB_KEY_BAD) {
				ilbadm_err(gettext("bad keyword %s"), key);
				rc = ILBADM_LIBERR;
				goto out;
			}
		}

		/* 6 */
		rc = i_store_val(val, store, keyword);
		if (rc != ILBADM_OK) {
			ilbadm_err("%s: %s", key, ilbadm_errstr(rc));
			/* Change to ILBADM_ILBERR to avoid more err msgs. */
			rc = ILBADM_LIBERR;
			goto out;
		}

		key = nextkey;
		n++;
	}

out:
	if (comma != NULL)
		*comma = ',';
	if (equals != NULL)
		*equals = '=';
	if (count != NULL)
		*count = n;
	return (rc);
}
