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
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/list.h>
#include <netdb.h>
#include <ofmt.h>
#include <assert.h>
#include <libilb.h>
#include "ilbadm.h"

static ilbadm_key_name_t rl_incoming_keys[] = {
	{ILB_KEY_VIP, "vip", ""},
	{ILB_KEY_PORT, "port", ""},
	{ILB_KEY_PROTOCOL, "protocol", "prot"},
	{ILB_KEY_BAD, "", ""}
};
static ilbadm_key_name_t rl_method_keys[] = {
	{ILB_KEY_ALGORITHM, "lbalg", "algo"},
	{ILB_KEY_TYPE, "type", "topo"},
	{ILB_KEY_SRC, "proxy-src", "nat-src"},
	{ILB_KEY_STICKY, "pmask", "persist"},
	{ILB_KEY_BAD, "", ""}
};
static ilbadm_key_name_t rl_outgoing_keys[] = {
	{ILB_KEY_SERVERGROUP, "servergroup", "sg"},
	{ILB_KEY_BAD, "", ""}
};
static ilbadm_key_name_t rl_healthchk_keys[] = {
	{ILB_KEY_HEALTHCHECK, "hc-name", "hcn"},
	{ILB_KEY_HCPORT, "hc-port", "hcp"},
	{ILB_KEY_BAD, "", ""}
};
static ilbadm_key_name_t rl_timer_keys[] = {
	{ILB_KEY_CONNDRAIN, "conn-drain", ""},
	{ILB_KEY_NAT_TO, "nat-timeout", ""},
	{ILB_KEY_STICKY_TO, "persist-timeout", ""},
	{ILB_KEY_BAD, "", ""}
};

static ilbadm_key_name_t *all_keys[] = {
	rl_incoming_keys, rl_method_keys, rl_outgoing_keys,
	rl_healthchk_keys, rl_timer_keys, NULL
};


/* field ids for of_* functions */
#define	OF_IP_VIP		0
#define	OF_IP_PROXYSRC		1
#define	OF_IP_STICKYMASK	2

#define	OF_STR_RNAME		0
#define	OF_STR_HCNAME		1
#define	OF_STR_SGNAME		2
#define	OF_STR_INTERFACE	3

#define	OF_PORT			0
#define	OF_HCPORT		1

#define	OF_T_CONN		0
#define	OF_T_NAT		1
#define	OF_T_STICKY		2

#define	OF_SRV_ID		0
#define	OF_SRV_ADDR		1
#define	OF_SRV_PORT		2
#define	OF_SRV_STATUS		3
#define	OF_SRV_RNAME		4
#define	OF_SRV_SGNAME		5
#define	OF_SRV_HOSTNAME		6

/* some field sizes of ofmt_field_t arrays */
#define	IPv4_FIELDWIDTH		16
#define	IPv6_FIELDWIDTH		39
#define	ILB_HOSTNAMELEN		20
#define	ILB_STATUSFIELD_LEN	7

typedef struct arg_struct {
	int		flags;
	char		*o_str;
	ofmt_field_t	*o_fields;
	ofmt_handle_t	oh;
} ilbadm_sh_rl_arg_t;

typedef struct ilbadm_rl_exp_arg {
	FILE	*fp;
} ilbadm_rl_exp_arg_t;

typedef struct ilbadm_rl_list_arg {
	ilb_handle_t	h;
	ilb_rule_data_t	*rd;
} ilbadm_rl_list_arg_t;

typedef struct ilbadm_rl_srvlist_arg {
	char		*sgname;
	ilb_server_data_t	*sd;
	ilb_rule_data_t	*rd;
	int		flags;
	char		*o_str;
	ofmt_field_t	*o_fields;
	ofmt_handle_t	oh;
} ilbadm_rl_srvlist_arg_t;

static ofmt_cb_t of_algo;
static ofmt_cb_t of_proto;
static ofmt_cb_t of_rl_ip;
static ofmt_cb_t of_rl_mask;
static ofmt_cb_t of_rport;
static ofmt_cb_t of_rstatus;
static ofmt_cb_t of_str;
static ofmt_cb_t of_time;
static ofmt_cb_t of_topo;
static ofmt_cb_t of_rl_srvlist;

static boolean_t of_srv2str(ofmt_arg_t *, char *, uint_t);
static boolean_t of_port2str(in_port_t, in_port_t, char *, uint_t);

static ofmt_field_t rfields_v4[] = {
	{"RULENAME",	ILB_NAMESZ,	OF_STR_RNAME,	of_str},
	{"STATUS",	ILB_STATUSFIELD_LEN,	0,	of_rstatus},
	{"PORT",	10,		OF_PORT,	of_rport},
	{"PROTOCOL",	5,		0,	of_proto},
	{"LBALG",	12,		0,	of_algo},
	{"TYPE",	8,		0,	of_topo},
	{"PROXY-SRC",	2*IPv4_FIELDWIDTH+1,	OF_IP_PROXYSRC,	of_rl_ip},
	{"PMASK",	6,	OF_IP_STICKYMASK, of_rl_mask},
	{"HC-NAME",	ILB_NAMESZ,	OF_STR_HCNAME,	of_str},
	{"HC-PORT",	8,		OF_HCPORT,	of_rport},
	{"CONN-DRAIN",	11,		OF_T_CONN,	of_time},
	{"NAT-TIMEOUT",	12,		OF_T_NAT,	of_time},
	{"PERSIST-TIMEOUT",		16,	OF_T_STICKY,	of_time},
	{"SERVERGROUP",	ILB_SGNAME_SZ,	OF_STR_SGNAME,	of_str},
	{"VIP",		IPv4_FIELDWIDTH,	OF_IP_VIP,	of_rl_ip},
	{"SERVERS",	20,		0,	of_rl_srvlist},
	{NULL,		0,		0,	NULL}
};

static ofmt_field_t rfields_v6[] = {
	{"RULENAME",	ILB_NAMESZ,	OF_STR_RNAME,	of_str},
	{"STATUS",	ILB_STATUSFIELD_LEN,	0,	of_rstatus},
	{"PORT",	10,		OF_PORT,	of_rport},
	{"PROTOCOL",	5,		0,	of_proto},
	{"LBALG",	12,		0,	of_algo},
	{"TYPE",	8,		0,	of_topo},
	{"PROXY-SRC",	IPv6_FIELDWIDTH,	OF_IP_PROXYSRC,	of_rl_ip},
	{"PMASK",	6,		OF_IP_STICKYMASK, of_rl_mask},
	{"HC-NAME",	ILB_NAMESZ,	OF_STR_HCNAME,	of_str},
	{"HC-PORT",	8,		OF_HCPORT,	of_rport},
	{"CONN-DRAIN",	11,		OF_T_CONN,	of_time},
	{"NAT-TIMEOUT",	12,		OF_T_NAT,	of_time},
	{"PERSIST-TIMEOUT",		16,	OF_T_STICKY,	of_time},
	{"SERVERGROUP",	ILB_SGNAME_SZ,	OF_STR_SGNAME,	of_str},
	{"VIP",		IPv6_FIELDWIDTH,	OF_IP_VIP,	of_rl_ip},
	{"SERVERS",	20,		0,	of_rl_srvlist},
	{NULL,		0,		0,	NULL}
};

static ofmt_field_t ssfields_v4[] = {
	{"SERVERID",	ILB_NAMESZ,	OF_SRV_ID,	of_srv2str},
	{"ADDRESS",	IPv4_FIELDWIDTH,	OF_SRV_ADDR,	of_srv2str},
	{"PORT",	5,			OF_SRV_PORT,	of_srv2str},
	{"RULENAME",	ILB_NAMESZ,	OF_SRV_RNAME,	of_srv2str},
	{"STATUS",	ILB_STATUSFIELD_LEN,	OF_SRV_STATUS,	of_srv2str},
	{"SERVERGROUP",	ILB_SGNAME_SZ,	OF_SRV_SGNAME,	of_srv2str},
	{"HOSTNAME",	ILB_HOSTNAMELEN,	OF_SRV_HOSTNAME, of_srv2str},
	{NULL,		0,		0,	NULL}
};

static ofmt_field_t ssfields_v6[] = {
	{"SERVERID",	ILB_NAMESZ,	OF_SRV_ID,	of_srv2str},
	{"ADDRESS",	IPv6_FIELDWIDTH,	OF_SRV_ADDR,	of_srv2str},
	{"PORT",	5,			OF_SRV_PORT,	of_srv2str},
	{"RULENAME",	ILB_NAMESZ,	OF_SRV_RNAME,	of_srv2str},
	{"STATUS",	ILB_STATUSFIELD_LEN,	OF_SRV_STATUS,	of_srv2str},
	{"SERVERGROUP",	ILB_SGNAME_SZ,	OF_SRV_SGNAME,	of_srv2str},
	{"HOSTNAME",	ILB_HOSTNAMELEN,	OF_SRV_HOSTNAME, of_srv2str},
	{NULL,		0,		0,	NULL}
};

extern int	optind, optopt, opterr;
extern char	*optarg;

extern ilbadm_val_type_t algo_types[];
extern ilbadm_val_type_t topo_types[];

static char *
i_key_to_opt(ilbadm_key_name_t *n, ilbadm_key_code_t k)
{
	int i;

	for (i = 0; n[i].k_key != ILB_KEY_BAD; i++)
		if (n[i].k_key == k)
			break;

	return (n[i].k_name);
}

char *
ilbadm_key_to_opt(ilbadm_key_code_t k)
{
	char 	*name;
	int	i;

	for (i = 0; all_keys[i] != NULL; i++) {
		name = i_key_to_opt(all_keys[i], k);
		if (*name != '\0')
			return (name);
	}

	return (NULL);
}

/*
 * ports are in HOST byte order
 */
static void
ports2str(short port1, short port2, char *buf, const int sz)
{
	if (port2 <= port1)
		(void) snprintf(buf, sz, "port=%d", port1);
	else
		(void) snprintf(buf, sz, "port=%d-%d", port1, port2);
}

static void
proto2str(short proto, char *buf, int sz)
{
	struct protoent *pe;

	pe = getprotobynumber((int)proto);
	if (pe != NULL)
		(void) snprintf(buf, sz, "protocol=%s", pe->p_name);
	else
		(void) sprintf(buf, "(bad proto %d)", proto);
}

static void
algo2str(ilb_algo_t algo, char *buf, int sz)
{
	char 	*s = i_str_from_val((int)algo, &algo_types[0]);

	(void) snprintf(buf, sz, "lbalg=%s", (s && *s) ? s : "(bad algo)");
}

static int
algo2bare_str(ilb_algo_t algo, char *buf, int sz)
{
	char 	*s = i_str_from_val((int)algo, &algo_types[0]);

	return (snprintf(buf, sz, "%s", (s && *s) ? s : ""));
}

static void
topo2str(ilb_topo_t topo, char *buf, int sz)
{
	char 	*s = i_str_from_val((int)topo, &topo_types[0]);

	(void) snprintf(buf, sz, "type=%s", (s && *s) ? s : "(bad type)");
}

static int
topo2bare_str(ilb_topo_t topo, char *buf, int sz)
{
	char 	*s = i_str_from_val((int)topo, &topo_types[0]);

	return (snprintf(buf, sz, "%s", (s && *s) ? s : ""));
}

static boolean_t
of_str(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;

	switch (of_arg->ofmt_id) {
	case OF_STR_RNAME:
		(void) strlcpy(buf, rd->r_name, bufsize);
		break;
	case OF_STR_SGNAME:
		(void) strlcpy(buf, rd->r_sgname, bufsize);
		break;
	case OF_STR_HCNAME:
		if (rd->r_hcname != NULL && *(rd->r_hcname) != '\0')
			(void) strlcpy(buf, rd->r_hcname, bufsize);
		break;
	}
	return (B_TRUE);
}

/* ARGSUSED */
static boolean_t
of_proto(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;

	if (rd->r_proto == IPPROTO_TCP)
		(void) strlcpy(buf, "TCP", bufsize);
	else if (rd->r_proto == IPPROTO_UDP)
		(void) strlcpy(buf, "UDP", bufsize);
	else
		return (B_FALSE);
	return (B_TRUE);
}

static boolean_t
of_rl_ip(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;
	ilb_ip_addr_t	*ip = NULL, *ip2 = NULL;

	switch (of_arg->ofmt_id) {
	case OF_IP_VIP:
		ip = &rd->r_vip;
		break;
	case OF_IP_PROXYSRC:
		ip = &rd->r_nat_src_start;
		ip2 = &rd->r_nat_src_end;
		break;
	case OF_IP_STICKYMASK:
		ip = &rd->r_stickymask;
		break;
	}

	/* only print something valid */
	if (ip != NULL && (ip->ia_af == AF_INET || ip->ia_af == AF_INET6))
		ip2str(ip, buf, bufsize, V6_ADDRONLY);
	if (ip2 != NULL && (ip2->ia_af == AF_INET || ip2->ia_af == AF_INET6) &&
	    buf[0] != '\0') {
		int	sl = strlen(buf);

		buf += sl; bufsize -= sl;
		*buf++ = '-'; bufsize--;
		ip2str(ip2, buf, bufsize, V6_ADDRONLY);
	}

	return (B_TRUE);
}

static boolean_t
of_rl_mask(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;
	ilb_ip_addr_t	*ip = NULL;

	assert(of_arg->ofmt_id == OF_IP_STICKYMASK);
	if (!(rd->r_flags & ILB_FLAGS_RULE_STICKY))
		return (B_TRUE);
	ip = &rd->r_stickymask;

	(void) snprintf(buf, bufsize, "/%d", ilbadm_mask_to_prefixlen(ip));
	return (B_TRUE);
}

static void
hcport_print(ilb_rule_data_t *rd, char *buf, uint_t bufsize)
{
	if (rd->r_hcport != 0)
		(void) snprintf(buf, bufsize, "%d", ntohs(rd->r_hcport));
	else if (rd->r_hcpflag == ILB_HCI_PROBE_ANY)
		(void) snprintf(buf, bufsize, "ANY");
	else
		buf[0] = '\0';
}
static boolean_t
of_rport(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;

	if (of_arg->ofmt_id == OF_PORT)
		return (of_port2str(rd->r_minport, rd->r_maxport, buf,
		    bufsize));

	/* only print a hcport if there's a hc name as well */
	if (of_arg->ofmt_id == OF_HCPORT && rd->r_hcname[0] != '\0')
		hcport_print(rd, buf, bufsize);

	return (B_TRUE);
}

/* ARGSUSED */
static boolean_t
of_rstatus(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;

	if ((rd->r_flags & ILB_FLAGS_RULE_ENABLED) == ILB_FLAGS_RULE_ENABLED)
		buf[0] = 'E';
	else
		buf[0] = 'D';
	buf[1] = '\0';
	return (B_TRUE);
}

static boolean_t
of_algo(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;

	if (algo2bare_str(rd->r_algo, buf, bufsize) == 0)
		return (B_FALSE);
	return (B_TRUE);
}

static boolean_t
of_topo(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;

	if (topo2bare_str(rd->r_topo, buf, bufsize) == 0)
		return (B_FALSE);
	return (B_TRUE);
}

static boolean_t
of_time(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;

	switch (of_arg->ofmt_id) {
	case OF_T_CONN:
		(void) snprintf(buf, bufsize, "%u", rd->r_conndrain);
		break;
	case OF_T_NAT:
		(void) snprintf(buf, bufsize, "%u", rd->r_nat_timeout);
		break;
	case OF_T_STICKY:
		(void) snprintf(buf, bufsize, "%u", rd->r_sticky_timeout);
		break;
	}
	return (B_TRUE);
}

typedef struct rl_showlist_arg {
	char	*buf;
	uint_t	bufsize;
} rl_showlist_arg_t;

/* ARGSUSED */
/* called by ilb_walk_servers(), cannot get rid of unused args */
static ilb_status_t
srv2srvID(ilb_handle_t h, ilb_server_data_t *sd, const char *sgname, void *arg)
{
	rl_showlist_arg_t	*sla = (rl_showlist_arg_t *)arg;
	int			len;

	(void) snprintf(sla->buf, sla->bufsize, "%s,", sd->sd_srvID);
	len = strlen(sd->sd_srvID) + 1;
	sla->buf += len;
	sla->bufsize -= len;

	return (ILB_STATUS_OK);
}

static boolean_t
of_rl_srvlist(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_list_arg_t *ra = (ilbadm_rl_list_arg_t *)of_arg->ofmt_cbarg;
	ilb_rule_data_t	*rd = (ilb_rule_data_t *)ra->rd;
	rl_showlist_arg_t	sla;

	sla.buf = buf;
	sla.bufsize = bufsize;

	(void) ilb_walk_servers(ra->h, srv2srvID, rd->r_sgname,
	    (void *)&sla);
	/* we're trailing a ',' which we need to remove */
	*--sla.buf = '\0';

	return (B_TRUE);
}

#define	RMAXCOLS 120	/* enough? */
#define	SERVER_WIDTH	(ILB_NAMESZ+1)	/* 1st guess */

static boolean_t
of_port2str(in_port_t minport, in_port_t maxport, char *buf, uint_t bufsize)
{
	in_port_t	h_min, h_max;
	int		len;

	h_min = ntohs(minport);
	h_max = ntohs(maxport);

	if (h_min == 0)
		return (B_FALSE); /* print "unspec" == "all ports" */

	len = snprintf(buf, bufsize, "%d", h_min);
	if (h_max > h_min)
		(void) snprintf(buf + len, bufsize - len, "-%d", h_max);
	return (B_TRUE);
}

static ilbadm_status_t
ip2hostname(ilb_ip_addr_t *ip, char *buf, uint_t bufsize)
{
	int		ret;
	struct hostent	*he;

	switch (ip->ia_af) {
	case AF_INET:
		he = getipnodebyaddr((char *)&ip->ia_v4, sizeof (ip->ia_v4),
		    ip->ia_af, &ret);
		break;
	case AF_INET6:
		he = getipnodebyaddr((char *)&ip->ia_v6, sizeof (ip->ia_v6),
		    ip->ia_af, &ret);
		break;
	default: return (ILBADM_INVAL_AF);
	}

	/* if we can't resolve this, just return an empty name */
	if (he == NULL)
		buf[0] = '\0';
	else
		(void) strlcpy(buf, he->h_name, bufsize);

	return (ILBADM_OK);
}

/* ARGSUSED */
/*
 * Since this function is used by libilb routine ilb_walk_rules()
 * it must return libilb errors
 */
static ilb_status_t
ilbadm_show_onerule(ilb_handle_t h, ilb_rule_data_t *rd, void *arg)
{
	ilbadm_sh_rl_arg_t	*larg = (ilbadm_sh_rl_arg_t *)arg;
	ofmt_status_t	oerr;
	int		oflags = 0;
	int		ocols = RMAXCOLS;
	ilbadm_rl_list_arg_t	ra;
	static ofmt_handle_t	oh = (ofmt_handle_t)NULL;
	ofmt_field_t	*fields;
	boolean_t	r_enabled = rd->r_flags & ILB_FLAGS_RULE_ENABLED;

	if (larg->o_str == NULL) {
		ilbadm_err(gettext("internal error"));
		return (ILB_STATUS_GENERIC);
	}

	/*
	 * only print rules (enabled/dis-) we're asked to
	 * note: both LIST_**ABLED flags can be set at the same time,
	 * whereas a rule has one state only. therefore the complicated
	 * statement.
	 */
	if (!((r_enabled && (larg->flags & ILBADM_LIST_ENABLED)) ||
	    (!r_enabled && (larg->flags & ILBADM_LIST_DISABLED))))
		return (ILB_STATUS_OK);

	if (larg->flags & ILBADM_LIST_PARSE)
		oflags |= OFMT_PARSABLE;

	if (larg->flags & ILBADM_LIST_FULL)
		oflags |= OFMT_MULTILINE;

	bzero(&ra, sizeof (ra));
	ra.rd = rd;
	ra.h = h;

	if (oh == NULL) {
		if (rd->r_vip.ia_af == AF_INET)
			fields = rfields_v4;
		else
			fields = rfields_v6;

		oerr = ofmt_open(larg->o_str, fields, oflags, ocols, &oh);
		if (oerr != OFMT_SUCCESS) {
			char	e[80];

			ilbadm_err(gettext("ofmt_open failed: %s"),
			    ofmt_strerror(oh, oerr, e, sizeof (e)));
			return (ILB_STATUS_GENERIC);
		}
	}

	ofmt_print(oh, &ra);

	return (ILB_STATUS_OK);
}

static char *full_list_rule_hdrs =
	"RULENAME,STATUS,PORT,PROTOCOL,LBALG,TYPE,PROXY-SRC,PMASK,"
	"HC-NAME,HC-PORT,CONN-DRAIN,NAT-TIMEOUT,"
	"PERSIST-TIMEOUT,SERVERGROUP,VIP,SERVERS";
static char *def_list_rule_hdrs =
	"RULENAME,STATUS,LBALG,TYPE,PROTOCOL,VIP,PORT";

/* ARGSUSED */
ilbadm_status_t
ilbadm_show_rules(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	int		c;
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	boolean_t	o_opt = B_FALSE, p_opt = B_FALSE;
	boolean_t	f_opt = B_FALSE;
	ilbadm_sh_rl_arg_t	larg = {0, NULL, NULL, NULL};

	larg.flags = ILBADM_LIST_ENABLED | ILBADM_LIST_DISABLED;
	while ((c = getopt(argc, argv, ":fpedo:")) != -1) {
		switch ((char)c) {
		case 'f': larg.flags |= ILBADM_LIST_FULL;
			larg.o_str = full_list_rule_hdrs;
			f_opt = B_TRUE;
			break;
		case 'p': larg.flags |= ILBADM_LIST_PARSE;
			p_opt = B_TRUE;
			break;
		case 'o': larg.o_str = optarg;
			o_opt = B_TRUE;
			break;
		/* -e and -d may be repeated - make sure the last one wins */
		case 'e': larg.flags &= ILBADM_LIST_NODISABLED;
			larg.flags |= ILBADM_LIST_ENABLED;
			break;
		case 'd': larg.flags &= ILBADM_LIST_NOENABLED;
			larg.flags |= ILBADM_LIST_DISABLED;
			break;
		case ':': ilbadm_err(gettext("missing option argument for %c"),
			    (char)optopt);
			rc = ILBADM_LIBERR;
			goto out;
		case '?':
		default:
			unknown_opt(argv, optind-1);
			/* not reached */
			break;
		}
	}

	if (f_opt && o_opt) {
		ilbadm_err(gettext("options -o and -f are mutually"
		    " exclusive"));
		exit(1);
	}

	if (p_opt && !o_opt) {
		ilbadm_err(gettext("option -p requires -o"));
		exit(1);
	}

	if (p_opt && larg.o_str != NULL &&
	    (strcasecmp(larg.o_str, "all") == 0)) {
		ilbadm_err(gettext("option -p requires explicit field"
		    " names for -o"));
		exit(1);
	}

	/* no -o option, so we use std. fields */
	if (!o_opt && !f_opt)
		larg.o_str = def_list_rule_hdrs;

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	if (optind >= argc) {
		rclib = ilb_walk_rules(h, ilbadm_show_onerule, NULL,
		    (void*)&larg);
	} else {
		while (optind < argc) {
			rclib = ilb_walk_rules(h, ilbadm_show_onerule,
			    argv[optind++], (void*)&larg);
			if (rclib != ILB_STATUS_OK)
				break;
		}
	}
out:
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if (rclib != ILB_STATUS_OK) {
		/*
		 * The show function returns ILB_STATUS_GENERIC after printing
		 * out an error message.  So we don't need to print it again.
		 */
		if (rclib != ILB_STATUS_GENERIC)
			ilbadm_err(ilb_errstr(rclib));
		rc = ILBADM_LIBERR;
	}
	return (rc);
}

static boolean_t
of_srv2str(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbadm_rl_srvlist_arg_t  *larg =
	    (ilbadm_rl_srvlist_arg_t *)of_arg->ofmt_cbarg;
	ilb_server_data_t	*sd = larg->sd;
	uint_t		op = of_arg->ofmt_id;
	boolean_t	ret = B_TRUE;
	ilbadm_status_t	rc;

	if (sd == NULL)
		return (B_FALSE);

	switch (op) {
	case OF_SRV_ID:
		(void) strlcpy(buf, sd->sd_srvID, bufsize);
		break;
	case OF_SRV_STATUS:
		if (ILB_IS_SRV_ENABLED(sd->sd_flags))
			buf[0] = 'E';
		else
			buf[0] = 'D';
		buf[1] = '\0';
		break;
	case OF_SRV_RNAME:
		(void) strlcpy(buf, larg->rd->r_name, bufsize);
		break;
	case OF_SRV_SGNAME:
		(void) strlcpy(buf, larg->sgname, bufsize);
		break;
	case OF_SRV_HOSTNAME:
		rc = ip2hostname(&sd->sd_addr, buf, bufsize);
		if (rc != ILBADM_OK) {
			buf[0] = '\0';
			ret = B_FALSE;
		}
		break;
	case OF_SRV_PORT:
		ret = of_port2str(sd->sd_minport, sd->sd_maxport,
		    buf, bufsize);
		break;
	case OF_SRV_ADDR:
		ip2str(&sd->sd_addr, buf, bufsize, V6_ADDRONLY);
		break;
	}

	return (ret);
}

/* ARGSUSED */
static ilb_status_t
i_show_rl_srv(ilb_handle_t h, ilb_server_data_t *sd, const char *sgname,
    void *arg)
{
	ilbadm_rl_srvlist_arg_t	*larg = (ilbadm_rl_srvlist_arg_t *)arg;

	larg->sd = sd;
	ofmt_print(larg->oh, larg);
	return (ILB_STATUS_OK);
}

/* ARGSUSED */
/*
 * Since this function is used by libilb routine ilb_walk_rules()
 * it must return libilb errors
 */
ilb_status_t
ilbadm_show_rl_servers(ilb_handle_t h, ilb_rule_data_t *rd, void *arg)
{
	ofmt_status_t	oerr;
	int		oflags = 0;
	int		ocols = RMAXCOLS;
	ofmt_field_t	*fields;
	static ofmt_handle_t	oh = (ofmt_handle_t)NULL;
	ilbadm_rl_srvlist_arg_t	*larg = (ilbadm_rl_srvlist_arg_t *)arg;

	/*
	 * in full mode, we currently re-open ofmt() for every rule; we use
	 * a variable number of lines, as we print one for every server
	 * attached to a rule.
	 */
	if (larg->o_str == NULL) {
		ilbadm_err(gettext("internal error"));
		return (ILB_STATUS_GENERIC);
	}

	if (larg->flags & ILBADM_LIST_PARSE)
		oflags |= OFMT_PARSABLE;

	if (rd->r_vip.ia_af == AF_INET)
		fields = ssfields_v4;
	else
		fields = ssfields_v6;

	if (oh == NULL) {
		oerr = ofmt_open(larg->o_str, fields, oflags, ocols, &oh);
		if (oerr != OFMT_SUCCESS) {
			char	e[80];

			ilbadm_err(gettext("ofmt_open failed: %s"),
			    ofmt_strerror(oh, oerr, e, sizeof (e)));
			return (ILB_STATUS_GENERIC);
		}
		larg->oh = oh;
	}

	larg->rd = rd;
	larg->sgname = rd->r_sgname;

	return (ilb_walk_servers(h, i_show_rl_srv, rd->r_sgname, (void *)larg));
}

static char *def_show_srv_hdrs =
	"SERVERID,ADDRESS,PORT,RULENAME,STATUS,SERVERGROUP";

/* ARGSUSED */
ilbadm_status_t
ilbadm_show_server(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	int		c;
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	boolean_t	o_opt = B_FALSE, p_opt = B_FALSE;
	ilbadm_rl_srvlist_arg_t	larg;

	bzero(&larg, sizeof (larg));
	while ((c = getopt(argc, argv, ":po:")) != -1) {
		switch ((char)c) {
		case 'p': larg.flags |= ILBADM_LIST_PARSE;
			p_opt = B_TRUE;
			break;
		case 'o': larg.o_str = optarg;
			o_opt = B_TRUE;
			break;
		case ':': ilbadm_err(gettext("missing option argument for %c"),
			    (char)optopt);
			rc = ILBADM_LIBERR;
			goto out;
		case '?':
		default:
			unknown_opt(argv, optind-1);
			/* not reached */
			break;
		}
	}

	if (p_opt && !o_opt) {
		ilbadm_err(gettext("option -p requires -o"));
		exit(1);
	}

	if (p_opt && larg.o_str != NULL &&
	    (strcasecmp(larg.o_str, "all") == 0)) {
		ilbadm_err(gettext("option -p requires explicit"
		    "  field names for -o"));
		exit(1);
	}

	/* no -o option, so we use default fields */
	if (!o_opt)
		larg.o_str = def_show_srv_hdrs;

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	if (optind >= argc) {
		rclib = ilb_walk_rules(h, ilbadm_show_rl_servers, NULL,
		    (void*)&larg);
	} else {
		while (optind < argc) {
			rclib = ilb_walk_rules(h, ilbadm_show_rl_servers,
			    argv[optind++], (void*)&larg);
			if (rclib != ILB_STATUS_OK)
				break;
		}
	}
out:
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if (rclib != ILB_STATUS_OK) {
		/*
		 * The show function returns ILB_STATUS_GENERIC after printing
		 * out an error message.  So we don't need to print it again.
		 */
		if (rclib != ILB_STATUS_GENERIC)
			ilbadm_err(ilb_errstr(rclib));
		rc = ILBADM_LIBERR;
	}
	return (rc);
}

static ilbadm_status_t
i_parse_rl_arg(char *arg, ilb_rule_data_t *rd, ilbadm_key_name_t *keylist)
{
	ilbadm_status_t	rc;

	rc = i_parse_optstring(arg, (void *) rd, keylist,
	    OPT_PORTS, NULL);
	return (rc);
}

static void
i_ilbadm_alloc_rule(ilb_rule_data_t **rdp)
{
	ilb_rule_data_t	*rd;

	*rdp = rd = (ilb_rule_data_t *)calloc(sizeof (*rd), 1);
	if (rd == NULL)
		return;
	rd->r_proto = IPPROTO_TCP;
}

static void
i_ilbadm_free_rule(ilb_rule_data_t *rd)
{
	free(rd);
}

/* ARGSUSED */
ilbadm_status_t
ilbadm_destroy_rule(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilbadm_status_t	rc = ILBADM_OK;
	ilb_status_t	rclib = ILB_STATUS_OK;
	boolean_t	all_rules = B_FALSE;
	int		c, i;

	while ((c = getopt(argc, argv, ":a")) != -1) {
		switch ((char)c) {
		case 'a':
			all_rules = B_TRUE;
			break;
		case '?':
		default:
			unknown_opt(argv, optind-1);
			/* not reached */
			break;
		}
	}

	if (optind >= argc && !all_rules) {
		ilbadm_err(gettext("usage: delete-rule -a | name"));
		return (ILBADM_LIBERR);
	}

	/* either "-a" or rulename, not both */
	if (optind < argc && all_rules) {
		rc = ILBADM_INVAL_ARGS;
		goto out;
	}

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	if (all_rules) {
		rclib = ilb_destroy_rule(h, NULL);
		goto out;
	}

	for (i = optind; i < argc && rclib == ILB_STATUS_OK; i++)
		rclib = ilb_destroy_rule(h, argv[i]);

out:
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	/* This prints the specific errors */
	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		rc = ILBADM_LIBERR;
	}
	/* This prints the generic errors */
	if ((rc != ILBADM_OK) && (rc != ILBADM_LIBERR))
		ilbadm_err(ilbadm_errstr(rc));
	return (rc);
}

/* ARGSUSED */
static ilbadm_status_t
ilbadm_Xable_rule(int argc, char *argv[], ilbadm_cmd_t cmd)
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	int		i;

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;
	/*
	 * by default, en/disable-rule mean "all", and not using
	 * a rule name will cause this behaviour to kick in
	 */
	if (argc < 2) {
		if (cmd == cmd_enable_rule)
			rclib = ilb_enable_rule(h, NULL);
		else
			rclib = ilb_disable_rule(h, NULL);
	} else {

		for (i = optind; i < argc && rc == ILBADM_OK; i++) {
			if (cmd == cmd_enable_rule)
				rclib = ilb_enable_rule(h, argv[i]);
			else
				rclib = ilb_disable_rule(h, argv[i]);
		}
	}
out:
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		rc = ILBADM_LIBERR;
	}
	return (rc);
}

ilbadm_status_t
ilbadm_enable_rule(int argc, char *argv[])
{

	return (ilbadm_Xable_rule(argc, argv, cmd_enable_rule));
}

ilbadm_status_t
ilbadm_disable_rule(int argc, char *argv[])
{
	return (ilbadm_Xable_rule(argc, argv, cmd_disable_rule));
}

/*
 * parse and create a rule
 */
ilbadm_status_t
ilbadm_create_rule(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	int		c;
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	ilb_rule_data_t	*rd;
	boolean_t	p_opt = B_FALSE;

	i_ilbadm_alloc_rule(&rd);

	while ((c = getopt(argc, argv, ":ei:m:o:t:h:p")) != -1) {
		switch ((char)c) {
		case 'e':
			rd->r_flags |= ILB_FLAGS_RULE_ENABLED;
			break;
		case 'h':
			/*
			 * Default value of of r_hcpflag means that if there
			 * is a port range, probe any port.  If there is only
			 * one port, probe that port.
			 */
			rd->r_hcpflag = ILB_HCI_PROBE_ANY;
			rc = i_parse_rl_arg(optarg, rd, &rl_healthchk_keys[0]);
			break;
		case 'o':
			rc = i_parse_rl_arg(optarg, rd, &rl_outgoing_keys[0]);
			break;
		case 'm':
			rc = i_parse_rl_arg(optarg, rd, &rl_method_keys[0]);
			break;
		case 't':
			rc = i_parse_rl_arg(optarg, rd, &rl_timer_keys[0]);
			break;
		case 'i':
			rc = i_parse_rl_arg(optarg, rd, &rl_incoming_keys[0]);
			break;
		case 'p':
			p_opt = B_TRUE;
			break;
		case ':':
			ilbadm_err(gettext("missing option-argument"
			    " for %c"), (char)optopt);
			rc = ILBADM_LIBERR;
			break;
		case '?':
		default:
			unknown_opt(argv, optind-1);
			/* not reached */
			break;

		}
		if (rc != ILBADM_OK)
			goto out;
	}

	if (optind >= argc) {
		ilbadm_err(gettext("missing mandatory arguments - please refer"
		    " to 'ilbadm create-rule' subcommand description in"
		    " ilbadm(8)"));
		rc = ILBADM_LIBERR;
		goto out;

	}

	if (p_opt) {
		/*
		 * if user hasn't specified a mask, apply default
		 */
		if ((rd->r_flags & ILB_FLAGS_RULE_STICKY) == 0) {
			char 	*maskstr;

			switch (rd->r_vip.ia_af) {
			case AF_INET:
				maskstr = "32";
				break;
			case AF_INET6:
				maskstr = "128";
				break;
			}
			rc = ilbadm_set_netmask(maskstr, &rd->r_stickymask,
			    rd->r_vip.ia_af);
			if (rc != ILBADM_OK) {
				ilbadm_err(gettext("trouble seting default"
				    " persistence mask"));
				rc = ILBADM_LIBERR;
				goto out;
			}
		}
	} else {
		/* use of sticky mask currently mandates "-p" */
		if ((rd->r_flags & ILB_FLAGS_RULE_STICKY) != 0) {
			ilbadm_err(gettext("use of stickymask requires"
			    " -p option"));
			rc = ILBADM_LIBERR;
			goto out;
		}
	}

	if (strlen(argv[optind]) > ILBD_NAMESZ -1) {
		ilbadm_err(gettext("rule name %s is too long -"
		    " must not exceed %d chars"), argv[optind],
		    ILBD_NAMESZ - 1);
		rc = ILBADM_LIBERR;
		goto out;
	}

	(void) strlcpy(rd->r_name, argv[optind], sizeof (rd->r_name));

	rc = i_check_rule_spec(rd);
	if (rc != ILBADM_OK)
		goto out;

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	rclib = ilb_create_rule(h, rd);

out:
	i_ilbadm_free_rule(rd);

	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		rc = ILBADM_LIBERR;
	}
	if ((rc != ILBADM_OK) && (rc != ILBADM_LIBERR))
		ilbadm_err(ilbadm_errstr(rc));

	return (rc);
}

/* ARGSUSED */

/*
 * Since this function is used by libilb function, ilb_walk_rules()
 * it must return libilb errors
 */
static ilb_status_t
ilbadm_export_rl(ilb_handle_t h, ilb_rule_data_t *rd, void *arg)
{
	char	linebuf[128];	/* should be enough */
	int	sz = sizeof (linebuf);
	FILE	*fp = ((ilbadm_rl_exp_arg_t *)arg)->fp;
	uint32_t	conndrain, nat_timeout, sticky_timeout;

	(void) fprintf(fp, "create-rule ");
	if (rd->r_flags & ILB_FLAGS_RULE_ENABLED)
		(void) fprintf(fp, "-e ");
	if (rd->r_flags & ILB_FLAGS_RULE_STICKY)
		(void) fprintf(fp, "-p ");

	ip2str(&rd->r_vip, linebuf, sz, V6_ADDRONLY);
	(void) fprintf(fp, "-i vip=%s,", linebuf);

	(void) ports2str(ntohs(rd->r_minport), ntohs(rd->r_maxport),
	    linebuf, sz);
	(void) fprintf(fp, "%s,", linebuf);

	proto2str(rd->r_proto, linebuf, sz);
	(void) fprintf(fp, "%s ", linebuf);

	algo2str(rd->r_algo, linebuf, sz);
	(void) fprintf(fp, "-m %s,", linebuf);

	topo2str(rd->r_topo, linebuf, sz);
	(void) fprintf(fp, "%s", linebuf);

	if (rd->r_nat_src_start.ia_af != AF_UNSPEC) {
		ip2str(&rd->r_nat_src_start, linebuf, sz, V6_ADDRONLY);
		/* if the address is unspecified, skip it */
		if (linebuf[0] != '\0') {
			(void) fprintf(fp, ",proxy-src=%s", linebuf);
			ip2str(&rd->r_nat_src_end, linebuf, sz, V6_ADDRONLY);
			(void) fprintf(fp, "-%s", linebuf);
		}
	}

	if (rd->r_flags & ILB_FLAGS_RULE_STICKY) {
		(void) fprintf(fp, ",pmask=/%d",
		    ilbadm_mask_to_prefixlen(&rd->r_stickymask));
	}

	(void) fprintf(fp, " ");

	if (*rd->r_hcname != '\0') {
		(void) fprintf(fp, "-h hc-name=%s", rd->r_hcname);
		hcport_print(rd, linebuf, sizeof (linebuf));

		if (linebuf[0] != '\0')
			(void) fprintf(fp, ",hc-port=%s", linebuf);
		(void) fprintf(fp, " ");
	}

	conndrain = rd->r_conndrain;
	nat_timeout = rd->r_nat_timeout;
	sticky_timeout = rd->r_sticky_timeout;
	if (conndrain != 0 || nat_timeout != 0 || sticky_timeout != 0) {
		int	cnt = 0;

		(void) fprintf(fp, "-t ");
		if (conndrain != 0) {
			cnt++;
			(void) fprintf(fp, "conn-drain=%u", conndrain);
		}
		if (nat_timeout != 0) {
			if (cnt > 0)
				(void) fprintf(fp, ",");
			cnt++;
			(void) fprintf(fp, "nat-timeout=%u", nat_timeout);
		}
		if (sticky_timeout != 0) {
			if (cnt > 0)
				(void) fprintf(fp, ",");
			(void) fprintf(fp, "persist-timeout=%u",
			    sticky_timeout);
		}
		(void) fprintf(fp, " ");
	}

	if (fprintf(fp, "-o servergroup=%s %s\n", rd->r_sgname, rd->r_name)
	    < 0 || fflush(fp) == EOF)
		return (ILB_STATUS_WRITE);

	return (ILB_STATUS_OK);
}

ilbadm_status_t
ilbadm_export_rules(ilb_handle_t h, FILE *fp)
{
	ilb_status_t	rclib;
	ilbadm_status_t	rc = ILBADM_OK;
	ilbadm_rl_exp_arg_t	arg;

	arg.fp = fp;

	rclib = ilb_walk_rules(h, ilbadm_export_rl, NULL, (void *)&arg);
	if (rclib != ILB_STATUS_OK)
		rc = ILBADM_LIBERR;
	return (rc);
}
