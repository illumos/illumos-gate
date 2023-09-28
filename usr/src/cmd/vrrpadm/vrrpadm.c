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

#include <sys/types.h>
#include <sys/varargs.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <locale.h>
#include <libintl.h>
#include <libvrrpadm.h>
#include <ofmt.h>

static vrrp_handle_t	vrrp_vh = NULL;
typedef void cmd_func_t(int, char *[], const char *);

static cmd_func_t do_create, do_delete, do_enable, do_disable,
    do_modify, do_show;

typedef struct {
	char		*c_name;
	cmd_func_t	*c_fn;
	const char	*c_usage;
} cmd_t;

static cmd_t cmds[] = {
	{ "create-router",	do_create,
	    "-V <vrid> -l <link> -A {inet | inet6} [-p <priority>] "
	    "[-i <adv_interval>] [-o <flags>] <router_name>" },
	{ "delete-router",	do_delete,	"<router_name>"		},
	{ "enable-router",	do_enable,	"<router_name>"		},
	{ "disable-router",	do_disable,	"<router_name>"		},
	{ "modify-router",	do_modify,
	    "[-p <priority>] [-i <adv_interval>] [-o <flags>] <router_name>" },
	{ "show-router",	do_show,
	    "[-P | -x] [-o field[,...]] [-p] [<router_name>]"	}
};

static const struct option lopts[] = {
	{"vrid",		required_argument,	0, 'V'},
	{"link",		required_argument,	0, 'l'},
	{"address_family",	required_argument,	0, 'A'},
	{"priority",		required_argument,	0, 'p'},
	{"adv_interval",	required_argument,	0, 'i'},
	{"flags",		required_argument,	0, 'o'},
	{ 0, 0, 0, 0 }
};

static const struct option l_show_opts[] = {
	{"peer",	no_argument,		0, 'P'},
	{"parsable",	no_argument,		0, 'p'},
	{"extended",	no_argument,		0, 'x'},
	{"output",	required_argument,	0, 'o'},
	{ 0, 0, 0, 0 }
};

static ofmt_cb_t sfunc_vrrp_conf;

/*
 * structures for 'dladm show-link -s' (print statistics)
 */
enum {
	ROUTER_NAME,
	ROUTER_VRID,
	ROUTER_LINK,
	ROUTER_VNIC,
	ROUTER_AF,
	ROUTER_PRIO,
	ROUTER_ADV_INTV,
	ROUTER_MODE,
	ROUTER_STATE,
	ROUTER_PRV_STAT,
	ROUTER_STAT_LAST,
	ROUTER_PEER,
	ROUTER_P_PRIO,
	ROUTER_P_INTV,
	ROUTER_P_ADV_LAST,
	ROUTER_M_DOWN_INTV,
	ROUTER_PRIMARY_IP,
	ROUTER_VIRTUAL_IPS,
	ROUTER_VIP_CNT
};

/*
 * structures for 'vrrpadm show-router'
 */
static const ofmt_field_t show_print_fields[] = {
/* name,	field width,	index,			callback */
{ "NAME",		8,	ROUTER_NAME,		sfunc_vrrp_conf	},
{ "VRID",		5,	ROUTER_VRID,		sfunc_vrrp_conf	},
{ "LINK",		8,	ROUTER_LINK,		sfunc_vrrp_conf },
{ "VNIC",		8,	ROUTER_VNIC,		sfunc_vrrp_conf },
{ "AF",			5,	ROUTER_AF,		sfunc_vrrp_conf },
{ "PRIO",		5,	ROUTER_PRIO,		sfunc_vrrp_conf },
{ "ADV_INTV",		9,	ROUTER_ADV_INTV,	sfunc_vrrp_conf },
{ "MODE",		6,	ROUTER_MODE,		sfunc_vrrp_conf	},
{ "STATE",		6,	ROUTER_STATE,		sfunc_vrrp_conf },
{ "PRV_STAT",		9, 	ROUTER_PRV_STAT,	sfunc_vrrp_conf	},
{ "STAT_LAST",		10,	ROUTER_STAT_LAST,	sfunc_vrrp_conf },
{ "PEER",		20,	ROUTER_PEER,		sfunc_vrrp_conf	},
{ "P_PRIO",		7,	ROUTER_P_PRIO,		sfunc_vrrp_conf	},
{ "P_INTV",		9,	ROUTER_P_INTV,		sfunc_vrrp_conf	},
{ "P_ADV_LAST",		11,	ROUTER_P_ADV_LAST,	sfunc_vrrp_conf	},
{ "M_DOWN_INTV",	12,	ROUTER_M_DOWN_INTV,	sfunc_vrrp_conf	},
{ "PRIMARY_IP",		20,	ROUTER_PRIMARY_IP,	sfunc_vrrp_conf	},
{ "VIRTUAL_IPS",	40,	ROUTER_VIRTUAL_IPS,	sfunc_vrrp_conf	},
{ "VIP_CNT",		7,	ROUTER_VIP_CNT,		sfunc_vrrp_conf	},
{ NULL,			0, 	0,			NULL}}
;

static vrrp_err_t do_show_router(const char *, ofmt_handle_t);
static int str2opt(char *opts, uint32_t *, boolean_t *, boolean_t *);
static char *timeval_since_str(int, char *, size_t);

static void usage();
static void warn(const char *, ...);
static void err_exit(const char *, ...);
static void opterr_exit(int, int, const char *);

int
main(int argc, char *argv[])
{
	vrrp_err_t	err;
	int		i;
	cmd_t		*cp;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (argv[1] == NULL)
		usage();

	if ((err = vrrp_open(&vrrp_vh)) != VRRP_SUCCESS)
		err_exit("operation failed: %s", vrrp_err2str(err));

	for (i = 0; i < sizeof (cmds) / sizeof (cmd_t); i++) {
		cp = &cmds[i];
		if (strcmp(argv[1], cp->c_name) == 0) {
			cp->c_fn(argc - 1, &argv[1], cp->c_usage);
			vrrp_close(vrrp_vh);
			return (EXIT_SUCCESS);
		}
	}

	usage();
	return (EXIT_FAILURE);
}

static void
do_create(int argc, char *argv[], const char *usage)
{
	vrrp_vr_conf_t		conf;
	int			c;
	uint32_t		create_mask = 0, mask;
	char			*endp;
	vrrp_err_t		err;

	/*
	 * default value
	 */
	bzero(&conf, sizeof (vrrp_vr_conf_t));
	conf.vvc_vrid = VRRP_VRID_NONE;
	conf.vvc_af = AF_UNSPEC;
	conf.vvc_pri = VRRP_PRI_DEFAULT;
	conf.vvc_adver_int = VRRP_MAX_ADVER_INT_DFLT;
	conf.vvc_preempt = B_TRUE;
	conf.vvc_accept = B_TRUE;
	conf.vvc_enabled = B_TRUE;

	while ((c = getopt_long(argc, argv, ":V:l:p:i:o:A:f", lopts,
	    NULL)) != EOF) {
		switch (c) {
		case 'l':
			if (strlcpy(conf.vvc_link, optarg,
			    sizeof (conf.vvc_link)) >=
			    sizeof (conf.vvc_link)) {
				err_exit("invalid data-link name %s", optarg);
			}
			break;
		case 'i':
			if (create_mask & VRRP_CONF_INTERVAL)
				err_exit("duplicate '-i' option");

			create_mask |= VRRP_CONF_INTERVAL;
			conf.vvc_adver_int = (uint32_t)strtol(optarg, &endp, 0);
			if ((*endp) != '\0' ||
			    conf.vvc_adver_int < VRRP_MAX_ADVER_INT_MIN ||
			    conf.vvc_adver_int > VRRP_MAX_ADVER_INT_MAX ||
			    (conf.vvc_adver_int == 0 && errno != 0)) {
				err_exit("invalid advertisement interval");
			}
			break;
		case 'p':
			if (create_mask & VRRP_CONF_PRIORITY)
				err_exit("duplicate '-p' option");

			create_mask |= VRRP_CONF_PRIORITY;
			conf.vvc_pri = strtol(optarg, &endp, 0);
			if ((*endp) != '\0' || conf.vvc_pri < VRRP_PRI_MIN ||
			    conf.vvc_pri > VRRP_PRI_OWNER ||
			    (conf.vvc_pri == 0 && errno != 0)) {
				err_exit("invalid priority");
			}
			break;
		case 'o':
			mask = 0;
			if (str2opt(optarg, &mask,
			    &conf.vvc_preempt, &conf.vvc_accept) != 0) {
				err_exit("invalid options: %s", optarg);
			}
			if (mask & create_mask & VRRP_CONF_PREEMPT)
				err_exit("duplicate '-o preempt' option");
			else if (mask & create_mask & VRRP_CONF_ACCEPT)
				err_exit("duplicate '-o accept' option");
			create_mask |= mask;
			break;
		case 'V':
			if (conf.vvc_vrid != VRRP_VRID_NONE)
				err_exit("duplicate '-V' option");

			conf.vvc_vrid = strtol(optarg, &endp, 0);
			if ((*endp) != '\0' || conf.vvc_vrid < VRRP_VRID_MIN ||
			    conf.vvc_vrid > VRRP_VRID_MAX ||
			    (conf.vvc_vrid == 0 && errno != 0)) {
				err_exit("invalid VRID");
			}
			break;
		case 'A':
			if (conf.vvc_af != AF_UNSPEC)
				err_exit("duplicate '-A' option");

			if (strcmp(optarg, "inet") == 0)
				conf.vvc_af = AF_INET;
			else if (strcmp(optarg, "inet6") == 0)
				conf.vvc_af = AF_INET6;
			else
				err_exit("invalid address family");
			break;
		default:
			opterr_exit(optopt, c, usage);
		}
	}

	if (argc - optind > 1)
		err_exit("usage: %s", gettext(usage));

	if (optind != argc - 1)
		err_exit("VRRP name not specified");

	if (strlcpy(conf.vvc_name, argv[optind],
	    sizeof (conf.vvc_name)) >= sizeof (conf.vvc_name)) {
		err_exit("Invalid router name %s", argv[optind]);
	}

	if (conf.vvc_vrid == VRRP_VRID_NONE)
		err_exit("VRID not specified");

	if (conf.vvc_af == AF_UNSPEC)
		err_exit("address family not specified");

	if (strlen(conf.vvc_link) == 0)
		err_exit("link name not specified");

	if (!conf.vvc_accept && conf.vvc_pri == VRRP_PRI_OWNER)
		err_exit("accept_mode must be true for virtual IP owner");

	if ((err = vrrp_create(vrrp_vh, &conf)) == VRRP_SUCCESS)
		return;

	err_exit("create-router failed: %s", vrrp_err2str(err));
}

static void
do_delete(int argc, char *argv[], const char *use)
{
	vrrp_err_t	err;

	if (argc != 2)
		err_exit("usage: %s", gettext(use));

	if ((err = vrrp_delete(vrrp_vh, argv[1])) != VRRP_SUCCESS)
		err_exit("delete-router failed: %s", vrrp_err2str(err));
}

static void
do_enable(int argc, char *argv[], const char *use)
{
	vrrp_err_t	err;

	if (argc != 2)
		err_exit("usage: %s", gettext(use));

	if ((err = vrrp_enable(vrrp_vh, argv[1])) != VRRP_SUCCESS)
		err_exit("enable-router failed: %s", vrrp_err2str(err));
}

static void
do_disable(int argc, char *argv[], const char *use)
{
	vrrp_err_t	err;

	if (argc != 2)
		err_exit("usage: %s", gettext(use));

	if ((err = vrrp_disable(vrrp_vh, argv[1])) != VRRP_SUCCESS)
		err_exit("disable-router failed: %s", vrrp_err2str(err));
}

static void
do_modify(int argc, char *argv[], const char *use)
{
	vrrp_vr_conf_t	conf;
	vrrp_err_t	err;
	uint32_t	modify_mask = 0, mask;
	char		*endp;
	int		c;

	while ((c = getopt_long(argc, argv, ":i:p:o:", lopts, NULL)) != EOF) {
		switch (c) {
		case 'i':
			if (modify_mask & VRRP_CONF_INTERVAL)
				err_exit("duplicate '-i' option");

			modify_mask |= VRRP_CONF_INTERVAL;
			conf.vvc_adver_int = (uint32_t)strtol(optarg, &endp, 0);
			if ((*endp) != '\0' ||
			    conf.vvc_adver_int < VRRP_MAX_ADVER_INT_MIN ||
			    conf.vvc_adver_int > VRRP_MAX_ADVER_INT_MAX ||
			    (conf.vvc_adver_int == 0 && errno != 0)) {
				err_exit("invalid advertisement interval");
			}
			break;
		case 'o':
			mask = 0;
			if (str2opt(optarg, &mask, &conf.vvc_preempt,
			    &conf.vvc_accept) != 0) {
				err_exit("Invalid options");
			}
			if (mask & modify_mask & VRRP_CONF_PREEMPT)
				err_exit("duplicate '-o preempt' option");
			else if (mask & modify_mask & VRRP_CONF_ACCEPT)
				err_exit("duplicate '-o accept' option");
			modify_mask |= mask;
			break;
		case 'p':
			if (modify_mask & VRRP_CONF_PRIORITY)
				err_exit("duplicate '-p' option");

			modify_mask |= VRRP_CONF_PRIORITY;
			conf.vvc_pri = strtol(optarg, &endp, 0);
			if ((*endp) != '\0' || conf.vvc_pri < VRRP_PRI_MIN ||
			    conf.vvc_pri > VRRP_PRI_OWNER ||
			    (conf.vvc_pri == 0 && errno != 0)) {
				err_exit("invalid priority");
			}
			break;
		default:
			opterr_exit(optopt, c, use);
		}
	}

	if (argc - optind > 1)
		err_exit("usage: %s", gettext(use));

	if (optind != argc - 1)
		err_exit("VRRP name not specified.");

	if (strlcpy(conf.vvc_name, argv[optind], sizeof (conf.vvc_name)) >=
	    sizeof (conf.vvc_name)) {
		err_exit("invalid router name %s", argv[optind]);
	}

	if ((modify_mask & VRRP_CONF_ACCEPT) && !conf.vvc_accept &&
	    (modify_mask & VRRP_CONF_PRIORITY) &&
	    conf.vvc_pri == VRRP_PRI_OWNER) {
		err_exit("accept_mode must be true for virtual IP owner");
	}

	if (modify_mask == 0)
		usage();

	err = vrrp_modify(vrrp_vh, &conf, modify_mask);
	if (err != VRRP_SUCCESS)
		err_exit("modify-router failed: %s", vrrp_err2str(err));
}

/*
 * 'show-router' one VRRP router.
 */
static vrrp_err_t
do_show_router(const char *vn, ofmt_handle_t ofmt)
{
	vrrp_queryinfo_t	*vq;
	vrrp_err_t		err;

	if ((err = vrrp_query(vrrp_vh, vn, &vq)) != VRRP_SUCCESS)
		return (err);

	ofmt_print(ofmt, vq);
	free(vq);
	return (VRRP_SUCCESS);
}

static void
do_show(int argc, char *argv[], const char *use)
{
	int			c;
	char			*fields_str = NULL;
	char			*names = NULL, *router;
	uint32_t		i, in_cnt = 0, out_cnt;
	ofmt_status_t		oferr;
	ofmt_handle_t		ofmt;
	uint_t			ofmt_flags = 0;
	vrrp_err_t		err = VRRP_SUCCESS;
	boolean_t		P_opt, x_opt;

	static char		*dft_fields_str =
	    "NAME,VRID,LINK,AF,PRIO,ADV_INTV,MODE,STATE,VNIC";
	static char		*ext_fields_str =
	    "NAME,STATE,PRV_STAT,STAT_LAST,VNIC,PRIMARY_IP,VIRTUAL_IPS";
	static char		*peer_fields_str =
	    "NAME,PEER,P_PRIO,P_INTV,P_ADV_LAST,M_DOWN_INTV";
	/*
	 * If parsable output is requested, add VIP_CNT into the output
	 * for extended output. It is not needed for human-readable
	 * output as it is obvious from the VIRTUAL_IPS list.
	 */
	static char		*ext_parsable_fields_str =
	    "NAME,STATE,PRV_STAT,STAT_LAST,VNIC,PRIMARY_IP,VIP_CNT,"
	    "VIRTUAL_IPS";

	P_opt = x_opt = B_FALSE;
	fields_str = dft_fields_str;
	while ((c = getopt_long(argc, argv, ":Pxpo:", l_show_opts,
	    NULL)) != EOF) {
		switch (c) {
		case 'o':
			fields_str = optarg;
			break;
		case 'p':
			ofmt_flags |= OFMT_PARSABLE;
			break;
		case 'P':
			P_opt = B_TRUE;
			fields_str = peer_fields_str;
			break;
		case 'x':
			x_opt = B_TRUE;
			fields_str = ext_fields_str;
			break;
		default:
			opterr_exit(optopt, c, use);
		}
	}

	if (x_opt && P_opt)
		err_exit("incompatible -P and -x options");

	/*
	 * If parsable output is requested, add VIP_CNT into the output
	 * for extended output.
	 */
	if ((ofmt_flags & OFMT_PARSABLE) && (fields_str == ext_fields_str))
		fields_str = ext_parsable_fields_str;

	if ((oferr = ofmt_open(fields_str, show_print_fields, ofmt_flags,
	    0, &ofmt)) != OFMT_SUCCESS) {
		char buf[OFMT_BUFSIZE];

		/*
		 * If some fields were badly formed in human-friendly mode, we
		 * emit a warning and continue.  Otherwise exit immediately.
		 */
		(void) ofmt_strerror(ofmt, oferr, buf, sizeof (buf));
		if (oferr != OFMT_EBADFIELDS || (ofmt_flags & OFMT_PARSABLE)) {
			ofmt_close(ofmt);
			err_exit(buf);
		} else {
			warn(buf);
		}
	}

	/* Show one router */
	if (optind == argc - 1) {
		err = do_show_router(argv[optind], ofmt);
		goto done;
	}

	/*
	 * Show all routers. First set in_cnt to 0 to find out the number
	 * of vrrp routers.
	 */
again:
	if ((in_cnt != 0) && (names = malloc(in_cnt * VRRP_NAME_MAX)) == NULL) {
		err = VRRP_ENOMEM;
		goto done;
	}

	out_cnt = in_cnt;
	if ((err = vrrp_list(vrrp_vh, VRRP_VRID_NONE, NULL, AF_UNSPEC,
	    &out_cnt, names)) != VRRP_SUCCESS) {
		free(names);
		goto done;
	}

	/*
	 * The VRRP routers has been changed between two vrrp_list()
	 * calls, try again.
	 */
	if (out_cnt > in_cnt) {
		in_cnt = out_cnt;
		free(names);
		goto again;
	}

	/*
	 * Each VRRP router name is separated by '\0`
	 */
	router = names;
	for (i = 0; i < in_cnt; i++) {
		(void) do_show_router(router, ofmt);
		router += strlen(router) + 1;
	}

	free(names);

done:
	ofmt_close(ofmt);

	if (err != VRRP_SUCCESS)
		err_exit(vrrp_err2str(err));
}

/*
 * Callback function to print fields of the configuration information.
 */
static boolean_t
sfunc_vrrp_conf(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	vrrp_queryinfo_t	*qinfo = ofmtarg->ofmt_cbarg;
	uint_t			ofmtid = ofmtarg->ofmt_id;
	vrrp_vr_conf_t		*conf = &qinfo->show_vi;
	vrrp_stateinfo_t	*sinfo = &qinfo->show_vs;
	vrrp_peer_t		*peer = &qinfo->show_vp;
	vrrp_timerinfo_t	*tinfo = &qinfo->show_vt;
	vrrp_addrinfo_t		*ainfo = &qinfo->show_va;

	switch (ofmtid) {
	case ROUTER_NAME:
		(void) snprintf(buf, bufsize, "%s", conf->vvc_name);
		break;
	case ROUTER_VRID:
		(void) snprintf(buf, bufsize, "%d", conf->vvc_vrid);
		break;
	case ROUTER_LINK:
		(void) snprintf(buf, bufsize, "%s", conf->vvc_link);
		break;
	case ROUTER_AF:
		(void) snprintf(buf, bufsize, "IPv%d",
		    conf->vvc_af == AF_INET ? 4 : 6);
		break;
	case ROUTER_PRIO:
		(void) snprintf(buf, bufsize, "%d", conf->vvc_pri);
		break;
	case ROUTER_ADV_INTV:
		(void) snprintf(buf, bufsize, "%d", conf->vvc_adver_int);
		break;
	case ROUTER_MODE:
		(void) strlcpy(buf, "-----", bufsize);
		if (conf->vvc_enabled)
			buf[0] = 'e';
		if (conf->vvc_pri == VRRP_PRI_OWNER)
			buf[1] = 'o';
		if (conf->vvc_preempt)
			buf[2] = 'p';
		if (conf->vvc_accept)
			buf[3] = 'a';
		break;
	case ROUTER_STATE:
		(void) snprintf(buf, bufsize, "%s",
		    vrrp_state2str(sinfo->vs_state));
		break;
	case ROUTER_PRV_STAT:
		(void) snprintf(buf, bufsize, "%s",
		    vrrp_state2str(sinfo->vs_prev_state));
		break;
	case ROUTER_STAT_LAST:
		(void) timeval_since_str(tinfo->vt_since_last_tran, buf,
		    bufsize);
		break;
	case ROUTER_PEER:
		/* LINTED E_CONSTANT_CONDITION */
		VRRPADDR2STR(conf->vvc_af, &peer->vp_addr,
		    buf, bufsize, B_FALSE);
		break;
	case ROUTER_P_PRIO:
		(void) snprintf(buf, bufsize, "%d", peer->vp_prio);
		break;
	case ROUTER_P_INTV:
		(void) snprintf(buf, bufsize, "%d", peer->vp_adver_int);
		break;
	case ROUTER_P_ADV_LAST:
		(void) timeval_since_str(tinfo->vt_since_last_adv, buf,
		    bufsize);
		break;
	case ROUTER_M_DOWN_INTV:
		(void) snprintf(buf, bufsize, "%d", tinfo->vt_master_down_intv);
		break;
	case ROUTER_VNIC:
		(void) snprintf(buf, bufsize, "%s",
		    strlen(ainfo->va_vnic) == 0 ? "--" : ainfo->va_vnic);
		break;
	case ROUTER_PRIMARY_IP:
		/* LINTED E_CONSTANT_CONDITION */
		VRRPADDR2STR(conf->vvc_af, &ainfo->va_primary,
		    buf, bufsize, B_FALSE);
		break;
	case ROUTER_VIRTUAL_IPS: {
		uint32_t i;

		for (i = 0; i < ainfo->va_vipcnt; i++) {
			/* LINTED E_CONSTANT_CONDITION */
			VRRPADDR2STR(conf->vvc_af, &(ainfo->va_vips[i]),
			    buf, bufsize, B_TRUE);
			if (i != ainfo->va_vipcnt - 1)
				(void) strlcat(buf, ",", bufsize);
		}
		break;
	}
	case ROUTER_VIP_CNT:
		(void) snprintf(buf, bufsize, "%d", ainfo->va_vipcnt);
		break;
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

static void
usage()
{
	int	i;
	cmd_t	*cp;

	(void) fprintf(stderr, "%s",
	    gettext("usage:  vrrpadm <sub-command> <args> ...\n"));

	for (i = 0; i < sizeof (cmds) / sizeof (cmd_t); i++) {
		cp = &cmds[i];
		if (cp->c_usage != NULL)
			(void) fprintf(stderr, "          %-10s %s\n",
			    gettext(cp->c_name), gettext(cp->c_usage));
	}

	vrrp_close(vrrp_vh);
	exit(EXIT_FAILURE);
}

static void
warn(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, gettext("warning: "));

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) putc('\n', stderr);
}

static void
err_exit(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) putc('\n', stderr);
	vrrp_close(vrrp_vh);
	exit(EXIT_FAILURE);
}

static void
opterr_exit(int opt, int opterr, const char *use)
{
	switch (opterr) {
	case ':':
		err_exit("option '-%c' requires a value\nusage: %s", opt,
		    gettext(use));
		break;
	case '?':
	default:
		err_exit("unrecognized option '-%c'\nusage: %s", opt,
		    gettext(use));
		break;
	}
}

static char *
timeval_since_str(int mill, char *str, size_t len)
{
	int	sec, msec, min;

	msec = mill % 1000;
	sec = mill / 1000;
	min = sec > 60 ? sec / 60 : 0;
	sec %= 60;

	if (min > 0)
		(void) snprintf(str, len, "%4dm%2ds", min, sec);
	else
		(void) snprintf(str, len, "%4d.%03ds", sec, msec);

	return (str);
}

/*
 * Parses options string. The values of the two options will be returned
 * by 'preempt' and 'accept', and the mask 'modify_mask' will be updated
 * accordingly.
 *
 * Returns 0 on success, errno on failures.
 *
 * Used by do_create() and do_modify().
 *
 * Note that "opts" could be modified internally in this function.
 */
static int
str2opt(char *opts, uint32_t *modify_mask, boolean_t *preempt,
    boolean_t *accept)
{
	char		*value;
	int		opt;
	uint32_t	mask = 0;
	enum { o_preempt = 0, o_un_preempt, o_accept, o_no_accept };
	static char	*myopts[] = {
		"preempt",
		"un_preempt",
		"accept",
		"no_accept",
		NULL
	};

	while (*opts != '\0') {
		switch ((opt = getsubopt(&opts, myopts, &value))) {
		case o_preempt:
		case o_un_preempt:
			if (mask & VRRP_CONF_PREEMPT)
				return (EINVAL);

			mask |= VRRP_CONF_PREEMPT;
			*preempt = (opt == o_preempt);
			break;
		case o_accept:
		case o_no_accept:
			if (mask & VRRP_CONF_ACCEPT)
				return (EINVAL);

			mask |= VRRP_CONF_ACCEPT;
			*accept = (opt == o_accept);
			break;
		default:
			return (EINVAL);
		}
	}

	*modify_mask |= mask;
	return (0);
}
