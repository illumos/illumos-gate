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
#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/list.h>
#include <ofmt.h>
#include <libilb.h>
#include "ilbadm.h"

static ilbadm_key_name_t servrange_keys[] = {
	{ILB_KEY_SERVER, "server", "servers"},
	{ILB_KEY_SERVRANGE, "server", "servers"},
	{ILB_KEY_BAD, "", ""}
};

static ilbadm_key_name_t serverID_keys[] = {
	{ILB_KEY_SERVERID, "server", ""},
	{ILB_KEY_BAD, "", ""}
};

typedef struct sg_export_arg {
	FILE		*fp;
	ilbadm_sgroup_t	*sg;
} sg_export_arg_t;

typedef struct arg_struct {
	int		flags;
	char		*o_str;
	ofmt_field_t	*o_fields;
	ofmt_handle_t	oh;
} list_arg_t;

typedef struct sg_srv_o_struct {
	char		*sgname;
	ilb_server_data_t	*sd;
} sg_srv_o_arg_t;

static ofmt_cb_t of_sgname;
static ofmt_cb_t of_srvID;
static ofmt_cb_t of_port;
static ofmt_cb_t of_ip;

static ofmt_field_t sgfields_v4[] = {
	{"SGNAME", ILB_SGNAME_SZ, 0, of_sgname},
	{"SERVERID", ILB_NAMESZ, 0, of_srvID},
	{"MINPORT", 8, 0, of_port},
	{"MAXPORT", 8, 1, of_port},
	{"IP_ADDRESS", 15, 0, of_ip},
	{NULL, 0, 0, NULL}
};
static ofmt_field_t sgfields_v6[] = {
	{"SGNAME", ILB_SGNAME_SZ, 0, of_sgname},
	{"SERVERID", ILB_NAMESZ, 0, of_srvID},
	{"MINPORT", 8, 0, of_port},
	{"MAXPORT", 8, 1, of_port},
	{"IP_ADDRESS", 39, 0, of_ip},
	{NULL, 0, 0, NULL}
};

#define	MAXCOLS	80 /* make flexible? */

extern int	optind, optopt, opterr;
extern char	*optarg;

static boolean_t
of_sgname(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	sg_srv_o_arg_t	*l = (sg_srv_o_arg_t *)of_arg->ofmt_cbarg;

	(void) strlcpy(buf, l->sgname, bufsize);
	return (B_TRUE);
}

static boolean_t
of_srvID(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	sg_srv_o_arg_t	*l = (sg_srv_o_arg_t *)of_arg->ofmt_cbarg;

	(void) strlcpy(buf, l->sd->sd_srvID, bufsize);
	return (B_TRUE);
}

static boolean_t
of_port(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	sg_srv_o_arg_t	*l = (sg_srv_o_arg_t *)of_arg->ofmt_cbarg;
	int		port;

	if (of_arg->ofmt_id == 0) {
		port = ntohs(l->sd->sd_minport);
		if (port == 0)
			*buf = '\0';
		else
			(void) snprintf(buf, bufsize, "%d", port);
	} else {
		port = ntohs(l->sd->sd_maxport);
		if (port == 0)
			*buf = '\0';
		else
			(void) snprintf(buf, bufsize, "%d", port);
	}
	return (B_TRUE);
}

static boolean_t
of_ip(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	sg_srv_o_arg_t	*l = (sg_srv_o_arg_t *)of_arg->ofmt_cbarg;

	ip2str(&l->sd->sd_addr, buf, bufsize, V6_ADDRONLY);
	return (B_TRUE);
}

ilbadm_status_t
i_list_sg_srv_ofmt(char *sgname, ilb_server_data_t *sd, void *arg)
{
	list_arg_t	*larg = (list_arg_t *)arg;
	sg_srv_o_arg_t	line_arg;

	line_arg.sgname = sgname;
	line_arg.sd = sd;
	ofmt_print(larg->oh, &line_arg);
	return (ILBADM_OK);
}

/*
 * This function is always called via ilb_walk_servergroups()
 * and so must return libilb errors.
 * That's why we need to retain currently unused "h" argument
 */
/* ARGSUSED */
static ilb_status_t
ilbadm_list_sg_srv(ilb_handle_t h, ilb_server_data_t *sd, const char *sgname,
    void *arg)
{
	char		ip_str[2*INET6_ADDRSTRLEN + 3] = "";
	char		port_str[INET6_ADDRSTRLEN];
	list_arg_t	*larg = (list_arg_t *)arg;
	ofmt_status_t	oerr;
	int		oflags = 0;
	int		ocols = MAXCOLS;
	int		h_minport, h_maxport;
	static ofmt_handle_t	oh = (ofmt_handle_t)NULL;
	ofmt_field_t	*ofp;

	if (larg->o_str != NULL) {
		if (oh == NULL) {
			if (sd->sd_addr.ia_af == AF_INET)
				ofp = sgfields_v6;
			else
				ofp = sgfields_v4;

			if (larg->flags & ILBADM_LIST_PARSE)
				oflags |= OFMT_PARSABLE;

			oerr = ofmt_open(larg->o_str, ofp, oflags, ocols, &oh);
			if (oerr != OFMT_SUCCESS) {
				char	e[80];

				ilbadm_err(gettext("ofmt_open failed: %s"),
				    ofmt_strerror(oh, oerr, e, sizeof (e)));
				return (ILB_STATUS_GENERIC);
			}
			larg->oh = oh;
		}


		(void) i_list_sg_srv_ofmt((char *)sgname, sd, arg);
		return (ILB_STATUS_OK);
	}

	ip2str(&sd->sd_addr, ip_str, sizeof (ip_str), 0);

	h_minport = ntohs(sd->sd_minport);
	h_maxport = ntohs(sd->sd_maxport);
	if (h_minport == 0)
		*port_str = '\0';
	else if (h_maxport > h_minport)
		(void) sprintf(port_str, ":%d-%d", h_minport, h_maxport);
	else
		(void) sprintf(port_str, ":%d", h_minport);

	(void) printf("%s: id:%s %s%s\n", sgname,
	    sd->sd_srvID?sd->sd_srvID:"(null)", ip_str, port_str);
	return (ILB_STATUS_OK);
}

ilb_status_t
ilbadm_list_sg(ilb_handle_t h, ilb_sg_data_t *sg, void *arg)
{
	if (sg->sgd_srvcount == 0) {
		ilb_server_data_t	tmp_srv;

		bzero(&tmp_srv, sizeof (tmp_srv));
		return (ilbadm_list_sg_srv(h, &tmp_srv, sg->sgd_name, arg));
	}

	return (ilb_walk_servers(h, ilbadm_list_sg_srv, sg->sgd_name, arg));
}

static char *def_fields = "SGNAME,SERVERID,MINPORT,MAXPORT,IP_ADDRESS";

/* ARGSUSED */
ilbadm_status_t
ilbadm_show_servergroups(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	int		c;
	char		optstr[] = ":po:";

	boolean_t	o_opt = B_FALSE, p_opt = B_FALSE;
	list_arg_t	larg = {0, def_fields, NULL, NULL};

	while ((c = getopt(argc, argv, optstr)) != -1) {
		switch ((char)c) {
		case 'p': p_opt = B_TRUE;
			larg.flags |= ILBADM_LIST_PARSE;
			break;
		case 'o': larg.o_str = optarg;
			o_opt = B_TRUE;
			break;
		case ':': ilbadm_err(gettext("missing option argument"
			    " for %c"), (char)optopt);
			rc = ILBADM_LIBERR;
			goto out;
		default: unknown_opt(argv, optind-1);
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
		ilbadm_err(gettext("option -p requires explicit field"
		    " names for -o"));
		exit(1);
	}

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	if (optind >= argc) {
		rclib = ilb_walk_servergroups(h, ilbadm_list_sg, NULL,
		    (void*)&larg);
		if (rclib != ILB_STATUS_OK)
			rc = ILBADM_LIBERR;
	} else {
		while (optind < argc) {
			rclib = ilb_walk_servergroups(h, ilbadm_list_sg,
			    argv[optind++], (void*)&larg);
			if (rclib != ILB_STATUS_OK) {
				rc = ILBADM_LIBERR;
				break;
			}
		}
	}

	if (larg.oh != NULL)
		ofmt_close(larg.oh);
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

ilbadm_servnode_t *
i_new_sg_elem(ilbadm_sgroup_t *sgp)
{
	ilbadm_servnode_t *s;

	s = (ilbadm_servnode_t *)calloc(sizeof (*s), 1);
	if (s != NULL) {
		list_insert_tail(&sgp->sg_serv_list, s);
		sgp->sg_count++;
	}
	return (s);
}

static ilbadm_status_t
i_parse_servrange_list(char *arg, ilbadm_sgroup_t *sgp)
{
	ilbadm_status_t	rc;
	int		count;

	rc = i_parse_optstring(arg, (void *) sgp, servrange_keys,
	    OPT_VALUE_LIST|OPT_IP_RANGE|OPT_PORTS, &count);
	return (rc);
}

static ilbadm_status_t
i_parse_serverIDs(char *arg, ilbadm_sgroup_t *sgp)
{
	ilbadm_status_t	rc;
	int		count;

	rc = i_parse_optstring(arg, (void *) sgp, serverID_keys,
	    OPT_VALUE_LIST|OPT_PORTS, &count);
	return (rc);
}

static ilbadm_status_t
i_mod_sg(ilb_handle_t h, ilbadm_sgroup_t *sgp, ilbadm_cmd_t cmd,
    int flags)
{
	ilbadm_servnode_t	*sn;
	ilb_server_data_t	*srv;
	ilb_status_t		rclib = ILB_STATUS_OK;
	ilbadm_status_t		rc = ILBADM_OK;

	if (h == ILB_INVALID_HANDLE && cmd != cmd_enable_server &&
	    cmd != cmd_disable_server)
		return (ILBADM_LIBERR);

	sn = list_head(&sgp->sg_serv_list);
	while (sn != NULL) {
		srv = &sn->s_spec;

		srv->sd_flags |= flags;
		if (cmd == cmd_create_sg || cmd == cmd_add_srv) {
			rclib = ilb_add_server_to_group(h, sgp->sg_name,
			    srv);
			if (rclib != ILB_STATUS_OK) {
				char	buf[INET6_ADDRSTRLEN + 1];

				rc = ILBADM_LIBERR;
				ip2str(&srv->sd_addr, buf, sizeof (buf),
				    V6_ADDRONLY);
				ilbadm_err(gettext("cannot add %s to %s: %s"),
				    buf, sgp->sg_name, ilb_errstr(rclib));
				/* if we created the SG, we bail out */
				if (cmd == cmd_create_sg)
					return (rc);
			}
		} else {
			assert(cmd == cmd_rem_srv);
			rclib = ilb_rem_server_from_group(h, sgp->sg_name,
			    srv);
			/* if we fail, we tell user and continue */
			if (rclib != ILB_STATUS_OK) {
				rc = ILBADM_LIBERR;
				ilbadm_err(
				    gettext("cannot remove %s from %s: %s"),
				    srv->sd_srvID, sgp->sg_name,
				    ilb_errstr(rclib));
			}
		}

		/*
		 * list_next returns NULL instead of cycling back to head
		 * so we don't have to check for list_head explicitly.
		 */
		sn = list_next(&sgp->sg_serv_list, sn);
	};

	return (rc);
}

static void
i_ilbadm_alloc_sgroup(ilbadm_sgroup_t **sgp)
{
	ilbadm_sgroup_t	*sg;

	*sgp = sg = (ilbadm_sgroup_t *)calloc(sizeof (*sg), 1);
	if (sg == NULL)
		return;
	list_create(&sg->sg_serv_list, sizeof (ilbadm_servnode_t),
	    offsetof(ilbadm_servnode_t, s_link));
}

static void
i_ilbadm_free_sgroup(ilbadm_sgroup_t *sg)
{
	ilbadm_servnode_t	*s;

	while ((s = list_remove_head(&sg->sg_serv_list)) != NULL)
		free(s);

	list_destroy(&sg->sg_serv_list);
}

ilbadm_status_t
ilbadm_create_servergroup(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	ilbadm_sgroup_t	*sg;
	int		c;
	int		flags = 0;

	i_ilbadm_alloc_sgroup(&sg);

	while ((c = getopt(argc, argv, ":s:")) != -1) {
		switch ((char)c) {
		case 's':
			rc = i_parse_servrange_list(optarg, sg);
			break;
		case ':':
			ilbadm_err(gettext("missing option-argument for"
			    " %c"), (char)optopt);
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
		    " to 'create-servergroup' subcommand"
		    "  description in ilbadm(8)"));
		rc = ILBADM_LIBERR;
		goto out;
	}

	if (strlen(argv[optind]) > ILB_SGNAME_SZ - 1) {
		ilbadm_err(gettext("servergroup name %s is too long -"
		    " must not exceed %d chars"), argv[optind],
		    ILB_SGNAME_SZ - 1);
		rc = ILBADM_LIBERR;
		goto out;
	}

	sg->sg_name = argv[optind];

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	rclib = ilb_create_servergroup(h, sg->sg_name);
	if (rclib != ILB_STATUS_OK)
		goto out;

	/* we create a servergroup with all servers enabled */
	ILB_SET_ENABLED(flags);
	rc = i_mod_sg(h, sg, cmd_create_sg, flags);

	if (rc != ILBADM_OK)
		(void) ilb_destroy_servergroup(h, sg->sg_name);

out:
	i_ilbadm_free_sgroup(sg);
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

ilbadm_status_t
ilbadm_add_server_to_group(int argc, char **argv)
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	ilbadm_sgroup_t	*sg;
	int		c;
	int		flags = 0;

	i_ilbadm_alloc_sgroup(&sg);

	while ((c = getopt(argc, argv, ":s:")) != -1) {
		switch ((char)c) {
		case 's':
			rc = i_parse_servrange_list(optarg, sg);
			break;
		case ':':
			ilbadm_err(gettext("missing option-argument for"
			    " %c"), (char)optopt);
			rc = ILBADM_LIBERR;
			break;
		case '?':
		default: unknown_opt(argv, optind-1);
			/* not reached */
			break;
		}

		if (rc != ILBADM_OK)
			goto out;
	}

	if (optind >= argc) {
		ilbadm_err(gettext("missing mandatory arguments - please refer"
		    " to 'add-server' subcommand description in ilbadm(8)"));
		rc = ILBADM_LIBERR;
		goto out;
	}

	sg->sg_name = argv[optind];

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	/* A server is added enabled */
	ILB_SET_ENABLED(flags);
	rc = i_mod_sg(h, sg, cmd_add_srv, flags);
out:
	i_ilbadm_free_sgroup(sg);
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if ((rc != ILBADM_OK) && (rc != ILBADM_LIBERR))
		ilbadm_err(ilbadm_errstr(rc));
	return (rc);
}

/* ARGSUSED */
static ilbadm_status_t
ilbadm_Xable_server(int argc, char *argv[], ilbadm_cmd_t cmd)
{
	ilb_handle_t		h = ILB_INVALID_HANDLE;
	ilbadm_status_t		rc = ILBADM_OK;
	ilb_status_t		rclib = ILB_STATUS_OK;
	int			i;

	if (argc < 2) {
		ilbadm_err(gettext("missing required argument"
		    " (server specification)"));
		rc = ILBADM_LIBERR;
		goto out;
	}

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	/* enable-server and disable-server only accepts serverids */
	for (i = 1; i < argc && rclib == ILB_STATUS_OK; i++) {
		ilb_server_data_t	srv;

		if (argv[i][0] != ILB_SRVID_PREFIX) {
			rc = ILBADM_INVAL_SRVID;
			goto out;
		}

		bzero(&srv, sizeof (srv));
		/* to do: check length */
		(void) strlcpy(srv.sd_srvID, argv[i], sizeof (srv.sd_srvID));
		switch (cmd) {
		case cmd_enable_server:
			rclib = ilb_enable_server(h, &srv, NULL);
			break;
		case cmd_disable_server:
			rclib = ilb_disable_server(h, &srv, NULL);
			break;
		}

		/* if we can't find a given server ID, just plough on */
		if (rclib == ILB_STATUS_ENOENT) {
			const char *msg = ilb_errstr(rclib);

			rc = ILBADM_LIBERR;
			ilbadm_err("%s: %s", msg, argv[i]);
			rclib = ILB_STATUS_OK;
			continue;
		}
		if (rclib != ILB_STATUS_OK)
			break;
	}
out:
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

ilbadm_status_t
ilbadm_disable_server(int argc, char *argv[])
{
	return (ilbadm_Xable_server(argc, argv, cmd_disable_server));
}

ilbadm_status_t
ilbadm_enable_server(int argc, char *argv[])
{
	return (ilbadm_Xable_server(argc, argv, cmd_enable_server));
}

/* ARGSUSED */
ilbadm_status_t
ilbadm_rem_server_from_group(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	ilbadm_sgroup_t	*sg;
	int		c;

	i_ilbadm_alloc_sgroup(&sg);

	while ((c = getopt(argc, argv, ":s:")) != -1) {
		switch ((char)c) {
		case 's':
			rc = i_parse_serverIDs(optarg, sg);
			break;
		case ':':
			ilbadm_err(gettext("missing option-argument for"
			    " %c"), (char)optopt);
			rc = ILBADM_LIBERR;
			break;
		case '?':
		default: unknown_opt(argv, optind-1);
			/* not reached */
			break;
		}
		if (rc != ILBADM_OK)
			goto out;
	}

	/* we need servergroup name and at least one serverID to remove */
	if (optind >= argc || sg->sg_count == 0) {
		rc = ILBADM_ENOOPTION;
		goto out;
	}

	sg->sg_name = argv[optind];

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	rc = i_mod_sg(h, sg, cmd_rem_srv, 0);
out:
	i_ilbadm_free_sgroup(sg);

	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);
	if ((rc != ILBADM_OK) && (rc != ILBADM_LIBERR))
		ilbadm_err(ilbadm_errstr(rc));
	return (rc);
}

ilbadm_status_t
ilbadm_destroy_servergroup(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	char		*sgname;

	if (argc != 2) {
		ilbadm_err(gettext("usage:ilbadm"
		    " delete-servergroup groupname"));
		rc = ILBADM_LIBERR;
		goto out;
	}

	sgname = argv[1];

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	rclib = ilb_destroy_servergroup(h, sgname);
out:
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		rc = ILBADM_LIBERR;
	}

	return (rc);
}

#define	BUFSZ	1024

static int
export_srv_spec(ilb_server_data_t *srv, char *buf, const int bufsize)
{
	int	len = 0, bufsz = (int)bufsize;

	ip2str(&srv->sd_addr, buf, bufsz, 0);

	len += strlen(buf);
	bufsz -= len;

	if (srv->sd_minport != 0) {
		in_port_t	h_min, h_max;
		int		inc;

		h_min = ntohs(srv->sd_minport);
		h_max = ntohs(srv->sd_maxport);

		/* to do: if service name was given, print that, not number */
		if (h_max <= h_min)
			inc = snprintf(buf+len, bufsz, ":%d", h_min);
		else
			inc = snprintf(buf+len, bufsz, ":%d-%d", h_min, h_max);

		if (inc > bufsz) /* too little space */
			return (-1);
		len += inc;
	}

	return (len);
}


/*
 * this is called by ilb_walk_servers(), therefore we return ilb_status_t
 * not ilbadm_status, and retain an unused function argument
 */
/* ARGSUSED */
ilb_status_t
ilbadm_export_a_srv(ilb_handle_t h, ilb_server_data_t *srv, const char *sgname,
    void *arg)
{
	sg_export_arg_t	*larg = (sg_export_arg_t *)arg;
	FILE		*fp = larg->fp;
	char		linebuf[BUFSZ]; /* XXXms make that dynamic */
	int		sz = BUFSZ;

	if (export_srv_spec(srv, linebuf, sz) == -1)
		return (ILB_STATUS_OK);

	(void) fprintf(fp, "add-server -s server=");

	(void) fprintf(fp, "%s %s\n", linebuf, sgname);
	return (ILB_STATUS_OK);
}

ilb_status_t
ilbadm_export_sg(ilb_handle_t h, ilb_sg_data_t *sg, void *arg)
{
	ilb_status_t	rc = ILB_STATUS_OK;
	sg_export_arg_t	*larg = (sg_export_arg_t *)arg;
	FILE		*fp = larg->fp;

	(void) fprintf(fp, "create-servergroup %s\n", sg->sgd_name);
	if (sg->sgd_srvcount == 0)
		return (ILB_STATUS_OK);

	rc = ilb_walk_servers(h, ilbadm_export_a_srv, sg->sgd_name, arg);
	if (rc != ILB_STATUS_OK)
		goto out;

	if (fflush(fp) == EOF)
		rc = ILB_STATUS_WRITE;

out:
	return (rc);
}

ilbadm_status_t
ilbadm_export_servergroups(ilb_handle_t h, FILE *fp)
{
	ilb_status_t	rclib = ILB_STATUS_OK;
	ilbadm_status_t	rc = ILBADM_OK;
	sg_export_arg_t	arg;

	arg.fp = fp;
	arg.sg = NULL;

	rclib = ilb_walk_servergroups(h, ilbadm_export_sg, NULL, (void *)&arg);
	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		rc = ILBADM_LIBERR;
	}

	return (rc);
}
