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

#ifndef	_ILBADM_H
#define	_ILBADM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/list.h>
#include <net/if.h>
#include <stdarg.h>
#include <inttypes.h>
#include <libilb.h>
#include <libintl.h>
#include <locale.h>

#define	ILBADM_VERSION  "1.0"
#define	ILBADM_COPYRIGHT \
	"Copyright 2009 Sun Microsystems, Inc.  All rights reserved.\n" \
	"Use is subject to license terms.\n"

/*
 * flag values
 */
#define	OPT_VALUE_LIST		0x0001
#define	OPT_IP_RANGE		0x0002
#define	OPT_PORTS		0x0004
#define	OPT_PORTS_ONLY		0x0008
#define	OPT_NAT			0x0010
#define	OPT_NUMERIC_ONLY	0x0020

#define	ILBD_BAD_VAL	(-1)

#define	ILBADM_LIST_FULL	0x0001
#define	ILBADM_LIST_PARSE	0x0002
#define	ILBADM_LIST_ENABLED	0x0004
#define	ILBADM_LIST_NOENABLED	(~ILBADM_LIST_ENABLED)
#define	ILBADM_LIST_DISABLED	0x0008
#define	ILBADM_LIST_NODISABLED	(~ILBADM_LIST_DISABLED)

#define	ILBADM_IMPORT_PRESERVE	0x1000

#define	V6_ADDRONLY	0x1	/* don't print surrounding "[]"s */

#define	ILB_SRVID_SZ	(ILB_NAMESZ - 5)
#define	ILBD_NAMESZ	ILB_NAMESZ

#define	ILB_MAX_PORT	UINT16_MAX

typedef enum {
	ILBADM_OK = 0,
	ILBADM_ASSIGNREQ,	/* assignment '=' required */
	ILBADM_EINVAL,		/* invalid value */
	ILBADM_ENOMEM,		/* malloc failed */
	ILBADM_ENOOPTION,	/* mandatory option missing */
	ILBADM_ENOPROTO,	/* protocol not found in database */
	ILBADM_ENOPROXY,	/* proxy-src is missing */
	ILBADM_ENOSERVICE,	/* servicename not found in database */
	ILBADM_ENOSGNAME,	/* servergroup name missing */
	ILBADM_ENORULE,		/* rulename missing or no such rule */
	ILBADM_ENOSERVER,	/* rulename missing or no such rule */
	ILBADM_EXPORTFAIL,	/* too little space to do export servergroup */
	ILBADM_FAIL,		/* processing of command failed */
	ILBADM_HCPRINT,		/* failed to print healthcheck */
	ILBADM_INVAL_ADDR,	/* invalid address */
	ILBADM_INVAL_AF,	/* invalid address family */
	ILBADM_INVAL_ALG,	/* LB algorithm failure */
	ILBADM_INVAL_ARGS,	/* invalid arguments to command */
	ILBADM_INVAL_COMMAND,	/* invalid command */
	ILBADM_INVAL_KEYWORD,	/* invalid keyword */
	ILBADM_INVAL_OPER,	/* invalid operation type */
	ILBADM_INVAL_PORT,	/* invalid value specified for port */
	ILBADM_INVAL_PROXY,	/* proxy-src not allowed   */
	ILBADM_INVAL_SYNTAX,	/* syntax error */
	ILBADM_INVAL_SRVID,	/* server id is invalid (missing "_" ?) */
	ILBADM_LIBERR,		/* translation of libilb errors. We also */
				/* set it in ilbadm fuctions to indicate */
				/* printing of non-generic error messages */
	ILBADM_NORECURSIVE,	/* recursive import not allowed */
	ILBADM_TOOMANYIPADDR,	/* too many addresses */
	ILBADM_NOKEYWORD_VAL	/* no value specified for a keyword */
} ilbadm_status_t;


typedef enum {
	ILB_KEY_BAD = -1,
	ILB_KEY_SERVER,
	ILB_KEY_SERVRANGE,	/* pseudo-key for SG creation */
	ILB_KEY_SERVERID,
	ILB_KEY_VIP,
	ILB_KEY_PORT,
	ILB_KEY_PROTOCOL,
	ILB_KEY_IPVERSION,
	ILB_KEY_ALGORITHM,
	ILB_KEY_TYPE,
	ILB_KEY_SERVERGROUP,
	ILB_KEY_HEALTHCHECK,
	ILB_KEY_HCPORT,
	ILB_KEY_SRC,
	ILB_KEY_STICKY,
	ILB_KEY_CONNDRAIN,	/* otional timers ... */
	ILB_KEY_NAT_TO,
	ILB_KEY_STICKY_TO,
	ILB_KEY_HC_TEST,
	ILB_KEY_HC_COUNT,
	ILB_KEY_HC_INTERVAL,
	ILB_KEY_HC_TIMEOUT
} ilbadm_key_code_t;

/*
 * we need a few codes for commands, can't use libilb ones
 */
typedef enum {
	cmd_create_sg,
	cmd_add_srv,
	cmd_rem_srv,
	cmd_enable_rule,
	cmd_disable_rule,
	cmd_enable_server,
	cmd_disable_server
} ilbadm_cmd_t;

/* filched from snoop_ether.c */
typedef struct val_type {
	int	v_type;
	char	v_name[20];
	char 	v_alias[8];	/* undocumented */
} ilbadm_val_type_t;

typedef struct key_names {
	ilbadm_key_code_t	k_key;
	char		k_name[20];
	char		k_alias[12];	/* undocumented */
} ilbadm_key_name_t;

typedef struct servnode {
	list_node_t	s_link;
	ilb_server_data_t	s_spec;
} ilbadm_servnode_t;

typedef struct sgroup {
	list_t		sg_serv_list;	/* list of servnode_t elements */
	int		sg_count;
	char 		*sg_name;
} ilbadm_sgroup_t;

typedef	struct cmd_hlp {
	char	*h_help;
} ilbadm_cmd_help_t;

typedef ilbadm_status_t	(* cmdfunc_t)(int, char **);

typedef struct cmd_names {
	char		c_name[25];
	char		c_alias[20];	/* undocumented */
	cmdfunc_t	c_action;
	ilbadm_cmd_help_t	*c_help;	/* for "usage" */
} ilbadm_cmd_desc_t;

ilbadm_status_t	ilbadm_add_server_to_group(int, char **);
ilbadm_status_t	ilbadm_create_servergroup(int, char **);
ilbadm_status_t	ilbadm_destroy_servergroup(int, char **);
ilbadm_status_t	ilbadm_rem_server_from_group(int, char **);

ilbadm_status_t	ilbadm_create_rule(int, char **);
ilbadm_status_t	ilbadm_destroy_rule(int, char **);
ilbadm_status_t	ilbadm_enable_rule(int, char **);
ilbadm_status_t	ilbadm_disable_rule(int, char **);
ilbadm_status_t	ilbadm_show_server(int, char **);
ilbadm_status_t	ilbadm_enable_server(int, char **);
ilbadm_status_t	ilbadm_disable_server(int, char **);

ilbadm_status_t	ilbadm_show_servergroups(int, char **);
ilbadm_status_t	ilbadm_show_rules(int, char **);
ilbadm_status_t	ilbadm_show_stats(int, char **);

ilbadm_status_t	ilbadm_create_hc(int, char **);
ilbadm_status_t	ilbadm_destroy_hc(int, char **);
ilbadm_status_t	ilbadm_show_hc(int, char **);
ilbadm_status_t	ilbadm_show_hc_result(int, char **);

ilbadm_status_t	ilbadm_noimport(int, char **);

ilbadm_status_t	ilbadm_show_nat(int, char **);
ilbadm_status_t	ilbadm_show_persist(int, char **);

ilbadm_status_t	i_parse_optstring(char *, void *, ilbadm_key_name_t *,
    int, int *);
ilbadm_servnode_t	*i_new_sg_elem(ilbadm_sgroup_t *);
ilbadm_status_t	ilbadm_import(int, int, char *[], int);
ilbadm_status_t	ilbadm_export(int, char *[]);
ilbadm_status_t	ilbadm_export_servergroups(ilb_handle_t h, FILE *);
ilbadm_status_t	ilbadm_export_hc(ilb_handle_t h, FILE *);
ilbadm_status_t	ilbadm_export_rules(ilb_handle_t h, FILE *);

ilbadm_status_t	i_check_rule_spec(ilb_rule_data_t *);
ilbadm_status_t ilbadm_set_netmask(char *, ilb_ip_addr_t *, int);
int		ilbadm_mask_to_prefixlen(ilb_ip_addr_t *);

void		print_cmdlist_short(char *, FILE *);
extern int	ilb_cmp_ipaddr(ilb_ip_addr_t *, ilb_ip_addr_t *,
    longlong_t *);

void	ip2str(ilb_ip_addr_t *, char *, size_t, int);
char	*i_str_from_val(int, ilbadm_val_type_t *);
char	*ilbadm_key_to_opt(ilbadm_key_code_t);

void	Usage(char *);
void	unknown_opt(char **, int);
const char	*ilbadm_errstr(ilbadm_status_t);
void	ilbadm_err(const char *format, ...);

#ifdef	__cplusplus
}
#endif

#endif /* _ILBADM_H */
