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
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#ifndef _NWAMCFG_H
#define	_NWAMCFG_H

/*
 * header file for nwamcfg command
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	NWAM_OK			0
#define	NWAM_ERR		1
#define	NWAM_REPEAT		2

/* max length of "ncu", "ncp", "loc", "enm", "wlan" */
#define	NWAM_MAX_TYPE_LEN	5

#define	CMD_CANCEL		0
#define	CMD_CLEAR		1
#define	CMD_COMMIT		2
#define	CMD_CREATE		3
#define	CMD_DESTROY		4
#define	CMD_END			5
#define	CMD_EXIT		6
#define	CMD_EXPORT		7
#define	CMD_GET			8
#define	CMD_HELP		9
#define	CMD_LIST		10
#define	CMD_REVERT		11
#define	CMD_SELECT		12
#define	CMD_SET			13
#define	CMD_VERIFY		14
#define	CMD_WALKPROP		15

#define	CMD_MIN	CMD_CANCEL
#define	CMD_MAX	CMD_WALKPROP

/* one-level resource types */
#define	RT1_UNKNOWN		0
#define	RT1_LOC			1
#define	RT1_NCP			2
#define	RT1_ENM			3
#define	RT1_WLAN		4

#define	RT1_MIN			RT1_UNKNOWN
#define	RT1_MAX			RT1_WLAN

/* two-level resource types */
#define	RT2_UNKNOWN		0
#define	RT2_NCU			1

#define	RT2_MIN			RT2_UNKNOWN
#define	RT2_MAX			RT2_NCU

/* class types for NCU's */
#define	NCU_CLASS_PHYS		0
#define	NCU_CLASS_IP		1
#define	NCU_CLASS_ANY		2

#define	NCU_CLASS_MIN		NCU_CLASS_PHYS
#define	NCU_CLASS_MAX		NCU_CLASS_ANY

/* property types, matches NWAM_*_PROP_* from libnwam.h */
#define	PT_UNKNOWN		0
#define	PT_ACTIVATION_MODE	1
#define	PT_ENABLED		2
#define	PT_TYPE			3
#define	PT_CLASS		4
#define	PT_PARENT		5
#define	PT_PRIORITY_GROUP	6
#define	PT_PRIORITY_MODE	7
#define	PT_LINK_MACADDR		8
#define	PT_LINK_AUTOPUSH	9
#define	PT_LINK_MTU		10
#define	PT_IP_VERSION		11
#define	PT_IPV4_ADDRSRC		12
#define	PT_IPV4_ADDR		13
#define	PT_IPV4_DEFAULT_ROUTE	14
#define	PT_IPV6_ADDRSRC		15
#define	PT_IPV6_ADDR		16
#define	PT_IPV6_DEFAULT_ROUTE	17
#define	PT_CONDITIONS		18
#define	PT_ENM_FMRI		19
#define	PT_ENM_START		20
#define	PT_ENM_STOP		21
#define	PT_LOC_NAMESERVICES	22
#define	PT_LOC_NAMESERVICES_CONFIG 23
#define	PT_LOC_DNS_CONFIGSRC	24
#define	PT_LOC_DNS_DOMAIN	25
#define	PT_LOC_DNS_SERVERS	26
#define	PT_LOC_DNS_SEARCH	27
#define	PT_LOC_NIS_CONFIGSRC	28
#define	PT_LOC_NIS_SERVERS	29
#define	PT_LOC_LDAP_CONFIGSRC	30
#define	PT_LOC_LDAP_SERVERS	31
#define	PT_LOC_DEFAULT_DOMAIN	32
#define	PT_LOC_NFSV4_DOMAIN	33
#define	PT_LOC_IPF_CONFIG	34
#define	PT_LOC_IPF_V6_CONFIG	35
#define	PT_LOC_IPNAT_CONFIG	36
#define	PT_LOC_IPPOOL_CONFIG	37
#define	PT_LOC_IKE_CONFIG	38
#define	PT_LOC_IPSECPOL_CONFIG	39
#define	PT_WLAN_BSSIDS		40
#define	PT_WLAN_PRIORITY	41
#define	PT_WLAN_KEYNAME		42
#define	PT_WLAN_KEYSLOT		43
#define	PT_WLAN_SECURITY_MODE	44
#define	PT_IP_PRIMARY		45
#define	PT_IP_REQHOST		46
/*
 * If any new PT_ are defined here, make sure it is added in the same
 * order into the pt_types array in nwamcfg.c
 */
#define	PT_MIN			PT_UNKNOWN
#define	PT_MAX			PT_IP_REQHOST

#define	MAX_SUBCMD_ARGS	3

typedef struct cmd {
	int	cmd_num;
	void	(*cmd_handler)(struct cmd *);
	int	cmd_res1_type;
	int	cmd_res2_type;
	int	cmd_prop_type;
	int	cmd_ncu_class_type;
	int	cmd_argc;
	char	*cmd_argv[MAX_SUBCMD_ARGS + 1];
} cmd_t;

/* Fuctions for each command */
typedef void (cmd_func_t)(cmd_t *);

extern cmd_func_t cancel_func, clear_func, commit_func, create_func;
extern cmd_func_t destroy_func, end_func, exit_func, export_func, get_func;
extern cmd_func_t help_func, list_func, revert_func, select_func, set_func;
extern cmd_func_t verify_func, walkprop_func;

extern cmd_t *alloc_cmd(void);
extern void free_cmd(cmd_t *cmd);

extern boolean_t check_scope(int);
extern const char *cmd_to_str(int);

extern void nerr(const char *, ...);
extern void properr(const char *);

extern boolean_t saw_error;

extern FILE *yyin;

#ifdef __cplusplus
}
#endif

#endif	/* _NWAMCFG_H */
