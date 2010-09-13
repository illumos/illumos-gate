/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IPQOS_CONF_H
#define	_IPQOS_CONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/nvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

/* debug level bits */
#define	L0	0x01
#define	L1	0x02
#define	L2	0x04
#define	DIFF	0x08
#define	KRET	0x10
#define	APPLY	0x20
#define	MHME	0x40
#define	RBK	0x80

/* directory for types files */
#define	TYPES_FILE_DIR		"/usr/lib/ipqosconf/"

/* location of lock file */
#define	IPQOS_CONF_LOCK_FILE	"/var/run/ipqosconf.lock"

/* location of startup config file */
#define	IPQOS_CONF_INIT_PATH	"/etc/inet/ipqosinit.conf"

/* ipqosconf commands */

#define	IPQOS_CONF_APPLY	1
#define	IPQOS_CONF_VIEW		2
#define	IPQOS_CONF_COMMIT	3
#define	IPQOS_CONF_FLUSH	4

/* print ntabs to stream fp */

#define	PRINT_TABS(fp, ntabs)\
{\
	int x;\
	for (x = 0; x < ntabs; x++)\
		(void) fprintf(fp, "\t");\
}

/* having to define this as ip6.h version in _KERNEL guard */
#ifndef	V4_PART_OF_V6
#define	V4_PART_OF_V6(v6)	v6._S6_un._S6_u32[3]
#endif

/*
 * given pointer cp advance it to the first non-space character.
 */
#define	SKIPWS(cp)	while (isspace(*cp) && (*cp != '\0')) cp++

/* extract the v4 and v6 bits of the ip_version enumeration from the filter */
#define	VERSION_IS_V4(flt)	((flt)->ip_versions & 0x01)
#define	VERSION_IS_V6(flt)	((flt)->ip_versions & 0x02)

/* retrieve short name from a module.name nvpair name */
#define	SHORT_NAME(longnme)	(strchr(longnme, '.') + 1)

/* latest version of cfg file supported (1.0) */
#define	IPQOS_CUR_FMT_MAJOR_VER	1
#define	IPQOS_CUR_FMT_MINOR_VER	0

/* length of string buffer used for storing an integer as a string */
#define	IPQOS_INT_STR_LEN	15

/* length of line buffer used to read types file */
#define	IPQOS_CONF_TYPE_LINE_LEN	1024

/* length of buffer used to store name of type when reading types file */
#define	IPQOS_CONF_TYPE_LEN	24

/* max length of value string in types file */
#define	IPQOS_VALST_MAXLEN 100

/* initial size of line buffer used by readtoken */
#define	IPQOS_CONF_LINEBUF_SZ	150

/* length of class/filter/action names */
#define	IPQOS_CONF_NAME_LEN	24

/* length of module names */
#define	IPQOS_CONF_MOD_NAME_LEN	10

/* IPQOS_CONF_NAME_LEN + IPQOS_CONF_MOD_NAME_LEN */
/* must be a numeric literal for use in scanf() format string */
#define	IPQOS_CONF_PNAME_LEN	34

/* length of buffer used to construct msgs for printing */
#define	IPQOS_MSG_BUF_SZ	200
/*
 * Define CURL here so that while you are reading
 * the code, it does not affect "vi" in pattern
 * matching.
 */
#define	CURL_BEGIN		'{'
#define	CURL_END		'}'

/* internal return codes */
#define	IPQOS_CONF_SUCCESS	0
#define	IPQOS_CONF_ERR		1
#define	IPQOS_CONF_RECOVER_ERR	2
#define	IPQOS_CONF_CURL_END	3
#define	IPQOS_CONF_CURL_BEGIN	4
#define	IPQOS_CONF_EOF		5
#define	IPQOS_CONF_NO_VER_STR	6

/* special tokens in config file */
#define	IPQOS_CONF_IP_VERSION_STR	"ip_version"
#define	IPQOS_CONF_NEXT_ACTION_STR	"next_action"
#define	IPQOS_CONF_NAME_STR 		"name"
#define	IPQOS_CONF_MODULE_STR 		"module"
#define	IPQOS_CONF_FILTER_STR 		"filter"
#define	IPQOS_CONF_ACTION_STR 		"action"
#define	IPQOS_CONF_CLASS_STR 		"class"
#define	IPQOS_CONF_PARAMS_STR 		"params"
#define	IPQOS_CONF_NEXT_STR		"next"
#define	IPQOS_CONF_STATS_ENABLE_STR	"enable_stats"
#define	IPQOS_CONF_GLOBAL_STATS_STR	"global_stats"
#define	IPQOS_CONF_DROP_STR		"drop"
#define	IPQOS_CONF_CONT_STR		"continue"
#define	IPQOS_CONF_DEFER_STR		"defer"
#define	IPQOS_CONF_TRUE_STR		"true"
#define	IPQOS_CONF_FALSE_STR		"false"
#define	IPQOS_FMT_VERSION_STR		"fmt_version"
#define	IPQOS_IFNAME_STR		"if_name"
#define	IPQOS_PLACE_PRM_STR		IPQOS_CONF_PARAMS_STR
#define	IPQOS_PLACE_FILTER_STR		IPQOS_CONF_FILTER_STR
#define	IPQOS_PLACE_MAP_STR		"map"

/* special tokens in types file */
#define	IPQOS_CONF_PERM_FILTER_MK	"#PERM_FILTER"
#define	IPQOS_CONF_PERM_CLASS_MK	"#PERM_CLASS"
#define	IPQOS_FMT_STR			"fmt_version"
#define	IPQOS_MOD_STR			"mod_version"


/* nvlist parameters */
#define	IPQOS_CONF_IP_VERSION		"ipgpc.ip_version"

/* name lookup errors returned from domultihome() */
#define	IPQOS_LOOKUP_RETRY	1
#define	IPQOS_LOOKUP_FAIL	2

/*
 * used in calls to ipp_action_info() to encapuslate both an action and
 * an ipqosconf internal return code.
 */
typedef struct ipqos_actinfo_prm_s {
	struct ipqos_conf_action_s *action;
	int intl_ret;
} ipqos_actinfo_prm_t;

/*
 * skeletal list element struct used in manipulating lists of more complex
 * structures.
 */
typedef struct ipqos_list_el_s {
	struct ipqos_list_el_s *next;
} ipqos_list_el_t;

typedef struct str_str {
	char *s1;
	char *s2;
} str_str_t;

typedef struct str_val {
	char *string;
	int value;
} str_val_t;

typedef struct str_val_nd {
	struct str_val sv;
	struct str_val_nd *next;
} str_val_nd_t;

/* type of msg to be printed by ipqos_msg */
enum msg_type { MT_ERROR, MT_WARNING, MT_LOG, MT_ENOSTR };

/* enum for allowable parameter types */

typedef enum ipqos_nvtype_e {
IPQOS_DATA_TYPE_UINT8,
IPQOS_DATA_TYPE_INT16,
IPQOS_DATA_TYPE_UINT16,
IPQOS_DATA_TYPE_INT32,
IPQOS_DATA_TYPE_UINT32,
IPQOS_DATA_TYPE_BOOLEAN,
IPQOS_DATA_TYPE_STRING,
IPQOS_DATA_TYPE_ACTION,
IPQOS_DATA_TYPE_ADDRESS,
IPQOS_DATA_TYPE_PORT,
IPQOS_DATA_TYPE_PROTO,
IPQOS_DATA_TYPE_ENUM,
IPQOS_DATA_TYPE_IFNAME,
IPQOS_DATA_TYPE_M_INDEX,
IPQOS_DATA_TYPE_INT_ARRAY,
IPQOS_DATA_TYPE_USER,
IPQOS_DATA_TYPE_ADDRESS_MASK,
IPQOS_DATA_TYPE_IFINDEX
} ipqos_nvtype_t;

/*
 * passed to readnvpair to indicate which special meanings for nv names
 * to use.
 */
typedef enum place_e {
PL_ACTION, PL_FILTER, PL_CLASS, PL_PARAMS, PL_MAP, PL_ANY} place_t;


/* classifier filter representation */

typedef struct ipqos_conf_filter_s {
	struct ipqos_conf_filter_s *next;
	char name[IPQOS_CONF_NAME_LEN];
	char class_name[IPQOS_CONF_NAME_LEN];
	nvlist_t *nvlist;
	boolean_t new;
	boolean_t modified;
	boolean_t cr_mod;
	boolean_t todel;
	boolean_t deleted;
	uint32_t originator;
	char *src_nd_name;
	char *dst_nd_name;
	int instance;
	uint32_t lineno;
	uint32_t ip_versions;
	int nlerr;
} ipqos_conf_filter_t;


/*
 * action reference - used to store information and reference an action struct.
 */

typedef struct ipqos_conf_act_ref_s {
	struct ipqos_conf_act_ref_s *next;
	struct ipqos_conf_act_ref_s *prev;
	char name[IPQOS_CONF_NAME_LEN];
	char field[IPQOS_CONF_PNAME_LEN];
	struct ipqos_conf_action_s *action;
	nvlist_t *nvlist;
} ipqos_conf_act_ref_t;


/* classifier class representation */

typedef struct ipqos_conf_class_s {
	struct ipqos_conf_class_s *next;
	char name[IPQOS_CONF_NAME_LEN];
	nvlist_t *nvlist;
	ipqos_conf_act_ref_t *alist;
	boolean_t modified;
	boolean_t new;
	boolean_t cr_mod;
	boolean_t todel;
	boolean_t deleted;
	boolean_t stats_enable;
	uint32_t originator;
	uint32_t lineno;
} ipqos_conf_class_t;

/* action parameters representation */

typedef struct ipqos_conf_params_s {
	struct ipqos_conf_params_s *next;
	ipqos_conf_act_ref_t *actions;
	nvlist_t *nvlist;
	boolean_t modified;
	boolean_t stats_enable;
	uint32_t originator;
	uint32_t lineno;
	boolean_t cr_mod;
} ipqos_conf_params_t;


/* signifys which stage of configuration application has just past */
enum visit {ADD_VISITED = 1, MOD_VISITED, REM_VISITED, INCYCLE_VISITED};

/*
 * action representation, with parameters, and lists of filters and classes
 * if classifier action.
 */
typedef struct ipqos_conf_action_s {
	struct ipqos_conf_action_s *next;
	char name[IPQOS_CONF_NAME_LEN];
	char module[IPQOS_CONF_NAME_LEN];
	ipqos_conf_filter_t *filters;
	ipqos_conf_class_t *classes;
	ipqos_conf_params_t *params;
	nvlist_t *nvlist;
	boolean_t todel;
	boolean_t deleted;
	boolean_t new;
	boolean_t modified;
	boolean_t cr_mod;
	ipqos_conf_act_ref_t *dependencies;
	enum visit visited;
	uint32_t lineno;
	ipqos_conf_filter_t *retry_filters;
	char **perm_classes;
	int num_perm_classes;
	int module_version;
} ipqos_conf_action_t;


#ifdef __cplusplus
}
#endif

#endif /* _IPQOS_CONF_H */
