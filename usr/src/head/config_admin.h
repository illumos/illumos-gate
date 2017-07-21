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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CONFIG_ADMIN_H
#define	_SYS_CONFIG_ADMIN_H

/*
 * config_admin.h
 *
 * this file supports usage of the interfaces defined in
 * config_admin.3x. which are contained in /usr/lib/libcfgadm.so.1
 */

#include <sys/param.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Defined constants
 */
#define	CFGA_AP_LOG_ID_LEN	20
#define	CFGA_AP_PHYS_ID_LEN	MAXPATHLEN
#define	CFGA_INFO_LEN		4096
#define	CFGA_TYPE_LEN		12

#define	CFGA_CLASS_LEN		12
#define	CFGA_LOG_EXT_LEN	30

#define	CFGA_DYN_SEP		"::"
#define	CFGA_PHYS_EXT_LEN	(CFGA_AP_PHYS_ID_LEN + CFGA_LOG_EXT_LEN)


/*
 * Configuration change state commands
 */
typedef enum {
	CFGA_CMD_NONE = 0,
	CFGA_CMD_LOAD,
	CFGA_CMD_UNLOAD,
	CFGA_CMD_CONNECT,
	CFGA_CMD_DISCONNECT,
	CFGA_CMD_CONFIGURE,
	CFGA_CMD_UNCONFIGURE
} cfga_cmd_t;

/*
 * Configuration states
 */
typedef enum {
	CFGA_STAT_NONE = 0,
	CFGA_STAT_EMPTY,
	CFGA_STAT_DISCONNECTED,
	CFGA_STAT_CONNECTED,
	CFGA_STAT_UNCONFIGURED,
	CFGA_STAT_CONFIGURED
} cfga_stat_t;

/*
 * Configuration conditions
 */
typedef enum {
	CFGA_COND_UNKNOWN = 0,
	CFGA_COND_OK,
	CFGA_COND_FAILING,
	CFGA_COND_FAILED,
	CFGA_COND_UNUSABLE
} cfga_cond_t;

/*
 * Flags
 */
#define	CFGA_FLAG_FORCE		1
#define	CFGA_FLAG_VERBOSE	2
#define	CFGA_FLAG_LIST_ALL	4

typedef char cfga_ap_log_id_t[CFGA_AP_LOG_ID_LEN];
typedef char cfga_ap_phys_id_t[CFGA_AP_PHYS_ID_LEN];
typedef char cfga_info_t[CFGA_INFO_LEN];
typedef char cfga_type_t[CFGA_TYPE_LEN];
typedef int cfga_flags_t;
typedef int cfga_busy_t;


typedef char cfga_log_ext_t[CFGA_LOG_EXT_LEN];
typedef char cfga_phys_ext_t[CFGA_PHYS_EXT_LEN];
typedef char cfga_class_t[CFGA_CLASS_LEN];

typedef struct cfga_list_data {
	cfga_log_ext_t	ap_log_id;	/* Attachment point logical id */
	cfga_phys_ext_t	ap_phys_id;	/* Attachment point physical id */
	cfga_class_t	ap_class;	/* Attachment point class */
	cfga_stat_t	ap_r_state;	/* Receptacle state */
	cfga_stat_t	ap_o_state;	/* Occupant state */
	cfga_cond_t	ap_cond;	/* Attachment point condition */
	cfga_busy_t	ap_busy;	/* Busy indicators */
	time_t		ap_status_time;	/* Attachment point last change */
	cfga_info_t	ap_info;	/* Miscellaneous information */
	cfga_type_t	ap_type;	/* Occupant type */
} cfga_list_data_t;

/*
 * The following structure is retained for backward compatibility
 */
typedef struct cfga_stat_data {
	cfga_ap_log_id_t ap_log_id;	/* Attachment point logical id */
	cfga_ap_phys_id_t ap_phys_id;	/* Attachment point physical id */
	cfga_stat_t	ap_r_state;	/* Receptacle state */
	cfga_stat_t	ap_o_state;	/* Occupant state */
	cfga_cond_t	ap_cond;	/* Attachment point condition */
	cfga_busy_t	ap_busy;	/* Busy indicators */
	time_t		ap_status_time;	/* Attachment point last change */
	cfga_info_t	ap_info;	/* Miscellaneous information */
	cfga_type_t	ap_type;	/* Occupant type */
} cfga_stat_data_t;


struct cfga_confirm {
	int (*confirm)(void *appdata_ptr, const char *message);
	void *appdata_ptr;
};

struct cfga_msg {
	int (*message_routine)(void *appdata_ptr, const char *message);
	void *appdata_ptr;
};

/*
 * Library function error codes returned by all functions below
 * except config_strerror which is used to decode the error
 * codes.
 */
typedef enum {
	CFGA_OK = 0,
	CFGA_NACK,
	CFGA_NOTSUPP,
	CFGA_OPNOTSUPP,
	CFGA_PRIV,
	CFGA_BUSY,
	CFGA_SYSTEM_BUSY,
	CFGA_DATA_ERROR,
	CFGA_LIB_ERROR,
	CFGA_NO_LIB,
	CFGA_INSUFFICENT_CONDITION,
	CFGA_INVAL,
	CFGA_ERROR,
	CFGA_APID_NOEXIST,
	CFGA_ATTR_INVAL
} cfga_err_t;


/*
 * config_admin.3x library interfaces
 */

cfga_err_t config_change_state(cfga_cmd_t state_change_cmd, int num_ap_ids,
    char *const *ap_ids, const char *options, struct cfga_confirm *confp,
    struct cfga_msg *msgp, char **errstring, cfga_flags_t flags);

cfga_err_t config_private_func(const char *function, int num_ap_ids,
    char *const *ap_ids, const char *options, struct cfga_confirm *confp,
    struct cfga_msg *msgp, char **errstring, cfga_flags_t flags);

cfga_err_t config_test(int num_ap_ids, char *const *ap_ids,
    const char *options, struct cfga_msg *msgp, char **errstring,
    cfga_flags_t flags);

cfga_err_t config_list_ext(int num_ap_ids, char *const *ap_ids,
    struct cfga_list_data **ap_id_list, int *nlist, const char *options,
    const char *listopts, char **errstring, cfga_flags_t flags);

cfga_err_t config_help(int num_ap_ids, char *const *ap_ids,
    struct cfga_msg *msgp, const char *options, cfga_flags_t flags);

const char *config_strerror(cfga_err_t cfgerrnum);

int config_ap_id_cmp(const cfga_ap_log_id_t ap_id1,
    const cfga_ap_log_id_t ap_id2);

void config_unload_libs();

/*
 * The following two routines are retained only for backward compatibility
 */
cfga_err_t config_stat(int num_ap_ids, char *const *ap_ids,
    struct cfga_stat_data *buf, const char *options, char **errstring);

cfga_err_t config_list(struct cfga_stat_data **ap_di_list, int *nlist,
    const char *options, char **errstring);


#ifdef CFGA_PLUGIN_LIB
/*
 * Plugin library routine hooks - only to be used by the generic
 * library and plugin libraries (who must define CFGA_PLUGIN_LIB
 * prior to the inclusion of this header).
 */

cfga_err_t cfga_change_state(cfga_cmd_t, const char *, const char *,
    struct cfga_confirm *, struct cfga_msg *, char **, cfga_flags_t);
cfga_err_t cfga_private_func(const char *, const char *, const char *,
    struct cfga_confirm *, struct cfga_msg *, char **, cfga_flags_t);
cfga_err_t cfga_test(const char *, const char *, struct cfga_msg *,
    char **, cfga_flags_t);
cfga_err_t cfga_list_ext(const char *, struct cfga_list_data **, int *,
    const char *, const char *, char **, cfga_flags_t);
cfga_err_t cfga_help(struct cfga_msg *, const char *, cfga_flags_t);
int cfga_ap_id_cmp(const cfga_ap_log_id_t,
    const cfga_ap_log_id_t);


/*
 * Plugin version information.
 */
#define	CFGA_HSL_V1	1
#define	CFGA_HSL_V2	2
#define	CFGA_HSL_VERS	CFGA_HSL_V2

/*
 * The following two routines are retained only for backward compatibility.
 */
cfga_err_t cfga_stat(const char *, struct cfga_stat_data *,
    const char *, char **);
cfga_err_t cfga_list(const char *, struct cfga_stat_data **, int *,
    const char *, char **);


#endif /* CFGA_PLUGIN_LIB */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CONFIG_ADMIN_H */
