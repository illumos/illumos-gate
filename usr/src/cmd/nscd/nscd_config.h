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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NSCD_CONFIG_H
#define	_NSCD_CONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "nscd_common.h"

/*
 * nscd_cfg_id_t is used to identify a config/stat
 * object. 'index' provides a way to quickly locate
 * the object in the associated configuration list.
 * 'name' can be looked up in the config info database
 * to obtain the index.
 */
typedef struct {
	int		index;
	char		*name;
} nscd_cfg_id_t;

/*
 * forward declaration of nscd_cfg_param_desc_t
 */
struct nscd_cfg_param_desc;

/*
 * for operations that apply to configuration data
 * in all the nsswitch databases
 */
#define	NSCD_CFG_NSW_ALLDB		"ALLDB"
#define	NSCD_CFG_NSW_ALLDB_INDEX	9999

/*
 * configuration lists includes switch databases (eg. hosts, passwd),
 * switch sources (eg. files, ldap), config parameter descriptions
 * (defined below), and status/statistic counter descriptions (defined
 * below)
 */
typedef struct {
	int		num;
	nscd_cfg_id_t	**list;
} nscd_cfg_list_t;

/*
 * type of configuration list
 */
typedef enum {
	NSCD_CFG_LIST_NSW_DB	= 0,
	NSCD_CFG_LIST_NSW_SRC	= 1,
	NSCD_CFG_LIST_PARAM	= 2,
	NSCD_CFG_LIST_STAT	= 3
} nscd_cfg_list_type_t;

/*
 * A config handle identifies config or stat data,
 * which if is nsswitch database specific, 'nswdb'
 * indicates the id of the database; if global,
 * 'nswdb' should be null. 'desc' is the config
 * param or stat description assocaited with the
 * data.
 */
typedef struct {
	nscd_cfg_id_t			*nswdb;
	void				*desc;
	nscd_cfg_list_type_t		type;
} nscd_cfg_handle_t;

/*
 * type of configuration/statistics data
 */
typedef enum {
	NSCD_CFG_DATA_NONE	= 0,
	NSCD_CFG_DATA_INTEGER	= 1,
	NSCD_CFG_DATA_BOOLEAN	= 2,
	NSCD_CFG_DATA_STRING	= 3,
	NSCD_CFG_DATA_BITMAP	= 4,
	NSCD_CFG_DATA_PERCENT	= 5
} nscd_cfg_data_type_t;
#define	NSCD_CFG_NUM_DATA_TYPE	5

/*
 * data flag is attached to config/stat data passed between
 * function to specify the nature/type of action to perform
 */

#define	NSCD_CFG_DFLAG_NONE			   0x0000

/*
 * data should not be freed by receiver;
 * otherwise it should be freed
 */
#define	NSCD_CFG_DFLAG_STATIC_DATA		   0x0001

/*
 * data is sent/received due to nscd initialization;
 * otherwise due to modification of the config data
 * requested by users
 */
#define	NSCD_CFG_DFLAG_INIT			   0x0002

/*
 * the entire group of data is, or should be, sent;
 * otherwise only a single parameter/stat value
 */
#define	NSCD_CFG_DFLAG_GROUP			   0x0004

/*
 * the data sent/received is to be verified by the
 * 'verify' function defined in the parameter
 * description
 */
#define	NSCD_CFG_DFLAG_VERIFY			   0x0008

/*
 * the data sent/received is to be processed by the
 * 'notify' function defined in the parameter
 * description
 */
#define	NSCD_CFG_DFLAG_NOTIFY			   0x0010

/*
 * the data sent/received is to be applied to all
 * nsswitch databases
 */
#define	NSCD_CFG_DFLAG_SET_ALL_DB		   0x0020

/*
 * the entire group of data is sent/received;
 * however, only those parameters selected by
 * the bitmap in the group info should be
 * processed
 */
#define	NSCD_CFG_DFLAG_BIT_SELECTED		   0x0040

/*
 * param flag is defined in the parameter description.
 * It specifies what operation should be applied to, or
 * the nature of, the config parameters.
 */

#define	NSCD_CFG_PFLAG_NONE			   0x0000

/*
 * At init/refresh time, send the parameter value
 * with the data of the entire group; otherwise
 * send the parameter value only
 */
#define	NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP	   0x0001

/*
 * At user requested update time, send the parameter
 * value with the data of the entire group; otherwise
 * send the parameter value only
 */
#define	NSCD_CFG_PFLAG_UPDATE_SEND_WHOLE_GROUP	   0x0002

/*
 * At init/refresh time, send the config data
 * once for each nsswitch database
 */
#define	NSCD_CFG_PFLAG_INIT_SET_ALL_DB		   0x0004

/*
 * At user requested update time, send the per nsswitch
 * database (non-global) data just one time (not once
 * for each nsswitch database)
 */
#define	NSCD_CFG_PFLAG_UPDATE_SEND_NON_GLOBAL_ONCE 0x0008

/*
 * send entire group data, but use bitmap to indicate
 * the one config parameter being processed. This flag
 * can only be sepcified for a group description
 */
#define	NSCD_CFG_PFLAG_SEND_BIT_SELECTED	   0x0010

/*
 * data is global, not per nsswitch database
 */
#define	NSCD_CFG_PFLAG_GLOBAL			   0x0020

/*
 * data is group data, not individual parameter value
 */
#define	NSCD_CFG_PFLAG_GROUP			   0x0040

/*
 * data is of variable length
 */
#define	NSCD_CFG_PFLAG_VLEN_DATA		   0x0080

/*
 * data is hidden, for internal use only, get/set not allowed
 */
#define	NSCD_CFG_PFLAG_HIDDEN			   0x0100

/*
 * data is linked, using the value of a different database
 */
#define	NSCD_CFG_PFLAG_LINKED			   0x0200

/*
 * data is obsolete, ignored with warning, should not be displayed
 */
#define	NSCD_CFG_PFLAG_OBSOLETE			   0x0400

/*
 * structure for error reporting
 */
typedef struct {
	nscd_rc_t	rc;
	char		*msg;
} nscd_cfg_error_t;

/*
 * typedef for flag, bitmap, and boolean
 */
typedef int		nscd_cfg_flag_t;
typedef int		nscd_cfg_bitmap_t;

/*
 * struct nscd_cfg_param_desc is used to describe each and
 * every one of the nscd config parameters so that they can
 * be processed generically by the configuration management
 * component. During init or update time, config data needs
 * to be pushed to other nscd components (frontend, switch
 * engine, cache backend, and so on) for further processing.
 * The 'verify' and 'notify' functions are the hooks provided
 * by these other components to validate and store the new
 * config data. The 'p_check' field, if specified, points
 * to a set of data used for preliminary check of a parameter
 * value (range, length, null checking etc).
 */
typedef	nscd_rc_t	(*nscd_cfg_func_notify_t)(void *,
			struct nscd_cfg_param_desc *,
			nscd_cfg_id_t *,
			nscd_cfg_flag_t,
			nscd_cfg_error_t **,
			void *);
typedef	nscd_rc_t	(*nscd_cfg_func_verify_t)(void *,
			struct	nscd_cfg_param_desc *,
			nscd_cfg_id_t *,
			nscd_cfg_flag_t,
			nscd_cfg_error_t **,
			void **);
typedef struct nscd_cfg_param_desc {
	nscd_cfg_id_t		id;
	nscd_cfg_data_type_t	type;
	nscd_cfg_flag_t		pflag;
	int	p_size;
	size_t	p_offset;
	int	p_fn;
	int	g_size;
	size_t	g_offset;
	int	g_index;
	void	*p_check;
	nscd_cfg_func_notify_t	notify;
	nscd_cfg_func_verify_t	verify;
} nscd_cfg_param_desc_t;

/*
 * the _nscd_cfg_get_param_desc_list function returns
 * the list of nscd config param descriptions at
 * run time
 */
typedef struct {
	int			num;
	nscd_cfg_param_desc_t	**list;
} nscd_cfg_param_desc_list_t;

/* this describes data of variable length */
typedef struct {
	void	*ptr;
	int	len;
} nscd_cfg_vlen_data_t;

/*
 * The following defines the various global and nsswitch
 * database specific data structures for all the groups of
 * configuration parameters. Before each one, there lists
 * the associated group info which contains the number of
 * parameters and the corresponding bitmap.
 */

typedef struct {
	int			num_param;
	nscd_cfg_bitmap_t	bitmap;
} nscd_cfg_group_info_t;
#define	NSCD_CFG_GROUP_INFO_NULL	{-1, 0x0000}

/*
 * frontend param group (Per nsswitch database)
 */
#define	NSCD_CFG_GROUP_INFO_FRONTEND	{1, 0x0001}
typedef struct {
	nscd_cfg_group_info_t	gi;
	int			worker_thread_per_nsw_db;
} nscd_cfg_frontend_t;

/*
 * switch engine param group (Per nsswitch database)
 */
#define	NSCD_CFG_GROUP_INFO_SWITCH	{7, 0x07f}
typedef struct {
	nscd_cfg_group_info_t	gi;
	char			*nsw_config_string;
	char			*nsw_config_db;
	nscd_bool_t		enable_lookup;
	nscd_bool_t		enable_loopback_checking;
	int			max_nsw_state_per_db;
	int			max_nsw_state_per_thread;
	int			max_getent_ctx_per_db;
} nscd_cfg_switch_t;

/*
 * log/debug param group (global)
 */
#define	NSCD_CFG_GROUP_INFO_GLOBAL_LOG	{3, 0x0007}
typedef struct {
	nscd_cfg_group_info_t	gi;
	char			*logfile;
	int			debug_level;
	int			debug_comp;
} nscd_cfg_global_log_t;

/*
 * frontend param group (global)
 */
#define	NSCD_CFG_GROUP_INFO_GLOBAL_FRONTEND	{2, 0x0003}
typedef struct {
	nscd_cfg_group_info_t	gi;
	int			common_worker_threads;
	int			cache_hit_threads;
} nscd_cfg_global_frontend_t;

/*
 * self credential param group (global)
 */
#define	NSCD_CFG_GROUP_INFO_GLOBAL_SELFCRED	{2, 0x0003}
typedef struct {
	nscd_cfg_group_info_t	gi;
	nscd_bool_t		enable_selfcred;
	int			per_user_nscd_ttl;
} nscd_cfg_global_selfcred_t;

/*
 * switch engine param group (global)
 */
#define	NSCD_CFG_GROUP_INFO_GLOBAL_SWITCH	{3, 0x0007}
typedef struct {
	nscd_cfg_group_info_t	gi;
	nscd_bool_t		enable_lookup_g;
	nscd_bool_t		enable_loopback_checking_g;
	int			check_smf_state_interval_g;
} nscd_cfg_global_switch_t;

/*
 * nscd_cfg_param_desc_t should always have nscd_cfg_id_t
 * as its first field. _nscd_cfg_get_desc below provides
 * an way to get to the nscd_cfg_param_desc_t from a
 * pointer to the static nscd_cfg_id_t returned by the
 * various_nscd_cfg_* functions
 */
#define	_nscd_cfg_get_desc_i(id)	((nscd_cfg_param_desc_t *)(id))

#define	_nscd_cfg_get_desc(h)		((h)->desc)

/*
 * The various param group structure should always have
 * nscd_cfg_group_info_t as its first field.
 * _nscd_cfg_get_gi below provides a generic way to
 * get to the nscd_cfg_group_info_t from a void pointer
 * to the various param group structure returned by the
 * _nscd_cfg_* functions
 */
#define	_nscd_cfg_get_gi(voidp)	((nscd_cfg_group_info_t *)(voidp))

/*
 * It is possible in the future, we will need more bits
 * than those in nscd_cfg_flag_t and nscd_cfg_bitmap_t. To
 * make it easier to extend, the following macro should be
 * used to deal with flags and bitmaps.
 * m, m1, m2, ma: mask, n: nth bit (0 based)
 * f: flag, v: value
 */
#define	NSCD_CFG_BITMAP_ZERO			0
#define	_nscd_cfg_bitmap_is_set(m, n)		(((m) >> n) & 1)
#define	_nscd_cfg_bitmap_is_not_set(m, n)	(!(((m) >> n) & 1))
#define	_nscd_cfg_bitmap_is_equal(m1, m2)	((m1) == (m2))
#define	_nscd_cfg_bitmap_value(m)		(m)
#define	_nscd_cfg_bitmap_set_nth(m, n)		((m) |= (1 << n))
#define	_nscd_cfg_bitmap_set(ma, m)		(*(nscd_cfg_bitmap_t *) \
							(ma) = (m))
#define	_nscd_cfg_bitmap_valid(m1, m2)		(((m1) & ~(m2)) == 0)

#define	NSCD_CFG_FLAG_ZERO			0
#define	_nscd_cfg_flag_is_set(f, v)		((f) & (v))
#define	_nscd_cfg_flag_is_not_set(f, v)		(!((f) & (v)))
#define	_nscd_cfg_flag_value(f)			(f)
#define	_nscd_cfg_flag_set(f, v)		((f) | (v))
#define	_nscd_cfg_flag_unset(f, v)		((f) & ~(v))

/*
 * handy macros
 */
#define	NSCD_NULL			"NULL"
#define	NSCD_CFG_MAX_ERR_MSG_LEN	1024
#define	NSCD_STR_OR_NULL(s)		((s) == NULL ? "NULL" : (s))
#define	NSCD_STR_OR_GLOBAL(s)		((s) == NULL ? "GLOBAL" : (s))
#define	NSCD_Y_OR_N(s)			(*(nscd_bool_t *)s == nscd_true ? \
				"yes" : "no")

#define	NSCD_ERR2MSG(e)		(((e) && (e)->msg) ? (e)->msg : "")


/*
 * This macro is based on offsetof defined in stddef_iso.h,
 * it gives the size of 'm' in structure 's' without needing
 * the declaration of a 's' variable (as macro sizeof does)
 */
#define	NSCD_SIZEOF(s, m)		(sizeof (((s *)0)->m))


/*
 * struct nscd_cfg_stat_desc is used to describe each and every
 * one of the nscd statistics counters so that they can be
 * processed generically by the configuration management
 * component. The component does not keep a separate copy of
 * all counters, which should be maintained by other nscd
 * components. The 'get_stat' functions defined in the
 * stat description are supplied by those components and used
 * by the config management component to request and print
 * counters on behave of the users. The free_stat function
 * returned by those components will also be used to free
 * the stat data if the NSCD_CFG_DFLAG_STATIC_DATA bit is
 * not set in dflag.
 */
struct nscd_cfg_stat_desc;
typedef	nscd_rc_t	(*nscd_cfg_func_get_stat_t)(void **,
			struct nscd_cfg_stat_desc *,
			nscd_cfg_id_t *,
			nscd_cfg_flag_t *,
			void (**) (void *),
			nscd_cfg_error_t **);
typedef struct nscd_cfg_stat_desc {
	nscd_cfg_id_t		id;
	nscd_cfg_data_type_t	type;
	nscd_cfg_flag_t		sflag;
	nscd_cfg_group_info_t	gi;
	int	s_size;
	size_t	s_offset;
	int	s_fn;
	int	g_size;
	size_t	g_offset;
	int	g_index;
	nscd_cfg_func_get_stat_t get_stat;
} nscd_cfg_stat_desc_t;

/*
 * stat flag is defined in the stat description. It
 * specifies the nature of the statistics counters.
 */

#define	NSCD_CFG_SFLAG_NONE			   0x0000

/*
 * statistics counter is global, not per nsswitch database
 */
#define	NSCD_CFG_SFLAG_GLOBAL			   0x0001

/*
 * description is for counter group, not individual counter
 */
#define	NSCD_CFG_SFLAG_GROUP			   0x0002

/*
 * The following defines the various global and nsswitch
 * database specific data structures for all the groups of
 * statistics counters. Before each one, there lists
 * the associated group info which contains the number of
 * counters and the corresponding bitmap.
 */

/*
 * switch engine stat group (Per nsswitch database)
 */
#define	NSCD_CFG_STAT_GROUP_INFO_SWITCH		{6, 0x003f}
typedef struct {
	nscd_cfg_group_info_t	gi;
	int			lookup_request_received;
	int			lookup_request_queued;
	int			lookup_request_in_progress;
	int			lookup_request_succeeded;
	int			lookup_request_failed;
	int			loopback_nsw_db_skipped;
} nscd_cfg_stat_switch_t;

/*
 * log/debug stat group (global)
 */
#define	NSCD_CFG_STAT_GROUP_INFO_GLOBAL_LOG	{1, 0x0001}
typedef struct {
	nscd_cfg_group_info_t	gi;
	int			entries_logged;
} nscd_cfg_stat_global_log_t;

/*
 * switch engine stat group (global)
 */
#define	NSCD_CFG_STAT_GROUP_INFO_GLOBAL_SWITCH	{6, 0x003f}
typedef struct {
	nscd_cfg_group_info_t	gi;
	int			lookup_request_received_g;
	int			lookup_request_queued_g;
	int			lookup_request_in_progress_g;
	int			lookup_request_succeeded_g;
	int			lookup_request_failed_g;
	int			loopback_nsw_db_skipped_g;
} nscd_cfg_stat_global_switch_t;

/*
 * control structure for appending string data to a buffer
 */
typedef struct {
	char		*buf;
	char		*next;
	int		size;
	int		used;
	int		left;
	int		real;
} nscd_cfg_buf_t;

/*
 * internal configuration management related functions
 */
nscd_rc_t _nscd_cfg_init();

nscd_rc_t
_nscd_cfg_get_param_desc_list(
	nscd_cfg_param_desc_list_t **list);

nscd_rc_t
_nscd_cfg_get_handle(
	char			*param_name,
	char			*nswdb_name,
	nscd_cfg_handle_t	**handle,
	nscd_cfg_error_t	**errorp);

nscd_cfg_error_t *
_nscd_cfg_make_error(
	nscd_rc_t		rc,
	char			*msg);

void
_nscd_cfg_free_handle(
	nscd_cfg_handle_t	*handle);

void
_nscd_cfg_free_group_data(
	nscd_cfg_handle_t	*handle,
	void			*data);

void
_nscd_cfg_free_param_data(
	void			*data);

void
_nscd_cfg_free_error(
	nscd_cfg_error_t	*error);

nscd_rc_t
_nscd_cfg_get(
	nscd_cfg_handle_t	*handle,
	void			**data,
	int			*data_len,
	nscd_cfg_error_t	**errorp);

nscd_rc_t
_nscd_cfg_set(
	nscd_cfg_handle_t	*handle,
	void			*data,
	nscd_cfg_error_t	**errorp);

nscd_rc_t
_nscd_cfg_str_to_data(
	nscd_cfg_param_desc_t	*desc,
	char			*str,
	void			*data,
	void			**data_p,
	nscd_cfg_error_t	**errorp);

nscd_rc_t
_nscd_cfg_prelim_check(
	nscd_cfg_param_desc_t	*desc,
	void			*data,
	nscd_cfg_error_t	**errorp);

nscd_rc_t
_nscd_cfg_read_file(
	char			*filename,
	nscd_cfg_error_t	**errorp);

nscd_rc_t
_nscd_cfg_set_linked(
	nscd_cfg_handle_t	*handle,
	void			*data,
	nscd_cfg_error_t	**errorp);

char *
_nscd_srcs_in_db_nsw_policy(
	int			num_src,
	char			**srcs);

nscd_rc_t
_nscd_cfg_read_nsswitch_file(
	char			*filename,
	nscd_cfg_error_t	**errorp);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_CONFIG_H */
