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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_POOL_INTERNAL_H
#define	_POOL_INTERNAL_H

#include <libnvpair.h>
#include <stdarg.h>
#include <sys/pool.h>
#include <sys/pool_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains the libpool internal definitions which are not
 * directly related to the data access abstraction logic.
 */

/*
 * Define the various query specifiers for use in the
 * pool_connection_t query function, pc_exec_query.
 */

#define	PEC_QRY_ANY		(PEC_QRY_SYSTEM | PEC_QRY_POOL | PEC_QRY_RES | \
				    PEC_QRY_COMP)
#define	PEC_QRY_SYSTEM		(1 << PEC_SYSTEM)
#define	PEC_QRY_POOL		(1 << PEC_POOL)
#define	PEC_QRY_RES		(PEC_QRY_RES_COMP | PEC_QRY_RES_AGG)
#define	PEC_QRY_RES_COMP	(1 << PEC_RES_COMP)
#define	PEC_QRY_RES_AGG		(1 << PEC_RES_AGG)
#define	PEC_QRY_COMP		(1 << PEC_COMP)
#define	PEC_QRY_ELEM(e)		(1 << pool_elem_class(e))

/*
 * Internal type conversion macros
 */
#define	TO_ELEM(s)		((pool_elem_t *)s)
/*
 * Get the configuration to which the supplied element belongs.
 */
#define	TO_CONF(s)		(s->pe_conf)

/*
 * Known Data Store Types
 */

#define	XML_DATA_STORE	0
#define	KERNEL_DATA_STORE	1

/*
 * Limits on pool values names and strings
 */
#define	PV_NAME_MAX_LEN		1024
#define	PV_VALUE_MAX_LEN	1024

/*
 * CB_TAB_BUF_SIZE represents the maximum number of indents to which a
 * char_buf_t is expected to grow. This value would need to be raised
 * if it was ever exceeded. It is an arbitrary limit, but currently
 * the implementation does not exceed a depth of 4.
 */

#define	CB_TAB_BUF_SIZE	8
#define	CB_DEFAULT_LEN	256

/*
 * Helpful pset macros
 */
#define	PSID_IS_SYSSET(psid)	(psid == PS_NONE)
#define	POOL_SYSID_BAD		(-2)
#define	POOL_SYSID_BAD_STRING	"-2"

/*
 * Size of generated ref_id buffer
 */

#define	KEY_BUFFER_SIZE	48

/*
 * Various useful constant strings which are often encountered
 */
extern const char *c_a_dtype;
extern const char *c_name;
extern const char *c_type;
extern const char *c_ref_id;
extern const char *c_max_prop;
extern const char *c_min_prop;
extern const char *c_size_prop;
extern const char *c_sys_prop;

/*
 * The char_buf_t type is a very simple string implementation which
 * makes it easier to manipulate complex character data.
 */
typedef struct char_buf
{
	size_t cb_size;
	char *cb_buf;
	char cb_tab_buf[CB_TAB_BUF_SIZE];
} char_buf_t;

/*
 * libpool uses an opaque discriminated union type, pool_value_t, to
 * contain values which are used to get/set properties on
 * configuration components. Each value is strictly typed and the
 * functions to manipulate these types are exported through the
 * external interface.
 */

/*
 * Initialize a pool_value_t
 */
#define	POOL_VALUE_INITIALIZER	/* = DEFAULT POOL VALUE */	\
	{POC_INVAL, NULL, 0 }

struct pool_value {
	pool_value_class_t	pv_class;		/* Value type */
	const char		*pv_name;		/* Value name */
	union
	{
		uint64_t	u;
		int64_t		i;
		double		d;
		uchar_t		b;
		const char	*s;
	} pv_u;
};

/*
 * The pool_prop_op_t structure is used to perform property specific validation
 * when setting the values of properties in a plugin and when getting a property
 * value which is not stored (i.e. it is generated dynamically by the plugin at
 * access.
 *
 * - ppo_get_value will provide a value for the specified property
 * - ppo_set_value will allow a provider to validate a value before setting it
 */
typedef struct pool_prop_op {
	int	(*ppo_get_value)(const pool_elem_t *, pool_value_t *);
	int	(*ppo_set_value)(pool_elem_t *, const pool_value_t *);
} pool_prop_op_t;

/*
 * The pool_prop_t structure is used to hold all property related information
 * for each property that a provider is interested in.
 *
 * - pp_pname is the name of the property
 * - pp_value is the initial value of the property
 * - pp_perms is an OR'd bitmap of the access characteristics for the property
 * - pp_init is a function which initialises the value member of the property
 * - pp_op is optional and supports access and validation of property values
 */
typedef struct pool_prop {
	const char	*pp_pname;
	pool_value_t	pp_value;
	uint_t		pp_perms;
	int		(*pp_init)(struct pool_prop *);
	pool_prop_op_t	pp_op;
} pool_prop_t;

/*
 * log state
 */
enum log_state {
	LS_DO,
	LS_UNDO,
	LS_RECOVER,
	LS_FAIL
};

/*
 * Forward declaration
 */
typedef struct log log_t;

/*
 * log item.
 *
 * Used to describe each operation which needs to be logged. When
 * modifications are desired to the kernel, they are logged in the
 * configuration log file. If the user commits the changes, then the
 * log entries are processed in sequence. If rollback is called, the
 * log is dismissed without being processed. If the commit operation
 * fails, then the log is "rolled back" to undo the previously
 * successful operations.
 */
typedef struct log_item {
	log_t *li_log;				/* Log containing this item */
	int li_op;				/* Type of operation */
	void *li_details;			/* Operation details */
	struct log_item *li_next;		/* List of log items */
	struct log_item *li_prev;		/* List of log items */
	enum log_state li_state;		/* Item state */
} log_item_t;

/*
 * log.
 *
 * This maintains a list of log items. The sentinel is used to
 * simplify processing around the "empty list". The state of the log
 * indicates whether transactions are being processed normally, or
 * whether recovery is in progress.
 */
struct log
{
	pool_conf_t *l_conf;			/* Configuration for this log */
	log_item_t *l_sentinel;			/* Log sentinel */
	enum log_state l_state;			/* Log state */
};


/*
 * log item action function type
 */
typedef int (*log_item_action_t)(log_item_t *);

/*
 * Get the max/min/size property value of a resource.
 */
extern int		resource_get_max(const pool_resource_t *, uint64_t *);
extern int		resource_get_min(const pool_resource_t *, uint64_t *);
extern int		resource_get_size(const pool_resource_t *, uint64_t *);
extern int		resource_get_pinned(const pool_resource_t *,
			    uint64_t *);

/*
 * Element utility operations.
 */
extern char		*elem_get_name(const pool_elem_t *);
extern id_t		elem_get_sysid(const pool_elem_t *);
extern int		elem_is_default(const pool_elem_t *);
extern boolean_t	elem_is_tmp(const pool_elem_t *);
extern const pool_elem_t *get_default_elem(const pool_elem_t *);
extern int		qsort_elem_compare(const void *, const void *);

/*
 * Get the class of the supplied element.
 */
extern const char	*pool_elem_class_string(const pool_elem_t *);
extern const char	*pool_resource_type_string(pool_resource_elem_class_t);
extern const char *pool_component_type_string(pool_component_elem_class_t);

/*
 * Commit the supplied configuration to the system. This function
 * attempts to make the system look like the supplied configuration.
 */
extern int		pool_conf_commit_sys(pool_conf_t *, int);

/*
 * Allocate an XML/kernel connection to a data representation.
 */
extern int		pool_xml_connection_alloc(pool_conf_t *, int);
extern int		pool_knl_connection_alloc(pool_conf_t *, int);

/*
 * Create/Destroy a pool component belonging to the supplied resource
 */
extern pool_component_t *pool_component_create(pool_conf_t *,
    const pool_resource_t *, int64_t);
extern int		pool_component_destroy(pool_component_t *);

/*
 * Get/Set the owner (container) of a particular configuration
 * element.
 */
extern pool_elem_t	*pool_get_container(const pool_elem_t *);
extern int		pool_set_container(pool_elem_t *, pool_elem_t *);

/*
 * These functions are used for debugging. Setting the environment
 * variable LIBPOOL_DEBUG to 1, enables these functions.
 */
extern void		do_dprintf(const char *, va_list);
extern void		pool_dprintf(const char *, ...);

/*
 * libpool maintains it's own error value, rather than further pollute
 * errno, this function is used to set the current error value for
 * retrieval.
 */
extern void		pool_seterror(int);

/*
 * Element Class
 */
extern pool_elem_class_t pool_elem_class(const pool_elem_t *);
extern pool_resource_elem_class_t pool_resource_elem_class(const pool_elem_t *);
extern pool_component_elem_class_t pool_component_elem_class(const
    pool_elem_t *);
extern int pool_elem_same_class(const pool_elem_t *, const pool_elem_t *);
extern pool_elem_class_t pool_elem_class_from_string(const char *);
extern pool_resource_elem_class_t pool_resource_elem_class_from_string(const
    char *);
extern pool_component_elem_class_t pool_component_elem_class_from_string(const
    char *);

/*
 * Element Equivalency
 */
extern int		pool_elem_compare(const pool_elem_t *,
    const pool_elem_t *);
extern int		pool_elem_compare_name(const pool_elem_t *,
    const pool_elem_t *);

/*
 * Dynamic character buffers. Limited functionality but enough for our
 * purposes.
 */
extern char_buf_t	*alloc_char_buf(size_t);
extern void		free_char_buf(char_buf_t *);
extern int		set_char_buf(char_buf_t *, const char *, ...);
extern int		append_char_buf(char_buf_t *, const char *, ...);

/*
 * Internal functions for use with pool values.
 */
extern int		pool_value_equal(pool_value_t *, pool_value_t *);
extern int		pool_value_from_nvpair(pool_value_t *, nvpair_t *);

/*
 * Check to ensure that the supplied string is a valid name for a pool
 * element.
 */
extern int		is_valid_name(const char *);

/*
 * Functions related to element prefix manipulation. You can get the
 * prefix for a supplied element or find out if a supplied string is a
 * valid prefix for a certain class of element.
 */
extern const char	*elem_get_prefix(const pool_elem_t *);
extern const char	*is_a_known_prefix(pool_elem_class_t, const char *);

/*
 * Internal property manipulators
 */
extern int		pool_put_ns_property(pool_elem_t *, const char *,
    const pool_value_t *);
extern int		pool_put_any_property(pool_elem_t *, const char *,
    const pool_value_t *);
extern int		pool_put_any_ns_property(pool_elem_t *, const char *,
    const pool_value_t *);
extern pool_value_class_t pool_get_ns_property(const pool_elem_t *,
    const char *, pool_value_t *);
extern int		pool_walk_any_properties(pool_conf_t *, pool_elem_t *,
    void *, int (*)(pool_conf_t *, pool_elem_t *, const char *,
    pool_value_t *, void *), int);
extern int		pool_set_temporary(pool_conf_t *, pool_elem_t *);

/*
 * Namespace aware utility functions.
 */
extern const char	*is_ns_property(const pool_elem_t *, const char *);
extern const char	*property_name_minus_ns(const pool_elem_t *,
    const char *);

/*
 * Initialisation routines.
 */
extern void		internal_init(void);

/*
 * Is the supplied configuration the dynamic configuration?
 */
extern int		conf_is_dynamic(const pool_conf_t *);

/*
 * Update the library snapshot from the kernel
 */
extern int		pool_knl_update(pool_conf_t *, int *);

/*
 * Resource property functions
 */
extern int		resource_is_default(const pool_resource_t *);
extern int		resource_is_system(const pool_resource_t *);
extern int		resource_can_associate(const pool_resource_t *);
extern const pool_resource_t	*get_default_resource(const pool_resource_t *);
extern pool_resource_t	*resource_by_sysid(const pool_conf_t *, id_t,
    const char *);

/*
 * Resource property provider functions
 */
extern uint_t		pool_get_provider_count(void);
extern const pool_prop_t *provider_get_props(const pool_elem_t *);
extern const pool_prop_t *provider_get_prop(const pool_elem_t *,
    const char *);
extern int		prop_is_stored(const pool_prop_t *);
extern int		prop_is_readonly(const pool_prop_t *);
extern int		prop_is_init(const pool_prop_t *);
extern int		prop_is_hidden(const pool_prop_t *);
extern int		prop_is_optional(const pool_prop_t *);

/*
 * Component property functions
 */
extern int		cpu_is_requested(pool_component_t *);

/*
 * Simple initialisation routines for values used when initialising the
 * property arrays for each plugin
 * Return PO_SUCCESS/PO_FAIL to indicate success/failure
 */
extern int		uint_init(pool_prop_t *, uint64_t);
extern int		int_init(pool_prop_t *, int64_t);
extern int		double_init(pool_prop_t *, double);
extern int		bool_init(pool_prop_t *, uchar_t);
extern int		string_init(pool_prop_t *, const char *);


/*
 * log functions
 */
extern log_t		*log_alloc(pool_conf_t *);
extern void		log_free(log_t *);
extern void		log_empty(log_t *);
extern int		log_walk(log_t *, log_item_action_t);
extern int		log_reverse_walk(log_t *, log_item_action_t);
extern uint_t		log_size(log_t *);
extern int		log_append(log_t *, int, void *);

/*
 * log item functions
 */
extern log_item_t	*log_item_alloc(log_t *, int, void *);
extern int		log_item_free(log_item_t *);

extern int		pool_validate_resource(const pool_conf_t *,
    const char *, const char *, int64_t);

/*
 * String atom functions
 */
extern const char	*atom_string(const char *);
extern void		atom_free(const char *);
/*
 * debugging functions
 */
#ifdef DEBUG
extern void		log_item_dprintf(log_item_t *);
extern void		pool_value_dprintf(const pool_value_t *);
extern void		pool_elem_dprintf(const pool_elem_t *);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _POOL_INTERNAL_H */
