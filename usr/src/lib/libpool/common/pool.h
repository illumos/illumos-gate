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

/*
 *  NOTE
 *
 *  The following contents of this file are private to the
 *  implementation of the Solaris system and are subject to change at
 *  any time without notice.  Applications using these interfaces may
 *  fail to run on future releases.
 */

#ifndef	_POOL_H
#define	_POOL_H

#include <sys/procset.h>
#include <sys/types.h>
#include <sys/pool.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Library versioning support (c.f. elf_version(3elf)).
 *
 * You can enquire about the version number of the library
 * by passing POOL_VER_NONE.  POOL_VER_CURRENT is the current
 * (most capable) version.
 *
 * You can set the version used by the library by passing the
 * required version number.  If this is not possible, the version
 * returned will be POOL_VER_NONE.
 */
#define	POOL_VER_CURRENT	1
#define	POOL_VER_NONE		0

extern uint_t pool_version(uint_t ver);

#ifndef PO_TRUE
#define	PO_TRUE	1
#endif

#ifndef PO_FALSE
#define	PO_FALSE	0
#endif

#ifndef PO_SUCCESS
#define	PO_SUCCESS	0
#endif

#ifndef PO_FAIL
#define	PO_FAIL	-1
#endif

/* Error codes */
#define	POE_OK			0
#define	POE_BAD_PROP_TYPE	1
#define	POE_INVALID_CONF	2
#define	POE_NOTSUP		3
#define	POE_INVALID_SEARCH    	4
#define	POE_BADPARAM    	5
#define	POE_PUTPROP    		6
#define	POE_DATASTORE		7
#define	POE_SYSTEM		8
#define	POE_ACCESS		9

/* Open Flags */
#define	PO_RDONLY		0x0
#define	PO_RDWR			0x1
#define	PO_CREAT		0x2
#define	PO_DISCO		0x4
#define	PO_UPDATE		0x8
#define	PO_TEMP			0x10

/* Allocation policy */
#define	POA_IMPORTANCE		"importance based"
#define	POA_SURPLUS_TO_DEFAULT	"surplus to default"

/* Pools updates */
#define	POU_SYSTEM		0x1
#define	POU_POOL		0x2
#define	POU_PSET		0x4
#define	POU_CPU			0x8

/* Data Export Formats */
typedef enum pool_export_format {
	POX_NATIVE,		/* Native data representation format */
	POX_TEXT		/* Text */
} pool_export_format_t;

/* Property data types */
typedef enum pool_value_class {
	POC_INVAL = -1,
	POC_UINT,
	POC_INT,
	POC_DOUBLE,
	POC_BOOL,
	POC_STRING
} pool_value_class_t;

/* Validation levels */
typedef enum pool_valid_level {
	POV_NONE = 0,		/* No validation */
	POV_LOOSE,		/* Loose validation */
	POV_STRICT,		/* Strict validation */
	POV_RUNTIME		/* Validate instantiation on current machine */
} pool_valid_level_t;

/* conf states */
typedef enum pool_conf_state {
	POF_INVALID = -1,
	POF_VALID,
	POF_DESTROY
} pool_conf_state_t;

/* Element data values */
typedef struct pool_value pool_value_t;

/* Elements */
typedef struct pool_elem pool_elem_t;
typedef struct pool pool_t;
typedef struct pool_resource pool_resource_t;
typedef struct pool_component pool_component_t;

/*
 * Resource management configuration
 */
typedef struct pool_conf pool_conf_t;

extern int		pool_error(void);
extern const char	*pool_strerror(int);
extern int		pool_resource_type_list(const char **, uint_t *);
extern int		pool_get_status(int *);
extern int		pool_set_status(int);

/* Configuration manipulation */
extern pool_conf_t *pool_conf_alloc(void);
extern void pool_conf_free(pool_conf_t *);
extern pool_conf_state_t pool_conf_status(const pool_conf_t *);

extern int pool_conf_close(pool_conf_t *);
extern int pool_conf_remove(pool_conf_t *);
extern int pool_conf_open(pool_conf_t *, const char *, int);
extern int pool_conf_rollback(pool_conf_t *);
extern int pool_conf_commit(pool_conf_t *, int);
extern int pool_conf_export(const pool_conf_t *, const char *,
    pool_export_format_t);
extern int pool_conf_validate(const pool_conf_t *, pool_valid_level_t);
extern int pool_conf_update(const pool_conf_t *, int *);
extern pool_t *pool_get_pool(const pool_conf_t *, const char *);
extern pool_t **pool_query_pools(const pool_conf_t *, uint_t *,
    pool_value_t **);
extern pool_resource_t *pool_get_resource(const pool_conf_t *, const char *,
    const char *);
extern pool_resource_t **pool_query_resources(const pool_conf_t *, uint_t *,
    pool_value_t **);
extern pool_component_t **pool_query_components(const pool_conf_t *, uint_t *,
    pool_value_t **);
extern const char *pool_conf_location(const pool_conf_t *);
extern char *pool_conf_info(const pool_conf_t *, int);

/* Resource manipulation */
extern pool_resource_t *pool_resource_create(pool_conf_t *, const char *,
    const char *);
extern int pool_resource_destroy(pool_conf_t *, pool_resource_t *);
extern int pool_resource_transfer(pool_conf_t *, pool_resource_t *,
    pool_resource_t *, uint64_t);
extern int pool_resource_xtransfer(pool_conf_t *, pool_resource_t *,
    pool_resource_t *, pool_component_t **);
extern pool_component_t **pool_query_resource_components(const pool_conf_t *,
    const pool_resource_t *, uint_t *, pool_value_t **);
extern char *pool_resource_info(const pool_conf_t *, const pool_resource_t *,
    int);

/* Pool manipulation */
extern pool_t *pool_create(pool_conf_t *, const char *);
extern int pool_destroy(pool_conf_t *, pool_t *);
extern int pool_associate(pool_conf_t *, pool_t *, const pool_resource_t *);
extern int pool_dissociate(pool_conf_t *, pool_t *, const pool_resource_t *);
extern char *pool_info(const pool_conf_t *, const pool_t *, int);
extern pool_resource_t **pool_query_pool_resources(const pool_conf_t *,
    const pool_t *, uint_t *, pool_value_t **);

/* Resource Component Manipulation */
extern pool_resource_t *pool_get_owning_resource(const pool_conf_t *,
    const pool_component_t *);
extern char *pool_component_info(const pool_conf_t *, const pool_component_t *,
    int);

/* Property manipulation */
extern pool_value_class_t pool_get_property(const pool_conf_t *,
    const pool_elem_t *, const char *, pool_value_t *);
extern int pool_put_property(pool_conf_t *, pool_elem_t *, const char *,
    const pool_value_t *);
extern int pool_rm_property(pool_conf_t *, pool_elem_t *, const char *);

/*
 * Walk the associated properties of the supplied element calling the supplied
 * function for each property in turn. There is no implied order in the walk.
 * The arg parameter allows caller-specific data to be passed to the call.
 */
extern int pool_walk_properties(pool_conf_t *, pool_elem_t *, void *,
    int (*)(pool_conf_t *, pool_elem_t *, const char *, pool_value_t *,
	    void *));

/* Get the underlying element */
extern pool_elem_t *pool_conf_to_elem(const pool_conf_t *);
extern pool_elem_t *pool_to_elem(const pool_conf_t *, const pool_t *);
extern pool_elem_t *pool_resource_to_elem(const pool_conf_t *,
    const pool_resource_t *);
extern pool_elem_t *pool_component_to_elem(const pool_conf_t *,
    const pool_component_t *);

/* Pool Property Value Manipulation */
/* Get/Set Pool Property Values and Type */
extern int pool_value_get_uint64(const pool_value_t *, uint64_t *);
extern int pool_value_get_int64(const pool_value_t *, int64_t *);
extern int pool_value_get_double(const pool_value_t *, double *);
extern int pool_value_get_bool(const pool_value_t *, uchar_t *);
extern int pool_value_get_string(const pool_value_t *, const char **);
extern pool_value_class_t pool_value_get_type(const pool_value_t *);
extern void pool_value_set_uint64(pool_value_t *, uint64_t);
extern void pool_value_set_int64(pool_value_t *, int64_t);
extern void pool_value_set_double(pool_value_t *, double);
extern void pool_value_set_bool(pool_value_t *, uchar_t);
extern int pool_value_set_string(pool_value_t *, const char *);
extern const char *pool_value_get_name(const pool_value_t *);
extern int pool_value_set_name(pool_value_t *, const char *);

/* Pool Property Value Creation/Destruction */
extern pool_value_t *pool_value_alloc(void);
extern void pool_value_free(pool_value_t *);

/* Default pool data store locations */
extern const char *pool_static_location(void);
extern const char *pool_dynamic_location(void);

/* Binding */
extern int pool_set_binding(const char *, idtype_t, id_t);
extern char *pool_get_binding(pid_t);
extern char *pool_get_resource_binding(const char *, pid_t);

/* Walking */
extern int pool_walk_pools(pool_conf_t *, void *,
    int (*)(pool_conf_t *, pool_t *, void *));
extern int pool_walk_resources(pool_conf_t *, pool_t *, void *,
    int (*)(pool_conf_t *, pool_resource_t *, void *));
extern int pool_walk_components(pool_conf_t *, pool_resource_t *, void *,
    int (*)(pool_conf_t *, pool_component_t *, void *));

#ifdef	__cplusplus
}
#endif

#endif	/* _POOL_H */
