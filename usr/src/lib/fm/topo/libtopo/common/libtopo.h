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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2018, Joyent, Inc. All rights reserved.
 */

#ifndef _LIBTOPO_H
#define	_LIBTOPO_H

#include <sys/nvpair.h>
#include <stdio.h>
#include <libdevinfo.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	TOPO_VERSION	1	/* Library ABI Interface Version */

typedef struct topo_hdl topo_hdl_t;
typedef struct topo_node tnode_t;
typedef struct topo_walk topo_walk_t;
typedef int32_t topo_instance_t;
typedef uint32_t topo_version_t;

typedef struct topo_list {
	struct topo_list *l_prev;
	struct topo_list *l_next;
} topo_list_t;

typedef struct topo_faclist {
	topo_list_t	tf_list;
	tnode_t		*tf_node;
} topo_faclist_t;

/*
 * The following functions, error codes and data structures are private
 * to libtopo snapshot consumers and enumerator modules.
 */
extern topo_hdl_t *topo_open(int, const char *, int *);
extern void topo_close(topo_hdl_t *);
extern char *topo_snap_hold(topo_hdl_t *, const char *, int *);
extern void topo_snap_release(topo_hdl_t *);

/*
 * Snapshot walker support
 */
typedef int (*topo_walk_cb_t)(topo_hdl_t *, tnode_t *, void *);

extern topo_walk_t *topo_walk_init(topo_hdl_t *, const char *, topo_walk_cb_t,
    void *, int *);
extern int topo_walk_step(topo_walk_t *, int);
extern void topo_walk_fini(topo_walk_t *);
extern di_node_t topo_hdl_devinfo(topo_hdl_t *);
extern di_prom_handle_t topo_hdl_prominfo(topo_hdl_t *);

/*
 * Walk status returned from walker
 */
#define	TOPO_WALK_ERR		-1
#define	TOPO_WALK_NEXT		0
#define	TOPO_WALK_TERMINATE	1

/*
 * Types of walks: depth-first (child) or breadth-first (sibling)
 */
#define	TOPO_WALK_CHILD		0x0001
#define	TOPO_WALK_SIBLING	0x0002

/*
 * FMRI helper routines
 */
extern int topo_fmri_present(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_replaced(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_contains(topo_hdl_t *, nvlist_t *, nvlist_t *, int *);
extern int topo_fmri_expand(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_unusable(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_service_state(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_retire(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_unretire(topo_hdl_t *, nvlist_t *, int *);
extern int topo_fmri_nvl2str(topo_hdl_t *, nvlist_t *, char **, int *);
extern int topo_fmri_str2nvl(topo_hdl_t *, const char *, nvlist_t **, int *);
extern int topo_fmri_asru(topo_hdl_t *, nvlist_t *, nvlist_t **, int *);
extern int topo_fmri_fru(topo_hdl_t *, nvlist_t *, nvlist_t **,
    int *);
extern int topo_fmri_label(topo_hdl_t *, nvlist_t *, char **, int *);
extern int topo_fmri_serial(topo_hdl_t *, nvlist_t *, char **, int *);
extern int topo_fmri_compare(topo_hdl_t *, nvlist_t *, nvlist_t *, int *);
extern int topo_fmri_facility(topo_hdl_t *, nvlist_t *, const char *,
    uint32_t, topo_walk_cb_t, void *, int *);

/*
 * Consolidation private utility functions
 */
extern ulong_t topo_fmri_strhash(topo_hdl_t *, const char *);
extern ulong_t topo_fmri_strhash_noauth(topo_hdl_t *, const char *);
extern boolean_t topo_fmri_strcmp(topo_hdl_t *, const char *, const char *);
extern boolean_t topo_fmri_strcmp_noauth(topo_hdl_t *, const char *,
    const char *);

/*
 * Topo node utilities: callable from topo_walk_step() callback or module
 * enumeration, topo_mod_enumerate()
 */
extern char *topo_node_name(tnode_t *);
extern topo_instance_t topo_node_instance(tnode_t *);
extern tnode_t *topo_node_parent(tnode_t *);
extern void *topo_node_private(tnode_t *);
extern int topo_node_flags(tnode_t *);
extern int topo_node_asru(tnode_t *, nvlist_t **, nvlist_t *, int *);
extern int topo_node_fru(tnode_t *, nvlist_t **, nvlist_t *, int *);
extern int topo_node_resource(tnode_t *, nvlist_t **, int *);
extern int topo_node_label(tnode_t *, char **, int *);
extern tnode_t *topo_node_lookup(tnode_t *, const char *, topo_instance_t);
extern int topo_method_invoke(tnode_t *node, const char *, topo_version_t,
    nvlist_t *, nvlist_t **, int *);
extern boolean_t topo_method_supported(tnode_t *, const char *,
    topo_version_t);
extern int topo_node_facility(topo_hdl_t *, tnode_t *, const char *,
    uint32_t, topo_faclist_t *, int *);
extern int topo_node_child_walk(topo_hdl_t *, tnode_t *, topo_walk_cb_t,
    void *, int *);

/*
 * Node flags: denotes type of node
 */
#define	TOPO_NODE_DEFAULT	0
#define	TOPO_NODE_FACILITY	1

#define	TOPO_FAC_TYPE_SENSOR	"sensor"
#define	TOPO_FAC_TYPE_INDICATOR	"indicator"

/*
 * Topo property get functions
 */
extern int topo_prop_get_int32(tnode_t *, const char *, const char *,
    int32_t *, int *);
extern int topo_prop_get_uint32(tnode_t *, const char *, const char *,
    uint32_t *, int *);
extern int topo_prop_get_int64(tnode_t *, const char *, const char *,
    int64_t *, int *);
extern int topo_prop_get_uint64(tnode_t *, const char *, const char *,
    uint64_t *, int *);
extern int topo_prop_get_double(tnode_t *, const char *, const char *,
    double *, int *);
extern int topo_prop_get_string(tnode_t *, const char *, const char *,
    char **, int *);
extern int topo_prop_get_fmri(tnode_t *, const char *, const char *,
    nvlist_t **, int *);
extern int topo_prop_get_int32_array(tnode_t *, const char *, const char *,
    int32_t **, uint_t *, int *);
extern int topo_prop_get_uint32_array(tnode_t *, const char *, const char *,
    uint32_t **, uint_t *, int *);
extern int topo_prop_get_int64_array(tnode_t *, const char *, const char *,
    int64_t **, uint_t *, int *);
extern int topo_prop_get_uint64_array(tnode_t *, const char *, const char *,
    uint64_t **, uint_t *, int *);
extern int topo_prop_get_string_array(tnode_t *, const char *, const char *,
    char ***, uint_t *, int *);
extern int topo_prop_get_fmri_array(tnode_t *, const char *, const char *,
    nvlist_t ***, uint_t *, int *);

/*
 * Topo property set functions
 */
extern int topo_prop_set_int32(tnode_t *, const char *, const char *, int,
    int32_t, int *);
extern int topo_prop_set_uint32(tnode_t *, const char *, const char *, int,
    uint32_t, int *);
extern int topo_prop_set_int64(tnode_t *, const char *, const char *,
    int, int64_t, int *);
extern int topo_prop_set_uint64(tnode_t *, const char *, const char *,
    int, uint64_t, int *);
extern int topo_prop_set_double(tnode_t *, const char *, const char *,
    int, double, int *);
extern int topo_prop_set_string(tnode_t *, const char *, const char *,
    int, const char *, int *);
extern int topo_prop_set_fmri(tnode_t *, const char *, const char *,
    int, const nvlist_t *, int *);
extern int topo_prop_set_int32_array(tnode_t *, const char *, const char *, int,
    int32_t *, uint_t, int *);
extern int topo_prop_set_uint32_array(tnode_t *, const char *, const char *,
    int, uint32_t *, uint_t, int *);
extern int topo_prop_set_int64_array(tnode_t *, const char *, const char *,
    int, int64_t *, uint_t, int *);
extern int topo_prop_set_uint64_array(tnode_t *, const char *, const char *,
    int, uint64_t *, uint_t, int *);
extern int topo_prop_set_string_array(tnode_t *, const char *, const char *,
    int, const char **, uint_t, int *);
extern int topo_prop_set_fmri_array(tnode_t *, const char *, const char *,
    int, const nvlist_t **, uint_t, int *);

#define	TOPO_PROP_IMMUTABLE	0
#define	TOPO_PROP_MUTABLE	0x01
#define	TOPO_PROP_NONVOLATILE	0x02

/* Protocol property group and property names */
#define	TOPO_PGROUP_PROTOCOL	"protocol"	/* Required property group */
#define	TOPO_PROP_RESOURCE	"resource"	/* resource FMRI */
#define	TOPO_PROP_ASRU		"ASRU"		/* ASRU FMRI */
#define	TOPO_PROP_FRU		"FRU"		/* FRU FMRI */
#define	TOPO_PROP_MOD		"module"	/* software module FMRI */
#define	TOPO_PROP_PKG		"package"	/* software package FMRI */
#define	TOPO_PROP_LABEL		"label"		/*  property LABEL */

#define	TOPO_METH_FAC_ENUM	"fac_enum"

/*
 * System property group
 */
#define	TOPO_PGROUP_SYSTEM	"system"
#define	TOPO_PROP_ISA		"isa"
#define	TOPO_PROP_MACHINE	"machine"

#define	TOPO_PGROUP_IPMI	"ipmi"

/*
 * These enum definitions are used to define a set of error tags associated with
 * libtopo error conditions occuring during the adminstration of
 * properties, invocation of methods and fmri-based queries.  The shell script
 * mkerror.sh is used to parse this file and create a corresponding topo_error.c
 * source file.
 *
 * If you do something other than add a new error tag here, you may need to
 * update the mkerror shell script as it is based upon simple regexps.
 */
typedef enum topo_prop_errno {
    ETOPO_PROP_UNKNOWN = 3000, /* unknown topo prop error */
    ETOPO_PROP_NOENT,   /* undefined property or property group */
    ETOPO_PROP_DEFD,    /* static property already defined */
    ETOPO_PROP_NOMEM,   /* memory limit exceeded during property allocation */
    ETOPO_PROP_TYPE,    /* invalid property type */
    ETOPO_PROP_NAME,    /* invalid property name */
    ETOPO_PROP_NOINHERIT, /* can not inherit property */
    ETOPO_PROP_NVL,	/* malformed property nvlist */
    ETOPO_PROP_METHOD,	/* get property method failed */
    ETOPO_PROP_END	/* end of prop errno list (to ease auto-merge) */
} topo_prop_errno_t;

typedef enum topo_method_errno {
    ETOPO_METHOD_UNKNOWN = 3100, /* unknown topo method error */
    ETOPO_METHOD_INVAL,		/* invalid method registration */
    ETOPO_METHOD_NOTSUP,	/* method not supported */
    ETOPO_METHOD_FAIL,		/* method failed */
    ETOPO_METHOD_VEROLD,	/* app is compiled to use obsolete method */
    ETOPO_METHOD_VERNEW,	/* app is compiled to use obsolete method */
    ETOPO_METHOD_NOMEM,		/* memory limit exceeded during method op */
    ETOPO_METHOD_DEFD,		/* method op already defined */
    ETOPO_METHOD_END		/* end of method errno list */
} topo_method_errno_t;

typedef enum topo_fmri_errno {
    ETOPO_FMRI_UNKNOWN = 3200, /* unknown topo fmri error */
    ETOPO_FMRI_NVL,		/* nvlist allocation failure for FMRI */
    ETOPO_FMRI_VERSION,		/* invalid FMRI scheme version */
    ETOPO_FMRI_MALFORM,		/* malformed FMRI */
    ETOPO_FMRI_NOMEM,		/* memory limit exceeded */
    ETOPO_FMRI_END		/* end of fmri errno list */
} topo_fmri_errno_t;

typedef enum topo_hdl_errno {
    ETOPO_HDL_UNKNOWN = 3300,	/* unknown topo handle error */
    ETOPO_HDL_ABIVER,		/* handle opened with invalid ABI version */
    ETOPO_HDL_SNAP,		/* snapshot already taken */
    ETOPO_HDL_INVAL,		/* invalid argument specified */
    ETOPO_HDL_UUID,		/* uuid already set */
    ETOPO_HDL_NOMEM,		/* memory limit exceeded */
    ETOPO_HDL_END		/* end of handle errno list */
} topo_hdl_errno_t;

extern const char *topo_strerror(int);
extern void topo_hdl_strfree(topo_hdl_t *, char *);
extern void topo_debug_set(topo_hdl_t *, const char *, const char *);

/*
 * The following functions and data structures to support property
 * observability are private to the fmtopo command.
 */

/*
 * Each topology node advertises the name and data stability of each of its
 * modules and properties. (see attributes(5)).
 */

/*
 * Topo stability attributes
 */
typedef enum topo_stability {
	TOPO_STABILITY_UNKNOWN = 0,	/* private to libtopo */
	TOPO_STABILITY_INTERNAL,	/* private to libtopo */
	TOPO_STABILITY_PRIVATE,		/* private to Sun */
	TOPO_STABILITY_OBSOLETE,	/* scheduled for removal */
	TOPO_STABILITY_EXTERNAL,	/* not controlled by Sun */
	TOPO_STABILITY_UNSTABLE,	/* new or rapidly changing */
	TOPO_STABILITY_EVOLVING,	/* less rapidly changing */
	TOPO_STABILITY_STABLE,		/* mature interface from Sun */
	TOPO_STABILITY_STANDARD		/* industry standard */
} topo_stability_t;

#define	TOPO_STABILITY_MAX	TOPO_STABILITY_STANDARD	/* max valid stab */

typedef struct topo_pgroup_info {
	const char *tpi_name;		/* property group name */
	topo_stability_t tpi_namestab;	/* stability of group name */
	topo_stability_t tpi_datastab;	/* stability of all property values */
	topo_version_t tpi_version;	/* version of pgroup definition */
} topo_pgroup_info_t;

extern topo_stability_t topo_name2stability(const char *);
extern const char *topo_stability2name(topo_stability_t);
extern void topo_pgroup_destroy(tnode_t *, const char *);
extern topo_pgroup_info_t *topo_pgroup_info(tnode_t *, const char *, int *);

typedef enum {
	TOPO_TYPE_INVALID = 0,
	TOPO_TYPE_BOOLEAN,	/* boolean */
	TOPO_TYPE_INT32,	/* int32_t */
	TOPO_TYPE_UINT32,	/* uint32_t */
	TOPO_TYPE_INT64,	/* int64_t */
	TOPO_TYPE_UINT64,	/* uint64_t */
	TOPO_TYPE_STRING,	/* const char* */
	TOPO_TYPE_TIME,		/* uint64_t */
	TOPO_TYPE_SIZE,		/* uint64_t */
	TOPO_TYPE_FMRI,		/* nvlist_t */
	TOPO_TYPE_INT32_ARRAY,	/* array of int32_t */
	TOPO_TYPE_UINT32_ARRAY,	/* array of uint32_t */
	TOPO_TYPE_INT64_ARRAY,	/* array of int64_t */
	TOPO_TYPE_UINT64_ARRAY,	/* array of uint64_t */
	TOPO_TYPE_STRING_ARRAY,	/* array of const char* */
	TOPO_TYPE_FMRI_ARRAY,	/* array of nvlist_t */
	TOPO_TYPE_DOUBLE	/* double */
} topo_type_t;

extern nvlist_t *topo_prop_getprops(tnode_t *, int *err);
extern int topo_prop_getprop(tnode_t *, const char *, const char *,
    nvlist_t *, nvlist_t **, int *);
extern int topo_prop_getpgrp(tnode_t *, const char *, nvlist_t **, int *);
extern int topo_prop_setprop(tnode_t *, const char *, nvlist_t *,
    int, nvlist_t *, int *);
extern int topo_fmri_getprop(topo_hdl_t *, nvlist_t *, const char *,
    const char *, nvlist_t *,  nvlist_t **, int *);
extern int topo_fmri_getpgrp(topo_hdl_t *, nvlist_t *, const char *,
    nvlist_t **, int *);
extern int topo_fmri_setprop(topo_hdl_t *, nvlist_t *, const char *,
    nvlist_t *, int, nvlist_t *, int *);

/* Property node NVL names used in topo_prop_getprops */
#define	TOPO_PROP_GROUP		"property-group"
#define	TOPO_PROP_GROUP_NAME	"property-group-name"
#define	TOPO_PROP_GROUP_DSTAB	"property-group-data-stability"
#define	TOPO_PROP_GROUP_NSTAB	"property-group-name-stability"
#define	TOPO_PROP_GROUP_VERSION	"property-group-version"
#define	TOPO_PROP_VAL		"property"
#define	TOPO_PROP_VAL_NAME	"property-name"
#define	TOPO_PROP_VAL_VAL	"property-value"
#define	TOPO_PROP_VAL_TYPE	"property-type"
#define	TOPO_PROP_FLAG		"property-flag"

/*
 * ARGS list used in topo property methods
 */
#define	TOPO_PROP_ARGS	"args"
#define	TOPO_PROP_PARGS	"private-args"

extern int topo_xml_print(topo_hdl_t *, FILE *, const char *scheme, int *);

extern void *topo_hdl_alloc(topo_hdl_t *, size_t);
extern void *topo_hdl_zalloc(topo_hdl_t *, size_t);
extern void topo_hdl_free(topo_hdl_t *, void *, size_t);
extern int topo_hdl_nvalloc(topo_hdl_t *, nvlist_t **, uint_t);
extern int topo_hdl_nvdup(topo_hdl_t *, nvlist_t *, nvlist_t **);
extern char *topo_hdl_strdup(topo_hdl_t *, const char *);

/*
 * Interfaces for converting sensor/indicator types, units, states, etc to
 * a string
 */
void topo_sensor_type_name(uint32_t type, char *buf, size_t len);
void topo_sensor_units_name(uint8_t type, char *buf, size_t len);
void topo_led_type_name(uint8_t type, char *buf, size_t len);
void topo_led_state_name(uint8_t type, char *buf, size_t len);
void topo_sensor_state_name(uint32_t sensor_type, uint8_t state, char *buf,
    size_t len);

/*
 * Defines for standard properties for sensors and indicators
 */
#define	TOPO_PGROUP_FACILITY	"facility"

#define	TOPO_SENSOR_READING	"reading"
#define	TOPO_SENSOR_STATE	"state"
#define	TOPO_SENSOR_CLASS	"sensor-class"
#define	TOPO_FACILITY_TYPE	"type"
#define	TOPO_SENSOR_UNITS	"units"
#define	TOPO_LED_MODE		"mode"

#define	TOPO_PROP_THRESHOLD_LNC		"threshold-lower-non-critical"
#define	TOPO_PROP_THRESHOLD_LCR		"threshold-lower-critical"
#define	TOPO_PROP_THRESHOLD_LNR		"threshold-lower-non-recoverable"

#define	TOPO_PROP_THRESHOLD_UNC		"threshold-upper-non-critical"
#define	TOPO_PROP_THRESHOLD_UCR		"threshold-upper-critical"
#define	TOPO_PROP_THRESHOLD_UNR		"threshold-upper-non-recoverable"

/*
 * Sensor Classes
 *
 * The "sensor-class" property in the "facility" propgroup on
 * facility nodes of type "sensor" should be set to one of these
 * two values.
 *
 * Threshold sensors provide an analog sensor reading via the
 * "reading" property in the facility propgroup.  They will also
 * provide one or more discrete states via the "state" property
 * in the facility propgroup.
 *
 * Discrete sensors will not provide an analog reading by will
 * provide one or more discrete states via the "state" property
 * in the facility propgroup.
 */
#define	TOPO_SENSOR_CLASS_THRESHOLD	"threshold"
#define	TOPO_SENSOR_CLASS_DISCRETE	"discrete"

/*
 * Sensor unit types.  We're using the unit types and corresponding
 * codes described in the IPMI 2.0 spec as a reference as it seems to be a
 * reasonably comprehensive list.  This also simplifies the IPMI provider code
 * since the unit type codes will map exactly to what libtopo uses (so no
 * conversion necessary).
 */
typedef enum topo_sensor_unit {
	TOPO_SENSOR_UNITS_UNSPECIFIED = 0,
	TOPO_SENSOR_UNITS_DEGREES_C,
	TOPO_SENSOR_UNITS_DEGREES_F,
	TOPO_SENSOR_UNITS_DEGREES_K,
	TOPO_SENSOR_UNITS_VOLTS,
	TOPO_SENSOR_UNITS_AMPS,
	TOPO_SENSOR_UNITS_WATTS,
	TOPO_SENSOR_UNITS_JOULES,
	TOPO_SENSOR_UNITS_COULOMBS,
	TOPO_SENSOR_UNITS_VA,
	TOPO_SENSOR_UNITS_NITS,
	TOPO_SENSOR_UNITS_LUMEN,
	TOPO_SENSOR_UNITS_LUX,
	TOPO_SENSOR_UNITS_CANDELA,
	TOPO_SENSOR_UNITS_KPA,
	TOPO_SENSOR_UNITS_PSI,

	TOPO_SENSOR_UNITS_NEWTON,
	TOPO_SENSOR_UNITS_CFM,
	TOPO_SENSOR_UNITS_RPM,
	TOPO_SENSOR_UNITS_HZ,
	TOPO_SENSOR_UNITS_MICROSEC,
	TOPO_SENSOR_UNITS_MILLISEC,
	TOPO_SENSOR_UNITS_SECS,
	TOPO_SENSOR_UNITS_MIN,
	TOPO_SENSOR_UNITS_HOUR,
	TOPO_SENSOR_UNITS_DAY,
	TOPO_SENSOR_UNITS_WEEK,
	TOPO_SENSOR_UNITS_MIL,
	TOPO_SENSOR_UNITS_INCHES,
	TOPO_SENSOR_UNITS_FEET,
	TOPO_SENSOR_UNITS_CUB_INCH,
	TOPO_SENSOR_UNITS_CUB_FEET,

	TOPO_SENSOR_UNITS_MM,
	TOPO_SENSOR_UNITS_CM,
	TOPO_SENSOR_UNITS_METERS,
	TOPO_SENSOR_UNITS_CUB_CM,
	TOPO_SENSOR_UNITS_CUB_METER,
	TOPO_SENSOR_UNITS_LITERS,
	TOPO_SENSOR_UNITS_FLUID_OUNCE,
	TOPO_SENSOR_UNITS_RADIANS,
	TOPO_SENSOR_UNITS_STERADIANS,
	TOPO_SENSOR_UNITS_REVOLUTIONS,
	TOPO_SENSOR_UNITS_CYCLES,
	TOPO_SENSOR_UNITS_GRAVITIES,
	TOPO_SENSOR_UNITS_OUNCE,
	TOPO_SENSOR_UNITS_POUND,
	TOPO_SENSOR_UNITS_FOOT_POUND,
	TOPO_SENSOR_UNITS_OZ_INCH,

	TOPO_SENSOR_UNITS_GAUSS,
	TOPO_SENSOR_UNITS_GILBERTS,
	TOPO_SENSOR_UNITS_HENRY,
	TOPO_SENSOR_UNITS_MILHENRY,
	TOPO_SENSOR_UNITS_FARAD,
	TOPO_SENSOR_UNITS_MICROFARAD,
	TOPO_SENSOR_UNITS_OHMS,
	TOPO_SENSOR_UNITS_SIEMENS,
	TOPO_SENSOR_UNITS_MOLE,
	TOPO_SENSOR_UNITS_BECQUEREL,
	TOPO_SENSOR_UNITS_PPM,
	TOPO_SENSOR_UNITS_RESERVED1,
	TOPO_SENSOR_UNITS_DECIBELS,
	TOPO_SENSOR_UNITS_DBA,
	TOPO_SENSOR_UNITS_DBC,
	TOPO_SENSOR_UNITS_GRAY,

	TOPO_SENSOR_UNITS_SIEVERT,
	TOPO_SENSOR_UNITS_COLOR_TEMP_K,
	TOPO_SENSOR_UNITS_BIT,
	TOPO_SENSOR_UNITS_KILOBIT,
	TOPO_SENSOR_UNITS_MEGABIT,
	TOPO_SENSOR_UNITS_GIGABIT,
	TOPO_SENSOR_UNITS_BYTE,
	TOPO_SENSOR_UNITS_KILOBYTE,
	TOPO_SENSOR_UNITS_MEGABYTE,
	TOPO_SENSOR_UNITS_GIGABYTE,
	TOPO_SENSOR_UNITS_WORD,
	TOPO_SENSOR_UNITS_DWORD,
	TOPO_SENSOR_UNITS_QWORD,
	TOPO_SENSOR_UNITS_MEMLINE,
	TOPO_SENSOR_UNITS_HIT,
	TOPO_SENSOR_UNITS_MISS,

	TOPO_SENSOR_UNITS_RETRY,
	TOPO_SENSOR_UNITS_RESET,
	TOPO_SENSOR_UNITS_OVERFLOW,
	TOPO_SENSOR_UNITS_UNDERRUN,
	TOPO_SENSOR_UNITS_COLLISION,
	TOPO_SENSOR_UNITS_PACKETS,
	TOPO_SENSOR_UNITS_MESSAGES,
	TOPO_SENSOR_UNITS_CHARACTERS,
	TOPO_SENSOR_UNITS_ERROR,
	TOPO_SENSOR_UNITS_CE,
	TOPO_SENSOR_UNITS_UE,
	TOPO_SENSOR_UNITS_FATAL_ERROR,
	TOPO_SENSOR_UNITS_GRAMS
} topo_sensor_unit_t;

/*
 * These defines are used by the topo_method_sensor_failure to indicate
 * whether the source of a sensor failure is believed to be the result of an
 * internal failure, external condition or unknown
 */
#define	TOPO_SENSOR_ERRSRC_UNKNOWN	0
#define	TOPO_SENSOR_ERRSRC_INTERNAL	1
#define	TOPO_SENSOR_ERRSRC_EXTERNAL	2

/*
 * Sensor Types amd the associated sensor-type-specific states
 *
 * These are used to decode the type and state properties in the facility
 * propgroup on facility nodes of type sensor.
 *
 * Again we're basically using the same defines as for IPMI as it's serves
 * as a good starting point and simplifies the IPMI provider code.  Of course
 * other facility providers will need to convert from their native codes
 * to the topo code when they set the type and state properties.
 */
#define	TOPO_SENSOR_TYPE_RESERVED			0x0000
#define	TOPO_SENSOR_TYPE_TEMP				0x0001
#define	TOPO_SENSOR_TYPE_VOLTAGE			0x0002
#define	TOPO_SENSOR_TYPE_CURRENT			0x0003
#define	TOPO_SENSOR_TYPE_FAN				0x0004
#define	TOPO_SENSOR_TYPE_PHYSICAL			0x0005

#define	TOPO_SENSOR_STATE_PHYSICAL_GENERAL		0x0001
#define	TOPO_SENSOR_STATE_PHYSICAL_BAY			0x0002
#define	TOPO_SENSOR_STATE_PHYSICAL_CARD			0x0004
#define	TOPO_SENSOR_STATE_PHYSICAL_PROCESSOR		0x0008
#define	TOPO_SENSOR_STATE_PHYSICAL_LAN			0x0010
#define	TOPO_SENSOR_STATE_PHYSICAL_DOCK			0x0020
#define	TOPO_SENSOR_STATE_PHYSICAL_FAN			0x0040

#define	TOPO_SENSOR_TYPE_PLATFORM			0x0006

#define	TOPO_SENSOR_STATE_PLATFORM_SECURE		0x0001
#define	TOPO_SENSOR_STATE_PLATFORM_USER_PASS		0x0002
#define	TOPO_SENSOR_STATE_PLATFORM_SETUP_PASS		0x0004
#define	TOPO_SENSOR_STATE_PLATFORM_NETWORK_PASS		0x0008
#define	TOPO_SENSOR_STATE_PLATFORM_OTHER_PASS		0x0010
#define	TOPO_SENSOR_STATE_PLATFORM_OUT_OF_BAND		0x0020

#define	TOPO_SENSOR_TYPE_PROCESSOR			0x0007

#define	TOPO_SENSOR_STATE_PROCESSOR_IERR		0x0001
#define	TOPO_SENSOR_STATE_PROCESSOR_THERMAL		0x0002
#define	TOPO_SENSOR_STATE_PROCESSOR_FRB1		0x0004
#define	TOPO_SENSOR_STATE_PROCESSOR_FRB2		0x0008
#define	TOPO_SENSOR_STATE_PROCESSOR_FRB3		0x0010
#define	TOPO_SENSOR_STATE_PROCESSOR_CONFIG		0x0020
#define	TOPO_SENSOR_STATE_PROCESSOR_SMBIOS		0x0040
#define	TOPO_SENSOR_STATE_PROCESSOR_PRESENT		0x0080
#define	TOPO_SENSOR_STATE_PROCESSOR_DISABLED		0x0100
#define	TOPO_SENSOR_STATE_PROCESSOR_TERMINATOR		0x0200
#define	TOPO_SENSOR_STATE_PROCESSOR_THROTTLED		0x0400

#define	TOPO_SENSOR_TYPE_POWER_SUPPLY			0x0008

#define	TOPO_SENSOR_STATE_POWER_SUPPLY_PRESENT		0x0001
#define	TOPO_SENSOR_STATE_POWER_SUPPLY_FAILURE		0x0002
#define	TOPO_SENSOR_STATE_POWER_SUPPLY_PREDFAIL		0x0004
#define	TOPO_SENSOR_STATE_POWER_SUPPLY_INPUT_LOST	0x0008
#define	TOPO_SENSOR_STATE_POWER_SUPPLY_INPUT_RANGE	0x0010
#define	TOPO_SENSOR_STATE_POWER_SUPPLY_INPUT_RANGE_PRES	0x0020
#define	TOPO_SENSOR_STATE_POWER_SUPPLY_CONFIG_ERR	0x0040

#define	TOPO_SENSOR_TYPE_POWER_UNIT			0x0009

#define	TOPO_SENSOR_STATE_POWER_UNIT_OFF		0x0001
#define	TOPO_SENSOR_STATE_POWER_UNIT_CYCLE		0x0002
#define	TOPO_SENSOR_STATE_POWER_UNIT_240_DOWN		0x0004
#define	TOPO_SENSOR_STATE_POWER_UNIT_INTERLOCK_DOWN	0x0008
#define	TOPO_SENSOR_STATE_POWER_UNIT_AC_LOST		0x0010
#define	TOPO_SENSOR_STATE_POWER_UNIT_SOFT_FAILURE	0x0020
#define	TOPO_SENSOR_STATE_POWER_UNIT_FAIL		0x0040
#define	TOPO_SENSOR_STATE_POWER_UNIT_PREDFAIL		0x0080

#define	TOPO_SENSOR_TYPE_COOLING			0x000A
#define	TOPO_SENSOR_TYPE_OTHER				0x000B

#define	TOPO_SENSOR_TYPE_MEMORY				0x000C

#define	TOPO_SENSOR_STATE_MEMORY_CE			0x0001
#define	TOPO_SENSOR_STATE_MEMORY_UE			0x0002
#define	TOPO_SENSOR_STATE_MEMORY_PARITY			0x0004
#define	TOPO_SENSOR_STATE_MEMORY_SCRUB_FAIL		0x0008
#define	TOPO_SENSOR_STATE_MEMORY_DISABLED		0x0010
#define	TOPO_SENSOR_STATE_MEMORY_CE_LOG_LIMIT		0x0020
#define	TOPO_SENSOR_STATE_MEMORY_PRESENT		0x0040
#define	TOPO_SENSOR_STATE_MEMORY_CONFIG_ERR		0x0080
#define	TOPO_SENSOR_STATE_MEMORY_SPARE			0x0100
#define	TOPO_SENSOR_STATE_MEMORY_THROTTLED		0x0200
#define	TOPO_SENSOR_STATE_MEMORY_OVERTEMP		0x0400

#define	TOPO_SENSOR_TYPE_BAY				0x000D

#define	TOPO_SENSOR_STATE_BAY_PRESENT			0x0001
#define	TOPO_SENSOR_STATE_BAY_FAULT			0x0002
#define	TOPO_SENSOR_STATE_BAY_PREDFAIL			0x0004
#define	TOPO_SENSOR_STATE_BAY_SPARE			0x0008
#define	TOPO_SENSOR_STATE_BAY_CHECK			0x0010
#define	TOPO_SENSOR_STATE_BAY_CRITICAL			0x0020
#define	TOPO_SENSOR_STATE_BAY_FAILED			0x0040
#define	TOPO_SENSOR_STATE_BAY_REBUILDING		0x0080
#define	TOPO_SENSOR_STATE_BAY_ABORTED			0x0100

#define	TOPO_SENSOR_TYPE_POST_RESIZE			0x000E

#define	TOPO_SENSOR_TYPE_FIRMWARE			0x000F

#define	TOPO_SENSOR_STATE_FIRMWARE_ERROR		0x0001
#define	TOPO_SENSOR_STATE_FIRMWARE_HANG			0x0002
#define	TOPO_SENSOR_STATE_FIRMWARE_PROGRESS		0x0004

#define	TOPO_SENSOR_TYPE_EVENT_LOG			0x0010

#define	TOPO_SENSOR_STATE_EVENT_LOG_CE			0x0001
#define	TOPO_SENSOR_STATE_EVENT_LOG_TYPE		0x0002
#define	TOPO_SENSOR_STATE_EVENT_LOG_RESET		0x0004
#define	TOPO_SENSOR_STATE_EVENT_LOG_ALL			0x0008
#define	TOPO_SENSOR_STATE_EVENT_LOG_FULL		0x0010
#define	TOPO_SENSOR_STATE_EVENT_LOG_ALMOST_FULL		0x0020

#define	TOPO_SENSOR_TYPE_WATCHDOG1			0x0011

#define	TOPO_SENSOR_STATE_WATCHDOG_BIOS_RESET		0x0001
#define	TOPO_SENSOR_STATE_WATCHDOG_OS_RESET		0x0002
#define	TOPO_SENSOR_STATE_WATCHDOG_OS_SHUTDOWN		0x0004
#define	TOPO_SENSOR_STATE_WATCHDOG_OS_PWR_DOWN		0x0008
#define	TOPO_SENSOR_STATE_WATCHDOG_OS_PWR_CYCLE		0x0010
#define	TOPO_SENSOR_STATE_WATCHDOG_OS_NMI_DIAG		0x0020
#define	TOPO_SENSOR_STATE_WATCHDOG_EXPIRED		0x0040
#define	TOPO_SENSOR_STATE_WATCHDOG_PRE_TIMEOUT_INT	0x0080

#define	TOPO_SENSOR_TYPE_SYSTEM				0x0012

#define	TOPO_SENSOR_STATE_SYSTEM_RECONF			0x0001
#define	TOPO_SENSOR_STATE_SYSTEM_BOOT			0x0002
#define	TOPO_SENSOR_STATE_SYSTEM_UNKNOWN_HW_FAILURE	0x0004
#define	TOPO_SENSOR_STATE_SYSTEM_AUX_LOG_UPDATED	0x0008
#define	TOPO_SENSOR_STATE_SYSTEM_PEF_ACTION		0x0010
#define	TOPO_SENSOR_STATE_SYSTEM_TIMETAMP_CLOCKSYNC	0x0020

#define	TOPO_SENSOR_TYPE_CRITICAL			0x0013

#define	TOPO_SENSOR_STATE_CRITICAL_EXT_NMI		0x0001
#define	TOPO_SENSOR_STATE_CRITICAL_BUS_TIMEOUT		0x0002
#define	TOPO_SENSOR_STATE_CRITICAL_IO_NMI		0x0004
#define	TOPO_SENSOR_STATE_CRITICAL_SW_NMI		0x0008
#define	TOPO_SENSOR_STATE_CRITICAL_PCI_PERR		0x0010
#define	TOPO_SENSOR_STATE_CRITICAL_PCI_SERR		0x0020
#define	TOPO_SENSOR_STATE_CRITICAL_EISA_FAILSAFE	0x0040
#define	TOPO_SENSOR_STATE_CRITICAL_BUS_CE		0x0080
#define	TOPO_SENSOR_STATE_CRITICAL_BUS_UE		0x0100
#define	TOPO_SENSOR_STATE_CRITICAL_FATAL_NMI		0x0200
#define	TOPO_SENSOR_STATE_CRITICAL_BUS_FATAL_ERR	0x0400
#define	TOPO_SENSOR_STATE_CRITICAL_BUS_DEGRADED		0x0800

#define	TOPO_SENSOR_TYPE_BUTTON				0x0014

#define	TOPO_SENSOR_STATE_BUTTON_PWR			0x0001
#define	TOPO_SENSOR_STATE_BUTTON_SLEEP			0x0002
#define	TOPO_SENSOR_STATE_BUTTON_RESET			0x0004
#define	TOPO_SENSOR_STATE_BUTTON_FRU_LATCH		0x0008
#define	TOPO_SENSOR_STATE_BUTTON_FRU_SERVICE		0x0010

#define	TOPO_SENSOR_TYPE_MODULE				0x0015
#define	TOPO_SENSOR_TYPE_MICROCONTROLLER		0x0016
#define	TOPO_SENSOR_TYPE_CARD				0x0017
#define	TOPO_SENSOR_TYPE_CHASSIS			0x0018

#define	TOPO_SENSOR_TYPE_CHIPSET			0x0019

#define	TOPO_SENSOR_STATE_CHIPSET_PWR_CTL_FAIL		0x0001

#define	TOPO_SENSOR_TYPE_FRU				0x001A

#define	TOPO_SENSOR_TYPE_CABLE				0x001B

#define	TOPO_SENSOR_STATE_CABLE_CONNECTED		0x0001
#define	TOPO_SENSOR_STATE_CABLE_CONFIG_ERR		0x0002

#define	TOPO_SENSOR_TYPE_TERMINATOR			0x001C

#define	TOPO_SENSOR_TYPE_BOOT_STATE			0x001D

#define	TOPO_SENSOR_STATE_BOOT_STATE_BIOS_PWR_UP	0x0001
#define	TOPO_SENSOR_STATE_BOOT_STATE_BIOS_HARD_RESET	0x0002
#define	TOPO_SENSOR_STATE_BOOT_STATE_BIOS_WARM_RESET	0x0004
#define	TOPO_SENSOR_STATE_BOOT_STATE_PXE_BOOT		0x0008
#define	TOPO_SENSOR_STATE_BOOT_STATE_DIAG_BOOT		0x0010
#define	TOPO_SENSOR_STATE_BOOT_STATE_OS_HARD_RESET	0x0020
#define	TOPO_SENSOR_STATE_BOOT_STATE_OS_WARM_RESET	0x0040
#define	TOPO_SENSOR_STATE_BOOT_STATE_SYS_RESTART	0x0080

#define	TOPO_SENSOR_TYPE_BOOT_ERROR			0x001E

#define	TOPO_SENSOR_STATE_BOOT_ERROR_NOMEDIA		0x0001
#define	TOPO_SENSOR_STATE_BOOT_ERROR_NON_BOOTABLE_DISK	0x0002
#define	TOPO_SENSOR_STATE_BOOT_ERROR_NO_PXE_SERVER	0x0004
#define	TOPO_SENSOR_STATE_BOOT_ERROR_INV_BOOT_SECT	0x0008
#define	TOPO_SENSOR_STATE_BOOT_ERROR_USR_SELECT_TIMEOUT	0x0010

#define	TOPO_SENSOR_TYPE_BOOT_OS			0x001F

#define	TOPO_SENSOR_STATE_BOOT_OS_A_DRV_BOOT_COMPLETE	0x0001
#define	TOPO_SENSOR_STATE_BOOT_OS_C_DRV_BOOT_COMPLETE	0x0002
#define	TOPO_SENSOR_STATE_BOOT_OS_PXE_BOOT_COMPLETE	0x0004
#define	TOPO_SENSOR_STATE_BOOT_OS_DIAG_BOOT_COMPLETE	0x0008
#define	TOPO_SENSOR_STATE_BOOT_OS_CDROM_BOOT_COMPLETE	0x0010
#define	TOPO_SENSOR_STATE_BOOT_OS_ROM_BOOT_COMPLETE	0x0020
#define	TOPO_SENSOR_STATE_BOOT_OS_UNSPEC_BOOT_COMPLETE	0x0040

#define	TOPO_SENSOR_TYPE_OS_SHUTDOWN			0x0020

#define	TOPO_SENSOR_STATE_OS_SHUTDOWN_LOADING		0x0001
#define	TOPO_SENSOR_STATE_OS_SHUTDOWN_CRASH		0x0002
#define	TOPO_SENSOR_STATE_OS_STOP_GRACEFUL		0x0004
#define	TOPO_SENSOR_STATE_OS_SHUTDOWN_GRACEFUL		0x0008
#define	TOPO_SENSOR_STATE_OS_SHUTDOWN_PEF		0x0010
#define	TOPO_SENSOR_STATE_OS_SHUTDOWN_BMC		0x0020

#define	TOPO_SENSOR_TYPE_SLOT				0x0021

#define	TOPO_SENSOR_STATE_SLOT_FAULT_ASSERTED		0x0001
#define	TOPO_SENSOR_STATE_SLOT_IDENTIFY_ASSERTED	0x0002
#define	TOPO_SENSOR_STATE_SLOT_CONNECTED		0x0004
#define	TOPO_SENSOR_STATE_SLOT_INSTALL_READY		0x0008
#define	TOPO_SENSOR_STATE_SLOT_REMOVE_READY		0x0010
#define	TOPO_SENSOR_STATE_SLOT_PWR_OFF			0x0020
#define	TOPO_SENSOR_STATE_SLOT_REMOVED			0x0040
#define	TOPO_SENSOR_STATE_SLOT_INTERLOCK_ASSERTED	0x0080
#define	TOPO_SENSOR_STATE_SLOT_DISABLED			0x0100
#define	TOPO_SENSOR_STATE_SLOT_SPARE_DEVICE		0x0200

#define	TOPO_SENSOR_TYPE_ACPI				0x0022

#define	TOPO_SENSOR_STATE_ACPI_PSTATE_S0_G0		0x0001
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_S1		0x0002
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_S2		0x0004
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_S3		0x0008
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_S4		0x0010
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_S5_G2_SOFT_OFF	0x0020
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_S4_S5_SOFT_OFF	0x0040
#define	TOPO_SENSOR_STATE_ACPI_PSATTE_G3_MECH_OFF	0x0080
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_S1_S2_S3_SLEEP	0x0100
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_G1_SLEEP		0x0200
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_S5_OVERRIDE	0x0400
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_LEGACY_ON		0x0800
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_LEGACY_OFF	0x1000
#define	TOPO_SENSOR_STATE_ACPI_PSTATE_UNKNOWN		0x2000

#define	TOPO_SENSOR_TYPE_WATCHDOG2			0x0023

#define	TOPO_SENSOR_STATE_WATCHDOG2_EXPIRED		0x0001
#define	TOPO_SENSOR_STATE_WATCHDOG2_HARD_RESET		0x0002
#define	TOPO_SENSOR_STATE_WATCHDOG2_PWR_DOWN		0x0004
#define	TOPO_SENSOR_STATE_WATCHDOG2_PWR_CYCLE		0x0008
#define	TOPO_SENSOR_STATE_WATCHDOG2_RESERVED1		0x0010
#define	TOPO_SENSOR_STATE_WATCHDOG2_RESERVED2		0x0020
#define	TOPO_SENSOR_STATE_WATCHDOG2_RESERVED3		0x0040
#define	TOPO_SENSOR_STATE_WATCHDOG2_RESERVED4		0x0080
#define	TOPO_SENSOR_STATE_WATCHDOG2_TIMEOUT_INT		0x0100

#define	TOPO_SENSOR_TYPE_ALERT				0x0024

#define	TOPO_SENSOR_STATE_ALERT_PLAT_PAGE		0x0001
#define	TOPO_SENSOR_STATE_ALERT_PLAT_LAN_ALERT		0x0002
#define	TOPO_SENSOR_STATE_ALERT_PLAT_EVT_TRAP		0x0004
#define	TOPO_SENSOR_STATE_ALERT_PLAT_SNMP_TRAP		0x0008

#define	TOPO_SENSOR_TYPE_PRESENCE			0x0025

#define	TOPO_SENSOR_STATE_PRESENCE_PRESENT		0x0001
#define	TOPO_SENSOR_STATE_PRESENCE_ABSENT		0x0002
#define	TOPO_SENSOR_STATE_PRESENCE_DISABLED		0x0004

#define	TOPO_SENSOR_TYPE_ASIC				0x0026

#define	TOPO_SENSOR_TYPE_LAN				0x0027

#define	TOPO_SENSOR_STATE_LAN_HEARTBEAT_LOST		0x0001
#define	TOPO_SENSOR_STATE_LAN_HEARTBEAT			0x0002

#define	TOPO_SENSOR_TYPE_HEALTH				0x0028

#define	TOPO_SENSOR_STATE_HEALTH_SENSOR_ACC_DEGRADED	0x0001
#define	TOPO_SENSOR_STATE_HEALTH_CNTLR_ACC_DEGRADED	0x0002
#define	TOPO_SENSOR_STATE_HEALTH_CNTLR_OFFLINE		0x0004
#define	TOPO_SENSOR_STATE_HEALTH_CNTLR_UNAVAIL		0x0008
#define	TOPO_SENSOR_STATE_HEALTH_SENSOR_FAILURE		0x0010
#define	TOPO_SENSOR_STATE_HEALTH_FRU_FAILURE		0x0020

#define	TOPO_SENSOR_TYPE_BATTERY			0x0029

#define	TOPO_SENSOR_STATE_BATTERY_LOW			0x0001
#define	TOPO_SENSOR_STATE_BATTERY_FAILED		0x0002
#define	TOPO_SENSOR_STATE_BATTERY_PRESENCE		0x0004

#define	TOPO_SENSOR_TYPE_AUDIT				0x002A

#define	TOPO_SENSOR_STATE_AUDIT_SESSION_ACTIVATED	0x0001
#define	TOPO_SENSOR_STATE_AUDIT_SESSION_DEACTIVATED	0x0002

#define	TOPO_SENSOR_TYPE_VERSION			0x002B

#define	TOPO_SENSOR_STATE_VERSION_HW_CHANGE		0x0001
#define	TOPO_SENSOR_STATE_VERSION_SW_CHANGE		0x0002
#define	TOPO_SENSOR_STATE_VERSION_HW_INCOMPATIBLE	0x0004
#define	TOPO_SENSOR_STATE_VERSION_SW_INCOMPATIBLE	0x0008
#define	TOPO_SENSOR_STATE_VERSION_HW_INVAL		0x0010
#define	TOPO_SENSOR_STATE_VERSION_SW_INVAL		0x0020
#define	TOPO_SENSOR_STATE_VERSION_HW_CHANGE_SUCCESS	0x0040
#define	TOPO_SENSOR_STATE_VERSION_SW_CHANGE_SUCCESS	0x0080

#define	TOPO_SENSOR_TYPE_FRU_STATE			0x002C

#define	TOPO_SENSOR_STATE_FRU_STATE_NOT_INSTALLED	0x0001
#define	TOPO_SENSOR_STATE_FRU_STATE_INACTIVE		0x0002
#define	TOPO_SENSOR_STATE_FRU_STATE_ACT_REQ		0x0004
#define	TOPO_SENSOR_STATE_FRU_STATE_ACT_INPROGRESS	0x0008
#define	TOPO_SENSOR_STATE_FRU_STATE_ACTIVE		0x0010
#define	TOPO_SENSOR_STATE_FRU_STATE_DEACT_REQ		0x0020
#define	TOPO_SENSOR_STATE_FRU_STATE_DEACT_INPROGRESS	0x0040
#define	TOPO_SENSOR_STATE_FRU_STATE_COMM_LOST		0x0080

/*
 * We simplify the IPMI sensor type code defines by combining the generic
 * and sensor-specific codes into a single range.  Because there's overlap
 * between the two ranges we offset the generic type codes by 0x0100
 * which allows ample room in the hole for future expansion of the table to
 * accomodate either additions to the IPMI spec or to support new sensor types
 * for alternate provider modules.
 */
#define	TOPO_SENSOR_TYPE_THRESHOLD_STATE		0x0101

#define	TOPO_SENSOR_STATE_THRESH_LOWER_NONCRIT		0x0001
#define	TOPO_SENSOR_STATE_THRESH_LOWER_CRIT		0x0002
#define	TOPO_SENSOR_STATE_THRESH_LOWER_NONREC		0x0004
#define	TOPO_SENSOR_STATE_THRESH_UPPER_NONCRIT		0x0008
#define	TOPO_SENSOR_STATE_THRESH_UPPER_CRIT		0x0010
#define	TOPO_SENSOR_STATE_THRESH_UPPER_NONREC		0x0020

#define	TOPO_SENSOR_TYPE_GENERIC_USAGE			0x0102

#define	TOPO_SENSOR_STATE_GENERIC_USAGE_IDLE		0x0001
#define	TOPO_SENSOR_STATE_GENERIC_USAGE_ACTIVE		0x0002
#define	TOPO_SENSOR_STATE_GENERIC_USAGE_BUSY		0x0004

#define	TOPO_SENSOR_TYPE_GENERIC_STATE			0x0103

#define	TOPO_SENSOR_STATE_GENERIC_STATE_DEASSERTED	0x0001
#define	TOPO_SENSOR_STATE_GENERIC_STATE_ASSERTED	0x0002

#define	TOPO_SENSOR_TYPE_GENERIC_PREDFAIL		0x0104

#define	TOPO_SENSOR_STATE_GENERIC_PREDFAIL_DEASSERTED	0x0001
#define	TOPO_SENSOR_STATE_GENERIC_PREDFAIL_ASSERTED	0x0002

#define	TOPO_SENSOR_TYPE_GENERIC_LIMIT			0x0105

#define	TOPO_SENSOR_STATE_GENERIC_LIMIT_NOT_EXCEEDED	0x0001
#define	TOPO_SENSOR_STATE_GENERIC_LIMIT_EXCEEDED	0x0002

#define	TOPO_SENSOR_TYPE_GENERIC_PERFORMANCE		0x0106

#define	TOPO_SENSOR_STATE_GENERIC_PERFORMANCE_MET	0x0001
#define	TOPO_SENSOR_STATE_GENERIC_PERFORMANCE_LAGS	0x0002

#define	TOPO_SENSOR_TYPE_SEVERITY			0x0107

#define	TOPO_SENSOR_STATE_SEVERITY_OK			0x0001
#define	TOPO_SENSOR_STATE_SEVERITY_NONCRIT_GOING_HIGH	0x0002
#define	TOPO_SENSOR_STATE_SEVERITY_CRIT_GOING_HIGH	0x0004
#define	TOPO_SENSOR_STATE_SEVERITY_NONREC_GOING_HIGH	0x0008
#define	TOPO_SENSOR_STATE_SEVERITY_NONCRIT_GOING_LOW	0x0010
#define	TOPO_SENSOR_STATE_SEVERITY_CRIT_GOING_LOW	0x0020
#define	TOPO_SENSOR_STATE_SEVERITY_NONREC_GOING_LOW	0x0020
#define	TOPO_SENSOR_STATE_SEVERITY_MONITOR		0x0040
#define	TOPO_SENSOR_STATE_SEVERITY_INFORMATIONAL	0x0080

#define	TOPO_SENSOR_TYPE_GENERIC_PRESENCE		0x0108

#define	TOPO_SENSOR_STATE_GENERIC_PRESENCE_DEASSERTED	0x0001
#define	TOPO_SENSOR_STATE_GENERIC_PRESENCE_ASSERTED	0x0002

#define	TOPO_SENSOR_TYPE_GENERIC_AVAILABILITY		0x0109

#define	TOPO_SENSOR_STATE_GENERIC_AVAIL_DEASSERTED	0x0001
#define	TOPO_SENSOR_STATE_GENERIC_AVAIL_ASSERTED	0x0002

#define	TOPO_SENSOR_TYPE_GENERIC_STATUS			0x010A

#define	TOPO_SENSOR_STATE_GENERIC_STATUS_RUNNING	0x0001
#define	TOPO_SENSOR_STATE_GENERIC_STATUS_IN_TEST	0x0002
#define	TOPO_SENSOR_STATE_GENERIC_STATUS_POWER_OFF	0x0004
#define	TOPO_SENSOR_STATE_GENERIC_STATUS_ONLINE		0x0008
#define	TOPO_SENSOR_STATE_GENERIC_STATUS_OFFLINE	0x0010
#define	TOPO_SENSOR_STATE_GENERIC_STATUS_OFF_DUTY	0x0020
#define	TOPO_SENSOR_STATE_GENERIC_STATUS_DEGRADED	0x0040
#define	TOPO_SENSOR_STATE_GENERIC_STATUS_POWER_SAVE	0x0080
#define	TOPO_SENSOR_STATE_GENERIC_STATUS_INSTALL_ERR	0x0100

#define	TOPO_SENSOR_TYPE_GENERIC_REDUNDANCY		0x010B

/*
 * ACPI power state
 */
#define	TOPO_SENSOR_TYPE_GENERIC_ACPI			0x010C

#define	TOPO_SENSOR_STATE_GENERIC_ACPI_D0		0x0001
#define	TOPO_SENSOR_STATE_GENERIC_ACPI_D1		0x0002
#define	TOPO_SENSOR_STATE_GENERIC_ACPI_D2		0x0004
#define	TOPO_SENSOR_STATE_GENERIC_ACPI_D3		0x0008

/*
 * These sensor types don't exist in the IPMI spec, but allow consumers to
 * associate discrete sensors with component failure.  The 'ok' sensor is the
 * inverse of the 'failure' sensor.  Note that the values intentionally mimic
 * TOPO_SENSOR_TYPE_GENERIC_STATE, so that you can use existing IPMI sensors
 * but just change the type to get semantically meaningful behavior.
 */
#define	TOPO_SENSOR_TYPE_GENERIC_FAILURE		0x010D

#define	TOPO_SENSOR_STATE_GENERIC_FAIL_DEASSERTED	0x0001
#define	TOPO_SENSOR_STATE_GENERIC_FAIL_NONRECOV		0x0002
#define	TOPO_SENSOR_STATE_GENERIC_FAIL_CRITICAL		0x0004

#define	TOPO_SENSOR_TYPE_GENERIC_OK			0x010E

#define	TOPO_SENSOR_STATE_GENERIC_OK_DEASSERTED		0x0001
#define	TOPO_SENSOR_STATE_GENERIC_OK_ASSERTED		0x0002

/*
 * Indicator modes and types
 */
typedef enum topo_led_state {
	TOPO_LED_STATE_OFF = 0,
	TOPO_LED_STATE_ON
} topo_led_state_t;

#define	TOPO_FAC_TYPE_ANY	0xFFFFFFFF

/*
 * This list is limited to the set of LED's that we're likely to manage through
 * FMA.  Thus is does not include things like power or activity LED's
 */
typedef enum topo_led_type {
	TOPO_LED_TYPE_SERVICE = 0,
	TOPO_LED_TYPE_LOCATE,
	TOPO_LED_TYPE_OK2RM,
	TOPO_LED_TYPE_PRESENT
} topo_led_type_t;


#ifdef __cplusplus
}
#endif

#endif /* _LIBTOPO_H */
