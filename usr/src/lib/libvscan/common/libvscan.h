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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef __LIBVS_H__
#define	__LIBVS_H__

#include <netdb.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Property IDs - general property group */
#define	VS_PROPID_MAXSIZE	0x01LL
#define	VS_PROPID_MAXSIZE_ACTION	0x02LL
#define	VS_PROPID_TYPES		0x04LL
#define	VS_PROPID_VLOG		0x08LL

#define	VS_PROPID_GEN_ALL		(VS_PROPID_MAXSIZE | \
    VS_PROPID_MAXSIZE_ACTION | VS_PROPID_TYPES | VS_PROPID_VLOG)

#define	VS_PROPID_VALUE_AUTH	0x010LL

/* Property IDs - scan engine property groups */
#define	VS_PROPID_SE_ENABLE	0x100LL
#define	VS_PROPID_SE_HOST	0x200LL
#define	VS_PROPID_SE_PORT	0x400LL
#define	VS_PROPID_SE_MAXCONN	0x800LL

#define	VS_PROPID_SE_ALL	(VS_PROPID_SE_ENABLE | \
    VS_PROPID_SE_HOST | VS_PROPID_SE_PORT | VS_PROPID_SE_MAXCONN)

/* Check for whether a property id is a scan engine id */
#define	VS_PROPID_IS_SE(id)	((id & VS_PROPID_SE_ALL) ? 1 : 0)

/* The maximum property id value - across all property groups */
#define	VS_PROPID_MAX		VS_PROPID_SE_MAXCONN

/* The number of properties in the largest property group */
#define	VS_NUM_PROPIDS		5

/* Range of scan engine IDs and max number of scan engines supported */
#define	VS_SE_MAX		16
#define	VS_SE_NAME_LEN		64

/* Min & Max scan engine connections per engine */
#define	VS_VAL_SE_MAXCONN_MIN	1
#define	VS_VAL_SE_MAXCONN_MAX	512

/* Can accommodate a string-ified ULONG_MAX plus unit specifier */
#define	VS_VAL_MAXSIZE_LEN	32

#define	VS_VAL_TYPES_LEN	4096
#define	VS_VAL_TYPES_INVALID_CHARS	"."

/* libvscan error codes */
#define	VS_ERR_NONE			0
#define	VS_ERR_INVALID_PROPERTY		1
#define	VS_ERR_INVALID_VALUE		2
#define	VS_ERR_INVALID_HOST		3
#define	VS_ERR_INVALID_SE		4
#define	VS_ERR_MAX_SE			5
#define	VS_ERR_AUTH			6
#define	VS_ERR_DAEMON_COMM		10
#define	VS_ERR_SCF			20
#define	VS_ERR_SYS			30


/* RBAC authorizations */
#define	VS_VALUE_AUTH		"solaris.smf.value.vscan"
#define	VS_ACTION_AUTH		"solaris.smf.manage.vscan"
#define	VS_MODIFY_AUTH		"solaris.smf.modify.application"

/* statistics door interface */
#define	VS_STATS_DOOR_NAME	"/var/run/vscan_stats_door"
#define	VS_STATS_DOOR_VERSION	1

/* scan statistics door request type */
typedef enum {
	VS_STATS_GET,
	VS_STATS_RESET
} vs_stats_req_t;

typedef struct vs_stats {
	uint64_t vss_scanned;
	uint64_t vss_infected;
	uint64_t vss_cleaned;
	uint64_t vss_failed;
	struct {
		char vss_engid[VS_SE_NAME_LEN];
		uint64_t vss_errors;
	} vss_eng[VS_SE_MAX];
} vs_stats_t;

/*
 *  General service configuration properties
 */
typedef struct vs_props {
	char vp_maxsize[VS_VAL_MAXSIZE_LEN];
	boolean_t vp_maxsize_action;
	char vp_types[VS_VAL_TYPES_LEN];
	char vp_vlog[MAXPATHLEN];
} vs_props_t;

/*
 *  Scan engine configuration properties.  These are defined
 *  per-engine.
 */
typedef struct vs_props_se {
	char vep_engid[VS_SE_NAME_LEN];
	boolean_t vep_enable;
	char vep_host[MAXHOSTNAMELEN];
	uint16_t vep_port;
	uint64_t vep_maxconn;
} vs_props_se_t;

typedef struct vs_props_all {
	vs_props_t va_props;
	vs_props_se_t va_se[VS_SE_MAX];
} vs_props_all_t;


/*
 * General service configuration properties API
 * These functions return VS_ERR_XXX error codes.
 */
int vs_props_get_all(vs_props_all_t *);
int vs_props_set(const vs_props_t *, uint64_t);
int vs_props_get(vs_props_t *, uint64_t);
int vs_props_validate(const vs_props_t *, uint64_t);


/*
 * Scan engine configuration properties API
 * These functions return VS_ERR_XXX error codes.
 */
int vs_props_se_create(char *, const vs_props_se_t *, uint64_t);
int vs_props_se_set(char *, const vs_props_se_t *, uint64_t);
int vs_props_se_get(char *, vs_props_se_t *, uint64_t);
int vs_props_se_validate(const vs_props_se_t *, uint64_t);
int vs_props_se_delete(const char *);


/* Get error string for error code */
const char *vs_strerror(int);

/* Functions to access/reset scan statistics in service daemon */
int vs_statistics(vs_stats_t *);
int vs_statistics_reset(void);


/*  Utility functions */

/*
 * Replace comma separators with '\0'.
 *
 * Types contains comma separated rules each beginning with +|-
 *   - embedded commas are escaped by backslash
 *   - backslash is escaped by backslash
 *   - a single backslash not followed by comma is illegal
 *
 * On entry to the function len must contain the length of
 * the buffer. On sucecssful exit len will contain the length
 * of the parsed data within the buffer.
 *
 * Returns 0 on success, -1 on failure
 */
int vs_parse_types(const char *, char *, uint32_t *);


/*
 * Converts a size string in the format into an integer.
 *
 * A size string is a numeric value followed by an optional unit
 * specifier which is used as a multiplier to calculate a raw
 * number.
 * The size string format is:  N[.N][KMGTP][B]
 *
 * The numeric value can contain a decimal portion. Unit specifiers
 * are either a one-character or two-character string; i.e. "K" or
 * "KB" for kilobytes. Unit specifiers must follow the numeric portion
 * immediately, and are not case-sensitive.
 *
 * If either "B" is specified, or there is no unit specifier portion
 * in the string, the numeric value is calculated with no multiplier
 * (assumes a basic unit of "bytes").
 *
 * Returns: -1: Failure; errno set to specify the error.
 *           0: Success.
 */
int vs_strtonum(const char *, uint64_t *);

#ifdef __cplusplus
}
#endif

#endif /* __LIBVS_H__ */
