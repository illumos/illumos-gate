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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_CFGADM_H
#define	_CFGADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Command line options
 */
#define	OPTIONS		"ac:fhlno:s:tx:vy"

/*
 * Configuration operations
 */
typedef enum {
	CFGA_OP_NONE = 0,
	CFGA_OP_CHANGE_STATE,
	CFGA_OP_TEST,
	CFGA_OP_LIST,
	CFGA_OP_PRIVATE,
	CFGA_OP_HELP
} cfga_op_t;

/*
 * Names for -c functions
 */
static char *state_opts[] = {
	"",
	"insert",
	"remove",
	"connect",
	"disconnect",
	"configure",
	"unconfigure",
	NULL
};

/*
 * Attachment point specifier types.
 */
typedef enum {
	UNKNOWN_AP,
	LOGICAL_AP_ID,
	PHYSICAL_AP_ID,
	AP_TYPE
} cfga_ap_types_t;

/*
 * Confirm values.
 */
enum confirm { CONFIRM_DEFAULT, CONFIRM_NO, CONFIRM_YES };

/* Limit size of sysinfo return */
#define	SYSINFO_LENGTH	256
#define	YESNO_STR_MAX	127

/* exit codes */
#define	EXIT_OK		0
#define	EXIT_OPFAILED	1
#define	EXIT_NOTSUPP	2
#define	EXIT_ARGERROR	3

/* Macro to figure size of cfga_list_data items */
#define	SZ_EL(EL)	(sizeof ((struct cfga_list_data *)NULL)->EL)

/* Maximum number of fields in cfgadm output */
#define	N_FIELDS	(sizeof (all_fields)/sizeof (all_fields[0]))

/* printing format controls */
#define	DEF_SORT_FIELDS		"ap_id"

#define	DEF_COLS		"ap_id:type:r_state:o_state:condition"
#define	DEF_COLS2		NULL
#define	DEF_COLS_VERBOSE	"ap_id:r_state:o_state:condition:info"
#define	DEF_COLS2_VERBOSE	"status_time:type:busy:physid"
#define	DEF_DELIM		" "

/* listing field delimiter */
#define	FDELIM		':'
#define	ARG_DELIM	' '

/* listing lengths for various fields */
#define	STATE_WIDTH	12	/* longest - "disconnected" */
#define	COND_WIDTH	10	/* longest is the heading - "condition" */
#define	TIME_WIDTH	12
#define	TIME_P_WIDTH	14	/* YYYYMMDDhhmmss */
/*	Date and time	formats	*/
/*
 * b --- abbreviated month name
 * e --- day number
 * Y --- year in the form ccyy
 * H --- hour(24-hour version)
 * M --- minute
 */
#define	FORMAT1	 "%b %e  %Y"
#define	FORMAT2  "%b %e %H:%M"

/* listing control data */
struct sort_el {
	int reverse;
	struct field_info *fld;
};

struct print_col {
	int width;
	struct field_info *line1;
	struct field_info *line2;
};

/*
 * The first three types are used for filtering and the last for sorting.
 */
typedef enum {
	CFGA_MATCH_PARTIAL,	/* pass if a partial match */
	CFGA_MATCH_EXACT,	/* pass only if an exact match */
	CFGA_MATCH_NOFILTER,	/* pass all. Not valid user input */
	CFGA_MATCH_ORDER	/* compare and return relative order */
} match_type_t;

struct field_info {
	char *name;
	char *heading;
	int width;
	int (*compare)(struct cfga_list_data *, struct cfga_list_data *,
	    match_type_t);
	void (*printfn)(struct cfga_list_data *, int, char *);
	cfga_err_t (*set_filter)(struct cfga_list_data *, const char *);
};

/* list option strings */
static char *list_options[] = {
#define	LIST_SORT	0
	"sort",
#define	LIST_COLS	1
	"cols",
#define	LIST_COLS2	2
	"cols2",
#define	LIST_DELIM	3
	"delim",
#define	LIST_NOHEADINGS	4
	"noheadings",
#define	LIST_SELECT	5
	"select",
#define	LIST_MATCH	6
	"match",
	NULL
};

/* Selection related */
typedef struct {
	char *arg;
	int resp; /* If set, this cmd arg received a response */
} ap_arg_t;

typedef struct {
	cfga_list_data_t *ldatap;
	int req; /* If set, this list_data was requested by user */
} ap_out_t;

/* Filtering related */
#define	CFGA_DEFAULT_MATCH	CFGA_MATCH_EXACT
#define	LEFT_PAREN	'('
#define	RIGHT_PAREN	')'
#define	CFGA_DEV_DIR	"/dev/cfg"
#define	SLASH		"/"
#define	EQUALS		"="

typedef enum {
	CFGA_PSTATE_INIT,
	CFGA_PSTATE_ATTR_DONE,
	CFGA_PSTATE_VAL_DONE,
	CFGA_PSTATE_ERR
} parse_state_t;

typedef struct match_cvt {
	char *str;
	match_type_t type;
} match_cvt_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _CFGADM_H */
