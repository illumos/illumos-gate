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

#ifndef _ZONECFG_H
#define	_ZONECFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * header file for zonecfg command
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>

#define	FALSE	0
#define	TRUE	1

typedef int bool;

#define	Z_ERR		1
#define	Z_USAGE		2
#define	Z_REPEAT	3

#define	CMD_ADD		0
#define	CMD_CANCEL	1
#define	CMD_COMMIT	2
#define	CMD_CREATE	3
#define	CMD_DELETE	4
#define	CMD_END		5
#define	CMD_EXIT	6
#define	CMD_EXPORT	7
#define	CMD_HELP	8
#define	CMD_INFO	9
#define	CMD_REMOVE	10
#define	CMD_REVERT	11
#define	CMD_SELECT	12
#define	CMD_SET		13
#define	CMD_VERIFY	14

#define	CMD_MIN		CMD_ADD
#define	CMD_MAX		CMD_VERIFY

/* resource types: increment RT_MAX when expanding this list */
#define	RT_UNKNOWN	0
#define	RT_ZONEPATH	1	/* really a property, but for info ... */
#define	RT_AUTOBOOT	2	/* really a property, but for info ... */
#define	RT_POOL		3	/* really a property, but for info ... */
#define	RT_FS		4
#define	RT_IPD		5
#define	RT_NET		6
#define	RT_DEVICE	7
#define	RT_RCTL		8
#define	RT_ATTR		9

#define	RT_MIN		RT_UNKNOWN
#define	RT_MAX		RT_ATTR

/* property types: increment PT_MAX when expanding this list */
#define	PT_UNKNOWN	0
#define	PT_ZONEPATH	1
#define	PT_AUTOBOOT	2
#define	PT_POOL		3
#define	PT_DIR		4
#define	PT_SPECIAL	5
#define	PT_TYPE		6
#define	PT_OPTIONS	7
#define	PT_ADDRESS	8
#define	PT_PHYSICAL	9
#define	PT_NAME		10
#define	PT_VALUE	11
#define	PT_MATCH	12
#define	PT_PRIV		13
#define	PT_LIMIT	14
#define	PT_ACTION	15
#define	PT_RAW		16

#define	PT_MIN		PT_UNKNOWN
#define	PT_MAX		PT_RAW

#define	MAX_EQ_PROP_PAIRS	3

#define	PROP_VAL_SIMPLE		0
#define	PROP_VAL_COMPLEX	1
#define	PROP_VAL_LIST		2

#define	PROP_VAL_MIN		PROP_VAL_SIMPLE
#define	PROP_VAL_MAX		PROP_VAL_LIST

/*
 * If any subcommand is ever modified to take more than three arguments,
 * this will need to be incremented.
 */
#define	MAX_SUBCMD_ARGS		3

typedef struct complex_property {
	int	cp_type;	/* from the PT_* list above */
	char	*cp_value;
	struct complex_property *cp_next;
} complex_property_t, *complex_property_ptr_t;

typedef struct list_property {
	char	*lp_simple;
	complex_property_ptr_t	lp_complex;
	struct list_property	*lp_next;
} list_property_t, *list_property_ptr_t;

typedef struct property_value {
	int	pv_type;	/* from the PROP_VAL_* list above */
	char	*pv_simple;
	complex_property_ptr_t	pv_complex;
	list_property_ptr_t	pv_list;
} property_value_t, *property_value_ptr_t;

typedef struct cmd {
	char	*cmd_name;
	void	(*cmd_handler)(struct cmd *);
	int	cmd_res_type;
	int	cmd_prop_nv_pairs;
	int	cmd_prop_name[MAX_EQ_PROP_PAIRS];
	property_value_ptr_t	cmd_property_ptr[MAX_EQ_PROP_PAIRS];
	int	cmd_argc;
	char	*cmd_argv[MAX_SUBCMD_ARGS + 1];
} cmd_t;

#define	HELP_USAGE	0x01
#define	HELP_SUBCMDS	0x02
#define	HELP_SYNTAX	0x04
#define	HELP_RESOURCES	0x08
#define	HELP_PROPS	0x10
#define	HELP_META	0x20
#define	HELP_NETADDR	0x40
#define	HELP_RES_SCOPE	0x80

#define	HELP_RES_PROPS	(HELP_RESOURCES | HELP_PROPS)

extern void add_func(cmd_t *);
extern void cancel_func(cmd_t *);
extern void commit_func(cmd_t *);
extern void create_func(cmd_t *);
extern void delete_func(cmd_t *);
extern void end_func(cmd_t *);
extern void exit_func(cmd_t *);
extern void export_func(cmd_t *);
extern void help_func(cmd_t *);
extern void info_func(cmd_t *);
extern void remove_func(cmd_t *);
extern void revert_func(cmd_t *);
extern void select_func(cmd_t *);
extern void set_func(cmd_t *);
extern void verify_func(cmd_t *);

extern cmd_t *alloc_cmd(void);
extern complex_property_ptr_t alloc_complex(void);
extern list_property_ptr_t alloc_list(void);
extern void free_cmd(cmd_t *cmd);
extern void free_complex(complex_property_ptr_t complex);
extern void free_list(list_property_ptr_t list);
extern void free_outer_list(list_property_ptr_t list);

extern void usage(bool verbose, uint_t flags);

extern FILE *yyin;

#ifdef __cplusplus
}
#endif

#endif	/* _ZONECFG_H */
