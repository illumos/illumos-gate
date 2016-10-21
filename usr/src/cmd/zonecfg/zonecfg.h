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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _ZONECFG_H
#define	_ZONECFG_H

/*
 * header file for zonecfg command
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>

#define	Z_ERR		1
#define	Z_USAGE		2
#define	Z_REPEAT	3

#define	CMD_ADD		0
#define	CMD_CANCEL	1
#define	CMD_CLEAR	2
#define	CMD_COMMIT	3
#define	CMD_CREATE	4
#define	CMD_DELETE	5
#define	CMD_END		6
#define	CMD_EXIT	7
#define	CMD_EXPORT	8
#define	CMD_HELP	9
#define	CMD_INFO	10
#define	CMD_REMOVE	11
#define	CMD_REVERT	12
#define	CMD_SELECT	13
#define	CMD_SET		14
#define	CMD_VERIFY	15

#define	CMD_MIN		CMD_ADD
#define	CMD_MAX		CMD_VERIFY

/* resource types: increment RT_MAX when expanding this list */
#define	RT_UNKNOWN	0
#define	RT_ZONENAME	1	/* really a property, but for info ... */
#define	RT_ZONEPATH	2	/* really a property, but for info ... */
#define	RT_AUTOBOOT	3	/* really a property, but for info ... */
#define	RT_POOL		4	/* really a property, but for info ... */
#define	RT_FS		5
#define	RT_NET		6
#define	RT_DEVICE	7
#define	RT_RCTL		8
#define	RT_ATTR		9
#define	RT_DATASET	10
#define	RT_LIMITPRIV	11	/* really a property, but for info ... */
#define	RT_BOOTARGS	12	/* really a property, but for info ... */
#define	RT_BRAND	13	/* really a property, but for info ... */
#define	RT_DCPU		14
#define	RT_MCAP		15
#define	RT_MAXLWPS	16	/* really a rctl alias property, but for info */
#define	RT_MAXSHMMEM	17	/* really a rctl alias property, but for info */
#define	RT_MAXSHMIDS	18	/* really a rctl alias property, but for info */
#define	RT_MAXMSGIDS	19	/* really a rctl alias property, but for info */
#define	RT_MAXSEMIDS	20	/* really a rctl alias property, but for info */
#define	RT_SHARES	21	/* really a rctl alias property, but for info */
#define	RT_SCHED	22	/* really a property, but for info ... */
#define	RT_IPTYPE	23	/* really a property, but for info ... */
#define	RT_PCAP		24
#define	RT_HOSTID	25	/* really a property, but for info ... */
#define	RT_ADMIN	26
#define	RT_FS_ALLOWED	27
#define	RT_MAXPROCS	28	/* really a rctl alias property, but for info */
#define	RT_SECFLAGS	29

#define	RT_MIN		RT_UNKNOWN
#define	RT_MAX		RT_SECFLAGS

/* property types: increment PT_MAX when expanding this list */
#define	PT_UNKNOWN	0
#define	PT_ZONENAME	1
#define	PT_ZONEPATH	2
#define	PT_AUTOBOOT	3
#define	PT_POOL		4
#define	PT_DIR		5
#define	PT_SPECIAL	6
#define	PT_TYPE		7
#define	PT_OPTIONS	8
#define	PT_ADDRESS	9
#define	PT_PHYSICAL	10
#define	PT_NAME		11
#define	PT_VALUE	12
#define	PT_MATCH	13
#define	PT_PRIV		14
#define	PT_LIMIT	15
#define	PT_ACTION	16
#define	PT_RAW		17
#define	PT_LIMITPRIV	18
#define	PT_BOOTARGS	19
#define	PT_BRAND	20
#define	PT_NCPUS	21
#define	PT_IMPORTANCE	22
#define	PT_SWAP		23
#define	PT_LOCKED	24
#define	PT_SHARES	25
#define	PT_MAXLWPS	26
#define	PT_MAXSHMMEM	27
#define	PT_MAXSHMIDS	28
#define	PT_MAXMSGIDS	29
#define	PT_MAXSEMIDS	30
#define	PT_MAXLOCKEDMEM	31
#define	PT_MAXSWAP	32
#define	PT_SCHED	33
#define	PT_IPTYPE	34
#define	PT_DEFROUTER	35
#define	PT_HOSTID	36
#define	PT_USER		37
#define	PT_AUTHS	38
#define	PT_FS_ALLOWED	39
#define	PT_MAXPROCS	40
#define	PT_ALLOWED_ADDRESS	41
#define	PT_DEFAULT	42
#define	PT_LOWER	43
#define	PT_UPPER	44

#define	PT_MIN		PT_UNKNOWN
#define	PT_MAX		PT_UPPER

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
extern void clear_func(cmd_t *);

extern cmd_t *alloc_cmd(void);
extern complex_property_ptr_t alloc_complex(void);
extern list_property_ptr_t alloc_list(void);
extern void free_cmd(cmd_t *cmd);
extern void free_complex(complex_property_ptr_t complex);
extern void free_list(list_property_ptr_t list);
extern void free_outer_list(list_property_ptr_t list);

extern void usage(boolean_t verbose, uint_t flags);

extern FILE *yyin;
extern char *res_types[];
extern char *prop_types[];

/*
 * NOTE: Only Lex and YACC should use the following functions.
 */
extern void assert_no_unclaimed_tokens(void);
extern char *claim_token(char *);

#ifdef __cplusplus
}
#endif

#endif	/* _ZONECFG_H */
