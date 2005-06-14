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
 * Copyright (c) 1994, 1997, 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#undef NIS /* confict in nis.h */
#undef T_UNSPEC		/* symbol conflict in nis.h -> ... -> sys/tiuser.h */

#include <rpcsvc/nis.h>
#include <rpcsvc/nislib.h>

/*
 * Defines for Nisplus alias handling functions
 */

#define	TABLE_TYPE "mail_aliases"

/*
 * Operating modes
 */

struct nis_mailias
{
	char *name;
	char *expn;
	char *comments;
	char *options;
};

typedef struct nis_mailias nis_mailias;

#define	FORWARD 0
#define	REVERSE 1

#define	MAILIAS_COLS	4	/* Number of cols in a mailias entry */
/*
 * These are the the columns in the NIS+ Table.
 */
#define	ALIAS_COL	0	/* the name of the alias */
#define	EXPANSION_COL	1	/* what the alias expands to */
#define	COMMENTS_COL	2	/* Human readable comments */
/*
 * Options column,
 * This consists of a list of
 * VARIABLE=VALUE, or VARIABLE names
 */
#define	OPTIONS_COL	3

#define	MAXLINE	2048		/* max line length */

#define	EN_len zo_data.objdata_u.en_data.en_cols.en_cols_len
#define	EN_colp zo_data.objdata_u.en_data.en_cols.en_cols_val
#define	EN_col_len(col) \
    zo_data.objdata_u.en_data.en_cols.en_cols_val[(col)].ec_value.ec_value_len
#define	EN_col_flags(col) \
    zo_data.objdata_u.en_data.en_cols.en_cols_val[(col)].ec_flags
#define	EN_col(col) \
    zo_data.objdata_u.en_data.en_cols.en_cols_val[(col)].ec_value.ec_value_val

/*
 * Macros which extract the Alias, Expansion, Comments, or Options column
 * of an nis alias table object
 */
#define	ALIAS(obj) ((obj)->EN_col(ALIAS_COL))
#define	EXPN(obj) ((obj)->EN_col(EXPANSION_COL))
#define	COMMENTS(obj) ((obj)->EN_col(COMMENTS_COL))
#define	OPTIONS(obj) ((obj)->EN_col(OPTIONS_COL))

#define	TA_val(col) zo_data.objdata_u.ta_data.ta_cols.ta_cols_val[(col)]

extern int check_table(nis_name mapname, nis_name domain);

extern void nis_mailias_add(nis_mailias a, nis_name alias_map, nis_name domain);

extern void nis_mailias_change(nis_mailias a, nis_name alias_map,
				nis_name domain);

extern void nis_mailias_delete(nis_mailias a, nis_name alias_map,
				nis_name domain);

extern void nis_mailias_edit(FILE *fp, nis_name map, nis_name domain);

extern void nis_mailias_init(nis_name map, nis_name domain);

extern void nis_mailias_list(FILE *fp, nis_name map, nis_name domain);

extern nis_result *nis_mailias_match(char *name, nis_name map,
					nis_name domain, int qtype);

extern nis_object *mailias_make_entry(struct nis_mailias a,
					nis_name map, nis_name domain);

extern void mailias_print(FILE *fp, nis_object *obj);

extern int print_comments;  /* Tells us whether to print comments and OPTIONS */
int print_comments;
