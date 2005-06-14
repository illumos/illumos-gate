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
 * Copyright 1994-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nisplus.h"

#include <ctype.h>
#include <pwd.h>
#include <search.h>
#include <nsswitch.h>

static void		space_rm();
static nis_object	*mailias_make_table(nis_name name, nis_name domain);

/*
 * Mailias_print(FILE *fp, nis_object *obj)
 *   takes an nis_object * which points to an nis mail alias
 *   object and prints to the file pointed to by fp.
 */

void
mailias_print(fp, obj)
	FILE *fp;
	nis_object *obj;
{
	char *val;
	char *c, *o;

	/*
	 * Need to print out an empty comments field if there's no
	 * comments but there are OPTIONS
	 */

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ)
		return;

	if (obj->EN_len != MAILIAS_COLS) {
		fprintf(fp, "warning: alias map has %d cols should have %d\n",
			obj->EN_len, MAILIAS_COLS);
		return;
	}

	val = ALIAS(obj);
	fprintf(fp, "%s: ", val? val: "");

	val = EXPN(obj);
	fprintf(fp, "%s", val? val: "");

	c = COMMENTS(obj) ? COMMENTS(obj) : "";
	o = OPTIONS(obj) ? OPTIONS(obj) : "";

	if (print_comments && !(*c == '\0' && *o == '\0')) {
		fprintf(fp, "#%s#%s", c, o);
	}
	fprintf(fp, "\n");
}

nis_result *
nis_mailias_match(name, map, domain, field)
	char *name;
	nis_name domain;
	nis_name map;
	int field;
{
	nis_result *res;

	char qbuf[MAXLINE + NIS_MAXNAMELEN];

	name = strdup(name);
	space_rm(name);

	if (!check_table(map, domain)) {
		res = (nis_result *)malloc(sizeof (nis_result));
		if (res == NULL) {
			perror(NULL);
			exit(-1);
		}
		res->status = NIS_NOTFOUND;
		free(name);
		return (res);
	}
	switch (field) {
	case EXPANSION_COL:
		(void) snprintf(qbuf, sizeof (qbuf), "[expansion=%s],%s.%s",
		    name, map, domain);
		break;
	case ALIAS_COL:
	default:
		(void) snprintf(qbuf, sizeof (qbuf), "[alias=%s],%s.%s", name,
		    map, domain);
		break;
	}
	res = nis_list(qbuf,  FOLLOW_LINKS | FOLLOW_PATH, NULL, NULL);
	free(name);
	return (res);
}

/*
 * nis_mailias_init(nis_name domain, nis_name map)
 *    initialiases an alias map in the given domain and gives the map
 *    the name passed to it in the second parameter.  This is usually used
 *    with the current domain and on the map mail_aliases
 */
void
nis_mailias_init(map, domain)
	nis_name domain;
	nis_name map;
{
	nis_object *ntable;
	nis_result *res;
	char name_buf[NIS_MAXNAMELEN];

	if (check_table(map, domain)) {
		fprintf(stderr, "Alias table %s.%s already exists\n",
			map, domain);
		exit(-1);
	}

	ntable = mailias_make_table(map, domain);
	(void) snprintf(name_buf, sizeof (name_buf), "%s.%s", map, domain);
	res = nis_add(name_buf, ntable);
	if (res->status != NIS_SUCCESS) {
		fprintf(stderr, "NIS alias map creation failed: %d\n",
			res->status);
		exit(-1);
	}
}

/*
 * nis_mailias_add( nis_mailias a, nis_name alias_map, nis_name domain)
 * adds the alias entry a to the map alias_map in domain "domain".
 * e.g. nis_mailias_add( a, "mail_aliases", "Eng.Sun.COM.");
 */
void
nis_mailias_add(a, alias_map, domain)
	nis_mailias a;
	nis_name alias_map;
	nis_name domain;
{
	nis_result *res;
	nis_object *a_entry;
	char name_buf[MAXLINE + NIS_MAXNAMELEN];

	space_rm(a.name);

	res = nis_mailias_match(a.name, alias_map, domain, ALIAS_COL);
	if (res->status == NIS_SUCCESS) {
		fprintf(stderr, "alias %s: is already in the map\n", a.name);
		exit(-1);
	}
	a_entry = mailias_make_entry(a, alias_map, domain);
	(void) snprintf(name_buf, sizeof (name_buf), "%s.%s", alias_map,
	    domain);
	res = nis_add_entry(name_buf, a_entry, 0);
	if (res->status != NIS_SUCCESS) {
		fprintf(stderr, "NIS alias add failed: %d\n", res->status);
		exit(-1);
	}
}


/*
 * nis_mailias_delete( nis_mailias a, nis_name alias_map, nis_name domain)
 * removes the alias entry a from the table alias_map in domain "domain".
 * e.g. nis_mailias_delete( a, "mail_aliases", "Eng.Sun.COM.");
 */
void
nis_mailias_delete(a, alias_map, domain)
	nis_mailias a;
	nis_name alias_map;
	nis_name domain;
{
	nis_result *res;
	char name_buf[MAXLINE + NIS_MAXNAMELEN];

	space_rm(a.name);

	res = nis_mailias_match(a.name, alias_map, domain, ALIAS_COL);
	if (res->status != NIS_SUCCESS) {
		fprintf(stderr, "alias %s: not found in the map\n", a.name);
		exit(-1);
	}

	(void) snprintf(name_buf, sizeof (name_buf), "%s.%s", alias_map,
	    domain);
	res = nis_remove_entry(name_buf, NIS_RES_OBJECT(res), 0);
	if (res->status != NIS_SUCCESS) {
		fprintf(stderr, "NIS alias remove failed: %d\n", res->status);
		exit(-1);
	}

}

/*
 * nis_mailias_change( nis_mailias a, nis_name alias_map, nis_name domain)
 * changes the alias entry a in the table alias_map in domain "domain".
 * e.g. nis_mailias_change( a, "mail_aliases", "Eng.Sun.COM.");
 */
void
nis_mailias_change(a, alias_map, domain)
	nis_mailias a;
	nis_name alias_map;
	nis_name domain;
{
	nis_result *res;
	char name_buf[MAXLINE + NIS_MAXNAMELEN];
	char *val;

	space_rm(a.name);

	res = nis_mailias_match(a.name, alias_map, domain, ALIAS_COL);
	if (res->status != NIS_SUCCESS) {
		fprintf(stderr, "alias %s: not found in the map\n", a.name);
		exit(-1);
	}

	space_rm(a.expn);

	val = a.expn ? a.expn : "";
	NIS_RES_OBJECT(res)->EN_col(EXPANSION_COL) = val;
	NIS_RES_OBJECT(res)->EN_col_len(EXPANSION_COL) = strlen(val) + 1;
	NIS_RES_OBJECT(res)->EN_col_flags(EXPANSION_COL) = EN_MODIFIED;

	val = a.comments ? a.comments: "";

	NIS_RES_OBJECT(res)->EN_col(COMMENTS_COL) = val;
	NIS_RES_OBJECT(res)->EN_col_len(COMMENTS_COL) = strlen(val) + 1;
	NIS_RES_OBJECT(res)->EN_col_flags(COMMENTS_COL) = EN_MODIFIED;

	val = a.options ? a.options : "";
	NIS_RES_OBJECT(res)->EN_col(OPTIONS_COL) = val;
	NIS_RES_OBJECT(res)->EN_col_len(OPTIONS_COL) = strlen(val) + 1;
	NIS_RES_OBJECT(res)->EN_col_flags(OPTIONS_COL) = EN_MODIFIED;

	(void) snprintf(name_buf, sizeof (name_buf), "[alias=%s],%s.%s", a.name,
	    alias_map, domain);
	res = nis_modify_entry(name_buf, NIS_RES_OBJECT(res), 0);
	if (res->status != NIS_SUCCESS) {
		fprintf(stderr, "NIS alias modify failed: %d\n", res->status);
		exit(-1);
	}
}

/*
 * Makes and Nis_alias table entry object, given 4 (possibly NULL)
 * values to put in the columns.
 */
nis_object *
mailias_make_entry(a, name, domain)
	nis_mailias a;
	nis_name name;
	nis_name domain;
{
	nis_object *ret;
	char name_buf[NIS_MAXNAMELEN];

	space_rm(a.name);

	ret = (nis_object *)malloc(sizeof (nis_object));
	if (ret == NULL) {
		perror(NULL);
		exit(-1);
	}
	ret->zo_name = name;
	(void) snprintf(name_buf, sizeof (name_buf), "%s.%s",
	    (getpwuid(getuid())->pw_name), domain);
	ret->zo_owner = strdup(name_buf);
	ret->zo_group = "";
	ret->zo_domain = domain;
	ret->zo_access = DEFAULT_RIGHTS;
	ret->zo_ttl = 24 * 60 * 60;

	ret->zo_data.zo_type = NIS_ENTRY_OBJ;
	ret->EN_data.en_type = TABLE_TYPE;
	ret->EN_len = MAILIAS_COLS;

	ret->EN_colp = (entry_col *)malloc(MAILIAS_COLS *
					    sizeof (struct entry_col));
	if (ret->EN_colp == NULL) {
		perror(NULL);
		exit(-1);
	}
	ret->EN_col(ALIAS_COL) = a.name ? a.name : "";
	ret->EN_col_len(ALIAS_COL) = strlen(ret->EN_col(ALIAS_COL)) + 1;

	space_rm(a.expn);

	ret->EN_col(EXPANSION_COL) = a.expn ? a.expn : "";
	ret->EN_col_len(EXPANSION_COL) =
		strlen(ret->EN_col(EXPANSION_COL)) + 1;

	ret->EN_col(COMMENTS_COL) = a.comments ? a.comments : "";
	ret->EN_col_len(COMMENTS_COL) = strlen(ret->EN_col(COMMENTS_COL)) + 1;

	ret->EN_col(OPTIONS_COL) = a.options ? a.options : "";
	ret->EN_col_len(OPTIONS_COL) =	strlen(ret->EN_col(OPTIONS_COL)) + 1;

	return (ret);
}

/*
 * Makes and Nis_alias table entry object, given 4 (possibly NULL)
 * values to put in the columns.
 */
nis_object *
mailias_make_table(name, domain)
	nis_name name;
	nis_name domain;
{
	nis_object *ret;
	char name_buf[NIS_MAXNAMELEN];

	ret = (nis_object *)malloc(sizeof (nis_object));
	if (ret == NULL) {
		perror(NULL);
		exit(-1);
	}
	ret->zo_name = strdup(name);
	(void) snprintf(name_buf, sizeof (name_buf), "%s.%s",
	    (getpwuid(getuid())->pw_name), domain);
	ret->zo_owner = strdup(name_buf);
	ret->zo_group = "";
	ret->zo_domain = strdup(domain);
	ret->zo_access = DEFAULT_RIGHTS;
	ret->zo_ttl = 24 * 60 * 60;

	ret->zo_data.zo_type = NIS_TABLE_OBJ;
	ret->TA_data.ta_type = strdup(TABLE_TYPE);
	ret->TA_data.ta_maxcol = MAILIAS_COLS;

	ret->TA_data.ta_sep = ' ';
	ret->TA_data.ta_cols.ta_cols_len = MAILIAS_COLS;
	ret->TA_data.ta_path = "";
	ret->TA_data.ta_cols.ta_cols_val =
		(struct table_col *)malloc(sizeof (table_col) * MAILIAS_COLS);
	if (ret->TA_data.ta_cols.ta_cols_val == NULL) {
		perror(NULL);
		exit(-1);
	}

	ret->TA_val(ALIAS_COL).tc_name = "alias";
	ret->TA_val(ALIAS_COL).tc_flags = TA_SEARCHABLE;
	ret->TA_val(ALIAS_COL).tc_rights = DEFAULT_RIGHTS;

	ret->TA_val(EXPANSION_COL).tc_name = "expansion";
	ret->TA_val(EXPANSION_COL).tc_flags = TA_SEARCHABLE;
	ret->TA_val(EXPANSION_COL).tc_rights = DEFAULT_RIGHTS;

	ret->TA_val(COMMENTS_COL).tc_name = "comments";
	ret->TA_val(COMMENTS_COL).tc_flags = 0;
	ret->TA_val(COMMENTS_COL).tc_rights = DEFAULT_RIGHTS;

	ret->TA_val(OPTIONS_COL).tc_name = "options";
	ret->TA_val(OPTIONS_COL).tc_flags = 0;
	ret->TA_val(OPTIONS_COL).tc_rights = DEFAULT_RIGHTS;

	return (ret);
}

#define	UNINIT 3

/*
 * Check to see if the aliases database is initialized/installed in
 * the proper format.
 *
 */
int
check_table(nis_name mapname, nis_name domain)
{
	nis_result *res = NULL;
	static int succeeded = UNINIT;

	char qbuf[MAXLINE + NIS_MAXNAMELEN];

	if (succeeded != UNINIT)
		return (succeeded);

	(void) snprintf(qbuf, sizeof (qbuf), "%s.%s", mapname, domain);
	while (res == NULL || res->status != NIS_SUCCESS) {
		res = nis_lookup(qbuf, FOLLOW_LINKS);

		switch (res->status) {

		case NIS_SUCCESS:
		case NIS_TRYAGAIN:
		case NIS_RPCERROR:
			break;
		default:	/* all other nisplus errors */
			succeeded = FALSE;
			return (FALSE);
		};
		sleep(2);	/* try not overwhelm hosed server */
	}

	if (NIS_RES_NUMOBJ(res) != 1 &&
	    (NIS_RES_OBJECT(res)->zo_data.zo_type != NIS_TABLE_OBJ)) {
		succeeded = FALSE;
		return (FALSE);
	}
	succeeded = TRUE;
	return (TRUE);

}

/*
 *  space_rm -- takes a pointer to a string as its input.  It removes
 *		all spaces and tabs from that string, except for those
 *		inside double quotes.
 */

void
space_rm(char *str)
{
	char *t1;
	int in_comment = FALSE;

	t1 = str;
	while (*str != '\0') {
		if (*str == '"')
			in_comment = !in_comment;
		if (in_comment || !isspace(*str))
			*t1++ = *str++;
		else
			str++;
	}
	*t1 = '\0';
}
