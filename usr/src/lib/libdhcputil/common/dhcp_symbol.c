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

#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <limits.h>
#include <errno.h>
#include <dhcp_impl.h>

#include "dhcp_symbol.h"

/*
 * The following structure and table are used to define the attributes
 * of a DHCP symbol category.
 */
typedef struct dsym_cat {
	char		*dc_string;	/* string value for the category */
	int		dc_minlen;	/* min. chars of dc_string to match */
	dsym_category_t	dc_id;		/* numerical value for the category */
	boolean_t	dc_dhcptab;	/* valid for dhcptab use? */
	ushort_t	dc_min;		/* minimum valid code */
	ushort_t	dc_max;		/* maximum valid code */
} dsym_cat_t;

static dsym_cat_t cats[] = {
	{ "Extend", 6, DSYM_EXTEND, B_TRUE, DHCP_LAST_STD + 1,
		DHCP_SITE_OPT - 1 },
	{ "Vendor=", 6, DSYM_VENDOR, B_TRUE, DHCP_FIRST_OPT,
		DHCP_LAST_OPT },
	{ "Site", 4, DSYM_SITE, B_TRUE, DHCP_SITE_OPT, DHCP_LAST_OPT },
	{ "Standard", 8, DSYM_STANDARD, B_FALSE, DHCP_FIRST_OPT,
	    DHCP_LAST_STD },
	{ "Field", 5, DSYM_FIELD, B_FALSE, CD_PACKET_START,
		CD_PACKET_END },
	{ "Internal", 8, DSYM_INTERNAL, B_FALSE, CD_INTRNL_START,
	    CD_INTRNL_END }
};

/*
 * The following structure and table are used to define the attributes
 * of a DHCP symbol type.
 */
typedef struct dsym_type {
	char		*dt_string;	/* string value for the type */
	dsym_cdtype_t	dt_id;		/* numerical value for the type */
	boolean_t	dt_dhcptab;	/* valid for dhcptab use? */
} dsym_type_t;

static dsym_type_t types[] = {
	{ "ASCII", DSYM_ASCII, B_TRUE },
	{ "OCTET", DSYM_OCTET, B_TRUE },
	{ "IP", DSYM_IP, B_TRUE },
	{ "NUMBER", DSYM_NUMBER, B_TRUE },
	{ "BOOL", DSYM_BOOL, B_TRUE },
	{ "INCLUDE", DSYM_INCLUDE, B_FALSE },
	{ "UNUMBER8", DSYM_UNUMBER8, B_TRUE },
	{ "UNUMBER16", DSYM_UNUMBER16, B_TRUE },
	{ "UNUMBER24", DSYM_UNUMBER24, B_TRUE },
	{ "UNUMBER32", DSYM_UNUMBER32, B_TRUE },
	{ "UNUMBER64", DSYM_UNUMBER64, B_TRUE },
	{ "SNUMBER8", DSYM_SNUMBER8, B_TRUE },
	{ "SNUMBER16", DSYM_SNUMBER16, B_TRUE },
	{ "SNUMBER32", DSYM_SNUMBER32, B_TRUE },
	{ "SNUMBER64", DSYM_SNUMBER64, B_TRUE },
	{ "IPV6", DSYM_IPV6, B_TRUE },
	{ "DUID", DSYM_DUID, B_TRUE },
	{ "DOMAIN", DSYM_DOMAIN, B_TRUE }
};

/*
 * symbol delimiters and constants
 */
#define	DSYM_CLASS_DEL		" \t\n"
#define	DSYM_FIELD_DEL		","
#define	DSYM_VENDOR_DEL		'='
#define	DSYM_QUOTE		'"'

/*
 * dsym_trim(): trims all whitespace from either side of a string
 *
 *  input: char **: a pointer to a string to trim of whitespace.
 * output: none
 */

static void
dsym_trim(char **str)
{

	char *tmpstr = *str;

	/*
	 * Trim all whitespace from the front of the string.
	 */
	while (*tmpstr != '\0' && isspace(*tmpstr)) {
		tmpstr++;
	}

	/*
	 * Move the str pointer to first non-whitespace char.
	 */
	*str = tmpstr;

	/*
	 * Check case where the string is nothing but whitespace.
	 */
	if (*tmpstr == '\0') {

		/*
		 * Trim all whitespace from the end of the string.
		 */
		tmpstr = *str + strlen(*str) - 1;
		while (tmpstr >= *str && isspace(*tmpstr)) {
			tmpstr--;
		}

		/*
		 * terminate after last non-whitespace char.
		 */
		*(tmpstr+1) = '\0';
	}
}

/*
 * dsym_get_token(): strtok_r() like routine, except consecutive delimiters
 *                   result in an empty string
 *
 *   note: original string is modified
 *
 *  input: char *: string in which to search for tokens
 *         char *: list of possible token delimiter characters
 *         char **: location for next call to routine
 *         boolean_t: should delimiters be ignored if within quoted string?
 * output: char *: token, or NULL if no more tokens
 */

static char *
dsym_get_token(char *str, char *dels, char **lasts, boolean_t quote_support)
{

	char *ptr = str;
	char *del;
	boolean_t found = B_FALSE;
	boolean_t in_quote = B_FALSE;

	/*
	 * If incoming string has no tokens return a NULL
	 * pointer to signify no more tokens.
	 */
	if (*ptr == '\0') {
		return (NULL);
	}

	/*
	 * Loop until either a token has been identified or until end
	 * of string has been reached.
	 */
	while (!found && *ptr != '\0') {

		/*
		 * If pointer currently lies within a quoted string,
		 * then do not check for the delimiter.
		 */
		if (!in_quote) {
			for (del = dels; !found && *del != '\0'; del++) {
				if (*del == *ptr) {
					*ptr++ = '\0';
					found = B_TRUE;
				}
			}
		}

		/*
		 * If the pointer is pointing at a delimiter, then
		 * check to see if it points to at a quote and update
		 * the state appropriately.
		 */
		if (!found) {
			if (quote_support && *ptr == DSYM_QUOTE) {
				in_quote = !in_quote;
			}
			ptr++;
		}
	}

	*lasts = ptr;

	return (str);
}

/*
 * dsym_get_long(): given a numeric string, returns its long value
 *
 *  input: const char *: the numeric string
 *         long *: the return location for the long value
 * output: DSYM_SUCCESS, DSYM_VALUE_OUT_OF_RANGE or DSYM_SYNTAX_ERROR
 */

static dsym_errcode_t
dsym_get_long(const char *str, long *val)
{

	int ret = DSYM_SUCCESS;
	int i;

	for (i = 0; str[i] != '\0'; i++) {
		if (!isdigit(str[i])) {
			return (DSYM_SYNTAX_ERROR);
		}
	}

	errno = 0;
	*val = strtol(str, NULL, 10);
	if (errno != 0) {
		ret = DSYM_VALUE_OUT_OF_RANGE;
	}

	return (ret);
}

/*
 * dsym_free_classes(): frees the classes allocated by dsym_parse_classes()
 *
 *  input: dhcp_classes_t *: pointer to structure containing classes to free
 * output: none
 */

void
dsym_free_classes(dhcp_classes_t *classes)
{

	int i;

	if (classes->dc_names == NULL) {
		return;
	}

	for (i = 0; i < classes->dc_cnt; i++) {
		free(classes->dc_names[i]);
	}

	free(classes->dc_names);
	classes->dc_names = NULL;
	classes->dc_cnt = 0;
}

/*
 * dsym_parse_classes(): given a "Vendor" class string, builds and returns
 *                     the list of vendor classes
 *
 *  input: char *: the "Vendor" class string
 *         dhcp_classes_t *: pointer to the classes structure
 * output: DSYM_SUCCESS, DSYM_INVALID_CAT, DSYM_EXCEEDS_MAX_CLASS_SIZE,
 *         DSYM_EXCEEDS_CLASS_SIZE, DSYM_SYNTAX_ERROR, or DSYM_NO_MEMORY
 */

static dsym_errcode_t
dsym_parse_classes(char *ptr, dhcp_classes_t *classes_ret)
{

	char **classes = NULL;
	char *cp;
	int len;
	int ret = DSYM_SUCCESS;
	int i;

	while (*ptr != '\0') {
		if (*ptr == DSYM_VENDOR_DEL) {
			ptr++;
			break;
		}
		ptr++;
	}

	if (*ptr == '\0') {
	    return (DSYM_INVALID_CAT);
	}

	if (strlen(ptr) > DSYM_MAX_CLASS_SIZE) {
		return (DSYM_EXCEEDS_MAX_CLASS_SIZE);
	}

	dsym_trim(&ptr);
	classes_ret->dc_cnt = 0;
	for (i = 0; ret == DSYM_SUCCESS; i++) {
		cp = dsym_get_token(ptr, DSYM_CLASS_DEL, &ptr, B_TRUE);
		if (cp == NULL) {
			break;
		}

		len = strlen(cp);

		if (len == 0) {
			continue;
		} else if (len > DSYM_CLASS_SIZE) {
			ret = DSYM_EXCEEDS_CLASS_SIZE;
			continue;
		}

		if (cp[0] == DSYM_QUOTE && cp[len-1] != DSYM_QUOTE) {
			ret = DSYM_SYNTAX_ERROR;
			continue;
		}

		/* Strip off the quotes */
		if (cp[0] == DSYM_QUOTE) {
			cp[len-1] = '\0';
			cp++;
		}

		classes = realloc(classes_ret->dc_names,
		    (sizeof (char **)) * (classes_ret->dc_cnt + 1));
		if (classes == NULL ||
		    (classes[classes_ret->dc_cnt] = strdup(cp))
		    == NULL) {
			ret = DSYM_NO_MEMORY;
			continue;
		}
		classes_ret->dc_names = classes;
		classes_ret->dc_cnt++;
	}

	if (ret != DSYM_SUCCESS) {
		dsym_free_classes(classes_ret);
	}

	return (ret);
}

/*
 * dsym_get_cat_by_name(): given a category field, returns the pointer to its
 *                         entry in the internal category table.
 *
 *  input: const char *: the category name
 *         dsym_cat_t *: the return location for the pointer to the table entry
 *         boolean_t: case-sensitive name compare
 * output: int: DSYM_SUCCESS or DSYM_INVALID_CAT
 */

static dsym_errcode_t
dsym_get_cat_by_name(const char *cat, dsym_cat_t **entry, boolean_t cs)
{

	dsym_cat_t *entryp = NULL;
	int ret = DSYM_SUCCESS;
	int cnt = sizeof (cats) / sizeof (dsym_cat_t);
	int result;
	int len;
	int i;

	for (i = 0; i < cnt; i++) {

		len = cats[i].dc_minlen;
		if (cs) {
			result = strncmp(cat, cats[i].dc_string, len);
		} else {
			result = strncasecmp(cat, cats[i].dc_string, len);
		}

		if (result == 0) {
			entryp = &cats[i];
			break;
		}
	}

	if (entryp != NULL) {
		/*
		 * Special code required for the Vendor category, because we
		 * allow whitespace between the keyword and the delimiter.
		 * If there is no delimiter, then this is an illegal category.
		 */
		const char *ptr = cat + entryp->dc_minlen;
		if (entryp->dc_id == DSYM_VENDOR) {
			while (*ptr != '\0' && isspace(*ptr)) {
				ptr++;
			}
			if (*ptr != DSYM_VENDOR_DEL) {
				ret = DSYM_INVALID_CAT;
			}
		} else {
			if (*ptr != '\0') {
				ret = DSYM_INVALID_CAT;
			}
		}
	} else {
		ret = DSYM_INVALID_CAT;
	}

	if (ret == DSYM_SUCCESS) {
		*entry = entryp;
	}

	return (ret);
}

/*
 * dsym_parse_cat(): given a category field, returns the category value
 *                 Note: The category must be a valid dhcptab category.
 *
 *  input: const char *: a category field
 *         dsym_category_t *: the return location for the category value
 * output: int: DSYM_SUCCESS or DSYM_INVALID_CAT
 */

static dsym_errcode_t
dsym_parse_cat(const char *field, dsym_category_t *cat)
{

	dsym_cat_t *entry;
	int ret;

	ret = dsym_get_cat_by_name(field, &entry, B_TRUE);
	if (ret == DSYM_SUCCESS) {
		/*
		 * Since this routine is meant to be used to parse dhcptab
		 * symbol definitions, only a subset of the DHCP categories
		 * are valid in this context.
		 */
		if (entry->dc_dhcptab) {
			*cat = entry->dc_id;
		} else {
			ret = DSYM_INVALID_CAT;
		}
	}

	return (ret);
}

/*
 * dsym_parse_intrange(): given a DHCP integer field, returns the value
 *
 *  input: const char *: a DHCP code field
 *         int *: the return location for the value
 *         int: the minimum valid value
 *         int: the maximum valid value
 * output: int: DSYM_SUCCESS, DSYM_SYNTAX_ERROR, or DSYM_VALUE_OUT_OF_RANGE
 */

static dsym_errcode_t
dsym_parse_intrange(const char *field, int *intval, int min, int max)
{

	int ret;
	long longval;

	ret = dsym_get_long(field, &longval);
	if (ret == DSYM_SUCCESS) {
		if (longval < min || longval > max) {
			ret = DSYM_VALUE_OUT_OF_RANGE;
		} else {
			*intval = (int)longval;
		}
	}
	return (ret);
}

/*
 * dsym_validate_code(): given a symbol category and code, validates
 *                       that the code is valid for the category
 *
 *  input: dsym_category_t: the symbol category
 *         uint16_t: the symbol code
 * output: DSYM_SUCCESS, DSYM_INVALID_CAT or DSYM_CODE_OUT_OF_RANGE
 */

static dsym_errcode_t
dsym_validate_code(dsym_category_t cat, ushort_t code)
{

	int cnt = sizeof (cats) / sizeof (dsym_cat_t);
	int i;

	/*
	 * Find the category entry from the internal table.
	 */
	for (i = 0; i < cnt; i++) {
		dsym_cat_t *entry;
		if (cat == cats[i].dc_id) {
			entry = &cats[i];
			if (code < entry->dc_min || code > entry->dc_max) {
				return (DSYM_CODE_OUT_OF_RANGE);
			}
			return (DSYM_SUCCESS);
		}
	}

	return (DSYM_INVALID_CAT);
}

/*
 * dsym_validate_granularity(): given a symbol type, validates
 *                       	that the granularity is valid for the type
 *
 *  input: dsym_cdtype_t: the symbol type
 *         uchar_t: the symbol granularity
 * output: DSYM_SUCCESS or DSYM_VALUE_OUT_OF_RANGE
 */

static dsym_errcode_t
dsym_validate_granularity(dsym_cdtype_t type, uchar_t gran)
{
	/*
	 * We only need to check for a 0 with non-boolean types, as
	 * anything else is already validated by the ranges passed to
	 * dsym_parse_intrange() in dsym_parse_field().
	 */
	if (gran == 0 && type != DSYM_BOOL) {
		return (DSYM_VALUE_OUT_OF_RANGE);
	}
	return (DSYM_SUCCESS);
}

/*
 * dsym_get_type_by_name(): given a type field, returns the pointer to its
 *                          entry in the internal type table.
 *
 *  input: const char *: the type name
 *         dsym_type_t *: the return location for the pointer to the table entry
 *         boolean_t: case-sensitive name compare
 * output: int: DSYM_SUCCESS or DSYM_INVALID_TYPE
 */

static dsym_errcode_t
dsym_get_type_by_name(const char *type, dsym_type_t **entry, boolean_t cs)
{
	int cnt = sizeof (types) / sizeof (dsym_type_t);
	int result;
	int i;

	for (i = 0; i < cnt; i++) {

		if (cs) {
			result = strcmp(type, types[i].dt_string);
		} else {
			result = strcasecmp(type, types[i].dt_string);
		}

		if (result == 0) {
			*entry = &types[i];
			return (DSYM_SUCCESS);
		}
	}

	return (DSYM_INVALID_TYPE);
}

/*
 * dsym_parse_type(): given a DHCP type string, returns the type id
 *
 *  input: char *: a DHCP type string
 *         dsym_cdtype_t *: the return location for the type id
 * output: int: DSYM_SUCCESS or DSYM_INVALID_TYPE
 */

static dsym_errcode_t
dsym_parse_type(char *field, dsym_cdtype_t *type)
{

	dsym_type_t *entry;
	int ret;

	ret = dsym_get_type_by_name(field, &entry, B_TRUE);
	if (ret == DSYM_SUCCESS) {
		/*
		 * Since this routine is meant to be used to parse dhcptab
		 * symbol definitions, only a subset of the DHCP type
		 * are valid in this context.
		 */
		if (entry->dt_dhcptab) {
			*type = entry->dt_id;
		} else {
			ret = DSYM_INVALID_TYPE;
		}
	}

	return (ret);
}

/*
 * dsym_free_fields(): frees an array of fields allocated by
 *                     dsym_init_parser().
 *
 *  input: char **: array of fields to free
 * output: none
 */

void
dsym_free_fields(char **fields)
{
	int i;
	if (fields != NULL) {
		for (i = 0; i < DSYM_NUM_FIELDS; i++) {
			free(fields[i]);
		}
		free(fields);
	}
}

/*
 * dsym_close_parser(): free up all resources associated with the parser
 *
 *  input: char **: the fields allocated by dsym_init_parser()
 *         dhcp_symbol_t *: the structure populated by dsym_init_parser()
 * output: none
 */

void
dsym_close_parser(char **fields, dhcp_symbol_t *sym)
{
	dsym_free_fields(fields);
	dsym_free_classes(&sym->ds_classes);
}

/*
 * dsym_init_parser(): initializes the structures used to parse a symbol
 *                     value.
 *
 *  input: const char *: the symbol name
 *         const char *: the symbol value in dhcptab format
 *         char ***: the return location for the symbol fields
 *         dhcp_symbol_t *: the structure which eventually will
 *                          be the repository for the parsed symbol data
 * output: int: DSYM_SUCCESS, DYSM_NO_MEMORY, DSYM_NULL_FIELD or
 *              DSYM_TOO_MANY_FIELDS
 */

dsym_errcode_t
dsym_init_parser(const char *name, const char *value, char ***fields_ret,
    dhcp_symbol_t *sym)
{

	int ret = DSYM_SUCCESS;
	char *cp;
	char *next;
	char *field;
	char **fields;
	int i;

	/*
	 * Initialize the symbol structure.
	 */
	sym->ds_category = 0;
	sym->ds_code = 0;
	(void) strlcpy(sym->ds_name, name, DSYM_MAX_SYM_LEN);
	sym->ds_type = 0;
	sym->ds_gran = 0;
	sym->ds_max = 0;
	sym->ds_classes.dc_names = NULL;
	sym->ds_classes.dc_cnt = 0;

	if ((cp = strdup(value)) == NULL ||
	    (fields = calloc(DSYM_NUM_FIELDS, sizeof (char *))) == NULL) {
		ret = DSYM_NO_MEMORY;
	}

	next = cp;
	for (i = 0; ret == DSYM_SUCCESS && i < DSYM_NUM_FIELDS; i++) {

		field = dsym_get_token(next, DSYM_FIELD_DEL, &next,
			B_FALSE);

		if (field == NULL) {
			ret = DSYM_NULL_FIELD;
			continue;
		}

		dsym_trim(&field);

		if (strlen(field) == 0) {
			ret = DSYM_NULL_FIELD;
			continue;
		}

		if ((fields[i] = strdup(field)) == NULL) {
			ret = DSYM_NO_MEMORY;
			continue;
		}
	}

	if (ret == DSYM_SUCCESS &&
	    dsym_get_token(next, DSYM_FIELD_DEL, &next, B_FALSE) != NULL) {
		ret = DSYM_TOO_MANY_FIELDS;
	}

	if (ret != DSYM_SUCCESS) {
		dsym_free_fields(fields);
	} else {
		*fields_ret = fields;
	}

	free(cp);
	return (ret);
}

/*
 * dsym_parse_field(): parses the specified symbol field.
 *
 *  input: int: the field number to be parsed.
 *         char **: symbol fields initialized by dsym_init_parser()
 *         dhcp_symbol_t *: the structure which will be the repository
 *                          for the parsed field
 * output: int: DSYM_SUCCESS, DSYM_SYNTAX_ERROR, DSYM_CODE_OUT_OF_RANGE,
 *              DSYM_INVALID_CAT, DSYM_INVALID_TYPE, DSYM_EXCEEDS_CLASS_SIZE,
 *              DSYM_EXCEEDS_MAX_CLASS_SIZE, DSYM_NO_MEMORY,
 *              DSYM_INVALID_FIELD_NUM, DSYM_VALUE_OUT_OF_RANGE
 */

dsym_errcode_t
dsym_parse_field(int field_num, char **fields, dhcp_symbol_t *sym)
{

	int 	ret = DSYM_SUCCESS;
	int	intval;

	switch (field_num) {

	case DSYM_CAT_FIELD:
		ret = dsym_parse_cat(fields[field_num], &sym->ds_category);
		if (ret == DSYM_SUCCESS && sym->ds_category == DSYM_VENDOR) {
			ret = dsym_parse_classes(fields[field_num],
			    &sym->ds_classes);
		}
		break;

	case DSYM_CODE_FIELD:
		ret = dsym_parse_intrange(fields[field_num], &intval, 0,
		    USHRT_MAX);
		if (ret == DSYM_SUCCESS) {
			sym->ds_code = (ushort_t)intval;
			ret = dsym_validate_code(sym->ds_category,
			    sym->ds_code);
		}
		break;

	case DSYM_TYPE_FIELD:
		ret = dsym_parse_type(fields[field_num], &sym->ds_type);
		break;

	case DSYM_GRAN_FIELD:
		ret = dsym_parse_intrange(fields[field_num], &intval, 0,
		    UCHAR_MAX);
		if (ret == DSYM_SUCCESS) {
			sym->ds_gran = (uchar_t)intval;
			ret = dsym_validate_granularity(sym->ds_type,
			    sym->ds_gran);
		}
		break;

	case DSYM_MAX_FIELD:
		ret = dsym_parse_intrange(fields[field_num], &intval, 0,
		    UCHAR_MAX);
		if (ret == DSYM_SUCCESS) {
			sym->ds_max = (uchar_t)intval;
		}
		break;
	default:
		ret = DSYM_INVALID_FIELD_NUM;
	}

	return (ret);
}

/*
 * dsym_parser(): parses a DHCP symbol value
 *
 *  input: char **: symbol fields initialized by dsym_init_parser()
 *         dhcp_symbol_t *: the structure which will be the repository
 *                          for the parsed field
 *         int *: last field processed
 *         boolean_t: parse all fields even though errors occur?
 * output: int: DSYM_SUCCESS, DSYM_SYNTAX_ERROR, DSYM_CODE_OUT_OF_RANGE,
 *              DSYM_INVALID_CAT, DSYM_INVALID_TYPE, DSYM_EXCEEDS_CLASS_SIZE,
 *              DSYM_EXCEEDS_MAX_CLASS_SIZE, DSYM_NO_MEMORY
 *              DSYM_INVALID_FIELD_NUM, DSYM_VALUE_OUT_OF_RANGE
 */

dsym_errcode_t
dsym_parser(char **fields, dhcp_symbol_t *sym, int *lastField,
    boolean_t bestEffort)
{

	int ret = DSYM_SUCCESS;
	int tret = DSYM_SUCCESS;
	int i;

	*lastField = -1;
	for (i = DSYM_FIRST_FIELD;
	    tret == DSYM_SUCCESS && i < DSYM_NUM_FIELDS; i++) {

		tret = dsym_parse_field(i, fields, sym);
		if (tret != DSYM_SUCCESS) {
			if (ret == DSYM_SUCCESS) {
				ret = tret;
			}
			if (bestEffort) {
				*lastField = i;
				tret = DSYM_SUCCESS;
			}
		}
	}

	if (*lastField == -1) {
		*lastField = i - 1;
	}

	return (ret);
}

/*
 * dsym_get_cat_id(): given a category string, return the associated id.
 *
 *  input: const char *: the category name
 *         dsym_category_t *: the return location for the id
 *         boolean_t: case-sensitive name compare
 * output: int: DSYM_SUCCESS or DSYM_INVALID_CAT
 */

dsym_errcode_t
dsym_get_cat_id(const char *cat, dsym_category_t *id, boolean_t cs)
{

	dsym_cat_t *entry;
	int ret;

	ret = dsym_get_cat_by_name(cat, &entry, cs);
	if (ret == DSYM_SUCCESS) {
		*id = entry->dc_id;
	}

	return (ret);
}

/*
 * dsym_get_code_ranges(): given a category field, returns its valid code
 *                         ranges.
 *
 *  input: const char *: the category name
 *         ushort *: return location for the minimum code value.
 *         ushort *: return location for the maximum code value.
 *         boolean_t: case-sensitive name compare
 * output: int: DSYM_SUCCESS or DSYM_INVALID_CAT
 */

dsym_errcode_t
dsym_get_code_ranges(const char *cat, ushort_t *min, ushort_t *max,
    boolean_t cs)
{

	dsym_cat_t *entry;
	int ret;

	ret = dsym_get_cat_by_name(cat, &entry, cs);
	if (ret == DSYM_SUCCESS) {
		*min = entry->dc_min;
		*max = entry->dc_max;
	}

	return (ret);
}

/*
 * dsym_get_type_id(): given a type string, return the associated type id.
 *
 *  input: const char *: the type name
 *         dsym_cdtype_t *: the return location for the id
 *         boolean_t: case-sensitive name compare
 * output: int: DSYM_SUCCESS or DSYM_INVALID_TYPE
 */

dsym_errcode_t
dsym_get_type_id(const char *type, dsym_cdtype_t *id, boolean_t cs)
{

	dsym_type_t *entry;
	int ret;

	ret = dsym_get_type_by_name(type, &entry, cs);
	if (ret == DSYM_SUCCESS) {
		*id = entry->dt_id;
	}

	return (ret);
}
