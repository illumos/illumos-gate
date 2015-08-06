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
 * Copyright 2015 Gary Mills
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <locale.h>

#include "ldap_parse.h"
#include "nis_parse_ldap_conf.h"
#include "nis_parse_ldap_yp_util.h"
#include "nis_parse_ldap_util.h"

/* other attribute functions */
static char *getIndex(const char **s_cur, const char *end_s);
static bool_t get_ttls(const char *s, const char *s_end,
    __nis_table_mapping_t *t_mapping);
static __nis_object_dn_t *parse_object_dn(const char *s, const char *end);
static int	parse_name_fields(const char *name_s, const char *name_s_end,
	__nis_table_mapping_t *t_mapping);
static void get_mapping_rule(const char *s, int len,
    __nis_table_mapping_t *tbl, bool_t to_ldap);
static bool_t get_deleteDisp(const char *s_begin, const char *s_end,
    __nis_object_dn_t *obj_dn);

/* mapping rule functions */
static const char *get_lhs(const char *s, const char *end_s,
    __nis_mapping_rlhs_t *lhs, __nis_mapping_item_type_t item_type);
static const char *get_lhs_match(const char *s, const char *end_s,
    __nis_mapping_rlhs_t *lhs, __nis_mapping_item_type_t item_type);
static const char *get_lhs_paren_item(const char *s, const char *end_s,
    __nis_mapping_rlhs_t *lhs, __nis_mapping_item_type_t item_type);
static const char *get_rhs(const char *s, const char *end_s,
    __nis_mapping_rlhs_t *lhs, __nis_mapping_item_type_t item_type);
static const char *get_mapping_item(const char *s, const char *end_s,
    __nis_mapping_item_t *item, __nis_mapping_item_type_t type);
static const char *get_print_mapping_element(const char *s,
    const char *end_s, char *fmt_string, __nis_mapping_element_t *e,
    __nis_mapping_item_type_t item_type);
static const char *get_subElement(const char *s, const char *end_s,
    __nis_mapping_sub_element_t *subelement,
    __nis_mapping_item_type_t type);
static bool_t get_mapping_format(const char *fmt_string,
    __nis_mapping_format_t **fmt, int *nfmt, int *numItems,
    bool_t print_mapping);
extern __yp_domain_context_t ypDomains;

/*
 * FUNCTION:	add_mapping_attribute
 *
 *	Adds the attribute value to __nis_table_mapping_t
 *	if the value is not yet set for the given database.
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		attribute number and value
 */

int
add_mapping_attribute(
	config_key		attrib_num,
	const char		*attrib_val,
	int			attrib_len,
	__nis_table_mapping_t	**table_mapping)
{
	const char		*s;
	const char		*attrib_end;
	const char		*db_id_end;
	const char		*begin_token;
	char			*index_string;
	__nis_object_dn_t	*objectDN;
	__nis_table_mapping_t	*t_mapping;
	__nis_table_mapping_t	*t;

	bool_t			new_mapping	= FALSE;
	int				nm;
	char			*tmp_dbId;

	attrib_end = attrib_val + attrib_len;
	for (s = attrib_val; s < attrib_end; s++)
		if (*s == COLON_CHAR)
			break;

	if (s == attrib_end || *attrib_val == COLON_CHAR) {
		p_error = parse_unexpected_data_end_rule;
		return (-1);
	}

	db_id_end = s;
	while (s > attrib_val && is_whitespace(s[-1]))
		s--;

	if (s == attrib_val) {
		p_error = parse_unexpected_data_end_rule;
		return (-1);
	}

	if (yp2ldap) {
		tmp_dbId = s_strndup(attrib_val, s - attrib_val);
		if (tmp_dbId == NULL) {
			p_error = parse_no_mem_error;
			return (-1);
		}
		if (strchr(tmp_dbId, COMMA_CHAR)) {
			/* domain explicitly specified */
			nm = check_domain_specific_order(tmp_dbId,
				attrib_num, *table_mapping, &ypDomains);
			/*
			 * No logging is needed here, as
			 * check_domain_specific_order
			 * will log any appropriate errors.
			 */
			if (nm != 0) {
				free(tmp_dbId);
				return (-1);
			}
		}
		free(tmp_dbId);
	}

	if ((t_mapping = find_table_mapping(attrib_val,
			s - attrib_val, *table_mapping)) == NULL) {
		/* No mapping with this id, create one */
		t_mapping = (__nis_table_mapping_t *)
			s_calloc(1, sizeof (__nis_table_mapping_t));

		if (t_mapping == NULL) {
			p_error = parse_no_mem_error;
			return (-1);
		}
		(void) initialize_table_mapping(t_mapping);

		/* dbId is the label before the colon */
		t_mapping->dbId = s_strndup(attrib_val, s - attrib_val);
		if (t_mapping->dbId == NULL) {
			p_error = parse_no_mem_error;
			free(t_mapping);
			return (-1);
		}
		new_mapping = TRUE;
	} else {
		/* a table mapping already exists, use it */
		new_mapping = FALSE;
	}

	s = db_id_end + 1;
	while (s < attrib_end && is_whitespace(*s))
		s++;

	switch (attrib_num) {
		case key_yp_map_flags:
			if (t_mapping->usedns_flag != 0 ||
				t_mapping->securemap_flag != 0) {
				warn_duplicate_map(t_mapping->dbId,
					attrib_num);
				break;
			}
			while (is_whitespace(*s) && s < attrib_end)
				s++;
			while (s < attrib_end) {
				if (s < attrib_end && *s == 'b')
					t_mapping->usedns_flag = 1;
				if (s < attrib_end && *s == 's')
					t_mapping->securemap_flag = 1;
				s++;
			}
			break;
		case key_yp_comment_char:
			if (t_mapping->commentChar !=
				DEFAULT_COMMENT_CHAR) {
				warn_duplicate_map(t_mapping->dbId, attrib_num);
				break;
			}
			while (is_whitespace(*s) && s < attrib_end)
				s++;
			if (s < attrib_end && (s+1) < attrib_end &&
				(s+2) <= attrib_end) {
				while (is_whitespace(attrib_end[-1]))
					attrib_end--;
				while (*s != SINGLE_QUOTE_CHAR)
					s++;
				if (*s == SINGLE_QUOTE_CHAR &&
					*(s+2) == SINGLE_QUOTE_CHAR) {
					t_mapping->commentChar = *(s+1);
				} else if (*s == SINGLE_QUOTE_CHAR &&
					*(s+1) == SINGLE_QUOTE_CHAR) {
					t_mapping->commentChar = NULL;
				} else {
					/* anything else is an error */
					p_error = parse_bad_yp_comment_error;
				}
				break;
			} else {
				p_error = parse_bad_yp_comment_error;
				break;
			}
		case key_yp_repeated_field_separators:
			while (s < attrib_end && is_whitespace(*s))
				s++;
			if (s < attrib_end) {
				while (is_whitespace(attrib_end[-1]))
					attrib_end--;
				while (s < attrib_end &&
						*s != DOUBLE_QUOTE_CHAR)
					s++;
				s++;
				begin_token = s;
				while (s < attrib_end &&
						*s != DOUBLE_QUOTE_CHAR) {
					if (*s == ESCAPE_CHAR)
						s++;
					s++;
				}
				t_mapping->separatorStr =
					s_strndup(begin_token, s - begin_token);
				if (t_mapping->separatorStr == NULL)
					break;
			} else {
				p_error = parse_bad_field_separator_error;
			}
			break;
		case key_yp_name_fields:
		case key_yp_split_field:
			if (t_mapping->e || t_mapping->numSplits > 0) {
				warn_duplicate_map(t_mapping->dbId,
					attrib_num);
				break;
			}
			if (parse_name_fields(s, attrib_end, t_mapping)) {
				p_error = parse_bad_name_field;
			}
			break;
		case key_yp_db_id_map:
		case key_db_id_map:
			if (t_mapping->objName != NULL) {
				warn_duplicate_map(t_mapping->dbId, attrib_num);
				break;
			}

			if (s < attrib_end && *s == OPEN_BRACKET) {
				index_string = getIndex(&s, attrib_end);
				if (index_string == NULL)
					break;
				(void) parse_index(index_string,
					index_string + strlen(index_string),
					&t_mapping->index);
				free(index_string);
				if (p_error != no_parse_error)
					break;
			}
			while (is_whitespace(*s) && s < attrib_end)
				s++;
			if (s < attrib_end) {
				while (is_whitespace(attrib_end[-1]))
					attrib_end--;
				t_mapping->objName =
					s_strndup_esc(s, attrib_end - s);
			} else {
				if (yp2ldap) {
					p_error = parse_bad_map_error;
				} else {
					t_mapping->objName = s_strndup(s, 0);
				}
			}
			break;

		case key_yp_entry_ttl:
		case key_entry_ttl:
			if (t_mapping->initTtlLo != (time_t)NO_VALUE_SET) {
				warn_duplicate_map(t_mapping->dbId, attrib_num);
				break;
			}

			if (!get_ttls(s, attrib_end, t_mapping))
				p_error = parse_bad_ttl_format_error;
			break;

		case key_yp_ldap_object_dn:
		case key_ldap_object_dn:
			if (t_mapping->objectDN != NULL) {
				warn_duplicate_map(t_mapping->dbId, attrib_num);
				break;
			}
			objectDN = parse_object_dn(s, attrib_end);
			if (objectDN == NULL)
				break;
			t_mapping->objectDN = objectDN;
			t_mapping->seq_num = seq_num++;
			break;

		case key_nis_to_ldap_map:
		case key_nisplus_to_ldap_map:
			if (t_mapping->ruleToLDAP != 0) {
				warn_duplicate_map(t_mapping->dbId, attrib_num);
				break;
			}

			get_mapping_rule(s, attrib_end - s, t_mapping, TRUE);
			break;

		case key_ldap_to_nis_map:
		case key_ldap_to_nisplus_map:
			if (t_mapping->ruleFromLDAP != NULL) {
				warn_duplicate_map(t_mapping->dbId, attrib_num);
				break;
			}

			get_mapping_rule(s, attrib_end - s, t_mapping, FALSE);
			break;

		default:
			p_error = parse_internal_error;
			break;
	}
	if (p_error == no_parse_error) {
		if (new_mapping) {
			if (*table_mapping == NULL)
				*table_mapping = t_mapping;
			else {
				for (t = *table_mapping; t->next != NULL;
				    t = t->next)
					;
				t->next = t_mapping;
			}
		}
	} else {
		if (new_mapping)
			free_table_mapping(t_mapping);
	}
	return (p_error == no_parse_error ? 0 : -1);
}

/*
 * FUNCTION:	add_ypdomains_attribute
 *
 * Adds the yp domains information to the __yp_domain_context_t
 * structure.
 *
 * RETURN:		0 on success, -1 on failure
 *
 * INPUT:		attribute number and value
 */

int
add_ypdomains_attribute(
	config_key		attrib_num,
	const char		*attrib_val,
	int				attrib_len,
	__yp_domain_context_t	*ypDomains)
{
	const char 		*s;
	const char		*attrib_end;
	int				numDomains = 0;

	attrib_end = attrib_val + attrib_len;
	for (s = attrib_val; s < attrib_end; s++) {
		if (*s == COLON_CHAR) {
			break;
		}
	}
	while (s > attrib_val && is_whitespace(s[-1]))
		s--;

	if (s == attrib_val) {
		p_error = parse_unexpected_data_end_rule;
		return (-1);
	}

	if (ypDomains == NULL) {
		/*
		 * No point allocating. We cant return the resulting structure,
		 * so just return failure. Should not ever happen because we
		 * are always called with a pointer to the global ypDomains
		 * structure.
		 */
		return (-1);
	}

	switch (attrib_num) {
		case key_yp_domain_context:
			numDomains = ypDomains->numDomains;
			ypDomains->domainLabels =
				(char **)s_realloc(ypDomains->domainLabels,
				(numDomains + 1) *
				sizeof (ypDomains->domainLabels[0]));
			if (ypDomains->domainLabels == NULL) {
				p_error = parse_no_mem_error;
				free_yp_domain_context(ypDomains);
				break;
			}
			ypDomains->domainLabels[numDomains] =
				s_strndup(attrib_val, s - attrib_val);
			if (ypDomains->domainLabels[numDomains] == NULL) {
				p_error = parse_no_mem_error;
				free_yp_domain_context(ypDomains);
				break;
			}
			ypDomains->numDomains = numDomains + 1;
			while (s < attrib_end && is_whitespace(*s))
				s++;
			if (*s == COLON_CHAR)
				s++;
			while (s < attrib_end && is_whitespace(*s))
				s++;
			ypDomains->domains =
				(char **)s_realloc(ypDomains->domains,
				(numDomains + 1) *
				sizeof (ypDomains->domains[0]));
			if (ypDomains->domains == NULL) {
				p_error = parse_no_mem_error;
				free_yp_domain_context(ypDomains);
				break;
			}

			if (s < attrib_end) {
				while (is_whitespace(attrib_end[-1]))
					attrib_end--;
				ypDomains->domains[numDomains] =
					s_strndup_esc(s, attrib_end - s);
				if (ypDomains->domains[numDomains] == NULL) {
					p_error = parse_no_mem_error;
					free_yp_domain_context(ypDomains);
					break;
				}
			} else {
				p_error = parse_unexpected_yp_domain_end_error;
				free(ypDomains->domainLabels[numDomains]);
				ypDomains->domainLabels[numDomains] = NULL;
				ypDomains->numDomains--;
				free_yp_domain_context(ypDomains);
			}
			break;
		case key_yppasswdd_domains:
			ypDomains->yppasswddDomainLabels =
				(char **)s_realloc(
				ypDomains->yppasswddDomainLabels,
				(ypDomains->numYppasswdd + 1) *
				sizeof (ypDomains->yppasswddDomainLabels[0]));
			if (ypDomains->yppasswddDomainLabels == NULL) {
				p_error = parse_no_mem_error;
				break;
			}
			ypDomains->yppasswddDomainLabels
				[ypDomains->numYppasswdd] =
				s_strndup(attrib_val, s - attrib_val);
			if (ypDomains->yppasswddDomainLabels
				[ypDomains->numYppasswdd] == NULL) {
				p_error = parse_no_mem_error;
			}
			ypDomains->numYppasswdd++;
			break;
	}

	return (p_error == no_parse_error ? 0 : -1);
}

/*
 * FUNCTION:	get_ttls
 *
 *	Parse time to live attribute
 *
 * RETURN VALUE:	TRUE on success, FALSE on failure
 *
 * INPUT:		the attribute value
 */

static bool_t
get_ttls(
	const char		*s,
	const char		*s_end,
	__nis_table_mapping_t	*t_mapping)
{
	time_t		initTtlHi	= 0;
	time_t		initTtlLo	= 0;
	time_t		ttl		= 0;
	time_t		digit;

	/*
	 * attribute should be of the form
	 * initialTTLlo ":" initialTTLhi ":" runningTTL
	 */

	if (s == s_end) {
		p_error = parse_bad_ttl_format_error;
		return (FALSE);
	}

	if (isdigit(*s)) {
		while (s < s_end && isdigit(*s)) {
			digit = (*s++) - '0';
			if (WILL_OVERFLOW_TIME(initTtlLo, digit))
				initTtlLo = TIME_MAX;
			else
				initTtlLo = initTtlLo * 10 + digit;
		}
	} else {
		initTtlLo = ONE_HOUR;
	}

	while (s < s_end && is_whitespace(*s))
		s++;
	if (s + 1 >= s_end || *s++ != COLON_CHAR) {
		p_error = parse_bad_ttl_format_error;
		return (FALSE);
	}

	while (s < s_end && is_whitespace(*s))
		s++;
	if (isdigit(*s)) {
		while (s < s_end && isdigit(*s)) {
			digit = (*s++) - '0';
			if (WILL_OVERFLOW_TIME(initTtlHi, digit))
				initTtlHi = TIME_MAX;
			else
				initTtlHi = initTtlHi * 10 + digit;
		}
	} else {
		initTtlHi = initTtlLo;
	}

	while (s < s_end && is_whitespace(*s))
		s++;
	if (s >= s_end || *s++ != COLON_CHAR) {
		p_error = parse_bad_ttl_format_error;
		return (FALSE);
	}

	while (s < s_end && is_whitespace(*s))
		s++;
	if (isdigit(*s)) {
		while (s < s_end && isdigit(*s)) {
			digit = (*s++) - '0';
			if (WILL_OVERFLOW_TIME(ttl, digit))
				ttl = TIME_MAX;
			else
				ttl = ttl * 10 + digit;
		}
	} else {
		ttl = ONE_HOUR;
	}
	while (s < s_end && is_whitespace(*s))
		s++;
	if (s != s_end) {
		p_error = parse_bad_ttl_format_error;
		return (FALSE);
	}

	t_mapping->initTtlLo = initTtlLo;
	t_mapping->initTtlHi = initTtlHi;
	t_mapping->ttl = ttl;
	return (TRUE);
}

/*
 * FUNCTION:	parse_name_fields
 *
 * Parse yp name fields
 *
 * RETURN VALUE:	0 on success, non-zero on failure
 *
 * INPUTS:		attrib_value and attribute_end pointers.
 */

static int
parse_name_fields(const char *name_s,
	const char *name_s_end,
	__nis_table_mapping_t   *t_map)
{
	int	i, n = 0;
	int nElements = 0;
	int numSplits = 0;
	int parse_next_line = 1;
	int itm_count = 0;
	const char	*begin_fmt;
	const char	*end_fmt;
	const char	*begin_token;
	const char	*end_token;
	char	*fmt_string = NULL;
	__nis_mapping_format_t  *base = NULL;
	__nis_mapping_item_t    *item = NULL;
	__nis_mapping_element_t *elmnt = NULL;
	__nis_mapping_item_type_t   item_type = mit_nisplus;
	token_type	token;

	t_map->numColumns = 0;

	for (; parse_next_line > 0; parse_next_line--) {
		nElements = 0;
		item = NULL;
		base = NULL;
		while (name_s < name_s_end && *name_s != OPEN_PAREN_CHAR)
			name_s++;
		if (name_s == name_s_end) {
			p_error = parse_unexpected_data_end_rule;
			return (1);
		}
		while (name_s < name_s_end && *name_s != DOUBLE_QUOTE_CHAR)
			name_s++;
		if (name_s == name_s_end) {
			p_error = parse_unexpected_data_end_rule;
			return (1);
		}
		begin_fmt = ++name_s; /* start of format string */
		while (name_s < name_s_end && *name_s != DOUBLE_QUOTE_CHAR)
			name_s++;
		if (name_s == name_s_end) {
			p_error = parse_unexpected_data_end_rule;
			return (1);
		}
		end_fmt = name_s;
		fmt_string = s_strndup(begin_fmt, end_fmt - begin_fmt);
		if (fmt_string == NULL) {
			p_error = parse_no_mem_error;
			return (2);
		}
		if (!get_mapping_format(fmt_string, &base, &n, NULL, FALSE)) {
			p_error = parse_internal_error;
			free(fmt_string);
			fmt_string = NULL;
			return (3);
		}
		free(fmt_string);
		fmt_string = NULL;
		for (n = 0; base[n].type != mmt_end; n++) {
			if (base[n].type != mmt_item && base[n].type
				!= mmt_berstring) {
				if (base[n].type == mmt_berstring_null)
					base[n].type = mmt_berstring;
				continue;
			}
			while (name_s < name_s_end && *name_s != COMMA_CHAR)
				name_s++;
			name_s++;    /* now at comma char */
			while (name_s < name_s_end && is_whitespace(*name_s))
				name_s++;
			begin_token = name_s++;
			end_token = name_s_end;
			name_s = get_next_token(
				&begin_token, &end_token, &token);
			if (name_s == NULL) {
				p_error = parse_item_expected_error;
				return (4);
			}
			if (token != string_token) {
				p_error = parse_item_expected_error;
				return (5);
			}
			item = (__nis_mapping_item_t *)s_realloc(item,
				(nElements + 1) *
				sizeof (__nis_mapping_item_t));
			if (item == NULL) {
				p_error = parse_no_mem_error;
				return (2);
			}
			name_s = get_mapping_item(begin_token, name_s_end,
				&item[nElements], item_type);
			if (name_s == NULL) {
				p_error = parse_unmatched_escape;
				for (n = 0; n < (nElements + 1); n++)
					free_mapping_item(&item[n]);
				free_mapping_format(base);
				return (4);
			}
			nElements++;
		}
		if (p_error != no_parse_error) {
			for (n = 0; n < (nElements + 1); n++)
				free_mapping_item(&item[n]);
			free_mapping_format(base);
			return (6);
		}
		name_s = skip_token(name_s, name_s_end, close_paren_token);
		if (name_s == NULL) {
			p_error = parse_close_paren_expected_error;
			for (n = 0; n < (nElements + 1); n++)
				free_mapping_item(&item[n]);
			free_mapping_format(base);
			return (4);
		}
		while (name_s < name_s_end && is_whitespace(*name_s))
			name_s++;
		if (*name_s == COMMA_CHAR)
			parse_next_line++;

		if (nElements == 0) {
			p_error = parse_no_match_item;
			for (n = 0; n < (nElements + 1); n++)
				free_mapping_item(&item[n]);
			free_mapping_format(base);
			return (7);
		}
		elmnt = (__nis_mapping_element_t *)s_realloc(elmnt,
			(numSplits + 1) *
			sizeof (__nis_mapping_element_t));
		if (elmnt == NULL) {
			for (n = 0; n < (nElements + 1); n++)
				free_mapping_item(&item[n]);
			free_mapping_format(base);
			p_error = parse_no_mem_error;
			return (2);
		}
		elmnt[numSplits].type = me_match;
		elmnt[numSplits].element.match.numItems = nElements;
		elmnt[numSplits].element.match.item = item;
		elmnt[numSplits].element.match.fmt = base;
		item = NULL;
		base = NULL;

		t_map->e = elmnt;
		t_map->numSplits = numSplits;
		n = t_map->numColumns;

		for (i = n, itm_count = 0; i < n + nElements; i++) {
			if (t_map->e[numSplits].element.
				match.item[itm_count].name) {
				if (!add_column(t_map,
					t_map->e[numSplits].element.
					match.item[itm_count].name))
					return (1);
				itm_count++;
			} else {
				p_error = parse_internal_error;
				for (n = 0; n < (nElements + 1); n++)
					free_mapping_item(&item[n]);
				free_mapping_format(base);
				free_mapping_element(elmnt);
				return (1);
			}
		}
		numSplits++;
	}
	elmnt = NULL;

	if (item != NULL) {
		for (n = 0; n < t_map->numColumns; n++) {
			free_mapping_item(&item[n]);
		}
		free(item);
	}
	if (elmnt != NULL)
		free_mapping_element(elmnt);
	if (base != NULL)
		free_mapping_format(base);

	return (p_error == no_parse_error ? 0 : -1);
}

/*
 * FUNCTION:	parse_object_dn
 *
 *	Parse object dn attribute
 *
 * RETURN VALUE:	__nis_object_dn_t on success
 *			NULL on failure
 *
 * INPUT:		the attribute value
 */

static __nis_object_dn_t *
parse_object_dn(const char *s, const char *end)
{
	const char		*s_begin;
	const char		*s_end;
	object_dn_token		token;
	parse_object_dn_state	dn_state	= dn_begin_parse;
	__nis_object_dn_t	*obj_dn		= NULL;
	__nis_object_dn_t	*next		= NULL;
	__nis_object_dn_t	*last		= NULL;

	/*
	 * The attribute should be of form
	 * objectDN *( ";" objectDN )
	 * objectDN = readObjectSpec [":"[writeObjectSpec]]
	 * readObjectSpec = [baseAndScope [filterAttrValList]]
	 * writeObjectSpec = [baseAndScope [attrValList [":" deleteDisp]]]
	 */

	while (s < end) {
		s_begin = s;
		s_end = end;
		s = get_next_object_dn_token(&s_begin, &s_end, &token);
		if (s == NULL)
			break;

		if (token == dn_no_token || token == dn_semi_token) {
			if (obj_dn == NULL)
				obj_dn = next;
			else
				last->next = next;
			last = next;
			next = NULL;
			if (token == dn_no_token)
				break;
			dn_state = dn_begin_parse;
		}
		if (next == NULL) {
			next = (__nis_object_dn_t *)
				s_calloc(1, sizeof (__nis_object_dn_t));
			if (next == NULL)
				break;
			next->read.scope = LDAP_SCOPE_ONELEVEL;
			next->write.scope = LDAP_SCOPE_UNKNOWN;
			next->delDisp = dd_always;
		}
		if (token == dn_semi_token)
			continue;

		switch (dn_state) {
		    case dn_begin_parse:
			if (token == dn_ques_token)
				dn_state = dn_got_read_q_scope;
			else if (token == dn_colon_token) {
				dn_state = dn_got_write_colon;
				next->write.scope = LDAP_SCOPE_ONELEVEL;
			} else {
				if (!validate_dn(s_begin, s_end - s_begin))
					break;
				next->read.base =
					s_strndup_esc(s_begin, s_end - s_begin);
				dn_state = dn_got_read_dn;
			}
			break;
		    case dn_got_read_dn:
			if (token == dn_ques_token)
				dn_state = dn_got_read_q_scope;
			else if (token == dn_colon_token) {
				dn_state = dn_got_write_colon;
				next->write.scope = LDAP_SCOPE_ONELEVEL;
			} else
				p_error = parse_object_dn_syntax_error;
			break;
		    case dn_got_read_q_scope:
			if (token == dn_ques_token)
				dn_state = dn_got_read_q_filter;
			else if (token == dn_colon_token) {
				dn_state = dn_got_write_colon;
				next->write.scope = LDAP_SCOPE_ONELEVEL;
			} else if (token == dn_base_token) {
				next->read.scope = LDAP_SCOPE_BASE;
				dn_state = dn_got_read_scope;
			} else if (token == dn_one_token) {
				next->read.scope = LDAP_SCOPE_ONELEVEL;
				dn_state = dn_got_read_scope;
			} else if (token == dn_sub_token) {
				next->read.scope = LDAP_SCOPE_SUBTREE;
				dn_state = dn_got_read_scope;
			} else {
				p_error = parse_invalid_scope;
			}
			break;
		    case dn_got_read_scope:
			if (token == dn_ques_token)
				dn_state = dn_got_read_q_filter;
			else if (token == dn_colon_token) {
				dn_state = dn_got_write_colon;
				next->write.scope = LDAP_SCOPE_ONELEVEL;
			} else
				p_error = parse_object_dn_syntax_error;
			break;
		    case dn_got_read_q_filter:
			if (token == dn_ques_token) {
				p_error = parse_object_dn_syntax_error;
			} else if (token == dn_colon_token) {
				dn_state = dn_got_write_colon;
				next->write.scope = LDAP_SCOPE_ONELEVEL;
			} else {
				if (!validate_ldap_filter(s_begin, s_end))
					break;
				next->read.attrs =
					s_strndup_esc(s_begin, s_end - s_begin);
				dn_state = dn_got_read_filter;
			}
			break;
		    case dn_got_read_filter:
			if (token == dn_ques_token) {
				p_error = parse_object_dn_syntax_error;
			} else if (token == dn_colon_token) {
				dn_state = dn_got_write_colon;
				next->write.scope = LDAP_SCOPE_ONELEVEL;
			} else
				p_error = parse_object_dn_syntax_error;
			break;
		    case dn_got_write_colon:
			if (token == dn_ques_token)
				dn_state = dn_got_write_q_scope;
			else if (token == dn_colon_token) {
				dn_state = dn_got_delete_colon;
			} else {
				if (!validate_dn(s_begin, s_end - s_begin))
					break;
				next->write.base =
					s_strndup_esc(s_begin, s_end - s_begin);
				dn_state = dn_got_write_dn;
			}
			break;
		    case dn_got_write_dn:
			if (token == dn_ques_token)
				dn_state = dn_got_write_q_scope;
			else if (token == dn_colon_token) {
				dn_state = dn_got_delete_colon;
			} else
				p_error = parse_object_dn_syntax_error;
			break;
		    case dn_got_write_q_scope:
			if (token == dn_ques_token)
				dn_state = dn_got_write_q_filter;
			else if (token == dn_colon_token) {
				dn_state = dn_got_delete_colon;
			} else if (token == dn_base_token) {
				next->write.scope = LDAP_SCOPE_BASE;
				dn_state = dn_got_write_scope;
			} else if (token == dn_one_token) {
				next->write.scope = LDAP_SCOPE_ONELEVEL;
				dn_state = dn_got_write_scope;
			} else if (token == dn_sub_token) {
				next->write.scope = LDAP_SCOPE_SUBTREE;
				dn_state = dn_got_write_scope;
			} else {
				p_error = parse_invalid_scope;
			}
			break;
		    case dn_got_write_scope:
			if (token == dn_ques_token)
				dn_state = dn_got_write_q_filter;
			else if (token == dn_colon_token) {
				dn_state = dn_got_delete_colon;
			} else
				p_error = parse_object_dn_syntax_error;
			break;
		    case dn_got_write_q_filter:
			if (token == dn_ques_token) {
				p_error = parse_object_dn_syntax_error;
			} else if (token == dn_colon_token) {
				dn_state = dn_got_delete_colon;
			} else {
				if (!validate_ldap_filter(s_begin, s_end))
					break;
				next->write.attrs =
					s_strndup_esc(s_begin, s_end - s_begin);
				dn_state = dn_got_write_filter;
			}
			break;
		    case dn_got_write_filter:
			if (token == dn_ques_token) {
				p_error = parse_object_dn_syntax_error;
			} else if (token == dn_colon_token) {
				dn_state = dn_got_delete_colon;

			} else
				p_error = parse_semi_expected_error;
			break;
		    case dn_got_delete_colon:
			if (token == dn_ques_token) {
				p_error = parse_object_dn_syntax_error;
			} else if (token == dn_colon_token) {
				p_error = parse_object_dn_syntax_error;
			} else {
				if (!get_deleteDisp(s_begin, s_end, next))
					break;
				dn_state = dn_got_delete_dsp;
			}
			break;
		    case dn_got_delete_dsp:
			p_error = parse_object_dn_syntax_error;
			break;
		}

		if (p_error != no_parse_error)
			break;
	}
	if (p_error != no_parse_error) {
		if (obj_dn != NULL)
			free_object_dn(obj_dn);
		if (next != NULL)
			free_object_dn(next);
		obj_dn = NULL;
	} else if (next != NULL) {
		if (obj_dn == NULL)
			obj_dn = next;
		else
			last->next = next;
	} else if (obj_dn == NULL)
		obj_dn = (__nis_object_dn_t *)
			s_calloc(1, sizeof (__nis_object_dn_t));

	return (obj_dn);
}

/*
 * FUNCTION:	get_mapping_rule
 *
 *	Parse mapping rule attributes
 *
 * RETURN VALUE:	None. Errors determined by p_error
 *
 * INPUT:		the attribute value and mapping rule type
 */

static void
get_mapping_rule(
	const char		*s,
	int			len,
	__nis_table_mapping_t	*tbl,
	bool_t			to_ldap)
{
	const char		*end_s			= s + len;
	const char		*begin_token;
	const char		*end_token;
	__nis_mapping_rule_t	**rule			= NULL;
	__nis_mapping_rule_t	*next			= NULL;
	/* __nis_mapping_rule_t	**r; */
	token_type		t;
	int			nRules			= 0;
	const char		*s1;
	int			i;

	/*
	 * The attribute value is of the form
	 * colattrspec *("," colattrspec)
	 * colattrspec	= lhs "=" rhs
	 * lhs		= lval | namespeclist
	 * rhs		= rval | [namespec]
	 */

	for (;;) {
		if ((next = (__nis_mapping_rule_t *)
		    s_calloc(1, sizeof (__nis_mapping_rule_t))) == NULL)
			break;

		s = get_lhs(s, end_s, &next->lhs,
			to_ldap ? mit_ldap : mit_nisplus);
		if (s == NULL)
			break;

		begin_token = s;
		end_token = end_s;
		s1 = get_next_token(&begin_token, &end_token, &t);
		if (s1 == NULL)
			break;
		if (!(to_ldap && (t == comma_token || t == no_token))) {
			s = get_rhs(s, end_s, &next->rhs,
				to_ldap ? mit_nisplus : mit_ldap);
			if (s == NULL)
				break;
		}

		if (next->lhs.numElements > 1 &&
		    (next->rhs.numElements != 1 ||
		    next->rhs.element[0].type != me_split)) {
			p_error = parse_lhs_rhs_type_mismatch;
			break;
		}
		if (rule == NULL) {
			rule = (__nis_mapping_rule_t **)
				malloc(sizeof (__nis_mapping_rule_t *));
			if (rule == NULL)
				break;
		} else {
			rule = (__nis_mapping_rule_t **)s_realloc(rule,
				(nRules + 1) *
				sizeof (__nis_mapping_rule_t *));
			if (rule == NULL)
				break;
		}

		rule[nRules++] = next;
		next = NULL;

		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL)
			break;
		if (t == comma_token)
			continue;
		if (t != no_token) {
			p_error = parse_unexpected_data_end_rule;
			break;
		}
		if (to_ldap) {
			tbl->numRulesToLDAP = nRules;
			tbl->ruleToLDAP = rule;
		} else {
			tbl->numRulesFromLDAP = nRules;
			tbl->ruleFromLDAP = rule;
		}
		return;
	}

	if (rule) {
		for (i = 0; i < nRules; i++)
			free_mapping_rule(rule[i]);
		free(rule);
	}
	if (next)
		free_mapping_rule(next);
}

/*
 * FUNCTION:	get_lhs
 *
 *	Parse left hand side of mapping rule attribute
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning rhs
 *
 * INPUT:		the attribute value and mapping rule type
 */

static const char *
get_lhs(const char			*s,
	const char			*end_s,
	__nis_mapping_rlhs_t		*lhs,
	__nis_mapping_item_type_t	item_type)
{
	token_type		t;
	const char		*begin_token;
	const char		*end_token;
	const char		*sav_s;
	__nis_mapping_element_t	*e		= NULL;

	/*
	 *	lhs can be expressed as:
	 *		item
	 *		(item)
	 *		(item list)
	 *		(fmt, item list)
	 *
	 * lhs = lval | namespeclist
	 * lval = "(" formatspec "," namespec *("," namespec) ")"
	 * namespeclist = namespec | "(" namespec *("," namespec) ")"
	 */

	for (; p_error == no_parse_error; ) {
		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL)
			break;
		if (t == no_token) {
			p_error = parse_unexpected_data_end_rule;
			break;
		}

		e = (__nis_mapping_element_t *)
			s_calloc(1, sizeof (__nis_mapping_element_t));
		if (e == NULL)
			break;

		if (t == open_paren_token) {
			free(e);
			e = NULL;

			begin_token = s;
			end_token = end_s;
			sav_s = s;
			s = get_next_token(&begin_token, &end_token, &t);
			if (s == NULL)
				break;

			if (t == quoted_string_token) {
				s = get_lhs_match(sav_s, end_s, lhs, item_type);
				if (s == NULL)
					break;
			} else if (t == string_token) {
				s = get_lhs_paren_item(sav_s, end_s, lhs,
					item_type);
				if (s == NULL)
					break;
			} else {
				p_error = parse_bad_lhs_format_error;
				break;
			}
		} else if (t == string_token) {
			s = get_mapping_item(begin_token, end_s,
				&e->element.item, item_type);
			if (s == NULL)
				break;
			e->type = me_item;
			if (!add_element(e, lhs))
				break;
			e = NULL;
		} else {
			p_error = parse_bad_lhs_format_error;
			break;
		}

		s = skip_token(s, end_s, equal_token);
		if (s == NULL)
			break;
		if (p_error == no_parse_error)
			return (s);
	}
	if (e != NULL)
		free_mapping_element(e);

	return (NULL);
}

/*
 * FUNCTION:	get_lhs_match
 *
 *	Parse left hand side of mapping rule attribute in case of
 *	matching rule
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning rhs
 *
 * INPUT:		the attribute value and mapping rule type
 */

static const char *
get_lhs_match(
	const char			*s,
	const char			*end_s,
	__nis_mapping_rlhs_t		*lhs,
	__nis_mapping_item_type_t	item_type)
{
	token_type			t;
	const char			*begin_token;
	const char			*end_token;
	int				n		= 0;
	int				nElements	= 0;
	char				*fmt_string	= NULL;
	__nis_mapping_format_t		*base		= NULL;
	__nis_mapping_item_t		*item		= NULL;
	__nis_mapping_item_t		*itm;
	__nis_mapping_element_t		*e;

	/*
	 *  lval = "(" formatspec "," namespec *("," namespec) ")"
	 */

	for (; p_error == no_parse_error; ) {
		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL || t != quoted_string_token) {
			p_error = parse_internal_error;
			break;
		}


		fmt_string = s_strndup(begin_token, end_token - begin_token);
		if (fmt_string == NULL)
			break;

		if (!get_mapping_format(fmt_string, &base, &n, NULL, FALSE))
			break;

		for (n = 0; base[n].type != mmt_end; n++) {
			if (base[n].type != mmt_item &&
			    base[n].type != mmt_berstring) {
				if (base[n].type == mmt_berstring_null)
					base[n].type = mmt_berstring;
				continue;
			}
			s = skip_token(s, end_s, comma_token);
			if (s == NULL) {
				p_error = parse_not_enough_extract_items;
				break;
			}
			begin_token = s;
			end_token = end_s;
			s = get_next_token(&begin_token, &end_token, &t);
			if (s == NULL)
				break;
			if (t != string_token) {
				p_error = parse_item_expected_error;
				break;
			}
			itm = (__nis_mapping_item_t *)
				s_realloc(item, (nElements + 1) *
				sizeof (__nis_mapping_item_t));
			if (itm == NULL)
				break;
			item = itm;

			s = get_mapping_item(begin_token, end_s,
				&item[nElements], item_type);
			if (s == NULL)
				break;
			nElements++;
		}
		if (p_error != no_parse_error)
			break;

		s = skip_token(s, end_s, close_paren_token);
		if (s == NULL)
			break;
		free(fmt_string);
		fmt_string = NULL;

		if (nElements == 0) {
			p_error = parse_no_match_item;
			break;
		}
		e = (__nis_mapping_element_t *)s_calloc(1,
			sizeof (__nis_mapping_element_t));
		if (e == NULL)
			break;
		e->type = me_match;
		e->element.match.numItems = nElements;
		e->element.match.item = item;
		e->element.match.fmt = base;
		lhs->numElements = 1;
		lhs->element = e;

		if (p_error == no_parse_error)
			return (s);
	}
	if (item == NULL) {
		for (n = 0; n < nElements; n++)
			free_mapping_item(&item[n]);
		free(item);
	}
	if (fmt_string != NULL)
		free(fmt_string);
	if (base != NULL)
		free_mapping_format(base);

	return (NULL);
}

/*
 * FUNCTION:	get_lhs_paren_item
 *
 *	Parse left hand side of mapping rule attribute in case of
 *	(item1, ..., item-n)
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning rhs
 *
 * INPUT:		the attribute value and mapping rule type
 */

static const char *
get_lhs_paren_item(
	const char			*s,
	const char			*end_s,
	__nis_mapping_rlhs_t		*lhs,
	__nis_mapping_item_type_t	item_type)
{
	token_type		t;
	const char		*begin_token;
	const char		*end_token;
	__nis_mapping_element_t	*e		= NULL;
	int			n		= 0;
	int			i;

	/*
	 * "(" namespec *("," namespec) ")"
	 */

	for (;;) {
		e = (__nis_mapping_element_t *)s_realloc(e, (n + 1) *
			sizeof (__nis_mapping_element_t));
		if (e == NULL)
			break;

		s = get_mapping_item(s, end_s, &e[n].element.item,
			item_type);
		if (s == NULL)
			break;
		e[n].type = me_item;
		n++;

		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s != NULL && t == close_paren_token) {
			lhs->numElements = n;
			if (n == 1)
				e[0].element.item.repeat = TRUE;
			lhs->element = e;
			return (s);
		}
		if (s == NULL || t != comma_token) {
			p_error = parse_comma_expected_error;
			break;
		}
	}
	for (i = 0; i < n; i++)
		free_mapping_element(&e[i]);
	if (e != NULL)
		free(e);
	return (NULL);
}

/*
 * FUNCTION:	get_rhs
 *
 *	Parse right hand side of mapping rule attribute
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next mapping rule
 *
 * INPUT:		the attribute value and mapping rule type
 */

static const char *
get_rhs(
	const char			*s,
	const char			*end_s,
	__nis_mapping_rlhs_t		*rhs,
	__nis_mapping_item_type_t	item_type)
{
	/*
	 * This handles the following cases:
	 *	name				me_item
	 *	(name)				me_item
	 *	(fmt, name-list)		me_print
	 *	(item, fmt)			me_extract
	 */

	token_type		t;
	const char		*begin_token;
	const char		*end_token;
	char			*str		= NULL;
	__nis_mapping_format_t	*fmt		= NULL;
	__nis_mapping_element_t	*e		= NULL;
	__nis_mapping_item_t	item;
	int			n;

	(void) memset(&item, 0, sizeof (item));

	for (; p_error == no_parse_error; ) {
		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL)
			break;

		e = (__nis_mapping_element_t *)
			s_calloc(1, sizeof (__nis_mapping_element_t));
		if (e == NULL)
			break;

		if (t == string_token) {
			s = get_mapping_item(begin_token, end_s,
				&e->element.item, item_type);
		} else if (t == open_paren_token) {
			begin_token = s;
			end_token = end_s;
			s = get_next_token(&begin_token, &end_token, &t);
			if (s == NULL)
				break;
			if (t == string_token) {
				/* (item, fmt) - me_extract */
				/* (item, "c") - me_split */
				s = get_mapping_item(begin_token, end_s,
					&item, item_type);
				if (s == NULL)
					break;
				begin_token = s;
				end_token = end_s;
				s = get_next_token(&begin_token, &end_token,
					&t);
				if (s == NULL)
					break;
				else if (t == close_paren_token) {
					item.repeat = TRUE;
					e->element.item = item;
					e->type = me_item;
					rhs->numElements = 1;
					rhs->element = e;
					return (s);
				} else if (t != comma_token) {
					p_error = parse_comma_expected_error;
					break;
				}

				begin_token = s;
				end_token = end_s;
				s = get_next_token(&begin_token, &end_token,
					&t);
				if (s == NULL || t != quoted_string_token) {
				    p_error =
					parse_format_string_expected_error;
				    break;
				}

				if (end_token == begin_token + 1 ||
				    (*begin_token == ESCAPE_CHAR &&
				    end_token == begin_token + 2)) {
					e->type = me_split;
					e->element.split.item = item;
					e->element.split.delim = *begin_token;
				} else {
					str = s_strndup(begin_token,
						end_token - begin_token);
					if (str == NULL)
						break;
					if (!get_mapping_format(str, &fmt,
					    NULL, &n, FALSE))
						break;
					free(str);
					str = NULL;
					if (n != 1) {
					    p_error =
						parse_bad_extract_format_spec;
					    break;
					}
					e->type = me_extract;
					e->element.extract.item = item;
					e->element.extract.fmt = fmt;
				}
				s = skip_token(s, end_s, close_paren_token);
			} else if (t == quoted_string_token) {
				/* (fmt, name-list) - me_print */
				str = s_strndup(begin_token,
					end_token - begin_token);
				if (str == NULL)
					break;

				s = get_print_mapping_element(s, end_s,
					str, e, item_type);
				free(str);
				str = NULL;
			} else {
				p_error = parse_start_rhs_unrecognized;
				break;
			}
		} else {
			p_error = parse_start_rhs_unrecognized;
			break;
		}
		if (s == NULL)
			break;
		rhs->numElements = 1;
		rhs->element = e;
		if (p_error == no_parse_error)
			return (s);
	}
	if (str)
		free(str);
	if (fmt != NULL)
		free_mapping_format(fmt);
	if (e != NULL)
		free_mapping_element(e);
	free_mapping_item(&item);

	return (NULL);
}

/*
 * FUNCTION:	get_print_mapping_element
 *
 *	Parse a print mapping rule attribute in case of the form
 *	(fmt, name-list)
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next mapping rule
 *
 * INPUT:		the attribute value and mapping rule type
 */

static const char *
get_print_mapping_element(
	const char			*s,
	const char			*end_s,
	char				*fmt_string,
	__nis_mapping_element_t		*e,
	__nis_mapping_item_type_t	item_type)
{
	token_type			t;
	const char			*begin_token;
	const char			*end_token;
	char				elide;
	bool_t				doElide;
	__nis_mapping_format_t		*base		= NULL;
	__nis_mapping_sub_element_t	*subElement	= NULL;
	int				n		= 0;
	int				nSub		= 0;
	int				numSubElements;

	for (; p_error == no_parse_error; ) {
		if (!get_mapping_format(fmt_string, &base, &n,
		    &numSubElements, TRUE))
			break;
		subElement = (__nis_mapping_sub_element_t *)
			s_calloc(numSubElements,
			sizeof (__nis_mapping_sub_element_t));
		if (subElement == NULL)
			break;
		for (n = 0; base[n].type != mmt_end; n++) {
			if (base[n].type != mmt_item &&
				base[n].type != mmt_berstring) {
			    if (base[n].type == mmt_berstring_null)
				base[n].type = mmt_berstring;
			    continue;
			}
			if (nSub < numSubElements) {
				s = skip_token(s, end_s, comma_token);
				if (s == NULL) {
					p_error = parse_bad_print_format;
					break;
				}
			}

			/* namelist may have parens around it */
			s = get_subElement(s, end_s, &subElement[nSub],
				item_type);
			if (s == NULL)
				break;
			nSub++;
		}
		if (p_error != no_parse_error)
			break;

		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL || t == no_token) {
			p_error = parse_unexpected_data_end_rule;
			break;
		} else if (t == close_paren_token) {
			doElide = FALSE;
			elide = '\0';
		} else if (t == comma_token) {
			begin_token = s;
			end_token = end_s;
			s = get_next_token(&begin_token, &end_token, &t);
			if (s != NULL && t == quoted_string_token &&
			    (end_token == begin_token + 1 ||
			    (*begin_token == ESCAPE_CHAR &&
			    end_token == begin_token + 2))) {
				if (numSubElements != 1 ||
				    subElement->type == me_extract ||
				    subElement->type == me_split) {
					p_error = parse_cannot_elide;
					break;
				}
				if (subElement->type == me_item &&
				    !subElement->element.item.repeat) {
					p_error = parse_cannot_elide;
					break;
				}
				elide = *begin_token;
				doElide = TRUE;

			} else {
				p_error = parse_bad_elide_char;
				break;
			}
			s = skip_token(s, end_s, close_paren_token);
			if (s == NULL)
				break;
		}

		e->type = me_print;
		e->element.print.fmt = base;
		e->element.print.numSubElements = numSubElements;
		e->element.print.subElement = subElement;
		e->element.print.elide = elide;
		e->element.print.doElide = doElide;

		if (p_error == no_parse_error)
			return (s);
	}
	if (base)
		free_mapping_format(base);
	if (subElement != NULL) {
		for (n = 0; n < numSubElements; n++)
			free_mapping_sub_element(&subElement[n]);
		free(subElement);
	}

	return (NULL);
}

/*
 * FUNCTION:	get_mapping_item
 *
 *	Parse attribute string to get mapping item
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after item
 *
 * INPUT:		the attribute value and mapping rule type
 */

static const char *
get_mapping_item(
	const char			*s,
	const char			*end_s,
	__nis_mapping_item_t		*item,
	__nis_mapping_item_type_t	type)
{
	token_type			t;
	const char			*begin_token;
	const char			*end_token;
	char				*name		= NULL;
	char				*index_string;
	const char			*s_sav;
	int				len;

	(void) memset(item, 0, sizeof (*item));

	/*
	 * A namepec is defined as follows:
	 * namespec	= ["ldap:"] attrspec [searchTriple] |
	 *		  ["nis+:"] colspec  [objectspec]
	 *
	 * The form of the item is assumed to be as follows:
	 * ["ldap:"] attrspec [searchTriple]
	 * attrspec = attribute | "(" attribute ")"
	 * searchTriple	= ":" [baseDN] ["?" [scope] ["?" [filter]]]
	 * baseDN = Base DN for search
	 * scope = "base" | "one" | "sub"
	 * filter = LDAP search filter
	 *
	 * The form of the objectspec is as follows:
	 * ["nis+:"] colspec  [objectspec]
	 * objectspec	= objectname | "[" indexlist "]" tablename
	 * objectname	= The name of a NIS+ object
	 * tablename	= The name of a NIS+ table
	 * indexlist	= colspec ["," colspec]
	 * colspec	= colname "=" colvalue
	 * colname	= The name of a column in the table
	 * colvalue	= colvaluestring | \" colvaluestring \"
	 */

	for (; p_error == no_parse_error; ) {
		while (s < end_s && is_whitespace(*s))
			s++;
		len = end_s - s;
		if (yp2ldap) {
			if ((begin_token = skip_string("ldap:", s,
				len)) != NULL) {
				item->type = mit_ldap;
			} else if ((begin_token = skip_string("yp:", s,
				len)) != NULL) {
				item->type = mit_nisplus;
			} else {
				item->type = type;
				begin_token = s;
			}
		} else {
			if ((begin_token = skip_string("ldap:", s,
				len)) != NULL) {
			item->type = mit_ldap;
			} else if ((begin_token = skip_string("nis+:", s,
				len)) != NULL) {
				item->type = mit_nisplus;
			} else if ((begin_token = skip_string("nisplus:", s,
				len)) != NULL) {
				item->type = mit_nisplus;
			} else {
				item->type = type;
				begin_token = s;
			}
		}

		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL || t != string_token) {
			p_error = parse_bad_item_format;
			break;
		}

		item->name = s_strndup_esc(begin_token,
			end_token - begin_token);
		if (item->name == NULL)
			break;
		if (item->type == mit_ldap) {
			item->searchSpec.triple.scope = LDAP_SCOPE_UNKNOWN;
			begin_token = s;
			end_token = end_s;
			s_sav = s;
			s = get_next_token(&begin_token, &end_token, &t);
			if (s != NULL && t == colon_token) {
				s = get_search_triple(s, end_s,
					&item->searchSpec.triple);
				if (s == NULL)
					break;
			} else
				s = s_sav;
		} else if (item->type == mit_nisplus) {
			while (s < end_s && is_whitespace(*s))
				s++;

			if (s < end_s && *s == OPEN_BRACKET) {
				index_string = getIndex(&s, end_s);
				if (index_string == NULL)
					break;
				(void) parse_index(index_string,
					index_string + strlen(index_string),
					&item->searchSpec.obj.index);
				free(index_string);
				if (p_error != no_parse_error)
					break;
			}
			s_sav = s;
			begin_token = s;
			end_token = end_s;
			s = get_next_token(&begin_token, &end_token, &t);
			if (s != NULL && t == string_token) {
				name = s_strndup_esc(begin_token,
					end_token - begin_token);
				if (name == NULL)
					break;
				item->searchSpec.obj.name = name;
			} else
				s = s_sav;
		}
		if (p_error == no_parse_error)
			return (s);
	}
	free_mapping_item(item);
	(void) memset(item, 0, sizeof (*item));
	if (name == NULL)
		free(name);
	return (NULL);
}

static const char *
get_print_sub_element(const char		*s,
		const char			*end_s,
		__nis_mapping_item_type_t	type,
		__nis_mapping_sub_element_t	*sub)
{

	int			k;
	int			n;
	const char		*begin_token;
	const char		*end_token;
	token_type		t;
	__nis_mapping_format_t	*base;
	__nis_mapping_item_t	*print_item;

	k = 0;
	base = sub->element.print.fmt;
	print_item = sub->element.print.item;
	sub->element.print.doElide = FALSE;
	sub->element.print.elide = '\0';

	for (n = 0; base[n].type != mmt_end; n++) {
		if (base[n].type != mmt_item && base[n].type != mmt_berstring) {
			if (base[n].type == mmt_berstring_null)
					base[n].type = mmt_berstring;
			continue;
		}
		s = skip_token(s, end_s, comma_token);
		if (s == NULL) {
			p_error = parse_bad_print_format;
			break;
		}

		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL)
			break;
		/*
		 * Determine if of the form
		 * ("fmt", (item), "delim") or
		 * ("fmt", item1, item2, ..., item n)
		 */
		if (t == open_paren_token) {
			if (sub->element.print.numItems != 1) {
				p_error = parse_invalid_print_arg;
				break;
			}
			s = get_mapping_item(s, end_s, &print_item[k++], type);
			s = skip_token(s, end_s, close_paren_token);
			s = skip_token(s, end_s, comma_token);
			if (s == NULL) {
				p_error = parse_bad_print_format;
				break;
			}
			begin_token = s;
			end_token = end_s;
			s = get_next_token(&begin_token, &end_token, &t);
			if (s == NULL)
				break;
			if (t != quoted_string_token ||
				    begin_token + 1 != end_token) {
				p_error = parse_bad_elide_char;
				break;
			}
			sub->element.print.elide = *begin_token;
			sub->element.print.doElide = TRUE;
			print_item[0].repeat = TRUE;
			break;
		}
		s = get_mapping_item(begin_token, end_s,
			&print_item[k++], type);
		if (s == NULL)
			break;

		if (p_error != no_parse_error)
			break;
	}

	return (p_error == no_parse_error ? s : NULL);
}

/*
 * FUNCTION:	get_subElement
 *
 *	Parse attribute string to get sub element item
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after item
 *
 * INPUT:		the attribute value and mapping rule type
 */

static const char *
get_subElement(
	const char			*s,
	const char			*end_s,
	__nis_mapping_sub_element_t	*subelement,
	__nis_mapping_item_type_t	type)
{
	token_type			t;
	const char			*begin_token;
	const char			*end_token;
	char				*fmt_string;
	__nis_mapping_item_t		item;
	__nis_mapping_element_type_t	e_type;
	__nis_mapping_item_t		*print_item	= NULL;
	__nis_mapping_format_t		*base		= NULL;
	int				n		= 0;
	int				numItems	= 0;
	unsigned char			delim;
	__nis_mapping_sub_element_t	sub;

/*
 *	What is the form of we are expecting here
 *	item					me_item
 *	(item)					me_item
 *	("fmt", item1, item2, ..., item n)	me_print
 *	("fmt", (item), "elide")		me_print
 *	(name, "delim")				me_split
 *	(item, "fmt")				me_extract
 */
	(void) memset(&item, 0, sizeof (item));

	for (; p_error == no_parse_error; ) {
		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL)
			break;
		if (t == string_token) {	/* me_item */
			s = get_mapping_item(begin_token, end_s,
				&subelement->element.item, type);
			if (s == NULL)
				break;
			subelement->type = me_item;
			return (s);
		} else if (t != open_paren_token) {
			p_error = parse_item_expected_error;
			break;
		}

		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL)
			break;

		if (t != string_token && t != quoted_string_token) {
			p_error = parse_item_expected_error;
			break;
		}
		e_type = me_print;
		if (t == string_token) {
			/* me_item, me_extract or me_split */
			s = get_mapping_item(begin_token, end_s, &item, type);
			if (s == NULL)
				break;

			begin_token = s;
			end_token = end_s;
			s = get_next_token(&begin_token, &end_token, &t);
			if (s == NULL) {
				p_error = parse_unexpected_data_end_rule;
				break;
			} else if (t == close_paren_token) {
				subelement->type = me_item;
				item.repeat = TRUE;
				subelement->element.item = item;
				if (yp2ldap) {
					while (s < end_s && is_whitespace(*s))
						s++;
					if (s == end_s) {
						p_error =
						parse_unexpected_data_end_rule;
						break;
					}
					if (*s == DASH_CHAR && s < end_s) {
						s++;
						while (s < end_s &&
							is_whitespace(*s))
							s++;
						begin_token = s;
						end_token = end_s;

						subelement->element.item.exItem
							=
							(__nis_mapping_item_t *)
					s_malloc(sizeof (__nis_mapping_item_t));
						if (!subelement->
						element.item.exItem)
							break;
						s = get_mapping_item(s, end_s,
							subelement->
							element.item.exItem,
							type);
						if (s == NULL) {
							p_error =
							parse_internal_error;
							free_mapping_item(
							subelement->
							element.item.exItem);
							subelement->
							element.item.exItem =
								NULL;
							break;
						}
					}
				}
				return (s);
			} else if (t != comma_token) {
				p_error = parse_comma_expected_error;
				break;
			}

			begin_token = s;
			end_token = end_s;
			s = get_next_token(&begin_token, &end_token, &t);
			if (s == NULL || t != quoted_string_token) {
				p_error = parse_format_string_expected_error;
				break;
			}
			if (end_token == begin_token + 1 ||
			    (*begin_token == ESCAPE_CHAR &&
			    end_token == begin_token + 2)) {
					/* me_split */
				delim = (unsigned char)end_token[-1];
				s = skip_token(s, end_s, close_paren_token);
				if (s == NULL)
					break;
				subelement->element.split.item = item;
				subelement->element.split.delim = delim;
				subelement->type = me_split;
				return (s);
			}
			e_type = me_extract;
		}
		fmt_string = s_strndup(begin_token, end_token - begin_token);
		if (fmt_string == NULL)
			break;
		if (!get_mapping_format(fmt_string, &base, &n, &numItems,
		    e_type == me_print)) {
			free(fmt_string);
			break;
		}
		free(fmt_string);

		if (numItems != 1 && e_type == me_extract) {
			p_error = numItems == 0 ?
				parse_not_enough_extract_items :
				parse_too_many_extract_items;
			break;
		} else if (numItems > 0 && e_type == me_print) {
			print_item = (__nis_mapping_item_t *)s_calloc(numItems,
				sizeof (__nis_mapping_item_t));
			if (print_item == NULL)
				break;
		}

		if (e_type == me_print) {
			sub.element.print.numItems = numItems;
			sub.element.print.fmt = base;
			sub.element.print.item = print_item;
			s = get_print_sub_element(s, end_s, type, &sub);
			if (s == NULL)
				break;
		}
		s = skip_token(s, end_s, close_paren_token);
		if (s == NULL)
			break;

		subelement->type = e_type;
		if (e_type == me_extract) {
			subelement->element.extract.fmt = base;
			subelement->element.extract.item = item;
		} else {
			subelement->type = me_print;
			subelement->element.print.fmt = base;
			subelement->element.print.numItems = numItems;
			subelement->element.print.item = print_item;
			subelement->element.print.doElide =
				sub.element.print.doElide;
			subelement->element.print.elide =
				sub.element.print.elide;
		}
		if (p_error == no_parse_error)
			return (s);
	}
	free_mapping_item(&item);
	if (base != NULL)
		free_mapping_format(base);
	if (print_item) {
		for (n = 0; n < numItems; n++)
			free_mapping_item(&print_item[n]);
		free(print_item);
	}

	return (NULL);
}

/*
 * FUNCTION:	skip_get_dn
 *
 *	Get first token after dn
 *
 * RETURN VALUE:	NULL if error (not valid dn)
 *			position of beginning next token after dn
 *
 * INPUT:		the attribute value
 */

const char *
skip_get_dn(const char *dn, const char *end)
{
	size_t		len		= 0;
	bool_t		in_quote	= FALSE;
	bool_t		goteq		= FALSE;
	bool_t		gotch		= FALSE;
	bool_t		done		= FALSE;
	bool_t		last_comma	= FALSE;
	const char	*last_dn	= dn;

	while (!done) {
		dn += len;
		if (last_comma) {
			last_dn = dn;
			last_comma = FALSE;
		}
		if (dn >= end)
			break;
		len = 1;
		switch (*dn) {
			case ESCAPE_CHAR:
				len = 2;
				gotch = TRUE;
				break;
			case DOUBLE_QUOTE_CHAR:
				in_quote = !in_quote;
				break;
			case QUESTION_MARK:
			case CLOSE_PAREN_CHAR:
			case COLON_CHAR:
				done = !in_quote;
				/* FALLTHRU */
			case SEMI_COLON_CHAR:
			case PLUS_SIGN:
			case COMMA_CHAR:
				if (!in_quote) {
					if (!goteq || !gotch)
						return (last_dn);
					goteq = FALSE;
					gotch = FALSE;
					if (*dn != PLUS_SIGN)
						last_dn = dn;
					last_comma = *dn == COMMA_CHAR;
				} else {
					gotch = TRUE;
				}
				break;
			case EQUAL_CHAR:
				if (!in_quote) {
					if (!gotch || goteq)
						return (NULL);
					goteq = TRUE;
					gotch = FALSE;
				} else {
					gotch = TRUE;
				}
				break;
			default:
				if (!is_whitespace(*dn))
					gotch = TRUE;
				break;
		}
	}

	if (dn == end) {
		if (!in_quote && goteq && gotch)
			last_dn = dn;
	}

	return (last_dn);
}

/*
 * FUNCTION:	get_ldap_filter_element
 *
 *	Get an ldap filter element for a given string
 *
 * RETURN VALUE:	NULL if error
 *			__nis_mapping_element_t if success
 *
 * INPUT:		the string to parse
 */

static __nis_mapping_element_t *
get_ldap_filter_element(
	const char			*s,
	const char			*end_s
)
{
	token_type			t;
	const char			*begin_token;
	const char			*end_token;
	char				*format_str;
	__nis_mapping_element_t		*e		= NULL;

	begin_token = s;
	end_token = end_s;
	s = get_next_token(&begin_token, &end_token, &t);
	if (s == NULL || t != open_paren_token)
		return (NULL);

	begin_token = s;
	end_token = end_s;
	s = get_next_token(&begin_token, &end_token, &t);
	if (s == NULL || t != quoted_string_token)
		return (NULL);

	format_str = s_strndup(begin_token, end_token - begin_token);
	if (format_str == NULL)
		return (NULL);
	e = (__nis_mapping_element_t *)
		s_calloc(1, sizeof (__nis_mapping_element_t));
	if (e != NULL) {
		(void) get_print_mapping_element(s, end_s,
				format_str, e, mit_nisplus);
		if (p_error != no_parse_error) {
			free_mapping_element(e);
			e = NULL;
		}
	}
	free(format_str);
	return (e);
}

/*
 * FUNCTION:	get_search_triple
 *
 *	Get the search triple or if NULL determine if valid
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after
 *			search triple
 *
 * INPUT:		the attribute value
 */

const char *
get_search_triple(
	const char			*s,
	const char			*end_s,
	__nis_search_triple_t		*triple
)
{
	const char	*begin_token;
	const char	*end_token;
	char		*search_base	= NULL;
	int		scope		= LDAP_SCOPE_ONELEVEL;
	char		*filter		= NULL;
	const char	*s1;
	__nis_mapping_element_t
			*element	= NULL;

	/*
	 * The form of the searchTriple is assumed to be as follows:
	 * searchTriple	= [baseDN] ["?" [scope] ["?" [filter]]]
	 * baseDN = Base DN for search
	 * scope = "base" | "one" | "sub"
	 * filter = LDAP search filter
	 */
	for (; p_error == no_parse_error; ) {
		while (s < end_s && is_whitespace(*s))
			s++;
		if (s == end_s)
			break;

		if (!IS_TERMINAL_CHAR(*s)) {
			begin_token = s;
			s = skip_get_dn(begin_token, end_s);
			if (s == NULL) {
				p_error = parse_invalid_dn;
				break;
			}
			if (triple != NULL) {
				search_base = s_strndup(begin_token,
					s - begin_token);
				if (search_base == NULL)
					break;
			}
			while (s < end_s && is_whitespace(*s))
				s++;
			if (s == end_s)
				break;
		}

		if (!IS_TERMINAL_CHAR(*s)) {
			p_error = parse_bad_ldap_item_format;
			break;
		}
		if (*s != QUESTION_MARK)
			break;

		s++;
		while (s < end_s && is_whitespace(*s))
			s++;
		if (s == end_s)
			break;

		/* base, one, or sub, or empty value */
		if (!IS_TERMINAL_CHAR(*s)) {
			if ((s1 = skip_string("base", s, end_s - s)) != NULL) {
				scope = LDAP_SCOPE_BASE;
			} else if ((s1 = skip_string("one", s, end_s - s)) !=
					NULL) {
				scope = LDAP_SCOPE_ONELEVEL;
			} else if ((s1 = skip_string("sub", s, end_s - s)) !=
					NULL) {
				scope = LDAP_SCOPE_SUBTREE;
			} else if (s + 1 < end_s && *s != QUESTION_MARK) {
				p_error = parse_invalid_scope;
				break;
			}
			if (s1 != NULL)
				s = s1;
			while (s < end_s && is_whitespace(*s))
				s++;
		}

		if (s == end_s)
			break;
		if (*s != QUESTION_MARK)
			break;
		s++;
		while (s < end_s && is_whitespace(*s))
			s++;
		if (s == end_s || IS_TERMINAL_CHAR(*s))
			break;

		/* LDAP search filter */
		if (*s == OPEN_PAREN_CHAR) {
		    begin_token = s;
		    end_token = end_s;
		    s = get_ldap_filter(&begin_token, &end_token);
		    if (s == NULL)
			break;
		    s = end_token;
		    element = get_ldap_filter_element(begin_token, end_token);
		    if (element != NULL)
			break;
		} else {
		    begin_token = s;
		    end_token = end_s;
		    s = get_ava_list(&begin_token, &end_token, TRUE);
		    if (s == NULL)
			break;
		    s = end_token;
		}
		if (triple != NULL)
			filter = s_strndup(begin_token, s - begin_token);
		if (p_error == no_parse_error)
			break;
	}
	if (p_error == no_parse_error && triple != NULL) {
		triple->base = search_base;
		triple->scope = scope;
		triple->attrs = filter;
		triple->element = element;
		element = NULL;
		filter = NULL;
		search_base = NULL;
	}

	if (search_base != NULL)
		free(search_base);
	if (filter != NULL)
		free(filter);
	if (element != NULL) {
		free_mapping_element(element);
		free(element);
	}
	return (p_error == no_parse_error ? s : NULL);
}

/*
 * FUNCTION:	get_mapping_format
 *
 *	Get the __nis_mapping_format_t from the string
 *
 * RETURN VALUE:	FALSE if error
 *			TRUE if __nis_mapping_format_t returned
 *
 * INPUT:		the format string
 */

static bool_t
get_mapping_format(
	const char		*fmt_string,
	__nis_mapping_format_t	**fmt,
	int			*nfmt,
	int			*numItems,
	bool_t			print_mapping)
{
	const char		*f	= fmt_string;
	const char		*ef;
	__nis_mapping_format_t	*b;
	__nis_mapping_format_t	*base	= NULL;
	int			n	= 0;
	int			nItems	= 0;

	f = fmt_string;
	ef = f + strlen(f);
	base = (__nis_mapping_format_t *)
	    s_calloc(1, sizeof (__nis_mapping_format_t));

	if (base == NULL)
		return (FALSE);
	base->type = mmt_begin;
	n++;

	for (;;) {
		b = (__nis_mapping_format_t *)s_realloc(
		    base, (n + 1) * sizeof (__nis_mapping_format_t));

		if (b == NULL)
			break;
		base = b;
		base[n].type = mmt_end;
		if (f == ef) {
			if (nfmt)
				*nfmt = n + 1;
			*fmt = base;
			if (numItems)
				*numItems = nItems;
			return (TRUE);
		}
		if (print_mapping)
		    f = get_next_print_format_item(f, ef, &base[n]);
		else
		    f = get_next_extract_format_item(f, ef, &base[n]);


		if (f == NULL)
			break;
		if (base[n].type == mmt_item ||
			base[n].type == mmt_berstring)
			nItems++;
		n++;
	}
	if (base != NULL)
		free_mapping_format(base);
	return (FALSE);
}

/*
 * FUNCTION:	getIndex
 *
 *	Returns a string containing the index
 *
 * RETURN VALUE:	NULL if error
 *			a string containing the index
 *
 * INPUT:		attribute containing the index
 */

static char *
getIndex(const char **s_cur, const char *s_end)
{
	const char	*s		= *s_cur + 1;
	const char	*s1;
	char		*s_index;
	char		*s_index1;
	char		*s_index_end;
	int		n_brackets	= 1;
	bool_t		in_quotes	= FALSE;
	char		*index		= NULL;

	while (s < s_end && is_whitespace(*s))
		s++;
	for (s1 = s; s1 < s_end; s1++) {
		if (*s1 == ESCAPE_CHAR)
			s1++;
		else if (*s1 == DOUBLE_QUOTE_CHAR) {
			in_quotes = !in_quotes;
		} else if (in_quotes)
			;
		else if (*s1 == CLOSE_BRACKET) {
			if (--n_brackets == 0)
				break;
		} else if (*s1 == OPEN_BRACKET)
			n_brackets++;
	}

	if (n_brackets == 0) {
		index = s_strndup(s, s1 - s);
		if (index != NULL) {
			s_index_end = index + (s1 - s);
			s_index1 = index;
			for (s_index = index; s_index < s_index_end;
			    s_index++) {
				if (*s_index == ESCAPE_CHAR) {
					*s_index1++ = *s_index++;
				} else if (*s_index == DOUBLE_QUOTE_CHAR) {
					in_quotes = !in_quotes;
				} else if (!in_quotes &&
				    is_whitespace(*s_index)) {
					continue;
				}
				*s_index1++ = *s_index;
			}
			*s_index1 = *s_index;

			s = s1 + 1;

			while (s < s_end && is_whitespace(*s))
				s++;
			*s_cur = s;
		}
	} else
		p_error = parse_mismatched_brackets;

	return (index);
}

/*
 * FUNCTION:	parse_index
 *
 *	Parse attribute string to get __nis_index_t
 *
 * RETURN VALUE:	FALSE if error
 *			TRUE if __nis_index_t returned
 *
 * INPUT:		the attribute value to parse
 */

bool_t
parse_index(const char *s, const char *end_s, __nis_index_t *index)
{
	const char		*begin_token;
	const char		*end_token;
	char			*name_str	= NULL;
	char			**name;
	char			*fmt_string	= NULL;
	__nis_mapping_format_t	*v		= NULL;
	__nis_mapping_format_t	**value;
	token_type		t;
	int			n		 = 0;

	if (index != NULL)
		(void) memset(index, 0, sizeof (*index));

	while (s < end_s) {
		if (n > 0) {
			s = skip_token(s, end_s, comma_token);
			if (s == NULL) {
				p_error = parse_bad_index_format;
				break;
			}
		}
		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL)
			break;
		if (t != string_token) {
			p_error = parse_bad_index_format;
			break;
		}
		s = skip_token(s, end_s, equal_token);
		if (s == NULL) {
			p_error = parse_bad_index_format;
			break;
		}
		if (index != NULL) {
			name_str = s_strndup_esc(begin_token,
				end_token - begin_token);
			if (name_str == NULL)
				break;
		}
		begin_token = s;
		end_token = end_s;
		s = get_next_token(&begin_token, &end_token, &t);
		if (s == NULL)
			break;
		if (t != string_token && t != quoted_string_token) {
			p_error = parse_bad_index_format;
			break;
		}
		fmt_string = s_strndup(begin_token, end_token - begin_token);
		if (fmt_string == NULL)
			break;
		if (!get_mapping_format(fmt_string, &v, NULL, NULL, FALSE))
			break;
		free(fmt_string);
		fmt_string = NULL;
		if (index != NULL) {
			name = s_realloc(index->name,
				(n + 1) * sizeof (char *));
			if (name == NULL)
				break;
			value = s_realloc(index->value,
				(n + 1) * sizeof (__nis_mapping_format_t *));
			if (value == NULL)
				break;
			name[n] = name_str;
			name_str = NULL;
			value[n] = v;
			v = NULL;
			index->numIndexes = ++n;
			index->name = name;
			index->value = value;
		} else if (v != NULL) {
			free_mapping_format(v);
			v = NULL;
		}
	}
	if (p_error != no_parse_error) {
		if (name_str != NULL)
			free(name_str);
		if (v != NULL)
			free_mapping_format(v);
		if (fmt_string != NULL)
			free(fmt_string);
		if (index != NULL)
			free_index(index);
	}
	return (p_error != no_parse_error);
}

/*
 * FUNCTION:	get_deleteDisp
 *
 *	Parse deleteDisp. Sets p_error if an error occurred.
 *
 * RETURN VALUE:	TRUE on success
 *			FAILURE on failure
 *
 * INPUT:		begin and end of string and __nis_object_dn_t
 */

static bool_t
get_deleteDisp(const char *s_begin, const char *s_end,
		__nis_object_dn_t *obj_dn)
{
	/*
	 * deleteDisp: "always" | perDbId | "never"
	 * perDbId: "dbid" "=" delDatabaseId
	 */

	if (same_string("always", s_begin, s_end - s_begin)) {
		obj_dn->delDisp = dd_always;
	} else if (same_string("never", s_begin, s_end - s_begin)) {
		obj_dn->delDisp = dd_never;
	} else if ((s_begin = skip_string("dbid", s_begin, s_end - s_begin))
			!= NULL) {
		obj_dn->delDisp = dd_perDbId;
		while (s_begin < s_end && is_whitespace(*s_begin))
			s_begin++;
		if (s_begin == s_end || *s_begin != EQUAL_CHAR) {
			p_error = parse_object_dn_syntax_error;
		} else {
			s_begin++;
			while (s_begin < s_end && is_whitespace(*s_begin))
				s_begin++;
			while (s_begin < s_end && is_whitespace(s_end[-1]))
				s_end--;
			if (s_begin == s_end) {
				p_error = parse_object_dn_syntax_error;
			} else {
				obj_dn->dbIdName =
					s_strndup(s_begin, s_end - s_begin);
			}
		}
	} else {
		p_error = parse_object_dn_syntax_error;
	}
	return (p_error == no_parse_error);
}
