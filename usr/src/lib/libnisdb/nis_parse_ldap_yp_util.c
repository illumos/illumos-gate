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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include "ldap_parse.h"
#include "nis_parse_ldap_conf.h"
#include "nis_parse_ldap_util.h"
#include "ldap_util.h"

/* Forward declarations */
int getfullmapname(char **, const char *);
int checkfullmapname(const char *, const char *, __nis_table_mapping_t **,
    __nis_table_mapping_t **);
int append_domainContext(__nis_table_mapping_t **, char *, char *);

static int	merge_table_mapping(__nis_table_mapping_t *in,
	__nis_table_mapping_t *out);
__nis_table_mapping_t *new_merged_mapping(const char *,
	__nis_table_mapping_t *intbl);
static int append_mapping_rule(__nis_mapping_rule_t *src_rule,
	__nis_table_mapping_t *tbl, int flag);


static int copy_object_dn(__nis_object_dn_t	*in,
		__nis_object_dn_t	*newdn);

/*
 * FUNCTION:	initialize_table_mapping
 *
 * Initialize the __nis_table_mapping_t structure.
 *
 * INPUT:	__nis_table_mapping_t
 *
 */
void
initialize_table_mapping(
	__nis_table_mapping_t *mapping)
{
	if (mapping != NULL) {
		mapping->dbId = NULL;

		mapping->index.numIndexes = 0;
		mapping->index.name = NULL;
		mapping->index.value = NULL;

		mapping->numColumns = 0;
		mapping->column = NULL;

		mapping->initTtlLo = (time_t)NO_VALUE_SET;
		mapping->initTtlHi = (time_t)NO_VALUE_SET;
		mapping->ttl = (time_t)NO_VALUE_SET;

		mapping->usedns_flag = 0;
		mapping->securemap_flag = 0;
		mapping->commentChar = DEFAULT_COMMENT_CHAR;
		mapping->numSplits = 0;

		mapping->objectDN = NULL;

		mapping->separatorStr = DEFAULT_SEP_STRING;

		mapping->numRulesFromLDAP = 0;
		mapping->numRulesToLDAP = 0;

		mapping->ruleFromLDAP = NULL;
		mapping->ruleToLDAP = NULL;

		mapping->e = NULL;
		mapping->objName = NULL;
		mapping->objPath = NULL;
		mapping->obj = NULL;
		mapping->isMaster = 0;
		mapping->seq_num = NO_VALUE_SET;
	}
}

/*
 * FUNCTION:	initialize_yp_parse_structs
 *
 * Initialize the __yp_domain_context_t structure.
 *
 * INPUT:		__yp_domain_context_t
 *
 */
void
initialize_yp_parse_structs(
	__yp_domain_context_t	*ypDomains)
{
	ypDomains->numDomains = 0;
	ypDomains->domainLabels = NULL;
	ypDomains->domains = NULL;
	ypDomains->numYppasswdd = 0;
	ypDomains->yppasswddDomainLabels = NULL;
}

/*
 * FUNCTION: 	merge_table_mapping
 *
 * Merges information from one table_mapping struct
 * into another
 *
 * INPUT: Source and Destination table_mapping structs.
 * RETURN: 0 on success and > 0 on error.
 */

static int
merge_table_mapping(
	__nis_table_mapping_t *in,
	__nis_table_mapping_t *out)
{
	int i;
	int orig_num_rules;
	int append;

	if (in == NULL)
		return (1);

	if (in->dbId == NULL)
		return (1);

	/*
	 * If 'in' is generic (non-expanded) and 'out' is domain-specific,
	 * then rules from 'in' should not be appended to those in 'out'.
	 */
	if (!strchr(in->dbId, COMMA_CHAR) && strchr(out->dbId, COMMA_CHAR))
		append = 0;
	else
		append = 1;


	if (!out->index.numIndexes && in->index.numIndexes > 0) {
		if (!dup_index(&in->index, &out->index))
			return (1);
	}

	/* add_column() increments numColumns, so we don't */
	if (!out->numColumns && in->numColumns > 0) {
		for (i = 0; i < in->numColumns; i++) {
			if (!add_column(out, in->column[i]))
				return (1);
		}
	}

	if (out->commentChar == DEFAULT_COMMENT_CHAR &&
	    in->commentChar != DEFAULT_COMMENT_CHAR)
		out->commentChar = in->commentChar;

	if (out->usedns_flag == 0)
		out->usedns_flag = in->usedns_flag;

	if (out->securemap_flag == 0)
		out->securemap_flag = in->securemap_flag;

	if ((strcmp(out->separatorStr, DEFAULT_SEP_STRING) == 0) &&
	    (strcmp(in->separatorStr, DEFAULT_SEP_STRING) != 0)) {
		out->separatorStr = s_strdup(in->separatorStr);
		if (!out->separatorStr)
			return (2);
	}

	if (!out->numSplits && !out->e && in->e) {
		out->numSplits = in->numSplits;
		out->e = (__nis_mapping_element_t *)
		    s_calloc(1, (in->numSplits+1) *
		    sizeof (__nis_mapping_element_t));
		if (!out->e)
			return (2);
		for (i = 0; i <= in->numSplits; i++) {
			if (!dup_mapping_element(&in->e[i], &out->e[i])) {
				for (; i > 0; i--) {
					free_mapping_element(&out->e[i - 1]);
				}
				out->e = NULL;
				return (1);
			}
		}
	}

	if (out->initTtlLo == (time_t)NO_VALUE_SET &&
	    in->initTtlLo != (time_t)NO_VALUE_SET)
		out->initTtlLo = in->initTtlLo;

	if (out->initTtlHi == (time_t)NO_VALUE_SET &&
	    in->initTtlHi != (time_t)NO_VALUE_SET)
		out->initTtlHi = in->initTtlHi;

	if (out->ttl == (time_t)NO_VALUE_SET &&
	    in->ttl != (time_t)NO_VALUE_SET)
		out->ttl = in->ttl;

	if (!out->numRulesFromLDAP && in->numRulesFromLDAP) {
		out->ruleFromLDAP = dup_mapping_rules(in->ruleFromLDAP,
		    in->numRulesFromLDAP);
		if (!out->ruleFromLDAP)
			return (1);
		out->numRulesFromLDAP = in->numRulesFromLDAP;
	} else if (append && out->numRulesFromLDAP && in->numRulesFromLDAP) {
		orig_num_rules = out->numRulesFromLDAP;
		for (i = 0; i < in->numRulesFromLDAP; i++) {
			if (append_mapping_rule(in->ruleFromLDAP[i], out, 0)) {
				for (i = out->numRulesFromLDAP;
				    i > orig_num_rules; i--) {
					free_mapping_rule(out->ruleFromLDAP[i]);
					out->ruleFromLDAP[i] = NULL;
				}
				return (1);

			}
		}
	}

	if (!out->numRulesToLDAP && in->numRulesToLDAP) {
		out->ruleToLDAP = dup_mapping_rules(in->ruleToLDAP,
		    in->numRulesToLDAP);
		if (!out->ruleToLDAP)
			return (1);
		out->numRulesToLDAP = in->numRulesToLDAP;
	} else if (append && out->numRulesToLDAP && in->numRulesToLDAP) {
		orig_num_rules = out->numRulesToLDAP;
		for (i = 0; i < in->numRulesToLDAP; i++) {
			if (append_mapping_rule(in->ruleToLDAP[i], out, 1)) {
				for (i = out->numRulesToLDAP;
				    i > orig_num_rules; i--) {
					free_mapping_rule(out->ruleToLDAP[i]);
					out->ruleToLDAP[i] = NULL;
				}
				return (1);
			}
		}
	}
	if (!out->objectDN && in->objectDN) {
		out->objectDN = (__nis_object_dn_t *)
		    s_calloc(1, sizeof (__nis_object_dn_t));
		if (!out->objectDN)
			return (2);
		if (copy_object_dn(in->objectDN, out->objectDN)) {
			free_object_dn(out->objectDN);
			out->objectDN = NULL;
			return (1);
		}
	}

	if (!out->objName && in->objName) {
		if (!strchr(in->objName, SPACE_CHAR)) {
			/* objName has no space- a single map dbIdMapping */
			out->objName = s_strndup(in->objName,
			    strlen(in->objName));
			if (!out->objName)
				return (2);
		}
	}

	if (!out->objName && out->dbId) {
		out->objName = s_strndup(out->dbId, strlen(out->dbId));
		if (!out->objName)
			return (2);
	}

	if (out->seq_num == NO_VALUE_SET && in->seq_num >= 0)
		out->seq_num = in->seq_num;

	return (p_error == no_parse_error ? 0 : 1);
}

/*
 * FUNCTION:	copy_object_dn
 *
 * Copies a __nis_object_dn_t structure.
 *
 * RETURN:	0 on success, > 0 on failure.
 *
 * NOTE:	The caller MUST free newdn using
 *		free_object_dn() if return value != 0 (error condition)
 */

static int
copy_object_dn(__nis_object_dn_t *in, __nis_object_dn_t *newdn)
{
	if (in == NULL) {
		p_error = parse_no_object_dn;
		return (1);
	}
	while (in != NULL) {
		if (in->read.base == NULL) {
			newdn->read.base = NULL;
		} else {
			newdn->read.base = s_strndup(
			    in->read.base, strlen(in->read.base));
			if (newdn->read.base == NULL)
				return (2);
		}
		newdn->read.scope = in->read.scope;
		if (in->read.attrs) {
			newdn->read.attrs = s_strndup(
			    in->read.attrs, strlen(in->read.attrs));
			if (newdn->read.attrs == NULL) {
				return (2);
			}
		} else {
			newdn->read.attrs = NULL;
		}
		newdn->read.element = in->read.element;
		if (in->write.base != NULL) {
			newdn->write.base = s_strndup(
			    in->write.base, strlen(in->write.base));
			if (newdn->write.base == NULL)
				return (2);
		} else {
			newdn->write.base = NULL;
		}
		newdn->write.scope = in->write.scope;
		if (in->write.attrs != NULL) {
			newdn->write.attrs = s_strndup(
			    in->write.attrs, strlen(in->write.attrs));
			if (newdn->write.attrs == NULL) {
				return (2);
			}
		} else {
			newdn->write.attrs = NULL;
		}
		newdn->write.element = in->write.element;
		if (in->dbIdName) {
			newdn->dbIdName = s_strndup(in->dbIdName,
			    strlen(in->dbIdName));
			if (newdn->dbIdName == NULL)
				return (2);
		}

		if (in->delDisp)
			newdn->delDisp = in->delDisp;

		if (in->dbId && in->numDbIds > 0) {
			newdn->dbId = dup_mapping_rules(in->dbId,
			    in->numDbIds);
			if (!newdn->dbId)
				return (1);
			newdn->numDbIds = in->numDbIds;
		}
		if (in->next != NULL) {
			newdn->next = (__nis_object_dn_t *)s_calloc(1,
			    sizeof (__nis_object_dn_t));
			if (newdn->next == NULL)
				return (1);
			newdn = newdn->next;
			in = in->next;
		} else {
			return (0);
		}
	} /* End of while on in */

	return (0);
}

/*
 * FUNCTION:	free_yp_domain_context
 *
 * Frees __yp_domain_context_t
 *
 * INPUT:		__yp_domain_context_t
 */
void
free_yp_domain_context(__yp_domain_context_t *domains)
{
	int i;

	if (domains != NULL) {
		for (i = 0; i < domains->numDomains; i++) {
			if (domains->domains[i] != NULL) {
				free(domains->domains[i]);
				domains->domains[i] = NULL;
			}
			if (domains->domainLabels[i] != NULL) {
				free(domains->domainLabels[i]);
				domains->domainLabels[i] = NULL;
			}
		}
		domains->domains = NULL;
		domains->domainLabels = NULL;
		for (i = 0; i < domains->numYppasswdd; i++) {
			if (domains->yppasswddDomainLabels[i] != NULL) {
				free(domains->yppasswddDomainLabels[i]);
				domains->yppasswddDomainLabels[i] =
				    NULL;
			}
		}
		domains->yppasswddDomainLabels = NULL;
		domains->numDomains = 0;
		domains = NULL;
	}
}

/*
 * FUNCTION:	second_parser_pass
 *
 * Prepares the linked list of table_mappings for processing
 * by finish_parse(), adding, merging and deleting structures
 * as necessary. Also adds dummy objectDN info. for splitField's.
 *
 * RETURN VALUE: 0 on success, > 0 on failure.
 */
int
second_parser_pass(__nis_table_mapping_t **table_mapping)
{
	__nis_table_mapping_t   *t, *t2;
	__nis_table_mapping_t   *t_new = NULL, *tg;
	__nis_table_mapping_t	*prev = NULL;
	char	*objs, *dom;
	char	*objName = NULL;
	char	*lasts;
	char	*tobj, *alias, *dupalias, *tmp;
	char	*myself = "second_parser_pass";
	int	i = 0, len;

	prev = NULL;
	for (t = *table_mapping; t != NULL; ) {
		/*
		 * Temporarily using this field to flag deletion.
		 * 0 : don't delete
		 * 1 : delete
		 * The mapping structure will be deleted in final_parser_pass
		 */
		t->isMaster = 0;

		if (!t->dbId) {
			p_error = parse_bad_map_error;
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			    "%s: no dbId field", myself);
			return (1);
		}
		tg = NULL;
		dom = strchr(t->dbId, COMMA_CHAR);
		if (t->objName != NULL) {
			objName = strdup(t->objName);
			if (objName == NULL) {
				p_error = parse_no_mem_error;
				logmsg(MSG_NOMEM, LOG_ERR,
				    "%s: Cannot allocate memory for objName",
				    myself);
				return (1);
			}
			objs = (char *)strtok_r(objName, " ", &lasts);
			/* Get the generic mapping */
			if (dom != NULL) {
				tg = find_table_mapping(t->dbId, dom - t->dbId,
				    *table_mapping);
			}
		} else {
			objs = NULL;
			if (dom == NULL) {
				t->objName = s_strndup(t->dbId,
				    strlen(t->dbId));
				if (!t->objName) {
					logmsg(MSG_NOMEM, LOG_ERR,
					    "%s: Cannot allocate memory for "
					    "t->objName", myself);
					objs = NULL;
					return (2);
				}
			} else {
				/* Force relationship for domain specific */

				/* Get the generic mapping */
				tg = find_table_mapping(t->dbId, dom - t->dbId,
				    *table_mapping);
				if (tg == NULL || tg->objName == NULL) {
					/* If not found, use dbId for objName */
					t->objName = s_strndup(t->dbId,
					    strlen(t->dbId));
					if (t->objName == NULL) {
						logmsg(MSG_NOMEM, LOG_ERR,
				    "%s: Cannot allocate memory for t->objName",
						    myself);
						return (2);
					}
				} else {
					dom++;
					tobj = s_strndup(tg->objName,
					    strlen(tg->objName));
					if (tobj == NULL) {
						logmsg(MSG_NOMEM, LOG_ERR,
				    "%s: Cannot allocate memory for t->objName",
						    myself);
						return (2);
					}
					alias = (char *)strtok_r(tobj, " ",
					    &lasts);

					/* Loop 'breaks' on errors */
					while (alias) {
						tmp = NULL;
						dupalias = s_strndup(alias,
						    strlen(alias));
						if (!dupalias)
							break;
						if (getfullmapname(&dupalias,
						    dom)) {
							i = 1;
							break;
						}
						if (t->objName == NULL)
							t->objName = dupalias;
						else {
							len = strlen(t->objName)
							    + strlen(dupalias) +
							    2;
							tmp = s_calloc(1, len);
							if (tmp == NULL)
								break;
							snprintf(tmp, len,
							    "%s %s",
							    t->objName,
							    dupalias);
							free(dupalias);
							dupalias = NULL;
							free(t->objName);
							t->objName = tmp;
						}
						alias = (char *)strtok_r(NULL,
						    " ", &lasts);
					}

					if (tobj)
						free(tobj);

					if (alias ||
					    (objName = s_strdup(t->objName))
					    == NULL) {
						if (i)
							logmsg(MSG_NOTIMECHECK,
							    LOG_ERR,
		    "%s: getfullmapname failed for %s for domain \"%s\"",
							    myself, dupalias,
							    dom);
						else {
							p_error =
							    parse_no_mem_error;
							logmsg(MSG_NOMEM,
							    LOG_ERR,
					    "%s: Cannot allocate memory",
							    myself);
						}
						if (dupalias)
							free(dupalias);
						if (t->objName)
							free(t->objName);
						return (2);

					}
					objs = (char *)strtok_r(objName, " ",
					    &lasts);
				}
			}
		}

		if (tg != NULL) {
			if (merge_table_mapping(tg, t)) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
	    "Error merging information from the %s to the %s mapping structure",
				    tg->dbId, t->dbId);
				objs = NULL;
				if (objName)
					free(objName);
				return (1);
			}
		}

		/*
		 * If objName is "map1 map2" then do the second pass.
		 * If it is just "map1" however skip the expansion.
		 * Also skip it if t->objName is null.
		 */
		if (objs && strncasecmp(objs, t->objName,
		    strlen(t->objName))) {
			t2 = find_table_mapping(objs, strlen(objs),
			    *table_mapping);
			if (t2) {
				if (merge_table_mapping(t, t2)) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
	    "Error merging information from the %s to the %s mapping structure",
					    t->dbId, t2->dbId);
					objs = NULL;
					if (objName)
						free(objName);
					return (1);
				}
				t->isMaster = 1;
			} else {
				t_new = new_merged_mapping(objs, t);
				if (t_new) {
					t->isMaster = 1;
					if (prev != NULL)
						prev->next = t_new;
					else
						*table_mapping = t_new;
					prev = t_new;
					prev->next = t;
				} else {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
				    "Error creating a new mapping structure %s",
					    objs);
					objs = NULL;
					if (objName)
						free(objName);
					return (1);
				}
			}
			while ((objs = (char *)strtok_r(NULL, " ", &lasts))
			    != NULL) {
				t2 = find_table_mapping(objs, strlen(objs),
				    *table_mapping);
				if (t2) {
					if (merge_table_mapping(t, t2)) {
						logmsg(MSG_NOTIMECHECK, LOG_ERR,
	    "Error merging information from the %s to the %s mapping structure",
						    t->dbId, t2->dbId);
						objs = NULL;
						if (objName)
							free(objName);
						return (1);
					}
					t->isMaster = 1;
				} else {
					/*
					 * create a new t_map with dbId = objs
					 * and copy t->* into new t_map
					 */
					t_new = new_merged_mapping(objs, t);
					if (t_new) {
						t->isMaster = 1;
						if (prev != NULL)
							prev->next = t_new;
						else
							*table_mapping = t_new;
						prev = t_new;
						prev->next = t;
					} else {
						logmsg(MSG_NOTIMECHECK, LOG_ERR,
				    "Error creating a new mapping structure %s",
						    objs);
						objs = NULL;
						if (objName)
							free(objName);
						return (1);
					}
				}
			}
		} /* if objs!= NULL */

		prev = t;
		t = t->next;

		if (objName) {
			free(objName);
			objName = NULL;
			objs = NULL;
		}
	} /* for t = table_mapping loop */
	return (0);
}

__nis_table_mapping_t *
new_merged_mapping(const char *match,
	__nis_table_mapping_t	*intbl)
{

	__nis_table_mapping_t	*outtable = NULL;

	outtable = (__nis_table_mapping_t *)
	    s_calloc(1, sizeof (__nis_table_mapping_t));
	if (outtable == NULL)
		return (NULL);
	initialize_table_mapping(outtable);
	outtable->dbId = s_strndup(match, strlen(match));
	if (outtable->dbId == NULL) {
		free_table_mapping(outtable);
		outtable = NULL;
		return (NULL);
	}
	if (merge_table_mapping(intbl, outtable)) {
		free_table_mapping(outtable);
		outtable = NULL;
	}
	return (outtable);
}

/*
 * FUNCTION:	final_parser_pass
 *
 * completes the final expansion of t_map structures linked list.
 * all structures will have a non-null objPath as well as a objName
 * in the form of "mapname . domainname ." or "splitfieldname .
 * domainname .".
 *
 * RETURN VALUE:	0 on success, -1 on failure, -2 on fatal error.
 */
int
final_parser_pass(
	__nis_table_mapping_t   **table_mapping,
	__yp_domain_context_t   *ypDomains)
{
	__nis_table_mapping_t   *t;
	__nis_table_mapping_t	*t1, *returned_map;
	__nis_table_mapping_t   *prev = NULL;
	int			i;
	char			*myself = "final_parser_pass";
	int			nm;
	bool_t			r;
	int			del_tbl_flag = 0;

	if (ypDomains) {
		if (!ypDomains->numDomains) {
			p_error = parse_internal_error;
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			    "%s:No domains specified.", myself);
			return (-1);
		}
	} else {
		p_error = parse_internal_error;
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
		    "%s:No domain structure supplied.", myself);
		return (-1);
	}
	prev = NULL;

	for (t = *table_mapping; t != NULL; ) {

		/* Delete if marked for deletion by second_parser_pass */
		if (t->isMaster == 1) {
			if (prev != NULL)
				prev->next = t->next;
			else
				*table_mapping = t->next;
			t1 = t;
			t = t->next;
			free_table_mapping(t1);
			continue;
		}

		if (!t->objName && t->dbId) {
			t->objName = s_strndup(t->dbId, strlen(t->dbId));
			if (!t->objName) {
				logmsg(MSG_NOMEM, LOG_ERR,
				    "%s:Could not allocate.", myself);
				return (-1);
			}
		}
		i = ypDomains->numDomains;
		while (i > 0) {
			if (i == 1) {
			/* modify existing table_mapping's */
				nm = checkfullmapname(t->dbId,
				    ypDomains->domainLabels[0],
				    table_mapping, &returned_map);
				if (nm == 1) {
					/* delete this mapping structure */
					logmsg(MSG_NOTIMECHECK,
					    LOG_WARNING,
					    "Mapping structure %s,%s "
					    "already exists.",
					    t->dbId,
					    ypDomains->domainLabels[0]);
					if (merge_table_mapping(t,
					    returned_map)) {
						logmsg(MSG_NOTIMECHECK, LOG_ERR,
						    "Error merging information "
						    "from the %s to the %s "
						    "mapping structure.",
						    t->dbId,
						    returned_map->dbId);
						return (-1);
					}
					if (del_tbl_flag == 0)
						del_tbl_flag = 1;
				} else if (nm == -1) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"Error searching for %s,%s structure",
					    t->dbId,
					    ypDomains->domainLabels[0]);
					return (-1);
				} else if (nm == 0 || nm == 2) {
					if ((append_domainContext(&t,
					    ypDomains->domainLabels[0],
					    ypDomains->domains[0])) != 0) {
						logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Error appending domainContext %s",
						    ypDomains->domainLabels[0]);
						return (-1);
					}
					del_tbl_flag = 0;
				}
			} else { /* if (i > 1) */
				/* need to create new table_mapping's */
				nm = checkfullmapname(t->dbId,
				    ypDomains->domainLabels[i - 1],
				    table_mapping, &returned_map);
				if (nm == -1) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Error searching for %s,%s structure",
					    t->dbId,
					    ypDomains->domainLabels[i - 1]);
					return (-1);
				} else if (nm == 0) {
					t1 = new_merged_mapping(t->dbId, t);
					/* we clone ourselves */
					if (t1) {
						if ((append_domainContext(&t1,
					ypDomains->domainLabels[i - 1],
					ypDomains->domains[i - 1])) != 0) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Error appending domainContext %s",
					ypDomains->domainLabels[i - 1]);
							free(t1);
							return (-1);
						}
						if (prev != NULL) {
							t1->next = prev->next;
							prev->next = t1;
							prev = prev->next;
						} else {
							t1->next =
							    *table_mapping;
							*table_mapping = t1;
							prev = t1;
						}
					} else { /* if !t1 */
						p_error = parse_internal_error;
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s:Could not create new table -"
					" check all instances of %s for errors",
					    myself, t->dbId);
						return (-1);
					}
				} else if (nm == 1) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"Mapping structure %s,%s already exists.",
					    t->dbId,
					    ypDomains->domainLabels[i - 1]);
					/*
					 * We should be deleting this, but can't
					 * really do it here, because we need to
					 * match with the domainLabels[0] case
					 * too. So we will just flag it for now.
					 */
					if (merge_table_mapping(t,
					    returned_map)) {
						logmsg(MSG_NOTIMECHECK, LOG_ERR,
	"Error merging information from the %s to the %s mapping structure.",
						    t->dbId,
						    returned_map->dbId);
						return (-1);
					}
					del_tbl_flag = 1;
				} else if (nm == 2) {
					if ((append_domainContext(&t,
					    ypDomains->domainLabels[i - 1],
					    ypDomains->domains[i - 1])) != 0) {
						logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"Error appending domainContext %s",
						ypDomains->domainLabels[i - 1]);
						return (-1);
					}
				} /* end of "if (nm == 0)" */
			} /* end of else if (i > 1) */


			/*
			 * 'merge_table_mapping' only copies unexpanded
			 * objectDN values into returned_map. Hence,
			 * read.base and write.base in returned_map
			 * needs to be expanded.
			 */
			if (nm == 1 && returned_map && returned_map->objectDN) {
				r = make_fqdn(
				    returned_map->objectDN,
				    ypDomains->domains[i - 1]);
				if (r == TRUE &&
				    returned_map->objectDN->write.base) {
					r = make_full_dn(
					    &returned_map->objectDN->write.base,
					    ypDomains->domains[i - 1]);
				}

				if (r == FALSE) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
					    "Error appending domainContext "
					    "%s to %s",
					    ypDomains->domainLabels[i - 1],
					    returned_map->dbId);
					return (-2);
				}
			}
			i--;
		} /* end of while i > 0 loop */

		if (del_tbl_flag == 1) {
			if (prev != NULL) {
				prev->next = t->next;
				free_table_mapping(t);
				t = prev->next;
			} else {
				*table_mapping = t->next;
				free_table_mapping(t);
				t = *table_mapping;
			}
			del_tbl_flag = 0;
		} else {
			prev = t;
			t = t->next;
		}
	} /* end of table mapping loop */

	for (t = *table_mapping; t != NULL; t = t->next) {
		if (!t->dbId) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			    "%s:Fatal error: structure with no dbId found.",
			    myself);
			return (-2);
		}
		append_dot(&t->dbId);
		if (!t->objectDN) {
			p_error = parse_internal_error;
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			    "%s:No objectDN for %s.", myself, t->dbId);
			return (-1);
		}
	}

	return (0);
}

/*
 * FUNCTION: append_mapping_rule
 *
 * Appends mapping rules to a table_mapping structure
 * with previously existing rules. flag controls whether
 * the functions works on the rules From or To LDAP.
 *
 * RETURN VALUE: 0 on success, >= 1 on failure.
 */

static int
append_mapping_rule(__nis_mapping_rule_t *src_rule,
	__nis_table_mapping_t *dst, int flag)
{
	__nis_mapping_rule_t **rules = NULL;

	if (flag == 0) {
		if (dst->ruleFromLDAP == NULL) {
			p_error = parse_internal_error;
			return (1);
		}
		rules = (__nis_mapping_rule_t **)
		    s_realloc(dst->ruleFromLDAP,
		    (dst->numRulesFromLDAP + 1) *
		    sizeof (__nis_mapping_rule_t *));
		if (rules == NULL)
			return (2);
		dst->ruleFromLDAP = rules;
		rules[dst->numRulesFromLDAP] = dup_mapping_rule(src_rule);
		if (rules[dst->numRulesFromLDAP] == NULL) {
			p_error = parse_no_mem_error;
			return (2);
		}
		dst->numRulesFromLDAP++;
	} else if (flag == 1) {
		if (dst->ruleToLDAP == NULL) {
			p_error = parse_internal_error;
			return (1);
		}
		rules = (__nis_mapping_rule_t **)
		    s_realloc(dst->ruleToLDAP,
		    (dst->numRulesToLDAP + 1) *
		    sizeof (__nis_mapping_rule_t *));
		if (rules == NULL)
			return (2);
		dst->ruleToLDAP = rules;
		rules[dst->numRulesToLDAP] = dup_mapping_rule(src_rule);
		if (rules[dst->numRulesToLDAP] == NULL) {
			p_error = parse_no_mem_error;
			return (2);
		}
		dst->numRulesToLDAP++;
	} else
		return (1);

	return (0);
}

/*
 * FUNCTION: check_domain_specific_order
 *
 * Makes sure that an attribute with explicitly specified
 * nisLDAPdomainContext is found before its non-domain
 * specific counterpart.
 *
 * RETURN VALUE: 0 normal exit
 *               1 if domain specific attribute found
 *                 after non-domain specific one.
 *				 -1 some error condition
 */

int
check_domain_specific_order(const char *sd,
	config_key	attrib_num,
	__nis_table_mapping_t *table_mapping,
	__yp_domain_context_t   *ypDomains)
{
	__nis_table_mapping_t *t;
	char    *myself = "check_domain_specific_order";
	char	*type;
	char	*dbId = 0;
	int 	i, len;
	int		match = 0;

	if (ypDomains) {
		if (!ypDomains->numDomains) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			    "%s:No domains specified.", myself);
			return (-1);
		}
	} else {
		logmsg(MSG_NOTIMECHECK, LOG_ERR,
		    "%s:No domain structure supplied.", myself);
		return (-1);
	}

	for (i = 0; i < ypDomains->numDomains; i++) {
		for (t = table_mapping; t != NULL; t = t->next) {
			len = strlen(sd);
			if ((strcasecmp(t->dbId, sd) == 0) && (len ==
			    strlen(t->dbId)))
				/* prevent from matching against itself */
				continue;
			dbId = s_strndup(t->dbId, strlen(t->dbId));
			if (dbId == NULL) {
				logmsg(MSG_NOMEM, LOG_ERR,
				    "%s:Memory allocation error.", myself);
				return (-1);
			}

			if (getfullmapname(&dbId,
			    ypDomains->domainLabels[i])) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"Error getting fully qualified name for %s",
				    dbId);
				free(dbId);
				return (-1);
			}
			if ((strcasecmp(dbId, sd) == 0) && (len ==
			    strlen(dbId))) {
				match = 0;
				switch (attrib_num) {
					case key_yp_map_flags:
						if (t->usedns_flag != 0 ||
						    t->securemap_flag != 0)
							match = 1;
						type = YP_MAP_FLAGS;
						break;
					case key_yp_comment_char:
						if (t->commentChar !=
						    DEFAULT_COMMENT_CHAR)
							match = 1;
						type = YP_COMMENT_CHAR;
						break;
					case key_yp_repeated_field_separators:
						if (strcmp(t->separatorStr,
						    DEFAULT_SEP_STRING) != 0)
							match = 1;
						type =
					YP_REPEATED_FIELD_SEPARATORS;
						break;
					case key_yp_name_fields:
						if (t->e && t->numColumns)
							match = 1;
						type = YP_NAME_FIELDS;
					case key_yp_split_field:
						if (t->e && t->numColumns)
							match = 1;
						type = YP_SPLIT_FIELD;
						break;
					case key_yp_db_id_map:
						if (t->objName)
							match = 1;
						type = YP_DB_ID_MAP;
						break;
					case key_yp_entry_ttl:
						if (t->initTtlLo !=
						    (time_t)NO_VALUE_SET)
							match = 1;
						type = YP_ENTRY_TTL;
						break;
					case key_yp_ldap_object_dn:
						if (t->objectDN)
							match = 1;
						type = YP_LDAP_OBJECT_DN;
						break;
					case key_nis_to_ldap_map:
						if (t->ruleToLDAP)
							match = 1;
						type = NIS_TO_LDAP_MAP;
						break;
					case key_ldap_to_nis_map:
						if (t->ruleFromLDAP)
							match = 1;
						type = LDAP_TO_NIS_MAP;
						break;
					default:
						type = "unknown";
						match = 0;
						break;
				}	/* end of switch */
				if (match) {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
"Relative attribute '%s' of type '%s' found before fully qualified one '%s'",
					    t->dbId, type, sd);
					free(dbId);
					dbId = NULL;
					return (1);
				}
			} /* end of strncasecmp */
			free(dbId);
			dbId = NULL;
		} /* end of t loop */
	} /* end of i loop */
	if (dbId)
		free(dbId);
	dbId = NULL;
	return (0);
}

int
getfullmapname(char **mapname, const char *domainname)
{
	char *maps = *mapname;
	int maplen = strlen(maps);
	int domainlen = strlen(domainname);

	if (!maplen || !domainlen ||
	    maps[maplen - 1] == PERIOD_CHAR)
		return (1);
	else if (strchr(maps, COMMA_CHAR)) {
		/* map already has a domain part, do nothing */
		return (0);
	} else {
		append_comma(&maps);
		maplen = strlen(maps);
		maps = realloc(maps, (maplen + domainlen + 1));
		if (maps != NULL) {
			if (strlcat(maps, domainname, (maplen + domainlen + 1))
			    >= (maplen + domainlen + 1))
				return (1);
			*mapname = maps;
			return (0);
		} else
			return (1);
	}
}

/*
 * FUNCTION: checkfullmapname
 *
 * Tries to find out if by appending the table mapping structures
 * with each of the provided nisLDAPdomainContexts, an already
 * existing fqdn table mapping structure results. That would be the
 * case when a full qualified domain specific attribute was present.
 *
 * Note that per NISLDAPmapping(4) such an attribute MUST be listed
 * in the mapping file BEFORE its non-fqdn counterpart.
 *
 * RETURNS:	0 normal exit, 1 if an existing structure found, -1 for all
 * errors, 2 if already fqdn. If returning 1 the existing structure is
 * in found_map.
 */

int
checkfullmapname(const char *mapname, const char *domainname,
__nis_table_mapping_t **table_mapping,
__nis_table_mapping_t **found_map)
{
	char *map;

	*found_map = NULL;

	/* This function does not alter mapname */

	if (!mapname || !domainname || *table_mapping == NULL)
		return (-1);

	if (strchr(mapname, COMMA_CHAR))
		return (2);

	if ((map = s_strndup(mapname, strlen(mapname))) == 0)
		return (-1);

	if (getfullmapname(&map, domainname)) {
		free(map);
		return (-1);
	}

	*found_map = find_table_mapping(map, strlen(map), *table_mapping);
	if (*found_map) {
		free(map);
		return (1);
	}

	free(map);
	return (0);
}

/*
 * FUNCTION:	append_domainContext
 *
 * Higher level function to append the domains to the appropriate
 * fields in a table mapping structure. Calls either getfullmapname()
 * or make_full_dn() to do the actual append.
 *
 * RETURNS: 0 on success, -1 on any error.
 */

int
append_domainContext(__nis_table_mapping_t **table_map,
char   *DomainLabel, char *Domain)
{
	__nis_table_mapping_t *tmp_map = *table_map;
	char *lasts;
	char *tmp_dbId = NULL;
	char *id = NULL;
	int  domain_specific = 0;
	char *myself = "append_domainContext";

	if (!DomainLabel || !Domain || !tmp_map)
		return (-1);
	if (tmp_map->dbId == NULL || tmp_map->objName == NULL) {
		p_error = parse_bad_map_error;
		return (-1);
	}
	tmp_dbId = s_strndup(tmp_map->dbId, strlen(tmp_map->dbId));
	if (!tmp_dbId)
		return (-1);
	if (strchr(tmp_map->dbId, COMMA_CHAR)) {
		domain_specific = 1;
		id = (char *)strtok_r(tmp_dbId, COMMA_STRING, &lasts);
		if (id)
			id = (char *)strtok_r(NULL, COMMA_STRING, &lasts);
		else {
			free(tmp_dbId);
			return (-1);
		}
		if (!id) {
			free(tmp_dbId);
			return (-1);
		}
		if (strcasecmp(id, DomainLabel)) {
			free(tmp_dbId);
			return (0);
		}
	} else {
		if (getfullmapname(&tmp_map->dbId, DomainLabel)) {
			free(tmp_dbId);
			return (-1);
		}
		append_dot(&tmp_map->dbId);
	}
	if (tmp_dbId)
		free(tmp_dbId);
	tmp_dbId = NULL;

	if (getfullmapname(&tmp_map->objName, DomainLabel))
		return (-1);
	append_dot(&tmp_map->objName);

	/*
	 * If domain specific mapping doesn't have objectDN,
	 * then don't touch. Most probably, pass for the generic mapping
	 * will handle this by coping over it's own objectDN
	 */
	if (domain_specific && tmp_map->objectDN == NULL)
		return (0);

	if (tmp_map->objectDN == NULL) {
		/* Allocate memory to objectDN */
		tmp_map->objectDN = (__nis_object_dn_t *)
		    s_calloc(1, sizeof (__nis_object_dn_t));
		if (tmp_map->objectDN == NULL) {
			logmsg(MSG_NOMEM, LOG_ERR,
"%s: Cannot allocate memory for objectDN",
			    myself);
			return (2);
		}
		tmp_map->objectDN->read.base = NULL;
		tmp_map->objectDN->write.base = NULL;
		tmp_map->objectDN->read.attrs = NULL;
		tmp_map->objectDN->write.attrs = NULL;
		tmp_map->objectDN->read.scope = LDAP_SCOPE_ONELEVEL;
		tmp_map->objectDN->write.scope = LDAP_SCOPE_UNKNOWN;
	}

	if (!make_fqdn(tmp_map->objectDN, Domain))
		return (-1);
	if (tmp_map->objectDN->write.base) {
		if (!make_full_dn(&tmp_map->objectDN->write.base, Domain))
			return (-1);
	}

	return (0);
}
