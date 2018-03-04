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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <lber.h>
#include <ldap.h>
#include <syslog.h>
#include <dlfcn.h>	/* for dynamic loading only */

#include "ldap_parse.h"
#include "nis_parse_ldap_conf.h"
#include "nis_parse_ldap_err.h"
#include "ldap_util.h"
#include "ldap_util.h"

void append_dot(char **str);
void	append_comma(char **str);
bool_t make_full_dn(char **dn, const char *base);
bool_t make_fqdn(__nis_object_dn_t *dn, const char *base);
char *get_default_ldap_base(const char *domain);
bool_t add_domain(char **objName, const char *domain);
bool_t add_column(__nis_table_mapping_t *t, const char *col_name);
__nis_mapping_rule_t **dup_mapping_rules(
	__nis_mapping_rule_t **rules, int n_rules);
__nis_mapping_rule_t *dup_mapping_rule(
	__nis_mapping_rule_t *in);
void *s_malloc(size_t size);
__nis_mapping_format_t *dup_format_mapping(
	__nis_mapping_format_t *in);
bool_t dup_mapping_element(__nis_mapping_element_t *in,
	__nis_mapping_element_t *out);
bool_t is_string_ok(char *, int);

extern FILE *cons;

/*
 * FUNCTION:	free_parse_structs
 *
 *	Release the resources in parse results
 *
 */

void
free_parse_structs()
{
	__nis_table_mapping_t	*t;
	__nis_table_mapping_t	*t1;

	free_proxy_info(&proxyInfo);
	for (t = ldapTableMapping; t != NULL; t = t1) {
		t1 = t->next;
		free_table_mapping(t);
	}
	ldapTableMapping = NULL;
}

/*
 * FUNCTION:	initialize_parse_structs
 *
 *	Initialize fields to unset values
 *
 * INPUT:		__nis_ldap_proxy_info, __nis_config_t
 * 			and __nisdb_table_mapping_t structures
 */

void
initialize_parse_structs(
	__nis_ldap_proxy_info	*proxy_info,
	__nis_config_t		*config_info,
	__nisdb_table_mapping_t	*table_info)
{
	proxy_info->default_servers = NULL;
	proxy_info->auth_method = (auth_method_t)NO_VALUE_SET;
	proxy_info->tls_method = (tls_method_t)NO_VALUE_SET;
	proxy_info->tls_cert_db = NULL;
	proxy_info->default_search_base = NULL;
	proxy_info->proxy_dn = NULL;
	proxy_info->proxy_passwd = NULL;
	proxy_info->default_nis_domain = NULL;
	proxy_info->bind_timeout.tv_sec = (time_t)NO_VALUE_SET;
	proxy_info->bind_timeout.tv_usec = 0;
	proxy_info->search_timeout.tv_sec = (time_t)NO_VALUE_SET;
	proxy_info->search_timeout.tv_usec = 0;
	proxy_info->modify_timeout.tv_sec = (time_t)NO_VALUE_SET;
	proxy_info->modify_timeout.tv_usec = 0;
	proxy_info->add_timeout.tv_sec = (time_t)NO_VALUE_SET;
	proxy_info->add_timeout.tv_usec = 0;
	proxy_info->delete_timeout.tv_sec = (time_t)NO_VALUE_SET;
	proxy_info->delete_timeout.tv_usec = 0;
	proxy_info->search_time_limit = (int)NO_VALUE_SET;
	proxy_info->search_size_limit = (int)NO_VALUE_SET;
	proxy_info->follow_referral = (follow_referral_t)NO_VALUE_SET;


	config_info->initialUpdate = (__nis_initial_update_t)NO_VALUE_SET;
	config_info->threadCreationError =
		(__nis_thread_creation_error_t)NO_VALUE_SET;
	config_info->threadCreationErrorTimeout.attempts = NO_VALUE_SET;
	config_info->threadCreationErrorTimeout.timeout = (time_t)NO_VALUE_SET;
	config_info->dumpError = (__nis_dump_error_t)NO_VALUE_SET;
	config_info->dumpErrorTimeout.attempts = NO_VALUE_SET;
	config_info->dumpErrorTimeout.timeout = (time_t)NO_VALUE_SET;
	config_info->resyncService = (__nis_resync_service_t)NO_VALUE_SET;
	config_info->updateBatching = (__nis_update_batching_t)NO_VALUE_SET;
	config_info->updateBatchingTimeout.timeout = (time_t)NO_VALUE_SET;
	config_info->numberOfServiceThreads = (int)NO_VALUE_SET;
	config_info->emulate_yp = (int)NO_VALUE_SET;
	config_info->maxRPCRecordSize = (int)NO_VALUE_SET;

	table_info->retrieveError = (__nis_retrieve_error_t)NO_VALUE_SET;
	table_info->retrieveErrorRetry.attempts = NO_VALUE_SET;
	table_info->retrieveErrorRetry.timeout = (time_t)NO_VALUE_SET;
	table_info->storeError = (__nis_store_error_t)NO_VALUE_SET;
	table_info->storeErrorRetry.attempts = NO_VALUE_SET;
	table_info->storeErrorRetry.timeout = (time_t)NO_VALUE_SET;
	table_info->refreshError = (__nis_refresh_error_t)NO_VALUE_SET;
	table_info->refreshErrorRetry.attempts = NO_VALUE_SET;
	table_info->refreshErrorRetry.timeout = (time_t)NO_VALUE_SET;
	table_info->matchFetch = (__nis_match_fetch_t)NO_VALUE_SET;
}

/*
 * FUNCTION:	free_mapping_rule
 *
 *	Frees __nis_mapping_rule_t
 *
 * INPUT:		__nis_mapping_rule_t
 */

void
free_mapping_rule(__nis_mapping_rule_t	*rule)
{
	int			i;
	__nis_mapping_rlhs_t	*r;

	if (rule != NULL) {
		r = &rule->lhs;
		for (i = 0; i < r->numElements; i++)
			free_mapping_element(&r->element[i]);
		if (r->element != NULL)
			free(r->element);

		r = &rule->rhs;
		for (i = 0; i < r->numElements; i++)
			free_mapping_element(&r->element[i]);
		if (r->element != NULL)
			free(r->element);

		free(rule);
	}
}

/*
 * FUNCTION:	free_mapping_element
 *
 *	Frees __nis_mapping_element_t
 *
 * INPUT:		__nis_mapping_element_t
 */

void
free_mapping_element(__nis_mapping_element_t *e)
{
	int	i;

	if (e == NULL)
		return;

	switch (e->type) {
	    case me_item:
		free_mapping_item(&e->element.item);
		break;
	    case me_print:
		if (e->element.print.fmt != NULL)
			free_mapping_format(e->element.print.fmt);
		e->element.print.fmt = NULL;
		for (i = 0; i < e->element.print.numSubElements; i++)
			free_mapping_sub_element(
				&e->element.print.subElement[i]);
		e->element.print.numSubElements = 0;
		if (e->element.print.subElement != NULL)
			free(e->element.print.subElement);
		e->element.print.subElement = NULL;
		break;
	    case me_split:
		free_mapping_item(&e->element.split.item);
		break;
	    case me_match:
		if (e->element.match.fmt != NULL)
			free_mapping_format(e->element.match.fmt);
		e->element.match.fmt = NULL;
		for (i = 0; i < e->element.match.numItems; i++)
			free_mapping_item(&e->element.match.item[i]);
		e->element.match.numItems = 0;
		if (e->element.match.item != NULL)
		    free(e->element.match.item);
		e->element.match.item = NULL;
		break;
	    case me_extract:
		if (e->element.extract.fmt != NULL)
			free_mapping_format(e->element.extract.fmt);
		e->element.extract.fmt = NULL;
		free_mapping_item(&e->element.extract.item);
		break;
	}
	e = NULL;
}

/*
 * FUNCTION:	free_table_mapping
 *
 *	Frees __nis_table_mapping_t
 *
 * INPUT:		__nis_table_mapping_t
 */

/*
 * free_table_mapping does not remove the table mapping from
 * its hashed list
 */

void
free_table_mapping(__nis_table_mapping_t *mapping)
{
	int	i;

	if (mapping == NULL)
		return;

	if (mapping->dbId != NULL)
		free(mapping->dbId);
	mapping->dbId = NULL;

	if (mapping->objName != NULL)
		free(mapping->objName);
	mapping->objName = NULL;

	for (i = 0; i < mapping->index.numIndexes; i++) {
		free(mapping->index.name[i]);
		free_mapping_format(mapping->index.value[i]);
	}

	if (mapping->index.name != NULL)
		free(mapping->index.name);
	mapping->index.name = NULL;

	if (mapping->index.value != NULL)
		free(mapping->index.value);
	mapping->index.value = NULL;

	mapping->index.numIndexes = 0;

	if (mapping->column != NULL) {
		for (i = 0; i < mapping->numColumns; i++) {
			free(mapping->column[i]);
		}
		mapping->numColumns = 0;
		free(mapping->column);
		mapping->column = NULL;
	}

	if (mapping->commentChar != NULL)
		mapping->commentChar = NULL;

	if (mapping->objectDN != NULL)
		free_object_dn(mapping->objectDN);
	mapping->objectDN = NULL;

	if (mapping->separatorStr != NULL)
		mapping->separatorStr = NULL;

	for (i = 0; i < mapping->numRulesFromLDAP; i++) {
		if (mapping->ruleFromLDAP[i]) /* See Comment below */
			free_mapping_rule(mapping->ruleFromLDAP[i]);
	}
	mapping->numRulesFromLDAP = 0;

	if (mapping->ruleFromLDAP != NULL)
		free(mapping->ruleFromLDAP);
	mapping->ruleFromLDAP = NULL;

	for (i = 0; i < mapping->numRulesToLDAP; i++) {
		if (mapping->ruleToLDAP[i])
		/*
		 * Normally mapping->ruleToLDAP[i] should
		 * always be non-null if
		 * mapping->numRulesToLDAP is > 0.
		 * However it is possible to have data
		 * corruption where numRulesToLDAP gets
		 * some integer value even though no real
		 * data is present in mapping->ruleToLDAP.
		 */
			free_mapping_rule(mapping->ruleToLDAP[i]);
	}
	mapping->numRulesToLDAP = 0;

	if (mapping->ruleToLDAP != NULL)
		free(mapping->ruleToLDAP);
	mapping->ruleToLDAP = NULL;

	if (mapping->e != NULL) {
		/* Similar logic as in above comment applies. */
		for (i = 0; i <= mapping->numSplits; i++) {
			free_mapping_element(&mapping->e[i]);
		}
		free(mapping->e);
	}
	mapping->e = NULL;

	mapping->numSplits = 0;

	free(mapping);
}

/*
 * FUNCTION:	free_config_info
 *
 *	Frees __nis_config_info_t
 *
 * INPUT:		__nis_config_info_t
 */

void
free_config_info(__nis_config_info_t *config_info)
{
	if (config_info->config_dn != NULL)
		free(config_info->config_dn);
	config_info->config_dn = NULL;

	if (config_info->default_servers != NULL)
		free(config_info->default_servers);
	config_info->default_servers = NULL;

	if (config_info->proxy_dn != NULL)
		free(config_info->proxy_dn);
	config_info->proxy_dn = NULL;

	if (config_info->proxy_passwd != NULL)
		free(config_info->proxy_passwd);
	config_info->proxy_passwd = NULL;

	if (config_info->tls_cert_db != NULL)
		free(config_info->tls_cert_db);
	config_info->tls_cert_db = NULL;
}

/*
 * FUNCTION:	free_proxy_info
 *
 *	Frees __nis_ldap_proxy_info
 *
 * INPUT:		__nis_ldap_proxy_info
 */

void
free_proxy_info(__nis_ldap_proxy_info *proxy_info)
{
	if (proxy_info->tls_cert_db != NULL)
		free(proxy_info->tls_cert_db);
	proxy_info->tls_cert_db = NULL;

	if (proxy_info->default_servers != NULL)
		free(proxy_info->default_servers);
	proxy_info->default_servers = NULL;

	if (proxy_info->default_search_base != NULL)
		free(proxy_info->default_search_base);
	proxy_info->default_search_base = NULL;

	if (proxy_info->proxy_dn != NULL)
		free(proxy_info->proxy_dn);
	proxy_info->proxy_dn = NULL;

	if (proxy_info->proxy_passwd != NULL)
		free(proxy_info->proxy_passwd);
	proxy_info->proxy_passwd = NULL;

	if (proxy_info->default_nis_domain != NULL)
		free(proxy_info->default_nis_domain);
	proxy_info->default_nis_domain = NULL;
}

/*
 * FUNCTION:	free_object_dn
 *
 *	Frees __nis_object_dn_t
 *
 * INPUT:		__nis_object_dn_t
 */

void
free_object_dn(__nis_object_dn_t *obj_dn)
{
	__nis_object_dn_t	*t;
	int			i;

	while (obj_dn != NULL) {
		if (obj_dn->read.base != NULL)
			free(obj_dn->read.base);
		obj_dn->read.base = NULL;
		if (obj_dn->read.attrs != NULL)
			free(obj_dn->read.attrs);
		obj_dn->read.attrs = NULL;
		if (obj_dn->write.base != NULL)
			free(obj_dn->write.base);
		obj_dn->write.base = NULL;
		if (obj_dn->write.attrs != NULL)
			free(obj_dn->write.attrs);
		obj_dn->write.attrs = NULL;
		if (obj_dn->dbIdName != NULL)
			free(obj_dn->dbIdName);
		obj_dn->dbIdName = NULL;
		for (i = 0; i < obj_dn->numDbIds; i++)
			free_mapping_rule(obj_dn->dbId[i]);
		obj_dn->numDbIds = 0;

		if (obj_dn->dbId != NULL)
			free(obj_dn->dbId);
		obj_dn->dbId = NULL;

		t = obj_dn;
		obj_dn = obj_dn->next;
		free(t);
	}
}

/*
 * FUNCTION:	free_index
 *
 *	Frees __nis_index_t
 *
 * INPUT:		__nis_index_t
 */

void
free_index(__nis_index_t *index)
{
	int	i;
	for (i = 0; i < index->numIndexes; i++) {
		free(index->name[i]);
		free_mapping_format(index->value[i]);
	}
	index->numIndexes = 0;
	if (index->name != NULL)
		free(index->name);
	index->name = NULL;
	if (index->value != NULL)
		free(index->value);
	index->value = NULL;
}

/*
 * FUNCTION:	free_mapping_item
 *
 *	Frees __nis_mapping_item_t
 *
 * INPUT:		__nis_mapping_item_t
 */

void
free_mapping_item(__nis_mapping_item_t	*item)
{
	if (item == NULL)
		return;

	if (item->name != NULL)
		free(item->name);
	item->name = NULL;
	if (item->type == mit_nisplus) {
		free_index(&item->searchSpec.obj.index);
		if (item->searchSpec.obj.name != NULL)
			free(item->searchSpec.obj.name);
		item->searchSpec.obj.name = NULL;
	} else if (item->type == mit_ldap) {
		if (item->searchSpec.triple.base != NULL)
			free(item->searchSpec.triple.base);
		item->searchSpec.triple.base = NULL;
		if (item->searchSpec.triple.attrs != NULL)
			free(item->searchSpec.triple.attrs);
		item->searchSpec.triple.attrs = NULL;
		if (item->searchSpec.triple.element != NULL) {
			free_mapping_element(
				item->searchSpec.triple.element);
			free(item->searchSpec.triple.element);
		}
		item->searchSpec.triple.element = NULL;
	}
	if (item->exItem != NULL) {
		free_mapping_item(item->exItem);
		free(item->exItem);
		item->exItem = 0;
	}
}

/*
 * FUNCTION:	free_mapping_format
 *
 *	Frees __nis_mapping_format_t
 *
 * INPUT:		__nis_mapping_format_t
 */

void
free_mapping_format(__nis_mapping_format_t *fmt)
{
	__nis_mapping_format_t *f = fmt;

	while (fmt->type != mmt_end) {
		switch (fmt->type) {
		    case mmt_item:
			break;
		    case mmt_string:
			if (fmt->match.string != NULL)
				free(fmt->match.string);
			fmt->match.string = NULL;
			break;
		    case mmt_single:
			if (fmt->match.single.lo != NULL)
				free(fmt->match.single.lo);
			fmt->match.single.lo = NULL;
			if (fmt->match.single.hi != NULL)
				free(fmt->match.single.hi);
			fmt->match.single.hi = NULL;
			break;
		    case mmt_limit:
			break;
		    case mmt_any:
			break;
		    case mmt_berstring:
		    case mmt_berstring_null:
			if (fmt->match.berString != NULL)
				free(fmt->match.berString);
			fmt->match.berString = NULL;
			break;
		    case mmt_begin:
			break;
		    case mmt_end:
			break;
		}
		fmt++;
	}
	free(f);
}

/*
 * FUNCTION:	free_mapping_sub_element
 *
 *	Frees __nis_mapping_sub_element_t
 *
 * INPUT:		__nis_mapping_sub_element_t
 */

void
free_mapping_sub_element(__nis_mapping_sub_element_t *sub)
{
	int	i;

	switch (sub->type) {
	    case me_item:
		free_mapping_item(&sub->element.item);
		break;
	    case me_print:
		if (sub->element.print.fmt != NULL)
			free_mapping_format(sub->element.print.fmt);
		sub->element.print.fmt = NULL;
		for (i = 0; i < sub->element.print.numItems; i++)
			free_mapping_item(&sub->element.print.item[i]);
		sub->element.print.numItems = 0;
		if (sub->element.print.item != NULL)
			free(sub->element.print.item);
		sub->element.print.item = NULL;
		break;
	    case me_split:
		free_mapping_item(&sub->element.split.item);
		break;
	    case me_extract:
		if (sub->element.extract.fmt != NULL)
			free_mapping_format(sub->element.extract.fmt);
		sub->element.extract.fmt = NULL;
		free_mapping_item(&sub->element.extract.item);
		break;
	}
}

/*
 * FUNCTION:	read_line
 *
 *	Gets next line in buffer - using '\' at end of line
 *  to indicate continuation. Lines beginning with # are
 *	ignored. start_line_num and start_line_num are
 *	maintained to track the line number currently being
 *	parsed.
 *
 * RETURN VALUE:	The number of characters read. 0 for
 *                      eof, -1 for error
 *
 * INPUT:		file descriptor, buffer, and buffer size
 */

int
read_line(int fd, char *buffer, int buflen)
{
	int		linelen;
	int		rc;
	char		c;
	bool_t		skip_line	= FALSE;
	bool_t		begin_line	= TRUE;
	static bool_t	prev_cr		= FALSE;

	start_line_num = cur_line_num;
	(void) memset(buffer, 0, buflen);
	for (; p_error == no_parse_error; ) {
		linelen = 0;
		while (linelen < buflen) {
			rc = read(fd, &c, 1);
			if (1 == rc) {
				if (c == '\n' || c == '\r') {
					if (c == '\n') {
						if (prev_cr) {
							prev_cr = FALSE;
							continue;
						} else {
							if (linelen == 0)
							    start_line_num =
								cur_line_num;
							else {
								if (
								is_string_ok(
								buffer,
								linelen)) {
								(void) memset(
								buffer, 0,
								linelen);
								linelen = 0;
								cur_line_num++;
								begin_line =
									TRUE;
								continue;
								}
							}
							cur_line_num++;
						}
						prev_cr = FALSE;
					} else {
						prev_cr = TRUE;
						if (linelen == 0)
						    start_line_num =
							cur_line_num;
						cur_line_num++;
					}
					if (skip_line) {
						skip_line = FALSE;
						if (linelen == 0)
						    start_line_num =
							cur_line_num;
					} else if (linelen > 0 &&
					    buffer[linelen - 1]
					    == ESCAPE_CHAR) {
						--linelen;
					} else if (linelen > 0) {
						buffer[linelen] = '\0';
						return (linelen);
					}
					begin_line = TRUE;
				} else {
					if (begin_line)
						skip_line = c == POUND_SIGN;
					begin_line = FALSE;
					if (!skip_line)
						buffer[linelen++] = c;
				}
			} else {
				if (linelen > 0 &&
				    buffer[linelen - 1] == ESCAPE_CHAR) {
					/* continuation on last line */
					p_error = parse_bad_continuation_error;
					return (-1);
				} else {
					buffer[linelen] = '\0';
					return (linelen);
				}
			}
		}
		p_error = parse_line_too_long;
	}
	return (-1);
}

/*
 * FUNCTION:	finish_parse
 *
 *	Adds any elements not configured, fully qualifies
 *      names
 *
 * RETURN VALUE:	0 on success, -1 on failure
 */

int
finish_parse(
	__nis_ldap_proxy_info	*proxy_info,
	__nis_table_mapping_t	**table_mapping)
{
	__nis_table_mapping_t	*t;
	__nis_table_mapping_t	*t1;
	__nis_table_mapping_t	*t2;
	__nis_table_mapping_t	*t_del		= NULL;
	int			i;
	int			j;
	int			k;
	__nis_object_dn_t	*objectDN;
	__nis_mapping_rlhs_t	*lhs;
	__nis_mapping_element_t	*e;
	char			*s;
	int			errnum;

	/* set to default those values yet set */
	if (proxy_info->auth_method ==
	    (auth_method_t)NO_VALUE_SET) {
		p_error = parse_no_proxy_auth_error;
		report_error(NULL, NULL);
		return (-1);
	}

	if (proxy_info->default_servers == NULL) {
		p_error = parse_no_ldap_server_error;
		report_error(NULL, NULL);
		return (-1);
	}

	if (proxy_info->tls_method == (tls_method_t)NO_VALUE_SET)
		proxy_info->tls_method = no_tls;
	else if (proxy_info->tls_method == ssl_tls &&
			(proxy_info->tls_cert_db == NULL ||
			*proxy_info->tls_cert_db == '\0')) {
		p_error = parse_no_cert_db;
		report_error(NULL, NULL);
		return (-1);
	}

	if (proxy_info->default_nis_domain == NULL)
		proxy_info->default_nis_domain =
			s_strdup(__nis_rpc_domain());
	else if (*proxy_info->default_nis_domain == '\0') {
		free(proxy_info->default_nis_domain);
		proxy_info->default_nis_domain =
			s_strdup(__nis_rpc_domain());
	}
	if (proxy_info->default_nis_domain != NULL)
		append_dot(&proxy_info->default_nis_domain);

	if (proxy_info->tls_method == ssl_tls) {
		if ((errnum = ldapssl_client_init(
				proxy_info->tls_cert_db, NULL)) < 0) {
			p_error = parse_ldapssl_client_init_error;
			report_error(ldapssl_err2string(errnum), NULL);
			return (-1);
		}
	}

	if (proxy_info->default_search_base == NULL)
	    proxy_info->default_search_base =
		get_default_ldap_base(proxy_info->default_nis_domain);

	/* convert a relative dn to a fullly qualified dn */
	(void) make_full_dn(&proxy_info->proxy_dn,
		proxy_info->default_search_base);

	if (p_error != no_parse_error) {
		report_error(NULL, NULL);
		return (-1);
	}

	/*
	 * Create a list of potential delete mappings
	 * those have NULL objectDNs, but badly also rules
	 * that are missing object dn's will be included.
	 * We will use the ttl field to determine if the
	 * delete rule is actually used
	 */
	t2 = NULL;
	for (t = *table_mapping; t != NULL; t = t1) {
		t1 = t->next;
		if (t->objectDN == NULL) {
			if (t2 == NULL)
				*table_mapping = t1;
			else
				t2->next = t1;
			t->next = t_del;
			t_del = t;
			t->ttl = 0;
		} else
			t2 = t;
	}

	for (t = *table_mapping; t != NULL; t = t->next) {
	    objectDN = t->objectDN;
	    while (objectDN != NULL) {
		if (objectDN->dbIdName != NULL) {
			s = objectDN->dbIdName;
			t1 = find_table_mapping(s, strlen(s), t_del);
			if (t1 == NULL) {
				p_error = parse_no_db_del_mapping_rule;
				report_error2(objectDN->dbIdName, t->dbId);
				return (-1);
			} else if (t1->objName != NULL ||
			    t1->numRulesToLDAP == 0 ||
			    t1->numRulesFromLDAP != 0) {
				p_error = parse_invalid_db_del_mapping_rule;
				report_error(t1->dbId, NULL);
				return (-1);
			}
			objectDN->dbId =
				dup_mapping_rules(t1->ruleToLDAP,
					t1->numRulesToLDAP);
			if (objectDN->dbId == NULL) {
				break;
			}
			objectDN->numDbIds = t1->numRulesToLDAP;
			t1->ttl++;
		}
		objectDN = objectDN->next;
	    }
	}

	for (t = t_del; t != NULL; t = t1) {
		t1 = t->next;
		if (t->ttl == 0) {
			p_error = parse_no_object_dn;
			report_error(t->dbId, NULL);
		}
		free_table_mapping(t);
	}

	if (p_error != no_parse_error)
		return (-1);

	/* set to default those table mapping values yet set */
	for (t = *table_mapping; t != NULL; t = t->next) {
		if (t->objName == 0) {
			p_error = parse_no_object_dn;
			report_error(t->dbId, NULL);
			return (-1);
		}
		if (!yp2ldap) {
			if (!add_domain(&t->objName,
					proxy_info->default_nis_domain)) {
				report_error(NULL, NULL);
				return (-1);
			}
		}
		if (t->initTtlHi == (time_t)NO_VALUE_SET)
			t->initTtlHi = DEFAULT_TTL_HIGH;
		if (t->initTtlLo == (time_t)NO_VALUE_SET)
			t->initTtlLo = DEFAULT_TTL_LOW;
		if (t->ttl == (time_t)NO_VALUE_SET)
			t->ttl = DEFAULT_TTL;
		objectDN = t->objectDN;

		/* fixup relative dn's */
		while (objectDN != NULL) {
			if (!yp2ldap) {
				if (!make_full_dn(&objectDN->read.base,
					proxy_info->default_search_base))
						break;
			}
			if (objectDN->write.scope != LDAP_SCOPE_UNKNOWN) {
				if (objectDN->write.base != NULL &&
					!make_full_dn(&objectDN->write.base,
					proxy_info->default_search_base))
						break;
				if (objectDN->write.base == NULL) {
				    objectDN->write.base =
					s_strdup(objectDN->read.base);
				    if (objectDN->write.base == NULL)
					break;
				}
			}
			objectDN = objectDN->next;
		}

		if (p_error != no_parse_error) {
			report_error(NULL, NULL);
			return (-1);
		}

		/* Check for ruleToLDAP with no rhs */
		for (i = 0; i < t->numRulesToLDAP; i++) {
		    if (t->ruleToLDAP[i]->rhs.numElements == 0) {
			p_error = parse_unexpected_data_end_rule;
			report_error(t->dbId, NULL);
			return (-1);
		    }
		}

		/* populate cols field */
		if (!yp2ldap) {
			for (i = 0; i < t->numRulesFromLDAP; i++) {
				lhs = &t->ruleFromLDAP[i]->lhs;
				for (j = 0; j < lhs->numElements; j++) {
					e = &lhs->element[j];
					switch (e->type) {
						case me_item:
						if (!add_column(t,
						e->element.item.name)) {
							report_error(
							NULL, NULL);
							return (-1);
						}
						break;
						case me_match:
						for (k = 0;
						k < e->element.match.numItems;
						k++)
							if (!add_column(t,
					e->element.match.item[k].name)) {
								report_error(
								NULL, NULL);
								return (-1);
							}
						break;
					}
				}
			}
		}
	}
	return (0);
}

/*
 * FUNCTION:	set_default_values
 *
 *	Sets unconfigured values to their default value
 */

void
set_default_values(__nis_ldap_proxy_info *proxy_info,
    __nis_config_t *config_info, __nisdb_table_mapping_t *table_info)
{
	if (proxy_info->bind_timeout.tv_sec == (time_t)NO_VALUE_SET)
		proxy_info->bind_timeout.tv_sec = DEFAULT_BIND_TIMEOUT;
	if (proxy_info->search_timeout.tv_sec == (time_t)NO_VALUE_SET)
		proxy_info->search_timeout.tv_sec =
			(yp2ldap)?DEFAULT_YP_SEARCH_TIMEOUT:
				DEFAULT_SEARCH_TIMEOUT;
	if (proxy_info->modify_timeout.tv_sec == (time_t)NO_VALUE_SET)
		proxy_info->modify_timeout.tv_sec = DEFAULT_MODIFY_TIMEOUT;
	if (proxy_info->add_timeout.tv_sec == (time_t)NO_VALUE_SET)
		proxy_info->add_timeout.tv_sec = DEFAULT_ADD_TIMEOUT;
	if (proxy_info->delete_timeout.tv_sec == (time_t)NO_VALUE_SET)
		proxy_info->delete_timeout.tv_sec = DEFAULT_DELETE_TIMEOUT;

	if (proxy_info->search_time_limit == (int)NO_VALUE_SET)
		proxy_info->search_time_limit = DEFAULT_SEARCH_TIME_LIMIT;
	if (proxy_info->search_size_limit == (int)NO_VALUE_SET)
		proxy_info->search_size_limit = DEFAULT_SEARCH_SIZE_LIMIT;

	if (proxy_info->follow_referral == (follow_referral_t)NO_VALUE_SET)
		proxy_info->follow_referral = no_follow;

	switch (config_info->initialUpdate) {
		case (__nis_initial_update_t)NO_VALUE_SET:
		case (__nis_initial_update_t)INITIAL_UPDATE_NO_ACTION:
		case (__nis_initial_update_t)NO_INITIAL_UPDATE_NO_ACTION:
			config_info->initialUpdate = ini_none;
			break;
		case (__nis_initial_update_t)FROM_NO_INITIAL_UPDATE:
			config_info->initialUpdate = from_ldap;
			break;
		case (__nis_initial_update_t)TO_NO_INITIAL_UPDATE:
			config_info->initialUpdate = to_ldap;
			break;
	}
	if (config_info->threadCreationError ==
	    (__nis_thread_creation_error_t)NO_VALUE_SET)
		config_info->threadCreationError = pass_error;
	if (config_info->threadCreationErrorTimeout.attempts == NO_VALUE_SET)
		config_info->threadCreationErrorTimeout.attempts =
			DEFAULT_THREAD_ERROR_ATTEMPTS;
	if (config_info->threadCreationErrorTimeout.timeout ==
			(time_t)NO_VALUE_SET)
		config_info->threadCreationErrorTimeout.timeout =
			DEFAULT_THREAD_ERROR_TIME_OUT;
	if (config_info->dumpError ==
	    (__nis_dump_error_t)NO_VALUE_SET)
		config_info->dumpError = de_retry;
	if (config_info->dumpErrorTimeout.attempts == NO_VALUE_SET)
		config_info->dumpErrorTimeout.attempts =
			DEFAULT_DUMP_ERROR_ATTEMPTS;
	if (config_info->dumpErrorTimeout.timeout == (time_t)NO_VALUE_SET)
		config_info->dumpErrorTimeout.timeout =
			DEFAULT_DUMP_ERROR_TIME_OUT;
	if (config_info->resyncService ==
	    (__nis_resync_service_t)NO_VALUE_SET)
		config_info->resyncService = from_copy;
	if (config_info->updateBatching ==
	    (__nis_update_batching_t)NO_VALUE_SET)
		config_info->updateBatching = accumulate;
	if (config_info->updateBatchingTimeout.timeout == (time_t)NO_VALUE_SET)
		config_info->updateBatchingTimeout.timeout =
			DEFAULT_BATCHING_TIME_OUT;
	if (config_info->numberOfServiceThreads == (int)NO_VALUE_SET)
		config_info->numberOfServiceThreads =
			DEFAULT_NUMBER_OF_THREADS;
	if (config_info->emulate_yp == (int)NO_VALUE_SET)
		config_info->emulate_yp =
			DEFAULT_YP_EMULATION;
	if (config_info->maxRPCRecordSize == (int)NO_VALUE_SET)
		config_info->maxRPCRecordSize = RPC_MAXDATASIZE;

	if (table_info->retrieveError ==
	    (__nis_retrieve_error_t)NO_VALUE_SET)
		table_info->retrieveError = use_cached;
	if (table_info->retrieveErrorRetry.attempts == NO_VALUE_SET)
		table_info->retrieveErrorRetry.attempts =
			DEFAULT_RETRIEVE_ERROR_ATTEMPTS;
	if (table_info->retrieveErrorRetry.timeout == (time_t)NO_VALUE_SET)
		table_info->retrieveErrorRetry.timeout =
			DEFAULT_RETRIEVE_ERROR_TIME_OUT;
	if (table_info->storeError ==
	    (__nis_store_error_t)NO_VALUE_SET)
		table_info->storeError = sto_retry;
	if (table_info->storeErrorRetry.attempts == NO_VALUE_SET)
		table_info->storeErrorRetry.attempts =
			DEFAULT_STORE_ERROR_ATTEMPTS;
	if (table_info->storeErrorRetry.timeout == (time_t)NO_VALUE_SET)
		table_info->storeErrorRetry.timeout =
			DEFAULT_STORE_ERROR_TIME_OUT;
	if (table_info->refreshError ==
	    (__nis_refresh_error_t)NO_VALUE_SET)
		table_info->refreshError = continue_using;
	if (table_info->refreshErrorRetry.attempts == NO_VALUE_SET)
		table_info->refreshErrorRetry.attempts =
			DEFAULT_REFRESH_ERROR_ATTEMPTS;
	if (table_info->refreshErrorRetry.timeout == (time_t)NO_VALUE_SET)
		table_info->refreshErrorRetry.timeout =
			DEFAULT_REFRESH_ERROR_TIME_OUT;
	if (table_info->matchFetch ==
	    (__nis_match_fetch_t)NO_VALUE_SET)
		table_info->matchFetch = no_match_only;
}

__nis_table_mapping_t *
find_table_mapping(const char *s, int len, __nis_table_mapping_t *table_mapping)
{
	__nis_table_mapping_t *t;

	for (t = table_mapping; t != NULL; t = t->next)
		if (strlen(t->dbId) == len &&
		    strncasecmp(t->dbId, s, len) == 0)
			break;
	return (t);
}

void
append_dot(char **str)
{
	char	*s	= *str;
	int	len	= strlen(s);

	if (len == 0 || s[len - 1] != PERIOD_CHAR) {
		s = s_realloc(s, len + 2);
		if (s != NULL) {
			s[len] = PERIOD_CHAR;
			s[len+1] = '\0';
			*str = s;
		}
	}
}

void
append_comma(char **str)
{

	char    *s  = *str;
	int len = strlen(s);

	if (len == 0 || s[len - 1] != COMMA_CHAR) {
		s = s_realloc(s, len + 2);
		if (s != NULL) {
			s[len] = COMMA_CHAR;
			s[len+1] = '\0';
			*str = s;
		}
	}
}

/*
 * FUNCTION:	make_full_dn
 *
 *	Appends the base dn if a relative ldap dn
 *	(invoked only for LDAP write cycle)
 *
 * RETURN VALUE:	FALSE if error
 *			TRUE if __nis_index_t returned
 *
 * INPUT:		the relative dn and ldap base
 */

bool_t
make_full_dn(char **dn, const char *base)
{
	int len;
	int len1;

	if (*dn == NULL) {
		*dn = s_strdup(base);
	} else {
		len = strlen(*dn);
		if (len > 0 && (*dn)[len-1] == COMMA_CHAR) {
			len1 = strlen(base) + 1;
			*dn = s_realloc(*dn, len + len1);
			if (*dn != NULL)
				(void) strcpy(*dn + len, base);
		}
	}
	return (*dn != NULL);
}

/*
 * FUNCTION:	make_fqdn
 *
 *	Appends the base dn if a relative ldap dn
 *	(invoked only for LDAP read cycle)
 *
 * RETURN VALUE:	FALSE if error
 *			TRUE if success
 *
 * INPUT:		the relative dn and ldap base
 */
bool_t
make_fqdn(__nis_object_dn_t *dn, const char *base)
{
	int len;
	int len1;

	if (dn == NULL) {
		return (FALSE);
	} else {
		while (dn != NULL && dn->read.base != NULL) {
			len = strlen(dn->read.base);
			if (len > 0 && (dn->read.base)[len-1] == COMMA_CHAR) {
				len1 = strlen(base) + 1;
				dn->read.base =
					s_realloc(dn->read.base, len + len1);
				if (dn->read.base != NULL)
					(void) strlcpy(dn->read.base + len,
							base, len1);
				else
					return (FALSE);
			}
			dn = dn->next;
		}
	}
	return (TRUE);
}

/*
 * FUNCTION:	get_default_ldap_base
 *
 *	Gets the default LDAP search base from the
 *	nis+ default domain
 *
 * RETURN VALUE:	NULL if error
 *			the default base
 *
 * INPUT:		the nis domain
 */

char *
get_default_ldap_base(const char *domain)
{

	int		len	= strlen(domain);
	int		i;
	int		count	= len + 4;
	char		*base;

	for (i = 0; i < len - 1; i++)
		if (domain[i] == PERIOD_CHAR)
			count += 4;
	if ((base = malloc(count)) == NULL) {
		p_error = parse_no_mem_error;
	} else {
		(void) strcpy(base, "dc=");
		count = 3;
		for (i = 0; i < len - 1; i++) {
			if (domain[i] == PERIOD_CHAR) {
				(void) strcpy(base + count, ",dc=");
				count += 4;
			} else {
				base[count++] = domain[i];
			}
		}
		base[count] = '\0';
	}
	return (base);
}

/*
 * FUNCTION:	add_domain
 *
 *	Appends the base domain if a relative object name
 *
 * RETURN VALUE:	FALSE if error
 *			TRUE if OK
 *
 * INPUT:		the relative object name and base domain
 *			name
 */

bool_t
add_domain(char **objName, const char *domain)
{
	int	len;
	int	len1;
	bool_t	trailing_dot;
	char	*obj_name;

	if (domain == NULL || *objName == NULL) {
		p_error = parse_internal_error;
		return (FALSE);
	}
	len1 = strlen(domain);
	trailing_dot = (len1 > 0 && domain[len1 - 1] == PERIOD_CHAR) ?
		0 : 1;
	len = strlen(*objName);
	if (len == 0 || (*objName)[len - 1] != PERIOD_CHAR) {
		obj_name = s_realloc(*objName,
			len + len1 + 2 + trailing_dot);
		if (obj_name != NULL) {
			obj_name[len++] = PERIOD_CHAR;
			(void) strcpy(obj_name + len, domain);
			if (trailing_dot != 0) {
				obj_name[len + len1] = PERIOD_CHAR;
				obj_name[len + len1 + 1] = '\0';
			}
			*objName = obj_name;
		}
	}

	return (*objName != NULL);
}

bool_t
dup_index(__nis_index_t *in, __nis_index_t *out)
{
	int i;
	int j;

	out->name = (char **)s_calloc(in->numIndexes, sizeof (char *));
	if (out->name == NULL)
		return (FALSE);
	out->value = (__nis_mapping_format_t **)
		s_calloc(in->numIndexes, sizeof (__nis_mapping_format_t *));
	if (out->value == NULL) {
		free(out->name);
		out->name = NULL;
		return (FALSE);
	}

	for (i = 0; i < in->numIndexes; i++) {
		out->name[i] = s_strdup(in->name[i]);
		if (out->name[i] == NULL)
			break;
		out->value[i] = dup_format_mapping(in->value[i]);
		if (out->value[i] == NULL)
			break;
	}
	if (i < in->numIndexes) {
		for (j = 0; j <= i; j++) {
			if (out->name[j] != NULL)
				free(out->name[j]);
			if (out->value[j] != NULL)
				free_mapping_format(out->value[j]);
		}
		free(out->name);
		out->name = NULL;
		free(out->value);
		out->value = NULL;
	} else {
		out->numIndexes = in->numIndexes;
	}
	return (i == in->numIndexes);
}

bool_t
dup_mapping_item(__nis_mapping_item_t *in, __nis_mapping_item_t *out)
{
	bool_t	ret;

	if (in->type == mit_nisplus) {
		ret = dup_index(&in->searchSpec.obj.index,
			&out->searchSpec.obj.index);
		if (!ret)
			return (ret);
		if (in->searchSpec.obj.name != NULL) {
		    out->searchSpec.obj.name =
			s_strdup(in->searchSpec.obj.name);
			if (out->searchSpec.obj.name == NULL)
				return (FALSE);
		} else
			out->searchSpec.obj.name = NULL;
	} else if (in->type == mit_ldap) {
		if (in->searchSpec.triple.base != NULL) {
		    out->searchSpec.triple.base =
			s_strdup(in->searchSpec.triple.base);
			if (out->searchSpec.triple.base == NULL)
				return (FALSE);
		} else
			out->searchSpec.triple.base = NULL;
		out->searchSpec.triple.scope =
			in->searchSpec.triple.scope;
		if (in->searchSpec.triple.attrs != NULL) {
		    out->searchSpec.triple.attrs =
			s_strdup(in->searchSpec.triple.attrs);
			if (out->searchSpec.triple.attrs == NULL)
				return (FALSE);
		} else
			out->searchSpec.triple.attrs = NULL;
		if (in->searchSpec.triple.element != NULL) {
			out->searchSpec.triple.element =
				(__nis_mapping_element_t *)
				s_calloc(1, sizeof (__nis_mapping_element_t));
			if (out->searchSpec.triple.element != NULL)
				dup_mapping_element(
					in->searchSpec.triple.element,
					out->searchSpec.triple.element);
			if (out->searchSpec.triple.element == NULL)
				return (FALSE);
		} else
			out->searchSpec.triple.element = NULL;
	}

	if (in->name != NULL) {
		out->name = s_strdup(in->name);
		if (out->name == NULL)
			return (FALSE);
	} else
		out->name = NULL;
	out->type = in->type;
	out->repeat = in->repeat;
	if (in->exItem) {
		out->exItem = (__nis_mapping_item_t *)s_malloc
			(sizeof (__nis_mapping_item_t));
		if (out->exItem == NULL)
			return (FALSE);
		else {
			(void) memset
				(out->exItem, 0, sizeof (out->exItem[0]));
			if (!dup_mapping_item
				(in->exItem, out->exItem))
				p_error = parse_internal_error;
		}
	} else
		out->exItem = NULL;

	return (p_error == no_parse_error);
}

__nis_mapping_format_t *
dup_format_mapping(__nis_mapping_format_t *in)
{
	int			i;
	__nis_mapping_format_t	*out;
	bool_t			got_end;

	i = 0;
	while (in[i].type != mmt_end)
		i++;
	out = (__nis_mapping_format_t *)s_calloc(
		i + 1, sizeof (__nis_mapping_format_t));
	if (out != NULL) {
		got_end = FALSE;
		for (i = 0; !got_end; i++) {
		    switch (in[i].type) {
			case mmt_item:
				break;
			case mmt_string:
				out[i].match.string =
					s_strdup(in[i].match.string);
				break;
			case mmt_single:
				out[i].match.single.numRange =
					in[i].match.single.numRange;
				out[i].match.single.lo =
					s_malloc(in[i].match.single.numRange);
				if (out[i].match.single.lo == NULL)
					break;
				out[i].match.single.hi =
					s_malloc(in[i].match.single.numRange);
				if (out[i].match.single.hi == NULL)
					break;
				memcpy(out[i].match.single.lo,
					in[i].match.single.lo,
					in[i].match.single.numRange);
				memcpy(out[i].match.single.hi,
					in[i].match.single.hi,
					in[i].match.single.numRange);
				break;
			case mmt_limit:
				out[i].match.limit = in[i].match.limit;
				break;
			case mmt_any:
				break;
			case mmt_berstring:
				out[i].match.berString =
					s_strdup(in[i].match.berString);
				break;
			case mmt_begin:
				break;
			case mmt_end:
				got_end = TRUE;
				break;
			default:
				p_error = parse_internal_error;
		    }
		    if (p_error != no_parse_error)
			break;
		    out[i].type = in[i].type;
		}
		if (p_error != no_parse_error) {
			free_mapping_format(out);
			out = NULL;
		}
	}

	return (out);
}

bool_t
dup_mapping_sub_element(
	__nis_mapping_sub_element_t	*in,
	__nis_mapping_sub_element_t	*out)
{
	bool_t	ret = FALSE;
	int	i;

	switch (in->type) {
		case me_item:
			ret = dup_mapping_item(&in->element.item,
				&out->element.item);
			break;
		case me_print:
			out->element.print.fmt =
				dup_format_mapping(in->element.print.fmt);
			if (out->element.print.fmt == NULL)
				break;
			out->element.print.numItems =
				in->element.print.numItems;
			out->element.print.item = (__nis_mapping_item_t *)
				s_calloc(in->element.print.numItems,
					sizeof (__nis_mapping_item_t));
			if (out->element.print.item == NULL)
				break;
			for (i = 0; i < in->element.print.numItems; i++)
				if (!dup_mapping_item(
					&in->element.print.item[i],
					&out->element.print.item[i]))
						break;
			if (i < in->element.print.numItems)
				break;
			ret = TRUE;
			out->element.print.doElide = in->element.print.doElide;
			out->element.print.elide = in->element.print.elide;
			break;
		case me_split:
			ret = dup_mapping_item(&in->element.split.item,
				&out->element.split.item);
			out->element.split.delim = in->element.split.delim;
			break;
		case me_extract:
			out->element.extract.fmt =
				dup_format_mapping(in->element.extract.fmt);
			if (out->element.extract.fmt == NULL)
				break;
			ret = dup_mapping_item(&in->element.extract.item,
				&out->element.extract.item);
			break;
		default:
			p_error = parse_internal_error;
	}
	out->type = in->type;

	return (ret);
}

bool_t
dup_mapping_element(
	__nis_mapping_element_t *in,
	__nis_mapping_element_t *out)
{
	bool_t	ret = FALSE;
	int	i;

	if (in == NULL)
		return (ret);

	switch (in->type) {
		case me_item:
			ret = dup_mapping_item(&in->element.item,
				&out->element.item);
			break;
		case me_print:
			out->element.print.fmt =
				dup_format_mapping(in->element.print.fmt);
			if (out->element.print.fmt == NULL)
				break;
			out->element.print.numSubElements =
				in->element.print.numSubElements;
			out->element.print.subElement =
				(__nis_mapping_sub_element_t *)
				s_calloc(in->element.print.numSubElements,
					sizeof (__nis_mapping_sub_element_t));
			if (out->element.print.subElement == NULL)
				break;
			for (i = 0; i < in->element.print.numSubElements; i++)
				if (!dup_mapping_sub_element(
					&in->element.print.subElement[i],
					&out->element.print.subElement[i]))
						break;
			if (i < in->element.print.numSubElements)
				break;
			ret = TRUE;
			out->element.print.doElide = in->element.print.doElide;
			out->element.print.elide = in->element.print.elide;
			break;
		case me_split:
			ret = dup_mapping_item(&in->element.split.item,
				&out->element.split.item);
			out->element.split.delim = in->element.split.delim;
			break;
		case me_match:
			out->element.match.fmt =
				dup_format_mapping(in->element.match.fmt);
			if (out->element.match.fmt == NULL)
				break;
			out->element.match.numItems =
				in->element.match.numItems;
			out->element.match.item = (__nis_mapping_item_t *)
				s_calloc(in->element.match.numItems,
					sizeof (__nis_mapping_item_t));
			if (out->element.match.item == NULL)
				break;
			for (i = 0; i < in->element.match.numItems; i++)
				if (!dup_mapping_item(
					&in->element.match.item[i],
					&out->element.match.item[i]))
						break;
			if (i < in->element.match.numItems)
				break;
			ret = TRUE;
			break;
		case me_extract:
			out->element.extract.fmt =
				dup_format_mapping(in->element.extract.fmt);
			if (out->element.extract.fmt == NULL)
				break;
			ret = dup_mapping_item(&in->element.extract.item,
				&out->element.extract.item);
			break;
		default:
			p_error = parse_internal_error;
	}
	out->type = in->type;

	return (ret);
}

__nis_mapping_rule_t *
dup_mapping_rule(__nis_mapping_rule_t *in)
{
	int			i;
	__nis_mapping_rlhs_t	*r_in;
	__nis_mapping_rlhs_t	*r_out;
	__nis_mapping_rule_t	*out;

	out = (__nis_mapping_rule_t *)
		s_calloc(1, sizeof (__nis_mapping_rule_t));
	if (out != NULL) {
		r_in = &in->lhs;
		r_out = &out->lhs;
		r_out->numElements = r_in->numElements;
		r_out->element = (__nis_mapping_element_t *)s_calloc
			(r_in->numElements, sizeof (__nis_mapping_element_t));
		if (r_out->element == NULL) {
			free_mapping_rule(out);
			return (NULL);
		}
		for (i = 0; i < r_in->numElements; i++) {
		    if (!dup_mapping_element(&r_in->element[i],
			&r_out->element[i]))
				break;
		}
		if (i < r_in->numElements) {
			free_mapping_rule(out);
			return (NULL);
		}

		r_in = &in->rhs;
		r_out = &out->rhs;
		r_out->numElements = r_in->numElements;
		r_out->element = (__nis_mapping_element_t *)s_calloc
			(r_in->numElements, sizeof (__nis_mapping_element_t));
		if (r_out->element == NULL) {
			free_mapping_rule(out);
			return (NULL);
		}
		for (i = 0; i < r_in->numElements; i++) {
		    if (!dup_mapping_element(&r_in->element[i],
			&r_out->element[i]))
				break;
		}
		if (i < r_in->numElements) {
			free_mapping_rule(out);
			return (NULL);
		}
	}
	return (out);
}

__nis_mapping_rule_t **
dup_mapping_rules(__nis_mapping_rule_t **rules, int n_rules)
{
	int			i, j;
	__nis_mapping_rule_t	**r;

	r = (__nis_mapping_rule_t **)s_calloc(n_rules,
		sizeof (__nis_mapping_rule_t *));
	if (r != NULL) {
		for (i = 0; i < n_rules; i++) {
			r[i] = dup_mapping_rule(rules[i]);
			if (r[i] == NULL) {
				for (j = 0; j < i; j++)
					free_mapping_rule(r[j]);
				free(r);
				r = NULL;
				break;
			}
		}
	}
	return (r);
}

/*
 * FUNCTION:	add_column
 *
 *	Adds a column name to the column list in __nis_table_mapping_t
 *
 * RETURN VALUE:	FALSE if error
 *			TRUE if __nis_index_t returned
 *
 * INPUT:		the __nis_table_mapping_t and column name
 */

bool_t
add_column(__nis_table_mapping_t *t, const char *col_name)
{
	int i;
	char **cols = NULL;

	if (!yp2ldap) {
		for (i = 0; i < t->numColumns; i++) {
			if (strcasecmp(col_name, t->column[i]) == 0)
				return (TRUE);
		}
	}
	cols = (char **)s_realloc(t->column, (t->numColumns + 1) *
		sizeof (char *));
	if (cols == NULL)
		return (FALSE);
	t->column = cols;
	cols[t->numColumns] = s_strdup(col_name);
	if (cols[t->numColumns] == NULL)
		return (FALSE);
	t->numColumns++;
	return (TRUE);
}

/*
 * FUNCTION:	add_element
 *
 *	Adds a __nis_mapping_element_t to __nis_mapping_rlhs_t
 *
 * RETURN VALUE:	FALSE if error
 *			TRUE if __nis_index_t returned
 *
 * INPUT:		the __nis_mapping_element_t and
 *			__nis_mapping_rlhs_t
 */

bool_t
add_element(
	__nis_mapping_element_t	*e,
	__nis_mapping_rlhs_t	*m)
{
	__nis_mapping_element_t *e1;
	int			i;
	int			n	= m->numElements;

	e1 = (__nis_mapping_element_t *)s_realloc(m->element,
		(n + 1) * sizeof (__nis_mapping_element_t));
	if (e1 == NULL) {
		e1 = m->element;
		for (i = 0; i < n; i++)
			free_mapping_element(e1++);
		if (m->element != NULL)
			free(m->element);
		m->element = NULL;
		m->numElements = 0;
	} else {
		e1[m->numElements++] = *e;
		free(e);
		m->element = (__nis_mapping_element_t *)e1;
	}
	return (e1 != NULL);
}

/*
 * FUNCTION:	get_next_object_dn_token
 *
 *	Get the next token in parsing object_dn
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after
 *			token
 *
 * INPUT:		the attribute value
 */

const char *
get_next_object_dn_token(
	const char	**begin_ret,
	const char	**end_ret,
	object_dn_token	*token)
{
	object_dn_token	t		= dn_no_token;
	const char	*s		= *begin_ret;
	const char	*begin;
	const char	*end		= *end_ret;
	const char	*s1;
	bool_t		in_quotes;

	while (s < end && is_whitespace(*s))
		s++;
	if (s >= end) {
		/* EMPTY */
	} else if (*s == SEMI_COLON_CHAR) {
		t = dn_semi_token;
		s++;
	} else if (*s == QUESTION_MARK) {
		t = dn_ques_token;
		s++;
	} else if (*s == COLON_CHAR) {
		t = dn_colon_token;
		s++;
	} else if (*s == OPEN_PAREN_CHAR) {
		begin = s;
		s = get_ldap_filter(&begin, &end);
		if (s != NULL) {
			t = dn_text_token;
			*begin_ret = begin;
			*end_ret = end;
		}
	} else {
		begin = s;
		in_quotes = FALSE;
		while (s < end) {
			if (*s == ESCAPE_CHAR) {
			    if (s + 2 > end) {
				p_error = parse_unmatched_escape;
				s = NULL;
				break;
			    }
			    s++;
			} else if (*s == DOUBLE_QUOTE_CHAR) {
				in_quotes = ! in_quotes;
			} else if (in_quotes)
				;
			else if (*s == SEMI_COLON_CHAR ||
				*s == QUESTION_MARK ||
				*s == COLON_CHAR)
					break;
			s++;
		}
		if (s != NULL) {
			s1 = s - 1;
			while (is_whitespace(*s1))
				s1--;
			s1++;
			if (same_string("base", begin, s1 - begin))
				t = dn_base_token;
			else if (same_string("one", begin, s1 - begin))
				t = dn_one_token;
			else if (same_string("sub", begin, s1 - begin))
				t = dn_sub_token;
			else
				t = dn_text_token;
			*begin_ret = begin;
			*end_ret = s1;
		}
	}
	*token = t;
	return (s);
}

/*
 * FUNCTION:	get_next_token
 *
 *	Get the next token in parsing mapping attribute
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after
 *			token
 *
 * INPUT:		the attribute value
 */

const char *
get_next_token(const char **begin_token, const char **end_token, token_type *t)
{
	const char	*s		= *begin_token;
	const char	*end_s		= *end_token;
	const char	*s_begin;

	while (s < end_s && is_whitespace(*s))
		s++;
	if (s == end_s) {
		*t = no_token;
		return (s);
	}

	s_begin = s;

	if (*s == OPEN_PAREN_CHAR) {
		*begin_token = s;
		s++;
		*end_token = s;
		while (s < end_s && is_whitespace(*s))
			s++;
		*t = open_paren_token;
	} else if (*s == DOUBLE_QUOTE_CHAR) {
		s++;
		while (s < end_s) {
			if (*s == ESCAPE_CHAR)
				s += 2;
			else if (*s == DOUBLE_QUOTE_CHAR)
				break;
			else
				s++;
		}
		if (s >= end_s) {
			p_error = parse_unmatched_escape;
			return (NULL);
		}

		*t = quoted_string_token;
		*begin_token = s_begin + 1;
		*end_token = s++;
	} else if (*s == EQUAL_CHAR || *s == COMMA_CHAR ||
	    *s == CLOSE_PAREN_CHAR || *s == COLON_CHAR) {
		if (*s == EQUAL_CHAR)
			*t = equal_token;
		else if (*s == COMMA_CHAR)
			*t = comma_token;
		else if (*s == CLOSE_PAREN_CHAR)
			*t = close_paren_token;
		else
			*t = colon_token;
		*begin_token = s;
		*end_token = ++s;
	} else {
		s_begin = s;
		while (s < end_s && !is_whitespace(*s)) {
			if (*s == ESCAPE_CHAR)
				s += 2;
			else if (*s == EQUAL_CHAR || *s == CLOSE_PAREN_CHAR ||
			    *s == OPEN_PAREN_CHAR || *s == COMMA_CHAR ||
			    *s == COLON_CHAR || *s == OPEN_BRACKET ||
			    *s == CLOSE_BRACKET)
				break;
			else
				s++;
		}
		if (s > end_s) {
			p_error = parse_unmatched_escape;
			return (NULL);
		}
		*t = string_token;
		*end_token = s;
		*begin_token = s_begin;
	}
	if (s) {
		while (s < end_s && is_whitespace(*s))
			s++;
	}
	return (s);
}

/*
 * FUNCTION:	skip_token
 *
 *	Skip over the specified token - An error is set if
 *	next token does not match expected token
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after
 *			token
 *
 * INPUT:		the attribute value
 */

const char *
skip_token(const char *s, const char *end_s, token_type t)
{
	bool_t	match;
	char	c	= 0;

	if (s == NULL)
		return (s);
	while (s < end_s && is_whitespace(*s))
		s++;
	c = (s == end_s) ? 0 : *s;
	switch (t) {
		case equal_token:
			match = c == EQUAL_CHAR;
			if (!match)
				p_error = parse_equal_expected_error;
			break;
		case comma_token:
			match = c == COMMA_CHAR;
			if (!match)
				p_error = parse_comma_expected_error;
			break;
		case close_paren_token:
			match = c == CLOSE_PAREN_CHAR;
			if (!match)
				p_error = parse_close_paren_expected_error;
			break;
		default:
			match = FALSE;
			break;
	}
	if (match) {
		s++;
		while (s < end_s && is_whitespace(*s))
			s++;
	} else {
		s = NULL;
	}
	return (s);
}

/*
 * FUNCTION:	get_next_extract_format_item
 *
 *	Get the next format token from the string. Note that
 *	get_next_extract_format_item may change the input string.
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after
 *			token
 *
 * INPUT:		the format string
 */

const char *
get_next_extract_format_item(
	const char		*begin_fmt,
	const char		*end_fmt,
	__nis_mapping_format_t	*fmt)
{
	const char	*s		= begin_fmt;
	const char	*s_end		= end_fmt;
	bool_t		escape;
	bool_t		in_range;
	bool_t		got_char;
	bool_t		done;
	int		numRange;
	char		*lo		= NULL;
	char		*hi		= NULL;
	bool_t		skip_ber;

	for (; p_error == no_parse_error; ) {
		if (s >= s_end)
			break;

		if (*s == PERCENT_SIGN) {
			s++;
			/*
			 * If the format is %s, it is interpreted
			 * as a string.
			 */
			if (s >= s_end) {
				p_error = parse_unsupported_format;
				break;
			}
			skip_ber = FALSE;
			switch (*s) {
				case 's':
					fmt->type = mmt_item;
					break;
				case 'n':	/* null */
				case 'x':	/* skip the next element */
					skip_ber = TRUE;
					/* FALLTHRU */
				case 'b':	/* boolean */
				case 'e':	/* enumerated */
				case 'i':	/* int */
				case 'o':	/* octet string */
				case 'B':	/* bit string */
					fmt->match.berString = s_strndup(s, 1);
					fmt->type = skip_ber ?
						mmt_berstring_null :
						mmt_berstring;
					break;
				case 'a':	/* octet string */
					if (yp2ldap) {
						fmt->match.berString =
							s_strndup(s, 1);
						fmt->type = skip_ber ?
							mmt_berstring_null :
							mmt_berstring;
						break;
					}
					/* FALLTHROUGH */
				case '{':	/* begin sequence */
				case '[':	/* begin set */
				case '}':	/* end sequence */
				case ']':	/* end set */
				case 'l':	/* length of next item */
				case 'O':	/* octet string */
				case 't':	/* tag of next item */
				case 'T':	/* skip tag of next item */
				case 'v':	/* seq of strings */
				case 'V':	/* seq of strings + lengths */
				default:
					p_error = parse_bad_ber_format;
					break;
			}
			s++;
		} else if (*s == ASTERIX_CHAR) {
			fmt->type = mmt_any;
			s++;
			while (s < s_end && *s == ASTERIX_CHAR)
				s++;

		} else if (*s == OPEN_BRACKET) {
			escape = FALSE;
			in_range = FALSE;
			got_char = FALSE;
			numRange = 0;
			done = FALSE;
			s++;
			for (; s < s_end; s++) {
				if (escape) {
					escape = FALSE;
				} else if (*s == DASH_CHAR) {
					if (in_range || !got_char) {
						p_error = parse_unexpected_dash;
						break;
					}
					in_range = TRUE;
					got_char = FALSE;
					continue;
				} else if (*s == CLOSE_BRACKET) {
					if (in_range) {
						p_error = parse_unexpected_dash;
					}
					done = TRUE;
					break;
				} else if (*s == ESCAPE_CHAR) {
					escape = TRUE;
					continue;
				}
				if (in_range) {
					hi[numRange - 1] = *s;
					in_range = FALSE;
				} else {
					lo = s_realloc(lo, numRange + 1);
					hi = s_realloc(hi, numRange + 1);
					if (lo == NULL || hi == NULL)
						break;
					lo[numRange] = *s;
					hi[numRange] = *s;
					numRange++;
					got_char = TRUE;
				}
			}
			if (p_error != no_parse_error) {
				break;
			} else if (!done) {
				p_error = parse_mismatched_brackets;
				break;
			}
			s++;
			fmt->type = mmt_single;
			fmt->match.single.numRange = numRange;
			fmt->match.single.lo = (unsigned char *)lo;
			fmt->match.single.hi = (unsigned char *)hi;
		} else {
			/* go to next key symbol - copy escaped key symbols */
			escape = FALSE;
			done = FALSE;
			while (s < s_end) {
				if (escape)
					escape = FALSE;
				else {
				    switch (*s) {
					case OPEN_BRACKET:
					case ASTERIX_CHAR:
					case PERCENT_SIGN:
						done = TRUE;
						break;
					case ESCAPE_CHAR:
						escape = !escape;
						break;
					default:
						break;
				    }
				}
				if (done)
					break;
				s++;
			}
			if (escape) {
				p_error = parse_unmatched_escape;
				break;
			}
			fmt->type = mmt_string;
			fmt->match.string =
				s_strndup_esc(begin_fmt, s - begin_fmt);
			if (fmt->match.string == NULL)
				break;
		}

		if (p_error == no_parse_error)
			return (s);
	}
	if (lo != NULL)
		free(lo);
	if (hi != NULL)
		free(hi);
	return (NULL);
}

/*
 * FUNCTION:	get_next_print_format_item
 *
 *	Get the next format token from the string
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after
 *			token
 *
 * INPUT:		the format string
 */

const char *
get_next_print_format_item(
	const char		*begin_fmt,
	const char		*end_fmt,
	__nis_mapping_format_t	*fmt)
{
	const char		*s	= begin_fmt;
	const char		*s_end	= end_fmt;
	bool_t			skip_ber;

	for (; p_error == no_parse_error; ) {
		if (s >= s_end) {
			p_error = parse_internal_error;
			break;
		}

		if (*s == PERCENT_SIGN) {
			s++;
			if (s >= s_end) {
				p_error = parse_unsupported_format;
				break;
			}
			skip_ber = FALSE;
			/*
			 * If the format is %s, it is interpretted
			 * as a string.
			 */
			switch (*s) {
				case 's':
					fmt->type = mmt_item;
					break;
				case 'n':	/* null */
				case 'x':	/* skip the next element */
					skip_ber = TRUE;
					/* FALLTHRU */
				case 'b':	/* boolean */
				case 'e':	/* enumerated */
				case 'i':	/* int */
				case 'o':	/* octet string */
				case 'B':	/* bit string */
					fmt->match.berString = s_strndup(s, 1);
					fmt->type = skip_ber ?
						mmt_berstring_null :
						mmt_berstring;
					break;
				case '{':	/* begin sequence */
				case '[':	/* begin set */
				case '}':	/* end sequence */
				case ']':	/* end set */
				case 'a':	/* octet string */
				case 'l':	/* length of next item */
				case 'O':	/* octet string */
				case 't':	/* tag of next item */
				case 'T':	/* skip tag of next item */
				case 'v':	/* seq of strings */
				case 'V':	/* seq of strings + lengths */
				default:
					p_error = parse_bad_ber_format;
					break;
			}
			s++;
		} else {
			while (s < s_end) {
				if (*s == PERCENT_SIGN)
					break;
				else if (*s == ESCAPE_CHAR)
					s++;
				s++;
			}
			if (s > s_end) {
				p_error = parse_unmatched_escape;
				break;
			}
			fmt->match.string =
				s_strndup_esc(begin_fmt, s - begin_fmt);
			if (fmt->match.string == NULL)
				break;
			fmt->type = mmt_string;
		}
		if (p_error == no_parse_error)
			return (s);
	}
	return (NULL);
}

/*
 * FUNCTION:	get_ldap_filter
 *
 *	Gets an LDAP filter - see RFC 2254. Note that this does not
 *	determine if the ldap filter is valid. This only determines
 *	that the parentheses are balanced.
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after
 *			filter
 *
 * INPUT:		the begin and end of string
 *
 * OUTPUT:		the begin and end of LDAP filter
 *
 */

const char *
get_ldap_filter(const char **begin, const char **end)
{
	const char	*s		= *begin;
	const char	*s_begin;
	const char	*s_end		= *end;
	int		nParen;

	for (; p_error == no_parse_error; ) {
		while (s < s_end && is_whitespace(*s))
			s++;
		if (s == s_end) {
			s = NULL;
			break;
		}

		s_begin = s;
		if (*s == OPEN_PAREN_CHAR) {
			nParen = 1;
			s++;
			while (s < s_end && nParen > 0) {
				if (*s == ESCAPE_CHAR)
					s++;
				else if (*s == OPEN_PAREN_CHAR)
					nParen++;
				else if (*s == CLOSE_PAREN_CHAR)
					nParen--;
				s++;
			}
			if (nParen == 0) {
				*begin = s_begin;
				*end = s;
				while (s < s_end && is_whitespace(*s))
					s++;
			} else
				s = NULL;
		} else
			s = NULL;
		if (p_error == no_parse_error)
			break;
	}
	if (s == NULL)
		p_error = parse_invalid_ldap_search_filter;

	return (s);
}

/*
 * FUNCTION:	get_ava_list
 *
 *	Gets an attribute value assertion list
 *
 * RETURN VALUE:	NULL if error
 *			position of beginning next token after
 *			after attribute assertion
 *
 * INPUT:		the begin and end of string
 *			Indicator if ava list is part of a nisplus
 *			item
 *
 * OUTPUT:		the begin and end of LDAP filter
 *
 */

const char *
get_ava_list(const char **begin, const char **end, bool_t end_nisplus)
{
	const char	*s		= *begin;
	const char	*s_begin;
	const char	*s_end		= *end;
	bool_t		in_quote;
	bool_t		got_equal;
	bool_t		got_data;

	for (; p_error == no_parse_error; ) {
		while (s < s_end && is_whitespace(*s))
			s++;
		if (s == s_end) {
			s = NULL;
			break;
		}

		in_quote = FALSE;
		got_equal = FALSE;
		got_data = FALSE;
		s_begin = s;
		while (s < s_end) {
			if (*s == ESCAPE_CHAR) {
			    s++;
			    got_data = TRUE;
			} else if (*s == DOUBLE_QUOTE_CHAR) {
			    in_quote = !in_quote;
			    got_data = TRUE;
			} else if (in_quote)
				;
			else if (*s == EQUAL_CHAR) {
			    if (end_nisplus && got_data && got_equal)
				break;
			    if (!got_data || got_equal) {
				got_equal = FALSE;
				break;
			    }
			    got_equal = TRUE;
			    got_data = FALSE;
			} else if (*s == COMMA_CHAR) {
			    if (!got_data || !got_equal)
				break;
			    got_data = FALSE;
			    got_equal = FALSE;
			} else if (is_whitespace(*s))
				;
			else
				got_data = TRUE;
			s++;
		}
		if (!got_data || !got_equal || in_quote)
			s = NULL;
		else {
			*begin = s_begin;
			*end = s;
			while (s < s_end && is_whitespace(*s))
				s++;
		}
		if (p_error == no_parse_error)
			break;
	}
	if (s == NULL)
		p_error = parse_invalid_ldap_search_filter;

	return (s);
}

/* Utility functions */
bool_t
validate_dn(const char *s, int len)
{
	const char *end = s + len;
	bool_t	valid;

	valid = skip_get_dn(s, end) == end;

	if (!valid)
		p_error = parse_bad_dn;
	return (valid);
}

bool_t
validate_ldap_filter(const char *s, const char *end)
{
	const char	*s_begin;
	const char	*s_end;

	s_begin = s;
	s_end = end;

	if (*s == OPEN_PAREN_CHAR) {
		s = get_ldap_filter(&s_begin, &s_end);
	} else {
		/* Assume an attribute value list */
		s = get_ava_list(&s_begin, &s_end, FALSE);
	}
	if (s == NULL || s_end != end)
		p_error = parse_invalid_ldap_search_filter;

	return (p_error == no_parse_error);
}

char *
s_strndup(const char *s, int n)
{
	char *d = (char *)malloc(n + 1);

	if (d != NULL) {
		(void) memcpy(d, s, n);
		d[n] = '\0';
	} else {
		p_error = parse_no_mem_error;
	}

	return (d);
}

char *
s_strndup_esc(const char *s, int n)
{
	char	*d	= (char *)malloc(n + 1);
	int	i;
	int	j;

	if (d != NULL) {
		for (i = 0, j = 0; i < n; i++) {
			if (s[i] == ESCAPE_CHAR)
				i++;
			d[j++] = s[i];
		}
		d[j] = '\0';
	} else {
		p_error = parse_no_mem_error;
	}

	return (d);
}

void *
s_calloc(size_t n, size_t size)
{
	void *d = (char *)calloc(n, size);

	if (d == NULL) {
		p_error = parse_no_mem_error;
	}

	return (d);
}

void *
s_malloc(size_t size)
{
	void *d = malloc(size);
	if (d == NULL)
		p_error = parse_no_mem_error;
	return (d);
}

void *
s_realloc(void *s, size_t size)
{
	s = realloc(s, size);
	if (s == NULL)
		p_error = parse_no_mem_error;
	return (s);
}

char *
s_strdup(const char *s)
{
	return (s != NULL ? s_strndup(s, strlen(s)) : NULL);
}

bool_t
is_whitespace(int c)
{
	return (c == ' ' || c == '\t');
}

bool_t
is_string_ok(char *buffer, int buflen)
{
	int i;

	if (buffer == NULL)
		return (FALSE);

	for (i = 0; i < buflen; i++) {
		if (!is_whitespace(buffer[i])) {
			if (buffer[i] == POUND_SIGN)
				return (TRUE);
			else
				return (FALSE);
		}
	}
	return (TRUE);
}

/*
 * Returns true if the first string is contained at the beginning of the
 * second string. Otherwise returns false.
 */

bool_t
contains_string(const char *s1, const char *s2)
{
	return (strncasecmp(s1, s2, strlen(s1)) == 0);
}

/*
 * Returns the next character position in the second string, if the first
 * string is contained at the beginning of the second string. Otherwise
 * returns NULL.
 */

const char *
skip_string(const char *s1, const char *s2, int len)
{
	int len1 = strlen(s1);

	if (len >= len1 && strncasecmp(s1, s2, strlen(s1)) == 0)
		return (s2 + len1);
	else
		return (NULL);
}

/*
 * The second string is not necessarily null terminated.
 * same_string returns true if the second string matches the first.
 * Otherwise returns false.
 */

bool_t
same_string(const char *s1, const char *s2, int len)
{
	int len1 = strlen(s1);

	return (len1 == len && strncasecmp(s1, s2, len1) == 0);
}

void
report_error(const char	*str, const char *attr)
{
	char	fmt_buf[1024];
	int	pos		= 0;

	if (command_line_source != NULL) {
		snprintf(fmt_buf, sizeof (fmt_buf), "Error parsing %s: ",
			command_line_source);
		pos = strlen(fmt_buf);
	} else if (file_source != NULL) {
		snprintf(fmt_buf, sizeof (fmt_buf), "Error parsing file '%s': ",
			file_source);
		pos = strlen(fmt_buf);
	} else if (ldap_source != NULL) {
		snprintf(fmt_buf, sizeof (fmt_buf), "Error for LDAP dn '%s': ",
			ldap_source);
		pos = strlen(fmt_buf);
	}

	if (start_line_num != 0) {
		snprintf(fmt_buf + pos, sizeof (fmt_buf) - pos, "at line %d: ",
			start_line_num);
		pos += strlen(fmt_buf + pos);
	}

	if (attr != NULL) {
		snprintf(fmt_buf + pos, sizeof (fmt_buf) - pos,
			"for attribute %s: ", attr);
		pos += strlen(fmt_buf + pos);
	}

	if (cons != NULL) {
		snprintf(fmt_buf + pos, sizeof (fmt_buf) - pos, "%s\n",
			parse_error_msg[p_error]);
		fprintf(cons, fmt_buf, str == NULL ? "" : str);
	} else {
		snprintf(fmt_buf + pos, sizeof (fmt_buf) - pos, "%s",
			parse_error_msg[p_error]);
		syslog(LOG_ERR, fmt_buf, str == NULL ? "" : str);
	}
}

void
report_error2(
	const char	*str1,
	const char	*str2)
{
	char	fmt_buf[1024];

	if (cons != NULL) {
		snprintf(fmt_buf, sizeof (fmt_buf),
			"%s\n",  parse_error_msg[p_error]);
		fprintf(cons, fmt_buf, str1, str2);
	} else {
		syslog(LOG_ERR, parse_error_msg[p_error], str1, str2);
	}
}

void
report_conn_error(
	conn_error	e,
	const char	*str1,
	const char	*str2)
{
	char	fmt_buf[1024];

	if (cons != NULL) {
		snprintf(fmt_buf, sizeof (fmt_buf),
			"%s\n",  conn_error_msg[e]);
		fprintf(cons, fmt_buf,
			str1 == NULL ? "" : str1,
			str2 == NULL ? "" : str2);
	} else {
		syslog(LOG_ERR,
			conn_error_msg[e],
			str1 == NULL ? "" : str1,
			str2 == NULL ? "" : str2);
	}
}

void
report_info(
	const char	*str,
	const char	*arg)
{
	if (cons != NULL) {
		fputs(str, cons);
		if (arg != NULL)
			fputs(arg, cons);
		fputs("\n", cons);
	} else
		syslog(LOG_INFO, str, arg);
}
