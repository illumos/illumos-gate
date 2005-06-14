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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include "ldap_parse.h"
#include "nis_parse_ldap_conf.h"

extern FILE *cons;

static bool_t get_timeval_t(const char *s, int len, struct timeval *t,
	time_t default_val);
static bool_t get_limit(const char *s, int len, int *limit, int default_val);
static bool_t get_time_t(const char *s, time_t *t, time_t default_val);
static bool_t get_uint_val(const char *attrib_val, int *val, int default_val);
static bool_t get_int_val(const char *attrib_val, int *val, int default_val);
static void warn_duplicate_val(config_key attrib_num);

static struct {
	const char	*key_name;
	config_key	key_id;
} keyword_lookup[] = {
	{CONFIG_DN,		key_config_dn},
	{YP_CONFIG_DN,	key_yp_config_dn},
	{CONFIG_SERVER_LIST,	key_config_server_list},
	{YP_CONFIG_SERVER_LIST,	key_yp_config_server_list},
	{CONFIG_AUTH_METHOD,	key_config_auth_method},
	{YP_CONFIG_AUTH_METHOD,	key_yp_config_auth_method},
	{CONFIG_TLS_OPTION,		key_config_tls_option},
	{YP_CONFIG_TLS_OPTION,	key_yp_config_tls_option},
	{CONFIG_TLS_CERT_DB,	key_config_tls_certificate_db},
	{YP_CONFIG_TLS_CERT_DB,	key_yp_config_tls_certificate_db},
	{CONFIG_PROXY_USER,		key_config_proxy_user},
	{YP_CONFIG_PROXY_USER,	key_yp_config_proxy_user},
	{CONFIG_PROXY_PASSWD,	key_config_proxy_passwd},
	{YP_CONFIG_PROXY_PASSWD,	key_yp_config_proxy_passwd},
	{PREFERRED_SERVERS,		key_preferred_servers},
	{AUTH_METHOD,		key_auth_method},
	{TLS_OPTION,		key_tls_option},
	{YP_TLS_OPTION,		key_yp_tls_option},
	{TLS_CERT_DB,		key_tls_certificate_db},
	{YP_TLS_CERT_DB,	key_yp_tls_certificate_db},
	{SEARCH_BASE,		key_search_base},
	{PROXY_USER,		key_proxy_user},
	{YP_PROXY_USER,		key_yp_proxy_user},
	{PROXY_PASSWD,		key_proxy_passwd},
	{YP_PROXY_PASSWD,	key_yp_proxy_passwd},
	{LDAP_BASE_DOMAIN,	key_ldap_base_domain},
	{YP_LDAP_BASE_DOMAIN,	key_yp_ldap_base_domain},
	{BIND_TIMEOUT,		key_bind_timeout},
	{YP_BIND_TIMEOUT,	key_yp_bind_timeout},
	{SEARCH_TIMEOUT,	key_search_timeout},
	{YP_SEARCH_TIMEOUT,	key_yp_search_timeout},
	{MODIFY_TIMEOUT,	key_modify_timeout},
	{YP_MODIFY_TIMEOUT,	key_yp_modify_timeout},
	{ADD_TIMEOUT,		key_add_timeout},
	{YP_ADD_TIMEOUT,	key_yp_add_timeout},

	{DELETE_TIMEOUT,	key_delete_timeout},
	{YP_DELETE_TIMEOUT,	key_yp_delete_timeout},
	{SEARCH_TIME_LIMIT,	key_search_time_limit},
	{YP_SEARCH_TIME_LIMIT,	key_yp_search_time_limit},
	{SEARCH_SIZE_LIMIT,	key_search_size_limit},
	{YP_SEARCH_SIZE_LIMIT,	key_yp_search_size_limit},
	{FOLLOW_REFERRAL,	key_follow_referral},
	{YP_FOLLOW_REFERRAL,	key_yp_follow_referral},
	{INITIAL_UPDATE_ACTION,	key_initial_update_action},
	{INITIAL_UPDATE_ONLY,	key_initial_update_only},
	{RETRIEVE_ERROR_ACTION,	key_retrieve_error_action},
	{YP_RETRIEVE_ERROR_ACTION,	key_yp_retrieve_error_action},
	{RETREIVE_ERROR_ATTEMPTS,
				key_retrieve_error_attempts},
	{YP_RETREIVE_ERROR_ATTEMPTS,
				key_yp_retrieve_error_attempts},
	{RETREIVE_ERROR_TIMEOUT,
				key_retreive_error_timeout},
	{YP_RETREIVE_ERROR_TIMEOUT,
				key_yp_retreive_error_timeout},
	{STORE_ERROR_ACTION,	key_store_error_action},
	{YP_STORE_ERROR_ACTION,	key_yp_store_error_action},
	{STORE_ERROR_ATTEMPTS,	key_store_error_attempts},
	{YP_STORE_ERROR_ATTEMPTS,	key_yp_store_error_attempts},
	{STORE_ERROR_TIMEOUT,	key_store_error_timeout},
	{YP_STORE_ERROR_TIMEOUT,	key_yp_store_error_timeout},

	{REFRESH_ERROR_ACTION,	key_refresh_error_action},

	{REFRESH_ERROR_ATTEMPTS,
				key_refresh_error_attempts},
	{REFRESH_ERROR_TIMEOUT,	key_refresh_error_timeout},
	{THREAD_CREATE_ERROR_ACTION,
				key_thread_create_error_action},
	{THREAD_CREATE_ERROR_ATTEMPTS,
				key_thread_create_error_attempts},
	{THREAD_CREATE_ERROR_TIMEOUT,
				key_thread_create_error_timeout},
	{DUMP_ERROR_ACTION,	key_dump_error_action},
	{DUMP_ERROR_ATTEMPTS,	key_dump_error_attempts},
	{DUMP_ERROR_TIMEOUT,	key_dump_error_timeout},
	{RESYNC,		key_resync},
	{UPDATE_BATCHING,	key_update_batching},
	{UPDATE_BATCHING_TIMEOUT,
				key_update_batching_timeout},
	{MATCH_FETCH,		key_match_fetch},
	{YP_MATCH_FETCH,	key_yp_match_fetch},
	{NUMBER_THEADS,		key_number_threads},
	{YP_EMULATION,		key_yp_emulation},
	{MAX_RPC_RECSIZE,	key_max_rpc_recsize},
	{YP_DOMAIN_CONTEXT,	key_yp_domain_context},
	{YPPASSWDD_DOMAINS,	key_yppasswdd_domains},
	{DB_ID_MAP,		key_db_id_map},
	{YP_DB_ID_MAP,	key_yp_db_id_map},
	{YP_COMMENT_CHAR,	key_yp_comment_char},
	{YP_MAP_FLAGS,		key_yp_map_flags},
	{ENTRY_TTL,		key_entry_ttl},
	{YP_ENTRY_TTL,	key_yp_entry_ttl},
	{YP_NAME_FIELDS,	key_yp_name_fields},
	{YP_SPLIT_FIELD,	key_yp_split_field},
	{YP_REPEATED_FIELD_SEPARATORS,	key_yp_repeated_field_separators},
	{LDAP_OBJECT_DN,	key_ldap_object_dn},
	{YP_LDAP_OBJECT_DN,	key_yp_ldap_object_dn},
	{LDAP_TO_NISPLUS_MAP,	key_ldap_to_nisplus_map},
	{LDAP_TO_NIS_MAP,	key_ldap_to_nis_map},
	{NISPLUS_TO_LDAP_MAP,	key_nisplus_to_ldap_map},
	{NIS_TO_LDAP_MAP,	key_nis_to_ldap_map}
};

/*
 * FUNCTION:	add_config_attribute
 *
 *	Adds the attribute value to __nis_config_info_t
 *	if the value is not yet set.
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		attribute number and value (assumed to be non-NULL)
 */

int
add_config_attribute(
	config_key		attrib_num,
	const char		*attrib_val,
	int			attrib_len,
	__nis_config_info_t	*config_info)
{
	switch (attrib_num) {
		case key_yp_config_dn:
		case key_config_dn:
			if (config_info->config_dn == NULL) {
				if (!validate_dn(attrib_val, attrib_len))
					break;
				config_info->config_dn =
					s_strndup(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_config_server_list:
		case key_config_server_list:
			if (config_info->default_servers == NULL) {
				config_info->default_servers =
					s_strndup(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_config_auth_method:
		case key_config_auth_method:
			if (config_info->auth_method ==
			    (auth_method_t)NO_VALUE_SET) {
				if (same_string("none", attrib_val,
						attrib_len))
					config_info->auth_method = none;
				else if (same_string("simple", attrib_val,
						attrib_len))
					config_info->auth_method = simple;
				else if (same_string("sasl/cram-md5",
						attrib_val, attrib_len))
					config_info->auth_method = cram_md5;
				else if (same_string("sasl/digest-md5",
						attrib_val, attrib_len))
					config_info->auth_method = digest_md5;
				else
					p_error = parse_bad_auth_method_error;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_config_tls_option:
		case key_config_tls_option:
			if (config_info->tls_method ==
			    (tls_method_t)NO_VALUE_SET) {
				if (same_string("none", attrib_val,
						attrib_len))
					config_info->tls_method = no_tls;
				else if (same_string("ssl", attrib_val,
						attrib_len))
					config_info->tls_method = ssl_tls;
				else
					p_error = parse_bad_tls_option_error;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_config_tls_certificate_db:
		case key_config_tls_certificate_db:
			if (config_info->tls_cert_db == NULL) {
				config_info->tls_cert_db =
					s_strndup(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_config_proxy_user:
		case key_config_proxy_user:
			if (config_info->proxy_dn == NULL) {
				config_info->proxy_dn =
					s_strndup(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_config_proxy_passwd:
		case key_config_proxy_passwd:
			if (config_info->proxy_passwd == NULL) {
				config_info->proxy_passwd =
					s_strndup_esc(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		default:
			p_error = parse_internal_error;
			break;
	}
	return (p_error == no_parse_error ? 0 : -1);
}

/*
 * FUNCTION:	add_bind_attribute
 *
 *	Adds the attribute value to __nis_ldap_proxy_info
 *	if the value is not yet set.
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		attribute number and value (assumed to be non-NULL)
 */

int
add_bind_attribute(
	config_key		attrib_num,
	const char		*attrib_val,
	int			attrib_len,
	__nis_ldap_proxy_info	*proxy_info)
{
	struct timeval	t;
	int		limit;

	switch (attrib_num) {
		case key_yp_preferred_servers:
		case key_preferred_servers:
			if (proxy_info->default_servers == NULL) {
				proxy_info->default_servers =
					s_strndup(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_auth_method:
		case key_auth_method:
			if (proxy_info->auth_method ==
			    (auth_method_t)NO_VALUE_SET) {
				if (same_string("none", attrib_val,
						attrib_len))
					proxy_info->auth_method = none;
				else if (same_string("simple", attrib_val,
						attrib_len))
					proxy_info->auth_method = simple;
				else if (same_string("sasl/cram-md5",
						attrib_val, attrib_len))
					proxy_info->auth_method = cram_md5;
				else if (same_string("sasl/digest-md5",
						attrib_val, attrib_len))
					proxy_info->auth_method = digest_md5;
				else
					p_error = parse_bad_auth_method_error;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_tls_option:
		case key_tls_option:
			if (proxy_info->tls_method ==
			    (tls_method_t)NO_VALUE_SET) {
				if (same_string("none", attrib_val,
						attrib_len))
					proxy_info->tls_method = no_tls;
				else if (same_string("ssl", attrib_val,
						attrib_len))
					proxy_info->tls_method = ssl_tls;
				else
					p_error = parse_bad_tls_option_error;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_tls_certificate_db:
		case key_tls_certificate_db:
			if (proxy_info->tls_cert_db == NULL) {
				proxy_info->tls_cert_db =
					s_strndup(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_search_base:
		case key_search_base:
			if (proxy_info->default_search_base == NULL) {
				if (!validate_dn(attrib_val, attrib_len))
					break;
				proxy_info->default_search_base =
					s_strndup(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_proxy_user:
		case key_proxy_user:
			if (proxy_info->proxy_dn == NULL) {
				proxy_info->proxy_dn =
					s_strndup(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_proxy_passwd:
		case key_proxy_passwd:
			if (proxy_info->proxy_passwd == NULL) {
				proxy_info->proxy_passwd =
					s_strndup_esc(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_ldap_base_domain:
		case key_ldap_base_domain:
			if (proxy_info->default_nis_domain == NULL) {
				proxy_info->default_nis_domain =
					s_strndup_esc(attrib_val, attrib_len);
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_bind_timeout:
		case key_bind_timeout:
			if (proxy_info->bind_timeout.tv_sec ==
			    (time_t)NO_VALUE_SET) {
				if (!get_timeval_t(attrib_val, attrib_len, &t,
						DEFAULT_BIND_TIMEOUT))
					break;
				proxy_info->bind_timeout = t;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_search_timeout:
			if (proxy_info->search_timeout.tv_sec ==
			    (time_t)NO_VALUE_SET) {
				if (!get_timeval_t(attrib_val, attrib_len, &t,
						DEFAULT_YP_SEARCH_TIMEOUT))
					break;
				proxy_info->search_timeout = t;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;

		case key_search_timeout:
			if (proxy_info->search_timeout.tv_sec ==
			    (time_t)NO_VALUE_SET) {
				if (!get_timeval_t(attrib_val, attrib_len, &t,
						DEFAULT_SEARCH_TIMEOUT))
					break;
				proxy_info->search_timeout = t;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_modify_timeout:
		case key_modify_timeout:
			if (proxy_info->modify_timeout.tv_sec ==
			    (time_t)NO_VALUE_SET) {
				if (!get_timeval_t(attrib_val, attrib_len, &t,
						DEFAULT_MODIFY_TIMEOUT))
					break;
				proxy_info->modify_timeout = t;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_add_timeout:
		case key_add_timeout:
			if (proxy_info->add_timeout.tv_sec ==
			    (time_t)NO_VALUE_SET) {
				if (!get_timeval_t(attrib_val, attrib_len, &t,
						DEFAULT_ADD_TIMEOUT))
					break;
				proxy_info->add_timeout = t;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_delete_timeout:
		case key_delete_timeout:
			if (proxy_info->delete_timeout.tv_sec ==
			    (time_t)NO_VALUE_SET) {
				if (!get_timeval_t(attrib_val, attrib_len, &t,
						DEFAULT_DELETE_TIMEOUT))
					break;
				proxy_info->delete_timeout = t;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_search_time_limit:
		case key_search_time_limit:
			if (proxy_info->search_time_limit ==
			    (int)NO_VALUE_SET) {
				if (!get_limit(attrib_val, attrib_len, &limit,
						DEFAULT_SEARCH_TIME_LIMIT))
					break;
				proxy_info->search_time_limit = limit;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_search_size_limit:
		case key_search_size_limit:
			if (proxy_info->search_size_limit ==
			    (int)NO_VALUE_SET) {
				if (!get_limit(attrib_val, attrib_len, &limit,
						DEFAULT_SEARCH_SIZE_LIMIT))
					break;
				proxy_info->search_size_limit = limit;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		case key_yp_follow_referral:
		case key_follow_referral:
			if (proxy_info->follow_referral ==
					(follow_referral_t)NO_VALUE_SET) {
			    if (same_string("yes", attrib_val, attrib_len))
				proxy_info->follow_referral = follow;
			    else if (same_string("no", attrib_val, attrib_len))
				proxy_info->follow_referral = no_follow;
			    else
				p_error = parse_yes_or_no_expected_error;
			} else {
				warn_duplicate_val(attrib_num);
			}
			break;
		default:
			p_error = parse_internal_error;
			break;
	}
	return (p_error == no_parse_error ? 0 : -1);
}

/*
 * FUNCTION:	add_operation_attribute
 *
 *	Adds the attribute value to __nis_config_t and
 *	__nisdb_table_mapping_t if the value is not yet set.
 *
 * RETURN VALUE:	0 on success, -1 on failure
 *
 * INPUT:		attribute number and value (assumed to be non-NULL)
 */

int
add_operation_attribute(
	config_key		attrib_num,
	const char		*attrib_val,
	int			attrib_len,
	__nis_config_t		*config_info,
	__nisdb_table_mapping_t	*table_info)
{
	char	buf[1024];
	int	i;
	int	len;
	time_t	timeout;
	bool_t	last_digit = FALSE;

	for (i = 0, len = 0; i < attrib_len; i++) {
		if (!last_digit &&
			is_whitespace(attrib_val[i]))
				continue;
		buf[len++] = attrib_val[i];
		if (len >= sizeof (buf)) {
			p_error = parse_line_too_long;
			return (-1);
		}
		last_digit = isdigit(attrib_val[i]);
	}
	buf[len] = '\0';

	switch (attrib_num) {
	    case key_initial_update_action:
		if (config_info->initialUpdate ==
			(__nis_initial_update_t)NO_VALUE_SET) {
		    if (strcasecmp("none", buf) == 0)
			    config_info->initialUpdate = ini_none;
		    else if (strcasecmp("from_ldap", buf) == 0)
			    config_info->initialUpdate =
				(__nis_initial_update_t)FROM_NO_INITIAL_UPDATE;
		    else if (strcasecmp("to_ldap", buf) == 0)
			    config_info->initialUpdate =
				(__nis_initial_update_t)TO_NO_INITIAL_UPDATE;
		    else
			p_error = parse_initial_update_action_error;
		} else if (config_info->initialUpdate ==
			(__nis_initial_update_t)INITIAL_UPDATE_NO_ACTION) {
		    if (strcasecmp("none", buf) == 0)
			    config_info->initialUpdate = ini_none;
		    else if (strcasecmp("from_ldap", buf) == 0)
			    config_info->initialUpdate = from_ldap_update_only;
		    else if (strcasecmp("to_ldap", buf) == 0)
			    config_info->initialUpdate = to_ldap_update_only;
		    else
			p_error = parse_initial_update_action_error;
		} else if (config_info->initialUpdate ==
			(__nis_initial_update_t)NO_INITIAL_UPDATE_NO_ACTION) {
		    if (strcasecmp("none", buf) == 0)
			    config_info->initialUpdate = ini_none;
		    else if (strcasecmp("from_ldap", buf) == 0)
			    config_info->initialUpdate = from_ldap;
		    else if (strcasecmp("to_ldap", buf) == 0)
			    config_info->initialUpdate = to_ldap;
		    else
			p_error = parse_initial_update_action_error;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_initial_update_only:
		if (config_info->initialUpdate ==
			(__nis_initial_update_t)NO_VALUE_SET) {
		    if (strcasecmp("yes", buf) == 0)
			    config_info->initialUpdate =
				(__nis_initial_update_t)
					INITIAL_UPDATE_NO_ACTION;
		    else if (strcasecmp("no", buf) == 0)
			    config_info->initialUpdate =
				(__nis_initial_update_t)
					NO_INITIAL_UPDATE_NO_ACTION;
		    else
			p_error = parse_initial_update_only_error;
		} else if (config_info->initialUpdate ==
			(__nis_initial_update_t)FROM_NO_INITIAL_UPDATE) {
		    if (strcasecmp("yes", buf) == 0)
			    config_info->initialUpdate = from_ldap_update_only;
		    else if (strcasecmp("no", buf) == 0)
			    config_info->initialUpdate = from_ldap;
		    else
			p_error = parse_initial_update_only_error;
		} else if (config_info->initialUpdate ==
			(__nis_initial_update_t)TO_NO_INITIAL_UPDATE) {
		    if (strcasecmp("yes", buf) == 0)
			    config_info->initialUpdate = to_ldap_update_only;
		    else if (strcasecmp("no", buf) == 0)
			    config_info->initialUpdate = to_ldap;
		    else
			p_error = parse_initial_update_only_error;
		} else if (config_info->initialUpdate != ini_none) {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_thread_create_error_action:
		if (config_info->threadCreationError ==
			(__nis_thread_creation_error_t)NO_VALUE_SET) {
		    if (strcasecmp("pass_error", buf) == 0)
			    config_info->threadCreationError = pass_error;
		    else if (strcasecmp("retry", buf) == 0)
			    config_info->threadCreationError = cre_retry;
		    else
			p_error = parse_thread_create_error_action_error;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_thread_create_error_attempts:
		if (config_info->threadCreationErrorTimeout.attempts ==
			NO_VALUE_SET) {
		    if (get_int_val(buf, &i, DEFAULT_THREAD_ERROR_ATTEMPTS))
			config_info->threadCreationErrorTimeout.attempts = i;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_thread_create_error_timeout:
		if (config_info->threadCreationErrorTimeout.timeout ==
			(time_t)NO_VALUE_SET) {
		    if (get_time_t(buf, &timeout,
				DEFAULT_THREAD_ERROR_TIME_OUT))
			config_info->threadCreationErrorTimeout.timeout =
				timeout;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_dump_error_action:
		if (config_info->dumpError ==
			(__nis_dump_error_t)NO_VALUE_SET) {
		    if (strcasecmp("rollback", buf) == 0)
			    config_info->dumpError = rollback;
		    else if (strcasecmp("retry", buf) == 0)
			    config_info->dumpError = de_retry;
		    else
			p_error = parse_dump_error_action_error;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_dump_error_attempts:
		if (config_info->dumpErrorTimeout.attempts == NO_VALUE_SET) {
		    if (get_int_val(buf, &i, DEFAULT_DUMP_ERROR_ATTEMPTS))
			config_info->dumpErrorTimeout.attempts = i;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_dump_error_timeout:
		if (config_info->dumpErrorTimeout.timeout ==
			(time_t)NO_VALUE_SET) {
		    if (get_time_t(buf, &timeout,
				DEFAULT_DUMP_ERROR_TIME_OUT))
			config_info->dumpErrorTimeout.timeout = timeout;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_resync:
		if (config_info->resyncService ==
			(__nis_resync_service_t)NO_VALUE_SET) {
		    if (strcasecmp("directory_locked", buf) == 0)
			    config_info->resyncService = directory_locked;
		    else if (strcasecmp("from_copy", buf) == 0)
			    config_info->resyncService = from_copy;
		    else if (strcasecmp("from_live", buf) == 0)
			    config_info->resyncService = from_live;
		    else
			p_error = parse_resync_error;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_update_batching:
		if (config_info->updateBatching ==
			(__nis_update_batching_t)NO_VALUE_SET) {
		    if (strcasecmp("none", buf) == 0)
			    config_info->updateBatching = upd_none;
		    else if (strcasecmp("accumulate", buf) == 0) {
			    config_info->updateBatching = accumulate;
		    } else if (strcasecmp("bounded_accumulate", buf) == 0) {
			    config_info->updateBatching = bounded_accumulate;
		    } else
			p_error = parse_update_batching_error;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_update_batching_timeout:
		if (config_info->updateBatchingTimeout.timeout ==
			(time_t)NO_VALUE_SET) {
		    if (get_time_t(buf, &timeout, DEFAULT_BATCHING_TIME_OUT))
			config_info->updateBatchingTimeout.timeout = timeout;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_number_threads:
		if (config_info->numberOfServiceThreads ==
			(int)NO_VALUE_SET) {
		    if (get_uint_val(buf, &i, DEFAULT_NUMBER_OF_THREADS))
			    config_info->numberOfServiceThreads = i;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_yp_emulation:
		if (config_info->emulate_yp ==
			(int)NO_VALUE_SET) {
		    if (strcasecmp("yes", buf) == 0)
			    config_info->emulate_yp = TRUE;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
		case key_yp_retrieve_error_action:
		if (table_info->retrieveError ==
			(__nis_retrieve_error_t)NO_VALUE_SET) {
			if (strcasecmp("use_cached", buf) == 0)
				table_info->retrieveError = use_cached;
			else if (strcasecmp("fail", buf) == 0)
				table_info->retrieveError = fail;
			else
		p_error = parse_yp_retrieve_error_action_error;
		} else {
			warn_duplicate_val(attrib_num);
		}
		break;
	    case key_retrieve_error_action:
		if (table_info->retrieveError ==
			(__nis_retrieve_error_t)NO_VALUE_SET) {
		    if (strcasecmp("use_cached", buf) == 0)
			    table_info->retrieveError = use_cached;
		    else if (strcasecmp("try_again", buf) == 0)
			    table_info->retrieveError = try_again;
		    else if (strcasecmp("unavail", buf) == 0)
			    table_info->retrieveError = ret_unavail;
		    else if (strcasecmp("no_such_name", buf) == 0)
			    table_info->retrieveError = no_such_name;
		    else if (strcasecmp("retry", buf) == 0)
			    table_info->retrieveError = ret_retry;
		    else
			p_error = parse_retrieve_error_action_error;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
		case key_yp_retrieve_error_attempts:
	    case key_retrieve_error_attempts:
		if (table_info->retrieveErrorRetry.attempts == NO_VALUE_SET) {
		    if (get_int_val(buf, &i, DEFAULT_RETRIEVE_ERROR_ATTEMPTS))
			table_info->retrieveErrorRetry.attempts = i;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
		case key_yp_retreive_error_timeout:
	    case key_retreive_error_timeout:
		if (table_info->retrieveErrorRetry.timeout ==
			(time_t)NO_VALUE_SET) {
		    if (get_time_t(buf, &timeout,
				DEFAULT_RETRIEVE_ERROR_TIME_OUT))
			table_info->retrieveErrorRetry.timeout = timeout;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
		case key_yp_store_error_action:
		if (table_info->storeError ==
			(__nis_store_error_t)NO_VALUE_SET) {
			if (strcasecmp("retry", buf) == 0)
				table_info->storeError = sto_retry;
			else if (strcasecmp("fail", buf) == 0)
				table_info->storeError = sto_fail;
			else
			p_error = parse_yp_store_error_action_error;
		} else {
			warn_duplicate_val(attrib_num);
		}
		break;
	    case key_store_error_action:
		if (table_info->storeError ==
			(__nis_store_error_t)NO_VALUE_SET) {
		    if (strcasecmp("system_error", buf) == 0)
			    table_info->storeError = system_error;
		    else if (strcasecmp("unavail", buf) == 0)
			    table_info->storeError = sto_unavail;
		    else if (strcasecmp("retry", buf) == 0)
			    table_info->storeError = sto_retry;
		    else
			p_error = parse_store_error_action_error;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
		case key_yp_store_error_attempts:
	    case key_store_error_attempts:
		if (table_info->storeErrorRetry.attempts == NO_VALUE_SET) {
		    if (get_int_val(buf, &i,
				DEFAULT_STORE_ERROR_ATTEMPTS))
			table_info->storeErrorRetry.attempts = i;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
		case key_yp_store_error_timeout:
	    case key_store_error_timeout:
		if (table_info->storeErrorRetry.timeout ==
			(time_t)NO_VALUE_SET) {
		    if (get_time_t(buf, &timeout,
				DEFAULT_STORE_ERROR_TIME_OUT))
			table_info->storeErrorRetry.timeout = timeout;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_refresh_error_action:
		if (table_info->refreshError ==
			(__nis_refresh_error_t)NO_VALUE_SET) {
		    if (strcasecmp("continue_using", buf) == 0)
			    table_info->refreshError = continue_using;
		    else if (strcasecmp("cache_expired", buf) == 0)
			    table_info->refreshError = cache_expired;
		    else if (strcasecmp("tryagain", buf) == 0)
			    table_info->refreshError = tryagain;
		    else if (strcasecmp("retry", buf) == 0)
			    table_info->refreshError = ref_retry;
		    else if (strcasecmp("continue_using,retry", buf) == 0 ||
			strcasecmp("retry,continue_using", buf) == 0)
			    table_info->refreshError = continue_using_retry;
		    else
			p_error = parse_refresh_error_action_error;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_refresh_error_attempts:
		if (table_info->refreshErrorRetry.attempts == NO_VALUE_SET) {
		    if (get_int_val(buf, &i, DEFAULT_REFRESH_ERROR_ATTEMPTS))
			table_info->refreshErrorRetry.attempts = i;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_refresh_error_timeout:
		if (table_info->refreshErrorRetry.timeout ==
			(time_t)NO_VALUE_SET) {
		    if (get_time_t(buf, &timeout,
				DEFAULT_REFRESH_ERROR_TIME_OUT))
			table_info->refreshErrorRetry.timeout = timeout;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
		case key_yp_match_fetch:
	    case key_match_fetch:
		if (table_info->matchFetch ==
			(__nis_match_fetch_t)NO_VALUE_SET) {
		    if (strcasecmp("no_match_only", buf) == 0)
			    table_info->matchFetch = no_match_only;
		    else if (strcasecmp("always", buf) == 0)
			    table_info->matchFetch = mat_always;
		    else if (strcasecmp("never", buf) == 0)
			    table_info->matchFetch = mat_never;
		    else
			p_error = parse_match_fetch_error;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    case key_max_rpc_recsize:
		if (config_info->maxRPCRecordSize ==
			(int)NO_VALUE_SET) {
		    if (get_uint_val(buf, &i, RPC_MAXDATASIZE))
			    config_info->maxRPCRecordSize = i;
		} else {
		    warn_duplicate_val(attrib_num);
		}
		break;
	    default:
		p_error = parse_internal_error;
		break;
	}

	return (p_error == no_parse_error ? 0 : -1);
}

/*
 * FUNCTION:	get_attrib_num
 *
 *	Get the attribute number for the corresponding keyword.
 *
 * RETURN VALUE:	attribute number on success,
 *			key_bad on failure
 *
 * INPUT:		the attribute name string (assumed to be non-NULL)
 */

config_key
get_attrib_num(const char *s, int n)
{
	int		k;
	int		i;
	config_key	attrib_num = key_bad;

	k = n < sizeof (_key_val) ? n : sizeof (_key_val) - 1;
	(void) memcpy(_key_val, s, k);
	_key_val[k] = '\0';

	for (i = 0; i < sizeof (keyword_lookup) /
			sizeof (keyword_lookup[0]); i++) {
		if (strncasecmp(s, keyword_lookup[i].key_name, n) == 0 &&
				strlen(keyword_lookup[i].key_name) == n) {
			attrib_num = keyword_lookup[i].key_id;
			break;
		}
	}

	if (attrib_num == key_bad) {
		p_error = parse_bad_key;
	}

	return (attrib_num);
}

/*
 * FUNCTION:	get_timeval_t
 *
 *	Extract time from string
 *
 * RETURN VALUE:	TRUE if parsed
 *			FALSE otherwise
 *
 * INPUT:		the attribute value string (assumed to be non-NULL)
 */

static bool_t
get_timeval_t(
	const char	*s,
	int		len,
	struct timeval	*t,
	time_t		default_val)
{
	time_t		tv_sec		= 0;
	time_t		tv_usec		= 0;
	time_t		digit;
	time_t		mult		= 100000;
	bool_t		got_digit	= FALSE;
	bool_t		got_period	= FALSE;
	const char	*s_end		= s + len;

	while (s < s_end && is_whitespace(*s))
		s++;

	while (s < s_end && isdigit(*s)) {
		digit = (*s++) - '0';
		got_digit = TRUE;
		if (WILL_OVERFLOW_TIME(tv_sec, digit))
			tv_sec = TIME_MAX;
		else
			tv_sec = tv_sec * 10 + digit;
	}
	while (s < s_end && is_whitespace(*s))
		s++;

	if (s < s_end && *s == PERIOD_CHAR) {
		s++;
		got_period = TRUE;
		while (s < s_end && isdigit(*s)) {
			got_digit = TRUE;
			digit = (*s++) - '0';
			tv_usec += digit * mult;
			mult /= 10;
		}
		while (s < s_end && is_whitespace(*s))
			s++;
	}
	if (s == s_end) {
		if (!got_digit) {
			if (got_period) {
				p_error = parse_bad_time_error;
				return (FALSE);
			}
			tv_sec = default_val;
		}
		t->tv_sec = tv_sec;
		t->tv_usec = tv_usec;
	} else
		p_error = parse_bad_time_error;

	return (s == s_end);
}

/*
 * FUNCTION:	get_limit
 *
 *	Extract limit from string
 *
 * RETURN VALUE:	TRUE if parsed
 *			FALSE otherwise
 *
 * INPUT:		the attribute value string (assumed to be non-NULL)
 */


static bool_t
get_limit(
	const char	*s,
	int		len,
	int		*limit,
	int		default_val)
{
	bool_t		got_digit	= FALSE;
	int		l		= 0;
	time_t		digit;
	const char	*s_end		= s + len;

	while (s < s_end && is_whitespace(*s))
		s++;

	while (s < s_end && isdigit(*s)) {
		got_digit = TRUE;
		digit = (*s++) - '0';
		if (WILL_OVERFLOW_LIMIT(l, digit))
			l = LIMIT_MAX;
		else
			l = l * 10 + digit;
	}
	while (s < s_end && is_whitespace(*s))
		s++;
	if (s == s_end) {
		if (!got_digit)
			l = default_val;
		*limit = l;
	} else
		p_error = parse_bad_uint_error;

	return (s == s_end);
}

/*
 * FUNCTION:	get_time_t
 *
 *	Parse a buffer containing a time_t string
 *
 * RETURN VALUE:	TRUE on success, FALSE on failure
 *
 * INPUT:		the attribute value string (assumed to be non-NULL)
 */

static bool_t
get_time_t(const char *s, time_t *t, time_t default_val)
{
	bool_t	got_digit	= FALSE;
	time_t	timeout		= 0;

	for (; is_whitespace(*s); s++)
		;
	while (isdigit(*s)) {
		got_digit = TRUE;
		if (WILL_OVERFLOW_TIME(timeout, *s))
			timeout = TIME_MAX;
		else
			timeout = timeout * 10 + *s - '0';
		s++;
	}
	for (; is_whitespace(*s); s++)
		;
	if (*s != '\0') {
		p_error = parse_bad_int_error;
		return (FALSE);
	}
	if (!got_digit)
		timeout = default_val;

	*t = timeout;
	return (TRUE);
}

/*
 * FUNCTION:	get_uint_val
 *
 *	Parse a buffer containing a non-negative integer
 *
 * RETURN VALUE:	TRUE on success, FALSE on failure
 *
 * INPUT:		the attribute value string (assumed to be non-NULL)
 */

static bool_t
get_uint_val(const char *s, int *val, int default_val)
{
	bool_t	got_digit	= FALSE;
	int	v		= 0;

	for (; is_whitespace(*s); s++)
		;
	while (isdigit(*s)) {
		got_digit = TRUE;
		if (WILL_OVERFLOW_INT(v, *s))
			v = INT_MAX;
		else
			v = v * 10 + *s - '0';
		s++;
	}
	for (; is_whitespace(*s); s++)
		;
	if (*s != '\0') {
		p_error = parse_bad_int_error;
		return (FALSE);
	}

	if (!got_digit)
		v = default_val;

	*val = v;
	return (TRUE);
}

/*
 * FUNCTION:	get_int_val
 *
 *	Parse a buffer containing a non-negative integer
 *
 * RETURN VALUE:	TRUE on success, FALSE on failure
 *
 * INPUT:		the attribute value string (assumed to be non-NULL)
 */

static bool_t
get_int_val(const char *s, int *val, int default_val)
{
	bool_t	got_digit	= FALSE;
	int	v		= 0;
	bool_t	is_neg		= FALSE;

	for (; is_whitespace(*s); s++)
		;
	if (*s == '-') {
		is_neg = TRUE;
		s++;
	}
	while (isdigit(*s)) {
		got_digit = TRUE;
		if (WILL_OVERFLOW_INT(v, *s))
			v = INT_MAX;
		else
			v = v * 10 + *s - '0';
		s++;
	}
	for (; is_whitespace(*s); s++)
		;
	if (*s != '\0') {
		p_error = parse_bad_int_error;
		return (FALSE);
	}

	if (!got_digit) {
		if (is_neg) {
			p_error = parse_bad_int_error;
			return (FALSE);
		}
		v = default_val;
	}
	if (is_neg)
		v = -v;
	*val = v;
	return (TRUE);
}

static void
warn_duplicate_val(
	config_key attrib_num)
{
	const char	*key_name = "Unknown";
	int		i;

	if (warn_file == NULL || is_cmd_line_option(attrib_num))
		return;

	for (i = 0; i < sizeof (keyword_lookup) /
			sizeof (keyword_lookup[0]); i++) {
		if (attrib_num == keyword_lookup[i].key_id) {
			key_name = keyword_lookup[i].key_name;
			break;
		}
	}
	if (cons != NULL) {
		fprintf(cons,
		"Warning: Duplicate value for %s in %s at line:%d\n",
			key_name, warn_file, start_line_num);
	} else {
		syslog(LOG_INFO,
			"Duplicate value for %s in %s at line:%d",
			key_name, warn_file, start_line_num);
	}
}

void
warn_duplicate_map(
	const char *db_id,
	config_key attrib_num)
{
	const char	*key_name = "Unknown";
	int		i;

	if (warn_file == NULL)
		return;

	for (i = 0; i < sizeof (keyword_lookup) /
			sizeof (keyword_lookup[0]); i++) {
		if (attrib_num == keyword_lookup[i].key_id) {
			key_name = keyword_lookup[i].key_name;
			break;
		}
	}
	if (cons != NULL) {
		fprintf(cons,
		"Warning: Duplicate value for %s:%s in %s at line:%d\n",
			key_name, db_id, warn_file, start_line_num);
	} else {
		syslog(LOG_INFO,
			"Duplicate value for %s:%s in %s at line:%d",
			key_name, db_id, warn_file, start_line_num);
	}
}
