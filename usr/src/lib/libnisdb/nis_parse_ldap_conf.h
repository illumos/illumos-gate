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

#ifndef	_NIS_PARSE_LDAP_CONF_H
#define	_NIS_PARSE_LDAP_CONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <lber.h>
#include <ldap.h>
#include <iso/limits_iso.h>
#include "ldap_parse.h"
#include "nisdb_ldap.h"

#define	DEFAULT_MAPPING_FILE	"/var/nis/NIS+LDAPmapping"
#define	YP_DEFAULT_MAPPING_FILE	"/var/yp/NISLDAPmapping"
#define	mmt_berstring_null	((__nis_mapping_match_type_t)-1)
#define	ESCAPE_CHAR		'\\'
#define	EQUAL_CHAR		'='
#define	COMMA_CHAR		','
#define	COMMA_STRING	","
#define	OPEN_PAREN_CHAR		'('
#define	CLOSE_PAREN_CHAR	')'
#define	DOUBLE_QUOTE_CHAR	'"'
#define	PERIOD_CHAR		'.'
#define	COLON_CHAR		':'
#define	POUND_SIGN		'#'
#define	SEMI_COLON_CHAR		';'
#define	QUESTION_MARK		'?'
#define	PLUS_SIGN		'+'
#define	PERCENT_SIGN		'%'
#define	OPEN_BRACKET		'['
#define	CLOSE_BRACKET		']'
#define	ASTERIX_CHAR		'*'
#define	DASH_CHAR				'-'
#define	SINGLE_QUOTE_CHAR		'\''
#define	DEFAULT_COMMENT_CHAR	'#'
#define	DEFAULT_SEP_STRING		" 	"
#define	SPACE_CHAR				' '

#define	FOREVER				-1
#define	FIFTEEN_SECONDS			15
#define	TWO_MINUTES			120
#define	THIRTY_MINUTES			1800
#define	THREE_MINUTES			180
#define	ONE_HOUR			3600
#define	MAX_LDAP_CONFIG_RETRY_TIME	60

#define	NO_VALUE_SET			-2

#define	INITIAL_UPDATE_NO_ACTION	-3
#define	NO_INITIAL_UPDATE_NO_ACTION	-4
#define	FROM_NO_INITIAL_UPDATE		-5
#define	TO_NO_INITIAL_UPDATE		-6

#define	BUFSIZE				8192

#ifndef UINT32_MAX
#define	UINT32_MAX		(4294967295U)
#endif

#define	IS_TERMINAL_CHAR(c)			\
		((c) == QUESTION_MARK	||	\
		(c) == EQUAL_CHAR 	||	\
		(c) == COMMA_CHAR	||	\
		(c) == CLOSE_PAREN_CHAR ||	\
		(c) == COLON_CHAR	||	\
		(c) == SEMI_COLON_CHAR)

#define	TIME_MAX LONG_MAX
#define	WILL_OVERFLOW_TIME(t, d) ((t) > TIME_MAX/10 ||	\
	((t) == TIME_MAX/10 && d > TIME_MAX % 10))

#define	LIMIT_MAX	(65535)
#define	WILL_OVERFLOW_LIMIT(t, d) ((t) > LIMIT_MAX/10 ||	\
	((t) == LIMIT_MAX/10 && d > LIMIT_MAX % 10))

#define	WILL_OVERFLOW_INT(t, d) ((t) > INT_MAX/10 ||	\
	((t) == INT_MAX/10 && d > INT_MAX % 10))

/* initial configuration keywords */
/* for NIS+ */
#define	CONFIG_DN		"nisplusLDAPconfigDN"
#define	CONFIG_SERVER_LIST	"nisplusLDAPconfigPreferredServerList"
#define	CONFIG_AUTH_METHOD	"nisplusLDAPconfigAuthenticationMethod"
#define	CONFIG_TLS_OPTION	"nisplusLDAPconfigTLS"
#define	CONFIG_TLS_CERT_DB	"nisplusLDAPconfigTLSCertificateDBPath"
#define	CONFIG_PROXY_USER	"nisplusLDAPconfigProxyUser"
#define	CONFIG_PROXY_PASSWD	"nisplusLDAPconfigProxyPassword"

#define	IS_CONFIG_KEYWORD(x)	\
	((x) >= key_config_dn && (x) <= key_config_proxy_passwd)

/* LDAP server keywords */
/* for NIS+ */
#define	PREFERRED_SERVERS	"preferredServerList"
#define	AUTH_METHOD		"authenticationMethod"
#define	TLS_OPTION		"nisplusLDAPTLS"
#define	TLS_CERT_DB		"nisplusLDAPTLSCertificateDBPath"
#define	SEARCH_BASE		"defaultSearchBase"
#define	PROXY_USER		"nisplusLDAPproxyUser"
#define	PROXY_PASSWD		"nisplusLDAPproxyPassword"
#define	LDAP_BASE_DOMAIN	"nisplusLDAPbaseDomain"
#define	BIND_TIMEOUT		"nisplusLDAPbindTimeout"
#define	SEARCH_TIMEOUT		"nisplusLDAPsearchTimeout"
#define	MODIFY_TIMEOUT		"nisplusLDAPmodifyTimeout"
#define	ADD_TIMEOUT		"nisplusLDAPaddTimeout"
#define	DELETE_TIMEOUT		"nisplusLDAPdeleteTimeout"
#define	SEARCH_TIME_LIMIT	"nisplusLDAPsearchTimeLimit"
#define	SEARCH_SIZE_LIMIT	"nisplusLDAPsearchSizeLimit"
#define	FOLLOW_REFERRAL		"nisplusLDAPfollowReferral"

#define	IS_BIND_INFO(x)	\
	((x) >= key_preferred_servers && (x) <= key_follow_referral)

/* This information will be need to determine the server behavior */

/* for NIS+ */
#define	INITIAL_UPDATE_ACTION	"nisplusLDAPinitialUpdateAction"
#define	INITIAL_UPDATE_ONLY	"nisplusLDAPinitialUpdateOnly"
#define	RETRIEVE_ERROR_ACTION	"nisplusLDAPretrieveErrorAction"
#define	RETREIVE_ERROR_ATTEMPTS	"nisplusLDAPretrieveErrorAttempts"
#define	RETREIVE_ERROR_TIMEOUT	"nisplusLDAPretrieveErrorTimeout"
#define	STORE_ERROR_ACTION	"nisplusLDAPstoreErrorAction"
#define	STORE_ERROR_ATTEMPTS	"nisplusLDAPstoreErrorAttempts"
#define	STORE_ERROR_TIMEOUT	"nisplusLDAPstoreErrorTimeout"
#define	REFRESH_ERROR_ACTION	"nisplusLDAPrefreshErrorAction"
#define	REFRESH_ERROR_ATTEMPTS	"nisplusLDAPrefreshErrorAttempts"
#define	REFRESH_ERROR_TIMEOUT	"nisplusLDAPrefreshErrorTimeout"
#define	THREAD_CREATE_ERROR_ACTION	\
				"nisplusThreadCreationErrorAction"
#define	THREAD_CREATE_ERROR_ATTEMPTS	\
				"nisplusThreadCreationErrorAttempts"
#define	THREAD_CREATE_ERROR_TIMEOUT	\
				"nisplusThreadCreationErrorTimeout"
#define	DUMP_ERROR_ACTION	"nisplusDumpErrorAction"
#define	DUMP_ERROR_ATTEMPTS	"nisplusDumpErrorAttempts"
#define	DUMP_ERROR_TIMEOUT	"nisplusDumpErrorTimeout"
#define	RESYNC			"nisplusResyncService"
#define	UPDATE_BATCHING		"nisplusUpdateBatching"
#define	UPDATE_BATCHING_TIMEOUT	"nisplusUpdateBatchingTimeout"
#define	MATCH_FETCH		"nisplusLDAPmatchFetchAction"
#define	NUMBER_THEADS		"nisplusNumberOfServiceThreads"
#define	YP_EMULATION		"ENABLE_NIS_YP_EMULATION"
#define	MAX_RPC_RECSIZE		"nisplusMaxRPCRecordSize"

#define	IS_OPER_INFO(x)		\
	((x) >= key_initial_update_action && (x) <= key_max_rpc_recsize)

#define	DB_ID_MAP		"nisplusLDAPdatabaseIdMapping"
#define	ENTRY_TTL		"nisplusLDAPentryTtl"
#define	LDAP_OBJECT_DN	"nisplusLDAPobjectDN"
#define	LDAP_TO_NISPLUS_MAP	"nisplusLDAPcolumnFromAttribute"
#define	NISPLUS_TO_LDAP_MAP	"nisplusLDAPattributeFromColumn"

/* The following definitions are for NIS */

#define	YP_CONFIG_DN			"nisLDAPconfigDN"
#define	YP_CONFIG_SERVER_LIST	"nisLDAPconfigPreferredServerList"
#define	YP_CONFIG_AUTH_METHOD	"nisLDAPconfigAuthenticationMethod"
#define	YP_CONFIG_TLS_OPTION	"nisLDAPconfigTLS"
#define	YP_CONFIG_TLS_CERT_DB	"nisLDAPconfigTLSCertificateDBPath"
#define	YP_CONFIG_PROXY_USER	"nisLDAPconfigProxyUser"
#define	YP_CONFIG_PROXY_PASSWD	"nisLDAPconfigProxyPassword"

#define	IS_YP_CONFIG_KEYWORD(x) \
	((x) >= key_yp_config_dn && (x) <= key_yp_config_proxy_passwd)

#define	YP_TLS_OPTION		"nisLDAPTLS"
#define	YP_TLS_CERT_DB		"nisLDAPTLSCertificateDBPath"
#define	YP_PROXY_USER		"nisLDAPproxyUser"
#define	YP_PROXY_PASSWD		"nisLDAPproxyPassword"
#define	YP_LDAP_BASE_DOMAIN		"nisLDAPbaseDomain"
#define	YP_BIND_TIMEOUT		"nisLDAPbindTimeout"
#define	YP_SEARCH_TIMEOUT	"nisLDAPsearchTimeout"
#define	YP_MODIFY_TIMEOUT	"nisLDAPmodifyTimeout"
#define	YP_ADD_TIMEOUT		"nisLDAPaddTimeout"
#define	YP_DELETE_TIMEOUT	"nisLDAPdeleteTimeout"
#define	YP_SEARCH_TIME_LIMIT	"nisLDAPsearchTimeLimit"
#define	YP_SEARCH_SIZE_LIMIT	"nisLDAPsearchSizeLimit"
#define	YP_FOLLOW_REFERRAL		"nisLDAPfollowReferral"

#define	IS_YP_BIND_INFO(x)  \
	((x) == key_preferred_servers || \
	(x) == key_auth_method || \
	(x) == key_search_base || \
	((x) >= key_yp_tls_option && (x) <= key_yp_follow_referral))

#define	YP_RETRIEVE_ERROR_ACTION	"nisLDAPretrieveErrorAction"
#define	YP_RETREIVE_ERROR_ATTEMPTS	"nisLDAPretrieveErrorAttempts"
#define	YP_RETREIVE_ERROR_TIMEOUT	"nisLDAPretrieveErrorTimeout"
#define	YP_STORE_ERROR_ACTION		"nisLDAPstoreErrorAction"
#define	YP_STORE_ERROR_ATTEMPTS		"nisLDAPstoreErrorAttempts"
#define	YP_STORE_ERROR_TIMEOUT		"nisLDAPstoreErrorTimeout"
#define	YP_MATCH_FETCH			"nisLDAPmatchFetchAction"

#define	IS_YP_OPER_INFO(x)  \
	((x) >= key_yp_retrieve_error_action && (x) <= key_yp_match_fetch)

#define	YP_DOMAIN_CONTEXT	"nisLDAPdomainContext"
#define	YPPASSWDD_DOMAINS	"nisLDAPyppasswddDomains"

#define	IS_YP_DOMAIN_INFO(x)	\
	((x) >= key_yp_domain_context && (x) <= key_yppasswdd_domains)

#define	YP_DB_ID_MAP		"nisLDAPdatabaseIdMapping"
#define	YP_COMMENT_CHAR		"nisLDAPcommentChar"
#define	YP_MAP_FLAGS		"nisLDAPmapFlags"
#define	YP_ENTRY_TTL		"nisLDAPentryTtl"
#define	YP_NAME_FIELDS		"nisLDAPnameFields"
#define	YP_SPLIT_FIELD		"nisLDAPsplitField"
#define	YP_REPEATED_FIELD_SEPARATORS	"nisLDAPrepeatedFieldSeparators"
#define	YP_LDAP_OBJECT_DN	"nisLDAPobjectDN"
#define	LDAP_TO_NIS_MAP		"nisLDAPfieldFromAttribute"
#define	NIS_TO_LDAP_MAP		"nisLDAPattributeFromField"

#define	IS_YP_MAP_ATTR(x)	\
	((x) == key_yp_domain_context || \
	(x) == key_yppasswdd_domains || \
	((x) >= key_yp_db_id_map && (x) <= key_nis_to_ldap_map))

#define	DEFAULT_YP_SEARCH_TIMEOUT	THREE_MINUTES
#define	DEFAULT_BIND_TIMEOUT		FIFTEEN_SECONDS
#define	DEFAULT_SEARCH_TIMEOUT		FIFTEEN_SECONDS
#define	DEFAULT_MODIFY_TIMEOUT		FIFTEEN_SECONDS
#define	DEFAULT_ADD_TIMEOUT		FIFTEEN_SECONDS
#define	DEFAULT_DELETE_TIMEOUT		FIFTEEN_SECONDS

#define	DEFAULT_SEARCH_TIME_LIMIT	LDAP_NO_LIMIT
#define	DEFAULT_SEARCH_SIZE_LIMIT	LDAP_NO_LIMIT

#define	DEFAULT_THREAD_ERROR_ATTEMPTS	FOREVER
#define	DEFAULT_THREAD_ERROR_TIME_OUT	FIFTEEN_SECONDS
#define	DEFAULT_DUMP_ERROR_ATTEMPTS	FOREVER
#define	DEFAULT_DUMP_ERROR_TIME_OUT	FIFTEEN_SECONDS
#define	DEFAULT_RETRIEVE_ERROR_ATTEMPTS	FOREVER
#define	DEFAULT_RETRIEVE_ERROR_TIME_OUT	FIFTEEN_SECONDS
#define	DEFAULT_STORE_ERROR_ATTEMPTS	FOREVER
#define	DEFAULT_STORE_ERROR_TIME_OUT	FIFTEEN_SECONDS
#define	DEFAULT_REFRESH_ERROR_ATTEMPTS	FOREVER
#define	DEFAULT_REFRESH_ERROR_TIME_OUT	FIFTEEN_SECONDS

#define	DEFAULT_BATCHING_TIME_OUT	TWO_MINUTES
#define	DEFAULT_NUMBER_OF_THREADS	0
#define	DEFAULT_YP_EMULATION		0

#define	DEFAULT_TTL_HIGH		(ONE_HOUR + THIRTY_MINUTES)
#define	DEFAULT_TTL_LOW			(ONE_HOUR - THIRTY_MINUTES)
#define	DEFAULT_TTL			ONE_HOUR

typedef enum {
	no_parse_error,
	parse_no_mem_error,
	parse_bad_key,
	parse_bad_continuation_error,
	parse_line_too_long,
	parse_internal_error,
	parse_initial_update_action_error,
	parse_initial_update_only_error,
	parse_retrieve_error_action_error,
	parse_store_error_action_error,
	parse_refresh_error_action_error,
	parse_thread_create_error_action_error,
	parse_dump_error_action_error,
	parse_resync_error,
	parse_update_batching_error,
	parse_match_fetch_error,
	parse_no_object_dn,
	parse_invalid_scope,
	parse_invalid_ldap_search_filter,
	parse_semi_expected_error,
	parse_mismatched_brackets,
	parse_unsupported_format,
	parse_unexpected_dash,
	parse_unmatched_escape,
	parse_bad_lhs_format_error,
	parse_comma_expected_error,
	parse_equal_expected_error,
	parse_close_paren_expected_error,
	parse_too_many_extract_items,
	parse_not_enough_extract_items,
	parse_bad_print_format,
	parse_bad_elide_char,
	parse_start_rhs_unrecognized,
	parse_item_expected_error,
	parse_format_string_expected_error,
	parse_unexpected_data_end_rule,
	parse_bad_ttl_format_error,
	parse_bad_auth_method_error,
	parse_open_file_error,
	parse_no_proxy_dn_error,
	parse_no_config_auth_error,
	parse_no_proxy_auth_error,
	parse_ldap_init_error,
	parse_ldap_bind_error,
	parse_ldap_search_error,
	parse_ldap_get_values_error,
	parse_object_dn_syntax_error,
	parse_invalid_dn,
	parse_bad_index_format,
	parse_bad_item_format,
	parse_bad_ldap_item_format,
	parse_invalid_print_arg,
	parse_bad_extract_format_spec,
	parse_no_db_del_mapping_rule,
	parse_invalid_db_del_mapping_rule,
	parse_bad_domain_name,
	parse_bad_dn,
	parse_yes_or_no_expected_error,
	parse_bad_uint_error,
	parse_bad_int_error,
	parse_bad_command_line_attribute_format,
	parse_no_ldap_server_error,
	parse_bad_ber_format,
	parse_no_config_server_addr,
	parse_bad_time_error,
	parse_lhs_rhs_type_mismatch,
	parse_no_match_item,
	parse_cannot_elide,
	parse_bad_tls_option_error,
	parse_ldapssl_client_init_error,
	parse_ldapssl_init_error,
	parse_no_available_referrals_error,
	parse_no_config_cert_db,
	parse_no_cert_db,
	parse_unknown_yp_domain_error,
	parse_unexpected_yp_domain_end_error,
	parse_bad_map_error,
	parse_bad_yp_comment_error,
	parse_bad_field_separator_error,
	parse_bad_name_field,
	parse_yp_retrieve_error_action_error,
	parse_yp_store_error_action_error
} parse_error;

typedef enum {
	no_conn_error,
	conn_no_mem_error,
	conn_ldap_init_error,
	conn_unsupported_ldap_bind_method,
	conn_ldap_bind_error
} conn_error;

typedef enum {
	key_bad = -1,
	no_more_keys = 0,
	key_config_dn = 1,
	key_config_server_list,
	key_config_auth_method,
	key_config_tls_option,
	key_config_tls_certificate_db,
	key_config_proxy_user,
	key_config_proxy_passwd,
	key_preferred_servers,
	key_auth_method,
	key_tls_option,
	key_tls_certificate_db,
	key_search_base,
	key_proxy_user,
	key_proxy_passwd,
	key_ldap_base_domain,
	key_bind_timeout,
	key_search_timeout,
	key_modify_timeout,
	key_add_timeout,
	key_delete_timeout,
	key_search_time_limit,
	key_search_size_limit,
	key_follow_referral,
	key_initial_update_action,
	key_initial_update_only,
	key_retrieve_error_action,
	key_retrieve_error_attempts,
	key_retreive_error_timeout,
	key_store_error_action,
	key_store_error_attempts,
	key_store_error_timeout,
	key_refresh_error_action,
	key_refresh_error_attempts,
	key_refresh_error_timeout,
	key_thread_create_error_action,
	key_thread_create_error_attempts,
	key_thread_create_error_timeout,
	key_dump_error_action,
	key_dump_error_attempts,
	key_dump_error_timeout,
	key_resync,
	key_update_batching,
	key_update_batching_timeout,
	key_match_fetch,
	key_number_threads,
	key_yp_emulation,
	key_max_rpc_recsize,
	key_db_id_map,
	key_entry_ttl,
	key_ldap_object_dn,
	key_ldap_to_nisplus_map,
	key_nisplus_to_ldap_map,
	key_yp_config_dn,
	key_yp_config_server_list,
	key_yp_config_auth_method,
	key_yp_config_tls_option,
	key_yp_config_tls_certificate_db,
	key_yp_config_proxy_user,
	key_yp_config_proxy_passwd,
	key_yp_preferred_servers,
	key_yp_auth_method,
	key_yp_tls_option,
	key_yp_tls_certificate_db,
	key_yp_search_base,
	key_yp_proxy_user,
	key_yp_proxy_passwd,
	key_yp_ldap_base_domain,
	key_yp_bind_timeout,
	key_yp_search_timeout,
	key_yp_modify_timeout,
	key_yp_add_timeout,
	key_yp_delete_timeout,
	key_yp_search_time_limit,
	key_yp_search_size_limit,
	key_yp_follow_referral,
	key_yp_retrieve_error_action,
	key_yp_retrieve_error_attempts,
	key_yp_retreive_error_timeout,
	key_yp_store_error_action,
	key_yp_store_error_attempts,
	key_yp_store_error_timeout,
	key_yp_match_fetch,
	key_yp_domain_context,
	key_yppasswdd_domains,
	key_yp_db_id_map,
	key_yp_comment_char,
	key_yp_map_flags,
	key_yp_entry_ttl,
	key_yp_name_fields,
	key_yp_split_field,
	key_yp_repeated_field_separators,
	key_yp_ldap_object_dn,
	key_ldap_to_nis_map,
	key_nis_to_ldap_map,
	n_config_keys
} config_key;

typedef enum {
	string_token,
	quoted_string_token,
	equal_token,
	comma_token,
	open_paren_token,
	close_paren_token,
	colon_token,
	no_token
} token_type;

typedef enum {
	dn_no_token,
	dn_semi_token,
	dn_ques_token,
	dn_colon_token,
	dn_base_token,
	dn_one_token,
	dn_sub_token,
	dn_text_token
} object_dn_token;

typedef enum {
	dn_begin_parse,
	dn_got_read_dn,
	dn_got_read_q_scope,
	dn_got_read_scope,
	dn_got_read_q_filter,
	dn_got_read_filter,
	dn_got_write_colon,
	dn_got_write_dn,
	dn_got_write_q_scope,
	dn_got_write_scope,
	dn_got_write_q_filter,
	dn_got_write_filter,
	dn_got_delete_colon,
	dn_got_delete_dsp
} parse_object_dn_state;

typedef enum {
	none = 1,
	simple,
	cram_md5,
	digest_md5
} auth_method_t;

typedef enum {
	no_tls = 1,
	ssl_tls
} tls_method_t;

typedef struct {
	char		*config_dn;
	char		*default_servers;
	auth_method_t	auth_method;
	tls_method_t	tls_method;
	char		*proxy_dn;
	char		*proxy_passwd;
	char		*tls_cert_db;
} __nis_config_info_t;

typedef enum {
	follow = 1,
	no_follow
} follow_referral_t;

typedef struct {
	char			*default_servers;
	auth_method_t		auth_method;
	tls_method_t		tls_method;
	char			*default_search_base;
	char			*proxy_dn;
	char			*proxy_passwd;
	char			*tls_cert_db;
	char			*default_nis_domain;
	struct timeval		bind_timeout;
	struct timeval		search_timeout;
	struct timeval		modify_timeout;
	struct timeval		add_timeout;
	struct timeval		delete_timeout;
	int			search_time_limit;
	int			search_size_limit;
	follow_referral_t	follow_referral;
} __nis_ldap_proxy_info;

extern __nisdb_table_mapping_t	ldapDBTableMapping;
extern __nis_ldap_proxy_info	proxyInfo;
extern __nis_table_mapping_t	*ldapTableMapping;

extern int parse_ldap_migration(const char *const *cmdline_options,
	const char *config_file);

extern void get_ldap_connection(LDAP **ld, time_t retry_time);
extern void free_ldap_connection(LDAP *ld);
extern void return_ldap_connection(LDAP *ld);
extern void free_ldap_connections();


extern void initialize_parse_structs(__nis_ldap_proxy_info *proxy_info,
    __nis_config_t *config_info, __nisdb_table_mapping_t *table_info);
extern void initialize_yp_parse_structs(__yp_domain_context_t *ypDomains);

/* Deallocation functions */
extern void free_parse_structs(void);
extern void free_yp_domain_context(__yp_domain_context_t *domains);
extern void free_config_info(__nis_config_info_t *config_info);
extern void free_mapping_rule(__nis_mapping_rule_t *rule);
extern void free_object_dn(__nis_object_dn_t *obj_dn);
extern void free_mapping_format(__nis_mapping_format_t *fmt);
extern void free_index(__nis_index_t *index);
extern void free_mapping_item(__nis_mapping_item_t *item);
extern void free_mapping_element(__nis_mapping_element_t *e);
extern void free_mapping_sub_element(__nis_mapping_sub_element_t *sub);
extern void free_proxy_info(__nis_ldap_proxy_info *proxy_info);
extern void free_table_mapping(__nis_table_mapping_t *mapping);

/* Parser functions */
extern int read_line(int fd, char *buffer, int buflen);
extern __nis_table_mapping_t *find_table_mapping(const char *s, int len,
    __nis_table_mapping_t *table_mapping);
extern int second_parser_pass(__nis_table_mapping_t **table_mapping);
extern int final_parser_pass(__nis_table_mapping_t **table_mapping,
	__yp_domain_context_t   *ypDomains);
extern int finish_parse(__nis_ldap_proxy_info *proxy_info,
    __nis_table_mapping_t **table_mapping);
extern void set_default_values(__nis_ldap_proxy_info *proxy_info,
    __nis_config_t *config_info, __nisdb_table_mapping_t *table_info);

extern int add_config_attribute(config_key attrib_num, const char *attrib_val,
    int attrib_len, __nis_config_info_t *config_info);
extern int add_bind_attribute(config_key attrib_num, const char *attrib_val,
    int attrib_len, __nis_ldap_proxy_info *proxy_info);
extern int add_operation_attribute(config_key attrib_num,
    const char *attrib_val, int attrib_len, __nis_config_t *config_info,
    __nisdb_table_mapping_t *table_info);
extern int add_mapping_attribute(config_key attrib_num, const char *attrib_val,
    int attrib_len, __nis_table_mapping_t **table_mapping);
extern int add_ypdomains_attribute(config_key attrib_num,
	const char *attrib_val, int attrib_len,
	__yp_domain_context_t *ypDomains);
extern config_key get_attrib_num(const char *s, int n);
bool_t is_cmd_line_option(config_key a_num);

extern const char *
skip_get_dn(const char *dn, const char *end);
extern const char *get_search_triple(const char *s, const char *end_s,
    __nis_search_triple_t *triple);
extern bool_t parse_index(const char *s, const char *end_s,
    __nis_index_t *index);
extern bool_t add_element(__nis_mapping_element_t *e,
    __nis_mapping_rlhs_t *m);
extern const char *skip_token(const char *s, const char *end_s,
    token_type t);
extern const char *get_next_extract_format_item(const char *begin_fmt,
    const char *end_fmt, __nis_mapping_format_t *fmt);
extern const char *get_next_print_format_item(const char *begin_fmt,
    const char *end_fmt, __nis_mapping_format_t *fmt);
extern const char *get_next_token(const char **begin_token,
    const char **end_token, token_type *t);
extern const char *get_next_object_dn_token(const char **begin_ret,
    const char **end_ret, object_dn_token *token);
extern const char *get_ldap_filter(const char **begin, const char **end);
const char *get_ava_list(const char **begin, const char **end,
	bool_t end_nisplus);

extern  void  init_yptol_flag();
/* Utility functions */
extern char *s_strndup_esc(const char *s, int n);
extern char *s_strndup(const char *s, int n);
extern char *s_strdup(const char *s);
extern void *s_calloc(size_t n, size_t size);
extern void *s_realloc(void *s, size_t size);
extern bool_t is_whitespace(int c);
extern bool_t contains_string(const char *s1, const char *s2);
extern const char *skip_string(const char *s1, const char *s2, int len);
extern bool_t same_string(const char *s1, const char *s2, int len);

/* Error and information reporting functions */
extern void report_error(const char *str, const char *attr);
extern void report_error2(const char *str1, const char *str2);
extern void report_info(const char *str, const char *arg);
extern void report_conn_error(conn_error e, const char *str1, const char *str2);
extern void warn_duplicate_map(const char *db_id, config_key attrib_num);

/* Validation functions */
extern bool_t validate_dn(const char *s, int len);
extern bool_t validate_ldap_filter(const char *s, const char *end);

extern int			start_line_num;
extern int			cur_line_num;
extern int			seq_num;
extern parse_error		p_error;
extern char			_key_val[38];
extern const char		*command_line_source;
extern const char		*file_source;
extern const char		*ldap_source;
extern const char		*warn_file;

/* SSL and sasl-digest md5 functions */
int ldapssl_client_init(const char *certdbpath, void *certdbhandle);
const char *ldapssl_err2string(const int prerrno);
LDAP *ldapssl_init(const char *defhost, int defport, int defsecure);
int ldap_x_sasl_digest_md5_bind_s(LDAP *ld, char *user_name,
	struct berval *cred,
	LDAPControl **serverctrls, LDAPControl **clientctrls);

#ifdef __cplusplus
}
#endif

#endif	/* _NIS_PARSE_LDAP_CONF_H */
