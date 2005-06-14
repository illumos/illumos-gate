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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NIS_PARSE_LDAP_ERR_H
#define	_NIS_PARSE_LDAP_ERR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

static char *parse_error_msg[] =
{
	"No Error",

	/* parse_no_mem_error */
	"Insufficient memory",

	/* parse_bad_key */
	"Unknown attribute name: '%s'",

	/* parse_bad_continuation_error */
	"Unable to continue",

	/* parse_line_too_long */
	"Too long to parse",

	/* parse_internal_error */
	"An internal error occurred: '%s'",

	/* parse_initial_update_action_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n\tnone\n\tfrom_ldap\n"
		"\tto_ldap",

	/* parse_initial_update_only_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n\tyes\n\tno",

	/* parse_retrieve_error_action_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n\tuse_cached\n"
		"\tretry\n\ttry_again\n\tunavail\n\tno_such_name",

	/* parse_store_error_action_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n"
		"\tretry\n\tsystem_error\n\tunavail",

	/* parse_refresh_error_action_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n\tcontinue_using\n"
		"\tretry\n\tcontinue_using,retry\n\tcache_expired\n\ttryagain",

	/* parse_thread_create_error_action_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n"
		"\tretry\n\tpass_error",

	/* parse_dump_error_action_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n\tretry\n\trollback",

	/* parse_resync_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n"
		"\tdirectory_locked\n\tfrom_copy\n"
		"\tfrom_live",

	/* parse_update_batching_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n"
		"\taccumulate\n"
		"\tbounded_accumulate\n"
		"\tnone",

	/* parse_match_fetch_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n"
		"\tno_match_only\n\talways\n\tnever",

	/* parse_no_object_dn */
	"No object dn specified with database id '%s'",

	/* parse_invalid_scope */
	"Invalid scope '%s'.\n"
		"The permitted values are:\n"
		"\tbase\n\tone\n\tsub",

	/* parse_invalid_ldap_search_filter */
	"Invalid LDAP search filter or attribute value list: '%s'",

	/* parse_semi_expected_error */
	"A semicolon was expected: '%s'",

	/* parse_mismatched_brackets */
	"Brackets mismatched: '%s'",

	/* parse_unsupported_format */
	"Unsupported format: '%s'",

	/* parse_unexpected_dash */
	"Unexpected dash: '%s'",

	/* parse_unmatched_escape */
	"Unexpected escape character: '%s'",

	/* parse_bad_lhs_format_error */
	"Could not parse attribute mapping: '%s'",

	/* parse_comma_expected_error */
	"Comma was expected: '%s'",

	/* parse_equal_expected_error */
	"Equal sign expected: '%s'",

	/* parse_close_paren_expected_error */
	"Close parentheses expected: '%s'",

	/* parse_too_many_extract_items */
	"Bad extract format: '%s'",

	/* parse_not_enough_extract_items */
	"Not enough extract parameters: '%s'",

	/* parse_bad_print_format */
	"Incorrect print format: '%s'",

	/* parse_bad_elide_char */
	"Bad elide char: '%s'",

	/* parse_start_rhs_unrecognized */
	"Could not parse attribute mapping: '%s'",

	/* parse_item_expected_error */
	"Other syntax encountered when item expected: '%s'",

	/* parse_format_string_expected_error */
	"Other syntax encountered"
		" when formatspec expected: '%s'",

	/* parse_unexpected_data_end_rule */
	"Bad syntax for attribute mapping rule: '%s'",

	/* parse_bad_ttl_format_error */
	"Incorrect syntax: '%s'\n"
		"The expected syntax is:\n"
		"\tdatabaseId \":\" initialTTLlo \":\" initialTTLhi"
		" \":\" runningTTL",

	/* parse_bad_auth_method_error */
	"Incorrect syntax: '%s'\n"
		"The supported authentication methods are:\n"
		"\tnone\n"
		"\tsimple\n"
		"\tsasl/cram-md5\n"
		"\tsasl/digest-md5",

	/* parse_open_file_error */
	"Could not open: '%s'",

	/* parse_no_proxy_dn_error */
	"nisplusLDAPconfigProxyUser was not specified",

	/* parse_no_config_auth_error */
	"nisplusLDAPconfigAuthenticationMethod was not specified",

	/* parse_no_proxy_auth_error */
	"authenticationMethod was not specified",

	/* parse_ldap_init_error */
	"ldap_init failed: '%s'",

	/* parse_ldap_bind_error */
	"ldap_bind failed for '%s': %s",

	/* parse_ldap_search_error */
	"ldap_search failed: '%s'",

	/* parse_ldap_get_values_error */
	"ldap_get_values failed: '%s'",

	/* parse_object_dn_syntax_error */
	"Bad object dn syntax: '%s'",

	/* parse_invalid_dn */
	"Invalid LDAP distinguished name: '%s'",

	/* parse_bad_index_format */
	"Invalid index: '%s'",

	/* parse_bad_item_format */
	"Invalid item: '%s'",

	/* parse_bad_ldap_item_format */
	"Invalid LDAP item: '%s'",

	/* parse_invalid_print_arg */
	"Invalid argument: '%s'",

	/* parse_bad_extract_format_spec */
	"Invalid extract format encountered: '%s'",

	/* parse_no_db_del_mapping_rule */
	"The mapping '%s' rule was not found found for database id '%s'",

	/* parse_invalid_db_del_mapping_rule */
	"Invalid delete mapping rule for database id '%s'",

	/* parse_bad_domain_name */
	"Bad domain name: '%s'",

	/* parse_bad_dn */
	"Bad distinguished name: '%s'",

	/* parse_yes_or_no_expected_error */
	"yes or no expected: '%s'",

	/* parse_bad_uint_error */
	"Invalid unsigned integer: '%s'",

	/* parse_bad_int_error */
	"Invalid integer: '%s'",

	/* parse_bad_command_line_attribute_format */
	"Invalid attribute specification: '%s'",

	/* parse_no_ldap_server_error */
	"preferredServerList was not specified",

	/* parse_bad_ber_format */
	"Invalid ber format specifed: '%s'",

	/* parse_no_config_server_addr */
	"nisplusLDAPconfigDefaultServerList was not specified",

	/* parse_bad_time_error */
	"Invalid time: '%s'",

	/* parse_lhs_rhs_type_mismatch */
	"There is a mismatch in the mapping rule: '%s'",

	/* parse_only_one_match_item */
	"No match item was specified: '%s'",

	/* parse_cannot_elide */
	"Cannot elide: '%s'",

	/* parse_bad_tls_option_error */
	"Incorrect syntax: '%s'\n"
		"The supported tls options are:\n"
		"\tnone\n"
		"\tssl",

	/* parse_ldapssl_client_init_error */
	"Failed to initialize SSL client: '%s'",

	/* parse_ldapssl_init_error */
	"ldapssl_init failed: '%s'",

	/* parse_no_available_referrals_error */
	"No suitable referrals found to read rpc.nisd configuration",

	/* parse_no_config_cert_db */
	"nisplusLDAPconfigTLSCertificateDBPath must be specified",

	/* parse_no_cert_db */
	"nisplusLDAPTLSCertificateDBPath must be specified",

	/* parse_unknown_yp_domain_error */
	"Unknown nisLDAPdomainContext found",

	/* parse_unexpected_yp_domain_error */
	"Incorrect syntax for nisLDAPdomainContext",

	/* parse_bad_map_error */
	"Incorrect syntax or unknown error in parsing",

	/* parse_bad_yp_comment_error */
	"Incorrect syntax for nisLDAPcommentChar",

	/* parse_bad_field_separator_error */
	"Incorrect syntax for nisLDAPrepeatedFieldSeparators",

	/* parse_bad_name_field */
"Incorrect syntax or parse error for nisLDAPnameFields or nisLDAPsplitField",

	/* parse_yp_retrieve_error_action_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n\tuse_cached\n"
		"\tfail",

	/* parse_yp_store_error_action_error */
	"Incorrect syntax: '%s'\n"
		"The permitted values are:\n\tretry\n"
		"\tfail"
};

static char *conn_error_msg[] =
{
	"No Error",

	/* conn_no_mem_error */
	"get_ldap_connection: Insufficient memory",

	/* conn_ldap_init_error */
	"make_ldap_session: ldap_init failed: %s",

	/* conn_unsupported_ldap_bind_method */
	"make_ldap_session: Unsupported LDAP bind method specified",

	/* conn_ldap_bind_error */
	"make_ldap_session: ldap_bind failed for'%s': %s"
};

#ifdef __cplusplus
}
#endif

#endif	/* _NIS_PARSE_LDAP_ERR_H */
