/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Gary Mills
 */

#ifndef _NIS_PARSE_LDAP_UTIL_H
#define	_NIS_PARSE_LDAP_UTIL_H

/*
 * Functions defined in nis_parse_ldap_util.c needed elsewhere
 */

#ifdef __cplusplus
extern "C" {
#endif

extern void *s_malloc(size_t);
extern bool_t add_column(__nis_table_mapping_t *, const char *);
extern bool_t dup_index(__nis_index_t *, __nis_index_t *);
extern bool_t dup_mapping_element(__nis_mapping_element_t *,
    __nis_mapping_element_t *);
extern bool_t make_fqdn(__nis_object_dn_t *, const char *);
extern bool_t make_full_dn(char **, const char *);
extern void append_dot(char **);
extern void append_comma(char **);
extern __nis_mapping_rule_t **dup_mapping_rules(__nis_mapping_rule_t **,
    int n_rules);
extern __nis_mapping_rule_t *dup_mapping_rule(__nis_mapping_rule_t *);

#ifdef __cplusplus
}
#endif

#endif /* _NIS_PARSE_LDAP_UTIL_H */
