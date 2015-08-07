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

#ifndef _NIS_PARSE_LDAP_YP_UTIL_H
#define	_NIS_PARSE_LDAP_YP_UTIL_H

/*
 * Functions defined in nis_parse_ldap_yp_util.c needed elsewhere
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int check_domain_specific_order(const char *, config_key,
    __nis_table_mapping_t *, __yp_domain_context_t *);
extern void initialize_table_mapping(__nis_table_mapping_t *);

#ifdef __cplusplus
}
#endif

#endif /* _NIS_PARSE_LDAP_YP_UTIL_H */
