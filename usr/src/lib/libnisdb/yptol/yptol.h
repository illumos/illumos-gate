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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__NTOL_H
#define	__NTOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DESCRIPTION: NIS to LDAP  header information
 */

/*
 * N2L File names
 */
#define	NTOL_MAP_FILE "/var/yp/NISLDAPmapping"
#define	NTOL_CONFIG_FILE "/etc/default/ypserv"

/*
 * Names of passwd files prefixes.
 */
#define	PASSWD_PREFIX	"passwd."
#define	PASSWD_ADJUNCT_PREFIX	"passwd.adjunct."

/*
 * Name of netgroup maps.
 */
#define	NETGROUP_MAP	"netgroup"
#define	NETGROUP_BYHOST	NETGROUP_MAP ".byhost"
#define	NETGROUP_BYUSER	NETGROUP_MAP ".byuser"

/*
 * Types of TTL update
 */
typedef enum {
	TTL_MIN, TTL_MAX, TTL_RAND, TTL_RUNNING
}TTL_TYPE;

/*
 * dit_access interface externs
 */
extern bool_t is_yptol_mode();
extern int read_from_dit(char *, char *, datum *, datum *);
extern suc_code write_to_dit(char *, char *, datum, datum, bool_t, bool_t);
extern int get_ttl_value(map_ctrl *, TTL_TYPE);
extern int get_mapping_domain_list(char ***);
extern int get_mapping_yppasswdd_domain_list(char ***);
extern void free_map_list(char **);
extern char **get_passwd_list(bool_t, char *);
extern void free_passwd_list(char **);
extern suc_code update_map_from_dit(map_ctrl *, bool_t);
extern char **get_mapping_map_list(char *);
extern suc_code make_nis_container(char *, char *, bool_t);
extern suc_code make_nis_domain(char *, bool_t);
extern suc_code update_netgroup_byxxx(map_ctrl *);

/*
 * Other externs
 */
extern suc_code update_entry_ttl(map_ctrl *, datum *, TTL_TYPE);
extern void dump_datum(datum *);
extern suc_code update_timestamp(DBM *);
extern suc_code addpair(DBM *, char *, char *);
extern bool_t has_map_expired(map_ctrl *);
extern suc_code update_map_if_required(map_ctrl *, bool_t);
extern suc_code update_entry_if_required(map_ctrl *, datum *);
extern void set_key_data(map_ctrl *, datum *);
extern bool_t is_map_updating(map_ctrl *);
extern bool_t has_entry_expired(map_ctrl *, datum *);
extern void add_separator(char *str);
extern suc_code update_map_ttl(map_ctrl *);
extern bool_t is_special_key(datum *);
extern suc_code open_yptol_files(map_ctrl *);
extern void set_key_data(map_ctrl *map, datum *data);

/* Error codes for mapping unit */
#define	MAP_NO_MEMORY				-2
#define	MAP_PARAM_ERROR				-3
#define	MAP_INTERNAL_ERROR			-4
#define	MAP_NAMEFIELD_MATCH_ERROR		-5
#define	MAP_NO_MAPPING_EXISTS			-6
#define	MAP_CREATE_LDAP_REQUEST_ERROR		-7
#define	MAP_NO_MATCHING_KEY			-8
#define	MAP_INDEXLIST_ERROR			-9
#define	MAP_WRITE_DISABLED			-10
#define	MAP_NO_DN				-11

/* Initial frequency of up/down load message printing */
#define	PRINT_FREQ				100

#ifdef	__cplusplus
}
#endif

#endif	/* __NTOL_H */
