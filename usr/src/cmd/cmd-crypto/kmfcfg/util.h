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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef	_UTIL_H
#define	_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <kmfapiP.h>


typedef struct _policy_list {
	KMF_POLICY_RECORD plc;
	struct _policy_list *next;
} POLICY_LIST;

void free_policy_list(POLICY_LIST *);
int getopt_av(int, char * const *, const char *);

int load_policies(char *, POLICY_LIST **);
int get_boolean(char *);
char *get_string(char *, int *err_flag);
int parseEKUOIDs(char *, KMF_POLICY_RECORD *);
int parseEKUNames(char *, KMF_POLICY_RECORD *);
uint16_t parseKUlist(char *);
void print_sanity_error(KMF_RETURN);

conf_entry_t *get_keystore_entry(char *);

#define	KC_OK			0
#define	KC_ERR_USAGE		1
#define	KC_ERR_LOADDB		2
#define	KC_ERR_FIND_POLICY	3
#define	KC_ERR_DELETE_POLICY	4
#define	KC_ERR_ADD_POLICY	5
#define	KC_ERR_VERIFY_POLICY	6
#define	KC_ERR_INCOMPLETE_POLICY 7
#define	KC_ERR_MEMORY		8
#define	KC_ERR_ACCESS		9
#define	KC_ERR_INSTALL		10
#define	KC_ERR_UNINSTALL	11
#define	KC_ERR_MODIFY_PLUGIN	12

#define	CONF_TEMPFILE	"/etc/crypto/kmfXXXXXX"

#ifdef __cplusplus
}
#endif
#endif /* _UTIL_H */
