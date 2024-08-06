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
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef	_LDAP_HEADERS_H
#define	_LDAP_HEADERS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>
#include <syslog.h>
#include <lastlog.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libintl.h>
#include <signal.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <libintl.h>
#include "ns_sldap.h"

#define	bool_t  int

/* Constants */
#define	LDAP_AUTHTOK_DATA	"SUNW-LDAP-AUTHTOK-DATA"
#define	NULLSTRING	""

typedef struct _ldap_authtok_data_ {
	int age_status;
} ldap_authtok_data;

/* LDAP specific functions */
int		__ldap_to_pamerror(int ldaperror);

/* from ldap_utils.c */
extern int 	authenticate(ns_cred_t **, const char *, const char *, int *);

#ifdef __cplusplus
}
#endif

#endif	/* _LDAP_HEADERS_H */
