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

#ifndef _DD_MISC_H
#define	_DD_MISC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dhcp_svc_private.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <jni.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DAEMON_FNAME	"in.dhcpd"

struct ip_interface {
	char name[IFNAMSIZ];
	struct in_addr addr;
	struct in_addr mask;
};

extern jstring dd_native_to_jstring(JNIEnv *, const char *);
extern char *dd_jstring_to_native(JNIEnv *, jstring);
extern boolean_t dd_jstring_to_UTF(JNIEnv *, jstring, char **);
extern boolean_t dd_get_str_attr(JNIEnv *, jclass, int, jobject, char **);
extern boolean_t dd_get_conf_datastore_t(JNIEnv *, dsvc_datastore_t *);
extern boolean_t dd_make_datastore_t(JNIEnv *, dsvc_datastore_t *, jobject);
extern void dd_free_datastore_t(dsvc_datastore_t *);
extern char **dd_data_stores(JNIEnv *);
extern void dd_free_data_stores(char **);
extern int dd_signal(char *, int);
extern pid_t dd_getpid(char *);
extern struct ip_interface **dd_get_interfaces(void);

#ifdef	__cplusplus
}
#endif

#endif	/* !_DD_MISC_H */
