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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NET_CFG_SERVICE_H
#define	_NET_CFG_SERVICE_H


#ifdef	__cplusplus
extern "C" {
#endif

/* password files */
#define	MMS_NET_CFG_HELLO_FILE		"/etc/mms/passwd/hello"
#define	MMS_NET_CFG_WELCOME_FILE	"/etc/mms/passwd/welcome"
#define	MMS_NET_CFG_DB_FILE		"/etc/mms/passwd/db"

char *mms_net_cfg_value(char *varname);
int mms_net_cfg_service(mms_network_cfg_t *net,
    char *inst, char *lang, char *ver);
char *mms_obfpassword(char *password, int ed);
int mms_net_cfg_write_pass_file(char *file, char *password);
char *mms_net_cfg_read_pass_file(char *file);

#ifdef	__cplusplus
}
#endif

#endif	/* _NET_CFG_SERVICE_H */
