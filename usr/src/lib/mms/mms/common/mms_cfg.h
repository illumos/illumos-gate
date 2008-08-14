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

#ifndef _MMS_CFG_H
#define	_MMS_CFG_H


#include <libscf.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MMS_CFG_MAX_NAME	scf_limit(SCF_LIMIT_MAX_NAME_LENGTH)
#define	MMS_CFG_MAX_VALUE	scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH)

#define	MMS_CFG_MMS_SVC		"application/management/mms"
#define	MMS_CFG_SVC		"svc:/" MMS_CFG_MMS_SVC
#define	MMS_CFG_MM_INST		MMS_CFG_SVC ":mm"
#define	MMS_CFG_DB_INST		MMS_CFG_SVC ":db"
#define	MMS_CFG_WCR_INST	MMS_CFG_SVC ":wcr"

#define	MMS_CFG_CONFIG_TYPE	MMS_CFG_SVC "/:properties/config/type"
#define	MMS_CFG_MGR_HOST	MMS_CFG_SVC "/:properties/manager/host"
#define	MMS_CFG_MGR_PORT	MMS_CFG_SVC "/:properties/manager/port"
#define	MMS_CFG_SSL_ENABLED	MMS_CFG_SVC "/:properties/ssl/enabled"
#define	MMS_CFG_SSL_CERT_FILE	MMS_CFG_SVC "/:properties/ssl/cert_file"
#define	MMS_CFG_SSL_PASS_FILE	MMS_CFG_SVC "/:properties/ssl/pass_file"
#define	MMS_CFG_SSL_DH_FILE	MMS_CFG_SVC "/:properties/ssl/dh_file"
#define	MMS_CFG_SSL_CRL_FILE	MMS_CFG_SVC "/:properties/ssl/crl_file"
#define	MMS_CFG_SSL_PEER_FILE	MMS_CFG_SVC "/:properties/ssl/peer_file"
#define	MMS_CFG_SSL_CIPHER	MMS_CFG_SVC "/:properties/ssl/cipher"
#define	MMS_CFG_SSL_VERIFY	MMS_CFG_SVC "/:properties/ssl/verify"
#define	MMS_CFG_DB_DATA		MMS_CFG_DB_INST "/:properties/postgresql/data"
#define	MMS_CFG_DB_LOG		MMS_CFG_DB_INST "/:properties/postgresql/log"
#define	MMS_CFG_DB_BIN		MMS_CFG_DB_INST "/:properties/postgresql/bin"
#define	MMS_CFG_MM_DB_HOST	MMS_CFG_MM_INST "/:properties/db/host"
#define	MMS_CFG_MM_DB_PORT	MMS_CFG_MM_INST "/:properties/db/port"
#define	MMS_CFG_MM_DB_USER	MMS_CFG_MM_INST "/:properties/db/user"
#define	MMS_CFG_MM_DB_NAME	MMS_CFG_MM_INST "/:properties/db/name"
#define	MMS_CFG_MM_TRACE	MMS_CFG_MM_INST "/:properties/option/trace"
#define	MMS_CFG_SSI_PATH	MMS_CFG_SVC ":wcr/:properties/option/ssi_path"
#define	MMS_CFG_LIBAPI_PATH	MMS_CFG_SVC				\
	":wcr/:properties/option/libapi_path"
#define	MMS_CFG_DB_RETRY	MMS_CFG_SVC				\
	":mm/:properties/option/db_reconnect_max_retry"
#define	MMS_CFG_DB_TIMEOUT	MMS_CFG_SVC				\
	":mm/:properties/option/db_reconnect_timeout"

char *mms_cfg_alloc_getvar(const char *fmri, int *err);
int mms_cfg_getvar(const char *fmri, char *value);
int mms_cfg_setvar(const char *fmri, const char *value);
int mms_cfg_unsetvar(const char *fmri);
scf_type_t mms_cfg_get_type(const char *fmri);
int mms_cfg_setvar_type(const char *fmri, const char *value, scf_type_t type);


#ifdef	__cplusplus
}
#endif

#endif /* _MMS_CFG_H */
