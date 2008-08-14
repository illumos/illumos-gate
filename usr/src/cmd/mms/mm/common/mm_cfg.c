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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <mms_par_impl.h>
#include <mms_trace.h>
#include <host_ident.h>
#include <mms_cfg.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "net_cfg_service.h"

static char *_SrcFile = __FILE__;

int
mm_cfg_read(mm_cfg_t *mm_cfg)
{
	char		*port;
	char		host_name[MMS_HOST_IDENT_LEN + 1];
	char		host_ip[MMS_IP_IDENT_LEN + 1];
	mms_network_cfg_t	*net_cfg = &mm_cfg->mm_network_cfg;
	mm_db_cfg_t	*db_cfg = &mm_cfg->mm_db_cfg;
	char		*value;


	mms_trace(MMS_DEVP, "mm_cfg_read");
	(void) memset(mm_cfg, 0, sizeof (mm_cfg_t));
	if (mms_net_cfg_service(net_cfg, "mm", "MMP", "1.0")) {
		mms_trace(MMS_ERR, "net config read");
		goto out;
	}
	(void) mms_host_info(host_name, host_ip);
	free(net_cfg->cli_host);
	if ((net_cfg->cli_host = strdup(host_name)) == NULL) {
		mms_trace(MMS_ERR, "config hostname");
		goto out;
	}
	db_cfg->mm_db_host = mms_cfg_alloc_getvar(MMS_CFG_MM_DB_HOST, NULL);
	db_cfg->mm_db_port = -1;
	if (port = mms_cfg_alloc_getvar(MMS_CFG_MM_DB_PORT, NULL)) {
		db_cfg->mm_db_port = atoi(port);
		free(port);
	}
	db_cfg->mm_db_name = mms_cfg_alloc_getvar(MMS_CFG_MM_DB_NAME, NULL);
	db_cfg->mm_db_user = mms_cfg_alloc_getvar(MMS_CFG_MM_DB_USER, NULL);
	db_cfg->mm_db_passwd = mms_net_cfg_read_pass_file(MMS_NET_CFG_DB_FILE);
	mm_cfg->mm_ssl_dh_file = mms_cfg_alloc_getvar(MMS_CFG_SSL_DH_FILE,
	    NULL);
	if (value = mms_cfg_alloc_getvar(MMS_CFG_SSL_VERIFY, NULL)) {
		if (strcasecmp(value, "true") == 0) {
			mm_cfg->mm_ssl_verify_peer = 1;
		}
		free(value);
	}
	if (net_cfg->cli_host == NULL ||
	    net_cfg->cli_name == NULL ||
	    net_cfg->cli_inst == NULL ||
	    net_cfg->cli_pass == NULL ||
	    db_cfg->mm_db_host == NULL ||
	    db_cfg->mm_db_port < 0 ||
	    db_cfg->mm_db_name == NULL ||
	    db_cfg->mm_db_user == NULL) {
		mms_trace(MMS_ERR, "invalid config");
		goto out;
	}
	return (0);

out:
	mm_cfg_free(mm_cfg);
	return (1);
}

void
mm_cfg_free(mm_cfg_t *mm_cfg)
{
	mms_network_cfg_t	*net_cfg = &mm_cfg->mm_network_cfg;
	mm_db_cfg_t	*db_cfg = &mm_cfg->mm_db_cfg;

	mms_net_cfg_free(net_cfg);
	free(mm_cfg->mm_ssl_dh_file);
	free(db_cfg->mm_db_host);
	free(db_cfg->mm_db_name);
	free(db_cfg->mm_db_user);
	free(db_cfg->mm_db_passwd);

	(void) memset(mm_cfg, 0, sizeof (mm_cfg_t));
}
