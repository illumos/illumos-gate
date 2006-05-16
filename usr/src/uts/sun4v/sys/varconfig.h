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
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_VARCONFIG_H
#define	_SYS_VARCONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


typedef enum {
	VAR_CONFIG_SET_REQ,
	VAR_CONFIG_DELETE_REQ,
	VAR_CONFIG_SET_RESP,
	VAR_CONFIG_DELETE_RESP
} var_config_cmd_t;

typedef struct  {
	var_config_cmd_t cmd;
} var_config_hdr_t;


typedef struct {
	char name_and_value[1];
} var_config_set_req_t;

typedef struct {
	char name[1];
} var_config_delete_req_t;


typedef enum {
	VAR_CONFIG_SUCCESS = 0,
	VAR_CONFIG_NO_SPACE,
	VAR_CONFIG_INVALID_VAR,
	VAR_CONFIG_INVALID_VAL,
	VAR_CONFIG_VAR_NOT_PRESENT
} var_config_status_t;

typedef struct {
	var_config_status_t result;
} var_config_resp_t;


typedef struct {
	var_config_hdr_t vc_hdr;
	union {
		var_config_set_req_t vc_set;
		var_config_delete_req_t vc_delete;
		var_config_resp_t vc_resp;
	} un;
} var_config_msg_t;

#define	var_config_cmd		vc_hdr.cmd
#define	var_config_set		un.vc_set
#define	var_config_delete	un.vc_delete
#define	var_config_resp		un.vc_resp

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_VARCONFIG_H */
