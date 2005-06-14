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
 * Copyright (c) 1993 by Sun Microsystems, Inc.
 */

#ifndef _FW_H
#define	_FW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>
#include "fakewin.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Header file for the framework.
 */
#define	CTXTLEN 1024

struct Op_arg_item {
	char _TKFAR *name;
	char _TKFAR *value;
	struct Op_arg_item _TKFAR *next;
};
typedef struct Op_arg_item Op_arg_item;

struct Op_row_link {
	Op_arg_item _TKFAR *first;
	Op_arg_item _TKFAR *last;
	struct Op_row_link _TKFAR *next;
};
typedef struct Op_row_link Op_row_link;

struct Op_arg {
	Op_row_link _TKFAR *first;
	Op_row_link _TKFAR *last;
	Op_row_link _TKFAR *curr;
	Op_arg_item _TKFAR *cura;
	u_long rows;
	bool_t xdr_flag;
};
typedef struct Op_arg Op_arg;

enum Fw_err {
	FW_ERR_NONE = 0,
	FW_ERR_FW = 1,
	FW_ERR_OP = 2
};
typedef enum Fw_err Fw_err;

struct Op_err {
	Fw_err type;
	u_long code;
	bool_t xdr_flag;
	char _TKFAR *message;
};
typedef struct Op_err Op_err;

typedef char invk_context[CTXTLEN];

struct invk_result {
	Op_err _TKFAR *err;
	Op_arg _TKFAR *arg;
	bool_t eof;
};
typedef struct invk_result invk_result;

struct invk_request {
	char _TKFAR *category;
	char _TKFAR *op;
	char _TKFAR *vers;
	char _TKFAR *locale;
	u_long threshold;
	invk_context context;
	Op_arg _TKFAR *arg;
};
typedef struct invk_request invk_request;

struct more_request {
	invk_context context;
	u_long threshold;
};
typedef struct more_request more_request;

struct kill_request {
	invk_context context;
};
typedef struct kill_request kill_request;

#define	FW_KV_DELIM		"="
#define	FW_KV_DELIM_CH		'='
#define	FW_VK_DELIM		"\n"
#define	FW_VK_DELIM_CH		'\n';
#define	FW_INPUT_VERS_VAL	1
#define	FW_INPUT_VERS_STR	"1"
#define	FW_OUTPUT_VERS_VAL	1
#define	FW_OUTPUT_VERS_STR	"1"
#define	FW_INPUT_VERS_KEY	"_SUNW_AO_INPUT_VERS"
#define	FW_OUTPUT_VERS_KEY	"_SUNW_AO_OUTPUT_VERS"
#define	FW_ROW_MARKER_KEY	"_SUNW_AO_BEGIN_ROW"
#define	FW_ROW_MARKER	FW_ROW_MARKER_KEY FW_KV_DELIM FW_OUTPUT_VERS_STR \
    FW_VK_DELIM
#define	FW_INPUT_VERS	FW_INPUT_VERS_KEY FW_KV_DELIM FW_INPUT_VERS_STR \
    FW_VK_DELIM
#define	FW_OUTPUT_VERS	FW_OUTPUT_VERS_KEY FW_KV_DELIM FW_OUTPUT_VERS_STR \
    FW_VK_DELIM
#define	FW_ERR_MSG_MAX		2047
#define	FW_UNIX_USER		"UU"

#define	FW_SUCCESS		0
#define	FW_ERROR		-1
#define	FW_TIMEOUT		-2

#define	SN_LOCALE_PATH_VAR	"_SN_LOCALE_PATH"
#define	SN_UNAME_VAR	"_SN_UNAME"
#define	SN_UID_VAR	"_SN_UID"

#include "fw_lib.h"

#ifdef __cplusplus
}
#endif

#endif /* !_FW_H */
