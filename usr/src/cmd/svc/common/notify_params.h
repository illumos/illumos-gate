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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_CMD_COMMON_NOTIFY_PARAMS_H
#define	_CMD_COMMON_NOTIFY_PARAMS_H

#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PARAM_ACTIVE	((const char *) "active")
#define	PARAM_INACTIVE	((const char *) "inactive")
#define	PARAM_SMTP_TO	((const char *) "to")

const char *get_fma_tag(uint32_t);
const char *get_fma_class(uint32_t);
int is_fma_token(const char *);
int has_fma_tag(const char *);
const char *de_tag(const char *);
const char *re_tag(const char *);
int32_t string_to_tset(const char *);
const char *tset_to_string(int32_t);
void listnotify_print(nvlist_t *, const char *);
void safe_printf(const char *, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _CMD_COMMON_NOTIFY_PARAMS_H */
