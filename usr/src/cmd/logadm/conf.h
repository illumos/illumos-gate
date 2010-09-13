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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * logadm/conf.h -- public definitions for conf module
 */

#ifndef	_LOGADM_CONF_H
#define	_LOGADM_CONF_H

#ifdef	__cplusplus
extern "C" {
#endif

int conf_open(const char *cfname, const char *tfname, struct opts *opts);
void conf_close(struct opts *opts);
void *conf_lookup(const char *lhs);
struct opts *conf_opts(const char *lhs);
void conf_replace(const char *lhs, struct opts *newopts);
void conf_set(const char *entry, char *o, const char *optarg);
struct fn_list *conf_entries(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _LOGADM_CONF_H */
