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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * config.h -- public definitions for config module
 *
 * this module supports management of system configuration information
 *
 */

#ifndef	_EFT_CONFIG_H
#define	_EFT_CONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include "tree.h"
#include "lut.h"

struct cfgdata {
	int raw_refcnt;
	/*
	 * The begin field points to the first byte of raw
	 * configuration information and end to the byte past the last
	 * byte where configuration information may be stored.
	 * nextfree points to where the next string may be added.
	 */
	char *begin;
	char *end;
	char *nextfree;
	struct config *cooked;
	struct lut *devcache;
	struct lut *devidcache;
	struct lut *cpucache;
};

void structconfig_free(struct config *cp);
struct cfgdata *config_snapshot(void);

void config_cook(struct cfgdata *cdata);
void config_free(struct cfgdata *cdata);

struct config *config_lookup(struct config *croot, char *path, int add);
struct config *config_next(struct config *cp);
struct config *config_child(struct config *cp);
struct config *config_parent(struct config *cp);

const char *config_getprop(struct config *cp, const char *name);
void config_setprop(struct config *cp, const char *name, const char *val);
void config_getcompname(struct config *cp, char **name, int *inst);

int config_is_connected(struct node *np, struct config *croot,
			struct evalue *valuep);
int config_is_type(struct node *np, struct config *croot,
		    struct evalue *valuep);
int config_is_on(struct node *np, struct config *croot, struct evalue *valuep);
int config_is_present(struct node *np, struct config *croot,
		    struct evalue *valuep);

void config_print(int flags, struct config *croot);

struct node *config_bydev_lookup(struct cfgdata *, const char *);
struct node *config_bycpuid_lookup(struct cfgdata *, uint32_t);
struct node *config_bydevid_lookup(struct cfgdata *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _EFT_CONFIG_H */
