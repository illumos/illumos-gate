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

#ifndef	_SVCS_H
#define	_SVCS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libscf.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern ssize_t max_scf_fmri_length;
extern ssize_t max_scf_name_length;
extern ssize_t max_scf_value_length;
extern char *locale;
extern int exit_status;

#ifndef NDEBUG
#define	scfdie()	do_scfdie(__FILE__, __LINE__)

void do_scfdie(const char *, int);
#else
void scfdie(void);
#endif

void *safe_malloc(size_t);
char *safe_strdup(const char *);

int pg_get_single_val(scf_propertygroup_t *, const char *, scf_type_t, void *,
    size_t, uint_t);
int inst_get_single_val(scf_instance_t *, const char *, const char *,
    scf_type_t, void *, size_t, uint_t, int, int);

void explain(int, int, char **);

#ifdef	__cplusplus
}
#endif

#endif /* _SVCS_H */
