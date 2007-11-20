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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBSCF_IMPL_H
#define	_LIBSCF_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef NATIVE_BUILD
#include "c_synonyms.h"
#endif

#include <libscf.h>
#include <libscf_priv.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SCF_FMRI_SVC_PREFIX		"svc:"
#define	SCF_FMRI_FILE_PREFIX		"file:"
#define	SCF_FMRI_SCOPE_PREFIX		"//"
#define	SCF_FMRI_LOCAL_SCOPE		"localhost"
#define	SCF_FMRI_SCOPE_SUFFIX		"@localhost"
#define	SCF_FMRI_SERVICE_PREFIX		"/"
#define	SCF_FMRI_INSTANCE_PREFIX	":"
#define	SCF_FMRI_PROPERTYGRP_PREFIX	"/:properties/"
#define	SCF_FMRI_PROPERTY_PREFIX	"/"
/*
 * This macro must be extended if additional FMRI prefixes are defined
 */
#define	SCF_FMRI_PREFIX_MAX_LEN		(sizeof (SCF_FMRI_SVC_PREFIX) > \
					    sizeof (SCF_FMRI_FILE_PREFIX) ? \
					    sizeof (SCF_FMRI_SVC_PREFIX) - 1 : \
					    sizeof (SCF_FMRI_FILE_PREFIX) - 1)

int scf_setup_error(void);
int scf_set_error(scf_error_t);			/* returns -1 */

typedef enum {
	SCF_MSG_ARGTOOLONG,
	SCF_MSG_PATTERN_NOINSTANCE,
	SCF_MSG_PATTERN_NOINSTSVC,
	SCF_MSG_PATTERN_NOSERVICE,
	SCF_MSG_PATTERN_NOENTITY,
	SCF_MSG_PATTERN_MULTIMATCH,
	SCF_MSG_PATTERN_POSSIBLE,
	SCF_MSG_PATTERN_LEGACY
} scf_msg_t;

const char *scf_get_msg(scf_msg_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSCF_IMPL_H */
