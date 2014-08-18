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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 */

#ifndef	_LIBSCF_IMPL_H
#define	_LIBSCF_IMPL_H

#include <libscf.h>
#include <libscf_priv.h>

#ifdef	__cplusplus
extern "C" {
#endif

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
	SCF_MSG_PATTERN_LEGACY,
	SCF_MSG_PATTERN_MULTIPARTIAL
} scf_msg_t;

scf_type_t scf_true_base_type(scf_type_t);
const char *scf_get_msg(scf_msg_t);
int ismember(const scf_error_t, const scf_error_t[]);
int32_t state_from_string(const char *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSCF_IMPL_H */
