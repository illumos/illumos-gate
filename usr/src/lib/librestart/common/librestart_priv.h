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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBRESTART_PRIV_H
#define	_LIBRESTART_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libscf.h>
#include <librestart.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	RESTARTER_NAME_TYPE		SCF_PROPERTY_TYPE
#define	RESTARTER_NAME_INSTANCE		"inst"
#define	RESTARTER_NAME_STATE		SCF_PROPERTY_STATE
#define	RESTARTER_NAME_NEXT_STATE	SCF_PROPERTY_NEXT_STATE
#define	RESTARTER_NAME_AUX_STATE	SCF_PROPERTY_AUX_STATE
#define	RESTARTER_NAME_ERROR		"error"

#define	RESTARTER_CHANNEL_MASTER	0
#define	RESTARTER_CHANNEL_DELEGATE	1

typedef struct instance_data {
	const char			*i_fmri;
	int				i_enabled;

	restarter_instance_state_t	i_state;
	restarter_instance_state_t	i_next_state;
	char				*i_aux_state;

	ctid_t				i_primary_ctid;
	ctid_t				i_transient_ctid;

	int				i_primary_ctid_stopped;
	int				i_fault_count;
	int				i_dirty;
} instance_data_t;

char *_restarter_get_channel_name(const char *, int);
int _restarter_commit_states(scf_handle_t *, instance_data_t *,
    restarter_instance_state_t, restarter_instance_state_t, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBRESTART_PRIV_H */
