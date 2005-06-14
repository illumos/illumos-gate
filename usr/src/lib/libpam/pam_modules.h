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
 * Copyright (c) 1992-1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_PAM_MODULES_H
#define	_PAM_MODULES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

extern int
pam_sm_authenticate(
	pam_handle_t	*pamh,
	int	flags,
	int	argc,
	const char	**argv);

extern int
pam_sm_setcred(
	pam_handle_t	*pamh,
	int	flags,
	int	argc,
	const char	**argv);

extern int
pam_sm_acct_mgmt(
	pam_handle_t	*pamh,
	int	flags,
	int	argc,
	const char	**argv);

extern int
pam_sm_open_session(
	pam_handle_t	*pamh,
	int	flags,
	int	argc,
	const char	**argv);

extern int
pam_sm_close_session(
	pam_handle_t	*pamh,
	int	flags,
	int	argc,
	const char	**argv);

/*
 * Be careful - there are flags defined for pam_chauthtok() in
 * pam_appl.h also.
 */
#define	PAM_PRELIM_CHECK	0x1
#define	PAM_UPDATE_AUTHTOK	0x2

extern int
pam_sm_chauthtok(
	pam_handle_t	*pamh,
	int		flags,
	int		argc,
	const char	**argv);

/*
 * pam_set_data is used to create module specific data, and
 * to optionally add a cleanup handler that gets called by pam_end.
 *
 */
extern int
pam_set_data(
	pam_handle_t *pamh,		/* PAM handle */
	const char *module_data_name,	/* unique module data name */
	void *data,			/* the module specific data */
	void (*cleanup)(pam_handle_t *pamh, void *data, int pam_end_status)
);

/*
 * get module specific data set by pam_set_scheme_data.
 * returns PAM_NO_MODULE_DATA if specified module data was not found.
 */
extern int
pam_get_data(
	const pam_handle_t *pamh,
	const char *module_data_name,
	const void **data
);

#ifdef __cplusplus
}
#endif

#endif	/* _PAM_MODULES_H */
