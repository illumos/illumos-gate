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

#ifndef _PKGCOND_H
#define	_PKGCOND_H


#ifdef __cplusplus
extern "C" {
#endif

/*
 * global definitions
 */

/* environment variable */
#define	ENV_VAR_DEBUG		"PKGCOND_DEBUG"
#define	ENV_VAR_PKGROOT		"PKG_INSTALL_ROOT"
#define	ENV_VAR_PATCHROOT	"ROOTDIR"
#define	ENV_VAR_SET		"SET_FROM_ENVIRONMENT"
#define	ENV_VAR_VERBOSE		"PKGCOND_VERBOSE"
#define	ENV_VAR_PKGZONENAME	"SUNW_PKG_INSTALL_ZONENAME"
#define	ENV_VAR_INITIAL_INSTALL	"PKG_INIT_INSTALL"
#define	ENV_VAR_PATCH_CLIENTVER	"PATCH_CLIENT_VERSION"

/* file system types */
#define	FSTYPE_INHERITED	"inherited"

/* return codes used with pkgcond itself */
#define	R_SUCCESS	0x0	/* condition match / success */
#define	R_FAILURE	0x1	/* condition no match / failure */
#define	R_USAGE		0x2	/* command usage issue */
#define	R_ERROR		0x3	/* could not determine condition / error */

/* main.c */
int	main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* _PKGCOND_H */
