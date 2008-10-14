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
 */


#ifndef	_LIBNSCTL_H
#define	_LIBNSCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/nsc_ioctl.h>


/*
 * Standard Definitions.
 */

#ifdef sun
#define	_NSC_DEV_PATH		"/dev/nsctl"
#else
#define	_NSC_DEV_PATH		"/dev/sd"
#endif
#define	_NSC_CKDCHK_PATH	"/usr/install/simckd/bin/ckdchk"
#define	_NSC_CKDCHK_LOG		"/rsvd/dumps/ckdchk.log"


typedef struct nsc_fd_s {
	int	sf_fd;			   /* SD device */
	int	sf_flag;		   /* Open flags */
	int	sf_fmode;		   /* File modes */
	char	sf_path[NSC_MAXPATH];   /* Pathname */
} nsc_fd_t;

#ifdef __cplusplus
}
#endif

#endif	/* _LIBNSCTL_H */
