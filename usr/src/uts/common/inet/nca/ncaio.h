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

#ifndef	_INET_NCAIO_H
#define	_INET_NCAIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sendfile.h>

/*
 * These request types are used with I_STR from ncafs to NCA.
 */
#define	NCA_BIND	0x00000001	/* to bind an address */
#define	NCA_LISTEN	0x00000002	/* ready to accept connections */
#define	NCA_READY	0x00000004	/* is NCA ready */

/* Data structs for nca_sendfilev to send sendfilevec to NCA */
#define	NCA_IO_SENDVEC	8

typedef struct nca_sendvec_s {
	int		sfv_fd;
	uint_t		sfv_flag;
	off_t		sfv_off;
	size_t		sfv_len;
	vnode_t		*sfv_vp;
} nca_sendvec_t;

#ifdef	__cplusplus
}
#endif

#endif /* _INET_NCAIO_H */
