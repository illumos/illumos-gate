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

#ifndef	_RPC_RPCSYS_H
#define	_RPC_RPCSYS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

enum rpcsys_op  { KRPC_REVAUTH };

/*
 * Private definitions for the krpc_sys/rpcsys system call.
 *
 * flavor_data for AUTH_DES and AUTH_KERB is NULL.
 * flavor_data for RPCSEC_GSS is rpc_gss_OID.
 *
 */
struct krpc_revauth_1 {
	uid_t	uid;
	int	rpcsec_flavor;
	void	*flavor_data;
};

#ifdef _SYSCALL32
struct krpc_revauth_132 {
	uid32_t	uid;
	int32_t	rpcsec_flavor;
	caddr32_t flavor_data;
};
#endif /* _SYSCALL32 */

struct krpc_revauth {
	int	version;	/* initially 1 */
	union	{
		struct krpc_revauth_1 r;
	} krpc_revauth_u;
};
#define	uid_1		krpc_revauth_u.r.uid
#define	rpcsec_flavor_1	krpc_revauth_u.r.rpcsec_flavor
#define	flavor_data_1	krpc_revauth_u.r.flavor_data

#ifdef _SYSCALL32
struct krpc_revauth32 {
	int32_t	version;	/* initially 1 */
	union	{
		struct krpc_revauth_132 r;
	} krpc_revauth_u;
};
#endif /* _SYSCALL32 */


#ifdef _KERNEL

extern	int	rpcsys(enum rpcsys_op opcode, void *arg);
extern	int	sec_clnt_revoke(int, uid_t, cred_t *, void *, model_t);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _RPC_RPCSYS_H */
