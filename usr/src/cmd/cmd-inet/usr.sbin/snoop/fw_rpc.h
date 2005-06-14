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
 * Copyright (c) 1993 by Sun Microsystems, Inc.
 */

/*
 * This file contains definitions which are only of interest to the actual
 * service daemon and client stubs.  Normal framework users will not include
 * this file.
 */

#ifndef _FW_RPC_H
#define	_FW_RPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	FW_NO_CONTEXT	"Plead no context"

#define	FW_PROG ((unsigned long)(150006))
#define	FW_VERSION ((unsigned long)(1))

#define	FW_INVOKE ((unsigned long)(1))
#define	FW_MORE ((unsigned long)(2))
#define	FW_KILL ((unsigned long)(3))


/* the xdr functions */

extern  bool_t _TKFAR _TKPASCAL xdr_Op_arg(XDR _TKFAR *, Op_arg _TKFAR *);
extern  bool_t _TKFAR _TKPASCAL xdr_Fw_err(XDR _TKFAR *, Fw_err _TKFAR *);
extern  bool_t _TKFAR _TKPASCAL xdr_Op_err(XDR _TKFAR *, Op_err _TKFAR *);
extern  bool_t _TKFAR _TKPASCAL xdr_invk_context(XDR _TKFAR *, invk_context);
extern  bool_t _TKFAR _TKPASCAL xdr_invk_result(XDR _TKFAR *,
    invk_result _TKFAR *);
extern  bool_t _TKFAR _TKPASCAL xdr_invk_request(XDR _TKFAR *,
    invk_request _TKFAR *);
extern  bool_t _TKFAR _TKPASCAL xdr_more_request(XDR _TKFAR *,
    more_request _TKFAR *);
extern  bool_t _TKFAR _TKPASCAL xdr_kill_request(XDR _TKFAR *,
    kill_request _TKFAR *);

#ifdef _WINDOWS
extern	void thunk_xdrs(void);
extern	void unthunk_xdrs(void);
extern	FARPROC lp_xdr_invk_request, lp_xdr_invk_result;
extern	FARPROC lp_xdr_more_request, lp_xdr_kill_request;
extern	FARPROC lp_xdr_Op_err, lp_xdr_Op_arg;
#endif

#ifdef __cplusplus
}
#endif

#endif /* !_FW_RPC_H */
