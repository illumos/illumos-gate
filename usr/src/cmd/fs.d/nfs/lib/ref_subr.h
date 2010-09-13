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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_REF_SUBR_H
#define	_REF_SUBR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <nfs/nfs4.h>
#include <rpcsvc/nfs4_prot.h>

extern utf8string *str_to_utf8(char *, utf8string *);
extern char *utf8_to_str(utf8string *, uint_t *, char *);
extern void print_referral_summary(fs_locations4 *);
extern int make_pathname4(char *, pathname4 *);
extern bool_t xdr_component4(register XDR *, component4 *);
extern bool_t xdr_utf8string(register XDR *, utf8string *);
extern bool_t xdr_pathname4(register XDR *, pathname4 *);
extern bool_t xdr_fs_location4(register XDR *, fs_location4 *);
extern bool_t xdr_fs_locations4(register XDR *, fs_locations4 *);

#ifdef __cplusplus
}
#endif

#endif	/* _REF_SUBR_H */
