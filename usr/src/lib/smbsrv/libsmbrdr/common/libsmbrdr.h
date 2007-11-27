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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBSMBRDR_H
#define	_LIBSMBRDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/libsmb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Redirector IPC functions
 *
 * The following functions are required by the mlsvc_join to
 * apply new authentication information for the authenticated IPC, rollback
 * or commit the changes to the original authentication information.
 */
extern void smbrdr_ipc_set(char *, unsigned char *);
extern void smbrdr_ipc_commit(void);
extern void smbrdr_ipc_rollback(void);
extern int smbrdr_ipc_skip_lsa_query(void);
extern char *smbrdr_ipc_get_user(void);
extern unsigned char *smbrdr_ipc_get_passwd(void);


/* Redirector LOGON function */
extern int mlsvc_logon(char *, char *, char *);

extern int smbrdr_rpc_readx(int, char *, int);


/* Redirector rpcpipe functions */
extern int mlsvc_open_pipe(char *, char *, char *, char *);
extern int mlsvc_close_pipe(int);


/* Redirector session functions */
extern void smbrdr_init(void);
extern int mlsvc_locate_domain_controller(char *);
extern int mlsvc_session_native_values(int, int *, int *, int *);
extern void mlsvc_check_sessions(void);
extern int mlsvc_echo(char *);
extern void mlsvc_disconnect(char *);


extern int smbrdr_rpc_transact(int, char *, int, char *, int);


/* DEBUG functions */
extern void smbrdr_dump_ofiles(void);
extern void smbrdr_dump_sessions(void);
extern void smbrdr_dump_netuse();

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSMBRDR_H */
