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

#ifndef	_LIBSMBRDR_H
#define	_LIBSMBRDR_H

#include <smbsrv/libsmb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Redirector LOGON function */
extern int smbrdr_logon(char *, char *, char *);
extern int smbrdr_get_ssnkey(int, unsigned char *, size_t);

/* Redirector named pipe functions */
extern int smbrdr_open_pipe(char *, char *, char *, char *);
extern int smbrdr_close_pipe(int);
extern int smbrdr_readx(int, char *, int);
extern int smbrdr_transact(int, char *, int, char *, int);

/* Redirector session functions */
extern int smbrdr_echo(const char *);
extern void smbrdr_disconnect(const char *);

/* DEBUG functions */
extern void smbrdr_dump_ofiles(void);
extern void smbrdr_dump_sessions(void);
extern void smbrdr_dump_netuse();

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSMBRDR_H */
