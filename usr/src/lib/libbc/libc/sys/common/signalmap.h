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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#define	XSIGUSR1 	16	/* user defined signal 1 */
#define	XSIGUSR2 	17	/* user defined signal 2 */
#define	XSIGCLD		18	/* System V name for SIGCHLD */
#define XSIGPWR		19	/* power-fail restart */
#define	XSIGWINCH 	20	/* window changed */
#define	XSIGURG		21	/* urgent condition on IO channel */
#define	XSIGIO		22	/* input/output possible signal */
#define	XSIGSTOP	23	/* sendable stop signal not from tty */
#define	XSIGTSTP	24	/* stop signal from tty */
#define	XSIGCONT	25	/* continue a stopped process */
#define	XSIGTTIN	26	/* to readers pgrp upon background tty read */
#define	XSIGTTOU	27	/* like TTIN for output */
#define	XSIGVTALRM 	28	/* virtual time alarm */
#define	XSIGPROF	29	/* profiling time alarm */
#define	XSIGXCPU	30	/* exceeded CPU time limit */
#define	XSIGXFSZ	31	/* exceeded file size limit */


/* SVR4 siginfo_t structure */
#define SI_PAD	((128/sizeof(int)) -3)

typedef struct siginfo {

        int     si_signo;                       /* signal from signal.h */
        int     si_code;                        /* code from above      */
        int     si_errno;                       /* error from errno.h   */

        union {

                int     _pad[SI_PAD];           /* for future growth    */
 
                struct {                        /* kill(), SIGCLD       */
                        long   _pid;           /* process ID           */
                        union {
                                struct {
                                        long   _uid;
                                } _kill;
                                struct {
                                        long _utime;
                                        int     _status;
                                        long _stime;
                                } _cld;
                        } _pdata;
                } _proc;

                struct {        /* SIGSEGV, SIGBUS, SIGILL and SIGFPE   */
                        char * _addr;          /* faulting address     */
                } _fault;
 
                struct {                        /* SIGPOLL, SIGXFSZ     */
                /* fd not currently available for SIGPOLL */
                        int     _fd;            /* file descriptor      */
                        long    _band;
                } _file;
 
        } _data;
 
} siginfo_t;

#define si_pid		_data._proc._pid
#define si_status	_data._proc._pdata._cld._status
#define si_addr		_data._fault._addr
