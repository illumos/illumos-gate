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
 * rex - remote execution server definitions
 *
 * Copyright (c) 1985 Sun Microsystems, Inc.
 */

#ifndef _RPCSVC_REX_H
#define	_RPCSVC_REX_H

#ident	"%Z%%M%	%I%	%E% SMI"
/*	@(#)rex.h 1.7 89/10/02 Copyr 1985 SMI */

#define	REXPROG		100017
#define	REXPROC_NULL	0	/* no operation */
#define	REXPROC_START	1	/* start a command */
#define	REXPROC_WAIT	2	/* wait for a command to complete */
#define	REXPROC_MODES	3	/* send the tty modes */
#define	REXPROC_WINCH	4	/* signal a window change */
#define	REXPROC_SIGNAL	5	/* other signals */

#define	REXVERS	1

/* flags for rst_flags field */
#define	REX_INTERACTIVE		1	/* Interative mode */

struct rex_start {
	/*
	 * Structure passed as parameter to start function
	 */
	char	**rst_cmd;	/* list of command and args */
	char	*rst_host;	/* working directory host name */
	char	*rst_fsname;	/* working directory file system name */
	char	*rst_dirwithin;	/* working directory within file system */
	char	**rst_env;	/* list of environment */
	u_short	rst_port0;	/* port for stdin */
	u_short	rst_port1;	/* port for stdin */
	u_short	rst_port2;	/* port for stdin */
	u_long	rst_flags;	/* options - see #defines above */
};

bool_t xdr_rex_start();

struct rex_result {
	/*
	 * Structure returned from the start function
	 */
	int	rlt_stat;	/* integer status code */
	char	*rlt_message;	/* string message for human consumption */
};
bool_t xdr_rex_result();
bool_t xdr_tchars();
bool_t xdr_ltchars();
bool_t xdr_sgttyb();

/*
 * sgttyb structure changed from BSD to SVR4. Since we send it over the
 * protocol, we stick to the old one for compatability
 */
struct	bsd_sgttyb {
	char	sg_ispeed;		/* input speed */
	char	sg_ospeed;		/* output speed */
	char	sg_erase;		/* erase character */
	char	sg_kill;		/* kill character */
	short	sg_flags;		/* mode flags */
};

struct rex_ttymode {
	/*
	 * Structure sent to set-up the tty modes
	 */
	struct bsd_sgttyb basic; /* standard unix tty flags */
	struct tchars more;	/* interrupt, kill characters, etc. */
	struct ltchars yetmore;	/* special Bezerkeley characters */
	u_long andmore;		/* and Berkeley modes */
};

bool_t xdr_rex_ttymode();

struct rex_ttysize {
	int ts_lines;
	int ts_cols;
};
typedef struct rex_ttysize rex_ttysize;
bool_t xdr_rex_ttysize();


#endif	/* _RPCSVC_REX_H */
