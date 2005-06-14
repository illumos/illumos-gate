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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <utmp.h>
#include <sys/types.h>
#include <sys/time.h>

/*
 * the following value will be stuffed into "fd2", which was previously
 * used to hold the fd of the utmpx or wtmpx file when the application
 * attempted to open utmp or wtmp.  Since we now only support utmpx
 * and wtmpx, that is always the only file we open (now as "fd").
 * The magic value in the second descriptor simply tells us that 
 * the fd is "special", in that we have to do utmp to utmpx
 * record conversions on data read or written.  The magic value
 * is specifically chosen to be higher than any possible fd value
 * could be in a 4.x application.
 */

#define UTMPX_MAGIC_FLAG	512

/*
 * 4.x utmp record format
 */
struct compat_utmp
  {
	char	ut_line[8];		/* tty name */
	char	ut_name[8];		/* user id */
	char	ut_host[16];		/* host name, if remote */
	time_t	ut_time;		/* time on */
  } ;


struct exit_status
{
	short e_termination;		/* termination status */
	short e_exit;			/* exit status */
} ;

struct utmpx
  {
      char    ut_user[32];            /* user login name */
      char    ut_id[4];               /* inittab id */
      char    ut_line[32];            /* device name (console, lnxx) */
      long   ut_pid;                 /* process id */
      short   ut_type;                /* type of entry */
      struct exit_status ut_exit;     /* process termination/exit status */
      struct timeval ut_tv;           /* time entry was made */
      long    ut_session;             /* session ID, used for windowing */
      long    pad[5];                 /* reserved for future use */
      short   ut_syslen;              /* significant length of ut_host */
                                      /*   including terminating null */
      char    ut_host[257];           /* remote host name */
  } ;


#define getmodsize(size, ftype, ttype)	\
	(((size / ftype) * ttype) + (size % ftype))
