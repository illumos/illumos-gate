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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_STRUCTS_H
#define	_STRUCTS_H

#include <sac.h>
#include "misc.h"

/*
 * error messages
 */

struct errmsg {
	char *e_str;			/* error string */
	int e_exitcode;			/* and associated exit status */
};


/*
 * everything we need to know about a port monitor
 */

struct	sactab {
	long	sc_flags;		/* flags */
	pid_t	sc_pid;			/* pid of PM */
	int	sc_rsmax;		/* max # of restarts */
	int	sc_rscnt;		/* # of restarts */
	int	sc_fd;			/* _pmpipe fd */
	int	sc_ok;			/* true if responded to last sanity poll */
	int	sc_valid;		/* true if entry is "current" */
	char	*sc_cmd;		/* command */
	char	*sc_comment;		/* comment associated with entry */
	struct	sactab	*sc_next;	/* next in list */
	short	sc_exit;		/* exit status */
	char	sc_maxclass;		/* largest class instruction this PM
					   understands.  This is currently
					   a place holder for future messages */
	unchar	sc_sstate;		/* SAC's idea of PM's state */
	unchar	sc_lstate;		/* SAC's idea of last valid state -
					   used for failure recovery - note:
					   SAC will set this field to ENABLED,
					   DISABLED, or NOTRUNNING as appropriate */
	unchar	sc_pstate;		/* PM's last reported state - note:
					   SAC will set this field to STARTING,
					   NOTRUNNING, or FAILED as appropriate */
	char	sc_tag[PMTAGSIZE + 1];	/* port monitor tag */
	char	sc_type[PMTYPESIZE + 1];/* port monitor type */
	char	sc_utid[IDLEN];		/* utmp id of PM */
};

/*
 * defn's for sc_sstate, sc_pstate, and sc_lstate
 */

#define	NOTRUNNING	0	/* PM not running */
#define	STARTING	1	/* PM starting, must be same as PM_STARTING */
#define	ENABLED		2	/* PM enabled, must be same as PM_ENABLED */
#define	DISABLED	3	/* PM disabled, must be same as PM_DISABLED */
#define	STOPPING	4	/* PM stopping, must be same as PM_STOPPING */
#define	FAILED		5	/* PM has failed */
#define	UNKNOWN		6	/* in recovery, state unknown */

/*
 * defn's for sc_flags
 */

#define	D_FLAG	0x1
#define	X_FLAG	0x2

#endif /* _STRUCTS_H */
