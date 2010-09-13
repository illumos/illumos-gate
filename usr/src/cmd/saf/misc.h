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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4*/


/*
 * current version of _sactab
 */

# define VERSION	1

/*
 * comment delimiter
 */

# define COMMENT	'#'

/*
 * field delimiter (one version for functions that take string args, and
 * one for character args)
 */

# define DELIM	":"
# define DELIMC	':'

/*
 * key file names
 */

# define HOME		"/etc/saf"			/* SAC home dir */
# define ALTHOME	"/var/saf"			/* alternate directory for misc. files */
# define SACTAB		"/etc/saf/_sactab"		/* SAC admin file */
# define LOGFILE	"/var/saf/_log"			/* SAC log file */
# define DBGFILE	"/var/saf/debug"		/* SAC debug file */
# define SYSCONFIG	"/etc/saf/_sysconfig"		/* sys config file */
# define CMDPIPE	"/etc/saf/_cmdpipe"		/* SAC command pipe */

/*
 * version string stamp
 */

# define VSTR		"# VERSION="

/*
 * miscellaneous
 */

# define PMTYPESIZE	14	/* maximum length for a port monitor type */
# define SVCTAGSIZE	14	/* maximum length for a service tag */
# define SLOP		20	/* enough extra bytes to hold status info */
# define TRUE		1	/* definition of true */
# define FALSE		0	/* definition of false */
# define SSTATE		255	/* special state to indicate no sac */
# define SIZE		512	/* scratch buffer size */
# define BADFARGSIZE	256	/* hold bad args (to -f) buffer size */
