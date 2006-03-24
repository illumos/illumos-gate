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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define BEGIN_CRITICAL	{ ignore_signals(); {
#define END_CRITICAL	} trap_signals(); }

extern void		ignore_signals(),
			trap_signals();

extern int		a,
			banner,
#if	defined(DIRECT_ACCESS)
			C,
#endif
			filebreak,
			h,
			j,
			l,
			M,
			t,
			o,
			Q,
			W,
			scheduler_active;

extern char		*A,
			*c,
			*cpi,
			*d,
			*D,
			*e,
			*f,
			**f_allow,
			**f_deny,
			**p_add,
			**p_remove,
			*P,
			*F,
			**H,
			*i,
			**I,
			*length,
			*lpi,
			*m,
			modifications[128],
#ifdef LP_USE_PAPI_ATTR
			*n_opt,
#endif
			*p,
			*r,
			*s,
			*stty_opt,
			**o_options,
			**S,
			**T,
			*u,
			**u_allow,
			**u_deny,
			*U,
			*v,
			*width,
			*x;

#if	defined(LPUSER)
extern SCALED		cpi_sdn,
			length_sdn,
			lpi_sdn,
			width_sdn;
#endif

#if	defined(PR_MAX)
extern PRINTER		*oldp;

extern PWHEEL		*oldS;
#endif

extern short		daisy;

extern char		*Local_System;

extern char		*getdflt();

extern int		ismodel(),
			output(),
			verify_form(),
			do_align();

extern void		do_fault(),
			do_mount(),
			do_printer(),
			do_pwheel(),
			done(),
			fromclass(),
			newdflt(),
			options(),
			rmdest(),
			startup(),
			usage();

/* Routines/variables needed for labeled systems */
extern void		update_dev_dbs(char *, char *, char *);
extern int		system_labeled;


#if	defined(__STDC__)
void			send_message( int , ... );
extern char ** pick_opts(char *, char **);
#else
extern void		send_message();
extern char ** pick_opts();
#endif
