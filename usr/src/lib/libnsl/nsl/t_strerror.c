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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */

#include "mt.h"
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <libintl.h>
#include <stropts.h>
#include <xti.h>
#include "tx.h"

static const char __nsl_dom[]  = "SUNW_OST_NETNSL";

static char *_xti_errlist[] = {
	"No Error",					/*  0 */
	"Incorrect address format",			/*  1 - TBADADDR */
	"Incorrect options format",			/*  2 - TBADOPT */
	"Illegal permissions",				/*  3 - TACCES */
	"Illegal file descriptor",			/*  4 - TBADF */
	"Couldn't allocate address",			/*  5 - TNOADDR */
	"Routine will place interface out of state",    /*  6 - TOUTSTATE */
	"Illegal called/calling sequence number",	/*  7 - TBADSEQ */
	"System error",					/*  8 - TSYSERR */
	"An event requires attention",			/*  9 - TLOOK */
	"Illegal amount of data",			/* 10 - TBADDATA */
	"Buffer not large enough",			/* 11 - TBUFOVFLW */
	"Can't send message - (blocked)",		/* 12 - TFLOW */
	"No message currently available",		/* 13 - TNODATA */
	"Disconnect message not found",			/* 14 - TNODIS */
	"Unitdata error message not found",		/* 15 - TNOUDERR */
	"Incorrect flags specified",			/* 16 - TBADFLAG */
	"Orderly release message not found",		/* 17 - TNOREL */
	"Primitive not supported by provider",		/* 18 - TNOTSUPPORT */
	"State is in process of changing",		/* 19 - TSTATECHNG */

	/* Following error codes are new in XTI */

	"Unsupported structure type requested",		/* 20 - TNOSTRUCTYPE */
	"Invalid transport provider name",		/* 21 - TBADNAME */
	"Listener queue length limit is zero",		/* 22 - TBADQLEN */
	"Transport address is in use",			/* 23 - TADDRBUSY */
	"Outstanding connection indications",		/* 24 - TINDOUT */
	"Listener-acceptor transport provider mismatch",
							/* 25 - TPROVMISMATCH */
	"Connection acceptor has listen queue length limit greater than zero",
							/* 26 - TRESQLEN */
"Connection acceptor-listener address not same but required by transport",
							/* 27 - TRESADDR */
	"Incoming connection queue is full",		/* 28 - TQFULL */
	"Protocol error on transport primitive",	/* 29 - TPROTO */
};

static int _xti_nerr = A_CNT(_xti_errlist)-1; /* take off entry t_errno 0 */

char *
_tx_strerror(int errnum, int api_semantics)
{
	static char buf[BUFSIZ];

	if (_T_IS_XTI(api_semantics)) {
		if (errnum <= _xti_nerr && errnum >= 0)
			return (dgettext(__nsl_dom, _xti_errlist[errnum]));
		(void) snprintf(buf, sizeof (buf), "%d: %s", errnum,
			dgettext(__nsl_dom, "error unknown"));
		return (buf);
	}

	/* TX_TLI_API */
	/*
	 * This code for TLI only. It uses "t_nerr" and "t_errlist"
	 * which are exposed interfaces in the t_error() man page.
	 * XTI uses different array to avoid binary compatibility
	 * issues in using the exposed array. [ XTI t_error() does
	 * not mention the error message list array ]
	 *
	 * For the moment we simply index into the t_errlist[] array.
	 * When the array fills (we cannot allow it to expand in size
	 * or binary compatibility will be broken), this code will need
	 * modification.  See the comment in _errlst.c.
	 */
	if (errnum < t_nerr && errnum >= 0)
		return (dgettext(__nsl_dom, t_errlist[errnum]));
	(void) snprintf(buf, sizeof (buf), "%d: %s", errnum,
			dgettext(__nsl_dom, "error unknown"));
	return (buf);
}
