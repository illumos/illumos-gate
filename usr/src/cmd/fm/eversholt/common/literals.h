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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * literals.h -- public definitions for literals in string table
 *
 * all strings in this program are kept in the string table provided
 * by the routines in stable.c.  this allows us to see if two strings
 * are equal by checking their pointers rather than calling strcmp().
 * when we want to check for a specific string we can either do this:
 * 	if (s == stable("word"))
 * or define the literal here in this file and then do this:
 * 	if (s == L_word)
 *
 * the macro L_DECL() below expands to an extern const char * declaration
 * for files that include it.  the exception is some cpp statements done by
 * literals.c which change L_DECL() to initialize the string by calling
 * stable().
 */

#ifndef	_ESC_COMMON_LITERALS_H
#define	_ESC_COMMON_LITERALS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	L_DECL
#define	L_DECL(s) extern const char *L_##s
#endif

/* reserved words */
L_DECL(asru);
L_DECL(div);
L_DECL(engine);
L_DECL(event);
L_DECL(fru);
L_DECL(if);
L_DECL(mask);
L_DECL(prop);
L_DECL(config);

/* event types */
L_DECL(fault);
L_DECL(upset);
L_DECL(defect);
L_DECL(error);
L_DECL(ereport);

/* engine types */
L_DECL(serd);
L_DECL(stat);

/* timeval suffixes */
L_DECL(nanosecond);
L_DECL(nanoseconds);
L_DECL(nsec);
L_DECL(nsecs);
L_DECL(ns);
L_DECL(microsecond);
L_DECL(microseconds);
L_DECL(usec);
L_DECL(usecs);
L_DECL(us);
L_DECL(millisecond);
L_DECL(milliseconds);
L_DECL(msec);
L_DECL(msecs);
L_DECL(ms);
L_DECL(second);
L_DECL(seconds);
L_DECL(s);
L_DECL(minute);
L_DECL(minutes);
L_DECL(min);
L_DECL(mins);
L_DECL(m);
L_DECL(hour);
L_DECL(hours);
L_DECL(hr);
L_DECL(hrs);
L_DECL(h);
L_DECL(day);
L_DECL(days);
L_DECL(d);
L_DECL(week);
L_DECL(weeks);
L_DECL(wk);
L_DECL(wks);
L_DECL(month);
L_DECL(months);
L_DECL(year);
L_DECL(years);
L_DECL(yr);
L_DECL(yrs);
L_DECL(infinity);

/* property names */
L_DECL(ASRU);
L_DECL(action);
L_DECL(FITrate);
L_DECL(FRU);
L_DECL(id);
L_DECL(message);
L_DECL(retire);
L_DECL(response);
L_DECL(FRUID);
L_DECL(N);
L_DECL(T);
L_DECL(count);
L_DECL(method);
L_DECL(poller);
L_DECL(timeout);
L_DECL(trip);
L_DECL(discard_if_config_unknown);

/* property values */
L_DECL(A);
L_DECL(volatile);
L_DECL(persistent);

/* event bubble types */
L_DECL(from);
L_DECL(to);
L_DECL(inhibit);

/*
 * internal function names.  note that "fru" and "asru" are also function
 * names.
 */
L_DECL(within);
L_DECL(call);
L_DECL(confcall);
L_DECL(confprop);
L_DECL(confprop_defined);
L_DECL(defined);
L_DECL(payloadprop);
L_DECL(payloadprop_contains);
L_DECL(payloadprop_defined);
L_DECL(setpayloadprop);
L_DECL(setserdsuffix);
L_DECL(setserdincrement);
L_DECL(setserdn);
L_DECL(setserdt);
L_DECL(envprop);
L_DECL(is_connected);
L_DECL(is_under);
L_DECL(is_on);
L_DECL(is_present);
L_DECL(is_type);
L_DECL(count);

/* our enumerated types (used for debugging) */
L_DECL(T_NOTHING);
L_DECL(T_NAME);
L_DECL(T_GLOBID);
L_DECL(T_ENAME);
L_DECL(T_EVENT);
L_DECL(T_ENGINE);
L_DECL(T_ASRU);
L_DECL(T_FRU);
L_DECL(T_TIMEVAL);
L_DECL(T_NUM);
L_DECL(T_QUOTE);
L_DECL(T_FUNC);
L_DECL(T_NVPAIR);
L_DECL(T_ASSIGN);
L_DECL(T_CONDIF);
L_DECL(T_CONDELSE);
L_DECL(T_NOT);
L_DECL(T_AND);
L_DECL(T_OR);
L_DECL(T_EQ);
L_DECL(T_NE);
L_DECL(T_SUB);
L_DECL(T_ADD);
L_DECL(T_MUL);
L_DECL(T_DIV);
L_DECL(T_MOD);
L_DECL(T_LT);
L_DECL(T_LE);
L_DECL(T_GT);
L_DECL(T_GE);
L_DECL(T_BITAND);
L_DECL(T_BITOR);
L_DECL(T_BITXOR);
L_DECL(T_BITNOT);
L_DECL(T_LSHIFT);
L_DECL(T_RSHIFT);
L_DECL(T_ARROW);
L_DECL(T_LIST);
L_DECL(T_FAULT);
L_DECL(T_UPSET);
L_DECL(T_DEFECT);
L_DECL(T_ERROR);
L_DECL(T_EREPORT);
L_DECL(T_SERD);
L_DECL(T_STAT);
L_DECL(T_PROP);
L_DECL(T_MASK);
L_DECL(N_UNSPEC);
L_DECL(N_FAULT);
L_DECL(N_UPSET);
L_DECL(N_DEFECT);
L_DECL(N_ERROR);
L_DECL(N_EREPORT);
L_DECL(N_SERD);
L_DECL(IT_NONE);
L_DECL(IT_VERTICAL);
L_DECL(IT_HORIZONTAL);
L_DECL(IT_ENAME);

/* misc */
L_DECL(nofile);

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_LITERALS_H */
