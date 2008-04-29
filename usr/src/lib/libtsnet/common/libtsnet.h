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
 * All symbols and functions in this header file and library are private to Sun
 * Microsystems.  The only guarantee that is made is that if your application
 * uses them, it will break on upgrade.
 */

#ifndef	_LIBTSNET_H
#define	_LIBTSNET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/tsol/tndb.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	TNRHTP_PATH	"/etc/security/tsol/tnrhtp"
#define	TNRHDB_PATH	"/etc/security/tsol/tnrhdb"
#define	TNZONECFG_PATH	"/etc/security/tsol/tnzonecfg"

#define	TNDB_COMMA	", \t"
#define	TN_RESERVED	",#;"

/*
 * String parsing routines
 *
 * These functions are in four logical groups: one for template (tnrhtp)
 * entries, one for remote host (tnrhdb) entries, one for zone configuration
 * (tnzonecfg) entries, and a fourth for routing attributes.
 *
 * In each group, there are functions that parse from a string or database, and
 * a function to free returned entries.  The parsing functions all take a
 * pointer to an integer and a pointer to a character pointer for returning
 * errors.  On error, the returned entry pointer is NULL, the integer is set to
 * one of the LTSNET_* errors below, and the character pointer points to the
 * location of the error.  (For the functions that iterate on a database, this
 * points into static storage in the library.  This storage is associated with
 * the iterator.)
 *
 * The functions that do look-ups based on a value (name or address) do not
 * return errors other than "not found," which is signaled by a return value of
 * NULL.
 */

/* Template entry parsing */
extern tsol_tpent_t *tsol_gettpbyname(const char *);
extern tsol_tpent_t *tsol_gettpent(void);
extern tsol_tpent_t *tsol_fgettpent(FILE *, boolean_t *);
extern void tsol_freetpent(tsol_tpent_t *);
extern void tsol_settpent(int);
extern void tsol_endtpent(void);
extern int str_to_tpstr(const char *, int, void *, char *, int);
extern tsol_tpent_t *tpstr_to_ent(tsol_tpstr_t *, int *, char **);

/* Remote host entry parsing */
extern tsol_rhent_t *tsol_getrhbyaddr(const void *, size_t, int);
extern tsol_rhent_t *tsol_getrhent(void);
extern tsol_rhent_t *tsol_fgetrhent(FILE *, boolean_t *);
extern void tsol_freerhent(tsol_rhent_t *);
extern void tsol_setrhent(int);
extern void tsol_endrhent(void);
extern int str_to_rhstr(const char *, int, void *, char *, int);
extern tsol_rhent_t *rhstr_to_ent(tsol_rhstr_t *, int *, char **);
extern tsol_host_type_t tsol_getrhtype(char *);


/* Zone configuration parsing */
extern tsol_zcent_t *tsol_sgetzcent(const char *, int *, char **);
extern void tsol_freezcent(tsol_zcent_t *);

/* Routing attribute parsing */
extern const char *sl_to_str(const bslabel_t *);
struct rtsa_s;
extern const char *rtsa_to_str(const struct rtsa_s *, char *, size_t);
extern boolean_t rtsa_keyword(const char *, struct rtsa_s *, int *, char **);
extern const char *parse_entry(char *, size_t, const char *, const char *);

/* Convert LTSNET_* to a printable string */
extern const char *tsol_strerror(int, int);

/* System calls; these return -1 on error and set errno */
extern int tnrhtp(int, tsol_tpent_t *);
extern int tnrh(int, tsol_rhent_t *);
extern int tnmlp(int, tsol_mlpent_t *);

/*
 * Errors that can occur in the parsing routines.  Note that not all errors are
 * possible with every routine.  Must be kept in sync with list in misc.c.
 */
#define	LTSNET_NONE		0	/* No error */
#define	LTSNET_SYSERR		1	/* System error; see errno */
#define	LTSNET_EMPTY		2	/* Empty string or end of list */
#define	LTSNET_ILL_ENTRY	3	/* Entry is malformed */
#define	LTSNET_NO_NAME		4	/* Missing name */
#define	LTSNET_NO_ATTRS		5	/* Missing template attributes */
#define	LTSNET_ILL_NAME		6	/* Illegal name */
#define	LTSNET_ILL_KEYDELIM	7	/* Illegal keyword delimiter */
#define	LTSNET_ILL_KEY		8	/* Unknown keyword */
#define	LTSNET_DUP_KEY		9	/* Duplicate keyword */
#define	LTSNET_ILL_VALDELIM	10	/* Illegal value delimiter */
#define	LTSNET_NO_HOSTTYPE	11	/* Missing host type */
#define	LTSNET_ILL_HOSTTYPE	12	/* Illegal host type */
#define	LTSNET_NO_LABEL		13	/* Missing label */
#define	LTSNET_ILL_LABEL	14	/* Illegal label */
#define	LTSNET_NO_RANGE		15	/* Missing label range */
#define	LTSNET_ILL_RANGE	16	/* Illegal label range */
#define	LTSNET_NO_LOWERBOUND	17	/* No lower bound in range */
#define	LTSNET_ILL_LOWERBOUND	18	/* Illegal lower bound in range */
#define	LTSNET_NO_UPPERBOUND	19	/* No upper bound in range */
#define	LTSNET_ILL_UPPERBOUND	20	/* Illegal upper bound in range */
#define	LTSNET_NO_DOI		21	/* Missing DOI */
#define	LTSNET_ILL_DOI		22	/* Illegal DOI */
#define	LTSNET_SET_TOO_BIG	23	/* Too many entries in set */
#define	LTSNET_NO_ADDR		24	/* Missing address/network */
#define	LTSNET_ILL_ADDR		25	/* Illegal address/network */
#define	LTSNET_ILL_FLAG		26	/* Illegal flag */
#define	LTSNET_ILL_MLP		27	/* Illegal MLP specification */
#define	LTSNET_BAD_TYPE		28	/* Unacceptable keyword for type */

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBTSNET_H */
