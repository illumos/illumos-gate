/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KDB5_UTIL_H
#define	_KDB5_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * admin/edit/kdb5_edit.h
 *
 * Copyright 1992 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

#include <kdb/kdb_log.h>

#define	MAX_HEADER	1024
#define	REALM_SEP	'@'
#define	REALM_SEP_STR	"@"

extern char *progname;
extern char *Err_no_database;

void add_key
PROTOTYPE((char const *, char const *,
	krb5_const_principal, const krb5_keyblock *,
	krb5_kvno, krb5_keysalt *));
int set_dbname_help
    PROTOTYPE((char *, char *));

char *kdb5_util_Init PROTOTYPE((int, char **));

int quit();

int check_for_match
    PROTOTYPE((char *, int, krb5_db_entry *, int, int));

void parse_token
    PROTOTYPE((char *, int *, int *, char *));

int create_db_entry
    PROTOTYPE((krb5_principal, krb5_db_entry *));

#ifdef	__cplusplus
}
#endif

#endif	/* !_KDB5_UTIL_H */
