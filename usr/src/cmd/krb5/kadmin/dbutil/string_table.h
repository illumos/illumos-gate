/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _STRING_TABLE_H
#define	_STRING_TABLE_H

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
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Header: /afs/athena.mit.edu/astaff/project/krbdev/.cvsroot/src/kadmin/\
 * dbutil/string_table.h,v 1.2 1996/07/22 20:25:25 marc Exp $
 *
 */

#ifndef _OVSEC_ADM_STRINGS_
 
extern char *str_PARSE_NAME;
extern char *str_HISTORY_PARSE_NAME;
extern char *str_ADMIN_PRINC_EXISTS;
extern char *str_CHANGEPW_PRINC_EXISTS;
extern char *str_HISTORY_PRINC_EXISTS;
extern char *str_ADMIN_PRINC_WRONG_ATTRS;
extern char *str_CHANGEPW_PRINC_WRONG_ATTRS;
extern char *str_HISTORY_PRINC_WRONG_ATTRS;
extern char *str_CREATED_PRINC_DB;
extern char *str_CREATED_POLICY_DB;
extern char *str_RANDOM_KEY;
extern char *str_ENCRYPT_KEY;
extern char *str_PUT_PRINC;
extern char *str_CREATING_POLICY_DB;
extern char *str_CLOSING_POLICY_DB;
extern char *str_CREATING_PRINC_DB;
extern char *str_CLOSING_PRINC_DB;
extern char *str_CREATING_PRINC_ENTRY;
extern char *str_A_PRINC;
extern char *str_UNPARSE_PRINC;
extern char *str_CREATED_PRINC;
extern char *str_INIT_KDB;
extern char *str_NO_KDB;
extern char *str_INIT_RANDOM_KEY;
extern char *str_TOO_MANY_ADMIN_PRINC;
extern char *str_TOO_MANY_CHANGEPW_PRINC;
extern char *str_TOO_MANY_HIST_PRINC;
extern char *str_WHILE_DESTROYING_ADMIN_SESSION;
 
#endif /* _OVSEC_ADM_STRINGS_ */

#ifdef	__cplusplus
}
#endif

#endif	/* !_STRING_TABLE_H */
