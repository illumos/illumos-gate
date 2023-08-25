/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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


/*
 * admin/stash/kdb5_stash.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Store the master database key in a file.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include <kadm5/admin.h>
#include "com_err.h"
#include <kadm5/admin.h>
#include <stdio.h>
#include <libintl.h>
#include "kdb5_util.h"

extern krb5_principal master_princ;
extern kadm5_config_params global_params;

extern int exit_status;

void
kdb5_stash(argc, argv)
    int argc;
    char *argv[];
{
    extern char *optarg;
    extern int optind;
    int optchar;
    krb5_error_code retval;
    char *dbname = (char *) NULL;
    char *realm = 0;
    char *mkey_name = 0;
    char *mkey_fullname;
    char *keyfile = 0;
    krb5_context context;
    krb5_keyblock mkey;

/* Solaris Kerberos */
#if 0
    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;
#endif
    retval = kadm5_init_krb5_context(&context);
    if( retval )
    {
	/* Solaris Kerberos */
	com_err(progname, retval, "while initializing krb5_context");
	exit(1);
    }

    if ((retval = krb5_set_default_realm(context,
					  util_context->default_realm))) {
	/* Solaris Kerberos */
	com_err(progname, retval, "while setting default realm name");
	exit(1);
    }

    dbname = global_params.dbname;
    realm = global_params.realm;
    mkey_name = global_params.mkey_name;
    keyfile = global_params.stash_file;

    optind = 1;
    while ((optchar = getopt(argc, argv, "f:")) != -1) {
	switch(optchar) {
	case 'f':
	    keyfile = optarg;
	    break;
	case '?':
	default:
	    usage();
	    return;
	}
    }

    if (!krb5_c_valid_enctype(global_params.enctype)) {
	char tmp[32];
	if (krb5_enctype_to_string(global_params.enctype,
					    tmp, sizeof (tmp)))
	    /* Solaris Kerberos */
	    com_err(progname, KRB5_PROG_KEYTYPE_NOSUPP,
		gettext("while setting up enctype %d"),
		global_params.enctype);
	else {
	    /* Solaris Kerberos */
	    com_err(progname, KRB5_PROG_KEYTYPE_NOSUPP, tmp);
	}
	exit_status++; return;
    }

    /* assemble & parse the master key name */
    retval = krb5_db_setup_mkey_name(context, mkey_name, realm,
				     &mkey_fullname, &master_princ);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval,
		gettext("while setting up master key name"));
	exit_status++; return;
    }

    retval = krb5_db_open(context, db5util_db_args,
			  KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_OTHER);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval,
		gettext("while initializing the database '%s'"),
		dbname);
	exit_status++; return;
    }

    /* TRUE here means read the keyboard, but only once */
    retval = krb5_db_fetch_mkey(context, master_princ,
				global_params.enctype,
				TRUE, FALSE, (char *) NULL,
				0, &mkey);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while reading master key"));
	(void) krb5_db_fini(context);
	exit_status++; return;
    }

    retval = krb5_db_verify_master_key(context, master_princ, &mkey);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval, gettext("while verifying master key"));
	krb5_free_keyblock_contents(context, &mkey);
	(void) krb5_db_fini(context);
	exit_status++; return;
    }

    retval = krb5_db_store_master_key(context, keyfile, master_princ,
				    &mkey, NULL);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, errno, gettext("while storing key"));
	krb5_free_keyblock_contents(context, &mkey);
	(void) krb5_db_fini(context);
	exit_status++; return;
    }
    krb5_free_keyblock_contents(context, &mkey);

    retval = krb5_db_fini(context);
    if (retval) {
	/* Solaris Kerberos */
	com_err(progname, retval,
		gettext("closing database '%s'"), dbname);
	exit_status++; return;
    }

    krb5_free_context(context);
    exit_status = 0;
    return;
}
