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


/*
 * Copyright 1994 by the Massachusetts Institute of Technology.
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
 * ss wrapper for kadmin
 */

#include <krb5.h>
#include <ss/ss.h>
#include <stdio.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include "kadmin.h"

extern ss_request_table kadmin_cmds;
extern int exit_status;
extern char *whoami;

int main(argc, argv)
    int argc;
    char *argv[];
{
    char *request;
    krb5_error_code retval;
    int sci_idx, code = 0;

    whoami = ((whoami = strrchr(argv[0], '/')) ? whoami+1 : argv[0]);

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)  /* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif

	(void) textdomain(TEXT_DOMAIN);

    request = kadmin_startup(argc, argv);
    sci_idx = ss_create_invocation(whoami, "5.0", (char *) NULL,
				   &kadmin_cmds, &retval);
    if (retval) {
	ss_perror(sci_idx, retval, gettext("creating invocation"));
	exit(1);
    }

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

    if (request) {
	    code = ss_execute_line(sci_idx, request);
	    if (code != 0) {
		    ss_perror(sci_idx, code, request);
		    exit_status++;
	    }
    } else
            retval = ss_listen(sci_idx);
    return quit() ? 1 : exit_status;
}
