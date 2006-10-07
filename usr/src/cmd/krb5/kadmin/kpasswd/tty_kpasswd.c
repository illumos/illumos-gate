/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
 * Copyright 1993-1994 OpenVision Technologies, Inc., All Rights Reserved.
 * 
 * $Header: /cvs/krbdev/krb5/src/kadmin/passwd/tty_kpasswd.c,v 1.9 2001/02/26 18:22:08 epeisach Exp $
 *
 *
 */

static char rcsid[] = "$Id: tty_kpasswd.c,v 1.9 2001/02/26 18:22:08 epeisach Exp $";

#include <kadm5/admin.h>
#include <krb5.h>

#include "kpasswd_strings.h"
#define string_text error_message

#include "kpasswd.h"
#include <stdio.h>
#include <pwd.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>

char *whoami;

void display_intro_message(fmt_string, arg_string)
     const char *fmt_string;
     const char *arg_string;
{
  com_err(whoami, 0, fmt_string, arg_string);
}

long read_old_password(context, password, pwsize)
     krb5_context context;
     char *password;
     unsigned int *pwsize;
{
  long code = krb5_read_password(context,
	    (char *) string_text(KPW_STR_OLD_PASSWORD_PROMPT),
			 0, password, pwsize);
  return code;
}

long read_new_password(server_handle, password, pwsize, msg_ret, msg_len, princ)
     void *server_handle;
     char *password;
     unsigned int *pwsize;
     char *msg_ret;
     int msg_len;
     krb5_principal princ;
{
	return (kadm5_chpass_principal_util(server_handle, princ, NULL,
					   NULL /* don't need new pw back */,
		msg_ret, msg_len));
}


/*
 * main() for tty version of kpasswd.c
 */
int
main(argc, argv)
     int argc;
     char *argv[];
{
  krb5_context context;
  int retval;

  whoami = (whoami = strrchr(argv[0], '/')) ? whoami + 1 : argv[0];

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)  /* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif

	(void) textdomain(TEXT_DOMAIN);

  retval = krb5_init_context(&context);
  if (retval) {
		com_err(whoami, retval, gettext("initializing krb5 context"));
       exit(retval);
  }
	/* initialize_kpws_error_table(); SUNWresync121 */

  retval = kpasswd(context, argc, argv);

  if (!retval)
    printf(string_text(KPW_STR_PASSWORD_CHANGED));

  exit(retval);
}
