/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * clients/kdestroy/kdestroy.c
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
 * Destroy the contents of your credential cache.
 */

#include <krb5.h>
#include <com_err.h>
#include <string.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <locale.h>
#include <rpc/types.h>
#include <rpc/rpcsys.h>
#include <rpc/rpcsec_gss.h>
#include <syslog.h>
#include <libintl.h>

#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#endif

#ifdef __STDC__
#define BELL_CHAR '\a'
#else
#define BELL_CHAR '\007'
#endif

extern int optind;
extern char *optarg;

#ifndef _WIN32
#define GET_PROGNAME(x) (strrchr((x), '/') ? strrchr((x), '/')+1 : (x))
#else
#define GET_PROGNAME(x) max(max(strrchr((x), '/'), strrchr((x), '\\')) + 1,(x))
#endif

char *progname;

int got_k5 = 0;
int got_k4 = 0;

int default_k5 = 1;
#ifdef KRB5_KRB4_COMPAT
int default_k4 = 1;
#else
int default_k4 = 0;
#endif


static void usage()
{
#define KRB_AVAIL_STRING(x) ((x)?gettext("available"):gettext("not available"))

    fprintf(stderr, gettext("Usage"), ": %s [-5] [-4] [-q] [-c cache_name]\n",
            progname);
    fprintf(stderr, "\t-5 Kerberos 5 (%s)\n", KRB_AVAIL_STRING(got_k5));
    fprintf(stderr, "\t-4 Kerberos 4 (%s)\n", KRB_AVAIL_STRING(got_k4));
    fprintf(stderr, gettext("\t   (Default is %s%s%s%s)\n"),
	    default_k5?"Kerberos 5":"",
	    (default_k5 && default_k4)?gettext(" and "):"",
	    default_k4?"Kerberos 4":"",
	    (!default_k5 && !default_k4)?gettext("neither"):"");
    fprintf(stderr, gettext("\t-q quiet mode\n"));
    fprintf(stderr, gettext("\t-c specify name of credentials cache\n"));
    exit(2);
}

int
main(argc, argv)
    int argc;
    char **argv;
{
    krb5_context kcontext;
    krb5_error_code retval;
    int c;
    krb5_ccache cache = NULL;
    char *cache_name = NULL;
    char *client_name = NULL;
    krb5_principal me;
    int code = 0;
#ifdef KRB5_KRB4_COMPAT
    int v4code = 0;
    int v4 = 1;
#endif
    int errflg = 0;
    int quiet = 0;
    struct krpc_revauth desarg;
    static  rpc_gss_OID_desc oid=
	{9, "\052\206\110\206\367\022\001\002\002"};

    static  rpc_gss_OID krb5_mech_type = &oid;

    int use_k5 = 0;
    int use_k4 = 0;

    progname = GET_PROGNAME(argv[0]);
    /* set locale and domain for internationalization */
    (void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif /* !TEXT_DOMAIN */

    (void) textdomain(TEXT_DOMAIN);

    got_k5 = 1;
#ifdef KRB5_KRB4_COMPAT
    got_k4 = 1;
#endif

    while ((c = getopt(argc, argv, "54qc:")) != -1) {
	switch (c) {
	case 'q':
	    quiet = 1;
	    break;
	case 'c':
	    if (cache_name) {
		fprintf(stderr, gettext("Only one -c option allowed\n"));
		errflg++;
	    } else {
		cache_name = optarg;
	    }
	    break;
	case '4':
	    if (!got_k4)
	    {
#ifdef KRB5_KRB4_COMPAT
		fprintf(stderr, "Kerberos 4 support could not be loaded\n");
#else
		fprintf(stderr, gettext("This was not built with Kerberos 4 support\n"));
#endif
		exit(3);
	    }
	    use_k4 = 1;
	    break;
	case '5':
	    if (!got_k5)
	    {
		fprintf(stderr, gettext("Kerberos 5 support could not be loaded\n"));
		exit(3);
	    }
	    use_k5 = 1;
	    break;
	case '?':
	default:
	    errflg++;
	    break;
	}
    }

    if (optind != argc)
	errflg++;

    if (errflg) {
	usage();
    }

    if (!use_k5 && !use_k4)
    {
	use_k5 = default_k5;
	use_k4 = default_k4;
    }

    if (!use_k5)
	got_k5 = 0;
    if (!use_k4)
	got_k4 = 0;

    if (got_k5) {
	retval = krb5_init_context(&kcontext);
	if (retval) {
	    com_err(progname, retval, gettext("while initializing krb5"));
	    exit(1);
	}

    	/*
     	 *  Solaris Kerberos
     	 *  Let us destroy the kernel cache first
     	 */
    	desarg.version = 1;
    	desarg.uid_1 = geteuid();
    	desarg.rpcsec_flavor_1 = RPCSEC_GSS;
    	desarg.flavor_data_1 = (void *) krb5_mech_type;
    	code = krpc_sys(KRPC_REVAUTH, (void *)&desarg);

    	if (code != 0) {
        	fprintf(stderr,
            		gettext("%s: kernel creds cache error %d \n"),
            		progname, code);
    	}

    	if (cache == NULL) {
        	if (code = krb5_cc_default(kcontext, &cache)) {
            	com_err(progname, code,
                	gettext("while getting default ccache"));
            	exit(1);
        	}
    	}

	if (cache_name) {
#ifdef KRB5_KRB4_COMPAT
	    v4 = 0;	/* Don't do v4 if doing v5 and cache name given. */
#endif
	    code = krb5_cc_resolve (kcontext, cache_name, &cache);
	    if (code != 0) {
		com_err (progname, code, gettext("while resolving %s"), cache_name);
		exit(1);
	    }
	} else {
	    code = krb5_cc_default(kcontext, &cache);
	    if (code) {
		com_err(progname, code, gettext("while getting default ccache"));
		exit(1);
	    }
	}

	/*
	 * Solaris Kerberos
         * Get client name for kwarn_del_warning.
	 */
        code = krb5_cc_get_principal(kcontext, cache, &me);
        if (code != 0)
            fprintf(stderr, gettext
                ("%s: Could not obtain principal name from cache\n"), progname);
        else
            if ((code = krb5_unparse_name(kcontext, me, &client_name)))
                fprintf(stderr, gettext
                    ("%s: Could not unparse principal name found in cache\n"), progname);

	code = krb5_cc_destroy (kcontext, cache);
	if (code != 0) {
	    com_err (progname, code, gettext("while destroying cache"));
	    if (code != KRB5_FCC_NOFILE) {
		if (quiet)
		    fprintf(stderr, gettext("Ticket cache NOT destroyed!\n"));
		else {
		    fprintf(stderr, gettext("Ticket cache %cNOT%c destroyed!\n"),
			    BELL_CHAR, BELL_CHAR);
		}
		errflg = 1;
	    }
	}
    }
#ifdef KRB5_KRB4_COMPAT
    if (got_k4 && v4) {
	v4code = dest_tkt();
	if (v4code == KSUCCESS && code != 0)
	    fprintf(stderr, "Kerberos 4 ticket cache destroyed.\n");
	if (v4code != KSUCCESS && v4code != RET_TKFIL) {
	    if (quiet)
		fprintf(stderr, "Kerberos 4 ticket cache NOT destroyed!\n");
	    else
		fprintf(stderr, "Kerberos 4 ticket cache %cNOT%c destroyed!\n",
			BELL_CHAR, BELL_CHAR);
	    errflg = 1;
	}
    }
#endif

    /* Solaris Kerberos */
    if (!errflg && client_name)
        kwarn_del_warning(client_name);
    else
        fprintf(stderr, gettext
            ("%s: TGT expire warning NOT deleted\n"), progname);

    return errflg;
}
