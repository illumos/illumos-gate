/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * clients/kinit/kinit.c
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
 * Initialize a credentials cache.
 */
#include <k5-int.h>
#include <profile/prof_int.h>
#include <com_err.h>
#include <libintl.h>

#include <krb5.h>
#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#define HAVE_KRB524
#else
#undef HAVE_KRB524
#endif
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <com_err.h>
#include <netdb.h>
#include <locale.h>

#ifdef GETOPT_LONG
#include <getopt.h>
#else
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#ifdef sun
/* SunOS4 unistd didn't declare these; okay to make unconditional?  */
extern int optind;
extern char *optarg;
#endif /* sun */
#else
extern int optind;
extern char *optarg;
extern int getopt();
#endif /* HAVE_UNISTD_H */
#endif /* GETOPT_LONG */

#ifndef _WIN32
#define GET_PROGNAME(x) (strrchr((x), '/') ? strrchr((x), '/')+1 : (x))
#else
#define GET_PROGNAME(x) max(max(strrchr((x), '/'), strrchr((x), '\\')) + 1,(x))
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
static
char * get_name_from_os()
{
    struct passwd *pw;
    if ((pw = getpwuid((int) getuid())))
	return pw->pw_name;
    return 0;
}
#else /* HAVE_PWD_H */
#ifdef _WIN32
static
char * get_name_from_os()
{
    static char name[1024];
    DWORD name_size = sizeof(name);
    if (GetUserName(name, &name_size)) {
	name[sizeof(name)-1] = 0; /* Just to be extra safe */
	return name;
    } else {
	return 0;
    }
}
#else /* _WIN32 */
static
char * get_name_from_os()
{
    return 0;
}
#endif /* _WIN32 */
#endif /* HAVE_PWD_H */

static char* progname_v5 = 0;
#ifdef KRB5_KRB4_COMPAT
static char* progname_v4 = 0;
static char* progname_v524 = 0;
#endif
#include <locale.h>

static int got_k5 = 0;
static int got_k4 = 0;

static int default_k5 = 1;
#if defined(KRB5_KRB4_COMPAT) && defined(KINIT_DEFAULT_BOTH)
static int default_k4 = 1;
#else
static int default_k4 = 0;
#endif

static int authed_k5 = 0;
static int authed_k4 = 0;

#define KRB4_BACKUP_DEFAULT_LIFE_SECS 24*60*60 /* 1 day */
#define	ROOT_UNAME	"root"

typedef enum { INIT_PW, INIT_KT, RENEW, VALIDATE } action_type;

struct k_opts
{
    /* in seconds */
    krb5_deltat starttime;
    krb5_deltat lifetime;
    krb5_deltat rlife;

    int forwardable;
    int proxiable;
    int addresses;

    int not_forwardable;
    int not_proxiable;
    int no_addresses;

    int verbose;

    char* principal_name;
    char* service_name;
    char* keytab_name;
    char* k5_cache_name;
    char* k4_cache_name;

    action_type action;

    int num_pa_opts;
    krb5_gic_opt_pa_data *pa_opts;
};

int	forwardable_flag = 0;
int	renewable_flag = 0;
int	proxiable_flag = 0;
int	no_address_flag = 0;
profile_options_boolean	config_option[] = {
	{ "forwardable",	&forwardable_flag,	0 },
	{ "renewable",		&renewable_flag,	0 },
	{ "proxiable",		&proxiable_flag,	0 },
	{ "no_addresses",	&no_address_flag,	0 },
	{ NULL,			NULL,			0 }
};

char	*renew_timeval=NULL;
char	*life_timeval=NULL;
int	lifetime_specified;
int	renewtime_specified;
profile_option_strings	config_times[] = {
	{ "max_life",		&life_timeval,	0 },
	{ "max_renewable_life",	&renew_timeval,	0 },
	{ NULL,			NULL,		0 }
};

struct k5_data
{
    krb5_context ctx;
    krb5_ccache cc;
    krb5_principal me;
    char* name;
};

struct k4_data
{
    krb5_deltat lifetime;
#ifdef KRB5_KRB4_COMPAT
    char aname[ANAME_SZ + 1];
    char inst[INST_SZ + 1];
    char realm[REALM_SZ + 1];
    char name[ANAME_SZ + 1 + INST_SZ + 1 + REALM_SZ + 1];
#endif
};

char	*realmdef[] = { "realms", NULL, "kinit", NULL };
char	*appdef[] = { "appdefaults", "kinit", NULL };

#define	krb_realm		(*(realmdef + 1))

#define	lifetime_specified	config_times[0].found
#define	renewtime_specified	config_times[1].found

/*
 * Try no preauthentication first; then try the encrypted timestamp
 */
krb5_preauthtype * preauth = NULL;
krb5_preauthtype preauth_list[2] = { 0, -1 };

static void _kwarnd_add_warning(char *, char *, time_t);
static void _kwarnd_del_warning(char *, char *);

#ifdef GETOPT_LONG
/* if struct[2] == NULL, then long_getopt acts as if the short flag
   struct[3] was specified.  If struct[2] != NULL, then struct[3] is
   stored in *(struct[2]), the array index which was specified is
   stored in *index, and long_getopt() returns 0. */

struct option long_options[] = {
    { "noforwardable", 0, NULL, 'F' },
    { "noproxiable", 0, NULL, 'P' },
    { "addresses", 0, NULL, 'a'},
    { "forwardable", 0, NULL, 'f' },
    { "proxiable", 0, NULL, 'p' },
    { "noaddresses", 0, NULL, 'A' },
    { NULL, 0, NULL, 0 }
};

#define GETOPT(argc, argv, str) getopt_long(argc, argv, str, long_options, 0)
#else
#define GETOPT(argc, argv, str) getopt(argc, argv, str)
#endif

static void
usage(progname)
     char *progname;
{
#define USAGE_BREAK "\n\t"

#ifdef GETOPT_LONG
#define USAGE_LONG_FORWARDABLE " | --forwardable | --noforwardable"
#define USAGE_LONG_PROXIABLE   " | --proxiable | --noproxiable"
#define USAGE_LONG_ADDRESSES   " | --addresses | --noaddresses"
#define USAGE_BREAK_LONG       USAGE_BREAK
#else
#define USAGE_LONG_FORWARDABLE ""
#define USAGE_LONG_PROXIABLE   ""
#define USAGE_LONG_ADDRESSES   ""
#define USAGE_BREAK_LONG       ""
#endif

    fprintf(stderr, "%s : %s  [-V] "
	    "[-l lifetime] [-s start_time] "
	    USAGE_BREAK
	    "[-r renewable_life] "
	    "[-f | -F" USAGE_LONG_FORWARDABLE "] "
	    USAGE_BREAK_LONG
	    "[-p | -P" USAGE_LONG_PROXIABLE "] "
	    USAGE_BREAK_LONG
	    "[-a | -A" USAGE_LONG_ADDRESSES "] "
	    USAGE_BREAK
	    "[-v] [-R] "
	    "[-k [-t keytab_file]] "
	    "[-c cachename] "
	    USAGE_BREAK
	    "[-S service_name]"
	    "[-X <attribute>[=<value>]] [principal]"
	    "\n\n",
	    gettext("Usage"), progname);

#define KRB_AVAIL_STRING(x) ((x)?gettext("available"):gettext("not available"))

#define OPTTYPE_KRB5   "5"
#define OPTTYPE_KRB4   "4"
#define OPTTYPE_EITHER "Either 4 or 5"
#ifdef HAVE_KRB524
#define OPTTYPE_BOTH "5, or both 5 and 4"
#else
#define OPTTYPE_BOTH "5"
#endif

#ifdef KRB5_KRB4_COMPAT
#define USAGE_OPT_FMT "%s%-50s%s\n"
#define ULINE(indent, col1, col2) \
fprintf(stderr, USAGE_OPT_FMT, indent, col1, col2)
#else
#define USAGE_OPT_FMT "%s%s\n"
#define ULINE(indent, col1, col2) \
fprintf(stderr, USAGE_OPT_FMT, indent, col1)
#endif

    ULINE("    ", "options:", "valid with Kerberos:");
    fprintf(stderr, "\t-5 Kerberos 5 (%s)\n", KRB_AVAIL_STRING(got_k5));
    fprintf(stderr, "\t-4 Kerberos 4 (%s)\n", KRB_AVAIL_STRING(got_k4));
    fprintf(stderr, "\t   (Default behavior is to try %s%s%s%s)\n",
	    default_k5?"Kerberos 5":"",
	    (default_k5 && default_k4)?gettext(" and "):"",
	    default_k4?"Kerberos 4":"",
	    (!default_k5 && !default_k4)?gettext("neither"):"");
    ULINE("\t", gettext("-V verbose"),                   OPTTYPE_EITHER);
    ULINE("\t", gettext("-l lifetime"),                  OPTTYPE_EITHER);
    ULINE("\t", gettext("-s start time"),                OPTTYPE_KRB5);
    ULINE("\t", gettext("-r renewable lifetime"),        OPTTYPE_KRB5);
    ULINE("\t", gettext("-f forwardable"),               OPTTYPE_KRB5);
    ULINE("\t", gettext("-F not forwardable"),           OPTTYPE_KRB5);
    ULINE("\t", gettext("-p proxiable"),                 OPTTYPE_KRB5);
    ULINE("\t", gettext("-P not proxiable"),             OPTTYPE_KRB5);
    ULINE("\t", gettext("-A do not include addresses"),  OPTTYPE_KRB5);
    ULINE("\t", gettext("-a include addresses"),         OPTTYPE_KRB5);
    ULINE("\t", gettext("-v validate"),                  OPTTYPE_KRB5);
    ULINE("\t", gettext("-R renew"),                     OPTTYPE_BOTH);
    ULINE("\t", gettext("-k use keytab"),                OPTTYPE_BOTH);
    ULINE("\t", gettext("-t filename of keytab to use"), OPTTYPE_BOTH);
    ULINE("\t", gettext("-c Kerberos 5 cache name"),     OPTTYPE_KRB5);
    /* This options is not yet available: */
    /* ULINE("\t", "-C Kerberos 4 cache name",     OPTTYPE_KRB4); */
    ULINE("\t", gettext("-S service"),                   OPTTYPE_BOTH);
    ULINE("\t", gettext("-X <attribute>[=<value>]"),     OPTTYPE_KRB5);
    exit(2);
}

static krb5_context errctx;
static void extended_com_err_fn (const char *myprog, errcode_t code,
				 const char *fmt, va_list args)
{
    const char *emsg;
    emsg = krb5_get_error_message (errctx, code);
    fprintf (stderr, "%s: %s ", myprog, emsg);
    krb5_free_error_message (errctx, emsg);
    vfprintf (stderr, fmt, args);
    fprintf (stderr, "\n");
}

static int
add_preauth_opt(struct k_opts *opts, char *av)
{
    char *sep, *v;
    krb5_gic_opt_pa_data *p, *x;

    if (opts->num_pa_opts == 0) {
	opts->pa_opts = malloc(sizeof(krb5_gic_opt_pa_data));
	if (opts->pa_opts == NULL)
	    return ENOMEM;
    } else {
	size_t newsize = (opts->num_pa_opts + 1) * sizeof(krb5_gic_opt_pa_data);
	x = realloc(opts->pa_opts, newsize);
	if (x == NULL)
	    return ENOMEM;
	opts->pa_opts = x;
    }
    p = &opts->pa_opts[opts->num_pa_opts];
    sep = strchr(av, '=');
    if (sep) {
	*sep = '\0';
	v = ++sep;
	p->value = v;
    } else {
	p->value = "yes";
    }
    p->attr = av;
    opts->num_pa_opts++;
    return 0;
}

static char *
parse_options(argc, argv, opts, progname)
    int argc;
    char **argv;
    struct k_opts* opts;
    char *progname;
{
    krb5_error_code code;
    int errflg = 0;
    int use_k4 = 0;
    int use_k5 = 0;
    int i;

    while ((i = GETOPT(argc, argv, "r:fpFP54aAVl:s:c:kt:RS:vX:"))
	   != -1) {
	switch (i) {
	case 'V':
	    opts->verbose = 1;
	    break;
	case 'l':
	    /* Lifetime */
	    code = krb5_string_to_deltat(optarg, &opts->lifetime);
	    if (code != 0 || opts->lifetime == 0) {
		fprintf(stderr, gettext("Bad lifetime value %s\n"), optarg);
		errflg++;
	    }
	    break;
	case 'r':
	    /* Renewable Time */
	    code = krb5_string_to_deltat(optarg, &opts->rlife);
	    if (code != 0 || opts->rlife == 0) {
		fprintf(stderr, gettext("Bad lifetime value %s\n"), optarg);
		errflg++;
	    }
	    break;
	case 'f':
	    opts->forwardable = 1;
	    break;
	case 'F':
	    opts->not_forwardable = 1;
	    break;
	case 'p':
	    opts->proxiable = 1;
	    break;
	case 'P':
	    opts->not_proxiable = 1;
	    break;
	case 'a':
	    /* Note: This is supported only with GETOPT_LONG */
	    opts->addresses = 1;
	    break;
	case 'A':
	    opts->no_addresses = 1;
	    break;
       	case 's':
	    code = krb5_string_to_deltat(optarg, &opts->starttime);
	    if (code != 0 || opts->starttime == 0) {
		krb5_timestamp abs_starttime;

		code = krb5_string_to_timestamp(optarg, &abs_starttime);
		if (code != 0 || abs_starttime == 0) {
		    fprintf(stderr, gettext("Bad start time value %s\n"), optarg);
		    errflg++;
		} else {
		    opts->starttime = abs_starttime - time(0);
		}
	    }
	    break;
	case 'S':
	    opts->service_name = optarg;
	    break;
	case 'k':
	    opts->action = INIT_KT;
	    break;
	case 't':
	    if (opts->keytab_name)
	    {
		fprintf(stderr, gettext("Only one -t option allowed.\n"));
		errflg++;
	    } else {
		opts->keytab_name = optarg;
	    }
	    break;
	case 'R':
	    opts->action = RENEW;
	    break;
	case 'v':
	    opts->action = VALIDATE;
	    break;
       	case 'c':
	    if (opts->k5_cache_name)
	    {
		fprintf(stderr, gettext("Only one -c option allowed\n"));
		errflg++;
	    } else {
		opts->k5_cache_name = optarg;
	    }
	    break;
	case 'X':
	    code = add_preauth_opt(opts, optarg);
	    if (code)
	    {
		com_err(progname, code, "while adding preauth option");
		errflg++;
	    }
	    break;
#if 0
	    /*
	      A little more work is needed before we can enable this
	      option.
	    */
	case 'C':
	    if (opts->k4_cache_name)
	    {
		fprintf(stderr, "Only one -C option allowed\n");
		errflg++;
	    } else {
		opts->k4_cache_name = optarg;
	    }
	    break;
#endif
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
	default:
	    errflg++;
	    break;
	}
    }

    if (opts->forwardable && opts->not_forwardable)
    {
	fprintf(stderr, gettext("Only one of -f and -F allowed\n"));
	errflg++;
    }
    if (opts->proxiable && opts->not_proxiable)
    {
	fprintf(stderr, gettext("Only one of -p and -P allowed\n"));
	errflg++;
    }
    if (opts->addresses && opts->no_addresses)
    {
	fprintf(stderr, gettext("Only one of -a and -A allowed\n"));
	errflg++;
    }

    if (argc - optind > 1) {
	fprintf(stderr, gettext("Extra arguments (starting with \"%s\").\n"),
		argv[optind+1]);
	errflg++;
    }

    /* At this point, if errorless, we know we only have one option
       selection */
    if (!use_k5 && !use_k4) {
	use_k5 = default_k5;
	use_k4 = default_k4;
    }

    /* Now, we encode the OPTTYPE stuff here... */
    if (!use_k5 &&
	(opts->starttime || opts->rlife || opts->forwardable ||
	 opts->proxiable || opts->addresses || opts->not_forwardable ||
	 opts->not_proxiable || opts->no_addresses ||
	 (opts->action == VALIDATE) || opts->k5_cache_name))
    {
	fprintf(stderr, gettext("Specified option that requires Kerberos 5\n"));
	errflg++;
    }
    if (!use_k4 &&
	opts->k4_cache_name)
    {
	fprintf(stderr, gettext("Specified option that require Kerberos 4\n"));
	errflg++;
    }
    if (
#ifdef HAVE_KRB524
	!use_k5
#else
	use_k4
#endif
	&& (opts->service_name || opts->keytab_name ||
	    (opts->action == INIT_KT) || (opts->action == RENEW))
	)
    {
	fprintf(stderr, gettext("Specified option that requires Kerberos 5\n"));
	errflg++;
    }

    if (errflg) {
	usage(progname);
    }

    got_k5 = got_k5 && use_k5;
    got_k4 = got_k4 && use_k4;

    opts->principal_name = (optind == argc-1) ? argv[optind] : 0;
    return opts->principal_name;
}

static int
k5_begin(opts, k5, k4)
    struct k_opts* opts;
struct k5_data* k5;
struct k4_data* k4;
{
    char* progname = progname_v5;
    krb5_error_code code = 0;

    if (!got_k5)
	return 0;

    code = krb5_init_context(&k5->ctx);
    if (code) {
	com_err(progname, code, gettext("while initializing Kerberos 5 library"));
	return 0;
    }
    errctx = k5->ctx;
    if (opts->k5_cache_name)
    {
	code = krb5_cc_resolve(k5->ctx, opts->k5_cache_name, &k5->cc);
	if (code != 0) {
	    com_err(progname, code, gettext("resolving ccache %s"),
		    opts->k5_cache_name);
	    return 0;
	}
    }
    else
    {
	if ((code = krb5_cc_default(k5->ctx, &k5->cc))) {
	    com_err(progname, code, gettext("while getting default ccache"));
	    return 0;
	}
    }

    if (opts->principal_name)
    {
	/* Use specified name */
	if ((code = krb5_parse_name(k5->ctx, opts->principal_name,
				    &k5->me))) {
	    com_err(progname, code, gettext("when parsing name %s"),
		    opts->principal_name);
	    return 0;
	}
    }
    else
    {
	/* No principal name specified */
	if (opts->action == INIT_KT) {
	    /* Use the default host/service name */
	  code = krb5_sname_to_principal(k5->ctx, NULL, NULL,
					 KRB5_NT_SRV_HST, &k5->me);
	  if (code) {
	    com_err(progname, code, gettext(
		    "when creating default server principal name"));
	    return 0;
	  }
	} else {
	  /* Get default principal from cache if one exists */
	  code = krb5_cc_get_principal(k5->ctx, k5->cc,
				       &k5->me);
	  if (code)
	    {
	      char *name = get_name_from_os();
	      if (!name)
		{
		  fprintf(stderr, gettext("Unable to identify user\n"));
		  return 0;
		}
                /* use strcmp to ensure only "root" is matched */
                if (strcmp(name, ROOT_UNAME) == 0)
                {
                	if (code = krb5_sname_to_principal(k5->ctx, NULL, ROOT_UNAME,
				    KRB5_NT_SRV_HST, &k5->me)) {
			    com_err(progname, code, gettext(
				"when creating default server principal name"));
                                return 0;
                        }
                } else
	      if ((code = krb5_parse_name(k5->ctx, name,
					  &k5->me)))
		{
		  com_err(progname, code, gettext("when parsing name %s"),
			  name);
		  return 0;
		}
	    }
	}
    }

    code = krb5_unparse_name(k5->ctx, k5->me, &k5->name);
    if (code) {
	com_err(progname, code, gettext("when unparsing name"));
	return 0;
    }
    opts->principal_name = k5->name;

#ifdef KRB5_KRB4_COMPAT
    if (got_k4)
    {
	/* Translate to a Kerberos 4 principal */
	code = krb5_524_conv_principal(k5->ctx, k5->me,
				       k4->aname, k4->inst, k4->realm);
	if (code) {
	    k4->aname[0] = 0;
	    k4->inst[0] = 0;
	    k4->realm[0] = 0;
	}
    }
#endif
    return 1;
}

static void
k5_end(k5)
    struct k5_data* k5;
{
    if (k5->name)
	krb5_free_unparsed_name(k5->ctx, k5->name);
    if (k5->me)
	krb5_free_principal(k5->ctx, k5->me);
    if (k5->cc)
	krb5_cc_close(k5->ctx, k5->cc);
    if (k5->ctx)
	krb5_free_context(k5->ctx);
    errctx = NULL;
    memset(k5, 0, sizeof(*k5));
}

static int
k4_begin(opts, k4)
    struct k_opts* opts;
    struct k4_data* k4;
{
#ifdef KRB5_KRB4_COMPAT
    char* progname = progname_v4;
    int k_errno = 0;
#endif

    if (!got_k4)
	return 0;

#ifdef KRB5_KRB4_COMPAT
    if (k4->aname[0])
	goto skip;

    if (opts->principal_name)
    {
	/* Use specified name */
        k_errno = kname_parse(k4->aname, k4->inst, k4->realm,
			      opts->principal_name);
	if (k_errno)
	{
	    fprintf(stderr, "%s: %s\n", progname,
		    krb_get_err_text(k_errno));
	    return 0;
	}
    } else {
	/* No principal name specified */
	if (opts->action == INIT_KT) {
	    /* Use the default host/service name */
	    /* XXX - need to add this functionality */
	    fprintf(stderr, "%s: Kerberos 4 srvtab support is not "
		    "implemented\n", progname);
	    return 0;
	} else {
	    /* Get default principal from cache if one exists */
	    k_errno = krb_get_tf_fullname(tkt_string(), k4->aname,
					  k4->inst, k4->realm);
	    if (k_errno)
	    {
		char *name = get_name_from_os();
		if (!name)
		{
		    fprintf(stderr, "Unable to identify user\n");
		    return 0;
		}
		k_errno = kname_parse(k4->aname, k4->inst, k4->realm,
				      name);
		if (k_errno)
		{
		    fprintf(stderr, "%s: %s\n", progname,
			    krb_get_err_text(k_errno));
		    return 0;
		}
	    }
	}
    }

    if (!k4->realm[0])
	krb_get_lrealm(k4->realm, 1);

    if (k4->inst[0])
	sprintf(k4->name, "%s.%s@%s", k4->aname, k4->inst, k4->realm);
    else
	sprintf(k4->name, "%s@%s", k4->aname, k4->realm);
    opts->principal_name = k4->name;

 skip:
    if (k4->aname[0] && !k_isname(k4->aname))
    {
	fprintf(stderr, "%s: bad Kerberos 4 name format\n", progname);
	return 0;
    }

    if (k4->inst[0] && !k_isinst(k4->inst))
    {
	fprintf(stderr, "%s: bad Kerberos 4 instance format\n", progname);
	return 0;
    }

    if (k4->realm[0] && !k_isrealm(k4->realm))
    {
	fprintf(stderr, "%s: bad Kerberos 4 realm format\n", progname);
	return 0;
    }
#endif /* KRB5_KRB4_COMPAT */
    return 1;
}

static void
k4_end(k4)
    struct k4_data* k4;
{
    memset(k4, 0, sizeof(*k4));
}

#ifdef KRB5_KRB4_COMPAT
static char stash_password[1024];
static int got_password = 0;
#endif /* KRB5_KRB4_COMPAT */

static krb5_error_code
KRB5_CALLCONV
kinit_prompter(
    krb5_context ctx,
    void *data,
    const char *name,
    const char *banner,
    int num_prompts,
    krb5_prompt prompts[]
    )
{
    int i;
    krb5_prompt_type *types;
    krb5_error_code rc =
	krb5_prompter_posix(ctx, data, name, banner, num_prompts, prompts);
    if (!rc && (types = krb5_get_prompt_types(ctx)))
	for (i = 0; i < num_prompts; i++)
	    if ((types[i] == KRB5_PROMPT_TYPE_PASSWORD) ||
		(types[i] == KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN))
	    {
#ifdef KRB5_KRB4_COMPAT
		strncpy(stash_password, prompts[i].reply->data,
			sizeof(stash_password));
		got_password = 1;
#endif
	    }
    return rc;
}

static int
k5_kinit(opts, k5)
    struct k_opts* opts;
    struct k5_data* k5;
{
    char* progname = progname_v5;
    int notix = 1;
    krb5_keytab keytab = 0;
    krb5_creds my_creds;
    krb5_error_code code = 0;
    krb5_get_init_creds_opt *options = NULL;
    int i;
    krb5_timestamp now;
    krb5_deltat lifetime = 0, rlife = 0, krb5_max_duration;

    if (!got_k5)
	return 0;

    code = krb5_get_init_creds_opt_alloc(k5->ctx, &options);
    if (code)
	goto cleanup;
    memset(&my_creds, 0, sizeof(my_creds));

    /*
     * Solaris Kerberos: added support for max_life and max_renewable_life
     * which should be removed in the next minor release.  See PSARC 2003/545
     * for more info.
     *
     * Also, check krb5.conf for proxiable/forwardable/renewable/no_address
     * parameter values.
     */
    /* If either tkt life or renew life weren't set earlier take common steps to
     * get the krb5.conf parameter values.
     */

    if ((code = krb5_timeofday(k5->ctx, &now))) {
	    com_err(progname, code, gettext("while getting time of day"));
	    exit(1);
    }
    krb5_max_duration = KRB5_KDB_EXPIRATION - now - 60*60;

    if (opts->lifetime == 0 || opts->rlife == 0) {

	krb_realm = krb5_princ_realm(k5->ctx, k5->me)->data;
	/* realm params take precedence */
	profile_get_options_string(k5->ctx->profile, realmdef, config_times);
	profile_get_options_string(k5->ctx->profile, appdef, config_times);

	/* if the input opts doesn't have lifetime set and the krb5.conf
	 * parameter has been set, use that.
	 */
	if (opts->lifetime == 0 && life_timeval != NULL) {
	    code = krb5_string_to_deltat(life_timeval, &lifetime);
	    if (code != 0 || lifetime == 0 || lifetime > krb5_max_duration) {
		fprintf(stderr, gettext("Bad max_life "
			    "value in Kerberos config file %s\n"),
			life_timeval);
		exit(1);
	    }
	    opts->lifetime = lifetime;
	}
	if (opts->rlife == 0 && renew_timeval != NULL) {
	    code = krb5_string_to_deltat(renew_timeval, &rlife);
	    if (code != 0 || rlife == 0 || rlife > krb5_max_duration) {
		fprintf(stderr, gettext("Bad max_renewable_life "
			    "value in Kerberos config file %s\n"),
			renew_timeval);
		exit(1);
	    }
	    opts->rlife = rlife;
	}
    }

    /*
     * If lifetime is not set on the cmdline or in the krb5.conf
     * file, default to max.
     */
    if (opts->lifetime == 0)
	    opts->lifetime = krb5_max_duration;


    profile_get_options_boolean(k5->ctx->profile,
				realmdef, config_option);
    profile_get_options_boolean(k5->ctx->profile,
				appdef, config_option);


    /* cmdline opts take precedence over krb5.conf file values */
    if (!opts->not_proxiable && proxiable_flag) {
	    krb5_get_init_creds_opt_set_proxiable(options, 1);
    }
    if (!opts->not_forwardable && forwardable_flag) {
	    krb5_get_init_creds_opt_set_forwardable(options, 1);
    }
    if (renewable_flag) {
	    /*
	     * If this flag is set in krb5.conf, but rlife is 0, then
	     * set it to the max (and let the KDC sort it out).
	     */
	    opts->rlife = opts->rlife ? opts->rlife : krb5_max_duration;
    }
    if (no_address_flag) {
	    /* cmdline opts will overwrite this below if needbe */
	    krb5_get_init_creds_opt_set_address_list(options, NULL);
    }


    /*
      From this point on, we can goto cleanup because my_creds is
      initialized.
    */

    if (opts->lifetime)
	krb5_get_init_creds_opt_set_tkt_life(options, opts->lifetime);
    if (opts->rlife)
	krb5_get_init_creds_opt_set_renew_life(options, opts->rlife);
    if (opts->forwardable)
	krb5_get_init_creds_opt_set_forwardable(options, 1);
    if (opts->not_forwardable)
	krb5_get_init_creds_opt_set_forwardable(options, 0);
    if (opts->proxiable)
	krb5_get_init_creds_opt_set_proxiable(options, 1);
    if (opts->not_proxiable)
	krb5_get_init_creds_opt_set_proxiable(options, 0);
    if (opts->addresses)
    {
	krb5_address **addresses = NULL;
	code = krb5_os_localaddr(k5->ctx, &addresses);
	if (code != 0) {
	    com_err(progname, code, gettext("getting local addresses"));
	    goto cleanup;
	}
	krb5_get_init_creds_opt_set_address_list(options, addresses);
    }
    if (opts->no_addresses)
	krb5_get_init_creds_opt_set_address_list(options, NULL);

    if ((opts->action == INIT_KT) && opts->keytab_name)
    {
	code = krb5_kt_resolve(k5->ctx, opts->keytab_name, &keytab);
	if (code != 0) {
	    com_err(progname, code, gettext("resolving keytab %s"),
		    opts->keytab_name);
	    goto cleanup;
	}
    }

    for (i = 0; i < opts->num_pa_opts; i++) {
	code = krb5_get_init_creds_opt_set_pa(k5->ctx, options,
					      opts->pa_opts[i].attr,
					      opts->pa_opts[i].value);
	if (code != 0) {
	    com_err(progname, code, "while setting '%s'='%s'",
		    opts->pa_opts[i].attr, opts->pa_opts[i].value);
	    goto cleanup;
	}
    }

    switch (opts->action) {
    case INIT_PW:
	code = krb5_get_init_creds_password(k5->ctx, &my_creds, k5->me,
					    0, kinit_prompter, 0,
					    opts->starttime,
					    opts->service_name,
					    options);
	break;
    case INIT_KT:
	code = krb5_get_init_creds_keytab(k5->ctx, &my_creds, k5->me,
					  keytab,
					  opts->starttime,
					  opts->service_name,
					  options);
	break;
    case VALIDATE:
	code = krb5_get_validated_creds(k5->ctx, &my_creds, k5->me, k5->cc,
					opts->service_name);
	break;
    case RENEW:
	code = krb5_get_renewed_creds(k5->ctx, &my_creds, k5->me, k5->cc,
				      opts->service_name);
	break;
    }

    if (code) {
	char *doing = 0;
	switch (opts->action) {
	case INIT_PW:
	case INIT_KT:
	    doing = gettext("getting initial credentials");
	    break;
	case VALIDATE:
	    doing = gettext("validating credentials");
	    break;
	case RENEW:
	    doing = gettext("renewing credentials");
	    break;
	}

	/* If got code == KRB5_AP_ERR_V4_REPLY && got_k4, we should
	   let the user know that maybe he/she wants -4. */
	if (code == KRB5KRB_AP_ERR_V4_REPLY && got_k4)
	    com_err(progname, code, "while %s\n"
		    "The KDC doesn't support v5.  "
		    "You may want the -4 option in the future",
		    doing);
	else if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
	    fprintf(stderr, gettext("%s: Password incorrect while %s\n"), progname,
		    doing);
	else
	    com_err(progname, code, gettext("while %s"), doing);
	goto cleanup;
    }

    if (!opts->lifetime) {
	/* We need to figure out what lifetime to use for Kerberos 4. */
	opts->lifetime = my_creds.times.endtime - my_creds.times.authtime;
    }

    code = krb5_cc_initialize(k5->ctx, k5->cc, k5->me);
    if (code) {
	com_err(progname, code, gettext("when initializing cache %s"),
		opts->k5_cache_name?opts->k5_cache_name:"");
	goto cleanup;
    }

    code = krb5_cc_store_cred(k5->ctx, k5->cc, &my_creds);
    if (code) {
	com_err(progname, code, gettext("while storing credentials"));
	goto cleanup;
    }

    if (opts->action == RENEW) {
        _kwarnd_del_warning(progname, opts->principal_name);
        _kwarnd_add_warning(progname, opts->principal_name, my_creds.times.endtime);
    } else if ((opts->action == INIT_KT) || (opts->action == INIT_PW)) {
        _kwarnd_add_warning(progname, opts->principal_name, my_creds.times.endtime);
    }

    notix = 0;

 cleanup:
    if (options)
	krb5_get_init_creds_opt_free(k5->ctx, options);
    if (my_creds.client == k5->me) {
	my_creds.client = 0;
    }
    if (opts->pa_opts) {
	free(opts->pa_opts);
	opts->pa_opts = NULL;
	opts->num_pa_opts = 0;
    }
    krb5_free_cred_contents(k5->ctx, &my_creds);
    if (keytab)
	krb5_kt_close(k5->ctx, keytab);
    return notix?0:1;
}

static int
k4_kinit(opts, k4, ctx)
    struct k_opts* opts;
    struct k4_data* k4;
    krb5_context ctx;
{
#ifdef KRB5_KRB4_COMPAT
    char* progname = progname_v4;
    int k_errno = 0;
#endif

    if (!got_k4)
	return 0;

    if (opts->starttime)
	return 0;

#ifdef KRB5_KRB4_COMPAT
    if (!k4->lifetime)
	k4->lifetime = opts->lifetime;
    if (!k4->lifetime)
	k4->lifetime = KRB4_BACKUP_DEFAULT_LIFE_SECS;

    k4->lifetime = krb_time_to_life(0, k4->lifetime);

    switch (opts->action)
    {
    case INIT_PW:
	if (!got_password) {
	    unsigned int pwsize = sizeof(stash_password);
	    krb5_error_code code;
	    char prompt[1024];

	    sprintf(prompt, gettext("Password for %s: "), opts->principal_name);
	    stash_password[0] = 0;
	    /*
	      Note: krb5_read_password does not actually look at the
	      context, so we're ok even if we don't have a context.  If
	      we cannot dynamically load krb5, we can substitute any
	      decent read password function instead of the krb5 one.
	    */
	    code = krb5_read_password(ctx, prompt, 0, stash_password, &pwsize);
	    if (code || pwsize == 0)
	    {
		fprintf(stderr, gettext("Error while reading password for '%s'\n"),
			opts->principal_name);
		memset(stash_password, 0, sizeof(stash_password));
		return 0;
	    }
	    got_password = 1;
	}
	k_errno = krb_get_pw_in_tkt(k4->aname, k4->inst, k4->realm, "krbtgt",
				    k4->realm, k4->lifetime, stash_password);

	if (k_errno) {
	    fprintf(stderr, "%s: %s\n", progname,
		    krb_get_err_text(k_errno));
	    if (authed_k5)
	        fprintf(stderr, gettext("Maybe your KDC does not support v4.  "
			"Try the -5 option next time.\n"));
	    return 0;
	}
	return 1;
#ifndef HAVE_KRB524
    case INIT_KT:
	fprintf(stderr, gettext("%s: srvtabs are not supported\n"), progname);
	return 0;
    case RENEW:
	fprintf(stderr, gettext("%s: renewal of krb4 tickets is not supported\n"),
		progname);
	return 0;
#else
    /* These cases are handled by the 524 code - this prevents the compiler
       warnings of not using all the enumerated types.
    */
    case INIT_KT:
    case RENEW:
    case VALIDATE:
        return 0;
#endif
    }
#endif
    return 0;
}

static char*
getvprogname(v, progname)
    char *v, *progname;
{
    unsigned int len = strlen(progname) + 2 + strlen(v) + 2;
    char *ret = malloc(len);
    if (ret)
	sprintf(ret, "%s(v%s)", progname, v);
    else
	ret = progname;
    return ret;
}

#ifdef HAVE_KRB524
/* Convert krb5 tickets to krb4. */
static int try_convert524(k5)
    struct k5_data* k5;
{
    char * progname = progname_v524;
    krb5_error_code code = 0;
    int icode = 0;
    krb5_principal kpcserver = 0;
    krb5_creds *v5creds = 0;
    krb5_creds increds;
    CREDENTIALS v4creds;

    if (!got_k4 || !got_k5)
	return 0;

    memset((char *) &increds, 0, sizeof(increds));
    /*
      From this point on, we can goto cleanup because increds is
      initialized.
    */

    if ((code = krb5_build_principal(k5->ctx,
				     &kpcserver,
				     krb5_princ_realm(k5->ctx, k5->me)->length,
				     krb5_princ_realm(k5->ctx, k5->me)->data,
				     "krbtgt",
				     krb5_princ_realm(k5->ctx, k5->me)->data,
				     NULL))) {
	com_err(progname, code, gettext(
		"while creating service principal name"));
	goto cleanup;
    }

    increds.client = k5->me;
    increds.server = kpcserver;
    /* Prevent duplicate free calls.  */
    kpcserver = 0;

    increds.times.endtime = 0;
    increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    if ((code = krb5_get_credentials(k5->ctx, 0,
				     k5->cc,
				     &increds,
				     &v5creds))) {
	com_err(progname, code,
		gettext("getting V5 credentials"));
	goto cleanup;
    }
    if ((icode = krb524_convert_creds_kdc(k5->ctx,
					  v5creds,
					  &v4creds))) {
	com_err(progname, icode,
		gettext("converting to V4 credentials"));
	goto cleanup;
    }
    /* this is stolen from the v4 kinit */
    /* initialize ticket cache */
    if ((icode = in_tkt(v4creds.pname, v4creds.pinst)
	 != KSUCCESS)) {
	com_err(progname, icode, gettext(
		"trying to create the V4 ticket file"));
	goto cleanup;
    }
    /* stash ticket, session key, etc. for future use */
    if ((icode = krb_save_credentials(v4creds.service,
				      v4creds.instance,
				      v4creds.realm,
				      v4creds.session,
				      v4creds.lifetime,
				      v4creds.kvno,
				      &(v4creds.ticket_st),
				      v4creds.issue_date))) {
	com_err(progname, icode, gettext(
		"trying to save the V4 ticket"));
	goto cleanup;
    }

 cleanup:
    memset(&v4creds, 0, sizeof(v4creds));
    if (v5creds)
	krb5_free_creds(k5->ctx, v5creds);
    increds.client = 0;
    krb5_free_cred_contents(k5->ctx, &increds);
    if (kpcserver)
	krb5_free_principal(k5->ctx, kpcserver);
    return !(code || icode);
}
#endif /* HAVE_KRB524 */

int
main(argc, argv)
    int argc;
    char **argv;
{
    struct k_opts opts;
    struct k5_data k5;
    struct k4_data k4;
    char *progname;

    (void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

    (void) textdomain(TEXT_DOMAIN);

    progname = GET_PROGNAME(argv[0]);
    progname_v5 = getvprogname("5", progname);
#ifdef KRB5_KRB4_COMPAT
    progname_v4 = getvprogname("4", progname);
    progname_v524 = getvprogname("524", progname);
#endif

    /* Ensure we can be driven from a pipe */
    if(!isatty(fileno(stdin)))
	setvbuf(stdin, 0, _IONBF, 0);
    if(!isatty(fileno(stdout)))
	setvbuf(stdout, 0, _IONBF, 0);
    if(!isatty(fileno(stderr)))
	setvbuf(stderr, 0, _IONBF, 0);

    /*
      This is where we would put in code to dynamically load Kerberos
      libraries.  Currenlty, we just get them implicitly.
    */
    got_k5 = 1;
#ifdef KRB5_KRB4_COMPAT
    got_k4 = 1;
#endif

    memset(&opts, 0, sizeof(opts));
    opts.action = INIT_PW;

    memset(&k5, 0, sizeof(k5));
    memset(&k4, 0, sizeof(k4));

    set_com_err_hook (extended_com_err_fn);

    parse_options(argc, argv, &opts, progname);

    got_k5 = k5_begin(&opts, &k5, &k4);
    got_k4 = k4_begin(&opts, &k4);

    authed_k5 = k5_kinit(&opts, &k5);
#ifdef HAVE_KRB524
    if (authed_k5)
	authed_k4 = try_convert524(&k5);
#endif
    if (!authed_k4)
	authed_k4 = k4_kinit(&opts, &k4, k5.ctx);
#ifdef KRB5_KRB4_COMPAT
    memset(stash_password, 0, sizeof(stash_password));
#endif

    if (authed_k5 && opts.verbose)
	fprintf(stderr, gettext("Authenticated to Kerberos v5\n"));
    if (authed_k4 && opts.verbose)
	fprintf(stderr, gettext("Authenticated to Kerberos v4\n"));

    k5_end(&k5);
    k4_end(&k4);

    if ((got_k5 && !authed_k5) || (got_k4 && !authed_k4) ||
	(!got_k5 && !got_k4))
	exit(1);
    return 0;
}

static void
_kwarnd_add_warning(char *progname, char *me, time_t endtime)
{
    if (kwarn_add_warning(me, endtime) != 0)
        fprintf(stderr, gettext(
            "%s:  no ktkt_warnd warning possible\n"), progname);
    return;
}


static void
_kwarnd_del_warning(char *progname, char *me)
{
    if (kwarn_del_warning(me) != 0)
        fprintf(stderr, gettext(
            "%s:  unable to delete ktkt_warnd message for %s\n"),
            progname, me);
    return;
}
