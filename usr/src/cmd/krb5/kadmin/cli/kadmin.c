/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * kadmin.c: base functions for a kadmin command line interface using
 * the OVSecure library
 */

#include <krb5.h>
#include <k5-int.h>
#include <kadm5/admin.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <math.h>
#include <unistd.h>
#include <pwd.h>
/* #include <sys/timeb.h> */
#include <time.h>
#include <libintl.h>

/*
 * Solaris:  the following are needed for paging
 */
#include <signal.h>
#include <sys/wait.h>

/* command name when called "locally" (i.e. non-networked client ) */
#define KADMIN_LOCAL_NAME "kadmin.local"

/* functions defined in remote/local specific files */
extern void usage(const char *);
extern void debugEnable(int);

/* local principal helpers */
static char *find_component(const char *, char);
static char *trim_principal(char *);
static char *build_admin_princ(const char *, const char *);

/*
 * special struct to convert flag names for principals
 * to actual krb5_flags for a principal
 */
struct pflag {
    char *flagname;		/* name of flag as typed to CLI */
    int flaglen;		/* length of string (not counting -,+) */
    krb5_flags theflag;		/* actual principal flag to set/clear */
    int set;			/* 0 means clear, 1 means set (on '-') */
};

static struct pflag flags[] = {
{"allow_postdated",	15,	KRB5_KDB_DISALLOW_POSTDATED,	1},
{"allow_forwardable",	17,	KRB5_KDB_DISALLOW_FORWARDABLE,	1},
{"allow_tgs_req",	13,	KRB5_KDB_DISALLOW_TGT_BASED,	1},
{"allow_renewable",	15,	KRB5_KDB_DISALLOW_RENEWABLE,	1},
{"allow_proxiable",	15,	KRB5_KDB_DISALLOW_PROXIABLE,	1},
{"allow_dup_skey",	14,	KRB5_KDB_DISALLOW_DUP_SKEY,	1},
{"allow_tix",		9,	KRB5_KDB_DISALLOW_ALL_TIX,	1},
{"requires_preauth",	16,	KRB5_KDB_REQUIRES_PRE_AUTH,	0},
{"requires_hwauth",	15,	KRB5_KDB_REQUIRES_HW_AUTH,	0},
{"needchange",		10,	KRB5_KDB_REQUIRES_PWCHANGE,	0},
{"allow_svr",		9,	KRB5_KDB_DISALLOW_SVR,		1},
{"password_changing_service",	25,	KRB5_KDB_PWCHANGE_SERVICE,	0 },
{"support_desmd5",	14,	KRB5_KDB_SUPPORT_DESMD5,	0 }
};

static char *prflags[] = {
    "DISALLOW_POSTDATED",	/* 0x00000001 */
    "DISALLOW_FORWARDABLE",	/* 0x00000002 */
    "DISALLOW_TGT_BASED",	/* 0x00000004 */
    "DISALLOW_RENEWABLE",	/* 0x00000008 */
    "DISALLOW_PROXIABLE",	/* 0x00000010 */
    "DISALLOW_DUP_SKEY",	/* 0x00000020 */
    "DISALLOW_ALL_TIX",		/* 0x00000040 */
    "REQUIRES_PRE_AUTH",	/* 0x00000080 */
    "REQUIRES_HW_AUTH",		/* 0x00000100 */
    "REQUIRES_PWCHANGE",	/* 0x00000200 */
    "UNKNOWN_0x00000400",	/* 0x00000400 */
    "UNKNOWN_0x00000800",	/* 0x00000800 */
    "DISALLOW_SVR",		/* 0x00001000 */
    "PWCHANGE_SERVICE",		/* 0x00002000 */
    "SUPPORT_DESMD5",		/* 0x00004000 */
    "NEW_PRINC",		/* 0x00008000 */
};

char *getenv();
int exit_status = 0;
char *def_realm = NULL;
char *whoami = NULL;
time_t get_date();

void *handle = NULL;
krb5_context context;
char *ccache_name = NULL;

char *
strdur(duration)
    time_t duration;
{
	static char out[100];
    int days, hours, minutes, seconds;
    
    days = duration / (24 * 3600);
    duration %= 24 * 3600;
    hours = duration / 3600;
    duration %= 3600;
    minutes = duration / 60;
    duration %= 60;
    seconds = duration;
	if (days == 1) {
		snprintf(out, sizeof (out), gettext("%d day %02d:%02d:%02d"),
			days, hours, minutes, seconds);
	} else {
		snprintf(out, sizeof (out), gettext("%d days %02d:%02d:%02d"),
			days, hours, minutes, seconds);
}
	return (out);
}

char *
strdate(when)
    krb5_timestamp when;
{
    struct tm *tm;
    static char out[30];
    
    time_t lcltim = when;

    tm = localtime(&lcltim);
	strftime(out, 30, gettext("%a %b %d %H:%M:%S %Z %Y"), tm);
	return (out);
}

/*
 * this is a wrapper to go around krb5_parse_principal so we can set
 * the default realm up properly
 */
krb5_error_code
kadmin_parse_name(name, principal)
    char *name;
    krb5_principal *principal;
{
    char *cp, *fullname;
    krb5_error_code retval;

    if (name == NULL)
	return (EINVAL);
    
    /* assumes def_realm is initialized! */
    fullname = (char *)malloc(strlen(name) + 1 + strlen(def_realm) + 1);
    if (fullname == NULL)
		return (ENOMEM);
    strcpy(fullname, name);
    cp = strchr(fullname, '@');
    while (cp) {
	if (cp - fullname && *(cp - 1) != '\\')
	    break;
	else
	    cp = strchr((cp + 1), '@');
    }
    if (cp == NULL) {
	strcat(fullname, "@");
	strcat(fullname, def_realm);
    }
    retval = krb5_parse_name(context, fullname, principal);
    free(fullname);
    return (retval);
}

char *
kadmin_startup(argc, argv)
    int argc;
    char *argv[];
{
    extern krb5_kt_ops krb5_ktf_writable_ops;
    extern char *optarg;
    char *princstr = NULL, *keytab_name = NULL, *query = NULL;
    char *password = NULL;
	char *kadmin_princ = NULL;
    char *luser, *canon, *cp;
	int optchar, use_keytab = 0, debug = 0;
    struct passwd *pw;
    kadm5_ret_t retval;
    krb5_ccache cc;
    krb5_principal princ;
    kadm5_config_params params;

    memset((char *) &params, 0, sizeof(params));
    
    if (retval = krb5_init_context(&context)) {
	com_err(whoami, retval,
		gettext("while initializing krb5 library"));
	 exit(1);
    }
    while ((optchar = getopt(argc, argv, "Dr:p:kq:w:d:s:mc:t:e:O")) != EOF) {
	switch (optchar) {
	case 'O':	/* Undocumented option for testing only */
		kadmin_princ = KADM5_ADMIN_SERVICE_P;
		break;
	case 'D':
		debug++;
		break;
	case 'r':
	    def_realm = optarg;
	    break;
	case 'p':
		princstr = strdup(optarg);
		if (princstr == NULL) {
			fprintf(stderr, gettext("Out of memory in %s\n"),
				whoami);
			exit(1);
		}
		break;
	case 'c':
	    ccache_name = optarg;
	    break;
	case 'k':
	    use_keytab++;
	    break;
       case 't':
	    keytab_name = optarg;
	    break;
	case 'w':
	    password = optarg;
	    break;
	case 'q':
	    query = optarg;
	    break;
	case 'd':
	    params.dbname = optarg;
	    params.mask |= KADM5_CONFIG_DBNAME;
	    break;
	case 's':
	    params.admin_server = optarg;
	    params.mask |= KADM5_CONFIG_ADMIN_SERVER;
	    break;
	case 'm':
	    params.mkey_from_kbd = 1;
	    params.mask |= KADM5_CONFIG_MKEY_FROM_KBD;
	    break;
	case 'e':
	    retval = krb5_string_to_keysalts(optarg,
				     ", \t", ":.-", 0,
				     &params.keysalts,
				     &params.num_keysalts);
	    if (retval) {
		com_err(whoami, retval,
			gettext("while parsing keysalts %s"), optarg);
		exit(1);
	    }
	    params.mask |= KADM5_CONFIG_ENCTYPES;
	    break;
	default:
	    usage(whoami);
	}
    }

    debugEnable(debug);

    if ((ccache_name && use_keytab) ||
	(keytab_name && !use_keytab))
	usage(whoami);

    if (def_realm == NULL && krb5_get_default_realm(context, &def_realm)) {
	free(princstr);
	fprintf(stderr,
		gettext("%s: unable to get default realm\n"), whoami);
	exit(1);
    }
    params.mask |= KADM5_CONFIG_REALM;
    params.realm = def_realm;

    if (kadmin_princ == NULL) {
	if (kadm5_get_adm_host_srv_name(context,
			       def_realm, &kadmin_princ)) {
		fprintf(stderr,
			gettext("%s: unable to get host based "
				"service name for realm %s\n"),
			whoami, def_realm);
		free(princstr);
		exit(1);
	}
    }

    /*
     * Set cc to an open credentials cache, either specified by the -c
     * argument or the default.
     */
    if (ccache_name == NULL) {
	 if (retval = krb5_cc_default(context, &cc)) {
	      com_err(whoami, retval,
				gettext("while opening default "
					"credentials cache"));
	      exit(1);
	 }
    } else {
	 if (retval = krb5_cc_resolve(context, ccache_name, &cc)) {
	      com_err(whoami, retval,
			gettext("while opening credentials cache %s"),
			ccache_name);
	      exit(1);
	 }
    }

    /*
     * If no principal name is specified: If a ccache was specified and
     * its primary principal name can be read, it is used, else if a
     * keytab was specified, the principal name is host/hostname,
     * otherwise append "/admin" to the primary name of the default
     * ccache, $USER, or pw_name.
     *
     * Gee, 100+ lines to figure out the client principal name.  This
     * should be compressed...
     */
	    
    if (princstr == NULL) {
	if (ccache_name != NULL &&
	    !krb5_cc_get_principal(context, cc, &princ)) {
		if (retval = krb5_unparse_name(context, princ,
				    &princstr)) {
		  com_err(whoami, retval,
			gettext("while canonicalizing principal name"));
			krb5_free_principal(context, princ);
		  exit(1);
	        }
		krb5_free_principal(context, princ);
     } else if (use_keytab != 0) {
	    if (retval = krb5_sname_to_principal(context, NULL,
					  "host", KRB5_NT_SRV_HST,
					  &princ)) {
		com_err(whoami, retval,
			gettext("creating host service principal"));
		exit(1);
	    }
	    if (retval = krb5_unparse_name(context, princ,
					    &princstr)) {
		  com_err(whoami, retval,
			gettext("while canonicalizing "
				"principal name"));
		  krb5_free_principal(context, princ);
		  exit(1);
	     }
	     krb5_free_principal(context, princ);
	} else if (!krb5_cc_get_principal(context, cc, &princ)) {
	    char *realm = NULL;

	    if (krb5_unparse_name(context, princ, &canon)) {
		fprintf(stderr,
			gettext("%s: unable to canonicalize "
				"principal\n"), whoami);
		krb5_free_principal(context, princ);
		exit(1);
	    }
	    krb5_free_principal(context, princ);
			(void) trim_principal(canon);
			princstr = build_admin_princ(canon, def_realm);
	    free(canon);
	} else if (luser = getenv("USER")) {
		princstr = build_admin_princ(luser, def_realm);
	} else if (pw = getpwuid(getuid())) {
		princstr = build_admin_princ(pw->pw_name, def_realm);
	} else {
		fprintf(stderr,
			gettext("%s: unable to figure out "
				"a principal name\n"),
				whoami);
		exit(1);
	}
    } else { /* (princstr != NULL) */
	/* See if we need to add the default realm */
	if (find_component(princstr, '@') == NULL) {
		size_t len;

		/*         principal     @        realm       NULL */
		len = strlen(princstr) + 1 + strlen(def_realm) + 1;
		princstr = realloc(princstr, len);
		if (princstr == NULL) {
			fprintf(stderr,
				gettext("%s: out of memory\n"), whoami);
			exit(1);
	    	}
		strcat(princstr, "@");
		strcat(princstr, def_realm);
	}
    }

    /*
     * Initialize the kadm5 connection.  If we were given a ccache, use
     * it.  Otherwise, use/prompt for the password.
     */
    if (ccache_name) {
	 printf(gettext(
		"Authenticating as principal %s with existing credentials.\n"),
		princstr);
	 retval = kadm5_init_with_creds(princstr, cc,
			kadmin_princ,
			&params,
			KADM5_STRUCT_VERSION,
			KADM5_API_VERSION_2,
			&handle);
    } else if (use_keytab) {
	 if (keytab_name)
	     printf(gettext("Authenticating as principal %s with keytab %s.\n"),
		    princstr, keytab_name);
	 else
	     printf(gettext(
		    "Authenticating as principal %s with default keytab.\n"),
		    princstr);
	 retval = kadm5_init_with_skey(princstr, keytab_name,
			kadmin_princ,
			&params,
			KADM5_STRUCT_VERSION,
			KADM5_API_VERSION_2,
			&handle);
    } else {
	 printf(gettext("Authenticating as principal %s with password.\n"),
		princstr);
	 retval = kadm5_init_with_password(princstr, password,
			kadmin_princ, &params,
			KADM5_STRUCT_VERSION,
			KADM5_API_VERSION_2,
			&handle);
    }
    if (retval) {
	    if (retval == KADM5_RPC_ERROR_CANTENCODEARGS ||
		retval == KADM5_RPC_ERROR_CANTDECODEARGS) {
		    com_err(whoami, KADM5_RPC_ERROR,
			gettext("while initializing %s interface"), whoami);

		    /* privacy-enabled mech probably not installed/configed */
		    com_err(whoami, retval, gettext("."), whoami);
	    } else {
		    com_err(whoami, retval,
			gettext("while initializing %s interface"), whoami);
	if (retval == KADM5_BAD_CLIENT_PARAMS ||
	    retval == KADM5_BAD_SERVER_PARAMS)
		usage(whoami);
	}
	exit(1);
    }
    free(princstr);

    if (retval = krb5_cc_close(context, cc)) {
	com_err(whoami, retval, gettext("while closing ccache %s"),
		ccache_name);
	exit(1);
    }
    /* register the WRFILE keytab type and set it as the default */
    if (retval = krb5_kt_register(context, &krb5_ktf_writable_ops)) {
	 com_err(whoami, retval,
	    gettext("while registering writable key table functions"));
	 exit(1);
    }
    {
	/*
	 * XXX krb5_defkeyname is an internal library global and
	 * should go away
	 */
	 extern char *krb5_defkeyname;

	 krb5_defkeyname = DEFAULT_KEYTAB;
    }

    if ((retval = kadm5_init_iprop(handle)) != 0) {
	com_err(whoami, retval, gettext("while mapping update log"));
	exit(1);
    }

    /* Solaris kerberos: fix memory leak */
    if (kadmin_princ)
	free(kadmin_princ);

    return (query);
}

static char *
find_component(const char *principal, char sep)
{
	char *p = strchr(principal, sep);

	for(p = strchr(principal, sep); p; p = strchr(p, sep))
		if (p != principal && *(p - 1) != '\\')
			break;
	return (p);
}

static char *
trim_principal(char *principal)
{
	char *p = find_component(principal, '/');

	if (p == NULL) 
		p = find_component(principal, '@');

	if (p)
		*p = '\0';

	return (principal);
}

static char *
build_admin_princ(const char *user, const char *realm)
{
	char *princstr;

	/* Add 7 to the length for "/admin@" */
	princstr = (char *) malloc(strlen(user) + 7 + strlen(realm) + 1);
	if (princstr == NULL) {
		fprintf(stderr,
			gettext("%s: out of memory\n"),
			whoami);
		exit(1);
	}
	sprintf(princstr, "%s/admin@%s", user, realm);
	
	return (princstr);
}

int
quit()
{
     krb5_ccache cc;
     int retval;

     kadm5_destroy(handle);
     if (ccache_name != NULL) {
	  fprintf(stderr,
			gettext("\n\a\a\aAdministration credentials "
				"NOT DESTROYED.\n"));
     }
     /* insert more random cleanup here */
     krb5_free_context(context);
     context = NULL;
     return (0);
}

void
kadmin_delprinc(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_ret_t retval;
    krb5_principal princ;
    char *canon;
	char reply[32];
    
    if (! (argc == 2 ||
		(argc == 3 && strcmp("-force", argv[1]) == 0))) {
		fprintf(stderr, "%s: delete_principal [-force] %s\n",
			gettext("usage"), gettext("principal"));
	return;
    }
    retval = kadmin_parse_name(argv[argc - 1], &princ);
    if (retval) {
		com_err("delete_principal", retval,
			gettext("while parsing principal name"));
	return;
    }
    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
	com_err("delete_principal", retval,
			gettext("while canonicalizing principal"));
	krb5_free_principal(context, princ);
	return;
    }
    if (argc == 2) {
		printf(gettext("Are you sure you want to delete "
			    "the principal \"%s\"? (yes/no): "), canon);
	fgets(reply, sizeof (reply), stdin);
		if (strncmp(gettext("yes\n"), reply, sizeof (reply)) &&
			strncmp(gettext("y\n"), reply, sizeof (reply)) &&
			strncmp(gettext("Y\n"), reply, sizeof (reply))) {
			fprintf(stderr,
				gettext("Principal \"%s\" not deleted\n"),
				canon);
	    free(canon);
	    krb5_free_principal(context, princ);
	    return;
	}
    }
    retval = kadm5_delete_principal(handle, princ);
    krb5_free_principal(context, princ);
    if (retval) {
	com_err("delete_principal", retval,
			gettext("while deleting principal \"%s\""), canon);
	free(canon);
	return;
    }
	printf(gettext("Principal \"%s\" deleted.\n"), canon);
	printf(gettext("Make sure that you have removed this principal "
			"from all ACLs before reusing.\n"));
    free(canon);
}

void
kadmin_cpw(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_ret_t retval;
    static char newpw[1024];
    static char prompt1[1024], prompt2[1024];
    char *canon;
    char *pwarg = NULL;
    int n_ks_tuple = 0, keepold = 0, randkey = 0;
    krb5_key_salt_tuple *ks_tuple = NULL;
    krb5_principal princ;
    
    if (argc < 2) {
	 goto usage;
    }
    for (argv++, argc--; argc > 1; argc--, argv++) {
	if (!strcmp("-pw", *argv)) {
	    argc--;
	    if (argc < 1) {
		fprintf(stderr, "change_password: %s",
			gettext("missing password arg\n"));
		goto usage;
	    }
	    pwarg = *++argv;
	    continue;
	}
	if (!strcmp("-randkey", *argv)) {
	    randkey++;
	    continue;
	}
	if (!strcmp("-keepold", *argv)) {
	    keepold++;
	    continue;
	}
	if (!strcmp("-e", *argv)) {
	    argc--;
	    if (argc < 1) {
		fprintf(stderr, "change_password: %s",
			gettext("missing keysaltlist arg\n"));
		goto usage;
	    }
	    retval = krb5_string_to_keysalts(*++argv, ", \t", ":.-", 0,
					     &ks_tuple, &n_ks_tuple);
	    if (retval) {
		com_err("change_password", retval,
			gettext("while parsing keysalts %s"), *argv);
		return;
	    }
	    continue;
	}
	goto usage;
    }
    retval = kadmin_parse_name(*argv, &princ);
    if (retval) {
	com_err("change_password", retval, 
		gettext("while parsing principal name"));
	if (ks_tuple != NULL)
	    free(ks_tuple);
	goto usage;
    }
    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
		com_err("change_password", retval,
			gettext("while canonicalizing principal"));
	krb5_free_principal(context, princ);
	if (ks_tuple != NULL)
	    free(ks_tuple);
	return;
    }
    if (pwarg != NULL) {
	if (keepold || ks_tuple != NULL) {
	    retval = kadm5_chpass_principal_3(handle, princ, keepold,
					      n_ks_tuple, ks_tuple, pwarg);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	} else {
	    retval = kadm5_chpass_principal(handle, princ, pwarg);
	}
	krb5_free_principal(context, princ);
	if (retval) {
	    com_err("change_password", retval,
				gettext("while changing password for \"%s\"."),
				canon);
	    free(canon);
	    return;
	}
		printf(gettext("Password for \"%s\" changed.\n"), canon);
	free(canon);
	return;
    } else if (randkey) {
	if (keepold || ks_tuple != NULL) {
	    retval = kadm5_randkey_principal_3(handle, princ, keepold,
					       n_ks_tuple, ks_tuple,
					       NULL, NULL);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	} else {
	    retval = kadm5_randkey_principal(handle, princ, NULL, NULL);
	}
	krb5_free_principal(context, princ);
	if (retval) {
	    com_err("change_password", retval,
				gettext("while randomizing key for \"%s\"."),
				canon);
	    free(canon);
	    return;
	}
	printf(gettext("Key for \"%s\" randomized.\n"), canon);
	free(canon);
	return;
    } else if (argc == 1) {
	unsigned int i = sizeof (newpw) - 1;
	
		snprintf(prompt1, sizeof (prompt1),
			gettext("Enter password for principal \"%.900s\""),
			*argv);
		snprintf(prompt2, sizeof (prompt2),
			gettext("Re-enter password for principal \"%.900s\""),
			*argv);
	retval = krb5_read_password(context, prompt1, prompt2,
				    newpw, &i);
	if (retval) {
	    com_err("change_password", retval,
				gettext("while reading password for \"%s\"."),
				canon);
	    free(canon);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	    krb5_free_principal(context, princ);
	    return;
	}
	if (keepold || ks_tuple != NULL) {
	    retval = kadm5_chpass_principal_3(handle, princ, keepold,
					      n_ks_tuple, ks_tuple,
					      newpw);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	} else {
	    retval = kadm5_chpass_principal(handle, princ, newpw);
	}
	krb5_free_principal(context, princ);
	memset(newpw, 0, sizeof (newpw));
	if (retval) {
	    com_err("change_password", retval,
				gettext("while changing password for \"%s\"."),
				canon);
	    free(canon);
	    return;
	}
		printf(gettext("Password for \"%s\" changed.\n"), canon);
	free(canon);
	return;
   } else {
	free(canon);
	krb5_free_principal(context, princ);
   usage:
		fprintf(stderr, "%s: change_password [-randkey] [-keepold] "
			"[-e keysaltlist] [-pw password] %s\n",
			gettext("usage"), gettext("principal"));
	return;
   }
}

int kadmin_parse_princ_args(argc, argv, oprinc, mask, pass, randkey,
			    ks_tuple, n_ks_tuple, caller)
    int argc;
    char *argv[];
    kadm5_principal_ent_t oprinc;
    long *mask;
    char **pass;
    int *randkey;
    krb5_key_salt_tuple **ks_tuple;
    int *n_ks_tuple;
    char *caller;
{
    int i, j, attrib_set;
    time_t date;
    time_t now;
    krb5_error_code retval;
    
    *mask = 0;
    *pass = NULL;
    *n_ks_tuple = 0;
    *ks_tuple = NULL;
    time(&now);
    *randkey = 0;
    for (i = 1; i < argc - 1; i++) {
	attrib_set = 0;
	if (strlen(argv[i]) == 7 &&
		    strcmp("-expire", argv[i]) == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		date = get_date(argv[i], NULL);
 		if (date == (time_t)-1) {
					fprintf(stderr,
						gettext("Invalid date "
							"specification "
							"\"%s\".\n"),
			     argv[i]);
					return (-1);
 		}
		oprinc->princ_expire_time = date;
		*mask |= KADM5_PRINC_EXPIRE_TIME;
		continue;
	    }
	}
	if (strlen(argv[i]) == 9 &&
		    strcmp("-pwexpire", argv[i]) == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		date = get_date(argv[i], NULL);
 		if (date == (time_t)-1) {
					fprintf(stderr,
						gettext("Invalid date "
							"specification "
							"\"%s\".\n"),
			     argv[i]);
					return (-1);
 		}
		oprinc->pw_expiration = date;
		*mask |= KADM5_PW_EXPIRATION;
		continue;
	    }
	}
	if (strlen(argv[i]) == 8 &&
		    strcmp("-maxlife", argv[i]) == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		date = get_date(argv[i], NULL);
 		if (date == (time_t)-1) {
					fprintf(stderr,
						gettext("Invalid date "
							"specification "
							"\"%s\".\n"),
			     argv[i]);
					return (-1);
 		}
				if (date <= now) {
					fprintf(stderr,
						gettext("Date specified is "
							"in the past "
							"\"%s\".\n"),
						argv[i]);
					return (-1);
				}
		oprinc->max_life = date - now;
		*mask |= KADM5_MAX_LIFE;
		continue;
	    }
	}
	if (strlen(argv[i]) == 13 &&
		    strcmp("-maxrenewlife", argv[i]) == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		date = get_date(argv[i], NULL);
 		if (date == (time_t)-1) {
					fprintf(stderr,
						gettext("Invalid date "
							"specification "
							"\"%s\".\n"),
			     argv[i]);
					return (-1);
 		}
				if (date <= now) {
					fprintf(stderr,
						gettext("Date specified is "
							"in the past "
							"\"%s\".\n"),
						argv[i]);
					return (-1);
				}
		oprinc->max_renewable_life = date - now;
		*mask |= KADM5_MAX_RLIFE;
		continue;
	    }
	}
	if (strlen(argv[i]) == 5 &&
		    strcmp("-kvno", argv[i]) == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		oprinc->kvno = atoi(argv[i]);
		*mask |= KADM5_KVNO;
		continue;
	    }
	}
	if (strlen(argv[i]) == 7 &&
		    strcmp("-policy", argv[i]) == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		oprinc->policy = argv[i];
		*mask |= KADM5_POLICY;
		continue;
	    }
	}
	if (strlen(argv[i]) == 12 &&
		    strcmp("-clearpolicy", argv[i]) == 0) {
	    oprinc->policy = NULL;
	    *mask |= KADM5_POLICY_CLR;
	    continue;
	}
	if (strlen(argv[i]) == 3 &&
		    strcmp("-pw", argv[i]) == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		*pass = argv[i];
		continue;
	    }
	}
	if (strlen(argv[i]) == 8 &&
		    strcmp("-randkey", argv[i]) == 0) {
	    ++*randkey;
	    continue;
	}
	if (!strcmp("-e", argv[i])) {
	    if (++i > argc - 2)
		return -1;
	    else {
		retval = krb5_string_to_keysalts(argv[i], ", \t", ":.-", 0,
						 ks_tuple, n_ks_tuple);
		if (retval) {
		    com_err(caller, retval,
			    gettext("while parsing keysalts %s"), argv[i]);
		    return -1;
		}
	    }
	    continue;
	}
	for (j = 0; j < sizeof (flags) / sizeof (struct pflag); j++) {
	    if (strlen(argv[i]) == flags[j].flaglen + 1 &&
			    strcmp(flags[j].flagname,
				    /* strip off leading + or - */
				    &argv[i][1]) == 0) {
		if (flags[j].set && argv[i][0] == '-' ||
		    !flags[j].set && argv[i][0] == '+') {
		    oprinc->attributes |= flags[j].theflag;
		    *mask |= KADM5_ATTRIBUTES;
		    attrib_set++;
		    break;
		} else if (flags[j].set && argv[i][0] == '+' ||
			   !flags[j].set && argv[i][0] == '-') {
		    oprinc->attributes &= ~flags[j].theflag;
		    *mask |= KADM5_ATTRIBUTES;
		    attrib_set++;
		    break;
		} else {
					return (-1);
		}
	    }
	}
	if (!attrib_set)
			return (-1);	/* nothing was parsed */
    }
    if (i != argc - 1) {
		return (-1);
    }
    retval = kadmin_parse_name(argv[i], &oprinc->principal);
    if (retval) {
		com_err(caller, retval, gettext("while parsing principal"));
		return (-1);
    }
	return (0);
}

void
kadmin_addprinc_usage(func)
   char *func;
{
	fprintf(stderr, "%s: %s %s\n", gettext("usage"), func,
		gettext("[options] principal"));
	fprintf(stderr, gettext("\toptions are:\n"));
	fprintf(stderr, "\t\t[-expire expdate] [-pwexpire pwexpdate] "
		"[-maxlife maxtixlife]\n\t\t[-kvno kvno] [-policy policy] "
		"[-randkey] [-pw password]\n\t\t[-maxrenewlife maxrenewlife] "
		"[-e keysaltlist] [{+|-}attribute]\n");
	fprintf(stderr, gettext("\tattributes are:\n"));
     fprintf(stderr, "%s%s%s",
		"\t\tallow_postdated allow_forwardable allow_tgs_req "
		"allow_renewable\n",
		"\t\tallow_proxiable allow_dup_skey allow_tix "
		"requires_preauth\n",
		"\t\trequires_hwauth needchange allow_svr "
		"password_changing_service\n");
}

void
kadmin_modprinc_usage(func)
   char *func;
{
	fprintf(stderr, "%s: %s %s\n", gettext("usage"), func,
		gettext("[options] principal"));
	fprintf(stderr, gettext("\toptions are:\n"));
	fprintf(stderr, "\t\t[-expire expdate] [-pwexpire pwexpdate] "
		"[-maxlife maxtixlife]\n\t\t[-kvno kvno] [-policy policy] "
		"[-clearpolicy]\n\t\t[-maxrenewlife maxrenewlife] "
		"[{+|-}attribute]\n");
	fprintf(stderr, gettext("\tattributes are:\n"));
     fprintf(stderr, "%s%s%s",
		"\t\tallow_postdated allow_forwardable allow_tgs_req "
		"allow_renewable\n",
		"\t\tallow_proxiable allow_dup_skey allow_tix "
		"requires_preauth\n",
		"\t\trequires_hwauth needchange allow_svr "
		"password_changing_service\n");
}

void
kadmin_addprinc(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_principal_ent_rec princ, dprinc;
    kadm5_policy_ent_rec defpol;
    long mask;
    int randkey = 0, i;
    int n_ks_tuple;
    krb5_key_salt_tuple *ks_tuple;
    char *pass, *canon;
    krb5_error_code retval;
    static char newpw[1024], dummybuf[256];
    static char prompt1[1024], prompt2[1024];
    int local_kadmin = 0;

    local_kadmin = (strcmp(whoami, KADMIN_LOCAL_NAME) == 0);

    if (dummybuf[0] == 0) {
	 for (i = 0; i < 256; i++)
	      dummybuf[i] = (i+1) % 256;
    }
    
    /* Zero all fields in request structure */
    memset(&princ, 0, sizeof(princ));
    memset(&dprinc, 0, sizeof(dprinc));

    princ.attributes = dprinc.attributes = 0;
    if (kadmin_parse_princ_args(argc, argv,
				&princ, &mask, &pass, &randkey,
				&ks_tuple, &n_ks_tuple,
				"add_principal")) {
	 kadmin_addprinc_usage("add_principal");
	 return;
    }

    retval = krb5_unparse_name(context, princ.principal, &canon);
    if (retval) {
	com_err("add_principal", retval,
		gettext("while canonicalizing principal"));
	krb5_free_principal(context, princ.principal);
	if (ks_tuple != NULL)
	    free(ks_tuple);
	return;
    }

    /*
     * If -policy was not specified, and -clearpolicy was not
     * specified, and the policy "default" exists, assign it.  If
     * -clearpolicy was specified, then KADM5_POLICY_CLR should be
     * unset, since it is never valid for kadm5_create_principal.
     */
    if ((! (mask & KADM5_POLICY)) &&
	(! (mask & KADM5_POLICY_CLR))) {
	 if (! kadm5_get_policy(handle, "default", &defpol)) {
	      fprintf(stderr,
		gettext(
		"NOTICE: no policy specified for %s; assigning \"default\"\n"),
		    canon);
	      princ.policy = "default";
	      mask |= KADM5_POLICY;
	      (void) kadm5_free_policy_ent(handle, &defpol);
	 } else
	      fprintf(stderr, gettext("WARNING: no policy specified "
			"for %s; defaulting to no policy\n"), canon);
    }
    mask &= ~KADM5_POLICY_CLR;
    
    /*
     * Set 'notix' for randkey principals and also for principals which have
     * specified flag options on the cmdline. This is because we want to apply
     * generic flag settings from 'default_principal_flags' first (during
     * principal creation), followed by a kadm5_modify_principal() which
     * correctly applies the cli flag options. So, we do *not* want any tix
     * issued in the interim.
     */
    if (randkey || (mask & KADM5_ATTRIBUTES))
	princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;

    if (randkey) {
	pass = dummybuf;
	mask |= KADM5_ATTRIBUTES;
    } else if (pass == NULL) {
	unsigned int i = sizeof (newpw) - 1;
	snprintf(prompt1, sizeof (prompt1),
		gettext("Enter password for principal \"%.900s\""),
		canon);
	snprintf(prompt2, sizeof (prompt1),
		gettext("Re-enter password for principal \"%.900s\""),
		canon);
	retval = krb5_read_password(context, prompt1, prompt2,
		    newpw, &i);
	if (retval) {
	    com_err("add_principal", retval,
		gettext("while reading password for \"%s\"."), canon);
	    free(canon);
	    krb5_free_principal(context, princ.principal);
	    return;
	}
	pass = newpw;
    }
    mask |= KADM5_PRINCIPAL;

    /*
     * If the client being used is local, always use the new
     * API so we get the full set of enctype support.
     */
    if (ks_tuple != NULL || local_kadmin) {
	retval = kadm5_create_principal_3(handle, &princ, mask,
					  n_ks_tuple, ks_tuple, pass);
    } else {
	retval = kadm5_create_principal(handle, &princ, mask, pass);
    }
    if (retval) {
	com_err("add_principal", retval,
		gettext("while creating \"%s\"."), canon);
	krb5_free_principal(context, princ.principal);
	free(canon);
	if (ks_tuple != NULL)
	    free(ks_tuple);
	return;
    }

    if (randkey) { /* more special stuff for -randkey */
	if (ks_tuple != NULL || local_kadmin) {
	    retval = kadm5_randkey_principal_3(handle, princ.principal,
					       FALSE,
					       n_ks_tuple, ks_tuple,
					       NULL, NULL);
	} else {
	    retval = kadm5_randkey_principal(handle, princ.principal,
					     NULL, NULL);
	}
	if (retval) {
	    com_err("add_principal", retval,
		gettext("while randomizing key for \"%s\"."), canon);
	    krb5_free_principal(context, princ.principal);
	    free(canon);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	    return;
	}
    }

    /*
     * We now retrieve the intersection set of the generic flag settings and
     * the ones specified on the cli & re-parse the princ args, just to make
     * sure we account for conflicts between 'default_principal_flags' and
     * the cmdline flag args. While we are here, also clear 'notix'.
     */
    if (randkey || (mask & KADM5_ATTRIBUTES)) {
	retval = kadm5_get_principal(handle, princ.principal, &dprinc,
			KADM5_PRINCIPAL_NORMAL_MASK);
        if (retval == 0) {
	    if (dprinc.attributes != 0)
		princ.attributes = dprinc.attributes;
	} else {
	    com_err("add_principal", retval,
		gettext("while doing a get_principal on \"%s\"."), canon);
	    printf(gettext("\nWarning: Principal \"%s\" could have incomplete "
		"flag settings, as a result of a failed get_principal.\n"
		"Check the 'default_principal_flags' setting in kdc.conf(4).\n"
		"If there is a mismatch, use modprinc in kadmin(1M) to rectify "
		"the same.\n\n"), canon);
	}

	(void) kadmin_parse_princ_args(argc, argv, &princ, &mask, &pass,
			&randkey, &ks_tuple, &n_ks_tuple, "add_principal");

	princ.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
	mask = KADM5_ATTRIBUTES;
	retval = kadm5_modify_principal(handle, &princ, mask);
	if (retval) {
	    com_err("add_principal", retval,
		gettext("while doing a modify_principal to restore flag "
			"settings for \"%s\"."), canon);
	    krb5_free_principal(context, princ.principal);
	    free(canon);
	    if (ks_tuple != NULL)
		free(ks_tuple);
	    return;
	}
    }

    krb5_free_principal(context, princ.principal);
	printf(gettext("Principal \"%s\" created.\n"), canon);
    if (ks_tuple != NULL)
	free(ks_tuple);
    free(canon);
}

void
kadmin_modprinc(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_principal_ent_rec princ, oldprinc;
    krb5_principal kprinc;
    long mask;
    krb5_error_code retval;
    char *pass, *canon;
    int randkey = 0;
    int n_ks_tuple = 0;
    krb5_key_salt_tuple *ks_tuple;

    if (argc < 2) {
	 kadmin_modprinc_usage("modify_principal");
	 return;
    }

    memset(&oldprinc, 0, sizeof(oldprinc));
    memset(&princ, 0, sizeof(princ));

    retval = kadmin_parse_name(argv[argc - 1], &kprinc);
    if (retval) {
		com_err("modify_principal", retval,
			gettext("while parsing principal"));
	return;
    }
    retval = krb5_unparse_name(context, kprinc, &canon);
    if (retval) {
	com_err("modify_principal", retval,
			gettext("while canonicalizing principal"));
	krb5_free_principal(context, kprinc);
	return;
    }
    retval = kadm5_get_principal(handle, kprinc, &oldprinc,
				 KADM5_PRINCIPAL_NORMAL_MASK);
    krb5_free_principal(context, kprinc);
    if (retval) {
		com_err("modify_principal", retval,
			gettext("while getting \"%s\"."), canon);
	free(canon);
	return;
    }
    princ.attributes = oldprinc.attributes;
    kadm5_free_principal_ent(handle, &oldprinc);
    retval = kadmin_parse_princ_args(argc, argv,
				     &princ, &mask,
				     &pass, &randkey,
				     &ks_tuple, &n_ks_tuple,
				     "modify_principal");
    if (ks_tuple != NULL) {
	free(ks_tuple);
	kadmin_modprinc_usage("modify_principal");
	free(canon);
	return;
    }
    if (retval) {
	kadmin_modprinc_usage("modify_principal");
	free(canon);
	return;
    }
    if (randkey) {
		fprintf(stderr, "modify_principal: -randkey %s ",
			gettext("not allowed\n"));
	krb5_free_principal(context, princ.principal);
	free(canon);
	return;
    }
    if (pass) {
	fprintf(stderr,
		"modify_principal: -pw %s change_password\n",
		gettext("not allowed; use"));
	krb5_free_principal(context, princ.principal);
	free(canon);
	return;
    }
    retval = kadm5_modify_principal(handle, &princ, mask);
    krb5_free_principal(context, princ.principal);
    if (retval) {
	com_err("modify_principal", retval,
			gettext("while modifying \"%s\"."), canon);
	free(canon);
	return;
    }
	printf(gettext("Principal \"%s\" modified.\n"), canon);
    free(canon);
}

void
kadmin_getprinc(argc, argv)
    int argc;
    char *argv[];
{
    kadm5_principal_ent_rec dprinc;
    krb5_principal princ;
    krb5_error_code retval;
    char *canon, *modcanon;
    int i;
    
    if (! (argc == 2 ||
		(argc == 3 && strcmp("-terse", argv[1]) == 0))) {
		fprintf(stderr, "%s: get_principal [-terse] %s\n",
			gettext("usage"), gettext("principal"));
	return;
    }
    memset(&dprinc, 0, sizeof(dprinc));
    memset(&princ, 0, sizeof(princ));

    retval = kadmin_parse_name(argv[argc - 1], &princ);
    if (retval) {
		com_err("get_principal", retval,
			gettext("while parsing principal"));
	return;
    }
    retval = krb5_unparse_name(context, princ, &canon);
    if (retval) {
		com_err("get_principal", retval,
			gettext("while canonicalizing principal"));
	krb5_free_principal(context, princ);
	return;
    }
    retval = kadm5_get_principal(handle, princ, &dprinc,
				 KADM5_PRINCIPAL_NORMAL_MASK | KADM5_KEY_DATA);
    krb5_free_principal(context, princ);
    if (retval) {
		com_err("get_principal", retval,
			gettext("while retrieving \"%s\"."), canon);
	free(canon);
	return;
    }
    retval = krb5_unparse_name(context, dprinc.mod_name, &modcanon);
    if (retval) {
		com_err("get_principal", retval,
			gettext("while unparsing modname"));
	kadm5_free_principal_ent(handle, &dprinc);
	free(canon);
	return;
    }
    if (argc == 2) {
		printf(gettext("Principal: %s\n"), canon);
		printf(gettext("Expiration date: %s\n"),
		    dprinc.princ_expire_time ?
		    strdate(dprinc.princ_expire_time) :
		    gettext("[never]"));
		printf(gettext("Last password change: %s\n"),
		    dprinc.last_pwd_change ?
		    strdate(dprinc.last_pwd_change) :
		    gettext("[never]"));
		printf(gettext("Password expiration date: %s\n"),
	       dprinc.pw_expiration ?
		    strdate(dprinc.pw_expiration) : gettext("[none]"));
		printf(gettext("Maximum ticket life: %s\n"),
		    strdur(dprinc.max_life));
		printf(gettext("Maximum renewable life: %s\n"),
		    strdur(dprinc.max_renewable_life));
		printf(gettext("Last modified: %s (%s)\n"),
		    strdate(dprinc.mod_date), modcanon);
		printf(gettext("Last successful authentication: %s\n"),
	       dprinc.last_success ? strdate(dprinc.last_success) :
		    gettext("[never]"));
		printf(gettext("Last failed authentication: %s\n"),
	       dprinc.last_failed ? strdate(dprinc.last_failed) :
		    gettext("[never]"));
		printf(gettext("Failed password attempts: %d\n"),
	       dprinc.fail_auth_count);
		printf(gettext("Number of keys: %d\n"), dprinc.n_key_data);
	for (i = 0; i < dprinc.n_key_data; i++) {
	     krb5_key_data *key_data = &dprinc.key_data[i];
	     char enctype[BUFSIZ], salttype[BUFSIZ];
	     
	     if (krb5_enctype_to_string(key_data->key_data_type[0],
					enctype, sizeof(enctype)))
				snprintf(enctype, sizeof (enctype),
					gettext("<Encryption type 0x%x>"),
			  key_data->key_data_type[0]);
			printf(gettext("Key: vno %d, %s, "),
			    key_data->key_data_kvno, enctype);
	     if (key_data->key_data_ver > 1) {
				if (krb5_salttype_to_string(
					key_data->key_data_type[1],
					      salttype, sizeof(salttype)))
					snprintf(salttype, sizeof (salttype),
						gettext("<Salt type 0x%x>"),
			       key_data->key_data_type[1]);
		  printf("%s\n", salttype);
	     } else
				printf(gettext("no salt\n"));
	}
	
		printf(gettext("Attributes:"));
	for (i = 0; i < sizeof (prflags) / sizeof (char *); i++) {
	    if (dprinc.attributes & (krb5_flags) 1 << i)
		printf(" %s", prflags[i]);
	}
	printf("\n");
		printf(gettext("Policy: %s\n"),
		    dprinc.policy ? dprinc.policy : gettext("[none]"));
    } else {
	printf("\"%s\"\t%d\t%d\t%d\t%d\t\"%s\"\t%d\t%d\t%d\t%d\t\"%s\""
	       "\t%d\t%d\t%d\t%d\t%d",
	       canon, dprinc.princ_expire_time, dprinc.last_pwd_change,
	       dprinc.pw_expiration, dprinc.max_life, modcanon,
	       dprinc.mod_date, dprinc.attributes, dprinc.kvno,
		    dprinc.mkvno, dprinc.policy ?
		    dprinc.policy : gettext("[none]"),
	       dprinc.max_renewable_life, dprinc.last_success,
	       dprinc.last_failed, dprinc.fail_auth_count,
	       dprinc.n_key_data);
	for (i = 0; i < dprinc.n_key_data; i++)
	     printf("\t%d\t%d\t%d\t%d",
		    dprinc.key_data[i].key_data_ver,
		    dprinc.key_data[i].key_data_kvno,
		    dprinc.key_data[i].key_data_type[0],
		    dprinc.key_data[i].key_data_type[1]);
	printf("\n");
   }
    free(modcanon);
    kadm5_free_principal_ent(handle, &dprinc);
    free(canon);
}

void
kadmin_getprincs(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    char *exp, **names;
    int i, count;

	FILE *output;
	int fd;
	struct sigaction nsig, osig;
	sigset_t nmask, omask;
	int waitb;

    exp = NULL;
    if (! (argc == 1 || (argc == 2 && (exp = argv[1])))) {
		fprintf(stderr, "%s: get_principals %s\n",
			gettext("usage"), gettext("[expression]"));
	return;
    }
    retval = kadm5_get_principals(handle, exp, &names, &count);
    if (retval) {
		com_err("get_principals", retval,
			gettext("while retrieving list."));
	return;
    }

	/*
	 * Solaris:  the following code is used for paging
	 */

	sigemptyset(&nmask);
	sigaddset(&nmask, SIGINT);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

	nsig.sa_handler = SIG_IGN;
	sigemptyset(&nsig.sa_mask);
	nsig.sa_flags = 0;
	sigaction(SIGINT, &nsig, &osig);

	fd = ss_pager_create();
	output = fdopen(fd, "w");

	sigprocmask(SIG_SETMASK, &omask, (sigset_t *)0);

    for (i = 0; i < count; i++)
		fprintf(output, "%s\n", names[i]);

	fclose(output);

	wait(&waitb);

    kadm5_free_name_list(handle, names, count);
}

int
kadmin_parse_policy_args(argc, argv, policy, mask, caller)
    int argc;
    char *argv[];
    kadm5_policy_ent_t policy;
    long *mask;
    char *caller;
{
    int i;
    time_t now;
    time_t date;
    krb5_error_code retval;

    time(&now);
    *mask = 0;
    for (i = 1; i < argc - 1; i++) {
	if (strlen(argv[i]) == 8 &&
		    strcmp(argv[i], "-maxlife") == 0) {
	    if (++i > argc -2)
				return (-1);
	    else {
		date = get_date(argv[i], NULL);
 		if (date == (time_t)-1) {
					fprintf(stderr,
						gettext("Invalid date "
							"specification "
							"\"%s\".\n"),
			     argv[i]);
					return (-1);
 		}
				if (date <= now) {
					fprintf(stderr,
						gettext("Date specified is "
							"in the past "
							"\"%s\".\n"),
						argv[i]);
					return (-1);
				}
		policy->pw_max_life = date - now;
		*mask |= KADM5_PW_MAX_LIFE;
		continue;
	    }
	} else if (strlen(argv[i]) == 8 &&
			strcmp(argv[i], "-minlife") == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		date = get_date(argv[i], NULL);
 		if (date == (time_t)-1) {
					fprintf(stderr,
						gettext("Invalid date "
							"specification "
							"\"%s\".\n"),
			     argv[i]);
					return (-1);
 		}
				if (date <= now) {
					fprintf(stderr,
						gettext("Date specified is "
							"in the past "
							"\"%s\".\n"),
						argv[i]);
					return (-1);
				}
		policy->pw_min_life = date - now;
		*mask |= KADM5_PW_MIN_LIFE;
		continue;
	    }
	} else if (strlen(argv[i]) == 10 &&
			strcmp(argv[i], "-minlength") == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		policy->pw_min_length = atoi(argv[i]);
		*mask |= KADM5_PW_MIN_LENGTH;
		continue;
	    }
	} else if (strlen(argv[i]) == 11 &&
			strcmp(argv[i], "-minclasses") == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		policy->pw_min_classes = atoi(argv[i]);
		*mask |= KADM5_PW_MIN_CLASSES;
		continue;
	    }
	} else if (strlen(argv[i]) == 8 &&
			strcmp(argv[i], "-history") == 0) {
	    if (++i > argc - 2)
				return (-1);
	    else {
		policy->pw_history_num = atoi(argv[i]);
		*mask |= KADM5_PW_HISTORY_NUM;
		continue;
	    }
	} else
			return (-1);
    }
    if (i != argc -1) {
		fprintf(stderr, gettext("%s: parser lost count!\n"), caller);
		return (-1);
    } else
		return (0);
}

void
kadmin_addmodpol_usage(func)
   char *func;
{
	fprintf(stderr, "%s: %s %s\n", gettext("usage"), func,
		gettext("[options] policy"));
	fprintf(stderr, gettext("\toptions are:\n"));
	fprintf(stderr, "\t\t[-maxlife time] [-minlife time] "
		"[-minlength length]\n\t\t[-minclasses number] "
		"[-history number]\n");
}

void
kadmin_addpol(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    long mask;
    kadm5_policy_ent_rec policy;

    memset(&policy, 0, sizeof(policy));
	if (kadmin_parse_policy_args(argc, argv,
				    &policy, &mask, "add_policy")) {
	 kadmin_addmodpol_usage("add_policy");
	 return;
    } else {
	policy.policy = argv[argc - 1];
	mask |= KADM5_POLICY;
	retval = kadm5_create_policy(handle, &policy, mask);
	if (retval) {
			com_err("add_policy", retval,
				gettext("while creating policy \"%s\"."),
		    policy.policy);
	    return;
	}
    }
}

void
kadmin_modpol(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    long mask;
    kadm5_policy_ent_rec policy;

    memset(&policy, 0, sizeof(policy));
    if (kadmin_parse_policy_args(argc, argv, &policy, &mask,
				 "modify_policy")) {
	kadmin_addmodpol_usage("modify_policy");
	return;
    } else {
	policy.policy = argv[argc - 1];
	retval = kadm5_modify_policy(handle, &policy, mask);
	if (retval) {
			com_err("modify_policy", retval,
				gettext("while modifying policy \"%s\"."),
		    policy.policy);
	    return;
	}
    }
}

void
kadmin_delpol(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
	char reply[32];
    
    if (! (argc == 2 ||
		(argc == 3 && strcmp("-force", argv[1]) == 0))) {
		fprintf(stderr, "%s: delete_policy [-force] %s\n",
			gettext("usage"), gettext("policy"));
	return;
    }
    if (argc == 2) {
		printf(gettext("Are you sure you want to delete the policy "
			    "\"%s\"? (yes/no): "), argv[1]);
	fgets(reply, sizeof (reply), stdin);
		if (strncmp(gettext("yes\n"), reply, sizeof (reply)) &&
			strncmp(gettext("y\n"), reply, sizeof (reply)) &&
			strncmp(gettext("Y\n"), reply, sizeof (reply))
			) {
			fprintf(stderr,
				gettext("Policy \"%s\" not deleted.\n"),
				argv[1]);
	    return;
	}
    }
    retval = kadm5_delete_policy(handle, argv[argc - 1]);
    if (retval) {
		com_err("delete_policy:", retval,
			gettext("while deleting policy \"%s\""),
		argv[argc - 1]);
	return;
    }
}

void
kadmin_getpol(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    kadm5_policy_ent_rec policy;
    
    if (! (argc == 2 ||
		(argc == 3 && strcmp("-terse", argv[1]) == 0))) {
		fprintf(stderr, "%s: get_policy [-terse] %s\n",
			gettext("usage"), gettext("policy"));
	return;
    }
    retval = kadm5_get_policy(handle, argv[argc - 1], &policy);
    if (retval) {
		com_err("get_policy", retval,
			gettext("while retrieving policy \"%s\"."),
		argv[argc - 1]);
	return;
    }
    if (argc == 2) {
		printf(gettext("Policy: %s\n"), policy.policy);
		printf(gettext("Maximum password life: %d\n"),
		    policy.pw_max_life);
		printf(gettext("Minimum password life: %d\n"),
		    policy.pw_min_life);
		printf(gettext("Minimum password length: %d\n"),
		    policy.pw_min_length);
		printf(gettext("Minimum number of password "
			    "character classes: %d\n"),
	       policy.pw_min_classes);
		printf(gettext("Number of old keys kept: %d\n"),
		    policy.pw_history_num);
		printf(gettext("Reference count: %d\n"), policy.policy_refcnt);
    } else {
	printf("\"%s\"\t%d\t%d\t%d\t%d\t%d\t%d\n",
	       policy.policy, policy.pw_max_life, policy.pw_min_life,
	       policy.pw_min_length, policy.pw_min_classes,
	       policy.pw_history_num, policy.policy_refcnt);
    }
    kadm5_free_policy_ent(handle, &policy);
}

void
kadmin_getpols(argc, argv)
    int argc;
    char *argv[];
{
    krb5_error_code retval;
    char *exp, **names;
    int i, count;

    exp = NULL;
    if (! (argc == 1 || (argc == 2 && (exp = argv[1])))) {
		fprintf(stderr, "%s: get_policies %s\n",
			gettext("usage"), gettext("[expression]\n"));
	return;
    }
    retval = kadm5_get_policies(handle, exp, &names, &count);
    if (retval) {
		com_err("get_policies", retval,
			gettext("while retrieving list."));
	return;
    }
    for (i = 0; i < count; i++)
	 printf("%s\n", names[i]);
    kadm5_free_name_list(handle, names, count);
}
