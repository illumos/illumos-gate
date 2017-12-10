/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * kdc/main.c
 *
 * Copyright 1990,2001 by the Massachusetts Institute of Technology.
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
 * Main procedure body for the KDC server process.
 */

#include <stdio.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>

#include "k5-int.h"
#include "com_err.h"
#include "adm.h"
#include "adm_proto.h"
#include "kdc_util.h"
#include "extern.h"
#include "kdc5_err.h"
#include <libintl.h>
#include <locale.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef KRB5_KRB4_COMPAT
#include <des.h>
#endif

#if defined(NEED_DAEMON_PROTO)
extern int daemon(int, int);
#endif

void usage (char *);

krb5_sigtype request_exit (int);
krb5_sigtype request_hup  (int);

void setup_signal_handlers (void);

krb5_error_code setup_sam (void);

void initialize_realms (krb5_context, int, char **);

void finish_realms (char *);

static int nofork = 0;
static int rkey_init_done = 0;

/* Solaris Kerberos: global here that other functions access */
int max_tcp_data_connections;

#ifdef POSIX_SIGNALS
static struct sigaction s_action;
#endif /* POSIX_SIGNALS */

#define	KRB5_KDC_MAX_REALMS	32

/*
 * Find the realm entry for a given realm.
 */
kdc_realm_t *
find_realm_data(char *rname, krb5_ui_4 rsize)
{
    int i;
    for (i=0; i<kdc_numrealms; i++) {
	if ((rsize == strlen(kdc_realmlist[i]->realm_name)) &&
	    !strncmp(rname, kdc_realmlist[i]->realm_name, rsize))
	    return(kdc_realmlist[i]);
    }
    return((kdc_realm_t *) NULL);
}

krb5_error_code
setup_server_realm(krb5_principal sprinc)
{
    krb5_error_code	kret;
    kdc_realm_t		*newrealm;

    kret = 0;
    if (kdc_numrealms > 1) {
	if (!(newrealm = find_realm_data(sprinc->realm.data,
					 (krb5_ui_4) sprinc->realm.length)))
	    kret = ENOENT;
	else
	    kdc_active_realm = newrealm;
    }
    else
	kdc_active_realm = kdc_realmlist[0];
    return(kret);
}

static void
finish_realm(kdc_realm_t *rdp)
{
    if (rdp->realm_dbname)
	free(rdp->realm_dbname);
    if (rdp->realm_mpname)
	free(rdp->realm_mpname);
    if (rdp->realm_stash)
	free(rdp->realm_stash);
    if (rdp->realm_ports)
	free(rdp->realm_ports);
    if (rdp->realm_tcp_ports)
	free(rdp->realm_tcp_ports);
    if (rdp->realm_keytab)
	krb5_kt_close(rdp->realm_context, rdp->realm_keytab);
    if (rdp->realm_context) {
	if (rdp->realm_mprinc)
	    krb5_free_principal(rdp->realm_context, rdp->realm_mprinc);
	if (rdp->realm_mkey.length && rdp->realm_mkey.contents) {
	    memset(rdp->realm_mkey.contents, 0, rdp->realm_mkey.length);
	    free(rdp->realm_mkey.contents);
	}
	krb5_db_fini(rdp->realm_context);
	if (rdp->realm_tgsprinc)
	    krb5_free_principal(rdp->realm_context, rdp->realm_tgsprinc);
	krb5_free_context(rdp->realm_context);
    }
    memset((char *) rdp, 0, sizeof(*rdp));
    free(rdp);
}

/*
 * Initialize a realm control structure from the alternate profile or from
 * the specified defaults.
 *
 * After we're complete here, the essence of the realm is embodied in the
 * realm data and we should be all set to begin operation for that realm.
 */
static krb5_error_code
init_realm(krb5_context kcontext, char *progname, kdc_realm_t *rdp, char *realm,
	   char *def_mpname, krb5_enctype def_enctype, char *def_udp_ports,
	   char *def_tcp_ports, krb5_boolean def_manual, char **db_args)
{
    krb5_error_code	kret;
    krb5_boolean	manual;
    krb5_realm_params	*rparams;

    memset((char *) rdp, 0, sizeof(kdc_realm_t));
    if (!realm) {
	kret = EINVAL;
	goto whoops;
    }
	
    rdp->realm_name = realm;
    kret = krb5int_init_context_kdc(&rdp->realm_context);
    if (kret) {
	com_err(progname, kret, gettext("while getting context for realm %s"),
		realm);
	goto whoops;
    }

    /*
     * Solaris Kerberos:
     * Set the current context to that of the realm being init'ed
     */
    krb5_klog_set_context(rdp->realm_context);

    kret = krb5_read_realm_params(rdp->realm_context, rdp->realm_name,
				  &rparams);
    if (kret) {
	com_err(progname, kret, gettext("while reading realm parameters"));
	goto whoops;
    }
    
    /* Handle profile file name */
    if (rparams && rparams->realm_profile)
	rdp->realm_profile = strdup(rparams->realm_profile);

    /* Handle master key name */
    if (rparams && rparams->realm_mkey_name)
	rdp->realm_mpname = strdup(rparams->realm_mkey_name);
    else
	rdp->realm_mpname = (def_mpname) ? strdup(def_mpname) :
	    strdup(KRB5_KDB_M_NAME);

    /* Handle KDC ports */
    if (rparams && rparams->realm_kdc_ports)
	rdp->realm_ports = strdup(rparams->realm_kdc_ports);
    else
	rdp->realm_ports = strdup(def_udp_ports);
    if (rparams && rparams->realm_kdc_tcp_ports)
	rdp->realm_tcp_ports = strdup(rparams->realm_kdc_tcp_ports);
    else
	rdp->realm_tcp_ports = strdup(def_tcp_ports);

    /* Handle stash file */
    if (rparams && rparams->realm_stash_file) {
	rdp->realm_stash = strdup(rparams->realm_stash_file);
	manual = FALSE;
    } else
	manual = def_manual;

    /* Handle master key type */
    if (rparams && rparams->realm_enctype_valid)
	rdp->realm_mkey.enctype = (krb5_enctype) rparams->realm_enctype;
    else
	rdp->realm_mkey.enctype = manual ? def_enctype : ENCTYPE_UNKNOWN;

    /* Handle reject-bad-transit flag */
    if (rparams && rparams->realm_reject_bad_transit_valid)
	rdp->realm_reject_bad_transit = rparams->realm_reject_bad_transit;
    else
	rdp->realm_reject_bad_transit = 1;

    /* Handle ticket maximum life */
    rdp->realm_maxlife = (rparams && rparams->realm_max_life_valid) ?
	rparams->realm_max_life : KRB5_KDB_MAX_LIFE;

    /* Handle ticket renewable maximum life */
    rdp->realm_maxrlife = (rparams && rparams->realm_max_rlife_valid) ?
	rparams->realm_max_rlife : KRB5_KDB_MAX_RLIFE;

    if (rparams)
	krb5_free_realm_params(rdp->realm_context, rparams);

    /*
     * We've got our parameters, now go and setup our realm context.
     */

    /* Set the default realm of this context */
    if ((kret = krb5_set_default_realm(rdp->realm_context, realm))) {
	com_err(progname, kret, gettext("while setting default realm to %s"),
		realm);
	goto whoops;
    }

    /* first open the database  before doing anything */
#ifdef KRBCONF_KDC_MODIFIES_KDB    
    if ((kret = krb5_db_open(rdp->realm_context, db_args, 
			     KRB5_KDB_OPEN_RW | KRB5_KDB_SRV_TYPE_KDC))) {
#else
    if ((kret = krb5_db_open(rdp->realm_context, db_args, 
			     KRB5_KDB_OPEN_RO | KRB5_KDB_SRV_TYPE_KDC))) {
#endif
	/*
	 * Solaris Kerberos:
	 * Make sure that error messages are printed using gettext
	 */
	com_err(progname, kret,
	    gettext("while initializing database for realm %s"), realm);
	goto whoops;
    }

    /* Assemble and parse the master key name */
    if ((kret = krb5_db_setup_mkey_name(rdp->realm_context, rdp->realm_mpname,
					rdp->realm_name, (char **) NULL,
					&rdp->realm_mprinc))) {
	com_err(progname, kret,
		gettext("while setting up master key name %s for realm %s"),
		rdp->realm_mpname, realm);
	goto whoops;
    }

    /*
     * Get the master key.
     */
    if ((kret = krb5_db_fetch_mkey(rdp->realm_context, rdp->realm_mprinc,
				   rdp->realm_mkey.enctype, manual,
				   FALSE, rdp->realm_stash,
				   0, &rdp->realm_mkey))) {
	com_err(progname, kret,
		gettext("while fetching master key %s for realm %s"),
		rdp->realm_mpname, realm);
	goto whoops;
    }

    /* Verify the master key */
    if ((kret = krb5_db_verify_master_key(rdp->realm_context,
					  rdp->realm_mprinc,
					  &rdp->realm_mkey))) {
	com_err(progname, kret,
		gettext("while verifying master key for realm %s"),
		realm);
	goto whoops;
    }

    if ((kret = krb5_db_set_mkey(rdp->realm_context, &rdp->realm_mkey))) {
	com_err(progname, kret,
		gettext("while processing master key for realm %s"),
		realm);
	goto whoops;
    }

    /* Set up the keytab */
    if ((kret = krb5_ktkdb_resolve(rdp->realm_context, NULL,
				   &rdp->realm_keytab))) {
	com_err(progname, kret,
		gettext("while resolving kdb keytab for realm %s"),
		realm);
	goto whoops;
    }

    /* Preformat the TGS name */
    if ((kret = krb5_build_principal(rdp->realm_context, &rdp->realm_tgsprinc,
				     strlen(realm), realm, KRB5_TGS_NAME,
				     realm, (char *) NULL))) {
	com_err(progname, kret,
		gettext("while building TGS name for realm %s"),
		realm);
	goto whoops;
    }

    if (!rkey_init_done) {
#ifdef KRB5_KRB4_COMPAT
	krb5_keyblock temp_key;
#endif
	/*
	 * If all that worked, then initialize the random key
	 * generators.
	 */
#ifdef KRB5_KRB4_COMPAT
	if ((kret = krb5_c_make_random_key(rdp->realm_context,
					   ENCTYPE_DES_CBC_CRC, &temp_key))) {
	    com_err(progname, kret,
		    "while initializing V4 random key generator");
	    goto whoops;
	}

	(void) des_init_random_number_generator(temp_key.contents);
	krb5_free_keyblock_contents(rdp->realm_context, &temp_key);
#endif
	rkey_init_done = 1;
    }
 whoops:
    /*
     * If we choked, then clean up any dirt we may have dropped on the floor.
     */
    if (kret) {
        
	finish_realm(rdp);
    }

    /*
     * Solaris Kerberos:
     * Set the current context back to the general context
     */
    krb5_klog_set_context(kcontext);

    return(kret);
}

krb5_sigtype
request_exit(int signo)
{
    signal_requests_exit = 1;

#ifdef POSIX_SIGTYPE
    return;
#else
    return(0);
#endif
}

krb5_sigtype
request_hup(int signo)
{
    signal_requests_hup = 1;

#ifdef POSIX_SIGTYPE
    return;
#else
    return(0);
#endif
}

void
setup_signal_handlers(void)
{
#ifdef POSIX_SIGNALS
    (void) sigemptyset(&s_action.sa_mask);
    s_action.sa_flags = 0;
    s_action.sa_handler = request_exit;
    (void) sigaction(SIGINT, &s_action, (struct sigaction *) NULL);
    (void) sigaction(SIGTERM, &s_action, (struct sigaction *) NULL);
    s_action.sa_handler = request_hup;
    (void) sigaction(SIGHUP, &s_action, (struct sigaction *) NULL);
    s_action.sa_handler = SIG_IGN;
    (void) sigaction(SIGPIPE, &s_action, (struct sigaction *) NULL);
#else  /* POSIX_SIGNALS */
    signal(SIGINT, request_exit);
    signal(SIGTERM, request_exit);
    signal(SIGHUP, request_hup);
    signal(SIGPIPE, SIG_IGN);
#endif /* POSIX_SIGNALS */

    return;
}

krb5_error_code
setup_sam(void)
{
    return krb5_c_make_random_key(kdc_context, ENCTYPE_DES_CBC_MD5, &psr_key);
}

void
usage(char *name)
{
    fprintf(stderr, gettext("usage: %s [-d dbpathname] [-r dbrealmname] [-R replaycachename ]\n\t[-m] [-k masterenctype] [-M masterkeyname] [-p port] [-n]\n"), name);
    fprintf(stderr, "usage: %s [-x db_args]* [-d dbpathname] [-r dbrealmname] [-R replaycachename ]\n\t[-m] [-k masterenctype] [-M masterkeyname] [-p port] [-X] [-n]\n"
	    "\nwhere,\n\t[-x db_args]* - any number of database specific arguments.\n"
	    "\t\t\tLook at each database documentation for supported arguments\n",
	    name);
    return;
}

void
initialize_realms(krb5_context kcontext, int argc, char **argv)
{
    int 		c;
    char		*db_name = (char *) NULL;
    char		*mkey_name = (char *) NULL;
    char		*rcname __unused;
    char		*lrealm = NULL;
    krb5_error_code	retval;
    krb5_enctype	menctype = ENCTYPE_UNKNOWN;
    kdc_realm_t		*rdatap;
    krb5_boolean	manual = FALSE;
    char		*default_udp_ports = 0;
    char		*default_tcp_ports = 0;
    krb5_pointer	aprof;
    const char		*hierarchy[3];
    char               **db_args      = NULL;
    int                  db_args_size = 0;

#ifdef KRB5_KRB4_COMPAT
    char                *v4mode = 0;
#endif
    extern char *optarg;

    rcname = KDCRCACHE;

    if (!krb5_aprof_init(DEFAULT_KDC_PROFILE, KDC_PROFILE_ENV, &aprof)) {
	hierarchy[0] = "kdcdefaults";
	hierarchy[1] = "kdc_ports";
	hierarchy[2] = (char *) NULL;
	if (krb5_aprof_get_string(aprof, hierarchy, TRUE, &default_udp_ports))
	    default_udp_ports = 0;
	hierarchy[1] = "kdc_tcp_ports";
	if (krb5_aprof_get_string(aprof, hierarchy, TRUE, &default_tcp_ports))
	    default_tcp_ports = 0;
	hierarchy[1] = "kdc_max_tcp_connections";
	if (krb5_aprof_get_int32(aprof, hierarchy, TRUE,
		&max_tcp_data_connections)) {
	    max_tcp_data_connections = DEFAULT_KDC_TCP_CONNECTIONS;
	} else if (max_tcp_data_connections < MIN_KDC_TCP_CONNECTIONS) {
	    max_tcp_data_connections = DEFAULT_KDC_TCP_CONNECTIONS;
	}
#ifdef KRB5_KRB4_COMPAT
	hierarchy[1] = "v4_mode";
	if (krb5_aprof_get_string(aprof, hierarchy, TRUE, &v4mode))
	    v4mode = 0;
#endif
	/* aprof_init can return 0 with aprof == NULL */
	if (aprof)
	     krb5_aprof_finish(aprof);
    }
    if (default_udp_ports == 0)
	default_udp_ports = strdup(DEFAULT_KDC_UDP_PORTLIST);
    if (default_tcp_ports == 0)
	default_tcp_ports = strdup(DEFAULT_KDC_TCP_PORTLIST);
    /*
     * Loop through the option list.  Each time we encounter a realm name,
     * use the previously scanned options to fill in for defaults.
     */
    while ((c = getopt(argc, argv, "x:r:d:mM:k:R:e:p:s:n4:X3")) != -1) {
	switch(c) {
	case 'x':
	    db_args_size++;
	    {
		char **temp = realloc( db_args, sizeof(char*) * (db_args_size+1)); /* one for NULL */
		if( temp == NULL )
		{
			/* Solaris Kerberos: Keep error messages consistent */
		    com_err(argv[0], errno, gettext("while initializing KDC"));
		    exit(1);
		}

		db_args = temp;
	    }
	    db_args[db_args_size-1] = optarg;
	    db_args[db_args_size]   = NULL;
	  break;

	case 'r':			/* realm name for db */
	    if (!find_realm_data(optarg, (krb5_ui_4) strlen(optarg))) {
		if ((rdatap = (kdc_realm_t *) malloc(sizeof(kdc_realm_t)))) {
		    if ((retval = init_realm(kcontext, argv[0], rdatap, optarg, 
					     mkey_name, menctype,
					     default_udp_ports,
					     default_tcp_ports, manual, db_args))) {
			/* Solaris Kerberos: Keep error messages consistent */
			com_err(argv[0], retval, gettext("while initializing realm %s"), optarg);
			exit(1);
		    }
		    kdc_realmlist[kdc_numrealms] = rdatap;
		    kdc_numrealms++;
		    free(db_args), db_args=NULL, db_args_size = 0;
		}
		else
		{
			/* Solaris Kerberos: Keep error messages consistent */
			com_err(argv[0], errno, gettext("while initializing realm %s"), optarg);
			exit(1);
		}
	    }
	    break;
	case 'd':			/* pathname for db */
	    /* now db_name is not a seperate argument. It has to be passed as part of the db_args */
	    if( db_name == NULL )
	    {
		db_name = malloc(sizeof("dbname=") + strlen(optarg));
		if( db_name == NULL )
		{
			/* Solaris Kerberos: Keep error messages consistent */
			com_err(argv[0], errno, gettext("while initializing KDC"));
			exit(1);
		}

		sprintf( db_name, "dbname=%s", optarg);
	    }

	    db_args_size++;
	    {
		char **temp = realloc( db_args, sizeof(char*) * (db_args_size+1)); /* one for NULL */
		if( temp == NULL )
		{
			/* Solaris Kerberos: Keep error messages consistent */
		    com_err(argv[0], errno, gettext("while initializing KDC"));
		    exit(1);
		}

		db_args = temp;
	    }
	    db_args[db_args_size-1] = db_name;
	    db_args[db_args_size]   = NULL;
	    break;
	case 'm':			/* manual type-in of master key */
	    manual = TRUE;
	    if (menctype == ENCTYPE_UNKNOWN)
		menctype = ENCTYPE_DES_CBC_CRC;
	    break;
	case 'M':			/* master key name in DB */
	    mkey_name = optarg;
	    break;
	case 'n':
	    nofork++;			/* don't detach from terminal */
	    break;
	case 'k':			/* enctype for master key */
		/* Solaris Kerberos: Keep error messages consistent */
	    if (retval = krb5_string_to_enctype(optarg, &menctype))
		com_err(argv[0], retval,
		    gettext("while converting %s to an enctype"), optarg);
	    break;
	case 'R':
	    rcname = optarg;
	    break;
	case 'p':
	    if (default_udp_ports)
		free(default_udp_ports);
	    default_udp_ports = strdup(optarg);

	    if (default_tcp_ports)
		free(default_tcp_ports);
	    default_tcp_ports = strdup(optarg);

	    break;
	case '4':
#ifdef KRB5_KRB4_COMPAT
	    if (v4mode)
		free(v4mode);
	    v4mode = strdup(optarg);
#endif
	    break;
	case 'X':
#ifdef KRB5_KRB4_COMPAT
		enable_v4_crossrealm(argv[0]);
#endif
		break;
	case '?':
	default:
	    usage(argv[0]);
	    exit(1);
	}
    }

#ifdef KRB5_KRB4_COMPAT
    /*
     * Setup the v4 mode 
     */
    process_v4_mode(argv[0], v4mode);
    free(v4mode);
#endif

    /*
     * Check to see if we processed any realms.
     */
    if (kdc_numrealms == 0) {
	/* no realm specified, use default realm */
	if ((retval = krb5_get_default_realm(kcontext, &lrealm))) {
	    com_err(argv[0], retval,
		gettext("while attempting to retrieve default realm"));
	/* Solaris Kerberos: avoid double logging */
#if 0
	    fprintf (stderr, "%s: %s, %s", argv[0], error_message (retval),
		gettext("attempting to retrieve default realm\n"));
#endif
	    exit(1);
	}
	if ((rdatap = (kdc_realm_t *) malloc(sizeof(kdc_realm_t)))) {
	    if ((retval = init_realm(kcontext, argv[0], rdatap, lrealm, 
				     mkey_name, menctype, default_udp_ports,
				     default_tcp_ports, manual, db_args))) {
		/* Solaris Kerberos: Keep error messages consistent */
		com_err(argv[0], retval, gettext("while initializing realm %s"), lrealm);
		exit(1);
	    }
	    kdc_realmlist[0] = rdatap;
	    kdc_numrealms++;
	} else {
    	    if (lrealm)
		free(lrealm);
	}
    }

#ifdef USE_RCACHE
    /*
     * Now handle the replay cache.
     */
    if ((retval = kdc_initialize_rcache(kcontext, rcname))) {
	com_err(argv[0], retval, gettext("while initializing KDC replay cache '%s'"),
		rcname);
	exit(1);
    }
#endif

    /* Ensure that this is set for our first request. */
    kdc_active_realm = kdc_realmlist[0];

    if (default_udp_ports)
	free(default_udp_ports);
    if (default_tcp_ports)
	free(default_tcp_ports);
    if (db_args)
	free(db_args);
    if (db_name)
	free(db_name);

    return;
}

void
finish_realms(char *prog)
{
    int i;

    for (i = 0; i < kdc_numrealms; i++) {
	finish_realm(kdc_realmlist[i]);
	kdc_realmlist[i] = 0;
    }
}

/*
 outline:

 process args & setup

 initialize database access (fetch master key, open DB)

 initialize network

 loop:
 	listen for packet

	determine packet type, dispatch to handling routine
		(AS or TGS (or V4?))

	reflect response

	exit on signal

 clean up secrets, close db

 shut down network

 exit
 */

int main(int argc, char **argv)
{
    krb5_error_code	retval;
    krb5_context	kcontext;
    int errout = 0;

    krb5_boolean log_stderr_set;

    (void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"KRB5KDC_TEST"	/* Use this only if it weren't */
#endif

    (void) textdomain(TEXT_DOMAIN);

    if (strrchr(argv[0], '/'))
	argv[0] = strrchr(argv[0], '/')+1;

    if (!(kdc_realmlist = (kdc_realm_t **) malloc(sizeof(kdc_realm_t *) * 
						  KRB5_KDC_MAX_REALMS))) {
	fprintf(stderr, gettext("%s: cannot get memory for realm list\n"), argv[0]);
	exit(1);
    }
    memset((char *) kdc_realmlist, 0,
	   (size_t) (sizeof(kdc_realm_t *) * KRB5_KDC_MAX_REALMS));

    /*
     * A note about Kerberos contexts: This context, "kcontext", is used
     * for the KDC operations, i.e. setup, network connection and error
     * reporting.  The per-realm operations use the "realm_context"
     * associated with each realm.
     */
    retval = krb5int_init_context_kdc(&kcontext);
    if (retval) {
	    com_err(argv[0], retval, gettext("while initializing krb5"));
	    exit(1);
    }
    krb5_klog_init(kcontext, "kdc", argv[0], 1);

    /*
     * Solaris Kerberos:
     * In the early stages of krb5kdc it is desirable to log error messages
     * to stderr as well as any other logging locations specified in config
     * files.
     */
     log_stderr_set = krb5_klog_logging_to_stderr();
     if (log_stderr_set != TRUE) {
     	krb5_klog_add_stderr();
     }

    /* initialize_kdc5_error_table();  SUNWresync121 XXX */

    /*
     * Scan through the argument list
     */
    initialize_realms(kcontext, argc, argv);

    setup_signal_handlers();

    load_preauth_plugins(kcontext);

    retval = setup_sam();
    if (retval) {
	com_err(argv[0], retval, gettext("while initializing SAM"));
	finish_realms(argv[0]);
	return 1;
    }

    if ((retval = setup_network(argv[0]))) {
	com_err(argv[0], retval, gettext("while initializing network"));
	finish_realms(argv[0]);
	return 1;
    }

    /* Solaris Kerberos: Remove the extra stderr logging */
    if (log_stderr_set != TRUE)
	krb5_klog_remove_stderr();

    /*
     * Solaris Kerberos:
     * List the logs (FILE, STDERR, etc) which are currently being
     * logged to and print that to stderr. Useful when trying to
     * track down a failure via SMF.
     */
    if (retval = krb5_klog_list_logs(argv[0])) {
	com_err(argv[0], retval, gettext("while listing logs"));
	if (log_stderr_set != TRUE) {
		fprintf(stderr, gettext("%s: %s while listing logs\n"),
		    argv[0], error_message(retval));
	}
    }

    if (!nofork && daemon(0, 0)) {
	com_err(argv[0], errno, gettext("while detaching from tty"));
	if (log_stderr_set != TRUE) {
		fprintf(stderr, gettext("%s: %s while detaching from tty\n"),
		  argv[0], strerror(errno));
	}
	finish_realms(argv[0]);
	return 1;
    }
    if (retval = krb5_klog_syslog(LOG_INFO, "commencing operation")) {
	com_err(argv[0], retval, gettext("while logging message"));
	errout++;
	};

    if ((retval = listen_and_process(argv[0]))) {
	com_err(argv[0], retval, gettext("while processing network requests"));
	errout++;
    }
    if ((retval = closedown_network(argv[0]))) {
	com_err(argv[0], retval, gettext("while shutting down network"));
	errout++;
    }
    krb5_klog_syslog(LOG_INFO, "shutting down");
    unload_preauth_plugins(kcontext);
    krb5_klog_close(kdc_context);
    finish_realms(argv[0]);
    if (kdc_realmlist) 
      free(kdc_realmlist);
#ifdef USE_RCACHE
    (void) krb5_rc_close(kcontext, kdc_rcache);
#endif
#ifndef NOCACHE
    kdc_free_lookaside(kcontext);
#endif
    krb5_free_context(kcontext);
    return errout;
}




