/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * clients/klist/klist.c
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
 * List out the contents of your credential cache or keytab.
 */

#include <k5-int.h>
#include "com_err.h"
#include <krb5.h>
#ifdef KRB5_KRB4_COMPAT
#include <kerberosIV/krb.h>
#endif /* KRB5_KRB4_COMPAT */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <libintl.h>
#include <locale.h>
#include <netinet/in.h>
#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h>
#endif
#include <inet/ip.h>
#include <inet/ip6.h>

#ifndef _WIN32
#define GET_PROGNAME(x) (strrchr((x), '/') ? strrchr((x), '/')+1 : (x)) 
#else
#define GET_PROGNAME(x) max(max(strrchr((x), '/'), strrchr((x), '\\')) + 1,(x))
#endif /* _WIN32 */

#ifndef _WIN32
#include <sys/socket.h>
#include <netdb.h>
#endif

extern int optind;

int show_flags = 0, show_time = 0, status_only = 0, show_keys = 0;
int show_etype = 0, show_addresses = 0, no_resolve = 0;
char *defname;
char *progname;
krb5_int32 now;
size_t timestamp_width;

krb5_context kcontext;

char * etype_string (krb5_enctype );
void show_credential (krb5_creds *);
	
void do_ccache (char *);
void do_keytab (char *);
void printtime (time_t);
void one_addr (krb5_address *);
void fillit (FILE *, unsigned int, int);
void show_addr(krb5_address *a);

#ifdef KRB5_KRB4_COMPAT
void do_v4_ccache (char *);
#endif /* KRB5_KRB4_COMPAT */

#define DEFAULT 0
#define CCACHE 1
#define KEYTAB 2

/*
 * The reason we start out with got_k4 and got_k5 as zero (false) is
 * so that we can easily add dynamic loading support for determining
 * whether Kerberos 4 and Keberos 5 libraries are available
 */

static int got_k5 = 0; 
static int got_k4 = 0;

static int default_k5 = 1;
#ifdef KRB5_KRB4_COMPAT
static int default_k4 = 1;
#else  /* KRB5_KRB4_COMPAT */
static int default_k4 = 0;
#endif /* KRB5_KRB4_COMPAT */

static void usage()
{
#define KRB_AVAIL_STRING(x) ((x)?gettext("available"):gettext("not available"))

    fprintf(stderr, gettext("Usage: %s [-5] [-4] [-e]"
                    " [[-c] [-f] [-s] [-a [-n]]] "
	            "[-k [-t] [-K]] [name]\n"), progname); 
    fprintf(stderr, "\t-5 Kerberos 5 (%s)\n", KRB_AVAIL_STRING(got_k5));
    fprintf(stderr, "\t-4 Kerberos 4 (%s)\n", KRB_AVAIL_STRING(got_k4));
    fprintf(stderr, gettext("\t   (Default is %s%s%s%s)\n"),
	    default_k5?"Kerberos 5":"",
	    (default_k5 && default_k4)?gettext(" and "):"",
	    default_k4?"Kerberos 4":"",
	    (!default_k5 && !default_k4)?gettext("neither"):"");
    fprintf(stderr, gettext("\t-c specifies credentials cache\n"));
    fprintf(stderr, gettext("\t-k specifies keytab\n"));
    fprintf(stderr, gettext("\t   (Default is credentials cache)\n"));
    fprintf(stderr, gettext("\t-e shows the encryption type\n"));
    fprintf(stderr, gettext("\toptions for credential caches:\n"));
    fprintf(stderr, gettext("\t\t-f shows credentials flags\n"));
    fprintf(stderr, gettext("\t\t-s sets exit status based on valid tgt existence\n"));
    fprintf(stderr, gettext("\t\t-a displays the address list\n"));
    fprintf(stderr, gettext("\t\t-n do not reverse-resolve\n"));
    fprintf(stderr, gettext("\toptions for keytabs:\n"));
    fprintf(stderr, gettext("\t\t-t shows keytab entry timestamps\n"));
    fprintf(stderr, gettext("\t\t-K shows keytab entry DES keys\n"));
    exit(1);
}


int
main(argc, argv)
    int argc;
    char **argv;
{
    int c;
    char *name;
    int mode;
    int use_k5 = 0, use_k4 = 0;

    got_k5 = 1;
#ifdef KRB5_KRB4_COMPAT
    got_k4 = 1;
#endif /* KRB5_KRB4_COMPAT */

    (void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif /* !TEXT_DOMAIN */

    (void) textdomain(TEXT_DOMAIN); 

    progname = GET_PROGNAME(argv[0]); 

    name = NULL;
    mode = DEFAULT;
    while ((c = getopt(argc, argv, "fetKsnack45")) != -1) {
	switch (c) {
	case 'f':
	    show_flags = 1;
	    break;
	case 'e':
	    show_etype = 1;
	    break;
	case 't':
	    show_time = 1;
	    break;
	case 'K':
	    show_keys = 1;
	    break;
	case 's':
	    status_only = 1;
	    break;
	case 'n':
	    no_resolve = 1;
	    break;
	case 'a':
	    show_addresses = 1;
	    break;
	case 'c':
	    if (mode != DEFAULT) usage();
	    mode = CCACHE;
	    break;
	case 'k':
	    if (mode != DEFAULT) usage();
	    mode = KEYTAB;
	    break;
	case '4':
	    if (!got_k4)
	    {
#ifdef KRB5_KRB4_COMPAT
		fprintf(stderr, "Kerberos 4 support could not be loaded\n");
#else  /* KRB5_KRB4_COMPAT */
		fprintf(stderr, gettext("This was not built with Kerberos 4 support\n"));
#endif /* KRB5_KRB4_COMPAT */
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
	    usage();
	    break;
	}
    }

    if (no_resolve && !show_addresses) {
	usage();
    }

    if (mode == DEFAULT || mode == CCACHE) {
	if (show_time || show_keys)
	    usage();
    } else {
	if (show_flags || status_only || show_addresses)
	    usage();
    }

    if (argc - optind > 1) {
		fprintf(stderr,
			gettext("Extra arguments (starting with \"%s\").\n"),
		argv[optind+1]);
	usage();
    }

    name = (optind == argc-1) ? argv[optind] : 0;

    if (!use_k5 && !use_k4)
    {
	use_k5 = default_k5;
	use_k4 = default_k4;
    }

    if (!use_k5)
	got_k5 = 0;
    if (!use_k4)
	got_k4 = 0;

    now = time(0);
    {
	char tmp[BUFSIZ];

	if (!krb5_timestamp_to_sfstring(now, tmp, 20, (char *) NULL) ||
	    !krb5_timestamp_to_sfstring(now, tmp, sizeof(tmp), 
					(char *) NULL))
	    timestamp_width = (int) strlen(tmp);
	else
	    timestamp_width = 15;
    }

    if (got_k5)
    {
	krb5_error_code retval;
	retval = krb5_init_context(&kcontext);
	if (retval) {
	    com_err(progname, retval, gettext("while initializing krb5"));
	    exit(1);
	}

	if (mode == DEFAULT || mode == CCACHE)
	    do_ccache(name);
	else
	    do_keytab(name);
    } else {
#ifdef KRB5_KRB4_COMPAT
	if (mode == DEFAULT || mode == CCACHE)
	    do_v4_ccache(name);
	else {
	    /* We may want to add v4 srvtab support */
	    fprintf(stderr, 
		    "%s: srvtab option not supported for Kerberos 4\n", 
		    progname);
	    exit(1);
	}
#endif /* KRB4_KRB5_COMPAT */
    }

    return 0;
}    

void do_keytab(name)
   char *name;
{
     krb5_keytab kt;
     krb5_keytab_entry entry;
     krb5_kt_cursor cursor;
     char buf[BUFSIZ]; /* hopefully large enough for any type */
     char *pname;
     int code;
     
     if (name == NULL) {
	  if ((code = krb5_kt_default(kcontext, &kt))) {
			com_err(progname, code,
				gettext("while getting default keytab"));
	       exit(1);
	  }
     } else {
	  if ((code = krb5_kt_resolve(kcontext, name, &kt))) {
			com_err(progname, code,
				gettext("while resolving keytab %s"),
		       name);
	       exit(1);
	  }
     }

     if ((code = krb5_kt_get_name(kcontext, kt, buf, BUFSIZ))) {
	  com_err(progname, code,
			gettext("while getting keytab name"));
	  exit(1);
     }

     printf(gettext("Keytab name: %s\n"), buf);
     
     if ((code = krb5_kt_start_seq_get(kcontext, kt, &cursor))) {
	  com_err(progname, code,
			gettext("while starting keytab scan"));
	  exit(1);
     }

     if (show_time) {
	  printf(gettext("KVNO Timestamp"));
	  fillit(stdout, timestamp_width -
	    sizeof (gettext("Timestamp")) + 2, (int)' ');
	  printf(gettext("Principal\n"));
	  printf("---- ");
	  fillit(stdout, timestamp_width, (int) '-');
	  printf(" ");
	  fillit(stdout, 78 - timestamp_width -
		    sizeof (gettext("KVNO")), (int)'-');
	  printf("\n");
     } else {
	  printf(gettext("KVNO Principal\n"));
	  printf("---- ------------------------------"
			    "--------------------------------------"
			    "------\n");
     }
     
     while ((code = krb5_kt_next_entry(kcontext, kt, &entry, &cursor)) == 0) {
	  if ((code = krb5_unparse_name(kcontext, entry.principal, &pname))) {
	       com_err(progname, code,
				gettext("while unparsing principal name"));
	       exit(1);
	  }
	  printf("%4d ", entry.vno);
	  if (show_time) {
	       printtime(entry.timestamp);
	       printf(" ");
	  }
	  printf("%s", pname);
	  if (show_etype)
	      printf(" (%s) " , etype_string(entry.key.enctype));
	  if (show_keys) {
	       printf(" (0x");
	       {
		    int i;
		    for (i = 0; i < entry.key.length; i++)
			 printf("%02x", entry.key.contents[i]);
	       }
	       printf(")");
	  }
	  printf("\n");
	  krb5_free_unparsed_name(kcontext, pname);
     }
     if (code && code != KRB5_KT_END) {
		com_err(progname, code,
			gettext("while scanning keytab"));
	  exit(1);
     }
     if ((code = krb5_kt_end_seq_get(kcontext, kt, &cursor))) {
		com_err(progname, code,
			gettext("while ending keytab scan"));
	  exit(1);
     }
     exit(0);
}
void do_ccache(name)
   char *name;
{
    krb5_ccache cache = NULL;
    krb5_cc_cursor cur;
    krb5_creds creds;
    krb5_principal princ;
    krb5_flags flags;
    krb5_error_code code;
    int	exit_status = 0;
	    
    if (status_only)
	/* exit_status is set back to 0 if a valid tgt is found */
	exit_status = 1;

    if (name == NULL) {
	if ((code = krb5_cc_default(kcontext, &cache))) {
	    if (!status_only)
				com_err(progname, code,
					gettext("while getting default "
						"ccache"));
	    exit(1);
	    }
    } else {
	if ((code = krb5_cc_resolve(kcontext, name, &cache))) {
	    if (!status_only)
				com_err(progname, code,
					gettext("while resolving ccache %s"),
			name);
	    exit(1);
	}
    }
 
    flags = 0;				/* turns off OPENCLOSE mode */
    if ((code = krb5_cc_set_flags(kcontext, cache, flags))) {
	if (code == KRB5_FCC_NOFILE) {
	    if (!status_only) {
		com_err(progname, code, gettext("(ticket cache %s:%s)"),
			krb5_cc_get_type(kcontext, cache),
			krb5_cc_get_name(kcontext, cache));
#ifdef KRB5_KRB4_COMPAT
		if (name == NULL)
		    do_v4_ccache(0);
#endif /* KRB5_KRB4_COMPAT */
	    }
	} else {
	    if (!status_only)
		com_err(progname, code,
			gettext("while setting cache "
				"flags(ticket cache %s:%s)"),
			krb5_cc_get_type(kcontext, cache),
			krb5_cc_get_name(kcontext, cache));
	}
	exit(1);
    }
    if ((code = krb5_cc_get_principal(kcontext, cache, &princ))) {
	if (!status_only)
			com_err(progname, code,
				gettext("while retrieving principal name"));
	exit(1);
    }
    if ((code = krb5_unparse_name(kcontext, princ, &defname))) {
	if (!status_only)
			com_err(progname, code,
				gettext("while unparsing principal name"));
	exit(1);
    }
    if (!status_only) {
		printf(gettext("Ticket cache: %s:%s\nDefault principal: "
			    "%s\n\n"),
	       krb5_cc_get_type(kcontext, cache),
	       krb5_cc_get_name(kcontext, cache), defname);
		fputs(gettext("Valid starting"), stdout);
		fillit(stdout, timestamp_width -
		    sizeof (gettext("Valid starting")) + 3, (int)' ');
		fputs(gettext("Expires"), stdout);
		fillit(stdout, timestamp_width -
		    sizeof (gettext("Expires")) + 3, (int)' ');
		fputs(gettext("Service principal\n"), stdout);
    }
    if ((code = krb5_cc_start_seq_get(kcontext, cache, &cur))) {
	if (!status_only)
			com_err(progname, code,
				gettext("while starting to retrieve tickets"));
	exit(1);
    }
    while (!(code = krb5_cc_next_cred(kcontext, cache, &cur, &creds))) {
	if (status_only) {
	    if (exit_status && creds.server->length == 2 &&
			    strcmp(creds.server->realm.data,
				princ->realm.data) == 0 &&
			    strcmp((char *)creds.server->data[0].data,
				"krbtgt") == 0 &&
		strcmp((char *)creds.server->data[1].data,
		       princ->realm.data) == 0 && 
		creds.times.endtime > now)
		exit_status = 0;
	} else {
	    show_credential(&creds);
	}
	krb5_free_cred_contents(kcontext, &creds);
    }
    if (code == KRB5_CC_END) {
	if ((code = krb5_cc_end_seq_get(kcontext, cache, &cur))) {
	    if (!status_only)
				com_err(progname, code,
					gettext("while finishing ticket "
						"retrieval"));
	    exit(1);
	}
	flags = KRB5_TC_OPENCLOSE;	/* turns on OPENCLOSE mode */
	if ((code = krb5_cc_set_flags(kcontext, cache, flags))) {
	    if (!status_only)
				com_err(progname, code,
					gettext("while closing ccache"));
	    exit(1);
	}
#ifdef KRB5_KRB4_COMPAT
	if (name == NULL && !status_only)
	    do_v4_ccache(0);
#endif /* KRB5_KRB4_COMPAT */
	exit(exit_status);
    } else {
	if (!status_only)
			com_err(progname, code,
				gettext("while retrieving a ticket"));
	exit(1);
    }	
}

char *
etype_string(enctype)
    krb5_enctype enctype;
{
    static char buf[256];
    krb5_error_code retval;
    
    if ((retval = krb5_enctype_to_string(enctype, buf, sizeof(buf)))) {
	/* XXX if there's an error != EINVAL, I should probably report it */
	snprintf(buf, sizeof(buf), gettext("unsupported encryption type %d"), enctype);
    }

    return buf;
}

static char *
flags_string(cred)
    register krb5_creds *cred;
{
    static char buf[32];
    int i = 0;
	
    if (cred->ticket_flags & TKT_FLG_FORWARDABLE)
	buf[i++] = 'F';
    if (cred->ticket_flags & TKT_FLG_FORWARDED)
	buf[i++] = 'f';
    if (cred->ticket_flags & TKT_FLG_PROXIABLE)
	buf[i++] = 'P';
    if (cred->ticket_flags & TKT_FLG_PROXY)
	buf[i++] = 'p';
    if (cred->ticket_flags & TKT_FLG_MAY_POSTDATE)
	buf[i++] = 'D';
    if (cred->ticket_flags & TKT_FLG_POSTDATED)
	buf[i++] = 'd';
    if (cred->ticket_flags & TKT_FLG_INVALID)
	buf[i++] = 'i';
    if (cred->ticket_flags & TKT_FLG_RENEWABLE)
	buf[i++] = 'R';
    if (cred->ticket_flags & TKT_FLG_INITIAL)
	buf[i++] = 'I';
    if (cred->ticket_flags & TKT_FLG_HW_AUTH)
	buf[i++] = 'H';
    if (cred->ticket_flags & TKT_FLG_PRE_AUTH)
	buf[i++] = 'A';
    if (cred->ticket_flags & TKT_FLG_TRANSIT_POLICY_CHECKED)
	buf[i++] = 'T';
    if (cred->ticket_flags & TKT_FLG_OK_AS_DELEGATE)
	buf[i++] = 'O';		/* D/d are taken.  Use short strings?  */
    if (cred->ticket_flags & TKT_FLG_ANONYMOUS)
	buf[i++] = 'a';
    buf[i] = '\0';
    return(buf);
}

void 
printtime(tv)
    time_t tv;
{
    char timestring[BUFSIZ];
    char fill;

    fill = ' ';
	if (!krb5_timestamp_to_sfstring((krb5_timestamp) tv, timestring,
					timestamp_width+1, &fill)) {
	printf(timestring);
    }
}

void
show_credential(cred)
    register krb5_creds * cred;
{
    krb5_error_code retval;
    krb5_ticket *tkt;
    char *name, *sname, *flags;
    int	extra_field = 0;

    retval = krb5_unparse_name(kcontext, cred->client, &name);
    if (retval) {
		com_err(progname, retval,
			gettext("while unparsing client name"));
	return;
    }
    retval = krb5_unparse_name(kcontext, cred->server, &sname);
    if (retval) {
		com_err(progname, retval,
			gettext("while unparsing server name"));
		krb5_free_unparsed_name(kcontext, name);
	return;
    }
    if (!cred->times.starttime)
	cred->times.starttime = cred->times.authtime;

    printtime(cred->times.starttime);
    putchar(' '); putchar(' ');
    printtime(cred->times.endtime);
    putchar(' '); putchar(' ');

    printf("%s\n", sname);

    if (strcmp(name, defname)) {
		printf(gettext("\tfor client %s"), name);
	    extra_field++;
    }
    
    if (cred->times.renew_till) {
	if (!extra_field)
		fputs("\t",stdout);
	else
		fputs(", ",stdout);
	fputs(gettext("renew until "), stdout);
	printtime(cred->times.renew_till);
	extra_field += 2;
    }

    if (extra_field > 3) {
	fputs("\n", stdout);
	extra_field = 0;
    }

    if (show_flags) {
	flags = flags_string(cred);
	if (flags && *flags) {
	    if (!extra_field)
		fputs("\t",stdout);
	    else
		fputs(", ",stdout);
			printf(gettext("Flags: %s"), flags);
	    extra_field++;
	}
    }

    if (extra_field > 2) {
	fputs("\n", stdout);
	extra_field = 0;
    }

    if (show_etype) {
	retval = decode_krb5_ticket(&cred->ticket, &tkt);
	if (retval)
	    goto err_tkt;

	if (!extra_field)
	    fputs("\t",stdout);
	else
	    fputs(", ",stdout);
	printf(gettext("Etype(skey, tkt): %s, "),
	       etype_string(cred->keyblock.enctype));
	printf("%s ",
	       etype_string(tkt->enc_part.enctype));
	extra_field++;

    err_tkt:
	if (tkt != NULL)
	    krb5_free_ticket(kcontext, tkt);
    }

    /* if any additional info was printed, extra_field is non-zero */
    if (extra_field)
	putchar('\n');


    if (show_addresses) {
	if (!cred->addresses || !cred->addresses[0]) {
	    printf(gettext("\tAddresses: (none)\n"));
	} else {
	    int i;

	    printf(gettext("\tAddresses: "));
	    one_addr(cred->addresses[0]);

	    for (i=1; cred->addresses[i]; i++) {
		printf(", ");
		one_addr(cred->addresses[i]);
	    }

	    printf("\n");
	}
    }

    krb5_free_unparsed_name(kcontext, name);
    krb5_free_unparsed_name(kcontext, sname);
}

#include "port-sockets.h"
#include "socket-utils.h" /* for ss2sin etc */
#include <fake-addrinfo.h>

void one_addr(a)
    krb5_address *a;
{
    struct sockaddr_storage ss;
    int err;
    char namebuf[NI_MAXHOST];

    memset (&ss, 0, sizeof (ss));

    switch (a->addrtype) {
    case ADDRTYPE_INET:
	if (a->length != IPV4_ADDR_LEN) {
	broken:
	    printf ("broken address (type %d length %d)",
		    a->addrtype, a->length);
	    return;
	}
	{
	    struct sockaddr_in *sinp = ss2sin (&ss);
	    sinp->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	    sinp->sin_len = sizeof (struct sockaddr_in);
#endif
	    memcpy (&sinp->sin_addr, a->contents, IPV4_ADDR_LEN);
	}
	break;
#ifdef KRB5_USE_INET6
    case ADDRTYPE_INET6:
	if (a->length != IPV6_ADDR_LEN)
	    goto broken;
	{
	    struct sockaddr_in6 *sin6p = ss2sin6 (&ss);
	    sin6p->sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	    sin6p->sin6_len = sizeof (struct sockaddr_in6);
#endif
	    memcpy (&sin6p->sin6_addr, a->contents, IPV6_ADDR_LEN);
	}
	break;
#endif
    default:
	printf(gettext("unknown addr type %d"), a->addrtype);
	return;
    }

    namebuf[0] = 0;
    err = getnameinfo (ss2sa (&ss), socklen (ss2sa (&ss)),
		       namebuf, sizeof (namebuf), 0, 0,
		       no_resolve ? NI_NUMERICHOST : 0U);
    if (err) {
	printf (gettext("unprintable address (type %d, error %d %s)"), a->addrtype, err,
		gai_strerror (err));
	return;
    }
    printf ("%s", namebuf);
}

void
fillit(f, num, c)
    FILE		*f;
    unsigned int	num;
    int			c;
{
    int i;

    for (i=0; i<num; i++)
	fputc(c, f);
}

#ifdef KRB5_KRB4_COMPAT
void
do_v4_ccache(name)
    char * name;
{
    char    pname[ANAME_SZ];
    char    pinst[INST_SZ];
    char    prealm[REALM_SZ];
    char    *file;
    int     k_errno;
    CREDENTIALS c;
    int     header = 1;

    if (!got_k4)
	return;

    file = name?name:tkt_string();

    if (status_only) {
	fprintf(stderr, 
		"%s: exit status option not supported for Kerberos 4\n",
		progname);
	exit(1);
    }

    if (got_k5)
	printf("\n\n");

    printf("Kerberos 4 ticket cache: %s\n", file);

    /* 
     * Since krb_get_tf_realm will return a ticket_file error, 
     * we will call tf_init and tf_close first to filter out
     * things like no ticket file.  Otherwise, the error that 
     * the user would see would be 
     * klist: can't find realm of ticket file: No ticket file (tf_util)
     * instead of
     * klist: No ticket file (tf_util)
     */

    /* Open ticket file */
    k_errno = tf_init(file, R_TKT_FIL);
    if (k_errno) {
	fprintf(stderr, "%s: %s\n", progname, krb_get_err_text (k_errno));
	exit(1);
    }
    /* Close ticket file */
    (void) tf_close();

    /* 
     * We must find the realm of the ticket file here before calling
     * tf_init because since the realm of the ticket file is not
     * really stored in the principal section of the file, the
     * routine we use must itself call tf_init and tf_close.
     */
    if ((k_errno = krb_get_tf_realm(file, prealm)) != KSUCCESS) {
	fprintf(stderr, "%s: can't find realm of ticket file: %s\n",
		progname, krb_get_err_text (k_errno));
	exit(1);
    }

    /* Open ticket file */
    if ((k_errno = tf_init(file, R_TKT_FIL))) {
	fprintf(stderr, "%s: %s\n", progname, krb_get_err_text (k_errno));
	exit(1);
    }
    /* Get principal name and instance */
    if ((k_errno = tf_get_pname(pname)) ||
	(k_errno = tf_get_pinst(pinst))) {
	fprintf(stderr, "%s: %s\n", progname, krb_get_err_text (k_errno));
	exit(1);
    }

    /* 
     * You may think that this is the obvious place to get the
     * realm of the ticket file, but it can't be done here as the
     * routine to do this must open the ticket file.  This is why 
     * it was done before tf_init.
     */
       
    printf("Principal: %s%s%s%s%s\n\n", pname,
	   (pinst[0] ? "." : ""), pinst,
	   (prealm[0] ? "@" : ""), prealm);
    while ((k_errno = tf_get_cred(&c)) == KSUCCESS) {
	if (header) {
	    printf("%-18s  %-18s  %s\n",
		   "  Issued", "  Expires", "  Principal");
	    header = 0;
	}
	printtime(c.issue_date);
	fputs("  ", stdout);
	printtime(krb_life_to_time(c.issue_date, c.lifetime));
	printf("  %s%s%s%s%s\n",
	       c.service, (c.instance[0] ? "." : ""), c.instance,
	       (c.realm[0] ? "@" : ""), c.realm);
    }
    if (header && k_errno == EOF) {
	printf("No tickets in file.\n");
    }
}
#endif /* KRB4_KRB5_COMPAT */
