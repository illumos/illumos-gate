/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright(c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved */

/*
 * Copyright (c) 1983 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * remote login server:
 *	remuser\0
 *	locuser\0
 *	terminal info\0
 *	data
 */

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <netdb.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include <stropts.h>
#include <sac.h>	/* for SC_WILDC */
#include <utmpx.h>
#include <sys/filio.h>
#include <sys/logindmux.h>
#include <sys/rlioctl.h>
#include <sys/termios.h>
#include <sys/tihdr.h>
#include <arpa/inet.h>
#include <security/pam_appl.h>
#include <strings.h>
#include <com_err.h>
#include <k5-int.h>
#include <kcmd.h>
#include <krb5_repository.h>
#include <sys/cryptmod.h>
#include <bsm/adt.h>
#include <addr_match.h>
#include <store_forw_creds.h>

#define	KRB5_RECVAUTH_V5 5
#define	UT_NAMESIZE	sizeof (((struct utmpx *)0)->ut_name)

static char lusername[UT_NAMESIZE+1];
static char rusername[UT_NAMESIZE+1];
static char *krusername = NULL;
static char term[64];

static krb5_ccache ccache = NULL;
static krb5_keyblock *session_key = NULL;
static int chksum_flag = 0;
static int use_auth = 0;
static enum kcmd_proto kcmd_protocol;
#ifdef ALLOW_KCMD_V2
static krb5_data encr_iv = { NULL, 0 };
static krb5_data decr_iv = { NULL, 0 };
#endif /* ALLOW_KCMD_V2 */

#define	CHKSUM_REQUIRED 0x01
#define	CHKSUM_IGNORED  0x02
#define	VALID_CHKSUM(x) ((x) == 0 || (x) == CHKSUM_REQUIRED ||\
			(x) == CHKSUM_IGNORED)

#define	PWD_IF_FAIL  0x01
#define	PWD_REQUIRED 0x02

#define	AUTH_NONE 0x00

#define	ARGSTR "k5exEXciM:s:S:D:"
#define	DEFAULT_TOS 16

#define	KRB5_PROG_NAME "krlogin"

#define	SECURE_MSG "This rlogin session is using encryption " \
	"for all data transmissions.\r\n"

#define	KRB_V5_SENDAUTH_VERS	"KRB5_SENDAUTH_V1.0"
#define	KRB5_RECVAUTH_V5	5

static krb5_error_code krb5_compat_recvauth(krb5_context context,
					    krb5_auth_context *auth_context,
					    krb5_pointer fdp,
					    krb5_principal server,
					    krb5_int32 flags,
					    krb5_keytab keytab,
					    krb5_ticket **ticket,
					    krb5_int32 *auth_sys,
					    krb5_data *version);

static void do_krb_login(int, char *, char *, krb5_context, int, krb5_keytab);
static int configure_stream(int, krb5_keyblock *, int, krb5_data *, uint_t);

extern krb5_error_code krb5_read_message(krb5_context, krb5_pointer,
					krb5_data *);
extern krb5_error_code krb5_net_read(krb5_context, int, char *, int);

#define	LOGIN_PROGRAM "/bin/login"

#define	DEFAULT_PROG_NAME	"rlogin"

static const char *pam_prog_name = DEFAULT_PROG_NAME;
static void	rmut(void);
static void	doit(int,  struct sockaddr_storage *, krb5_context, int,
		    krb5_keytab);
static void	protocol(int, int, int);

static int	readstream(int, char *, int);
static void	fatal(int, const char *);
static void	fatalperror(int, const char *);
static int	send_oob(int fd, void *ptr, size_t count);
static int	removemod(int f, char *modname);

static int
issock(int fd)
{
	struct stat stats;

	if (fstat(fd, &stats) == -1)
		return (0);
	return (S_ISSOCK(stats.st_mode));
}

/*
 * audit_rlogin_settid stores the terminal id while it is still
 * available.  Subsequent calls to adt_load_hostname() return
 * the id which is stored here.
 */
static int
audit_rlogin_settid(int fd) {
	adt_session_data_t	*ah;
	adt_termid_t		*termid;
	int			rc;

	if ((rc = adt_start_session(&ah, NULL, 0)) == 0) {
		if ((rc = adt_load_termid(fd, &termid)) == 0) {
			if ((rc = adt_set_user(ah, ADT_NO_AUDIT,
			    ADT_NO_AUDIT, 0, ADT_NO_AUDIT,
			    termid, ADT_SETTID)) == 0)
				(void) adt_set_proc(ah);
			free(termid);
		}
		(void) adt_end_session(ah);
	}
	return (rc);
}


/* ARGSUSED */
int
main(int argc, char *argv[])
{
	int on = 1;
	socklen_t fromlen;
	struct sockaddr_storage from;
	int fd = -1;

	extern char *optarg;
	int c;
	int tos = -1;
	krb5_context krb_context;
	krb5_keytab keytab = NULL;
	krb5_error_code status;
	char *realm = NULL;
	char *keytab_file = NULL;
	int encr_flag = 0;
	struct sockaddr_storage ouraddr;
	socklen_t ourlen;
#ifdef DEBUG
	int debug_port = 0;
#endif /* DEBUG */
	openlog("rlogind", LOG_PID | LOG_ODELAY, LOG_DAEMON);

	while ((c = getopt(argc, argv, ARGSTR)) != -1) {
		switch (c) {
		case 'k':
		case '5':
			use_auth = KRB5_RECVAUTH_V5;
			break;
		case 'e':
		case 'E':
		case 'x':
		case 'X':
			encr_flag = 1;
			break;
		case 'M':
			realm = (char *)strdup(optarg);
			break;
		case 'S':
			keytab_file = (char *)strdup(optarg);
			break;
		case 'c':
			chksum_flag |= CHKSUM_REQUIRED;
			break;
		case 'i':
			chksum_flag |= CHKSUM_IGNORED;
			break;
		case 's':
			if (optarg == NULL || (tos = atoi(optarg)) < 0 ||
			    tos > 255) {
				syslog(LOG_ERR, "%s: illegal tos value: "
				    "%s\n", argv[0], optarg);
			} else {
				if (tos < 0)
					tos = DEFAULT_TOS;
			}
			break;
#ifdef DEBUG
		case 'D':
			debug_port = atoi(optarg);
			break;
#endif /* DEBUG */
		default:
			syslog(LOG_ERR, "Unrecognized command line option "
			    "(-%c), exiting", optopt);
			exit(EXIT_FAILURE);
		}
	}
	if (use_auth == KRB5_RECVAUTH_V5) {
		status = krb5_init_context(&krb_context);
		if (status) {
			syslog(LOG_ERR, "Error initializing krb5: %s",
			    error_message(status));
			exit(EXIT_FAILURE);
		}
		if (realm != NULL)
			(void) krb5_set_default_realm(krb_context, realm);
		if (keytab_file != NULL) {
			if ((status = krb5_kt_resolve(krb_context,
						    keytab_file,
						    &keytab))) {
				com_err(argv[0],
					status,
					"while resolving srvtab file %s",
					keytab_file);
				exit(EXIT_FAILURE);
			}
		}
	}

#ifdef DEBUG
	if (debug_port) {
		int s;
		struct sockaddr_in sin;

		if ((s = socket(AF_INET, SOCK_STREAM, PF_UNSPEC)) < 0) {
			fatalperror(STDERR_FILENO, "Error in socket");
		}

		(void) memset((char *)&sin, 0, sizeof (sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(debug_port);
		sin.sin_addr.s_addr = INADDR_ANY;

		(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
					(char *)&on, sizeof (on));

		if ((bind(s, (struct sockaddr *)&sin, sizeof (sin))) < 0) {
			fatalperror(STDERR_FILENO, "bind error");
		}

		if ((listen(s, 5)) < 0) {
			fatalperror(STDERR_FILENO, "listen error");
		}

		fromlen = sizeof (from);
		if ((fd = accept(s, (struct sockaddr *)&from, &fromlen)) < 0) {
			fatalperror(STDERR_FILENO, "accept error");
		}

		(void) close(s);
	} else
#endif /* DEBUG */
	{
		if (!issock(STDIN_FILENO))
			fatal(STDIN_FILENO,
				"stdin is not a socket file descriptor");
		fd = STDIN_FILENO;
	}

	fromlen = sizeof (from);
	if (getpeername(fd, (struct sockaddr *)&from, &fromlen) < 0)
		fatalperror(STDERR_FILENO, "getpeername");

	if (audit_rlogin_settid(fd))	/* set terminal ID */
		fatalperror(STDERR_FILENO, "audit");

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on,
	    sizeof (on)) < 0)
		syslog(LOG_WARNING, "setsockopt(SO_KEEPALIVE): %m");

	if (!VALID_CHKSUM(chksum_flag)) {
		syslog(LOG_ERR, "Configuration error: mutually exclusive "
		    "options specified (-c and -i)");
		fatal(fd, "Checksums are required and ignored (-c and -i);"
		    "these options are mutually exclusive - check "
		    "the documentation.");
	}
	ourlen = sizeof (ouraddr);
	if (getsockname(fd, (struct sockaddr *)&ouraddr, &ourlen) == -1) {
		syslog(LOG_ERR, "getsockname error: %m");
		exit(EXIT_FAILURE);
	}

	if (tos != -1 &&
	    ouraddr.ss_family != AF_INET6 &&
	    setsockopt(fd, IPPROTO_IP, IP_TOS, (char *)&tos,
					sizeof (tos)) < 0 &&
					errno != ENOPROTOOPT) {
		syslog(LOG_ERR, "setsockopt(IP_TOS %d): %m", tos);
	}
	doit(fd, &from, krb_context, encr_flag, keytab);
	return (0);
}

static void	cleanup(int);
static int	nsize = 0;	/* bytes read prior to pushing rlmod */
static char	*rlbuf;		/* buffer where nbytes are read to */
static char	*line;

static struct winsize win = { 0, 0, 0, 0 };
static pid_t pid;
static char hostname[MAXHOSTNAMELEN + 1];

static void
getstr(int f, char *buf, int cnt, char *err)
{
	char c;
	do {
		if (read(f, &c, 1) != 1 || (--cnt < 0)) {
			syslog(LOG_ERR, "Error reading \'%s\' field", err);
			exit(EXIT_FAILURE);
		}
		*buf++ = c;
	} while (c != '\0');
}

static krb5_error_code
recvauth(int f,
	krb5_context krb_context,
	unsigned int *valid_checksum,
	krb5_ticket **ticket,
	int *auth_type,
	krb5_principal *client,
	int encr_flag,
	krb5_keytab keytab)
{
	krb5_error_code status = 0;
	krb5_auth_context auth_context = NULL;
	krb5_rcache rcache;
	krb5_authenticator *authenticator;
	krb5_data inbuf;
	krb5_data auth_version;

	*valid_checksum = 0;

	if ((status = krb5_auth_con_init(krb_context, &auth_context)))
		return (status);

	/* Only need remote address for rd_cred() to verify client */
	if ((status = krb5_auth_con_genaddrs(krb_context, auth_context, f,
			KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR)))
		return (status);

	status = krb5_auth_con_getrcache(krb_context, auth_context, &rcache);
	if (status)
		return (status);

	if (!rcache) {
		krb5_principal server;

		status = krb5_sname_to_principal(krb_context, 0, 0,
						KRB5_NT_SRV_HST, &server);
		if (status)
			return (status);

		status = krb5_get_server_rcache(krb_context,
				krb5_princ_component(krb_context, server, 0),
				&rcache);
		krb5_free_principal(krb_context, server);
		if (status)
			return (status);

		status = krb5_auth_con_setrcache(krb_context, auth_context,
						rcache);
		if (status)
			return (status);
	}
	if ((status = krb5_compat_recvauth(krb_context,
					&auth_context,
					&f,
					NULL,	/* Specify daemon principal */
					0,	/* no flags */
					keytab,	/* NULL to use v5srvtab */
					ticket,	/* return ticket */
					auth_type, /* authentication system */
					&auth_version))) {
		if (*auth_type == KRB5_RECVAUTH_V5) {
			/*
			 * clean up before exiting
			 */
			getstr(f, rusername, sizeof (rusername), "remuser");
			getstr(f, lusername, sizeof (lusername), "locuser");
			getstr(f, term, sizeof (term), "Terminal type");
		}
		return (status);
	}

	getstr(f, lusername, sizeof (lusername), "locuser");
	getstr(f, term, sizeof (term), "Terminal type");

	kcmd_protocol = KCMD_UNKNOWN_PROTOCOL;
	if (auth_version.length != 9 || auth_version.data == NULL) {
		syslog(LOG_ERR, "Bad application protocol version length in "
		    "KRB5 exchange, exiting");
		fatal(f, "Bad application version length, exiting.");
	}
	/*
	 * Determine which Kerberos CMD protocol was used.
	 */
	if (strncmp(auth_version.data, "KCMDV0.1", 9) == 0) {
		kcmd_protocol = KCMD_OLD_PROTOCOL;
	} else if (strncmp(auth_version.data, "KCMDV0.2", 9) == 0) {
		kcmd_protocol = KCMD_NEW_PROTOCOL;
	} else {
		syslog(LOG_ERR, "Unrecognized KCMD protocol (%s), exiting",
			(char *)auth_version.data);
		fatal(f, "Unrecognized KCMD protocol, exiting");
	}

	if ((*auth_type == KRB5_RECVAUTH_V5) && chksum_flag &&
		kcmd_protocol == KCMD_OLD_PROTOCOL) {
		if ((status = krb5_auth_con_getauthenticator(krb_context,
							    auth_context,
							    &authenticator)))
			return (status);
		if (authenticator->checksum) {
			struct sockaddr_storage adr;
			int adr_length = sizeof (adr);
			int buflen;
			krb5_data input;
			krb5_keyblock key;
			char *chksumbuf;

			/*
			 * Define the lenght of the chksum buffer.
			 * chksum string = "[portnum]:termstr:username"
			 * The extra 32 is to hold a integer string for
			 * the portnumber.
			 */
			buflen = strlen(term) + strlen(lusername) + 32;
			chksumbuf = (char *)malloc(buflen);
			if (chksumbuf == 0) {
				krb5_free_authenticator(krb_context,
							authenticator);
				fatal(f, "Out of memory error");
			}

			if (getsockname(f, (struct sockaddr *)&adr,
							&adr_length) != 0) {
				krb5_free_authenticator(krb_context,
							authenticator);
				fatal(f, "getsockname error");
			}

			(void) snprintf(chksumbuf, buflen,
					"%u:%s%s",
					ntohs(SOCK_PORT(adr)),
					term, lusername);

			input.data = chksumbuf;
			input.length = strlen(chksumbuf);
			key.contents = (*ticket)->enc_part2->session->contents;
			key.length = (*ticket)->enc_part2->session->length;
			status = krb5_c_verify_checksum(krb_context,
						&key, 0,
						&input,
						authenticator->checksum,
						valid_checksum);

			if (status == 0 && *valid_checksum == 0)
				status = KRB5KRB_AP_ERR_BAD_INTEGRITY;

			if (chksumbuf)
				krb5_xfree(chksumbuf);
			if (status) {
				krb5_free_authenticator(krb_context,
							authenticator);
				return (status);
			}
		}
		krb5_free_authenticator(krb_context, authenticator);
	}

	if ((status = krb5_copy_principal(krb_context,
					(*ticket)->enc_part2->client,
					client)))
		return (status);

	/* Get the Unix username of the remote user */
	getstr(f, rusername, sizeof (rusername), "remuser");

	/* Get the Kerberos principal name string of the remote user */
	if ((status = krb5_unparse_name(krb_context, *client, &krusername)))
		return (status);

#ifdef DEBUG
	syslog(LOG_DEBUG | LOG_AUTH, "rlogind: got krb5 credentials for %s",
	    (krusername != NULL ? krusername : "<unknown>"));
#endif

	if (encr_flag) {
		status = krb5_auth_con_getremotesubkey(krb_context,
						    auth_context,
						    &session_key);
		if (status) {
			syslog(LOG_ERR, "Error getting KRB5 session "
			    "subkey, exiting");
			fatal(f, "Error getting KRB5 session subkey, exiting");
		}
		/*
		 * The "new" protocol requires that a subkey be sent.
		 */
		if (session_key == NULL &&
		    kcmd_protocol == KCMD_NEW_PROTOCOL) {
			syslog(LOG_ERR, "No KRB5 session subkey sent, exiting");
			fatal(f, "No KRB5 session subkey sent, exiting");
		}
		/*
		 * The "old" protocol does not permit an authenticator subkey.
		 * The key is taken from the ticket instead (see below).
		 */
		if (session_key != NULL &&
		    kcmd_protocol == KCMD_OLD_PROTOCOL) {
			syslog(LOG_ERR, "KRB5 session subkey not permitted "
			    "with old KCMD protocol, exiting");

			fatal(f, "KRB5 session subkey not permitted "
			    "with old KCMD protocol, exiting");
		}
		/*
		 * If no key at this point, use the session key from
		 * the ticket.
		 */
		if (session_key == NULL) {
			/*
			 * Save the session key so we can configure the crypto
			 * module later.
			 */
			status = krb5_copy_keyblock(krb_context,
					    (*ticket)->enc_part2->session,
					    &session_key);
			if (status) {
				syslog(LOG_ERR, "krb5_copy_keyblock failed");
				fatal(f, "krb5_copy_keyblock failed");
			}
		}
		/*
		 * If session key still cannot be found, we must
		 * exit because encryption is required here
		 * when encr_flag (-x) is set.
		 */
		if (session_key == NULL) {
			syslog(LOG_ERR, "Could not find an encryption key,"
				    "exiting");
			fatal(f, "Encryption required but key not found, "
			    "exiting");
		}
	}
	/*
	 * Use krb5_read_message to read the principal stuff.
	 */
	if ((status = krb5_read_message(krb_context, (krb5_pointer)&f,
					&inbuf)))
		fatal(f, "Error reading krb5 message");

	if (inbuf.length) { /* Forwarding being done, read creds */
		krb5_creds **creds = NULL;

		if (status = krb5_rd_cred(krb_context, auth_context, &inbuf,
					    &creds, NULL)) {
			if (rcache)
				(void) krb5_rc_close(krb_context, rcache);
			krb5_free_creds(krb_context, *creds);
			fatal(f, "Can't get forwarded credentials");
		}

		/* Store the forwarded creds in the ccache */
		if (status = store_forw_creds(krb_context,
					    creds, *ticket, lusername,
					    &ccache)) {
			if (rcache)
				(void) krb5_rc_close(krb_context, rcache);
			krb5_free_creds(krb_context, *creds);
			fatal(f, "Can't store forwarded credentials");
		}
		krb5_free_creds(krb_context, *creds);
	}

	if (rcache)
		(void) krb5_rc_close(krb_context, rcache);

	return (status);
}

static void
do_krb_login(int f, char *host_addr, char *hostname,
	    krb5_context krb_context, int encr_flag,
	    krb5_keytab keytab)
{
	krb5_error_code status;
	uint_t valid_checksum;
	krb5_ticket	*ticket = NULL;
	int auth_sys = 0;
	int auth_sent = 0;
	krb5_principal client = NULL;

	if (getuid())
		fatal(f, "Error authorizing KRB5 connection, "
			"server lacks privilege");

	status = recvauth(f, krb_context, &valid_checksum, &ticket,
			&auth_sys, &client, encr_flag, keytab);
	if (status) {
		if (ticket)
			krb5_free_ticket(krb_context, ticket);
		if (status != 255)
			syslog(LOG_ERR,
			    "Authentication failed from %s(%s): %s\n",
			    host_addr, hostname, error_message(status));
		fatal(f, "Kerberos authentication failed, exiting");
	}

	if (auth_sys != KRB5_RECVAUTH_V5) {
		fatal(f, "This server only supports Kerberos V5");
	} else {
		/*
		 * Authenticated OK, now check authorization.
		 */
		if (client && krb5_kuserok(krb_context, client, lusername))
		    auth_sent = KRB5_RECVAUTH_V5;
	}

	if (auth_sent == KRB5_RECVAUTH_V5 &&
	    kcmd_protocol == KCMD_OLD_PROTOCOL &&
	    chksum_flag == CHKSUM_REQUIRED && !valid_checksum) {
		syslog(LOG_ERR, "Client did not supply required checksum, "
		    "connection rejected.");
		fatal(f, "Client did not supply required checksum, "
		    "connection rejected.");
	}

	if (auth_sys != auth_sent) {
		char *msg_fail = NULL;
		int msgsize = 0;

		if (ticket)
			krb5_free_ticket(krb_context, ticket);

		if (krusername != NULL) {
			/*
			 * msgsize must be enough to hold
			 * krusername, lusername and a brief
			 * message describing the failure.
			 */
			msgsize = strlen(krusername) +
				strlen(lusername) + 80;
			msg_fail = (char *)malloc(msgsize);
		}
		if (msg_fail == NULL) {
			syslog(LOG_ERR, "User is not authorized to login to "
			    "specified account");

			fatal(f, "User is not authorized to login to "
			    "specified account");
		}
		if (auth_sent != 0)
			(void) snprintf(msg_fail, msgsize,
					"Access denied because of improper "
					"KRB5 credentials");
		else
			(void) snprintf(msg_fail, msgsize,
					"User %s is not authorized to login "
					"to account %s",
					krusername, lusername);
		syslog(LOG_ERR, "%s", msg_fail);
		fatal(f, msg_fail);
	}
}

/*
 * stop_stream
 *
 * Utility routine to send a CRYPTIOCSTOP ioctl to the
 * crypto module(cryptmod).
 */
static void
stop_stream(int fd, int dir)
{
	struct strioctl  crioc;
	uint32_t stopdir = dir;

	crioc.ic_cmd = CRYPTIOCSTOP;
	crioc.ic_timout = -1;
	crioc.ic_len = sizeof (stopdir);
	crioc.ic_dp = (char *)&stopdir;

	if (ioctl(fd, I_STR, &crioc))
		syslog(LOG_ERR, "Error sending CRYPTIOCSTOP ioctl: %m");
}

/*
 * start_stream
 *
 * Utility routine to send a CRYPTIOCSTART ioctl to the
 * crypto module(cryptmod).  This routine may contain optional
 * payload data that the cryptmod will interpret as bytes that
 * need to be decrypted and sent back up to the application
 * via the data stream.
 */
static void
start_stream(int fd, int dir)
{
	struct strioctl crioc;
	uint32_t iocval;
	size_t datalen = 0;
	char *data = NULL;

	if (dir == CRYPT_DECRYPT) {
		iocval = CRYPTIOCSTARTDEC;

		/* Look for data not yet processed */
		if (ioctl(fd, I_NREAD, &datalen) < 0) {
			syslog(LOG_ERR, "I_NREAD returned error %m");
			datalen = 0;
		} else {
			if (datalen > 0) {
				data = malloc(datalen);
				if (data != NULL) {
					int nbytes = read(fd, data, datalen);
					datalen = nbytes;
				} else {
					syslog(LOG_ERR,
						"malloc error (%d bytes)",
						datalen);
					datalen = 0;
				}
			} else {
				datalen = 0;
			}
		}
	} else {
		iocval = CRYPTIOCSTARTENC;
	}

	crioc.ic_cmd = iocval;
	crioc.ic_timout = -1;
	crioc.ic_len = datalen;
	crioc.ic_dp = data;

	if (ioctl(fd, I_STR, &crioc))
		syslog(LOG_ERR, "Error sending CRYPTIOCSTART ioctl: %m");

	if (data != NULL)
		free(data);
}

static int
configure_stream(int fd, krb5_keyblock *skey, int dir, krb5_data *ivec,
		uint_t iv_usage)
{
	struct cr_info_t setup_info;
	struct strioctl crioc;
	int retval = 0;

	switch (skey->enctype) {
	case ENCTYPE_DES_CBC_CRC:
		setup_info.crypto_method = CRYPT_METHOD_DES_CBC_CRC;
		break;
	case ENCTYPE_DES_CBC_MD5:
		setup_info.crypto_method = CRYPT_METHOD_DES_CBC_MD5;
		break;
	case ENCTYPE_DES_CBC_RAW:
		setup_info.crypto_method = CRYPT_METHOD_DES_CBC_NULL;
		break;
	case ENCTYPE_DES3_CBC_SHA1:
		setup_info.crypto_method = CRYPT_METHOD_DES3_CBC_SHA1;
		break;
	case ENCTYPE_ARCFOUR_HMAC:
		setup_info.crypto_method = CRYPT_METHOD_ARCFOUR_HMAC_MD5;
		break;
	case ENCTYPE_ARCFOUR_HMAC_EXP:
		setup_info.crypto_method = CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP;
		break;
	case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
		setup_info.crypto_method = CRYPT_METHOD_AES128;
		break;
	case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
		setup_info.crypto_method = CRYPT_METHOD_AES256;
		break;
	default:
		syslog(LOG_ERR, "Enctype in kerberos session key "
		    "is not supported by crypto module(%d)",
		    skey->enctype);
		return (-1);
	}
	if (ivec == NULL || ivec->length == 0) {
		(void) memset(&setup_info.ivec, 0, sizeof (setup_info.ivec));

		if (skey->enctype != ENCTYPE_ARCFOUR_HMAC &&
		    skey->enctype != ENCTYPE_ARCFOUR_HMAC_EXP)
			/* Kerberos IVs are 8 bytes long for DES keys */
			setup_info.iveclen = KRB5_MIT_DES_KEYSIZE;
		else
			setup_info.iveclen = 0;
	} else {
		(void) memcpy(&setup_info.ivec, ivec->data, ivec->length);
		setup_info.iveclen = ivec->length;
	}

	setup_info.ivec_usage = iv_usage;
	(void) memcpy(&setup_info.key, skey->contents, skey->length);

	setup_info.keylen = skey->length;
	setup_info.direction_mask = dir;
	/*
	 * R* commands get special handling by crypto module -
	 * 4 byte length field is used before each encrypted block
	 * of data.
	 */
	setup_info.option_mask = (kcmd_protocol == KCMD_OLD_PROTOCOL ?
				CRYPTOPT_RCMD_MODE_V1 :
				CRYPTOPT_RCMD_MODE_V2);

	crioc.ic_cmd = CRYPTIOCSETUP;
	crioc.ic_timout = -1;
	crioc.ic_len = sizeof (setup_info);
	crioc.ic_dp = (char *)&setup_info;

	if (ioctl(fd, I_STR, &crioc)) {
		syslog(LOG_ERR, "Error sending CRYPTIOCSETUP ioctl: %m");
		retval = -1;
	}
	return (retval);
}

static krb5_error_code
krb5_compat_recvauth(krb5_context context,
		    krb5_auth_context *auth_context,
		    krb5_pointer fdp,	/* IN */
		    krb5_principal server,	/* IN */
		    krb5_int32 flags,	/* IN */
		    krb5_keytab keytab,	/* IN */
		    krb5_ticket **ticket, /* OUT */
		    krb5_int32 *auth_sys, /* OUT */
		    krb5_data *version)   /* OUT */
{
	krb5_int32 vlen;
	char	*buf;
	int	len, length;
	krb5_int32	retval;
	int		fd = *((int *)fdp);

	if ((retval = krb5_net_read(context, fd, (char *)&vlen, 4)) != 4)
		return ((retval < 0) ? errno : ECONNABORTED);

	/*
	 * Assume that we're talking to a V5 recvauth; read in the
	 * the version string, and make sure it matches.
	 */
	len = (int)ntohl(vlen);

	if (len < 0 || len > 255)
		return (KRB5_SENDAUTH_BADAUTHVERS);

	buf = malloc(len);
	if (buf == NULL)
		return (ENOMEM);

	length = krb5_net_read(context, fd, buf, len);
	if (len != length) {
		krb5_xfree(buf);
		return ((len < 0) ? errno : ECONNABORTED);
	}

	if (strcmp(buf, KRB_V5_SENDAUTH_VERS) != 0) {
		krb5_xfree(buf);
		return (KRB5_SENDAUTH_BADAUTHVERS);
	}
	krb5_xfree(buf);

	*auth_sys = KRB5_RECVAUTH_V5;

	retval = krb5_recvauth_version(context, auth_context, fdp,
				    server, flags | KRB5_RECVAUTH_SKIP_VERSION,
				    keytab, ticket, version);

	return (retval);
}


static void
doit(int f,
	struct sockaddr_storage *fromp,
	krb5_context krb_context,
	int encr_flag,
	krb5_keytab keytab)
{
	int p, t, on = 1;
	char c;
	char abuf[INET6_ADDRSTRLEN];
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	int fromplen;
	in_port_t port;
	struct termios tp;
	boolean_t bad_port;
	boolean_t no_name;
	char rhost_addra[INET6_ADDRSTRLEN];

	if (!(rlbuf = malloc(BUFSIZ))) {
		syslog(LOG_ERR, "rlbuf malloc failed\n");
		exit(EXIT_FAILURE);
	}
	(void) alarm(60);
	if (read(f, &c, 1) != 1 || c != 0) {
		syslog(LOG_ERR, "failed to receive protocol zero byte\n");
		exit(EXIT_FAILURE);
	}
	(void) alarm(0);
	if (fromp->ss_family == AF_INET) {
		sin = (struct sockaddr_in *)fromp;
		port = sin->sin_port = ntohs((ushort_t)sin->sin_port);
		fromplen = sizeof (struct sockaddr_in);

		if (!inet_ntop(AF_INET, &sin->sin_addr,
			    rhost_addra, sizeof (rhost_addra)))
			goto badconversion;
	} else if (fromp->ss_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)fromp;
		port = sin6->sin6_port = ntohs((ushort_t)sin6->sin6_port);
		fromplen = sizeof (struct sockaddr_in6);

		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			struct in_addr ipv4_addr;

			IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr,
					    &ipv4_addr);
			if (!inet_ntop(AF_INET, &ipv4_addr, rhost_addra,
				    sizeof (rhost_addra)))
				goto badconversion;
		} else {
			if (!inet_ntop(AF_INET6, &sin6->sin6_addr,
				    rhost_addra, sizeof (rhost_addra)))
				goto badconversion;
		}
	} else {
		syslog(LOG_ERR, "unknown address family %d\n",
		    fromp->ss_family);
		fatal(f, "Permission denied");
	}

	/*
	 * Allow connections only from the "ephemeral" reserved
	 * ports(ports 512 - 1023) by checking the remote port
	 * because other utilities(e.g. in.ftpd) can be used to
	 * allow a unprivileged user to originate a connection
	 * from a privileged port and provide untrustworthy
	 * authentication.
	 */
	bad_port = (use_auth != KRB5_RECVAUTH_V5 &&
		    (port >= (in_port_t)IPPORT_RESERVED) ||
		    (port < (in_port_t)(IPPORT_RESERVED/2)));
	no_name = getnameinfo((const struct sockaddr *) fromp,
			    fromplen, hostname, sizeof (hostname),
			    NULL, 0, 0) != 0;

	if (no_name || bad_port) {
		(void) strlcpy(abuf, rhost_addra, sizeof (abuf));
		/* If no host name, use IP address for name later on. */
		if (no_name)
			(void) strlcpy(hostname, abuf, sizeof (hostname));
	}

	if (!no_name) {
		/*
		 * Even if getnameinfo() succeeded, we still have to check
		 * for spoofing.
		 */
		check_address("rlogind", fromp, sin, sin6, rhost_addra,
		    hostname, sizeof (hostname));
	}

	if (bad_port) {
		if (no_name)
			syslog(LOG_NOTICE,
			    "connection from %s - bad port\n",
			    abuf);
		else
			syslog(LOG_NOTICE,
			    "connection from %s(%s) - bad port\n",
			    hostname, abuf);
		fatal(f, "Permission denied");
	}

	if (use_auth == KRB5_RECVAUTH_V5) {
		do_krb_login(f, rhost_addra, hostname,
			    krb_context, encr_flag, keytab);
		if (krusername != NULL && strlen(krusername)) {
			/*
			 * Kerberos Authentication succeeded,
			 * so set the proper program name to use
			 * with pam (important during 'cleanup'
			 * routine later).
			 */
			pam_prog_name = KRB5_PROG_NAME;
		}
	}

	if (write(f, "", 1) != 1) {
		syslog(LOG_NOTICE,
		    "send of the zero byte(to %s) failed:"
		    " cannot start data transfer mode\n",
		    (no_name ? abuf : hostname));
		exit(EXIT_FAILURE);
	}
	if ((p = open("/dev/ptmx", O_RDWR)) == -1)
		fatalperror(f, "cannot open /dev/ptmx");
	if (grantpt(p) == -1)
		fatal(f, "could not grant subsidiary pty");
	if (unlockpt(p) == -1)
		fatal(f, "could not unlock subsidiary pty");
	if ((line = ptsname(p)) == NULL)
		fatal(f, "could not enable subsidiary pty");
	if ((t = open(line, O_RDWR)) == -1)
		fatal(f, "could not open subsidiary pty");
	if (ioctl(t, I_PUSH, "ptem") == -1)
		fatalperror(f, "ioctl I_PUSH ptem");
	if (ioctl(t, I_PUSH, "ldterm") == -1)
		fatalperror(f, "ioctl I_PUSH ldterm");
	if (ioctl(t, I_PUSH, "ttcompat") == -1)
		fatalperror(f, "ioctl I_PUSH ttcompat");
	/*
	 * POP the sockmod and push the rlmod module.
	 *
	 * Note that sockmod has to be removed since readstream assumes
	 * a "raw" TPI endpoint(e.g. it uses getmsg).
	 */
	if (removemod(f, "sockmod") < 0)
		fatalperror(f, "couldn't remove sockmod");

	if (encr_flag) {
		if (ioctl(f, I_PUSH, "cryptmod") < 0)
		    fatalperror(f, "ioctl I_PUSH rlmod");

	}

	if (ioctl(f, I_PUSH, "rlmod") < 0)
		fatalperror(f, "ioctl I_PUSH rlmod");

	if (encr_flag) {
		/*
		 * Make sure rlmod will pass unrecognized IOCTLs to cryptmod
		 */
		uchar_t passthru = 1;
		struct strioctl rlmodctl;

		rlmodctl.ic_cmd = CRYPTPASSTHRU;
		rlmodctl.ic_timout = -1;
		rlmodctl.ic_len = sizeof (uchar_t);
		rlmodctl.ic_dp = (char *)&passthru;

		if (ioctl(f, I_STR, &rlmodctl) < 0)
			fatal(f, "ioctl CRYPTPASSTHRU failed\n");
	}

	/*
	 * readstream will do a getmsg till it receives
	 * M_PROTO type T_DATA_REQ from rloginmodopen()
	 * indicating all data on the stream prior to pushing rlmod has
	 * been drained at the stream head.
	 */
	if ((nsize = readstream(f, rlbuf, BUFSIZ)) < 0)
		fatalperror(f, "readstream failed");
	/*
	 * Make sure the pty doesn't modify the strings passed
	 * to login as part of the "rlogin protocol."  The login
	 * program should set these flags to apropriate values
	 * after it has read the strings.
	 */
	if (ioctl(t, TCGETS, &tp) == -1)
		fatalperror(f, "ioctl TCGETS");
	tp.c_lflag &= ~(ECHO|ICANON);
	tp.c_oflag &= ~(XTABS|OCRNL);
	tp.c_iflag &= ~(IGNPAR|ICRNL);
	if (ioctl(t, TCSETS, &tp) == -1)
		fatalperror(f, "ioctl TCSETS");

	/*
	 * System V ptys allow the TIOC{SG}WINSZ ioctl to be
	 * issued on the manager side of the pty.  Luckily, that's
	 * the only tty ioctl we need to do do, so we can close the
	 * subsidiary side in the parent process after the fork.
	 */
	(void) ioctl(p, TIOCSWINSZ, &win);

	pid = fork();
	if (pid < 0)
		fatalperror(f, "fork");
	if (pid == 0) {
		int tt;
		struct utmpx ut;

		/* System V login expects a utmp entry to already be there */
		(void) memset(&ut, 0, sizeof (ut));
		(void) strncpy(ut.ut_user, ".rlogin", sizeof (ut.ut_user));
		(void) strncpy(ut.ut_line, line, sizeof (ut.ut_line));
		ut.ut_pid = getpid();
		ut.ut_id[0] = 'r';
		ut.ut_id[1] = (char)SC_WILDC;
		ut.ut_id[2] = (char)SC_WILDC;
		ut.ut_id[3] = (char)SC_WILDC;
		ut.ut_type = LOGIN_PROCESS;
		ut.ut_exit.e_termination = 0;
		ut.ut_exit.e_exit = 0;
		(void) time(&ut.ut_tv.tv_sec);
		if (makeutx(&ut) == NULL)
			syslog(LOG_INFO, "in.rlogind:\tmakeutx failed");

		/* controlling tty */
		if (setsid() == -1)
			fatalperror(f, "setsid");
		if ((tt = open(line, O_RDWR)) == -1)
			fatalperror(f, "could not re-open subsidiary pty");

		if (close(p) == -1)
			fatalperror(f, "error closing pty manager");
		if (close(t) == -1)
			fatalperror(f, "error closing pty subsidiary"
				    " opened before session established");
		/*
		 * If this fails we may or may not be able to output an
		 * error message.
		 */
		if (close(f) == -1)
			fatalperror(f, "error closing deamon stdout");
		if (dup2(tt, STDIN_FILENO) == -1 ||
		    dup2(tt, STDOUT_FILENO) == -1 ||
		    dup2(tt, STDERR_FILENO) == -1)
			exit(EXIT_FAILURE);	/* Disaster! No stderr! */

		(void) close(tt);

		if (use_auth == KRB5_RECVAUTH_V5 &&
		    krusername != NULL && strlen(krusername)) {
			(void) execl(LOGIN_PROGRAM, "login",
				    "-d", line,
				    "-r", hostname,
				    "-u", krusername, /* KRB5 principal name */
				    "-s", pam_prog_name,
				    "-t", term,	/* Remote Terminal */
				    "-U", rusername,	/* Remote User */
				    "-R", KRB5_REPOSITORY_NAME,
				    lusername,  /* local user */
				    NULL);
		} else {
			(void) execl(LOGIN_PROGRAM, "login",
				"-d", line,
				"-r", hostname,
				NULL);
		}

		fatalperror(STDERR_FILENO, "/bin/login");
		/*NOTREACHED*/
	}
	(void) close(t);
	(void) ioctl(f, FIONBIO, &on);
	(void) ioctl(p, FIONBIO, &on);

	/*
	 * Must ignore SIGTTOU, otherwise we'll stop
	 * when we try and set subsidiary pty's window shape
	 * (our controlling tty is the manager pty).
	 * Likewise, we don't want any of the tty-generated
	 * signals from chars passing through.
	 */
	(void) sigset(SIGTSTP, SIG_IGN);
	(void) sigset(SIGINT, SIG_IGN);
	(void) sigset(SIGQUIT, SIG_IGN);
	(void) sigset(SIGTTOU, SIG_IGN);
	(void) sigset(SIGTTIN, SIG_IGN);
	(void) sigset(SIGCHLD, cleanup);
	(void) setpgrp();

	if (encr_flag) {
		krb5_data ivec, *ivptr;
		uint_t ivec_usage;
		stop_stream(f, CRYPT_ENCRYPT|CRYPT_DECRYPT);

		/*
		 * Configure the STREAMS crypto module.  For now,
		 * don't use any IV parameter.  KCMDV0.2 support
		 * will require the use of Initialization Vectors
		 * for both encrypt and decrypt modes.
		 */
		if (kcmd_protocol == KCMD_OLD_PROTOCOL) {
			if (session_key->enctype == ENCTYPE_DES_CBC_CRC) {
				/*
				 * This is gross but necessary for MIT compat.
				 */
				ivec.length = session_key->length;
				ivec.data = (char *)session_key->contents;
				ivec_usage = IVEC_REUSE;
				ivptr = &ivec;
			} else {
				ivptr = NULL; /* defaults to all 0's */
				ivec_usage = IVEC_NEVER;
			}
			/*
			 * configure both sides of stream together
			 * since they share the same IV.
			 * This is what makes the OLD KCMD protocol
			 * less secure than the newer one - Bad ivecs.
			 */
			if (configure_stream(f, session_key,
				CRYPT_ENCRYPT|CRYPT_DECRYPT,
				ivptr, ivec_usage) != 0)
				fatal(f, "Cannot initialize encryption -"
					" exiting.\n");
		} else {
			size_t blocksize;
			if (session_key->enctype == ENCTYPE_ARCFOUR_HMAC ||
			    session_key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
				if (configure_stream(f, session_key,
					CRYPT_ENCRYPT|CRYPT_DECRYPT,
					NULL, IVEC_NEVER) != 0)
					fatal(f,
					"Cannot initialize encryption -"
					" exiting.\n");
				goto startcrypto;
			}
			if (krb5_c_block_size(krb_context,
					    session_key->enctype,
					    &blocksize)) {
				syslog(LOG_ERR, "Cannot determine blocksize "
				    "for encryption type %d",
				    session_key->enctype);
				fatal(f, "Cannot determine blocksize "
				    "for encryption - exiting.\n");
			}
			ivec.data = (char *)malloc(blocksize);
			ivec.length = blocksize;
			if (ivec.data == NULL)
				fatal(f, "memory error - exiting\n");
			/*
			 * Following MIT convention -
			 *   encrypt IV = 0x01 x blocksize
			 *   decrypt IV = 0x00 x blocksize
			 *   ivec_usage = IVEC_ONETIME
			 *
			 * configure_stream separately for encrypt and
			 * decrypt because there are 2 different IVs.
			 *
			 * AES uses 0's for IV.
			 */
			if (session_key->enctype ==
				ENCTYPE_AES128_CTS_HMAC_SHA1_96 ||
			    session_key->enctype ==
				ENCTYPE_AES256_CTS_HMAC_SHA1_96)
				(void) memset(ivec.data, 0x00, blocksize);
			else
				(void) memset(ivec.data, 0x01, blocksize);
			if (configure_stream(f, session_key, CRYPT_ENCRYPT,
				&ivec, IVEC_ONETIME) != 0)
				fatal(f, "Cannot initialize encryption -"
					" exiting.\n");
			(void) memset(ivec.data, 0x00, blocksize);
			if (configure_stream(f, session_key, CRYPT_DECRYPT,
				&ivec, IVEC_ONETIME) != 0)
				fatal(f, "Cannot initialize encryption -"
					" exiting.\n");

			(void) free(ivec.data);
		}
startcrypto:
		start_stream(f, CRYPT_ENCRYPT);
		start_stream(f, CRYPT_DECRYPT);
	}
	protocol(f, p, encr_flag);
	cleanup(0);
	/*NOTREACHED*/

badconversion:
	fatalperror(f, "address conversion");
	/*NOTREACHED*/
}

/*
 * rlogin "protocol" machine.
 */
static void
protocol(int f, int p, int encr_flag)
{
	struct	stat	buf;
	struct	protocol_arg	rloginp;
	struct	strioctl	rloginmod;
	int	ptmfd;	/* fd of logindmux coneected to ptmx */
	int	netfd;	/* fd of logindmux connected to netf */
	static uchar_t	oobdata[] = {TIOCPKT_WINDOW};

	/* indicate new rlogin */
	if (send_oob(f, oobdata, 1) < 0)
		fatalperror(f, "send_oob");
	/*
	 * We cannot send the SECURE_MSG until after the
	 * client has been signaled with the oobdata (above).
	 */
	if (encr_flag) {
		if (write(f, SECURE_MSG, strlen(SECURE_MSG)) < 0)
			fatalperror(f, "Error writing SECURE message");
	}

	/*
	 * Open logindmux driver and link netf and ptmx
	 * underneath logindmux.
	 */
	if ((ptmfd = open("/dev/logindmux", O_RDWR)) == -1)
		fatalperror(f, "open /dev/logindmux");

	if ((netfd = open("/dev/logindmux", O_RDWR)) == -1)
		fatalperror(f, "open /dev/logindmux");

	if (ioctl(ptmfd, I_LINK, p) < 0)
		fatal(f, "ioctl I_LINK of /dev/ptmx failed\n");

	if (ioctl(netfd, I_LINK, f) < 0)
		fatal(f, "ioctl I_LINK of tcp connection failed\n");

	/*
	 * Figure out the device number of the ptm's mux fd, and pass that
	 * to the net's mux.
	 */
	if (fstat(ptmfd, &buf) < 0)
		fatalperror(f, "cannot determine device number"
		    " of pty side of /dev/logindmux");
	rloginp.dev = buf.st_rdev;
	rloginp.flag = 0;

	rloginmod.ic_cmd = LOGDMX_IOC_QEXCHANGE;
	rloginmod.ic_timout = -1;
	rloginmod.ic_len = sizeof (struct protocol_arg);
	rloginmod.ic_dp = (char *)&rloginp;

	if (ioctl(netfd, I_STR, &rloginmod) < 0)
		fatal(netfd, "ioctl LOGDMX_IOC_QEXCHANGE of netfd failed\n");

	/*
	 * Figure out the device number of the net's mux fd, and pass that
	 * to the ptm's mux.
	 */
	if (fstat(netfd, &buf))
		fatalperror(f, "cannot determine device number"
		    " of network side of /dev/logindmux");
	rloginp.dev = buf.st_rdev;
	rloginp.flag = 1;

	rloginmod.ic_cmd = LOGDMX_IOC_QEXCHANGE;
	rloginmod.ic_timout = -1;
	rloginmod.ic_len = sizeof (struct protocol_arg);
	rloginmod.ic_dp = (char *)&rloginp;

	if (ioctl(ptmfd, I_STR, &rloginmod) < 0)
		fatal(netfd, "ioctl LOGDMXZ_IOC_QEXCHANGE of ptmfd failed\n");
	/*
	 * Send an ioctl type RL_IOC_ENABLE to reenable the
	 * message queue and reinsert the data read from streamhead
	 * at the time of pushing rloginmod module.
	 * We need to send this ioctl even if no data was read earlier
	 * since we need to reenable the message queue of rloginmod module.
	 */
	rloginmod.ic_cmd = RL_IOC_ENABLE;
	rloginmod.ic_timout = -1;
	if (nsize) {
		rloginmod.ic_len = nsize;
		rloginmod.ic_dp = rlbuf;
	} else {
		rloginmod.ic_len = 0;
		rloginmod.ic_dp = NULL;
	}

	if (ioctl(netfd, I_STR, &rloginmod) < 0)
		fatal(netfd, "ioctl RL_IOC_ENABLE of netfd failed\n");

	/*
	 * User level daemon now pauses till the shell exits.
	 */
	(void) pause();
}

/* This is a signal handler, hence the dummy argument */
/*ARGSUSED*/
static void
cleanup(int dummy)
{
	rmut();
	exit(EXIT_FAILURE);
	/*NOTREACHED*/
}

/*
 * TPI style replacement for socket send() primitive, so we don't require
 * sockmod to be on the stream.
 */
static int
send_oob(int fd, void *ptr, size_t count)
{
	struct T_exdata_req exd_req;
	struct strbuf hdr, dat;
	int ret;

	exd_req.PRIM_type = T_EXDATA_REQ;
	exd_req.MORE_flag = 0;

	hdr.buf = (char *)&exd_req;
	hdr.len = sizeof (exd_req);

	dat.buf = ptr;
	dat.len = count;

	ret = putmsg(fd, &hdr, &dat, 0);
	if (ret == 0)
		ret = count;
	return (ret);
}

static void
fatal(int fd, const char *msg)
{
	char *bufp;
	size_t len = strlen(msg) + 16;		/* enough for our wrapper */

	bufp = alloca(len);
	/* ASCII 001 is the error indicator */
	len = snprintf(bufp, len, "\01rlogind: %s.\r\n", msg);
	(void) write(fd, bufp, len);
	exit(EXIT_FAILURE);
	/*NOTREACHED*/
}

/*PRINTFLIKE2*/
static void
fatalperror(int fd, const char *msg)
{
	char *bufp;
	const char *errstr;
	int save_errno = errno;
	size_t len = strlen(msg);

	if ((errstr = strerror(save_errno))) {
		len += strlen(errstr) + 3;	/* 3 for ": " and \0 below */
		bufp = alloca(len);
		(void) snprintf(bufp, len, "%s: %s", msg, errstr);
	} else {
		const char fmt[] = "%s: Error %d";

		/* -4 for %s & %d. "*8/3" is bytes->decimal, pessimistically */
		len += sizeof (fmt) -4 + (sizeof (save_errno) *8 /3);
		bufp = alloca(len);
		(void) snprintf(bufp, len, fmt, msg, save_errno);
	}
	fatal(fd, bufp);
	/*NOTREACHED*/
}

static void
rmut(void)
{
	pam_handle_t *pamh;
	struct utmpx *up;
	char user[sizeof (up->ut_user) + 1];
	char ttyn[sizeof (up->ut_line) + 1];
	char rhost[sizeof (up->ut_host) + 1];

	/* while cleaning up dont allow disruption */
	(void) sigset(SIGCHLD, SIG_IGN);

	setutxent();
	while (up = getutxent()) {
		if (up->ut_pid == pid) {
			if (up->ut_type == DEAD_PROCESS)
				break;		/* Cleaned up elsewhere. */

			/*
			 * call pam_close_session if login changed
			 * the utmpx user entry from type LOGIN_PROCESS
			 * to type USER_PROCESS, which happens
			 * after pam_open_session is called.
			 */
			if (up->ut_type == USER_PROCESS) {
				(void) strlcpy(user, up->ut_user,
					    sizeof (user));
				(void) strlcpy(ttyn, up->ut_line,
					    sizeof (ttyn));
				(void) strlcpy(rhost, up->ut_host,
					    sizeof (rhost));

				/*
				 * Use the same pam_prog_name that
				 * 'login' used.
				 */
				if ((pam_start(pam_prog_name, user,  NULL,
					    &pamh))
				    == PAM_SUCCESS) {
					(void) pam_set_item(pamh, PAM_TTY,
							    ttyn);
					(void) pam_set_item(pamh, PAM_RHOST,
							    rhost);
					(void) pam_close_session(pamh, 0);
					(void) pam_end(pamh, PAM_SUCCESS);
				}
			}

			up->ut_type = DEAD_PROCESS;
			up->ut_exit.e_termination = WTERMSIG(0);
			up->ut_exit.e_exit = WEXITSTATUS(0);
			(void) time(&up->ut_tv.tv_sec);

			if (modutx(up) == NULL) {
				/*
				 * Since modutx failed we'll
				 * write out the new entry
				 * ourselves.
				 */
				(void) pututxline(up);
				updwtmpx("wtmpx", up);
			}
			break;
		}
	}

	endutxent();

	(void) sigset(SIGCHLD, cleanup);
}

static int
readstream(int fd, char *buf, int size)
{
	struct strbuf ctlbuf, datbuf;
	union T_primitives tpi;
	int	nbytes = 0;
	int	ret = 0;
	int	flags = 0;
	int	bufsize = size;
	int	nread;

	(void) memset(&ctlbuf, 0, sizeof (ctlbuf));
	(void) memset(&datbuf, 0, sizeof (datbuf));

	ctlbuf.buf = (char *)&tpi;
	ctlbuf.maxlen = sizeof (tpi);
	datbuf.buf = buf;
	datbuf.maxlen = size;

	for (;;) {
		if (ioctl(fd, I_NREAD, &nread) < 0) {
			syslog(LOG_ERR, "I_NREAD returned error %m");
			return (-1);
		}
		if (nread + nbytes > bufsize) {
			buf = (char *)realloc(buf, (unsigned)(bufsize + nread));
			if (buf == NULL) {
				syslog(LOG_WARNING,
				    "buffer allocation failed\n");
				return (-1);
			}
			bufsize += nread;
			rlbuf = buf;
			datbuf.buf = buf + nbytes;
		}
		datbuf.maxlen = bufsize - nbytes;
		ret = getmsg(fd, &ctlbuf, &datbuf, &flags);
		if (ret < 0) {
			syslog(LOG_ERR, "getmsg failed error %m");
			return (-1);
		}
		if ((ctlbuf.len == 0) && (datbuf.len == 0)) {
			/*
			 * getmsg() returned no data - this indicates
			 * that the connection is closing down.
			 */
			cleanup(0);
		}
		if (ctlbuf.len <= 0) {
			nbytes += datbuf.len;
			datbuf.buf += datbuf.len;
			continue;
		}
		if (tpi.type == T_DATA_REQ) {
			return (nbytes);
		}
		if ((tpi.type == T_ORDREL_IND) || (tpi.type == T_DISCON_IND))
			cleanup(0);
	}
}

/*
 * Verify that the named module is at the top of the stream
 * and then pop it off.
 */
static int
removemod(int f, char *modname)
{
	char topmodname[BUFSIZ];

	if (ioctl(f, I_LOOK, topmodname) < 0)
		return (-1);
	if (strcmp(modname, topmodname) != 0) {
		errno = ENXIO;
		return (-1);
	}
	if (ioctl(f, I_POP, 0) < 0)
		return (-1);
	return (0);
}
