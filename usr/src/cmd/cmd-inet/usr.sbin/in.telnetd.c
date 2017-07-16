/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California.
 * All Rights Reserved.
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Telnet server.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/filio.h>
#include <sys/time.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/tihdr.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <netinet/in.h>

#define	AUTHWHO_STR
#define	AUTHTYPE_NAMES
#define	AUTHHOW_NAMES
#define	AUTHRSP_NAMES
#define	ENCRYPT_NAMES

#include <arpa/telnet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <syslog.h>
#include <ctype.h>
#include <fcntl.h>
#include <sac.h>	/* for SC_WILDC */
#include <utmpx.h>
#include <sys/ttold.h>
#include <malloc.h>
#include <string.h>
#include <security/pam_appl.h>
#include <sys/tihdr.h>
#include <sys/logindmux.h>
#include <sys/telioctl.h>
#include <deflt.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <termios.h>

#include <com_err.h>
#include <krb5.h>
#include <krb5_repository.h>
#include <des/des.h>
#include <rpc/des_crypt.h>
#include <sys/cryptmod.h>
#include <bsm/adt.h>

#define	TELNETD_OPTS "Ss:a:dEXUhR:M:"
#ifdef DEBUG
#define	DEBUG_OPTS "p:e"
#else
#define	DEBUG_OPTS ""
#endif /* DEBUG */

#define	OPT_NO			0		/* won't do this option */
#define	OPT_YES			1		/* will do this option */
#define	OPT_YES_BUT_ALWAYS_LOOK	2
#define	OPT_NO_BUT_ALWAYS_LOOK	3

#define	MAXOPTLEN 256
#define	MAXUSERNAMELEN 256

static char	remopts[MAXOPTLEN];
static char	myopts[MAXOPTLEN];
static uchar_t	doopt[] = { (uchar_t)IAC, (uchar_t)DO, '%', 'c', 0 };
static uchar_t	dont[] = { (uchar_t)IAC, (uchar_t)DONT, '%', 'c', 0 };
static uchar_t	will[] = { (uchar_t)IAC, (uchar_t)WILL, '%', 'c', 0 };
static uchar_t	wont[] = { (uchar_t)IAC, (uchar_t)WONT, '%', 'c', 0 };
/*
 * I/O data buffers, pointers, and counters.
 */
static char	ptyobuf[BUFSIZ], *pfrontp = ptyobuf, *pbackp = ptyobuf;

static char	*netibuf, *netip;
static int	netibufsize;

#define	NIACCUM(c)	{   *netip++ = c; \
			    ncc++; \
			}

static char	netobuf[BUFSIZ], *nfrontp = netobuf, *nbackp = netobuf;
static char	*neturg = 0;		/* one past last bye of urgent data */
/* the remote system seems to NOT be an old 4.2 */
static int	not42 = 1;
static char	defaultfile[] = "/etc/default/telnetd";
static char	bannervar[] = "BANNER=";

static char BANNER1[] = "\r\n\r\n";
static char BANNER2[] = "\r\n\r\0\r\n\r\0";

/*
 * buffer for sub-options - enlarged to 4096 to handle credentials
 * from AUTH options
 */
static char	subbuffer[4096], *subpointer = subbuffer, *subend = subbuffer;
#define	SB_CLEAR()	subpointer = subbuffer;
#define	SB_TERM()	{ subend = subpointer; SB_CLEAR(); }
#define	SB_ACCUM(c)	if (subpointer < (subbuffer+sizeof (subbuffer))) { \
				*subpointer++ = (c); \
			}
#define	SB_GET()	((*subpointer++)&0xff)
#define	SB_EOF()	(subpointer >= subend)
#define	SB_LEN()	(subend - subpointer)

#define	MAXERRSTRLEN 1024
#define	MAXPRINCLEN 256

extern uint_t kwarn_add_warning(char *, int);
extern uint_t kwarn_del_warning(char *);

static boolean_t auth_debug = 0;
static boolean_t negotiate_auth_krb5 = 1;
static boolean_t auth_negotiated = 0;
static int auth_status = 0;
static int auth_level = 0;
static char	*AuthenticatingUser = NULL;
static char	*krb5_name = NULL;

static krb5_address rsaddr = { 0, 0, 0, NULL };
static krb5_address rsport = { 0, 0, 0, NULL };

static krb5_context telnet_context = 0;
static krb5_auth_context auth_context = 0;

/* telnetd gets session key from here */
static krb5_ticket *ticket = NULL;
static krb5_keyblock *session_key = NULL;
static char *telnet_srvtab = NULL;

typedef struct {
	uchar_t AuthName;
	uchar_t AuthHow;
	char  *AuthString;
} AuthInfo;

static AuthInfo auth_list[] = {
	{AUTHTYPE_KERBEROS_V5, AUTH_WHO_CLIENT | AUTH_HOW_MUTUAL |
	AUTH_ENCRYPT_ON, "KRB5 MUTUAL CRYPTO"},
	{AUTHTYPE_KERBEROS_V5, AUTH_WHO_CLIENT | AUTH_HOW_MUTUAL,
	"KRB5 MUTUAL" },
	{AUTHTYPE_KERBEROS_V5,	AUTH_WHO_CLIENT | AUTH_HOW_ONE_WAY,
	"KRB5 1-WAY" },
	{0, 0, "NONE"}
};

static AuthInfo NoAuth = {0, 0, NULL};

static AuthInfo *authenticated = NULL;

#define	PREAMBLE_SIZE		5	/* for auth_reply_str allocation */
#define	POSTAMBLE_SIZE		5
#define	STR_DATA_LEN(len)	((len) * 2 + PREAMBLE_SIZE + POSTAMBLE_SIZE)

static void auth_name(uchar_t *, int);
static void auth_is(uchar_t *, int);

#define	NO_ENCRYPTION   0x00
#define	SEND_ENCRYPTED  0x01
#define	RECV_ENCRYPTED  0x02
#define	ENCRYPT_BOTH_WAYS    (SEND_ENCRYPTED | RECV_ENCRYPTED)

static telnet_enc_data_t  encr_data;
static boolean_t negotiate_encrypt = B_TRUE;
static boolean_t sent_encrypt_support = B_FALSE;
static boolean_t sent_will_encrypt = B_FALSE;
static boolean_t sent_do_encrypt = B_FALSE;
static boolean_t enc_debug = 0;

static void encrypt_session_key(Session_Key *key, cipher_info_t *cinfo);
static int  encrypt_send_encrypt_is();

extern void mit_des_fixup_key_parity(Block);
extern int krb5_setenv(const char *, const char *, int);
/* need to know what FD to use to talk to the crypto module */
static int cryptmod_fd = -1;

#define	LOGIN_PROGRAM "/bin/login"

/*
 * State for recv fsm
 */
#define	TS_DATA		0	/* base state */
#define	TS_IAC		1	/* look for double IAC's */
#define	TS_CR		2	/* CR-LF ->'s CR */
#define	TS_SB		3	/* throw away begin's... */
#define	TS_SE		4	/* ...end's (suboption negotiation) */
#define	TS_WILL		5	/* will option negotiation */
#define	TS_WONT		6	/* wont " */
#define	TS_DO		7	/* do " */
#define	TS_DONT		8	/* dont " */

static int	ncc;
static int	master;		/* master side of pty */
static int	pty;		/* side of pty that gets ioctls */
static int	net;
static int	inter;
extern char **environ;
static char	*line;
static int	SYNCHing = 0;		/* we are in TELNET SYNCH mode */
static int	state = TS_DATA;

static int env_ovar = -1;	/* XXX.sparker */
static int env_ovalue = -1;	/* XXX.sparker */
static char pam_svc_name[64];
static boolean_t	telmod_init_done = B_FALSE;

static void	doit(int, struct sockaddr_storage *);
static void	willoption(int);
static void	wontoption(int);
static void	dooption(int);
static void	dontoption(int);
static void	fatal(int, char *);
static void	fatalperror(int, char *, int);
static void	mode(int, int);
static void	interrupt(void);
static void	drainstream(int);
static int	readstream(int, char *, int);
static int	send_oob(int fd, char *ptr, int count);
static int	local_setenv(const char *name, const char *value, int rewrite);
static void	local_unsetenv(const char *name);
static void	suboption(void);
static int	removemod(int f, char *modname);
static void	willoption(int option);
static void	wontoption(int option);
static void	dooption(int option);
static void	dontoption(int option);
static void	write_data(const char *, ...);
static void	write_data_len(const char *, int);
static void	rmut(void);
static void	cleanup(int);
static void	telnet(int, int);
static void	telrcv(void);
static void	sendbrk(void);
static void	ptyflush(void);
static void	netclear(void);
static void	netflush(void);
static void	showbanner(void);
static void	map_banner(char *);
static void	defbanner(void);
static void ttloop(void);

/*
 * The env_list linked list is used to store the environment variables
 * until the final exec of login.  A malevolent client might try to
 * send an environment variable intended to affect the telnet daemon's
 * execution.  Right now the BANNER expansion is the only instance.
 * Note that it is okay to pass the environment variables to login
 * because login protects itself against environment variables mischief.
 */

struct envlist {
	struct envlist	*next;
	char		*name;
	char		*value;
	int		delete;
};

static struct envlist *envlist_head = NULL;

/*
 * The following are some clocks used to decide how to interpret
 * the relationship between various variables.
 */

static struct {
	int
	system,			/* what the current time is */
	echotoggle,		/* last time user entered echo character */
	modenegotiated,		/* last time operating mode negotiated */
	didnetreceive,		/* last time we read data from network */
	ttypeopt,		/* ttype will/won't received */
	ttypesubopt,		/* ttype subopt is received */
	getterminal,		/* time started to get terminal information */
	xdisplocopt,		/* xdisploc will/wont received */
	xdisplocsubopt,		/* xdisploc suboption received */
	nawsopt,		/* window size will/wont received */
	nawssubopt,		/* window size received */
	environopt,		/* environment option will/wont received */
	oenvironopt,		/* "old" environ option will/wont received */
	environsubopt,		/* environment option suboption received */
	oenvironsubopt,		/* "old environ option suboption received */
	gotDM;			/* when did we last see a data mark */

	int getauth;
	int authopt;	/* Authentication option negotiated */
	int authdone;

	int getencr;
	int encropt;
	int encr_support;
} clocks;

static int init_neg_done = 0;
static boolean_t resolve_hostname = 0;
static boolean_t show_hostinfo = 1;

#define	settimer(x)	(clocks.x = ++clocks.system)
#define	sequenceIs(x, y)	(clocks.x < clocks.y)

static void send_will(int);
static void send_wont(int);
static void send_do(int);
static char *__findenv(const char *name, int *offset);

/* ARGSUSED */
static void
auth_finished(AuthInfo *ap, int result)
{
	if ((authenticated = ap) == NULL) {
		authenticated = &NoAuth;
		if (myopts[TELOPT_ENCRYPT] == OPT_YES)
			send_wont(TELOPT_ENCRYPT);
		myopts[TELOPT_ENCRYPT] = remopts[TELOPT_ENCRYPT] = OPT_NO;
		encr_data.encrypt.autoflag = 0;
	} else if (result != AUTH_REJECT &&
		myopts[TELOPT_ENCRYPT] == OPT_YES &&
		remopts[TELOPT_ENCRYPT] == OPT_YES) {

		/*
		 * Authentication successful, so we have a session key, and
		 * we're willing to do ENCRYPT, so send our ENCRYPT SUPPORT.
		 *
		 * Can't have sent ENCRYPT SUPPORT yet!  And if we're sending it
		 * now it's really only because we did the DO ENCRYPT/WILL
		 * ENCRYPT dance before authentication, which is ok, but not too
		 * bright since we have to do the DONT ENCRYPT/WONT ENCRYPT
		 * dance if authentication fails, though clients typically just
		 * don't care.
		 */
		write_data("%c%c%c%c%c%c%c",
			(uchar_t)IAC,
			(uchar_t)SB,
			(uchar_t)TELOPT_ENCRYPT,
			(uchar_t)ENCRYPT_SUPPORT,
			(uchar_t)TELOPT_ENCTYPE_DES_CFB64,
			(uchar_t)IAC,
			(uchar_t)SE);

		netflush();

		sent_encrypt_support = B_TRUE;

		if (enc_debug)
			(void) fprintf(stderr,
			"SENT ENCRYPT SUPPORT\n");

		(void) encrypt_send_encrypt_is();
	}

	auth_status = result;

	settimer(authdone);
}

static void
reply_to_client(AuthInfo *ap, int type, void *data, int len)
{
	uchar_t reply[BUFSIZ];
	uchar_t *p = reply;
	uchar_t *cd = (uchar_t *)data;

	if (len == -1 && data != NULL)
		len = strlen((char *)data);
	else if (len > (sizeof (reply) - 9)) {
		syslog(LOG_ERR,
		    "krb5 auth reply length too large (%d)", len);
		if (auth_debug)
			(void) fprintf(stderr,
				    "krb5 auth reply length too large (%d)\n",
				    len);
		return;
	} else if (data == NULL)
		len = 0;

	*p++ = IAC;
	*p++ = SB;
	*p++ = TELOPT_AUTHENTICATION;
	*p++ = AUTHTYPE_KERBEROS_V5;
	*p++ = ap->AuthName;
	*p++ = ap->AuthHow; /* MUTUAL, ONE-WAY, etc */
	*p++ = type;	    /* RESPONSE or ACCEPT */
	while (len-- > 0) {
		if ((*p++ = *cd++) == IAC)
			*p++ = IAC;
	}
	*p++ = IAC;
	*p++ = SE;

	/* queue the data to be sent */
	write_data_len((const char *)reply, p-reply);

#if defined(AUTHTYPE_NAMES) && defined(AUTHWHO_STR) &&\
defined(AUTHHOW_NAMES) && defined(AUTHRSP_NAMES)
	if (auth_debug) {
		(void) fprintf(stderr, "SENT TELOPT_AUTHENTICATION REPLY "
			    "%s %s|%s %s\n",
			    AUTHTYPE_NAME(ap->AuthName),
			    AUTHWHO_NAME(ap->AuthHow & AUTH_WHO_MASK),
			    AUTHHOW_NAME(ap->AuthHow & AUTH_HOW_MASK),
			    AUTHRSP_NAME(type));
	}
#endif /* AUTHTYPE_NAMES && AUTHWHO_NAMES && AUTHHOW_NAMES && AUTHRSP_NAMES */

	netflush();
}

/* Decode, decrypt and store the forwarded creds in the local ccache. */
static krb5_error_code
rd_and_store_forwarded_creds(krb5_context context,
			    krb5_auth_context auth_context,
			    krb5_data *inbuf, krb5_ticket *ticket,
			    char *username)
{
	krb5_creds **creds;
	krb5_error_code retval;
	char ccname[MAXPATHLEN];
	krb5_ccache ccache = NULL;
	char *client_name = NULL;

	if (retval = krb5_rd_cred(context, auth_context, inbuf, &creds, NULL))
		return (retval);

	(void) sprintf(ccname, "FILE:/tmp/krb5cc_p%ld", getpid());
	(void) krb5_setenv("KRB5CCNAME", ccname, 1);

	if ((retval = krb5_cc_default(context, &ccache)))
		goto cleanup;

	if ((retval = krb5_cc_initialize(context, ccache,
					ticket->enc_part2->client)) != 0)
		goto cleanup;

	if ((retval = krb5_cc_store_cred(context, ccache, *creds)) != 0)
		goto cleanup;

	if ((retval = krb5_cc_close(context, ccache)) != 0)
		goto cleanup;

	/* Register with ktkt_warnd(1M) */
	if ((retval = krb5_unparse_name(context, (*creds)->client,
					&client_name)) != 0)
		goto cleanup;
	(void) kwarn_del_warning(client_name);
	if (kwarn_add_warning(client_name, (*creds)->times.endtime) != 0) {
		syslog(LOG_AUTH|LOG_NOTICE,
		    "rd_and_store_forwarded_creds: kwarn_add_warning"
		    " failed: ktkt_warnd(1M) down? ");
		if (auth_debug)
			(void) fprintf(stderr,
				    "kwarn_add_warning failed:"
				    " ktkt_warnd(1M) down?\n");
	}
	free(client_name);
	client_name = NULL;

	if (username != NULL) {
		/*
		 * This verifies that the user is valid on the local system,
		 * maps the username from KerberosV5 to unix,
		 * and moves the KRB5CCNAME file to the correct place
		 *  /tmp/krb5cc_[uid] with correct ownership (0600 uid gid).
		 *
		 * NOTE: the user must be in the gsscred table in order to map
		 * from KRB5 to Unix.
		 */
		(void) krb5_kuserok(context, ticket->enc_part2->client,
				username);
	}
	if (auth_debug)
		(void) fprintf(stderr,
			    "Successfully stored forwarded creds\n");

cleanup:
	krb5_free_creds(context, *creds);
	return (retval);
}

static void
kerberos5_is(AuthInfo *ap, uchar_t *data, int cnt)
{
	krb5_error_code err = 0;
	krb5_principal server;
	krb5_keyblock *newkey = NULL;
	krb5_keytab keytabid = 0;
	krb5_data outbuf;
	krb5_data inbuf;
	krb5_authenticator *authenticator;
	char errbuf[MAXERRSTRLEN];
	char *name;
	krb5_data auth;

	Session_Key skey;

	if (cnt-- < 1)
		return;
	switch (*data++) {
	case KRB_AUTH:
		auth.data = (char *)data;
		auth.length = cnt;

		if (auth_context == NULL) {
			err = krb5_auth_con_init(telnet_context, &auth_context);
			if (err)
				syslog(LOG_ERR,
				    "Error getting krb5 auth "
				    "context: %s", error_message(err));
		}
		if (!err) {
			krb5_rcache rcache;

			err = krb5_auth_con_getrcache(telnet_context,
						    auth_context,
						    &rcache);
			if (!err && !rcache) {
				err = krb5_sname_to_principal(telnet_context,
							    0, 0,
							    KRB5_NT_SRV_HST,
							    &server);
				if (!err) {
					err = krb5_get_server_rcache(
						telnet_context,
						krb5_princ_component(
							telnet_context,
							server, 0),
						&rcache);

					krb5_free_principal(telnet_context,
							    server);
				}
			}
			if (err)
				syslog(LOG_ERR,
				    "Error allocating krb5 replay cache: %s",
				    error_message(err));
			else {
				err = krb5_auth_con_setrcache(telnet_context,
							    auth_context,
							    rcache);
				if (err)
					syslog(LOG_ERR,
					    "Error creating krb5 "
					    "replay cache: %s",
					    error_message(err));
			}
		}
		if (!err && telnet_srvtab != NULL)
			err = krb5_kt_resolve(telnet_context,
					    telnet_srvtab, &keytabid);
		if (!err)
			err = krb5_rd_req(telnet_context, &auth_context, &auth,
					NULL, keytabid, NULL, &ticket);
		if (err) {
			(void) snprintf(errbuf, sizeof (errbuf),
				"Error reading krb5 auth information:"
				" %s", error_message(err));
			goto errout;
		}

		/*
		 * Verify that the correct principal was used
		 */
		if (krb5_princ_component(telnet_context,
				ticket->server, 0)->length < MAXPRINCLEN) {
			char princ[MAXPRINCLEN];
			(void) strncpy(princ,
				    krb5_princ_component(telnet_context,
						ticket->server, 0)->data,
				    krb5_princ_component(telnet_context,
					    ticket->server, 0)->length);
			princ[krb5_princ_component(telnet_context,
					ticket->server, 0)->length] = '\0';
			if (strcmp("host", princ)) {
				if (strlen(princ) < sizeof (errbuf) - 39) {
				    (void) snprintf(errbuf, sizeof (errbuf),
						"incorrect service "
						    "name: \"%s\" != "
						    "\"host\"",
						    princ);
			    } else {
				    (void) strncpy(errbuf,
						"incorrect service "
						"name: principal != "
						"\"host\"",
						sizeof (errbuf));
			    }
			    goto errout;
			}
		} else {
			(void) strlcpy(errbuf, "service name too long",
					sizeof (errbuf));
			goto errout;
		}

		err = krb5_auth_con_getauthenticator(telnet_context,
						auth_context,
						&authenticator);
		if (err) {
			(void) snprintf(errbuf, sizeof (errbuf),
				"Failed to get authenticator: %s",
				error_message(err));
			goto errout;
		}
		if ((ap->AuthHow & AUTH_ENCRYPT_MASK) == AUTH_ENCRYPT_ON &&
			!authenticator->checksum) {
			(void) strlcpy(errbuf,
				    "authenticator is missing checksum",
				    sizeof (errbuf));
			goto errout;
		}
		if (authenticator->checksum) {
			char type_check[2];
			krb5_checksum *cksum = authenticator->checksum;
			krb5_keyblock *key;
			krb5_data input;
			krb5_boolean valid;

			type_check[0] = ap->AuthName;
			type_check[1] = ap->AuthHow;

			err = krb5_auth_con_getkey(telnet_context,
						auth_context, &key);
			if (err) {
				(void) snprintf(errbuf, sizeof (errbuf),
					"Failed to get key from "
					"authenticator: %s",
					error_message(err));
				goto errout;
			}

			input.data = type_check;
			input.length = 2;
			err = krb5_c_verify_checksum(telnet_context,
							key, 0,
							&input,
							cksum,
							&valid);
			if (!err && !valid)
				err = KRB5KRB_AP_ERR_BAD_INTEGRITY;

			if (err) {
				(void) snprintf(errbuf, sizeof (errbuf),
						"Kerberos checksum "
						"verification failed: "
						"%s",
						error_message(err));
				goto errout;
			}
			krb5_free_keyblock(telnet_context, key);
		}

		krb5_free_authenticator(telnet_context, authenticator);
		if ((ap->AuthHow & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) {
			/* do ap_rep stuff here */
			if ((err = krb5_mk_rep(telnet_context, auth_context,
					    &outbuf))) {
				(void) snprintf(errbuf, sizeof (errbuf),
						"Failed to make "
						"Kerberos auth reply: "
						"%s",
						error_message(err));
				goto errout;
			}
			reply_to_client(ap, KRB_RESPONSE, outbuf.data,
					outbuf.length);
		}
		if (krb5_unparse_name(telnet_context,
				    ticket->enc_part2->client,
				    &name))
			name = 0;
		reply_to_client(ap, KRB_ACCEPT, name, name ? -1 : 0);
		if (auth_debug) {
			syslog(LOG_NOTICE,
			    "\tKerberos5 identifies user as ``%s''\r\n",
			    name ? name : "");
		}
		if (name != NULL) {
			krb5_name = (char *)strdup(name);
		}
		auth_finished(ap, AUTH_USER);

		if (name != NULL)
			free(name);
		(void) krb5_auth_con_getremotesubkey(telnet_context,
		    auth_context, &newkey);
		if (session_key != NULL) {
			krb5_free_keyblock(telnet_context, session_key);
			session_key = 0;
		}
		if (newkey != NULL) {
			(void) krb5_copy_keyblock(telnet_context,
			    newkey, &session_key);
			krb5_free_keyblock(telnet_context, newkey);
		} else {
			(void) krb5_copy_keyblock(telnet_context,
			    ticket->enc_part2->session, &session_key);
		}

		/*
		 * Initialize encryption stuff.  Currently, we are only
		 * supporting 8 byte keys and blocks. Check for this later.
		 */
		skey.type = SK_DES;
		skey.length = DES_BLOCKSIZE;
		skey.data = session_key->contents;
		encrypt_session_key(&skey, &encr_data.encrypt);
		encrypt_session_key(&skey, &encr_data.decrypt);
		break;
	case KRB_FORWARD:
		inbuf.length = cnt;
		inbuf.data = (char *)data;
		if (auth_debug)
			(void) fprintf(stderr,
				    "RCVD KRB_FORWARD data (%d bytes)\n", cnt);

		if (auth_context != NULL) {
			krb5_rcache rcache;

			err = krb5_auth_con_getrcache(telnet_context,
						    auth_context, &rcache);
			if (!err && !rcache) {
				err = krb5_sname_to_principal(telnet_context,
					0, 0, KRB5_NT_SRV_HST, &server);
				if (!err) {
					err = krb5_get_server_rcache(
						telnet_context,
						krb5_princ_component(
							telnet_context,
							server, 0),
						&rcache);
					krb5_free_principal(telnet_context,
								server);
				}
			}
			if (err) {
				syslog(LOG_ERR,
				    "Error allocating krb5 replay cache: %s",
				    error_message(err));
			} else {
				err = krb5_auth_con_setrcache(telnet_context,
					auth_context, rcache);
				if (err)
					syslog(LOG_ERR,
					    "Error creating krb5 replay cache:"
					    " %s",
					    error_message(err));
			}
		}
		/*
		 * Use the 'rsaddr' and 'rsport' (remote service addr/port)
		 * from the original connection.  This data is used to
		 * verify the forwarded credentials.
		 */
		if (!(err = krb5_auth_con_setaddrs(telnet_context, auth_context,
					    NULL, &rsaddr)))
			err = krb5_auth_con_setports(telnet_context,
						auth_context, NULL, &rsport);

		if (err == 0)
			/*
			 * If all is well, store the forwarded creds in
			 * the users local credential cache.
			 */
			err = rd_and_store_forwarded_creds(telnet_context,
							auth_context, &inbuf,
							ticket,
							AuthenticatingUser);
		if (err) {
			(void) snprintf(errbuf, sizeof (errbuf),
					"Read forwarded creds failed: %s",
					error_message(err));
			syslog(LOG_ERR, "%s", errbuf);

			reply_to_client(ap, KRB_FORWARD_REJECT, errbuf, -1);
			if (auth_debug)
				(void) fprintf(stderr,
					    "\tCould not read "
					    "forwarded credentials\r\n");
		} else
			reply_to_client(ap, KRB_FORWARD_ACCEPT, (void *) 0, 0);

		if (rsaddr.contents != NULL)
			free(rsaddr.contents);

		if (rsport.contents != NULL)
			free(rsport.contents);

		if (auth_debug)
			(void) fprintf(stderr, "\tForwarded "
						"credentials obtained\r\n");
		break;
	default:
		if (auth_debug)
			(void) fprintf(stderr,
				    "\tUnknown Kerberos option %d\r\n",
				    data[-1]);
		reply_to_client(ap, KRB_REJECT, (void *) 0, 0);
		break;
	}
	return;

errout:
	reply_to_client(ap, KRB_REJECT, errbuf, -1);

	if (auth_debug)
		(void) fprintf(stderr, "\tKerberos V5 error: %s\r\n", errbuf);

	syslog(LOG_ERR, "%s", errbuf);

	if (auth_context != NULL) {
		(void) krb5_auth_con_free(telnet_context, auth_context);
		auth_context = 0;
	}
}

static int
krb5_init()
{
	int code = 0;

	if (telnet_context == NULL) {
		code = krb5_init_context(&telnet_context);
		if (code != 0 && auth_debug)
			syslog(LOG_NOTICE,
			    "Cannot initialize Kerberos V5: %s",
			    error_message(code));
	}

	return (code);
}

static void
auth_name(uchar_t *data, int cnt)
{
	char namebuf[MAXPRINCLEN];

	if (cnt < 1) {
		if (auth_debug)
			(void) fprintf(stderr,
				    "\t(auth_name) Empty NAME in auth "
				    "reply\n");
		return;
	}
	if (cnt > sizeof (namebuf)-1) {
		if (auth_debug)
			(void) fprintf(stderr,
				    "\t(auth_name) NAME exceeds %d bytes\n",
				sizeof (namebuf)-1);
		return;
	}
	(void) memcpy((void *)namebuf, (void *)data, cnt);
	namebuf[cnt] = 0;
	if (auth_debug)
		(void) fprintf(stderr, "\t(auth_name) name [%s]\n", namebuf);
	AuthenticatingUser = (char *)strdup(namebuf);
}

static void
auth_is(uchar_t *data, int cnt)
{
	AuthInfo *aptr = auth_list;

	if (cnt < 2)
		return;

	/*
	 * We failed to negoiate secure authentication
	 */
	if (data[0] == AUTHTYPE_NULL) {
		auth_finished(0, AUTH_REJECT);
		return;
	}

	while (aptr->AuthName != NULL &&
	    (aptr->AuthName != data[0] || aptr->AuthHow != data[1]))
		aptr++;

	if (aptr != NULL) {
		if (auth_debug)
			(void) fprintf(stderr, "\t(auth_is) auth type is %s "
				"(%d bytes)\n",	aptr->AuthString, cnt);

		if (aptr->AuthName == AUTHTYPE_KERBEROS_V5)
			kerberos5_is(aptr, data+2, cnt-2);
	}
}

static int
krb5_user_status(char *name, int namelen, int level)
{
	int retval = AUTH_USER;

	if (auth_debug)
		(void) fprintf(stderr, "\t(krb5_user_status) level = %d "
			"auth_level = %d  user = %s\n",
			level, auth_level,
			(AuthenticatingUser != NULL ? AuthenticatingUser : ""));

	if (level < AUTH_USER)
		return (level);

	if (AuthenticatingUser != NULL &&
	    (retval = krb5_kuserok(telnet_context, ticket->enc_part2->client,
			    AuthenticatingUser))) {
		(void) strncpy(name, AuthenticatingUser, namelen);
		return (AUTH_VALID);
	} else {
		if (!retval)
			syslog(LOG_ERR,
			    "Krb5 principal lacks permission to "
			    "access local account for %s",
			    AuthenticatingUser);
		return (AUTH_USER);
	}
}

/*
 * Wrapper around /dev/urandom
 */
static int
getrandom(char *buf, int buflen)
{
	static int devrandom = -1;

	if (devrandom == -1 &&
	    (devrandom = open("/dev/urandom", O_RDONLY)) == -1) {
		fatalperror(net, "Unable to open /dev/urandom: ",
			    errno);
		return (-1);
	}

	if (read(devrandom, buf, buflen) == -1) {
		fatalperror(net, "Unable to read from /dev/urandom: ",
			    errno);
		return (-1);
	}

	return (0);
}

/*
 * encrypt_init
 *
 * Initialize the encryption data structures
 */
static void
encrypt_init()
{
	(void) memset(&encr_data.encrypt, 0, sizeof (cipher_info_t));
	(void) memset(&encr_data.decrypt, 0, sizeof (cipher_info_t));

	encr_data.encrypt.state = ENCR_STATE_NOT_READY;
	encr_data.decrypt.state = ENCR_STATE_NOT_READY;
}

/*
 * encrypt_send_request_start
 *
 * Request that the remote side automatically start sending
 * encrypted output
 */
static void
encrypt_send_request_start()
{
	uchar_t buf[6+TELNET_MAXKEYIDLEN], *p;

	p = buf;

	*p++ = IAC;
	*p++ = SB;
	*p++ = TELOPT_ENCRYPT;
	*p++ = ENCRYPT_REQSTART;
	/*
	 * We are telling the remote side which
	 * decrypt key we will use so that it may
	 * encrypt in the same key.
	 */
	(void) memcpy(p, encr_data.decrypt.keyid, encr_data.decrypt.keyidlen);
	p += encr_data.decrypt.keyidlen;

	*p++ = IAC;
	*p++ = SE;

	write_data_len((const char *)buf, p-buf);
	netflush();
	if (enc_debug)
		(void) fprintf(stderr,
			    "SENT TELOPT_ENCRYPT ENCRYPT_REQSTART\n");
}

/*
 * encrypt_is
 *
 * When we receive the TELOPT_ENCRYPT ENCRYPT_IS ...
 * message, the client is telling us that it will be sending
 * encrypted data using the indicated cipher.
 * We must initialize the read (decrypt) side of our connection
 */
static void
encrypt_is(uchar_t *data, int cnt)
{
	register int type;
	register int iv_status = CFB64_IV_OK;
	register int lstate = 0;

	uchar_t sbbuf[] = {
		(uchar_t)IAC,
		(uchar_t)SB,
		(uchar_t)TELOPT_ENCRYPT,
		(uchar_t)ENCRYPT_REPLY,
		(uchar_t)0,		/* placeholder:  sbbuf[4] */
		(uchar_t)CFB64_IV_OK,	/* placeholder:  sbbuf[5] */
		(uchar_t)IAC,
		(uchar_t)SE,
	};

	if (--cnt < 0)
		return;

	type = sbbuf[4] = *data++;

	/*
	 * Steps to take:
	 *   1. Create the proper stream Initialization vector
	 *		- copy the correct 'seed' to IV and output blocks
	 *		- set the correct key schedule
	 *   2. Generate reply for the other side:
	 *		IAC SB TELOPT_ENCRYPT ENCRYPT_REPLY type CFB64_IV_OK
	 *		[ data ... ] IAC SE
	 *   3. Tell crypto module:  method, direction, IV
	 */
	switch (type) {
	case TELOPT_ENCTYPE_DES_CFB64:
		encr_data.decrypt.type = type;

		lstate = encr_data.decrypt.state;
		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(encrypt_is) initial state = %d\n",
				    lstate);
		/*
		 * Before we extract the IV bytes, make sure we got
		 * enough data.
		 */
		if (cnt < sizeof (Block)) {
			iv_status = CFB64_IV_BAD;
			if (enc_debug)
				(void) fprintf(stderr,
					    "\t(encrypt_is) Not enough "
					    "IV bytes\n");
			lstate = ENCR_STATE_NOT_READY;
		} else {
			data++; /* skip over the CFB64_IV byte */
			(void) memcpy(encr_data.decrypt.ivec, data,
				    sizeof (Block));
			lstate = ENCR_STATE_IN_PROGRESS;
		}
		break;
	case TELOPT_ENCTYPE_NULL:
		encr_data.decrypt.type = type;
		lstate &= ~ENCR_STATE_NO_RECV_IV;
		lstate &= ~ENCR_STATE_NO_SEND_IV;
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(encrypt_is) We accept NULL encr\n");
		break;
	default:
		iv_status = CFB64_IV_BAD;
		encr_data.decrypt.type = NULL;
		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(encrypt_is) Can't find type (%d) "
				    "for initial negotiation\r\n",
				    type);
		lstate = ENCR_STATE_NOT_READY;
		break;
	}

	sbbuf[5] = (uchar_t)iv_status; /* either CFB64_IV_OK or BAD */

	if (iv_status == CFB64_IV_OK) {
		/*
		 * send IV to crypto module and indicate it is for
		 * decrypt only
		 */
		lstate &= ~ENCR_STATE_NO_RECV_IV;  /* we received an OK IV */
		lstate &= ~ENCR_STATE_NO_SEND_IV;  /* we dont send an IV */
	} else {
		/* tell crypto module to disable crypto on "read" stream */
		lstate = ENCR_STATE_NOT_READY;
	}

	write_data_len((const char *)sbbuf, sizeof (sbbuf));
	netflush();
#ifdef ENCRYPT_NAMES
	if (enc_debug)
		(void) fprintf(stderr,
			    "SENT TELOPT_ENCRYPT ENCRYPT_REPLY %s %s\n",
			    ENCTYPE_NAME(type),
			    (iv_status == CFB64_IV_OK ? "CFB64_IV_OK" :
			    "CFB64_IV_BAD"));
#endif /* ENCRYPT_NAMES */
	/* Update the state of the decryption negotiation */
	encr_data.decrypt.state = lstate;

	if (lstate == ENCR_STATE_NOT_READY)
		encr_data.decrypt.autoflag = 0;
	else {
		if (lstate == ENCR_STATE_OK && encr_data.decrypt.autoflag)
			encrypt_send_request_start();
	}
	if (enc_debug)
		(void) fprintf(stderr,
			    "\t(encrypt_is) final DECRYPT state = %d\n",
			    encr_data.decrypt.state);
}

/*
 * encrypt_send_encrypt_is
 *
 * Tell the client what encryption we will use
 * and what our IV will be.
 */
static int
encrypt_send_encrypt_is()
{
	register int lstate;
	krb5_error_code kret;
	uchar_t sbbuf[MAXOPTLEN], *p;
	int i;

	lstate = encr_data.encrypt.state;

	if (encr_data.encrypt.type == ENCTYPE_NULL) {
		/*
		 * Haven't received ENCRYPT SUPPORT yet or we couldn't agree
		 * on a cipher.
		 */
		return (lstate);
	}

	/*
	 * - Create a random DES key
	 *
	 * - DES ECB encrypt
	 *   encrypt the IV using itself as the key.
	 *
	 * - Send response
	 *   IAC SB TELOPT_ENCRYPT ENCRYPT_IS CFB64 FB64_IV [ feed block ]
	 *   IAC SE
	 *
	 */
	if (lstate == ENCR_STATE_NOT_READY)
		lstate = ENCR_STATE_IN_PROGRESS;
	else if ((lstate & ENCR_STATE_NO_SEND_IV) == 0) {
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(encrypt_send_is) IV already sent,"
				" state = %d\n", lstate);
		return (lstate);
	}

	if (!VALIDKEY(encr_data.encrypt.krbdes_key)) {
		/*
		 * Invalid key, set flag so we try again later
		 * when we get a good one
		 */
		encr_data.encrypt.need_start = 1;
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(encrypt_send_is) No Key, cannot "
				"start encryption yet\n");
		return (lstate);
	}
	if (enc_debug)
		(void) fprintf(stderr,
			    "\t(encrypt_send_is) Creating new feed\n");

	/*
	 * Create a random feed and send it over.
	 *
	 * Use the /dev/[u]random interface to generate
	 * our encryption IV.
	 */
	kret = getrandom((char *)encr_data.encrypt.ivec, sizeof (Block));

	if (kret) {
		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(encrypt_send_is) error from "
				    "getrandom: %d\n", kret);
		syslog(LOG_ERR, "Failed to create encryption key (err %d)\n");
		encr_data.encrypt.type = ENCTYPE_NULL;
	} else {
		mit_des_fixup_key_parity(encr_data.encrypt.ivec);
	}

	p = sbbuf;
	*p++ = IAC;
	*p++ = SB;
	*p++ = TELOPT_ENCRYPT;
	*p++ = ENCRYPT_IS;
	*p++ = encr_data.encrypt.type;
	*p++ = CFB64_IV;

	/*
	 * Copy the IV bytes individually so that when a
	 * 255 (telnet IAC) is used, it can be "escaped" by
	 * adding it twice (telnet RFC 854).
	 */
	for (i = 0; i < sizeof (Block); i++)
		if ((*p++ = encr_data.encrypt.ivec[i]) == IAC)
			*p++ = IAC;

	*p++ = IAC;
	*p++ = SE;
	write_data_len((const char *)sbbuf, (size_t)(p-sbbuf));
	netflush();

	if (!kret) {
		lstate &= ~ENCR_STATE_NO_SEND_IV; /* we sent our IV */
		lstate &= ~ENCR_STATE_NO_SEND_IV; /* dont need decrypt IV */
	}
	encr_data.encrypt.state = lstate;

	if (enc_debug) {
		int i;
		(void) fprintf(stderr,
			    "SENT TELOPT_ENCRYPT ENCRYPT_IS %d CFB64_IV ",
			    encr_data.encrypt.type);
		for (i = 0; i < (p-sbbuf); i++)
			(void) fprintf(stderr, "%d ", (int)sbbuf[i]);
		(void) fprintf(stderr, "\n");
	}

	return (lstate);
}

/*
 * stop_stream
 *
 * Utility routine to send a CRIOCSTOP ioctl to the
 * crypto module (cryptmod).
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

	if (ioctl(fd, I_STR, &crioc)) {
		syslog(LOG_ERR, "Error sending CRYPTIOCSTOP ioctl: %m");
	}
}

/*
 * start_stream
 *
 * Utility routine to send a CRYPTIOCSTART ioctl to the
 * crypto module (cryptmod).  This routine may contain optional
 * payload data that the cryptmod will interpret as bytes that
 * need to be decrypted and sent back up to the application
 * via the data stream.
 */
static void
start_stream(int fd, int dir, int datalen, char *data)
{
	struct strioctl crioc;

	crioc.ic_cmd = (dir == CRYPT_ENCRYPT ? CRYPTIOCSTARTENC :
			CRYPTIOCSTARTDEC);
	crioc.ic_timout = -1;
	crioc.ic_len = datalen;
	crioc.ic_dp = data;

	if (ioctl(fd, I_STR, &crioc)) {
		syslog(LOG_ERR, "Error sending CRYPTIOCSTART ioctl: %m");
	}
}

/*
 * encrypt_start_output
 *
 * Tell the other side to start encrypting its data
 */
static void
encrypt_start_output()
{
	int lstate;
	uchar_t *p;
	uchar_t sbbuf[MAXOPTLEN];
	struct strioctl crioc;
	struct cr_info_t cki;

	/*
	 * Initialize crypto and send the ENCRYPT_IS msg
	 */
	lstate = encrypt_send_encrypt_is();

	if (lstate != ENCR_STATE_OK) {
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(encrypt_start_output) ENCRYPT state "
				"= %d\n", lstate);
		return;
	}

	p = sbbuf;

	*p++ = IAC;
	*p++ = SB;
	*p++ = TELOPT_ENCRYPT;
	*p++ = ENCRYPT_START;

	(void) memcpy(p, encr_data.encrypt.keyid, encr_data.encrypt.keyidlen);
	p += encr_data.encrypt.keyidlen;

	*p++ = IAC;
	*p++ = SE;

	/* Flush this data out before we start encrypting */
	write_data_len((const char *)sbbuf, (int)(p-sbbuf));
	netflush();

	if (enc_debug)
		(void) fprintf(stderr, "SENT TELOPT_ENCRYPT ENCRYPT_START %d "
			"(lstate = %d) data waiting = %d\n",
			(int)encr_data.encrypt.keyid[0],
			lstate, nfrontp-nbackp);

	encr_data.encrypt.state = lstate;

	/*
	 * tell crypto module what key to use for encrypting
	 * Note that the ENCRYPT has not yet been enabled, but we
	 * need to first set the crypto key to use.
	 */
	cki.direction_mask = CRYPT_ENCRYPT;

	if (encr_data.encrypt.type == TELOPT_ENCTYPE_DES_CFB64) {
		cki.crypto_method = CRYPT_METHOD_DES_CFB;
	} else {
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(encrypt_start_output) - unknown "
				"crypto_method %d\n",
				encr_data.encrypt.type);
		syslog(LOG_ERR, "unrecognized crypto encrypt method: %d",
				encr_data.encrypt.type);

		return;
	}

	/*
	 * If we previously configured this crypto method, we dont want to
	 * overwrite the key or ivec information already given to the crypto
	 * module as it will cause the cipher data between the client and server
	 * to become out of synch and impossible to decipher.
	 */
	if (encr_data.encrypt.setup == cki.crypto_method) {
		cki.keylen = 0;
		cki.iveclen = 0;
	} else {
		cki.keylen = DES_BLOCKSIZE;
		(void) memcpy(cki.key, (void *)encr_data.encrypt.krbdes_key,
		    DES_BLOCKSIZE);

		cki.iveclen = DES_BLOCKSIZE;
		(void) memcpy(cki.ivec, (void *)encr_data.encrypt.ivec,
		    DES_BLOCKSIZE);

		cki.ivec_usage = IVEC_ONETIME;
	}

	cki.option_mask = 0;

	/* Stop encrypt side prior to setup so we dont lose data */
	stop_stream(cryptmod_fd, CRYPT_ENCRYPT);

	crioc.ic_cmd = CRYPTIOCSETUP;
	crioc.ic_timout = -1;
	crioc.ic_len = sizeof (struct cr_info_t);
	crioc.ic_dp = (char *)&cki;

	if (ioctl(cryptmod_fd, I_STR, &crioc)) {
		perror("ioctl(CRYPTIOCSETUP) [encrypt_start_output] error");
	} else {
		/* Setup completed OK */
		encr_data.encrypt.setup = cki.crypto_method;
	}

	/*
	 * We do not check for "stuck" data when setting up the
	 * outbound "encrypt" channel.  Any data queued prior to
	 * this IOCTL will get processed correctly without our help.
	 */
	start_stream(cryptmod_fd, CRYPT_ENCRYPT, 0, NULL);

	/*
	 * tell crypto module to start encrypting
	 */
	if (enc_debug)
		(void) fprintf(stderr,
			"\t(encrypt_start_output) Encrypting output\n");
}

/*
 * encrypt_request_start
 *
 * The client requests that we start encryption immediately after
 * successful negotiation
 */
static void
encrypt_request_start(void)
{
	if (encr_data.encrypt.type == ENCTYPE_NULL) {
		encr_data.encrypt.autoflag = 1;
		if (enc_debug)
			(void) fprintf(stderr, "\t(encrypt_request_start) "
				"autoencrypt = ON\n");
	} else {
		encrypt_start_output();
	}
}

/*
 * encrypt_end
 *
 * ENCRYPT END received, stop decrypting the read stream
 */
static void
encrypt_end(int direction)
{
	struct cr_info_t cki;
	struct strioctl  crioc;
	uint32_t stopdir;

	stopdir = (direction == TELNET_DIR_DECRYPT ? CRYPT_DECRYPT :
		CRYPT_ENCRYPT);

	stop_stream(cryptmod_fd, stopdir);

	/*
	 * Call this function when we wish to disable crypto in
	 * either direction (ENCRYPT or DECRYPT)
	 */
	cki.direction_mask = (direction == TELNET_DIR_DECRYPT ? CRYPT_DECRYPT :
			    CRYPT_ENCRYPT);
	cki.crypto_method = CRYPT_METHOD_NONE;
	cki.option_mask = 0;

	cki.keylen = 0;
	cki.iveclen = 0;
	cki.ivec_usage = IVEC_ONETIME;

	crioc.ic_cmd = CRYPTIOCSETUP;
	crioc.ic_timout = -1;
	crioc.ic_len = sizeof (cki);
	crioc.ic_dp = (char *)&cki;

	if (ioctl(cryptmod_fd, I_STR, &crioc)) {
		perror("ioctl(CRYPTIOCSETUP) [encrypt_end] error");
	}

	start_stream(cryptmod_fd, stopdir, 0, NULL);
}

/*
 * encrypt_request_end
 *
 * When we receive a REQEND from the client, it means
 * that we are supposed to stop encrypting
 */
static void
encrypt_request_end()
{
	/*
	 * Tell the other side we are done encrypting
	 */

	write_data("%c%c%c%c%c%c",
		(uchar_t)IAC,
		(uchar_t)SB,
		(uchar_t)TELOPT_ENCRYPT,
		(uchar_t)ENCRYPT_END,
		(uchar_t)IAC,
		(uchar_t)SE);
	netflush();
	if (enc_debug)
		(void) fprintf(stderr, "SENT TELOPT_ENCRYPT ENCRYPT_END\n");

	/*
	 * Turn off encryption of the write stream
	 */
	encrypt_end(TELNET_DIR_ENCRYPT);
}

/*
 * encrypt_send_request_end
 *
 * We stop encrypting the write stream and tell the other side about it.
 */
static void
encrypt_send_request_end()
{
	write_data("%c%c%c%c%c%c",
		(uchar_t)IAC,
		(uchar_t)SB,
		(uchar_t)TELOPT_ENCRYPT,
		(uchar_t)ENCRYPT_REQEND,
		(uchar_t)IAC,
		(uchar_t)SE);
	netflush();
	if (enc_debug)
		(void) fprintf(stderr, "SENT TELOPT_ENCRYPT ENCRYPT_REQEND\n");
}

/*
 * encrypt_start
 *
 * The client is going to start sending encrypted data
 * using the previously negotiated cipher (see what we set
 * when we did the REPLY in encrypt_is).
 */
static void
encrypt_start(void)
{
	struct cr_info_t cki;
	struct strioctl  crioc;
	int bytes = 0;
	char *dataptr = NULL;

	if (encr_data.decrypt.type == ENCTYPE_NULL) {
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(encrypt_start) No DECRYPT method "
				"defined yet\n");
		encrypt_send_request_end();
		return;
	}

	cki.direction_mask = CRYPT_DECRYPT;

	if (encr_data.decrypt.type == TELOPT_ENCTYPE_DES_CFB64) {
		cki.crypto_method = CRYPT_METHOD_DES_CFB;
	} else {
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(encrypt_start) - unknown "
				"crypto_method %d\n", encr_data.decrypt.type);

		syslog(LOG_ERR, "unrecognized crypto decrypt method: %d",
				encr_data.decrypt.type);

		return;
	}

	/*
	 * Don't overwrite previously configured key and ivec info
	 */
	if (encr_data.decrypt.setup != cki.crypto_method) {
		(void) memcpy(cki.key, (void *)encr_data.decrypt.krbdes_key,
		    DES_BLOCKSIZE);
		(void) memcpy(cki.ivec, (void *)encr_data.decrypt.ivec,
		    DES_BLOCKSIZE);

		cki.keylen = DES_BLOCKSIZE;
		cki.iveclen = DES_BLOCKSIZE;
		cki.ivec_usage = IVEC_ONETIME;
	} else {
		cki.keylen = 0;
		cki.iveclen = 0;
	}
	cki.option_mask = 0;

	stop_stream(cryptmod_fd, CRYPT_DECRYPT);

	crioc.ic_cmd = CRYPTIOCSETUP;
	crioc.ic_timout = -1;
	crioc.ic_len = sizeof (struct cr_info_t);
	crioc.ic_dp = (char *)&cki;

	if (ioctl(cryptmod_fd, I_STR, &crioc)) {
		syslog(LOG_ERR, "ioctl(CRYPTIOCSETUP) [encrypt_start] "
		    "error: %m");
	} else {
		encr_data.decrypt.setup = cki.crypto_method;
	}
	if (enc_debug)
		(void) fprintf(stderr,
			    "\t(encrypt_start) called CRYPTIOCSETUP for "
			    "decrypt side\n");

	/*
	 * Read any data stuck between the cryptmod and the application
	 * so we can pass it back down to be properly decrypted after
	 * this operation finishes.
	 */
	if (ioctl(cryptmod_fd, I_NREAD, &bytes) < 0) {
		syslog(LOG_ERR, "I_NREAD returned error %m");
		bytes = 0;
	}

	/*
	 * Any data which was read AFTER the ENCRYPT START message
	 * must be sent back down to be decrypted properly.
	 *
	 * 'ncc' is the number of bytes that have been read but
	 * not yet processed by the telnet state machine.
	 *
	 * 'bytes' is the number of bytes waiting to be read from
	 * the stream.
	 *
	 * If either one is a positive value, then those bytes
	 * must be pulled up and sent back down to be decrypted.
	 */
	if (ncc || bytes) {
		drainstream(bytes);
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(encrypt_start) after drainstream, "
				"ncc=%d bytes = %d\n", ncc, bytes);
		bytes += ncc;
		dataptr = netip;
	}

	start_stream(cryptmod_fd, CRYPT_DECRYPT, bytes, dataptr);

	/*
	 * The bytes putback into the stream are no longer
	 * available to be read by the server, so adjust the
	 * counter accordingly.
	 */
	ncc = 0;
	netip = netibuf;
	(void) memset(netip, 0, netibufsize);

#ifdef ENCRYPT_NAMES
	if (enc_debug) {
		(void) fprintf(stderr,
			    "\t(encrypt_start) Start DECRYPT using %s\n",
			    ENCTYPE_NAME(encr_data.decrypt.type));
	}
#endif /* ENCRYPT_NAMES */
}

/*
 * encrypt_support
 *
 * Called when we recieve the TELOPT_ENCRYPT SUPPORT [ encr type list ]
 * message from a client.
 *
 * Choose an agreeable method (DES_CFB64) and
 * respond with  TELOPT_ENCRYPT ENCRYPT_IS [ desired crypto method ]
 *
 * from: RFC 2946
 */
static void
encrypt_support(char *data, int cnt)
{
	int lstate = ENCR_STATE_NOT_READY;
	int type, use_type = 0;

	while (cnt-- > 0 && use_type == 0) {
		type = *data++;
#ifdef ENCRYPT_NAMES
		if (enc_debug)
			(void) fprintf(stderr,
				    "RCVD ENCRYPT SUPPORT %s\n",
				    ENCTYPE_NAME(type));
#endif /* ENCRYPT_NAMES */
		/*
		 * Prefer CFB64
		 */
		if (type == TELOPT_ENCTYPE_DES_CFB64) {
			use_type = type;
		}
	}
	encr_data.encrypt.type = use_type;

	if (use_type != TELOPT_ENCTYPE_NULL &&
	    authenticated != NULL && authenticated != &NoAuth &&
	    auth_status != AUTH_REJECT) {

		/* Authenticated -> have session key -> send ENCRYPT IS */
		lstate = encrypt_send_encrypt_is();
		if (lstate == ENCR_STATE_OK)
			encrypt_start_output();
	} else if (use_type == TELOPT_ENCTYPE_NULL) {
		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(encrypt_support) Cannot agree "
				    "on crypto algorithm, output encryption "
				    "disabled.\n");

		/*
		 * Cannot agree on crypto algorithm
		 * RFC 2946 sez:
		 *    send "IAC SB ENCRYPT IS NULL IAC SE"
		 *    optionally, also send IAC WONT ENCRYPT
		 */
		write_data("%c%c%c%c%c%c%c",
			(uchar_t)IAC,
			(uchar_t)SB,
			(uchar_t)TELOPT_ENCRYPT,
			(uchar_t)ENCRYPT_IS,
			(uchar_t)TELOPT_ENCTYPE_NULL,
			(uchar_t)IAC,
			(uchar_t)SE);
		send_wont(TELOPT_ENCRYPT);
		netflush();
		if (enc_debug)
			(void) fprintf(stderr,
				    "SENT TELOPT_ENCRYPT ENCRYPT_IS "
				    "[NULL]\n");

		remopts[TELOPT_ENCRYPT] = OPT_NO;
	}
	settimer(encr_support);
}

/*
 * encrypt_send_keyid
 *
 * Sent the key id we will use to the client
 */
static void
encrypt_send_keyid(int dir, uchar_t *keyid, int keylen, boolean_t saveit)
{
	uchar_t sbbuf[128], *p;

	p = sbbuf;

	*p++ = IAC;
	*p++ = SB;
	*p++ = TELOPT_ENCRYPT;
	*p++ = (dir == TELNET_DIR_ENCRYPT ? ENCRYPT_ENC_KEYID :
		ENCRYPT_DEC_KEYID);
	if (saveit) {
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(send_keyid) store %d byte %s keyid\n",
				keylen,
				(dir == TELNET_DIR_ENCRYPT ? "ENCRYPT" :
				"DECRYPT"));

		if (dir == TELNET_DIR_ENCRYPT) {
			(void) memcpy(encr_data.encrypt.keyid, keyid, keylen);
			encr_data.encrypt.keyidlen = keylen;
		} else {
			(void) memcpy(encr_data.decrypt.keyid, keyid, keylen);
			encr_data.decrypt.keyidlen = keylen;
		}
	}
	(void) memcpy(p, keyid, keylen);
	p += keylen;

	*p++ = IAC;
	*p++ = SE;
	write_data_len((const char *)sbbuf, (size_t)(p-sbbuf));
	netflush();

	if (enc_debug)
		(void) fprintf(stderr, "SENT TELOPT_ENCRYPT %s %d\n",
			(dir == TELNET_DIR_ENCRYPT ? "ENC_KEYID" :
			"DEC_KEYID"), keyid[0]);
}

/*
 * encrypt_reply
 *
 * When we receive the TELOPT_ENCRYPT REPLY [crtype] CFB64_IV_OK IAC SE
 * message, process it accordingly.
 * If the vector is acceptable, tell client we are encrypting and
 * enable encryption on our write stream.
 *
 * Negotiate the KEYID next..
 * RFC 2946, 2952
 */
static void
encrypt_reply(char *data, int len)
{
	uchar_t type = (uchar_t)(*data++);
	uchar_t result = (uchar_t)(*data);
	int lstate;

#ifdef ENCRYPT_NAMES
	if (enc_debug)
		(void) fprintf(stderr,
			"\t(encrypt_reply) ENCRYPT REPLY %s %s [len=%d]\n",
			ENCRYPT_NAME(type),
			(result == CFB64_IV_OK ? "CFB64_IV_OK" :
			"CFB64_IV_BAD"), len);
#endif /* ENCRYPT_NAMES */

	lstate = encr_data.encrypt.state;
	if (enc_debug)
		(void) fprintf(stderr,
			"\t(encrypt_reply) initial ENCRYPT state = %d\n",
			lstate);
	switch (result) {
	case CFB64_IV_OK:
		if (lstate == ENCR_STATE_NOT_READY)
			lstate = ENCR_STATE_IN_PROGRESS;
		lstate &= ~ENCR_STATE_NO_RECV_IV; /* we got the IV */
		lstate &= ~ENCR_STATE_NO_SEND_IV; /* we dont need to send IV */

		/*
		 * The correct response here is to send the encryption key id
		 * RFC 2752.
		 *
		 * Send keyid 0 to indicate that we will just use default
		 * keys.
		 */
		encrypt_send_keyid(TELNET_DIR_ENCRYPT, (uchar_t *)"\0", 1, 1);

		break;
	case CFB64_IV_BAD:
		/*
		 * Clear the ivec
		 */
		(void) memset(encr_data.encrypt.ivec, 0, sizeof (Block));
		lstate = ENCR_STATE_NOT_READY;
		break;
	default:
		if (enc_debug)
			(void) fprintf(stderr,
				"\t(encrypt_reply) Got unknown IV value in "
				"REPLY message\n");
		lstate = ENCR_STATE_NOT_READY;
		break;
	}

	encr_data.encrypt.state = lstate;
	if (lstate == ENCR_STATE_NOT_READY) {
		encr_data.encrypt.autoflag = 0;
		encr_data.encrypt.type = ENCTYPE_NULL;
		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(encrypt_reply) encrypt.autoflag = "
				    "OFF\n");
	} else {
		encr_data.encrypt.type = type;
		if ((lstate == ENCR_STATE_OK) && encr_data.encrypt.autoflag)
			encrypt_start_output();
	}

	if (enc_debug)
		(void) fprintf(stderr,
			    "\t(encrypt_reply) ENCRYPT final state = %d\n",
			    lstate);
}

static void
encrypt_set_keyid_state(uchar_t *keyid, int *keyidlen, int dir)
{
	int lstate;

	lstate = (dir == TELNET_DIR_ENCRYPT ? encr_data.encrypt.state :
		encr_data.decrypt.state);

	if (enc_debug)
		(void) fprintf(stderr,
			    "\t(set_keyid_state) %s initial state = %d\n",
			    (dir == TELNET_DIR_ENCRYPT ? "ENCRYPT" :
			    "DECRYPT"), lstate);

	/*
	 * Currently, we only support using the default keyid,
	 * so it should be an error if the len > 1 or the keyid != 0.
	 */
	if (*keyidlen != 1 || (*keyid != '\0')) {
		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(set_keyid_state) unexpected keyid: "
				    "len=%d value=%d\n", *keyidlen, *keyid);
		*keyidlen = 0;
		syslog(LOG_ERR, "rcvd unexpected keyid %d  - only keyid of 0 "
		    "is supported",  *keyid);
	} else {
		/*
		 * We move to the "IN_PROGRESS" state.
		 */
		if (lstate == ENCR_STATE_NOT_READY)
			lstate = ENCR_STATE_IN_PROGRESS;
		/*
		 * Clear the NO_KEYID bit because we now have a valid keyid
		 */
		lstate &= ~ENCR_STATE_NO_KEYID;
	}

	if (enc_debug)
		(void) fprintf(stderr,
			    "\t(set_keyid_state) %s final state = %d\n",
			    (dir == TELNET_DIR_ENCRYPT ? "ENCRYPT" :
			    "DECRYPT"), lstate);

	if (dir == TELNET_DIR_ENCRYPT)
		encr_data.encrypt.state = lstate;
	else
		encr_data.decrypt.state = lstate;
}

/*
 * encrypt_keyid
 *
 * Set the keyid value in the key_info structure.
 * if necessary send a response to the sender
 */
static void
encrypt_keyid(uchar_t *newkeyid, int *keyidlen, uchar_t *keyid,
	int len, int dir)
{
	if (len > TELNET_MAXNUMKEYS) {
		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(keyid) keylen too big (%d)\n", len);
		return;
	}

	if (enc_debug) {
		(void) fprintf(stderr, "\t(keyid) set KEYID for %s len = %d\n",
			    (dir == TELNET_DIR_ENCRYPT ? "ENCRYPT" :
			    "DECRYPT"), len);
	}

	if (len == 0) {
		if (*keyidlen == 0) {
			if (enc_debug)
				(void) fprintf(stderr,
					    "\t(keyid) Got 0 length keyid - "
					    "failure\n");
			return;
		}
		*keyidlen = 0;
		encrypt_set_keyid_state(newkeyid, keyidlen, dir);

	} else if (len != *keyidlen || memcmp(keyid, newkeyid, len)) {
		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(keyid) Setting new key (%d bytes)\n",
				    len);

		*keyidlen = len;
		(void) memcpy(newkeyid, keyid, len);

		encrypt_set_keyid_state(newkeyid, keyidlen, dir);
	} else {
		encrypt_set_keyid_state(newkeyid, keyidlen, dir);

		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(keyid) %s Key already in place,"
				    "state = %d autoflag=%d\n",
			(dir == TELNET_DIR_ENCRYPT ? "ENCRYPT" : "DECRYPT"),
			(dir == TELNET_DIR_ENCRYPT ? encr_data.encrypt.state:
			encr_data.decrypt.state),
			(dir == TELNET_DIR_ENCRYPT ?
				encr_data.encrypt.autoflag:
				encr_data.decrypt.autoflag));

		/* key already in place */
		if ((encr_data.encrypt.state == ENCR_STATE_OK) &&
		    dir == TELNET_DIR_ENCRYPT && encr_data.encrypt.autoflag) {
			encrypt_start_output();
		}
		return;
	}

	if (enc_debug)
		(void) fprintf(stderr, "\t(keyid) %s final state = %d\n",
			    (dir == TELNET_DIR_ENCRYPT ? "ENCRYPT" :
			    "DECRYPT"),
			    (dir == TELNET_DIR_ENCRYPT ?
			    encr_data.encrypt.state :
			    encr_data.decrypt.state));

	encrypt_send_keyid(dir, newkeyid, *keyidlen, 0);
}

/*
 * encrypt_enc_keyid
 *
 * We received the ENC_KEYID message from a client indicating that
 * the client wishes to verify that the indicated keyid maps to a
 * valid key.
 */
static void
encrypt_enc_keyid(char *data, int cnt)
{
	/*
	 * Verify the decrypt keyid is valid
	 */
	encrypt_keyid(encr_data.decrypt.keyid, &encr_data.decrypt.keyidlen,
		    (uchar_t *)data, cnt, TELNET_DIR_DECRYPT);
}

/*
 * encrypt_dec_keyid
 *
 * We received the DEC_KEYID message from a client indicating that
 * the client wants to verify that the indicated keyid maps to a valid key.
 */
static void
encrypt_dec_keyid(char *data, int cnt)
{
	encrypt_keyid(encr_data.encrypt.keyid, &encr_data.encrypt.keyidlen,
		    (uchar_t *)data, cnt, TELNET_DIR_ENCRYPT);
}

/*
 * encrypt_session_key
 *
 * Store the session key in the encryption data record
 */
static void
encrypt_session_key(Session_Key *key, cipher_info_t *cinfo)
{
	if (key == NULL || key->type != SK_DES) {
		if (enc_debug)
			(void) fprintf(stderr,
				    "\t(session_key) Cannot set krb5 "
				    "session key (unknown type = %d)\n",
				    key ? key->type : -1);
	}
	if (enc_debug)
		(void) fprintf(stderr,
			    "\t(session_key) Settting session key "
			    "for server\n");

	/* store the key in the cipher info data struct */
	(void) memcpy(cinfo->krbdes_key, (void *)key->data, sizeof (Block));

	/*
	 * Now look to see if we still need to send the key and start
	 * encrypting.
	 *
	 * If so, go ahead an call it now that we have the key.
	 */
	if (cinfo->need_start) {
		if (encrypt_send_encrypt_is() == ENCR_STATE_OK) {
			cinfo->need_start = 0;
		}
	}
}

/*
 * new_env
 *
 * Used to add an environment variable and value to the
 * linked list structure.
 */
static int
new_env(const char *name, const char *value)
{
	struct envlist *env;

	env = malloc(sizeof (struct envlist));
	if (env == NULL)
		return (1);
	if ((env->name = strdup(name)) == NULL) {
		free(env);
		return (1);
	}
	if ((env->value = strdup(value)) == NULL) {
		free(env->name);
		free(env);
		return (1);
	}
	env->delete = 0;
	env->next = envlist_head;
	envlist_head = env;
	return (0);
}

/*
 * del_env
 *
 * Used to delete an environment variable from the linked list
 * structure.  We just set a flag because we will delete the list
 * anyway before we exec login.
 */
static int
del_env(const char *name)
{
	struct envlist *env;

	for (env = envlist_head; env; env = env->next) {
		if (strcmp(env->name, name) == 0) {
			env->delete = 1;
			break;
		}
	}
	return (0);
}

static int
issock(int fd)
{
	struct stat stats;

	if (fstat(fd, &stats) == -1)
		return (0);
	return (S_ISSOCK(stats.st_mode));
}

/*
 * audit_telnet_settid stores the terminal id while it is still
 * available.  Subsequent calls to adt_load_hostname() return
 * the id which is stored here.
 */
static int
audit_telnet_settid(int sock) {
	adt_session_data_t	*ah;
	adt_termid_t		*termid;
	int			rc;

	if ((rc = adt_start_session(&ah, NULL, 0)) == 0) {
		if ((rc = adt_load_termid(sock, &termid)) == 0) {
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
	struct sockaddr_storage from;
	int on = 1;
	socklen_t fromlen;
	int issocket;
#if	defined(DEBUG)
	ushort_t porttouse = 0;
	boolean_t standalone = 0;
#endif /* defined(DEBUG) */
	extern char *optarg;
	char c;
	int tos = -1;

	while ((c = getopt(argc, argv, TELNETD_OPTS DEBUG_OPTS)) != -1) {
		switch (c) {
#if defined(DEBUG)
		case 'p':
			/*
			 * note: alternative port number only used in
			 * standalone mode.
			 */
			porttouse = atoi(optarg);
			standalone = 1;
			break;
		case 'e':
			enc_debug = 1;
			break;
#endif /* DEBUG */
		case 'a':
			if (strcasecmp(optarg, "none") == 0) {
				auth_level = 0;
			} else if (strcasecmp(optarg, "user") == 0) {
				auth_level = AUTH_USER;
			} else if (strcasecmp(optarg, "valid") == 0) {
				auth_level = AUTH_VALID;
			} else if (strcasecmp(optarg, "off") == 0) {
				auth_level = -1;
				negotiate_auth_krb5 = 0;
			} else if (strcasecmp(optarg, "debug") == 0) {
				auth_debug = 1;
			} else {
				syslog(LOG_ERR,
				    "unknown authentication level specified "
				    "with \'-a\' option (%s)", optarg);
				auth_level = AUTH_USER;
			}
			break;
		case 'X':
			/* disable authentication negotiation */
			negotiate_auth_krb5 = 0;
			break;
		case 'R':
		case 'M':
			if (optarg != NULL) {
				int ret = krb5_init();
				if (ret) {
					syslog(LOG_ERR,
						"Unable to use Kerberos V5 as "
						"requested, exiting");
					exit(1);
				}
				(void) krb5_set_default_realm(telnet_context,
				    optarg);
				syslog(LOG_NOTICE,
				    "using %s as default KRB5 realm", optarg);
			}
			break;
		case 'S':
			telnet_srvtab = (char *)strdup(optarg);
			break;
		case 'E': /* disable automatic encryption */
			negotiate_encrypt = B_FALSE;
			break;
		case 'U':
			resolve_hostname = 1;
			break;
		case 's':
			if (optarg == NULL || (tos = atoi(optarg)) < 0 ||
			    tos > 255) {
				syslog(LOG_ERR, "telnetd: illegal tos value: "
				    "%s\n", optarg);
			} else {
				if (tos < 0)
					tos = 020;
			}
			break;
		case 'h':
			show_hostinfo = 0;
			break;
		default:
			syslog(LOG_ERR, "telnetd: illegal cmd line option %c",
			    c);
			break;
		}
	}

	netibufsize = BUFSIZ;
	if (!(netibuf = (char *)malloc(netibufsize)))
		syslog(LOG_ERR, "netibuf malloc failed\n");
	(void) memset(netibuf, 0, netibufsize);
	netip = netibuf;

#if	defined(DEBUG)
	if (standalone) {
		int s, ns, foo;
		struct servent *sp;
		static struct sockaddr_in6 sin6 = { AF_INET6 };
		int option = 1;

		if (porttouse) {
			sin6.sin6_port = htons(porttouse);
		} else {
			sp = getservbyname("telnet", "tcp");
			if (sp == 0) {
				(void) fprintf(stderr,
					    "telnetd: tcp/telnet: "
					    "unknown service\n");
				exit(EXIT_FAILURE);
			}
			sin6.sin6_port = sp->s_port;
		}

		s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (s < 0) {
			perror("telnetd: socket");
			exit(EXIT_FAILURE);
		}
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&option,
		    sizeof (option)) == -1)
			perror("setsockopt SO_REUSEADDR");
		if (bind(s, (struct sockaddr *)&sin6, sizeof (sin6)) < 0) {
			perror("bind");
			exit(EXIT_FAILURE);
		}
		if (listen(s, 32) < 0) {
			perror("listen");
			exit(EXIT_FAILURE);
		}

		/* automatically reap all child processes */
		(void) signal(SIGCHLD, SIG_IGN);

		for (;;) {
			pid_t pid;

			foo = sizeof (sin6);
			ns = accept(s, (struct sockaddr *)&sin6, &foo);
			if (ns < 0) {
				perror("accept");
				exit(EXIT_FAILURE);
			}
			pid = fork();
			if (pid == -1) {
				perror("fork");
				exit(EXIT_FAILURE);
			}
			if (pid == 0) {
				(void) dup2(ns, 0);
				(void) close(s);
				(void) signal(SIGCHLD, SIG_DFL);
				break;
			}
			(void) close(ns);
		}
	}
#endif /* defined(DEBUG) */

	openlog("telnetd", LOG_PID | LOG_ODELAY, LOG_DAEMON);

	issocket = issock(0);
	if (!issocket)
		fatal(0, "stdin is not a socket file descriptor");

	fromlen = (socklen_t)sizeof (from);
	(void) memset((char *)&from, 0, sizeof (from));
	if (getpeername(0, (struct sockaddr *)&from, &fromlen)
	    < 0) {
		(void) fprintf(stderr, "%s: ", argv[0]);
		perror("getpeername");
		_exit(EXIT_FAILURE);
	}

	if (audit_telnet_settid(0)) {	/* set terminal ID */
		(void) fprintf(stderr, "%s: ", argv[0]);
		perror("audit");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(0, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on,
						sizeof (on)) < 0) {
		syslog(LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
	}

	/*
	 * Set the TOS value
	 */
	if (tos != -1 &&
	    setsockopt(0, IPPROTO_IP, IP_TOS,
		    (char *)&tos, sizeof (tos)) < 0 &&
		errno != ENOPROTOOPT) {
		syslog(LOG_ERR, "setsockopt (IP_TOS %d): %m", tos);
	}

	if (setsockopt(net, SOL_SOCKET, SO_OOBINLINE, (char *)&on,
	    sizeof (on)) < 0) {
		syslog(LOG_WARNING, "setsockopt (SO_OOBINLINE): %m");
	}

	/* set the default PAM service name */
	(void) strcpy(pam_svc_name, "telnet");

	doit(0, &from);
	return (EXIT_SUCCESS);
}

static char	*terminaltype = 0;

/*
 * ttloop
 *
 *	A small subroutine to flush the network output buffer, get some data
 * from the network, and pass it through the telnet state machine.  We
 * also flush the pty input buffer (by dropping its data) if it becomes
 * too full.
 */
static void
ttloop(void)
{
	if (nfrontp-nbackp) {
		netflush();
	}
read_again:
	ncc = read(net, netibuf, netibufsize);
	if (ncc < 0) {
		if (errno == EINTR)
			goto read_again;
		syslog(LOG_INFO, "ttloop:  read: %m");
		exit(EXIT_FAILURE);
	} else if (ncc == 0) {
		syslog(LOG_INFO, "ttloop:  peer closed connection\n");
		exit(EXIT_FAILURE);
	}

	netip = netibuf;
	telrcv();		/* state machine */
	if (ncc > 0) {
		pfrontp = pbackp = ptyobuf;
		telrcv();
	}
}

static void
send_do(int option)
{
	write_data("%c%c%c", (uchar_t)IAC, (uchar_t)DO, (uchar_t)option);
}

static void
send_will(int option)
{
	write_data("%c%c%c", (uchar_t)IAC, (uchar_t)WILL, (uchar_t)option);
}

static void
send_wont(int option)
{
	write_data("%c%c%c", (uchar_t)IAC, (uchar_t)WONT, (uchar_t)option);
}


/*
 * getauthtype
 *
 * Negotiate automatic authentication, is possible.
 */
static int
getauthtype(char *username, int *len)
{
	int init_status = -1;

	init_status = krb5_init();

	if (auth_level == -1 || init_status != 0) {
		remopts[TELOPT_AUTHENTICATION] = OPT_NO;
		myopts[TELOPT_AUTHENTICATION] = OPT_NO;
		negotiate_auth_krb5 = B_FALSE;
		negotiate_encrypt = B_FALSE;
		return (AUTH_REJECT);
	}

	if (init_status == 0 && auth_level != -1) {
		if (negotiate_auth_krb5) {
			/*
			 * Negotiate Authentication FIRST
			 */
			send_do(TELOPT_AUTHENTICATION);
			remopts[TELOPT_AUTHENTICATION] =
				OPT_YES_BUT_ALWAYS_LOOK;
		}
		while (sequenceIs(authopt, getauth))
			ttloop();

		if (remopts[TELOPT_AUTHENTICATION] == OPT_YES) {
			/*
			 * Request KRB5 Mutual authentication and if that fails,
			 * KRB5 1-way client authentication
			 */
			uchar_t sbbuf[MAXOPTLEN], *p;
			p = sbbuf;
			*p++ = (uchar_t)IAC;
			*p++ = (uchar_t)SB;
			*p++ = (uchar_t)TELOPT_AUTHENTICATION;
			*p++ = (uchar_t)TELQUAL_SEND;
			if (negotiate_auth_krb5) {
				*p++ = (uchar_t)AUTHTYPE_KERBEROS_V5;
				*p++ = (uchar_t)(AUTH_WHO_CLIENT |
						AUTH_HOW_MUTUAL |
						AUTH_ENCRYPT_ON);
				*p++ = (uchar_t)AUTHTYPE_KERBEROS_V5;
				*p++ = (uchar_t)(AUTH_WHO_CLIENT |
						AUTH_HOW_MUTUAL);
				*p++ = (uchar_t)AUTHTYPE_KERBEROS_V5;
				*p++ = (uchar_t)(AUTH_WHO_CLIENT|
						AUTH_HOW_ONE_WAY);
			} else {
				*p++ = (uchar_t)AUTHTYPE_NULL;
			}
			*p++ = (uchar_t)IAC;
			*p++ = (uchar_t)SE;

			write_data_len((const char *)sbbuf,
				    (size_t)(p - sbbuf));
			netflush();
			if (auth_debug)
				(void) fprintf(stderr,
					    "SENT TELOPT_AUTHENTICATION "
					    "[data]\n");

			/* auth_wait returns the authentication level */
			/* status = auth_wait(username, len); */
			while (sequenceIs(authdone, getauth))
				ttloop();
			/*
			 * Now check to see if the user is valid or not
			 */
			if (authenticated == NULL || authenticated == &NoAuth)
				auth_status = AUTH_REJECT;
			else {
				/*
				 * We cant be VALID until the user status is
				 * checked.
				 */
				if (auth_status == AUTH_VALID)
					auth_status = AUTH_USER;

				if (authenticated->AuthName ==
					AUTHTYPE_KERBEROS_V5)
					auth_status = krb5_user_status(
						username, *len, auth_status);
			}
		}
	}
	return (auth_status);
}

static void
getencrtype(void)
{
	if (krb5_privacy_allowed() && negotiate_encrypt) {
		if (myopts[TELOPT_ENCRYPT] != OPT_YES) {
			if (!sent_will_encrypt) {
				send_will(TELOPT_ENCRYPT);
				sent_will_encrypt = B_TRUE;
			}
			if (enc_debug)
				(void) fprintf(stderr, "SENT WILL ENCRYPT\n");
		}
		if (remopts[TELOPT_ENCRYPT] != OPT_YES) {
			if (!sent_do_encrypt) {
				send_do(TELOPT_ENCRYPT);
				sent_do_encrypt = B_TRUE;
				remopts[TELOPT_ENCRYPT] =
				    OPT_YES_BUT_ALWAYS_LOOK;
			}
			if (enc_debug)
				(void) fprintf(stderr, "SENT DO ENCRYPT\n");
		}
		myopts[TELOPT_ENCRYPT] = OPT_YES;

		while (sequenceIs(encropt, getencr))
		    ttloop();

		if (auth_status != AUTH_REJECT &&
		    remopts[TELOPT_ENCRYPT] == OPT_YES &&
		    myopts[TELOPT_ENCRYPT] == OPT_YES) {

			if (sent_encrypt_support == B_FALSE) {
				write_data("%c%c%c%c%c%c%c",
					(uchar_t)IAC,
					(uchar_t)SB,
					(uchar_t)TELOPT_ENCRYPT,
					(uchar_t)ENCRYPT_SUPPORT,
					(uchar_t)TELOPT_ENCTYPE_DES_CFB64,
					(uchar_t)IAC,
					(uchar_t)SE);

				netflush();
			}
			/*
			 * Now wait for a response to these messages before
			 * continuing...
			 * Look for TELOPT_ENCRYPT suboptions
			 */
			while (sequenceIs(encr_support, getencr))
				ttloop();
		}
	} else {
		/* Dont need responses to these, so dont wait for them */
		settimer(encropt);
		remopts[TELOPT_ENCRYPT] = OPT_NO;
		myopts[TELOPT_ENCRYPT] = OPT_NO;
	}

}

/*
 * getterminaltype
 *
 * Ask the other end to send along its terminal type.
 * Output is the variable terminaltype filled in.
 */
static void
getterminaltype(void)
{
	/*
	 * The remote side may have already sent this info, so
	 * dont ask for these options if the other side already
	 * sent the information.
	 */
	if (sequenceIs(ttypeopt, getterminal)) {
		send_do(TELOPT_TTYPE);
		remopts[TELOPT_TTYPE] = OPT_YES_BUT_ALWAYS_LOOK;
	}

	if (sequenceIs(nawsopt, getterminal)) {
		send_do(TELOPT_NAWS);
		remopts[TELOPT_NAWS] = OPT_YES_BUT_ALWAYS_LOOK;
	}

	if (sequenceIs(xdisplocopt, getterminal)) {
		send_do(TELOPT_XDISPLOC);
		remopts[TELOPT_XDISPLOC] = OPT_YES_BUT_ALWAYS_LOOK;
	}

	if (sequenceIs(environopt, getterminal)) {
		send_do(TELOPT_NEW_ENVIRON);
		remopts[TELOPT_NEW_ENVIRON] = OPT_YES_BUT_ALWAYS_LOOK;
	}

	if (sequenceIs(oenvironopt, getterminal)) {
		send_do(TELOPT_OLD_ENVIRON);
		remopts[TELOPT_OLD_ENVIRON] = OPT_YES_BUT_ALWAYS_LOOK;
	}

	/* make sure encryption is started here */
	while (auth_status != AUTH_REJECT &&
		authenticated != &NoAuth && authenticated != NULL &&
		remopts[TELOPT_ENCRYPT] == OPT_YES &&
		encr_data.encrypt.autoflag &&
		encr_data.encrypt.state != ENCR_STATE_OK) {
	    if (enc_debug)
		(void) fprintf(stderr, "getterminaltype() forcing encrypt\n");
	    ttloop();
	}

	if (enc_debug) {
	    (void) fprintf(stderr, "getterminaltype() encryption %sstarted\n",
		    encr_data.encrypt.state == ENCR_STATE_OK ? "" : "not ");
	}

	while (sequenceIs(ttypeopt, getterminal) ||
	    sequenceIs(nawsopt, getterminal) ||
	    sequenceIs(xdisplocopt, getterminal) ||
	    sequenceIs(environopt, getterminal) ||
	    sequenceIs(oenvironopt, getterminal)) {
		ttloop();
	}


	if (remopts[TELOPT_TTYPE] == OPT_YES) {
		static uchar_t sbbuf[] = { (uchar_t)IAC, (uchar_t)SB,
		    (uchar_t)TELOPT_TTYPE, (uchar_t)TELQUAL_SEND,
		    (uchar_t)IAC, (uchar_t)SE };

		write_data_len((const char *)sbbuf, sizeof (sbbuf));
	}
	if (remopts[TELOPT_XDISPLOC] == OPT_YES) {
		static uchar_t sbbuf[] = { (uchar_t)IAC, (uchar_t)SB,
		    (uchar_t)TELOPT_XDISPLOC, (uchar_t)TELQUAL_SEND,
		    (uchar_t)IAC, (uchar_t)SE };

		write_data_len((const char *)sbbuf, sizeof (sbbuf));
	}
	if (remopts[TELOPT_NEW_ENVIRON] == OPT_YES) {
		static uchar_t sbbuf[] = { (uchar_t)IAC, (uchar_t)SB,
		    (uchar_t)TELOPT_NEW_ENVIRON, (uchar_t)TELQUAL_SEND,
		    (uchar_t)IAC, (uchar_t)SE };

		write_data_len((const char *)sbbuf, sizeof (sbbuf));
	}
	if (remopts[TELOPT_OLD_ENVIRON] == OPT_YES) {
		static uchar_t sbbuf[] = { (uchar_t)IAC, (uchar_t)SB,
		    (uchar_t)TELOPT_OLD_ENVIRON, (uchar_t)TELQUAL_SEND,
		    (uchar_t)IAC, (uchar_t)SE };

		write_data_len((const char *)sbbuf, sizeof (sbbuf));
	}

	if (remopts[TELOPT_TTYPE] == OPT_YES) {
		while (sequenceIs(ttypesubopt, getterminal)) {
			ttloop();
		}
	}
	if (remopts[TELOPT_XDISPLOC] == OPT_YES) {
		while (sequenceIs(xdisplocsubopt, getterminal)) {
			ttloop();
		}
	}
	if (remopts[TELOPT_NEW_ENVIRON] == OPT_YES) {
		while (sequenceIs(environsubopt, getterminal)) {
			ttloop();
		}
	}
	if (remopts[TELOPT_OLD_ENVIRON] == OPT_YES) {
		while (sequenceIs(oenvironsubopt, getterminal)) {
			ttloop();
		}
	}
	init_neg_done = 1;
}

pid_t pid;

/*
 * Get a pty, scan input lines.
 */
static void
doit(int f, struct sockaddr_storage *who)
{
	char *host;
	char host_name[MAXHOSTNAMELEN];
	int p, t, tt;
	struct sgttyb b;
	int	ptmfd;	/* fd of logindmux connected to pty */
	int	netfd;	/* fd of logindmux connected to netf */
	struct	stat	buf;
	struct	protocol_arg	telnetp;
	struct	strioctl	telnetmod;
	struct	envlist	*env, *next;
	int	nsize = 0;
	char abuf[INET6_ADDRSTRLEN];
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	socklen_t wholen;
	char username[MAXUSERNAMELEN];
	int len;
	uchar_t passthru;
	char *slavename;

	if ((p = open("/dev/ptmx", O_RDWR | O_NOCTTY)) == -1) {
		fatalperror(f, "open /dev/ptmx", errno);
	}
	if (grantpt(p) == -1)
		fatal(f, "could not grant slave pty");
	if (unlockpt(p) == -1)
		fatal(f, "could not unlock slave pty");
	if ((slavename = ptsname(p)) == NULL)
		fatal(f, "could not enable slave pty");
	(void) dup2(f, 0);
	if ((t = open(slavename, O_RDWR | O_NOCTTY)) == -1)
		fatal(f, "could not open slave pty");
	if (ioctl(t, I_PUSH, "ptem") == -1)
		fatalperror(f, "ioctl I_PUSH ptem", errno);
	if (ioctl(t, I_PUSH, "ldterm") == -1)
		fatalperror(f, "ioctl I_PUSH ldterm", errno);
	if (ioctl(t, I_PUSH, "ttcompat") == -1)
		fatalperror(f, "ioctl I_PUSH ttcompat", errno);

	line = slavename;

	pty = t;

	if (ioctl(t, TIOCGETP, &b) == -1)
		syslog(LOG_INFO, "ioctl TIOCGETP pty t: %m\n");
	b.sg_flags = O_CRMOD|O_XTABS|O_ANYP;
	/* XXX - ispeed and ospeed must be non-zero */
	b.sg_ispeed = B38400;
	b.sg_ospeed = B38400;
	if (ioctl(t, TIOCSETN, &b) == -1)
		syslog(LOG_INFO, "ioctl TIOCSETN pty t: %m\n");
	if (ioctl(pty, TIOCGETP, &b) == -1)
		syslog(LOG_INFO, "ioctl TIOCGETP pty pty: %m\n");
	b.sg_flags &= ~O_ECHO;
	if (ioctl(pty, TIOCSETN, &b) == -1)
		syslog(LOG_INFO, "ioctl TIOCSETN pty pty: %m\n");

	if (who->ss_family == AF_INET) {
		char *addrbuf = NULL;
		char *portbuf = NULL;

		sin = (struct sockaddr_in *)who;
		wholen = sizeof (struct sockaddr_in);

		addrbuf = (char *)malloc(wholen);
		if (addrbuf == NULL)
			fatal(f, "Cannot alloc memory for address info\n");
		portbuf = (char *)malloc(sizeof (sin->sin_port));
		if (portbuf == NULL) {
			free(addrbuf);
			fatal(f, "Cannot alloc memory for port info\n");
		}

		(void) memcpy(addrbuf, (const void *)&sin->sin_addr, wholen);
		(void) memcpy(portbuf, (const void *)&sin->sin_port,
			    sizeof (sin->sin_port));

		if (rsaddr.contents != NULL)
			free(rsaddr.contents);

		rsaddr.contents = (krb5_octet *)addrbuf;
		rsaddr.length = wholen;
		rsaddr.addrtype = ADDRTYPE_INET;

		if (rsport.contents != NULL)
			free(rsport.contents);

		rsport.contents = (krb5_octet *)portbuf;
		rsport.length = sizeof (sin->sin_port);
		rsport.addrtype = ADDRTYPE_IPPORT;
	} else if (who->ss_family == AF_INET6) {
		struct in_addr ipv4_addr;
		char *addrbuf = NULL;
		char *portbuf = NULL;

		sin6 = (struct sockaddr_in6 *)who;
		wholen = sizeof (struct sockaddr_in6);

		IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr,
				    &ipv4_addr);

		addrbuf = (char *)malloc(wholen);
		if (addrbuf == NULL)
			fatal(f, "Cannot alloc memory for address info\n");

		portbuf = (char *)malloc(sizeof (sin6->sin6_port));
		if (portbuf == NULL) {
			free(addrbuf);
			fatal(f, "Cannot alloc memory for port info\n");
		}

		(void) memcpy((void *) addrbuf,
			    (const void *)&ipv4_addr,
			    wholen);
		/*
		 * If we already used rsaddr.contents, free the previous
		 * buffer.
		 */
		if (rsaddr.contents != NULL)
			free(rsaddr.contents);

		rsaddr.contents = (krb5_octet *)addrbuf;
		rsaddr.length = sizeof (ipv4_addr);
		rsaddr.addrtype = ADDRTYPE_INET;

		(void) memcpy((void *) portbuf, (const void *)&sin6->sin6_port,
			    sizeof (sin6->sin6_port));

		if (rsport.contents != NULL)
			free(rsport.contents);

		rsport.contents = (krb5_octet *)portbuf;
		rsport.length = sizeof (sin6->sin6_port);
		rsport.addrtype = ADDRTYPE_IPPORT;
	} else {
		syslog(LOG_ERR, "unknown address family %d\n",
		    who->ss_family);
		fatal(f, "getpeername: unknown address family\n");
	}

	if (getnameinfo((const struct sockaddr *) who, wholen, host_name,
	    sizeof (host_name), NULL, 0, 0) == 0) {
		host = host_name;
	} else {
		/*
		 * If the '-U' option was given on the cmd line, we must
		 * be able to lookup the hostname
		 */
		if (resolve_hostname) {
			fatal(f, "Couldn't resolve your address into a "
			    "host name.\r\nPlease contact your net "
			    "administrator");
		}

		if (who->ss_family == AF_INET6) {
			if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
				struct in_addr ipv4_addr;

				IN6_V4MAPPED_TO_INADDR(&sin6->sin6_addr,
				    &ipv4_addr);
				host = (char *)inet_ntop(AF_INET,
				    &ipv4_addr, abuf, sizeof (abuf));
			} else {
				host = (char *)inet_ntop(AF_INET6,
				    &sin6->sin6_addr, abuf,
				    sizeof (abuf));
			}
		} else if (who->ss_family == AF_INET) {
				host = (char *)inet_ntop(AF_INET,
				    &sin->sin_addr, abuf, sizeof (abuf));
			}
	}
	/*
	 * Note that sockmod has to be removed since readstream assumes
	 * a "raw" TPI endpoint (e.g. it uses getmsg).
	 */
	if (removemod(f, "sockmod") < 0)
		fatalperror(f, "couldn't remove sockmod", errno);

	encrypt_init();

	/*
	 * Push the crypto module on the stream before 'telmod' so it
	 * can encrypt/decrypt without interfering with telmod functionality
	 * We must push it now because many of the crypto options negotiated
	 * initially must be saved in the crypto module (via IOCTL calls).
	 */
	if (ioctl(f, I_PUSH, "cryptmod") < 0)
		fatalperror(f, "ioctl I_PUSH cryptmod", errno);

	cryptmod_fd = f;
	/*
	 * gotta set the encryption clock now because it is often negotiated
	 * immediately by the client, and if we wait till after we negotiate
	 * auth, it will be out of whack with when the WILL/WONT ENCRYPT
	 * option is received.
	 */
	settimer(getencr);

	/*
	 * get terminal type.
	 */
	username[0] = '\0';
	len = sizeof (username);

	settimer(getterminal);
	settimer(getauth);
	/*
	 * Exchange TELOPT_AUTHENTICATE options per RFC 2941/2942
	 */
	auth_status = getauthtype(username, &len);
	/*
	 * Exchange TELOPT_ENCRYPT options per RFC 2946
	 */
	getencrtype();
	getterminaltype();

	if (ioctl(f, I_PUSH, "telmod") < 0)
		fatalperror(f, "ioctl I_PUSH telmod", errno);

	/*
	 * Make sure telmod will pass unrecognized IOCTLs to cryptmod
	 */
	passthru = 1;

	telnetmod.ic_cmd = CRYPTPASSTHRU;
	telnetmod.ic_timout = -1;
	telnetmod.ic_len = sizeof (uchar_t);
	telnetmod.ic_dp = (char *)&passthru;

	if (ioctl(f, I_STR, &telnetmod) < 0)
		fatal(f, "ioctl CRPASSTHRU failed\n");

	if (!ncc)
		netip = netibuf;

	/*
	 * readstream will do a getmsg till it receives M_PROTO type
	 * T_DATA_REQ from telnetmodopen().  This signals that all data
	 * in-flight before telmod was pushed has been received at the
	 * stream head.
	 */
	while ((nsize = readstream(f, netibuf, ncc + netip - netibuf)) > 0) {
		ncc += nsize;
	}

	if (nsize < 0) {
		fatalperror(f, "readstream failed\n", errno);
	}

	/*
	 * open logindmux drivers and link them with network and ptm
	 * file descriptors.
	 */
	if ((ptmfd = open("/dev/logindmux", O_RDWR)) == -1) {
		fatalperror(f, "open /dev/logindmux", errno);
	}
	if ((netfd = open("/dev/logindmux", O_RDWR)) == -1) {
		fatalperror(f, "open /dev/logindmux", errno);
	}

	if (ioctl(ptmfd, I_LINK, p) < 0)
		fatal(f, "ioctl I_LINK of /dev/ptmx failed\n");
	if (ioctl(netfd, I_LINK, f) < 0)
		fatal(f, "ioctl I_LINK of tcp connection failed\n");

	/*
	 * Figure out the device number of ptm's mux fd, and pass that
	 * to the net's mux.
	 */
	if (fstat(ptmfd, &buf) < 0) {
		fatalperror(f, "fstat ptmfd failed", errno);
	}
	telnetp.dev = buf.st_rdev;
	telnetp.flag = 0;

	telnetmod.ic_cmd = LOGDMX_IOC_QEXCHANGE;
	telnetmod.ic_timout = -1;
	telnetmod.ic_len = sizeof (struct protocol_arg);
	telnetmod.ic_dp = (char *)&telnetp;

	if (ioctl(netfd, I_STR, &telnetmod) < 0)
		fatal(netfd, "ioctl LOGDMX_IOC_QEXCHANGE of netfd failed\n");

	/*
	 * Figure out the device number of the net's mux fd, and pass that
	 * to the ptm's mux.
	 */
	if (fstat(netfd, &buf) < 0) {
		fatalperror(f, "fstat netfd failed", errno);
	}
	telnetp.dev = buf.st_rdev;
	telnetp.flag = 1;

	telnetmod.ic_cmd = LOGDMX_IOC_QEXCHANGE;
	telnetmod.ic_timout = -1;
	telnetmod.ic_len = sizeof (struct protocol_arg);
	telnetmod.ic_dp = (char *)&telnetp;

	if (ioctl(ptmfd, I_STR, &telnetmod) < 0)
		fatal(netfd, "ioctl LOGDMX_IOC_QEXCHANGE of ptmfd failed\n");

	net = netfd;
	master = ptmfd;
	cryptmod_fd = netfd;

	/*
	 * Show banner that getty never gave, but
	 * only if the user did not automatically authenticate.
	 */
	if (getenv("USER") == NULL && auth_status < AUTH_USER)
		showbanner();

	/*
	 * If the user automatically authenticated with Kerberos
	 * we must set the service name that PAM will use.  We
	 * need to do it BEFORE the child fork so that 'cleanup'
	 * in the parent can call the PAM cleanup stuff with the
	 * same PAM service that /bin/login will use to authenticate
	 * this session.
	 */
	if (auth_level >= 0 && auth_status >= AUTH_USER &&
	    (AuthenticatingUser != NULL) && strlen(AuthenticatingUser)) {
		(void) strcpy(pam_svc_name, "ktelnet");
	}
	/*
	 * Request to do suppress go ahead.
	 *
	 * Send this before sending the TELOPT_ECHO stuff below because
	 * some clients (MIT KRB5 telnet) have quirky 'kludge mode' support
	 * that has them turn off local echo mode if SGA is not received first.
	 * This also has the odd side-effect of causing the client to enable
	 * encryption and then immediately disable it during the ECHO option
	 * negotiations.  Its just better to to SGA first now that we support
	 * encryption.
	 */
	if (!myopts[TELOPT_SGA]) {
	    dooption(TELOPT_SGA);
	}

	/*
	 * Pretend we got a DO ECHO from the client if we have not
	 * yet negotiated the ECHO.
	 */
	if (!myopts[TELOPT_ECHO]) {
	    dooption(TELOPT_ECHO);
	}

	/*
	 * Is the client side a 4.2 (NOT 4.3) system?  We need to know this
	 * because 4.2 clients are unable to deal with TCP urgent data.
	 *
	 * To find out, we send out a "DO ECHO".  If the remote system
	 * answers "WILL ECHO" it is probably a 4.2 client, and we note
	 * that fact ("WILL ECHO" ==> that the client will echo what
	 * WE, the server, sends it; it does NOT mean that the client will
	 * echo the terminal input).
	 */
	send_do(TELOPT_ECHO);
	remopts[TELOPT_ECHO] = OPT_YES_BUT_ALWAYS_LOOK;

	if ((pid = fork()) < 0)
		fatalperror(netfd, "fork", errno);
	if (pid)
		telnet(net, master);
	/*
	 * The child process needs to be the session leader
	 * and have the pty as its controlling tty.  Thus we need
	 * to re-open the slave side of the pty no without
	 * the O_NOCTTY flag that we have been careful to
	 * use up to this point.
	 */
	(void) setsid();

	tt = open(line, O_RDWR);
	if (tt < 0)
		fatalperror(netfd, line, errno);
	(void) close(netfd);
	(void) close(ptmfd);
	(void) close(f);
	(void) close(p);
	(void) close(t);
	if (tt != 0)
		(void) dup2(tt, 0);
	if (tt != 1)
		(void) dup2(tt, 1);
	if (tt != 2)
		(void) dup2(tt, 2);
	if (tt > 2)
		(void) close(tt);

	if (terminaltype)
		(void) local_setenv("TERM", terminaltype+5, 1);
	/*
	 * 	-h : pass on name of host.
	 *		WARNING:  -h is accepted by login if and only if
	 *			getuid() == 0.
	 * 	-p : don't clobber the environment (so terminal type stays set).
	 */
	{
		/* System V login expects a utmp entry to already be there */
		struct utmpx ut;
		(void) memset((char *)&ut, 0, sizeof (ut));
		(void) strncpy(ut.ut_user, ".telnet", sizeof (ut.ut_user));
		(void) strncpy(ut.ut_line, line, sizeof (ut.ut_line));
		ut.ut_pid = getpid();
		ut.ut_id[0] = 't';
		ut.ut_id[1] = (char)SC_WILDC;
		ut.ut_id[2] = (char)SC_WILDC;
		ut.ut_id[3] = (char)SC_WILDC;
		ut.ut_type = LOGIN_PROCESS;
		ut.ut_exit.e_termination = 0;
		ut.ut_exit.e_exit = 0;
		(void) time(&ut.ut_tv.tv_sec);
		if (makeutx(&ut) == NULL)
			syslog(LOG_INFO, "in.telnetd:\tmakeutx failed");
	}

	/*
	 * Load in the cached environment variables and either
	 * set/unset them in the environment.
	 */
	for (next = envlist_head; next; ) {
		env = next;
		if (env->delete)
			(void) local_unsetenv(env->name);
		else
			(void) local_setenv(env->name, env->value, 1);
		free(env->name);
		free(env->value);
		next = env->next;
		free(env);
	}

	if (!username || !username[0])
		auth_status = AUTH_REJECT; /* we dont know who this is */

	/* If the current auth status is less than the required level, exit */
	if (auth_status < auth_level) {
		fatal(net, "Authentication failed\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * If AUTH_VALID (proper authentication REQUIRED and we have
	 * a krb5_name), exec '/bin/login', make sure it uses the
	 * correct PAM service name (pam_svc_name). If possible,
	 * make sure the krb5 authenticated user's name (krb5_name)
	 * is in the PAM REPOSITORY for krb5.
	 */
	if (auth_level >= 0 &&
	    (auth_status == AUTH_VALID || auth_status == AUTH_USER) &&
	    ((krb5_name != NULL) && strlen(krb5_name)) &&
	    ((AuthenticatingUser != NULL) && strlen(AuthenticatingUser))) {
		(void) execl(LOGIN_PROGRAM, "login",
			    "-p",
			    "-d", slavename,
			    "-h", host,
			    "-u", krb5_name,
			    "-s", pam_svc_name,
			    "-R", KRB5_REPOSITORY_NAME,
			    AuthenticatingUser, 0);
	} else if (auth_level >= 0 &&
		auth_status >= AUTH_USER &&
		(((AuthenticatingUser != NULL) && strlen(AuthenticatingUser)) ||
		getenv("USER"))) {
		/*
		 * If we only know the name but not the principal,
		 * login will have to authenticate further.
		 */
		(void) execl(LOGIN_PROGRAM, "login",
		    "-p",
		    "-d", slavename,
		    "-h", host,
		    "-s", pam_svc_name, "--",
		    (AuthenticatingUser != NULL ? AuthenticatingUser :
			getenv("USER")), 0);

	} else /* default, no auth. info available, login does it all */ {
		(void) execl(LOGIN_PROGRAM, "login",
		    "-p", "-h", host, "-d", slavename, "--",
		    getenv("USER"), 0);
	}

	fatalperror(netfd, LOGIN_PROGRAM, errno);
	/*NOTREACHED*/
}

static void
fatal(int f, char *msg)
{
	char buf[BUFSIZ];

	(void) snprintf(buf, sizeof (buf), "telnetd: %s.\r\n", msg);
	(void) write(f, buf, strlen(buf));
	exit(EXIT_FAILURE);
	/*NOTREACHED*/
}

static void
fatalperror(int f, char *msg, int errnum)
{
	char buf[BUFSIZ];

	(void) snprintf(buf, sizeof (buf),
			"%s: %s\r\n", msg, strerror(errnum));
	fatal(f, buf);
	/*NOTREACHED*/
}

/*
 * Main loop.  Select from pty and network, and
 * hand data to telnet receiver finite state machine
 * when it receives telnet protocol. Regular data
 * flow between pty and network takes place through
 * inkernel telnet streams module (telmod).
 */
static void
telnet(int net, int master)
{
	int on = 1;
	char mode;
	struct	strioctl	telnetmod;
	int	nsize = 0;
	char	binary_in = 0;
	char binary_out = 0;

	if (ioctl(net, FIONBIO, &on) == -1)
		syslog(LOG_INFO, "ioctl FIONBIO net: %m\n");
	if (ioctl(master, FIONBIO, &on) == -1)
		syslog(LOG_INFO, "ioctl FIONBIO pty p: %m\n");
	(void) signal(SIGTSTP, SIG_IGN);
	(void) signal(SIGCHLD, (void (*)())cleanup);
	(void) setpgrp();

	/*
	 * Call telrcv() once to pick up anything received during
	 * terminal type negotiation.
	 */
	telrcv();

	netflush();
	ptyflush();

	for (;;) {
		fd_set ibits, obits, xbits;
		int c;

		if (ncc < 0)
			break;

		FD_ZERO(&ibits);
		FD_ZERO(&obits);
		FD_ZERO(&xbits);

		/*
		 * If we couldn't flush all our output to the network,
		 * keep checking for when we can.
		 */
		if (nfrontp - nbackp)
			FD_SET(net, &obits);
		/*
		 * Never look for input if there's still
		 * stuff in the corresponding output buffer
		 */
		if (pfrontp - pbackp) {
			FD_SET(master, &obits);
		} else {
			FD_SET(net, &ibits);
		}
		if (!SYNCHing) {
			FD_SET(net, &xbits);
		}

#define	max(x, y)	(((x) < (y)) ? (y) : (x))

		/*
		 * make an ioctl to telnet module (net side) to send
		 * binary mode of telnet daemon. binary_in and
		 * binary_out are 0 if not in binary mode.
		 */
		if (binary_in != myopts[TELOPT_BINARY] ||
		    binary_out != remopts[TELOPT_BINARY]) {

			mode = 0;
			if (myopts[TELOPT_BINARY] != OPT_NO)
				mode |= TEL_BINARY_IN;

			if (remopts[TELOPT_BINARY] != OPT_NO)
				mode |= TEL_BINARY_OUT;

			telnetmod.ic_cmd = TEL_IOC_MODE;
			telnetmod.ic_timout = -1;
			telnetmod.ic_len = 1;
			telnetmod.ic_dp = &mode;

			syslog(LOG_DEBUG, "TEL_IOC_MODE binary has changed\n");

			if (ioctl(net, I_STR, &telnetmod) < 0)
				fatal(net, "ioctl TEL_IOC_MODE failed\n");
			binary_in = myopts[TELOPT_BINARY];
			binary_out = remopts[TELOPT_BINARY];
		}
		if (state == TS_DATA) {
			if ((nfrontp == nbackp) &&
				(pfrontp == pbackp)) {
				if (ioctl(net, I_NREAD, &nsize) < 0)
					fatalperror(net,
					    "ioctl I_NREAD failed\n", errno);
				if (nsize)
					drainstream(nsize);

				/*
				 * make an ioctl to reinsert remaining data at
				 * streamhead. After this, ioctl reenables the
				 * telnet lower put queue. This queue was
				 * noenabled by telnet module after sending
				 * protocol/urgent data to telnetd.
				 */

				telnetmod.ic_cmd = TEL_IOC_ENABLE;
				telnetmod.ic_timout = -1;
				if (ncc || nsize) {
					telnetmod.ic_len = ncc + nsize;
					telnetmod.ic_dp = netip;
				} else {
					telnetmod.ic_len = 0;
					telnetmod.ic_dp = NULL;
				}
				if (ioctl(net, I_STR, &telnetmod) < 0)
					fatal(net, "ioctl TEL_IOC_ENABLE \
						failed\n");

				telmod_init_done = B_TRUE;

				netip = netibuf;
				(void) memset(netibuf, 0, netibufsize);

				ncc = 0;
			}
		} else {
			/*
			 * state not changed to TS_DATA and hence, more to read
			 * send ioctl to get one more message block.
			 */
			telnetmod.ic_cmd = TEL_IOC_GETBLK;
			telnetmod.ic_timout = -1;
			telnetmod.ic_len = 0;
			telnetmod.ic_dp = NULL;

			if (ioctl(net, I_STR, &telnetmod) < 0)
				fatal(net, "ioctl TEL_IOC_GETBLK failed\n");
		}

		if ((c = select(max(net, master) + 1, &ibits, &obits, &xbits,
		    (struct timeval *)0)) < 1) {
			if (c == -1) {
				if (errno == EINTR) {
					continue;
				}
			}
			(void) sleep(5);
			continue;
		}

		/*
		 * Any urgent data?
		 */
		if (FD_ISSET(net, &xbits)) {
			SYNCHing = 1;
		}

		/*
		 * Something to read from the network...
		 */
		if (FD_ISSET(net, &ibits)) {
		    ncc = read(net, netibuf, netibufsize);
		    if (ncc < 0 && errno == EWOULDBLOCK)
			ncc = 0;
		    else {
			if (ncc <= 0) {
			    break;
			}
			netip = netibuf;
		    }
		}

		if (FD_ISSET(net, &obits) && (nfrontp - nbackp) > 0)
			netflush();
		if (ncc > 0)
			telrcv();
		if (FD_ISSET(master, &obits) && (pfrontp - pbackp) > 0)
			ptyflush();
	}
	cleanup(0);
}

static void
telrcv(void)
{
	int c;

	while (ncc > 0) {
		if ((&ptyobuf[BUFSIZ] - pfrontp) < 2)
			return;
		c = *netip & 0377;
		/*
		 * Once we hit data, we want to transition back to
		 * in-kernel processing.  However, this code is shared
		 * by getterminaltype()/ttloop() which run before the
		 * in-kernel plumbing is available.  So if we are still
		 * processing the initial option negotiation, even TS_DATA
		 * must be processed here.
		 */
		if (c != IAC && state == TS_DATA && init_neg_done) {
			break;
		}
		netip++;
		ncc--;
		switch (state) {

		case TS_CR:
			state = TS_DATA;
			/* Strip off \n or \0 after a \r */
			if ((c == 0) || (c == '\n')) {
				break;
			}
			/* FALLTHRU */

		case TS_DATA:
			if (c == IAC) {
				state = TS_IAC;
				break;
			}
			if (inter > 0)
				break;
			/*
			 * We map \r\n ==> \r, since
			 * We now map \r\n ==> \r for pragmatic reasons.
			 * Many client implementations send \r\n when
			 * the user hits the CarriageReturn key.
			 *
			 * We USED to map \r\n ==> \n, since \r\n says
			 * that we want to be in column 1 of the next
			 * line.
			 */
			if (c == '\r' && (myopts[TELOPT_BINARY] == OPT_NO)) {
				state = TS_CR;
			}
			*pfrontp++ = c;
			break;

		case TS_IAC:
			switch (c) {

			/*
			 * Send the process on the pty side an
			 * interrupt.  Do this with a NULL or
			 * interrupt char; depending on the tty mode.
			 */
			case IP:
				interrupt();
				break;

			case BREAK:
				sendbrk();
				break;

			/*
			 * Are You There?
			 */
			case AYT:
				write_data_len("\r\n[Yes]\r\n", 9);
				break;

			/*
			 * Abort Output
			 */
			case AO: {
					struct ltchars tmpltc;

					ptyflush();	/* half-hearted */
					if (ioctl(pty, TIOCGLTC, &tmpltc) == -1)
						syslog(LOG_INFO,
						    "ioctl TIOCGLTC: %m\n");
					if (tmpltc.t_flushc != '\377') {
						*pfrontp++ = tmpltc.t_flushc;
					}
					netclear();	/* clear buffer back */
					write_data("%c%c", (uchar_t)IAC,
						(uchar_t)DM);

					neturg = nfrontp-1; /* off by one XXX */
					netflush();
					netflush(); /* XXX.sparker */
					break;
				}

			/*
			 * Erase Character and
			 * Erase Line
			 */
			case EC:
			case EL: {
					struct sgttyb b;
					char ch;

					ptyflush();	/* half-hearted */
					if (ioctl(pty, TIOCGETP, &b) == -1)
						syslog(LOG_INFO,
						    "ioctl TIOCGETP: %m\n");
					ch = (c == EC) ?
						b.sg_erase : b.sg_kill;
					if (ch != '\377') {
						*pfrontp++ = ch;
					}
					break;
				}

			/*
			 * Check for urgent data...
			 */
			case DM:
				break;

			/*
			 * Begin option subnegotiation...
			 */
			case SB:
				state = TS_SB;
				SB_CLEAR();
				continue;

			case WILL:
				state = TS_WILL;
				continue;

			case WONT:
				state = TS_WONT;
				continue;

			case DO:
				state = TS_DO;
				continue;

			case DONT:
				state = TS_DONT;
				continue;

			case IAC:
				*pfrontp++ = c;
				break;
			}
			state = TS_DATA;
			break;
		case TS_SB:
			if (c == IAC) {
				state = TS_SE;
			} else {
				SB_ACCUM(c);
			}
			break;
		case TS_SE:
			if (c != SE) {
				if (c != IAC) {
					SB_ACCUM((uchar_t)IAC);
				}
				SB_ACCUM(c);
				state = TS_SB;

			} else {
				SB_TERM();
				suboption();	/* handle sub-option */
				state = TS_DATA;
			}
			break;

		case TS_WILL:
			if (remopts[c] != OPT_YES)
				willoption(c);
			state = TS_DATA;
			continue;

		case TS_WONT:
			if (remopts[c] != OPT_NO)
				wontoption(c);
			state = TS_DATA;
			continue;

		case TS_DO:
			if (myopts[c] != OPT_YES)
				dooption(c);
			state = TS_DATA;
			continue;

		case TS_DONT:
			if (myopts[c] != OPT_NO) {
				dontoption(c);
			}
			state = TS_DATA;
			continue;

		default:
			syslog(LOG_ERR, "telnetd: panic state=%d\n", state);
			(void) printf("telnetd: panic state=%d\n", state);
			exit(EXIT_FAILURE);
		}
	}
}

static void
willoption(int option)
{
	uchar_t *fmt;
	boolean_t send_reply = B_TRUE;

	switch (option) {
	case TELOPT_BINARY:
		mode(O_RAW, 0);
		fmt = doopt;
		break;

	case TELOPT_ECHO:
		not42 = 0;		/* looks like a 4.2 system */
		/*
		 * Now, in a 4.2 system, to break them out of ECHOing
		 * (to the terminal) mode, we need to send a "WILL ECHO".
		 * Kludge upon kludge!
		 */
		if (myopts[TELOPT_ECHO] == OPT_YES) {
			dooption(TELOPT_ECHO);
		}
		fmt = dont;
		break;
	case TELOPT_TTYPE:
		settimer(ttypeopt);
		goto common;

	case TELOPT_NAWS:
		settimer(nawsopt);
		goto common;

	case TELOPT_XDISPLOC:
		settimer(xdisplocopt);
		goto common;

	case TELOPT_NEW_ENVIRON:
		settimer(environopt);
		goto common;

	case TELOPT_AUTHENTICATION:
		settimer(authopt);
		if (remopts[option] == OPT_NO ||
		    negotiate_auth_krb5 == 0)
			fmt = dont;
		else
			fmt = doopt;
		break;

	case TELOPT_OLD_ENVIRON:
		settimer(oenvironopt);
		goto common;
common:
		if (remopts[option] == OPT_YES_BUT_ALWAYS_LOOK) {
			remopts[option] = OPT_YES;
			return;
		}
		/*FALLTHRU*/
	case TELOPT_SGA:
		fmt = doopt;
		break;

	case TELOPT_TM:
		fmt = dont;
		break;

	case TELOPT_ENCRYPT:
		settimer(encropt); /* got response to do/dont */
		if (enc_debug)
			(void) fprintf(stderr,
				    "RCVD IAC WILL TELOPT_ENCRYPT\n");
		if (krb5_privacy_allowed()) {
			fmt = doopt;
			if (sent_do_encrypt)
				send_reply = B_FALSE;
			else
				sent_do_encrypt = B_TRUE;
		} else {
			fmt = dont;
		}
		break;

	default:
		fmt = dont;
		break;
	}
	if (fmt == doopt) {
		remopts[option] = OPT_YES;
	} else {
		remopts[option] = OPT_NO;
	}
	if (send_reply) {
		write_data((const char *)fmt, option);
		netflush();
	}
}

static void
wontoption(int option)
{
	uchar_t *fmt;
	int send_reply = 1;

	switch (option) {
	case TELOPT_ECHO:
		not42 = 1;		/* doesn't seem to be a 4.2 system */
		break;

	case TELOPT_BINARY:
		mode(0, O_RAW);
		break;

	case TELOPT_TTYPE:
		settimer(ttypeopt);
		break;

	case TELOPT_NAWS:
		settimer(nawsopt);
		break;

	case TELOPT_XDISPLOC:
		settimer(xdisplocopt);
		break;

	case TELOPT_NEW_ENVIRON:
		settimer(environopt);
		break;

	case TELOPT_OLD_ENVIRON:
		settimer(oenvironopt);
		break;

	case TELOPT_AUTHENTICATION:
		settimer(authopt);
		auth_finished(0, AUTH_REJECT);
		if (auth_debug)
			(void) fprintf(stderr,
				    "RCVD WONT TELOPT_AUTHENTICATE\n");

		remopts[option] = OPT_NO;
		send_reply = 0;
		break;

	case TELOPT_ENCRYPT:
		if (enc_debug)
			(void) fprintf(stderr,
				    "RCVD IAC WONT TELOPT_ENCRYPT\n");
		settimer(encropt); /* got response to will/wont */
		/*
		 * Remote side cannot send encryption. No reply necessary
		 * Treat this as if "IAC SB ENCRYPT END IAC SE" were
		 * received (RFC 2946) and disable crypto.
		 */
		encrypt_end(TELNET_DIR_DECRYPT);
		send_reply = 0;
		break;
	}

	fmt = dont;
	remopts[option] = OPT_NO;
	if (send_reply) {
		write_data((const char *)fmt, option);
	}
}

/*
 * We received an "IAC DO ..." message from the client, change our state
 * to OPT_YES.
 */
static void
dooption(int option)
{
	uchar_t *fmt;
	boolean_t send_reply = B_TRUE;

	switch (option) {

	case TELOPT_TM:
		fmt = wont;
		break;

	case TELOPT_ECHO:
		mode(O_ECHO|O_CRMOD, 0);
		fmt = will;
		break;

	case TELOPT_BINARY:
		mode(O_RAW, 0);
		fmt = will;
		break;

	case TELOPT_SGA:
		fmt = will;
		break;

	case TELOPT_LOGOUT:
		/*
		 * Options don't get much easier.  Acknowledge the option,
		 * and then clean up and exit.
		 */
		write_data((const char *)will, option);
		netflush();
		cleanup(0);
		/*NOTREACHED*/

	case TELOPT_ENCRYPT:
		if (enc_debug)
			(void) fprintf(stderr, "RCVD DO TELOPT_ENCRYPT\n");
		settimer(encropt);
		/*
		 * We received a "DO".  This indicates that the other side
		 * wants us to encrypt our data (pending negotiatoin).
		 * reply with "IAC WILL ENCRYPT" if we are able to send
		 * encrypted data.
		 */
		if (krb5_privacy_allowed() && negotiate_encrypt) {
			fmt = will;
			if (sent_will_encrypt)
				send_reply = B_FALSE;
			else
				sent_will_encrypt = B_TRUE;
			/* return if we already sent "WILL ENCRYPT" */
			if (myopts[option] == OPT_YES)
				return;
		} else {
			fmt = wont;
		}
		break;

	case TELOPT_AUTHENTICATION:
		if (auth_debug) {
			(void) fprintf(stderr,
				    "RCVD DO TELOPT_AUTHENTICATION\n");
		}
		/*
		 * RFC 2941 - only the server can send
		 * "DO TELOPT_AUTHENTICATION".
		 * if a server receives this, it must respond with WONT...
		 */
		fmt = wont;
		break;

	default:
		fmt = wont;
		break;
	}
	if (fmt == will) {
		myopts[option] = OPT_YES;
	} else {
		myopts[option] = OPT_NO;
	}
	if (send_reply) {
		write_data((const char *)fmt, option);
		netflush();
	}
}

/*
 * We received an "IAC DONT ..." message from client.
 * Client does not agree with the option so act accordingly.
 */
static void
dontoption(int option)
{
	int send_reply = 1;
	switch (option) {
	case TELOPT_ECHO:
		/*
		 * we should stop echoing, since the client side will be doing
		 * it, but keep mapping CR since CR-LF will be mapped to it.
		 */
		mode(0, O_ECHO);
		break;

	case TELOPT_ENCRYPT:
		if (enc_debug)
			(void) fprintf(stderr, "RCVD IAC DONT ENCRYPT\n");
		settimer(encropt);
		/*
		 * Remote side cannot receive any encrypted data,
		 * so dont send any.  No reply necessary.
		 */
		send_reply = 0;
		break;

	default:
		break;
	}

	myopts[option] = OPT_NO;

	if (send_reply) {
		write_data((const char *)wont, option);
	}
}

/*
 * suboption()
 *
 *	Look at the sub-option buffer, and try to be helpful to the other
 * side.
 *
 */
static void
suboption(void)
{
	int subchar;

	switch (subchar = SB_GET()) {
	case TELOPT_TTYPE: {		/* Yaaaay! */
		static char terminalname[5+41] = "TERM=";

		settimer(ttypesubopt);

		if (SB_GET() != TELQUAL_IS) {
			return;	/* ??? XXX but, this is the most robust */
		}

		terminaltype = terminalname+strlen(terminalname);

		while (terminaltype < (terminalname + sizeof (terminalname) -
		    1) && !SB_EOF()) {
			int c;

			c = SB_GET();
			if (isupper(c)) {
				c = tolower(c);
			}
			*terminaltype++ = c;    /* accumulate name */
		}
		*terminaltype = 0;
		terminaltype = terminalname;
		break;
	}

	case TELOPT_NAWS: {
		struct winsize ws;

		if (SB_EOF()) {
			return;
		}
		ws.ws_col = SB_GET() << 8;
		if (SB_EOF()) {
			return;
		}
		ws.ws_col |= SB_GET();
		if (SB_EOF()) {
			return;
		}
		ws.ws_row = SB_GET() << 8;
		if (SB_EOF()) {
			return;
		}
		ws.ws_row |= SB_GET();
		ws.ws_xpixel = 0; ws.ws_ypixel = 0;
		(void) ioctl(pty, TIOCSWINSZ, &ws);
		settimer(nawsopt);
		break;
	}

	case TELOPT_XDISPLOC: {
		if (SB_EOF() || SB_GET() != TELQUAL_IS) {
			return;
		}
		settimer(xdisplocsubopt);
		subpointer[SB_LEN()] = '\0';
		if ((new_env("DISPLAY", subpointer)) == 1)
			perror("malloc");
		break;
	}

	case TELOPT_NEW_ENVIRON:
	case TELOPT_OLD_ENVIRON: {
		int c;
		char *cp, *varp, *valp;

		if (SB_EOF())
			return;
		c = SB_GET();
		if (c == TELQUAL_IS) {
			if (subchar == TELOPT_OLD_ENVIRON)
				settimer(oenvironsubopt);
			else
				settimer(environsubopt);
		} else if (c != TELQUAL_INFO) {
			return;
		}

		if (subchar == TELOPT_NEW_ENVIRON) {
		    while (!SB_EOF()) {
			c = SB_GET();
			if ((c == NEW_ENV_VAR) || (c == ENV_USERVAR))
				break;
		    }
		} else
		{
			while (!SB_EOF()) {
				c = SB_GET();
				if ((c == env_ovar) || (c == ENV_USERVAR))
					break;
			}
		}

		if (SB_EOF())
			return;

		cp = varp = (char *)subpointer;
		valp = 0;

		while (!SB_EOF()) {
			c = SB_GET();
			if (subchar == TELOPT_OLD_ENVIRON) {
				if (c == env_ovar)
					c = NEW_ENV_VAR;
				else if (c == env_ovalue)
					c = NEW_ENV_VALUE;
			}
			switch (c) {

			case NEW_ENV_VALUE:
				*cp = '\0';
				cp = valp = (char *)subpointer;
				break;

			case NEW_ENV_VAR:
			case ENV_USERVAR:
				*cp = '\0';
				if (valp) {
					if ((new_env(varp, valp)) == 1) {
						perror("malloc");
					}
				} else {
					(void) del_env(varp);
				}
				cp = varp = (char *)subpointer;
				valp = 0;
				break;

			case ENV_ESC:
				if (SB_EOF())
					break;
				c = SB_GET();
				/* FALL THROUGH */
			default:
				*cp++ = c;
				break;
			}
		}
		*cp = '\0';
		if (valp) {
			if ((new_env(varp, valp)) == 1) {
				perror("malloc");
			}
		} else {
			(void) del_env(varp);
		}
		break;
	}  /* end of case TELOPT_NEW_ENVIRON */

	case TELOPT_AUTHENTICATION:
		if (SB_EOF())
			break;
		switch (SB_GET()) {
		case TELQUAL_SEND:
		case TELQUAL_REPLY:
			/*
			 * These are sent server only and cannot be sent by the
			 * client.
			 */
			break;
		case TELQUAL_IS:
			if (auth_debug)
				(void) fprintf(stderr,
					    "RCVD AUTHENTICATION IS "
					    "(%d bytes)\n",
					    SB_LEN());
			if (!auth_negotiated)
				auth_is((uchar_t *)subpointer, SB_LEN());
			break;
		case TELQUAL_NAME:
			if (auth_debug)
				(void) fprintf(stderr,
					    "RCVD AUTHENTICATION NAME "
					    "(%d bytes)\n",
					    SB_LEN());
			if (!auth_negotiated)
				auth_name((uchar_t *)subpointer, SB_LEN());
			break;
		}
		break;

	case TELOPT_ENCRYPT: {
		int c;
		if (SB_EOF())
			break;
		c = SB_GET();
#ifdef ENCRYPT_NAMES
		if (enc_debug)
			(void) fprintf(stderr, "RCVD ENCRYPT %s\n",
				    ENCRYPT_NAME(c));
#endif /* ENCRYPT_NAMES */
		switch (c) {
		case ENCRYPT_SUPPORT:
			encrypt_support(subpointer, SB_LEN());
			break;
		case ENCRYPT_IS:
			encrypt_is((uchar_t *)subpointer, SB_LEN());
			break;
		case ENCRYPT_REPLY:
			(void) encrypt_reply(subpointer, SB_LEN());
			break;
		case ENCRYPT_START:
			encrypt_start();
			break;
		case ENCRYPT_END:
			encrypt_end(TELNET_DIR_DECRYPT);
			break;
		case ENCRYPT_REQSTART:
			encrypt_request_start();
			break;
		case ENCRYPT_REQEND:
			/*
			 * We can always send an REQEND so that we cannot
			 * get stuck encrypting.  We should only get this
			 * if we have been able to get in the correct mode
			 * anyhow.
			 */
			encrypt_request_end();
			break;
		case ENCRYPT_ENC_KEYID:
			encrypt_enc_keyid(subpointer, SB_LEN());
			break;
		case ENCRYPT_DEC_KEYID:
			encrypt_dec_keyid(subpointer, SB_LEN());
			break;
		default:
			break;
		}
	}
	break;

	default:
		break;
	}
}

static void
mode(int on, int off)
{
	struct termios  tios;

	ptyflush();
	if (tcgetattr(pty, &tios) < 0)
		syslog(LOG_INFO, "tcgetattr: %m\n");

	if (on & O_RAW) {
		tios.c_cflag |= CS8;
		tios.c_iflag &= ~IUCLC;
		tios.c_lflag &= ~(XCASE|IEXTEN);
	}
	if (off & O_RAW) {
		if ((tios.c_cflag & PARENB) != 0)
			tios.c_cflag &= ~CS8;
		tios.c_lflag |= IEXTEN;
	}

	if (on & O_ECHO)
		tios.c_lflag |= ECHO;
	if (off & O_ECHO)
		tios.c_lflag &= ~ECHO;

	if (on & O_CRMOD) {
		tios.c_iflag |= ICRNL;
		tios.c_oflag |= ONLCR;
	}
	/*
	 * Because "O_CRMOD" will never be set in "off" we don't have to
	 * handle this case here.
	 */

	if (tcsetattr(pty, TCSANOW, &tios) < 0)
		syslog(LOG_INFO, "tcsetattr: %m\n");
}

/*
 * Send interrupt to process on other side of pty.
 * If it is in raw mode, just write NULL;
 * otherwise, write intr char.
 */
static void
interrupt(void)
{
	struct sgttyb b;
	struct tchars tchars;

	ptyflush();	/* half-hearted */
	if (ioctl(pty, TIOCGETP, &b) == -1)
		syslog(LOG_INFO, "ioctl TIOCGETP: %m\n");
	if (b.sg_flags & O_RAW) {
		*pfrontp++ = '\0';
		return;
	}
	*pfrontp++ = ioctl(pty, TIOCGETC, &tchars) < 0 ?
		'\177' : tchars.t_intrc;
}

/*
 * Send quit to process on other side of pty.
 * If it is in raw mode, just write NULL;
 * otherwise, write quit char.
 */
static void
sendbrk(void)
{
	struct sgttyb b;
	struct tchars tchars;

	ptyflush();	/* half-hearted */
	(void) ioctl(pty, TIOCGETP, &b);
	if (b.sg_flags & O_RAW) {
		*pfrontp++ = '\0';
		return;
	}
	*pfrontp++ = ioctl(pty, TIOCGETC, &tchars) < 0 ?
		'\034' : tchars.t_quitc;
}

static void
ptyflush(void)
{
	int n;

	if ((n = pfrontp - pbackp) > 0)
		n = write(master, pbackp, n);
	if (n < 0)
		return;
	pbackp += n;
	if (pbackp == pfrontp)
		pbackp = pfrontp = ptyobuf;
}

/*
 * nextitem()
 *
 *	Return the address of the next "item" in the TELNET data
 * stream.  This will be the address of the next character if
 * the current address is a user data character, or it will
 * be the address of the character following the TELNET command
 * if the current address is a TELNET IAC ("I Am a Command")
 * character.
 */

static char *
nextitem(char *current)
{
	if ((*current&0xff) != IAC) {
		return (current+1);
	}
	switch (*(current+1)&0xff) {
	case DO:
	case DONT:
	case WILL:
	case WONT:
		return (current+3);
	case SB:		/* loop forever looking for the SE */
	{
		char *look = current+2;

		for (;;) {
			if ((*look++&0xff) == IAC) {
				if ((*look++&0xff) == SE) {
					return (look);
				}
			}
		}
	}
	default:
		return (current+2);
	}
}


/*
 * netclear()
 *
 *	We are about to do a TELNET SYNCH operation.  Clear
 * the path to the network.
 *
 *	Things are a bit tricky since we may have sent the first
 * byte or so of a previous TELNET command into the network.
 * So, we have to scan the network buffer from the beginning
 * until we are up to where we want to be.
 *
 *	A side effect of what we do, just to keep things
 * simple, is to clear the urgent data pointer.  The principal
 * caller should be setting the urgent data pointer AFTER calling
 * us in any case.
 */
static void
netclear(void)
{
	char *thisitem, *next;
	char *good;
#define	wewant(p)	((nfrontp > p) && ((*p&0xff) == IAC) && \
				((*(p+1)&0xff) != EC) && ((*(p+1)&0xff) != EL))

	thisitem = netobuf;

	while ((next = nextitem(thisitem)) <= nbackp) {
		thisitem = next;
	}

	/* Now, thisitem is first before/at boundary. */

	good = netobuf;	/* where the good bytes go */

	while (nfrontp > thisitem) {
		if (wewant(thisitem)) {
			int length;

			next = thisitem;
			do {
				next = nextitem(next);
			} while (wewant(next) && (nfrontp > next));
			length = next-thisitem;
			(void) memmove(good, thisitem, length);
			good += length;
			thisitem = next;
		} else {
			thisitem = nextitem(thisitem);
		}
	}

	nbackp = netobuf;
	nfrontp = good;		/* next byte to be sent */
	neturg = 0;
}


/*
 *  netflush
 *		Send as much data as possible to the network,
 *	handling requests for urgent data.
 */
static void
netflush(void)
{
	int n;

	if ((n = nfrontp - nbackp) > 0) {
		/*
		 * if no urgent data, or if the other side appears to be an
		 * old 4.2 client (and thus unable to survive TCP urgent data),
		 * write the entire buffer in non-OOB mode.
		 */
		if ((neturg == 0) || (not42 == 0)) {
			n = write(net, nbackp, n);	/* normal write */
		} else {
			n = neturg - nbackp;
			/*
			 * In 4.2 (and 4.3) systems, there is some question
			 * about what byte in a sendOOB operation is the "OOB"
			 * data.  To make ourselves compatible, we only send ONE
			 * byte out of band, the one WE THINK should be OOB
			 * (though we really have more the TCP philosophy of
			 * urgent data rather than the Unix philosophy of OOB
			 * data).
			 */
			if (n > 1) {
				/* send URGENT all by itself */
				n = write(net, nbackp, n-1);
			} else {
				/* URGENT data */
				n = send_oob(net, nbackp, n);
			}
		}
	}
	if (n < 0) {
		if (errno == EWOULDBLOCK)
			return;
		/* should blow this guy away... */
		return;
	}

	nbackp += n;

	if (nbackp >= neturg) {
		neturg = 0;
	}
	if (nbackp == nfrontp) {
		nbackp = nfrontp = netobuf;
	}
}

/* ARGSUSED */
static void
cleanup(int signum)
{
	/*
	 * If the TEL_IOC_ENABLE ioctl hasn't completed, then we need to
	 * handle closing differently.  We close "net" first and then
	 * "master" in that order.  We do close(net) first because
	 * we have no other way to disconnect forwarding between the network
	 * and master.  So by issuing the close()'s we ensure that no further
	 * data rises from TCP.  A more complex fix would be adding proper
	 * support for throwing a "stop" switch for forwarding data between
	 * logindmux peers.  It's possible to block in the close of the tty
	 * while the network still receives data and the telmod module is
	 * TEL_STOPPED.  A denial-of-service attack generates this case,
	 * see 4102102.
	 */

	if (!telmod_init_done) {
		(void) close(net);
		(void) close(master);
	}
	rmut();

	exit(EXIT_FAILURE);
}

static void
rmut(void)
{
	pam_handle_t    *pamh;
	struct utmpx *up;
	char user[sizeof (up->ut_user) + 1];
	char ttyn[sizeof (up->ut_line) + 1];
	char rhost[sizeof (up->ut_host) + 1];

	/* while cleaning up don't allow disruption */
	(void) signal(SIGCHLD, SIG_IGN);

	setutxent();
	while (up = getutxent()) {
		if (up->ut_pid == pid) {
			if (up->ut_type == DEAD_PROCESS) {
				/*
				 * Cleaned up elsewhere.
				 */
				break;
			}

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
				if ((pam_start("telnet", user, NULL, &pamh)) ==
				    PAM_SUCCESS) {
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

	(void) signal(SIGCHLD, (void (*)())cleanup);
}

static int
readstream(int fd, char *buf, int offset)
{
	struct strbuf ctlbuf, datbuf;
	union T_primitives tpi;
	int	ret = 0;
	int	flags = 0;
	int	bytes_avail, count;

	(void) memset((char *)&ctlbuf, 0, sizeof (ctlbuf));
	(void) memset((char *)&datbuf, 0, sizeof (datbuf));

	ctlbuf.buf = (char *)&tpi;
	ctlbuf.maxlen = sizeof (tpi);

	if (ioctl(fd, I_NREAD, &bytes_avail) < 0) {
		syslog(LOG_ERR, "I_NREAD returned error %m");
		return (-1);
	}
	if (bytes_avail > netibufsize - offset) {
		count = netip - netibuf;
		netibuf = (char *)realloc(netibuf,
		    (unsigned)netibufsize + bytes_avail);
		if (netibuf == NULL) {
			fatal(net, "netibuf realloc failed\n");
		}
		netibufsize += bytes_avail;
		netip = netibuf + count;
		buf = netibuf;
	}
	datbuf.buf = buf + offset;
	datbuf.maxlen = netibufsize;
	ret = getmsg(fd, &ctlbuf, &datbuf, &flags);
	if (ret < 0) {
		syslog(LOG_ERR, "getmsg returned -1, errno %d\n",
			errno);
		return (-1);
	}
	if (ctlbuf.len <= 0) {
		return (datbuf.len);
	}

	if (tpi.type == T_DATA_REQ) {
		return (0);
	}

	if ((tpi.type == T_ORDREL_IND) || (tpi.type == T_DISCON_IND))
		cleanup(0);
	fatal(fd, "no data or protocol element recognized");
	return (0);
}

static void
drainstream(int size)
{
	int	nbytes;
	int	tsize;

	tsize = netip - netibuf;

	if ((tsize + ncc + size) > netibufsize) {
		if (!(netibuf = (char *)realloc(netibuf,
		    (unsigned)tsize + ncc + size)))
			fatalperror(net, "netibuf realloc failed\n", errno);
		netibufsize = tsize + ncc + size;

		netip = netibuf + tsize;
	}

	if ((nbytes = read(net, (char *)netip + ncc, size)) != size)
		syslog(LOG_ERR, "read %d bytes\n", nbytes);
}

/*
 * TPI style replacement for socket send() primitive, so we don't require
 * sockmod to be on the stream.
 */
static int
send_oob(int fd, char *ptr, int count)
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
	if (ret == 0) {
		ret = count;
	}
	return (ret);
}


/*
 * local_setenv --
 *	Set the value of the environmental variable "name" to be
 *	"value".  If rewrite is set, replace any current value.
 */
static int
local_setenv(const char *name, const char *value, int rewrite)
{
	static int alloced;			/* if allocated space before */
	char *c;
	int l_value, offset;

	/*
	 * Do not allow environment variables which begin with LD_ to be
	 * inserted into the environment.  While normally the dynamic linker
	 * protects the login program, that is based on the assumption hostile
	 * invocation of login are from non-root users.  However, since telnetd
	 * runs as root, this cannot be utilized.  So instead we simply
	 * prevent LD_* from being inserted into the environment.
	 * This also applies to other environment variables that
	 * are to be ignored in setugid apps.
	 * Note that at this point name can contain '='!
	 * Also, do not allow TTYPROMPT to be passed along here.
	 */
	if (strncmp(name, "LD_", 3) == 0 ||
	    strncmp(name, "NLSPATH", 7) == 0 ||
	    (strncmp(name, "TTYPROMPT", 9) == 0 &&
		(name[9] == '\0' || name[9] == '='))) {
		return (-1);
	}
	if (*value == '=')			/* no `=' in value */
		++value;
	l_value = strlen(value);
	if ((c = __findenv(name, &offset))) {	/* find if already exists */
		if (!rewrite)
			return (0);
		if ((int)strlen(c) >= l_value) { /* old larger; copy over */
			while (*c++ = *value++)
				;
			return (0);
		}
	} else {					/* create new slot */
		int cnt;
		char **p;

		for (p = environ, cnt = 0; *p; ++p, ++cnt)
			;
		if (alloced) {			/* just increase size */
			environ = (char **)realloc((char *)environ,
			    (size_t)(sizeof (char *) * (cnt + 2)));
			if (!environ)
				return (-1);
		} else {				/* get new space */
			alloced = 1;		/* copy old entries into it */
			p = (char **)malloc((size_t)(sizeof (char *)*
			    (cnt + 2)));
			if (!p)
				return (-1);
			(void) memcpy(p, environ, cnt * sizeof (char *));
			environ = p;
		}
		environ[cnt + 1] = NULL;
		offset = cnt;
	}
	for (c = (char *)name; *c && *c != '='; ++c)	/* no `=' in name */
		;
	if (!(environ[offset] =			/* name + `=' + value */
	    malloc((size_t)((int)(c - name) + l_value + 2))))
		return (-1);
	for (c = environ[offset]; ((*c = *name++) != 0) && (*c != '='); ++c)
		;
	for (*c++ = '='; *c++ = *value++; )
		;
	return (0);
}

/*
 * local_unsetenv(name) --
 *	Delete environmental variable "name".
 */
static void
local_unsetenv(const char *name)
{
	char **p;
	int offset;

	while (__findenv(name, &offset))	/* if set multiple times */
		for (p = &environ[offset]; ; ++p)
			if ((*p = *(p + 1)) == 0)
				break;
}

/*
 * __findenv --
 *	Returns pointer to value associated with name, if any, else NULL.
 *	Sets offset to be the offset of the name/value combination in the
 *	environmental array, for use by local_setenv() and local_unsetenv().
 *	Explicitly removes '=' in argument name.
 */
static char *
__findenv(const char *name, int *offset)
{
	extern char **environ;
	int len;
	const char *np;
	char **p, *c;

	if (name == NULL || environ == NULL)
		return (NULL);
	for (np = name; *np && *np != '='; ++np)
		continue;
	len = np - name;
	for (p = environ; (c = *p) != NULL; ++p)
		if (strncmp(c, name, len) == 0 && c[len] == '=') {
			*offset = p - environ;
			return (c + len + 1);
		}
	return (NULL);
}

static void
showbanner(void)
{
	char	*cp;
	char	evalbuf[BUFSIZ];

	if (defopen(defaultfile) == 0) {
		int	flags;

		/* ignore case */
		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);
		if (cp = defread(bannervar)) {
			FILE	*fp;

			if (strlen(cp) + strlen("eval echo '") + strlen("'\n")
			    + 1 < sizeof (evalbuf)) {
				(void) strlcpy(evalbuf, "eval echo '",
					sizeof (evalbuf));
				(void) strlcat(evalbuf, cp, sizeof (evalbuf));
				(void) strlcat(evalbuf, "'\n",
						sizeof (evalbuf));

				if (fp = popen(evalbuf, "r")) {
					char	buf[BUFSIZ];
					size_t	size;

					/*
					 * Pipe I/O atomicity guarantees we
					 * need only one read.
					 */
					if ((size = fread(buf, 1,
							sizeof (buf) - 1,
							fp)) != 0) {
						char	*p;
						buf[size] = '\0';
						p = strrchr(buf, '\n');
						if (p != NULL)
							*p = '\0';
						if (strlen(buf)) {
							map_banner(buf);
							netflush();
						}
					}
					(void) pclose(fp);
					/* close default file */
					(void) defopen(NULL);
					return;
				}
			}
		}
		(void) defopen(NULL);	/* close default file */
	}

	defbanner();
	netflush();
}

static void
map_banner(char *p)
{
	char	*q;

	/*
	 *	Map the banner:  "\n" -> "\r\n" and "\r" -> "\r\0"
	 */
	for (q = nfrontp; p && *p && q < nfrontp + sizeof (netobuf) - 1; )
		if (*p == '\n') {
			*q++ = '\r';
			*q++ = '\n';
			p++;
		} else if (*p == '\r') {
			*q++ = '\r';
			*q++ = '\0';
			p++;
		} else
			*q++ = *p++;

	nfrontp += q - netobuf;
}

/*
 * Show banner that getty never gave.  By default, this is `uname -sr`.
 *
 * The banner includes some null's (for TELNET CR disambiguation),
 * so we have to be somewhat complicated.
 */
static void
defbanner(void)
{
	struct utsname u;

	/*
	 * Dont show this if the '-h' option was present
	 */
	if (!show_hostinfo)
		return;

	if (uname(&u) == -1)
		return;

	write_data_len((const char *) BANNER1, sizeof (BANNER1) - 1);
	write_data_len(u.sysname, strlen(u.sysname));
	write_data_len(" ", 1);
	write_data_len(u.release, strlen(u.release));
	write_data_len((const char *)BANNER2, sizeof (BANNER2) - 1);
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

static void
write_data(const char *format, ...)
{
	va_list args;
	int		len;
	char	argp[BUFSIZ];

	va_start(args, format);

	if ((len = vsnprintf(argp, sizeof (argp), format, args)) == -1)
		return;

	write_data_len(argp, len);
	va_end(args);
}

static void
write_data_len(const char *buf, int len)
{
	int remaining, copied;

	remaining = BUFSIZ - (nfrontp - netobuf);
	while (len > 0) {
		/*
		 * If there's not enough space in netobuf then
		 * try to make some.
		 */
	if ((len > BUFSIZ ? BUFSIZ : len) > remaining) {
			netflush();
			remaining = BUFSIZ - (nfrontp - netobuf);
		}
		/* Copy as much as we can */
		copied = remaining > len ? len : remaining;
		(void) memmove(nfrontp, buf, copied);
		nfrontp += copied;
		len -= copied;
		remaining -= copied;
		buf += copied;
	}
}
