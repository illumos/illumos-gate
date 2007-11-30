/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This program is the ssh daemon.  It listens for connections from clients,
 * and performs authentication, executes use commands or shell, and forwards
 * information to/from the application to the user client over an encrypted
 * connection.  This can also handle forwarding of X11, TCP/IP, and
 * authentication agent connections.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 implementation:
 * Privilege Separation:
 *
 * Copyright (c) 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 2002 Niels Provos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"
RCSID("$OpenBSD: sshd.c,v 1.260 2002/09/27 10:42:09 mickey Exp $");

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/md5.h>

#include <openssl/rand.h>
#ifdef HAVE_SECUREWARE
#include <sys/security.h>
#include <prot.h>
#endif

#include "ssh.h"
#include "ssh1.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "rsa.h"
#include "sshpty.h"
#include "packet.h"
#include "mpaux.h"
#include "log.h"
#include "servconf.h"
#include "uidswap.h"
#include "compat.h"
#include "buffer.h"
#include "cipher.h"
#include "kex.h"
#include "key.h"
#include "dh.h"
#include "myproposal.h"
#include "authfile.h"
#include "pathnames.h"
#include "atomicio.h"
#include "canohost.h"
#include "auth.h"
#include "misc.h"
#include "dispatch.h"
#include "channels.h"
#include "session.h"
#include "g11n.h"
#include "sshlogin.h"
#include "xlist.h"

#ifdef HAVE_BSM
#include "bsmaudit.h"
adt_session_data_t *ah = NULL;
#endif /* HAVE_BSM */

#ifdef ALTPRIVSEP
#include "altprivsep.h"
#endif /* ALTPRIVSEP */

#ifdef HAVE_SOLARIS_CONTRACTS
#include <sys/ctfs.h>
#include <sys/contract.h>
#include <sys/contract/process.h>
#include <libcontract.h>
#endif /* HAVE_SOLARIS_CONTRACTS */

#ifdef GSSAPI
#include "ssh-gss.h"
extern Gssctxt *xxx_gssctxt;
#endif /* GSSAPI */

#ifdef LIBWRAP
#include <tcpd.h>
#include <syslog.h>
#ifndef lint
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif /* lint */
#endif /* LIBWRAP */

#ifndef O_NOCTTY
#define O_NOCTTY	0
#endif

#ifdef HAVE___PROGNAME
extern char *__progname;
#else
char *__progname;
#endif

/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
static char *config_file_name = _PATH_SERVER_CONFIG_FILE;

/*
 * Flag indicating whether IPv4 or IPv6.  This can be set on the command line.
 * Default value is AF_UNSPEC means both IPv4 and IPv6.
 */
#ifdef IPV4_DEFAULT
int IPv4or6 = AF_INET;
#else
int IPv4or6 = AF_UNSPEC;
#endif

/*
 * Debug mode flag.  This can be set on the command line.  If debug
 * mode is enabled, extra debugging output will be sent to the system
 * log, the daemon will not go to background, and will exit after processing
 * the first connection.
 */
int debug_flag = 0;

/* Flag indicating that the daemon should only test the configuration and keys. */
static int test_flag = 0;

/* Flag indicating that the daemon is being started from inetd. */
static int inetd_flag = 0;

/* Flag indicating that sshd should not detach and become a daemon. */
static int no_daemon_flag = 0;

/* debug goes to stderr unless inetd_flag is set */
int log_stderr = 0;

/* Saved arguments to main(). */
static char **saved_argv;
static int saved_argc;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
static int listen_socks[MAX_LISTEN_SOCKS];
static int num_listen_socks = 0;

/*
 * the client's version string, passed by sshd2 in compat mode. if != NULL,
 * sshd will skip the version-number exchange
 */
static char *client_version_string = NULL;
static char *server_version_string = NULL;

/* for rekeying XXX fixme */
Kex *xxx_kex;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
static struct {
	Key	*server_key;		/* ephemeral server key */
	Key	*ssh1_host_key;		/* ssh1 host key */
	Key	**host_keys;		/* all private host keys */
	int	have_ssh1_key;
	int	have_ssh2_key;
	u_char	ssh1_cookie[SSH_SESSION_KEY_LENGTH];
} sensitive_data;

/*
 * Flag indicating whether the RSA server key needs to be regenerated.
 * Is set in the SIGALRM handler and cleared when the key is regenerated.
 */
static volatile sig_atomic_t key_do_regen = 0;

/* This is set to true when a signal is received. */
static volatile sig_atomic_t received_sighup = 0;
static volatile sig_atomic_t received_sigterm = 0;

/* session identifier, used by RSA-auth */
u_char session_id[16];

/* same for ssh2 */
u_char *session_id2 = NULL;
int session_id2_len = 0;

/* record remote hostname or ip */
u_int utmp_len = MAXHOSTNAMELEN;

/* options.max_startup sized array of fd ints */
static int *startup_pipes = NULL;
static int startup_pipe = -1;	/* in child */

#ifdef GSSAPI
static gss_OID_set mechs = GSS_C_NULL_OID_SET;
#endif /* GSSAPI */

/* Prototypes for various functions defined later in this file. */
void destroy_sensitive_data(void);
static void demote_sensitive_data(void);

static void do_ssh1_kex(void);
static void do_ssh2_kex(void);

/*
 * Close all listening sockets
 */
static void
close_listen_socks(void)
{
	int i;

	for (i = 0; i < num_listen_socks; i++)
		(void) close(listen_socks[i]);
	num_listen_socks = -1;
}

static void
close_startup_pipes(void)
{
	int i;

	if (startup_pipes)
		for (i = 0; i < options.max_startups; i++)
			if (startup_pipes[i] != -1)
				(void) close(startup_pipes[i]);
}

/*
 * Signal handler for SIGHUP.  Sshd execs itself when it receives SIGHUP;
 * the effect is to reread the configuration file (and to regenerate
 * the server key).
 */
static void
sighup_handler(int sig)
{
	int save_errno = errno;

	received_sighup = 1;
	(void) signal(SIGHUP, sighup_handler);
	errno = save_errno;
}

/*
 * Called from the main program after receiving SIGHUP.
 * Restarts the server.
 */
static void
sighup_restart(void)
{
	log("Received SIGHUP; restarting.");
	close_listen_socks();
	close_startup_pipes();
	(void) execv(saved_argv[0], saved_argv);
	log("RESTART FAILED: av[0]='%.100s', error: %.100s.", saved_argv[0],
	    strerror(errno));
	exit(1);
}

/*
 * Generic signal handler for terminating signals in the master daemon.
 */
static void
sigterm_handler(int sig)
{
	received_sigterm = sig;
}

/*
 * SIGCHLD handler.  This is called whenever a child dies.  This will then
 * reap any zombies left by exited children.
 */
static void
main_sigchld_handler(int sig)
{
	int save_errno = errno;
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
	    (pid < 0 && errno == EINTR))
		;

	(void) signal(SIGCHLD, main_sigchld_handler);
	errno = save_errno;
}

/*
 * Signal handler for the alarm after the login grace period has expired.
 */
static void
grace_alarm_handler(int sig)
{
	/* XXX no idea how fix this signal handler */

	/* Log error and exit. */
	fatal("Timeout before authentication for %s", get_remote_ipaddr());
}

#ifdef HAVE_SOLARIS_CONTRACTS
static int contracts_fd = -1;
void
contracts_pre_fork()
{
	const char *during = "opening process contract template";

	/*
	 * Failure should not be treated as fatal on the theory that
	 * it's better to start with children in the same contract as
	 * the master listener than not at all.
	 */

	if (contracts_fd == -1) {
		if ((contracts_fd = open64(CTFS_ROOT "/process/template",
				O_RDWR)) == -1)
			goto cleanup;

		during = "setting sundry contract terms";
		if ((errno = ct_pr_tmpl_set_param(contracts_fd, CT_PR_PGRPONLY)))
			goto cleanup;

		if ((errno = ct_tmpl_set_informative(contracts_fd, CT_PR_EV_HWERR)))
			goto cleanup;

		if ((errno = ct_pr_tmpl_set_fatal(contracts_fd, CT_PR_EV_HWERR)))
			goto cleanup;

		if ((errno = ct_tmpl_set_critical(contracts_fd, 0)))
			goto cleanup;
	}

	during = "setting active template";
	if ((errno = ct_tmpl_activate(contracts_fd)))
		goto cleanup;

	debug3("Set active contract");
	return;

cleanup:
	if (contracts_fd != -1)
		(void) close(contracts_fd);

	contracts_fd = -1;

	if (errno)
		debug2("Error while trying to set up active contract"
			" template: %s while %s", strerror(errno), during);
}

void
contracts_post_fork_child()
{
	/* Clear active template so fork() creates no new contracts. */

	if (contracts_fd == -1)
		return;

	if ((errno = (ct_tmpl_clear(contracts_fd))))
		debug2("Error while trying to clear active contract template"
			" (child): %s", strerror(errno));
	else
		debug3("Cleared active contract template (child)");

	(void) close(contracts_fd);

	contracts_fd = -1;
}

void
contracts_post_fork_parent(int fork_succeeded)
{
	char path[PATH_MAX];
	int cfd, n;
	ct_stathdl_t st;
	ctid_t latest;

	/* Clear active template, abandon latest contract. */
	if (contracts_fd == -1)
		return;

	if ((errno = ct_tmpl_clear(contracts_fd)))
		debug2("Error while clearing active contract template: %s",
			strerror(errno));
	else
		debug3("Cleared active contract template (parent)");

	if (!fork_succeeded)
		return;

	if ((cfd = open64(CTFS_ROOT "/process/latest", O_RDONLY)) == -1) {
		debug2("Error while getting latest contract: %s",
			strerror(errno));
		return;
	}

	if ((errno = ct_status_read(cfd, CTD_COMMON, &st)) != 0) {
		debug2("Error while getting latest contract ID: %s",
			strerror(errno));
		(void) close(cfd);
		return;
	}

	latest = ct_status_get_id(st);
	ct_status_free(st);
	(void) close(cfd);

	n = snprintf(path, PATH_MAX, CTFS_ROOT "/all/%ld/ctl", latest);

	if (n >= PATH_MAX) {
		debug2("Error while opening the latest contract ctl file: %s",
			strerror(ENAMETOOLONG));
		return;
	}

	if ((cfd = open64(path, O_WRONLY)) == -1) {
		debug2("Error while opening the latest contract ctl file: %s",
			strerror(errno));
		return;
	}
	
	if ((errno = ct_ctl_abandon(cfd)))
		debug2("Error while abandoning latest contract: %s",
			strerror(errno));
	else
		debug3("Abandoned latest contract");

	(void) close(cfd);
}
#endif /* HAVE_SOLARIS_CONTRACTS */

/*
 * Signal handler for the key regeneration alarm.  Note that this
 * alarm only occurs in the daemon waiting for connections, and it does not
 * do anything with the private key or random state before forking.
 * Thus there should be no concurrency control/asynchronous execution
 * problems.
 */
static void
generate_ephemeral_server_key(void)
{
	u_int32_t rnd = 0;
	int i;

	verbose("Generating %s%d bit RSA key.",
	    sensitive_data.server_key ? "new " : "", options.server_key_bits);
	if (sensitive_data.server_key != NULL)
		key_free(sensitive_data.server_key);
	sensitive_data.server_key = key_generate(KEY_RSA1,
	    options.server_key_bits);
	verbose("RSA key generation complete.");

	for (i = 0; i < SSH_SESSION_KEY_LENGTH; i++) {
		if (i % 4 == 0)
			rnd = arc4random();
		sensitive_data.ssh1_cookie[i] = rnd & 0xff;
		rnd >>= 8;
	}
	arc4random_stir();
}

static void
key_regeneration_alarm(int sig)
{
	int save_errno = errno;

	(void) signal(SIGALRM, SIG_DFL);
	errno = save_errno;
	key_do_regen = 1;
}

static void
sshd_exchange_identification(int sock_in, int sock_out)
{
	int i, mismatch;
	int remote_major, remote_minor;
	int major, minor;
	char *s;
	char buf[256];			/* Must not be larger than remote_version. */
	char remote_version[256];	/* Must be at least as big as buf. */

	if ((options.protocol & SSH_PROTO_1) &&
	    (options.protocol & SSH_PROTO_2)) {
		major = PROTOCOL_MAJOR_1;
		minor = 99;
	} else if (options.protocol & SSH_PROTO_2) {
		major = PROTOCOL_MAJOR_2;
		minor = PROTOCOL_MINOR_2;
	} else {
		major = PROTOCOL_MAJOR_1;
		minor = PROTOCOL_MINOR_1;
	}
	(void) snprintf(buf, sizeof buf, "SSH-%d.%d-%.100s\n", major, minor, SSH_VERSION);
	server_version_string = xstrdup(buf);

	if (client_version_string == NULL) {
		/* Send our protocol version identification. */
		if (atomicio(write, sock_out, server_version_string,
		    strlen(server_version_string))
		    != strlen(server_version_string)) {
			log("Could not write ident string to %s", get_remote_ipaddr());
			fatal_cleanup();
		}

		/* Read other sides version identification. */
		(void) memset(buf, 0, sizeof(buf));
		for (i = 0; i < sizeof(buf) - 1; i++) {
			if (atomicio(read, sock_in, &buf[i], 1) != 1) {
				log("Did not receive identification string from %s",
				    get_remote_ipaddr());
				fatal_cleanup();
			}
			if (buf[i] == '\r') {
				buf[i] = 0;
				/* Kludge for F-Secure Macintosh < 1.0.2 */
				if (i == 12 &&
				    strncmp(buf, "SSH-1.5-W1.0", 12) == 0)
					break;
				continue;
			}
			if (buf[i] == '\n') {
				buf[i] = 0;
				break;
			}
		}
		buf[sizeof(buf) - 1] = 0;
		client_version_string = xstrdup(buf);
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	if (sscanf(client_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		s = "Protocol mismatch.\n";
		(void) atomicio(write, sock_out, s, strlen(s));
		(void) close(sock_in);
		(void) close(sock_out);
		log("Bad protocol version identification '%.100s' from %s",
		    client_version_string, get_remote_ipaddr());
		fatal_cleanup();
	}
	debug("Client protocol version %d.%d; client software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_datafellows(remote_version);

	if (datafellows & SSH_BUG_PROBE) {
		log("probed from %s with %s.  Don't panic.",
		    get_remote_ipaddr(), client_version_string);
		fatal_cleanup();
	}

	if (datafellows & SSH_BUG_SCANNER) {
		log("scanned from %s with %s.  Don't panic.",
		    get_remote_ipaddr(), client_version_string);
		fatal_cleanup();
	}

	mismatch = 0;
	switch (remote_major) {
	case 1:
		if (remote_minor == 99) {
			if (options.protocol & SSH_PROTO_2)
				enable_compat20();
			else
				mismatch = 1;
			break;
		}
		if (!(options.protocol & SSH_PROTO_1)) {
			mismatch = 1;
			break;
		}
		if (remote_minor < 3) {
			packet_disconnect("Your ssh version is too old and "
			    "is no longer supported.  Please install a newer version.");
		} else if (remote_minor == 3) {
			/* note that this disables agent-forwarding */
			enable_compat13();
		}
		break;
	case 2:
		if (options.protocol & SSH_PROTO_2) {
			enable_compat20();
			break;
		}
		/* FALLTHROUGH */
	default:
		mismatch = 1;
		break;
	}
	chop(server_version_string);
	debug("Local version string %.200s", server_version_string);

	if (mismatch) {
		s = "Protocol major versions differ.\n";
		(void) atomicio(write, sock_out, s, strlen(s));
		(void) close(sock_in);
		(void) close(sock_out);
		log("Protocol major versions differ for %s: %.200s vs. %.200s",
		    get_remote_ipaddr(),
		    server_version_string, client_version_string);
		fatal_cleanup();
	}
}

/* Destroy the host and server keys.  They will no longer be needed. */
void
destroy_sensitive_data(void)
{
	int i;

	if (sensitive_data.server_key) {
		key_free(sensitive_data.server_key);
		sensitive_data.server_key = NULL;
	}
	for (i = 0; i < options.num_host_key_files; i++) {
		if (sensitive_data.host_keys[i]) {
			key_free(sensitive_data.host_keys[i]);
			sensitive_data.host_keys[i] = NULL;
		}
	}
	sensitive_data.ssh1_host_key = NULL;
	(void) memset(sensitive_data.ssh1_cookie, 0, SSH_SESSION_KEY_LENGTH);
}

/* Demote private to public keys for network child */
static void
demote_sensitive_data(void)
{
	Key *tmp;
	int i;

	if (sensitive_data.server_key) {
		tmp = key_demote(sensitive_data.server_key);
		key_free(sensitive_data.server_key);
		sensitive_data.server_key = tmp;
	}

	for (i = 0; i < options.num_host_key_files; i++) {
		if (sensitive_data.host_keys[i]) {
			tmp = key_demote(sensitive_data.host_keys[i]);
			key_free(sensitive_data.host_keys[i]);
			sensitive_data.host_keys[i] = tmp;
			if (tmp->type == KEY_RSA1)
				sensitive_data.ssh1_host_key = tmp;
		}
	}

	/* We do not clear ssh1_host key and cookie.  XXX - Okay Niels? */
}

static char *
list_hostkey_types(void)
{
	Buffer b;
	char *p;
	int i;

	buffer_init(&b);
	for (i = 0; i < options.num_host_key_files; i++) {
		Key *key = sensitive_data.host_keys[i];
		if (key == NULL)
			continue;
		switch (key->type) {
		case KEY_RSA:
		case KEY_DSA:
			if (buffer_len(&b) > 0)
				buffer_append(&b, ",", 1);
			p = key_ssh_name(key);
			buffer_append(&b, p, strlen(p));
			break;
		}
	}
	buffer_append(&b, "\0", 1);
	p = xstrdup(buffer_ptr(&b));
	buffer_free(&b);
	debug("list_hostkey_types: %s", p);
	return p;
}

#ifdef lint
static
#endif /* lint */
Key *
get_hostkey_by_type(int type)
{
	int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		Key *key = sensitive_data.host_keys[i];
		if (key != NULL && key->type == type)
			return key;
	}
	return NULL;
}

#ifdef lint
static
#endif /* lint */
Key *
get_hostkey_by_index(int ind)
{
	if (ind < 0 || ind >= options.num_host_key_files)
		return (NULL);
	return (sensitive_data.host_keys[ind]);
}

#ifdef lint
static
#endif /* lint */
int
get_hostkey_index(Key *key)
{
	int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		if (key == sensitive_data.host_keys[i])
			return (i);
	}
	return (-1);
}

/*
 * returns 1 if connection should be dropped, 0 otherwise.
 * dropping starts at connection #max_startups_begin with a probability
 * of (max_startups_rate/100). the probability increases linearly until
 * all connections are dropped for startups > max_startups
 */
static int
drop_connection(int startups)
{
	double p, r;

	if (startups < options.max_startups_begin)
		return 0;
	if (startups >= options.max_startups)
		return 1;
	if (options.max_startups_rate == 100)
		return 1;

	p  = 100 - options.max_startups_rate;
	p *= startups - options.max_startups_begin;
	p /= (double) (options.max_startups - options.max_startups_begin);
	p += options.max_startups_rate;
	p /= 100.0;
	r = arc4random() / (double) UINT_MAX;

	debug("drop_connection: p %g, r %g", p, r);
	return (r < p) ? 1 : 0;
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("sshd version %s\n"), SSH_VERSION);
	(void) fprintf(stderr,
	    gettext("Usage: %s [options]\n"
		"Options:\n"
		"  -f file    Configuration file (default %s)\n"
		"  -d         Debugging mode (multiple -d means more "
		"debugging)\n"
		"  -i         Started from inetd\n"
		"  -D         Do not fork into daemon mode\n"
		"  -t         Only test configuration file and keys\n"
		"  -q         Quiet (no logging)\n"
		"  -p port    Listen on the specified port (default: 22)\n"
		"  -k seconds Regenerate server key every this many seconds "
		"(default: 3600)\n"
		"  -g seconds Grace period for authentication (default: 600)\n"
		"  -b bits    Size of server RSA key (default: 768 bits)\n"
		"  -h file    File from which to read host key (default: %s)\n"
		"  -4         Use IPv4 only\n"
		"  -6         Use IPv6 only\n"
		"  -o option  Process the option as if it was read from "
		"a configuration file.\n"),
	    __progname, _PATH_SERVER_CONFIG_FILE, _PATH_HOST_KEY_FILE);
	exit(1);
}

/*
 * Main program for the daemon.
 */
int
main(int ac, char **av)
{
	extern char *optarg;
	extern int optind;
	int opt, sock_in = 0, sock_out = 0, newsock, j, i, fdsetsz, on = 1;
	pid_t pid;
	socklen_t fromlen;
	fd_set *fdset;
	struct sockaddr_storage from;
	const char *remote_ip;
	int remote_port;
	FILE *f;
	struct addrinfo *ai;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	int listen_sock, maxfd;
	int startup_p[2];
	int startups = 0;
	Authctxt *authctxt;
	Key *key;
	int ret, key_used = 0;
#ifdef HAVE_BSM
	au_id_t	    auid = AU_NOAUDITID;
#endif /* HAVE_BSM */
#ifdef ALTPRIVSEP
	pid_t aps_child;
#endif /* ALTPRIVSEP */

	__progname = get_progname(av[0]);

	(void) g11n_setlocale(LC_ALL, "");

#ifdef HAVE_SECUREWARE
	(void)set_auth_parameters(ac, av);
#endif

	init_rng();

	/* Save argv. */
	saved_argc = ac;
	saved_argv = av;

	/* Initialize configuration options to their default values. */
	initialize_server_options(&options);

	/* Parse command-line arguments. */
	while ((opt = getopt(ac, av, "f:p:b:k:h:g:V:u:o:dDeiqtQ46")) != -1) {
		switch (opt) {
		case '4':
			IPv4or6 = AF_INET;
			break;
		case '6':
			IPv4or6 = AF_INET6;
			break;
		case 'f':
			config_file_name = optarg;
			break;
		case 'd':
			if (0 == debug_flag) {
				debug_flag = 1;
				options.log_level = SYSLOG_LEVEL_DEBUG1;
			} else if (options.log_level < SYSLOG_LEVEL_DEBUG3) {
				options.log_level++;
			} else {
				(void) fprintf(stderr,
					gettext("Debug level too high.\n"));
				exit(1);
			}
			break;
		case 'D':
			no_daemon_flag = 1;
			break;
		case 'e':
			log_stderr = 1;
			break;
		case 'i':
			inetd_flag = 1;
			break;
		case 'Q':
			/* ignored */
			break;
		case 'q':
			options.log_level = SYSLOG_LEVEL_QUIET;
			break;
		case 'b':
			options.server_key_bits = atoi(optarg);
			break;
		case 'p':
			options.ports_from_cmdline = 1;
			if (options.num_ports >= MAX_PORTS) {
				(void) fprintf(stderr, gettext("too many ports.\n"));
				exit(1);
			}
			options.ports[options.num_ports++] = a2port(optarg);
			if (options.ports[options.num_ports-1] == 0) {
				(void) fprintf(stderr, gettext("Bad port number.\n"));
				exit(1);
			}
			break;
		case 'g':
			if ((options.login_grace_time = convtime(optarg)) == -1) {
				(void) fprintf(stderr,
					gettext("Invalid login grace time.\n"));
				exit(1);
			}
			break;
		case 'k':
			if ((options.key_regeneration_time = convtime(optarg)) == -1) {
				(void) fprintf(stderr,
					gettext("Invalid key regeneration "
						"interval.\n"));
				exit(1);
			}
			break;
		case 'h':
			if (options.num_host_key_files >= MAX_HOSTKEYS) {
				(void) fprintf(stderr,
					gettext("too many host keys.\n"));
				exit(1);
			}
			options.host_key_files[options.num_host_key_files++] = optarg;
			break;
		case 'V':
			client_version_string = optarg;
			/* only makes sense with inetd_flag, i.e. no listen() */
			inetd_flag = 1;
			break;
		case 't':
			test_flag = 1;
			break;
		case 'o':
			if (process_server_config_line(&options, optarg,
			    "command-line", 0) != 0)
				exit(1);
			break;
		case '?':
		default:
			usage();
			break;
		}
	}
	SSLeay_add_all_algorithms();
	channel_set_af(IPv4or6);

	/*
	 * Force logging to stderr until we have loaded the private host
	 * key (unless started from inetd)
	 */
	log_init(__progname,
	    options.log_level == SYSLOG_LEVEL_NOT_SET ?
	    SYSLOG_LEVEL_INFO : options.log_level,
	    options.log_facility == SYSLOG_FACILITY_NOT_SET ?
	    SYSLOG_FACILITY_AUTH : options.log_facility,
	    !inetd_flag);

#ifdef _UNICOS
	/* Cray can define user privs drop all prives now!
	 * Not needed on PRIV_SU systems!
	 */
	drop_cray_privs();
#endif

	seed_rng();

	/* Read server configuration options from the configuration file. */
	read_server_config(&options, config_file_name);

	/* Fill in default values for those options not explicitly set. */
	fill_default_server_options(&options);

	utmp_len = options.lookup_client_hostnames ? utmp_len : 0;

	/* Check that there are no remaining arguments. */
	if (optind < ac) {
		(void) fprintf(stderr, gettext("Extra argument %s.\n"), av[optind]);
		exit(1);
	}

	debug("sshd version %.100s", SSH_VERSION);

	/* load private host keys */
	if (options.num_host_key_files > 0)
		sensitive_data.host_keys =
		    xmalloc(options.num_host_key_files * sizeof(Key *));
	for (i = 0; i < options.num_host_key_files; i++)
		sensitive_data.host_keys[i] = NULL;
	sensitive_data.server_key = NULL;
	sensitive_data.ssh1_host_key = NULL;
	sensitive_data.have_ssh1_key = 0;
	sensitive_data.have_ssh2_key = 0;

	for (i = 0; i < options.num_host_key_files; i++) {
		key = key_load_private(options.host_key_files[i], "", NULL);
		sensitive_data.host_keys[i] = key;
		if (key == NULL) {
			error("Could not load host key: %s",
			    options.host_key_files[i]);
			sensitive_data.host_keys[i] = NULL;
			continue;
		}
		switch (key->type) {
		case KEY_RSA1:
			sensitive_data.ssh1_host_key = key;
			sensitive_data.have_ssh1_key = 1;
			break;
		case KEY_RSA:
		case KEY_DSA:
			sensitive_data.have_ssh2_key = 1;
			break;
		}
		debug("private host key: #%d type %d %s", i, key->type,
		    key_type(key));
	}
	if ((options.protocol & SSH_PROTO_1) && !sensitive_data.have_ssh1_key) {
		log("Disabling protocol version 1. Could not load host key");
		options.protocol &= ~SSH_PROTO_1;
	}
	if ((options.protocol & SSH_PROTO_2) &&
	    !sensitive_data.have_ssh2_key) {
#ifdef GSSAPI
		if (options.gss_keyex)
			ssh_gssapi_server_mechs(&mechs);

		if (mechs == GSS_C_NULL_OID_SET) {
			log("Disabling protocol version 2. Could not load host"
			    "key or GSS-API mechanisms");
			options.protocol &= ~SSH_PROTO_2;
		}
#else
		log("Disabling protocol version 2. Could not load host key");
		options.protocol &= ~SSH_PROTO_2;
#endif /* GSSAPI */
	}
	if (!(options.protocol & (SSH_PROTO_1|SSH_PROTO_2))) {
		log("sshd: no hostkeys available -- exiting.");
		exit(1);
	}

	/* Check certain values for sanity. */
	if (options.protocol & SSH_PROTO_1) {
		if (options.server_key_bits < 512 ||
		    options.server_key_bits > 32768) {
			(void) fprintf(stderr, gettext("Bad server key size.\n"));
			exit(1);
		}
		/*
		 * Check that server and host key lengths differ sufficiently. This
		 * is necessary to make double encryption work with rsaref. Oh, I
		 * hate software patents. I dont know if this can go? Niels
		 */
		if (options.server_key_bits >
		    BN_num_bits(sensitive_data.ssh1_host_key->rsa->n) -
		    SSH_KEY_BITS_RESERVED && options.server_key_bits <
		    BN_num_bits(sensitive_data.ssh1_host_key->rsa->n) +
		    SSH_KEY_BITS_RESERVED) {
			options.server_key_bits =
			    BN_num_bits(sensitive_data.ssh1_host_key->rsa->n) +
			    SSH_KEY_BITS_RESERVED;
			debug("Forcing server key to %d bits to make it differ from host key.",
			    options.server_key_bits);
		}
	}

	/* Configuration looks good, so exit if in test mode. */
	if (test_flag)
		exit(0);

	/*
	 * Clear out any supplemental groups we may have inherited.  This
	 * prevents inadvertent creation of files with bad modes (in the
	 * portable version at least, it's certainly possible for PAM 
	 * to create a file, and we can't control the code in every 
	 * module which might be used).
	 */
	if (setgroups(0, NULL) < 0)
		debug("setgroups() failed: %.200s", strerror(errno));

	/* Initialize the log (it is reinitialized below in case we forked). */
	if (debug_flag && !inetd_flag)
		log_stderr = 1;
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

#ifdef HAVE_BSM
	(void) setauid(&auid);
#endif /* HAVE_BSM */

	/*
	 * If not in debugging mode, and not started from inetd, disconnect
	 * from the controlling terminal, and fork.  The original process
	 * exits.
	 */
	if (!(debug_flag || inetd_flag || no_daemon_flag)) {
#ifdef TIOCNOTTY
		int fd;
#endif /* TIOCNOTTY */
		if (daemon(0, 0) < 0)
			fatal("daemon() failed: %.200s", strerror(errno));

		/* Disconnect from the controlling tty. */
#ifdef TIOCNOTTY
		fd = open(_PATH_TTY, O_RDWR | O_NOCTTY);
		if (fd >= 0) {
			(void) ioctl(fd, TIOCNOTTY, NULL);
			(void) close(fd);
		}
#endif /* TIOCNOTTY */
	}
	/* Reinitialize the log (because of the fork above). */
	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	/* Initialize the random number generator. */
	arc4random_stir();

	/* Chdir to the root directory so that the current disk can be
	   unmounted if desired. */
	(void) chdir("/");

	/* ignore SIGPIPE */
	(void) signal(SIGPIPE, SIG_IGN);

	/* Start listening for a socket, unless started from inetd. */
	if (inetd_flag) {
		int s1;
		s1 = dup(0);	/* Make sure descriptors 0, 1, and 2 are in use. */
		(void) dup(s1);
		sock_in = dup(0);
		sock_out = dup(1);
		startup_pipe = -1;
		/*
		 * We intentionally do not close the descriptors 0, 1, and 2
		 * as our code for setting the descriptors won\'t work if
		 * ttyfd happens to be one of those.
		 */
		debug("inetd sockets after dupping: %d, %d", sock_in, sock_out);
		if (options.protocol & SSH_PROTO_1)
			generate_ephemeral_server_key();
	} else {
		for (ai = options.listen_addrs; ai; ai = ai->ai_next) {
			if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
				continue;
			if (num_listen_socks >= MAX_LISTEN_SOCKS)
				fatal("Too many listen sockets. "
				    "Enlarge MAX_LISTEN_SOCKS");
			if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, sizeof(ntop), strport, sizeof(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
				error("getnameinfo failed");
				continue;
			}
			/* Create socket for listening. */
			listen_sock = socket(ai->ai_family, SOCK_STREAM, 0);
			if (listen_sock < 0) {
				/* kernel may not support ipv6 */
				verbose("socket: %.100s", strerror(errno));
				continue;
			}
			if (fcntl(listen_sock, F_SETFL, O_NONBLOCK) < 0) {
				error("listen_sock O_NONBLOCK: %s", strerror(errno));
				(void) close(listen_sock);
				continue;
			}
			/*
			 * Set socket options.
			 * Allow local port reuse in TIME_WAIT.
			 */
			if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
			    &on, sizeof(on)) == -1)
				error("setsockopt SO_REUSEADDR: %s", strerror(errno));

			debug("Bind to port %s on %s.", strport, ntop);

			/* Bind the socket to the desired port. */
			if (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) < 0) {
				if (!ai->ai_next)
				    error("Bind to port %s on %s failed: %.200s.",
					    strport, ntop, strerror(errno));
				(void) close(listen_sock);
				continue;
			}
			listen_socks[num_listen_socks] = listen_sock;
			num_listen_socks++;

			/* Start listening on the port. */
			log("Server listening on %s port %s.", ntop, strport);
			if (listen(listen_sock, 5) < 0)
				fatal("listen: %.100s", strerror(errno));

		}
		freeaddrinfo(options.listen_addrs);

		if (!num_listen_socks)
			fatal("Cannot bind any address.");

		if (options.protocol & SSH_PROTO_1)
			generate_ephemeral_server_key();

		/*
		 * Arrange to restart on SIGHUP.  The handler needs
		 * listen_sock.
		 */
		(void) signal(SIGHUP, sighup_handler);

		(void) signal(SIGTERM, sigterm_handler);
		(void) signal(SIGQUIT, sigterm_handler);

		/* Arrange SIGCHLD to be caught. */
		(void) signal(SIGCHLD, main_sigchld_handler);

		/* Write out the pid file after the sigterm handler is setup */
		if (!debug_flag) {
			/*
			 * Record our pid in /var/run/sshd.pid to make it
			 * easier to kill the correct sshd.  We don't want to
			 * do this before the bind above because the bind will
			 * fail if there already is a daemon, and this will
			 * overwrite any old pid in the file.
			 */
			f = fopen(options.pid_file, "wb");
			if (f) {
				(void) fprintf(f, "%ld\n", (long) getpid());
				(void) fclose(f);
			}
		}

		/* setup fd set for listen */
		fdset = NULL;
		maxfd = 0;
		for (i = 0; i < num_listen_socks; i++)
			if (listen_socks[i] > maxfd)
				maxfd = listen_socks[i];
		/* pipes connected to unauthenticated childs */
		startup_pipes = xmalloc(options.max_startups * sizeof(int));
		for (i = 0; i < options.max_startups; i++)
			startup_pipes[i] = -1;

		/*
		 * Stay listening for connections until the system crashes or
		 * the daemon is killed with a signal.
		 */
		for (;;) {
			if (received_sighup)
				sighup_restart();
			if (fdset != NULL)
				xfree(fdset);
			fdsetsz = howmany(maxfd+1, NFDBITS) * sizeof(fd_mask);
			fdset = (fd_set *)xmalloc(fdsetsz);
			(void) memset(fdset, 0, fdsetsz);

			for (i = 0; i < num_listen_socks; i++)
				FD_SET(listen_socks[i], fdset);
			for (i = 0; i < options.max_startups; i++)
				if (startup_pipes[i] != -1)
					FD_SET(startup_pipes[i], fdset);

			/* Wait in select until there is a connection. */
			ret = select(maxfd+1, fdset, NULL, NULL, NULL);
			if (ret < 0 && errno != EINTR)
				error("select: %.100s", strerror(errno));
			if (received_sigterm) {
				log("Received signal %d; terminating.",
				    (int) received_sigterm);
				close_listen_socks();
				(void) unlink(options.pid_file);
				exit(255);
			}
			if (key_used && key_do_regen) {
				generate_ephemeral_server_key();
				key_used = 0;
				key_do_regen = 0;
			}
			if (ret < 0)
				continue;

			for (i = 0; i < options.max_startups; i++)
				if (startup_pipes[i] != -1 &&
				    FD_ISSET(startup_pipes[i], fdset)) {
					/*
					 * the read end of the pipe is ready
					 * if the child has closed the pipe
					 * after successful authentication
					 * or if the child has died
					 */
					(void) close(startup_pipes[i]);
					startup_pipes[i] = -1;
					startups--;
				}
			for (i = 0; i < num_listen_socks; i++) {
				if (!FD_ISSET(listen_socks[i], fdset))
					continue;
				fromlen = sizeof(from);
				newsock = accept(listen_socks[i], (struct sockaddr *)&from,
				    &fromlen);
				if (newsock < 0) {
					if (errno != EINTR && errno != EWOULDBLOCK)
						error("accept: %.100s", strerror(errno));
					continue;
				}
				if (fcntl(newsock, F_SETFL, 0) < 0) {
					error("newsock del O_NONBLOCK: %s", strerror(errno));
					(void) close(newsock);
					continue;
				}
				if (drop_connection(startups) == 1) {
					debug("drop connection #%d", startups);
					(void) close(newsock);
					continue;
				}
				if (pipe(startup_p) == -1) {
					(void) close(newsock);
					continue;
				}

				for (j = 0; j < options.max_startups; j++)
					if (startup_pipes[j] == -1) {
						startup_pipes[j] = startup_p[0];
						if (maxfd < startup_p[0])
							maxfd = startup_p[0];
						startups++;
						break;
					}

				/*
				 * Got connection.  Fork a child to handle it, unless
				 * we are in debugging mode.
				 */
				if (debug_flag) {
					/*
					 * In debugging mode.  Close the listening
					 * socket, and start processing the
					 * connection without forking.
					 */
					debug("Server will not fork when running in debugging mode.");
					close_listen_socks();
					sock_in = newsock;
					sock_out = newsock;
					startup_pipe = -1;
					pid = getpid();
					break;
				} else {
					/*
					 * Normal production daemon.  Fork, and have
					 * the child process the connection. The
					 * parent continues listening.
					 */
#ifdef HAVE_SOLARIS_CONTRACTS
					/*
					 * Setup Solaris contract template so
					 * the child process is in a different
					 * process contract than the parent;
					 * prevents established connections from
					 * being killed when the sshd master
					 * listener service is stopped.
					 */
					contracts_pre_fork();
#endif /* HAVE_SOLARIS_CONTRACTS */
					if ((pid = fork()) == 0) {
						/*
						 * Child.  Close the listening and max_startup
						 * sockets.  Start using the accepted socket.
						 * Reinitialize logging (since our pid has
						 * changed).  We break out of the loop to handle
						 * the connection.
						 */
#ifdef HAVE_SOLARIS_CONTRACTS
						contracts_post_fork_child();
#endif /* HAVE_SOLARIS_CONTRACTS */
						xfree(fdset);
						startup_pipe = startup_p[1];
						close_startup_pipes();
						close_listen_socks();
						sock_in = newsock;
						sock_out = newsock;
						log_init(__progname, options.log_level, options.log_facility, log_stderr);
						break;
					}

#ifdef HAVE_SOLARIS_CONTRACTS
					contracts_post_fork_parent((pid > 0));
#endif /* HAVE_SOLARIS_CONTRACTS */
				}

				/* Parent.  Stay in the loop. */
				if (pid < 0)
					error("fork: %.100s", strerror(errno));
				else
					debug("Forked child %ld.", (long)pid);

				(void) close(startup_p[1]);

				/* Mark that the key has been used (it was "given" to the child). */
				if ((options.protocol & SSH_PROTO_1) &&
				    key_used == 0) {
					/* Schedule server key regeneration alarm. */
					(void) signal(SIGALRM, key_regeneration_alarm);
					(void) alarm(options.key_regeneration_time);
					key_used = 1;
				}

				arc4random_stir();

				/* Close the new socket (the child is now taking care of it). */
				(void) close(newsock);
			}
			/* child process check (or debug mode) */
			if (num_listen_socks < 0)
				break;
		}
	}

	/* This is the child processing a new connection. */
#ifdef HAVE_BSM
	audit_sshd_settid(newsock);
#endif
	/*
	 * Create a new session and process group since the 4.4BSD
	 * setlogin() affects the entire process group.  We don't
	 * want the child to be able to affect the parent.
	 */
#if 0
	/* XXX: this breaks Solaris */
	if (!debug_flag && !inetd_flag && setsid() < 0)
		error("setsid: %.100s", strerror(errno));
#endif

	/*
	 * Disable the key regeneration alarm.  We will not regenerate the
	 * key since we are no longer in a position to give it to anyone. We
	 * will not restart on SIGHUP since it no longer makes sense.
	 */
	(void) alarm(0);
	(void) signal(SIGALRM, SIG_DFL);
	(void) signal(SIGHUP, SIG_DFL);
	(void) signal(SIGTERM, SIG_DFL);
	(void) signal(SIGQUIT, SIG_DFL);
	(void) signal(SIGCHLD, SIG_DFL);
	(void) signal(SIGINT, SIG_DFL);

	/* Set keepalives if requested. */
	if (options.keepalives &&
	    setsockopt(sock_in, SOL_SOCKET, SO_KEEPALIVE, &on,
	    sizeof(on)) < 0)
		debug2("setsockopt SO_KEEPALIVE: %.100s", strerror(errno));

	/*
	 * Register our connection.  This turns encryption off because we do
	 * not have a key.
	 */
	packet_set_connection(sock_in, sock_out);

	remote_port = get_remote_port();
	remote_ip = get_remote_ipaddr();

#ifdef LIBWRAP
	/* Check whether logins are denied from this host. */
	{
		struct request_info req;

		(void) request_init(&req, RQ_DAEMON, __progname, RQ_FILE, sock_in, 0);
		fromhost(&req);

		if (!hosts_access(&req)) {
			debug("Connection refused by tcp wrapper");
			refuse(&req);
			/* NOTREACHED */
			fatal("libwrap refuse returns");
		}
	}
#endif /* LIBWRAP */

	/* Log the connection. */
	verbose("Connection from %.500s port %d", remote_ip, remote_port);

	/*
	 * We don\'t want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don\'t set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	(void) signal(SIGALRM, grace_alarm_handler);
	if (!debug_flag)
		(void) alarm(options.login_grace_time);

	sshd_exchange_identification(sock_in, sock_out);
	/*
	 * Check that the connection comes from a privileged port.
	 * Rhosts-Authentication only makes sense from privileged
	 * programs.  Of course, if the intruder has root access on his local
	 * machine, he can connect from any port.  So do not use these
	 * authentication methods from machines that you do not trust.
	 */
	if (options.rhosts_authentication &&
	    (remote_port >= IPPORT_RESERVED ||
	    remote_port < IPPORT_RESERVED / 2)) {
		debug("Rhosts Authentication disabled, "
		    "originating port %d not trusted.", remote_port);
		options.rhosts_authentication = 0;
	}
#if defined(KRB4) && !defined(KRB5)
	if (!packet_connection_is_ipv4() &&
	    options.kerberos_authentication) {
		debug("Kerberos Authentication disabled, only available for IPv4.");
		options.kerberos_authentication = 0;
	}
#endif /* KRB4 && !KRB5 */
#ifdef AFS
	/* If machine has AFS, set process authentication group. */
	if (k_hasafs()) {
		k_setpag();
		k_unlog();
	}
#endif /* AFS */

	packet_set_nonblocking();

	/* perform the key exchange */
	/* authenticate user and start session */
	if (compat20) {
		do_ssh2_kex();
		authctxt = do_authentication2();
	} else {
		do_ssh1_kex();
		authctxt = do_authentication();
	}

authenticated:
	/* Authentication complete */
	(void) alarm(0);

	if (startup_pipe != -1) {
		(void) close(startup_pipe);
		startup_pipe = -1;
	}

#ifdef ALTPRIVSEP
	if ((aps_child = altprivsep_start_monitor(authctxt)) == -1)
		fatal("Monitor could not be started.");

	if (aps_child > 0) {

		/* ALTPRIVSEP Monitor */

		/*
		 * The ALTPRIVSEP monitor here does:
		 *
		 *  - record keeping and auditing
		 *  - PAM cleanup
		 */

		/*
		 * If the monitor fatal()s it will audit/record a logout, so
		 * we'd better do something to really mean it: shutdown the
		 * socket but leave the child alone -- it's been disconnected
		 * and we hope it exits, but killing any pid from a privileged
		 * monitor could be dangerous.
		 *
		 * NOTE: Order matters -- these fatal cleanups must come before
		 * the audit logout fatal cleanup as these functions are called
		 * in LIFO.
		 *
		 * NOTE: The monitor will packet_close(), which will close
		 * "newsock," so we dup() it.
		 */
		newsock = dup(newsock);
		fatal_add_cleanup((void (*)(void *))altprivsep_shutdown_sock,
			(void *)&newsock);

		if (compat20) {
			debug3("Recording SSHv2 session login in wtmpx");
			record_login(getpid(), NULL, "sshd", authctxt->user);
		}

#ifdef HAVE_BSM
		fatal_remove_cleanup(
			(void (*)(void *))audit_failed_login_cleanup,
			(void *)authctxt);

		/* Initialize the group list, audit sometimes needs it. */
		if (initgroups(authctxt->pw->pw_name,
		    authctxt->pw->pw_gid) < 0) {
			perror("initgroups");
			exit (1);
		}
		audit_sshd_login(&ah, authctxt->pw->pw_uid,
			authctxt->pw->pw_gid);

		fatal_add_cleanup((void (*)(void *))audit_sshd_logout,
			(void *)&ah);
#endif /* HAVE_BSM */

#ifdef GSSAPI
		fatal_add_cleanup((void (*)(void *))ssh_gssapi_cleanup_creds,
			(void *)&xxx_gssctxt);
#endif /* GSSAPI */

		altprivsep_do_monitor(authctxt, aps_child);

		/* If we got here the connection is dead. */
		fatal_remove_cleanup((void (*)(void *))altprivsep_shutdown_sock,
			(void *)&newsock);

		if (compat20) {
			debug3("Recording SSHv2 session logout in wtmpx");
			record_logout(getpid(), NULL, "sshd", authctxt->user);
		}

		/*
		 * Make sure the socket is closed. The monitor can't call
		 * packet_close here as it's done a packet_set_connection()
		 * with the pipe to the child instead of the socket.
		 */
		(void) shutdown(newsock, SHUT_RDWR);

#ifdef GSSAPI
		fatal_remove_cleanup((void (*)(void *))ssh_gssapi_cleanup_creds,
			&xxx_gssctxt);
		ssh_gssapi_cleanup_creds(xxx_gssctxt);
		ssh_gssapi_server_mechs(NULL); /* release cached mechs list */
#endif /* GSSAPI */

#ifdef HAVE_BSM
		fatal_remove_cleanup((void (*)(void *))audit_sshd_logout, (void *)&ah);
		audit_sshd_logout(&ah);
#endif /* HAVE_BSM */

#ifdef USE_PAM
		finish_pam(authctxt);
#endif /* USE_PAM */

		return (ret);

		/* NOTREACHED */

	} else {

		/* ALTPRIVSEP Child */

		/*
		 * Drop privileges, access to privileged resources.
		 *
		 * Destroy private host keys, if any.
		 *
		 * No need to release any GSS credentials -- sshd only acquires
		 * creds to determine what mechs it can negotiate then releases
		 * them right away and uses GSS_C_NO_CREDENTIAL to accept
		 * contexts.
		 */
		debug2("Unprivileged server process dropping privileges");
		permanently_set_uid(authctxt->pw);
		destroy_sensitive_data();
		ssh_gssapi_server_mechs(NULL); /* release cached mechs list */

#ifdef HAVE_BSM
		fatal_remove_cleanup(
			(void (*)(void *))audit_failed_login_cleanup,
			(void *)authctxt);
#endif /* HAVE_BSM */

		/* Logged-in session. */
		do_authenticated(authctxt);

		/* The connection has been terminated. */
		verbose("Closing connection to %.100s", remote_ip);

		packet_close();

		return (0);

		/* NOTREACHED */
	}
#endif /* ALTPRIVSEP */
}

/*
 * Decrypt session_key_int using our private server key and private host key
 * (key with larger modulus first).
 */
int
ssh1_session_key(BIGNUM *session_key_int)
{
	int rsafail = 0;

	if (BN_cmp(sensitive_data.server_key->rsa->n, sensitive_data.ssh1_host_key->rsa->n) > 0) {
		/* Server key has bigger modulus. */
		if (BN_num_bits(sensitive_data.server_key->rsa->n) <
		    BN_num_bits(sensitive_data.ssh1_host_key->rsa->n) + SSH_KEY_BITS_RESERVED) {
			fatal("do_connection: %s: server_key %d < host_key %d + SSH_KEY_BITS_RESERVED %d",
			    get_remote_ipaddr(),
			    BN_num_bits(sensitive_data.server_key->rsa->n),
			    BN_num_bits(sensitive_data.ssh1_host_key->rsa->n),
			    SSH_KEY_BITS_RESERVED);
		}
		if (rsa_private_decrypt(session_key_int, session_key_int,
		    sensitive_data.server_key->rsa) <= 0)
			rsafail++;
		if (rsa_private_decrypt(session_key_int, session_key_int,
		    sensitive_data.ssh1_host_key->rsa) <= 0)
			rsafail++;
	} else {
		/* Host key has bigger modulus (or they are equal). */
		if (BN_num_bits(sensitive_data.ssh1_host_key->rsa->n) <
		    BN_num_bits(sensitive_data.server_key->rsa->n) + SSH_KEY_BITS_RESERVED) {
			fatal("do_connection: %s: host_key %d < server_key %d + SSH_KEY_BITS_RESERVED %d",
			    get_remote_ipaddr(),
			    BN_num_bits(sensitive_data.ssh1_host_key->rsa->n),
			    BN_num_bits(sensitive_data.server_key->rsa->n),
			    SSH_KEY_BITS_RESERVED);
		}
		if (rsa_private_decrypt(session_key_int, session_key_int,
		    sensitive_data.ssh1_host_key->rsa) < 0)
			rsafail++;
		if (rsa_private_decrypt(session_key_int, session_key_int,
		    sensitive_data.server_key->rsa) < 0)
			rsafail++;
	}
	return (rsafail);
}
/*
 * SSH1 key exchange
 */
static void
do_ssh1_kex(void)
{
	int i, len;
	int rsafail = 0;
	BIGNUM *session_key_int;
	u_char session_key[SSH_SESSION_KEY_LENGTH];
	u_char cookie[8];
	u_int cipher_type, auth_mask, protocol_flags;
	u_int32_t rnd = 0;

	/*
	 * Generate check bytes that the client must send back in the user
	 * packet in order for it to be accepted; this is used to defy ip
	 * spoofing attacks.  Note that this only works against somebody
	 * doing IP spoofing from a remote machine; any machine on the local
	 * network can still see outgoing packets and catch the random
	 * cookie.  This only affects rhosts authentication, and this is one
	 * of the reasons why it is inherently insecure.
	 */
	for (i = 0; i < 8; i++) {
		if (i % 4 == 0)
			rnd = arc4random();
		cookie[i] = rnd & 0xff;
		rnd >>= 8;
	}

	/*
	 * Send our public key.  We include in the packet 64 bits of random
	 * data that must be matched in the reply in order to prevent IP
	 * spoofing.
	 */
	packet_start(SSH_SMSG_PUBLIC_KEY);
	for (i = 0; i < 8; i++)
		packet_put_char(cookie[i]);

	/* Store our public server RSA key. */
	packet_put_int(BN_num_bits(sensitive_data.server_key->rsa->n));
	packet_put_bignum(sensitive_data.server_key->rsa->e);
	packet_put_bignum(sensitive_data.server_key->rsa->n);

	/* Store our public host RSA key. */
	packet_put_int(BN_num_bits(sensitive_data.ssh1_host_key->rsa->n));
	packet_put_bignum(sensitive_data.ssh1_host_key->rsa->e);
	packet_put_bignum(sensitive_data.ssh1_host_key->rsa->n);

	/* Put protocol flags. */
	packet_put_int(SSH_PROTOFLAG_HOST_IN_FWD_OPEN);

	/* Declare which ciphers we support. */
	packet_put_int(cipher_mask_ssh1(0));

	/* Declare supported authentication types. */
	auth_mask = 0;
	if (options.rhosts_authentication)
		auth_mask |= 1 << SSH_AUTH_RHOSTS;
	if (options.rhosts_rsa_authentication)
		auth_mask |= 1 << SSH_AUTH_RHOSTS_RSA;
	if (options.rsa_authentication)
		auth_mask |= 1 << SSH_AUTH_RSA;
#if defined(KRB4) || defined(KRB5)
	if (options.kerberos_authentication)
		auth_mask |= 1 << SSH_AUTH_KERBEROS;
#endif
#if defined(AFS) || defined(KRB5)
	if (options.kerberos_tgt_passing)
		auth_mask |= 1 << SSH_PASS_KERBEROS_TGT;
#endif
#ifdef AFS
	if (options.afs_token_passing)
		auth_mask |= 1 << SSH_PASS_AFS_TOKEN;
#endif
	if (options.challenge_response_authentication == 1)
		auth_mask |= 1 << SSH_AUTH_TIS;
	if (options.password_authentication)
		auth_mask |= 1 << SSH_AUTH_PASSWORD;
	packet_put_int(auth_mask);

	/* Send the packet and wait for it to be sent. */
	packet_send();
	packet_write_wait();

	debug("Sent %d bit server key and %d bit host key.",
	    BN_num_bits(sensitive_data.server_key->rsa->n),
	    BN_num_bits(sensitive_data.ssh1_host_key->rsa->n));

	/* Read clients reply (cipher type and session key). */
	packet_read_expect(SSH_CMSG_SESSION_KEY);

	/* Get cipher type and check whether we accept this. */
	cipher_type = packet_get_char();

	if (!(cipher_mask_ssh1(0) & (1 << cipher_type))) {
		packet_disconnect("Warning: client selects unsupported cipher.");
	}

	/* Get check bytes from the packet.  These must match those we
	   sent earlier with the public key packet. */
	for (i = 0; i < 8; i++) {
		if (cookie[i] != packet_get_char()) {
			packet_disconnect("IP Spoofing check bytes do not match.");
		}
	}

	debug("Encryption type: %.200s", cipher_name(cipher_type));

	/* Get the encrypted integer. */
	if ((session_key_int = BN_new()) == NULL)
		fatal("do_ssh1_kex: BN_new failed");
	packet_get_bignum(session_key_int);

	protocol_flags = packet_get_int();
	packet_set_protocol_flags(protocol_flags);
	packet_check_eom();

	/* Decrypt session_key_int using host/server keys */
	rsafail = ssh1_session_key(session_key_int);

	/*
	 * Extract session key from the decrypted integer.  The key is in the
	 * least significant 256 bits of the integer; the first byte of the
	 * key is in the highest bits.
	 */
	if (!rsafail) {
		(void) BN_mask_bits(session_key_int, sizeof(session_key) * 8);
		len = BN_num_bytes(session_key_int);
		if (len < 0 || len > sizeof(session_key)) {
			error("do_connection: bad session key len from %s: "
			    "session_key_int %d > sizeof(session_key) %lu",
			    get_remote_ipaddr(), len, (u_long)sizeof(session_key));
			rsafail++;
		} else {
			(void) memset(session_key, 0, sizeof(session_key));
			(void) BN_bn2bin(session_key_int,
			    session_key + sizeof(session_key) - len);

			compute_session_id(session_id, cookie,
			    sensitive_data.ssh1_host_key->rsa->n,
			    sensitive_data.server_key->rsa->n);
			/*
			 * Xor the first 16 bytes of the session key with the
			 * session id.
			 */
			for (i = 0; i < 16; i++)
				session_key[i] ^= session_id[i];
		}
	}
	if (rsafail) {
		int bytes = BN_num_bytes(session_key_int);
		u_char *buf = xmalloc(bytes);
		MD5_CTX md;

		log("do_connection: generating a fake encryption key");
		(void) BN_bn2bin(session_key_int, buf);
		MD5_Init(&md);
		MD5_Update(&md, buf, bytes);
		MD5_Update(&md, sensitive_data.ssh1_cookie, SSH_SESSION_KEY_LENGTH);
		MD5_Final(session_key, &md);
		MD5_Init(&md);
		MD5_Update(&md, session_key, 16);
		MD5_Update(&md, buf, bytes);
		MD5_Update(&md, sensitive_data.ssh1_cookie, SSH_SESSION_KEY_LENGTH);
		MD5_Final(session_key + 16, &md);
		(void) memset(buf, 0, bytes);
		xfree(buf);
		for (i = 0; i < 16; i++)
			session_id[i] = session_key[i] ^ session_key[i + 16];
	}
	/* Destroy the private and public keys. No longer. */
	destroy_sensitive_data();

	/* Destroy the decrypted integer.  It is no longer needed. */
	BN_clear_free(session_key_int);

	/* Set the session key.  From this on all communications will be encrypted. */
	packet_set_encryption_key(session_key, SSH_SESSION_KEY_LENGTH, cipher_type);

	/* Destroy our copy of the session key.  It is no longer needed. */
	(void) memset(session_key, 0, sizeof(session_key));

	debug("Received session key; encryption turned on.");

	/* Send an acknowledgment packet.  Note that this packet is sent encrypted. */
	packet_start(SSH_SMSG_SUCCESS);
	packet_send();
	packet_write_wait();
}

/*
 * SSH2 key exchange: diffie-hellman-group1-sha1
 */
static void
do_ssh2_kex(void)
{
	Kex *kex;
	Kex_hook_func kex_hook = NULL;
	char **locales;

	if (options.ciphers != NULL) {
		myproposal[PROPOSAL_ENC_ALGS_CTOS] =
		myproposal[PROPOSAL_ENC_ALGS_STOC] = options.ciphers;
	}
	myproposal[PROPOSAL_ENC_ALGS_CTOS] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_CTOS]);
	myproposal[PROPOSAL_ENC_ALGS_STOC] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_STOC]);

	if (options.macs != NULL) {
		myproposal[PROPOSAL_MAC_ALGS_CTOS] =
		myproposal[PROPOSAL_MAC_ALGS_STOC] = options.macs;
	}
	if (!options.compression) {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "none";
	}

	/*
	 * Prepare kex algs / hostkey algs (excluding GSS, which is
	 * handled in the kex hook.
	 *
	 * XXX This should probably move to the kex hook as well, where
	 * all non-constant kex offer material belongs.
	 */
	myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = list_hostkey_types();

	/* If we have no host key algs we can't offer KEXDH/KEX_DH_GEX */
	if (myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] == NULL ||
	    *myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] == '\0')
		myproposal[PROPOSAL_KEX_ALGS] = "";

	if ((locales = g11n_getlocales()) != NULL) {
		/* Solaris 9 SSH expects a list of locales */
		if (datafellows & SSH_BUG_LOCALES_NOT_LANGTAGS)
			myproposal[PROPOSAL_LANG_STOC] = xjoin(locales, ',');
		else
			myproposal[PROPOSAL_LANG_STOC] =
				g11n_locales2langs(locales);
	}

	if (locales != NULL)
		g11n_freelist(locales);

	if ((myproposal[PROPOSAL_LANG_STOC] != NULL) || 
	    (strcmp(myproposal[PROPOSAL_LANG_STOC], "")) != 0)
		myproposal[PROPOSAL_LANG_CTOS] =
			xstrdup(myproposal[PROPOSAL_LANG_STOC]);

#ifdef GSSAPI
	if (options.gss_keyex)
		kex_hook = ssh_gssapi_server_kex_hook;
#endif /* GSSAPI */

	/* start key exchange */
	kex = kex_setup(NULL, myproposal, kex_hook);

	if (myproposal[PROPOSAL_LANG_STOC] != NULL)
		xfree(myproposal[PROPOSAL_LANG_STOC]);
	if (myproposal[PROPOSAL_LANG_CTOS] != NULL)
		xfree(myproposal[PROPOSAL_LANG_CTOS]);

	kex->kex[KEX_DH_GRP1_SHA1] = kexdh_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
#ifdef GSSAPI
	kex->kex[KEX_GSS_GRP1_SHA1] = kexgss_server;
#endif /* GSSAPI */
	kex->server = 1;
	kex->client_version_string=client_version_string;
	kex->server_version_string=server_version_string;
	kex->load_host_key=&get_hostkey_by_type;
	kex->host_key_index=&get_hostkey_index;

	xxx_kex = kex;

	dispatch_run(DISPATCH_BLOCK, &kex->done, kex);

	if (kex->name) {
		xfree(kex->name);
		kex->name = NULL;
	}
	session_id2 = kex->session_id;
	session_id2_len = kex->session_id_len;

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	packet_start(SSH2_MSG_IGNORE);
	packet_put_cstring("markus");
	packet_send();
	packet_write_wait();
#endif
	debug("KEX done");
}
