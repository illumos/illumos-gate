/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 support by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"
RCSID("$OpenBSD: session.c,v 1.150 2002/09/16 19:55:33 stevesk Exp $");

#ifdef HAVE_DEFOPEN
#include <deflt.h>
#include <ulimit.h>
#endif /* HAVE_DEFOPEN */

#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

#include <priv.h>

#include "ssh.h"
#include "ssh1.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "sshpty.h"
#include "packet.h"
#include "buffer.h"
#include "mpaux.h"
#include "uidswap.h"
#include "compat.h"
#include "channels.h"
#include "bufaux.h"
#include "auth.h"
#include "auth-options.h"
#include "pathnames.h"
#include "log.h"
#include "servconf.h"
#include "sshlogin.h"
#include "serverloop.h"
#include "canohost.h"
#include "session.h"
#include "tildexpand.h"
#include "misc.h"
#include "sftp.h"

#ifdef USE_PAM
#include <security/pam_appl.h>
#endif /* USE_PAM */

#ifdef GSSAPI
#include "ssh-gss.h"
#endif

#ifdef ALTPRIVSEP
#include "altprivsep.h"
#endif /* ALTPRIVSEP */

#ifdef HAVE_CYGWIN
#include <windows.h>
#include <sys/cygwin.h>
#define is_winnt       (GetVersion() < 0x80000000)
#endif

/* func */

Session *session_new(void);
void	session_set_fds(Session *, int, int, int);
void	session_pty_cleanup(void *);
void	session_xauthfile_cleanup(void *s);
void	session_proctitle(Session *);
int	session_setup_x11fwd(Session *);
void	do_exec_pty(Session *, const char *);
void	do_exec_no_pty(Session *, const char *);
void	do_exec(Session *, const char *);
void	do_login(Session *, const char *);
void	do_child(Session *, const char *);
void	do_motd(void);
int	check_quietlogin(Session *, const char *);

static void do_authenticated1(Authctxt *);
static void do_authenticated2(Authctxt *);

static int  session_pty_req(Session *);
static int  session_env_req(Session *s);
static void session_free_env(char ***envp);
static void safely_chroot(const char *path, uid_t uid);
static void drop_privs(uid_t uid);

#ifdef USE_PAM
static void session_do_pam(Session *, int);
#endif /* USE_PAM */

/* import */
extern ServerOptions options;
extern char *__progname;
extern int log_stderr;
extern int debug_flag;
extern u_int utmp_len;
extern void destroy_sensitive_data(void);

#ifdef GSSAPI
extern Gssctxt *xxx_gssctxt;
#endif /* GSSAPI */

/* original command from peer. */
const char *original_command = NULL;

/* data */
#define MAX_SESSIONS 10
Session	sessions[MAX_SESSIONS];

#define	SUBSYSTEM_NONE		0
#define	SUBSYSTEM_EXT		1
#define	SUBSYSTEM_INT_SFTP	2

#ifdef HAVE_LOGIN_CAP
login_cap_t *lc;
#endif

/* Name and directory of socket for authentication agent forwarding. */
static char *auth_sock_name = NULL;
static char *auth_sock_dir = NULL;

/* removes the agent forwarding socket */

static void
auth_sock_cleanup_proc(void *_pw)
{
	struct passwd *pw = _pw;

	if (auth_sock_name != NULL) {
		temporarily_use_uid(pw);
		unlink(auth_sock_name);
		rmdir(auth_sock_dir);
		auth_sock_name = NULL;
		restore_uid();
	}
}

static int
auth_input_request_forwarding(struct passwd * pw)
{
	Channel *nc;
	int sock;
	struct sockaddr_un sunaddr;

	if (auth_sock_name != NULL) {
		error("authentication forwarding requested twice.");
		return 0;
	}

	/* Temporarily drop privileged uid for mkdir/bind. */
	temporarily_use_uid(pw);

	/* Allocate a buffer for the socket name, and format the name. */
	auth_sock_name = xmalloc(MAXPATHLEN);
	auth_sock_dir = xmalloc(MAXPATHLEN);
	strlcpy(auth_sock_dir, "/tmp/ssh-XXXXXXXX", MAXPATHLEN);

	/* Create private directory for socket */
	if (mkdtemp(auth_sock_dir) == NULL) {
		packet_send_debug("Agent forwarding disabled: "
		    "mkdtemp() failed: %.100s", strerror(errno));
		restore_uid();
		xfree(auth_sock_name);
		xfree(auth_sock_dir);
		auth_sock_name = NULL;
		auth_sock_dir = NULL;
		return 0;
	}
	snprintf(auth_sock_name, MAXPATHLEN, "%s/agent.%ld",
		 auth_sock_dir, (long) getpid());

	/* delete agent socket on fatal() */
	fatal_add_cleanup(auth_sock_cleanup_proc, pw);

	/* Create the socket. */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		packet_disconnect("socket: %.100s", strerror(errno));

	/* Bind it to the name. */
	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, auth_sock_name, sizeof(sunaddr.sun_path));

	if (bind(sock, (struct sockaddr *) & sunaddr, sizeof(sunaddr)) < 0)
		packet_disconnect("bind: %.100s", strerror(errno));

	/* Restore the privileged uid. */
	restore_uid();

	/* Start listening on the socket. */
	if (listen(sock, 5) < 0)
		packet_disconnect("listen: %.100s", strerror(errno));

	/* Allocate a channel for the authentication agent socket. */
	nc = channel_new("auth socket",
	    SSH_CHANNEL_AUTH_SOCKET, sock, sock, -1,
	    CHAN_X11_WINDOW_DEFAULT, CHAN_X11_PACKET_DEFAULT,
	    0, xstrdup("auth socket"), 1);
	strlcpy(nc->path, auth_sock_name, sizeof(nc->path));
	return 1;
}


void
do_authenticated(Authctxt *authctxt)
{
	/* setup the channel layer */
	if (!no_port_forwarding_flag && options.allow_tcp_forwarding)
		channel_permit_all_opens();

	if (compat20)
		do_authenticated2(authctxt);
	else
		do_authenticated1(authctxt);

	/* remove agent socket */
	if (auth_sock_name != NULL)
		auth_sock_cleanup_proc(authctxt->pw);
#ifdef KRB4
	if (options.kerberos_ticket_cleanup)
		krb4_cleanup_proc(authctxt);
#endif
#ifdef KRB5
	if (options.kerberos_ticket_cleanup)
		krb5_cleanup_proc(authctxt);
#endif
}

/*
 * Prepares for an interactive session.  This is called after the user has
 * been successfully authenticated.  During this message exchange, pseudo
 * terminals are allocated, X11, TCP/IP, and authentication agent forwardings
 * are requested, etc.
 */
static void
do_authenticated1(Authctxt *authctxt)
{
	Session *s;
	char *command;
	int success, type, screen_flag;
	int enable_compression_after_reply = 0;
	u_int proto_len, data_len, dlen, compression_level = 0;

	s = session_new();
	s->authctxt = authctxt;
	s->pw = authctxt->pw;

	/*
	 * We stay in this loop until the client requests to execute a shell
	 * or a command.
	 */
	for (;;) {
		success = 0;

		/* Get a packet from the client. */
		type = packet_read();

		/* Process the packet. */
		switch (type) {
		case SSH_CMSG_REQUEST_COMPRESSION:
			compression_level = packet_get_int();
			packet_check_eom();
			if (compression_level < 1 || compression_level > 9) {
				packet_send_debug("Received illegal compression level %d.",
				    compression_level);
				break;
			}
			if (!options.compression) {
				debug2("compression disabled");
				break;
			}
			/* Enable compression after we have responded with SUCCESS. */
			enable_compression_after_reply = 1;
			success = 1;
			break;

		case SSH_CMSG_REQUEST_PTY:
			success = session_pty_req(s);
			break;

		case SSH_CMSG_X11_REQUEST_FORWARDING:
			s->auth_proto = packet_get_string(&proto_len);
			s->auth_data = packet_get_string(&data_len);

			screen_flag = packet_get_protocol_flags() &
			    SSH_PROTOFLAG_SCREEN_NUMBER;
			debug2("SSH_PROTOFLAG_SCREEN_NUMBER: %d", screen_flag);

			if (packet_remaining() == 4) {
				if (!screen_flag)
					debug2("Buggy client: "
					    "X11 screen flag missing");
				s->screen = packet_get_int();
			} else {
				s->screen = 0;
			}
			packet_check_eom();
			success = session_setup_x11fwd(s);
			if (!success) {
				xfree(s->auth_proto);
				xfree(s->auth_data);
				s->auth_proto = NULL;
				s->auth_data = NULL;
			}
			break;

		case SSH_CMSG_AGENT_REQUEST_FORWARDING:
			if (no_agent_forwarding_flag || compat13) {
				debug("Authentication agent forwarding not permitted for this authentication.");
				break;
			}
			debug("Received authentication agent forwarding request.");
			success = auth_input_request_forwarding(s->pw);
			break;

		case SSH_CMSG_PORT_FORWARD_REQUEST:
			if (no_port_forwarding_flag) {
				debug("Port forwarding not permitted for this authentication.");
				break;
			}
			if (!options.allow_tcp_forwarding) {
				debug("Port forwarding not permitted.");
				break;
			}
			debug("Received TCP/IP port forwarding request.");
			channel_input_port_forward_request(s->pw->pw_uid == 0, options.gateway_ports);
			success = 1;
			break;

		case SSH_CMSG_MAX_PACKET_SIZE:
			if (packet_set_maxsize(packet_get_int()) > 0)
				success = 1;
			break;

#if defined(AFS) || defined(KRB5)
		case SSH_CMSG_HAVE_KERBEROS_TGT:
			if (!options.kerberos_tgt_passing) {
				verbose("Kerberos TGT passing disabled.");
			} else {
				char *kdata = packet_get_string(&dlen);
				packet_check_eom();

				/* XXX - 0x41, see creds_to_radix version */
				if (kdata[0] != 0x41) {
#ifdef KRB5
					krb5_data tgt;
					tgt.data = kdata;
					tgt.length = dlen;

					if (auth_krb5_tgt(s->authctxt, &tgt))
						success = 1;
					else
						verbose("Kerberos v5 TGT refused for %.100s", s->authctxt->user);
#endif /* KRB5 */
				} else {
#ifdef AFS
					if (auth_krb4_tgt(s->authctxt, kdata))
						success = 1;
					else
						verbose("Kerberos v4 TGT refused for %.100s", s->authctxt->user);
#endif /* AFS */
				}
				xfree(kdata);
			}
			break;
#endif /* AFS || KRB5 */

#ifdef AFS
		case SSH_CMSG_HAVE_AFS_TOKEN:
			if (!options.afs_token_passing || !k_hasafs()) {
				verbose("AFS token passing disabled.");
			} else {
				/* Accept AFS token. */
				char *token = packet_get_string(&dlen);
				packet_check_eom();

				if (auth_afs_token(s->authctxt, token))
					success = 1;
				else
					verbose("AFS token refused for %.100s",
					    s->authctxt->user);
				xfree(token);
			}
			break;
#endif /* AFS */

		case SSH_CMSG_EXEC_SHELL:
		case SSH_CMSG_EXEC_CMD:
			if (type == SSH_CMSG_EXEC_CMD) {
				command = packet_get_string(&dlen);
				debug("Exec command '%.500s'", command);
				do_exec(s, command);
				xfree(command);
			} else {
				do_exec(s, NULL);
			}
			packet_check_eom();
			session_close(s);
			return;

		default:
			/*
			 * Any unknown messages in this phase are ignored,
			 * and a failure message is returned.
			 */
			log("Unknown packet type received after authentication: %d", type);
		}
		packet_start(success ? SSH_SMSG_SUCCESS : SSH_SMSG_FAILURE);
		packet_send();
		packet_write_wait();

		/* Enable compression now that we have replied if appropriate. */
		if (enable_compression_after_reply) {
			enable_compression_after_reply = 0;
			packet_start_compression(compression_level);
		}
	}
}

/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
void
do_exec_no_pty(Session *s, const char *command)
{
	pid_t pid;

	int inout[2], err[2];
	/* Uses socket pairs to communicate with the program. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, inout) < 0 ||
	    socketpair(AF_UNIX, SOCK_STREAM, 0, err) < 0)
		packet_disconnect("Could not create socket pairs: %.100s",
				  strerror(errno));
	if (s == NULL)
		fatal("do_exec_no_pty: no session");

	session_proctitle(s);

	/* Fork the child. */
	if ((pid = fork()) == 0) {
		fatal_remove_all_cleanups();

		/* Child.  Reinitialize the log since the pid has changed. */
		log_init(__progname, options.log_level, options.log_facility, log_stderr);

		/*
		 * Create a new session and process group since the 4.4BSD
		 * setlogin() affects the entire process group.
		 */
		if (setsid() < 0)
			error("setsid failed: %.100s", strerror(errno));

		/*
		 * Redirect stdin, stdout, and stderr.  Stdin and stdout will
		 * use the same socket, as some programs (particularly rdist)
		 * seem to depend on it.
		 */
		close(inout[1]);
		close(err[1]);
		if (dup2(inout[0], 0) < 0)	/* stdin */
			perror("dup2 stdin");
		if (dup2(inout[0], 1) < 0)	/* stdout.  Note: same socket as stdin. */
			perror("dup2 stdout");
		if (s->is_subsystem) {
			/*
			 * Redirect the subsystem's stderr to /dev/null. We might send it
			 * over to the other side but changing that might break existing
			 * SSH clients.
			 */
			close(err[0]);
			if ((err[0] = open(_PATH_DEVNULL, O_WRONLY)) == -1)
				fatal("Cannot open /dev/null: %.100s", strerror(errno));
		} 
		if (dup2(err[0], 2) < 0)	/* stderr */
			perror("dup2 stderr");

#ifdef _UNICOS
		cray_init_job(s->pw); /* set up cray jid and tmpdir */
#endif

		/* Do processing for the child (exec command etc). */
		do_child(s, command);
		/* NOTREACHED */
	}
#ifdef _UNICOS
	signal(WJSIGNAL, cray_job_termination_handler);
#endif /* _UNICOS */
#ifdef HAVE_CYGWIN
	if (is_winnt)
		cygwin_set_impersonation_token(INVALID_HANDLE_VALUE);
#endif
	if (pid < 0)
		packet_disconnect("fork failed: %.100s", strerror(errno));

	s->pid = pid;
	/* Set interactive/non-interactive mode. */
	packet_set_interactive(s->display != NULL);

	/* We are the parent.  Close the child sides of the socket pairs. */
	close(inout[0]);
	close(err[0]);

	/*
	 * Enter the interactive session.  Note: server_loop must be able to
	 * handle the case that fdin and fdout are the same.
	 */
	if (compat20) {
		session_set_fds(s, inout[1], inout[1], s->is_subsystem ? -1 : err[1]);
		if (s->is_subsystem)
                        close(err[1]);
		/* Don't close channel before sending exit-status! */
		channel_set_wait_for_exit(s->chanid, 1);
	} else {
		server_loop(pid, inout[1], inout[1], err[1]);
		/* server_loop has closed inout[1] and err[1]. */
	}
}

/*
 * This is called to fork and execute a command when we have a tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors, controlling tty, updating wtmp, utmp,
 * lastlog, and other such operations.
 */
void
do_exec_pty(Session *s, const char *command)
{
	int fdout, ptyfd, ttyfd, ptymaster, pipe_fds[2];
	pid_t pid;

	if (s == NULL)
		fatal("do_exec_pty: no session");
	ptyfd = s->ptyfd;
	ttyfd = s->ttyfd;

#ifdef USE_PAM
	session_do_pam(s, 1);	/* pam_open_session() */
#endif /* USE_PAM */

	/*
	 * This pipe lets sshd wait for child to exec or exit.  This is
	 * particularly important for ALTPRIVSEP because the child is
	 * the one to call the monitor to request a record_login() and
	 * we don't want the child and the parent to compete for the
	 * monitor's attention.  But this is generic code and doesn't
	 * hurt to have here even if ALTPRIVSEP is not used.
	 */
	if (pipe(pipe_fds) != 0)
		packet_disconnect("pipe failed: %.100s", strerror(errno));

	(void) fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC);
	(void) fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

	/* Fork the child. */
	if ((pid = fork()) == 0) {
		(void) close(pipe_fds[0]);

		fatal_remove_all_cleanups();

		/* Child.  Reinitialize the log because the pid has changed. */
		log_init(__progname, options.log_level, options.log_facility, log_stderr);
		/* Close the master side of the pseudo tty. */
		close(ptyfd);

		/* Make the pseudo tty our controlling tty. */
		pty_make_controlling_tty(&ttyfd, s->tty);

		/* Redirect stdin/stdout/stderr from the pseudo tty. */
		if (dup2(ttyfd, 0) < 0)
			error("dup2 stdin: %s", strerror(errno));
		if (dup2(ttyfd, 1) < 0)
			error("dup2 stdout: %s", strerror(errno));
		if (dup2(ttyfd, 2) < 0)
			error("dup2 stderr: %s", strerror(errno));

		/* Close the extra descriptor for the pseudo tty. */
		close(ttyfd);

		/* record login, etc. similar to login(1) */
		do_login(s, command);

		/*
		 * Close the pipe to the parent so it can re-enter its event
		 * loop and service the ptm; if enough debug messages get
		 * written to the pty before this happens there will be a
		 * deadlock.
		 */
		close(pipe_fds[1]);

		/*
		 * do_motd() was called originally in do_login(). However,
		 * when the /etc/motd file is large, a deadlock would happen,
		 * because
		 * - The child is blocked at fputs() to pty, when pty buffer
		 *   is full.
		 * - The parent can not consume the pty buffer, because it is
		 *   still blocked at read(pipe_fds[0]).
		 *
		 * To resolve the deadlock issue, we defer do_motd() after
		 * close(pipe_fds[1]).
		 */
		do_motd();

		/* Do common processing for the child, such as execing the command. */
		do_child(s, command);
		/* NOTREACHED */
	}

	/* Wait for child to exec() or exit() */
	(void) close(pipe_fds[1]);
	(void) read(pipe_fds[0], &pipe_fds[1], sizeof(int));

#ifdef _UNICOS
	signal(WJSIGNAL, cray_job_termination_handler);
#endif /* _UNICOS */
#ifdef HAVE_CYGWIN
	if (is_winnt)
		cygwin_set_impersonation_token(INVALID_HANDLE_VALUE);
#endif
	if (pid < 0)
		packet_disconnect("fork failed: %.100s", strerror(errno));
	s->pid = pid;

	/* Parent.  Close the slave side of the pseudo tty. */
	close(ttyfd);

	/*
	 * Create another descriptor of the pty master side for use as the
	 * standard input.  We could use the original descriptor, but this
	 * simplifies code in server_loop.  The descriptor is bidirectional.
	 */
	fdout = dup(ptyfd);
	if (fdout < 0)
		packet_disconnect("dup #1 failed: %.100s", strerror(errno));

	/* we keep a reference to the pty master */
	ptymaster = dup(ptyfd);
	if (ptymaster < 0)
		packet_disconnect("dup #2 failed: %.100s", strerror(errno));
	s->ptymaster = ptymaster;

	/* Enter interactive session. */
	packet_set_interactive(1);
	if (compat20) {
		session_set_fds(s, ptyfd, fdout, -1);
		/* Don't close channel before sending exit-status! */
		channel_set_wait_for_exit(s->chanid, 1);
	} else {
		server_loop(pid, ptyfd, fdout, -1);
		/* server_loop _has_ closed ptyfd and fdout. */
	}
}

/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
void
do_exec(Session *s, const char *command)
{
	if (command)
		s->command = xstrdup(command);

	if (forced_command) {
		original_command = command;
		command = forced_command;
		debug("Forced command '%.900s'", command);
	}

	if (s->ttyfd != -1)
		do_exec_pty(s, command);
	else
		do_exec_no_pty(s, command);

	original_command = NULL;
}


/* administrative, login(1)-like work */
void
do_login(Session *s, const char *command)
{
	char *time_string;
#ifndef ALTPRIVSEP
	struct passwd * pw = s->pw;
#endif /* ALTPRIVSEP*/
	pid_t pid = getpid();

	/* Record that there was a login on that tty from the remote host. */
#ifdef ALTPRIVSEP
	debug3("Recording SSHv2 channel login in utmpx/wtmpx");
	altprivsep_record_login(pid, s->tty);
#endif /* ALTPRIVSEP*/

	if (check_quietlogin(s, command))
		return;

#ifdef USE_PAM
		print_pam_messages();
#endif /* USE_PAM */
#ifdef WITH_AIXAUTHENTICATE
	if (aixloginmsg && *aixloginmsg)
		printf("%s\n", aixloginmsg);
#endif /* WITH_AIXAUTHENTICATE */

#ifndef NO_SSH_LASTLOG
	if (options.print_lastlog && s->last_login_time != 0) {
		time_string = ctime(&s->last_login_time);
		if (strchr(time_string, '\n'))
			*strchr(time_string, '\n') = 0;
		if (strcmp(s->hostname, "") == 0)
			printf("Last login: %s\r\n", time_string);
		else
			printf("Last login: %s from %s\r\n", time_string,
			    s->hostname);
	}
#endif /* NO_SSH_LASTLOG */

}

/*
 * Display the message of the day.
 */
void
do_motd(void)
{
	FILE *f;
	char buf[256];

	if (options.print_motd) {
#ifdef HAVE_LOGIN_CAP
		f = fopen(login_getcapstr(lc, "welcome", "/etc/motd",
		    "/etc/motd"), "r");
#else
		f = fopen("/etc/motd", "r");
#endif
		if (f) {
			while (fgets(buf, sizeof(buf), f))
				fputs(buf, stdout);
			fclose(f);
		}
	}
}


/*
 * Check for quiet login, either .hushlogin or command given.
 */
int
check_quietlogin(Session *s, const char *command)
{
	char buf[256];
	struct passwd *pw = s->pw;
	struct stat st;

	/* Return 1 if .hushlogin exists or a command given. */
	if (command != NULL)
		return 1;
	snprintf(buf, sizeof(buf), "%.200s/.hushlogin", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	if (login_getcapbool(lc, "hushlogin", 0) || stat(buf, &st) >= 0)
		return 1;
#else
	if (stat(buf, &st) >= 0)
		return 1;
#endif
	return 0;
}

/*
 * Sets the value of the given variable in the environment.  If the variable
 * already exists, its value is overriden.
 */
void
child_set_env(char ***envp, u_int *envsizep, const char *name,
	const char *value)
{
	debug3("child_set_env(%s, %s)", name, value);
	child_set_env_silent(envp, envsizep, name, value);
}


void
child_set_env_silent(char ***envp, u_int *envsizep, const char *name,
	const char *value)
{
	u_int i, namelen;
	char **env;

	/*
	 * Find the slot where the value should be stored.  If the variable
	 * already exists, we reuse the slot; otherwise we append a new slot
	 * at the end of the array, expanding if necessary.
	 */
	env = *envp;
	namelen = strlen(name);
	for (i = 0; env[i]; i++)
		if (strncmp(env[i], name, namelen) == 0 && env[i][namelen] == '=')
			break;
	if (env[i]) {
		/* Reuse the slot. */
		xfree(env[i]);
	} else {
		/* New variable.  Expand if necessary. */
		if (i >= (*envsizep) - 1) {
			if (*envsizep >= 1000)
				fatal("child_set_env: too many env vars,"
				    " skipping: %.100s", name);
			(*envsizep) += 50;
			env = (*envp) = xrealloc(env, (*envsizep) * sizeof(char *));
		}
		/* Need to set the NULL pointer at end of array beyond the new slot. */
		env[i + 1] = NULL;
	}

	/* Allocate space and format the variable in the appropriate slot. */
	env[i] = xmalloc(strlen(name) + 1 + strlen(value) + 1);
	snprintf(env[i], strlen(name) + 1 + strlen(value) + 1, "%s=%s", name, value);
}

/*
 * Reads environment variables from the given file and adds/overrides them
 * into the environment.  If the file does not exist, this does nothing.
 * Otherwise, it must consist of empty lines, comments (line starts with '#')
 * and assignments of the form name=value.  No other forms are allowed.
 */
static void
read_environment_file(char ***env, u_int *envsize,
	const char *filename)
{
	FILE *f;
	char buf[4096];
	char *cp, *value;
	u_int lineno = 0;

	f = fopen(filename, "r");
	if (!f)
		return;

	while (fgets(buf, sizeof(buf), f)) {
		if (++lineno > 1000)
			fatal("Too many lines in environment file %s", filename);
		for (cp = buf; *cp == ' ' || *cp == '\t'; cp++)
			;
		if (!*cp || *cp == '#' || *cp == '\n')
			continue;
		if (strchr(cp, '\n'))
			*strchr(cp, '\n') = '\0';
		value = strchr(cp, '=');
		if (value == NULL) {
			fprintf(stderr, gettext("Bad line %u in %.100s\n"),
				lineno, filename);
			continue;
		}
		/*
		 * Replace the equals sign by nul, and advance value to
		 * the value string.
		 */
		*value = '\0';
		value++;
		child_set_env(env, envsize, cp, value);
	}
	fclose(f);
}

void copy_environment(char **source, char ***env, u_int *envsize)
{
	char *var_name, *var_val;
	int i;

	if (source == NULL)
		return;

	for(i = 0; source[i] != NULL; i++) {
		var_name = xstrdup(source[i]);
		if ((var_val = strstr(var_name, "=")) == NULL) {
			xfree(var_name);
			continue;
		}
		*var_val++ = '\0';

		debug3("Copy environment: %s=%s", var_name, var_val);
		child_set_env(env, envsize, var_name, var_val);
		
		xfree(var_name);
	}
}

#ifdef HAVE_DEFOPEN
static
void
deflt_do_setup_env(Session *s, const char *shell, char ***env, u_int *envsize)
{
	int	flags;
	char	*ptr;
	mode_t	Umask = 022;

	if (defopen(_PATH_DEFAULT_LOGIN))
		return;

	/* Ignore case */
	flags = defcntl(DC_GETFLAGS, 0);
	TURNOFF(flags, DC_CASE);
	(void) defcntl(DC_SETFLAGS, flags);

	/* TZ & HZ */
	if ((ptr = defread("TIMEZONE=")) != NULL)
		child_set_env(env, envsize, "TZ", ptr);
	if ((ptr = defread("HZ=")) != NULL)
		child_set_env(env, envsize, "HZ", ptr);

	/* PATH */
	if (s->pw->pw_uid != 0 && (ptr = defread("PATH=")) != NULL)
		child_set_env(env, envsize, "PATH", ptr);
	if (s->pw->pw_uid == 0 && (ptr = defread("SUPATH=")) != NULL)
		child_set_env(env, envsize, "PATH", ptr);

	/* SHELL */
	if ((ptr = defread("ALTSHELL=")) != NULL) {
		if (strcasecmp("YES", ptr) == 0)
			child_set_env(env, envsize, "SHELL", shell);
		else
			child_set_env(env, envsize, "SHELL", "");
	}

	/* UMASK */
	if ((ptr = defread("UMASK=")) != NULL &&
	    sscanf(ptr, "%lo", &Umask) == 1 &&
	    Umask <= (mode_t)0777)
		(void) umask(Umask);
	else
		(void) umask(022);

	/* ULIMIT */
	if ((ptr = defread("ULIMIT=")) != NULL && atol(ptr) > 0L &&
	    ulimit(UL_SETFSIZE, atol(ptr)) < 0L)
		error("Could not set ULIMIT to %ld from %s\n", atol(ptr),
			_PATH_DEFAULT_LOGIN);

	(void) defopen(NULL);
}
#endif /* HAVE_DEFOPEN */

static char **
do_setup_env(Session *s, const char *shell)
{
	char buf[256];
	char path_maildir[] = _PATH_MAILDIR;
	u_int i, envsize, pm_len;
	char **env;
	struct passwd *pw = s->pw;

	/* Initialize the environment. */
	envsize = 100;
	env = xmalloc(envsize * sizeof(char *));
	env[0] = NULL;

#ifdef HAVE_CYGWIN
	/*
	 * The Windows environment contains some setting which are
	 * important for a running system. They must not be dropped.
	 */
	copy_environment(environ, &env, &envsize);
#endif

#ifdef GSSAPI
	/* Allow any GSSAPI methods that we've used to alter 
	 * the childs environment as they see fit
	 */
	ssh_gssapi_do_child(xxx_gssctxt, &env,&envsize);
#endif

	/* Set basic environment. */
	child_set_env(&env, &envsize, "USER", pw->pw_name);
	child_set_env(&env, &envsize, "LOGNAME", pw->pw_name);
	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
#ifdef HAVE_LOGIN_CAP
	if (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
	else
		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
#else /* HAVE_LOGIN_CAP */
# ifndef HAVE_CYGWIN
	/*
	 * There's no standard path on Windows. The path contains
	 * important components pointing to the system directories,
	 * needed for loading shared libraries. So the path better
	 * remains intact here.
	 */
#  ifdef SUPERUSER_PATH
	child_set_env(&env, &envsize, "PATH", 
	    s->pw->pw_uid == 0 ? SUPERUSER_PATH : _PATH_STDPATH);
#  else 
	child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
#  endif /* SUPERUSER_PATH */
# endif /* HAVE_CYGWIN */
#endif /* HAVE_LOGIN_CAP */

	pm_len = strlen(path_maildir);
	if (path_maildir[pm_len - 1] == '/' && pm_len > 1)
		path_maildir[pm_len - 1] = NULL;
	snprintf(buf, sizeof buf, "%.200s/%.50s",
		 path_maildir, pw->pw_name);
	child_set_env(&env, &envsize, "MAIL", buf);

	/* Normal systems set SHELL by default. */
	child_set_env(&env, &envsize, "SHELL", shell);

#ifdef HAVE_DEFOPEN
	deflt_do_setup_env(s, shell, &env, &envsize);
#endif /* HAVE_DEFOPEN */

#define PASS_ENV(x) \
	if (getenv(x)) \
		child_set_env(&env, &envsize, x, getenv(x));

	if (getenv("TZ"))
		child_set_env(&env, &envsize, "TZ", getenv("TZ"));

	if (s->auth_file != NULL)
		child_set_env(&env, &envsize, "XAUTHORITY", s->auth_file);

	PASS_ENV("LANG")
	PASS_ENV("LC_ALL")
	PASS_ENV("LC_CTYPE")
	PASS_ENV("LC_COLLATE")
	PASS_ENV("LC_TIME")
	PASS_ENV("LC_NUMERIC")
	PASS_ENV("LC_MONETARY")
	PASS_ENV("LC_MESSAGES")

#undef PASS_ENV

	if (s->env != NULL)
		copy_environment(s->env, &env, &envsize);

	/* Set custom environment options from RSA authentication. */
	while (custom_environment) {
		struct envstring *ce = custom_environment;
		char *str = ce->s;

		for (i = 0; str[i] != '=' && str[i]; i++)
			;
		if (str[i] == '=') {
			str[i] = 0;
			child_set_env(&env, &envsize, str, str + i + 1);
		}
		custom_environment = ce->next;
		xfree(ce->s);
		xfree(ce);
	}

	/* SSH_CLIENT deprecated */
	snprintf(buf, sizeof buf, "%.50s %d %d",
	    get_remote_ipaddr(), get_remote_port(), get_local_port());
	child_set_env(&env, &envsize, "SSH_CLIENT", buf);

	snprintf(buf, sizeof buf, "%.50s %d %.50s %d",
	    get_remote_ipaddr(), get_remote_port(),
	    get_local_ipaddr(packet_get_connection_in()), get_local_port());
	child_set_env(&env, &envsize, "SSH_CONNECTION", buf);

	if (s->ttyfd != -1)
		child_set_env(&env, &envsize, "SSH_TTY", s->tty);
	if (s->term)
		child_set_env(&env, &envsize, "TERM", s->term);
	if (s->display)
		child_set_env(&env, &envsize, "DISPLAY", s->display);
	if (original_command)
		child_set_env(&env, &envsize, "SSH_ORIGINAL_COMMAND",
		    original_command);

#ifdef _UNICOS
	if (cray_tmpdir[0] != '\0')
		child_set_env(&env, &envsize, "TMPDIR", cray_tmpdir);
#endif /* _UNICOS */

#ifdef _AIX
	{
		char *cp;

		if ((cp = getenv("AUTHSTATE")) != NULL)
			child_set_env(&env, &envsize, "AUTHSTATE", cp);
		if ((cp = getenv("KRB5CCNAME")) != NULL)
			child_set_env(&env, &envsize, "KRB5CCNAME", cp);
		read_environment_file(&env, &envsize, "/etc/environment");
	}
#endif
#ifdef KRB4
	if (s->authctxt->krb4_ticket_file)
		child_set_env(&env, &envsize, "KRBTKFILE",
		    s->authctxt->krb4_ticket_file);
#endif
#ifdef KRB5
	if (s->authctxt->krb5_ticket_file)
		child_set_env(&env, &envsize, "KRB5CCNAME",
		    s->authctxt->krb5_ticket_file);
#endif
#ifdef USE_PAM
	/*
	 * Pull in any environment variables that may have
	 * been set by PAM.
	 */
	{
		char **p;

		p = fetch_pam_environment(s->authctxt);
		copy_environment(p, &env, &envsize);
		free_pam_environment(p);
	}
#endif /* USE_PAM */

	if (auth_sock_name != NULL)
		child_set_env(&env, &envsize, SSH_AUTHSOCKET_ENV_NAME,
		    auth_sock_name);

	/* read $HOME/.ssh/environment. */
	if (options.permit_user_env) {
		snprintf(buf, sizeof buf, "%.200s/.ssh/environment",
		    strcmp(pw->pw_dir, "/") ? pw->pw_dir : "");
		read_environment_file(&env, &envsize, buf);
	}
	if (debug_flag) {
		/* dump the environment */
		fprintf(stderr, gettext("Environment:\n"));
		for (i = 0; env[i]; i++)
			fprintf(stderr, "  %.200s\n", env[i]);
	}
	return env;
}

/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
static void
do_rc_files(Session *s, const char *shell)
{
	FILE *f = NULL;
	char cmd[1024];
	int do_xauth;
	struct stat st;

	do_xauth =
	    s->display != NULL && s->auth_proto != NULL && s->auth_data != NULL;

	/* ignore _PATH_SSH_USER_RC for subsystems */
	if (!s->is_subsystem && (stat(_PATH_SSH_USER_RC, &st) >= 0)) {
		snprintf(cmd, sizeof cmd, "%s -c '%s %s'",
		    shell, _PATH_BSHELL, _PATH_SSH_USER_RC);
		if (debug_flag)
			fprintf(stderr, "Running %s\n", cmd);
		f = popen(cmd, "w");
		if (f) {
			if (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} else
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_USER_RC);
	} else if (stat(_PATH_SSH_SYSTEM_RC, &st) >= 0) {
		if (debug_flag)
			fprintf(stderr, "Running %s %s\n", _PATH_BSHELL,
			    _PATH_SSH_SYSTEM_RC);
		f = popen(_PATH_BSHELL " " _PATH_SSH_SYSTEM_RC, "w");
		if (f) {
			if (do_xauth)
				fprintf(f, "%s %s\n", s->auth_proto,
				    s->auth_data);
			pclose(f);
		} else
			fprintf(stderr, "Could not run %s\n",
			    _PATH_SSH_SYSTEM_RC);
	} else if (do_xauth && options.xauth_location != NULL) {
		/* Add authority data to .Xauthority if appropriate. */
		if (debug_flag) {
			fprintf(stderr,
			    "Running %.500s add "
			    "%.100s %.100s %.100s\n",
			    options.xauth_location, s->auth_display,
			    s->auth_proto, s->auth_data);
		}
		snprintf(cmd, sizeof cmd, "%s -q -",
		    options.xauth_location);
		f = popen(cmd, "w");
		if (f) {
			fprintf(f, "add %s %s %s\n",
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} else {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
}

/* Disallow logins if /etc/nologin exists. This does not apply to root. */
static void
do_nologin(struct passwd *pw)
{
	FILE *f = NULL;
	char buf[1024];
	struct stat sb;

	if (pw->pw_uid == 0)
		return;

	if (stat(_PATH_NOLOGIN, &sb) == -1)
	       return;

	/* /etc/nologin exists.  Print its contents if we can and exit. */
	log("User %.100s not allowed because %s exists.", pw->pw_name,
	    _PATH_NOLOGIN);
	if ((f = fopen(_PATH_NOLOGIN, "r")) != NULL) {
		while (fgets(buf, sizeof(buf), f))
			fputs(buf, stderr);
		fclose(f);
	}
	exit(254);
}

/* Chroot into ChrootDirectory if the option is set. */
void
chroot_if_needed(struct passwd *pw)
{
	char *chroot_path, *tmp;

	if (chroot_requested(options.chroot_directory)) {
		tmp = tilde_expand_filename(options.chroot_directory,
		    pw->pw_uid);
		chroot_path = percent_expand(tmp, "h", pw->pw_dir,
		    "u", pw->pw_name, (char *)NULL);
		safely_chroot(chroot_path, pw->pw_uid);
		free(tmp);
		free(chroot_path);
	}
}

/*
 * Chroot into a directory after checking it for safety: all path components
 * must be root-owned directories with strict permissions.
 */
static void
safely_chroot(const char *path, uid_t uid)
{
	const char *cp;
	char component[MAXPATHLEN];
	struct stat st;

	if (*path != '/')
		fatal("chroot path does not begin at root");
	if (strlen(path) >= sizeof(component))
		fatal("chroot path too long");

	/*
	 * Descend the path, checking that each component is a
	 * root-owned directory with strict permissions.
	 */
	for (cp = path; cp != NULL;) {
		if ((cp = strchr(cp, '/')) == NULL)
			strlcpy(component, path, sizeof(component));
		else {
			cp++;
			memcpy(component, path, cp - path);
			component[cp - path] = '\0';
		}
	
		debug3("%s: checking '%s'", __func__, component);

		if (stat(component, &st) != 0)
			fatal("%s: stat(\"%s\"): %s", __func__,
			    component, strerror(errno));
		if (st.st_uid != 0 || (st.st_mode & 022) != 0)
			fatal("bad ownership or modes for chroot "
			    "directory %s\"%s\"", 
			    cp == NULL ? "" : "component ", component);
		if (!S_ISDIR(st.st_mode))
			fatal("chroot path %s\"%s\" is not a directory",
			    cp == NULL ? "" : "component ", component);
	}

	if (chdir(path) == -1)
		fatal("Unable to chdir to chroot path \"%s\": "
		    "%s", path, strerror(errno));
	if (chroot(path) == -1)
		fatal("chroot(\"%s\"): %s", path, strerror(errno));
	if (chdir("/") == -1)
		fatal("%s: chdir(/) after chroot: %s",
		    __func__, strerror(errno));
	verbose("Changed root directory to \"%s\"", path);
}

static void
launch_login(struct passwd *pw, const char *hostname)
{
	/* Launch login(1). */

	execl(LOGIN_PROGRAM, "login", "-h", hostname,
#ifdef xxxLOGIN_NEEDS_TERM
		    (s->term ? s->term : "unknown"),
#endif /* LOGIN_NEEDS_TERM */
#ifdef LOGIN_NO_ENDOPT
	    "-p", "-f", pw->pw_name, (char *)NULL);
#else
	    "-p", "-f", "--", pw->pw_name, (char *)NULL);
#endif

	/* Login couldn't be executed, die. */

	perror("login");
	exit(1);
}

/*
 * Performs common processing for the child, such as setting up the
 * environment, closing extra file descriptors, setting the user and group
 * ids, and executing the command or shell.
 */
#define ARGV_MAX 10
void
do_child(Session *s, const char *command)
{
	extern char **environ;
	char **env;
	char *argv[ARGV_MAX];
	const char *shell, *shell0;
	struct passwd *pw = s->pw;

	/* remove hostkey from the child's memory */
	destroy_sensitive_data();

	do_nologin(pw);
	chroot_if_needed(pw);

	/*
	 * Get the shell from the password data.  An empty shell field is
	 * legal, and means /bin/sh.
	 */
	shell = (pw->pw_shell[0] == '\0') ? _PATH_BSHELL : pw->pw_shell;
#ifdef HAVE_LOGIN_CAP
	shell = login_getcapstr(lc, "shell", (char *)shell, (char *)shell);
#endif

	env = do_setup_env(s, shell);

	/*
	 * Close the connection descriptors; note that this is the child, and
	 * the server will still have the socket open, and it is important
	 * that we do not shutdown it.  Note that the descriptors cannot be
	 * closed before building the environment, as we call
	 * get_remote_ipaddr there.
	 */
	if (packet_get_connection_in() == packet_get_connection_out())
		close(packet_get_connection_in());
	else {
		close(packet_get_connection_in());
		close(packet_get_connection_out());
	}
	/*
	 * Close all descriptors related to channels.  They will still remain
	 * open in the parent.
	 */
	/* XXX better use close-on-exec? -markus */
	channel_close_all();

	/*
	 * Close any extra file descriptors.  Note that there may still be
	 * descriptors left by system functions.  They will be closed later.
	 */
	endpwent();

	/*
	 * Must switch to the new environment variables so that .ssh/rc,
	 * /etc/ssh/sshrc, and xauth are run in the proper environment.
	 */
	environ = env;

	/*
	 * New environment has been installed. We need to update locale
	 * so that error messages beyond this point have the proper
	 * character encoding.
	 */
	(void) setlocale(LC_ALL, ""); 

	/*
	 * Close any extra open file descriptors so that we don\'t have them
	 * hanging around in clients.  Note that we want to do this after
	 * initgroups, because at least on Solaris 2.3 it leaves file
	 * descriptors open.
	 */
	closefrom(STDERR_FILENO + 1);

#ifdef AFS
	/* Try to get AFS tokens for the local cell. */
	if (k_hasafs()) {
		char cell[64];

		if (k_afs_cell_of_file(pw->pw_dir, cell, sizeof(cell)) == 0)
			krb_afslog(cell, 0);

		krb_afslog(0, 0);
	}
#endif /* AFS */

	/* Change current directory to the user's home directory. */
	if (chdir(pw->pw_dir) < 0) {
		/* Suppress missing homedir warning for chroot case */
		if (!chroot_requested(options.chroot_directory))
			fprintf(stderr, "Could not chdir to home "
			    "directory %s: %s\n", pw->pw_dir,
			    strerror(errno));
	}

	do_rc_files(s, shell);

	/* restore SIGPIPE for child */
	signal(SIGPIPE,  SIG_DFL);

	if (s->is_subsystem == SUBSYSTEM_INT_SFTP) {
		int i;
		char *p, *args;
		extern int optind, optreset;

		/* This will set the E/P sets here, simulating exec(2). */
		drop_privs(pw->pw_uid);

		setproctitle("%s@internal-sftp-server", s->pw->pw_name);
		args = xstrdup(command ? command : "sftp-server");

		i = 0;
		for ((p = strtok(args, " ")); p != NULL; (p = strtok(NULL, " "))) {
			if (i < ARGV_MAX - 1)
				argv[i++] = p;
		}

		argv[i] = NULL;
		optind = optreset = 1;
		__progname = argv[0];
		exit(sftp_server_main(i, argv, s->pw));
	}

	/* Get the last component of the shell name. */
	if ((shell0 = strrchr(shell, '/')) != NULL)
		shell0++;
	else
		shell0 = shell;

	/*
	 * If we have no command, execute the shell.  In this case, the shell
	 * name to be passed in argv[0] is preceded by '-' to indicate that
	 * this is a login shell.
	 */
	if (!command) {
		char argv0[256];

		/* Start the shell.  Set initial character to '-'. */
		argv0[0] = '-';

		if (strlcpy(argv0 + 1, shell0, sizeof(argv0) - 1)
		    >= sizeof(argv0) - 1) {
			errno = EINVAL;
			perror(shell);
			exit(1);
		}

		/* Execute the shell. */
		argv[0] = argv0;
		argv[1] = NULL;
		execve(shell, argv, env);

		/* Executing the shell failed. */
		perror(shell);
		exit(1);
	}
	/*
	 * Execute the command using the user's shell.  This uses the -c
	 * option to execute the command.
	 */
	argv[0] = (char *) shell0;
	argv[1] = "-c";
	argv[2] = (char *) command;
	argv[3] = NULL;
	execve(shell, argv, env);
	perror(shell);
	exit(1);
}

Session *
session_new(void)
{
	int i;
	static int did_init = 0;
	if (!did_init) {
		debug("session_new: init");
		for (i = 0; i < MAX_SESSIONS; i++) {
			sessions[i].used = 0;
		}
		did_init = 1;
	}
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &sessions[i];
		if (! s->used) {
			memset(s, 0, sizeof(*s));
			s->chanid = -1;
			s->ptyfd = -1;
			s->ttyfd = -1;
			s->used = 1;
			s->self = i;
			s->env = NULL;
			debug("session_new: session %d", i);
			return s;
		}
	}
	return NULL;
}

static void
session_dump(void)
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &sessions[i];
		debug("dump: used %d session %d %p channel %d pid %ld",
		    s->used,
		    s->self,
		    s,
		    s->chanid,
		    (long)s->pid);
	}
}

int
session_open(Authctxt *authctxt, int chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	if (s == NULL) {
		error("no more sessions");
		return 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	if (s->pw == NULL)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	return 1;
}

#ifndef lint
Session *
session_by_tty(char *tty)
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &sessions[i];
		if (s->used && s->ttyfd != -1 && strcmp(s->tty, tty) == 0) {
			debug("session_by_tty: session %d tty %s", i, tty);
			return s;
		}
	}
	debug("session_by_tty: unknown tty %.100s", tty);
	session_dump();
	return NULL;
}
#endif /* lint */

static Session *
session_by_channel(int id)
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &sessions[i];
		if (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d", i, id);
			return s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	return NULL;
}

static Session *
session_by_pid(pid_t pid)
{
	int i;
	debug("session_by_pid: pid %ld", (long)pid);
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &sessions[i];
		if (s->used && s->pid == pid)
			return s;
	}
	error("session_by_pid: unknown pid %ld", (long)pid);
	session_dump();
	return NULL;
}

static int
session_window_change_req(Session *s)
{
	s->col = packet_get_int();
	s->row = packet_get_int();
	s->xpixel = packet_get_int();
	s->ypixel = packet_get_int();
	packet_check_eom();
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	return 1;
}

static int
session_pty_req(Session *s)
{
	u_int len;
	int n_bytes;

	if (no_pty_flag) {
		debug("Allocating a pty not permitted for this authentication.");
		return 0;
	}
	if (s->ttyfd != -1) {
		packet_disconnect("Protocol error: you already have a pty.");
		return 0;
	}
	/* Get the time and hostname when the user last logged in. */
	if (options.print_lastlog) {
		s->hostname[0] = '\0';
		s->last_login_time = get_last_login_time(s->pw->pw_uid,
		    s->pw->pw_name, s->hostname, sizeof(s->hostname));
		
		/*
		 * PAM may update the last login date.
		 *
		 * Ideally PAM would also show the last login date as a
		 * PAM_TEXT_INFO conversation message, and then we could just
		 * always force the use of keyboard-interactive just so we can
		 * pass any such PAM prompts and messages from the account and
		 * session stacks, but skip pam_authenticate() if other userauth
		 * has succeeded and the user's password isn't expired.
		 *
		 * Unfortunately this depends on support for keyboard-
		 * interactive in the client, and support for lastlog messages
		 * in some PAM module.
		 *
		 * As it is Solaris updates the lastlog in PAM, but does
		 * not show the lastlog date in PAM.  If and when this state of
		 * affairs changes this hack can be reconsidered, and, maybe,
		 * removed.
		 *
		 * So we're stuck with a crude hack: get the lastlog
		 * time before calling pam_open_session() and store it
		 * in the Authctxt and then use it here once.  After
		 * that, if the client opens any more pty sessions we'll
		 * show the last lastlog entry since userauth.
		 */
		if (s->authctxt != NULL && s->authctxt->last_login_time > 0) {
			s->last_login_time = s->authctxt->last_login_time;
			(void) strlcpy(s->hostname,
				       s->authctxt->last_login_host,
				       sizeof(s->hostname));
			s->authctxt->last_login_time = 0;
			s->authctxt->last_login_host[0] = '\0';
		}
	}

	s->term = packet_get_string(&len);

	if (compat20) {
		s->col = packet_get_int();
		s->row = packet_get_int();
	} else {
		s->row = packet_get_int();
		s->col = packet_get_int();
	}
	s->xpixel = packet_get_int();
	s->ypixel = packet_get_int();

	if (strcmp(s->term, "") == 0) {
		xfree(s->term);
		s->term = NULL;
	}

	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	if (!pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, sizeof(s->tty))) {
		if (s->term)
			xfree(s->term);
		s->term = NULL;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		return 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	/* for SSH1 the tty modes length is not given */
	if (!compat20)
		n_bytes = packet_remaining();
	tty_parse_modes(s->ttyfd, &n_bytes);

	/*
	 * Add a cleanup function to clear the utmp entry and record logout
	 * time in case we call fatal() (e.g., the connection gets closed).
	 */
	fatal_add_cleanup(session_pty_cleanup, (void *)s);
	pty_setowner(s->pw, s->tty);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	packet_check_eom();
	session_proctitle(s);
	return 1;
}

static int
session_subsystem_req(Session *s)
{
	struct stat st;
	u_int len;
	int success = 0;
	char *prog, *cmd, *subsys = packet_get_string(&len);
	u_int i;

	packet_check_eom();
	log("subsystem request for %.100s", subsys);

	for (i = 0; i < options.num_subsystems; i++) {
		if (strcmp(subsys, options.subsystem_name[i]) == 0) {
			prog = options.subsystem_command[i];
			cmd = options.subsystem_args[i];
			if (strcmp(INTERNAL_SFTP_NAME, prog) == 0) {
				s->is_subsystem = SUBSYSTEM_INT_SFTP;
			/*
			 * We must stat(2) the subsystem before we chroot in
			 * order to be able to send a proper error message.
			 */
			} else if (chroot_requested(options.chroot_directory)) {
				char chdirsub[MAXPATHLEN];

				strlcpy(chdirsub, options.chroot_directory,
				    sizeof (chdirsub));
				strlcat(chdirsub, "/", sizeof (chdirsub));
				strlcat(chdirsub, prog, sizeof (chdirsub));
				if (stat(chdirsub, &st) < 0) {
					error("subsystem: cannot stat %s under "
					    "chroot directory %s: %s", prog,
					    options.chroot_directory,
					    strerror(errno));
					if (strcmp(subsys, "sftp") == 0)
						error("subsystem: please see "
						    "the Subsystem option in "
						    "sshd_config(4) for an "
						    "explanation of '%s'.",
						    INTERNAL_SFTP_NAME);
					break;
				}
			} else if (stat(prog, &st) < 0) {
				error("subsystem: cannot stat %s: %s", prog,
				    strerror(errno));
				break;
			} else {
				s->is_subsystem = SUBSYSTEM_EXT;
			}
			debug("subsystem: exec() %s", cmd);
			do_exec(s, cmd);
			success = 1;
			break;
		}
	}

	if (!success)
		log("subsystem request for %.100s failed, subsystem not found",
		    subsys);

	xfree(subsys);
	return success;
}

/*
 * Serve "x11-req" channel request for X11 forwarding for the current session
 * channel.
 */
static int
session_x11_req(Session *s)
{
	int success, fd;
	char xauthdir[] = "/tmp/ssh-xauth-XXXXXX";

	s->single_connection = packet_get_char();
	s->auth_proto = packet_get_string(NULL);
	s->auth_data = packet_get_string(NULL);
	s->screen = packet_get_int();
	packet_check_eom();

	success = session_setup_x11fwd(s);
	if (!success) {
		xfree(s->auth_proto);
		xfree(s->auth_data);
		s->auth_proto = NULL;
		s->auth_data = NULL;
		return (success);
	}

	/*
	 * Create per session X authority file so that different sessions
	 * don't contend for one common file. The reason for this is that
	 * xauth(1) locking doesn't work too well over network filesystems.
	 *
	 * If mkdtemp() or open() fails then s->auth_file remains NULL which
	 * means that we won't set XAUTHORITY variable in child's environment
	 * and xauth(1) will use the default location for the authority file.
	 */
	if (mkdtemp(xauthdir) != NULL) {
		s->auth_file = xmalloc(MAXPATHLEN);
		snprintf(s->auth_file, MAXPATHLEN, "%s/xauthfile",
		    xauthdir);
		/*
		 * we don't want that "creating new authority file" message to
		 * be printed by xauth(1) so we must create that file
		 * beforehand.
		 */
		if ((fd = open(s->auth_file, O_CREAT | O_EXCL | O_RDONLY,
		    S_IRUSR | S_IWUSR)) == -1) {
			error("failed to create the temporary X authority "
			    "file %s: %.100s; will use the default one",
			    s->auth_file, strerror(errno));
			xfree(s->auth_file);
			s->auth_file = NULL;
			if (rmdir(xauthdir) == -1) {
				error("cannot remove xauth directory %s: %.100s",
				    xauthdir, strerror(errno));
			}
		} else {
			close(fd);
			debug("temporary X authority file %s created",
			    s->auth_file);

			/*
			 * add a cleanup function to remove the temporary
			 * xauth file in case we call fatal() (e.g., the
			 * connection gets closed).
			 */
			fatal_add_cleanup(session_xauthfile_cleanup, (void *)s);
		}
	}
	else {
		error("failed to create a directory for the temporary X "
		    "authority file: %.100s; will use the default xauth file",
		    strerror(errno));
	}

	return (success);
}

static int
session_shell_req(Session *s)
{
	packet_check_eom();
	do_exec(s, NULL);
	return 1;
}

static int
session_exec_req(Session *s)
{
	u_int len;
	char *command = packet_get_string(&len);
	packet_check_eom();
	do_exec(s, command);
	xfree(command);
	return 1;
}

static int
session_auth_agent_req(Session *s)
{
	static int called = 0;
	packet_check_eom();
	if (no_agent_forwarding_flag) {
		debug("session_auth_agent_req: no_agent_forwarding_flag");
		return 0;
	}
	if (called) {
		return 0;
	} else {
		called = 1;
		return auth_input_request_forwarding(s->pw);
	}
}

static int
session_loc_env_check(char *var, char *val)
{
	char *current;
	int cat, ret;

	if (strcmp(var, "LANG") == 0)
		cat = LC_ALL;
	else if (strcmp(var, "LC_ALL") == 0)
		cat = LC_ALL;
	else if (strcmp(var, "LC_CTYPE") == 0)
		cat = LC_CTYPE;
	else if (strcmp(var, "LC_COLLATE") == 0)
		cat = LC_COLLATE;
	else if (strcmp(var, "LC_TIME") == 0)
		cat = LC_TIME;
	else if (strcmp(var, "LC_NUMERIC") == 0)
		cat = LC_NUMERIC;
	else if (strcmp(var, "LC_MONETARY") == 0)
		cat = LC_MONETARY;
	else if (strcmp(var, "LC_MESSAGES") == 0)
		cat = LC_MESSAGES;

	current = setlocale(cat, NULL);

	ret = (setlocale(cat, val) != NULL);
	(void) setlocale(cat, current);
	return (ret);
}

static int
session_env_req(Session *s)
{
	Channel *c;
	char *var, *val, *e;
	char **p;
	size_t len;
	int ret = 0;

	/* Get var/val from the rest of this packet */
	var = packet_get_string(NULL);
	val = packet_get_string(NULL);

	/*
	 * We'll need the channel ID for the packet_send_debug messages,
	 * so get it now.
	 */
	if ((c = channel_lookup(s->chanid)) == NULL)
		goto done;	/* shouldn't happen! */

	debug2("Received request for environment variable %s=%s", var, val);

	/* For now allow only LANG and LC_* */
	if (strcmp(var, "LANG") != 0 && strncmp(var, "LC_", 3) != 0) {
		debug2("Rejecting request for environment variable %s", var);
		goto done;
	}

	if (!session_loc_env_check(var, val)) {
		packet_send_debug(gettext("Missing locale support for %s=%s"),
			var, val);
		goto done;
	}

	packet_send_debug(gettext("Channel %d set: %s=%s"), c->remote_id,
		var, val);

	/*
	 * Always append new environment variables without regard to old
	 * ones being overriden.  The way these are actually added to
	 * the environment of the session process later settings
	 * override earlier ones; see copy_environment().
	 */
	if (s->env == NULL) {
		char **env;

		env = xmalloc(sizeof (char **) * 2);
		memset(env, 0, sizeof (char **) * 2);

		s->env = env;
		p = env;
	} else {
		for (p = s->env; *p != NULL ; p++);

		s->env = xrealloc(s->env, (p - s->env + 2) * sizeof (char **));

		for (p = s->env; *p != NULL ; p++);
	}

	len = snprintf(NULL, 0, "%s=%s", var, val);
	e = xmalloc(len + 1);
	(void) snprintf(e, len + 1, "%s=%s", var, val);

	(*p++) = e;
	*p = NULL;

	ret = 1;

done:
	xfree(var);
	xfree(val);

	return (ret);
}

static void
session_free_env(char ***envp)
{
	char **env, **p;

	if (envp == NULL || *envp == NULL)
		return;

	env = *envp;

	*envp = NULL;

	for (p = env; *p != NULL; p++)
		xfree(*p);

	xfree(env);
}

int
session_input_channel_req(Channel *c, const char *rtype)
{
	int success = 0;
	Session *s;

	if ((s = session_by_channel(c->self)) == NULL) {
		log("session_input_channel_req: no session %d req %.100s",
		    c->self, rtype);
		return 0;
	}
	debug("session_input_channel_req: session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	if (c->type == SSH_CHANNEL_LARVAL) {
		if (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(s);
		} else if (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(s);
		} else if (strcmp(rtype, "pty-req") == 0) {
			success =  session_pty_req(s);
		} else if (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(s);
		} else if (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			success = session_auth_agent_req(s);
		} else if (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(s);
		} else if (strcmp(rtype, "env") == 0) {
			success = session_env_req(s);
		}
	}
	if (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(s);
	}
	return success;
}

void
session_set_fds(Session *s, int fdin, int fdout, int fderr)
{
	if (!compat20)
		fatal("session_set_fds: called for proto != 2.0");
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	if (s->chanid == -1)
		fatal("no channel for session %d", s->self);
	channel_set_fds(s->chanid,
	    fdout, fdin, fderr,
	    fderr == -1 ? CHAN_EXTENDED_IGNORE : CHAN_EXTENDED_READ,
	    1,
	    CHAN_SES_WINDOW_DEFAULT);
}

/*
 * Function to perform pty cleanup. Also called if we get aborted abnormally
 * (e.g., due to a dropped connection).
 */
void
session_pty_cleanup2(void *session)
{
	Session *s = session;

	if (s == NULL) {
		error("session_pty_cleanup: no session");
		return;
	}
	if (s->ttyfd == -1)
		return;

	debug("session_pty_cleanup: session %d release %s", s->self, s->tty);

#ifdef USE_PAM
	session_do_pam(s, 0);
#endif /* USE_PAM */

	/* Record that the user has logged out. */
	if (s->pid != 0) {
		debug3("Recording SSHv2 channel logout in utmpx/wtmpx");
#ifdef ALTPRIVSEP
		altprivsep_record_logout(s->pid);
#endif /* ALTPRIVSEP */
	}

	/* Release the pseudo-tty. */
	if (getuid() == 0)
		pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
	if (close(s->ptymaster) < 0)
		error("close(s->ptymaster/%d): %s", s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

void
session_pty_cleanup(void *session)
{
	session_pty_cleanup2(session);
}

/*
 * We use a different temporary X authority file per every session so we
 * should remove those files when fatal() is called.
 */
void
session_xauthfile_cleanup(void *session)
{
	Session *s = session;

	if (s == NULL) {
		error("session_xauthfile_cleanup: no session");
		return;
	}

	debug("session_xauthfile_cleanup: session %d removing %s", s->self,
	    s->auth_file);

	if (unlink(s->auth_file) == -1) {
		error("session_xauthfile_cleanup: cannot remove xauth file: "
		    "%.100s", strerror(errno));
		return;
	}

	/* dirname() will modify s->auth_file but that's ok */
	if (rmdir(dirname(s->auth_file)) == -1) {
		error("session_xauthfile_cleanup: "
		    "cannot remove xauth directory: %.100s", strerror(errno));
		return;
	}
}

static char *
sig2name(int sig)
{
#define SSH_SIG(x) if (sig == SIG ## x) return #x
	SSH_SIG(ABRT);
	SSH_SIG(ALRM);
	SSH_SIG(FPE);
	SSH_SIG(HUP);
	SSH_SIG(ILL);
	SSH_SIG(INT);
	SSH_SIG(KILL);
	SSH_SIG(PIPE);
	SSH_SIG(QUIT);
	SSH_SIG(SEGV);
	SSH_SIG(TERM);
	SSH_SIG(USR1);
	SSH_SIG(USR2);
#undef	SSH_SIG
	return "SIG@openssh.com";
}

static void
session_exit_message(Session *s, int status)
{
	Channel *c;

	if ((c = channel_lookup(s->chanid)) == NULL)
		fatal("session_exit_message: session %d: no channel %d",
		    s->self, s->chanid);
	debug("session_exit_message: session %d channel %d pid %ld",
	    s->self, s->chanid, (long)s->pid);

	if (WIFEXITED(status)) {
		channel_request_start(s->chanid, "exit-status", 0);
		packet_put_int(WEXITSTATUS(status));
		packet_send();
	} else if (WIFSIGNALED(status)) {
		channel_request_start(s->chanid, "exit-signal", 0);
		packet_put_cstring(sig2name(WTERMSIG(status)));
#ifdef WCOREDUMP
		packet_put_char(WCOREDUMP(status));
#else /* WCOREDUMP */
		packet_put_char(0);
#endif /* WCOREDUMP */
		packet_put_cstring("");
		packet_put_cstring("");
		packet_send();
	} else {
		/* Some weird exit cause.  Just exit. */
		packet_disconnect("wait returned status %04x.", status);
	}

	/* Ok to close channel now */
	channel_set_wait_for_exit(s->chanid, 0);

	/* disconnect channel */
	debug("session_exit_message: release channel %d", s->chanid);
	channel_cancel_cleanup(s->chanid);
	/*
	 * emulate a write failure with 'chan_write_failed', nobody will be
	 * interested in data we write.
	 * Note that we must not call 'chan_read_failed', since there could
	 * be some more data waiting in the pipe.
	 */
	if (c->ostate != CHAN_OUTPUT_CLOSED)
		chan_write_failed(c);
	s->chanid = -1;
}

void
session_close(Session *s)
{
	debug("session_close: session %d pid %ld", s->self, (long)s->pid);
	if (s->ttyfd != -1) {
		fatal_remove_cleanup(session_pty_cleanup, (void *)s);
		session_pty_cleanup(s);
	}
	if (s->auth_file != NULL) {
		fatal_remove_cleanup(session_xauthfile_cleanup, (void *)s);
		session_xauthfile_cleanup(s);
		xfree(s->auth_file);
	}
	if (s->term)
		xfree(s->term);
	if (s->display)
		xfree(s->display);
	if (s->auth_display)
		xfree(s->auth_display);
	if (s->auth_data)
		xfree(s->auth_data);
	if (s->auth_proto)
		xfree(s->auth_proto);
	if (s->command)
		xfree(s->command);
	session_free_env(&s->env);
	s->used = 0;
	session_proctitle(s);
}

void
session_close_by_pid(pid_t pid, int status)
{
	Session *s = session_by_pid(pid);
	if (s == NULL) {
		debug("session_close_by_pid: no session for pid %ld",
		    (long)pid);
		return;
	}
	if (s->chanid != -1)
		session_exit_message(s, status);
	session_close(s);
}

/*
 * This is called when a channel dies before the session 'child' itself dies.
 * It can happen for example if we exit from an interactive shell before we
 * exit from forwarded X11 applications.
 */
void
session_close_by_channel(int id, void *arg)
{
	Session *s = session_by_channel(id);
	if (s == NULL) {
		debug("session_close_by_channel: no session for id %d", id);
		return;
	}
	debug("session_close_by_channel: channel %d child %ld",
	    id, (long)s->pid);
	if (s->pid != 0) {
		debug("session_close_by_channel: channel %d: has child", id);
		/*
		 * delay detach of session, but release pty, since
		 * the fd's to the child are already closed
		 */
		if (s->ttyfd != -1) {
			fatal_remove_cleanup(session_pty_cleanup, (void *)s);
			session_pty_cleanup(s);
		}
		return;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(s->chanid);
	s->chanid = -1;
	session_close(s);
}

void
session_destroy_all(void (*closefunc)(Session *))
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &sessions[i];
		if (s->used) {
			if (closefunc != NULL)
				closefunc(s);
			else
				session_close(s);
		}
	}
}

static char *
session_tty_list(void)
{
	static char buf[1024];
	int i;
	buf[0] = '\0';
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &sessions[i];
		if (s->used && s->ttyfd != -1) {
			if (buf[0] != '\0')
				strlcat(buf, ",", sizeof buf);
			strlcat(buf, strrchr(s->tty, '/') + 1, sizeof buf);
		}
	}
	if (buf[0] == '\0')
		strlcpy(buf, "notty", sizeof buf);
	return buf;
}

void
session_proctitle(Session *s)
{
	if (s->pw == NULL)
		error("no user for session %d", s->self);
	else
		setproctitle("%s@%s", s->pw->pw_name, session_tty_list());
}

int
session_setup_x11fwd(Session *s)
{
	struct stat st;
	char display[512], auth_display[512];
	char hostname[MAXHOSTNAMELEN];

	if (no_x11_forwarding_flag) {
		packet_send_debug("X11 forwarding disabled in user configuration file.");
		return 0;
	}
	if (!options.x11_forwarding) {
		debug("X11 forwarding disabled in server configuration file.");
		return 0;
	}
	if (!options.xauth_location ||
	    (stat(options.xauth_location, &st) == -1)) {
		packet_send_debug("No xauth program; cannot forward with spoofing.");
		return 0;
	}
	if (s->display != NULL) {
		debug("X11 display already set.");
		return 0;
	}
	if (x11_create_display_inet(options.x11_display_offset,
	    options.x11_use_localhost, s->single_connection,
	    &s->display_number) == -1) {
		debug("x11_create_display_inet failed.");
		return 0;
	}

	/* Set up a suitable value for the DISPLAY variable. */
	if (gethostname(hostname, sizeof(hostname)) < 0)
		fatal("gethostname: %.100s", strerror(errno));
	/*
	 * auth_display must be used as the displayname when the
	 * authorization entry is added with xauth(1).  This will be
	 * different than the DISPLAY string for localhost displays.
	 */
	if (options.x11_use_localhost) {
		snprintf(display, sizeof display, "localhost:%u.%u",
		    s->display_number, s->screen);
		snprintf(auth_display, sizeof auth_display, "unix:%u.%u",
		    s->display_number, s->screen);
		s->display = xstrdup(display);
		s->auth_display = xstrdup(auth_display);
	} else {
#ifdef IPADDR_IN_DISPLAY
		struct hostent *he;
		struct in_addr my_addr;

		he = gethostbyname(hostname);
		if (he == NULL) {
			error("Can't get IP address for X11 DISPLAY.");
			packet_send_debug("Can't get IP address for X11 DISPLAY.");
			return 0;
		}
		memcpy(&my_addr, he->h_addr_list[0], sizeof(struct in_addr));
		snprintf(display, sizeof display, "%.50s:%u.%u", inet_ntoa(my_addr),
		    s->display_number, s->screen);
#else
		snprintf(display, sizeof display, "%.400s:%u.%u", hostname,
		    s->display_number, s->screen);
#endif
		s->display = xstrdup(display);
		s->auth_display = xstrdup(display);
	}

	return 1;
}

#ifdef USE_PAM
int session_do_pam_conv(int, struct pam_message **,
			struct pam_response **, void *);

static struct pam_conv session_pam_conv = {
	session_do_pam_conv,
	NULL
};

static void
session_do_pam(Session *s, int do_open)
{
	int pam_retval;
	char *where, *old_tty, *old_tty_copy = NULL;
	struct pam_conv old_conv, *old_conv_ptr;

	if (!s || !s->authctxt || !s->authctxt->pam || !s->authctxt->pam->h)
		return;

	/* Save current PAM item values */
	where = "getting PAM_CONV";
	pam_retval = pam_get_item(s->authctxt->pam->h, PAM_CONV,
				  (void **) &old_conv_ptr);
	if (pam_retval != PAM_SUCCESS)
		goto done;
	old_conv = *old_conv_ptr;

	where = "getting PAM_TTY";
	pam_retval = pam_get_item(s->authctxt->pam->h, PAM_TTY,
				  (void **) &old_tty);
	if (pam_retval != PAM_SUCCESS)
		goto done;
	old_tty_copy = xstrdup(old_tty);

	/* Change PAM_TTY and PAM_CONV items */
	where = "setting PAM_TTY";
	pam_retval = pam_set_item(s->authctxt->pam->h, PAM_TTY, s->tty);
	if (pam_retval != PAM_SUCCESS)
		goto done;

	where = "setting PAM_CONV";
	session_pam_conv.appdata_ptr = s;
	pam_retval = pam_set_item(s->authctxt->pam->h,
				  PAM_CONV, &session_pam_conv);
	if (pam_retval != PAM_SUCCESS)
		goto done;

	/* Call pam_open/close_session() */
	if (do_open) {
		where = "calling pam_open_session()";
		pam_retval = pam_open_session(s->authctxt->pam->h, 0);
	}
	else {
		where = "calling pam_close_session()";
		pam_retval = pam_close_session(s->authctxt->pam->h, 0);
	}

	/* Reset PAM_TTY and PAM_CONV items to previous values */
	where = "setting PAM_TTY";
	pam_retval = pam_set_item(s->authctxt->pam->h, PAM_TTY, old_tty_copy);
	if (pam_retval != PAM_SUCCESS)
		goto done;

	where = "setting PAM_CONV";
	pam_retval = pam_set_item(s->authctxt->pam->h, PAM_CONV, &old_conv);
	if (pam_retval != PAM_SUCCESS)
		goto done;

	session_pam_conv.appdata_ptr = NULL;

done:
	if (old_tty_copy)
		xfree(old_tty_copy);

	if (pam_retval == PAM_SUCCESS)
		return;

	/* fatal()? probably not... */
	log("PAM failed[%d] while %s: %s", pam_retval, where,
	    PAM_STRERROR(s->authctxt->pam->h, pam_retval));
}

int
session_do_pam_conv(int num_prompts,
		    struct pam_message **prompts,
		    struct pam_response **resp,
		    void *app_data)
{
	Session *s = (Session *) app_data;

	struct pam_response *reply;
	int count;
	char *prompt;

	if (channel_lookup(s->chanid) == NULL)
		return PAM_CONV_ERR;

	/* PAM will free this later */
	reply = xmalloc(num_prompts * sizeof(*reply));

	(void) memset(reply, 0, num_prompts * sizeof(*reply));
	for (count = 0; count < num_prompts; count++) {
		switch(PAM_MSG_MEMBER(prompts, count, msg_style)) {
		case PAM_TEXT_INFO:
			/* Write to stdout of channel */
			prompt = PAM_MSG_MEMBER(prompts, count, msg);
			if (prompt != NULL && s->ttyfd != -1) {
				debug2("session_do_pam_conv: text info "
				       "prompt: %s", prompt);
				(void) write(s->ttyfd, prompt, strlen(prompt));
				(void) write(s->ttyfd, "\n", 1);
			}
			reply[count].resp = xstrdup("");
			reply[count].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_ERROR_MSG:
			/* Write to stderr of channel */
			prompt = PAM_MSG_MEMBER(prompts, count, msg);
			if (prompt != NULL && s->ttyfd != -1) {
				debug2("session_do_pam_conv: error "
				       "prompt: %s", prompt);
				(void) write(s->ttyfd, prompt, strlen(prompt));
				(void) write(s->ttyfd, "\n", 1);
			}
			reply[count].resp = xstrdup("");
			reply[count].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_PROMPT_ECHO_ON:
		case PAM_PROMPT_ECHO_OFF:
		    /*
		     * XXX Someday add support for echo on/off prompts
		     *     here on sessions with ttys.
		     */
		default:
			xfree(reply);
			return PAM_CONV_ERR;
		}
	}

	*resp = reply;

	return PAM_SUCCESS;
}
#endif /* USE_PAM */

static void
do_authenticated2(Authctxt *authctxt)
{
	server_loop2(authctxt);
}

/*
 * Drop the privileges. We need this for the in-process SFTP server only. For
 * the shell and the external subsystem the exec(2) call will do the P = E = I
 * assignment itself. Never change the privileges if the connecting user is
 * root. See privileges(5) if the terminology used here is not known to you.
 */
static void
drop_privs(uid_t uid)
{
	priv_set_t *priv_inherit;

	/* If root is connecting we are done. */
	if (uid == 0)
		return;

	if ((priv_inherit = priv_allocset()) == NULL)
		fatal("priv_allocset: %s", strerror(errno));
	if (getppriv(PRIV_INHERITABLE, priv_inherit) != 0)
		fatal("getppriv: %s", strerror(errno));

	/*
	 * This will limit E as well. Note that before this P was a
	 * superset of I, see permanently_set_uid().
	 */
	if (setppriv(PRIV_SET, PRIV_PERMITTED, priv_inherit) == -1)
		fatal("setppriv: %s", strerror(errno));

	priv_freeset(priv_inherit);

	/*
	 * By manipulating the P set above we entered a PA mode which we
	 * do not need to retain in.
	 */
	if (setpflags(PRIV_AWARE, 0) == -1)
		fatal("setpflags: %s", strerror(errno));
}
