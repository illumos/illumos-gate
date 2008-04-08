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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "includes.h"
#include "atomicio.h"
#include "auth.h"
#include "bufaux.h"
#include "buffer.h"
#include "cipher.h"
#include "compat.h"
#include "dispatch.h"
#include "getput.h"
#include "kex.h"
#include "log.h"
#include "mac.h"
#include "packet.h"
#include "uidswap.h"
#include "ssh2.h"
#include "sshlogin.h"
#include "xmalloc.h"
#include "altprivsep.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

extern Kex *xxx_kex;

static Buffer to_monitor;
static Buffer from_monitor;

/*
 * Sun's Alternative Privilege Separation basics:
 *
 * Abstract
 * --------
 *
 * sshd(1M) fork()s and drops privs in the child while retaining privs
 * in the parent (a.k.a., the monitor).  The unprivileged sshd and the
 * monitor talk over a pipe using a simple protocol.
 *
 * The monitor protocol is all about having the monitor carry out the
 * only operations that require privileges OR access to privileged
 * resources.  These are: utmpx/wtmpx record keeping, auditing, and
 * SSHv2 re-keying.
 *
 * Re-Keying
 * ---------
 *
 * Re-keying is the only protocol version specific aspect of sshd in
 * which the monitor gets involved.
 *
 * The monitor processes all SSHv2 re-key protocol packets, but the
 * unprivileged sshd process does the transport layer crypto for those
 * packets.
 *
 * The monitor and its unprivileged sshd child process treat
 * SSH_MSG_NEWKEYS SSH2 messages specially: a) the monitor does not call
 * set_newkeys(), but b) the child asks the monitor for the set of
 * negotiated algorithms, key, IV and what not for the relevant
 * transport direction and then calls set_newkeys().
 *
 * Monitor Protocol
 * ----------------
 *
 * Monitor IPC message formats are similar to SSHv2 messages, minus
 * compression, encryption, padding and MACs:
 *
 *  - 4 octet message length
 *  - message data
 *     - 1 octet message type
 *     - message data
 *
 * In broad strokes:
 *
 *  - IPC: pipe, exit(2)/wait4(2)
 *
 *  - threads: the monitor and child are single-threaded
 *
 *  - monitor main loop: a variant of server_loop2(), for re-keying only
 *  - unpriv child main loop: server_loop2(), as usual
 *
 *  - protocol:
 *     - key exchange packets are always forwarded as is to the monitor
 *     - newkeys, record_login(), record_logout() are special packets
 *     using the packet type range reserved for local extensions
 *
 *  - the child drops privs and runs like a normal sshd, except that it
 *  sets dispatch handlers for key exchange packets that forward the
 *  packets to the monitor
 *
 * Event loops:
 *
 *  - all monitor protocols are synchronous: because the SSHv2 rekey
 *  protocols are synchronous and because the other monitor operations
 *  are synchronous (or have no replies),
 *
 *  - server_loop2() is modified to check the monitor pipe for rekey
 *  packets to forward to the client
 *
 *  - and dispatch handlers are set, upon receipt of KEXINIT (and reset
 *  when NEWKEYS is sent out) to forward incoming rekey packets to the
 *  monitor.
 *
 *  - the monitor runs an event loop not unlike server_loop2() and runs
 *  key exchanges almost exactly as a pre-altprivsep sshd would
 *
 *  - unpriv sshd exit -> monitor cleanup (including audit logout) and exit
 *
 *  - fatal() in monitor -> forcibly shutdown() socket and kill/wait for
 *  child (so that the audit event for the logout better reflects
 *  reality -- i.e., logged out means logged out, but for bg jobs)
 *
 * Message formats:
 *
 *  - key exchange packets/replies forwarded "as is"
 *
 *  - all other monitor requests are sent as SSH2_PRIV_MSG_ALTPRIVSEP and have a
 *  sub-type identifier (one octet)
 *  - private request sub-types include:
 *     - get new shared secret from last re-key
 *     - record login  (utmpx/wtmpx), request data contains three arguments:
 *     pid, ttyname, program name
 *     - record logout (utmpx/wtmpx), request data contains one argument: pid
 *
 * Reply sub-types include:
 *
 *  - NOP (for record_login/logout)
 *  - new shared secret from last re-key
 */

static int aps_started = 0;
static int is_monitor = 0;

static pid_t monitor_pid, child_pid;
static int pipe_fds[2];
static int pipe_fd = -1;
static Buffer input_pipe, output_pipe; /* for pipe I/O */

static Authctxt *xxx_authctxt;

/* Monitor functions */
extern void aps_monitor_loop(Authctxt *authctxt, int pipe, pid_t child_pid);
static void aps_record_login(void);
static void aps_record_logout(void);
static void aps_start_rekex(void);

/* Altprivsep packet utilities for communication with the monitor */
static void	altprivsep_packet_start(u_char);
static int	altprivsep_packet_send(void);
static int	altprivsep_fwd_packet(u_char type);

static int	altprivsep_packet_read(void);
static void	altprivsep_packet_read_expect(int type);

static void	altprivsep_packet_put_char(int ch);
static void	altprivsep_packet_put_int(u_int value);
static void	altprivsep_packet_put_cstring(const char *str);
static void	altprivsep_packet_put_raw(const void *buf, u_int len);

static u_int	 altprivsep_packet_get_char(void);
static void	*altprivsep_packet_get_raw(u_int *length_ptr);
static void	*altprivsep_packet_get_string(u_int *length_ptr);

/*
 * Start monitor from privileged sshd process.
 *
 * Return values are like fork(2); the parent is the monitor.  The caller should
 * fatal() on error.
 *
 * Privileges are dropped, on the unprivileged side, upon success.
 */
pid_t
altprivsep_start_monitor(Authctxt *authctxt)
{
	pid_t pid;
	int junk;

	if (aps_started || authctxt == NULL || authctxt->pw == NULL)
		fatal("Monitor startup failed: missing state");

	xxx_authctxt = authctxt;

	packet_set_server();

	buffer_init(&output_pipe);
	buffer_init(&input_pipe);

	if (pipe(pipe_fds) != 0) {
		error("Monitor startup failure: could not create pipes: %s",
			strerror(errno));
		return (-1);
	}

	(void) fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC);
	(void) fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

	monitor_pid = getpid();

	if ((pid = fork()) > 0) {
		/* parent */
		child_pid = pid;

		debug2("Monitor pid %ld, unprivileged child pid %ld",
			monitor_pid, child_pid);

		(void) close(pipe_fds[1]);

		pipe_fd = pipe_fds[0];

		if (fcntl(pipe_fd, F_SETFL, O_NONBLOCK) < 0)
			error("fcntl O_NONBLOCK: %.100s", strerror(errno));

		/* signal readiness of monitor */
		(void) write(pipe_fd, &pid, sizeof (pid));

		aps_started = 1;
		is_monitor = 1;

		debug2("Monitor started");

		set_log_txt_prefix("monitor ");

		return (pid);

	}

	if (pid < 0) {
		debug2("Monitor startup failure: could not fork unprivileged"
			" process:  %s", strerror(errno));
		return (pid);
	}

	/* caller should drop privs */

	(void) close(pipe_fds[0]);

	pipe_fd = pipe_fds[1];

	/* wait for monitor to be ready */
	debug2("Waiting for monitor");
	(void) read(pipe_fd, &junk, sizeof (junk));
	debug2("Monitor signalled readiness");

	if (fcntl(pipe_fd, F_SETFL, O_NONBLOCK) < 0)
		error("fcntl O_NONBLOCK: %.100s", strerror(errno));

	buffer_init(&to_monitor);
	buffer_init(&from_monitor);

	if (compat20) {
		debug3("Setting handler to forward re-key packets to monitor");
		dispatch_range(SSH2_MSG_KEXINIT, SSH2_MSG_TRANSPORT_MAX,
			&altprivsep_rekey);
	}

	/* AltPrivSep interfaces are set up */
	aps_started = 1;
	return (pid);
}

int
altprivsep_get_pipe_fd(void)
{
	return (pipe_fd);
}

void
altprivsep_rekey(int type, u_int32_t seq, void *ctxt)
{
	Kex *kex = (Kex *)ctxt;

	if (kex == NULL)
		fatal("Missing key exchange context in unprivileged process");

	debug2("Forwarding re-key packet (%d) to monitor", type);

	if (type != SSH2_MSG_NEWKEYS)
		if (!altprivsep_fwd_packet(type))
			fatal("Monitor not responding");

	/* tell server_loop2() that we're re-keying */
	kex->done = 0;

	/* NEWKEYS is special: get the new keys for client->server direction */
	if (type == SSH2_MSG_NEWKEYS) {
		debug2("Getting new inbound keystate from monitor");
		altprivsep_get_newkeys(MODE_IN);
		kex->done = 1;
	}
}

void
altprivsep_process_input(fd_set *rset)
{
	void	*data;
	int	 type;
	u_int	 dlen;

	debug2("Reading from pipe to monitor (%d)", pipe_fd);

	if (pipe_fd == -1)
		return;

	if (!FD_ISSET(pipe_fd, rset))
		return;

	if ((type = altprivsep_packet_read()) == -1)
		fatal("Monitor not responding");

	if (!compat20)
		return; /* shouldn't happen! but be safe */

	if (type == 0)
		return;	/* EOF -- nothing to do here */

	if (type >= SSH2_MSG_MAX)
		fatal("Received garbage from monitor");

	debug2("Read packet type %d from pipe to monitor", (u_int)type);

	if (type == SSH2_PRIV_MSG_ALTPRIVSEP)
		return; /* shouldn't happen! */

	/* NEWKEYS is special: get the new keys for server->client direction */
	if (type == SSH2_MSG_NEWKEYS) {
		debug2("Getting new outbound keystate from monitor");
		packet_start(SSH2_MSG_NEWKEYS);
		packet_send();
		altprivsep_get_newkeys(MODE_OUT);
		return;
	}

	data = altprivsep_packet_get_raw(&dlen);

	packet_start((u_char)type);

	if (data != NULL && dlen > 0)
		packet_put_raw(data, dlen);

	packet_send();
}

void
altprivsep_do_monitor(Authctxt *authctxt, pid_t child_pid)
{
	aps_monitor_loop(authctxt, pipe_fd, child_pid);
}

int
altprivsep_started(void)
{
	return (aps_started);
}

int
altprivsep_is_monitor(void)
{
	return (is_monitor);
}

/*
 * A fatal cleanup function to forcibly shutdown the connection socket
 */
void
altprivsep_shutdown_sock(void *arg)
{
	int sock;

	if (arg == NULL)
		return;

	sock = *(int *)arg;

	(void) shutdown(sock, SHUT_RDWR);
}

/* Calls _to_ monitor from unprivileged process */
static
int
altprivsep_fwd_packet(u_char type)
{
	u_int len;
	void  *data;

	altprivsep_packet_start(type);
	data = packet_get_raw(&len);
	altprivsep_packet_put_raw(data, len);

	/* packet_send()s any replies from the monitor to the client */
	return (altprivsep_packet_send());
}

extern Newkeys *current_keys[MODE_MAX];

/* To be called from packet.c:set_newkeys() before referencing current_keys */
void
altprivsep_get_newkeys(enum kex_modes mode)
{
	Newkeys	*newkeys;
	Comp	*comp;
	Enc	*enc;
	Mac	*mac;
	u_int	 len;

	if (!altprivsep_started())
		return;

	if (altprivsep_is_monitor())
		return; /* shouldn't happen */

	/* request new keys */
	altprivsep_packet_start(SSH2_PRIV_MSG_ALTPRIVSEP);
	altprivsep_packet_put_char(APS_MSG_NEWKEYS_REQ);
	altprivsep_packet_put_int((u_int)mode);
	altprivsep_packet_send();
	altprivsep_packet_read_expect(SSH2_PRIV_MSG_ALTPRIVSEP);
	if (altprivsep_packet_get_char() != APS_MSG_NEWKEYS_REP)
		fatal("Received garbage from monitor during re-keying");

	newkeys = xmalloc(sizeof (*newkeys));
	memset(newkeys, 0, sizeof (*newkeys));

	enc = &newkeys->enc;
	mac = &newkeys->mac;
	comp = &newkeys->comp;

	/* Cipher name, key, IV */
	enc->name = altprivsep_packet_get_string(NULL);
	if ((enc->cipher = cipher_by_name(enc->name)) == NULL)
		fatal("Monitor negotiated an unknown cipher during re-key");

	enc->key = altprivsep_packet_get_string(&enc->key_len);
	enc->iv = altprivsep_packet_get_string(&enc->block_size);

	/* MAC name */
	mac->name = altprivsep_packet_get_string(NULL);
	if (mac_init(mac, mac->name) < 0)
		fatal("Monitor negotiated an unknown MAC algorithm "
			"during re-key");

	mac->key = altprivsep_packet_get_string(&len);
	if (len > mac->key_len)
		fatal("%s: bad mac key length: %d > %d", __func__, len,
			mac->key_len);

	/* Compression algorithm name */
	comp->name = altprivsep_packet_get_string(NULL);
	if (strcmp(comp->name, "zlib") != 0 && strcmp(comp->name, "none") != 0)
		fatal("Monitor negotiated an unknown compression "
			"algorithm during re-key");

	comp->type = 0;
	comp->enabled = 0; /* forces compression re-init, as per-spec */
	if (strcmp(comp->name, "zlib") == 0)
		comp->type = 1;

	/*
	 * Now install new keys
	 *
	 * For now abuse kex.c/packet.c non-interfaces.  Someday, when
	 * the many internal interfaces are parametrized, made reentrant
	 * and thread-safe, made more consistent, and when necessary-but-
	 * currently-missing interfaces are added then this bit of
	 * ugliness can be revisited.
	 *
	 * The ugliness is in the set_newkeys(), its name and the lack
	 * of a (Newkeys *) parameter, which forces us to pass the
	 * newkeys through current_keys[mode].  But this saves us some
	 * lines of code for now, though not comments.
	 *
	 * Also, we've abused, in the code above, knowledge of what
	 * set_newkeys() expects the current_keys[mode] to contain.
	 */
	current_keys[mode] = newkeys;
	set_newkeys(mode);

}

void
altprivsep_record_login(pid_t pid, const char *ttyname)
{
	altprivsep_packet_start(SSH2_PRIV_MSG_ALTPRIVSEP);
	altprivsep_packet_put_char(APS_MSG_RECORD_LOGIN);
	altprivsep_packet_put_int(pid);
	altprivsep_packet_put_cstring(ttyname);
	altprivsep_packet_send();
	altprivsep_packet_read_expect(SSH2_PRIV_MSG_ALTPRIVSEP);
}

void
altprivsep_record_logout(pid_t pid)
{
	altprivsep_packet_start(SSH2_PRIV_MSG_ALTPRIVSEP);
	altprivsep_packet_put_char(APS_MSG_RECORD_LOGOUT);
	altprivsep_packet_put_int(pid);
	altprivsep_packet_send();
	altprivsep_packet_read_expect(SSH2_PRIV_MSG_ALTPRIVSEP);
}

void
altprivsep_start_rekex(void)
{
	altprivsep_packet_start(SSH2_PRIV_MSG_ALTPRIVSEP);
	altprivsep_packet_put_char(APS_MSG_START_REKEX);
	altprivsep_packet_send();
	altprivsep_packet_read_expect(SSH2_PRIV_MSG_ALTPRIVSEP);
}

static void aps_send_newkeys(void);

/* Monitor side dispatch handler for SSH2_PRIV_MSG_ALTPRIVSEP */
/* ARGSUSED */
void
aps_input_altpriv_msg(int type, u_int32_t seq, void *ctxt)
{
	u_char req_type;

	req_type = packet_get_char();

	switch (req_type) {
	case APS_MSG_NEWKEYS_REQ:
		aps_send_newkeys();
		break;
	case APS_MSG_RECORD_LOGIN:
		aps_record_login();
		break;
	case APS_MSG_RECORD_LOGOUT:
		aps_record_logout();
		break;
	case APS_MSG_START_REKEX:
		aps_start_rekex();
		break;
	default:
		break;
	}
}

/* Monitor-side handlers for APS_MSG_* */
static
void
aps_send_newkeys(void)
{
	Newkeys *newkeys;
	Enc *enc;
	Mac *mac;
	Comp *comp;
	enum kex_modes mode;

	/* get direction for which newkeys are wanted */
	mode = (enum kex_modes) packet_get_int();
	packet_check_eom();

	/* get those newkeys */
	newkeys = kex_get_newkeys(mode);
	enc = &newkeys->enc;
	mac = &newkeys->mac;
	comp = &newkeys->comp;

	/*
	 * Negotiated algorithms, client->server and server->client, for
	 * cipher, mac and compression.
	 */
	packet_start(SSH2_PRIV_MSG_ALTPRIVSEP);
	packet_put_char(APS_MSG_NEWKEYS_REP);
	packet_put_cstring(enc->name);
	packet_put_string(enc->key, enc->key_len);
	packet_put_string(enc->iv, enc->block_size);
	packet_put_cstring(mac->name);
	packet_put_string(mac->key, mac->key_len);
	packet_put_cstring(comp->name);

	packet_send();
	free_keys(newkeys);
}

struct _aps_login_rec {
	pid_t			lr_pid;
	char			*lr_tty;
	struct _aps_login_rec	*next;
};

typedef struct _aps_login_rec aps_login_rec;

static aps_login_rec *aps_login_list = NULL;

static
void
aps_record_login(void)
{
	aps_login_rec	*new_rec;
	struct stat	 sbuf;
	size_t		 proc_path_len;
	char		*proc_path;

	new_rec = xmalloc(sizeof (aps_login_rec));
	memset(new_rec, 0, sizeof (aps_login_rec));

	new_rec->lr_pid = packet_get_int();
	new_rec->lr_tty = packet_get_string(NULL);

	proc_path_len = snprintf(NULL, 0, "/proc/%d", new_rec->lr_pid);
	proc_path = xmalloc(proc_path_len + 1);
	(void) snprintf(proc_path, proc_path_len + 1, "/proc/%d",
			new_rec->lr_pid);

	if (stat(proc_path, &sbuf) ||
	    sbuf.st_uid != xxx_authctxt->pw->pw_uid ||
	    stat(new_rec->lr_tty, &sbuf) < 0 ||
	    sbuf.st_uid != xxx_authctxt->pw->pw_uid) {
		debug2("Spurious record_login request from unprivileged sshd");
		xfree(proc_path);
		xfree(new_rec->lr_tty);
		xfree(new_rec);
		return;
	}

	/* Insert new record on list */
	new_rec->next = aps_login_list;
	aps_login_list = new_rec;

	record_login(new_rec->lr_pid, new_rec->lr_tty, NULL,
		xxx_authctxt->user);

	packet_start(SSH2_PRIV_MSG_ALTPRIVSEP);
	packet_send();

	xfree(proc_path);
}

static
void
aps_record_logout(void)
{
	aps_login_rec	**p, *q;
	pid_t		 pid;

	pid = packet_get_int();
	packet_check_eom();

	for (p = &aps_login_list; *p != NULL; p = &q->next) {
		q = *p;
		if (q->lr_pid == pid) {
			record_logout(q->lr_pid, q->lr_tty, NULL,
				xxx_authctxt->user);

			/* dequeue */
			*p = q->next;
			xfree(q->lr_tty);
			xfree(q);
			break;
		}
	}

	packet_start(SSH2_PRIV_MSG_ALTPRIVSEP);
	packet_send();
}

static
void
aps_start_rekex(void)
{
	/*
	 * Send confirmation. We could implement it without that but it doesn't
	 * bring any harm to do that and we are consistent with other subtypes
	 * of our private SSH2_PRIV_MSG_ALTPRIVSEP message type.
	 */
	packet_start(SSH2_PRIV_MSG_ALTPRIVSEP);
	packet_send();

	/*
	 * KEX_INIT message could be the one that reached the limit. In that
	 * case, it was already forwarded to us from the unnprivileged child,
	 * and maybe even acted upon. Obviously we must not send another
	 * KEX_INIT message.
	 */
	if (!(xxx_kex->flags & KEX_INIT_SENT))
		kex_send_kexinit(xxx_kex);
	else
		debug2("rekeying already in progress");
}


/* Utilities for communication with the monitor */
static
void
altprivsep_packet_start(u_char type)
{
	buffer_clear(&to_monitor);
	buffer_put_char(&to_monitor, type);
}
static
void
altprivsep_packet_put_char(int ch)
{
	buffer_put_char(&to_monitor, ch);
}
static
void
altprivsep_packet_put_int(u_int value)
{
	buffer_put_int(&to_monitor, value);
}
static
void
altprivsep_packet_put_cstring(const char *str)
{
	buffer_put_cstring(&to_monitor, str);
}
static
void
altprivsep_packet_put_raw(const void *buf, u_int len)
{
	buffer_append(&to_monitor, buf, len);
}

/*
 * Send a monitor packet to the monitor.  This function is blocking.
 *
 * Returns -1 if the monitor pipe has been closed earlier, fatal()s if
 * there's any other problems.
 */
static
int
altprivsep_packet_send(void)
{
	ssize_t len;
	u_int32_t plen;	/* packet length */
	u_char	plen_buf[sizeof (plen)];
	u_char padlen;	/* padding length */
	fd_set *setp;

	if (pipe_fd == -1)
		return (-1);

	if ((plen = buffer_len(&to_monitor)) == 0)
		return (0);

	/*
	 * We talk the SSHv2 binary packet protocol to the monitor,
	 * using the none cipher, mac and compression algorithms.
	 *
	 * But, interestingly, the none cipher has a block size of 8
	 * bytes, thus we must pad the packet.
	 *
	 * Also, encryption includes the packet length, so the padding
	 * must account for that field.  I.e., (sizeof (packet length) +
	 * sizeof (padding length) + packet length + padding length) %
	 * block_size must == 0.
	 *
	 * Also, there must be at least four (4) bytes of padding.
	 */
	padlen = (8 - ((plen + sizeof (plen) + sizeof (padlen)) % 8)) % 8;
	if (padlen < 4)
		padlen += 8;

	/* packet length counts padding and padding length field */
	plen += padlen + sizeof (padlen);

	PUT_32BIT(plen_buf, plen);

	setp = xmalloc(howmany(pipe_fd + 1, NFDBITS) * sizeof (fd_mask));
	memset(setp, 0, howmany(pipe_fd + 1, NFDBITS) * sizeof (fd_mask));
	FD_SET(pipe_fd, setp);

	while (select(pipe_fd + 1, NULL, setp, NULL, NULL) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		else
			goto pipe_gone;
	}

	xfree(setp);

	/* packet length field */
	len = atomicio(write, pipe_fd, plen_buf, sizeof (plen));

	if (len != sizeof (plen))
		goto pipe_gone;

	/* padding length field */
	len = atomicio(write, pipe_fd, &padlen, sizeof (padlen));

	if (len != sizeof (padlen))
		goto pipe_gone;

	len = atomicio(write, pipe_fd, buffer_ptr(&to_monitor), plen - 1);

	if (len != (plen - 1))
		goto pipe_gone;

	buffer_clear(&to_monitor);

	return (1);

pipe_gone:

	(void) close(pipe_fd);

	pipe_fd = -1;

	fatal("Monitor not responding");

	/* NOTREACHED */
	return (0);
}

/*
 * Read a monitor packet from the monitor.  This function is blocking.
 */
static
int
altprivsep_packet_read(void)
{
	ssize_t len = -1;
	u_int32_t plen;
	u_char plen_buf[sizeof (plen)];
	u_char padlen;
	fd_set *setp;

	if (pipe_fd == -1)
		return (-1);

	setp = xmalloc(howmany(pipe_fd + 1, NFDBITS) * sizeof (fd_mask));
	memset(setp, 0, howmany(pipe_fd + 1, NFDBITS) * sizeof (fd_mask));
	FD_SET(pipe_fd, setp);

	while (select(pipe_fd + 1, setp, NULL, NULL, NULL) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		else
			goto pipe_gone;
	}

	xfree(setp);

	/* packet length field */
	len = atomicio(read, pipe_fd, plen_buf, sizeof (plen));

	plen = GET_32BIT(plen_buf);

	if (len != sizeof (plen))
		goto pipe_gone;

	/* padding length field */
	len = atomicio(read, pipe_fd, &padlen, sizeof (padlen));

	if (len != sizeof (padlen))
		goto pipe_gone;

	plen -= sizeof (padlen);

	buffer_clear(&from_monitor);
	buffer_append_space(&from_monitor, plen);

	/* packet data + padding */
	len = atomicio(read, pipe_fd, buffer_ptr(&from_monitor), plen);

	if (len != plen)
		goto pipe_gone;

	/* remove padding */
	if (padlen > 0)
		buffer_consume_end(&from_monitor, padlen);

	/* packet type */
	return (buffer_get_char(&from_monitor));

pipe_gone:

	(void) close(pipe_fd);

	pipe_fd = -1;

	if (len < 0)
		fatal("Monitor not responding");

	debug2("Monitor pipe closed by monitor");
	return (0);
}

static
void
altprivsep_packet_read_expect(int expected)
{
	int type;

	type = altprivsep_packet_read();

	if (type <= 0)
		fatal("Monitor not responding");

	if (type != expected)
		fatal("Protocol error in privilege separation; expected "
			"packet type %d, got %d", expected, type);
}

static
u_int
altprivsep_packet_get_char(void)
{
	return (buffer_get_char(&from_monitor));
}
void
*altprivsep_packet_get_raw(u_int *length_ptr)
{
	if (length_ptr != NULL)
		*length_ptr = buffer_len(&from_monitor);

	return (buffer_ptr(&from_monitor));
}
void
*altprivsep_packet_get_string(u_int *length_ptr)
{
	return (buffer_get_string(&from_monitor, length_ptr));
}
