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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <netinet/in.h>		/* struct in_addr */
#include <netinet/dhcp.h>
#include <signal.h>
#include <sys/dlpi.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <errno.h>
#include <net/route.h>
#include <net/if_arp.h>
#include <string.h>
#include <dhcpmsg.h>
#include <ctype.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>

#include "states.h"
#include "agent.h"
#include "interface.h"
#include "util.h"
#include "packet.h"
#include "defaults.h"

/*
 * this file contains utility functions that have no real better home
 * of their own.  they can largely be broken into six categories:
 *
 *  o  conversion functions -- functions to turn integers into strings,
 *     or to convert between units of a similar measure.
 *
 *  o  ipc-related functions -- functions to simplify the generation of
 *     ipc messages to the agent's clients.
 *
 *  o  signal-related functions -- functions to clean up the agent when
 *     it receives a signal.
 *
 *  o  routing table manipulation functions
 *
 *  o  acknak handler functions
 *
 *  o  true miscellany -- anything else
 */

/*
 * pkt_type_to_string(): stringifies a packet type
 *
 *   input: uchar_t: a DHCP packet type value, as defined in RFC2131
 *  output: const char *: the stringified packet type
 */

const char *
pkt_type_to_string(uchar_t type)
{
	/*
	 * note: the ordering here allows direct indexing of the table
	 *	 based on the RFC2131 packet type value passed in.
	 */

	static const char *types[] = {
		"BOOTP",  "DISCOVER", "OFFER",   "REQUEST", "DECLINE",
		"ACK",    "NAK",      "RELEASE", "INFORM"
	};

	if (type >= (sizeof (types) / sizeof (*types)) || types[type] == NULL)
		return ("<unknown>");

	return (types[type]);
}

/*
 * dlpi_to_arp(): converts DLPI datalink types into ARP datalink types
 *
 *   input: uchar_t: the DLPI datalink type
 *  output: uchar_t: the ARP datalink type (0 if no corresponding code)
 */

uchar_t
dlpi_to_arp(uchar_t dlpi_type)
{
	switch (dlpi_type) {

	case DL_ETHER:
		return (1);

	case DL_FRAME:
		return (15);

	case DL_ATM:
		return (16);

	case DL_HDLC:
		return (17);

	case DL_FC:
		return (18);

	case DL_CSMACD:				/* ieee 802 networks */
	case DL_TPB:
	case DL_TPR:
	case DL_METRO:
	case DL_FDDI:
		return (6);
	case DL_IB:
		return (ARPHRD_IB);
	}

	return (0);
}

/*
 * monosec_to_string(): converts a monosec_t into a date string
 *
 *   input: monosec_t: the monosec_t to convert
 *  output: const char *: the corresponding date string
 */

const char *
monosec_to_string(monosec_t monosec)
{
	time_t	time = monosec_to_time(monosec);
	char	*time_string = ctime(&time);

	/* strip off the newline -- ugh, why, why, why.. */
	time_string[strlen(time_string) - 1] = '\0';
	return (time_string);
}

/*
 * monosec(): returns a monotonically increasing time in seconds that
 *            is not affected by stime(2) or adjtime(2).
 *
 *   input: void
 *  output: monosec_t: the number of seconds since some time in the past
 */

monosec_t
monosec(void)
{
	return (gethrtime() / NANOSEC);
}

/*
 * monosec_to_time(): converts a monosec_t into real wall time
 *
 *    input: monosec_t: the absolute monosec_t to convert
 *   output: time_t: the absolute time that monosec_t represents in wall time
 */

time_t
monosec_to_time(monosec_t abs_monosec)
{
	return (abs_monosec - monosec()) + time(NULL);
}

/*
 * send_ok_reply(): sends an "ok" reply to a request and closes the ipc
 *		    connection
 *
 *   input: dhcp_ipc_request_t *: the request to reply to
 *	    int *: the ipc connection file descriptor (set to -1 on return)
 *  output: void
 *    note: the request is freed (thus the request must be on the heap).
 */

void
send_ok_reply(dhcp_ipc_request_t *request, int *control_fd)
{
	send_error_reply(request, 0, control_fd);
}

/*
 * send_error_reply(): sends an "error" reply to a request and closes the ipc
 *		       connection
 *
 *   input: dhcp_ipc_request_t *: the request to reply to
 *	    int: the error to send back on the ipc connection
 *	    int *: the ipc connection file descriptor (set to -1 on return)
 *  output: void
 *    note: the request is freed (thus the request must be on the heap).
 */

void
send_error_reply(dhcp_ipc_request_t *request, int error, int *control_fd)
{
	send_data_reply(request, control_fd, error, DHCP_TYPE_NONE, NULL, NULL);
}

/*
 * send_data_reply(): sends a reply to a request and closes the ipc connection
 *
 *   input: dhcp_ipc_request_t *: the request to reply to
 *	    int *: the ipc connection file descriptor (set to -1 on return)
 *	    int: the status to send back on the ipc connection (zero for
 *		 success, DHCP_IPC_E_* otherwise).
 *	    dhcp_data_type_t: the type of the payload in the reply
 *	    void *: the payload for the reply, or NULL if there is no payload
 *	    size_t: the size of the payload
 *  output: void
 *    note: the request is freed (thus the request must be on the heap).
 */

void
send_data_reply(dhcp_ipc_request_t *request, int *control_fd,
    int error, dhcp_data_type_t type, void *buffer, size_t size)
{
	dhcp_ipc_reply_t	*reply;

	if (*control_fd == -1)
		return;

	reply = dhcp_ipc_alloc_reply(request, error, buffer, size, type);
	if (reply == NULL)
		dhcpmsg(MSG_ERR, "send_data_reply: cannot allocate reply");

	else if (dhcp_ipc_send_reply(*control_fd, reply) != 0)
		dhcpmsg(MSG_ERR, "send_data_reply: dhcp_ipc_send_reply");

	/*
	 * free the request since we've now used it to send our reply.
	 * we can also close the socket since the reply has been sent.
	 */

	free(reply);
	free(request);
	(void) dhcp_ipc_close(*control_fd);
	*control_fd = -1;
}

/*
 * print_server_msg(): prints a message from a DHCP server
 *
 *   input: struct ifslist *: the interface the message came in on
 *	    DHCP_OPT *: the option containing the string to display
 *  output: void
 */

void
print_server_msg(struct ifslist *ifsp, DHCP_OPT *p)
{
	dhcpmsg(MSG_INFO, "%s: message from server: %.*s", ifsp->if_name,
	    p->len, p->value);
}

/*
 * alrm_exit(): Signal handler for SIGARLM. terminates grandparent.
 *
 *    input: int: signal the handler was called with.
 *
 *   output: void
 */

static void
alrm_exit(int sig)
{
	int exitval;

	if (sig == SIGALRM && grandparent != 0)
		exitval = EXIT_SUCCESS;
	else
		exitval = EXIT_FAILURE;

	_exit(exitval);
}

/*
 * daemonize(): daemonizes the process
 *
 *   input: void
 *  output: int: 1 on success, 0 on failure
 */

int
daemonize(void)
{
	/*
	 * We've found that adoption takes sufficiently long that
	 * a dhcpinfo run after dhcpagent -a is started may occur
	 * before the agent is ready to process the request.
	 * The result is an error message and an unhappy user.
	 *
	 * The initial process now sleeps for DHCP_ADOPT_SLEEP,
	 * unless interrupted by a SIGALRM, in which case it
	 * exits immediately. This has the effect that the
	 * grandparent doesn't exit until the dhcpagent is ready
	 * to process requests. This defers the the balance of
	 * the system start-up script processing until the
	 * dhcpagent is ready to field requests.
	 *
	 * grandparent is only set for the adopt case; other
	 * cases do not require the wait.
	 */

	if (grandparent != 0)
		(void) signal(SIGALRM, alrm_exit);

	switch (fork()) {

	case -1:
		return (0);

	case  0:
		if (grandparent != 0)
			(void) signal(SIGALRM, SIG_DFL);

		/*
		 * setsid() makes us lose our controlling terminal,
		 * and become both a session leader and a process
		 * group leader.
		 */

		(void) setsid();

		/*
		 * under POSIX, a session leader can accidentally
		 * (through open(2)) acquire a controlling terminal if
		 * it does not have one.  just to be safe, fork again
		 * so we are not a session leader.
		 */

		switch (fork()) {

		case -1:
			return (0);

		case 0:
			(void) signal(SIGHUP, SIG_IGN);
			(void) chdir("/");
			(void) umask(022);
			closefrom(0);
			break;

		default:
			_exit(EXIT_SUCCESS);
		}
		break;

	default:
		if (grandparent != 0) {
			(void) signal(SIGCHLD, SIG_IGN);
			dhcpmsg(MSG_DEBUG, "dhcpagent: daemonize: "
			    "waiting for adoption to complete.");
			if (sleep(DHCP_ADOPT_SLEEP) == 0) {
				dhcpmsg(MSG_WARNING, "dhcpagent: daemonize: "
				    "timed out awaiting adoption.");
			}
		}
		_exit(EXIT_SUCCESS);
	}

	return (1);
}

/*
 * update_default_route(): update the interface's default route
 *
 *   input: int: the type of message; either RTM_ADD or RTM_DELETE
 *	    struct in_addr: the default gateway to use
 *	    const char *: the interface associated with the route
 *	    int: any additional flags (besides RTF_STATIC and RTF_GATEWAY)
 *  output: int: 1 on success, 0 on failure
 */

static int
update_default_route(const char *ifname, int type, struct in_addr *gateway_nbo,
    int flags)
{
	static int rtsock_fd = -1;
	struct {
		struct rt_msghdr	rm_mh;
		struct sockaddr_in	rm_dst;
		struct sockaddr_in	rm_gw;
		struct sockaddr_in	rm_mask;
		struct sockaddr_dl	rm_ifp;
	} rtmsg;

	if (rtsock_fd == -1) {
		rtsock_fd = socket(PF_ROUTE, SOCK_RAW, 0);
		if (rtsock_fd == -1) {
			dhcpmsg(MSG_ERR, "update_default_route: "
			    "cannot create routing socket");
			return (0);
		}
	}

	(void) memset(&rtmsg, 0, sizeof (rtmsg));
	rtmsg.rm_mh.rtm_version = RTM_VERSION;
	rtmsg.rm_mh.rtm_msglen	= sizeof (rtmsg);
	rtmsg.rm_mh.rtm_type	= type;
	rtmsg.rm_mh.rtm_pid	= getpid();
	rtmsg.rm_mh.rtm_flags	= RTF_GATEWAY | RTF_STATIC | flags;
	rtmsg.rm_mh.rtm_addrs	= RTA_GATEWAY | RTA_DST | RTA_NETMASK | RTA_IFP;

	rtmsg.rm_gw.sin_family	= AF_INET;
	rtmsg.rm_gw.sin_addr	= *gateway_nbo;

	rtmsg.rm_dst.sin_family = AF_INET;
	rtmsg.rm_dst.sin_addr.s_addr = htonl(INADDR_ANY);

	rtmsg.rm_mask.sin_family = AF_INET;
	rtmsg.rm_mask.sin_addr.s_addr = htonl(0);

	rtmsg.rm_ifp.sdl_family	= AF_LINK;
	rtmsg.rm_ifp.sdl_index	= if_nametoindex(ifname);

	return (write(rtsock_fd, &rtmsg, sizeof (rtmsg)) == sizeof (rtmsg));
}

/*
 * add_default_route(): add the default route to the given gateway
 *
 *   input: const char *: the name of the interface associated with the route
 *	    struct in_addr: the default gateway to add
 *  output: int: 1 on success, 0 on failure
 */

int
add_default_route(const char *ifname, struct in_addr *gateway_nbo)
{
	if (strchr(ifname, ':') != NULL)	/* see README */
		return (1);

	return (update_default_route(ifname, RTM_ADD, gateway_nbo, RTF_UP));
}

/*
 * del_default_route(): deletes the default route to the given gateway
 *
 *   input: const char *: the name of the interface associated with the route
 *	    struct in_addr: if not INADDR_ANY, the default gateway to remove
 *  output: int: 1 on success, 0 on failure
 */

int
del_default_route(const char *ifname, struct in_addr *gateway_nbo)
{
	if (strchr(ifname, ':') != NULL)
		return (1);

	if (gateway_nbo->s_addr == htonl(INADDR_ANY)) /* no router */
		return (1);

	return (update_default_route(ifname, RTM_DELETE, gateway_nbo, 0));
}

/*
 * inactivity_shutdown(): shuts down agent if there are no interfaces to manage
 *
 *   input: iu_tq_t *: unused
 *	    void *: unused
 *  output: void
 */

/* ARGSUSED */
void
inactivity_shutdown(iu_tq_t *tqp, void *arg)
{
	if (ifs_count() > 0)	/* shouldn't happen, but... */
		return;

	iu_stop_handling_events(eh, DHCP_REASON_INACTIVITY, NULL, NULL);
}

/*
 * graceful_shutdown(): shuts down the agent gracefully
 *
 *   input: int: the signal that caused graceful_shutdown to be called
 *  output: void
 */

void
graceful_shutdown(int sig)
{
	iu_stop_handling_events(eh, (sig == SIGTERM ? DHCP_REASON_TERMINATE :
	    DHCP_REASON_SIGNAL), drain_script, NULL);
}

/*
 * register_acknak(): registers dhcp_acknak() to be called back when ACK or
 *		      NAK packets are received on a given interface
 *
 *   input: struct ifslist *: the interface to register for
 *  output: int: 1 on success, 0 on failure
 */

int
register_acknak(struct ifslist *ifsp)
{
	iu_event_id_t	ack_id, ack_bcast_id = -1;

	/*
	 * having an acknak id already registered isn't impossible;
	 * handle the situation as gracefully as possible.
	 */

	if (ifsp->if_acknak_id != -1) {
		dhcpmsg(MSG_DEBUG, "register_acknak: acknak id pending, "
		    "attempting to cancel");
		if (unregister_acknak(ifsp) == 0)
			return (0);
	}

	switch (ifsp->if_state) {

	case BOUND:
	case REBINDING:
	case RENEWING:

		ack_bcast_id = iu_register_event(eh, ifsp->if_sock_fd, POLLIN,
		    dhcp_acknak, ifsp);

		if (ack_bcast_id == -1) {
			dhcpmsg(MSG_WARNING, "register_acknak: cannot "
			    "register to receive socket broadcasts");
			return (0);
		}

		ack_id = iu_register_event(eh, ifsp->if_sock_ip_fd, POLLIN,
		    dhcp_acknak, ifsp);
		break;

	default:
		ack_id = iu_register_event(eh, ifsp->if_dlpi_fd, POLLIN,
		    dhcp_acknak, ifsp);
		break;
	}

	if (ack_id == -1) {
		dhcpmsg(MSG_WARNING, "register_acknak: cannot register event");
		(void) iu_unregister_event(eh, ack_bcast_id, NULL);
		return (0);
	}

	ifsp->if_acknak_id = ack_id;
	hold_ifs(ifsp);

	ifsp->if_acknak_bcast_id = ack_bcast_id;
	if (ifsp->if_acknak_bcast_id != -1) {
		hold_ifs(ifsp);
		dhcpmsg(MSG_DEBUG, "register_acknak: registered broadcast id "
		    "%d", ack_bcast_id);
	}

	dhcpmsg(MSG_DEBUG, "register_acknak: registered acknak id %d", ack_id);
	return (1);
}

/*
 * unregister_acknak(): unregisters dhcp_acknak() to be called back
 *
 *   input: struct ifslist *: the interface to unregister for
 *  output: int: 1 on success, 0 on failure
 */

int
unregister_acknak(struct ifslist *ifsp)
{
	if (ifsp->if_acknak_id != -1) {

		if (iu_unregister_event(eh, ifsp->if_acknak_id, NULL) == 0) {
			dhcpmsg(MSG_DEBUG, "unregister_acknak: cannot "
			    "unregister acknak id %d on %s",
			    ifsp->if_acknak_id, ifsp->if_name);
			return (0);
		}

		dhcpmsg(MSG_DEBUG, "unregister_acknak: unregistered acknak id "
		    "%d", ifsp->if_acknak_id);

		ifsp->if_acknak_id = -1;
		(void) release_ifs(ifsp);
	}

	if (ifsp->if_acknak_bcast_id != -1) {

		if (iu_unregister_event(eh, ifsp->if_acknak_bcast_id, NULL)
		    == 0) {
			dhcpmsg(MSG_DEBUG, "unregister_acknak: cannot "
			    "unregister broadcast id %d on %s",
			    ifsp->if_acknak_id, ifsp->if_name);
			return (0);
		}

		dhcpmsg(MSG_DEBUG, "unregister_acknak: unregistered "
		    "broadcast id %d", ifsp->if_acknak_bcast_id);

		ifsp->if_acknak_bcast_id = -1;
		(void) release_ifs(ifsp);
	}

	return (1);
}

/*
 * bind_sock(): binds a socket to a given IP address and port number
 *
 *   input: int: the socket to bind
 *	    in_port_t: the port number to bind to, host byte order
 *	    in_addr_t: the address to bind to, host byte order
 *  output: int: 1 on success, 0 on failure
 */

int
bind_sock(int fd, in_port_t port_hbo, in_addr_t addr_hbo)
{
	struct sockaddr_in	sin;
	int			on = 1;

	(void) memset(&sin, 0, sizeof (struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port   = htons(port_hbo);
	sin.sin_addr.s_addr = htonl(addr_hbo);

	(void) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (int));

	return (bind(fd, (struct sockaddr *)&sin, sizeof (sin)) == 0);
}

/*
 * valid_hostname(): check whether a string is a valid hostname
 *
 *   input: const char *: the string to verify as a hostname
 *  output: boolean_t: B_TRUE if the string is a valid hostname
 *
 * Note that we accept both host names beginning with a digit and
 * those containing hyphens.  Neither is strictly legal according
 * to the RFCs, but both are in common practice, so we endeavour
 * to not break what customers are using.
 */

static boolean_t
valid_hostname(const char *hostname)
{
	unsigned int i;

	for (i = 0; hostname[i] != '\0'; i++) {

		if (isalpha(hostname[i]) || isdigit(hostname[i]) ||
		    (((hostname[i] == '-') || (hostname[i] == '.')) && (i > 0)))
			continue;

		return (B_FALSE);
	}

	return (i > 0);
}

/*
 * iffile_to_hostname(): return the hostname contained on a line of the form
 *
 * [ ^I]*inet[ ^I]+hostname[\n]*\0
 *
 * in the file located at the specified path
 *
 *   input: const char *: the path of the file to look in for the hostname
 *  output: const char *: the hostname at that path, or NULL on failure
 */

#define	IFLINE_MAX	1024	/* maximum length of a hostname.<if> line */

const char *
iffile_to_hostname(const char *path)
{
	FILE		*fp;
	static char	ifline[IFLINE_MAX];

	fp = fopen(path, "r");
	if (fp == NULL)
		return (NULL);

	/*
	 * /etc/hostname.<if> may contain multiple ifconfig commands, but each
	 * such command is on a separate line (see the "while read ifcmds" code
	 * in /etc/init.d/inetinit).  Thus we will read the file a line at a
	 * time, searching for a line of the form
	 *
	 * [ ^I]*inet[ ^I]+hostname[\n]*\0
	 *
	 * extract the host name from it, and check it for validity.
	 */
	while (fgets(ifline, sizeof (ifline), fp) != NULL) {
		char *p;

		if ((p = strstr(ifline, "inet")) != NULL) {
			if ((p != ifline) && !isspace(p[-1])) {
				(void) fclose(fp);
				return (NULL);
			}
			p += 4;	/* skip over "inet" and expect spaces or tabs */
			if ((*p == '\n') || (*p == '\0')) {
				(void) fclose(fp);
				return (NULL);
			}
			if (isspace(*p)) {
				char *nlptr;

				/* no need to read more of the file */
				(void) fclose(fp);

				while (isspace(*p))
					p++;
				if ((nlptr = strrchr(p, '\n')) != NULL)
					*nlptr = '\0';
				if (strlen(p) > MAXHOSTNAMELEN) {
					dhcpmsg(MSG_WARNING,
					    "iffile_to_hostname:"
					    " host name too long");
					return (NULL);
				}
				if (valid_hostname(p)) {
					return (p);
				} else {
					dhcpmsg(MSG_WARNING,
					    "iffile_to_hostname:"
					    " host name not valid");
					return (NULL);
				}
			} else {
				(void) fclose(fp);
				return (NULL);
			}
		}
	}

	(void) fclose(fp);
	return (NULL);
}
