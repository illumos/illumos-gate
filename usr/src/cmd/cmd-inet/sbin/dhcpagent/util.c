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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/socket.h>
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

/*
 * this file contains utility functions that have no real better home
 * of their own.  they can largely be broken into six categories:
 *
 *  o  conversion functions -- functions to turn integers into strings,
 *     or to convert between units of a similar measure.
 *
 *  o  time and timer functions -- functions to handle time measurement
 *     and events.
 *
 *  o  ipc-related functions -- functions to simplify the generation of
 *     ipc messages to the agent's clients.
 *
 *  o  signal-related functions -- functions to clean up the agent when
 *     it receives a signal.
 *
 *  o  routing table manipulation functions
 *
 *  o  true miscellany -- anything else
 */

/*
 * pkt_type_to_string(): stringifies a packet type
 *
 *   input: uchar_t: a DHCP packet type value, RFC 2131 or 3315
 *	    boolean_t: B_TRUE if IPv6
 *  output: const char *: the stringified packet type
 */

const char *
pkt_type_to_string(uchar_t type, boolean_t isv6)
{
	/*
	 * note: the ordering in these arrays allows direct indexing of the
	 *	 table based on the RFC packet type value passed in.
	 */

	static const char *v4types[] = {
		"BOOTP",  "DISCOVER", "OFFER",   "REQUEST", "DECLINE",
		"ACK",    "NAK",      "RELEASE", "INFORM"
	};
	static const char *v6types[] = {
		NULL, "SOLICIT", "ADVERTISE", "REQUEST",
		"CONFIRM", "RENEW", "REBIND", "REPLY",
		"RELEASE", "DECLINE", "RECONFIGURE", "INFORMATION-REQUEST",
		"RELAY-FORW", "RELAY-REPL"
	};

	if (isv6) {
		if (type >= sizeof (v6types) / sizeof (*v6types) ||
		    v6types[type] == NULL)
			return ("<unknown>");
		else
			return (v6types[type]);
	} else {
		if (type >= sizeof (v4types) / sizeof (*v4types) ||
		    v4types[type] == NULL)
			return ("<unknown>");
		else
			return (v4types[type]);
	}
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
 * hrtime_to_monosec(): converts a hrtime_t to monosec_t
 *
 *    input: hrtime_t: the time to convert
 *   output: monosec_t: the time in monosec_t
 */

monosec_t
hrtime_to_monosec(hrtime_t hrtime)
{
	return (hrtime / NANOSEC);
}

/*
 * print_server_msg(): prints a message from a DHCP server
 *
 *   input: dhcp_smach_t *: the state machine the message is associated with
 *	    const char *: the string to display
 *	    uint_t: length of string
 *  output: void
 */

void
print_server_msg(dhcp_smach_t *dsmp, const char *msg, uint_t msglen)
{
	if (msglen > 0) {
		dhcpmsg(MSG_INFO, "%s: message from server: %.*s",
		    dsmp->dsm_name, msglen, msg);
	}
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
			/*
			 * Note that we're not the agent here, so the DHCP
			 * logging subsystem hasn't been configured yet.
			 */
			syslog(LOG_DEBUG | LOG_DAEMON, "dhcpagent: daemonize: "
			    "waiting for adoption to complete.");
			if (sleep(DHCP_ADOPT_SLEEP) == 0) {
				syslog(LOG_WARNING | LOG_DAEMON,
				    "dhcpagent: daemonize: timed out awaiting "
				    "adoption.");
			}
			syslog(LOG_DEBUG | LOG_DAEMON, "dhcpagent: daemonize: "
			    "wait finished");
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
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

static boolean_t
update_default_route(uint32_t ifindex, int type, struct in_addr *gateway_nbo,
    int flags)
{
	struct {
		struct rt_msghdr	rm_mh;
		struct sockaddr_in	rm_dst;
		struct sockaddr_in	rm_gw;
		struct sockaddr_in	rm_mask;
		struct sockaddr_dl	rm_ifp;
	} rtmsg;

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
	rtmsg.rm_ifp.sdl_index	= ifindex;

	return (write(rtsock_fd, &rtmsg, sizeof (rtmsg)) == sizeof (rtmsg));
}

/*
 * add_default_route(): add the default route to the given gateway
 *
 *   input: const char *: the name of the interface associated with the route
 *	    struct in_addr: the default gateway to add
 *  output: boolean_t: B_TRUE on success, B_FALSE otherwise
 */

boolean_t
add_default_route(uint32_t ifindex, struct in_addr *gateway_nbo)
{
	return (update_default_route(ifindex, RTM_ADD, gateway_nbo, RTF_UP));
}

/*
 * del_default_route(): deletes the default route to the given gateway
 *
 *   input: const char *: the name of the interface associated with the route
 *	    struct in_addr: if not INADDR_ANY, the default gateway to remove
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

boolean_t
del_default_route(uint32_t ifindex, struct in_addr *gateway_nbo)
{
	if (gateway_nbo->s_addr == htonl(INADDR_ANY)) /* no router */
		return (B_TRUE);

	return (update_default_route(ifindex, RTM_DELETE, gateway_nbo, 0));
}

/*
 * inactivity_shutdown(): shuts down agent if there are no state machines left
 *			  to manage
 *
 *   input: iu_tq_t *: unused
 *	    void *: unused
 *  output: void
 */

/* ARGSUSED */
void
inactivity_shutdown(iu_tq_t *tqp, void *arg)
{
	if (smach_count() > 0)	/* shouldn't happen, but... */
		return;

	dhcpmsg(MSG_VERBOSE, "inactivity_shutdown: timed out");

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
 * bind_sock(): binds a socket to a given IP address and port number
 *
 *   input: int: the socket to bind
 *	    in_port_t: the port number to bind to, host byte order
 *	    in_addr_t: the address to bind to, host byte order
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

boolean_t
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
 * bind_sock_v6(): binds a socket to a given IP address and port number
 *
 *   input: int: the socket to bind
 *	    in_port_t: the port number to bind to, host byte order
 *	    in6_addr_t: the address to bind to, network byte order
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

boolean_t
bind_sock_v6(int fd, in_port_t port_hbo, const in6_addr_t *addr_nbo)
{
	struct sockaddr_in6	sin6;
	int			on = 1;

	(void) memset(&sin6, 0, sizeof (struct sockaddr_in6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port   = htons(port_hbo);
	if (addr_nbo != NULL) {
		(void) memcpy(&sin6.sin6_addr, addr_nbo,
		    sizeof (sin6.sin6_addr));
	}

	(void) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (int));

	return (bind(fd, (struct sockaddr *)&sin6, sizeof (sin6)) == 0);
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

/*
 * init_timer(): set up a DHCP timer
 *
 *   input: dhcp_timer_t *: the timer to set up
 *  output: void
 */

void
init_timer(dhcp_timer_t *dt, lease_t startval)
{
	dt->dt_id = -1;
	dt->dt_start = startval;
}

/*
 * cancel_timer(): cancel a DHCP timer
 *
 *   input: dhcp_timer_t *: the timer to cancel
 *  output: boolean_t: B_TRUE on success, B_FALSE otherwise
 */

boolean_t
cancel_timer(dhcp_timer_t *dt)
{
	if (dt->dt_id == -1)
		return (B_TRUE);

	if (iu_cancel_timer(tq, dt->dt_id, NULL) == 1) {
		dt->dt_id = -1;
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * schedule_timer(): schedule a DHCP timer.  Note that it must not be already
 *		     running, and that we can't cancel here.  If it were, and
 *		     we did, we'd leak a reference to the callback argument.
 *
 *   input: dhcp_timer_t *: the timer to schedule
 *  output: boolean_t: B_TRUE on success, B_FALSE otherwise
 */

boolean_t
schedule_timer(dhcp_timer_t *dt, iu_tq_callback_t *cbfunc, void *arg)
{
	if (dt->dt_id != -1)
		return (B_FALSE);
	dt->dt_id = iu_schedule_timer(tq, dt->dt_start, cbfunc, arg);
	return (dt->dt_id != -1);
}

/*
 * dhcpv6_status_code(): report on a DHCPv6 status code found in an option
 *			 buffer.
 *
 *   input: const dhcpv6_option_t *: pointer to option
 *	    uint_t: option length
 *	    const char **: error string (nul-terminated)
 *	    const char **: message from server (unterminated)
 *	    uint_t *: length of server message
 *  output: int: -1 on error, or >= 0 for a DHCPv6 status code
 */

int
dhcpv6_status_code(const dhcpv6_option_t *d6o, uint_t olen, const char **estr,
    const char **msg, uint_t *msglenp)
{
	uint16_t status;
	static const char *v6_status[] = {
		NULL,
		"Unknown reason",
		"Server has no addresses available",
		"Client record unavailable",
		"Prefix inappropriate for link",
		"Client must use multicast",
		"No prefix available"
	};
	static char sbuf[32];

	*estr = "";
	*msg = "";
	*msglenp = 0;
	if (d6o == NULL)
		return (0);
	olen -= sizeof (*d6o);
	if (olen < 2) {
		*estr = "garbled status code";
		return (-1);
	}

	*msg = (const char *)(d6o + 1) + 2;
	*msglenp = olen - 2;

	(void) memcpy(&status, d6o + 1, sizeof (status));
	status = ntohs(status);
	if (status > 0) {
		if (status > DHCPV6_STAT_NOPREFIX) {
			(void) snprintf(sbuf, sizeof (sbuf), "status %u",
			    status);
			*estr = sbuf;
		} else {
			*estr = v6_status[status];
		}
	}
	return (status);
}
