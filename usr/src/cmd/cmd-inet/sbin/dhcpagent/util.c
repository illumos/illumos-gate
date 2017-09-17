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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016-2017, Chris Fraire <cfraire@me.com>.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
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
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <dhcp_hostconf.h>
#include <dhcp_inittab.h>
#include <dhcp_symbol.h>
#include <limits.h>
#include <strings.h>
#include <libipadm.h>

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

#define	ETCNODENAME		"/etc/nodename"

static	boolean_t	is_fqdn(const char *);
static	boolean_t	dhcp_assemble_fqdn(char *fqdnbuf, size_t buflen,
			    dhcp_smach_t *dsmp);

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
				if (ipadm_is_valid_hostname(p)) {
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

void
write_lease_to_hostconf(dhcp_smach_t *dsmp)
{
	PKT_LIST *plp[2];
	const char *hcfile;

	hcfile = ifname_to_hostconf(dsmp->dsm_name, dsmp->dsm_isv6);
	plp[0] = dsmp->dsm_ack;
	plp[1] = dsmp->dsm_orig_ack;
	if (write_hostconf(dsmp->dsm_name, plp, 2,
	    monosec_to_time(dsmp->dsm_curstart_monosec),
	    dsmp->dsm_isv6) != -1) {
		dhcpmsg(MSG_DEBUG, "wrote lease to %s", hcfile);
	} else if (errno == EROFS) {
		dhcpmsg(MSG_DEBUG, "%s is on a read-only file "
		    "system; not saving lease", hcfile);
	} else {
		dhcpmsg(MSG_ERR, "cannot write %s (reboot will "
		    "not use cached configuration)", hcfile);
	}
}

/*
 * Try to get a string from the first line of a file, up to but not
 * including any space (0x20) or newline.
 *
 *   input: const char *: file name;
 *	    char *: allocated buffer space;
 *	    size_t: space available in buf;
 *  output: boolean_t: B_TRUE if a non-empty string was written to buf;
 *		       B_FALSE otherwise.
 */

static boolean_t
dhcp_get_oneline(const char *filename, char *buf, size_t buflen)
{
	char	value[SYS_NMLN], *c;
	int	fd, i;

	if ((fd = open(filename, O_RDONLY)) <= 0) {
		dhcpmsg(MSG_DEBUG, "dhcp_get_oneline: could not open %s",
		    filename);
		*buf = '\0';
	} else {
		if ((i = read(fd, value, SYS_NMLN - 1)) <= 0) {
			dhcpmsg(MSG_WARNING, "dhcp_get_oneline: no line in %s",
			    filename);
			*buf = '\0';
		} else {
			value[i] = '\0';
			if ((c = strchr(value, '\n')) != NULL)
				*c = '\0';
			if ((c = strchr(value, ' ')) != NULL)
				*c = '\0';

			if (strlcpy(buf, value, buflen) >= buflen) {
				dhcpmsg(MSG_WARNING, "dhcp_get_oneline: too"
				    " long value, %s", value);
				*buf = '\0';
			}
		}
		(void) close(fd);
	}

	return (*buf != '\0');
}

/*
 * Try to get the hostname from the /etc/nodename file. uname(2) cannot
 * be used, because that is initialized after DHCP has solicited, in order
 * to allow for the possibility that utsname.nodename can be set from
 * DHCP Hostname. Here, though, we want to send a value specified
 * advance of DHCP, so read /etc/nodename directly.
 *
 *   input: char *: allocated buffer space;
 *	    size_t: space available in buf;
 *  output: boolean_t: B_TRUE if a non-empty string was written to buf;
 *		       B_FALSE otherwise.
 */

static boolean_t
dhcp_get_nodename(char *buf, size_t buflen)
{
	return (dhcp_get_oneline(ETCNODENAME, buf, buflen));
}

/*
 * dhcp_add_hostname_opt(): Set CD_HOSTNAME option if REQUEST_HOSTNAME is
 *			    affirmative and if 1) dsm_msg_reqhost is available;
 *			    or 2) hostname is read from an extant
 *			    /etc/hostname.<ifname> file; or 3) interface is
 *			    primary and nodename(4) is defined.
 *
 *   input: dhcp_pkt_t *: pointer to DHCP message being constructed;
 *	    dhcp_smach_t *: pointer to interface DHCP state machine;
 *  output: B_TRUE if a client hostname was added; B_FALSE otherwise.
 */

boolean_t
dhcp_add_hostname_opt(dhcp_pkt_t *dpkt, dhcp_smach_t *dsmp)
{
	const char	*reqhost;
	char		nodename[MAXNAMELEN];

	if (!df_get_bool(dsmp->dsm_name, dsmp->dsm_isv6, DF_REQUEST_HOSTNAME))
		return (B_FALSE);

	dhcpmsg(MSG_DEBUG, "dhcp_add_hostname_opt: DF_REQUEST_HOSTNAME");

	if (dsmp->dsm_msg_reqhost != NULL &&
	    ipadm_is_valid_hostname(dsmp->dsm_msg_reqhost)) {
		reqhost = dsmp->dsm_msg_reqhost;
	} else {
		char		hostfile[PATH_MAX + 1];

		(void) snprintf(hostfile, sizeof (hostfile),
		    "/etc/hostname.%s", dsmp->dsm_name);
		reqhost = iffile_to_hostname(hostfile);
	}

	if (reqhost == NULL && (dsmp->dsm_dflags & DHCP_IF_PRIMARY) &&
	    dhcp_get_nodename(nodename, sizeof (nodename))) {
		reqhost = nodename;
	}

	if (reqhost != NULL) {
		free(dsmp->dsm_reqhost);
		if ((dsmp->dsm_reqhost = strdup(reqhost)) == NULL)
			dhcpmsg(MSG_WARNING, "dhcp_add_hostname_opt: cannot"
			    " allocate memory for host name option");
	}

	if (dsmp->dsm_reqhost != NULL) {
		dhcpmsg(MSG_DEBUG, "dhcp_add_hostname_opt: host %s for %s",
		    dsmp->dsm_reqhost, dsmp->dsm_name);
		(void) add_pkt_opt(dpkt, CD_HOSTNAME, dsmp->dsm_reqhost,
		    strlen(dsmp->dsm_reqhost));
		return (B_FALSE);
	} else {
		dhcpmsg(MSG_DEBUG, "dhcp_add_hostname_opt: no hostname for %s",
		    dsmp->dsm_name);
	}

	return (B_TRUE);
}

/*
 * dhcp_add_fqdn_opt(): Set client FQDN option if dhcp_assemble_fqdn()
 *			initializes an FQDN, or else do nothing.
 *
 *   input: dhcp_pkt_t *: pointer to DHCP message being constructed;
 *	    dhcp_smach_t *: pointer to interface DHCP state machine;
 *  output: B_TRUE if a client FQDN was added; B_FALSE otherwise.
 */

boolean_t
dhcp_add_fqdn_opt(dhcp_pkt_t *dpkt, dhcp_smach_t *dsmp)
{
	/*
	 * RFC 4702 section 2:
	 *
	 * The format of the Client FQDN option is:
	 *
	 *  Code   Len    Flags  RCODE1 RCODE2   Domain Name
	 * +------+------+------+------+------+------+--
	 * |  81  |   n  |      |      |      |       ...
	 * +------+------+------+------+------+------+--
	 *
	 * Code and Len are distinct, and the remainder is in a single buffer,
	 * opt81, for Flags + (unused) RCODE1 and RCODE2 (all octets) and a
	 * potentially maximum-length domain name.
	 *
	 * The format of the Flags field is:
	 *
	 *  0 1 2 3 4 5 6 7
	 * +-+-+-+-+-+-+-+-+
	 * |  MBZ  |N|E|O|S|
	 * +-+-+-+-+-+-+-+-+
	 *
	 * where MBZ is ignored and NEOS are:
	 *
	 * S = 1 to request that "the server SHOULD perform the A RR (FQDN-to-
	 * address) DNS updates;
	 *
	 * O = 0, for a server-only response bit;
	 *
	 * E = 1 to indicate the domain name is in "canonical wire format,
	 * without compression (i.e., ns_name_pton2) ....  This encoding SHOULD
	 * be used by clients ....";
	 *
	 * N = 0 to request that "the server SHALL perform DNS updates [of the
	 * PTR RR]." (1 would request SHALL NOT update).
	 */

	const uint8_t	S_BIT_POS = 7;
	const uint8_t	E_BIT_POS = 5;
	const uint8_t	S_BIT = 1 << (7 - S_BIT_POS);
	const uint8_t	E_BIT = 1 << (7 - E_BIT_POS);
	const size_t	OPT_FQDN_METALEN = 3;
	char		fqdnbuf[MAXNAMELEN];
	uchar_t		enc_fqdnbuf[MAXNAMELEN];
	uint8_t		fqdnopt[MAXNAMELEN + OPT_FQDN_METALEN];
	uint_t		fqdncode;
	size_t		len, metalen;

	if (dsmp->dsm_isv6)
		return (B_FALSE);

	if (!dhcp_assemble_fqdn(fqdnbuf, sizeof (fqdnbuf), dsmp))
		return (B_FALSE);

	/* encode the FQDN in canonical wire format */

	if (ns_name_pton2(fqdnbuf, enc_fqdnbuf, sizeof (enc_fqdnbuf),
	    &len) < 0) {
		dhcpmsg(MSG_WARNING, "dhcp_add_fqdn_opt: error encoding domain"
		    " name %s", fqdnbuf);
		return (B_FALSE);
	}

	dhcpmsg(MSG_DEBUG, "dhcp_add_fqdn_opt: interface FQDN is %s"
	    " for %s", fqdnbuf, dsmp->dsm_name);

	bzero(fqdnopt, sizeof (fqdnopt));
	fqdncode = CD_CLIENTFQDN;
	metalen = OPT_FQDN_METALEN;
	*fqdnopt = S_BIT | E_BIT;
	(void) memcpy(fqdnopt + metalen, enc_fqdnbuf, len);
	(void) add_pkt_opt(dpkt, fqdncode, fqdnopt, metalen + len);

	return (B_TRUE);
}

/*
 * dhcp_adopt_domainname(): Set namebuf if either dsm_dhcp_domainname or
 *			    resolv's "default domain (deprecated)" is defined.
 *
 *   input: char *: pointer to buffer to which domain name will be written;
 *	    size_t length of buffer;
 *	    dhcp_smach_t *: pointer to interface DHCP state machine;
 *  output: B_TRUE if namebuf was set to a valid domain name; B_FALSE
 *	    otherwise.
 */

static boolean_t
dhcp_adopt_domainname(char *namebuf, size_t buflen, dhcp_smach_t *dsmp)
{
	const char		*domainname;
	struct __res_state	res_state;
	int			lasterrno;

	domainname = dsmp->dsm_dhcp_domainname;

	if (ipadm_is_nil_hostname(domainname)) {
		/*
		 * fall back to resolv's "default domain (deprecated)"
		 */
		bzero(&res_state, sizeof (struct __res_state));

		if ((lasterrno = res_ninit(&res_state)) != 0) {
			dhcpmsg(MSG_WARNING, "dhcp_adopt_domainname: error %d"
			    " initializing resolver", lasterrno);
			return (B_FALSE);
		}

		domainname = NULL;
		if (!ipadm_is_nil_hostname(res_state.defdname))
			domainname = res_state.defdname;

		/* N.b. res_state.defdname survives the following call */
		res_ndestroy(&res_state);
	}

	if (domainname == NULL)
		return (B_FALSE);

	if (strlcpy(namebuf, domainname, buflen) >= buflen) {
		dhcpmsg(MSG_WARNING,
		    "dhcp_adopt_domainname: too long adopted domain"
		    " name %s for %s", domainname, dsmp->dsm_name);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * dhcp_pick_domainname(): Set namebuf if DNS_DOMAINNAME is defined in
 *			   /etc/default/dhcpagent or if dhcp_adopt_domainname()
 *			   succeeds.
 *
 *   input: char *: pointer to buffer to which domain name will be written;
 *	    size_t length of buffer;
 *	    dhcp_smach_t *: pointer to interface DHCP state machine;
 *  output: B_TRUE if namebuf was set to a valid domain name; B_FALSE
 *	    otherwise.
 */

static boolean_t
dhcp_pick_domainname(char *namebuf, size_t buflen, dhcp_smach_t *dsmp)
{
	const char	*domainname;

	/*
	 * Try to use a static DNS_DOMAINNAME if defined in
	 * /etc/default/dhcpagent.
	 */
	domainname = df_get_string(dsmp->dsm_name, dsmp->dsm_isv6,
	    DF_DNS_DOMAINNAME);
	if (!ipadm_is_nil_hostname(domainname)) {
		if (strlcpy(namebuf, domainname, buflen) >= buflen) {
			dhcpmsg(MSG_WARNING, "dhcp_pick_domainname: too long"
			    " DNS_DOMAINNAME %s for %s", domainname,
			    dsmp->dsm_name);
			return (B_FALSE);
		}
		return (B_TRUE);
	} else if (df_get_bool(dsmp->dsm_name, dsmp->dsm_isv6,
	    DF_ADOPT_DOMAINNAME)) {
		return (dhcp_adopt_domainname(namebuf, buflen, dsmp));
	} else {
		return (B_FALSE);
	}
}

/*
 * dhcp_assemble_fqdn(): Set fqdnbuf if REQUEST_FQDN is set and
 *			 either a host name was sent in the IPC message (e.g.,
 *			 from ipadm(1M) -h,--reqhost) or the interface is
 *			 primary and a nodename(4) is defined. If the host
 *			 name is not already fully qualified per is_fqdn(),
 *			 then dhcp_pick_domainname() is tried to select a
 *			 domain to be used to construct an FQDN.
 *
 *   input: char *: pointer to buffer to which FQDN will be written;
 *	    size_t length of buffer;
 *	    dhcp_smach_t *: pointer to interface DHCP state machine;
 *  output: B_TRUE if fqdnbuf was assigned a valid FQDN; B_FALSE otherwise.
 */

static boolean_t
dhcp_assemble_fqdn(char *fqdnbuf, size_t buflen, dhcp_smach_t *dsmp)
{
	char		nodename[MAXNAMELEN], *reqhost;
	size_t		pos, len;


	if (!df_get_bool(dsmp->dsm_name, dsmp->dsm_isv6, DF_REQUEST_FQDN))
		return (B_FALSE);

	dhcpmsg(MSG_DEBUG, "dhcp_assemble_fqdn: DF_REQUEST_FQDN");

	/* It's convenient to ensure fqdnbuf is always null-terminated */
	bzero(fqdnbuf, buflen);

	reqhost = dsmp->dsm_msg_reqhost;
	if (ipadm_is_nil_hostname(reqhost) &&
	    (dsmp->dsm_dflags & DHCP_IF_PRIMARY) &&
	    dhcp_get_nodename(nodename, sizeof (nodename))) {
		reqhost = nodename;
	}

	if (ipadm_is_nil_hostname(reqhost)) {
		dhcpmsg(MSG_DEBUG,
		    "dhcp_assemble_fqdn: no interface reqhost for %s",
		    dsmp->dsm_name);
		return (B_FALSE);
	}

	if ((pos = strlcpy(fqdnbuf, reqhost, buflen)) >= buflen) {
		dhcpmsg(MSG_WARNING, "dhcp_assemble_fqdn: too long reqhost %s"
		    " for %s", reqhost, dsmp->dsm_name);
		return (B_FALSE);
	}

	/*
	 * If not yet FQDN, construct if possible
	 */
	if (!is_fqdn(reqhost)) {
		char		domainname[MAXNAMELEN];
		size_t		needdots;

		if (!dhcp_pick_domainname(domainname, sizeof (domainname),
		    dsmp)) {
			dhcpmsg(MSG_DEBUG,
			    "dhcp_assemble_fqdn: no domain name for %s",
			    dsmp->dsm_name);
			return (B_FALSE);
		}

		/*
		 * Finish constructing FQDN. Account for space needed to hold a
		 * separator '.' and a terminating '.'.
		 */
		len = strlen(domainname);
		needdots = 1 + (domainname[len - 1] != '.');

		if (pos + len + needdots >= buflen) {
			dhcpmsg(MSG_WARNING, "dhcp_assemble_fqdn: too long"
			    " FQDN %s.%s for %s", fqdnbuf, domainname,
			    dsmp->dsm_name);
			return (B_FALSE);
		}

		/* add separator and then domain name */
		fqdnbuf[pos++] = '.';
		if (strlcpy(fqdnbuf + pos, domainname, buflen - pos) >=
		    buflen - pos) {
			/* shouldn't get here as we checked above */
			return (B_FALSE);
		}
		pos += len;

		/* ensure the final character is '.' */
		if (needdots > 1)
			fqdnbuf[pos++] = '.'; /* following is already zeroed */
	}

	if (!ipadm_is_valid_hostname(fqdnbuf)) {
		dhcpmsg(MSG_WARNING, "dhcp_assemble_fqdn: invalid FQDN %s"
		    " for %s", fqdnbuf, dsmp->dsm_name);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * is_fqdn() : Determine if the `hostname' can be considered as a Fully
 *	       Qualified Domain Name by being "rooted" (i.e., ending in '.')
 *	       or by containing at least three DNS labels (e.g.,
 *	       srv.example.com).
 *
 *   input: const char *: the hostname to inspect;
 *  output: boolean_t: B_TRUE if `hostname' is not NULL satisfies the
 *	    criteria above; otherwise, B_FALSE;
 */

boolean_t
is_fqdn(const char *hostname)
{
	const char *c;
	size_t i;

	if (hostname == NULL)
		return (B_FALSE);

	i = strlen(hostname);
	if (i > 0 && hostname[i - 1] == '.')
		return (B_TRUE);

	c = hostname;
	i = 0;
	while ((c = strchr(c, '.')) != NULL) {
		++i;
		++c;
	}

	/* at least two separators is inferred to be fully-qualified */
	return (i >= 2);
}

/*
 * terminate_at_space(): Reset the first space, 0x20, to 0x0 in the
 *			 specified string.
 *
 *   input: char *: NULL or a null-terminated string;
 *  output: void.
 */

static void
terminate_at_space(char *value)
{
	if (value != NULL) {
		char	*sp;

		sp = strchr(value, ' ');
		if (sp != NULL)
			*sp = '\0';
	}
}

/*
 * get_offered_domainname_v4(): decode a defined v4 DNSdmain value if it
 *				exists to return a copy of the domain
 *				name.
 *
 *   input: dhcp_smach_t *: the state machine REQUESTs are being sent from;
 *	    PKT_LIST *: the best packet to be used to construct a REQUEST;
 *  output: char *: NULL or a copy of the domain name ('\0' terminated);
 */

static char *
get_offered_domainname_v4(PKT_LIST *offer)
{
	char		*domainname = NULL;
	DHCP_OPT	*opt;

	if ((opt = offer->opts[CD_DNSDOMAIN]) != NULL) {
		uchar_t		*valptr;
		dhcp_symbol_t	*symp;

		valptr = (uchar_t *)opt + DHCP_OPT_META_LEN;

		symp = inittab_getbycode(
		    ITAB_CAT_STANDARD, ITAB_CONS_INFO, opt->code);
		if (symp != NULL) {
			domainname = inittab_decode(symp, valptr,
			    opt->len, B_TRUE);
			terminate_at_space(domainname);
			free(symp);
		}
	}

	return (domainname);
}

/*
 * save_domainname(): assign dsm_dhcp_domainname from
 *		      get_offered_domainname_v4 or leave the field NULL if no
 *		      option is present.
 *
 *   input: dhcp_smach_t *: the state machine REQUESTs are being sent from;
 *	    PKT_LIST *: the best packet to be used to construct a REQUEST;
 *  output: void
 */

void
save_domainname(dhcp_smach_t *dsmp, PKT_LIST *offer)
{
	char	*domainname = NULL;

	free(dsmp->dsm_dhcp_domainname);
	dsmp->dsm_dhcp_domainname = NULL;

	if (!dsmp->dsm_isv6) {
		domainname = get_offered_domainname_v4(offer);
	}

	dsmp->dsm_dhcp_domainname = domainname;
}
