/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

 /*
  * This module determines the type of socket (datagram, stream), the client
  * socket address and port, the server socket address and port. In addition,
  * it provides methods to map a transport address to a printable host name
  * or address. Socket address information results are in static memory.
  * 
  * The result from the hostname lookup method is STRING_PARANOID when a host
  * pretends to have someone elses name, or when a host name is available but
  * could not be verified.
  * 
  * When lookup or conversion fails the result is set to STRING_UNKNOWN.
  * 
  * Diagnostics are reported through syslog(3).
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) socket.c 1.15 97/03/21 19:27:24";
#endif

/* System libraries. */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>

extern char *inet_ntoa();

/* Local stuff. */

#include "tcpd.h"

/* Forward declarations. */

static void sock_sink();

#ifdef APPEND_DOT

 /*
  * Speed up DNS lookups by terminating the host name with a dot. Should be
  * done with care. The speedup can give problems with lookups from sources
  * that lack DNS-style trailing dot magic, such as local files or NIS maps.
  */

static struct hostent *tcpd_gethostbyname_dot(name, af)
char   *name;
int af;
{
    char    dot_name[MAXHOSTNAMELEN + 1];

    /*
     * Don't append dots to unqualified names. Such names are likely to come
     * from local hosts files or from NIS.
     */

    if (strchr(name, '.') == 0 || strlen(name) >= MAXHOSTNAMELEN - 1) {
	return (tcpd_gethostbyname(name, af));
    } else {
	sprintf(dot_name, "%s.", name);
	return (tcpd_gethostbyname(dot_name, af));
    }
}

#define tcpd_gethostbyname tcpd_gethostbyname_dot
#endif

/* sock_host - look up endpoint addresses and install conversion methods */

void    sock_host(request)
struct request_info *request;
{
    static struct sockaddr_gen client;
    static struct sockaddr_gen server;
    int     len;
    char    buf[BUFSIZ];
    int     fd = request->fd;

    sock_methods(request);

    /*
     * Look up the client host address. Hal R. Brand <BRAND@addvax.llnl.gov>
     * suggested how to get the client host info in case of UDP connections:
     * peek at the first message without actually looking at its contents. We
     * really should verify that client.sin_family gets the value AF_INET,
     * but this program has already caused too much grief on systems with
     * broken library code.
     */

    len = sizeof(client);
    if (getpeername(fd, (struct sockaddr *) & client, &len) < 0) {
	request->sink = sock_sink;
	len = sizeof(client);
	if (recvfrom(fd, buf, sizeof(buf), MSG_PEEK,
		     (struct sockaddr *) & client, &len) < 0) {
	    tcpd_warn("can't get client address: %m");
	    return;				/* give up */
	}
#ifdef really_paranoid
	memset(buf, 0 sizeof(buf));
#endif
    }
    sockgen_simplify(&client);
    request->client->sin = &client;

    /*
     * Determine the server binding. This is used for client username
     * lookups, and for access control rules that trigger on the server
     * address or name.
     */

    len = sizeof(server);
    if (getsockname(fd, (struct sockaddr *) & server, &len) < 0) {
	tcpd_warn("getsockname: %m");
	return;
    }
    sockgen_simplify(&server);
    request->server->sin = &server;
}

/* sock_hostaddr - map endpoint address to printable form */

void    sock_hostaddr(host)
struct host_info *host;
{
    struct sockaddr_gen *sin = host->sin;

    if (sin != 0)
#ifdef HAVE_IPV6
	
	(void) inet_ntop(SGFAM(sin), SGADDRP(sin), host->addr, sizeof(host->addr));
#else
	STRN_CPY(host->addr, inet_ntoa(sin->sg_sin.sin_addr), sizeof(host->addr));
#endif
}

/* sock_hostname - map endpoint address to host name */

void    sock_hostname(host)
struct host_info *host;
{
    struct sockaddr_gen *sin = host->sin;
    struct hostent *hp;
    int     i;
    int     herr;

    /*
     * On some systems, for example Solaris 2.3, gethostbyaddr(0.0.0.0) does
     * not fail. Instead it returns "INADDR_ANY". Unfortunately, this does
     * not work the other way around: gethostbyname("INADDR_ANY") fails. We
     * have to special-case 0.0.0.0, in order to avoid false alerts from the
     * host name/address checking code below.
     */
    if (sin != 0
	&& !SG_IS_UNSPECIFIED(sin)
	&& (hp = gethostbyaddr(SGADDRP(sin), SGADDRSZ(sin), SGFAM(sin))) != 0) {

	STRN_CPY(host->name, hp->h_name, sizeof(host->name));

	/*
	 * Verify that the address is a member of the address list returned
	 * by gethostbyname(hostname).
	 * 
	 * Verify also that gethostbyaddr() and gethostbyname() return the same
	 * hostname, or rshd and rlogind may still end up being spoofed.
	 * 
	 * On some sites, gethostbyname("localhost") returns "localhost.domain".
	 * This is a DNS artefact. We treat it as a special case. When we
	 * can't believe the address list from gethostbyname("localhost")
	 * we're in big trouble anyway.
	 */

	if ((hp = tcpd_gethostbyname(host->name, SGFAM(sin))) == 0) {

	    /*
	     * Unable to verify that the host name matches the address. This
	     * may be a transient problem or a botched name server setup.
	     */

	    tcpd_warn("can't verify hostname: gethostbyname(%s) failed",
		      host->name);

	} else if (STR_NE(host->name, hp->h_name)
		   && STR_NE(host->name, "localhost")) {

	    /*
	     * The gethostbyaddr() and gethostbyname() calls did not return
	     * the same hostname. This could be a nameserver configuration
	     * problem. It could also be that someone is trying to spoof us.
	     */

	    tcpd_warn("host name/name mismatch: %s != %.*s",
		      host->name, STRING_LENGTH, hp->h_name);

	} else {
#ifdef HAVE_IPV6
	    char buf[INET6_ADDRSTRLEN];
#endif

	    /*
	     * The address should be a member of the address list returned by
	     * gethostbyname(). We should first verify that the h_addrtype
	     * field is AF_INET, but this program has already caused too much
	     * grief on systems with broken library code.
	     */

	    for (i = 0; hp->h_addr_list[i]; i++) {
		if (memcmp(hp->h_addr_list[i],
			   (char *) SGADDRP(sin),
			   SGADDRSZ(sin)) == 0) {
		    return;			/* name is good, keep it */
		}
	    }

	    /*
	     * The host name does not map to the initial address. Perhaps
	     * someone has messed up. Perhaps someone compromised a name
	     * server.
	     */
	    tcpd_warn("host name/address mismatch: %s != %.*s",
#ifdef HAVE_IPV6
		      inet_ntop(SGFAM(sin), SGADDRP(sin), buf, sizeof(buf)),
#else
		      inet_ntoa(sin->sg_sin.sin_addr),
#endif
		      STRING_LENGTH, hp->h_name);
	}
	strcpy(host->name, paranoid);		/* name is bad, clobber it */
    }
}

/* sock_sink - absorb unreceived IP datagram */

static void sock_sink(fd)
int     fd;
{
    char    buf[BUFSIZ];
    struct sockaddr_in sin;
    int     size = sizeof(sin);

    /*
     * Eat up the not-yet received datagram. Some systems insist on a
     * non-zero source address argument in the recvfrom() call below.
     */

    (void) recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) & sin, &size);
}

/*
 * If we receive a V4 connection on a V6 socket, we pretend we really
 * got a V4 connection.
 */
void sockgen_simplify(sg)
sockaddr_gen *sg;
{
#ifdef HAVE_IPV6
    if (sg->sg_family == AF_INET6 &&
	IN6_IS_ADDR_V4MAPPED(&sg->sg_sin6.sin6_addr)) {
	    struct sockaddr_in v4_addr;

#ifdef IN6_V4MAPPED_TO_INADDR			/* Solaris 8 */
	    IN6_V4MAPPED_TO_INADDR(&sg->sg_sin6.sin6_addr, &v4_addr.sin_addr);
#elif defined(IN6_MAPPED_TO_V4) 		/* Solaris 8 Beta only? */
	    IN6_MAPPED_TO_V4(&sg->sg_sin6.sin6_addr, &v4_addr.sin_addr);
#else						/* Do it the hard way */
	    memcpy(&v4_addr.sin_addr, ((char*) &sg->sg_sin6.sin6_addr) + 12, 4);
#endif
	    v4_addr.sin_port = sg->sg_sin6.sin6_port;
	    v4_addr.sin_family = AF_INET;
	    memcpy(&sg->sg_sin, &v4_addr, sizeof(v4_addr));
    }
#else
    return;
#endif /* HAVE_IPV6 */
}
