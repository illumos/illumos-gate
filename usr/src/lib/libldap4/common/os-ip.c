/*
 * Copyright (c) 1995-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  os-ip.c -- platform-specific TCP & UDP related code
 */

#ifndef lint
static char copyright[] = "@(#) Copyright (c) 1995 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#ifdef _WIN32
#include <io.h>
#include "msdos.h"
#else /* _WIN32 */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif /* _WIN32 */
#ifdef _AIX
#include <sys/select.h>
#endif /* _AIX */
#ifdef VMS
#include "ucx_select.h"
#endif /* VMS */
#include "portable.h"
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

#ifdef LDAP_REFERRALS
#ifdef USE_SYSCONF
#include <unistd.h>
#endif /* USE_SYSCONF */
#ifdef notyet
#ifdef NEED_FILIO
#include <sys/filio.h>
#else /* NEED_FILIO */
#include <sys/ioctl.h>
#endif /* NEED_FILIO */
#endif /* notyet */
#endif /* LDAP_REFERRALS */

#ifdef MACOS
#define	tcp_close(s)	tcpclose(s)
#else /* MACOS */
#ifdef DOS
#ifdef PCNFS
#define	tcp_close(s)	close(s)
#endif /* PCNFS */
#ifdef NCSA
#define	tcp_close(s)	netclose(s); netshut()
#endif /* NCSA */
#ifdef WINSOCK
#define	tcp_close(s)	closesocket(s); WSACleanup();
#endif /* WINSOCK */
#else /* DOS */
#define	tcp_close(s)	close(s)
#endif /* DOS */
#endif /* MACOS */
#ifdef SUN
#include <nss_dbdefs.h>
#endif

#include <fcntl.h>
#include <sys/poll.h>


/*
 * Do an async connect or blocking connect depending on the timeout
 * value. LDAP_X_IO_TIMEOUT_NO_TIMEOUT means do a blocking connect.
 * Otherwise wait for timeout milliseconds for the connection.
 * Returns 0 on success and -1 on failure.
 */
static int
do_connect(int s, struct sockaddr *sin, int timeout)
{
	int flags, connected = 0;
	int retval, error, n;
	fd_set wfds;
	struct timeval waittime, *sel_timeout;

	/* set the socket to do non-blocking i/o */
	flags = fcntl(s, F_GETFL, 0);
	fcntl(s, F_SETFL, flags | O_NONBLOCK);

	if (connect(s, sin, sizeof (struct sockaddr_in)) == 0) {
		connected = 1;
	} else if (errno == EINPROGRESS) {
		/* if NO_TIMEOUT is specified do a blocking connect */
		if (timeout <= LDAP_X_IO_TIMEOUT_NO_TIMEOUT) {
			sel_timeout = NULL;
		} else {
			/* set the timeout to the specified value */
			waittime.tv_sec = timeout / MILLISEC;
			waittime.tv_usec = (timeout % MILLISEC) * 1000;
			sel_timeout = &waittime;
		}

		FD_ZERO(&wfds);
		FD_SET(s, &wfds);
		n = sizeof (error);
		if (select(s+1, NULL, &wfds, NULL, sel_timeout) > 0 &&
			FD_ISSET(s, &wfds) &&
			getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &n) == 0 &&
			error == 0) {
			connected = 1;
		}
	}

	/* if we are connected restore the flags for the socket */
	if (connected) {
		fcntl(s, F_SETFL, flags);
	}

	return (connected ? 0 : -1);
}


int
connect_to_host(Sockbuf *sb, char *host, in_addr_t address,
	int port, int async, int timeout)
/*
 * if host == NULL, connect using address
 * "address" and "port" must be in network byte order
 * zero is returned upon success, -1 if fatal error, -2 EINPROGRESS
 * async is only used ifdef LDAP_REFERRALS (non-0 means don't wait for connect)
 * XXX async is not used yet!
 */
{
	int			rc, i, s, connected, use_hp;
	struct sockaddr_in	sin;
	struct hostent		*hp;
#ifdef notyet
#ifdef LDAP_REFERRALS
	int			status;	/* for ioctl call */
#endif /* LDAP_REFERRALS */
#endif /* notyet */
#ifdef SUN
	struct hostent		hpret;
	char			hpbuf[NSS_BUFLEN_HOSTS];
	int			hperrno;
#endif

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 201, "connect_to_host: "
		"%1$s:%2$d\n"), (host == NULL) ? catgets(slapdcat, 1, 202,
		"(by address)") : host, ntohs(port), 0);

	connected = use_hp = 0;

	if (host != NULL && (address = inet_addr(host)) == -1) {
#ifdef SUN
		if ((hp = gethostbyname_r(host, &hpret, hpbuf,
			NSS_BUFLEN_HOSTS, &hperrno)) == NULL) {
#else
		if ((hp = gethostbyname(host)) == NULL) {
#endif
			errno = EHOSTUNREACH;	/* not exactly right, but... */
			return (-1);
		}
		use_hp = 1;
	}

	rc = -1;
	for (i = 0; !use_hp || (hp->h_addr_list[i] != 0); i++) {
		if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			return (-1);
		}
#ifdef notyet
#ifdef LDAP_REFERRALS
		status = 1;
		if (async && ioctl(s, FIONBIO, (caddr_t)&status) == -1) {
			Debug(LDAP_DEBUG_ANY, catgets(slapdcat, 1, 203,
				"FIONBIO ioctl failed on %d\n"), s, 0, 0);
		}
#endif /* LDAP_REFERRALS */
#endif /* notyet */
		(void) memset((char *)&sin, 0, sizeof (struct sockaddr_in));
		sin.sin_family = AF_INET;
		sin.sin_port = port;
		SAFEMEMCPY((char *) &sin.sin_addr.s_addr,
		    (use_hp ? (char *) hp->h_addr_list[i] :
		    (char *)&address), sizeof (sin.sin_addr.s_addr));

		if (do_connect(s, (struct sockaddr *)&sin, timeout) == 0) {
			connected = 1;
			break;
		}

#ifdef notyet
#ifdef LDAP_REFERRALS
#ifdef EAGAIN
		if (errno == EINPROGRESS || errno == EAGAIN) {
#else /* EAGAIN */
		if (errno == EINPROGRESS) {
#endif /* EAGAIN */
			Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 204,
				"connect would block...\n"), 0, 0, 0);
			rc = -2;
			break;
		}
#endif /* LDAP_REFERRALS */
#endif /* notyet */

#ifdef LDAP_DEBUG
		if (ldap_debug & LDAP_DEBUG_TRACE) {
			perror((char *)inet_ntoa(sin.sin_addr));
		}
#endif
		close(s);
		if (!use_hp) {
			break;
		}
	}

	if (connected) {
		rc = 0;
		sb->sb_sd = s;
#ifdef notyet
#ifdef LDAP_REFERRALS
		status = 0;
		if (!async && ioctl(s, FIONBIO, (caddr_t)&on) == -1) {
			Debug(LDAP_DEBUG_ANY, catgets(slapdcat, 1, 203,
				"FIONBIO ioctl failed on %d\n"), s, 0, 0);
		}
#endif /* LDAP_REFERRALS */
#endif /* notyet */

		Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 205,
			"sd %1$d connected to: %2$s\n"), s,
			inet_ntoa(sin.sin_addr), 0);
	}

	return (rc);
}


void
close_ldap_connection( Sockbuf *sb )
{
#ifdef LDAP_SSL
	if (sb->sb_ssl){
		SSL_close(sb->sb_ssl);
		SSL_delete(sb->sb_ssl);
	}
	sb->sb_ssl = NULL;
	sb->sb_ssl_tls = 0;
#endif
    tcp_close( sb->sb_sd );
}


#ifdef KERBEROS
char *
host_connected_to( Sockbuf *sb )
{
	struct hostent		*hp;
	char			*p;
	int			len;
	struct sockaddr_in	sin;
#ifdef SUN
    struct hostent      hpret;
    char                hpbuf[NSS_BUFLEN_HOSTS];
    int                 hperrno;
#endif

	(void)memset( (char *)&sin, 0, sizeof( struct sockaddr_in ));
	len = sizeof( sin );
	if ( getpeername( sb->sb_sd, (struct sockaddr *)&sin, &len ) == -1 ) {
		return( NULL );
	}

	/*
	 * do a reverse lookup on the addr to get the official hostname.
	 * this is necessary for kerberos to work right, since the official
	 * hostname is used as the kerberos instance.
	 */
#ifdef SUN
	if (( hp = gethostbyaddr_r((char *) &sin.sin_addr,
		   sizeof( sin.sin_addr ), AF_INET,
		   &hpret, hpbuf, NSS_BUFLEN_HOSTS, &hperrno)) != NULL ) {
#else
	if (( hp = gethostbyaddr( (char *) &sin.sin_addr,
	    sizeof( sin.sin_addr ), AF_INET )) != NULL ) {
#endif
		if ( hp->h_name != NULL ) {
			return( strdup( hp->h_name ));
		}
	}

	return( NULL );
}
#endif /* KERBEROS */


#ifdef LDAP_REFERRALS
#ifdef SUN
/* for UNIX */
#include <stropts.h>
#include <poll.h>

struct selectinfo {
	struct pollfd fds[LDAP_DEFAULT_REFHOPLIMIT];
	int nbfds;
};


void
mark_select_write( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	int i;
	
	sip = (struct selectinfo *)ld->ld_selectinfo;
	
	/* find if sb is in fds */
	for (i=0; i< sip->nbfds; i++) {
		if (sip->fds[i].fd == sb->sb_sd){
			sip->fds[i].events |= POLLOUT;
			return;
		}
	}
	if (sip->nbfds < LDAP_DEFAULT_REFHOPLIMIT) {
		sip->fds[sip->nbfds].fd = sb->sb_sd;
		sip->fds[sip->nbfds].events |= POLLOUT;
		sip->nbfds++;
	}
	else {
		/* Should not happen */
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 206, "Mark for poll : Too many descriptors\n"), 0, 0, 0 );
	}
}


void
mark_select_read( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	int i;
	
	sip = (struct selectinfo *)ld->ld_selectinfo;

	/* find if sb is in fds */
	for (i=0; i< sip->nbfds; i++) {
		if (sip->fds[i].fd == sb->sb_sd) {
			sip->fds[i].events |= POLLIN;
			return;
		}
	}
	
	if (sip->nbfds < LDAP_DEFAULT_REFHOPLIMIT) {
		sip->fds[sip->nbfds].fd = sb->sb_sd;
		sip->fds[sip->nbfds].events |= POLLIN;
		sip->nbfds++;
	}
	else {
		/* Should not happen */
		Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 206, "Mark for poll : Too many descriptors\n"), 0, 0, 0 );
	}
}


void
mark_select_clear( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	int i;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	for (i = 0; i< sip->nbfds; i++) {
		if (sip->fds[i].fd == sb->sb_sd){
			i++;
			for (; i < sip->nbfds; i ++) {
				sip->fds[ i - 1] = sip->fds[i];
			}
			sip->fds[i].fd = -1;
			sip->fds[i].events = -1;
			sip->nbfds--;
			return;
		}
	}
	/* If we reach here, there's a pb. */
	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 207, "Clear poll : descriptor not found\n"), 0, 0, 0 );
}


long
is_write_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	int i;
	
	sip = (struct selectinfo *)ld->ld_selectinfo;

	for (i=0; i< sip->nbfds; i++) {
		if (sip->fds[i].fd == sb->sb_sd) {
			if ( sip->fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				return (-1);
			}
			return( sip->fds[i].revents & POLLOUT );
		}
	}
	return(0);
}


long
is_read_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	int i;
	
	sip = (struct selectinfo *)ld->ld_selectinfo;

	for (i=0; i< sip->nbfds; i++) {
		if (sip->fds[i].fd == sb->sb_sd) {
			if (sip->fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				return (-1);
			}
			return( sip->fds[i].revents & POLLIN );
		}
	}
	return(0);
}

void *
new_select_info()
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)calloc( 1, sizeof( struct selectinfo ));

	return( (void *)sip );
}


void
free_select_info( void *sip )
{
	free( sip );
}


int
do_ldap_select( LDAP *ld, struct timeval *timeout )
{
	struct selectinfo	*sip;
	int tim;
#if defined( SUN ) && defined( _REENTRANT )
	int rv;
#endif

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 208, "do_ldap_select\n"), 0, 0, 0 );

	sip = (struct selectinfo *)ld->ld_selectinfo;
	
/* 	sip->fds[0].revents = 0; */

	if ( timeout ) {
		tim = (timeout->tv_sec*1000)+(timeout->tv_usec/1000);
	} else {
		tim = INFTIM;
	} /* end if */
	errno=0;
#if defined( SUN ) && defined( _REENTRANT )
/*        UNLOCK_LDAP(ld); */
	LOCK_POLL(ld);
	rv = poll(sip->fds,sip->nbfds,tim);
/*	LOCK_LDAP(ld); */
	UNLOCK_POLL(ld);
	return(rv);
#else
	return( poll(sip->fds,sip->nbfds,tim) );
#endif
}
#else
/* for UNIX */
struct selectinfo {
	fd_set	si_readfds;
	fd_set	si_writefds;
	fd_set	si_use_readfds;
	fd_set	si_use_writefds;
};


void
mark_select_write( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	if ( !FD_ISSET( sb->sb_sd, &sip->si_writefds )) {
		FD_SET( sb->sb_sd, &sip->si_writefds );
	}
}


void
mark_select_read( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	if ( !FD_ISSET( sb->sb_sd, &sip->si_readfds )) {
		FD_SET( sb->sb_sd, &sip->si_readfds );
	}
}


void
mark_select_clear( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	FD_CLR( sb->sb_sd, &sip->si_writefds );
	FD_CLR( sb->sb_sd, &sip->si_readfds );
}


long
is_write_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	return( FD_ISSET( sb->sb_sd, &sip->si_use_writefds ));
}


long
is_read_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	return( FD_ISSET( sb->sb_sd, &sip->si_use_readfds ));
}


void *
new_select_info()
{
	struct selectinfo	*sip;

	if (( sip = (struct selectinfo *)calloc( 1,
	    sizeof( struct selectinfo ))) != NULL ) {
		FD_ZERO( &sip->si_readfds );
		FD_ZERO( &sip->si_writefds );
	}

	return( (void *)sip );
}


void
free_select_info( void *sip )
{
	free( sip );
}


int
do_ldap_select( LDAP *ld, struct timeval *timeout )
{
	struct selectinfo	*sip;
	static int		tblsize;

	Debug( LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 208, "do_ldap_select\n"), 0, 0, 0 );

#if defined( SUN ) && defined( _REENTRANT )
	LOCK_LDAP(ld);
#endif	
	if ( tblsize == 0 ) {
#ifdef USE_SYSCONF
		tblsize = (int)sysconf( _SC_OPEN_MAX );
#else /* USE_SYSCONF */
		tblsize = getdtablesize();
#endif /* USE_SYSCONF */
	}

	sip = (struct selectinfo *)ld->ld_selectinfo;
	sip->si_use_readfds = sip->si_readfds;
	sip->si_use_writefds = sip->si_writefds;
	
#if defined( SUN ) && defined( _REENTRANT )
	UNLOCK_LDAP(ld);
#endif
	return( select( tblsize, &sip->si_use_readfds, &sip->si_use_writefds,
	    NULL, timeout ));
}
#endif /* SUN */
#endif /* LDAP_REFERRALS */
