
#ifndef _PORT_SOCKET_H
#define _PORT_SOCKET_H
#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>

/* Some of our own infrastructure where the WinSock stuff was too hairy
   to dump into a clean Unix program...  */

typedef WSABUF sg_buf;

#define SG_ADVANCE(SG, N) \
	((SG)->len < (N)				\
	 ? (abort(), 0)					\
	 : ((SG)->buf += (N), (SG)->len -= (N), 0))

#define SG_LEN(SG)		((SG)->len + 0)
#define SG_BUF(SG)		((SG)->buf + 0)
#define SG_SET(SG, B, N)	((SG)->buf = (char *)(B),(SG)->len = (N))

#define SOCKET_INITIALIZE()     0
#define SOCKET_CLEANUP()
#define SOCKET_ERRNO            (WSAGetLastError())
#define SOCKET_SET_ERRNO(x)     (WSASetLastError (x))
#define SOCKET_NFDS(f)          (0)     /* select()'s first arg is ignored */
#define SOCKET_READ(fd, b, l)   (recv(fd, b, l, 0))
#define SOCKET_WRITE(fd, b, l)  (send(fd, b, l, 0))
#define SOCKET_CONNECT		connect	/* XXX */
#define SOCKET_GETSOCKNAME	getsockname /* XXX */
#define SOCKET_CLOSE		close /* XXX */
#define SOCKET_EINTR            WSAEINTR

/* Return -1 for error or number of bytes written.
   TMP is a temporary variable; must be declared by the caller, and
   must be used by this macro (to avoid compiler warnings).  */
/* WSASend returns 0 or SOCKET_ERROR.  */
#define SOCKET_WRITEV_TEMP DWORD
#define SOCKET_WRITEV(FD, SG, LEN, TMP)	\
	(WSASend((FD), (SG), (LEN), &(TMP), 0, 0, 0) ? -1 : (TMP))

#define SHUTDOWN_READ	SD_RECEIVE
#define SHUTDOWN_WRITE	SD_SEND
#define SHUTDOWN_BOTH	SD_BOTH

#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#ifndef ECONNRESET
#define ECONNRESET  WSAECONNRESET
#endif
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH WSAEHOSTUNREACH
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT WSAETIMEDOUT
#endif

#elif defined(__palmos__)

/* If this source file requires it, define struct sockaddr_in
   (and possibly other things related to network I/O).  */

#include "autoconf.h"
#include <netdb.h>
typedef int socklen_t;

#else /* UNIX variants */

#include "autoconf.h"

#include <sys/types.h>
#include <netinet/in.h>		/* For struct sockaddr_in and in_addr */
#include <arpa/inet.h>		/* For inet_ntoa */
#include <netdb.h>

#ifndef HAVE_NETDB_H_H_ERRNO
extern int h_errno;		/* In case it's missing, e.g., HP-UX 10.20. */
#endif

#include <sys/param.h>		/* For MAXHOSTNAMELEN */
#include <sys/socket.h>		/* For SOCK_*, AF_*, etc */
#include <sys/time.h>		/* For struct timeval */
#include <net/if.h>		/* For struct ifconf, for localaddr.c */
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>		/* For struct iovec, for sg_buf */
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>		/* For FIONBIO on Solaris.  */
#endif

/* Either size_t or int or unsigned int is probably right.  Under
   SunOS 4, it looks like int is desired, according to the accept man
   page.  */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

/* XXX should only be done if sockaddr_storage not found */
#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
struct krb5int_sockaddr_storage {
    struct sockaddr_in s;
    /* Plenty of slop just in case we get an ipv6 address anyways.  */
    long extra[16];
};
#define sockaddr_storage krb5int_sockaddr_storage
#endif

/*
 * Compatability with WinSock calls on MS-Windows...
 */
#define	SOCKET		int
#define	INVALID_SOCKET	((SOCKET)~0)
#define	closesocket	close
#define	ioctlsocket	ioctl
#define	SOCKET_ERROR	(-1)

typedef struct iovec sg_buf;

#define SG_ADVANCE(SG, N) \
	((SG)->iov_len < (N)					\
	 ? (abort(), 0)						\
	 : ((SG)->iov_base = (char *) (SG)->iov_base + (N),	\
	    (SG)->iov_len -= (N), 0))

#define SG_LEN(SG)		((SG)->iov_len + 0)
#define SG_BUF(SG)		((char*)(SG)->iov_base + 0)
#define SG_SET(SG, B, L)	((SG)->iov_base = (char*)(B), (SG)->iov_len = (L))

/* Some of our own infrastructure where the WinSock stuff was too hairy
   to dump into a clean Unix program...  */

#define	SOCKET_INITIALIZE()	(0)	/* No error (or anything else) */
#define	SOCKET_CLEANUP()	/* nothing */
#define	SOCKET_ERRNO		errno
#define	SOCKET_SET_ERRNO(x)	(errno = (x))
#define SOCKET_NFDS(f)		((f)+1)	/* select() arg for a single fd */
#define SOCKET_READ		read
#define SOCKET_WRITE		write
#define SOCKET_CONNECT		connect
#define SOCKET_GETSOCKNAME	getsockname
#define SOCKET_CLOSE		close
#define SOCKET_EINTR		EINTR
#define SOCKET_WRITEV_TEMP int
/* Use TMP to avoid compiler warnings and keep things consistent with
   Windoze version.  */
#define SOCKET_WRITEV(FD, SG, LEN, TMP) \
	((TMP) = writev((FD), (SG), (LEN)), (TMP))

#define SHUTDOWN_READ	0
#define SHUTDOWN_WRITE	1
#define SHUTDOWN_BOTH	2

#ifndef HAVE_INET_NTOP
#define inet_ntop(AF,SRC,DST,CNT)					    \
    ((AF) == AF_INET							    \
     ? ((CNT) < 16							    \
	? (SOCKET_SET_ERRNO(ENOSPC), (const char *)NULL)		    \
	: (sprintf((DST), "%d.%d.%d.%d",				    \
		   ((const unsigned char *)(const void *)(SRC))[0] & 0xff,  \
		   ((const unsigned char *)(const void *)(SRC))[1] & 0xff,  \
		   ((const unsigned char *)(const void *)(SRC))[2] & 0xff,  \
		   ((const unsigned char *)(const void *)(SRC))[3] & 0xff), \
	   (DST)))							    \
     : (SOCKET_SET_ERRNO(EAFNOSUPPORT), (const char *)NULL))
#define HAVE_INET_NTOP
#endif

#endif /* _WIN32 */

#if !defined(_WIN32)
/* UNIX or ...?  */
# ifdef S_SPLINT_S
extern int socket (int, int, int) /*@*/;
# endif
#endif

#endif /*_PORT_SOCKET_H*/
