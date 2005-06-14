/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _SOLARISINT_H
#define _SOLARISINT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>

#include "ldap.h"

/*
 * These were moved from lber.h. This should have been ifdef'd with
 * _SOLARIS_SDK but since we do not want to expose these in lber.h its
 * not possible to ifndef it there.
 */

/* BerElement set/get options */
#define LBER_OPT_REMAINING_BYTES	0x01
#define LBER_OPT_TOTAL_BYTES		0x02
#define LBER_OPT_USE_DER		0x04
#define LBER_OPT_TRANSLATE_STRINGS	0x08
#define LBER_OPT_BYTES_TO_WRITE		0x10
#define LBER_OPT_MEMALLOC_FN_PTRS	0x20
#define LBER_OPT_DEBUG_LEVEL		0x40
/*
 * LBER_USE_DER is defined for compatibility with the C LDAP API RFC.
 * In our implementation, we recognize it (instead of the numerically
 * identical LBER_OPT_REMAINING_BYTES) in calls to ber_alloc_t() and 
 * ber_init_w_nullchar() only.  Callers of ber_set_option() or
 * ber_get_option() must use LBER_OPT_USE_DER instead.  Sorry!
 */
#define LBER_USE_DER			0x01

/* Sockbuf set/get options */
#define LBER_SOCKBUF_OPT_TO_FILE		0x001
#define LBER_SOCKBUF_OPT_TO_FILE_ONLY		0x002
#define LBER_SOCKBUF_OPT_MAX_INCOMING_SIZE	0x004
#define LBER_SOCKBUF_OPT_NO_READ_AHEAD		0x008
#define LBER_SOCKBUF_OPT_DESC			0x010
#define LBER_SOCKBUF_OPT_COPYDESC		0x020
#define LBER_SOCKBUF_OPT_READ_FN		0x040
#define LBER_SOCKBUF_OPT_WRITE_FN		0x080
#define LBER_SOCKBUF_OPT_EXT_IO_FNS		0x100

#ifndef _SOLARIS_SDK
/*
 * The following is not used by solaris. Just kept to stay in sync with
 * iplanet and also a place holder (0x200)
 */
#define LBER_SOCKBUF_OPT_VALID_TAG              0x200
#endif	/* !_SOLARIS_SDK */

/*
 * Socket buffer structure associated to the LDAP connection
 */
#define LDAP_X_OPT_SOCKBUF	(LDAP_OPT_PRIVATE_EXTENSION_BASE + 0x0F02)
	/* 0x4000 + 0x0F02 = 0x4F02 = 20226 - API extension */


#define LBER_OPT_ON	((void *) 1)
#define LBER_OPT_OFF	((void *) 0)

/* Used in various functions */
#define LBER_FUNC_VALUE		-1

struct lextiof_socket_private;          /* Defined by the extended I/O */
                                        /* callback functions */
struct lextiof_session_private;         /* Defined by the extended I/O */
                                        /* callback functions */

/* This is modeled after the PRIOVec that is passed to the NSPR
   writev function! The void* is a char* in that struct */
typedef struct ldap_x_iovec {
        char    *ldapiov_base;
        int     ldapiov_len;
} ldap_x_iovec;

/*
 * libldap read and write I/O function callbacks.  The rest of the I/O callback
 * types are defined in ldap.h
 */
typedef int (LDAP_C LDAP_CALLBACK LDAP_IOF_READ_CALLBACK)( LBER_SOCKET s,
	void *buf, int bufsize );
typedef int (LDAP_C LDAP_CALLBACK LDAP_IOF_WRITE_CALLBACK)( LBER_SOCKET s,
	const void *buf, int len );
typedef int (LDAP_C LDAP_CALLBACK LDAP_X_EXTIOF_READ_CALLBACK)( int s,
	void *buf, int bufsize, struct lextiof_socket_private *arg );
typedef int (LDAP_C LDAP_CALLBACK LDAP_X_EXTIOF_WRITE_CALLBACK)( int s,
	const void *buf, int len, struct lextiof_socket_private *arg );
typedef int (LDAP_C LDAP_CALLBACK LDAP_X_EXTIOF_WRITEV_CALLBACK)(int s,
        const ldap_x_iovec iov[], int iovcnt, struct lextiof_socket_private *socketarg);


/*
 * Structure for use with LBER_SOCKBUF_OPT_EXT_IO_FNS:
 */
struct lber_x_ext_io_fns {
	    /* lbextiofn_size should always be set to LBER_X_EXTIO_FNS_SIZE */
	int				lbextiofn_size;
	LDAP_X_EXTIOF_READ_CALLBACK	*lbextiofn_read;
	LDAP_X_EXTIOF_WRITE_CALLBACK	*lbextiofn_write;
	struct lextiof_socket_private	*lbextiofn_socket_arg;
        LDAP_X_EXTIOF_WRITEV_CALLBACK   *lbextiofn_writev;
};
#define LBER_X_EXTIO_FNS_SIZE sizeof(struct lber_x_ext_io_fns)

/*
 * liblber memory allocation callback functions.  These are global to all
 *  Sockbufs and BerElements.  Install your own functions by using a call
 *  like this: ber_set_option( NULL, LBER_OPT_MEMALLOC_FN_PTRS, &memalloc_fns );
 */
typedef void * (LDAP_C LDAP_CALLBACK LDAP_MALLOC_CALLBACK)( size_t size );
typedef void * (LDAP_C LDAP_CALLBACK LDAP_CALLOC_CALLBACK)( size_t nelem,
	size_t elsize );
typedef void * (LDAP_C LDAP_CALLBACK LDAP_REALLOC_CALLBACK)( void *ptr,
	size_t size );
typedef void (LDAP_C LDAP_CALLBACK LDAP_FREE_CALLBACK)( void *ptr );

struct lber_memalloc_fns {
	LDAP_MALLOC_CALLBACK	*lbermem_malloc;
	LDAP_CALLOC_CALLBACK	*lbermem_calloc;
	LDAP_REALLOC_CALLBACK	*lbermem_realloc;
	LDAP_FREE_CALLBACK	*lbermem_free;
};

/*
 * Functions marked as Project Private in PSARC case and moved
 * from lber.h
 */
typedef struct sockbuf Sockbuf;

LDAP_API(void) LDAP_CALL ber_special_free(void* buf, BerElement *ber);
LDAP_API(void*) LDAP_CALL ber_special_alloc(size_t size, BerElement **ppBer);
LDAP_API(ber_uint_t) LDAP_CALL ber_get_next_buffer( void *buffer,
	size_t buffer_size, ber_len_t *len, BerElement *ber,
	ber_uint_t *Bytes_Scanned );
LDAP_API(ber_uint_t) LDAP_CALL ber_get_next_buffer_ext( void *buffer,
	size_t buffer_size, ber_len_t *len, BerElement *ber,
	ber_len_t *Bytes_Scanned, Sockbuf *sb );
LDAP_API(void) LDAP_CALL ber_init_w_nullchar( BerElement *ber, int options );
LDAP_API(int) LDAP_CALL ber_set_option( BerElement *ber, int option, 
	void *value );
LDAP_API(int) LDAP_CALL ber_get_option( BerElement *ber, int option, 
	void *value );
LDAP_API(Sockbuf*) LDAP_CALL ber_sockbuf_alloc( void );
LDAP_API(void) LDAP_CALL ber_sockbuf_free( Sockbuf* p );
LDAP_API(int) LDAP_CALL ber_sockbuf_set_option( Sockbuf *sb, int option, 
	void *value );
LDAP_API(int) LDAP_CALL ber_sockbuf_get_option( Sockbuf *sb, int option, 
	void *value );
LDAP_API(int) LDAP_CALL ber_flush( Sockbuf *sb, BerElement *ber, int freeit );
LDAP_API(ber_tag_t) LDAP_CALL ber_get_next( Sockbuf *sb, ber_len_t *len,
	BerElement *ber );

/*
 * The following was moved from ldap.h
 */

/*
 * These extended I/O function callbacks echo the BSD socket API but accept
 * an extra pointer parameter at the end of their argument list that can
 * be used by client applications for their own needs.  For some of the calls,
 * the pointer is a session argument of type struct lextiof_session_private *
 * that is associated with the LDAP session handle (LDAP *).  For others, the
 * pointer is a socket specific struct lextiof_socket_private * argument that
 * is associated with a particular socket (a TCP connection).
 *
 * The lextiof_session_private and lextiof_socket_private structures are not
 * defined by the LDAP C API; users of this extended I/O interface should
 * define these themselves.
 *
 * The combination of the integer socket number (i.e., lpoll_fd, which is
 * the value returned by the CONNECT callback) and the application specific
 * socket argument (i.e., lpoll_socketarg, which is the value set in *sockargpp
 * by the CONNECT callback) must be unique.
 *
 * The types for the extended READ and WRITE callbacks are actually in lber.h.
 *
 * The CONNECT callback gets passed both the session argument (sessionarg)
 * and a pointer to a socket argument (socketargp) so it has the
 * opportunity to set the socket-specific argument.  The CONNECT callback
 * also takes a timeout parameter whose value can be set by calling
 * ldap_set_option( ld, LDAP_X_OPT_..., &val ).  The units used for the
 * timeout parameter are milliseconds.
 *
 * A POLL interface is provided instead of a select() one.  The timeout is
 * in milliseconds.

 * A NEWHANDLE callback function is also provided.  It is called right
 * after the LDAP session handle is created, e.g., during ldap_init().
 * If the NEWHANDLE callback returns anything other than LDAP_SUCCESS,
 * the session handle allocation fails.
 *
 * A DISPOSEHANDLE callback function is also provided.  It is called right
 * before the LDAP session handle and its contents are destroyed, e.g.,
 * during ldap_unbind().
 */

/* LDAP poll()-like descriptor:
 */
typedef struct ldap_x_pollfd {	   /* used by LDAP_X_EXTIOF_POLL_CALLBACK */
    int		lpoll_fd;	   /* integer file descriptor / socket */
    struct lextiof_socket_private
		*lpoll_socketarg;
				   /* pointer socket and for use by */
				   /* application */
    short	lpoll_events;      /* requested event */
    short	lpoll_revents;     /* returned event */
} LDAP_X_PollFD;

/* Event flags for lpoll_events and lpoll_revents:
 */
#define LDAP_X_POLLIN    0x01  /* regular data ready for reading */
#define LDAP_X_POLLPRI   0x02  /* high priority data available */
#define LDAP_X_POLLOUT   0x04  /* ready for writing */
#define LDAP_X_POLLERR   0x08  /* error occurred -- only in lpoll_revents */
#define LDAP_X_POLLHUP   0x10  /* connection closed -- only in lpoll_revents */
#define LDAP_X_POLLNVAL  0x20  /* invalid lpoll_fd -- only in lpoll_revents */

/* Options passed to LDAP_X_EXTIOF_CONNECT_CALLBACK to modify socket behavior:
 */
#define LDAP_X_EXTIOF_OPT_NONBLOCKING	0x01  /* turn on non-blocking mode */
#define LDAP_X_EXTIOF_OPT_SECURE	0x02  /* turn on 'secure' mode */

/* extended I/O callback function prototypes:
 */
typedef int	(LDAP_C LDAP_CALLBACK LDAP_X_EXTIOF_CONNECT_CALLBACK )(
	    const char *hostlist, int port, /* host byte order */
	    int timeout /* milliseconds */,
	    unsigned long options, /* bitmapped options */
	    struct lextiof_session_private *sessionarg,
	    struct lextiof_socket_private **socketargp
#ifdef _SOLARIS_SDK
		, void **datapriv );
#else
		);
#endif
typedef int	(LDAP_C LDAP_CALLBACK LDAP_X_EXTIOF_CLOSE_CALLBACK )(
	    int s, struct lextiof_socket_private *socketarg );
typedef int	(LDAP_C LDAP_CALLBACK LDAP_X_EXTIOF_POLL_CALLBACK)(
	    LDAP_X_PollFD fds[], int nfds, int timeout /* milliseconds */,
	    struct lextiof_session_private *sessionarg );
typedef int	(LDAP_C LDAP_CALLBACK LDAP_X_EXTIOF_NEWHANDLE_CALLBACK)(
	    LDAP *ld, struct lextiof_session_private *sessionarg );
typedef void	(LDAP_C LDAP_CALLBACK LDAP_X_EXTIOF_DISPOSEHANDLE_CALLBACK)(
	    LDAP *ld, struct lextiof_session_private *sessionarg );


/* Structure to hold extended I/O function pointers:
 */
struct ldap_x_ext_io_fns {
	/* lextiof_size should always be set to LDAP_X_EXTIO_FNS_SIZE */
	int					lextiof_size;
	LDAP_X_EXTIOF_CONNECT_CALLBACK		*lextiof_connect;
	LDAP_X_EXTIOF_CLOSE_CALLBACK		*lextiof_close;
	LDAP_X_EXTIOF_READ_CALLBACK		*lextiof_read;
	LDAP_X_EXTIOF_WRITE_CALLBACK		*lextiof_write;
	LDAP_X_EXTIOF_POLL_CALLBACK		*lextiof_poll;
	LDAP_X_EXTIOF_NEWHANDLE_CALLBACK	*lextiof_newhandle;
	LDAP_X_EXTIOF_DISPOSEHANDLE_CALLBACK	*lextiof_disposehandle;
	void					*lextiof_session_arg;
	LDAP_X_EXTIOF_WRITEV_CALLBACK           *lextiof_writev;
};
#define LDAP_X_EXTIO_FNS_SIZE	sizeof(struct ldap_x_ext_io_fns)


/*
 * Utility functions for parsing space-separated host lists (useful for
 * implementing an extended I/O CONNECT callback function).
 */
struct ldap_x_hostlist_status;
LDAP_API(int) LDAP_CALL ldap_x_hostlist_first( const char *hostlist,
	int defport, char **hostp, int *portp /* host byte order */,
	struct ldap_x_hostlist_status **statusp );
LDAP_API(int) LDAP_CALL ldap_x_hostlist_next( char **hostp,
	int *portp /* host byte order */, struct ldap_x_hostlist_status *status );
LDAP_API(void) LDAP_CALL ldap_x_hostlist_statusfree(
	struct ldap_x_hostlist_status *status );


/*
 * I/O callback functions (note that types for the read and write callbacks
 * are actually in lber.h):
 */
typedef int	(LDAP_C LDAP_CALLBACK LDAP_IOF_SELECT_CALLBACK)( int nfds,
	fd_set *readfds, fd_set *writefds, fd_set *errorfds,
	struct timeval *timeout );
typedef LBER_SOCKET (LDAP_C LDAP_CALLBACK LDAP_IOF_SOCKET_CALLBACK)(
	int domain, int type, int protocol );
typedef int	(LDAP_C LDAP_CALLBACK LDAP_IOF_IOCTL_CALLBACK)( LBER_SOCKET s, 
	int option, ... );
typedef int	(LDAP_C LDAP_CALLBACK LDAP_IOF_CONNECT_CALLBACK )(
	LBER_SOCKET s, struct sockaddr *name, int namelen );
typedef int	(LDAP_C LDAP_CALLBACK LDAP_IOF_CLOSE_CALLBACK )(
	LBER_SOCKET s );
typedef int	(LDAP_C LDAP_CALLBACK LDAP_IOF_SSL_ENABLE_CALLBACK )(
	LBER_SOCKET s );


/*
 * Structure to hold I/O function pointers:
 */
struct ldap_io_fns {
	LDAP_IOF_READ_CALLBACK *liof_read;
	LDAP_IOF_WRITE_CALLBACK *liof_write;
	LDAP_IOF_SELECT_CALLBACK *liof_select;
	LDAP_IOF_SOCKET_CALLBACK *liof_socket;
	LDAP_IOF_IOCTL_CALLBACK *liof_ioctl;
	LDAP_IOF_CONNECT_CALLBACK *liof_connect;
	LDAP_IOF_CLOSE_CALLBACK *liof_close;
	LDAP_IOF_SSL_ENABLE_CALLBACK *liof_ssl_enable;
};

/********* the functions in the following section are experimental ***********/

#define	LDAP_OPT_PREFERRED_LANGUAGE	0x14	/* 20 - API extension */

/*
 * SSL option (an API extension):
 */
#define	LDAP_OPT_SSL			0x0A	/* 10 - API extension */

/*
 * Referral hop limit (an API extension):
 */
#define	LDAP_OPT_REFERRAL_HOP_LIMIT	0x10	/* 16 - API extension */

/*
 * DNS resolver callbacks (an API extension --LDAP_API_FEATURE_X_DNS_FUNCTIONS).
 * Note that gethostbyaddr() is not currently used.
 */
#define	LDAP_OPT_DNS_FN_PTRS		0x60	/* 96 - API extension */

typedef struct LDAPHostEnt {
    char	*ldaphe_name;		/* official name of host */
    char	**ldaphe_aliases;	/* alias list */
    int		ldaphe_addrtype;	/* host address type */
    int		ldaphe_length;		/* length of address */
    char	**ldaphe_addr_list;	/* list of addresses from name server */
} LDAPHostEnt;

typedef LDAPHostEnt * (LDAP_C LDAP_CALLBACK LDAP_DNSFN_GETHOSTBYNAME)(
	const char *name, LDAPHostEnt *result, char *buffer,
	int buflen, int *statusp, void *extradata);
typedef LDAPHostEnt * (LDAP_C LDAP_CALLBACK LDAP_DNSFN_GETHOSTBYADDR)(
	const char *addr, int length, int type, LDAPHostEnt *result,
	char *buffer, int buflen, int *statusp, void *extradata);
typedef int (LDAP_C LDAP_CALLBACK LDAP_DNSFN_GETPEERNAME)(
	LDAP *ld, struct sockaddr *netaddr, char *buffer, int buflen);

struct ldap_dns_fns {
	void				*lddnsfn_extradata;
	int				lddnsfn_bufsize;
	LDAP_DNSFN_GETHOSTBYNAME	*lddnsfn_gethostbyname;
	LDAP_DNSFN_GETHOSTBYADDR	*lddnsfn_gethostbyaddr;
	LDAP_DNSFN_GETPEERNAME		*lddnsfn_getpeername;
};

/*
 * Generalized cache callback interface:
 */
#define	LDAP_OPT_CACHE_FN_PTRS		0x0D	/* 13 - API extension */
#define	LDAP_OPT_CACHE_STRATEGY		0x0E	/* 14 - API extension */
#define	LDAP_OPT_CACHE_ENABLE		0x0F	/* 15 - API extension */

/* cache strategies */
#define	LDAP_CACHE_CHECK		0
#define	LDAP_CACHE_POPULATE		1
#define	LDAP_CACHE_LOCALDB		2

typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_BIND_CALLBACK)(LDAP *ld, int msgid,
	ber_tag_t tag, const char *dn, const struct berval *creds,
	int method);
typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_UNBIND_CALLBACK)(LDAP *ld,
	int unused0, unsigned long unused1);
typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_SEARCH_CALLBACK)(LDAP *ld,
	int msgid, ber_tag_t tag, const char *base, int scope,
	const char LDAP_CALLBACK *filter, char **attrs, int attrsonly);
typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_COMPARE_CALLBACK)(LDAP *ld,
	int msgid, ber_tag_t tag, const char *dn, const char *attr,
	const struct berval *value);
typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_ADD_CALLBACK)(LDAP *ld,
	int msgid, ber_tag_t tag, const char *dn, LDAPMod **attrs);
typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_DELETE_CALLBACK)(LDAP *ld,
	int msgid, ber_tag_t tag, const char *dn);
typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_MODIFY_CALLBACK)(LDAP *ld,
	int msgid, ber_tag_t tag, const char *dn, LDAPMod **mods);
typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_MODRDN_CALLBACK)(LDAP *ld,
	int msgid, ber_tag_t tag, const char *dn, const char *newrdn,
	int deleteoldrdn);
typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_RESULT_CALLBACK)(LDAP *ld,
	int msgid, int all, struct timeval *timeout, LDAPMessage **result);
typedef int (LDAP_C LDAP_CALLBACK LDAP_CF_FLUSH_CALLBACK)(LDAP *ld,
	const char *dn, const char *filter);

struct ldap_cache_fns {
	void    *lcf_private;
	LDAP_CF_BIND_CALLBACK *lcf_bind;
	LDAP_CF_UNBIND_CALLBACK *lcf_unbind;
	LDAP_CF_SEARCH_CALLBACK *lcf_search;
	LDAP_CF_COMPARE_CALLBACK *lcf_compare;
	LDAP_CF_ADD_CALLBACK *lcf_add;
	LDAP_CF_DELETE_CALLBACK *lcf_delete;
	LDAP_CF_MODIFY_CALLBACK *lcf_modify;
	LDAP_CF_MODRDN_CALLBACK *lcf_modrdn;
	LDAP_CF_RESULT_CALLBACK *lcf_result;
	LDAP_CF_FLUSH_CALLBACK *lcf_flush;
};

int LDAP_CALL ldap_cache_flush(LDAP *ld, const char *dn,
	const char *filter);

/*
 * Memory allocation callback functions (an API extension --
 * LDAP_API_FEATURE_X_MEMALLOC_FUNCTIONS).  These are global and can
 * not be set on a per-LDAP session handle basis.  Install your own
 * functions by making a call like this:
 *    ldap_set_option( NULL, LDAP_OPT_MEMALLOC_FN_PTRS, &memalloc_fns );
 *
 * look in lber.h for the function typedefs themselves.
 */
#define LDAP_OPT_MEMALLOC_FN_PTRS	0x61	/* 97 - API extension */

struct ldap_memalloc_fns {
	LDAP_MALLOC_CALLBACK	*ldapmem_malloc;
	LDAP_CALLOC_CALLBACK	*ldapmem_calloc;
	LDAP_REALLOC_CALLBACK	*ldapmem_realloc;
	LDAP_FREE_CALLBACK	*ldapmem_free;
};


/*
 * Memory allocation functions (an API extension)
 */
void *ldap_x_malloc( size_t size );
void *ldap_x_calloc( size_t nelem, size_t elsize );
void *ldap_x_realloc( void *ptr, size_t size );
void ldap_x_free( void *ptr );

/*
 * Extra thread callback functions (an API extension --
 * LDAP_API_FEATURE_X_EXTHREAD_FUNCTIONS)
 */
#define LDAP_OPT_EXTRA_THREAD_FN_PTRS  0x65	/* 101 - API extension */

typedef int (LDAP_C LDAP_CALLBACK LDAP_TF_MUTEX_TRYLOCK_CALLBACK)( void *m );
typedef void *(LDAP_C LDAP_CALLBACK LDAP_TF_SEMA_ALLOC_CALLBACK)( void );
typedef void (LDAP_C LDAP_CALLBACK LDAP_TF_SEMA_FREE_CALLBACK)( void *s );
typedef int (LDAP_C LDAP_CALLBACK LDAP_TF_SEMA_WAIT_CALLBACK)( void *s );
typedef int (LDAP_C LDAP_CALLBACK LDAP_TF_SEMA_POST_CALLBACK)( void *s );
typedef void *(LDAP_C LDAP_CALLBACK LDAP_TF_THREADID_CALLBACK)(void);

struct ldap_extra_thread_fns {
        LDAP_TF_MUTEX_TRYLOCK_CALLBACK *ltf_mutex_trylock;
        LDAP_TF_SEMA_ALLOC_CALLBACK *ltf_sema_alloc;
        LDAP_TF_SEMA_FREE_CALLBACK *ltf_sema_free;
        LDAP_TF_SEMA_WAIT_CALLBACK *ltf_sema_wait;
        LDAP_TF_SEMA_POST_CALLBACK *ltf_sema_post;
	LDAP_TF_THREADID_CALLBACK *ltf_threadid_fn;
};


/*
 * Debugging level (an API extension)
 */
#define LDAP_OPT_DEBUG_LEVEL		0x6E	/* 110 - API extension */
/* On UNIX, there's only one copy of ldap_debug */
/* On NT, each dll keeps its own module_ldap_debug, which */
/* points to the process' ldap_debug and needs initializing after load */
#ifdef _WIN32
extern int		*module_ldap_debug;
typedef void (*set_debug_level_fn_t)(int*);
#endif

/************************ end of experimental section ************************/


LDAP_API(int) LDAP_CALL ldap_keysort_entries( LDAP *ld, LDAPMessage **chain,
	void *arg, LDAP_KEYGEN_CALLBACK *gen, LDAP_KEYCMP_CALLBACK *cmp,
	LDAP_KEYFREE_CALLBACK *fre );

/*
 * utility routines
 */
LDAP_API(int) LDAP_CALL ldap_charray_add( char ***a, char *s );
LDAP_API(int) LDAP_CALL ldap_charray_merge( char ***a, char **s );
LDAP_API(void) LDAP_CALL ldap_charray_free( char **array );
LDAP_API(int) LDAP_CALL ldap_charray_inlist( char **a, char *s );
LDAP_API(char **) LDAP_CALL ldap_charray_dup( char **a );
LDAP_API(char **) LDAP_CALL ldap_str2charray( char *str, char *brkstr );
LDAP_API(int) LDAP_CALL ldap_charray_position( char **a, char *s );

/*
 * UTF-8 routines (should these move into libnls?)
 */
/* number of bytes in character */
LDAP_API(int) LDAP_CALL ldap_utf8len( const char* );
/* find next character */
LDAP_API(char*) LDAP_CALL ldap_utf8next( char* );
/* find previous character */
LDAP_API(char*) LDAP_CALL ldap_utf8prev( char* );
/* copy one character */
LDAP_API(int) LDAP_CALL ldap_utf8copy( char* dst, const char* src );
/* total number of characters */
LDAP_API(size_t) LDAP_CALL ldap_utf8characters( const char* );
/* get one UCS-4 character, and move *src to the next character */
LDAP_API(unsigned long) LDAP_CALL ldap_utf8getcc( const char** src );
/* UTF-8 aware strtok_r() */
LDAP_API(char*) LDAP_CALL ldap_utf8strtok_r( char* src, const char* brk, char** next);

/* like isalnum(*s) in the C locale */
LDAP_API(int) LDAP_CALL ldap_utf8isalnum( char* s );
/* like isalpha(*s) in the C locale */
LDAP_API(int) LDAP_CALL ldap_utf8isalpha( char* s );
/* like isdigit(*s) in the C locale */
LDAP_API(int) LDAP_CALL ldap_utf8isdigit( char* s );
/* like isxdigit(*s) in the C locale */
LDAP_API(int) LDAP_CALL ldap_utf8isxdigit(char* s );
/* like isspace(*s) in the C locale */
LDAP_API(int) LDAP_CALL ldap_utf8isspace( char* s );

#define LDAP_UTF8LEN(s)  ((0x80 & *(unsigned char*)(s)) ?   ldap_utf8len (s) : 1)
#define LDAP_UTF8NEXT(s) ((0x80 & *(unsigned char*)(s)) ?   ldap_utf8next(s) : (s)+1)
#define LDAP_UTF8INC(s)  ((0x80 & *(unsigned char*)(s)) ? s=ldap_utf8next(s) : ++s)

#define LDAP_UTF8PREV(s)   ldap_utf8prev(s)
#define LDAP_UTF8DEC(s) (s=ldap_utf8prev(s))

#define LDAP_UTF8COPY(d,s) ((0x80 & *(unsigned char*)(s)) ? ldap_utf8copy(d,s) : ((*(d) = *(s)), 1))
#define LDAP_UTF8GETCC(s) ((0x80 & *(unsigned char*)(s)) ? ldap_utf8getcc (&s) : *s++)
#define LDAP_UTF8GETC(s) ((0x80 & *(unsigned char*)(s)) ? ldap_utf8getcc ((const char**)&s) : *s++)

#ifdef __cplusplus
}
#endif
#endif /* _SOLARISINT_H */

