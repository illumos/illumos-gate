/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _PORT_NETDB_H
#define	_PORT_NETDB_H

#ifdef	__cplusplus
extern "C" {
#endif

/* AI_NUMERICSERV is not a valid flag for getaddrinfo */
#define	AI_MASK		0x0038	/* mask of valid flags */

/* EAI_OVERFLOW was removed from ISC */
#define	EAI_BADHINTS  12

/*
 * these are libresolv2 functions that were renamed in previous versions to
 * res_* because they conflict with libnsl or libsocket
 */

#define	endhostent res_endhostent /* libnsl */
void endhostent __P((void));
#define	endnetent res_endnetent  /* libsocket */
void endnetent __P((void));
#define	freeaddrinfo res_freeaddrinfo /* libsocket */
void freeaddrinfo __P((struct addrinfo *));
#define	freehostent res_freehostent  /* libsocket and libnsl */
void freehostent __P((struct hostent *));
#define	getaddrinfo res_getaddrinfo  /* libsocket */
int getaddrinfo __P((const char *, const char *,
				const struct addrinfo *, struct addrinfo **));
#define	gethostbyaddr res_gethostbyaddr /* libnsl */
struct hostent *gethostbyaddr __P((const char *, int, int));
#define	gethostbyname res_gethostbyname /* libnsl */
struct hostent *gethostbyname __P((const char *));
#define	gethostbyname2 res_gethostbyname2 /* lib/nsswitch/dns */
struct hostent *gethostbyname2 __P((const char *, int));
#define	gethostent res_gethostent  /* libnsl */
struct hostent *gethostent __P((void));
#define	getipnodebyaddr res_getipnodebyaddr  /* libnsl and libsocket */
struct hostent *getipnodebyaddr __P((const void *, size_t, int, int *));
#define	getipnodebyname res_getipnodebyname  /* libnsl and libsocket */
struct hostent *getipnodebyname __P((const char *, int, int, int *));

#define	getnetbyaddr res_getnetbyaddr /* libsocket */
struct netent *getnetbyaddr __P((unsigned long, int));
#define	getnetbyname res_getnetbyname /* libsocket */
struct netent *getnetbyname __P((const char *));
#define	getnetent res_getnetent /* libsocket */
struct netent *getnetent __P((void));
#define	sethostent res_sethostent /* libnsl */
void sethostent __P((int));
#define	setnetent res_setnetent /* libsocket */
void setnetent __P((int));

/*
 * these are other irs functions now included in libresolv.so.2. We rename the
 * ones that overlap with libsocket or libnsl
 */

/* endprotoent is in libsocket.so.1 */
#define	endprotoent res_endprotoent
void		endprotoent __P((void));

/* endservent is in libsocket.so.1 */
#define	endservent res_endservent
void		endservent __P((void));

/* note: the next two symbols are variables, not functions */

/* gai_errlist is in libsocket.so.1 */
#define	gai_errlist res_gai_errlist

/* gai_nerr is in libsocket.so.1 */
#define	gai_nerr res_gai_nerr

/* gai_strerror is in libsocket.so.1 */
#define	gai_strerror res_gai_strerror
const char *gai_strerror __P((int ecode));

/* gethostbyaddr_r is in libnsl.so.1 */
#define	gethostbyaddr_r res_gethostbyaddr_r
struct hostent *gethostbyaddr_r __P((const char *addr, int len, int type,
				struct hostent *hptr, char *buf,
				int buflen, int *h_errnop));

/* gethostbyname_r is in libnsl.so.1 */
#define	gethostbyname_r res_gethostbyname_r
struct hostent *gethostbyname_r __P((const char *name,	 struct hostent *hptr,
				char *buf, int buflen, int *h_errnop));

/* gethostent_r is in libnsl.so.1 */
#define	gethostent_r res_gethostent_r
struct hostent *gethostent_r __P((struct hostent *hptr, char *buf, int buflen,
				int *h_errnop));

/* getnameinfo is in libsocket.so.1 */
#define	getnameinfo res_getnameinfo
int getnameinfo __P((const struct sockaddr *, size_t, char *,
				size_t, char *, size_t, int));

/* getnetbyaddr_r is in libsocket.so.1 */
#define	getnetbyaddr_r res_getnetbyaddr_r
struct netent *getnetbyaddr_r __P((long, int, struct netent *, char *, int));

/* getnetbyname_r is in libsocket.so.1 */
#define	getnetbyname_r res_getnetbyname_r
struct netent *getnetbyname_r __P((const char *, struct netent *, char *, int));

/* getnetent_r is in libsocket.so.1 */
#define	getnetent_r res_getnetent_r
struct netent *getnetent_r __P((struct netent *, char *, int));

/* getprotobyname is in libsocket.so.1 */
#define	getprotobyname res_getprotobyname
struct protoent	*getprotobyname __P((const char *));

/* getprotobyname_r is in libsocket.so.1 */
#define	getprotobyname_r res_getprotobyname_r
struct protoent	*getprotobyname_r __P((const char *, struct protoent *,
				char *, int));

/* getprotobynumber is in libsocket.so.1 */
#define	getprotobynumber res_getprotobynumber
struct protoent	*getprotobynumber __P((int));

/* getprotobynumber_r is in libsocket.so.1 */
#define	getprotobynumber_r res_getprotobynumber_r
struct protoent	*getprotobynumber_r __P((int,
				struct protoent *, char *, int));

/* getprotoent is in libsocket.so.1 */
#define	getprotoent res_getprotoent
struct protoent	*getprotoent __P((void));

/* getprotoent_r is in libsocket.so.1 */
#define	getprotoent_r res_getprotoent_r
struct protoent	*getprotoent_r __P((struct protoent *, char *, int));

/* getservbyname is in libsocket.so.1 and libnsl.so.1 */
#define	getservbyname res_getservbyname
struct servent *getservbyname __P((const char *, const char *));

/* getservbyname_r is in libsocket.so.1 and libnsl.so.1 */
#define	getservbyname_r res_getservbyname_r
struct servent *getservbyname_r __P((const char *name, const char *,
				struct servent *, char *, int));

/* getservbyport is in libsocket.so.1 and libnsl.so.1 */
#define	getservbyport res_getservbyport
struct servent *getservbyport __P((int, const char *));

/* getservbyport_r is in libsocket.so.1 and libnsl.so.1 */
#define	getservbyport_r res_getservbyport_r
struct servent *getservbyport_r __P((int port, const char *,
				struct servent *, char *, int));

/* getservent is in libsocket.so.1 */
#define	getservent res_getservent
struct servent *getservent __P((void));

/* getservent_r is in libsocket.so.1 */
#define	getservent_r res_getservent_r
struct servent *getservent_r __P((struct servent *, char *, int));

/* innetgr is in libsocket.so.1 */
#define	innetgr res_innetgr
int innetgr __P((const char *, const char *, const char *, const char *));

/* setprotoent is in libsocket.so.1 */
#define	setprotoent res_setprotoent
void setprotoent __P((int));

/* setservent is in libsocket.so.1 */
#define	setservent res_setservent
void setservent __P((int));



#ifdef	__cplusplus
}
#endif

#endif /* _PORT_NETDB_H */
