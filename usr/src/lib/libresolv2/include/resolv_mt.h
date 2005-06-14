/*
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 */

#ifndef	_RESOLV_MT_H
#define	_RESOLV_MT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	SUNW_MT_RESOLVER

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

/* Access functions for the libresolv private interface */

int			__res_enable_mt(void);
int			__res_disable_mt(void);

/* Per-thread context */

typedef struct {
#ifdef SUNW_HOSTS_FALLBACK
	int				no_hosts_fallback_private;
#endif /* SUNW_HOSTS_FALLBACK */
#ifdef	SUNW_OVERRIDE_RETRY
	int				retry_save;
	int				retry_private;
#endif	/* SUNW_OVERRIDE_RETRY */
	char				inet_nsap_ntoa_tmpbuf[255*3];
	char				sym_ntos_unname[20];
	char				sym_ntop_unname[20];
	char				p_option_nbuf[40];
	char				p_time_nbuf[40];
	char				precsize_ntoa_retbuf[sizeof "90000000.00"];
	char				loc_ntoa_tmpbuf[sizeof
"1000 60 60.000 N 1000 60 60.000 W -12345678.00m 90000000.00m 90000000.00m 90000000.00m"];
	char				p_secstodate_output[15];
} mtctxres_t;

/* Thread-specific data (TSD) */

extern mtctxres_t			*___mtctxres();
#define	mtctxres			(___mtctxres())

/* Various static data that should be TSD */

#define	sym_ntos_unname			(mtctxres->sym_ntos_unname)
#define	sym_ntop_unname			(mtctxres->sym_ntop_unname)
#define	inet_nsap_ntoa_tmpbuf		(mtctxres->inet_nsap_ntoa_tmpbuf)
#define	p_option_nbuf			(mtctxres->p_option_nbuf)
#define	p_time_nbuf			(mtctxres->p_time_nbuf)
#define	precsize_ntoa_retbuf		(mtctxres->precsize_ntoa_retbuf)
#define	loc_ntoa_tmpbuf			(mtctxres->loc_ntoa_tmpbuf)
#define	p_secstodate_output		(mtctxres->p_secstodate_output)

#endif /* SUNW_MT_RESOLVER */

#ifdef	__cplusplus
}
#endif

#endif /* _RESOLV_MT_H */
