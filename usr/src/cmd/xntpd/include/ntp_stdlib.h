/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ntp_stdlib.h - Prototypes for XNTP lib.
 */
#include <sys/types.h>

#include "ntp_types.h"
#include "ntp_string.h"
#include "l_stdlib.h"

#if defined(__STDC__)
extern	void	msyslog		P((int, const char *, ...));
#else
extern	void	msyslog		P(());
#endif

#if 0				/* HMS: These seem to be unused now */
extern	void	auth_des	P((u_long *, u_char *));
extern	int	auth_parity	P((u_long *));
extern	void	auth_setkey	P((u_long, u_long *));
extern	void	auth_subkeys	P((u_long *, u_char *, u_char *));

extern	void	auth_delkeys	P((void));

#endif

extern	void	auth1crypt	P((u_int32, u_int32 *, int));
extern	int	auth2crypt	P((u_int32, u_int32 *, int));
extern	void	auth_delkeys	P((void));
extern	int	auth_havekey	P((u_int32));
extern	int	authdecrypt	P((u_int32, u_int32 *, int));
extern	int	authencrypt	P((u_int32, u_int32 *, int));
extern	int	authhavekey	P((u_int32));
extern	int	authistrusted	P((u_int32));
extern	int	authreadkeys	P((const char *));
extern	void	authtrust	P((u_int32, int));
extern	int	authusekey	P((u_int32, int, const char *));

extern	void	calleapwhen	P((u_long, u_long *, u_long *));
extern	u_long	calyearstart	P((u_long));
extern	const char *clockname	P((int));
extern	int	clocktime	P((int, int, int, int, int, u_long, u_long *, u_int32 *));
extern	char *	emalloc		P((u_int));
extern	int	ntp_getopt	P((int, char **, const char *));
extern	void	init_auth	P((void));
extern	void	init_lib	P((void));
extern	void	init_random	P((void));
extern	struct savekey *auth_findkey P((u_int32));
extern	int	auth_moremem	P((void));

#ifdef	DES
extern	void	DESauth1crypt	P((u_int32, u_int32 *, int));
extern	int	DESauth2crypt	P((u_int32, u_int32 *, int));
extern	int	DESauthdecrypt	P((u_int32, const u_int32 *, int));
extern	int	DESauthencrypt	P((u_int32, u_int32 *, int));
extern	void	DESauth_setkey	P((u_int32, const u_int32 *));
extern	void	DESauth_subkeys	P((const u_int32 *, u_char *, u_char *));
extern	void	DESauth_des	P((u_int32 *, u_char *));
extern	int	DESauth_parity	P((u_int32 *));
#endif	/* DES */

#ifdef	MD5
extern	void	MD5auth1crypt	P((u_int32, u_int32 *, int));
extern	int	MD5auth2crypt	P((u_int32, u_int32 *, int));
extern	int	MD5authdecrypt	P((u_int32, const u_int32 *, int));
extern	int	MD5authencrypt	P((u_int32, u_int32 *, int));
extern	void	MD5auth_setkey	P((u_int32, const u_int32 *));
#endif	/* MD5 */

extern	int	atoint		P((const char *, long *));
extern	int	atouint		P((const char *, u_long *));
extern	int	hextoint	P((const char *, u_long *));
extern	char *	humandate	P((u_long));
extern	char *	inttoa		P((long));
extern	char *	mfptoa		P((u_long, u_long, int));
extern	char *	mfptoms		P((u_long, u_long, int));
extern	const char * modetoa	P((int));
extern  const char * eventstr   P((int));
extern  const char * ceventstr  P((int));
extern	char *	statustoa	P((int, int));
extern  const char * sysstatstr P((int));
extern  const char * peerstatstr P((int));
extern  const char * clockstatstr P((int));
extern	u_int32	netof		P((u_int32));
extern	char *	numtoa		P((u_int32));
extern	char *	numtohost	P((u_int32));
extern	int	octtoint	P((const char *, u_long *));
extern	u_long	ranp2		P((int));
extern	char *	refnumtoa	P((u_int32));
extern	int	tsftomsu	P((u_long, int));
extern	char *	uinttoa		P((u_long));

extern	int	decodenetnum	P((const char *, u_int32 *));

extern	char *	FindConfig	P((char *));

extern void signal_no_reset P((int, RETSIGTYPE (*func)(int)));
