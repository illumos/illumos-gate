/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include "tip.h"

extern int	df02_dialer(char *, char *), df03_dialer(char *, char *);
extern int	biz31f_dialer(char *, char *), biz31w_dialer(char *, char *);
extern int	biz22f_dialer(char *, char *), biz22w_dialer(char *, char *);
extern int	hayes_dialer(char *, char *);
extern int	ven_dialer(char *, char *);
extern int	v3451_dialer(char *, char *);
extern int	v831_dialer(char *, char *);
extern int	dn_dialer(char *, char *);
extern void	df_disconnect(void), df_abort(void);
extern void	biz31_disconnect(void), biz31_abort(void);
extern void	biz22_disconnect(void), biz22_abort(void);
extern void	hayes_disconnect(void), hayes_abort(void);
extern void	ven_disconnect(void), ven_abort(void);
extern void	v3451_disconnect(void), v3451_abort(void);
extern void	v831_disconnect(void), v831_abort(void);
extern void	dn_disconnect(void), dn_abort(void);

acu_t acutable[] = {
#if BIZ1031
	"biz31f", biz31f_dialer, biz31_disconnect,	biz31_abort,
	"biz31w", biz31w_dialer, biz31_disconnect,	biz31_abort,
#endif
#if BIZ1022
	"biz22f", biz22f_dialer, biz22_disconnect,	biz22_abort,
	"biz22w", biz22w_dialer, biz22_disconnect,	biz22_abort,
#endif
#if DF02
	"df02",	df02_dialer,	df_disconnect,		df_abort,
#endif
#if DF03
	"df03",	df03_dialer,	df_disconnect,		df_abort,
#endif
#if DN11
	"dn11",	dn_dialer,	dn_disconnect,		dn_abort,
#endif
#ifdef VENTEL
	"ventel", ven_dialer,	ven_disconnect,		ven_abort,
#endif
#ifdef V3451
#ifndef V831
	"vadic", v3451_dialer,	v3451_disconnect,	v3451_abort,
#endif
	"v3451", v3451_dialer,	v3451_disconnect,	v3451_abort,
#endif
#ifdef V831
#ifndef V3451
	"vadic", v831_dialer,	v831_disconnect,	v831_abort,
#endif
	"v831", v831_dialer,	v831_disconnect,	v831_abort,
#endif
#ifdef HAYES
	"hayes", hayes_dialer,	hayes_disconnect,	hayes_abort,
	"at",	hayes_dialer,	hayes_disconnect,	hayes_abort,
#endif
	NULL,	NULL,		NULL,			NULL
};
