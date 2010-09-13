/*
 * Copyright (c) 2004, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Ucred.xs contains XS wrappers for the process privilege maniplulation
 * functions.
 */


/* Solaris includes. */
#include <ucred.h>
#include <priv.h>

/* Perl includes. */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

typedef int sysret;
typedef priv_set_t Sun__Solaris__Privilege__Privset;
typedef ucred_t Sun__Solaris__Ucred__Ucred;

static priv_set_t *
dupset(const priv_set_t *s)
{
	priv_set_t *new = priv_allocset();
	if (new == NULL)
		return (NULL);

	priv_copyset(s, new);
	return (new);
}

#define	RETPRIVSET(set)		\
	ST(0) = sv_newmortal();						\
	sv_setref_pv(ST(0), "Sun::Solaris::Privilege::PrivsetPtr",	\
	    (void*)(set));						\
	SvREADONLY_on(SvRV(ST(0)))

#define	RETUCRED(uc)		\
	ST(0) = sv_newmortal();						\
	sv_setref_pv(ST(0), "Sun::Solaris::Ucred::UcredPtr",		\
	    (void*)(uc));						\
	SvREADONLY_on(SvRV(ST(0)))
/*
 * The XS code exported to perl is below here.  Note that the XS preprocessor
 * has its own commenting syntax, so all comments from this point on are in
 * that form.
 */

MODULE = Sun::Solaris::Ucred PACKAGE = Sun::Solaris::Ucred
PROTOTYPES: ENABLE

Sun::Solaris::Ucred::Ucred *
ucred_get(pid);
	pid_t pid;

uid_t
ucred_geteuid(uc)
	Sun::Solaris::Ucred::Ucred *uc;

uid_t
ucred_getruid(uc)
	Sun::Solaris::Ucred::Ucred *uc;

uid_t
ucred_getsuid(uc)
	Sun::Solaris::Ucred::Ucred *uc;

gid_t
ucred_getegid(uc)
	Sun::Solaris::Ucred::Ucred *uc;

gid_t
ucred_getrgid(uc)
	Sun::Solaris::Ucred::Ucred *uc;

gid_t
ucred_getsgid(uc)
	Sun::Solaris::Ucred::Ucred *uc;

pid_t
ucred_getpid(uc)
	Sun::Solaris::Ucred::Ucred *uc;

zoneid_t
ucred_getzoneid(uc)
	Sun::Solaris::Ucred::Ucred *uc;

projid_t
ucred_getprojid(uc)
	Sun::Solaris::Ucred::Ucred *uc;

uint_t
ucred_getpflags(uc, flags)
	Sun::Solaris::Ucred::Ucred *uc;
	uint_t flags;

Sun::Solaris::Privilege::Privset *
ucred_getprivset(uc, which)
	Sun::Solaris::Ucred::Ucred *uc;
	const char *which;
PREINIT:
	const priv_set_t *val;
CODE:
	/*
	 * Since this function returns a pointer into the ucred_t, we need
	 * to copy it or perl may free one before the other; and the
	 * priv_set_t * returned by it doesn't react kindly to free().
	 */
	val = ucred_getprivset(uc, which);
	if (val == NULL || (RETVAL = dupset(val)) == NULL)
		XSRETURN_UNDEF;
	RETPRIVSET(RETVAL);

Sun::Solaris::Ucred::Ucred *
getpeerucred(fd)
	int fd;
CODE:
	RETVAL = NULL;
	if (getpeerucred(fd, &RETVAL) != 0)
		XSRETURN_UNDEF;
	RETUCRED(RETVAL);

void
ucred_getgroups(uc)
	Sun::Solaris::Ucred::Ucred *uc;
PREINIT:
	const gid_t *gids;
	int n;
PPCODE:
	n = ucred_getgroups(uc, &gids);
	if (n < 0)
		XSRETURN_UNDEF;

	PUTBACK;
	if (GIMME_V == G_SCALAR) {
		EXTEND(SP, 1);
		PUSHs(sv_2mortal(newSViv(n)));
		PUTBACK;
		XSRETURN(1);
	} else if (GIMME_V == G_ARRAY) {
		int i;
		EXTEND(SP, n);

		for (i = 0; i < n; i++)
			PUSHs(sv_2mortal(newSViv(gids[i])));
		PUTBACK;
		XSRETURN(n);
	} else {
		PUTBACK;
		XSRETURN(0);
	}




MODULE = Sun::Solaris::Ucred PACKAGE = Sun::Solaris::Ucred::UcredPtr PREFIX = Ucred_

void
Ucred_DESTROY(uc)
	Sun::Solaris::Ucred::Ucred *uc;
CODE:
	ucred_free(uc);

