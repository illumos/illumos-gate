/*
 * Copyright (c) 2004, Oracle and/or its affiliates. All rights reserved.
 */

/* Solaris includes. */
#include <priv.h>
#include <ctype.h>

/* Perl includes. */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define	IVCONST(s, c)	newCONSTSUB(s, #c, newSViv((int)(intptr_t)c));
#define	POFF		(sizeof ("PRIV_") - 1)

#define	RETPRIVSET(set)		\
	ST(0) = sv_newmortal();						\
	sv_setref_pv(ST(0), "Sun::Solaris::Privilege::PrivsetPtr",	\
	    (void*)(set));						\
	SvREADONLY_on(SvRV(ST(0)))

typedef int sysret;

typedef priv_set_t Sun__Solaris__Privilege__Privset;

static priv_set_t *
dupset(const priv_set_t *s)
{
	priv_set_t *new = priv_allocset();
	if (new == NULL)
		return (NULL);

	priv_copyset(s, new);
	return (new);
}

/*
 * Automatically derive the #define constant from the constant value.
 * This is the uppercase value of the constant with "PRIV_" prepended.
 * The (name, value) pair computed in that way is stored twice:
 * 	once as constant subroutine in the module's hash table.
 *	once as (key, value) in a hash table.
 */

static void
PRIVconst(HV *sym, HV *var, const char *name)
{
	char upname[128];
	ssize_t len;
	int i;

	len = snprintf(upname, sizeof (upname), "PRIV_%s", name);
	if (len >= sizeof (upname))
		return;

	for (i = POFF; i < len; i++)
		upname[i] = toupper(upname[i]);
	newCONSTSUB(sym, upname, newSVpv(name, len - POFF));
	hv_store(var, upname, len, newSVpv(name, len - POFF), 0);
}

/*
 * The XS code exported to perl is below here.  Note that the XS preprocessor
 * has its own commenting syntax, so all comments from this point on are in
 * that form.
 *
 * Inside perl, privilege sets are represented as expanded strings;
 * privileges and privilege sets are only known by name.
 */

MODULE = Sun::Solaris::Privilege PACKAGE = Sun::Solaris::Privilege
PROTOTYPES: ENABLE

 #
 # Define any constants that need to be exported.  By doing it this way we can
 # avoid the overhead of using the DynaLoader package, and in addition constants
 # defined using this mechanism are eligible for inlining by the perl
 # interpreter at compile time.
 #
BOOT:
{
	HV *stash;
	HV *privs;
	HV *privsets;
	const char *p;
	int i;

	stash = gv_stashpv("Sun::Solaris::Privilege", TRUE);

	/*
	 * Global constants
	 */
	IVCONST(stash, PRIV_STR_PORT);
	IVCONST(stash, PRIV_STR_LIT);
	IVCONST(stash, PRIV_STR_SHORT);
	IVCONST(stash, PRIV_ALLSETS);
	IVCONST(stash, PRIV_DEBUG);
	IVCONST(stash, PRIV_AWARE);
	IVCONST(stash, PRIV_ON);
	IVCONST(stash, PRIV_OFF);
	IVCONST(stash, PRIV_SET);

	/*
	 * %PRIVILEGES hash and the privilege constants
	 */
	privs = perl_get_hv("Sun::Solaris::Privilege::PRIVILEGES", TRUE);
	for (i = 0; (p = priv_getbynum(i++)) != NULL; )
		PRIVconst(stash, privs, p);

	/*
	 * %PRIVSETS hash and the privset constants
	 */
	privsets = perl_get_hv("Sun::Solaris::Privilege::PRIVSETS", TRUE);
	for (i = 0; (p = priv_getsetbynum(i++)) != NULL; )
		PRIVconst(stash, privsets, p);
}


Sun::Solaris::Privilege::Privset *
getppriv(which)
	const char *which;
CODE:
	RETVAL = priv_allocset();
	if (getppriv(which, RETVAL) != 0) {
		priv_freeset(RETVAL);
		XSRETURN_UNDEF;
	} else {
		RETPRIVSET(RETVAL);
	}

sysret
setppriv(op, which, set)
	int op;
	const char *which;
	Sun::Solaris::Privilege::Privset *set;

Sun::Solaris::Privilege::Privset *
priv_emptyset()
CODE:
	RETVAL = priv_allocset();
	if (RETVAL == NULL) {
		XSRETURN_UNDEF;
	}
	priv_emptyset(RETVAL);
	RETPRIVSET(RETVAL);

Sun::Solaris::Privilege::Privset *
priv_fillset()
CODE:
	RETVAL = priv_allocset();
	if (RETVAL == NULL) {
		XSRETURN_UNDEF;
	}
	priv_fillset(RETVAL);
	RETPRIVSET(RETVAL);

boolean_t
priv_isemptyset(set)
	Sun::Solaris::Privilege::Privset *set;

boolean_t
priv_isfullset(set)
	Sun::Solaris::Privilege::Privset *set;

boolean_t
priv_isequalset(set1, set2)
	Sun::Solaris::Privilege::Privset *set1;
	Sun::Solaris::Privilege::Privset *set2;

boolean_t
priv_issubset(set1, set2)
	Sun::Solaris::Privilege::Privset *set1;
	Sun::Solaris::Privilege::Privset *set2;

boolean_t
priv_ismember(set, priv)
	Sun::Solaris::Privilege::Privset *set;
	const char *priv;

boolean_t
priv_ineffect(priv)
	const char *priv;

Sun::Solaris::Privilege::Privset *
priv_intersect(set1, set2)
	Sun::Solaris::Privilege::Privset *set1;
	Sun::Solaris::Privilege::Privset *set2;
CODE:
	RETVAL = dupset(set2);
	if (RETVAL == NULL) {
		XSRETURN_UNDEF;
	}
	priv_intersect(set1, RETVAL);
	RETPRIVSET(RETVAL);

Sun::Solaris::Privilege::Privset *
priv_union(set1, set2)
	Sun::Solaris::Privilege::Privset *set1;
	Sun::Solaris::Privilege::Privset *set2;
CODE:
	RETVAL = dupset(set2);
	if (RETVAL == NULL) {
		XSRETURN_UNDEF;
	}
	priv_union(set1, RETVAL);
	RETPRIVSET(RETVAL);

Sun::Solaris::Privilege::Privset *
priv_inverse(set1)
	Sun::Solaris::Privilege::Privset *set1;
CODE:
	RETVAL = dupset(set1);
	if (RETVAL == NULL) {
		XSRETURN_UNDEF;
	}
	priv_inverse(RETVAL);
	RETPRIVSET(RETVAL);


sysret
priv_addset(set, priv)
	Sun::Solaris::Privilege::Privset *set;
	const char *priv;

Sun::Solaris::Privilege::Privset *
priv_copyset(set1)
	Sun::Solaris::Privilege::Privset *set1;
CODE:
	RETVAL = dupset(set1);
	if (RETVAL == NULL) {
		XSRETURN_UNDEF;
	}
	RETPRIVSET(RETVAL);


sysret
priv_delset(set, priv)
	Sun::Solaris::Privilege::Privset *set;
	const char *priv;

const char *
priv_getbynum(i)
	int i;

const char *
priv_getsetbynum(i)
	int i;

char *
priv_set_to_str(s, c, f)
	Sun::Solaris::Privilege::Privset *s;
	char c;
	int f;
CLEANUP:
	free(RETVAL);

Sun::Solaris::Privilege::Privset *
priv_str_to_set(buf, sep);
	const char *buf;
	const char *sep;
CODE:
	RETVAL = priv_str_to_set(buf, sep, NULL);
	if (RETVAL == NULL) {
		XSRETURN_UNDEF;
	}
	RETPRIVSET(RETVAL);

char *
priv_gettext(priv)
	const char *priv
CLEANUP:
	free(RETVAL);

sysret
setpflags(flag, val)
	uint_t flag;
	uint_t val;

sysret
getpflags(flag)
	uint_t flag;

MODULE = Sun::Solaris::Privilege PACKAGE = Sun::Solaris::Privilege::PrivsetPtr PREFIX = Privilege_

void
Privilege_DESTROY(ps)
	Sun::Solaris::Privilege::Privset *ps;
CODE:
	priv_freeset(ps);

