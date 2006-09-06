/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Lgrp.xs contains XS wrappers for the system locality group library
 * liblgrp(3LIB).
 */

#include <sys/errno.h>
#include <sys/lgrp_user.h>

/*
 * On i386 Solaris defines SP, which conflicts with the perl definition of SP
 * We don't need the Solaris one, so get rid of it to avoid warnings.
 */
#undef SP

/* Perl XS includes. */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* Return undef in scalar context and empty list in list context */
#define LGRP_BADVAL() {			\
	if (GIMME_V == G_ARRAY)		\
			XSRETURN_EMPTY;	\
		else			\
			XSRETURN_UNDEF;	\
}

/*
 * Push all values from input array onto the perl return stack.
 */
#define	PUSHARRAY(array, nitems)	\
{					\
	int x;				\
					\
	if (nitems < 0) {		\
		LGRP_BADVAL()		\
	} else if (nitems > 0) {	\
		EXTEND(SP, nitems);	\
		for (x = 0; x < nitems; x++) {	\
			PUSHs(sv_2mortal(newSVnv(array[x])));	\
		}			\
	}				\
}

/*
 * Several constants are not present in the first version of the Lgrp API,
 * we define them here.
 *
 * lgrp_resources() and lgrp_latency_cookie() only appear in API v2. If the
 * module is linked with old version of liblgrp(3LIB) there is no lgrp_resources
 * symbol in the library and perl wrapper returns empty list and sets errno to
 * EINVAL.
 *
 * The lgrp_latency_cookie() is emulated using lgrp_latency().
 */
#if LGRP_VER_CURRENT == 1
#define	LGRP_CONTENT_ALL LGRP_CONTENT_HIERARCHY
#define	LGRP_LAT_CPU_TO_MEM 	0
#define LGRP_RSRC_CPU           0       /* CPU resources */
#define LGRP_RSRC_MEM           1       /* memory resources */

#define LGRP_RESOURCES(c, lgrp, type) \
	{ errno = EINVAL; LGRP_BADVAL(); }

/*
 * Simulate lgrp_latency_cookie() which just fails. This macro is never called
 * and we just define it so that the C compiler will not complain about the
 * missing symbol.
 */
#define	lgrp_latency_cookie(c, f, t, b) (errno = EINVAL, -1)

#else
#define	LGRP_RESOURCES(c, lgrp, type) { \
	int nr;				\
	lgrp_id_t *lgrps;		\
					\
	errno = 0;			\
	nr = lgrp_resources(c, lgrp, NULL, 0, type);	\
	if (nr < 0)			\
		LGRP_BADVAL();		\
	if (GIMME_V == G_SCALAR)	\
		XSRETURN_IV(nr);	\
	if (nr == 0) {			\
		XSRETURN_EMPTY;		\
	} else if (New(0, lgrps, nr, lgrp_id_t) == NULL) {	\
		errno = ENOMEM;		\
		LGRP_BADVAL();		\
	} else {			\
		nr = lgrp_resources(c, lgrp, lgrps, nr, type);	\
		PUSHARRAY(lgrps, nr);	\
		Safefree(lgrps);	\
	}				\
}
#endif

/*
 * Special version of lgrp_latency_cookie(). Use lgrp_latency() for liblgrp V1
 * and lgrp_latency_cookie for V2.
 */
static int
_lgrp_latency_cookie(lgrp_cookie_t cookie, lgrp_id_t from, lgrp_id_t to,
				   int between)
{
	return (LGRP_VER_CURRENT < 2 ?
	    lgrp_latency(from, to) :
	    lgrp_latency_cookie(cookie, from, to, between));
}

/*
 * Most functions in liblgrp return -1 on failure. The perl equivalent returns
 * 'undef' instead. The macro should be call after the RETVAL is set to the
 * return value of the function.
 */
#define	RETURN_UNDEF_IF_FAIL { if (RETVAL < 0) XSRETURN_UNDEF; }

/*
 * End of C part, start of XS part.
 *
 * The XS code exported to perl is below here.  Note that the XS preprocessor
 * has its own commenting syntax, so all comments from this point on are in
 * that form.
 */

MODULE = Sun::Solaris::Lgrp PACKAGE = Sun::Solaris::Lgrp
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

	stash = gv_stashpv("Sun::Solaris::Lgrp", TRUE);
	newCONSTSUB(stash, "LGRP_AFF_NONE", newSViv(LGRP_AFF_NONE));
	newCONSTSUB(stash, "LGRP_AFF_STRONG", newSViv(LGRP_AFF_STRONG));
	newCONSTSUB(stash, "LGRP_AFF_WEAK", newSViv(LGRP_AFF_WEAK));
	newCONSTSUB(stash, "LGRP_VER_CURRENT", newSViv(LGRP_VER_CURRENT));
	newCONSTSUB(stash, "LGRP_VER_NONE", newSViv(LGRP_VER_NONE));
	newCONSTSUB(stash, "LGRP_NONE", newSViv(LGRP_NONE));
	newCONSTSUB(stash, "LGRP_RSRC_CPU", newSViv(LGRP_RSRC_CPU));
	newCONSTSUB(stash, "LGRP_RSRC_MEM", newSViv(LGRP_RSRC_MEM));
	newCONSTSUB(stash, "LGRP_CONTENT_HIERARCHY",
			newSViv(LGRP_CONTENT_HIERARCHY));
	newCONSTSUB(stash, "LGRP_CONTENT_DIRECT", newSViv(LGRP_CONTENT_DIRECT));
	newCONSTSUB(stash, "LGRP_VIEW_CALLER", newSViv(LGRP_VIEW_CALLER));
	newCONSTSUB(stash, "LGRP_VIEW_OS", newSViv(LGRP_VIEW_OS));
	newCONSTSUB(stash, "LGRP_MEM_SZ_FREE", newSViv(LGRP_MEM_SZ_FREE));
	newCONSTSUB(stash, "LGRP_MEM_SZ_INSTALLED",
			newSViv(LGRP_MEM_SZ_INSTALLED));
	newCONSTSUB(stash, "LGRP_CONTENT_ALL", newSViv(LGRP_CONTENT_ALL));
	newCONSTSUB(stash, "LGRP_LAT_CPU_TO_MEM", newSViv(LGRP_LAT_CPU_TO_MEM));
	newCONSTSUB(stash, "P_PID", newSViv(P_PID));
	newCONSTSUB(stash, "P_LWPID", newSViv(P_LWPID));
	newCONSTSUB(stash, "P_MYID", newSViv(P_MYID));
	}

 #
 # The code below uses POSTCALL directive which allows to return 'undef'
 # whenever a C function returns a negative value.
 #


 #
 # lgrp_init([view])
 # Use LGRP_VIEW_OS as the default view.
 #
lgrp_cookie_t
lgrp_init(lgrp_view_t view = LGRP_VIEW_OS)
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;

lgrp_view_t
lgrp_view(cookie)
       lgrp_cookie_t cookie
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;

lgrp_affinity_t
lgrp_affinity_get(idtype, id, lgrp)
	idtype_t idtype;
	id_t id;
	lgrp_id_t lgrp;
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;

int
lgrp_affinity_set(idtype, id, lgrp, affinity)
	idtype_t idtype;
	id_t id;
	lgrp_id_t lgrp;
	lgrp_affinity_t affinity;
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;
	XSRETURN_YES;

int
lgrp_cookie_stale(cookie)
	lgrp_cookie_t cookie;
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;

int
lgrp_fini(cookie)
	lgrp_cookie_t cookie;
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;
	XSRETURN_YES;

lgrp_id_t
lgrp_home(idtype, id)
	idtype_t idtype;
	id_t id;
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;

int
lgrp_latency(lgrp_id_t from,lgrp_id_t to)
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;

lgrp_mem_size_t
lgrp_mem_size(cookie, lgrp, type, content)
	lgrp_cookie_t	cookie
	lgrp_id_t	lgrp
	int		type
	lgrp_content_t	content
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;

int
lgrp_nlgrps(cookie)
	lgrp_cookie_t cookie;
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;

lgrp_id_t
lgrp_root(cookie)
	lgrp_cookie_t cookie
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;

int
lgrp_version(int version = LGRP_VER_NONE)

 #
 # lgrp_latency_cookie calls our internal wrapper  _lgrp_latency_cookie() which
 # works for both old and new versions of liblgrp.
 # 
int
lgrp_latency_cookie(lgrp_cookie_t cookie, lgrp_id_t from, lgrp_id_t to, int between = 0)
  CODE:
	RETVAL = _lgrp_latency_cookie(cookie, from, to, between);
  POSTCALL:
	RETURN_UNDEF_IF_FAIL;
  OUTPUT:
	RETVAL

 #
 # Functions below convert C arrays into Perl lists. They use XS PPCODE
 # directive to avoid implicit RETVAL assignments and manipulate perl
 # stack directly.
 #
 # When called in scalar context functions return the number of elements
 # in the list or undef on failure.
 #
 # The PUSHARRAY() macro defined above pushes all values from the C array to
 # the perl stack.
 #

 #
 # @children = lgrp_children($cookie, $parent).
 #
void
lgrp_children(cookie, lgrp)
	lgrp_cookie_t cookie;
	lgrp_id_t lgrp;
  PREINIT:
	lgrp_id_t *lgrps;
	int	count;
  PPCODE:
	errno = 0;
	if ((count = lgrp_children(cookie, lgrp, NULL, 0)) < 0)
		LGRP_BADVAL();

	if (GIMME_V == G_SCALAR)
		XSRETURN_IV(count);

	if (count > 0) {
		if (New(0, lgrps, count, lgrp_id_t) == NULL) {
			errno = ENOMEM;
			LGRP_BADVAL();
		} else {
			count = lgrp_children(cookie, lgrp, lgrps, count);
			PUSHARRAY(lgrps, count);
			Safefree(lgrps);
		}
	}

 #
 # @parents = lgrp_parents($cookie, $lgrp).
 #
void
lgrp_parents(cookie, lgrp)
	lgrp_cookie_t cookie;
	lgrp_id_t lgrp;
  PREINIT:
	lgrp_id_t *lgrps;
	int count;
  PPCODE:
	errno = 0;
	if ((count = lgrp_parents(cookie, lgrp, NULL, 0)) < 0)
		LGRP_BADVAL();

	if (GIMME_V == G_SCALAR)
		XSRETURN_IV(count);

	if (count > 0) {
		if (New(0, lgrps, count, lgrp_id_t) == NULL) {
			errno = ENOMEM;
			LGRP_BADVAL();
		} else {
			count = lgrp_parents(cookie, lgrp, lgrps, count);
			PUSHARRAY(lgrps, count);
			Safefree(lgrps);
		}
	}

 #
 # @parents = lgrp_cpus($cookie, $lgrp, $content).
 # Content should be LGRP_CONTENT_HIERARCHY or LGRP_CONTENT_ALL or
 # 	LGRP_CONTENT_DIRECT
void
lgrp_cpus(cookie, lgrp, content)
	lgrp_cookie_t cookie;
	lgrp_id_t lgrp;
	lgrp_content_t content;
  PREINIT:
	int ncpus;
	processorid_t *cpus;
  PPCODE:
	errno = 0;
	if ((ncpus = lgrp_cpus(cookie, lgrp, NULL, 0, content)) < 0)
		LGRP_BADVAL();

	if (GIMME_V == G_SCALAR)
		XSRETURN_IV(ncpus);

	if (ncpus > 0) {
		if (New(0, cpus, ncpus, processorid_t) == NULL) {
			errno = ENOMEM;
			LGRP_BADVAL();
		} else {
			ncpus = lgrp_cpus(cookie, lgrp, cpus, ncpus, content);
			PUSHARRAY(cpus, ncpus);
			Safefree(cpus);
		}
	}

void
lgrp_resources(cookie, lgrp, type)
	lgrp_cookie_t cookie;
	lgrp_id_t lgrp;
	int type;
  PPCODE:
	LGRP_RESOURCES(cookie, lgrp, type);
