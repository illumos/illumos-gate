#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Replacement for getpwnam - we need it to handle files other than
 * /etc/passwd so we can permit different passwd files for each different
 * host
 * (c) 1998-2000 by Bernhard Rosenkränzer <bero@redhat.com>
 * 19980930	Initial version
 * 20000211	Various fixes
 */

#include <pwd.h>
#include <sys/types.h>
#include <stdio.h>
#ifdef SHADOW_PASSWORD
# ifdef HAVE_SHADOW_H
#  include <shadow.h>
# endif
#endif

struct passwd *bero_getpwnam(const char * name, const char * file);
struct passwd *bero_getpwuid(uid_t uid, const char * file);
#ifdef SHADOW_PASSWORD
struct spwd *bero_getspnam(const char * name, const char * file);
#endif
