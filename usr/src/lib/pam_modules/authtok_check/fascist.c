/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * This program is copyright Alec Muffett 1993. The author disclaims all
 * responsibility or liability with respect to it's usage or its effect
 * upon hardware or computer systems, and maintains copyright as set out
 * in the "LICENCE" document which accompanies distributions of Crack v4.0
 * and upwards.
 */

#include "packer.h"


static char *r_destructors[] = {
	":",			/* noop - must do this to test raw word. */
	"[",			/* trimming leading/trailing junk */
	"]",
	"[[",
	"]]",
	"[[[",
	"]]]",

	"/?p@?p",		/* purging out punctuation/symbols/junk */
	"/?s@?s",
	"/?X@?X",
	/* attempt reverse engineering of password strings */
	"/$s$s",
	"/$s$s/0s0o",
	"/$s$s/0s0o/2s2a",
	"/$s$s/0s0o/2s2a/3s3e",
	"/$s$s/0s0o/2s2a/3s3e/5s5s",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/1s1i",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/1s1l",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/1s1i/4s4a",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/1s1i/4s4h",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/1s1l/4s4a",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/1s1l/4s4h",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/4s4a",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/4s4h",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/4s4a",
	"/$s$s/0s0o/2s2a/3s3e/5s5s/4s4h",
	"/$s$s/0s0o/2s2a/3s3e/1s1i",
	"/$s$s/0s0o/2s2a/3s3e/1s1l",
	"/$s$s/0s0o/2s2a/3s3e/1s1i/4s4a",
	"/$s$s/0s0o/2s2a/3s3e/1s1i/4s4h",
	"/$s$s/0s0o/2s2a/3s3e/1s1l/4s4a",
	"/$s$s/0s0o/2s2a/3s3e/1s1l/4s4h",
	"/$s$s/0s0o/2s2a/3s3e/4s4a",
	"/$s$s/0s0o/2s2a/3s3e/4s4h",
	"/$s$s/0s0o/2s2a/3s3e/4s4a",
	"/$s$s/0s0o/2s2a/3s3e/4s4h",
	"/$s$s/0s0o/2s2a/5s5s",
	"/$s$s/0s0o/2s2a/5s5s/1s1i",
	"/$s$s/0s0o/2s2a/5s5s/1s1l",
	"/$s$s/0s0o/2s2a/5s5s/1s1i/4s4a",
	"/$s$s/0s0o/2s2a/5s5s/1s1i/4s4h",
	"/$s$s/0s0o/2s2a/5s5s/1s1l/4s4a",
	"/$s$s/0s0o/2s2a/5s5s/1s1l/4s4h",
	"/$s$s/0s0o/2s2a/5s5s/4s4a",
	"/$s$s/0s0o/2s2a/5s5s/4s4h",
	"/$s$s/0s0o/2s2a/5s5s/4s4a",
	"/$s$s/0s0o/2s2a/5s5s/4s4h",
	"/$s$s/0s0o/2s2a/1s1i",
	"/$s$s/0s0o/2s2a/1s1l",
	"/$s$s/0s0o/2s2a/1s1i/4s4a",
	"/$s$s/0s0o/2s2a/1s1i/4s4h",
	"/$s$s/0s0o/2s2a/1s1l/4s4a",
	"/$s$s/0s0o/2s2a/1s1l/4s4h",
	"/$s$s/0s0o/2s2a/4s4a",
	"/$s$s/0s0o/2s2a/4s4h",
	"/$s$s/0s0o/2s2a/4s4a",
	"/$s$s/0s0o/2s2a/4s4h",
	"/$s$s/0s0o/3s3e",
	"/$s$s/0s0o/3s3e/5s5s",
	"/$s$s/0s0o/3s3e/5s5s/1s1i",
	"/$s$s/0s0o/3s3e/5s5s/1s1l",
	"/$s$s/0s0o/3s3e/5s5s/1s1i/4s4a",
	"/$s$s/0s0o/3s3e/5s5s/1s1i/4s4h",
	"/$s$s/0s0o/3s3e/5s5s/1s1l/4s4a",
	"/$s$s/0s0o/3s3e/5s5s/1s1l/4s4h",
	"/$s$s/0s0o/3s3e/5s5s/4s4a",
	"/$s$s/0s0o/3s3e/5s5s/4s4h",
	"/$s$s/0s0o/3s3e/5s5s/4s4a",
	"/$s$s/0s0o/3s3e/5s5s/4s4h",
	"/$s$s/0s0o/3s3e/1s1i",
	"/$s$s/0s0o/3s3e/1s1l",
	"/$s$s/0s0o/3s3e/1s1i/4s4a",
	"/$s$s/0s0o/3s3e/1s1i/4s4h",
	"/$s$s/0s0o/3s3e/1s1l/4s4a",
	"/$s$s/0s0o/3s3e/1s1l/4s4h",
	"/$s$s/0s0o/3s3e/4s4a",
	"/$s$s/0s0o/3s3e/4s4h",
	"/$s$s/0s0o/3s3e/4s4a",
	"/$s$s/0s0o/3s3e/4s4h",
	"/$s$s/0s0o/5s5s",
	"/$s$s/0s0o/5s5s/1s1i",
	"/$s$s/0s0o/5s5s/1s1l",
	"/$s$s/0s0o/5s5s/1s1i/4s4a",
	"/$s$s/0s0o/5s5s/1s1i/4s4h",
	"/$s$s/0s0o/5s5s/1s1l/4s4a",
	"/$s$s/0s0o/5s5s/1s1l/4s4h",
	"/$s$s/0s0o/5s5s/4s4a",
	"/$s$s/0s0o/5s5s/4s4h",
	"/$s$s/0s0o/5s5s/4s4a",
	"/$s$s/0s0o/5s5s/4s4h",
	"/$s$s/0s0o/1s1i",
	"/$s$s/0s0o/1s1l",
	"/$s$s/0s0o/1s1i/4s4a",
	"/$s$s/0s0o/1s1i/4s4h",
	"/$s$s/0s0o/1s1l/4s4a",
	"/$s$s/0s0o/1s1l/4s4h",
	"/$s$s/0s0o/4s4a",
	"/$s$s/0s0o/4s4h",
	"/$s$s/0s0o/4s4a",
	"/$s$s/0s0o/4s4h",
	"/$s$s/2s2a",
	"/$s$s/2s2a/3s3e",
	"/$s$s/2s2a/3s3e/5s5s",
	"/$s$s/2s2a/3s3e/5s5s/1s1i",
	"/$s$s/2s2a/3s3e/5s5s/1s1l",
	"/$s$s/2s2a/3s3e/5s5s/1s1i/4s4a",
	"/$s$s/2s2a/3s3e/5s5s/1s1i/4s4h",
	"/$s$s/2s2a/3s3e/5s5s/1s1l/4s4a",
	"/$s$s/2s2a/3s3e/5s5s/1s1l/4s4h",
	"/$s$s/2s2a/3s3e/5s5s/4s4a",
	"/$s$s/2s2a/3s3e/5s5s/4s4h",
	"/$s$s/2s2a/3s3e/5s5s/4s4a",
	"/$s$s/2s2a/3s3e/5s5s/4s4h",
	"/$s$s/2s2a/3s3e/1s1i",
	"/$s$s/2s2a/3s3e/1s1l",
	"/$s$s/2s2a/3s3e/1s1i/4s4a",
	"/$s$s/2s2a/3s3e/1s1i/4s4h",
	"/$s$s/2s2a/3s3e/1s1l/4s4a",
	"/$s$s/2s2a/3s3e/1s1l/4s4h",
	"/$s$s/2s2a/3s3e/4s4a",
	"/$s$s/2s2a/3s3e/4s4h",
	"/$s$s/2s2a/3s3e/4s4a",
	"/$s$s/2s2a/3s3e/4s4h",
	"/$s$s/2s2a/5s5s",
	"/$s$s/2s2a/5s5s/1s1i",
	"/$s$s/2s2a/5s5s/1s1l",
	"/$s$s/2s2a/5s5s/1s1i/4s4a",
	"/$s$s/2s2a/5s5s/1s1i/4s4h",
	"/$s$s/2s2a/5s5s/1s1l/4s4a",
	"/$s$s/2s2a/5s5s/1s1l/4s4h",
	"/$s$s/2s2a/5s5s/4s4a",
	"/$s$s/2s2a/5s5s/4s4h",
	"/$s$s/2s2a/5s5s/4s4a",
	"/$s$s/2s2a/5s5s/4s4h",
	"/$s$s/2s2a/1s1i",
	"/$s$s/2s2a/1s1l",
	"/$s$s/2s2a/1s1i/4s4a",
	"/$s$s/2s2a/1s1i/4s4h",
	"/$s$s/2s2a/1s1l/4s4a",
	"/$s$s/2s2a/1s1l/4s4h",
	"/$s$s/2s2a/4s4a",
	"/$s$s/2s2a/4s4h",
	"/$s$s/2s2a/4s4a",
	"/$s$s/2s2a/4s4h",
	"/$s$s/3s3e",
	"/$s$s/3s3e/5s5s",
	"/$s$s/3s3e/5s5s/1s1i",
	"/$s$s/3s3e/5s5s/1s1l",
	"/$s$s/3s3e/5s5s/1s1i/4s4a",
	"/$s$s/3s3e/5s5s/1s1i/4s4h",
	"/$s$s/3s3e/5s5s/1s1l/4s4a",
	"/$s$s/3s3e/5s5s/1s1l/4s4h",
	"/$s$s/3s3e/5s5s/4s4a",
	"/$s$s/3s3e/5s5s/4s4h",
	"/$s$s/3s3e/5s5s/4s4a",
	"/$s$s/3s3e/5s5s/4s4h",
	"/$s$s/3s3e/1s1i",
	"/$s$s/3s3e/1s1l",
	"/$s$s/3s3e/1s1i/4s4a",
	"/$s$s/3s3e/1s1i/4s4h",
	"/$s$s/3s3e/1s1l/4s4a",
	"/$s$s/3s3e/1s1l/4s4h",
	"/$s$s/3s3e/4s4a",
	"/$s$s/3s3e/4s4h",
	"/$s$s/3s3e/4s4a",
	"/$s$s/3s3e/4s4h",
	"/$s$s/5s5s",
	"/$s$s/5s5s/1s1i",
	"/$s$s/5s5s/1s1l",
	"/$s$s/5s5s/1s1i/4s4a",
	"/$s$s/5s5s/1s1i/4s4h",
	"/$s$s/5s5s/1s1l/4s4a",
	"/$s$s/5s5s/1s1l/4s4h",
	"/$s$s/5s5s/4s4a",
	"/$s$s/5s5s/4s4h",
	"/$s$s/5s5s/4s4a",
	"/$s$s/5s5s/4s4h",
	"/$s$s/1s1i",
	"/$s$s/1s1l",
	"/$s$s/1s1i/4s4a",
	"/$s$s/1s1i/4s4h",
	"/$s$s/1s1l/4s4a",
	"/$s$s/1s1l/4s4h",
	"/$s$s/4s4a",
	"/$s$s/4s4h",
	"/$s$s/4s4a",
	"/$s$s/4s4h",
	"/0s0o",
	"/0s0o/2s2a",
	"/0s0o/2s2a/3s3e",
	"/0s0o/2s2a/3s3e/5s5s",
	"/0s0o/2s2a/3s3e/5s5s/1s1i",
	"/0s0o/2s2a/3s3e/5s5s/1s1l",
	"/0s0o/2s2a/3s3e/5s5s/1s1i/4s4a",
	"/0s0o/2s2a/3s3e/5s5s/1s1i/4s4h",
	"/0s0o/2s2a/3s3e/5s5s/1s1l/4s4a",
	"/0s0o/2s2a/3s3e/5s5s/1s1l/4s4h",
	"/0s0o/2s2a/3s3e/5s5s/4s4a",
	"/0s0o/2s2a/3s3e/5s5s/4s4h",
	"/0s0o/2s2a/3s3e/5s5s/4s4a",
	"/0s0o/2s2a/3s3e/5s5s/4s4h",
	"/0s0o/2s2a/3s3e/1s1i",
	"/0s0o/2s2a/3s3e/1s1l",
	"/0s0o/2s2a/3s3e/1s1i/4s4a",
	"/0s0o/2s2a/3s3e/1s1i/4s4h",
	"/0s0o/2s2a/3s3e/1s1l/4s4a",
	"/0s0o/2s2a/3s3e/1s1l/4s4h",
	"/0s0o/2s2a/3s3e/4s4a",
	"/0s0o/2s2a/3s3e/4s4h",
	"/0s0o/2s2a/3s3e/4s4a",
	"/0s0o/2s2a/3s3e/4s4h",
	"/0s0o/2s2a/5s5s",
	"/0s0o/2s2a/5s5s/1s1i",
	"/0s0o/2s2a/5s5s/1s1l",
	"/0s0o/2s2a/5s5s/1s1i/4s4a",
	"/0s0o/2s2a/5s5s/1s1i/4s4h",
	"/0s0o/2s2a/5s5s/1s1l/4s4a",
	"/0s0o/2s2a/5s5s/1s1l/4s4h",
	"/0s0o/2s2a/5s5s/4s4a",
	"/0s0o/2s2a/5s5s/4s4h",
	"/0s0o/2s2a/5s5s/4s4a",
	"/0s0o/2s2a/5s5s/4s4h",
	"/0s0o/2s2a/1s1i",
	"/0s0o/2s2a/1s1l",
	"/0s0o/2s2a/1s1i/4s4a",
	"/0s0o/2s2a/1s1i/4s4h",
	"/0s0o/2s2a/1s1l/4s4a",
	"/0s0o/2s2a/1s1l/4s4h",
	"/0s0o/2s2a/4s4a",
	"/0s0o/2s2a/4s4h",
	"/0s0o/2s2a/4s4a",
	"/0s0o/2s2a/4s4h",
	"/0s0o/3s3e",
	"/0s0o/3s3e/5s5s",
	"/0s0o/3s3e/5s5s/1s1i",
	"/0s0o/3s3e/5s5s/1s1l",
	"/0s0o/3s3e/5s5s/1s1i/4s4a",
	"/0s0o/3s3e/5s5s/1s1i/4s4h",
	"/0s0o/3s3e/5s5s/1s1l/4s4a",
	"/0s0o/3s3e/5s5s/1s1l/4s4h",
	"/0s0o/3s3e/5s5s/4s4a",
	"/0s0o/3s3e/5s5s/4s4h",
	"/0s0o/3s3e/5s5s/4s4a",
	"/0s0o/3s3e/5s5s/4s4h",
	"/0s0o/3s3e/1s1i",
	"/0s0o/3s3e/1s1l",
	"/0s0o/3s3e/1s1i/4s4a",
	"/0s0o/3s3e/1s1i/4s4h",
	"/0s0o/3s3e/1s1l/4s4a",
	"/0s0o/3s3e/1s1l/4s4h",
	"/0s0o/3s3e/4s4a",
	"/0s0o/3s3e/4s4h",
	"/0s0o/3s3e/4s4a",
	"/0s0o/3s3e/4s4h",
	"/0s0o/5s5s",
	"/0s0o/5s5s/1s1i",
	"/0s0o/5s5s/1s1l",
	"/0s0o/5s5s/1s1i/4s4a",
	"/0s0o/5s5s/1s1i/4s4h",
	"/0s0o/5s5s/1s1l/4s4a",
	"/0s0o/5s5s/1s1l/4s4h",
	"/0s0o/5s5s/4s4a",
	"/0s0o/5s5s/4s4h",
	"/0s0o/5s5s/4s4a",
	"/0s0o/5s5s/4s4h",
	"/0s0o/1s1i",
	"/0s0o/1s1l",
	"/0s0o/1s1i/4s4a",
	"/0s0o/1s1i/4s4h",
	"/0s0o/1s1l/4s4a",
	"/0s0o/1s1l/4s4h",
	"/0s0o/4s4a",
	"/0s0o/4s4h",
	"/0s0o/4s4a",
	"/0s0o/4s4h",
	"/2s2a",
	"/2s2a/3s3e",
	"/2s2a/3s3e/5s5s",
	"/2s2a/3s3e/5s5s/1s1i",
	"/2s2a/3s3e/5s5s/1s1l",
	"/2s2a/3s3e/5s5s/1s1i/4s4a",
	"/2s2a/3s3e/5s5s/1s1i/4s4h",
	"/2s2a/3s3e/5s5s/1s1l/4s4a",
	"/2s2a/3s3e/5s5s/1s1l/4s4h",
	"/2s2a/3s3e/5s5s/4s4a",
	"/2s2a/3s3e/5s5s/4s4h",
	"/2s2a/3s3e/5s5s/4s4a",
	"/2s2a/3s3e/5s5s/4s4h",
	"/2s2a/3s3e/1s1i",
	"/2s2a/3s3e/1s1l",
	"/2s2a/3s3e/1s1i/4s4a",
	"/2s2a/3s3e/1s1i/4s4h",
	"/2s2a/3s3e/1s1l/4s4a",
	"/2s2a/3s3e/1s1l/4s4h",
	"/2s2a/3s3e/4s4a",
	"/2s2a/3s3e/4s4h",
	"/2s2a/3s3e/4s4a",
	"/2s2a/3s3e/4s4h",
	"/2s2a/5s5s",
	"/2s2a/5s5s/1s1i",
	"/2s2a/5s5s/1s1l",
	"/2s2a/5s5s/1s1i/4s4a",
	"/2s2a/5s5s/1s1i/4s4h",
	"/2s2a/5s5s/1s1l/4s4a",
	"/2s2a/5s5s/1s1l/4s4h",
	"/2s2a/5s5s/4s4a",
	"/2s2a/5s5s/4s4h",
	"/2s2a/5s5s/4s4a",
	"/2s2a/5s5s/4s4h",
	"/2s2a/1s1i",
	"/2s2a/1s1l",
	"/2s2a/1s1i/4s4a",
	"/2s2a/1s1i/4s4h",
	"/2s2a/1s1l/4s4a",
	"/2s2a/1s1l/4s4h",
	"/2s2a/4s4a",
	"/2s2a/4s4h",
	"/2s2a/4s4a",
	"/2s2a/4s4h",
	"/3s3e",
	"/3s3e/5s5s",
	"/3s3e/5s5s/1s1i",
	"/3s3e/5s5s/1s1l",
	"/3s3e/5s5s/1s1i/4s4a",
	"/3s3e/5s5s/1s1i/4s4h",
	"/3s3e/5s5s/1s1l/4s4a",
	"/3s3e/5s5s/1s1l/4s4h",
	"/3s3e/5s5s/4s4a",
	"/3s3e/5s5s/4s4h",
	"/3s3e/5s5s/4s4a",
	"/3s3e/5s5s/4s4h",
	"/3s3e/1s1i",
	"/3s3e/1s1l",
	"/3s3e/1s1i/4s4a",
	"/3s3e/1s1i/4s4h",
	"/3s3e/1s1l/4s4a",
	"/3s3e/1s1l/4s4h",
	"/3s3e/4s4a",
	"/3s3e/4s4h",
	"/3s3e/4s4a",
	"/3s3e/4s4h",
	"/5s5s",
	"/5s5s/1s1i",
	"/5s5s/1s1l",
	"/5s5s/1s1i/4s4a",
	"/5s5s/1s1i/4s4h",
	"/5s5s/1s1l/4s4a",
	"/5s5s/1s1l/4s4h",
	"/5s5s/4s4a",
	"/5s5s/4s4h",
	"/5s5s/4s4a",
	"/5s5s/4s4h",
	"/1s1i",
	"/1s1l",
	"/1s1i/4s4a",
	"/1s1i/4s4h",
	"/1s1l/4s4a",
	"/1s1l/4s4h",
	"/4s4a",
	"/4s4h",
	"/4s4a",
	"/4s4h",
	/* done */
	(char *)0
};


int
FascistLook(PWDICT *pwp, const char *instring)
{
	int i;
	char *password;
	uint32_t notfound;
	char rpassword[PATH_MAX];

	notfound = PW_WORDS(pwp);

	(void) strlcpy(rpassword, instring, TRUNCSTRINGSIZE);
	password = rpassword;

	(void) strcpy(password, Lowercase(password));
	(void) Trim(password);

	/*
	 * it should be safe to use Mangle with its reliance on PATH_SIZE
	 * since password cannot be longer than TRUNCSTRINGSIZE;
	 * nonetheless this is not an elegant solution
	 */

	for (i = 0; r_destructors[i]; i++) {
		char *a;

		if (!(a = Mangle(password, r_destructors[i]))) {
			continue;
		}

		if (FindPW(pwp, a) != notfound) {
			return (DICTIONARY_WORD);
		}
	}

	(void) strlcpy(password, Reverse(password), PATH_MAX);

	for (i = 0; r_destructors[i]; i++) {
		char *a;

		if (!(a = Mangle(password, r_destructors[i]))) {
			continue;
		}
		if (FindPW(pwp, a) != notfound) {
			return (REVERSE_DICTIONARY_WORD);
		}
	}

	return (0);
}

int
DictCheck(const char *password, char *path)
{
	PWDICT *pwp;
	int r;

	if ((pwp = PWOpen(path, "rF")) == NULL)
		return (DATABASE_OPEN_FAIL);

	r = FascistLook(pwp, password);
	(void) PWClose(pwp);
	return (r);
}
