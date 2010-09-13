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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <crypt.h>
#include <string.h>

#ifdef CRYPT_SHA256
static const struct
{
	const char *salt;
	const char *input;
	const char *expected;
} tests2[] = {
	{ "$5$saltstring", "Hello world!",
	    "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" },
	{ "$5$rounds=10000$saltstringsaltstring", "Hello world!",
	    "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBA"
	    "wqFMz2.opqey6IcA" },
	{ "$5$rounds=5000$toolongsaltstring", "This is just a test",
	    "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07g"
	    "uHPvOW8mGRcvxa5" },
	{ "$5$rounds=1400$anotherlongsaltstring",
	    "a very much longer text to encrypt.  This one even stretches"
	    " over morethan one line.",
	    "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIU"
	    "nzyxf12oP84Bnq1" },
	{ "$5$rounds=77777$short",
	    "we have a short salt string but not a short password",
	    "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0"
	    "KQRd/" },
	{ "$5$rounds=123456$asaltof16chars..", "a short string",
	    "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2"
	    "jxPyzV/cZKmF/wJvD" },
	{ "$5$rounds=10$roundstoolow", "the minimum number is still observed",
	    "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY"
	    "9l/gL972bIC" },
};
#elif CRYPT_SHA512
static const struct
{
	const char *salt;
	const char *input;
	const char *expected;
} tests2[] = {
	{ "$6$saltstring", "Hello world!",
	    "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnI"
	    "FNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1" },
	{ "$6$rounds=10000$saltstringsaltstring", "Hello world!",
	    "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3"
	    "Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v." },
	{ "$6$rounds=5000$toolongsaltstring", "This is just a test",
	    "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxG"
	    "oNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0" },
	{ "$6$rounds=1400$anotherlongsaltstring",
	    "a very much longer text to encrypt.  This one even stretches "
	    "over morethan one line.",
	    "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/p"
	    "Qs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1" },
	{ "$6$rounds=77777$short",
	    "we have a short salt string but not a short password",
	    "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXb"
	    "kvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0" },
	{ "$6$rounds=123456$asaltof16chars..", "a short string",
	    "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ"
	    "4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1" },
	{ "$6$rounds=10$roundstoolow", "the minimum number is still observed",
	    "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50Y"
	    "hH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX." },
};

#else
#error "One of CRYPT_SHA256 or CRYPT_SHA512 must be defined"
#endif

#define	ntests2 (sizeof (tests2) / sizeof (tests2[0]))

int
main(int argc, char *argv[])
{
	int cnt;
	int failures = 0;
	char ctbuffer[CRYPT_MAXCIPHERTEXTLEN];
	size_t ctbufflen = sizeof (ctbuffer);

#ifdef CRYPT_SHA256
	fprintf(stderr, "CRYPT_SHA256 ");
#elif CRYPT_SHA512
	fprintf(stderr, "CRYPT_SHA512 ");
#endif
	fprintf(stderr, "CRYPT_MAXCIPHERTEXTLEN = %d\n",
	    CRYPT_MAXCIPHERTEXTLEN);
	for (cnt = 0; cnt < ntests2; ++cnt) {
		char *cp;
		fprintf(stderr, "test %d (outlen=%d):  ", cnt,
		    strlen(tests2[cnt].expected));
		cp = crypt_genhash_impl(ctbuffer, ctbufflen,
		    tests2[cnt].input, tests2[cnt].salt, NULL);

		if (cp == NULL || (strcmp(cp, tests2[cnt].expected) != 0)) {
			fprintf(stderr,
			    "FAILED\nE(%d): \"%s\"\nG(%d): \"%s\"\n",
			    strlen(tests2[cnt].expected), tests2[cnt].expected,
			    (cp ? strlen(cp) : 0), (cp ? cp : "NULL"));
			failures++;
		} else {
			fprintf(stderr, "OK\n");
		}
	}

	if (failures == 0) {
		fprintf(stderr, "all tests OK\n");
	} else {
		fprintf(stderr, "%d tests failed\n", failures);
	}

	return (failures);
}
