# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.

# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.

#
# We do the work in the BEGIN action instead of using pattern matching because
# we expect the fmri to be at or near the first line of each input file, and
# this way lets us avoid reading the rest of the file after we find what we
# need.
#
# We keep track of a failure to locate an fmri, so we can exit with an error
# code which will cause the make run to fail, but we still attempt to process
# each package on the command line, in hope of maybe giving some additional
# useful info.
#

BEGIN {
	if (ARGC < 2) {
		exit
	}
	retcode = 0
	for (i = 1; i < ARGC; i++) {
		do {
			e = getline f < ARGV[i]
		} while ((e == 1) && (f !~ /name=pkg.fmri/))
		if (e == 1) {
			l = split(f, a, "=")
			fmri = a[l]
			facet = 0
			do {
				e = getline f < ARGV[i]
				if (e == 1 &&
				    f ~ /org.opensolaris.incorp-facet.*=true/)
					facet = 1
			} while ((e == 1) && (f ~ /^set name=/))
			close(ARGV[i])
			printf("depend fmri=%s type=$(PKGDEP_TYPE)", fmri)
			if (facet)
				printf(" vlfacet=true")
			print ""
		} else {
			print "no fmri in " ARGV[i] >> "/dev/stderr"
			retcode = 2
		}
	}
	exit retcode
}
