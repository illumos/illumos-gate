#!/usr/bin/env python

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2017 by Delphix. All rights reserved.
#

import re
import sys

#
# This script parses the stdout of zfstest, which has this format:
#
# Test: /path/to/testa (run as root) [00:00] [PASS]
# Test: /path/to/testb (run as jkennedy) [00:00] [PASS]
# Test: /path/to/testc (run as root) [00:00] [FAIL]
# [...many more results...]
#
# Results Summary
# FAIL       4
# PASS     450
#
# Running Time:   01:15:33
# Percent passed: 99.1%
# Log directory:  /var/tmp/test_results/20130720T050603
#

summary = {
    'total': float(0),
    'passed': float(0),
    'logfile': "Could not determine logfile location."
}

#
# These tests are known to fail, thus we use this list to prevent these
# failures from failing the job as a whole; only unexpected failures
# bubble up to cause this script to exit with a non-zero exit status.
#
known = {
    'acl/nontrivial/zfs_acl_chmod_inherit_003_pos': 'FAIL',
    'bootfs/bootfs_006_pos': 'FAIL',
    'bootfs/bootfs_008_neg': 'FAIL',
    'cache/cache_010_neg': 'FAIL',
    'cli_root/zfs_property/zfs_written_property_001_pos': 'FAIL',
    'cli_root/zfs_snapshot/zfs_snapshot_009_pos': 'FAIL',
    'cli_root/zpool_add/zpool_add_001_pos': 'FAIL',
    'cli_root/zpool_add/zpool_add_002_pos': 'FAIL',
    'cli_root/zpool_clear/zpool_clear_001_pos': 'FAIL',
    'cli_root/zpool_expand/zpool_expand_001_pos': 'FAIL',
    'cli_root/zpool_get/zpool_get_002_pos': 'FAIL',
    'delegate/zfs_allow_007_pos': 'FAIL',
    'devices/devices_001_pos': 'FAIL',
    'devices/devices_002_neg': 'FAIL',
    'grow_replicas/grow_replicas_001_pos': 'FAIL',
    'inheritance/inherit_001_pos': 'FAIL',
    'mdb/mdb_001_pos': 'FAIL',
    'refreserv/refreserv_004_pos': 'FAIL',
    'rootpool/rootpool_002_neg': 'FAIL',
    'rootpool/rootpool_007_neg': 'FAIL',
    'redundancy/redundancy_001_pos': 'FAIL',
    'redundancy/redundancy_002_pos': 'FAIL',
    'redundancy/redundancy_003_pos': 'FAIL',
    'redundancy/redundancy_004_neg': 'FAIL',
    'reservation/reservation_013_pos': 'FAIL',
    'reservation/reservation_017_pos': 'FAIL',
    'rsend/rsend_008_pos': 'FAIL',
    'rsend/rsend_009_pos': 'FAIL',
    'scrub_mirror/scrub_mirror_001_pos': 'SKIP',
    'scrub_mirror/scrub_mirror_002_pos': 'SKIP',
    'scrub_mirror/scrub_mirror_003_pos': 'SKIP',
    'scrub_mirror/scrub_mirror_004_pos': 'SKIP',
    'scrub_mirror/setup': 'FAIL',
    'slog/slog_013_pos': 'FAIL',
    'slog/slog_014_pos': 'FAIL',
    'snapshot/snapshot_008_pos' : 'FAIL',
    'vdev_zaps/vdev_zaps_007_pos': 'FAIL',
    'write_dirs/setup': 'FAIL',
    'write_dirs/write_dirs_001_pos': 'SKIP',
    'write_dirs/write_dirs_002_pos': 'SKIP',
    'xattr/xattr_011_pos': 'FAIL',
    'zpool_clear/zpool_clear_001_pos': 'FAIL',
    'zvol/zvol_misc/zvol_misc_001_neg': 'FAIL',
    'zvol/zvol_misc/zvol_misc_002_pos': 'FAIL',
    'zvol/zvol_misc/zvol_misc_003_neg': 'FAIL',
    'zvol/zvol_misc/zvol_misc_004_pos': 'FAIL',
    'zvol/zvol_misc/zvol_misc_005_neg': 'FAIL',
    'zvol/zvol_misc/zvol_misc_006_pos': 'FAIL',
    'zvol/zvol_swap/zvol_swap_004_pos': 'FAIL'
}


def usage(s):
    print s
    sys.exit(1)


def process_results(pathname):
    try:
        f = open(pathname)
    except IOError, e:
        print 'Error opening file: %s' % e
        sys.exit(1)

    prefix = '/opt/zfs-tests/tests/functional/'
    pattern = '^Test:\s*%s(\S+)\s*\(run as (\S+)\)\s*\[(\S+)\]\s*\[(\S+)\]' % \
              prefix
    pattern_log = '^\s*Log directory:\s*(\S*)'

    d = {}
    for l in f.readlines():
        m = re.match(pattern, l)
        if m and len(m.groups()) == 4:
            summary['total'] += 1
            if m.group(4) == "PASS":
                summary['passed'] += 1
            d[m.group(1)] = m.group(4)
            continue

        m = re.match(pattern_log, l)
        if m:
            summary['logfile'] = m.group(1)

    return d


if __name__ == "__main__":
    if len(sys.argv) is not 2:
        usage('usage: %s <pathname>' % sys.argv[0])
    results = process_results(sys.argv[1])

    if summary['total'] == 0:
        print "\n\nNo test results were found."
        print "Log directory:  %s" % summary['logfile']
        sys.exit(0)

    expected = []
    unexpected = []

    for test in results.keys():
        if results[test] == "PASS":
            continue

        if test not in known or results[test] not in known[test]:
            unexpected.append(test)
        else:
            expected.append(test)

    print "\nTests with results other than PASS that are expected:"
    for test in sorted(expected):
        print "    %s %s" % (results[test], test)

    print "\nTests with result of PASS that are unexpected:"
    for test in sorted(known.keys()):
        # We probably should not be silently ignoring the case
        # where "test" is not in "results".
        if test not in results or results[test] != "PASS":
            continue
        print "    %s %s (expected %s)" % (results[test], test, known[test])

    print "\nTests with results other than PASS that are unexpected:"
    for test in sorted(unexpected):
        expect = "PASS" if test not in known else known[test]
        print "    %s %s (expected %s)" % (results[test], test, expect)

    print "\nPercent passed: %5.2f%%" % \
        ((summary['passed'] / summary['total']) * 100)
    print "Log directory:  %s" % summary['logfile']

    if len(unexpected) == 0:
        sys.exit(0)
    else:
        sys.exit(1)
