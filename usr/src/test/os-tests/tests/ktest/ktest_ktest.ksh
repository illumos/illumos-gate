#!/usr/bin/ksh
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
# Copyright 2025 Oxide Computer Company
#

# Load the required ktest module
if ! ktest load ktest; then
	exit 1
fi

echo "Running status tests"
echo "Some are expected to emit non-PASS results"
ktest run -n -p -o "test,result" ktest:selftest: | awk -F: '
BEGIN {
	expect["ktest_st_none_test"] = "NONE";
	expect["ktest_st_pass_test"] = "PASS";
	expect["ktest_st_fail_test"] = "FAIL";
	expect["ktest_st_err_test"] = "ERROR";
	expect["ktest_st_skip_test"] = "SKIP";
	expect["ktest_st_mult_result_test"] = "ERROR";
	expect["ktest_st_unique_test"] = "PASS";
	expect["ktest_st_name_test"] = "PASS";

	expected_count = 8;

	test_count = 0;
	issue_count = 0;
}
/:/ {
	print $0
	test_count += 1;
	if ($1 in expect) {
		if (expect[$1] != $2) {
			printf "Unexpected status for test %s, %s != %s\n",
			    $1, $2, expect[$1];
			issue_count += 1;
		}
	} else {
		printf "unexpected test %s\n" $1
		issue_count += 1;
	}
}
END {
if (test_count != expected_count) {
		printf "Did not encount expected number of tests: %d != %d\n",
		    test_count, expected_count;
		issue_count += 1;
	}
	if (issue_count != 0) {
		print "Errors detected"
		exit 1
	}
}
'
exit $?
