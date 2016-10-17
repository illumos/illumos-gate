#! /usr/bin/ksh
#
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

# Copyright 2015, Richard Lowe.

# Verify that zones can be configured with security-flags
LC_ALL=C                        # Collation is important

expect_success() {
    name=$1

    (echo "create -b";
     echo "set zonepath=/$name.$$";
     cat /dev/stdin;
     echo "verify";
     echo "commit";
     echo "exit") | zonecfg -z $name.$$ > out.$$ 2>&1

    r=$?

    zonecfg -z $name.$$ delete -F

    if (($r != 0)); then
        printf "%s: FAIL\n" $name
        cat out.$$
        rm out.$$
        return 1 
    else
        rm out.$$
        printf  "%s: PASS\n" $name
        return 0
    fi
}

expect_fail() {
    name=$1
    expect=$2

    (echo "create -b";
     echo "set zonepath=/$name.$$";
     cat /dev/stdin;
     echo "verify";
     echo "commit";
     echo "exit") | zonecfg -z $name.$$ > out.$$ 2>&1

    r=$?

    # Ideally will fail, since we don't want the create to have succeeded.
    zonecfg -z $name.$$ delete -F >/dev/null 2>&1


    if (($r == 0)); then
        printf "%s: FAIL (succeeded)\n" $name
        rm out.$$
        return 1
    else
        grep -q "$expect" out.$$
        if (( $? != 0 )); then
            printf "%s: FAIL (error didn't match)\n" $name
            echo "Wanted:"
            echo "  $expect"
            echo "Got:"
            sed -e 's/^/  /' out.$$
            rm out.$$
            return 1;
        else
            rm out.$$
            printf  "%s: PASS\n" $name
            return 0
        fi
    fi
}

ret=0

expect_success valid-no-config <<EOF
EOF
(( $? != 0 )) && ret=1

expect_success valid-full-config <<EOF
add security-flags
set lower=none
set default=aslr
set upper=all
end
EOF
(( $? != 0 )) && ret=1

expect_success valid-partial-config <<EOF
add security-flags
set default=aslr
end
EOF
(( $? != 0 )) && ret=1

expect_fail invalid-full-lower-gt-def "default secflags must be above the lower limit" <<EOF
add security-flags
set lower=aslr
set default=none
set upper=all
end
EOF
(( $? != 0 )) && ret=1

expect_fail invalid-partial-lower-gt-def "default secflags must be above the lower limit" <<EOF
add security-flags
set lower=aslr
set default=none
end
EOF
(( $? != 0 )) && ret=1

expect_fail invalid-full-def-gt-upper "default secflags must be within the upper limit" <<EOF
add security-flags
set lower=none
set default=all
set upper=none
end
EOF
(( $? != 0 )) && ret=1

expect_fail invalid-partial-def-gt-upper "default secflags must be within the upper limit" <<EOF
add security-flags
set default=all
set upper=none
end
EOF
(( $? != 0 )) && ret=1

expect_fail invalid-full-def-gt-upper "default secflags must be within the upper limit" <<EOF
add security-flags
set lower=none
set default=all
set upper=none
end
EOF
(( $? != 0 )) && ret=1

expect_fail invalid-partial-lower-gt-upper "lower secflags must be within the upper limit" <<EOF
add security-flags
set lower=all
set upper=none
end
EOF
(( $? != 0 )) && ret=1

expect_fail invalid-parse-fail-def "default security flags 'fail' are invalid" <<EOF
add security-flags
set default=fail
end
EOF
(( $? != 0 )) && ret=1

expect_fail invalid-parse-fail-lower "lower security flags 'fail' are invalid" <<EOF
add security-flags
set lower=fail
end
EOF
(( $? != 0 )) && ret=1

expect_fail invalid-parse-fail-def "upper security flags 'fail' are invalid" <<EOF
add security-flags
set upper=fail
end
EOF
(( $? != 0 )) && ret=1

exit $ret
