#!/usr/bin/ksh
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# souroc.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/liocnse/CDDL.
#

#
# Copyright 2022 Oxide Computer Company
#

#
# This test focuses around the generation of files with object capabilities and
# verifies that tools like elfedit, elfdump, ld, and ld.so.1 can deal with them
# all appropriately.
#

export LC_ALL=C.UTF-8
unalias -a
set -o pipefail

oc_arg0=$(basename $0)
oc_tmpdir=/tmp/objcap.$$
oc_prog_nocap="$oc_tmpdir/prog.nocap"
oc_prog_hw1="$oc_tmpdir/prog.hw1"
oc_prog_hw3="$oc_tmpdir/prog.hw3"
oc_prog_hw123="$oc_tmpdir/prog.hw123"
oc_cap_hw1="0x42"
oc_cap_hw2="0x169"
oc_cap_hw3="0x7777"
oc_err=0

pass()
{
        typeset msg="$*"
	echo "TEST PASSED: $msg"
}

warn()
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "TEST FAILED: $msg" >&2
	oc_err=1
}

fatal()
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$oc_arg0: $msg" >&2
        exit 1
}

cleanup()
{
	rm -rf "$oc_tmpdir"
}

#
# Set up our test environment. This generally requires us to create the
# source file, mapfiles, and related contents that the test requires.
#
setup()
{
	typeset cfile="$oc_tmpdir/test.c"
	typeset mapfile_hw1="$oc_tmpdir/test.mapfile.hw1"
	typeset mapfile_hw3="$oc_tmpdir/test.mapfile.hw3"
	typeset mapfile_hw123="$oc_tmpdir/test.mapfile.hw123"

	if ! mkdir "$oc_tmpdir"; then
		fatal "failed to make directory $oc_tmpdir"
	fi

	trap 'cleanup' EXIT

	cat > $cfile <<EOF
int
main(void)
{
	return (0);
}
EOF
	if (( $? != 0 )); then
		fatal "failed to write token C file to $cfile"
	fi

	cat > $mapfile_hw1 <<EOF
\$mapfile_version 2
CAPABILITY {
	HW_1 += $oc_cap_hw1;
};
EOF

	if (( $? != 0 )); then
		fatal "failed to write out $mapfile_hw1"
	fi

	cat > $mapfile_hw3 <<EOF
\$mapfile_version 2
CAPABILITY {
	HW_3 += $oc_cap_hw3;
};
EOF

	if (( $? != 0 )); then
		fatal "failed to write out $mapfile_hw3"
	fi

	cat > $mapfile_hw123 <<EOF
\$mapfile_version 2
CAPABILITY {
	HW_1 += $oc_cap_hw1;
	HW_2 += $oc_cap_hw2;
	HW_3 += $oc_cap_hw3;
};
EOF

	if (( $? != 0 )); then
		fatal "failed to write out $mapfile_hw3"
	fi

	if ! gcc -m64 -o $oc_prog_nocap $cfile; then
		fatal "failed to create $oc_prog_nocap"
	fi

	if ! gcc -m64 -o $oc_prog_hw1 $cfile -Wl,-M$mapfile_hw1; then
		fatal "failed to create $oc_prog_hw1"
	fi

	if ! gcc -m64 -o $oc_prog_hw3 $cfile -Wl,-M$mapfile_hw3; then
		fatal "failed to create $oc_prog_hw1"
	fi

	if ! gcc -m64 -o $oc_prog_hw123 $cfile -Wl,-M$mapfile_hw123; then
		fatal "failed to create $oc_prog_hw1"
	fi
}

verify_caps()
{
	typeset file="$1"
	typeset data="$2"
	typeset -a vals=($3 $4 $5)
	typeset -a caps=("CA_SUNW_HW_1" "CA_SUNW_HW_2" "CA_SUNW_HW_3")
	typeset -a ee=("cap:hw1" "cap:hw2" "cap:hw3")
	typeset out=
	typeset ee_out=
	typeset i=

	out=$(elfdump -H $file 2>&1)
	if (( $? != 0 )); then
		warn "elfdump -H $file failed with $?"
		return
	fi

	#
	# If we don't expect a object capability, then we're done here.
	#
	if (( data == 0 )); then
		if [[ -n "$out" ]]; then
			fail "elfdump -H $file had unexpected output: $out"
		else
			pass "elfdump -H $file contained no output"
		fi
		return
	fi

	if [[ -z "$out" ]]; then
		fail "elfdump -H $file had no output, but expected caps"
		return
	fi

	#
	# At this point, for each hw cap, if there is a value, check that we
	# have an elfdump output line and then verify that we have the expected
	# value via elfedit.
	#
	for ((i = 0; i < 3; i++)); do
		if [[ "${vals[$i]}" == "0" ]]; then
			continue;
		fi

		if ! echo $out | grep -q ${caps[$i]}; then
			warn "elfdump -H $file missing ${caps[$i]}"
		else
			pass "elfdump -H $file has ${caps[$i]}"
		fi

		ee_out=$(elfedit -e "${ee[$i]} -o num" $file)
		if [[ -z $ee_out ]]; then
			warn "failed to dump ${ee[$i]} from $file via elfedit"
			continue
		fi

		if [[ "$ee_out" != "${vals[$i]}" ]]; then
			warn "mismatched value for ${ee[$i]} in $file: found " \
			    "$out, expected ${vals[$i]}"
		else
			pass "elfedit has correct value for ${ee[$i]} in $file"
		fi
	done
}

#
# Attempt to execute a program with symbol capabilities. We override the
# symbol capabilities in the system for the specified file to the ones
# indicated in the function. We need to restrict to the program we're
# calling so that way we don't accidentally tell ld not to load a system
# library.
#
run_prog()
{
	typeset prog="$1"
	typeset run=$2
	typeset cap="$3"
	typeset case="$4"
	typeset ret=

	LD_CAP_FILES=$prog LD_HWCAP=$3 $prog 2>/dev/null 1>/dev/null
	ret=$?
	if (( run != 0 && ret == 0 )); then
		pass "exec prog $case"
	elif (( run != 0 && ret != 0 )); then
		warn "exec prog $case returned $ret, expected 0"
	elif (( run == 0 && ret == 0 )); then
		warn "exec prog $case returned $ret, expected non-zero"
	else
		pass "exec prog $case"
	fi
}

#
# Use elfedit to modify a specific hwcap and make sure we see the new value.
#
edit_prog()
{
	typeset input="$1"
	typeset pass="$2"
	typeset cap="$3"
	typeset cmd="$4"
	typeset exp="$5"
	typeset ret=

	rm -f "$input.edit"
	elfedit -e "$cap $cmd" "$input" "$input.edit" >/dev/null 2>/dev/null
	ret=$?

	if (( pass == 0 )); then
		if (( ret == 0 )); then
			warn "elfedit -e $cap $cmd $input worked, expected failure"
		else
			pass "elfedit -e $cap $cmd $input failed correctly"
		fi
		return
	fi

	if (( ret != 0 )); then
		warn "elfedit -e $cap $cmd $input failed with $ret, expected success"
		return
	fi

	ret=$(elfedit -e "$cap -o num" "$input.edit")
	if (( $? != 0 )); then
		warn "failed to extract hwcap after elfedit -e $cap $cmd $input"
	fi

	if [[ "$ret" != "$exp" ]]; then
		warn "elfedit -e $cap $cmd $input had wrong output " \
		    "expected $exp, found $val"
	else
		pass "elfedit -e $cap $cmd $input"
	fi
}

setup
verify_caps "$oc_prog_nocap" 0
verify_caps "$oc_prog_hw1" 1 $oc_cap_hw1 0 0
verify_caps "$oc_prog_hw3" 1 0 0 $oc_cap_hw3
verify_caps "$oc_prog_hw123" 1 $oc_cap_hw1 $oc_cap_hw2 $oc_cap_hw3

#
# Now that we've verified the caps in these files, try to run them in a
# given alternate symbol cap env.
#
run_prog "$oc_prog_nocap" 1 "[1]0,[2]0,[3]0" "no need, no caps"
run_prog "$oc_prog_hw1" 0 "[1]0,[2]0,[3]0" "need hw1, no caps"
run_prog "$oc_prog_hw3" 0 "[1]0,[2]0,[3]0" "need hw3, no caps"
run_prog "$oc_prog_hw123" 0 "[1]0,[2]0,[3]0" "need hw{123}, no caps"

run_prog "$oc_prog_nocap" 1 "[1]0x42,[2]0,[3]0" "no need, hw1=0x42"
run_prog "$oc_prog_hw1" 1 "[1]0x42,[2]0,[3]0" "need hw1, hw1=0x42"
run_prog "$oc_prog_hw3" 0 "[1]0x42,[2]0,[3]0" "need hw3, hw1=0x42"
run_prog "$oc_prog_hw123" 0 "[1]0x42,[2]0,[3]0" "need hw{123}, hw1=0x42"

run_prog "$oc_prog_nocap" 1 "[1]0,[2]0,[3]0x7777" "no need, hw3=0x7777"
run_prog "$oc_prog_hw1" 0 "[1]0,[2]0,[3]0x7777" "need hw1, hw3=0x7777"
run_prog "$oc_prog_hw3" 1 "[1]0,[2]0,[3]0x7777" "need hw3, hw3=0x7777"
run_prog "$oc_prog_hw123" 0 "[1]0,[2]0,[3]0x7777" "need hw{123}, hw3=0x7777"

run_prog "$oc_prog_nocap" 1 "[1]0,[2]0x1369,[3]0" "no need, hw2=0x1369"
run_prog "$oc_prog_hw1" 0 "[1]0,[2]0x1369,[3]0" "need hw1, hw2=0x1369"
run_prog "$oc_prog_hw3" 0 "[1]0,[2]0x1369,[3]0" "need hw3, hw2=0x1369"
run_prog "$oc_prog_hw123" 0 "[1]0,[2]0x1369,[3]0" "need hw{123}, hw2=0x1369"

run_prog "$oc_prog_nocap" 1 "[1]0x42,[2]0,[3]0x7777" \
    "no need, hw1=0x42,hw3=0x7777"
run_prog "$oc_prog_hw1" 1 "[1]0x42,[2]0,[3]0x7777" \
    "need hw1, hw1=0x42,hw3=0x7777"
run_prog "$oc_prog_hw3" 1 "[1]0x42,[2]0,[3]0x7777" \
    "need hw3, hw1=0x42,hw3=0x7777"
run_prog "$oc_prog_hw123" 0 "[1]0x42,[2]0,[3]0x7777" \
     "need hw{123}, hw1=0x42,hw3=0x7777"

run_prog "$oc_prog_nocap" 1 "[1]0x42,[2]0x1369,[3]0x7777" \
    "no need, hw1=0x42,hw2=0x1369,hw3=0x7777"
run_prog "$oc_prog_hw1" 1 "[1]0x42,[2]0x1369,[3]0x7777" \
    "need hw1, hw1=0x42,hw2=0x1369,hw3=0x7777"
run_prog "$oc_prog_hw3" 1 "[1]0x42,[2]0x1369,[3]0x7777" \
    "need hw3, hw1=0x42,hw2=0x1369,hw3=0x7777"
run_prog "$oc_prog_hw123" 1 "[1]0x42,[2]0x1369,[3]0x7777" \
    "need hw{123}, hw1=0x42,hw2=0x1369,hw3=0x7777"

edit_prog "$oc_prog_hw1" 1 "cap:hw1" "-or 0x1000" "0x1042"
edit_prog "$oc_prog_hw1" 1 "cap:hw1" "-and 0x1000" "0"
edit_prog "$oc_prog_hw1" 1 "cap:hw1" "-cmp 0x42" "0xffffffbd"
edit_prog "$oc_prog_hw3" 1 "cap:hw3" "-and 0x643f" "0x6437"
edit_prog "$oc_prog_hw123" 1 "cap:hw2" "0x12345" "0x12345"

#
# Failure cases here are meant to cover missing capaibilities and bad strings.
#
edit_prog "$oc_prog_hw1" 0 "cap:hw1" "-or zelda"
edit_prog "$oc_prog_hw1" 0 "cap:hw2" "-or 0x100"
edit_prog "$oc_prog_nocap" 0 "cap:hw1" "-or 0x1"
edit_prog "$oc_prog_hw3" 0 "cap:hw1" "-and 0xff"
edit_prog "$oc_prog_hw3" 0 "cap:hw2" "-and 0xff"
edit_prog "$oc_prog_hw3" 0 "cap:hw3" "-and link"
edit_prog "$oc_prog_hw123" 0 "cap:hw2" "ganondorf"

if (( oc_err == 0 )); then
	printf "All tests passed successfully\n"
fi

exit $oc_err
