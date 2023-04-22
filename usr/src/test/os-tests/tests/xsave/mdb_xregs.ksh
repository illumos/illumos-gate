#!/usr/bin/ksh
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

#
# Copyright 2023 Oxide Computer Company
#

#
# This test attempts to verify that we can mdb (via libproc / thread_db)
# and xregs sees the expected extended register set. It also ensures
# that the same values are visible via a core file from that process at
# the same point.
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

mx_exit=0
mx_arg0="$(basename $0)"
mx_dir="$(dirname $0)"
mx_data="$mx_dir/data"
mx_tmpdir="/tmp/mdb_xregs.$$"

typeset -A mx_seed
mx_seed["32"]=0x12900922
mx_seed["64"]=0x11900456
typeset -A mx_hwtype
mx_hwtype["32"]="$mx_dir/xsu_hwtype.32"
mx_hwtype["64"]="$mx_dir/xsu_hwtype.64"
typeset -A mx_setprog
mx_setprog["32"]="$mx_dir/xregs_set.32"
mx_setprog["64"]="$mx_dir/xregs_set.64"

warn()
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	mx_exit=1
}

fatal()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "$mx_arg0: $msg" >&2
	exit 1
}

cleanup()
{
	[[ -n "$mx_tmpdir" ]] && rm -rf "$mx_tmpdir"
}

setup()
{
	if ! mkdir $mx_tmpdir; then
		fatal "failed to create temporary directory: $mx_tmpdir"
	fi
}

check_file()
{
	typeset src="$1"
	typeset act="$2"
	typeset desc="$3"

	if [[ ! -f "$act" ]]; then
		warn "failed to generate $act"
		return
	fi

	if ! diff -q $src $act; then
		diff -u $src $act
		warn "$desc: $act did not match expected output"
	else
		printf "TEST PASSED: %s\n" "$desc"
	fi
}

#
# Run one instance of mdb to grab and get our first pass data files
# against a real process. We're not really counting on our exit status
# from mdb here, mostly on whether or not the generated files all exist
# in the end. We gather data from the generated cores in a separate run.
#
run_live_mdb()
{
	typeset prog="$1"
	typeset seed="$2"
	typeset fpregs="$3"
	typeset core="$4"
	typeset coreloc="$5"

	mdb $prog <<EOF
yield::bp
::run $seed
::tmodel lwp
::fpregs ! cat > $fpregs.lwp
::tmodel thread
::fpregs ! cat > $fpregs.thread
_uberdata::printf "$core.%u" uberdata_t pid ! cat > $coreloc
::gcore -o $core
::kill
\$q
EOF
}

#
# We've been given a core file that matches something we just ran above. We
# should be able to read the ::fpregs from it and get the exact same data.
#
check_core()
{
	typeset core="$1"
	typeset output="$2"
	typeset check="$3"

	if ! mdb -e "::fpregs ! cat > $output" $core; then
		warn "mdb failed to get ::fpregs from $core"
		return
	fi

	check_file $check $output "extracted core matches"
}

run_one_isa()
{
	typeset isa="$1"
	typeset target=${mx_setprog[$isa]}
	typeset hwprog=${mx_hwtype[$isa]}
	typeset seed=${mx_seed[$isa]}
	typeset coreloc="$mx_tmpdir/coreloc"
	typeset fpu_type=
	typeset corename=
	typeset fpregs=
	typeset check=

	if ! fpu_type=$($hwprog 2>/dev/null); then
		warn "failed to determine $isa-bit FPU type"
		return
	fi

	printf "Discovered FPU: %s %s-bit\n" $fpu_type $isa
	corename="$mx_tmpdir/core.$fpu_type.$isa"
	fpregs="$mx_tmpdir/fpregs.$fpu_type.$isa"
	check="$mx_data/mdb_xregs.$fpu_type.$isa"

	run_live_mdb $target $seed $fpregs $corename $coreloc
	check_file "$check" "$fpregs.lwp" "$isa-bit $fpu_type ::fpregs (lwp)"
	check_file "$check" "$fpregs.lwp" "$isa-bit $fpu_type ::fpregs (thread)"

	if [[ ! -f "$coreloc" ]]; then
		warn "missing core file location file, cannot run core tests"
		return
	fi

	typeset -i ncores=0
	for f in $(cat $coreloc); do
		((ncores++))
		if [[ ! -f "$f" ]]; then
			warn "core file location $f is not a file"
			continue
		fi

		check_core "$f" "$mx_tmpdir/fpregs.core" $check
	done

	if ((ncores == 0)); then
		warn "No core files found!"
	fi
}

setup
trap 'cleanup' EXIT

run_one_isa "32"
run_one_isa "64"

exit $mx_exit
