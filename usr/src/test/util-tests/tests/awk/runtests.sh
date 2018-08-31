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

#
# Copyright 2018, Joyent, Inc.
#

AWK=/usr/bin/nawk
WORKDIR=$(mktemp -d /tmp/nawktest.XXXXXX)

SUCCESSES=0
TOTAL=0

while [[ $# -gt 0 ]]; do
	case $1 in
		-o)
		AWK=$2
		shift 2
		;;
		*)
		printf 'Usage: runtests.sh [-o <override awk executable>]\n' >&2
		exit 1
		;;
	esac
done

# Make path absolute so we can change directories.
AWK=$(cd $(dirname $AWK); pwd)/$(basename $AWK)
TOP=$(cd $(dirname $0); pwd)

# Move into $TOP in case we were run from elsewhere.
cd $TOP

if [[ ! -x $AWK ]]; then
	printf 'awk executable "%s" is not executable\n' "$AWK" >&2
	exit 1
fi

if [[ ! -x /bin/bash ]]; then
	printf 'executable "/bin/bash" not found\n' >&2
	exit 1
fi

if [[ "$(id -u)" == "0" ]]; then
	printf 'runtests.sh should not be run as root\n' >&2
	exit 1
fi


export AWK
export WORKDIR

mkdir -p $WORKDIR

printf 'Running AWK tests ($AWK="%s")\n' "$AWK"

printf '\n# Examples from "The AWK Programming Environment"\n\n'

for script in examples/awk/p.*; do
	((TOTAL+=1))
	printf "$script... "
	if cmp -s <($AWK -f ${script} data/test.countries 2>&1) ${script/awk/out}; then
		printf "ok\n"
		((SUCCESSES+=1))
	else
		printf "failed\n"
	fi
done

printf '\n# One True AWK Example Programs\n\n'

for script in examples/awk/t.*; do
	((TOTAL+=1))
	printf "$script... "
	if diff <($AWK -f ${script} data/test.data 2>&1) ${script/awk/out}; then
		printf "ok\n"
		((SUCCESSES+=1))
	else
		printf "failed\n"
	fi
done

# Run the test programs

printf '\n# One True AWK Test Programs\n\n'

cd tests || exit 1
for script in ./T.*; do
	((TOTAL+=1))
	rm -f $WORKDIR/test.temp*
	printf "$script... "
	if $script > /dev/null 2>&1; then
		printf "ok\n"
		((SUCCESSES+=1))
	else
		printf "failed\n"
	fi
done
cd $TOP

printf '\n# Imported GAWK Test Programs\n\n'

cd gnu || exit 1
for PROG in *.awk; do
	((TOTAL+=1))
	export LANG=C
	printf "$PROG... "
	INPUT="${PROG/.awk/.in}"
	if [[ -f $INPUT ]]; then
		$AWK -f $PROG < $INPUT > $WORKDIR/test.temp.out 2>&1 || \
		    echo EXIT CODE: $? >> $WORKDIR/test.temp.out
	else
		$AWK -f $PROG > $WORKDIR/test.temp.out 2>&1 || \
		    echo EXIT CODE: $? >> $WORKDIR/test.temp.out
	fi
	if diff $WORKDIR/test.temp.out ${PROG/.awk/.ok}; then
		printf "ok\n"
		((SUCCESSES+=1))
	else
		printf "failed\n"
	fi
done

for script in ./*.sh; do
	((TOTAL+=1))
	export LANG=C
	printf "$script... "
	$script > $WORKDIR/test.temp.out 2>&1
	if diff $WORKDIR/test.temp.out ${script/.sh/.ok}; then
		printf "ok\n"
		((SUCCESSES+=1))
	else
		printf "failed\n"
	fi
done
cd $TOP

printf '\n# Imported GAWK Syntax Tests\n\n'

cd syn || exit 1
for PROG in *.awk; do
	((TOTAL+=1))
	printf "$PROG... "
	if $AWK -f $PROG /dev/null > /dev/null 2> $WORKDIR/test.temp.out; then
		printf "failed (should exit nonzero)\n"
		continue
	fi

	if diff $WORKDIR/test.temp.out <(sed "s|\$AWK|$AWK|g" ${PROG/.awk/.ok}); then
		printf "ok\n"
		((SUCCESSES+=1))
	else
		printf "failed\n"
	fi
done
cd $TOP

printf '\n\nTOTAL: %d/%d\n' "$SUCCESSES" "$TOTAL"

rm -rf $WORKDIR

if [[ $SUCCESSES != $TOTAL ]]; then
	exit 1
fi
