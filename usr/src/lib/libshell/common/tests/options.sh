########################################################################
#                                                                      #
#               This software is part of the ast package               #
#           Copyright (c) 1982-2007 AT&T Knowledge Ventures            #
#                      and is licensed under the                       #
#                  Common Public License, Version 1.0                  #
#                      by AT&T Knowledge Ventures                      #
#                                                                      #
#                A copy of the License is available at                 #
#            http://www.opensource.org/licenses/cpl1.0.txt             #
#         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         #
#                                                                      #
#              Information and Software Systems Research               #
#                            AT&T Research                             #
#                           Florham Park NJ                            #
#                                                                      #
#                  David Korn <dgk@research.att.com>                   #
#                                                                      #
########################################################################
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	let Errors+=1
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0
if	[[ $( ${SHELL-ksh} -s hello<<-\!
		print $1
		!
	    ) != hello ]]
then	err_exit "${SHELL-ksh} -s not working"
fi
x=$(
	set -e
	false && print bad
	print good
)
if	[[ $x != good ]]
then	err_exit 'sh -e not workuing'
fi
[[ $($SHELL -D -c 'print hi; print $"hello"') == '"hello"' ]] || err_exit 'ksh -D not working'

tmp=/tmp/ksh$$
mkdir $tmp
rc=$tmp/.kshrc
print $'function env_hit\n{\n\tprint OK\n}' > $rc

export ENV=$rc
if	[[ -o privileged ]]
then
	[[ $(print env_hit | $SHELL 2>&1) == "OK" ]] &&
		err_exit 'privileged nointeractive shell reads $ENV file'
	[[ $(print env_hit | $SHELL -E 2>&1) == "OK" ]] &&
		err_exit 'privileged -E reads $ENV file'
	[[ $(print env_hit | $SHELL +E 2>&1) == "OK" ]] &&
		err_exit 'privileged +E reads $ENV file'
	[[ $(print env_hit | $SHELL --rc 2>&1) == "OK" ]] &&
		err_exit 'privileged --rc reads $ENV file'
	[[ $(print env_hit | $SHELL --norc 2>&1) == "OK" ]] &&
		err_exit 'privileged --norc reads $ENV file'
else
	[[ $(print env_hit | $SHELL 2>&1) == "OK" ]] &&
		err_exit 'nointeractive shell reads $ENV file'
	[[ $(print env_hit | $SHELL -E 2>&1) == "OK" ]] ||
		err_exit '-E ignores $ENV file'
	[[ $(print env_hit | $SHELL +E 2>&1) == "OK" ]] &&
		err_exit '+E reads $ENV file'
	[[ $(print env_hit | $SHELL --rc 2>&1) == "OK" ]] ||
		err_exit '--rc ignores $ENV file'
	[[ $(print env_hit | $SHELL --norc 2>&1) == "OK" ]] &&
		err_exit '--norc reads $ENV file'
fi

export ENV=
if	[[ -o privileged ]]
then
	[[ $(print env_hit | HOME=$tmp $SHELL 2>&1) == "OK" ]] &&
		err_exit 'privileged nointeractive shell reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL -E 2>&1) == "OK" ]] &&
		err_exit 'privileged -E ignores empty $ENV'
	[[ $(print env_hit | HOME=$tmp $SHELL +E 2>&1) == "OK" ]] &&
		err_exit 'privileged +E reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL --rc 2>&1) == "OK" ]] &&
		err_exit 'privileged --rc ignores empty $ENV'
	[[ $(print env_hit | HOME=$tmp $SHELL --norc 2>&1) == "OK" ]] &&
		err_exit 'privileged --norc reads $HOME/.kshrc file'
else
	[[ $(print env_hit | HOME=$tmp $SHELL 2>&1) == "OK" ]] &&
		err_exit 'nointeractive shell reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL -E 2>&1) == "OK" ]] &&
		err_exit '-E ignores empty $ENV'
	[[ $(print env_hit | HOME=$tmp $SHELL +E 2>&1) == "OK" ]] &&
		err_exit '+E reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL --rc 2>&1) == "OK" ]] &&
		err_exit '--rc ignores empty $ENV'
	[[ $(print env_hit | HOME=$tmp $SHELL --norc 2>&1) == "OK" ]] &&
		err_exit '--norc reads $HOME/.kshrc file'
fi

unset ENV
if	[[ -o privileged ]]
then
	[[ $(print env_hit | HOME=$tmp $SHELL 2>&1) == "OK" ]] &&
		err_exit 'privileged nointeractive shell reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL -E 2>&1) == "OK" ]] &&
		err_exit 'privileged -E reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL +E 2>&1) == "OK" ]] &&
		err_exit 'privileged +E reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL --rc 2>&1) == "OK" ]] &&
		err_exit 'privileged --rc reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL --norc 2>&1) == "OK" ]] &&
		err_exit 'privileged --norc reads $HOME/.kshrc file'
else
	[[ $(print env_hit | HOME=$tmp $SHELL 2>&1) == "OK" ]] &&
		err_exit 'nointeractive shell reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL -E 2>&1) == "OK" ]] ||
		err_exit '-E ignores $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL +E 2>&1) == "OK" ]] &&
		err_exit '+E reads $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL --rc 2>&1) == "OK" ]] ||
		err_exit '--rc ignores $HOME/.kshrc file'
	[[ $(print env_hit | HOME=$tmp $SHELL --norc 2>&1) == "OK" ]] &&
		err_exit '--norc reads $HOME/.kshrc file'
fi

rm -rf $tmp

if	command set -G 2> /dev/null
then	mkdir /tmp/ksh$$
	cd /tmp/ksh$$
	mkdir bar foo
	> bar.c  > bam.c
	> bar/foo.c > bar/bam.c
	> foo/bam.c
	set -- **.c
	expected='bam.c bar.c'
	[[ $* == $expected ]] ||
		err_exit "-G **.c failed -- expected '$expected', got '$*'"
	set -- **
	expected='bam.c bar bar.c bar/bam.c bar/foo.c foo foo/bam.c'
	[[ $* == $expected ]] ||
		err_exit "-G ** failed -- expected '$expected', got '$*'"
	set -- **/*.c
	expected='bam.c bar.c bar/bam.c bar/foo.c foo/bam.c'
	[[ $* == $expected ]] ||
		err_exit "-G **/*.c failed -- expected '$expected', got '$*'"
	set -- **/bam.c
	expected='bam.c bar/bam.c foo/bam.c'
	[[ $* == $expected ]] ||
		err_exit "-G **/bam.c failed -- expected '$expected', got '$*'"
	cd ~-
	rm -rf /tmp/ksh$$
fi

mkdir /tmp/ksh$$
cd /tmp/ksh$$
t="<$$>.profile.<$$>"
echo "echo '$t'" > .profile
cp $SHELL ./-ksh
if	[[ -o privileged ]]
then
	[[ $(HOME=$PWD $SHELL -l </dev/null 2>&1) == *$t* ]] &&
		err_exit 'privileged -l reads .profile'
	[[ $(HOME=$PWD $SHELL --login </dev/null 2>&1) == *$t* ]] &&
		err_exit 'privileged --login reads .profile'
	[[ $(HOME=$PWD $SHELL --login-shell </dev/null 2>&1) == *$t* ]] &&
		err_exit 'privileged --login-shell reads .profile'
	[[ $(HOME=$PWD $SHELL --login_shell </dev/null 2>&1) == *$t* ]] &&
		err_exit 'privileged --login_shell reads .profile'
	[[ $(HOME=$PWD exec -a -ksh $SHELL </dev/null 2>&1) == *$t* ]]  &&
		err_exit 'privileged exec -a -ksh ksh reads .profile'
	[[ $(HOME=$PWD ./-ksh -i </dev/null 2>&1) == *$t* ]] &&
		err_exit 'privileged ./-ksh reads .profile'
	[[ $(HOME=$PWD ./-ksh -ip </dev/null 2>&1) == *$t* ]] &&
		err_exit 'privileged ./-ksh -p reads .profile'
else
	[[ $(HOME=$PWD $SHELL -l </dev/null 2>&1) == *$t* ]] ||
		err_exit '-l ignores .profile'
	[[ $(HOME=$PWD $SHELL --login </dev/null 2>&1) == *$t* ]] ||
		err_exit '--login ignores .profile'
	[[ $(HOME=$PWD $SHELL --login-shell </dev/null 2>&1) == *$t* ]] ||
		err_exit '--login-shell ignores .profile'
	[[ $(HOME=$PWD $SHELL --login_shell </dev/null 2>&1) == *$t* ]] ||
		err_exit '--login_shell ignores .profile'
	[[ $(HOME=$PWD exec -a -ksh $SHELL </dev/null 2>&1) == *$t* ]]  ||
		err_exit 'exec -a -ksh ksh ignores .profile'
	[[ $(HOME=$PWD ./-ksh -i </dev/null 2>&1) == *$t* ]] ||
		err_exit './-ksh ignores .profile'
	[[ $(HOME=$PWD ./-ksh -ip </dev/null 2>&1) == *$t* ]] &&
		err_exit './-ksh -p does not ignore .profile'
fi
cd ~-
rm -rf /tmp/ksh$$


# { exec interactive login_shell restricted xtrace } in the following test

for opt in \
	allexport all-export all_export \
	bgnice bg-nice bg_nice \
	clobber emacs \
	errexit err-exit err_exit \
	glob \
	globstar glob-star glob_star \
	gmacs \
	ignoreeof ignore-eof ignore_eof \
	keyword log markdirs monitor notify \
	pipefail pipe-fail pipe_fail \
	trackall track-all track_all \
	unset verbose vi \
	viraw vi-raw vi_raw
do	old=$opt
	if [[ ! -o $opt ]]
	then	old=no$opt
	fi

	set --$opt || err_exit "set --$opt failed"
	[[ -o $opt ]] || err_exit "[[ -o $opt ]] failed"
	[[ -o no$opt ]] && err_exit "[[ -o no$opt ]] failed"
	[[ -o no-$opt ]] && err_exit "[[ -o no-$opt ]] failed"
	[[ -o no_$opt ]] && err_exit "[[ -o no_$opt ]] failed"
	[[ -o ?$opt ]] || err_exit "[[ -o ?$opt ]] failed"
	[[ -o ?no$opt ]] || err_exit "[[ -o ?no$opt ]] failed"
	[[ -o ?no-$opt ]] || err_exit "[[ -o ?no-$opt ]] failed"
	[[ -o ?no_$opt ]] || err_exit "[[ -o ?no_$opt ]] failed"

	set --no$opt || err_exit "set --no$opt failed"
	[[ -o no$opt ]] || err_exit "[[ -o no$opt ]] failed"
	[[ -o $opt ]] && err_exit "[[ -o $opt ]] failed"

	set --no-$opt || err_exit "set --no-$opt failed"
	[[ -o no$opt ]] || err_exit "[[ -o no$opt ]] failed"
	[[ -o $opt ]] && err_exit "[[ -o $opt ]] failed"

	set --no_$opt || err_exit "set --no_$opt failed"
	[[ -o no$opt ]] || err_exit "[[ -o no$opt ]] failed"
	[[ -o $opt ]] && err_exit "[[ -o $opt ]] failed"

	set -o $opt || err_exit "set -o $opt failed"
	[[ -o $opt ]] || err_exit "[[ -o $opt ]] failed"
	set -o $opt=1 || err_exit "set -o $opt=1 failed"
	[[ -o $opt ]] || err_exit "[[ -o $opt ]] failed"
	set -o no$opt=0 || err_exit "set -o no$opt=0 failed"
	[[ -o $opt ]] || err_exit "[[ -o $opt ]] failed"
	set --$opt=1 || err_exit "set --$opt=1 failed"
	[[ -o $opt ]] || err_exit "[[ -o $opt ]] failed"
	set --no$opt=0 || err_exit "set --no$opt=0 failed"
	[[ -o $opt ]] || err_exit "[[ -o $opt ]] failed"

	set -o no$opt || err_exit "set -o no$opt failed"
	[[ -o no$opt ]] || err_exit "[[ -o no$opt ]] failed"
	set -o $opt=0 || err_exit "set -o $opt=0 failed"
	[[ -o no$opt ]] || err_exit "[[ -o no$opt ]] failed"
	set -o no$opt=1 || err_exit "set -o no$opt=1 failed"
	[[ -o no$opt ]] || err_exit "[[ -o no$opt ]] failed"
	set --$opt=0 || err_exit "set --$opt=0 failed"
	[[ -o no$opt ]] || err_exit "[[ -o no$opt ]] failed"
	set --no$opt=1 || err_exit "set --no$opt=1 failed"
	[[ -o no$opt ]] || err_exit "[[ -o no$opt ]] failed"

	set -o no-$opt || err_exit "set -o no-$opt failed"
	[[ -o no-$opt ]] || err_exit "[[ -o no-$opt ]] failed"

	set -o no_$opt || err_exit "set -o no_$opt failed"
	[[ -o no_$opt ]] || err_exit "[[ -o no_$opt ]] failed"

	set +o $opt || err_exit "set +o $opt failed"
	[[ -o no$opt ]] || err_exit "[[ -o no$opt ]] failed"

	set +o no$opt || err_exit "set +o no$opt failed"
	[[ -o $opt ]] || err_exit "[[ -o $opt ]] failed"

	set +o no-$opt || err_exit "set +o no-$opt failed"
	[[ -o $opt ]] || err_exit "[[ -o $opt ]] failed"

	set +o no_$opt || err_exit "set +o no_$opt failed"
	[[ -o $opt ]] || err_exit "[[ -o $opt ]] failed"

	set --$old
done

for opt in \
	exec interactive login_shell login-shell logi privileged \
	rc restricted xtrace
do	[[ -o $opt ]]
	y=$?
	[[ -o no$opt ]]
	n=$?
	case $y$n in
	10|01)	;;
	*)	err_exit "[[ -o $opt ]] == [[ -o no$opt ]]" ;;
	esac
done

for opt in \
	foo foo-bar foo_bar
do	if	[[ -o ?$opt ]]
	then	err_exit "[[ -o ?$opt ]] should fail"
	fi
	if	[[ -o ?no$opt ]]
	then	err_exit "[[ -o ?no$opt ]] should fail"
	fi
done
false | true | true   || err_exit 'pipe not exiting exit value of last element'
true | true | false   && err_exit 'pipe not exiting false'
set -o pipefail
false | true | true    && err_exit 'pipe with first not failing with pipefail'
true | false | true    && err_exit 'pipe middle not failing with pipefail'
true | true | false    && err_exit 'pipe last not failing with pipefail'
exit $((Errors))
