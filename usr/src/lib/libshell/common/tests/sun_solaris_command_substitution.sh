#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

# test setup
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors < 127 && Errors++ ))
}
alias err_exit='err_exit $LINENO'

set -o nounset
Command=${0##*/}
integer Errors=0


function isvalidpid
{
	kill -0 ${1} 2>/dev/null && return 0
	return 1
}
integer testfilesize i maxwait
typeset tmpfile
integer testid


########################################################################
#### test set 001:
# run loop and check various temp filesizes
# (Please keep this test syncted with sun_solaris_cr_6800929_large_command_substitution_hang.sh)

# test 1: run loop and check various temp filesizes
tmpfile="$(mktemp -t "ksh93_tests_command_substitution.${PPID}.$$.XXXXXX")" || err_exit "Cannot create temporary file."

compound test1=(
	compound -a testcases=(
		# test 1a: Run test child for $(...)
		# (note the pipe chain has to end in a builtin command, an external command may not trigger the bug)
		( name="test1a" cmd="builtin cat ; print -- \"\$(cat \"${tmpfile}\" | cat)\" ; true" )
		# test 1b: Same as test1a but uses ${... ; } instead if $(...)
		( name="test1b" cmd="builtin cat ; print -- \"\${ cat \"${tmpfile}\" | cat ; }\" ; true" )
		# test 1c: Same as test1a but does not use a pipe
		( name="test1c" cmd="builtin cat ; print -- \"\$(cat \"${tmpfile}\" ; true)\" ; true" )
		# test 1d: Same as test1a but does not use a pipe
		( name="test1d" cmd="builtin cat ; print -- \"\${ cat \"${tmpfile}\" ; true ; }\" ; true" )

		# test 1e: Same as test1a but uses an external "cat" command
		( name="test1e" cmd="builtin -d cat /bin/cat ; print -- \"\$(cat \"${tmpfile}\" | cat)\" ; true" )
		# test 1f: Same as test1a but uses an external "cat" command
		( name="test1f" cmd="builtin -d cat /bin/cat ; print -- \"\${ cat \"${tmpfile}\" | cat ; }\" ; true" )
		# test 1g: Same as test1a but uses an external "cat" command
		( name="test1g" cmd="builtin -d cat /bin/cat ; print -- \"\$(cat \"${tmpfile}\" ; true)\" ; true" )
		# test 1h: Same as test1a but uses an external "cat" command
		( name="test1h" cmd="builtin -d cat /bin/cat ; print -- \"\${ cat \"${tmpfile}\" ; true ; }\" ; true" )
	)
)

for (( testfilesize=1*1024 ; testfilesize <= 1024*1024 ; testfilesize*=2 )) ; do
	# Create temp file
	{
		for (( i=0 ; i < testfilesize ; i+=64 )) ; do
			print "0123456789abcdef01234567890ABCDEF0123456789abcdef01234567890ABCDE"
		done
	} >"${tmpfile}"

	# wait up to log2(i) seconds for the child to terminate
	# (this is 10 seconds for 1KB and 19 seconds for 512KB)
	(( maxwait=log2(testfilesize) ))
		
	for testid in "${!test1.testcases[@]}" ; do
		nameref currtst=test1.testcases[testid]
		${SHELL} -o errexit -c "${currtst.cmd}" >"${tmpfile}.out" &
		(( childpid=$! ))

		for (( i=0 ; i < maxwait ; i++ )) ; do
			isvalidpid ${childpid} || break
			sleep 0.25
		done

		if isvalidpid ${childpid} ; then
			err_exit "${currtst.name}: child (pid=${childpid}) still busy, filesize=${testfilesize}."
			kill -KILL ${childpid} 2>/dev/null
		fi
		wait || err_exit "${currtst.name}: Child returned non-zero exit code." # wait for child (and/or avoid zombies/slime)

		# compare input/output
		cmp -s "${tmpfile}" "${tmpfile}.out" || err_exit "${currtst.name}: ${tmpfile} and ${tmpfile}.out differ, filesize=${testfilesize}."
		rm "${tmpfile}.out"
	done

	# Cleanup
	rm "${tmpfile}"
done


########################################################################
#### test set 002:
# If a command substitution calls a function and that function contains
# a command substitution which contains a piped command, the original
# command substitution calling the function will return 127 instead of 0.
# This is causing problems in several VSC tests.
# If we remove the piped command from the simple
# case in the attached script, it returns 0.

typeset str
typeset testbody
typeset testout

testbody=$(
# <CS> means command substitution start, <CE> means command substitution end
cat <<EOF
myfunc ()
{ 
	pipedcmd=<CS> printf "hi" | tr "h" "H" <CE>
	echo \$pipedcmd

	return 0
}

foo=<CS>myfunc<CE>
retval=\$?

if [ "\$foo"X != "HiX" ]; then
	echo "myfunc returned '\${foo}'; expected 'Hi'"
fi

if [ \$retval -ne 0 ]; then
	echo "command substitution calling myfunc returned \"\${retval}\"; expected 0"
else
	echo "command substitution calling myfunc successfully returned 0"
fi
EOF
)


# Test 002/a: Plain test
testout=${ printf "%B\n" testbody | sed 's/<CS>/$(/g;s/<CE>/)/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "command substitution calling myfunc successfully returned 0" ]] || err_exit "Expected 'command substitution calling myfunc successfully returned 0', got ${testout}"

# Test 002/b: Same as test002/a but replaces "$(" with "${"
testout=${ printf "%B\n" testbody | sed 's/<CS>/${ /g;s/<CE>/ ; }/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "command substitution calling myfunc successfully returned 0" ]] || err_exit "Expected 'command substitution calling myfunc successfully returned 0', got ${testout}"

# Test 002/c: Same as test002/a but forces |fork()| for a subshell via "ulimit -c 0"
testout=${ printf "%B\n" testbody | sed 's/<CS>/$( ulimit -c 0 ; /g;s/<CE>/)/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "command substitution calling myfunc successfully returned 0" ]] || err_exit "Expected 'command substitution calling myfunc successfully returned 0', got ${testout}"

# Test 002/d: Same as test002/a but uses extra subshell
testout=${ printf "%B\n" testbody | sed 's/<CS>/$( ( /g;s/<CE>/) )/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "command substitution calling myfunc successfully returned 0" ]] || err_exit "Expected 'command substitution calling myfunc successfully returned 0', got ${testout}"

# Test 002/e: Same as test002/b but uses extra subshell after "${ " 
testout=${ printf "%B\n" testbody | sed 's/<CS>/${ ( /g;s/<CE>/) ; }/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "command substitution calling myfunc successfully returned 0" ]] || err_exit "Expected 'command substitution calling myfunc successfully returned 0', got ${testout}"




########################################################################
#### test set 003:
# An expression within backticks which should return false, instead
# returns true (0).

typeset str
typeset testbody
typeset testout

testbody=$(
# <CS> means command substitution start, <CE> means command substitution end
cat <<EOF
if <CS>expr "NOMATCH" : ".*Z" > /dev/null<CE> ; then
        echo "xerror"
else
        echo "xok"
fi
EOF
)


# Test 003/a: Plain test
testout=${ printf "%B\n" testbody | sed 's/<CS>/$(/g;s/<CE>/)/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "xok" ]] || err_exit "Expected 'xok', got ${testout}"

# Test 003/b: Same as test003/a but replaces "$(" with "${"
testout=${ printf "%B\n" testbody | sed 's/<CS>/${ /g;s/<CE>/ ; }/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "xok" ]] || err_exit "Expected 'xok', got ${testout}"

# Test 003/c: Same as test003/a but forces |fork()| for a subshell via "ulimit -c 0"
testout=${ printf "%B\n" testbody | sed 's/<CS>/$( ulimit -c 0 ; /g;s/<CE>/)/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "xok" ]] || err_exit "Expected 'xok', got ${testout}"

# Test 003/d: Same as test003/a but uses extra subshell
testout=${ printf "%B\n" testbody | sed 's/<CS>/$( ( /g;s/<CE>/) )/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "xok" ]] || err_exit "Expected 'xok', got ${testout}"

# Test 003/e: Same as test003/b but uses extra subshell after "${ " 
testout=${ printf "%B\n" testbody | sed 's/<CS>/${ ( /g;s/<CE>/) ; }/g' | ${SHELL} 2>&1 || err_exit "command returned exit code $?" }
[[ "${testout}" == "xok" ]] || err_exit "Expected 'xok', got ${testout}"


########################################################################
#### test set 004:
# test pipe within ${... ; } command subtitution ending in a
# non-builtin command (therefore we use "/bin/cat" instead of "cat" below
# to force the use of the external "cat" command). ast-ksh.2009-01-20
# had a bug which caused this test to fail.
testout=$( ${SHELL} -c 'pipedcmd=${ printf "hi" | /bin/cat ; } ; print $pipedcmd' )
[[ "${testout}" == "hi" ]] || err_exit "test004: Expected 'hi', got '${testout}'"


########################################################################
#### test set 005:
# Test whether the shell may hang in a
# 'exec 5>/dev/null; print $(eval ls -d . 2>&1 1>&5)'
# Originally discovered with ast-ksh.2009-05-05 which hung in
# the "configure" script of postgresql-8.3.7.tar.gz (e.g. 
# configure --enable-thread-safety --without-readline)
compound test5=(
	compound -a testcases=(
		# gsf's reduced testcase
		( name="test5_a" cmd='exec 5>/dev/null; print $(eval ls -d . 2>&1 1>&5)done' )
		# gisburn's reduced testcase
		( name="test5_b" cmd='exec 5>/dev/null; print $(eval "/bin/printf hello\n" 2>&1 1>&5)done' )

		## The following tests do not trigger the problem but are included here for completeness
		## and to make sure we don't get other incarnations of the same problem later...

		# same as test5_a but uses ${ ... ; } instead of $(...)
		( name="test5_c" cmd='exec 5>/dev/null; print "${ eval ls -d . 2>&1 1>&5 ;}done"' )
		# same as test5_b but uses ${ ... ; } instead of $(...)
		( name="test5_d" cmd='exec 5>/dev/null; print "${ eval "/bin/printf hello\n" 2>&1 1>&5 ;}done"' )
		# same as test5_a but uses "ulimit -c 0" to force the shell to use a seperare process for $(...)
		( name="test5_e" cmd='exec 5>/dev/null; print $(ulimit -c 0 ; eval ls -d . 2>&1 1>&5)done' )
		# same as test5_b but uses "ulimit -c 0" to force the shell to use a seperare process for $(...)
		( name="test5_f" cmd='exec 5>/dev/null; print $(ulimit -c 0 ; eval "/bin/printf hello\n" 2>&1 1>&5)done' )
	)
)

maxwait=5
for testid in "${!test5.testcases[@]}" ; do
	nameref currtst=test5.testcases[testid]
	${SHELL} -o errexit -c "${currtst.cmd}" >"${tmpfile}.out" &
	(( childpid=$! ))

	for (( i=0 ; i < maxwait ; i++ )) ; do
		isvalidpid ${childpid} || break
		sleep 0.25
	done

	if isvalidpid ${childpid} ; then
		err_exit "${currtst.name}: child (pid=${childpid}) still busy."
		kill -KILL ${childpid} 2>/dev/null
	fi
	wait || err_exit "${currtst.name}: Child returned non-zero exit code." # wait for child (and/or avoid zombies/slime)

	testout="$( < "${tmpfile}.out")"
	rm "${tmpfile}.out" || err_exit "File '${tmpfile}.out' could not be removed."
	[[ "${testout}" == "done" ]] || err_exit "test '${currtst.name}' failed, expected 'done', got '${testout}'"
done


# tests done
exit $((Errors))
