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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# Test whether CR #6800929 ("snv_106 ksh93 update breaks Install(1M)") has been fixed.
# 
# Quote from CR #6800929: 
# ---- snip ----
# so i just upgraded this morning from snv_105 to snv_106.  now
# Install(1M) is hanging whenever i run it.  i'm running it as follows:
#         Install -o debug -k i86xpv -T domu-219:/tmp
# 
# and here's where it's hung:
# ---8<---
#  Edward Pilatowicz <edward.pilatowicz@sun.com> 
# $ pstack 204600
# 204600: /bin/ksh /opt/onbld/bin/Install -o debug -k i86xpv -T domu-219:/tmp
#  fffffd7fff2e3d1a write    (1, 4154c0, 64)
#  fffffd7ffefdafc8 sfwr () + 2d0
#  fffffd7ffefc0f6f _sfflsbuf () + 217
#  fffffd7ffefcb9f7 sfsync () + 17f
#  fffffd7ffefc5c58 _sfphead () + 188
#  fffffd7ffefc5ef5 _sfpmove () + 55
#  fffffd7ffefc2595 _sfmode () + 22d
#  fffffd7ffefc5fb1 sfpool () + 99
#  fffffd7fff15eb8e sh_exec () + 2f56
#  fffffd7fff15f78c sh_exec () + 3b54
#  fffffd7fff15d9c8 sh_exec () + 1d90
#  fffffd7fff15788e sh_subshell () + 646
#  fffffd7fff134562 comsubst () + 8a2
#  fffffd7fff12f61f copyto () + bcf
#  fffffd7fff12df79 sh_macexpand () + 1f1
#  fffffd7fff1129f5 arg_expand () + a5
#  fffffd7fff112812 sh_argbuild () + 9a
#  fffffd7fff15dbe2 sh_exec () + 1faa
#  fffffd7fff15d854 sh_exec () + 1c1c
#  fffffd7fff0f22ef b_dot_cmd () + 507
#  fffffd7fff161559 sh_funct () + 199
#  fffffd7fff15ef35 sh_exec () + 32fd
#  fffffd7fff136e86 exfile () + 786
#  fffffd7fff136676 sh_main () + 7fe
#  0000000000400e72 main () + 52
#  0000000000400ccc ????
# ---8<---
# 
# there is only one place where Install(1M) invokes "uniq":
#         set -- `grep "^CONF" $modlist | sort | uniq`;
# 
# as it turns out, i can easily reproduce this problem as follows:
# ---8<---
# $ ksh93
# $ set -- `cat /etc/termcap | sort | uniq`
# <hang>
# ---8<---
# ---- snip ----


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

# common functions/variables
function isvalidpid
{
	kill -0 ${1} 2>/dev/null && return 0
	return 1
}
integer testfilesize i maxwait
typeset tmpfile
integer testid


# test 1: run loop and check various temp filesizes
tmpfile="$(mktemp -t "sun_solaris_cr_6800929_large_command_substitution_hang.${PPID}.$$.XXXXXX")" || err_exit "Cannot create temporary file."

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
		
	for testid in "${!testcases[@]}" ; do
		nameref currtst=testcases[testid]
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


# test 2a: Edward Pilatowicz <edward.pilatowicz@sun.com>'s Solaris-specific testcase
${SHELL} -o errexit -c 'builtin uniq ; set -- `cat /etc/termcap | sort | uniq` ; true' >/dev/null &
(( childpid=$! ))
sleep 5
if isvalidpid ${childpid} ; then
	err_exit "test2a: child (pid=${childpid}) still busy."
	kill -KILL ${childpid} 2>/dev/null
fi
wait || err_exit "test2a: Child returned non-zero exit code." # wait for child (and/or avoid zombies/slime)


# test 2b: Same as test 2a but uses ${... ; } instead of $(...)
${SHELL} -o errexit -c 'builtin uniq ; set -- ${ cat /etc/termcap | sort | uniq ; } ; true' >/dev/null &
(( childpid=$! ))
sleep 5
if isvalidpid ${childpid} ; then
	err_exit "test2b: child (pid=${childpid}) still busy."
	kill -KILL ${childpid} 2>/dev/null
fi
wait || err_exit "test2b: Child returned non-zero exit code." # wait for child (and/or avoid zombies/slime)


# test 2c: Same as test 2a but makes sure that "uniq" is not a builtin
${SHELL} -o errexit -c 'builtin -d uniq /bin/uniq ; set -- `cat /etc/termcap | sort | uniq` ; true' >/dev/null &
(( childpid=$! ))
sleep 5
if isvalidpid ${childpid} ; then
	err_exit "test2c: child (pid=${childpid}) still busy."
	kill -KILL ${childpid} 2>/dev/null
fi
wait || err_exit "test2c: Child returned non-zero exit code." # wait for child (and/or avoid zombies/slime)


# test 2d: Same as test 2c but uses ${... ; } instead of $(...)
${SHELL} -o errexit -c 'builtin -d uniq /bin/uniq ; set -- ${ cat /etc/termcap | sort | uniq ; } ; true' >/dev/null &
(( childpid=$! ))
sleep 5
if isvalidpid ${childpid} ; then
	err_exit "test2d: child (pid=${childpid}) still busy."
	kill -KILL ${childpid} 2>/dev/null
fi
wait || err_exit "test2d: Child returned non-zero exit code." # wait for child (and/or avoid zombies/slime)


# tests done
exit $((Errors))
