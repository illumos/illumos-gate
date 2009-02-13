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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#  xxxxx@xxxxx $ pstack 204600
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
#  xxxxx@xxxxx $ ksh93
#  xxxxx@xxxxx $ set -- `cat /etc/termcap | sort | uniq`
# <hang>
# ---8<---
# ---- snip ----


function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors+=1 ))
}

alias err_exit='err_exit $LINENO'

integer Errors=0

integer i j d
typeset tmpfile

# test 1: run loop and check various temp filesizes
tmpfile="$(mktemp "/tmp/sun_solaris_cr_6800929_large_command_substitution_hang.${PPID}.$$.XXXXXX")" || err_exit "Cannot create temporary file."

for (( i=1*1024 ; i <= 512*1024 ; i*=2 )) ; do
	# Create temp file
	{
		for ((j=0 ; j < i ; j+=16 )) ; do
			print "0123456789abcde"
		done
	} >"${tmpfile}"
	
	# Run test child
	${SHELL} -c "builtin cat ; print -- \"\$(cat \"${tmpfile}\" | cat)\" ; true" >/dev/null &
	(( childpid=$! ))

	# wait up to log2(i) seconds for the child to terminate
	# (this is 10 seconds for 1KB and 19 seconds for 512KB)
	(( d=log2(i) ))
	for (( j=0 ; j < d ; j++ )) ; do
		kill -0 ${childpid} 2>/dev/null || break
		sleep 0.5
	done

	if kill -0 ${childpid} 2>/dev/null ; then
		err_exit "test1: child (pid=${childpid}) still busy, filesize=${i}."
		kill -KILL ${childpid} 2>/dev/null
	fi
	wait # wait for child (and/or avoid zombies/slime)
	rm "${tmpfile}"
done


# test 2: Edward's Solaris-specific testcase
${SHELL} -c 'builtin uniq ; set -- `cat /etc/termcap | sort | uniq` ; true' >/dev/null &
(( childpid=$! ))
sleep 5
if kill -0 ${childpid} 2>/dev/null ; then
	err_exit "test2: child (pid=${childpid}) still busy."
	kill -KILL ${childpid} 2>/dev/null
fi
wait # wait for child (and/or avoid zombies/slime)

# tests done
exit $((Errors))
