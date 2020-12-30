########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2012 AT&T Intellectual Property          #
#                      and is licensed under the                       #
#                 Eclipse Public License, Version 1.0                  #
#                    by AT&T Intellectual Property                     #
#                                                                      #
#                A copy of the License is available at                 #
#          http://www.eclipse.org/org/documents/epl-v10.html           #
#         (with md5 checksum b35adb5213ca9657e911e9befb180842)         #
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

tmp=$(mktemp -dt) || { err_exit mktemp -dt failed; exit 1; }
trap "cd /; rm -rf $tmp" EXIT

foo=abc
typeset -C bar=(x=3 y=4 t=7)
typeset -A z=([abc]=qqq)
integer r=9
function fn
{
	print global fn $foo
}
function fun
{
	print global fun $foo
}
mkdir -p $tmp/global/bin $tmp/local/bin
cat > $tmp/global/xfun <<- \EOF
	function xfun
	{
		print xfun global $foo
	}
EOF
cat > $tmp/local/xfun <<- \EOF
	function xfun
	{
		print xfun local $foo
	}
EOF
chmod +x "$tmp/global/xfun" "$tmp/local/xfun"
print 'print local prog $1' >  $tmp/local/bin/run
print 'print global prog $1' >  $tmp/global/bin/run
chmod +x "$tmp/local/bin/run" "$tmp/global/bin/run"
PATH=$tmp/global/bin:$PATH
FPATH=$tmp/global

namespace x
{
	foo=bar
	typeset -C bar=(x=1 y=2 z=3)
	typeset -A z=([qqq]=abc)
	function fn
	{
		print local fn $foo
	}
	[[ $(fn) == 'local fn bar' ]] || err_exit 'fn inside namespace should run local function'
	[[ $(fun) == 'global fun abc' ]] || err_exit 'global fun run from namespace not working'
	(( r == 9 )) || err_exit 'global variable r not set in namespace'
false
	[[ ${z[qqq]} == abc ]] || err_exit 'local array element not correct'
	[[ ${z[abc]} == '' ]] || err_exit 'global array element should not be visible when local element exists'
	[[ ${bar.y} == 2 ]] || err_exit 'local variable bar.y not found'
	[[ ${bar.t} == '' ]] || err_exit 'global bar.t should not be visible'
	function runxrun
	{
		xfun
	}
	function runrun
	{
		run $1
	}
	PATH=$tmp/local/bin:/bin
	FPATH=$tmp/local
	[[ $(runxrun) ==  'xfun local bar' ]] || err_exit 'local function on FPATH failed'
	[[ $(runrun $foo) ==  'local prog bar' ]] || err_exit 'local binary on PATH failed'
}
[[ $(fn) == 'global fn abc' ]] || err_exit 'fn outside namespace should run global function'
[[ $(.x.fn) == 'local fn bar' ]] || err_exit 'namespace function called from global failed'
[[  ${z[abc]} == qqq ]] || err_exit 'global associative array should not be affected by definiton in namespace'
[[  ${bar.y} == 4 ]] || err_exit 'global compound variable should not be affected by definiton in namespace'
[[  ${bar.z} == ''  ]] || err_exit 'global compound variable should not see elements in namespace'
[[ $(xfun) ==  'xfun global abc' ]] || err_exit 'global function on FPATH failed'
[[ $(run $foo) ==  'global prog abc' ]] || err_exit 'global binary on PATH failed'
false
[[ $(.x.runxrun) ==  'xfun local bar' ]] || err_exit 'namespace function on FPATH failed'

exit $((Errors<125?Errors:125))
