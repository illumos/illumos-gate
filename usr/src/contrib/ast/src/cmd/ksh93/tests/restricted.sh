########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2011 AT&T Intellectual Property          #
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

# test restricted shell
pwd=$PWD
case $SHELL in
/*)	;;
*/*)	SHELL=$pwd/$SHELL;;
*)	SHELL=$(whence "$SHELL");;
esac
function check_restricted
{
	rm -f out
	LC_MESSAGES=C rksh -c "$@" 2> out > /dev/null
	grep restricted out  > /dev/null 2>&1
}

[[ $SHELL != /* ]] && SHELL=$pwd/$SHELL
cd $tmp || err_exit "cd $tmp failed"
ln -s $SHELL rksh
PATH=$PWD:$PATH
rksh -c  '[[ -o restricted ]]' || err_exit 'restricted option not set'
[[ $(rksh -c 'print hello') == hello ]] || err_exit 'unable to run print'
check_restricted /bin/echo || err_exit '/bin/echo not resticted'
check_restricted ./echo || err_exit './echo not resticted'
check_restricted 'SHELL=ksh' || err_exit 'SHELL asignment not resticted'
check_restricted 'PATH=/bin' || err_exit 'PATH asignment not resticted'
check_restricted 'FPATH=/bin' || err_exit 'FPATH asignment not resticted'
check_restricted 'ENV=/bin' || err_exit 'ENV asignment not resticted'
check_restricted 'print > file' || err_exit '> file not restricted'
> empty
check_restricted 'print <> empty' || err_exit '<> file not restricted'
print 'echo hello' > script
chmod +x ./script
! check_restricted script ||  err_exit 'script without builtins should run in restricted mode'
check_restricted ./script ||  err_exit 'script with / in name should not run in restricted mode'
print '/bin/echo hello' > script
! check_restricted script ||  err_exit 'script with pathnames should run in restricted mode'
print 'echo hello> file' > script
! check_restricted script ||  err_exit 'script with output redirection should run in restricted mode'
print 'PATH=/bin' > script
! check_restricted script ||  err_exit 'script with PATH assignment should run in restricted mode'
cat > script <<!
#! $SHELL
print hello
!
! check_restricted 'script;:' ||  err_exit 'script with #! pathname should run in restricted mode'
! check_restricted 'script' ||  err_exit 'script with #! pathname should run in restricted mode even if last command in script'
for i in PATH ENV FPATH
do	check_restricted  "function foo { typeset $i=foobar;};foo" || err_exit "$i can be changed in function by using typeset"
done

exit $((Errors<125?Errors:125))
