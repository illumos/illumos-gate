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

function abspath
{
        base=$(basename $SHELL)
        cd ${SHELL%/$base}
        newdir=$(pwd)
        cd ~-
        print $newdir/$base
}
#test for proper exit of shell
builtin getconf
ABSHELL=$(abspath)
cd $tmp || { err_exit "cd $tmp failed"; exit 1; }
print exit 0 >.profile
${ABSHELL}  <<!
HOME=$PWD \
PATH=$PATH \
SHELL=$ABSSHELL \
$(
	v=$(getconf LIBPATH)
	for v in ${v//,/ }
	do	v=${v#*:}
		v=${v%%:*}
		eval [[ \$$v ]] && eval print -n \" \"\$v=\"\$$v\"
	done
) \
exec -c -a -ksh ${ABSHELL} -c "exit 1" 1>/dev/null 2>&1
!
status=$(echo $?)
if	[[ -o noprivileged && $status != 0 ]]
then	err_exit 'exit in .profile is ignored'
elif	[[ -o privileged && $status == 0 ]]
then	err_exit 'privileged .profile not ignored'
fi
if	[[ $(trap 'code=$?; echo $code; trap 0; exit $code' 0; exit 123) != 123 ]]
then	err_exit 'exit not setting $?'
fi
cat > run.sh <<- "EOF"
	trap 'code=$?; echo $code; trap 0; exit $code' 0
	( trap 0; exit 123 )
EOF
if	[[ $($SHELL ./run.sh) != 123 ]]
then	err_exit 'subshell trap on exit overwrites parent trap'
fi
cd ~- || err_exit "cd back failed"
$SHELL -c 'builtin -f cmd getconf; getconf --"?-version"; exit 0' >/dev/null 2>&1 || err_exit 'ksh plugin exit failed -- was ksh built with CCFLAGS+=$(CC.EXPORT.DYNAMIC)?'

exit $((Errors<125?Errors:125))
