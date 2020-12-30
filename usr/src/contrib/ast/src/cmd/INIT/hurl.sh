########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1994-2011 AT&T Intellectual Property          #
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
#                 Glenn Fowler <gsf@research.att.com>                  #
#                                                                      #
########################################################################
: copy http url data

command=hurl
agent="$command/2009-01-20 (AT&T Research)"
authorize=
verbose=0

case `(getopts '[-][123:xyz]' opt --xyz; echo 0$opt) 2>/dev/null` in
0123)	ARGV0="-a $command"
	USAGE=$'
[-?
@(#)$Id: hurl (AT&T Research) 2009-01-20 $
]
'$USAGE_LICENSE$'
[+NAME?hurl - copy http url data]
[+DESCRIPTION?\bhurl\b copies the data for the \bhttp\b \aurl\a operand
	to the standard output. The \aurl\a must be of the form
	\b[http://]]\b\ahost\a[\b:\b\aport\a]]\b/\b\apath\a. The default
	\aport\a is \b80\b.]
[+?\bhurl\b is a shell script that attempts to access the \aurl\a by
	these methods:]{
	[+/dev/tcp/\ahost\a\b/80\b?Supported by \bksh\b(1) and recent
		\bbash\b(1).]
	[+wget -nv -O - \aurl\a?]
	[+lynx -source \aurl\a?]
	[+curl -s -L -o - \aurl\a?]
}
[a:authorize?The url authorization user name and password, separated
	by \b:\b (one colon character.)]:[user::password]
[s:size?Terminate the data transmission after \abytes\a have been
	transferred.]:[bytes]
[v:verbose?Verbose trace.]

url

[+SEE ALSO?\bcurl\b(1), \blynx\b(1), \bwget\b(1)]
'
	;;
*)	ARGV0=""
	USAGE="a:v"
	;;
esac

usage()
{
	OPTIND=0
	getopts $ARGV0 "$USAGE" OPT '-?'
	exit 2
}

integer limit=0 total=0 block=8*1024

while	getopts $ARGV0 "$USAGE" OPT
do	case $OPT in
	a)	authorize=$OPTARG ;;
	s)	limit=$OPTARG ;;
	v)	verbose=1 ;;
	esac
done
shift `expr $OPTIND - 1`

url=$1
AUTHORIZE=

exec 9<&0

while	:
do	test 0 != $verbose && echo "$command: url=$url" >&2
	case $url in
	*://*/*)prot=${url%%:*}
		url=${url#*://}
		;;
	*)	prot=http
		;;
	esac
	host=$url
	path=/${host#*/}
	host=${host%%/*}
	case $host in
	*:+([0-9]))
		port=${host##*:}
		host=${host%:*}
		;;
	*)	port=80
		;;
	esac
	test 0 != $verbose && echo "$command: prot=$prot host=$host port=$port path=$path" >&2
	case $prot in
	http)	if	(eval "exec >" || exit 0) 2>/dev/null &&
			eval "exec 8<> /dev/tcp/\$host/$port" 2>/dev/null
		then	test 0 != $verbose && echo "$command: using /dev/tcp/$host/$port" >&2
			if	! echo "GET $path HTTP/1.0
Host: $host
User-Agent: $agent${AUTHORIZE}
" >&8
			then	echo "$command: $host: write error"
				exit 1
			fi
			{
				if	! read prot code text
				then	echo "$command: $host: read error" >&2
					exit 1
				fi
				code=${code%:*}
				type=Basic
				realm=access
				test 0 != $verbose && echo "$command: prot=$prot code=$code $text" >&2
				while	:
				do	if	! read head data
					then	echo "$command: $host: read error" >&2
						exit 1
					fi
					test 0 != $verbose && echo "$command: head=$head $data" >&2
					case $head in
					Location:)
						case $code in
						30[123])url=$data
							continue 2
							;;
						esac
						;;
					WWW-Authenticate:)
						set -- $data
						type=$1
						shift
						eval "$@"
						realm=${realm%$'\r'}
						;;
					''|?)	break
						;;
					esac
				done
				case $code in
				200)	if	(( limit ))
					then	(( limit = (limit + block - 1) / block))
						dd bs=$block count=$limit silent=1
					else	cat
					fi
					exit
					;;
				401)	{
						if	[[ $AUTHORIZE || $type != Basic ]]
						then	print authorization failed
							exit 1
						fi
						if	[[ ! $authorize ]]
						then	if	[[ ! -t 0 ]]
							then	print authorization failed
								exit 1
							fi
							print -n "Enter user name for $realm: "
							read -u9 user
							print -n "Password: "
							trap 'stty echo <&9' 0 1 2 3 15
							stty -echo
							read password
							stty echo
							print
							trap - 0 1 2 3 15
							authorize=$user:$password
						fi
						AUTHORIZE=$'\nAuthorization: '$type' '$(print -n -r -- "$authorize" | uuencode -h -x base64)$'\r'
					} <&9 >&2
					continue 2
					;;
				*)	echo "$0: $url: $code: $text" >&2
					exit 1
					;;
				esac
			} <&8 
		elif	wget ${authorize:+--http-user="${authorize%:*}"} ${password:+--http-passwd="${password##*:}"} -nv -O - $url 2>/dev/null
		then	test 0 != $verbose && echo "$command: using wget" >&2
			exit
		elif	lynx ${authorize:+-auth "$authorize"} -source $url 2>/dev/null
		then	test 0 != $verbose && echo "$command: using wget" >&2
			exit
		elif	curl ${authorize:+-u "$authorize"} -s -L -o - $url 2>/dev/null
		then	test 0 != $verbose && echo "$command: using curl" >&2
			exit
		else	echo "$command: $url: { /dev/tcp/$host/$port wget curl } failed" >&2
			exit 1
		fi
		;;
	*)	echo "$command: $prot: protocol not supported" >&2
		exit 1
		;;
	esac
done
