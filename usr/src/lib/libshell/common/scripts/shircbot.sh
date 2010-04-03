#!/usr/bin/ksh93

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
# shircbot - a simple IRC client/bot demo
#

# Solaris needs /usr/xpg6/bin:/usr/xpg4/bin because the tools in /usr/bin are not POSIX-conformant
export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/bin:/usr/bin

# Make sure all math stuff runs in the "C" locale to avoid problems
# with alternative # radix point representations (e.g. ',' instead of
# '.' in de_DE.*-locales). This needs to be set _before_ any
# floating-point constants are defined in this script).
if [[ "${LC_ALL}" != "" ]] ; then
    export \
        LC_MONETARY="${LC_ALL}" \
        LC_MESSAGES="${LC_ALL}" \
        LC_COLLATE="${LC_ALL}" \
        LC_CTYPE="${LC_ALL}"
        unset LC_ALL
fi
export LC_NUMERIC=C

function fatal_error
{
	print -u2 "${progname}: $*"
	exit 1
}

# Definition for a IRC session class
typeset -T ircsession_t=(
	compound server=(
		typeset name
		integer port
	)
	
	typeset nick="ksh93irc"
	
	typeset running=true
	
	integer fd=-1
	
	function createsession
	{
		set -o xtrace
		
		_.server.name=$1
		_.server.port=$2
		_.nick=$3
		
		redirect {_.fd}<> "/dev/tcp/${_.server.name}/${_.server.port}"
		(( $? == 0 )) || { print -n2 $"Could not open server connection." ; return 1 ; }
		
		printf "fd=%d\n" _.fd
		
		return 0
	}

	function login
	{
		{
			printf "USER %s %s %s %s\n" "${_.nick}" "${_.nick}" "${_.nick}" "${_.nick}"
			printf "NICK %s\n" "${_.nick}"
		} >&${_.fd}
		
		return 0
	}

	function join_channel
	{
		printf "JOIN %s\n" "$1" >&${_.fd}
		
		return 0
	}
		
	function mainloop
	{
		typeset line
		float -S last_tick=0
		# We use the linebuf_t class here since network traffic
		# isn't guranteed to fit a single $'\n'-terminated line
		# into one TCP package. linebuf_t buffers characters
		# until it has one complete line. This avoids the need for
		# async I/O normally used by IRC clients
		linebuf_t serverbuf
		linebuf_t clientbuf
		integer fd=${_.fd}
	
		_.login
		
		while ${_.running} ; do
			while serverbuf.readbuf line <&${fd} ; do
				_.dispatch_serverevent "$line"
			done

			while clientbuf.readbuf line </dev/stdin ; do
				printf "client: %q\n" "${line}"
				printf "%s\n" "${line}" >&${fd}
			done
			
			# call mainloop_tick function in intervals to handle
			# async events (e.g. automatic /join etc.)
			if (( (SECONDS-last_tick) > 5. )) ; then
				(( last_tick=SECONDS ))
				_.mainloop_tick
			fi
		done
		
		return 0
	}
	
	function mainloop_tick
	{
		return 0
	}
	
	function dispatch_serverevent
	{
		typeset line="$1"
		
		case "${line}" in
			~(El)PING)
				compound ping_args=(
					line="$line"
				)
				_.serverevent_ping "ping_args"
				;;
			~(El):.*\ PRIVMSG)
				compound privmsg_args=(
					typeset line="$line"
					typeset msguser="${line/~(Elr)([^ ]+) ([^ ]+) ([^ ]+) (.*)/\1}"
					typeset msgchannel="${line/~(Elr)([^ ]+) ([^ ]+) ([^ ]+) (.*)/\3}"
					typeset msg="${line/~(Elr)([^ ]+) ([^ ]+) ([^ ]+) (.*)/\4}"
				)
				_.serverevent_privmsg "privmsg_args"
				;;
			~(El):.*\ INVITE)
				compound invite_args=(
					typeset line="$line"
					typeset inviteuser="${line/~(Elr)([^ ]+) ([^ ]+) ([^ ]+) (.*)/\1}"
					typeset invitenick="${line/~(Elr)([^ ]+) ([^ ]+) ([^ ]+) (.*)/\3}"
					typeset invitechannel="${line/~(Elr)([^ ]+) ([^ ]+) ([^ ]+) (.*)/\4}"
				)
				_.serverevent_invite "invite_args"
				;;
			*)
				printf "server: %q\n" "${line}"
				;;
		esac
		
		return 0
	}
	
	function serverevent_privmsg
	{
		nameref args=$1
		typeset msguser="${args.msguser}"
		typeset msgchannel="${args.msgchannel}"
		typeset msg="${args.msg}"
		
		printf "#privms: user=%q, channel=%q, msg=%q\n" "$msguser" "$msgchannel" "$msg"
		
		return 0
	}

	function serverevent_invite
	{
		nameref args=$1
		
		printf "JOIN %s\n" "${args.invitechannel/:/}" >&${_.fd}
		
		return 0
	}
		
	function send_privmsg
	{
		typeset channel="$1"
		typeset msg="$2"

		# Do we have to escape any characters in "msg" ?	
		printf "PRIVMSG %s :%s\n" "${channel}" "${msg}" >&${_.fd}

		return 0
	}
	
	function serverevent_ping
	{
		nameref args=$1

		printf "PONG %s\n" "${args.line/~(Elr)([^ ]+) ([^ ]+).*/\2}" >&${_.fd}

		return 0
	}
)

# line buffer class
# The buffer class tries to read characters from the given <fd> until
# it has read a whole line.
typeset -T linebuf_t=(
	typeset buf
	
	function reset
	{
		_.buf=""
		return 0
	}
	
	function readbuf
	{
		nameref var=$1
		typeset ch

		while IFS='' read -t 0.2 -N 1 ch ; do
			[[ "$ch" == $'\r' ]] && continue
			
			if [[ "$ch" == $'\n' ]] ; then
				var="${_.buf}"
				_.reset
				return 0
			fi
			
			_.buf+="$ch"
		done
		
		return 1
	}
)

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${shircbot_usage}" OPT '-?'
	exit 2
}

# program start
# (be carefull with builtins here - they are unconditionally available
# in the shell's "restricted" mode)
builtin basename
builtin sum

typeset progname="${ basename "${0}" ; }"

typeset -r shircbot_usage=$'+
[-?\n@(#)\$Id: shircbot (Roland Mainz) 2009-09-09 \$\n]
[-author?Roland Mainz <roland.mainz@sun.com>]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?shircbot - simple IRC bot demo]
[+DESCRIPTION?\bshircbot\b is a small demo IRC bot which provides
	a simple IRC bot with several subcommands.]
[n:nickname?IRC nickname for this bot.]:[nick]
[s:ircserver?IRC servername.]:[servername]
[j:joinchannel?IRC servername.]:[channelname]
[+SEE ALSO?\bksh93\b(1)]
'

compound config=(
	typeset nickname="${LOGNAME}bot"
	typeset servername="irc.freenode.net"
	integer port=6667
	typeset -a join_channels
)

while getopts -a "${progname}" "${shircbot_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		n)	config.nickname="${OPTARG}" ;;
		s)	config.servername="${OPTARG}" ;;
		j)	config.join_channels+=( "${OPTARG}" ) ;;
		*)	usage ;;
	esac
done
shift $((OPTIND-1))

# if no channel was provided we join a predefined set of channels
if (( ${#config.join_channels[@]} == 0 )) ; then
	if [[ "${config.servername}" == "irc.freenode.net" ]] ; then
		config.join_channels+=( "#opensolaris" )
		config.join_channels+=( "#opensolaris-dev" )
		config.join_channels+=( "#opensolaris-arc" )
		config.join_channels+=( "#opensolaris-meeting" )
		config.join_channels+=( "#ospkg" )
		config.join_channels+=( "#ksh" )
	elif [[ "${config.servername}" == ~(E)irc.(sfbay|sweden) ]] ; then
		config.join_channels+=( "#onnv" )
	fi
fi

print "## Start."

ircsession_t mybot

# override ircsession_t::serverevent_privmsg with a new method for our bot
function mybot.serverevent_privmsg
{
	nameref args=$1
	typeset msguser="${args.msguser}"
	typeset msgchannel="${args.msgchannel}"
	typeset msg="${args.msg}"
	
	printf "#message: user=%q, channel=%q, msg=%q\n" "$msguser" "$msgchannel" "$msg"
	
	# Check if we get a private message
	if [[ "${msgchannel}" == "${_.nick}" ]] ; then
		# ${msgchannel} point to our own nick if we got a private message,
		# we need to extract the sender's nickname from ${msguser} and put
		# it into msgchannel
		msgchannel="${msguser/~(El):(.*)!.*/\1}"
	else
		# check if this is a command for this bot
		[[ "$msg" != ~(Eli):${_.nick}:[[:space:]]  ]] && return 0
	fi
	
	# strip beginning (e.g. ":<nick>:" or ":") plus extra spaces
	msg="${msg/~(Eli)(:${_.nick})*:[[:space:]]*/}"
	
	printf "botmsg=%q\n" "$msg"
	
	case "$msg" in
		~(Eli)date)
			_.send_privmsg "$msgchannel" "${
			        printf "%(%Y-%m-%d, %Th/%Z)T\n"
			}"
			;;
		~(Eli)echo)
			_.send_privmsg "$msgchannel" "${msg#*echo}"
			;;
		~(Eli)exitbot)
			typeset exitkey="$(print "$msguser" | sum -x sha1)" # this is unwise&&insecure
			if [[ "$msg" == *${exitkey}* ]] ; then
				_.running=false
			fi
			;;
		~(Eli)help)
			_.send_privmsg "$msgchannel" "${
				printf "Hello, this is shircbot, written in ksh93 (%s). " "${.sh.version}"
				printf "Subcommands are 'say hello', 'math <math-expr>', 'stocks', 'uuid', 'date' and 'echo'."
				}"
			;;
		~(Eli)math)
			if [[ "${msg}" == ~(E)[\`\$] ]] ; then
				# "restricted" shell mode would prevent any damage but we try to be carefull...
				_.send_privmsg "$msgchannel" "Syntax error."
			else
				typeset mathexpr="${msg#*math}"

				printf "Calculating '%s'\n" "${mathexpr}"
				_.send_privmsg "$msgchannel" "${
				        ( printf 'export PATH=/usr/${RANDOM}/$$/${RANDOM}/foo ; set -o restricted ; printf "%%s = %%.40g\n" "%s" $(( %s ))\n' "${mathexpr}" "${mathexpr}" | source /dev/stdin 2>&1 )
				}"
			fi
			;;
		~(Eli)say\ hello)
			_.send_privmsg "$msgchannel" "Hello, this is a bot."
			;;
		~(Eli)stocks)
			typeset stockmsg tickersymbol
			for tickersymbol in "JAVA" "ORCL" "IBM" "AAPL" "HPQ" ; do
				stockmsg="$( /usr/sfw/bin/wget -q -O /dev/stdout "http://quote.yahoo.com/d/quotes.csv?f=sl1d1t1c1ohgv&e=.csv&s=${tickersymbol}" 2>&1 )"
				_.send_privmsg "$msgchannel" "${tickersymbol}: ${stockmsg//,/ }"
			done
			;;
		~(Eli)uuid)
			_.send_privmsg "$msgchannel" "${
			        print "%(%Y%M%D%S%N)T$((RANDOM))%s\n" "${msguser}" | sum -x sha256
			}"
			;;
	esac
	
	return 0
}

# Automatically join the list of channels listed in |config.join_channels|
# after the client is connected to the server for some time
function mybot.mainloop_tick
{
	integer -S autojoin_done=2
	integer i
	
	if (( autojoin_done-- == 0 && ${#config.join_channels[@]} > 0 )) ; then
		print "# Autojoin channels..."

		for ((i=0 ; i < ${#config.join_channels[@]} ; i++ )) ; do
			mybot.join_channel "${config.join_channels[i]}"
		done
	fi
	
	return 0
}

mybot.createsession "${config.servername}" ${config.port} "${config.nickname}"

# This is a network-facing application - once we've set eveything up
# we set PATH to a random value and switch to the shell's restricted
# mode to make sure noone can escape the jail.
#export PATH=/usr/$RANDOM/foo
#set -o restricted

mybot.mainloop

print "## End."

exit 0
