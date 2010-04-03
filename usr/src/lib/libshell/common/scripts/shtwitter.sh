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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
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

function encode_x_www_form_urlencoded
{
	nameref formdata=$1
	nameref content="formdata.content"
	integer numformelements=${#formdata.form[*]}
	integer i j
    
	content=""
    
	for (( i=0 ; i < numformelements ; i++ )) ; do
		nameref element="formdata.form[${i}]"
		typeset data="${element.data}"
		integer datalen="${#data}"
		typeset c

		[[ "$content" != "" ]] && content+="&"
	
		content+="${element.name}="
        
		for ((j=0 ; j < datalen ; j++)) ; do
			c="${data:j:1}"
			case "$c" in
				' ') c="+"   ;;
				'!') c="%21" ;;
				'*') c="%2A" ;;
				"'") c="%27" ;;
				'(') c="%28" ;;
				')') c="%29" ;;
				';') c="%3B" ;;
				':') c="%3A" ;;
				'@') c="%40" ;;
				'&') c="%26" ;;
				'=') c="%3D" ;;
				'+') c="%2B" ;;
				'$') c="%24" ;;
				',') c="%2C" ;;
				'/') c="%2F" ;;
				'?') c="%3F" ;;
				'%') c="%25" ;;
				'#') c="%23" ;;
				'[') c="%5B" ;;
				'\') c="%5C" ;; # we need this to avoid the '\'-quoting hell
				']') c="%5D" ;;
				*)   ;;
			esac
			content+="$c"
		done
	done
    
	formdata.content_length=${#content}

	return 0
}

# parse HTTP return code, cookies etc.
function parse_http_response
{
	nameref response="$1"
	typeset h statuscode statusmsg i
    
	# we use '\r' as additional IFS to filter the final '\r'
	IFS=$' \t\r' read -r h statuscode statusmsg  # read HTTP/1.[01] <code>
	[[ "$h" != ~(Eil)HTTP/.* ]]         && { print -u2 -f $"%s: HTTP/ header missing\n" "$0" ; return 1 ; }
	[[ "$statuscode" != ~(Elr)[0-9]* ]] && { print -u2 -f $"%s: invalid status code\n"  "$0" ; return 1 ; }
	response.statuscode="$statuscode"
	response.statusmsg="$statusmsg"
    
	# skip remaining headers
	while IFS='' read -r i ; do
		[[ "$i" == $'\r' ]] && break

		# strip '\r' at the end
		i="${i/~(Er)$'\r'/}"

		case "$i" in
			~(Eli)Content-Type:.*)
				response.content_type="${i/~(El).*:[[:blank:]]*/}"
				;;
			~(Eli)Content-Length:[[:blank:]]*[0-9]*)
				integer response.content_length="${i/~(El).*:[[:blank:]]*/}"
				;;
			~(Eli)Transfer-Encoding:.*)
				response.transfer_encoding="${i/~(El).*:[[:blank:]]*/}"
				;;
		esac
	done

	return 0
}

function cat_http_body
{
	typeset emode="$1"
	typeset hexchunksize="0"
	integer chunksize=0 
    
	if [[ "${emode}" == "chunked" ]] ; then
		while IFS=$'\r' read hexchunksize &&
			[[ "${hexchunksize}" == ~(Elri)[0-9abcdef]+ ]] &&
			(( chunksize=$( printf "16#%s\n" "${hexchunksize}" ) )) && (( chunksize > 0 )) ; do
			dd bs=1 count="${chunksize}" 2>/dev/null
		done
	else
		cat
	fi

	return 0
}

function encode_http_basic_auth
{
	typeset user="$1"
	typeset passwd="$2"
	typeset s
	integer s_len
	typeset -b base64var
    
	# ksh93 binary variables use base64 encoding, the same as the
	# HTTP basic authentification. We only have to read the
	# plaintext user:passwd string into the binary variable "base64var"
	# and then print this variable as ASCII.
	s="${user}:${passwd}"
	s_len="${#s}"
	print -n "${s}" | read -N${s_len} base64var
    
	print -- "${base64var}" # print ASCII (base64) representation of binary var
    
	return 0
}

function put_twitter_message
{
	[[ "$SHTWITTER_USER"   == "" ]] && { print -u2 -f $"%s: SHTWITTER_USER not set.\n" "$0" ; return 1 ; }
	[[ "$SHTWITTER_PASSWD" == "" ]] && { print -u2 -f $"%s: SHTWITTER_PASSWD not set.\n" "$0" ; return 1 ; }

	(( $# != 1 )) && { print -u2 -f $"%s: Wrong number of arguments.\n" "$0" ; return 1 ; }

	# site setup
	typeset url_host="twitter.com"
	typeset url_path="/statuses/update.xml"
	typeset url="http://${url_host}${url_path}"
	integer netfd # http stream number
	typeset msgtext="$1"
	compound httpresponse # http response

	# argument for "encode_x_www_form_urlencoded"
	compound urlform=(
		# input
		compound -a form=(
			( name="status"	data="${msgtext}" )
		)
		# output
		typeset content
		integer content_length
	)
     
	typeset request=""
	typeset content=""

	encode_x_www_form_urlencoded urlform
          
	content="${urlform.content}"

	request="POST ${url_path} HTTP/1.1\r\n"
	request+="Host: ${url_host}\r\n"
	request+="Authorization: Basic ${ encode_http_basic_auth "${SHTWITTER_USER}" "${SHTWITTER_PASSWD}" ; }\r\n"
	request+="User-Agent: ${http_user_agent}\r\n"
	request+="Connection: close\r\n"
	request+="Content-Type: application/x-www-form-urlencoded\r\n"
	request+="Content-Length: $(( urlform.content_length ))\r\n"

	redirect {netfd}<> "/dev/tcp/${url_host}/80" 
	(( $? != 0 )) && { print -u2 -f "%s: Could not open connection to %s\n." "$0" "${url_host}" ;  return 1 ; }

	# send http post
	{
		print -n -- "${request}\r\n"
		print -n -- "${content}\r\n"
	}  >&${netfd}

	# process reply
	parse_http_response httpresponse <&${netfd}
	response="${ cat_http_body "${httpresponse.transfer_encoding}" <&${netfd} ; }"

	# close connection
	redirect {netfd}<&-
    
	printf $"twitter response was (%s,%s): %s\n" "${httpresponse.statuscode}" "${httpresponse.statusmsg}" "${response}"
    
	if (( httpresponse.statuscode >= 200 && httpresponse.statuscode <= 299 )) ; then
		return 0
	else
		return 1
	fi

	# not reached
}

function verify_twitter_credentials
{
	[[ "$SHTWITTER_USER"   == "" ]] && { print -u2 -f $"%s: SHTWITTER_USER not set.\n" "$0" ; return 1 ; }
	[[ "$SHTWITTER_PASSWD" == "" ]] && { print -u2 -f $"%s: SHTWITTER_PASSWD not set.\n" "$0" ; return 1 ; }

	(( $# != 0 )) && { print -u2 -f $"%s: Wrong number of arguments.\n" "$0" ; return 1 ; }

	# site setup
	typeset url_host="twitter.com"
	typeset url_path="/account/verify_credentials.xml"
	typeset url="http://${url_host}${url_path}"
	integer netfd # http stream number
	compound httpresponse # http response

	typeset request=""

	request="POST ${url_path} HTTP/1.1\r\n"
	request+="Host: ${url_host}\r\n"
	request+="Authorization: Basic ${ encode_http_basic_auth "${SHTWITTER_USER}" "${SHTWITTER_PASSWD}" ; }\r\n"
	request+="User-Agent: ${http_user_agent}\r\n"
	request+="Connection: close\r\n"
	request+="Content-Type: application/x-www-form-urlencoded\r\n"
	request+="Content-Length: 0\r\n" # dummy

	redirect {netfd}<> "/dev/tcp/${url_host}/80" 
	(( $? != 0 )) && { print -u2 -f $"%s: Could not open connection to %s.\n" "$0" "${url_host}" ;  return 1 ; }

	# send http post
	{
		print -n -- "${request}\r\n"
	}  >&${netfd}

	# process reply
	parse_http_response httpresponse <&${netfd}
	response="${ cat_http_body "${httpresponse.transfer_encoding}" <&${netfd} ; }"

	# close connection
	redirect {netfd}<&-
    
	printf $"twitter response was (%s,%s): %s\n" "${httpresponse.statuscode}" "${httpresponse.statusmsg}" "${response}"
    
	if (( httpresponse.statuscode >= 200 && httpresponse.statuscode <= 299 )) ; then
		return 0
	else
		return 1
	fi

	# not reached
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${shtwitter_usage}" OPT '-?'
	exit 2
}

# program start
builtin basename
builtin cat
builtin date
builtin uname

typeset progname="${ basename "${0}" ; }"

# HTTP protocol client identifer
typeset -r http_user_agent="shtwitter/ksh93 (2010-03-27; ${ uname -s -r -p ; })"

typeset -r shtwitter_usage=$'+
[-?\n@(#)\$Id: shtwitter (Roland Mainz) 2010-03-27 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?shtwitter - read/write text data to internet clipboards]
[+DESCRIPTION?\bshtwitter\b is a small utility which can read and write text
	to the twitter.com microblogging site.]
[+?The first arg \bmethod\b describes one of the methods, "update" posts a
	text message to the users twitter blog, returning the raw response
	message from the twitter server.]
[+?The second arg \bstring\b contains the string data which should be
	stored on twitter.com.]

method [ string ]

[+SEE ALSO?\bksh93\b(1), \brssread\b(1), \bshtinyurl\b(1), http://www.twitter.com]
'

while getopts -a "${progname}" "${shtwitter_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		*)	usage ;;
	esac
done
shift $((OPTIND-1))

# expecting at least one more argument
(($# >= 1)) || usage

typeset method="$1"
shift

case "${method}" in
	update|blog)		put_twitter_message        "$@" ; exit $? ;;
	verify_credentials)	verify_twitter_credentials "$@" ; exit $? ;;
	*)			usage ;;
esac

fatal_error $"not reached."
# EOF.
