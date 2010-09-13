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

function request_tinyurl
{
	# site setup
	typeset url_host="tinyurl.com"
	typeset url_path="/api-create.php"
	typeset url="http://${url_host}${url_path}"
	integer netfd # http stream number
	typeset inputurl="$1"
	compound httpresponse # http response
	typeset request=""

	# we assume "inputurl" is a correctly encoded URL which doesn't
	# require any further mangling
	url_path+="?url=${inputurl}"

	request="GET ${url_path} HTTP/1.1\r\n"
	request+="Host: ${url_host}\r\n"
	request+="User-Agent: ${http_user_agent}\r\n"
	request+="Connection: close\r\n"

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
        
	if (( httpresponse.statuscode >= 200 && httpresponse.statuscode <= 299 )) ; then
		print -r -- "${response}"
		return 0
	else
		print -u2 -f $"tinyurl response was (%s,%s):\n%s\n" "${httpresponse.statuscode}" "${httpresponse.statusmsg}" "${response}"
		return 1
	fi
	
	# not reached
}

function request_trimurl
{
	# site setup
	typeset url_host="api.tr.im"
	typeset url_path="/api/trim_url.xml"
	typeset url="http://${url_host}${url_path}"
	integer netfd # http stream number
	typeset inputurl="$1"
	compound httpresponse # http response
	typeset request=""

	# we assume "inputurl" is a correctly encoded URL which doesn't
	# require any further mangling
	url_path+="?url=${inputurl}"

	request="GET ${url_path} HTTP/1.1\r\n"
	request+="Host: ${url_host}\r\n"
	request+="User-Agent: ${http_user_agent}\r\n"
	request+="Connection: close\r\n"

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
        
	if (( httpresponse.statuscode >= 200 && httpresponse.statuscode <= 299 )) ; then
		# the statement below should really parse the XML...
		print -r -- "${response/~(Elr).*(\<url\>)(.*)(\<\/url\>).*/\2}"
		return 0
	else
		print -u2 -f $"tr.im response was (%s,%s):\n%s\n" "${httpresponse.statuscode}" "${httpresponse.statusmsg}" "${response}"
		return 1
	fi
	
	# not reached
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${shtinyurl_usage}" OPT '-?'
	exit 2
}

# program start
builtin basename
builtin cat
builtin date
builtin uname

typeset progname="${ basename "${0}" ; }"

# HTTP protocol client identifer
typeset -r http_user_agent="shtinyurl/ksh93 (2010-03-27; ${ uname -s -r -p ; })"

typeset -r shtinyurl_usage=$'+
[-?\n@(#)\$Id: shtinyurl (Roland Mainz) 2010-03-27 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?shtinyurl - create short alias URL from long URL]
[+DESCRIPTION?\bshtinyurl\b is a small utility which passes a given URL
	to internet service which creates short aliases in the
	form of http://<servicename>/XXXXXXXX to redirect long URLs.]
[+?The first arg \burl\b describes a long URL which is transformed into
	a tinyurl.com short alias.]
[P:provider?Service provider (either \'tinyurl.com\' or \'tr.im\').]:[mode]

url

[+SEE ALSO?\bksh93\b(1), \brssread\b(1), \bshtwitter\b(1), http://www.tinyurl.com, http://tr.im]
'

typeset service_provider="tr.im"

while getopts -a "${progname}" "${shtinyurl_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		P)	service_provider="${OPTARG}" ;;
		*)	usage ;;
	esac
done
shift $((OPTIND-1))

# expecting at least one more argument
(( $# >= 1 )) || usage

typeset url="$1"
shift

case "${service_provider}" in
	"tinyurl.com")
		request_tinyurl "${url}"
		exit $?
		;;
	"tr.im")
		request_trimurl "${url}"
		exit $?
		;;
	*)
		fatal_error "Unsupported service provider."
esac

# not reached

# EOF.
