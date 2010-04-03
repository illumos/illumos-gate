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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
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

function encode_multipart_form_data
{
	nameref formdata="$1"
	nameref content="formdata.content"
	integer numformelements=${#formdata.form[*]}
	integer i
	typeset tmp
    
	content=""
    
	# todo: add support to upload files
	for (( i=0 ; i < numformelements ; i++ )) ; do
		nameref element="formdata.form[${i}]"

		content+="--${formdata.boundary}\n"
		content+="Content-Disposition: form-data; name=\"${element.name}\"\n"
		content+="\n"
		# make sure we quote the '\' properly since we pass these data to one instance of
		# "print" when putting the content on the wire.
		content+="${element.data//\\/\\\\}\n" # fixme: may need encoding for non-ASCII data
	done
    
	# we have to de-quote the content before we can count the real numer of bytes in the payload
	tmp="$(print -- "${content}")"
	formdata.content_length=${#tmp}

	# add content tail (which MUST not be added to the content length)
	content+="--${formdata.boundary}--\n"

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

function history_write_record
{
	# rec: history record:
	#     rec.title
	#     rec.description
	#     rec.provider
	#     rec.providertoken
	#     rec.url
	nameref rec="$1"
	integer histfd

	mkdir -p "${HOME}/.shnote"
    
	{
		# write a single-line record which can be read
		# as a compound variable back into the shell
		printf "title=%q description=%q date=%q provider=%q providertoken=%q url=%q\n" \
			"${rec.title}" \
			"${rec.description}" \
			"$(date)" \
			"${rec.provider}" \
			"${rec.providertoken}" \
			"${rec.url}"	    
	} >>"${history_file}"

	return $?
}

function print_history
{
	integer histfd # http stream number
	typeset line

	(( $# != 0 && $# != 1 )) && { print -u2 -f $"%s: Wrong number of arguments.\n" "$0" ; return 1 ; }

	# default output format is:
	# <access url>/<title> <date> <access url>
	[[ "$1" == "-l" ]] || printf "# %s\t\t\t\t\t%s\t%s\n" "<url>" "<title>" "<date>"

	# no history file ?     
	if [[ ! -f "${history_file}" ]] ; then
		return 0
	fi

	# open history file
	redirect {histfd}<> "${history_file}"
	(( $? != 0 )) && { print -u2 "Could not open history file." ;  return 1 ; }
    
	while read -u${histfd} line ; do
		compound rec
	
		printf "( %s )\n" "${line}"  | read -C rec
	
		if [[ "$1" == "-l" ]] ; then 
			print -- "${rec}"
		else
			printf "%q\t%q\t%q\n" "${rec.url}" "${rec.title}" "${rec.date}"
		fi
	
		unset rec
	done
    
	# close history file
	redirect {histfd}<&-
	
	return 0
}

function put_note_pastebin_ca
{
	# key to autheticate this script against pastebin.ca
	typeset -r pastebin_ca_key="9CFXFyeNC3iga/vthok75kTBu5kSSLPD"
	# site setup
	typeset url_host="opensolaris.pastebin.ca"
	typeset url_path="/quiet-paste.php?api=${pastebin_ca_key}"
	typeset url="http://${url_host}${url_path}"
	integer netfd # http stream number
	compound httpresponse
	
	(( $# != 1 )) && { print -u2 -f $"%s: Wrong number of arguments.\n" "$0" ; return 1 ; }
	(( ${#1} == 0 )) && { print -u2 -f $"%s: No data.\n" "$0" ; return 1 ; }

	# argument for "encode_multipart_form_data"
	compound mimeform=(
		# input
		typeset boundary
		typeset -a form
		# output
		typeset content
		integer content_length
	)
     
	typeset request=""
	typeset content=""

	typeset -r boundary="--------shnote_${RANDOM}_Xfish_${RANDOM}_Yeats_${RANDOM}_Zchicken_${RANDOM}monster_--------"

	mimeform.boundary="${boundary}"
	mimeform.form=( # we use explicit index numbers since we rely on them below when filling the history
		[0]=( name="name"		data="${LOGNAME}" )
		[1]=( name="expiry"		data="Never" )
		[2]=( name="type"		data="1" )
		[3]=( name="description"	data="logname=${LOGNAME};hostname=$(hostname);date=$(date)" )
		[4]=( name="content"		data="$1" )
	)
	encode_multipart_form_data mimeform
          
	content="${mimeform.content}"

	request="POST ${url_path} HTTP/1.1\r\n"
	request+="Host: ${url_host}\r\n"
	request+="User-Agent: ${http_user_agent}\r\n"
	request+="Connection: close\r\n"
	request+="Content-Type: multipart/form-data; boundary=${boundary}\r\n"
	request+="Content-Length: $(( mimeform.content_length ))\r\n"

	redirect {netfd}<> "/dev/tcp/${url_host}/80" 
	(( $? != 0 )) && { print -u2 -f $"%s: Could not open connection to %s.\n" "$0" "${url_host}" ;  return 1 ; }

	# send http post
	{
		print -n -- "${request}\r\n"
		print -n -- "${content}\r\n"
	}  >&${netfd}

	# process reply
	parse_http_response httpresponse <&${netfd}
	response="$(cat_http_body "${httpresponse.transfer_encoding}" <&${netfd})"

	# close connection
	redirect {netfd}<&-
    
	if [[ "${response}" == ~(E).*SUCCESS.* ]] ; then
		typeset response_token="${response/~(E).*SUCCESS:/}"

		printf "SUCCESS: http://opensolaris.pastebin.ca/%s\n" "${response_token}"
	
		# write history entry
		compound histrec=(
			title="${mimeform.form[0].data}"
			description="${mimeform.form[3].data}"
			providertoken="${response_token}"
			provider="opensolaris.pastebin.ca"
			url="http://opensolaris.pastebin.ca/${response_token}"
		)	

		history_write_record histrec
		return 0
	else
		printf "ERROR: %s\n" "${response}"
		return 1
	fi
	
	# not reached
}

function get_note_pastebin_ca
{
	typeset recordname="$1"
	integer netfd # http stream number

	(( $# != 1 )) && { print -u2 -f $"%s: No key or key URL.\n" "$0" ; return 1 ; }
    
	case "${recordname}" in
		~(Elr)[0-9][0-9]*)
			# pass-through
			;;
		~(Elr)http://opensolaris.pastebin.ca/raw/[0-9]*)
			recordname="${recordname/~(El)http:\/\/opensolaris.pastebin.ca\/raw\//}"
			;;
		~(Elr)http://opensolaris.pastebin.ca/[0-9]*)
			recordname="${recordname/~(El)http:\/\/opensolaris.pastebin.ca\//}"
			;;
		*)
			fatal_error $"Unsupported record name ${recordname}."
	esac
    
	print -u2 -f "# Record name is '%s'\n" "${recordname}"

	typeset url_host="opensolaris.pastebin.ca"
	typeset url_path="/raw/${recordname}"
	typeset url="http://${url_host}${url_path}"
	# I hereby curse Solaris for not having an entry for "http" in /etc/services

	# open TCP channel
	redirect {netfd}<> "/dev/tcp/${url_host}/80"
	(( $? != 0 )) && { print -u2 -f $"%s: Could not open connection to %s.\n" "$0" "${url_host}" ; return 1 ; }

	# send HTTP request    
	request="GET ${url_path} HTTP/1.1\r\n"
	request+="Host: ${url_host}\r\n"
	request+="User-Agent: ${http_user_agent}\r\n"
	request+="Connection: close\r\n"
	print -u${netfd} -- "${request}\r\n"
    
	# collect response and send it to stdout
	parse_http_response httpresponse <&${netfd}
	cat_http_body "${httpresponse.transfer_encoding}" <&${netfd}
    
	# close connection
	redirect {netfd}<&-
    
	print # add newline
    
	return 0
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${USAGE}" OPT '-?'
	exit 2
}

# program start
builtin basename
builtin cat
builtin date
builtin uname

typeset progname="${ basename "${0}" ; }"

# HTTP protocol client identifer
typeset -r http_user_agent="shnote/ksh93 (2010-03-27; $(uname -s -r -p))"

# name of history log (the number after "history" is some kind of version
# counter to handle incompatible changes to the history file format)
typeset -r history_file="${HOME}/.shnote/history0.txt"

typeset -r shnote_usage=$'+
[-?\n@(#)\$Id: shnote (Roland Mainz) 2010-03-27 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?shnote - read/write text data to internet clipboards]
[+DESCRIPTION?\bshnote\b is a small utilty which can read and write text
	data to internet "clipboards" such as opensolaris.pastebin.ca.]
[+?The first arg \bmethod\b describes one of the methods, "put" saves a string
	to the internet clipboard, returning an identifer and the full URL
	where the data are stored. The method "get" retrives the raw
	information using the identifer from the previous "put" action.
	The method "hist" prints a history of transactions created with the
	"put" method and the keys to retrive them again using the "get" method.]
[+?The second arg \bstring\b contains either the string data which should be
	stored on the clipboard using the "put" method, the "get" method uses
	this information as identifer to retrive the raw data from the
	clipboard.]

method [ string ]

[+SEE ALSO?\bksh93\b(1), \brssread\b(1), \bshtwitter\b(1), \bshtinyurl\b(1), http://opensolaris.pastebin.ca]
'

while getopts -a "${progname}" "${shnote_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		*)	usage ;;
	esac
done
shift $((OPTIND-1))

# expecting at least one more argument, the single method below will do
# the checks for more arguments if needed ("put" and "get" methods need
# at least one extra argument, "hist" none).
(($# >= 1)) || usage

typeset method="$1"
shift

case "${method}" in
	put)	put_note_pastebin_ca "$@" ; exit $? ;;
	get)	get_note_pastebin_ca "$@" ; exit $? ;;
	hist)	print_history "$@"        ; exit $? ;;
	*)	usage ;;
esac

fatal_error $"not reached."
# EOF.
