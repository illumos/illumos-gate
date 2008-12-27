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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# rssread - a simple RSS2.0 reader with RSS to XHTML to
# plaintext conversion.
#

# Solaris needs /usr/xpg6/bin:/usr/xpg4/bin because the tools in /usr/bin are not POSIX-conformant
export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/bin:/usr/bin

function printmsg
{
	print -u2 "$*"
}

function debugmsg
{
#	printmsg "$*"
true
}

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
			[[ "${hexchunksize}" == ~(Elri)[0-9abcdef]* ]] &&
			(( chunksize=16#${hexchunksize} )) && (( chunksize > 0 )) ; do
			dd bs=1 count="${chunksize}" 2>/dev/null
		done
	else
		cat
	fi

	return 0
}

function cat_http
{
	typeset protocol="${1%://*}"
	typeset path1="${1#*://}" # "http://foo.bat.net/x/y.html" ----> "foo.bat.net/x/y.html"

	typeset host="${path1%%/*}"
	typeset path="${path1#*/}"
	typeset port="${host##*:}"
    
	integer netfd
	typeset -C httpresponse # http response

	# If URL did not contain a port number in the host part then look at the
	# protocol to get the port number
	if [[ "${port}" == "${host}" ]] ; then
		case "${protocol}" in
			"http") port=80 ;;
			*)      port="$(getent services "${protocol}" | sed 's/[^0-9]*//;s/\/.*//')" ;;
		esac
	else
		host="${host%:*}"
	fi
    
	printmsg "protocol=${protocol} port=${port} host=${host} path=${path}"
    
	# prechecks
	[[ "${protocol}" == "" ]] && { print -u2 -f "%s: protocol not set.\n" "$0" ; return 1 ; }
	[[ "${port}"     == "" ]] && { print -u2 -f "%s: port not set.\n"     "$0" ; return 1 ; }
	[[ "${host}"     == "" ]] && { print -u2 -f "%s: host not set.\n"     "$0" ; return 1 ; }
	[[ "${path}"     == "" ]] && { print -u2 -f "%s: path not set.\n"     "$0" ; return 1 ; }

	# open TCP channel
	redirect {netfd}<>"/dev/tcp/${host}/${port}"
	(( $? != 0 )) && { print -u2 -f "%s: Couldn't open %s\n" "$0" "${1}" ; return 1 ; }

	# send HTTP request    
	request="GET /${path} HTTP/1.1\r\n"
	request+="Host: ${host}\r\n"
	request+="User-Agent: rssread/ksh93 (2008-10-14; $(uname -s -r -p))\r\n"
	request+="Connection: close\r\n"
	print -n -- "${request}\r\n" >&${netfd}
    
	# collect response and send it to stdout
	parse_http_response httpresponse <&${netfd}
	cat_http_body "${httpresponse.transfer_encoding}" <&${netfd}
    
	# close connection
	redirect {netfd}<&-
	
	return 0
}

function html_entity_to_ascii
{
	typeset buf
	typeset entity
	typeset c
	typeset value

	# Todo: Add more HTML/MathML entities here
	# Note we use a static variable (typeset -S) here to make sure we
	# don't loose the cache data between calls
	typeset -S -A entity_cache=(
		# entity to ascii (fixme: add UTF-8 transliterations)
		["nbsp"]=' '
		["lt"]='<'
		["le"]='<='
		["gt"]='>'
		["ge"]='>='
		["amp"]='&'
		["quot"]='"'
		["apos"]="'"
	)
    
	buf=""
	while IFS='' read -r -N 1 c ; do
		if [[ "$c" != "&" ]] ; then
			print -n -r -- "${c}"
			continue
		fi
        
		entity=""
		while IFS='' read -r -N 1 c ; do
			case "$c" in
				";")
				break
				;;
			~(Eilr)[a-z0-9#])
				entity+="$c"
				continue
				;;
			*)
#				debugmsg "error &${entity}${c}#"

				print -n -r -- "${entity}${c}"
				entity=""
				continue 2
				;;
			esac
		done
        
		value=""
		if [[ "${entity_cache["${entity}"]}" != "" ]] ; then
#			debugmsg "match #${entity}# = #${entity_cache["${entity}"]}#"
			value="${entity_cache["${entity}"]}"
		else
			if [[ "${entity:0:1}" == "#" ]] ; then
				# decimal literal
				value="${ printf "\u[${ printf "%x" "${entity:1:8}" ; }]" ; }"
			elif [[ "${entity:0:7}" == ~(Eilr)[0-9a-f]* ]] ; then
				# hexadecimal literal
				value="${ printf "\u[${entity:0:7}]" ; }"
			else
				# unknown literal - pass-through
				value="ENT=|${entity}|"
			fi

			entity_cache["${entity}"]="${value}"

#			debugmsg "lookup #${entity}# = #${entity_cache["${entity}"]}#"
		fi

		printf "%s" "${value}"
	done

	return 0
}

# dumb xhtml handler - no CSS,  tables, images, iframes or nested
# structures are supported (and we assume that the input is correct
# xhtml). The code was written in a trial&&error manner and should be
# rewritten to parse xhtml correctly.
function handle_html
{
    # we can't use global variables here when multiple callbacks use the same
    # callback function - but we can use the callback associative array for
    # variable storage instead
    nameref callbacks=${1}
    typeset tag_type="$2"
    typeset tag_value="$3"

    case "${tag_type}" in
        tag_begin)
            case "${tag_value}" in
                br) printf "\n" ;;
                hr) printf "\n-------------------------------------\n" ;;
                pre) callbacks["html_pre"]='true' ;;
                p)  printf "\n" ;;
            esac
            ;;

        tag_end)
            case "${tag_value}" in
                pre) callbacks["html_pre"]='false' ;;
            esac
            ;;

        tag_text)
            if ${callbacks["html_pre"]} ; then
                printf "%s" "${tag_value}"
            else
                # compress spaces/newlines/tabs/etc.
                printf "%s" "${tag_value//+([\n\r\t\v[:space:][:blank:]])/ }"
            fi
            ;;

        document_start)
            callbacks["html_pre"]='false'
            ;;
        document_end) ;;
    esac

    return 0
}

function handle_rss
{
	# we can't use global variables here when multiple callbacks use the same
	# callback function - but we can use the callback associative array for
	# variable storage instead
	nameref callbacks=${1}
	typeset tag_type="$2"
	typeset tag_value="$3"

	case "${tag_type}" in
		tag_begin)
			case "${tag_value}" in
				item)
					item["title"]=""
					item["link"]=""
					item["tag"]=""
					item["description"]=""
					;;
			esac
			callbacks["textbuf"]=""
			;;
		tag_end)
			case "${tag_value}" in
				item)
					# note that each RSS item needs to be converted seperately from RSS to HTML to plain text
					# to make sure that the state of one RSS item doesn't affect others
					(
						printf $"<br />#### RSS item: title: %s ####" "${item["title"]}"
						printf $"<br />## author: %s" "${item["author"]}"
						printf $"<br />## link:   %s" "${item["link"]}"
						printf $"<br />## date:   %s" "${item["pubDate"]}"
						printf $"<br />## begin description:"
						printf $"<br />%s<br />" "${item["description"]}"
						printf $"<br />## end description<br />"
						print # extra newline to make sure the sed pipeline gets flushed
					) | 
						html_entity_to_ascii |	# convert XML entities (e.g. decode RSS content to HTML code)
						xml_tok "xhtmltok_cb" |	# convert HTML to plain text
						html_entity_to_ascii	# convert HTML entities
					;;
				title)                item["title"]="${callbacks["textbuf"]}"        ; callbacks["textbuf"]="" ;;
				link)                 item["link"]="${callbacks["textbuf"]}"         ; callbacks["textbuf"]="" ;;
				dc:creator | author)  item["author"]="${callbacks["textbuf"]}"       ; callbacks["textbuf"]="" ;;
				dc:date | pubDate)    item["pubDate"]="${callbacks["textbuf"]}"      ; callbacks["textbuf"]="" ;;
				description)          item["description"]="${callbacks["textbuf"]}"  ; callbacks["textbuf"]="" ;;
			esac
			callbacks["textbuf"]=""
			;;
		tag_text)
			callbacks["textbuf"]+="${tag_value}"
			;;
		document_start) ;;
		document_end) ;;
	esac
	return 0
}

function xml_tok
{
    typeset buf=""
    typeset namebuf=""
    typeset attrbuf=""
    typeset c=""
    typeset isendtag # bool: true/false
    typeset issingletag # bool: true/false (used for tags like "<br />")
    nameref callbacks=${1}
    
    [[ ! -z "${callbacks["document_start"]}" ]] && ${callbacks["document_start"]} "${1}" "document_start"

    while IFS='' read -r -N 1 c ; do
        isendtag=false
        
        if [[ "$c" == "<" ]] ; then
	    # flush any text content
            if [[ "$buf" != "" ]] ; then
                [[ ! -z "${callbacks["tag_text"]}" ]] && ${callbacks["tag_text"]} "${1}" "tag_text" "$buf"
                buf=""
            fi
            
            IFS='' read -r -N 1 c
            if [[ "$c" == "/" ]] ; then
                isendtag=true
            else
                buf="$c"
            fi
            IFS='' read -r -d '>' c
            buf+="$c"
	    
	    # handle comments
	    if [[ "$buf" == ~(El)!-- ]] ; then
	        # did we read the comment completely ?
	        if [[ "$buf" != ~(Elr)!--.*-- ]] ; then
		    buf+=">"
	            while [[ "$buf" != ~(Elr)!--.*-- ]] ; do
		        IFS='' read -r -N 1 c || break
		        buf+="$c"
		    done
		fi
	    
		[[ ! -z "${callbacks["tag_comment"]}" ]] && ${callbacks["tag_comment"]} "${1}" "tag_comment" "${buf:3:${#buf}-5}"
		buf=""
		continue
	    fi
	    
	    # check if the tag starts and ends at the same time (like "<br />")
	    if [[ "${buf}" == ~(Er).*/ ]] ; then
	        issingletag=true
		buf="${buf%*/}"
	    else
	        issingletag=false
	    fi
	    
	    # check if the tag has attributes (e.g. space after name)
	    if [[ "$buf" == ~(E)[[:space:][:blank:]] ]] ; then
	        namebuf="${buf%%~(E)[[:space:][:blank:]].*}"
                attrbuf="${buf#~(E).*[[:space:][:blank:]]}"
            else
	        namebuf="$buf"
		attrbuf=""
	    fi
	    
            if ${isendtag} ; then
                [[ ! -z "${callbacks["tag_end"]}" ]] && ${callbacks["tag_end"]} "${1}" "tag_end" "$namebuf"
            else
                [[ ! -z "${callbacks["tag_begin"]}" ]] && ${callbacks["tag_begin"]} "${1}" "tag_begin" "$namebuf" "$attrbuf"

                # handle tags like <br/> (which are start- and end-tag in one piece)
                if ${issingletag} ; then
                    [[ ! -z "${callbacks["tag_end"]}" ]] && ${callbacks["tag_end"]} "${1}" "tag_end" "$namebuf"
                fi
            fi
            buf=""
        else
            buf+="$c"
        fi
    done

    [[ ! -z "${callbacks["document_end"]}" ]] && ${callbacks["document_end"]} "${1}" "document_end" "exit_success"
    
    print # final newline to make filters like "sed" happy
}

# return the value of LC_MESSAGES needed for subprocesses which
# want to run in a different locale/encoding
function get_lc_messages
{
	[[ "${LC_ALL}"       != "" ]] && { print "${LC_ALL}"      ; return 0 ; }
	[[ "${LC_MESSAGES}"  != "" ]] && { print "${LC_MESSAGES}" ; return 0 ; }
	[[ "${LANG}"         != "" ]] && { print "${LANG}"        ; return 0 ; }
	print "C" ; return 0
}

function do_rssread
{
	# set unicode locale since RSS is encoded in UTF-8
	# (and make sure $LC_MESSAGES is set to the parent
	# process's locale that all error messages are using
	# the callers locale/encoding)
	export \
		LC_MESSAGES="${ get_lc_messages ; }" \
		LC_MONETARY="en_US.UTF-8" \
		LC_NUMERIC="en_US.UTF-8" \
		LC_COLLATE="en_US.UTF-8" \
		LC_CTYPE="en_US.UTF-8" \
		LC_TIME="en_US.UTF-8" \
		LANG="en_US.UTF-8"

	# need extra newline after cat_http to terminate line with $'\n'
	# to make "xml_tok" happy
	{ cat_http "$1" ; print ; } |
		xml_tok "rsstok_cb"
	return 0
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${rssread_usage}" OPT '-?'
	exit 2
}

# make sure we use the ksh93 builtin versions
builtin basename
builtin cat

typeset -A rsstok_cb # callbacks for xml_tok
rsstok_cb["tag_begin"]="handle_rss"
rsstok_cb["tag_end"]="handle_rss"
rsstok_cb["tag_text"]="handle_rss"
rsstok_cb["textbuf"]=""

typeset -A xhtmltok_cb # callbacks for xml_tok
xhtmltok_cb["tag_begin"]="handle_html"
xhtmltok_cb["tag_end"]="handle_html"
xhtmltok_cb["tag_text"]="handle_html"
xhtmltok_cb["textbuf"]=""
xhtmltok_cb["html_pre"]='false'

typeset -A item

typeset -A bookmark_urls

# "ramdom" urls for testing
bookmark_urls=(
	["google_blogs_ksh"]="http://blogsearch.google.com/blogsearch_feeds?hl=en&scoring=d&q=(%22ksh93%22%7C%22ksh+93%22+%7C+%22korn93%22+%7C+%22korn+93%22)&ie=utf-8&num=100&output=rss"
	# OpenSolaris.org sites
	["ksh93_integration"]="http://www.opensolaris.org/rss/os/project/ksh93-integration/announcements/rss2.xml"
	["shell"]="http://www.opensolaris.org/rss/os/project/shell/announcements/rss2.xml"
	["systemz"]="http://www.opensolaris.org/rss/os/project/systemz/announcements/rss2.xml"
	# some Sun staff/sites
	["blogs_sun_com"]="http://blogs.sun.com/main/feed/entries/rss"
	["bigadmin"]="http://www.sun.com/bigadmin/content/rss/motd.xml"
	["jmcp"]="http://www.jmcp.homeunix.com/roller/jmcp/feed/entries/rss"
	["katakai"]="http://blogs.sun.com/katakai/feed/entries/rss"
	["alanc"]="http://blogs.sun.com/alanc/feed/entries/rss"
	["planetsun"]="http://www.planetsun.org/rss20.xml"
	["planetsolaris"]="http://www.planetsolaris.org/rss20.xml"
	["planetopensolaris"]="http://planet.opensolaris.org/rss20.xml"
	["theregister_uk"]="http://www.theregister.co.uk/headlines.rss"
	["heise"]="http://www.heise.de/newsticker/heise.rdf"
	["slashdot"]="http://rss.slashdot.org/Slashdot/slashdot"
)

typeset progname="${ basename "${0}" ; }"

typeset -r rssread_usage=$'+
[-?\n@(#)\$Id: rssread (Roland Mainz) 2008-11-10 \$\n]
[-author?Roland Mainz <roland.mainz@sun.com>]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?rssread - fetch RSS messages and convert them to plain text]
[+DESCRIPTION?\brssread\b RSS to plain text converter
        which fetches RSS streams via HTTP and converts them from
	RSS to HTML to plain text in the current locale/encoding.]
[I:noiconv?Do not convert data from UTF-8 to current locale/encoding.]

[ url ]

[+SEE ALSO?\bksh93\b(1), \bshnote\b(1)]
'

typeset noiconv=false

while getopts -a "${progname}" "${rssread_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		I)    noiconv=true  ;;
		+I)   noiconv=false ;;
		*)    usage ;;
	esac
done
shift $((OPTIND-1))

typeset url="$1"

if [[ "${url}" == "" ]] ; then
	fatal_error $"No url given."
fi

if [[ "${bookmark_urls[${url}]}" != "" ]] ; then
	printmsg $"Using bookmark ${url} = ${bookmark_urls[${url}]}"
	url="${bookmark_urls[${url}]}"
fi

if ${noiconv} ; then
	do_rssread "${url}"
else
	do_rssread "${url}" | iconv -f "UTF-8" - -
fi

exit 0
#EOF.
