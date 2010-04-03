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

# constants values for tokenizer/parser stuff
compound -r ch=(
	newline=$'\n'
	tab=$'\t'
	formfeed=$'\f'
)

function fatal_error
{
	print -u2 "${progname}: $*"
	exit 1
}

function printmsg
{
	print -u2 "$*"
}


function attrstrtoattrarray
{
#set -o xtrace
    typeset s="$1"
    nameref aa=$2 # attribute array
    integer aa_count=0
    integer aa_count=0
    typeset nextattr
    integer currattrlen=0
    typeset tagstr
    typeset tagval

    while (( ${#s} > 0 )) ; do
        # skip whitespaces
        while [[ "${s:currattrlen:1}" == ~(E)[[:blank:][:space:]] ]] ; do
            (( currattrlen++ ))
        done
        s="${s:currattrlen:${#s}}"
        
        # anything left ?
        (( ${#s} == 0 )) && break

        # Pattern tests:
        #x="foo=bar huz=123" ; print "${x##~(E)[[:alnum:]_-:]*=[^[:blank:]\"]*}"
        #x='foo="ba=r o" huz=123' ; print "${x##~(E)[[:alnum:]_-:]*=\"[^\"]*\"}"
        #x="foo='ba=r o' huz=123" ; print "${x##~(E)[[:alnum:]_-:]*=\'[^\"]*\'}"
        #x="foox huz=123" ; print "${x##~(E)[[:alnum:]_-:]*}"
        # All pattern combined via eregex (w|x|y|z):
        #x='foo="bar=o" huz=123' ; print "${x##~(E)([[:alnum:]_-:]*=[^[:blank:]\"]*|[[:alnum:]_-:]*=\"[^\"]*\"|[[:alnum:]_-:]*=\'[^\"]*\')}"
        nextattr="${s##~(E)([[:alnum:]_-:]*=[^[:blank:]\"]*|[[:alnum:]_-:]*=\"[^\"]*\"|[[:alnum:]_-:]*=\'[^\"]*\'|[[:alnum:]_-:]*)}"
        currattrlen=$(( ${#s} - ${#nextattr}))

        # add entry
        tagstr="${s:0:currattrlen}"
        if [[ "${tagstr}" == *=* ]] ; then
            # normal case: attribute with value
            
            tagval="${tagstr#*=}"
            
            # strip quotes ('' or "")
            if [[ "${tagval}" == ~(Elr)(\'.*\'|\".*\") ]] ; then
                tagval="${tagval:1:${#tagval}-2}"
            fi
            
            aa[${aa_count}]=( name="${tagstr%%=*}" value="${tagval}" )
        else
            # special case for HTML where you have something like <foo baz>
            aa[${aa_count}]=( name="${tagstr}" )
        fi
        (( aa_count++ ))
        (( aa_count > 1000 )) && fatal_error "$0: aa_count too large" # assert
    done
}

# XML document handler
function handle_xml_document
{
#set -o xtrace
    nameref callbacks=${1}
    typeset tag_type="${2}"
    typeset tag_value="${3}"
    typeset tag_attributes="${4}"
    nameref doc=${callbacks["arg_tree"]}
    nameref nodepath="${stack.items[stack.pos]}"
    nameref nodesnum="${stack.items[stack.pos]}num"
    
    case "${tag_type}" in
        tag_comment)
            nodepath[${nodesnum}]+=( 
                typeset tagtype="comment"
                typeset tagvalue="${tag_value}"
            )
            (( nodesnum++ ))
            ;;
    esac
    
#    print "xmltok: '${tag_type}' = '${tag_value}'"
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

# enumerate comments in a shell (or shell-like) script
function enumerate_comments_shell
{
	set -o errexit

	typeset input_file="$1"
	nameref comment_array="$2"
	integer max_num_comments="$3"
	integer ca=0 # index in "comment_array"

	integer res=0

	typeset comment=""

	while (( res == 0 )) ; do
		IFS='' read -r line
		(( res=$? ))
	
		if [[ "${line}" == ~(El)#.* ]] ; then
			comment+="${line#\#}${ch.newline}"
		else
			if [[ "$comment" != "" ]] ; then
				comment_array[ca++]="${comment}"
				comment=""
		
				if (( ca > max_num_comments )) ; then
					break
				fi
			fi
		fi
	done <"${input_file}"

	return 0
}


# enumerate comments in a troff document
function enumerate_comments_troff
{
	set -o errexit

	typeset input_file="$1"
	nameref comment_array="$2"
	integer max_num_comments="$3"
	integer ca=0 # index in "comment_array"

	integer res=0

	typeset comment=""

	while (( res == 0 )) ; do
		IFS='' read -r line
		(( res=$? ))
	
		if [[ "${line}" == ~(El)\.*\\\" ]] ; then
			comment+="${line#~(El)\.*\\\"}${ch.newline}"
		else
			if [[ "$comment" != "" ]] ; then
				comment_array[ca++]="${comment}"
				comment=""
		
				if (( ca > max_num_comments )) ; then
					break
				fi
			fi
		fi
	done <"${input_file}"

	return 0
}


# enumerate comments in files which are preprocessed by
# CPP (e.g. C, C++, Imakefile etc.)
function enumerate_comments_cpp
{
	set -o errexit
#	set -o nounset

	integer err=0

	typeset input_file="$1"
	nameref comment_array="$2"
	integer max_num_comments="$3"
	integer max_filesize_for_scan="$4"
	integer ca=0 # index in "comment_array"

	typeset content
	integer content_length

	integer file_pos # file position
	compound line_pos=(
		integer x=0 # X position in line
		integer y=0 # Y position in line (line number)
	)
	typeset c c2

	typeset comment

	compound state=(
		# C comment state
		typeset in_c_comment=false
		# C++ comment state
		compound cxx=(
			typeset in_comment=false
			typeset comment_continued=false
			# position of current //-pos
			compound comment_pos=(
				integer x=-1 
				integer y=-1
			)
			# position of previous //-pos
			compound comment_prev_pos=(
				integer x=-1
				integer y=-1
			)
		)
		# literal state
		typeset in_sq_literal=false # single-quote literal
		typeset in_dq_literal=false # double-quote literal
	)

	content="$(< "${input_file}")"

	# Truncate file to "max_filesize_for_scan" charatcters.
	# This was originally added to work around a performance problem with
	# the ${str:offset:chunksize} operator which scales badly in ksh93
	# version 's' with the number of characters
	if (( ${#content} > max_filesize_for_scan )) ; then
		print -u2 -f "## WARNING: File '%s' truncated to %d characters\n" \
			"${input_file}" \
			max_filesize_for_scan
		content="${content:0:max_filesize_for_scan}"
	fi
	content_length=${#content}

	# Iterate through the source code. The last character
	# (when file_pos == content_length) will be empty to indicate
	# EOF (this is needed for cases like when
	# a C++ comment is not terminated by a newline... ;-/)
	for (( file_pos=0 ; file_pos <= content_length ; file_pos++ )) ; do
		c2="${content:file_pos:2}"
		c="${c2:0:1}"
	
		if [[ "$c" == "${ch.newline}" ]] ; then
			(( line_pos.x=0, line_pos.y++ ))
		else
			(( line_pos.x++ ))
		fi
	
		if ${state.in_c_comment} ; then
			if [[ "$c2" == "*/" ]] ; then
				(( file_pos++, line_pos.x++ ))
				state.in_c_comment=false
		
				# flush comment text
				comment_array[ca++]="${comment}"
				comment=""
		
				if (( ca > max_num_comments )) ; then
					break
				fi
			else
				comment+="$c"
			fi
		elif ${state.cxx.in_comment} ; then
			if [[ "$c" == "${ch.newline}" || "$c" == "" ]] ; then
				state.cxx.in_comment=false
		
				# flush comment text
				if ${state.cxx.comment_continued} ; then
					comment_array[ca-1]+="${ch.newline}${comment}"
					(( state.cxx.comment_prev_pos.x=state.cxx.comment_pos.x ,
					   state.cxx.comment_prev_pos.y=state.cxx.comment_pos.y ))
				else
					comment_array[ca++]="${comment}"
					(( state.cxx.comment_prev_pos.x=state.cxx.comment_pos.x ,
					   state.cxx.comment_prev_pos.y=state.cxx.comment_pos.y ))
				fi
				comment=""
				
				if (( ca > max_num_comments )) ; then
					break
				fi
			else
				comment+="$c"
			fi
		elif ${state.in_sq_literal} ; then
			if [[ "$c" == "'" && "${content:file_pos-1:1}" != '\' ]] ; then
				state.in_sq_literal=false
			fi
		elif ${state.in_dq_literal} ; then
			if [[ "$c" == '"' && "${content:file_pos-1:1}" != '\' ]] ; then
				state.in_dq_literal=false
			fi
		else
			if [[ "$c2" == "/*" ]] ; then
				(( file_pos++, line_pos.x++ ))
				state.in_c_comment=true
				comment=""
			elif [[ "$c2" == "//" ]] ; then
				(( file_pos++, line_pos.x++ ))
				if (( state.cxx.comment_prev_pos.x == line_pos.x && \
					state.cxx.comment_prev_pos.y == (line_pos.y-1) )) ; then
					state.cxx.comment_continued=true
			else
				state.cxx.comment_continued=false
			fi
			(( state.cxx.comment_pos.x=line_pos.x , state.cxx.comment_pos.y=line_pos.y ))
			state.cxx.in_comment=true
			comment=""
			elif [[ "$c" == "'" && "${content:file_pos-1:1}" != '\' ]] ; then
				state.in_sq_literal=true
			elif [[ "$c" == '"' && "${content:file_pos-1:1}" != '\' ]] ; then
				state.in_dq_literal=true
			fi
		fi
	done

	if [[ "$comment" != "" ]] ; then
		print -u2 "## ERROR: Comment text buffer not empty at EOF."
		err=1
	fi

	if ${state.in_c_comment} ; then
		print -u2 "## ERROR: C comment did not close before EOF."
		err=1
	fi

	if ${state.cxx.in_comment} ; then
		print -u2 "## ERROR: C++ comment did not close before EOF."
		err=1
	fi

	if ${state.in_dq_literal} ; then
		print -u2 "## ERROR: Double-quoted literal did not close before EOF."
		err=1
	fi

	# We treat this one only as warning since things like "foo.html.cpp" may
	# trigger this condition accidently
	if ${state.in_sq_literal} ; then
		print -u2 "## WARNING: Single-quoted literal did not close before EOF."
	fi

	return $err
}

# determine file type
function get_file_format
{
	set -o errexit

	typeset filename="$1"
	nameref file_format="$2"

	typeset fileeval # evaluation result of /usr/bin/file
	
	# check whether "filename" is a plain, readable file
	[[ ! -f "$filename" ]] && return 1
	[[ ! -r "$filename" ]] && return 1
	
	# In theory this code would exclusively look at the contents of
	# the file to figure out it's file format - unfortunately
	# /usr/bin/file is virtually useless (the heuristics, matching
	# and output unreliable) for many file formats and therefore
	# we have to do a multi-stage approach which looks
	# at the file's content if possible and at the filename
	# otherwise. Fun... ;-(
	
	# pass one: Find matches for file formats where /usr/bin/file
	# is known to be unreliable:
	case "$filename" in
		*.[ch] | *.cpp | *.cc | *.cxx | *.hxx)
			file_format="c_source"
			return 0
			;;
		*Imakefile)
			file_format="imakefile"
			return 0
			;;
		*Makefile)
			file_format="makefile"
			return 0
			;;
	esac

	# pass two: match by file content via /usr/bin/file
	fileeval="$(LC_ALL=C /usr/bin/file "$filename")"
	case "$fileeval" in
		~(E)roff)
			file_format="troff"
			return 0
			;;
		~(E)html\ document)
			file_format="html"
			return 0
			;;
		~(E)sgml\ document)
			file_format="sgml"
			return 0
			;;
		~(E)executable.*(shell|(/|/r|/pf)(sh|ksh|ksh93|rksh93|dtksh|tksh|bash))\ script)
			file_format="shell"
			return 0
			;;
		~(E)executable.*/perl\ script)
			file_format="perl"
			return 0
			;;
	esac

	# pass three: fallhack to filename matching
	case "$filename" in
		*.man)
			file_format="troff"
			return 0
			;;
		*.html)
			file_format="html"
			return 0
			;;
		*.sgml)
			file_format="sgml"
			return 0
			;;
		*.xml)
			file_format="xml"
			return 0
			;;
		*.png)
			file_format="image_png"
			return 0
			;;
		*.xcf)
			file_format="image_xcf"
			return 0
			;;
		*.shar)
			file_format="archive_shell"
			return 0
			;;
		*.sh)
			file_format="shell"
			return 0
			;;
		*.pcf)
			file_format="font_pcf"
			return 0
			;;
		*.bdf)
			file_format="font_bdf"
			return 0
			;;
		*.pmf)
			file_format="font_pmf"
			return 0
			;;
		*.ttf | *.otf)
			file_format="font_ttf"
			return 0
			;;
		*.pfa | *.pfb)
			file_format="font_postscript"
			return 0
			;;
	esac
	
	return 1
}

function extract_comments
{
	set -o errexit

	nameref records="$1"
	typeset filename="$2"
	integer max_num_comments="$3"
	integer max_filesize_for_scan="$4"

	typeset datatype=""

	records[${filename}]=(
		typeset filename="$filename"

		typeset fileformat_found="false" # "true" or "false"
		typeset file_format=""
		
		typeset -A hashsum

		typeset comments_parsed="false" # "true" or "false"
		typeset -a comments
	)
	
	records[${filename}].hashsum["md5"]="$(sum  -x md5  < "$filename")"
	records[${filename}].hashsum["sha1"]="$(sum -x sha1 < "$filename")"

	if get_file_format "$filename" datatype ; then
		records[${filename}].fileformat_found="true"
		records[${filename}].file_format="$datatype"
	else
		return 1
	fi
	
	case "$datatype" in
		c_source|imakefile)
			enumerate_comments_cpp "${filename}" "records[${filename}].comments" ${max_num_comments} ${max_filesize_for_scan} && \
				records[${filename}].comments_parsed=true
			;;
		shell|makefile)
			enumerate_comments_shell "${filename}" "records[${filename}].comments" ${max_num_comments} ${max_filesize_for_scan} && \
				records[${filename}].comments_parsed=true
			;;
		troff)
			enumerate_comments_troff "${filename}" "records[${filename}].comments" ${max_num_comments} ${max_filesize_for_scan} && \
				records[${filename}].comments_parsed=true
			;;
		# NOTE: Disabled for now
		#xml|html|sgml)
		#	enumerate_comments_xml "${filename}" "records[${filename}].comments" ${max_num_comments} ${max_filesize_for_scan} && \
		#		records[${filename}].comments_parsed=true
		#	;;
	esac
	
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
			(( chunksize=$( printf "16#%s\n" "${hexchunksize}" )  )) && (( chunksize > 0 )) ; do
			dd bs=1 count="${chunksize}" 2>/dev/null
		done
	else
		cat
	fi

	return 0
}

function cat_url
{
	typeset protocol="${1%://*}"
	typeset path1="${1#*://}" # "http://foo.bat.net/x/y.html" ----> "foo.bat.net/x/y.html"
	
	if [[ "${protocol}" == "file" ]] ; then
		cat "${path1}"
		return $?
	elif [[ "${protocol}" == ~(Elr)http(|s) ]] ; then
		typeset host="${path1%%/*}"
		typeset path="${path1#*/}"
		typeset port="${host##*:}"
    
		integer netfd
		compound httpresponse # http response

		# If URL did not contain a port number in the host part then look at the
		# protocol to get the port number
		if [[ "${port}" == "${host}" ]] ; then
			case "${protocol}" in
				"http")  port=80 ;;
				"https") port=443 ;;
				*)       port="$(getent services "${protocol}" | sed 's/[^0-9]*//;s/\/.*//')" ;;
			esac
		else
			host="${host%:*}"
		fi
    
		printmsg "protocol=${protocol} port=${port} host=${host} path=${path}"
    
		# prechecks
		[[ "${protocol}" != "" ]] || { print -u2 -f "%s: protocol not set.\n" "$0" ; return 1 ; }
		[[ "${port}"     != "" ]] || { print -u2 -f "%s: port not set.\n"     "$0" ; return 1 ; }
		[[ "${host}"     != "" ]] || { print -u2 -f "%s: host not set.\n"     "$0" ; return 1 ; }
		[[ "${path}"     != "" ]] || { print -u2 -f "%s: path not set.\n"     "$0" ; return 1 ; }

		# open TCP channel
		if [[ "${protocol}" == "https" ]] ; then
			compound sslfifo
			sslfifo.dir="$(mktemp -d)"
			sslfifo.in="${sslfifo.dir}/in"
			sslfifo.out="${sslfifo.dir}/out"
			
			# register an EXIT trap and use "errexit" to leave it at the first error
			# (this saves lots of if/fi tests for error checking)
			trap "rm -r \"${sslfifo.dir}\"" EXIT 
			set -o errexit
				
			mkfifo "${sslfifo.in}" "${sslfifo.out}"

			# create async openssl child to handle https
			openssl s_client -quiet -connect "${host}:${port}" <"${sslfifo.in}" >>"${sslfifo.out}" &

			# send HTTP request    
			request="GET /${path} HTTP/1.1\r\n"
			request+="Host: ${host}\r\n"
			request+="User-Agent: crawlsrccomments/ksh93(ssl) (2010-03-27; $(uname -s -r -p))\r\n"
			request+="Connection: close\r\n"
			print -n -- "${request}\r\n" >>	"${sslfifo.in}"
			
			# collect response and send it to stdout
			{
				parse_http_response httpresponse
				cat_http_body "${httpresponse.transfer_encoding}"
			} <"${sslfifo.out}"
			
			wait || { print -u2 -f "%s: openssl failed.\n" ; exit 1 ; }
					
			return 0
		else
			redirect {netfd}<> "/dev/tcp/${host}/${port}"
			(( $? != 0 )) && { print -u2 -f "%s: Could not open %s\n" "$0" "${1}" ; return 1 ; }

			# send HTTP request    
			request="GET /${path} HTTP/1.1\r\n"
			request+="Host: ${host}\r\n"
			request+="User-Agent: crawlsrccomments/ksh93 (2010-03-27; $(uname -s -r -p))\r\n"
			request+="Connection: close\r\n"
			print -n -- "${request}\r\n" >&${netfd}
    
			# collect response and send it to stdout
			parse_http_response httpresponse <&${netfd}
			cat_http_body "${httpresponse.transfer_encoding}" <&${netfd}
    
			# close connection
			redirect {netfd}<&-
			
			return 0
		fi
	else
		return 1
	fi
	# notreached
}

function print_stats
{
	set -o errexit

	# gather some statistics
	compound stats=(
		integer files_with_comments=0
		integer files_without_comments=0

		integer files_without_known_format=0

		integer files_with_license_info=0
		integer files_without_license_info=0

		integer total_num_files=0
	)

	for i in $(printf "%s\n" "${!records[@]}" | sort) ; do
		if "${records[$i].comments_parsed}" ; then
			(( stats.files_with_comments++ ))
		else
			(( stats.files_without_comments++ ))
		fi

		if ! "${records[$i].fileformat_found}" ; then
			(( stats.files_without_known_format++ ))
		fi

		if "${records[$i].license_info_found}" ; then
			(( stats.files_with_license_info++ ))
		else
			(( stats.files_without_license_info++ ))
		fi

		(( stats.total_num_files++ ))
	done

	print -v stats
	return 0
}


function print_comments_plain
{
	set -o errexit
	
	nameref records=$1
	nameref options=$2
	typeset i j

	for i in $(printf "%s\n" "${!records[@]}" | sort) ; do
		nameref node=records[$i]
	
		if [[ "${options.filepattern.accept}" != "" ]] && \
		   [[ "${node.filename}" != ${options.filepattern.accept} ]] ; then
			continue
		fi
		if [[ "${options.filepattern.reject}" != "" ]] && \
		   [[ "${node.filename}" == ${options.filepattern.reject} ]] ; then
			continue
		fi

		node.license_info_found=false

		if ! "${node.comments_parsed}" ; then
			continue
		fi

		for j in "${!node.comments[@]}" ; do
			typeset s="${node.comments[$j]}"
			typeset match=false
		
			if [[ "${options.commentpattern.accept}" != "" ]] && \
		   	   [[ "$s" == ${options.commentpattern.accept} ]] ; then
				match=true
			fi
			if [[ "${options.commentpattern.reject}" != "" ]] && \
	  		   [[ "$s" == ${options.commentpattern.reject} ]] ; then
				match=false
			fi

			if "${match}" ; then
				printf "\f#### filename='%s',\tcomment=%s\n" "${node.filename}" "$j"
				printf "%s\n" "$s"
				node.license_info_found=true
			fi
		done
	
		if ! "${node.license_info_found}" ; then
			printf "## no match found in '%s'," "${node.filename}"
			printf "comments_parsed=%s, fileformat_found=%s, file_format=%s\n" \
				"${node.comments_parsed}" \
				"${node.fileformat_found}" \
				"${node.file_format}"
		fi
	done
	
	return 0
}

function print_comments_duplicates_compressed
{
	set -o errexit

	nameref records=$1
	nameref options=$2
	typeset i j
	typeset -A hashed_comments
	integer num_hashed_comments
	
	for i in $(printf "%s\n" "${!records[@]}" | sort) ; do
		nameref node=records[$i]
	
		if [[ "${options.filepattern.accept}" != "" ]] && \
		   [[ "${node.filename}" != ${options.filepattern.accept} ]] ; then
			continue
		fi
		if [[ "${options.filepattern.reject}" != "" ]] && \
		   [[ "${node.filename}" == ${options.filepattern.reject} ]] ; then
			continue
		fi

		node.license_info_found=false

		if ! "${node.comments_parsed}" ; then
			continue
		fi

		for j in "${!node.comments[@]}" ; do
			typeset s="${node.comments[$j]}"
			typeset match=false
		
			if [[ "${options.commentpattern.accept}" != "" ]] && \
		   	   [[ "$s" == ${options.commentpattern.accept} ]] ; then
				match=true
			fi
			if [[ "${options.commentpattern.reject}" != "" ]] && \
	  		   [[ "$s" == ${options.commentpattern.reject} ]] ; then
				match=false
			fi
			

			if "${match}" ; then
				typeset -l hashstring # lowercase

				# compress the comment (e.g. convert whiteapces and '.,:;()"' to newline characters) ...
				hashstring="${s//+([\n\r\t\v*#.,:;\(\)\"[:space:][:blank:]])/${ch.newline}}"
				# ... and then create a MD5 hash from this string
				hash="$(sum -x md5 <<<"${hashstring}")"

				nameref hc_node=hashed_comments[${hash}]

				if [[ "${hc_node}" == "" ]] ; then
					# build node if there isn't one yet
					typeset -a hc_node.fileids
					typeset    hc_node.comment="$s"
				fi
				
				hc_node.fileids+=( "$(printf "%s (md5='%s', sha1='%s')\n" "${node.filename}" "${node.hashsum["md5"]}" "${node.hashsum["sha1"]}")" )

				node.license_info_found=true
			fi
		done
	
		if ! "${node.license_info_found}" ; then
			printf "## no match found in " 
			printf "%s (md5='%s', sha1='%s'), " "${node.filename}" "${node.hashsum["md5"]}" "${node.hashsum["sha1"]}"
			printf "comments_parsed=%s, fileformat_found=%s, file_format=%s\n" \
				"${node.comments_parsed}" \
				"${node.fileformat_found}" \
				"${node.file_format}"
		fi
	done

	# print comments and all fileids (filename+hash sums) which include this comment
	for i in "${!hashed_comments[@]}" ; do
		printf "\f## The comment (ID=%s) ..." "${i}"
		printf "\n-- snip --"
		printf "\n%s" "${hashed_comments[${i}].comment}"
		printf "\n-- snip --"
		printf "\n... applies to the following files:\n"
		printf "\t%s\n" "${hashed_comments[${i}].fileids[@]}" # printf repeats the format string for each array memeber
	done
	
	return 0
}

function do_crawl
{
	set -o errexit

	compound options=(
		integer max_filesize_for_scan=$((256*1024))
		integer max_num_comments=$((2**62)) # FIXME: This should be "+Inf" (=Infinite)
	)

	shift
	while getopts -a "${progname}" "${do_crawl_usage}" OPT "$@" ; do 
		printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
		case ${OPT} in
			S)	options.max_filesize_for_scan="${OPTARG}"  ;;
			N)	options.max_num_comments="${OPTARG}"  ;;
			*)	usage do_crawl_usage ;;
		esac
	done
	shift $((OPTIND-1))
	
	compound scan=(
		typeset -A records
	)

	# read filenames from stdin
	while read i ; do
		printf "## scanning %s ...\n" "$i"
		extract_comments scan.records "$i" ${options.max_num_comments} ${options.max_filesize_for_scan} || true
	done

	# print compound variable array (we strip the "typeset -A records" for now)
	print -v scan >"crawlsrccomments_extracted_comments.cpv"
		
	print "# Wrote results to crawlsrccomments_extracted_comments.cpv"

	return 0
}

function do_getcomments
{
	set -o errexit

	# vars
	compound scan
	typeset database
	typeset tmp

	compound options=(
		typeset database="crawlsrccomments_extracted_comments.cpv"

		typeset print_stats=false
		typeset zapduplicates=false
		compound filepattern=(
			typeset accept="*"
			typeset reject=""
		)
		compound commentpattern=(
			typeset accept="~(Ei)(license|copyright)"
			typeset reject=""
		)
	)

	shift
	while getopts -a "${progname}" "${do_getcomments_usage}" OPT "$@" ; do 
	#    printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
		case ${OPT} in
			c)	options.commentpattern.accept="${OPTARG}" ;;
			C)	options.commentpattern.reject="${OPTARG}" ;;
			D)	options.database="${OPTARG}" ;;
			l)	options.filepattern.accept="${OPTARG}" ;;
			L)	options.filepattern.reject="${OPTARG}" ;;
			S)	options.print_stats=true ;;
			+S)	options.print_stats=false ;;
			Z)	options.zapduplicates=true ;;
			+Z)	options.zapduplicates=false ;;
			*)	usage do_getcomments_usage ;;
		esac
	done
	shift $((OPTIND-1))

	# array of temporary files which should be cleaned-up upon exit
	typeset -a tmpfiles
	trap 'set -o errexit ; print -u2 "# Cleaning up..." ; ((${#tmpfiles[@]} > 0)) && rm -- "${tmpfiles[@]}" ; print -u2 "# Done."' EXIT

	# Support for HTTP URLs
	if [[ "${options.database}" == ~(El)(http|https)://.* ]] ; then
		database="/tmp/extract_license_cat_url_${PPID}_$$.tmp"
		tmpfiles+=( "${database}" )
		print -u2 "# Loading URL..."
		cat_url "${options.database}" >"${database}"
		print -u2 "# Loading URL done."
	else
		database="${options.database}"
	fi

	if [[ ! -r "${database}" ]] ; then
		fatal_error "Can't read ${database}."
	fi

	# Support for compressed database files
	case "$(LC_ALL=C /usr/bin/file "${database}")" in
		*bzip2*) 
			tmp="/tmp/extract_license_bzcat_${PPID}_$$.tmp"
			tmpfiles+=( "${tmp}" )
			print -u2 "# Uncompressing data (bzip2) ..."
			bzcat <"${database}" >"${tmp}"
			print -u2 "# Uncompression done."
			database="${tmp}"
			;;
		*gzip*) 
			tmp="/tmp/extract_license_bzcat_${PPID}_$$.tmp"
			tmpfiles+=( "${tmp}" )
			print -u2 "# Uncompressing data (gzip) ..."
			gunzip -c <"${database}" >"${tmp}"
			print -u2 "# Uncompression done."
			database="${tmp}"
			;;
	esac

	# Read compound variable which contain all recorded comments
	print -u2 "# reading records..."
	read -C scan <"${database}" || fatal_error 'Error reading data.'
	print -u2 -f "# reading %d records done.\n" "${#scan.records[@]}"

	# print comments
	print -u2 "# processing data..."
	print "## comments start:"
	if "${options.zapduplicates}" ; then
		print_comments_duplicates_compressed scan.records options
	else
		print_comments_plain scan.records options
	fi
	print "## comments end"
	print -u2 "# processing data done."

	if "${options.print_stats}" ; then
		print_stats
	fi

	return 0
}

function usage
{
	nameref usagemsg=$1
	OPTIND=0
	getopts -a "${progname}" "${usagemsg}" OPT '-?'
	exit 2
}

typeset -r do_getcomments_usage=$'+
[-?\n@(#)\$Id: getcomments (Roland Mainz) 2010-03-27 \$\n]
[-author?Roland Mainz <roland.mainz@sun.com>]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?getcomments - extract license information from source files]
[+DESCRIPTION?\bgetcomments\b is a small utilty script which extracts
	license information from the "\bgetcomments\b"-database
	file created by \bcrawl\b. The script allows various
	filters (see options below) to be applied on the database]
[+?The license extraction is done in two steps - first a crawler script
	called \bcrawl\b will scan all source files, extract
	the comments and stores this information in a "database" file called
	"crawlsrccomments_extracted_comments.cpv" and then \bextract_license\b allows
	queries on this database.]
[D:database?Database file for input (either file, http:// or https://-URL).]:[database]
[l:acceptfilepattern?Process only files which match pattern.]:[pattern]
[L:rejectfilepattern?Process only files which do not match pattern.]:[pattern]
[c:acceptcommentpattern?Match comments which match pattern. Defaults to ~(Ei)(license|copyright)]:[pattern]
[C:rejectcommentpattern?Discard comments which match pattern. Defaults to ""]:[pattern]
[S:stats?Print statistics.]
[Z:zapsimilar?Combine similar/duplicate comments in the report.]
[+SEE ALSO?\bksh93\b(1), \bsvcprop\b(1)]
'

typeset -r do_crawl_usage=$'+
[-?\n@(#)\$Id: crawl (Roland Mainz) 2010-03-27 \$\n]
[-author?Roland Mainz <roland.mainz@sun.com>]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?crawl - crawl comment information from source files]
[+DESCRIPTION?\bcrawl\b is a small utilty script which reads
	a list of source code files from stdin, determinates the type of
	syntax used by these files and then extracts
	comments from the source code and stores this information into a
	"database"-like file called "crawlsrccomments_extracted_comments.cpv" which can then
	be processed by \bextract_license\b or similar processing tools.]
[S:scanmaxcharacters?Scan a maximum number of numchars characters for comments.
	Defaults to 256K characters.]:[numchars]
[N:maxnumcomments?Maximum numbers of comments to crawl. Defaults to "+Infinite"]:[numcomments]
[+SEE ALSO?\bksh93\b(1), \bsvcprop\b(1)]
'

typeset -r crawlsrccomments_usage=$'+
[-?\n@(#)\$Id: crawlsrccomments (Roland Mainz) 2010-03-27 \$\n]
[-author?Roland Mainz <roland.mainz@sun.com>]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?crawlsrccomments - extract and filter comment information from source files]
[+DESCRIPTION?\bcrawlsrccomments\b is a small utilty script which reads
	a list of source code files from stdin, determinates the type of
	syntax used by these files and then extracts
	comments from the source code and stores this information into a
	"database"-like file called "crawlsrccomments_extracted_comments.cpv" which can then
	be processed by \bextract_license\b or similar processing tools.]

[crawl|getcomments] options

[+SEE ALSO?\bksh93\b(1), \bsvcprop\b(1)]
'


# program start
builtin basename
builtin cat
builtin date
builtin uname
builtin rm
builtin sum || fatal_error "sum builtin not found."

# exit at the first error we hit
set -o errexit

typeset progname="${ basename "${0}" ; }"

while getopts -a "${progname}" "${crawlsrccomments_usage}" OPT ; do 
	# printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		*)	usage crawlsrccomments_usage ;;
	esac
done
shift $((OPTIND-1))

typeset cmd="$1"

case "$cmd" in
	"crawl")
		progname+=" ${cmd}"
		do_crawl "$@"
		exit $?
		;;
	"getcomments")
		progname+=" ${cmd}"
		do_getcomments "$@"
		exit $?
		;;
	*)
		usage crawlsrccomments_usage
		;;
esac

fatal_error "not reached."
# EOF.
