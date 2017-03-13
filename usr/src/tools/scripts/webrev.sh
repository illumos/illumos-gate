#!/usr/bin/ksh93 -p
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
# Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2008, 2010, Richard Lowe
# Copyright 2012 Marcel Telka <marcel@telka.sk>
# Copyright 2014 Bart Coddens <bart.coddens@gmail.com>
# Copyright 2017 Nexenta Systems, Inc.
# Copyright 2016 Joyent, Inc.
# Copyright 2016 RackTop Systems.
#

#
# This script takes a file list and a workspace and builds a set of html files
# suitable for doing a code review of source changes via a web page.
# Documentation is available via the manual page, webrev.1, or just
# type 'webrev -h'.
#
# Acknowledgements to contributors to webrev are listed in the webrev(1)
# man page.
#

REMOVED_COLOR=brown
CHANGED_COLOR=blue
NEW_COLOR=blue

HTML='<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">\n'

FRAMEHTML='<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Frameset//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-frameset.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">\n'

STDHEAD='<meta http-equiv="cache-control" content="no-cache"></meta>
<meta http-equiv="Content-Type" content="text/xhtml;charset=utf-8"></meta>
<meta http-equiv="Pragma" content="no-cache"></meta>
<meta http-equiv="Expires" content="-1"></meta>
<!--
   Note to customizers: the body of the webrev is IDed as SUNWwebrev
   to allow easy overriding by users of webrev via the userContent.css
   mechanism available in some browsers.

   For example, to have all "removed" information be red instead of
   brown, set a rule in your userContent.css file like:

       body#SUNWwebrev span.removed { color: red ! important; }
-->
<style type="text/css" media="screen">
body {
    background-color: #eeeeee;
}
hr {
    border: none 0;
    border-top: 1px solid #aaa;
    height: 1px;
}
div.summary {
    font-size: .8em;
    border-bottom: 1px solid #aaa;
    padding-left: 1em;
    padding-right: 1em;
}
div.summary h2 {
    margin-bottom: 0.3em;
}
div.summary table th {
    text-align: right;
    vertical-align: top;
    white-space: nowrap;
}
span.lineschanged {
    font-size: 0.7em;
}
span.oldmarker {
    color: red;
    font-size: large;
    font-weight: bold;
}
span.newmarker {
    color: green;
    font-size: large;
    font-weight: bold;
}
span.removed {
    color: brown;
}
span.changed {
    color: blue;
}
span.new {
    color: blue;
    font-weight: bold;
}
span.chmod {
    font-size: 0.7em;
    color: #db7800;
}
a.print { font-size: x-small; }
a:hover { background-color: #ffcc99; }
</style>

<style type="text/css" media="print">
pre { font-size: 0.8em; font-family: courier, monospace; }
span.removed { color: #444; font-style: italic }
span.changed { font-weight: bold; }
span.new { font-weight: bold; }
span.newmarker { font-size: 1.2em; font-weight: bold; }
span.oldmarker { font-size: 1.2em; font-weight: bold; }
a.print {display: none}
hr { border: none 0; border-top: 1px solid #aaa; height: 1px; }
</style>
'

#
# UDiffs need a slightly different CSS rule for 'new' items (we don't
# want them to be bolded as we do in cdiffs or sdiffs).
#
UDIFFCSS='
<style type="text/css" media="screen">
span.new {
    color: blue;
    font-weight: normal;
}
</style>
'

#
# CSS for the HTML version of the man pages.
#
MANCSS='
html { max-width: 880px; margin-left: 1em; }
body { font-size: smaller; font-family: Helvetica,Arial,sans-serif; }
h1 { margin-bottom: 1ex; font-size: 110%; margin-left: -4ex; }
h2 { margin-bottom: 1ex; font-size: 105%; margin-left: -2ex; }
table { width: 100%; margin-top: 0ex; margin-bottom: 0ex; }
td { vertical-align: top; }
blockquote { margin-left: 5ex; margin-top: 0ex; margin-bottom: 0ex; }
div.section { margin-bottom: 2ex; margin-left: 5ex; }
table.foot { font-size: smaller; margin-top: 1em;
    border-top: 1px dotted #dddddd; }
td.foot-date { width: 50%; }
td.foot-os { width: 50%; text-align: right; }
table.head { font-size: smaller; margin-bottom: 1em;
    border-bottom: 1px dotted #dddddd; }
td.head-ltitle { width: 10%; }
td.head-vol { width: 80%; text-align: center; }
td.head-rtitle { width: 10%; text-align: right; }
.emph { font-style: italic; font-weight: normal; }
.symb { font-style: normal; font-weight: bold; }
.lit { font-style: normal; font-weight: normal; font-family: monospace; }
i.addr { font-weight: normal; }
i.arg { font-weight: normal; }
b.cmd { font-style: normal; }
b.config { font-style: normal; }
b.diag { font-style: normal; }
i.farg { font-weight: normal; }
i.file { font-weight: normal; }
b.flag { font-style: normal; }
b.fname { font-style: normal; }
i.ftype { font-weight: normal; }
b.includes { font-style: normal; }
i.link-sec { font-weight: normal; }
b.macro { font-style: normal; }
b.name { font-style: normal; }
i.ref-book { font-weight: normal; }
i.ref-issue { font-weight: normal; }
i.ref-jrnl { font-weight: normal; }
span.ref-title { text-decoration: underline; }
span.type { font-style: italic; font-weight: normal; }
b.utility { font-style: normal; }
b.var { font-style: normal; }
dd.list-ohang { margin-left: 0ex; }
ul.list-bul { list-style-type: disc; padding-left: 1em; }
ul.list-dash { list-style-type: none; padding-left: 0em; }
li.list-dash:before { content: "\2014  "; }
ul.list-hyph { list-style-type: none; padding-left: 0em; }
li.list-hyph:before { content: "\2013  "; }
ul.list-item { list-style-type: none; padding-left: 0em; }
ol.list-enum { padding-left: 2em; }
'

#
# Display remote target with prefix and trailing slash.
#
function print_upload_header
{
	typeset -r prefix=$1
	typeset display_target

	if [[ -z $tflag ]]; then
		display_target=${prefix}${remote_target}
	else
		display_target=${remote_target}
	fi

	if [[ ${display_target} != */ ]]; then
		display_target=${display_target}/
	fi

	print "      Upload to: ${display_target}\n" \
	    "     Uploading: \c"
}

#
# Upload the webrev via rsync. Return 0 on success, 1 on error.
#
function rsync_upload
{
	if (( $# != 2 )); then
		print "\nERROR: rsync_upload: wrong usage ($#)"
		exit 1
	fi

	typeset -r dst=$1
	integer -r print_err_msg=$2

	print_upload_header ${rsync_prefix}
	print "rsync ... \c"
	typeset -r err_msg=$( $MKTEMP /tmp/rsync_err.XXXXXX )
	if [[ -z $err_msg ]]; then
		print "\nERROR: rsync_upload: cannot create temporary file"
		return 1
	fi
	#
	# The source directory must end with a slash in order to copy just
	# directory contents, not the whole directory.
	#
	typeset src_dir=$WDIR
	if [[ ${src_dir} != */ ]]; then
		src_dir=${src_dir}/
	fi
	$RSYNC -r -q ${src_dir} $dst 2>$err_msg
	if (( $? != 0 )); then
		if (( ${print_err_msg} > 0 )); then
			print "Failed.\nERROR: rsync failed"
			print "src dir: '${src_dir}'\ndst dir: '$dst'"
			print "error messages:"
			$SED 's/^/> /' $err_msg
			rm -f $err_msg
		fi
		return 1
	fi

	rm -f $err_msg
	print "Done."
	return 0
}

#
# Create directories on remote host using SFTP. Return 0 on success,
# 1 on failure.
#
function remote_mkdirs
{
	typeset -r dir_spec=$1
	typeset -r host_spec=$2

	#
	# If the supplied path is absolute we assume all directories are
	# created, otherwise try to create all directories in the path
	# except the last one which will be created by scp.
	#
	if [[ "${dir_spec}" == */* && "${dir_spec}" != /* ]]; then
		print "mkdirs \c"
		#
		# Remove the last directory from directory specification.
		#
		typeset -r dirs_mk=${dir_spec%/*}
		typeset -r batch_file_mkdir=$( $MKTEMP \
		    /tmp/webrev_mkdir.XXXXXX )
		if [[ -z $batch_file_mkdir ]]; then
			print "\nERROR: remote_mkdirs:" \
			    "cannot create temporary file for batch file"
			return 1
		fi
		OLDIFS=$IFS
		IFS=/
		typeset dir
		for dir in ${dirs_mk}; do
			#
			# Use the '-' prefix to ignore mkdir errors in order
			# to avoid an error in case the directory already
			# exists. We check the directory with chdir to be sure
			# there is one.
			#
			print -- "-mkdir ${dir}" >> ${batch_file_mkdir}
			print "chdir ${dir}" >> ${batch_file_mkdir}
		done
		IFS=$OLDIFS
		typeset -r sftp_err_msg=$( $MKTEMP /tmp/webrev_scp_err.XXXXXX )
		if [[ -z ${sftp_err_msg} ]]; then
			print "\nERROR: remote_mkdirs:" \
			    "cannot create temporary file for error messages"
			return 1
		fi
		$SFTP -b ${batch_file_mkdir} ${host_spec} 2>${sftp_err_msg} 1>&2
		if (( $? != 0 )); then
			print "\nERROR: failed to create remote directories"
			print "error messages:"
			$SED 's/^/> /' ${sftp_err_msg}
			rm -f ${sftp_err_msg} ${batch_file_mkdir}
			return 1
		fi
		rm -f ${sftp_err_msg} ${batch_file_mkdir}
	fi

	return 0
}

#
# Upload the webrev via SSH. Return 0 on success, 1 on error.
#
function ssh_upload
{
	if (( $# != 1 )); then
		print "\nERROR: ssh_upload: wrong number of arguments"
		exit 1
	fi

	typeset dst=$1
	typeset -r host_spec=${dst%%:*}
	typeset -r dir_spec=${dst#*:}

	#
	# Display the upload information before calling delete_webrev
	# because it will also print its progress.
	#
	print_upload_header ${ssh_prefix}

	#
	# If the deletion was explicitly requested there is no need
	# to perform it again.
	#
	if [[ -z $Dflag ]]; then
		#
		# We do not care about return value because this might be
		# the first time this directory is uploaded.
		#
		delete_webrev 0
	fi

	#
	# Create remote directories. Any error reporting will be done
	# in remote_mkdirs function.
	#
	remote_mkdirs ${dir_spec} ${host_spec}
	if (( $? != 0 )); then
		return 1
	fi

	print "upload ... \c"
	typeset -r scp_err_msg=$( $MKTEMP /tmp/scp_err.XXXXXX )
	if [[ -z ${scp_err_msg} ]]; then
		print "\nERROR: ssh_upload:" \
		    "cannot create temporary file for error messages"
		return 1
	fi
	$SCP -q -C -B -o PreferredAuthentications=publickey -r \
		$WDIR $dst 2>${scp_err_msg}
	if (( $? != 0 )); then
		print "Failed.\nERROR: scp failed"
		print "src dir: '$WDIR'\ndst dir: '$dst'"
		print "error messages:"
		$SED 's/^/> /' ${scp_err_msg}
		rm -f ${scp_err_msg}
		return 1
	fi

	rm -f ${scp_err_msg}
	print "Done."
	return 0
}

#
# Delete webrev at remote site. Return 0 on success, 1 or exit code from sftp
# on failure. If first argument is 1 then perform the check of sftp return
# value otherwise ignore it. If second argument is present it means this run
# only performs deletion.
#
function delete_webrev
{
	if (( $# < 1 )); then
		print "delete_webrev: wrong number of arguments"
		exit 1
	fi

	integer -r check=$1
	integer delete_only=0
	if (( $# == 2 )); then
		delete_only=1
	fi

	#
	# Strip the transport specification part of remote target first.
	#
	typeset -r stripped_target=${remote_target##*://}
	typeset -r host_spec=${stripped_target%%:*}
	typeset -r dir_spec=${stripped_target#*:}
	typeset dir_rm

	#
	# Do not accept an absolute path.
	#
	if [[ ${dir_spec} == /* ]]; then
		return 1
	fi

	#
	# Strip the ending slash.
	#
	if [[ ${dir_spec} == */ ]]; then
		dir_rm=${dir_spec%%/}
	else
		dir_rm=${dir_spec}
	fi

	if (( ${delete_only} > 0 )); then
		print "       Removing: \c"
	else
		print "rmdir \c"
	fi
	if [[ -z "$dir_rm" ]]; then
		print "\nERROR: empty directory for removal"
		return 1
	fi

	#
	# Prepare batch file.
	#
	typeset -r batch_file_rm=$( $MKTEMP /tmp/webrev_remove.XXXXXX )
	if [[ -z $batch_file_rm ]]; then
		print "\nERROR: delete_webrev: cannot create temporary file"
		return 1
	fi
	print "rename $dir_rm $TRASH_DIR/removed.$$" > $batch_file_rm

	#
	# Perform remote deletion and remove the batch file.
	#
	typeset -r sftp_err_msg=$( $MKTEMP /tmp/webrev_scp_err.XXXXXX )
	if [[ -z ${sftp_err_msg} ]]; then
		print "\nERROR: delete_webrev:" \
		    "cannot create temporary file for error messages"
		return 1
	fi
	$SFTP -b $batch_file_rm $host_spec 2>${sftp_err_msg} 1>&2
	integer -r ret=$?
	rm -f $batch_file_rm
	if (( $ret != 0 && $check > 0 )); then
		print "Failed.\nERROR: failed to remove remote directories"
		print "error messages:"
		$SED 's/^/> /' ${sftp_err_msg}
		rm -f ${sftp_err_msg}
		return $ret
	fi
	rm -f ${sftp_err_msg}
	if (( ${delete_only} > 0 )); then
		print "Done."
	fi

	return 0
}

#
# Upload webrev to remote site
#
function upload_webrev
{
	integer ret

	if [[ ! -d "$WDIR" ]]; then
		print "\nERROR: webrev directory '$WDIR' does not exist"
		return 1
	fi

	#
	# Perform a late check to make sure we do not upload closed source
	# to remote target when -n is used. If the user used custom remote
	# target he probably knows what he is doing.
	#
	if [[ -n $nflag && -z $tflag ]]; then
		$FIND $WDIR -type d -name closed \
			| $GREP closed >/dev/null
		if (( $? == 0 )); then
			print "\nERROR: directory '$WDIR' contains" \
			    "\"closed\" directory"
			return 1
		fi
	fi


	#
	# We have the URI for remote destination now so let's start the upload.
	#
	if [[ -n $tflag ]]; then
		if [[ "${remote_target}" == ${rsync_prefix}?* ]]; then
			rsync_upload ${remote_target##$rsync_prefix} 1
			ret=$?
			return $ret
		elif [[ "${remote_target}" == ${ssh_prefix}?* ]]; then
			ssh_upload ${remote_target##$ssh_prefix}
			ret=$?
			return $ret
		fi
	else
		#
		# Try rsync first and fallback to SSH in case it fails.
		#
		rsync_upload ${remote_target} 0
		ret=$?
		if (( $ret != 0 )); then
			print "Failed. (falling back to SSH)"
			ssh_upload ${remote_target}
			ret=$?
		fi
		return $ret
	fi
}

#
# input_cmd | url_encode | output_cmd
#
# URL-encode (percent-encode) reserved characters as defined in RFC 3986.
#
# Reserved characters are: :/?#[]@!$&'()*+,;=
#
# While not a reserved character itself, percent '%' is reserved by definition
# so encode it first to avoid recursive transformation, and skip '/' which is
# a path delimiter.
#
# The quotation character is deliberately not escaped in order to make
# the substitution work with GNU sed.
#
function url_encode
{
	$SED -e "s|%|%25|g" -e "s|:|%3A|g" -e "s|\&|%26|g" \
	    -e "s|?|%3F|g" -e "s|#|%23|g" -e "s|\[|%5B|g" \
	    -e "s|*|%2A|g" -e "s|@|%40|g" -e "s|\!|%21|g" \
	    -e "s|=|%3D|g" -e "s|;|%3B|g" -e "s|\]|%5D|g" \
	    -e "s|(|%28|g" -e "s|)|%29|g" -e "s|'|%27|g" \
	    -e "s|+|%2B|g" -e "s|\,|%2C|g" -e "s|\\\$|%24|g"
}

#
# input_cmd | html_quote | output_cmd
# or
# html_quote filename | output_cmd
#
# Make a piece of source code safe for display in an HTML <pre> block.
#
html_quote()
{
	$SED -e "s/&/\&amp;/g" -e "s/</\&lt;/g" -e "s/>/\&gt;/g" "$@" | expand
}

# 
# Trim a digest-style revision to a conventionally readable yet useful length
#
trim_digest()
{
	typeset digest=$1

	echo $digest | $SED -e 's/\([0-9a-f]\{12\}\).*/\1/'
}

#
# input_cmd | its2url | output_cmd
#
# Scan for information tracking system references and insert <a> links to the
# relevant databases.
#
its2url()
{
	$SED -f ${its_sed_script}
}

#
# strip_unchanged <infile> | output_cmd
#
# Removes chunks of sdiff documents that have not changed. This makes it
# easier for a code reviewer to find the bits that have changed.
#
# Deleted lines of text are replaced by a horizontal rule. Some
# identical lines are retained before and after the changed lines to
# provide some context.  The number of these lines is controlled by the
# variable C in the $AWK script below.
#
# The script detects changed lines as any line that has a "<span class="
# string embedded (unchanged lines have no particular class and are not
# part of a <span>).  Blank lines (without a sequence number) are also
# detected since they flag lines that have been inserted or deleted.
#
strip_unchanged()
{
	$AWK '
	BEGIN	{ C = c = 20 }
	NF == 0 || /<span class="/ {
		if (c > C) {
			c -= C
			inx = 0
			if (c > C) {
				print "\n</pre><hr></hr><pre>"
				inx = c % C
				c = C
			}

			for (i = 0; i < c; i++)
				print ln[(inx + i) % C]
		}
		c = 0;
		print
		next
	}
	{	if (c >= C) {
			ln[c % C] = $0
			c++;
			next;
		}
		c++;
		print
	}
	END	{ if (c > (C * 2)) print "\n</pre><hr></hr>" }

	' $1
}

#
# sdiff_to_html
#
# This function takes two files as arguments, obtains their diff, and
# processes the diff output to present the files as an HTML document with
# the files displayed side-by-side, differences shown in color.  It also
# takes a delta comment, rendered as an HTML snippet, as the third
# argument.  The function takes two files as arguments, then the name of
# file, the path, and the comment.  The HTML will be delivered on stdout,
# e.g.
#
#   $ sdiff_to_html old/usr/src/tools/scripts/webrev.sh \
#         new/usr/src/tools/scripts/webrev.sh \
#         webrev.sh usr/src/tools/scripts \
#         '<a href="http://monaco.sfbay.sun.com/detail.jsp?cr=1234567">
#          1234567</a> my bugid' > <file>.html
#
# framed_sdiff() is then called which creates $2.frames.html
# in the webrev tree.
#
# FYI: This function is rather unusual in its use of awk.  The initial
# diff run produces conventional diff output showing changed lines mixed
# with editing codes.  The changed lines are ignored - we're interested in
# the editing codes, e.g.
#
#      8c8
#      57a61
#      63c66,76
#      68,93d80
#      106d90
#      108,110d91
#
#  These editing codes are parsed by the awk script and used to generate
#  another awk script that generates HTML, e.g the above lines would turn
#  into something like this:
#
#      BEGIN { printf "<pre>\n" }
#      function sp(n) {for (i=0;i<n;i++)printf "\n"}
#      function wl(n) {printf "<font color=%s>%4d %s </font>\n", n, NR, $0}
#      NR==8           {wl("#7A7ADD");next}
#      NR==54          {wl("#7A7ADD");sp(3);next}
#      NR==56          {wl("#7A7ADD");next}
#      NR==57          {wl("black");printf "\n"; next}
#        :               :
#
#  This script is then run on the original source file to generate the
#  HTML that corresponds to the source file.
#
#  The two HTML files are then combined into a single piece of HTML that
#  uses an HTML table construct to present the files side by side.  You'll
#  notice that the changes are color-coded:
#
#   black     - unchanged lines
#   blue      - changed lines
#   bold blue - new lines
#   brown     - deleted lines
#
#  Blank lines are inserted in each file to keep unchanged lines in sync
#  (side-by-side).  This format is familiar to users of sdiff(1) or
#  Teamware's filemerge tool.
#
sdiff_to_html()
{
	diff -b $1 $2 > /tmp/$$.diffs

	TNAME=$3
	TPATH=$4
	COMMENT=$5

	#
	#  Now we have the diffs, generate the HTML for the old file.
	#
	$AWK '
	BEGIN	{
		printf "function sp(n) {for (i=0;i<n;i++)printf \"\\n\"}\n"
		printf "function removed() "
		printf "{printf \"<span class=\\\"removed\\\">%%4d %%s</span>\\n\", NR, $0}\n"
		printf "function changed() "
		printf "{printf \"<span class=\\\"changed\\\">%%4d %%s</span>\\n\", NR, $0}\n"
		printf "function bl() {printf \"%%4d %%s\\n\", NR, $0}\n"
}
	/^</	{next}
	/^>/	{next}
	/^---/	{next}

	{
	split($1, a, /[cad]/) ;
	if (index($1, "a")) {
		if (a[1] == 0) {
			n = split(a[2], r, /,/);
			if (n == 1)
				printf "BEGIN\t\t{sp(1)}\n"
			else
				printf "BEGIN\t\t{sp(%d)}\n",\
				(r[2] - r[1]) + 1
			next
		}

		printf "NR==%s\t\t{", a[1]
		n = split(a[2], r, /,/);
		s = r[1];
		if (n == 1)
			printf "bl();printf \"\\n\"; next}\n"
		else {
			n = r[2] - r[1]
			printf "bl();sp(%d);next}\n",\
			(r[2] - r[1]) + 1
		}
		next
	}
	if (index($1, "d")) {
		n = split(a[1], r, /,/);
		n1 = r[1]
		n2 = r[2]
		if (n == 1)
			printf "NR==%s\t\t{removed(); next}\n" , n1
		else
			printf "NR==%s,NR==%s\t{removed(); next}\n" , n1, n2
		next
	}
	if (index($1, "c")) {
		n = split(a[1], r, /,/);
		n1 = r[1]
		n2 = r[2]
		final = n2
		d1 = 0
		if (n == 1)
			printf "NR==%s\t\t{changed();" , n1
		else {
			d1 = n2 - n1
			printf "NR==%s,NR==%s\t{changed();" , n1, n2
		}
		m = split(a[2], r, /,/);
		n1 = r[1]
		n2 = r[2]
		if (m > 1) {
			d2  = n2 - n1
			if (d2 > d1) {
				if (n > 1) printf "if (NR==%d)", final
				printf "sp(%d);", d2 - d1
			}
		}
		printf "next}\n" ;

		next
	}
	}

	END	{ printf "{printf \"%%4d %%s\\n\", NR, $0 }\n" }
	' /tmp/$$.diffs > /tmp/$$.file1

	#
	#  Now generate the HTML for the new file
	#
	$AWK '
	BEGIN	{
		printf "function sp(n) {for (i=0;i<n;i++)printf \"\\n\"}\n"
		printf "function new() "
		printf "{printf \"<span class=\\\"new\\\">%%4d %%s</span>\\n\", NR, $0}\n"
		printf "function changed() "
		printf "{printf \"<span class=\\\"changed\\\">%%4d %%s</span>\\n\", NR, $0}\n"
		printf "function bl() {printf \"%%4d %%s\\n\", NR, $0}\n"
	}

	/^</	{next}
	/^>/	{next}
	/^---/	{next}

	{
	split($1, a, /[cad]/) ;
	if (index($1, "d")) {
		if (a[2] == 0) {
			n = split(a[1], r, /,/);
			if (n == 1)
				printf "BEGIN\t\t{sp(1)}\n"
			else
				printf "BEGIN\t\t{sp(%d)}\n",\
				(r[2] - r[1]) + 1
			next
		}

		printf "NR==%s\t\t{", a[2]
		n = split(a[1], r, /,/);
		s = r[1];
		if (n == 1)
			printf "bl();printf \"\\n\"; next}\n"
		else {
			n = r[2] - r[1]
			printf "bl();sp(%d);next}\n",\
			(r[2] - r[1]) + 1
		}
		next
	}
	if (index($1, "a")) {
		n = split(a[2], r, /,/);
		n1 = r[1]
		n2 = r[2]
		if (n == 1)
			printf "NR==%s\t\t{new() ; next}\n" , n1
		else
			printf "NR==%s,NR==%s\t{new() ; next}\n" , n1, n2
		next
	}
	if (index($1, "c")) {
		n = split(a[2], r, /,/);
		n1 = r[1]
		n2 = r[2]
		final = n2
		d2 = 0;
		if (n == 1) {
			final = n1
			printf "NR==%s\t\t{changed();" , n1
		} else {
			d2 = n2 - n1
			printf "NR==%s,NR==%s\t{changed();" , n1, n2
		}
		m = split(a[1], r, /,/);
		n1 = r[1]
		n2 = r[2]
		if (m > 1) {
			d1  = n2 - n1
			if (d1 > d2) {
				if (n > 1) printf "if (NR==%d)", final
				printf "sp(%d);", d1 - d2
			}
		}
		printf "next}\n" ;
		next
	}
	}
	END	{ printf "{printf \"%%4d %%s\\n\", NR, $0 }\n" }
	' /tmp/$$.diffs > /tmp/$$.file2

	#
	# Post-process the HTML files by running them back through $AWK
	#
	html_quote < $1 | $AWK -f /tmp/$$.file1 > /tmp/$$.file1.html

	html_quote < $2 | $AWK -f /tmp/$$.file2 > /tmp/$$.file2.html

	#
	# Now combine into a valid HTML file and side-by-side into a table
	#
	print "$HTML<head>$STDHEAD"
	print "<title>$WNAME Sdiff $TPATH/$TNAME</title>"
	print "</head><body id=\"SUNWwebrev\">"
	print "<a class=\"print\" href=\"javascript:print()\">Print this page</a>"
	print "<pre>$COMMENT</pre>\n"
	print "<table><tr valign=\"top\">"
	print "<td><pre>"

	strip_unchanged /tmp/$$.file1.html

	print "</pre></td><td><pre>"

	strip_unchanged /tmp/$$.file2.html

	print "</pre></td>"
	print "</tr></table>"
	print "</body></html>"

	framed_sdiff $TNAME $TPATH /tmp/$$.file1.html /tmp/$$.file2.html \
	    "$COMMENT"
}


#
# framed_sdiff <filename> <filepath> <lhsfile> <rhsfile> <comment>
#
# Expects lefthand and righthand side html files created by sdiff_to_html.
# We use insert_anchors() to augment those with HTML navigation anchors,
# and then emit the main frame.  Content is placed into:
#
#    $WDIR/DIR/$TNAME.lhs.html
#    $WDIR/DIR/$TNAME.rhs.html
#    $WDIR/DIR/$TNAME.frames.html
#
# NOTE: We rely on standard usage of $WDIR and $DIR.
#
function framed_sdiff
{
	typeset TNAME=$1
	typeset TPATH=$2
	typeset lhsfile=$3
	typeset rhsfile=$4
	typeset comments=$5
	typeset RTOP

	# Enable html files to access WDIR via a relative path.
	RTOP=$(relative_dir $TPATH $WDIR)

	# Make the rhs/lhs files and output the frameset file.
	print "$HTML<head>$STDHEAD" > $WDIR/$DIR/$TNAME.lhs.html

	cat >> $WDIR/$DIR/$TNAME.lhs.html <<-EOF
	    <script type="text/javascript" src="${RTOP}ancnav.js"></script>
	    </head>
	    <body id="SUNWwebrev" onkeypress="keypress(event);">
	    <a name="0"></a>
	    <pre>$comments</pre><hr></hr>
	EOF

	cp $WDIR/$DIR/$TNAME.lhs.html $WDIR/$DIR/$TNAME.rhs.html

	insert_anchors $lhsfile >> $WDIR/$DIR/$TNAME.lhs.html
	insert_anchors $rhsfile >> $WDIR/$DIR/$TNAME.rhs.html

	close='</body></html>'

	print $close >> $WDIR/$DIR/$TNAME.lhs.html
	print $close >> $WDIR/$DIR/$TNAME.rhs.html

	print "$FRAMEHTML<head>$STDHEAD" > $WDIR/$DIR/$TNAME.frames.html
	print "<title>$WNAME Framed-Sdiff " \
	    "$TPATH/$TNAME</title> </head>" >> $WDIR/$DIR/$TNAME.frames.html
	cat >> $WDIR/$DIR/$TNAME.frames.html <<-EOF
	  <frameset rows="*,60">
	    <frameset cols="50%,50%">
	      <frame src="$TNAME.lhs.html" scrolling="auto" name="lhs"></frame>
	      <frame src="$TNAME.rhs.html" scrolling="auto" name="rhs"></frame>
	    </frameset>
	  <frame src="${RTOP}ancnav.html" scrolling="no" marginwidth="0"
	   marginheight="0" name="nav"></frame>
	  <noframes>
	    <body id="SUNWwebrev">
	      Alas 'frames' webrev requires that your browser supports frames
	      and has the feature enabled.
	    </body>
	  </noframes>
	  </frameset>
	</html>
	EOF
}


#
# fix_postscript
#
# Merge codereview output files to a single conforming postscript file, by:
#	- removing all extraneous headers/trailers
#	- making the page numbers right
#	- removing pages devoid of contents which confuse some
#	  postscript readers.
#
# From Casper.
#
function fix_postscript
{
	infile=$1

	cat > /tmp/$$.crmerge.pl << \EOF

	print scalar(<>);		# %!PS-Adobe---
	print "%%Orientation: Landscape\n";

	$pno = 0;
	$doprint = 1;

	$page = "";

	while (<>) {
		next if (/^%%Pages:\s*\d+/);

		if (/^%%Page:/) {
			if ($pno == 0 || $page =~ /\)S/) {
				# Header or single page containing text
				print "%%Page: ? $pno\n" if ($pno > 0);
				print $page;
				$pno++;
			} else {
				# Empty page, skip it.
			}
			$page = "";
			$doprint = 1;
			next;
		}

		# Skip from %%Trailer of one document to Endprolog
		# %%Page of the next
		$doprint = 0 if (/^%%Trailer/);
		$page .= $_ if ($doprint);
	}

	if ($page =~ /\)S/) {
		print "%%Page: ? $pno\n";
		print $page;
	} else {
		$pno--;
	}
	print "%%Trailer\n%%Pages: $pno\n";
EOF

	$PERL /tmp/$$.crmerge.pl < $infile
}


#
# input_cmd | insert_anchors | output_cmd
#
# Flag blocks of difference with sequentially numbered invisible
# anchors.  These are used to drive the frames version of the
# sdiffs output.
#
# NOTE: Anchor zero flags the top of the file irrespective of changes,
# an additional anchor is also appended to flag the bottom.
#
# The script detects changed lines as any line that has a "<span
# class=" string embedded (unchanged lines have no class set and are
# not part of a <span>.  Blank lines (without a sequence number)
# are also detected since they flag lines that have been inserted or
# deleted.
#
function insert_anchors
{
	$AWK '
	function ia() {
		printf "<a name=\"%d\" id=\"anc%d\"></a>", anc, anc++;
	}

	BEGIN {
		anc=1;
		inblock=1;
		printf "<pre>\n";
	}
	NF == 0 || /^<span class=/ {
		if (inblock == 0) {
			ia();
			inblock=1;
		}
		print;
		next;
	}
	{
		inblock=0;
		print;
	}
	END {
		ia();

		printf "<b style=\"font-size: large; color: red\">";
		printf "--- EOF ---</b>"
		for(i=0;i<8;i++) printf "\n\n\n\n\n\n\n\n\n\n";
		printf "</pre>"
		printf "<form name=\"eof\">";
		printf "<input name=\"value\" value=\"%d\" " \
		    "type=\"hidden\"></input>", anc - 1;
		printf "</form>";
	}
	' $1
}


#
# relative_dir
#
# Print a relative return path from $1 to $2.  For example if
# $1=/tmp/myreview/raw_files/usr/src/tools/scripts and $2=/tmp/myreview,
# this function would print "../../../../".
#
# In the event that $1 is not in $2 a warning is printed to stderr,
# and $2 is returned-- the result of this is that the resulting webrev
# is not relocatable.
#
function relative_dir
{
	typeset cur="${1##$2?(/)}"

	#
	# If the first path was specified absolutely, and it does
	# not start with the second path, it's an error.
	#
	if [[ "$cur" = "/${1#/}" ]]; then
		# Should never happen.
		print -u2 "\nWARNING: relative_dir: \"$1\" not relative "
		print -u2 "to \"$2\".  Check input paths.  Framed webrev "
		print -u2 "will not be relocatable!"
		print $2
		return
	fi

	#
	# This is kind of ugly.  The sed script will do the following:
	#
	# 1. Strip off a leading "." or "./": this is important to get
	#    the correct arcnav links for files in $WDIR.
	# 2. Strip off a trailing "/": this is not strictly necessary,
	#    but is kind of nice, since it doesn't end up in "//" at
	#    the end of a relative path.
	# 3. Replace all remaining sequences of non-"/" with "..": the
	#    assumption here is that each dirname represents another
	#    level of relative separation.
	# 4. Append a trailing "/" only for non-empty paths: this way
	#    the caller doesn't need to duplicate this logic, and does
	#    not end up using $RTOP/file for files in $WDIR.
	#
	print $cur | $SED -e '{
		s:^\./*::
		s:/$::
		s:[^/][^/]*:..:g
		s:^\(..*\)$:\1/:
	}'
}

#
# frame_nav_js
#
# Emit javascript for frame navigation
#
function frame_nav_js
{
cat << \EOF
var myInt;
var scrolling = 0;
var sfactor = 3;
var scount = 10;

function scrollByPix()
{
	if (scount <= 0) {
		sfactor *= 1.2;
		scount = 10;
	}
	parent.lhs.scrollBy(0, sfactor);
	parent.rhs.scrollBy(0, sfactor);
	scount--;
}

function scrollToAnc(num)
{
	// Update the value of the anchor in the form which we use as
	// storage for this value.  setAncValue() will take care of
	// correcting for overflow and underflow of the value and return
	// us the new value.
	num = setAncValue(num);

	// Set location and scroll back a little to expose previous
	// lines.
	//
	// Note that this could be improved: it is possible although
	// complex to compute the x and y position of an anchor, and to
	// scroll to that location directly.
	//
	parent.lhs.location.replace(parent.lhs.location.pathname + "#" + num);
	parent.rhs.location.replace(parent.rhs.location.pathname + "#" + num);

	parent.lhs.scrollBy(0, -30);
	parent.rhs.scrollBy(0, -30);
}

function getAncValue()
{
	return (parseInt(parent.nav.document.diff.real.value));
}

function setAncValue(val)
{
	if (val <= 0) {
		val = 0;
		parent.nav.document.diff.real.value = val;
		parent.nav.document.diff.display.value = "BOF";
		return (val);
	}

	//
	// The way we compute the max anchor value is to stash it
	// inline in the left and right hand side pages-- it's the same
	// on each side, so we pluck from the left.
	//
	maxval = parent.lhs.document.eof.value.value;
	if (val < maxval) {
		parent.nav.document.diff.real.value = val;
		parent.nav.document.diff.display.value = val.toString();
		return (val);
	}

	// this must be: val >= maxval
	val = maxval;
	parent.nav.document.diff.real.value = val;
	parent.nav.document.diff.display.value = "EOF";
	return (val);
}

function stopScroll()
{
	if (scrolling == 1) {
		clearInterval(myInt);
		scrolling = 0;
	}
}

function startScroll()
{
	stopScroll();
	scrolling = 1;
	myInt = setInterval("scrollByPix()", 10);
}

function handlePress(b)
{
	switch (b) {
	case 1:
		scrollToAnc(-1);
		break;
	case 2:
		scrollToAnc(getAncValue() - 1);
		break;
	case 3:
		sfactor = -3;
		startScroll();
		break;
	case 4:
		sfactor = 3;
		startScroll();
		break;
	case 5:
		scrollToAnc(getAncValue() + 1);
		break;
	case 6:
		scrollToAnc(999999);
		break;
	}
}

function handleRelease(b)
{
	stopScroll();
}

function keypress(ev)
{
	var keynum;
	var keychar;

	if (window.event) { // IE
		keynum = ev.keyCode;
	} else if (ev.which) { // non-IE
		keynum = ev.which;
	}

	keychar = String.fromCharCode(keynum);

	if (keychar == "k") {
		handlePress(2);
		return (0);
	} else if (keychar == "j" || keychar == " ") {
		handlePress(5);
		return (0);
	}

	return (1);
}

function ValidateDiffNum()
{
	var val;
	var i;

	val = parent.nav.document.diff.display.value;
	if (val == "EOF") {
		scrollToAnc(999999);
		return;
	}

	if (val == "BOF") {
		scrollToAnc(0);
		return;
	}

	i = parseInt(val);
	if (isNaN(i)) {
		parent.nav.document.diff.display.value = getAncValue();
	} else {
		scrollToAnc(i);
	}

	return (false);
}
EOF
}

#
# frame_navigation
#
# Output anchor navigation file for framed sdiffs.
#
function frame_navigation
{
	print "$HTML<head>$STDHEAD"

	cat << \EOF
<title>Anchor Navigation</title>
<meta http-equiv="Content-Script-Type" content="text/javascript">
<meta http-equiv="Content-Type" content="text/html">

<style type="text/css">
    div.button td { padding-left: 5px; padding-right: 5px;
		    background-color: #eee; text-align: center;
		    border: 1px #444 outset; cursor: pointer; }
    div.button a { font-weight: bold; color: black }
    div.button td:hover { background: #ffcc99; }
</style>
EOF

	print "<script type=\"text/javascript\" src=\"ancnav.js\"></script>"

	cat << \EOF
</head>
<body id="SUNWwebrev" bgcolor="#eeeeee" onload="document.diff.real.focus();"
	onkeypress="keypress(event);">
    <noscript lang="javascript">
      <center>
	<p><big>Framed Navigation controls require Javascript</big><br></br>
	Either this browser is incompatable or javascript is not enabled</p>
      </center>
    </noscript>
    <table width="100%" border="0" align="center">
	<tr>
          <td valign="middle" width="25%">Diff navigation:
          Use 'j' and 'k' for next and previous diffs; or use buttons
          at right</td>
	  <td align="center" valign="top" width="50%">
	    <div class="button">
	      <table border="0" align="center">
                  <tr>
		    <td>
		      <a onMouseDown="handlePress(1);return true;"
			 onMouseUp="handleRelease(1);return true;"
			 onMouseOut="handleRelease(1);return true;"
			 onClick="return false;"
			 title="Go to Beginning Of file">BOF</a></td>
		    <td>
		      <a onMouseDown="handlePress(3);return true;"
			 onMouseUp="handleRelease(3);return true;"
			 onMouseOut="handleRelease(3);return true;"
			 title="Scroll Up: Press and Hold to accelerate"
			 onClick="return false;">Scroll Up</a></td>
		    <td>
		      <a onMouseDown="handlePress(2);return true;"
			 onMouseUp="handleRelease(2);return true;"
			 onMouseOut="handleRelease(2);return true;"
			 title="Go to previous Diff"
			 onClick="return false;">Prev Diff</a>
		    </td></tr>

		  <tr>
		    <td>
		      <a onMouseDown="handlePress(6);return true;"
			 onMouseUp="handleRelease(6);return true;"
			 onMouseOut="handleRelease(6);return true;"
			 onClick="return false;"
			 title="Go to End Of File">EOF</a></td>
		    <td>
		      <a onMouseDown="handlePress(4);return true;"
			 onMouseUp="handleRelease(4);return true;"
			 onMouseOut="handleRelease(4);return true;"
			 title="Scroll Down: Press and Hold to accelerate"
			 onClick="return false;">Scroll Down</a></td>
		    <td>
		      <a onMouseDown="handlePress(5);return true;"
			 onMouseUp="handleRelease(5);return true;"
			 onMouseOut="handleRelease(5);return true;"
			 title="Go to next Diff"
			 onClick="return false;">Next Diff</a></td>
		  </tr>
              </table>
	    </div>
	  </td>
	  <th valign="middle" width="25%">
	    <form action="" name="diff" onsubmit="return ValidateDiffNum();">
		<input name="display" value="BOF" size="8" type="text"></input>
		<input name="real" value="0" size="8" type="hidden"></input>
	    </form>
	  </th>
	</tr>
    </table>
  </body>
</html>
EOF
}



#
# diff_to_html <filename> <filepath> { U | C } <comment>
#
# Processes the output of diff to produce an HTML file representing either
# context or unified diffs.
#
diff_to_html()
{
	TNAME=$1
	TPATH=$2
	DIFFTYPE=$3
	COMMENT=$4

	print "$HTML<head>$STDHEAD"
	print "<title>$WNAME ${DIFFTYPE}diff $TPATH</title>"

	if [[ $DIFFTYPE == "U" ]]; then
		print "$UDIFFCSS"
	fi

	cat <<-EOF
	</head>
	<body id="SUNWwebrev">
        <a class="print" href="javascript:print()">Print this page</a>
	<pre>$COMMENT</pre>
        <pre>
	EOF

	html_quote | $AWK '
	/^--- new/	{ next }
	/^\+\+\+ new/	{ next }
	/^--- old/	{ next }
	/^\*\*\* old/	{ next }
	/^\*\*\*\*/	{ next }
	/^-------/	{ printf "<center><h1>%s</h1></center>\n", $0; next }
	/^\@\@.*\@\@$/	{ printf "</pre><hr></hr><pre>\n";
			  printf "<span class=\"newmarker\">%s</span>\n", $0;
			  next}

	/^\*\*\*/	{ printf "<hr></hr><span class=\"oldmarker\">%s</span>\n", $0;
			  next}
	/^---/		{ printf "<span class=\"newmarker\">%s</span>\n", $0;
			  next}
	/^\+/		{printf "<span class=\"new\">%s</span>\n", $0; next}
	/^!/		{printf "<span class=\"changed\">%s</span>\n", $0; next}
	/^-/		{printf "<span class=\"removed\">%s</span>\n", $0; next}
			{printf "%s\n", $0; next}
	'

	print "</pre></body></html>\n"
}


#
# source_to_html { new | old } <filename>
#
# Process a plain vanilla source file to transform it into an HTML file.
#
source_to_html()
{
	WHICH=$1
	TNAME=$2

	print "$HTML<head>$STDHEAD"
	print "<title>$WNAME $WHICH $TNAME</title>"
	print "<body id=\"SUNWwebrev\">"
	print "<pre>"
	html_quote | $AWK '{line += 1 ; printf "%4d %s\n", line, $0 }'
	print "</pre></body></html>"
}

#
# comments_from_wx {text|html} filepath
#
# Given the pathname of a file, find its location in a "wx" active
# file list and print the following comment.  Output is either text or
# HTML; if the latter, embedded bugids (sequence of 5 or more digits)
# are turned into URLs.
#
# This is also used with Mercurial and the file list provided by hg-active.
#
comments_from_wx()
{
	typeset fmt=$1
	typeset p=$2

	comm=`$AWK '
	$1 == "'$p'" {
		do getline ; while (NF > 0)
		getline
		while (NF > 0) { print ; getline }
		exit
	}' < $wxfile`

	if [[ -z $comm ]]; then
		comm="*** NO COMMENTS ***"
	fi

	if [[ $fmt == "text" ]]; then
		print -- "$comm"
		return
	fi

	print -- "$comm" | html_quote | its2url

}

#
# getcomments {text|html} filepath parentpath
#
# Fetch the comments depending on what SCM mode we're in.
#
getcomments()
{
	typeset fmt=$1
	typeset p=$2
	typeset pp=$3

	if [[ -n $Nflag ]]; then
		return
	fi
	#
	# Mercurial support uses a file list in wx format, so this
	# will be used there, too
	#
	if [[ -n $wxfile ]]; then
		comments_from_wx $fmt $p
	fi
}

#
# printCI <total-changed> <inserted> <deleted> <modified> <unchanged>
#
# Print out Code Inspection figures similar to sccs-prt(1) format.
#
function printCI
{
	integer tot=$1 ins=$2 del=$3 mod=$4 unc=$5
	typeset str
	if (( tot == 1 )); then
		str="line"
	else
		str="lines"
	fi
	printf '%d %s changed: %d ins; %d del; %d mod; %d unchg\n' \
	    $tot $str $ins $del $mod $unc
}


#
# difflines <oldfile> <newfile>
#
# Calculate and emit number of added, removed, modified and unchanged lines,
# and total lines changed, the sum of added + removed + modified.
#
function difflines
{
	integer tot mod del ins unc err
	typeset filename

	eval $( diff -e $1 $2 | $AWK '
	# Change range of lines: N,Nc
	/^[0-9]*,[0-9]*c$/ {
		n=split(substr($1,1,length($1)-1), counts, ",");
		if (n != 2) {
			error=2
			exit;
		}
		#
		# 3,5c means lines 3 , 4 and 5 are changed, a total of 3 lines.
		# following would be 5 - 3 = 2! Hence +1 for correction.
		#
		r=(counts[2]-counts[1])+1;

		#
		# Now count replacement lines: each represents a change instead
		# of a delete, so increment c and decrement r.
		#
		while (getline != /^\.$/) {
			c++;
			r--;
		}
		#
		# If there were more replacement lines than original lines,
		# then r will be negative; in this case there are no deletions,
		# but there are r changes that should be counted as adds, and
		# since r is negative, subtract it from a and add it to c.
		#
		if (r < 0) {
			a-=r;
			c+=r;
		}

		#
		# If there were more original lines than replacement lines, then
		# r will be positive; in this case, increment d by that much.
		#
		if (r > 0) {
			d+=r;
		}
		next;
	}

	# Change lines: Nc
	/^[0-9].*c$/ {
		# The first line is a replacement; any more are additions.
		if (getline != /^\.$/) {
			c++;
			while (getline != /^\.$/) a++;
		}
		next;
	}

	# Add lines: both Na and N,Na
	/^[0-9].*a$/ {
		while (getline != /^\.$/) a++;
		next;
	}

	# Delete range of lines: N,Nd
	/^[0-9]*,[0-9]*d$/ {
		n=split(substr($1,1,length($1)-1), counts, ",");
		if (n != 2) {
			error=2
			exit;
		}
		#
		# 3,5d means lines 3 , 4 and 5 are deleted, a total of 3 lines.
		# following would be 5 - 3 = 2! Hence +1 for correction.
		#
		r=(counts[2]-counts[1])+1;
		d+=r;
		next;
	}

	# Delete line: Nd.   For example 10d says line 10 is deleted.
	/^[0-9]*d$/ {d++; next}

	# Should not get here!
	{
		error=1;
		exit;
	}

	# Finish off - print results
	END {
		printf("tot=%d;mod=%d;del=%d;ins=%d;err=%d\n",
		    (c+d+a), c, d, a, error);
	}' )

	# End of $AWK, Check to see if any trouble occurred.
	if (( $? > 0 || err > 0 )); then
		print "Unexpected Error occurred reading" \
		    "\`diff -e $1 $2\`: \$?=$?, err=" $err
		return
	fi

	# Accumulate totals
	(( TOTL += tot ))
	(( TMOD += mod ))
	(( TDEL += del ))
	(( TINS += ins ))
	# Calculate unchanged lines
	unc=`wc -l < $1`
	if (( unc > 0 )); then
		(( unc -= del + mod ))
		(( TUNC += unc ))
	fi
	# print summary
	print "<span class=\"lineschanged\">"
	printCI $tot $ins $del $mod $unc
	print "</span>"
}


#
# flist_from_wx
#
# Sets up webrev to source its information from a wx-formatted file.
# Sets the global 'wxfile' variable.
#
function flist_from_wx
{
	typeset argfile=$1
	if [[ -n ${argfile%%/*} ]]; then
		#
		# If the wx file pathname is relative then make it absolute
		# because the webrev does a "cd" later on.
		#
		wxfile=$PWD/$argfile
	else
		wxfile=$argfile
	fi

	$AWK '{ c = 1; print;
	  while (getline) {
		if (NF == 0) { c = -c; continue }
		if (c > 0) print
	  }
	}' $wxfile > $FLIST

	print " Done."
}

#
# Call hg-active to get the active list output in the wx active list format
#
function hg_active_wxfile
{
	typeset child=$1
	typeset parent=$2

	TMPFLIST=/tmp/$$.active
	$HG_ACTIVE -w $child -p $parent -o $TMPFLIST
	wxfile=$TMPFLIST
}

#
# flist_from_mercurial
# Call hg-active to get a wx-style active list, and hand it off to
# flist_from_wx
#
function flist_from_mercurial
{
	typeset child=$1
	typeset parent=$2

	print " File list from: hg-active -p $parent ...\c"
	if [[ ! -x $HG_ACTIVE ]]; then
		print		# Blank line for the \c above
		print -u2 "Error: hg-active tool not found.  Exiting"
		exit 1
	fi
	hg_active_wxfile $child $parent

	# flist_from_wx prints the Done, so we don't have to.
	flist_from_wx $TMPFLIST
}

#
# Transform a specified 'git log' output format into a wx-like active list.
#
function git_wxfile
{
	typeset child="$1"
	typeset parent="$2"

	TMPFLIST=/tmp/$$.active
	$PERL -e 'my (%files, %realfiles, $msg);
	my $parent = $ARGV[0];
	my $child = $ARGV[1];

	open(F, "git diff -M --name-status $parent..$child |");
	while (<F>) {
	    chomp;
	    if (/^R(\d+)\s+([^ ]+)\s+([^ ]+)/) { # rename
		if ($1 >= 75) {		 # Probably worth treating as a rename
		    $realfiles{$3} = $2;
		} else {
		    $realfiles{$3} = $3;
		    $realfiles{$2} = $2;
		}
	    } else {
		my $f = (split /\s+/, $_)[1];
		$realfiles{$f} = $f;
	    }
	}
	close(F);

	my $state = 1;		    # 0|comments, 1|files
	open(F, "git whatchanged --pretty=format:%B $parent..$child |");
	while (<F>) {
	    chomp;
	    if (/^:[0-9]{6}/) {
		my ($unused, $fname, $fname2) = split(/\t/, $_);
		$fname = $fname2 if defined($fname2);
		next if !defined($realfiles{$fname}); # No real change
		$state = 1;
		chomp $msg;
		$files{$fname} .= $msg;
	    } else {
		if ($state == 1) {
		    $state = 0;
		    $msg = /^\n/ ? "" : "\n";
		}
		$msg .= "$_\n" if ($_);
	    }
	}
	close(F);
	 
	for (sort keys %files) {
	    if ($realfiles{$_} ne $_) {
		print "$_ $realfiles{$_}\n$files{$_}\n\n";
	    } else {
		print "$_\n$files{$_}\n\n"
	    }
	}' ${parent} ${child} > $TMPFLIST

	wxfile=$TMPFLIST
}

#
# flist_from_git
# Build a wx-style active list, and hand it off to flist_from_wx
#
function flist_from_git
{
	typeset child=$1
	typeset parent=$2

	print " File list from: git ...\c"
	git_wxfile "$child" "$parent";

	# flist_from_wx prints the Done, so we don't have to.
	flist_from_wx $TMPFLIST
}

#
# flist_from_subversion
#
# Generate the file list by extracting file names from svn status.
#
function flist_from_subversion
{
	CWS=$1
	OLDPWD=$2

	cd $CWS
	print -u2 " File list from: svn status ... \c"
	svn status | $AWK '/^[ACDMR]/ { print $NF }' > $FLIST
	print -u2 " Done."
	cd $OLDPWD
}

function env_from_flist
{
	[[ -r $FLIST ]] || return

	#
	# Use "eval" to set env variables that are listed in the file
	# list.  Then copy those into our local versions of those
	# variables if they have not been set already.
	#
	eval `$SED -e "s/#.*$//" $FLIST | $GREP = `

	if [[ -z $codemgr_ws && -n $CODEMGR_WS ]]; then
		codemgr_ws=$CODEMGR_WS
		export CODEMGR_WS
	fi

	#
	# Check to see if CODEMGR_PARENT is set in the flist file.
	#
	if [[ -z $codemgr_parent && -n $CODEMGR_PARENT ]]; then
		codemgr_parent=$CODEMGR_PARENT
		export CODEMGR_PARENT
	fi
}

function look_for_prog
{
	typeset path
	typeset ppath
	typeset progname=$1

	ppath=$PATH
	ppath=$ppath:/usr/sfw/bin:/usr/bin:/usr/sbin
	ppath=$ppath:/opt/onbld/bin
	ppath=$ppath:/opt/onbld/bin/`uname -p`

	PATH=$ppath prog=`whence $progname`
	if [[ -n $prog ]]; then
		print $prog
	fi
}

function get_file_mode
{
	$PERL -e '
		if (@stat = stat($ARGV[0])) {
			$mode = $stat[2] & 0777;
			printf "%03o\n", $mode;
			exit 0;
		} else {
			exit 1;
		}
	    ' $1
}

function build_old_new_mercurial
{
	typeset olddir="$1"
	typeset newdir="$2"
	typeset old_mode=
	typeset new_mode=
	typeset file

	#
	# Get old file mode, from the parent revision manifest entry.
	# Mercurial only stores a "file is executable" flag, but the
	# manifest will display an octal mode "644" or "755".
	#
	if [[ "$PDIR" == "." ]]; then
		file="$PF"
	else
		file="$PDIR/$PF"
	fi
	file=`echo $file | $SED 's#/#\\\/#g'`
	# match the exact filename, and return only the permission digits
	old_mode=`$SED -n -e "/^\\(...\\) . ${file}$/s//\\1/p" \
	    < $HG_PARENT_MANIFEST`

	#
	# Get new file mode, directly from the filesystem.
	# Normalize the mode to match Mercurial's behavior.
	#
	new_mode=`get_file_mode $CWS/$DIR/$F`
	if [[ -n "$new_mode" ]]; then
		if [[ "$new_mode" = *[1357]* ]]; then
			new_mode=755
		else
			new_mode=644
		fi
	fi

	#
	# new version of the file.
	#
	rm -rf $newdir/$DIR/$F
	if [[ -e $CWS/$DIR/$F ]]; then
		cp $CWS/$DIR/$F $newdir/$DIR/$F
		if [[ -n $new_mode ]]; then
			chmod $new_mode $newdir/$DIR/$F
		else
			# should never happen
			print -u2 "ERROR: set mode of $newdir/$DIR/$F"
		fi
	fi

	#
	# parent's version of the file
	#
	# Note that we get this from the last version common to both
	# ourselves and the parent.  References are via $CWS since we have no
	# guarantee that the parent workspace is reachable via the filesystem.
	#
	if [[ -n $parent_webrev && -e $PWS/$PDIR/$PF ]]; then
		cp $PWS/$PDIR/$PF $olddir/$PDIR/$PF
	elif [[ -n $HG_PARENT ]]; then
		hg cat -R $CWS -r $HG_PARENT $CWS/$PDIR/$PF > \
		    $olddir/$PDIR/$PF 2>/dev/null

		if (( $? != 0 )); then
			rm -f $olddir/$PDIR/$PF
		else
			if [[ -n $old_mode ]]; then
				chmod $old_mode $olddir/$PDIR/$PF
			else
				# should never happen
				print -u2 "ERROR: set mode of $olddir/$PDIR/$PF"
			fi
		fi
	fi
}

function build_old_new_git
{
	typeset olddir="$1"
	typeset newdir="$2"
	typeset o_mode=
	typeset n_mode=
	typeset o_object=
	typeset n_object=
	typeset OWD=$PWD
	typeset file
	typeset type

	cd $CWS

	#
	# Get old file and its mode from the git object tree
	#
	if [[ "$PDIR" == "." ]]; then
		file="$PF"
	else
		file="$PDIR/$PF"
	fi

	if [[ -n $parent_webrev && -e $PWS/$PDIR/$PF ]]; then
		cp $PWS/$PDIR/$PF $olddir/$PDIR/$PF
	else
		$GIT ls-tree $GIT_PARENT $file | read o_mode type o_object junk
		$GIT cat-file $type $o_object > $olddir/$file 2>/dev/null

		if (( $? != 0 )); then
			rm -f $olddir/$file
		elif [[ -n $o_mode ]]; then
			# Strip the first 3 digits, to get a regular octal mode
			o_mode=${o_mode/???/}
			chmod $o_mode $olddir/$file
		else
			# should never happen
			print -u2 "ERROR: set mode of $olddir/$file"
		fi
	fi

	#
	# new version of the file.
	#
	if [[ "$DIR" == "." ]]; then
		file="$F"
	else
		file="$DIR/$F"
	fi
	rm -rf $newdir/$file

        if [[ -e $CWS/$DIR/$F ]]; then
		cp $CWS/$DIR/$F $newdir/$DIR/$F
		chmod $(get_file_mode $CWS/$DIR/$F) $newdir/$DIR/$F
        fi
	cd $OWD
}

function build_old_new_subversion
{
	typeset olddir="$1"
	typeset newdir="$2"

	# Snag new version of file.
	rm -f $newdir/$DIR/$F
	[[ -e $CWS/$DIR/$F ]] && cp $CWS/$DIR/$F $newdir/$DIR/$F

	if [[ -n $PWS && -e $PWS/$PDIR/$PF ]]; then
		cp $PWS/$PDIR/$PF $olddir/$PDIR/$PF
	else
		# Get the parent's version of the file.
		svn status $CWS/$DIR/$F | read stat file
		if [[ $stat != "A" ]]; then
			svn cat -r BASE $CWS/$DIR/$F > $olddir/$PDIR/$PF
		fi
	fi
}

function build_old_new_unknown
{
	typeset olddir="$1"
	typeset newdir="$2"

	#
	# Snag new version of file.
	#
	rm -f $newdir/$DIR/$F
	[[ -e $CWS/$DIR/$F ]] && cp $CWS/$DIR/$F $newdir/$DIR/$F

	#
	# Snag the parent's version of the file.
	#
	if [[ -f $PWS/$PDIR/$PF ]]; then
		rm -f $olddir/$PDIR/$PF
		cp $PWS/$PDIR/$PF $olddir/$PDIR/$PF
	fi
}

function build_old_new
{
	typeset WDIR=$1
	typeset PWS=$2
	typeset PDIR=$3
	typeset PF=$4
	typeset CWS=$5
	typeset DIR=$6
	typeset F=$7

	typeset olddir="$WDIR/raw_files/old"
	typeset newdir="$WDIR/raw_files/new"

	mkdir -p $olddir/$PDIR
	mkdir -p $newdir/$DIR

	if [[ $SCM_MODE == "mercurial" ]]; then
		build_old_new_mercurial "$olddir" "$newdir"
	elif [[ $SCM_MODE == "git" ]]; then
		build_old_new_git "$olddir" "$newdir"
	elif [[ $SCM_MODE == "subversion" ]]; then
		build_old_new_subversion "$olddir" "$newdir"
	elif [[ $SCM_MODE == "unknown" ]]; then
		build_old_new_unknown "$olddir" "$newdir"
	fi

	if [[ ! -f $olddir/$PDIR/$PF && ! -f $newdir/$DIR/$F ]]; then
		print "*** Error: file not in parent or child"
		return 1
	fi
	return 0
}


#
# Usage message.
#
function usage
{
	print 'Usage:\twebrev [common-options]
	webrev [common-options] ( <file> | - )
	webrev [common-options] -w <wx file>

Options:
	-c <revision>: generate webrev for single revision (git only)
	-C <filename>: Use <filename> for the information tracking configuration.
	-D: delete remote webrev
	-h <revision>: specify "head" revision for comparison (git only)
	-i <filename>: Include <filename> in the index.html file.
	-I <filename>: Use <filename> for the information tracking registry.
	-n: do not generate the webrev (useful with -U)
	-O: Print bugids/arc cases suitable for OpenSolaris.
	-o <outdir>: Output webrev to specified directory.
	-p <compare-against>: Use specified parent wkspc or basis for comparison
	-t <remote_target>: Specify remote destination for webrev upload
	-U: upload the webrev to remote destination
	-w <wxfile>: Use specified wx active file.

Environment:
	WDIR: Control the output directory.
	WEBREV_TRASH_DIR: Set directory for webrev delete.

SCM Environment:
	CODEMGR_WS: Workspace location.
	CODEMGR_PARENT: Parent workspace location.
'

	exit 2
}

#
#
# Main program starts here
#
#

trap "rm -f /tmp/$$.* ; exit" 0 1 2 3 15

set +o noclobber

PATH=$(/bin/dirname "$(whence $0)"):$PATH

[[ -z $WDIFF ]] && WDIFF=`look_for_prog wdiff`
[[ -z $WX ]] && WX=`look_for_prog wx`
[[ -z $HG_ACTIVE ]] && HG_ACTIVE=`look_for_prog hg-active`
[[ -z $GIT ]] && GIT=`look_for_prog git`
[[ -z $WHICH_SCM ]] && WHICH_SCM=`look_for_prog which_scm`
[[ -z $CODEREVIEW ]] && CODEREVIEW=`look_for_prog codereview`
[[ -z $PS2PDF ]] && PS2PDF=`look_for_prog ps2pdf`
[[ -z $PERL ]] && PERL=`look_for_prog perl`
[[ -z $RSYNC ]] && RSYNC=`look_for_prog rsync`
[[ -z $SCCS ]] && SCCS=`look_for_prog sccs`
[[ -z $AWK ]] && AWK=`look_for_prog nawk`
[[ -z $AWK ]] && AWK=`look_for_prog gawk`
[[ -z $AWK ]] && AWK=`look_for_prog awk`
[[ -z $SCP ]] && SCP=`look_for_prog scp`
[[ -z $SED ]] && SED=`look_for_prog sed`
[[ -z $SFTP ]] && SFTP=`look_for_prog sftp`
[[ -z $SORT ]] && SORT=`look_for_prog sort`
[[ -z $MKTEMP ]] && MKTEMP=`look_for_prog mktemp`
[[ -z $GREP ]] && GREP=`look_for_prog grep`
[[ -z $FIND ]] && FIND=`look_for_prog find`
[[ -z $MANDOC ]] && MANDOC=`look_for_prog mandoc`
[[ -z $COL ]] && COL=`look_for_prog col`

# set name of trash directory for remote webrev deletion
TRASH_DIR=".trash"
[[ -n $WEBREV_TRASH_DIR ]] && TRASH_DIR=$WEBREV_TRASH_DIR

if [[ ! -x $PERL ]]; then
	print -u2 "Error: No perl interpreter found.  Exiting."
	exit 1
fi

if [[ ! -x $WHICH_SCM ]]; then
	print -u2 "Error: Could not find which_scm.  Exiting."
	exit 1
fi

#
# These aren't fatal, but we want to note them to the user.
# We don't warn on the absence of 'wx' until later when we've
# determined that we actually need to try to invoke it.
#
[[ ! -x $CODEREVIEW ]] && print -u2 "WARNING: codereview(1) not found."
[[ ! -x $PS2PDF ]] && print -u2 "WARNING: ps2pdf(1) not found."
[[ ! -x $WDIFF ]] && print -u2 "WARNING: wdiff not found."

# Declare global total counters.
integer TOTL TINS TDEL TMOD TUNC

# default remote host for upload/delete
typeset -r DEFAULT_REMOTE_HOST="cr.opensolaris.org"
# prefixes for upload targets
typeset -r rsync_prefix="rsync://"
typeset -r ssh_prefix="ssh://"

cflag=
Cflag=
Dflag=
flist_mode=
flist_file=
hflag=
iflag=
Iflag=
lflag=
Nflag=
nflag=
Oflag=
oflag=
pflag=
tflag=
uflag=
Uflag=
wflag=
remote_target=

#
# NOTE: when adding/removing options it is necessary to sync the list
#	with usr/src/tools/onbld/hgext/cdm.py
#
while getopts "c:C:Dh:i:I:lnNo:Op:t:Uw" opt
do
	case $opt in
	c)	cflag=1
		codemgr_head=$OPTARG
		codemgr_parent=$OPTARG~1;;

	C)	Cflag=1
		ITSCONF=$OPTARG;;

	D)	Dflag=1;;

	h)	hflag=1
		codemgr_head=$OPTARG;;

	i)	iflag=1
		INCLUDE_FILE=$OPTARG;;

	I)	Iflag=1
		ITSREG=$OPTARG;;

	N)	Nflag=1;;

	n)	nflag=1;;

	O)	Oflag=1;;

	o)	oflag=1
		# Strip the trailing slash to correctly form remote target.
		WDIR=${OPTARG%/};;

	p)	pflag=1
		codemgr_parent=$OPTARG;;

	t)	tflag=1
		remote_target=$OPTARG;;

	U)	Uflag=1;;

	w)	wflag=1;;

	?)	usage;;
	esac
done

FLIST=/tmp/$$.flist

if [[ -n $wflag && -n $lflag ]]; then
	usage
fi

# more sanity checking
if [[ -n $nflag && -z $Uflag ]]; then
	print "it does not make sense to skip webrev generation" \
	    "without -U"
	exit 1
fi

if [[ -n $tflag && -z $Uflag && -z $Dflag ]]; then
	echo "remote target has to be used only for upload or delete"
	exit 1
fi

#
# For the invocation "webrev -n -U" with no other options, webrev will assume
# that the webrev exists in ${CWS}/webrev, but will upload it using the name
# $(basename ${CWS}).  So we need to get CWS set before we skip any remaining
# logic.
#
$WHICH_SCM | read SCM_MODE junk || exit 1
if [[ $SCM_MODE == "mercurial" ]]; then
	#
	# Mercurial priorities:
	# 1. hg root from CODEMGR_WS environment variable
	# 1a. hg root from CODEMGR_WS/usr/closed if we're somewhere under
	#    usr/closed when we run webrev
	# 2. hg root from directory of invocation
	#
	if [[ ${PWD} =~ "usr/closed" ]]; then
		testparent=${CODEMGR_WS}/usr/closed
		# If we're in OpenSolaris mode, we enforce a minor policy:
		# help to make sure the reviewer doesn't accidentally publish
		# source which is under usr/closed
		if [[ -n "$Oflag" ]]; then
			print -u2 "OpenSolaris output not permitted with" \
			    "usr/closed changes"
			exit 1
		fi
	else
		testparent=${CODEMGR_WS}
	fi
	[[ -z $codemgr_ws && -n $testparent ]] && \
	    codemgr_ws=$(hg root -R $testparent 2>/dev/null)
	[[ -z $codemgr_ws ]] && codemgr_ws=$(hg root 2>/dev/null)
	CWS=$codemgr_ws
elif [[ $SCM_MODE == "git" ]]; then
	#
	# Git priorities:
	# 1. git rev-parse --git-dir from CODEMGR_WS environment variable
	# 2. git rev-parse --git-dir from directory of invocation
	#
	[[ -z $codemgr_ws && -n $CODEMGR_WS ]] && \
	    codemgr_ws=$($GIT --git-dir=$CODEMGR_WS/.git rev-parse --git-dir \
		2>/dev/null)
	[[ -z $codemgr_ws ]] && \
	    codemgr_ws=$($GIT rev-parse --git-dir 2>/dev/null)

	if [[ "$codemgr_ws" == ".git" ]]; then
		codemgr_ws="${PWD}/${codemgr_ws}"
	fi

	if [[ "$codemgr_ws" = *"/.git" ]]; then
		codemgr_ws=$(dirname $codemgr_ws) # Lose the '/.git'
	fi
	CWS="$codemgr_ws"
elif [[ $SCM_MODE == "subversion" ]]; then
	#
	# Subversion priorities:
	# 1. CODEMGR_WS from environment
	# 2. Relative path from current directory to SVN repository root
	#
	if [[ -n $CODEMGR_WS && -d $CODEMGR_WS/.svn ]]; then
		CWS=$CODEMGR_WS
	else
		svn info | while read line; do
			if [[ $line == "URL: "* ]]; then
				url=${line#URL: }
			elif [[ $line == "Repository Root: "* ]]; then
				repo=${line#Repository Root: }
			fi
		done

		rel=${url#$repo}
		CWS=${PWD%$rel}
	fi
fi

#
# If no SCM has been determined, take either the environment setting
# setting for CODEMGR_WS, or the current directory if that wasn't set.
#
if [[ -z ${CWS} ]]; then
	CWS=${CODEMGR_WS:-.}
fi

#
# If the command line options indicate no webrev generation, either
# explicitly (-n) or implicitly (-D but not -U), then there's a whole
# ton of logic we can skip.
#
# Instead of increasing indentation, we intentionally leave this loop
# body open here, and exit via break from multiple points within.
# Search for DO_EVERYTHING below to find the break points and closure.
#
for do_everything in 1; do

# DO_EVERYTHING: break point
if [[ -n $nflag || ( -z $Uflag && -n $Dflag ) ]]; then
	break
fi

#
# If this manually set as the parent, and it appears to be an earlier webrev,
# then note that fact and set the parent to the raw_files/new subdirectory.
#
if [[ -n $pflag && -d $codemgr_parent/raw_files/new ]]; then
	parent_webrev=$(readlink -f "$codemgr_parent")
	codemgr_parent=$(readlink -f "$codemgr_parent/raw_files/new")
fi

if [[ -z $wflag && -z $lflag ]]; then
	shift $(($OPTIND - 1))

	if [[ $1 == "-" ]]; then
		cat > $FLIST
		flist_mode="stdin"
		flist_done=1
		shift
	elif [[ -n $1 ]]; then
		if [[ ! -r $1 ]]; then
			print -u2 "$1: no such file or not readable"
			usage
		fi
		cat $1 > $FLIST
		flist_mode="file"
		flist_file=$1
		flist_done=1
		shift
	else
		flist_mode="auto"
	fi
fi

#
# Before we go on to further consider -l and -w, work out which SCM we think
# is in use.
#
case "$SCM_MODE" in
mercurial|git|subversion)
	;;
unknown)
	if [[ $flist_mode == "auto" ]]; then
		print -u2 "Unable to determine SCM in use and file list not specified"
		print -u2 "See which_scm(1) for SCM detection information."
		exit 1
	fi
	;;
*)
	if [[ $flist_mode == "auto" ]]; then
		print -u2 "Unsupported SCM in use ($SCM_MODE) and file list not specified"
		exit 1
	fi
	;;
esac

print -u2 "   SCM detected: $SCM_MODE"

if [[ -n $wflag ]]; then
	#
	# If the -w is given then assume the file list is in Bonwick's "wx"
	# command format, i.e.  pathname lines alternating with SCCS comment
	# lines with blank lines as separators.  Use the SCCS comments later
	# in building the index.html file.
	#
	shift $(($OPTIND - 1))
	wxfile=$1
	if [[ -z $wxfile && -n $CODEMGR_WS ]]; then
		if [[ -r $CODEMGR_WS/wx/active ]]; then
			wxfile=$CODEMGR_WS/wx/active
		fi
	fi

	[[ -z $wxfile ]] && print -u2 "wx file not specified, and could not " \
	    "be auto-detected (check \$CODEMGR_WS)" && exit 1

	if [[ ! -r $wxfile ]]; then
		print -u2 "$wxfile: no such file or not readable"
		usage
	fi

	print -u2 " File list from: wx 'active' file '$wxfile' ... \c"
	flist_from_wx $wxfile
	flist_done=1
	if [[ -n "$*" ]]; then
		shift
	fi
elif [[ $flist_mode == "stdin" ]]; then
	print -u2 " File list from: standard input"
elif [[ $flist_mode == "file" ]]; then
	print -u2 " File list from: $flist_file"
fi

if [[ $# -gt 0 ]]; then
	print -u2 "WARNING: unused arguments: $*"
fi

#
# Before we entered the DO_EVERYTHING loop, we should have already set CWS
# and CODEMGR_WS as needed.  Here, we set the parent workspace.
#
if [[ $SCM_MODE == "mercurial" ]]; then
	#
	# Parent can either be specified with -p
	# Specified with CODEMGR_PARENT in the environment
	# or taken from hg's default path.
	#

	if [[ -z $codemgr_parent && -n $CODEMGR_PARENT ]]; then
		codemgr_parent=$CODEMGR_PARENT
	fi

	if [[ -z $codemgr_parent ]]; then
		codemgr_parent=`hg path -R $codemgr_ws default 2>/dev/null`
	fi

	PWS=$codemgr_parent

	#
	# If the parent is a webrev, we want to do some things against
	# the natural workspace parent (file list, comments, etc)
	#
	if [[ -n $parent_webrev ]]; then
		real_parent=$(hg path -R $codemgr_ws default 2>/dev/null)
	else
		real_parent=$PWS
	fi

	#
	# If hg-active exists, then we run it.  In the case of no explicit
	# flist given, we'll use it for our comments.  In the case of an
	# explicit flist given we'll try to use it for comments for any
	# files mentioned in the flist.
	#
	if [[ -z $flist_done ]]; then
		flist_from_mercurial $CWS $real_parent
		flist_done=1
	fi

	#
	# If we have a file list now, pull out any variables set
	# therein.  We do this now (rather than when we possibly use
	# hg-active to find comments) to avoid stomping specifications
	# in the user-specified flist.
	#
	if [[ -n $flist_done ]]; then
		env_from_flist
	fi

	#
	# Only call hg-active if we don't have a wx formatted file already
	#
	if [[ -x $HG_ACTIVE && -z $wxfile ]]; then
		print "  Comments from: hg-active -p $real_parent ...\c"
		hg_active_wxfile $CWS $real_parent
		print " Done."
	fi

	#
	# At this point we must have a wx flist either from hg-active,
	# or in general.  Use it to try and find our parent revision,
	# if we don't have one.
	#
	if [[ -z $HG_PARENT ]]; then
		eval `$SED -e "s/#.*$//" $wxfile | $GREP HG_PARENT=`
	fi

	#
	# If we still don't have a parent, we must have been given a
	# wx-style active list with no HG_PARENT specification, run
	# hg-active and pull an HG_PARENT out of it, ignore the rest.
	#
	if [[ -z $HG_PARENT && -x $HG_ACTIVE ]]; then
		$HG_ACTIVE -w $codemgr_ws -p $real_parent | \
		    eval `$SED -e "s/#.*$//" | $GREP HG_PARENT=`
	elif [[ -z $HG_PARENT ]]; then
		print -u2 "Error: Cannot discover parent revision"
		exit 1
	fi

	pnode=$(trim_digest $HG_PARENT)
	PRETTY_PWS="${PWS} (at ${pnode})"
	cnode=$(hg parent -R $codemgr_ws --template '{node|short}' \
	    2>/dev/null)
	PRETTY_CWS="${CWS} (at ${cnode})"}
elif [[ $SCM_MODE == "git" ]]; then
	# Check that "head" revision specified with -c or -h is sane
	if [[ -n $cflag || -n $hflag ]]; then
		head_rev=$($GIT rev-parse --verify --quiet "$codemgr_head")
		if [[ -z $head_rev ]]; then
			print -u2 "Error: bad revision ${codemgr_head}"
			exit 1
		fi
	fi

	if [[ -z $codemgr_head ]]; then
		codemgr_head="HEAD";
	fi

	# Parent can either be specified with -p, or specified with
	# CODEMGR_PARENT in the environment.
	if [[ -z $codemgr_parent && -n $CODEMGR_PARENT ]]; then
		codemgr_parent=$CODEMGR_PARENT
	fi

	# Try to figure out the parent based on the branch the current
	# branch is tracking, if we fail, use origin/master
	this_branch=$($GIT branch | nawk '$1 == "*" { print $2 }')
	par_branch="origin/master"

	# If we're not on a branch there's nothing we can do
	if [[ $this_branch != "(no branch)" ]]; then
		$GIT for-each-ref					\
		    --format='%(refname:short) %(upstream:short)'	\
		    refs/heads/ |					\
		    while read local remote; do
			if [[ "$local" == "$this_branch" ]]; then
				par_branch="$remote"
			fi
		done
	fi

	if [[ -z $codemgr_parent ]]; then
		codemgr_parent=$par_branch
	fi
	PWS=$codemgr_parent

	#
	# If the parent is a webrev, we want to do some things against
	# the natural workspace parent (file list, comments, etc)
	#
	if [[ -n $parent_webrev ]]; then
		real_parent=$par_branch
	else
		real_parent=$PWS
	fi

	if [[ -z $flist_done ]]; then
		flist_from_git "$codemgr_head" "$real_parent"
		flist_done=1
	fi

	#
	# If we have a file list now, pull out any variables set
	# therein.
	#
	if [[ -n $flist_done ]]; then
		env_from_flist
	fi

	#
	# If we don't have a wx-format file list, build one we can pull change
	# comments from.
	#
	if [[ -z $wxfile ]]; then
		print "  Comments from: git...\c"
		git_wxfile "$codemgr_head" "$real_parent"
		print " Done."
	fi

	if [[ -z $GIT_PARENT ]]; then
		GIT_PARENT=$($GIT merge-base "$real_parent" "$codemgr_head")
	fi
	if [[ -z $GIT_PARENT ]]; then
		print -u2 "Error: Cannot discover parent revision"
		exit 1
	fi

	pnode=$(trim_digest $GIT_PARENT)

	if [[ -n $cflag ]]; then
		PRETTY_PWS="previous revision (at ${pnode})"
	elif [[ $real_parent == */* ]]; then
		origin=$(echo $real_parent | cut -d/ -f1)
		origin=$($GIT remote -v | \
		    $AWK '$1 == "'$origin'" { print $2; exit }')
		PRETTY_PWS="${PWS} (${origin} at ${pnode})"
	elif [[ -n $pflag && -z $parent_webrev ]]; then
		PRETTY_PWS="${CWS} (explicit revision ${pnode})"
	else
		PRETTY_PWS="${PWS} (at ${pnode})"
	fi

	cnode=$($GIT --git-dir=${codemgr_ws}/.git rev-parse --short=12 \
	    ${codemgr_head} 2>/dev/null)

	if [[ -n $cflag || -n $hflag ]]; then
		PRETTY_CWS="${CWS} (explicit head at ${cnode})"
	else
		PRETTY_CWS="${CWS} (at ${cnode})"
	fi
elif [[ $SCM_MODE == "subversion" ]]; then

	#
	# We only will have a real parent workspace in the case one
	# was specified (be it an older webrev, or another checkout).
	#
	[[ -n $codemgr_parent ]] && PWS=$codemgr_parent

	if [[ -z $flist_done && $flist_mode == "auto" ]]; then
		flist_from_subversion $CWS $OLDPWD
	fi
else
	if [[ $SCM_MODE == "unknown" ]]; then
		print -u2 "    Unknown type of SCM in use"
	else
		print -u2 "    Unsupported SCM in use: $SCM_MODE"
	fi

	env_from_flist

	if [[ -z $CODEMGR_WS ]]; then
		print -u2 "SCM not detected/supported and " \
		    "CODEMGR_WS not specified"
		exit 1
		fi

	if [[ -z $CODEMGR_PARENT ]]; then
		print -u2 "SCM not detected/supported and " \
		    "CODEMGR_PARENT not specified"
		exit 1
	fi

	CWS=$CODEMGR_WS
	PWS=$CODEMGR_PARENT
fi

#
# If the user didn't specify a -i option, check to see if there is a
# webrev-info file in the workspace directory.
#
if [[ -z $iflag && -r "$CWS/webrev-info" ]]; then
	iflag=1
	INCLUDE_FILE="$CWS/webrev-info"
fi

if [[ -n $iflag ]]; then
	if [[ ! -r $INCLUDE_FILE ]]; then
		print -u2 "include file '$INCLUDE_FILE' does not exist or is" \
		    "not readable."
		exit 1
	else
		#
		# $INCLUDE_FILE may be a relative path, and the script alters
		# PWD, so we just stash a copy in /tmp.
		#
		cp $INCLUDE_FILE /tmp/$$.include
	fi
fi

# DO_EVERYTHING: break point
if [[ -n $Nflag ]]; then
	break
fi

typeset -A itsinfo
typeset -r its_sed_script=/tmp/$$.its_sed
valid_prefixes=
if [[ -z $nflag ]]; then
	DEFREGFILE="$(/bin/dirname "$(whence $0)")/../etc/its.reg"
	if [[ -n $Iflag ]]; then
		REGFILE=$ITSREG
	elif [[ -r $HOME/.its.reg ]]; then
		REGFILE=$HOME/.its.reg
	else
		REGFILE=$DEFREGFILE
	fi
	if [[ ! -r $REGFILE ]]; then
		print "ERROR: Unable to read database registry file $REGFILE"
		exit 1
	elif [[ $REGFILE != $DEFREGFILE ]]; then
		print "   its.reg from: $REGFILE"
	fi

	$SED -e '/^#/d' -e '/^[ 	]*$/d' $REGFILE | while read LINE; do

		name=${LINE%%=*}
		value="${LINE#*=}"

		if [[ $name == PREFIX ]]; then
			p=${value}
			valid_prefixes="${p} ${valid_prefixes}"
		else
			itsinfo["${p}_${name}"]="${value}"
		fi
	done


	DEFCONFFILE="$(/bin/dirname "$(whence $0)")/../etc/its.conf"
	CONFFILES=$DEFCONFFILE
	if [[ -r $HOME/.its.conf ]]; then
		CONFFILES="${CONFFILES} $HOME/.its.conf"
	fi
	if [[ -n $Cflag ]]; then
		CONFFILES="${CONFFILES} ${ITSCONF}"
	fi
	its_domain=
	its_priority=
	for cf in ${CONFFILES}; do
		if [[ ! -r $cf ]]; then
			print "ERROR: Unable to read database configuration file $cf"
			exit 1
		elif [[ $cf != $DEFCONFFILE ]]; then
			print "       its.conf: reading $cf"
		fi
		$SED -e '/^#/d' -e '/^[ 	]*$/d' $cf | while read LINE; do
		    eval "${LINE}"
		done
	done

	#
	# If an information tracking system is explicitly identified by prefix,
	# we want to disregard the specified priorities and resolve it accordingly.
	#
	# To that end, we'll build a sed script to do each valid prefix in turn.
	#
	for p in ${valid_prefixes}; do
		#
		# When an informational URL was provided, translate it to a
		# hyperlink.  When omitted, simply use the prefix text.
		#
		if [[ -z ${itsinfo["${p}_INFO"]} ]]; then
			itsinfo["${p}_INFO"]=${p}
		else
			itsinfo["${p}_INFO"]="<a href=\\\"${itsinfo["${p}_INFO"]}\\\">${p}</a>"
		fi

		#
		# Assume that, for this invocation of webrev, all references
		# to this information tracking system should resolve through
		# the same URL.
		#
		# If the caller specified -O, then always use EXTERNAL_URL.
		#
		# Otherwise, look in the list of domains for a matching
		# INTERNAL_URL.
		#
		[[ -z $Oflag ]] && for d in ${its_domain}; do
			if [[ -n ${itsinfo["${p}_INTERNAL_URL_${d}"]} ]]; then
				itsinfo["${p}_URL"]="${itsinfo[${p}_INTERNAL_URL_${d}]}"
				break
			fi
		done
		if [[ -z ${itsinfo["${p}_URL"]} ]]; then
			itsinfo["${p}_URL"]="${itsinfo[${p}_EXTERNAL_URL]}"
		fi

		#
		# Turn the destination URL into a hyperlink
		#
		itsinfo["${p}_URL"]="<a href=\\\"${itsinfo[${p}_URL]}\\\">&</a>"

		# The character class below contains a literal tab
		print "/^${p}[: 	]/ {
				s;${itsinfo[${p}_REGEX]};${itsinfo[${p}_URL]};g
				s;^${p};${itsinfo[${p}_INFO]};
			}" >> ${its_sed_script}
	done

	#
	# The previous loop took care of explicit specification.  Now use
	# the configured priorities to attempt implicit translations.
	#
	for p in ${its_priority}; do
		print "/^${itsinfo[${p}_REGEX]}[ 	]/ {
				s;^${itsinfo[${p}_REGEX]};${itsinfo[${p}_URL]};g
			}" >> ${its_sed_script}
	done
fi

#
# Search for DO_EVERYTHING above for matching "for" statement
# and explanation of this terminator.
#
done

#
# Output directory.
#
WDIR=${WDIR:-$CWS/webrev}

#
# Name of the webrev, derived from the workspace name or output directory;
# in the future this could potentially be an option.
#
if [[ -n $oflag ]]; then
	WNAME=${WDIR##*/}
else
	WNAME=${CWS##*/}
fi

# Make sure remote target is well formed for remote upload/delete.
if [[ -n $Dflag || -n $Uflag ]]; then
	#
	# If remote target is not specified, build it from scratch using
	# the default values.
	#
	if [[ -z $tflag ]]; then
		remote_target=${DEFAULT_REMOTE_HOST}:${WNAME}
	else
		#
		# Check upload target prefix first.
		#
		if [[ "${remote_target}" != ${rsync_prefix}* &&
		    "${remote_target}" != ${ssh_prefix}* ]]; then
			print "ERROR: invalid prefix of upload URI" \
			    "($remote_target)"
			exit 1
		fi
		#
		# If destination specification is not in the form of
		# host_spec:remote_dir then assume it is just remote hostname
		# and append a colon and destination directory formed from
		# local webrev directory name.
		#
		typeset target_no_prefix=${remote_target##*://}
		if [[ ${target_no_prefix} == *:* ]]; then
			if [[ "${remote_target}" == *: ]]; then
				remote_target=${remote_target}${WNAME}
			fi
		else
			if [[ ${target_no_prefix} == */* ]]; then
				print "ERROR: badly formed upload URI" \
					"($remote_target)"
				exit 1
			else
				remote_target=${remote_target}:${WNAME}
			fi
		fi
	fi

	#
	# Strip trailing slash. Each upload method will deal with directory
	# specification separately.
	#
	remote_target=${remote_target%/}
fi

#
# Option -D by itself (option -U not present) implies no webrev generation.
#
if [[ -z $Uflag && -n $Dflag ]]; then
	delete_webrev 1 1
	exit $?
fi

#
# Do not generate the webrev, just upload it or delete it.
#
if [[ -n $nflag ]]; then
	if [[ -n $Dflag ]]; then
		delete_webrev 1 1
		(( $? == 0 )) || exit $?
	fi
	if [[ -n $Uflag ]]; then
		upload_webrev
		exit $?
	fi
fi

if [ "${WDIR%%/*}" ]; then
	WDIR=$PWD/$WDIR
fi

if [[ ! -d $WDIR ]]; then
	mkdir -p $WDIR
	(( $? != 0 )) && exit 1
fi

#
# Summarize what we're going to do.
#
print "      Workspace: ${PRETTY_CWS:-$CWS}"
if [[ -n $parent_webrev ]]; then
	print "Compare against: webrev at $parent_webrev"
else
	print "Compare against: ${PRETTY_PWS:-$PWS}"
fi

[[ -n $INCLUDE_FILE ]] && print "      Including: $INCLUDE_FILE"
print "      Output to: $WDIR"

#
# Save the file list in the webrev dir
#
[[ ! $FLIST -ef $WDIR/file.list ]] && cp $FLIST $WDIR/file.list

rm -f $WDIR/$WNAME.patch
rm -f $WDIR/$WNAME.ps
rm -f $WDIR/$WNAME.pdf

touch $WDIR/$WNAME.patch

print "   Output Files:"

#
# Clean up the file list: Remove comments, blank lines and env variables.
#
$SED -e "s/#.*$//" -e "/=/d" -e "/^[   ]*$/d" $FLIST > /tmp/$$.flist.clean
FLIST=/tmp/$$.flist.clean

#
# For Mercurial, create a cache of manifest entries.
#
if [[ $SCM_MODE == "mercurial" ]]; then
	#
	# Transform the FLIST into a temporary sed script that matches
	# relevant entries in the Mercurial manifest as follows:
	# 1) The script will be used against the parent revision manifest,
	#    so for FLIST lines that have two filenames (a renamed file)
	#    keep only the old name.
	# 2) Escape all forward slashes the filename.
	# 3) Change the filename into another sed command that matches
	#    that file in "hg manifest -v" output:  start of line, three
	#    octal digits for file permissions, space, a file type flag
	#    character, space, the filename, end of line.
	# 4) Eliminate any duplicate entries.  (This can occur if a
	#    file has been used as the source of an hg cp and it's
	#    also been modified in the same changeset.)
	#
	SEDFILE=/tmp/$$.manifest.sed
	$SED '
		s#^[^ ]* ##
		s#/#\\\/#g
		s#^.*$#/^... . &$/p#
	' < $FLIST | $SORT -u > $SEDFILE

	#
	# Apply the generated script to the output of "hg manifest -v"
	# to get the relevant subset for this webrev.
	#
	HG_PARENT_MANIFEST=/tmp/$$.manifest
	hg -R $CWS manifest -v -r $HG_PARENT |
	    $SED -n -f $SEDFILE > $HG_PARENT_MANIFEST
fi

#
# First pass through the files: generate the per-file webrev HTML-files.
#
cat $FLIST | while read LINE
do
	set - $LINE
	P=$1

	#
	# Normally, each line in the file list is just a pathname of a
	# file that has been modified or created in the child.  A file
	# that is renamed in the child workspace has two names on the
	# line: new name followed by the old name.
	#
	oldname=""
	oldpath=""
	rename=
	if [[ $# -eq 2 ]]; then
		PP=$2			# old filename
		if [[ -f $PP ]]; then
			oldname=" (copied from $PP)"
		else
			oldname=" (renamed from $PP)"
		fi
		oldpath="$PP"
		rename=1
		PDIR=${PP%/*}
		if [[ $PDIR == $PP ]]; then
			PDIR="."   # File at root of workspace
		fi

		PF=${PP##*/}

		DIR=${P%/*}
		if [[ $DIR == $P ]]; then
			DIR="."   # File at root of workspace
		fi

		F=${P##*/}

	else
		DIR=${P%/*}
		if [[ "$DIR" == "$P" ]]; then
			DIR="."   # File at root of workspace
		fi

		F=${P##*/}

		PP=$P
		PDIR=$DIR
		PF=$F
	fi

	COMM=`getcomments html $P $PP`

	print "\t$P$oldname\n\t\t\c"

	# Make the webrev mirror directory if necessary
	mkdir -p $WDIR/$DIR

	#
	# We stash old and new files into parallel directories in $WDIR
	# and do our diffs there.  This makes it possible to generate
	# clean looking diffs which don't have absolute paths present.
	#

	build_old_new "$WDIR" "$PWS" "$PDIR" "$PF" "$CWS" "$DIR" "$F" || \
	    continue

	#
	# Keep the old PWD around, so we can safely switch back after
	# diff generation, such that build_old_new runs in a
	# consistent environment.
	#
	OWD=$PWD
	cd $WDIR/raw_files

	#
	# The "git apply" command does not tolerate the spurious
	# "./" that we otherwise insert; be careful not to include
	# it in the paths that we pass to diff(1).
	#
	if [[ $PDIR == "." ]]; then
		ofile=old/$PF
	else
		ofile=old/$PDIR/$PF
	fi
	if [[ $DIR == "." ]]; then
		nfile=new/$F
	else
		nfile=new/$DIR/$F
	fi

	mv_but_nodiff=
	cmp $ofile $nfile > /dev/null 2>&1
	if [[ $? == 0 && $rename == 1 ]]; then
		mv_but_nodiff=1
	fi

	#
	# If we have old and new versions of the file then run the appropriate
	# diffs.  This is complicated by a couple of factors:
	#
	#	- renames must be handled specially: we emit a 'remove'
	#	  diff and an 'add' diff
	#	- new files and deleted files must be handled specially
	#	- GNU patch doesn't interpret the output of illumos diff
	#	  properly when it comes to adds and deletes.  We need to
	#	  do some "cleansing" transformations:
	#	    [to add a file] @@ -1,0 +X,Y @@  -->  @@ -0,0 +X,Y @@
	#	    [to del a file] @@ -X,Y +1,0 @@  -->  @@ -X,Y +0,0 @@
	#
	cleanse_rmfile="$SED 's/^\(@@ [0-9+,-]*\) [0-9+,-]* @@$/\1 +0,0 @@/'"
	cleanse_newfile="$SED 's/^@@ [0-9+,-]* \([0-9+,-]* @@\)$/@@ -0,0 \1/'"

	rm -f $WDIR/$DIR/$F.patch
	if [[ -z $rename ]]; then
		if [ ! -f "$ofile" ]; then
			diff -u /dev/null $nfile | sh -c "$cleanse_newfile" \
			    > $WDIR/$DIR/$F.patch
		elif [ ! -f "$nfile" ]; then
			diff -u $ofile /dev/null | sh -c "$cleanse_rmfile" \
			    > $WDIR/$DIR/$F.patch
		else
			diff -u $ofile $nfile > $WDIR/$DIR/$F.patch
		fi
	else
		diff -u $ofile /dev/null | sh -c "$cleanse_rmfile" \
		    > $WDIR/$DIR/$F.patch

		diff -u /dev/null $nfile | sh -c "$cleanse_newfile" \
		    >> $WDIR/$DIR/$F.patch
	fi

	#
	# Tack the patch we just made onto the accumulated patch for the
	# whole wad.
	#
	cat $WDIR/$DIR/$F.patch >> $WDIR/$WNAME.patch
	print " patch\c"

	if [[ -f $ofile && -f $nfile && -z $mv_but_nodiff ]]; then
		${CDIFFCMD:-diff -bt -C 5} $ofile $nfile > $WDIR/$DIR/$F.cdiff
		diff_to_html $F $DIR/$F "C" "$COMM" < $WDIR/$DIR/$F.cdiff \
		    > $WDIR/$DIR/$F.cdiff.html
		print " cdiffs\c"

		${UDIFFCMD:-diff -bt -U 5} $ofile $nfile > $WDIR/$DIR/$F.udiff
		diff_to_html $F $DIR/$F "U" "$COMM" < $WDIR/$DIR/$F.udiff \
		    > $WDIR/$DIR/$F.udiff.html
		print " udiffs\c"

		if [[ -x $WDIFF ]]; then
			$WDIFF -c "$COMM" \
			    -t "$WNAME Wdiff $DIR/$F" $ofile $nfile > \
			    $WDIR/$DIR/$F.wdiff.html 2>/dev/null
			if [[ $? -eq 0 ]]; then
				print " wdiffs\c"
			else
				print " wdiffs[fail]\c"
			fi
		fi

		sdiff_to_html $ofile $nfile $F $DIR "$COMM" \
		    > $WDIR/$DIR/$F.sdiff.html
		print " sdiffs\c"
		print " frames\c"

		rm -f $WDIR/$DIR/$F.cdiff $WDIR/$DIR/$F.udiff
		difflines $ofile $nfile > $WDIR/$DIR/$F.count
	elif [[ -f $ofile && -f $nfile && -n $mv_but_nodiff ]]; then
		# renamed file: may also have differences
		difflines $ofile $nfile > $WDIR/$DIR/$F.count
	elif [[ -f $nfile ]]; then
		# new file: count added lines
		difflines /dev/null $nfile > $WDIR/$DIR/$F.count
	elif [[ -f $ofile ]]; then
		# old file: count deleted lines
		difflines $ofile /dev/null > $WDIR/$DIR/$F.count
	fi

	#
	# Check if it's man page, and create plain text, html and raw (ascii)
	# output for the new version, as well as diffs against old version.
	#
	if [[ -f "$nfile" && "$nfile" = *.+([0-9])*([a-zA-Z]) && \
	    -x $MANDOC && -x $COL ]]; then
		$MANDOC -Tascii $nfile | $COL -b > $nfile.man.txt
		source_to_html txt < $nfile.man.txt > $nfile.man.txt.html
		print " man-txt\c"
		print "$MANCSS" > $WDIR/raw_files/new/$DIR/man.css
		$MANDOC -Thtml -Ostyle=man.css $nfile > $nfile.man.html
		print " man-html\c"
		$MANDOC -Tascii $nfile > $nfile.man.raw
		print " man-raw\c"
		if [[ -f "$ofile" && -z $mv_but_nodiff ]]; then
			$MANDOC -Tascii $ofile | $COL -b > $ofile.man.txt
			${CDIFFCMD:-diff -bt -C 5} $ofile.man.txt \
			    $nfile.man.txt > $WDIR/$DIR/$F.man.cdiff
			diff_to_html $F $DIR/$F "C" "$COMM" < \
			    $WDIR/$DIR/$F.man.cdiff > \
			    $WDIR/$DIR/$F.man.cdiff.html
			print " man-cdiffs\c"
			${UDIFFCMD:-diff -bt -U 5} $ofile.man.txt \
			    $nfile.man.txt > $WDIR/$DIR/$F.man.udiff
			diff_to_html $F $DIR/$F "U" "$COMM" < \
			    $WDIR/$DIR/$F.man.udiff > \
			    $WDIR/$DIR/$F.man.udiff.html
			print " man-udiffs\c"
			if [[ -x $WDIFF ]]; then
				$WDIFF -c "$COMM" -t "$WNAME Wdiff $DIR/$F" \
				    $ofile.man.txt $nfile.man.txt > \
				    $WDIR/$DIR/$F.man.wdiff.html 2>/dev/null
				if [[ $? -eq 0 ]]; then
					print " man-wdiffs\c"
				else
					print " man-wdiffs[fail]\c"
				fi
			fi
			sdiff_to_html $ofile.man.txt $nfile.man.txt $F.man $DIR \
			    "$COMM" > $WDIR/$DIR/$F.man.sdiff.html
			print " man-sdiffs\c"
			print " man-frames\c"
		fi
		rm -f $ofile.man.txt $nfile.man.txt
		rm -f $WDIR/$DIR/$F.man.cdiff $WDIR/$DIR/$F.man.udiff
	fi

	#
	# Now we generate the postscript for this file.  We generate diffs
	# only in the event that there is delta, or the file is new (it seems
	# tree-killing to print out the contents of deleted files).
	#
	if [[ -f $nfile ]]; then
		ocr=$ofile
		[[ ! -f $ofile ]] && ocr=/dev/null

		if [[ -z $mv_but_nodiff ]]; then
			textcomm=`getcomments text $P $PP`
			if [[ -x $CODEREVIEW ]]; then
				$CODEREVIEW -y "$textcomm" \
				    -e $ocr $nfile \
				    > /tmp/$$.psfile 2>/dev/null &&
				    cat /tmp/$$.psfile >> $WDIR/$WNAME.ps
				if [[ $? -eq 0 ]]; then
					print " ps\c"
				else
					print " ps[fail]\c"
				fi
			fi
		fi
	fi

	if [[ -f $ofile ]]; then
		source_to_html Old $PP < $ofile > $WDIR/$DIR/$F-.html
		print " old\c"
	fi

	if [[ -f $nfile ]]; then
		source_to_html New $P < $nfile > $WDIR/$DIR/$F.html
		print " new\c"
	fi

	cd $OWD

	print
done

frame_nav_js > $WDIR/ancnav.js
frame_navigation > $WDIR/ancnav.html

if [[ ! -f $WDIR/$WNAME.ps ]]; then
	print " Generating PDF: Skipped: no output available"
elif [[ -x $CODEREVIEW && -x $PS2PDF ]]; then
	print " Generating PDF: \c"
	fix_postscript $WDIR/$WNAME.ps | $PS2PDF - > $WDIR/$WNAME.pdf
	print "Done."
else
	print " Generating PDF: Skipped: missing 'ps2pdf' or 'codereview'"
fi

# If we're in OpenSolaris mode and there's a closed dir under $WDIR,
# delete it - prevent accidental publishing of closed source

if [[ -n "$Oflag" ]]; then
	$FIND $WDIR -type d -name closed -exec /bin/rm -rf {} \;
fi

# Now build the index.html file that contains
# links to the source files and their diffs.

cd $CWS

# Save total changed lines for Code Inspection.
print "$TOTL" > $WDIR/TotalChangedLines

print "     index.html: \c"
INDEXFILE=$WDIR/index.html
exec 3<&1			# duplicate stdout to FD3.
exec 1<&-			# Close stdout.
exec > $INDEXFILE		# Open stdout to index file.

print "$HTML<head>$STDHEAD"
print "<title>$WNAME</title>"
print "</head>"
print "<body id=\"SUNWwebrev\">"
print "<div class=\"summary\">"
print "<h2>Code Review for $WNAME</h2>"

print "<table>"

#
# Get the preparer's name:
#
# If the SCM detected is Mercurial, and the configuration property
# ui.username is available, use that, but be careful to properly escape
# angle brackets (HTML syntax characters) in the email address.
#
# Otherwise, use the current userid in the form "John Doe (jdoe)", but
# to maintain compatibility with passwd(4), we must support '&' substitutions.
#
preparer=
if [[ "$SCM_MODE" == mercurial ]]; then
	preparer=`hg showconfig ui.username 2>/dev/null`
	if [[ -n "$preparer" ]]; then
		preparer="$(echo "$preparer" | html_quote)"
	fi
fi
if [[ -z "$preparer" ]]; then
	preparer=$(
	    $PERL -e '
	        ($login, $pw, $uid, $gid, $quota, $cmt, $gcos) = getpwuid($<);
	        if ($login) {
	            $gcos =~ s/\&/ucfirst($login)/e;
	            printf "%s (%s)\n", $gcos, $login;
	        } else {
	            printf "(unknown)\n";
	        }
	')
fi

PREPDATE=$(LC_ALL=C /usr/bin/date +%Y-%b-%d\ %R\ %z\ %Z)
print "<tr><th>Prepared by:</th><td>$preparer on $PREPDATE</td></tr>"
print "<tr><th>Workspace:</th><td>${PRETTY_CWS:-$CWS}"
print "</td></tr>"
print "<tr><th>Compare against:</th><td>"
if [[ -n $parent_webrev ]]; then
	print "webrev at $parent_webrev"
else
	print "${PRETTY_PWS:-$PWS}"
fi
print "</td></tr>"
print "<tr><th>Summary of changes:</th><td>"
printCI $TOTL $TINS $TDEL $TMOD $TUNC
print "</td></tr>"

if [[ -f $WDIR/$WNAME.patch ]]; then
	wpatch_url="$(print $WNAME.patch | url_encode)"
	print "<tr><th>Patch of changes:</th><td>"
	print "<a href=\"$wpatch_url\">$WNAME.patch</a></td></tr>"
fi
if [[ -f $WDIR/$WNAME.pdf ]]; then
	wpdf_url="$(print $WNAME.pdf | url_encode)"
	print "<tr><th>Printable review:</th><td>"
	print "<a href=\"$wpdf_url\">$WNAME.pdf</a></td></tr>"
fi

if [[ -n "$iflag" ]]; then
	print "<tr><th>Author comments:</th><td><div>"
	cat /tmp/$$.include
	print "</div></td></tr>"
fi
print "</table>"
print "</div>"

#
# Second pass through the files: generate the rest of the index file
#
cat $FLIST | while read LINE
do
	set - $LINE
	P=$1

	if [[ $# == 2 ]]; then
		PP=$2
		oldname="$PP"
	else
		PP=$P
		oldname=""
	fi

	mv_but_nodiff=
	cmp $WDIR/raw_files/old/$PP $WDIR/raw_files/new/$P > /dev/null 2>&1
	if [[ $? == 0 && -n "$oldname" ]]; then
		mv_but_nodiff=1
	fi

	DIR=${P%/*}
	if [[ $DIR == $P ]]; then
		DIR="."   # File at root of workspace
	fi

	# Avoid processing the same file twice.
	# It's possible for renamed files to
	# appear twice in the file list

	F=$WDIR/$P

	print "<p>"

	# If there's a diffs file, make diffs links

	if [[ -f $F.cdiff.html ]]; then
		cdiff_url="$(print $P.cdiff.html | url_encode)"
		udiff_url="$(print $P.udiff.html | url_encode)"
		sdiff_url="$(print $P.sdiff.html | url_encode)"
		frames_url="$(print $P.frames.html | url_encode)"
		print "<a href=\"$cdiff_url\">Cdiffs</a>"
		print "<a href=\"$udiff_url\">Udiffs</a>"
		if [[ -f $F.wdiff.html && -x $WDIFF ]]; then
			wdiff_url="$(print $P.wdiff.html | url_encode)"
			print "<a href=\"$wdiff_url\">Wdiffs</a>"
		fi
		print "<a href=\"$sdiff_url\">Sdiffs</a>"
		print "<a href=\"$frames_url\">Frames</a>"
	else
		print " ------ ------"
		if [[ -x $WDIFF ]]; then
			print " ------"
		fi
		print " ------ ------"
	fi

	# If there's an old file, make the link

	if [[ -f $F-.html ]]; then
		oldfile_url="$(print $P-.html | url_encode)"
		print "<a href=\"$oldfile_url\">Old</a>"
	else
		print " ---"
	fi

	# If there's an new file, make the link

	if [[ -f $F.html ]]; then
		newfile_url="$(print $P.html | url_encode)"
		print "<a href=\"$newfile_url\">New</a>"
	else
		print " ---"
	fi

	if [[ -f $F.patch ]]; then
		patch_url="$(print $P.patch | url_encode)"
		print "<a href=\"$patch_url\">Patch</a>"
	else
		print " -----"
	fi

	if [[ -f $WDIR/raw_files/new/$P ]]; then
		rawfiles_url="$(print raw_files/new/$P | url_encode)"
		print "<a href=\"$rawfiles_url\">Raw</a>"
	else
		print " ---"
	fi

	print "<b>$P</b>"

	# For renamed files, clearly state whether or not they are modified
	if [[ -f "$oldname" ]]; then
		if [[ -n "$mv_but_nodiff" ]]; then
			print "<i>(copied from $oldname)</i>"
		else
			print "<i>(copied and modified from $oldname)</i>"
		fi
	elif [[ -n "$oldname" ]]; then
		if [[ -n "$mv_but_nodiff" ]]; then
			print "<i>(renamed from $oldname)</i>"
		else
			print "<i>(renamed and modified from $oldname)</i>"
		fi
	fi

	# If there's an old file, but no new file, the file was deleted
	if [[ -f $F-.html && ! -f $F.html ]]; then
		print " <i>(deleted)</i>"
	fi

	# Check for usr/closed and deleted_files/usr/closed
	if [ ! -z "$Oflag" ]; then
		if [[ $P == usr/closed/* || \
		    $P == deleted_files/usr/closed/* ]]; then
			print "&nbsp;&nbsp;<i>Closed source: omitted from" \
			    "this review</i>"
		fi
	fi

	manpage=
	if [[ -f $F.man.cdiff.html || \
	    -f $WDIR/raw_files/new/$P.man.txt.html ]]; then
		manpage=1
		print "<br/>man:"
	fi

	if [[ -f $F.man.cdiff.html ]]; then
		mancdiff_url="$(print $P.man.cdiff.html | url_encode)"
		manudiff_url="$(print $P.man.udiff.html | url_encode)"
		mansdiff_url="$(print $P.man.sdiff.html | url_encode)"
		manframes_url="$(print $P.man.frames.html | url_encode)"
		print "<a href=\"$mancdiff_url\">Cdiffs</a>"
		print "<a href=\"$manudiff_url\">Udiffs</a>"
		if [[ -f $F.man.wdiff.html && -x $WDIFF ]]; then
			manwdiff_url="$(print $P.man.wdiff.html | url_encode)"
			print "<a href=\"$manwdiff_url\">Wdiffs</a>"
		fi
		print "<a href=\"$mansdiff_url\">Sdiffs</a>"
		print "<a href=\"$manframes_url\">Frames</a>"
	elif [[ -n $manpage ]]; then
		print " ------ ------"
		if [[ -x $WDIFF ]]; then
			print " ------"
		fi
		print " ------ ------"
	fi

	if [[ -f $WDIR/raw_files/new/$P.man.txt.html ]]; then
		mantxt_url="$(print raw_files/new/$P.man.txt.html | url_encode)"
		print "<a href=\"$mantxt_url\">TXT</a>"
		manhtml_url="$(print raw_files/new/$P.man.html | url_encode)"
		print "<a href=\"$manhtml_url\">HTML</a>"
		manraw_url="$(print raw_files/new/$P.man.raw | url_encode)"
		print "<a href=\"$manraw_url\">Raw</a>"
	elif [[ -n $manpage ]]; then
		print " --- ---- ---"
	fi

	print "</p>"

	# Insert delta comments
	print "<blockquote><pre>"
	getcomments html $P $PP
	print "</pre>"

	# Add additional comments comment
	print "<!-- Add comments to explain changes in $P here -->"

	# Add count of changes.
	if [[ -f $F.count ]]; then
	    cat $F.count
	    rm $F.count
	fi

	if [[ $SCM_MODE == "mercurial" ||
	    $SCM_MODE == "unknown" ]]; then
		# Include warnings for important file mode situations:
		# 1) New executable files
		# 2) Permission changes of any kind
		# 3) Existing executable files
		old_mode=
		if [[ -f $WDIR/raw_files/old/$PP ]]; then
			old_mode=`get_file_mode $WDIR/raw_files/old/$PP`
		fi

		new_mode=
		if [[ -f $WDIR/raw_files/new/$P ]]; then
			new_mode=`get_file_mode $WDIR/raw_files/new/$P`
		fi

		if [[ -z "$old_mode" && "$new_mode" = *[1357]* ]]; then
			print "<span class=\"chmod\">"
			print "<p>new executable file: mode $new_mode</p>"
			print "</span>"
		elif [[ -n "$old_mode" && -n "$new_mode" &&
		    "$old_mode" != "$new_mode" ]]; then
			print "<span class=\"chmod\">"
			print "<p>mode change: $old_mode to $new_mode</p>"
			print "</span>"
		elif [[ "$new_mode" = *[1357]* ]]; then
			print "<span class=\"chmod\">"
			print "<p>executable file: mode $new_mode</p>"
			print "</span>"
		fi
	fi

	print "</blockquote>"
done

print
print
print "<hr></hr>"
print "<p style=\"font-size: small\">"
print "This code review page was prepared using <b>$0</b>."
print "Webrev is maintained by the <a href=\"http://www.illumos.org\">"
print "illumos</a> project.  The latest version may be obtained"
print "<a href=\"http://src.illumos.org/source/xref/illumos-gate/usr/src/tools/scripts/webrev.sh\">here</a>.</p>"
print "</body>"
print "</html>"

exec 1<&-			# Close FD 1.
exec 1<&3			# dup FD 3 to restore stdout.
exec 3<&-			# close FD 3.

print "Done."

#
# If remote deletion was specified and fails do not continue.
#
if [[ -n $Dflag ]]; then
	delete_webrev 1 1
	(( $? == 0 )) || exit $?
fi

if [[ -n $Uflag ]]; then
	upload_webrev
	exit $?
fi
