#!/usr/bin/ksh -p
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

# Upload the webrev via rsync. Return 0 on success, 1 on error.
function rsync_upload
{
	if (( $# != 1 )); then
		return 1
	fi

	typeset dst=$1

	print "        Syncing: \c"
	# end source directory with a slash in order to copy just
	# directory contents, not the whole directory
	$RSYNC -r -q $WDIR/ $dst
	if (( $? != 0 )); then
		print "failed to sync webrev directory " \
		    "'$WDIR' to '$dst'"
		return 1
	fi

	print "Done."
	return 0
}

# Upload the webrev via SSH. Return 0 on success, 1 on error.
function ssh_upload
{
	if (( $# != 1 )); then
		print "ssh_upload: wrong usage"
		return 1
	fi

	typeset dst=$1
	typeset -r host_spec=${dst%%:*}
	typeset -r dir_spec=${dst#*:}

	# if the deletion was explicitly requested there is no need
	# to perform it again
	if [[ -z $Dflag ]]; then
		# we do not care about return value because this might be
		# the first time this directory is uploaded
		delete_webrev 0
	fi

	# if the supplied path is absolute we assume all directories are
	# created, otherwise try to create all directories in the path
	# except the last one which will be created by scp
	if [[ "${dir_spec}" == */* && "${dir_spec}" != /* ]]; then
		print "  Creating dirs: \c"
		typeset -r dirs_mk=${dir_spec%/*}
		typeset -r batch_file_mkdir=$( $MKTEMP /tmp/$webrev_mkdir.XXX )
                OLDIFS=$IFS
                IFS=/
                mk=
                for dir in $dirs_mk; do
                        if [[ -z $mk ]]; then
                                mk=$dir
                        else
                                mk=$mk/$dir
                        fi
                        echo "mkdir $mk" >> $batch_file_mkdir
                done
                IFS=$OLDIFS
		$SFTP -b $batch_file_mkdir $host_spec 2>/dev/null 1>&2
		if (( $? != 0 )); then
			echo "Failed to create remote directories"
			rm -f $batch_file_mkdir
			return 1
		fi
		rm -f $batch_file_mkdir
		print "Done."
	fi

	print "      Uploading: \c"
	$SCP -q -C -B -o PreferredAuthentications=publickey -r \
		$WDIR $dst
	if (( $? != 0 )); then
		print "failed to upload webrev directory" \
		    "'$WDIR' to '$dst'"
		return 1
	fi

	print "Done."
	return 0
}

#
# Delete webrev at remote site. Return 0 on success, 1 or exit code from sftp
# on failure.
#
function delete_webrev
{
	if (( $# != 1 )); then
		print "delete_webrev: wrong usage"
		return 1
	fi

	# Strip the transport specification part of remote target first.
	typeset -r stripped_target=${remote_target##*://}
	typeset -r host_spec=${stripped_target%%:*}
	typeset -r dir_spec=${stripped_target#*:}
	integer -r check=$1
	typeset dir_rm

	# Do not accept an absolute path.
	if [[ ${dir_spec} == /* ]]; then
		return 1
	fi

	# Strip the ending slash.
	if [[ ${dir_spec} == */ ]]; then
		dir_rm=${dir_spec%%/}
	else
		dir_rm=${dir_spec}
	fi

	print "Removing remote: \c"
	if [[ -z "$dir_rm" ]]; then
		print "empty directory for removal"
		return 1
	fi

	# Prepare batch file.
	typeset -r batch_file_rm=$( $MKTEMP /tmp/webrev_remove.XXX )
	if [[ -z $batch_file_rm ]]; then
		print "Cannot create temporary file"
		return 1
	fi
	print "rename $dir_rm $TRASH_DIR/removed.$$" > $batch_file_rm

	# Perform remote deletion and remove the batch file.
	$SFTP -b $batch_file_rm $host_spec 2>/dev/null 1>&2
	integer -r ret=$?
	rm -f $batch_file_rm
	if (( $ret != 0 && $check > 0 )); then
		print "Failed"
		return $ret
	fi
	print "Done."

	return 0
}

#
# Upload webrev to remote site
#
function upload_webrev
{
	typeset -r rsync_prefix="rsync://"
	typeset -r ssh_prefix="ssh://"

	if [[ ! -d "$WDIR" ]]; then
		echo "webrev directory '$WDIR' does not exist"
		return 1
	fi

	# Perform a late check to make sure we do not upload closed source
	# to remote target when -n is used. If the user used custom remote
	# target he probably knows what he is doing.
	if [[ -n $nflag && -z $tflag ]]; then
		$FIND $WDIR -type d -name closed \
			| $GREP closed >/dev/null
		if (( $? == 0 )); then
			echo "directory '$WDIR' contains \"closed\" directory"
			return 1
		fi
	fi

	# we have the URI for remote destination now so let's start the upload
	if [[ -n $tflag ]]; then
		if [[ "${remote_target}" == ${rsync_prefix}?* ]]; then
			rsync_upload ${remote_target##$rsync_prefix}
			return $?
		elif [[ "${remote_target}" == ${ssh_prefix}?* ]]; then
			ssh_upload ${remote_target##$ssh_prefix}
			return $?
		else
			echo "invalid upload URI ($remote_target)"
			return 1
		fi
	else
		# try rsync first and fallback to SSH in case it fails
		rsync_upload ${remote_target}
		if (( $? != 0 )); then
			echo "rsync upload failed, falling back to SSH"
			ssh_upload ${remote_target}
		fi
		return $?
	fi

	return 0
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
	sed -e "s/&/\&amp;/g" -e "s/</\&lt;/g" -e "s/>/\&gt;/g" "$@" | expand
}

#
# input_cmd | bug2url | output_cmd
#
# Scan for bugids and insert <a> links to the relevent bug database.
#
bug2url()
{
	sed -e 's|[0-9]\{5,\}|<a href=\"'$BUGURL'&\">&</a>|g'
}

#
# input_cmd | sac2url | output_cmd
#
# Scan for ARC cases and insert <a> links to the relevent SAC database.
# This is slightly complicated because inside the SWAN, SAC cases are
# grouped by ARC: PSARC/2006/123.  But on OpenSolaris.org, they are
# referenced as 2006/123 (without labelling the ARC).
#
sac2url()
{
	if [[ -z "$Oflag" ]]; then
	    sed -e 's|\([A-Z]\{1,2\}ARC\)[ /]\([0-9]\{4\}\)/\([0-9]\{3\}\)|<a href=\"'$SACURL'/\1/\2/\3\">\1 \2/\3</a>|g'
	else
	    sed -e 's|\([A-Z]\{1,2\}ARC\)[ /]\([0-9]\{4\}\)/\([0-9]\{3\}\)|<a href=\"'$SACURL'/\2/\3\">\1 \2/\3</a>|g'
	fi
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
	    <script type="text/javascript" src="$RTOP/ancnav.js"></script>
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
	  <frame src="$RTOP/ancnav.html" scrolling="no" marginwidth="0"
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
# 	- removing all extraneous headers/trailers
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
	typeset ret=""
	if [[ $2 == $cur ]]; then   # Should never happen.
		# Should never happen.
		print -u2 "\nWARNING: relative_dir: \"$1\" not relative "
		print -u2 "to \"$2\".  Check input paths.  Framed webrev "
		print -u2 "will not be relocatable!"
		print $2
		return
	fi

	while [[ -n ${cur} ]];
	do
		cur=${cur%%*(/)*([!/])}
		if [[ -z $ret ]]; then
			ret=".."
		else
			ret="../$ret"
		fi
	done
	print $ret
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
var scrolling=0;
var sfactor = 3;
var scount=10;

function scrollByPix() {
	if (scount<=0) {
		sfactor*=1.2;
		scount=10;
	}
	parent.lhs.scrollBy(0,sfactor);
	parent.rhs.scrollBy(0,sfactor);
	scount--;
}

function scrollToAnc(num) {

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

	parent.lhs.scrollBy(0,-30);
	parent.rhs.scrollBy(0,-30);
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

function stopScroll() {
	if (scrolling==1) {
		clearInterval(myInt);
		scrolling=0;
	}
}

function startScroll() {
	stopScroll();
	scrolling=1;
	myInt=setInterval("scrollByPix()",10);
}

function handlePress(b) {

	switch (b) {
	    case 1 :
		scrollToAnc(-1);
		break;
	    case 2 :
		scrollToAnc(getAncValue() - 1);
		break;
	    case 3 :
		sfactor=-3;
		startScroll();
		break;
	    case 4 :
		sfactor=3;
		startScroll();
		break;
	    case 5 :
		scrollToAnc(getAncValue() + 1);
		break;
	    case 6 :
		scrollToAnc(999999);
		break;
	}
}

function handleRelease(b) {
	stopScroll();
}

function keypress(ev) {
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

function ValidateDiffNum(){
	val = parent.nav.document.diff.display.value;
	if (val == "EOF") {
		scrollToAnc(999999);
		return;
	}

	if (val == "BOF") {
		scrollToAnc(0);
		return;
	}

        i=parseInt(val);
        if (isNaN(i)) {
                parent.nav.document.diff.display.value = getAncValue();
        } else {
                scrollToAnc(i);
        }
        return false;
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
# comments_from_teamware {text|html} parent-file child-file
#
# Find the first delta in the child that's not in the parent.  Get the
# newest delta from the parent, get all deltas from the child starting
# with that delta, and then get all info starting with the second oldest
# delta in that list (the first delta unique to the child).
#
# This code adapted from Bill Shannon's "spc" script
#
comments_from_teamware()
{
	fmt=$1
	pfile=$PWS/$2
	cfile=$CWS/$3

	if [[ ! -f $PWS/${2%/*}/SCCS/s.${2##*/} && -n $RWS ]]; then
		pfile=$RWS/$2
	fi

	if [[ -f $pfile ]]; then
		psid=$($SCCS prs -d:I: $pfile 2>/dev/null)
	else
		psid=1.1
	fi

	set -A sids $($SCCS prs -l -r$psid -d:I: $cfile 2>/dev/null)
	N=${#sids[@]}

	nawkprg='
		/^COMMENTS:/	{p=1; continue}
		/^D [0-9]+\.[0-9]+/ {printf "--- %s ---\n", $2; p=0; }
		NF == 0u	{ continue }
		{if (p==0) continue; print $0 }'

	if [[ $N -ge 2 ]]; then
		sid1=${sids[$((N-2))]}	# Gets 2nd to last sid

		if [[ $fmt == "text" ]]; then
			$SCCS prs -l -r$sid1 $cfile  2>/dev/null | \
			    $AWK "$nawkprg"
			return
		fi

		$SCCS prs -l -r$sid1 $cfile  2>/dev/null | \
		    html_quote | bug2url | sac2url | $AWK "$nawkprg"
	fi
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

	print -- "$comm" | html_quote | bug2url | sac2url

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
	else
		if [[ $SCM_MODE == "teamware" ]]; then
			comments_from_teamware $fmt $pp $p
		fi
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
# flist_from_teamware [ <args-to-putback-n> ]
#
# Generate the file list by extracting file names from a putback -n.  Some
# names may come from the "update/create" messages and others from the
# "currently checked out" warning.  Renames are detected here too.  Extract
# values for CODEMGR_WS and CODEMGR_PARENT from the output of the putback
# -n as well, but remove them if they are already defined.
#
function flist_from_teamware
{
	if [[ -n $codemgr_parent && -z $parent_webrev ]]; then
		if [[ ! -d $codemgr_parent/Codemgr_wsdata ]]; then
			print -u2 "parent $codemgr_parent doesn't look like a" \
			    "valid teamware workspace"
			exit 1
		fi
		parent_args="-p $codemgr_parent"
	fi

	print " File list from: 'putback -n $parent_args $*' ... \c"

	putback -n $parent_args $* 2>&1 |
	    $AWK '
		/^update:|^create:/	{print $2}
		/^Parent workspace:/	{printf("CODEMGR_PARENT=%s\n",$3)}
		/^Child workspace:/	{printf("CODEMGR_WS=%s\n",$3)}
		/^The following files are currently checked out/ {p = 1; continue}
		NF == 0			{p=0 ; continue}
		/^rename/		{old=$3}
		$1 == "to:"		{print $2, old}
		/^"/			{continue}
		p == 1			{print $1}' |
	    sort -r -k 1,1 -u | sort > $FLIST

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
	eval `sed -e "s/#.*$//" $FLIST | $GREP = `

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
	ppath=$ppath:/opt/teamware/bin:/opt/onbld/bin
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

function build_old_new_teamware
{
	typeset olddir="$1"
	typeset newdir="$2"

	# If the child's version doesn't exist then
	# get a readonly copy.

	if [[ ! -f $CWS/$DIR/$F && -f $CWS/$DIR/SCCS/s.$F ]]; then
		$SCCS get -s -p $CWS/$DIR/$F > $CWS/$DIR/$F
	fi

	# The following two sections propagate file permissions the
	# same way SCCS does.  If the file is already under version
	# control, always use permissions from the SCCS/s.file.  If
	# the file is not under SCCS control, use permissions from the
	# working copy.  In all cases, the file copied to the webrev
	# is set to read only, and group/other permissions are set to
	# match those of the file owner.  This way, even if the file
	# is currently checked out, the webrev will display the final
	# permissions that would result after check in.

	#
	# Snag new version of file.
	#
	rm -f $newdir/$DIR/$F
	cp $CWS/$DIR/$F $newdir/$DIR/$F
	if [[ -f $CWS/$DIR/SCCS/s.$F ]]; then
		chmod `get_file_mode $CWS/$DIR/SCCS/s.$F` \
		    $newdir/$DIR/$F
	fi
	chmod u-w,go=u $newdir/$DIR/$F

	#
	# Get the parent's version of the file. First see whether the
	# child's version is checked out and get the parent's version
	# with keywords expanded or unexpanded as appropriate.
	#
	if [[ -f $PWS/$PDIR/$PF && ! -f $PWS/$PDIR/SCCS/s.$PF && \
	    ! -f $PWS/$PDIR/SCCS/p.$PF ]]; then
		# Parent is not a real workspace, but just a raw
		# directory tree - use the file that's there as
		# the old file.

		rm -f $olddir/$PDIR/$PF
		cp $PWS/$PDIR/$PF $olddir/$PDIR/$PF
	else
		if [[ -f $PWS/$PDIR/SCCS/s.$PF ]]; then
			real_parent=$PWS
		else
			real_parent=$RWS
		fi

		rm -f $olddir/$PDIR/$PF

		if [[ -f $real_parent/$PDIR/$PF ]]; then
			if [ -f $CWS/$DIR/SCCS/p.$F ]; then
				$SCCS get -s -p -k $real_parent/$PDIR/$PF > \
				    $olddir/$PDIR/$PF
			else
				$SCCS get -s -p    $real_parent/$PDIR/$PF > \
				    $olddir/$PDIR/$PF
			fi
			chmod `get_file_mode $real_parent/$PDIR/SCCS/s.$PF` \
			    $olddir/$PDIR/$PF
		fi
	fi
	if [[ -f $olddir/$PDIR/$PF ]]; then
		chmod u-w,go=u $olddir/$PDIR/$PF
	fi
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
	file=`echo $file | sed 's#/#\\\/#g'`
	# match the exact filename, and return only the permission digits
	old_mode=`sed -n -e "/^\\(...\\) . ${file}$/s//\\1/p" \
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

	if [[ $SCM_MODE == "teamware" ]]; then
		build_old_new_teamware "$olddir" "$newdir"
	elif [[ $SCM_MODE == "mercurial" ]]; then
		build_old_new_mercurial "$olddir" "$newdir"
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
	-D: delete remote webrev
	-i <filename>: Include <filename> in the index.html file.
	-n: do not generate the webrev (useful with -U)
	-O: Print bugids/arc cases suitable for OpenSolaris.
	-o <outdir>: Output webrev to specified directory.
	-p <compare-against>: Use specified parent wkspc or basis for comparison
	-t <remote_target>: Specify remote destination for webrev upload
	-U: upload the webrev to remote destination
	-w <wxfile>: Use specified wx active file.

Environment:
	WDIR: Control the output directory.
	WEBREV_BUGURL: Control the URL prefix for bugids.
	WEBREV_SACURL: Control the URL prefix for ARC cases.
	WEBREV_TRASH_DIR: Set directory for webrev delete.

SCM Specific Options:
	TeamWare: webrev [common-options] -l [arguments to 'putback']

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

PATH=$(dirname $(whence $0)):$PATH

[[ -z $WDIFF ]] && WDIFF=`look_for_prog wdiff`
[[ -z $WX ]] && WX=`look_for_prog wx`
[[ -z $HG_ACTIVE ]] && HG_ACTIVE=`look_for_prog hg-active`
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
[[ -z $SFTP ]] && SFTP=`look_for_prog sftp`
[[ -z $MKTEMP ]] && MKTEMP=`look_for_prog mktemp`
[[ -z $GREP ]] && GREP=`look_for_prog grep`
[[ -z $FIND ]] && FIND=`look_for_prog find`

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

Dflag=
flist_mode=
flist_file=
iflag=
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
# 	with usr/src/tools/onbld/hgext/cdm.py
#
while getopts "i:o:p:lwONnt:UD" opt
do
	case $opt in
	D)	Dflag=1;;

	i)	iflag=1
		INCLUDE_FILE=$OPTARG;;

	#
	# If -l has been specified, we need to abort further options
	# processing, because subsequent arguments are going to be
	# arguments to 'putback -n'.
	#
	l)	lflag=1
		break;;

	N)	Nflag=1;;

	n)	nflag=1;;

	O)	Oflag=1;;

	o)	oflag=1
		WDIR=$OPTARG;;

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
# If this manually set as the parent, and it appears to be an earlier webrev,
# then note that fact and set the parent to the raw_files/new subdirectory.
#
if [[ -n $pflag && -d $codemgr_parent/raw_files/new ]]; then
	parent_webrev="$codemgr_parent"
	codemgr_parent="$codemgr_parent/raw_files/new"
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
$WHICH_SCM | read SCM_MODE junk || exit 1
case "$SCM_MODE" in
teamware|mercurial|subversion)
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

if [[ -n $lflag ]]; then
	#
	# If the -l flag is given instead of the name of a file list,
	# then generate the file list by extracting file names from a
	# putback -n.
	#
	shift $(($OPTIND - 1))
	if [[ $SCM_MODE == "teamware" ]]; then
		flist_from_teamware "$*"
	else
		print -u2 -- "Error: -l option only applies to TeamWare"
		exit 1
	fi
	flist_done=1
	shift $#
elif [[ -n $wflag ]]; then
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

if [[ $SCM_MODE == "teamware" ]]; then
	#
	# Parent (internally $codemgr_parent) and workspace ($codemgr_ws) can
	# be set in a number of ways, in decreasing precedence:
	#
	#      1) on the command line (only for the parent)
	#      2) in the user environment
	#      3) in the flist
	#      4) automatically based on the workspace (only for the parent)
	#

	#
	# Here is case (2): the user environment
	#
	[[ -z $codemgr_ws && -n $CODEMGR_WS ]] && codemgr_ws=$CODEMGR_WS
	if [[ -n $codemgr_ws && ! -d $codemgr_ws ]]; then
		print -u2 "$codemgr_ws: no such workspace"
		exit 1
	fi

	[[ -z $codemgr_parent && -n $CODEMGR_PARENT ]] && \
	    codemgr_parent=$CODEMGR_PARENT
	if [[ -n $codemgr_parent && ! -d $codemgr_parent ]]; then
		print -u2 "$codemgr_parent: no such directory"
		exit 1
	fi

	#
	# If we're in auto-detect mode and we haven't already gotten the file
	# list, then see if we can get it by probing for wx.
	#
	if [[ -z $flist_done && $flist_mode == "auto" && -n $codemgr_ws ]]; then
		if [[ ! -x $WX ]]; then
			print -u2 "WARNING: wx not found!"
		fi

		#
		# We need to use wx list -w so that we get renamed files, etc.
		# but only if a wx active file exists-- otherwise wx will
		# hang asking us to initialize our wx information.
		#
		if [[ -x $WX && -f $codemgr_ws/wx/active ]]; then
			print -u2 " File list from: 'wx list -w' ... \c"
			$WX list -w > $FLIST
			$WX comments > /tmp/$$.wx_comments
			wxfile=/tmp/$$.wx_comments
			print -u2 "done"
			flist_done=1
		fi
	fi

	#
	# If by hook or by crook we've gotten a file list by now (perhaps
	# from the command line), eval it to extract environment variables from
	# it: This is step (3).
	#
	env_from_flist

	#
	# Continuing step (3): If we still have no file list, we'll try to get
	# it from teamware.
	#
	if [[ -z $flist_done ]]; then
		flist_from_teamware
		env_from_flist
	fi

	#
	# (4) If we still don't have a value for codemgr_parent, get it
	# from workspace.
	#
	[[ -z $codemgr_ws ]] && codemgr_ws=`workspace name`
	[[ -z $codemgr_parent ]] && codemgr_parent=`workspace parent`
	if [[ ! -d $codemgr_parent ]]; then
		print -u2 "$CODEMGR_PARENT: no such parent workspace"
		exit 1
	fi

	#
	# Observe true directory name of CODEMGR_WS, as used later in
	# webrev title.
	#
	codemgr_ws=$(cd $codemgr_ws;print $PWD)

	#
	# Reset CODEMGR_WS to make sure teamware commands are happy.
	#
	CODEMGR_WS=$codemgr_ws
	CWS=$codemgr_ws
	PWS=$codemgr_parent

	[[ -n $parent_webrev ]] && RWS=$(workspace parent $CWS)

elif [[ $SCM_MODE == "mercurial" ]]; then
	[[ -z $codemgr_ws && -n $CODEMGR_WS ]] && \
	    codemgr_ws=`hg root -R $CODEMGR_WS 2>/dev/null`

	[[ -z $codemgr_ws ]] && codemgr_ws=`hg root 2>/dev/null`

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

	CWS_REV=`hg parent -R $codemgr_ws --template '{node|short}' 2>/dev/null`
	CWS=$codemgr_ws
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
		eval `sed -e "s/#.*$//" $wxfile | $GREP HG_PARENT=`
	fi

	#
	# If we still don't have a parent, we must have been given a
	# wx-style active list with no HG_PARENT specification, run
	# hg-active and pull an HG_PARENT out of it, ignore the rest.
	#
	if [[ -z $HG_PARENT && -x $HG_ACTIVE ]]; then
		$HG_ACTIVE -w $codemgr_ws -p $real_parent | \
		    eval `sed -e "s/#.*$//" | $GREP HG_PARENT=`
	elif [[ -z $HG_PARENT ]]; then
		print -u2 "Error: Cannot discover parent revision"
		exit 1
	fi
elif [[ $SCM_MODE == "subversion" ]]; then
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
	print -u2 "SCM not detected/supported and CODEMGR_WS not specified"
	exit 1
    fi

    if [[ -z $CODEMGR_PARENT ]]; then
	print -u2 "SCM not detected/supported and CODEMGR_PARENT not specified"
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
	# If remote target is not specified, build it from scratch using
	# the default values.
	if [[ -z $tflag ]]; then
		remote_target=${DEFAULT_REMOTE_HOST}:${WNAME}
	else
		# If destination specification is not in the form of
		# host_spec:remote_dir then assume it is just remote hostname
		# and append a colon and destination directory formed from
		# local webrev directory name.
		if [[ -z ${remote_target##*:} ]]; then
			if [[ "${remote_target}" == *: ]]; then
				dst=${remote_target}${WNAME}
			else
				dst=${remote_target}:${WNAME}
			fi
		fi
	fi
fi

# Option -D by itself (option -U not present) implies no webrev generation.
if [[ -z $Uflag && -n $Dflag ]]; then
	delete_webrev 1
	exit $?
fi

# Do not generate the webrev, just upload it or delete it.
if [[ -n $nflag ]]; then
	if [[ -n $Dflag ]]; then
		delete_webrev 1
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
if [[ -n $CWS_REV ]]; then
	print "      Workspace: $CWS (at $CWS_REV)"
else
	print "      Workspace: $CWS"
fi
if [[ -n $parent_webrev ]]; then
	print "Compare against: webrev at $parent_webrev"
else
	if [[ -n $HG_PARENT ]]; then
		hg_parent_short=`echo $HG_PARENT \
			| sed -e 's/\([0-9a-f]\{12\}\).*/\1/'`
		print "Compare against: $PWS (at $hg_parent_short)"
	else
		print "Compare against: $PWS"
	fi
fi

[[ -n $INCLUDE_FILE ]] && print "      Including: $INCLUDE_FILE"
print "      Output to: $WDIR"

#
# Save the file list in the webrev dir
#
[[ ! $FLIST -ef $WDIR/file.list ]] && cp $FLIST $WDIR/file.list

#
#    Bug IDs will be replaced by a URL.  Order of precedence
#    is: default location, $WEBREV_BUGURL, the -O flag.
#
BUGURL='http://monaco.sfbay.sun.com/detail.jsp?cr='
[[ -n $WEBREV_BUGURL ]] && BUGURL="$WEBREV_BUGURL"
[[ -n "$Oflag" ]] && \
    BUGURL='http://bugs.opensolaris.org/bugdatabase/view_bug.do?bug_id='

#
#    Likewise, ARC cases will be replaced by a URL.  Order of precedence
#    is: default, $WEBREV_SACURL, the -O flag.
#
#    Note that -O also triggers different substitution behavior for
#    SACURL.  See sac2url().
#
SACURL='http://sac.eng.sun.com'
[[ -n $WEBREV_SACURL ]] && SACURL="$WEBREV_SACURL"
[[ -n "$Oflag" ]] && \
    SACURL='http://www.opensolaris.org/os/community/arc/caselog'

rm -f $WDIR/$WNAME.patch
rm -f $WDIR/$WNAME.ps
rm -f $WDIR/$WNAME.pdf

touch $WDIR/$WNAME.patch

print "   Output Files:"

#
# Clean up the file list: Remove comments, blank lines and env variables.
#
sed -e "s/#.*$//" -e "/=/d" -e "/^[   ]*$/d" $FLIST > /tmp/$$.flist.clean
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
	#
	SEDFILE=/tmp/$$.manifest.sed
	sed '
		s#^[^ ]* ##
		s#/#\\\/#g
		s#^.*$#/^... . &$/p#
	' < $FLIST > $SEDFILE

	#
	# Apply the generated script to the output of "hg manifest -v"
	# to get the relevant subset for this webrev.
	#
	HG_PARENT_MANIFEST=/tmp/$$.manifest
	hg -R $CWS manifest -v -r $HG_PARENT |
	    sed -n -f $SEDFILE > $HG_PARENT_MANIFEST
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
		oldname=" (was $PP)"
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
	# If we're in OpenSolaris mode, we enforce a minor policy:
	# help to make sure the reviewer doesn't accidentally publish
	# source which is in usr/closed/* or deleted_files/usr/closed/*
	#
	if [[ -n "$Oflag" ]]; then
		pclosed=${P##usr/closed/}
		pdeleted=${P##deleted_files/usr/closed/}
		if [[ "$pclosed" != "$P" || "$pdeleted" != "$P" ]]; then
			print "*** Omitting closed source for OpenSolaris" \
			    "mode review"
			continue
		fi
	fi

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
	ofile=old/$PDIR/$PF
	nfile=new/$DIR/$F

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
	#	- Solaris patch(1m) can't cope with file creation
	#	  (and hence renames) as of this writing.
	#       - To make matters worse, gnu patch doesn't interpret the
	#	  output of Solaris diff properly when it comes to
	#	  adds and deletes.  We need to do some "cleansing"
	#         transformations:
	# 	    [to add a file] @@ -1,0 +X,Y @@  -->  @@ -0,0 +X,Y @@
	#	    [to del a file] @@ -X,Y +1,0 @@  -->  @@ -X,Y +0,0 @@
	#
	cleanse_rmfile="sed 's/^\(@@ [0-9+,-]*\) [0-9+,-]* @@$/\1 +0,0 @@/'"
	cleanse_newfile="sed 's/^@@ [0-9+,-]* \([0-9+,-]* @@\)$/@@ -0,0 \1/'"

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

print "<tr><th>Prepared by:</th><td>$preparer on `date`</td></tr>"
print "<tr><th>Workspace:</th><td>$CWS"
if [[ -n $CWS_REV ]]; then
	print "(at $CWS_REV)"
fi
print "</td></tr>"
print "<tr><th>Compare against:</th><td>"
if [[ -n $parent_webrev ]]; then
	print "webrev at $parent_webrev"
else
	print "$PWS"
	if [[ -n $hg_parent_short ]]; then
		print "(at $hg_parent_short)"
	fi
fi
print "</td></tr>"
print "<tr><th>Summary of changes:</th><td>"
printCI $TOTL $TINS $TDEL $TMOD $TUNC
print "</td></tr>"

if [[ -f $WDIR/$WNAME.patch ]]; then
	print "<tr><th>Patch of changes:</th><td>"
	print "<a href=\"$WNAME.patch\">$WNAME.patch</a></td></tr>"
fi
if [[ -f $WDIR/$WNAME.pdf ]]; then
	print "<tr><th>Printable review:</th><td>"
	print "<a href=\"$WNAME.pdf\">$WNAME.pdf</a></td></tr>"
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
		print "<a href=\"$P.cdiff.html\">Cdiffs</a>"
		print "<a href=\"$P.udiff.html\">Udiffs</a>"

		if [[ -f $F.wdiff.html && -x $WDIFF ]]; then
			print "<a href=\"$P.wdiff.html\">Wdiffs</a>"
		fi

		print "<a href=\"$P.sdiff.html\">Sdiffs</a>"

		print "<a href=\"$P.frames.html\">Frames</a>"
	else
		print " ------ ------ ------"

		if [[ -x $WDIFF ]]; then
			print " ------"
		fi

		print " ------"
	fi

	# If there's an old file, make the link

	if [[ -f $F-.html ]]; then
		print "<a href=\"$P-.html\">Old</a>"
	else
		print " ---"
	fi

	# If there's an new file, make the link

	if [[ -f $F.html ]]; then
		print "<a href=\"$P.html\">New</a>"
	else
		print " ---"
	fi

	if [[ -f $F.patch ]]; then
		print "<a href=\"$P.patch\">Patch</a>"
	else
		print " -----"
	fi

	if [[ -f $WDIR/raw_files/new/$P ]]; then
		print "<a href=\"raw_files/new/$P\">Raw</a>"
	else
		print " ---"
	fi

	print "<b>$P</b>"

	# For renamed files, clearly state whether or not they are modified
	if [[ -n "$oldname" ]]; then
		if [[ -n "$mv_but_nodiff" ]]; then
			print "<i>(renamed only, was $oldname)</i>"
		else
			print "<i>(modified and renamed, was $oldname)</i>"
		fi
	fi

	# If there's an old file, but no new file, the file was deleted
	if [[ -f $F-.html && ! -f $F.html ]]; then
		print " <i>(deleted)</i>"
	fi

	#
	# Check for usr/closed and deleted_files/usr/closed
	#
	if [ ! -z "$Oflag" ]; then
		if [[ $P == usr/closed/* || \
		    $P == deleted_files/usr/closed/* ]]; then
			print "&nbsp;&nbsp;<i>Closed source: omitted from" \
			    "this review</i>"
		fi
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

	if [[ $SCM_MODE == "teamware" ||
	    $SCM_MODE == "mercurial" ||
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
print "Webrev is maintained by the <a href=\"http://www.opensolaris.org\">"
print "OpenSolaris</a> project.  The latest version may be obtained"
print "<a href=\"http://src.opensolaris.org/source/xref/onnv/onnv-gate/usr/src/tools/scripts/webrev.sh\">here</a>.</p>"
print "</body>"
print "</html>"

exec 1<&-			# Close FD 1.
exec 1<&3			# dup FD 3 to restore stdout.
exec 3<&-			# close FD 3.

print "Done."

# If remote deletion was specified and fails do not continue.
if [[ -n $Dflag ]]; then
	delete_webrev 1
	(( $? == 0 )) || exit $?
fi

if [[ -n $Uflag ]]; then
	upload_webrev
	exit $?
fi
