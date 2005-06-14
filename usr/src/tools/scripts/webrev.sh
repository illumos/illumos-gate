#!/usr/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# This script takes a file list and a workspace
# and builds a set of html files suitable for doing
# a code review of source changes via a web page.
#
# Here's how you use it:
#
#	$ webrev file.list
#
# Alternatively, just run "webrev -l" and it'll extract
# a file list from the output of "putback -n" that will
# include any files updated, created, or currently sccs
# checked out. The script creates a "webrev" directory
# in the workspace directory that contains all the generated
# html files.  It also stashes a copy of the file list in
# there.
#
#
# 1) If you run "webrev -l" it'll extract a file list from
#    the output of "putback -n" that will include any files
#    updated, created, or currently checked out.  This is
#    the easiest way to use webrev.  If you use the "-l"
#    option to generate the file list then skip to step (4).
#    Note: if the workspace is large (e.g. all of Solaris usr/src
#    then this might take a while. You can run "webrev -l -f flp"
#    to have webrev extract a file list from the output of
#    "putback -n -f flp".
#
#    The file list created by "webrev -l" is stashed in the
#    webrev directory as "file.list".
#
#    If you would like more control over the file list then
#    create a file containing a list of all the files to
#    be included in your review with paths relative to your
#    workspace directory, e.g.
#
#          usr/src/uts/common/fs/nfs/nfs_subr.c
#          usr/src/uts/common/fs/nfs/nfs_export.c
#          usr/src/cmd/fs.d/nfs/mountd/mountd.c
#           :
#
#    Include the paths of any files added, deleted, or modified.
#    You can keep this list of files in the webrev directory
#    that the script creates in your workspace directory
#    (CODEMGR_WS).
#
# 2) The script needs to be able locate your workspace and
#    its parent.  If you have already activated your workspace
#    with the "ws" command then the script will use the
#    CODEMGR_WS environment variable.  If you are not working
#    within a workspace activation, then you'll need to set
#    the environment variable within the file list, e.g.
#
#          CODEMGR_WS=/home/brent/myws
#
#          usr/src/uts/common/fs/nfs/nfs_subr.c
#          usr/src/uts/common/fs/nfs/nfs_export.c
#          usr/src/cmd/fs.d/nfs/mountd/mountd.c
#           :
#
#    If you would like to compare against some other workspace
#    that is not the parent, then you can set the CODEMGR_PARENT
#    environment variable in the file list, e.g.
#
#          CODEMGR_WS=/home/brent/myws
#          CODEMGR_PARENT=/ws/on297-gate
#
#          usr/src/uts/common/fs/nfs/nfs_subr.c
#          usr/src/uts/common/fs/nfs/nfs_export.c
#          usr/src/cmd/fs.d/nfs/mountd/mountd.c
#           :
#
# 3) Run this script with the name of the file containing
#    the file list as an argument, e.g.
#
#      $ webrev  file.list
#
#    If you supply "-" as the name of the file, then stdin
#    will be used.
#
#    If you use the "-w" flag, i.e. "webrev  -w  file.list"
#    then webrev will assume the file list is in the format
#    expected by the "wx" package: pathname lines alternating
#    with SCCS comment lines separated by blank lines, e.g.
#
#          usr/src/uts/common/fs/nfs/nfs_subr.c
#
#          1206578 Fix spelling error in comment
#
#          usr/src/uts/common/fs/nfs/nfs_export.c
#
#          4039272 cstyle fixes
#
#          usr/src/cmd/fs.d/nfs/mountd/mountd.c
#
#          1927634 mountd daemon doesn't handle expletives
#
#    Embedded bug ids (any sequence of 5 or more digits)
#    will be converted to a URL (see URL environment variable
#    below).
#
# 4) For each file in the list, the script will compare it
#    with the version in the parent workspace (CODEMGR_PARENT)
#    and generate context and side-by-side diffs (sdiffs) as
#    HTML files as well as HTML renderings of the old and new
#    files with prepended line numbers for easy cross-checking
#    with diffs.
#
#    The HTML files will have additional formatting to
#    color code the source lines:
#
#      unchanged : black
#        removed : brown
#        changed : blue
#            new : bold blue
#
#  
# 5) Webrev will create a directory $CODEMGR_WS/webrev
#    and create the HTML files in a hierarchy beneath
#    this directory. Links to these HTML files will be
#    built into an index.html file in the "webrev" directory.
#    If you would like the "webrev" directory to appear
#    somewhere other than $CODEMGR_WS, then set the WDIR
#    environment variable, e.g.
#
#        WDIR=/tmp  webrev -l
#
#    Each file will be listed on a line with a link to
#    its Cdiffs, Udiffs, Sdiffs, Old, and New versions.  A blank
#    line will be inserted between filenames that do not exist
#    within the same directory as a grouping aid.
#    SCCS comments for each delta will be included
#    automatically. Bug numbers (any sequence of 5 or more
#    digits) in the comment will be replaced by a URL to
#    your local bug server.  You may need to modify the URL
#    below:
#
    if [[ -z $WEBREV_BUGURL ]]; then
	URL='http://monaco.sfbay.sun.com/detail.jsp?cr='
    else
	URL="$WEBREV_BUGURL"
    fi
#
#    Likewise, ARC cases will be replaced by a URL starting with:
#
     URL2="http://sac.eng.sun.com/"
#
#    As a review aid, you can add value to the index
#    file by including text that explains the changes in front
#    of the links for each file.  You might also add links
#    to the one-pager, project plan, or other documents
#    helpful to the reviewer.
#
# 6) View the index.html file with your web browser to 
#    verify that its what you want your reviewers to see.
#    The browser must support HTML tables and colored fonts.
#    Then send an Email invitation to your reviewers including
#    the URL to the index.html file in your workspace.  If you
#    use an "http:" URL then you can omit the "index.html"
#    filename, e.g.
#
#          To: bob, jane, wendy
#          Subject: Please review fix for bug 1234576
#
#          I'd be grateful if would review my bugfix.
#          All the relevant information can be obtained
#          with the following URL:
#
#             http://jurassic.eng/home/brent/myws/webrev
#
#          Thanks
#                 Brent
#
###############
#
#    Acknowledgements to Rob Thurlow, Mike Eisler, Lin Ling,
#    Rod Evans, Mike Kupfer, Greg Onufer, Glenn Skinner,
#    Oleg Larin, David Robinson, Matthew Cross, David L. Paktor,
#    Neal Gafter, John Beck, Darren Moffat, Norm Shulman, Bill Watson,
#    Pedro Rubio and Bill Shannon for valuable feedback and insight in
#    building this script.
#
#    Have fun!
#			Brent Callaghan  11/28/96
###############
#
#          Change Log
#
# 3/28/97  Add support for specifying stdin as a "-" argument.
#
# 6/15/97  Fix to allow file overwrite for users who set "noclobber"
#
# 8/19/97  Fix illegal "&" escape sequences (from Greg Onufer)
#
# 10/29/97 Create all HTML files under a "webrev" directory
#          Add -bw flags to "sdiff"
#
# 3/9/98   Improvements to better handle Java code.
#          Fix for quoting of code in <pre> blocks.
#          Fix some color bugs.  SCCS fix with not
#          getting appropriate parent version depending
#          on whether child version is checked out or
#          not (from Bill Shannon).
#
# 3/13/98  Added code from Bill Shannon's "spc" script
#          To add SCCS comments automatically to index.html.
#
# 3/18/98  Added -l option to generate file list automatically.
#
# 4/4/98   Added -w option to support Bonwick's wx package
#          active file list which can included pending
#          SCCS comments.
#          Reorganized layout of index file so that SCCS comments
#          now come after the file diffs line.  This looks much
#          better. Also, reduced the text point size in diffs
#          so that more source code can be viewed.
#
# 3/6/98   Handle files in the root directory of the workspace.
#
# 10/15/98 Fix minor bugs in sdiff color coding.
#          Replace long runs of unchanged lines in sdiff
#          by a horiz rule.
#	   Link bugids in SCCS & wx comments to web page via URL.
#          Bracket HTML page with <html> ... </html>.
#	   Add HTML comment to index file to help in placing
#	   change comments.
#
# 10/22/98 Fixed a bug affecting wx comments output.
#          File names in index file are now bold.
#          Basename of child workspace is used as the title.
#
# 12/22/98 Allow user to specify WDIR target directory for
#          "webrev" directory.
#
# 2/8/99   Allow file comparison with a parent that is not
#          a workspace - just a raw directory hierarchy of
#          files created by a workspace snapshot tool like
#          freezept (from Matthew Cross).
#
# 3/18/99  Allow the -l option to extract values for
#	   CODEMGR_WS and for CODEMGR_PARENT if they
#          are not already defined.  Play the file list
#          out through stdout once it's created
#	   (from David L. Paktor).
#
# 3/18/99  Correctly handle the case where no changes are found
#
# 4/7/99   Handle case of relative name for -w filename.
#
# 8/20/99  Fix handling of file.list
#
# 10/25/99 Additions or deletions to the beginning of a file
#          caused the lines to go out of synch.  Added new
#          code to handle this case.  Thanks to Glenn Skinner
#          for reporting the bug.
#
# 4/21/00  Added date of webrev run to last line of index page
#	   (suggestion by David Robinson)
#
# 8/2/00   Changed "sort" to "sort -u" to eliminate
#          duplicates in putback output. Thanks to 
#          Bill Shannon.
#
# 11/21/00 Added filenames to the HTML page titles.
#          (suggestion by David Robinson)
#
# 11/21/00 Fixed a problem with lost sccs comments in a
#          new file.  Also added a default for the -w wxfile
#          flag.  Thanks to Darren Moffat for these.
#
# 11/22/00 Fix to detect and handle renames correctly.
#
# 1/17/01  Allow the use of a file list program (flp) to
#          be specified as an argument to -l. For example:
#          "webrev -l -f ~/aux.flp". An flp is a program
#          that generates a file list. Thanks to Norm Shulman.
#
# 2/1/01   Invoke context diff from CDIFFCMD environment
#          variable.  This allows an alternative diff
#          command line to be invoked if set in the environment.
#          Thanks to John Beck (a fan of udiff).
#
# 2/2/01   Change "sort -k1,1" to "sort -k 1,1"
#          Bugfix from Neal Gafter
#
# 4/27/01  Added webrev script date to index page
#	   Suggestion from John Beck
#
# 4/27/01  Protect HTML sensitive characters in SCCS
#          delta comments. Bug reported by Pedro Rubio
#
# 7/24/01  Modify page title to be workspace name - suggestion
#	   from Bill Watson.
#
# Following variable is set to SCCS delta date 20YY/MM/DD.
# Note this will have to be changed in 2100 or when SCCS has support for
# 4 digit years; whichever is the sooner!
#
  WEBREV_UPDATED=20%E%
#
###############

REMOVED_COLOR=brown
CHANGED_COLOR=blue
NEW_COLOR=blue

#
# Make a piece of source code safe for display in an HTML <pre> block.
#
html_quote()
{
	sed -e "s/&/\&amp;/g" -e "s/</\&lt;/g" -e "s/>/\&gt;/g" "$@" | expand
}

sdiff_to_html()
{
#
#  This function takes two files as arguments, obtains their diff,
#  and processes the diff output to present the files as an HTML
#  document with the files displayed side-by-side, differences
#  shown in color.
#
#  This HTML generated by this function assumes that the browser
#  can handle HTML 3.0 tables and colored text as implemented
#  in Netscape 2.0.  The output is "wide" so it will be necessary
#  to widen the browser window when viewing the output.
#
#  The function takes two files as arguments
#  and the HTML will be delivered on stdout, e.g.
#
#    $ sdiff_html  prog.c-  prog.c  >  prog.diffs.html
#
#  In addition if WEBREV_FRAMES == 'yes' then framed_sdiff() is called
#  which creates $2.frames.html in the webrev tree.
#
#  FYI: This function is rather unusual in its use of awk.
#  The initial diff run produces conventional diff output
#  showing changed lines mixed with editing codes.  The
#  changes lines are ignored - we're interested in the 
#  editing codes, e.g.
#
#      8c8
#      57a61
#      63c66,76
#      68,93d80
#      106d90
#      108,110d91
#
#  These editing codes are parsed by the awk script and used to
#  generate another awk script that generates HTML, e.g the
#  above lines would turn into something like this:
#
#      BEGIN { printf "<pre>\n" }
#      function sp(n) {for (i=0;i<n;i++)printf "\n"}
#      function wl(n) {printf "<FONT COLOR=%s>%3d %s </FONT>\n", n, NR, $0}
#      NR==8           {wl("#7A7ADD");next}
#      NR==54          {wl("#7A7ADD");sp(3);next}
#      NR==56          {wl("#7A7ADD");next}
#      NR==57          {wl("black");printf "\n"; next}
#        :               :
#
#  This script is then run on the original source file to generate
#  the HTML that corresponds to the source file.
#
#  The two HTML files are then combined into a single piece of 
#  HTML that uses an HTML table construct to present the files
#  side by side.  You'll notice that the changes are color-coded:
#
#   black     - unchanged lines
#   blue      - changed lines
#   bold blue - new lines
#   brown     - deleted lines
#
#  Blank lines are inserted in each file to keep unchanged
#  lines in sync (side-by-side).  This format is familiar
#  to users of sdiff(1) or Teamware's filemerge tool.

diff -b $1 $2 > /tmp/$$.diffs

#
#  Now we have the diffs, generate the HTML for the old file.
#

TNAME=$2

nawk '
BEGIN	{
	printf "function sp(n) {for (i=0;i<n;i++)printf \"\\n\"}\n"
	printf "function wl(n) {printf \"<FONT COLOR=%%s>%%3d %%s </FONT>\\n\", n, NR, $0}\n"
	printf "function bl() {printf \"%%3d %%s\\n\", NR, $0}\n"
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
			printf "NR==%s\t\t{wl(\"'$REMOVED_COLOR'\") ; next}\n" , n1
		else
			printf "NR==%s,NR==%s\t{wl(\"'$REMOVED_COLOR'\") ; next}\n" , n1, n2
		next	
	}
	if (index($1, "c")) {
		n = split(a[1], r, /,/);
		n1 = r[1]
		n2 = r[2]
		final = n2
		d1 = 0
		if (n == 1)
			printf "NR==%s\t\t{wl(\"'$CHANGED_COLOR'\");" , n1
		else {
			d1 = n2 - n1
			printf "NR==%s,NR==%s\t{wl(\"'$CHANGED_COLOR'\");" , n1, n2
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
END	{ printf "{printf \"%%3d %%s\\n\", NR, $0 }\n" }
' /tmp/$$.diffs > /tmp/$$.file1

html_quote $1 | nawk -f /tmp/$$.file1 > /tmp/$$.file1.html

#
#  Now generate the HTML for the new file
#

nawk '
BEGIN	{ 
	printf "function sp(n) {for (i=0;i<n;i++)printf \"\\n\"}\n"
	printf "function wl(n) {printf \"<FONT COLOR=%%s>%%3d %%s </FONT>\\n\", n, NR, $0}\n"
	printf "function wlb(n) {printf \"<FONT COLOR=%%s><b>%%3d %%s</b></FONT>\\n\", n, NR, $0}\n"
	printf "function bl() {printf \"%%3d %%s\\n\", NR, $0}\n"
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
			printf "NR==%s\t\t{wlb(\"'$NEW_COLOR'\") ; next}\n" , n1
		else
			printf "NR==%s,NR==%s\t{wlb(\"'$NEW_COLOR'\") ; next}\n" , n1, n2
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
			printf "NR==%s\t\t{wl(\"'$CHANGED_COLOR'\");" , n1
		} else {
			d2 = n2 - n1
			printf "NR==%s,NR==%s\t{wl(\"'$CHANGED_COLOR'\");" , n1, n2
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
END	{ printf "{printf \"%%3d %%s\\n\", NR, $0 }\n" }
' /tmp/$$.diffs > /tmp/$$.file2

html_quote $2 | nawk -f /tmp/$$.file2 > /tmp/$$.file2.html

# Now combine into a table

echo "<body bgcolor=#EEEEEE>"
echo "<title> Sdiff $TNAME </title>"
echo "<table><tr valign=top>"
echo "<td><pre>"

strip_unchanged /tmp/$$.file1.html

echo "</pre></td><td><pre>"

strip_unchanged /tmp/$$.file2.html

echo "</pre></td>"
echo "</tr></table>"

if [[ $WEBREV_FRAMES == 'yes' ]]; then
    framed_sdiff $TNAME /tmp/$$.file1.html /tmp/$$.file2.html
fi

}

####################################

function framed_sdiff
{
# Expects html files created by sdiff_to_html which it then augments
# with HTML navigation anchors.  
#
# NOTE: We rely on standard usage of $TNAME and $WDIR/$DIR.
#
    typeset TNAME=$1
    typeset file1=$2
    typeset file2=$3
    typeset RTOP
    # Make the rhs/lhs files and output the frameset file.
    insert_anchors $file1 > $WDIR/$DIR/$TNAME.lhs.html
    insert_anchors $file2 > $WDIR/$DIR/$TNAME.rhs.html
    # Enable html files to access WDIR via a relative path.
    RTOP=$(relative_cws)
    cat > $WDIR/$DIR/$TNAME.frames.html <<-EOF
	<html><head>
	    <title>Framed Sdiff for $TNAME</title>
	  </head>
	  <FRAMESET ROWS="*,50">
	    <FRAMESET COLS="50%,50%">
	      <FRAME SRC="$TNAME.lhs.html" SCROLLING="auto" NAME="lhs">
	      <FRAME SRC="$TNAME.rhs.html" SCROLLING="auto" NAME="rhs">
	    </FRAMESET>
	  <FRAME SRC="${RTOP}ancnav.html" SCROLLING="no" MARGINWIDTH="0"
	   MARGINHEIGHT="0">
	  <NOFRAMES>
	    <P>Alas FRAMES webrev requires that your browser supports FRAMES
	    and has the feature enabled.  
	    <a href="index.html">Return to webrev index</a>.</p>
	  </NOFRAMES>
	  </FRAMESET>
	</html>
	EOF
}

####################################

strip_unchanged()
{
# Removes chunks of sdiff documents that have not
# changed. This makes it easier for a code reviewer
# to find the bits that have changed.
#
# Deleted lines of text are replaced by an
# horizontal rule. Some identical lines are
# retained before and after the changed lines
# to provide some context.  The number of these
# lines is controlled by the variable C in the
# nawk script below.
#
# The script detects changed lines as any line
# that has a "FONT COLOR=" string embedded (unchanged
# lines use the default color and have no FONT directive).
# Blank lines (without a sequence number) are also detected
# since they flag lines that have been inserted or deleted.

nawk '

BEGIN	{ C = c = 20 }
NF == 0 || /FONT COLOR=/ {
	if (c > C) {
		c -= C
		inx = 0
                if (c > C) {
			print "\n<hr>"
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
END	{ if (c > (C * 2)) print "\n<hr>" }

' $1
}
####################################

function insert_anchors
{
# Flag blocks of difference with sequentially numbered invisible
# anchors.  These are used to drive the WEBREV_FRAMES version of the
# sdiffs output.
#
# NOTE: Anchor zero flags the top of the file irrespective of changes,
# an additional anchor is also appended to flag the bottom.
#
# The script detects changed lines as any line that has a "<FONT
# COLOR=" string embedded (unchanged lines use the default color and
# have no FONT directive).  Blank lines (without a sequence number)
# are also detected since they flag lines that have been inserted or
# deleted.
#
# In addition, here is a good place to top and tail the document for
# use in its parent frame.  We add a lot of blank lines to tackily
# assist the last anchors to have an effect on the screen.

print '<html>\n<body bgcolor="#EEEEEE">\n<pre>'

nawk '
function ia() {
	printf "<A NAME=\"%d\"></A>", anc++;
}
BEGIN {
	anc=0;
	inblock=1;
	ia();
}
NF == 0 || /^<FONT COLOR=/ {
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
	print "<center><font color=\"red\"><b>--- EOF ---</b></font></center>";
	for(i=0;i<8;i++) printf "\n\n\n\n\n\n\n\n\n\n";
}
' $1

print '</pre>\n</html>'
}

####################################

function relative_cws
{
#
# Print a relative return path from PWD to CWS.  for example if
# PWD=/ws/onnv-gate/usr/src/tools/scripts and CWS=/ws/onnv-gate this
# function would print "../../../../".
#
# In the event that CWS is not in PWD a warning is printed to stderr,
# WDIR is returned and thus the resulting webrev is not relocatable.
#
    typeset cur="${PWD##$CWS(/)}" ret
    if [[ $PWD == $cur ]]; then # Should never happen.
	print -u2 "\nWarning: relative_cws: \"$PWD\" not relative to \"$CWS\"."
	print -u2 "Check input paths.  Framed webrev will not be relocatable!"
	print $WDIR
    else
	while [[ -n ${cur} ]]
	do
	    cur=${cur%%*(/)*([!/])}
	    ret="../$ret"
	done
	print $ret
    fi
}

####################################

function frame_navigation
{
# Output anchor navigation file for framed sdiffs.
cat << \EOF
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html><head><title>Anchor Navigation</title>
<meta http-equiv="Content-Script-Type" content="text/javascript">
<meta http-equiv="Content-Type" content="text/html">
    <style>
      div.button td { background: #900;}
      div.button a { color: white }
      div.button a:hover { background: black; color: white }
    </style>
    <script language="JavaScript">
<!--
var anc=0;
var myInt;
var scrolling=0;
var sfactor;
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

function scrollByAnc(num) {
	if (num < 0) {
		anc=0;
		num=0;
	}
	if (num >= parent.lhs.document.anchors.length) {
		anc=parent.lhs.document.anchors.length - 1;
		num=anc;
	}
	parent.lhs.location.replace(parent.lhs.location.pathname + "#" + num);
	parent.rhs.location.replace(parent.rhs.location.pathname + "#" + num);
	anc=num;
	if (num <= 0) {
	    document.diff.sync.value="BOF";
	} else if (num < parent.lhs.document.anchors.length - 1) {
	    document.diff.sync.value=num;
        } else {
	    document.diff.sync.value="EOF";
	}
	// Scroll back a little to expose previous lines.
	parent.lhs.scrollBy(0,-30);
	parent.rhs.scrollBy(0,-30);
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
		scrollByAnc(-1);
		break;
	    case 2 :
		scrollByAnc(anc-1);
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
		scrollByAnc(anc+1);
		break;
	    case 6 :
		scrollByAnc(parent.lhs.document.anchors.length);
		break;
	}
}

function handleRelease(b) {
	stopScroll();
}

function ValidateDiffNum(){
        i=Number(document.diff.sync.value);
	if (isNaN(i)) {
		document.diff.sync.value=anc;
	} else {
		scrollByAnc(i);
	}
	return false;
}

//-->
    </script>
  </head>
  <body>
    <noscript lang="javascript">
      <center>
	<p><big>Framed Navigation controls require Javascript</big><br>
	Either this browser is incompatable or javascript is not enabled</p>
      </center>
    </noscript>
    <table width="100%" border="0" align="center">
	<tr><th valign="middle" width="25%"><i>Diff navigation:</i></th>
	  <td align="centre" valign="top" width="50%">
	    <div class="button">
	      <table border="0" cellpadding="2" align="center"><tr>
		    <td align="center" valign="left">
		      <a onMouseDown="handlePress(1);return true;"
			 onMouseUp="handleRelease(1);return true;"
			 onMouseOut="handleRelease(1);return true;"
			 onClick="return false;"
			 title="Go to Beginning Of file">BOF</a></td>
		    <td align="center" valign="middle">
		      <a onMouseDown="handlePress(3);return true;"
			 onMouseUp="handleRelease(3);return true;"
			 onMouseOut="handleRelease(3);return true;"
			 title="Scroll Up: Press and Hold to accelerate"
			 onClick="return false;">Scroll frames Up</a></td>
		    <td align="center" valign="right">
		      <a onMouseDown="handlePress(2);return true;"
			 onMouseUp="handleRelease(2);return true;"
			 onMouseOut="handleRelease(2);return true;" 
			 title="Go to previous Diff"
			 onClick="return false;">Prev Diff</a>
		    </td></tr>
		  <tr>
		    <td align="center" valign="left">
		      <a onMouseDown="handlePress(6);return true;" 
			 onMouseUp="handleRelease(6);return true;" 
			 onMouseOut="handleRelease(6);return true;" 
			 onClick="return false;"
			 title="Go to End Of File">EOF</a></td>
		    <td align="center" valign="middle">
		      <a onMouseDown="handlePress(4);return true;" 
			 onMouseUp="handleRelease(4);return true;" 
			 onMouseOut="handleRelease(4);return true;" 
			 title="Scroll Down: Press and Hold to accelerate"
			 onClick="return false;">Scroll frames Down</a></td>
		    <td align="center" valign="right">
		      <a onMouseDown="handlePress(5);return true;" 
			 onMouseUp="handleRelease(5);return true;" 
			 onMouseOut="handleRelease(5);return true;" 
			 title="Go to next Diff"
			 onClick="return false;">Next Diff</a></td>
		  </tr></table>
	    </dev>
	  </TD>
	  <th valign="middle" width="25%">
	    <form name="diff" onsubmit="return ValidateDiffNum();">
		<input name="sync" value="BOF" size="8" type="text">
	    </form>
	  </th>
	</TR>
    </table>
  </body>
</html>
EOF
}

####################################

diff_to_html()
{
TNAME=$1
DIFFTYPE=$2

html_quote | nawk '
BEGIN	{printf "<body bgcolor=\"#EEEEEE\"><title>'$DIFFTYPE'diff '$TNAME'</title><pre>\n"}
/^-------/	{ printf "<center><h1>%s</h1></center>\n", $0; next }
/^\*\*\*\*/	{ printf "<hr>\n"; next}
/^\*\*\*/	{ printf "<FONT COLOR=\"red\" SIZE=+1><b>%s</b></FONT>\n", $0 ; next}
/^---/		{ printf "<FONT COLOR=\"green\" SIZE=+1><b>%s</b></FONT>\n", $0 ; next}
/^\+/	{printf "<FONT COLOR=\"'$NEW_COLOR'\"><b>%s</b></FONT>\n", $0; next}
/^!/	{printf "<FONT COLOR=\"'$CHANGED_COLOR'\">%s</FONT>\n", $0; next}
/^-/	{printf "<FONT COLOR=\"'$REMOVED_COLOR'\">%s</FONT>\n", $0; next}
	{printf "<FONT COLOR=\"black\">%s</FONT>\n", $0; next}
END	{printf "</pre></FONT></body>\n"}
'
}

####################################

source_to_html()
{
WHICH=$1
TNAME=$2

html_quote | nawk '
BEGIN	{printf "<body bgcolor=\"#EEEEEE\"><title>'"$WHICH $TNAME"'</title><pre>\n"}
	{line += 1 ; printf "%3d %s\n", line, $0 }
'
}

####################################
# Find the first delta in the child that's not in the parent.
# Get the newest delta from the parent, get all deltas from the
# child starting with that delta, and then get all info starting
# with the second oldest delta in that list (the first delta
# unique to the child).
#
# This code adapted from Bill Shannon's "spc" script

deltacomments()
{
pfile=$PWS/$1
cfile=$CWS/$2

if [ -f $pfile ]; then
	psid=$(sccs prs -d:I: $pfile 2>/dev/null)
else
	psid=1.1
fi

set -A sids $(sccs prs -l -r$psid -d:I: $cfile 2>/dev/null)
N=${#sids[@]}

if [[ $N -ge 2 ]]; then
	sid1=${sids[$((N-2))]}	# Gets 2nd to last sid

	echo "<ul>"
	sccs prs -l -r$sid1 $cfile  2>/dev/null |
	html_quote |
	sed -e 's|[0-9]\{5,\}|<a href='$URL'&>&</a>|g' \
	    -e 's|\([A-Z]\{1,2\}ARC\)[ /]\([0-9]\{4\}/[0-9]\{3\}\)|<a href='$URL2'\1/\2>\1 \2</a>|g'|
	nawk '/^COMMENTS:/ {p=1; printf "<li>"; continue}
		NF == 0 { continue }
		/^D / {p=0}
		{if (p==0) continue; print $0 "<br>"}'
	echo "</ul>"
fi
}

####################################
# Given the pathname of a file, find its location
# in a "wx" active file list and print the following
# sccs comment. Embedded bugids (sequence of 5 or
# more digits) are turned into URLs.

wxcomments()
{

	echo "<blockquote><pre>"
	nawk '
	$1 == "'$1'" {
		do getline ; while (NF > 0)
		getline
		while (NF > 0) { print ; getline }
		exit
	}' < $WXFILE | html_quote |
	sed -e 's|[0-9]\{5,\}|<a href='$URL'&>&</a>|g' \
	    -e 's|\([A-Z]\{1,2\}ARC\)[ /]\([0-9]\{4\}/[0-9]\{3\}\)|<a href='$URL2'\1/\2>\1 \2</a>|g'
	echo "</pre></blockquote>"
}

#####################################
# Calculate number of changes.
# 

function difflines
{
    integer tot chg del ins unc err
    typeset filename

    diff -e $1 $2 | eval $( nawk '
    ## Change range of lines: N,Nc
    /^[0-9]*,[0-9]*c$/ {
	n=split(substr($1,1,length($1)-1), counts, ",");
	if (n != 2) {
	    error=2
	    exit;
	}
	## 3,5c means lines 3 , 4 and 5 are changed, a total of 3 lines.
	## following would be 5 - 3 = 2! Hence +1 for correction.
	r=(counts[2]-counts[1])+1;
	## Now count replacement lines: each represents a change instead
	## of a delete, so increment c and decrement r.
	while (getline != /^\.$/) {
		c++;
		r--;
	}
	## If there were more replacement lines than original lines,
	## then r will be negative; in this case there are no deletions,
	## but there are r changes that should be counted as adds, and
	## since r is negative, subtract it from a and add it to c.
	if (r < 0) {
		a-=r;
		c+=r;
	}
	## If there were more original lines than replacement lines, then
	## r will be positive; in this case, increment d by that much.
	if (r > 0) {
		d+=r;
	}
	next;
    }

    ## Change lines: Nc
    /^[0-9].*c$/ {
	## The first line is a replacement; any more are additions.
	if (getline != /^\.$/) {
		c++;
		while (getline != /^\.$/) a++;
	}
	next;
    }

    ## Add lines: both Na and N,Na
    /^[0-9].*a$/ {
	while (getline != /^\.$/) a++;
	next;
    }

    ## Delete range of lines: N,Nd
    /^[0-9]*,[0-9]*d$/ {
	n=split(substr($1,1,length($1)-1), counts, ",");
	if (n != 2) {
	    error=2
	    exit;
	}
	## 3,5d means lines 3 , 4 and 5 are deleted, a total of 3 lines.
	## following would be 5 - 3 = 2! Hence +1 for correction.
	r=(counts[2]-counts[1])+1;
	d+=r;
	next;
    }

    ## Delete line: Nd
    ## For example 10d says line 10 is deleted. 
    /^[0-9]*d$/ {d++; next}

    ## Should not get here!
    {
	error=1;
	exit;
    }

    ## Finish off - print results
    END{
	printf("tot=%d;chg=%d;del=%d;ins=%d;err=%d\n",
	    (c+d+a), c, d, a, error);
    }' )

    # End of nawk, Check to see if any trouble occurred.
    if (( $? > 0 || err > 0 )); then
	print "Unexpected Error occurred reading \`diff -e $1 $2\`: \$?=$?, err=" $err
    else
	# Accumulate totals
	(( TOTL += tot ))
	(( TCHG += chg ))
    	(( TDEL += del ))
	(( TINS += ins ))
	# Calculate unchanged lines
	wc -l $1 | read unc filename
	if (( unc > 0 )); then
	    (( unc -= del + chg ))
	    (( TUNC += unc ))
	fi
	# print summary
	printCI $tot $ins $del $chg $unc
    fi
}

#####################################
# Print out Code Inspection figures similar to sccs-prt(1) format.
#
function printCI
{
    integer tot=$1 ins=$2 del=$3 chg=$4 unc=$5
    typeset str
    if (( tot == 1 )); then
	str="line"
    else
	str="lines"
    fi
    printf "%d %s changed : %d/%d/%d/%d %s\n" \
	$tot $str $ins $del $chg $unc "(inserted/deleted/modified/unchanged)"
}

#####################################
#
#   Start Here
#
#####################################

trap "rm -f /tmp/$$.* ; exit" 0 1 2 3 15

set +o noclobber

WDIFF=${WDIFF:-/ws/onnv-gate/public/bin/wdiff}

FLIST=$1

# By default enable frame diff.
WEBREV_FRAMES=${WEBREV_FRAMES:-yes}

# Declare global total counters.
integer TOTL TINS TDEL TCHG TUNC

if [ "$FLIST" = "-" ]; then
	FLIST=/tmp/$$.flist
	cat > $FLIST
fi

# If the -l flag is given instead of the name of
# a file list, then generate the file list by
# extracting file names from a putback -n.
# Some names may come from the "update/create"
# messages and others from the "currently checked out"
# warning. Renames are detected here too.
# Extract values for CODEMGR_WS and CODEMGR_PARENT
# from the output of the putback -n as well, but remove
# them if they are already defined.

if [ "$FLIST" = "-l" ]; then

	FLIST=/tmp/$$.filelist
	print "Generating file list ...\c"

	putback -n $2 $3 2>&1 |
	awk '/^update:|^create:/{print $2}
		/^Parent workspace:/{printf("CODEMGR_PARENT=%s\n",$3)}   \
		/^Child workspace:/{printf("CODEMGR_WS=%s\n",$3)}   \
		/^The following files/{p=1 ; continue}
		/^rename/{old=$3}
		$1 == "to:"{print $2, old}
		/^"/ {continue}
		NF == 0 {p=0 ; continue}
		{if (p==1) print $1}' |
	sort -r -k 1,1 -u | sort > $FLIST

	print " Done\n"
fi

# If the -w flag is given then assume the file
# list is in Bonwick's "wx" command format, i.e.
# pathname lines alternating with SCCS comment
# lines with blank lines as separators.
# Use the SCCS comments later in building
# the index.html file.

if [ "$FLIST" = "-w" ]; then
	shift
	WXFILE=$1

	# If the wx file pathname is relative
	# then make it absolute because the
	# webrev does a "cd" later on.
	#
	# If no wx file pathname is given, then
	# it defaults to "wx/active" in the
	# workspace directory.

	if [ -z "${WXFILE}" ]; then
		WXFILE=${CODEMGR_WS}/wx/active
	elif [ ${WXFILE%%/*} ]; then
		WXFILE=$PWD/$WXFILE
	fi

	FLIST=/tmp/$$.filelist
	nawk '{ c = 1; print;
	  while (getline) {
		if (NF == 0) { c = -c; continue }
		if (c > 0) print
	  }
	}' $WXFILE > $FLIST
fi

if [ ! -f $FLIST ]; then
	echo "$FLIST: no such file"

	echo "Usage: webrev <file>"
	echo "       webrev -"
	echo "       webrev -w [<wx file>]"
	echo "       webrev -l [-f flp]"
	exit 1
fi


# Remove workspace variables from the flist
# file if they're already set in the environment.
# We want the environment variables to take
# precedence over any set in the file list.

if [ "$CODEMGR_WS" != "" ]; then
	egrep -v '^CODEMGR_WS=' $FLIST > $FLIST.$$
	mv $FLIST.$$ $FLIST
fi
if [ "$CODEMGR_PARENT" != "" ]; then
	egrep -v '^CODEMGR_PARENT=' $FLIST > $FLIST.$$
	mv $FLIST.$$ $FLIST
fi


# Now do an "eval" to set env variables that
# are listed in the file list.

eval `sed -e "s/#.*$//" $FLIST | grep = `


if [ "$CODEMGR_WS" = "" ]; then
	echo "CODEMGR_WS not set."
	echo "Activate a workspace or set in $FLIST"
	exit 1
fi

if [ ! -d $CODEMGR_WS ]; then
	echo "$CODEMGR_WS: no such workspace"
	exit 1
fi

# Observe true directory name of CODEMGR_WS, as used later in webrev title.
CODEMGR_WS=$(cd $CODEMGR_WS;print $PWD)

if [ "$CODEMGR_PARENT" = "" ]; then
	CODEMGR_PARENT=`workspace parent`
fi

if [ ! -d $CODEMGR_PARENT ]; then
	echo "$CODEMGR_PARENT: no such parent workspace"
	exit 1
fi

echo
echo CODEMGR_WS=$CODEMGR_WS
echo CODEMGR_PARENT=$CODEMGR_PARENT
echo

CWS=$CODEMGR_WS
PWS=$CODEMGR_PARENT
WDIR=${WDIR:-$CWS}/webrev
if [ ${WDIR%%/*} ]; then
	WDIR=$PWD/$WDIR
fi
if [ ! -d $WDIR ]; then
	mkdir $WDIR
fi

# Save the file list in the webrev dir

if [ ! $FLIST -ef $WDIR/file.list ]; then
	cp $FLIST $WDIR/file.list
fi

# Remove comments, blank lines and env variables from the file list

sed -e "s/#.*$//" -e "/=/d" -e "/^[   ]*$/d" $FLIST |

# ... and read lines from the cleaned-up file list

while read LINE
do
	set - $LINE
	P=$1

	# Normally, each line in the file list is
	# just a pathname of a file that has
	# been modified or created in the child.
	# A file that is renamed in the child workspace
	# has two names on the line: new name followed
	# by the old name.

	if [ $# = 2 ]; then
		PP=$2			# old filename
		OLDNAME=" (was $PP)"
        	PDIR=${PP%/*}
        	if [ "$PDIR" == "$PP" ]; then
			PDIR="."   # File at root of workspace
		fi

		PF=${PP##*/}

	        DIR=${P%/*}
	        if [ "$DIR" == "$P" ]; then
			DIR="."   # File at root of workspace
		fi
	
		F=${P##*/}
        else
		OLDNAME=""
	        DIR=${P%/*}
	        if [ "$DIR" == "$P" ]; then
			DIR="."   # File at root of workspace
		fi
	
		F=${P##*/}

		PP=$P
		PDIR=$DIR
		PF=$F
	fi



	if [ ! -d $CWS/$DIR ]; then
		echo "  $CWS/$DIR: no such directory"
		continue
	fi

	print "  $P$OLDNAME\n\t\c"

	# Make the webrev mirror directory if necessary

	if [ ! -d $WDIR/$DIR ]; then
		mkdir -p $WDIR/$DIR
	fi

	# cd to the directory so the names are short

	cd $CWS/$DIR

	# If the child's version doesn't exist then
	# get a readonly copy.

	if [ ! -f $F -a -f SCCS/s.$F ]; then
		sccs get -s $F
	fi

	# Get the parent's version of the file. First see
	# whether the child's version is checked out and
	# get the parent's version with keywords expanded
	# or unexpanded as appropriate.

	if [ -f $PWS/$PDIR/SCCS/s.$PF -o -f $PWS/$PDIR/SCCS/p.$PF ]; then
		if [ -f SCCS/p.$F ]; then
			sccs get -s -p -k $PWS/$PDIR/$PF > $WDIR/$DIR/$F-
		else
			sccs get -s -p    $PWS/$PDIR/$PF > $WDIR/$DIR/$F-
		fi
        else
                if [ -f $PWS/$PDIR/$PF ]; then
                        # Parent is not a real workspace, but just a raw
                        # directory tree - use the file that's there as
                        # the old file.
  
                        cp $PWS/$PDIR/$PF $WDIR/$DIR/$F-
                fi
	fi

	if [ ! -f $F -a ! -f $WDIR/$DIR/$F- ]; then
		echo "*** Error: file not in parent or child"
		continue
	fi

	# If we have old and new versions of the file
	# then run the appropriate diffs.

	if [ -f $F -a -f $WDIR/$DIR/$F- ]; then
		${CDIFFCMD:-diff -b -C 5} $WDIR/$DIR/$F- $F > $WDIR/$DIR/$F.cdiff
		diff_to_html $F "C" < $WDIR/$DIR/$F.cdiff > $WDIR/$DIR/$F.cdiff.html
		print " cdiffs\c"

		${UDIFFCMD:-diff -b -U 5} $WDIR/$DIR/$F- $F > $WDIR/$DIR/$F.udiff
		diff_to_html $F "U" < $WDIR/$DIR/$F.udiff > $WDIR/$DIR/$F.udiff.html
		print " udiffs\c"

		if [[ -x $WDIFF ]]; then
			$WDIFF -t "Wdiff $DIR/$F" $WDIR/$DIR/$F- $F > $WDIR/$DIR/$F.wdiff.html
			print " wdiffs\c"
		fi

		sdiff_to_html $WDIR/$DIR/$F- $F > $WDIR/$DIR/$F.sdiff.html
		print " sdiffs\c"

		if [[ $WEBREV_FRAMES == 'yes' ]]; then
			print " frames\c"
		fi

		rm -f $WDIR/$DIR/$F.cdiff $WDIR/$DIR/$F.udiff

		difflines $WDIR/$DIR/$F- $F > $WDIR/$DIR/$F.count
	elif [ -f $F ]; then
		# new file: count added lines
		difflines /dev/null $F > $WDIR/$DIR/$F.count
	elif [ -f $WDIR/$DIR/$F- ]; then
		# old file: count deleted lines
		difflines $WDIR/$DIR/$F- /dev/null > $WDIR/$DIR/$F.count
	fi

	if [ -f $WDIR/$DIR/$F- ]; then
		source_to_html Old $PF < $WDIR/$DIR/$F- > $WDIR/$DIR/$F-.html
		rm -f $WDIR/$DIR/$F-
		print " old\c"
	fi

	if [ -f $F ]; then
		source_to_html New $F < $F > $WDIR/$DIR/$F.html
		print " new\c"
	fi

	echo
done

if [[ $WEBREV_FRAMES == 'yes' ]]; then
	frame_navigation > $WDIR/ancnav.html	
fi

# Now build the index.html file that contains
# links to the source files and their diffs.

cd $CWS

# Save total changed lines for Code Inspection.
echo "$TOTL" > $WDIR/TotalChangedLines

INDEXFILE=$WDIR/index.html
exec 3<&1			# duplicate stdout to FD3.
exec 1<&-			# Close stdout.
exec > $INDEXFILE		# Open stdout to index file.

echo "<html>"
echo '<body bgcolor="#EEEEEE">'
echo "<title>${CWS##*/}</title>"
echo "<center><h1>${CWS##*/}</h1></center>"
echo "<p>"
echo "Parent workspace is $PWS <br>"
echo "Child  workspace is $CWS <br>"
printCI $TOTL $TINS $TDEL $TCHG $TUNC
echo "<hr>"
echo "<code>"

sed -e "s/#.*$//" -e "/=/d" -e "/^[   ]*$/d" $FLIST |

# ... and read lines from the cleaned-up file list

while read LINE
do
	set - $LINE
	P=$1

	if [ $# = 2 ]; then
		PP=$2
		OLDNAME=" <i>(was $PP)</i>"
	else
		PP=$P
		OLDNAME=""
	fi

	# Avoid processing the same file twice.
	# It's possible for renamed files to
	# appear twice in the file list

	F=$WDIR/$P

	# Group files in
	# the same directory

	D=${F%/*}
	if [ "$D" != "$PD" ]; then
		echo "<p>"
	else
		echo "<br>"
	fi
	echo
	echo
	PD=$D

	# If there's a diffs file, make diffs links

	if [ -f $F.cdiff.html ]; then
		echo "<a href=$P.cdiff.html>Cdiffs</a>"
		echo "<a href=$P.udiff.html>Udiffs</a>"

		if [ -x $WDIFF ]; then
			echo "<a href=$P.wdiff.html>Wdiffs</a>"
		fi

		echo "<a href=$P.sdiff.html>Sdiffs</a>"

		if [[ $WEBREV_FRAMES == 'yes' ]]; then
			print "<a href=\"$P.frames.html\">Frames</a>"
		fi
	else
		echo "------ ------ ------"

		if [ -x $WDIFF ]; then
			echo " ------"
		fi

		if [[ $WEBREV_FRAMES == 'yes' ]]; then
			print " ------"
		fi
	fi
	
	# If there's an old file, make the link

	if [ -f $F-.html ]; then
		echo "<a href=$P-.html>Old</a>"
	else
		echo "---"
	fi
	
	# If there's an new file, make the link

	if [ -f $F.html ]; then
		echo "<a href=$P.html>New</a>"
	else
		echo "---"
	fi
	echo "<b>$P</b>$OLDNAME<p>"

	# Insert delta comments

	if [ "$WXFILE" ]; then
		wxcomments $P
	else
		deltacomments $PP $P
	fi

	# Add additional comments comment

	echo "<!-- Add comments to explain changes in $P here -->"

	# Add count of changes.

	if [ -f $F.count ]; then
	    echo "<blockquote>"
	    cat $F.count
	    echo "</blockquote>"
	    rm $F.count
	fi
done

echo "</code>"
echo
echo
echo "<P><HR><FONT SIZE=2>"
echo "This code review page prepared with <b>webrev</b> (vers $WEBREV_UPDATED) on `date`."
echo "</FONT>"
echo "</html>"

exec 1<&-			# Close FD 1.
exec 1<&3			# dup FD 3 to restore stdout.
exec 3<&-			# close FD 3.

print "\n$WDIR created."
