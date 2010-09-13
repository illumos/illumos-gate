#!/usr/bin/perl -w
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Make a dynamic HTML page for the unified diffs between two (C) files.
#

use Getopt::Std;

$diffword = "wdiff";
$context = 10;

getopt('t:c:');

if ($#ARGV + 1 == 1) {
	$diffword = $ARGV[0];
	open DIFF, "<&STDIN";
	$ARGV[0] = '-';
	$ARGV[1] = '-';
} elsif ($#ARGV + 1 == 2) {
	open DIFF, "diff -D $diffword $ARGV[0] $ARGV[1] | expand |";
} else {
	print "Usage: $0 [-t title] [-c comment] file1 file2\n";
	exit 2;
}

$title = $opt_t ? $opt_t : "Differences between $ARGV[0] and $ARGV[1]";
$comment = "";
if (defined $opt_c) {
	$comment = "<pre>\n" . $opt_c . "\n</pre>\n<hr />";
}

$indiff = 0;
$line1 = 0;
$line2 = 0;
@pretext = ();		# Speculative pretext buffer (code)
$posttext = 0;		# Lines of posttext to print
$nelided = 0;		# Number of elided chunks
$endfunc = 0;		# Seen end of function?
$inelided = 0;		# Elided section open?
$elided_lines = 0;

print <<END;
<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>
    <title>$title</title>

    <meta http-equiv="cache-control" content="no-cache" />

    <style type='text/css' media='screen'>
      pre	{ margin: 2px; }

      body	{ background-color: #eeeeee; }

      hr	{ border: none 0; border-top: 1px solid #aaa; height: 1px; }

      .subtracted { color: brown }
      .added	{ color: blue }

      .elided	{ border: 1px solid #444; cursor: pointer; margin: 1px }

      table.hidebar { border: 1px solid #ff9900; background-color: #eee;
      		  text-align: center; border-collapse: collapse; }

      .hidebar td.active-down { border: 1px solid #ff9900;
		border-right: 1px solid #ccc; cursor: s-resize }

      .hidebar td.active-down:hover { background-color: #ffcc99; }

      .hidebar td.active-up { border: 1px solid #ff9900; cursor: n-resize;
		border-left: 1px solid #ccc; }

      .hidebar td.active-up:hover { background-color: #ffcc99; }

      .hidebar td.elided-label { font-style: italic; width: 12em; }

      .cmdbox	{ position: fixed; top: 0; right: 0;
	          border-left: solid 1px #444;
	          border-bottom: solid 1px #444;
      		  background-color: #ccc; text-align: center }

      .cmdbox td { background-color: #eee; border: 1px #444 outset;
		   cursor: pointer; padding: 3px 4px; }
      .cmdbox td:hover { background-color: #ffcc99;
 		outline: thin solid #ff9900; }

      a:hover { background-color: #ffcc99; }

      a.print { font-size: x-small; }
    </style>

    <style type='text/css' media='print'>
	pre { font-family: courier, monospace; font-size: 0.8em; }
	.cmdbox { display: none; }
        a.print { display: none; }
	.hidebar td.active-down { display: none; }
	.hidebar td.active-up { display: none; }
        .hidebar td.elided-label { font-style: italic; font-size: small; }
	table.hidebar { border: none; border-bottom: 1px dotted #000000; }
	span.added { font-weight: bold;
	         background-color: #eee; width: 100%; display: block; }
	span.subtracted { font-style: italic;
		 background-color: #eee; width: 100%; display: block; }
	.elided { display: none; }
        hr { border: none 0; border-top: 1px solid #aaa; height: 1px; }
    </style>

    <script type="text/javascript">
      function show_n_hide_dir(id_to_show, id_to_hide, dir) {
	      var elt_to_show = document.getElementById(id_to_show);
	      var elt_to_hide = document.getElementById(id_to_hide);
	      // When we're opening up, we need to make the bottoms of the
	      // elements appear to be the same.  So our invariant should be
	      // elt.offsetBottom - window.scrollY.
	      var preinvar = elt_to_hide.offsetHeight - window.scrollY;
	      elt_to_show.style.setProperty('display', '', '');
	      elt_to_hide.style.setProperty('display', 'none', '');
	      if (dir == 'up') {
		      var postinvar = elt_to_show.offsetHeight - window.scrollY;
		      window.scrollBy(0, postinvar - preinvar);
	      }
      }

      function handle_click(e) {
	      var eh = e.target;
	      var es = document.getElementById("hb-" + e.target.id);
	      eh.style.setProperty('display', 'none', '');
	      es.style.setProperty('display', '', '');
	      /* Scroll so new element is at cursor. */
	      window.scroll(0, es.offsetTop + (es.offsetHeight / 2)
	          - e.clientY);
      }

      function stripsearch(str) {
	q = str.indexOf("?");
	if (q != -1)
	  str = str.substr(0, q);
	return (str);
      }

      function split() {
        page = stripsearch(location.href);
	halfway = window.scrollY + window.innerHeight / 2 - 5;
	document.write('<frameset rows="50%,*">' +
	  '<frame src="' + page + "?" + window.scrollY + '" />' +
	  '<frame src="' + page + "?" + halfway + '" />' +
	  '</frameset>');
	document.close();
      }

      function closeframe() {
	page = stripsearch(location.href);

	otherf = window.parent.frames[0];
	if (otherf == window)
	  otherf = window.parent.frames[1];

	parent.location.replace(page + "?" + otherf.scrollY);
      }
    </script>
  </head>
  <body id='SUNWwebrev'>
    <a class="print" href="javascript:print()">Print this page</a>
    $comment
    <table class='cmdbox'>
      <tr>
        <td onclick='split()'>Split</td>
	<td id='close' onclick='closeframe()'>Close</td>
      </tr>
      <tr><td colspan="2" onclick='open_or_close_all(1)'>Expand all</td></tr>
      <tr><td colspan="2" onclick='open_or_close_all(0)'>Collapse all</td></tr>
    </table>

    <script type='text/javascript'>
      if (window == top)
        document.getElementById('close').style.setProperty('display', 'none', '');
    </script>
END

print "<pre><span class='subtracted'>          --- $ARGV[0]
</span><span class='added'>          +++ $ARGV[1]
</span>";

sub begin_elided {
	++$nelided;
	# onclick handler assigned at bottom
	print "<pre id='elided$nelided' class='elided' style='display: none'>";
	$inelided = 1;
	$elided_lines = 0;
}

sub end_elided {
	print "</pre>\n";

	print <<END;
<table id='hb-elided$nelided' class='hidebar'>
  <tr>
    <td class='active-down'
      onclick='show_n_hide_dir("elided$nelided", "hb-elided$nelided", "down")'>
      &darr;&nbsp;open down&nbsp;&darr;</td>
    <td class="elided-label">$elided_lines lines elided</td>
    <td class='active-up'
      onclick='show_n_hide_dir("elided$nelided", "hb-elided$nelided", "up")'>
      &uarr;&nbsp;open up&nbsp;&uarr;</td>
  </tr>
</table>
END
	$inelided = 0;
}

while (<DIFF>) {
	chomp;

	# Change detection
	$previndiff = $indiff;

	if (!$indiff) {
		if (/^#ifdef $diffword$/) {
			$indiff = 1;
		} elsif (/^#ifndef $diffword$/) {
			$indiff = -1;
		}
	} else {
		if (/^#else \/\* $diffword \*\/$/) {
			$indiff = -$indiff;
			print "</span>";
			printf "<span class='%s'>",
			    ($indiff > 0 ? "added" : "subtracted");
			next;
		} elsif (/^#endif \/\* (! )?$diffword \*\/$/) {
			$indiff = 0;
			$posttext = $context;
			print "</span>";
			next;
		}
	}

	if (!$previndiff && $indiff) {
		# Beginning of a change: If we have an elided section open,
		# end it.  Print the pretext and continue.

		if ($inelided) {
			end_elided;
			print "<pre>";
		}

		print @pretext;
		@pretext = ();
		$endfunc = 0;

		printf "<span class='%s'>",
		    ($indiff > 0 ? "added" : "subtracted");
		next;
	}

	# Line of code

	# Quote for HTML
	s/&/&amp;/g;
	s/</&lt;/g;
	s/>/&gt;/g;

	# Format the line according to $indiff, and print it or put it into
	# a buffer.
	if ($indiff == -1) {
		++$line1;
		printf "%4d %4s -%s\n", $line1, "", $_;
	} elsif ($indiff == 0) {
		++$line1;
		++$line2;

		$str = sprintf "%4d %4d  %s\n", $line1, $line2, $_;

		if ($posttext > 0) {
			print $str;
			--$posttext;
		} else {
			push @pretext, $str;
			if ($#pretext + 1 > $context) {
				$str = shift @pretext;

				if (!$inelided) {
					print "</pre>\n";
					begin_elided;
				}

				++$elided_lines;

				print $str;
			}
		}
	} elsif ($indiff == 1) {
		++$line2;
		printf "%4s %4d +%s\n", "", $line2, $_;
	}
}

print @pretext;

if ($inelided) {
	$elided_lines += @pretext;
	end_elided;
} else {
	print "    </pre>\n";
}

print "<pre id='linerefpre'><span id='lineref'>", 'X' x (4 + 1 + 4 + 2 + 80),
    "</span></pre>\n";

print <<END;
    <br clear="all" />
    <br />

    <script type="text/javascript">
      /* Assign event handlers and widths. */
      var w = document.getElementById('lineref').offsetWidth;
      for (var i = 1; i <= $nelided; ++i) {
	      var e = document.getElementById("elided" + i);
	      e.onclick = handle_click;
              e.style.setProperty('width', w + "px", '');

	      e = document.getElementById("hb-elided" + i);
              e.style.setProperty('width', w + "px", '');
      }

      /* Hide our line size reference. */
      document.getElementById('linerefpre').style.setProperty('display',
          'none', '');

      /* Scroll as indicated. */
      str = location.search;
      s = str.substring(1, str.length);
      if (s > 0)
        window.scroll(0, s);

      function open_or_close_all(open) {
	      for (var i = 1; i <= $nelided; ++i) {
		      var e = document.getElementById("hb-elided" + i);
		      e.style.setProperty("display", open ? "none" : "", "");

		      e = document.getElementById("elided" + i);
		      e.style.setProperty("display", open ? "" : "none", "");
	      }
      }
    </script>
  </body>
</html>
END
