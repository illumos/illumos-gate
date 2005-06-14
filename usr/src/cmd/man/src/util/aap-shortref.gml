<!--
    Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
    Use is subject to license terms.

    CDDL HEADER START

    The contents of this file are subject to the terms of the
    Common Development and Distribution License, Version 1.0 only
    (the "License").  You may not use this file except in compliance
    with the License.

    You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
    or http://www.opensolaris.org/os/licensing.
    See the License for the specific language governing permissions
    and limitations under the License.

    When distributing Covered Code, include this CDDL HEADER in each
    file and include the License file at usr/src/OPENSOLARIS.LICENSE.
    If applicable, add the following below this CDDL HEADER, with the
    fields enclosed by brackets "[]" replaced with your own identifying
    information: Portions Copyright [yyyy] [name of copyright owner]

    CDDL HEADER END
-->
<!-- SCCS keyword
#pragma ident	"%Z%%M%	%I%	%E% SMI"
-->
<!-- Public entity for AAP short reference maps.  Typical invocation:
  <!ENTITY % srmaps PUBLIC "-//USA/AAP//SHORTREF SR-1//EN" >   %srmaps;
  NOTE: The entity "mdash" must be defined before invoking this one.
-->
<!ENTITY  s..line  STARTTAG "line">
<!ENTITY  s..p     STARTTAG "p" >
<!ENTITY  s..q     STARTTAG "q" >
<!ENTITY  e..q     ENDTAG   "q" >
<!ENTITY  s..li    STARTTAG "li" >
<!ENTITY  s..c     STARTTAG "c" >
<!ENTITY  s..row   STARTTAG "row" >
<!ENTITY  c..null  CDATA    "" >
<!ENTITY  s..dt    STARTTAG "dt" >
<!ENTITY  s..dd    STARTTAG "dd" >
<!SHORTREF bkmap
           "&#RS;&#RE" s..p  -- null record is paragraph start-tag  --
           "&#RS;B"    c..null -- leading blanks are suppressed --
           '"'      s..q     -- quotation is quote start-tag --
           "--"     mdash    -- two hyphens is an em dash --
>
<!SHORTREF qmap
           '"'      e..q     -- quotation is quote end-tag --
           "--"     mdash    -- two hyphens is an em dash --
>
<!SHORTREF dlmap
           "#"      s..dt    -- number sign is def term start-tag --
           "|"      s..dd    -- vertical bar is def descr start-tag --
           "&#RS;&#RE;" s..p  -- null record is paragraph start-tag  --
           "&#RS;B"    c..null -- leading blanks are suppressed --
           '"'      s..q     -- quotation is quote start-tag --
           "--"     mdash    -- two hyphens is an em dash --
>
<!SHORTREF listmap
           "#"      s..li    -- number sign is list item start-tag --
           "&#RS;&#RE;" s..p  -- null record is paragraph start-tag  --
           "&#RS;B"    c..null -- leading blanks are suppressed --
           '"'      s..q     -- quotation is quote start-tag --
           "--"     mdash    -- two hyphens is an em dash --
>
<!SHORTREF litmap
           "&#RS;"   s..line -- record start is line start-tag --
           "--"     mdash    -- two hyphens is an em dash --
>
<!SHORTREF tblmap
           "@"      s..row   -- commercial at is row start-tag --
           "|"      s..c     -- vertical bar is tbl entry start-tag --
           "&#RS;&#RE;" s..p -- null record is paragraph start-tag  --
           "&#RS;B"    c..null -- leading blanks are suppressed --
           '"'      s..q     -- quotation is quote start-tag --
           "--"     mdash    -- two hyphens is an em dash --
>
