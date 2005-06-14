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
<!-- Public document type declaration subset. Typical invocation:
<!ENTITY % atimath PUBLIC "-//ArborText//ELEMENTS Math Equation Structures//EN">
%atimath;
-->

<!-- Declarations for ArborText Equations (based on AAP math)
$Header: ati-math.elm,v 18.2 93/06/22 18:14:58 txf Exp $

NOTE: Dtgen excludes ati-math tags from the <docname>.menu and
<docname>.tags files it builds since the user cannot manipulate
these tags directly.  The tag exclusion algorithm requires that
the first and last math elements (in the order they are defined
in this file) be named <fd> and <rm> respectively.

If these assumptions are invalidated, then some math elements may
be included into the menus, or some of the DTD's elements might be 
excluded from the menus.
-->

<!ENTITY % p.em.ph	"b|it|rm">
<!ENTITY % p.fnt.ph	"blkbd|ig|sc|ge|ty|mit">
<!ENTITY % sp.pos	"vmk|vmkr|vsp|hsp|tu">
<!ENTITY % f-cs		"a|%p.em.ph|%p.fnt.ph|g|bg|%sp.pos">
<!ENTITY % f-cstxt	"#PCDATA|%f-cs">
<!ENTITY % f-scs	"rf|inc|v|dy|fi">
<!ENTITY % limits	"pr|in|sum">
<!ENTITY % f-bu		"fr|rad|lim|ar|stk|cases|eqaln|fen">
<!ENTITY % f-ph		"unl|ovl|unb|ovb|sup|inf">
<!ENTITY % f-butxt	"%f-bu|%limits|%f-cstxt|%f-scs|%f-ph|phr">
<!ENTITY % f-phtxt	"#PCDATA|%p.em.ph">
<!ENTITY % f-post       "par|sqb|llsqb|rrsqb|cub|ceil|fl|ang
                            |sol|vb|uc|dc">
<!ENTITY % f-style      "s|d|t|da|dot|b|bl|n">

<!ELEMENT fd		- - (fl)*>
<!ELEMENT fl		O O (%f-butxt)*>

  <![IGNORE [
  <!ELEMENT fd		- - (la?,fl)+>
  <!ELEMENT la		- - (%f-cstxt;|%f-ph;)*>
  <!ATTLIST la		loc		CDATA	#IMPLIED>
  ]]>

<!ELEMENT f		- - (%f-butxt)*>

<!ELEMENT fr		- - (nu,de)>
<!ATTLIST fr		shape		CDATA	#IMPLIED
			align		CDATA	#IMPLIED
			style		CDATA	#IMPLIED>
<!ELEMENT (nu|de)	O O (%f-butxt)*>
  <![IGNORE [
  <!ELEMENT lim		- - (op,ll,ul,opd?)>
  ]]>
<!ELEMENT lim		- - (op,ll?,ul?,opd?)>
<!ATTLIST lim		align		(r|c)	#IMPLIED>
  <![IGNORE [
  <!ELEMENT op		- - (%f-cstxt|rf|%f-ph) -(tu)>
  ]]>
<!ELEMENT op		- - (%f-cstxt|rf|%f-ph)* -(tu)>
<!ELEMENT (ll|ul)	O O (%f-butxt)*>
<!ELEMENT opd		- O (%f-butxt)*>
  <![IGNORE [
  <!ELEMENT (%limits)	- - (ll,ul,opd?)>
  ]]>
<!ELEMENT (%limits)	- - (ll?,ul?,opd?)>
<!ATTLIST (%limits)	align		CDATA	#IMPLIED>
<!ELEMENT rad		- - (rcd,rdx?)>
<!ELEMENT rcd		O O (%f-butxt)*>
<!ELEMENT rdx		- O (%f-butxt)* -(tu)>
  <![IGNORE [
  <!ELEMENT fen		- - ((%f-butxt)*,(cp,(%f-butxt)*)*,rp)>
  ]]>
<!ELEMENT fen		- - (%f-butxt|cp|rp)*>
<!ATTLIST fen		lp		(%f-post;)	vb
			style		(%f-style;)     s>
<!ELEMENT (cp|rp)	- O EMPTY>
<!ATTLIST (cp|rp)	post		(%f-post;)      vb
			style		(%f-style;)	s>
<!ELEMENT ar		- - (arr+)>
<!ATTLIST ar		cs		CDATA	#IMPLIED
			rs		CDATA	#IMPLIED
			ca		CDATA	#IMPLIED>
<!ELEMENT arr		- O (arc+)>
<!ELEMENT arc		O O (%f-butxt)*>
<!ATTLIST arc		align		CDATA	#IMPLIED>
<!ELEMENT cases		- - (arr+)>
<!ELEMENT eqaln		- - (eqline+)>
<!ELEMENT eqline	- - (%f-butxt)*>
<!ELEMENT stk		- - (lyr+)>
<!ELEMENT lyr		O O (%f-butxt)* -(tu)>
<!ATTLIST lyr		align		CDATA	#IMPLIED>
<!ELEMENT ach		- - (%f-butxt)*>
<!ATTLIST ach		atom		CDATA	#IMPLIED>
<!ELEMENT (sup|inf)	- - (%f-butxt)* -(tu)>
<!ATTLIST (sup|inf)	loc		CDATA	#IMPLIED>
<!ELEMENT (unl|ovl)	- - (%f-butxt)*>
<!ATTLIST (unl|ovl)	style		CDATA	#IMPLIED>
<!ELEMENT (unb|ovb)	- - (%f-butxt)*>
<!ELEMENT a		- - (ac,ac) -(tu)>
<!ATTLIST a		valign		CDATA	#IMPLIED>
  <![IGNORE [
  <!ELEMENT ac		O O (%f-cstxt|%f-scs)* -(sup|inf)>
  ]]>
<!ELEMENT ac		O O (%f-cstxt|%f-scs|sup|inf)*>
<!ELEMENT (%f-scs)	- O (%f-cstxt|sup|inf)* -(tu|%limits|%f-bu|%f-ph)>
<!ELEMENT phr		- O (%f-phtxt)*>
<!ELEMENT vmk		- O EMPTY>
<!ATTLIST vmk		id		CDATA	#IMPLIED>
<!ELEMENT vmkr		- O EMPTY>
<!ATTLIST vmkr		rid		CDATA	#IMPLIED>
<!ELEMENT (hsp|vsp)	- O EMPTY>
<!ATTLIST (hsp|vsp)	sp		CDATA	#IMPLIED>
<!ELEMENT tu		- O EMPTY>
<!ELEMENT (g|bg)	- - (#PCDATA)>
<!ELEMENT (%p.fnt.ph;)	- - (%f-cstxt)*>
<!ELEMENT (%p.em.ph;)	- - (%f-cstxt)*>

<!ENTITY % ISOamsa PUBLIC
 "ISO 8879:1986//ENTITIES Added Math Symbols: Arrow Relations//EN">
%ISOamsa;

<!ENTITY % ISOamsb PUBLIC
 "ISO 8879:1986//ENTITIES Added Math Symbols: Binary Operators//EN">
%ISOamsb;

<!ENTITY % ISOamsn PUBLIC
 "ISO 8879:1986//ENTITIES Added Math Symbols: Negated Relations//EN">
%ISOamsn;

<!ENTITY % ISOamso PUBLIC
 "ISO 8879:1986//ENTITIES Added Math Symbols: Ordinary//EN">
%ISOamso;

<!ENTITY % ISOamsr PUBLIC
 "ISO 8879:1986//ENTITIES Added Math Symbols: Relations//EN">
%ISOamsr;

<!ENTITY % ISOcyr1 PUBLIC "ISO 8879:1986//ENTITIES Russian Cyrillic//EN">
%ISOcyr1;

<!ENTITY % ISOdia PUBLIC "ISO 8879:1986//ENTITIES Diacritical Marks//EN">
%ISOdia;

<!ENTITY % ISOlat1 PUBLIC "ISO 8879:1986//ENTITIES Added Latin 1//EN">
%ISOlat1;

<!ENTITY % ISOlat2 PUBLIC "ISO 8879:1986//ENTITIES Added Latin 2//EN">
%ISOlat2;

<!ENTITY % ISOnum PUBLIC
 "ISO 8879:1986//ENTITIES Numeric and Special Graphic//EN">
%ISOnum;

<!ENTITY % ISOpub PUBLIC "ISO 8879:1986//ENTITIES Publishing//EN">
%ISOpub;

<!ENTITY % ISOtech PUBLIC "ISO 8879:1986//ENTITIES General Technical//EN">
%ISOtech;

<!ENTITY % ATIeqn1 PUBLIC "-//ArborText//ENTITIES Equation1//EN">
%ATIeqn1;





