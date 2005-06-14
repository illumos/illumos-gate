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
<!-- ArborText style table -->

<!-- It is assumed that %tblcon is defined when this file is included,
     to specify content for tablecell, e.g.,
	<!ENTITY % tblcon "#PCDATA|emphasis|%eqn|graphic" >
-->

<!-- [JFS] The table, tablerow and tablecell elements have a new
           attribute defined called "label". This attribute is
	   intended to be used by command language processing.
	   <tablecell> also has another attribute called "action". It
	   is anticipated that this attribute will also contribute to
	   command language processing of tables.
-->

<!ELEMENT table		- - (rowrule,(tablerow,rowrule)+)>
<!ATTLIST table		acl		CDATA	#IMPLIED
			chj		CDATA	#IMPLIED
			csl		CDATA	#IMPLIED
			cst		CDATA	#IMPLIED
			ctl		CDATA	#IMPLIED
			cwl		CDATA	#REQUIRED
			hff		CDATA	#IMPLIED
			hfs		CDATA	#IMPLIED
			htm		CDATA	#IMPLIED
			hts		CDATA	#IMPLIED
			jst		CDATA	#IMPLIED
			ncols		CDATA	#IMPLIED
			off		CDATA	#IMPLIED
			rth		CDATA	#IMPLIED
			rst		CDATA	#IMPLIED
			rvj		CDATA	#IMPLIED
			tff		CDATA	#IMPLIED
			tfs		CDATA	#IMPLIED
			tts		CDATA	#IMPLIED
			unt		CDATA	#IMPLIED
			wdm		CDATA	#REQUIRED
			ctmarg		CDATA	#IMPLIED
			cbmarg		CDATA	#IMPLIED
			clmarg		CDATA	#IMPLIED
			crmarg		CDATA	#IMPLIED
			dispwid		CDATA	#IMPLIED
			label		CDATA	#IMPLIED
			>

<!ELEMENT tablerow	- O (cellrule,(tablecell,cellrule)+)>
<!ATTLIST tablerow	hdr		CDATA	#IMPLIED
			rht		CDATA	#IMPLIED
			rvj		CDATA	#IMPLIED
			label           CDATA   #IMPLIED
			>

<!ELEMENT tablecell	- - (%tblcon)*>

<!ATTLIST tablecell	cff		CDATA	#IMPLIED
			cfs		CDATA	#IMPLIED
			chj		CDATA	#IMPLIED
			cts		CDATA	#IMPLIED
			cvj		CDATA	#IMPLIED
			shd		CDATA	#IMPLIED
			spn		CDATA	#IMPLIED
			vspn		CDATA	#IMPLIED
			label           CDATA   #IMPLIED
			action		CDATA	#IMPLIED>

<!ELEMENT rowrule	- O EMPTY>
<!ATTLIST rowrule	rty		CDATA	#IMPLIED
			rtl		CDATA	#IMPLIED>

<!ELEMENT cellrule	- O EMPTY>
<!ATTLIST cellrule	rty		CDATA	#IMPLIED>
