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
<!-- CORE DTD SUBSET
	This subset declaration defines a core set of elements. The subset
	includes some common basic elemnents such as paragraphs, lists,
	figures, footnotes, etc. It does not contain any definitions for
	heirarchical elements such as front, body, rear, chapters,
	sections, etc. The elements below are intended to be included in a
	master dtd by reference, e.g., to defined the content of a section,
	the master dtd would only need to declare the section and any
	heirarchical elements included therein, but not need to decalare
	anything at the "leaf" level:

		<!ELEMENT section - O (title,(%parlevel;|subsect))

	In other words the dtd author concentrates on the document
	structure and simply references the leaf level components.
-->

<!ENTITY % par "par">
<!ENTITY % fig "figure">
<!ENTITY % footnote "footnote">
<!ENTITY % graphic "graphic">
<!ENTITY % list "list">
<!ENTITY % xref "xref">

<!ENTITY % notes "%footnote;|endnote|citation">
<!ENTITY % text  "CDATA" -- text, no entities (e.g., no diacritics) -->
<!ENTITY % etext "#PCDATA" -- text with entities (e.g., diacritics) -->
<!ENTITY % eqn  "display-equation">
<!ENTITY % table "table">
<!ENTITY % emphasis "bold|ital|boldit|under">
<!ENTITY % figures "%graphic;|reserve-space|%table|figurepar">
<!ENTITY % parlevel "%par;|%fig;|%list;|list|computer|poetry|%eqn|extract">
<!ENTITY % subp.a1 "%etext|%xref;|super|sub|%emphasis|indexterm|inline-equation">
<!ENTITY % subp.a2 "%subp.a1|%notes">
<!-- note, since subp.b is a subset of parlevel, don't include subp.b
 in any model that contains parlevel (in the same "or" group)-->
<!ENTITY % subp.b "computer|%eqn|%list|extract|poetry">

<!ENTITY % tblcon "%subp.a2|%subp.b|graphic" >

<!ENTITY % jfstable PUBLIC "-//ArborText//ELEMENTS jfs Table Structures//EN">
%jfstable;

<!ELEMENT %par;  - - (%subp.a2|%subp.b)*>

<!ELEMENT %list;  - - (item)*>
<!ELEMENT list - O (li,li,li*) >

<!ELEMENT (item|li) O O (%subp.a2|%subp.b)*>
<!ATTLIST item state (0|1) "0" 
               id  ID #IMPLIED>

<!ELEMENT %fig; - - (caption?,(%figures|%subp.b)*)>

<!ELEMENT extract - O (%parlevel)*>

<!ELEMENT poetry - O (%subp.a2)*>

<!ELEMENT caption - O (%subp.a2)*>
<!ATTLIST caption id  ID #IMPLIED>

<!ELEMENT %graphic; - O EMPTY>
<!ATTLIST %graphic; filename CDATA #IMPLIED
   type       CDATA #IMPLIED
   mag        NUMBER #IMPLIED
   vertadjpct CDATA -25>

<!ELEMENT reserve-space - O EMPTY>


<!-- eqn [mostly aap]-->
<!-- NOTE:
        We include and use our
        math equation document declaration subset.
-->

<!ENTITY % atimath PUBLIC "-//ArborText//ELEMENTS Math Equation Structures//EN">
%atimath;

<!ELEMENT display-equation - - (equation-caption?,fd?) >
<!ATTLIST display-equation id  ID #IMPLIED>

<!ELEMENT equation-caption - - (%subp.a2)*>

<!ELEMENT inline-equation - - (f)? >


<!ELEMENT figurepar - - (%subp.a1|%subp.b)*>

<!ELEMENT computer - - (%etext)*>

<!ELEMENT super  - - (%subp.a1)*  -(super)>

<!ELEMENT sub  - - (%subp.a1)*  -(sub)>

<!ELEMENT (%emphasis;) - - (%subp.a1)*  -(%emphasis;)>

<!ELEMENT indexterm - - (%etext|indextopic)* >

<!ELEMENT indextopic - - (%etext)*>

<!ELEMENT %footnote; - - (notepar)+>

<!ELEMENT endnote - - (notepar)+>

<!ELEMENT endnotes - O EMPTY>

<!ELEMENT notepar O O (%subp.a1|%subp.b)*>

<!ELEMENT %xref; - O EMPTY>
<!ATTLIST %xref; refid IDREF #REQUIRED>

<!ELEMENT citation - - %text>
<!ATTLIST citation citid  ID #IMPLIED>
