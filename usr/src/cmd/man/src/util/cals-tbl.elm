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

<!--	This entity is fragment of:

	<!DOCTYPE doc PUBLIC "-//USA-DOD//DTD MIL-M-38784B 910201//EN">

	...and contains the elements that define CALS tables.

	NOTE:  The table elements and ATTLISTs reference a number
	of other elements and parametric entities that are not
	defined in this fragment.  They are listed below.


Parametric entities that must be defined by the referencing entity:

	ENTITY NAME	WHERE USED
	%titles		In content model of:
			<table>
			<chart>

	%yesorno	In ATTLIST of:
			<table>
			<chart>
			<tgroup>
			<colspec>
			<spanspec>
			<row>
			<entry>
			<entrytbl>

	%bodyatt	In ATTLIST of:
			<table>
			<chart>
			
	%secur		In ATTLIST of:
			<table>
			<chart>
			<tgroup>
			<thead>
			<tfoot>
			<tbody>
			<row>
			<entry>
			<entrytbl>

	%paracon	In content model of:
			<entry>



Elements that are referenced either in a content model,
inclusions, or exclusions. 

	<chart>/<table> content model:
		%titles;

	<chart>/<table> exclusion list: 
		<figure>

	<entry> content model:
		<para>
		<warning>
		<caution>
		<note>
		<legend>
		%paracon;

-->


<!-- The table elements:  -->

<!ELEMENT (table | chart) - - (%titles;, tgroup+)     -(table | chart | figure)>

<!ATTLIST (table | chart)   tabstyle    NMTOKEN     #IMPLIED
                            tocentry    %yesorno;   "1"
                            shortentry  %yesorno;   #IMPLIED
                            frame  (top|bottom|topbot|all|sides|none) #IMPLIED
                            colsep      %yesorno;    #IMPLIED
                            rowsep      %yesorno;    #IMPLIED
                            orient    (port | land)  #IMPLIED
                            pgwide      %yesorno;    #IMPLIED
                            %bodyatt;
                            %secur; >

<!ELEMENT tgroup  - o   (colspec*, spanspec*, thead?, tfoot?, tbody) >

<!ATTLIST tgroup  cols         NUMBER   #REQUIRED
                  tgroupstyle  NMTOKEN  #IMPLIED
                  colsep       %yesorno;  #IMPLIED
                  rowsep       %yesorno;  #IMPLIED
                  align  (left | right | center | justify | char )  "left"
                  charoff      NUTOKEN     "50"
                  char         CDATA       ""
                  %secur; >

<!ELEMENT colspec    - o   EMPTY>

<!ATTLIST colspec  colnum     NUMBER      #IMPLIED
                   colname    NMTOKEN     #IMPLIED
                   align  (left|right|center|justify|char)  #IMPLIED
                   charoff    NUTOKEN     #IMPLIED
                   char       CDATA       #IMPLIED
                   colwidth   CDATA       #IMPLIED
                   colsep     %yesorno;   #IMPLIED
                   rowsep     %yesorno;   #IMPLIED>

<!ELEMENT spanspec    - o   EMPTY >

<!ATTLIST spanspec  namest    NMTOKEN     #REQUIRED
                    nameend   NMTOKEN     #REQUIRED
                    spanname  NMTOKEN     #REQUIRED
                    align  (left|right|center|justify|char)  "center"
                    charoff   NUTOKEN     #IMPLIED
                    char      CDATA       #IMPLIED
                    colsep    %yesorno;   #IMPLIED
                    rowsep    %yesorno;   #IMPLIED>

<!ELEMENT (thead | tfoot)   - o   (colspec*, row+)  -(entrytbl) >

<!ATTLIST thead   valign  (top | middle | bottom) "bottom"
                  %secur; >

<!ATTLIST tfoot   valign   (top | middle | bottom) "top"
                  %secur; >

<!ELEMENT tbody   - o   (row+) >

<!ATTLIST tbody   valign  (top | middle | bottom)  "top"
                  %secur; >

<!ELEMENT row     - o   (entry | entrytbl)+ >

<!ATTLIST row   rowsep   %yesorno;   #IMPLIED
                %secur; >

<!--CHANGE 910201 - FOLLOWING ELEMENT CHANGED  -->

<!ELEMENT entry   - o   (para | warning | caution | note | legend | %paracon;)+>

<!--CHANGE 910201 - FOLLOWING ATTLIST CHANGED  -->

<!ATTLIST entry   colname     NMTOKEN     #IMPLIED
                  namest      NMTOKEN     #IMPLIED
                  nameend     NMTOKEN     #IMPLIED
                  spanname    NMTOKEN     #IMPLIED
                  morerows    NUMBER      "0"
                  colsep      %yesorno;   #IMPLIED
                  rowsep      %yesorno;   #IMPLIED
                  rotate      %yesorno;   "0"
                  valign  (top | bottom | middle)  "top"
                  align  (left | right | center | justify | char )  #IMPLIED 
                  charoff      NUTOKEN    #IMPLIED
                  char         CDATA      #IMPLIED
                  %secur; >

<!-- ELEMENT      ATTR  MIN   VALUE CONTENT     DEFAULT     EXCEPT -->

<!ELEMENT entrytbl   - -  (colspec*, spanspec*, thead?, tbody)+     -(entrytbl)>

<!ATTLIST entrytbl  cols    NUMBER    #REQUIRED
                   tgroupstyle  NMTOKEN  #IMPLIED
                   colname      NMTOKEN  #IMPLIED
                   spanname     NMTOKEN  #IMPLIED
                   colsep       %yesorno; #IMPLIED
                   rowsep       %yesorno; #IMPLIED
                   align  (left | right | center | justify | char )  #IMPLIED
                   charoff      NUTOKEN    #IMPLIED
                   char         CDATA      #IMPLIED
                   %secur; >








