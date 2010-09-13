<!SGML  "ISO 8879:1986"
-- Copyright 2005 Sun Microsystems, Inc.  All rights reserved. --
-- Use is subject to license terms. --
-- --
-- CDDL HEADER START --
-- --
-- The contents of this file are subject to the terms of the --
-- Common Development and Distribution License, Version 1.0 only --
-- (the "License").  You may not use this file except in compliance --
-- with the License. --
-- --
-- You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE --
-- or http://www.opensolaris.org/os/licensing. --
-- See the License for the specific language governing permissions --
-- and limitations under the License. --
-- --
-- When distributing Covered Code, include this CDDL HEADER in each --
-- file and include the License file at usr/src/OPENSOLARIS.LICENSE. --
-- If applicable, add the following below this CDDL HEADER, with the --
-- fields enclosed by brackets "[]" replaced with your own identifying --
-- information: Portions Copyright [yyyy] [name of copyright owner] --
-- --
-- CDDL HEADER END --
-- --
-- ident	"%Z%%M%	%I%	%E% SMI" --

         --  SGML Declaration for SolBook 2.0  --

CHARSET

        BASESET   "ISO 646:1983//CHARSET
                   International Reference Version (IRV)//ESC 2/5 4/0"
        DESCSET
                    0   9   UNUSED
                    9   2   9
                   11   2   UNUSED
                   13   1   13
                   14  18   UNUSED
                   32  95   32
                  127   1   UNUSED

        BASESET   "ISO Registration Number 100//CHARSET
                   ECMA-94 Right Part of Latin Alphabet Nr. 1//ESC 2/13 4/1"
        DESCSET  
                  128  32   UNUSED
                  160  96   32


CAPACITY  SGMLREF

        TOTALCAP 99000000
        ATTCAP    1000000
        ATTCHCAP  1000000
        AVGRPCAP  1000000
        ELEMCAP   1000000
        ENTCAP    1000000
        ENTCHCAP  1000000
        GRPCAP    1000000
        IDCAP    45000000
        IDREFCAP 45000000
  
	--
                TOTALCAP        4000000
                ATTCAP           256000
                AVGRPCAP         256000
                ENTCAP           300000
                ENTCHCAP         350000
                GRPCAP           300000
                IDCAP           2000000
	--

SCOPE    DOCUMENT

SYNTAX

        SHUNCHAR CONTROLS   0   1   2   3   4   5   6   7   8   9
                           10  11  12  13  14  15  16  17  18  19
                           20  21  22  23  24  25  26  27  28  29
                           30  31                     127 128 129
                          130 131 132 133 134 135 136 137 138 139
                          140 141 142 143 144 145 146 147 148 149
                          150 151 152 153 154 155 156 157 158 159

        BASESET  "ISO 646:1983//CHARSET
                  International Reference Version (IRV)//ESC 2/5 4/0"
        DESCSET
                 0 128 0


        FUNCTION
                  RE          13
                  RS          10
                  SPACE       32
                  TAB SEPCHAR  9

        NAMING
                  LCNMSTRT ""
                  UCNMSTRT ""
                  LCNMCHAR ".-_"
                  UCNMCHAR ".-_"
                  NAMECASE GENERAL YES
                           ENTITY  NO

        DELIM     GENERAL  SGMLREF
                  SHORTREF SGMLREF

        NAMES     SGMLREF

        QUANTITY  SGMLREF
		  ATTCNT    256
                  GRPCNT    253
                  GRPGTCNT  253
                  LITLEN   8092
                  NAMELEN    44
                  TAGLVL    100

FEATURES

        MINIMIZE
                  DATATAG  NO
                  OMITTAG  NO
                  RANK     NO
                  SHORTTAG YES 

        LINK
                  SIMPLE   NO
                  IMPLICIT NO
                  EXPLICIT NO

        OTHER
                  CONCUR   NO
                  SUBDOC   NO
                  FORMAL   NO

        APPINFO   NONE
>
<!-- version: $Id: solbook.dcl	1.9 - 98/04/06 16:53:26 altheim $ -->
