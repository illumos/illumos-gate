#############################################################################
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#	solbook-to-man.ts
#
#############################################################################
#
# Copyright (c) 1996 X Consortium
# Copyright (c) 1996 Dalrymple Consulting
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# X CONSORTIUM OR DALRYMPLE CONSULTING BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# Except as contained in this notice, the names of the X Consortium and
# Dalrymple Consulting shall not be used in advertising or otherwise to
# promote the sale, use or other dealings in this Software without prior
# written authorization.
# 
#############################################################################
#
# Written 5/29/96 by Fred Dalrymple
#
#############################################################################
#
#  Variables
#
Var:	callout 0
Var:	orderlist 0
Var:	nestorderlist 0
Var:	procstep 0
Var:	procsubstep 0
Var:	examplenum 1
Var:	tablenum 1
Var:	firstpara false
Var:	nestedpara false
Var:	termcount 0
#
#
#
#
#############################################################################
#
#  Hierarchy (and document meta stuff)
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		REFENTRY
StartText:	.TH ${_followrel descendant REFENTRYTITLE 1000}
		${_followrel descendant MANVOLNUM 1000}
EndText:	...\\" created by instant / solbook-to-man, ${date}
-
#
GI:		REFMISCINFO
#	The Last Change date
AttValue:	CLASS DATE
Set:	the_date ${+content}
Ignore:	data
-
#
GI:		REFMISCINFO
#	The OS release string
AttValue:	CLASS SOFTWARE
Set:	the_release ${+content}
Ignore:	data
-
#
GI:		REFMISCINFO
#	The section title
AttValue:	CLASS SECTDESC
Set:	the_sect ${+content}
Ignore:	data
-
GI:		REFMISCINFO
# Do nothing
Ignore:		data
-
#
GI:		REFMETA
# Use the end of refmeta to output the arguments for the .TH macro
EndText:	\s"${the_date}"\s"${the_release}"\s"${the_sect}"
-
#
#
GI:		DOCINFO
Ignore:		all
-
#
GI:		TITLE
Context:	DOCINFO
#	inside DocInfo, which we're ignoring
-
GI:		REFNAMEDIV
StartText:	.SH "NAME"
-
#
GI:		REFDESCRIPTOR
EndText:	,\s${_set refnameseen xy}
-
#
GI:		REFNAME
Relation:	sibling-1 REFDESCRIPTOR
EndText:	,\s
-
#
GI:		REFNAME
StartText:	${_isset refnameseen xxx 20}
EndText:	${_set refnameseen xxx}
-
#
GI:		_rfname
SpecID:		20
Ignore:		data
StartText:	,\s
EndText:	${_set refnameseen xy}
-
#
GI:		REFPURPOSE
StartText:	\s\\-\s
EndText:	
-
#
GI:		REFCLASS
StartText:	.PP
EndText:	
-
#
GI:		REFSYNOPSISDIV
StartText:	.SH "SYNOPSIS"
EndText:	
-
#
GI:             TITLE
Context:        REFSYNOPSISDIV
Ignore:         all
-
#
GI:		REFSECT1
StartText:	.SH "${_followrel child TITLE 1000}"
EndText:	
-
#
GI:		REFSECT2
StartText:	.SS "${_followrel child TITLE 1000}"
EndText:	
-
#
GI:		REFSECT3
StartText:	.SS "${_followrel child TITLE 1000}"
EndText:	
-
#
GI:		BRIDGEHEAD
StartText:	.PP\\fB
EndText:	\\fR.PP
-
#
GI:		TITLE
Context:	REFSECT1
Ignore:		all
-
#
GI:		TITLE
Context:	REFSECT2
Ignore:		all
-
#
GI:		TITLE
Context:	REFSECT3
Ignore:		all
-
#
GI:		LEGALNOTICE
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		TITLE
Context:	LEGALNOTICE
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		REFENTRYTITLE
Context:	REFMETA
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		MANVOLNUM
Context:	REFMETA
#	part of the DocInfo structure, which is ignored, though this element
#	if accessed directly by the _followrel call from the REFENTRY element.
Ignore:		all
-
#
GI:		SUBTITLE
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		AUTHORGROUP
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		AUTHOR
Context:	AUTHORGROUP
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		EDITOR
Context:	AUTHORGROUP
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		COLLAB
Context:	AUTHORGROUP
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		COLLABNAME
Context:	COLLAB
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		CORPAUTHOR
Context:	AUTHORGROUP
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
GI:		OTHERCREDIT
Context:	AUTHORGROUP
#	part of the DocInfo structure, which is ignored
Ignore:		all
-
#
#
#############################################################################
#
#  (before we get into the branch stuff, we turn off paragraphs in some
#   contexts where they would break the flow.  Generally, this happens
#   within indented areas, such as within lists.
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		PARA
Context:	ENTRY
NthChild:	1
#	nothing in this context
-
#
GI:		PARA
Context:	ENTRY
StartText: .br.sp 1
-
#
GI:		PARA
Context:	NOTE
NthChild:	1
EndText:	.sp 1
-
#
GI:		PARA
Context:	NOTE
# EndText handled in NOTE EndText
-
#
GI:		PARA
Context:	CAUTION
# EndText handled in CAUTION EndText
-
#
GI:		PARA
Context:	GLOSSDEF
NthChild:	1
#	nothing in this context
-
#
GI:		PARA
Context:	STEP
NthChild:	1
StartText:	\\fB
EndText:	\\fR
-
#
GI:     PARA
Context:    STEP
Relation:   sibling-1 TITLE
StartText:  \\fB
EndText:    \\fR
-
#
GI:		PARA
Context:	STEP
StartText:	.sp 2n
-
#
GI:		PARA
Context:	CALLOUT
NthChild:	1
#	nothing in this context
-
#
GI:		PARA
Context:	MSGTEXT
NthChild:	1
#	nothing in this context
-
#
GI:		PARA
Context:	MSGEXPLAN
NthChild:	1
#	nothing in this context
-
#
#
#############################################################################
#
#  Regular "branch" stuff
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		FORMALPARA
#	it's all done in TITLE (FORMALPARA) and PARA
-
#
GI:		TITLE
Context:	FORMALPARA
StartText:	.PP\\fB
EndText:	\\fR
-
#
GI:		PARA
Context:	LISTITEM
EndText:	.sp
-
#
GI:		PARA
Relation:	ancestor ORDEREDLIST
StartText:	.sp
-
#
GI:		PARA
Context:	LISTITEM
Relation:	ancestor VARLISTENTRY
NthChild:	1
EndText:	.sp
-
#
GI:       PARA
Relation:   ancestor VARLISTENTRY
StartText:    .sp
-
#
GI:		PARA
Context:	INFORMALEXAMPLE
StartText:	.RS
EndText:	.RE
-
#
GI:		PARA
Relation:	ancestor STEP
StartText:	.IP "" 10
-
#
GI:		PARA
StartText:	.PP
-
#
GI:		SIMPARA
StartText:	.PP
-
#
GI:     PROGRAMLISTING
StartText:  .sp.nf\\f(CW
EndText:    \\fR.fi.sp
-
#
GI:		LITERALLAYOUT
Context:	ENTRY
StartText:	.nf
EndText:	.fi
-
#
#GI:		LITERALLAYOUT
#Relation:	ancestor LISTITEM
#StartText:	.nf.sp
#EndText:	.fi.sp
#-
#
GI:		LITERALLAYOUT
StartText:	.sp.nf
EndText:	.fi.sp
-
#
GI:		BLOCKQUOTE
StartText:	.PP.RS
EndText:	.RE
-
#
GI:		TITLE
Context:	BLOCKQUOTE
StartText:	\\fB
EndText:	\\fR.PP
-
#
GI:		EPIGRAPH
StartText:	.PP.RS
EndText:	.RE
-
#
GI:		ATTRIBUTION
StartText:	\\fI
EndText:	\\fR.PP
-
#
GI:		ABSTRACT
Relation:	child TITLE
-
#
GI:		ABSTRACT
StartText:	.SS "Abstract"
-
#
GI:		TITLE
Context:	ABSTRACT
StartText:	.SS "
EndText:	"
-
#
GI:		REVHISTORY
StartText:	.SS "Revision History"
EndText:	
-
#
GI:		REVISION
StartText:	.PP\\fBRevision:\\fR\s
EndText:	
-
#
GI:		REVNUMBER
StartText:	#\s
EndText:	;\s
-
#
GI:		DATE
EndText:	;\s
-
#
GI:		AUTHORINITIALS
Context:	REVISION
StartText:	\s
-
#
GI:		REVREMARK
StartText:	;\s\s
EndText:	
-
#
GI:		PROGRAMLISTINGCO
#	nothing to do specifically in ProgramListingCO -- it falls to
#	the content of ProgramListing and any callout list
-
#
GI:		SCREEN
Relation:	ancestor LISTITEM
StartText:	.nf.sp
EndText:	.fi.sp
-
#
GI:		SCREEN
StartText:	.PP.nf
EndText:	.fi
-
#
GI:		SCREENCO
#	nothing to do specifically in ScreenCO -- it falls to
#	the content of Screen and any callout list
-
#
GI:		SCREENSHOT
#	nothing specific to do here -- defer to any ScreenInfo or the
#	included graphic
-
#
GI:		SCREENINFO
StartText:	.PP\\fI
EndText:	\\fR.PP
-
#
GI:		GRAPHICCO
#	nothing to do specifically in GraphicCO -- it falls to
#	the content of Graphic and any callout list
-
#
GI:		INFORMALEXAMPLE
StartText:	.sp
EndText:	.sp
-
#
GI:		EXAMPLE
#	nothing special to do here -- it falls to the content.
-
#
GI:		TITLE
Context:	EXAMPLE
StartText:	.PP\\fBExample ${examplenum}: 
EndText:	\\fR
Increment:	examplenum 1
-
#
GI:		FIGURE
#	nothing special to do here -- it falls to the content.
-
#
GI:		TITLE
Context:	FIGURE
StartText:	.PP\\fB
EndText:	\\fR
-
#
GI:		SIDEBAR
Relation:	child TITLE
StartText:	.PP.RS
EndText:	.RE
-
#
GI:		SIDEBAR
StartText:	.PP.RS\\fB[ Sidebar ]\\fR
EndText:	.RE
-
#
GI:		TITLE
Context:	SIDEBAR
StartText:	\\fB[ Sidebar:\s
EndText:	\s]\\fR
-
#
GI:		HIGHLIGHTS
StartText:	.SS "Highlights"
-
#
GI:		AUTHORBLURB
#	nothing to do specially -- an included title may occur
-
#
GI:		TITLE
Context:	AUTHORBLURB
StartText:	.PP\\fB
EndText:	\\fR
-
#
#
#############################################################################
#
#  Call-out material
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		CO
#	nothing to do for the anchor of a callout
-
#
GI:		AREASPEC
Ignore:		all
#	not much to do with representing the anchor of callouts in n/troff
-
#
GI:		AREA
Ignore:		all
#	part of AreaSpec, which is being ignored
-
#
GI:		AREASET
Ignore:		all
#	part of AreaSpec, which is being ignored
-
#
#
#############################################################################
#
#  Address block
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		ADDRESS
StartText:	.PP.nf
EndText:	.fi
-
#
GI:		STREET
#	just the content...
-
#
GI:		POB
#	just the content...
-
#
GI:		POSTCODE
#	just the content...
-
#
GI:		CITY
EndText:	,\s
-
#
GI:		STATE
#	just the content
-
#
GI:		COUNTRY
#	just the content
-
#
GI:		PHONE
StartText:	voice:\s
-
#
GI:		FAX
StartText:	fax:\s
-
#
GI:		OTHERADDR
#	just the content..
-
#
GI:		EMAIL
Context:	ADDRESS
#	just the content..
-
#
#
#############################################################################
#
#  Lists
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		GLOSSLIST
Relation:	ancestor ITEMIZEDLIST
StartText:	.RS
EndText:	.RE
-
#
GI:		GLOSSLIST
Relation:	ancestor GLOSSLIST
StartText:	.RS
EndText:	.RE
-
#
GI:		GLOSSLIST
Relation:	ancestor ORDEREDLIST
StartText:	.RS
EndText:	.RE
-
#
GI:		GLOSSLIST
Relation:	ancestor SIMPLELIST
StartText:	.RS
EndText:	.RE
-
#
GI:		GLOSSLIST
Relation:	ancestor VARIABLELIST
StartText:	.RS
EndText:	.RE
-
#
GI:		GLOSSLIST
Relation:	ancestor SEGMENTEDLIST
StartText:	.RS
EndText:	.RE
-
#
GI:		GLOSSLIST
#	Nothing to do here..  see glossentry, etc
-
#
GI:		GLOSSENTRY
#	nothing to do..
-
#
GI:		GLOSSTERM
Context:	GLOSSENTRY
StartText:	.IP "
EndText:	" 10
-
#
GI:		GLOSSTERM
StartText:	\\fB
EndText:	\\fR
-
#
GI:		ACRONYM
Context:	GLOSSENTRY
StartText:	(\\fIacronym:\s\\fR
EndText:	)\s\s
-
#
GI:		ABBREV
Context:	GLOSSENTRY
StartText:	(\\fIabbreviation:\s\\fR
EndText:	)\s\s
-
#
GI:		GLOSSSEE
StartText:	\\fISee \\fR
-
#
GI:		GLOSSDEF
#	nothing special to do -- just pass the content.
-
#
GI:		GLOSSSEEALSO
StartText:	\\fISee Also \\fR
-
#
GI:		ITEMIZEDLIST
Relation:	ancestor LISTITEM
StartText:	.sp.in +2
EndText:	.in -2
-
#
GI:		ITEMIZEDLIST
StartText:	.sp.in +2
EndText:	.in -2
-
#
GI:		LISTITEM
Context:	ITEMIZEDLIST
PAttSet:	MARK NONE
StartText:	.mk.in +3.rt
EndText:	.in -3
-
#
GI:		LISTITEM
Context:	ITEMIZEDLIST
StartText:	\\(bu.mk.in +3.rt
EndText:	.in -3
-
#
GI:		ORDEREDLIST
Relation:	ancestor ITEMIZEDLIST
StartText:	.RS ${_set orderlist 1}
EndText:	.RE
-
#
GI:		ORDEREDLIST
Relation:	ancestor GLOSSLIST
StartText:	.RS
EndText:	.RE
-
#
GI:		ORDEREDLIST
Relation:	ancestor ORDEREDLIST
StartText:	.in +4${_set nestorderlist ${orderlist}} ${_set orderlist a}
EndText:	.in -4.sp${_set orderlist ${nestorderlist}}
-
#
GI:		ORDEREDLIST
Relation:	ancestor SIMPLELIST
StartText:	.RS
EndText:	.RE
-
#
GI:		ORDEREDLIST
Relation:	ancestor VARIABLELIST
StartText:	.in +4${_set orderlist 1}
EndText:	.sp.in -4
-
#
GI:		ORDEREDLIST
Relation:	ancestor SEGMENTEDLIST
StartText:	.RS${_set orderlist 1}
EndText:	.RE
-
#
GI:		ORDEREDLIST
StartText:	${_set orderlist 1}
-
#
GI:		LISTITEM
Context:	ORDEREDLIST
Increment:	orderlist 1
StartText:	.br.sp${orderlist}..mk.in +4.rt
EndText:	.in -4
-
#
GI:		SIMPLELIST
Relation:	ancestor ITEMIZEDLIST
StartText:	.RS
EndText:	.RE
-
#
GI:		SIMPLELIST
Relation:	ancestor GLOSSLIST
StartText:	.RS
EndText:	.RE
-
#
GI:		SIMPLELIST
Relation:	ancestor ORDEREDLIST
StartText:	.RS
EndText:	.RE
-
#
GI:		SIMPLELIST
Relation:	ancestor SIMPLELIST
StartText:	.RS
EndText:	.RE
-
#
GI:		SIMPLELIST
Relation:	ancestor VARIABLELIST
StartText:	.RS
EndText:	.RE
-
#
GI:		SIMPLELIST
Relation:	ancestor SEGMENTEDLIST
StartText:	.RS
EndText:	.RE
-
#
GI:		SIMPLELIST
#	nothing to do here..
-
#
GI:		MEMBER
PAttSet:	TYPE INLINE
NthChild:	1
-
#
GI:		MEMBER
PAttSet:	TYPE INLINE
StartText:	,\s
-
#
GI:		MEMBER
PAttSet:	TYPE HORIZ
NthChild:	1
StartText:	.PP\t
-
#
GI:		MEMBER
PAttSet:	TYPE HORIZ
StartText:	\t
-
#
GI:		MEMBER
PAttSet:	TYPE VERT
StartText:	.IP "" 10
EndText:	
-
#
#GI:		VARIABLELIST
#Relation:	ancestor ITEMIZEDLIST
#StartText:	.RS 4
#EndText:	.sp.RE
#-
#
GI:		VARIABLELIST
Relation:	ancestor GLOSSLIST
StartText:	.RS 4
EndText:	.sp.RE
-
#
GI:		VARIABLELIST
Relation:	ancestor ORDEREDLIST
StartText:	.RS 4
EndText:	.sp.RE
-
#
GI:		VARIABLELIST
Relation:	ancestor SIMPLELIST
StartText:	.RS 4
EndText:	.sp.RE
-
#
GI:		VARIABLELIST
Relation:	ancestor VARIABLELIST
StartText:	${_set twotermlen ${onetermlen}}${_set onetermlen ${etermlength}}
EndText:	${_set etermlength ${onetermlen}}${_set onetermlen ${twotermlen}}
-
#
GI:		VARIABLELIST
Relation:	ancestor SEGMENTEDLIST
StartText:	.RS 4
EndText:	.RE
-
#
GI:		VARIABLELIST
Context:	PARA
EndText:	.sp
-
#
GI:		VARIABLELIST
#Catch all
-
# Determine how much to indent VarlistEntry's ListItem
#
GI:		VARLISTENTRY
PAttSet:	TERMLENGTH XTRANARROW
StartText: ${_set stermlength \.in\s+9n.rt}${_set etermlength \.in\s-9n}
-
GI:		VARLISTENTRY
PAttSet:	TERMLENGTH NARROW
StartText:	${_set stermlength \.in\s+16n.rt}${_set etermlength \.in\s-16n}
-
#
GI:		VARLISTENTRY
PAttSet:	TERMLENGTH MEDIUM
StartText:	${_set stermlength \.in\s+24n.rt}${_set etermlength \.in\s-24n}
-
#
GI:		VARLISTENTRY
PAttSet:	TERMLENGTH WIDE
StartText:	${_set stermlength \.in\s+32n.rt}${_set etermlength \.in\s-32n}
-
#
GI:		VARLISTENTRY
PAttSet:	TERMLENGTH XTRAWIDE
StartText:	${_set stermlength \.in\s+40n.rt}${_set etermlength \.in\s-40n}
-
#
GI:		VARLISTENTRY
PAttSet:	TERMLENGTH WHOLELINE
StartText:	${_set stermlength \.sp\s.6\.in\s+4}${_set etermlength \.in\s-4}
-
#
GI:		VARLISTENTRY
StartText:	${_set stermlength \.sp\s.6\.in\s+4}${_set etermlength \.in\s-4}
-
#
GI:		TERM
NthChild:	1
StartText:	.sp.ne 2.mk\\fB
Increment:	termcount 1
EndText:	\\fR
-
#
GI:		TERM
StartText:	.br\\fB
Increment:	termcount 1
EndText:	\\fR
-
#
GI:		LISTITEM
Relation:	parent VARLISTENTRY
StartText:	${stermlength}
EndText:	.sp ${termcount}${etermlength}${_set termcount 0}
-
#
GI:		SEGMENTEDLIST
Relation:	ancestor ITEMIZEDLIST
StartText:	.RS${_followrel child TITLE 400}.TStab();l l l l l l l l l l l l l l l l l l.
EndText:	.TE.RE
-
#
GI:		SEGMENTEDLIST
Relation:	ancestor GLOSSLIST
StartText:	.RS${_followrel child TITLE 400}.TStab();l l l l l l l l l l l l l l l l l l.
EndText:	.TE.RE
-
#
GI:		SEGMENTEDLIST
Relation:	ancestor ORDETERLIST
StartText:	.RS${_followrel child TITLE 400}.TStab();l l l l l l l l l l l l l l l l l l.
EndText:	.TE.RE
-
#
GI:		SEGMENTEDLIST
Relation:	ancestor SIMPLELIST
StartText:	.RS${_followrel child TITLE 400}.TStab();l l l l l l l l l l l l l l l l l l.
EndText:	.TE.RE
-
#
GI:		SEGMENTEDLIST
Relation:	ancestor VARIABLELIST
StartText:	.RS${_followrel child TITLE 400}.TStab();l l l l l l l l l l l l l l l l l l.
EndText:	.TE.RE
-
#
GI:		SEGMENTEDLIST
Relation:	ancestor SEGMENTEDLIST
StartText:	.RS${_followrel child TITLE 400}.TStab();l l l l l l l l l l l l l l l l l l.
EndText:	.TE.RE
-
#
GI:		SEGMENTEDLIST
Relation:	child TITLE
StartText:	${_followrel child TITLE 400}.TStab();l l l l l l l l l l l l l l l l l l.
EndText:	.TE
-
#
GI:		TITLE
Context:	SEGMENTEDLIST
#	ignored by default -- must be called by SEGMENTEDLIST gi
Ignore:		all
-
#
GI:		_segmentedlist_title
SpecID:		400
StartText:	.sp 1\\fB
EndText:	\\fR
-
#
GI:		SEGTITLE
StartText:	\\fB
EndText:	\\fR
-
#
GI:		SEGLISTITEM
StartText:	
EndText:	
-
#
GI:		SEG
EndText:	
-
#
GI:		PROCEDURE
AttValue:	ROLE SINGLE-STEP
StartText:	${_set singlestep xxx}${_set manysteps xy}
-
#
GI:		PROCEDURE
#	defer to the content...
StartText:	${_set procstep 1}${_set procsubstep a}${_set manysteps xxx}
-
#
GI:		TITLE
Context:	PROCEDURE
StartText:	.PP\\fB
EndText:	\\fR
-
#
GI:	 _onestep
SpecID:	9000
StartText:	.PP.RS
EndText:	.RE${_set singlestep xy}
-
#
GI:	_manysteps
SpecID:	9001
StartText:	.RS.TP 4\\fB${procstep}.\\fR
EndText:	.RE
Increment:	procstep 1
-
#
GI:		STEP
Context:	SUBSTEPS
StartText:	.TP 4\\fB${procsubstep}\\fR.
EndText:	
Increment:	procsubstep 1
-
#
GI:		STEP
StartText:	${_isset singlestep xxx 9000}${_isset manysteps xxx 9001}
Ignore:		all
EndText:	
-
#
GI:		TITLE
Context:	STEP
# Ignore - Optional titles deprecated
Ignore:		all
-
#
GI:		SUBSTEPS
StartText:	.RS
EndText:	.RE
-
#
GI:		CALLOUTLIST
StartText:	${_set callout 1}
#	nothing to do specifically, defer to the content...
-
#
GI:		TITLE
Context:	CALLOUTLIST
StartText:	\\fB
EndText:	\\fR.PP
-
#
GI:		CALLOUT
StartText:	.PP\\fICallout ${callout}.\s\s\\fR
EndText:	
Increment:	callout
-
#
#
#############################################################################
#
#  Messages
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		MSGSET
StartText:	.PP
-
#
GI:		MSGENTRY
EndText:	.sp
-
#
GI:		MSG
Relation:	child TITLE
StartText:	.PP
EndText:	
-
#
GI:		MSG
EndText:	
-
#
GI:		TITLE
Context:	MSG
StartText:	.PP\\fB
EndText:	\\fR.PP
-
#
GI:		MSGINFO
#	nothing specific -- just groups (MsgLevel | MsgOrig | MsgAud)*
-
#
GI:		MSGEXPLAN
AttValue:     ROLE DESCRIPTION
StartText:	.RS 3.sp\\fBDescription\\fR:.RS 3
EndText:	.RE.RE
-
#
GI:		MSGEXPLAN
AttValue:     ROLE CAUSE
StartText:	.RS 3.sp\\fBCause\\fR:.RS 3
EndText:	.RE.RE
-
#
GI:		MSGEXPLAN
AttValue:     ROLE EXAMPLE
StartText:	.RS 3.sp\\fBExample\\fR:.RS 3
EndText:	.RE.RE
-
#
GI:		MSGEXPLAN
AttValue:     ROLE SOLUTION
StartText:	.RS 3.sp\\fBSolution\\fR:.RS 3
EndText:	.RE.RE
-
#
GI:		MSGEXPLAN
#			No gentext
StartText:	.RS 2.sp
EndText:	.RE
-
GI:		TITLE
Context:	MSGEXPLAN
StartText:	.PP\\fB
EndText:	\\fR
-
#
GI:		MSGMAIN
#	defer to content
-
#
GI:		TITLE
Context:	MSGMAIN
StartText:	\\fB
EndText:	\\fR
-
#
GI:		MSGSUB
#	defer to content
-
#
GI:		TITLE
Context:	MSGSUB
StartText:	.PP\\fB
EndText:	\\fR
-
#
GI:		MSGREL
#	defer to content
-
#
GI:		TITLE
Context:	MSGREL
StartText:	.PP\\fB
EndText:	\\fR
-
#
GI:		MSGLEVEL
StartText:	.PP\\fIMessage level:\s\s\\fR
EndText:	
-
#
GI:		MSGORIG
StartText:	.PP\\fIMessage origin:\s\s\\fR
EndText:	
-
#
GI:		MSGAUD
StartText:	.PP\\fIMessage audience:\s\s\\fR
EndText:	
-
#
GI:		MSGTEXT
StartText:	\\f(CW
EndText:	\\fR
-
#
#
#############################################################################
#
#  Admonitions
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		CAUTION
Relation:	child TITLE
StartText:	.PP.RS
EndText:	.RE
-
#
GI:		CAUTION
StartText:	.sp.mk\\fBCaution\\fR\s\\-\s.in +10.rt
EndText:	.in -10
-
#
GI:		TITLE
Context:	CAUTION
StartText:	.sp.mk\\fBCaution\\fR\s\\-\s.in +10.rt
EndText:	.in -10
-
#
GI:		IMPORTANT
Relation:	child TITLE
StartText:	.PP.RS
EndText:	.RE
-
#
GI:		IMPORTANT
StartText:	.PP.RS\\fBImportant:\s\s
EndText:	.RE
-
#
GI:		TITLE
Context:	IMPORTANT
StartText:	\\fBImportant:\s\s
EndText:	\\fR.PP
-
#
GI:		NOTE
Relation:	child TITLE
StartText:	.PP.RS
EndText:	.RE
-
#
GI:		NOTE
StartText:	.sp.mk\\fBNote\\fR\s\\-\s.in +8.rt
EndText:	.in -8
-
#
GI:		TITLE
Context:	NOTE
StartText:	.sp.mk\\fBNote\\fR\s\\-\s.in +8.rt
EndText:	.in -8
-
#
GI:		TIP
Relation:	child TITLE
StartText:	.PP.RS
EndText:	.RE
-
#
GI:		TIP
StartText:	.PP.RS\\fBTip:\s\s
EndText:	.RE
-
#
GI:		TITLE
Context:	TIP
StartText:	\\fBTip:\s\s
EndText:	\\fR.PP
-
#
GI:		WARNING
Relation:	child TITLE
StartText:	.PP.RS
EndText:	.RE
-
#
GI:		WARNING
StartText:	.PP.RS\\fBWarning:\s\s
EndText:	.RE
-
#
GI:		TITLE
Context:	WARNING
StartText:	\\fBWarning:\s\s
EndText:	\\fR.PP
-
#
#
#############################################################################
#
#  Synopses
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		SYNOPSIS
StartText:	.PP.nf
EndText:	.fi
-
#
GI:		CMDSYNOPSIS
StartText:	.PP
EndText:	
-
#
GI:		ARG
Context:	GROUP
NthChild:	1
AttValue:	CHOICE OPT
StartText:	\s[
EndText:	${_attval REP REPEAT 505}]
-
#
GI:		ARG
Context:	GROUP
NthChild:	1
EndText:	${_attval REP REPEAT 505}
-
#
GI:		ARG
Context:	GROUP
AttValue:	CHOICE OPT
StartText:	\s|\s[
EndText:	${_attval REP REPEAT 505}]
-
#
GI:		ARG
Context:	GROUP
StartText:	\s|\s
EndText:	${_attval REP REPEAT 505}
-
#
GI:		ARG
AttValue:	CHOICE OPT
StartText:	\s[
EndText:	${_attval REP REPEAT 505}]
-
#
GI:     ARG
AttValue:   CHOICE REQ
StartText:  \s{
EndText:    ${_attval REP REPEAT 505}}
-
#
GI:		ARG
AttValue:	CHOICE PLAIN
StartText:	\s
EndText:	${_attval REP REPEAT 505}
-
#
GI:		ARG
#	no special attrs -- just pass content through
EndText:	${_attval REP REPEAT 505}
-
#
GI:		_arg_group
SpecID:		505
StartText:	\\&...
Ignore:		all
-
#
GI:		GROUP
AttValue:	CHOICE OPT
StartText:	\s[
EndText:	]\s${_attval REP REPEAT 505}
-
#
GI:		GROUP
AttValue:	CHOICE REQ
StartText:	\s{
EndText:	}\s${_attval REP REPEAT 505}
-
#
GI:		GROUP
AttValue:	CHOICE PLAIN
StartText:	\s
EndText:	${_attval REP REPEAT 505}
-
#
GI:		SBR
StartText:	.br
-
#
GI:		SYNOPFRAGMENT
#	nothing special to do here -- just pass through content (Arg | Group)+
-
#
GI:		SYNOPFRAGMENTREF
#	WHAT TO DO HERE??   pass through the content, but what about the
#	linkend?  (will call it across...)
EndText:	\s\\fI(refers to: ${_followlink LINKEND 1000})\\fR
-
#
GI:		FUNCSYNOPSIS
StartText:	.PP
EndText:	
-
#
GI:		FUNCSYNOPSISINFO
StartText:	.nf
EndText:	.fi.LP
-
#
GI:		FUNCPROTOTYPE
#	nothing special -- just pass through content (looks like
#	a function def
StartText:	.sp 1
-
#
GI:		FUNCDEF
StartText:	\\fB
EndText:	\\fR(
-
#
GI:		FUNCPARAMS
StartText:	(\\fB
EndText:	\\fR)
-
#
GI:		VOID
StartText:	\\fBvoid\\fR);
-
#
GI:		VARARGS
StartText:	\\fB\\&...\\fR);
-
#
GI:		PARAMDEF
Relation:	sibling+ PARAMDEF
StartText:	\\fB
EndText:	\\fR,\s
-
#
GI:		PARAMDEF
StartText:	\\fB
EndText:	\\fR);
-
#
#
#############################################################################
#
#  Links
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		LINK
# Defer to content
-
#
GI:		OLINK
# Defer to content
-
#
GI:		ULINK
StartText:	\\fI
EndText:	\\fR
-
#
GI:		FOOTNOTEREF
#	just let the footnote ref mark come through
-
#
GI:		FOOTNOTE
#	just let footnote body come through (-man doesn't support footnotes)
-
#
GI:		XREF
AttValue:	LINKEND
StartText:	\\fI${_followlink LINKEND 600}
EndText:	\\fR
-
#
GI:		XREF
StartText:	\\fI
EndText:	\\fR
-
#
GI:		_xref
SpecID:		600
StartText:	${_followrel child TITLE 2000}
Ignore:		all
-
#
GI:		ANCHOR
#	nothing to do -- this just marks a place..
-
#
#
#############################################################################
#
#  Graphics and Equations
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:     GRAPHIC
AttValue:   REMAP pic
StartText:	.LP.RSPlease see the online man page on docs.sun.com or a print copy for the diagram..RE.LP
-
#
GI:		GRAPHIC
AttValue:	ENTITYREF
StartText:	.PP.if t .P! "${_filename}"
-
#
GI:		GRAPHIC
# Do nothing
-
#
GI:		INLINEGRAPHIC
StartText:	.if t .P! "${_filename}"
-
#
GI:		INFORMALEQUATION
#	nothing special to do -- defer to graphic content..
-
#
GI:		EQUATION
#Set up for running EQN pre-processor
StartText:  .EQdelim $$.EN.sp 2
-
#
GI:		ALT
# Pass through $$ deliminited EQN code
Context:	EQUATION
StartText:	
EndText:	
-
#
GI:		TITLE
Context:	EQUATION
StartText:	.PP\\fB
EndText:	\\fR
-
#
GI:		INLINEEQUATION
#	nothing special to do -- defer to graphic content..
-
#
#
#############################################################################
#
#  Tables
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
#
GI:		INFORMALTABLE
StartText:	.sp${_calstable tbl tablestart}
EndText:	${_calstable tbl tableend}.sp
-
#
GI:		TABLE
StartText:	.PP\\fBTable ${tablenum} ${_followrel child TITLE 1000}\\fR.sp
		${_calstable tbl tablestart}
EndText:	${_calstable tbl tableend}
Increment:	tablenum 1
-
#
GI:		TITLE
Context:	TABLE
#	handled in TABLE element
Ignore:		all
-
#
GI:		TGROUP
StartText:	${_calstable tbl tablegroup}${_followrel child THEAD 700}${_followrel child TBODY 700}${_followrel child TFOOT 701}
EndText:	${_calstable tbl tablegroupend}
-
#
GI:		COLSPEC
Ignore:		all
-
#
GI:		SPANSPEC
Ignore:		all
-
#
GI:		THEAD TBODY TFOOT
#	they're called explicitly from TGROUP, but ignored here
Ignore:		all
-
#
GI:		_thead_tbody
SpecID:		700
#	nothing special to do -- just pass through content
-
#
GI:		_tfoot
SpecID:		701
StartText:	${_calstable tbl tablefoot}
-
#
GI:		ROW
StartText:	${_calstable tbl rowstart}
EndText:	${_calstable tbl rowend}
-
#
GI:		ENTRY
StartText:	${_calstable tbl entrystart}
EndText:	${_calstable tbl entryend}
-
#
GI:		ENTRYTBL
StartText:
EndText:
Message:	IMPLEMENT <${_gi} ${_allatts}>
-
#
#
#############################################################################
#
#  Index terms
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		INDEXTERM
#StartText:	.iX\s
#EndText:	
Ignore:		all
-
#
GI:		PRIMARY
StartText:	"
EndText:	"
-
#
GI:		SECONDARY
StartText:	\s"
EndText:	"
-
#
GI:		TERTIARY
StartText:	\s"
EndText:	"
-
#
GI:		SEE
StartText:	\s"See:\s
EndText:	"
-
#
GI:		SEEALSO
StartText:	\s"SeeAlso:\s
EndText:	"
-
#
#
#############################################################################
#
#  Author / OtherCredit material
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		OTHERCREDIT
#	nothing specific -- defer to content
-
#
GI:		HONORIFIC
#	nothing specific -- defer to content
EndText:	\s
-
#
GI:		FIRSTNAME
#	nothing specific -- defer to content
EndText:	\s
-
#
GI:		SURNAME
#	nothing specific -- defer to content
EndText:	\s
-
#
GI:		LINEAGE
#	nothing specific -- defer to content
EndText:	\s
-
#
GI:		OTHERNAME
#	nothing specific -- defer to content
StartText:	(
EndText:	)\s
-
#
GI:		AFFILIATION
#	nothing specific -- defer to content
EndText:	\s
-
#
GI:		SHORTAFFIL
#	nothing specific -- defer to content
EndText:	\s
-
#
GI:		JOBTITLE
#	nothing specific -- defer to content
EndText:	\s
-
#
GI:		ORGNAME
#	nothing specific -- defer to content
EndText:	\s
-
#
GI:		ORGDIV
#	nothing specific -- defer to content
EndText:	\s
-
#
GI:		CONTRIB
#	nothing specific -- defer to content
EndText:	\s
-
#
#
#############################################################################
#
#  "Leaf" material
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		ABBREV
#	no special presentation
-
#
GI:		ACCEL
#	no special presentation
-
#
GI:		ACRONYM
#	Small Bold
StartText:	\\fB
EndText:	\\fR
-
#
GI:		AUTHORINITIALS
#	no special presentation
-
#
GI:		CITATION
StartText:	\\fI
EndText:	\\fR
-
#
GI:		CITETITLE
AttValue:	PUBWORK
StartText:	\\fI
EndText:	\\fR
-
#
GI:		CITETITLE
StartText:	\\fI
EndText:	\\fR
-
#
GI:		CITEREFENTRY
#	defer to content..
-
#
GI:		REFENTRYTITLE
StartText:	\\fB
EndText:	\\fR
-
#
GI:		MANVOLNUM
StartText:	(
EndText:	)
-
#
GI:		COMMENT
#	docbook says to inhibit this from finished products...
Ignore:		all
-
#
GI:		EMAIL
#	no special presentation
-
#
GI:		EMPHASIS
StartText:	\\fI
EndText:	\\fR
-
#
GI:		ERRORCODE
StartText:	\\fB
EndText:	\\fR
-
#
GI:		ENVAR
StartText:	\\fB
EndText:	\\fR
-
#
GI:		FIRSTTERM
StartText:	\\fI
EndText:	\\fR
-
#
GI:		FOREIGNPHRASE
#	no special presentation
-
#
GI:		PHRASE
#	no special presentation
-
#
GI:		QUOTE
StartText:	``\\fI
EndText:	\\fR''
-
#
GI:		TRADEMARK
EndText:	\\u\\s-2TM\\s+2\\d
-
#
GI:		WORDASWORD
#	no special presentation
-
#
GI:		ACTION
#	no special presentation
-
#
GI:		APPLICATION
StartText:	\\fB
EndText:	\\fR
-
#
GI:		CLASSNAME
StartText:	\\fB
EndText:	\\fR
-
#
GI:		COMMAND
StartText:	\\fB
EndText:	\\fR
-
#
GI:		COMPUTEROUTPUT
StartText:	\\f(CW
EndText:	\\fR
-
#
GI:		DATABASE
#	no special presentation
-
#
GI:		ERRORNAME
StartText:	\\fB
EndText:	\\fR
-
#
GI:		ERRORTYPE
#	no special presentation
-
#
GI:		FILENAME
AttValue:	CLASS HEADERFILE
StartText:	\\fB<
EndText:	>\\fR
-
#
GI:		FILENAME
StartText:	\\fB
EndText:	\\fR
-
#
GI:		FUNCTION
Relation:	parent FUNCDEF
StartText:	\\fB
EndText:	\\fR
-
#
GI:     FUNCTION
Relation:   descendant PARAMETER
StartText:  \\fB
EndText:    )\\fR
-
#
GI:		FUNCTION
StartText:	\\fB
EndText:	(\\|)\\fR
-
#
GI:		GUIBUTTON
StartText:	\\fB
EndText:	\\fR
-
#
GI:		GUIICON
StartText:	\\fB
EndText:	\\fR
-
#
GI:		GUILABEL
#	no special presentation
-
#
GI:		GUIMENU
#	no special presentation
-
#
GI:		GUIMENUITEM
#	no special presentation
-
#
GI:		GUISUBMENU
#	no special presentation
-
#
GI:		HARDWARE
#	no special presentation
-
#
GI:		INTERFACE
#	no special presentation
-
#
GI:		INTERFACEDEFINITION
StartText:	\\fB
EndText:	\\fR
-
#
GI:		KEYCAP
StartText:	\\fB<
EndText:	>\\fR
-
#
GI:		KEYCODE
#	no special presentation
-
#
GI:		KEYCOMBO
#	no special presentation -- defer to the content
-
#
GI:		KEYSYM
StartText:	\\fB<
EndText:	>\\fR
-
#
GI:		LINEANNOTATION
StartText:	\\fI
EndText:	\\fR
-
#
GI:		LITERAL
StartText:	\\fB
EndText:	\\fR
-
#
GI:		MARKUP
StartText:	\\f(CW
EndText:	\\fR
-
#
GI:		MEDIALABEL
#	no special presentation
-
#
GI:		MENUCHOICE
#	no special presentation
-
#
GI:		SHORTCUT
#	no special presentation
-
#
GI:		MOUSEBUTTON
#	no special presentation
-
#
GI:		OPTION
AttValue:	ROLE PLUS
StartText:	+\\fB
EndText:	\\fR
-
#
GI:		OPTION
AttValue:	ROLE NODASH
StartText:	\\fB
EndText:	\\fR
-
GI:		OPTION
StartText:	-\\fB
EndText:	\\fR
-
#
GI:		OPTIONAL
StartText:	[
EndText:	]
-
#
GI:		PARAMETER
Relation:   parent PARAMDEF
StartText:	\\fI
EndText:	\\fP
-
#
GI:     PARAMETER
Relation:   parent FUNCTION
NthChild:   1
StartText:  (\\fI
EndText:    \\fP
-
#
GI:     PARAMETER
Relation:   parent FUNCTION
StartText:  ,\s\\fI
EndText:    \\fP
-
#
GI:		PARAMETER
StartText:	\\fI
EndText:	\\fR
-
#
GI:		PROPERTY
StartText:	\\fB
EndText:	\\fR
-
#
GI:		REPLACEABLE
StartText:	\\fI
EndText:	\\fR
-
#
GI:		RETURNVALUE
StartText:	\\fB
EndText:	\\fR
-
#
GI:		SGMLTAG
AttValue:	CLASS ELEMENT
StartText:	\\fB<
EndText:	>\\fR
-
#
GI:		SGMLTAG
StartText:	\\fB
EndText:	\\fR
-
#
GI:		STRUCTFIELD
StartText:	\\fB
EndText:	\\fR
-
#
GI:		STRUCTNAME
StartText:	\\fB
EndText:	\\fR
-
#
GI:		SYMBOL
AttValue:	ROLE Variable
StartText:	\\fI
EndText:	\\fR
-
#
GI:		SYMBOL
StartText:	\\fI
EndText:	\\fR
-
#
GI:		SYSTEMITEM
AttValue:	CLASS CONSTANT
StartText:	\\fB
EndText:	\\fR
-
#
GI:		SYSTEMITEM
AttValue:	CLASS ENVIRONVAR
StartText:	\\fB
EndText:	\\fR
-
#
GI:		SYSTEMITEM
AttValue:	CLASS RESOURCE
StartText:	\\fB
EndText:	\\fR
-
#
GI:		SYSTEMITEM
StartText:	\\fB
EndText:	\\fR
-
#
GI:		TOKEN
StartText:	\\fB
EndText:	\\fR
-
#
GI:		TYPE
StartText:	\\fB
EndText:	\\fR
-
#
GI:		USERINPUT
StartText:	\\fB
EndText:	\\fR
-
#
GI:		AUTHOR
#	no special presentation - defer to content
-
#
GI:		CORPAUTHOR
#	no special presentation
-
#
GI:		MODESPEC
#	nothing to render (this is meta information for Links)
-
#
GI:		PRODUCTNAME
StartText:	\\fB
EndText:	\\fR
-
#
GI:		PRODUCTNUMBER
#	no special presentation
-
#
GI:		SUBSCRIPT
StartText:	\\d
EndText:	\\u
-
#
GI:		SUPERSCRIPT
AttValue:	REMAP nopower
StartText:	\\u
EndText:	\\d
-
#
GI:		SUPERSCRIPT
StartText:	.ie t \\u\\c.el \\h'-1'**\\c
EndText:	.ie t \\d\\c.el \\h'-1'\\c
-
#
#
#############################################################################
#
#  stuff that gets ignored (and doesn't belong elsewhere)
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		TITLEABBREV
#	this element is ignored in favor of the real title
Ignore:		all
-
#
#
#
#############################################################################
#
#  handle layout-specific stuff and PIs
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		BEGINPAGE
StartText:	.br\s
EndText:	
-
#
GI:		_x-break
StartText:	.br\s
EndText:	
-
#
GI:		_sml-break
StartText:	.br\s
EndText:	
-
#
GI:		_sml-need
StartText:	.ne\s
EndText:	
-
#
GI:		_sml-size
StartText:	.ps\s
EndText:	
-
#
GI:		_sml-indent
StartText:	.in\s
EndText:	
-
#
GI:		_sml-space
StartText:	.sp\s
EndText:	
-
#
GI:		_sml-tabset
StartText:	.ta\s
EndText:	
-
#
#
#############################################################################
#
#  General purpose transpecs
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		_passthrough
SpecID:		1000
Substitute:	" ""
-
#
GI:		_passthrough2
SpecID:		2000
-
#
GI:		_doTitle
SpecID:		1010
StartText:	.PP\\fB
EndText:	\\fR.PP
-
#
#
#############################################################################
#
#  Catch-all for unknown PIs -- ignore them...
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:		_*
Ignore:		data
-
#
#
#############################################################################
#
#  Catch-all for unknown elements -- just output their content..
#
#   ####     #####     #####     #####     #####     #####     ####     #####     
#
GI:	*
-
#
