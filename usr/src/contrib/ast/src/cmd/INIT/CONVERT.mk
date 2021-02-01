/*
 * {automake|configure} => {nmake|iffe} conversion support
 *
 * The first command line target overrides the default original source
 * directory name $(MAKEFILE:D). The hard work is in the makefile using
 * these assertions, since it must (manually) provide the nmake makefiles
 * and config equivalent iffe scripts. The conversion makefile is typically
 * named lib/package/PACKAGE.cvt in an ast package $PACKAGEROOT directory,
 * and the conversion is run from the $PACKAGEROOT directory, e.g.:
 *
 *	nmake -I lib/package -f PACKAGE-VERSION/PACKAGE.cvt
 *
 * The conversion requires the ast nmake, pax and tw commands.
 *
 * After the conversion you will be liberated from ./configure, *.in,
 * *.am, automake, autom4te, libtool, make depend, and makefile
 * recursion ordering. You can build from $PACKAGEROOT using the ast
 * package(1) (which sets up the { HOSTTYPE PATH VPATH } environment):
 *
 *	package make
 *
 * or cd into any arch/$HOSTTYPE/src subdirectory and rebuild that portion
 * of the hierarchy with the ast nmake(1) (after setting PATH and VPATH):
 *
 *	nmake
 *
 * The conversion assertions are:
 *
 *	package :CONVERT: file ...
 *
 *	    files in the original source directory are copied
 *	    and converted into the ./src and ./lib subdirectories 
 *	    the default original source directory is ./original
 *
 *		package	package name
 *		file	original source file that must exist
 *
 *	:OMIT: pattern
 *
 *	    files matching pattern are not copied into the converted
 *	    directory
 *
 *		pattern	ksh pattern of files to omit
 *
 *	:COPY: from to [ file ... ]
 *
 *	    files in the from directory are copied to the to directory
 *	    the action may contain :MOVE: exceptions to the copy
 *
 *		from	original directory subdirectory
 *			  . names the original directory
 *			 .. names the 
 *		to	converted subdirectory
 *			  libNAME => src/lib/libNAME
 *			     NAME => src/cmd/NAME
 *		file	files or files in subdirectories to be copied;
 *			explicit files are copied to the to directory;
 *			if no files are specified then the from hierarchy
 *			is recursively copied to the converted directory
 *
 *	:MOVE: to file ...
 *
 *	    :COPY: assertion exceptions placed in the assertion's action
 *
 *		to	files or subdirectory files are copied to this directory
 *		file	file or files in subdirectories to be copied
 *
 *	:FILE: to file <<!
 *	contents
 *	!
 *
 *	    the :FILE: action is copied to the named file in the to directory
 *	    the :FILE: action is usually specified using the here syntax to
 *	    avoid make comment, quote and variable expansion
 *
 *	:EDIT: to file ... | - pattern <<!
 *	edit script
 *	!
 *
 *	    the :EDIT: action is an ed(1) script applied to each file in the
 *	    to directory after it has been copied from the original source
 *	    directory; if to is - then the :EDIT: action is a sed(1) script
 *	    that is applied to all files matching the file pattern during the
 *	    copy from the original source directory; a file may be subject to
 *	    both a sed(1) and ed(1) :EDIT:; the :EDIT: action is usually
 *	    specified using the here syntax to avoid make comment, quote and
 *	    variable expansion
 */

.CONVERT.ID. = "@(#)$Id: CONVERT (AT&T Research) 2004-03-19 $"

set nojobs noscan nowriteobject writestate=$$(MAKEFILE).ms

package = $(PWD:B)
here = !-=-=-=-=-!
hierarchy = src src/cmd src/lib
omit = .*|*.?(l)[ao]
original = $(MAKEFILE:D)
showedit = $(-debug:?p??)

CPFLAGS = -u
PAXFLAGS = -u -v
STDEDFLAGS = -
TW = tw
TWFLAGS = -CP

all  : .VIRTUAL file
file : .VIRTUAL edit
edit : .VIRTUAL copy
copy : .VIRTUAL init
init : .VIRTUAL

.MAKEINIT : .cvt.init

.cvt.init : .MAKE .VIRTUAL .FORCE
	local D
	if D = "$(~.ARGS:O=1)"
		if "$(D:T>FD)"
			original := $(D)
			.ARGS : .CLEAR $(~.ARGS:O>1)
		end
	end

.cvt.filter =
.cvt.package =

.cvt.atom : .FUNCTION
	local N V
	V := $(%:O=1)
	let .cvt.$(V) = .cvt.$(V) + 1
	return .cvt.$(V).$(.cvt.$(V))

.cvt.omit : .FUNCTION
	return -s',^\(\(?K)?(*/)($(omit))?(/*))$,,$(showedit)'

.cvt.to : .FUNCTION
	if "$(%)" == "."
		return src
	end
	if "$(%)" == "*/*"
		return src/$(%)
	end
	if "$(%)" == "lib*"
		return src/lib/$(%)
	end
	return src/cmd/$(%)

":CONVERT:" : .MAKE .OPERATOR
	local I
	package := $(<)
	I := $(hierarchy:C,$,/Makefile)
	init : .cvt.verify $(I)
	$(I) : .ACCEPT
		test -d $(<:D) || $(MKDIR) -p $(<:D)
		echo :MAKE: > $(<)
	.cvt.verify : .MAKE .FORCE .REPEAT
		local I
		if I = "$(.cvt.package:T!=F)"
			error 3 $(original): not a $(package) source directory: missing $(I)
		end
	.cvt.package := $(>:C,^,$$(original)/,)

":COPY:" : .MAKE .OPERATOR
	local F T I A
	F := $(>:O=1)
	T := $(.cvt.to $(>:O=2))
	A := $(.cvt.atom copy)
	copy : $(A)
	$(A) : .VIRTUAL
	if F == "."
		$(A) : $(T)
		$(T) :
			test -d $(<) || $(MKDIR) -p $(<)
		for I $(>:O>2)
			eval
			$$(A) : $(I:D=$(T):B:S)
			$(I:D=$(T):B:S) : $$(original)/$(I)
				$$(CP) $$(CPFLAGS) $$(*) $$(<)
			end
		end
	elif "$(F:T=FF)" || "$(F:N=*.(pax|t[bg]z))"
		eval
		$$(A) : $$(F)
			test -d $(T) || $$(MKDIR) -p $(T)
			cd $(T)
			$$(PAX) $$(PAXFLAGS) -rf $$(*:P=A) -s ',^$(>:O=2)/*,,' $(.cvt.omit) $(.cvt.filter)
		end
	else
		F := $$(original)/$(F)
		if ! "$(@:V)"
			eval
			$$(A) : .FORCE
				test -d $(T) || $$(MKDIR) -p $(T)
				cd $(F:V)
				$$(TW) $$(TWFLAGS) | $$(PAX) $$(PAXFLAGS) -rw $(.cvt.omit) $(.cvt.filter) $(T:P=A)
			end
		else
			.cvt.move =
			: $(@:V:@R)
			eval
			$$(A) : .FORCE
				test -d $(T) || $$(MKDIR) -p $(T)
				cd $(F:V)
				$$(TW) $$(TWFLAGS) | $$(PAX) $$(PAXFLAGS) -rw $(.cvt.omit) $(.cvt.move) $(.cvt.filter) $(T:P=A)
			end
		end
	end

":EDIT:" : .MAKE .OPERATOR
	local A D F
	D := $(>:O=1)
	if D == "-"
		A := ^$(>:O=2)^$$(SED) -e $(@:Q:/'\n'/ -e /G)
		.cvt.filter += --action=$(A:@Q)
	else
		D := $(.cvt.to $(D))
		F := $(>:O>1:C,^,$(D)/,)
		edit : $(F)
		eval
		$$(F) :
			$$(STDED) $$(STDEDFLAGS) $$(<) <<'$(here)'
			$(@:V)
			w
			q
			$(here)
		end
	end

":FILE:" : .MAKE .OPERATOR
	local ( D F ) $(>)
	local A
	A := $(.cvt.atom file)
	$(A) := $(@:V)
	D := $(.cvt.to $(D))
	file : $(D)/$(F)
	eval
	$$(D)/$$(F) :
		test -d $$(<:D) || $$(MKDIR) -p $$(<:D)
		cat > $$(<) <<'$(here)'
		$$($(A):V)
		$(here)
	end

":MOVE:" : .MAKE .OPERATOR
	local T I
	T := ../../../$(.cvt.to $(>:O=1))
	for I $(>:O>1)
		if I == "*/"
			.cvt.move += -s',^\(\(?K)$(I)),$(T)/,$(showedit)'
			.cvt.move += -s',^\(\(?K)$(I:C%/$%%))$,,$(showedit)'
		else
			.cvt.move += -s',^\(\(?K)$(I))$,$(T)/$(I:B:S),$(showedit)'
		end
	end

":OMIT:" : .MAKE .OPERATOR
	local P
	for P $(>)
		omit := $(omit)|$(P)
	end
