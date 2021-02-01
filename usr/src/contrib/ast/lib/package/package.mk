/*
 * source and binary package support
 *
 * @(#)package.mk (AT&T Research) 2012-02-14
 *
 * usage:
 *
 *	cd $INSTALLROOT/lib/package
 *	nmake -f name [closure] [cyg|exp|lcl|pkg|rpm|tgz] [base|delta] type
 *
 * where:
 *
 *	name	package description file or component
 *
 *	type	source	build source archive, generates
 *			$(PACKAGEDIR)/name.version.release.suffix
 *		binary	build binary archive, generates
 *			$(PACKAGEDIR)/name.version.hosttype.release.suffix
 *		runtime	build binary archive, generates
 *			$(PACKAGEDIR)/name-run.version.hosttype.release.suffix
 *
 * NOTE: $(PACKAGEDIR) is in the lowest view and is shared among all views
 *
 * generated archive member files are $(PACKAGEROOT) relative
 *
 * main assertions:
 *
 *	NAME [ name=value ] :PACKAGE: component ...
 *	:OMIT: component ...
 *	:LICENSE: license-class-pattern
 *	:CATEGORY: category-id ...
 *	:COVERS: package ...
 *	:REQURES: package ...
 *	:INDEX: index description line
 *	:DESCRIPTION:
 *		[ verbose description ]
 *	:DETAILS: style
 *		:README:
 *			readme lines
 *		:EXPORT:
 *			name=value
 *		target :INSTALL: [ source ]
 *
 * option variables, shown with default values
 *
 *	format=tgz
 *		archive format
 *
 *	version=YYYY-MM-DD
 *		package base version (overrides current date)
 *
 *	release=YYYY-MM-DD
 *		package delta release (overrides current date)
 *
 *	license=type.class
 *		:LICENSE: type.class pattern override
 *
 *	notice=1
 *		include the conspicuous empty notice file
 *
 *	copyright=0
 *		do not prepend source file copyright notice
 *
 *	strip=0
 *		don't strip non-lcl binary package members
 *
 *	variants=pattern
 *		include variants matching pattern in binary packages
 *
 *	incremental=[source:1 binary:0]
 *		if a base archive is generated then also generate an
 *		incremental delta archive from the previous base
 *
 * NOTE: the Makerules.mk :PACKAGE: operator defers to :package: when
 *	 a target is specified
 */

/* these are ast centric -- we'll parameterize another day */

org = ast
url = http://www.research.att.com/sw/download

/* generic defaults */

base =
category = utils
checksum = md5
closure =
copyright = 1
delta =
format = tgz
incremental =
index =
init = INIT
license =
licenses = $(org)
mamfile = 1
opt =
name =
notice =
release =
strip = 0
style = tgz
suffix = tgz
type =
variants = !(cc-g)
vendor =
version = $("":T=R%Y-%m-%d)

SUM = sum

package.notice = ------------ NOTICE -- LICENSED SOFTWARE -- SEE README FOR DETAILS ------------

package.readme = $(@.package.readme.)

.package.readme. :
	This is a package root directory $PACKAGEROOT. Source and binary
	packages in this directory tree are controlled by the command
	$()
		bin/package
	$()
	Binary files may be in this directory or in the install root directory
	$()
		INSTALLROOT=$PACKAGEROOT/arch/`bin/package`
	$()
	For more information run
	$()
		bin/package help
	$()
	Many of the packaged commands self-document via the --man and --html
	options; those that do have no separate man page.
	$()
	Each package is covered by one of the license files
	$()
		$(PACKAGELIB)/LICENSES/<license>
	$()
	where <license> is the license type for the package.  At the top
	of each license file is a URL; the license covers all software that
	refers to this URL. For details run
	$()
		bin/package license [<package>]
	$()
	Any archives, distributions or packages made from source or
	binaries covered by license(s) must contain the corresponding
	license file(s)$(notice:?, this README file, and the empty file$$("\n")$$(package.notice)?.?)

.package.licenses. : .FUNCTION
	local I F L R T all save text
	L := $(%)
	while L == "--*"
		I := $(L:O=1)
		if I == "--all"
			all = 1
		elif I == "--save"
			save = 1
		elif I == "--text"
			text = 1
		end
		L := $(L:O>1)
	end
	if "$(L)" == "*-*"
		L += $(L:/[^-]*-//) $(L:/-.*//)
	end
	L += $(licenses)
	for I $(L:U)
		if I == "gpl"
			I = gnu
			all =
		end
		if F = "$(I:D=$(PACKAGESRC):B:S=.lic:T=F)"
			R += $(F)
			if save || text
				T := $(.FIND. lib/package .lic $(F):P=W,query=type)
				R += $(T:D=$(PACKAGESRC)/LICENSES:B)
			end
			if save
				R += $(F:T=I:N=*.def:D=$(PACKAGESRC):B:S:T=F)
			elif ! all
				break
			end
		end
	end
	return $(R)

/*
 * glob(3) doesn't handle / in alternation -- should it?
 */

.package.glob. : .FUNCTION
	local A D I P S
	for I $(%)
		if I == "*/*"
			D := $(I:C,/.*,,)
			if ! "$(A:N=$(D))"
				local S.$(D)
				A += $(D)
			end
			S.$(D) += $(I:C,[^/]*/,,)
		else
			P := $(P)$(S)$(I)
		end
		S = |
	end
	if P == "*\|*"
		P := ($(P))
	end
	for I $(A)
		P += $(I)/$(.package.glob. $(S.$(I)))
	end
	return $(P)


.MAKEINIT : .package.init

.package.init : .MAKE .VIRTUAL .FORCE
	local V
	V := $(VROOT:T=F:P=L*)
	if ! PACKAGEROOT
	PACKAGEROOT := $(V:N!=*/arch/+([!/]):O=1)
	end
	if V == "$(PACKAGEROOT)"
		V :=
	end
	V += $(INSTALLROOT) $(PACKAGEROOT)
	PACKAGEVIEW := $(V:H=RU)
	INSTALLOFFSET := $(INSTALLROOT:C%$(PACKAGEROOT)/%%)
	if license
		license := $(license)|none.none
	end

PACKAGELIB = lib/package
PACKAGESRC = $(PACKAGEROOT)/$(PACKAGELIB)
PACKAGEBIN = $(INSTALLROOT)/$(PACKAGELIB)
PACKAGEDIR = $(PACKAGESRC)/$(style)
INSTALLOFFSET = $(INSTALLROOT:C%$(PACKAGEROOT)/%%)

package.omit = -|*/$(init)
package.glob.all = $(INSTALLROOT)/src/*/*/($(MAKEFILES:/:/|/G))
package.all = $(package.glob.all:P=G:W=O=$(?$(name):A=.VIRTUAL):N!=$(package.omit):T=F:$(PACKAGEVIEW:C,.*,C;^&/;;,:/ /:/G):U)
package.glob.pkg = $(.package.glob. $(~$(name):P=U):C%.*%$(INSTALLROOT)/src/*/&/($(MAKEFILES:/:/|/G))%) $(~$(name):P=U:N=$(name):?$$(INSTALLROOT)/src/$$(name)/($$(MAKEFILES:/:/|/G))??)
package.pkg = $(package.glob.pkg:P=G:D:N!=$(package.omit):T=F:$(PACKAGEVIEW:C,.*,C;^&/;;,:/ /:/G):U)
package.closure = $(closure:?$$(package.all)?$$(package.pkg)?)

package.init = $(.package.glob. $("$(init)$(name)":P=U):C%.*%$(INSTALLROOT)/src/*/&/($(MAKEFILES:/:/|/G))%:P=G:T=F:D::B)
package.ini = ignore mamprobe manmake package silent
package.src.pat = $(PACKAGESRC)/($(name).(ini|pkg))
package.src = $(package.src.pat:P=G) $(.package.licenses. --save $(name))
package.bin = $(PACKAGEBIN)/$(name).ini

package.mam = --never --force --mam=static --corrupt=accept --clobber --compare --link='lib*.a*' CC=$(CC.DIALECT:N=C++:?CC?cc?) package.license.class=$(license:Q) $(=) 'dontcare test' install test

op = current
stamp = [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]
source = $(PACKAGEDIR)/$(name).$(version)$(release:?.$(release)??).$(suffix)
binary = $(PACKAGEDIR)/$(name).$(version)$(release:?.$(release)??).$(CC.HOSTTYPE).$(suffix)
runtime = $(PACKAGEDIR)/$(name)-run.$(version)$(release:?.$(release)??).$(CC.HOSTTYPE).$(suffix)
old.new.source = $(PACKAGEDIR)/$(name).$(version).$(old.version).$(suffix)
old.new.binary = $(PACKAGEDIR)/$(name).$(version).$(old.version).$(CC.HOSTTYPE).$(suffix)
old.new.runtime = $(PACKAGEDIR)/$(name)-run.$(version).$(old.version).$(CC.HOSTTYPE).$(suffix)

source.list = $("$(PACKAGEDIR)/$(name).*$(stamp).$(suffix)":P=G:H=R)
binary.list = $("$(PACKAGEDIR)/$(name).*$(stamp).$(CC.HOSTTYPE).$(suffix)":P=G:H=R)
runtime.list = $("$(PACKAGEDIR)/$(name)-run.*$(stamp).$(CC.HOSTTYPE).$(suffix)":P=G:H>)

source.ratz = $("$(INSTALLROOT)/src/cmd/$(init)/ratz.c":T=F)
binary.ratz = $("$(INSTALLROOT)/src/cmd/$(init)/ratz":T=F)

$(init) : .VIRTUAL $(init)

package.requires = 0

":package:" : .MAKE .OPERATOR
	local P I R V
	P := $(<:O=1)
	$(P) : $(>:V)
	if ! package.requires
		if ! name
			name := $(P)
			.PACKAGE. := $(P)
			if name == "$(init)"
				package.omit = -
				package.src += $(package.ini:C,^,$(PACKAGEROOT)/bin/,) $(PACKAGESRC)/package.mk
			else
				$(P) : $(package.init)
			end
			for I $(<:O>1)
				if I == "*=*"
					eval
					$(I)
					end
				else
					version := $(I)
				end
			end
			LICENSEFILEDEFAULT := $(.package.licenses. $(name):@/ /:/G)
			export LICENSEFILEDEFAULT
		end
		if "$(>)"
			for I $(>:V)
				$(I) : .VIRTUAL
				if I == "/*"
					package.dir += $(I:V)
				end
			end
		end
		if "$(@)"
			$(P).README := $(@)
		else
			$(P).README := This is the $(P) package.
		end
	end

":AUXILIARY:" : .MAKE .OPERATOR
	package.auxiliary.$(style) += $(>:N=/*:T=F) $(>:N!=/*:C%^%$(INSTALLROOT)/%:T=F)

":CATEGORY:" : .MAKE .OPERATOR
	if ! package.requires
		category := $(>)
	end

.covers. : .FUNCTION
	local I C D F K=0 L
	for I $(%)
		if ! "$(~covers:N=$(I:B))"
			if F = "$(I:D:B:S=.pkg:T=F)"
				if D = "$(F:T=I)"
					covers : $(I:B)
					for L $(D)
						if L == ":COVERS:"
							K = 1
						elif L == ":*:"
							if K
								break
							end
						elif K
							: $(.covers. $(L))
						end
					end
				end
			else
				error $(--exec:?3?1?) $(I): unknown package $(I)
			end
		end
	end

":COVERS:" : .MAKE .OPERATOR
	if ! package.requires
		: $(.covers. $(>))
	end

":DESCRIPTION:" : .MAKE .OPERATOR
	if ! package.requires
		$(name).README := $(@:V)
	end

":DETAILS:" : .MAKE .OPERATOR
	if ! package.requires
		details.$(>:O=1) := $(@:V)
	end

":EXPORT:" : .MAKE .OPERATOR
	if ! package.requires
		export.$(style) := $(@:/$$("\n")/ /G)
	end

":INDEX:" : .MAKE .OPERATOR
	if ! package.requires
		index := $(>)
	end

":INSTALL:" : .MAKE .OPERATOR
	if ! package.requires
		local T S F X
		S := $(>)
		T := $(<)
		if "$(exe.$(style))" && "$(T)" == "bin/*([!./])"
			T := $(T).exe
		end
		if ! "$(S)"
			S := $(T)
		elif "$(exe.$(style))" && "$(S)" == "bin/*([!./])"
			S := $(S).exe
		end
		install.$(style) := $(install.$(style):V)$("\n")install : $$(ROOT)/$(T)$("\n")$$(ROOT)/$(T) : $$(ARCH)/$(S)$("\n\t")cp $< $@
		if strip && "$(T:N=*.exe)"
			install.$(style) := $(install.$(style):V)$("\n\t")strip $@ 2>/dev/null
		end
		X := $(PACKAGEROOT)/arch/$(CC.HOSTTYPE)/$(S)
		if strip && "$(X:T=Y)" == "*/?(x-)(dll|exe)"
			F := filter $(STRIP) $(STRIPFLAGS) $(X)
		end
		if "$(filter.$(style):V)"
			filter.$(style) := $(filter.$(style):V)$$("\n")
		end
		filter.$(style) := $(filter.$(style):V);;$(F);$(X);usr/$(T)
	end

":LICENSE:" : .MAKE .OPERATOR
	if ! package.requires && ! license
		license := $(>)
	end

":OMIT:" : .MAKE .OPERATOR
	if ! package.requires
		package.omit := $(package.omit)|$(>:C,^,*/,:/ /|/G)
	end

":POSTINSTALL:" : .MAKE .OPERATOR
	if ! package.requires
		postinstall.$(style) := $(@:V)
	end

":README:" : .MAKE .OPERATOR
	if ! package.requires
		readme.$(style) := $(@:V)
	end

.requires. : .FUNCTION
	local I C D F K=0 L V T M=0
	for I $(%)
		if ! "$(~requires:N=$(I:B))"
			if F = "$(I:D:B:S=.pkg:T=F)"
				if I == "$(init)"
					package.omit = -
				else
					requires : $(I:B)
				end
				if V = "$(I:D:B=gen/$(I:B):S=.ver:T=F)"
					req : $(I:B)
				else
					error 1 $(I): package should be written before $(P)
				end
				let package.requires = package.requires + 1
				include "$(F)"
				let package.requires = package.requires - 1
			else
				error 1 $(I): package not found
			end
		end
	end

":REQUIRES:" : .MAKE .OPERATOR
	: $(.requires. $(>))

":TEST:" : .MAKE .OPERATOR
	if ! package.requires
		local T
		T := $(>)
		if "$(T)" == "bin/*([!./])"
			if "$(exe.$(style))"
				T := $(T).exe
			end
			T := $$(PWD)/$$(ARCH)/$(T)
		end
		test.$(style) := $(test.$(style):V)$("\n")test : $(T:V)$("\n\t")$(@)
	end

base delta : .MAKE .VIRTUAL .FORCE
	op := $(<)

closure : .MAKE .VIRTUAL .FORCE
	$(<) := 1

cyg exp lcl pkg rpm tgz : .MAKE .VIRTUAL .FORCE
	style := $(<)

source : .source.init .source.gen .source.$$(style)

.source.init : .MAKE
	local A B D P V I
	type := source
	if ! "$(incremental)"
		incremental = 1
	end
	if "$(source.$(name))"
		suffix = c
	end
	: $(.init.$(style))
	: $(details.$(style):V:R) :
	A := $(source.list)
	B := $(A:N=*.$(stamp).$(suffix):N!=*.$(stamp).$(stamp).*:O=1:T=F)
	P := $(A:N=*.$(stamp).$(suffix):N!=*.$(stamp).$(stamp).*:O=2:T=F)
	D := $(A:N=*.$(stamp).$(stamp).$(suffix):O=1:T=F)
	if op == "delta"
		if ! B
			error 3 delta requires a base archive
		end
		base := -z $(B)
		deltaversion := $(B:B:/$(name).//)
		let deltasince = $(deltaversion:/.*-//) + 1
		deltasince := $(deltaversion:/[^-]*$/$(deltasince:F=%02d)/)
		if "$(release)" != "$(stamp)"
			release := $("":T=R%Y-%m-%d)
		end
		source := $(B:D:B:S=.$(release).$(suffix))
		version := $(source:B:B:/$(name).//)
	elif B || op == "base"
		if op == "base"
			for I $(B) $(P)
				V := $(I:B:/$(name)\.\([^.]*\).*/\1/)
				if V == "$(stamp)" && V != "$(version)"
					old.version := $(V)
					old.source := $(I)
					if "$(old.version)" >= "$(version)"
						error 3 $(name): previous base $(old.version) is newer than $(version)
					end
					break
				end
			end
		else
			source := $(B)
		end
		if B == "$(source)"
			if "$(B:D:B:B)" == "$(D:D:B:B)" && "$(B:B::S)" != "$(D:B::S)"
				error 3 $(B:B:S): base overwrite would invalidate delta $(D:B:S)
			end
			error 1 $(B:B:S): replacing current base
		end
		version := $(source:B:S:/^$(name).\(.*\).$(suffix)$/\1/)
	end
	PACKAGEGEN := $(PACKAGESRC)/gen

.source.gen : $$(PACKAGEDIR) $$(PACKAGEGEN) $$(PACKAGEGEN)/SOURCE.html $$(PACKAGEGEN)/BINARY.html $$(PACKAGEGEN)/DETAILS.html

BINPACKAGE := $(PATH:/:/ /G:X=package:T=F:O=1)

$$(PACKAGEDIR) $$(PACKAGEGEN) : .IGNORE
	[[ -d $(<) ]] || mkdir $(<)

$$(PACKAGEGEN)/SOURCE.html : $(BINPACKAGE)
	$(*) html source > $(<)

$$(PACKAGEGEN)/BINARY.html : $(BINPACKAGE)
	$(*) html binary > $(<)

$$(PACKAGEGEN)/DETAILS.html : $(BINPACKAGE)
	$(*) html intro > $(<)

.source.exp .source.pkg .source.rpm : .MAKE
	error 3 $(style): source package style not supported yet

exe.cyg = .exe
vendor.cyg = gnu

.name.cyg : .FUNCTION
	local N
	N := $(%)
	if N == "*-*"
		vendor := $(N:/-.*//)
		if vendor == "$(vendor.cyg)"
			vendor :=
			N := $(N:/[^-]*-//)
		end
		N := $(N:/-//G)
	end
	return $(N)

.init.cyg : .FUNCTION
	local N O
	closure = 1
	init = .
	strip = 1
	suffix = tar.bz2
	format = tbz
	vendor := $(licenses:N!=$(vendor.cyg):O=1)
	package.ini := $(package.ini)
	package.src.pat := $(package.src.pat)
	package.src := $(package.src)
	package.bin := $(package.bin)
	.source.gen : .CLEAR $(*.source.gen:V:N!=*.html)
	name.original := $(name)
	name := $(.name.cyg $(name))
	if name != "$(name.original)"
		$(name) : $(~$(name.original))
		O := $(~covers)
		covers : .CLEAR
		for N $(O)
			covers : $(.name.cyg $(N))
		end
	end
	stamp = [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9]
	version.original := $(version)
	version := $(version:/-//G)-1
	if opt
		opt := $(opt)/$(vendor)/
	else
		opt := $(name)-$(version)/
	end
	if type == "source"
		version := $(version)-src
		source = $(PACKAGEDIR)/$(name)-$(version)$(release:?.$(release)??).$(suffix)
	else
		binary = $(PACKAGEDIR)/$(name)-$(version)$(release:?.$(release)??).$(suffix)
	end

.source.cyg :
	if	[[ '$(~$(name))' ]]
	then	tmp=/tmp/pkg$(tmp)
		mkdir $tmp
		{
			integer m=0 o
			cat > $tmp/configure <<'!'
	echo "you didn't have to do that"
	!
			chmod +x $tmp/configure
			echo ";;;$tmp/configure;configure"
			cat > $tmp/Makefile0 <<'!'
	HOSTTYPE := $$(shell bin/package)
	ROOT = ../..
	ARCH = arch/$$(HOSTTYPE)
	all :
		PACKAGEROOT= CYGWIN="$$CYGWIN ntsec binmode" bin/package make $(export.$(style))
	install : all
	$(install.$(style):V)
	$(test.$(style):V)
	!
			echo ";;;$tmp/Makefile0;Makefile"
			cat > $tmp/CYGWIN-README <<'!'
	$(readme.$(style):@?$$(readme.$$(style))$$("\n\n")??)To build binaries from source into the ./arch/`bin/package` tree run:
	$()
		make
	$()
	$(test.$(style):@?To test the binaries after building/installing run:$$("\n\n\t")make test$$("\n\n")??)To build and/or install the binaries run:
	$()
		make install
	$()
	The bin/package command provides a command line interface for all package
	operations. The $(opt:/.$//) source and binary packages were generated by:
	$()
		package write cyg base source version=$(version.original) $(name.original)
		package write cyg base binary version=$(version.original) $(name.original)
	$()
	using the $(org)-base package. To download and install the latest
	$(org)-base source package in /opt/$(org) run:
	$()
		PATH=/opt/$(org)/bin:$PATH
		cd /opt/$(org)
		package authorize "NAME" password "PASSWORD" setup flat source $("\\")
			$(url) $("\\")
			$(org)-base
		package make
	$()
	and export /opt/$(org)/bin in PATH to use. The NAME and PASSWORD signify your
	agreement to the software license(s). All users get the same NAME and PASSWORD.
	See $(url) for details. If multiple architectures may be built under
	/opt/$(org) then drop "flat" and export /opt/$(org)/arch/`package`/bin in PATH
	to use. To update previously downloaded packages from the same url simply run:
	$()
		cd /opt/$(org)
		package setup
		package make
	$()
	To download and install the latest $(org)-base binary package in
	/opt/$(org) change "source" to "binary" and omit "package make".
	!
			echo ";;;$tmp/CYGWIN-README;CYGWIN-PATCHES/README"
			cat > $(source:/-src.$(suffix)//).setup.hint <<'!'
	category: $(category:/\(.\).*/\1/U)$(category:/.\(.*\)/\1/L)
	requires: cygwin
	sdesc: "$(index)"
	ldesc: "$($(name.original).README)"
	!
			echo ";;;$(source:/-src.$(suffix)//).setup.hint;CYGWIN-PATCHES/setup.hint"
			echo ";;;$(BINPACKAGE);bin/package"
			cat > $tmp/Makefile <<'!'
	:MAKE:
	!
			echo ";;;$tmp/Makefile;src/Makefile"
			echo ";;;$tmp/Makefile;src/cmd/Makefile"
			echo ";;;$tmp/Makefile;src/lib/Makefile"
			if	[[ '$(mamfile)' == 1 ]]
			then	cat > $tmp/Mamfile1 <<'!'
	info mam static
	note source level :MAKE: equivalent
	make install
	make all
	exec - ${MAMAKE} -r '*/*' ${MAMAKEARGS}
	done all virtual
	done install virtual
	!
				echo ";;;$tmp/Mamfile1;src/Mamfile"
				cat > $tmp/Mamfile2 <<'!'
	info mam static
	note component level :MAKE: equivalent
	make install
	make all
	exec - ${MAMAKE} -r '*' ${MAMAKEARGS}
	done all virtual
	done install virtual
	!
				echo ";;;$tmp/Mamfile2;src/cmd/Mamfile"
				echo ";;;$tmp/Mamfile2;src/lib/Mamfile"
			fi
			$(package.src:U:T=F:/.*/echo ";;;&"$("\n")/)
			echo ";;;$(PACKAGEGEN)/$(name.original).req"
			set -- $(package.closure)
			for i
			do	cd $(INSTALLROOT)/$i
				if	[[ ! '$(license)' ]] || $(MAKE) --noexec --silent 'exit $$(LICENSECLASS:N=$(license):?0?1?)' .
				then	if	[[ '$(mamfile)' == 1 ]]
					then	(( o=m ))
						s=$( $(MAKE) --noexec --recurse=list recurse 2>/dev/null )
						if	[[ $s ]]
						then	for j in $s
							do	if	[[ -d $j ]]
								then	cd $j
									if	[[ ! '$(license)' ]] || $(MAKE) --noexec --silent 'exit $$(LICENSECLASS:N=$(license):?0?1?)' .
									then	(( m++ ))
										$(MAKE) $(package.mam) $(export.$(style):Q) > $tmp/$m.mam
										echo ";;;$tmp/$m.mam;$i/$j/Mamfile"
									fi
									cd $(INSTALLROOT)/$i
								fi
							done
							if	(( o != m ))
							then	(( m++ ))
								cat > $tmp/$m.mam <<'!'
	info mam static
	note subcomponent level :MAKE: equivalent
	make install
	make all
	exec - ${MAMAKE} -r '*' ${MAMAKEARGS}
	done all virtual
	done install virtual
	!
								echo ";;;$tmp/$m.mam;$i/Mamfile"
							fi
						else	(( m++ ))
							$(MAKE) $(package.mam) $(export.$(style):Q) > $tmp/$m.mam
							echo ";;;$tmp/$m.mam;$i/Mamfile"
						fi
					fi
					$(MAKE) --noexec $(-) $(=) recurse list.package.$(type) package.license.class=$(license:Q)
				fi
			done
			set -- $(package.dir:P=G)
			for i
			do	tw -d $i -e "action:printf(';;;%s;%s\n',path,path);"
			done
		} |
		{
			: > $tmp/HEAD
			cat > $tmp/README <<'!'
	$(package.readme)
	!
			echo ";;;$tmp/README;README"
			sort -t';' -k5,5 -u
			: > $tmp/TAIL
			[[ '$(notice)' ]] && echo ";;;$tmp/TAIL;$(package.notice)"
		} |
		$(PAX)	--filter=- \
			--to=ascii \
			--format=$(format) \
			--local \
			-wvf $(source) $(base) \
			$(PACKAGEVIEW:C%.*%-s",^&/,,"%) \
			$(vendor:?-s",^[^/],$(opt)&,"??)
		$(SUM) -x $(checksum) < $(source) > $(source:D:B:S=.$(checksum))
		rm -rf $tmp
	fi

.source.lcl :
	if	[[ '$(~$(name))' ]]
	then	tmp=/tmp/pkg$(tmp)
		mkdir $tmp
		{
			integer m=0 o
			$(package.src:U:T=F:/.*/echo ";;;&"$("\n")/)
			set -- $(package.closure)
			for i
			do	cd $(INSTALLROOT)/$i
				$(MAKE) --noexec $(-) $(=) .FILES.+=Mamfile recurse list.package.local
			done
			set -- $(package.dir:P=G)
			for i
			do	tw -d $i -e "action:printf(';;;%s;%s\n',path,path);"
			done
		} |
		sort -t';' -k5,5 -u |
		$(PAX)	--filter=- \
			--to=ascii \
			$(op:N=delta:??--format=$(format)?) \
			--local \
			-wvf $(source) $(base) \
			$(op:N=delta:?--format=gzip??) \
			$(PACKAGEVIEW:C%.*%-s",^&/,,"%)
		rm -rf $tmp
	fi

.source.tgz :
	if	[[ '$(~$(name))' ]]
	then	tmp=/tmp/pkg$(tmp)
		mkdir $tmp
		{
			integer m=0 o
			if	[[ '$(init)' == '$(name)' ]]
			then	cat > $tmp/Makefile <<'!'
	:MAKE:
	!
				$(CMP) $(CMPFLAGS) $tmp/Makefile $(PACKAGEROOT)/src/Makefile && touch -r $(PACKAGEROOT)/src/Makefile $tmp/Makefile
				echo ";;;$tmp/Makefile;src/Makefile"
				cp $tmp/Makefile $tmp/Makefile1
				$(CMP) $(CMPFLAGS) $tmp/Makefile1 $(PACKAGEROOT)/src/cmd/Makefile && touch -r $(PACKAGEROOT)/src/cmd/Makefile $tmp/Makefile1
				echo ";;;$tmp/Makefile1;src/cmd/Makefile"
				cp $tmp/Makefile $tmp/Makefile2
				$(CMP) $(CMPFLAGS) $tmp/Makefile2 $(PACKAGEROOT)/src/lib/Makefile && touch -r $(PACKAGEROOT)/src/lib/Makefile $tmp/Makefile2
				echo ";;;$tmp/Makefile2;src/lib/Makefile"
				if	[[ '$(mamfile)' == 1 ]]
				then	cat > $tmp/Mamfile1 <<'!'
	info mam static
	note source level :MAKE: equivalent
	make install
	make all
	exec - ${MAMAKE} -r '*/*' ${MAMAKEARGS}
	done all virtual
	done install virtual
	!
					$(CMP) $(CMPFLAGS) $tmp/Mamfile1 $(PACKAGEROOT)/src/Mamfile && touch -r $(PACKAGEROOT)/src/Mamfile $tmp/Mamfile1
					echo ";;;$tmp/Mamfile1;src/Mamfile"
					cat > $tmp/Mamfile2 <<'!'
	info mam static
	note component level :MAKE: equivalent
	make install
	make all
	exec - ${MAMAKE} -r '*' ${MAMAKEARGS}
	done all virtual
	done install virtual
	!
					$(CMP) $(CMPFLAGS) $tmp/Mamfile2 $(PACKAGEROOT)/src/cmd/Mamfile && touch -r $(PACKAGEROOT)/src/cmd/Mamfile $tmp/Mamfile2
					echo ";;;$tmp/Mamfile2;src/cmd/Mamfile"
					cp $tmp/Mamfile2 $tmp/Mamfile3
					$(CMP) $(CMPFLAGS) $tmp/Mamfile3 $(PACKAGEROOT)/src/lib/Mamfile && touch -r $(PACKAGEROOT)/src/lib/Mamfile $tmp/Mamfile3
					echo ";;;$tmp/Mamfile3;src/lib/Mamfile"
				fi
			fi
			$(package.src:U:T=F:C%^$(PACKAGEROOT)/%%:C%.*%echo ";;;$(PACKAGEROOT)/&;&"$("\n")%)
			if	[[ '$(~covers)' ]]
			then	for i in $(~covers)
				do	for j in lib pkg
					do	if	[[ -f $(PACKAGESRC)/$i.$j ]]
						then	echo ";;;$(PACKAGESRC)/$i.$j;$(PACKAGELIB)/$i.$j"
						fi
					done
					for j in ver req
					do	if	[[ -f $(PACKAGEGEN)/$i.$j ]]
						then	echo ";;;$(PACKAGEGEN)/$i.$j;$(PACKAGELIB)/$i.$j"
						fi
					done
				done
				for i in $(~covers:D=$(PACKAGESRC):B:S=.lic:T=F:T=I:N=*.def:D=$(PACKAGESRC):B:S:T=F:B:S)
				do	echo ";;;$(PACKAGESRC)/$i;$(PACKAGELIB)/$i"
				done
			fi
			if	[[ '$(PACKAGEDIR:B)' == '$(style)' ]]
			then	echo $(name) $(version) $(release|version) 1 > $tmp/t
				$(CMP) $(CMPFLAGS) $tmp/t $(PACKAGEGEN)/$(name).ver || cp $tmp/t $(PACKAGEGEN)/$(name).ver
				echo ";;;$(PACKAGEGEN)/$(name).ver;$(PACKAGELIB)/$(name).ver"
				sed 's,1$,0,' $(~req:D=$(PACKAGEGEN):B:S=.ver:T=F) < /dev/null > $tmp/t
				$(CMP) $(CMPFLAGS) $tmp/t $(PACKAGEGEN)/$(name).req || cp $tmp/t $(PACKAGEGEN)/$(name).req
				echo ";;;$(PACKAGEGEN)/$(name).req;$(PACKAGELIB)/$(name).req"
				{
					echo "name='$(name)'"
					echo "index='$(index)'"
					echo "covers='$(~covers)'"
					echo "requires='$(~req)'"
				} > $tmp/t
				$(CMP) $(CMPFLAGS) $tmp/t $(PACKAGEGEN)/$(name).inx || cp $tmp/t $(PACKAGEGEN)/$(name).inx
				{
					{
					echo '$($(name).README)'
					if	[[ '$(~covers)' ]]
					then	echo "This package is a superset of the following package$(~covers:O=2:?s??): $(~covers); you won't need $(~covers:O=2:?these?this?) if you download $(name)."
					fi
					if	[[ '$(~requires)' ]]
					then	echo 'It requires the following package$(~requires:O=2:?s??): $(~requires).'
					fi
					} | fmt
					package help source
					package release $(name)
				} > $tmp/t
				$(CMP) $(CMPFLAGS) $tmp/t $(PACKAGEGEN)/$(name).README || cp $tmp/t $(PACKAGEGEN)/$(name).README
				echo ";;;$(PACKAGEGEN)/$(name).README;$(PACKAGELIB)/$(name).README"
				{
					echo '.xx title="$(name) package"'
					echo '.xx meta.description="$(name) package"'
					echo '.xx meta.keywords="software, package"'
					echo '.MT 4'
					echo '.TL'
					echo '$(name) package'
					echo '.H 1 "$(name) package"'
					echo '$($(name).README)'
					set -- $(package.closure:C,.*,$(INSTALLROOT)/&/PROMO.mm,:T=F:D::B)
					hot=
					for i
					do	hot="$hot -e s/\\(\\<$i\\>\\)/\\\\h'0*1'\\1\\\\h'0'/"
					done
					set -- $(package.closure:B)
					if	(( $# ))
					then	echo 'Components in this package:'
						echo '.P'
						echo '.TS'
						echo 'center expand;'
						echo 'l l l l l l.'
						if	[[ $hot ]]
						then	hot="sed $hot"
						else	hot=cat
						fi
						for i
						do	echo $i
						done |
						pr -6 -t -s'	' |
						$hot
						echo '.TE'
					fi
					echo '.P'
					if	[[ '$(~covers)' ]]
					then	echo "This package is a superset of the following package$(~covers:O=2:?s??): $(~covers); you won't need $(~covers:O=2:?these?this?) if you download $(name)."
					fi
					if	[[ '$(~requires)' ]]
					then	echo 'It requires the following package$(~requires:O=2:?s??): $(~requires).'
					fi
					set -- $(.package.licenses. --all $(name))
					case $# in
					0)	;;
					*)	case $# in
						1)	echo 'The software is covered by this license:' ;;
						*)	echo 'The software is covered by these licenses:' ;;
						esac
						echo .BL
						for j
						do	i=$( $(PROTO) -l $j -p -h -o type=usage /dev/null | sed -e 's,.*\[-license?\([^]]*\).*,\1,' )
							echo .LI
							echo ".xx link=\"$i\""
						done
						echo .LE
						echo 'Individual components may be covered by separate licenses;'
						echo 'refer to the component source and/or binaries for more information.'
						echo .P
						;;
					esac
					echo 'A recent'
					echo '.xx link="release change log"'
					echo 'is also included.'
					cat $(package.closure:C,.*,$(INSTALLROOT)/&/PROMO.mm,:T=F) < /dev/null
					echo '.H 1 "release change log"'
					echo '.xx index'
					echo '.nf'
					package release $(name) |
					sed -e 's/:::::::: \(.*\) ::::::::/.fi\$("\n").H 1 "\1 changes"\$("\n").nf/'
					echo '.fi'
				} |
				$(MM2HTML) $(MM2HTMLFLAGS) -o nohtml.ident > $tmp/t
				$(STDED) $(STDEDFLAGS) $tmp/t <<'!'
	/^<!--LABELS-->$/,/^<!--\/LABELS-->$/s/ changes</</
	/^<!--LABELS-->$/,/^<!--\/LABELS-->$/m/<A name="release change log">/
	w
	q
	!
				$(CMP) $(CMPFLAGS) $tmp/t $(PACKAGEGEN)/$(name).html || cp $tmp/t $(PACKAGEGEN)/$(name).html
				echo ";;;$(PACKAGEGEN)/$(name).html;$(PACKAGELIB)/$(name).html"
				if	[[ '$(deltasince)' ]]
				then	{
					echo '.xx title="$(name) package"'
					echo '.xx meta.description="$(name) package $(version) delta $(release)"'
					echo '.xx meta.keywords="software, package, delta"'
					echo '.MT 4'
					echo '.TL'
					echo '$(name) package $(deltaversion) delta $(release)'
					echo '.H 1 "$(name) package $(deltaversion) delta $(release) changes"'
					echo '.nf'
					package release $(deltasince) $(name) |
					sed -e 's/:::::::: \(.*\) ::::::::/.H 2 \1/'
					echo '.fi'
					} |
					$(MM2HTML) $(MM2HTMLFLAGS) -o nohtml.ident > $tmp/t
					$(CMP) $(CMPFLAGS) $tmp/t $(PACKAGEGEN)/$(name).$(release).html || cp $tmp/t $(PACKAGEGEN)/$(name).$(release).html
					echo ";;;$(PACKAGEGEN)/$(name).$(release).html;$(PACKAGELIB)/$(name).$(release).html"
				fi
			fi
			set -- $(package.closure)
			for i
			do	cd $(INSTALLROOT)/$i
				if	[[ ! '$(license)' ]] || $(MAKE) --noexec --silent 'exit $$(LICENSECLASS:N=$(license):?0?1?)' .
				then	if	[[ '$(mamfile)' == 1 ]]
					then	(( o=m ))
						s=$( $(MAKE) --noexec --recurse=list recurse 2>/dev/null )
						if	[[ $s ]]
						then	for j in $s
							do	if	[[ -d $j ]]
								then	cd $j
									if	[[ ! '$(license)' ]] || $(MAKE) --noexec --silent 'exit $$(LICENSECLASS:N=$(license):?0?1?)' .
									then	(( m++ ))
										$(MAKE) $(package.mam) > $tmp/$m.mam
										$(CMP) $(CMPFLAGS) $tmp/$m.mam $(PACKAGEROOT)/$i/$j/Mamfile && touch -r $(PACKAGEROOT)/$i/$j/Mamfile $tmp/$m.mam
										echo ";;;$tmp/$m.mam;$i/$j/Mamfile"
									fi
									cd $(INSTALLROOT)/$i
								fi
							done
							if	(( o != m ))
							then	(( m++ ))
								cat > $tmp/$m.mam <<'!'
	info mam static
	note subcomponent level :MAKE: equivalent
	make install
	make all
	exec - ${MAMAKE} -r '*' ${MAMAKEARGS}
	done all virtual
	done install virtual
	!
								$(CMP) $(CMPFLAGS) $tmp/$m.mam $(PACKAGEROOT)/$i/Mamfile && touch -r $(PACKAGEROOT)/$i/Mamfile $tmp/$m.mam
								echo ";;;$tmp/$m.mam;$i/Mamfile"
							fi
						else	(( m++ ))
							$(MAKE) $(package.mam) > $tmp/$m.mam
							$(CMP) $(CMPFLAGS) $tmp/$m.mam $(PACKAGEROOT)/$i/Mamfile && touch -r $(PACKAGEROOT)/$i/Mamfile $tmp/$m.mam
							echo ";;;$tmp/$m.mam;$i/Mamfile"
						fi
					fi
					$(MAKE) --noexec $(-) $(=) recurse list.package.$(type) package.license.class=$(license:Q) $(copyright:N=1:??LICENSE=?)
				fi
			done
			set -- $(package.dir:P=G)
			for i
			do	tw -d $i -e "action:printf(';;;%s;%s\n',path,path);"
			done
		} |
		{
			: > $tmp/HEAD
			[[ '$(notice)' ]] && echo ";;;$tmp/HEAD;$(package.notice)"
			cat > $tmp/README <<'!'
	$(package.readme)
	!
			echo ";;;$tmp/README;README"
			$(CMP) $(CMPFLAGS) $tmp/README $(PACKAGEROOT)/README && touch -r $(PACKAGEROOT)/README $tmp/README
			sort -t';' -k5,5 -u
			: > $tmp/TAIL
			[[ '$(notice)' ]] && echo ";;;$tmp/TAIL;$(package.notice)"
		} |
		$(PAX)	--filter=- \
			--to=ascii \
			$(op:N=delta:??--format=$(format)?) \
			--local \
			-wvf $(source) $(base) \
			$(op:N=delta:?--format=gzip??) \
			$(PACKAGEVIEW:C%.*%-s",^&/,,"%)
		$(SUM) -x $(checksum) < $(source) > $(source:D:B:S=.$(checksum))
		echo local > $(source:D:B=$(name):S=.tim)
		if	[[ '$(incremental)' == 1 && '$(old.source)' ]]
		then	$(PAX) -rf $(source) -wvf $(old.new.source) -z $(old.source)
			$(SUM) -x $(checksum) < $(old.new.source) > $(old.new.source:D:B:S=.$(checksum))
		fi
		rm -rf $tmp
	else	if	[[ '$(old.source)' ]] && $(CMP) $(CMPFLAGS) $(source.$(name)) $(source)
		then	: $(name) is up to date
		else	echo $(name) $(version) $(release|version) 1 > $(PACKAGEGEN)/$(name).ver
			: > $(PACKAGEGEN)/$(name).req
			{
				echo "name='$(name)'"
				echo "index='$(index)'"
				echo "covers='$(~covers)'"
				echo "requires='$(~req)'"
			} > $(PACKAGEGEN)/$(name).inx
			{
				echo '.xx title="$(name) package"'
				echo '.xx meta.description="$(name) package"'
				echo '.xx meta.keywords="software, package"'
				echo '.MT 4'
				echo '.TL'
				echo '$(name) package'
				echo '.H 1'
				echo '$($(name).README)'
			} |
			$(MM2HTML) $(MM2HTMLFLAGS) -o nohtml.ident > $(PACKAGEGEN)/$(name).html
			if	[[ '$(source.$(name))' ]]
			then	{
					echo '$($(name).README)'
					package help source
				} > $(PACKAGEGEN)/$(name).README
				cp $(source.$(name)) $(source)
				$(SUM) -x $(checksum) < $(source) > $(source:D:B:S=.$(checksum))
			fi
			echo local > $(source:D:B=$(name):S=.tim)
		fi
	fi

binary : .binary.init .binary.gen .binary.$$(style)

.binary.init : .MAKE
	local A B D I P V
	type := binary
	if ! "$(incremental)"
		incremental = 0
	end
	if ! "$(~$(name))"
		if name == "ratz"
			suffix = exe
		else
			suffix = gz
		end
	end
	: $(.init.$(style)) :
	: $(details.$(style):V:R) :
	A := $(binary.list)
	B := $(A:N=*.$(stamp).$(CC.HOSTTYPE).$(suffix):N!=*.$(stamp).$(stamp).*:O=1:T=F)
	P := $(A:N=*.$(stamp).$(CC.HOSTTYPE).$(suffix):N!=*.$(stamp).$(stamp).*:O=2:T=F)
	D := $(A:N=*.$(stamp).$(stamp).$(CC.HOSTTYPE).$(suffix):O=1:T=F)
	if op == "delta"
		if ! B
			error 3 delta requires a base archive
		end
		base := -z $(B)
		if "$(release)" != "$(stamp)"
			release := $("":T=R%Y-%m-%d)
		end
		binary := $(B:/$(CC.HOSTTYPE).$(suffix)$/$(release).&/)
		version := $(binary:B:B:/$(name).//)
	elif B || op == "base"
		if op == "base"
			for I $(B) $(P)
				V := $(I:B:/$(name)\.\([^.]*\).*/\1/)
				if V == "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]" && V != "$(version)"
					old.version := $(V)
					old.binary := $(I)
					if "$(old.version)" >= "$(version)"
						error 3 $(name): previous base $(old.version) is newer than $(version)
					end
					break
				end
			end
		else
			binary := $(B)
		end
		if B == "$(binary)"
			if "$(B:D:B)" == "$(D:D:B)" && "$(B:S)" != "$(D:S)"
				error 3 $(B:B:S): base overwrite would invalidate delta $(D:B:S)
			end
			error 1 $(B:B:S): replacing current base
		end
		version := $(binary:B:/$(name).//:/\..*//)
	end
	PACKAGEGEN := $(PACKAGEBIN)/gen

.binary.gen : $$(PACKAGEDIR) $$(PACKAGEGEN)

.binary.exp .binary.pkg .binary.rpm : .MAKE
	error 3 $(style): binary package style not supported yet

.binary.cyg :
	if	[[ '$(~$(name))' ]]
	then	tmp=/tmp/pkg$(tmp)
		mkdir $tmp
		{
			integer m=0 o
			{
				echo '$($(name.original).README)' | fmt
				cat <<'!'
	$(readme.$(style):@?$$("\n")$$(readme.$$(style))??)
	!
			} > $tmp/README1
			echo ";;;$tmp/README1;usr/share/doc/Cygwin/$(opt:/.$//).README"
			{
				echo '$($(name.original).README)' | fmt
				cat <<'!'
	$()
	The remainder of this file is the README from the source package
	that was used to generate this binary package. It describes
	the source build hierarchy, not the current directory.
	$()
	$(package.readme)
	!
			} > $tmp/README2
			echo ";;;$tmp/README2;usr/share/doc/$(opt)README"
			package release $(name.original) > $tmp/RELEASE
			echo ";;;$tmp/RELEASE;usr/share/doc/$(opt)RELEASE"
			cat > $(binary:/.$(suffix)//).setup.hint <<'!'
	category: $(category:/\(.\).*/\1/U)$(category:/.\(.*\)/\1/L)
	requires: cygwin
	sdesc: "$(index)"
	ldesc: "$($(name.original).README)"
	!
			set -- $(.package.licenses. --text $(name.original):N!=*.lic)
			for i
			do	echo ";;;${i};usr/share/doc/$(opt)LICENSE-${i##*/}"
			done
			cat <<'!'
	$(filter.$(style))
	!
			if	[[ '$(postinstall.$(style):V:O=1:?1??)' ]]
			then	cat >$tmp/postinstall <<'!'
	$("#")!/bin/sh
	$(postinstall.$(style))
	!
				echo ";;;$tmp/postinstall;etc/postinstall/$(name).sh"
			fi
		} |
		{
			: > $tmp/HEAD
			[[ '$(notice)' ]] && echo ";;;$tmp/HEAD;$(package.notice)"
			sort -t';' -k5,5 -u
			: > $tmp/TAIL
			[[ '$(notice)' ]] && echo ";;;$tmp/TAIL;$(package.notice)"
		} |
		$(PAX)	--filter=- \
			--to=ascii \
			--format=$(format) \
			--local \
			-wvf $(binary)
		$(SUM) -x $(checksum) < $(binary) > $(binary:D:B:S=.$(checksum))
		rm -rf $tmp
	fi

.binary.lcl :
	if	[[ '$(~$(name))' ]]
	then	tmp=/tmp/pkg$(tmp)
		mkdir $tmp
		{
			$(package.src:U:T=F:/.*/echo ";;;&"$("\n")/)
			$(package.bin:U:T=F:/.*/echo ";;;&"$("\n")/)
			set -- $(package.closure)
			for i
			do	cd $(INSTALLROOT)/$i
				$(MAKE) --noexec $(-) --variants=$(variants:Q) $(=) recurse list.package.$(type) package.license.class=$(license:Q) cc-
			done
		} |
		$(PAX)	--filter=- \
			--to=ascii \
			$(op:N=delta:??--format=$(format)?) \
			--local \
			--checksum=md5:$(PACKAGEGEN)/$(name).sum \
			--install=$(PACKAGEGEN)/$(name).ins \
			-wvf $(binary) $(base) \
			$(op:N=delta:?--format=gzip??) \
			-s",^$tmp/,$(INSTALLOFFSET)/," \
			$(PACKAGEROOT:C%.*%-s",^&/,,"%)
		$(SUM) -x $(checksum) < $(binary) > $(binary:D:B:S=.$(checksum))
		echo local > $(binary:D:B=$(name):S=.$(CC.HOSTTYPE).tim)
		rm -rf $tmp
	fi

.binary.tgz :
	if	[[ '$(~$(name))' ]]
	then	tmp=/tmp/pkg$(tmp)
		mkdir $tmp
		{
			if	[[ '$(init)' == '$(name)' ]]
			then	for i in lib32 lib64
				do	if	[[ -d $(INSTALLROOT)/$i ]]
					then	echo ";physical;;$(INSTALLROOT)/$i"
					fi
				done
			fi
			$(package.src:U:T=F:C%^$(PACKAGEROOT)/%%:C%.*%echo ";;;$(PACKAGEROOT)/&;&"$("\n")%)
			$(package.bin:U:T=F:C%^$(INSTALLROOT)/%%:C%.*%echo ";;;$(INSTALLROOT)/&;&"$("\n")%)
			$(package.auxiliary.$(style):U:T=F:C%^$(INSTALLROOT)/%%:C%.*%echo ";;;$(INSTALLROOT)/&;&"$("\n")%)
			if	[[ '$(PACKAGEDIR:B)' == '$(style)' ]]
			then	echo $(name) $(version) $(release|version) 1 > $(PACKAGEGEN)/$(name).ver
				echo ";;;$(PACKAGEGEN)/$(name).ver;$(PACKAGELIB)/$(name).ver"
				if	[[ '$(~covers)' ]]
				then	for i in $(~covers)
					do	for j in lic pkg
						do	if	[[ -f $(PACKAGESRC)/$i.$j ]]
							then	echo ";;;$(PACKAGESRC)/$i.$j;$(PACKAGELIB)/$i.$j"
							fi
						done
						for j in ver req
						do	if	[[ -f $(PACKAGEGEN)/$i.$j ]]
							then	echo ";;;$(PACKAGEGEN)/$i.$j;$(PACKAGELIB)/$i.$j"
							fi
						done
					done
					for i in $(~covers:D=$(PACKAGESRC):B:S=.lic:T=F:T=I:N=*.def:D=$(PACKAGESRC):B:S:T=F:B:S)
					do	echo ";;;$(PACKAGESRC)/$i;$(PACKAGELIB)/$i"
					done
				fi
				sed 's,1$,0,' $(~req:D=$(PACKAGEGEN):B:S=.ver:T=F) < /dev/null > $(PACKAGEGEN)/$(name).req
				echo ";;;$(PACKAGEGEN)/$(name).req;$(PACKAGELIB)/$(name).req"
				{
					echo "name='$(name)'"
					echo "index='$(index)'"
					echo "covers='$(~covers)'"
					echo "requires='$(~req)'"
				} > $(PACKAGEGEN)/$(name).inx
				{
					{
					echo '$($(name).README)'
					if	[[ '$(~covers)' ]]
					then	echo "This package is a superset of the following package$(~covers:O=2:?s??): $(~covers); you won't need $(~covers:O=2:?these?this?) if you download $(name)."
					fi
					if	[[ '$(~requires)' ]]
					then	echo 'It requires the following package$(~requires:O=2:?s??): $(~requires).'
					fi
					} | fmt
					package help binary
					package release $(name)
				} > $(PACKAGEGEN)/$(name).README
				echo ";;;$(PACKAGEGEN)/$(name).README;$(PACKAGELIB)/$(name).README"
			fi
			set -- $(package.closure)
			for i
			do	cd $(INSTALLROOT)/$i
				$(MAKE) --noexec $(-) --variants=$(variants:Q) $(=) package.strip=$(strip) recurse list.package.$(type) package.license.class=$(license:Q) cc-
			done
		} |
		{
			: > $tmp/HEAD
			[[ '$(notice)' ]] && echo ";;;$tmp/HEAD;$(package.notice)"
			cat > $tmp/README <<'!'
	$(package.readme)
	!
			echo ";;;$tmp/README;README"
			sort -t';' -k5,5 -u
			: > $tmp/TAIL
			[[ '$(notice)' ]] && echo ";;;$tmp/TAIL;$(package.notice)"
		} |
		$(PAX)	--filter=- \
			--to=ascii \
			$(op:N=delta:??--format=$(format)?) \
			--local \
			--checksum=md5:$(PACKAGEGEN)/$(name).sum \
			--install=$(PACKAGEGEN)/$(name).ins \
			-wvf $(binary) $(base) \
			$(op:N=delta:?--format=gzip??) \
			-s",^$tmp/,$(INSTALLOFFSET)/," \
			$(PACKAGEROOT:C%.*%-s",^&/,,"%)
		echo $(binary) >> $(binary:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
		$(SUM) -x $(checksum) < $(binary) > $(binary:D:B:S=.$(checksum))
		echo $(binary:D:B:S=.$(checksum)) >> $(binary:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
		echo local > $(binary:D:B=$(name):S=.$(CC.HOSTTYPE).tim)
		if	[[ '$(incremental)' == 1 && '$(old.binary)' ]]
		then	$(PAX) -rf $(binary) -wvf $(old.new.binary) -z $(old.binary)
			echo $(old.new.binary) >> $(binary:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
			$(SUM) -x $(checksum) < $(old.new.binary) > $(old.new.binary:D:B:S=.$(checksum))
			echo $(old.new.binary:D:B:S=.$(checksum)) >> $(binary:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
		fi
		rm -rf $tmp
	else	if	[[ '$(binary.$(name))' ]]
		then	exe=$(binary.$(name))
		else	exe=$(INSTALLROOT)/bin/$(name)
		fi
		if	[[ '$(old.binary)' ]] && $(CMP) $(CMPFLAGS) $exe $(binary)
		then	: $(name) is up to date
		else	echo $(name) $(version) $(release|version) 1 > $(PACKAGEGEN)/$(name).ver
			: > $(PACKAGEGEN)/$(name).req
			{
				echo "name='$(name)'"
				echo "index='$(index)'"
				echo "covers='$(~covers)'"
				echo "requires='$(~req)'"
			} > $(PACKAGEGEN)/$(name).inx
			{
				echo '$($(name).README)'
				package help binary
			} > $(PACKAGEGEN)/$(name).README
			case "$(binary)" in
			*.gz)	gzip < $exe > $(binary) ;;
			*)	cp $exe $(binary) ;;
			esac
			$(SUM) -x $(checksum) < $(binary) > $(binary:D:B:S=.$(checksum))
			echo local > $(binary:D:B=$(name):S=.$(CC.HOSTTYPE).tim)
		fi
		echo $(binary) >> $(binary:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
		echo $(binary:D:B:S=.$(checksum)) >> $(binary:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
	fi

runtime : .runtime.init .runtime.gen .runtime.$$(style)

.runtime.init : .MAKE
	local A B D I P V
	type := runtime
	if ! "$(incremental)"
		incremental = 0
	end
	if ! "$(~$(name))"
		if name == "ratz"
			suffix = exe
		else
			suffix = gz
		end
	end
	: $(.init.$(style)) :
	: $(details.$(style):V:R) :
	A := $(runtime.list)
	B := $(A:N=*.$(stamp).$(CC.HOSTTYPE).$(suffix):N!=*.$(stamp).$(stamp).*:O=1:T=F)
	P := $(A:N=*.$(stamp).$(CC.HOSTTYPE).$(suffix):N!=*.$(stamp).$(stamp).*:O=2:T=F)
	D := $(A:N=*.$(stamp).$(stamp).$(CC.HOSTTYPE).$(suffix):O=1:T=F)
	if op == "delta"
		if ! B
			error 3 delta requires a base archive
		end
		base := -z $(B)
		if "$(release)" != "$(stamp)"
			release := $("":T=R%Y-%m-%d)
		end
		runtime := $(B:/$(CC.HOSTTYPE).$(suffix)$/$(release).&/)
		version := $(runtime:B:B:/$(name).//)
	elif B || op == "base"
		if op == "base"
			for I $(B) $(P)
				V := $(I:B:/$(name)-run\.\([^.]*\).*/\1/)
				if V == "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]" && V != "$(version)"
					old.version := $(V)
					old.runtime := $(I)
					if "$(old.version)" >= "$(version)"
						error 3 $(name): previous base $(old.version) is newer than $(version)
					end
					break
				end
			end
		else
			runtime := $(B)
		end
		if B == "$(runtime)"
			if "$(B:D:B)" == "$(D:D:B)" && "$(B:S)" != "$(D:S)"
				error 3 $(B:B:S): base overwrite would invalidate delta $(D:B:S)
			end
			error 1 $(B:B:S): replacing current base
		end
		version := $(runtime:B:/$(name)-run.//:/\..*//)
	end
	PACKAGEGEN := $(PACKAGESRC)/gen

.runtime.gen : $$(PACKAGEDIR) $$(PACKAGEGEN)

.runtime.cyg .runtime.exp .runtime.lcl .runtime.pkg .runtime.rpm : .MAKE
	error 3 $(style): runtime package style not supported yet

.runtime.tgz :
	if	[[ '$(~$(name))' ]]
	then	tmp=/tmp/pkg$(tmp)
		mkdir $tmp
		{
			if	[[ '$(init)' == '$(name)' ]]
			then	for i in lib32 lib64
				do	if	[[ -d $(INSTALLROOT)/$i ]]
					then	echo ";physical;;$(INSTALLROOT)/$i"
					fi
				done
			fi
			$(package.src:U:T=F:C%^$(PACKAGEROOT)/%%:C%.*%echo ";;;$(PACKAGEROOT)/&;&"$("\n")%)
			$(package.bin:U:T=F:C%^$(INSTALLROOT)/%%:C%.*%echo ";;;$(INSTALLROOT)/&;&"$("\n")%)
			$(package.auxiliary.$(style):U:T=F:C%^$(INSTALLROOT)/%%:C%.*%echo ";;;$(INSTALLROOT)/&;&"$("\n")%)
			echo $(name) $(version) $(release|version) 1 > $(PACKAGEGEN)/$(name).ver
			echo ";;;$(PACKAGEGEN)/$(name).ver;$(PACKAGELIB)/$(name).ver"
			if	[[ '$(~covers)' ]]
			then	for i in $(~covers)
				do	for j in lic pkg
					do	if	[[ -f $(PACKAGESRC)/$i.$j ]]
						then	echo ";;;$(PACKAGESRC)/$i.$j;$(PACKAGELIB)/$i.$j"
						fi
					done
					for j in ver req
					do	if	[[ -f $(PACKAGEGEN)/$i.$j ]]
						then	echo ";;;$(PACKAGEGEN)/$i.$j;$(PACKAGELIB)/$i.$j"
						fi
					done
				done
				for i in $(~covers:D=$(PACKAGESRC):B:S=.lic:T=F:T=I:N=*.def:D=$(PACKAGESRC):B:S:T=F:B:S)
				do	echo ";;;$(PACKAGESRC)/$i;$(PACKAGELIB)/$i"
				done
			fi
			sed 's,1$,0,' $(~req:D=$(PACKAGEGEN):B:S=.ver:T=F) < /dev/null > $(PACKAGEGEN)/$(name).req
			echo ";;;$(PACKAGEGEN)/$(name).req;$(PACKAGELIB)/$(name).req"
			{
				echo "name='$(name)'"
				echo "index='$(index)'"
				echo "covers='$(~covers)'"
				echo "requires='$(~req)'"
			} > $(PACKAGEGEN)/$(name).inx
			{
				{
				echo '$($(name).README)'
				if	[[ '$(~covers)' ]]
				then	echo
					echo "This package is a superset of the following package$(~covers:O=2:?s??): $(~covers); you won't need $(~covers:O=2:?these?this?) if you download $(name)."
				fi
				if	[[ '$(~requires)' ]]
				then	echo
					echo 'It requires the following package$(~requires:O=2:?s??): $(~requires).'
				fi
				echo
				echo "To install this $(type) package read the tarball into a directory"
				echo "suitable for containing bin and lib subdirectories, and run the"
				echo "$(PACKAGELIB)/gen/$(name)-run.ins script to fix up permissions."
				echo
				echo "To use the package export the bin directory in PATH. The commands and"
				echo "libraries use \$PATH to locate dynamic libraries and related data files."
				echo
				} | fmt
			} > $(PACKAGEGEN)/$(name)-run.README
			echo ";;;$(PACKAGEGEN)/$(name)-run.README;$(PACKAGELIB)/$(name)-run.README"
			set -- $(package.closure)
			for i
			do	cd $(INSTALLROOT)/$i
				$(MAKE) --noexec $(-) --variants=$(variants:Q) $(=) package.strip=$(strip) recurse list.package.$(type) package.license.class=$(license:Q) cc-
			done
		} |
		{
			: > $tmp/HEAD
			[[ '$(notice)' ]] && echo ";;;$tmp/HEAD;$(package.notice)"
			cat > $tmp/README <<'!'
	$(package.readme)
	!
			echo ";;;$tmp/README;README"
			sort -t';' -k5,5 -u
			: > $tmp/TAIL
			[[ '$(notice)' ]] && echo ";;;$tmp/TAIL;$(package.notice)"
		} |
		$(PAX)	--filter=- \
			--to=ascii \
			$(op:N=delta:??--format=$(format)?) \
			--local \
			--checksum=md5:$(PACKAGEGEN)/$(name)-run.sum \
			--install=$(PACKAGEGEN)/$(name)-run.ins \
			-wvf $(runtime) $(base) \
			$(op:N=delta:?--format=gzip??) \
			-s",^$tmp/,$(INSTALLOFFSET)/," \
			$(PACKAGEROOT:C%.*%-s",^&/,,"%)
		echo $(runtime) >> $(runtime:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
		$(SUM) -x $(checksum) < $(runtime) > $(runtime:D:B:S=.$(checksum))
		echo $(runtime:D:B:S=.$(checksum)) >> $(runtime:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
		echo local > $(runtime:D:B=$(name)-run:S=.$(CC.HOSTTYPE).tim)
		if	[[ '$(incremental)' == 1 && '$(old.runtime)' ]]
		then	$(PAX) -rf $(runtime) -wvf $(old.new.runtime) -z $(old.runtime)
			echo $(old.new.runtime) >> $(runtime:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
			$(SUM) -x $(checksum) < $(old.new.runtime) > $(old.new.runtime:D:B:S=.$(checksum))
			echo $(old.new.runtime:D:B:S=.$(checksum)) >> $(runtime:D:B=PACKAGE:S=.$(CC.HOSTTYPE).lst)
		fi
		rm -rf $tmp
	fi

list.installed list.manifest :
	set -- $(package.closure)
	for i
	do	cd $(INSTALLROOT)/$i
		ignore $(MAKE) --noexec $(-) $(=) $(<)
	done
