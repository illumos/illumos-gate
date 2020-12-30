/*
 * initialization for all packages
 */

ID = ast
SILENT = /* this component builds silent -- this prevents us from using it while building it */

:PACKAGE: license=$(ID)

LICENSE = since=1994,author=gsf

PACKAGEROOT = $(INSTALLROOT:T=F:P=L*:O=n)

hurl :: hurl.sh LICENSE=since=2003,author=gsf

iffe :: iffe.sh LICENSE=since=1994,author=gsf+kpv

mktest :: mktest.sh LICENSE=since=2005,author=gsf

package :: package.sh

regress :: regress.sh LICENSE=since=1995,author=gsf

rt :: rt.sh LICENSE=since=2005,author=gsf

$(PACKAGEROOT)/bin :INSTALLDIR: execrate ignore mamprobe package silent

crossexec :: crossexec.sh

ditto :: ditto.sh LICENSE=since=2001,author=gsf+ek

execrate :: execrate.sh LICENSE=since=2002,author=gsf

filter :: filter.sh

ignore :: ignore.sh

silent :: silent.sh

$(PACKAGEROOT)/lib/package :INSTALLDIR: package.mk CONVERT.mk

$(LIBDIR)/make :INSTALLDIR: package.mk PROBE.mk TEST.mk WWW.mk \
	MSGFUN.mk MSGKEY.mk MAPLIB.mk

:TEST: iffe mamake

cc ld ldd :PACKAGE_INIT: mamake.c proto.c ratz.c release.c

:: RELEASE hosttype.tst p.c hello.c \
	ar.ibm.risc \
	cc.specialize cc.pentium4 \
	ldd.cygwin.i386 \
	cc.darwin.i386 cc.darwin.i386-64 cc.darwin ldd.darwin \
	cc.hp.ia64 cc.hp.pa cc.hp.pa64 ld.hp.pa ldd.hp.pa \
	cc.ibm.risc cc.ibm.risc.gcc ldd.ibm.risc \
	cc.linux.ia64-icc cc.linux.i386-icc cc.linux.i386-64-icc \
	cc.lynxos.i386 cc.lynxos.ppc ldd.lynxos \
	cc.mvs.390 cc.next.i386 cc.next.m68k ldd.mvs.390 \
	cc.osf.alpha \
	cc.sco.i386 \
	cc.sgi.mips2 cc.sgi.mips3 cc.sgi.mips3-o32 cc.sgi.mips4 \
	cc.sgi.mips4-n32 ldd.sgi \
	cc.unix.mc68k

LICENSE : .DONTCARE

if ! CC.HOSTTYPE
	CC.HOSTTYPE := $(_hosttype_|HOSTTYPE)
end

$(BINDIR)/mkdir :INSTALL: mkdir.sh
	if	test ! -x $(<) -a -x /bin/mkdir
	then	mkdir -p 2>/dev/null || :
		if	test -d ./-p
		then	rmdir ./-p
			cp $(*) $(<)
			chmod +x $(<)
		fi
	fi

/*
 * ksh93 function search on PATH
 * ksh93 builtin command library -lcmd
 * ksh93 ld library path search on PATH
 */

$(BINDIR)/.paths :INSTALL: (CC.DIALECT)
	if	test ! -f $(<) -o -w $(<)
	then	N='$("\n")'
		H=$(CC.HOSTTYPE)
		P="$(-mam:??$(.GETCONF LIBPATH:/:/ /G:/,/ : /G:Q)?)"
		b= f= h= l= n= p= u= B= L=
		set : $P
		while	:
		do	while	:
			do	case $1 in
				'')	break 2 ;;
				:)	shift; break ;;
				esac
				shift
			done
			case $# in
			0|1)	break ;;
			esac
			case $L in
			?*)	L="$L|" ;;
			esac
			L="$L$2=*"
			B=$1
		done
		if	test -f $(<)
		then	while	read x
			do	case $x in
				*\$\(\"*)	break # to fix 2012-06-18 edit botch #
						;;
				'#'?*)		case $h in
						'')	h=$x ;;
						esac
						;;
				$L)		l=$x
						;;
				*BUILTIN_LIB=*)	b=$x
						;;
				*FPATH=*)	f=$x
						;;
				*PLUGIN_LIB=*)	p=$x
						;;
				*)		case $u in
						?*)	u=$u$N ;;
						esac
						u=$u$x
						;;
				esac
			done < $(<)
		fi
		ifs=$IFS
		m=
		case $p in
		?*)	b=
			;;
		esac
		case $b in
		?*)	IFS='='
			set $b
			IFS=$ifs
			shift
			p="PLUGIN_LIB=$*"
			case $b in
			[Nn][Oo]*)	p=no$p ;;
			esac
			m=1
			;;
		esac
		case $f in
		'')	f="FPATH=../fun"
			m=1
			;;
		esac
		case $h in
		'')	h='# use { no NO } prefix to permanently disable #' ;;
		esac
		case $l in
		'')	set x x : $P
			l=
			while	:
			do	while	:
				do	case $# in
					0)	break ;;
					esac
					x=$1
					shift
					case $x in
					:)	break ;;
					esac
				done
				case $# in
				0|1)	break
					;;
				2)	l=$2
					;;
				*)	case "$H" in
					$3)	l=$2; break ;;
					esac
					;;
				esac
			done
			case $l in
			'')	if	test -x /lib/dld.sl
				then	l=SHLIB_PATH
				elif	test -x /usr/lib/dyld
				then	l=DYLD_LIBRARY_PATH
				else	case "$H" in
					ibm.*|mvs.*)
						l=LIBPATH
						;;
					sgi.mips3)	
						l=LD_LIBRARYN32_PATH
						;;
					sgi.mips4)	
						l=LD_LIBRARYN64_PATH
						;;
					*)	l=LD_LIBRARY_PATH
						;;
					esac
				fi
				;;
			esac
			case $l in
			?*)	case $B in
				'')	B=lib ;;
				esac
				l="$l=../$B"
				m=1
				;;
			esac
			;;
		esac
		case $p in
		'')	p="PLUGIN_LIB=cmd"
			case '$(CC.DIALECT:N=*EXPORT=[AD]LL*)' in
			'')	p=no$p ;;
			esac
			m=1
			;;
		esac
		case $m in
		1)	case $u in
			?*)	u=$N$u ;;
			esac
			echo "$h$N$p$N$f$N$l$u" > $(<)
			;;
		esac
	fi

/*
 * probe initialization
 */

for T C+probe C+make+probe.lcl C+pp+probe.lcl
	if T == "*.lcl"
		$(T) : .DONTCARE
	end
	$(LIBDIR)/probe/$(T:C,+,/,G) :INSTALL: $(T)
end

$(LIBDIR)/probe/C/mam/probe :INSTALL: mprobe

mprobe :: mprobe.sh

$(LIBDIR)/probe/C/make :INSTALLDIR: probe probe.ini

probe.sh : C+probe make.probe
	cat $(*) > $(<)

probe :: probe.sh

probe.ini : (CC.HOSTTYPE) probe.win32
	t=$(CC.HOSTTYPE)
	ifs=$IFS
	IFS=.
	set x $t
	IFS=$ifs
	t=$2
	set x $(*)
	while	:
	do	shift
		case $# in
		0)	break ;;
		esac
		case $1 in
		*probe.$t)
			break
		esac
	done
	case $1 in
	?*)	cmp -s $1 $(<) || cp $1 $(<) ;;
	*)	: > $(<)
	esac

/*
 * proto initialization
 */

$(INCLUDEDIR)/$(ID) :INSTALLDIR: prototyped.h

prototyped.h : $(BINDIR)/proto
	proto -f /dev/null > h.$(tmp).h
	if	$(CMP) -s h.$(tmp).h $(<)
	then	$(RM) -f h.$(tmp).h
	else	$(MV) h.$(tmp).h $(<)
	fi

/*
 * check if -ldl is required
 * this allows makefiles to use -ldl on all systems
 *
 * NOTE: this works around the sgi botch:
 *	 (1) irix 5.* made -ldl optional but warned
 *	 (2) irix 6.* has no -ldl
 *	 (3) dynamic progs built on irix 5.* and using -ldl fail
 *           at runtime on irix 6.* because -ldl is not there
 */

dl :MAPLIB: dl.c

/*
 * requiring these is a botch
 */

iconv :MAPLIB: iconv.c

w :MAPLIB: w.c w2.c

/*
 * miscellaneous -l* checks
 */

intl :MAPLIB: intl.c

m :MAPLIB: m.c m2.c m3.c m4.c m5.c m6.c

nsl :MAPLIB: nsl.c

/*
 * what was sco smoking
 * almost all of gethost* are in -lnsl except gethostbyname which
 * is in -lsocket which isn't needed to resolve socket() but seems
 * to do the -lnsl job
 */

socket :MAPLIB: socket.c nsl.c

/*
 * more substance abuse
 * gdbm's ndbm "compatibility" doesn't supply <ndbm.h>, instead supplies
 * <gdbm/ndbm.h> which provides K&R prototypes *and* it requires -lgdbm
 * some <ndbm.h> implementations use -lndbm, others -ldbm, still others -lc
 * this is why unix is starting to look like windows
 * this map allows makefiles to use -ldbm on all systems
 *
 * and this just in: sometimes its <gdbm-ndbm.h> and possibly -lgdbm_compat
 *
 * at least the -l* buck stops here
 */

dbm db - gdbm_compat - gdbm - ndbm - dbm :MAPLIB: db.c gdbm.c gdbm1.c gdbm2.c
