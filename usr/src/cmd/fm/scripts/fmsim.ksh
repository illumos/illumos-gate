#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

export PATH=/usr/bin:/usr/sbin:/usr/ccs/bin
unset ENV TMPDIR
umask 022
cwd=$PWD

isa=$(uname -p)
if [[ $isa = sparc ]]; then
	isa64=sparcv9
elif [[ $isa = i386 ]]; then
	isa64=amd64
else
	isa64=unknown
fi

if [[ -n "$CODEMGR_WS" ]]; then
	sysroot=$CODEMGR_WS/proto/root_$isa
elif [[ -n "$ROOT" ]]; then
	sysroot=$ROOT
else
	sysroot=/
fi

quote=
eol='\'
files=

simchan=com.sun:fm:fmd$$
simroot=/tmp/fmd.$$
simscript=run
simpid=

truss_cmd=
truss_args=
dump_args=
inj_args=
fmd_args=

opt_h=false
opt_i=false
opt_s=false
opt_w=false
opt_x=false

function cp_so
{
	nm -ghp $1 2>/dev/null | while read addr type name; do
		[[ $type != T ]] && continue
		case $name in
		_fmd_init)        cp $1 $2/usr/lib/fm/fmd/plugins; return ;;
		fmd_fmri_nvl2str) cp $1 $2/usr/lib/fm/fmd/schemes; return ;;
		topo_load)        cp $1 $2/usr/lib/fm/topo/plugins; return ;;
		esac
	done
	die "\nunknown .so type -- $1"
}

function cp_topo
{
	mkdir -p $2/usr/lib/fm/topo/maps
	cp $1 $2/usr/lib/fm/topo/maps; 
	for platdir in $2/usr/platform/*/lib/fm/topo/maps; do
		rm -f $platdir/* 2>/dev/null
	done
}

function list_cmds
{
	for cmd in fmadm fmdump fmstat; do
		echo usr/sbin/$cmd
	done
}

function wait_status
{
	if [[ $1 -gt 128 ]]; then
		sig=$(kill -l $(($1 - 128)))
		die "fmd terminated from signal $sig (see $simroot)"
	elif [[ $1 -ne 0 ]]; then
		die "fmd terminated with status $1 (see $simroot)"
	fi
}

function wait_prompt
{
	echo "fmsim: [ Press return to $* ] \c"
	mode=$(stty -g)
	stty -echo -isig min 1 time 0
	read s; echo
	stty $mode
}

function die
{
	echo "fmsim: $*" >& 2
	$opt_w && wait_prompt exit
	[[ -n "$simpid" ]] && exit 1 || exit 2
}

while [[ $# -gt 0 ]]; do
	OPTIND=1; while getopts ':d:D:ehio:st:vVwx' c; do
		case "$c" in
		d)
			simroot=$OPTARG
			;;
		D)
			truss_cmd=dtrace
			truss_args="-s $OPTARG -c"
			quote="'"; eol=""
			;;
		e|v|V)
			dump_args="$dump_args -$c"
			;;
		h|i|s|w|x)
			eval opt_$c'='true
			;;
		o)
			fmd_args="$fmd_args -o $OPTARG"
			;;
		t)
			truss_cmd=truss
			truss_args="$OPTARG"
			;;
		:)
			die "option requires an argument -- $OPTARG"
			;;
		*)
			die "illegal option -- $OPTARG"
			;;
		esac
	done
	let OPTIND="$OPTIND - 1"; shift $OPTIND

	if [[ $# -gt 0 ]]; then
		if [[ -d $1 ]]; then
			files="$files $1/*"
		else
			files="$files $1"
		fi
		shift
	fi
done

for file in $files; do
	[[ -r $file ]] || die "input file is missing or not readable -- $file"
done

if $opt_h || [[ -z "$files" && $opt_i = false ]]; then
	echo "Usage: fmsim [-ehisvVwx] [-d dir] [-D a.d] [-o opt=val]" \
	    "[-t args] [file ...]"

	echo "\t-d  set the simulation root directory to the given location"
	echo "\t-D  start fmd(8) using dtrace(8) and specified D script"
	echo "\t-e  display error log content instead of fault log content"
	echo "\t-h  display usage information for fmsim and exit"
	echo "\t-i  set interactive mode: do not stop after sending events"
	echo "\t-o  set fmd(8) option to specified value during simulation"
	echo "\t-s  set up simulation world but do not actually run simulation"
	echo "\t-t  start fmd(8) using truss(1) and specified arguments"
	echo "\t-v  set verbose mode: display additional event detail"
	echo "\t-V  set very verbose mode: display complete event contents"
	echo "\t-w  wait for a keypress after simulation completes"
	echo "\t-x  delete simulation world if simulation is successful"

	exit 0
fi

echo "fmsim: creating simulation world $simroot ... \c"
[[ -d $simroot ]] || mkdir -p $simroot || exit 1
cd $simroot || exit 1
echo "done."

echo "fmsim: populating /var ... \c"
mkdir -p -m 0755 var/fm/fmd
mkdir -p -m 0700 var/fm/fmd/ckpt
mkdir -p -m 0700 var/fm/fmd/rsrc
mkdir -p -m 0700 var/fm/fmd/xprt
echo "done."

echo "fmsim: populating /usr/lib/fm from $sysroot ... \c"
(cd $sysroot && find usr/lib/fm -depth -print | cpio -pdmu $simroot)

for platdir in $sysroot/usr/platform/*/lib/fm; do
	[[ -d $platdir ]] && platdir=${platdir#$sysroot} || continue
	echo "fmsim: populating $platdir from $sysroot ... \c"
	(cd $sysroot && find ${platdir#/} -depth -print | cpio -pdmu $simroot)
done

echo "fmsim: populating /usr/lib/locale/$LANG from $sysroot ... \c"
(cd $sysroot && find usr/lib/locale/$LANG -depth -print | cpio -pdmu $simroot)

echo "fmsim: populating /usr/sbin from $sysroot ... \c"
(cd $sysroot && list_cmds | cpio -pdmu $simroot)

echo "fmsim: adding customizations:\c"
cd $cwd || exit $1

for file in $files; do
	base=$(basename $file)
	case $base in
	*.cmd)	die "\neversholt command file not yet supported -- $file" ;;
	fmd.conf) cp $file $simroot/etc/fm/fmd ;;
	*.conf)	cp $file $simroot/usr/lib/fm/fmd/plugins ;;
	*.dict)	cp $file $simroot/usr/lib/fm/dict ;;
	*.eft) cp $file $simroot/usr/lib/fm/eft ;;
	*.esc)	die "\neversholt source file not yet supported -- $file" ;;
	*.inj)	inj_args="$inj_args $file" ;;
	*.log)	inj_args="$inj_args $file" ;;
	*log)	inj_args="$inj_args $file" ;;
	*.mo)	cp $file $simroot/usr/lib/locale/$LANG/LC_MESSAGES ;;
	*.so)	cp_so $file $simroot ;;
	*.topo) die "\n .topo files not supported -- $file" ;;
	*.xml) cp_topo $file $simroot ;;
	*)	die "\nunknown file type or suffix -- $file" ;;
	esac
	echo " $base\c"
done

cd $simroot || exit 1
echo " done."

echo "fmsim: generating script ... \c"
cat >$simscript <<EOS
#!/bin/ksh -p
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"@(#)fmsim.ksh	1.5	06/10/11 SMI"

#
# fmsim(8) script generated for $simroot $(date)
#

export LD_LIBRARY_PATH=$simroot/usr/lib:$simroot/usr/lib/fm
export LD_LIBRARY_PATH_64=$simroot/usr/lib/64:$simroot/usr/lib/fm/$isa64

export _THREAD_ERROR_DETECTION=2

exec $truss_cmd $truss_args $quote./usr/lib/fm/fmd/fmd -R $simroot $eol
    -o fg=true -o clock=simulated $eol
    -o rpc.adm.prog=0 -o rpc.adm.path=$simroot/rpc $eol
    -o sysevent-transport:device=/dev/null $eol
    -o sysevent-transport:channel=$simchan $fmd_args$quote

EOS

chmod 0555 $simscript
echo "done."

if $opt_s; then
	echo "fmsim: simulation is saved in $simroot"
	exit 0
fi

export LD_LIBRARY_PATH=$simroot/usr/lib:$simroot/usr/lib/fm
export LD_LIBRARY_PATH_64=$simroot/usr/lib/64:$simroot/usr/lib/fm/$isa64

echo "fmsim: simulation $$ running fmd(8)\c"
./usr/lib/fm/fmd/fmd -V | cut -d: -f2

./$simscript &
simpid=$!
trap '' INT HUP
cd $cwd
i=0

while [[ ! -s $simroot/rpc ]]; do
	[[ $i -ge 30 ]] && kill -9 $simpid >/dev/null 2>&1
	kill -0 $simpid >/dev/null 2>&1 || break
	let i="$i + 1"
	sleep 1
done

kill -0 $simpid >/dev/null 2>&1 || {
	wait $simpid
	wait_status $?
}

echo "fmsim: rpc adm requests can rendezvous at" $(<$simroot/rpc)
echo "fmsim: injectors should use channel $simchan"
echo "fmsim: debuggers should attach to PID $simpid"

for arg in $inj_args; do
	echo "fmsim: injecting events from $arg ... \c"
	$simroot/usr/lib/fm/fmd/fminject -q -c $simchan $arg || {
		echo "fmsim: fminject failed for $arg: aborting simulation" >& 2
		kill $simpid >/dev/null 2>&1
	}
	echo "done."
done

if [[ $opt_i = false ]]; then
	echo "fmsim: injecting event to advance to end-of-time ... \c"
	echo 'endhrtime;' | $simroot/usr/lib/fm/fmd/fminject -q -c $simchan -
	echo "done."
fi

wait $simpid
status=$?

if [[ -f $simroot/var/fm/fmd/errlog ]]; then
	echo; $simroot/usr/sbin/fmdump -R $simroot $dump_args; echo
fi

wait_status $status
$opt_w && wait_prompt exit
$opt_x && rm -rf $simroot

exit 0
