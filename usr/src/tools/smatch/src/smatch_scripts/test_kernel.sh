#!/bin/bash

NR_CPU=$(cat /proc/cpuinfo | grep ^processor | wc -l)
TARGET="bzImage modules"
WLOG="smatch_warns.txt"
LOG="smatch_compile.warns"
function usage {
    echo
    echo "Usage:  $0 [smatch options]"
    echo "Compiles the kernel with -j${NR_CPU}"
    echo " available options:"
    echo "	--endian          : enable endianess check"
    echo "	--target {TARGET} : specify build target, default: $TARGET"
    echo "	--log {FILE}      : Output compile log to file, default is: $LOG"
    echo "	--wlog {FILE}     : Output warnigs to file, default is: $WLOG"
    echo "	--help            : Show this usage"
    exit 1
}


while true ; do
    if [[ "$1" == "--endian" ]] ; then
	ENDIAN="CF=-D__CHECK_ENDIAN__"
	shift
    elif [[ "$1" == "--target" ]] ; then
	shift
	TARGET="$1"
	shift
    elif [[ "$1" == "--log" ]] ; then
	shift
	LOG="$1"
	shift
    elif [[ "$1" == "--wlog" ]] ; then
	shift
	WLOG="$1"
	shift
    elif [[ "$1" == "--help" ]] ; then
	usage
    else
	    break
    fi
done

# receive parameters from environment, which override
[ -z "${SMATCH_ENV_TARGET:-}" ] || TARGET="$SMATCH_ENV_TARGET"
[ -z "${SMATCH_ENV_BUILD_PARAM:-}" ] || BUILD_PARAM="$SMATCH_ENV_BUILD_PARAM"

SCRIPT_DIR=$(dirname $0)
if [ -e $SCRIPT_DIR/../smatch ] ; then
    cp $SCRIPT_DIR/../smatch $SCRIPT_DIR/../bak.smatch
    CMD=$SCRIPT_DIR/../bak.smatch
elif which smatch | grep smatch > /dev/null ; then
    CMD=smatch
else
    echo "Smatch binary not found."
    exit 1
fi

make clean
find -name \*.c.smatch -exec rm \{\} \;
make -j${NR_CPU} $ENDIAN -k CHECK="$CMD -p=kernel --file-output --succeed $*" \
	C=1 $BUILD_PARAM $TARGET 2>&1 | tee $LOG
BUILD_STATUS=${PIPESTATUS[0]}
find -name \*.c.smatch -exec cat \{\} \; -exec rm \{\} \; > $WLOG
find -name \*.c.smatch.sql -exec cat \{\} \; -exec rm \{\} \; > $WLOG.sql
find -name \*.c.smatch.caller_info -exec cat \{\} \; -exec rm \{\} \; > $WLOG.caller_info

echo "Done. Build with status $BUILD_STATUS. The warnings are saved to $WLOG"
exit $BUILD_STATUS
