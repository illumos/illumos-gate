#!/bin/bash -e

usage()
{
    echo "usage:  $0 <patch file>"
    exit 1
}

if [ "$1" = "" ] ; then
    usage
fi

if [ "$1" = "--compile" ] ; then
    compile=true
    shift
fi

SCRIPT_DIR=$(dirname $0)
if [ -e $SCRIPT_DIR/kchecker ] ; then
    KCHECKER=$SCRIPT_DIR/kchecker
    STRIP=$SCRIPT_DIR/strip_whitespace.pl
elif which kchecker | grep kchecker > /dev/null ; then
    KCHECKER=kchecker
    STRIP=strip_whitespace.pl
else
    echo "$SCRIPT_DIR"
    echo "kchecker script not found."
    exit 1
fi

PATCH=$1

files=$(grep ^+++ $PATCH | cut -f 1 | cut -b 5-)
if [ "$files" = "" ] ; then
    usage
fi

if ! cat $PATCH | patch -p1 --dry-run > /dev/null ; then
    echo "Couldn't apply patch"
    exit 1
fi

before=$(mktemp /tmp/before.XXXXXXXXXX)
after=$(mktemp /tmp/after.XXXXXXXXXX)
tmpfile=$(mktemp)

for file in $files ; do
    file=${file#*/}

    $STRIP $file > $before
    if [ "$compile" = "true" ] ; then
	if ! $KCHECKER --test-parsing --outfile=$before $file ; then
		echo "warning: compile failed."
	fi
	mv $before $tmpfile
	$STRIP $file > $before
	cat $tmpfile >> $before
    fi
    cat $PATCH | patch -p1
    $STRIP $file > $after
    if [ "$compile" = "true" ] ; then
	if ! $KCHECKER --test-parsing --outfile=$after $file ; then
		echo "warning: compile failed.  *again*"
	fi
	mv $after $tmpfile
	$STRIP $file > $after
	cat $tmpfile >> $after
    fi
    cat $PATCH | patch -p1 -R

    if [ ! -s $before ] ; then
	echo "Error:  No result"
	exit 1
    fi

    if diff $before $after > /dev/null ; then
	echo
	echo Only white space changed
	echo
    else
	echo '!!#$%@$%@^@#$^@#%@$%@$%@#%$@#%!!'
	echo '!!                            !!'
	echo '!!  This patch changes stuff  !!'
	echo '!!                            !!'
	echo '!!#$%@$%@^@#$^@#%@$%@$%@#%$@#%!!'

	diff -u $before $after 
    fi
    rm -f $before $after $tmpfile
done

