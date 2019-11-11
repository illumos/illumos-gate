#!/bin/bash

print_help()
{
    echo "usage: $0 <warning file>"
    exit 1;
}

set_title()
{
    echo -ne "\033]0;$*\007"
    echo ========================================
    echo $*
    echo ----------------------------------------
}

cmd_help()
{
    echo "n - skips to next message"
    echo "f - skips to next file"
    echo "? - print this message again"
}

save_thoughts()
{
    echo "************"
    echo $sm_err
    echo -n "What do you think?:  "
    read ans
    if echo $ans | grep ^$ > /dev/null ; then
        return
    fi 

    #store the result
    echo $sm_err       >> summary
    echo $ans       >> summary
    echo ========== >> summary
}

if [ "$1" = "--new" ] ; then
    shift
    NEW=Y
fi

file=$1
if [ "$file" = "" ] ; then
    if [ -e err-list ] ; then
	file="err-list"
    else
	print_help
    fi
fi

TXT=$(cat $file | uniq -f 2)

IFS='
'
for sm_err in $TXT ; do
    file=$(echo $sm_err | cut -d ':' -f 1)
    line=$(echo $sm_err | cut -d ' ' -f 1 | cut -d ':' -f 2)

    if [ "$file" = "$skip_file" ] ; then
	continue
    fi
    skip_file=""

    last=$(echo $sm_err | cut -d ' ' -f 2-)
    last=$(echo $last | sed -e 's/line .*//')

    if [ "$NEW" = "Y" ] ; then
	if grep -F "$last" *summary* > /dev/null ; then
	    echo "skipping $sm_err"
	    continue
	fi
    fi

    set_title $sm_err

    #grep -A1 "$file $line" *summary* 2> /dev/null 
    grep -A1 -F "$last" *summary* 2> /dev/null

    ans="?"
    while echo $ans | grep '?' > /dev/null ; do
	echo -n "[? for help]: "
	read ans
	if echo $ans | grep n > /dev/null ; then
	    continue 2
	fi
	if echo $ans | grep f > /dev/null ; then
	    skip_file=$file
	    continue 2
	fi
	if echo $ans | grep '?' > /dev/null ; then
	    cmd_help
	fi
    done

    # I have this in my .vimrc
    # map <C-j> :! echo $sm_err<CR>
    export sm_err

    vim $file +${line}

    save_thoughts
done	
IFS=
