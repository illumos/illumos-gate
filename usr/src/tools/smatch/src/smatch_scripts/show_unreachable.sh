#!/bin/bash

context=6
while true ; do
    if [ "$1" = "-C" ] ; then
        shift
        context=$1
        shift
        continue
    fi
    if [ "$1" = "-k" ] ; then
        shift
        mode=kernel
        continue
    fi
    if [ "$1" = "-b" ] ; then
        shift
        nobreak=yes
        continue
    fi
    break
done


file=$1
if [[ "$file" = "" ]] ; then
    echo "Usage:  $0 [-C <lines>] [-b] [-k] <file with smatch messages>"
    echo "  -C <lines>:  Print <lines> of context"
    echo "  -b        :  Ignore unreachable break statements"
    echo "  -k        :  Ignore some kernel defines"
    exit 1
fi

kernel_ignore_functions="DLM_ASSERT
BT_SI_SM_RETURN
BT_STATE_CHANGE
PARSE_ERROR1
PARSE_ERROR
CMDINSIZE
PROCESS_SYSTEM_PARAM
RETURN_STATUS
ar9170_regwrite_result
module_put_and_exit
SEG32
CASE_PIPExTRE
"

grep 'ignoring unreachable' $file | cut -d ' ' -f1 | while read loc; do
    code_file=$(echo $loc | cut -d ':' -f 1)
    line=$(echo $loc | cut -d ':' -f 2)

    if [ "$mode" = "kernel" ] ; then
        # BUG() is sometimes defined away on embedded systems
        if tail -n +$(($line - 1)) $code_file | head -n 1 | \
            egrep -qw '(BUG|BT_STATE_CHANGE)' ; then
            continue;
        fi
        skip=0
        line_txt=$(tail -n +$(($line)) $code_file | head -n 1)
        for func in $kernel_ignore_functions ; do
            if echo "$line_txt" | egrep -qw $func ; then
                skip=1
                break
            fi
        done
        if [ "$skip" == 1 ] ; then
            continue
        fi
    fi

    if [ "$nobreak" = "yes" ] ; then
        if tail -n +$(($line)) $code_file | head -n 1 | grep -qw 'break' ; then
            continue;
        fi

    fi
    echo "========================================================="
    echo $code_file:$line
    tail -n +$(($line - ($context - 1))) $code_file | head -n $(($context - 1))
    echo "---------------------------------------------------------"
    tail -n +${line} $code_file | head -n $context
done

