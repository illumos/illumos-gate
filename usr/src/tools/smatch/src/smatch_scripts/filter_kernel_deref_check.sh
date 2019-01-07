#!/bin/bash

file=$1
if [[ "$file" = "" ]] ; then
    echo "Usage:  $0 <file with smatch messages>"
    exit 1
fi

IFS="
"

for line in $(grep 'dereferenced before' $file) ; do

    code_file=$(echo "$line" | cut -d ':' -f1)
    lineno=$(echo "$line" | cut -d ' ' -f1 | cut -d ':' -f2)
    function=$(echo "$line" | cut -d ' ' -f2)
    variable=$(echo "$line" | cut -d "'" -f3)
    source_line=$(tail -n +$lineno $code_file | head -n 1 | sed -e 's/^\W*//')

    if echo "$source_line" | grep -q rcu_assign_pointer ; then
	continue
    fi
    if echo "$source_line" | grep -q '^\W*tda_' ; then
	continue
    fi
    if echo "$source_line" | grep -q tda_fail ; then
	continue
    fi
    if echo "$source_line" | grep -q '^\W*ATH5K_' ; then
	continue
    fi
    if echo "$source_line" | grep -qw CMDINFO ; then
	continue
    fi
    if echo "$source_line" | grep -qw dump_desc_dbg ; then
	continue
    fi
    if echo "$source_line" | grep -qw CAMERA_IS_OPERATIONAL ; then
	continue
    fi
    if echo "$source_line" | grep -qw USBVISION_IS_OPERATIONAL ; then
	continue
    fi
    if echo "$source_line" | grep -qw DEV_INIT_TEST_WITH_RETURN ; then
	continue
    fi
    if echo "$source_line" | grep -qw TW_PRINTK ; then
	continue
    fi
    if echo "$source_line" | grep -qw RESET_ONE_SEC_TX_CNT ; then
	continue
    fi
    if echo "$source_line" | grep -qw SOCK_DEBUG; then
	continue
    fi
    if echo "$source_line" | grep -qw P80211SKB_RXMETA ; then
	continue
    fi
    if echo "$source_line" | grep -qw ACM_READY ; then
	continue
    fi
    if echo "$source_line" | grep -qw v4l2_subdev_notify ; then
	continue
    fi
    if echo "$source_line" | egrep -qw 'tuner_(err|info)' ; then
	continue
    fi
    if echo "$source_line" | grep -qw DBG_SKB ; then
	continue
    fi
    if echo "$source_line" | grep -qw for_each_mddev ; then
	continue
    fi
    if echo "$source_line" | grep -qw v4l2_subdev_call ; then
	continue
    fi
    if echo "$source_line" | grep -qw VALID_CALLBACK ; then
	continue
    fi
    if [ "$variable" == "bp->dev" ] && echo "$source_line" | grep -qw DP ; then
	continue
    fi
    if echo "$source_line" | grep -qw BNX2X_ERR ; then
	continue
    fi
    if echo "$source_line" | grep -qw FCOE_NETDEV_DBG ; then
	continue
    fi
    if echo "$source_line" | grep -qw __rq_for_each_bio ; then
	continue
    fi
    if echo "$source_line" | grep -qw IPS_DMA_DIR ; then
	continue
    fi
    if [ "$variable" == "dev" ] && echo "$source_line" | grep -qw dprintk ; then
	continue
    fi

    echo "$code_file:$lineno $function '$variable': $source_line"
done

