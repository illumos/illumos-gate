# -*-Shell-script-*-
#
# hal-functions.sh:	This file contains functions to be used by most or all
#                       hal shell scripts
# hal-system-lcd-get-brightness.sh
#
# Licensed under the Academic Free License version 2.1
#

hal_check_priv() {
    if [ "$HAVE_POLKIT" = "1" -a -n $HAL_METHOD_INVOKED_BY_SYSTEMBUS_CONNECTION_NAME ]; then
        ACTION=$1
        PK_RESULT=`hal-is-caller-privileged --udi $UDI --action $ACTION \
            --caller $HAL_METHOD_INVOKED_BY_SYSTEMBUS_CONNECTION_NAME`
        RET=$?
        if [ "$RET" != "0" ]; then
            echo "org.freedesktop.Hal.Device.Error" >&2
            echo "Cannot determine if caller is privileged" >&2
            exit 1
        fi
        if [ "$PK_RESULT" != "yes" ] ;then
            echo "org.freedesktop.Hal.Device.PermissionDeniedByPolicy" >&2
            echo "$ACTION $PK_RESULT <-- (action, result)" >&2
            exit 1
        fi
    fi
}

hal_call_backend() {
    PROGRAM=`basename $0`
    if [ -n "$HALD_UNAME_S" -a -x ./$HALD_UNAME_S/$PROGRAM-$HALD_UNAME_S ]; then
        ./$HALD_UNAME_S/$PROGRAM-$HALD_UNAME_S $@
    else
        echo "org.freedesktop.Hal.Device.UnknownError" >&2
        echo "No back-end for your operating system" >&2
        exit 1
    fi
}

hal_exec_backend() {
    PROGRAM=`basename $0`
    if [ -n "$HALD_UNAME_S" -a -x ./$HALD_UNAME_S/$PROGRAM-$HALD_UNAME_S ]; then
        exec ./$HALD_UNAME_S/$PROGRAM-$HALD_UNAME_S $@
    else
        echo "org.freedesktop.Hal.Device.UnknownError" >&2
        echo "No back-end for your operating system" >&2
        exit 1
    fi
}
