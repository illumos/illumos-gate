#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright (c) 2014, Joyent, Inc.
#

if [ "$PS1" ]; then
    mt_tty=$(/usr/bin/tty 2>/dev/null)
    if [[ $mt_tty =~ ^/dev/term/[abcd] ]]; then
        # If we're on the serial console, we generally won't know how
        # big our terminal is.  Attempt to ask it using control sequences
        # and resize our pty accordingly.
        mt_output=$(/usr/lib/measure_terminal 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            eval "$mt_output"
        else
            # We could not read the size, but we should set a 'sane'
            # default as the dimensions of the previous user's terminal
            # persist on the tty device.
            export LINES=25
            export COLUMNS=80
        fi
        /usr/bin/stty rows ${LINES} columns ${COLUMNS} 2>/dev/null
    fi
    unset mt_output mt_tty
    shopt -s checkwinsize
    if [[ -f /.dcinfo ]]; then
        . /.dcinfo
        DC_NAME="${SDC_DATACENTER_NAME}"
    fi
    if [[ -n "${DC_NAME}" ]]; then
       PS1="[\u@\h (${DC_NAME}) \w]\\$ "
    else
       PS1="[\u@\h \w]\\$ "
    fi
    alias ll='ls -lF'
    alias ls='ls --color=auto'
    [ -n "${SSH_CLIENT}" ] && export PROMPT_COMMAND='echo -ne "\033]0;${HOSTNAME} \007" && history -a'
fi

# Load bash completion
[ -f /etc/bash/bash_completion ] && . /etc/bash/bash_completion

svclog() {
  if [[ -z "$PAGER" ]]; then
    PAGER=less
  fi
  $PAGER `svcs -L $1`
}

svclogf() {
  /usr/bin/tail -f `svcs -L $1`
}
