#! /usr/bin/csh -f
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 1980 Regents of the University of California.
# All rights reserved.  The Berkeley Software License Agreement
# specifies the terms and conditions for redistribution.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#       which : tells you which program you get
#
# Set prompt so .cshrc will think we're interactive and set aliases.
# Save and restore path to prevent .cshrc from messing it up.
set _which_saved_path_ = ( $path )
set prompt = ""
if ( -r ~/.cshrc && -f ~/.cshrc ) source ~/.cshrc
set path = ( $_which_saved_path_ )
unset prompt _which_saved_path_
set noglob
set exit_status = 0
foreach arg ( $argv )
    set alius = `alias $arg`
    switch ( $#alius )
        case 0 :
            breaksw
        case 1 :
            set arg = $alius[1]
            breaksw
        default :
            echo ${arg}: "      " aliased to $alius
            continue
    endsw
    unset found
    if ( "$arg:h" != "$arg:t" ) then		# head != tail, don't search
        if ( -e $arg ) then			# just do simple lookup
            echo $arg
        else
            echo $arg not found
	    set exit_status = 1
        endif
        continue
    else
        foreach i ( $path )
            if ( -x $i/$arg && ! -d $i/$arg ) then
                echo $i/$arg
                set found
                break
            endif
        end
    endif
    if ( ! $?found ) then
        echo no $arg in $path
	set exit_status = 1
    endif
end

exit ${exit_status}

