#!/usr/bin/ksh93

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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# termclock - a simple analog clock for terminals
#

# Solaris needs /usr/xpg6/bin:/usr/xpg4/bin because the tools in /usr/bin are not POSIX-conformant
export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/bin:/usr/bin

# Make sure all math stuff runs in the "C" locale to avoid problems
# with alternative # radix point representations (e.g. ',' instead of
# '.' in de_DE.*-locales). This needs to be set _before_ any
# floating-point constants are defined in this script).
if [[ "${LC_ALL}" != "" ]] ; then
    export \
        LC_MONETARY="${LC_ALL}" \
        LC_MESSAGES="${LC_ALL}" \
        LC_COLLATE="${LC_ALL}" \
        LC_CTYPE="${LC_ALL}"
        unset LC_ALL
fi
export LC_NUMERIC=C

function fatal_error
{
	print -u2 "${progname}: $*"
	exit 1
}

# cache tput values (to avoid |fork()|'ing a "tput" child every second)
function tput_cup
{
	# static variable as cache for "tput_cup"
	typeset -S -A tput_cup_cache

	integer y="$1" x="$2"
	nameref c="tput_cup_cache[\"${y}_${x}\"]"
    
	if [[ "$c" == "" ]] ; then
		# fast path for known terminal types
		if [[ ${TERM} == ~(Elr)(vt100|vt220|xterm|xterm-color|dtterm) ]] ; then
			c="${ printf "\E[%d;%dH" y+1 x+1 ; }"
		else
			c="${ tput cup $y $x ; }"
		fi
	fi
    
	print -r -n -- "$c"
	return 0
}

# Get terminal size and put values into a compound variable with the integer
# members "columns" and "lines"
function get_term_size
{
	nameref rect=$1
    
	rect.columns=${ tput cols ; } || return 1
	rect.lines=${ tput lines ; }  || return 1
    
	return 0
}

function draw_clock
{
	float angle a
	float x y
	integer i=1

	for(( angle=0.0 ; angle < 360. ; angle+=6 )) ; do
		((
			a=angle/360.*(2*M_PI) ,

			x=clock.len_x*cos(a) ,
			y=clock.len_y*sin(a)
		))

		tput_cup $(( y+clock.middle_y )) $(( x+clock.middle_x ))
	
		# add "mark" every 30 degrees
		if (( int(angle)%30 == 0 )) ; then
			print -r -n "$(((++i)%12+1))"
		else
			print -r -n "x"
		fi
	done
	return 0
}

function draw_hand
{
	float   angle="$1" a
	typeset ch="$2"
	float   length="$3"
	float   x y
    
	(( a=angle/360.*(2*M_PI) ))

	for (( s=0.0 ; s < 10. ; s+=0.5 )) ; do
		((
			x=(clock.len_x*(s/10.)*(length/100.))*cos(a) ,
			y=(clock.len_y*(s/10.)*(length/100.))*sin(a)
		))

		tput_cup $(( y+clock.middle_y )) $(( x+clock.middle_x ))
		print -r -n -- "${ch}"
	done
	return 0
}

function draw_clock_hand
{
	nameref hand=$1
	draw_hand $(( 360.*(hand.val/hand.scale)-90. )) "${hand.ch}" ${hand.length}
	return 0
}

function clear_clock_hand
{
	nameref hand=$1
	draw_hand $(( 360.*(hand.val/hand.scale)-90. )) " " ${hand.length}
	return 0
}

function main_loop
{
	typeset c
	
	# note: we can't use subshells when writing to the double-buffer file because this
	# will render the tput value cache useless
	while true ; do
		if ${init_screen} ; then
			init_screen="false"

			get_term_size termsize || fatal_error $"Couldn't get terminal size."

			((
				clock.middle_x=termsize.columns/2.-.5 ,
				clock.middle_y=termsize.lines/2.-.5 ,
				clock.len_x=termsize.columns/2-2 ,
				clock.len_y=termsize.lines/2-2 ,
			))

			{
				clear
				draw_clock
			} >&6
		fi

		{
			(( ${ date +"hours.val=%H , minutes.val=%M , seconds.val=%S" ; } ))

			# small trick to get a smooth "analog" flair
			((
				hours.val+=minutes.val/60. ,
				minutes.val+=seconds.val/60.
			))

			draw_clock_hand seconds
			draw_clock_hand minutes
			draw_clock_hand hours
	    
			# move cursor to home position
			tput_cup 0 0
		} >&6

		6<#((0))
		cat <&6

		redirect 6<&- ;  rm -f "${scratchfile}" ; redirect 6<> "${scratchfile}"

		c="" ; read -r -t ${update_interval} -N 1 c
		if [[ "$c" != "" ]] ; then
			case "$c" in
				~(Fi)q | $'\E') return 0 ;;
			esac
		fi

		{
			clear_clock_hand hours
			clear_clock_hand minutes
			clear_clock_hand seconds
		} >&6
	done
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${termclock_usage}" OPT '-?'
	exit 2
}

# program start
builtin basename
builtin cat
builtin date
builtin mktemp
builtin rm

typeset progname="${ basename "${0}" ; }"

float -r M_PI=3.14159265358979323846

# terminal size rect
compound termsize=(
	integer columns=-1
	integer lines=-1
)

typeset init_screen="true"

compound clock=(
	float   middle_x
	float   middle_y
	integer len_x
	integer len_y
)


# set clock properties
compound seconds=(
	float val
	typeset ch
	float   scale
	integer length )
compound minutes=(
	float val
	typeset ch
	float   scale
	integer length )
compound hours=(
	float val
	typeset ch
	float   scale
	integer length )

seconds.length=90 seconds.scale=60 seconds.ch=$"s"
minutes.length=75 minutes.scale=60 minutes.ch=$"m"
hours.length=50   hours.scale=12   hours.ch=$"h"

float update_interval=0.9

typeset -r termclock_usage=$'+
[-?\n@(#)\$Id: termclock (Roland Mainz) 2009-12-02 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[-author?David Korn <dgk@research.att.com>]
[+NAME?termclock - analog clock for terminals]
[+DESCRIPTION?\btermclock\b is an analog clock for terminals.
        The termclock program displays the time in analog or digital
        form. The time is continuously updated at a frequency which
        may be specified by the user.]
[u:update?Update interval (defaults to 0.9 seconds).]:[interval]
[+SEE ALSO?\bksh93\b(1), \bxclock\b(1)]
'

while getopts -a "${progname}" "${termclock_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		u)    update_interval=${OPTARG} ;;
		*)    usage ;;
	esac
done
shift $((OPTIND-1))

# prechecks
which tput >/dev/null   || fatal_error $"tput not found."
(( update_interval >= 0. && update_interval <= 7200. )) || fatal_error $"invalid update_interval value."

# create temporary file for double-buffering and register an EXIT trap
# to remove this file when the shell interpreter exits
scratchfile="${ mktemp -t "termclock.ppid${PPID}_pid$$.XXXXXX" ; }"
[[ "${scratchfile}" != "" ]] || fatal_error $"Could not create temporary file name."
trap 'rm -f "${scratchfile}"' EXIT
rm -f "${scratchfile}" ; redirect 6<> "${scratchfile}" || fatal_error $"Could not create temporary file."

# register trap to handle window size changes
trap 'init_screen="true"' WINCH

main_loop

# exiting - put cursor below clock
tput_cup $((termsize.lines-2)) 0

exit 0
# EOF.
