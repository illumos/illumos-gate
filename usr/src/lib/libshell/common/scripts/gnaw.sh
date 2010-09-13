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
# gnaw - a simple ksh93 technology demo
#
# Note that this script has been written with the main idea to show
# many of ksh93's new features (comparing to ksh88/bash) and not
# as an example of efficient&&clean script code (much of the code
# could be done more efficient using compound variables, this script
# focus is the usage of associative arrays).
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

function print_setcursorpos
{
    print -n -- "${vtcode[cup_${1}_${2}]}"
}

function beep
{
    ${quiet} || print -n -- "${vtcode["bel"]}"
}

function fatal_error
{
    print -u2 "${progname}: $*"
    exit 1
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

function print_levelmap
{
    integer screen_y_offset=$1
    integer start_y_pos=$2 # start at this line in the map
    integer max_numlines=$3 # maximum lines we're allowed to render
    integer x
    integer y
    typeset line=""

    print_setcursorpos 0 ${screen_y_offset}

    for (( y=start_y_pos; (y-start_y_pos) < max_numlines && y < levelmap["max_y"] ; y++ )) ; do
        line=""
        for (( x=0 ; x < levelmap["max_x"] ; x++ )) ; do
            line+="${levelmap["${x}_${y}"]}"
        done

        print -- "${line} "
    done
    
    # print lines filled with spaces for each line not filled
    # by the level map
    line="${vtcode["spaceline"]:0:${levelmap["max_x"]}}"
    for (( ; (y-start_y_pos) < max_numlines ; y++ )) ; do
        print -- "${line} "
    done
    return 0
}

function level_completed
{
    integer i
    typeset dummy
    typeset render_buffer="$(
    print -n -- "${vtcode["clear"]}"
    cat <<ENDOFTEXT

 #       ######  #    #  ######  #
 #       #       #    #  #       #
 #       #####   #    #  #####   #
 #       #       #    #  #       #
 #       #        #  #   #       #
 ######  ######    ##    ######  ######

             (Good job)

     #####    ####   #    #  ######
     #    #  #    #  ##   #  #
     #    #  #    #  # #  #  #####
     #    #  #    #  #  # #  #
     #    #  #    #  #   ##  #
     #####    ####   #    #  ######


ENDOFTEXT

    printf "    SCORE: --> %s <--\n" "${player["score"]}"
    printf "    LIVES: --> %s <--\n" "${player["lives"]}"
    )"
    print -- "${render_buffer}${end_of_frame}"

    # wait five seconds and swallow any user input
    for (( i=0 ; i < 50 ; i++ )) ; do
        read -r -t 0.1 -n 1 dummy
    done

    print "Press any key to continue...${end_of_frame}"
    # wait five secs or for a key
    read -r -t 5 -n 1 dummy
    return 0
}

function game_over
{
    typeset dummy
    typeset render_buffer="$(
    print -n -- "${vtcode["clear"]}"
    cat <<ENDOFTEXT

  ####     ##    #    #  ######
 #    #   #  #   ##  ##  #
 #       #    #  # ## #  #####
 #  ###  ######  #    #  #
 #    #  #    #  #    #  #
  ####   #    #  #    #  ######

            (LOSER!)

  ####   #    #  ######  #####
 #    #  #    #  #       #    #
 #    #  #    #  #####   #    #
 #    #  #    #  #       #####
 #    #   #  #   #       #   #
  ####     ##    ######  #    #

ENDOFTEXT

    printf "\n    SCORE: --> %s <--\n" "${player["score"]}"
    )"
    print -r -- "${render_buffer}${end_of_frame}"

    # wait five seconds and swallow any user input
    for (( i=0 ; i < 50 ; i++ )) ; do
        read -r -t 0.1 -n 1 dummy
    done

    print "Press any key to continue...${end_of_frame}"
    # wait five secs or for a key
    read -r -t 5 -n 1 dummy
    return 0
}

function run_logo
{
    typeset render_buffer="$(
    cat <<ENDOFTEXT

 #####  #     #    #    #     #   ###
#     # ##    #   # #   #  #  #   ###
#       # #   #  #   #  #  #  #   ###
#  #### #  #  # #     # #  #  #    #
#     # #   # # ####### #  #  #
#     # #    ## #     # #  #  #   ###
 #####  #     # #     #  ## ##    ###
ENDOFTEXT
    )"
    print -- "${vtcode["clear"]}${render_buffer}"
    
    # wait two seconds and swallow any user input
    for (( i=0 ; i < 20 ; i++ )) ; do
        read -r -t 0.1 -n 1 dummy
    done

    print "\n   (The KornShell 93 maze game)"
    
    attract_mode
    return 0
}

function attract_mode
{
(
    # Now present some info, line-by-line in an endless loop
    # until the user presses a key (we turn the "magic" return
    # code for that)
    integer -r magic_return_code=69
    typeset line
    IFS='' ; # Make sure we do not swallow whitespaces

    while true ; do
        (
            redirect 5<&0
        
        (cat <<ENDOFTEXT





         ################
     ########################
   ############################
  #######     ######     #######
  ######     ######     ########
  #######     ######     #######
  ##############################
  ##############################
  ##############################
  ##############################
  ##############################
  #########  ########  #########
  #  ####      ####      ####  #






           Written by

          Roland Mainz
    (roland.mainz@nrubsig.org)






           ##############         
      ########################    
   #################**############
  ################################
 ############################     
 ######################           
 ################                 
 ######################           
 ############################     
  ################################
   ############################## 
      ########################    
           ##############    







             High scores:
  
        * 'chin'      8200 pt
        * 'gisburn'   7900 pt
        * 'tpenta'    5520 pt
        * 'kupfer'    5510 pt
        * 'noname'    5000 pt
        * 'noname'    4000 pt
        * 'livad'     3120 pt
        * 'noname'    3000 pt
        * 'noname'    2000 pt
        * 'noname'    1000 pt
  
ENDOFTEXT

        # clear screen, line-by-line
        for (( i=0 ; i < termsize.lines ; i++ )) ; do print "" ; done
        ) | (while read -r line ; do
                read -r -t 0.3 -n 1 c <&5
                [[ "$c" != "" ]] && exit ${magic_return_code}
                print -- "${line}"
            done)
        (( $? == magic_return_code )) && exit ${magic_return_code}
        )
        (( $? == magic_return_code )) && return 0
        
        sleep 2
    done
)
}

function run_menu
{
    integer numlevels=0
    integer selected_level=0
    typeset l
         
    # built list of available levels based on the "function levelmap_.*"
    # built into this script
    typeset -f | egrep "^function.*levelmap_.*" | sed 's/^function //' |
    while read -r l ; do
        levellist[numlevels]="$l"
        numlevels+=1
    done
       
    # swallow any queued user input (e.g. drain stdin)
    read -r -t 0.1 -n 100 dummy
    
    while true ; do
        # menu loop with timeout (which switches to "attract mode")
        while true ; do
            print -n -- "${vtcode["clear"]}"

    cat <<ENDOFTEXT
>======================================\   
>  /-\     .--.                        |
> | OO|   / _.-' .-.   .-.  .-.   .-.  |
> |   |   \  '-. '-'   '-'  '-'   '-'  |
> ^^^^^    '--'                        |
>======\       /================\  .-. |
>      |       |                |  '-' |
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
ENDOFTEXT
            print "    GNAW - the ksh93 maze game"
            print "\n\tMenu:"

            print "\t - [L]evels:"
            for (( i=0 ; i < numlevels ; i++ )) ; do
                printf "\t    %s %s \n" "$( (( i == selected_level )) && print -n "*" || print -n " ")" "${levellist[i]##levelmap_}"
            done

            print  "\t - Rendering options:"
            printf "\t    [%s] Use [U]nicode\n" "$( (( game_use_unicode == 1 )) && print -n "x" || print -n "_" )"
            printf "\t    [%s] Use [C]olors\n"  "$( (( game_use_colors  == 1 )) && print -n "x" || print -n "_" )"

            print "\t - [S]tart - [Q]uit"

            # wait 30 secs (before we switch to "attract mode")
            c="" ; read -r -t 30 -n 1 c
            case "$c" in
                'l') (( selected_level=(selected_level+numlevels+1) % numlevels )) ;;
                'L') (( selected_level=(selected_level+numlevels-1) % numlevels )) ;;
                ~(Fi)s)
                    (( game_use_colors == 1 )) && print -- "${vtcode["bg_black"]}"
                    case "${game_use_colors}${game_use_unicode}" in
                        "00") main_loop "${levellist[selected_level]}" ;;
                        "01") main_loop "${levellist[selected_level]}" | map_filter 0 1 ;;
                        "10") main_loop "${levellist[selected_level]}" | map_filter 1 0 ;;
                        "11") main_loop "${levellist[selected_level]}" | map_filter 1 1 ;;
                    esac
                    print -- "${vtcode["vtreset"]}"
                    ;;
                ~(Fi)q | $'\E')
                    # make sure we do not exit on a cursor key (e.g. <esc>[A,B,C,D)
                    read -r -t 0.01 -n 1 c
                    if [[ "$c" == "[" ]] ; then
                        # this was a cursor key sequence, just eat the 3rd charcater
                        read -r -t 0.01 -n 1 c
                    else
                        exit 0
                    fi
                    ;;           
                ~(Fi)u) (( game_use_unicode=(game_use_unicode+2+1) % 2)) ;;
                ~(Fi)c) (( game_use_colors=(game_use_colors+2+1) % 2))   ;;
                "") break ;; # timeout, switch to attract mode
                *) beep ;;
            esac
        done
        
        print -n -- "${vtcode["clear"]}"
        attract_mode
    done
    return 0
}

function levelmap_stripes
{
cat <<ENDOFLEVEL
###################################
#.......    ...............    P  #
#########..#################..### #
#########..#################..### #
#.......    ..    ..............# #
###############  ################ #
###############  ################ #
#............. M  ..............# #
##..#####################  ###### #
##..#####################  ###### #
#.......  ...........    .......# #
########  ############  ######### #
#   ####  ############  ######### #
# #..................     ......# #
# ############################### # 
#                                 #
###################################
ENDOFLEVEL
    return 0
}

function levelmap_livad
{
cat <<ENDOFLEVEL
#####################################################
#                                                   #
# ##############  ###############  ################ #
# #............       P             ..............# #
#  .#############################################.# #
# #.#..........                     ............#.  #
# #.#.##########  ###############  ############.#.# #
# #...#........                     ..........#...# #
# #...#.#####################################.#.#.# #
# #...#.#......                     ........#...#.# #
# #.#.#...######  #########################.#.#.#.# #
#  .#.....#....          M          ......#...#.#.# #
# #.#.#...#######################  ########.#.#.#.# #
# #...#.#......                     ........#...#.# #
# #...#.########  ###############  ##########.#.#.# #
# #...#........                     ..........#...# #
# #.#.#########################################.#.# #
# #.#..........                     ............#.  #
#  .############  ###############  ##############.# #
# #............                     ..............# #
# ################################################# #
#                                                   #
#####################################################
ENDOFLEVEL
    return 0
}

function levelmap_classic1
{
cat <<ENDOFLEVEL
#########################
#.P.........#...........#
#.####.####.#.####.####.#
#.#  #.#  #.#.#  #.#  #.#
#.#  #.#  #.#.#  #.#  #.#
#.####.####.#.####.####.#
#.......................#
#.####.#.#######.#.####.#
#.#  #.#.#     #.#.#  #.#
#.####.#.#######.#.####.#
#......#....#....#......#
######.####.#.####.######
###### #         # ######
###### # ##   ## # ######
###### # #     # # ######
#        #  M  #        #
###### # ####### # ######
###### #         # ######
###### # ####### # ######
###### # #     # # ######
######.#.#######.#.######
#...........#...........#
#.###.###...#...###.###.#
#...#...............#...#
###.#....#######....#.###
# #.#..#.#     #.#..#.# #
###....#.#######.#....###
#......#....#....#......#
#.#########.#.#########.#
#.......................#
#########################
ENDOFLEVEL
    return 0
}

function levelmap_classic2
{
cat <<ENDOFLEVEL
#######################
#.P...#.........#.....#
#.###.#.#######.#.###.#
#.....................#
###.#.####.#.####.#.###
###.#......#......#.###
###.###.#######.###.###
###.................###
###.###.### ###.###.###
###.#...#M    #...#.###
###.#.#.#######.#.#.###
#.....#.........#.....#
###.#####..#..#####.###
###........#........###
###.###.#######.###.###
#.....................#
#.###.####.#.####.###.#
#.###.#....#....#.###.#
#.###.#.#######.#.###.#
#.....................#
#######################
ENDOFLEVEL
    return 0
}

function levelmap_easy
{
cat <<ENDOFLEVEL
##################
# .............. #
# . ######       #
# . #  M #       #
# . #    #       #
# . ### ##       #
# .   #          #
# .   ###        #
# .              #
# ..........     #
# .......... P   #
##################
ENDOFLEVEL
    return 0
}

function levelmap_sunsolaristext
{
cat <<ENDOFLEVEL
################################################
# .####   .    #  #....#                       #
# #       #    #  #....#                       #
#  ####   #    #  #.#..#          M            #
#      #  #    #  #..#.#                       #
# #    #  #    #  #...##                       #
#  ####    ####   #....#                       #
#                                              #
#  ####    ####  #       ##    #####  #  ####  #
# #       #.  .# #      #  #   #....# # #      #
#  ####   #    # #      # P #  #....# #  ####  #
#      #  #    ###      #.#### #.###  #      # #
# #   .#  #.  ..        #    # #...#  # #    # #
#  ####    ####  ###### .    #  ....# #  ####. #
################################################
ENDOFLEVEL
    return 0
}

function read_levelmap
{
    typeset map="$( $1 )"

    integer y=0
    integer x=0
    integer maxx=0
    integer numdots=0
    typeset line
    typeset c
    
    while read -r line ; do
        for (( x=0 ; x < ${#line} ; x++ )) ; do
            c="${line:x:1}"
            
            case $c in
                ".") numdots+=1 ;;
                "M")
		    # log start position of monsters
                    levelmap["monsterstartpos_x"]="$x"
                    levelmap["monsterstartpos_y"]="$y"
                    c=" "
                    ;;
                "P")
		    # log start position of player
                    levelmap["playerstartpos_x"]="$x"
                    levelmap["playerstartpos_y"]="$y"
                    c=" "
                    ;;
            esac

            levelmap["${x}_${y}"]="$c"
        done
        (( maxx=x , y++ ))
    done <<<"${map}"

    levelmap["max_x"]=${maxx}
    levelmap["max_y"]=${y}
    levelmap["numdots"]=${numdots}
    
    # consistency checks
    if [[ "${levelmap["monsterstartpos_x"]}" == "" ]] ; then
        fatal_error "read_levelmap: monsterstartpos_x is empty."
    fi
    if [[ "${levelmap["playerstartpos_x"]}" == "" ]] ; then
        fatal_error "read_levelmap: playerstartpos_x is empty."
    fi
        
    return 0
}
    
function player.set
{    
    case "${.sh.subscript}" in
        pos_y)
            if [[ "${levelmap["${player["pos_x"]}_${.sh.value}"]}" == "#" ]] ; then
                .sh.value=${player["pos_y"]}
                beep
            fi
            ;;

        pos_x)
            if [[ "${levelmap["${.sh.value}_${player["pos_y"]}"]}" == "#" ]] ; then
                .sh.value=${player["pos_x"]}
                beep
            fi
            ;;
    esac
    return 0
}

function monster.set
{    
    case "${.sh.subscript}" in
        *_pos_y)
            if [[ "${levelmap["${monster[${currmonster}_"pos_x"]}_${.sh.value}"]}" == "#" ]] ; then
                .sh.value=${monster[${currmonster}_"pos_y"]}
                # turn homing off when the monster hit a wall
                monster[${currmonster}_"homing"]=0
            fi
            ;;

        *_pos_x)
            if [[ "${levelmap["${.sh.value}_${monster[${currmonster}_"pos_y"]}"]}" == "#" ]] ; then
                .sh.value=${monster[${currmonster}_"pos_x"]}
                # turn homing off when the monster hit a wall
                monster[${currmonster}_"homing"]=0
            fi
            ;;
    esac
    return 0
}

function render_game
{
    # render_buffer is some kind of "background buffer" to "double buffer"
    # all output and combine it in one write to reduce flickering in the
    # terminal
    typeset render_buffer="$(
        integer screen_y_offset=1
        integer start_y_pos=0
        integer render_num_lines=${levelmap["max_y"]}

        if (( (termsize.lines-3) < levelmap["max_y"] )) ; then
            (( start_y_pos=player["pos_y"] / 2))
            (( render_num_lines=termsize.lines-5))
        fi

        #print -n -- "${vtcode["clear"]}"
        print_setcursorpos 0 0

        # print score (note the " " around "%d" are neccesary to clean up cruft
        # when we overwrite the level
        printf "SCORE: %05d  DOTS: %.3d  LIVES: %2.d " "${player["score"]}" "${levelmap["numdots"]}" "${player["lives"]}"
        print_levelmap ${screen_y_offset} ${start_y_pos} ${render_num_lines}

        # render player
        print_setcursorpos ${player["pos_x"]} $((player["pos_y"]+screen_y_offset-start_y_pos))
        print -n "@"

        # render monsters
        for currmonster in ${monsterlist} ; do
            (( m_pos_x=monster[${currmonster}_"pos_x"] ))
            (( m_pos_y=monster[${currmonster}_"pos_y"]+screen_y_offset-start_y_pos ))

            if (( m_pos_y >= screen_y_offset && m_pos_y < render_num_lines )) ; then
                print_setcursorpos ${m_pos_x} ${m_pos_y}
                print -n "x"
            fi
        done

        # status block
        print_setcursorpos 0 $((render_num_lines+screen_y_offset))
        emptyline="                                                            "
        print -n " >> ${player["message"]} <<${emptyline:0:${#emptyline}-${#player["message"]}}"
    )"
    print -r -- "${render_buffer}${end_of_frame}"
#    print "renderbuffersize=$(print "${render_buffer}" | wc -c) ${end_of_frame}"
    return 0
}

function main_loop
{
    float   sleep_per_cycle=0.2
    float   seconds_before_read
    integer num_cycles=0
    float   rs
    
    print -n -- "${vtcode["clear"]}"

    read_levelmap "$1"
    
    # player init
    player["pos_x"]=${levelmap["playerstartpos_x"]}
    player["pos_y"]=${levelmap["playerstartpos_y"]}
    player["score"]=0         # player score
    player["lives"]=5         # number of lives
    player["invulnerable"]=10 # cycles how long the player remains invulnerable
    player["message"]="Go..."

    monsterlist="maw claw jitterbug tentacle grendel"

    for currmonster in ${monsterlist} ; do
        monster[${currmonster}_"pos_x"]=${levelmap["monsterstartpos_x"]}
        monster[${currmonster}_"pos_y"]=${levelmap["monsterstartpos_y"]}
        monster[${currmonster}_"xstep"]=0
        monster[${currmonster}_"ystep"]=0
        monster[${currmonster}_"homing"]=0
    done    

    # main game cycle loop
    while true ; do
        num_cycles+=1
        seconds_before_read=${SECONDS}
        c="" ; read -r -t ${sleep_per_cycle} -n 1 c
               
        if [[ "$c" != "" ]] ; then
            # special case handling for cursor keys which are usually composed
            # of three characters (e.g. "<ESC>[D"). If only <ESC> is hit we
            # quicky exit
            if [[ "$c" == $'\E' ]] ; then
                read -r -t 0.1 -n 1 c
                if [[ "$c" != "[" ]] ; then
                    return 0
                fi

                # we assume the user is using the cursor keys, this |read|
                # should fetch the 3rd byte of the three-character sequence
                # for the cursor keys
                read -r -t 0.1 -n 1 c
            fi

            # if the user hit a key the "read" above was interrupted
            # and didn't wait exactly |sleep_per_cycle| seconds.
            # We wait here some moments (|rs|="remaining seconds") to
            # avoid that the game gets "faster" when more user input 
            # is given.
            (( rs=sleep_per_cycle-(SECONDS-seconds_before_read) ))
            (( rs > 0.001 )) && sleep ${rs}

            player["message"]=""

            case "$c" in
                j|D|4) (( player["pos_x"]-=1 )) ;;
                k|C|6) (( player["pos_x"]+=1 )) ;;
                i|A|8) (( player["pos_y"]-=1 )) ;;
                m|B|2) (( player["pos_y"]+=1 )) ;;

                q) return 0 ;;
            esac

            if [[ "${levelmap["${player["pos_x"]}_${player["pos_y"]}"]}" == "." ]] ; then
                levelmap["${player["pos_x"]}_${player["pos_y"]}"]=" "
                (( levelmap["numdots"]-=1 ))

                (( player["score"]+=10 ))
                player["message"]='GNAW!!'

                if (( levelmap["numdots"] <= 0 )) ; then
                    level_completed
                    return 0
                fi
            fi
        fi

        # generic player status change
        if (( player["invulnerable"] > 0 )) ; then
            (( player["invulnerable"]-=1 ))
        fi
        if (( player["lives"] <= 0 )) ; then
            game_over
            return 0
        fi 

        # move monsters
        for currmonster in ${monsterlist} ; do
            # make monster as half as slow then the others when it is following the user
            if (( monster[${currmonster}_"homing"] > 0 )) ; then
                (( (num_cycles%2) > 0 )) && continue
            fi
                       
            if [[ ${monster[${currmonster}_"pos_x"]} == ${player["pos_x"]} ]] ; then
                if (( (monster[${currmonster}_"pos_y"]-player["pos_y"]) > 0 )) ; then
                    (( monster[${currmonster}_"xstep"]=+0 , monster[${currmonster}_"ystep"]=-1 ))
                else
                    (( monster[${currmonster}_"xstep"]=+0 , monster[${currmonster}_"ystep"]=+1 ))
                fi
                monster[${currmonster}_"homing"]=1
                if (( player["invulnerable"] <= 0 )) ; then
                    player["message"]="Attention: ${currmonster} is chasing you"
                fi
            elif (( monster[${currmonster}_"pos_y"] == player["pos_y"] )) ; then
                if (( (monster[${currmonster}_"pos_x"]-player["pos_x"]) > 0 )) ; then
                    (( monster[${currmonster}_"xstep"]=-1 , monster[${currmonster}_"ystep"]=-0 ))
                else
                    (( monster[${currmonster}_"xstep"]=+1 , monster[${currmonster}_"ystep"]=+0 ))
                fi           
                monster[${currmonster}_"homing"]=1
                if (( player["invulnerable"] <= 0 )) ; then
                    player["message"]="Attention: ${currmonster} is chasing you"
                fi
            else
                if (( monster[${currmonster}_"homing"] == 0 )) ; then
                    case $((SECONDS % 6 + RANDOM % 4)) in
                        0) (( monster[${currmonster}_"xstep"]=+0 , monster[${currmonster}_"ystep"]=+0 )) ;;
                        2) (( monster[${currmonster}_"xstep"]=+0 , monster[${currmonster}_"ystep"]=+1 )) ;;
                        3) (( monster[${currmonster}_"xstep"]=+1 , monster[${currmonster}_"ystep"]=+0 )) ;;
                        5) (( monster[${currmonster}_"xstep"]=+0 , monster[${currmonster}_"ystep"]=-1 )) ;;
                        6) (( monster[${currmonster}_"xstep"]=-1 , monster[${currmonster}_"ystep"]=+0 )) ;;
                    esac
                fi
            fi
       
            (( monster[${currmonster}_"pos_x"]=monster[${currmonster}_"pos_x"]+monster[${currmonster}_"xstep"] ))
            (( monster[${currmonster}_"pos_y"]=monster[${currmonster}_"pos_y"]+monster[${currmonster}_"ystep"] ))
           
            # check if a monster hit the player
            if (( player["invulnerable"] <= 0 )) ; then
                if (( monster[${currmonster}_"pos_x"] == player["pos_x"] && \
                      monster[${currmonster}_"pos_y"] == player["pos_y"] )) ; then
                     # if player was hit by a monster take one life and
                     # make him invulnerable for 10 cycles to avoid that
                     # the next cycle steals more lives
                     player["message"]="Ouuuchhhh"
                     player["invulnerable"]=10
                     (( player["lives"]-=1 ))

                     beep ; beep ; sleep 0.2 ; beep ; beep
                fi
            fi 
        done    

        render_game
    done
    return 0
}

function map_filter
{
    typeset ch_player ch_monster ch_wall var

    if (( $1 == 1 )) ; then
        ch_player="${vtcode["fg_yellow"]}"
        ch_monster="${vtcode["fg_red"]}"
        ch_wall="${vtcode["fg_blue"]}"
    else
        ch_player=""
        ch_monster=""
        ch_wall=""
    fi

    if (( $2 == 1 )) ; then
        # unicode map
        ch_player+="$(printf '\u[24d2]')"
        ch_monster+="$(printf '\u[2605]')"
        ch_wall+="$(printf '\u[25a6]')"
    else
        # ascii map
        ch_player+="@"
        ch_monster+="x"
        ch_wall+="#"
    fi

    # note that this filter currently defeats the "double-buffering"
    while IFS='' read -r -d "${end_of_frame}" var ; do
        var="${var// /${vtcode["fg_grey"]} }"
        var="${var//\./${vtcode["fg_lightred"]}.}"
        var="${var//@/${ch_player}}"
        var="${var//x/${ch_monster}}"
        var="${var//#/${ch_wall}}"

        print -r -- "${var}"
    done
    return 0
}

function exit_trap
{
    # restore stty settings
    stty ${saved_stty}
    
    print "bye."
    return 0
}

function usage
{
    OPTIND=0
    getopts -a "${progname}" "${gnaw_usage}" OPT '-?'
    exit 2
}

# program start
# make sure we use the ksh93 "cat" builtin which supports the "-u" option
builtin basename
builtin cat
builtin wc

typeset progname="${ basename "${0}" ; }"

# terminal size rect
compound termsize=(
    integer columns=-1
    integer lines=-1
)

# global variables
typeset quiet=false

typeset -A levelmap
typeset -A player
typeset -A monster
# global rendering options
integer game_use_colors=0
integer game_use_unicode=0

typeset -r gnaw_usage=$'+
[-?\n@(#)\$Id: gnaw (Roland Mainz) 2009-05-09 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?gnaw - maze game written in ksh93]
[+DESCRIPTION?\bgnaw\b is a maze game.
        The player maneuvers a yellow "@" sign to navigate a maze while eating
        small dots. A level is finished when all the dots are eaten. Five monsters
        (maw, claw, jitterbug, tentacle and grendel) also wander the maze in an attempt
        to catch the "@". Each level begins with all ghosts in their home, and "@" near
        the bottom of the maze. The monsters are released from the home one by one at the
        start of each level and start their rentless hunt after the player.]
[q:quiet?Disable use of terminal bell.]
[+SEE ALSO?\bksh93\b(1)]
'

while getopts -a "${progname}" "${gnaw_usage}" OPT ; do 
#    printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
    case ${OPT} in
        q)    quiet=true  ;;
        +q)   quiet=false ;;
        *)    usage ;;
    esac
done
shift $((OPTIND-1))

# save stty values and register the exit trap which restores these values on exit
saved_stty="$(stty -g)"
trap exit_trap EXIT

print "Loading..."

# set stty values, "-icanon min 1 time 0 -inpck" should improve input latency,
# "-echo" turns the terminal echo off
stty -icanon min 1 time 0 -inpck -echo

get_term_size termsize || fatal_error "Could not get terminal size."

# prechecks
(( termsize.columns < 60 )) && fatal_error "Terminal width must be larger than 60 columns (currently ${termsize.columns})."

typeset -A vtcode
# color values taken from http://frexx.de/xterm-256-notes/, other
# codes from http://vt100.net/docs/vt100-tm/
vtcode=(
    ["bg_black"]="$(print -n "\E[40m")"
    ["fg_black"]="$(print -n "\E[30m")"
    ["fg_red"]="$(print -n "\E[31m")"
    ["fg_lightred"]="$(print -n "\E[1;31m")"
    ["fg_green"]="$(print -n "\E[32m")"
    ["fg_lightgreen"]="$(print -n "\E[1;32m")"
    ["fg_yellow"]="$(print -n "\E[33m")"
    ["fg_lightyellow"]="$(print -n "\E[1;33m")"
    ["fg_blue"]="$(print -n "\E[34m")"
    ["fg_lightblue"]="$(print -n "\E[1;34m")"
    ["fg_grey"]="$(print -n "\E[1;37m")"
    ["fg_white"]="$(print -n "\E[37m")"

    # misc other vt stuff
    ["vtreset"]="$(tput reset)"
    ["clear"]="$(tput clear)"
    ["bel"]="$(tput bel)"
    ["spaceline"]="$(for (( i=0 ; i < termsize.columns ; i++ )) ; do print -n " " ; done)"
)

# character used to as marker that a single frame ends at this point - this
# is used by the "double buffering" code to make sure the "read" builtin
# can read a whole "frame" instead of reading stuff line-by-line
typeset -r end_of_frame=$'\t'

# get terminal sequence to move cursor to position x,y
# (see http://vt100.net/docs/vt100-ug/chapter3.html#CPR)
case ${TERM} in
    xterm | xterm-color | vt100 | vt220 | dtterm | sun | sun-color)
        cup="$(infocmp -1 | \
	       egrep '^[[:space:]]*cup=' | \
	       sed -e 's/.*cup=//' \
	           -e 's/%[%id]*p1[%id]*/%2\\\$d/g' \
		   -e 's/%[%id]*p2[%id]*/%1\\\$d/g' \
		   -e 's/,$//')"
        for (( x=0 ; x < termsize.columns ; x++ )) ; do
            for (( y=0 ; y < termsize.lines ; y++ )) ; do
                vtcode[cup_${x}_${y}]="$(printf "${cup}" $((x + 1)) $((y + 1)) )"
            done
        done
        ;;
    *)
        printf "# Unrecognised terminal type '%s', fetching %dx%d items from terminfo database, please wait...\n" "${TERM}" "${termsize.columns}" "${termsize.lines}"
        for (( x=0 ; x < termsize.columns ; x++ )) ; do
            for (( y=0 ; y < termsize.lines ; y++ )) ; do
                vtcode[cup_${x}_${y}]="$(tput cup ${y} ${x})"
            done
        done
        ;;
esac

print -- "${vtcode["vtreset"]}"

run_logo
run_menu

exit 0
# EOF.
