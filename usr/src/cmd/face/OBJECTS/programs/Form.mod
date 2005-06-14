#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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

form="Modify Programs"

done=`indicator -w;message "";
$VMSYS/bin/delserve "${ARG1}" "${ARG3}";
$VMSYS/bin/creaserve "$F1" "$F2" "$F3" "$F4" "$F5" "${ARG3}"`close $VMSYS/OBJECTS/programs/Form.mod $VMSYS/OBJECTS/programs/Menu.list

help=OPEN TEXT $VMSYS/OBJECTS/Text.h "$TITLE" programs/T.hmod"$ITEM"

`set -l TERML="${TERMINFO:-/usr/lib/terminfo}";
fmlgrep TERM= ${ARG2} | fmlcut -d= -f2 | fmlcut -d";" -f1 | set -l OF1;
set -l OF2="${ARG1}";
if fmlgrep '^eval' ${ARG2} > /dev/null;
then
	fmlgrep '^eval' ${ARG2} | fmlcut -d" " -f2- | set -l OF3;
else
	tail -1 ${ARG2} | set -l OF3;
fi;
fmlgrep '^cd' ${ARG2} | fmlcut -d" " -f2 | set -l OF4;
if fmlgrep '^echo' ${ARG2} > /dev/null;
then
	set -l OF5=yes;
else
	set -l OF5=no;
fi`

name=Terminal Type:
show=false
nrow=1
ncol=1
rows=1
columns=14
frow=1
fcol=24
lininfo=`set -l TITLE="Terminal Type" -l ITEM=1;message -f "Enter the correct Terminal type needed for the command invoked."`
value=const "${OF1}"
valid=`echo ${F1} | fmlcut -c1 | set -l TDIR;
if [ -z "${F1}" ];
then
	set -l IMSG="You must enter a value for this field.";
	echo false;
elif [ -f "${TERML}/${TDIR}/${F1}" -a -s "${TERML}/${TDIR}/${F1}" ];
then
	echo true;
else
	set -l IMSG="${F1} is not a valid terminal on your system.";
	echo false;
fi`
invalidmsg="${IMSG}"

name=Program Menu Name:
nrow=2
ncol=1
rows=1
columns=45
frow=2
fcol=24
lininfo=`set -l TITLE="Program Menu Name" -l ITEM=2;message -f "Enter a name, then press SAVE when you complete the form."`
value=const "${OF2}"
valid=`indicator -w;
if [ -z "${F2}" ];
then
	set -l IMSG="You must enter a value for this field.";
	echo false;
elif [ "${F2}" = "${OF2}" ];
then
	echo true;
elif echo "${F2}"|fmlgrep '^.*;.*$' > /dev/null;
then
	set -l IMSG="Semi-colons are not allowed in this field.";
	echo false;
elif fmlgrep "name=\"${F2}\"" $HOME/pref/services > /dev/null 2> /dev/null;
then
	set -l IMSG="${F2} already exists.";
	echo false;
elif fmlgrep "name=\"${F2}\"" $VMSYS/lib/services > /dev/null 2> /dev/null;
then
	set -l IMSG="${F2} already exists.";
	echo false;
else
	echo true;
fi`
invalidmsg="${IMSG}"


name=Name of Command:
nrow=3
ncol=1
rows=1
columns=45
frow=3
fcol=24
lininfo=`set -l TITLE="Name of Command" -l ITEM=3;message -f "Enter a command name, then press SAVE when you complete the form."`
value=const "${OF3}"
valid=`indicator -w;
echo "${F3}"|fmlcut -f1 -d" "|set -l NF3;
if [ -z "${F3}" ];
then
	set -l IVAL=false -l IMSG="A value must be entered for this field.";
elif regex -v "${NF3}" '^/[a-zA-Z_/0-9]+$' > /dev/null;
then
	set -l IVAL=true;
elif regex -v "${NF3}" '^[a-zA-Z_0-9]+$' > /dev/null;
then
	set -l IVAL=true;
else
	set -l IVAL=false -l IMSG="${NF3} contains an illegal character.";
fi;
if [ "${IVAL}" = "true" ];
then
	if [  -x "${NF3}" ];
	then
		if [ ! -f "${NF3}" ];
		then
			set -l IVAL=false -l IMSG="A directory name is not valid input for this field.";
		fi;
	else 	
		if shell type "${NF3}" | fmlgrep "not found" > /dev/null;
		then
			set -l IVAL=false -l IMSG="${NF3} is not a valid command.";
		fi;
	fi;
fi`${IVAL}
invalidmsg=${IMSG}
scroll=true

name=Working Directory:
nrow=4
ncol=1
rows=1
columns=45
frow=4
fcol=24
lininfo=`set -l TITLE="Working Directory" -l ITEM=4;message -f "Enter a directory name, then press SAVE when you complete the form."`
value=const "${OF4}"
valid=`test -d $F4`
invalidmsg=const "The Path entered must be a valid directory"
wrap=true

name=Prompt for Arguments:
nrow=5
ncol=1
rows=1
columns=3
frow=5
fcol=24
lininfo=`set -l TITLE="Prompt for Arguments" -l ITEM=5;message -f "Press CHOICES to select, then press SAVE when you complete the form."`
value=const "${OF5}"
rmenu={ yes no }
menuonly=true
invalidmsg="The only valid responses are yes and no."

name=RESET
button=8
action=reset
