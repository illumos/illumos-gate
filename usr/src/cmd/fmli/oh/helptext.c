/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

char *Help_text[] = {

/***************************************************
 * CANCEL
 ***************************************************/
"\
\n\
\n\
   The cancel command allows you to cancel a current command or\n\
   activity.\n\
\n\
   To use cancel choose one of the following options:\n\
\n\
 	 - Screen Labeled Key - Press CANCEL\n\
\n\
 	 - Typed Command - Type cancel + ENTER\n\
",

/***************************************************
 * CLEANUP
 ***************************************************/
"\
\n\
   The cleanup command cancels all frames on the screen,\n\
   excluding those frames that can only be canceled upon exit. \n\
\n\
   Use one of the following:\n\
\n\
 	 - Command Menu - Select cleanup + ENTER\n\
\n\
 	 - Typed Command - Type cleanup + ENTER\n\
",

/***************************************************
 * CMD-MENU
 ***************************************************/
"\
The cmd-menu is a multi-column menu of the commands available.\n\
It serves as a command reference list, a place from which you\n\
can issue a command, or a place to get help on a specific\n\
command.\n\
",
 
/***************************************************
 * EXIT
 ***************************************************/
"\
\n\
   Use the exit command to cancel all frames and exit the application.\n\
\n\
   To exit use one of the following options:\n\
\n\
 	 - Command Menu - Select exit + ENTER\n\
\n\
 	 - Typed Command - Type exit + ENTER\n\
",

/***************************************************
 * FRM-MGMT
 ***************************************************/
"\
\n\
   The frm-mgmt command allows you to move and reshape frames.   It\n\
   also  supports  a  \\\"list\\\"  operation which lists for you all open\n\
   frames on the screen.  In the command syntax \\\"operation\\\"  refers\n\
   to \\\"move\\\", \\\"reshape\\\" or \\\"list\\\".\n\
\n\
     1.  To use the frm-mgmt command, choose one of the following.\n\
	 If  a frame number or name is not specified, the currently\n\
	 active frame is assumed to be the frame you would like to\n\
	 operate  on.\n\
\n\
	    - Screen Labeled Key - Press FRM-MGMT\n\
\n\
	    - Command Menu - Select frm-mgmt + ENTER\n\
\n\
	    - Typed Command - Type frm-mgmt [operation]\n\
			       [frame_#] + ENTER\n\
\n\
     2.  If an \\\"operation\\\" is not specified a pop-up  menu  frame\n\
	 will  appear  listing frm-mgmt operations.  You select\n\
	 the frame operation you want  to  perform  by  moving  the\n\
	 cursor  to the item and pressing ENTER or the ENTER screen\n\
	 labeled  key.   Pressing  the  CANCEL  screen  labeled  key\n\
	 cancels the frm-mgmt command.\n\
",

/***************************************************
 * GOTO
 ***************************************************/
"\
\n\
   The goto command allows you to move the cursor to another\n\
   open frame by specifying the frame number.\n\
\n\
     1.  To use the goto choose one of the following:\n\
\n\
	    - Command Menu - Select goto + ENTER\n\
\n\
	    - Typed Command - Type goto [frame_#] + ENTER\n\
\n\
     2.  If you use the goto command without specifying a frame\n\
	 number, you will be prompted for one.\n\
",

/***************************************************
 * HELP
 ***************************************************/
"\
\n\
   The help command creates an active frame containing a text message\n\
   which  describes either the action you are trying to perform or the\n\
   current object or form.  To exit the Help Facility press the CANCEL\n\
   screen labeled key.\n\
\n\
   To access help use one of the following options.  If no argument is\n\
   specified the system assumes you want help on the current frame or\n\
   on what you are currently doing.\n\
\n\
	 - Screen Labeled Key - Press HELP\n\
\n\
	 - Command Menu - Select help + ENTER\n\
\n\
	 - Typed command - Type help [command_name] + ENTER\n\
",

/***************************************************
 * NEXT-FRM
 ***************************************************/
"\
\n\
   The next-frm command allows you to move among frames according to\n\
   the order in which frames were opened.\n\
\n\
   To use next-frm choose one of the following options:\n\
\n\
 	 - Screen Labeled Key - Press NEXT-FRM\n\
\n\
 	 - Command Menu - Select next-frm + ENTER\n\
\n\
 	 - Typed Command - Type next-frm + ENTER\n\
",

/*************************************************** 
 * PREV-FRM
 ***************************************************/
"\
\n\
   The prev-frm command allows you to move to the previous frame\n\
   according to the reverse order in which the frames were opened.\n\
\n\
   To use prev-frm choose one of the following options:\n\
\n\
 	 - Screen Labeled Key - Press PREV-FRM\n\
\n\
 	 - Command Menu - Select prev-frm + ENTER\n\
\n\
 	 - Typed Command - Type prev-frm + ENTER\n\
",

/***************************************************
 * REFRESH
 ***************************************************/
"\
\n\
   The refresh command will simply redraw the screen.\n\
\n\
 	 - Command Menu - Select refresh + ENTER\n\
\n\
 	 - Typed Command - Type refresh + ENTER\n\
",

/***************************************************
 * UNIX
 ***************************************************/
"\
\n\
   The unix-system command invokes the shell command interpreter\n\
   defined in the environmental variable SHELL.\n\
\n\
   To invoke unix-system use one of the following options:\n\
\n\
 	 - Command Menu - Select unix-system + ENTER\n\
\n\
 	 - Typed Command - Type unix-system + ENTER\n\
\n\
   Your screen will be cleared of frames and the prompt\n\
   defined in the environmental variable PS1 will be displayed.\n\
\n\
   To return from the shell type exit or control-d at the prompt.\n\
   You will then be prompted to press ENTER to refresh the screen.\n\
",


/***************************************************
 * UPDATE
 ***************************************************/
"\
\n\
   The update command is used to update the contents of a frame to\n\
   reflect changes made since the frame was  originally  opened.\n\
\n\
   To use the update command do one of the following options.  If a\n\
   frame  is  not  specified,  the current frame is assumed.  In the\n\
   \\\"typed command\\\" syntax the frame number is specified  as\n\
   it is listed in the label of the frame to be updated.  \n\
\n\
 	 - Command Menu - Select update + ENTER\n\
\n\
 	 - Typed Command - Type update [ frame_number] + ENTER\n\
",

};
