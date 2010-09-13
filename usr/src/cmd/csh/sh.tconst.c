/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * C shell
 */

/*
 * These tchar constants used to be defined as
 * character string constants. 
 */

#include "sh.h"

tchar S_[] = {0};
tchar S_0[]={'0', 0};
tchar S_1[]={'1', 0};
tchar S_AND[] = {'&', 0};	/* & */
tchar S_ANDAND[] = {'&', '&', 0};	/* && */
tchar S_AST[]={'*', 0};
tchar S_AT[] = { '@', 0 };
tchar S_BAR[] = {'|', 0};	/* | */
tchar S_BARBAR[] = {'|','|', 0};	/* || */
tchar S_BRABRA[] = {'{', '}', 0};	/* {} */
tchar S_BRAPPPBRA[] = {'{', ' ', '.', '.', '.', ' ', '}', 0};	/* { ... } */
tchar S_COLON[] = {':', 0}; /*:*/
tchar S_DASHl[] = {'-', 'l', 0};	/*-l */
tchar S_DELIM[] = {' ','\'','"','\t',';','&','<','>','(',')','|','`',0};
tchar S_DOT[] = {'.', 0};
tchar S_DOTDOTSLA[]={'.', '.', '/', 0};
tchar S_DOTSLA[]={'.', '/', 0};
tchar S_EQ[] = {'=', 0};	/*=*/
tchar S_EXAS[] = {'!', 0};       /* ! */
tchar S_HAT[] = {'^', 0};	/* ^ */
tchar S_HOME[] = {'H','O','M','E',0};/*HOME*/
tchar S_IOT[] = {'I', 'O', 'T', 0}; /*IOT*/
tchar S_LANG[]={'L', 'A', 'N', 'G', 0}; /*LANG*/
tchar S_LBRA[] = {'{', 0};	/* { */
tchar S_LBRASP[] = {'(', ' ', 0};	/*( */
tchar S_LC_ALL[]={'L', 'C', '_', 'A', 'L', 'L',  0}; /*LC_ALL*/
tchar S_LC_CTYPE[]={'L', 'C', '_', 'C', 'T', 'Y', 'P',  'E', 0}; /*LC_CTYPE*/
tchar S_LC_MESSAGES[]={'L', 'C', '_', 
		   'M', 'E', 'S', 'S', 'A', 'G', 'E', 'S', 0}; /*LC_MESSAGES*/
tchar S_LESLES[]={'<', '<', 0};
tchar S_LPAR[] = {'(', 0};	/* ( */
tchar S_MINUS[] = {'-',0};/*"-"*/
tchar S_MINl[]={'-', 'l', 0};
tchar S_NDOThistory[] = {'~','/','.','h','i','s','t','o','r','y',0};
tchar S_OTHERSH[] = {'/','b','i','n','/','s','h',0};
tchar S_PARCENTMINUS[] = {'%', '-', 0}; /*%-*/
tchar S_PARCENTPARCENT[] = {'%', '%', 0}; /*%%*/
tchar S_PARCENTPLUS[] = {'%', '+', 0}; /*%+*/
tchar S_PARCENTSHARP[] = {'%', '#', 0}; /*%#*/
tchar S_PATH[] = {'P','A','T','H',0};/*"PATH"*/
tchar S_PERSENTSP[] = {'%',' ',0};
tchar S_PWD[]={'P', 'W', 'D', 0};
tchar S_Pjob[] = {'%','j','o','b', 0}; /*"%job"*/
tchar S_PjobAND[] = {'%','j','o','b',' ','&',0}; /*"%job &"*/
tchar S_QPPPQ[] = {'`', ' ', '.', '.', '.', ' ', '`', 0}; /*` ... `*/
tchar S_RBRA[] = {'}', 0};	/* } */
tchar S_RPAR[] = {')', 0}; /*)*/
tchar S_SEMICOLONSP[] = {';', ' ', 0};	/* | */
tchar S_SHARPSP[] = {'#',' ',0};
tchar S_SHELLPATH[] = {'/','b','i','n','/','c','s','h',0};
tchar S_SLADOTcshrc[] = {'/','.','c','s','h','r','c', 0};
tchar S_SLADOThistory[] = {'/','.','h','i','s','t','o','r','y', 0};
tchar S_SLADOTlogin[] = {'/','.','l','o','g','i','n', 0};
tchar S_SLADOTlogout[] = {'/','.','l','o','g','o','u','t', 0};
tchar S_SLASH[] = {'/', 0}; /* "/" */
tchar S_SP[] = {' ', 0};	/* */
tchar S_SPANDANDSP[] = {' ', '&', '&', ' ', 0};	/* && */
tchar S_SPBARBARSP[] = {' ', '|', '|', ' ', 0};	/* || */
tchar S_SPBARSP[] = {' ', '|', ' ', 0};	/* | */
tchar S_SPGTRGTRSP[] = {' ', '>', '>', ' ', 0};	/* >> */
tchar S_SPGTR[] = {' ', '>',0};	/* > */
tchar S_SPLESLESSP[] = {' ', '<', '<', ' ', 0};	/* << */
tchar S_SPLESSP[] = {' ', '<', ' ', 0};	/* < */
tchar S_SPPPP[] = {' ', '.', '.', '.', 0};	/* ... */
tchar S_SPRBRA[] = {' ', ')', 0};	/* )*/
tchar S_SUNW_VARLEN[] = {'S', 'U', 'N', 'W', '_',
	'V', 'A', 'R', 'L', 'E', 'N', 0};
tchar S_TERM[] = {'T','E','R','M',0};/*TERM*/
tchar S_TIL[] = {'~', 0};	/* ~ */
tchar S_TOPBIT[] = {(tchar)QUOTE, 0};	/* Was "\200".  A hack! */
tchar S_USAGEFORMAT[] = {'%','U','u',' ','%','S','s',' ','%','E',' ','%','P', ' ','%','X','+','%','D','k',' ','%','I','+','%','O','i','o',' ','%','F','p','f','+', '%','W','w',0};
tchar S_USER[] = {'U','S','E','R',0};/*USER*/
tchar S_alias[] = { 'a','l','i','a','s', 0 };
tchar S_alloc[] = { 'a','l','l','o','c', 0};
tchar S_aout[] = {'a','.','o','u','t',0};
tchar S_argv[]={'a', 'r', 'g', 'v', 0};
tchar S_bg[] = { 'b','g', 0};
tchar S_bin[] = {'/','b','i','n',0};
tchar S_break[] = { 'b','r','e','a','k', 0};
tchar S_breaksw[] = { 'b','r','e','a','k','s','w', 0};
tchar S_bye[] = { 'b','y','e', 0};
tchar S_case[] = { 'c','a','s','e', 0};
tchar S_cd[] = { 'c','d', 0};
tchar S_cdpath[]={'c', 'd', 'p', 'a', 't', 'h', 0};
tchar S_chdir[] = { 'c','h','d','i','r', 0};
tchar S_child[] = {'c', 'h', 'i', 'l', 'd', 0};	/*child */
tchar S_continue[] = { 'c','o','n','t','i','n','u','e', 0};
tchar S_coredumpsize[] = {'c','o','r','e','d','u','m','p','s','i','z','e',0};/*"coredumpsize"*/
tchar S_cputime[] = {'c','p','u','t','i','m','e',0};/*"cputime"*/
tchar S_csh[]={'c', 's', 'h', 0};
tchar S_cwd[]={'c', 'w', 'd', 0};
tchar S_datasize[] = {'d','a','t','a','s','i','z','e',0};/*"datasize"*/
tchar S_default[] =  { 'd','e','f','a','u','l','t', 0 };
tchar S_descriptors[] = {'d', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 's', 0};
tchar S_dirs[] =  { 'd','i','r','s', 0 };
tchar S_echo[] = {'e','c','h','o', 0};
tchar S_else[] =  { 'e','l','s','e', 0 };
tchar S_end[] =  { 'e','n','d', 0 };
tchar S_endif[] =  { 'e','n','d','i','f', 0 };
tchar S_endsw[] =  { 'e','n','d','s','w', 0 };
tchar S_erwxfdzo[] = {'e', 'r', 'w', 'x', 'f', 'd', 'z', 'o', 0}; /* erwxfdzo */
tchar S_eval[] =  { 'e','v','a','l', 0 };
tchar S_exec[] =  { 'e','x','e','c', 0 };
tchar S_exit[] =  { 'e','x','i','t', 0 };
tchar S_fg[] =  { 'f','g', 0 };
tchar S_fignore[] = {'f','i','g','n','o','r','e',0};
tchar S_filec[] = {'f','i','l','e','c',0};/*filec*/
tchar S_filesize[] = {'f','i','l','e','s','i','z','e',0};/*"filesize"*/
tchar S_foreach[] =  { 'f','o','r','e','a','c','h', 0 };
tchar S_gd[] =  { 'g','d', 0 };
tchar S_glob[] =  { 'g','l','o','b', 0 };
tchar S_goto[] =  { 'g','o','t','o', 0 };
tchar S_h[] = {'-','h',0};
tchar S_hardpaths[]={'h', 'a', 'r', 'd', 'p', 'a', 't', 'h', 's', 0};
tchar S_hashstat[] =  { 'h','a','s','h','s','t','a','t', 0 };
tchar S_histchars[] = {'h','i','s','t','c','h','a','r','s',0}; /*histchars*/
tchar S_history[] = {'h','i','s','t','o','r','y',0};
tchar S_home[]={'h', 'o', 'm', 'e', 0};
tchar S_hours[] = {'h','o','u','r','s',0};/*"hours"*/
tchar S_htrqxe[]={'h', 't', 'r', 'q', 'x', 'e', 0};
tchar S_if[] =  { 'i','f', 0 };
tchar S_ignoreeof[] = {'i','g','n','o','r','e','e','o','f',0};	/*"ignoreeof"*/
tchar S_jobs[] = {'j','o','b','s', 0};
tchar S_kbytes[] = {'k','b','y','t','e','s',0};/*"kbytes"*/
tchar S_kill[] =  { 'k','i','l','l', 0 };
tchar S_label[] =  { 'l','a','b','e','l', 0 };
tchar S_limit[] =  { 'l','i','m','i','t', 0 };
tchar S_login[] =  { 'l','o','g','i','n', 0 };
tchar S_logout[] =  { 'l','o','g','o','u','t', 0 };
tchar S_mail[] = {'m','a','i','l', 0};
tchar S_megabytes[] = {'m','e','g','a','b','y','t','e','s',0};/*"megabytes"*/
tchar S_memorysize[] = {'m','e','m','o','r','y','s','i','z','e',0};/*"memorysize"*/
tchar S_minutes[]={'m','i','n','u','t','e','s',0};/*"minutes"*/
tchar S_n[] = {'-','n',0};/*"-n"*/
tchar S_newgrp[] =  { 'n','e','w','g','r','p', 0 };
tchar S_nice[] =  { 'n','i','c','e', 0 };
tchar S_nobeep[] = {'n', 'o', 'b', 'e', 'e', 'p', 0};
tchar S_noclobber[] = {'n','o','c','l','o','b','b','e','r',0};/*noclobber*/
tchar S_noglob[] = {'n', 'o', 'g', 'l', 'o', 'b', 0}; /*noglob */
tchar S_nohup[] = {'n', 'o', 'h', 'u', 'p', 0};	/*nohup */
tchar S_nonomatch[] = {'n', 'o', 'n', 'o', 'm', 'a', 't', 'c', 'h', 0}; /*nonomatch */
tchar S_notify[] = {'n', 'o', 't', 'i', 'f', 'y', 0};	/*nofify */
tchar S_onintr[] =  { 'o','n','i','n','t','r', 0 };
tchar S_path[] = {'p','a','t','h', 0}; /*path*/
tchar S_popd[] =  { 'p','o','p','d', 0 };
tchar S_prompt[] = {'p','r','o','m','p','t', 0};
tchar S_pushd[] =  { 'p','u','s','h','d', 0 };
tchar S_rd[] =  { 'r','d', 0 };
tchar S_rehash[] =  { 'r','e','h','a','s','h', 0 };
tchar S_repeat[] =  { 'r','e','p','e','a','t', 0 };
tchar S_savehist[] = {'s','a','v','e','h','i','s','t', 0};
tchar S_seconds[] = {'s','e','c','o','n','d','s',0};/*"seconds"*/
tchar S_set[] =  { 's','e','t', 0 };
tchar S_setenv[] =  { 's','e','t','e','n','v', 0 };
tchar S_shell[] = {'s','h','e','l','l', 0};
tchar S_shift[] =  { 's','h','i','f','t', 0 };
tchar S_source[] = {'s','o','u','r','c','e',0};
tchar S_stacksize[] = {'s','t','a','c','k','s','i','z','e',0};/*"stacksize"*/
tchar S_status[]={'s', 't', 'a', 't', 'u', 's', 0};
tchar S_stop[] =  { 's','t','o','p', 0 };
tchar S_suspend[] =  { 's','u','s','p','e','n','d', 0 };
tchar S_switch[] =  { 's','w','i','t','c','h', 0 };
tchar S_term[] = {'t','e','r','m', 0};
tchar S_then[] = {'t','h','e','n',0}; /*"then"*/
tchar S_time[] = {'t', 'i', 'm', 'e', 0};	/*time*/
tchar S_umask[] =  { 'u','m','a','s','k', 0 };
tchar S_unalias[] =  { 'u','n','a','l','i','a','s', 0 };
tchar S_unhash[] =  { 'u','n','h','a','s','h', 0 };
tchar S_unlimit[] =  { 'u','n','l','i','m','i','t', 0 };
tchar S_unlimited[] = {'u','n','l','i','m','i','t','e','d',0};/*"unlimited"*/
tchar S_unset[] =  { 'u','n','s','e','t', 0 };
tchar S_unsetenv[] =  { 'u','n','s','e','t','e','n','v', 0 };
tchar S_user[] = {'u','s','e','r', 0};
tchar S_usrbin[] = {'/','u','s','r','/','b','i','n',0};
tchar S_usrucb[] = {'/','u','s','r','/','u','c','b',0};
tchar S_verbose[] = {'v','e','r','b','o','s','e', 0};
tchar S_wait[] =  { 'w','a','i','t', 0 };
tchar S_while[] =  { 'w','h','i','l','e', 0 };
/* Dummy search path for just absolute search when no path */
tchar *justabs[] =      { S_ /* "" */, 0 };
