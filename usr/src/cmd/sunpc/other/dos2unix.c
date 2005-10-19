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
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 *	Converts files from one char set to another
 *
 *	Written 11/09/87	Eddy Bell
 *
 */


/*
 *  INCLUDED and DEFINES
 */
#include	<stdio.h>
#include	<fcntl.h>
#include	<sys/systeminfo.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>

/*#include	<io.h>			for microsoft c 4.0 */

#define 	CONTENTS_ASCII	0
#define 	CONTENTS_ASCII8 1
#define 	CONTENTS_ISO	2
#define 	CONTENTS_DOS	3
#ifdef _F_BIN
#define DOS_BUILD 1
#else
#define UNIX_BUILD 1
#endif

/******************************************************************************
 * INCLUDES AND DEFINES
 ******************************************************************************/
#ifdef UNIX_BUILD
#include <sys/types.h>
#include	<sys/kbio.h>
#include	<sys/time.h>
#include	<fcntl.h>
#include "../sys/dos_iso.h"
#endif

#ifdef DOS_BUILD
#include <dos.h>
#include "..\sys\dos_iso.h"
#endif


#define 	GLOBAL
#define 	LOCAL	static
#define 	VOID	int
#define 	BOOL	int

#define 	FALSE	0
#define 	TRUE	~FALSE

#define 	CR	0x0D
#define 	LF	0x0A
#define 	DOS_EOF 0x1A
#define		MAXLEN	1024


/******************************************************************************
 * FUNCTION AND VARIABLE DECLARATIONS
 ******************************************************************************/
static	void	error();
static	void	usage();
static int	tmpfd = -1;

/******************************************************************************
* ENTRY POINTS
 ******************************************************************************/

int
main(int argc, char **argv)
{
   FILE *in_stream = NULL;
   FILE *out_stream = NULL;
	unsigned char tmp_buff[512];
	unsigned char *src_str, *dest_str;
	char	 *in_file_name, *out_file_name;
   int num_read, i, j, out_len, translate_mode, same_name;			       /* char count for fread() */
   unsigned char * dos_to_iso;
	int	type;
	int	code_page_overide; /* over ride of default codepage */
#ifdef UNIX_BUILD
	int	kbdfd;
#endif
	char	sysinfo_str[MAXLEN];

	same_name = FALSE;
	out_file_name = (char *)0;

    /*	The filename parameter is positionally dependent - it must be the
     *	second argument, immediately following the program name. Except
     *	when a char set switch is passed then the file name must be third
     *	argument.
     */

	argv++;
	in_stream = stdin;
	out_stream = stdout;
	j = 0;  /* count for file names 0 -> source 1-> dest */
	translate_mode = CONTENTS_ISO; /*default trans mode*/
	code_page_overide = 0;
	for (i=1; i<argc; i++) {
      		if (*argv[0] == '-') {
			if (argc > 1 && !strncmp(*argv,"-iso",4)) {
				translate_mode = CONTENTS_ISO;
				argv++;
			} else if (argc > 1 && !strncmp(*argv,"-7",2)) {
				translate_mode = CONTENTS_ASCII;
				argv++;
			} else if (argc > 1 && !strncmp(*argv,"-ascii",6)) {
				translate_mode = CONTENTS_DOS;
				argv++;
			} else if (argc > 1 && !strncmp(*argv,"-437",4)) {
				code_page_overide = CODE_PAGE_US;
				argv++;
			} else if (argc > 1 && !strncmp(*argv,"-850",4)) {
				code_page_overide = CODE_PAGE_MULTILINGUAL;
				argv++;
			} else if (argc > 1 && !strncmp(*argv,"-860",4)) {
				code_page_overide = CODE_PAGE_PORTUGAL;
				argv++;
			} else if (argc > 1 && !strncmp(*argv,"-863",4)) {
				code_page_overide = CODE_PAGE_CANADA_FRENCH;
				argv++;
			} else if (argc > 1 && !strncmp(*argv,"-865",4)) {
				code_page_overide = CODE_PAGE_NORWAY;
				argv++;
			} else
				argv++;
			continue;
		}else{  /* not a command so must be filename */
			switch(j){
				case IN_FILE:	/* open in file from cmdline */
		       			in_file_name = *argv;
		       			j++;  /* next file name is outfile */
			       	break;

				case OUT_FILE:	/* open out file from cmdline */
					out_file_name = *argv;
					j++;
			   	break;

				default:
					usage();
			}
		}
		
	
	argv++;
	}

	/* input file is specified */
	if (j > 0) {
		in_stream = fopen(in_file_name, "r");
		if (in_stream == NULL)
			error("Couldn't open input file %s.", in_file_name);
	}

	/* output file is secified */
	if (j > 1) {
		if(!strcmp(in_file_name, out_file_name)){
			/* input and output have same name */
			if (access(out_file_name, 2))
				error("%s not writable.", out_file_name);
			strcpy(out_file_name, "/tmp/udXXXXXX");
			tmpfd = mkstemp(out_file_name);
			if (tmpfd == -1) {
				error("Couldn't create output file %s.",
				    out_file_name);
			}
			(void) close(tmpfd);
			same_name = TRUE;
		} else
			same_name = FALSE;
		out_stream = fopen(out_file_name, "w");
		if (out_stream == NULL) {
			(void) unlink(out_file_name);
			error("Couldn't open output file %s.", out_file_name);
		}
	}

#ifdef _F_BIN
	setmode(fileno(in_stream), O_BINARY);
	setmode(fileno(out_stream), O_BINARY);
#endif

#ifdef UNIX_BUILD
	if(!code_page_overide){
		if (sysinfo(SI_ARCHITECTURE,sysinfo_str,MAXLEN)  < 0) {
			fprintf(stderr,"could not obtain system information\n");
			(void) unlink(out_file_name);
			exit(1);
		
		}
		if (strcmp(sysinfo_str,"i386")) {
			if ((kbdfd = open("/dev/kbd", O_WRONLY)) < 0) {
				fprintf(stderr, "could not open /dev/kbd to "
				    "get keyboard type US keyboard assumed\n");
			}
			if (ioctl(kbdfd, KIOCLAYOUT, &type) < 0) {
				fprintf(stderr,"could not get keyboard type US keyboard assumed\n");
			}
		} else {
			type = 0;
		}
		switch(type){
			case	0:
			case	1:	/* United States */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	2:	/* Belgian French */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	3:	/* Canadian French */
				dos_to_iso = &dos_to_iso_cp_863[0];
			break;
	
			case	4:	/* Danish */
				dos_to_iso = &dos_to_iso_cp_865[0];
			break;
	
			case	5:	/* German */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	6:	/* Italian */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	7:	/* Netherlands Dutch */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	8:	/* Norwegian */
				dos_to_iso = &dos_to_iso_cp_865[0];
			break;
	
			case	9:	/* Portuguese */
				dos_to_iso = &dos_to_iso_cp_860[0];
			break;
	
			case	10:	/* Spanish */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	11:	/* Swedish Finnish */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	12:	/* Swiss French */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	13:	/* Swiss German */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	14:	/* United Kingdom */
				dos_to_iso = &dos_to_iso_cp_437[0];
	
			break;
			
			default:
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
		}
	}else{
		switch(code_page_overide){
			case CODE_PAGE_US:
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
			
			case CODE_PAGE_MULTILINGUAL:
				dos_to_iso = &dos_to_iso_cp_850[0];
			break;
			
			case CODE_PAGE_PORTUGAL:
				dos_to_iso = &dos_to_iso_cp_860[0];
			break;
			
			case CODE_PAGE_CANADA_FRENCH:
				dos_to_iso = &dos_to_iso_cp_863[0];
			break;
			
			case CODE_PAGE_NORWAY:
				dos_to_iso = &dos_to_iso_cp_865[0];
			break;
		}
	}	
	
#endif
#ifdef DOS_BUILD
	if(!code_page_overide){
		{
		union REGS regs;
		regs.h.ah = 0x66;	/* get/set global code page */
		regs.h.al = 0x01;		/* get */
		intdos(&regs, &regs);
		type = regs.x.bx;
		}
		switch(type){
			case	437:	/* United States */
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
	
			case	850:	/* Multilingual */
				dos_to_iso = &dos_to_iso_cp_850[0];
			break;
			
			case	860:	/* Portuguese */
				dos_to_iso = &dos_to_iso_cp_860[0];
			break;
			
			case	863:	/* Canadian French */
				dos_to_iso = &dos_to_iso_cp_863[0];
			break;
	
			case	865:	/* Danish */
				dos_to_iso = &dos_to_iso_cp_865[0];
			break;
	
			default:
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
		}
	}else{
		switch(code_page_overide){
			case CODE_PAGE_US:
				dos_to_iso = &dos_to_iso_cp_437[0];
			break;
			
			case CODE_PAGE_MULTILINGUAL:
				dos_to_iso = &dos_to_iso_cp_850[0];
			break;
			
			case CODE_PAGE_PORTUGAL:
				dos_to_iso = &dos_to_iso_cp_860[0];
			break;
			
			case CODE_PAGE_CANADA_FRENCH:
				dos_to_iso = &dos_to_iso_cp_863[0];
			break;
			
			case CODE_PAGE_NORWAY:
				dos_to_iso = &dos_to_iso_cp_865[0];
			break;
		}
	}	
	
	
#endif

    /*	While not EOF, read in chars and send them to out_stream
     *	if current char is not a CR.
     */

    do {
		num_read = fread(&tmp_buff[0], 1, 100, in_stream);
		i = 0;
		out_len = 0;
		src_str = dest_str = &tmp_buff[0];
		switch (translate_mode){
			case CONTENTS_ISO:
				{
				while ( i++ != num_read ){
					if( *src_str == '\r'){
						src_str++;
						}
					else{
						out_len++;
						*dest_str++ = dos_to_iso[*src_str++];
						}
					}
				}
				break;

			case CONTENTS_ASCII:
				{
				while ( i++ != num_read){
					if( *src_str == '\r'){
						src_str++;
						continue;
						}
					else if ( *src_str > 127 ){
						*dest_str++ = (unsigned char) ' ';
						src_str++;
						out_len++;
						}
					else{
						out_len++;
						*dest_str++ = *src_str++;
						}
					}
				}
				break;

			case CONTENTS_DOS:
				{
				while ( i++ != num_read){
					if( *src_str == '\r'){
						src_str++;
						continue;
						}
						*dest_str++ =	*src_str++;
						out_len++;
					}
				}
				break;
			}
		if (out_len > num_read)
			out_len = num_read;
		if (tmp_buff[out_len-2] == DOS_EOF)
			out_len -= 2;
		else if (tmp_buff[out_len-1] == DOS_EOF)
			out_len -= 1;

		if( out_len > 0 &&
		    out_len != (i= fwrite(&tmp_buff[0], 1, out_len, out_stream)))
			error("Error writing %s.", out_file_name);

		} while (!feof(in_stream));

	fclose(out_stream);
	fclose(in_stream);
	if(same_name){
		unlink(in_file_name);
		in_stream = fopen(out_file_name, "r");
		out_stream = fopen(in_file_name, "w");
#ifdef _F_BIN
		setmode(fileno(in_stream), O_BINARY);
		setmode(fileno(out_stream), O_BINARY);
#endif
		while ((num_read = (unsigned)fread(tmp_buff, 1, sizeof tmp_buff, in_stream)) != 0) {
		   if( num_read != fwrite(tmp_buff, 1, num_read, out_stream))
			error("Error writing %s.", in_file_name);
		}
		fclose(out_stream);
		fclose(in_stream);
		unlink(out_file_name);
	}
	return (0);
}

void	error(format, args)
	char	*format;
	char	*args;
{
	fprintf(stderr, "dos2unix: ");
	fprintf(stderr, format, args);
	fprintf(stderr, "  %s.\n", strerror(errno));
	exit(1);
}

void usage()
{
	fprintf(stderr, "usage: dos2unix [ -ascii ] [ -iso ] [ -7 ] [ originalfile [ convertedfile ] ]\n");
	exit(1);
}

