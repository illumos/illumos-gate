/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/* Copyright 1995 by Sun Microsystems, Inc.
 * All rights are reserved.
 */

#include <stdio.h>
#include <signal.h>
#include "kdefs.h"
#include "ktable.h"

struct _cv_state {
        char **my_outbuf;
        size_t *my_outbytesleft;
        int invalid;
        int flush_obuf;
        char temp_obuf[5];
        int temp_obuf_cnt;
};

void AddChar (char Char, struct _cv_state *st);
void echo_conso(char code, struct _cv_state *st);
void echo_vowel(char code, struct _cv_state *st);


/* write Hangul 7-bit Standard code sequences (KSC 5601)
 * from Standard 2-byte Combination code(87-3).
 * also handles Hangul and English display modes */

int
write_21(code_2, st)
KCHAR code_2;
struct _cv_state *st;
{
	register KCHAR buffer;	/* buffer for Hangul code conversion */
	register char code_1;	/* 1-byte code converted */

	buffer = Y19_32[(short)INITIAL_SOUND(code_2) - 0x09] + BEG_OF_CONSO;
	code_1 = (char) buffer;
	if(code_1 != BEG_OF_CONSO)
		AddChar(code_1, st);

	buffer = Y21_32[(short)MIDDLE_SOUND(code_2)] + BEG_OF_VOW;
	code_1 = (char) buffer;
	if(code_1 != BEG_OF_VOW)
		echo_vowel(code_1, st);

	buffer = Y28_32[FINAL_SOUND(code_2) - 0x01] + BEG_OF_CONSO;
	code_1 = (char) buffer;
	if(code_1 != BEG_OF_CONSO)
		echo_conso(code_1, st);

	return(1);
}

void
echo_vowel(char code, struct _cv_state* st)
{
	switch (code) {
	case O_A:				/* o-a	0x6d */
		AddChar(O, st);
		AddChar(A, st);
		break;

	case O_AE:				/* o-ae	0x6e */
		AddChar(O, st);
		AddChar(AE, st);
		break;

	case O_I:				/* o-i	0x6f */
		AddChar(O, st);
		AddChar(I, st);
		break;

	case U_E:				/* u-e	0x74 */
		AddChar(U, st);
		AddChar(E, st);
		break;

	case U_EA:				/* u-ea	0x75 */
		AddChar(U, st);
		AddChar(EA, st);
		break;

	case U_I:				/* u-i	0x75 */
		AddChar(U, st);
		AddChar(I, st);
		break;

	case EU_I:				/* eu-i	0x7b */
		AddChar(EU, st);
		AddChar(I, st);
		break;

	default:
		AddChar(code, st);
		break;

	}
}

void
echo_conso(char code, struct _cv_state *st)
{
	switch (code) {
	case GIUG_SIOD:				/* gi-ug and si-od	0x43 */
		AddChar(GI_UG, st);
		AddChar(SI_OD, st);
		break;

	case NIUN_JIUD:				/* ni-un and ji-ud	0x45 */
		AddChar(NI_UN, st);
		AddChar(JI_UD, st);
		break;

	case NIUN_HIUD:				/* ni-un and hi-ud	0x46 */
		AddChar(NI_UN, st);
		AddChar(HI_UD, st);
		break;

	case RIUL_GIUG:				/* ri-ul and gi_ug	0x4a */
		AddChar(RI_UL, st);
		AddChar(GI_UG, st);
		break;

	case RIUL_MIUM:				/* ri-ul and mi_um	0x4b */
		AddChar(RI_UL, st);
		AddChar(MI_UM, st);
		break;

	case RIUL_BIUB:				/* ri-ul and bi_ub	0x4c */
		AddChar(RI_UL, st);
		AddChar(BI_UB, st);
		break;

	case RIUL_SIOD:				/* ri-ul and si-od	0x4d */
		AddChar(RI_UL, st);
		AddChar(SI_OD, st);
		break;

	case RIUL_TIGUT:			/* ri-ul and ti-gut	0x4e */
		AddChar(RI_UL, st);
		AddChar(TI_GUT, st);
		break;

	case RIUL_PIUP:				/* ri-ul and pi-up	0x4f */
		AddChar(RI_UL, st);
		AddChar(PI_UP, st);
		break;

	case RIUL_HIUD:				/* ri-ul and hi-ud	0x50 */
		AddChar(RI_UL, st);
		AddChar(HI_UD, st);
		break;

	case BIUB_SIOD:				/* bi-ub and si-od	0x54 */
		AddChar(BI_UB, st);
		AddChar(SI_OD, st);
		break;

	default :
		AddChar(code, st);
		break;
	}
}

#ifdef TESTPRINT
main(argc,argv)		/* Hangul 2-byte Combination code files
                           to 7-bit ASCII file conversion */
int argc;
char *argv[];
{
	int fd,i,n;
	char *myname;
	short buf[BUFSIZ];

	myname = argv[0];
	if(argc == 1){
		printf("usage: %s file ...\n",myname);
		exit(0);
	} else {
		while(--argc > 0){
			if((fd = open(*++argv,0)) == -1){
				printf("%s: can't open %s\n",myname,*argv);
			} else {
				while ((n = read(fd,buf,bufsize)) > 0){
					for (i = 0; i < n/2; i++)
						write_21(buf[i]);
				}
				close(fd);
			}
		}
	}
}
#endif
