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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "signal.h"
#include "stdio.h"
#include "errno.h"

#include "lp.h"
#include "msgs.h"
#include "string.h"

void			startup(),
			cleanup(),
			done();

extern char		*getenv(),
			*malloc(),
			*realloc();

extern long		atol();

extern int		atoi();

static void		wakeup();
extern char    *optarg;
extern int     optind, opterr, optopt;
int optsw;

#define PREFIX_STRING "%%["
#define SUFFIX_STRING "]%%"
#define PRINTER_ERROR_STRING "PrinterError:"
#define STATUS_STRING "status:"
#define JOB_STRING "job:"
#define STATUS_OK_STRING "ready and printing"
#define PAPER_CHANGED_STRING "paper changed:"

/*
 * Some common postscript printer fault messages.
 * These strings are here so that they get l10ned and then lpstat will
 * be able to display them in the users language.
 * This seemed like a good place for them, since lp.tell knows about
 * postscript msgs.
 */

char *ps_m1 = "unable to print: out of media (paper)";
char *ps_m2 = "out of media (paper)";
char *ps_m3 = "unable to print: tray not (properly) installed";
char *ps_m4 = "tray not (properly) installed";
char *ps_m5 = "unable to print: paper out for the selected tray";
char *ps_m6 = "paper out for the selected tray";
char *ps_m7 = "unable to print: cartridge life expiring";
char *ps_m8 = "cartridge life expiring";
char *ps_m9 = "unable to print: printer cover not locked";
char *ps_m10 = "printer cover not locked";
char *ps_m11 = "unable to print: media (paper) jam in exit path";
char *ps_m12 = "media (paper) jam in exit path";
char *ps_m13 = "unable to print: media (paper) jam in feed path";
char *ps_m14 = "media (paper) jam in feed path";
char *ps_m15 = "unable to print: drum assembly almost expended";
char *ps_m16 = "drum assembly almost expended";
char *ps_m17 = "unable to print: toner cartridge almost expended";
char *ps_m18 = "toner cartridge almost expended";
char *ps_m19 = "unable to print: drum assembly not (properly) installed";
char *ps_m20 = "drum assembly not (properly) installed";
char *ps_m21 = "unable to print: toner cartridge not (properly) installed";
char *ps_m22 = "toner cartridge not (properly) installed";
char *ps_m23 = "unable to print: drum assembly requires replacement";
char *ps_m24 = "drum assembly requires replacement";
char *ps_m25 = "unable to print: toner cartridge requires replacement";
char *ps_m26 = "toner cartridge requires replacement";
char *ps_m27 = "unable to print: fuser warming up";
char *ps_m28 = "fuser warming up";
char *ps_m29 = "unable to print: printer not responding";
char *ps_m30 = "printer not responding";
char *ps_m31 = "unable to print: fuser pausing";
char *ps_m32 = "fuser pausing";
char *ps_m33 = "unable to print: printer turned off";
char *ps_m34 = "printer turned off";
char *ps_m35 = "unable to print: printer warming up";
char *ps_m36 = "printer warming up";
char *ps_m37 = "unable to print: interlock open";
char *ps_m38 = "interlock open";
char *ps_m39 = "unable to print: selected tray out";
char *ps_m40 = "selected tray out";
char *ps_m41 = "unable to print: paper out for the manual tray";
char *ps_m42 = "paper out for the manual tray";
char *ps_m43 = "unable to print: paper exit jam";
char *ps_m44 = "paper exit jam";
char *ps_m45 = "unable to print: paper misfeed jam";
char *ps_m46 = "paper misfeed jam";
char *ps_m47 = "unable to print: paper jam between registration & heat rollers";
char *ps_m48 = "paper jam between registration & heat rollers";
char *ps_m49 = "unable to print: paper jam at registration roller";
char *ps_m50 = "paper jam at registration roller";
char *ps_m51 = "unable to print: no cartridge";
char *ps_m52 = "no cartridge";
char *ps_m53 = "unable to print: cartridge out";
char *ps_m54 = "cartridge out";

/**
 ** main()
 **/

int
main(int argc, char *argv[])
{
	char			*alert_text,
				buf[BUFSIZ],
				msgbuf[MSGMAX],
				*bufPtr,
				*printer,
				*s_key;

	char *printerErrorString = NULL;
	char *statusString = NULL;
	char *paperChangedString = NULL;
	char *suffixString = NULL;
	char *jobString = NULL;
	char *prefixString = NULL;
	char *statusOkString = NULL;
	int			mtype,
               doStdOut,
					doDebug,
					first,
				oldalarm;
		

	short			status;

	long			key,clearKey;
	char *ptr1,*ptr2,*ptr3,*ptr4,*ptr5;
	int trayNum = 0;
	int mode = 0;
	int pagesPrinted = 0;
	char *paperType = NULL;
	short mesgRetType;
	int useLaserWriterMessages;
	int pLen,sLen,peLen,jLen,pcLen ;

	void			(*oldsignal)();


	/*
	 * Run immune from typical interruptions, so that
	 * we stand a chance to get the fault message.
	 * EOF (or startup error) is the only way out.
	 */
	signal (SIGHUP, SIG_IGN);
	signal (SIGINT, SIG_IGN);
	signal (SIGQUIT, SIG_IGN);
	signal (SIGTERM, SIG_IGN);

	/*
	 *  Do we have a key?
	 */
	if (
		argc < 2 
	     || !(s_key = getenv("SPOOLER_KEY"))
	     || !*s_key
	     || (key = atol(s_key)) <= 0
	) {
		printf( "Usage: lptell [-lodk] [-X String]  printer\n");
		printf("Options (where X is P,S,e,s, O or c )\n");
		printf("   environment variable SPOOLER_KEY: must be defined and > 0\n");
		printf("   printer: name of printer to give status for.\n");
		printf("   -l: expect laser writer type messages (NeWSprint does)\n");
		printf("   -o: send input to stdout\n");
		printf("   -d: send additional debugging output to stdout\n");
		printf("   -P String: string for prefix, default: '%%%%['\n");
		printf("   -S String: string for suffix, default: ']%%%%'\n");
		printf("   -e String: string to detect printer error,\n");
		printf("       default: 'PrinterError:', send S_SEND_FAULT to lpsched\n");
		printf(
		"   -c String: string to detect paper change in context of printer error,\n");
		printf("       default: 'paper changed:', send S_PAPER_CHANGED to lpsched\n");
		printf("   -s String: string to detect printer ok status, \n");
		printf("       default: 'status:', send S_CLEAR_FAULT to lpsched\n");
		printf("       -k: do not use the key for making status ok\n");
		printf("   -O String: string sent as status message to lpsched,\n");
		printf("                  default: 'ready and printing:'\n");
		exit (90);
		  }


	doStdOut = 0;
	doDebug = 0;
	useLaserWriterMessages = 0;
	clearKey = key;

	prefixString = PREFIX_STRING; pLen = strlen(prefixString);
	suffixString = SUFFIX_STRING; 
	printerErrorString = PRINTER_ERROR_STRING; 
	  peLen = strlen(printerErrorString);
	statusString = STATUS_STRING; sLen = strlen(statusString);
	jobString = JOB_STRING; jLen = strlen(jobString);
	paperChangedString = PAPER_CHANGED_STRING; 
	  pcLen = strlen(paperChangedString);
	statusOkString = STATUS_OK_STRING; 

   while ((optsw = getopt(argc, argv, "le:s:c:okdO:S:P:")) != EOF) {
		switch ( optsw ) {
			case 'l':
				useLaserWriterMessages = 1;
				break;
			case 'P':
				prefixString = (optarg  ? strdup(optarg) : NULL);
				pLen = strlen(prefixString );
				break;
			case 'S':
				suffixString = (optarg  ? strdup(optarg) : NULL);
				break;
			case 'e':
				printerErrorString = (optarg  ? strdup(optarg) : NULL);
				peLen = strlen(printerErrorString);
				break;
			case 's':
				statusString = (optarg  ? strdup(optarg) : NULL);
				sLen = strlen(statusString);
				break;
			case 'O':
				statusOkString = (optarg  ? strdup(optarg) : NULL);
				break;
			case 'c':
				paperChangedString = (optarg  ? strdup(optarg) : NULL);
				pcLen = strlen(paperChangedString );
				break;
			case 'k':
				clearKey = -1;
				break;
			case 'o':
				doStdOut = 1;
				break;
			case 'd':
				doDebug = 1;
				break;
			}
		}
	/*
	 * Which printer is this? Do we have a key?
	 */
	if (
	     !(printer = argv[optind])
	     || !*printer
	) {
		exit (90);
		  }
	if (doDebug) {
		printf( "start lp.tell for %s key %d mode %s %s\n", 
				printer,key,(useLaserWriterMessages ? "LW" : "standard"),
				(doStdOut ? "doStdOut" : "no output"));
		printf( "prefix (%s) suffix (%s) printerError (%s)\n",
			  prefixString,suffixString,printerErrorString);
		printf( "paper_changed (%s) status (%s) key %d \n",
			paperChangedString,statusString , clearKey);
		fflush(stdout);
	   }
	/*
	 * Wait for a message on the standard input. When a single line
	 * comes in, take a couple of more seconds to get any other lines
	 * that may be ready, then send them to the Spooler.
	 */
	while (fgets(buf, BUFSIZ, stdin)) {
		if (useLaserWriterMessages) {
			/* NeWSprint style processing (which simulates the LaserWriter
			 *There are four types of messages:
			 * 	1) fault messages: printer error message from handler
			 * 	2) clear fault messages: printer ok messages from handler
			 * 	3) paper changed messages: printer handler detected paper change
			 * 	4) server messages: xnews problems
			 */
			bufPtr = buf;
			if (strncmp(prefixString, bufPtr, pLen) == 0) {
				bufPtr += pLen;
				while (*bufPtr == ' ')
					bufPtr++;
					
				if (strncmp(printerErrorString, bufPtr,
						peLen) == 0) {
					bufPtr += peLen;
					while (*bufPtr == ' ')
						bufPtr++;

					if ((strncmp(bufPtr,paperChangedString,pcLen) == 0) &&
							 (ptr1 = bufPtr +pcLen) && 
							 (ptr2 = strchr(ptr1+1,':')) && 
							 (ptr3 = strchr(ptr2+1,':')) &&
							 (ptr4 = strchr(ptr3+1,':')) && 
							 (ptr5 = strchr(ptr4+1,'\n'))) {
						if (doStdOut) printf("%s",buf); 
						*ptr2 =0;
						*ptr3= 0;
						*ptr4= 0;
						*ptr5= 0;
						trayNum = atoi(ptr1+1);
						paperType = ptr2+1;
						mode = atoi(ptr3+1);
						pagesPrinted = atoi(ptr4+1);
						if (doDebug) {
							 printf("Paper changed: %s tray %d paper %s md %d pages %d\n",
								printer,trayNum,paperType,mode,pagesPrinted);
							}
						startup ();
						mesgRetType = R_PAPER_CHANGED;
						(void)putmessage ( msgbuf, S_PAPER_CHANGED, printer, trayNum,
							paperType, mode, pagesPrinted);
					} else {
						if (doStdOut)  printf("%s",buf); 
						if (ptr1 = strstr(bufPtr,suffixString))  *ptr1 = 0; 
						if ( doDebug ) {
							printf("Send fault: %s key %d (%s)\n",printer,key,bufPtr);
						}
						mesgRetType = R_SEND_FAULT;
						startup ();
						(void)putmessage (msgbuf,S_SEND_FAULT,printer,key,bufPtr);
					}
				} else if ((first = (strncmp(statusString,bufPtr,sLen) == 0)) ||
							 (strncmp(jobString,bufPtr,jLen) == 0)) {
					bufPtr += (first ? sLen : jLen);
					if (doStdOut)  printf("%s",buf);
					if (ptr1 = strstr(bufPtr,suffixString))  *ptr1 = 0;
					if ( doDebug ) {
						printf("Clear fault: %s key %d (%s)\n",printer, clearKey,
							  bufPtr);
						}
					mesgRetType = R_CLEAR_FAULT;
					startup ();
					(void)putmessage( msgbuf,S_CLEAR_FAULT,printer,clearKey,
						statusOkString);
				} else {
					if (doStdOut)  printf("%s",buf); 
					if (ptr1 = strstr(bufPtr,suffixString))  *ptr1 = 0;
					if ( doDebug ) {
						printf("Server error: %s key %d (%s)\n",printer,key,
							 buf);
					}
					mesgRetType = 0;
				}
			} else {
				if (doStdOut) printf("%s",buf); 
				if (ptr1 = strstr(bufPtr,suffixString))
					*ptr1 = 0;
				if (doDebug) {
					printf("Server error: %s key %d (%s)\n",
						printer, key, buf);
				}
				mesgRetType = 0;
			}
		} else {	/* not generic PostScript style messages */
			oldsignal = signal(SIGALRM, wakeup);
			oldalarm = alarm(2);

			alert_text = 0;
			do {
				if (alert_text)
					alert_text = realloc(alert_text,
						strlen(alert_text)+strlen(buf)+1
					);
				else {
					alert_text = malloc(strlen(buf) + 1);
					alert_text[0] = 0;
				}
				strcat (alert_text, buf);
	 
			} while (fgets(buf, BUFSIZ, stdin));
	 
			alarm (oldalarm);
			signal (SIGALRM, oldsignal);

			if (doStdOut) {
				if ( doDebug ) {
					printf("Send generic fault: %s key %d (%s)\n",printer,key,
						alert_text);
					}
				else {
					printf("%s\n",alert_text);
					}
				}
			if (strcmp(alert_text, "printer ok\n") == 0) {
				mesgRetType = R_CLEAR_FAULT;
				startup ();
				(void)putmessage(msgbuf, S_CLEAR_FAULT, printer,
						clearKey, statusOkString);
			} else {
         			mesgRetType = R_SEND_FAULT;
				startup ();
				(void)putmessage(msgbuf, S_SEND_FAULT, printer,
						key, alert_text); 
			}  
		}

		if (mesgRetType) {
			if (msend(msgbuf) == -1)
				done (91);
			if (mrecv(msgbuf, sizeof(msgbuf)) == -1)
				done (92);
			mtype = getmessage(msgbuf, mesgRetType, &status);
			/*
			 * check for R_CLEAR_FAULT here and 3 lines below
			 * because older lpsched doesn't pass S_CLEAR_FAULT
			 */
			if ((mtype != mesgRetType) &&
			    (mesgRetType != R_CLEAR_FAULT))
				done (93);

			if ((status != MOK) && (mesgRetType != R_CLEAR_FAULT))
				done (94);
		}
		
	}
	done (0);

	return (0);
}

/**
 ** startup() - OPEN MESSAGE QUEUE TO SPOOLER
 ** cleanup() - CLOSE THE MESSAGE QUEUE TO THE SPOOLER
 **/

static int		have_contacted_spooler	= 0;

void			startup ()
{
	void			catch();

	/*
	 * Open a message queue to the Spooler.
	 * An error is deadly.
	 */
	if (!have_contacted_spooler) {
		if (mopen() == -1) {
	
			switch (errno) {
			case ENOMEM:
			case ENOSPC:
				break;
			default:
				break;
			}

			exit (1);
		}
		have_contacted_spooler = 1;
	}
	return;
}

void			cleanup ()
{
	if (have_contacted_spooler)
		mclose ();
	return;
}

/**
 ** wakeup() - TRAP ALARM
 **/

static void		wakeup ()
{
	return;
}

/**
 ** done() - CLEANUP AND EXIT
 **/

void			done (ec)
	int			ec;
{
	cleanup ();
	exit (ec);
}
