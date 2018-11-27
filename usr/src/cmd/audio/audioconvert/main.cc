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
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>

#include <convert.h>

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif

const char	*opt_string = "pf:o:i:FTD?";

char		*Stdin;
char		*Stdout;
char		*Suffix = (char *)".AUDCVTMP";

char		*progname; // program name
char		*fake_argv[] = {(char *)"-", NULL}; // stdin with no args

extern char	*optarg;
extern int	optind;

int		Statistics = 0;
int		Debug = 0;

void		init_header(AudioHdr&);
void		usage();

int
main(int argc, char *argv[])
{
	AudioUnixfile*	ifp = NULL;	// input & output audio objects
	AudioUnixfile*	ofp = NULL;
	AudioHdr	ihdr;		// input/output headers
	AudioHdr	ohdr;
	char		*infile = NULL; // input/output file names
	char		*outfile = NULL;
	char		*realfile = NULL;
	char		*out_fmt = NULL;	// output fmt string
	AudioError	err;		// for error msgs
	int		c;		// for getopt
	int		pflag = 0;	// in place flag
	int		fflag = 0;	// ignore header (force conversion)
	int		stdin_seen = 0;	// already read stdin
	int		israw = 0;	// once we've seen -i, it's raw data
	format_type	ofmt = F_SUN;	// output format type
	format_type	ifmt = F_SUN;	// expected input format type
	format_type	fmt = F_SUN;	// actual input format type
	off_t		o_offset = 0;	// output offset (ignored)
	off_t		i_offset = 0;	// input offset
	int		i;
	struct stat	st;

	setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	// basename of program
	if (progname = strrchr(argv[0], '/')) {
		progname++;
	} else {
		progname = argv[0];
	}
	Stdin = MGET("(stdin)");
	Stdout = MGET("(stdout)");

	// init the input & output headers
	init_header(ihdr);
	init_header(ohdr);

	// some conversions depend on invocation name. we'll create
	// default input/output formats based on argv[0] that
	// can be overridden by -o or -i options.
	if (strcmp(progname, "ulaw2pcm") == 0) {
		(void) parse_format((char *)"ulaw", ihdr, ifmt, i_offset);
		(void) parse_format((char *)"pcm", ohdr, ofmt, o_offset);
	} else if (strcmp(progname, "pcm2ulaw") == 0) {
		(void) parse_format((char *)"pcm", ihdr, ifmt, i_offset);
		(void) parse_format((char *)"ulaw", ohdr, ofmt, o_offset);
	} else if (strcmp(progname, "adpcm_enc") == 0) {
		(void) parse_format((char *)"ulaw", ihdr, ifmt, i_offset);
		(void) parse_format((char *)"g721", ohdr, ofmt, o_offset);
	} else if (strcmp(progname, "adpcm_dec") == 0) {
		(void) parse_format((char *)"g721", ihdr, ifmt, i_offset);
		(void) parse_format((char *)"ulaw", ohdr, ofmt, o_offset);
	} else if (strcmp(progname, "raw2audio") == 0) {
		(void) parse_format((char *)"ulaw", ihdr, ifmt, i_offset);
		(void) parse_format((char *)"ulaw", ohdr, ofmt, o_offset);
		israw++;
		pflag++;
	} else if (argc <= 1) {
		// audioconvert with no arguments
		usage();
	}

	// now parse the rest of the arg's
	while ((c = getopt(argc, argv, opt_string)) != -1) {
		switch (c) {
#ifdef DEBUG
		case 'D':
			// enable debug messages
			Debug++;
			break;
#endif
		case 'p':
			// convert files in place
			if (outfile != NULL) {
				Err(MGET("can't use -p with -o\n"));
				exit(1);
			}
			pflag++;
			break;
		case 'F':
			// force treatment of audio files as raw files
			// (ignore filehdr).
			fflag++;
			break;
		case 'f':
			// save format string to parse later, but verify now
			out_fmt = optarg;
			if (parse_format(out_fmt, ohdr, ofmt, o_offset) == -1)
				exit(1);
			if (o_offset != 0) {
				Err(MGET("can't specify an offset with -f\n"));
				exit(1);
			}
			break;
		case 'o':
			if (pflag) {
				Err(MGET("can't use -o with -p\n"));
				exit(1);
			}
			outfile = optarg;
			break;
		case 'i':
			// if bogus input header, exit ...
			if (parse_format(optarg, ihdr, ifmt, i_offset) == -1) {
				exit(1);
			}
			israw++;
			break;
		default:
		case '?':
			usage();
		}
	}

	// XXX - should check argument consistency here....

	// If no args left, we're taking input from stdin.
	// In this case, make argv point to a fake argv with "-" as a file
	// name, and set optind and argc apropriately so we'll go through
	// the loop below once.
	if (optind >= argc) {
		argv = fake_argv;
		argc = 1;
		optind = 0;
		/*
		 * XXX - we turn off pflag if stdin is the only input file.
		 * this is kind of a hack. if invoked as raw2audio, pflag
		 * it turned on. if no files are given, we want to turn
		 * it off, otherwise we'll complain about using -p with
		 * stdin, which won't make sense if invoked as raw2audio.
		 * instead, just silently ignore. the message is still given
		 * and stdin is ignored if it's specified as one of several
		 * input files.
		 */
		pflag = 0;
	}

	// From this point on we're looking at file names or -i args
	// for input format specs.
	for (; optind < argc; optind++) {
		// new input format spec.
		if (strcmp(argv[optind], "-i") == 0) {
			init_header(ihdr);
			i_offset = 0;
			ifmt = F_SUN;
			// if bogus input header, exit ...
			if (parse_format(argv[++optind], ihdr, ifmt, i_offset)
			    == -1) {
				exit(1);
			}
			israw++;
		} else if (strcmp(argv[optind], "-") == 0) {
			// ignore stdin argument if in place
			if (pflag) {
				Err(MGET("can't use %s with -p flag\n"),
				    Stdin);
				continue;
			}

			if (stdin_seen) {
				Err(MGET("already used stdin for input\n"));
				continue;
			} else {
				stdin_seen++;
			}

			infile = Stdin;
		} else {
			infile = argv[optind];
		}

		// if no audio object returned, just continue to the next
		// file. if a fatal error occurs, open_input_file()
		// will exit the program.
		ifp =
		    open_input_file(infile, ihdr, israw, fflag, i_offset, fmt);
		if (!ifp) {
			continue;
		}

		if ((err = ifp->Open()) != AUDIO_SUCCESS) {
			Err(MGET("open error on input file %s - %s\n"),
			    infile, err.msg());
			exit(1);
		}
		ifp->Reference();

		// create the output file if not created yet, or if
		// converting in place. ofp will be NULL only the first
		// time through. use the header of the first input file
		// to base the output format on - then create the output
		// header w/the output format spec.
		if ((ofp == NULL) && !pflag) {

			ohdr = ifp->GetHeader();
			ohdr = ifp->GetHeader();
			ofmt = ifmt;
			// just use input hdr if no output hdr spec
			if (out_fmt) {
				if (parse_format(out_fmt, ohdr, ofmt, o_offset)
				    == -1) {
					exit(1);
				}
			}

			// need to check before output is opened ...
			if (verify_conversion(ifp->GetHeader(), ohdr) == -1) {
				// XXX - bomb out or skip?
				exit(3);
			}

			// Create the file and set the info string.
			char		*infoString;
			int		infoStringLen;
			infoString = ifp->GetInfostring(infoStringLen);
			ofp = create_output_file(outfile, ohdr, ofmt,
						    infoString);

		} else if (pflag) {

			// create new output header based on each input file
			ohdr = ifp->GetHeader();
			ofmt = ifmt;
			// just use input hdr if no output hdr spec
			if (out_fmt) {
				if (parse_format(out_fmt, ohdr, ofmt, o_offset)
				    == -1) {
					exit(1);
				}
			}

			// get the *real* path of the infile (follow sym-links),
			// and the stat info.
			realfile = infile;
			get_realfile(realfile, &st);

			// if the file is read-only, give up
			if (access(realfile, W_OK)) {
				// XXX - do we really want to exit?
				perror(infile);
				Err(MGET("cannot rewrite in place\n"));
				exit(1);
			}

			// this is now the output file.
			i = strlen(realfile) + strlen(Suffix) + 1;
			outfile = (char *)malloc((unsigned)i);
			if (outfile == NULL) {
				Err(MGET("out of memory\n"));
				exit(1);
			}
			(void) sprintf(outfile, "%s%s", realfile, Suffix);

			// outfile will get re-assigned to a tmp file
			if (verify_conversion(ifp->GetHeader(), ohdr) == -1) {
				// XXX - bomb out or skip?
				exit(3);
			}

			// If no conversion, just skip the file
			if (noop_conversion(ifp->GetHeader(), ohdr,
			    fmt, ofmt, i_offset, o_offset)) {
				if (Debug)
				    Err(MGET(
					"%s: no-op conversion...skipping\n"),
					infile);
				continue;
			}

			// Get the input info string.
			char		*infoString;
			int		infoStringLen;
			infoString = ifp->GetInfostring(infoStringLen);
			ofp = create_output_file(outfile, ohdr, ofmt,
						    infoString);
		}

		// verify that it's a valid conversion by looking at the
		// file headers. (this will be called twice for the first
		// file if *not* converting in place. that's ok....
		if (!pflag && (verify_conversion(ifp->GetHeader(), ohdr)
		    == -1)) {
			// XXX - bomb out or skip file if invalid conversion?
			exit(3);
		}

		// do the conversion, if error, bomb out
		if (do_convert(ifp, ofp) == -1) {
			exit(4);
		}

		ifp->Close();
		ifp->Dereference();

		// if in place, finish up by renaming the outfile to
		// back to the infile.
		if (pflag) {
			delete(ofp);	// will close and deref, etc.

			if (rename(outfile, realfile) < 0) {
				perror(outfile);
				Err(MGET("error renaming %s to %s"),
				    outfile, realfile);
				exit(1);
			}
			/* Set the permissions to match the original */
			if (chmod(realfile, (int)st.st_mode) < 0) {
				Err(MGET("WARNING: could not reset mode of"));
				perror(realfile);
			}
		}
	}

	if (!pflag) {
		delete(ofp);		// close output file
	}

	return (0);
}


// initialize audio hdr to default val's
void
init_header(
	AudioHdr&	hdr)
{
	hdr.encoding = NONE;
	hdr.sample_rate = 0;
	hdr.samples_per_unit = 0;
	hdr.bytes_per_unit = 0;
	hdr.channels = 0;
}

extern "C" { void _doprnt(char *, ...); }

// report a fatal error and exit
void
Err(char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fprintf(stderr, "%s: ", progname);
	_doprnt(format, ap, stderr);
	fflush(stderr);
	va_end(ap);
}

void
usage()
{
	fprintf(stderr, MGET(
	    "Convert between audio file formats and data encodings -- usage:\n"
	    "\t%s [-pF] [-f outfmt] [-o outfile] [[-i infmt] [file ...]] ...\n"
	    "where:\n"
	    "\t-p\tConvert files in place\n"
	    "\t-F\tForce interpretation of -i (ignore existing file hdr)\n"
	    "\t-f\tOutput format description\n"
	    "\t-o\tOutput file (default: stdout)\n"
	    "\t-i\tInput format description\n"
	    "\tfile\tList of files to convert (default: stdin)\n\n"
	    "Format Description:\n"
	    "\tkeyword=value[,keyword=value...]\n"
	    "where:\n"
	    "\tKeywords:\tValues:\n"
	    "\trate\t\tSample Rate in samples/second\n"
	    "\tchannels\tNumber of interleaved channels\n"
	    "\tencoding\tAudio encoding. One of:\n"
	    "\t\t\t    ulaw, alaw, g721, g723,\n"
	    "\t\t\t    linear8, linear16, linear32\n"
	    "\t\t\t    pcm   (same as linear16)\n"
	    "\t\t\t    voice (ulaw,mono,rate=8k)\n"
	    "\t\t\t    cd    (linear16,stereo,rate=44.1k)\n"
	    "\t\t\t    dat   (linear16,stereo,rate=48k)\n"
	    "\tformat\t\tFile format. One of:\n"
	    "\t\t\t    sun, raw (no format)\n"
	    "\toffset\t\tByte offset (raw input only)\n"),
	    progname);
	exit(1);
}
