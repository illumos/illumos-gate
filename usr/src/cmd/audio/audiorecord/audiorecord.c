/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Command-line audio record utility */

#include <stdio.h>
#include <libgen.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <locale.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>	/* All occurances of INT_MAX used to be ~0  (by MCA) */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stropts.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <libaudio.h>
#include <audio_device.h>

#define	irint(d)	((int)d)

/* localization stuff */
#define	MGET(s)		(char *)gettext(s)

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif

#define	Error		(void) fprintf

/* Local variables */
static char	*prog;
static char	prog_opts[] = "aft:v:d:i:e:s:c:T:?"; /* getopt() flags */
static char	*Stdout;

/* XXX - the input buffer size should depend on sample_rate */
#define	AUDIO_BUFSIZ (1024 * 64)
static unsigned char	buf[AUDIO_BUFSIZ];
static char 		swapBuf[AUDIO_BUFSIZ];	/* for byte swapping */


#define	MAX_GAIN		(100)	/* maximum gain */

static char	*Info = NULL;		/* pointer to info data */
static unsigned	Ilen = 0;		/* length of info data */
static unsigned	Volume = INT_MAX;	/* record volume */
static double	Savevol;		/* saved  volume */
static unsigned	Sample_rate = 0;
static unsigned	Channels = 0;
static unsigned	Precision = 0;		/* based on encoding */
static unsigned	Encoding = 0;

static int	NetEndian = TRUE;	/* endian nature of the machines */

static int	Append = FALSE;		/* append to output file */
static int	Force = FALSE;		/* ignore rate differences on append */
static double	Time = -1.;		/* recording time */
static unsigned	Limit = AUDIO_UNKNOWN_SIZE;	/* recording limit */
static char	*Audio_dev = "/dev/audio";

static int		Audio_fd = -1;
			/* file descriptor for audio device */
static Audio_hdr	Dev_hdr;		/* audio header for device */
static Audio_hdr	Save_hdr;		/* saved audio device header */
static char		*Ofile;			/* current filename */
static int		File_type = FILE_AU;	/* audio file type */
static int		File_type_set = FALSE;	/* file type specified as arg */
static Audio_hdr	File_hdr;		/* audio header for file */
static int		Cleanup = FALSE;	/* SIGINT sets this flag */
static unsigned		Size = 0;		/* Size of output file */
static unsigned		Oldsize = 0;
			/* Size of input file, if append */

/* Global variables */
extern int getopt();
extern int optind;
extern char *optarg;

/* Local Functions */
static void usage(void);
static void sigint(int sig);
static int parse_unsigned(char *str, unsigned *dst, char *flag);
static int parse_sample_rate(char *s, unsigned *rate);


static void
usage(void)
{
	Error(stderr, MGET("Record an audio file -- usage:\n"
	    "\t%s [-af] [-v vol]\n"
	    "\t%.*s [-c channels] [-s rate] [-e encoding]\n"
	    "\t%.*s [-t time] [-i info] [-d dev] [-T au|wav|aif[f]] [file]\n"
	    "where:\n"
	    "\t-a\tAppend to output file\n"
	    "\t-f\tIgnore sample rate differences on append\n"
	    "\t-v\tSet record volume (0 - %d)\n"
	    "\t-c\tSpecify number of channels to record\n"
	    "\t-s\tSpecify rate in samples per second\n"
	    "\t-e\tSpecify encoding (ulaw | alaw | [u]linear | linear8 )\n"
	    "\t-t\tSpecify record time (hh:mm:ss.dd)\n"
	    "\t-i\tSpecify a file header information string\n"
	    "\t-d\tSpecify audio device (default: /dev/audio)\n"
	    "\t-T\tSpecify the audio file type (default: au)\n"
	    "\tfile\tRecord to named file\n"
	    "\t\tIf no file specified, write to stdout\n"
	    "\t\tDefault audio encoding is ulaw, 8khz, mono\n"
	    "\t\tIf -t is not specified, record until ^C\n"),
	    prog,
	    strlen(prog), "                    ",
	    strlen(prog), "                    ",
	    MAX_GAIN);
	exit(1);
}

static void
sigint(int sig)
{
	/* If this is the first ^C, set a flag for the main loop */
	if (!Cleanup && (Audio_fd >= 0)) {
		/* flush input queues before exiting */
		Cleanup = TRUE;
		if (audio_pause_record(Audio_fd) == AUDIO_SUCCESS)
			return;
		Error(stderr, MGET("%s: could not flush input buffer\n"), prog);
	}

	/* If double ^C, really quit */
	if (Audio_fd >= 0) {
		if (Volume != INT_MAX)
			(void) audio_set_record_gain(Audio_fd, &Savevol);
		if (audio_cmp_hdr(&Save_hdr, &Dev_hdr) != 0) {
			(void) audio_set_record_config(Audio_fd, &Save_hdr);
		}
	}
	exit(1);
}

/*
 * Record from the audio device to a file.
 */
int
main(int argc, char **argv)
{
	int		i;
	int		cnt;
	int		err;
	int		file_type;
	int		ofd;
	int 		swapBytes = FALSE;
	double		vol;
	struct stat	st;
	struct pollfd	pfd;
	char		*cp;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* Get the program name */
	prog = strrchr(argv[0], '/');
	if (prog == NULL)
		prog = argv[0];
	else
		prog++;
	Stdout = MGET("(stdout)");

	/* first check AUDIODEV environment for audio device name */
	if (cp = getenv("AUDIODEV")) {
		Audio_dev = cp;
	}

	/* Set the endian nature of the machine */
	if ((ulong_t)1 != htonl((ulong_t)1)) {
		NetEndian = FALSE;
	}

	err = 0;
	while ((i = getopt(argc, argv, prog_opts)) != EOF) {
		switch (i) {
		case 'v':
			if (parse_unsigned(optarg, &Volume, "-v")) {
				err++;
			} else if (Volume > MAX_GAIN) {
				Error(stderr, MGET("%s: invalid value for "
				"-v\n"), prog);
				err++;
			}
			break;
		case 't':
			Time = audio_str_to_secs(optarg);
			if ((Time == HUGE_VAL) || (Time < 0.)) {
				Error(stderr, MGET("%s: invalid value for "
				"-t\n"), prog);
				err++;
			}
			break;
		case 'd':
			Audio_dev = optarg;
			break;
		case 'f':
			Force = TRUE;
			break;
		case 'a':
			Append = TRUE;
			break;
		case 'i':
			Info = optarg;		/* set information string */
			Ilen = strlen(Info);
			break;
		case 's':
			if (parse_sample_rate(optarg, &Sample_rate)) {
				err++;
			}
			break;
		case 'c':
			if (strncmp(optarg, "mono", strlen(optarg)) == 0) {
				Channels = 1;
			} else if (strncmp(optarg, "stereo",
			    strlen(optarg)) == 0) {
				Channels = 2;
			} else if (parse_unsigned(optarg, &Channels, "-c")) {
				err++;
			} else if ((Channels != 1) && (Channels != 2)) {
				Error(stderr, "%s: invalid value for -c\n",
				    prog);
				err++;
			}
			break;
		case 'e':
			if (strncmp(optarg, "ulinear", strlen(optarg)) == 0) {
				Encoding = AUDIO_ENCODING_LINEAR8;
				Precision = 8;
			} else if (strncmp(optarg, "linear8",
			    strlen("linear8")) == 0) {
				Encoding = AUDIO_ENCODING_LINEAR;
				Precision = 8;
			} else if (strncmp(optarg, "ulaw",
			    strlen(optarg)) == 0) {
				Encoding = AUDIO_ENCODING_ULAW;
				Precision = 8;
			} else if (strncmp(optarg, "alaw",
			    strlen(optarg)) == 0) {
				Encoding = AUDIO_ENCODING_ALAW;
				Precision = 8;
			} else if ((strncmp(optarg, "linear",
			    strlen(optarg)) == 0) || (strncmp(optarg, "pcm",
			    strlen(optarg)) == 0)) {
				Encoding = AUDIO_ENCODING_LINEAR;
				Precision = 16;
			} else {
				Error(stderr, MGET("%s: invalid value for "
				    "-e\n"), prog);
				err++;
			}
			break;
		case 'T':
			if (strncmp(optarg, "au", strlen(optarg)) == 0) {
				File_type = FILE_AU;
			} else if (strncmp(optarg, "wav",
			    strlen(optarg)) == 0) {
				File_type = FILE_WAV;
			} else if (strncmp(optarg, "aif",
			    strlen(optarg)) == 0) {
				File_type = FILE_AIFF;
			} else if (strncmp(optarg, "aiff",
			    strlen(optarg)) == 0) {
				File_type = FILE_AIFF;
			} else {
				Error(stderr, MGET("%s: invalid value for "
				    "-T\n"), prog);
				err++;
			}
			File_type_set = TRUE;
			break;
		case '?':
			usage();
	/*NOTREACHED*/
		}
	}
	if (Append && (Info != NULL)) {
		Error(stderr, MGET("%s: cannot specify -a and -i\n"), prog);
		err++;
	}
	if (err > 0)
		exit(1);

	argc -= optind;		/* update arg pointers */
	argv += optind;

	/* Open the output file */
	if (argc <= 0) {
		Ofile = Stdout;
	} else {
		Ofile = *argv++;
		argc--;

		/* Interpret "-" filename to mean stdout */
		if (strcmp(Ofile, "-") == 0)
			Ofile = Stdout;

		/* if -T not set then we use the file suffix */
		if (File_type_set == FALSE) {
			char	*file_name;
			char	*start;

			/* get the file name without the path */
			file_name = basename(Ofile);

			/* get the true suffix */
			start = strrchr(file_name, '.');

			/* if no '.' then there's no suffix */
			if (start) {
				/* is this a .au file? */
				if (strcasecmp(start, ".au") == 0) {
					File_type = FILE_AU;
				} else if (strcasecmp(start, ".wav") == 0) {
					File_type = FILE_WAV;
				} else if (strcasecmp(start, ".aif") == 0) {
					File_type = FILE_AIFF;
				} else if (strcasecmp(start, ".aiff") == 0) {
					File_type = FILE_AIFF;
				} else {
					/* the default is .au */
					File_type = FILE_AU;
				}
			} else {
				/* no suffix, so default to .au */
				File_type = FILE_AU;
			}
		}
	}

	if (Ofile == Stdout) {
		ofd = fileno(stdout);
		Append = FALSE;
	} else {
		ofd = open(Ofile,
		    (O_RDWR | O_CREAT | (Append ? 0 : O_TRUNC)), 0666);
		if (ofd < 0) {
			Error(stderr, MGET("%s: cannot open "), prog);
			perror(Ofile);
			exit(1);
		}
		if (Append) {
			/*
			 * Check to make sure we're appending to an audio file.
			 * It must be a regular file (if zero-length, simply
			 * write it from scratch).  Also, its file header
			 * must match the input device configuration.
			 */
			if ((fstat(ofd, &st) < 0) || (!S_ISREG(st.st_mode))) {
				Error(stderr,
				    MGET("%s: %s is not a regular file\n"),
				    prog, Ofile);
				exit(1);
			}
			if (st.st_size == 0) {
				Append = FALSE;
				goto openinput;
			}

			err = audio_read_filehdr(ofd, &File_hdr, &file_type,
			    (char *)NULL, 0);

			if (err != AUDIO_SUCCESS) {
				Error(stderr,
				    MGET("%s: %s is not a valid audio file\n"),
				    prog, Ofile);
				exit(1);
			}

			/* we need to make sure file types match */
			if (File_type_set == TRUE) {
				/* specified by the command line, must match */
				if (File_type != file_type) {
					Error(stderr,
					    MGET("%s: file types must match\n"),
					    prog);
					exit(1);
				}
			} else {
				/* not specified, so force */
				File_type = file_type;
			}

			/*
			 * Set the format state to the format
			 * in the file header.
			 */
			Sample_rate = File_hdr.sample_rate;
			Channels = File_hdr.channels;
			Encoding = File_hdr.encoding;
			Precision = File_hdr.bytes_per_unit * 8;

			/* make sure we support the encoding method */
			switch (Encoding) {
				case AUDIO_ENCODING_LINEAR8:
				case AUDIO_ENCODING_ULAW:
				case AUDIO_ENCODING_ALAW:
				case AUDIO_ENCODING_LINEAR:
					break;
				default: {
					char	msg[AUDIO_MAX_ENCODE_INFO];
					(void) audio_enc_to_str(&File_hdr, msg);
					Error(stderr,
					    MGET("%s: Append is not supported "
					    "for "), prog);
					Error(stderr,
					    MGET("this file encoding:\n\t"
					    "[%s]\n"), msg);
					exit(1);
					}
			}

			/* Get the current size, if possible */
			Oldsize = File_hdr.data_size;
			if ((Oldsize == AUDIO_UNKNOWN_SIZE) &&
			    ((err = (int)lseek(ofd, 0L, SEEK_CUR)) >= 0)) {
				if (err < 0) {
					Error(stderr,
					    MGET("%s: %s is not a valid audio "
					    "file\n"), prog, Ofile);
					exit(1);
				}
				Oldsize = st.st_size - err;
			}
			/* Seek to end to start append */
			if ((int)lseek(ofd, st.st_size, SEEK_SET) < 0) {
				Error(stderr,
				    MGET("%s: cannot find end of %s\n"),
				    prog, Ofile);
				exit(1);
			}
		}
	}
openinput:
	/* Validate and open the audio device */
	err = stat(Audio_dev, &st);
	if (err < 0) {
		Error(stderr, MGET("%s: cannot open "), prog);
		perror(Audio_dev);
		exit(1);
	}
	if (!S_ISCHR(st.st_mode)) {
		Error(stderr, MGET("%s: %s is not an audio device\n"), prog,
		    Audio_dev);
		exit(1);
	}

	/*
	 * For the mixer environment we need to open the audio device before
	 * the control device. If successful we pause right away to keep
	 * from queueing up a bunch of useless data.
	 */
	Audio_fd = open(Audio_dev, O_RDONLY | O_NONBLOCK);
	if (Audio_fd < 0) {
		if (errno == EBUSY) {
			Error(stderr, MGET("%s: %s is busy\n"),
			    prog, Audio_dev);
		} else {
			Error(stderr, MGET("%s: error opening "), prog);
			perror(Audio_dev);
		}
		exit(1);
	}
	if (audio_pause_record(Audio_fd) != AUDIO_SUCCESS) {
		Error(stderr, MGET("%s: not able to pause recording\n"), prog);
		exit(1);
	}

	/* get the current settings */
	if (audio_get_record_config(Audio_fd, &Save_hdr) != AUDIO_SUCCESS) {
		(void) close(Audio_fd);
		Error(stderr, MGET("%s: %s is not an audio device\n"),
		    prog, Audio_dev);
		exit(1);
	}
	/* make a copy into the working data structure */
	bcopy(&Save_hdr, &Dev_hdr, sizeof (Save_hdr));

	/* flush any queued audio data */
	if (audio_flush_record(Audio_fd) != AUDIO_SUCCESS) {
		Error(stderr, MGET("%s: not able to flush recording\n"), prog);
		exit(1);
	}

	if (Sample_rate != 0) {
		Dev_hdr.sample_rate = Sample_rate;
	}
	if (Channels != 0) {
		Dev_hdr.channels = Channels;
	}
	if (Precision != 0) {
		Dev_hdr.bytes_per_unit = Precision / 8;
	}
	if (Encoding != 0) {
		Dev_hdr.encoding = Encoding;
	}

	/*
	 * For .wav we always record 8-bit linear as unsigned. Thus we
	 * force unsigned linear to make life a lot easier on the user.
	 *
	 * For .aiff we set the default to 8-bit signed linear, not
	 * u-law, if Encoding isn't already set.
	 */
	if (File_type == FILE_WAV &&
	    Dev_hdr.encoding == AUDIO_ENCODING_LINEAR &&
	    Dev_hdr.bytes_per_unit == 1) {
		/* force to unsigned */
		Dev_hdr.encoding = AUDIO_ENCODING_LINEAR8;
	} else if (File_type == FILE_AIFF && Encoding == 0) {
		Dev_hdr.encoding = AUDIO_ENCODING_LINEAR;
		if (Precision == 0) {
			Dev_hdr.bytes_per_unit = AUDIO_PRECISION_8 / 8;
		}
	}

	if (audio_set_record_config(Audio_fd, &Dev_hdr) != AUDIO_SUCCESS) {
		Error(stderr, MGET(
		    "%s: Audio format not supported by the audio device\n"),
		    prog);
		exit(1);
	}

	if (audio_resume_record(Audio_fd) != AUDIO_SUCCESS) {
		Error(stderr, MGET("%s: not able to resume recording\n"), prog);
		exit(1);
	}

	/* If appending to an existing file, check the configuration */
	if (Append) {
		char	msg[AUDIO_MAX_ENCODE_INFO];

		switch (audio_cmp_hdr(&Dev_hdr, &File_hdr)) {
		case 0:			/* configuration matches */
			break;
		case 1:			/* all but sample rate matches */
			if (Force) {
				Error(stderr, MGET("%s: WARNING: appending "
				    "%.3fkHz data to %s (%.3fkHz)\n"), prog,
				    ((double)Dev_hdr.sample_rate / 1000.),
				    Ofile,
				    ((double)File_hdr.sample_rate / 1000.));
				break;
			}		/* if not -f, fall through */
			/* FALLTHROUGH */
		default:		/* encoding mismatch */
			(void) audio_enc_to_str(&Dev_hdr, msg);
			Error(stderr,
			    MGET("%s: device encoding [%s]\n"), prog, msg);
			(void) audio_enc_to_str(&File_hdr, msg);
			Error(stderr,
			    MGET("\tdoes not match file encoding [%s]\n"), msg);
			exit(1);
		}
	} else if (!isatty(ofd)) {
		if (audio_write_filehdr(ofd, &Dev_hdr, File_type, Info,
		    Ilen) != AUDIO_SUCCESS) {
			Error(stderr,
			    MGET("%s: error writing header for %s\n"), prog,
			    Ofile);
			exit(1);
		}
	}

	/*
	 * 8-bit audio isn't a problem, however 16-bit audio is. If the file
	 * is an endian that is different from the machine then the bytes
	 * will need to be swapped.
	 *
	 * Note: The following if() could be simplified, but then it gets
	 * to be very hard to read. So it's left as is.
	 */
	if (Dev_hdr.bytes_per_unit == 2 &&
	    ((!NetEndian && File_type == FILE_AIFF) ||
	    (!NetEndian && File_type == FILE_AU) ||
	    (NetEndian && File_type == FILE_WAV))) {
		swapBytes = TRUE;
	}

	/* If -v flag, set the record volume now */
	if (Volume != INT_MAX) {
		vol = (double)Volume / (double)MAX_GAIN;
		(void) audio_get_record_gain(Audio_fd, &Savevol);
		err = audio_set_record_gain(Audio_fd, &vol);
		if (err != AUDIO_SUCCESS) {
			Error(stderr,
			    MGET("%s: could not set record volume for %s\n"),
			    prog, Audio_dev);
			exit(1);
		}
	}

	if (isatty(ofd)) {
		Error(stderr, MGET("%s: No files and stdout is a tty\n"),
		    prog);
		exit(1);
	}

	/* Set up SIGINT handler so that final buffers may be flushed */
	(void) signal(SIGINT, sigint);

	/*
	 * At this point, we're (finally) ready to copy the data.
	 * Init a poll() structure, to use when there's nothing to read.
	 */
	if (Time > 0)
		Limit = audio_secs_to_bytes(&Dev_hdr, Time);
	pfd.fd = Audio_fd;
	pfd.events = POLLIN;
	while ((Limit == AUDIO_UNKNOWN_SIZE) || (Limit != 0)) {
		/* Fill the buffer or read to the time limit */
		cnt = read(Audio_fd, (char *)buf,
		    ((Limit != AUDIO_UNKNOWN_SIZE) && (Limit < sizeof (buf)) ?
		    (int)Limit : sizeof (buf)));

		if (cnt == 0)		/* normally, eof can't happen */
			break;

		/* If error, probably have to wait for input */
		if (cnt < 0) {
			if (Cleanup)
				break;		/* done if ^C seen */
			switch (errno) {
			case EAGAIN:
				(void) poll(&pfd, 1L, -1);
				break;
			case EOVERFLOW:  /* Possibly a Large File */
				Error(stderr, MGET("%s: error reading"), prog);
				perror("Large File");
				exit(1);
			default:
				Error(stderr, MGET("%s: error reading"), prog);
				perror(Audio_dev);
				exit(1);
			}
			continue;
		}

		/* Swab the output if required. */
		if (swapBytes) {
			swab((char *)buf, swapBuf, cnt);
			err = write(ofd, swapBuf, cnt);
		} else {
			err = write(ofd, (char *)buf, cnt);
		}
		if (err < 0) {
			Error(stderr, MGET("%s: error writing "), prog);
			perror(Ofile);
			exit(1);
		}
		if (err != cnt) {
			Error(stderr, MGET("%s: error writing "), prog);
			perror(Ofile);
			break;
		}
		Size += cnt;
		if (Limit != AUDIO_UNKNOWN_SIZE)
			Limit -= cnt;
	}

	/* Attempt to rewrite the data_size field of the file header */
	if (!Append || (Oldsize != AUDIO_UNKNOWN_SIZE)) {
		if (Append)
			Size += Oldsize;
		(void) audio_rewrite_filesize(ofd, File_type, Size,
		    Dev_hdr.channels, Dev_hdr.bytes_per_unit);
	}

	(void) close(ofd);			/* close input file */


	/* Check for error during record */
	if (audio_get_record_error(Audio_fd, (unsigned *)&err) != AUDIO_SUCCESS)
		Error(stderr, MGET("%s: error reading device status\n"), prog);
	else if (err)
		Error(stderr, MGET("%s: WARNING: Data overflow occurred\n"),
		    prog);

	/* Reset record volume, encoding */
	if (Volume != INT_MAX)
		(void) audio_set_record_gain(Audio_fd, &Savevol);
	if (audio_cmp_hdr(&Save_hdr, &Dev_hdr) != 0) {
		(void) audio_set_record_config(Audio_fd, &Save_hdr);
	}
	(void) close(Audio_fd);
	return (0);
}

/* Parse an unsigned integer */
static int
parse_unsigned(char *str, unsigned *dst, char *flag)
{
	char		x;

	if (sscanf(str, "%u%c", dst, &x) != 1) {
		Error(stderr, MGET("%s: invalid value for %s\n"), prog, flag);
		return (1);
	}
	return (0);
}

/*
 * set the sample rate. assume anything is ok. check later on to make sure
 * the sample rate is valid.
 */
static int
parse_sample_rate(char *s, unsigned *rate)
{
	char		*cp;
	double		drate;

	/*
	 * check if it's "cd" or "dat" or "voice". these also set
	 * the precision and encoding, etc.
	 */
	if (strcasecmp(s, "dat") == 0) {
		drate = 48000.0;
	} else if (strcasecmp(s, "cd") == 0) {
		drate = 44100.0;
	} else if (strcasecmp(s, "voice") == 0) {
		drate = 8000.0;
	} else {
		/* just do an atof */
		drate = atof(s);

		/*
		 * if the first non-digit is a "k" multiply by 1000,
		 * if it's an "h", leave it alone. anything else,
		 * return an error.
		 */

		/*
		 * XXX bug alert: could have multiple "." in string
		 * and mess things up.
		 */
		for (cp = s; *cp && (isdigit(*cp) || (*cp == '.')); cp++)
			/* NOP */;
		if (*cp != NULL) {
			if ((*cp == 'k') || (*cp == 'K')) {
				drate *= 1000.0;
			} else if ((*cp != 'h') || (*cp != 'H')) {
				/* bogus! */
				Error(stderr,
				    MGET("invalid sample rate: %s\n"), s);
				return (1);
			}
		}

	}

	*rate = irint(drate);
	return (0);
}
