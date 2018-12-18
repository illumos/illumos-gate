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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/* Command-line audio play utility */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <locale.h>
#include <limits.h>	/* All occurances of INT_MAX used to be ~0  (by MCA) */
#include <unistd.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <netinet/in.h>

#include <libaudio.h>
#include <audio_device.h>
#include <audio_encode.h>

/* localization stuff */
#define	MGET(s)		(char *)gettext(s)

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif

#define	Error		(void) fprintf


/* Local variables */
static char *prog;

static char prog_opts[] =	"VEiv:d:?";	/* getopt() flags */

static char			*Stdin;

#define	MAX_GAIN		(100)		/* maximum gain */

/*
 * This defines the tolerable sample rate error as a ratio between the
 * sample rates of the audio data and the audio device.
 */
#define	SAMPLE_RATE_THRESHOLD	(.01)

#define		BUFFER_LEN	10	/* seconds - for file i/o */
#define		ADPCM_SIZE	(1000*8) /* adpcm conversion output buf size */
#define		SWAP_SIZE	(8192)
			/* swap bytes conversion output buf size */

static unsigned		Volume = INT_MAX;	/* output volume */
static double		Savevol;		/* saved volume level */

static int		Verbose = FALSE;	/* verbose messages */
static int		Immediate = FALSE;
			/* don't hang waiting for device */
static int		Errdetect = FALSE;	/* don't worry about underrun */
static char		*Audio_dev = "/dev/audio";

static int NetEndian = TRUE;		/* endian nature of the machine */

static int		Audio_fd = -1;
			/* file descriptor for audio device */
static int		Audio_ctlfd = -1;
			/* file descriptor for control device */
static Audio_hdr	Save_hdr;
			/* saved audio header for device */
static Audio_hdr	Dev_hdr;		/* audio header for device */
static char		*Ifile;			/* current filename */
static Audio_hdr	File_hdr;		/* audio header for file */
static unsigned		Decode = AUDIO_ENCODING_NONE;
			/* decode type, if any */

static unsigned char	*buf = NULL;		/* dynamically alloc'd */
static unsigned		bufsiz = 0;		/* size of output buffer */
static unsigned char	adpcm_buf[ADPCM_SIZE + 32];
			/* for adpcm conversion */
static unsigned char	swap_buf[SWAP_SIZE + 32];
			/* for byte swap conversion */
static unsigned char	*inbuf;
			/* current input buffer pointer */
static unsigned		insiz;			/* current input buffer size */

/*
 * The decode_g72x() function is capable of decoding only one channel
 * at a time and so multichannel data must be decomposed (using demux()
 * function below ) into its constituent channels and each passed
 * separately to the decode_g72x() function. Encoded input channels are
 * stored in **in_ch_data and decoded output channels in **out_ch_data.
 * Once each channel has been decoded they are recombined (see mux()
 * function below) before being written to the audio device. For each
 * channel and adpcm state structure is created.
 */

/* adpcm state structures */
static struct audio_g72x_state *adpcm_state = NULL;
static unsigned char	**in_ch_data = NULL;	/* input channels */
static unsigned char	**out_ch_data = NULL;	/* output channels */
static int		out_ch_size;		/* output channel size */

static char		*Audio_path = NULL;
			/* path to search for audio files */

/* Global variables */
extern int	getopt(int, char *const *, const char *);
extern int	optind;
extern char	*optarg;

/* Local functions  */
static void usage(void);
static void sigint(int sig);
static void open_audio(void);
static int path_open(char *fname, int flags, mode_t mode, char *path);
static int parse_unsigned(char *str, unsigned *dst, char *flag);
static int reconfig(void);
static void initmux(int unitsz, int unitsp);
static void demux(int unitsz, int cnt);
static void mux(char *);
static void freemux(void);


static void
usage(void)
{
	Error(stderr, MGET("Play an audio file -- usage:\n"
	    "\t%s [-iV] [-v vol] [-d dev] [file ...]\n"
	    "where:\n"
	    "\t-i\tDon't hang if audio device is busy\n"
	    "\t-V\tPrint verbose warning messages\n"
	    "\t-v\tSet output volume (0 - %d)\n"
	    "\t-d\tSpecify audio device (default: /dev/audio)\n"
	    "\tfile\tList of files to play\n"
	    "\t\tIf no files specified, read stdin\n"),
	    prog, MAX_GAIN);
	exit(1);
}

static void
sigint(int sig)
{
	/* flush output queues before exiting */
	if (Audio_fd >= 0) {
		(void) audio_flush_play(Audio_fd);

		/* restore saved parameters */
		if (Volume != INT_MAX)
			(void) audio_set_play_gain(Audio_fd, &Savevol);
		if ((Audio_ctlfd >= 0) &&
		    (audio_cmp_hdr(&Save_hdr, &Dev_hdr) != 0)) {
			(void) audio_set_play_config(Audio_fd, &Save_hdr);
		}
	}
	exit(1);
}

/* Open the audio device and initalize it. */
static void
open_audio(void)
{
	int		err;
	double		vol;

	/* Return if already open */
	if (Audio_fd >= 0)
		return;

	/* Try opening without waiting, first */
	Audio_fd = open(Audio_dev, O_WRONLY | O_NONBLOCK);
	if ((Audio_fd < 0) && (errno == EBUSY)) {
		if (Immediate) {
			Error(stderr, MGET("%s: %s is busy\n"),
			    prog, Audio_dev);
			exit(1);
		}
		if (Verbose) {
			Error(stderr, MGET("%s: waiting for %s..."),
			    prog, Audio_dev);
			(void) fflush(stderr);
		}
		/* Now hang until it's open */
		Audio_fd = open(Audio_dev, O_WRONLY);
		if (Verbose)
			Error(stderr, (Audio_fd < 0) ? "\n" : MGET("open\n"));
	}
	if (Audio_fd < 0) {
		Error(stderr, MGET("%s: error opening "), prog);
		perror(Audio_dev);
		exit(1);
	}

	/* Clear the non-blocking flag (in System V it persists after open) */
	(void) fcntl(Audio_fd, F_SETFL,
	    (fcntl(Audio_fd, F_GETFL, 0) & ~(O_NDELAY | O_NONBLOCK)));

	/* Get the device output encoding configuration */
	if (audio_get_play_config(Audio_fd, &Dev_hdr) != AUDIO_SUCCESS) {
		Error(stderr, MGET("%s: %s is not an audio device\n"),
		    prog, Audio_dev);
		exit(1);
	}

	/* If -v flag, set the output volume now */
	if (Volume != INT_MAX) {
		vol = (double)Volume / (double)MAX_GAIN;
		(void) audio_get_play_gain(Audio_fd, &Savevol);
		err = audio_set_play_gain(Audio_fd, &vol);
		if (err != AUDIO_SUCCESS) {
			Error(stderr,
			    MGET("%s: could not set output volume for %s\n"),
			    prog, Audio_dev);
			exit(1);
		}
	}
}

/* Play a list of audio files. */
int
main(int argc, char **argv) {
	int		errorStatus = 0;
	int		i;
	int		c;
	int		cnt;
	int		file_type;
	int		rem;
	int		outsiz;
	int		tsize;
	int		len;
	int		err;
	int		ifd;
	int		stdinseen;
	int		regular;
	int		swapBytes;
	int		frame;
	char		*outbuf;
	caddr_t		mapaddr;
	struct stat	st;
	char		*cp;
	char		ctldev[MAXPATHLEN];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* Get the program name */
	prog = strrchr(argv[0], '/');
	if (prog == NULL)
		prog = argv[0];
	else
		prog++;
	Stdin = MGET("(stdin)");

	/* Check AUDIODEV environment for audio device name */
	if (cp = getenv("AUDIODEV")) {
		Audio_dev = cp;
	}

	/* Parse the command line arguments */
	err = 0;
	while ((i = getopt(argc, argv, prog_opts)) != EOF) {
		switch (i) {
			case 'v':
				if (parse_unsigned(optarg, &Volume, "-v")) {
					err++;
				} else if (Volume > MAX_GAIN) {
					Error(stderr, MGET("%s: invalid value "
					    "for -v\n"), prog);
					err++;
				}
				break;
			case 'd':
				Audio_dev = optarg;
				break;
			case 'V':
				Verbose = TRUE;
				break;
			case 'E':
				Errdetect = TRUE;
				break;
			case 'i':
				Immediate = TRUE;
				break;
			case '?':
				usage();
		/*NOTREACHED*/
		}
	}
	if (err > 0)
		exit(1);

	argc -= optind;		/* update arg pointers */
	argv += optind;

	/* Validate and open the audio device */
	err = stat(Audio_dev, &st);
	if (err < 0) {
		Error(stderr, MGET("%s: cannot stat "), prog);
		perror(Audio_dev);
		exit(1);
	}
	if (!S_ISCHR(st.st_mode)) {
		Error(stderr, MGET("%s: %s is not an audio device\n"), prog,
		    Audio_dev);
		exit(1);
	}

	/* This should probably use audio_cntl instead of open_audio */
	if ((argc <= 0) && isatty(fileno(stdin))) {
		Error(stderr, MGET("%s: No files and stdin is a tty.\n"), prog);
		exit(1);
	}

	/* Check on the -i status now. */
	Audio_fd = open(Audio_dev, O_WRONLY | O_NONBLOCK);
	if ((Audio_fd < 0) && (errno == EBUSY)) {
		if (Immediate) {
			Error(stderr, MGET("%s: %s is busy\n"), prog,
			    Audio_dev);
			exit(1);
		}
	}
	(void) close(Audio_fd);
	Audio_fd = -1;

	/* Try to open the control device and save the current format */
	(void) snprintf(ctldev, sizeof (ctldev), "%sctl", Audio_dev);
	Audio_ctlfd = open(ctldev, O_RDWR);
	if (Audio_ctlfd >= 0) {
		/*
		 * wait for the device to become available then get the
		 * controls. We want to save the format that is left when the
		 * device is in a quiescent state. So wait until then.
		 */
		Audio_fd = open(Audio_dev, O_WRONLY);
		(void) close(Audio_fd);
		Audio_fd = -1;
		if (audio_get_play_config(Audio_ctlfd, &Save_hdr)
		    != AUDIO_SUCCESS) {
			(void) close(Audio_ctlfd);
			Audio_ctlfd = -1;
		}
	}

	/* store AUDIOPATH so we don't keep doing getenv() */
	Audio_path = getenv("AUDIOPATH");

	/* Set up SIGINT handler to flush output */
	(void) signal(SIGINT, sigint);

	/* Set the endian nature of the machine. */
	if ((ulong_t)1 != htonl((ulong_t)1)) {
		NetEndian = FALSE;
	}

	/* If no filenames, read stdin */
	stdinseen = FALSE;
	if (argc <= 0) {
		Ifile = Stdin;
	} else {
		Ifile = *argv++;
		argc--;
	}

	/* Loop through all filenames */
	do {
		/* Interpret "-" filename to mean stdin */
		if (strcmp(Ifile, "-") == 0)
			Ifile = Stdin;

		if (Ifile == Stdin) {
			if (stdinseen) {
				Error(stderr,
				    MGET("%s: stdin already processed\n"),
				    prog);
				goto nextfile;
			}
			stdinseen = TRUE;
			ifd = fileno(stdin);
		} else {
			if ((ifd = path_open(Ifile, O_RDONLY, 0, Audio_path))
			    < 0) {
				Error(stderr, MGET("%s: cannot open "), prog);
				perror(Ifile);
				errorStatus++;
				goto nextfile;
			}
		}

		/* Check to make sure this is an audio file */
		err = audio_read_filehdr(ifd, &File_hdr, &file_type,
		    (char *)NULL, 0);
		if (err != AUDIO_SUCCESS) {
			Error(stderr,
			    MGET("%s: %s is not a valid audio file\n"),
			    prog, Ifile);
			errorStatus++;
			goto closeinput;
		}

		/* If G.72X adpcm, set flags for conversion */
		if ((File_hdr.encoding == AUDIO_ENCODING_G721) &&
		    (File_hdr.samples_per_unit == 2) &&
		    (File_hdr.bytes_per_unit == 1)) {
			Decode = AUDIO_ENCODING_G721;
			File_hdr.encoding = AUDIO_ENCODING_ULAW;
			File_hdr.samples_per_unit = 1;
			File_hdr.bytes_per_unit = 1;
			adpcm_state = (struct audio_g72x_state *)malloc
			    (sizeof (*adpcm_state) * File_hdr.channels);
			for (i = 0; i < File_hdr.channels; i++) {
				g721_init_state(&adpcm_state[i]);
			}
		} else if ((File_hdr.encoding == AUDIO_ENCODING_G723) &&
		    (File_hdr.samples_per_unit == 8) &&
		    (File_hdr.bytes_per_unit == 3)) {
			Decode = AUDIO_ENCODING_G723;
			File_hdr.encoding = AUDIO_ENCODING_ULAW;
			File_hdr.samples_per_unit = 1;
			File_hdr.bytes_per_unit = 1;
			adpcm_state = (struct audio_g72x_state *)malloc
			    (sizeof (*adpcm_state) * File_hdr.channels);
			for (i = 0; i < File_hdr.channels; i++) {
				g723_init_state(&adpcm_state[i]);
			}
		} else {
			Decode = AUDIO_ENCODING_NONE;
		}

		/* Check the device configuration */
		open_audio();
		if (audio_cmp_hdr(&Dev_hdr, &File_hdr) != 0) {
			/*
			 * The device does not match the input file.
			 * Wait for any old output to drain, then attempt
			 * to reconfigure the audio device to match the
			 * input data.
			 */
			if (audio_drain(Audio_fd, FALSE) != AUDIO_SUCCESS) {
				/* Flush any remaining audio */
				(void) ioctl(Audio_fd, I_FLUSH, FLUSHW);

				Error(stderr, MGET("%s: "), prog);
				perror(MGET("AUDIO_DRAIN error"));
				exit(1);
			}

			/* Flush any remaining audio */
			(void) ioctl(Audio_fd, I_FLUSH, FLUSHW);

			if (!reconfig()) {
				errorStatus++;
				goto closeinput;
			}
		}


		/* try to do the mmaping - for regular files only ... */
		err = fstat(ifd, &st);
		if (err < 0) {
			Error(stderr, MGET("%s: cannot stat "), prog);
			perror(Ifile);
			exit(1);
		}
		regular = (S_ISREG(st.st_mode));


		/* If regular file, map it.  Else, allocate a buffer */
		mapaddr = 0;

		/*
		 * This should compare to MAP_FAILED not -1, can't
		 * find MAP_FAILED
		 */
		if (regular && ((mapaddr = mmap(0, st.st_size, PROT_READ,
		    MAP_SHARED, ifd, 0)) != MAP_FAILED)) {

			(void) madvise(mapaddr, st.st_size, MADV_SEQUENTIAL);

			/* Skip the file header and set the proper size */
			cnt = lseek(ifd, 0, SEEK_CUR);
			if (cnt < 0) {
			    perror("lseek");
			    exit(1);
			}
			inbuf = (unsigned char *) mapaddr + cnt;
			len = cnt = st.st_size - cnt;
		} else {		/* Not a regular file, or map failed */

			/* mark is so. */
			mapaddr = 0;

			/* Allocate buffer to hold 10 seconds of data */
			cnt = BUFFER_LEN * File_hdr.sample_rate *
			    File_hdr.bytes_per_unit * File_hdr.channels;
			if (bufsiz != cnt) {
				if (buf != NULL) {
					(void) free(buf);
				}
				buf = (unsigned char *) malloc(cnt);
				if (buf == NULL) {
					Error(stderr,
					    MGET("%s: couldn't allocate %dK "
					    "buf\n"), prog, bufsiz / 1000);
					exit(1);
				}
				inbuf = buf;
				bufsiz = cnt;
			}
		}

		/* Set buffer sizes and pointers for conversion, if any */
		switch (Decode) {
		default:
		case AUDIO_ENCODING_NONE:
			insiz = bufsiz;
			outbuf = (char *)buf;
			break;
		case AUDIO_ENCODING_G721:
			insiz = ADPCM_SIZE / 2;
			outbuf = (char *)adpcm_buf;
			initmux(1, 2);
			break;
		case AUDIO_ENCODING_G723:
			insiz = (ADPCM_SIZE * 3) / 8;
			outbuf = (char *)adpcm_buf;
			initmux(3, 8);
			break;
		}

		/*
		 * 8-bit audio isn't a problem, however 16-bit audio is.
		 * If the file is an endian that is different from the machine
		 * then the bytes will need to be swapped.
		 *
		 * Note: Because the G.72X conversions produce 8bit output,
		 * they don't require a byte swap before display and so
		 * this scheme works just fine. If a conversion is added
		 * that produces a 16 bit result and therefore requires
		 * byte swapping before output, then a mechanism
		 * for chaining the two conversions will have to be built.
		 *
		 * Note: The following if() could be simplified, but then
		 * it gets to be very hard to read. So it's left as is.
		 */

		if (File_hdr.bytes_per_unit == 2 &&
		    ((!NetEndian && file_type == FILE_AIFF) ||
		    (!NetEndian && file_type == FILE_AU) ||
		    (NetEndian && file_type == FILE_WAV))) {
			swapBytes = TRUE;
		} else {
			swapBytes = FALSE;
		}

		if (swapBytes) {
			/* Read in interal number of sample frames. */
			frame = File_hdr.bytes_per_unit * File_hdr.channels;
			insiz = (SWAP_SIZE / frame) * frame;
			/* make the output buffer  the swap buffer. */
			outbuf = (char *)swap_buf;
		}

		/*
		 * At this point, we're all ready to copy the data.
		 */
		if (mapaddr == 0) { /* Not mmapped, do it a buffer at a time. */
			inbuf = buf;
			frame = File_hdr.bytes_per_unit * File_hdr.channels;
			rem = 0;
			while ((cnt = read(ifd, inbuf+rem, insiz-rem)) >= 0) {
				/*
				 * We need to ensure only an integral number of
				 * samples is ever written to the audio device.
				 */
				cnt = cnt + rem;
				rem = cnt % frame;
				cnt = cnt - rem;

				/*
				 * If decoding adpcm, or swapping bytes do it
				 * now.
				 *
				 * We treat the swapping like a separate
				 * encoding here because the G.72X encodings
				 * decode to single byte output samples. If
				 * another encoding is added and it produces
				 * multi-byte output samples this will have to
				 * be changed.
				 */
				if (Decode == AUDIO_ENCODING_G721) {
				    outsiz = 0;
				    demux(1, cnt / File_hdr.channels);
				    for (c = 0; c < File_hdr.channels; c++) {
					err = g721_decode(in_ch_data[c],
					    cnt / File_hdr.channels,
					    &File_hdr,
					    (void*)out_ch_data[c],
					    &tsize,
					    &adpcm_state[c]);
					outsiz = outsiz + tsize;
					if (err != AUDIO_SUCCESS) {
					    Error(stderr, MGET(
						"%s: error decoding g721\n"),
						prog);
						errorStatus++;
						break;
					}
				    }
				    mux(outbuf);
				    cnt = outsiz;
				} else if (Decode == AUDIO_ENCODING_G723) {
				    outsiz = 0;
				    demux(3, cnt / File_hdr.channels);
				    for (c = 0; c < File_hdr.channels; c++) {
					err = g723_decode(in_ch_data[c],
					    cnt / File_hdr.channels,
					    &File_hdr,
					    (void*)out_ch_data[c],
					    &tsize,
					    &adpcm_state[c]);
					outsiz = outsiz + tsize;
					if (err != AUDIO_SUCCESS) {
					    Error(stderr, MGET(
						"%s: error decoding g723\n"),
						prog);
					    errorStatus++;
					    break;
					}
				    }
				    mux(outbuf);
				    cnt = outsiz;
				} else if (swapBytes) {
					swab((char *)inbuf, outbuf, cnt);
				}

				/* If input EOF, write an eof marker */
				err = write(Audio_fd, outbuf, cnt);

				if (err < 0) {
					perror("write");
					errorStatus++;
					break;
				} else if (err != cnt) {
					Error(stderr,
					    MGET("%s: output error: "), prog);
					perror("");
					errorStatus++;
					break;
				}
				if (cnt == 0) {
					break;
				}
				/* Move remainder to the front of the buffer */
				if (rem != 0) {
					(void *)memcpy(inbuf, inbuf + cnt, rem);
				}

			}
			if (cnt < 0) {
				Error(stderr, MGET("%s: error reading "), prog);
				perror(Ifile);
				errorStatus++;
			}
		} else {	/* We're mmaped */
			if ((Decode != AUDIO_ENCODING_NONE) || swapBytes) {

				/* Transform data if we have to. */
				for (i = 0; i <= len; i += cnt) {
					cnt = insiz;
					if ((i + cnt) > len) {
						cnt = len - i;
					}
					if (Decode == AUDIO_ENCODING_G721) {
					    outsiz = 0;
					    demux(1, cnt / File_hdr.channels);
					    for (c = 0; c < File_hdr.channels;
						c++) {
						err = g721_decode(
						    in_ch_data[c],
						    cnt / File_hdr.channels,
						    &File_hdr,
						    (void*)out_ch_data[c],
						    &tsize,
						    &adpcm_state[c]);
						outsiz = outsiz + tsize;
						if (err != AUDIO_SUCCESS) {
						    Error(stderr, MGET(
							"%s: error decoding "
							"g721\n"), prog);
						    errorStatus++;
						    break;
						}
					    }
					    mux(outbuf);
					} else if
					    (Decode == AUDIO_ENCODING_G723) {
						outsiz = 0;
						demux(3,
						    cnt / File_hdr.channels);
						for (c = 0;
							c < File_hdr.channels;
							c++) {
						    err = g723_decode(
							in_ch_data[c],
							cnt /
							    File_hdr.channels,
							&File_hdr,
							(void*)out_ch_data[c],
							&tsize,
							&adpcm_state[c]);
						    outsiz = outsiz + tsize;
						    if (err != AUDIO_SUCCESS) {
							Error(stderr, MGET(
							    "%s: error "
							    "decoding g723\n"),
							    prog);
							errorStatus++;
							break;
						    }
						}
						mux(outbuf);
					} else if (swapBytes) {
						swab((char *)inbuf, outbuf,
						    cnt);
						outsiz = cnt;
					}
					inbuf += cnt;

					/* If input EOF, write an eof marker */
					err = write(Audio_fd, (char *)outbuf,
					    outsiz);
					if (err < 0) {
						perror("write");
						errorStatus++;
					} else if (outsiz == 0) {
						break;
					}

				}
			} else {
				/* write the whole thing at once!  */
				err = write(Audio_fd, inbuf, len);
				if (err < 0) {
					perror("write");
					errorStatus++;
				}
				if (err != len) {
					Error(stderr,
					    MGET("%s: output error: "), prog);
					perror("");
					errorStatus++;
				}
				err = write(Audio_fd, inbuf, 0);
				if (err < 0) {
					perror("write");
					errorStatus++;
				}
			}
		}

		/* Free memory if decoding ADPCM */
		switch (Decode) {
		case AUDIO_ENCODING_G721:
		case AUDIO_ENCODING_G723:
			freemux();
			break;
		default:
			break;
		}

closeinput:;
		if (mapaddr != 0)
			(void) munmap(mapaddr, st.st_size);
		(void) close(ifd);		/* close input file */
		if (Errdetect) {
			cnt = 0;
			(void) audio_set_play_error(Audio_fd,
			    (unsigned int *)&cnt);
			if (cnt) {
				Error(stderr,
				    MGET("%s: output underflow in %s\n"),
				    Ifile, prog);
				errorStatus++;
			}
		}
nextfile:;
	} while ((argc > 0) && (argc--, (Ifile = *argv++) != NULL));

	/*
	 * Though drain is implicit on close(), it's performed here
	 * to ensure that the volume is reset after all output is complete.
	 */
	(void) audio_drain(Audio_fd, FALSE);

	/* Flush any remaining audio */
	(void) ioctl(Audio_fd, I_FLUSH, FLUSHW);

	if (Volume != INT_MAX)
		(void) audio_set_play_gain(Audio_fd, &Savevol);
	if ((Audio_ctlfd >= 0) && (audio_cmp_hdr(&Save_hdr, &Dev_hdr) != 0)) {
		(void) audio_set_play_config(Audio_fd, &Save_hdr);
	}
	(void) close(Audio_fd);			/* close output */
	return (errorStatus);
}


/*
 * Try to reconfigure the audio device to match the file encoding.
 * If this fails, we should attempt to make the input data match the
 * device encoding.  For now, we give up on this file.
 *
 * Returns TRUE if successful.  Returns FALSE if not.
 */
static int
reconfig(void)
{
	int	err;
	char	msg[AUDIO_MAX_ENCODE_INFO];

	Dev_hdr = File_hdr;
	err = audio_set_play_config(Audio_fd, &Dev_hdr);

	switch (err) {
	case AUDIO_SUCCESS:
		return (TRUE);

	case AUDIO_ERR_NOEFFECT:
		/*
		 * Couldn't change the device.
		 * Check to see if we're nearly compatible.
		 * audio_cmp_hdr() returns >0 if only sample rate difference.
		 */
		if (audio_cmp_hdr(&Dev_hdr, &File_hdr) > 0) {
			double	ratio;

			ratio = (double)abs((int)
			    (Dev_hdr.sample_rate - File_hdr.sample_rate)) /
			    (double)File_hdr.sample_rate;
			if (ratio <= SAMPLE_RATE_THRESHOLD) {
				if (Verbose) {
					Error(stderr,
					    MGET("%s: WARNING: %s sampled at "
					    "%d, playing at %d\n"),
					    prog, Ifile, File_hdr.sample_rate,
					    Dev_hdr.sample_rate);
				}
				return (TRUE);
			}
			Error(stderr,
			    MGET("%s: %s sample rate %d not available\n"),
			    prog, Ifile, File_hdr.sample_rate);
			return (FALSE);
		}
		(void) audio_enc_to_str(&File_hdr, msg);
		Error(stderr, MGET("%s: %s encoding not available: %s\n"),
		    prog, Ifile, msg);
		return (FALSE);

	default:
		Error(stderr,
		    MGET("%s: %s audio encoding type not available\n"),
		    prog, Ifile);
		exit(1);
	}
	return (TRUE);
}


/* Parse an unsigned integer */
static int
parse_unsigned(char *str, unsigned *dst, char *flag)
{
	char	x;

	if (sscanf(str, "%u%c", dst, &x) != 1) {
		Error(stderr, MGET("%s: invalid value for %s\n"), prog, flag);
		return (1);
	}
	return (0);
}

/*
 * Search for fname in path and open. Ignore path not opened O_RDONLY.
 * Note: in general path can be a list of ':' separated paths to search
 * through.
 */
static int
path_open(char *fname, int flags, mode_t mode, char *path)
{
	char		fullpath[MAXPATHLEN]; 	/* full path of file */
	char 		*buf;			/* malloc off the tmp buff */
	char		*cp;
	struct stat	st;

	if (!fname) {		/* bogus */
		return (-1);
	}

	/*
	 * cases where we don't bother checking path:
	 *	- no path
	 *	- file not opened O_RDONLY
	 *	- not a relative path (i.e. starts with /, ./, or ../).
	 */

	if ((!path) || (flags != O_RDONLY) || (*fname == '/') ||
	    (strncmp(fname, "./", strlen("./")) == 0) ||
	    (strncmp(fname, "../", strlen("../")) == 0)) {
		return (open(fname, flags, mode));
	}

	/*
	 * Malloc off a buffer to hold the path variable.
	 * This is NOT limited to MAXPATHLEN characters as
	 * it may contain multiple paths.
	 */
	buf = malloc(strlen(path) + 1);

	/*
	 * if first character is ':', but not the one following it,
	 * skip over it - or it'll be interpreted as "./". it's OK
	 * to have "::" since that does mean "./".
	 */

	if ((path[0] == ':') && (path[1] != ':')) {
		(void) strncpy(buf, path+1, strlen(path));
	} else {
		(void) strncpy(buf, path, strlen(path));
	}

	for (path = buf; path && *path; ) {
		if (cp = strchr(path, ':')) {
			*cp++ = NULL; /* now pts to next path element */
		}

		/* the safest way to create the path string :-) */
		if (*path) {
			(void) strncpy(fullpath, path, MAXPATHLEN);
			(void) strncat(fullpath, "/", MAXPATHLEN);
		} else {
			/* a NULL path element means "./" */
			(void) strncpy(fullpath, "./", MAXPATHLEN);
		}
		(void) strncat(fullpath, fname, MAXPATHLEN);

		/* see if there's a match */
		if (stat(fullpath, &st) >= 0) {
			if (S_ISREG(st.st_mode)) {
				/* got a match! */
				if (Verbose) {
					Error(stderr,
					    MGET("%s: Found %s in path "
					    "at %s\n"),
					    prog, fname, fullpath);
				}
				return (open(fullpath, flags, mode));
			}
		}

		/* go on to the next one */
		path = cp;
	}

	/*
	 * if we fall through with no match, just do a normal file open
	 */
	return (open(fname, flags, mode));
}


/*
 * initmux()
 *
 * Description:
 *      Allocates memory for carrying out demultiplexing/multiplexing.
 *
 * Arguments:
 *      int		unitsz		Bytes per unit
 *	int		unitsp		Samples per unit
 *
 * Returns:
 *      void
 */
static void
initmux(int unitsz, int unitsp)
{
	int	c;		/* Channel */
	int	in_ch_size;	/* Input channel size */

	/* Size of each input channel */
	in_ch_size = insiz / File_hdr.channels;

	/* Size of each output channel */
	out_ch_size = in_ch_size * unitsp / unitsz;

	/* Allocate pointers to input channels */
	in_ch_data = malloc(sizeof (unsigned char *) * File_hdr.channels);

	if (in_ch_data == NULL) {
		Error(stderr, MGET("%s: couldn't allocate %dK buf\n"),
		    prog, sizeof (unsigned char *) * File_hdr.channels / 1000);
		exit(1);
	}

	/* Allocate input channels */
	for (c = 0; c < File_hdr.channels; c++) {
		in_ch_data[c] = malloc(sizeof (unsigned char) * in_ch_size);

		if (in_ch_data[c] == NULL) {
			Error(stderr, MGET("%s: couldn't allocate %dK buf\n"),
			    prog, in_ch_size / 1000);
			exit(1);
		}
	}

	/* Allocate pointers to output channels */
	out_ch_data = malloc(sizeof (unsigned char *) * File_hdr.channels);

	if (out_ch_data == NULL) {
		Error(stderr, MGET("%s: couldn't allocate %dK buf\n"),
		    prog, sizeof (unsigned char *) * File_hdr.channels / 1000);
		exit(1);
	}

	/* Allocate output channels */
	for (c = 0; c < File_hdr.channels; c++) {
		out_ch_data[c] = malloc(sizeof (unsigned char) * out_ch_size);

		if (out_ch_data[c] == NULL) {
			Error(stderr, MGET("%s: couldn't allocate %dK buf\n"),
			    prog, out_ch_size / 1000);
			exit(1);
		}
	}
}

/*
 * demux()
 *
 * Description:
 *      Split a multichannel signal into separate channels.
 *
 * Arguments:
 *      int		unitsz		Bytes per unit
 *	int		cnt		Bytes to process
 *
 * Returns:
 *      void
 */
static void
demux(int unitsz, int cnt)
{
	int	c;		/* Channel */
	int	s;		/* Sample */
	int	b;		/* Byte */
	int	tp;		/* Pointer into current data */
	int	dp;		/* Pointer into target data */

	/* Split */
	for (c = 0; c < File_hdr.channels; c++) {
		for (s = 0; s < cnt / unitsz; s++) {
			tp = s * unitsz;
			dp = (s * File_hdr.channels + c) * unitsz;
			for (b = 0; b < unitsz; b++) {
				in_ch_data[c][tp + b] = inbuf[dp + b];
			}
		}
	}
}

/*
 * mux()
 *
 * Description:
 *      Combine separate channels to produce a multichannel signal.
 *
 * Arguments:
 *      char		*outbuf		Combined signal
 *
 * Returns:
 *      void
 */
static void
mux(char *outbuf)
{
	int	c;		/* Channel */
	int	s;		/* Sample */

	/* Combine */
	for (c = 0; c < File_hdr.channels; c++) {
		for (s = 0; s < out_ch_size; s++) {
			outbuf[File_hdr.channels * s + c] = out_ch_data[c][s];
		}
	}
}

/*
 * freemux()
 *
 * Description:
 *      Free memory used in multiplexing/demultiplexing.
 *
 * Arguments:
 *      void
 *
 * Returns:
 *      void
 */
static void
freemux(void)
{
	int	c;		/* Channel */

	/* Free */
	for (c = 0; c < File_hdr.channels; c++) {
		free(in_ch_data[c]);
		free(out_ch_data[c]);
		free(&adpcm_state[c]);
	}

	free(in_ch_data);
	free(out_ch_data);
}
