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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains a set of Very Paranoid routines to convert
 * audio file headers to in-core audio headers and vice versa.
 *
 * They are robust enough to handle any random file input without
 * crashing miserably.  Of course, bad audio headers coming from
 * the calling program can cause significant problems.
 */

#include <stdlib.h>
#include <memory.h>
#include <fcntl.h>
#include <errno.h>	/* needed for large file error checking */
#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <libintl.h>
#include <math.h>

#include <libaudio_impl.h>	/* include other audio hdr's */

/* Round up to a double boundary */
#define	ROUND_DBL(x)	(((x) + 7) & ~7)

#define	HEADER_BUFFER		100

#define	_MGET_(str)	(char *)dgettext(TEXT_DOMAIN, str)

static int audio_encode_aiff(Audio_hdr *, unsigned char *, unsigned int *);
static int audio_encode_au(Audio_hdr *, char *, unsigned int,
	unsigned char *, unsigned int *);
static int audio_encode_wav(Audio_hdr *, unsigned char *, unsigned int *);
static double convert_from_ieee_extended(unsigned char *);
static void convert_to_ieee_extended(double, unsigned char *);

/*
 * Write an audio file header to an output stream.
 *
 * The file header is encoded from the supplied Audio_hdr structure.
 * If 'infop' is not NULL, it is the address of a buffer containing 'info'
 * data.  'ilen' specifies the size of this buffer.
 * The entire file header will be zero-padded to a double-word boundary.
 *
 * Note that the file header is stored on-disk in big-endian format,
 * regardless of the machine type.
 *
 * Note also that the output file descriptor must not have been set up
 * non-blocking i/o.  If non-blocking behavior is desired, set this
 * flag after writing the file header.
 */
int
audio_write_filehdr(int fd, Audio_hdr *hdrp, int file_type, char *infop,
	unsigned int ilen)
					/* file descriptor */
					/* audio header */
					/* audio header type */
					/* info buffer pointer */
					/* buffer size */
{
	int		err;
	unsigned	blen;
	unsigned char	*buf;		/* temporary buffer */

	/* create tmp buf for the encoding routines to work with */
	blen = HEADER_BUFFER + (infop ? ilen : 0) + 4;
	blen = ROUND_DBL(blen);

	if (!(buf = (unsigned char *)calloc(1, blen))) {
		return (AUDIO_UNIXERROR);
	}

	switch (file_type) {
	case FILE_AU:
		err = audio_encode_au(hdrp, infop, ilen, buf, &blen);
		break;
	case FILE_WAV:
		err = audio_encode_wav(hdrp, buf, &blen);
		break;
	case FILE_AIFF:
		err = audio_encode_aiff(hdrp, buf, &blen);
		break;
	default:
		return (AUDIO_ERR_BADFILETYPE);
	}

	if (err != AUDIO_SUCCESS) {
		return (err);
	}

	/* Write and free the holding buffer */
	err = write(fd, (char *)buf, (int)blen);
	(void) free((char *)buf);

	if (err != blen)
		return ((err < 0) ? AUDIO_UNIXERROR : AUDIO_ERR_BADFILEHDR);

	return (AUDIO_SUCCESS);

}

/*
 * Rewrite the aiff header chunk length and the data chunk length fields.
 */
static int
audio_rewrite_aiff_filesize(int fd, unsigned int size, unsigned int channels,
	unsigned int bytes_per_sample)
{
	unsigned int	offset;
	unsigned int	tmp_uint;
	unsigned int	tmp_uint2;
	unsigned int	total_size;

	/* first fix aiff_hdr_size */
	total_size = size + sizeof (aiff_hdr_chunk_t) +
	    AUDIO_AIFF_COMM_CHUNK_SIZE + sizeof (aiff_ssnd_chunk_t);
	tmp_uint = total_size - (2 * sizeof (int));
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &tmp_uint2);
	offset = sizeof (int);
	if (lseek(fd, offset, SEEK_SET) < 0) {
		return (AUDIO_ERR_NOEFFECT);
	}
	if (write(fd, &tmp_uint2, sizeof (tmp_uint2)) != sizeof (tmp_uint2)) {
		return (AUDIO_ERR_NOEFFECT);
	}

	/* fix the frame count */
	tmp_uint = size / channels / bytes_per_sample;
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &tmp_uint2);
	offset = sizeof (aiff_hdr_chunk_t) + (2 * sizeof (int)) +
	    sizeof (short);
	if (lseek(fd, offset, SEEK_SET) < 0) {
		return (AUDIO_ERR_NOEFFECT);
	}
	if (write(fd, &tmp_uint2, sizeof (tmp_uint2)) != sizeof (tmp_uint2)) {
		return (AUDIO_ERR_NOEFFECT);
	}

	/* fix the data size */
	tmp_uint = size + sizeof (aiff_ssnd_chunk_t) - (2 * sizeof (int));
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &tmp_uint2);
	offset = sizeof (aiff_hdr_chunk_t) + AUDIO_AIFF_COMM_CHUNK_SIZE +
	    sizeof (int);
	if (lseek(fd, offset, SEEK_SET) < 0) {
		return (AUDIO_ERR_NOEFFECT);
	}
	if (write(fd, &tmp_uint2, sizeof (tmp_uint2)) != sizeof (tmp_uint2)) {
		return (AUDIO_ERR_NOEFFECT);
	}

	return (AUDIO_SUCCESS);

}

/*
 * Rewrite the data size field for the .au file format. Rewrite the audio
 * file header au_data_size field with the supplied value. Otherwise,
 * return AUDIO_ERR_NOEFFECT.
 */
static int
audio_rewrite_au_filesize(int fd, unsigned int size)
{
	au_filehdr_t	fhdr;
	int		err;
	int		data;
	int		offset;

	/* seek to the position of the au_data_size member */
	offset = (char *)&fhdr.au_data_size - (char *)&fhdr;
	if (lseek(fd, offset, SEEK_SET) < 0) {
		return (AUDIO_ERR_NOEFFECT);
	}

	/* Encode the 32-bit integer header field */
	AUDIO_AU_HOST2FILE(&size, &data);

	/* Write the data */
	err = write(fd, (char *)&data, sizeof (fhdr.au_data_size));
	if (err != sizeof (fhdr.au_data_size))
		return ((err < 0) ? AUDIO_UNIXERROR : AUDIO_ERR_BADFILEHDR);

	return (AUDIO_SUCCESS);

}

/*
 * Rewrite the riff header chunk length and the data chunk length fields.
 */
static int
audio_rewrite_wav_filesize(int fd, unsigned int size)
{
	wav_filehdr_t	fhdr;
	int		calc_size;
	int		err;
	int		data;
	int		offset;

	/* seek to the position of the riff header chunk length */
	calc_size = size + sizeof (fhdr) - sizeof (fhdr.wav_riff_ID) -
	    sizeof (fhdr.wav_riff_size);
	AUDIO_WAV_HOST2FILE_INT(&calc_size, &data);
	offset = (char *)&fhdr.wav_riff_size - (char *)&fhdr;
	if (lseek(fd, offset, SEEK_SET) < 0) {
		return (AUDIO_ERR_NOEFFECT);
	}

	/* Write the data */
	err = write(fd, (char *)&data, sizeof (fhdr.wav_riff_size));
	if (err != sizeof (fhdr.wav_riff_size))
		return ((err < 0) ? AUDIO_UNIXERROR : AUDIO_ERR_BADFILEHDR);

	/* now seek to the position of the data chunk length */
	AUDIO_WAV_HOST2FILE_INT(&size, &data);
	offset = (char *)&fhdr.wav_data_size - (char *)&fhdr;
	if (lseek(fd, offset, SEEK_SET) < 0) {
		return (AUDIO_ERR_NOEFFECT);
	}

	/* Write the data */
	err = write(fd, (char *)&data, sizeof (fhdr.wav_data_size));
	if (err != sizeof (fhdr.wav_data_size))
		return ((err < 0) ? AUDIO_UNIXERROR : AUDIO_ERR_BADFILEHDR);

	return (AUDIO_SUCCESS);

}

/*
 * Rewrite the data size field of an audio header to the output stream if
 * the output file is capable of seeking.
 */
int
audio_rewrite_filesize(int fd, int file_type, unsigned int size,
	unsigned int channels, unsigned int bytes_per_sample)
					/* file descriptor */
					/* audio file type */
					/* new data size */
					/* number of channels */
					/* number of bytes per sample */
{
	int		fcntl_err;

	/* Can we seek back in this file and write without appending? */
	fcntl_err = fcntl(fd, F_GETFL, 0);
	if ((fcntl_err < 0) && ((errno == EOVERFLOW) || (errno == EINVAL))) {
		/* Large file encountered (probably) */
		perror("fcntl");
		exit(1);
	} else if ((lseek(fd, (off_t)0, SEEK_SET) < 0) ||
		    (fcntl_err & FAPPEND)) {
		return (AUDIO_ERR_NOEFFECT);
	}

	switch (file_type) {
	case FILE_AU:
		return (audio_rewrite_au_filesize(fd, size));
	case FILE_WAV:
		return (audio_rewrite_wav_filesize(fd, size));
	case FILE_AIFF:
		return (audio_rewrite_aiff_filesize(fd, size, channels,
		    bytes_per_sample));
	default:
		return (AUDIO_ERR_BADFILETYPE);
	}
}


/*
 * Decode an audio file header from an input stream.
 *
 * The file header is decoded into the supplied Audio_hdr structure, regardless
 * of the file format. Thus .wav and .aiff files look like .au files once the
 * header is decoded.
 *
 * If 'infop' is not NULL, it is the address of a buffer to which the
 * 'info' portion of the file header will be copied.  'ilen' specifies
 * the maximum number of bytes to copy.  The buffer will be NULL-terminated,
 * even if it means over-writing the last byte.
 *
 * Note that the .au file header is stored on-disk in big-endian format,
 * regardless of the machine type.  This may not have been true if
 * the file was written on a non-Sun machine.  For now, such
 * files will appear invalid.
 *
 * Note also that the input file descriptor must not have been set up
 * non-blocking i/o.  If non-blocking behavior is desired, set this
 * flag after reading the file header.
 */
int
audio_read_filehdr(int fd, Audio_hdr *hdrp, int *file_type, char *infop,
	unsigned int ilen)
					/* input file descriptor */
					/* output audio header */
					/* audio file type */
					/* info buffer pointer */
					/* buffer size */
{
	int		err;
	int		dsize;
	int		isize;
	unsigned	resid;
	unsigned char	buf[HEADER_BUFFER];
	struct stat	st;

	/* decode the file header and fill in the hdrp structure */
	if ((err = audio_decode_filehdr(fd, buf, file_type, hdrp, &isize)) !=
	    AUDIO_SUCCESS) {
		goto checkerror;
	}

	/* Stat the file, to determine if it is a regular file. */
	err = fstat(fd, &st);
	if (err < 0) {
		return (AUDIO_UNIXERROR);
	}

	/*
	 * If au_data_size is not indeterminate (i.e., this isn't a pipe),
	 * try to validate the au_offset and au_data_size.
	 */
	if (*file_type == FILE_AU && hdrp->data_size != AUDIO_UNKNOWN_SIZE) {
		/* Only trust the size for regular files */
		if (S_ISREG(st.st_mode)) {
			dsize = isize + hdrp->data_size + sizeof (au_filehdr_t);
			if (st.st_size < dsize) {
				(void) fprintf(stderr,
				    _MGET_("Warning: More audio data "
				    "than the file header specifies\n"));
			} else if (st.st_size > dsize) {
				(void) fprintf(stderr,
				    _MGET_("Warning: Less audio data "
				    "than the file header specifies\n"));
			}
		}
	}

	resid = isize;
	/*
	 * Deal with extra header data.
	 */
	if ((infop != NULL) && (ilen != 0)) {
		/*
		 * If infop is non-NULL, try to read in the info data
		 */
		if (isize > ilen)
			isize = ilen;
		err = read(fd, infop, (int)isize);
		if (err != isize)
			goto checkerror;

		/* Zero any residual bytes in the text buffer */
		if (isize < ilen)
			(void) memset(&infop[isize], '\0',
				    (int)(ilen - isize));
		else
			infop[ilen - 1] = '\0';	/* zero-terminate */

		resid -= err;		/* subtract the amount read */
	}

	/*
	 * If we truncated the info, seek or read data until info size
	 * is satisfied.  If regular file, seek nearly to end and check
	 * for eof.
	 */
	if (resid != 0) {
		if (S_ISREG(st.st_mode)) {
			err = lseek(fd, (off_t)(resid - 1), SEEK_CUR);
			if ((err < 0) ||
			    ((err = read(fd, (char *)buf, 1)) != 1))
				goto checkerror;
		} else while (resid != 0) {
			char	junk[8192];	/* temporary buffer */

			isize = (resid > sizeof (junk)) ?
			    sizeof (junk) : resid;
			err = read(fd, junk, isize);
			if (err != isize)
				goto checkerror;
			resid -= err;
		}
	}

	return (AUDIO_SUCCESS);

checkerror:
	if ((err < 0) && (errno == EOVERFLOW)) {
		perror("read");
		exit(1);
	} else {
		return ((err < 0) ? AUDIO_UNIXERROR : AUDIO_ERR_BADFILEHDR);
	}
	return (AUDIO_SUCCESS);
}

/*
 * Return TRUE if the named file is an audio file.  Else, return FALSE.
 */
int
audio_isaudiofile(char *name)
{
	int		fd;
	int		err;
	int		file_type;	/* ignored */
	int		isize;
	Audio_hdr	hdr;
	unsigned char	buf[sizeof (au_filehdr_t)];

	/* Open the file (set O_NONBLOCK in case the name refers to a device) */
	fd = open(name, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		if (errno == EOVERFLOW) {
			perror("open");
			exit(1);
		} else {
			return (FALSE);
		}
	}

	/* Read the header (but not the text info). */
	err = read(fd, (char *)buf, sizeof (buf));
	if (err < 0) {
		if (errno == EOVERFLOW) {
			perror("open");
			exit(1);
		} else {
			return (FALSE);
		}
	}
	(void) close(fd);

	if ((err == sizeof (buf)) &&
	    (audio_decode_filehdr(fd, buf, &file_type, &hdr, &isize) ==
	    AUDIO_SUCCESS)) {
		return (hdr.encoding);
	} else {
		return (FALSE);
	}
}

/*
 * audio_endian()
 *
 * This routine tests the magic number at the head of a buffer
 * containing the file header.  The first thing in the header
 * should be the magic number.
 */
static int
audio_endian(unsigned char *buf, int *file_type)
{
	unsigned int	magic1;
	unsigned int	magic2;

	/* put the buffer into an int that is aligned properly */
	(void) memcpy(&magic1, buf, sizeof (magic1));

	magic2 = magic1;
	SWABI(magic2);

	if (magic1 == AUDIO_AU_FILE_MAGIC || magic2 == AUDIO_AU_FILE_MAGIC) {
		*file_type = FILE_AU;
		return (AUDIO_ENDIAN_BIG);
	} else if (magic1 == AUDIO_WAV_RIFF_ID || magic2 == AUDIO_WAV_RIFF_ID) {
		*file_type = FILE_WAV;
		return (AUDIO_ENDIAN_SMALL);
	} else if (magic1 == AUDIO_AIFF_HDR_CHUNK_ID ||
	    magic2 == AUDIO_AIFF_HDR_CHUNK_ID) {
		*file_type = FILE_AIFF;
		return (AUDIO_ENDIAN_BIG);
	}

	return (AUDIO_ENDIAN_UNKNOWN);
}

/*
 * Decode an aiff file header. Unlike .au and .wav, we have to process
 * by chunk.
 */
static int
decode_aiff(int fd, unsigned char *buf, Audio_hdr *hdrp, int *isize)
{
	aiff_hdr_chunk_t	hdr_chunk;
	aiff_comm_chunk_t	comm_chunk;
	aiff_ssnd_chunk_t	ssnd_chunk;
	uint32_t		ID;
	uint32_t		size;
	uint32_t		tmp;
	int			data_type;
	int			hdr_sizes;
	int			sr;
	short			bits_per_sample;
	short			channels;

	/* we've read in 4 bytes, read in the rest of the wav header */
	size = sizeof (hdr_chunk) - sizeof (hdr_chunk.aiff_hdr_ID);

	/* read in the rest of the header */
	if (read(fd, &hdr_chunk.aiff_hdr_size, size) != size) {
		return (AUDIO_UNIXERROR);
	}

	/* see which kind of audio file we have */
	AUDIO_AIFF_FILE2HOST_INT(&hdr_chunk.aiff_hdr_data_type, &data_type);
	if (data_type != AUDIO_AIFF_HDR_FORM_AIFF) {
		/* we can't play this version of a .aiff file */
		return (AUDIO_ERR_BADFILEHDR);
	}

	hdr_sizes = sizeof (hdr_chunk);

	/*
	 * We don't know what the chunk order will be, so read each, getting
	 * the data we need from each. Eventually we'll get to the end of
	 * the file, in which case we should have all of the info on the
	 * file that we need. We then lseek() back to the data to play.
	 *
	 * We start each loop by reading the chunk ID.
	 */
	while (read(fd, &tmp, sizeof (tmp)) == sizeof (tmp)) {
		AUDIO_AIFF_FILE2HOST_INT(&tmp, &ID);
		switch (ID) {
		case AUDIO_AIFF_COMM_ID:
			/* read in the rest of the COMM chunk */
			size = AUDIO_AIFF_COMM_CHUNK_SIZE -
			    sizeof (comm_chunk.aiff_comm_ID);
			if (read(fd, &comm_chunk.aiff_comm_size, size) !=
			    size) {
				return (AUDIO_UNIXERROR);
			}

			sr = convert_from_ieee_extended(
			    comm_chunk.aiff_comm_sample_rate);

			hdr_sizes += AUDIO_AIFF_COMM_CHUNK_SIZE;

			break;
		case AUDIO_AIFF_SSND_ID:
			/* read in the rest of the INST chunk */
			size = sizeof (ssnd_chunk) -
			    sizeof (ssnd_chunk.aiff_ssnd_ID);
			if (read(fd, &ssnd_chunk.aiff_ssnd_size, size) !=
			    size) {
				return (AUDIO_UNIXERROR);
			}

			/*
			 * This has to be the last chunk because the audio data
			 * follows. So we should have all we need to tell the
			 * app the format information.
			 */
			hdrp->sample_rate = sr;

			AUDIO_AIFF_FILE2HOST_SHORT(
			    &comm_chunk.aiff_comm_channels,
			    &channels);
			/* use channels to convert from short to int */
			hdrp->channels = channels;

			AUDIO_AIFF_FILE2HOST_SHORT(
			    &comm_chunk.aiff_comm_sample_size,
			    &bits_per_sample);
			switch (bits_per_sample) {
			case AUDIO_AIFF_COMM_8_BIT_SAMPLE_SIZE:
				hdrp->encoding = AUDIO_AU_ENCODING_LINEAR_8;
				break;
			case AUDIO_AIFF_COMM_16_BIT_SAMPLE_SIZE:
				hdrp->encoding = AUDIO_AU_ENCODING_LINEAR_16;
				break;
			default:
				return (AUDIO_ERR_BADFILEHDR);
			}

			AUDIO_AIFF_FILE2HOST_INT(&ssnd_chunk.aiff_ssnd_size,
			    &size);
			size -= sizeof (ssnd_chunk.aiff_ssnd_offset) +
			    sizeof (ssnd_chunk.aiff_ssnd_block_size);
			hdrp->data_size = size;

			hdr_sizes += sizeof (ssnd_chunk);

			*isize = hdr_sizes - sizeof (au_filehdr_t);

			return (AUDIO_SUCCESS);
		default:
			/*
			 * Unknown chunk. Read the size, which is right after
			 * the ID. Then seek past it to get to the next chunk.
			 */
			if (read(fd, &size, sizeof (size)) != sizeof (size)) {
				return (AUDIO_UNIXERROR);
			}

			if (lseek(fd, size, SEEK_CUR) < 0) {
				return (AUDIO_UNIXERROR);
			}
			break;
		}
	}

	return (AUDIO_SUCCESS);

}	/* decode_aiff() */

/*
 * Decode an au file header.
 */
static int
decode_au(int fd, unsigned char *buf, Audio_hdr *hdrp, int *isize,
    boolean_t read_info)
{
	au_filehdr_t	fhdr;
	int		offset;
	int		size;

	if (read_info) {
		/* read in the rest of the au header */
		size = sizeof (fhdr) - sizeof (int);
		(void) lseek(fd, (off_t)4, SEEK_SET);
		if (read(fd, &buf[sizeof (int)], size) != size) {

			return (AUDIO_UNIXERROR);
		}
	}

	/* put the buffer into a structure that is aligned properly */
	(void) memcpy(&fhdr, buf, sizeof (fhdr));

	/* Decode the 32-bit integer header fields. */
	AUDIO_AU_FILE2HOST(&fhdr.au_offset, &offset);
	AUDIO_AU_FILE2HOST(&fhdr.au_data_size, &hdrp->data_size);
	AUDIO_AU_FILE2HOST(&fhdr.au_encoding, &hdrp->encoding);
	AUDIO_AU_FILE2HOST(&fhdr.au_sample_rate, &hdrp->sample_rate);
	AUDIO_AU_FILE2HOST(&fhdr.au_channels, &hdrp->channels);

	/* Set the info field size (ie, number of bytes left before data). */
	*isize = offset - sizeof (au_filehdr_t);

	return (AUDIO_SUCCESS);

}	/* decode_au() */

/*
 * Decode a wav file header.
 *
 * .wav files are stored on-disk in little-endian format.
 */
static int
decode_wav(int fd, unsigned char *buf, Audio_hdr *hdrp, int *isize)
{
	wav_filehdr_t	fhdr;
	uint32_t	ID;
	uint32_t	size;
	short		bits_per_sample;
	short		encoding;

	/* we've read in 4 bytes, read in the rest of the wav header */
	size = sizeof (fhdr) - sizeof (int);

	/* read in the rest of the header */
	if (read(fd, &buf[sizeof (int)], size) != size) {
		return (AUDIO_UNIXERROR);
	}

	/* put the buffer into a structure that is aligned properly */
	(void) memcpy(&fhdr, buf, sizeof (fhdr));

	/* make sure we have the correct RIFF type */
	AUDIO_WAV_FILE2HOST_INT(&fhdr.wav_type_ID, &ID);
	if (ID != AUDIO_WAV_TYPE_ID) {
		/* not a wave file */
		return (AUDIO_ERR_BADFILEHDR);
	}

	/* decode the fields */
	AUDIO_WAV_FILE2HOST_INT(&fhdr.wav_fmt_ID, &ID);
	if (ID != AUDIO_WAV_FORMAT_ID) {
		/* mangled format */
		return (AUDIO_ERR_BADFILEHDR);
	}

	AUDIO_WAV_FILE2HOST_SHORT(&fhdr.wav_fmt_encoding, &encoding);
	AUDIO_WAV_FILE2HOST_SHORT(&fhdr.wav_fmt_channels, &hdrp->channels);
	AUDIO_WAV_FILE2HOST_INT(&fhdr.wav_fmt_sample_rate, &hdrp->sample_rate);
	AUDIO_WAV_FILE2HOST_SHORT(&fhdr.wav_fmt_bits_per_sample,
	    &bits_per_sample);

	/* convert .wav encodings to .au encodings */
	switch (encoding) {
	case AUDIO_WAV_FMT_ENCODING_PCM:
		switch (bits_per_sample) {
		case AUDIO_WAV_FMT_BITS_PER_SAMPLE_8_BITS:
			hdrp->encoding = AUDIO_AU_ENCODING_LINEAR_8;
			break;
		case AUDIO_WAV_FMT_BITS_PER_SAMPLE_16_BITS:
			hdrp->encoding = AUDIO_AU_ENCODING_LINEAR_16;
			break;
		default:
			return (AUDIO_ERR_BADFILEHDR);
		}
		break;
	case AUDIO_WAV_FMT_ENCODING_ALAW:
		hdrp->encoding = AUDIO_AU_ENCODING_ALAW;
		break;
	case AUDIO_WAV_FMT_ENCODING_MULAW:
		hdrp->encoding = AUDIO_AU_ENCODING_ULAW;
		break;
	default:
		return (AUDIO_ERR_BADFILEHDR);
	}

	AUDIO_WAV_FILE2HOST_INT(&fhdr.wav_data_size, &hdrp->data_size);

	*isize = sizeof (wav_filehdr_t) - sizeof (au_filehdr_t);

	return (AUDIO_SUCCESS);

}	/* decode_wav() */

/*
 * Try to decode buffer containing an audio file header into an audio header.
 */
int
audio_decode_filehdr(int fd, unsigned char *buf, int *file_type,
	Audio_hdr *hdrp, int *isize)
					/* file descriptor */
					/* buffer address */
					/* audio file type */
					/* output audio header */
					/* output size of info */
{
	int		err;
	struct stat	fd_stat;
	boolean_t	read_info;

	/* Test for .au first */
	hdrp->endian = audio_endian(buf, file_type);

	/*
	 * When cat'ing a file, audioconvert will read the whole header
	 * trying to figure out the file. audioplay however, does not.
	 * Hence we check if this is a pipe and do not attempt to read
	 * any more header info if the file type is already known.
	 * Otherwise we overwrite the header data already in the buffer.
	 */
	if (fstat(fd, &fd_stat) < 0) {
		return (AUDIO_ERR_BADFILEHDR);
	}
	if (S_ISFIFO(fd_stat.st_mode) && (*file_type == FILE_AU)) {
		read_info = B_FALSE;
	} else {
		/*
		 * Not an au file, or file type unknown. Reread the header's
		 * magic number. Fortunately this is always an int.
		 */
		(void) lseek(fd, (off_t)0, SEEK_SET);
		err = read(fd, (char *)buf, sizeof (int));
		read_info = B_TRUE;

		/* test the magic number to determine the endian */
		if ((hdrp->endian = audio_endian(buf, file_type)) ==
		    AUDIO_ENDIAN_UNKNOWN) {

			return (AUDIO_ERR_BADFILEHDR);
		}
	}

	/* decode the different file types, putting the data into hdrp */
	switch (*file_type) {
	case FILE_AU:
		if ((err = decode_au(fd, buf, hdrp, isize, read_info)) !=
		    AUDIO_SUCCESS) {
			return (err);
		}
		break;
	case FILE_WAV:
		if ((err = decode_wav(fd, buf, hdrp, isize)) != AUDIO_SUCCESS) {
			return (err);
		}
		break;
	case FILE_AIFF:
		if ((err = decode_aiff(fd, buf, hdrp, isize)) !=
		    AUDIO_SUCCESS) {
			return (err);
		}
		break;
	default:
		return (AUDIO_ERR_BADFILEHDR);
	}

	/* Convert from file format info to audio format info */
	switch (hdrp->encoding) {
	case AUDIO_AU_ENCODING_ULAW:
		hdrp->encoding = AUDIO_ENCODING_ULAW;
		hdrp->bytes_per_unit = 1;
		hdrp->samples_per_unit = 1;
		break;
	case AUDIO_AU_ENCODING_ALAW:
		hdrp->encoding = AUDIO_ENCODING_ALAW;
		hdrp->bytes_per_unit = 1;
		hdrp->samples_per_unit = 1;
		break;
	case AUDIO_AU_ENCODING_LINEAR_8:
		if (*file_type == FILE_WAV) {
			hdrp->encoding = AUDIO_ENCODING_LINEAR8;
		} else {
			hdrp->encoding = AUDIO_ENCODING_LINEAR;
		}
		hdrp->bytes_per_unit = 1;
		hdrp->samples_per_unit = 1;
		break;
	case AUDIO_AU_ENCODING_LINEAR_16:
		hdrp->encoding = AUDIO_ENCODING_LINEAR;
		hdrp->bytes_per_unit = 2;
		hdrp->samples_per_unit = 1;
		break;
	case AUDIO_AU_ENCODING_LINEAR_24:
		hdrp->encoding = AUDIO_ENCODING_LINEAR;
		hdrp->bytes_per_unit = 3;
		hdrp->samples_per_unit = 1;
		break;
	case AUDIO_AU_ENCODING_LINEAR_32:
		hdrp->encoding = AUDIO_ENCODING_LINEAR;
		hdrp->bytes_per_unit = 4;
		hdrp->samples_per_unit = 1;
		break;
	case AUDIO_AU_ENCODING_FLOAT:
		hdrp->encoding = AUDIO_ENCODING_FLOAT;
		hdrp->bytes_per_unit = 4;
		hdrp->samples_per_unit = 1;
		break;
	case AUDIO_AU_ENCODING_DOUBLE:
		hdrp->encoding = AUDIO_ENCODING_FLOAT;
		hdrp->bytes_per_unit = 8;
		hdrp->samples_per_unit = 1;
		break;
	case AUDIO_AU_ENCODING_ADPCM_G721:
		hdrp->encoding = AUDIO_ENCODING_G721;
		hdrp->bytes_per_unit = 1;
		hdrp->samples_per_unit = 2;
		break;
	case AUDIO_AU_ENCODING_ADPCM_G723_3:
		hdrp->encoding = AUDIO_ENCODING_G723;
		hdrp->bytes_per_unit = 3;
		hdrp->samples_per_unit = 8;
		break;
	case AUDIO_AU_ENCODING_ADPCM_G723_5:
		hdrp->encoding = AUDIO_ENCODING_G723;
		hdrp->bytes_per_unit = 5;
		hdrp->samples_per_unit = 8;
		break;

	default:
		return (AUDIO_ERR_BADFILEHDR);
	}
	return (AUDIO_SUCCESS);
}

/*
 * Encode a .aiff file header from the supplied Audio_hdr structure and
 * store in the supplied char* buffer. blen is the size of the buffer to
 * store the header in. Unlike .au and .wav we can't cast to a data structure.
 * We have to build it one chunk at a time.
 *
 * NOTE: .aiff doesn't support unsigned 8-bit linear PCM.
 */
static int
audio_encode_aiff(Audio_hdr *hdrp, unsigned char *buf, unsigned int *blen)
					/* audio header */
					/* output buffer */
					/* output buffer size */
{
	aiff_comm_chunk_t	comm_chunk;
	aiff_hdr_chunk_t	hdr_chunk;
	aiff_ssnd_chunk_t	ssnd_chunk;
	uint32_t		tmp_uint;
	uint32_t		tmp_uint2;
	int			buf_size = 0;
	uint16_t		tmp_ushort;

	/* the only encoding we support for .aiff is signed linear PCM */
	if (hdrp->encoding != AUDIO_ENCODING_LINEAR) {
		return (AUDIO_ERR_ENCODING);
	}

	/* build the header chunk */
	tmp_uint = AUDIO_AIFF_HDR_CHUNK_ID;
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &hdr_chunk.aiff_hdr_ID);
	/* needs to be fixed when closed */
	tmp_uint = AUDIO_AIFF_UNKNOWN_SIZE;
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &hdr_chunk.aiff_hdr_size);
	tmp_uint = AUDIO_AIFF_HDR_FORM_AIFF;
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &hdr_chunk.aiff_hdr_data_type);
	(void) memcpy(&buf[buf_size], &hdr_chunk, sizeof (hdr_chunk));
	buf_size += sizeof (hdr_chunk);

	/* build the COMM chunk */
	tmp_uint = AUDIO_AIFF_COMM_ID;
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &comm_chunk.aiff_comm_ID);
	tmp_uint = AUDIO_AIFF_COMM_SIZE;
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &comm_chunk.aiff_comm_size);
	tmp_ushort = hdrp->channels;
	AUDIO_AIFF_HOST2FILE_SHORT(&tmp_ushort, &comm_chunk.aiff_comm_channels);
	/* needs to be fixed when closed */
	tmp_uint = AUDIO_AIFF_UNKNOWN_SIZE;
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &tmp_uint2);
	AUDIO_AIFF_COMM_INT2FRAMES(comm_chunk.aiff_comm_frames, tmp_uint2);
	tmp_ushort = hdrp->bytes_per_unit * 8;
	AUDIO_AIFF_HOST2FILE_SHORT(&tmp_ushort,
	    &comm_chunk.aiff_comm_sample_size);
	convert_to_ieee_extended((double)hdrp->sample_rate,
	    comm_chunk.aiff_comm_sample_rate);
	(void) memcpy(&buf[buf_size], &comm_chunk, AUDIO_AIFF_COMM_CHUNK_SIZE);
	buf_size += AUDIO_AIFF_COMM_CHUNK_SIZE;

	/* build the SSND chunk */
	tmp_uint = AUDIO_AIFF_SSND_ID;
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &ssnd_chunk.aiff_ssnd_ID);
	/* needs to be fixed when closed */
	tmp_uint = AUDIO_AIFF_UNKNOWN_SIZE;
	AUDIO_AIFF_HOST2FILE_INT(&tmp_uint, &ssnd_chunk.aiff_ssnd_size);
	ssnd_chunk.aiff_ssnd_offset = 0;
	ssnd_chunk.aiff_ssnd_block_size = 0;
	(void) memcpy(&buf[buf_size], &ssnd_chunk, sizeof (ssnd_chunk));
	buf_size += sizeof (ssnd_chunk);

	*blen = buf_size;

	return (AUDIO_SUCCESS);

}	/* audio_encode_aiff() */

/*
 * Encode a .au file header from the supplied Audio_hdr structure and
 * store in the supplied char* buffer. blen is the size of the buffer to
 * store the header in. If 'infop' is not NULL, it is the address of a
 * buffer containing 'info' data. 'ilen' specifies the size of this buffer.
 * The entire file header will be zero-padded to a double-word boundary.
 *
 * NOTE: .au doesn't support unsigned 8-bit linear PCM.
 */
static int
audio_encode_au(Audio_hdr *hdrp, char *infop, unsigned int ilen,
	unsigned char *buf, unsigned int *blen)
					/* audio header */
					/* info buffer pointer */
					/* info buffer size */
					/* output buffer */
					/* output buffer size */
{
	au_filehdr_t	fhdr;
	int		encoding;
	int		hdrsize;
	int		magic;
	int		offset;

	/*
	 * Set the size of the real header (hdr size + info size).
	 * If no supplied info, make sure a minimum size is accounted for.
	 * Also, round the whole thing up to double-word alignment.
	 */
	if ((infop == NULL) || (ilen == 0)) {
		infop = NULL;
		ilen = 4;
	}
	hdrsize = sizeof (fhdr) + ilen;
	offset = ROUND_DBL(hdrsize);

	/* Check the data encoding. */
	switch (hdrp->encoding) {
	case AUDIO_ENCODING_LINEAR8:
		return (AUDIO_ERR_ENCODING);	/* we don't support ulinear */
	case AUDIO_ENCODING_ULAW:
		if (hdrp->samples_per_unit != 1)
			return (AUDIO_ERR_BADHDR);

		switch (hdrp->bytes_per_unit) {
		case 1:
			encoding = AUDIO_AU_ENCODING_ULAW;
			break;
		default:
			return (AUDIO_ERR_BADHDR);
		}
		break;
	case AUDIO_ENCODING_ALAW:
		if (hdrp->samples_per_unit != 1)
			return (AUDIO_ERR_BADHDR);

		switch (hdrp->bytes_per_unit) {
		case 1:
			encoding = AUDIO_AU_ENCODING_ALAW;
			break;
		default:
			return (AUDIO_ERR_BADHDR);
		}
		break;
	case AUDIO_ENCODING_LINEAR:
		if (hdrp->samples_per_unit != 1)
			return (AUDIO_ERR_BADHDR);

		switch (hdrp->bytes_per_unit) {
		case 1:
			encoding = AUDIO_AU_ENCODING_LINEAR_8;
			break;
		case 2:
			encoding = AUDIO_AU_ENCODING_LINEAR_16;
			break;
		case 3:
			encoding = AUDIO_AU_ENCODING_LINEAR_24;
			break;
		case 4:
			encoding = AUDIO_AU_ENCODING_LINEAR_32;
			break;
		default:
			return (AUDIO_ERR_BADHDR);
		}
		break;
	case AUDIO_ENCODING_FLOAT:
		if (hdrp->samples_per_unit != 1)
			return (AUDIO_ERR_BADHDR);

		switch (hdrp->bytes_per_unit) {
		case 4:
			encoding = AUDIO_AU_ENCODING_FLOAT;
			break;
		case 8:
			encoding = AUDIO_AU_ENCODING_DOUBLE;
			break;
		default:
			return (AUDIO_ERR_BADHDR);
		}
		break;
	case AUDIO_ENCODING_G721:
		if (hdrp->bytes_per_unit != 1)
			return (AUDIO_ERR_BADHDR);
		else if (hdrp->samples_per_unit != 2)
			return (AUDIO_ERR_BADHDR);
		else
			encoding = AUDIO_AU_ENCODING_ADPCM_G721;
		break;
	case AUDIO_ENCODING_G723:
		if (hdrp->samples_per_unit != 8)
			return (AUDIO_ERR_BADHDR);
		else if (hdrp->bytes_per_unit == 3)
			encoding = AUDIO_AU_ENCODING_ADPCM_G723_3;
		else if (hdrp->bytes_per_unit == 5)
			encoding = AUDIO_AU_ENCODING_ADPCM_G723_5;
		else
			return (AUDIO_ERR_BADHDR);
		break;
	default:
		return (AUDIO_ERR_BADHDR);
	}

	/* copy the fhdr into the supplied buffer - make sure it'll fit */
	if (*blen < offset) {
		/* XXX - is this apropriate? */
		return (AUDIO_EOF);
	}

	/* reset blen to actual size of hdr data */
	*blen = (unsigned)offset;

	magic = AUDIO_AU_FILE_MAGIC;	/* set the magic number */

	/* Encode the audio header structure. */
	AUDIO_AU_HOST2FILE(&magic, &fhdr.au_magic);
	AUDIO_AU_HOST2FILE(&offset, &fhdr.au_offset);
	AUDIO_AU_HOST2FILE(&hdrp->data_size, &fhdr.au_data_size);
	AUDIO_AU_HOST2FILE(&encoding, &fhdr.au_encoding);
	AUDIO_AU_HOST2FILE(&hdrp->sample_rate, &fhdr.au_sample_rate);
	AUDIO_AU_HOST2FILE(&hdrp->channels, &fhdr.au_channels);

	/* Copy to the buffer */
	(void) memcpy(buf, &fhdr, sizeof (fhdr));

	/* Copy the info data, if present */
	if (infop != NULL) {
		(void) memcpy(&buf[sizeof (fhdr)], infop, (int)ilen);
		buf += ilen;
	}

	if (offset > hdrsize) {
		(void) memset(&buf[hdrsize], '\0', (size_t)(offset - hdrsize));
	}

	/* buf now has the data, just return ... */

	return (AUDIO_SUCCESS);

}	/* audio_encode_au() */

/*
 * Encode a .wav file header from the supplied Audio_hdr structure and
 * store in the supplied char* buffer. blen is the size of the buffer to
 * store the header in. .wav doesn't support an information string like
 * .au does.
 *
 * NOTE: .wav only supports a few encoding methods.
 */
static int
audio_encode_wav(Audio_hdr *hdrp, unsigned char *buf, unsigned int *blen)
					/* audio header */
					/* output buffer */
					/* output buffer size */
{
	wav_filehdr_t	fhdr;
	int		bytes_per_second;
	int		bytes_per_sample;
	int		bits_per_sample;
	int		id;
	int		length;
	int		type;
	short		encoding;

	/* make sure we've got valid encoding and precision settings for .wav */
	switch (hdrp->encoding) {
	case AUDIO_ENCODING_LINEAR8:
		if (hdrp->bytes_per_unit != 1) {
			return (AUDIO_ERR_ENCODING);
		}
		encoding = AUDIO_WAV_FMT_ENCODING_PCM;
		break;
	case AUDIO_ENCODING_ULAW:
		if (hdrp->bytes_per_unit != 1) {
			return (AUDIO_ERR_ENCODING);
		}
		encoding = AUDIO_WAV_FMT_ENCODING_MULAW;
		break;
	case AUDIO_ENCODING_ALAW:
		if (hdrp->bytes_per_unit != 1) {
			return (AUDIO_ERR_ENCODING);
		}
		encoding = AUDIO_WAV_FMT_ENCODING_ALAW;
		break;
	case AUDIO_ENCODING_LINEAR:
		if (hdrp->bytes_per_unit != 2) {
			return (AUDIO_ERR_ENCODING);
		}
		encoding = AUDIO_WAV_FMT_ENCODING_PCM;
		break;
	default:
		return (AUDIO_ERR_ENCODING);
	}

	/* fill in the riff chunk */
	id = AUDIO_WAV_RIFF_ID;
	length = AUDIO_WAV_UNKNOWN_SIZE;
	AUDIO_WAV_HOST2FILE_INT(&id, &fhdr.wav_riff_ID);
	AUDIO_WAV_HOST2FILE_INT(&length, &fhdr.wav_riff_size);

	/* fill in the type chunk */
	type = AUDIO_WAV_TYPE_ID;
	AUDIO_WAV_HOST2FILE_INT(&type, &fhdr.wav_type_ID);


	/* fill in the format chunk */
	id = AUDIO_WAV_FORMAT_ID;
	length = AUDIO_WAV_FORMAT_SIZE;
	bytes_per_second = hdrp->sample_rate * hdrp->channels *
	    hdrp->bytes_per_unit;
	bytes_per_sample = hdrp->channels * hdrp->bytes_per_unit;
	bits_per_sample = hdrp->bytes_per_unit * 8;

	AUDIO_WAV_HOST2FILE_INT(&id, &fhdr.wav_fmt_ID);
	AUDIO_WAV_HOST2FILE_INT(&length, &fhdr.wav_fmt_size);
	AUDIO_WAV_HOST2FILE_SHORT(&encoding, &fhdr.wav_fmt_encoding);
	AUDIO_WAV_HOST2FILE_SHORT(&hdrp->channels, &fhdr.wav_fmt_channels);
	AUDIO_WAV_HOST2FILE_INT(&hdrp->sample_rate, &fhdr.wav_fmt_sample_rate);
	AUDIO_WAV_HOST2FILE_INT(&bytes_per_second,
	    &fhdr.wav_fmt_bytes_per_second);
	AUDIO_WAV_HOST2FILE_SHORT(&bytes_per_sample,
	    &fhdr.wav_fmt_bytes_per_sample);
	AUDIO_WAV_HOST2FILE_SHORT(&bits_per_sample,
	    &fhdr.wav_fmt_bits_per_sample);

	/* fill in the data chunk */
	id = AUDIO_WAV_DATA_ID_LC;
	length = AUDIO_WAV_UNKNOWN_SIZE;
	AUDIO_WAV_HOST2FILE_INT(&id, &fhdr.wav_data_ID);
	AUDIO_WAV_HOST2FILE_INT(&length, &fhdr.wav_data_size);

	*blen = sizeof (fhdr);

	/* copy to the buffer */
	(void) memcpy(buf, &fhdr, sizeof (fhdr));

	return (AUDIO_SUCCESS);

}	/* audio_encode_wav() */

/*
 * Utility routine used to convert 10 byte IEEE extended float into
 * a regular double. Raw data arrives in an unsigned char array. Because
 * this is for sample rate, which is always positive, we don't worry
 * about the sign.
 */
static double
convert_from_ieee_extended(unsigned char *data)
{
	double		value = 0.0;
	unsigned long	high_mantissa;
	unsigned long	low_mantissa;
	int		exponent;

	/* first 2 bytes are the exponent */
	exponent = ((data[0] & 0x7f) << 8) | data[1];

	high_mantissa = ((unsigned long)data[2] << 24) |
	    ((unsigned long)data[3] << 16) |
	    ((unsigned long)data[4] << 8) |
	    (unsigned long)data[5];
	low_mantissa = ((unsigned long)data[6] << 24) |
	    ((unsigned long)data[7] << 16) |
	    ((unsigned long)data[8] << 8) |
	    (unsigned long)data[9];

	/* convert exponent and mantissas into a real double */
	if (exponent == 0 && high_mantissa == 0 && low_mantissa == 0) {
		/* everything is 0, so we're done */
		value = 0.0;
	} else {
		if (exponent == 0x7fff) {	/* infinity */
			value = MAXFLOAT;
		} else {
			/* convert exponent from being unsigned to signed */
			exponent -= 0x3fff;

			exponent -= 31;
			value = ldexp((double)high_mantissa, exponent);

			exponent -= 32;
			value += ldexp((double)low_mantissa, exponent);
		}
	}

	return (value);

}

/*
 * Utility routine to convert a double into 10 byte IEEE extended floating
 * point. The new number is placed into the unsigned char array. This is a
 * very brain dead convesion routine. It only supports integers, but then
 * that should be all we need for sample rate.
 */
static void
convert_to_ieee_extended(double value, unsigned char *data)
{
	double		fmantissa;
	int		exponent;
	int		mantissa;

	exponent = 16398;
	fmantissa = value;

	while (fmantissa < 44000) {
		fmantissa *= 2;
		exponent--;
	}

	mantissa = (int)fmantissa << 16;

	data[0] = exponent >> 8;
	data[1] = exponent;
	data[2] = mantissa >> 24;
	data[3] = mantissa >> 16;
	data[4] = mantissa >> 8;
	data[5] = mantissa;
	data[6] = 0;
	data[7] = 0;
	data[8] = 0;
	data[9] = 0;

}
