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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <AudioDebug.h>
#include <AudioDevice.h>

#define	irint(d)	((int)(d))

// class AudioDevice methods


// class AudioInfo Constructor
AudioInfo::
AudioInfo()
{
	Clear();
}

// Reset the info structure
void AudioInfo::
Clear()
{
	AUDIO_INITINFO(&info);
}


// Initialize default device access mode, used when no mode is supplied
const FileAccess	AudioDevice::defmode = WriteOnly;

// Default audio device and environment variable names
const char *AudioDevice::AUDIO_ENV = "AUDIODEV";
const char *AudioDevice::AUDIO_DEV = "/dev/audio";


// Constructor with optional path and mode arguments
AudioDevice::
AudioDevice(
	const char		*path,		// filename
	const FileAccess	acc):		// access mode
	AudioUnixfile(path, acc),
	devtype(AudioDeviceUnknown)
{
}

// Destructor must call the local Close() routine
AudioDevice::
~AudioDevice()
{
	// If the device was open, close it
	if (opened()) {
		(void) Close();
	}
}

// Return TRUE if stream is open
Boolean AudioDevice::
opened() const
{
	return (isfdset());
}

// Get the audio device type
AudioDeviceType AudioDevice::
GetDeviceType() const
{
	return (devtype);
}

// Get the device information structure
AudioError AudioDevice::
GetState(
	AudioInfo&	info) const		// info to set
{
	// Get the device information
	if (ioctl(getfd(), AUDIO_GETINFO, &info) < 0)
		return (RaiseError(AUDIO_UNIXERROR, Warning));
	return (AUDIO_SUCCESS);
}

// Set the device information structure (and return it updated)
AudioError AudioDevice::
SetState(
	AudioInfo&	info)			// info to set
{
	int		i;
	AudioHdr	hdr_local;
	AudioError	err;

	if (!opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// Set the device information
	// Try a couple of times if interrupted by a signal
	for (i = 0; i < 3; i++) {
		if (ioctl(getfd(), AUDIO_SETINFO, &info) >= 0) {
			// Save the new encoding
			err = info_to_hdr(info->record, hdr_local);
			if (!err)
				readhdr = hdr_local;
			return (err);
		}
		if (errno != EINTR)
			break;
	}
	return (AUDIO_UNIXERROR);
}

// Enable/disable SIGPOLL for the device
// The normal device receives signals only on i/o conditions
// For state change notification, open the control device
AudioError AudioDevice::
SetSignal(
	Boolean		on)			// True to enable
{
	int		flag;

	// Flag of zero disables SIGPOLL
	flag = 0;
	if (on) {
		// Enable signals for the accessed streams
		if (GetAccess().Readable())
			flag |= S_INPUT;
		if (GetAccess().Writeable())
			flag |= S_OUTPUT;
	}
	// Set the streams flag
	if (ioctl(getfd(), I_SETSIG, flag) < 0)
		return (RaiseError(AUDIO_UNIXERROR));
	return (AUDIO_SUCCESS);
}

// Clear the cached read header
void AudioDevice::
clearhdr()
{
	readhdr.Clear();
}

// Decode a device info structure into an audio file header
AudioError AudioDevice::
info_to_hdr(
	const AudioPRinfo&	prinfo,		// info structure to decode
	AudioHdr&		h) const	// header to fill in
{
	AudioHdr		hdr_local;	// local copy of header
	AudioError		err;

	hdr_local.sample_rate = prinfo.sample_rate;
	hdr_local.channels = prinfo.channels;

	switch (prinfo.encoding) {
	case AUDIO_ENCODING_ULAW:
		hdr_local.encoding = ULAW;
		hdr_local.samples_per_unit = 1;
		hdr_local.bytes_per_unit = prinfo.precision / 8;
		break;
	case AUDIO_ENCODING_ALAW:
		hdr_local.encoding = ALAW;
		hdr_local.samples_per_unit = 1;
		hdr_local.bytes_per_unit = prinfo.precision / 8;
		break;
	case AUDIO_ENCODING_LINEAR:
		hdr_local.encoding = LINEAR;
		hdr_local.samples_per_unit = 1;
		hdr_local.bytes_per_unit = prinfo.precision / 8;
		break;
	default:
		return (RaiseError(AUDIO_ERR_ENCODING));
	}

	err = RaiseError(hdr_local.Validate());
	if (err == AUDIO_SUCCESS)
		h = hdr_local;
	return (err);
}

// Decode an audio file header into a device info structure
AudioError AudioDevice::
hdr_to_info(
	const AudioHdr&		h,		// header to decode
	AudioPRinfo&		prinfo) const	// info structure to fill in
{
	AudioInfo		info;		// local copy of info
	AudioError		err;

	// Validate header before converting
	err = RaiseError(h.Validate());
	if (err != AUDIO_SUCCESS)
		return (err);

	info->play.sample_rate = h.sample_rate;
	info->play.channels = h.channels;

	switch (h.encoding) {
	case ULAW:
		info->play.encoding = AUDIO_ENCODING_ULAW;
		info->play.precision = h.bytes_per_unit * 8;
		break;
	case ALAW:
		info->play.encoding = AUDIO_ENCODING_ALAW;
		info->play.precision = h.bytes_per_unit * 8;
		break;
	case LINEAR:
		info->play.encoding = AUDIO_ENCODING_LINEAR;
		info->play.precision = h.bytes_per_unit * 8;
		break;
	default:
		return (RaiseError(AUDIO_ERR_ENCODING));
	}

	prinfo = info->play;
	return (AUDIO_SUCCESS);
}

// Figure out what kind of audio device is connected
// XXX - this should be replaced by a capabilities database lookup
void AudioDevice::
decode_devtype()
{
#ifdef MAX_AUDIO_DEV_LEN
	struct audio_device	adev;
#else /* 4.1.3 */
	int			adev;
#endif /* 4.1.3 */

/*
 * Spectrum 16, MultiSound and SB16 are all place holders for
 * x86 devices.
 */
	if (ioctl(getfd(), AUDIO_GETDEV, &adev) >= 0) {
#ifdef MAX_AUDIO_DEV_LEN
		if (strcmp(adev.name, "SUNW,CS4231") == 0)
			devtype = AudioDeviceCODEC;
		else if (strcmp(adev.name, "SUNW,audiots") == 0)
			devtype = AudioDeviceCODEC;
		else if (strcmp(adev.name, "SUNW,am79c30") == 0)
			devtype = AudioDeviceAMD;
		else if (strcmp(adev.name, "SUNW,sbpro") == 0)
			devtype = AudioDeviceSBPRO;
		else if (strcmp(adev.name, "SUNW,spectrum") == 0)
			devtype = AudioDeviceSPECTRUM;
		else if (strcmp(adev.name, "SUNW,multisound") == 0)
			devtype = AudioDeviceMULTISOUND;
		else if (strcmp(adev.name, "SUNW,sb16") == 0)
			devtype = AudioDeviceSB16;
		else
			devtype = AudioDeviceUnknown;
#else /* 4.1.3 */
	switch (adev) {
	case AUDIO_DEV_AMD:
		devtype = AudioDeviceAMD;
		break;
	default:
		devtype = AudioDeviceUnknown;
		break;
	}
#endif /* 4.1.3 */
	} else {
		// AUDIO_GETDEV not supported.  Assume AMD.
		devtype = AudioDeviceAMD;
	}
}

// Return TRUE if the sample rates are within a close tolerance (1%)
Boolean AudioDevice::
rate_match(
	unsigned int		rate1,
	unsigned int		rate2)
{
	Double			tol;

	tol = ((double)rate2 - (double)rate1) / (double)rate2;
	if (fabs(tol) > .01)
		return (FALSE);
	return (TRUE);
}

// Return TRUE if the device supports the audio format
// If the sample rate does not match, but is within tolerance, rewrite it.
// XXX - this should *really* be replaced by a capabilities database lookup
Boolean AudioDevice::
CanSetHeader(
	AudioHdr&		h)
{
	if (RaiseError(h.Validate()) || !opened())
		return (FALSE);

	switch (devtype) {
	default:			// if unknown type, assume AMD
	case AudioDeviceAMD:
		if ((h.encoding != ULAW) && (h.encoding != ALAW))
			return (FALSE);
		if (!rate_match(h.sample_rate, 8000) || (h.channels != 1))
			return (FALSE);
		h.sample_rate = 8000;
		break;

	case AudioDeviceCODEC:
		if (h.channels > 2)
			return (FALSE);
		switch (h.encoding) {
		case ULAW:
		case ALAW:
		case LINEAR:
			break;
		default:
			return (FALSE);
		}
		if (rate_match(h.sample_rate, 5510)) {
			h.sample_rate = 5510;
		} else if (rate_match(h.sample_rate, 6620)) {
			h.sample_rate = 6620;
		} else if (rate_match(h.sample_rate, 8000)) {
			h.sample_rate = 8000;
		} else if (rate_match(h.sample_rate, 9600)) {
			h.sample_rate = 9600;
		} else if (rate_match(h.sample_rate, 11025)) {
			h.sample_rate = 11025;
		} else if (rate_match(h.sample_rate, 16000)) {
			h.sample_rate = 16000;
		} else if (rate_match(h.sample_rate, 18900)) {
			h.sample_rate = 18900;
		} else if (rate_match(h.sample_rate, 22050)) {
			h.sample_rate = 22050;
		} else if (rate_match(h.sample_rate, 27420)) {
			h.sample_rate = 27420;
		} else if (rate_match(h.sample_rate, 32000)) {
			h.sample_rate = 32000;
		} else if (rate_match(h.sample_rate, 33075)) {
			h.sample_rate = 33075;
		} else if (rate_match(h.sample_rate, 37800)) {
			h.sample_rate = 37800;
		} else if (rate_match(h.sample_rate, 44100)) {
			h.sample_rate = 44100;
		} else if (rate_match(h.sample_rate, 48000)) {
			h.sample_rate = 48000;
		} else {
			return (FALSE);
		}
		break;
	case AudioDeviceSBPRO:
		if (h.encoding != ULAW)  // For now only supports ULAW
			return (FALSE);
		if (h.channels > 2)
			return (FALSE);
		if (h.sample_rate < 4000 || h.sample_rate > 44100)
			return (FALSE);
		break;
	case AudioDeviceSB16:
	/*
	 * Place holders for x86 devices, these are treated as if they
	 * are equivelant to the SB16 for now.
	 */
	case AudioDeviceSPECTRUM:
	case AudioDeviceMULTISOUND:
		if (h.channels > 2)
			return (FALSE);
		switch (h.encoding) {
		/*
		 * The SBPro driver does not do ALAW
		 */
		case ULAW:
			break;
		case LINEAR:
			// We don't support 8bit linear as this should
			// be unsigned linear and we have assumed signed all
			// along. Must change this in XAL
			if (h.bytes_per_unit != 2) // LINEAR must be 16 bit
				return (FALSE);
			break;
		default:
			return (FALSE);
		}
		// I don't know if this is correct - sdy check it out please
		if (h.sample_rate < 4000 || h.sample_rate > 44100)
			return (FALSE);
		break;
	}
	return (TRUE);
}

// Set input encoding
AudioError AudioDevice::
SetReadHeader(
	AudioHdr&		h)	// header (updated)
{
	AudioInfo		info;
	AudioError		err;

	// Convert header to encoding fields
	err = hdr_to_info(h, info->record);
	if (err == AUDIO_SUCCESS) {
		// Set the device encoding
		err = SetState(info);
		if (!err)
			h = readhdr;
	}
	return (err);
}

// Set output encoding
AudioError AudioDevice::
SetWriteHeader(
	AudioHdr&		h)	// header (updated)
{
	AudioInfo		info;
	AudioError		err;

	// Convert header to encoding fields
	err = hdr_to_info(h, info->play);
	if (err == AUDIO_SUCCESS) {
		// Set the device encoding
		err = SetState(info);
		if (err == AUDIO_SUCCESS) {
			// Save (and return) the new encoding
			err = info_to_hdr(info->play, h);
			if (!err)
				(void) AudioStream::updateheader(h);
		}
	}
	return (err);
}

// Get input encoding
AudioHdr AudioDevice::
GetReadHeader()
{
	AudioInfo		info;
	AudioHdr		h;

	// If the cached header is valid, use it.
	// XXX - If a state change determines the encoding changed, we had
	// XXX - better invalidate the cache and call this routine again.
	if (readhdr.Validate() == AUDIO_SUCCESS)
		return (readhdr);

	// Get the device state
	if (GetState(info) == AUDIO_SUCCESS) {
		(void) info_to_hdr(info->record, h);
		readhdr = h;
	}
	return (h);
}

// Get output encoding
AudioHdr AudioDevice::
GetWriteHeader()
{
	AudioInfo		info;
	AudioHdr		h;

	// Get the device state
	if (GetState(info) == AUDIO_SUCCESS) {
		(void) info_to_hdr(info->play, h);
		(void) AudioStream::updateheader(h);
	}
	return (h);
}

// SetHeader function sets the output encoding
AudioError AudioDevice::
SetHeader(
	const AudioHdr&	h)		// header
{
	AudioError	err;
	AudioHdr	tmphdr;

	// Set the output header in the cached structure
	err = AudioStream::updateheader(h);
	if (!opened() || (err != AUDIO_SUCCESS)) {
		if ((err == AUDIO_UNIXERROR) && (err.sys == EBUSY))
			err = AUDIO_ERR_FORMATLOCK;
		return (err);
	}

	// If the device is open, set the output header
	return (SetWriteHeader(tmphdr = AudioStream::GetHeader()));
}

// GetHeader returns the cached input encoding
AudioHdr AudioDevice::
GetHeader()
{
	if (GetPlayOpen()) {
		return (GetWriteHeader());
	} else {
		return (GetReadHeader());
	}
}

// Open an audio device for output
// Open the device and set the output encoding
AudioError AudioDevice::
Create()
{
	AudioError	err;
	AudioHdr	tmphdr;

	if (!hdrset())
		return (RaiseError(AUDIO_ERR_BADHDR));
	err = Open();
	if (err == AUDIO_SUCCESS)
		err = SetWriteHeader(tmphdr = AudioStream::GetHeader());
	return (err);
}

// Open an audio device
AudioError AudioDevice::
Open()
{
	// If name was NULL, use default search path
	return (OpenPath());
}

// Open an audio device, with a path environment as a fall-back
AudioError AudioDevice::
OpenPath(
	const char	*path)
{
	char		*str;
	char		*wrk;
	char		*component;
	int		openmode;
	AudioError	err;

	// Convert the open mode to an int argument for open()
	openmode = GetAccess();

	// Can't open if already opened or if mode not set
	if ((openmode == -1) || opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// If non-blocking set, this counts for open(), too
	if (!GetBlocking())
		openmode |= O_NONBLOCK;

	// Search path:
	//	1) try name, if supplied: fail if no good
	//	2) if no name, try to find 'path' in the environment:
	//		if not found, assume 'path' is the path string itself
	//		first try the path as a deivce name
	//		then, try every colon-separated path component in it
	//	3) try "/dev/audio"

	if (strlen(GetName()) != 0)
		return (RaiseError(tryopen(GetName(), openmode)));

	// Try path as environment variable name, else assume it is a path
	str = (path == NULL) ? NULL : getenv(path);
	if (str == NULL)
		str = (char *)path;

	if (str != NULL) {
		// Make a copy of the path, in case we have to parse it
		wrk = new char[strlen(str) + 1];
		(void) strcpy(wrk, str);
		str = wrk;

		// Try the whole string, then every component
		for (component = str; component[0] != '\0'; ) {
			err = tryopen(component, openmode);
			switch (err) {
			case AUDIO_SUCCESS:		// found a device
			case AUDIO_ERR_DEVICEBUSY:
				delete wrk;
				return (RaiseError(err));
			}
			if (str == NULL)
				break;
			component = str;
			str = strchr(str, ':');
			if (str != NULL)
				*str++ = '\0';
		}
		delete wrk;
	}
	return (RaiseError(tryopen(AUDIO_DEV, openmode)));
}

// Attempt to open the audio device with the given name and mode
AudioError AudioDevice::
tryopen(
	const char	*devname,
	int		openmode)
{
	struct stat	st;
	int		desc;
	AudioInfo	info;
	AudioError	err;

	// If the name is changing, set the new one
	if (devname != GetName())
		SetName(devname);

	// XXX - convert name to device name, using audio config file

	// Check the file.  If non-existent, give up.
	if (stat(devname, &st) < 0) {
		return (AUDIO_UNIXERROR);
	}

	// If not a character file, stop right there
	if (!S_ISCHR(st.st_mode))
		return (AUDIO_ERR_NOTDEVICE);

	// Open the file and check that it's an audio file
	desc = open(devname, openmode);
	if (desc < 0) {
		if (errno == EBUSY) {
			return (AUDIO_ERR_DEVICEBUSY);
		} else {
			return (AUDIO_UNIXERROR);
		}
	}

	// Set the file descriptor (this marks the file open)
	setfd(desc);
	err = GetState(info);
	if (err != AUDIO_SUCCESS) {
		(void) close(desc);
		setfd(-1);
		return (err);
	}

	// Get the device type
	decode_devtype();

	// Set up the cached versions of the current encoding format
	if (GetAccess().Writeable())
		(void) GetWriteHeader();
	if (GetAccess().Readable())
		(void) GetReadHeader();

	// Set the appropriate blocking/non-blocking mode
	SetBlocking(GetBlocking());
	return (AUDIO_SUCCESS);
}

// Read data from device into specified buffer.
// No data format translation takes place.
// Since there's no going back, the object's read position pointer is updated.
AudioError AudioDevice::
ReadData(
	void*		buf,		// destination buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	AudioError	err;
	size_t		svlen;

	svlen = len;

	// Call the real routine
tryagain:
	len = svlen;
	err = AudioUnixfile::ReadData(buf, len, pos);

	// XXX - Check for bug 1100839: short blocking reads
	if (GetBlocking()) {
		if (err == AUDIO_EOF)
			goto tryagain;
		if (!err && (len < svlen)) {
			if (len == 0) {
				AUDIO_DEBUG((1,
			    "AudioDevice: zero-length blocking read\n"));
				goto tryagain;
			} else {
				AUDIO_DEBUG((1,
				    "AudioDevice: short blocking read: %d/%d\n",
				    len, svlen));
			}
		}
	}

	// Update the object's read position
	if (!err)
		(void) SetReadPosition(pos, Absolute);

	return (err);
}

// Write data to device from specified buffer.
// No data format translation takes place.
// Since there's no going back, the object's write position pointer is updated.
AudioError AudioDevice::
WriteData(
	void*		buf,		// source buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	AudioError	err;

	// Call the real routine
	err = AudioUnixfile::WriteData(buf, len, pos);

	// Update the object's write position
	if (err == AUDIO_SUCCESS)
		(void) SetWritePosition(pos, Absolute);
	return (err);
}

// Write eof sync flag
AudioError AudioDevice::
WriteEof()
{
	Boolean		EOFblock;
	AudioError	err;

	if (!opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// Make sure the device is set to blocking mode
	if (!(EOFblock = GetBlocking()))
		SetBlocking(TRUE);

	// A zero-length write represents an EOF marker
	if (write(getfd(), NULL, 0) < 0) {
		// A failed non-blocking request should never happen!
		if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
			err = AUDIO_ERR_NOEFFECT;
		} else {
			err = AUDIO_UNIXERROR;
		}
	}
	// Restore blocking mode
	if (!EOFblock)
		SetBlocking(EOFblock);
	return (RaiseError(err));
}

// Flush all queued input and output
AudioError AudioDevice::
Flush(
	const FileAccess	which)
{
	int			flag;
	AudioInfo		info;
	Double			pos;

	if (!opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	flag = 0;
	if (which.Writeable())
		flag |= FLUSHW;
	if (which.Readable())
		flag |= FLUSHR;

	if (ioctl(getfd(), I_FLUSH, flag) < 0)
		return (RaiseError(AUDIO_UNIXERROR));

	if (which.Writeable()) {
		// Back up the object's write position
		if (!GetState(info)) {
			pos = GetWriteHeader().Samples_to_Time(
			    info->play.samples);
			(void) SetWritePosition(pos, Absolute);
		}
	}
	return (AUDIO_SUCCESS);
}

// Wait for output to drain
AudioError AudioDevice::
DrainOutput()
{
	if (!opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	while (ioctl(getfd(), AUDIO_DRAIN, 0) < 0) {
		// If interrupted system call while fd is set blocking, retry
		if ((errno == EINTR) && GetBlocking())
			continue;
		return (RaiseError(AUDIO_UNIXERROR));
	}
	return (AUDIO_SUCCESS);
}

// Set the input/output pause flags on the device
AudioError AudioDevice::
Pause(
	const FileAccess	which)
{
	AudioInfo		info;

	if (which.Writeable())
		info->play.pause = TRUE;
	if (which.Readable())
		info->record.pause = TRUE;
	return (SetState(info));
}

// Resume input/output on the device
AudioError AudioDevice::
Resume(
	const FileAccess	which)
{
	AudioInfo		info;

	if (which.Writeable())
		info->play.pause = FALSE;
	if (which.Readable())
		info->record.pause = FALSE;
	return (SetState(info));
}

// Set play eof count
AudioError AudioDevice::
SetPlayEof(
	unsigned&		cnt)
{
	AudioInfo		info;
	AudioError		err;

	info->play.eof = cnt;
	err = SetState(info);
	if (err == AUDIO_SUCCESS)
		cnt = info->play.eof;
	return (err);
}

// Set play sample count
AudioError AudioDevice::
SetPlaySamples(
	unsigned&		cnt)
{
	AudioInfo		info;
	AudioError		err;

	info->play.samples = cnt;
	err = SetState(info);
	if (err == AUDIO_SUCCESS)
		cnt = info->play.samples;
	return (err);
}

// Set record sample count
AudioError AudioDevice::
SetRecSamples(
	unsigned&		cnt)
{
	AudioInfo		info;
	AudioError		err;

	info->record.samples = cnt;
	err = SetState(info);
	if (err == AUDIO_SUCCESS)
		cnt = info->record.samples;
	return (err);
}

// Set play error flag, returning old state
AudioError AudioDevice::
SetPlayError(
	Boolean&		flag)
{
	AudioInfo		info;
	AudioError		err;

	info->play.error = flag;
	err = SetState(info);
	if (err == AUDIO_SUCCESS)
		flag = info->play.error;
	return (err);
}

// Set record error flag, returning old state
AudioError AudioDevice::
SetRecError(
	Boolean&		flag)
{
	AudioInfo		info;
	AudioError		err;

	info->record.error = flag;
	err = SetState(info);
	if (err == AUDIO_SUCCESS)
		flag = info->record.error;
	return (err);
}

// Set record input buffer delay, returning new value
AudioError AudioDevice::
SetRecDelay(
	Double&			delay)
{
	unsigned int		d;
	AudioInfo		info;
	AudioError		err;

	d = (unsigned int) GetHeader().Time_to_Bytes(delay);
	info->record.buffer_size = d;
	err = SetState(info);
	if (err != AUDIO_SUCCESS)
		GetState(info);
	d = info->record.buffer_size;
	delay = GetHeader().Bytes_to_Time(d);
	return (err);
}

// Set Play-Waiting flag
AudioError AudioDevice::
SetPlayWaiting()
{
	AudioInfo		info;

	info->play.waiting = TRUE;
	return (SetState(info));
}

// Set Record-Waiting flag
AudioError AudioDevice::
SetRecWaiting()
{
	AudioInfo		info;

	info->record.waiting = TRUE;
	return (SetState(info));
}


// Scale an integer gain level to floating point (0. to 1.)
Double AudioDevice::
scale_gain(
	unsigned int	val)		// gain value
{
	return ((Double)(val - AUDIO_MIN_GAIN) /
	    (Double)(AUDIO_MAX_GAIN - AUDIO_MIN_GAIN));
}

// Rescale a floating point level to the correct gain
unsigned int AudioDevice::
unscale_gain(
	Double		val)		// floating point value
{
	return (irint((Double)(AUDIO_MAX_GAIN - AUDIO_MIN_GAIN) * val)
	    + AUDIO_MIN_GAIN);
}

// Scale an integer balance level to floating point (-1. to 1.)
Double AudioDevice::
scale_balance(
	unsigned int	val)		// balance value
{
	return (((Double)(val - AUDIO_LEFT_BALANCE) /
	    (Double)(AUDIO_MID_BALANCE - AUDIO_LEFT_BALANCE)) - 1.);
}

// Rescale a floating point level to the correct balance
unsigned int AudioDevice::
unscale_balance(
	Double		val)		// floating point value
{
	return (irint((val + 1.) *
	    (Double)(AUDIO_MID_BALANCE - AUDIO_LEFT_BALANCE))
	    + AUDIO_LEFT_BALANCE);
}

// Raise or lower a gain field by one notch
// This is useful for fields that don't have an increment/decrement ioctl
AudioError AudioDevice::
incr_volume(
	Boolean		up,		// true to raise, false to lower
	AudioInfo&	info,		// info structure
	unsigned int	*field)		// ptr to gain field in info
{
	int		incr;
	unsigned int	oldval;
	int		val;
	AudioError	err;

	// Get the starting point
	err = GetState(info);
	if (err != AUDIO_SUCCESS)
		return (err);
	oldval = *field;		// Save starting point

	// If we're already at the min or max, do nothing
	if (up) {
		if (oldval == AUDIO_MAX_GAIN)
			return (AUDIO_SUCCESS);
		incr = 1;
	} else {
		if (oldval == AUDIO_MIN_GAIN)
			return (AUDIO_SUCCESS);
		incr = -1;
	}

	// Keep trying until you hit min/max or the value actually changes
	for (val = (int)oldval + incr;
	    (val >= AUDIO_MIN_GAIN) && (val <= AUDIO_MAX_GAIN);
	    val += incr) {
		info.Clear();
		*field = (unsigned int) val;
		err = SetState(info);
		if (err != AUDIO_SUCCESS)
			return (err);
		if (*field != oldval)
			break;		// the value changed!
	}
	return (AUDIO_SUCCESS);
}

// Set Play volume
AudioError AudioDevice::
SetPlayVolume(
	Double&		vol)
{
	AudioError	err;
	AudioInfo	info;

	info->play.gain = unscale_gain(vol);
	err = SetState(info);
	vol = scale_gain(info->play.gain);
	return (err);
}

// Raise volume a notch
AudioError AudioDevice::
PlayVolumeUp()
{
	AudioInfo	info;

	return (incr_volume(TRUE, info, &info->play.gain));
}

// Lower volume a notch
AudioError AudioDevice::
PlayVolumeDown()
{
	AudioInfo	info;

	return (incr_volume(FALSE, info, &info->play.gain));
}

// Record volume
AudioError AudioDevice::
SetRecVolume(
	Double&		vol)
{
	AudioError	err;
	AudioInfo	info;

	info->record.gain = unscale_gain(vol);
	err = SetState(info);
	vol = scale_gain(info->record.gain);
	return (err);
}

// Raise volume a notch
AudioError AudioDevice::
RecVolumeUp()
{
	AudioInfo	info;

	return (incr_volume(TRUE, info, &info->record.gain));
}

// Lower volume a notch
AudioError AudioDevice::
RecVolumeDown()
{
	AudioInfo	info;

	return (incr_volume(FALSE, info, &info->record.gain));
}

// Monitor volume
AudioError AudioDevice::
SetMonVolume(
	Double&		vol)
{
	AudioError	err;
	AudioInfo	info;

	info->monitor_gain = unscale_gain(vol);
	err = SetState(info);
	vol = scale_gain(info->monitor_gain);
	return (err);
}

// Raise volume a notch
AudioError AudioDevice::
MonVolumeUp()
{
	AudioInfo	info;

	return (incr_volume(TRUE, info, &info->monitor_gain));
}

// Lower volume a notch
AudioError AudioDevice::
MonVolumeDown()
{
	AudioInfo	info;

	return (incr_volume(FALSE, info, &info->monitor_gain));
}


// Set balance
AudioError AudioDevice::
SetPlayBalance(
	Double&		bal)
{
	AudioError	err;
	AudioInfo	info;

	info->play.balance = unscale_balance(bal);
	err = SetState(info);
	bal = scale_balance(info->play.balance);
	return (err);
}

// Set balance
AudioError AudioDevice::
SetRecBalance(
	Double&		bal)
{
	AudioError	err;
	AudioInfo	info;

	info->record.balance = unscale_balance(bal);
	err = SetState(info);
	bal = scale_balance(info->record.balance);
	return (err);
}

// Get Play volume
Double AudioDevice::
GetPlayVolume(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		(void) GetState(info);
		return (scale_gain(info->play.gain));
	} else {
		return (scale_gain((*uinfo)->play.gain));
	}
}

// Get Record volume
Double AudioDevice::
GetRecVolume(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		(void) GetState(info);
		return (scale_gain(info->record.gain));
	} else {
		return (scale_gain((*uinfo)->record.gain));
	}
}

// Get Monitor volume
Double AudioDevice::
GetMonVolume(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		(void) GetState(info);
		return (scale_gain(info->monitor_gain));
	} else {
		return (scale_gain((*uinfo)->monitor_gain));
	}
}

// Get Play balance
Double AudioDevice::
GetPlayBalance(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		(void) GetState(info);
		return (scale_balance(info->play.balance));
	} else {
		return (scale_balance((*uinfo)->play.balance));
	}
}

// Get Record balance
Double AudioDevice::
GetRecBalance(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		(void) GetState(info);
		return (scale_balance(info->record.balance));
	} else {
		return (scale_balance((*uinfo)->record.balance));
	}
}

// Get play sample count
unsigned AudioDevice::
GetPlaySamples(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		if (GetState(info))
			return (AUDIO_UNKNOWN_SIZE);
		return (info->play.samples);
	} else {
		return ((*uinfo)->play.samples);
	}
}

// Get record sample count
unsigned AudioDevice::
GetRecSamples(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		if (GetState(info))
			return (AUDIO_UNKNOWN_SIZE);
		return (info->record.samples);
	} else {
		return ((*uinfo)->record.samples);
	}
}

// Get Play-Open flag
Boolean AudioDevice::
GetPlayOpen(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		if (!GetState(info) && info->play.open)
			return (TRUE);
	} else {
		if ((*uinfo)->play.open)
			return (TRUE);
	}
	return (FALSE);
}

// Get Record-Open flag
Boolean AudioDevice::
GetRecOpen(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		if (!GetState(info) && info->record.open)
			return (TRUE);
	} else {
		if ((*uinfo)->record.open)
			return (TRUE);
	}
	return (FALSE);
}

// Get Play-Waiting flag
Boolean AudioDevice::
GetPlayWaiting(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		if (!GetState(info) && info->play.waiting)
			return (TRUE);
	} else {
		if ((*uinfo)->play.waiting)
			return (TRUE);
	}
	return (FALSE);
}

// Get Record-Waiting flag
Boolean AudioDevice::
GetRecWaiting(
	AudioInfo*	uinfo)
{
	if (uinfo == 0) {
		AudioInfo	info;
		if (!GetState(info) && info->record.waiting)
			return (TRUE);
	} else {
		if ((*uinfo)->record.waiting)
			return (TRUE);
	}
	return (FALSE);
}
