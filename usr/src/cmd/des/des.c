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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * DES encrypt/decrypt command
 * Features:
 *	Hardware or software implementation
 *	Cipher Block Chaining (default) or Electronic Code Book (-b) modes
 *  A word about the key:
 * 	The DES standard specifies that the low bit of each of the 8 bytes
 *	of the key is used for odd parity.  We prompt the user for an 8
 *	byte ASCII key and add parity to the high bit and use the result
 *	as the key.  The nature of parity is that given any 7 bits you can
 *	figure out what the missing bit should be, so it doesn't matter which
 *	bit is used for parity; the information (in the theoretical sense) is
 * 	the same.
 */
#include <stdio.h>
#include <string.h>
#include <rpc/des_crypt.h>

#define DES_CBC	0
#define DES_ECB 1


int ifd=0, ofd=1;		/* input and output descriptors */
char *cmdname;			/* our command name */


struct des_info {
	char *key;			/* encryption key */
	char *ivec;			/* initialization vector: CBC mode only */
	unsigned flags;		/* direction, device flags */
	unsigned mode;		/* des mode: ecb or cbc */
} g_des;


void des_setup(char *key, unsigned int mode, unsigned int flags);
void fencrypt(void);
void fdecrypt(void);
void usage(void);
static void putparity(char *p);
int
main(int argc, char **argv)
{
	char *key = NULL, keybuf[8], *getpass();
	unsigned mode = DES_CBC;	
	unsigned flags = DES_HW;
	int dirset = 0; 	/* set if dir set */
	int fflg = 0;	/* suppress warning if H/W DES not available */
	unsigned err;

	cmdname = *argv++;
	argc--;
	while (argc > 0 && argv[0][0] == '-') {
		switch (argv[0][1]) {
		case 'e':	/* encrypt */
			flags |= DES_ENCRYPT;  	dirset++;
			break;
		case 'd':	/* decrypt */
			flags |= DES_DECRYPT;	dirset++;
			break;
		case 'b':	/* use Book mode */
			mode = DES_ECB;	
			break;
		case 'f':	/* force silent */
			fflg++;
			break;
		case 's':	/* use software DES */
			flags |= DES_SW;	
			break;
		case 'k':	/* key */
			if (--argc == 0)
				usage();
			strncpy(keybuf, *++argv, 8);
			for (key = *argv; *key; )
				*key++ = '\0'; 
			key = keybuf;
			break;
		default:
			usage();
		}
		argv++;
		argc--;
	}
	if (!dirset)
		usage();
	if (argc > 0) {
		ifd = open(*argv, 0);
		if (ifd < 0) {
			perror(*argv);
			exit(1);
		}
		argv++;
		argc--;
	}
	if (argc > 0) {
		ofd = creat(*argv, 0666);
		if (ofd < 0) {
			perror(*argv);
			exit(1);
		}
		argv++;
		argc--;
	}
	if (argc)
		usage();
	if (key == NULL) {
		if ((key = getpass("Enter key: ")) == NULL) {
			fprintf(stderr, "%s: unable to get key\n", cmdname);
			exit(1);
		}
		strncpy(keybuf, key, 8);
	}
	if ((flags & DES_DEVMASK) == DES_HW && no_hwdevice()) {
		flags &= ~DES_DEVMASK;	/* clear device bit */
		flags |= DES_SW;		/* set device to software */	
		if (!fflg) {
			fprintf(stderr, "%s: WARNING: using software DES algorithm\n", 
				cmdname);
		}
	} 
	if ((flags & DES_DEVMASK) == DES_SW && no_swdevice()) {
		fprintf(stderr, "%s: no software encryption available\n", 
			cmdname);
		exit(1);
	}
	des_setup(key, mode, flags);
	switch (flags & DES_DIRMASK) {
	case DES_ENCRYPT:	
		fencrypt();
		break;
	case DES_DECRYPT:	
		fdecrypt();
		break;
	}
	return (0);
}



int
no_hwdevice(void)
{
	char key[8];
	char buf[8];

	return (ecb_crypt(key,buf,8,DES_ENCRYPT | DES_HW) != 0);
}
	

int
no_swdevice(void)
{
	char key[8];
	char buf[8];
	int res;

	return (ecb_crypt(key,buf,8,DES_ENCRYPT | DES_SW) != 0);
}
	
		


void
des_setup(char *key, unsigned int mode, unsigned int flags)
{
	static char ivec[8];

	g_des.flags = flags;
	g_des.mode = mode;
	putparity(key);
	g_des.key = key;

	memset(ivec, 0, 8);
	g_des.ivec = ivec;
}


void
crypt(char *buf, unsigned int len)
{

	if (g_des.mode == DES_ECB) {
		ecb_crypt(g_des.key, buf, len, g_des.flags);
	} else {
		cbc_crypt(g_des.key, buf, len, g_des.flags, g_des.ivec);
	}
}


char buf[DES_MAXDATA];

/*
 * Encrypt a file:
 * Takes an arbitrary number of bytes of input and
 * produces an encrypted output file which is always the
 * the next multiple of 8 bytes bigger (e.g., 64 -> 72, 71 -> 72)
 * The last byte, when decrypted, gives the number of actual data bytes
 * in the last 8 bytes.  Other bytes are filled with random values to
 * make it hard to cryptanalize.
 */
void
fencrypt(void)
{
	int n, k, j;
	char *cp;

	while ((n = read(ifd, buf, sizeof buf)) > 0) {
		j = n;
		while (n & 7) {
			k = 8 - (n & 7);
			if ((j = read(ifd, buf+n, k)) <= 0)
				break;
			n += j;
		}
		k = n &~ 7;
		if (k == 0)
			break;
		crypt(buf, k);
		if (write(ofd, buf, k) != k)
			perror("write");
		if (j <= 0)
			break;
	}
	if (n >= 0) {
		cp = &buf[n];
		k = 7 - (n & 7);
		srand(getpid());
		for (j = 0; j < k; j++)
			*cp++ = rand();
		*cp++ = n & 7;
		cp -= 8;
		
		crypt(cp, 8);
		if (write(ofd, cp, 8) != 8)
			perror("write");
	} else
		perror("read");
}




/*
 * Decrypt a file:
 * Look at the last byte of the last 8 byte block decrypted
 * to determine how many of the last 8 bytes to save.
 * This also serves as a check to see if the decryption succeeded
 * with a probability of (256-8)/256.
 */
void
fdecrypt(void)
{
	char last8buf[8], *last8;
	int n, k, j;

	last8 = NULL;
	while ((n = read(ifd, buf, sizeof buf)) > 0) {
		j = n;
		while (n & 7) {
			k = 8 - (n & 7);
			if ((j = read(ifd, buf+n, k)) <= 0)
				break;
			n += j;
		}
		if (j <= 0)
			break;
		crypt(buf, n);
		if (last8)
			write(ofd, last8, 8);
		last8 = last8buf;
		n -= 8;
		memcpy(last8, buf+n, 8);
		if (n && write(ofd, buf, n) != n)
			perror("write");
	}
	if (n >= 0) {
		if (last8 == NULL
		|| n != 0
		|| ((signed char)last8[7]) < 0
		|| last8[7] > 7)
			fprintf(stderr, "%s: decryption failed\n", cmdname);
		else if (((signed char)last8[7]) > 0)
			write(ofd, last8, last8[7]);
	} else
		perror("read");
}


void
usage(void)
{
	fprintf(stderr,
		"Usage: %s -e [-b] [-f] [-k key] [ infile [ outfile ] ]\n",
		cmdname);
	fprintf(stderr,
		"   or: %s -d [-b] [-f] [-k key] [ infile [ outfile ] ]\n",
		cmdname);
	fprintf(stderr, "Use -e to encrypt, -d to decrypt\n");
	exit(2);
}




/*
 * Table giving odd parity (in high bit) for ASCII characters
 * program does not use des_setparity() (which puts parity
 * in low bit) in order to maintain backward compatibility
 */
static unsigned char partab[128] = {
    0x80, 0x01, 0x02, 0x83, 0x04, 0x85, 0x86, 0x07,
    0x08, 0x89, 0x8a, 0x0b, 0x8c, 0x0d, 0x0e, 0x8f,
    0x10, 0x91, 0x92, 0x13, 0x94, 0x15, 0x16, 0x97,
    0x98, 0x19, 0x1a, 0x9b, 0x1c, 0x9d, 0x9e, 0x1f,
    0x20, 0xa1, 0xa2, 0x23, 0xa4, 0x25, 0x26, 0xa7,
    0xa8, 0x29, 0x2a, 0xab, 0x2c, 0xad, 0xae, 0x2f,
    0xb0, 0x31, 0x32, 0xb3, 0x34, 0xb5, 0xb6, 0x37,
    0x38, 0xb9, 0xba, 0x3b, 0xbc, 0x3d, 0x3e, 0xbf,
    0x40, 0xc1, 0xc2, 0x43, 0xc4, 0x45, 0x46, 0xc7,
    0xc8, 0x49, 0x4a, 0xcb, 0x4c, 0xcd, 0xce, 0x4f,
    0xd0, 0x51, 0x52, 0xd3, 0x54, 0xd5, 0xd6, 0x57,
    0x58, 0xd9, 0xda, 0x5b, 0xdc, 0x5d, 0x5e, 0xdf,
    0xe0, 0x61, 0x62, 0xe3, 0x64, 0xe5, 0xe6, 0x67,
    0x68, 0xe9, 0xea, 0x6b, 0xec, 0x6d, 0x6e, 0xef,
    0x70, 0xf1, 0xf2, 0x73, 0xf4, 0x75, 0x76, 0xf7,
    0xf8, 0x79, 0x7a, 0xfb, 0x7c, 0xfd, 0xfe, 0x7f,
};



/*
 * Add odd parity to high bit of 8 byte key
 */
static void
putparity(char *p)
{
    int i;
 
    for (i = 0; i < 8; i++) {
        *p = partab[*p & 0x7f];
        p++;
    }
}
