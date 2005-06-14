/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * Most of this file was originally the source file "inflate.c", written
 * by Mark Adler.  It has been very heavily modified.  In particular, the
 * original would run through the whole file at once, and this version can
 * be stopped and restarted on any boundary during the decompression process.
 *
 * The license and header comments that file are included here.
 */

/* inflate.c -- Not copyrighted 1992 by Mark Adler
   version c10p1, 10 January 1993 */

/* You can do whatever you like with this source file, though I would
   prefer that if you modify it and redistribute it that you include
   comments to that effect with your name and the date.  Thank you.
 */

/*
   Inflate deflated (PKZIP's method 8 compressed) data.  The compression
   method searches for as much of the current string of bytes (up to a
   length of 258) in the previous 32K bytes.  If it doesn't find any
   matches (of at least length 3), it codes the next byte.  Otherwise, it
   codes the length of the matched string and its distance backwards from
   the current position.  There is a single Huffman code that codes both
   single bytes (called "literals") and match lengths.  A second Huffman
   code codes the distance information, which follows a length code.  Each
   length or distance code actually represents a base value and a number
   of "extra" (sometimes zero) bits to get to add to the base value.  At
   the end of each deflated block is a special end-of-block (EOB) literal/
   length code.  The decoding process is basically: get a literal/length
   code; if EOB then done; if a literal, emit the decoded byte; if a
   length then get the distance and emit the referred-to bytes from the
   sliding window of previously emitted data.

   There are (currently) three kinds of inflate blocks: stored, fixed, and
   dynamic.  The compressor deals with some chunk of data at a time, and
   decides which method to use on a chunk-by-chunk basis.  A chunk might
   typically be 32K or 64K.  If the chunk is uncompressible, then the
   "stored" method is used.  In this case, the bytes are simply stored as
   is, eight bits per byte, with none of the above coding.  The bytes are
   preceded by a count, since there is no longer an EOB code.

   If the data is compressible, then either the fixed or dynamic methods
   are used.  In the dynamic method, the compressed data is preceded by
   an encoding of the literal/length and distance Huffman codes that are
   to be used to decode this block.  The representation is itself Huffman
   coded, and so is preceded by a description of that code.  These code
   descriptions take up a little space, and so for small blocks, there is
   a predefined set of codes, called the fixed codes.  The fixed method is
   used if the block codes up smaller that way (usually for quite small
   chunks), otherwise the dynamic method is used.  In the latter case, the
   codes are customized to the probabilities in the current block, and so
   can code it much better than the pre-determined fixed codes.

   The Huffman codes themselves are decoded using a mutli-level table
   lookup, in order to maximize the speed of decoding plus the speed of
   building the decoding tables.  See the comments below that precede the
   lbits and dbits tuning parameters.
 */


/*
   Notes beyond the 1.93a appnote.txt:

   1. Distance pointers never point before the beginning of the output
      stream.
   2. Distance pointers can point back across blocks, up to 32k away.
   3. There is an implied maximum of 7 bits for the bit length table and
      15 bits for the actual data.
   4. If only one code exists, then it is encoded using one bit.  (Zero
      would be more efficient, but perhaps a little confusing.)  If two
      codes exist, they are coded using one bit each (0 and 1).
   5. There is no way of sending zero distance codes--a dummy must be
      sent if there are none.  (History: a pre 2.0 version of PKZIP would
      store blocks with no distance codes, but this was discovered to be
      too harsh a criterion.)  Valid only for 1.93a.  2.04c does allow
      zero distance codes, which is sent as one code of zero bits in
      length.
   6. There are up to 286 literal/length codes.  Code 256 represents the
      end-of-block.  Note however that the static length tree defines
      288 codes just to fill out the Huffman codes.  Codes 286 and 287
      cannot be used though, since there is no length base or extra bits
      defined for them.  Similarly, there are up to 30 distance codes.
      However, static trees define 32 codes (all 5 bits) to fill out the
      Huffman codes, but the last two had better not show up in the data.
   7. Unzip can check dynamic Huffman blocks for complete code sets.
      The exception is that a single code would not be complete (see #4).
   8. The five bits following the block type is really the number of
      literal codes sent minus 257.
   9. Length codes 8,16,16 are interpreted as 13 length codes of 8 bits
      (1+6+6).  Therefore, to output three times the length, you output
      three codes (1+1+1), whereas to output four times the same length,
      you only need two codes (1+3).  Hmm.
  10. In the tree reconstruction algorithm, Code = Code + Increment
      only if BitLength(i) is not zero.  (Pretty obvious.)
  11. Correction: 4 Bits: # of Bit Length codes - 4     (4 - 19)
  12. Note: length code 284 can represent 227-258, but length code 285
      really is 258.  The last length deserves its own, short code
      since it gets used a lot in very redundant files.  The length
      258 is special since 258 - 3 (the min match length) is 255.
  13. The literal/length and distance code bit lengths are read as a
      single stream of lengths.  It is possible (and advantageous) for
      a repeat code (16, 17, or 18) to go across the boundary between
      the two sets of lengths.
 */

#ifndef NO_DECOMPRESSION

#include "shared.h"

#include "filesys.h"

/* so we can disable decompression  */
int no_decompression = 0;

/* used to tell if "read" should be redirected to "gunzip_read" */
int compressed_file;

/* internal variables only */
static int gzip_data_offset;
static int gzip_filepos;
static int gzip_filemax;
static int gzip_fsmax;
static int saved_filepos;
static unsigned long gzip_crc;

/* internal extra variables for use of inflate code */
static int block_type;
static int block_len;
static int last_block;
static int code_state;


/* Function prototypes */
static void initialize_tables (void);

/*
 *  Linear allocator.
 */

static unsigned long linalloc_topaddr;

static void *
linalloc (int size)
{
  linalloc_topaddr = (linalloc_topaddr - size) & ~3;
  return (void *) linalloc_topaddr;
}

static void
reset_linalloc (void)
{
  linalloc_topaddr = RAW_ADDR ((mbi.mem_upper << 10) + 0x100000);
}


/* internal variable swap function */
static void
gunzip_swap_values (void)
{
  register int itmp;

  /* swap filepos */
  itmp = filepos;
  filepos = gzip_filepos;
  gzip_filepos = itmp;

  /* swap filemax */
  itmp = filemax;
  filemax = gzip_filemax;
  gzip_filemax = itmp;

  /* swap fsmax */
  itmp = fsmax;
  fsmax = gzip_fsmax;
  gzip_fsmax = itmp;
}


/* internal function for eating variable-length header fields */
static int
bad_field (int len)
{
  char ch = 1;
  int not_retval = 1;

  do
    {
      if (len >= 0)
	{
	  if (!(len--))
	    break;
	}
      else
	{
	  if (!ch)
	    break;
	}
    }
  while ((not_retval = grub_read (&ch, 1)) == 1);

  return (!not_retval);
}


/* Little-Endian defines for the 2-byte magic number for gzip files */
#define GZIP_HDR_LE      0x8B1F
#define OLD_GZIP_HDR_LE  0x9E1F

/* Compression methods (see algorithm.doc) */
#define STORED      0
#define COMPRESSED  1
#define PACKED      2
#define LZHED       3
/* methods 4 to 7 reserved */
#define DEFLATED    8
#define MAX_METHODS 9

/* gzip flag byte */
#define ASCII_FLAG   0x01	/* bit 0 set: file probably ascii text */
#define CONTINUATION 0x02	/* bit 1 set: continuation of multi-part gzip file */
#define EXTRA_FIELD  0x04	/* bit 2 set: extra field present */
#define ORIG_NAME    0x08	/* bit 3 set: original file name present */
#define COMMENT      0x10	/* bit 4 set: file comment present */
#define ENCRYPTED    0x20	/* bit 5 set: file is encrypted */
#define RESERVED     0xC0	/* bit 6,7:   reserved */

#define UNSUPP_FLAGS (CONTINUATION|ENCRYPTED|RESERVED)

/* inflate block codes */
#define INFLATE_STORED    0
#define INFLATE_FIXED     1
#define INFLATE_DYNAMIC   2

typedef unsigned char uch;
typedef unsigned short ush;
typedef unsigned long ulg;

/*
 *  Window Size
 *
 *  This must be a power of two, and at least 32K for zip's deflate method
 */

#define WSIZE 0x8000


int
gunzip_test_header (void)
{
  unsigned char buf[10];
  
  /* "compressed_file" is already reset to zero by this point */

  /*
   *  This checks if the file is gzipped.  If a problem occurs here
   *  (other than a real error with the disk) then we don't think it
   *  is a compressed file, and simply mark it as such.
   */
  if (no_decompression
      || grub_read (buf, 10) != 10
      || ((*((unsigned short *) buf) != GZIP_HDR_LE)
	  && (*((unsigned short *) buf) != OLD_GZIP_HDR_LE)))
    {
      filepos = 0;
      return ! errnum;
    }

  /*
   *  This does consistency checking on the header data.  If a
   *  problem occurs from here on, then we have corrupt or otherwise
   *  bad data, and the error should be reported to the user.
   */
  if (buf[2] != DEFLATED
      || (buf[3] & UNSUPP_FLAGS)
      || ((buf[3] & EXTRA_FIELD)
	  && (grub_read (buf, 2) != 2
	      || bad_field (*((unsigned short *) buf))))
      || ((buf[3] & ORIG_NAME) && bad_field (-1))
      || ((buf[3] & COMMENT) && bad_field (-1)))
    {
      if (! errnum)
	errnum = ERR_BAD_GZIP_HEADER;
      
      return 0;
    }

  gzip_data_offset = filepos;
  
  /* We could read the last 8 bytes of the file to get the uncompressed
   * size. Doing so under tftp would cause the file to be downloaded
   * twice, which can be problem with large files. So we set it to
   * MAXINT and correct it later when we get to the end of the file
   * in get_byte().
   */
  gzip_fsmax = gzip_filemax = MAXINT;

  initialize_tables ();

  compressed_file = 1;
  gunzip_swap_values ();
  /*
   *  Now "gzip_*" values refer to the compressed data.
   */

  filepos = 0;

  return 1;
}


/* Huffman code lookup table entry--this entry is four bytes for machines
   that have 16-bit pointers (e.g. PC's in the small or medium model).
   Valid extra bits are 0..13.  e == 15 is EOB (end of block), e == 16
   means that v is a literal, 16 < e < 32 means that v is a pointer to
   the next table, which codes e - 16 bits, and lastly e == 99 indicates
   an unused code.  If a code with e == 99 is looked up, this implies an
   error in the data. */
struct huft
{
  uch e;			/* number of extra bits or operation */
  uch b;			/* number of bits in this code or subcode */
  union
    {
      ush n;			/* literal, length base, or distance base */
      struct huft *t;		/* pointer to next level of table */
    }
  v;
};


/* The inflate algorithm uses a sliding 32K byte window on the uncompressed
   stream to find repeated byte strings.  This is implemented here as a
   circular buffer.  The index is updated simply by incrementing and then
   and'ing with 0x7fff (32K-1). */
/* It is left to other modules to supply the 32K area.  It is assumed
   to be usable as if it were declared "uch slide[32768];" or as just
   "uch *slide;" and then malloc'ed in the latter case.  The definition
   must be in unzip.h, included above. */


/* sliding window in uncompressed data */
static uch slide[WSIZE];

/* current position in slide */
static unsigned wp;


/* Tables for deflate from PKZIP's appnote.txt. */
static unsigned bitorder[] =
{				/* Order of the bit length code lengths */
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
static ush cplens[] =
{				/* Copy lengths for literal codes 257..285 */
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
  35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0};
	/* note: see note #13 above about the 258 in this list. */
static ush cplext[] =
{				/* Extra bits for literal codes 257..285 */
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
  3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 99, 99};	/* 99==invalid */
static ush cpdist[] =
{				/* Copy offsets for distance codes 0..29 */
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
  257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
  8193, 12289, 16385, 24577};
static ush cpdext[] =
{				/* Extra bits for distance codes */
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
  7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
  12, 12, 13, 13};


/*
   Huffman code decoding is performed using a multi-level table lookup.
   The fastest way to decode is to simply build a lookup table whose
   size is determined by the longest code.  However, the time it takes
   to build this table can also be a factor if the data being decoded
   is not very long.  The most common codes are necessarily the
   shortest codes, so those codes dominate the decoding time, and hence
   the speed.  The idea is you can have a shorter table that decodes the
   shorter, more probable codes, and then point to subsidiary tables for
   the longer codes.  The time it costs to decode the longer codes is
   then traded against the time it takes to make longer tables.

   This results of this trade are in the variables lbits and dbits
   below.  lbits is the number of bits the first level table for literal/
   length codes can decode in one step, and dbits is the same thing for
   the distance codes.  Subsequent tables are also less than or equal to
   those sizes.  These values may be adjusted either when all of the
   codes are shorter than that, in which case the longest code length in
   bits is used, or when the shortest code is *longer* than the requested
   table size, in which case the length of the shortest code in bits is
   used.

   There are two different values for the two tables, since they code a
   different number of possibilities each.  The literal/length table
   codes 286 possible values, or in a flat code, a little over eight
   bits.  The distance table codes 30 possible values, or a little less
   than five bits, flat.  The optimum values for speed end up being
   about one bit more than those, so lbits is 8+1 and dbits is 5+1.
   The optimum values may differ though from machine to machine, and
   possibly even between compilers.  Your mileage may vary.
 */


static int lbits = 9;		/* bits in base literal/length lookup table */
static int dbits = 6;		/* bits in base distance lookup table */


/* If BMAX needs to be larger than 16, then h and x[] should be ulg. */
#define BMAX 16			/* maximum bit length of any code (16 for explode) */
#define N_MAX 288		/* maximum number of codes in any set */


static unsigned hufts;		/* track memory usage */


/* Macros for inflate() bit peeking and grabbing.
   The usage is:

        NEEDBITS(j)
        x = b & mask_bits[j];
        DUMPBITS(j)

   where NEEDBITS makes sure that b has at least j bits in it, and
   DUMPBITS removes the bits from b.  The macros use the variable k
   for the number of bits in b.  Normally, b and k are register
   variables for speed, and are initialized at the beginning of a
   routine that uses these macros from a global bit buffer and count.

   If we assume that EOB will be the longest code, then we will never
   ask for bits with NEEDBITS that are beyond the end of the stream.
   So, NEEDBITS should not read any more bytes than are needed to
   meet the request.  Then no bytes need to be "returned" to the buffer
   at the end of the last block.

   However, this assumption is not true for fixed blocks--the EOB code
   is 7 bits, but the other literal/length codes can be 8 or 9 bits.
   (The EOB code is shorter than other codes because fixed blocks are
   generally short.  So, while a block always has an EOB, many other
   literal/length codes have a significantly lower probability of
   showing up at all.)  However, by making the first table have a
   lookup of seven bits, the EOB code will be found in that first
   lookup, and so will not require that too many bits be pulled from
   the stream.
 */

static ulg bb;			/* bit buffer */
static unsigned bk;		/* bits in bit buffer */

static ush mask_bits[] =
{
  0x0000,
  0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff,
  0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff
};

#define NEEDBITS(n) do {while(k<(n)){b|=((ulg)get_byte())<<k;k+=8;}} while (0)
#define DUMPBITS(n) do {b>>=(n);k-=(n);} while (0)

#define INBUFSIZ  0x2000

static uch inbuf[INBUFSIZ];
static int bufloc;
static uch endbuf[8];

static int
get_byte (void)
{
  if (filepos == gzip_data_offset || bufloc == INBUFSIZ)
    {
      int pos;
      int old_filepos = filepos;
      bufloc = 0;
      grub_read (inbuf, INBUFSIZ);
      /* If there are 8 bytes or less left, we have read in all the
       * the file content. So get the last 8 bytes and get the crc
       * and uncompressed size. This is important for the loop in
       * gunzip_read() to terminate properly.
       */
      if (filepos >= filemax - 8) {
	uch *eb = endbuf;
	for (pos = filemax - 8; pos < filepos; pos++)
		*eb++ = inbuf[pos - old_filepos];
	if (filemax > filepos)
		grub_read(eb, filemax - filepos);
  	gzip_crc = *((unsigned long *) endbuf);
	gzip_filemax = *((unsigned long *) (endbuf + 4));
      }
    }

  return inbuf[bufloc++];
}

/* decompression global pointers */
static struct huft *tl;		/* literal/length code table */
static struct huft *td;		/* distance code table */
static int bl;			/* lookup bits for tl */
static int bd;			/* lookup bits for td */


/* more function prototypes */
static int huft_build (unsigned *, unsigned, unsigned, ush *, ush *,
		       struct huft **, int *);
static int inflate_codes_in_window (void);


/* Given a list of code lengths and a maximum table size, make a set of
   tables to decode that set of codes.  Return zero on success, one if
   the given code set is incomplete (the tables are still built in this
   case), two if the input is invalid (all zero length codes or an
   oversubscribed set of lengths), and three if not enough memory. */

static int
huft_build (unsigned *b,	/* code lengths in bits (all assumed <= BMAX) */
	    unsigned n,		/* number of codes (assumed <= N_MAX) */
	    unsigned s,		/* number of simple-valued codes (0..s-1) */
	    ush * d,		/* list of base values for non-simple codes */
	    ush * e,		/* list of extra bits for non-simple codes */
	    struct huft **t,	/* result: starting table */
	    int *m)		/* maximum lookup bits, returns actual */
{
  unsigned a;			/* counter for codes of length k */
  unsigned c[BMAX + 1];		/* bit length count table */
  unsigned f;			/* i repeats in table every f entries */
  int g;			/* maximum code length */
  int h;			/* table level */
  register unsigned i;		/* counter, current code */
  register unsigned j;		/* counter */
  register int k;		/* number of bits in current code */
  int l;			/* bits per table (returned in m) */
  register unsigned *p;		/* pointer into c[], b[], or v[] */
  register struct huft *q;	/* points to current table */
  struct huft r;		/* table entry for structure assignment */
  struct huft *u[BMAX];		/* table stack */
  unsigned v[N_MAX];		/* values in order of bit length */
  register int w;		/* bits before this table == (l * h) */
  unsigned x[BMAX + 1];		/* bit offsets, then code stack */
  unsigned *xp;			/* pointer into x */
  int y;			/* number of dummy codes added */
  unsigned z;			/* number of entries in current table */

  /* Generate counts for each bit length */
  memset ((char *) c, 0, sizeof (c));
  p = b;
  i = n;
  do
    {
      c[*p]++;			/* assume all entries <= BMAX */
      p++;			/* Can't combine with above line (Solaris bug) */
    }
  while (--i);
  if (c[0] == n)		/* null input--all zero length codes */
    {
      *t = (struct huft *) NULL;
      *m = 0;
      return 0;
    }

  /* Find minimum and maximum length, bound *m by those */
  l = *m;
  for (j = 1; j <= BMAX; j++)
    if (c[j])
      break;
  k = j;			/* minimum code length */
  if ((unsigned) l < j)
    l = j;
  for (i = BMAX; i; i--)
    if (c[i])
      break;
  g = i;			/* maximum code length */
  if ((unsigned) l > i)
    l = i;
  *m = l;

  /* Adjust last length count to fill out codes, if needed */
  for (y = 1 << j; j < i; j++, y <<= 1)
    if ((y -= c[j]) < 0)
      return 2;			/* bad input: more codes than bits */
  if ((y -= c[i]) < 0)
    return 2;
  c[i] += y;

  /* Generate starting offsets into the value table for each length */
  x[1] = j = 0;
  p = c + 1;
  xp = x + 2;
  while (--i)
    {				/* note that i == g from above */
      *xp++ = (j += *p++);
    }

  /* Make a table of values in order of bit lengths */
  p = b;
  i = 0;
  do
    {
      if ((j = *p++) != 0)
	v[x[j]++] = i;
    }
  while (++i < n);

  /* Generate the Huffman codes and for each, make the table entries */
  x[0] = i = 0;			/* first Huffman code is zero */
  p = v;			/* grab values in bit order */
  h = -1;			/* no tables yet--level -1 */
  w = -l;			/* bits decoded == (l * h) */
  u[0] = (struct huft *) NULL;	/* just to keep compilers happy */
  q = (struct huft *) NULL;	/* ditto */
  z = 0;			/* ditto */

  /* go through the bit lengths (k already is bits in shortest code) */
  for (; k <= g; k++)
    {
      a = c[k];
      while (a--)
	{
	  /* here i is the Huffman code of length k bits for value *p */
	  /* make tables up to required level */
	  while (k > w + l)
	    {
	      h++;
	      w += l;		/* previous table always l bits */

	      /* compute minimum size table less than or equal to l bits */
	      z = (z = g - w) > (unsigned) l ? l : z;	/* upper limit on table size */
	      if ((f = 1 << (j = k - w)) > a + 1)	/* try a k-w bit table */
		{		/* too few codes for k-w bit table */
		  f -= a + 1;	/* deduct codes from patterns left */
		  xp = c + k;
		  while (++j < z)	/* try smaller tables up to z bits */
		    {
		      if ((f <<= 1) <= *++xp)
			break;	/* enough codes to use up j bits */
		      f -= *xp;	/* else deduct codes from patterns */
		    }
		}
	      z = 1 << j;	/* table entries for j-bit table */

	      /* allocate and link in new table */
	      q = (struct huft *) linalloc ((z + 1) * sizeof (struct huft));

	      hufts += z + 1;	/* track memory usage */
	      *t = q + 1;	/* link to list for huft_free() */
	      *(t = &(q->v.t)) = (struct huft *) NULL;
	      u[h] = ++q;	/* table starts after link */

	      /* connect to last table, if there is one */
	      if (h)
		{
		  x[h] = i;	/* save pattern for backing up */
		  r.b = (uch) l;	/* bits to dump before this table */
		  r.e = (uch) (16 + j);		/* bits in this table */
		  r.v.t = q;	/* pointer to this table */
		  j = i >> (w - l);	/* (get around Turbo C bug) */
		  u[h - 1][j] = r;	/* connect to last table */
		}
	    }

	  /* set up table entry in r */
	  r.b = (uch) (k - w);
	  if (p >= v + n)
	    r.e = 99;		/* out of values--invalid code */
	  else if (*p < s)
	    {
	      r.e = (uch) (*p < 256 ? 16 : 15);		/* 256 is end-of-block code */
	      r.v.n = (ush) (*p);	/* simple code is just the value */
	      p++;		/* one compiler does not like *p++ */
	    }
	  else
	    {
	      r.e = (uch) e[*p - s];	/* non-simple--look up in lists */
	      r.v.n = d[*p++ - s];
	    }

	  /* fill code-like entries with r */
	  f = 1 << (k - w);
	  for (j = i >> w; j < z; j += f)
	    q[j] = r;

	  /* backwards increment the k-bit code i */
	  for (j = 1 << (k - 1); i & j; j >>= 1)
	    i ^= j;
	  i ^= j;

	  /* backup over finished tables */
	  while ((i & ((1 << w) - 1)) != x[h])
	    {
	      h--;		/* don't need to update q */
	      w -= l;
	    }
	}
    }

  /* Return true (1) if we were given an incomplete table */
  return y != 0 && g != 1;
}


/*
 *  inflate (decompress) the codes in a deflated (compressed) block.
 *  Return an error code or zero if it all goes ok.
 */

static unsigned inflate_n, inflate_d;

static int
inflate_codes_in_window (void)
{
  register unsigned e;		/* table entry flag/number of extra bits */
  unsigned n, d;		/* length and index for copy */
  unsigned w;			/* current window position */
  struct huft *t;		/* pointer to table entry */
  unsigned ml, md;		/* masks for bl and bd bits */
  register ulg b;		/* bit buffer */
  register unsigned k;		/* number of bits in bit buffer */

  /* make local copies of globals */
  d = inflate_d;
  n = inflate_n;
  b = bb;			/* initialize bit buffer */
  k = bk;
  w = wp;			/* initialize window position */

  /* inflate the coded data */
  ml = mask_bits[bl];		/* precompute masks for speed */
  md = mask_bits[bd];
  for (;;)			/* do until end of block */
    {
      if (!code_state)
	{
	  NEEDBITS ((unsigned) bl);
	  if ((e = (t = tl + ((unsigned) b & ml))->e) > 16)
	    do
	      {
		if (e == 99)
		  {
		    errnum = ERR_BAD_GZIP_DATA;
		    return 0;
		  }
		DUMPBITS (t->b);
		e -= 16;
		NEEDBITS (e);
	      }
	    while ((e = (t = t->v.t + ((unsigned) b & mask_bits[e]))->e) > 16);
	  DUMPBITS (t->b);

	  if (e == 16)		/* then it's a literal */
	    {
	      slide[w++] = (uch) t->v.n;
	      if (w == WSIZE)
		break;
	    }
	  else
	    /* it's an EOB or a length */
	    {
	      /* exit if end of block */
	      if (e == 15)
		{
		  block_len = 0;
		  break;
		}

	      /* get length of block to copy */
	      NEEDBITS (e);
	      n = t->v.n + ((unsigned) b & mask_bits[e]);
	      DUMPBITS (e);

	      /* decode distance of block to copy */
	      NEEDBITS ((unsigned) bd);
	      if ((e = (t = td + ((unsigned) b & md))->e) > 16)
		do
		  {
		    if (e == 99)
		      {
			errnum = ERR_BAD_GZIP_DATA;
			return 0;
		      }
		    DUMPBITS (t->b);
		    e -= 16;
		    NEEDBITS (e);
		  }
		while ((e = (t = t->v.t + ((unsigned) b & mask_bits[e]))->e)
		       > 16);
	      DUMPBITS (t->b);
	      NEEDBITS (e);
	      d = w - t->v.n - ((unsigned) b & mask_bits[e]);
	      DUMPBITS (e);
	      code_state++;
	    }
	}

      if (code_state)
	{
	  /* do the copy */
	  do
	    {
	      n -= (e = (e = WSIZE - ((d &= WSIZE - 1) > w ? d : w)) > n ? n
		    : e);
	      if (w - d >= e)
		{
		  memmove (slide + w, slide + d, e);
		  w += e;
		  d += e;
		}
	      else
		/* purposefully use the overlap for extra copies here!! */
		{
		  while (e--)
		    slide[w++] = slide[d++];
		}
	      if (w == WSIZE)
		break;
	    }
	  while (n);

	  if (!n)
	    code_state--;

	  /* did we break from the loop too soon? */
	  if (w == WSIZE)
	    break;
	}
    }

  /* restore the globals from the locals */
  inflate_d = d;
  inflate_n = n;
  wp = w;			/* restore global window pointer */
  bb = b;			/* restore global bit buffer */
  bk = k;

  return !block_len;
}


/* get header for an inflated type 0 (stored) block. */

static void
init_stored_block (void)
{
  register ulg b;		/* bit buffer */
  register unsigned k;		/* number of bits in bit buffer */

  /* make local copies of globals */
  b = bb;			/* initialize bit buffer */
  k = bk;

  /* go to byte boundary */
  DUMPBITS (k & 7);

  /* get the length and its complement */
  NEEDBITS (16);
  block_len = ((unsigned) b & 0xffff);
  DUMPBITS (16);
  NEEDBITS (16);
  if (block_len != (unsigned) ((~b) & 0xffff))
    errnum = ERR_BAD_GZIP_DATA;
  DUMPBITS (16);

  /* restore global variables */
  bb = b;
  bk = k;
}


/* get header for an inflated type 1 (fixed Huffman codes) block.  We should
   either replace this with a custom decoder, or at least precompute the
   Huffman tables. */

static void
init_fixed_block ()
{
  int i;			/* temporary variable */
  unsigned l[288];		/* length list for huft_build */

  /* set up literal table */
  for (i = 0; i < 144; i++)
    l[i] = 8;
  for (; i < 256; i++)
    l[i] = 9;
  for (; i < 280; i++)
    l[i] = 7;
  for (; i < 288; i++)		/* make a complete, but wrong code set */
    l[i] = 8;
  bl = 7;
  if ((i = huft_build (l, 288, 257, cplens, cplext, &tl, &bl)) != 0)
    {
      errnum = ERR_BAD_GZIP_DATA;
      return;
    }

  /* set up distance table */
  for (i = 0; i < 30; i++)	/* make an incomplete code set */
    l[i] = 5;
  bd = 5;
  if ((i = huft_build (l, 30, 0, cpdist, cpdext, &td, &bd)) > 1)
    {
      errnum = ERR_BAD_GZIP_DATA;
      return;
    }

  /* indicate we're now working on a block */
  code_state = 0;
  block_len++;
}


/* get header for an inflated type 2 (dynamic Huffman codes) block. */

static void
init_dynamic_block (void)
{
  int i;			/* temporary variables */
  unsigned j;
  unsigned l;			/* last length */
  unsigned m;			/* mask for bit lengths table */
  unsigned n;			/* number of lengths to get */
  unsigned nb;			/* number of bit length codes */
  unsigned nl;			/* number of literal/length codes */
  unsigned nd;			/* number of distance codes */
  unsigned ll[286 + 30];	/* literal/length and distance code lengths */
  register ulg b;		/* bit buffer */
  register unsigned k;		/* number of bits in bit buffer */

  /* make local bit buffer */
  b = bb;
  k = bk;

  /* read in table lengths */
  NEEDBITS (5);
  nl = 257 + ((unsigned) b & 0x1f);	/* number of literal/length codes */
  DUMPBITS (5);
  NEEDBITS (5);
  nd = 1 + ((unsigned) b & 0x1f);	/* number of distance codes */
  DUMPBITS (5);
  NEEDBITS (4);
  nb = 4 + ((unsigned) b & 0xf);	/* number of bit length codes */
  DUMPBITS (4);
  if (nl > 286 || nd > 30)
    {
      errnum = ERR_BAD_GZIP_DATA;
      return;
    }

  /* read in bit-length-code lengths */
  for (j = 0; j < nb; j++)
    {
      NEEDBITS (3);
      ll[bitorder[j]] = (unsigned) b & 7;
      DUMPBITS (3);
    }
  for (; j < 19; j++)
    ll[bitorder[j]] = 0;

  /* build decoding table for trees--single level, 7 bit lookup */
  bl = 7;
  if ((i = huft_build (ll, 19, 19, NULL, NULL, &tl, &bl)) != 0)
    {
      errnum = ERR_BAD_GZIP_DATA;
      return;
    }

  /* read in literal and distance code lengths */
  n = nl + nd;
  m = mask_bits[bl];
  i = l = 0;
  while ((unsigned) i < n)
    {
      NEEDBITS ((unsigned) bl);
      j = (td = tl + ((unsigned) b & m))->b;
      DUMPBITS (j);
      j = td->v.n;
      if (j < 16)		/* length of code in bits (0..15) */
	ll[i++] = l = j;	/* save last length in l */
      else if (j == 16)		/* repeat last length 3 to 6 times */
	{
	  NEEDBITS (2);
	  j = 3 + ((unsigned) b & 3);
	  DUMPBITS (2);
	  if ((unsigned) i + j > n)
	    {
	      errnum = ERR_BAD_GZIP_DATA;
	      return;
	    }
	  while (j--)
	    ll[i++] = l;
	}
      else if (j == 17)		/* 3 to 10 zero length codes */
	{
	  NEEDBITS (3);
	  j = 3 + ((unsigned) b & 7);
	  DUMPBITS (3);
	  if ((unsigned) i + j > n)
	    {
	      errnum = ERR_BAD_GZIP_DATA;
	      return;
	    }
	  while (j--)
	    ll[i++] = 0;
	  l = 0;
	}
      else
	/* j == 18: 11 to 138 zero length codes */
	{
	  NEEDBITS (7);
	  j = 11 + ((unsigned) b & 0x7f);
	  DUMPBITS (7);
	  if ((unsigned) i + j > n)
	    {
	      errnum = ERR_BAD_GZIP_DATA;
	      return;
	    }
	  while (j--)
	    ll[i++] = 0;
	  l = 0;
	}
    }

  /* free decoding table for trees */
  reset_linalloc ();

  /* restore the global bit buffer */
  bb = b;
  bk = k;

  /* build the decoding tables for literal/length and distance codes */
  bl = lbits;
  if ((i = huft_build (ll, nl, 257, cplens, cplext, &tl, &bl)) != 0)
    {
#if 0
      if (i == 1)
	printf ("gunzip: incomplete literal tree\n");
#endif

      errnum = ERR_BAD_GZIP_DATA;
      return;
    }
  bd = dbits;
  if ((i = huft_build (ll + nl, nd, 0, cpdist, cpdext, &td, &bd)) != 0)
    {
#if 0
      if (i == 1)
	printf ("gunzip: incomplete distance tree\n");
#endif

      errnum = ERR_BAD_GZIP_DATA;
      return;
    }

  /* indicate we're now working on a block */
  code_state = 0;
  block_len++;
}


static void
get_new_block (void)
{
  register ulg b;		/* bit buffer */
  register unsigned k;		/* number of bits in bit buffer */

  hufts = 0;

  /* make local bit buffer */
  b = bb;
  k = bk;

  /* read in last block bit */
  NEEDBITS (1);
  last_block = (int) b & 1;
  DUMPBITS (1);

  /* read in block type */
  NEEDBITS (2);
  block_type = (unsigned) b & 3;
  DUMPBITS (2);

  /* restore the global bit buffer */
  bb = b;
  bk = k;

  if (block_type == INFLATE_STORED)
    init_stored_block ();
  if (block_type == INFLATE_FIXED)
    init_fixed_block ();
  if (block_type == INFLATE_DYNAMIC)
    init_dynamic_block ();
}


static void
inflate_window (void)
{
  /* initialize window */
  wp = 0;

  /*
   *  Main decompression loop.
   */

  while (wp < WSIZE && !errnum)
    {
      if (!block_len)
	{
	  if (last_block)
	    break;

	  get_new_block ();
	}

      if (block_type > INFLATE_DYNAMIC)
	errnum = ERR_BAD_GZIP_DATA;

      if (errnum)
	return;

      /*
       *  Expand stored block here.
       */
      if (block_type == INFLATE_STORED)
	{
	  int w = wp;

	  /*
	   *  This is basically a glorified pass-through
	   */

	  while (block_len && w < WSIZE && !errnum)
	    {
	      slide[w++] = get_byte ();
	      block_len--;
	    }

	  wp = w;

	  continue;
	}

      /*
       *  Expand other kind of block.
       */

      if (inflate_codes_in_window ())
	reset_linalloc ();
    }

  saved_filepos += WSIZE;

  /* XXX do CRC calculation here! */
}


static void
initialize_tables (void)
{
  saved_filepos = 0;
  filepos = gzip_data_offset;

  /* initialize window, bit buffer */
  bk = 0;
  bb = 0;

  /* reset partial decompression code */
  last_block = 0;
  block_len = 0;

  /* reset memory allocation stuff */
  reset_linalloc ();
}


int
gunzip_read (char *buf, int len)
{
  int ret = 0;

  compressed_file = 0;
  gunzip_swap_values ();
  /*
   *  Now "gzip_*" values refer to the uncompressed data.
   */

  /* do we reset decompression to the beginning of the file? */
  if (saved_filepos > gzip_filepos + WSIZE)
    initialize_tables ();

  /*
   *  This loop operates upon uncompressed data only.  The only
   *  special thing it does is to make sure the decompression
   *  window is within the range of data it needs.
   */

  while (len > 0 && !errnum)
    {
      register int size;
      register char *srcaddr;

      while (gzip_filepos >= saved_filepos)
	inflate_window ();

      /* We could have started with an unknown gzip_filemax (MAXINT)
       * which has been updated in get_byte(). If so, update len
       * to avoid reading beyond the end.
       */
      if (len > (gzip_filemax - gzip_filepos)) {
        len = gzip_filemax - gzip_filepos;
      }

      srcaddr = (char *) ((gzip_filepos & (WSIZE - 1)) + slide);
      size = saved_filepos - gzip_filepos;
      if (size > len)
	size = len;

      memmove (buf, srcaddr, size);

      buf += size;
      len -= size;
      gzip_filepos += size;
      ret += size;
    }

  compressed_file = 1;
  gunzip_swap_values ();
  /*
   *  Now "gzip_*" values refer to the compressed data.
   */

  if (errnum)
    ret = 0;

  return ret;
}

#endif /* ! NO_DECOMPRESSION */
