/*
 *  ISO 9660 filesystem backend for GRUB (GRand Unified Bootloader)
 *  including Rock Ridge Extensions support
 *
 *  Copyright (C) 1998, 1999  Kousuke Takai  <tak@kmc.kyoto-u.ac.jp>
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
 *  References:
 *	linux/fs/isofs/rock.[ch]
 *	mkisofs-1.11.1/diag/isoinfo.c
 *	mkisofs-1.11.1/iso9660.h
 *		(all are written by Eric Youngdale)
 */

#ifndef _ISO9660_H_
#define _ISO9660_H_

#define ISO_SECTOR_BITS              (11)
#define ISO_SECTOR_SIZE              (1<<ISO_SECTOR_BITS)

#define	ISO_REGULAR	1	/* regular file	*/
#define	ISO_DIRECTORY	2	/* directory	*/
#define	ISO_OTHER	0	/* other file (with Rock Ridge) */

#define	RR_FLAG_PX	0x01	/* have POSIX file attributes */
#define RR_FLAG_PN	0x02	/* POSIX devices */
#define RR_FLAG_SL	0x04	/* Symbolic link */
#define	RR_FLAG_NM	0x08	/* have alternate file name   */
#define RR_FLAG_CL	0x10	/* Child link */
#define RR_FLAG_PL	0x20	/* Parent link */
#define RR_FLAG_RE	0x40	/* Relocation directory */
#define RR_FLAG_TF	0x80	/* Timestamps */

/* POSIX file attributes for Rock Ridge extensions */
#define	POSIX_S_IFMT	0xF000
#define	POSIX_S_IFREG	0x8000
#define	POSIX_S_IFDIR	0x4000

/* volume descriptor types */
#define ISO_VD_PRIMARY 1
#define ISO_VD_END 255

#define ISO_STANDARD_ID "CD001"

#ifndef ASM_FILE

#ifndef __sun
#ifndef	__BIT_TYPES_DEFINED__
typedef		 int	 int8_t	__attribute__((mode(QI)));
typedef unsigned int   u_int8_t	__attribute__((mode(QI)));
typedef		 int	int16_t	__attribute__((mode(HI)));
typedef unsigned int  u_int16_t	__attribute__((mode(HI)));
typedef		 int	int32_t	__attribute__((mode(SI)));
typedef unsigned int  u_int32_t	__attribute__((mode(SI)));
#endif
#else
#ifndef GRUB_UTIL
typedef		 char  int8_t;
typedef		 short int16_t;
typedef		 int   int32_t;
#endif /* ! GRUB_UTIL */
typedef unsigned char  u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int   u_int32_t;
#endif /* __sun */

typedef	union {
  u_int8_t l,b;
}	iso_8bit_t;

struct __iso_16bit {
  u_int16_t l, b;
} __attribute__ ((packed));
typedef	struct __iso_16bit iso_16bit_t;

struct __iso_32bit {
  u_int32_t l, b;
} __attribute__ ((packed));
typedef	struct __iso_32bit iso_32bit_t;

typedef u_int8_t		iso_date_t[7];

struct iso_directory_record {
  iso_8bit_t	length;
  iso_8bit_t	ext_attr_length;
  iso_32bit_t	extent;
  iso_32bit_t	size;
  iso_date_t	date;
  iso_8bit_t	flags;
  iso_8bit_t	file_unit_size;
  iso_8bit_t	interleave;
  iso_16bit_t	volume_seq_number;
  iso_8bit_t	name_len;
  u_int8_t	name[1];
} __attribute__ ((packed));

struct iso_primary_descriptor {
  iso_8bit_t	type;
  u_int8_t	id[5];
  iso_8bit_t	version;
  u_int8_t	_unused1[1];
  u_int8_t	system_id[32];
  u_int8_t	volume_id[32];
  u_int8_t	_unused2[8];
  iso_32bit_t	volume_space_size;
  u_int8_t	_unused3[32];
  iso_16bit_t	volume_set_size;
  iso_16bit_t	volume_seq_number;
  iso_16bit_t	logical_block_size;
  iso_32bit_t	path_table_size;
  u_int8_t	type_l_path_table[4];
  u_int8_t	opt_type_l_path_table[4];
  u_int8_t	type_m_path_table[4];
  u_int8_t	opt_type_m_path_table[4];
  struct iso_directory_record root_directory_record;
  u_int8_t	volume_set_id[128];
  u_int8_t	publisher_id[128];
  u_int8_t	preparer_id[128];
  u_int8_t	application_id[128];
  u_int8_t	copyright_file_id[37];
  u_int8_t	abstract_file_id[37];
  u_int8_t	bibliographic_file_id[37];
  u_int8_t	creation_date[17];
  u_int8_t	modification_date[17];
  u_int8_t	expiration_date[17];
  u_int8_t	effective_date[17];
  iso_8bit_t	file_structure_version;
  u_int8_t	_unused4[1];
  u_int8_t	application_data[512];
  u_int8_t	_unused5[653];
} __attribute__ ((packed));

struct rock_ridge {
  u_int16_t	signature;
  u_int8_t	len;
  u_int8_t	version;
  union {
    struct SP {
      u_int16_t	magic;
      u_int8_t	skip;
    } sp;
    struct CE {
      iso_32bit_t	extent;
      iso_32bit_t	offset;
      iso_32bit_t	size;
    } ce;
    struct ER {
      u_int8_t	len_id;
      u_int8_t	len_des;
      u_int8_t	len_src;
      u_int8_t	ext_ver;
      u_int8_t	data[0];
    } er;
    struct RR {
      iso_8bit_t	flags;
    } rr;
    struct PX {
      iso_32bit_t	mode;
      iso_32bit_t	nlink;
      iso_32bit_t	uid;
      iso_32bit_t	gid;
    } px;
    struct PN {
      iso_32bit_t	dev_high;
      iso_32bit_t	dev_low;
    } pn;
    struct SL {
      iso_8bit_t flags;
      struct SL_component {
	iso_8bit_t	flags;
	u_int8_t		len;
	u_int8_t		text[0];
      } link;
    } sl;
    struct NM {
      iso_8bit_t	flags;
      u_int8_t	name[0];
    } nm;
    struct CL {
      iso_32bit_t	location;
    } cl;
    struct PL {
      iso_32bit_t	location;
    } pl;
    struct TF {
      iso_8bit_t	flags;
      iso_date_t	times[0];
    } tf;
  } u;
} __attribute__ ((packed));

typedef	union RR_ptr {
  struct rock_ridge *rr;
  char		  *ptr;
  int		   i;
} RR_ptr_t;

#define	RRMAGIC(c1, c2)	((c1)|(c2) << 8)

#define	CHECK2(ptr, c1, c2) \
	(*(unsigned short *)(ptr) == (((c1) | (c2) << 8) & 0xFFFF))

#endif /* !ASM_FILE */

#endif /* _ISO9660_H_ */
