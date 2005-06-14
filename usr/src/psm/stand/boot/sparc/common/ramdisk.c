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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/promif.h>
#include <sys/salib.h>
/* EXPORT DELETE START */
#include <bootlog.h>
/* EXPORT DELETE END */
#include "ramdisk.h"

/*
 * This is a chunk of Forth delivered by the OBP group.  When loaded
 * into OBP it creates a ramdisk device node whose functionality is
 * defined in FWARC 2002/299.
 *
 * Note the %s in the line following " new-device" - this is where we
 * plug the name of the node in.
 */
static const char ramdisk_fth[] =

"headerless "

"\" /\" find-package 0= if"
"   .\" Can't find /\" abort "
"then  push-package "

"new-device"
"   \" %s\"		device-name"
"   \" block\"		encode-string \" device_type\" property"
/* CSTYLED */
"   \" SUNW,ramdisk\"	encode-string \" compatible\"  property"

"   hex"

"   headerless"

"   0 value mmu-ihandle"
"   0 value mem-ihandle"

"   : get-memory-ihandles" /* ( -- ) */
"      \" /chosen\" find-package drop dup \" mmu\" rot"
"      get-package-property if"
"	  .\" Can't find chosen mmu property\" cr abort"
"      then"
"      decode-int to mmu-ihandle 2drop"
"      \" memory\" rot get-package-property if"
" 	  .\" Can't find chosen memory property\" cr abort"
"      then"
"      decode-int to mem-ihandle 2drop"
"   ;"

"   : get-page-size" /* ( -- page-size ) */
"     mmu-ihandle ihandle>phandle \" page-size\" rot get-package-property"
"      if  h# 2000  else  decode-int nip nip  then "
"   ;"

"   : get-mode" /* ( -- rw-mode ) */
"      here \" translate\" mmu-ihandle $call-method if"
" 	  nip nip"
"      else"
" 	  h# 27"
"      then"
"   ;"

"   : 64>32bit-phys" /* ( 64bit.lo 64bit.hi -- 32bit.lo 32bit.hi ) */
"      drop xlsplit"
"   ;"

"   : 32>64bit-phys" /* ( 32bit.lo 32bit.hi -- 64bit.lo 64bit.hi ) */
"      lxjoin 0"
"   ;"

"   : phy-claim" /* ( size align -- base.lo base.hi 0 | error ) */
"       \" claim\" mem-ihandle ['] $call-method catch if"
"	    drop 2drop 2drop -1"
"	else"
"	   64>32bit-phys 0"
"	then"
"   ;"

"   : phy-release" /* ( phys.lo phys.hi size -- ) */
"      >r 32>64bit-phys r> \" release\" mem-ihandle $call-method"
"   ;"

"   : vir-claim" /* ( [ virt ] size align -- base ) */
"      \" claim\" mmu-ihandle $call-method"
"   ;"

"   : vir-release" /* ( virt size -- ) */
"      \" release\" mmu-ihandle $call-method"
"   ;"

"   : vir-map" /* ( phys-lo phys-hi virt size mode -- ) */
"      >r >r >r 32>64bit-phys r> r> r>"
"      \" map\" mmu-ihandle $call-method"
"   ;"

"   : vir-unmap" /* ( virt size -- ) */
"      \" unmap\" mmu-ihandle $call-method"
"   ;"
"   headers"

/*  \ This structure represents a physical "chunk" of ramdisk memory */
"   struct"
"      /l field >res-pa.lo"		/* \ lower 32bits of physical address */
"      /l field >res-pa.hi"		/* \ upper 32bits of physical address */
"      /l field >res-len.lo"		/* \ lower 32bits of chunk size */
"      /l field >res-len.hi"		/* \ upper 32bits of chunk size */
"   constant /res-entry"

"   4	value    max-res-entries"	/* \ Max # of non-contig phys chunks */

"   max-res-entries /res-entry *"	/* \ size of resource buffer */
"   ( value ) buffer: my-resources"	/* \ resource buffer label */
"   0      value      num-res-entries"	/* \ current # of chunks allocated */
"   h# 10 constant    label-size"	/* \ size of disk-label buffer */
"   label-size instance buffer: my-label" /* \ for disk-label argument string */

"   get-memory-ihandles"		/* \ So we can claim/map/free memory */
"   get-page-size value pagesize"	/* \ get virt pagesize from vmem node */
"   get-mode	value	 mode"		/* \ get mode to map virt memory with */

"   0 instance	value	 window-mapped?" /* \ just in case for pa's near 0 */
"   0 instance	value	 window-pa"	/* \ physical base of virtual window */
"   0 instance	value	 window-base"	/* \ virtual window base */
"   h# 10000	constant window-size"	/* \ virtual window size */

"   0 instance	value	 filepos"	/* \ file position marker */
"   -1		value	 new-disk?"	/* \ need to alloc new resources? */

"   0 instance	value	 offset-low"	/* \ Offset to start of partition */
"   0 instance	value	 offset-high"	/* \ For partition relative seeks */
"   0 instance	value	 label-package"	/* \ ihandle for disk-label package */

"   external"				/* \ Because device_type = block */

"   0		value	 size"		/* \ size of disk */
"   0		value	 #blocks"	/* \ size of disk / decimal 512 */

"   headerless"

"   : round-up"	/* ( n -- n' ) */
"      1- tuck + swap invert and"
"   ;"

"   : init-label-package" /* ( adr len -- okay? ) */
"      0 to offset-high  0 to offset-low"
"      \" disk-label\"  $open-package to label-package"
"      label-package  if"
"	  0 0  \" offset\" label-package $call-method"
"	  to offset-high to offset-low"
" 	  true"
"      else"
" 	  .\" Can't open disk label package\"  cr  false"
"      then"
"   ;"

"   : res-entry-len" /* ( n -- 64bit-len | 0 )	\ Get length of chunk n */
"      dup num-res-entries > if"
"	  drop 0"
"      else"
" 	  /res-entry * my-resources +"
" 	  dup >res-len.lo l@ swap >res-len.hi l@"
" 	  lxjoin"
"      then"
"   ;"

"   : res-entry-pa" /* ( n -- 64bit-pa | 0 )	\ Get phys address of chunk n */
"      dup num-res-entries > if"		/* ( n ) */
" 	  drop 0"				/* ( 0 ) */
"      else"					/* ( n ) */
" 	  /res-entry * my-resources +"		/* ( chunk-adr ) */
" 	  dup >res-pa.lo l@ swap >res-pa.hi l@"	/* ( pa.lo pa.hi ) */
" 	  lxjoin"				/* ( 64bit-pa ) */
"      then"					/* ( 64bit-pa ) */
"   ;"

"   : claim-window" /* ( -- )			\ Claim mem for virt window */
"      window-size pagesize vir-claim to window-base"
"   ;"

"   : release-window" /* ( -- )			\ Free virt window memory */
"      window-base window-size"
"      2dup vir-unmap"
"      vir-release"
"   ;"

"   : map-window" /* ( 64bit-pa -- ) \ Map a physical address to the v-window */
"      dup to window-pa"
"      xlsplit window-base window-size mode vir-map"
"      -1 to window-mapped?"
"   ;"

"   : unmap-window" /* ( -- )			\ Unmap the virtual window */
"      window-base window-size vir-unmap"
"      0 to window-mapped?"
"   ;"

"   : in-window?" /* ( pa -- in-window? ) */
"      window-mapped? if"
"	  window-pa dup window-size + 1- between"
"      else"
"	  drop 0"
"      then"
"   ;"

"   : window-left" /* ( offset -- space-left-in-window ) */
"     window-size mod"
"     window-size swap -"
"   ;"

"   : release-resources" /* ( -- )  \ release previously claimed phys addrs */
"      num-res-entries 0 2dup = if"			/* ( res-entries 0 ) */
"	 2drop exit"					/* ( ) */
"      then"						/* ( res-entries 0 ) */
"      do"						/* ( ) */
" 	  i res-entry-pa xlsplit"			/* ( pa.lo pa.hi ) */
" 	  i res-entry-len phy-release"			/* ( ) */
"      loop"						/* ( ) */
"      0 to num-res-entries"				/* ( ) */
"      my-resources max-res-entries /res-entry * erase"	/* ( ) */
"   ;"

"   : fill-entry" /* ( pa.lo pa.hi size.lo size.hi  -- )    \ fill chunk buf */
"      num-res-entries /res-entry * my-resources +"
"      tuck >res-len.hi l!"
"      tuck >res-len.lo l!"
"      tuck >res-pa.hi  l!"
"      >res-pa.lo	l!"
"      num-res-entries 1+ to num-res-entries"
"   ;"

/*  \ First attempt to claim the whole ramdisk contiguously. */
/*  \ If that doesn't work, try to claim it in smaller chunks */

"   : attempt-claim" /* ( size -- error? ) */
"      size 0 begin"			/* ( next totcl ) */
"	  over pagesize phy-claim if"	/* ( next totcl ) */
"	     swap 2 / window-size"	/* ( totcl next' ) */
" 	     round-up swap"		/* ( next' totcl ) */
"	  else"				/* ( next totcl pa.lo,hi ) */
" 	     2over drop xlsplit"	/* ( next totcl pa.lo,hi len.lo,hi ) */
" 	     fill-entry"		/* ( next totcl ) */
" 	     over +"			/* ( next totcl ) */
" 	  then"				/* ( next totcl ) */
" 	  2dup size - 0>="		/* ( next totcl next comp? ) */
" 	  swap size max-res-entries /"	/* ( next totcl comp? next smallest ) */
" 	  - 0< or"			/* ( next totcl ) */
"      until"				/* ( next totcl ) */
"      nip size - 0< if  -1  else  0  then"
"   ;"

"   : claim-resources" /* ( -- error? ) */
"      attempt-claim if  release-resources -1  else  0  then"
"   ;"

/*  \ Given a 0-relative disk offset compute the proper physical address */
"   : offset>pa" /* ( disk-offset -- 64bit-pa error? ) */
"      0 num-res-entries 0 do"		/* ( disk-offset 0 ) */
"	  i res-entry-len +"		/* ( disk-offset len' ) */
" 	  2dup - 0< if"			/* ( disk-offset len' ) */
"	     - i res-entry-len +"	/* ( offset-into-pa ) \ briefly -ve */
" 	     i res-entry-pa + 0"	/* ( pa 0 ) */
" 	     unloop exit"		/* ( pa 0 ) */
" 	  then"				/* ( disk-offset len' ) */
"      loop"				/* ( disk-offset len' ) */
"      drop -1"				/* ( offset error ) */
"   ;"

/*  \ Map the virtual window to the physical-address corresponding to the */
/*  \ given 0-relative disk offset */
"   : get-window" /* ( offset -- va len error? ) */
"      dup offset>pa if"			/* ( offset pa ) */
" 	  -1"					/* ( offset pa -1 ) */
"      else"					/* ( offset pa ) */
" 	  dup in-window? 0= if"			/* ( offset pa ) */
" 	     unmap-window"			/* ( offset pa ) */
" 	     over window-size mod - map-window"	/* ( offset ) */
" 	  else"
" 	     drop"
" 	  then"
" 	   window-base over window-size mod +"	/* ( offset va ) */
" 	  swap window-left 0"			/* ( va len 0 ) */
"      then"					/* ( va len error? ) */
"   ;"

"   headers"

/*  \ Write len1 bytes from src into va. */
"   : partial-write" /* ( src len0 va len1 -- len' ) */
"      rot min dup >r move r>"
"   ;"

/*  \ Read len1 bytes from src into va. */
"   : partial-read" /* ( src len0 va len1 -- len' ) */
"      rot min dup >r >r swap r> move r>"
"   ;"

"   defer operation ' partial-write is operation"

/*  \ Write or Read len given the src address.  The block-operation word */
/*  \ determines the physical address that corresponds to the current file */
/*  \ position, and maps/unmaps the 64K virtual window */
"   : block-operation" /* ( src len acf -- len' ) */
"      is operation"
"      0 -rot begin"			/* ( 0 src len ) */
" 	  dup 0>"			/* ( len' src len more? ) */
"      while"				/* ( len' src len  ) */
" 	  2dup filepos"			/* ( len' src len src len filepos ) */
" 	  get-window if"		/* ( len' src len src len va len ) */
" 	     2drop 2drop 2drop exit"	/* ( len' ) */
" 	  then"				/* ( len src len src len va len ) */
" 	  operation"			/* ( len src len len' ) */
" 	  dup filepos + to filepos"	/* ( len src len len' ) */
" 	  >r r@ - rot r@ + rot r> + rot" /* ( len' src' len' ) */
"      repeat"				/* ( len' src' len' ) */
"      2drop"				/* ( len' ) */
"   ;"

"   : range-bad?" /* ( adr -- range-bad? ) */
"      0 size between 0="
"   ;"

"   : space-left" /* ( -- space-left ) */
"      size filepos -"
"   ;"

"   : hex-number" /* ( adr,len -- true | n false ) */
"      base @ >r hex $number r> base !"
"   ;"

"   : parse-size" /* ( $nums -- 64bit-size | 0 )  \ poss ',' seperated ints */
"      ascii , left-parse-string"		/* ( $num $num ) */
"      hex-number if  2drop 0 exit  then"	/* ( $num n ) */
"      over 0= if  nip nip exit  then"		/* ( $num n ) */
"      -rot hex-number if  drop 0 exit  then"	/* ( hi lo ) */
"      swap lxjoin"
"   ;"

"   : set-size" /* ( adr len -- error? ) */
"      parse-size dup 0= if"		/* ( size ) */
"	  drop -1"			/* ( -1 ) */
"      else"				/* ( size ) */
" 	  window-size round-up"		/* ( size' ) */
" 	  dup to size"			/* ( size' ) */
" 	  d# 512 / to #blocks"		/* ( ) */
" 	  \" nolabel\" my-label pack"	/* \ first open cannot have a label */
" 	  drop 0"			/* ( 0 ) */
"      then"				/* ( error? ) */
"   ;"

"   : $=" /* (s adr1 len1 adr2 len2 -- same? ) */
"      rot tuck  <>  if  3drop false exit  then"	/* ( adr1 adr2 len1 ) */
"      comp 0="						/* ( same? ) */
"   ;"

"   : is-label?" /* ( adr len -- is-label? )	\ $= "nolabel" or <a-z> */
"      dup 1 = if"				/* ( adr len ) */
" 	  drop c@ ascii a ascii z between"	/* ( is-label? ) */
"      else"					/* ( adr len ) */
" 	  \" nolabel\" $="			/* ( is-label? ) */
"      then"					/* ( is-label? ) */
"   ;"

"   : set-label" /* ( adr len -- error? ) */
"      my-label label-size erase"
"      dup 1+ label-size > if"
"	  2drop -1"
"      else"
"	  my-label pack drop 0"
"      then"
"   ;"

"   : process-args" /* ( arg$ -- error? ) */
"      ascii = left-parse-string"		/* ( value$ key$ ) */
"      new-disk? if"				/* ( value$ key$ ) */
" 	  2dup \" size\" $= if"			/* ( value$ key$ ) */
" 	    2drop set-size exit"		/* ( error? ) */
" 	  then"					/* ( value$ key$ ) */
"      else"					/* ( value$ key$ ) */
" 	  2dup is-label? if"			/* ( value$ key$ ) */
" 	    2swap 2drop set-label exit"		/* ( error? ) */
" 	  then"					/* ( value$ key$ ) */
"      then"					/* ( value$ key$ ) */
"     .\" Inappropriate argument \" type cr  2drop -1"	/* ( -1 ) */
"   ;"

/*  \ Publish the physical chunks that make up the ramdisk in the */
/*  \ existing property */
"   : create-existing-prop" /* ( -- ) */
"     0 0 encode-bytes"				/* ( adr 0 ) */
"     num-res-entries 0 do"			/* ( adr 0 ) */
"       i /res-entry * my-resources + >r"	/* ( adr len ) */
"       r@ >res-pa.hi l@  encode-int encode+"	/* ( adr len ) */
"       r@ >res-pa.lo l@  encode-int encode+"	/* ( adr len ) */
"       r@ >res-len.hi l@ encode-int encode+"	/* ( adr len ) */
"       r> >res-len.lo l@ encode-int encode+"	/* ( adr len ) */
"     loop"					/* ( adr len ) */
"     \" existing\" property"			/* ( ) */
"   ;"

"   external"

"   : read" /* ( adr,len -- len' ) */
"      space-left"			/* ( adr len space-left ) */
"      min ['] partial-read"		/* ( adr len' read-acf ) */
"      block-operation"			/* ( len' ) */
"   ;"

"   : write" /* ( adr,len -- len' ) */
"      space-left"			/* ( adr len space-left ) */
"      min ['] partial-write"		/* ( adr len' write-acf ) */
"      block-operation"			/* ( len' ) */
"   ;"

"   : seek" /* ( offset other -- error? ) */
"      offset-high + swap offset-low + swap drop"  /* \ "other" arg unused */
"      dup 0< if"			/* ( offset ) */
"	  size +"			/* ( offset' ) */
"      then"				/* ( offset' ) */
"	  0 + dup range-bad? if"	/* ( offset' ) */
" 	  drop -1"			/* ( -1 ) */
"      else"				/* ( offset' ) */
" 	  to filepos false"		/* ( 0 ) */
"      then"				/* ( error? ) */
"   ;"

"   : load" /* ( addr -- size ) */
"      \" load\"  label-package $call-method"
"   ;"

"   : offset" /* ( rel -- abs )  \ needed for device_type = block */
"      offset-low +"
"   ;"

/*  \ release resources, initialize data, remove existing property */
/*  \ Can be called with no instance data */
"   : destroy" /* ( -- ) */
"      \" existing\" delete-property"
"      0 to size"
"      -1 to new-disk?"
"      release-resources"
"   ;"

"   : open" /* ( -- flag ) */
"      my-args process-args if"
"	  0 exit"				/* \ unrecognized arguments */
"      then"
"      new-disk? if"
"	  claim-resources if  0 exit  then"	/* \ can't claim */
"	  create-existing-prop"			/* \ advertise resources */
"	  0 to new-disk?"			/* \ no longer a new-disk */
"      then"
"      claim-window"				/* \ claim virtual window */
"      my-label count init-label-package 0= if  0 exit  then"
"      -1"
"   ;"

"   : close" /* ( -- ) */
"      window-base if "
"	  release-window"
"      then"
"   ; "
"finish-device "

"pop-package"

;	/* end of ramdisk_fth[] initialization */


/*
 * Create an actual ramdisk instance.
 */
static void
create_ramdisk_node(const char *ramdisk_name)
{
	char	*fth_buf;
	size_t	buf_size;

	buf_size = sizeof (ramdisk_fth) + strlen(ramdisk_name);

	fth_buf = bkmem_alloc(buf_size);
	if (fth_buf == NULL) {
		prom_panic("unable to allocate Forth buffer for ramdisk");
	}

	(void) snprintf(fth_buf, buf_size, ramdisk_fth, ramdisk_name);

	prom_interpret(fth_buf, 0, 0, 0, 0, 0);

	bkmem_free(fth_buf, buf_size);
}

int
create_ramdisk(const char *ramdisk_name, size_t size, char **device_path)
{
	static int	first_time = 1;
	char		buf[OBP_MAXPATHLEN];
	ihandle_t	ih;

	/*
	 * Ensure that size is a multiple of page size (rounded up).
	 */
	size = ptob(btopr(size));

/* EXPORT DELETE START */
	bootlog("wanboot", BOOTLOG_VERBOSE, "Creating ramdisk, size=0x%lx",
	    size);
/* EXPORT DELETE END */

	if (strcmp(ramdisk_name, RD_ROOTFS) == 0 ||
	    strcmp(ramdisk_name, RD_BOOTFS) == 0) {

		if (first_time) {
			first_time = 0;

			create_ramdisk_node(RD_ROOTFS);
			create_ramdisk_node(RD_BOOTFS);
		}

		(void) snprintf(buf, sizeof (buf), "/%s:nolabel", ramdisk_name);
		*device_path = strdup(buf);

		if (*device_path != NULL) {
			(void) snprintf(buf, sizeof (buf), "/%s:size=%x,%x",
			    ramdisk_name,
			    (uint32_t)(size >> 32), (uint32_t)size);

			if ((ih = prom_open(buf)) != 0) {
				return (ih);
			}
		}
	}

/* EXPORT DELETE START */
	bootlog("wanboot", BOOTLOG_CRIT, "Cannot create ramdisk \"%s\"",
	    ramdisk_name);
/* EXPORT DELETE END */
	prom_panic("create_ramdisk: fatal error");
	/* NOTREACHED */
}
