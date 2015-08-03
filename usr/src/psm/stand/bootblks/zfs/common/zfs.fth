\
\ CDDL HEADER START
\
\ The contents of this file are subject to the terms of the
\ Common Development and Distribution License (the "License").
\ You may not use this file except in compliance with the License.
\
\ You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
\ or http://www.opensolaris.org/os/licensing.
\ See the License for the specific language governing permissions
\ and limitations under the License.
\
\ When distributing Covered Code, include this CDDL HEADER in each
\ file and include the License file at usr/src/OPENSOLARIS.LICENSE.
\ If applicable, add the following below this CDDL HEADER, with the
\ fields enclosed by brackets "[]" replaced with your own identifying
\ information: Portions Copyright [yyyy] [name of copyright owner]
\
\ CDDL HEADER END
\
\
\ Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
\ Use is subject to license terms.
\
\ Copyright 2015 Toomas Soome <tsoome@me.com>


purpose: ZFS file system support package
copyright: Copyright 2010 Sun Microsystems, Inc. All Rights Reserved

" /packages" get-package  push-package

new-device
   fs-pkg$  device-name  diag-cr?

   0 instance value temp-space


   \ 64b ops
   \ fcode is still 32b on 64b sparc-v9, so
   \ we need to override some arithmetic ops
   \ stack ops and logical ops (dup, and, etc) are 64b
   : xcmp  ( x1 x2 -- -1|0|1 )
      xlsplit rot xlsplit        ( x2.lo x2.hi x1.lo x1.hi )
      rot 2dup  u<  if           ( x2.lo x1.lo x1.hi x2.hi )
         2drop 2drop  -1         ( lt )
      else  u>  if               ( x2.lo x1.lo )
         2drop  1                ( gt )
      else  swap 2dup u<  if     ( x1.lo x2.lo )
         2drop  -1               ( lt )
      else  u>  if               (  )
         1                       ( gt )
      else                       (  )
         0                       ( eq )
      then then then then        ( -1|0|1 )
   ;
   : x<   ( x1 x2 -- <? )   xcmp  -1 =  ;
   : x>   ( x1 x2 -- >? )   xcmp   1 =  ;
\  : x=   ( x1 x2 -- =? )   xcmp   0=   ;
   : x<>  ( x1 x2 -- <>? )  xcmp   0<>  ;
   : x0=  ( x -- 0=? )      xlsplit 0=  swap 0=  and  ;

   /buf-len  instance buffer:  numbuf

   : (xu.)  ( u -- u$ )
      numbuf /buf-len +  swap         ( adr u )
      begin
         d# 10 /mod  swap             ( adr u' rem )
         ascii 0  +                   ( adr u' c )
         rot 1-  tuck c!              ( u adr' )
         swap  dup 0=                 ( adr u done? )
      until  drop                     ( adr )
      dup  numbuf -  /buf-len swap -  ( adr len )
   ;

   \ pool name
   /buf-len  instance buffer:  bootprop-buf
   : bootprop$  ( -- prop$ )  bootprop-buf cscount  ;

   \ decompression
   \
   \ uts/common/os/compress.c has a definitive theory of operation comment
   \ on lzjb, but here's the reader's digest version:
   \
   \ repeated phrases are replaced by referenced to the original
   \ e.g.,
   \ y a d d a _ y a d d a _ y a d d a , _ b l a h _ b l a h _ b l a h
   \ becomes
   \ y a d d a _ 6 11 , _ b l a h 5 10
   \ where 6 11 means memmove(ptr, ptr - 6, 11)
   \
   \ data is separated from metadata with embedded copymap entries
   \ every 8 items  e.g., 
   \ 0x40 y a d d a _ 6 11 , 0x20 _ b l a h 5 10
   \ the copymap has a set bit for copy refercences
   \ and a clear bit for bytes to be copied directly
   \
   \ the reference marks are encoded with match-bits and match-min
   \ e.g.,
   \ byte[0] = ((mlen - MATCH_MIN) << (NBBY - MATCH_BITS) | (off >> NBBY)
   \ byte[1] = (uint8_t)off
   \

   : pow2  ( n -- 2**n )  1 swap lshift  ;

   \ assume MATCH_BITS=6 and MATCH_MIN=3
   6                       constant mbits
   3                       constant mmin
   8 mbits -               constant mshift
   d# 16 mbits -  pow2 1-  constant mmask

   : decode-src  ( src -- mlen off )
      dup c@  swap  1+ c@              ( c[0] c[1] )
      over  mshift rshift  mmin +      ( c[0] c[1] mlen )
      -rot  swap bwjoin  mmask  and    ( mlen off )
   ;

   \ equivalent of memmove(dst, dst - off, len)
   \ src points to a copy reference to be decoded
   : mcopy  ( dend dst src -- dend dst' )
      decode-src                         ( dend dst mlen off )
      2 pick  swap -  >r                 ( dent dst mlen  r: cpy )
      begin
         1-  dup 0>=                     ( dend dst mlen' any?  r: cpy )
         2over >  and                    ( dend dst mlen !done?  r : cpy )
      while                              ( dend dst mlen  r: cpy )
         swap  r> dup 1+ >r  c@          ( dend mlen dst c  r: cpy' )
         over c!  1+  swap               ( dend dst' mlen  r: cpy )
      repeat                             ( dend dst' mlen  r: cpy )
      r> 2drop                           ( dend dst )
   ;


   : lzjb ( src dst len -- )
      over +  swap                  ( src dend dst )
      rot >r                        ( dend dst  r: src )

      \ setup mask so 1st while iteration fills map
      0  7 pow2  2swap              ( map mask dend dst  r: src )

      begin  2dup >  while
         2swap  1 lshift            ( dend dst map mask'  r: src )

         dup  8 pow2  =  if
            \ fetch next copymap
            2drop                   ( dend dst  r: src )
            r> dup 1+ >r  c@  1     ( dend dst map' mask'  r: src' )
         then                       ( dend dst map mask  r: src' )

         \ if (map & mask) we hit a copy reference
         \ else just copy 1 byte
         2swap  2over and  if       ( map mask dend dst  r: src )
            r> dup 2+ >r            ( map mask dend dst src  r: src' )
            mcopy                   ( map mask dend dst'  r: src )
         else
            r> dup 1+ >r  c@        ( map mask dend dst c  r: src' )
            over c!  1+             ( map mask dend dst'  r: src )
         then
      repeat                        ( map mask dend dst  r: src )
      2drop 2drop  r> drop          (  )
   ;

   \ decode lz4 buffer header, returns src addr and len
   : lz4_sbuf ( addr -- s_addr s_len )
      dup C@ 8 lshift swap 1+		( byte0 addr++ )
      dup C@				( byte0 addr byte1 )
      rot				( addr byte1 byte0 )
      or d# 16 lshift swap 1+		( d addr++ )

      dup C@ 8 lshift			( d addr byte2 )
      swap 1+				( d byte2 addr++ )
      dup C@ swap 1+			( d byte2 byte3 addr++ )
      -rot				( d s_addr byte2 byte3 )
      or				( d s_addr d' )
      rot				( s_addr d' d )
      or				( s_addr s_len )
    ;

    4           constant STEPSIZE
    8           constant COPYLENGTH
    5           constant LASTLITERALS
    4           constant ML_BITS
    d# 15       constant ML_MASK		\ (1<<ML_BITS)-1
    4           constant RUN_BITS		\ 8 - ML_BITS
    d# 15       constant RUN_MASK		\ (1<<RUN_BITS)-1

    \ A32(d) = A32(s); d+=4; s+=4
    : lz4_copystep ( dest source -- dest' source')
      2dup swap 4 move
      swap 4 +
      swap 4 +		( dest+4 source+4 )
    ;

    \ do { LZ4_COPYPACKET(s, d) } while (d < e);
    : lz4_copy ( e d s -- e d' s' )
      begin			( e d s )
        lz4_copystep
        lz4_copystep		( e d s )
        over			( e d s d )
        3 pick < 0=
      until
    ;

    \ lz4 decompress translation from C code
    \ could use some factorisation
    : lz4 ( src dest len -- )
      swap dup >r swap		\ save original dest to return stack.
      rot			( dest len src )
      lz4_sbuf			( dest len s_buf s_len )
      over +			( dest len s_buf s_end )
      2swap				( s_buf s_end dest len )
      over +			( s_buf s_end dest dest_end )
      2swap				( dest dest_end s_buf s_end )

      \ main loop
      begin 2dup < while
         swap dup C@		( dest dest_end s_end s_buf token )
         swap CHAR+ swap		( dest dest_end s_end s_buf++ token )
         dup ML_BITS rshift	( dest dest_end s_end s_buf token length )
         >r rot rot r>		( dest dest_end token s_end s_buf length )
         dup RUN_MASK = if
           d# 255 begin		( dest dest_end token s_end s_buf length s )
             swap		( dest dest_end token s_end s_buf s length )
             >r >r			( ... R: length s )
             2dup >			( dest dest_end token s_end s_buf flag )
             r@ d# 255 = and ( dest dest_end token s_end s_buf flag R: length s )
             r> swap r> swap ( dest dest_end token s_end s_buf s length flag )
             >r swap r>	 ( dest dest_end token s_end s_buf length s flag )
           while
             drop >r		( dest dest_end token s_end s_buf R: length )
             dup c@ swap CHAR+	( dest dest_end token s_end s s_buf++ )
	     swap			( dest dest_end token s_end s_buf s )
             dup			( dest dest_end token s_end s_buf s s )
             r> + swap		( dest dest_end token s_end s_buf length s )
           repeat
           drop			( dest dest_end token s_end s_buf length )
         then

         -rot			( dest dest_end token length s_end s_buf )
         swap >r >r		( dest dest_end token length R: s_end s_buf )
         swap >r		( dest dest_end length R: s_end s_buf token )
         rot			( dest_end length dest )
         2dup +			( dest_end length dest cpy )

         2dup > if ( dest > cpy )
            " lz4 overflow" die
         then

         3 pick COPYLENGTH - over < ( dest_end length dest cpy flag )
         3 pick			( dest_end length dest cpy flag length )
         r>			( dest_end length dest cpy flag length token )
         r>	( dest_end length dest cpy flag length token s_buf R: s_end )
         rot	( dest_end length dest cpy flag token s_buf length )
         over +	( dest_end length dest cpy flag token s_buf length+s_buf )
         r@ COPYLENGTH - > ( dest_end length dest cpy flag token s_buf flag )
         swap >r ( dest_end length dest cpy flag token flag R: s_end s_buf )
         swap >r ( dest_end length dest cpy flag flag R: s_end s_buf token )
         or if		( dest_end length dest cpy R: s_end s_buf token )

           3 pick over swap > if
             " lz4 write beyond buffer end" die	( write beyond the dest end )
           then			( dest_end length dest cpy )

           2 pick			( dest_end length dest cpy length )
           r> r> swap	( dest_end length dest cpy length s_buf token R: s_end )
           r>		( dest_end length dest cpy length s_buf token s_end )
           swap >r >r	( dest_end length dest cpy length s_buf R: token s_end )

           swap over +	( dest_end length dest cpy s_buf s_buf+length )
           r@ > if	( dest_end length dest cpy s_buf R: token s_end )
              " lz4 read beyond source" die	\ read beyond source buffer
           then

           nip		( dest_end length dest s_buf R: token s_end )
           >r		( dest_end length dest R: token s_end s_buf )
           over r@		( dest_end length dest length s_buf )
           -rot move	( dest_end length )

           r> + r> r> drop < if
             " lz4 format violation" die		\ LZ4 format violation
           then

           r> drop		\ drop original dest
           drop
           exit			\ parsing done
         then

         swap		( dest_end length cpy dest R: s_end s_buf token )
         r> r> swap >r		( dest_end length cpy dest s_buf R: s_end token )

         lz4_copy		( dest_end length cpy dest s_buf)

         -rot			( dest_end length s_buf cpy dest )
         over -			( dest_end length s_buf cpy dest-cpy )
         rot			( dest_end length cpy dest-cpy s_buf )
         swap -			( dest_end length cpy s_buf )

         dup C@ swap		( dest_end length cpy b s_buf )
         dup 1+ C@ 8 lshift	( dest_end length cpy b s_buf w )
         rot or			( dest_end length cpy s_buf w )
         2 pick swap -		( dest_end length cpy s_buf ref )
         swap 2 +			( dest_end length cpy ref s_buf+2 )
			\ note: cpy is also dest, remember to save it
         -rot			( dest_end length s_buf cpy ref )
         dup			( dest_end length s_buf cpy ref ref )

			\ now we need original dest
         r> r> swap r@		( dest_end length s_buf cpy ref ref s_end token dest )
         -rot swap >r >r
         < if
           " lz4 reference outside buffer" die	\ reference outside dest buffer
         then			( dest_end length s_buf op ref )

         2swap			( dest_end op ref length s_buf )
         swap		( dest_end op ref s_buf length R: dest s_end token )

         \ get matchlength
         drop r> ML_MASK and	( dest_end op ref s_buf length R: dest s_end )
         dup ML_MASK = if	( dest_end op ref s_buf length R: dest s_end )
           -1		\ flag to top
           begin
             rot			( dest_end op ref length flag s_buf )
	     dup r@ <		( dest_end op ref length flag s_buf flag )
             rot and		( dest_end op ref length s_buf flag )
           while
             dup c@		( dest_end op ref length s_buf s )
             swap 1+		( dest_end op ref length s s_buf++ )
             -rot		( dest_end op ref s_buf length s )
             swap over + swap	( dest_end op ref s_buf length+s s )
             d# 255 =
           repeat
           swap
         then			( dest_end op ref s_buf length R: dest s_end )

         2swap			( dest_end s_buf length op ref )

         \ copy repeated sequence
         2dup - STEPSIZE < if	( dest_end s_buf length op ref )
           \ 4 times *op++ = *ref++;
           dup c@ >r		( dest_end s_buf length op ref R: C )
           CHAR+ swap		( dest_end s_buf length ref++ op )
           dup r> swap c! CHAR+ swap    ( dest_end s_buf length op ref )
           dup c@ >r		( dest_end s_buf length op ref R: C )
           CHAR+ swap		( dest_end s_buf length ref++ op )
           dup r> swap c! CHAR+ swap    ( dest_end s_buf length op ref )
           dup c@ >r		( dest_end s_buf length op ref R: C )
           CHAR+ swap		( dest_end s_buf length ref++ op )
           dup r> swap c! CHAR+ swap    ( dest_end s_buf length op ref )
           dup c@ >r		( dest_end s_buf length op ref R: C )
           CHAR+ swap		( dest_end s_buf length ref++ op )
           dup r> swap c! CHAR+ swap    ( dest_end s_buf length op ref )
           2dup -			( dest_end s_buf length op ref op-ref )
           case
             1 of 3 endof
             2 of 2 endof
             3 of 3 endof
               0
           endcase
           -			\ ref -= dec
           2dup swap 4 move	( dest_end s_buf length op ref )
           swap STEPSIZE 4 - +
           swap			( dest_end s_buf length op ref )
        else
           lz4_copystep		( dest_end s_buf length op ref )
        then
        -rot			( dest_end s_buf ref length op )
        swap over		( dest_end s_buf ref op length op )
        + STEPSIZE 4 - -	( dest_end s_buf ref op cpy R: dest s_end )

        \ if cpy > oend - COPYLENGTH
        4 pick COPYLENGTH -	( dest_end s_buf ref op cpy oend-COPYLENGTH )
        2dup > if		( dest_end s_buf ref op cpy oend-COPYLENGTH )
          swap			( dest_end s_buf ref op oend-COPYLENGTH cpy )

          5 pick over < if
            " lz4 write outside buffer" die	\ write outside of dest buffer
          then			( dest_end s_buf ref op oend-COPYLENGTH cpy )

          >r	( dest_end s_buf ref op oend-COPYLENGTH R: dest s_end cpy )
          -rot swap		( dest_end s_buf oend-COPYLENGTH op ref )
          lz4_copy		( dest_end s_buf oend-COPYLENGTH op ref )
          rot drop swap r>	( dest_end s_buf ref op cpy )
          begin
            2dup <
          while
            >r			( dest_end s_buf ref op R: cpy )
            over			( dest_end s_buf ref op ref )
            c@			( dest_end s_buf ref op C )
            over c!		( dest_end s_buf ref op )
            >r 1+ r> 1+ r>	( dest_end s_buf ref++ op++ cpy )
          repeat

          nip			( dest_end s_buf ref op )
          dup 4 pick = if
            \ op == dest_end  we are done, cleanup
            r> r> 2drop 2drop 2drop
            exit
          then
				( dest_end s_buf ref op R: dest s_end )
          nip			( dest_end s_buf op )
        else
          drop			( dest_end s_buf ref op cpy R: dest s_end)
          -rot			( dest_end s_buf cpy ref op )
          swap			( dest_end s_buf cpy op ref )
          lz4_copy
          2drop			( dest_end s_buf op )
       then

       -rot r>			( op dest_end s_buf s_end R: dest )
     repeat

     r> drop
     2drop
     2drop
   ;

   \
   \	ZFS block (SPA) routines
   \

   1           constant  def-comp#
   2           constant  no-comp#
   3           constant  lzjb-comp#
   d# 15       constant  lz4-comp#

   h# 2.0000   constant  /max-bsize
   d# 512      constant  /disk-block
   d# 128      constant  /blkp

   alias  /gang-block  /disk-block

   \ the ending checksum is larger than 1 byte, but that
   \ doesn't affect the math here
   /gang-block 1-
   /blkp  /    constant  #blks/gang

   : blk_offset    ( bp -- n )  h#  8 +  x@  -1 h# 7fff.ffff  lxjoin  and  ;
   : blk_gang      ( bp -- n )  h#  8 +  x@  xlsplit  nip  d# 31 rshift  ;
   : blk_etype     ( bp -- n )  h# 32 +  c@  ;
   : blk_comp      ( bp -- n )  h# 33 +  c@  h# 7f and ;
   : blk_embedded? ( bp -- flag )  h# 33 +  c@  h# 80 and h# 80 = ;
   : blk_psize     ( bp -- n )  h# 34 +  w@  ;
   : blk_lsize     ( bp -- n )  h# 36 +  w@  ;
   : blk_birth     ( bp -- n )  h# 50 +  x@  ;

   : blke_psize    ( bp -- n )  h# 34 +  c@  1 rshift h# 7f and 1+ ;
   : blke_lsize    ( bp -- n )  h# 34 +  l@  h# 1ff.ffff and 1+ ;

   0 instance value dev-ih
   0 instance value blk-space
   0 instance value gang-space

   : foff>doff  ( fs-off -- disk-off )    /disk-block *  h# 40.0000 +  ;
   : fsz>dsz    ( fs-size -- disk-size )  1+  /disk-block *  ;

   : bp-dsize  ( bp -- dsize )
      dup blk_embedded? if
         blke_psize
      else
         blk_psize fsz>dsz
      then
   ;

   : bp-lsize  ( bp -- lsize )
      dup blk_embedded? if
         blke_lsize
      else
         blk_lsize fsz>dsz
      then
   ;

   : (read-dva)  ( adr len dva -- )
      blk_offset foff>doff  dev-ih  read-disk
   ;

   : gang-read  ( adr len bp gb-adr -- )    tokenizer[ reveal ]tokenizer

      \ read gang block
      tuck  /gang-block rot  (read-dva)   ( adr len gb-adr )

      \ loop through indirected bp's
      dup  /blkp #blks/gang *             ( adr len gb-adr bp-list bp-list-len )
      bounds  do                          ( adr len gb-adr )
         i blk_offset x0=  ?leave

         \ calc subordinate read len
         over  i bp-dsize  min            ( adr len gb-adr sub-len )
         2swap swap                       ( gb-adr sub-len len adr )

         \ nested gang block - recurse with new gang block area
         i blk_gang  if
            2swap                         ( len adr gb-adr sub-len )
            3dup  swap  /gang-block +     ( len adr gb-adr sub-len adr sub-len gb-adr' )
            i swap  gang-read             ( len adr gb-adr sub-len )
            2swap                         ( gb-adr sub-len len adr )
         else
            3dup  nip  swap               ( gb-adr sub-len len adr adr sub-len )
            i (read-dva)                  ( gb-adr sub-len len adr )
         then                             ( gb-adr sub-len len adr )

         \ adjust adr,len and check if done
         -rot  over -                     ( gb-adr adr sub-len len' )
         -rot  +  swap                    ( gb-adr adr' len' )
         dup 0=  ?leave
         rot                              ( adr' len' gb-adr )
      /blkp  +loop
      3drop                               (  )
   ;

   : read-dva  ( adr len dva -- )
      dup  blk_gang  if
         gang-space  gang-read
      else
         (read-dva)
      then
   ;

   : read-embedded ( adr len bp -- )
      \ loop over buf len, w in comment is octet count
      \ note, we dont increment bp, but use index value of w
      \ so we can skip the non-payload octets
      swap 0 0                              ( adr bp len 0 0 )
      rot 0 do                              ( adr bp 0 0 )
         I 8 mod 0= if                      ( adr bp w x )
            drop                            ( adr bp w )
            2dup                            ( adr bp w bp w )
            xa+                             ( adr bp w bp+w*8 )
            x@ swap                         ( adr bp x w )
            1+ dup 6 = if 1+ else           \ skip 6th word
               dup h# a = if 1+ then        \ skip 10th word
            then                            ( adr bp x w )
            swap                            ( adr bp w x )
         then
         2swap                              ( w x adr bp )
         -rot                               ( w bp x adr )
         swap dup                           ( w bp adr x x )
         I 8 mod 4 < if
            xlsplit                         ( w bp adr x x.lo x.hi )
            drop                            ( w bp adr x x.lo )
         else
            xlsplit                         ( w bp adr x x.lo x.hi )
            nip                             ( w bp adr x x.hi )
         then
         I 4 mod 8 * rshift h# ff and       ( w bp adr x c )
         rot                                ( w bp x c adr )
         swap over                          ( w bp x adr c adr )
         I + c!                             ( w bp x adr )

         \ now we need to fix the stack for next pass
         \ need to get ( adr bp w x )
         swap 2swap                         ( adr x w bp )
         -rot                               ( adr bp x w )
         swap                               ( adr bp w x )
      loop
      2drop 2drop
   ;

   \ block read that check for holes, gangs, compression, etc
   : read-bp  ( adr len bp -- )
      \ sparse block?
      dup x@ x0=                         ( addr len bp flag0 )
      swap dup 8 + x@ x0=                ( addr len flag0 bp flag1 )
      rot                                ( addr len bp flag1 flag0 )
      and if
         drop  erase  exit               (  )
      then

      \ no compression?
      dup blk_comp  no-comp#  =  if
         read-dva  exit                  (  )
      then

      \ read into blk-space. read is either from embedded area or disk
      dup blk_embedded? if
         dup blk-space  over bp-dsize    ( adr len bp bp blk-adr rd-len )
         rot  read-embedded              ( adr len bp )
      else
         dup blk-space  over bp-dsize    ( adr len bp bp blk-adr rd-len )
         rot  read-dva                   ( adr len bp )
      then

      \ set up the stack for decompress
      blk_comp >r                        ( adr len R: alg )
      blk-space -rot r>                  ( blk-adr adr len alg )

      case
         lzjb-comp#  of lzjb endof
         lz4-comp#   of lz4  endof
         def-comp#   of lz4  endof       \ isn't this writer only?
         dup .h
         "  : unknown compression algorithm, only lzjb and lz4 are supported"
         die
      endcase                             (  )
   ;

   \
   \    ZFS vdev routines
   \

   h# 1.c000  constant /nvpairs
   h# 4000    constant nvpairs-off

   \
   \ xdr packed nvlist
   \
   \  12B header
   \  array of xdr packed nvpairs
   \     4B encoded nvpair size
   \     4B decoded nvpair size
   \     4B name string size
   \     name string
   \     4B data type
   \     4B # of data elements
   \     data
   \  8B of 0
   \
   d# 12      constant /nvhead

   : >nvsize  ( nv -- size )  l@  ;
   : >nvname  ( nv -- name$ )
      /l 2* +  dup /l +  swap l@
   ;
   : >nvdata  ( nv -- data )
      >nvname +  /l roundup
   ;

   \ convert nvdata to 64b int or string
   : nvdata>x  ( nvdata -- x )
      /l 2* +                   ( ptr )
      dup /l + l@  swap l@      ( x.lo x.hi )
      lxjoin                    ( x )
   ;
   alias nvdata>$ >nvname

   : nv-lookup  ( nv name$ -- nvdata false  |  true )
      rot /nvhead +               ( name$ nvpair )
      begin  dup >nvsize  while
         dup >r  >nvname          ( name$ nvname$  r: nvpair )
         2over $=  if             ( name$  r: nvpair )
            2drop  r> >nvdata     ( nvdata )
            false exit            ( nvdata found )
         then                     ( name$  r: nvpair )
         r>  dup >nvsize  +       ( name$ nvpair' )
      repeat
      3drop  true                 ( not-found )
   ;

   : scan-vdev  ( -- )
      temp-space /nvpairs nvpairs-off    ( adr len off )
      dev-ih  read-disk                  (  )
      temp-space " txg"  nv-lookup  if
         " no txg nvpair"  die
      then  nvdata>x                     ( txg )
      x0=  if
         " detached mirror"  die
      then                               (  )
      temp-space " name"  nv-lookup  if
         " no name nvpair"  die
      then  nvdata>$                     ( pool$ )
      bootprop-buf swap  move            (  )
   ;


   \
   \	ZFS ueber-block routines
   \

   d# 1024                  constant /uber-block
   d# 128                   constant #ub/label
   #ub/label /uber-block *  constant /ub-ring
   h# 2.0000                constant ubring-off

   : ub_magic      ( ub -- n )          x@  ;
   : ub_txg        ( ub -- n )  h# 10 + x@  ;
   : ub_timestamp  ( ub -- n )  h# 20 + x@  ;
   : ub_rootbp     ( ub -- p )  h# 28 +     ;

   0 instance value uber-block

   : ub-cmp  ( ub1 ub2 -- best-ub )

      \ ub1 wins if ub2 isn't valid
      dup  ub_magic h# 00bab10c  x<>  if
         drop  exit                  ( ub1 )
      then

      \ if ub1 is 0, ub2 wins by default
      over 0=  if  nip  exit  then   ( ub2 )

      \ 2 valid ubs, compare transaction groups
      over ub_txg  over ub_txg       ( ub1 ub2 txg1 txg2 )
      2dup x<  if
         2drop nip  exit             ( ub2 )
      then                           ( ub1 ub2 txg1 txg2 )
      x>  if  drop  exit  then       ( ub1 )

      \ same txg, check timestamps
      over ub_timestamp  over ub_timestamp  x>  if
         nip                         ( ub2 )
      else
         drop                        ( ub1 )
      then
   ;

   \ find best uber-block in ring, and copy it to uber-block
   : get-ub  ( -- )
      temp-space  /ub-ring ubring-off       ( adr len off )
      dev-ih  read-disk                     (  )
      0  temp-space /ub-ring                ( null-ub adr len )
      bounds  do                            ( ub )
         i ub-cmp                           ( best-ub )
      /uber-block +loop

      \ make sure we found a valid ub
      dup 0=  if  " no ub found" die  then

      uber-block /uber-block  move          (  )
   ;


   \
   \	ZFS dnode (DMU) routines
   \

   d# 44  constant ot-sa#

   d# 512 constant /dnode

   : dn_indblkshift   ( dn -- n )  h#   1 +  c@  ;
   : dn_nlevels       ( dn -- n )  h#   2 +  c@  ;
   : dn_bonustype     ( dn -- n )  h#   4 +  c@  ;
   : dn_datablkszsec  ( dn -- n )  h#   8 +  w@  ;
   : dn_bonuslen      ( dn -- n )  h#   a +  w@  ;
   : dn_blkptr        ( dn -- p )  h#  40 +      ;
   : dn_bonus         ( dn -- p )  h#  c0 +      ;
   : dn_spill         ( dn -- p )  h# 180 +      ;

   0 instance value dnode

   \ indirect cache
   \
   \ ind-cache is a 1 block indirect block cache from dnode ic-dn
   \
   \ ic-bp and ic-bplim point into the ic-dn's block ptr array,
   \ either in dn_blkptr or in ind-cache   ic-bp is the ic-blk#'th
   \ block ptr, and ic-bplim is limit of the current bp array
   \
   \ the assumption is that reads will be sequential, so we can
   \ just increment ic-bp
   \
   0 instance value  ind-cache
   0 instance value  ic-dn
   0 instance value  ic-blk#
   0 instance value  ic-bp
   0 instance value  ic-bplim

   : dn-bsize    ( dn -- bsize )    dn_datablkszsec /disk-block  *  ;
   : dn-indsize  ( dn -- indsize )  dn_indblkshift  pow2  ;
   : dn-indmask  ( dn -- mask )     dn-indsize 1-  ;

   \ recursively climb the block tree from the leaf to the root
   : blk@lvl>bp  ( dn blk# lvl -- bp )   tokenizer[ reveal ]tokenizer
      >r  /blkp *  over dn_nlevels         ( dn bp-off #lvls  r: lvl )

      \ at top, just add dn_blkptr
      r@  =  if                            ( dn bp-off  r: lvl )
         swap dn_blkptr  +                 ( bp  r: lvl )
         r> drop  exit                     ( bp )
      then                                 ( dn bp-off  r: lvl )

      \ shift bp-off down and find parent indir blk
      2dup over  dn_indblkshift  rshift    ( dn bp-off dn blk#  r: lvl )
      r> 1+  blk@lvl>bp                    ( dn bp-off bp )

      \ read parent indir blk and index
      rot tuck dn-indsize                  ( bp-off dn bp len )
      ind-cache swap rot  read-bp          ( bp-off dn )
      dn-indmask  and                      ( bp-off' )
      ind-cache +                          ( bp )
   ;

   \ return end of current bp array
   : bplim ( dn bp -- bp-lim )
      over dn_nlevels  1  =  if
          drop dn_blkptr              ( bp0 )
          3 /blkp *  +                ( bplim )
      else
          1+  swap dn-indsize         ( bp+1 indsz )
          roundup                     ( bplim )
      then
   ;

   \ return the lblk#'th block ptr from dnode
   : lblk#>bp  ( dn blk# -- bp )
      2dup                               ( dn blk# dn blk# )
      ic-blk# <>  swap  ic-dn  <>  or    ( dn blk# cache-miss? )
      ic-bp  ic-bplim  =                 ( dn blk# cache-miss? cache-empty? )
      or  if                             ( dn blk# )
         2dup  1 blk@lvl>bp              ( dn blk# bp )
         dup         to ic-bp            ( dn blk# bp )
         swap        to ic-blk#          ( dn bp )
         2dup bplim  to ic-bplim         ( dn bp )
         over        to ic-dn
      then  2drop                        (  )
      ic-blk# 1+          to ic-blk#
      ic-bp dup  /blkp +  to ic-bp       ( bp )
   ;


   \
   \	ZFS attribute (ZAP) routines
   \

   1        constant  fzap#
   3        constant  uzap#

   d# 64    constant  /uzap

   d# 24    constant  /lf-chunk
   d# 21    constant  /lf-arr
   h# ffff  constant  chain-end#

   h# 100   constant /lf-buf
   /lf-buf  instance buffer: leaf-value
   /lf-buf  instance buffer: leaf-name

   : +le              ( len off -- n )  +  w@  ;
   : le_next          ( le -- n )  h# 2 +le  ;
   : le_name_chunk    ( le -- n )  h# 4 +le  ;
   : le_name_length   ( le -- n )  h# 6 +le  ;
   : le_value_chunk   ( le -- n )  h# 8 +le  ;
   : le_value_length  ( le -- n )  h# a +le  ;

   : la_array  ( la -- adr )  1+  ;
   : la_next   ( la -- n )    h# 16 +  w@  ;

   0 instance value zap-space

   \ setup leaf hash bounds
   : >leaf-hash  ( dn lh -- hash-adr /hash )
      /lf-chunk 2*  +                 ( dn hash-adr ) 
      \ size = (bsize / 32) * 2
      swap dn-bsize  4 rshift         ( hash-adr /hash )
   ;
   : >leaf-chunks  ( lf -- ch0 )  >leaf-hash +  ;

   \ convert chunk # to leaf chunk
   : ch#>lc  ( dn ch# -- lc )
      /lf-chunk *                     ( dn lc-off )
      swap zap-space  >leaf-chunks    ( lc-off ch0 )
      +                               ( lc )
   ;

   \ assemble chunk chain into single buffer
   : get-chunk-data  ( dn ch# adr -- )
      dup >r  /lf-buf  erase          ( dn ch#  r: adr )
      begin
         2dup  ch#>lc  nip            ( dn la  r: adr )
         dup la_array                 ( dn la la-arr  r: adr )
         r@  /lf-arr  move            ( dn la  r: adr )
         r>  /lf-arr +  >r            ( dn la  r: adr' )
         la_next  dup chain-end#  =   ( dn la-ch# end?  r: adr )
      until  r> 3drop                 (  )
   ;

   \ get leaf entry's name
   : entry-name$  ( dn le -- name$ )
      2dup le_name_chunk              ( dn le dn la-ch# )
      leaf-name  get-chunk-data       ( dn le )
      nip  le_name_length 1-          ( len )
      leaf-name swap                  ( name$ )
   ;

   \ return entry value as int
   : entry-int-val  ( dn le -- n )
      le_value_chunk                  ( dn la-ch# )
      leaf-value  get-chunk-data      (  )
      leaf-value x@                   ( n )
   ;


[ifdef] strlookup
   \ get leaf entry's value as string
   : entry-val$  ( dn le -- val$ )
      2dup le_value_chunk             ( dn le dn la-ch# )
      leaf-value  get-chunk-data      ( dn le )
      nip le_value_length             ( len )
      leaf-value swap                 ( name$ )
   ;
[then]

   \ apply xt to entry
   : entry-apply  ( xt dn le -- xt dn false  |  ??? true )
      over >r                    ( xt dn le  r: dn )
      rot  dup >r  execute  if   ( ???  r: xt dn )
         r> r>  2drop  true      ( ??? true )
      else                       (  )
         r> r>  false            ( xt dn false )
      then
   ;
         
   \ apply xt to every entry in chain
   : chain-apply  ( xt dn ch# -- xt dn false  |  ??? true )
      begin
         2dup  ch#>lc  nip               ( xt dn le )
         dup >r  entry-apply  if         ( ???  r: le )
            r> drop  true  exit          ( ??? found )
         then                            ( xt dn  r: le )
         r> le_next                      ( xt dn ch# )
         dup chain-end#  =               ( xt dn ch# end? )
      until  drop                        ( xt dn )
      false                              ( xt dn false )
   ;

   \ apply xt to every entry in leaf
   : leaf-apply  ( xt dn blk# -- xt dn false  |  ??? true )

      \ read zap leaf into zap-space
      2dup lblk#>bp                       ( xt dn blk# bp )
      nip  over dn-bsize  zap-space       ( xt dn bp len adr )
      swap rot  read-bp                   ( xt dn )

     \ call chunk-look for every valid chunk list
      dup zap-space  >leaf-hash           ( xt dn hash-adr /hash )
      bounds  do                          ( xt dn )
         i w@  dup chain-end#  <>  if     ( xt dn ch# )
            chain-apply  if               ( ??? )
               unloop  true  exit         ( ??? found )
            then                          ( xt dn )
         else  drop  then                 ( xt dn )
      /w  +loop
      false                               ( xt dn not-found )
   ;

   \ apply xt to every entry in fzap
   : fzap-apply  ( xt dn fz -- ??? not-found? )

      \ blk# 1 is always the 1st leaf
      >r  1 leaf-apply  if              ( ???  r: fz )
         r> drop  true  exit            ( ??? found )
      then  r>                          ( xt dn fz )

      \ call leaf-apply on every non-duplicate hash entry
      \ embedded hash is in 2nd half of fzap block
      over dn-bsize  tuck +             ( xt dn bsize hash-eadr )
      swap 2dup  2/  -                  ( xt dn hash-eadr bsize hash-adr )
      nip  do                           ( xt dn )
         i x@  dup 1  <>  if            ( xt dn blk# )
            leaf-apply  if              ( ??? )
               unloop  true  exit       ( ??? found )
            then                        ( xt dn )
         else  drop  then               ( xt dn )
      /x  +loop
      2drop  false                      ( not-found )
   ;

   : mze_value  ( uz -- n )  x@  ;
   : mze_name   ( uz -- p )  h# e +  ;

   : uzap-name$  ( uz -- name$ )  mze_name  cscount  ;

   \ apply xt to each entry in micro-zap
   : uzap-apply ( xt uz len -- ??? not-found? )
      bounds  do                      ( xt )
         i swap  dup >r               ( uz xt  r: xt )
         execute  if                  ( ???  r: xt )
            r> drop                   ( ??? )
            unloop true  exit         ( ??? found )
         then  r>                     ( xt )
      /uzap  +loop
      drop  false                     ( not-found )
   ;

   \ match by name
   : fz-nmlook  ( prop$ dn le -- prop$ false  |  prop$ dn le true )
      2dup entry-name$        ( prop$ dn le name$ )
      2rot 2swap              ( dn le prop$ name$ )
      2over  $=  if           ( dn le prop$ )
         2swap  true          ( prop$ dn le true )
      else                    ( dn le prop$ )
         2swap 2drop  false   ( prop$ false )
      then                    ( prop$ false  |  prop$ dn le true )
   ;

   \ match by name
   : uz-nmlook  ( prop$ uz -- prop$ false  |  prop$ uz true )
      dup >r  uzap-name$      ( prop$ name$  r: uz )
      2over  $=  if           ( prop$  r: uz )
         r>  true             ( prop$ uz true )
      else                    ( prop$  r: uz )
         r> drop  false       ( prop$ false )
      then                    ( prop$ false  |  prop$ uz true )
   ;

   : zap-type   ( zp -- n )     h#  7 + c@  ;
   : >uzap-ent  ( adr -- ent )  h# 40 +  ;

   \ read zap block into temp-space
   : get-zap  ( dn -- zp )
      dup  0 lblk#>bp    ( dn bp )
      swap dn-bsize      ( bp len )
      temp-space swap    ( bp adr len )
      rot read-bp        (  )
      temp-space         ( zp )
   ;

   \ find prop in zap dnode
   : zap-lookup  ( dn prop$ -- [ n ] not-found? )
      rot  dup get-zap                    ( prop$ dn zp )
      dup zap-type  case
         uzap#  of
            >uzap-ent  swap dn-bsize      ( prop$ uz len )
            ['] uz-nmlook  -rot           ( prop$ xt uz len )
            uzap-apply  if                ( prop$ uz )
               mze_value  -rot 2drop      ( n )
               false                      ( n found )
            else                          ( prop$ )
               2drop  true                ( !found )
            then                          ( [ n ] not-found? )
         endof
         fzap#  of
            ['] fz-nmlook  -rot           ( prop$ xt dn fz )
            fzap-apply  if                ( prop$ dn le )
               entry-int-val              ( prop$ n )
               -rot 2drop  false          ( n found )
            else                          ( prop$ )
               2drop  true                ( !found )
            then                          ( [ n ] not-found? )
         endof
         3drop 2drop  true                ( !found )
      endcase                             ( [ n ] not-found? )
   ;

[ifdef] strlookup
   : zap-lookup-str  ( dn prop$ -- [ val$ ] not-found? )
      rot  dup get-zap                    ( prop$ dn zp )
      dup zap-type  fzap#  <>  if         ( prop$ dn zp )
         2drop 2drop  true  exit          ( !found )
      then                                ( prop$ dn zp )
      ['] fz-nmlook -rot                  ( prop$ xt dn fz )
      fzap-apply  if                      ( prop$ dn le )
         entry-val$  2swap 2drop  false   ( val$ found )
      else                                ( prop$ )
         2drop  true                      ( !found )
      then                                ( [ val$ ] not-found? )
   ;
[then]

   : fz-print  ( dn le -- false )
      entry-name$  type cr  false
   ;

   : uz-print  ( uz -- false )
      uzap-name$  type cr  false
   ;

   : zap-print  ( dn -- )
      dup get-zap                         ( dn zp )
      dup zap-type  case
         uzap#  of
            >uzap-ent  swap dn-bsize      ( uz len )
            ['] uz-print  -rot            ( xt uz len )
            uzap-apply                    ( false )
         endof
         fzap#  of
            ['] fz-print -rot             ( xt dn fz )
            fzap-apply                    ( false )
         endof
         3drop  false                     ( false )
      endcase                             ( false )
      drop                                (  )
   ;


   \
   \	ZFS object set (DSL) routines
   \

   1 constant pool-dir#

   : dd_head_dataset_obj  ( dd -- n )  h#  8 +  x@  ;
   : dd_child_dir_zapobj  ( dd -- n )  h# 20 +  x@  ;

   : ds_snapnames_zapobj  ( ds -- n )  h# 20 +  x@  ;
   : ds_bp                ( ds -- p )  h# 80 +      ;

   0 instance value mos-dn
   0 instance value obj-dir
   0 instance value root-dsl
   0 instance value fs-dn

   \ dn-cache contains dc-dn's contents at dc-blk#
   \ dc-dn will be either mos-dn or fs-dn
   0 instance value dn-cache
   0 instance value dc-dn
   0 instance value dc-blk#

   alias  >dsl-dir  dn_bonus
   alias  >dsl-ds   dn_bonus

   : #dn/blk  ( dn -- n )     dn-bsize /dnode  /  ;

   \ read block into dn-cache
   : get-dnblk  ( dn blk# -- )
      lblk#>bp  dn-cache swap         ( adr bp )
      dup bp-lsize swap  read-bp      (  )
   ;

   \ read obj# from objset dir dn into dnode
   : get-dnode  ( dn obj# -- )

      \ check dn-cache
      2dup  swap #dn/blk  /mod       ( dn obj# off# blk# )
      swap >r  nip                   ( dn blk#  r: off# )
      2dup  dc-blk#  <>              ( dn blk# dn !blk-hit?  r: off# )
      swap dc-dn  <>  or  if         ( dn blk#  r: off# )
         \ cache miss, fill from dir
         2dup  get-dnblk
         over  to dc-dn
         dup   to dc-blk#
      then                           ( dn blk#  r: off# )

      \ index and copy
      2drop r>  /dnode *             ( off )
      dn-cache +                     ( dn-adr )
      dnode  /dnode  move            (  )
   ;

   \ read meta object set from uber-block
   : get-mos  ( -- )
      mos-dn uber-block ub_rootbp    ( adr bp )
      dup bp-lsize swap read-bp
   ;

   : get-mos-dnode  ( obj# -- )
      mos-dn swap  get-dnode
   ;

   \ get root dataset
   : get-root-dsl  ( -- )

      \ read MOS
      get-mos

      \ read object dir
      pool-dir#  get-mos-dnode
      dnode obj-dir  /dnode  move

      \ read root dataset
      obj-dir " root_dataset"  zap-lookup  if
         " no root_dataset"  die
      then                                   ( obj# )
      get-mos-dnode                          (  )
      dnode root-dsl  /dnode  move
   ;

   \ find snapshot of given dataset
   : snap-look  ( snap$ ds-obj# -- [ss-obj# ] not-found? )
      get-mos-dnode  dnode >dsl-ds         ( snap$ ds )
      ds_snapnames_zapobj  get-mos-dnode   ( snap$ )
      dnode -rot  zap-lookup               ( [ss-obj# ] not-found? )
   ;

   \ dsl dir to dataset
   : dir>ds   ( dn -- obj# )  >dsl-dir dd_head_dataset_obj  ;

   \ look thru the dsl hierarchy for path
   \ this looks almost exactly like a FS directory lookup
   : dsl-lookup ( path$ -- [ ds-obj# ] not-found? )
      root-dsl >r                                 ( path$  r: root-dn )
      begin
         ascii /  left-parse-string               ( path$ file$  r: dn )
      dup  while

         \ get child dir zap dnode
         r>  >dsl-dir dd_child_dir_zapobj         ( path$ file$ obj# )
         get-mos-dnode                            ( path$ file$ )

         \ check for snapshot names
         ascii @  left-parse-string               ( path$ snap$ file$ )

         \ search it
         dnode -rot zap-lookup  if                ( path$ snap$ )
            \ not found
            2drop 2drop true  exit                ( not-found )
         then                                     ( path$ snap$ obj# )
         get-mos-dnode                            ( path$ snap$ )

         \ lookup any snapshot name
         dup  if
            \ must be last path component
            2swap  nip  if                        ( snap$ )
               2drop true  exit                   ( not-found )
            then
            dnode dir>ds  snap-look  if           (  )
               true  exit                         ( not-found )
            then                                  ( obj# )
            false  exit                           ( obj# found )
         else  2drop  then                        ( path$ )

         dnode >r                                 ( path$  r: dn )
      repeat                                      ( path$ file$  r: dn)
      2drop 2drop  r> drop                        (  )

      \ found it, return dataset obj#
      dnode  dir>ds                               ( ds-obj# )
      false                                       ( ds-obj# found )
   ;

   \ get objset from dataset
   : get-objset  ( adr dn -- )
      >dsl-ds ds_bp  dup bp-lsize swap  read-bp
   ;


   \
   \	ZFS file-system (ZPL) routines
   \

   1       constant master-node#

   0 instance value bootfs-obj#
   0 instance value root-obj#
   0 instance value current-obj#
   0 instance value search-obj#

   instance defer fsize         ( dn -- size )
   instance defer mode          ( dn -- mode )
   instance defer parent        ( dn -- obj# )
   instance defer readlink      ( dst dn -- )

   \
   \ routines when bonus pool contains a znode
   \
   d# 264  constant /znode
   d#  56  constant /zn-slink

   : zp_mode    ( zn -- n )  h# 48 +  x@  ;
   : zp_size    ( zn -- n )  h# 50 +  x@  ;
   : zp_parent  ( zn -- n )  h# 58 +  x@  ;

   alias  >znode  dn_bonus

   : zn-fsize     ( dn -- n )  >znode zp_size    ;
   : zn-mode      ( dn -- n )  >znode zp_mode    ;
   : zn-parent    ( dn -- n )  >znode zp_parent  ;

   \ copy symlink target to dst
   : zn-readlink  ( dst dn -- )
      dup zn-fsize  tuck /zn-slink  >  if ( dst size dn )
         \ contents in 1st block
         temp-space  over dn-bsize        ( dst size dn t-adr bsize )
         rot  0 lblk#>bp  read-bp         ( dst size )
         temp-space                       ( dst size src )
      else                                ( dst size dn )
         \ contents in dnode
         >znode  /znode +                 ( dst size src )
      then                                ( dst size src )
      -rot  move                          (  )
   ;

   \
   \ routines when bonus pool contains sa's
   \

   \ SA header size when link is in dn_bonus
   d# 16  constant  /sahdr-link

   : sa_props  ( sa -- n )   h# 4 +  w@  ;

   : sa-hdrsz  ( sa -- sz )  sa_props h# 7  >>  ;

   alias  >sa  dn_bonus

   : >sadata    ( dn -- adr )  >sa dup  sa-hdrsz  +  ;
   : sa-mode    ( dn -- n )    >sadata           x@  ;
   : sa-fsize   ( dn -- n )    >sadata  h#  8 +  x@  ;
   : sa-parent  ( dn -- n )    >sadata  h# 28 +  x@  ;

   \ copy symlink target to dst
   : sa-readlink  ( dst dn -- )
      dup  >sa sa-hdrsz  /sahdr-link  <>  if
         \ contents in 1st attr of dn_spill
         temp-space  over dn_spill           ( dst dn t-adr bp )
         dup bp-lsize  swap  read-bp         ( dst dn )
         sa-fsize                            ( dst size )
         temp-space dup sa-hdrsz  +          ( dst size src )
      else                                   ( dst dn )
         \ content in bonus buf
         dup dn_bonus  over  dn_bonuslen  +  ( dst dn ebonus )
         swap sa-fsize  tuck  -              ( dst size src )
      then                                   ( dst size src )
      -rot  move                             (  )
   ;


   \ setup attr routines for dn
   : set-attr  ( dn -- )
      dn_bonustype  ot-sa#  =  if
         ['] sa-fsize     to  fsize
         ['] sa-mode      to  mode
         ['] sa-parent    to  parent
         ['] sa-readlink  to  readlink
      else
         ['] zn-fsize     to  fsize
         ['] zn-mode      to  mode
         ['] zn-parent    to  parent
         ['] zn-readlink  to  readlink
      then
   ;

   : ftype     ( dn -- type )  mode   h# f000  and  ;
   : dir?      ( dn -- flag )  ftype  h# 4000  =  ;
   : symlink?  ( dn -- flag )  ftype  h# a000  =  ;

   \ read obj# from fs objset
   : get-fs-dnode  ( obj# -- )
      dup to current-obj#
      fs-dn swap  get-dnode    (  )
   ;

   \ get root-obj# from dataset
   : get-rootobj#  ( ds-obj# -- fsroot-obj# )
      dup to bootfs-obj#
      get-mos-dnode                   (  )
      fs-dn dnode  get-objset

      \ get root obj# from master node
      master-node#  get-fs-dnode
      dnode  " ROOT"  zap-lookup  if
         " no ROOT"  die
      then                             ( fsroot-obj# )
   ;

   : prop>rootobj#  ( -- )
      obj-dir " pool_props" zap-lookup  if
         " no pool_props"  die
      then                               ( prop-obj# )
      get-mos-dnode                      (  )
      dnode " bootfs" zap-lookup  if
         " no bootfs"  die
      then                               ( ds-obj# )
      get-rootobj#                       ( fsroot-obj# )
   ;

   : fs>rootobj#  ( fs$ -- root-obj# not-found? )

      \ skip pool name
      ascii /  left-parse-string  2drop

      \ lookup fs in dsl 
      dsl-lookup  if                   (  )
         true  exit                    ( not-found )
      then                             ( ds-obj# )

      get-rootobj#                     ( fsroot-obj# )
      false                            ( fsroot-obj# found )
   ;

   \ lookup file is current directory
   : dirlook  ( file$ dn -- not-found? )
      \ . and .. are magic
      -rot  2dup " ."  $=  if     ( dn file$ )
         3drop  false  exit       ( found )
      then

      2dup " .."  $=  if
         2drop  parent            ( obj# )
      else                        ( dn file$ )
         \ search dir
         current-obj# to search-obj#
         zap-lookup  if           (  )
            true  exit            ( not-found )
         then                     ( obj# )
      then                        ( obj# )
      get-fs-dnode
      dnode  set-attr
      false                       ( found )
   ;

   /buf-len  instance buffer: fpath-buf
   /buf-len  instance buffer: tpath-buf

   : tpath-buf$  ( -- path$ )  tpath-buf cscount  ;
   : fpath-buf$  ( -- path$ )  fpath-buf cscount  ;

   \ modify tail to account for symlink
   : follow-symlink  ( tail$ -- tail$' )
      \ read target
      tpath-buf /buf-len  erase
      tpath-buf dnode  readlink

      \ append current path
      ?dup  if                                  ( tail$ )
	 " /" tpath-buf$  $append               ( tail$ )
	 tpath-buf$  $append                    (  )
      else  drop  then                          (  )

      \ copy to fpath
      fpath-buf  /buf-len  erase
      tpath-buf$  fpath-buf  swap move
      fpath-buf$                                ( path$ )

      \ get directory that starts changed path
      over c@  ascii /  =  if                   ( path$ )
	 str++  root-obj#                       ( path$' obj# )
      else                                      ( path$ )
         search-obj#                            ( path$ obj# )
      then                                      ( path$ obj# )
      get-fs-dnode                              ( path$ )
      dnode  set-attr
   ;

   \ open dnode at path
   : lookup  ( path$ -- not-found? )

      \ get directory that starts path
      over c@  ascii /  =  if
         str++  root-obj#                         ( path$' obj# )
      else
         current-obj#                             ( path$ obj# )
      then                                        ( path$ obj# )
      get-fs-dnode                                ( path$ )
      dnode  set-attr

      \ lookup each path component
      begin                                       ( path$ )
         ascii /  left-parse-string               ( path$ file$ )
      dup  while
         dnode dir?  0=  if
            2drop true  exit                      ( not-found )
         then                                     ( path$ file$ )
         dnode dirlook  if                        ( path$ )
            2drop true  exit                      ( not-found )
         then                                     ( path$ )
         dnode symlink?  if
            follow-symlink                        ( path$' )
         then                                     ( path$ )
      repeat                                      ( path$ file$ )
      2drop 2drop  false                          ( found )
   ;

   \
   \   ZFS volume (ZVOL) routines
   \
   1 constant  zvol-data#
   2 constant  zvol-prop#

   0 instance value zv-dn

   : get-zvol  ( zvol$ -- not-found? )
      dsl-lookup  if
         drop true  exit           ( failed )
      then                         ( ds-obj# )

      \ get zvol objset
      get-mos-dnode                (  )
      zv-dn dnode  get-objset
      false                        ( succeeded )
   ;

   \ get zvol data dnode
   : zvol-data  ( -- )
      zv-dn zvol-data#  get-dnode
   ;

   : zvol-size  ( -- size )
       zv-dn zvol-prop#   get-dnode
       dnode " size"  zap-lookup  if
          " no zvol size"  die
       then                            ( size )
   ;
       

   \
   \	ZFS installation routines
   \

   \ ZFS file interface
   struct
      /x     field >busy
      /x     field >offset
      /x     field >fsize
      /dnode field >dnode
   constant /file-record

   d# 10                  constant #opens
   #opens /file-record *  constant /file-records

   /file-records  instance buffer: file-records

   -1 instance value current-fd

   : fd>record     ( fd -- rec )  /file-record *  file-records +  ;
   : file-offset@  ( -- off )     current-fd fd>record >offset  x@  ;
   : file-offset!  ( off -- )     current-fd fd>record >offset  x!  ;
   : file-dnode    ( -- dn )      current-fd fd>record >dnode  ;
   : file-size     ( -- size )    current-fd fd>record >fsize  x@  ;
   : file-bsize    ( -- bsize )   file-dnode  dn-bsize  ;

   \ find free fd slot
   : get-slot  ( -- fd false | true )
      #opens 0  do
         i fd>record >busy x@  0=  if
            i false  unloop exit
         then
      loop  true
   ;

   : free-slot  ( fd -- )
      0 swap  fd>record >busy  x!
   ;

   \ init fd to offset 0 and copy dnode
   : init-fd  ( fsize fd -- )
      fd>record                ( fsize rec )
      dup  >busy  1 swap  x!
      dup  >dnode  dnode swap  /dnode  move
      dup  >fsize  rot swap  x!     ( rec )
      >offset  0 swap  x!      (  )
   ;

   \ make fd current
   : set-fd  ( fd -- error? )
      dup fd>record  >busy x@  0=  if   ( fd )
         drop true  exit                ( failed )
      then                              ( fd )
      to current-fd  false              ( succeeded )
   ;

   \ read next fs block
   : file-bread  ( adr -- )
      file-bsize                      ( adr len )
      file-offset@ over  /            ( adr len blk# )
      file-dnode swap  lblk#>bp       ( adr len bp )
      read-bp                         ( )
   ;

   \ advance file io stack by n
   : fio+  ( # adr len n -- #+n adr+n len-n )
      dup file-offset@ +  file-offset!
      dup >r  -  -rot   ( len' # adr  r: n )
      r@  +  -rot       ( adr' len' #  r: n )
      r>  +  -rot       ( #' adr' len' )
   ;


   /max-bsize    5 *
   /uber-block        +
   /dnode        6 *  +
   /disk-block   6 *  +    ( size )
   \ ugh - sg proms can't free 512k allocations
   \ that aren't a multiple of 512k in size
   h# 8.0000  roundup      ( size' )
   constant  alloc-size


   : allocate-buffers  ( -- )
      alloc-size h# a0.0000 vmem-alloc  dup 0=  if
         " no memory"  die
      then                                ( adr )
      dup to temp-space    /max-bsize  +  ( adr )
      dup to dn-cache      /max-bsize  +  ( adr )
      dup to blk-space     /max-bsize  +  ( adr )
      dup to ind-cache     /max-bsize  +  ( adr )
      dup to zap-space     /max-bsize  +  ( adr )
      dup to uber-block    /uber-block +  ( adr )
      dup to mos-dn        /dnode      +  ( adr )
      dup to obj-dir       /dnode      +  ( adr )
      dup to root-dsl      /dnode      +  ( adr )
      dup to fs-dn         /dnode      +  ( adr )
      dup to zv-dn         /dnode      +  ( adr )
      dup to dnode         /dnode      +  ( adr )
          to gang-space                   (  )

      \ zero instance buffers
      file-records /file-records  erase
      bootprop-buf /buf-len  erase
   ;

   : release-buffers  ( -- )
      temp-space  alloc-size  mem-free
   ;

   external

   : open ( -- okay? )
      my-args dev-open  dup 0=  if
         exit                       ( failed )
      then  to dev-ih

      allocate-buffers
      scan-vdev
      get-ub
      get-root-dsl
      true
   ;

   : open-fs  ( fs$ -- okay? )
      fs>rootobj#  if        (  )
         false               ( failed )
      else                   ( obj# )
         to root-obj#  true  ( succeeded )
      then                   ( okay? )
   ;

   : close  ( -- )
      dev-ih dev-close
      0 to dev-ih
      release-buffers
   ;

   : open-file  ( path$ -- fd true | false )

      \ open default fs if no open-fs
      root-obj# 0=  if
         prop>rootobj#  to root-obj#
      then

      get-slot  if
         2drop false  exit         ( failed )
      then  -rot                   ( fd path$ )

      lookup  if                   ( fd )
         drop false  exit          ( failed )
      then                         ( fd )

      dnode fsize  over init-fd
      true                         ( fd succeeded )
   ;

   : open-volume ( vol$ -- okay? )
      get-slot  if
         2drop false  exit         ( failed )
      then  -rot                   ( fd vol$ )

      get-zvol  if                 ( fd )
         drop false  exit          ( failed )
      then

      zvol-size over               ( fd size fd )
      zvol-data init-fd            ( fd )
      true                         ( fd succeeded )
   ;
      
   : close-file  ( fd -- )
      free-slot   (  )
   ;

   : size-file  ( fd -- size )
      set-fd  if  0  else  file-size  then
   ;

   : seek-file  ( off fd -- off true | false )
      set-fd  if                ( off )
         drop false  exit       ( failed )
      then                      ( off )

      dup file-size x>  if      ( off )
         drop false  exit       ( failed )
      then                      ( off )
      dup  file-offset!  true   ( off succeeded )
   ;

   : read-file  ( adr len fd -- #read )
      set-fd  if                   ( adr len )
         2drop 0  exit             ( 0 )
      then                         ( adr len )

      \ adjust len if reading past eof
      dup  file-offset@ +  file-size  x>  if
         dup  file-offset@ +  file-size -  -
      then
      dup 0=  if  nip exit  then

      0 -rot                              ( #read adr len )

      \ initial partial block
      file-offset@ file-bsize  mod  ?dup  if  ( #read adr len off )
         temp-space  file-bread
         2dup  file-bsize  swap -  min    ( #read adr len off cpy-len )
         2over drop -rot                  ( #read adr len adr off cpy-len )
         >r  temp-space +  swap           ( #read adr len cpy-src adr  r: cpy-len )
         r@  move  r> fio+                ( #read' adr' len' )
      then                                ( #read adr len )

      dup file-bsize /  0  ?do            ( #read adr len )
         over  file-bread
         file-bsize fio+                  ( #read' adr' len' )
      loop                                ( #read adr len )

      \ final partial block
      dup  if                             ( #read adr len )
         temp-space  file-bread
         2dup temp-space -rot  move       ( #read adr len )
         dup fio+                         ( #read' adr' 0 )
      then  2drop                         ( #read )
   ;

   : cinfo-file  ( fd -- bsize fsize comp? )
      set-fd  if
         0 0 0
      else
         file-bsize  file-size             ( bsize fsize )
         \ zfs does internal compression
         0                                 ( bsize fsize comp? )
      then
   ;

   \ read ramdisk fcode at rd-offset
   : get-rd   ( adr len -- )
      rd-offset dev-ih  read-disk
   ;

   : bootprop
      " /"  bootprop$  $append
      bootfs-obj# (xu.)  bootprop$  $append
      bootprop$  encode-string  " zfs-bootfs"   ( propval propname )
      true
   ;


   : chdir  ( dir$ -- )
      current-obj# -rot            ( obj# dir$ )
      lookup  if                   ( obj# )
         to current-obj#           (  )
         ." no such dir" cr  exit
      then                         ( obj# )
      dnode dir?  0=  if           ( obj# )
         to current-obj#           (  )
         ." not a dir" cr  exit
      then  drop                   (  )
   ;

   : dir  ( -- )
      current-obj# get-fs-dnode
      dnode zap-print
   ;

finish-device
pop-package
