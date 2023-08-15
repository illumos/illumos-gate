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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/scsi/scsi.h>
#include <sys/mtio.h>
#include <sys/condvar.h>
#include <sys/kstat.h>
#include <sys/scsi/targets/stdef.h>

const char st_conf_version[] = "st_conf.c 1.92 08/10/17";
/*
 * General
 * -------
 * o MT_DENSITYx counts from 1..4, rather than 0..3.
 * o Some entries specify a value for the 'length' member that is
 *   less than the actual length of the 'vid' member. This is done
 *   intentionally to allow the comparison to succeed for different
 *   drives.
 */

/*
 * Drive Tables.
 *
 * The structure and option definitions can be
 * found in <sys/scsi/targets/stdef.h>.
 *
 * Note: that blocksize should be a power of two
 * for fixed-length recording devices.
 *
 * Note: the speed codes are unused at present.
 * The driver turns around whatever is reported
 * from the drive via the mode sense.
 *
 * Note: the read retry and write retry counts
 * are there to provide a limit until warning
 * messages are printed.
 *
 *
 * Note: For drives that are not in this table....
 *
 * The first open of the device will cause a MODE SENSE command
 * to be sent. From that we can determine block size. If block
 * size is zero, than this drive is in variable-record length
 * mode. The driver uses the SCSI-2 specification density codes in
 * order to attempt to determine what kind of sequential access
 * device this is. This will allow determination of 1/4" cartridge,
 * 1/2" cartridge, some helical scan (3.81 && 8 mm cartridge) and
 * 1/2" reel tape devices. The driver will print what it finds and is
 * assuming to the console. If the device you have hooked up returns
 * the default density code (0) after power up, the drive cannot
 * determine what kind of drive it might be, so it will assume that
 * it is an unknown 1/4" cartridge tape (QIC).
 *
 * If the drive is determined in this way to be a 1/2" 9-track reel
 * type device, an attempt will be mode to put it in Variable
 * record length mode.
 *
 * Generic drives are assumed to support only the long erase option
 * and will not to be run in buffered mode.
 */

/*
 * Format for Tape Drive Entry
 *
 * Please maintain the format currently in use for defining the properties
 * associated with each tape drive. This format is intended to make the
 * entries more readable and help increase the accuracy of the entries.
 * See the actual entries for examples of what they should look like.
 *
 * Important points to note about the format:
 *
 * 1. The opening and closing braces are indented 2 spaces.
 * 2. Each line in the entry is indented 4 spaces.
 * 3. The numerical values and text in the .options comments are indented two
 *    spaces in the comment block.
 * 4. The maximum line width is 80 columns; do not exceed this.
 * 5. The comment delimiters should line up, per the example.
 * 6. The OR symbol (|) should line up for multiple options.
 * 7. Hexadecimal values should be capitalized, for consistency.
 * 8. The leading / in the comment block header is indented 2 spaces and the
 *    susequent *'s should all line up.
 * 9. Order of the entries is very important. There are several groups of
 *    entries where the last entry in the grouping acts as a catch-all. If you
 *    place an entry after the catch-all, it will never be used by the driver.
 * 10. TABs should not be used anywhere between the BEGIN CSTYLED and
 *    END CSTYLED lines.
 */

/*
 * Supported Drive Options
 *
 * The descriptions for the supported drive options are taken from stdef.h.
 *
 * ST_VARIABLE                          Device supports variable length record
 *                                      sizes.
 * ST_QIC                               QIC tape device.
 * ST_REEL                              1/2-inch reel tape device.
 * ST_BSF                               Device supports backspace file as in
 *                                      mt(1) bsf backspace over EOF marks.
 *                                      Devices not supporting bsf will fail
 *                                      with ENOTTY upon use of bsf.
 * ST_BSR                               Device supports backspace record as in
 *                                      mt(1) bsr : backspace over records. If
 *                                      the device does not support bsr, the st
 *                                      driver emulates the action by rewinding
 *                                      the tape and using forward space file
 *                                      (fsf) to the correct file and then uses
 *                                      forward space record (fsr) to the
 *                                      correct record.
 * ST_LONG_ERASE                        Device needs a longer time than normal
 *                                      to erase.
 * ST_AUTODEN_OVERRIDE                  Autodensity override flag Device can
 *                                      figure out the tape density
 *                                      automatically,without issuing a mode-
 *                                      select/mode-sense.
 * ST_NOBUF                             Don't use buffered mode. This disables
 *                                      the device's ability for buffered writes
 *                                      i.e. The device acknowledges write
 *                                      completion after the data is written to
 *                                      the device's buffer, but before all the
 *                                      data is actually written to tape.
 * ST_RESERVED_BIT1                     Reserved bit parity while talking to it.
 * ST_KNOWS_EOD                         Device knows when EOD (End of Data) has
 *                                      been reached. If the device knows EOD,
 *                                      st uses fast file skipping. If it does
 *                                      not know EOD, file skipping happens one
 *                                      file at a time.
 * ST_UNLOADABLE                        Device will not complain if the st
 *                                      driver is unloaded & loaded again;
 *                                      e.g. will return the correct inquiry
 *                                      string.
 * ST_SOFT_ERROR_REPORTING              Do request or log sense on close to
 *                                      report soft errors.Currently only
 *                                      Exabyte and DAT drives support this
 *                                      feature.
 * ST_LONG_TIMEOUTS                     Device needs 5 times longer timeouts
 *                                      for normal operation.
 * ST_BUFFERED_WRITES                   The data is buffered in the driver and
 *                                      pre-acked to the application.
 * ST_NO_RECSIZE_LIMIT                  For variable record size devices only.
 *                                      If flag is set,then don't limit record
 *                                      size to 64k as in pre-Solaris 2.4
 *                                      releases. The only limit on the record
 *                                      size will be the max record size the
 *                                      device can handle or the max DMA
 *                                      transfer size of the machine, which ever
 *                                      is smaller. Beware of incompatabilities
 *                                      with tapes of pre-Solaris 2.4 OS's
 *                                      written with large (>64k) block sizes,
 *                                      as their true block size is a max of
 *                                      approx 64k.
 * ST_MODE_SEL_COMP                     Use mode select of device configuration
 *                                      page (0x10) to enable/disable
 *                                      compression instead of density codes
 *                                      for the "c" and "u" devices.
 * ST_NO_RESERVE_RELEASE                For devices which do not support
 *                                      RESERVE/RELEASE SCSI command. If this
 *                                      is enabled then RESERVE/RELEASE would
 *                                      not be used during open/close for High
 *                                      Availability.
 * ST_READ_IGNORE_ILI                   This flag is only applicable to
 *                                      variable block devices which support
 *                                      the SILI bit option. It indicates that
 *                                      the SILI bit will be ignored during
 *                                      reads.
 * ST_READ_IGNORE_EOFS                  When this flag is set two EOF marks do
 *                                      not indicate an EOM. This option is
 *                                      only supported on 1/2" reel tapes.
 * ST_SHORT_FILEMARKS                   This option applies only to EXABYTE 8mm
 *                                      tape drives which support short
 *                                      filemarks. When this flag is set, short
 *                                      filemarks will be used for writing
 *                                      filemarks.
 * ST_EJECT_ON_CHANGER_FAILURE          When this flag is set and the tape is
 *                                      trapped in the medium changer, the
 *                                      tape is automatically ejected.
 * ST_RETRY_ON_RECOVERED_DEFERRED_ERROR This option applies only to IBM MAGSTAR
 *                                      3590. If this flag is set, the st
 *                                      driver will retry the last cmd if the
 *                                      last error cause a check condition with
 *                                      error code 0x71 and sense code 0x01.
 */

/*
 * Values Corresponding To The Supported Drive Options Flags
 *
 * ST_VARIABLE                            0x000001
 * ST_QIC                                 0x000002
 * ST_REEL                                0x000004
 * ST_BSF                                 0x000008
 * ST_BSR                                 0x000010
 * ST_LONG_ERASE                          0x000020
 * ST_AUTODEN_OVERRIDE                    0x000040
 * ST_NOBUF                               0x000080
 * ST_RESERVED_BIT1                       0x000100
 * ST_KNOWS_EOD                           0x000200
 * ST_UNLOADABLE                          0x000400
 * ST_SOFT_ERROR_REPORTING                0x000800
 * ST_LONG_TIMEOUT                        0x001000
 * ST_BUFFERED_WRITES                     0x004000
 * ST_NO_RECSIZE_LIMIT                    0x008000
 * ST_MODE_SEL_COMP                       0x010000
 * ST_NO_RESERVE_RELEASE                  0x020000
 * ST_READ_IGNORE_ILI                     0x040000
 * ST_READ_IGNORE_EOFS                    0x080000
 * ST_SHORT_FILEMARKS                     0x100000
 * ST_EJECT_ON_CHANGER_FAILURE            0x200000
 * ST_RETRY_ON_RECOVERED_DEFERRED_ERROR   0x400000
 */

const struct st_drivetype st_drivetypes[] =
{
	/* BEGIN CSTYLED */
  /*
   * Anritsu 1/2" reel
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The Anritsu 1/2" reel has two density codes (or 0 for "default").
   * [2] The Anritsu 1/2" reel has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Unisys 1/2\" Reel",      /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "ANRITSU DMT2120",        /* .vid             Vendor-product ID string    */
    ST_TYPE_ANRITSU,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE  |            /*    00001           Supports variable length  */
    ST_REEL      |            /*    00004           1/2-inch reel tape device */
    ST_BSF       |            /*    00008           Supports SPACE block fwd  */
    ST_BSR       |            /*    00010           Supports SPACE block rev  */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0041D                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x02, 0x03, 0x03}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Archive QIC-150 1/4" cartridge
   *
   *     NOTES
   *     -----
   *  o The manual for the Archive drive claims that this drive
   *    can backspace filemarks. In practice this doens't always
   *    seem to be the case.
   * [1] The QIC-150 uses 0 or "default" density.
   * [2] The QIC-150 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Archive QIC-150",        /* .name            Display ("pretty") name     */
    13,                       /* .length          Length of next item...      */
    "ARCHIVE VIPER",          /* .vid             Vendor-product ID string    */
    ST_TYPE_ARCHIVE,          /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC              |     /*    00002           QIC tape device           */
    ST_AUTODEN_OVERRIDE |     /*    00040           Autodensity override flag */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00642                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Archive Python 04106 4mm 2GB drive
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The Python 04106 has only one density, 0x42 (or 0 for "default").
   * [2] The Python 04106 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] The manufacturer recommends 0x2c ("MT_ISPYTHON") here,
   *     even though ST_TYPE_PYTHON is recommended.  For con-
   *     sistency, let's not fight it.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Seagate Scorpion 24 DDS3 DAT",
                              /* .name            Display ("pretty") name     */
    20,                       /* .length          Length of next item...      */
    "ARCHIVE Python 04106",   /* .vid             Vendor-product ID string    */
    MT_ISPYTHON,              /* .type            Numeric type  [Note 4]      */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE        |      /*    00001           Supports variable length  */
    ST_BSF             |      /*    00008           Supports SPACE block fwd  */
    ST_BSR             |      /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE      |      /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD       |      /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE      |      /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS   |      /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    09639                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x8C, 0x8C, 0x8C}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY3,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Archive/Conner CTDX004 4mm DAT
   *
   *     NOTES
   *     -----
   * [1] The CTDX004 uses 0 or the "default" density code.
   * [2] The CTDX004 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] Data is buffered in the driver and pre-acked to the application. This
   *     is only supported in 2.5.1.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Archive/Conner CTDX004 4mm DAT",
                              /* .name            Display ("pretty") name     */
    20,                       /* .length          Length of next item...      */
    "ARCHIVE Python 28388",   /* .vid             Vendor-product ID string    */
    ST_TYPE_PYTHON,           /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE             | /*    00001           Supports variable length  */
    ST_BSF                  | /*    00008           Supports SPACE block fwd  */
    ST_BSR                  | /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE           | /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD            | /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE           | /*    00400           Driver can be unloaded    */
    ST_SOFT_ERROR_REPORTING | /*    00800           Reports errors on close   */
    ST_LONG_TIMEOUTS        | /*    01000           More time for some ops    */
    ST_BUFFERED_WRITES      | /*    04000           [Note 4]                  */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    0DE39                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY1,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Archive Python 4mm 2GB drive
   *
   *     NOTES
   *     -----
   *  o This must be the last entry in the list of Python drives, since it
   *    acts as a catch-all for any Python drive not listed above.
   *
   * [1] The Archive Python 4mm has only one density, 0x8c (or 0 for "default").
   * [2] The Archive Python 4mm has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] Do a request or log sense on close to report soft errors.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Archive Python 4mm Helical Scan",
                              /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "ARCHIVE Python",         /* .vid             Vendor-product ID string    */
    ST_TYPE_PYTHON,           /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE             | /*    00001           Supports variable length  */
    ST_BSF                  | /*    00008           Supports SPACE block fwd  */
    ST_BSR                  | /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE           | /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD            | /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE           | /*    00400           Driver can be unloaded    */
    ST_SOFT_ERROR_REPORTING | /*    00800           Error reporting [Note 4]  */
    ST_LONG_TIMEOUTS        | /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    09E39                                     */
    5000,                     /* .max_rretries    [Note 3]                    */
    5000,                     /* .max_wretries    [Note 3]                    */
    {0x00, 0x8C, 0x8C, 0x8C}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Benchmark DLT1
   *
   *     NOTES
   *     -----
   * [1] The DLT1 reads several tape formats, but the st driver supports
   *     only DLT1 native.
   * [2] The DLT1 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] The DLT1 has Density codes that turn on and off compression however
   *     the data compression enable overrides them.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Benchmark DLT1",         /* .name            Display ("pretty") name     */
    12,                       /* .length          Length of next item...      */
    "BNCHMARKDLT1",           /* .vid             Vendor-product ID string    */
    ST_TYPE_BMDLT1,           /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE       |     /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS    |     /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           [Note 4]                  */
                              /*    -----                                     */
                              /*    19639                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x40, 0x40, 0x40, 0x40}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },



  /*
   * CDC 1/2" cartridge
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The CDC 1/2" cartridge uses 0 or the "default" density code.
   * [2] The CDC 1/2" cartridge has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "CDC 1/2\" Cartridge",    /* .name            Display ("pretty") name     */
    3,                        /* .length          Length of next item...      */
    "LMS",                    /* .vid             Vendor-product ID string    */
    ST_TYPE_CDC,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_QIC              |     /*    0x002           QIC tape device           */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_LONG_ERASE       |     /*    00020           Needs extra time to erase */
    ST_AUTODEN_OVERRIDE |     /*    00040           Autodensity override flag */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0066B                                     */
    300,                      /* .max_rretries    [Note 3]                    */
    300,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

   /*
   * Emulex MT-02 controller for 1/4" cartridge
   *
   *     NOTES
   *     -----
   *  o The EMULEX MT-02 adheres to CCS level 0, and thus
   *    returns nothing of interest for the INQUIRY command
   *    past the 'response data format' field (which will be
   *    zero). The driver will recognize this and assume that
   *    a drive that so responds is actually an MT-02 (there
   *    is no other way to really do this, awkward as it
   *    may seem).
   *
   *  o This is an unsupported drive.
   *
   * [1] Low density is a vendor unique density code.
   *     This gives us 9 Track QIC-11. Supposedly the MT02 can
   *     read 4 Track QIC-11 while in this mode. If that doesn't
   *     work, change one of the duplicated QIC-24 fields to 0x4.
   * [2] The MT-02 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Emulex MT02 QIC-11/QIC-24",
                              /* .name            Display ("pretty") name     */
    12,                       /* .length          Length of next item...      */
    "Emulex  MT02",           /* .vid             Vendor-product ID string    */
    ST_TYPE_EMULEX,           /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC       |            /*    00002           QIC tape device           */
    ST_KNOWS_EOD |            /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00602                                     */
    130,                      /* .max_rretries    [Note 3]                    */
    130,                      /* .max_wretries    [Note 3]                    */
    {0x84, 0x05, 0x05, 0x05}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Exabyte 8900 8mm helical scan drive (also called Mammoth)
   *
   *     NOTES
   *     -----
   * [1] Compression on the 8900 is controlled via the Device Configuration mode
   *     page or the Data Compression page (either one). Even when enabled, the
   *     8900 automatically disables compression on-the-fly if it determines
   *     that it cannot achieve a reasonable compression ratio on the data.
   * [2] The 8900 can write in only one format, which is selected overtly by
   *     setting Density Code in the block descriptor to 27h; in addition to
   *     this native format, the 8900 can read tapes written in 8200, 8500 and
   *     8500-compressed formats. We set the density to 27h at all times: we
   *     _can_ do this because the format is changed automatically to match the
   *     data on any previously-written tape; we _must_ do this to ensure that
   *     never-before-written 8900 AME tapes are written in "8900 format" (all
   *     writes to them in any other format will fail). By establishing
   *     MT_DENSITY4 (corresponding to the "c" and "u" minor devices) as the
   *     default, applications which open '/dev/rmt/x' write compressed data
   *     automatically (but see Note [1]).
   * [3] The 8900 has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Mammoth EXB-8900 8mm Helical Scan",
                              /* .name            Display ("pretty") name     */
    16,                       /* .length          Length of next item...      */
    "EXABYTE EXB-8900",       /* .vid             Vendor-product ID string    */
    ST_TYPE_EXB8500,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE             | /*    00001           Supports variable length  */
    ST_BSF                  | /*    00008           Supports SPACE block fwd  */
    ST_BSR                  | /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE           | /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD            | /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE           | /*    00400           Driver can be unloaded    */
    ST_SOFT_ERROR_REPORTING | /*    00800           Reports errors on close   */
    ST_LONG_TIMEOUTS        | /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT     | /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           [Note 1]                  */
                              /*    -----                                     */
                              /*    19E39                                     */
    5000,                     /* .max_rretries    [Note 4]                    */
    5000,                     /* .max_wretries    [Note 4]                    */
    {0x27, 0x27, 0x27, 0x27}, /* .densities       Density codes [Note 2]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 3]        */
  },

  /*
   * Exabyte 8mm 5GB cartridge
   *
   *     NOTES
   *     -----
   *  o  ST_KNOWS_EOD here will cause medium error messages
   *
   *  o  The string length (16) has been reduced to 15 to allow for other
   *     compatible models (eg the 8505 half-height)  (BugTraq #1091196)
   *
   * [1] The density code entry requires four values, even if there are less
   *     than four values for the drive.
   * [2] The Exabyte EXB-8500 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Exabyte EXB-8500 8mm Helical Scan",
                              /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "EXABYTE EXB-850*",       /* .vid             Vendor-product ID string    */
    ST_TYPE_EXB8500,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE             | /*    00001           Supports variable length  */
    ST_BSF                  | /*    00008           Supports SPACE block fwd  */
    ST_BSR                  | /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE           | /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD            | /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE           | /*    00400           Driver can be unloaded    */
    ST_SOFT_ERROR_REPORTING | /*    00800           Reports errors on close   */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    08E39                                     */
    5000,                     /* .max_rretries    [Note 3]                    */
    5000,                     /* .max_wretries    [Note 3]                    */
    {0x14, 0x15, 0x8C, 0x8C}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Exabyte 8mm 2GB cartridge
   *
   *     NOTES
   *     -----
   * [1] The Exabyte EXB-8200 uses 0 or the "default" density code.
   * [2] The Exabyte EXB-8200 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] Do a request or log sense on close to report soft errors.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Exabyte EXB-8200 8mm Helical Scan",
                              /* .name            Display ("pretty") name     */
    16,                       /* .length          Length of next item...      */
    "EXABYTE EXB-8200",       /* .vid             Vendor-product ID string    */
    ST_TYPE_EXABYTE,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE             | /*    00001           Supports variable length  */
    ST_BSF                  | /*    00008           Supports SPACE block fwd  */
    ST_BSR                  | /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE           | /*    00020           Needs extra time to erase */
    ST_AUTODEN_OVERRIDE     | /*    00040           Autodensity override flag */
    ST_UNLOADABLE           | /*    00400           Driver can be unloaded    */
    ST_SOFT_ERROR_REPORTING | /*    00800           Error reporting [Note 4]  */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    08C79                                     */
    5000,                     /* .max_rretries    [Note 3]                    */
    5000,                     /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Exabyte DC-2000 cartridge
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   *  o This entry uses a shortened Vendor-product ID string for the
   *    INQUIRY match.
   *
   * [1] The Exabyte DC-2000 uses 0 or the "default" density.
   * [2] The Exabyte DC-2000 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Exabyte EXB-2501 QIC",   /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "EXABYTE EXB-25**",       /* .vid             Vendor-product ID string    */
    ST_TYPE_EXABYTE,          /* .type            Numeric type (cf. mtio.h)   */
    1024,                     /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC              |     /*    00002           QIC tape device           */
    ST_AUTODEN_OVERRIDE |     /*    00040           Autodensity override flag */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00442                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * EXABYTE 4mm Helical Scan
   *
   *     NOTES
   *     -----
   *
   *  o This entry uses a shortened Vendor-product ID string for the
   *    INQUIRY match.
   *
   * [1] The EXABYTE 4mm uses 0 or the "default" density code.
   * [2] The EXABYTE 4mm has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Exabyte 4mm Helical Scan",
                              /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "EXABYTE EXB-420*",       /* .vid             Vendor-product ID string    */
    ST_TYPE_EXABYTE,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE   |           /*    00001           Supports variable length  */
    ST_BSF        |           /*    00008           Supports SPACE block fwd  */
    ST_BSR        |           /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE |           /*    00020           Needs extra time to erase */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00439                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Fujitsu 1/2" cartridge
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The Fujitsu 1/2" drive uses 0 or the "default" density code.
   * [2] The Fujitsu 1/2" drive has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Fujitsu 1/2\" Cartridge",/* .name            Display ("pretty") name     */
    2,                        /* .length          Length of next item...      */
    "\076\000",               /* .vid             Vendor-product ID string    */
    ST_TYPE_FUJI,             /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE   |           /*    00001           Supports variable length  */
    ST_QIC        |           /*    00002           QIC tape device           */
    ST_BSF        |           /*    00008           Supports SPACE block fwd  */
    ST_BSR        |           /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE |           /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD  |           /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0063B                                     */
    300,                      /* .max_rretries    [Note 3]                    */
    300,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * HP 1/2" reel
   *
   *     NOTES
   *     -----
   * [1] The HP 1/2" reel uses the vendor unique density '0xC3':
   *     this is compressed 6250 mode. Beware that using large
   *     data sets consisting of repeated data compresses *too*
   *     well and one can run into the unix 2 gb file offset limit
   *     this way.
   * [2] The HP 1/2" reel has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP-88780 1/2\" Reel",    /* .name            Display ("pretty") name     */
    13,                       /* .length          Length of next item...      */
    "HP      88780",          /* .vid             Vendor-product ID string    */
    ST_TYPE_HP,               /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE  |            /*    00001           Supports variable length  */
    ST_REEL      |            /*    00004           1/2-inch reel tape device */
    ST_BSF       |            /*    00008           Supports SPACE block fwd  */
    ST_BSR       |            /*    00010           Supports SPACE block rev  */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0041D                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x01, 0x02, 0x03, 0xC3}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * HP 35470A 4mm DAT
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The HP 35470A uses 0 or the "default" density code.
   * [2] The HP 35470A has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP 35470A 4mm DAT",      /* .name            Display ("pretty") name     */
    16,                       /* .length          Length of next item...      */
    "HP      HP35470A",       /* .vid             Vendor-product ID string    */
    ST_TYPE_DAT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE       |     /*    00020           Needs extra time to erase */
    ST_AUTODEN_OVERRIDE |     /*    00040           Autodensity override flag */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS,         /*    01000           More time for some ops    */
                              /*    -----                                     */
                              /*    01679                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * HP 35480A 4mm DAT
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The HP 35480A uses 0 or the "default" density code.
   * [2] The HP 35480A has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP 35480A 4mm DAT",      /* .name            Display ("pretty") name     */
    16,                       /* .length          Length of next item...      */
    "HP      HP35480A",       /* .vid             Vendor-product ID string    */
    ST_TYPE_DAT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE   |           /*    00001           Supports variable length  */
    ST_BSF        |           /*    00008           Supports SPACE block fwd  */
    ST_BSR        |           /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE |           /*    00020           Needs extra time to erase */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00439                                     */
    400,                      /* .max_rretries    [Note 1]                    */
    400,                      /* .max_wretries    [Note 1]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 2]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 3]        */
  },

  /*
   * HP JetStore 6000 C1533
   *
   *     NOTES
   *     -----
   *  o This is only supported for x86.
   *
   * [1] The HP JetStore 6000 uses 0 or the "default" density code.
   * [2] The HP JetStore 6000 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP JetStore 6000 C1533", /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "HP      C1533A",         /* .vid             Vendor-product ID string    */
    ST_TYPE_DAT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE   |           /*    00001           Supports variable length  */
    ST_BSF        |           /*    00008           Supports SPACE block fwd  */
    ST_BSR        |           /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE |           /*    00020           Needs extra time to erase */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00639                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * HP DDS-3 4mm DAT
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] Compression on the HP DDS-3 is controlled
   *     via the Device Configuration mode page.
   * [2] The HP DDS-3 has only one density, 0x8c (or 0 for "default").
   * [3] The HP DDS-3 has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP DDS-3 4MM DAT",       /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "HP      C1537A",         /* .vid             Vendor-product ID string    */
    MT_ISDAT,                 /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE        |      /*    00001           Supports variable length  */
    ST_BSF             |      /*    00008           Supports SPACE block fwd  */
    ST_BSR             |      /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE      |      /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD       |      /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE      |      /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS   |      /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    09639                                     */
    400,                      /* .max_rretries    [Note 4]                    */
    400,                      /* .max_wretries    [Note 4]                    */
    {0x00, 0x8C, 0x8C, 0x8C}, /* .densities       Density codes [Note 2]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 3]        */
  },

  /*
   * HP DDS-3 4mm DAT loader
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] Compression on the DDS-3 Loader is controlled
   *     via the Device Configuration mode page.
   * [2] The DDS-3 Loader has only one density, 0x8c (or 0 for "default").
   * [3] The DDS-3 Loader has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP DDS-3 4MM DAT loader",/* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "HP      C1557A",         /* .vid             Vendor-product ID string    */
    MT_ISDAT,                 /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE        |      /*    00001           Supports variable length  */
    ST_BSF             |      /*    00008           Supports SPACE block fwd  */
    ST_BSR             |      /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE      |      /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD       |      /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE      |      /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS   |      /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    09639                                     */
    400,                      /* .max_rretries    [Note 4]                    */
    400,                      /* .max_wretries    [Note 4]                    */
    {0x00, 0x8C, 0x8C, 0x8C}, /* .densities       Density codes [Note 2]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 3]        */
  },

  /*
   * HP C5683A DDS-4 DAT drives with Sun-specific behavior
   *
   * When the configuration switches on the drive are set appropriately, the
   * HP C5683A: interprets a density code of 8Ch to mean "enable compression",
   * 00h to mean "disable compression"; senses the tape type automatically;
   * adjusts to match the tape type. (That is, compression is controlled via
   * the Sun-unique 8Ch density code, rather than using the Data Compression
   * mode page).
   *
   *     NOTES
   *     -----
   * [1] 00h = compression disabled, 8Ch = compression enabled, and all DDS-x
   *     format-related adjustments are performed automatically by the drive.
   * [2] The 5683 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP DDS-4 DAT (Sun)",     /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "HP      C5683A",         /* .vid             Vendor-product ID string    */
    MT_ISDAT,                 /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE       |     /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS    |     /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    09639                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x00, 0x8C, 0x8C, 0x8C}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * HP C5713A DDS-4 DAT autochangers with Sun-specific behavior
   *
   * When the configuration switches on the drive are set appropriately, the
   * HP C5713A: interprets a density code of 8Ch to mean "enable compression",
   * 00h to mean "disable compression"; senses the tape type automatically;
   * adjusts to match the tape type. (That is, compression is controlled via
   * the Sun-unique 8Ch density code, rather than using the Data Compression
   * mode page).
   *
   *     NOTES
   *     -----
   * [1] 00h = compression disabled, 8Ch = compression enabled, and all DDS-x
   *     format-related adjustments are performed automatically by the drive.
   * [2] The 5713 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP DDS-4 DAT (Sun)",     /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "HP      C5713A",         /* .vid             Vendor-product ID string    */
    MT_ISDAT,                 /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE       |     /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS    |     /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    09639                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x00, 0x8C, 0x8C, 0x8C}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

   /*
    * HP C7438A
    */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP DAT-72",              /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "HP      C7438A",         /* .vid             Vendor-product ID string    */
    MT_ISDAT,                 /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           Mode select compression   */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries      Not Used                  */
    -1,                       /* .max_wretries      Not Used                  */
    {0x47, 0x47, 0x47, 0x47}, /* .densities       Density codes               */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes Not Used        */
    0,                        /* .non_motion_timeout Nothing Special          */
    MINUTES(7),               /* .io_timeout         7 minutes (recover read) */
    0,                        /* .rewind_timeout     Nothing Special          */
    MINUTES(600),             /* .space_timeout      10 Hours (space seq file)*/
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(290)              /* .erase_timeout      4 hours 50 minutes       */
  },

  /*
   * HP DAT-160
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP DDS-6 DAT",           /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "HP      DAT160",         /* .vid             Vendor-product ID string    */
    MT_ISDAT,                 /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*    10000           Mode select compression   */
    ST_WORMABLE,              /*  1000000           Drive is WORM capable     */
                              /*  -------                                     */
                              /*  1018619                                     */
    -1,                       /* .max_rretries      Not Used                  */
    -1,                       /* .max_wretries      Not Used                  */
    {0x48, 0x48, 0x48, 0x48}, /* .densities       Density codes               */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes Not Used        */
    0,                        /* .non_motion_timeout Nothing Special          */
    MINUTES(5),               /* .io_timeout                                  */
    MINUTES(10),              /* .rewind_timeout                              */
    MINUTES(20),              /* .space_timeout                               */
    MINUTES(10),              /* .load_timeout                                */
    MINUTES(10),              /* .unload_timeout                              */
    MINUTES(300)              /* .erase_timeout      5 hours                  */
  },

  /*
   * HP Ultrium LTO Gen 4
   * [1] This drive supports two densites at this time.
   *     In reality the type of media GEN 3 or GEN 4 selects the density.
   *     ST_MODE_SEL_COMP controls compression.
   * [2] The Ultrium LTO has one speed.
   * [3] max_rretries and max_wretries are not used but kept for
   *     backward compatibility.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP Ultrium LTO 4",       /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "HP      Ultrium 4*",     /* .vid             handles SCSI or FC          */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*  0000001           Supports variable length  */
    ST_BSF              |     /*  0000008           Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*  0000200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*  0000400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000           Mode select compression   */
    ST_WORMABLE,              /*  1000000           Drive is WORM capable     */
                              /*  -------                                     */
                              /*  1018619                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x44, 0x44, 0x46, 0x46}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    MINUTES(1),               /* .non_motion_timeout                          */
    MINUTES(20),              /* .io_timeout                                  */
    MINUTES(10),              /* .rewind_timeout                              */
    MINUTES(20),              /* .space_timeout                               */
    MINUTES(10),              /* .load_timeout                                */
    MINUTES(10),              /* .unload_timeout                              */
    MINUTES(300)              /* .erase_timeout      Five Hours               */
  },

  /*
   * HP Ultrium LTO Gen 3
   * [1] This drive supports two densites at this time.
   *     In reality the type of media GEN 2 or GEN 3 selects the density.
   *     ST_MODE_SEL_COMP controls compression.
   * [2] The Ultrium LTO has one speed.
   * [3] max_rretries and max_wretries are not used but kept for
   *     backward compatibility.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP Ultrium LTO 3",       /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "HP      Ultrium 3*",     /* .vid             handles SCSI or FC          */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*  0000001           Supports variable length  */
    ST_BSF              |     /*  0000008           Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*  0000200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*  0000400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000           Mode select compression   */
    ST_WORMABLE,              /*  1000000           Drive is WORM capable     */
                              /*  -------                                     */
                              /*  1018619                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x42, 0x42, 0x44, 0x44}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    MINUTES(1),               /* .non_motion_timeout                          */
    MINUTES(20),              /* .io_timeout                                  */
    MINUTES(10),              /* .rewind_timeout                              */
    MINUTES(20),              /* .space_timeout                               */
    MINUTES(10),              /* .load_timeout                                */
    MINUTES(10),              /* .unload_timeout                              */
    MINUTES(300)              /* .erase_timeout      Five Hours               */
  },

  /*
   * HP Ultrium LTO Gen 2
   * [1] This drive supports two densites at this time.
   *     In reality the type of media GEN 1 or GEN 2 selects the density.
   *     ST_MODE_SEL_COMP controls compression.
   * [2] The Ultrium LTO has one speed.
   * [3] max_rretries and max_wretries are not used but kept for
   *     backward compatibility.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP Ultrium LTO 2",       /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "HP      Ultrium 2*",     /* .vid             handles SCSI or FC          */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           Mode select compression   */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x40, 0x40, 0x42, 0x42}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    MINUTES(10),              /* .non_motion_timeout                          */
    MINUTES(5),               /* .io_timeout Four                             */
    MINUTES(10),              /* .rewind_timeout                              */
    MINUTES(20),              /* .space_timeout                               */
    MINUTES(10),              /* .load_timeout                                */
    MINUTES(10),              /* .unload_timeout                              */
    MINUTES(300)              /* .erase_timeout      Five Hours               */
  },

  /*
   * HP Ultrium LTO
   * [1] This drive supports only one density at this time.
         ST_MODE_SEL_COMP controls compression.
   * [2] The Ultrium LTO has one speed.
   * [3] max_rretries and max_wretries are not used but kept for
   *     backward compatibility.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "HP Ultrium LTO",         /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "HP      Ultrium 1*",     /* .vid             handles SCSI and FC         */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           Mode select compression   */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x40, 0x40, 0x40, 0x40}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    MINUTES(1),               /* .non_motion_timeout                          */
    MINUTES(5),               /* .io_timeout Four                             */
    MINUTES(10),              /* .rewind_timeout                              */
    MINUTES(20),              /* .space_timeout                               */
    MINUTES(10),              /* .load_timeout                                */
    MINUTES(10),              /* .unload_timeout                              */
    MINUTES(300)              /* .erase_timeout      Five Hours               */
  },

  /*
   * Kennedy 1/2" reel
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   *  o This entry uses a shortened Vendor-product ID string for the
   *    INQUIRY match.
   *
   * [1] The density code entry requires four values, even if there are less
   *     than four values for the drive.
   * [2] The Kennedy 1/2" reel has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Kennedy 1/2\" Reel",     /* .name            Display ("pretty") name     */
    4,                        /* .length          Length of next item...      */
    "KENN***",                /* .vid             Vendor-product ID string    */
    ST_TYPE_KENNEDY,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE |             /*    00001           Supports variable length  */
    ST_REEL     |             /*    00004           1/2-inch reel tape device */
    ST_BSF      |             /*    00008           Supports SPACE block fwd  */
    ST_BSR      |             /*    00010           Supports SPACE block rev  */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0041D                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x01, 0x02, 0x03, 0x03}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * M4 Data Systems 9303 transport with 9700 512k i/f
   *
   *     NOTES
   *     -----
   *  o  The M4 Data 9303 is in non-buffered mode because it doesn't
   *     flush the buffer at end of tape writes. If you don't care
   *     about end of tape conditions (e.g., you use dump(8) which
   *     cannot handle end-of-tape anyhow), take out the ST_NOBUF.
   *
   *  o This is an unsupported drive.
   *
   * [1] The density code entry requires four values, even if there are less
   *     than four values for the drive.
   * [2] The M4 Data has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "M4-Data 1/2\" Reel",     /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "M4 DATA 123107 SCSI",    /* .vid             Vendor-product ID string    */
    ST_TYPE_REEL,             /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE  |            /*    00001           Supports variable length  */
    ST_REEL      |            /*    00004           1/2-inch reel tape device */
    ST_BSF       |            /*    00008           Supports SPACE block fwd  */
    ST_BSR       |            /*    00010           Supports SPACE block rev  */
    ST_NOBUF     |            /*    00080           Don't use buffered mode.  */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0049D                                     */
    500,                      /* .max_rretries    [Note 3]                    */
    500,                      /* .max_wretries    [Note 3]                    */
    {0x01, 0x02, 0x06, 0x06}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Quantum VS 160
   *
   * Notes
   * [1] The VS160 reads several formats which the drive autodetects.
   *     It can write only in VS160 format so all densities set ro 0x50.
   * [2] The speed field is not used and the VS160's speed is not setable.
   * [3] Retry counts are not used any more and set to -1.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Quantum VS160",          /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "QUANTUM DLT VS160",      /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001         Supports variable length    */
    ST_BSF              |     /*    00008         Supports SPACE block fwd    */
    ST_BSR              |     /*    00010         Supports SPACE block rev    */
    ST_AUTODEN_OVERRIDE |     /*    00040         Has only one density        */
    ST_KNOWS_EOD        |     /*    00200         Recognizes end-of-data      */
    ST_UNLOADABLE       |     /*    00400         Driver can be unloaded      */
    ST_NO_RECSIZE_LIMIT |     /*    08000         Supports blocks > 64KB      */
    ST_MODE_SEL_COMP,         /*    10000         Uses Mode select Compress   */
                              /* --------                                     */
                              /* 00018659                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x50, 0x50, 0x50, 0x50}, /* .densities       [Note 1]                    */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    MINUTES(2),               /* .non_motion_timeout Nothing special          */
    MINUTES(15),              /* .io_timeout         First write to new tape  */
    MINUTES(15),              /* .rewind_timeout     15 minutes               */
    MINUTES(15),              /* .space_timeout      15 minutes               */
    MINUTES(15),              /* .load_timeout       read catalog             */
    MINUTES(15),              /* .unload_timeout     write catalog + unthread */
    MINUTES(180)              /* .erase_timeout      3 hours                  */
  },
  /*
   * Quantum Super DLT600
   *
   *    NOTES
   *    -----
   *
   * [1] The Super DLT 600 supports many tape formats, Most are media selected.
   *     Previous DLT drives had density codes for compress and non-compress,
         This drive uses mode select to control compression.
   * [2] The Super DLT has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Quantum Super DLT 600",  /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "QUANTUM SDLT600",        /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*  0000001         Supports variable length    */
    ST_BSF              |     /*  0000008         Supports SPACE block fwd    */
    ST_BSR              |     /*  0000010         Supports SPACE block rev    */
    ST_KNOWS_EOD        |     /*  0000200         Recognizes end-of-data      */
    ST_UNLOADABLE       |     /*  0000400         Driver can be unloaded      */
    ST_NO_RECSIZE_LIMIT |     /*  0008000         Supports blocks > 64KB      */
    ST_MODE_SEL_COMP    |     /*  0010000         Uses Mode select Compress   */
    ST_WORMABLE,              /*  1000000         Is capable of WORM          */
                              /*  -------                                     */
                              /*  1018619                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x4a, 0x4a, 0x4a, 0x4a}, /* .densities       [Note 1]                    */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    MINUTES(60),              /* .io_timeout Four    One Hour                 */
    MINUTES(4),               /* .rewind_timeout     Four Minutes             */
    MINUTES(360),             /* .space_timeout      6 Hour if Directory bad  */
    MINUTES(16),              /* .load_timeout       Nothing Special          */
    MINUTES(16),              /* .unload_timeout     Nothing Special          */
    MINUTES(360)              /* .erase_timeout      Six hours                */
  },

 /*
   * Quantum Super DLT320
   *
   *    NOTES
   *    -----
   *  o  There is not going to be a SUN version of this drive. It will
   *     be released as QUANTUM only.
   *
   * [1] The Super DLT implements many tape formats, but the st driver supports
   *     only the four highest densities.
   * [2] The Super DLT has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Quantum Super DLT 320",  /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "QUANTUM SDLT320",        /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001         Supports variable length    */
    ST_BSF              |     /*    00008         Supports SPACE block fwd    */
    ST_BSR              |     /*    00010         Supports SPACE block rev    */
    ST_KNOWS_EOD        |     /*    00200         Recognizes end-of-data      */
    ST_UNLOADABLE       |     /*    00400         Driver can be unloaded      */
    ST_NO_RECSIZE_LIMIT,      /*    08000         Supports blocks > 64KB      */
                              /* --------                                     */
                              /* 00008619                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x90, 0x91, 0x92, 0x93}, /* .densities       [Note 1]                    */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Default 2 minutes        */
    MINUTES(60),              /* .io_timeout Four    Now 1 hour               */
    MINUTES(4),               /* .rewind_timeout     Four Minutes             */
    MINUTES(360),             /* .space_timeout      Six Hours                */
    MINUTES(16),              /* .load_timeout       Sixteen Minutes          */
    MINUTES(16),              /* .unload_timeout     Sixteen Minutes          */
    MINUTES(360)              /* .erase_timeout      Six hours                */
  },

  /*
   * Quantum Super DLT
   *
   *    NOTES
   *    -----
   *  o  There is not going to be a SUN version of this drive. It will
   *     be released as QUANTUM only.
   *
   * [1] The Super DLT implements many tape formats, but the st driver supports
   *     only the four highest densities.
   * [2] The Super DLT has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Quantum Super DLT 220",  /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "QUANTUM SuperDLT1",      /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001         Supports variable length    */
    ST_BSF              |     /*    00008         Supports SPACE block fwd    */
    ST_BSR              |     /*    00010         Supports SPACE block rev    */
    ST_KNOWS_EOD        |     /*    00200         Recognizes end-of-data      */
    ST_UNLOADABLE       |     /*    00400         Driver can be unloaded      */
    ST_NO_RECSIZE_LIMIT,      /*    08000         Supports blocks > 64KB      */
                              /* --------                                     */
                              /* 00008619                                     */
    -1,                       /* .max_rretries    [Note 3]                    */
    -1,                       /* .max_wretries    [Note 3]                    */
    {0x88, 0x89, 0x90, 0x91}, /* .densities       [Note 1]                    */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Default 2 minutes        */
    MINUTES(60),              /* .io_timeout Four    Now 1 hour               */
    MINUTES(4),               /* .rewind_timeout     Four Minutes             */
    MINUTES(360),             /* .space_timeout      Six Hours                */
    MINUTES(16),              /* .load_timeout       Sixteen Minutes          */
    MINUTES(16),              /* .unload_timeout     Sixteen Minutes          */
    MINUTES(360)              /* .erase_timeout      Six hours                */
  },

  /*
   * Quantum DLT8000
   *
   *    NOTES
   *    -----
   *  o  There is not going to be a SUN version of this drive. It will
   *     be released as QUANTUM only.
   *
   * [1] The DLT8000 implements many tape formats, but the st driver supports
   *     only the four highest densities.
   * [2] The DLT8000 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Quantum DLT8000",        /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "QUANTUM DLT8000",        /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS    |     /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_CLN_TYPE_3,            /* 40000000                                     */
                              /*    -----                                     */
                              /* 40009619                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x84, 0x85, 0x88, 0x89}, /* .densities       [Note 1]                    */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(360)              /* .erase_timeout      Six hours                */
  },

  /*
   * Quantum DLT7000
   *
   *     NOTES
   *     -----
   * [1] The DLT7000 implements many tape formats, but the st driver supports
   *     only the four highest densities.
   * [2] The DLT7000 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] Data is buffered in the driver and pre-acked to the application. This
   *      is only supported in Solaris 2.5.1.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Quantum DLT7000",        /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "QUANTUM DLT7000",        /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS    |     /*    01000           More time for some ops    */
    ST_BUFFERED_WRITES  |     /*    04000           [Note 4]                  */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_CLN_TYPE_3,            /* 40000000         Asks to be cleaned this way */
                              /* --------                                     */
                              /* 4000D619                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x82, 0x83, 0x84, 0x85}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY3,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(360)              /* .erase_timeout      Six hours                */
  },

  /*
   * Quantum DLT4000
   *
   *     NOTES
   *     -----
   * [1] The DLT4000 implements many tape formats, but the st driver supports
   *     only the four highest densities.
   * [2] The DLT4000 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] Data is buffered in the driver and pre-acked to the application. This
   *     is only supported in 2.5.1.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Quantum DLT4000",        /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "Quantum DLT4000",        /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE        |      /*    00001           Supports variable length  */
    ST_BSF             |      /*    00008           Supports SPACE block fwd  */
    ST_BSR             |      /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD       |      /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE      |      /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS   |      /*    01000           More time for some ops    */
    ST_BUFFERED_WRITES |      /*    04000           [Note 4]                  */
    ST_NO_RECSIZE_LIMIT|      /*    08000           Supports blocks > 64KB    */
    ST_CLN_TYPE_3,            /* 40000000         Asks to be cleaned this way */
                              /* --------                                     */
                              /* 4000D619                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x80, 0x81, 0x82, 0x83}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY3,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(360)              /* .erase_timeout      Six hours                */
  },

  /*
   * [1] The DLT-S4 has three densites at this time,
   *     0x49 for SuperDLT tape I, 0x4a for SuperDLT tape II,
   *     0x4b for SuperDLT tape III.
   *     This drive is configured with ST_KNOWS_MEDIA.
   *     That means that it will look at the mediatype from the mode sense
   *     to select the density code. The compression will be selected based
   *     on the minor node the user opened.
   * [2] S4 reports a medium type that is used to select the density.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Quantum DLT-S4",         /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "QUANTUM DLT-S4",         /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*  0000001           Supports variable length  */
    ST_BSF              |     /*  0000008           Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*  0000200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*  0000400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000           [Note 1]                  */
    ST_KNOWS_MEDIA      |     /*  0800000         Media detrmines density     */
    ST_WORMABLE,              /*  1000000            Supports WORM            */
                              /*    -----                                     */
                              /*  1818619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x49, 0x4a, 0x4b, 0x4b}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0x86, 0x87, 0x91, 0x91}, /* .mediatype       Media type  [Note 2]        */
    0,                        /* .non_motion_time                             */
    MINUTES(60),              /* .io_time                                     */
    MINUTES(4),               /* .rewind_time                                 */
    MINUTES(360),             /* .space_time                                  */
    MINUTES(16),              /* .load_time                                   */
    MINUTES(16),              /* .unload_time                                 */
    MINUTES(360)              /* .erase_time                                  */
  },

  /*
   * Seagate Hornet NS20 Travan
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The NS20 Travan uses 0 or the "default" density code.
   * [2] The NS20 Travan has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Seagate Hornet NS20 Travan",
                              /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "Seagate STT20000N",      /* .vid             Vendor-product ID string    */
    MT_ISQIC,                 /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC              |     /*    00002           QIC tape device           */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    0840A                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY1,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Seagate DAT 72
   *
   *  [1] Has only one density, Uses Mode Select to enable-disable compression.
   *  [2] Only one speed.
   */

  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Seagate DAT 72",         /* .name            Display ("pretty") name     */
    23,                       /* .length          Length of next item...      */
    "SEAGATE DAT    DAT72-00",/* .vid             Vendor-product ID string    */
    MT_ISDAT,                 /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           variable length records   */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports backspace record */
    ST_KNOWS_EOD        |     /*    00200           Knows EOD when it sees it */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           Mode select compression   */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not Used any more.          */
    {0x47, 0x47, 0x47, 0x47}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout                          */
    MINUTES(15),              /* .io_timeout                                  */
    MINUTES(2),               /* .rewind_timeout                              */
    MINUTES(15),              /* .space_timeout                               */
    0,                        /* .load_timeout                                */
    0,                        /* .unload_timeout                              */
    MINUTES(240)              /* .erase_timeout                               */
  },

  /*
   * Certance Ultrium LTO 3
   * [1] This drive supports 3 densites at this time.
   *     ST_MODE_SEL_COMP controls compression.
   * [2] max_rretries and max_wretries are not used but kept for
   *     backward compatibility.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Certance Ultrium 3",     /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "CERTANCEULTRIUM 3",      /* .vid             handles SCSI or FC          */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           Mode select compression   */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    [Note 2]                    */
    -1,                       /* .max_wretries    [Note 2]                    */
    {0x40, 0x42, 0x44, 0x44}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes                 */
    0,                        /* .non_motion_timeout                          */
    MINUTES(60),              /* .io_timeout                                  */
    MINUTES(35),              /* .rewind_timeout                              */
    MINUTES(60),              /* .space_timeout                               */
    MINUTES(35),              /* .load_timeout                                */
    MINUTES(35),              /* .unload_timeout                              */
    MINUTES(180)              /* .erase_timeout                               */
  },

  /*
   * Certance Ultrium LTO 2
   * [1] This drive supports two densites at this time.
   *     0x40 for Ultrium 1 and 0x42 for Ultrium 2.
   *     ST_MODE_SEL_COMP controls compression.
   * [2] max_rretries and max_wretries are not used but kept for
   *     backward compatibility.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Certance Ultrium 2", /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "CERTANCEULTRIUM 2",      /* .vid             handles SCSI or FC          */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           Mode select compression   */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    [Note 2]                    */
    -1,                       /* .max_wretries    [Note 2]                    */
    {0x40, 0x40, 0x42, 0x42}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes                 */
    0,                        /* .non_motion_timeout                          */
    MINUTES(60),              /* .io_timeout                                  */
    MINUTES(35),              /* .rewind_timeout                              */
    MINUTES(60),              /* .space_timeout                               */
    MINUTES(35),              /* .load_timeout                                */
    MINUTES(35),              /* .unload_timeout                              */
    MINUTES(180)              /* .erase_timeout                               */
  },

  /*
   * Seagate Ultrium LTO
   *
   *  [1] Has only one density, Uses Mode Select to enable-disable compression.
   *  [2] Only one speed.
   */

  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Seagate Ultrium LTO",    /* .name            Display ("pretty") name     */
    23,                       /* .length          Length of next item...      */
    "SEAGATE ULTRIUM06242-XX",/* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           variable length records   */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports backspace record */
    ST_KNOWS_EOD        |     /*    00200           Knows EOD when it sees it */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           Mode select compression   */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not Used any more.          */
    {0x40, 0x40, 0x40, 0x40}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout                          */
    MINUTES(10),              /* .io_timeout                                  */
    MINUTES(15),              /* .rewind_timeout                              */
    MINUTES(120),             /* .space_timeout                               */
    MINUTES(5),               /* .load_timeout                                */
    MINUTES(2),               /* .unload_timeout                              */
    MINUTES(120)              /* .erase_timeout                               */
  },

  /*
   * SONY 4mm DAT
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   *  o This entry uses a shortened Vendor-product ID string for the
   *    INQUIRY match.
   *
   * [1] The SDT-5000 uses 0 or the "default" density code.
   * [2] The SDT-5000 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "SONY 4mm DAT",           /* .name            Display ("pretty") name     */
    12,                       /* .length          Length of next item...      */
    "SONY    SDT-****",       /* .vid             Vendor-product ID string    */
    ST_TYPE_DAT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE   |           /*    00001           Supports variable length  */
    ST_BSF        |           /*    00008           Supports SPACE block fwd  */
    ST_BSR        |           /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE |           /*    00020           Needs extra time to erase */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00439                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Sun StorageTek T10000A tape drive.
   *
   *     NOTES
   *     -----
   *  o  The T10000A has special needs - support for SCSI LOCATE and
   *     READ POSITION commands - so we must be sure to place this
   *     entry before the one for ST_TYPE_STC3490 (generic STK
   *     half-inch cartridge drives).
   * [1] Compression on the T10000A is controlled
   *     via the Device Configuration mode page.
   * [2] The T10000A has only one writable density, 0x4A.
   * [3] The T10000A has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member    Description              */
                              /* ----------------    -----------              */
    "Sun StorageTek T10000A", /* .name               Display ("pretty") name  */
    15,                       /* .length             Length of next item...   */
    "STK     T10000A",        /* .vid                Vendor-product ID string */
    ST_TYPE_STK9840,          /* .type               Numeric type (cf. mtio.h)*/
    0,                        /* .bsize              Block size (0 = variable)*/
                              /* .options            Drive option flags:      */
    ST_VARIABLE         |     /*  0000001            Supports variable length */
    ST_BSF              |     /*  0000008            Supports SPACE block fwd */
    ST_BSR              |     /*  0000010            Supports SPACE block rev */
    ST_AUTODEN_OVERRIDE |     /*  0000040            Autodensity override flag*/
    ST_KNOWS_EOD        |     /*  0000200            Recognizes end-of-data   */
    ST_UNLOADABLE       |     /*  0000400            Driver can be unloaded   */
    ST_NO_RECSIZE_LIMIT |     /*  0008000            Supports blocks > 64KB   */
    ST_MODE_SEL_COMP    |     /*  0010000            [Note 1]                 */
    ST_WORMABLE,              /*  1000000            Supports WORM            */
                              /*  -------                                     */
                              /*  1018659                                     */
    -1,                       /* .max_rretries       [Note 4]                 */
    -1,                       /* .max_wretries       [Note 4]                 */
    {0x4A,0x4A,0x4A,0x4A},    /* .densities          Density codes [Note 2]   */
    MT_DENSITY4,              /* .default_density    (.densities[x])          */
    {0,0,0,0},                /* .speeds             Speed codes [Note 3]     */
    0,                        /* .non_motion_timeout Nothing Special          */
    MINUTES(5),               /* .io_timeout Five    Five Minutes             */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(180)              /* .erase_timeout      Three Hours              */
  },

  /*
   * STK 9840C cartridge drive.
   *
   *     NOTES
   *     -----
   *  o  The 9840C has special needs - support for SCSI LOCATE and
   *     READ POSITION commands - so we must be sure to place this
   *     entry before the one for ST_TYPE_STC3490 (generic STK
   *     half-inch cartridge drives).
   * [1] Compression on the 9840C is controlled
   *     via the Device Configuration mode page.
   * [2] The 9840C has only one writable density, 0x45. I can read tapes writen
   *     with 9840 and 9840B writen with there density code 0x42.
   * [3] The 9840C has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member    Description              */
                              /* ----------------    -----------              */
    "StorageTek 9840C",       /* .name               Display ("pretty") name  */
    14,                       /* .length             Length of next item...   */
    "STK     T9840C",         /* .vid                Vendor-product ID string */
    ST_TYPE_STK9840,          /* .type               Numeric type (cf. mtio.h)*/
    0,                        /* .bsize              Block size (0 = variable)*/
                              /* .options            Drive option flags:      */
    ST_VARIABLE         |     /*  0000001            Supports variable length */
    ST_BSF              |     /*  0000008            Supports SPACE block fwd */
    ST_BSR              |     /*  0000010            Supports SPACE block rev */
    ST_KNOWS_EOD        |     /*  0000200            Recognizes end-of-data   */
    ST_UNLOADABLE       |     /*  0000400            Driver can be unloaded   */
    ST_NO_RECSIZE_LIMIT |     /*  0008000            Supports blocks > 64KB   */
    ST_MODE_SEL_COMP    |     /*  0010000            [Note 1]                 */
    ST_WORMABLE,              /*  1000000            Supports WORM            */
                              /*  -------                                     */
                              /*  1018619                                     */
    -1,                       /* .max_rretries       [Note 4]                 */
    -1,                       /* .max_wretries       [Note 4]                 */
    {0x45,0x45,0x45,0x45},    /* .densities          Density codes [Note 2]   */
    MT_DENSITY1,              /* .default_density    (.densities[x])          */
    {0,0,0,0},                /* .speeds             Speed codes [Note 3]     */
    0,                        /* .non_motion_timeout Nothing Special          */
    MINUTES(5),               /* .io_timeout Five    Five Minutes             */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(70)               /* .erase_timeout      One Hour and ten Minutes */
  },

  /*
   * STK 9840B cartridge drive.
   *
   *     NOTES
   *     -----
   *  o  The 9840B has special needs - support for SCSI LOCATE and
   *     READ POSITION commands - so we must be sure to place this
   *     entry before the one for ST_TYPE_STC3490 (generic STK
   *     half-inch cartridge drives).
   * [1] Compression on the 9840B is controlled
   *     via the Device Configuration mode page.
   * [2] The 9840B has only one density, 0x42 (or 0 for "default").
   * [3] The 9840B has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member    Description              */
                              /* ----------------    -----------              */
    "StorageTek 9840B",       /* .name               Display ("pretty") name  */
    14,                       /* .length             Length of next item...   */
    "STK     T9840B",         /* .vid                Vendor-product ID string */
    ST_TYPE_STK9840,          /* .type               Numeric type (cf. mtio.h)*/
    0,                        /* .bsize              Block size (0 = variable)*/
                              /* .options            Drive option flags:      */
    ST_VARIABLE         |     /*  0000001            Supports variable length */
    ST_BSF              |     /*  0000008            Supports SPACE block fwd */
    ST_BSR              |     /*  0000010            Supports SPACE block rev */
    ST_KNOWS_EOD        |     /*  0000200            Recognizes end-of-data   */
    ST_UNLOADABLE       |     /*  0000400            Driver can be unloaded   */
    ST_NO_RECSIZE_LIMIT |     /*  0008000            Supports blocks > 64KB   */
    ST_MODE_SEL_COMP    |     /*  0010000            [Note 1]                 */
    ST_WORMABLE,              /*  1000000            Supports WORM            */
                              /*  -------                                     */
                              /*  1018619                                     */
    -1,                       /* .max_rretries       [Note 4]                 */
    -1,                       /* .max_wretries       [Note 4]                 */
    {0x42,0x42,0x42,0x42},    /* .densities          Density codes [Note 2]   */
    MT_DENSITY1,              /* .default_density    (.densities[x])          */
    {0,0,0,0},                /* .speeds             Speed codes [Note 3]     */
    0,                        /* .non_motion_timeout Nothing Special          */
    MINUTES(5),               /* .io_timeout Five    Five Minutes             */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(70)               /* .erase_timeout      One Hour and ten Minutes */
  },

  /*
   * STK 9940B cartridge drive.
   *
   *     NOTES
   *     -----
   * [1] Compression on the 9940 is controlled
   *     via the Device Configuration mode page.
   * [2] The 9940 has only one density, 0x44.
   * [3] The 9940 has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver not used.
   */
  {                           /* Structure member    Description               */
                              /* ----------------    -----------               */
    "StorageTek 9940B",       /* .name               Display ("pretty") name   */
    14,                       /* .length             Length of next item...    */
    "STK     T9940B",         /* .vid                Vendor-product ID string  */
    ST_TYPE_STK9840,          /* .type               Numeric type (cf. mtio.h) */
    0,                        /* .bsize              Block size (0 = variable) */
                              /* .options            Drive option flags:       */
    ST_VARIABLE         |     /*  0000001            Supports variable length  */
    ST_BSF              |     /*  0000008            Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010            Supports SPACE block rev  */
    ST_AUTODEN_OVERRIDE |     /*  0000040            Autodensity override flag */
    ST_KNOWS_EOD        |     /*  0000200            Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*  0000400            Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000            Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000            [Note 1]                  */
    ST_WORMABLE,              /*  1000000            Supports WORM             */
                              /*  -------                                      */
                              /*  1018659                                      */
    -1,                       /* .max_rretries       [Note 4]                  */
    -1,                       /* .max_wretries       [Note 4]                  */
    {0x44,0x44,0x44,0x44},    /* .densities          Density codes [Note 2]    */
    MT_DENSITY1,              /* .default_density    (.densities[x])           */
    {0, 0, 0, 0},             /* .speeds             Speed codes [Note 3]      */
    0,                        /* .non_motion_timeout Nothing Special           */
    MINUTES(5),               /* .io_timeout         Five minutes              */
    0,                        /* .rewind_timeout     Nothing Special           */
    MINUTES(180),             /* .space_timeout      Three Hours     3 x 9840  */
    0,                        /* .load_timeout       Nothing Special           */
    0,                        /* .unload_timeout     Nothing Special           */
    MINUTES(210)              /* .erase_timeout      Three and a half hours    */
  },

  /*
   * STK 9940 cartridge drive.
   *
   *     NOTES
   *     -----
   * [1] Compression on the 9940 is controlled
   *     via the Device Configuration mode page.
   * [2] The 9940 has only one density, 0x43.
   * [3] The 9940 has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver not used.
   */
  {                           /* Structure member    Description              */
                              /* ----------------    -----------              */
    "StorageTek 9940",        /* .name               Display ("pretty") name  */
    14,                       /* .length             Length of next item...   */
    "STK     T9940A",         /* .vid                Vendor-product ID string */
    ST_TYPE_STK9840,          /* .type               Numeric type (cf. mtio.h)*/
    0,                        /* .bsize              Block size (0 = variable)*/
                              /* .options            Drive option flags:      */
    ST_VARIABLE         |     /*  0000001            Supports variable length */
    ST_BSF              |     /*  0000008            Supports SPACE block fwd */
    ST_BSR              |     /*  0000010            Supports SPACE block rev */
    ST_KNOWS_EOD        |     /*  0000200            Recognizes end-of-data   */
    ST_UNLOADABLE       |     /*  0000400            Driver can be unloaded   */
    ST_NO_RECSIZE_LIMIT |     /*  0008000            Supports blocks > 64KB   */
    ST_MODE_SEL_COMP    |     /*  0010000            [Note 1]                 */
    ST_WORMABLE,              /*  1000000            Supports WORM            */
                              /*  -------                                     */
                              /*  1018619                                     */
    -1,                       /* .max_rretries       [Note 4]                 */
    -1,                       /* .max_wretries       [Note 4]                 */
    {0x43,0x43,0x43,0x43},    /* .densities          Density codes [Note 2]   */
    MT_DENSITY1,              /* .default_density    (.densities[x])          */
    {0, 0, 0, 0},             /* .speeds             Speed codes [Note 3]     */
    0,                        /* .non_motion_timeout Nothing Special          */
    MINUTES(5),               /* .io_timeout         Five Minutes             */
    0,                        /* .rewind_timeout     Nothing Special          */
    MINUTES(180),             /* .space_timeout      Three Hours     3 x 9840 */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(210)              /* .erase_timeout      Three and a half hours   */
  },

  /*
   * STK 9840 cartridge drive (Sun codename: Ironsides)
   *
   *     NOTES
   *     -----
   *  o  The 9840 has special needs - support for SCSI LOCATE and
   *     READ POSITION commands - so we must be sure to place this
   *     entry before the one for ST_TYPE_STC3490 (generic STK
   *     half-inch cartridge drives).
   * [1] Compression on the 9840 is controlled
   *     via the Device Configuration mode page.
   * [2] The 9840 has only one density, 0x42 (or 0 for "default").
   * [3] The 9840 has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver anachronisms.
   * [5] ST_LONG_ERASE is not needed or used when .erase_timeout
   *     is non-zero.
   */
  {                           /* Structure member    Description              */
                              /* ----------------    -----------              */
    "StorageTek 9840",        /* .name               Display ("pretty") name  */
    12,                       /* .length             Length of next item...   */
    "STK     9840",           /* .vid                Vendor-product ID string */
    ST_TYPE_STK9840,          /* .type               Numeric type (cf. mtio.h)*/
    0,                        /* .bsize              Block size (0 = variable)*/
                              /* .options            Drive option flags:      */
    ST_VARIABLE         |     /*  0000001            Supports variable length */
    ST_BSF              |     /*  0000008            Supports SPACE block fwd */
    ST_BSR              |     /*  0000010            Supports SPACE block rev */
    ST_KNOWS_EOD        |     /*  0000200            Recognizes end-of-data   */
    ST_UNLOADABLE       |     /*  0000400            Driver can be unloaded   */
    ST_NO_RECSIZE_LIMIT |     /*  0008000            Supports blocks > 64KB   */
    ST_MODE_SEL_COMP    |     /*  0010000            [Note 1]                 */
    ST_WORMABLE,              /*  1000000            Supports WORM            */
                              /*  -------                                     */
                              /*  1018619                                     */
    10,                       /* .max_rretries       [Note 4]                 */
    10,                       /* .max_wretries       [Note 4]                 */
    {0x00, 0x00, 0x00, 0x00}, /* .densities          Density codes [Note 2]   */
    MT_DENSITY1,              /* .default_density    (.densities[x])          */
    {0, 0, 0, 0},             /* .speeds             Speed codes [Note 3]     */
    0,                        /* .non_motion_timeout Nothing Special          */
    MINUTES(5),               /* .io_timeout         Five Minutes             */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(70)               /* .erase_timeout      One Hour and ten Minutes */
  },

  /*
   * Sony SAIT
   *
   * Only looking at part of the product ID so it will match SDZ-100 and
   * SDZ-130. One is SCSI other is Fibre but same configuration otherwise.
   *
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Sony Super AIT",         /* .name            Display ("pretty") name     */
    13,                       /* .length          Length of next item...      */
    "SONY    SDZ-1*",         /* .vid             Vendor-product ID string    */
    ST_TYPE_AIT,              /* .type            Numeric type (cf. mtio.h)   */
    0,
    ST_VARIABLE         |     /*  0000001           Supports variable length  */
    ST_BSF              |     /*  0000008           Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010           Supports SPACE block rev  */
    ST_AUTODEN_OVERRIDE |     /*  0000040           Suports only one density  */
    ST_KNOWS_EOD        |     /*  0000200           Knows End Of Data         */
    ST_UNLOADABLE       |     /*  0000400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000           mode select compression   */
    ST_WORMABLE,              /*  1000000           Drive is WORM capable     */
                              /*  -------                                     */
                              /*  1018659                                     */
    -1,                       /* .max_rretries    Not used                    */
    -1,                       /* .max_wretries    Not used                    */
    {0x40, 0x40, 0x40, 0x40}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    0,                        /* .erase_timeout      Six hours                */
  },

  /*
   * Sony SDX-420
   * This drive is listed before the more generic AIT drives becouse it runs
   * only in fixed block mode. It also responds to READ BLOCK LIMITS which
   * leads st to beleive its a variable block capable but it will fail any
   * i/o that doesn't have the fix bit set in the CDB.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Sony AIT II",            /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "SONY    SDX-420*",       /* .vid             Vendor-product ID string    */
    ST_TYPE_AIT,              /* .type            Numeric type (cf. mtio.h)   */
    512,
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_AUTODEN_OVERRIDE |     /*    00040           One density code          */
    ST_KNOWS_EOD        |     /*    00200           Knows End Of Data         */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           mode select compression   */
                              /*    -----                                     */
                              /*    18658                                     */
    -1,                       /* .max_rretries    Not used                    */
    -1,                       /* .max_wretries    Not used                    */
    {0x30, 0x30, 0x30, 0x30}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    0,                        /* .erase_timeout      Six hours                */
  },

  /*
   * Sony SDX-520
   * This drive is listed before the more generic AIT drives becouse it runs
   * only in fixed block mode. It also responds to READ BLOCK LIMITS which
   * leads st to beleive its a variable block capable but it will fail any
   * i/o that doesn't have the fix bit set in the CDB.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Sony AIT II",            /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "SONY    SDX-520*",       /* .vid             Vendor-product ID string    */
    ST_TYPE_AIT,              /* .type            Numeric type (cf. mtio.h)   */
    512,
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_AUTODEN_OVERRIDE |     /*    00040           One density code          */
    ST_KNOWS_EOD        |     /*    00200           Knows End Of Data         */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           mode select compression   */
                              /*    -----                                     */
                              /*    18658                                     */
    -1,                       /* .max_rretries    Not used                    */
    -1,                       /* .max_wretries    Not used                    */
    {0x30, 0x30, 0x30, 0x30}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    0,                        /* .erase_timeout      Six hours                */
  },

  /* Sony generic AIT
   *
   *
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Sony AIT",               /* .name            Display ("pretty") name     */
    12,                       /* .length          Length of next item...      */
    "SONY    SDX-*",          /* .vid             Vendor-product ID string    */
    ST_TYPE_AIT,              /* .type            Numeric type (cf. mtio.h)   */
    0,
    ST_VARIABLE         |     /*  0000001           Supports variable length  */
    ST_BSF              |     /*  0000008           Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010           Supports SPACE block rev  */
    ST_AUTODEN_OVERRIDE |     /*  0000040           One density code          */
    ST_KNOWS_EOD        |     /*  0000200           Knows End Of Data         */
    ST_UNLOADABLE       |     /*  0000400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000           mode select compression   */
    ST_WORMABLE,              /*  1000000           Drive is WORM capable     */
                              /*  -------                                     */
                              /*  1018659                                     */
    -1,                       /* .max_rretries    Not used                    */
    -1,                       /* .max_wretries    Not used                    */
    {0x30, 0x30, 0x30, 0x30}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    0,                        /* .erase_timeout      Six hours                */
  },

  /*
   * Sun DLT7000
   *
   *     NOTES
   *     -----
   * [1] The DLT7000 implements many tape formats, but the st driver supports
   *     only the four highest densities.
   * [2] The DLT7000 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] Data is buffered in the driver and pre-acked to the application. This
   *     is only supported in 2.5.1.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Sun DLT7000",            /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "SUN     DLT7000",        /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS    |     /*    01000           More time for some ops    */
    ST_BUFFERED_WRITES  |     /*    04000           [Note 4]                  */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_CLN_TYPE_3,            /* 40000000         Asks to be cleaned this way */
                              /* --------                                     */
                              /* 4000D619                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x82, 0x83, 0x84, 0x85}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY3,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(360)              /* .erase_timeout      Six hours                */
  },

  /*
   * Sun DLT4000
   *
   *     NOTES
   *     -----
   * [1] The DLT4000 implements many tape formats, but the st driver supports
   *     only the four highest densities.
   * [2] The DLT4000 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] Data is buffered in the driver and pre-acked to the application. This
   *     is only supported in 2.5.1.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "DLT4000",                /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "SUN     DLT4000",        /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE        |      /*    00001           Supports variable length  */
    ST_BSF             |      /*    00008           Supports SPACE block fwd  */
    ST_BSR             |      /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD       |      /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE      |      /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS   |      /*    01000           More time for some ops    */
    ST_BUFFERED_WRITES |      /*    04000           [Note 4]                  */
    ST_NO_RECSIZE_LIMIT|      /*    08000           Supports blocks > 64KB    */
    ST_CLN_TYPE_3,            /* 40000000         Asks to be cleaned this way */
                              /* --------                                     */
                              /* 4000D619                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x80, 0x81, 0x82, 0x83}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY3,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(360)              /* .erase_timeout      Six hours                */
  },

  /*
   * Sun DLT4700
   *
   *     NOTES
   *     -----
   * [1] Compression on the DLT4700 is controlled via the Device Configuration
   *     mode page or the Data Compression page (either one).
   * [2] The DLT4700 implements many tape formats, but the st driver supports
   *     only the four highest densities.
   * [3] The DLT4700 has only one speed (if the driver ever cares).
   * [4] max_rretries and max_wretries are driver anachronisms.
   * [5] Data is buffered in the driver and pre-acked to the application. This
   *     is only supported in 2.5.1.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "DLT4700 Library",        /* .name            Display ("pretty") name     */
    15,                       /* .length          Length of next item...      */
    "SUN     DLT4700",        /* .vid             Vendor-product ID string    */
    ST_TYPE_DLT,              /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE        |      /*    00001           Supports variable length  */
    ST_BSF             |      /*    00008           Supports SPACE block fwd  */
    ST_BSR             |      /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD       |      /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE      |      /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS   |      /*    01000           More time for some ops    */
    ST_BUFFERED_WRITES |      /*    04000           [Note 5]                  */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    0D619                                     */
    400,                      /* .max_rretries    [Note 4]                    */
    400,                      /* .max_wretries    [Note 4]                    */
    {0x80, 0x81, 0x82, 0x83}, /* .densities       Density codes [Note 2]      */
    MT_DENSITY3,              /* .default_density (.densities[x])             */
    { 0, 0, 0, 0 },           /* .speeds          Speed codes [Note 2]        */
    0,                        /* .non_motion_timeout Nothing special          */
    0,                        /* .io_timeout Four    Nothing Special          */
    0,                        /* .rewind_timeout     Nothing Special          */
    0,                        /* .space_timeout      Nothing Special          */
    0,                        /* .load_timeout       Nothing Special          */
    0,                        /* .unload_timeout     Nothing Special          */
    MINUTES(360)              /* .erase_timeout      Six hours                */
  },

  /*
   * Tandberg SLR5 4/8G (standard firmware)
   *
   *     NOTES
   *     -----
   * [1] The density code entry requires four values, even if there are less
   *     than four values for the drive.
   * [2] The Tandberg SLR5 4/8G has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Tandberg 4/8 Gig QIC",   /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "TANDBERG SLR5 4/8GB",    /* .vid             Vendor-product ID string    */
    ST_TYPE_TAND25G,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE        |      /*    00001           Supports variable length  */
    ST_QIC             |      /*    00002           QIC tape device           */
    ST_BSF             |      /*    00008           Supports SPACE block fwd  */
    ST_BSR             |      /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE      |      /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD       |      /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE      |      /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS   |      /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    0963B                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x22, 0x22, 0x26, 0x26}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Tandberg SLR5 (SMI firmware).
   *
   *     NOTES
   *     -----
   *  o The inquiry string for this drive is actually padded with blanks, but
   *    we only check the first 13 characters so that this will act as a default
   *    to cover other revisions of firmware on SLR5s which may show up.
   *
   * [1] The density code entry requires four values, even if there are less
   *     than four values for the drive.
   * [2] The Tandberg SLR5 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Tandberg 8 Gig QIC",     /* .name            Display ("pretty") name     */
    13,                       /* .length          Length of next item...      */
    "TANDBERG SLR5",          /* .vid             Vendor-product ID string    */
    ST_TYPE_TAND25G,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE        |      /*    00001           Supports variable length  */
    ST_QIC             |      /*    00002           QIC tape device           */
    ST_BSF             |      /*    00008           Supports SPACE block fwd  */
    ST_BSR             |      /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE      |      /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD       |      /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE      |      /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS   |      /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    0963B                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0xA0, 0xD0, 0xD0, 0xD0}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Tandberg 4100 QIC
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The Tandberg 4100 uses 0 or the "default" density code.
   * [2] The Tandberg 4100 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Tandberg 4100 QIC",      /* .name            Display ("pretty") name     */
    13,                       /* .length          Length of next item...      */
    "TANDBERG 4100",          /* .vid             Vendor-product ID string    */
    MT_ISQIC,                 /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC        |           /*    00002           QIC tape device           */
    ST_BSF        |           /*    00008           Supports SPACE block fwd  */
    ST_BSR        |           /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE |           /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD  |           /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0063A                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Tandberg 4200 QIC
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The Tandberg 4200 uses 0 or the "default" density code.
   * [2] The Tandberg 4200 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Tandberg 4200 QIC",      /* .name            Display ("pretty") name     */
    13,                       /* .length          Length of next item...      */
    "TANDBERG 4200",          /* .vid             Vendor-product ID string    */
    MT_ISQIC,                 /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC        |           /*    00002           QIC tape device           */
    ST_BSF        |           /*    00008           Supports SPACE block fwd  */
    ST_BSR        |           /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE |           /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD  |           /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0063A                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Tandberg QIC 2.5 Gig Tape Drive
   *
   *     NOTES
   *     -----
   * [1] The TDC 4200 uses 0 or the "default" density code.
   * [2] The TDC 4200 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] Data is buffered in the driver and pre-acked to the application. This
   *     is only supported in 2.5.1.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Tandberg QIC 2.5 Gig Tape Drive",
                              /* .name            Display ("pretty") name     */
    16,                       /* .length          Length of next item...      */
    "TANDBERG TDC 420*",      /* .vid             Vendor-product ID string    */
    MT_ISQIC,                 /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE          |    /*    00001           Supports variable length  */
    ST_QIC               |    /*    00002           QIC tape device           */
    ST_BSF               |    /*    00008           Supports SPACE block fwd  */
    ST_BSR               |    /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE        |    /*    00020           Needs extra time to erase */
    ST_AUTODEN_OVERRIDE  |    /*    00040           Autodensity override flag */
    ST_KNOWS_EOD         |    /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE        |    /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS     |    /*    01000           More time for some ops    */
    ST_BUFFERED_WRITES   |    /*    04000           [Note 4]                  */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    0D67B                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY1,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Tandberg MLR1 QIC
   *
   *     NOTES
   *     -----
   * [1] The MLR1 uses 0 or the "default" density code.
   * [2] The MLR1 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   * [4] Data is buffered in the driver and pre-acked to the application. This
   *     is only supported in 2.5.1.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Tandberg MLR1 QIC",      /* .name            Display ("pretty") name     */
    12,                       /* .length          Length of next item...      */
    "TANDBERGMLR1",           /* .vid             Vendor-product ID string    */
    MT_ISQIC,                 /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC            |       /*    00002         QIC tape device             */
    ST_BSF            |       /*    00008         Supports SPACE block fwd    */
    ST_BSR            |       /*    00010         Supports SPACE block rev    */
    ST_LONG_ERASE     |       /*    00020         Needs extra time to erase   */
    ST_KNOWS_EOD      |       /*    00200         Recognizes end-of-data      */
    ST_UNLOADABLE     |       /*    00400         Driver can be unloaded      */
    ST_BUFFERED_WRITES,       /*    04000         [Note 4]                    */
                              /*    -----                                     */
                              /*    0463A                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY1,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Tandberg MLR3 QIC
   *
   *     NOTES
   *     -----
   * [1] The density code entry requires four values, even if there are less
   *     than four values for the drive.
   * [2] The MLR3 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Tandberg 50 Gig QIC",    /* .name            Display ("pretty") name     */
    12,                       /* .length          Length of next item...      */
    "TANDBERGMLR3",           /* .vid             Vendor-product ID string    */
    MT_ISTAND25G,             /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE        |      /*    00001           Supports variable length  */
    ST_QIC             |      /*    00002           QIC tape device           */
    ST_BSF             |      /*    00008           Supports SPACE block fwd  */
    ST_BSR             |      /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE      |      /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD       |      /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE      |      /*    00400           Driver can be unloaded    */
    ST_LONG_TIMEOUTS   |      /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT,      /*    08000           Supports blocks > 64KB    */
                              /*    -----                                     */
                              /*    0963B                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0xA0, 0xD0, 0xD0, 0xD0}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY3,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * WangDAT 3.81mm cartridge
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The WangDAT 3.81mm uses 0 or the "default" density code.
   * [2] The WangDAT 3.81mm has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Wang DAT 3.81 Helical Scan",
                              /* .name            Display ("pretty") name     */
    7,                        /* .length          Length of next item...      */
    "WangDAT",                /* .vid             Vendor-product ID string    */
    ST_TYPE_WANGDAT,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_AUTODEN_OVERRIDE |     /*    00040           Autodensity override flag */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00659                                     */
    5000,                     /* .max_rretries    [Note 3]                    */
    5000,                     /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Wangtek QIC-150 1/4" cartridge
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The Wangtek QIC-150 uses 0 or the "default" density code.
   * [2] The Wangtek QIC-150 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Wangtek QIC-150",        /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "WANGTEK 5150ES",         /* .vid             Vendor-product ID string    */
    ST_TYPE_WANGTEK,          /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC              |     /*    00002           QIC tape device           */
    ST_AUTODEN_OVERRIDE |     /*    00040           Autodensity override flag */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00642                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Wangtek 4mm RDAT drive
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   *  o This entry uses a shortened Vendor-product ID string for the
   *    INQUIRY match.
   *
   * [1] The Wangtek 4mm RDAT uses 0 or the "default" density code.
   * [2] The Wangtek 4mm RDAT has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Wangtek 4mm Helical Scan",
                              /* .name            Display ("pretty") name     */
    14,                       /* .length          Length of next item...      */
    "WANGTEK 6130-H*",        /* .vid             Vendor-product ID string    */
    ST_TYPE_WANGTHS,          /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_AUTODEN_OVERRIDE |     /*    00040           Autodensity override flag */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    00659                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * Wangtek QIC-150 1/4" cartridge
   *
   *     NOTES
   *     -----
   *  o This is an unsupported drive.
   *
   * [1] The Wangtek QIC-150 uses 0 or the "default" density code.
   * [2] The Wangtek QIC-150 has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Wangtek 5525ES SCSI",    /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "WANGTEK 5525ES SCSI",    /* .vid             Vendor-product ID string    */
    ST_TYPE_WANGTEK,          /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC              |     /*    00002           QIC tape device           */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE       |     /*    00020           Needs extra time to erase */
    ST_AUTODEN_OVERRIDE |     /*    00040           Autdensity override flag  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0067A                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY2,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * [1] The Ecrix VXA-1 has only one density at this time,
   *     Compression is controlled via the Device Configuration
   *     mode page.
   * [2] The Ecrix VXA-1 is a veriable speed device. The drive determines
   *     the optimum speed. (if the driver ever cares).
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Ecrix VXA-1",            /* .name            Display ("pretty") name     */
    13,                       /* .length          Length of next item...      */
    "ECRIX   VXA-1",          /* .vid             Vendor-product ID string    */
    MT_ISOTHER,               /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE             | /*    00001           Supports variable length  */
    ST_BSF                  | /*    00008           Supports SPACE block fwd  */
    ST_BSR                  | /*    00010           Supports SPACE block rev  */
    ST_LONG_ERASE           | /*    00020           Needs extra time to erase */
    ST_KNOWS_EOD            | /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE           | /*    00400           Driver can be unloaded    */
    ST_SOFT_ERROR_REPORTING | /*    00800           Reports errors on close   */
    ST_LONG_TIMEOUTS        | /*    01000           More time for some ops    */
    ST_NO_RECSIZE_LIMIT     | /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP        | /*    10000         Mode Select to enable comp  */
    ST_CLN_TYPE_1,            /* 10000000         Asks to be cleaned this way */
                              /* --------                                     */
                              /* 10019E39                                     */
    -1,                       /* .max_rretries                                */
    -1,                       /* .max_wretries                                */
    {0x80, 0x80, 0x80, 0x80}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },

  /*
   * [1] The IBM Ultrium Gen 4 "OEM" version has two densites at this time,
   *     One for Gen 3 0x44, One for Gen 4 0x46.
   *     This drive is configured with ST_KNOWS_MEDIA.
   *     That means that it will look at the mediatype from the mode sense
   *     to select the density code. The compression will be selected based
   *     on the minor node the user opened.
   * [2] The IBM LTO reports a medium type that is used to select the density.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "IBM Ultrium Gen 4 LTO",  /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "IBM     ULTRIUM-TD4",    /* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*  0000001           Supports variable length  */
    ST_BSF              |     /*  0000008           Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*  0000200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*  0000400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000           [Note 1]                  */
    ST_KNOWS_MEDIA      |     /*  0800000         Media detrmines density     */
    ST_WORMABLE,              /*  1000000         Is WORM capable             */
                              /*  -------                                     */
                              /*  1818619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x44, 0x44, 0x46, 0x46}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0x38, 0x38, 0x48, 0x48}, /* .mediatype       Media type  [Note 2]        */
    MINUTES(1),               /* .non_motion_time                             */
    MINUTES(23),              /* .io_time                                     */
    MINUTES(9),               /* .rewind_time                                 */
    MINUTES(183),             /* .space_time      worst case directory invalid*/
    MINUTES(9),               /* .load_time                                   */
    MINUTES(13),              /* .unload_time                                 */
    MINUTES(180)              /* .erase_time                                  */
  },

  /*
   * [1] The IBM Ultrium Gen 4 "IBM" version has two densites at this time,
   *     One for Gen 3 0x44, one for Gen 4 0x46.
   *     This drive is configured with ST_KNOWS_MEDIA.
   *     That means that it will look at the mediatype from the mode sense
   *     to select the density code. The compression will be selected based
   *     on the minor node the user opened.
   * [2] The IBM LTO reports a medium type that is used to select the density.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "IBM Ultrium Gen 4 LTO",  /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "IBM     ULT3580-TD4",    /* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*  0000001           Supports variable length  */
    ST_BSF              |     /*  0000008           Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*  0000200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*  0000400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000           [Note 1]                  */
    ST_KNOWS_MEDIA      |     /*  0800000         Media detrmines density     */
    ST_WORMABLE,              /*  1000000         Is WORM capable             */
                              /*  -------                                     */
                              /*  1818619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x44, 0x44, 0x46, 0x46}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0x38, 0x38, 0x48, 0x48}, /* .mediatype       Media type  [Note 2]        */
    MINUTES(1),               /* .non_motion_time                             */
    MINUTES(23),              /* .io_time                                     */
    MINUTES(9),               /* .rewind_time                                 */
    MINUTES(183),             /* .space_time      worst case directory invalid*/
    MINUTES(9),               /* .load_time                                   */
    MINUTES(13),              /* .unload_time                                 */
    MINUTES(180)              /* .erase_time                                  */
  },

  /*
   * [1] The IBM Ultrium Gen 3 "OEM" version has three densites at this time,
   *     One for Gen 1 0x40, One for Gen 2 0x42 and for Gen 3 0x44.
   *     This drive is configured with ST_KNOWS_MEDIA.
   *     That means that it will look at the mediatype from the mode sense
   *     to select the density code. The compression will be selected based
   *     on the minor node the user opened.
   * [2] The IBM LTO reports a medium type that is used to select the density.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "IBM Ultrium Gen 3 LTO",  /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "IBM     ULTRIUM-TD3",    /* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*  0000001           Supports variable length  */
    ST_BSF              |     /*  0000008           Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*  0000200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*  0000400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000           [Note 1]                  */
    ST_KNOWS_MEDIA      |     /*  0800000         Media detrmines density     */
    ST_WORMABLE,              /*  1000000         Is WORM capable             */
                              /*  -------                                     */
                              /*  1818619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x40, 0x42, 0x44, 0x44}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0x18, 0x28, 0x38, 0x38}, /* .mediatype       Media type  [Note 2]        */
    MINUTES(1),               /* .non_motion_time                             */
    MINUTES(18),              /* .io_time                                     */
    MINUTES(9),               /* .rewind_time                                 */
    MINUTES(165),             /* .space_time      worst case directory invalid*/
    MINUTES(9),               /* .load_time                                   */
    MINUTES(12),              /* .unload_time                                 */
    MINUTES(160)              /* .erase_time                                  */
  },

  /*
   * [1] The IBM Ultrium Gen 3 "IBM" version has three densites at this time,
   *     One for Gen 1 0x40, One for Gen 2 0x42 and Gen 3 0x44.
   *     This drive is configured with ST_KNOWS_MEDIA.
   *     That means that it will look at the mediatype from the mode sense
   *     to select the density code. The compression will be selected based
   *     on the minor node the user opened.
   * [2] The IBM LTO reports a medium type that is used to select the density.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "IBM Ultrium Gen 3 LTO",  /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "IBM     ULT3580-TD3",    /* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*  0000001           Supports variable length  */
    ST_BSF              |     /*  0000008           Supports SPACE block fwd  */
    ST_BSR              |     /*  0000010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*  0000200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*  0000400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*  0008000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP    |     /*  0010000           [Note 1]                  */
    ST_KNOWS_MEDIA      |     /*  0800000         Media detrmines density     */
    ST_WORMABLE,              /*  1000000         Is WORM capable             */
                              /*  -------                                     */
                              /*  1818619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x40, 0x42, 0x44, 0x44}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0x18, 0x28, 0x38, 0x38}, /* .mediatype       Media type  [Note 2]        */
    MINUTES(1),               /* .non_motion_time                             */
    MINUTES(18),              /* .io_time                                     */
    MINUTES(9),               /* .rewind_time                                 */
    MINUTES(165),             /* .space_time      worst case directory invalid*/
    MINUTES(9),               /* .load_time                                   */
    MINUTES(12),              /* .unload_time                                 */
    MINUTES(160)              /* .erase_time                                  */
  },

  /*
   * [1] The IBM Ultrium Gen 2 "OEM" version has two densites at this time,
   *     One for Gen 1 0x40, One for Gen 2 0x42. In reallity The media
   *     Selects which density code is used but this documents the codes
   *     for those who care to know.
   *     Compression is controlled via the Compression mode page.
   * [2] The IBM Ultrium has only one speed (if the driver ever cares).
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "IBM Ultrium Gen 2 LTO",  /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "IBM     ULTRIUM-TD2",    /* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           [Note 1]                  */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x40, 0x40, 0x42, 0x42}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    MINUTES(1),               /* .non_motion_time                             */
    MINUTES(18),              /* .io_time                                     */
    MINUTES(9),               /* .rewind_time                                 */
    MINUTES(151),             /* .space_time      worst case directory invalid*/
    MINUTES(12),              /* .load_time                                   */
    MINUTES(11),              /* .unload_time                                 */
    MINUTES(151)              /* .erase_time                                  */
  },

  /*
   * [1] The IBM Ultrium Gen 2 "IBM" version has two densites at this time,
   *     One for Gen 1 0x40, One for Gen 2 0x42. In reallity The media
   *     Selects which density code is used but this documents the codes
   *     for those who care to know.
   *     Compression is controlled via the Compression mode page.
   * [2] The IBM Ultrium has only one speed (if the driver ever cares).
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "IBM Ultrium Gen 2 LTO",  /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "IBM     ULT3580-TD2",    /* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           [Note 1]                  */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x40, 0x40, 0x42, 0x42}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    MINUTES(1),               /* .non_motion_time                             */
    MINUTES(18),              /* .io_time                                     */
    MINUTES(9),               /* .rewind_time                                 */
    MINUTES(151),             /* .space_time      worst case directory invalid*/
    MINUTES(12),              /* .load_time                                   */
    MINUTES(11),              /* .unload_time                                 */
    MINUTES(151)              /* .erase_time                                  */
  },

  /*
   * [1] The IBM Ultrium has only one density at this time,
   *     Compression is controlled via the Device Configuration mode page.
   * [2] The IBM Ultrium has only one speed (if the driver ever cares).
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "IBM Ultrium LTO",        /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "IBM     ULTRIUM-TD1",    /* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           [Note 1]                  */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x40, 0x40, 0x40, 0x40}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    MINUTES(1),               /* .non_motion_time                             */
    MINUTES(18),              /* .io_time                                     */
    MINUTES(8),               /* .rewind_time                                 */
    MINUTES(173),             /* .space_time      worst case directory invalid*/
    MINUTES(11),              /* .load_time                                   */
    MINUTES(11),              /* .unload_time                                 */
    MINUTES(173)              /* .erase_time                                  */
  },

  /*
   * This is the same drive as the above except for the inquiry string and
   * that it is a "End User Version".
   * [1] The IBM Ultrium has only one density at this time,
   *     Compression is controlled via the Device Configuration mode page.
   * [2] The IBM Ultrium has only one speed (if the driver ever cares).
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "IBM Ultrium LTO",        /* .name            Display ("pretty") name     */
    19,                       /* .length          Length of next item...      */
    "IBM     ULT3580-TD1",    /* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           [Note 1]                  */
                              /*    -----                                     */
                              /*    18619                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x40, 0x40, 0x40, 0x40}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    MINUTES(1),               /* .non_motion_time                             */
    MINUTES(18),              /* .io_time                                     */
    MINUTES(8),               /* .rewind_time                                 */
    MINUTES(173),             /* .space_time      worst case directory invalid*/
    MINUTES(11),              /* .load_time                                   */
    MINUTES(11),              /* .unload_time                                 */
    MINUTES(173)              /* .erase_time                                  */
  },

  /*
   * [1] The IBM 3592 Cartridge has only one density at this time,
   *     Compression is controlled via the Device Configuration mode page.
   * [2] The IBM 3592 Cartridge has only one speed (if the driver ever cares).
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "IBM 3592 Cartridge",     /* .name            Display ("pretty") name     */
    13,                       /* .length          Length of next item...      */
    "IBM     03592",          /* .vid             Vendor-product ID string    */
    MT_LTO,                   /* .type            Numeric type (cf. mtio.h)   */
    0,                        /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_VARIABLE         |     /*    00001           Supports variable length  */
    ST_BSF              |     /*    00008           Supports SPACE block fwd  */
    ST_BSR              |     /*    00010           Supports SPACE block rev  */
    ST_AUTODEN_OVERRIDE |     /*    00040           Autodensity override flag */
    ST_KNOWS_EOD        |     /*    00200           Recognizes end-of-data    */
    ST_UNLOADABLE       |     /*    00400           Driver can be unloaded    */
    ST_NO_RECSIZE_LIMIT |     /*    08000           Supports blocks > 64KB    */
    ST_MODE_SEL_COMP,         /*    10000           [Note 1]                  */
                              /*    -----                                     */
                              /*    18659                                     */
    -1,                       /* .max_rretries    Not used any more.          */
    -1,                       /* .max_wretries    Not used any more.          */
    {0x51, 0x51, 0x51, 0x51}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY4,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0},             /* .speeds          Speed codes [Note 2]        */
    MINUTES(1),               /* .non_motion_time                             */
    MINUTES(18),              /* .io_time                                     */
    MINUTES(8),               /* .rewind_time                                 */
    MINUTES(14),              /* .space_time      worst case directory invalid*/
    MINUTES(12),              /* .load_time                                   */
    MINUTES(12),              /* .unload_time                                 */
    MINUTES(235)              /* .erase_time                                  */
  },

  /*
   * Seagate Hornet NS20 USB Travan
   *
   *     NOTES
   *     -----
   *  o This drive is not OEM'ed or qualified by Sun.
   *
   * [1] The NS20 Travan uses 0 or the "default" density code.
   * [2] The NS20 Travan has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Seagate Hornet NS20 Travan",
                              /* .name            Display ("pretty") name     */
    17,                       /* .length          Length of next item...      */
    "Seagate STT20000A",      /* .vid             Vendor-product ID string    */
    MT_ISQIC,                 /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC              |     /*    00002           QIC tape device           */
    ST_BSF              |     /*    00008           Supports back SPACE file  */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0040A                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY1,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  },


  /*
   * Seagate Hornet Travan 40
   *
   *     NOTES
   *     -----
   *  o This drive is not OEM'ed or qualified by Sun.
   *
   * [1] The Travan uses 0 or the "default" density code.
   * [2] The Travan has only one speed (if the driver ever cares).
   * [3] max_rretries and max_wretries are driver anachronisms.
   */
  {                           /* Structure member Description                 */
                              /* ---------------- -----------                 */
    "Seagate Hornet Travan 40",
                              /* .name            Display ("pretty") name     */
    16,                       /* .length          Length of next item...      */
    "Seagate STT3401A",       /* .vid             Vendor-product ID string    */
    MT_ISQIC,                 /* .type            Numeric type (cf. mtio.h)   */
    512,                      /* .bsize           Block size (0 = variable)   */
                              /* .options         Drive option flags:         */
    ST_QIC              |     /*    00002           QIC tape device           */
    ST_BSF              |     /*    00008           Supports back SPACE file  */
    ST_UNLOADABLE,            /*    00400           Driver can be unloaded    */
                              /*    -----                                     */
                              /*    0040A                                     */
    400,                      /* .max_rretries    [Note 3]                    */
    400,                      /* .max_wretries    [Note 3]                    */
    {0x00, 0x00, 0x00, 0x00}, /* .densities       Density codes [Note 1]      */
    MT_DENSITY1,              /* .default_density (.densities[x])             */
    {0, 0, 0, 0}              /* .speeds          Speed codes [Note 2]        */
  }

	/* END CSTYLED */

};


const int st_ndrivetypes = (sizeof (st_drivetypes)/sizeof (st_drivetypes[0]));
