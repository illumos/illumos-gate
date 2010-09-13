<?xml version="1.0" encoding="utf-8" ?>

<!--
   * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
   * Use is subject to license terms.
   *
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
   *
   * ident	"%Z%%M%	%I%	%E% SMI"
   *
   * Used by metassist(1M) to create a Bourne shell script from an XML
   * file conforming to the volume-config DTD.
   *
   * See volume-config(4) for a detailed description of the volume-
   * config syntax.
   -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>

  <!-- Set a default lang -->
  <xsl:param name="lang">en</xsl:param>

  <!-- The file containing localized <message> elements -->
  <!-- Currently set to local doc until an i18n scheme is established -->
  <xsl:variable name="msgfile" select="document('')"/>
  <xsl:variable name="langprefix" select="substring-before($lang,'-')"/>

  <!-- Root template -->
  <xsl:template match="/">

    <!-- Use Bourne shell -->
    <xsl:text>#!/bin/sh

#
# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Environment</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
#

# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Amend PATH</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
PATH="/usr/sbin:/usr/bin:$PATH"
export PATH

# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Disk set name</xsl:with-param>
    </xsl:call-template>

    <!-- Set disk set -->
    <xsl:text>&#x0a;</xsl:text>
    <xsl:text>diskset='</xsl:text>
    <xsl:value-of select="//diskset/@name" />

    <!-- &#x0a; is a newline entity -->
    <xsl:text>'&#x0a;</xsl:text>

    <xsl:text>
#
# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Functions</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
#

# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Echo (verbose) and exec given command, exit on error</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
execho () {
    test -n "$verbose" &amp;&amp; echo "$@"
    "$@" || exit
}

# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Get full /dev/rdsk path of given slice</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
fullpath () {
    case "$1" in
        /dev/dsk/*|/dev/did/dsk/*) echo "$1" | sed 's/dsk/rdsk/' ;;
        /*) echo "$1" ;;
        *) echo /dev/rdsk/"$1" ;;
    esac
}

# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Run fmthard, ignore partboot error, error if output</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
fmthard_special () {
    ignore='Error writing partboot'
    out=`fmthard "$@" 2&gt;&amp;1`
    result=$?
    echo "$out" |
    case "$out" in
        *"$ignore"*) grep -v "$ignore"; return 0 ;;
        '') return "$result" ;;
        *) cat; return 1 ;;
    esac &gt;&amp;2
}

#
# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Main</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
#

# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Verify root</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
if [ "`id | sed 's/^[^(]*(\([^)]*\).*/\1/'`" != root ]
then
    echo "</xsl:text>

    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">This script must be run as root.</xsl:with-param>
    </xsl:call-template>

    <xsl:text>" >&amp;2
    exit 1;
fi

# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Check for verbose option</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
case "$1" in
    -v) verbose=1 ;;
    *) verbose= ;;
esac
    </xsl:text>

    <!-- Create disk set -->
    <xsl:apply-templates select="//diskset" mode="create"/>

    <!-- Format unused slices -->
    <xsl:apply-templates select="//slice[@sizeinblocks = 0]" mode="create"/>

    <!-- Add disks to set -->
    <xsl:apply-templates select="//disk" mode="add"/>

    <!-- Format used slices -->
    <xsl:apply-templates select="//slice[@sizeinblocks != 0]" mode="create"/>

    <!-- Create HSPs -->
    <xsl:apply-templates select="//hsp" mode="create"/>

    <!-- Create stripes -->
    <xsl:apply-templates select="//stripe" mode="create"/>

    <!-- Create concats -->
    <xsl:apply-templates select="//concat" mode="create"/>

    <!-- Create mirrors -->
    <xsl:apply-templates select="//mirror" mode="create"/>

  </xsl:template>

  <!-- "Create disk set" template -->
  <xsl:template match="diskset" mode="create">
    <xsl:text>&#x0a;# </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Does the disk set exist?</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
if metaset -s "$diskset" >/dev/null 2>&amp;1
then
    # </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Take control of disk set</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
    execho metaset -s "$diskset" -t
else
    # </xsl:text>
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Create the disk set</xsl:with-param>
    </xsl:call-template>

    <xsl:text>
    autotakeargs=
    /usr/sbin/clinfo || autotakeargs='-A enable'
    execho metaset -s "$diskset" $autotakeargs -a -h `uname -n | cut -f1 -d.`
fi
    </xsl:text>
  </xsl:template>

  <!-- "Add disk" template -->
  <xsl:template match="disk" mode="add">
    <!-- Add comment -->
    <xsl:if test="position() = 1">
      <xsl:text>&#x0a;# </xsl:text>
      <xsl:call-template name="gettext">
        <xsl:with-param name="msgid">Add disks to set</xsl:with-param>
      </xsl:call-template>
      <xsl:text>&#x0a;</xsl:text>
    </xsl:if>

    <!-- Output command -->
    <xsl:call-template name="parameterize">
      <xsl:with-param name="string">execho metaset -s "$diskset" -a {1}</xsl:with-param>
      <xsl:with-param name="1" select="@name"/>
    </xsl:call-template>

    <xsl:text>&#x0a;</xsl:text>
  </xsl:template>

  <!-- "Create slice" template -->
  <xsl:template match="slice" mode="create">

    <!-- Add comment -->
    <xsl:if test="position() = 1">
      <xsl:text>&#x0a;# </xsl:text>
      <xsl:call-template name="gettext">
        <xsl:with-param name="msgid">Format slices</xsl:with-param>
      </xsl:call-template>
      <xsl:text>&#x0a;</xsl:text>
    </xsl:if>

    <!-- Does this slice have a start sector and size? -->
    <xsl:if test="(@startsector and @sizeinblocks) or (@sizeinblocks = 0)">

      <!-- Output command -->
      <xsl:call-template name="parameterize">
        <xsl:with-param name="string">execho fmthard_special -d {1}:{5}:0:{2}:{3} `fullpath {4}`</xsl:with-param>
        <xsl:with-param name="1">
          <xsl:call-template name="getslice">
            <xsl:with-param name="device" select="@name" />
          </xsl:call-template>
        </xsl:with-param>
        <xsl:with-param name="2">
          <xsl:choose>
            <!-- When zeroing out a slice, use 0 for start sector -->
            <xsl:when test="@sizeinblocks = 0">0</xsl:when>
            <!-- Otherwise, use the start sector supplied -->
            <xsl:otherwise>
              <xsl:value-of select="@startsector" />
            </xsl:otherwise>
          </xsl:choose>
        </xsl:with-param>
        <xsl:with-param name="3" select="@sizeinblocks" />
        <xsl:with-param name="4" select="@name" />
        <xsl:with-param name="5">
          <xsl:choose>
            <!-- When zeroing out a slice, use 0 (V_UNASSIGNED) slice tag -->
            <xsl:when test="@sizeinblocks = 0">0</xsl:when>
            <!-- Otherwise, use 4 (V_USR) -->
            <xsl:otherwise>4</xsl:otherwise>
          </xsl:choose>
        </xsl:with-param>
      </xsl:call-template>

      <xsl:text>&#x0a;</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- Template for a "create volume" comment -->
  <xsl:template name="createdevcomment">
    <!-- Indent parameter -->
    <xsl:param name = "indent" />

    <xsl:text>&#x0a;</xsl:text>
    <xsl:value-of select="$indent" />
    <xsl:text># </xsl:text>

    <!-- Add comment -->
    <xsl:call-template name="gettext">
      <xsl:with-param name="msgid">Create {1} {2}</xsl:with-param>
      <xsl:with-param name="1" select="name()"/>
      <xsl:with-param name="2" select="@name"/>
    </xsl:call-template>

    <xsl:text>&#x0a;</xsl:text>
  </xsl:template>

  <!-- "Create hsp" template -->
  <xsl:template match="hsp" mode="create">

    <!-- Does this HSP contain slice elements? -->
    <xsl:if test="slice">

      <xsl:text>&#x0a;# </xsl:text>

      <!-- Add comment -->
      <xsl:call-template name="gettext">
        <xsl:with-param name="msgid">Does {1} exist?</xsl:with-param>
        <xsl:with-param name="1" select="@name"/>
      </xsl:call-template>

      <xsl:text>&#x0a;</xsl:text>

      <!-- Output command to test for existence of HSP -->
      <xsl:call-template name="parameterize">
        <xsl:with-param name="string">metahs -s "$diskset" -i {1} >/dev/null 2>&amp;1 || {</xsl:with-param>
        <xsl:with-param name="1" select="@name"/>
      </xsl:call-template>

      <!-- Add comment -->
      <xsl:call-template name="createdevcomment">
        <xsl:with-param name = "indent" xml:space="preserve">    </xsl:with-param>
      </xsl:call-template>

      <!-- Output command to create HSP -->
      <xsl:call-template name="parameterize">
        <xsl:with-param name="string">    execho metainit -s "$diskset" {1}</xsl:with-param>
        <xsl:with-param name="1" select="@name"/>
      </xsl:call-template>

      <xsl:text>&#x0a;}&#x0a;&#x0a;# </xsl:text>

      <!-- Add comment -->
      <xsl:call-template name="gettext">
        <xsl:with-param name="msgid">Add slices to {1}</xsl:with-param>
        <xsl:with-param name="1" select="@name"/>
      </xsl:call-template>

      <xsl:text>&#x0a;</xsl:text>

      <xsl:for-each select="slice">

        <!-- Output command -->
        <xsl:call-template name="parameterize">
          <xsl:with-param name="string">execho metahs -s "$diskset" -a {1} {2}</xsl:with-param>
          <xsl:with-param name="1" select="../@name"/>
          <xsl:with-param name="2" select="@name"/>
        </xsl:call-template>

        <xsl:text>&#x0a;</xsl:text>

      </xsl:for-each>
    </xsl:if>

  </xsl:template>

  <!-- "Create stripe/concat" template -->
  <xsl:template match="stripe|concat" mode="create">

    <!-- Does this stripe/concat contain slice elements? -->
    <xsl:if test="slice">

      <!-- Add comment -->
      <xsl:call-template name="createdevcomment"/>

      <!-- Output command -->
      <xsl:text>execho metainit -s "$diskset" </xsl:text>
      <xsl:value-of select="@name" />

      <xsl:choose>
        <!-- Stripe-specific parameters -->
        <xsl:when test="name() = 'stripe'">
          <xsl:text> 1 </xsl:text>
          <xsl:value-of select="count(slice)" />

          <xsl:for-each select="slice">
            <xsl:text> </xsl:text>
            <xsl:value-of select="@name" />
          </xsl:for-each>

          <!-- Does this stripe contain an interlace attribute? -->
          <xsl:if test="@interlace">

            <!-- Write interlace with unit string -->
            <xsl:variable name="interlace"
              select="substring-before(@interlace, 'KB')"/>
            <xsl:choose>
              <xsl:when test="$interlace != ''">
                <xsl:value-of select="concat(' -i ', $interlace, 'k')" />
              </xsl:when>
              <xsl:otherwise>
                <xsl:variable name="interlace"
                  select="substring-before(@interlace, 'MB')"/>
                <xsl:choose>
                  <xsl:when test="$interlace != ''">
                    <xsl:value-of select="concat(' -i ', $interlace, 'm')" />
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:variable name="interlace"
                      select="substring-before(@interlace, 'BLOCKS')"/>
                    <xsl:if test="$interlace != ''">
                      <xsl:value-of select="concat(' -i ', $interlace, 'b')" />
                    </xsl:if>
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:if>
        </xsl:when>

        <!-- Concat-specific parameters -->
        <xsl:otherwise>
          <xsl:text> </xsl:text>
          <xsl:value-of select="count(slice)" />

          <xsl:for-each select="slice">
            <xsl:text> 1 </xsl:text>
            <xsl:value-of select="@name" />
          </xsl:for-each>
        </xsl:otherwise>
      </xsl:choose>

      <xsl:text>&#x0a;</xsl:text>
    </xsl:if>

    <!-- Does this stripe/concat contain hsp elements? -->
    <xsl:if test="hsp">

      <xsl:text>&#x0a;# </xsl:text>

      <!-- Add comment -->
      <xsl:call-template name="gettext">
        <xsl:with-param name="msgid">Associate {1} {2} with hot spare pool {3}</xsl:with-param>
        <xsl:with-param name="1" select="name()"/>
        <xsl:with-param name="2" select="@name"/>
        <xsl:with-param name="3" select="hsp/@name"/>
      </xsl:call-template>

      <xsl:text>&#x0a;</xsl:text>

      <!-- Output command -->
      <xsl:call-template name="parameterize">
        <xsl:with-param name="string">execho metaparam -s "$diskset" -h {1} {2}</xsl:with-param>
        <xsl:with-param name="1" select="hsp/@name"/>
        <xsl:with-param name="2" select="@name"/>
      </xsl:call-template>

      <xsl:text>&#x0a;</xsl:text>
    </xsl:if>
  </xsl:template>

  <!-- "Create mirror" template -->
  <xsl:template match="mirror" mode="create">
    <!-- Add comment -->
    <xsl:call-template name="createdevcomment"/>

    <!-- Attach submirrors -->
    <xsl:for-each select="stripe|concat">
      <xsl:choose >
        <xsl:when test="position() = 1">

          <!-- Output create command -->
          <xsl:call-template name="parameterize">
            <xsl:with-param name="string">execho metainit -s "$diskset" {1} -m {2}</xsl:with-param>
            <xsl:with-param name="1" select="../@name"/>
            <xsl:with-param name="2" select="@name"/>
          </xsl:call-template>

          <!-- Read option -->
          <xsl:choose >
            <!-- Geometric -->
            <xsl:when test="../@read = 'GEOMETRIC'">
              <xsl:text> -g</xsl:text>
            </xsl:when>

            <!-- First -->
            <xsl:when test="../@read = 'FIRST'">
              <xsl:text> -r</xsl:text>
            </xsl:when>
          </xsl:choose>

          <!-- Write option - serial -->
          <xsl:if test="../@write = 'SERIAL'">
            <xsl:text> -S</xsl:text>
          </xsl:if>

          <!-- Pass number -->
          <xsl:if test="../@passnum">
            <xsl:text> </xsl:text>
            <xsl:value-of select="../@passnum" />
          </xsl:if>

          <xsl:text>&#x0a;</xsl:text>
        </xsl:when>

        <xsl:otherwise>
          <!-- Output attach command -->
          <xsl:call-template name="parameterize">
            <xsl:with-param name="string">execho metattach -s "$diskset" {1} {2}</xsl:with-param>
            <xsl:with-param name="1" select="../@name"/>
            <xsl:with-param name="2" select="@name"/>
          </xsl:call-template>

          <xsl:text>&#x0a;</xsl:text>
        </xsl:otherwise>
      </xsl:choose>
    </xsl:for-each>
  </xsl:template>

  <!-- Get the slice index from a device string -->
  <xsl:template name="getslice">
    <xsl:param name="device" />

    <xsl:choose>

      <!-- Does $device contain 's'? -->
      <xsl:when test="contains($device, 's')">

        <!-- Recurse with remaining text -->
        <xsl:call-template name="getslice">
          <xsl:with-param name="device" select="substring-after($device, 's')" />
        </xsl:call-template>
      </xsl:when>

      <!-- No match -->
      <xsl:otherwise>
        <xsl:value-of select="$device" />
      </xsl:otherwise>

    </xsl:choose>
  </xsl:template>

  <!-- Generic (global) search and replace template -->
  <xsl:template name="searchreplace">
    <xsl:param name="text" />
    <xsl:param name="search" />
    <xsl:param name="replace" />

    <xsl:choose>

      <!-- Does $text contain $search? -->
      <xsl:when test="contains($text, $search)">

        <!-- Print text before match -->
        <xsl:value-of select="substring-before($text, $search)" />

        <!-- Print replaced text -->
        <xsl:value-of select="$replace" />

        <!-- Recurse with remaining text -->
        <xsl:call-template name="searchreplace">
          <xsl:with-param name="text" select="substring-after($text, $search)" />
          <xsl:with-param name="search" select="$search" />
          <xsl:with-param name="replace" select="$replace" />
        </xsl:call-template>
      </xsl:when>

      <!-- No match -->
      <xsl:otherwise>
        <xsl:value-of select="$text" />
      </xsl:otherwise>

    </xsl:choose>
  </xsl:template>

  <!--
     * Given a message ID (msgid), find a localized message string
     * stored in $msgfile as a xsl:variable.  Return the first
     * occurance of:
     *
     * 1. The message localized for the language code and country
     *    code, ie. "en-us"
     *
     * 2. The message localized for a sublanguage
     *
     * 3. The message localized for the language code only, ie. "en"
     *
     * 4. The message localized for the language code, with any
     *    country code, ie. "en-gb"
     *
     * 5. $msgid
     *
     * Parameters:
     *
     *    msgid: The message identification key
     *
     *    1, 2, 3, 4, 5: Parameters to replace "{1}", "{2}", "{3}",
     *    "{4}", "{5}" respectively, in the retrieved message
     -->
  <xsl:template name="gettext">
    <xsl:param name="msgid"/>
    <xsl:param name="1"/>
    <xsl:param name="2"/>
    <xsl:param name="3"/>
    <xsl:param name="4"/>
    <xsl:param name="5"/>
    <xsl:variable name="messages" select="$msgfile//message[@msgid=$msgid]"/>

    <xsl:call-template name="parameterize">
      <xsl:with-param name="1" select="$1"/>
      <xsl:with-param name="2" select="$2"/>
      <xsl:with-param name="3" select="$3"/>
      <xsl:with-param name="4" select="$4"/>
      <xsl:with-param name="5" select="$5"/>
      <xsl:with-param name="string">

        <xsl:choose>

          <!-- Exact match for $lang -->
          <xsl:when test="$messages[@xml:lang=$lang]">
            <xsl:value-of select="$messages[@xml:lang=$lang][1]"/>
          </xsl:when>

          <!-- Sublanguage of $lang -->
          <xsl:when test="$messages[lang($lang)]">
            <xsl:value-of name="message" select="$messages[lang($lang)][1]"/>
          </xsl:when>

          <!-- Exact match for $langprefix -->
          <xsl:when test="$messages[@xml:lang=$langprefix]">
            <xsl:value-of select="$messages[@xml:lang=$langprefix][1]"/>
          </xsl:when>

          <!-- Sublanguage of $langprefix -->
          <xsl:when test="$messages[lang($langprefix)]">
            <xsl:value-of select="$messages[lang($langprefix)][1]"/>
          </xsl:when>

          <!-- No match found, return msgid -->
          <xsl:otherwise>
            <xsl:value-of select="$msgid"/>
          </xsl:otherwise>

        </xsl:choose>
      </xsl:with-param>
    </xsl:call-template>
  </xsl:template>

  <!-- Parameterize up to 5 parameters -->
  <xsl:template name="parameterize">
    <xsl:param name="string"/>
    <xsl:param name="1"/>
    <xsl:param name="2"/>
    <xsl:param name="3"/>
    <xsl:param name="4"/>
    <xsl:param name="5"/>

    <xsl:call-template name="searchreplace">
      <xsl:with-param name="text">
        <xsl:call-template name="searchreplace">
          <xsl:with-param name="text">
            <xsl:call-template name="searchreplace">
              <xsl:with-param name="text">
                <xsl:call-template name="searchreplace">
                  <xsl:with-param name="text">
                    <xsl:call-template name="searchreplace">
                      <xsl:with-param name="text" select="$string"/>
                      <xsl:with-param name="search">{1}</xsl:with-param>
                      <xsl:with-param name="replace" select="$1"/>
                    </xsl:call-template>
                  </xsl:with-param>
                  <xsl:with-param name="search">{2}</xsl:with-param>
                  <xsl:with-param name="replace" select="$2"/>
                </xsl:call-template>
              </xsl:with-param>
              <xsl:with-param name="search">{3}</xsl:with-param>
              <xsl:with-param name="replace" select="$3"/>
            </xsl:call-template>
          </xsl:with-param>
          <xsl:with-param name="search">{4}</xsl:with-param>
          <xsl:with-param name="replace" select="$4"/>
        </xsl:call-template>
      </xsl:with-param>
      <xsl:with-param name="search">{5}</xsl:with-param>
      <xsl:with-param name="replace" select="$5"/>
    </xsl:call-template>
  </xsl:template>

  <!-- Localized message strings used throughout -->
  <xsl:template name="localization">
    <message xml:lang="de" msgid="Sample message">Beispielanzeige</message>
  </xsl:template>

</xsl:stylesheet>
