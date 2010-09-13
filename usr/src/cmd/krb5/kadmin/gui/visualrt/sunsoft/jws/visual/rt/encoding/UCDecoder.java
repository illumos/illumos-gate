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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/**
 * Copyright 1996 Active Software Inc. 
 */

package sunsoft.jws.visual.rt.encoding;

import java.io.*;

// Referenced classes of package sunsoft.jws.visual.rt.encoding:
//            CEStreamExhausted, CRC16

public class UCDecoder
{
    
    protected int bytesPerAtom()
    {
        return 2;
    }
    
    protected int bytesPerLine()
    {
        return 48;
    }
    
    protected void decodeAtom(InputStream inStream,
			      OutputStream outStream, int l)
	throws IOException
    {
        byte a = -1;
        byte b = -1;
        byte c = -1;
        byte tmp[] = new byte[3];
        int i = inStream.read(tmp);
        if (i != 3)
            throw new CEStreamExhausted();
        for (i = 0; i < 64 && (a == -1 || b == -1 || c == -1); i++)
	    {
		if (tmp[0] == map_array[i])
		    a = (byte)i;
		if (tmp[1] == map_array[i])
		    b = (byte)i;
		if (tmp[2] == map_array[i])
		    c = (byte)i;
	    }
        
        byte high_byte = (byte)(((a & 0x38) << 2) + (b & 0x1f));
        byte low_byte = (byte)(((a & 0x7) << 5) + (c & 0x1f));
        int p1 = 0;
        int p2 = 0;
        for (i = 1; i < 256; i *= 2)
	    {
		if ((high_byte & i) != 0)
		    p1++;
		if ((low_byte & i) != 0)
		    p2++;
	    }
        
        int np1 = (b & 0x20) / 32;
        int np2 = (c & 0x20) / 32;
        if ((p1 & 0x1) != np1)
            throw new IOException("UCDecoder: High byte parity error.");
        if ((p2 & 0x1) != np2)
            throw new IOException("UCDecoder: Low byte parity error.");
        outStream.write(high_byte);
        crc.update(high_byte);
        if (l == 2)
	    {
		outStream.write(low_byte);
		crc.update(low_byte);
	    }
    }
    
    protected void decodeBufferPrefix(InputStream inStream,
				      OutputStream outStream)
    {
        sequence = 0;
    }
    
    protected int decodeLinePrefix(InputStream inStream,
				   OutputStream outStream)
	throws IOException
    {
        crc.value = 0;
        do
	    {
		int c = inStream.read(tmp, 0, 1);
		if (c == -1)
		    throw new CEStreamExhausted();
	    }
        while (tmp[0] != 42);
        lineAndSeq.reset();
        decodeAtom(inStream, lineAndSeq, 2);
        byte xtmp[] = lineAndSeq.toByteArray();
        int nLen = xtmp[0] & 0xff;
        int nSeq = xtmp[1] & 0xff;
        if (nSeq != sequence)
	    {
		throw new IOException("UCDecoder: Out of sequence line.");
	    }
        else
	    {
		sequence = sequence + 1 & 0xff;
		return nLen;
	    }
    }
    
    protected void decodeLineSuffix(InputStream inStream,
				    OutputStream outStream)
	throws IOException
    {
        int lineCRC = crc.value;
        lineAndSeq.reset();
        decodeAtom(inStream, lineAndSeq, 2);
        byte tmp[] = lineAndSeq.toByteArray();
        int readCRC = (tmp[0] << 8 & 0xff00) + (tmp[1] & 0xff);
        if (readCRC != lineCRC)
            throw new IOException("UCDecoder: CRC check failed.");
        else
            return;
    }
    
    public void decodeBuffer(InputStream aStream, OutputStream bStream)
	throws IOException
    {
        int totalBytes = 0;
        decodeBufferPrefix(aStream, bStream);
        try
	    {
		do
		    {
			int length = decodeLinePrefix(aStream, bStream);
			int i;
			for (i = 0; i + bytesPerAtom() < length;
			     i += bytesPerAtom())
			    {
				decodeAtom(aStream, bStream, bytesPerAtom());
				totalBytes += bytesPerAtom();
			    }
                
			if (i + bytesPerAtom() == length)
			    {
				decodeAtom(aStream, bStream, bytesPerAtom());
				totalBytes += bytesPerAtom();
			    }
			else
			    {
				decodeAtom(aStream, bStream, length - i);
				totalBytes += length - i;
			    }
			decodeLineSuffix(aStream, bStream);
		    }
		while (true);
	    }
        catch (CEStreamExhausted ex)
	    {
		decodeBufferSuffix(aStream, bStream);
	    }
    }
    
    public byte[] decodeBuffer(String inputString)
	throws IOException
    {
        byte inputBuffer[] = new byte[inputString.length()];
        inputString.getBytes(0, inputString.length(), inputBuffer, 0);
        ByteArrayInputStream inStream =
	    new ByteArrayInputStream(inputBuffer);
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        decodeBuffer(inStream, outStream);
        return outStream.toByteArray();
    }
    
    protected void decodeBufferSuffix(InputStream inputstream,
				      OutputStream outputstream)
	throws IOException
    {
    }
    
    public UCDecoder()
    {
        super();
        tmp = new byte[2];
        crc = new CRC16();
        lineAndSeq = new ByteArrayOutputStream(2);
    }
    
    private static final byte map_array[] = {
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
        85, 86, 87, 88, 89, 90, 97, 98, 99, 100,
        101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
        111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
        121, 122, 40, 41
    };
    private int sequence;
    private byte tmp[];
    CRC16 crc;
    private ByteArrayOutputStream lineAndSeq;
    
}
