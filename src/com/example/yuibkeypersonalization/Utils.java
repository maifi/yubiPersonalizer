package com.example.yuibkeypersonalization;

import java.util.Arrays;

/***
 * Support functions for byte array handling.
 * 
 * @author christian.lesjak@student.tugraz.at
 * 
 */
public final class Utils {

	/***
	 * Converts a byte array to a hex string.
	 * 
	 * @param b
	 *            byte array to be converted
	 * @return resulting hex string
	 */
	public static String byteArrayToHexString(byte[] b) {
		// check
		if (b == null || b.length == 0) {
			return "";
		}
		
		// init
		StringBuffer sb = new StringBuffer(b.length * 2);

		// convert
		for (int i = 0; i < b.length; i++) {
			int v = b[i] & 0xff;
			if (v < 16) {
				sb.append('0');
			}
			sb.append(Integer.toHexString(v));
		}

		// return
		return (sb.toString().trim().toUpperCase());
	}

	// Convert hex string back to byte array
	public static byte[] hexStringToByteArray(String str) {
		// check input
		if (!str.matches("[0-9A-F]+"))
			return (null);
		if ((str.length() % 2) != 0)
			return (null);

		// init
		byte[] bytes = new byte[str.length() / 2];

		// convert
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(str.substring(2 * i, 2 * i + 2),
					16);
		}

		// return
		return (bytes);
	}

	/***
	 * Concats multiple byte arrays.
	 * 
	 * @param first
	 *            first byte array
	 * @param rest
	 *            subsequent byte arrays that will be concatenated to the first
	 * @return concatenation of all byte arrays.
	 */
	public static byte[] concatAll(byte[] first, byte[]... rest) {
		// init
		int totalLength = first.length;
		for (byte[] array : rest) {
			totalLength += array.length;
		}
		byte[] result = Arrays.copyOf(first, totalLength);
		int offset = first.length;

		// concat
		for (byte[] array : rest) {
			System.arraycopy(array, 0, result, offset, array.length);
			offset += array.length;
		}

		// return
		return result;
	}

	/***
	 * Compares two byte arrays for equal length and content.
	 * 
	 * @param first
	 *            first byte array
	 * @param second
	 *            second byte array
	 * @return true on equality, false otherwise
	 */
	public static boolean areEqual(byte[] first, byte[] second) {
		// check some weird cases
		if (first == second)
			return (true);
		if (first == null && second != null)
			return (false);
		if (first != null && second == null)
			return (false);
		if (first.length != second.length)
			return (false);

		// check content
		for (int i = 0; i < first.length; i++)
			if (first[i] != second[i])
				return (false);

		// return success
		return (true);
	}
	
	/**
	 * Converts a two byte return value(apdu) into an integer value
	 */
	public static int bytesToInt(byte hi, byte lo){

		int _hi = hi,_lo = lo;
		if(hi<0) _hi = hi+256;
		if(lo<0) _lo = lo+256;

		return (_hi<<8 | _lo);
	}
	
	/**
	 * Returns a String in the form [11,22,33] ;
	 * @param b
	 * @return
	 */
	public static String byteArrayToArrayString(byte[] b) {
		// check
		if (b == null || b.length == 0) {
			return "";
		}
		
		// init
		StringBuffer sb = new StringBuffer(b.length * 2);

		// convert
		for (int i = 0; i < b.length; i++) {
			int v = b[i] & 0xff;

			sb.append(v);
			if(i<b.length -1)
				sb.append(",");
		}

		sb.insert(0, "[");
		sb.append("]");

		// return
		return (sb.toString());
	}
}
