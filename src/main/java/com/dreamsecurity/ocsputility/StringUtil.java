package com.dreamsecurity.ocsputility;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;


/**
 * String manipulative functions
 * @author dream
 *
 */
public class StringUtil {

	public static String getSubstringBefore(String strToParse, String substrSeparator, boolean searchFromEnd) {
        if ((strToParse == null) || (substrSeparator == null)) {
            return strToParse;
        }
        String strParsed = strToParse;
        int nPos = 0;
        if (searchFromEnd == false) {
            nPos = strParsed.indexOf(substrSeparator);
        } else {
            nPos = strParsed.lastIndexOf(substrSeparator);
        }
        if (nPos == -1) {
            nPos = strToParse.length();
        }
        return strParsed.substring(0, nPos);
    }
    
    /**
     * Returns a substring after a given substring separator. Substring can be
     * an empty string if input string ends with substring separator. If
     * separator was not found, input string will be returned.
     * 
     * @param strToParse
     *            String to parse
     * @param substrSeparator
     *            Substring separator
     * @param searchFromEnd
     *            If true, string to parse will be searched backwards
     * 
     * @return Substring if separator was found; else input string
     */
    public static String getSubstringAfter(String strToParse, String substrSeparator, boolean searchFromEnd) {
        if ((strToParse == null) || (substrSeparator == null)) {
            return strToParse;
        }
        String strParsed = strToParse;
        int nPos = 0;
        if (searchFromEnd == false) {
            nPos = strParsed.indexOf(substrSeparator);
        } else {
            nPos = strParsed.lastIndexOf(substrSeparator);
        }
        if (nPos == -1) {
            return strToParse;
        } else if (nPos >= (strParsed.length() - 1)) {
            return "";
        }
        return strParsed.substring(nPos + substrSeparator.length(), strParsed.length());
    }
    
    public static int[] commaSeparatedStringToIntArray(String commaSeparatedString) {
        String[] sResult = commaSeparatedStringToStringArray(commaSeparatedString);
        if (sResult == null) {
            return null;
        } else {
            int[] result = new int[sResult.length];
            for (int i = 0; i < result.length; i++) {
                result[i] = Integer.valueOf(sResult[i]);
            }
            return result;
        }
    }
    
    public static String[] commaSeparatedStringToStringArray(String commaSeparatedString) {
        if (commaSeparatedString == null || commaSeparatedString.trim().isEmpty()) {
            return null;
        } else {
            return commaSeparatedString.split(",");
        }
    }
    
    public static String arrayToCommaSeparatedString(int[] array) {
        if (array == null) {
            return null;
        }
        StringBuffer result = new StringBuffer();
        for (int i = 0; i < array.length; i++) {
            result.append(array[i] + (i == array.length - 1 ? "" : ", "));
        }
        return result.toString();
    }
    public static String arrayToCommaSeparatedString(String[] array) {
        if (array == null) {
            return null;
        }
        StringBuffer result = new StringBuffer();
        for (int i = 0; i < array.length; i++) {
            result.append(array[i] + (i == array.length - 1 ? "" : ", "));
        }
        return result.toString();
    }
    
    public static String listToCommaSeparatedString(List<String> list) {
        if (list == null) {
            return null;
        }
        StringBuffer result = new StringBuffer();
        for (int i = 0; i < list.size(); i++) {
            result.append(list.get(i) + (i == list.size() - 1 ? "" : ", "));
        }
        return result.toString();
    }
    
    /**
     * Returns true if 's' contains 'searchFor', ignoring case. 
     * @param s
     * @param searchFor
     * @return
     */
    public static boolean containsIgnoreCase(String s, String searchFor) {
        return s.toLowerCase().contains(searchFor.toLowerCase());
    }
    
    /**
     * Returns true if the passed list contains the passed String s, ignoring
     * case.
     * 
     * @param list
     * @param s
     * @return
     */
    public static boolean containsIgnoreCase(List<String> list, String s){
        for (String string : list) {
            if( string.toLowerCase().equals(s.toLowerCase())){
                return true;
            }
        }
        return false;
    }
    
    /**
     * Returns true if the passed <i>map</a> contains the passed {@link String} key <i>key</i>, ignoring
     * case.
     * 
     * @param map
     * @param key
     * @return
     */
    public static boolean containsKeyIgnoreCase(Map<String, ?> map, String key) {
        Set<String> keys = map.keySet();
        for (String string : keys) {
            if (key.equalsIgnoreCase(string)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Get a string from <i>map</i> irgnoring the case of the key
     * @param map
     * @param key
     * @return
     */
    public static String getIgnoreCase(Map<String, String> map, String key) {
        Set<String> keys = map.keySet();
        for (String string : keys) {
            if (key.equalsIgnoreCase(string)) {
                return map.get(string);
            }
        }
        return null;
    }
    
    /**
     * Creates a new {@link List<?>} of {@link String} and adds <i>s</i> to it
     * @param s
     * @return
     */
    public static List<String> createList(String s){
        List<String> result = new ArrayList<String>();
        result.add(s);
        return result;
    }
    
    /**
	 * Reads an {@link InputStream} into a byte array
	 * 
	 * @param is
	 *            The {@link InputStream} to be read
	 * @return The read byte array
	 * @throws IOException
	 */
	public static byte[] inputStreamToBytes(InputStream is) throws IOException
	{
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int nRead;
		byte[] data = new byte[16384];
		while ((nRead = is.read(data, 0, data.length)) != -1)
		{
			buffer.write(data, 0, nRead);
		}
		buffer.flush();
		return buffer.toByteArray();
	}
	
	public static byte[] convertUUID(UUID uuid) {
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return bb.array();
    }
    
  
    /**
     * Concatenates the given arrays in order of their occurence
     * @param arrays
     * @return
     */
    public static byte[] concatArrays(byte[]... arrays) {
        int size = 0;
        for (byte[] cur : arrays) {
            if (cur == null)
                continue;
            size = size + cur.length;
        }
        
        byte[] out = new byte[size];
        
        int curPos = 0;
        for (byte[] cur : arrays) {
            if (cur == null)
                continue;
            System.arraycopy(cur, 0, out, curPos, cur.length);
            curPos = curPos + cur.length;
        }
        
        return out;
    }
    
    /**
     * Removes leading zero bytes from a byte array
     * @param in
     * @return
     */
    public static byte[] removeLeadingZeros(byte[] in) {
        if (in.length > 1) {
            
            int i = 0;
            while (in[i] == 0x00) {
                i++;
            }
            
            byte[] out = new byte[in.length - i];
            System.arraycopy(in, i, out, 0, in.length - i);
            
            return out;
        }
        return in;
    }
	
}
