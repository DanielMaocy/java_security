package com.md5;

import java.security.MessageDigest;

public class MD5 {
	
	private static final String hexDigits[] = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

	/**
	 * MD5Ç©Ãû
	 * @param str
	 * @return
	 */
	public static String sign(String str) {
		String result = "";
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			result = byteArrayToHexString(md.digest(str.getBytes("utf-8")));
		} catch (Exception exception) {
		}
		
		return result;
	}
	
	private static String byteArrayToHexString(byte b[]) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < b.length; i++){
			result.append(byteToHexString(b[i]));
		}

		return result.toString();
	}

	private static String byteToHexString(byte b) {
		int n = b;
		if (n < 0){
			n += 256;
		}
		int d1 = n / 16;
		int d2 = n % 16;
		
		return hexDigits[d1] + hexDigits[d2];
	}
}
