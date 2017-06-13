package com.rsa;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import com.sun.org.apache.xml.internal.security.utils.Base64;

public class RSA {
	
	private static String publicKeyStr = ""; // 公钥
	private static String privateKeyStr = ""; // 私钥
	
	/**
	 * 初始化公钥和私钥
	 */
	public static void initKey() {
		try {
			// 实例化秘钥对生成对象
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			
			// 获取秘钥对(公钥和私钥)持有者对象
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			
			RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
			publicKeyStr = Base64.encode(rsaPublicKey.getEncoded());
			privateKeyStr = Base64.encode(rsaPrivateKey.getEncoded());
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e);
		}
	}
	
	/**
	 * 私钥加密
	 * @param str
	 * @return
	 */
	public static String privateKeyEncryption(String str) {
		String encryptionStr = "";
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(Base64.decode(privateKeyStr.getBytes()));
			
			// 实例化指定算法的秘钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			
			// 获取指定算法的Cipher对象
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey); // 初始化为加密模式
			byte[] result = cipher.doFinal(str.getBytes());
			encryptionStr = Base64.encode(result);
		}catch(Exception e) {
			System.out.println(e);
		}

		return encryptionStr;
	}
	
	/**
	 * 公钥解密
	 * @param str
	 * @return
	 */
	public static String publicKeyDecryption(String str) {
		String decryptionStr = "";
		try {
			X509EncodedKeySpec x509EncodedKeySped
					= new X509EncodedKeySpec(Base64.decode(publicKeyStr.getBytes()));
			
			// 实例化指定算法的秘钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			
			// 获取指定算法的Cipher对象
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey); // 初始化为解密模式
			byte[] result = cipher.doFinal(Base64.decode(str.getBytes()));
			decryptionStr = new String(result);
		}catch(Exception e) {
			System.out.println(e);
		}
		
		return decryptionStr;
	}
	
	/**
	 * 公钥加密
	 * @param str
	 * @return
	 */
	public static String publicKeyEncryption(String str) {
		String encryptionStr = "";
		try {
			X509EncodedKeySpec x509EncodedKeySped 
					= new X509EncodedKeySpec(Base64.decode(publicKeyStr.getBytes()));
			
			// 实例化指定算法的秘钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			
			// 获取指定算法的Cipher对象
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey); // 初始化为加密模式
			byte[] result = cipher.doFinal(str.getBytes());
			encryptionStr = Base64.encode(result);
		}catch(Exception e) {
			System.out.println(e);
		}
		return encryptionStr;
	}
	
	/**
	 * 私钥解密
	 * @param str
	 * @return
	 */
	public static String privateKeyDecryption(String str) {
		String decryptionStr = "";
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(Base64.decode(privateKeyStr.getBytes()));
			
			// 实例化指定算法的秘钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			
			// 获取指定算法的Cipher对象
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey); // 初始化为解密模式
			byte[] result = cipher.doFinal(Base64.decode(str.getBytes()));
			decryptionStr = new String(result);
		}catch(Exception e) {
			System.out.println(e);
		}
		
		return decryptionStr;
	}

	public static void main(String[] args) {
		initKey();
		System.out.println("公钥长度：" + publicKeyStr.length() + "; 公钥值：" + publicKeyStr);
		System.out.println("\n私钥长度：" + privateKeyStr.length() + "; 私钥值：" + privateKeyStr);
		
		String privateEncryptionStr = privateKeyEncryption("maocy1234");
		System.out.println("\n私钥加密：" + privateEncryptionStr);
		
		String publicDecryptionStr = publicKeyDecryption(privateEncryptionStr);
		System.out.println("\n公钥解密：" + publicDecryptionStr);
		
		String publicEncryptionStr = publicKeyEncryption("privateEncryptionStr");
		System.out.println("\n公钥加密：" + publicEncryptionStr);
		
		String privateDecryptionStr = privateKeyDecryption(publicEncryptionStr);
		System.out.println("\n私钥解密：" + privateDecryptionStr);
	}
}
