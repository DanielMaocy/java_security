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
	
	private static String publicKeyStr = ""; // ��Կ
	private static String privateKeyStr = ""; // ˽Կ
	
	/**
	 * ��ʼ����Կ��˽Կ
	 */
	public static void initKey() {
		try {
			// ʵ������Կ�����ɶ���
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			
			// ��ȡ��Կ��(��Կ��˽Կ)�����߶���
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
	 * ˽Կ����
	 * @param str
	 * @return
	 */
	public static String privateKeyEncryption(String str) {
		String encryptionStr = "";
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(Base64.decode(privateKeyStr.getBytes()));
			
			// ʵ����ָ���㷨����Կ����
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			
			// ��ȡָ���㷨��Cipher����
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey); // ��ʼ��Ϊ����ģʽ
			byte[] result = cipher.doFinal(str.getBytes());
			encryptionStr = Base64.encode(result);
		}catch(Exception e) {
			System.out.println(e);
		}

		return encryptionStr;
	}
	
	/**
	 * ��Կ����
	 * @param str
	 * @return
	 */
	public static String publicKeyDecryption(String str) {
		String decryptionStr = "";
		try {
			X509EncodedKeySpec x509EncodedKeySped
					= new X509EncodedKeySpec(Base64.decode(publicKeyStr.getBytes()));
			
			// ʵ����ָ���㷨����Կ����
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			
			// ��ȡָ���㷨��Cipher����
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey); // ��ʼ��Ϊ����ģʽ
			byte[] result = cipher.doFinal(Base64.decode(str.getBytes()));
			decryptionStr = new String(result);
		}catch(Exception e) {
			System.out.println(e);
		}
		
		return decryptionStr;
	}
	
	/**
	 * ��Կ����
	 * @param str
	 * @return
	 */
	public static String publicKeyEncryption(String str) {
		String encryptionStr = "";
		try {
			X509EncodedKeySpec x509EncodedKeySped 
					= new X509EncodedKeySpec(Base64.decode(publicKeyStr.getBytes()));
			
			// ʵ����ָ���㷨����Կ����
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			
			// ��ȡָ���㷨��Cipher����
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey); // ��ʼ��Ϊ����ģʽ
			byte[] result = cipher.doFinal(str.getBytes());
			encryptionStr = Base64.encode(result);
		}catch(Exception e) {
			System.out.println(e);
		}
		return encryptionStr;
	}
	
	/**
	 * ˽Կ����
	 * @param str
	 * @return
	 */
	public static String privateKeyDecryption(String str) {
		String decryptionStr = "";
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(Base64.decode(privateKeyStr.getBytes()));
			
			// ʵ����ָ���㷨����Կ����
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			
			// ��ȡָ���㷨��Cipher����
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey); // ��ʼ��Ϊ����ģʽ
			byte[] result = cipher.doFinal(Base64.decode(str.getBytes()));
			decryptionStr = new String(result);
		}catch(Exception e) {
			System.out.println(e);
		}
		
		return decryptionStr;
	}

	public static void main(String[] args) {
		initKey();
		System.out.println("��Կ���ȣ�" + publicKeyStr.length() + "; ��Կֵ��" + publicKeyStr);
		System.out.println("\n˽Կ���ȣ�" + privateKeyStr.length() + "; ˽Կֵ��" + privateKeyStr);
		
		String privateEncryptionStr = privateKeyEncryption("maocy1234");
		System.out.println("\n˽Կ���ܣ�" + privateEncryptionStr);
		
		String publicDecryptionStr = publicKeyDecryption(privateEncryptionStr);
		System.out.println("\n��Կ���ܣ�" + publicDecryptionStr);
		
		String publicEncryptionStr = publicKeyEncryption("privateEncryptionStr");
		System.out.println("\n��Կ���ܣ�" + publicEncryptionStr);
		
		String privateDecryptionStr = privateKeyDecryption(publicEncryptionStr);
		System.out.println("\n˽Կ���ܣ�" + privateDecryptionStr);
	}
}
