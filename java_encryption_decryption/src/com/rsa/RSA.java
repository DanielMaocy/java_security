package com.rsa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class RSA {
	
	/**
	 * ������Կ��˽Կ
	 * @Title: createPublicKeyAndPrivateKey
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017��6��23�� ����4:07:42
	 * @param length
	 * @return Map(��ԿKey:publicKey��˽ԿKey:privateKey)
	 */
	public static Map<String, String> createPublicKeyAndPrivateKey(int length) {
		Map<String, String> map = new HashMap<String, String>();
		try {
			// ʵ������Կ�����ɶ���
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			
			// ��ȡ��Կ��(��Կ��˽Կ)�����߶���
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			
			RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
			map.put("publicKey", Base64.encode(rsaPublicKey.getEncoded()));
			map.put("privateKey", Base64.encode(rsaPrivateKey.getEncoded()));
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e);
		}
		return map;
	}

	/**
	 * ˽Կ����
	 * @Title: privateKeyEncryption
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017��6��23�� ����4:11:33
	 * @param key ˽Կ
	 * @param data ��������
	 * @param len �����ܳ���
	 * @return 
	 */
	public static byte[] privateKeyEncryption(String key, byte[] data, int len) {
		byte[] result = null;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(Base64.decode(key));
			
			// ʵ����ָ���㷨����Կ����
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			
			// ��ȡָ���㷨��Cipher����
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey); // ��ʼ��Ϊ����ģʽ
			
			int length = data.length;
			int index = 0; // ����������ʼλ��
			int encryLength = (length - index) > len ? len : (length - index); // ���μ��ܳ���
			byte[] temp;
			do {
				temp = cipher.doFinal(data, index, encryLength);
				out.write(temp, 0, temp.length);
				index += encryLength;
				encryLength = (length - index) > len ? len : (length - index);
			}while(encryLength > 0);
			
			result = out.toByteArray();
		}catch(Exception e) {
			System.out.println(e);
		}finally {
			try {
				out.close();
			} catch (IOException e) {
				System.out.println(e);
			}
		}

		return result;
	}
	
	/**
	 * ��Կ����
	 * @Title: publicKeyDecryption
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017��6��23�� ����4:22:12
	 * @param key ��Կ
	 * @param data ��������
	 * @param len ������󳤶�
	 * @return
	 */
	public static byte[] publicKeyDecryption(String key, byte[] data, int len) {
		byte[] result = null;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			X509EncodedKeySpec x509EncodedKeySped
					= new X509EncodedKeySpec(Base64.decode(key.getBytes()));
			
			// ʵ����ָ���㷨����Կ����
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			
			// ��ȡָ���㷨��Cipher����
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey); // ��ʼ��Ϊ����ģʽ
			
			byte[] bytes = Base64.decode(data);
			int length = bytes.length;
			int index = 0; // ����������ʼλ��
			int decryLength = (length - index) > len ? len : (length - index); // ���ν��ܳ���
			byte[] temp;
			do {
				temp = cipher.doFinal(bytes, index, decryLength);
				out.write(temp, 0, temp.length);
				index += decryLength;
				decryLength = (length - index) > len ? len : (length - index);
			}while(decryLength > 0);
			
			result = out.toByteArray();
		}catch(Exception e) {
			System.out.println(e);
		}finally {
			try {
				out.close();
			} catch (IOException e) {
				System.out.println(e);
			}
		}
		
		return result;
	}
	
	/**
	 * ��Կ����
	 * @Title: publicKeyEncryption
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017��6��23�� ����4:24:36
	 * @param key ��Կ
	 * @param data ��������
	 * @param len �����ܳ���
	 * @return
	 */
	public static byte[] publicKeyEncryption(String key, byte[] data, int len) {
		byte[] result = null;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			X509EncodedKeySpec x509EncodedKeySped 
					= new X509EncodedKeySpec(Base64.decode(key));
			
			// ʵ����ָ���㷨����Կ����
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			
			// ��ȡָ���㷨��Cipher����
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey); // ��ʼ��Ϊ����ģʽ
			
			int length = data.length;
			int index = 0; // ����������ʼλ��
			int encryLength = (length - index) > len ? len : (length - index); // ���ν��ܳ���
			byte[] temp;
			do {
				temp = cipher.doFinal(data, index, encryLength);
				out.write(temp, 0, temp.length);
				index += encryLength;
				encryLength = (length - index) > len ? len : (length - index);
			}while(encryLength > 0);
			
			result = out.toByteArray();
		}catch(Exception e) {
			System.out.println(e);
		}finally {
			try {
				out.close();
			} catch (IOException e) {
				System.out.println(e);
			}
		}
		
		return result;
	}
	
	/**
	 * ˽Կ����
	 * @Title: privateKeyDecryption
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017��6��23�� ����4:28:54
	 * @param key ˽Կ
	 * @param data ��������
	 * @param len �����ܳ���
	 * @return
	 */
	public static byte[] privateKeyDecryption(String key, byte[] data, int len) {
		byte[] result = null;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(Base64.decode(key.getBytes()));
			
			// ʵ����ָ���㷨����Կ����
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			
			// ��ȡָ���㷨��Cipher����
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey); // ��ʼ��Ϊ����ģʽ
			
			byte[] bytes = Base64.decode(data);
			int length = bytes.length;
			int index = 0; // ����������ʼλ��
			int decryLength = (length - index) > len ? len : (length - index); // ���ν��ܳ���
			byte[] temp;
			do {
				temp = cipher.doFinal(bytes, index, decryLength);
				out.write(temp, 0, temp.length);
				index += decryLength;
				decryLength = (length - index) > len ? len : (length - index);
			}while(decryLength > 0);
			
			result = out.toByteArray();
		}catch(Exception e) {
			System.out.println(e);
		}finally {
			try {
				out.close();
			} catch (IOException e) {
				System.out.println(e);
			}
		}
		
		return result;
	}
	
	/**
	 * ˽Կǩ��
	 * @param str
	 * @return
	 */
	public static String privateKeySign(String key, byte[] data) {
		String sign = "";
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(Base64.decode(key.getBytes()));
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        PrivateKey privateK = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
	        Signature signature = Signature.getInstance("MD5withRSA");
	        signature.initSign(privateK);
	        signature.update(data);
	        sign = new String(Base64.decode(signature.sign()));
		}catch(Exception e) {
			System.out.println(e);
		}
        
        return sign;
    }

	public static void main(String[] args) {
		String str = "maocy1234ma2oy1234maocy1234maocy15234maocy1234maocy1234maocy1234maocy1234maocy1234234maocy1234maocy1234maocy1234maocy1maocy1234ma2oy1234maocy1234maocy15234maocy1234maocy1234maocy1234maocy1234maocy1234234maocy1234maocy1234maocy1234maocy1maocy1234ma2oy1234maocy1234maocy15234maocy1234maocy1234maocy1234maocy1234maocy1234234maocy1234maocy1234maocy1234maocy1maocy1234ma2oy1234maocy1234maocy15234maocy1234maocy1234maocy1234maocy1234maocy1234234maocy1234maocy1234maocy1234maocy1maocy1234ma2oy1234maocy1234maocy15234maocy1234maocy1234maocy1234maocy1234maocy1234234maocy1234maocy1234maocy1234maocy1maocy1234ma2oy1234maocy1234maocy15234maocy1234maocy1234maocy1234maocy1234maocy1234234maocy1234maocy1234maocy1234maocy1";
		Map<String, String> map = createPublicKeyAndPrivateKey(1024);
		String publicKey = map.get("publicKey");
		String privateKey = map.get("privateKey");
		
		try {
			// ˽Կ����
			byte[] privateKeyEncry = privateKeyEncryption(privateKey, str.getBytes("utf-8"), 117);
			String privateKeyEncryStr = Base64.encode(privateKeyEncry);
			System.out.println("˽Կ���ܣ�" + privateKeyEncryStr);
			
			// ��Կ����
			byte[] publicKeyDecry = publicKeyDecryption(publicKey, privateKeyEncryStr.getBytes("utf-8"), 128);
			String publicKeyDecryStr = new String(publicKeyDecry);
			System.out.println("\n��Կ���ܣ�" + publicKeyDecryStr);
			
			// ��Կ����
			byte[] publicKeyEncry = publicKeyEncryption(publicKey, str.getBytes("utf-8"), 117);
			String publicKeyEncryStr = Base64.encode(publicKeyEncry);
			System.out.println("\n��Կ���ܣ�" + publicKeyEncryStr);
			
			// ˽Կ����
			byte[] privateKeyDecry = privateKeyDecryption(privateKey, publicKeyEncryStr.getBytes("utf-8"), 128);
			String privateKeyDecryStr = new String(privateKeyDecry);
			System.out.println("\n��Կ���ܣ�" + privateKeyDecryStr);
		}catch(Exception e) {
			System.out.println(e);
		}
	}
}
