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
	 * 创建公钥和私钥
	 * @Title: createPublicKeyAndPrivateKey
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017年6月23日 下午4:07:42
	 * @param length
	 * @return Map(公钥Key:publicKey；私钥Key:privateKey)
	 */
	public static Map<String, String> createPublicKeyAndPrivateKey(int length) {
		Map<String, String> map = new HashMap<String, String>();
		try {
			// 实例化秘钥对生成对象
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			
			// 获取秘钥对(公钥和私钥)持有者对象
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
	 * 私钥加密
	 * @Title: privateKeyEncryption
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017年6月23日 下午4:11:33
	 * @param key 私钥
	 * @param data 加密数据
	 * @param len 最大加密长度
	 * @return 
	 */
	public static byte[] privateKeyEncryption(String key, byte[] data, int len) {
		byte[] result = null;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(Base64.decode(key));
			
			// 实例化指定算法的秘钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			
			// 获取指定算法的Cipher对象
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey); // 初始化为加密模式
			
			int length = data.length;
			int index = 0; // 加密索引开始位置
			int encryLength = (length - index) > len ? len : (length - index); // 单次加密长度
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
	 * 公钥解密
	 * @Title: publicKeyDecryption
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017年6月23日 下午4:22:12
	 * @param key 公钥
	 * @param data 解密数据
	 * @param len 解密最大长度
	 * @return
	 */
	public static byte[] publicKeyDecryption(String key, byte[] data, int len) {
		byte[] result = null;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			X509EncodedKeySpec x509EncodedKeySped
					= new X509EncodedKeySpec(Base64.decode(key.getBytes()));
			
			// 实例化指定算法的秘钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			
			// 获取指定算法的Cipher对象
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey); // 初始化为解密模式
			
			byte[] bytes = Base64.decode(data);
			int length = bytes.length;
			int index = 0; // 解密索引开始位置
			int decryLength = (length - index) > len ? len : (length - index); // 单次解密长度
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
	 * 公钥加密
	 * @Title: publicKeyEncryption
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017年6月23日 下午4:24:36
	 * @param key 公钥
	 * @param data 加密数据
	 * @param len 最大加密长度
	 * @return
	 */
	public static byte[] publicKeyEncryption(String key, byte[] data, int len) {
		byte[] result = null;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			X509EncodedKeySpec x509EncodedKeySped 
					= new X509EncodedKeySpec(Base64.decode(key));
			
			// 实例化指定算法的秘钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			
			// 获取指定算法的Cipher对象
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey); // 初始化为加密模式
			
			int length = data.length;
			int index = 0; // 解密索引开始位置
			int encryLength = (length - index) > len ? len : (length - index); // 单次解密长度
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
	 * 私钥解密
	 * @Title: privateKeyDecryption
	 * @Description: 
	 * @Author: maocy
	 * @Date: 2017年6月23日 下午4:28:54
	 * @param key 私钥
	 * @param data 解密数据
	 * @param len 最大解密长度
	 * @return
	 */
	public static byte[] privateKeyDecryption(String key, byte[] data, int len) {
		byte[] result = null;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(Base64.decode(key.getBytes()));
			
			// 实例化指定算法的秘钥工厂
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			
			// 获取指定算法的Cipher对象
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey); // 初始化为解密模式
			
			byte[] bytes = Base64.decode(data);
			int length = bytes.length;
			int index = 0; // 解密索引开始位置
			int decryLength = (length - index) > len ? len : (length - index); // 单次解密长度
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
	 * 私钥签名
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
			// 私钥加密
			byte[] privateKeyEncry = privateKeyEncryption(privateKey, str.getBytes("utf-8"), 117);
			String privateKeyEncryStr = Base64.encode(privateKeyEncry);
			System.out.println("私钥加密：" + privateKeyEncryStr);
			
			// 公钥解密
			byte[] publicKeyDecry = publicKeyDecryption(publicKey, privateKeyEncryStr.getBytes("utf-8"), 128);
			String publicKeyDecryStr = new String(publicKeyDecry);
			System.out.println("\n公钥解密：" + publicKeyDecryStr);
			
			// 公钥加密
			byte[] publicKeyEncry = publicKeyEncryption(publicKey, str.getBytes("utf-8"), 117);
			String publicKeyEncryStr = Base64.encode(publicKeyEncry);
			System.out.println("\n公钥加密：" + publicKeyEncryStr);
			
			// 私钥解密
			byte[] privateKeyDecry = privateKeyDecryption(privateKey, publicKeyEncryStr.getBytes("utf-8"), 128);
			String privateKeyDecryStr = new String(privateKeyDecry);
			System.out.println("\n公钥解密：" + privateKeyDecryStr);
		}catch(Exception e) {
			System.out.println(e);
		}
	}
}
