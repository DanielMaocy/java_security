package com.rsa;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class RSA {

	public static void main(String[] args) {
		jdkRSA("mao123456789");
	}
	
	public static void jdkRSA(String str) {
		try {
			// 初始化秘钥
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(1024);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
			System.out.println("Public Key: " + Base64.encode(rsaPublicKey.getEncoded()));
			System.out.println("Private Key: " + Base64.encode(rsaPrivateKey.getEncoded()));
			
			// 私钥加密、公钥解密——加密
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec 
					= new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] result = cipher.doFinal(str.getBytes());
			System.out.println("私钥加密、公钥解密——加密：" + Base64.encode(result));
			
			// 私钥加密、公钥解密——解密
			X509EncodedKeySpec x509EncodedKeySped
					= new X509EncodedKeySpec(rsaPublicKey.getEncoded());
			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			result = cipher.doFinal(result);
			System.out.println("私钥加密、公钥解密——解密：" + new String(result));
			
			// 公钥加密、私钥解密——加密
			x509EncodedKeySped = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
			publicKey = keyFactory.generatePublic(x509EncodedKeySped);
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			result = cipher.doFinal(result);
			System.out.println("公钥加密、私钥解密——加密：" + Base64.encode(result));
			
			// 公钥加密、私钥解密——解密
			pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
			privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			result = cipher.doFinal(result);
			System.out.println("公钥加密、私钥解密——解密：" + new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
