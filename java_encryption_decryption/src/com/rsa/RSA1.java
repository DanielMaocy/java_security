package com.rsa;

import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class RSA1 {
	/** 指定加密算法为RSA */  
    private static final String ALGORITHM = "RSA";  
    /** 密钥长度，用来初始化 */  
    private static final int KEYSIZE = 1204;  
    /** 指定公钥存放文件 */  
    private static String PUBLIC_KEY_FILE = "PublicKey";  
    /** 指定私钥存放文件 */  
    private static String PRIVATE_KEY_FILE = "PrivateKey";

    private static void genKeyPair() throws NoSuchAlgorithmException {  
        
        // 随机数生成器
        SecureRandom secureRandom = new SecureRandom();  
          
        // KeyPairGenerator对象 
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);  
        keyPairGenerator.initialize(KEYSIZE, secureRandom);  
  
        KeyPair keyPair = keyPairGenerator.generateKeyPair(); // 生成密匙对  
        Key publicKey = keyPair.getPublic(); // 获取公钥 
        Key privateKey = keyPair.getPrivate(); // 获取私钥   
  
        byte[] publicKeyBytes = publicKey.getEncoded();  
        byte[] privateKeyBytes = privateKey.getEncoded();  
  
        String publicKeyBase64 = new BASE64Encoder().encode(publicKeyBytes);  
        String privateKeyBase64 = new BASE64Encoder().encode(privateKeyBytes);  
  
        System.out.println("publicKeyBase64.length():" + publicKeyBase64.length());  
        System.out.println("publicKeyBase64:" + publicKeyBase64);  
  
        System.out.println("privateKeyBase64.length():" + privateKeyBase64.length());  
        System.out.println("privateKeyBase64:" + privateKeyBase64);  
    }  
    
    /** 
     * 加密方法 
     * @param source 源数据 
     * @return 
     * @throws Exception 
     */  
    public static String encrypt(String source) throws Exception {  
          
//        Key publicKey = getKey("");  
  
        /** 得到Cipher对象来实现对源数据的RSA加密 */  
        Cipher cipher = Cipher.getInstance(ALGORITHM);  
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
        byte[] b = source.getBytes();  
        /** 执行加密操作 */  
        byte[] b1 = cipher.doFinal(b);  
        BASE64Encoder encoder = new BASE64Encoder();  
        return encoder.encode(b1);  
    }  
  
    /** 
     * 解密算法 
     * @param cryptograph    密文 
     * @return 
     * @throws Exception 
     */  
    public static String decrypt(String cryptograph) throws Exception {  
          
//        Key privateKey = getKey("");  
  
        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */  
        Cipher cipher = Cipher.getInstance(ALGORITHM);  
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);  
        BASE64Decoder decoder = new BASE64Decoder();  
        byte[] b1 = decoder.decodeBuffer(cryptograph);  
  
        /** 执行解密操作 */  
        byte[] b = cipher.doFinal(b1);  
        return new String(b);  
    }  
    
    public static void main(String[] args) throws IOException, ClassNotFoundException {
	}
}
