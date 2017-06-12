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
	/** ָ�������㷨ΪRSA */  
    private static final String ALGORITHM = "RSA";  
    /** ��Կ���ȣ�������ʼ�� */  
    private static final int KEYSIZE = 1204;  
    /** ָ����Կ����ļ� */  
    private static String PUBLIC_KEY_FILE = "PublicKey";  
    /** ָ��˽Կ����ļ� */  
    private static String PRIVATE_KEY_FILE = "PrivateKey";

    private static void genKeyPair() throws NoSuchAlgorithmException {  
        
        // �����������
        SecureRandom secureRandom = new SecureRandom();  
          
        // KeyPairGenerator���� 
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);  
        keyPairGenerator.initialize(KEYSIZE, secureRandom);  
  
        KeyPair keyPair = keyPairGenerator.generateKeyPair(); // �����ܳ׶�  
        Key publicKey = keyPair.getPublic(); // ��ȡ��Կ 
        Key privateKey = keyPair.getPrivate(); // ��ȡ˽Կ   
  
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
     * ���ܷ��� 
     * @param source Դ���� 
     * @return 
     * @throws Exception 
     */  
    public static String encrypt(String source) throws Exception {  
          
//        Key publicKey = getKey("");  
  
        /** �õ�Cipher������ʵ�ֶ�Դ���ݵ�RSA���� */  
        Cipher cipher = Cipher.getInstance(ALGORITHM);  
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
        byte[] b = source.getBytes();  
        /** ִ�м��ܲ��� */  
        byte[] b1 = cipher.doFinal(b);  
        BASE64Encoder encoder = new BASE64Encoder();  
        return encoder.encode(b1);  
    }  
  
    /** 
     * �����㷨 
     * @param cryptograph    ���� 
     * @return 
     * @throws Exception 
     */  
    public static String decrypt(String cryptograph) throws Exception {  
          
//        Key privateKey = getKey("");  
  
        /** �õ�Cipher��������ù�Կ���ܵ����ݽ���RSA���� */  
        Cipher cipher = Cipher.getInstance(ALGORITHM);  
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);  
        BASE64Decoder decoder = new BASE64Decoder();  
        byte[] b1 = decoder.decodeBuffer(cryptograph);  
  
        /** ִ�н��ܲ��� */  
        byte[] b = cipher.doFinal(b1);  
        return new String(b);  
    }  
    
    public static void main(String[] args) throws IOException, ClassNotFoundException {
	}
}
