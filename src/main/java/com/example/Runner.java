package com.example;

import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * keytool -keystore keystore -genkey -alias client
 * keytool -genkey -alias John -keyalg RSA -keystore keystore  -keysize 2048
 */
public class Runner {

	public static void main(String[] args) {
		try {

			String keyStore = "keystore";
			String keyStorePass = "company";
			
			byte[] message = "My.Very_Strong_Password1!".getBytes("UTF-8");

			KeyStore ks = loadKeyStore(keyStore, keyStorePass);

			PrivateKey privateKey = (PrivateKey) ks.getKey("john", keyStorePass.toCharArray());
			
			PublicKey publicKey = ks.getCertificate("john").getPublicKey();
			
			System.out.println("plain message: " + new String(message, "UTF8"));
			
			byte[] secret = encrypt(publicKey, message);
		
			System.out.println("encrypt message: " + new String(secret, "UTF8"));
			
			byte[] recovered_message = decrypt(privateKey, secret);
			
			System.out.println("decrypt message: " + new String(recovered_message, "UTF8"));

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static KeyStore loadKeyStore(String keyStore, String key) {
		try {
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			// get user password and file input stream
			char[] password = key.toCharArray();
			FileInputStream fis = new FileInputStream(keyStore);
			ks.load(fis, password);
			fis.close();
			return ks;
		} catch (Exception e) {
			System.err.println("Unable to open keystore " + keyStore + ": Caught " + e);
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] encrypt(PublicKey key, byte[] plaintext) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(plaintext);
	}

	public static byte[] decrypt(PrivateKey key, byte[] ciphertext) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(ciphertext);
	}

}
