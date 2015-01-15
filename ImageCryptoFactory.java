import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Class provides utility methods to encrypt/devrypt images using AES 256-bit algorithm 
 * @author madhurbhargava
 *
 */
public class ImageCryptoFactory {
	
	    private static final String password = "test";
	    private static String salt;
	    private static int pswdIterations = 65536  ;
	    private static int keySize = 256;
	    private static byte[] ivBytes;
	 
	    /**
	     * Encrypts a normal image
	     * @param image
	     * @return CipherInputStream
	     */
	    public static CipherInputStream encryptImage(File image) {   
	         
	        //get salt
	        salt = generateSalt();      
	        byte[] saltBytes;
			try 
			{
				saltBytes = salt.getBytes("UTF-8");
			} 
			catch (UnsupportedEncodingException e) 
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	         
	        
	        SecretKeyFactory factory;
			try {
				factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	        PBEKeySpec spec = new PBEKeySpec(
	                password.toCharArray(), 
	                saltBytes, 
	                pswdIterations, 
	                keySize
	                );
	 
	        SecretKey secretKey;
			try {
				secretKey = factory.generateSecret(spec);
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
	 
	        
	        Cipher cipher;
			try {
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
			
	        try {
				cipher.init(Cipher.ENCRYPT_MODE, secret);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	        AlgorithmParameters params = cipher.getParameters();
	        try {
				ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
			} catch (InvalidParameterSpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	        CipherInputStream cipherIn;
			try {
				cipherIn = new CipherInputStream(new FileInputStream(image), cipher);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	        return cipherIn;
	    }
	 
	    /**
	     * Decrypts an encrypted Image. Failure will return null
	     * @param encryptedImage
	     * @return CipherInputStream
	     */
	    public static CipherInputStream decryptImage(File encryptedImage) {
	 
	        byte[] saltBytes = null;
			try {
				saltBytes = salt.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	 
	        // Derive the key
	        SecretKeyFactory factory = null;
			try {
				factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	        PBEKeySpec spec = new PBEKeySpec(
	                password.toCharArray(), 
	                saltBytes, 
	                pswdIterations, 
	                keySize
	                );
	 
	        SecretKey secretKey = null;
			try {
				secretKey = factory.generateSecret(spec);
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
	 
	        
	        Cipher cipher = null;
			try {
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	        try {
				cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	     
	 
	        CipherInputStream cipherIn = null;
			try {
				cipherIn = new CipherInputStream(new FileInputStream(encryptedImage), cipher);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return null;
			}
	 
	        return cipherIn;
	    }
	 
	    private static String generateSalt() {
	        SecureRandom random = new SecureRandom();
	        byte bytes[] = new byte[20];
	        random.nextBytes(bytes);
	        String s = new String(bytes);
	        return s;
	    }
	    
	    /**
	     * Driver main method to demonstrate the usage
	     * @param args
	     */
	    public static void main(String[] args)
	    {
	    	File file = new File("img.PNG");
	    	CipherInputStream cis = ImageCryptoFactory.encryptImage(file);
	    	FileOutputStream fos = null;
	    	File ofile = null;
	    	try {
	    		ofile = new File("encrypted_img.png");
				fos=new FileOutputStream(ofile);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    	int i; 
	    	try {
				while((i=cis.read())!=-1){
				fos.write(i);
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    	
	    	cis = ImageCryptoFactory.decryptImage(new File("encrypted_img.png"));
	    	try {
	    		ofile = new File("decrypted_img.png");
				fos=new FileOutputStream(ofile);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    	int j; 
	    	try {
				while((j=cis.read())!=-1){
				fos.write(j);
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    }
	
}
