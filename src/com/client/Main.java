package com.client;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Main {

    public static void main(String[] args) throws Exception {
        String message = "/";

        if(args.length > 0) {
            message = args[0];
        }

        KeyPairGenerator keyPairGen;
        try {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }

        // Wir generieren ein 2048-bit RSA Keypair

        keyPairGen.initialize(2048);

        KeyPair pair = keyPairGen.generateKeyPair();

        PublicKey clientPublicKey = pair.getPublic();
        PrivateKey clientPrivateKey = pair.getPrivate();

        Key aesKey;


	    Socket socket = null;
        try {
            socket = new Socket("localhost", 8080);

            OutputStream raus = socket.getOutputStream();
            PrintStream ps = new PrintStream(raus, true);

            InputStream rein = socket.getInputStream();
            BufferedReader buff = new BufferedReader(new InputStreamReader(rein));


            // Zuerst senden wir den Public Key des Clients
            System.out.println("Out: " + new String(Base64.getEncoder().encode(clientPublicKey.getEncoded())));
            ps.println(new String(Base64.getEncoder().encode(clientPublicKey.getEncoded())));

            // Der Public Key des Servers wird konvertiert in PublicKey
            String serverPublicKeyRaw = buff.readLine();
            PublicKey serverPublicKey = PublicKeyFromString(serverPublicKeyRaw.replace("\n", ""));
            System.out.println("Received server public key: " + serverPublicKeyRaw);

            // Wir generieren einen 128-bit AES Key zum Verschlüsseln der Daten
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            aesKey = keygen.generateKey();

            System.out.println("AES Key: " + new String(Base64.getEncoder().encode(aesKey.getEncoded())));
            String encryptedKey = encrypt(new String(Base64.getEncoder().encode(aesKey.getEncoded())), serverPublicKey);
            ps.println(encryptedKey);

            ps.println(encryptAES(message, aesKey));

            String response = decryptAES(buff.readLine(), aesKey);

            System.out.println("Received response from server: " + response);

            BufferedWriter writer = new BufferedWriter(new FileWriter("/tmp/temp.html"));
            writer.write(response);
            writer.close();

            new JEditorPane("http://localhost:8000/temp.html");

            Runtime.getRuntime().exec("xdg-open http://localhost:8000/temp.html");

        } catch (UnknownHostException e) {
            System.out.println("Unknown Host...");
            e.printStackTrace();
        } catch (IOException e) {
            System.out.println("IOProbleme...");
            e.printStackTrace();
        } finally {
            if (socket != null)
                try {
                    socket.close();
                    System.out.println("Socket geschlossen...");
                } catch (IOException e) {
                    System.out.println("Socket nicht zu schliessen...");
                    e.printStackTrace();
                }
        }
    }

    private static PublicKey PublicKeyFromString(String key) throws Exception {

        byte[] keyBytes = Base64.getDecoder().decode(key);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    private static String decrypt(String cipherText, PrivateKey serverPrivateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    private static String decryptAES(String ciphertext, Key aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] keyBytes = aesKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);

        // Entschluesseln
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] clearBytes = cipher.doFinal(cipherBytes);

        return new String(clearBytes);
    }

    private static String encryptAES(String cleartext, Key aesKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] keyBytes = aesKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(cleartext.getBytes());


        return new String(Base64.getEncoder().encode(encrypted));
    }
}
