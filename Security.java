package ctu.server;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ctu.core.abstracts.Connection;
import ctu.core.abstracts.Packet;
import ctu.core.interfaces.Crypt;
import ctu.core.interfaces.Listener;
import ctu.core.packets.PacketClientSecretKey;
import ctu.core.packets.PacketServerPublicKey;

public class Security implements Listener {
	public enum KeyAlgorithms {
		AES
	}

	public enum KeyLength {
		L128, L192, L256
	}

	public enum KeyPairAlgorithms {
		DIFFIE_HELLMAN, DSA, RSA, EC
	}

	public enum KeyPairLenght {
		L1024, L2048, L4096
	}

	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

	public static String bytesToHex(byte[] bytes) {
		final char[] hexChars = new char[bytes.length * 2];

		for (int j = 0; j < bytes.length; j++) {
			final int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}

		return new String(hexChars);
	}

	private String serverAlgorithm;
	private int serverKeySize;
	@SuppressWarnings("unused")
	private String clientAlgorithm; // Client algorithm is not used on the server.
	private int padding;
	@SuppressWarnings("unused")
	private int clientKeySize; // Client key size is not used on the server.

	public Security(KeyPairAlgorithms serverAlgorithm, KeyPairLenght serverKeySize, KeyAlgorithms clientAlgorithm, KeyLength clientKeySize) {
		switch (serverAlgorithm) {
		case DIFFIE_HELLMAN:
			this.serverAlgorithm = "DiffieHellman";
			break;
		case DSA:
			this.serverAlgorithm = "DSA";
			break;
		case EC:
			this.serverAlgorithm = "EC";
			break;
		case RSA:
			this.serverAlgorithm = "RSA";
			break;
		}

		switch (serverKeySize) {
		case L1024:
			this.serverKeySize = 1024;
			break;
		case L2048:
			this.serverKeySize = 2048;
			break;
		case L4096:
			this.serverKeySize = 4096;
			break;
		}

		switch (clientAlgorithm) {
		case AES:
			this.clientAlgorithm = "AES";
			this.padding = 16;
			break;
		}

		switch (clientKeySize) {
		case L128:
			this.clientKeySize = 128;
			break;
		case L192:
			this.clientKeySize = 192;
			break;
		case L256:
			this.clientKeySize = 256;
			break;
		}
	}

	public byte[] decryptSecretKey(byte[] b, PrivateKey privateKey) {
		byte[] bytes = null;

		try {
			final Cipher cipher = Cipher.getInstance(serverAlgorithm);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			bytes = cipher.doFinal(b);
		} catch (final NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (final NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (final InvalidKeyException e) {
			e.printStackTrace();
		} catch (final IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (final BadPaddingException e) {
			e.printStackTrace();
		}

		return bytes;
	}

	@Override
	public void postConnect(Connection connection) {
		System.out.println(String.format("Client #%s (SID: %s) Security module enabled", connection.getCID(), connection.getSID()));

		PublicKey publicKey = null;
		PrivateKey privateKey = null;

		try {
			final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(this.serverAlgorithm);
			keyPairGenerator.initialize(this.serverKeySize);
			final KeyPair keyPair = keyPairGenerator.generateKeyPair();
			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
		} catch (final NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		final PacketServerPublicKey serverPublicKey = new PacketServerPublicKey();
		serverPublicKey.serverPublicKey = publicKey.getEncoded();
		connection.sendTCP(serverPublicKey);

		final byte[] bytes = connection.recvTCP();

		if (bytes != null) {
			System.out.println(String.format("[RECEIVING] ClientSecretKey [%s] from client #%s (SID: %s).", bytes.length, connection.getCID(), connection.getSID()));

			final Packet packet = connection.bytesToPacket(bytes);
			if (packet instanceof PacketClientSecretKey) {
				final PacketClientSecretKey clientSecretKey = (PacketClientSecretKey) packet;

				System.out.println(String.format("Client #%s (SID: %s) Decrypting Secret via private key.", connection.getCID(), connection.getSID()));
				final SecretKey secretKey = GetSecretKey(decryptSecretKey(clientSecretKey.getClientSecretKey(), privateKey));

				connection.setCrypt(new Crypt() {
					@Override
					public byte[] decrypt(byte[] bytes) {
						return secDecrypt(bytes, secretKey);
					}

					@Override
					public byte[] encrypt(byte[] bytes) {
						return secEncrypt(bytes, secretKey);
					}
				});

				connection.setPadding(padding);

				System.out.println(String.format("Client #%s (SID: %s) Secret: %s", connection.getCID(), connection.getSID(), bytesToHex(secretKey.getEncoded())));
				System.out.println(String.format("Client #%s (SID: %s) Security Functioning", connection.getCID(), connection.getSID()));
			}
		}
	}

	public byte[] secDecrypt(byte[] b, SecretKey secretKey) {
		byte[] bytes = null;

		try {
			final IvParameterSpec iv = new IvParameterSpec("RandomInitVector".getBytes("UTF-8"));
			final SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

			b = Arrays.copyOf(b, 16 * (Math.round(b.length / 16)));

			bytes = cipher.doFinal(b);
		} catch (final BadPaddingException e) {
		} catch (final Exception e) {
			e.printStackTrace();
		}

		return bytes;
	}

	public byte[] secEncrypt(byte[] b, SecretKey secretKey) {
		byte[] bytes = null;

		try {
			final IvParameterSpec iv = new IvParameterSpec("RandomInitVector".getBytes("UTF-8"));
			final SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

			final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

			bytes = cipher.doFinal(b);

		} catch (final BadPaddingException e) {
		} catch (final Exception e) {
			e.printStackTrace();
		}

		return bytes;
	}

	protected SecretKey GetSecretKey(byte[] b) {
		return new SecretKeySpec(b, 0, b.length, serverAlgorithm);
	}

	@Override
	public void connected(Connection connection) {
	}

	@Override
	public void recieved(Connection connection, Packet packet) {
	}

	@Override
	public void disconnected(Connection connection) {
	}

	@Override
	public void reset(Connection connection) {
	}

	@Override
	public void timeout(Connection connection) {
	}
}