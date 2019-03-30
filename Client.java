package main;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import encryption.EncryptRSA;

public class Client {
	public static void main(String[] args) {
		System.out.println("Client starting...");

		try {
			Socket soc = new Socket("127.0.0.1", 9182);

			PrintWriter out = new PrintWriter(soc.getOutputStream(), true);
			BufferedReader in = new BufferedReader(new InputStreamReader(soc.getInputStream()));

			System.out.println("Waiting for server to send public key");

			String serverPublicKey = in.readLine();
			System.out.println("Recieved key");

			PublicKey publicKeyServer = KeyFactory.getInstance("RSA")
					.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(serverPublicKey)));

			System.out.println("Key saved.");

			Scanner userIn = new Scanner(System.in);
			System.out.println("All messages sent to server are encrypted.");
			while (true) {
				System.out.print("\n Enter message to send: ");
				String messageIn = userIn.nextLine();
				if (messageIn.equalsIgnoreCase("/exit")) {
					break;
				}
				String messageInEncrypted = Base64.getEncoder()
						.encodeToString(EncryptRSA.encrypt(messageIn.getBytes("UTF-8"), publicKeyServer));
				out.println(messageInEncrypted);
			}
			System.out.println("Sending shutdown message to server...");
			// telling server to save and exit too
			out.println(Base64.getEncoder()
					.encodeToString(EncryptRSA.encrypt(new String("/exit").getBytes("UTF-8"), publicKeyServer)));
			System.out.println("Exiting client...");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
