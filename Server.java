package main;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import encryption.EncryptRSA;

public class Server {
	public static void main(String[] args) {
		System.out.println("Server starting...");
		try {
			ServerSocket serverSoc = new ServerSocket(9182);
			Socket soc = serverSoc.accept();

			PrintWriter out = new PrintWriter(soc.getOutputStream(), true);
			BufferedReader in = new BufferedReader(new InputStreamReader(soc.getInputStream()));

			System.out.println("Client Connection Successful!");

			System.out.println("Creating RSA keys....");
			long timeStart = System.currentTimeMillis();
			KeyPair keys = EncryptRSA.generateKeyPair();
			long timeEnd = System.currentTimeMillis();
			System.out.println("Completed. Took " + (timeEnd - timeStart) + "ms to complete");
			System.out.println("Creating log file...");
			File logFile = new File("data.log");

			if (!logFile.exists()) {
				logFile.createNewFile();
			}
			PrintWriter logWrite = new PrintWriter(logFile);
			ArrayList<String> logFileContents = new ArrayList<String>();
			Scanner logFileReader = new Scanner(logFile);
			Date date = new Date();
			SimpleDateFormat format = new SimpleDateFormat("yy-MM-dd-HH:mm:ss:SSS");
			System.out.println("Completed.");

			String publicKeyToSend = Base64.getEncoder().encodeToString(keys.getPublic().getEncoded());

			out.println(publicKeyToSend);
			System.out.println("Waiting for messages - writing to data.log");
			while (true) {

				String recievedMessage = in.readLine();
				String messageDecrypted = new String(
						EncryptRSA.decrypt(Base64.getDecoder().decode(recievedMessage), keys.getPrivate()), "UTF-8");
				if (messageDecrypted.equalsIgnoreCase("/exit")) {
					break;
				}
				System.out.println("Writing: '" + messageDecrypted + "'");

				while (logFileReader.hasNextLine()) {
					logFileContents.add(logFileReader.nextLine());
				}
				logFileContents.add(format.format(date) + " - " + messageDecrypted);
				for (String line : logFileContents) {
					logWrite.println(line);
				}
				logWrite.flush();

				logFileContents.clear();

			}
			logWrite.close();
			logFileReader.close();

			System.out.println("Exiting server - log file finalized....");

		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}
