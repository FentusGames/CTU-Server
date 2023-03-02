package ctu.server;

import java.io.IOException;
import java.net.ServerSocket;

import javax.net.ServerSocketFactory;

import ctu.core.abstracts.CTU;
import ctu.core.abstracts.Connection;

public class CTUServer extends CTU {
	private int id = 1;

	ServerSocket serverSocket = null;

	public int getId() {
		return id;
	}

	@Override
	public void exec() {
		System.out.println("Starting...");

		try {
			serverSocket = ServerSocketFactory.getDefault().createServerSocket(getConfig().PORT);

			setServerSocket(serverSocket);
		} catch (final IOException e) {
			e.printStackTrace();
		} finally {
			System.out.println("Waiting for connections...");

			while (isRunning()) {
				try {
					setSocket(serverSocket.accept());
				} catch (final IOException e) {
					setRunning(false);
					break;
				} finally {
					Connection connection = new Connection(this) {

					};

					connection.setCID(id++);

					connection.start();
				}
			}

			try {
				if (!serverSocket.isClosed()) {
					serverSocket.close();
				}
			} catch (final IOException e) {
				e.printStackTrace();
			}

			executorStop();
		}
	}
}
