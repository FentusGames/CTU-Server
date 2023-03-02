package ctu.server;

import ctu.core.abstracts.Connection;
import ctu.core.abstracts.Packet;
import ctu.core.interfaces.Listener;

public class Messages implements Listener {
	@Override
	public void connected(Connection connection) {
		System.out.println(String.format("Client #%s (SID: %s) Connected...", connection.getCID(), connection.getSID()));
	}

	@Override
	public void disconnected(Connection connection) {
		System.out.println(String.format("Client #%s (SID: %s) Disconnected...", connection.getCID(), connection.getSID()));
	}

	@Override
	public void postConnect(Connection connection) {
		System.out.println(String.format("Client #%s (SID: %s) Post Connect...", connection.getCID(), connection.getSID()));
	}

	@Override
	public void reset(Connection connection) {
		System.out.println(String.format("Client #%s (SID: %s) Reset...", connection.getCID(), connection.getSID()));
	}

	@Override
	public void timeout(Connection connection) {
		System.out.println(String.format("Client #%s (SID: %s) Timed Out...", connection.getCID(), connection.getSID()));
	}

	@Override
	public void recieved(Connection connection, Packet packet) {
	}
}