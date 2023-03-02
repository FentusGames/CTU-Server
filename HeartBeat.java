package ctu.server;

import ctu.core.abstracts.Connection;
import ctu.core.abstracts.Packet;
import ctu.core.interfaces.Listener;
import ctu.core.packets.PacketPing;

public class HeartBeat implements Listener {
	@Override
	public void postConnect(Connection connection) {
	}

	@Override
	public void connected(Connection connection) {
	}

	@Override
	public void recieved(Connection connection, Packet packet) {
		if (packet instanceof PacketPing) {
			final PacketPing ping = (PacketPing) packet;
			connection.sendTCP(ping);
		}
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