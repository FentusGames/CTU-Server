# CTU Server
A simple Java TPC network server that uses colfer. This is the server module, requires CTU Core to function.
```java
public static void main(String[] args) throws InterruptedException {
	Config config = new Config();

	config.IP_ADDRESS = "10.89.0.6";
	config.PORT = 9999;
	config.PACKET_SIZE = 1400;
	config.TIMEOUT = 10000;
	config.DEFAULT_ITERATIONS = 150000;
	config.ALGORITHM = "pbkdf2_sha256";

	CTUServer server = new CTUServer();
	
	// Register packets.
	// E.G. server.register(PACKETNAME.class);

	server.addListener(new Listener() {
		@Override
		public void timeout(Connection connection) {}

		@Override
		public void reset(Connection connection) {}

		@Override
		public void recieved(Connection connection, Packet packet) {}

		@Override
		public void postConnect(Connection connection) {}

		@Override
		public void disconnected(Connection connection) {}

		@Override
		public void connected(Connection connection) {}
	});

	server.setConfig(config);

	server.addListener(new Messages());
	server.addListener(new Security(KeyPairAlgorithms.RSA, KeyPairLenght.L1024, KeyAlgorithms.AES, KeyLength.L128));
	server.addListener(new HeartBeat());
	server.addListener(new Compressor(Algorithms.GZIP));

	// Some sort of loop to keep the server open.
}
```
