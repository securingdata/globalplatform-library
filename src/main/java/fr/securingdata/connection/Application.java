package fr.securingdata.connection;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

public class Application {
	private CardTerminal selectedReader;
	protected Connection connection;
	
	public Application(CardTerminal reader) {
		selectedReader = reader;
	}
	public void coldReset() throws ConnectionException {
		try {
			if (connection == null) {
				connection = Connection.getConnection();
				if (selectedReader != null)
					connection.contectAutoToReader(selectedReader);
				else
					connection.connectAuto();
			}
			connection.coldReset();
		} catch (CardException e) {
			throw new ConnectionException("Card exception. " + e.getMessage(), e.getCause());
		}
	}
	public void disconnect() {
		if (connection != null) {
			try {
				connection.disconnect();
			} catch (CardException e) {
				connection = null;
			}
		}
	}
	public APDUResponse select(String aid) throws ConnectionException {
		return send("Select", "00 A4 04 00", aid, "00");
	}
	public APDUResponse send(String header, String data, String le) throws ConnectionException {
		try {
			return unwrap(connection.send(header, wrap(header, data, le), le));
		} catch (CardException e) {
			throw new ConnectionException("Card exception. " + e.getMessage(), e.getCause());
		}
	}
	public APDUResponse send(String cmdName, String header, String data, String le) throws ConnectionException {
		return send(header, data, le);
	}
	public String wrap(String header, String data, String le) throws ConnectionException {
		return data;
	}
	public APDUResponse unwrap(APDUResponse response) throws ConnectionException {
		return response;
	}
}
