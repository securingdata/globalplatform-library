package fr.securingdata.connection;

import javax.smartcardio.ATR;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

public class Application {
	private String selectedAid;
	protected CardTerminal selectedReader;
	protected Connection connection;
	
	public Application(CardTerminal reader) {
		selectedReader = reader;
	}
	public void logComment(String comment) {
		if (connection != null)
			connection.logComment(comment, "=");
	}
	public void coldReset() throws ConnectionException {
		try {
			if (connection == null) {
				ATR atr = null;
				connection = Connection.getConnection();
				if (selectedReader != null)
					atr = connection.contectAutoToReader(selectedReader);
				else
					atr = connection.connectAuto();
				if (atr == null)
					throw new ConnectionException("No card present.");
			}
			connection.coldReset();
			selectedAid = null;
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
	public String getSelectedAid() {
		return selectedAid;
	}
	public APDUResponse select(String aid) throws ConnectionException {
		APDUResponse resp = send("Select", "00 A4 04 00", aid, "00");
		if (resp.getStatusWord() == (short) 0x9000)
			selectedAid = aid;
		return resp;
	}
	public APDUResponse send(String header, String data, String le) throws ConnectionException {
		try {
			return unwrap(connection.send(header, wrap(header, data, le), le));
		} catch (CardException e) {
			throw new ConnectionException("Card exception. " + e.getMessage(), e.getCause());
		}
	}
	public APDUResponse send(String cmdName, String header, String data, String le) throws ConnectionException {
		try {
			return unwrap(connection.send(cmdName, header, wrap(header, data, le), le));
		} catch (CardException e) {
			throw new ConnectionException("Card exception. " + e.getMessage(), e.getCause());
		}
	}
	public String wrap(String header, String data, String le) throws ConnectionException {
		return data;
	}
	public APDUResponse unwrap(APDUResponse response) throws ConnectionException {
		return response;
	}
	protected APDUResponse rawSend(String cmdName, String header, String data, String le) throws ConnectionException {
		try {
			return connection.send(cmdName, header, data, le);
		} catch (CardException e) {
			throw new ConnectionException("Card exception. " + e.getMessage(), e.getCause());
		}
	}
}
