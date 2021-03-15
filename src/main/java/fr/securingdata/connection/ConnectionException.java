package fr.securingdata.connection;

public class ConnectionException extends Exception {
	
	private static final long serialVersionUID = 6034985175849833979L;
	
	public ConnectionException(String msg) {
		super(msg);
	}
	public ConnectionException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
