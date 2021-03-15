package fr.securingdata.globalplatform;

import fr.securingdata.connection.ConnectionException;

public class GPException extends ConnectionException {
	private static final long serialVersionUID = -7989026726148003459L;

	public GPException(String msg) {
		super(msg);
	}
	public GPException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
