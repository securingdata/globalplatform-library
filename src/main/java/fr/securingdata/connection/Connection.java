package fr.securingdata.connection;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

import fr.securingdata.util.StringHex;
import javafx.beans.property.StringProperty;

public class Connection {
	private static StringProperty logListener;
	
	public static void main(String[] args) throws CardException {
		Connection connection = Connection.getConnection();
		connection.connectAuto();
		connection.send("00 A4 04 00", "a000000151000000", "00");
		connection.coldReset();
		connection.send("00 A4 04 00", "a000000151000000", "00");
		
		/*StringHex resp = connection.send("00 A4 04 00", "A0 00 00 00 03 00 00 00", "00");
		resp = connection.send("00 CA 00 66", "", "00");*/
		//System.out.println(resp.toString());
		
	}
	
	private static Connection connection;
	
	private TerminalFactory terminalFactory;
	private CardTerminal terminal;
	private Card card;
	private CardChannel channel;
	
	private Connection() {
		if (System.getProperty("os.name").equals("Linux")) {//Workaround for bug in Linux to have a correct path for libpcsclite
			try {
				String line;
				String comm[] = { "find", "/usr", "/lib", "-name",
				"libpcsclite.so.1" };
				Process p = Runtime.getRuntime().exec(comm);

				BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

				while ((line = reader.readLine()) != null && !line.equals("")) {
					if (line.contains("libpcsclite.so.1")) {
						System.setProperty("sun.security.smartcardio.library",line);
						break;
					}
				}
				p.destroy();
			} catch (Exception e) {}
		}
		
		terminalFactory = TerminalFactory.getDefault();
	}
	
	public static void setLogListener(StringProperty sp) {
		logListener = sp;
	}
	
	public static Connection getConnection() {
		if (connection == null) {
			connection = new Connection();
		}
		return connection;
	}
	
	public static List<CardTerminal> getTerminals() {
		getConnection();//Force create Connection singleton to ensure bug workaround on Linux
		try {
			return TerminalFactory.getDefault().terminals().list();
		} catch (CardException e) {
			return null;
		}
	}
	public ATR contectAutoToReader(CardTerminal ct) {
		try {
			if (ct.isCardPresent()) {
				terminal = ct;
				card = terminal.connect("*");
				channel = card.getBasicChannel();
				ATR atr = card.getATR();
				if (logListener != null) {
					logListener.set("Connected to " + ct.getName() + "\n");
					logListener.set("With protocol " + card.getProtocol() + "\n\n");
				}
				return atr;
			}
		} catch (CardException e) {
			if (logListener != null) {
				logListener.set("Issue with reader " + ct.getName() + ": " + e.getMessage() + "\n");
			}
		}
		return null;
	}
	public ATR connectAuto() {
		try {
			for (CardTerminal ct : terminalFactory.terminals().list()) {
				ATR atr = contectAutoToReader(ct);
				if (atr != null)
					return atr;
				if (logListener != null)
					logListener.set("Trying with reader:" + ct.getName() + "\n\n");

			}
		} catch (CardException e) {
			if (logListener != null)
				logListener.set("No reader found.\n");
		}
		return null;
	}
	public void disconnect() throws CardException {
		channel = null;
		card.disconnect(true);
	}
	public ATR coldReset() throws CardException {
		channel = null;
		card.disconnect(true);
		card = terminal.connect("*");
		channel = card.getBasicChannel();
		ATR atr = card.getATR();
		if (logListener != null) {
			logListener.set("Cold Reset\n");
			logListener.set("ATR: " + new StringHex(atr.getBytes()) + "\n\n");
		}
		return atr;
	}
	private void logBlock(String title, StringHex block) {
		String tmp;
		for (int i = 0; i < block.size(); i += 16) {
			if (i == 0 && title.equals("Send: ")) {
				tmp = title + block.get(0, Math.min(5, block.size()));
				if (logListener != null)
					logListener.set(tmp + "\n");
				i = i - 16 + 5;
			}
			else {
				tmp = (i == 0 ? title : "      ") + block.get(i, Math.min(16, block.size() - i));
				if (logListener != null)
					logListener.set(tmp + "\n");
			}
		}
	}
	private APDUResponse send(CommandAPDU command) throws CardException {
		logBlock("Send: ", new StringHex(command.getBytes()));
		APDUResponse response =  new APDUResponse(channel.transmit(command).getBytes());
		logBlock("Resp: ", new StringHex(response.toBytes()));
		if (logListener != null)
			logListener.set("\n");
		return response;
	}
	public APDUResponse send(StringHex header, StringHex data) throws CardException {
		byte[] bHeader = header.toBytes();
		assert(bHeader.length == 4);
		if (data == null)
			return send(new CommandAPDU(bHeader[0], bHeader[1], bHeader[2], bHeader[3], 256));
		else
			return send(new CommandAPDU(bHeader[0], bHeader[1], bHeader[2], bHeader[3], data.toBytes(), 256));
	}
	public APDUResponse send(String header, String data, String le) throws CardException {
		return send(new StringHex(header), data.isEmpty() ? null : new StringHex(data));
	}
	public APDUResponse send(String cmdName, String header, String data, String le) throws CardException {
		logComment(cmdName, "-");
		return send(header, data, le);
	}
	public void logComment(String comment, String pattern) {
		if (logListener != null) {
			String tmp = "";
			for (int i = 0; i < comment.length() + 2; i++)
				tmp += pattern;
			logListener.set(tmp + "\n");
			logListener.set(" " + comment + "\n");
			logListener.set(tmp + "\n");
		}
	}
	public boolean isConnected() {
		return channel != null;
	}
}
