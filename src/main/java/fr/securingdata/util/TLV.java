package fr.securingdata.util;

public class TLV {
	
	public static StringHex createLV(String data) {
		return createLV(new StringHex(data));
	}
	public static StringHex createLV(StringHex data) {
		String len;
		if (data.size() < 0x80) {
			len = StringHex.byteToHex((byte) data.size());
		}
		else if (data.size() <= 0xFF) {
			len = "81 " + StringHex.byteToHex((byte) data.size());
		}
		else if (data.size() <= 0xFFFF) {
			len = "82 " + StringHex.shortToHex((short) data.size());
		}
		else {
			System.out.println("Not supported yet");
			return null;
		}
		return StringHex.concatenate(new StringHex(len), data);
	}
	
	public static StringHex createTLV(String tag, String data) {
		return createTLV(new StringHex(tag), new StringHex(data));
	}
	public static StringHex createTLV(StringHex tag, StringHex data) {
		return StringHex.concatenate(tag, createLV(data));
	}
}
