package fr.securingdata.util;

public class TLV {
	
	public static StringHex createTLV(StringHex tag, StringHex data) {
		String len;
		if (data.size() <= 0x7F) {
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
		return StringHex.concatenate(tag, new StringHex(len), data);
	}
}
