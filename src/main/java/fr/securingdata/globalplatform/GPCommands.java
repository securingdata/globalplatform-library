package fr.securingdata.globalplatform;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.crypto.spec.SecretKeySpec;

import fr.securingdata.connection.APDUResponse;
import fr.securingdata.connection.ConnectionException;
import fr.securingdata.util.Crypto;
import fr.securingdata.util.StringHex;
import fr.securingdata.util.TLV;

public class GPCommands {
	public static final String SECURE_CLA = "84";
	
	public static final String INS_DELETE  = "E4";
	public static final String INS_INSTALL = "E6";
	public static final String INS_LOAD    = "E8";
	public static final String INS_PUT_KEY = "D8";
	
	public static final String P1_INSTALL_FOR_LOAD            = "02";
	public static final String P1_INSTALL_FOR_INSTALL         = "04";
	public static final String P1_INSTALL_FOR_MAKE_SELECTABLE = "08";
	
	public static final int BLOCK_LEN = 0x80;
	
	
	private SCP scp;
	
	public GPCommands(SCP scp) {
		this.scp = scp;
	}
	
	public static StringHex getRawCap(String path) {
		byte[] order = {1, 2, 4, 3, 6, 7, 8, 10, 5, 9, 11};
		byte[][] components = new byte[12][];
		
		try (ZipFile zip = new ZipFile(path)) {
			Enumeration<? extends ZipEntry> entries = zip.entries();
			
			
			while(entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();
				if (entry.getName().endsWith(".cap")) {
					byte[] componentData;
					try (BufferedInputStream bis = new BufferedInputStream(zip.getInputStream(entry))) {
						componentData = new byte[(int) entry.getSize()];
						bis.read(componentData);
					}
					components[componentData[0]] = componentData;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		StringHex raw = new StringHex("");
		for (byte o : order) {
			if (components[o] != null)
				raw = StringHex.concatenate(raw, new StringHex(components[o]));
		}
		
		return raw;
	}
	public void loadCAP(byte[] rawCap) throws ConnectionException {
		StringHex loadFileDataBlock = TLV.createTLV(new StringHex("C4"), new StringHex(rawCap));
		
		byte blockNumber = 0;
		for (int i = 0, remaining = loadFileDataBlock.size(); remaining > 0; i += BLOCK_LEN, remaining -= BLOCK_LEN, blockNumber++) {
			load(BLOCK_LEN >= remaining, blockNumber, loadFileDataBlock.get(i, Math.min(BLOCK_LEN, remaining)).toString());
		}
	}
	
	public APDUResponse select(String aid) throws ConnectionException {
		APDUResponse resp = scp.select(aid);
		return resp;
	}
	public APDUResponse initUpdate(byte kvn, byte kid) throws ConnectionException {
		return scp.initUpdate(kvn, kid);
	}
	public APDUResponse externalAuth(byte secLevel) throws ConnectionException {
		return scp.externalAuth(secLevel);
	}

	public APDUResponse delete(String aid, boolean related) throws ConnectionException {
		return scp.send("Delete", SECURE_CLA + INS_DELETE + "00" + (related ? "80" : "00"), TLV.createTLV(new StringHex("4F"), new StringHex(aid)).toString(), "00");
	}
	public APDUResponse installForLoad(String pckgAID, String sdAid) throws ConnectionException {
		return installForLoad(pckgAID, sdAid, "", "", "");
	}
	public APDUResponse installForLoad(String pckgAID, String sdAid, String hash, String loadParam, String token) throws ConnectionException {
		StringHex shPckgAID = new StringHex(pckgAID);
		StringHex shSdAid = new StringHex(sdAid);
		StringHex shHash = new StringHex(hash);
		StringHex shLoadParam = new StringHex(loadParam);
		StringHex shToken = new StringHex(token);
		
		return scp.send("Install For Load", SECURE_CLA + INS_INSTALL + P1_INSTALL_FOR_LOAD + "00", 
				TLV.createLV(shPckgAID).toString() +
				TLV.createLV(shSdAid).toString() + 
				TLV.createLV(shHash).toString() + 
				TLV.createLV(shLoadParam).toString() + 
				TLV.createLV(shToken).toString(), "00");
	}
	
	public APDUResponse installForInstallAndMakeSelectable(String loadFileAID, String moduleAID, String appAID, String privileges, String parameters) throws ConnectionException {
		StringHex shLoadFileAID = new StringHex(loadFileAID);
		StringHex shModuleAID = new StringHex(moduleAID);
		StringHex shAppAID = new StringHex(appAID);
		StringHex shPrivileges = new StringHex((privileges == null || privileges.isEmpty()) ? "00" : privileges);
		StringHex shParameters = new StringHex((parameters == null || parameters.isEmpty()) ? "C9 01 00" : parameters);
		
		String p1 = new StringHex(P1_INSTALL_FOR_INSTALL).xor(new StringHex(P1_INSTALL_FOR_MAKE_SELECTABLE)).toString();
		
		return scp.send("Install For Install And Make Selectable", SECURE_CLA + INS_INSTALL + p1 + "00", 
				StringHex.byteToHex((byte)shLoadFileAID.size()) + shLoadFileAID.toString() +
				StringHex.byteToHex((byte)shModuleAID.size()) + shModuleAID.toString() + 
				StringHex.byteToHex((byte)shAppAID.size()) + shAppAID.toString() + 
				StringHex.byteToHex((byte)shPrivileges.size()) + shPrivileges.toString() + 
				StringHex.byteToHex((byte)shParameters.size()) + shParameters.toString() +
				"00", "00");
	}
	
	public APDUResponse load(boolean lastBlock, byte blockNumber, String block) throws ConnectionException {
		return scp.send("Load", SECURE_CLA + INS_LOAD + (lastBlock ? "80" : "00") + StringHex.byteToHex(blockNumber), block, "00");
	}
	public APDUResponse getData(String tag) throws ConnectionException {
		String cla = scp.secLevel != 0 ? SECURE_CLA : "00";
		return scp.send("Get Data", cla + "CA" + tag, "", "");
	}
	public APDUResponse storeData(String data) throws ConnectionException {
		return scp.send("Store Data", SECURE_CLA + "E2 9000", data, "");
	}
	
	public APDUResponse putDESKeys(boolean create, StringHex kenc, StringHex kmac, StringHex kdek) throws ConnectionException, GeneralSecurityException {
		StringHex checkData = SCP02.EIGHT_BYTES_NULL;
		String header = SECURE_CLA + INS_PUT_KEY + (create ? "00" : "20") + "81";
		String data = "20";
		
		//kenc
		String encryptedKey = scp.encrypt(kenc).toString();
		String checksum = SCP02.encrypt(kenc, checkData).get(0, 3).toString();
		data += "80 10 " + encryptedKey + " 03 " + checksum;
		
		//kmac
		encryptedKey = scp.encrypt(kmac).toString();
		checksum = SCP02.encrypt(kmac, checkData).get(0, 3).toString();
		data += "80 10 " + encryptedKey + " 03 " + checksum;
		
		//kdek
		encryptedKey = scp.encrypt(kdek).toString();
		checksum = SCP02.encrypt(kdek, checkData).get(0, 3).toString();
		data += "80 10 " + encryptedKey + " 03 " + checksum;
		
		return scp.send("Put Key DES (" + (create ? "Create)" : "Update)"), header, data, "");
	}
	public APDUResponse putAESKeys(boolean create, StringHex kenc, StringHex kmac, StringHex kdek) throws ConnectionException, GeneralSecurityException {
		StringHex checkData = new StringHex("01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01");
		String header = SECURE_CLA + INS_PUT_KEY + (create ? "00" : "30") + "81";
		String data = "30";
		
		//kenc
		String encryptedKey = scp.encrypt(kenc).toString();
		String checksum = Crypto.aes(new SecretKeySpec(kenc.toBytes(), "AES"), checkData).get(0, 3).toString();
		data += "88 10 " + encryptedKey + " 03 " + checksum;
		
		//kmac
		encryptedKey = scp.encrypt(kmac).toString();
		checksum = Crypto.aes(new SecretKeySpec(kmac.toBytes(), "AES"), checkData).get(0, 3).toString();
		data += "88 10 " + encryptedKey + " 03 " + checksum;
		
		//kdek
		encryptedKey = scp.encrypt(kdek).toString();
		checksum = Crypto.aes(new SecretKeySpec(kdek.toBytes(), "AES"), checkData).get(0, 3).toString();
		data += "88 10 " + encryptedKey + " 03 " + checksum;
		
		return scp.send("Put Key AES (" + (create ? "Create)" : "Update)"), header, data, "");
	}
	public APDUResponse putTokenKey(boolean create, StringHex pub) throws ConnectionException, GeneralSecurityException {
		String header = SECURE_CLA + INS_PUT_KEY + (create ? "00" : "70") + "01";
		String data = "70";
		
		data += TLV.createTLV(new StringHex("B0"), pub).toString();
		//data += "F0 01 02";//Key Parameter Reference P-521
		data += "00";//No key check
		
		return scp.send("Put Key ECC (" + (create ? "Create)" : "Update)"), header, data, "");
	}
}
