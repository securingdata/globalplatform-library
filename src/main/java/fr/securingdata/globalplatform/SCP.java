package fr.securingdata.globalplatform;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardTerminal;

import fr.securingdata.connection.APDUResponse;
import fr.securingdata.connection.Application;
import fr.securingdata.connection.ConnectionException;
import fr.securingdata.util.Bits;
import fr.securingdata.util.StringHex;

public abstract class SCP extends Application implements Bits {
	
	public enum StaticDerivation {
		NO_DERIVATION, EMVCPS1_1, VISA, VISA2;
	}
	public enum KeyName {
		DEFAULT_KENC((short) 1),
		DEFAULT_KMAC((short) 2),
		DEFAULT_KDEK((short) 3),
		SCP02_KENC((short) 0x2001),
		SCP02_KMAC((short) 0x2002),
		SCP02_KDEK((short) 0x2003),
		SCP03_KENC((short) 0x3001),
		SCP03_KMAC((short) 0x3002),
		SCP03_KDEK((short) 0x3003);
		
		public final short kvnAndKid;
		private KeyName(short kvnAndKid) {
			this.kvnAndKid = kvnAndKid;
		}
	}
	
	public static final byte SEC_LEVEL_NO       = ZERO;
	public static final byte SEC_LEVEL_C_MAC    = BIT1;
	public static final byte SEC_LEVEL_C_DEC    = BIT2;
	public static final byte SEC_LEVEL_R_MAC    = BIT5;
	public static final byte SEC_LEVEL_R_ENC    = BIT6;
	public static final byte SEC_LEVEL_ANY_AUTH = BIT7;
	public static final byte SEC_LEVEL_AUTH     = BIT8;
	
	public static final String DEFAULT_KENC = "DEFAULT_KENC";
	
	protected static final int KEY_DIV_DATA_LEN = 10;
	protected              int KEY_INFO_LEN;
	protected static final int CHALLENGE_LEN    = 8;
	protected static final int CRYPTOGRAM_LEN   = 8;
	
	protected static final String SENC_NAME = "sEnc";
	protected static final String SMAC_NAME = "sMac";
	protected static final String RMAC_NAME = "rMac";
	protected static final String KDEK_NAME = "kDek";
	
	protected HashMap<Short, Key> keySet;
	protected StaticDerivation staticDerivation;
	protected byte implementation;
	
	protected short currentKeys;
	protected byte secLevel;
	protected Key sEnc;
	protected Key sMac, rMac;
	protected Key kDek;
	protected StringHex macChaining;
	protected StringHex hostChallenge;
	protected StringHex cardChallenge;
	protected StringHex cardCrypto;
	protected StringHex hostCrypto;
	protected StringHex keyDivData;
	protected StringHex keyInfo;
	protected StringHex derivationData;
	
	protected SCP(CardTerminal reader) {
		super(reader);
		keySet = new HashMap<>();
		staticDerivation = StaticDerivation.NO_DERIVATION;
		KEY_INFO_LEN = 2;
		secLevel = SEC_LEVEL_NO;
		byte[] tmp = new byte[8];
		new Random().nextBytes(tmp);
		hostChallenge = new StringHex(tmp);
	}
	
	public void coldReset() throws ConnectionException {
		super.coldReset();
		secLevel = SEC_LEVEL_NO;
		macChaining = null;
		derivationData = null;
	}
	public void setImplementationOption(byte implementation) {
		this.implementation = implementation;
	}
	public void setStaticDerivation(StaticDerivation staticDerivation) {
		this.staticDerivation = staticDerivation;
	}
	public void addKey(KeyName keyName, Key key) {
		keySet.put(keyName.kvnAndKid, key);
	}
	
	@Deprecated
	public abstract String getCipherName();
	@Deprecated
	public Cipher getCipher() throws GPException {
		try {
			return Cipher.getInstance(getCipherName());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new GPException("Crypto exception.", e.getCause());
		}
	}
	
	private void setCurrentKeys(byte kvn, byte kid) {
		currentKeys = (short) (((kvn << 8) & 0xFF00) | (kid & 0xFF));
	}
	protected Key getKey(short kvnAndKid) {
		return keySet.get(Short.valueOf(kvnAndKid));
	}
	public Key instanciateKey(String key) {
		return instanciateKey(new StringHex(key));
	}
	public Key instanciateKey(StringHex key) {
		return instanciateKey(key.toBytes());
	}
	public abstract Key instanciateKey(byte[] keyValue);
	protected static Key convertInTDES(Key k) {
		return convertInTDES(new StringHex(k.getEncoded()));
	}
	protected static Key convertInTDES(StringHex des2) {
		if (des2.size() == 16)
			des2 = StringHex.concatenate(des2, des2.get(0, 8));
		return new SecretKeySpec(des2.toBytes(), "DESede");
	}
	public void setSessionKey(String keyName, StringHex keyValue) throws GPException {
		setSessionKey(keyName, keyValue.toBytes());
	}
	public void setSessionKey(String keyName, byte[] keyValue) throws GPException {
		switch (keyName) {
			case SENC_NAME:
				sEnc = instanciateKey(keyValue);
				return;
			case SMAC_NAME:
				sMac = instanciateKey(keyValue);
				return;
			case RMAC_NAME:
				rMac = instanciateKey(keyValue);
				return;
			case KDEK_NAME:
				kDek = instanciateKey(keyValue);
				return;
			default:
				throw new GPException("Unknown key name.");
		}
	}
	public void deriveStaticKeys() throws GPException {
		StringHex kdd = null;
		Cipher cipher;
		
		try {
			switch(staticDerivation) {
				case NO_DERIVATION:
					setSessionKey(SENC_NAME, getKey((short) (currentKeys + 1)).getEncoded());
					setSessionKey(SMAC_NAME, getKey((short) (currentKeys + 2)).getEncoded());
					setSessionKey(KDEK_NAME, getKey((short) (currentKeys + 3)).getEncoded());
					return;
				case EMVCPS1_1:
					kdd = StringHex.concatenate(keyDivData.get(4, 6), new StringHex("F0 01"), 
												keyDivData.get(4, 6), new StringHex("0F 01"));
					cipher = Cipher.getInstance("DESede/ECB/NoPadding");
					
					cipher.init(Cipher.ENCRYPT_MODE, convertInTDES(getKey((short) (currentKeys + 1))));
					setSessionKey(SENC_NAME, cipher.doFinal(kdd.toBytes()));

					cipher.init(Cipher.ENCRYPT_MODE, convertInTDES(getKey((short) (currentKeys + 2))));
					kdd.set(7, (byte) 0x02);
					kdd.set(15, (byte) 0x02);
					setSessionKey(SMAC_NAME, cipher.doFinal(kdd.toBytes()));
					
					cipher.init(Cipher.ENCRYPT_MODE, convertInTDES(getKey((short) (currentKeys + 3))));
					kdd.set(7, (byte) 0x03);
					kdd.set(15, (byte) 0x03);
					setSessionKey(KDEK_NAME, cipher.doFinal(kdd.toBytes()));
					break;
				case VISA:
					cipher = Cipher.getInstance("DESede/ECB/NoPadding");
					kdd = keyDivData.get(2, 8);
					
					cipher.init(Cipher.ENCRYPT_MODE, convertInTDES(getKey((short) (currentKeys + 1))));
					StringHex left = new StringHex("FF FF");
					StringHex right = new StringHex("01 00 00 00 00 00");
					setSessionKey(SENC_NAME, cipher.doFinal(StringHex.concatenate(left, kdd, right).toBytes()));
					
					cipher.init(Cipher.ENCRYPT_MODE, convertInTDES(getKey((short) (currentKeys + 2))));
					left = new StringHex("00 00");
					right = new StringHex("02 00 00 00 00 00");
					setSessionKey(SMAC_NAME, cipher.doFinal(StringHex.concatenate(left, kdd, right).toBytes()));
					
					cipher.init(Cipher.ENCRYPT_MODE, convertInTDES(getKey((short) (currentKeys + 3))));
					left = new StringHex("F0 F0");
					right = new StringHex("03 00 00 00 00 00");
					setSessionKey(KDEK_NAME, cipher.doFinal(StringHex.concatenate(left, kdd, right).toBytes()));
					break;
				case VISA2:
					kdd = StringHex.concatenate(keyDivData.get(0, 2), keyDivData.get(4, 4), new StringHex("F0 01"), 
												keyDivData.get(0, 2), keyDivData.get(4, 4), new StringHex("0F 01"));
					cipher = Cipher.getInstance("DESede/ECB/NoPadding");
					
					cipher.init(Cipher.ENCRYPT_MODE, convertInTDES(getKey((short) (currentKeys + 1))));
					setSessionKey(SENC_NAME, cipher.doFinal(kdd.toBytes()));
					
					cipher.init(Cipher.ENCRYPT_MODE, convertInTDES(getKey((short) (currentKeys + 2))));
					kdd.set(7, (byte) 0x02);
					kdd.set(15, (byte) 0x02);
					setSessionKey(SMAC_NAME, cipher.doFinal(kdd.toBytes()));
					
					cipher.init(Cipher.ENCRYPT_MODE, convertInTDES(getKey((short) (currentKeys + 3))));
					kdd.set(7, (byte) 0x03);
					kdd.set(15, (byte) 0x03);
					setSessionKey(KDEK_NAME, cipher.doFinal(kdd.toBytes()));
					break;
			}
		} catch (GeneralSecurityException e) {
			throw new GPException("Crypto exception. " + e.getMessage(), e.getCause());
		}
	}
	public abstract void computeSessionKeys() throws GPException;
	public abstract void computeCryptograms() throws GPException;
	public abstract String wrap(String header, String data, String le) throws GPException;
	public abstract APDUResponse unwrap(APDUResponse response) throws GPException;
	public abstract StringHex encrypt(StringHex data) throws GeneralSecurityException;
	
	public APDUResponse initUpdate(byte kvn, byte kid) throws ConnectionException {
		assert(hostChallenge.size() == 8);
		APDUResponse response = send("Initialize Update", "8050" + StringHex.byteToHex(kvn) + StringHex.byteToHex(kid), hostChallenge.toString(), "00");
		secLevel = SEC_LEVEL_NO;
		
		if ((response.getStatusWord() & 0xFFFF) == 0x9000) {
			setCurrentKeys(kvn, kid);
			keyDivData = response.get(0, KEY_DIV_DATA_LEN);
			keyInfo = response.get(KEY_DIV_DATA_LEN, KEY_INFO_LEN);
			cardChallenge = response.get(KEY_DIV_DATA_LEN + KEY_INFO_LEN, CHALLENGE_LEN);
			cardCrypto = response.get(KEY_DIV_DATA_LEN + KEY_INFO_LEN + CHALLENGE_LEN, CRYPTOGRAM_LEN);
		}
		else {
			throw new GPException(Integer.toHexString(response.getStatusWord() & 0xFFFF) + " obtained instead of 9000 in Initialize Update command");
		}
		
		deriveStaticKeys();
		computeSessionKeys();
		computeCryptograms();
		
		return response;
	}
	public APDUResponse externalAuth(byte secLevel) throws ConnectionException {
		return externalAuth(secLevel, true);
	}
	public APDUResponse externalAuth(byte secLevel, boolean exceptionOnFail) throws ConnectionException {
		this.secLevel = (byte) (SEC_LEVEL_AUTH | SEC_LEVEL_C_MAC);//Hack to force a correct wrapping
		APDUResponse response = send("External Authenticate", "84 82 " + StringHex.byteToHex(secLevel) + " 00", hostCrypto.toString(), "00");
		if ((response.getStatusWord() & 0xFFFF) == 0x9000) {
			this.secLevel = (byte) (SEC_LEVEL_AUTH | secLevel);
		}
		else {
			this.secLevel = SEC_LEVEL_NO;
			if (exceptionOnFail)
				throw new GPException(Integer.toHexString(response.getStatusWord()) + " obtained instead of 9000 in External Authenticate command");
		}
		
		return response;
	}
}
