// package de.srlabs.patchanalysis_module.analysis.signatures;

// import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.security.MessageDigest;
import java.io.RandomAccessFile;

// import de.srlabs.patchanalysis_module.Constants;
// import de.srlabs.patchanalysis_module.helpers.ProcessHelper;
class Mask {

    private int position;
    private long mask;

    public Mask(int position, long mask){
        this.mask = mask;
        this.position = position;
    }
    public int getPosition(){
        return position;
    }
    public long getMask(){
        return mask;
    }

}


/** Contains code length, checksum (SHA256) and list of masks
 *  Idea: Use mask to zero out all bits which can be change due to relocation entries in .o file
 * Created by jonas on 14.12.17.
 */
public class MaskSignature {

	public static final String SIGNATURE_TYPE = "MASK";
	private List<Mask> maskList = new ArrayList<>();
	private String signatureType;
	private String architecture;
	private int codeLen;
	private byte[] originalCode;
	private String checksumSha256;

	// 2020-11-26 16:45:24.737 | INFO     | analysis.TestEngine:runMaskSignatureTest:611 - /home/vancir/Downloads/meilan_note3/meilannote3/meilannote3/system/lib64/libsonivox.so
	// 2020-11-26 16:45:24.737 | INFO     | analysis.TestEngine:runMaskSignatureTest:612 - MASK:4e4:6d1a89b7be605dd6fe45638f3ac4fe639789e4731cc4fde57ac4aa601e0e0a86:0020A_0004B_0028C_0018C_001cC_0038C_00b4C_0098C_0080C_0038C_001cC_0010C_00a0C_0018C_0098C_0010A_0008B_0008C_0020C_0014C_002cC_0028C
	// 2020-11-26 16:45:24.770 | INFO     | analysis.TestEngine:runMaskSignatureTest:639 - /system/lib64/libsonivox.so DLSParser 39652 1256
	// 2020-11-26 16:45:24.771 | INFO     | analysis.signatures.MaskSignature:checkCodeBuf:83 -  
	// 6d1a89b7be605dd6fe45638f3ac4fe639789e4731cc4fde57ac4aa601e0e0a86
	// 8a3548825c53da2e487d3d73efa300a69da3e8a62c108a1d506efdbef42debda
	public static void main(String[] args) {
		try {
			String filename = "/home/vancir/Downloads/meilan_note3/meilannote3/meilannote3/system/lib64/libsonivox.so";
			// String filename = "libsonivox.so";
			String signature = "MASK:4e4:6d1a89b7be605dd6fe45638f3ac4fe639789e4731cc4fde57ac4aa601e0e0a86:0020A_0004B_0028C_0018C_001cC_0038C_00b4C_0098C_0080C_0038C_001cC_0010C_00a0C_0018C_0098C_0010A_0008B_0008C_0020C_0014C_002cC_0028C";
			MaskSignature signatureChecker = new MaskSignature();
			signatureChecker.parse(signature);
			long symbolPos = 39652;
			int symbolLength = 1256;
	
			byte[] codeBuf = new byte[symbolLength];
			RandomAccessFile file = new RandomAccessFile(filename, "r");
			file.seek(symbolPos);
			file.read(codeBuf);
			file.close();
	
			boolean result =  signatureChecker.checkCodeBuf(codeBuf);
			System.out.println(result);
			
			byte[] myvar = "Any String you want".getBytes();
			String Hashresult = signatureChecker.sha256(myvar);
			System.out.println(Hashresult);
		} catch (Exception e) {
			//TODO: handle exception
		}

	}

	public MaskSignature() {
		maskList = new ArrayList<>();
	}

	/**
	 * Reads a signature based on sigStr
	 * @param signatureString
	 */
	public MaskSignature parse(String signatureString) throws IOException{
		String[] parts  = signatureString.split(":");
		if (parts.length == 4 || parts.length == 3) {
			this.signatureType = parts[0];
			this.codeLen = Integer.parseInt(parts[1], 16);
			this.checksumSha256 = parts[2];
			//Log.i(Constants.LOG_TAG,"sha256 checksum:"+this.checksumSha256);
			String[] maskStrList = null;
			if(parts.length == 4) {
				String maskString = parts[3];
				maskStrList = maskString.split("_");
			}
			else{
				maskStrList = new String[]{};
			}

			int pos = 0;
			for (String maskStr : maskStrList) {
				int offset = Integer.parseInt(maskStr.substring(0, 4), 16);
				String maskCode = maskStr.substring(4);
				long mask = 0;
				switch (maskCode) {
				case "A":
					mask = 0x9f00001fL;
					break;
				case "B":
					mask = 0xffc003ffL;
					break;
				case "C":
					mask = 0xfc000000L;
					break;
				default:
					if (maskCode.length() == 8) {
						mask = Long.parseLong(maskCode, 16);
					} else {
						throw new IllegalStateException("Mask code not neccessary length!");
					}
				}
				pos += offset;
				this.maskList.add(new Mask(pos, mask));
			}
			return this;
		}
		else{
			throw new IOException("Exception while parsing mask signature string: "+signatureString);
		}
		//Log.e(Constants.LOG_TAG,"Error while parsing signature string, wrong format!");
	}

	public int getCodeLength() {
		return this.codeLen;
	}

	public String getSignatureType() {
		return this.signatureType;
	}



	public static String sha256(byte[] base) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(base);
			StringBuilder hexString = new StringBuilder();

			for (int i = 0; i < hash.length; i++) {
				String hex = Integer.toHexString(0xff & hash[i]);
				if (hex.length() == 1) hexString.append('0');
				hexString.append(hex);
			}

			return hexString.toString();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}


	/**
	 * unpack byte array to unsigned 32bit integer and wrap as long
	 */
	public static long unpack(byte[] bytes) {
		long value = bytes[0] & 0xFFL;
		value |= (bytes[1] << 8) & 0xFFFFL;
		value |= (bytes[2] << 16) & 0xFFFFFFL;
		value |= (bytes[3] << 24) & 0xFFFFFFFFL;
		return value;
	}

	/**
	 * pack unsigned 32bit integer (wrapped in long) to byte array
	 * @param i
	 * @return
	 */
	public static byte[] pack(long i) {
		byte[] result = new byte[4];
		result[3] = (byte) ((i >> 24) & 0xff);
		result[2] = (byte) ((i >> 16) & 0xff);
		result[1] = (byte) ((i >> 8) & 0xff);
		result[0] = (byte) ((i >> 0) & 0xff);
		return result;
	}



	/**
	 * Checks if the signature matches the given code
	 * @return
	 */
	public boolean checkCodeBuf(byte[] code) {

		ByteArrayOutputStream maskedCode = new ByteArrayOutputStream();
		int maskPos = 0;
		for (int i = 0; i < code.length; i += 4) {
			byte[] instBytes = Arrays.copyOfRange(code, i, i + 4);
			if (maskPos < this.maskList.size() && this.maskList.get(maskPos).getPosition() == i) {
				// System.out.println("instBytes before");
				// for (int j=0; j<instBytes.length; j++) {
				// 	System.out.format("%02X ", instBytes[j]);
				// }
				// System.out.println("");
				long inst = this.unpack(instBytes);
				// System.out.println("inst unpacked:" + inst);
				
				inst = (inst & this.maskList.get(maskPos).getMask());
				// System.out.println("inst masked:" + inst);
				
				// System.out.println("instBytes repacked:");
				instBytes = this.pack(inst);
				// for (int j=0; j<instBytes.length; j++) {
				// 	System.out.format("%02X ", instBytes[j]);
				// }
				// System.out.println("");
				maskPos += 1;
			}
			try {
				// System.out.println(instBytes);
				maskedCode.write(instBytes);
			} catch (IOException e) {
				//Log.e(Constants.LOG_TAG,"Error when appending bytes: "+e);
			}
		}
		// for (byte b : maskedCode.toByteArray()) { 
  
        //     // Print the byte 
        //     System.out.println(b); 
        // } 

		String calculatedHash = this.sha256(maskedCode.toByteArray());
		if(this.checksumSha256 == null)
			// Log.d(Constants.LOG_TAG,"sha256 is null: parsed");
			System.out.println("sha256 is null: parsed");
		if(calculatedHash == null)
			// Log.d(Constants.LOG_TAG,"sha256 is null: calculated");
			System.out.println("sha256 is null: parsed");
		
		System.out.println(this.checksumSha256 + " " + calculatedHash);
		if (this.checksumSha256.equals(calculatedHash)) {
			return true;
		}
		return false;
	}

}
