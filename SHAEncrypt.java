import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SHAEncrypt {

    private String mPassword;
    private String mEncType = "SHA-512";
    private String mData;
    private String output = "";

    public SHAEncrypt(String data, String password) {
        this.mData = data;
        this.mPassword = password;
    }

    public SHAEncrypt(String data, String password, String encType) {
        this.mData = data;
        this.mPassword = password;
        this.mEncType = encType;
    }

    private byte[] encryptSHA() {
        byte[] byteData = mData.getBytes();
        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance(mEncType);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        sha.update(byteData);
        return sha.digest();
    }

    private String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    public String encrypt(){
        Mac sha512 = null;
        String sHMAC = "HMAC-" + mEncType.replace("-","");
        try {
            sha512 = Mac.getInstance(sHMAC);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecretKeySpec s_key = new SecretKeySpec(mPassword.getBytes(), sHMAC);

        try {
            sha512.init(s_key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        byte[] bytes = sha512.doFinal(mData.getBytes());

        output = bytesToHex(bytes);
        return output;
    }

}
