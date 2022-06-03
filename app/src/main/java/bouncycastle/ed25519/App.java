package bouncycastle.ed25519;

import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.*;
import java.security.*;

public class App {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {

        Security.addProvider(new BouncyCastleProvider());

        var keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC");
        keyPairGenerator.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed25519), new SecureRandom());

        var keyPair = keyPairGenerator.generateKeyPair();

        var privateKey = new PemObject("EC PRIVATE KEY", keyPair.getPrivate().getEncoded());

        var file = new File("key.pem");
        System.out.println("writing ed25519 key to '" + file.getAbsolutePath() + "'");

        try (var bufferedWriter = new BufferedWriter(new FileWriter(file))) {
            try (var pemWriter = new JcaPEMWriter(bufferedWriter)) {
                pemWriter.writeObject(privateKey);
            }
        }
    }
}
