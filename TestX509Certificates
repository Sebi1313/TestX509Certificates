import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.security.cert.Certificate;


/**
 * Created by mg13 on 8/8/2015.
 */
public class TestX509Certificates {

    private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week
    private static final int RSA_SEC_PARAM = 1024;
    private static SecureRandom random = new SecureRandom();
    private static final String X509_CERTIFICATE_SIGNATURE_ALGORITHM = "SHA256WITHRSAENCRYPTION";
    private static final String ROOT_ALIAS = "root";
    private static final String INTERMEDIATE_ALIAS = "intermediate";
    private static final String END_ENTITY_ALIAS = "end";

    public static KeyPair generateRSAKeyPair()
            throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(RSA_SEC_PARAM, random);

        return kpGen.generateKeyPair();
    }

    /**
     * Generate a sample V1 certificate to use as a CA root certificate
     */
    public static X509Certificate generateRootCert(KeyPair pair) throws Exception {

        // Pick the public-key signature algorithm to sign certificates. We are using RSA
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(X509_CERTIFICATE_SIGNATURE_ALGORITHM);
        // Pick the algorithm to perform the hashing on the information to be signed. We
        // sign the resulting hash
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        // Retrieve the private key which is used to sign the certificate
        AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
        // Retrieve the pulic key information used by the subject to verify
        // the signature
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
        // Define the validity period. The certificate may expire before the
        // end date but not after.
        Date startDate = new Date(System.currentTimeMillis());
        Date endDate = new Date(System.currentTimeMillis() + VALIDITY_PERIOD);
        X500Name name = new X500Name("CN=Root");
        // Create unique serial number for the certificate (need to check if it
        // it's actually unique)
        BigInteger serialNum = BigInteger.valueOf(new SecureRandom().nextLong());
        // Generate the actual certificate
        X509v1CertificateBuilder certGen = new X509v1CertificateBuilder(name, serialNum, startDate, endDate, name, subPubKeyInfo);
        // Sign it
        X509CertificateHolder certificateHolder = certGen.build(sigGen);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);

    }

    /**
     * Generate a sample V3 certificate to use as an intermediate CA certificate
     */
    public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert) throws Exception {

        ASN1Sequence seq = null;

        seq = (ASN1Sequence) new ASN1InputStream(intKey.getEncoded()).readObject();
        SubjectPublicKeyInfo parentPubKeyInfo = new SubjectPublicKeyInfo(seq);
        // Define the validity period. The certificate may expire before the
        // end date but not after.
        Date startDate = new Date(System.currentTimeMillis());
        Date endDate = new Date(System.currentTimeMillis() + VALIDITY_PERIOD);
        ContentSigner signer = null;

        signer = new JcaContentSignerBuilder(X509_CERTIFICATE_SIGNATURE_ALGORITHM).build(caKey);

        // Create unique serial number for the certificate (need to check if it
        // it's actually unique)
        BigInteger serialNum = BigInteger.valueOf(new SecureRandom().nextLong());
        X509v3CertificateBuilder certGen = null;

        certGen = new JcaX509v3CertificateBuilder(
                caCert,
                serialNum,
                startDate,
                endDate,
                new X500Principal("CN=Intermediate Certificate"),
                intKey)
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.35"),
                        false,
                        new AuthorityKeyIdentifier(parentPubKeyInfo))
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.19"),
                        false,
                        new BasicConstraints(false)) // true if it is allowed to sign other certs
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.15"),
                        true,
                        new X509KeyUsage(
                                X509KeyUsage.digitalSignature |
                                        X509KeyUsage.nonRepudiation |
                                        X509KeyUsage.keyEncipherment |
                                        X509KeyUsage.dataEncipherment));

        // Build/sign the certificate.
        X509CertificateHolder certHolder = certGen.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        return cert;
    }

    /**
     * Generate a sample V3 certificate to use as an end entity certificate
     */
    public static X509Certificate generateEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert) throws Exception {
        ASN1Sequence seq = null;
        seq = (ASN1Sequence) new ASN1InputStream(entityKey.getEncoded()).readObject();
        SubjectPublicKeyInfo parentPubKeyInfo = new SubjectPublicKeyInfo(seq);
        // Define the validity period. The certificate may expire before the
        // end date but not after.
        Date startDate = new Date(System.currentTimeMillis());
        Date endDate = new Date(System.currentTimeMillis() + VALIDITY_PERIOD);
        ContentSigner signer = null;

        signer = new JcaContentSignerBuilder(X509_CERTIFICATE_SIGNATURE_ALGORITHM).build(caKey);

        // Create unique serial number for the certificate (need to check if it
        // it's actually unique)
        BigInteger serialNum = BigInteger.valueOf(new SecureRandom().nextLong());

        X509v3CertificateBuilder certGen = null;

        certGen = new JcaX509v3CertificateBuilder(
                caCert,
                serialNum,
                startDate,
                endDate,
                new X500Principal("CN=End Certificate"),
                entityKey)
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.35"),
                        false,
                        new AuthorityKeyIdentifier(parentPubKeyInfo))
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.19"),
                        false,
                        new BasicConstraints(false)) // true if it is allowed to sign other certs
                .addExtension(
                        new ASN1ObjectIdentifier("2.5.29.15"),
                        true,
                        new X509KeyUsage(
                                X509KeyUsage.digitalSignature |
                                        X509KeyUsage.nonRepudiation |
                                        X509KeyUsage.keyEncipherment |
                                        X509KeyUsage.keyCertSign |
                                        X509KeyUsage.cRLSign |
                                        X509KeyUsage.dataEncipherment));


        // Build/sign the certificate.
        X509CertificateHolder certHolder = certGen.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        return cert;
    }

    /**
     * Generate a X500PrivateCredential for the root entity.
     */
    public static X500PrivateCredential createRootCredential() throws Exception {
        KeyPair rootPair = null;

        rootPair = generateRSAKeyPair();

        X509Certificate rootCert = generateRootCert(rootPair);

        return new X500PrivateCredential(rootCert, rootPair.getPrivate(), ROOT_ALIAS);
    }

    /**
     * Generate a X500PrivateCredential for the intermediate entity.
     */
    public static X500PrivateCredential createIntermediateCredential(
            PrivateKey caKey,
            X509Certificate caCert) throws Exception {
        KeyPair interPair = null;

        interPair = generateRSAKeyPair();

        X509Certificate interCert = generateIntermediateCert(interPair.getPublic(), caKey, caCert);

        return new X500PrivateCredential(interCert, interPair.getPrivate(), INTERMEDIATE_ALIAS);
    }

    /**
     * Generate a X500PrivateCredential for the end entity.
     */
    public static X500PrivateCredential createEndEntityCredential(
            PrivateKey caKey,
            X509Certificate caCert) throws Exception {
        KeyPair endPair = null;

        endPair = generateRSAKeyPair();

        X509Certificate endCert = generateEndEntityCert(endPair.getPublic(), caKey, caCert);

        return new X500PrivateCredential(endCert, endPair.getPrivate(), END_ENTITY_ALIAS);
    }

    public static void main(String[] args) throws Exception {
        // Retrieve root, intermediate and end entity credentials
        X500PrivateCredential rootCredential = createRootCredential();
        X500PrivateCredential interCredential = createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
        X500PrivateCredential endCredential = createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());

        // client credentials
        KeyStore keyStore = null;

        keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", endCredential.getPrivateKey(), "clientPassword".toCharArray(),
                new Certificate[]{endCredential.getCertificate(), interCredential.getCertificate(), rootCredential.getCertificate()});
        keyStore.store(new FileOutputStream("client.p12"), "clientPassword".toCharArray());

        // trust store for client
        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setCertificateEntry("trust", rootCredential.getCertificate());

        keyStore.store(new FileOutputStream("trust.jks"), "trustPassword".toCharArray());

        // server credentials
        keyStore = KeyStore.getInstance("JKS");

        keyStore.load(null, null);

        keyStore.setKeyEntry("server", rootCredential.getPrivateKey(), "serverPassword".toCharArray(),
                new Certificate[]{rootCredential.getCertificate()});

        keyStore.store(new FileOutputStream("server.jks"), "serverPassword".toCharArray());
    }
}
