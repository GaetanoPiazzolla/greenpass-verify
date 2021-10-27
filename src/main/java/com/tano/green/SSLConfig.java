package com.tano.green;

import okhttp3.CipherSuite;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.TlsVersion;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collections;

public class SSLConfig {

    public static OkHttpClient getHttpClient() throws CertificateException, IOException,
            KeyStoreException, NoSuchAlgorithmException, KeyManagementException {

        // Loading CAs from an InputStream
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        InputStream cert = SSLConfig.class.getClassLoader().getResourceAsStream("certificate.cer");
        Certificate ca = cf.generateCertificate(cert);

        // Creating a KeyStore containing our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore   = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);

        // Creating a TrustManager that trusts the CAs in our KeyStore.
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);

        // Creating an SSLSocketFactory that uses our TrustManager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager)tmf.getTrustManagers()[0]);
        builder.hostnameVerifier((hostname, session) -> true);
        builder.followSslRedirects(true);

        ConnectionSpec spec = new
                ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_2)
                .cipherSuites(
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
                .build();

        builder.connectionSpecs(Collections.singletonList(spec));

        return builder.build();
    }
}
