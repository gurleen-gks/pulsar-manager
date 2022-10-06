/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.pulsar.manager.zuul;

import lombok.extern.slf4j.Slf4j;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

@Configuration
@Slf4j
public class HttpsClientConfiguration {

    @Value("${tls.enabled}")
    private boolean tlsEnabled;

    @Value("${tls.keystore}")
    private String tlsKeystore;

    @Value("${tls.truststore:/pulsar-manager/yahoo_certificate_bundle.jks}")
    private String tlsTruststore;

    @Value("${tls.keystore.password}")
    private String tlsKeystorePassword;

    @Value("${tls.hostname.verifier}")
    private boolean tlsHostnameVerifier;

    @Bean
    public CloseableHttpClient httpClient() throws Exception {
        log.info("tls enabled {}, keystore {}, keystore password: {}, tlsHostnameVerifier: {}", tlsEnabled, tlsKeystore, tlsKeystorePassword, tlsHostnameVerifier);
        if (tlsEnabled) {
//            Resource resource = new FileSystemResource(tlsKeystore);
//            File keyStoreFile = resource.getFile();
//            Resource resourceT = new FileSystemResource(tlsTruststore);
//            File trustStoreFile = resourceT.getFile();
            KeyManagerFactory keyManagerFactory = buildKeyManagerFactory();

            TrustManagerFactory trustManagerFactory = buildTrustManagerFactory();

            SSLContext sslcontext = buildSslContext(keyManagerFactory, trustManagerFactory);
//            SSLContext sslcontext = SSLContexts.custom()
//                    .loadTrustMaterial(trustStoreFile, null,
//                            new TrustSelfSignedStrategy())
//                    .loadKeyMaterial(keyStoreFile, tlsKeystorePassword.toCharArray(), tlsKeystorePassword.toCharArray())
//                    .build();

            HostnameVerifier hostnameVerifier = (s, sslSession) -> {
                // Custom logic to verify host name, tlsHostnameVerifier is false for test
                if (!tlsHostnameVerifier) {
                    return true;
                } else {
                    HostnameVerifier hv= HttpsURLConnection.getDefaultHostnameVerifier();
                    return hv.verify(s, sslSession);
                }
            };

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                    sslcontext,
                    hostnameVerifier);

            return HttpClients.custom()
                    .setSSLSocketFactory(sslsf)
                    .build();
        }
        return HttpClients.custom().build();
    }

    private KeyManagerFactory buildKeyManagerFactory() throws UnrecoverableKeyException,
            NoSuchAlgorithmException,
            KeyStoreException,
            IOException,
            CertificateException {
        String storeType = "pkcs12";
        KeyStore keyStore = KeyStore.getInstance(storeType);

        char[] storePass = tlsKeystorePassword.toCharArray();
        try (InputStream fis = new FileInputStream(tlsKeystore)) {
            keyStore.load(fis, storePass);
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm()
        );

        char[] keyPass = tlsKeystorePassword.toCharArray();
        keyManagerFactory.init(keyStore, keyPass);

        return keyManagerFactory;
    }

    private TrustManagerFactory buildTrustManagerFactory() throws KeyStoreException,
            IOException,
            NoSuchAlgorithmException,
            CertificateException {
        String storeType = "jks";
        KeyStore trustStore = KeyStore.getInstance(storeType);

        try (InputStream fis = new FileInputStream(tlsTruststore)) {
            trustStore.load(fis, null);
        }

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
        );

        trustManagerFactory.init(trustStore);

        return trustManagerFactory;
    }

    static SSLContext buildSslContext(
            KeyManagerFactory keyManagerFactory,
            TrustManagerFactory trustManagerFactory) throws KeyManagementException,
            NoSuchAlgorithmException {
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");

        sslContext.init(
                keyManagerFactory.getKeyManagers(),
                trustManagerFactory.getTrustManagers(),
                null
        );

        return sslContext;
    }
}
