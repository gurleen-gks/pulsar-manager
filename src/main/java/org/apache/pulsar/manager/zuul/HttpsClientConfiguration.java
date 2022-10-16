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

import com.oath.auth.KeyRefresher;
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

    @Value("${tls.certpath}")
    private String tlsCertpath;

    @Value("${tls.keypath}")
    private String tlsKeypath;

    @Value("${tls.truststore}")
    private String tlsTruststore;

    @Value("${tls.truststore.password}")
    private String tlsTruststorePassword;

    @Value("${tls.hostname.verifier}")
    private boolean tlsHostnameVerifier;

    @Bean
    public CloseableHttpClient httpClient() throws Exception {
        log.info("tls enabled {}, keystore {}, keystore password: {}, tlsHostnameVerifier: {}, cert: {}, key: {}", tlsEnabled, tlsTruststore, tlsTruststorePassword, tlsHostnameVerifier, tlsCertpath, tlsKeypath);
        if (tlsEnabled) {
            SSLContext sslcontext = createAthenzSSLContext(tlsCertpath, tlsKeypath, tlsTruststore, tlsTruststorePassword);
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

    public static SSLContext createAthenzSSLContext(String certPath, String certKeyPath, String trustStorePath, String trustStorePassword) throws Exception {
        log.info("Create SSLContext from Athenz 509x certs...");
        KeyRefresher keyRefresher = com.oath.auth.Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                certPath, certKeyPath);
        keyRefresher.startup();
        return com.oath.auth.Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());
    }}
