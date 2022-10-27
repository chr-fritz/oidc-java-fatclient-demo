package de.chrfritz.oidc.auth;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import de.chrfritz.oidc.auth.oauth.pkce_flow.AuthorizationCodeWithPkceClient;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.*;

/**
 * A small example how to use the client.
 */
@Slf4j
public class CliTestClient {

    public static void main(String[] args) {
        ExecutorService executorService = Executors.newCachedThreadPool();
        AuthorizationCodeWithPkceClient client = new AuthorizationCodeWithPkceClient(
            URI.create("http://localhost:8080/realms/master/"),
            new ClientID("java-demo"),
            executorService,
            Duration.ofSeconds(90),
            51200,
            51299
        );
        try {
            client.initialize();
            AccessToken token = client.authenticateAsync(Arrays.asList("openid", "profile")).get(90, TimeUnit.SECONDS);
            LOGGER.info("Got valid access token: {}", token);

            getUserInfo(token);
        } catch (InterruptedException | TimeoutException | IOException | URISyntaxException | ExecutionException e) {
            LOGGER.warn("can not get token: ", e);
        } finally {
            executorService.shutdown();
        }
    }

    private static void getUserInfo(AccessToken token) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL("http://localhost:8080/realms/master/protocol/openid-connect/userinfo")
            .openConnection();
        connection.addRequestProperty("Authorization", token.getType().getValue() + " " + token.getValue());
        connection.connect();
        String body = new String(connection.getInputStream().readAllBytes());
        LOGGER.info("Got {} from UserInfo Endpoint. Body:\n\n{}", connection.getResponseCode(), body);
    }
}
