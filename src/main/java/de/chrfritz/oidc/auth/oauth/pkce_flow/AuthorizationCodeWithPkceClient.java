package de.chrfritz.oidc.auth.oauth.pkce_flow;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Collection;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

/**
 * Implements the OAuth Authentication Client for the Authorization Code Flow with Proof Key for Code Exchange (PKCE).
 */
@Slf4j
@RequiredArgsConstructor
public class AuthorizationCodeWithPkceClient {

    @NonNull
    private final URI issuer;
    @NonNull
    private final ClientID clientId;
    @NonNull
    private final ExecutorService executorService;
    @NonNull
    private final Duration timeout;
    private final int portRangeStart;
    private final int portRangeStop;
    private OIDCProviderMetadata oidcProviderMetadata;

    /**
     * Initializes the Authentication client by reading the issuers metadata and some flow specifics.
     */
    public final void initialize() {
        try {
            Issuer issuerConfig = new Issuer(issuer);
            OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(issuerConfig);
            HTTPResponse response = request.toHTTPRequest().send();
            String body = response.getContent();
            oidcProviderMetadata = OIDCProviderMetadata.parse(body);
        } catch (IOException | ParseException e) {
            throw new IllegalStateException("Can not read issuer metadata: ", e);
        }
    }

    @NotNull
    @SuppressWarnings(
        "squid:S1130" // keep AuthenticationException as RuntimeException in throws list
    )
    public Future<AccessToken> authenticateAsync(Collection<String> scopes) throws IOException, URISyntaxException {
        Scope scope = new Scope(scopes.toArray(String[]::new));
        LOGGER.debug("Perform authentication using {} for scopes {}", getClass().getSimpleName(), String.join(", ", scopes));
        return performAuthentication(scope)
            .thenApply(AuthorizationCodeWithPkceClient::mapTokenResponse);
    }

    protected CompletableFuture<TokenResponse> performAuthentication(Scope scope) throws IOException, URISyntaxException {
        State state = new State();
        ResponseHttpServer httpServer = new ResponseHttpServer(executorService, portRangeStart, portRangeStop, timeout, state);
        httpServer.start();

        URI callbackUri = new URI("http", null, "localhost", httpServer.getLocalPort(), "/callback", null, null);
        CodeVerifier codeVerifier = new CodeVerifier();
        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(new ResponseType("code"), scope, clientId, callbackUri)
            .endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI())
            .state(state)
            .codeChallenge(codeVerifier, CodeChallengeMethod.S256)
            .nonce(new Nonce())
            .build();
        LOGGER.info("Auth: {}", authenticationRequest.toURI());
        Process process = Browser.openAsApp(authenticationRequest.toURI());

        return httpServer.getAuthCodeFuture()
            .thenApply(r -> {
                try {
                    return retrieveAccessToken(r, authenticationRequest, codeVerifier);
                } finally {
                    process.destroy();
                }
            });
    }

    private static AccessToken mapTokenResponse(TokenResponse response) {
        if (!(response instanceof AccessTokenResponse)) {
            throw new IllegalArgumentException(
                "Received an invalid token response: " + response.toErrorResponse().getErrorObject().getDescription());
        }
        return ((AccessTokenResponse) response).getTokens().getAccessToken();
    }

    private TokenResponse retrieveAccessToken(AuthorizationSuccessResponse response, AuthenticationRequest authenticationRequest, CodeVerifier codeVerifier) {
        try {
            AuthorizationCodeGrant grant = new AuthorizationCodeGrant(
                response.getAuthorizationCode(),
                authenticationRequest.getRedirectionURI(),
                codeVerifier);
            TokenRequest tokenRequest = new TokenRequest(
                oidcProviderMetadata.getTokenEndpointURI(),
                clientId,
                grant);
            HTTPResponse tokenResponse = tokenRequest.toHTTPRequest().send();

            return TokenResponse.parse(tokenResponse.getContentAsJSONObject());
        } catch (IOException | ParseException e) {
            throw new IllegalStateException("Can not get token: ", e);
        }
    }
}
