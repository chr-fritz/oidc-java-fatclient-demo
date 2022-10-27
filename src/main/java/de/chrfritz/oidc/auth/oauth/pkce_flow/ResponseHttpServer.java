package de.chrfritz.oidc.auth.oauth.pkce_flow;

import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.State;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.*;

/**
 * The response http server is a small http server that will handle the request to the callback uri.
 * <p>
 * It will shut down itself either after the first handled request or after the configured timeout.
 * <p>
 * It provides through {@link #getAuthCodeFuture()} a completable future that will contain the authorization code which
 * is required to request the access token.
 */
@Slf4j
class ResponseHttpServer {
    private static final ScheduledExecutorService shutdownExecutor = Executors.newSingleThreadScheduledExecutor();
    @Getter
    private final CompletableFuture<AuthorizationSuccessResponse> authCodeFuture = new CompletableFuture<>();
    private final ExecutorService executor;
    private final int portRangeStart;
    private final int portRangeStop;
    private final Duration timeout;
    private final State expectedState;
    private HttpServer server;
    @Getter
    private int localPort;
    private ScheduledFuture<?> shutdownFuture;

    /**
     * Initializes the response http server.
     */
    /*package-protected*/ ResponseHttpServer(ExecutorService executor, int portRangeStart, int portRangeStop, Duration timeout, State expectedState) {
        this.executor = executor;
        this.portRangeStart = portRangeStart;
        this.portRangeStop = portRangeStop;
        this.timeout = timeout;
        this.expectedState = expectedState;
    }

    /*package-protected*/ void start() throws IOException {
        localPort = findFirstFreePort(portRangeStart, portRangeStop);

        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), localPort), 1);
        server.setExecutor(executor);
        server.createContext("/callback", this::handleRequest);
        server.start();

        // shutdown the server after the timeout was run out.
        shutdownFuture = shutdownExecutor.schedule(this::stop, timeout.plusSeconds(10).getSeconds(), TimeUnit.SECONDS);
    }

    private void handleRequest(HttpExchange request) throws IOException {
        URI uri = request.getRequestURI();
        try {
            AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(uri);
            if (authorizationResponse instanceof AuthorizationSuccessResponse) {
                State state = authorizationResponse.toSuccessResponse().getState();
                if (Objects.equals(state, expectedState)) {
                    sendResponse(request, "<script>window.open('', '_self', ''); window.close();</script>", 200);
                    authCodeFuture.complete(authorizationResponse.toSuccessResponse());
                }
                else {
                    sendResponse(request, "Received state is not equal to expected state.", 400);
                    authCodeFuture.completeExceptionally(new IllegalStateException(
                        "Received state \"" + state + "\" is not equal to the expected state \"" + expectedState +
                            "\"."));
                }
            }
            else {
                sendResponse(request, "Invalid response", 400);
                authCodeFuture.completeExceptionally(new IllegalStateException(
                    "Invalid response: " + authorizationResponse));
            }
        } catch (ParseException e) {
            sendResponse(request, e.getMessage(), 400);
            authCodeFuture.completeExceptionally(e);
        } finally {
            request.close();
            executor.submit(this::stop);
        }
    }

    private static void sendResponse(HttpExchange request, String responseBody, int statusCode) throws IOException {
        byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
        request.sendResponseHeaders(statusCode, bytes.length);
        request.getResponseBody().write(bytes);
    }

    /*package-protected*/ void stop() {
        server.stop(1);
        shutdownFuture.cancel(false);
    }

    /**
     * Find the first free port in the given range.
     *
     * @param start The first port to check if it is free.
     * @param stop  The last port to check if it is free.
     * @return The first port within the rage which is free. otherwise -1.
     */
    private static int findFirstFreePort(int start, int stop) {
        for (int port = start; port <= stop; port++) {
            if (isPortFree(port)) {
                return port;
            }
        }
        return -1;
    }

    /**
     * Checks if the given port is not in use.
     *
     * @param port The port to check.
     * @return true if the port can be used for the http server.
     */
    @SuppressWarnings(
        "squid:S4818" // Just open the socket to check if it is free.
    )
    private static boolean isPortFree(int port) {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            return serverSocket.getLocalPort() == port;
        } catch (IOException e) {
            LOGGER.trace("Check if port {} is free failed: ", port, e);
            return false;
        }
    }
}
