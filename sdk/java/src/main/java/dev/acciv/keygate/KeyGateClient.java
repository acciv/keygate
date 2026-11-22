package dev.acciv.keygate;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/** Клиент keygate без внешних зависимостей. */
public final class KeyGateClient {
    private final String baseUrl;
    private final String masterKey;
    private final String clientId;

    public KeyGateClient(String baseUrl, String masterKey, String clientId) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.masterKey = masterKey;
        this.clientId = clientId;
    }

    public String request(String method, String path, String jsonBody) throws IOException {
        URL url = new URL(baseUrl + path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method);
        connection.setRequestProperty("X-KeyGate-Key", masterKey);
        connection.setRequestProperty("X-Client-ID", clientId);
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);

        if (jsonBody != null) {
            connection.setDoOutput(true);
            try (OutputStream out = connection.getOutputStream()) {
                out.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }
        }

        int status = connection.getResponseCode();
        String body = new String(
                status >= 400 ? connection.getErrorStream().readAllBytes() : connection.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        connection.disconnect();
        if (status >= 400) {
            throw new IOException("keygate HTTP " + status + ": " + body);
        }
        return body.trim();
    }

    public String health() throws IOException { return request("GET", "/healthz", null); }
    public String resolve(String provider, String scope, int ttl) throws IOException {
        String body = String.format("{\"provider\":\"%s\",\"scope\":\"%s\",\"ttl\":%d}", provider, scope, ttl);
        return request("POST", "/v1/keys/resolve", body);
    }
    public String rotate(String provider) throws IOException {
        return request("POST", "/v1/keys/rotate", "{\"provider\":\"" + provider + "\"}");
    }
    public String audit() throws IOException { return request("GET", "/v1/audit", null); }
    public String providers() throws IOException { return request("GET", "/v1/providers", null); }
}
