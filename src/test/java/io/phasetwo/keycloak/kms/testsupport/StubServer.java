package io.phasetwo.keycloak.kms.testsupport;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;

/**
 * A throwaway in-process HTTP server.
 *
 * <p>An in-process server rather than a mocking framework, because what these tests need to check
 * is what actually goes over the wire — that IMDSv2's token header is present, that Pod Identity's
 * Authorization header is sent — and a mock of our own client would assert only that we call our
 * own code the way we wrote it.
 */
public class StubServer implements AutoCloseable {

  public record Request(String method, String path, Map<String, String> headers, String body) {}

  private final HttpServer server;
  private final List<Request> requests = new ArrayList<>();
  private final Map<String, BiFunction<Request, HttpExchange, String>> routes =
      new ConcurrentHashMap<>();
  private final Map<String, Integer> statuses = new ConcurrentHashMap<>();

  public StubServer() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          String body =
              new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
          Map<String, String> headers = new ConcurrentHashMap<>();
          exchange
              .getRequestHeaders()
              .forEach((k, v) -> headers.put(k.toLowerCase(java.util.Locale.ROOT), v.get(0)));
          Request r =
              new Request(
                  exchange.getRequestMethod(), exchange.getRequestURI().getPath(), headers, body);
          synchronized (requests) {
            requests.add(r);
          }

          BiFunction<Request, HttpExchange, String> route = routes.get(r.path());
          if (route == null) {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
          }
          String response = route.apply(r, exchange);
          int status = statuses.getOrDefault(r.path(), 200);
          byte[] out = response.getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(status, out.length);
          exchange.getResponseBody().write(out);
          exchange.close();
        });
    server.start();
  }

  public StubServer route(String path, String response) {
    routes.put(path, (r, e) -> response);
    return this;
  }

  public StubServer route(String path, int status, String response) {
    statuses.put(path, status);
    return route(path, response);
  }

  public StubServer route(String path, BiFunction<Request, HttpExchange, String> handler) {
    routes.put(path, handler);
    return this;
  }

  public String baseUrl() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  public List<Request> requests() {
    synchronized (requests) {
      return List.copyOf(requests);
    }
  }

  public Request lastRequestTo(String path) {
    synchronized (requests) {
      return requests.stream().filter(r -> r.path().equals(path)).reduce((a, b) -> b).orElse(null);
    }
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
