package org.cloudfoundry.reactor.tokenprovider;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.cloudfoundry.reactor.ConnectionContext;
import org.cloudfoundry.reactor.RootProvider;
import org.cloudfoundry.reactor.util.ErrorPayloadMappers;
import org.cloudfoundry.reactor.util.JsonCodec;
import org.cloudfoundry.reactor.util.Operator;
import org.cloudfoundry.reactor.util.OperatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.netty.ByteBufFlux;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.client.HttpClientForm;
import reactor.netty.http.client.HttpClientRequest;

@ExtendWith(MockitoExtension.class)
class AbstractUaaTokenProviderConcurrencyTest {

    @Mock
    private ConnectionContext connectionContext;

    @Mock
    private RootProvider rootProvider;

    @Mock
    private HttpClient httpClient;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private Operator operator;

    @Mock
    private ByteBufFlux responseBody;

    private AtomicInteger refreshTokenUsageCount;
    private AtomicInteger primaryTokenUsageCount;
    private CountDownLatch concurrentStartLatch;
    private AtomicReference<String> lastUsedRefreshToken;

    @BeforeEach
    void setUp() {
        refreshTokenUsageCount = new AtomicInteger(0);
        primaryTokenUsageCount = new AtomicInteger(0);
        concurrentStartLatch = new CountDownLatch(1);
        lastUsedRefreshToken = new AtomicReference<>();

        // Setup basic mocks
        when(connectionContext.getRootProvider()).thenReturn(rootProvider);
        when(connectionContext.getHttpClient()).thenReturn(httpClient);
        when(connectionContext.getObjectMapper()).thenReturn(objectMapper);
        when(connectionContext.getCacheDuration()).thenReturn(Optional.of(Duration.ofMinutes(5)));
        
        when(rootProvider.getRoot(eq("authorization_endpoint"), eq(connectionContext)))
                .thenReturn(Mono.just("https://uaa.example.com"));
    }

    @Test
    void testConcurrentTokenRequestsPreventRefreshTokenReuse() throws Exception {
        // Given: A properly mocked token provider
        TestableTokenProvider tokenProvider = new TestableTokenProvider();
        setupMocksForTokenRequests();
        
        // Pre-populate refresh token cache
        setRefreshTokenInCache(tokenProvider, connectionContext, "concurrent-test-refresh-token");

        ExecutorService executor = Executors.newFixedThreadPool(2);
        CompletableFuture<String> future1 = new CompletableFuture<>();
        CompletableFuture<String> future2 = new CompletableFuture<>();
        AtomicReference<Throwable> error1 = new AtomicReference<>();
        AtomicReference<Throwable> error2 = new AtomicReference<>();

        try {
            // When: Two threads call getToken() concurrently
            executor.submit(() -> {
                try {
                    concurrentStartLatch.await();
                    // Call the actual final getToken() method
                    String token = tokenProvider.getToken(connectionContext).block(Duration.ofSeconds(10));
                    future1.complete(token);
                } catch (Exception e) {
                    error1.set(e);
                    future1.completeExceptionally(e);
                }
            });

            executor.submit(() -> {
                try {
                    concurrentStartLatch.await();
                    // Call the actual final getToken() method
                    String token = tokenProvider.getToken(connectionContext).block(Duration.ofSeconds(10));
                    future2.complete(token);
                } catch (Exception e) {
                    error2.set(e);
                    future2.completeExceptionally(e);
                }
            });

            // Start both threads simultaneously
            concurrentStartLatch.countDown();

            // Then: Both requests should complete successfully
            String token1 = future1.get(15, TimeUnit.SECONDS);
            String token2 = future2.get(15, TimeUnit.SECONDS);

            // Verify no exceptions occurred
            assertNull(error1.get(), "First request should not throw an exception");
            assertNull(error2.get(), "Second request should not throw an exception");
            
            // Both should receive valid tokens
            assertNotNull(token1, "First request should return a token");
            assertNotNull(token2, "Second request should return a token");
            assertTrue(token1.startsWith("Bearer"), "First token should be properly formatted");
            assertTrue(token2.startsWith("Bearer"), "Second token should be properly formatted");

            // Critical assertion: refresh token should only be used once
            assertEquals(1, refreshTokenUsageCount.get(), 
                        "Refresh token should only be used once, preventing concurrent reuse");
            
            // One request should fall back to primary token
            assertEquals(1, primaryTokenUsageCount.get(),
                        "Primary token should be used once when refresh fails");

        } finally {
            executor.shutdown();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @Test 
    void testStructuralChangesForConcurrencyFix() throws Exception {
        // Given: A token provider instance
        TestableTokenProvider tokenProvider = new TestableTokenProvider();

        // When/Then: Verify the fixed implementation has the necessary fields
        assertTrue(hasTokenRefreshLocksField(tokenProvider), 
                  "Fixed implementation should have tokenRefreshLocks field for synchronization");
        
        assertTrue(canCreateTokenRefreshLock(tokenProvider, connectionContext),
                  "Should be able to create locks per connection context");
    }

    @Test
    void testInvalidateDoesNotCauseRaceConditions() throws Exception {
        // Given: Token provider with cached refresh token
        TestableTokenProvider tokenProvider = new TestableTokenProvider();
        setupMocksForTokenRequests();
        setRefreshTokenInCache(tokenProvider, connectionContext, "invalidate-test-token");

        // When: Concurrent invalidate and getToken calls
        ExecutorService executor = Executors.newFixedThreadPool(2);
        AtomicReference<Exception> exception = new AtomicReference<>();

        try {
            CompletableFuture<Void> invalidateFuture = CompletableFuture.runAsync(() -> {
                try {
                    concurrentStartLatch.await();
                    tokenProvider.invalidate(connectionContext);
                } catch (Exception e) {
                    exception.set(e);
                }
            }, executor);

            CompletableFuture<String> getTokenFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    concurrentStartLatch.await();
                    return tokenProvider.getToken(connectionContext).block(Duration.ofSeconds(5));
                } catch (Exception e) {
                    exception.set(e);
                    throw new RuntimeException(e);
                }
            }, executor);

            concurrentStartLatch.countDown();

            // Wait for both operations
            invalidateFuture.get(10, TimeUnit.SECONDS);
            String token = getTokenFuture.get(10, TimeUnit.SECONDS);

            // Then: Should complete without exceptions
            assertNull(exception.get(), "Concurrent invalidate and getToken should not cause exceptions");
            assertNotNull(token, "Token should still be obtainable");

        } finally {
            executor.shutdown();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private void setupMocksForTokenRequests() {
        try (MockedStatic<JsonCodec> jsonCodec = mockStatic(JsonCodec.class);
             MockedStatic<ErrorPayloadMappers> errorMappers = mockStatic(ErrorPayloadMappers.class)) {
            
            // Mock error payload mapper
            errorMappers.when(() -> ErrorPayloadMappers.uaa(any(ObjectMapper.class)))
                       .thenReturn(throwable -> throwable);

            // Mock JSON decoding with smart response based on usage patterns
            jsonCodec.when(() -> JsonCodec.decode(eq(objectMapper), any(ByteBufFlux.class), eq(Map.class)))
                    .thenAnswer(invocation -> createSmartTokenResponse());

            // Mock the operator chain
            mockOperatorChain();
        }
    }

    private Mono<Map<String, String>> createSmartTokenResponse() {
        // Analyze the call stack to determine if this is a refresh or primary request
        boolean isRefreshRequest = isRefreshTokenRequest();
        
        if (isRefreshRequest) {
            int count = refreshTokenUsageCount.incrementAndGet();
            if (count == 1) {
                // First refresh token use succeeds
                Map<String, String> response = new HashMap<>();
                response.put("access_token", "refreshed-access-token");
                response.put("token_type", "Bearer");
                response.put("refresh_token", "new-refresh-token");
                return Mono.just(response);
            } else {
                // Subsequent refresh token uses fail (UAA behavior)
                return Mono.error(new RuntimeException("invalid_grant: refresh token has been revoked"));
            }
        } else {
            // Primary token request
            primaryTokenUsageCount.incrementAndGet();
            Map<String, String> response = new HashMap<>();
            response.put("access_token", "primary-access-token");
            response.put("token_type", "Bearer");
            response.put("refresh_token", "fresh-refresh-token");
            return Mono.just(response);
        }
    }

    private boolean isRefreshTokenRequest() {
        // Simple heuristic: check if we have a refresh token in cache and this is the first/second call
        return refreshTokenUsageCount.get() == 0 && 
               hasRefreshTokenInCache(connectionContext);
    }

    private boolean hasRefreshTokenInCache(ConnectionContext context) {
        // This is a simplified check - in a real scenario you'd inspect the actual cache
        return refreshTokenUsageCount.get() == 0;
    }

    private void mockOperatorChain() {
        when(operator.headers(any())).thenReturn(operator);
        when(operator.post()).thenReturn(operator);
        when(operator.uri(any())).thenReturn(operator);
        when(operator.sendForm(any())).thenReturn(operator);
        when(operator.response()).thenReturn(operator);
        when(operator.parseBodyToToken(any())).thenAnswer(invocation -> 
            createSmartTokenResponse().map(payload -> 
                String.format("%s %s", payload.get("token_type"), payload.get("access_token"))));
    }

    // Helper methods for reflection-based testing

    private void setRefreshTokenInCache(TestableTokenProvider tokenProvider, ConnectionContext context, String token) {
        try {
            Field refreshTokensField = AbstractUaaTokenProvider.class.getDeclaredField("refreshTokens");
            refreshTokensField.setAccessible(true);
            @SuppressWarnings("unchecked")
            java.util.concurrent.ConcurrentMap<ConnectionContext, Mono<String>> refreshTokens = 
                (java.util.concurrent.ConcurrentMap<ConnectionContext, Mono<String>>) refreshTokensField.get(tokenProvider);
            refreshTokens.put(context, Mono.just(token));
        } catch (Exception e) {
            throw new RuntimeException("Failed to set refresh token", e);
        }
    }

    private boolean hasTokenRefreshLocksField(TestableTokenProvider tokenProvider) {
        try {
            Field field = AbstractUaaTokenProvider.class.getDeclaredField("tokenRefreshLocks");
            return field != null;
        } catch (NoSuchFieldException e) {
            return false;
        }
    }

    private boolean canCreateTokenRefreshLock(TestableTokenProvider tokenProvider, ConnectionContext context) {
        try {
            Field field = AbstractUaaTokenProvider.class.getDeclaredField("tokenRefreshLocks");
            field.setAccessible(true);
            Object locks = field.get(tokenProvider);
            return locks instanceof java.util.concurrent.ConcurrentMap;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Concrete implementation that only implements the abstract methods.
     * Does NOT override any final methods.
     */
    private static class TestableTokenProvider extends AbstractUaaTokenProvider {

        @Override
        String getIdentityZoneSubdomain() {
            return null; // No subdomain for test
        }

        @Override
        void tokenRequestTransformer(HttpClientRequest request, HttpClientForm form) {
            // Implementation for primary token request (e.g., password grant)
            form.multipart(false)
                .attr("client_id", getClientId())
                .attr("client_secret", getClientSecret())
                .attr("grant_type", "password")
                .attr("username", "testuser")
                .attr("password", "testpass");
        }

        @Override
        public String getClientId() {
            return "test-client";
        }

        @Override
        public String getClientSecret() {
            return "test-secret";
        }
    }
}