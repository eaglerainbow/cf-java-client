/*
 * Copyright 2013-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.reactor.tokenprovider;

import static io.netty.handler.codec.http.HttpHeaderNames.AUTHORIZATION;
import static io.netty.handler.codec.http.HttpHeaderNames.CONTENT_TYPE;
import static io.netty.handler.codec.http.HttpHeaderValues.APPLICATION_X_WWW_FORM_URLENCODED;
import static reactor.core.publisher.Sinks.EmitFailureHandler.FAIL_FAST;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.util.AsciiString;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import org.cloudfoundry.Nullable;
import org.cloudfoundry.reactor.ConnectionContext;
import org.cloudfoundry.reactor.TokenProvider;
import org.cloudfoundry.reactor.util.ErrorPayloadMappers;
import org.cloudfoundry.reactor.util.JsonCodec;
import org.cloudfoundry.reactor.util.Operator;
import org.cloudfoundry.reactor.util.OperatorContext;
import org.cloudfoundry.reactor.util.UserAgent;
import org.immutables.value.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.netty.ByteBufFlux;
import reactor.netty.http.client.HttpClientForm;
import reactor.netty.http.client.HttpClientRequest;

/**
 * An abstract base class for all token providers that interact with the UAA. It encapsulates the logic to refresh the token before
 * expiration.
 */
public abstract class AbstractUaaTokenProvider implements TokenProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger("cloudfoundry-client.token");

    private static final String ACCESS_TOKEN = "access_token";

    private static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";

    private static final String REFRESH_TOKEN = "refresh_token";

    private static final String TOKEN_TYPE = "token_type";

    private static final ZoneId UTC = ZoneId.of("UTC");

    private final ConcurrentMap<ConnectionContext, Mono<String>> accessTokens =
            new ConcurrentHashMap<>(1);

    private final ConcurrentMap<ConnectionContext, RefreshToken> refreshTokenStreams =
            new ConcurrentHashMap<>(1);

    private final ConcurrentMap<ConnectionContext, Mono<String>> refreshTokens =
            new ConcurrentHashMap<>(1);

    // Add locks per connection context to synchronize token refresh operations
    private final ConcurrentMap<ConnectionContext, ReentrantLock> tokenRefreshLocks =
            new ConcurrentHashMap<>(1);

    /**
     * The client id. Defaults to {@code cf}.
     */
    @Value.Default
    public String getClientId() {
        return "cf";
    }

    /**
     * The client secret. Defaults to {@code ""}.
     */
    @Value.Default
    public String getClientSecret() {
        return "";
    }

    /**
     * Returns a {@link Flux} of refresh tokens for a connection
     *
     * @param connectionContext A {@link ConnectionContext} to be used to identity which connection the refresh tokens be retrieved for
     * @return a {@link Flux} that emits the last token on subscribe and new refresh tokens as they are negotiated
     */
    public Flux<String> getRefreshTokens(ConnectionContext connectionContext) {
        return getRefreshTokenStream(connectionContext).sink.asFlux();
    }

    @Override
    public final Mono<String> getToken(ConnectionContext connectionContext) {
        return this.accessTokens.computeIfAbsent(connectionContext, this::token);
    }

    @Override
    public void invalidate(ConnectionContext connectionContext) {
        this.accessTokens.put(connectionContext, token(connectionContext));
    }

    /**
     * The identity zone subdomain
     */
    @Nullable
    abstract String getIdentityZoneSubdomain();

    /**
     * Transforms an {@code HttpClientRequest} and an {@code HttpClientForm} in order to make a request that negotiates an access token.
     *
     * @param request the {@link HttpClientRequest} to transform to perform the token request
     * @param form    the {@link HttpClientForm} to transform to perform the token request
     */
    abstract void tokenRequestTransformer(HttpClientRequest request, HttpClientForm form);

    private static String extractAccessToken(Map<String, String> payload) {
        String accessToken = payload.get(ACCESS_TOKEN);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Access Token: {}", accessToken);

            parseToken(accessToken)
                    .ifPresent(
                            claims -> {
                                LOGGER.debug(
                                        "Access Token Issued At:  {} UTC",
                                        toLocalDateTime(claims.getIssuedAt()));
                                LOGGER.debug(
                                        "Access Token Expires At: {} UTC",
                                        toLocalDateTime(claims.getExpiration()));
                            });
        }

        return String.format("%s %s", payload.get(TOKEN_TYPE), accessToken);
    }

    private static Optional<Claims> parseToken(String token) {
        if (!token.contains(".")) {
            return Optional.empty();
        }

        try {
            String jws = token.substring(0, token.lastIndexOf('.') + 1);
            JwtParser parser = Jwts.parser().build();

            return Optional.of(parser.parseClaimsJwt(jws).getBody());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static void setContentType(HttpHeaders httpHeaders) {
        httpHeaders.set(CONTENT_TYPE, APPLICATION_X_WWW_FORM_URLENCODED);
    }

    private static LocalDateTime toLocalDateTime(Date date) {
        return LocalDateTime.from(date.toInstant().atZone(UTC));
    }

    private static Function<UriComponentsBuilder, UriComponentsBuilder> tokenUriTransformer(
            String identityZoneId) {
        return root -> {
            if (identityZoneId != null) {
                root.host(String.format("%s.%s", identityZoneId, root.build().getHost()));
            }

            return root.pathSegment("oauth", "token");
        };
    }

    private void addHeaders(HttpHeaders httpHeaders) {
        setContentType(httpHeaders);
        setAuthorization(httpHeaders);
        UserAgent.setUserAgent(httpHeaders);
        JsonCodec.setDecodeHeaders(httpHeaders);
    }

    private Operator createOperator(ConnectionContext connectionContext, String root) {
        OperatorContext context = OperatorContext.of(connectionContext, root);
        return new Operator(context, connectionContext.getHttpClient())
                .withErrorPayloadMapper(
                        ErrorPayloadMappers.uaa(connectionContext.getObjectMapper()));
    }

    private Consumer<Map<String, String>> extractRefreshToken(ConnectionContext connectionContext) {
        return payload ->
                Optional.ofNullable(payload.get(REFRESH_TOKEN))
                        .ifPresent(
                                refreshToken -> {
                                    if (LOGGER.isDebugEnabled()) {
                                        LOGGER.debug("Refresh Token: {}", refreshToken);

                                        parseToken(refreshToken)
                                                .ifPresent(
                                                        claims -> {
                                                            LOGGER.debug(
                                                                    "Refresh Token Issued At:  {}"
                                                                            + " UTC",
                                                                    toLocalDateTime(
                                                                            claims.getIssuedAt()));
                                                            LOGGER.debug(
                                                                    "Refresh Token Expires At: {}"
                                                                            + " UTC",
                                                                    toLocalDateTime(
                                                                            claims
                                                                                    .getExpiration()));
                                                        });
                                    }

                                    this.refreshTokens.put(
                                            connectionContext, Mono.just(refreshToken));
                                    getRefreshTokenStream(connectionContext)
                                            .sink
                                            .emitNext(refreshToken, FAIL_FAST);
                                });
    }

    private RefreshToken getRefreshTokenStream(ConnectionContext connectionContext) {
        return this.refreshTokenStreams.computeIfAbsent(connectionContext, c -> new RefreshToken());
    }

    private ReentrantLock getTokenRefreshLock(ConnectionContext connectionContext) {
        return this.tokenRefreshLocks.computeIfAbsent(connectionContext, c -> new ReentrantLock());
    }

    private Mono<String> primaryToken(ConnectionContext connectionContext) {
        return requestToken(
                connectionContext,
                this::tokenRequestTransformer,
                tokensExtractor(connectionContext));
    }

    private Mono<String> refreshToken(ConnectionContext connectionContext, String refreshToken) {
        return requestToken(
                        connectionContext,
                        refreshTokenGrantTokenRequestTransformer(refreshToken),
                        tokensExtractor(connectionContext))
                .doOnError(t -> LOGGER.error("Refresh token grant error.", t))
                .doOnError(t -> {
                    // Clear the refresh token on error to prevent reuse
                    this.refreshTokens.remove(connectionContext);
                })
                .onErrorResume(t -> Mono.empty());
    }

    private BiConsumer<HttpClientRequest, HttpClientForm> refreshTokenGrantTokenRequestTransformer(
            String refreshToken) {
        return (request, form) ->
                form.multipart(false)
                        .attr("client_id", getClientId())
                        .attr("client_secret", getClientSecret())
                        .attr("grant_type", "refresh_token")
                        .attr("refresh_token", refreshToken);
    }

    private Mono<String> requestToken(
            ConnectionContext connectionContext,
            BiConsumer<HttpClientRequest, HttpClientForm> tokenRequestTransformer,
            Function<ByteBufFlux, Mono<String>> tokenExtractor) {
        return connectionContext
                .getRootProvider()
                .getRoot(AUTHORIZATION_ENDPOINT, connectionContext)
                .map(root -> createOperator(connectionContext, root))
                .flatMap(
                        operator ->
                                operator.headers(this::addHeaders)
                                        .post()
                                        .uri(tokenUriTransformer(getIdentityZoneSubdomain()))
                                        .sendForm(tokenRequestTransformer)
                                        .response()
                                        .parseBodyToToken(
                                                responseWithBody ->
                                                        tokenExtractor.apply(
                                                                responseWithBody.getBody())));
    }

    private void setAuthorization(HttpHeaders headers) {
        String encoded =
                Base64.getEncoder()
                        .encodeToString(
                                new AsciiString(getClientId())
                                        .concat(":")
                                        .concat(getClientSecret())
                                        .toByteArray());
        headers.set(AUTHORIZATION, String.format("Basic %s", encoded));
    }

    private Mono<String> tokenProtectedFromConcurrency(ConnectionContext connectionContext) {
        // Check if another thread already refreshed the token while we waited
        final Mono<String> currentToken = this.accessTokens.get(connectionContext);
        if (currentToken != null && currentToken != this.accessTokens.computeIfAbsent(connectionContext, this::token)) {
            return currentToken;
        }

        // Token acquisition logic
        final Mono<String> tokenMono = this.refreshTokens
                .getOrDefault(connectionContext, Mono.empty())
                .flatMap(refreshToken -> {
                    // Clear the refresh token immediately to prevent concurrent use
                    this.refreshTokens.remove(connectionContext);
                    /*
                     * Note: This removal might mean, that in case fetching
                     * a new access token by using this refresh token fails, 
                     * we may lose the refresh token (as we are not putting
                     * it back to the ConcurrentMap anymore).
                     * However, this should not turn out to be harmful,
                     * as in this case, a "primary token" is fetched instead.
                     */
                    return refreshToken(connectionContext, refreshToken)
                            .doOnSubscribe(s -> LOGGER.debug("Negotiating using refresh token"));
                })
                .switchIfEmpty(
                        primaryToken(connectionContext)
                                .doOnSubscribe(s -> LOGGER.debug("Negotiating using token provider")));

        // Apply caching only to successful responses
        // prevent that broken tokens are ever cached
        final Mono<String> tokenMonoNonBroken = tokenMono
                .filter(token -> token != null && !token.trim().isEmpty());
        
        final Mono<String> cached = connectionContext
                .getCacheDuration()
                .map(duration -> tokenMonoNonBroken.cache(duration))
                .orElseGet(() -> tokenMonoNonBroken.cache())
                .checkpoint();

        return cached;
    }
    
    private Mono<String> token(ConnectionContext connectionContext) {
        return Mono.fromCallable(() -> {
            final ReentrantLock lock = getTokenRefreshLock(connectionContext);
            lock.lock();
            try {
                return tokenProtectedFromConcurrency(connectionContext);
            } finally {
                lock.unlock();
            }
        }).flatMap(mono -> mono);
    }

    @SuppressWarnings("unchecked")
    private Function<ByteBufFlux, Mono<String>> tokensExtractor(
            ConnectionContext connectionContext) {
        return body ->
                JsonCodec.decode(connectionContext.getObjectMapper(), body, Map.class)
                        .map(payload -> (Map<String, String>) payload)
                        .doOnNext(extractRefreshToken(connectionContext))
                        .map(AbstractUaaTokenProvider::extractAccessToken);
    }

    private static final class RefreshToken {

        private Sinks.Many<String> sink = Sinks.many().replay().latest();
    }
}