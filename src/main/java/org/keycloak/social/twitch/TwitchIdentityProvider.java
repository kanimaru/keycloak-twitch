package org.keycloak.social.twitch;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Twitch identity provider.
 * <p>
 * For the most part, all the methods defined in the class are
 * <i>exactly</i> the same as those in {@link OIDCIdentityProvider}. The only
 * difference is that, wherever a Twitch OAuth 2.0 access token response is
 * received, we convert it to a format that can be deserialized to an instance
 * of Keycloak's {@link AccessTokenResponse}.
 * <p>
 * Unfortunately, this conversion is necessary due to the fact that
 * <a href="https://dev.twitch.tv/docs/authentication/getting-tokens-oauth">
 * Twitch's authorization server implementation</a> diverges from the
 * <a href="https://tools.ietf.org/html/rfc6749">OAuth 2.0 specification</a>;
 * specifically, in their formatting of the "scope" parameter of the access
 * token response.
 * <p>
 * The <a href="https://tools.ietf.org/html/rfc6749#section-3.3">OAuth 2.0
 * specification</a> denotes that the scope parameter is to be expressed as "a
 * list of space-delimited, case-sensitive strings". However, in Twitch's
 * OAuth 2.0 Access Token response, the scope parameter is expressed as a JSON
 * array of strings.
 *
 * @see TwitchIdentityProvider#convertFromTwitchAccessTokenResponseToSpec(String)
 */
public class TwitchIdentityProvider extends OIDCIdentityProvider
        implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    public static final String AUTH_URL = "https://id.twitch.tv/oauth2/authorize";
    public static final String TOKEN_URL = "https://id.twitch.tv/oauth2/token";
    public static final String PROFILE_URL = "https://id.twitch.tv/oauth2/userinfo";
    public static final String DEFAULT_SCOPE = "openid user:read:email";

    private static final String BROKER_NONCE_PARAM = "BROKER_NONCE";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    // UserInfo claims
    public static final String CLAIM_PICTURE = "picture";
    public static final String CLAIM_EMAIL_VERIFIED = "email_verified"; // It could be possible that the ID Token claim would also work, and we wouldn't need to pull this info from userinfo endpoint.
    public static final String CLAIM_UPDATED_AT = "updated_at";

    public TwitchIdentityProvider(
            KeycloakSession session,
            TwitchIdentityProviderConfig config
    ) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl())
                .queryParam(OAuth2Constants.CLIENT_ID, getConfig().getClientId())
                .queryParam(OAuth2Constants.RESPONSE_TYPE, "code")
                .queryParam(OAuth2Constants.REDIRECT_URI, request.getRedirectUri())
                .queryParam(OAuth2Constants.STATE, request.getState().getEncoded())
                .queryParam(OAuth2Constants.SCOPE, getConfig().getDefaultScope())
                // Claims are needed to get the right information from the user endpoint see https://dev.twitch.tv/docs/authentication/getting-tokens-oidc/#requesting-claims
                .queryParam("claims", "%7B%22userinfo%22%3A%7B%22email%22%3Anull%2C%22email_verified%22%3Anull%2C%22picture%22%3Anull%2C%22preferred_username%22%3Anull%2C%22updated_at%22%3Anull%7D%2C%22id_token%22%3A%7B%22email_verified%22%3Anull%7D%7D");


        String loginHint = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        if (loginHint != null) {
            uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
        }

        String nonce = UUID.randomUUID().toString();
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        request.getAuthenticationSession().setClientNote(BROKER_NONCE_PARAM, nonce);

        logger.debugf("Twitch authorization URL: %s", uriBuilder.build().toString());

        return uriBuilder;

    }

    @Override
    protected Response exchangeSessionToken(UriInfo uriInfo,
                                            EventBuilder event,
                                            ClientModel authorizedClient,
                                            UserSessionModel tokenUserSession,
                                            UserModel tokenSubject) {
        String refreshToken = tokenUserSession.getNote(FEDERATED_REFRESH_TOKEN);
        String accessToken = tokenUserSession.getNote(FEDERATED_ACCESS_TOKEN);

        if (accessToken == null) {
            event.detail(Details.REASON, "requested_issuer is not linked");
            event.error(Errors.INVALID_TOKEN);
            return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
            long expiration = Long.parseLong(tokenUserSession.getNote(FEDERATED_TOKEN_EXPIRATION));
            if (expiration == 0 || expiration > Time.currentTime()) {
                AccessTokenResponse tokenResponse = new AccessTokenResponse();
                tokenResponse.setExpiresIn(expiration);
                tokenResponse.setToken(accessToken);
                tokenResponse.setIdToken(null);
                tokenResponse.setRefreshToken(null);
                tokenResponse.setRefreshExpiresIn(0);
                tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
                tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
                event.success();
                return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
            }
            String response = getRefreshTokenRequest(session, refreshToken, getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret())).asString();
            if (response.contains("error")) {
                logger.debugv("Error refreshing token, refresh token expiration?: {0}", response);
                event.detail(Details.REASON, "requested_issuer token expired");
                event.error(Errors.INVALID_TOKEN);
                return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
            }

            /*
             * Convert Twitch-style access token response to OAuth 2.0
             * spec-compliant.
             */
            response = convertFromTwitchAccessTokenResponseToSpec(response);

            AccessTokenResponse newResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
            long accessTokenExpiration = newResponse.getExpiresIn() > 0 ? Time.currentTime() + newResponse.getExpiresIn() : 0;
            tokenUserSession.setNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(accessTokenExpiration));
            tokenUserSession.setNote(FEDERATED_REFRESH_TOKEN, newResponse.getRefreshToken());
            tokenUserSession.setNote(FEDERATED_ACCESS_TOKEN, newResponse.getToken());
            tokenUserSession.setNote(FEDERATED_ID_TOKEN, newResponse.getIdToken());
            newResponse.setIdToken(null);
            newResponse.setRefreshToken(null);
            newResponse.setRefreshExpiresIn(0);
            newResponse.getOtherClaims().clear();
            newResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
            newResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
            event.success();
            return Response.ok(newResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            throw new TwitchParsingException("Can't convert twitch token to real OIDC tokens.", e);
        }
    }

    @Override
    protected void setEmailVerified(UserModel user, BrokeredIdentityContext context) {
        OIDCIdentityProviderConfig config = getConfig();
        Map<String, Object> contextData = context.getContextData();
        Boolean emailVerified = (Boolean) contextData.get(CLAIM_EMAIL_VERIFIED); // Getting it from User Endpoint
        logger.debugf("Stored email verification status: %s", emailVerified);

        if (!config.isTrustEmail() || emailVerified == null) {
            // fallback to the default behavior if trust is disabled or there is no email_verified claim
            super.setEmailVerified(user, context);
            return;
        }

        user.setEmailVerified(emailVerified);
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        logger.debugf("Twitch raw token response: %s", response);

        AccessTokenResponse tokenResponse;
        try {
            /*
             * Convert Twitch-style access token response to OAuth 2.0
             * spec-compliant.
             */
            response = convertFromTwitchAccessTokenResponseToSpec(response);

            tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not decode access token response.", e);
        }
        String accessToken = checkAccessTokenAvailability(tokenResponse);

        String encodedIdToken = tokenResponse.getIdToken();

        JsonWebToken idToken = validateToken(encodedIdToken);

        try {
            BrokeredIdentityContext identity = extractIdentity(tokenResponse, accessToken, idToken);

            if (!identity.getId().equals(idToken.getSubject())) {
                throw new IdentityBrokerException("Mismatch between the subject in the id_token and the subject from the user_info endpoint");
            }

            identity.getContextData().put(BROKER_NONCE_PARAM, idToken.getOtherClaims().get(OIDCLoginProtocol.NONCE_PARAM));

            if (getConfig().isStoreToken()) {
                if (tokenResponse.getExpiresIn() > 0) {
                    long accessTokenExpiration = Time.currentTime() + tokenResponse.getExpiresIn();
                    tokenResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                    response = JsonSerialization.writeValueAsString(tokenResponse);
                }
                identity.setToken(response);
            }

            return identity;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not fetch attributes from userinfo endpoint.", e);
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentity(
            AccessTokenResponse tokenResponse,
            String accessToken,
            JsonWebToken idToken) throws IOException {
        BrokeredIdentityContext identity = super.extractIdentity(tokenResponse, accessToken, idToken);

        try {
            String userInfoUrl = getConfig().getUserInfoUrl();
            if (userInfoUrl != null && !userInfoUrl.trim().isEmpty()) {
                SimpleHttp userInfoRequest = SimpleHttp.doGet(userInfoUrl, session)
                        .header("Authorization", "Bearer " + accessToken);

                String userInfoResponse = userInfoRequest.asString();
                logger.debugf("UserInfo response for Twitch: %s", userInfoResponse);

                JsonNode userInfo = objectMapper.readTree(userInfoResponse);

                // Extract email from UserInfo if available
                if (userInfo.has("email")) {
                    identity.setEmail(userInfo.get("email").asText());
                }

                if (userInfo.has(CLAIM_EMAIL_VERIFIED)) {
                    boolean emailVerified = userInfo.get(CLAIM_EMAIL_VERIFIED).asBoolean();
                    identity.getContextData().put(CLAIM_EMAIL_VERIFIED, emailVerified);
                }

                if (userInfo.has(CLAIM_PICTURE)) {
                    String pictureUrl = userInfo.get(CLAIM_PICTURE).asText();
                    identity.setUserAttribute(CLAIM_PICTURE, pictureUrl);
                }

                if (userInfo.has(CLAIM_UPDATED_AT)) {
                    String updatedAt = userInfo.get(CLAIM_UPDATED_AT).asText();
                    identity.setUserAttribute(CLAIM_UPDATED_AT, updatedAt);
                }
            }
        } catch (Exception e) {
            logger.warnf("Failed to fetch UserInfo manually: %s", e.getMessage());
        }

        return identity;
    }

    private String checkAccessTokenAvailability(AccessTokenResponse tokenResponse) {
        String accessToken = tokenResponse.getToken();

        if (accessToken == null) {
            throw new IdentityBrokerException("No access_token from server.");
        }

        return accessToken;
    }

    /**
     * Convert an OAuth 2.0 access token response formatted according to
     * <a href="https://dev.twitch.tv/docs/authentication/getting-tokens-oauth">
     * Twitch's authorization server implementation</a> to one that is
     * formatted according to the <a href="https://tools.ietf.org/html/rfc6749">
     * OAuth 2.0 specification</a>.
     * <p>
     * The <a href="https://tools.ietf.org/html/rfc6749#section-3.3">OAuth 2.0
     * specification</a> denotes that the scope parameter is to be expressed as
     * "a list of space-delimited, case-sensitive strings". However, in
     * Twitch's OAuth 2.0 Access Token response, the scope parameter is
     * expressed as a JSON array of strings.
     * <p>
     * Note that if the scope parameter is already formatted according to the
     * OAuth 2.0 specification, this method just returns the access token
     * response as is.
     *
     * @param response OAuth 2.0 access token response formatted according to
     *                 <a href="https://dev.twitch.tv/docs/authentication/getting-tokens-oauth">
     *                 Twitch's authorization server implementation</a>
     * @return OAuth 2.0 access token response formatted according to the
     * <a href="https://tools.ietf.org/html/rfc6749"> OAuth 2.0
     * specification</a>.
     * @throws JsonProcessingException If JSON (de)serialization fails.
     */
    public String convertFromTwitchAccessTokenResponseToSpec(String response) throws JsonProcessingException {
        Map<String, Object> accessTokenResponseMap = mapper.readValue(response,
                new TypeReference<Map<String, Object>>() {
                }
        );

        Object scopeObj = accessTokenResponseMap.get("scope");
        if (scopeObj instanceof List<?>) {
            String scope = ((List<?>) scopeObj).stream()
                    .map(Object::toString)
                    .collect(Collectors.joining(" "));

            accessTokenResponseMap.put("scope", scope);
            return objectMapper.writeValueAsString(accessTokenResponseMap);
        } else if (scopeObj instanceof String) {
            /*
             * The scope is already expressed as a string. This may be an
             * access token response that we've already stored in the
             * database after converting it in the past.
             *
             * We'll just assume that it's already formatted according to the
             * OAuth 2.0 specification and return the access token response as
             * it is.
             */
            return objectMapper.writeValueAsString(accessTokenResponseMap);
        } else {
            throw new InvalidTwitchAccessTokenResponseScopeException();
        }
    }
}
