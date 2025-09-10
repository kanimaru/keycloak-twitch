package org.keycloak.social.twitch;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;


public class TwitchUserAttributeMapper extends AbstractJsonUserAttributeMapper {

    private static final String[] cp = new String[]{TwitchIdentityProviderFactory.PROVIDER_ID};

    @Override
    public String[] getCompatibleProviders() {
        return cp;
    }

    @Override
    public String getId() {
        return "twitch-user-attribute-mapper";
    }

}
