package com.danielfrak.code.keycloak.authenticator;

import com.danielfrak.code.keycloak.providers.rest.ConfigurationProperties;
import com.danielfrak.code.keycloak.providers.rest.LegacyProvider;
import com.danielfrak.code.keycloak.providers.rest.LegacyProviderFactory;
import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUser;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;

import java.util.List;
import java.util.Optional;

public class UserInfoAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(UserInfoAuthenticator.class);
    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        List<ComponentModel> componentModels = realm.getStorageProviders(UserStorageProvider.class).toList();

        for (ComponentModel componentModel : componentModels) {
            // Check that the provider is of our type, and that it's not this model
            if (componentModel.getProviderId().equals(ConfigurationProperties.PROVIDER_NAME)) {
                LOG.infof("Found provider named \"%s\" with ID: %s", componentModel.getName(), componentModel.getId());
                // Using getProvider with componentModel is deprecated, but the replacement, getComponentProvider, always return null
                LegacyProvider legacyProvider = session.getProvider(LegacyProvider.class, componentModel);

                if (legacyProvider == null) {
                    LOG.debug("Provider not found in session, trying to create");
                    legacyProvider = new LegacyProviderFactory().create(session, componentModel);
                }

                if (legacyProvider != null) {
                    LOG.debug("Have provider, getting user info");
                    Optional<LegacyUser> legacyUser = legacyProvider.getLegacyUserInfo(user);
                    if (legacyUser.isPresent()) {
                        legacyProvider.updateUserInfo(user, legacyUser.get(), realm);
                    } else {
                        LOG.infof("User with email \"%s\" was not found", user.getEmail());
                    }
                } else {
                    LOG.info("Failed getting provider");
                }
            }
        }

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        this.session = session;
        this.realm = realm;
        this.user = user;

        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
