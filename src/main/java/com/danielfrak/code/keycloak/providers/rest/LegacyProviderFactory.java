package com.danielfrak.code.keycloak.providers.rest;

import com.danielfrak.code.keycloak.providers.rest.remote.UserModelFactory;
import com.danielfrak.code.keycloak.providers.rest.rest.http.HttpClient;
import com.danielfrak.code.keycloak.providers.rest.rest.RestUserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

import java.util.List;

import static com.danielfrak.code.keycloak.providers.rest.ConfigurationProperties.*;

public class LegacyProviderFactory implements UserStorageProviderFactory<LegacyProvider> {

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ConfigurationProperties.getConfigProperties();
    }

    @Override
    public LegacyProvider create(KeycloakSession session, ComponentModel model) {
        var userModelFactory = new UserModelFactory(session, model);
        var httpClient = new HttpClient(HttpClientBuilder.create().setRedirectStrategy(new LaxRedirectStrategy()));
        var restService = new RestUserService(model, httpClient, new ObjectMapper());
        return new LegacyProvider(session, restService, userModelFactory, model);
    }

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
        String selectedClient = config.get(VALID_FOR_CLIENT_PROPERTY, "");
        if (!selectedClient.isEmpty() && realm.getClientByClientId(selectedClient) == null) {
            throw new ComponentValidationException(String.format("Client \"%s\" does not exist", selectedClient));
        }

        boolean restrictRoles = Boolean.parseBoolean(config.get(RESTRICT_ROLES_TO_CLIENT_PROPERTY, "false"));
        if (restrictRoles && selectedClient.isEmpty()) {
            throw new ComponentValidationException("Setting 'Restrict role actions to client' requires 'Valid for Client ID' to be set");
        }

        boolean preventRoleUpdate = Boolean.parseBoolean(config.get(PREVENT_ROLE_UPDATE_PROPERTY, "false"));
        if (preventRoleUpdate && selectedClient.isEmpty()) {
            throw new ComponentValidationException("Setting 'Prevent role update' requires 'Valid for Client ID' to be set");
        }

        if (preventRoleUpdate && !restrictRoles) {
            throw new ComponentValidationException("Setting 'Prevent role update' requires 'Restrict role actions to client' to be enabled");
        }
    }
}
