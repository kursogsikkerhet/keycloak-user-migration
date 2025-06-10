package com.danielfrak.code.keycloak.providers.rest;

import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.*;

public final class ConfigurationProperties {

    public static final String PROVIDER_NAME = "User migration using a REST client";
    public static final String URI_PROPERTY = "URI";
    public static final String API_TOKEN_PROPERTY = "API_TOKEN";
    public static final String API_TOKEN_ENABLED_PROPERTY = "API_TOKEN_ENABLED";
    public static final String API_HTTP_BASIC_ENABLED_PROPERTY = "API_HTTP_BASIC_ENABLED";
    public static final String API_HTTP_BASIC_USERNAME_PROPERTY = "API_HTTP_BASIC_USERNAME";
    public static final String API_HTTP_BASIC_PASSWORD_PROPERTY = "API_HTTP_BASIC_PASSWORD";
    public static final String USE_EMAIL_FOR_CREDENTIAL_VERIFICATION_PROPERTY = "USE_EMAIL_FOR_CREDENTIAL_VERIFICATION";
    public static final String ROLE_MAP_PROPERTY = "ROLE_MAP";
    public static final String GROUP_MAP_PROPERTY = "GROUP_MAP";
    public static final String MIGRATE_UNMAPPED_ROLES_PROPERTY = "MIGRATE_UNMAPPED_ROLES";
    public static final String MIGRATE_UNMAPPED_GROUPS_PROPERTY = "MIGRATE_UNMAPPED_GROUPS";
    public static final String VALID_FOR_CLIENT_PROPERTY = "VALID_FOR_CLIENT";
    public static final String RESTRICT_ROLES_TO_CLIENT_PROPERTY = "RESTRICT_ROLES_TO_CLIENT";
    public static final String USE_ID_AS_USERNAME_PROPERTY = "USE_ID_AS_USERNAME";
    public static final String PREVENT_ROLE_UPDATE_PROPERTY = "PREVENT_ROLE_UPDATE";

    private static final List<ProviderConfigProperty> PROPERTIES = List.of(
            new ProviderConfigProperty(URI_PROPERTY,
                    "Rest client URI (required)",
                    "URI of the legacy system endpoints",
                    STRING_TYPE, null),
            new ProviderConfigProperty(VALID_FOR_CLIENT_PROPERTY,
                    "Valid for Client ID",
                    """
                        The migration can be restricted to only migrate users logging in \
                        using a specific client.
                        Select a Client ID, or leave blank if valid for all clients.
                    """,
                    CLIENT_LIST_TYPE,
                    null),
            new ProviderConfigProperty(API_TOKEN_ENABLED_PROPERTY,
                    "Rest client Bearer token auth enabled",
                    "Enables Bearer token authentication for legacy user service",
                    BOOLEAN_TYPE, false),
            new ProviderConfigProperty(API_TOKEN_PROPERTY,
                    "Rest client Bearer token",
                    "Bearer token",
                    PASSWORD, null),
            new ProviderConfigProperty(API_HTTP_BASIC_ENABLED_PROPERTY,
                    "Rest client basic auth enabled",
                    "Enables HTTP basic auth for legacy user service",
                    BOOLEAN_TYPE, false),
            new ProviderConfigProperty(API_HTTP_BASIC_USERNAME_PROPERTY,
                    "Rest client basic auth username",
                    "HTTP basic auth username for legacy user service",
                    STRING_TYPE, null),
            new ProviderConfigProperty(API_HTTP_BASIC_PASSWORD_PROPERTY,
                    "Rest client basic auth password",
                    "HTTP basic auth password for legacy user service",
                    PASSWORD, null),
            new ProviderConfigProperty(USE_EMAIL_FOR_CREDENTIAL_VERIFICATION_PROPERTY,
                    "Use email for credential verification",
                    "Use the user's email instead of the username as the path " +
                    "parameter when making the credential verification request.",
                    BOOLEAN_TYPE, false),
            new ProviderConfigProperty(USE_ID_AS_USERNAME_PROPERTY,
                    "Replace username with Keycloak ID",
                    """
                        Helps prevent conflicts when importing users from several legacy systems.
                        The behaviour depends on 'Use email for credential verification':
                        If `On` the user is created with Keycloak ID as username.
                        If `Off`, the user will be created using the legacy system username, and updated to use \
                        the Keycloak ID when the Federation Link is removed.
                    """,
                    BOOLEAN_TYPE, false),
            new ProviderConfigProperty(ROLE_MAP_PROPERTY,
                    "Legacy role conversion",
                    "Role conversion in the format 'legacyRole:newRole'",
                    MULTIVALUED_STRING_TYPE, null),
            new ProviderConfigProperty(MIGRATE_UNMAPPED_ROLES_PROPERTY,
                    "Migrate unmapped roles",
                    "Whether or not to migrate roles not found in the field above",
                    BOOLEAN_TYPE, true),
            new ProviderConfigProperty(RESTRICT_ROLES_TO_CLIENT_PROPERTY,
                    "Restrict role actions to client",
                    """
                        If 'Valid Client ID' is set, this will only use roles defined on the selected client. \
                        New roles will be created on the client instead of in the realm.
                    """,
                    BOOLEAN_TYPE, false),
            new ProviderConfigProperty(PREVENT_ROLE_UPDATE_PROPERTY,
                    "Prevent role update",
                    """
                        Enable if using Keycloak as the authoritative source for roles.
                        Requires that 'Valid for Client ID' is set. Only uses/checks roles set on the client.
                        The role will be set if the user has no role for the client, \
                        but not change or add roles.
                    """,
                    BOOLEAN_TYPE, false),
            new ProviderConfigProperty(GROUP_MAP_PROPERTY,
                    "Legacy group conversion",
                    "Group conversion in the format 'legacyGroup:newGroup'",
                    MULTIVALUED_STRING_TYPE, null),
            new ProviderConfigProperty(MIGRATE_UNMAPPED_GROUPS_PROPERTY,
                    "Migrate unmapped groups",
                    "Whether or not to migrate groups not found in the field above",
                    BOOLEAN_TYPE, true)
    );

    private ConfigurationProperties() {
    }

    public static List<ProviderConfigProperty> getConfigProperties() {
        return PROPERTIES;
    }
}
