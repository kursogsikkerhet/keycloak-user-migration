package com.danielfrak.code.keycloak.providers.rest;

import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUser;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;

import java.util.Optional;

public interface LegacyUserStorageProvider extends UserStorageProvider {
    Optional<LegacyUser> getLegacyUserInfo(String email);
    void updateUserInfo(UserModel user, LegacyUser legacyUser, RealmModel realm);
}
