package net.openid.appauth;

import androidx.annotation.Nullable;

class TokenRequestCallableResult {

    TokenRequestCallableResult(AuthorizationException ex) {
        this.ex = ex;
        this.response = null;
    }

    TokenRequestCallableResult(TokenResponse response) {
        this.ex = null;
        this.response = response;
    }

    @Nullable
    public final TokenResponse response;

    @Nullable
    public final AuthorizationException ex;
}
