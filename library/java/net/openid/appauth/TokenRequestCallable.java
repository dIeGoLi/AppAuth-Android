package net.openid.appauth;

import android.text.TextUtils;

import androidx.annotation.NonNull;

import net.openid.appauth.connectivity.ConnectionBuilder;
import net.openid.appauth.internal.Logger;
import net.openid.appauth.internal.UriUtil;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.util.Map;
import java.util.concurrent.Callable;

class TokenRequestCallable {
    private TokenRequest mRequest;
    private ClientAuthentication mClientAuthentication;
    private final ConnectionBuilder mConnectionBuilder;
    private Clock mClock;

    private AuthorizationException mException;

    TokenRequestCallable(TokenRequest request,
                     @NonNull ClientAuthentication clientAuthentication,
                     @NonNull ConnectionBuilder connectionBuilder,
                     Clock clock) {
        mRequest = request;
        mClientAuthentication = clientAuthentication;
        mConnectionBuilder = connectionBuilder;
        mClock = clock;
    }

    public TokenRequestCallableResult call() {
        JSONObject json = performRequest();
        return parseJson(json);
    }

    private TokenRequestCallableResult parseJson(JSONObject json) {
        if (mException != null) {
            return new TokenRequestCallableResult(mException);
        }

        if (json.has(AuthorizationException.PARAM_ERROR)) {
            AuthorizationException ex;
            try {
                String error = json.getString(AuthorizationException.PARAM_ERROR);
                ex = AuthorizationException.fromOAuthTemplate(
                    AuthorizationException.TokenRequestErrors.byString(error),
                    error,
                    json.optString(AuthorizationException.PARAM_ERROR_DESCRIPTION, null),
                    UriUtil.parseUriIfAvailable(
                        json.optString(AuthorizationException.PARAM_ERROR_URI)));
            } catch (JSONException jsonEx) {
                ex = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                    jsonEx);
            }
            return new TokenRequestCallableResult(ex);
        }

        TokenResponse response;
        try {
            response = new TokenResponse.Builder(mRequest).fromResponseJson(json).build();
        } catch (JSONException jsonEx) {

            return new TokenRequestCallableResult( AuthorizationException.fromTemplate(
                AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                jsonEx));
        }

        if (response.idToken != null) {
            IdToken idToken;
            try {
                idToken = IdToken.from(response.idToken);
            } catch (IdToken.IdTokenException | JSONException ex) {
                return new TokenRequestCallableResult(
                    AuthorizationException.fromTemplate(
                        AuthorizationException.GeneralErrors.ID_TOKEN_PARSING_ERROR,
                        ex));
            }

            try {
                idToken.validate(mRequest, mClock);
            } catch (AuthorizationException ex) {
                return new TokenRequestCallableResult(ex);
            }
        }
        Logger.debug("Token exchange with %s completed",
            mRequest.configuration.tokenEndpoint);
        return new TokenRequestCallableResult(response);
    }

    private JSONObject performRequest() {
        InputStream is = null;
        try {
            HttpURLConnection conn = mConnectionBuilder.openConnection(
                mRequest.configuration.tokenEndpoint);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            addJsonToAcceptHeader(conn);
            conn.setDoOutput(true);

            Map<String, String> headers = mClientAuthentication
                .getRequestHeaders(mRequest.clientId);
            if (headers != null) {
                for (Map.Entry<String,String> header : headers.entrySet()) {
                    conn.setRequestProperty(header.getKey(), header.getValue());
                }
            }

            Map<String, String> parameters = mRequest.getRequestParameters();
            Map<String, String> clientAuthParams = mClientAuthentication
                .getRequestParameters(mRequest.clientId);
            if (clientAuthParams != null) {
                parameters.putAll(clientAuthParams);
            }

            String queryData = UriUtil.formUrlEncode(parameters);
            conn.setRequestProperty("Content-Length", String.valueOf(queryData.length()));
            OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());

            wr.write(queryData);
            wr.flush();

            if (conn.getResponseCode() >= HttpURLConnection.HTTP_OK
                && conn.getResponseCode() < HttpURLConnection.HTTP_MULT_CHOICE) {
                is = conn.getInputStream();
            } else {
                is = conn.getErrorStream();
            }
            String response = Utils.readInputStream(is);
            return new JSONObject(response);
        } catch (IOException ex) {
            Logger.debugWithStack(ex, "Failed to complete exchange request");
            mException = AuthorizationException.fromTemplate(
                AuthorizationException.GeneralErrors.NETWORK_ERROR, ex);
        } catch (JSONException ex) {
            Logger.debugWithStack(ex, "Failed to complete exchange request");
            mException = AuthorizationException.fromTemplate(
                AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR, ex);
        } finally {
            Utils.closeQuietly(is);
        }
        return null;
    }

    /**
     * GitHub will only return a spec-compliant response if JSON is explicitly defined
     * as an acceptable response type. As this is essentially harmless for all other
     * spec-compliant IDPs, we add this header if no existing Accept header has been set
     * by the connection builder.
     */
    private void addJsonToAcceptHeader(URLConnection conn) {
        if (TextUtils.isEmpty(conn.getRequestProperty("Accept"))) {
            conn.setRequestProperty("Accept", "application/json");
        }
    }
}
