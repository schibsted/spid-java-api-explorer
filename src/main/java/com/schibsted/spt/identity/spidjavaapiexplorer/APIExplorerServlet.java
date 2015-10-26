package com.schibsted.spt.identity.spidjavaapiexplorer;

import com.schibsted.spt.identity.spidjavaapiexplorer.controller.ServletController;
import com.schibsted.spt.identity.spidjavaapiexplorer.exception.ServletControllerException;
import no.spid.api.client.SpidApiClient;
import no.spid.api.client.SpidApiResponse;
import no.spid.api.connection.SpidHttp4ClientFactory;
import no.spid.api.exceptions.SpidApiException;
import no.spid.api.exceptions.SpidOAuthException;
import no.spid.api.oauth.SpidOAuthToken;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.*;

public class APIExplorerServlet extends ServletController {
    private final Logger log = LoggerFactory.getLogger(APIExplorerServlet.class);
    private static final String TOKEN = "token";
    private static final String AUTHENTICATED_USER = "authenticated_user";
    private Properties sppProps = new Properties();

    private List<String> validActions = new ArrayList<>();

    private SpidApiClient client;

    public APIExplorerServlet() {
        validActions.add("index");
        validActions.add("authorize");
        validActions.add("authresponse");
        validActions.add("serverauth");
        validActions.add("logout");
        validActions.add("apirequest");
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        try {
            sppProps.load(config.getServletContext().getResourceAsStream("/WEB-INF/config.properties"));

            final String userClientId = sppProps.getProperty("CLIENT_ID");
            final String secret = sppProps.getProperty("CLIENT_SECRET");
            final String signatureSecret = sppProps.getProperty("SIGNATURE_SECRET");
            final String redirectUrl = sppProps.getProperty("REDIRECT_URL");
            final String spidBaseUrl = sppProps.getProperty("SPID_ENVIRONMENT");

            client = new SpidApiClient.ClientBuilder(
                    userClientId,
                    secret,
                    signatureSecret,
                    redirectUrl,
                    spidBaseUrl)
                    .connectionClientFactory(new SpidHttp4ClientFactory())
                    .build();


        } catch (IOException e) {
            log.error("No config file found. Please copy '/WEB-INF/config-dist.properties' to '/WEB-INF/config.properties' and fill out correct properties");
            e.printStackTrace();
        }
    }

    public void indexAction() throws IOException, SpidOAuthException, SpidApiException {
        HttpSession session = request.getSession(true);
        SpidOAuthToken token = (SpidOAuthToken) session.getAttribute(TOKEN);

        Map<String, String> data = new HashMap<>();

        if (token == null) {
            setOutput(null);
            response.sendRedirect("/explorer/authorize");
            return;
        }

        authenticatedAs(session, data);
        jsApiMethods(token, data);
        exampleURLs(token, data);

        setOutputData(data);
    }

    private void authenticatedAs(HttpSession session, Map<String, String> data) {
        JSONObject authenticatedUser = (JSONObject) session.getAttribute(AUTHENTICATED_USER);
        if (authenticatedUser != null) {
            data.put("authenticatedAs", authenticatedUser.getString("displayName"));
        } else {
            data.put("authenticatedAs", "Server To Server");
        }
    }

    private SpidOAuthToken jsApiMethods(SpidOAuthToken token, Map<String, String> data) throws SpidOAuthException, SpidApiException {
        String jsApiMethods = "";
        SpidApiResponse endpointsResponse = client.GET(token, "/endpoints", null);
        JSONObject endpoints = endpointsResponse.getJsonResponse();
        jsApiMethods = endpoints.getJSONArray("data").toString();
        data.put("jsapimethods", jsApiMethods);
        return token;
    }

    private void exampleURLs(SpidOAuthToken token, Map<String, String> data) throws SpidOAuthException {
        Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", request.getRequestURL().toString());

        SPPUrlHelper urls = new SPPUrlHelper(
                sppProps.getProperty("CLIENT_ID"),
                sppProps.getProperty("SPID_ENVIRONMENT"));

        String accessToken = token.getAccessToken();

        data.put("getPurchaseURI", urls.getPurchaseURI(accessToken, params));
        data.put("getLogoutURI", client.getLogoutURL(token, sppProps.getProperty("REDIRECT_URL") + "/explorer/authorize"));
        data.put("getLoginURI", urls.getLoginURI(params));
        data.put("getSignupURI", urls.getSignupURI(params));

        params.clear();
        data.put("getAccountURI", urls.getAccountURI(params));
        data.put("getPurchaseHistoryURI", urls.getPurchaseHistoryURI(params));
        data.put("getLoginStatusURI", urls.getLoginStatusURI(params));
    }

    public void authorizeAction() throws ServletControllerException {
        String url = "";

        try {
            url = client.getFlowUrl("login", sppProps.getProperty("REDIRECT_URL") + "/explorer/authresponse");
        } catch (SpidOAuthException e) {
            throw new ServletControllerException(e);
        }

        Map<String, String> data = new HashMap();
        data.put("userAuthURL", url);
        setOutputData(data);
    }

    public void authresponseAction() throws ServletControllerException, IOException {
        SpidApiResponse clientResponse = null;

        try {
            String code = request.getParameter("code");
            SpidOAuthToken userToken = client.getUserToken(code);
            clientResponse = client.GET(userToken, "/me", null);

            HttpSession session = request.getSession(true);
            session.setAttribute(TOKEN, userToken);
            session.setAttribute(AUTHENTICATED_USER, clientResponse.getJsonResponse().getJSONObject("data"));
        } catch (SpidOAuthException | SpidApiException e) {
            throw new ServletControllerException(e);
        }

        setOutput(null);
        response.sendRedirect("/explorer/index");
    }

    public void serverauthAction() throws ServletControllerException, IOException {
        HttpSession session = request.getSession(true);
        try {
            session.setAttribute(TOKEN, client.getServerToken());
        } catch (SpidOAuthException e) {
            log.warn("Could not authenticate client: " + e.getMessage());
            throw new ServletControllerException(e);
        }

        setOutput(null);
        response.sendRedirect("/explorer/index");
    }

    public void logoutAction() throws IOException, SpidOAuthException {
        HttpSession session = request.getSession(true);
        String redirectUrl = sppProps.getProperty("REDIRECT_URL") + "/explorer/index";
        SpidOAuthToken token = (SpidOAuthToken) session.getAttribute(TOKEN);
        if (token != null) {
            redirectUrl = client.getLogoutURL(token, sppProps.getProperty("REDIRECT_URL") + "/explorer/index");
        }
        cleanSessionData(session);
        setOutput(null);
        response.sendRedirect(redirectUrl);
    }

    private void cleanSessionData(HttpSession session) {
        session.removeAttribute(TOKEN);
        session.removeAttribute(AUTHENTICATED_USER);
    }

    public void apirequestAction() throws ServletControllerException, IOException, SpidOAuthException {
        HttpSession session = request.getSession(true);
        setOutput(null);
        response.setContentType("application/json");

        try {
            String method = getParameter("method");
            SpidOAuthToken token = (SpidOAuthToken) session.getAttribute(TOKEN);
            SpidApiResponse spidApiResponse = null;
            switch (getParameter("httpMethod")) {
                case "GET":
                    spidApiResponse = client.GET(token, "/" + method, extractParameters());
                    break;
                case "POST":
                    spidApiResponse = client.POST(token, "/" + method, extractParameters());
                    break;
                case "DELETE":
                    spidApiResponse = client.DELETE(token, "/" + method, extractParameters());
                    break;
                default:
                    throw new IllegalStateException("Method not supported");
            }

            if (method.equals("logout")) {
                cleanSessionData(session);
            }
            response.getWriter().println(spidApiResponse.getJsonResponse());
        } catch (SpidApiException e) {
            response.getWriter().println(e.getResponseBody());
        } catch (SpidOAuthException e) {
            String jsonString = "{ exception: " + JSONObject.quote(e.getMessage()) + "}";
            response.getWriter().println(new JSONObject(jsonString));
        }
    }

    private Map<String, String> extractParameters() {
        List<String> excludeList = new ArrayList<>();
        excludeList.add("httpMethod");
        excludeList.add("method");
        excludeList.add("page");

        Map params = getParameters();
        Map<String, String> result = new HashMap<>();
        for (Object key : params.keySet()) {
            if (key instanceof String && params.get(key) instanceof String[] && !excludeList.contains(key)) {
                result.put((String) key, ((String[]) params.get(key))[0]);
            }
        }

        return result;
    }

    @Override
    public List<String> getValidActions() {
        return validActions;
    }
}
