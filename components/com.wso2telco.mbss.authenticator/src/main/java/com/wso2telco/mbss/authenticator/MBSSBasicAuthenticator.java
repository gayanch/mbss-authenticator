package com.wso2telco.mbss.authenticator;

import com.wso2telco.mbss.authenticator.internal.MBSSAuthenticatorServiceComponent;
import com.wso2telco.mbss.authenticator.model.AuthorizeRoleResponse;
import com.wso2telco.mbss.authenticator.model.MBSSAuthenticatorConfig;
import com.wso2telco.mbss.authenticator.util.ConfigLoader;
import com.wso2telco.mbss.authenticator.util.SessionAuthenticatorDbUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.SQLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * Username Password based custom Authenticator
 */
public class MBSSBasicAuthenticator extends AbstractApplicationAuthenticator implements
        LocalApplicationAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(MBSSBasicAuthenticator.class);


    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();//This is the
        // default WSO2 IS login page. If you can create your custom login page you can use
        // that instead.
        String queryParams =
                FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(),
                        context.getContextIdentifier());

        try {
            if (context.isRetrying()) {
                String failedReason = context.getProperty(MBSSAuthenticatorConstants.FAILED_REASON)
                        .toString();

                MBSSAuthenticatorConfig.ErrorMessagesConfig errorMessagesConfig =
                        ConfigLoader.getInstance().getMbssAuthenticatorConfig().getErrorMessagesConfig();

                if (MBSSAuthenticatorConstants.FAILED_REASON_ACCOUNT_SUSPENDED.equals(failedReason)) {
                    String retryParam = "&authFailure=true&authFailureMsg=" +
                            errorMessagesConfig.getAccountSuspendedMessage().replaceAll(" ", "%20");

                    response.sendRedirect(response.encodeRedirectURL(new StringBuilder().append(loginPage)
                            .append("?").append(queryParams).toString())
                            + "&authenticators=BasicAuthenticator:LOCAL" + retryParam);
                    return;

                } else if (MBSSAuthenticatorConstants.FAILED_REASON_SESSION_LIMIT.equals(failedReason)) {
                    String retryParam = "&authFailure=true&authFailureMsg=" +
                            errorMessagesConfig.getSessionLimitExceededMessage().replaceAll(" ", "%20");

                    response.sendRedirect(response.encodeRedirectURL(new StringBuilder().append(loginPage)
                            .append("?").append(queryParams).toString())
                            + "&authenticators=BasicAuthenticator:LOCAL" + retryParam);
                    return;

                } else if (MBSSAuthenticatorConstants.FAILED_REASON_INVALID_CREDENTIALS.equals(failedReason)) {
                    String retryParam = "&authFailure=true&authFailureMsg=" +
                            errorMessagesConfig.getInvalidCredentialsMessage().replaceAll(" ", "%20");

                    response.sendRedirect(response.encodeRedirectURL(new StringBuilder().append(loginPage)
                            .append("?").append(queryParams).toString())
                            + "&authenticators=BasicAuthenticator:LOCAL" + retryParam);
                    return;

                } else if (MBSSAuthenticatorConstants.FAILED_REASON_UNKNOWN.equals(failedReason)) {
                    //most of the time this is caused by locked accounts, detailed error message can be found
                    //in context property: SessionAuthenticatorConstants.FAILED_REASON_CAUSE
                    String retryParam = "&authFailure=true&authFailureMsg=" +
                            errorMessagesConfig.getAccountLockedMessage().replaceAll(" ", "%20");
                    response.sendRedirect(response.encodeRedirectURL(new StringBuilder().append(loginPage)
                            .append("?").append(queryParams).toString())
                            + "&authenticators=BasicAuthenticator:LOCAL" + retryParam);
                    return;

                } else if (MBSSAuthenticatorConstants.FAILED_REASON_OUTSIDE_WORKING_HOURS.equals(failedReason)) {
                    String retryParam = "&authFailure=true&authFailureMsg=" +
                            errorMessagesConfig.getLoginTimeRestrictedMessage().replaceAll(" ", "%20");

                    response.sendRedirect(response.encodeRedirectURL(new StringBuilder().append(loginPage)
                            .append("?").append(queryParams).toString())
                            + "&authenticators=BasicAuthenticator:LOCAL" + retryParam);
                    return;

                }
            }

            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) +
                    "&authenticators=BasicAuthenticator:" + "LOCAL");
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * This method is used to process the authentication response.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        boolean credentialsValid = isUserCredentialsValid(request, response, context);
        if (!credentialsValid) {
            throw new AuthenticationFailedException("User authentication failed.");
        }

        boolean accountSuspended = isAccountSuspended(request, response, context);
        if (accountSuspended) {
            throw new AuthenticationFailedException("User account is suspended");
        }

        boolean newSessionAllowed = isNewSessionAllowed(request, response, context);
        if (!newSessionAllowed) {
            throw new AuthenticationFailedException("New sessions are not allowed at the moment.");
        }

        boolean timeRestricted = isLoginTimeRestricted(request, response, context);
        if (timeRestricted) {
            throw new AuthenticationFailedException("Login is aborted due to login time restrictions.");
        }
    }


    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    @Override
    public String getFriendlyName() {
        //Set the name to be displayed in local authenticator drop down lsit
        return MBSSAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {
        String userName = httpServletRequest.getParameter(MBSSAuthenticatorConstants.USER_NAME);
        String password = httpServletRequest.getParameter(MBSSAuthenticatorConstants.PASSWORD);
        if (userName != null && password != null) {
            return true;
        }
        return false;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {
        return httpServletRequest.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {
        return MBSSAuthenticatorConstants.AUTHENTICATOR_NAME;
    }


    private boolean isUserCredentialsValid(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) {
        String username = request.getParameter(MBSSAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(MBSSAuthenticatorConstants.PASSWORD);
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));

        boolean isAuthenticated = false;
        try {
            int tenantId = MBSSAuthenticatorServiceComponent.getRealmService().getTenantManager().
                    getTenantId(MultitenantUtils.getTenantDomain(username));
            UserStoreManager userStoreManager = (UserStoreManager) MBSSAuthenticatorServiceComponent
                    .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();

            isAuthenticated = userStoreManager.authenticate(MultitenantUtils.getTenantAwareUsername(username), password);

            if (!isAuthenticated) {
                String message = "Invalid credentials for username: " + username;
                log.error(message);
                context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON,
                        MBSSAuthenticatorConstants.FAILED_REASON_INVALID_CREDENTIALS);
            }
        } catch (UserStoreException e) {
            log.warn(e.getMessage(), e);

            context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON,
                    MBSSAuthenticatorConstants.FAILED_REASON_UNKNOWN);
            context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON_CAUSE, e.getMessage());
        }

        return isAuthenticated;
    }


    private boolean isAccountSuspended(HttpServletRequest request, HttpServletResponse response,
                                       AuthenticationContext context) {

        boolean featureEnabled = ConfigLoader.getInstance().getMbssAuthenticatorConfig().getFeatureConfig()
                .isAccountSuspensionEnabled();
        if (!featureEnabled) {
            return false;
        }

        String username = request.getParameter(MBSSAuthenticatorConstants.USER_NAME);
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));

        boolean isSuspended = false;
        try {
            int tenantId = MBSSAuthenticatorServiceComponent.getRealmService().getTenantManager().
                    getTenantId(MultitenantUtils.getTenantDomain(username));
            UserStoreManager userStoreManager = (UserStoreManager) MBSSAuthenticatorServiceComponent
                    .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();

            String accountSuspendedClaimValue = userStoreManager.getUserClaimValue(username,
                    MBSSAuthenticatorConstants.ACCOUNT_SUSPENDED_CLAIM, null);

            if (Boolean.TRUE.toString().equals(accountSuspendedClaimValue)) {
                isSuspended = true;
                String message = "User account (" + username + ") is suspended due to inactivity. " +
                        "Authorization aborted.";
                log.warn(message);
                context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON,
                        MBSSAuthenticatorConstants.FAILED_REASON_ACCOUNT_SUSPENDED);
            }
        } catch (UserStoreException e) {
            isSuspended = true;
            log.warn(e.getMessage(), e);

            context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON,
                    MBSSAuthenticatorConstants.FAILED_REASON_UNKNOWN);
            context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON_CAUSE, e.getMessage());
        }

        return isSuspended;
    }


    private boolean isNewSessionAllowed(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationContext context) {

        boolean featureEnabled = ConfigLoader.getInstance().getMbssAuthenticatorConfig().getFeatureConfig()
                .isSessionLimitingEnabled();
        if (!featureEnabled) {
            return true;
        }

        final int maximumSessionCount = ConfigLoader.getInstance().getMbssAuthenticatorConfig().getFeatureConfig()
                .getMaximumSessionLimit();

        String username = request.getParameter(MBSSAuthenticatorConstants.USER_NAME);
        String serviceProviderName = context.getServiceProviderName();
        boolean allowed = false;
        try {
            int cachedActiveSessions = SessionAuthenticatorDbUtil.getActiveSessionCount(username + ":"
                    + serviceProviderName);
            if (cachedActiveSessions < maximumSessionCount) {
                allowed = true;
            } else {
                log.warn("Authentication blocked for user: " + username + ", Reason: Active session limit exceeded.");
                context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON,
                        MBSSAuthenticatorConstants.FAILED_REASON_SESSION_LIMIT);
            }
        } catch (SQLException e) {
            log.error(e.getMessage(), e);
        }

        return allowed;
    }

    private boolean isLoginTimeRestricted(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationContext context) {

        boolean featureEnabled = ConfigLoader.getInstance().getMbssAuthenticatorConfig().getFeatureConfig()
                .isLoginTimeRestrictionEnabled();
        if (!featureEnabled) {
            return false;
        }

        boolean timeRestricted = false;
        String username = request.getParameter(MBSSAuthenticatorConstants.USER_NAME);
        UserStoreManager userStoreManager = null;
        try {
            int tenantId = MBSSAuthenticatorServiceComponent.getRealmService().getTenantManager().
                    getTenantId(MultitenantUtils.getTenantDomain(username));
            userStoreManager = (UserStoreManager) MBSSAuthenticatorServiceComponent
                    .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
        } catch (UserStoreException e) {
            log.error(e.getMessage(), e);
        }

        List<MBSSAuthenticatorConfig.WorkingTime> timeList = ConfigLoader.getInstance()
                .getMbssAuthenticatorConfig().getWorkingTimeRoleConfig();

        for (MBSSAuthenticatorConfig.WorkingTime workingTime: timeList) {
            AuthorizeRoleResponse roleResponse = authorizeLoginForRole(workingTime, username, userStoreManager);

            if (roleResponse.getResponseType() != AuthorizeRoleResponse.RESPONSE_TYPE_OK) {
                context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON,
                        MBSSAuthenticatorConstants.FAILED_REASON_OUTSIDE_WORKING_HOURS);

                log.warn("User login prevented according to login time restrictions. " +
                        "[User: " + username + ", Affected Role: " + roleResponse.getRole() + "]");
                timeRestricted = true;
            }
        }

        return timeRestricted;
    }

    private AuthorizeRoleResponse authorizeLoginForRole(MBSSAuthenticatorConfig.WorkingTime config, String username,
                                                        UserStoreManager userStoreManager) {

        try {
            AbstractUserStoreManager abstractUserStoreManager = ((AbstractUserStoreManager) userStoreManager);


            if (abstractUserStoreManager != null) {
                if (abstractUserStoreManager.isUserInRole(username, config.getRole())) {
                    boolean authorized = isLoginAllowedByTimeConfig(config);

                    if (!authorized) {
                        return new AuthorizeRoleResponse(AuthorizeRoleResponse.RESPONSE_TYPE_RESTRICTED_TIME,
                                "Login is not allowed at this moment due to login time restrictions",
                                username, config.getRole());
                    }
                }
            }
        } catch (UserStoreException e) {
            log.error("Error occurred while checking login time restrictions", e);
        }

        return new AuthorizeRoleResponse(AuthorizeRoleResponse.RESPONSE_TYPE_OK, "Login authorized",
                username, config.getRole());
    }

    private boolean isLoginAllowedByTimeConfig(MBSSAuthenticatorConfig.WorkingTime config) {
        try {
            Date start = new SimpleDateFormat("HHmm").parse(config.getStartTime());
            Date end = new SimpleDateFormat("HHmm").parse(config.getEndTime());
            Date current = new SimpleDateFormat("HHmm")
                    .parse(new SimpleDateFormat("HHmm").format(new Date()));

            if (end.before(start)) {
                //ranges are scattered across 2 days, add one day to end date and compare
                Calendar calendar = Calendar.getInstance();
                calendar.setTime(end);
                calendar.add(Calendar.DATE, 1);

                Date correctedEnd = calendar.getTime();

                return start.before(current) && correctedEnd.after(current);
            }
            //ranges are within same day
            return start.before(current) && end.after(current);
        } catch (ParseException e) {
            log.error("Error occurred while checking authorized login times.", e);
            return true;
        }
    }

    private boolean isPasswordExpired(HttpServletRequest request, HttpServletResponse response,
                                      AuthenticationContext context) {
        boolean featureEnabled = ConfigLoader.getInstance().getMbssAuthenticatorConfig().getFeatureConfig()
                .isPeriodicPasswordChangeEnabled();
        if (!featureEnabled) {
            return false;
        }

        int expireInterval = ConfigLoader.getInstance().getMbssAuthenticatorConfig().getPasswordChangeConfig()
                .getPasswordChangeInterval();
        String username = request.getParameter(MBSSAuthenticatorConstants.USER_NAME);
        boolean expired = false;
        long currentTime = System.currentTimeMillis();
        long lastPasswordChangeTime = -1l;

        try {
            int tenantId = MBSSAuthenticatorServiceComponent.getRealmService().getTenantManager().
                    getTenantId(MultitenantUtils.getTenantDomain(username));
            UserStoreManager userStoreManager = (UserStoreManager) MBSSAuthenticatorServiceComponent
                    .getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();

            String lastPasswordChangeClaimValue = userStoreManager.getUserClaimValue(username,
                    MBSSAuthenticatorConstants.LAST_PASSWORD_CHANGE_CLAIM, null);

            if (null != lastPasswordChangeClaimValue && (!lastPasswordChangeClaimValue.isEmpty())) {
                lastPasswordChangeTime = Long.parseLong(lastPasswordChangeClaimValue);
            }
        } catch (UserStoreException e) {
            log.warn(e.getMessage(), e);

            context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON,
                    MBSSAuthenticatorConstants.FAILED_REASON_UNKNOWN);
            context.setProperty(MBSSAuthenticatorConstants.FAILED_REASON_CAUSE, e.getMessage());
        }

        if (lastPasswordChangeTime != -1) {
            long unchangedDurationInMillis = currentTime - lastPasswordChangeTime;
            long expireIntervalInMillis = expireInterval * 24 * 60 * 60 * 1000;

            if (unchangedDurationInMillis > expireIntervalInMillis) {
                expired = true;
            }
        }

        return expired;
    }
}