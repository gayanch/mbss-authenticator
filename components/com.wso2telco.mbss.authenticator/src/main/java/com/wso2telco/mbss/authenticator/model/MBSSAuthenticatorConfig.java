package com.wso2telco.mbss.authenticator.model;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement(name="mbssAuthenticatorConfig")
public class MBSSAuthenticatorConfig {
    private List<MBSSAuthenticatorConfig.WorkingTime> workingTimeRoleConfig;
    private MBSSAuthenticatorConfig.ErrorMessagesConfig errorMessagesConfig;
    private FeatureConfig featureConfig;

    @XmlElementWrapper(name = "workingTimes")
    @XmlElement(name = "workingTime")
    public List<MBSSAuthenticatorConfig.WorkingTime> getWorkingTimeRoleConfig() {
        return workingTimeRoleConfig;
    }

    public void setWorkingTimeRoleConfig(List<MBSSAuthenticatorConfig.WorkingTime> workingTimeRoleConfig) {
        this.workingTimeRoleConfig = workingTimeRoleConfig;
    }

    @XmlElement(name = "errorMessages")
    public ErrorMessagesConfig getErrorMessagesConfig() {
        return errorMessagesConfig;
    }

    public void setErrorMessagesConfig(ErrorMessagesConfig errorMessagesConfig) {
        this.errorMessagesConfig = errorMessagesConfig;
    }

    @XmlElement(name = "featureConfig")
    public FeatureConfig getFeatureConfig() {
        return featureConfig;
    }

    public void setFeatureConfig(FeatureConfig featureConfig) {
        this.featureConfig = featureConfig;
    }

    public static class FeatureConfig {
        private boolean accountSuspensionEnabled;
        private boolean sessionLimitingEnabled;
        private boolean loginTimeRestrictionEnabled;

        @XmlElement(name = "accountSuspensionFeature")
        public boolean isAccountSuspensionEnabled() {
            return accountSuspensionEnabled;
        }

        public void setAccountSuspensionEnabled(boolean accountSuspensionEnabled) {
            this.accountSuspensionEnabled = accountSuspensionEnabled;
        }

        @XmlElement(name = "sessionLimitingFeatrue")
        public boolean isSessionLimitingEnabled() {
            return sessionLimitingEnabled;
        }

        public void setSessionLimitingEnabled(boolean sessionLimitingEnabled) {
            this.sessionLimitingEnabled = sessionLimitingEnabled;
        }

        @XmlElement(name = "loginTimeRestrictionFeatrue")
        public boolean isLoginTimeRestrictionEnabled() {
            return loginTimeRestrictionEnabled;
        }

        public void setLoginTimeRestrictionEnabled(boolean loginTimeRestrictionEnabled) {
            this.loginTimeRestrictionEnabled = loginTimeRestrictionEnabled;
        }
    }

    public static class ErrorMessagesConfig {
        private String accountSuspendedMessage;
        private String sessionLimitExceededMessage;
        private String invalidCredentialsMessage;
        private String accountLockedMessage;
        private String loginTimeRestrictedMessage;
        private String unknownErrorMessage;

        @XmlElement(name = "accountSuspendedMessage")
        public String getAccountSuspendedMessage() {
            return accountSuspendedMessage;
        }

        public void setAccountSuspendedMessage(String accountSuspendedMessage) {
            this.accountSuspendedMessage = accountSuspendedMessage;
        }

        @XmlElement(name = "sessionLimitExceededMessage")
        public String getSessionLimitExceededMessage() {
            return sessionLimitExceededMessage;
        }

        public void setSessionLimitExceededMessage(String sessionLimitExceededMessage) {
            this.sessionLimitExceededMessage = sessionLimitExceededMessage;
        }

        @XmlElement(name = "invalidCredentialsMessage")
        public String getInvalidCredentialsMessage() {
            return invalidCredentialsMessage;
        }

        public void setInvalidCredentialsMessage(String invalidCredentialsMessage) {
            this.invalidCredentialsMessage = invalidCredentialsMessage;
        }

        @XmlElement(name = "accountLockedMessage")
        public String getAccountLockedMessage() {
            return accountLockedMessage;
        }

        public void setAccountLockedMessage(String accountLockedMessage) {
            this.accountLockedMessage = accountLockedMessage;
        }

        @XmlElement(name = "loginTimeRestrictedMessage")
        public String getLoginTimeRestrictedMessage() {
            return loginTimeRestrictedMessage;
        }

        public void setLoginTimeRestrictedMessage(String loginTimeRestrictedMessage) {
            this.loginTimeRestrictedMessage = loginTimeRestrictedMessage;
        }

        @XmlElement(name = "unknownErrorMessage")
        public String getUnknownErrorMessage() {
            return unknownErrorMessage;
        }

        public void setUnknownErrorMessage(String unknownErrorMessage) {
            this.unknownErrorMessage = unknownErrorMessage;
        }
    }

    public static class WorkingTime {
        String role;
        String startTime;
        String endTime;

        @XmlElement(name = "role")
        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }

        @XmlElement(name = "start")
        public String getStartTime() {
            return startTime;
        }

        public void setStartTime(String startTime) {
            this.startTime = startTime;
        }

        @XmlElement(name = "end")
        public String getEndTime() {
            return endTime;
        }

        public void setEndTime(String endTime) {
            this.endTime = endTime;
        }
    }
}