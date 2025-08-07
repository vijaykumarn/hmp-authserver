package io.vikunalabs.hmp.auth.shared.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@ConfigurationProperties(prefix = "app.session")
@Component
public class SessionProperties {
    private Timeout timeout = new Timeout();
    private int maxConcurrent = 3;
    private boolean requireSameIp = true;
    private boolean detectUserAgentChange = true;
    
    @Data
    public static class Timeout {
        private int defaultSeconds = 3600;
        private int rememberMeSeconds = 2592000;
    }
}
