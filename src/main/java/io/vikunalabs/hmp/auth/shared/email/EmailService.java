package io.vikunalabs.hmp.auth.shared.email;

import java.util.Map;

public interface EmailService {
    void sendEmail(String to, String subject, String templateName, Map<String, Object> templateModel);
}
