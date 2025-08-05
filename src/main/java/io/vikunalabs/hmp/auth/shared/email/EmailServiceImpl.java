package io.vikunalabs.hmp.auth.shared.email;

import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class EmailServiceImpl implements EmailService {
    @Override
    public void sendEmail(String to, String subject, String templateName, Map<String, Object> templateModel) {
        log.info("Sending email to {}", to);
    }
}
