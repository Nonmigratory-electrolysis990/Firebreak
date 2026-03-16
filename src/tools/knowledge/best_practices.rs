use crate::mcp::protocol::ToolCallResult;

struct BestPractice {
    topic: &'static str,
    content: &'static str,
}

static PRACTICES: &[BestPractice] = &[
    // === Original 17 topics ===
    BestPractice {
        topic: "jwt-auth",
        content: include_str!("../../../knowledge/best-practices/jwt-auth.md"),
    },
    BestPractice {
        topic: "rls-policy",
        content: include_str!("../../../knowledge/best-practices/rls-policy.md"),
    },
    BestPractice {
        topic: "file-upload",
        content: include_str!("../../../knowledge/best-practices/file-upload.md"),
    },
    BestPractice {
        topic: "cors",
        content: include_str!("../../../knowledge/best-practices/cors.md"),
    },
    BestPractice {
        topic: "rate-limiting",
        content: include_str!("../../../knowledge/best-practices/rate-limiting.md"),
    },
    BestPractice {
        topic: "password-storage",
        content: include_str!("../../../knowledge/best-practices/password-storage.md"),
    },
    BestPractice {
        topic: "input-validation",
        content: include_str!("../../../knowledge/best-practices/input-validation.md"),
    },
    BestPractice {
        topic: "session-management",
        content: include_str!("../../../knowledge/best-practices/session-management.md"),
    },
    BestPractice {
        topic: "api-auth",
        content: include_str!("../../../knowledge/best-practices/api-auth.md"),
    },
    BestPractice {
        topic: "error-handling",
        content: include_str!("../../../knowledge/best-practices/error-handling.md"),
    },
    BestPractice {
        topic: "database-security",
        content: include_str!("../../../knowledge/best-practices/database-security.md"),
    },
    BestPractice {
        topic: "docker-security",
        content: include_str!("../../../knowledge/best-practices/docker-security.md"),
    },
    BestPractice {
        topic: "oauth-security",
        content: include_str!("../../../knowledge/best-practices/oauth-security.md"),
    },
    BestPractice {
        topic: "websocket-security",
        content: include_str!("../../../knowledge/best-practices/websocket-security.md"),
    },
    BestPractice {
        topic: "logging-security",
        content: include_str!("../../../knowledge/best-practices/logging-security.md"),
    },
    BestPractice {
        topic: "dependency-management",
        content: include_str!("../../../knowledge/best-practices/dependency-management.md"),
    },
    BestPractice {
        topic: "secrets-management",
        content: include_str!("../../../knowledge/best-practices/secrets-management.md"),
    },
    // === Batch 1: Vulnerability & Protocol topics (20) ===
    BestPractice {
        topic: "xss-prevention",
        content: include_str!("../../../knowledge/best-practices/xss-prevention.md"),
    },
    BestPractice {
        topic: "sql-injection",
        content: include_str!("../../../knowledge/best-practices/sql-injection.md"),
    },
    BestPractice {
        topic: "csrf-protection",
        content: include_str!("../../../knowledge/best-practices/csrf-protection.md"),
    },
    BestPractice {
        topic: "ssrf-prevention",
        content: include_str!("../../../knowledge/best-practices/ssrf-prevention.md"),
    },
    BestPractice {
        topic: "command-injection",
        content: include_str!("../../../knowledge/best-practices/command-injection.md"),
    },
    BestPractice {
        topic: "path-traversal",
        content: include_str!("../../../knowledge/best-practices/path-traversal.md"),
    },
    BestPractice {
        topic: "deserialization",
        content: include_str!("../../../knowledge/best-practices/deserialization.md"),
    },
    BestPractice {
        topic: "xml-security",
        content: include_str!("../../../knowledge/best-practices/xml-security.md"),
    },
    BestPractice {
        topic: "graphql-security",
        content: include_str!("../../../knowledge/best-practices/graphql-security.md"),
    },
    BestPractice {
        topic: "websocket-auth",
        content: include_str!("../../../knowledge/best-practices/websocket-auth.md"),
    },
    BestPractice {
        topic: "http-headers",
        content: include_str!("../../../knowledge/best-practices/http-headers.md"),
    },
    BestPractice {
        topic: "cookie-security",
        content: include_str!("../../../knowledge/best-practices/cookie-security.md"),
    },
    BestPractice {
        topic: "tls-configuration",
        content: include_str!("../../../knowledge/best-practices/tls-configuration.md"),
    },
    BestPractice {
        topic: "dns-security",
        content: include_str!("../../../knowledge/best-practices/dns-security.md"),
    },
    BestPractice {
        topic: "email-security",
        content: include_str!("../../../knowledge/best-practices/email-security.md"),
    },
    BestPractice {
        topic: "file-inclusion",
        content: include_str!("../../../knowledge/best-practices/file-inclusion.md"),
    },
    BestPractice {
        topic: "clickjacking",
        content: include_str!("../../../knowledge/best-practices/clickjacking.md"),
    },
    BestPractice {
        topic: "cache-security",
        content: include_str!("../../../knowledge/best-practices/cache-security.md"),
    },
    BestPractice {
        topic: "redirect-security",
        content: include_str!("../../../knowledge/best-practices/redirect-security.md"),
    },
    BestPractice {
        topic: "subdomain-security",
        content: include_str!("../../../knowledge/best-practices/subdomain-security.md"),
    },
    // === Batch 2: Framework & Platform topics (20) ===
    BestPractice {
        topic: "nextjs-security",
        content: include_str!("../../../knowledge/best-practices/nextjs-security.md"),
    },
    BestPractice {
        topic: "supabase-security",
        content: include_str!("../../../knowledge/best-practices/supabase-security.md"),
    },
    BestPractice {
        topic: "express-security",
        content: include_str!("../../../knowledge/best-practices/express-security.md"),
    },
    BestPractice {
        topic: "django-security",
        content: include_str!("../../../knowledge/best-practices/django-security.md"),
    },
    BestPractice {
        topic: "flask-security",
        content: include_str!("../../../knowledge/best-practices/flask-security.md"),
    },
    BestPractice {
        topic: "rails-security",
        content: include_str!("../../../knowledge/best-practices/rails-security.md"),
    },
    BestPractice {
        topic: "react-security",
        content: include_str!("../../../knowledge/best-practices/react-security.md"),
    },
    BestPractice {
        topic: "vue-security",
        content: include_str!("../../../knowledge/best-practices/vue-security.md"),
    },
    BestPractice {
        topic: "angular-security",
        content: include_str!("../../../knowledge/best-practices/angular-security.md"),
    },
    BestPractice {
        topic: "svelte-security",
        content: include_str!("../../../knowledge/best-practices/svelte-security.md"),
    },
    BestPractice {
        topic: "aws-security",
        content: include_str!("../../../knowledge/best-practices/aws-security.md"),
    },
    BestPractice {
        topic: "gcp-security",
        content: include_str!("../../../knowledge/best-practices/gcp-security.md"),
    },
    BestPractice {
        topic: "azure-security",
        content: include_str!("../../../knowledge/best-practices/azure-security.md"),
    },
    BestPractice {
        topic: "kubernetes-security",
        content: include_str!("../../../knowledge/best-practices/kubernetes-security.md"),
    },
    BestPractice {
        topic: "terraform-security",
        content: include_str!("../../../knowledge/best-practices/terraform-security.md"),
    },
    BestPractice {
        topic: "ci-cd-security",
        content: include_str!("../../../knowledge/best-practices/ci-cd-security.md"),
    },
    BestPractice {
        topic: "mobile-api-security",
        content: include_str!("../../../knowledge/best-practices/mobile-api-security.md"),
    },
    BestPractice {
        topic: "microservices-security",
        content: include_str!("../../../knowledge/best-practices/microservices-security.md"),
    },
    BestPractice {
        topic: "serverless-security",
        content: include_str!("../../../knowledge/best-practices/serverless-security.md"),
    },
    BestPractice {
        topic: "jamstack-security",
        content: include_str!("../../../knowledge/best-practices/jamstack-security.md"),
    },
    // === Batch 3: Auth, Ops & Compliance topics (20) ===
    BestPractice {
        topic: "password-reset",
        content: include_str!("../../../knowledge/best-practices/password-reset.md"),
    },
    BestPractice {
        topic: "mfa-implementation",
        content: include_str!("../../../knowledge/best-practices/mfa-implementation.md"),
    },
    BestPractice {
        topic: "rbac-implementation",
        content: include_str!("../../../knowledge/best-practices/rbac-implementation.md"),
    },
    BestPractice {
        topic: "api-versioning",
        content: include_str!("../../../knowledge/best-practices/api-versioning.md"),
    },
    BestPractice {
        topic: "webhook-security",
        content: include_str!("../../../knowledge/best-practices/webhook-security.md"),
    },
    BestPractice {
        topic: "payment-security",
        content: include_str!("../../../knowledge/best-practices/payment-security.md"),
    },
    BestPractice {
        topic: "search-security",
        content: include_str!("../../../knowledge/best-practices/search-security.md"),
    },
    BestPractice {
        topic: "upload-validation",
        content: include_str!("../../../knowledge/best-practices/upload-validation.md"),
    },
    BestPractice {
        topic: "image-processing",
        content: include_str!("../../../knowledge/best-practices/image-processing.md"),
    },
    BestPractice {
        topic: "pdf-generation",
        content: include_str!("../../../knowledge/best-practices/pdf-generation.md"),
    },
    BestPractice {
        topic: "cron-job-security",
        content: include_str!("../../../knowledge/best-practices/cron-job-security.md"),
    },
    BestPractice {
        topic: "backup-security",
        content: include_str!("../../../knowledge/best-practices/backup-security.md"),
    },
    BestPractice {
        topic: "incident-response",
        content: include_str!("../../../knowledge/best-practices/incident-response.md"),
    },
    BestPractice {
        topic: "penetration-testing",
        content: include_str!("../../../knowledge/best-practices/penetration-testing.md"),
    },
    BestPractice {
        topic: "compliance-basics",
        content: include_str!("../../../knowledge/best-practices/compliance-basics.md"),
    },
    BestPractice {
        topic: "encryption-at-rest",
        content: include_str!("../../../knowledge/best-practices/encryption-at-rest.md"),
    },
    BestPractice {
        topic: "encryption-in-transit",
        content: include_str!("../../../knowledge/best-practices/encryption-in-transit.md"),
    },
    BestPractice {
        topic: "key-management",
        content: include_str!("../../../knowledge/best-practices/key-management.md"),
    },
    BestPractice {
        topic: "content-security-policy",
        content: include_str!("../../../knowledge/best-practices/content-security-policy.md"),
    },
    BestPractice {
        topic: "feature-flags",
        content: include_str!("../../../knowledge/best-practices/feature-flags.md"),
    },
    // === Batch 4: Infrastructure, Advanced Auth & Emerging topics (23) ===
    BestPractice {
        topic: "redis-security",
        content: include_str!("../../../knowledge/best-practices/redis-security.md"),
    },
    BestPractice {
        topic: "elasticsearch-security",
        content: include_str!("../../../knowledge/best-practices/elasticsearch-security.md"),
    },
    BestPractice {
        topic: "rabbitmq-security",
        content: include_str!("../../../knowledge/best-practices/rabbitmq-security.md"),
    },
    BestPractice {
        topic: "grpc-security",
        content: include_str!("../../../knowledge/best-practices/grpc-security.md"),
    },
    BestPractice {
        topic: "rest-api-design",
        content: include_str!("../../../knowledge/best-practices/rest-api-design.md"),
    },
    BestPractice {
        topic: "single-sign-on",
        content: include_str!("../../../knowledge/best-practices/single-sign-on.md"),
    },
    BestPractice {
        topic: "token-refresh",
        content: include_str!("../../../knowledge/best-practices/token-refresh.md"),
    },
    BestPractice {
        topic: "ip-allowlisting",
        content: include_str!("../../../knowledge/best-practices/ip-allowlisting.md"),
    },
    BestPractice {
        topic: "data-masking",
        content: include_str!("../../../knowledge/best-practices/data-masking.md"),
    },
    BestPractice {
        topic: "rate-limiting-advanced",
        content: include_str!("../../../knowledge/best-practices/rate-limiting-advanced.md"),
    },
    BestPractice {
        topic: "cors-advanced",
        content: include_str!("../../../knowledge/best-practices/cors-advanced.md"),
    },
    BestPractice {
        topic: "third-party-scripts",
        content: include_str!("../../../knowledge/best-practices/third-party-scripts.md"),
    },
    BestPractice {
        topic: "browser-storage",
        content: include_str!("../../../knowledge/best-practices/browser-storage.md"),
    },
    BestPractice {
        topic: "webauthn-passkeys",
        content: include_str!("../../../knowledge/best-practices/webauthn-passkeys.md"),
    },
    BestPractice {
        topic: "jwt-advanced",
        content: include_str!("../../../knowledge/best-practices/jwt-advanced.md"),
    },
    BestPractice {
        topic: "graphql-federation",
        content: include_str!("../../../knowledge/best-practices/graphql-federation.md"),
    },
    BestPractice {
        topic: "database-migration",
        content: include_str!("../../../knowledge/best-practices/database-migration.md"),
    },
    BestPractice {
        topic: "monitoring-alerting",
        content: include_str!("../../../knowledge/best-practices/monitoring-alerting.md"),
    },
    BestPractice {
        topic: "zero-trust",
        content: include_str!("../../../knowledge/best-practices/zero-trust.md"),
    },
    BestPractice {
        topic: "supply-chain",
        content: include_str!("../../../knowledge/best-practices/supply-chain.md"),
    },
    BestPractice {
        topic: "chatbot-security",
        content: include_str!("../../../knowledge/best-practices/chatbot-security.md"),
    },
    BestPractice {
        topic: "ai-integration",
        content: include_str!("../../../knowledge/best-practices/ai-integration.md"),
    },
    BestPractice {
        topic: "regex-security",
        content: include_str!("../../../knowledge/best-practices/regex-security.md"),
    },
];

pub fn best_practice(topic: &str) -> ToolCallResult {
    let normalized = topic.trim().to_lowercase();

    if let Some(practice) = PRACTICES.iter().find(|p| p.topic == normalized) {
        return super::text_result(practice.content);
    }

    let available: Vec<&str> = PRACTICES.iter().map(|p| p.topic).collect();
    super::error_result(&format!(
        "Unknown topic '{}'. Available topics: {}",
        topic,
        available.join(", ")
    ))
}
