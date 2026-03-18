/// Integration tests for the middleware pipeline.
///
/// Run with: `cargo test`
/// These tests exercise the auth, ACL, and rate-limit logic in isolation,
/// without starting a real Pingora server. For full end-to-end tests,
/// use the docker-compose stack and send HTTP requests via `reqwest`.

#[cfg(test)]
mod auth_tests {
    use pingora_middleware::auth::{has_role, required_roles_for_path, validate_jwt};

    #[test]
    fn valid_jwt_parses_claims() {
        // Generate a token signed with the test secret
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use serde_json::json;

        std::env::set_var("JWT_SECRET", "test-secret");

        let claims = json!({
            "sub": "user-123",
            "roles": ["user"],
            "exp": 9999999999u64,
        });

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap();

        let header = format!("Bearer {token}");
        let result = validate_jwt(&header);
        assert!(result.is_ok(), "expected valid JWT: {:?}", result.err());
        assert_eq!(result.unwrap().sub, "user-123");
    }

    #[test]
    fn missing_bearer_prefix_rejected() {
        let result = validate_jwt("some-raw-token");
        assert!(result.is_err());
    }

    #[test]
    fn expired_token_rejected() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use serde_json::json;

        std::env::set_var("JWT_SECRET", "test-secret");

        let claims = json!({
            "sub": "user-456",
            "roles": ["user"],
            "exp": 1u64,   // already expired
        });
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap();

        let result = validate_jwt(&format!("Bearer {token}"));
        assert!(result.is_err());
    }

    #[test]
    fn acl_admin_path_requires_admin_role() {
        let required = required_roles_for_path("/api/admin/users");
        assert!(required.is_some());

        let user_roles = vec!["user".to_string()];
        assert!(!has_role(&user_roles, required.unwrap()));

        let admin_roles = vec!["admin".to_string()];
        assert!(has_role(&admin_roles, required.unwrap()));
    }

    #[test]
    fn acl_internal_path_allows_service_role() {
        let required = required_roles_for_path("/api/internal/sync");
        assert!(required.is_some());

        let svc_roles = vec!["service".to_string()];
        assert!(has_role(&svc_roles, required.unwrap()));
    }

    #[test]
    fn acl_public_path_has_no_role_requirement() {
        let required = required_roles_for_path("/api/v1/products");
        assert!(required.is_none());
    }
}

#[cfg(test)]
mod canary_tests {
    use pingora_middleware::loadbalancer::canary_peer;

    #[test]
    fn same_user_always_gets_same_canary_decision() {
        let addr = "canary:8080";
        let result1 = canary_peer("user-stable", addr, 0.5);
        let result2 = canary_peer("user-stable", addr, 0.5);
        assert_eq!(result1, result2, "canary routing must be deterministic");
    }

    #[test]
    fn zero_fraction_never_canaries() {
        for i in 0..100 {
            let uid = format!("user-{i}");
            assert!(canary_peer(&uid, "canary:8080", 0.0).is_none());
        }
    }

    #[test]
    fn full_fraction_always_canaries() {
        for i in 0..100 {
            let uid = format!("user-{i}");
            assert!(canary_peer(&uid, "canary:8080", 1.0).is_some());
        }
    }
}
