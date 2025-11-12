sudo install -d -m 755 /opt/zso
sudo tee /opt/zso/schema.sql >/dev/null <<'SQL'
CREATE DATABASE IF NOT EXISTS zso
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE zso;

DROP TABLE IF EXISTS webauthn_credentials;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id           CHAR(36)       NOT NULL,
  email        VARCHAR(255)   NOT NULL,
  user_handle  VARBINARY(32)  NOT NULL,
  created_at   TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email),
  UNIQUE KEY uq_users_user_handle (user_handle)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE webauthn_credentials (
  credential_id    VARBINARY(255)  NOT NULL,
  user_id          CHAR(36)        NOT NULL,
  public_key       BLOB            NOT NULL,
  sign_count       BIGINT UNSIGNED NOT NULL DEFAULT 0,
  created_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at     TIMESTAMP NULL DEFAULT NULL,
  PRIMARY KEY (credential_id),
  KEY idx_wac_user_id (user_id),
  CONSTRAINT fk_wac_user
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SQL
