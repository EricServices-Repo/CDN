-- Run once after 20261102_cdn_bash_nodes.sql. Back up before upgrading.
ALTER TABLE cdn_bash_domains ADD COLUMN policy_json MEDIUMTEXT NULL;
ALTER TABLE cdn_bash_nodes ADD COLUMN published_state MEDIUMTEXT NULL, ADD COLUMN deployment_id BIGINT UNSIGNED NULL, ADD COLUMN agent_version INT UNSIGNED NOT NULL DEFAULT 2, ADD COLUMN last_probe_at DATETIME NULL;
CREATE TABLE cdn_bash_deployments (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(120) NOT NULL,
    actor VARCHAR(100) NOT NULL,
    status ENUM('draft','canary','published','rolled_back') NOT NULL DEFAULT 'draft',
    canary_node VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE cdn_bash_snapshots (
    deployment_id BIGINT UNSIGNED NOT NULL,
    node_id VARCHAR(64) NOT NULL,
    desired_json MEDIUMTEXT NOT NULL,
    previous_json MEDIUMTEXT NOT NULL,
    previous_deployment_id BIGINT UNSIGNED NULL,
    activated TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY(deployment_id,node_id),
    FOREIGN KEY(deployment_id) REFERENCES cdn_bash_deployments(id),
    FOREIGN KEY(node_id) REFERENCES cdn_bash_nodes(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE cdn_bash_metric_history (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    node_id VARCHAR(64) NOT NULL,
    hostname VARCHAR(253) NOT NULL,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    interval_seconds INT UNSIGNED NOT NULL,
    requests BIGINT UNSIGNED NOT NULL,
    bytes BIGINT UNSIGNED NOT NULL,
    hits BIGINT UNSIGNED NOT NULL,
    errors BIGINT UNSIGNED NOT NULL,
    origin_latency_ms DOUBLE NOT NULL,
    KEY history_node_time(node_id,received_at),
    KEY history_time(received_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE cdn_bash_alerts (
    fingerprint CHAR(64) PRIMARY KEY,
    node_id VARCHAR(64) NOT NULL,
    kind VARCHAR(50) NOT NULL,
    severity ENUM('warning','critical') NOT NULL,
    message VARCHAR(255) NOT NULL,
    opened_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,
    acknowledged_at DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE cdn_bash_probes (
    node_id VARCHAR(64) NOT NULL,
    hostname VARCHAR(253) NOT NULL,
    checked_at DATETIME NOT NULL,
    status_code INT NOT NULL,
    revision VARCHAR(64) NOT NULL,
    latency_ms DOUBLE NOT NULL,
    failures INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY(node_id,hostname)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE cdn_bash_settings (
    name VARCHAR(64) PRIMARY KEY,
    value VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT INTO cdn_bash_settings(name,value) VALUES ('deployment_ready','0');
