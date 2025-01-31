CREATE TABLE IF NOT EXISTS clients (
    id                TEXT      PRIMARY KEY,
    enabled           BOOLEAN   DEFAULT TRUE,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP
);

CREATE TABLE IF NOT EXISTS public_keys (
    key               BLOB      PRIMARY KEY,
    client_id         TEXT      NOT NULL,
    enabled           BOOLEAN   DEFAULT TRUE,
    last_connected_at TIMESTAMP,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP,

    FOREIGN KEY (client_id) REFERENCES clients(id)
);
