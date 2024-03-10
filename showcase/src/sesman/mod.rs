mod protogen;

pub mod client;
pub mod server;

const GRPC_URL: &str = "http://127.0.0.1:14514";
const DB_PATH: &str = "/dev/shm/mpc_eddsa";

const SQL_CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS messages (
    topic TEXT NOT NULL,
    src INT NOT NULL,
    dst INT NOT NULL,
    obj BLOB DEFAULT NULL,
    primary key (topic, src, dst)
);
"#;

const SQL_INSERT: &str = r#"
INSERT INTO messages (topic, src, dst, obj)
VALUES (?, ?, ?, ?)
"#;

const SQL_SELECT: &str = r#"
SELECT obj FROM messages
WHERE topic = ? AND src = ? AND dst = ?
"#;
