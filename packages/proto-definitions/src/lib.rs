//! Versioned Protobuf contracts for Neuromesh telemetry ingestion.

pub mod neuromesh {
    pub mod telemetry {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/neuromesh.telemetry.v1.rs"));
        }
    }
}

pub use neuromesh::telemetry::v1::EnrichedNetworkEvent;

pub const ENRICHED_NETWORK_EVENT_SCHEMA_VERSION: u32 = 1;
