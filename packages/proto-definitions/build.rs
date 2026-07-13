use std::io::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=network_event.proto");
    println!("cargo:rerun-if-changed=proto/telemetry.proto");

    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().expect("protoc vendored"),
    );

    let mut config = prost_build::Config::new();
    config.compile_protos(&["network_event.proto", "proto/telemetry.proto"], &["."])?;
    Ok(())
}
