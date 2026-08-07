// Builds the guest to a RISC-V ELF; its hash is the verification key. The remap strips the
// machine's $CARGO_HOME from dependency panic paths.
fn main() {
    let cargo_home = std::env::var("CARGO_HOME")
        .unwrap_or_else(|_| format!("{}/.cargo", std::env::var("HOME").unwrap()));
    sp1_build::build_program_with_args(
        "../guest",
        sp1_build::BuildArgs {
            rustflags: vec![format!("--remap-path-prefix={cargo_home}=/cargo")],
            locked: true,
            ..Default::default()
        },
    );
}
