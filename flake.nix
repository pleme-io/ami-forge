{
  description = "ami-forge — Rust CLI for AMI build pipeline";

  inputs.substrate.url = "github:pleme-io/substrate";

  outputs = { substrate, ... }: substrate.rust.tool {
    src = ./.;
    member = "ami-forge";
  };
}
