{
  description = "trill: stream PipeWire audio from Linux to a phone over Wi-Fi";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      libs = pkgs: with pkgs; [
        pipewire
        roc-toolkit
        openssl
        avahi
        asio
        nlohmann_json
        spdlog
        cli11
        tomlplusplus
      ];
    in {
      packages = forAllSystems (pkgs: {
        default = pkgs.stdenv.mkDerivation {
          pname = "trill";
          version = "0.1.0";
          src = self;
          sourceRoot = "source/server";
          nativeBuildInputs = with pkgs; [ cmake ninja pkg-config ];
          buildInputs = libs pkgs ++ [ pkgs.gtest ];
          cmakeFlags = [ "-DTRILL_BUILD_TESTS=OFF" ];
          meta = {
            description = "Stream PipeWire audio to a phone over Wi-Fi";
            license = pkgs.lib.licenses.mit;
            mainProgram = "trill";
            platforms = pkgs.lib.platforms.linux;
          };
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          name = "trill-server";
          nativeBuildInputs = with pkgs; [
            cmake ninja pkg-config ccache
            clang-tools          # clangd, clang-format, clang-tidy
            gdb valgrind
          ];
          buildInputs = libs pkgs ++ [ pkgs.gtest ];
          packages = with pkgs; [
            pipewire             # pw-cli pw-dump pw-top pw-link pw-metadata
            wireplumber          # wpctl
            avahi                # avahi-browse
            roc-toolkit          # roc-send roc-recv roc-copy
            iproute2             # tc netem for loss tests
            socat jq sox openssl
            (python3.withPackages (ps: [ ps.cryptography ]))
          ];
          shellHook = ''
            export CMAKE_GENERATOR=Ninja
            export CMAKE_EXPORT_COMPILE_COMMANDS=ON
            echo "trill server shell. Configure: cmake -S server -B build --preset debug"
          '';
        };

        # Helper tools for the Android side (Android Studio/SDK installed separately).
        android = pkgs.mkShell {
          name = "trill-android-tools";
          packages = with pkgs; [
            jdk17 gradle android-tools   # adb
            roc-toolkit                  # roc-send for FakeHost / manual tests
            openssl jq
            (python3.withPackages (ps: [ ps.cryptography ]))
          ];
        };
      });

      nixosModules.default = { config, lib, pkgs, ... }:
        let cfg = config.services.trill; in {
          options.services.trill = {
            enable = lib.mkEnableOption "trill daemon (PipeWire audio to phone)";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
            };
            port = lib.mkOption { type = lib.types.port; default = 47800; };
            openFirewall = lib.mkOption { type = lib.types.bool; default = true; };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];
            services.avahi = {
              enable = true;
              publish.enable = true;
              publish.userServices = true;
              openFirewall = true;
            };
            networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
            systemd.user.services.trilld = {
              description = "trill daemon";
              wantedBy = [ "default.target" ];
              after = [ "pipewire.service" ];
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/trilld";
                Restart = "on-failure";
              };
            };
          };
        };
    };
}
