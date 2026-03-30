#!/usr/bin/env bash
# Generate hierCov-instrumented Verilog for Encarsia HierFuzz.
# Run this locally (not in Docker) before starting encarsia experiments.
#
# Prerequisites:
#   - Docker container "encarsia" running (or FIRRTL files already copied)
#   - firrtl2 built: firrtl2/utils/bin/firrtl
#   - scripts/firrtl3_to_1.py available
#
# Usage:
#   source ./env.sh
#   bash encarsia-meta/gen_hiercov.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/hiercov_build"
FIRRTL2="$PROJECT_DIR/firrtl2/utils/bin/firrtl"
CONVERT="$PROJECT_DIR/micro_rocket/micro_rocket_574/scripts/firrtl3_to_1.py"
PATCH_EXT="$SCRIPT_DIR/patch_extmodules.py"
GEN_RECEPTOR="$SCRIPT_DIR/gen_receptor.py"
PATCH_VERILOG_EXT="$SCRIPT_DIR/patch_verilog_extmodules.py"

mkdir -p "$BUILD_DIR"

# --- Rocket ---

ROCKET_FIR="$BUILD_DIR/rocket.fir"
if [ ! -f "$ROCKET_FIR" ]; then
    echo "Copying Rocket FIRRTL from Docker..."
    docker cp encarsia:/cascade-chipyard/sims/verilator/generated-src/chipyard.TestHarness.MyBigVMRocketConfig/chipyard.TestHarness.MyBigVMRocketConfig.top.fir "$ROCKET_FIR"
fi

ROCKET_V1="$BUILD_DIR/rocket_v1.fir"
if [ ! -f "$ROCKET_V1" ]; then
    echo "Converting Rocket FIRRTL 3→1..."
    python3 "$CONVERT" --input "$ROCKET_FIR" --output "$ROCKET_V1"
fi

ROCKET_LO="$BUILD_DIR/rocket.lo.fir"
if [ ! -f "$ROCKET_LO" ]; then
    echo "Lowering Rocket FIRRTL..."
    "$FIRRTL2" -td "$BUILD_DIR" -i "$ROCKET_V1" -X low -o rocket.lo.fir
fi

ROCKET_LO_PATCHED="$BUILD_DIR/rocket.lo.patched.fir"
if [ ! -f "$ROCKET_LO_PATCHED" ]; then
    echo "Patching Rocket extmodules (adding metaAssert/metaReset ports)..."
    python3 "$PATCH_EXT" --input "$ROCKET_LO" --output "$ROCKET_LO_PATCHED"
fi

ROCKET_HIERCOV="$BUILD_DIR/rocket_hiercov_v6a.v"
if [ ! -f "$ROCKET_HIERCOV" ]; then
    echo "Applying hierCov v6a to Rocket..."
    "$FIRRTL2" -td "$BUILD_DIR" -i "$ROCKET_LO_PATCHED" \
        -fct hier_cov.hierCoverage_v6a -X verilog -o rocket_hiercov_v6a.v
fi

ROCKET_GEN_DIR="/cascade-chipyard/sims/verilator/generated-src/chipyard.TestHarness.MyBigVMRocketConfig"

# Copy extmodule Verilog from Docker (same config as the .fir)
if [ ! -f "$BUILD_DIR/rocket_plusarg_reader.v" ]; then
    echo "Copying Rocket extmodule Verilog from Docker..."
    docker cp "encarsia:$ROCKET_GEN_DIR/plusarg_reader.v" "$BUILD_DIR/rocket_plusarg_reader.v"
    docker cp "encarsia:$ROCKET_GEN_DIR/chipyard.TestHarness.MyBigVMRocketConfig.top.mems.v" "$BUILD_DIR/rocket_mems.v"
    docker cp "encarsia:$ROCKET_GEN_DIR/ClockDividerN.sv" "$BUILD_DIR/rocket_ClockDividerN.sv" 2>/dev/null || true
fi

ROCKET_RECEPTOR="$BUILD_DIR/rocket_hiercov_receptor.v"
if [ ! -f "$ROCKET_RECEPTOR" ]; then
    echo "Generating Rocket hierCov receptor..."
    python3 "$GEN_RECEPTOR" "$ROCKET_HIERCOV" Rocket > "$ROCKET_RECEPTOR"
    # Append patched extmodule Verilog (with metaReset/metaAssert ports)
    python3 "$PATCH_VERILOG_EXT" "$BUILD_DIR/rocket_plusarg_reader.v" >> "$ROCKET_RECEPTOR"
    python3 "$PATCH_VERILOG_EXT" "$BUILD_DIR/rocket_mems.v" >> "$ROCKET_RECEPTOR"
    if [ -f "$BUILD_DIR/rocket_ClockDividerN.sv" ]; then
        python3 "$PATCH_VERILOG_EXT" "$BUILD_DIR/rocket_ClockDividerN.sv" >> "$ROCKET_RECEPTOR"
    fi
fi

# --- BOOM ---

BOOM_FIR="$BUILD_DIR/boom.fir"
if [ ! -f "$BOOM_FIR" ]; then
    echo "Copying BOOM FIRRTL from Docker..."
    docker cp encarsia:/cascade-chipyard/sims/verilator/generated-src/chipyard.TestHarness.MyMediumBoomConfigTracing/chipyard.TestHarness.MyMediumBoomConfigTracing.top.fir "$BOOM_FIR"
fi

BOOM_V1="$BUILD_DIR/boom_v1.fir"
if [ ! -f "$BOOM_V1" ]; then
    echo "Converting BOOM FIRRTL 3→1..."
    python3 "$CONVERT" --input "$BOOM_FIR" --output "$BOOM_V1"
fi

BOOM_LO="$BUILD_DIR/boom.lo.fir"
if [ ! -f "$BOOM_LO" ]; then
    echo "Lowering BOOM FIRRTL..."
    "$FIRRTL2" -td "$BUILD_DIR" -i "$BOOM_V1" -X low -o boom.lo.fir
fi

BOOM_LO_PATCHED="$BUILD_DIR/boom.lo.patched.fir"
if [ ! -f "$BOOM_LO_PATCHED" ]; then
    echo "Patching BOOM extmodules (adding metaAssert/metaReset ports)..."
    python3 "$PATCH_EXT" --input "$BOOM_LO" --output "$BOOM_LO_PATCHED"
fi

BOOM_HIERCOV="$BUILD_DIR/boom_hiercov_v6a.v"
if [ ! -f "$BOOM_HIERCOV" ]; then
    echo "Applying hierCov v6a to BOOM..."
    "$FIRRTL2" -td "$BUILD_DIR" -i "$BOOM_LO_PATCHED" \
        -fct hier_cov.hierCoverage_v6a -X verilog -o boom_hiercov_v6a.v
fi

BOOM_GEN_DIR="/cascade-chipyard/sims/verilator/generated-src/chipyard.TestHarness.MyMediumBoomConfigTracing"

# Copy extmodule Verilog from Docker (same config as the .fir)
if [ ! -f "$BUILD_DIR/boom_plusarg_reader.v" ]; then
    echo "Copying BOOM extmodule Verilog from Docker..."
    docker cp "encarsia:$BOOM_GEN_DIR/plusarg_reader.v" "$BUILD_DIR/boom_plusarg_reader.v"
    docker cp "encarsia:$BOOM_GEN_DIR/chipyard.TestHarness.MyMediumBoomConfigTracing.top.mems.v" "$BUILD_DIR/boom_mems.v"
    docker cp "encarsia:$BOOM_GEN_DIR/ClockDividerN.sv" "$BUILD_DIR/boom_ClockDividerN.sv" 2>/dev/null || true
fi

BOOM_RECEPTOR="$BUILD_DIR/boom_hiercov_receptor.v"
if [ ! -f "$BOOM_RECEPTOR" ]; then
    echo "Generating BOOM hierCov receptor..."
    python3 "$GEN_RECEPTOR" "$BOOM_HIERCOV" BoomCore > "$BOOM_RECEPTOR"
    # Append patched extmodule Verilog (with metaReset/metaAssert ports)
    python3 "$PATCH_VERILOG_EXT" "$BUILD_DIR/boom_plusarg_reader.v" >> "$BOOM_RECEPTOR"
    python3 "$PATCH_VERILOG_EXT" "$BUILD_DIR/boom_mems.v" >> "$BOOM_RECEPTOR"
    if [ -f "$BUILD_DIR/boom_ClockDividerN.sv" ]; then
        python3 "$PATCH_VERILOG_EXT" "$BUILD_DIR/boom_ClockDividerN.sv" >> "$BOOM_RECEPTOR"
    fi
fi

echo ""
echo "Done! HierCov artifacts in: $BUILD_DIR"
echo "  Rocket: rocket_hiercov_v6a.v, rocket_hiercov_receptor.v"
echo "  BOOM:   boom_hiercov_v6a.v,   boom_hiercov_receptor.v"
echo ""
echo "Mount into Docker with:"
echo "  -v $BUILD_DIR:/encarsia-hierfuzz/hiercov_build"
