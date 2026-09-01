#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
source_root="${NEWAPI_WEB_SOURCE:-/Volumes/1/code/newapi/web}"
artifact_root="$project_root/internal/app/ui/newapi-dist"
stage_root="$(mktemp -d /tmp/aegislure-newapi.XXXXXX)"

cleanup() {
  rm -rf "$stage_root"
}
trap cleanup EXIT

if [[ ! -d "$source_root/src" || ! -d "$source_root/node_modules" ]]; then
  echo "New API web source or node_modules not found: $source_root" >&2
  exit 1
fi

echo "Staging New API web source from $source_root"
rsync -a --exclude '.git' --exclude 'node_modules' --exclude 'dist' \
  "$source_root/" "$stage_root/"
ln -s "$source_root/node_modules" "$stage_root/node_modules"

# The override tree is intentionally kept in this repository so the embedded
# artifact can be rebuilt without editing the separately maintained source
# checkout or importing its server/data plane.
if [[ -d "$script_dir/newapi-overrides/src" ]]; then
  rsync -a "$script_dir/newapi-overrides/src/" "$stage_root/src/"
fi

replace_text() {
  local file="$1"
  local old_text="$2"
  local new_text="$3"
  AEGISLURE_OLD_TEXT="$old_text" AEGISLURE_NEW_TEXT="$new_text" \
    perl -0pi -e 's/\Q$ENV{AEGISLURE_OLD_TEXT}\E/$ENV{AEGISLURE_NEW_TEXT}/g' "$file"
}

# Keep restricted account actions on pages that are available to the public
# tenant, while preserving the upstream page copy and layout.
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "title: t('Add credits')" "title: t('Profile')"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "description: t('Keep enough balance before production traffic')" \
  "description: t('Personal settings and profile management.')"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "title: t('Send a request')" "title: t('Usage Logs')"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "description: t('Verify routing with Playground or your client')" \
  "description: t('Review your recent requests')"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "'Start routing traffic'" "'Send a request'"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "'/wallet'" "'/profile'"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "'/playground'" "'/usage-logs'"
replace_text "$stage_root/src/features/dashboard/components/overview/summary-cards.tsx" \
  "render={<Link to='/wallet' />}" "render={<Link to='/profile' />}"
replace_text "$stage_root/src/features/dashboard/components/overview/summary-cards.tsx" \
  "{t('Wallet')}" "{t('Profile')}"
# The upstream mobile drawer hard-codes a wallet link. Remove that link and
# its now-unused icon from the staged copy.
mobile_drawer="$stage_root/src/components/layout/components/mobile-drawer.tsx"
perl -0pi -e 's/, Wallet//' "$mobile_drawer"
perl -0pi -e 's{\n        <Link\n          to='\''/wallet'\''.*?\n        </Link>}{}s' "$mobile_drawer"

source_commit="$(git -C "$source_root" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
echo "Building New API web commit $source_commit"
(
  cd "$stage_root"
  pnpm build
)

# Payment/vendor artwork is not part of the embedded build. The output is
# still the complete upstream-derived UI, with restricted navigation hidden
# by the override and rejected by the Go profile router.
find "$stage_root/dist" -type f \( \
  -name 'pay-apple.png' -o -name 'pay-card.png' -o -name 'pay-google.png' \
  -o -name 'waffo-logo-light.svg' -o -name 'waffo-logo-dark.svg' \
\) -delete

rm -rf "$artifact_root"
mkdir -p "$artifact_root"
cp -a "$stage_root/dist/." "$artifact_root/"
# Keep generated text diff-friendly without touching binary fonts or images.
find "$artifact_root" -type f \( -name '*.css' -o -name '*.html' -o -name '*.js' \) \
  -exec perl -pi -e 's/[ \t]+$//' {} +
cat > "$artifact_root/SOURCE.txt" <<EOF
New API web source commit: $source_commit
Source: https://github.com/QuantumNous/new-api
EOF

echo "Embedded artifact written to $artifact_root"
