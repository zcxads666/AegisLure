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

# Keep the marketing surface truthful for a single-node synthetic tenant.
replace_text "$stage_root/src/features/home/components/sections/stats.tsx" \
  "{ end: 50, suffix: '+', label: t('upstream services integrated') },\n    { end: 100, suffix: '+', label: t('model billing support') },\n    { end: 50, suffix: '+', label: t('compatible API routes') },\n    { end: 10, suffix: '+', label: t('scheduling controls') }," \
  "{ end: 3, suffix: '', label: t('local synthetic protocols') },\n    { end: 1, suffix: '', label: t('single-node tenant') },\n    { end: 4, suffix: '', label: t('local dashboard surfaces') },\n    { end: 0, suffix: '', label: t('external channels enabled') },"
replace_text "$stage_root/src/features/home/components/sections/how-it-works.tsx" \
  "Add your API keys, set up channels and configure access permissions" \
  "Create a scoped API key and choose a catalog model"
replace_text "$stage_root/src/features/home/components/sections/how-it-works.tsx" \
  "Connect through OpenAI, Claude, Gemini, and other compatible API routes" \
  "Call the local synthetic endpoint with OpenAI, Claude, or Gemini-compatible formats"
replace_text "$stage_root/src/features/home/components/sections/how-it-works.tsx" \
  "Track usage, costs and performance with real-time analytics" \
  "Review local quota and request events in the usage logs"
replace_text "$stage_root/src/features/home/components/sections/cta.tsx" \
  "Deploy your own gateway and start routing requests through your configured upstream services." \
  "Start with a local synthetic response, then inspect the recorded usage event."
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "gpt-4.1-mini" "gpt-5.6-sol"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "Start routing traffic" "Get a synthetic response"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "Add credits" "Review virtual quota"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "Keep enough balance before production traffic" "Review the virtual quota before making requests"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "Verify routing with Playground or your client" "Send a request from your client"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "'/wallet'" "'/profile'"
replace_text "$stage_root/src/features/dashboard/components/overview/overview-dashboard.tsx" \
  "'/playground'" "'/usage-logs'"
replace_text "$stage_root/src/features/dashboard/components/overview/summary-cards.tsx" \
  "render={<Link to='/wallet' />}" "render={<Link to='/profile' />}"
replace_text "$stage_root/src/features/dashboard/components/overview/summary-cards.tsx" \
  "{t('Wallet')}" "{t('Profile')}"
replace_text "$stage_root/src/features/home/components/sections/features.tsx" \
  "Transparent Billing" "Local Usage Metering"
replace_text "$stage_root/src/features/home/components/sections/features.tsx" \
  "Pay-as-you-go with real-time usage monitoring" "Synthetic usage records with quota accounting"
replace_text "$stage_root/src/features/home/components/sections/features.tsx" \
  "Team Collaboration" "Single-node Isolation"
replace_text "$stage_root/src/features/home/components/sections/features.tsx" \
  "Multi-user management with flexible permission allocation" "One local tenant with no administrative surface"

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

# Payment/vendor artwork is not part of the standalone tenant. The build
# output is still the complete upstream-derived UI, with unsafe navigation
# hidden by the override and rejected by the Go profile router.
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
Source checkout: $source_root
Standalone overrides: $script_dir/newapi-overrides
Built by: $script_dir/build-newapi-web.sh
EOF

echo "Embedded artifact written to $artifact_root"
