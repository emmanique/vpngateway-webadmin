#!/usr/bin/env bash
# Roll back only the per-host temporary VPN trial. Existing DIRECT policy is untouched.
set -u
host="${1:?}" lan="${2:?}" table="${3:?}" priority="${4:?}"
for tag in outgoing incoming; do
  handles=$(nft -a list chain ip filter DOCKER-USER 2>/dev/null | awk -v tag="vpngw_trial_${tag}" '$0 ~ tag {for(i=1;i<=NF;i++)if($i=="handle") print $(i+1)}')
  for h in $handles; do nft delete rule ip filter DOCKER-USER handle "$h" || :; done
done
ip -4 rule del pref "$priority" iif "$lan" from "$host/32" lookup "$table" 2>/dev/null || :
ip -4 route flush table "$table" 2>/dev/null || :
nft delete table inet vpngw_trial_guard 2>/dev/null || :
nft delete table ip vpngw_trial_nat 2>/dev/null || :
echo "VPN_TRIAL_REVERTED host=$host existing_DIRECT_unchanged=true"
