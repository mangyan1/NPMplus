# Encrypted Client Hello (ECH)

NPMplus supports generating and automatically rotating Encrypted Client Hello (ECH) keys. This guide covers the container's ECH hooks and how to drive them from your own cron script.

- To enable and configure ECH, you need to set up a cron script that triggers the key generation and updates your DNS records.
- When the container starts, it automatically creates an empty file at `/opt/npmplus/tls/ech/cron.sh`. You need to fill this file with a script to handle your ECH keys.
- If this file is not empty, NPMplus will automatically execute it regularly, enable ECH in the nginx configuration, and reload nginx after execution.
- Inside your `cron.sh`, use the built-in `ech.sh` command to generate your keys. The syntax is: `ech.sh <public-name> <identifier> [max-name-length (default 64)]`.
- This command generates the keys in `/opt/npmplus/tls/ech/` (saving the current and previous keys) and outputs the Base64-encoded ECH config list to standard output, which you can capture to update your DNS records.
- Because ECH requires advertising your public key via an HTTPS DNS record, your `cron.sh` must push the newly generated config to your DNS provider.
- There is an example cron.sh script for Cloudflare in the repository root: [`ech-cron-cloudflare-example.sh`](../ech-cron-cloudflare-example.sh). You can adapt this script, add your API tokens, define your zones/records, and place its contents into `/opt/npmplus/tls/ech/cron.sh`.
- By default, the container will run your `cron.sh` script and reload nginx on container start and then every hour after container start. You can change this interval by setting the `ECH_ROTATION_INTERVAL` environment variable in your `compose.yaml`.
- Use your server's hostname/PTR record as the public name, and make sure a (dead) host with a valid cert for your public name exists. The "identifier" is only used as part of the filename.
- Use only one ECH key shared across all your hosts. If you configure multiple ECH keys then only the one with the alphabetically first "identifier" will be used in the retry_configs response.
- Do not set HTTPS records for FQDNs which use a CNAME record, but set them for the CNAME target, as only the HTTPS record of the CNAME target will be used by chromium.
- Deleting/clearing the cron.sh will disable ECH, but you still need to remove ECH from the HTTPS records yourself.