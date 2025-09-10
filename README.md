# keycloak-twitch

Keycloak 26.3.3 identity provider for Twitch.

Original project by https://github.com/intricate/keycloak-twitch

## Usage:
- Copy the jar file to the /opt/keycloak/providers directory
- Restart Keycloak (depending on the deployment method, you need to build the keycloak manually; the docker image does it automatically)

## Changelog:
- Updated to Keycloak 26.3.3
- Added Twitch Claim Support
- Added basic support for email verification by Twitch