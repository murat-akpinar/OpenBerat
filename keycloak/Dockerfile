# SPDX-FileCopyrightText: 2026 OpenBerat contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# Keycloak was a stock image until the login theme arrived. A theme is read at
# runtime, so bind-mounting it would be exactly the configuration drift the
# rules forbid — it is baked in like every other running configuration. The
# realm export stays a mount because it is import data, not configuration.
# The build context is the repository root so the mark can come from the
# frontend rather than be kept in two places.
FROM quay.io/keycloak/keycloak:26.3
COPY keycloak/themes/ /opt/keycloak/themes/
COPY frontend/src/logo.svg /opt/keycloak/themes/openberat/login/resources/img/logo.svg
