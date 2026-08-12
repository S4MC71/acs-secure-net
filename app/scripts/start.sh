#!/bin/bash

# Write security secrets to individual files at runtime — never in source code
mkdir -p /app/secrets /app/files/classified /app/files/agents /etc/acs

# API secrets — each in its own file, read by server.js at runtime
echo "ACS_SECURE{num3r1c_1d_1d0r_4g3nt_d4t4_l34k3d}"           > /app/secrets/i1
echo "ACS_SECURE{uu1d_m1ss10n_1d0r_cl4ss1f13d_3xp0s3d}"         > /app/secrets/i2
echo "ACS_SECURE{ph0n3_num_1d0r_4g3nt_l0c4t3d}"                  > /app/secrets/i3
echo "ACS_SECURE{3m41l_1d0r_0p3r4t1v3_pr0f1l3_3xp0s3d}"         > /app/secrets/i4
echo "ACS_SECURE{us3rn4m3_1d0r_s3cr3t_n0t3_r34d}"                > /app/secrets/i5
echo "ACS_SECURE{slvg_1d0r_1nt3l_r3p0rt_cl4ss1f13d}"             > /app/secrets/i6
echo "ACS_SECURE{c0mp0s1t3_1d0r_ph0n3_d0b_byp4ss}"               > /app/secrets/i7a
echo "ACS_SECURE{c0mp0s1t3_1d0r_3m41l_c0d3_byp4ss}"              > /app/secrets/i7b
echo "ACS_SECURE{c0mp0s1t3_1d0r_n4m3_b1rth_byp4ss}"              > /app/secrets/i7c
echo "ACS_SECURE{f1l3_p4th_1d0r_cl4ss1f13d_f1l3_r34d}"           > /app/secrets/i8
echo "ACS_SECURE{b4s364_1d0r_3nc0d3d_r3f_byp4ss}"                > /app/secrets/i9a
echo "ACS_SECURE{h3x_1d0r_3nc0d3d_r3f_byp4ss}"                   > /app/secrets/i9b
echo "ACS_SECURE{url_3nc0d3d_1d0r_r3f_byp4ss}"                   > /app/secrets/i9c
echo "ACS_SECURE{md5_h4sh_1d0r_3m41l_l00kup_byp4ss}"             > /app/secrets/i10a
echo "ACS_SECURE{sh41_h4sh_1d0r_us3rn4m3_l00kup_byp4ss}"         > /app/secrets/i10b
echo "ACS_SECURE{m4g1c_l1nk_1d0r_t0k3n_s3qu3nt14l}"              > /app/secrets/i11a
echo "ACS_SECURE{r3s3t_t0k3n_1d0r_b4s364_byp4ss}"                > /app/secrets/i11b
echo "ACS_SECURE{qr_t0k3n_1d0r_w34k_c0d3_byp4ss}"                > /app/secrets/i11c
chmod 600 /app/secrets/*

# File-based secrets — inside agent files (discovered via file path IDOR)
cat > /app/files/agents/agent_001.txt << 'F'
AGENT DOSSIER — CLASSIFIED
Name: Kira Nakamura  Codename: PHANTOM  Clearance: OMEGA
Bank Account: GH-ACC-229-88774411  Passphrase: midnight-lotus-7749
SECRET_TOKEN: ACS_SECURE{f1l3_p4th_1d0r_4g3nt_d0ss13r_l34k3d}
F

cat > /app/files/agents/agent_002.txt << 'F'
AGENT DOSSIER — CLASSIFIED
Name: Marcus Osei  Codename: WRAITH  Clearance: SIGMA
Safe House: 44 Shadow Lane, Accra  Passphrase: iron-serpent-3301
SECRET_TOKEN: ACS_SECURE{f1l3_p4th_1d0r_wr41th_d0ss13r_l34k3d}
F

cat > /app/files/classified/mission_alpha.txt << 'F'
OPERATION ALPHA — EYES ONLY
Target: HVA  Location: Grid 77-Alpha  Handler: Director Mawuli
SECRET_TOKEN: ACS_SECURE{f1l3_p4th_1d0r_m1ss10n_4lph4_3xp0s3d}
F

cat > /app/files/classified/shadow_config.txt << 'F'
ACS SECURE NET INTERNAL CONFIG
JWT_SECRET=acs_secure_net_ops_2026
SECRET_TOKEN: ACS_SECURE{f1l3_p4th_1d0r_c0nf1g_3xp0s3d}
F

chmod -R 644 /app/files

cat > /etc/acs/ops.key << 'K'
ACS Secure Net Ops Key
JWT_SECRET=acs_secure_net_ops_2026
Property of: ACS Secure Net
K

echo "ACS_SECURE{r00t_pr1v3sc_4cs_s3cur3_n3t_c0mpr0m1s3d}" > /root/root.txt
chmod 600 /root/root.txt

node /app/setup.js
exec node /app/server.js


