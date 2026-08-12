'use strict';
const sqlite3 = require('sqlite3').verbose();
const path    = require('path');
const crypto  = require('crypto');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = path.join(__dirname, 'data', 'acs_secure.db');
const db = new sqlite3.Database(DB_PATH);

const md5  = s => crypto.createHash('md5').update(s).digest('hex');
const sha1 = s => crypto.createHash('sha1').update(s).digest('hex');

db.serialize(() => {

  db.run(`CREATE TABLE IF NOT EXISTS agents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid          TEXT UNIQUE NOT NULL,
    username      TEXT UNIQUE NOT NULL,
    slug          TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password      TEXT NOT NULL,
    name          TEXT NOT NULL,
    phone         TEXT UNIQUE NOT NULL,
    dob           TEXT NOT NULL,
    codename      TEXT NOT NULL,
    faction       TEXT DEFAULT 'SHADOW',
    clearance     TEXT DEFAULT 'ALPHA',
    rank          TEXT DEFAULT 'Operative',
    bio           TEXT,
    secret_note   TEXT,
    bank_account  TEXT,
    safe_location TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS missions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid          TEXT UNIQUE NOT NULL,
    slug          TEXT UNIQUE NOT NULL,
    agent_id      INTEGER NOT NULL,
    title         TEXT NOT NULL,
    classification TEXT DEFAULT 'SECRET',
    description   TEXT,
    location      TEXT,
    target        TEXT,
    status        TEXT DEFAULT 'active',
    mission_date  TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS intel_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    slug          TEXT UNIQUE NOT NULL,
    agent_id      INTEGER NOT NULL,
    title         TEXT NOT NULL,
    content       TEXT NOT NULL,
    classification TEXT DEFAULT 'CONFIDENTIAL',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS agent_files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      INTEGER NOT NULL,
    filename      TEXT NOT NULL,
    filepath      TEXT NOT NULL,
    description   TEXT,
    classification TEXT DEFAULT 'SECRET',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS verification_codes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      INTEGER NOT NULL,
    code          TEXT NOT NULL,
    purpose       TEXT NOT NULL,
    used          INTEGER DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS access_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      INTEGER NOT NULL,
    token         TEXT UNIQUE NOT NULL,
    token_type    TEXT NOT NULL,
    used          INTEGER DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS qr_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      INTEGER NOT NULL,
    qr_code       TEXT UNIQUE NOT NULL,
    purpose       TEXT DEFAULT 'auth',
    used          INTEGER DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS encoded_refs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      INTEGER NOT NULL,
    ref_type      TEXT NOT NULL,
    ref_value     TEXT NOT NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ── Agents ────────────────────────────────────────────────────────
  const agents = [
    {
      uuid:uuidv4(), username:'phantom_k', slug:'phantom-kira', email:'kira@acs.ops',
      password:'Kira@2025', name:'Kira Nakamura', phone:'+233201110001', dob:'1990-03-15',
      codename:'PHANTOM', faction:'OMEGA', clearance:'OMEGA', rank:'Senior Operative',
      bio:'Veteran field agent, specialised in infiltration and data extraction.',
      secret_note:'Safe house coords: 7.9465N, -1.0232W. Next extraction: 2025-09-01.',
      bank_account:'GH-ACC-229-88774411', safe_location:'44 Shadow Lane, Kumasi'
    },
    {
      uuid:uuidv4(), username:'wraith_m', slug:'wraith-marcus', email:'marcus@acs.ops',
      password:'Marcus@2025', name:'Marcus Osei', phone:'+233201110002', dob:'1985-07-22',
      codename:'WRAITH', faction:'SIGMA', clearance:'SIGMA', rank:'Field Commander',
      bio:'Demolitions expert and covert operations specialist.',
      secret_note:'Emergency contact: Handler Adjoa. Code phrase: iron-serpent-3301.',
      bank_account:'GH-ACC-774-99112233', safe_location:'Block 7, Osu, Accra'
    },
    {
      uuid:uuidv4(), username:'viper_a', slug:'viper-ama', email:'ama@acs.ops',
      password:'Ama@2025', name:'Ama Boateng', phone:'+233201110003', dob:'1995-11-08',
      codename:'VIPER', faction:'DELTA', clearance:'DELTA', rank:'Intelligence Analyst',
      bio:'Cyber operations and signals intelligence expert.',
      secret_note:'Encrypted comms key: delta-seven-foxtrot-9922.',
      bank_account:'GH-ACC-331-55667788', safe_location:'12 Cantonments, Accra'
    },
    {
      uuid:uuidv4(), username:'ghost_k', slug:'ghost-kwame', email:'kwame@acs.ops',
      password:'Kwame@2025', name:'Kwame Darko', phone:'+233201110004', dob:'1988-05-30',
      codename:'GHOST', faction:'ALPHA', clearance:'ALPHA', rank:'Operative',
      bio:'Surveillance and counter-intelligence specialist.',
      secret_note:'Cover identity: Kwame Mensah, accountant. DOC: GHA-112-885.',
      bank_account:'GH-ACC-556-22334455', safe_location:'East Legon, Accra'
    },
    {
      uuid:uuidv4(), username:'shadow_y', slug:'shadow-yaw', email:'yaw@acs.ops',
      password:'Yaw@2025', name:'Yaw Asante', phone:'+233201110005', dob:'1992-09-14',
      codename:'SHADOW', faction:'ALPHA', clearance:'ALPHA', rank:'Recruit',
      bio:'New recruit undergoing field training. Standard entry point.',
      secret_note:'Training handler: Senior Operative PHANTOM.',
      bank_account:'GH-ACC-112-11223344', safe_location:'Madina, Accra'
    },
  ];

  agents.forEach(a => db.run(
    `INSERT OR IGNORE INTO agents (uuid,username,slug,email,password,name,phone,dob,codename,faction,clearance,rank,bio,secret_note,bank_account,safe_location)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [a.uuid,a.username,a.slug,a.email,a.password,a.name,a.phone,a.dob,a.codename,a.faction,a.clearance,a.rank,a.bio,a.secret_note,a.bank_account,a.safe_location]
  ));

  setTimeout(() => {
    db.all('SELECT id,uuid,username,email,phone,dob,name FROM agents ORDER BY id', [], (e, ags) => {
      if (!ags||!ags.length) return;

      // Missions
      const missions = [
        [ags[0].id, uuidv4(), 'operation-nightfall', 'Operation Nightfall', 'TOP SECRET', 'Neutralise HVT in grid 77A', 'Grid 77-Alpha, Northern Region', 'Asset Kofi Mensah', 'active', '2025-09-15'],
        [ags[1].id, uuidv4(), 'operation-iron-veil', 'Operation Iron Veil', 'TOP SECRET', 'Intercept arms shipment at port', 'Tema Port, Accra', 'Shipment HV-2209', 'active', '2025-09-20'],
        [ags[2].id, uuidv4(), 'operation-cipher', 'Operation Cipher', 'SECRET', 'Extract encrypted comms from target network', 'Cyberspace - Target: TelGh Corp', 'Network Asset T-7', 'completed', '2025-08-01'],
        [ags[3].id, uuidv4(), 'operation-ghost-walk', 'Operation Ghost Walk', 'CONFIDENTIAL', 'Surveillance of suspect at coordinates', 'Airport Residential, Accra', 'Suspect 44-X', 'active', '2025-09-10'],
      ];
      missions.forEach(m => db.run(
        `INSERT OR IGNORE INTO missions (agent_id,uuid,slug,title,classification,description,location,target,status,mission_date) VALUES (?,?,?,?,?,?,?,?,?,?)`, m
      ));

      // Intel reports
      const intel = [
        [ags[0].id, 'phantom-intel-alpha', 'PHANTOM Field Report Alpha', 'OMEGA-level field report. Asset confirmed at secondary location. Extraction window: 72 hours.', 'OMEGA'],
        [ags[1].id, 'wraith-intel-bravo', 'WRAITH Sigint Report Bravo', 'Intercepted communications suggest imminent asset movement. Counter-ops required.', 'TOP SECRET'],
        [ags[2].id, 'viper-cyber-gamma', 'VIPER Cyber Report Gamma', 'Network breach confirmed. 3.2TB of encrypted comms extracted. Decryption ongoing.', 'TOP SECRET'],
      ];
      intel.forEach(i => db.run(
        `INSERT OR IGNORE INTO intel_reports (agent_id,slug,title,content,classification) VALUES (?,?,?,?,?)`, i
      ));

      // Agent files
      ags.forEach((ag, i) => {
        db.run(`INSERT OR IGNORE INTO agent_files (agent_id,filename,filepath,description,classification) VALUES (?,?,?,?,?)`,
          [ag.id, `agent_00${i+1}.txt`, `agents/agent_00${i+1}.txt`, `Dossier for operative ${ag.codename||ag.name}`, 'CLASSIFIED']
        );
      });
      db.run(`INSERT OR IGNORE INTO agent_files (agent_id,filename,filepath,description,classification) VALUES (?,?,?,?,?)`,
        [ags[0].id, 'mission_alpha.txt', 'classified/mission_alpha.txt', 'Operation Alpha mission brief', 'TOP SECRET']
      );
      db.run(`INSERT OR IGNORE INTO agent_files (agent_id,filename,filepath,description,classification) VALUES (?,?,?,?,?)`,
        [ags[0].id, 'shadow_config.txt', 'classified/shadow_config.txt', 'System configuration', 'OMEGA']
      );

      // Verification codes (for composite IDOR)
      ags.forEach(ag => {
        const code = String(Math.floor(1000 + (ag.id * 1111))).slice(0, 4);
        db.run(`INSERT OR IGNORE INTO verification_codes (agent_id,code,purpose) VALUES (?,?,?)`,
          [ag.id, code, 'identity_verification']
        );
      });

      // Access tokens (magic links, reset tokens)
      ags.forEach((ag, i) => {
        // Magic link — sequential and predictable
        const magicToken = `magic-${String(ag.id).padStart(6, '0')}-acssec`;
        db.run(`INSERT OR IGNORE INTO access_tokens (agent_id,token,token_type) VALUES (?,?,?)`,
          [ag.id, magicToken, 'magic_link']
        );
        // Reset token — base64 of agent ID
        const resetToken = Buffer.from(`reset:${ag.id}:acssec`).toString('base64');
        db.run(`INSERT OR IGNORE INTO access_tokens (agent_id,token,token_type) VALUES (?,?,?)`,
          [ag.id, resetToken, 'reset']
        );
        // QR token — simple sequential code
        const qrCode = `QR-${String(ag.id * 1337).padStart(8, '0')}`;
        db.run(`INSERT OR IGNORE INTO qr_tokens (agent_id,qr_code,purpose) VALUES (?,?,?)`,
          [ag.id, qrCode, 'auth']
        );
        // Encoded refs
        const b64Ref = Buffer.from(String(ag.id)).toString('base64');
        const hexRef = Buffer.from(String(ag.id)).toString('hex');
        const urlRef = encodeURIComponent(`agent_${ag.id}`);
        const md5Ref = md5(ag.email);
        const sha1Ref = sha1(ag.username);
        db.run(`INSERT OR IGNORE INTO encoded_refs (agent_id,ref_type,ref_value) VALUES (?,?,?)`, [ag.id, 'base64', b64Ref]);
        db.run(`INSERT OR IGNORE INTO encoded_refs (agent_id,ref_type,ref_value) VALUES (?,?,?)`, [ag.id, 'hex', hexRef]);
        db.run(`INSERT OR IGNORE INTO encoded_refs (agent_id,ref_type,ref_value) VALUES (?,?,?)`, [ag.id, 'url', urlRef]);
        db.run(`INSERT OR IGNORE INTO encoded_refs (agent_id,ref_type,ref_value) VALUES (?,?,?)`, [ag.id, 'md5', md5Ref]);
        db.run(`INSERT OR IGNORE INTO encoded_refs (agent_id,ref_type,ref_value) VALUES (?,?,?)`, [ag.id, 'sha1', sha1Ref]);
      });
    });
  }, 600);

  console.log('[ACS SECURE NET] Database seeded.');
});
setTimeout(() => db.close(), 4000);
