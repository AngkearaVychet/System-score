<?php
/**
 * សៀវភៅពិន្ទុសិស្ស — server API
 * Stores the page's documents (classes, sheets, settings, honor, photos) and teacher accounts in SQLite.
 * Requires PHP 7.4+ with pdo_sqlite. No other setup: the database is created on first use.
 */
declare(strict_types=1);

// Where the database lives. Moving it outside the public web folder is safer, e.g. '/home/USER/gradebook-data'.
// The database is kept OUTSIDE the public web folder when the host allows it (next to public_html),
// otherwise in ./data protected by .htaccess. Set GRADEBOOK_DATA_DIR to choose a folder yourself.
function pick_data_dir(): string {
  $env = getenv('GRADEBOOK_DATA_DIR');
  if ($env) return rtrim($env, '/');
  $root = rtrim((string)($_SERVER['DOCUMENT_ROOT'] ?? ''), '/');
  if ($root !== '') {
    $outside = dirname($root) . '/gradebook-data';
    if (is_dir($outside) ? is_writable($outside) : (is_writable(dirname($root)) && @mkdir($outside, 0770, true))) return $outside;
  }
  return __DIR__ . '/data';
}
define('DATA_DIR', pick_data_dir());
const MAX_DOC_BYTES = 400000;
const COLLECTIONS = ['classes', 'sheets', 'settings', 'honor', 'photos'];

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

session_name('gradebook');
session_set_cookie_params([
  'lifetime' => 60 * 60 * 24 * 14, 'path' => '/', 'httponly' => true,
  'samesite' => 'Strict', 'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();

function out(int $code, array $body): void {
  http_response_code($code);
  echo json_encode($body, JSON_UNESCAPED_UNICODE);
  exit;
}

if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0770, true)) out(500, ['error' => 'មិនអាចបង្កើតថត data បានទេ']);
if (!file_exists(DATA_DIR . '/.htaccess')) @file_put_contents(DATA_DIR . '/.htaccess', "Require all denied\nDeny from all\n");
if (!file_exists(DATA_DIR . '/index.html')) @file_put_contents(DATA_DIR . '/index.html', '');

try {
  $db = new PDO('sqlite:' . DATA_DIR . '/gradebook.sqlite');
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $db->exec('PRAGMA busy_timeout = 5000');
  $db->exec('PRAGMA journal_mode = WAL');
  $db->exec('CREATE TABLE IF NOT EXISTS docs (path TEXT PRIMARY KEY, coll TEXT NOT NULL, id TEXT NOT NULL,
             data TEXT NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT)');
  $db->exec('CREATE INDEX IF NOT EXISTS docs_coll ON docs (coll)');
  $db->exec('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, name TEXT NOT NULL,
             role TEXT NOT NULL, pass TEXT NOT NULL, created_at INTEGER NOT NULL)');
} catch (Throwable $e) {
  out(500, ['error' => 'មូលដ្ឋានទិន្នន័យមិនដំណើរការ (ត្រូវការ PHP pdo_sqlite)']);
}

/* ---------- helpers ---------- */
function body(): stdClass {
  if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(405, ['error' => 'POST only']);
  if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) out(415, ['error' => 'JSON only']);
  $raw = file_get_contents('php://input');
  if (strlen($raw) > 2 * MAX_DOC_BYTES) out(413, ['error' => 'ទិន្នន័យធំពេក']);
  $j = json_decode($raw);
  if (!($j instanceof stdClass)) out(400, ['error' => 'bad json']);
  return $j;
}
function user_row(PDO $db, string $u): ?array {
  $s = $db->prepare('SELECT username, name, role FROM users WHERE username = ?');
  $s->execute([$u]);
  $r = $s->fetch(PDO::FETCH_ASSOC);
  return $r ?: null;
}
function me(PDO $db): ?array {
  if (empty($_SESSION['u'])) return null;
  $u = user_row($db, $_SESSION['u']);
  if (!$u) { $_SESSION = []; }
  return $u;
}
function need(PDO $db): array { $u = me($db); if (!$u) out(401, ['error' => 'សូមចូលប្រើម្ដងទៀត']); return $u; }
function need_admin(PDO $db): array { $u = need($db); if ($u['role'] !== 'admin') out(403, ['error' => 'សម្រាប់តែអ្នកគ្រប់គ្រង']); return $u; }
function split_path(string $p): array {
  if (!preg_match('#^([a-z]+)/([A-Za-z0-9_\-.~:@+]{1,200})$#', $p, $m) || !in_array($m[1], COLLECTIONS, true)) out(400, ['error' => 'bad path']);
  return [$m[1], $m[2]];
}
function get_doc(PDO $db, string $p): ?stdClass {
  $s = $db->prepare('SELECT data FROM docs WHERE path = ?');
  $s->execute([$p]);
  $r = $s->fetchColumn();
  return $r === false ? null : json_decode($r);
}
function put_doc(PDO $db, string $p, stdClass $data, array $u): void {
  [$c, $id] = split_path($p);
  $json = json_encode($data, JSON_UNESCAPED_UNICODE);
  if (strlen($json) > MAX_DOC_BYTES) out(413, ['error' => 'ឯកសារធំពេក']);
  $s = $db->prepare('INSERT OR REPLACE INTO docs (path, coll, id, data, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?)');
  $s->execute([$p, $c, $id, $json, time(), $u['username']]);
}
function merge($a, $b) {
  if (!($a instanceof stdClass) || !($b instanceof stdClass)) return $b;
  foreach (get_object_vars($b) as $k => $v) {
    $a->$k = (isset($a->$k) && $a->$k instanceof stdClass && $v instanceof stdClass) ? merge($a->$k, $v) : $v;
  }
  return $a;
}
/** Teachers enter scores, students, photos and honor-roll dates; admins also manage classes, subjects and school info. */
function check_write(PDO $db, array $u, string $p): void {
  if ($u['role'] === 'admin') return;
  [$c, $id] = split_path($p);
  if ($c === 'settings' || ($c === 'photos' && $id === 'logo')) out(403, ['error' => 'សម្រាប់តែអ្នកគ្រប់គ្រង']);
  if ($c === 'classes' && get_doc($db, $p) === null) out(403, ['error' => 'មានតែអ្នកគ្រប់គ្រងទេដែលបង្កើតថ្នាក់បាន']);
}
function users_list(PDO $db): array {
  return $db->query('SELECT username, name, role FROM users ORDER BY role, name')->fetchAll(PDO::FETCH_ASSOC);
}
function valid_user(string $u): bool { return (bool)preg_match('/^[A-Za-z0-9_.\-]{3,32}$/', $u); }

/* ---------- routes ---------- */
$a = $_GET['a'] ?? '';
switch ($a) {
  case 'me':
    $count = (int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn();
    out(200, ['user' => me($db), 'needsSetup' => $count === 0]);

  case 'setup': {
    $j = body();
    if ((int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn() > 0) out(403, ['error' => 'បានរៀបចំរួចហើយ']);
    $u = trim((string)($j->username ?? '')); $pw = (string)($j->password ?? ''); $name = trim((string)($j->name ?? ''));
    if (!valid_user($u)) out(400, ['error' => 'ឈ្មោះអ្នកប្រើ ៣–៣២ អក្សរឡាតាំង ឬលេខ']);
    if (strlen($pw) < 6) out(400, ['error' => 'ពាក្យសម្ងាត់យ៉ាងតិច ៦ តួ']);
    $db->prepare('INSERT INTO users (username, name, role, pass, created_at) VALUES (?, ?, ?, ?, ?)')
       ->execute([$u, $name ?: $u, 'admin', password_hash($pw, PASSWORD_DEFAULT), time()]);
    session_regenerate_id(true); $_SESSION['u'] = $u;
    out(200, ['user' => user_row($db, $u)]);
  }

  case 'login': {
    $j = body();
    $u = trim((string)($j->username ?? '')); $pw = (string)($j->password ?? '');
    $s = $db->prepare('SELECT pass FROM users WHERE username = ?'); $s->execute([$u]);
    $hash = $s->fetchColumn();
    if (!$hash || !password_verify($pw, $hash)) { usleep(800000); out(401, ['error' => 'ឈ្មោះអ្នកប្រើ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវ']); }
    session_regenerate_id(true); $_SESSION['u'] = $u;
    out(200, ['user' => user_row($db, $u)]);
  }

  case 'logout':
    body(); $_SESSION = []; session_destroy();
    out(200, ['ok' => true]);

  case 'get': {
    need($db);
    $p = (string)($_GET['p'] ?? ''); split_path($p);
    $d = get_doc($db, $p);
    out(200, ['data' => $d]);
  }

  case 'list': {
    need($db);
    $c = (string)($_GET['c'] ?? '');
    if (!in_array($c, COLLECTIONS, true) || $c === 'photos') out(400, ['error' => 'bad collection']);
    $s = $db->prepare('SELECT id, data FROM docs WHERE coll = ? ORDER BY id'); $s->execute([$c]);
    $docs = [];
    foreach ($s->fetchAll(PDO::FETCH_ASSOC) as $r) $docs[] = ['id' => $r['id'], 'data' => json_decode($r['data'])];
    out(200, ['docs' => $docs]);
  }

  case 'set': {
    $j = body(); $u = need($db);
    $p = (string)($j->p ?? ''); split_path($p);
    if (!(($j->data ?? null) instanceof stdClass)) out(400, ['error' => 'data must be an object']);
    check_write($db, $u, $p);
    put_doc($db, $p, $j->data, $u);
    out(200, ['ok' => true]);
  }

  case 'patch': {
    $j = body(); $u = need($db);
    $p = (string)($j->p ?? ''); split_path($p);
    if (!(($j->data ?? null) instanceof stdClass)) out(400, ['error' => 'data must be an object']);
    check_write($db, $u, $p);
    $db->beginTransaction();
    $cur = get_doc($db, $p) ?? new stdClass();
    put_doc($db, $p, merge($cur, $j->data), $u);
    $db->commit();
    out(200, ['ok' => true]);
  }

  case 'del': {
    $j = body(); need_admin($db);
    $p = (string)($j->p ?? ''); split_path($p);
    $db->prepare('DELETE FROM docs WHERE path = ?')->execute([$p]);
    out(200, ['ok' => true]);
  }

  case 'users':
    need_admin($db);
    out(200, ['users' => users_list($db)]);

  case 'user_save': {
    $j = body(); $me = need_admin($db);
    $u = trim((string)($j->username ?? '')); $name = trim((string)($j->name ?? ''));
    $pw = (string)($j->password ?? ''); $role = ($j->role ?? '') === 'admin' ? 'admin' : 'teacher';
    if (!valid_user($u)) out(400, ['error' => 'ឈ្មោះអ្នកប្រើ ៣–៣២ អក្សរឡាតាំង ឬលេខ']);
    if ($name === '') out(400, ['error' => 'សូមបញ្ចូលឈ្មោះពេញ']);
    $exists = user_row($db, $u);
    if (!$exists && strlen($pw) < 6) out(400, ['error' => 'ពាក្យសម្ងាត់យ៉ាងតិច ៦ តួ']);
    if ($pw !== '' && strlen($pw) < 6) out(400, ['error' => 'ពាក្យសម្ងាត់យ៉ាងតិច ៦ តួ']);
    if ($exists && $u === $me['username'] && $role !== 'admin') out(400, ['error' => 'មិនអាចដកសិទ្ធិអ្នកគ្រប់គ្រងពីខ្លួនឯងបានទេ']);
    if ($exists) {
      $db->prepare('UPDATE users SET name = ?, role = ? WHERE username = ?')->execute([$name, $role, $u]);
      if ($pw !== '') $db->prepare('UPDATE users SET pass = ? WHERE username = ?')->execute([password_hash($pw, PASSWORD_DEFAULT), $u]);
    } else {
      $db->prepare('INSERT INTO users (username, name, role, pass, created_at) VALUES (?, ?, ?, ?, ?)')
         ->execute([$u, $name, $role, password_hash($pw, PASSWORD_DEFAULT), time()]);
    }
    out(200, ['users' => users_list($db)]);
  }

  case 'user_del': {
    $j = body(); $me = need_admin($db);
    $u = trim((string)($j->username ?? ''));
    if ($u === $me['username']) out(400, ['error' => 'មិនអាចលុបគណនីខ្លួនឯងបានទេ']);
    $db->prepare('DELETE FROM users WHERE username = ?')->execute([$u]);
    out(200, ['users' => users_list($db)]);
  }

  default:
    out(404, ['error' => 'unknown action']);
}
