# Files:
Below are the relevant files, files are pasted as separate files sources within ```this-markings``` . OKAY!
#


```php name=.htaccess
# Disable directory listing

Options -Indexes

# Deny access to sensitive files

<FilesMatch "\.(sql|sqlite|sqlite3|bak|ini|log|sh|bat)$">
Require all denied
</FilesMatch>

# Basic security headers if PHP script didn't run (fallback)

<IfModule mod_headers.c>
  Header set X-Frame-Options "DENY"
  Header set X-Content-Type-Options "nosniff"
  Header set Referrer-Policy "no-referrer"
</IfModule>

```

```php name=api.php
<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/auth.php';

header('Content-Type: application/json; charset=utf-8');

// Extra hardening for API
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

$pdo = db();
$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

function json_input(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === '' || $raw === false) return [];
    $d = json_decode($raw, true);
    return is_array($d) ? $d : [];
}

try {
    if ($action === 'login' && $method === 'POST') {
        $data = json_input();
        $username = trim((string)($data['username'] ?? ''));
        $password = (string)($data['password'] ?? '');
        if ($username === '' || $password === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Missing credentials']);
            exit;
        }

        $ip = client_ip();
        $lockSecs = throttle_is_locked($pdo, $ip, $username);
        if ($lockSecs !== null) {
            http_response_code(429);
            echo json_encode(['error' => 'Too many attempts. Try again later.', 'retry_after_sec' => $lockSecs]);
            exit;
        }

        $stmt = $pdo->prepare('SELECT id, username, pw_hash FROM users WHERE username = :u LIMIT 1');
        $stmt->execute([':u' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        $ok = $user && password_verify($password, $user['pw_hash']);
        if (!$ok) {
            throttle_register_fail($pdo, $ip, $username);
            http_response_code(401);
            echo json_encode(['error' => 'Invalid username or password']);
            exit;
        }

        if (password_needs_rehash($user['pw_hash'], PASSWORD_DEFAULT)) {
            $upd = $pdo->prepare('UPDATE users SET pw_hash = :p WHERE id = :id');
            $upd->execute([':p' => password_hash($password, PASSWORD_DEFAULT), ':id' => $user['id']]);
        }

        throttle_register_success($pdo, $ip, $username);
        set_user($user);
        echo json_encode(['ok' => true, 'csrf' => csrf_token()]);
        exit;
    }

    if ($action === 'logout' && $method === 'POST') {
        require_login();
        require_csrf();
        logout_user();
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($action === 'me' && $method === 'GET') {
        echo json_encode(['user' => current_user()]);
        exit;
    }

    // Authenticated endpoints
    require_login();

    if ($action === 'list_categories' && $method === 'GET') {
        $uid = current_user()['id'];
        $stmt = $pdo->prepare('SELECT id, name, color FROM categories WHERE owner_id = :o ORDER BY sort_order, name');
        $stmt->execute([':o' => $uid]);
        echo json_encode(['categories' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
        exit;
    }

    if ($action === 'add_category' && $method === 'POST') {
        require_csrf();
        $uid = current_user()['id'];
        $data = json_input();
        $name = trim((string)($data['name'] ?? ''));
        $color = (string)($data['color'] ?? '#60a5fa');
        if ($name === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Name required']);
            exit;
        }
        $now = gmdate('c');
        $stmt = $pdo->prepare('INSERT INTO categories (id, owner_id, name, color, sort_order, created_at, updated_at) VALUES (:id, :o, :n, :c, :s, :ca, :ua)');
        $id = uuid();
        $stmt->execute([
            ':id' => $id,
            ':o'  => $uid,
            ':n'  => $name,
            ':c'  => $color,
            ':s'  => 0,
            ':ca' => $now,
            ':ua' => $now,
        ]);
        echo json_encode(['ok' => true, 'id' => $id]);
        exit;
    }

    if ($action === 'list_events_by_day' && $method === 'GET') {
        $uid = current_user()['id'];
        $dayKey = (string)($_GET['day_key'] ?? '');
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $dayKey)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid day_key']);
            exit;
        }
        $stmt = $pdo->prepare("
            SELECT e.id, e.title, e.description, e.start_at, e.end_at, e.category_id,
                   c.name AS category_name, c.color AS category_color
            FROM events e
            LEFT JOIN categories c ON c.id = e.category_id
            WHERE e.owner_id = :o AND e.day_key = :d
            ORDER BY e.start_at ASC
        ");
        $stmt->execute([':o' => $uid, ':d' => $dayKey]);
        echo json_encode(['events' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
        exit;
    }

    if ($action === 'add_event' && $method === 'POST') {
        require_csrf();
        $uid = current_user()['id'];
        $data = json_input();

        $categoryId = isset($data['category_id']) ? (string)$data['category_id'] : null;
        $title = trim((string)($data['title'] ?? ''));
        $description = trim((string)($data['description'] ?? ''));
        $startUtc = trim((string)($data['start_at_utc'] ?? ''));
        $endUtc = trim((string)($data['end_at_utc'] ?? ''));
        $dayKey = trim((string)($data['day_key'] ?? ''));
        $tz = trim((string)($data['timezone'] ?? 'UTC'));

        if ($title === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Title required']);
            exit;
        }
        if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $dayKey)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid day_key']);
            exit;
        }
        $isIso = static function (string $s): bool {
            return (bool)preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/', $s);
        };
        if (!$isIso($startUtc) || !$isIso($endUtc)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid start/end time']);
            exit;
        }
        if ($categoryId !== null && $categoryId !== '') {
            $chk = $pdo->prepare('SELECT COUNT(*) FROM categories WHERE id = :id AND owner_id = :o');
            $chk->execute([':id' => $categoryId, ':o' => $uid]);
            if ((int)$chk->fetchColumn() === 0) {
                http_response_code(403);
                echo json_encode(['error' => 'Invalid category']);
                exit;
            }
        } else {
            $categoryId = null;
        }

        $now = gmdate('c');
        $id = uuid();
        $ins = $pdo->prepare('
            INSERT INTO events (id, owner_id, category_id, start_at, end_at, day_key, all_day, timezone, title, description, created_at, updated_at)
            VALUES (:id, :o, :c, :s, :e, :d, 0, :tz, :t, :desc, :ca, :ua)
        ');
        $ins->execute([
            ':id' => $id,
            ':o'  => $uid,
            ':c'  => $categoryId,
            ':s'  => $startUtc,
            ':e'  => $endUtc,
            ':d'  => $dayKey,
            ':tz' => $tz,
            ':t'  => $title,
            ':desc' => $description,
            ':ca' => $now,
            ':ua' => $now,
        ]);
        echo json_encode(['ok' => true, 'id' => $id]);
        exit;
    }

    // NEW: update_event for editing time/title/desc/category
    if ($action === 'update_event' && $method === 'POST') {
        require_csrf();
        $uid = current_user()['id'];
        $data = json_input();
        $id = (string)($data['id'] ?? '');
        if ($id === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Missing id']);
            exit;
        }
        $chk = $pdo->prepare('SELECT COUNT(*) FROM events WHERE id = :id AND owner_id = :o');
        $chk->execute([':id' => $id, ':o' => $uid]);
        if ((int)$chk->fetchColumn() === 0) {
            http_response_code(404);
            echo json_encode(['error' => 'Not found']);
            exit;
        }

        $fields = [];
        $params = [':id' => $id];
        $now = gmdate('c');

        if (isset($data['title'])) {
            $fields[] = 'title = :title';
            $params[':title'] = trim((string)$data['title']);
        }
        if (isset($data['description'])) {
            $fields[] = 'description = :description';
            $params[':description'] = trim((string)$data['description']);
        }
        if (array_key_exists('category_id', $data)) {
            $cat = $data['category_id'] ?: null;
            if ($cat !== null) {
                $chk2 = $pdo->prepare('SELECT COUNT(*) FROM categories WHERE id = :id AND owner_id = :o');
                $chk2->execute([':id' => $cat, ':o' => $uid]);
                if ((int)$chk2->fetchColumn() === 0) {
                    http_response_code(403);
                    echo json_encode(['error' => 'Invalid category']);
                    exit;
                }
            }
            $fields[] = 'category_id = :category_id';
            $params[':category_id'] = $cat;
        }
        $isIso = static function (string $s): bool {
            return (bool)preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/', $s);
        };
        if (isset($data['start_at_utc'])) {
            $s = (string)$data['start_at_utc'];
            if (!$isIso($s)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid start_at_utc']);
                exit;
            }
            $fields[] = 'start_at = :start_at';
            $params[':start_at'] = $s;
        }
        if (isset($data['end_at_utc'])) {
            $e = (string)$data['end_at_utc'];
            if (!$isIso($e)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid end_at_utc']);
                exit;
            }
            $fields[] = 'end_at = :end_at';
            $params[':end_at'] = $e;
        }
        if (isset($data['day_key'])) {
            $d = (string)$data['day_key'];
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $d)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid day_key']);
                exit;
            }
            $fields[] = 'day_key = :day_key';
            $params[':day_key'] = $d;
        }
        if (isset($data['timezone'])) {
            $fields[] = 'timezone = :timezone';
            $params[':timezone'] = (string)$data['timezone'];
        }

        if (empty($fields)) {
            echo json_encode(['ok' => true, 'updated' => false]);
            exit;
        }
        $fields[] = 'updated_at = :ua';
        $params[':ua'] = $now;
        $sql = 'UPDATE events SET ' . implode(', ', $fields) . ' WHERE id = :id';
        $upd = $pdo->prepare($sql);
        $upd->execute($params);
        echo json_encode(['ok' => true, 'updated' => true]);
        exit;
    }

    if ($action === 'delete_event' && $method === 'POST') {
        require_csrf();
        $uid = current_user()['id'];
        $data = json_input();
        $id = (string)($data['id'] ?? '');
        if ($id === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Missing id']);
            exit;
        }
        $chk = $pdo->prepare('SELECT COUNT(*) FROM events WHERE id = :id AND owner_id = :o');
        $chk->execute([':id' => $id, ':o' => $uid]);
        if ((int)$chk->fetchColumn() === 0) {
            http_response_code(404);
            echo json_encode(['error' => 'Not found']);
            exit;
        }
        $del = $pdo->prepare('DELETE FROM events WHERE id = :id');
        $del->execute([':id' => $id]);
        echo json_encode(['ok' => true]);
        exit;
    }

    http_response_code(404);
    echo json_encode(['error' => 'Unknown action']);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Server error', 'detail' => $e->getMessage()]);
}
```

```php name=auth.php
<?php

declare(strict_types=1);

require_once __DIR__ . '/security.php';

// Start session after applying security settings
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function current_user(): ?array
{
    return $_SESSION['user'] ?? null;
}

function set_user(array $user): void
{
    // Prevent session fixation
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
    $_SESSION['user'] = [
        'id' => $user['id'],
        'username' => $user['username'],
    ];
    rotate_csrf_token(true);
}

function logout_user(): void
{
    // Regenerate before destroying to invalidate fixation attempts
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    }
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }
    session_destroy();
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function rotate_csrf_token(bool $force = false): string
{
    if ($force || empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function require_csrf(): void
{
    $h = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!hash_equals(csrf_token(), $h)) {
        http_response_code(419);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'CSRF token mismatch']);
        exit;
    }
}

function require_login(): void
{
    if (!current_user()) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Unauthenticated']);
        exit;
    }
}

/**
 * Brute-force protection (login throttling)
 * Uses login_throttle table keyed by (ip, username)
 */
function client_ip(): string
{
    // Prefer REMOTE_ADDR; avoid trusting X-Forwarded-For on shared hosts unless configured
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function throttle_is_locked(PDO $pdo, string $ip, string $username): ?int
{
    $stmt = $pdo->prepare('SELECT locked_until FROM login_throttle WHERE ip = :ip AND username = :u LIMIT 1');
    $stmt->execute([':ip' => $ip, ':u' => $username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || empty($row['locked_until'])) return null;
    $lu = strtotime($row['locked_until']);
    $now = time();
    if ($lu > $now) {
        return $lu - $now; // seconds remaining
    }
    return null;
}

function throttle_register_fail(PDO $pdo, string $ip, string $username): void
{
    $pdo->beginTransaction();
    try {
        $sel = $pdo->prepare('SELECT fail_count, last_fail_at FROM login_throttle WHERE ip = :ip AND username = :u LIMIT 1');
        $sel->execute([':ip' => $ip, ':u' => $username]);
        $row = $sel->fetch(PDO::FETCH_ASSOC);

        $nowIso = gmdate('c');
        $failCount = 1;
        $lockedUntil = null;

        if ($row) {
            $failCount = (int)$row['fail_count'] + 1;
        }

        // Policy: after 5+ consecutive failures, lock for min(2^(n-5), 30) minutes
        if ($failCount >= 5) {
            $minutes = min(30, 2 ** ($failCount - 5));
            $lockedUntil = gmdate('c', time() + $minutes * 60);
        }

        if ($row) {
            $upd = $pdo->prepare('UPDATE login_throttle SET fail_count = :c, last_fail_at = :lf, locked_until = :lu WHERE ip = :ip AND username = :u');
            $upd->execute([':c' => $failCount, ':lf' => $nowIso, ':lu' => $lockedUntil, ':ip' => $ip, ':u' => $username]);
        } else {
            $ins = $pdo->prepare('INSERT INTO login_throttle (ip, username, fail_count, last_fail_at, locked_until) VALUES (:ip, :u, :c, :lf, :lu)');
            $ins->execute([':ip' => $ip, ':u' => $username, ':c' => $failCount, ':lf' => $nowIso, ':lu' => $lockedUntil]);
        }
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        // fail closed: ignore
    }
}

function throttle_register_success(PDO $pdo, string $ip, string $username): void
{
    $del = $pdo->prepare('DELETE FROM login_throttle WHERE ip = :ip AND username = :u');
    $del->execute([':ip' => $ip, ':u' => $username]);
}
```

```php name=bootstrap.php
<?php

declare(strict_types=1);

require_once __DIR__ . '/db.php';

function uuid(): string
{
    $d = random_bytes(16);
    $d[6] = chr((ord($d[6]) & 0x0f) | 0x40);
    $d[8] = chr((ord($d[8]) & 0x3f) | 0x80);
    $hex = bin2hex($d);
    return sprintf(
        '%s-%s-%s-%s-%s',
        substr($hex, 0, 8),
        substr($hex, 8, 4),
        substr($hex, 12, 4),
        substr($hex, 16, 4),
        substr($hex, 20, 12)
    );
}

function bootstrap_db(): void
{
    $pdo = db();
    $schema = file_get_contents(__DIR__ . '/schema.sql');
    $pdo->exec($schema);

    $stmt = $pdo->query('SELECT COUNT(*) FROM users');
    $count = (int)$stmt->fetchColumn();
    if ($count === 0) {
        $now = gmdate('c');
        $users = [
            ['admin', '123456789'],
            ['secondadmin', '123456789'],
        ];
        $ins = $pdo->prepare('INSERT INTO users (id, username, pw_hash, created_at) VALUES (:id, :u, :p, :c)');
        foreach ($users as [$u, $p]) {
            $ins->execute([
                ':id' => uuid(),
                ':u'  => $u,
                ':p'  => password_hash($p, PASSWORD_DEFAULT),
                ':c'  => $now,
            ]);
        }
        // Seed categories for each user
        $uStmt = $pdo->query('SELECT id FROM users');
        $catIns = $pdo->prepare('INSERT INTO categories (id, owner_id, name, color, sort_order, created_at, updated_at) VALUES (:id, :o, :n, :c, :s, :ca, :ua)');
        while ($row = $uStmt->fetch(PDO::FETCH_ASSOC)) {
            $owner = $row['id'];
            $now = gmdate('c');
            foreach ([['Work', '#60a5fa'], ['Home', '#22c55e']] as $i => [$name, $color]) {
                $catIns->execute([
                    ':id' => uuid(),
                    ':o'  => $owner,
                    ':n'  => $name,
                    ':c'  => $color,
                    ':s'  => $i,
                    ':ca' => $now,
                    ':ua' => $now,
                ]);
            }
        }
    }
}

bootstrap_db();
```
```php name=db.php
<?php

declare(strict_types=1);

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dataDir = __DIR__ . '/data';
    if (!is_dir($dataDir)) {
        mkdir($dataDir, 0775, true);
    }
    $dsn = 'sqlite:' . $dataDir . '/app.sqlite';
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA foreign_keys = ON;');
    $pdo->exec('PRAGMA journal_mode = WAL;');
    return $pdo;
}
```
```php name=index.php
<?php

declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/auth.php';

$user = current_user();
$csrf = csrf_token();
?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8" />
    <title>Task Manager (PHP + SQLite)</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES) ?>">
    <link rel="icon" href="./assets/icon.png" />
    <link rel="stylesheet" href="./assets/styles.css" />
</head>

<body data-logged-in="<?= $user ? '1' : '0' ?>">
    <?php if (!$user) : ?>
    <div class="login-wrap">
        <div class="card login">
            <h1>Sign in</h1>
            <p class="muted">Use your admin credentials to access your calendar and notes.</p>
            <div class="row">
                <label class="label" for="username">Username</label>
                <input class="input" id="username" type="text" placeholder="admin" autocomplete="username">
            </div>
            <div class="row">
                <label class="label" for="password">Password</label>
                <input class="input" id="password" type="password" placeholder="********"
                    autocomplete="current-password">
            </div>
            <div class="actions">
                <button id="btn-login" class="btn primary">Sign in</button>
            </div>
            <p class="small-note">Default users: admin / 123456789 and secondadmin / 123456789</p>
        </div>
    </div>
    <?php else : ?>
    <div class="container">
        <aside class="sidebar">
            <div class="month" id="mini-calendar"></div>
            <div class="card" style="margin-top:12px; padding:10px;">
                <div class="hstack" style="justify-content:space-between;">
                    <strong>Categories</strong>
                    <button class="btn" id="btn-add-category" title="Add category">+</button>
                </div>
                <div id="category-list" style="margin-top:8px;"></div>
            </div>
            <div style="margin-top:12px;">
                <span class="badge">Logged in as <?= htmlspecialchars($user['username']) ?></span>
                <button id="btn-logout" class="btn" style="margin-top:8px;">Logout</button>
            </div>
        </aside>
        <main class="main">
            <div class="topbar">
                <div class="hstack">
                    <button id="btn-prev" class="btn" title="Previous period">◀</button>
                    <button id="btn-today" class="btn">Today</button>
                    <button id="btn-next" class="btn" title="Next period">▶</button>
                </div>
                <div id="current-date" style="font-weight:600;"></div>
                <div class="spacer"></div>
                <div class="hstack">
                    <button id="btn-day" class="btn active">Day</button>
                    <button id="btn-week" class="btn">Week</button>
                    <button id="btn-month" class="btn">Month</button>
                </div>
            </div>

            <div class="grid-wrap">
                <div id="day-grid" class="day-grid">
                    <div class="time-col" id="time-col"></div>
                    <div class="slot-col" id="slot-col"></div>
                </div>
            </div>
        </main>
    </div>

    <div id="modal-root" class="modal-root" aria-live="polite"></div>
    <?php endif; ?>

    <script src="./assets/app.js"></script>
</body>

</html>
```
```php name=php-init.php
<?php

declare(strict_types=1);

/**
 * One-time initializer for the Task Manager (PHP + SQLite).
 *
 * - Verifies PHP requirements (PDO + SQLite)
 * - Creates data/ and a secure .htaccess to protect the DB file
 * - Runs schema and seed (via bootstrap.php)
 * - Compiles SCSS to CSS if scssphp is available; otherwise copies SCSS to CSS
 * - Creates a demo category and sample event for visual verification
 *
 * After it reports success, delete this file from the server.
 */

header('Content-Type: text/html; charset=utf-8');

$results = [];
$ok = true;
function step(string $label, callable $fn): void
{
    global $results, $ok;
    try {
        $r = $fn();
        if ($r === true) {
            $results[] = ["ok", $label];
        } else {
            $results[] = ["ok", $label . " — " . (is_string($r) ? $r : "done")];
        }
    } catch (Throwable $e) {
        $results[] = ["err", $label . " — " . $e->getMessage()];
        $ok = false;
    }
}

$root = __DIR__;
$dataDir = $root . '/data';
$dbFile = $dataDir . '/app.sqlite';
$schemaFile = $root . '/schema.sql';
$assetsDir = $root . '/assets';
$scssFile = $assetsDir . '/styles.scss';
$cssFile  = $assetsDir . '/styles.css';

step("Check PHP version >= 7.4", function () {
    if (version_compare(PHP_VERSION, '7.4.0', '<')) {
        throw new RuntimeException("PHP " . PHP_VERSION . " found. Upgrade to >= 7.4");
    }
    return "PHP " . PHP_VERSION;
});

step("Check PDO and SQLite driver", function () {
    if (!class_exists(PDO::class)) {
        throw new RuntimeException("PDO not available");
    }
    $drivers = PDO::getAvailableDrivers();
    if (!in_array('sqlite', $drivers, true)) {
        throw new RuntimeException("PDO SQLite driver not available");
    }
    return "Drivers: " . implode(', ', $drivers);
});

step("Ensure data/ directory exists and is writable", function () use ($dataDir) {
    if (!is_dir($dataDir)) {
        if (!mkdir($dataDir, 0775, true)) {
            throw new RuntimeException("Failed to create $dataDir");
        }
    }
    if (!is_writable($dataDir)) {
        // Try to set perms if possible (may be ignored on some hosts)
        @chmod($dataDir, 0775);
    }
    if (!is_writable($dataDir)) {
        throw new RuntimeException("$dataDir is not writable by PHP");
    }
    return realpath($dataDir) ?: $dataDir;
});

step("Write Apache protection to data/.htaccess", function () use ($dataDir) {
    $ht = $dataDir . '/.htaccess';
    $contents = <<<HT
# Deny web access to database files
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Deny from all
</IfModule>
HT;
    file_put_contents($ht, $contents);
    return basename($ht) . " created";
});

// Load your existing DB bootstrap (creates schema and seeds users/categories)
step("Run database bootstrap (schema + seed)", function () use ($root, $dbFile) {
    require_once $root . '/bootstrap.php'; // this runs bootstrap_db() inside
    if (!file_exists($dbFile)) {
        throw new RuntimeException("Database file missing after bootstrap: " . $dbFile);
    }
    $size = filesize($dbFile);
    return "DB at " . basename($dbFile) . " (" . number_format((float)$size) . " bytes)";
});

step("Compile SCSS to CSS if scssphp exists; otherwise copy", function () use ($scssFile, $cssFile) {
    if (!file_exists($scssFile)) {
        // Nothing to do; ensure CSS exists
        if (!file_exists($cssFile)) {
            throw new RuntimeException("Neither styles.scss nor styles.css found in assets/");
        }
        return "SCSS not found; using existing CSS";
    }
    // Try scssphp (if available as a single-file include or installed via composer)
    $compiled = false;
    $errors = [];

    // Common locations: vendor autoload, or single-file include
    $attempts = [
        function () {
            // Composer autoload (if present)
            $vendor = __DIR__ . '/vendor/autoload.php';
            if (file_exists($vendor)) require_once $vendor;
            return class_exists('\\ScssPhp\\ScssPhp\\Compiler');
        },
        function () {
            // Single-file include if bundled manually
            $single = __DIR__ . '/vendor/scssphp/scss.inc.php';
            if (file_exists($single)) require_once $single;
            return class_exists('\\ScssPhp\\ScssPhp\\Compiler');
        },
    ];

    foreach ($attempts as $try) {
        try {
            $try();
        } catch (Throwable $e) { /* ignore */
        }
        if (class_exists('\\ScssPhp\\ScssPhp\\Compiler')) {
            try {
                $compiler = new \ScssPhp\ScssPhp\Compiler();
                $scss = file_get_contents($scssFile) ?: '';
                $css = $compiler->compileString($scss)->getCss();
                file_put_contents($cssFile, "/* compiled by php-init */\n" . $css);
                $compiled = true;
                break;
            } catch (Throwable $e) {
                $errors[] = $e->getMessage();
            }
        }
    }

    if (!$compiled) {
        // Fallback: copy SCSS to CSS (most browsers will ignore SCSS-only syntax that isn't valid CSS)
        // Prefer precompiled CSS in production.
        $banner = "/* NOTE: SCSS was not compiled on this host. This is a fallback copy. Use real CSS in production. */\n";
        $scss = file_get_contents($scssFile) ?: '';
        file_put_contents($cssFile, $banner . $scss);
        return "scssphp not available; copied styles.scss -> styles.css";
    }
    return "SCSS compiled to CSS";
});

// Create a demo category and event for visual verification
step("Insert demo category and event for today", function () {
    require_once __DIR__ . '/db.php';
    $pdo = db();

    // Find admin user
    $uStmt = $pdo->prepare('SELECT id FROM users WHERE username = :u LIMIT 1');
    $uStmt->execute([':u' => 'admin']);
    $admin = $uStmt->fetch(PDO::FETCH_ASSOC);
    if (!$admin) {
        throw new RuntimeException("Admin user not found after seed");
    }
    $owner = $admin['id'];

    // Ensure a 'Demo' category exists
    $cSel = $pdo->prepare('SELECT id FROM categories WHERE owner_id = :o AND name = :n LIMIT 1');
    $cSel->execute([':o' => $owner, ':n' => 'Demo']);
    $cat = $cSel->fetch(PDO::FETCH_ASSOC);
    if ($cat) {
        $catId = $cat['id'];
    } else {
        $catId = uuid();
        $now = gmdate('c');
        $cIns = $pdo->prepare('INSERT INTO categories (id, owner_id, name, color, sort_order, created_at, updated_at) VALUES (:id, :o, :n, :c, :s, :ca, :ua)');
        $cIns->execute([
            ':id' => $catId, ':o' => $owner, ':n' => 'Demo',
            ':c' => '#f59e0b', ':s' => 99, ':ca' => $now, ':ua' => $now
        ]);
    }

    // Insert a sample event at today's 10:00 local for 30 minutes
    $now = new DateTimeImmutable('now');
    // derive local date key and convert to UTC ISO strings for storage
    $localDate = $now->format('Y-m-d');
    $startLocal = DateTimeImmutable::createFromFormat('Y-m-d H:i', $localDate . ' 10:00');
    $endLocal   = DateTimeImmutable::createFromFormat('Y-m-d H:i', $localDate . ' 10:30');
    if (!$startLocal || !$endLocal) {
        throw new RuntimeException("Failed to compute demo event times");
    }
    // Store as ISO 8601 in UTC but keep day_key as local date
    $startUtc = $startLocal->setTimezone(new DateTimeZone('UTC'))->format('c');
    $endUtc   = $endLocal->setTimezone(new DateTimeZone('UTC'))->format('c');
    $dayKey   = $localDate;

    // If a demo event already exists for today, skip insert
    $eSel = $pdo->prepare('SELECT COUNT(*) FROM events WHERE owner_id = :o AND day_key = :d AND title = :t');
    $eSel->execute([':o' => $owner, ':d' => $dayKey, ':t' => 'Demo: Welcome!']);
    if ((int)$eSel->fetchColumn() === 0) {
        $eIns = $pdo->prepare('INSERT INTO events (id, owner_id, category_id, start_at, end_at, day_key, all_day, timezone, title, description, created_at, updated_at)
                               VALUES (:id, :o, :c, :s, :e, :d, 0, :tz, :title, :desc, :ca, :ua)');
        $id = uuid();
        $nowIso = gmdate('c');
        $tzName = (new DateTimeZone(date_default_timezone_get()))->getName();
        $eIns->execute([
            ':id' => $id,
            ':o'  => $owner,
            ':c'  => $catId,
            ':s'  => $startUtc,
            ':e'  => $endUtc,
            ':d'  => $dayKey,
            ':tz' => $tzName,
            ':title' => 'Demo: Welcome!',
            ':desc'  => 'Click any slot to add your own event. This is a demo entry.',
            ':ca' => $nowIso,
            ':ua' => $nowIso,
        ]);
        return "Inserted demo event for " . $dayKey . " (10:00–10:30)";
    }
    return "Demo event already present for " . $dayKey;
});

// Summaries
$summary = [
    'users' => 0, 'categories' => 0, 'events' => 0, 'db_path' => $dbFile
];
step("Count rows and verify DB", function () use (&$summary) {
    require_once __DIR__ . '/db.php';
    $pdo = db();
    $summary['users'] = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    $summary['categories'] = (int)$pdo->query('SELECT COUNT(*) FROM categories')->fetchColumn();
    $summary['events'] = (int)$pdo->query('SELECT COUNT(*) FROM events')->fetchColumn();
    return "users={$summary['users']}, categories={$summary['categories']}, events={$summary['events']}";
});

?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8" />
    <title>Task Manager Init</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
    body {
        font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
        margin: 20px;
        color: #0f172a;
    }

    .ok {
        color: #16a34a;
    }

    .err {
        color: #dc2626;
    }

    pre {
        background: #0b1020;
        color: #e5e7eb;
        padding: 10px;
        border-radius: 6px;
        overflow: auto;
    }

    .card {
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        padding: 16px;
        margin-top: 16px;
    }

    a.btn {
        display: inline-block;
        padding: 8px 12px;
        background: #1f2937;
        color: #fff;
        border-radius: 6px;
        text-decoration: none;
    }
    </style>
</head>

<body>
    <h1>Task Manager — Initialization</h1>
    <div class="card">
        <h2>Steps</h2>
        <ul>
            <?php foreach ($results as [$type, $msg]) : ?>
            <li class="<?= htmlspecialchars($type) ?>"><?= htmlspecialchars($msg) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>

    <div class="card">
        <h2>Summary</h2>
        <pre><?php echo htmlspecialchars(json_encode($summary, JSON_PRETTY_PRINT), ENT_QUOTES); ?></pre>
        <p>Database location: <strong><?php echo htmlspecialchars($summary['db_path'], ENT_QUOTES); ?></strong></p>
    </div>

    <?php if ($ok) : ?>
    <p><a class="btn" href="./index.php">Go to the app</a></p>
    <p>After confirming everything works, for security, please delete <code>php-init.php</code> from the server.</p>
    <?php else : ?>
    <p class="err">Some steps failed. Fix the issues above and reload this page.</p>
    <?php endif; ?>
</body>

</html>
```
```php name=schema.sql
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
  id         TEXT PRIMARY KEY,
  username   TEXT UNIQUE NOT NULL,
  pw_hash    TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS categories (
  id         TEXT PRIMARY KEY,
  owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  color      TEXT NOT NULL DEFAULT '#60a5fa',
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(owner_id, name)
);

CREATE TABLE IF NOT EXISTS events (
  id          TEXT PRIMARY KEY,
  owner_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category_id TEXT REFERENCES categories(id) ON DELETE SET NULL,
  start_at    TEXT NOT NULL,   -- ISO 8601 UTC
  end_at      TEXT NOT NULL,   -- ISO 8601 UTC
  day_key     TEXT NOT NULL,   -- YYYY-MM-DD local date of start time
  all_day     INTEGER NOT NULL DEFAULT 0,
  timezone    TEXT NOT NULL DEFAULT 'UTC',
  title       TEXT,
  description TEXT,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_day ON events(day_key);
CREATE INDEX IF NOT EXISTS idx_events_start ON events(start_at);

-- Brute-force protection
CREATE TABLE IF NOT EXISTS login_throttle (
  ip           TEXT NOT NULL,
  username     TEXT NOT NULL,
  fail_count   INTEGER NOT NULL DEFAULT 0,
  last_fail_at TEXT,
  locked_until TEXT,
  PRIMARY KEY (ip, username)
);
CREATE INDEX IF NOT EXISTS idx_login_throttle_locked ON login_throttle(locked_until);
```
```php name=README.md
Here’s a complete, final package overview plus a new init-db.php you can run once to initialize (or reset) the SQLite database. I also included short, ordered steps to follow and quick sanity checks.

Full architecture tree

Text
Desktop/taskmanager/
├─ index.php
├─ api.php
├─ init-db.php ← new: one-click DB initializer/reset
├─ php-init.php (optional initializer; safe to keep or delete)
├─ bootstrap.php
├─ db.php
├─ auth.php
├─ schema.sql
├─ README.md
├─ assets/
│ ├─ app.js
│ ├─ styles.scss
│ ├─ styles.css
│ └─ icon.png (optional)
└─ data/
├─ .htaccess (blocks web access to DB)
└─ app.sqlite (created at runtime)

```

```scss name=assets/scss/main.scss

```

```javascript name=assets/js/app.js
(function () {
  // Build context from DOM (no inline script needed)
  const loggedAttr = document.body
    ? document.body.getAttribute("data-logged-in")
    : "0";
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const ctx = {
    loggedIn: loggedAttr === "1",
    csrf: csrfMeta ? csrfMeta.content : "",
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
  };

  // Utilities
  const qs = (sel, el = document) => el.querySelector(sel);
  const qsa = (sel, el = document) => Array.from(el.querySelectorAll(sel));
  const ce = (tag, props = {}) =>
    Object.assign(document.createElement(tag), props);
  const pad = (n) => String(n).padStart(2, "0");

  function fmtDateHeader(d) {
    const opts = {
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "numeric",
    };
    return d.toLocaleString(undefined, opts);
  }
  function dateKey(d) {
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  }
  function addDays(d, days) {
    const x = new Date(d.getTime());
    x.setDate(x.getDate() + days);
    return x;
  }
  function atTime(d, hh, mm) {
    return new Date(d.getFullYear(), d.getMonth(), d.getDate(), hh, mm, 0, 0);
  }
  function toIsoZ(dLocal) {
    return dLocal.toISOString();
  }
  function parseIsoZ(iso) {
    return new Date(iso);
  }
  function snap15(minutes) {
    return Math.round(minutes / 15) * 15;
  }

  const API = {
    async login(username, password) {
      const res = await fetch("./api.php?action=login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || "Login failed");
      return body;
    },
    async logout() {
      const res = await fetch("./api.php?action=logout", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": ctx.csrf,
        },
        body: "{}",
      });
      if (!res.ok) throw new Error("Logout failed");
      return res.json();
    },
    async listCategories() {
      const res = await fetch("./api.php?action=list_categories");
      if (!res.ok) throw new Error("Failed to load categories");
      return res.json();
    },
    async addCategory(name, color) {
      const res = await fetch("./api.php?action=add_category", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": ctx.csrf,
        },
        body: JSON.stringify({ name, color }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || "Failed to add category");
      return body;
    },
    async listEventsByDay(dayKey) {
      const res = await fetch(
        "./api.php?action=list_events_by_day&day_key=" +
          encodeURIComponent(dayKey)
      );
      if (!res.ok) throw new Error("Failed to load events");
      return res.json();
    },
    async addEvent(payload) {
      const res = await fetch("./api.php?action=add_event", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": ctx.csrf,
        },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || "Failed to add event");
      return body;
    },
    async updateEvent(payload) {
      const res = await fetch("./api.php?action=update_event", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": ctx.csrf,
        },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || "Failed to update event");
      return body;
    },
    async deleteEvent(id) {
      const res = await fetch("./api.php?action=delete_event", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": ctx.csrf,
        },
        body: JSON.stringify({ id }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || "Failed to delete event");
      return body;
    },
  };

  // State
  const state = {
    selectedDate: new Date(),
    categories: [],
    events: [],
    view: "day", // 'day' | 'week' | 'month'
  };

  // Login
  function initLogin() {
    const btn = qs("#btn-login");
    const username = qs("#username");
    const password = qs("#password");

    async function doLogin() {
      btn.disabled = true;
      const prev = btn.textContent;
      btn.textContent = "Signing in...";
      try {
        await API.login(username.value.trim(), password.value);
        window.location.reload();
      } catch (e) {
        alert(e.message || "Login failed");
      } finally {
        btn.disabled = false;
        btn.textContent = prev;
      }
    }
    btn?.addEventListener("click", doLogin);
    password?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doLogin();
    });
  }

  // Day grid rendering
  function renderTimeCol(selectedDate) {
    const col = qs("#time-col");
    if (!col) return;
    col.innerHTML = "";
    const start = atTime(selectedDate, 8, 0);
    for (let i = 0; i < 96; i++) {
      const cell = ce("div", { className: "time-cell" });
      const t = new Date(start.getTime() + i * 15 * 60000);
      cell.textContent = t.getMinutes() === 0 ? `${pad(t.getHours())}:00` : "";
      col.appendChild(cell);
    }
  }

  function renderSlots(selectedDate) {
    const slotCol = qs("#slot-col");
    if (!slotCol) return;
    slotCol.innerHTML = "";
    const start = atTime(selectedDate, 8, 0);
    for (let i = 0; i < 96; i++) {
      const slot = ce("div", { className: "slot" });
      const slotTime = new Date(start.getTime() + i * 15 * 60000);
      slot.title = slotTime.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
      slot.addEventListener("click", () => openCreateEventModal(slotTime));
      slotCol.appendChild(slot);
    }
  }

  function minutesBetween(a, b) {
    return Math.round((b.getTime() - a.getTime()) / 60000);
  }
  function clearEventsUI() {
    qsa(".event-chip").forEach((el) => el.remove());
  }

  // Drag/resize state
  let dragState = null; // { type: 'move'|'resize', id, originalStart, originalEnd, startY, pxPerMin, dayStart, dayEnd, chipEl }
  function attachDragAndEditBehavior(chip, ev, dayStart, dayEnd) {
    // Edit on double-click
    chip.addEventListener("dblclick", (e) => {
      e.stopPropagation();
      openEditEventModal(ev);
    });
    // Delete via context menu (right-click)
    chip.addEventListener("contextmenu", async (e) => {
      e.preventDefault();
      const ok = confirm(`Delete this event?\n\n${ev.title || ""}`);
      if (ok) {
        try {
          await API.deleteEvent(ev.id);
          await loadEventsForDay(state.selectedDate);
        } catch (err) {
          alert(err.message || "Failed to delete");
        }
      }
    });

    // Create a bottom resize handle
    const handle = ce("div");
    handle.style.position = "absolute";
    handle.style.left = "0";
    handle.style.right = "0";
    handle.style.bottom = "0";
    handle.style.height = "6px";
    handle.style.cursor = "ns-resize";
    handle.style.background = "rgba(255,255,255,0.2)";
    chip.appendChild(handle);

    const pxPer15 = 18;
    const pxPerMin = pxPer15 / 15;

    chip.style.cursor = "move";
    chip.addEventListener("mousedown", (e) => {
      // Ignore if clicked on handle (it will have its own mousedown)
      if (e.target === handle) return;
      if (state.view !== "day") return;

      dragState = {
        type: "move",
        id: ev.id,
        originalStart: parseIsoZ(ev.start_at),
        originalEnd: parseIsoZ(ev.end_at),
        startY: e.clientY,
        pxPerMin,
        dayStart,
        dayEnd,
        chipEl: chip,
      };
      e.preventDefault();
    });

    handle.addEventListener("mousedown", (e) => {
      if (state.view !== "day") return;
      dragState = {
        type: "resize",
        id: ev.id,
        originalStart: parseIsoZ(ev.start_at),
        originalEnd: parseIsoZ(ev.end_at),
        startY: e.clientY,
        pxPerMin,
        dayStart,
        dayEnd,
        chipEl: chip,
      };
      e.preventDefault();
      e.stopPropagation();
    });
  }

  function onMouseMove(e) {
    if (!dragState) return;
    const deltaPx = e.clientY - dragState.startY;
    const deltaMinRaw = deltaPx / dragState.pxPerMin;
    const deltaMin = snap15(deltaMinRaw);

    if (dragState.type === "move") {
      const newStart = new Date(
        dragState.originalStart.getTime() + deltaMin * 60000
      );
      const duration =
        dragState.originalEnd.getTime() - dragState.originalStart.getTime();
      const newEnd = new Date(newStart.getTime() + duration);

      // clamp to day window [08:00, next 08:00]
      if (newStart < dragState.dayStart || newEnd > dragState.dayEnd) return;

      // visual feedback
      const topMin = minutesBetween(dragState.dayStart, newStart);
      dragState.chipEl.style.top = `${Math.floor(
        topMin * dragState.pxPerMin
      )}px`;
    } else if (dragState.type === "resize") {
      const newEnd = new Date(
        dragState.originalEnd.getTime() + deltaMin * 60000
      );
      // min duration 15 minutes, clamp to dayEnd
      const minEnd = new Date(dragState.originalStart.getTime() + 15 * 60000);
      if (newEnd < minEnd || newEnd > dragState.dayEnd) return;

      const durationMin = minutesBetween(dragState.originalStart, newEnd);
      dragState.chipEl.style.height = `${Math.max(
        16,
        Math.floor(durationMin * dragState.pxPerMin) - 2
      )}px`;
    }
  }

  async function onMouseUp(e) {
    if (!dragState) return;
    const deltaPx = e.clientY - dragState.startY;
    const deltaMinRaw = deltaPx / dragState.pxPerMin;
    const deltaMin = snap15(deltaMinRaw);

    try {
      if (dragState.type === "move") {
        let newStart = new Date(
          dragState.originalStart.getTime() + deltaMin * 60000
        );
        let newEnd = new Date(
          dragState.originalEnd.getTime() + deltaMin * 60000
        );
        if (newStart < dragState.dayStart) {
          newEnd = new Date(newEnd.getTime() + (dragState.dayStart - newStart));
          newStart = new Date(dragState.dayStart);
        }
        if (newEnd > dragState.dayEnd) {
          const diff = newEnd.getTime() - dragState.dayEnd.getTime();
          newStart = new Date(newStart.getTime() - diff);
          newEnd = new Date(dragState.dayEnd);
        }

        await API.updateEvent({
          id: dragState.id,
          start_at_utc: toIsoZ(newStart),
          end_at_utc: toIsoZ(newEnd),
          day_key: dateKey(newStart),
          timezone: ctx.tz,
        });
      } else if (dragState.type === "resize") {
        let newEnd = new Date(
          dragState.originalEnd.getTime() + deltaMin * 60000
        );
        const minEnd = new Date(dragState.originalStart.getTime() + 15 * 60000);
        if (newEnd < minEnd) newEnd = minEnd;
        if (newEnd > dragState.dayEnd) newEnd = dragState.dayEnd;

        await API.updateEvent({
          id: dragState.id,
          end_at_utc: toIsoZ(newEnd),
          day_key: dateKey(dragState.originalStart),
          timezone: ctx.tz,
        });
      }
      await loadEventsForDay(state.selectedDate);
    } catch (err) {
      alert(err.message || "Failed to update");
      await loadEventsForDay(state.selectedDate);
    } finally {
      dragState = null;
    }
  }

  function renderEvents(selectedDate) {
    clearEventsUI();
    const slotCol = qs("#slot-col");
    if (!slotCol) return;

    const dayStart = atTime(selectedDate, 8, 0);
    const dayEnd = atTime(addDays(selectedDate, 1), 8, 0);
    const pxPer15 = 18; // must match CSS row height
    const pxPerMin = pxPer15 / 15;

    state.events.forEach((ev) => {
      const start = parseIsoZ(ev.start_at);
      const end = parseIsoZ(ev.end_at);

      // Clamp to visible window
      const visStart = start < dayStart ? dayStart : start;
      const visEnd = end > dayEnd ? dayEnd : end;
      if (visEnd <= dayStart || visStart >= dayEnd) return;

      const topMin = Math.max(0, minutesBetween(dayStart, visStart));
      const durMin = Math.max(15, minutesBetween(visStart, visEnd)); // minimum 15min

      const chip = ce("div", { className: "event-chip" });
      chip.style.top = `${Math.floor(topMin * pxPerMin)}px`;
      chip.style.height = `${Math.max(
        16,
        Math.floor(durMin * pxPerMin) - 2
      )}px`;
      chip.style.background = ev.category_color || "#60a5fa";
      chip.style.color = "#0b0f16";
      chip.style.position = "absolute";
      chip.style.left = "72px";
      chip.style.right = "12px";

      const title = ce("div", {
        className: "title",
        textContent: ev.title || "(no title)",
      });
      const time = ce("div", {
        className: "time",
        textContent: `${start.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        })} – ${end.toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        })}`,
      });

      chip.appendChild(title);
      chip.appendChild(time);

      // Attach drag, resize, edit, delete behaviors
      attachDragAndEditBehavior(chip, ev, dayStart, dayEnd);

      slotCol.appendChild(chip);
    });
  }

  function closeModal() {
    const root = qs("#modal-root");
    if (!root) return;
    root.classList.remove("show");
    root.innerHTML = "";
  }

  function openCreateEventModal(slotTimeLocal) {
    const root = qs("#modal-root");
    if (!root) return;
    root.innerHTML = "";
    root.classList.add("show");
    const backdrop = ce("div", { className: "modal-backdrop" });
    const modal = ce("div", { className: "modal card" });
    const h3 = ce("h3", { textContent: "Add Event" });

    const form = ce("form");
    form.innerHTML = `
      <div class="form-grid">
        <div>
          <label class="label">Category</label>
          <select class="select" id="ev-category"><option value="">No category</option></select>
        </div>
        <div>
          <label class="label">Time</label>
          <input class="input" id="ev-time" type="time" step="900" />
        </div>
        <div class="col-span-2">
          <label class="label">Title</label>
          <input class="input" id="ev-title" type="text" placeholder="Title">
        </div>
        <div class="col-span-2">
          <label class="label">Description</label>
          <textarea class="textarea" id="ev-desc" placeholder="Description (optional)"></textarea>
        </div>
      </div>
      <div class="hstack" style="justify-content:flex-end; gap:8px; margin-top:12px;">
        <button type="button" class="btn" id="ev-cancel">Cancel</button>
        <button type="submit" class="btn primary" id="ev-save">Save</button>
      </div>
    `;

    const sel = form.querySelector("#ev-category");
    state.categories.forEach((c) => {
      const opt = ce("option", { value: c.id, textContent: c.name });
      opt.style.backgroundColor = c.color;
      sel.appendChild(opt);
    });

    const tInput = form.querySelector("#ev-time");
    tInput.value = `${pad(slotTimeLocal.getHours())}:${pad(
      slotTimeLocal.getMinutes()
    )}`;

    form
      .querySelector("#ev-cancel")
      .addEventListener("click", () => closeModal());
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const title = form.querySelector("#ev-title").value.trim();
      const description = form.querySelector("#ev-desc").value.trim();
      const category_id = form.querySelector("#ev-category").value || null;
      const [hh, mm] = tInput.value
        .split(":")
        .map((x) => parseInt(x || "0", 10));
      if (!title) {
        alert("Title is required");
        return;
      }
      const startLocal = atTime(state.selectedDate, hh, mm);
      const endLocal = new Date(startLocal.getTime() + 30 * 60000);

      try {
        await API.addEvent({
          category_id,
          title,
          description,
          start_at_utc: toIsoZ(startLocal),
          end_at_utc: toIsoZ(endLocal),
          day_key: dateKey(state.selectedDate),
          timezone: ctx.tz,
        });
        closeModal();
        await loadEventsForDay(state.selectedDate);
      } catch (err) {
        alert(err.message || "Failed to save");
      }
    });

    modal.appendChild(h3);
    modal.appendChild(form);
    root.appendChild(backdrop);
    root.appendChild(modal);
    backdrop.addEventListener("click", closeModal);
  }

  function openEditEventModal(ev) {
    const root = qs("#modal-root");
    if (!root) return;
    root.innerHTML = "";
    root.classList.add("show");
    const backdrop = ce("div", { className: "modal-backdrop" });
    const modal = ce("div", { className: "modal card" });
    const h3 = ce("h3", { textContent: "Edit Event" });

    const start = parseIsoZ(ev.start_at);
    const form = ce("form");
    form.innerHTML = `
      <div class="form-grid">
        <div>
          <label class="label">Category</label>
          <select class="select" id="ev-category"><option value="">No category</option></select>
        </div>
        <div>
          <label class="label">Time</label>
          <input class="input" id="ev-time" type="time" step="900" />
        </div>
        <div class="col-span-2">
          <label class="label">Title</label>
          <input class="input" id="ev-title" type="text">
        </div>
        <div class="col-span-2">
          <label class="label">Description</label>
          <textarea class="textarea" id="ev-desc"></textarea>
        </div>
      </div>
      <div class="hstack" style="justify-content:space-between; gap:8px; margin-top:12px;">
        <button type="button" class="btn danger" id="ev-delete">Delete</button>
        <div>
          <button type="button" class="btn" id="ev-cancel">Cancel</button>
          <button type="submit" class="btn primary" id="ev-save">Save</button>
        </div>
      </div>
    `;

    // Fill categories
    const sel = form.querySelector("#ev-category");
    state.categories.forEach((c) => {
      const opt = ce("option", { value: c.id, textContent: c.name });
      opt.style.backgroundColor = c.color;
      sel.appendChild(opt);
    });
    sel.value = ev.category_id || "";

    // Fill time/title/desc
    form.querySelector("#ev-time").value = `${pad(start.getHours())}:${pad(
      start.getMinutes()
    )}`;
    form.querySelector("#ev-title").value = ev.title || "";
    form.querySelector("#ev-desc").value = ev.description || "";

    form
      .querySelector("#ev-cancel")
      .addEventListener("click", () => closeModal());
    form.querySelector("#ev-delete").addEventListener("click", async () => {
      const ok = confirm("Delete this event?");
      if (!ok) return;
      try {
        await API.deleteEvent(ev.id);
        closeModal();
        await loadEventsForDay(state.selectedDate);
      } catch (err) {
        alert(err.message || "Failed to delete");
      }
    });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const title = form.querySelector("#ev-title").value.trim();
      const description = form.querySelector("#ev-desc").value.trim();
      const category_id = form.querySelector("#ev-category").value || null;
      const [hh, mm] = form
        .querySelector("#ev-time")
        .value.split(":")
        .map((x) => parseInt(x || "0", 10));
      if (!title) {
        alert("Title is required");
        return;
      }

      // compute new start local using selectedDate's date
      const startLocal = atTime(state.selectedDate, hh, mm);
      const oldStart = parseIsoZ(ev.start_at);
      const endLocal = new Date(
        startLocal.getTime() +
          (parseIsoZ(ev.end_at).getTime() - oldStart.getTime())
      );

      try {
        await API.updateEvent({
          id: ev.id,
          title,
          description,
          category_id,
          start_at_utc: toIsoZ(startLocal),
          end_at_utc: toIsoZ(endLocal),
          day_key: dateKey(startLocal),
          timezone: ctx.tz,
        });
        closeModal();
        await loadEventsForDay(state.selectedDate);
      } catch (err) {
        alert(err.message || "Failed to update");
      }
    });

    modal.appendChild(h3);
    modal.appendChild(form);
    root.appendChild(backdrop);
    root.appendChild(modal);
    backdrop.addEventListener("click", closeModal);
  }

  // Mini calendar (left)
  function startOfMonth(d) {
    return new Date(d.getFullYear(), d.getMonth(), 1);
  }
  function endOfMonth(d) {
    return new Date(d.getFullYear(), d.getMonth() + 1, 0);
  }
  function startOfWeek(d) {
    const x = new Date(d.getTime());
    const dow = x.getDay();
    x.setDate(x.getDate() - dow);
    x.setHours(0, 0, 0, 0);
    return x;
  }
  function addMonths(d, n) {
    return new Date(d.getFullYear(), d.getMonth() + n, d.getDate());
  }

  let miniMonthAnchor = new Date();
  function renderMiniCalendar() {
    const wrap = qs("#mini-calendar");
    if (!wrap) return;
    wrap.innerHTML = "";
    const header = document.createElement("div");
    header.className = "month-header";
    const prev = ce("button", { className: "btn", textContent: "‹" });
    const next = ce("button", { className: "btn", textContent: "›" });
    const label = ce("div", { style: "font-weight:600;" });
    label.textContent = miniMonthAnchor.toLocaleString(undefined, {
      month: "long",
      year: "numeric",
    });
    header.appendChild(prev);
    header.appendChild(label);
    header.appendChild(next);

    prev.addEventListener("click", () => {
      miniMonthAnchor = addMonths(miniMonthAnchor, -1);
      renderMiniCalendar();
    });
    next.addEventListener("click", () => {
      miniMonthAnchor = addMonths(miniMonthAnchor, +1);
      renderMiniCalendar();
    });

    const grid = ce("div", { className: "month-grid" });
    const dayNames = [];
    for (let i = 0; i < 7; i++) {
      const d = new Date(2020, 5, 7 + i);
      dayNames.push(d.toLocaleString(undefined, { weekday: "short" }));
    }
    dayNames.forEach((name) =>
      grid.appendChild(ce("div", { className: "day-name", textContent: name }))
    );

    const first = startOfMonth(miniMonthAnchor);
    const gridStart = startOfWeek(first);
    for (let i = 0; i < 42; i++) {
      const d = new Date(
        gridStart.getFullYear(),
        gridStart.getMonth(),
        gridStart.getDate() + i
      );
      const btn = ce("button", {
        className: "day-cell",
        textContent: String(d.getDate()),
      });
      if (d.getMonth() !== miniMonthAnchor.getMonth()) btn.classList.add("out");
      const today = new Date();
      if (d.toDateString() === today.toDateString()) btn.classList.add("today");
      if (d.toDateString() === state.selectedDate.toDateString())
        btn.classList.add("selected");
      btn.addEventListener("click", async () => {
        state.selectedDate = new Date(
          d.getFullYear(),
          d.getMonth(),
          d.getDate()
        );
        updateHeaderDate();
        renderView();
        await loadEventsForDay(state.selectedDate);
        renderMiniCalendar();
      });
      grid.appendChild(btn);
    }

    wrap.appendChild(header);
    wrap.appendChild(grid);
  }

  // Week + Month simple renderers to make buttons functional
  function renderWeek() {
    const gridWrap = qs(".grid-wrap");
    if (!gridWrap) return;
    gridWrap.innerHTML = "";

    const start = startOfWeek(state.selectedDate);
    const container = ce("div", { className: "card", style: "padding:12px;" });
    const title = ce("div", {
      style: "font-weight:600; margin-bottom:8px;",
      textContent: `Week of ${start.toLocaleDateString()}`,
    });
    container.appendChild(title);

    // For simplicity, fetch each day's events (7 calls). Can optimize later with a range API.
    const list = ce("div");
    container.appendChild(list);
    gridWrap.appendChild(container);

    (async () => {
      list.textContent = "Loading week...";
      const days = [];
      for (let i = 0; i < 7; i++) days.push(addDays(start, i));
      const all = [];
      for (const d of days) {
        try {
          const { events } = await API.listEventsByDay(dateKey(d));
          all.push({ day: d, events: events || [] });
        } catch {
          all.push({ day: d, events: [] });
        }
      }
      list.innerHTML = "";
      all.forEach(({ day, events }) => {
        const dayRow = ce("div", { style: "margin-bottom:10px;" });
        const h = ce("div", {
          style: "font-weight:600;",
          textContent: day.toLocaleDateString(undefined, {
            weekday: "short",
            month: "short",
            day: "numeric",
          }),
        });
        dayRow.appendChild(h);
        if (events.length === 0) {
          dayRow.appendChild(
            ce("div", { className: "small-note", textContent: "No events" })
          );
        } else {
          events.forEach((ev) => {
            const s = parseIsoZ(ev.start_at).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            });
            const e = parseIsoZ(ev.end_at).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            });
            const row = ce("div", { className: "hstack" });
            const dot = ce("span", { className: "badge", textContent: " " });
            dot.style.background = ev.category_color || "#60a5fa";
            dot.style.borderColor = dot.style.background;
            const a = ce("a", {
              href: "#",
              textContent: `${s}–${e} ${ev.title || ""}`,
              style: "margin-left:6px;",
            });
            a.addEventListener("click", (e2) => {
              e2.preventDefault();
              state.selectedDate = new Date(
                day.getFullYear(),
                day.getMonth(),
                day.getDate()
              );
              state.view = "day";
              updateHeaderDate();
              renderView();
              loadEventsForDay(state.selectedDate);
            });
            row.appendChild(dot);
            row.appendChild(a);
            dayRow.appendChild(row);
          });
        }
        list.appendChild(dayRow);
      });
    })();
  }

  // Replace your existing renderMonth() with this version

  function renderMonth() {
    const gridWrap = document.querySelector(".grid-wrap");
    if (!gridWrap) return;
    gridWrap.innerHTML = "";

    // Container
    const container = Object.assign(document.createElement("div"), {
      className: "month",
    });

    // Header label for current month
    const header = Object.assign(document.createElement("div"), {
      className: "month-header",
    });
    const label = Object.assign(document.createElement("div"), {
      style: "font-weight:600;",
    });
    label.textContent = state.selectedDate.toLocaleString(undefined, {
      month: "long",
      year: "numeric",
    });
    header.appendChild(label);
    container.appendChild(header);

    // Grid
    const grid = Object.assign(document.createElement("div"), {
      className: "month-grid",
    });

    // Day names (Sun..Sat)
    for (let i = 0; i < 7; i++) {
      const d = new Date(2020, 5, 7 + i);
      grid.appendChild(
        Object.assign(document.createElement("div"), {
          className: "day-name",
          textContent: d.toLocaleString(undefined, { weekday: "short" }),
        })
      );
    }

    // 6 weeks grid starting from the week of the first day of the month
    const first = new Date(
      state.selectedDate.getFullYear(),
      state.selectedDate.getMonth(),
      1
    );
    const gridStart = (function startOfWeek(d) {
      const x = new Date(d.getTime());
      const dow = x.getDay(); // 0=Sun..6=Sat
      x.setDate(x.getDate() - dow);
      x.setHours(0, 0, 0, 0);
      return x;
    })(first);

    for (let i = 0; i < 42; i++) {
      const d = new Date(
        gridStart.getFullYear(),
        gridStart.getMonth(),
        gridStart.getDate() + i
      );
      const btn = Object.assign(document.createElement("button"), {
        className: "day-cell",
        textContent: String(d.getDate()),
      });

      if (d.getMonth() !== state.selectedDate.getMonth())
        btn.classList.add("out");
      const today = new Date();
      if (d.toDateString() === today.toDateString()) btn.classList.add("today");
      if (d.toDateString() === state.selectedDate.toDateString())
        btn.classList.add("selected");

      btn.addEventListener("click", async () => {
        state.selectedDate = new Date(
          d.getFullYear(),
          d.getMonth(),
          d.getDate()
        );
        state.view = "day";
        updateHeaderDate();
        renderView();
        await loadEventsForDay(state.selectedDate);
      });

      grid.appendChild(btn);
    }

    container.appendChild(grid);
    gridWrap.appendChild(container);
  }

  // Events loading
  async function loadEventsForDay(d) {
    try {
      const { events } = await API.listEventsByDay(dateKey(d));
      state.events = events || [];
      if (state.view === "day") renderEvents(d);
    } catch (e) {
      console.error(e);
      alert("Failed to load events");
    }
  }
  function updateHeaderDate() {
    const el = qs("#current-date");
    if (el) el.textContent = fmtDateHeader(state.selectedDate);
  }

  // Topbar wiring and view switching
  function setViewButtons() {
    const day = qs("#btn-day");
    const week = qs("#btn-week");
    const month = qs("#btn-month");
    [day, week, month].forEach((b) => b && b.classList.remove("active"));
    if (state.view === "day") day && day.classList.add("active");
    if (state.view === "week") week && week.classList.add("active");
    if (state.view === "month") month && month.classList.add("active");
  }

  function renderView() {
    setViewButtons();
    const gridWrap = qs(".grid-wrap");
    if (!gridWrap) return;

    if (state.view === "day") {
      // Make sure day grid exists
      gridWrap.innerHTML = `
        <div id="day-grid" class="day-grid">
          <div class="time-col" id="time-col"></div>
          <div class="slot-col" id="slot-col"></div>
        </div>
      `;
      updateHeaderDate();
      renderTimeCol(state.selectedDate);
      renderSlots(state.selectedDate);
      renderEvents(state.selectedDate);
    } else if (state.view === "week") {
      updateHeaderDate();
      renderWeek();
    } else if (state.view === "month") {
      updateHeaderDate();
      renderMonth();
    }
  }

  function wireTopbar() {
    const btnPrev = qs("#btn-prev");
    const btnNext = qs("#btn-next");
    const btnToday = qs("#btn-today");
    const btnDay = qs("#btn-day");
    const btnWeek = qs("#btn-week");
    const btnMonth = qs("#btn-month");

    btnPrev?.addEventListener("click", async () => {
      const delta =
        state.view === "day" ? -1 : state.view === "week" ? -7 : -30;
      state.selectedDate = addDays(state.selectedDate, delta);
      renderView();
      if (state.view === "day") await loadEventsForDay(state.selectedDate);
    });

    btnNext?.addEventListener("click", async () => {
      const delta = state.view === "day" ? 1 : state.view === "week" ? 7 : 30;
      state.selectedDate = addDays(state.selectedDate, delta);
      renderView();
      if (state.view === "day") await loadEventsForDay(state.selectedDate);
    });

    btnToday?.addEventListener("click", async () => {
      state.selectedDate = new Date();
      renderView();
      if (state.view === "day") await loadEventsForDay(state.selectedDate);
    });

    btnDay?.addEventListener("click", async () => {
      state.view = "day";
      renderView();
      await loadEventsForDay(state.selectedDate);
    });
    btnWeek?.addEventListener("click", () => {
      state.view = "week";
      renderView();
    });
    btnMonth?.addEventListener("click", () => {
      state.view = "month";
      renderView();
    });
  }

  function wireSidebar() {
    const addCat = qs("#btn-add-category");
    addCat?.addEventListener("click", async () => {
      const name = prompt("Category name");
      if (!name) return;
      let color = prompt("Color (hex like #60a5fa) or leave blank for default");
      if (!color) color = "#60a5fa";
      try {
        await API.addCategory(name.trim(), color.trim());
        await loadCategories();
      } catch (e) {
        alert(e.message || "Failed to add category");
      }
    });
    const btnLogout = qs("#btn-logout");
    btnLogout?.addEventListener("click", async () => {
      if (!confirm("Sign out?")) return;
      try {
        await API.logout();
        window.location.reload();
      } catch (e) {
        alert("Failed to logout");
      }
    });
  }

  async function initApp() {
    if (!ctx.loggedIn) {
      initLogin();
      return;
    }
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);

    renderView();
    wireTopbar();
    wireSidebar();
    await loadCategories();
    await loadEventsForDay(state.selectedDate);
  }
  document.addEventListener("DOMContentLoaded", initApp);
})();

// load category
// Add/restore these two functions (place above wireSidebar)

async function loadCategories() {
  try {
    const { categories } = await API.listCategories();
    state.categories = categories || [];
    renderCategoryList();
  } catch (e) {
    console.error(e);
    alert("Failed to load categories");
  }
}

function renderCategoryList() {
  const list = document.querySelector("#category-list");
  if (!list) return;
  list.innerHTML = "";

  if (!state.categories.length) {
    list.appendChild(
      Object.assign(document.createElement("div"), {
        className: "small-note",
        textContent: "No categories yet.",
      })
    );
    return;
  }

  state.categories.forEach((c) => {
    const row = Object.assign(document.createElement("div"), {
      className: "hstack",
    });

    const swatch = Object.assign(document.createElement("span"), {
      className: "badge",
      textContent: " ",
    });
    swatch.style.background = c.color;
    swatch.style.borderColor = c.color;
    swatch.style.width = "14px";
    swatch.style.height = "14px";
    swatch.style.display = "inline-block";
    swatch.style.borderRadius = "999px";

    const name = Object.assign(document.createElement("div"), {
      textContent: c.name,
      style: "margin-left:6px; flex:1;",
    });

    row.appendChild(swatch);
    row.appendChild(name);
    list.appendChild(row);
  });
}


```

```javascript name=assets/js/styles.scss


```

```javascript name=assets/styles.css
/* compiled or fallback CSS; if php-init cannot compile SCSS, this file is used as-is */
:root {
  --bg: #0f1115;
  --panel: #141821;
  --panel-2: #1a2030;
  --text: #e6edf3;
  --muted: #94a3b8;
  --accent: #60a5fa;
  --accent-2: #22d3ee;
  --danger: #ef4444;
  --success: #22c55e;
  --warning: #f59e0b;
  --border: #253047;
  --slot: #131a27;
  --slot-alt: #0f1521;
  --today: #1f2a44;
  --shadow: rgba(0, 0, 0, 0.4);
  --sidebar-w: 240px;
  --radius: 8px;
  --radius-sm: 6px;
  --radius-lg: 12px;
  --grid-border: #253047;
  --slot-hover: #1f2a44;
}

* {
  box-sizing: border-box;
}
html,
body {
  height: 100%;
}
body {
  margin: 0;
  background: linear-gradient(180deg, var(--bg), #0b0d12 60%);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu,
    Cantarell, Noto Sans, Arial, "Apple Color Emoji", "Segoe UI Emoji";
}

a {
  color: var(--accent);
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}

button,
input,
select,
textarea {
  font-family: inherit;
  font-size: 14px;
  color: var(--text);
}

.container {
  display: grid;
  grid-template-columns: var(--sidebar-w) 1fr;
  height: 100vh;
}

.sidebar {
  padding: 16px;
  background: linear-gradient(180deg, var(--panel), var(--panel-2));
  border-right: 1px solid var(--border);
}

.main {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.topbar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  background: rgba(10, 12, 18, 0.5);
  backdrop-filter: blur(6px);
  position: sticky;
  top: 0;
  z-index: 10;
}

.hstack {
  display: flex;
  align-items: center;
  gap: 8px;
}
.spacer {
  flex: 1;
}

.btn {
  background: #111827;
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  cursor: pointer;
}
.btn:hover {
  background: #0e1626;
}
.btn.primary {
  background: linear-gradient(180deg, #1f3b63, #1a2e4a);
  border-color: #24406b;
}
.btn.danger {
  background: #3a0d12;
  border-color: #57151c;
  color: #ffd6db;
}
.btn.ghost {
  background: transparent;
  border-color: transparent;
  color: var(--muted);
}
.btn.active {
  outline: 2px solid var(--accent);
}

.input,
.select,
.textarea {
  width: 100%;
  background: #0c101a;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text);
  padding: 8px 10px;
}
.textarea {
  min-height: 80px;
  resize: vertical;
}

.card {
  background: linear-gradient(180deg, #0d121c, #0c121b);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: 0 10px 30px var(--shadow);
}

/* Login */
.login-wrap {
  height: 100vh;
  display: grid;
  place-items: center;
  padding: 16px;
}
.login {
  width: 100%;
  max-width: 380px;
  padding: 20px;
}
.login h1 {
  margin: 0 0 12px;
  font-size: 20px;
}
.login .muted {
  color: var(--muted);
  font-size: 13px;
  margin-bottom: 12px;
}
.login .row {
  display: grid;
  gap: 6px;
  margin-bottom: 10px;
}
.login .actions {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 8px;
}

/* Mini Calendar */
.month {
  display: grid;
  gap: 10px;
}
.month-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.month-grid {
  display: grid;
  grid-template-columns: repeat(7, 1fr);
  gap: 4px;
}
.day-name {
  text-align: center;
  font-size: 12px;
  color: var(--muted);
}
.day-cell {
  border: 1px solid var(--border);
  border-radius: 6px;
  text-align: center;
  padding: 6px 0;
  cursor: pointer;
  background: #0d1422;
}
.day-cell.out {
  opacity: 0.4;
}
.day-cell.today {
  outline: 2px solid var(--accent-2);
}
.day-cell.selected {
  background: var(--today);
  border-color: #2c3b61;
}
.day-cell:hover {
  background: #0f1a2b;
}

/* Main calendar grid */
.grid-wrap {
  padding: 12px;
  overflow: auto;
  height: calc(100vh - 52px);
}
.day-grid {
  display: grid;
  grid-template-columns: 64px 1fr;
}
.time-col {
  display: grid;
  grid-template-rows: repeat(96, 18px);
  border-right: 1px solid var(--grid-border);
}
.slot-col {
  position: relative;
  display: grid;
  grid-template-rows: repeat(96, 18px);
}
.time-cell {
  font-size: 11px;
  color: var(--muted);
  padding-right: 6px;
  display: flex;
  align-items: flex-start;
  justify-content: flex-end;
}
.slot {
  border-bottom: 1px dashed #1c2942;
  background: var(--slot);
}
.slot:nth-child(4n) {
  border-bottom: 1px solid var(--grid-border);
  background: var(--slot-alt);
}
.slot:hover {
  background: var(--slot-hover);
  cursor: pointer;
}

/* Event chips */
.event-chip {
  position: absolute;
  left: 72px;
  right: 12px;
  border-radius: 6px;
  padding: 6px 8px;
  font-size: 12px;
  color: #0b0f16;
  background: #60a5fa; /* JS may override to category color */
  border: 1px solid rgba(255, 255, 255, 0.6);
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.35);
  overflow: hidden;
}
.event-chip .title {
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.event-chip .time {
  font-size: 11px;
  opacity: 0.8;
}

/* Modal */
.modal-root {
  position: fixed;
  inset: 0;
  display: none;
  align-items: center;
  justify-content: center;
}
.modal-root.show {
  display: flex;
}
.modal-backdrop {
  position: absolute;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
}
.modal {
  position: relative;
  width: min(560px, 94vw);
  z-index: 2;
  padding: 16px;
}
.modal h3 {
  margin: 0 0 10px;
}

/* Badges and misc */
.badge {
  padding: 2px 6px;
  font-size: 11px;
  border: 1px solid var(--border);
  border-radius: 999px;
  color: var(--muted);
}

/* Forms */
.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}
.form-grid .col-span-2 {
  grid-column: span 2;
}
.label {
  font-size: 12px;
  color: var(--muted);
}

/* Footer small note */
.small-note {
  font-size: 12px;
  color: var(--muted);
}

```
