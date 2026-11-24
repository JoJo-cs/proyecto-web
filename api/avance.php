<?php
/**
 *
 * Para correrlo:   php -S localhost:8000 -t api
 * Luego abre:      http://localhost:8000/avance.php
 */

declare(strict_types=1);

date_default_timezone_set('America/Mexico_City');
const DIAS = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado'];
const TIPOS = ['obligatoria', 'optativa', 'electiva'];

// Solo se usa para importar tus datos viejos la primera vez (en local).
const ARCHIVO = __DIR__ . '/../datos.json';

/* ------------------------------------------------------------------ */
/* Base de datos (PDO)                                                 */
/* Vercel: define DATABASE_URL (Postgres, p. ej. Neon). Local: SQLite. */
/* ------------------------------------------------------------------ */

function db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }

    $url = getenv('DATABASE_URL') ?: getenv('POSTGRES_URL') ?: '';
    if ($url !== '') {
        $p   = parse_url($url);
        $dsn = sprintf('pgsql:host=%s;port=%d;dbname=%s;sslmode=require',
            $p['host'], $p['port'] ?? 5432, ltrim($p['path'] ?? '', '/'));
        $pdo = new PDO($dsn, rawurldecode($p['user'] ?? ''), rawurldecode($p['pass'] ?? ''));
    } else {
        $pdo = new PDO('sqlite:' . __DIR__ . '/../avance.sqlite');
    }
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('CREATE TABLE IF NOT EXISTS usuarios (id VARCHAR(32) PRIMARY KEY, usuario VARCHAR(30) UNIQUE NOT NULL, clave TEXT NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS datos_usuario (usuario_id VARCHAR(32) PRIMARY KEY, contenido TEXT NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS sesiones (id VARCHAR(128) PRIMARY KEY, datos TEXT NOT NULL, actualizado BIGINT NOT NULL)');
    return $pdo;
}

// En Vercel no hay disco persistente: las sesiones (token CSRF y avisos) también van a la BD.
final class SesionBD implements SessionHandlerInterface
{
    public function open(string $path, string $name): bool { return true; }
    public function close(): bool { return true; }

    public function read(string $id): string|false
    {
        $s = db()->prepare('SELECT datos FROM sesiones WHERE id = ?');
        $s->execute([$id]);
        return (string) ($s->fetchColumn() ?: '');
    }

    public function write(string $id, string $data): bool
    {
        $s = db()->prepare('INSERT INTO sesiones (id, datos, actualizado) VALUES (?, ?, ?)
            ON CONFLICT (id) DO UPDATE SET datos = excluded.datos, actualizado = excluded.actualizado');
        return $s->execute([$id, $data, time()]);
    }

    public function destroy(string $id): bool
    {
        return db()->prepare('DELETE FROM sesiones WHERE id = ?')->execute([$id]);
    }

    public function gc(int $max_lifetime): int|false
    {
        $s = db()->prepare('DELETE FROM sesiones WHERE actualizado < ?');
        $s->execute([time() - $max_lifetime]);
        return $s->rowCount();
    }
}

// Sesión de 30 días (por defecto PHP la borra a los ~24 min de inactividad).
ini_set('session.gc_maxlifetime', '2592000');
session_set_cookie_params([
    'lifetime' => 2592000,
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => !empty($_SERVER['HTTPS']) || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https',
]);
session_set_save_handler(new SesionBD(), true);
session_start();
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

/* ------------------------------------------------------------------ */
/* Almacenamiento                                                      */
/* ------------------------------------------------------------------ */

function datosPorDefecto(): array
{
    return [
        'carrera'        => 'Mi carrera',
        'creditosPlan'   => 300,
        'minAprobatoria' => 6.0,
        'materias'       => [],
        'minTipo'        => ['obligatoria' => 0.0, 'optativa' => 0.0, 'electiva' => 0.0],
        'agenda'         => [],
        'horario'        => [],
    ];
}

function cargar(): array
{
    $s = db()->prepare('SELECT contenido FROM datos_usuario WHERE usuario_id = ?');
    $s->execute([$_SESSION['uid']]);
    $contenido = $s->fetchColumn();
    $json = json_decode((string) $contenido, true);
    if (!is_array($json)) {
        return datosPorDefecto();
    }
    return array_merge(datosPorDefecto(), $json);
}

function guardar(array $datos): ?string
{
    try {
        $s = db()->prepare('INSERT INTO datos_usuario (usuario_id, contenido) VALUES (?, ?)
            ON CONFLICT (usuario_id) DO UPDATE SET contenido = excluded.contenido');
        $s->execute([$_SESSION['uid'], json_encode($datos, JSON_UNESCAPED_UNICODE)]);
        return null;
    } catch (PDOException $e) {
        return 'No se pudo guardar en la base de datos.';
    }
}

/* ------------------------------------------------------------------ */
/* Cuentas: registro e inicio de sesión (cada usuario con sus datos)   */
/* ------------------------------------------------------------------ */

$errorLogin    = null;
$errorRegistro = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && in_array($_POST['accion'] ?? '', ['login', 'registro', 'logout'], true)) {
    if (!hash_equals($_SESSION['csrf'], (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(403);
        exit('Token de seguridad inválido. Recarga la página e inténtalo de nuevo.');
    }
    $accionCuenta = $_POST['accion'];
    $usuario      = strtolower(texto('usuario'));
    $claveForm    = (string) ($_POST['clave'] ?? '');

    if ($accionCuenta === 'logout') {
        session_destroy();
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    if ($accionCuenta === 'login') {
        $s = db()->prepare('SELECT id, clave FROM usuarios WHERE usuario = ?');
        $s->execute([$usuario]);
        $fila = $s->fetch(PDO::FETCH_ASSOC);
        if ($fila && password_verify($claveForm, $fila['clave'])) {
            session_regenerate_id(true);
            $_SESSION['uid'] = $fila['id'];
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        }
        sleep(1);   // frena un poco los intentos de adivinar contraseñas
        $errorLogin = 'Usuario o contraseña incorrectos.';
    }

    if ($accionCuenta === 'registro') {
        if (!preg_match('/^[a-z0-9_.-]{3,30}$/', $usuario)) {
            $errorRegistro = 'El usuario debe tener de 3 a 30 caracteres: letras, números, punto, guion o guion bajo.';
        } elseif (strlen($claveForm) < 8) {
            $errorRegistro = 'La contraseña debe tener al menos 8 caracteres.';
        } elseif ($claveForm !== (string) ($_POST['clave2'] ?? '')) {
            $errorRegistro = 'Las contraseñas no coinciden.';
        } else {
            $id = bin2hex(random_bytes(16));
            try {
                $primero = (int) db()->query('SELECT COUNT(*) FROM usuarios')->fetchColumn() === 0;
                db()->prepare('INSERT INTO usuarios (id, usuario, clave) VALUES (?, ?, ?)')
                    ->execute([$id, $usuario, password_hash($claveForm, PASSWORD_DEFAULT)]);
                if ($primero && is_file(ARCHIVO)) {   // la primera cuenta hereda tu datos.json local
                    db()->prepare('INSERT INTO datos_usuario (usuario_id, contenido) VALUES (?, ?)')
                        ->execute([$id, (string) file_get_contents(ARCHIVO)]);
                }
                session_regenerate_id(true);
                $_SESSION['uid'] = $id;
                header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
                exit;
            } catch (PDOException $e) {
                $errorRegistro = in_array((string) $e->getCode(), ['23505', '23000'], true)
                    ? 'Ese usuario ya existe. Elige otro.'
                    : 'No se pudo crear la cuenta.';
            }
        }
    }
}

if (empty($_SESSION['uid'])) {
    http_response_code($errorLogin ? 401 : 200);
    ?><!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Acceder · Avance académico</title>
<style>
  body{font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#E7EBF1;color:#101B2D}
  .caja{background:#fff;padding:28px;border-radius:12px;box-shadow:0 6px 18px rgba(16,27,45,.1);width:min(320px,90vw)}
  h1{font-size:1.2rem;margin:0 0 8px}
  input,button{font:inherit;width:100%;box-sizing:border-box;padding:9px 10px;border-radius:8px;border:1px solid #CFD6E0;margin-top:8px}
  button{margin-top:12px;background:#101B2D;color:#fff;border-color:#101B2D;cursor:pointer}
  details{margin-top:18px;border-top:1px solid #CFD6E0;padding-top:14px}
  summary{cursor:pointer;color:#5A6779;font-size:.9rem}
  .mal{color:#9B1B30;margin:10px 0 0;font-size:.9rem}
  @media (prefers-color-scheme:dark){body{background:#0D1420;color:#E6EBF2}.caja{background:#162030}input{background:#162030;color:inherit;border-color:#2B3850}button{background:#E6EBF2;color:#0D1420;border-color:#E6EBF2}details{border-color:#2B3850}summary{color:#9AA6B8}.mal{color:#F27A8F}}
</style>
</head>
<body>
<div class="caja">
  <h1>Avance académico</h1>
  <form method="post">
    <input type="hidden" name="accion" value="login"><?= csrf() ?>
    <input name="usuario" placeholder="Usuario" autocomplete="username" required autofocus value="<?= $errorLogin ? e($usuario ?? '') : '' ?>">
    <input type="password" name="clave" placeholder="Contraseña" autocomplete="current-password" required>
    <button type="submit">Entrar</button>
    <?php if ($errorLogin): ?><p class="mal"><?= e($errorLogin) ?></p><?php endif; ?>
  </form>
  <details <?= $errorRegistro ? 'open' : '' ?>>
    <summary>Crear una cuenta</summary>
    <form method="post">
      <input type="hidden" name="accion" value="registro"><?= csrf() ?>
      <input name="usuario" placeholder="Usuario (3 a 30 caracteres)" autocomplete="username" required value="<?= $errorRegistro ? e($usuario ?? '') : '' ?>">
      <input type="password" name="clave" placeholder="Contraseña (mínimo 8)" autocomplete="new-password" minlength="8" required>
      <input type="password" name="clave2" placeholder="Repite la contraseña" autocomplete="new-password" minlength="8" required>
      <button type="submit">Crear cuenta</button>
      <?php if ($errorRegistro): ?><p class="mal"><?= e($errorRegistro) ?></p><?php endif; ?>
    </form>
  </details>
</div>
</body>
</html>
<?php
    exit;
}

/* ------------------------------------------------------------------ */
/* Acciones                                                            */
/* ------------------------------------------------------------------ */

$datos  = cargar();
$error  = null;
$aviso  = $_SESSION['aviso'] ?? null;
unset($_SESSION['aviso']);

function num(string $campo, float $porDefecto = 0.0): float
{
    $v = str_replace(',', '.', trim((string) ($_POST[$campo] ?? '')));
    return is_numeric($v) ? (float) $v : $porDefecto;
}

function texto(string $campo): string
{
    return trim((string) ($_POST[$campo] ?? ''));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && !hash_equals($_SESSION['csrf'], (string) ($_POST['csrf'] ?? ''))) {
    http_response_code(403);
    exit('Token de seguridad inválido. Recarga la página e inténtalo de nuevo.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $accion = $_POST['accion'] ?? '';

    if ($accion === 'plan') {
        $datos['carrera']        = texto('carrera') !== '' ? texto('carrera') : 'Mi carrera';
        $datos['creditosPlan']   = max(1.0, num('creditosPlan', 300));
        $datos['minAprobatoria'] = min(10.0, max(0.0, num('minAprobatoria', 6)));
        foreach (TIPOS as $t) { $datos['minTipo'][$t] = max(0.0, num('min_' . $t)); }
        $error = guardar($datos);
        $aviso = $error ? null : 'Plan de estudios actualizado.';
    }

    if ($accion === 'agregar') {
        $nombre = texto('nombre');
        if ($nombre === '') {
            $error = 'Escribe el nombre de la materia para agregarla.';
        } else {
            $cal    = texto('calificacion');
            $estado = in_array($_POST['estado'] ?? '', ['aprobada', 'cursando', 'pendiente'], true)
                ? $_POST['estado'] : 'pendiente';

            $datos['materias'][] = [
                'id'           => uniqid('m', true),
                'nombre'       => $nombre,
                'semestre'     => (int) max(0, num('semestre', 1)),
                'creditos'     => max(0.0, num('creditos', 0)),
                'calificacion' => $cal === '' ? null : min(10.0, max(0.0, num('calificacion'))),
                'estado'       => $estado,
                'tipo'         => in_array($_POST['tipo'] ?? '', TIPOS, true) ? $_POST['tipo'] : 'obligatoria',
                'evals'        => [],
            ];
            $error = guardar($datos);
            $aviso = $error ? null : 'Materia agregada.';
        }
    }

    if ($accion === 'actualizar') {
        $id = $_POST['id'] ?? '';
        foreach ($datos['materias'] as $i => $m) {
            if ($m['id'] === $id) {
                $cal = texto('calificacion');
                $datos['materias'][$i]['nombre']       = texto('nombre') !== '' ? texto('nombre') : $m['nombre'];
                $datos['materias'][$i]['semestre']     = (int) max(0, num('semestre', (float) $m['semestre']));
                $datos['materias'][$i]['creditos']     = max(0.0, num('creditos', (float) $m['creditos']));
                $datos['materias'][$i]['calificacion'] = $cal === '' ? null : min(10.0, max(0.0, num('calificacion')));
                $datos['materias'][$i]['estado']       = in_array($_POST['estado'] ?? '', ['aprobada', 'cursando', 'pendiente'], true)
                    ? $_POST['estado'] : $m['estado'];
                $datos['materias'][$i]['tipo'] = in_array($_POST['tipo'] ?? '', TIPOS, true) ? $_POST['tipo'] : ($m['tipo'] ?? 'obligatoria');
                break;
            }
        }
        $error = guardar($datos);
        $aviso = $error ? null : 'Cambios guardados.';
    }

    if ($accion === 'eliminar') {
        $id = $_POST['id'] ?? '';
        $datos['materias'] = array_values(array_filter(
            $datos['materias'],
            static fn(array $m): bool => $m['id'] !== $id
        ));
        $error = guardar($datos);
        $aviso = $error ? null : 'Materia eliminada.';
    }

    if ($accion === 'vaciar') {
        $datos['materias'] = [];
        $error = guardar($datos);
        $aviso = $error ? null : 'Se borraron todas las materias.';
    }

    if ($accion === 'evals') {
        $id = $_POST['id'] ?? '';
        $nom = (array) ($_POST['ev_nombre'] ?? []); $pes = (array) ($_POST['ev_peso'] ?? []); $cls = (array) ($_POST['ev_cal'] ?? []);
        $ev = [];
        foreach ($nom as $k => $n) {
            $n = trim((string) $n);
            $p = str_replace(',', '.', trim((string) ($pes[$k] ?? '')));
            $c = str_replace(',', '.', trim((string) ($cls[$k] ?? '')));
            if ($n === '' || !is_numeric($p) || (float) $p <= 0) { continue; }
            $ev[] = ['nombre' => $n, 'peso' => min(100.0, (float) $p), 'cal' => is_numeric($c) ? min(10.0, max(0.0, (float) $c)) : null];
        }
        foreach ($datos['materias'] as $i => $m) { if ($m['id'] === $id) { $datos['materias'][$i]['evals'] = $ev; } }
        $error = guardar($datos);
        $aviso = $error ? null : 'Evaluaciones guardadas.';
    }

    if ($accion === 'agenda_add') {
        $t = texto('titulo'); $f = texto('fecha');
        if ($t === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $f)) {
            $error = 'Escribe un título y una fecha válida para la agenda.';
        } else {
            $datos['agenda'][] = ['id' => uniqid('a', true), 'titulo' => $t, 'fecha' => $f, 'materia' => texto('materia'),
                'tipo' => ($_POST['tipo'] ?? '') === 'examen' ? 'examen' : 'entrega', 'hecho' => false];
            $error = guardar($datos);
            $aviso = $error ? null : 'Agregado a la agenda.';
        }
    }

    if ($accion === 'agenda_hecho' || $accion === 'agenda_del') {
        $id = $_POST['id'] ?? '';
        foreach ($datos['agenda'] as $i => $a) {
            if ($a['id'] !== $id) { continue; }
            if ($accion === 'agenda_del') { unset($datos['agenda'][$i]); } else { $datos['agenda'][$i]['hecho'] = !$a['hecho']; }
        }
        $datos['agenda'] = array_values($datos['agenda']);
        $error = guardar($datos);
        $aviso = $error ? null : 'Agenda actualizada.';
    }

    if ($accion === 'horario_add') {
        $dia = (int) ($_POST['dia'] ?? -1); $ini = texto('inicio'); $fin = texto('fin');
        if (!isset(DIAS[$dia]) || !preg_match('/^\d{2}:\d{2}$/', $ini) || !preg_match('/^\d{2}:\d{2}$/', $fin) || $fin <= $ini || texto('materia') === '') {
            $error = 'Indica materia, día y un horario válido (la hora de fin debe ser posterior al inicio).';
        } else {
            $datos['horario'][] = ['id' => uniqid('h', true), 'dia' => $dia, 'inicio' => $ini, 'fin' => $fin, 'materia' => texto('materia'), 'salon' => texto('salon')];
            $error = guardar($datos);
            $aviso = $error ? null : 'Clase agregada al horario.';
        }
    }

    if ($accion === 'horario_del') {
        $id = $_POST['id'] ?? '';
        $datos['horario'] = array_values(array_filter($datos['horario'], static fn(array $h): bool => $h['id'] !== $id));
        $error = guardar($datos);
        $aviso = $error ? null : 'Clase eliminada del horario.';
    }

    // Post/Redirect/Get: evita que F5 reenvíe el formulario.
    if ($error === null && $aviso !== null) {
        $_SESSION['aviso'] = $aviso;
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }
}

/* ------------------------------------------------------------------ */
/* Cálculos                                                            */
/* ------------------------------------------------------------------ */

$min          = (float) $datos['minAprobatoria'];
$plan         = (float) $datos['creditosPlan'];
$materias     = $datos['materias'];

usort($materias, static function (array $a, array $b): int {
    return [$a['semestre'], $a['nombre']] <=> [$b['semestre'], $b['nombre']];
});

$credAprobados = 0.0;
$credCursando  = 0.0;
$credTotalPlan = 0.0;   // créditos capturados, sirve para avisar si el plan no cuadra
$sumaPonderada = 0.0;
$sumaCreditos  = 0.0;
$sumaSimple    = 0.0;
$conteoSimple  = 0;
$reprobadas    = 0;

foreach ($materias as $m) {
    $cr  = (float) $m['creditos'];
    $cal = $m['calificacion'];
    $credTotalPlan += $cr;

    $aprobada = $m['estado'] === 'aprobada' && ($cal === null || (float) $cal >= $min);

    if ($aprobada) {
        $credAprobados += $cr;
    } elseif ($m['estado'] === 'cursando') {
        $credCursando += $cr;
    }

    if ($cal !== null) {
        if ((float) $cal < $min) {
            $reprobadas++;
        }
        if ($aprobada) {
            $sumaPonderada += (float) $cal * $cr;
            $sumaCreditos  += $cr;
            $sumaSimple    += (float) $cal;
            $conteoSimple++;
        }
    }
}

$promPonderado = $sumaCreditos > 0 ? $sumaPonderada / $sumaCreditos : null;
$promSimple    = $conteoSimple > 0 ? $sumaSimple / $conteoSimple : null;
$avance        = $plan > 0 ? min(100.0, $credAprobados / $plan * 100) : 0.0;
$avanceCurso   = $plan > 0 ? min(100.0, ($credAprobados + $credCursando) / $plan * 100) : 0.0;
$faltan        = max(0.0, $plan - $credAprobados);

// Créditos por tipo, por semestre y distribución de calificaciones (solo materias acreditadas)
$credTipo = array_fill_keys(TIPOS, 0.0);
$porSem   = [];
$dist     = ['<6' => 0, '6' => 0, '7' => 0, '8' => 0, '9' => 0, '10' => 0];
foreach ($materias as $m) {
    $cal = $m['calificacion'];
    if ($m['estado'] !== 'aprobada' || ($cal !== null && (float) $cal < $min)) { continue; }
    $t = in_array($m['tipo'] ?? '', TIPOS, true) ? $m['tipo'] : 'obligatoria';
    $credTipo[$t] += (float) $m['creditos'];
    $s = (int) $m['semestre'];
    $porSem[$s]['cred'] = ($porSem[$s]['cred'] ?? 0.0) + (float) $m['creditos'];
    if ($cal !== null) {
        $porSem[$s]['suma'] = ($porSem[$s]['suma'] ?? 0.0) + (float) $cal;
        $porSem[$s]['n']    = ($porSem[$s]['n'] ?? 0) + 1;
        $dist[(float) $cal < 6 ? '<6' : (string) (int) floor((float) $cal)]++;
    }
}
ksort($porSem);
$gProm = []; $gCred = [];
foreach ($porSem as $s => $v) {
    $gCred['S' . $s] = $v['cred'];
    if (!empty($v['n'])) { $gProm['S' . $s] = $v['suma'] / $v['n']; }
}

// Horario: clases agrupadas por día y ordenadas por hora de inicio
$horario = $datos['horario'];
usort($horario, static fn(array $a, array $b): int => $a['inicio'] <=> $b['inicio']);

// Agenda: ordenada por fecha; "próximos" = pendientes que vencen en 7 días o ya vencidos
$agenda = $datos['agenda'];
usort($agenda, static fn(array $a, array $b): int => $a['fecha'] <=> $b['fecha']);
$proximos = array_filter($agenda, static fn(array $a): bool => !$a['hecho'] && dias($a['fecha']) <= 7);

/**porcentaje de créditos y el trámite que desbloquean. */
$hitos = [
    ['pct' => 50,  'titulo' => 'Prácticas profesionales',   'detalle' => 'La mayoría de los planes las abre a la mitad de los créditos.'],
    ['pct' => 70,  'titulo' => 'Servicio social',           'detalle' => 'Requisito típico para registrar tu programa ante Servicios Escolares.'],
    ['pct' => 90,  'titulo' => 'Trámite de titulación',     'detalle' => 'Buen momento para elegir modalidad y juntar documentos.'],
    ['pct' => 100, 'titulo' => 'Egreso',                    'detalle' => 'Plan de estudios cubierto al cien.'],
];

foreach ($hitos as $i => $h) {
    $necesarios          = $plan * $h['pct'] / 100;
    $hitos[$i]['creditos'] = $necesarios;
    $hitos[$i]['listo']    = $credAprobados >= $necesarios;
    $hitos[$i]['faltan']   = max(0.0, $necesarios - $credAprobados);
}

$proximo = null;
foreach ($hitos as $h) {
    if (!$h['listo']) { $proximo = $h; break; }
}

function e(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

function fmt(?float $n, int $dec = 1): string
{
    return $n === null ? '—' : number_format($n, $dec, '.', ',');
}
function csrf(): string
{
    return '<input type="hidden" name="csrf" value="' . e($_SESSION['csrf']) . '">';
}

function dias(string $fecha): int
{
    return (int) (new DateTimeImmutable('today'))->diff(new DateTimeImmutable($fecha))->format('%r%a');
}

/** Calificación acumulada y lo que se necesita en lo que falta para llegar al mínimo. */
function evalResumen(array $evs, float $min): string
{
    $acum = 0.0; $hecho = 0.0; $total = 0.0;
    foreach ($evs as $v) {
        $total += (float) $v['peso'];
        if ($v['cal'] !== null) { $acum += (float) $v['cal'] * (float) $v['peso'] / 100; $hecho += (float) $v['peso']; }
    }
    if ($total <= 0) { return 'Sin evaluaciones'; }
    $resto = $total - $hecho;
    $pre = 'Acumulado ' . fmt($acum, 2) . ' · pesos ' . fmt($total, 0) . '%';
    if ($resto <= 0) { return $pre . ' · final ' . fmt($acum, 2) . ($acum >= $min ? ' ✓' : ' ✗'); }
    $nec = ($min - $acum) / ($resto / 100);
    if ($nec <= 0) { return $pre . ' · ya aseguraste el mínimo'; }
    if ($nec > 10) { return $pre . ' · ya no alcanzas el mínimo'; }
    return $pre . ' · necesitas ' . fmt($nec, 1) . ' en el ' . fmt($resto, 0) . '% restante';
}

/** Gráfica de barras en SVG (hereda colores del tema con variables CSS). */
function barras(array $d, int $dec = 1, float $max = 0.0): string
{
    if (!$d) { return '<p class="vacio">Sin datos todavía.</p>'; }
    $max = $max > 0 ? $max : max(1.0, (float) max($d));
    $w = 56; $h = 120; $o = '<svg viewBox="0 0 ' . (count($d) * $w) . ' ' . ($h + 36) . '" class="graf" role="img">'; $i = 0;
    foreach ($d as $k => $v) {
        $bh = $v / $max * $h; $x = $i * $w + 10; $c = $i * $w + $w / 2; $i++;
        $o .= '<rect x="' . $x . '" y="' . (16 + $h - $bh) . '" width="' . ($w - 20) . '" height="' . $bh . '" rx="3"/>'
            . '<text x="' . $c . '" y="' . (12 + $h - $bh) . '" class="gv">' . fmt((float) $v, $dec) . '</text>'
            . '<text x="' . $c . '" y="' . ($h + 32) . '">' . e((string) $k) . '</text>';
    }
    return $o . '</svg>';
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script>try{var t=localStorage.getItem("tema")||(matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light");document.documentElement.dataset.theme=t}catch(e){}</script>
<title>Avance académico · <?= e($datos['carrera']) ?></title>
<style>
  :root{
    --tinta:#101B2D;
    --tinta-suave:#5A6779;
    --papel:#E7EBF1;
    --superficie:#FFFFFF;
    --linea:#CFD6E0;
    --jade:#0E7A5F;
    --ambar:#B4690E;
    --carmin:#9B1B30;
    --radio:12px;
    --hover:#F4F7FB;--p1:#B7D8CE;--p2:#CBE3DB;
    --ok-bg:#E3F2EC;--ok-bd:#9CCEBD;--ok-tx:#0B5C48;--mal-bg:#FBE7EB;--mal-bd:#E0A8B4;
    --sombra:0 1px 2px rgba(16,27,45,.06),0 6px 18px rgba(16,27,45,.06);
  }
  :root[data-theme=dark]{
    --tinta:#E6EBF2;--tinta-suave:#9AA6B8;--papel:#0D1420;--superficie:#162030;--linea:#2B3850;
    --jade:#36C49C;--ambar:#E3A650;--carmin:#F27A8F;--hover:#1B2739;--p1:#1D4A40;--p2:#245649;
    --ok-bg:#12332B;--ok-bd:#1F6B58;--ok-tx:#8FE3C8;--mal-bg:#3A1823;--mal-bd:#7A2E42;
    --sombra:0 1px 2px rgba(0,0,0,.4),0 6px 18px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box}
  html{-webkit-text-size-adjust:100%}
  body{
    margin:0;
    background:var(--papel);
    color:var(--tinta);
    font:16px/1.55 "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-variant-numeric:tabular-nums;
  }
  .envoltura{max-width:1040px;margin:0 auto;padding:32px 20px 72px}
  h1{font-size:1.45rem;font-weight:600;letter-spacing:-.01em;margin:0}
  h2{font-size:1.05rem;font-weight:600;margin:0 0 14px}
  p{margin:0 0 10px}
  a{color:var(--jade)}

  header.cabecera{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:baseline;justify-content:space-between;margin-bottom:22px}
  header.cabecera span{color:var(--tinta-suave);font-size:.9rem}

  .tarjeta{box-shadow:var(--sombra);background:var(--superficie);border:1px solid var(--linea);border-radius:var(--radio);padding:22px;margin-bottom:22px}

  /* --- Regla de avance (el elemento protagonista) --- */
  .regla-cifra{display:flex;align-items:flex-end;gap:12px;margin-bottom:4px}
  .regla-cifra strong{font-size:3.4rem;line-height:.95;font-weight:600;letter-spacing:-.03em}
  .regla-cifra small{color:var(--tinta-suave);font-size:.95rem;padding-bottom:6px}
  .barra{position:relative;height:30px;margin:30px 0 6px}
  .barra .canal{position:absolute;inset:0;background:var(--papel);border:1px solid var(--linea);border-radius:8px;overflow:hidden}
  .barra i{position:absolute;inset:0 auto 0 0;display:block;background:var(--jade)}
  .barra i.proyeccion{background:repeating-linear-gradient(135deg,var(--p1) 0 6px,var(--p2) 6px 12px)}
  .marca{position:absolute;top:-24px;bottom:-24px;width:1px;background:var(--tinta);opacity:.35}
  .marca b{position:absolute;top:-2px;left:4px;font-size:.72rem;font-weight:600;white-space:nowrap;color:var(--tinta-suave)}
  .marca.cumplida{background:var(--jade);opacity:1}
  .marca.cumplida b{color:var(--jade)}
  .pie-regla{display:flex;flex-wrap:wrap;gap:6px 20px;color:var(--tinta-suave);font-size:.88rem;margin-top:26px}
  .pie-regla em{font-style:normal;color:var(--tinta);font-weight:600}

  .rejilla{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1px;background:var(--linea);border:1px solid var(--linea);border-radius:var(--radio);overflow:hidden;margin-bottom:22px}
  .dato{background:var(--superficie);padding:16px 18px}
  .dato b{display:block;font-size:1.7rem;font-weight:600;letter-spacing:-.02em}
  .dato span{color:var(--tinta-suave);font-size:.85rem}

  /* --- Alertas --- */
  .hito{display:flex;gap:14px;align-items:flex-start;padding:13px 0;border-top:1px solid var(--linea)}
  .hito:first-of-type{border-top:0}
  .hito .sello{flex:0 0 auto;width:26px;height:26px;border-radius:50%;border:1px solid var(--linea);display:grid;place-items:center;font-size:.8rem;color:var(--tinta-suave)}
  .hito.listo .sello{background:var(--jade);border-color:var(--jade);color:var(--superficie)}
  .hito.siguiente .sello{border-color:var(--ambar);color:var(--ambar)}
  .hito h3{margin:0;font-size:.98rem;font-weight:600}
  .hito p{margin:2px 0 0;font-size:.87rem;color:var(--tinta-suave)}
  .hito.listo h3{color:var(--jade)}

  /* --- Tabla --- */
  .desliza{overflow-x:auto;margin:0 -22px;padding:0 22px}
  table{border-collapse:collapse;width:100%;min-width:780px;font-size:.93rem}
  th{text-align:left;font-weight:600;font-size:.82rem;color:var(--tinta-suave);padding:0 8px 8px;border-bottom:1px solid var(--linea)}
  td{padding:5px 8px;border-bottom:1px solid var(--papel);vertical-align:middle}
  tr:hover td{background:var(--hover)}
  td.numero{width:88px}
  .vacio{padding:26px 0;color:var(--tinta-suave)}

  input,select,button{font:inherit;color:inherit}
  input,select{width:100%;padding:6px 8px;border:1px solid var(--linea);border-radius:8px;background:var(--superficie)}
  input:focus-visible,select:focus-visible,button:focus-visible{outline:2px solid var(--jade);outline-offset:1px}
  button{cursor:pointer;border:1px solid var(--tinta);background:var(--tinta);color:var(--superficie);padding:8px 16px;font-weight:500;transition:opacity .15s;border-radius:8px}
  button.tenue{background:transparent;color:var(--tinta-suave);border-color:var(--linea);padding:5px 10px;font-size:.85rem}
  button.tenue:hover{color:var(--carmin);border-color:var(--carmin)}
  .acciones{display:flex;gap:6px}

  .fila-alta{display:grid;grid-template-columns:2.4fr .7fr .9fr .9fr 1.1fr auto;gap:10px;align-items:end}
  .campo label{display:block;font-size:.8rem;color:var(--tinta-suave);margin-bottom:4px}

  .marca-reprobada{color:var(--carmin);font-weight:600}
  .marca-aprobada{color:var(--jade)}

  .mensaje{padding:11px 14px;border-radius:8px;margin-bottom:18px;font-size:.92rem}
  .mensaje.ok{background:var(--ok-bg);border:1px solid var(--ok-bd);color:var(--ok-tx)}
  .mensaje.mal{background:var(--mal-bg);border:1px solid var(--mal-bd);color:var(--carmin)}
  .nota{font-size:.85rem;color:var(--tinta-suave)}

  .fila-alta.mat{grid-template-columns:2.4fr .7fr .9fr .9fr 1.1fr 1.1fr auto}
  button:hover{opacity:.88}
  .tema{float:right}
  .mensaje.alerta{background:var(--mal-bg);border:1px solid var(--ambar);color:var(--tinta)}
  .chip{display:inline-block;margin:2px 6px 2px 0;padding:2px 10px;border-radius:99px;background:var(--superficie);border:1px solid var(--ambar);font-size:.85rem}
  .inline{display:inline}
  .ag{display:flex;gap:10px;align-items:center;padding:9px 0;border-top:1px solid var(--linea)}
  .ag.hecho .tit{text-decoration:line-through;color:var(--tinta-suave)}
  .ag .tit{flex:1}.ag small{color:var(--tinta-suave)}
  .ins{font-size:.72rem;padding:1px 8px;border-radius:99px;border:1px solid var(--linea);color:var(--tinta-suave)}
  .ins.examen{border-color:var(--carmin);color:var(--carmin)}
  .graficas{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px}
  .graf{width:100%;max-height:190px}.graf rect{fill:var(--jade)}.graf text{fill:var(--tinta-suave);font-size:11px;text-anchor:middle}.graf text.gv{fill:var(--tinta);font-weight:600}
  .graficas h3{font-size:.9rem;margin:0 0 6px;color:var(--tinta-suave);font-weight:600}
  .tipo{display:grid;grid-template-columns:110px 1fr auto;gap:12px;align-items:center;padding:6px 0;font-size:.92rem}
  .mini{height:8px;background:var(--papel);border-radius:99px;overflow:hidden}.mini i{display:block;height:100%;background:var(--jade)}
  details.parcial{border-top:1px solid var(--linea);padding:10px 0}
  details.parcial summary{cursor:pointer;font-weight:600}details.parcial summary small{display:block;font-weight:400;color:var(--tinta-suave)}
  details.desplegable>summary{cursor:pointer;list-style:none;font-weight:600;font-size:1.05rem}
  details.desplegable>summary::before{content:'▸ ';color:var(--jade)}
  details.desplegable[open]>summary::before{content:'▾ '}
  .hor{display:grid;grid-template-columns:repeat(6,minmax(130px,1fr));gap:10px;margin-top:14px;overflow-x:auto}
  .hor h3{font-size:.8rem;color:var(--tinta-suave);margin:0 0 6px;text-transform:uppercase;letter-spacing:.04em}
  .clase{background:var(--papel);border-left:3px solid var(--jade);border-radius:8px;padding:7px 9px;margin-bottom:8px;font-size:.85rem;position:relative}
  .clase b{display:block;padding-right:18px}.clase small{color:var(--tinta-suave)}
  .clase form{position:absolute;top:4px;right:4px}.clase button{padding:0 6px;font-size:.8rem;line-height:1.4}
  .evs{display:grid;grid-template-columns:2fr 1fr 1fr;gap:8px;margin:10px 0}
  @media (max-width:760px){
    .fila-alta.mat{grid-template-columns:1fr 1fr}
    .fila-alta{grid-template-columns:1fr 1fr}
    .fila-alta .campo:first-child{grid-column:1 / -1}
    .fila-alta button{grid-column:1 / -1}
    .regla-cifra strong{font-size:2.6rem}
  }
</style>
</head>
<body>
<div class="envoltura">

  <header class="cabecera">
    <h1><?= e($datos['carrera']) ?></h1>
    <span><?= fmt($plan, 0) ?> créditos en el plan · aprueba con <?= fmt($min, 1) ?></span>
    <button type="button" class="tenue tema" id="tema">◐ Tema</button>
    <form method="post"><input type="hidden" name="accion" value="logout"><?= csrf() ?><button class="tenue" type="submit">Salir</button></form>
  </header>

  <?php if ($aviso): ?><div class="mensaje ok"><?= e($aviso) ?></div><?php endif; ?>
  <?php if ($error): ?><div class="mensaje mal"><?= e($error) ?></div><?php endif; ?>

  <?php if ($proximos): ?>
  <div class="mensaje alerta"><b>Próximamente:</b>
    <?php foreach ($proximos as $a): $d = dias($a['fecha']); ?>
      <span class="chip"><?= e($a['titulo']) ?> · <?= $d < 0 ? 'venció hace ' . -$d . ' d' : ($d === 0 ? 'hoy' : 'en ' . $d . ' d') ?></span>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

  <!-- Avance -->
  <section class="tarjeta">
    <div class="regla-cifra">
      <strong><?= fmt($avance, 1) ?>%</strong>
      <small>de la carrera cubierto · <?= fmt($credAprobados, 0) ?> de <?= fmt($plan, 0) ?> créditos</small>
    </div>

    <div class="barra">
      <div class="canal">
        <i class="proyeccion" style="width:<?= $avanceCurso ?>%"></i>
        <i style="width:<?= $avance ?>%"></i>
      </div>
      <?php foreach ($hitos as $h): if ($h['pct'] >= 100) continue; ?>
        <span class="marca <?= $h['listo'] ? 'cumplida' : '' ?>" style="left:<?= $h['pct'] ?>%">
          <b><?= $h['pct'] ?>%</b>
        </span>
      <?php endforeach; ?>
    </div>

    <div class="pie-regla">
      <span>Cursando ahora: <em><?= fmt($credCursando, 0) ?></em> créditos</span>
      <span>Te faltan <em><?= fmt($faltan, 0) ?></em> para terminar</span>
      <?php if ($proximo): ?>
        <span>Siguiente trámite: <em><?= e($proximo['titulo']) ?></em>
          <?= $proximo['faltan'] > 0 ? 'a ' . fmt($proximo['faltan'], 0) . ' créditos' : '' ?></span>
      <?php else: ?>
        <span><em>Cubriste todos los hitos del plan.</em></span>
      <?php endif; ?>
    </div>
  </section>

  <!-- Indicadores -->
  <div class="rejilla">
    <div class="dato"><b><?= fmt($promPonderado, 2) ?></b><span>Promedio ponderado por créditos</span></div>
    <div class="dato"><b><?= fmt($promSimple, 2) ?></b><span>Promedio simple de materias</span></div>
    <div class="dato"><b><?= fmt($credAprobados, 0) ?></b><span>Créditos acreditados</span></div>
    <div class="dato"><b<?= $reprobadas ? ' class="marca-reprobada"' : '' ?>><?= $reprobadas ?></b><span>Materias por debajo de <?= fmt($min, 1) ?></span></div>
  </div>

  <!-- Gráficas y créditos por tipo -->
  <section class="tarjeta">
    <h2>Análisis</h2>
    <div class="graficas">
      <div><h3>Promedio por semestre</h3><?= barras($gProm, 2, 10.0) ?></div>
      <div><h3>Créditos acreditados por semestre</h3><?= barras($gCred, 0) ?></div>
      <div><h3>Distribución de calificaciones</h3><?= barras($dist, 0) ?></div>
    </div>
    <h3 style="margin:22px 0 4px;font-size:.9rem;color:var(--tinta-suave)">Créditos por tipo de materia</h3>
    <?php foreach (TIPOS as $t): $mt = (float) $datos['minTipo'][$t]; $c = $credTipo[$t]; ?>
      <div class="tipo">
        <span><?= e(ucfirst($t)) ?></span>
        <div class="mini"><i style="width:<?= $mt > 0 ? min(100.0, $c / $mt * 100) : 0 ?>%"></i></div>
        <small><?= fmt($c, 0) ?><?= $mt > 0 ? ' de ' . fmt($mt, 0) . ' mínimos' : ' (sin mínimo definido)' ?></small>
      </div>
    <?php endforeach; ?>
  </section>

  <!-- Alertas de trámites -->
  <section class="tarjeta">
    <h2>Trámites que puedes iniciar</h2>
    <?php foreach ($hitos as $h):
      $clase = $h['listo'] ? 'listo' : (($proximo && $proximo['pct'] === $h['pct']) ? 'siguiente' : ''); ?>
      <div class="hito <?= $clase ?>">
        <span class="sello"><?= $h['listo'] ? '✓' : $h['pct'] ?></span>
        <div>
          <h3><?= e($h['titulo']) ?>
            <?= $h['listo'] ? '— ya puedes iniciarlo' : '— faltan ' . fmt($h['faltan'], 0) . ' créditos' ?>
          </h3>
          <p><?= e($h['detalle']) ?> Se activa con <?= fmt($h['creditos'], 0) ?> créditos (<?= $h['pct'] ?>%).</p>
        </div>
      </div>
    <?php endforeach; ?>
    <p class="nota" style="margin-top:14px">Los porcentajes son los más comunes en México, pero cada universidad fija los suyos: confirma en tu reglamento y ajusta los hitos en el arreglo <code>$hitos</code> del archivo.</p>
  </section>

  <!-- Materias -->
  <section class="tarjeta">
    <h2>Materias del plan</h2>

    <form method="post" class="fila-alta mat" style="margin-bottom:22px">
      <input type="hidden" name="accion" value="agregar">
      <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
      <div class="campo">
        <label for="nombre">Materia</label>
        <input id="nombre" name="nombre" placeholder="Cálculo diferencial" required>
      </div>
      <div class="campo">
        <label for="semestre">Semestre</label>
        <input id="semestre" name="semestre" type="number" min="0" max="20" value="1">
      </div>
      <div class="campo">
        <label for="creditos">Créditos</label>
        <input id="creditos" name="creditos" type="number" step="0.5" min="0" value="8">
      </div>
      <div class="campo">
        <label for="calificacion">Calificación</label>
        <input id="calificacion" name="calificacion" type="number" step="0.1" min="0" max="10" placeholder="—">
      </div>
      <div class="campo">
        <label for="tipo">Tipo</label>
        <select id="tipo" name="tipo"><?php foreach (TIPOS as $t): ?><option value="<?= $t ?>"><?= ucfirst($t) ?></option><?php endforeach; ?></select>
      </div>
      <div class="campo">
        <label for="estado">Estado</label>
        <select id="estado" name="estado">
          <option value="aprobada">Aprobada</option>
          <option value="cursando">Cursando</option>
          <option value="pendiente" selected>Pendiente</option>
        </select>
      </div>
      <button type="submit">Agregar materia</button>
    </form>

    <?php if (!$materias): ?>
      <p class="vacio">Todavía no hay materias. Captura la primera arriba y el avance empieza a calcularse solo.</p>
    <?php else: ?>
      <div class="desliza">
      <table>
        <thead>
          <tr>
            <th>Materia</th><th>Sem.</th><th>Créditos</th><th>Calif.</th><th>Tipo</th><th>Estado</th><th></th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($materias as $m):
          $cal = $m['calificacion'];
          $reprobada = $cal !== null && (float) $cal < $min;
          $fe = 'e' . md5($m['id']);   // formulario de edición
          $fb = 'b' . md5($m['id']);   // formulario de borrado
        ?>
          <tr>
            <td><input form="<?= $fe ?>" name="nombre" value="<?= e($m['nombre']) ?>"></td>
            <td class="numero"><input form="<?= $fe ?>" name="semestre" type="number" min="0" max="20" value="<?= (int) $m['semestre'] ?>"></td>
            <td class="numero"><input form="<?= $fe ?>" name="creditos" type="number" step="0.5" min="0" value="<?= e((string) $m['creditos']) ?>"></td>
            <td class="numero">
              <input form="<?= $fe ?>" name="calificacion" type="number" step="0.1" min="0" max="10"
                     class="<?= $reprobada ? 'marca-reprobada' : '' ?>"
                     value="<?= $cal === null ? '' : e((string) $cal) ?>" placeholder="—">
            </td>
            <td style="width:130px"><select form="<?= $fe ?>" name="tipo"><?php foreach (TIPOS as $t): ?><option value="<?= $t ?>"<?= ($m['tipo'] ?? 'obligatoria') === $t ? ' selected' : '' ?>><?= ucfirst($t) ?></option><?php endforeach; ?></select></td>
            <td style="width:142px">
              <select form="<?= $fe ?>" name="estado">
                <option value="aprobada"  <?= $m['estado'] === 'aprobada'  ? 'selected' : '' ?>>Aprobada</option>
                <option value="cursando"  <?= $m['estado'] === 'cursando'  ? 'selected' : '' ?>>Cursando</option>
                <option value="pendiente" <?= $m['estado'] === 'pendiente' ? 'selected' : '' ?>>Pendiente</option>
              </select>
            </td>
            <td>
              <div class="acciones">
                <button class="tenue" type="submit" form="<?= $fe ?>">Guardar</button>
                <button class="tenue" type="submit" form="<?= $fb ?>" title="Eliminar materia">✕</button>
              </div>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      </div>

      <?php /* Los formularios viven fuera de la tabla; los campos se enlazan con el atributo form. */ ?>
      <?php foreach ($materias as $m):
        $fe = 'e' . md5($m['id']);
        $fb = 'b' . md5($m['id']); ?>
        <form id="<?= $fe ?>" method="post" hidden>
          <input type="hidden" name="accion" value="actualizar">
          <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
          <input type="hidden" name="id" value="<?= e($m['id']) ?>">
        </form>
        <form id="<?= $fb ?>" method="post" hidden
              onsubmit="return confirm('¿Eliminar <?= e(str_replace(["'", '"'], '', $m['nombre'])) ?>?')">
          <input type="hidden" name="accion" value="eliminar">
          <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
          <input type="hidden" name="id" value="<?= e($m['id']) ?>">
        </form>
      <?php endforeach; ?>
    <?php endif; ?>
  </section>

  <!-- Calificación por parciales -->
  <section class="tarjeta">
    <h2>Calificación por parciales <small class="nota">(materias en estado “Cursando”)</small></h2>
    <?php $hay = false; foreach ($materias as $m): if ($m['estado'] !== 'cursando') { continue; } $hay = true; $evs = $m['evals'] ?? []; ?>
      <details class="parcial">
        <summary><?= e($m['nombre']) ?><small><?= e(evalResumen($evs, $min)) ?></small></summary>
        <form method="post">
          <input type="hidden" name="accion" value="evals"><?= csrf() ?>
          <input type="hidden" name="id" value="<?= e($m['id']) ?>">
          <div class="evs">
            <b class="nota">Evaluación</b><b class="nota">Peso (%)</b><b class="nota">Calif.</b>
            <?php foreach (array_merge($evs, [['nombre' => '', 'peso' => '', 'cal' => null], ['nombre' => '', 'peso' => '', 'cal' => null]]) as $v): ?>
              <input name="ev_nombre[]" placeholder="Parcial 1, Tarea, Proyecto…" value="<?= e($v['nombre']) ?>">
              <input name="ev_peso[]" type="number" step="0.5" min="0" max="100" value="<?= e((string) $v['peso']) ?>">
              <input name="ev_cal[]" type="number" step="0.1" min="0" max="10" placeholder="—" value="<?= $v['cal'] === null ? '' : e((string) $v['cal']) ?>">
            <?php endforeach; ?>
          </div>
          <button type="submit">Guardar evaluaciones</button>
          <span class="nota"> Deja la calificación vacía en lo que aún no se evalúa; los pesos deberían sumar 100.</span>
        </form>
      </details>
    <?php endforeach; if (!$hay): ?><p class="vacio">Marca una materia como “Cursando” para registrar sus parciales.</p><?php endif; ?>
  </section>

  <!-- Horario semanal -->
  <details class="tarjeta desplegable" <?= $horario ? 'open' : '' ?>>
    <summary>Horario semanal</summary>
    <form method="post" class="fila-alta" style="grid-template-columns:2fr 1.2fr 1fr 1fr 1fr auto;margin-top:14px">
      <input type="hidden" name="accion" value="horario_add"><?= csrf() ?>
      <div class="campo"><label for="hmateria">Materia</label><input id="hmateria" name="materia" list="lm" required></div>
      <div class="campo"><label for="hdia">Día</label><select id="hdia" name="dia"><?php foreach (DIAS as $i => $d): ?><option value="<?= $i ?>"><?= $d ?></option><?php endforeach; ?></select></div>
      <div class="campo"><label for="hini">Inicio</label><input id="hini" name="inicio" type="time" required></div>
      <div class="campo"><label for="hfin">Fin</label><input id="hfin" name="fin" type="time" required></div>
      <div class="campo"><label for="hsalon">Salón</label><input id="hsalon" name="salon"></div>
      <button type="submit">Agregar</button>
    </form>
    <div class="hor">
      <?php foreach (DIAS as $i => $d): ?>
        <div>
          <h3><?= $d ?></h3>
          <?php foreach ($horario as $h): if ($h['dia'] !== $i) { continue; } ?>
            <div class="clase">
              <b><?= e($h['materia']) ?></b>
              <small><?= e($h['inicio']) ?>–<?= e($h['fin']) ?><?= $h['salon'] !== '' ? ' · ' . e($h['salon']) : '' ?></small>
              <form method="post" onsubmit="return confirm('¿Quitar esta clase del horario?')">
                <input type="hidden" name="accion" value="horario_del"><?= csrf() ?><input type="hidden" name="id" value="<?= e($h['id']) ?>">
                <button class="tenue" title="Quitar">✕</button>
              </form>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endforeach; ?>
    </div>
    <?php if (!$horario): ?><p class="vacio">Aún no registras clases. Agrega la primera arriba.</p><?php endif; ?>
  </details>

  <!-- Agenda -->
  <section class="tarjeta">
    <h2>Agenda de entregas y exámenes</h2>
    <form method="post" class="fila-alta" style="grid-template-columns:2fr 1.4fr 1fr 1fr auto;margin-bottom:14px">
      <input type="hidden" name="accion" value="agenda_add"><?= csrf() ?>
      <div class="campo"><label for="titulo">Título</label><input id="titulo" name="titulo" placeholder="Entrega proyecto final" required></div>
      <div class="campo"><label for="amateria">Materia</label><input id="amateria" name="materia" list="lm"></div>
      <div class="campo"><label for="fecha">Fecha</label><input id="fecha" name="fecha" type="date" required></div>
      <div class="campo"><label for="atipo">Tipo</label><select id="atipo" name="tipo"><option value="entrega">Entrega</option><option value="examen">Examen</option></select></div>
      <button type="submit">Agregar</button>
      <datalist id="lm"><?php foreach ($materias as $m): ?><option value="<?= e($m['nombre']) ?>"><?php endforeach; ?></datalist>
    </form>
    <?php foreach ($agenda as $a): ?>
      <div class="ag <?= $a['hecho'] ? 'hecho' : '' ?>">
        <span class="ins <?= $a['tipo'] ?>"><?= $a['tipo'] === 'examen' ? 'Examen' : 'Entrega' ?></span>
        <span class="tit"><?= e($a['titulo']) ?> <small><?= e($a['materia']) ?></small></span>
        <small><?= e($a['fecha']) ?></small>
        <form method="post" class="inline"><input type="hidden" name="accion" value="agenda_hecho"><?= csrf() ?><input type="hidden" name="id" value="<?= e($a['id']) ?>"><button class="tenue" title="Marcar hecho">✓</button></form>
        <form method="post" class="inline"><input type="hidden" name="accion" value="agenda_del"><?= csrf() ?><input type="hidden" name="id" value="<?= e($a['id']) ?>"><button class="tenue" title="Eliminar">✕</button></form>
      </div>
    <?php endforeach; if (!$agenda): ?><p class="vacio">Sin pendientes. Agrega tu primera entrega o examen.</p><?php endif; ?>
  </section>

  <!-- Configuración del plan -->
  <section class="tarjeta">
    <h2>Datos de tu plan</h2>
    <form method="post" class="fila-alta">
      <input type="hidden" name="accion" value="plan">
      <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
      <div class="campo">
        <label for="carrera">Carrera</label>
        <input id="carrera" name="carrera" value="<?= e($datos['carrera']) ?>">
      </div>
      <div class="campo" style="grid-column:span 2">
        <label for="creditosPlan">Créditos totales del plan</label>
        <input id="creditosPlan" name="creditosPlan" type="number" step="1" min="1" value="<?= e((string) $plan) ?>">
      </div>
      <div class="campo" style="grid-column:span 2">
        <label for="minAprobatoria">Calificación mínima aprobatoria</label>
        <input id="minAprobatoria" name="minAprobatoria" type="number" step="0.1" min="0" max="10" value="<?= e((string) $min) ?>">
      </div>
      <div class="campo" style="grid-column:span 2"><label for="min_obligatoria">Créditos mínimos obligatorias</label><input id="min_obligatoria" name="min_obligatoria" type="number" step="1" min="0" value="<?= e((string) $datos['minTipo']['obligatoria']) ?>"></div>
      <div class="campo" style="grid-column:span 2"><label for="min_optativa">Créditos mínimos optativas</label><input id="min_optativa" name="min_optativa" type="number" step="1" min="0" value="<?= e((string) $datos['minTipo']['optativa']) ?>"></div>
      <div class="campo" style="grid-column:span 2"><label for="min_electiva">Créditos mínimos electivas</label><input id="min_electiva" name="min_electiva" type="number" step="1" min="0" value="<?= e((string) $datos['minTipo']['electiva']) ?>"></div>
      <button type="submit">Guardar plan</button>
    </form>
    <p class="nota" style="margin-top:14px">
      Llevas <?= fmt($credTotalPlan, 0) ?> créditos capturados de <?= fmt($plan, 0) ?> declarados en el plan.
      <?php if ($credTotalPlan > $plan): ?>Capturaste más créditos de los que dice el plan; revisa el total.<?php endif; ?>
    </p>
    <form method="post" onsubmit="return confirm('Esto borra todas las materias. ¿Continuar?')" style="margin-top:6px">
      <input type="hidden" name="accion" value="vaciar">
      <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
      <button class="tenue" type="submit">Borrar todas las materias</button>
    </form>
  </section>

</div>
<script>document.getElementById('tema').onclick=function(){var d=document.documentElement,t=d.dataset.theme==='dark'?'light':'dark';d.dataset.theme=t;try{localStorage.setItem('tema',t)}catch(e){}}</script>
</body>
</html>
