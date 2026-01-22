<?php
/**
 * SURVIVAL MAZE FOREST - API SEDERHANA
 * Versi stabil untuk Laragon dengan debugging
 */

// ============================================
// KONFIGURASI AWAL
// ============================================
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Database configuration for Laragon
define('DB_HOST', 'localhost');
define('DB_NAME', 'survival_maze_db');
define('DB_USER', 'root');
define('DB_PASS', '');
define('JWT_SECRET', 'survival_maze_secret_key_2024');

// ============================================
// HELPER FUNCTIONS
// ============================================
function jsonResponse($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data, JSON_PRETTY_PRINT);
    exit();
}

function getRequestBody() {
    $input = file_get_contents('php://input');
    if (empty($input)) {
        return [];
    }
    return json_decode($input, true);
}

function validateRequired($data, $fields) {
    $errors = [];
    foreach ($fields as $field) {
        if (!isset($data[$field]) || empty(trim($data[$field]))) {
            $errors[] = "Field '$field' is required";
        }
    }
    return $errors;
}

function getDbConnection() {
    try {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
        $pdo = new PDO($dsn, DB_USER, DB_PASS);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        return $pdo;
    } catch (PDOException $e) {
        jsonResponse([
            'status' => 'error',
            'message' => 'Database connection failed: ' . $e->getMessage()
        ], 500);
    }
    return null;
}

function generateToken($user_id, $username) {
    $payload = [
        'user_id' => $user_id,
        'username' => $username,
        'exp' => time() + (7 * 24 * 60 * 60)
    ];
    
    $header = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $payload_encoded = base64_encode(json_encode($payload));
    $signature = hash_hmac('sha256', "$header.$payload_encoded", JWT_SECRET, true);
    $signature_encoded = base64_encode($signature);
    
    return "$header.$payload_encoded.$signature_encoded";
}

function validateToken($token) {
    if (empty($token)) {
        return false;
    }
    
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }
    
    list($header, $payload, $signature) = $parts;
    
    $valid_signature = hash_hmac('sha256', "$header.$payload", JWT_SECRET, true);
    $valid_signature_encoded = base64_encode($valid_signature);
    
    if ($signature !== $valid_signature_encoded) {
        return false;
    }
    
    $payload_data = json_decode(base64_decode($payload), true);
    
    if (isset($payload_data['exp']) && $payload_data['exp'] < time()) {
        return false;
    }
    
    return $payload_data;
}

// ============================================
// API ROUTING
// ============================================
$method = $_SERVER['REQUEST_METHOD'];
$action = isset($_GET['action']) ? $_GET['action'] : '';

// Default response for root
if (empty($action)) {
    jsonResponse([
        'status' => 'success',
        'message' => 'Survival Maze Forest API',
        'version' => '1.0',
        'endpoints' => [
            '/api.php?action=register' => 'POST - Register new user',
            '/api.php?action=login' => 'POST - Login user',
            '/api.php?action=profile' => 'GET - Get user profile',
            '/api.php?action=save' => 'POST - Save game',
            '/api.php?action=load' => 'GET - Load game',
            '/api.php?action=leaderboard' => 'GET - Get leaderboard',
            '/api.php?action=health' => 'GET - Health check'
        ]
    ]);
}

// Handle actions
try {
    switch ($action) {
        case 'health':
            handleHealthCheck();
            break;
            
        case 'register':
            if ($method !== 'POST') {
                jsonResponse(['status' => 'error', 'message' => 'Method not allowed'], 405);
            }
            handleRegister();
            break;
            
        case 'login':
            if ($method !== 'POST') {
                jsonResponse(['status' => 'error', 'message' => 'Method not allowed'], 405);
            }
            handleLogin();
            break;
            
        case 'profile':
            handleProfile($method);
            break;
            
        case 'save':
            if ($method !== 'POST') {
                jsonResponse(['status' => 'error', 'message' => 'Method not allowed'], 405);
            }
            handleSaveGame();
            break;
            
        case 'load':
            if ($method !== 'GET') {
                jsonResponse(['status' => 'error', 'message' => 'Method not allowed'], 405);
            }
            handleLoadGame();
            break;
            
        case 'leaderboard':
            if ($method !== 'GET') {
                jsonResponse(['status' => 'error', 'message' => 'Method not allowed'], 405);
            }
            handleLeaderboard();
            break;
            
        default:
            jsonResponse(['status' => 'error', 'message' => 'Action not found'], 404);
    }
} catch (Exception $e) {
    jsonResponse([
        'status' => 'error',
        'message' => 'Server error: ' . $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ], 500);
}

// ============================================
// API HANDLERS
// ============================================

function handleHealthCheck() {
    $db = getDbConnection();
    if ($db) {
        jsonResponse([
            'status' => 'success',
            'message' => 'API is running',
            'database' => 'connected',
            'timestamp' => date('Y-m-d H:i:s')
        ]);
    }
}

function handleRegister() {
    $data = getRequestBody();
    
    // Validate required fields
    $errors = validateRequired($data, ['username', 'password', 'email']);
    if (!empty($errors)) {
        jsonResponse(['status' => 'error', 'message' => 'Validation failed', 'errors' => $errors], 400);
    }
    
    $username = trim($data['username']);
    $password = $data['password'];
    $email = trim($data['email']);
    $full_name = isset($data['full_name']) ? trim($data['full_name']) : $username;
    $gender = isset($data['gender']) ? trim($data['gender']) : 'Male';
    
    // Basic validation
    if (strlen($username) < 3 || strlen($username) > 20) {
        jsonResponse(['status' => 'error', 'message' => 'Username must be 3-20 characters'], 400);
    }
    
    if (strlen($password) < 6) {
        jsonResponse(['status' => 'error', 'message' => 'Password must be at least 6 characters'], 400);
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        jsonResponse(['status' => 'error', 'message' => 'Invalid email format'], 400);
    }
    
    $db = getDbConnection();
    
    try {
        // Check if user exists
        $stmt = $db->prepare("SELECT user_id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        
        if ($stmt->rowCount() > 0) {
            jsonResponse(['status' => 'error', 'message' => 'Username or email already exists'], 409);
        }
        
        // Hash password
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        
        // Start transaction
        $db->beginTransaction();
        
        // Insert user
        $stmt = $db->prepare("
            INSERT INTO users (username, password_hash, email, full_name, gender, created_at) 
            VALUES (?, ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([$username, $password_hash, $email, $full_name, $gender]);
        
        $user_id = $db->lastInsertId();
        
        // Create user progress
        $stmt = $db->prepare("INSERT INTO user_progress (user_id) VALUES (?)");
        $stmt->execute([$user_id]);
        
        // Create user inventory
        $stmt = $db->prepare("
            INSERT INTO user_inventory (user_id, ammo, wood, iron, rope, food, coin, bomb, shield) 
            VALUES (?, 60, 20, 10, 5, 0, 0, 1, 0)
        ");
        $stmt->execute([$user_id]);
        
        // Create user settings
        $stmt = $db->prepare("INSERT INTO user_settings (user_id) VALUES (?)");
        $stmt->execute([$user_id]);
        
        // Create leaderboard entry
        $stmt = $db->prepare("INSERT INTO leaderboard (user_id) VALUES (?)");
        $stmt->execute([$user_id]);
        
        // Generate token
        $token = generateToken($user_id, $username);
        
        $db->commit();
        
        // Get created user
        $stmt = $db->prepare("
            SELECT user_id, username, email, full_name, gender, created_at 
            FROM users WHERE user_id = ?
        ");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch();
        
        jsonResponse([
            'status' => 'success',
            'message' => 'Registration successful',
            'data' => [
                'user' => $user,
                'token' => $token
            ]
        ], 201);
        
    } catch (PDOException $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        jsonResponse(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()], 500);
    }
}

function handleLogin() {
    $data = getRequestBody();
    
    if (!isset($data['username']) || !isset($data['password'])) {
        jsonResponse(['status' => 'error', 'message' => 'Username and password required'], 400);
    }
    
    $username = trim($data['username']);
    $password = $data['password'];
    
    $db = getDbConnection();
    
    try {
        // Find user
        $stmt = $db->prepare("
            SELECT user_id, username, password_hash, email, full_name, gender 
            FROM users WHERE username = ? OR email = ?
        ");
        $stmt->execute([$username, $username]);
        
        if ($stmt->rowCount() === 0) {
            jsonResponse(['status' => 'error', 'message' => 'User not found'], 404);
        }
        
        $user = $stmt->fetch();
        
        // Verify password
        if (!password_verify($password, $user['password_hash'])) {
            jsonResponse(['status' => 'error', 'message' => 'Invalid password'], 401);
        }
        
        // Update last login
        $stmt = $db->prepare("UPDATE users SET last_login = NOW() WHERE user_id = ?");
        $stmt->execute([$user['user_id']]);
        
        // Generate token
        $token = generateToken($user['user_id'], $user['username']);
        
        // Get user progress
        $stmt = $db->prepare("SELECT * FROM user_progress WHERE user_id = ?");
        $stmt->execute([$user['user_id']]);
        $progress = $stmt->fetch();
        
        // Get inventory
        $stmt = $db->prepare("SELECT * FROM user_inventory WHERE user_id = ?");
        $stmt->execute([$user['user_id']]);
        $inventory = $stmt->fetch();
        
        // Remove password hash from response
        unset($user['password_hash']);
        
        jsonResponse([
            'status' => 'success',
            'message' => 'Login successful',
            'data' => [
                'user' => $user,
                'progress' => $progress,
                'inventory' => $inventory,
                'token' => $token
            ]
        ]);
        
    } catch (PDOException $e) {
        jsonResponse(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()], 500);
    }
}

function handleProfile($method) {
    // Get token from header
    $headers = getallheaders();
    $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
    
    if (empty($authHeader)) {
        jsonResponse(['status' => 'error', 'message' => 'Authorization header missing'], 401);
    }
    
    $token = str_replace('Bearer ', '', $authHeader);
    $tokenData = validateToken($token);
    
    if (!$tokenData) {
        jsonResponse(['status' => 'error', 'message' => 'Invalid or expired token'], 401);
    }
    
    $user_id = $tokenData['user_id'];
    $db = getDbConnection();
    
    if ($method === 'GET') {
        try {
            // Get user profile with all related data
            $stmt = $db->prepare("
                SELECT 
                    u.*,
                    up.current_stage,
                    up.highest_stage,
                    up.total_kills,
                    up.total_walls_built,
                    up.total_coin_collected,
                    up.total_quests_completed,
                    ui.ammo,
                    ui.wood,
                    ui.iron,
                    ui.coin,
                    ui.bomb,
                    ui.shield,
                    lb.total_score,
                    lb.stage_reached,
                    lb.total_kills as lb_kills
                FROM users u
                LEFT JOIN user_progress up ON u.user_id = up.user_id
                LEFT JOIN user_inventory ui ON u.user_id = ui.user_id
                LEFT JOIN leaderboard lb ON u.user_id = lb.user_id
                WHERE u.user_id = ?
            ");
            $stmt->execute([$user_id]);
            
            $profile = $stmt->fetch();
            
            if (!$profile) {
                jsonResponse(['status' => 'error', 'message' => 'User not found'], 404);
            }
            
            // Remove sensitive data
            unset($profile['password_hash']);
            
            jsonResponse([
                'status' => 'success',
                'data' => $profile
            ]);
            
        } catch (PDOException $e) {
            jsonResponse(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()], 500);
        }
    } else {
        jsonResponse(['status' => 'error', 'message' => 'Method not allowed'], 405);
    }
}

function handleSaveGame() {
    // Get token from header
    $headers = getallheaders();
    $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
    
    if (empty($authHeader)) {
        jsonResponse(['status' => 'error', 'message' => 'Authorization header missing'], 401);
    }
    
    $token = str_replace('Bearer ', '', $authHeader);
    $tokenData = validateToken($token);
    
    if (!$tokenData) {
        jsonResponse(['status' => 'error', 'message' => 'Invalid or expired token'], 401);
    }
    
    $user_id = $tokenData['user_id'];
    $data = getRequestBody();
    
    if (!isset($data['stage_number']) || !isset($data['save_data'])) {
        jsonResponse(['status' => 'error', 'message' => 'Stage number and save data required'], 400);
    }
    
    $stage_number = (int)$data['stage_number'];
    $save_data = json_encode($data['save_data']);
    $save_name = isset($data['save_name']) ? $data['save_name'] : 'Auto Save';
    $play_duration = isset($data['play_duration']) ? (int)$data['play_duration'] : 0;
    
    $db = getDbConnection();
    
    try {
        // Start transaction
        $db->beginTransaction();
        
        // Set all saves to not current
        $stmt = $db->prepare("UPDATE game_saves SET is_current_save = FALSE WHERE user_id = ?");
        $stmt->execute([$user_id]);
        
        // Insert new save
        $stmt = $db->prepare("
            INSERT INTO game_saves (user_id, stage_number, save_name, save_data, is_current_save, play_duration, save_timestamp) 
            VALUES (?, ?, ?, ?, TRUE, ?, NOW())
        ");
        $stmt->execute([$user_id, $stage_number, $save_name, $save_data, $play_duration]);
        
        $save_id = $db->lastInsertId();
        
        // Update user progress
        $stmt = $db->prepare("
            UPDATE user_progress 
            SET current_stage = ?, 
                highest_stage = GREATEST(highest_stage, ?),
                total_play_time_current = total_play_time_current + ?
            WHERE user_id = ?
        ");
        $stmt->execute([$stage_number, $stage_number, $play_duration, $user_id]);
        
        // Update inventory if provided
        if (isset($data['inventory']) && is_array($data['inventory'])) {
            $inventory = $data['inventory'];
            
            // Update specific fields
            if (isset($inventory['coin'])) {
                $stmt = $db->prepare("UPDATE user_inventory SET coin = ? WHERE user_id = ?");
                $stmt->execute([(int)$inventory['coin'], $user_id]);
            }
        }
        
        // Update leaderboard
        $stmt = $db->prepare("
            UPDATE leaderboard 
            SET stage_reached = GREATEST(stage_reached, ?),
                total_play_time = total_play_time + ?,
                last_updated = NOW()
            WHERE user_id = ?
        ");
        $stmt->execute([$stage_number, $play_duration, $user_id]);
        
        $db->commit();
        
        jsonResponse([
            'status' => 'success',
            'message' => 'Game saved successfully',
            'data' => [
                'save_id' => $save_id,
                'stage' => $stage_number
            ]
        ]);
        
    } catch (PDOException $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        jsonResponse(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()], 500);
    }
}

function handleLoadGame() {
    // Get token from header
    $headers = getallheaders();
    $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
    
    if (empty($authHeader)) {
        jsonResponse(['status' => 'error', 'message' => 'Authorization header missing'], 401);
    }
    
    $token = str_replace('Bearer ', '', $authHeader);
    $tokenData = validateToken($token);
    
    if (!$tokenData) {
        jsonResponse(['status' => 'error', 'message' => 'Invalid or expired token'], 401);
    }
    
    $user_id = $tokenData['user_id'];
    $stage = isset($_GET['stage']) ? (int)$_GET['stage'] : null;
    
    $db = getDbConnection();
    
    try {
        if ($stage) {
            // Load specific stage
            $stmt = $db->prepare("
                SELECT * FROM game_saves 
                WHERE user_id = ? AND stage_number = ? 
                ORDER BY save_timestamp DESC LIMIT 1
            ");
            $stmt->execute([$user_id, $stage]);
        } else {
            // Load current save
            $stmt = $db->prepare("
                SELECT * FROM game_saves 
                WHERE user_id = ? AND is_current_save = TRUE 
                ORDER BY save_timestamp DESC LIMIT 1
            ");
            $stmt->execute([$user_id]);
        }
        
        if ($stmt->rowCount() === 0) {
            // Return default state
            $stmt = $db->prepare("SELECT current_stage FROM user_progress WHERE user_id = ?");
            $stmt->execute([$user_id]);
            $progress = $stmt->fetch();
            
            $default_stage = $progress ? $progress['current_stage'] : 1;
            
            jsonResponse([
                'status' => 'success',
                'data' => [
                    'stage_number' => $default_stage,
                    'save_data' => [
                        'player' => [
                            'x' => 200,
                            'y' => 200,
                            'hp' => 100,
                            'lives' => 3
                        ],
                        'inventory' => [
                            'ammo' => 60,
                            'wood' => 20,
                            'iron' => 10,
                            'coin' => 0,
                            'bomb' => 1
                        ]
                    ]
                ]
            ]);
            return;
        }
        
        $save = $stmt->fetch();
        $save['save_data'] = json_decode($save['save_data'], true);
        
        jsonResponse([
            'status' => 'success',
            'data' => $save
        ]);
        
    } catch (PDOException $e) {
        jsonResponse(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()], 500);
    }
}

function handleLeaderboard() {
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $type = isset($_GET['type']) ? $_GET['type'] : 'score';
    
    $db = getDbConnection();
    
    try {
        $order_by = "lb.total_score DESC";
        if ($type === 'stage') {
            $order_by = "lb.stage_reached DESC, lb.total_score DESC";
        } elseif ($type === 'kills') {
            $order_by = "lb.total_kills DESC, lb.total_score DESC";
        }
        
        $stmt = $db->prepare("
            SELECT 
                u.username,
                u.full_name,
                u.gender,
                lb.stage_reached,
                lb.total_kills,
                lb.total_score,
                lb.total_play_time
            FROM leaderboard lb
            JOIN users u ON lb.user_id = u.user_id
            ORDER BY $order_by
            LIMIT ?
        ");
        $stmt->bindValue(1, $limit, PDO::PARAM_INT);
        $stmt->execute();
        
        $leaderboard = $stmt->fetchAll();
        
        // Add rank
        foreach ($leaderboard as $index => &$player) {
            $player['rank'] = $index + 1;
        }
        
        jsonResponse([
            'status' => 'success',
            'data' => [
                'leaderboard' => $leaderboard,
                'total' => count($leaderboard)
            ]
        ]);
        
    } catch (PDOException $e) {
        jsonResponse(['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()], 500);
    }
}
?>