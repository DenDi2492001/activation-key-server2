<?php
// validate.php - Enhanced Version for GitHub Pages & InfinityFree

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set headers for CORS and JSON
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Accept, Origin');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Max-Age: 86400');
header('Content-Type: application/json; charset=utf-8');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit(0);
}

// Handle JSONP requests
if (isset($_GET['callback'])) {
    $callback = $_GET['callback'];
    header('Content-Type: application/javascript; charset=utf-8');
    
    // Handle key generation via JSONP
    if (isset($_GET['action']) && $_GET['action'] === 'generate') {
        $system_id = isset($_GET['system_id']) ? trim($_GET['system_id']) : '';
        $duration = isset($_GET['duration']) ? $_GET['duration'] : '';
        $vendor_password = isset($_GET['vendor_password']) ? $_GET['vendor_password'] : '';
        
        $valid_vendor_password = "VENDOR123";
        $secret_key = "DENDI_SECURE_KEY_2025_V2";
        
        if ($vendor_password === $valid_vendor_password && !empty($system_id) && !empty($duration)) {
            $result = generateActivationKey($system_id, $duration, $secret_key);
            $response = array('success' => true, 'data' => $result);
        } else {
            $response = array('success' => false, 'error' => 'Invalid parameters or unauthorized');
        }
        
        echo $callback . '(' . json_encode($response) . ');';
        exit;
    }
    
    // Handle status check via JSONP
    $data = array(
        'status' => 'active', 
        'service' => 'Activation Key Server', 
        'version' => '2.0',
        'timestamp' => date('Y-m-d H:i:s')
    );
    echo $callback . '(' . json_encode($data) . ');';
    exit;
}

// Configuration
$secret_key = "DENDI_SECURE_KEY_2025_V2";
$used_keys_file = "used_keys.json";
$activation_logs = "activation_logs.json";

// Initialize files if they don't exist
function initializeFiles() {
    global $used_keys_file, $activation_logs;
    
    if (!file_exists($used_keys_file)) {
        file_put_contents($used_keys_file, json_encode([]));
    }
    
    if (!file_exists($activation_logs)) {
        file_put_contents($activation_logs, json_encode([]));
    }
}

// Used keys tracking functions
function loadUsedKeys() {
    global $used_keys_file;
    initializeFiles();
    
    if (!file_exists($used_keys_file)) {
        return [];
    }
    
    $data = file_get_contents($used_keys_file);
    if ($data === false) {
        return [];
    }
    
    $decoded = json_decode($data, true);
    return is_array($decoded) ? $decoded : [];
}

function saveUsedKeys($used_keys) {
    global $used_keys_file;
    
    if (!is_array($used_keys)) {
        $used_keys = [];
    }
    
    $result = file_put_contents($used_keys_file, json_encode($used_keys));
    return $result !== false;
}

function isKeyUsed($activation_key) {
    $used_keys = loadUsedKeys();
    return in_array($activation_key, $used_keys);
}

function markKeyAsUsed($activation_key) {
    $used_keys = loadUsedKeys();
    if (!in_array($activation_key, $used_keys)) {
        $used_keys[] = $activation_key;
        saveUsedKeys($used_keys);
        return true;
    }
    return false;
}

// Activation logging
function logActivation($system_id, $activation_key, $duration, $ip) {
    global $activation_logs;
    $logs = [];
    
    if (file_exists($activation_logs)) {
        $data = file_get_contents($activation_logs);
        if ($data !== false) {
            $logs = json_decode($data, true) ?: [];
        }
    }
    
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'system_id' => $system_id,
        'activation_key' => $activation_key,
        'duration' => $duration,
        'ip_address' => $ip
    ];
    
    array_unshift($logs, $log_entry);
    
    // Keep only last 1000 logs
    if (count($logs) > 1000) {
        $logs = array_slice($logs, 0, 1000);
    }
    
    file_put_contents($activation_logs, json_encode($logs));
    return true;
}

// Validate activation key
function validateActivationKey($system_id, $activation_key, $secret_key) {
    $activation_key = str_replace('-', '', $activation_key);
    $activation_key = strtoupper($activation_key);
    
    // Check if key is already used
    if (isKeyUsed($activation_key)) {
        return array('valid' => false, 'error' => 'This activation key has already been used');
    }
    
    // Validate key length
    if (strlen($activation_key) != 16) {
        return array('valid' => false, 'error' => 'Invalid key length');
    }
    
    // Check if key is alphanumeric
    if (!ctype_alnum($activation_key)) {
        return array('valid' => false, 'error' => 'Key must be alphanumeric');
    }
    
    // Extract duration code from first character
    $duration_code = substr($activation_key, 0, 1);
    $key_hash = substr($activation_key, 1);
    
    // Generate expected hash based on system_id and secret
    $expected_string = $system_id . $secret_key . $duration_code;
    $expected_hash = substr(hash('sha256', $expected_string), 0, 15);
    $expected_hash = strtoupper($expected_hash);
    
    // Compare hashes
    if ($key_hash === $expected_hash) {
        // Map duration codes to actual durations
        $duration_map = array(
            'T' => '2days',
            'M' => '1month', 
            'Q' => '3months',
            'H' => '6months',
            'Y' => '12months'
        );
        
        $duration = isset($duration_map[$duration_code]) ? $duration_map[$duration_code] : '2days';
        
        // Mark key as used and log activation
        if (markKeyAsUsed($activation_key)) {
            logActivation($system_id, $activation_key, $duration, $_SERVER['REMOTE_ADDR']);
            
            return array(
                'valid' => true,
                'duration' => $duration,
                'system_id' => $system_id,
                'message' => 'Activation successful'
            );
        } else {
            return array('valid' => false, 'error' => 'Failed to mark key as used');
        }
    }
    
    return array('valid' => false, 'error' => 'Invalid activation key');
}

// Generate activation key (for vendor use)
function generateActivationKey($system_id, $duration, $secret_key) {
    $duration_map = array(
        '2days' => 'T',
        '1month' => 'M',
        '3months' => 'Q', 
        '6months' => 'H',
        '12months' => 'Y'
    );
    
    $duration_code = isset($duration_map[$duration]) ? $duration_map[$duration] : 'T';
    
    // Generate hash
    $base_string = $system_id . $secret_key . $duration_code;
    $hash = substr(hash('sha256', $base_string), 0, 15);
    $hash = strtoupper($hash);
    
    $key = $duration_code . $hash;
    
    // Format with dashes for display
    $formatted_key = substr($key, 0, 4) . '-' . substr($key, 4, 4) . '-' . 
                     substr($key, 8, 4) . '-' . substr($key, 12, 4);
    
    return array(
        'raw_key' => $key,
        'formatted_key' => $formatted_key,
        'duration' => $duration,
        'system_id' => $system_id,
        'generated_at' => date('Y-m-d H:i:s')
    );
}

// Main request handling
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    
    // If no JSON input, try form data
    if (empty($input)) {
        $input = $_POST;
    }
    
    $system_id = isset($input['system_id']) ? trim($input['system_id']) : '';
    $activation_key = isset($input['activation_key']) ? trim($input['activation_key']) : '';
    $action = isset($input['action']) ? $input['action'] : '';
    $duration = isset($input['duration']) ? $input['duration'] : '';
    $vendor_password = isset($input['vendor_password']) ? $input['vendor_password'] : '';
    
    // Vendor password for key generation
    $valid_vendor_password = "VENDOR123";
    
    if ($action === 'validate') {
        if (empty($system_id) || empty($activation_key)) {
            echo json_encode(array('valid' => false, 'error' => 'Missing system_id or activation_key'));
            exit;
        }
        
        $result = validateActivationKey($system_id, $activation_key, $secret_key);
        echo json_encode($result);
        
    } elseif ($action === 'generate' && $vendor_password === $valid_vendor_password) {
        if (empty($system_id) || empty($duration)) {
            echo json_encode(array('success' => false, 'error' => 'Missing system_id or duration'));
            exit;
        }
        
        $result = generateActivationKey($system_id, $duration, $secret_key);
        echo json_encode(array('success' => true, 'data' => $result));
        
    } else {
        echo json_encode(array('valid' => false, 'error' => 'Invalid action or unauthorized'));
    }
    
} elseif ($_SERVER['REQUEST_METHOD'] == 'GET' && !isset($_GET['callback'])) {
    // Simple status check for regular GET
    $used_keys_count = count(loadUsedKeys());
    $logs_count = 0;
    
    if (file_exists($activation_logs)) {
        $logs_data = file_get_contents($activation_logs);
        if ($logs_data !== false) {
            $logs = json_decode($logs_data, true);
            $logs_count = is_array($logs) ? count($logs) : 0;
        }
    }
    
    echo json_encode(array(
        'status' => 'active', 
        'service' => 'Activation Key Server', 
        'version' => '2.0',
        'used_keys_count' => $used_keys_count,
        'activation_logs_count' => $logs_count,
        'timestamp' => date('Y-m-d H:i:s'),
        'server' => $_SERVER['HTTP_HOST'] ?? 'Unknown'
    ));
}

// Handle direct access - show info
if ($_SERVER['REQUEST_METHOD'] == 'GET' && empty($_GET)) {
    echo json_encode(array(
        'message' => 'Activation Key Server is running',
        'endpoints' => array(
            'GET ?callback=xxx' => 'JSONP status check',
            'GET ?callback=xxx&action=generate&system_id=XXX&duration=XXX&vendor_password=XXX' => 'Generate key via JSONP',
            'POST with JSON body' => 'Generate/validate keys via POST',
            'GET (no params)' => 'Server status'
        ),
        'timestamp' => date('Y-m-d H:i:s')
    ));
}
?>
