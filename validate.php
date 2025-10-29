<?php
// validate.php - Fixed for GitHub Pages JSONP

// Handle JSONP requests first
if (isset($_GET['callback'])) {
    $callback = $_GET['callback'];
    
    // Set proper content type for JSONP
    header('Content-Type: application/javascript; charset=utf-8');
    
    // Handle key generation
    if (isset($_GET['action']) && $_GET['action'] === 'generate') {
        $system_id = isset($_GET['system_id']) ? trim($_GET['system_id']) : '';
        $duration = isset($_GET['duration']) ? $_GET['duration'] : '';
        $vendor_password = isset($_GET['vendor_password']) ? $_GET['vendor_password'] : '';
        
        $valid_vendor_password = "VENDOR123";
        $secret_key = "DENDI_SECURE_KEY_2025_V2";
        
        if ($vendor_password === $valid_vendor_password && !empty($system_id) && !empty($duration)) {
            // Generate activation key
            $result = generateActivationKey($system_id, $duration, $secret_key);
            $response = array('success' => true, 'data' => $result);
        } else {
            $response = array('success' => false, 'error' => 'Invalid parameters or unauthorized');
        }
        
        echo $callback . '(' . json_encode($response) . ');';
        exit;
    }
    
    // Handle status check
    $data = array(
        'status' => 'active', 
        'service' => 'Activation Key Server', 
        'version' => '2.0',
        'timestamp' => date('Y-m-d H:i:s')
    );
    echo $callback . '(' . json_encode($data) . ');';
    exit;
}

// Regular CORS headers for other requests
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

// Configuration
$secret_key = "DENDI_SECURE_KEY_2025_V2";

// Generate activation key function
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

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    
    $system_id = isset($input['system_id']) ? trim($input['system_id']) : '';
    $action = isset($input['action']) ? $input['action'] : '';
    $duration = isset($input['duration']) ? $input['duration'] : '';
    $vendor_password = isset($input['vendor_password']) ? $input['vendor_password'] : '';
    
    $valid_vendor_password = "VENDOR123";
    
    if ($action === 'generate' && $vendor_password === $valid_vendor_password) {
        if (empty($system_id) || empty($duration)) {
            echo json_encode(array('success' => false, 'error' => 'Missing system_id or duration'));
            exit;
        }
        
        $result = generateActivationKey($system_id, $duration, $secret_key);
        echo json_encode(array('success' => true, 'data' => $result));
    } else {
        echo json_encode(array('success' => false, 'error' => 'Invalid action or unauthorized'));
    }
    
} elseif ($_SERVER['REQUEST_METHOD'] == 'GET' && !isset($_GET['callback'])) {
    // Simple status check for regular GET
    echo json_encode(array(
        'status' => 'active', 
        'service' => 'Activation Key Server', 
        'version' => '2.0',
        'timestamp' => date('Y-m-d H:i:s')
    ));
}
?>
