<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Preflight request handling
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit(0);
}

// Configuration - CHANGE THIS SECRET KEY!
$secret_key = "DENDI_SECURE_KEY_2025_V2";

// Validate activation key
function validateActivationKey($system_id, $activation_key, $secret_key) {
    // Remove any dashes from key
    $activation_key = str_replace('-', '', $activation_key);
    $activation_key = strtoupper($activation_key);
    
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
            'Y' => '12months',
            '1' => '12months',
            '6' => '6months',
            '3' => '3months',
            'A' => '12months',
            'B' => '12months',
            'C' => '6months',
            'D' => '6months',
            'E' => '3months',
            'F' => '3months',
            'G' => '1month'
        );
        
        $duration = isset($duration_map[$duration_code]) ? $duration_map[$duration_code] : '2days';
        
        return array(
            'valid' => true,
            'duration' => $duration,
            'system_id' => $system_id,
            'message' => 'Activation successful'
        );
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
        'system_id' => $system_id
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
    
} elseif ($_SERVER['REQUEST_METHOD'] == 'GET') {
    // Simple status check
    echo json_encode(array('status' => 'active', 'service' => 'Activation Key Server', 'version' => '2.0'));
} else {
    echo json_encode(array('valid' => false, 'error' => 'Only POST and GET requests allowed'));
}
?>