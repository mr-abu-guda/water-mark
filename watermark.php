<?php
// =====================================================================
// Watermark PHP API v2.0
// =====================================================================

@set_time_limit(180);
@ini_set('memory_limit', '256M');
@ini_set('max_execution_time', '180');

header('Content-Type: application/json; charset=utf-8');
error_reporting(0);
ini_set('display_errors', '0');

// ---------- Configuration ----------
define('LOGO_URL', getenv('WATERMARK_LOGO_URL') ?: 'https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgnmeBqYlMAGrIoBDjfooPRcF43BJ71ZSLLm-dWTVU1hGBvSAVeAo5C4PY2tsBned2rINPnd_tWoC40NP2BZ6vXnapfoigzcyaTp4WkAGvOBpWp5hz95Es1Mln_Owo5UlSEypYgyEUM634mSgztY-Yx88LcmW0zjB3YkPD0jZxYJXuzUGBP9yriYETaTDE/s500/blfym1%20(2).png');

define('MAX_FILE_SIZE', 15 * 1024 * 1024);
define('DOWNLOAD_TIMEOUT', 25);
define('DOWNLOAD_MAX_BYTES', 20 * 1024 * 1024);

define('IMGBB_API_KEY', getenv('IMGBB_API_KEY') ?: '');
define('IMGBB_API_URL', 'https://api.imgbb.com/1/upload');
define('IMGBB_BAN_HOURS', 12);
// ✅ تم التعديل: /tmp لأن المشروع في Render للقراءة فقط
define('IMGBB_BAN_STATE_FILE', getenv('IMGBB_BAN_STATE_FILE') ?: '/tmp/.imgbb_bans.json');

// ---------- JSON response ----------
function respond($success, $data = array(), $status = 200)
{
    http_response_code($status);
    echo json_encode(
        array_merge(array('success' => $success), $data),
        JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
    );
    exit;
}

// ---------- HTTP helpers ----------
function httpGetBinary($url, $timeout = DOWNLOAD_TIMEOUT, $maxBytes = DOWNLOAD_MAX_BYTES)
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
            CURLOPT_HTTPHEADER => array('Accept: image/*,*/*;q=0.8'),
            CURLOPT_MAXFILESIZE => $maxBytes
        ));
        $data = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($data !== false && $status >= 200 && $status < 300 && strlen($data) <= $maxBytes) {
            return $data;
        }
    }
    $context = stream_context_create(array(
        'http' => array(
            'timeout' => $timeout,
            'follow_location' => 1,
            'user_agent' => 'Mozilla/5.0',
            'header' => "Accept: image/*\r\n"
        ),
        'ssl' => array('verify_peer' => false, 'verify_peer_name' => false)
    ));
    $data = @file_get_contents($url, false, $context, 0, $maxBytes);
    return $data !== false ? $data : false;
}

function httpPostForm($url, $postData, $timeout = 45)
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postData,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_FOLLOWLOCATION => false
        ));
        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return array('body' => $response, 'status' => $status);
    }
    $context = stream_context_create(array(
        'http' => array(
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $postData,
            'timeout' => $timeout,
            'ignore_errors' => true
        ),
        'ssl' => array('verify_peer' => true, 'verify_peer_name' => true)
    ));
    $response = @file_get_contents($url, false, $context);
    $status = 0;
    if (!empty($http_response_header)) {
        foreach ($http_response_header as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d+)#', $h, $m)) { $status = (int)$m[1]; break; }
        }
    }
    return array('body' => $response, 'status' => $status);
}

// ---------- SSRF basic protection ----------
function isSafeUrl($url)
{
    $parsed = parse_url($url);
    if (!$parsed || empty($parsed['host']) || empty($parsed['scheme'])) return false;
    if (!in_array(strtolower($parsed['scheme']), array('http', 'https'), true)) return false;
    $host = strtolower($parsed['host']);
    if (in_array($host, array('localhost', '127.0.0.1', '::1', '0.0.0.0'), true)) return false;
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        if (!filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
    }
    return true;
}

// ---------- ImgBB ban state ----------
function getBannedKeys()
{
    $dir = dirname(IMGBB_BAN_STATE_FILE);
    if (!is_writable($dir)) {
        return $GLOBALS['__imgbb_session_bans'] ?? array();
    }
    if (!is_file(IMGBB_BAN_STATE_FILE)) return array();
    $content = @file_get_contents(IMGBB_BAN_STATE_FILE);
    if (!$content) return array();
    $data = @json_decode($content, true);
    if (!is_array($data)) return array();
    $now = time();
    $clean = array();
    foreach ($data as $hash => $info) {
        if (is_array($info) && isset($info['until']) && (int)$info['until'] > $now) {
            $clean[$hash] = $info;
        }
    }
    return $clean;
}

function saveBannedKeys($data)
{
    $dir = dirname(IMGBB_BAN_STATE_FILE);
    if (!is_writable($dir)) {
        $GLOBALS['__imgbb_session_bans'] = $data;
        return;
    }
    @file_put_contents(IMGBB_BAN_STATE_FILE, json_encode($data), LOCK_EX);
}

function banImgBBKey($hash, $reason)
{
    $bans = getBannedKeys();
    $bans[$hash] = array(
        'until' => time() + IMGBB_BAN_HOURS * 3600,
        'banned_at' => time(),
        'reason' => substr((string)$reason, 0, 200)
    );
    saveBannedKeys($bans);
}

function getActiveImgBBKeys()
{
    $raw = array_filter(array_map('trim', explode(',', IMGBB_API_KEY)));
    if (!$raw) return array('active' => array(), 'banned' => array());
    $bans = getBannedKeys();
    $now = time();
    $active = array();
    $banned = array();
    foreach ($raw as $i => $key) {
        $hash = hash('sha256', $key);
        if (isset($bans[$hash]) && (int)$bans[$hash]['until'] > $now) {
            $banned[] = array('index' => $i, 'hash' => substr($hash, 0, 8), 'until' => (int)$bans[$hash]['until']);
        } else {
            $active[] = array('key' => $key, 'hash' => $hash, 'index' => $i);
        }
    }
    return array('active' => $active, 'banned' => $banned);
}

// ---------- ImgBB upload with rotation ----------
function uploadToImgBB($imageBase64)
{
    if (empty(IMGBB_API_KEY) || strpos(IMGBB_API_KEY, 'YOUR_') !== false) {
        return null;
    }

    $info = getActiveImgBBKeys();
    if (!$info['active']) return null;

    foreach ($info['active'] as $item) {
        $label = 'key #' . ($item['index'] + 1);
        $r = httpPostForm(IMGBB_API_URL, http_build_query(array(
            'image' => $imageBase64,
            'key' => $item['key']
        )), 45);

        if ($r['status'] === 429) {
            banImgBBKey($item['hash'], '429 Too Many Requests');
            continue;
        }

        if (!$r['body']) continue;

        $data = json_decode($r['body'], true);

        if ($r['status'] >= 200 && $r['status'] < 300 && !empty($data['success']) && !empty($data['data']['url'])) {
            return array('url' => $data['data']['url'], 'key_index' => $item['index']);
        }

        $errMsg = json_encode($data ?: array());
        if (preg_match('/429|rate.?limit|too many/i', $errMsg)) {
            banImgBBKey($item['hash'], '429 (body)');
        }
    }

    return null;
}

// ---------- Image decoding ----------
function imageFromBinary($binary)
{
    if (!is_string($binary) || $binary === '') return false;
    if (strlen($binary) > MAX_FILE_SIZE) return false;

    $info = @getimagesizefromstring($binary);
    if (!$info || empty($info['mime'])) return false;

    $allowed = array('image/jpeg', 'image/png', 'image/webp', 'image/gif');
    if (!in_array($info['mime'], $allowed, true)) return false;

    $image = @imagecreatefromstring($binary);
    return $image ?: false;
}

function decodeImageFromUrl($url)
{
    if (!isSafeUrl($url)) return false;
    $binary = httpGetBinary($url);
    if ($binary === false) return false;
    return imageFromBinary($binary);
}

function decodeImageFromBase64($data)
{
    if (!is_string($data) || $data === '') return false;
    if (strpos($data, ',') !== false) {
        $parts = explode(',', $data, 2);
        $data = $parts[1];
    }
    $binary = base64_decode($data, true);
    if ($binary === false) return false;
    return imageFromBinary($binary);
}

function decodeImage($data)
{
    if (!is_string($data) || $data === '') return false;
    $trimmed = trim($data);

    if (preg_match('#^https?://#i', $trimmed)) {
        return decodeImageFromUrl($trimmed);
    }

    return decodeImageFromBase64($trimmed);
}

// ---------- Logo ----------
function loadLogo()
{
    static $cached = null;
    static $attempted = false;
    if ($attempted) return $cached;
    $attempted = true;

    $binary = httpGetBinary(LOGO_URL, 15, 10 * 1024 * 1024);
    if ($binary === false) { $cached = false; return false; }

    $info = @getimagesizefromstring($binary);
    if (!$info || strpos($info['mime'], 'image/') !== 0) { $cached = false; return false; }

    $cached = @imagecreatefromstring($binary) ?: false;
    return $cached;
}

// ---------- Watermark ----------
function addCenterLogo($image, $logo)
{
    if (!$logo) return $image;

    $width = imagesx($image);
    $height = imagesy($image);
    $logoWidth = imagesx($logo);
    $logoHeight = imagesy($logo);

    if ($logoWidth < 1 || $logoHeight < 1) {
        imagedestroy($logo);
        return $image;
    }

    $targetWidth = max(1, (int)($width * 0.80));
    $scale = $targetWidth / $logoWidth;
    $targetHeight = max(1, (int)($logoHeight * $scale));

    $maxHeight = max(1, (int)($height * 0.80));
    if ($targetHeight > $maxHeight) {
        $scale = $maxHeight / $targetHeight;
        $targetWidth = max(1, (int)($targetWidth * $scale));
        $targetHeight = max(1, (int)($targetHeight * $scale));
    }

    $resized = imagecreatetruecolor($targetWidth, $targetHeight);
    imagealphablending($resized, false);
    imagesavealpha($resized, true);
    $transparent = imagecolorallocatealpha($resized, 0, 0, 0, 127);
    imagefill($resized, 0, 0, $transparent);

    imagecopyresampled(
        $resized, $logo,
        0, 0, 0, 0,
        $targetWidth, $targetHeight,
        $logoWidth, $logoHeight
    );

    for ($y = 0; $y < $targetHeight; $y++) {
        for ($x = 0; $x < $targetWidth; $x++) {
            $pixel = imagecolorat($resized, $x, $y);
            $alpha = ($pixel >> 24) & 0x7F;
            $red = ($pixel >> 16) & 0xFF;
            $green = ($pixel >> 8) & 0xFF;
            $blue = $pixel & 0xFF;
            $newAlpha = (int)(127 - ((127 - $alpha) * 0.42));
            $color = imagecolorallocatealpha($resized, $red, $green, $blue, max(0, min(127, $newAlpha)));
            imagesetpixel($resized, $x, $y, $color);
        }
    }

    $x = (int)(($width - $targetWidth) / 2);
    $y = (int)(($height - $targetHeight) / 2);

    imagealphablending($image, true);
    imagecopy($image, $resized, $x, $y, 0, 0, $targetWidth, $targetHeight);

    imagedestroy($resized);
    imagedestroy($logo);
    return $image;
}

// =====================================================================
// MAIN
// =====================================================================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(false, array('message' => 'استخدم POST لإرسال الصورة.'), 405);
}

if (!extension_loaded('gd')) {
    respond(false, array('message' => 'مكتبة GD غير مفعلة على الخادم.'), 500);
}

$rawInput = file_get_contents('php://input');
$request = json_decode($rawInput, true);

if (!is_array($request)) {
    respond(false, array('message' => 'بيانات الطلب غير صحيحة.'), 400);
}

if (empty($request['image'])) {
    respond(false, array('message' => 'لم يتم إرسال صورة (image مطلوب: URL أو base64).'), 400);
}

$image = decodeImage($request['image']);

if (!$image) {
    respond(false, array(
        'message' => 'الصورة غير صالحة، أو الرابط غير آمن، أو الحجم > 15MB، أو فشل التنزيل.'
    ), 400);
}

$width = imagesx($image);
$height = imagesy($image);

if ($width > 8000 || $height > 8000 || ($width * $height) > 30000000) {
    imagedestroy($image);
    respond(false, array('message' => 'أبعاد الصورة كبيرة جدًا.'), 400);
}

$logo = loadLogo();
if ($logo) {
    $image = addCenterLogo($image, $logo);
}

ob_start();
imagepng($image, null, 6);
$imageBinary = ob_get_clean();
imagedestroy($image);

if (!$imageBinary) {
    respond(false, array('message' => 'تعذر إنشاء الصورة النهائية.'), 500);
}

$imageBase64 = base64_encode($imageBinary);

$imgbbResult = uploadToImgBB($imageBase64);

if ($imgbbResult && !empty($imgbbResult['url'])) {
    respond(true, array(
        'message' => 'تمت معالجة الصورة ورفعها إلى ImgBB بنجاح.',
        'image' => $imgbbResult['url'],
        'host' => 'imgbb',
        'key_index' => $imgbbResult['key_index'],
        'filename' => 'mine-android-watermarked.png',
        'width' => $width,
        'height' => $height,
        'size' => strlen($imageBinary)
    ));
}

respond(true, array(
    'message' => 'تمت معالجة الصورة (تعذّر الرفع لـ ImgBB؛ أُعيدت base64 كاحتياطي).',
    'image' => 'data:image/png;base64,' . $imageBase64,
    'host' => 'fallback',
    'filename' => 'mine-android-watermarked.png',
    'width' => $width,
    'height' => $height,
    'size' => strlen($imageBinary)
));