"""
AI Fingerprint matching engine.
Uses OpenCV for image preprocessing and a CNN model for matching.
Falls back to ORB feature matching when the CNN model is not available.
"""
import os
import io
import hashlib
import numpy as np
import cv2
from PIL import Image

# Try importing TensorFlow - fall back to OpenCV-only if not available
try:
    import tensorflow as tf
    from tensorflow import keras
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

FINGERPRINT_SIZE = (96, 96)
MATCH_THRESHOLD = 0.75


def preprocess_fingerprint(image_data):
    """
    Preprocess a fingerprint image for matching.
    - Convert to grayscale
    - Apply histogram equalization
    - Apply Gaussian blur
    - Apply adaptive thresholding
    - Resize to standard dimensions
    """
    # Convert bytes to numpy array
    if isinstance(image_data, bytes):
        nparr = np.frombuffer(image_data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
    elif isinstance(image_data, np.ndarray):
        if len(image_data.shape) == 3:
            img = cv2.cvtColor(image_data, cv2.COLOR_BGR2GRAY)
        else:
            img = image_data
    else:
        # Try to open with PIL
        pil_img = Image.open(io.BytesIO(image_data) if isinstance(image_data, bytes) else image_data)
        img = np.array(pil_img.convert('L'))
    
    if img is None:
        raise ValueError("Could not decode fingerprint image")
    
    # Histogram equalization for contrast enhancement
    img = cv2.equalizeHist(img)
    
    # Gaussian blur to reduce noise
    img = cv2.GaussianBlur(img, (5, 5), 0)
    
    # Adaptive threshold for ridge extraction
    img = cv2.adaptiveThreshold(
        img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 11, 2
    )
    
    # Resize to standard dimensions
    img = cv2.resize(img, FINGERPRINT_SIZE)
    
    return img


def extract_features_orb(img):
    """Extract ORB features from a fingerprint image."""
    orb = cv2.ORB_create(nfeatures=500)
    keypoints, descriptors = orb.detectAndCompute(img, None)
    return keypoints, descriptors


def match_fingerprints_orb(img1, img2):
    """
    Match two fingerprint images using ORB feature matching.
    Returns a similarity score between 0 and 1.
    """
    _, desc1 = extract_features_orb(img1)
    _, desc2 = extract_features_orb(img2)
    
    if desc1 is None or desc2 is None:
        return 0.0
    
    # Use BFMatcher with Hamming distance for ORB
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    
    try:
        matches = bf.knnMatch(desc1, desc2, k=2)
    except cv2.error:
        return 0.0
    
    # Apply Lowe's ratio test
    good_matches = []
    for match_pair in matches:
        if len(match_pair) == 2:
            m, n = match_pair
            if m.distance < 0.75 * n.distance:
                good_matches.append(m)
    
    # Calculate similarity score
    if len(matches) == 0:
        return 0.0
    
    score = len(good_matches) / max(len(desc1), len(desc2))
    return min(score * 2.5, 1.0)  # Scale up and cap at 1.0


def build_cnn_model():
    """Build a simple CNN model for fingerprint feature extraction."""
    if not TF_AVAILABLE:
        return None
    
    model = keras.Sequential([
        keras.layers.Input(shape=(96, 96, 1)),
        keras.layers.Conv2D(32, (3, 3), activation='relu', padding='same'),
        keras.layers.BatchNormalization(),
        keras.layers.MaxPooling2D((2, 2)),
        keras.layers.Conv2D(64, (3, 3), activation='relu', padding='same'),
        keras.layers.BatchNormalization(),
        keras.layers.MaxPooling2D((2, 2)),
        keras.layers.Conv2D(128, (3, 3), activation='relu', padding='same'),
        keras.layers.BatchNormalization(),
        keras.layers.MaxPooling2D((2, 2)),
        keras.layers.Conv2D(256, (3, 3), activation='relu', padding='same'),
        keras.layers.BatchNormalization(),
        keras.layers.GlobalAveragePooling2D(),
        keras.layers.Dense(128, activation='relu'),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(64, activation='sigmoid')  # 64-dim embedding
    ])
    
    return model


# Global CNN model (lazy loaded)
_cnn_model = None


def get_cnn_model():
    """Get or create the CNN model singleton."""
    global _cnn_model
    if _cnn_model is None and TF_AVAILABLE:
        _cnn_model = build_cnn_model()
    return _cnn_model


def extract_cnn_embedding(img):
    """Extract CNN embedding from a preprocessed fingerprint."""
    model = get_cnn_model()
    if model is None:
        return None
    
    # Prepare image for CNN
    img_normalized = img.astype('float32') / 255.0
    img_batch = np.expand_dims(np.expand_dims(img_normalized, axis=-1), axis=0)
    
    embedding = model.predict(img_batch, verbose=0)
    return embedding[0]


def match_fingerprints_cnn(img1, img2):
    """
    Match fingerprints using CNN embeddings and cosine similarity.
    """
    emb1 = extract_cnn_embedding(img1)
    emb2 = extract_cnn_embedding(img2)
    
    if emb1 is None or emb2 is None:
        return match_fingerprints_orb(img1, img2)
    
    # Cosine similarity
    dot_product = np.dot(emb1, emb2)
    norm1 = np.linalg.norm(emb1)
    norm2 = np.linalg.norm(emb2)
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
    
    similarity = dot_product / (norm1 * norm2)
    return float(max(0.0, similarity))


def match_fingerprints(img_data1, img_data2, method='auto'):
    """
    Main fingerprint matching function.
    
    Args:
        img_data1: First fingerprint image (bytes or numpy array)
        img_data2: Second fingerprint image (bytes or numpy array)
        method: 'orb', 'cnn', or 'auto' (tries CNN first, falls back to ORB)
    
    Returns:
        tuple: (is_match: bool, score: float, method_used: str)
    """
    try:
        processed1 = preprocess_fingerprint(img_data1)
        processed2 = preprocess_fingerprint(img_data2)
    except Exception as e:
        return False, 0.0, f'error: {str(e)}'
    
    if method == 'cnn' or (method == 'auto' and TF_AVAILABLE):
        score = match_fingerprints_cnn(processed1, processed2)
        method_used = 'cnn'
    else:
        score = match_fingerprints_orb(processed1, processed2)
        method_used = 'orb'
    
    # If CNN score is very low, also try ORB for a combined score
    if method == 'auto' and method_used == 'cnn' and score < 0.3:
        orb_score = match_fingerprints_orb(processed1, processed2)
        if orb_score > score:
            score = (score + orb_score) / 2
            method_used = 'hybrid'
    
    is_match = score >= MATCH_THRESHOLD
    return is_match, round(score, 4), method_used


def generate_fingerprint_hash(img_data):
    """
    Generate a unique hash from fingerprint image data.
    Used for quick duplicate detection.
    """
    try:
        processed = preprocess_fingerprint(img_data)
        # Create a perceptual hash
        resized = cv2.resize(processed, (32, 32))
        flat = resized.flatten()
        mean = flat.mean()
        binary = (flat > mean).astype(np.uint8)
        hash_bytes = np.packbits(binary).tobytes()
        return hashlib.sha256(hash_bytes).hexdigest()
    except Exception:
        return hashlib.sha256(img_data if isinstance(img_data, bytes) else b'').hexdigest()


def generate_template(img_data):
    """
    Generate a compact fingerprint template for storage.
    """
    try:
        processed = preprocess_fingerprint(img_data)
        # Store the processed and compressed image as the template
        _, buffer = cv2.imencode('.png', processed)
        return buffer.tobytes()
    except Exception:
        return None
