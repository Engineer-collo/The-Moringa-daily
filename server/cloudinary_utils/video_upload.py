from flask import Blueprint, request, jsonify
import cloudinary.uploader

video_upload_bp = Blueprint('video_upload', __name__)

@video_upload_bp.route('/upload-video', methods=['POST'])
def upload_video():
    if 'video' not in request.files:
        return jsonify({'error': 'No video part'}), 400

    video_file = request.files['video']

    try:
        result = cloudinary.uploader.upload_large(
            video_file,
            resource_type='video'
        )
        return jsonify({'secure_url': result['secure_url']}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
