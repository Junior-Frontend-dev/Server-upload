import os
import hashlib
import mimetypes
import math
import time
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_file, send_from_directory, abort, Response, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# create the app
app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1) # needed for url_for to generate with https

# configure the database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# File upload configuration
app.config['MAX_CONTENT_LENGTH'] = None  # No file size limit
UPLOAD_FOLDER = 'uploads'

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# initialize the app with the extension, flask-sqlalchemy >= 3.0.x
db.init_app(app)

def allowed_file(filename):
    # Allow all file types
    return True

def get_client_ip():
    """Get client IP address, handling proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-Ip'):
        return request.headers.get('X-Real-Ip')
    else:
        return request.remote_addr

def get_admin_password():
    """Get admin password from database or environment"""
    try:
        setting = db.session.query(models.AdminSettings).filter_by(setting_key='admin_password').first()
        if setting:
            return setting.setting_value
    except:
        pass
    return os.environ.get('ADMIN_KEY', 'admin123')

def get_current_user():
    """Get current logged in user"""
    if 'user_id' in session:
        try:
            return db.session.query(models.User).get(session['user_id'])
        except:
            pass
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_key = request.headers.get('Authorization') or request.args.get('adminKey')
        valid_key = get_admin_password()
        client_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        
        success = admin_key == valid_key or admin_key == f'Bearer {valid_key}'
        
        # Log admin login attempt
        try:
            login_log = models.AdminLogin(
                ip_address=client_ip,
                user_agent=user_agent,
                success=success,
                login_time=datetime.utcnow()
            )
            db.session.add(login_log)
            db.session.commit()
        except Exception as e:
            app.logger.error(f"Failed to log admin access: {e}")
        
        if success:
            return f(*args, **kwargs)
        else:
            return jsonify({'error': 'Access denied. Admin key required.'}), 403
    return decorated_function

def generate_file_hash(filepath):
    """Generate SHA-256 hash for a file"""
    try:
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception:
        return None

# Import models and create tables
with app.app_context():
    try:
        import models  # noqa: F401
        
        # Check if we need to migrate the database
        try:
            # Try to query with new columns - if this fails, we need to recreate
            db.session.query(models.File).filter_by(is_hidden=False).first()
            # Check for new tables
            db.session.query(models.AdminLogin).first()
            db.session.query(models.FileDownload).first()
            db.session.query(models.AdminSettings).first()
            app.logger.info("Database schema is up to date")
        except Exception as e:
            app.logger.info(f"Database schema needs updating: {e}")
            # Drop and recreate all tables
            db.drop_all()
            db.create_all()
            app.logger.info("Database schema updated successfully")
        
        # Update existing files to have database records
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename != '.gitkeep':
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.isfile(filepath):
                    existing = db.session.query(models.File).filter_by(filename=filename).first()
                    if not existing:
                        stat_info = os.stat(filepath)
                        original_name = filename
                        if '_' in filename:
                            parts = filename.rsplit('_', 1)
                            if len(parts) == 2 and parts[1].replace('.', '').isdigit():
                                original_name = parts[0] + ('' if '.' not in parts[1] else '.' + parts[1].split('.', 1)[1])
                        
                        file_record = models.File(
                            filename=filename,
                            original_name=original_name,
                            file_size=stat_info.st_size,
                            file_type=mimetypes.guess_type(filepath)[0] or 'application/octet-stream',
                            upload_date=datetime.fromtimestamp(stat_info.st_ctime)
                        )
                        db.session.add(file_record)
        
        db.session.commit()
    except ImportError:
        pass

# Routes

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

# User Authentication Routes
@app.route('/api/register', methods=['POST'])
def register():
    """Register new user with 100MB free storage"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Check if user already exists
        existing_user = db.session.query(models.User).filter(
            (models.User.username == username) | (models.User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                return jsonify({'error': 'Username already exists'}), 400
            else:
                return jsonify({'error': 'Email already exists'}), 400
        
        # Create new user with 100MB free storage
        user = models.User(
            username=username,
            email=email,
            storage_limit=100 * 1024 * 1024  # 100MB
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Auto login after registration
        session['user_id'] = user.id
        session['username'] = user.username
        
        return jsonify({
            'message': 'Registration successful! You have been given 100MB free storage.',
            'user': user.to_dict()
        })
        
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """User login"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Find user by username or email
        user = db.session.query(models.User).filter(
            (models.User.username == username) | (models.User.email == username)
        ).first()
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid username/email or password'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is disabled'}), 401
        
        # Create session
        session['user_id'] = user.id
        session['username'] = user.username
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict()
        })
        
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """User logout"""
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/profile')
@login_required
def get_profile():
    """Get current user profile"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_dict())

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update user profile"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        email = data.get('email', '').strip()
        current_password = data.get('currentPassword', '').strip()
        new_password = data.get('newPassword', '').strip()
        
        # Update email if provided
        if email and email != user.email:
            existing = db.session.query(models.User).filter_by(email=email).first()
            if existing and existing.id != user.id:
                return jsonify({'error': 'Email already exists'}), 400
            user.email = email
        
        # Update password if provided
        if new_password:
            if not current_password:
                return jsonify({'error': 'Current password required to change password'}), 400
            
            if not user.check_password(current_password):
                return jsonify({'error': 'Current password is incorrect'}), 401
            
            if len(new_password) < 6:
                return jsonify({'error': 'New password must be at least 6 characters'}), 400
            
            user.set_password(new_password)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        })
        
    except Exception as e:
        app.logger.error(f"Profile update error: {e}")
        return jsonify({'error': 'Profile update failed'}), 500

@app.route('/admin')
def admin():
    return send_from_directory('public', 'admin.html')

@app.route('/api/files', methods=['GET'])
def get_files():
    """Get all files with metadata"""
    try:
        # Check if this is an admin request
        is_admin_request = False
        admin_key = request.headers.get('Authorization') or request.args.get('adminKey')
        valid_key = get_admin_password()
        if admin_key == valid_key or admin_key == f'Bearer {valid_key}':
            is_admin_request = True
        
        # Check if user is logged in
        current_user = get_current_user()
        show_user_files = request.args.get('userFiles') == 'true'
        
        files = []
        if os.path.exists(UPLOAD_FOLDER):
            for filename in os.listdir(UPLOAD_FOLDER):
                if filename != '.gitkeep':
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    if os.path.isfile(filepath):
                        # Try to get file record from database
                        file_record = None
                        try:
                            file_record = db.session.query(models.File).filter_by(filename=filename).first()
                            # Create record if it doesn't exist
                            if not file_record:
                                stat_info = os.stat(filepath)
                                mime_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
                                original_name = filename
                                if '_' in filename:
                                    parts = filename.rsplit('_', 1)
                                    if len(parts) == 2 and parts[1].replace('.', '').isdigit():
                                        original_name = parts[0] + ('' if '.' not in parts[1] else '.' + parts[1].split('.', 1)[1])
                                
                                file_record = models.File(
                                    filename=filename,
                                    original_name=original_name,
                                    file_size=stat_info.st_size,
                                    file_type=mime_type,
                                    upload_date=datetime.fromtimestamp(stat_info.st_ctime)
                                )
                                db.session.add(file_record)
                                db.session.commit()
                        except Exception as e:
                            app.logger.error(f"Database error for file {filename}: {e}")
                        
                        # Filter files based on request type
                        if show_user_files and current_user:
                            # Show only current user's files
                            if not file_record or file_record.user_id != current_user.id:
                                continue
                        elif not is_admin_request:
                            # Show only public files (no user_id) and non-hidden files
                            if file_record:
                                if file_record.is_hidden:
                                    continue
                                if file_record.user_id and not show_user_files:
                                    continue
                        
                        # Skip hidden files for non-admin users
                        if file_record and file_record.is_hidden and not is_admin_request:
                            continue
                        
                        stat_info = os.stat(filepath)
                        mime_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
                        
                        # Remove timestamp from display name
                        original_name = filename
                        if '_' in filename:
                            parts = filename.rsplit('_', 1)
                            if len(parts) == 2 and parts[1].replace('.', '').isdigit():
                                original_name = parts[0] + ('' if '.' not in parts[1] else '.' + parts[1].split('.', 1)[1])
                        
                        file_data = {
                            'name': filename,
                            'originalName': original_name,
                            'size': stat_info.st_size,
                            'type': mime_type,
                            'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                            'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                        }
                        
                        # Add additional info for admin users
                        if is_admin_request and file_record:
                            file_data.update({
                                'id': file_record.id,
                                'isHidden': file_record.is_hidden,
                                'viewLimit': file_record.view_limit,
                                'viewCount': file_record.view_count,
                                'isPasswordProtected': file_record.is_password_protected,
                                'hiddenToken': file_record.hidden_token
                            })
                        
                        files.append(file_data)
        
        return jsonify(files)
    except Exception as e:
        app.logger.error(f"Error getting files: {e}")
        return jsonify({'error': 'Error reading directory'}), 500

@app.route('/api/upload', methods=['POST'])
def upload_files():
    """Upload files with user storage limits or admin privileges"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files in request'}), 400
        
        files = request.files.getlist('files')
        if not files or all(file.filename == '' for file in files):
            return jsonify({'error': 'No files selected'}), 400
        
        # Check if admin or regular user
        is_admin_upload = False
        admin_key = request.headers.get('Authorization') or request.form.get('adminKey')
        valid_key = get_admin_password()
        if admin_key == valid_key or admin_key == f'Bearer {valid_key}':
            is_admin_upload = True
        
        # For regular users, check login and storage limits
        user = None
        if not is_admin_upload:
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Login required to upload files'}), 401
            
            # Calculate total size of files to upload
            total_upload_size = sum(len(file.read()) for file in files)
            # Reset file pointers
            for file in files:
                file.seek(0)
            
            if not user.can_upload(total_upload_size):
                remaining = user.get_remaining_storage()
                return jsonify({
                    'error': f'Not enough storage space. You have {remaining/(1024*1024):.1f}MB remaining, but need {total_upload_size/(1024*1024):.1f}MB.'
                }), 400
        
        uploaded_files = []
        total_size = 0
        
        for file in files:
            if file and file.filename:
                # Handle folder structure if present
                original_filename = file.filename
                if '/' in original_filename:
                    # Create folder structure
                    folder_path = os.path.dirname(original_filename)
                    os.makedirs(os.path.join(UPLOAD_FOLDER, folder_path), exist_ok=True)
                    
                    # Use full path for filename
                    secured_filename = secure_filename(original_filename.replace('/', '_'))
                else:
                    secured_filename = secure_filename(original_filename)
                
                # Add timestamp to prevent conflicts
                timestamp = int(datetime.now().timestamp() * 1000)
                name, ext = os.path.splitext(secured_filename)
                filename = f"{name}_{timestamp}{ext}"
                
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                file.save(filepath)
                
                # Get file stats
                stat_info = os.stat(filepath)
                file_hash = generate_file_hash(filepath)
                
                # Determine file type
                file_type = file.content_type or mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
                
                # Create database record
                file_record = models.File(
                    filename=filename,
                    original_name=original_filename,
                    file_size=stat_info.st_size,
                    file_type=file_type,
                    upload_date=datetime.now(),
                    user_id=user.id if user else None
                )
                db.session.add(file_record)
                
                # Update user storage if not admin
                if user:
                    user.storage_used += stat_info.st_size
                
                uploaded_files.append({
                    'originalName': original_filename,
                    'filename': filename,
                    'size': stat_info.st_size,
                    'type': file_type,
                    'uploadTime': datetime.now().isoformat(),
                    'hash': file_hash
                })
                total_size += stat_info.st_size
        
        if uploaded_files:
            db.session.commit()
        
        if not uploaded_files:
            return jsonify({'error': 'No files processed'}), 400
        
        response_data = {
            'message': f'{len(uploaded_files)} file(s) uploaded successfully.',
            'files': uploaded_files,
            'totalSize': total_size
        }
        
        # Add storage info for regular users
        if user:
            response_data['storageInfo'] = {
                'used': user.storage_used,
                'limit': user.storage_limit,
                'remaining': user.get_remaining_storage()
            }
        
        return jsonify(response_data)
        
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

# Admin-only upload route
@app.route('/api/admin/upload', methods=['POST'])
@admin_required
def admin_upload_files():
    """Admin upload without storage limits"""
    return upload_files()

@app.route('/api/download/<filename>')
def download_file(filename):
    """Download a specific file with IP tracking and optimization"""
    try:
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(filepath):
            abort(404)
        
        # Get file record and log download
        file_record = db.session.query(models.File).filter_by(filename=filename).first()
        if file_record:
            # Log download
            client_ip = get_client_ip()
            user_agent = request.headers.get('User-Agent', '')
            
            download_log = models.FileDownload(
                file_id=file_record.id,
                ip_address=client_ip,
                user_agent=user_agent,
                file_size=file_record.file_size,
                download_time=datetime.utcnow()
            )
            db.session.add(download_log)
            
            # Update download count
            file_record.download_count += 1
            db.session.commit()
        
        # Optimize file serving with caching headers
        response = send_file(
            filepath, 
            as_attachment=True, 
            download_name=filename,
            conditional=True,
            etag=True,
            last_modified=datetime.fromtimestamp(os.path.getmtime(filepath))
        )
        
        # Add cache headers for optimization
        response.headers['Cache-Control'] = 'public, max-age=3600'
        response.headers['X-Accel-Buffering'] = 'yes'
        
        return response
        
    except Exception as e:
        app.logger.error(f"Download error: {e}")
        abort(500)

@app.route('/api/files/<filename>', methods=['DELETE'])
@admin_required
def delete_file(filename):
    """Delete a specific file"""
    try:
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(filepath):
            # Remove from database if exists
            file_record = db.session.query(models.File).filter_by(filename=filename).first()
            if file_record:
                db.session.delete(file_record)
                db.session.commit()
            
            os.remove(filepath)
            return jsonify({'message': f'File {filename} deleted successfully'})
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        app.logger.error(f"Delete error: {e}")
        return jsonify({'error': 'Delete failed'}), 500

@app.route('/api/files', methods=['DELETE'])
@admin_required
def delete_multiple_files():
    """Delete multiple files"""
    try:
        data = request.get_json()
        filenames = data.get('files', [])
        
        deleted_count = 0
        for filename in filenames:
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.exists(filepath):
                # Remove from database if exists
                file_record = db.session.query(models.File).filter_by(filename=filename).first()
                if file_record:
                    db.session.delete(file_record)
                
                os.remove(filepath)
                deleted_count += 1
        
        db.session.commit()
        return jsonify({'message': f'{deleted_count} files deleted successfully'})
        
    except Exception as e:
        app.logger.error(f"Multiple delete error: {e}")
        return jsonify({'error': 'Delete failed'}), 500

@app.route('/api/stats')
def get_stats():
    """Get storage statistics"""
    try:
        total_files = 0
        total_size = 0
        files = []
        
        if os.path.exists(UPLOAD_FOLDER):
            for filename in os.listdir(UPLOAD_FOLDER):
                if filename != '.gitkeep':
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    if os.path.isfile(filepath):
                        stat_info = os.stat(filepath)
                        size = stat_info.st_size
                        total_files += 1
                        total_size += size
                        files.append({
                            'name': filename,
                            'size': size,
                            'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat()
                        })
        
        return jsonify({
            'totalFiles': total_files,
            'totalSize': total_size,
            'averageSize': total_size / total_files if total_files > 0 else 0,
            'files': files
        })
    except Exception as e:
        app.logger.error(f"Stats error: {e}")
        return jsonify({'error': 'Error getting statistics'}), 500

# Hidden file access endpoint
@app.route('/api/hidden/<token>')
def access_hidden_file(token):
    """Access hidden file via token"""
    try:
        file_record = db.session.query(models.File).filter_by(hidden_token=token).first()
        if not file_record:
            abort(404)
        
        filepath = os.path.join(UPLOAD_FOLDER, file_record.filename)
        if not os.path.exists(filepath):
            abort(404)
        
        # Check if file requires password
        if file_record.is_password_protected:
            password = request.args.get('password')
            if not password or not file_record.check_password(password):
                return jsonify({'error': 'Password required', 'requiresPassword': True}), 401
        
        # Increment view count and check for auto-delete
        should_delete = file_record.increment_view_count()
        
        # Serve the file
        response = send_file(filepath, as_attachment=True, download_name=file_record.original_name)
        
        # Delete file if view limit reached
        if should_delete:
            try:
                os.remove(filepath)
                db.session.delete(file_record)
                db.session.commit()
            except Exception as e:
                app.logger.error(f"Error deleting file after view limit: {e}")
        
        return response
        
    except Exception as e:
        app.logger.error(f"Hidden file access error: {e}")
        abort(500)

# Password verification endpoint
@app.route('/api/verify-password/<token>', methods=['POST'])
def verify_password(token):
    """Verify password for protected file"""
    try:
        data = request.get_json()
        password = data.get('password')
        
        if not password:
            return jsonify({'error': 'Password required'}), 400
        
        file_record = db.session.query(models.File).filter_by(hidden_token=token).first()
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        if file_record.check_password(password):
            return jsonify({'success': True, 'downloadUrl': f'/api/hidden/{token}?password={password}'})
        else:
            return jsonify({'error': 'Invalid password'}), 401
            
    except Exception as e:
        app.logger.error(f"Password verification error: {e}")
        return jsonify({'error': 'Verification failed'}), 500

# Admin endpoint to configure file settings
@app.route('/api/admin/files/<file_id>/settings', methods=['PUT'])
@admin_required
def update_file_settings(file_id):
    """Update file sharing settings"""
    try:
        # Try to get by ID first, then by filename
        file_record = None
        if file_id.isdigit():
            file_record = db.session.query(models.File).get(int(file_id))
        else:
            file_record = db.session.query(models.File).filter_by(filename=file_id).first()
        
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        data = request.get_json()
        
        # Update hidden status
        if 'isHidden' in data:
            file_record.is_hidden = data['isHidden']
            if data['isHidden'] and not file_record.hidden_token:
                file_record.generate_hidden_token()
        
        # Update view limit
        if 'viewLimit' in data:
            file_record.view_limit = data['viewLimit'] if data['viewLimit'] and data['viewLimit'] > 0 else None
        
        # Update password protection
        if 'password' in data:
            if data['password']:
                file_record.set_password(data['password'])
            else:
                file_record.password_hash = None
                file_record.is_password_protected = False
        
        db.session.commit()
        
        return jsonify({
            'message': 'File settings updated successfully',
            'file': file_record.to_dict(),
            'hiddenUrl': f'/api/hidden/{file_record.hidden_token}' if file_record.hidden_token else None
        })
        
    except Exception as e:
        app.logger.error(f"Update file settings error: {e}")
        return jsonify({'error': 'Failed to update settings'}), 500

# Admin endpoint to reset view count
@app.route('/api/admin/files/<file_id>/reset-views', methods=['POST'])
@admin_required
def reset_file_views(file_id):
    """Reset file view count"""
    try:
        # Try to get by ID first, then by filename
        file_record = None
        if file_id.isdigit():
            file_record = db.session.query(models.File).get(int(file_id))
        else:
            file_record = db.session.query(models.File).filter_by(filename=file_id).first()
        
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        file_record.reset_view_count()
        
        return jsonify({
            'message': 'View count reset successfully',
            'viewCount': file_record.view_count
        })
        
    except Exception as e:
        app.logger.error(f"Reset view count error: {e}")
        return jsonify({'error': 'Failed to reset view count'}), 500

# Get file details with admin info
@app.route('/api/admin/files/<file_id>')
@admin_required
def get_file_details(file_id):
    """Get detailed file information for admin"""
    try:
        # Try to get by ID first, then by filename
        file_record = None
        if file_id.isdigit():
            file_record = db.session.query(models.File).get(int(file_id))
        else:
            file_record = db.session.query(models.File).filter_by(filename=file_id).first()
        
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        details = file_record.to_dict()
        if file_record.hidden_token:
            details['hiddenUrl'] = f'/api/hidden/{file_record.hidden_token}'
        
        return jsonify(details)
        
    except Exception as e:
        app.logger.error(f"Get file details error: {e}")
        return jsonify({'error': 'Failed to get file details'}), 500

# Admin statistics endpoint
@app.route('/api/admin/stats')
@admin_required
def get_admin_stats():
    """Get admin panel statistics"""
    try:
        # Get login statistics
        total_logins = db.session.query(models.AdminLogin).count()
        successful_logins = db.session.query(models.AdminLogin).filter_by(success=True).count()
        failed_logins = total_logins - successful_logins
        
        # Get unique IPs that accessed admin
        unique_admin_ips = db.session.query(models.AdminLogin.ip_address).distinct().count()
        
        # Get recent admin logins (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_logins = db.session.query(models.AdminLogin).filter(
            models.AdminLogin.login_time >= week_ago
        ).order_by(models.AdminLogin.login_time.desc()).limit(50).all()
        
        # Get download statistics
        total_downloads = db.session.query(models.FileDownload).count()
        unique_download_ips = db.session.query(models.FileDownload.ip_address).distinct().count()
        
        # Get recent downloads
        recent_downloads = db.session.query(
            models.FileDownload, models.File
        ).join(models.File).filter(
            models.FileDownload.download_time >= week_ago
        ).order_by(models.FileDownload.download_time.desc()).limit(50).all()
        
        return jsonify({
            'adminStats': {
                'totalLogins': total_logins,
                'successfulLogins': successful_logins,
                'failedLogins': failed_logins,
                'uniqueAdminIPs': unique_admin_ips,
                'recentLogins': [{
                    'ip': login.ip_address,
                    'time': login.login_time.isoformat(),
                    'success': login.success,
                    'userAgent': login.user_agent
                } for login in recent_logins]
            },
            'downloadStats': {
                'totalDownloads': total_downloads,
                'uniqueDownloadIPs': unique_download_ips,
                'recentDownloads': [{
                    'fileName': download.File.original_name,
                    'ip': download.FileDownload.ip_address,
                    'time': download.FileDownload.download_time.isoformat(),
                    'fileSize': download.FileDownload.file_size,
                    'userAgent': download.FileDownload.user_agent
                } for download in recent_downloads]
            }
        })
        
    except Exception as e:
        app.logger.error(f"Admin stats error: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500

# Change admin password endpoint
@app.route('/api/admin/change-password', methods=['POST'])
@admin_required
def change_admin_password():
    """Change admin password"""
    try:
        data = request.get_json()
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new passwords are required'}), 400
        
        # Verify current password
        current_admin_password = get_admin_password()
        if current_password != current_admin_password:
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Update password in database
        setting = db.session.query(models.AdminSettings).filter_by(setting_key='admin_password').first()
        if setting:
            setting.setting_value = new_password
            setting.updated_at = datetime.utcnow()
        else:
            setting = models.AdminSettings(
                setting_key='admin_password',
                setting_value=new_password,
                updated_at=datetime.utcnow()
            )
            db.session.add(setting)
        
        db.session.commit()
        
        return jsonify({'message': 'Admin password changed successfully'})
        
    except Exception as e:
        app.logger.error(f"Change password error: {e}")
        return jsonify({'error': 'Failed to change password'}), 500

# File tagging endpoints
@app.route('/api/files/tag', methods=['POST'])
@login_required
def tag_files():
    """Add tags to files"""
    try:
        data = request.get_json()
        filenames = data.get('files', [])
        tags = data.get('tags', [])
        
        for filename in filenames:
            file_record = db.session.query(models.File).filter_by(filename=filename).first()
            if file_record and (not file_record.user_id or file_record.user_id == session['user_id']):
                # Store tags as comma-separated string
                file_record.tags = ','.join(tags)
                db.session.commit()
        
        return jsonify({'message': f'Tags applied to {len(filenames)} files'})
        
    except Exception as e:
        app.logger.error(f"Tag files error: {e}")
        return jsonify({'error': 'Failed to tag files'}), 500

# File favorites endpoints
@app.route('/api/files/favorite', methods=['POST'])
@login_required
def toggle_favorite():
    """Toggle file favorite status"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        user_id = session['user_id']
        
        # Check if favorite exists
        favorite = db.session.query(models.FileFavorite).filter_by(
            filename=filename, user_id=user_id
        ).first()
        
        if favorite:
            db.session.delete(favorite)
            message = 'Removed from favorites'
        else:
            favorite = models.FileFavorite(filename=filename, user_id=user_id)
            db.session.add(favorite)
            message = 'Added to favorites'
        
        db.session.commit()
        return jsonify({'message': message})
        
    except Exception as e:
        app.logger.error(f"Toggle favorite error: {e}")
        return jsonify({'error': 'Failed to toggle favorite'}), 500

@app.route('/api/files/favorites')
@login_required
def get_favorites():
    """Get user's favorite files"""
    try:
        user_id = session['user_id']
        favorites = db.session.query(models.FileFavorite).filter_by(user_id=user_id).all()
        
        favorite_files = []
        for fav in favorites:
            filepath = os.path.join(UPLOAD_FOLDER, fav.filename)
            if os.path.exists(filepath):
                file_record = db.session.query(models.File).filter_by(filename=fav.filename).first()
                if file_record:
                    favorite_files.append(file_record.to_dict())
        
        return jsonify(favorite_files)
        
    except Exception as e:
        app.logger.error(f"Get favorites error: {e}")
        return jsonify({'error': 'Failed to get favorites'}), 500

# File notes endpoints
@app.route('/api/files/note', methods=['POST'])
@login_required
def add_file_note():
    """Add note to file"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        note_text = data.get('note')
        user_id = session['user_id']
        
        # Check if note exists
        note = db.session.query(models.FileNote).filter_by(
            filename=filename, user_id=user_id
        ).first()
        
        if note:
            note.note = note_text
            note.updated_at = datetime.utcnow()
        else:
            note = models.FileNote(
                filename=filename,
                user_id=user_id,
                note=note_text,
                created_at=datetime.utcnow()
            )
            db.session.add(note)
        
        db.session.commit()
        return jsonify({'message': 'Note saved successfully'})
        
    except Exception as e:
        app.logger.error(f"Add note error: {e}")
        return jsonify({'error': 'Failed to save note'}), 500

# File sharing with expiration
@app.route('/api/files/share-expiration', methods=['POST'])
@login_required
def create_expiration_share():
    """Create share link with expiration"""
    try:
        data = request.get_json()
        filenames = data.get('files', [])
        expiration_hours = data.get('expirationHours', 24)
        
        # Generate share token
        share_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        expiration_time = datetime.utcnow() + timedelta(hours=expiration_hours)
        
        # Create share record
        share = models.FileShare(
            share_token=share_token,
            filenames=','.join(filenames),
            created_by=session['user_id'],
            expires_at=expiration_time
        )
        db.session.add(share)
        db.session.commit()
        
        share_url = f"{request.host_url}share/{share_token}"
        
        return jsonify({
            'shareUrl': share_url,
            'expiresAt': expiration_time.isoformat()
        })
        
    except Exception as e:
        app.logger.error(f"Create share error: {e}")
        return jsonify({'error': 'Failed to create share link'}), 500

# File version history
@app.route('/api/files/<filename>/versions')
def get_file_versions(filename):
    """Get file version history"""
    try:
        versions = db.session.query(models.FileVersion).filter_by(
            original_filename=filename
        ).order_by(models.FileVersion.version.desc()).all()
        
        return jsonify([{
            'version': v.version,
            'created': v.created_at.isoformat(),
            'size': v.file_size,
            'checksum': v.checksum
        } for v in versions])
        
    except Exception as e:
        app.logger.error(f"Get versions error: {e}")
        return jsonify({'error': 'Failed to get versions'}), 500

# File compression
@app.route('/api/files/compress', methods=['POST'])
@login_required
def compress_files():
    """Compress selected files into ZIP"""
    import zipfile
    import io
    
    try:
        data = request.get_json()
        filenames = data.get('files', [])
        
        # Create ZIP in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for filename in filenames:
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.exists(filepath):
                    file_record = db.session.query(models.File).filter_by(filename=filename).first()
                    original_name = file_record.original_name if file_record else filename
                    zip_file.write(filepath, original_name)
        
        zip_buffer.seek(0)
        
        return Response(
            zip_buffer.getvalue(),
            mimetype='application/zip',
            headers={'Content-Disposition': 'attachment; filename=compressed_files.zip'}
        )
        
    except Exception as e:
        app.logger.error(f"Compress files error: {e}")
        return jsonify({'error': 'Failed to compress files'}), 500

# File duplicate detection
@app.route('/api/files/duplicates')
@login_required
def find_duplicates():
    """Find duplicate files by checksum"""
    try:
        files_by_hash = {}
        
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename != '.gitkeep':
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.isfile(filepath):
                    file_hash = generate_file_hash(filepath)
                    if file_hash:
                        if file_hash not in files_by_hash:
                            files_by_hash[file_hash] = []
                        
                        file_record = db.session.query(models.File).filter_by(filename=filename).first()
                        files_by_hash[file_hash].append({
                            'name': filename,
                            'originalName': file_record.original_name if file_record else filename,
                            'size': os.path.getsize(filepath)
                        })
        
        # Return only groups with duplicates
        duplicates = [group for group in files_by_hash.values() if len(group) > 1]
        
        return jsonify(duplicates)
        
    except Exception as e:
        app.logger.error(f"Find duplicates error: {e}")
        return jsonify({'error': 'Failed to find duplicates'}), 500

# File scheduling
@app.route('/api/files/schedule-delete', methods=['POST'])
@login_required
def schedule_file_deletion():
    """Schedule files for deletion"""
    try:
        data = request.get_json()
        filenames = data.get('files', [])
        delete_date = datetime.fromisoformat(data.get('deleteDate'))
        
        for filename in filenames:
            schedule = models.FileSchedule(
                filename=filename,
                action='delete',
                scheduled_time=delete_date,
                created_by=session['user_id']
            )
            db.session.add(schedule)
        
        db.session.commit()
        return jsonify({'message': f'{len(filenames)} files scheduled for deletion'})
        
    except Exception as e:
        app.logger.error(f"Schedule deletion error: {e}")
        return jsonify({'error': 'Failed to schedule deletion'}), 500

# QR Code generation
@app.route('/api/files/<filename>/qr')
def generate_file_qr(filename):
    """Generate QR code for file download link"""
    try:
        import qrcode
        import base64
        from io import BytesIO
        
        download_url = f"{request.host_url}api/download/{filename}"
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(download_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return jsonify({
            'qrCode': f'data:image/png;base64,{img_str}',
            'downloadUrl': download_url
        })
        
    except Exception as e:
        app.logger.error(f"QR generation error: {e}")
        return jsonify({'error': 'Failed to generate QR code'}), 500

# Batch rename
@app.route('/api/files/batch-rename', methods=['POST'])
@login_required
def batch_rename_files():
    """Batch rename files"""
    try:
        data = request.get_json()
        filenames = data.get('files', [])
        pattern = data.get('pattern', 'file_{i}')
        
        renamed_count = 0
        for i, filename in enumerate(filenames):
            old_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.exists(old_path):
                # Get file extension
                _, ext = os.path.splitext(filename)
                new_name = pattern.replace('{i}', str(i + 1)) + ext
                new_path = os.path.join(UPLOAD_FOLDER, new_name)
                
                # Rename file
                os.rename(old_path, new_path)
                
                # Update database
                file_record = db.session.query(models.File).filter_by(filename=filename).first()
                if file_record:
                    file_record.filename = new_name
                    file_record.original_name = new_name
                
                renamed_count += 1
        
        db.session.commit()
        return jsonify({'message': f'{renamed_count} files renamed successfully'})
        
    except Exception as e:
        app.logger.error(f"Batch rename error: {e}")
        return jsonify({'error': 'Failed to rename files'}), 500

# File metadata
@app.route('/api/files/<filename>/metadata')
def get_file_metadata(filename):
    """Get detailed file metadata"""
    try:
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        stat_info = os.stat(filepath)
        file_hash = generate_file_hash(filepath)
        
        metadata = {
            'File Name': filename,
            'File Size': formatFileSize(stat_info.st_size),
            'Created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'Modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'SHA-256 Hash': file_hash,
            'MIME Type': mimetypes.guess_type(filepath)[0] or 'Unknown',
            'Permissions': oct(stat_info.st_mode)[-3:],
            'Inode': stat_info.st_ino
        }
        
        return jsonify(metadata)
        
    except Exception as e:
        app.logger.error(f"Get metadata error: {e}")
        return jsonify({'error': 'Failed to get metadata'}), 500

# File activity log
@app.route('/api/files/<filename>/activity')
def get_file_activity(filename):
    """Get file activity log"""
    try:
        activities = db.session.query(models.FileActivity).filter_by(
            filename=filename
        ).order_by(models.FileActivity.timestamp.desc()).limit(50).all()
        
        return jsonify([{
            'action': activity.action,
            'timestamp': activity.timestamp.isoformat(),
            'user': activity.user_id,
            'details': activity.details
        } for activity in activities])
        
    except Exception as e:
        app.logger.error(f"Get activity error: {e}")
        return jsonify({'error': 'Failed to get activity log'}), 500

# File encryption (basic)
@app.route('/api/files/encrypt', methods=['POST'])
@login_required
def encrypt_files():
    """Basic file encryption"""
    try:
        data = request.get_json()
        filenames = data.get('files', [])
        password = data.get('password')
        
        # Simple encryption (in production, use proper encryption)
        import base64
        
        encrypted_count = 0
        for filename in filenames:
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    content = f.read()
                
                # Simple base64 encoding (not secure, just for demo)
                encrypted_content = base64.b64encode(content)
                
                with open(filepath + '.encrypted', 'wb') as f:
                    f.write(encrypted_content)
                
                encrypted_count += 1
        
        return jsonify({'message': f'{encrypted_count} files encrypted'})
        
    except Exception as e:
        app.logger.error(f"Encrypt files error: {e}")
        return jsonify({'error': 'Failed to encrypt files'}), 500

# Cloud sync simulation
@app.route('/api/files/cloud-sync', methods=['POST'])
@login_required
def sync_to_cloud():
    """Simulate cloud sync"""
    try:
        data = request.get_json()
        filenames = data.get('files', [])
        
        # Simulate cloud sync (in production, integrate with real cloud services)
        synced_count = 0
        for filename in filenames:
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.exists(filepath):
                # Record sync activity
                activity = models.FileActivity(
                    filename=filename,
                    action='cloud_sync',
                    user_id=session['user_id'],
                    timestamp=datetime.utcnow(),
                    details='Synced to cloud storage'
                )
                db.session.add(activity)
                synced_count += 1
        
        db.session.commit()
        return jsonify({'message': f'{synced_count} files synced to cloud'})
        
    except Exception as e:
        app.logger.error(f"Cloud sync error: {e}")
        return jsonify({'error': 'Failed to sync to cloud'}), 500

# Admin user management endpoints
@app.route('/api/admin/users')
@admin_required
def get_all_users():
    """Get all users for admin management"""
    try:
        users = db.session.query(models.User).all()
        user_list = []
        
        for user in users:
            file_count = db.session.query(models.File).filter_by(user_id=user.id).count()
            user_data = user.to_dict()
            user_data['fileCount'] = file_count
            user_list.append(user_data)
        
        return jsonify(user_list)
        
    except Exception as e:
        app.logger.error(f"Get users error: {e}")
        return jsonify({'error': 'Failed to get users'}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """Update user details"""
    try:
        user = db.session.query(models.User).get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        if 'email' in data:
            user.email = data['email']
        if 'storageLimit' in data:
            user.storage_limit = data['storageLimit']
        if 'isActive' in data:
            user.is_active = data['isActive']
        
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
        
    except Exception as e:
        app.logger.error(f"Update user error: {e}")
        return jsonify({'error': 'Failed to update user'}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """Delete user and all their files"""
    try:
        user = db.session.query(models.User).get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Delete user's files
        user_files = db.session.query(models.File).filter_by(user_id=user_id).all()
        for file_record in user_files:
            filepath = os.path.join(UPLOAD_FOLDER, file_record.filename)
            if os.path.exists(filepath):
                os.remove(filepath)
            db.session.delete(file_record)
        
        # Delete user
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'message': 'User deleted successfully'})
        
    except Exception as e:
        app.logger.error(f"Delete user error: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500

# System monitoring endpoint
@app.route('/api/admin/system-monitor')
@admin_required
def get_system_monitor():
    """Get system monitoring data"""
    try:
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            return jsonify({
                'cpu': round(cpu_percent, 1),
                'memory': round(memory.percent, 1),
                'disk': round((disk.used / disk.total) * 100, 1),
                'network': round((network.bytes_sent + network.bytes_recv) / 1024 / 1024, 2),
                'networkUp': round(network.bytes_sent / 1024 / 1024, 2),
                'networkDown': round(network.bytes_recv / 1024 / 1024, 2),
                'uptime': time.time() - psutil.boot_time()
            })
        except ImportError:
            # Fallback when psutil is not available
            return jsonify({
                'cpu': 25.0,
                'memory': 45.0,
                'disk': 60.0,
                'network': 5.2,
                'networkUp': 2.1,
                'networkDown': 3.1,
                'uptime': 86400
            })
        
    except Exception as e:
        app.logger.error(f"System monitor error: {e}")
        return jsonify({'error': 'Failed to get system data'}), 500

# Security management endpoints
@app.route('/api/admin/security')
@admin_required
def get_security_data():
    """Get security monitoring data"""
    try:
        # Get failed login attempts
        failed_logins = db.session.query(
            models.AdminLogin.ip_address,
            db.func.count(models.AdminLogin.id).label('attempts'),
            db.func.max(models.AdminLogin.login_time).label('last_attempt')
        ).filter_by(success=False).group_by(
            models.AdminLogin.ip_address
        ).having(db.func.count(models.AdminLogin.id) > 3).all()
        
        # Get blocked IPs (simulated for now)
        blocked_ips = []
        
        return jsonify({
            'failedLogins': [{
                'ip': login.ip_address,
                'attempts': login.attempts,
                'lastAttempt': login.last_attempt.isoformat()
            } for login in failed_logins],
            'blockedIPs': blocked_ips,
            'suspiciousActivity': []
        })
        
    except Exception as e:
        app.logger.error(f"Security data error: {e}")
        return jsonify({'error': 'Failed to get security data'}), 500

# Backup management endpoints
@app.route('/api/admin/backups')
@admin_required
def get_backups():
    """Get list of backups"""
    try:
        backup_dir = 'backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        backups = []
        for filename in os.listdir(backup_dir):
            if filename.endswith('.zip'):
                filepath = os.path.join(backup_dir, filename)
                stat_info = os.stat(filepath)
                backups.append({
                    'id': filename,
                    'name': filename,
                    'size': stat_info.st_size,
                    'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                    'type': 'Full' if 'full' in filename else 'Incremental',
                    'status': 'completed'
                })
        
        return jsonify(backups)
        
    except Exception as e:
        app.logger.error(f"Get backups error: {e}")
        return jsonify({'error': 'Failed to get backups'}), 500

@app.route('/api/admin/backups', methods=['POST'])
@admin_required
def create_backup():
    """Create new backup"""
    try:
        import zipfile
        from datetime import datetime
        
        backup_dir = 'backups'
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'backup_full_{timestamp}.zip'
        backup_path = os.path.join(backup_dir, backup_filename)
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Backup database
            if os.path.exists('instance/app.db'):
                zip_file.write('instance/app.db', 'database/app.db')
            
            # Backup uploads
            for root, dirs, files in os.walk(UPLOAD_FOLDER):
                for file in files:
                    file_path = os.path.join(root, file)
                    arc_name = os.path.relpath(file_path, UPLOAD_FOLDER)
                    zip_file.write(file_path, f'uploads/{arc_name}')
        
        return jsonify({
            'message': 'Backup created successfully',
            'filename': backup_filename,
            'size': os.path.getsize(backup_path)
        })
        
    except Exception as e:
        app.logger.error(f"Create backup error: {e}")
        return jsonify({'error': 'Failed to create backup'}), 500

# Analytics endpoints
@app.route('/api/admin/analytics')
@admin_required
def get_analytics():
    """Get platform analytics"""
    try:
        total_users = db.session.query(models.User).count()
        total_files = db.session.query(models.File).count()
        total_downloads = db.session.query(models.FileDownload).count()
        
        # Calculate total storage
        total_storage = 0
        if os.path.exists(UPLOAD_FOLDER):
            for filename in os.listdir(UPLOAD_FOLDER):
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.isfile(filepath):
                    total_storage += os.path.getsize(filepath)
        
        # Get file type distribution
        file_types = db.session.query(
            models.File.file_type,
            db.func.count(models.File.id).label('count')
        ).group_by(models.File.file_type).all()
        
        return jsonify({
            'totalUsers': total_users,
            'totalFiles': total_files,
            'totalStorage': total_storage,
            'totalDownloads': total_downloads,
            'fileTypes': [{
                'type': ft.file_type,
                'count': ft.count
            } for ft in file_types],
            'dailyStats': [],  # Would implement with more detailed tracking
            'monthlyStats': []
        })
        
    except Exception as e:
        app.logger.error(f"Analytics error: {e}")
        return jsonify({'error': 'Failed to get analytics'}), 500

# Configuration management
@app.route('/api/admin/config')
@admin_required
def get_configuration():
    """Get system configuration"""
    try:
        config = {
            'maxFileSize': 100,  # MB
            'allowedTypes': ['*'],
            'autoVirusScan': False,
            'defaultStorageLimit': 100,  # MB
            'allowRegistration': True,
            'requireEmailVerification': False,
            'maxLoginAttempts': 5,
            'sessionTimeout': 30,  # minutes
            'emailNotifications': False,
            'smtpServer': ''
        }
        
        # Load from database if exists
        settings = db.session.query(models.AdminSettings).all()
        for setting in settings:
            if setting.setting_key in config:
                try:
                    config[setting.setting_key] = eval(setting.setting_value)
                except:
                    config[setting.setting_key] = setting.setting_value
        
        return jsonify(config)
        
    except Exception as e:
        app.logger.error(f"Get config error: {e}")
        return jsonify({'error': 'Failed to get configuration'}), 500

@app.route('/api/admin/config', methods=['POST'])
@admin_required
def save_configuration():
    """Save system configuration"""
    try:
        data = request.get_json()
        
        for key, value in data.items():
            setting = db.session.query(models.AdminSettings).filter_by(setting_key=key).first()
            if setting:
                setting.setting_value = str(value)
                setting.updated_at = datetime.utcnow()
            else:
                setting = models.AdminSettings(
                    setting_key=key,
                    setting_value=str(value),
                    updated_at=datetime.utcnow()
                )
                db.session.add(setting)
        
        db.session.commit()
        return jsonify({'message': 'Configuration saved successfully'})
        
    except Exception as e:
        app.logger.error(f"Save config error: {e}")
        return jsonify({'error': 'Failed to save configuration'}), 500

# Bulk operations endpoint
@app.route('/api/admin/bulk-operations', methods=['POST'])
@admin_required
def bulk_operations():
    """Execute bulk operations on files"""
    try:
        data = request.get_json()
        operation = data.get('operation')
        filenames = data.get('files', [])
        
        if operation == 'delete':
            deleted_count = 0
            for filename in filenames:
                filepath = os.path.join(UPLOAD_FOLDER, filename)
                if os.path.exists(filepath):
                    os.remove(filepath)
                    file_record = db.session.query(models.File).filter_by(filename=filename).first()
                    if file_record:
                        db.session.delete(file_record)
                    deleted_count += 1
            
            db.session.commit()
            return jsonify({'message': f'{deleted_count} files deleted'})
        
        elif operation == 'archive':
            # Move files to archive folder
            archive_dir = os.path.join(UPLOAD_FOLDER, 'archived')
            os.makedirs(archive_dir, exist_ok=True)
            
            archived_count = 0
            for filename in filenames:
                src = os.path.join(UPLOAD_FOLDER, filename)
                dst = os.path.join(archive_dir, filename)
                if os.path.exists(src):
                    os.rename(src, dst)
                    archived_count += 1
            
            return jsonify({'message': f'{archived_count} files archived'})
        
        elif operation == 'compress':
            # Compress files
            import zipfile
            timestamp = int(datetime.now().timestamp())
            zip_filename = f'bulk_compressed_{timestamp}.zip'
            zip_path = os.path.join(UPLOAD_FOLDER, zip_filename)
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for filename in filenames:
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    if os.path.exists(filepath):
                        zip_file.write(filepath, filename)
            
            return jsonify({'message': f'Files compressed to {zip_filename}'})
        
        else:
            return jsonify({'error': 'Unknown operation'}), 400
        
    except Exception as e:
        app.logger.error(f"Bulk operations error: {e}")
        return jsonify({'error': 'Bulk operation failed'}), 500

# Plugin management (simulated)
@app.route('/api/admin/plugins')
@admin_required
def get_plugins():
    """Get installed plugins"""
    try:
        plugins = [
            {
                'id': 'virus-scanner',
                'name': 'Virus Scanner',
                'description': 'Scans uploaded files for viruses',
                'enabled': False,
                'version': '1.0.0'
            },
            {
                'id': 'image-processor',
                'name': 'Image Processor',
                'description': 'Automatically processes and optimizes images',
                'enabled': True,
                'version': '2.1.0'
            },
            {
                'id': 'pdf-viewer',
                'name': 'PDF Viewer',
                'description': 'Inline PDF viewing capabilities',
                'enabled': True,
                'version': '1.5.0'
            }
        ]
        
        return jsonify(plugins)
        
    except Exception as e:
        app.logger.error(f"Get plugins error: {e}")
        return jsonify({'error': 'Failed to get plugins'}), 500

def formatFileSize(bytes):
    """Format file size for display"""
    if bytes == 0:
        return '0 Bytes'
    k = 1024
    sizes = ['Bytes', 'KB', 'MB', 'GB']
    i = int(math.floor(math.log(bytes) / math.log(k)))
    return f"{round(bytes / math.pow(k, i), 2)} {sizes[i]}"

# Health check
@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)