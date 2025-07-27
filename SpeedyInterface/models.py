from app import db
from datetime import datetime
import secrets
import string
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    storage_used = db.Column(db.Integer, default=0)  # bytes
    storage_limit = db.Column(db.Integer, default=100*1024*1024)  # 100MB default
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    files = db.relationship('File', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_remaining_storage(self):
        return max(0, self.storage_limit - self.storage_used)
    
    def can_upload(self, file_size):
        return self.storage_used + file_size <= self.storage_limit
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'storageUsed': self.storage_used,
            'storageLimit': self.storage_limit,
            'remainingStorage': self.get_remaining_storage(),
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'isActive': self.is_active
        }


class AdminLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(500), nullable=True)
    success = db.Column(db.Boolean, default=True)


class FileDownload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    download_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(500), nullable=True)
    file_size = db.Column(db.Integer, nullable=False)


class AdminSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class FileFavorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique favorite per user per file
    __table_args__ = (db.UniqueConstraint('filename', 'user_id'),)


class FileNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    share_token = db.Column(db.String(64), unique=True, nullable=False)
    filenames = db.Column(db.Text, nullable=False)  # Comma-separated filenames
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    access_count = db.Column(db.Integer, default=0)
    max_access = db.Column(db.Integer, nullable=True)


class FileVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    version = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(255), nullable=False)  # Versioned filename
    file_size = db.Column(db.Integer, nullable=False)
    checksum = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)


class FileSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # delete, archive, etc.
    scheduled_time = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    executed = db.Column(db.Boolean, default=False)
    executed_at = db.Column(db.DateTime, nullable=True)


class FileActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    details = db.Column(db.Text, nullable=True)


class FileComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    parent_id = db.Column(db.Integer, db.ForeignKey('file_comment.id'), nullable=True)  # For replies
    
    # Relationship for replies
    replies = db.relationship('FileComment', backref=db.backref('parent', remote_side=[id]))


class FileCollection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_public = db.Column(db.Boolean, default=False)


class FileCollectionItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    collection_id = db.Column(db.Integer, db.ForeignKey('file_collection.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    collection = db.relationship('FileCollection', backref='items')


class FileRating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    review = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique rating per user per file
    __table_args__ = (db.UniqueConstraint('filename', 'user_id'),)


class FileStatistics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    total_downloads = db.Column(db.Integer, default=0)
    total_views = db.Column(db.Integer, default=0)
    unique_downloaders = db.Column(db.Integer, default=0)
    last_accessed = db.Column(db.DateTime, nullable=True)
    bandwidth_used = db.Column(db.BigInteger, default=0)  # Total bytes downloaded
    peak_downloads_day = db.Column(db.Date, nullable=True)
    peak_downloads_count = db.Column(db.Integer, default=0)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    download_count = db.Column(db.Integer, default=0)
    
    # User relationship
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # New fields for advanced features
    is_hidden = db.Column(db.Boolean, default=False)
    hidden_token = db.Column(db.String(64), unique=True, nullable=True)
    view_limit = db.Column(db.Integer, nullable=True)  # None = unlimited
    view_count = db.Column(db.Integer, default=0)
    password_hash = db.Column(db.String(128), nullable=True)
    is_password_protected = db.Column(db.Boolean, default=False)
    tags = db.Column(db.Text, nullable=True)  # Comma-separated tags
    
    def generate_hidden_token(self):
        """Generate a unique token for hidden file access"""
        if not self.hidden_token:
            self.hidden_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        return self.hidden_token
    
    def set_password(self, password):
        """Set password for file protection"""
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)
        self.is_password_protected = True
    
    def check_password(self, password):
        """Check if provided password is correct"""
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)
    
    def increment_view_count(self):
        """Increment view count and check if file should be deleted"""
        self.view_count += 1
        db.session.commit()
        
        # Check if file should be auto-deleted
        if self.view_limit and self.view_count >= self.view_limit:
            return True  # Signal for deletion
        return False
    
    def reset_view_count(self):
        """Reset view count to 0"""
        self.view_count = 0
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.filename,
            'originalName': self.original_name,
            'size': self.file_size,
            'type': self.file_type,
            'created': self.upload_date.isoformat() if self.upload_date else None,
            'downloads': self.download_count,
            'isHidden': self.is_hidden,
            'hiddenToken': self.hidden_token,
            'viewLimit': self.view_limit,
            'viewCount': self.view_count,
            'isPasswordProtected': self.is_password_protected
        }