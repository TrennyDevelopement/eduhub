  const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS for all routes
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-user-email', 'x-user-password', 'x-user-id', 'x-user-role', 'x-token']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://trenny:trennydev@trennydev.hieeqv2.mongodb.net/eduhub_school?retryWrites=true&w=majority';
const client = new MongoClient(MONGODB_URI);
let db;

// Global System Configuration
let systemConfig = {
    // Security Features (Admin can toggle these)
    security: {
        passwordHashing: false, // Default: No hashing
        jwtEnabled: false, // Default: No JWT
        sessionTimeout: 24, // Hours
        maxLoginAttempts: 5,
        enable2FA: false,
        requireStrongPassword: false
    },
    
    // Backup Settings
    backup: {
        enabled: true,
        interval: 6, // hours
        maxBackups: 3,
        autoBackup: true
    },
    
    // Feature Toggles (Admin can enable/disable)
    features: {
        attendance: true,
        exams: true,
        results: true,
        assignments: true,
        library: true,
        fees: true,
        transport: true,
        hostel: true,
        medical: true,
        announcements: true,
        resources: true,
        gallery: true,
        events: true,
        quizzes: true,
        studyTools: true,
        classTests: true,
        analytics: true,
        notifications: true
    },
    
    // System Settings
    system: {
        schoolName: "EduHub International School",
        schoolCode: "EHIS001",
        academicYear: "2024-2025",
        currency: "₹",
        timezone: "Asia/Kolkata",
        dateFormat: "DD/MM/YYYY",
        maxFileSize: 10, // MB
        allowedFileTypes: ['pdf', 'doc', 'docx', 'jpg', 'png', 'mp4', 'mp3']
    }
};

// JWT Secret (for when JWT is enabled)
const JWT_SECRET = process.env.JWT_SECRET || 'eduhub-school-management-secret-key-2024';

// Connect to MongoDB
const connectToMongoDB = async () => {
    try {
        console.log('🔄 Connecting to MongoDB...');
        await client.connect();
        db = client.db('eduhub_school');
        console.log('✅ MongoDB connected successfully');
        
        await initializeCollections();
        await loadSystemConfig();
        await initializeDefaultData();
        startBackupScheduler();
        startCleanupScheduler();
        
        console.log('🚀 System initialized successfully');
        console.log('📊 Security Features:');
        console.log(`   • Password Hashing: ${systemConfig.security.passwordHashing ? '✅ Enabled' : '❌ Disabled'}`);
        console.log(`   • JWT Authentication: ${systemConfig.security.jwtEnabled ? '✅ Enabled' : '❌ Disabled'}`);
        
    } catch (error) {
        console.error('❌ MongoDB connection failed:', error.message);
        setTimeout(connectToMongoDB, 5000);
    }
};

// Initialize collections
const initializeCollections = async () => {
    const collections = [
        // Core collections
        'users', 'students', 'teachers', 'parents', 'admins', 'examiners', 'principals', 'librarians',
        'classes', 'sections', 'subjects', 'departments',
        
        // Academic collections
        'courses', 'chapters', 'topics',
        'attendance', 'attendance_records',
        'exams', 'exam_schedules', 'exam_results',
        'assignments', 'submissions',
        'class_tests', 'test_results',
        
        // Resource collections
        'resources', 'resource_categories',
        'videos', 'video_categories',
        'notes', 'note_categories',
        'question_papers', 'syllabus',
        
        // Library collections
        'library_books', 'book_categories',
        'book_issues', 'book_returns',
        
        // Financial collections
        'fee_structures', 'fee_payments', 'fee_receipts',
        'fee_categories', 'discounts',
        
        // Communication collections
        'announcements', 'notifications', 'messages',
        'circulars', 'notices',
        
        // Event collections
        'events', 'calendars', 'holidays', 'important_dates',
        
        // System collections
        'system_config', 'system_logs', 'audit_logs',
        'backups', 'backup_history',
        
        // Role & Permission collections
        'roles', 'permissions', 'role_assignments',
        'user_roles', 'role_permissions',
        
        // Analytics collections
        'analytics_data', 'graphs_data', 'statistics',
        'performance_metrics', 'attendance_reports',
        
        // Gallery collections
        'galleries', 'photos', 'albums', 'videos_gallery',
        
        // Transportation collections
        'transport_routes', 'transport_vehicles', 'transport_assignments',
        
        // Hostel collections
        'hostels', 'hostel_rooms', 'hostel_allocations',
        
        // Medical collections
        'medical_records', 'vaccinations', 'medical_appointments',
        
        // Achievement collections
        'achievements', 'certificates', 'awards',
        
        // Feedback collections
        'feedbacks', 'surveys', 'poll_responses',
        
        // Study tools
        'flashcards', 'flashcard_sets',
        'quizzes', 'quiz_questions', 'quiz_attempts',
        'study_plans', 'study_sessions', 'study_groups',
        
        // Timetable collections
        'timetables', 'periods', 'timetable_slots',
        
        // Other
        'suspended_users', 'login_attempts', 'password_resets'
    ];
    
    for (const collectionName of collections) {
        try {
            await db.createCollection(collectionName);
        } catch (error) {
            // Collection already exists
        }
    }
    
    // Create indexes
    await createIndexes();
    console.log('✅ Database initialized');
};

// Create indexes
const createIndexes = async () => {
    // Core indexes
    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    await db.collection('users').createIndex({ role: 1 });
    await db.collection('users').createIndex({ status: 1 });
    
    await db.collection('students').createIndex({ admissionNo: 1 }, { unique: true });
    await db.collection('students').createIndex({ class: 1, section: 1, rollNo: 1 });
    
    await db.collection('teachers').createIndex({ teacherId: 1 }, { unique: true });
    
    // Exam indexes
    await db.collection('exams').createIndex({ examCode: 1 }, { unique: true });
    await db.collection('exams').createIndex({ class: 1, date: 1 });
    
    await db.collection('exam_results').createIndex({ 
        studentId: 1, 
        examId: 1, 
        subject: 1 
    }, { unique: true });
    
    // Library indexes
    await db.collection('library_books').createIndex({ isbn: 1 }, { unique: true });
    await db.collection('book_issues').createIndex({ studentId: 1, returned: 1 });
    
    // Fee indexes
    await db.collection('fee_structures').createIndex({ feeCode: 1 }, { unique: true });
    
    // Audit log indexes
    await db.collection('audit_logs').createIndex({ timestamp: -1 });
    await db.collection('audit_logs').createIndex({ userId: 1 });
    
    // Resource indexes
    await db.collection('resources').createIndex({ type: 1, subject: 1 });
};

// Load system configuration from database
const loadSystemConfig = async () => {
    try {
        const config = await db.collection('system_config').findOne({});
        if (config) {
            systemConfig = { ...systemConfig, ...config };
            console.log('📋 System configuration loaded');
        } else {
            // Save default config
            await db.collection('system_config').insertOne(systemConfig);
            console.log('📋 Default system configuration saved');
        }
    } catch (error) {
        console.error('Error loading system config:', error);
    }
};

// ==================== DATE/TIME UTILITIES (Replacing moment) ====================

const formatDate = (date = new Date()) => {
    const d = new Date(date);
    const day = d.getDate().toString().padStart(2, '0');
    const month = (d.getMonth() + 1).toString().padStart(2, '0');
    const year = d.getFullYear();
    return `${day}/${month}/${year}`;
};

const formatDateTime = (date = new Date()) => {
    const d = new Date(date);
    const day = d.getDate().toString().padStart(2, '0');
    const month = (d.getMonth() + 1).toString().padStart(2, '0');
    const year = d.getFullYear();
    const hours = d.getHours().toString().padStart(2, '0');
    const minutes = d.getMinutes().toString().padStart(2, '0');
    const seconds = d.getSeconds().toString().padStart(2, '0');
    return `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;
};

const getStartOfDay = (date = new Date()) => {
    const d = new Date(date);
    d.setHours(0, 0, 0, 0);
    return d;
};

const getEndOfDay = (date = new Date()) => {
    const d = new Date(date);
    d.setHours(23, 59, 59, 999);
    return d;
};

const addHours = (date, hours) => {
    const d = new Date(date);
    d.setHours(d.getHours() + hours);
    return d;
};

const getStartOfMonth = (date = new Date()) => {
    const d = new Date(date);
    d.setDate(1);
    d.setHours(0, 0, 0, 0);
    return d;
};

const formatDateForFileName = (date = new Date()) => {
    const d = new Date(date);
    const year = d.getFullYear();
    const month = (d.getMonth() + 1).toString().padStart(2, '0');
    const day = d.getDate().toString().padStart(2, '0');
    const hours = d.getHours().toString().padStart(2, '0');
    const minutes = d.getMinutes().toString().padStart(2, '0');
    return `${year}-${month}-${day}_${hours}-${minutes}`;
};

const getDayName = (date = new Date()) => {
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return days[date.getDay()];
};

const getMonthName = (date = new Date()) => {
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    return months[date.getMonth()];
};

const formatTime = (date = new Date()) => {
    const d = new Date(date);
    const hours = d.getHours().toString().padStart(2, '0');
    const minutes = d.getMinutes().toString().padStart(2, '0');
    return `${hours}:${minutes}`;
};

const isSameDay = (date1, date2) => {
    const d1 = new Date(date1);
    const d2 = new Date(date2);
    return d1.getDate() === d2.getDate() &&
           d1.getMonth() === d2.getMonth() &&
           d1.getFullYear() === d2.getFullYear();
};

// ==================== SECURITY UTILITIES ====================

// Hash password if hashing is enabled
const hashPassword = async (password) => {
    if (systemConfig.security.passwordHashing) {
        return await bcrypt.hash(password, 10);
    }
    return password; // Return plain text if hashing disabled
};

// Compare password
const comparePassword = async (plainPassword, storedPassword) => {
    if (systemConfig.security.passwordHashing) {
        try {
            return await bcrypt.compare(plainPassword, storedPassword);
        } catch (error) {
            // If stored password is not hashed (shouldn't happen when hashing is enabled)
            return plainPassword === storedPassword;
        }
    }
    return plainPassword === storedPassword; // Direct comparison if no hashing
};

// Generate JWT token
const generateToken = (user) => {
    if (!systemConfig.security.jwtEnabled) {
        return null;
    }
    
    return jwt.sign(
        {
            id: user._id,
            email: user.email,
            role: user.role,
            userId: user.userId || user.admissionNo || user.teacherId
        },
        JWT_SECRET,
        { expiresIn: `${systemConfig.security.sessionTimeout}h` }
    );
};

// Verify JWT token
const verifyToken = (token) => {
    if (!systemConfig.security.jwtEnabled) {
        return { valid: false, error: 'JWT is disabled' };
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return { valid: true, user: decoded };
    } catch (error) {
        return { valid: false, error: error.message };
    }
};

// ==================== SECURITY MIGRATION FUNCTIONS ====================

// Convert all passwords to plain text (when hashing is disabled)
const convertPasswordsToPlainText = async () => {
    try {
        console.log('🔄 Converting all passwords to plain text...');
        
        const users = await db.collection('users').find({}).toArray();
        let updatedCount = 0;
        
        // This is only possible if we have the original passwords stored somewhere
        // Since we don't, we can't convert hashed passwords back to plain text
        // We'll set a default password for all users
        const defaultPassword = 'password123';
        
        for (const user of users) {
            await db.collection('users').updateOne(
                { _id: user._id },
                { $set: { password: defaultPassword } }
            );
            updatedCount++;
        }
        
        console.log(`✅ Converted ${updatedCount} passwords to plain text`);
        console.log(`⚠️  All passwords have been reset to: ${defaultPassword}`);
        console.log('⚠️  Users must update their passwords after login');
        
        return updatedCount;
        
    } catch (error) {
        console.error('Error converting passwords:', error);
        throw error;
    }
};

// Convert all passwords to hashed (when hashing is enabled)
const convertPasswordsToHashed = async () => {
    try {
        console.log('🔄 Converting all passwords to hashed...');
        
        const users = await db.collection('users').find({}).toArray();
        let updatedCount = 0;
        
        for (const user of users) {
            // Check if password is already hashed
            const isAlreadyHashed = user.password.startsWith('$2a$') || user.password.startsWith('$2b$');
            
            if (!isAlreadyHashed) {
                // Hash the plain text password
                const hashedPassword = await bcrypt.hash(user.password, 10);
                
                await db.collection('users').updateOne(
                    { _id: user._id },
                    { $set: { password: hashedPassword } }
                );
                updatedCount++;
            }
        }
        
        console.log(`✅ Hashed ${updatedCount} passwords`);
        return updatedCount;
        
    } catch (error) {
        console.error('Error hashing passwords:', error);
        throw error;
    }
};

// ==================== AUTHENTICATION MIDDLEWARE ====================

const authenticateUser = async (req, res, next) => {
    try {
        // Check for token in headers (if JWT enabled)
        if (systemConfig.security.jwtEnabled) {
            const token = req.headers['x-token'] || req.headers['authorization']?.split(' ')[1];
            
            if (!token) {
                return res.status(401).json({ 
                    error: 'Authentication required',
                    message: 'Token is required when JWT is enabled'
                });
            }
            
            const verification = verifyToken(token);
            if (!verification.valid) {
                return res.status(401).json({ 
                    error: 'Invalid token',
                    message: verification.error 
                });
            }
            
            req.user = verification.user;
            
            // Check if user exists and is active
            const user = await db.collection('users').findOne({ 
                _id: new ObjectId(req.user.id),
                status: 'active'
            });
            
            if (!user) {
                return res.status(401).json({ error: 'User not found or inactive' });
            }
            
            req.userData = user;
            return next();
        }
        
        // If JWT disabled, use email/password in headers
        const email = req.headers['x-user-email'];
        const password = req.headers['x-user-password'];
        
        if (!email || !password) {
            return res.status(401).json({ 
                error: 'Authentication required',
                message: 'Please provide x-user-email and x-user-password headers'
            });
        }
        
        // Find user
        const user = await db.collection('users').findOne({ 
            email: email,
            status: 'active'
        });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Verify password
        const passwordValid = await comparePassword(password, user.password);
        if (!passwordValid) {
            // Log failed attempt
            await logLoginAttempt(email, false);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Log successful attempt
        await logLoginAttempt(email, true);
        
        req.user = {
            id: user._id,
            email: user.email,
            role: user.role,
            name: user.name,
            userId: user.userId || user.admissionNo || user.teacherId
        };
        
        req.userData = user;
        next();
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Check permission middleware
const checkPermission = (requiredRole) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        // Check if user has required role
        if (requiredRole && req.user.role !== requiredRole) {
            return res.status(403).json({ 
                error: 'Access denied',
                message: `Required role: ${requiredRole}, Your role: ${req.user.role}`
            });
        }
        
        next();
    };
};

// Check feature enabled middleware
const checkFeatureEnabled = (featureName) => {
    return (req, res, next) => {
        if (!systemConfig.features[featureName]) {
            return res.status(403).json({ 
                error: 'Feature disabled',
                message: `${featureName} feature is currently disabled by administrator`
            });
        }
        next();
    };
};

// ==================== AUDIT LOGGING ====================

const logAudit = async (action, details, userId, userEmail, ipAddress = '') => {
    try {
        await db.collection('audit_logs').insertOne({
            action,
            details,
            userId,
            userEmail,
            userRole: (await db.collection('users').findOne({ email: userEmail }))?.role || 'unknown',
            ipAddress,
            timestamp: new Date()
        });
    } catch (error) {
        console.error('Error logging audit:', error);
    }
};

const logLoginAttempt = async (email, success, ipAddress = '') => {
    try {
        await db.collection('login_attempts').insertOne({
            email,
            success,
            ipAddress,
            timestamp: new Date()
        });
    } catch (error) {
        console.error('Error logging login attempt:', error);
    }
};

// ==================== INITIALIZE DEFAULT DATA ====================

const initializeDefaultData = async () => {
    try {
        console.log('🔄 Initializing default data...');
        
        // Check if default admin exists
        const adminExists = await db.collection('users').findOne({ email: 'admin@eduhub.com' });
        
        if (!adminExists) {
            // Create default admin (super admin - can do everything)
            const adminPassword = await hashPassword('admin123');
            
            const superAdmin = {
                email: 'admin@eduhub.com',
                password: adminPassword,
                name: 'Super Administrator',
                role: 'super_admin',
                userId: 'SUPER001',
                permissions: ['all'],
                canViewPasswords: true,
                canToggleFeatures: true,
                canEditEverything: true,
                canManageUsers: true,
                canManageSystem: true,
                status: 'active',
                createdAt: new Date(),
                lastLogin: null
            };
            
            await db.collection('users').insertOne(superAdmin);
            
            // Also create in admins collection
            await db.collection('admins').insertOne({
                adminId: 'SUPER001',
                email: 'admin@eduhub.com',
                name: 'Super Administrator',
                phone: '9876543210',
                permissions: ['all'],
                status: 'active',
                createdAt: new Date()
            });
            
            console.log('✅ Super Admin created: admin@eduhub.com / admin123');
            
            // Create other default roles
            await createDefaultRoles();
            
            // Create default classes, subjects, etc.
            await createDefaultAcademicData();
            
            console.log('✅ Default data initialization completed');
        }
        
    } catch (error) {
        console.error('Error initializing default data:', error);
    }
};

const createDefaultRoles = async () => {
    const defaultRoles = [
        {
            role: 'super_admin',
            description: 'Super Administrator - Full system access',
            permissions: ['all'],
            canViewPasswords: true,
            canToggleFeatures: true,
            canEditEverything: true,
            canManageUsers: true,
            level: 1
        },
        {
            role: 'admin',
            description: 'Administrator - Full school management',
            permissions: ['manage_students', 'manage_teachers', 'manage_exams', 'manage_fees', 'manage_library', 'view_reports'],
            canViewPasswords: true,
            canToggleFeatures: false,
            canEditEverything: true,
            canManageUsers: true,
            level: 2
        },
        {
            role: 'principal',
            description: 'Principal - School head access',
            permissions: ['view_all', 'manage_teachers', 'manage_exams', 'view_reports', 'approve_requests'],
            canViewPasswords: false,
            canToggleFeatures: false,
            canEditEverything: false,
            canManageUsers: false,
            level: 3
        },
        {
            role: 'examiner',
            description: 'Examiner - Exam management access',
            permissions: ['manage_exams', 'manage_results', 'create_tests', 'upload_question_papers', 'view_exam_reports'],
            canViewPasswords: false,
            canToggleFeatures: false,
            canEditEverything: false,
            canManageUsers: false,
            level: 4
        },
        {
            role: 'teacher',
            description: 'Teacher - Class management access',
            permissions: ['manage_class', 'take_attendance', 'create_assignments', 'grade_assignments', 'create_class_tests'],
            canViewPasswords: false,
            canToggleFeatures: false,
            canEditEverything: false,
            canManageUsers: false,
            level: 5
        },
        {
            role: 'librarian',
            description: 'Librarian - Library management access',
            permissions: ['manage_books', 'issue_books', 'manage_fines', 'view_library_reports'],
            canViewPasswords: false,
            canToggleFeatures: false,
            canEditEverything: false,
            canManageUsers: false,
            level: 5
        },
        {
            role: 'student',
            description: 'Student - Student access',
            permissions: ['view_attendance', 'view_results', 'submit_assignments', 'access_library', 'view_resources'],
            canViewPasswords: false,
            canToggleFeatures: false,
            canEditEverything: false,
            canManageUsers: false,
            level: 6
        },
        {
            role: 'parent',
            description: 'Parent - Parent access',
            permissions: ['view_child_attendance', 'view_child_results', 'pay_fees', 'receive_notifications'],
            canViewPasswords: false,
            canToggleFeatures: false,
            canEditEverything: false,
            canManageUsers: false,
            level: 6
        }
    ];
    
    for (const role of defaultRoles) {
        await db.collection('roles').updateOne(
            { role: role.role },
            { $set: role },
            { upsert: true }
        );
    }
};

const createDefaultAcademicData = async () => {
    // Create default classes (1-12)
    for (let i = 1; i <= 12; i++) {
        await db.collection('classes').updateOne(
            { classNumber: i },
            { $set: { 
                classNumber: i,
                className: `Class ${i}`,
                sections: ['A', 'B', 'C', 'D'],
                status: 'active'
            }},
            { upsert: true }
        );
    }
    
    // Create default subjects
    const defaultSubjects = [
        { code: 'ENG', name: 'English', type: 'core' },
        { code: 'MATH', name: 'Mathematics', type: 'core' },
        { code: 'SCI', name: 'Science', type: 'core' },
        { code: 'SOC', name: 'Social Studies', type: 'core' },
        { code: 'PHY', name: 'Physics', type: 'science' },
        { code: 'CHEM', name: 'Chemistry', type: 'science' },
        { code: 'BIO', name: 'Biology', type: 'science' },
        { code: 'COMP', name: 'Computer Science', type: 'elective' },
        { code: 'ECO', name: 'Economics', type: 'commerce' },
        { code: 'ACC', name: 'Accountancy', type: 'commerce' },
        { code: 'BUS', name: 'Business Studies', type: 'commerce' }
    ];
    
    for (const subject of defaultSubjects) {
        await db.collection('subjects').updateOne(
            { code: subject.code },
            { $set: subject },
            { upsert: true }
        );
    }
};

// ==================== BACKUP SYSTEM ====================

const createBackup = async () => {
    if (!systemConfig.backup.enabled) return;
    
    try {
        console.log('🔄 Creating database backup...');
        
        // Get all collections
        const collections = await db.listCollections().toArray();
        const backupData = {
            timestamp: new Date(),
            backupId: `backup_${Date.now()}`,
            collections: {}
        };
        
        // Backup each collection (limit to 1000 documents per collection for size)
        for (const collection of collections) {
            const data = await db.collection(collection.name)
                .find({})
                .limit(1000)
                .toArray();
            
            backupData.collections[collection.name] = data;
        }
        
        // Convert to JSON string (in production, you might want to compress this)
        const backupJson = JSON.stringify(backupData, null, 2);
        
        // Generate a unique backup name
        const backupName = `backup_${formatDateForFileName()}.json`;
        
        // Store backup in database
        await db.collection('backups').insertOne({
            backupId: backupData.backupId,
            name: backupName,
            timestamp: backupData.timestamp,
            size: Buffer.byteLength(backupJson, 'utf8'),
            collectionCount: collections.length,
            data: backupJson, // Storing as text in DB
            status: 'completed'
        });
        
        // Remove old backups if exceeding max
        const allBackups = await db.collection('backups')
            .find({})
            .sort({ timestamp: -1 })
            .toArray();
        
        if (allBackups.length > systemConfig.backup.maxBackups) {
            const backupsToDelete = allBackups.slice(systemConfig.backup.maxBackups);
            for (const backup of backupsToDelete) {
                await db.collection('backups').deleteOne({ _id: backup._id });
            }
        }
        
        console.log(`✅ Backup created: ${backupName}`);
        
    } catch (error) {
        console.error('Error creating backup:', error);
    }
};

const startBackupScheduler = () => {
    if (systemConfig.backup.autoBackup) {
        // Run backup immediately
        createBackup();
        
        // Schedule regular backups
        const intervalHours = systemConfig.backup.interval;
        setInterval(createBackup, intervalHours * 60 * 60 * 1000);
        
        console.log(`✅ Backup scheduler started (every ${intervalHours} hours)`);
    }
};

const startCleanupScheduler = () => {
    // Cleanup old logs every day
    setInterval(async () => {
        try {
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            
            // Cleanup old audit logs
            await db.collection('audit_logs').deleteMany({
                timestamp: { $lt: thirtyDaysAgo }
            });
            
            // Cleanup old login attempts
            await db.collection('login_attempts').deleteMany({
                timestamp: { $lt: thirtyDaysAgo }
            });
            
        } catch (error) {
            console.error('Error in cleanup:', error);
        }
    }, 24 * 60 * 60 * 1000); // Every 24 hours
};

// ==================== API ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        version: '3.0.0',
        database: db ? 'connected' : 'disconnected',
        security: {
            passwordHashing: systemConfig.security.passwordHashing,
            jwtEnabled: systemConfig.security.jwtEnabled
        },
        features: systemConfig.features
    });
});

// ==================== AUTHENTICATION ROUTES ====================

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        // Find user
        const user = await db.collection('users').findOne({ 
            email: email,
            status: 'active'
        });
        
        if (!user) {
            await logLoginAttempt(email, false, req.ip);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Verify password
        const passwordValid = await comparePassword(password, user.password);
        if (!passwordValid) {
            await logLoginAttempt(email, false, req.ip);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Update last login
        await db.collection('users').updateOne(
            { _id: user._id },
            { $set: { lastLogin: new Date() } }
        );
        
        // Generate token if JWT enabled
        let token = null;
        if (systemConfig.security.jwtEnabled) {
            token = generateToken(user);
        }
        
        // Log successful login
        await logLoginAttempt(email, true, req.ip);
        await logAudit('LOGIN', `User logged in: ${email}`, user._id, email, req.ip);
        
        // Prepare response based on security settings
        const response = {
            message: 'Login successful',
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                userId: user.userId || user.admissionNo || user.teacherId,
                canViewPasswords: user.canViewPasswords || false,
                permissions: user.permissions || []
            },
            security: {
                jwtEnabled: systemConfig.security.jwtEnabled,
                passwordHashing: systemConfig.security.passwordHashing
            }
        };
        
        if (token) {
            response.token = token;
            response.tokenExpiresIn = `${systemConfig.security.sessionTimeout}h`;
        }
        
        res.json(response);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Register new user (admin only)
app.post('/api/auth/register', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const userData = req.body;
        
        // Check if user exists
        const existingUser = await db.collection('users').findOne({ email: userData.email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        // Hash password if enabled
        const password = await hashPassword(userData.password || 'password123');
        
        // Create user object
        const newUser = {
            email: userData.email,
            password: password,
            name: userData.name,
            role: userData.role,
            userId: userData.userId,
            status: 'active',
            createdAt: new Date(),
            lastLogin: null
        };
        
        // Add role-specific fields
        if (userData.role === 'student') {
            newUser.admissionNo = userData.admissionNo;
            newUser.class = userData.class;
            newUser.section = userData.section;
            newUser.rollNo = userData.rollNo;
            
            // Also create in students collection
            await db.collection('students').insertOne({
                admissionNo: userData.admissionNo,
                email: userData.email,
                name: userData.name,
                class: userData.class,
                section: userData.section,
                rollNo: userData.rollNo,
                status: 'active',
                createdAt: new Date()
            });
            
        } else if (userData.role === 'teacher') {
            newUser.teacherId = userData.teacherId;
            newUser.subject = userData.subject;
            
            await db.collection('teachers').insertOne({
                teacherId: userData.teacherId,
                email: userData.email,
                name: userData.name,
                subject: userData.subject,
                status: 'active',
                createdAt: new Date()
            });
            
        } else if (userData.role === 'admin') {
            newUser.adminId = userData.adminId;
            newUser.permissions = userData.permissions || [];
            
            await db.collection('admins').insertOne({
                adminId: userData.adminId,
                email: userData.email,
                name: userData.name,
                permissions: userData.permissions,
                status: 'active',
                createdAt: new Date()
            });
        }
        
        // Insert user
        const result = await db.collection('users').insertOne(newUser);
        
        // Log the action
        await logAudit('USER_CREATE', `Created ${userData.role} user: ${userData.email}`, req.user.id, req.user.email, req.ip);
        
        res.status(201).json({
            message: 'User created successfully',
            userId: result.insertedId,
            email: userData.email,
            role: userData.role,
            password: userData.password // Return plain password if no hashing
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== SYSTEM MANAGEMENT ROUTES ====================

// Get system configuration
app.get('/api/system/config', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        res.json(systemConfig);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update system configuration
app.post('/api/system/config', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const updates = req.body;
        
        // Update in memory
        systemConfig = { ...systemConfig, ...updates };
        
        // Update in database
        await db.collection('system_config').updateOne(
            {},
            { $set: updates },
            { upsert: true }
        );
        
        // Log the action
        await logAudit('SYSTEM_CONFIG_UPDATE', 'Updated system configuration', req.user.id, req.user.email, req.ip);
        
        res.json({
            message: 'System configuration updated',
            config: systemConfig
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Toggle security features
app.post('/api/system/toggle-security', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const { feature, enabled } = req.body;
        
        if (!['passwordHashing', 'jwtEnabled'].includes(feature)) {
            return res.status(400).json({ error: 'Invalid security feature' });
        }
        
        // Store old setting
        const oldSetting = systemConfig.security[feature];
        
        // Update configuration
        systemConfig.security[feature] = enabled;
        
        await db.collection('system_config').updateOne(
            {},
            { $set: { [`security.${feature}`]: enabled } }
        );
        
        // Handle security migrations
        if (feature === 'passwordHashing') {
            if (enabled && !oldSetting) {
                // Enable hashing - convert all passwords to hashed
                const count = await convertPasswordsToHashed();
                await logAudit('SECURITY_MIGRATION', `Enabled password hashing. Hashed ${count} passwords`, req.user.id, req.user.email, req.ip);
            } else if (!enabled && oldSetting) {
                // Disable hashing - convert all passwords to plain text
                const count = await convertPasswordsToPlainText();
                await logAudit('SECURITY_MIGRATION', `Disabled password hashing. Reset ${count} passwords to default`, req.user.id, req.user.email, req.ip);
            }
        } else if (feature === 'jwtEnabled') {
            if (!enabled && oldSetting) {
                // JWT disabled - clear all tokens from response (tokens will be invalidated naturally when JWT is disabled)
                // Note: In production, you'd want to blacklist existing tokens
                await logAudit('SECURITY_MIGRATION', 'JWT authentication disabled. All existing tokens invalidated.', req.user.id, req.user.email, req.ip);
            }
        }
        
        await logAudit('SECURITY_TOGGLE', `${feature} set to ${enabled}`, req.user.id, req.user.email, req.ip);
        
        res.json({
            message: `Security feature ${feature} ${enabled ? 'enabled' : 'disabled'}`,
            feature,
            enabled,
            migration: feature === 'passwordHashing' ? (enabled ? 'Passwords have been hashed' : 'Passwords have been reset to default') : null
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Toggle system features
app.post('/api/system/toggle-feature', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const { feature, enabled } = req.body;
        
        if (!systemConfig.features.hasOwnProperty(feature)) {
            return res.status(400).json({ error: 'Invalid feature' });
        }
        
        // Update configuration
        systemConfig.features[feature] = enabled;
        
        await db.collection('system_config').updateOne(
            {},
            { $set: { [`features.${feature}`]: enabled } }
        );
        
        await logAudit('FEATURE_TOGGLE', `${feature} ${enabled ? 'enabled' : 'disabled'}`, req.user.id, req.user.email, req.ip);
        
        res.json({
            message: `Feature ${feature} ${enabled ? 'enabled' : 'disabled'}`,
            feature,
            enabled
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all users with passwords (admin only)
app.get('/api/system/users-with-passwords', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const users = await db.collection('users').find({}, {
            projection: {
                email: 1,
                password: 1,
                name: 1,
                role: 1,
                status: 1,
                createdAt: 1,
                lastLogin: 1
            }
        }).sort({ createdAt: -1 }).toArray();
        
        res.json(users);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== BACKUP MANAGEMENT ROUTES ====================

// Get all backups
app.get('/api/backups', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const backups = await db.collection('backups')
            .find({})
            .sort({ timestamp: -1 })
            .limit(10)
            .toArray();
        
        res.json(backups.map(backup => ({
            id: backup._id,
            backupId: backup.backupId,
            name: backup.name,
            timestamp: backup.timestamp,
            size: backup.size,
            collectionCount: backup.collectionCount,
            status: backup.status
        })));
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get specific backup data
app.get('/api/backups/:id/data', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const backup = await db.collection('backups').findOne({ 
            _id: new ObjectId(req.params.id) 
        });
        
        if (!backup) {
            return res.status(404).json({ error: 'Backup not found' });
        }
        
        // Parse the JSON data
        const backupData = JSON.parse(backup.data);
        
        res.json({
            backupId: backup.backupId,
            timestamp: backup.timestamp,
            data: backupData
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create manual backup
app.post('/api/backups/create', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        await createBackup();
        
        res.json({ 
            message: 'Backup created successfully',
            timestamp: new Date()
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Restore from backup
app.post('/api/backups/:id/restore', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const backup = await db.collection('backups').findOne({ 
            _id: new ObjectId(req.params.id) 
        });
        
        if (!backup) {
            return res.status(404).json({ error: 'Backup not found' });
        }
        
        // Parse backup data
        const backupData = JSON.parse(backup.data);
        
        // Clear existing data and restore
        for (const [collectionName, documents] of Object.entries(backupData.collections)) {
            // Drop collection
            await db.collection(collectionName).deleteMany({});
            
            // Insert documents if any
            if (documents.length > 0) {
                await db.collection(collectionName).insertMany(documents);
            }
        }
        
        // Reload system config
        await loadSystemConfig();
        
        await logAudit('BACKUP_RESTORE', `Restored from backup: ${backup.name}`, req.user.id, req.user.email, req.ip);
        
        res.json({ 
            message: 'Backup restored successfully',
            backupName: backup.name
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== USER MANAGEMENT ROUTES ====================

// Get all users
app.get('/api/users', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const { role, status, search } = req.query;
        let query = {};
        
        if (role) query.role = role;
        if (status) query.status = status;
        if (search) {
            query.$or = [
                { email: { $regex: search, $options: 'i' } },
                { name: { $regex: search, $options: 'i' } }
            ];
        }
        
        const users = await db.collection('users').find(query, {
            projection: { password: 0 }
        }).sort({ createdAt: -1 }).toArray();
        
        res.json(users);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update user
app.put('/api/users/:id', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const updates = req.body;
        delete updates._id;
        delete updates.password; // Use separate endpoint for password change
        
        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { ...updates, updatedAt: new Date() } }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logAudit('USER_UPDATE', `Updated user: ${req.params.id}`, req.user.id, req.user.email, req.ip);
        
        res.json({ message: 'User updated successfully' });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete user
app.delete('/api/users/:id', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Get user details before deletion for audit
        const user = await db.collection('users').findOne({ 
            _id: new ObjectId(userId) 
        });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Delete user from users collection
        const result = await db.collection('users').deleteOne({ 
            _id: new ObjectId(userId) 
        });
        
        // Also delete from role-specific collection
        if (user.role === 'student' && user.admissionNo) {
            await db.collection('students').deleteOne({ admissionNo: user.admissionNo });
        } else if (user.role === 'teacher' && user.teacherId) {
            await db.collection('teachers').deleteOne({ teacherId: user.teacherId });
        } else if (user.role === 'admin' && user.adminId) {
            await db.collection('admins').deleteOne({ adminId: user.adminId });
        }
        
        await logAudit('USER_DELETE', `Deleted user: ${user.email} (${user.role})`, req.user.id, req.user.email, req.ip);
        
        res.json({
            message: 'User deleted successfully',
            deletedUser: {
                email: user.email,
                role: user.role,
                name: user.name
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Reset user password (admin can view/reset passwords)
app.post('/api/users/:id/reset-password', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const { newPassword } = req.body;
        
        if (!newPassword) {
            return res.status(400).json({ error: 'New password is required' });
        }
        
        // Hash if enabled
        const hashedPassword = await hashPassword(newPassword);
        
        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { password: hashedPassword, updatedAt: new Date() } }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await logAudit('PASSWORD_RESET', `Reset password for user: ${req.params.id}`, req.user.id, req.user.email, req.ip);
        
        res.json({ 
            message: 'Password reset successfully',
            plainPassword: systemConfig.security.passwordHashing ? null : newPassword
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user's plain password (admin only)
app.get('/api/users/:id/password', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const user = await db.collection('users').findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { password: 1, email: 1 } }
        );
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // If password hashing is enabled, we can't show plain password
        if (systemConfig.security.passwordHashing) {
            return res.json({
                email: user.email,
                hashedPassword: user.password,
                note: 'Password is hashed. Cannot display plain text.'
            });
        }
        
        res.json({
            email: user.email,
            plainPassword: user.password
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ROLE MANAGEMENT ROUTES ====================

// Assign examiner role to teacher
app.post('/api/roles/assign-examiner', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const { teacherId, permissions } = req.body;
        
        const teacher = await db.collection('teachers').findOne({ teacherId });
        if (!teacher) {
            return res.status(404).json({ error: 'Teacher not found' });
        }
        
        // Update user role
        await db.collection('users').updateOne(
            { email: teacher.email },
            { $set: { role: 'examiner' } }
        );
        
        // Create examiner record
        await db.collection('examiners').updateOne(
            { teacherId },
            { $set: {
                teacherId,
                email: teacher.email,
                name: teacher.name,
                permissions: permissions || ['manage_exams', 'manage_results', 'upload_question_papers'],
                assignedBy: req.user.email,
                assignedAt: new Date(),
                status: 'active'
            }},
            { upsert: true }
        );
        
        await logAudit('ROLE_ASSIGN', `Assigned examiner role to ${teacher.name}`, req.user.id, req.user.email, req.ip);
        
        res.json({
            message: 'Examiner role assigned successfully',
            teacher: {
                teacherId,
                name: teacher.name,
                email: teacher.email,
                permissions: permissions
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Assign principal role
app.post('/api/roles/assign-principal', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const { userId, permissions } = req.body;
        
        const user = await db.collection('users').findOne({ 
            $or: [
                { _id: new ObjectId(userId) },
                { email: userId }
            ]
        });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Update user role
        await db.collection('users').updateOne(
            { _id: user._id },
            { $set: { 
                role: 'principal',
                permissions: permissions || ['view_all', 'manage_teachers', 'approve_requests']
            }}
        );
        
        // Create principal record
        await db.collection('principals').updateOne(
            { userId: user._id },
            { $set: {
                userId: user._id,
                email: user.email,
                name: user.name,
                permissions: permissions || ['view_all', 'manage_teachers', 'approve_requests'],
                assignedBy: req.user.email,
                assignedAt: new Date(),
                status: 'active'
            }},
            { upsert: true }
        );
        
        await logAudit('ROLE_ASSIGN', `Assigned principal role to ${user.name}`, req.user.id, req.user.email, req.ip);
        
        res.json({
            message: 'Principal role assigned successfully',
            principal: {
                name: user.name,
                email: user.email,
                permissions: permissions
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Assign librarian role
app.post('/api/roles/assign-librarian', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const { userId, canManageFees = false } = req.body;
        
        const user = await db.collection('users').findOne({ 
            $or: [
                { _id: new ObjectId(userId) },
                { email: userId }
            ]
        });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Update user role
        await db.collection('users').updateOne(
            { _id: user._id },
            { $set: { role: 'librarian' } }
        );
        
        // Create librarian record
        await db.collection('librarians').updateOne(
            { userId: user._id },
            { $set: {
                userId: user._id,
                email: user.email,
                name: user.name,
                canManageFees,
                assignedBy: req.user.email,
                assignedAt: new Date(),
                status: 'active'
            }},
            { upsert: true }
        );
        
        await logAudit('ROLE_ASSIGN', `Assigned librarian role to ${user.name}`, req.user.id, req.user.email, req.ip);
        
        res.json({
            message: 'Librarian role assigned successfully',
            librarian: {
                name: user.name,
                email: user.email,
                canManageFees
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== STUDENT MANAGEMENT ROUTES ====================

app.get('/api/students', authenticateUser, async (req, res) => {
    try {
        const { class: className, section, status, search } = req.query;
        let query = {};
        
        if (className) query.class = className;
        if (section) query.section = section;
        if (status) query.status = status;
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { admissionNo: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ];
        }
        
        const students = await db.collection('students').find(query)
            .sort({ class: 1, section: 1, rollNo: 1 })
            .toArray();
        
        res.json(students);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/students/:id', authenticateUser, async (req, res) => {
    try {
        const student = await db.collection('students').findOne({ 
            $or: [
                { _id: new ObjectId(req.params.id) },
                { admissionNo: req.params.id }
            ]
        });
        
        if (!student) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        // Get student's user account details (including password if admin)
        let userDetails = null;
        const user = await db.collection('users').findOne({ email: student.email });
        
        if (user && (req.user.role === 'super_admin' || req.user.role === 'admin')) {
            userDetails = {
                email: user.email,
                password: user.password,
                lastLogin: user.lastLogin,
                status: user.status
            };
        }
        
        res.json({
            ...student,
            userDetails
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== EXAM MANAGEMENT ROUTES ====================

// Create exam (admin/examiner)
app.post('/api/exams', authenticateUser, checkFeatureEnabled('exams'), async (req, res) => {
    try {
        // Check permission
        if (!['super_admin', 'admin', 'examiner'].includes(req.user.role)) {
            return res.status(403).json({ error: 'Permission denied' });
        }
        
        const examData = req.body;
        
        // Generate exam code
        const examCount = await db.collection('exams').countDocuments();
        examData.examCode = `EXAM${(examCount + 1).toString().padStart(4, '0')}`;
        
        examData.createdBy = req.user.email;
        examData.createdAt = new Date();
        examData.status = 'scheduled';
        
        const result = await db.collection('exams').insertOne(examData);
        
        await logAudit('EXAM_CREATE', `Created exam: ${examData.name}`, req.user.id, req.user.email, req.ip);
        
        res.status(201).json({
            message: 'Exam created successfully',
            examId: result.insertedId,
            examCode: examData.examCode,
            examData
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Upload results (examiner/admin)
app.post('/api/exams/:id/results', authenticateUser, checkFeatureEnabled('results'), async (req, res) => {
    try {
        if (!['super_admin', 'admin', 'examiner'].includes(req.user.role)) {
            return res.status(403).json({ error: 'Permission denied' });
        }
        
        const { results } = req.body;
        
        // Validate results structure
        if (!Array.isArray(results)) {
            return res.status(400).json({ error: 'Results must be an array' });
        }
        
        const exam = await db.collection('exams').findOne({ _id: new ObjectId(req.params.id) });
        if (!exam) {
            return res.status(404).json({ error: 'Exam not found' });
        }
        
        // Process and save results
        const processedResults = results.map(result => ({
            examId: req.params.id,
            examCode: exam.examCode,
            examName: exam.name,
            studentId: result.studentId,
            studentName: result.studentName,
            class: exam.class,
            subject: exam.subject,
            marks: result.marks,
            totalMarks: exam.totalMarks,
            percentage: (result.marks / exam.totalMarks) * 100,
            grade: calculateGrade((result.marks / exam.totalMarks) * 100),
            uploadedBy: req.user.email,
            uploadedAt: new Date(),
            status: 'published'
        }));
        
        // Insert results
        await db.collection('exam_results').insertMany(processedResults);
        
        await logAudit('RESULTS_UPLOAD', `Uploaded results for exam: ${exam.name}`, req.user.id, req.user.email, req.ip);
        
        res.json({
            message: 'Results uploaded successfully',
            count: processedResults.length,
            exam: exam.name
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Grade calculator
const calculateGrade = (percentage) => {
    if (percentage >= 90) return 'A+';
    if (percentage >= 80) return 'A';
    if (percentage >= 70) return 'B+';
    if (percentage >= 60) return 'B';
    if (percentage >= 50) return 'C';
    if (percentage >= 40) return 'D';
    if (percentage >= 33) return 'E';
    return 'F';
};

// ==================== CLASS TEST ROUTES ====================

// Create class test (teacher)
app.post('/api/class-tests', authenticateUser, checkFeatureEnabled('classTests'), async (req, res) => {
    try {
        if (!['super_admin', 'admin', 'teacher', 'examiner'].includes(req.user.role)) {
            return res.status(403).json({ error: 'Permission denied' });
        }
        
        const testData = req.body;
        
        // Generate test ID
        testData.testId = `TEST${Date.now()}`;
        testData.createdBy = req.user.email;
        testData.createdAt = new Date();
        testData.status = 'active';
        
        await db.collection('class_tests').insertOne(testData);
        
        await logAudit('TEST_CREATE', `Created class test: ${testData.name}`, req.user.id, req.user.email, req.ip);
        
        res.status(201).json({
            message: 'Class test created successfully',
            testId: testData.testId,
            testData
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Upload test results
app.post('/api/class-tests/:id/results', authenticateUser, async (req, res) => {
    try {
        const { results } = req.body;
        
        const test = await db.collection('class_tests').findOne({ testId: req.params.id });
        if (!test) {
            return res.status(404).json({ error: 'Test not found' });
        }
        
        const processedResults = results.map(result => ({
            testId: req.params.id,
            testName: test.name,
            studentId: result.studentId,
            studentName: result.studentName,
            class: test.class,
            subject: test.subject,
            marks: result.marks,
            totalMarks: test.totalMarks,
            uploadedBy: req.user.email,
            uploadedAt: new Date()
        }));
        
        await db.collection('test_results').insertMany(processedResults);
        
        res.json({
            message: 'Test results uploaded successfully',
            count: processedResults.length
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== LIBRARY MANAGEMENT ROUTES ====================

// Add book (librarian/admin)
app.post('/api/library/books', authenticateUser, checkFeatureEnabled('library'), async (req, res) => {
    try {
        if (!['super_admin', 'admin', 'librarian'].includes(req.user.role)) {
            return res.status(403).json({ error: 'Permission denied' });
        }
        
        const bookData = req.body;
        
        // Generate book ID if not provided
        if (!bookData.bookId) {
            const count = await db.collection('library_books').countDocuments();
            bookData.bookId = `BOOK${(count + 1).toString().padStart(5, '0')}`;
        }
        
        bookData.addedBy = req.user.email;
        bookData.addedAt = new Date();
        bookData.available = bookData.totalCopies || 1;
        bookData.status = 'available';
        
        // Handle cover image (URL or base64)
        if (bookData.coverImage && bookData.coverImage.startsWith('data:image')) {
            // Store as text (base64) or upload to cloud storage
            // For now, we'll store as text
            bookData.coverImageData = bookData.coverImage;
            delete bookData.coverImage;
        }
        
        await db.collection('library_books').insertOne(bookData);
        
        await logAudit('BOOK_ADD', `Added book: ${bookData.title}`, req.user.id, req.user.email, req.ip);
        
        res.status(201).json({
            message: 'Book added successfully',
            bookId: bookData.bookId,
            bookData: {
                title: bookData.title,
                author: bookData.author,
                isbn: bookData.isbn,
                available: bookData.available
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Issue book to student
app.post('/api/library/books/issue', authenticateUser, async (req, res) => {
    try {
        if (!['super_admin', 'admin', 'librarian'].includes(req.user.role)) {
            return res.status(403).json({ error: 'Permission denied' });
        }
        
        const { bookId, studentId, studentName, class: className, section, dueDate } = req.body;
        
        // Check book availability
        const book = await db.collection('library_books').findOne({ bookId });
        if (!book) {
            return res.status(404).json({ error: 'Book not found' });
        }
        
        if (book.available <= 0) {
            return res.status(400).json({ error: 'Book not available' });
        }
        
        // Create issue record
        const issueRecord = {
            issueId: `ISSUE${Date.now()}`,
            bookId,
            bookTitle: book.title,
            bookAuthor: book.author,
            studentId,
            studentName,
            class: className,
            section,
            issueDate: new Date(),
            dueDate: new Date(dueDate),
            issuedBy: req.user.email,
            returned: false,
            fine: 0,
            status: 'issued'
        };
        
        await db.collection('book_issues').insertOne(issueRecord);
        
        // Update book availability
        await db.collection('library_books').updateOne(
            { bookId },
            { $inc: { available: -1 } }
        );
        
        await logAudit('BOOK_ISSUE', `Issued book: ${book.title} to ${studentName}`, req.user.id, req.user.email, req.ip);
        
        res.json({
            message: 'Book issued successfully',
            issueId: issueRecord.issueId,
            dueDate: issueRecord.dueDate
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Return book
app.post('/api/library/books/return', authenticateUser, async (req, res) => {
    try {
        if (!['super_admin', 'admin', 'librarian'].includes(req.user.role)) {
            return res.status(403).json({ error: 'Permission denied' });
        }
        
        const { issueId, condition, fine = 0 } = req.body;
        
        const issue = await db.collection('book_issues').findOne({ issueId });
        if (!issue) {
            return res.status(404).json({ error: 'Issue record not found' });
        }
        
        if (issue.returned) {
            return res.status(400).json({ error: 'Book already returned' });
        }
        
        // Update issue record
        await db.collection('book_issues').updateOne(
            { issueId },
            { 
                $set: {
                    returned: true,
                    returnDate: new Date(),
                    returnedBy: req.user.email,
                    condition,
                    fine,
                    status: 'returned'
                }
            }
        );
        
        // Update book availability
        await db.collection('library_books').updateOne(
            { bookId: issue.bookId },
            { $inc: { available: 1 } }
        );
        
        await logAudit('BOOK_RETURN', `Returned book: ${issue.bookTitle}`, req.user.id, req.user.email, req.ip);
        
        res.json({
            message: 'Book returned successfully',
            issueId,
            fine
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== FEE MANAGEMENT ROUTES ====================

// Update fee structure (admin/librarian)
app.post('/api/fees/structure', authenticateUser, checkFeatureEnabled('fees'), async (req, res) => {
    try {
        if (!['super_admin', 'admin', 'librarian'].includes(req.user.role)) {
            // Librarian can only update library fees
            if (req.user.role === 'librarian') {
                const { feeType } = req.body;
                if (!feeType || !feeType.toLowerCase().includes('library')) {
                    return res.status(403).json({ 
                        error: 'Librarian can only update library fees' 
                    });
                }
            } else {
                return res.status(403).json({ error: 'Permission denied' });
            }
        }
        
        const feeData = req.body;
        
        // Generate fee code
        const count = await db.collection('fee_structures').countDocuments();
        feeData.feeCode = `FEE${(count + 1).toString().padStart(5, '0')}`;
        
        feeData.createdBy = req.user.email;
        feeData.createdAt = new Date();
        feeData.status = 'active';
        
        await db.collection('fee_structures').insertOne(feeData);
        
        await logAudit('FEE_UPDATE', `Updated fee structure: ${feeData.feeType}`, req.user.id, req.user.email, req.ip);
        
        res.status(201).json({
            message: 'Fee structure updated successfully',
            feeCode: feeData.feeCode,
            feeData
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== RESOURCE MANAGEMENT ROUTES ====================

// Upload resource (teacher/admin)
app.post('/api/resources', authenticateUser, checkFeatureEnabled('resources'), async (req, res) => {
    try {
        if (!['super_admin', 'admin', 'teacher', 'examiner'].includes(req.user.role)) {
            return res.status(403).json({ error: 'Permission denied' });
        }
        
        const resourceData = req.body;
        
        // Validate resource type
        const allowedTypes = ['pdf', 'video', 'note', 'question_paper', 'syllabus'];
        if (!allowedTypes.includes(resourceData.type)) {
            return res.status(400).json({ error: 'Invalid resource type' });
        }
        
        // Handle different resource types
        switch (resourceData.type) {
            case 'video':
                // YouTube link or video URL
                if (!resourceData.videoUrl) {
                    return res.status(400).json({ error: 'Video URL is required' });
                }
                break;
                
            case 'pdf':
            case 'note':
                // Can be Google Drive link or direct URL
                if (!resourceData.fileUrl) {
                    return res.status(400).json({ error: 'File URL is required' });
                }
                break;
        }
        
        resourceData.resourceId = `RES${Date.now()}`;
        resourceData.uploadedBy = req.user.email;
        resourceData.uploadedAt = new Date();
        resourceData.status = 'active';
        resourceData.downloads = 0;
        resourceData.views = 0;
        
        await db.collection('resources').insertOne(resourceData);
        
        await logAudit('RESOURCE_UPLOAD', `Uploaded resource: ${resourceData.title}`, req.user.id, req.user.email, req.ip);
        
        res.status(201).json({
            message: 'Resource uploaded successfully',
            resourceId: resourceData.resourceId,
            resourceData
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ANALYTICS & GRAPHS ROUTES ====================

// Get overall class performance
app.get('/api/analytics/class-performance/:class', authenticateUser, async (req, res) => {
    try {
        const className = req.params.class;
        
        // Get exam results for the class
        const results = await db.collection('exam_results').find({ 
            class: className 
        }).toArray();
        
        // Get class tests
        const tests = await db.collection('test_results').find({
            class: className
        }).toArray();
        
        // Get attendance
        const attendance = await db.collection('attendance_records').aggregate([
            { $match: { class: className } },
            { $group: {
                _id: { studentId: '$studentId', studentName: '$studentName' },
                totalDays: { $sum: 1 },
                presentDays: { $sum: { $cond: [{ $eq: ['$status', 'present'] }, 1, 0] } },
                attendancePercentage: { 
                    $avg: { $cond: [{ $eq: ['$status', 'present'] }, 100, 0] } 
                }
            }},
            { $sort: { attendancePercentage: -1 } }
        ]).toArray();
        
        // Calculate statistics
        const examStats = calculateExamStatistics(results);
        const testStats = calculateTestStatistics(tests);
        const attendanceStats = calculateAttendanceStatistics(attendance);
        
        // Create graph data
        const graphData = {
            examPerformance: examStats,
            testPerformance: testStats,
            attendanceTrend: attendanceStats,
            topPerformers: getTopPerformers(results),
            weakAreas: getWeakAreas(results),
            monthlyTrend: getMonthlyTrend(results)
        };
        
        res.json({
            class: className,
            totalStudents: attendance.length,
            overallPerformance: {
                examAverage: examStats.averagePercentage,
                testAverage: testStats.averagePercentage,
                attendanceAverage: attendanceStats.averagePercentage
            },
            graphData
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get student analytics
app.get('/api/analytics/student/:id', authenticateUser, async (req, res) => {
    try {
        const studentId = req.params.id;
        
        // Get student details
        const student = await db.collection('students').findOne({
            $or: [
                { _id: new ObjectId(studentId) },
                { admissionNo: studentId }
            ]
        });
        
        if (!student) {
            return res.status(404).json({ error: 'Student not found' });
        }
        
        // Get all data for the student
        const [examResults, testResults, attendance, assignments] = await Promise.all([
            db.collection('exam_results').find({ studentId }).sort({ uploadedAt: -1 }).toArray(),
            db.collection('test_results').find({ studentId }).sort({ uploadedAt: -1 }).toArray(),
            db.collection('attendance_records').find({ studentId }).sort({ date: -1 }).limit(30).toArray(),
            db.collection('submissions').find({ studentId }).sort({ submittedAt: -1 }).toArray()
        ]);
        
        // Calculate performance
        const performance = {
            exams: {
                total: examResults.length,
                average: examResults.length > 0 ? 
                    examResults.reduce((sum, r) => sum + r.percentage, 0) / examResults.length : 0,
                recent: examResults.slice(0, 5)
            },
            tests: {
                total: testResults.length,
                average: testResults.length > 0 ? 
                    testResults.reduce((sum, r) => sum + (r.marks / r.totalMarks * 100), 0) / testResults.length : 0,
                recent: testResults.slice(0, 5)
            },
            attendance: {
                totalDays: attendance.length,
                presentDays: attendance.filter(a => a.status === 'present').length,
                percentage: attendance.length > 0 ? 
                    (attendance.filter(a => a.status === 'present').length / attendance.length) * 100 : 0,
                recent: attendance.slice(0, 10)
            }
        };
        
        // Create graph data
        const graphData = {
            examTrend: examResults.map(r => ({
                date: r.uploadedAt,
                exam: r.examName,
                percentage: r.percentage,
                grade: r.grade
            })),
            subjectPerformance: calculateSubjectPerformance(examResults),
            attendanceHistory: attendance.map(a => ({
                date: a.date,
                status: a.status,
                subject: a.subject
            }))
        };
        
        res.json({
            student: {
                name: student.name,
                class: student.class,
                section: student.section,
                admissionNo: student.admissionNo
            },
            performance,
            graphData
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Helper functions for analytics
const calculateExamStatistics = (results) => {
    if (!results || results.length === 0) {
        return { averagePercentage: 0, topScore: 0, lowestScore: 0, gradeDistribution: {} };
    }
    
    const percentages = results.map(r => r.percentage);
    const average = percentages.reduce((a, b) => a + b, 0) / percentages.length;
    
    return {
        averagePercentage: Math.round(average * 100) / 100,
        topScore: Math.max(...percentages),
        lowestScore: Math.min(...percentages),
        gradeDistribution: results.reduce((acc, r) => {
            acc[r.grade] = (acc[r.grade] || 0) + 1;
            return acc;
        }, {})
    };
};

const calculateTestStatistics = (tests) => {
    if (!tests || tests.length === 0) {
        return { averagePercentage: 0, topScore: 0, lowestScore: 0 };
    }
    
    const percentages = tests.map(t => (t.marks / t.totalMarks) * 100);
    const average = percentages.reduce((a, b) => a + b, 0) / percentages.length;
    
    return {
        averagePercentage: Math.round(average * 100) / 100,
        topScore: Math.max(...percentages),
        lowestScore: Math.min(...percentages)
    };
};

const calculateAttendanceStatistics = (attendance) => {
    if (!attendance || attendance.length === 0) {
        return { averagePercentage: 0, bestAttendance: 0, worstAttendance: 0 };
    }
    
    const percentages = attendance.map(a => a.attendancePercentage);
    const average = percentages.reduce((a, b) => a + b, 0) / percentages.length;
    
    return {
        averagePercentage: Math.round(average * 100) / 100,
        bestAttendance: Math.max(...percentages),
        worstAttendance: Math.min(...percentages)
    };
};

const getTopPerformers = (results) => {
    const studentPerformance = results.reduce((acc, r) => {
        if (!acc[r.studentId]) {
            acc[r.studentId] = {
                studentId: r.studentId,
                studentName: r.studentName,
                totalExams: 0,
                totalPercentage: 0
            };
        }
        acc[r.studentId].totalExams++;
        acc[r.studentId].totalPercentage += r.percentage;
        return acc;
    }, {});
    
    return Object.values(studentPerformance)
        .map(s => ({
            ...s,
            averagePercentage: s.totalPercentage / s.totalExams
        }))
        .sort((a, b) => b.averagePercentage - a.averagePercentage)
        .slice(0, 10);
};

const getWeakAreas = (results) => {
    const subjectPerformance = results.reduce((acc, r) => {
        if (!acc[r.subject]) {
            acc[r.subject] = {
                subject: r.subject,
                totalExams: 0,
                totalPercentage: 0
            };
        }
        acc[r.subject].totalExams++;
        acc[r.subject].totalPercentage += r.percentage;
        return acc;
    }, {});
    
    return Object.values(subjectPerformance)
        .map(s => ({
            ...s,
            averagePercentage: s.totalPercentage / s.totalExams
        }))
        .sort((a, b) => a.averagePercentage - b.averagePercentage)
        .slice(0, 5);
};

const getMonthlyTrend = (results) => {
    const monthlyData = results.reduce((acc, r) => {
        const date = new Date(r.uploadedAt);
        const month = `${getMonthName(date)} ${date.getFullYear()}`;
        if (!acc[month]) {
            acc[month] = {
                month,
                totalExams: 0,
                totalPercentage: 0
            };
        }
        acc[month].totalExams++;
        acc[month].totalPercentage += r.percentage;
        return acc;
    }, {});
    
    return Object.values(monthlyData)
        .map(m => ({
            ...m,
            averagePercentage: m.totalPercentage / m.totalExams
        }))
        .sort((a, b) => {
            // Sort by date
            const [monthA, yearA] = a.month.split(' ');
            const [monthB, yearB] = b.month.split(' ');
            const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
            const dateA = new Date(parseInt(yearA), months.indexOf(monthA));
            const dateB = new Date(parseInt(yearB), months.indexOf(monthB));
            return dateA - dateB;
        });
};

const calculateSubjectPerformance = (results) => {
    const subjectData = results.reduce((acc, r) => {
        if (!acc[r.subject]) {
            acc[r.subject] = {
                subject: r.subject,
                totalExams: 0,
                totalPercentage: 0,
                grades: {}
            };
        }
        acc[r.subject].totalExams++;
        acc[r.subject].totalPercentage += r.percentage;
        acc[r.subject].grades[r.grade] = (acc[r.subject].grades[r.grade] || 0) + 1;
        return acc;
    }, {});
    
    return Object.values(subjectData).map(s => ({
        ...s,
        averagePercentage: s.totalPercentage / s.totalExams,
        bestGrade: Object.keys(s.grades).reduce((a, b) => s.grades[a] > s.grades[b] ? a : b)
    }));
};

// ==================== AUDIT LOGS ROUTES ====================

// Get audit logs (admin only)
app.get('/api/system/audit-logs', authenticateUser, checkPermission('super_admin'), async (req, res) => {
    try {
        const { page = 1, limit = 50, userId, action, startDate, endDate } = req.query;
        const skip = (page - 1) * limit;
        
        let query = {};
        if (userId) query.userId = userId;
        if (action) query.action = action;
        if (startDate || endDate) {
            query.timestamp = {};
            if (startDate) query.timestamp.$gte = new Date(startDate);
            if (endDate) query.timestamp.$lte = new Date(endDate);
        }
        
        const [logs, total] = await Promise.all([
            db.collection('audit_logs').find(query)
                .sort({ timestamp: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .toArray(),
            db.collection('audit_logs').countDocuments(query)
        ]);
        
        res.json({
            logs,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== DASHBOARD STATISTICS ====================

app.get('/api/dashboard/stats', authenticateUser, async (req, res) => {
    try {
        // Get statistics based on user role
        let stats = {};
        
        if (['super_admin', 'admin', 'principal'].includes(req.user.role)) {
            // Full school statistics
            const [
                totalStudents, totalTeachers, totalParents,
                totalExams, totalAssignments, totalBooks,
                todayAttendance, pendingFees, upcomingEvents
            ] = await Promise.all([
                db.collection('students').countDocuments({ status: 'active' }),
                db.collection('teachers').countDocuments({ status: 'active' }),
                db.collection('users').countDocuments({ role: 'parent', status: 'active' }),
                db.collection('exams').countDocuments({ status: 'scheduled' }),
                db.collection('assignments').countDocuments({ dueDate: { $gte: new Date() } }),
                db.collection('library_books').countDocuments(),
                db.collection('attendance').countDocuments({ 
                    date: { 
                        $gte: getStartOfDay(),
                        $lte: getEndOfDay()
                    }
                }),
                db.collection('fee_payments').countDocuments({ status: 'pending' }),
                db.collection('events').countDocuments({ 
                    date: { $gte: new Date() },
                    status: 'upcoming'
                })
            ]);
            
            stats = {
                overview: {
                    totalStudents, totalTeachers, totalParents,
                    totalExams, totalAssignments, totalBooks
                },
                today: {
                    todayAttendance, pendingFees, upcomingEvents
                },
                financial: {
                    totalRevenue: await calculateTotalRevenue(),
                    pendingAmount: await calculatePendingFees()
                }
            };
            
        } else if (req.user.role === 'teacher') {
            // Teacher dashboard
            const teacher = await db.collection('teachers').findOne({ email: req.user.email });
            
            stats = {
                myClasses: teacher?.classes || [],
                totalStudents: await db.collection('students').countDocuments({
                    class: { $in: teacher?.classes || [] }
                }),
                pendingAssignments: await db.collection('submissions').countDocuments({
                    graded: false,
                    subject: teacher?.subject
                }),
                upcomingClasses: await getUpcomingClasses(req.user.email)
            };
            
        } else if (req.user.role === 'student') {
            // Student dashboard
            const student = await db.collection('students').findOne({ email: req.user.email });
            
            stats = {
                attendance: await getStudentAttendance(student?.admissionNo),
                upcomingExams: await db.collection('exams').countDocuments({
                    class: student?.class,
                    date: { $gte: new Date() }
                }),
                pendingAssignments: await db.collection('assignments').countDocuments({
                    class: student?.class,
                    dueDate: { $gte: new Date() }
                }),
                libraryBooks: await db.collection('book_issues').countDocuments({
                    studentId: student?.admissionNo,
                    returned: false
                })
            };
        }
        
        // Add system info
        stats.system = {
            security: {
                passwordHashing: systemConfig.security.passwordHashing,
                jwtEnabled: systemConfig.security.jwtEnabled
            },
            features: systemConfig.features
        };
        
        res.json(stats);
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Helper functions for dashboard
const calculateTotalRevenue = async () => {
    const result = await db.collection('fee_payments').aggregate([
        { $match: { status: 'paid' } },
        { $group: {
            _id: null,
            total: { $sum: '$amount' }
        }}
    ]).toArray();
    
    return result[0]?.total || 0;
};

const calculatePendingFees = async () => {
    const result = await db.collection('fee_payments').aggregate([
        { $match: { status: 'pending' } },
        { $group: {
            _id: null,
            total: { $sum: '$amount' }
        }}
    ]).toArray();
    
    return result[0]?.total || 0;
};

const getUpcomingClasses = async (teacherEmail) => {
    const today = new Date();
    const dayOfWeek = today.getDay();
    const dayName = getDayName(today);
    
    return await db.collection('timetables').find({
        teacher: teacherEmail,
        day: dayName,
        $or: [
            { startTime: { $gt: formatTime() } },
            { endTime: { $gt: formatTime() } }
        ]
    }).toArray();
};

const getStudentAttendance = async (studentId) => {
    const today = new Date();
    const startOfMonth = getStartOfMonth(today);
    
    const records = await db.collection('attendance_records').find({
        studentId,
        date: { $gte: startOfMonth }
    }).toArray();
    
    if (records.length === 0) return { percentage: 0, present: 0, total: 0 };
    
    const present = records.filter(r => r.status === 'present').length;
    return {
        percentage: Math.round((present / records.length) * 100),
        present,
        total: records.length
    };
};

// ==================== SEARCH ENDPOINT ====================

app.get('/api/search', authenticateUser, async (req, res) => {
    try {
        const { q, type } = req.query;
        
        if (!q) {
            return res.json({ results: [] });
        }
        
        let results = [];
        
        if (type === 'student') {
            results = await db.collection('students').find({
                $or: [
                    { name: { $regex: q, $options: 'i' } },
                    { admissionNo: { $regex: q, $options: 'i' } },
                    { email: { $regex: q, $options: 'i' } }
                ]
            }).limit(20).toArray();
            
        } else if (type === 'teacher') {
            results = await db.collection('teachers').find({
                $or: [
                    { name: { $regex: q, $options: 'i' } },
                    { teacherId: { $regex: q, $options: 'i' } },
                    { email: { $regex: q, $options: 'i' } }
                ]
            }).limit(20).toArray();
            
        } else if (type === 'book') {
            results = await db.collection('library_books').find({
                $or: [
                    { title: { $regex: q, $options: 'i' } },
                    { author: { $regex: q, $options: 'i' } },
                    { isbn: { $regex: q, $options: 'i' } }
                ]
            }).limit(20).toArray();
            
        } else {
            // Global search
            const [students, teachers, books, resources] = await Promise.all([
                db.collection('students').find({
                    $or: [
                        { name: { $regex: q, $options: 'i' } },
                        { admissionNo: { $regex: q, $options: 'i' } }
                    ]
                }).limit(5).toArray(),
                
                db.collection('teachers').find({
                    $or: [
                        { name: { $regex: q, $options: 'i' } },
                        { teacherId: { $regex: q, $options: 'i' } }
                    ]
                }).limit(5).toArray(),
                
                db.collection('library_books').find({
                    $or: [
                        { title: { $regex: q, $options: 'i' } },
                        { author: { $regex: q, $options: 'i' } }
                    ]
                }).limit(5).toArray(),
                
                db.collection('resources').find({
                    $or: [
                        { title: { $regex: q, $options: 'i' } },
                        { description: { $regex: q, $options: 'i' } }
                    ]
                }).limit(5).toArray()
            ]);
            
            results = [
                ...students.map(s => ({ ...s, type: 'student' })),
                ...teachers.map(t => ({ ...t, type: 'teacher' })),
                ...books.map(b => ({ ...b, type: 'book' })),
                ...resources.map(r => ({ ...r, type: 'resource' }))
            ];
        }
        
        res.json({ results });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.stack);
    
    // Log the error
    logAudit('SERVER_ERROR', err.message, req.user?.id || 'unknown', req.user?.email || 'unknown', req.ip);
    
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!',
        timestamp: new Date().toISOString()
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        path: req.path,
        method: req.method,
        availableEndpoints: [
            '/api/health',
            '/api/auth/login',
            '/api/dashboard/stats',
            '/api/system/config',
            '/api/users',
            '/api/students',
            '/api/teachers',
            '/api/exams',
            '/api/library/books',
            '/api/analytics/class-performance/:class',
            '/api/search'
        ]
    });
});

// ==================== START SERVER ====================

connectToMongoDB();

app.listen(PORT, () => {
    console.log(`🚀 EduHub School Management System`);
    console.log(`📍 Port: ${PORT}`);
    console.log(`📊 Features: ${Object.keys(systemConfig.features).filter(k => systemConfig.features[k]).length}+ enabled`);
    console.log(`🔐 Security: ${systemConfig.security.passwordHashing ? 'Hashing ✅' : 'Hashing ❌'} | ${systemConfig.security.jwtEnabled ? 'JWT ✅' : 'JWT ❌'}`);
    console.log(`💾 Backups: ${systemConfig.backup.enabled ? `Auto (every ${systemConfig.backup.interval}h)` : 'Manual'}`);
    console.log(`👑 Super Admin: admin@eduhub.com / admin123`);
    console.log(`🔗 Health Check: http://localhost:${PORT}/api/health`);
});

// Export for serverless deployment
module.exports = app;
