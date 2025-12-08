const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Store logs in memory (in production, you might want to use a logging service)
const logs = [];
const LOG_PASSWORD = process.env.LOG_PASSWORD || 'bunny';
// Add this at the VERY BEGINNING of your file
process.on('uncaughtException', (error) => {
    console.error('💥 UNCAUGHT EXCEPTION:', error);
    console.error(error.stack);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 UNHANDLED REJECTION at:', promise, 'reason:', reason);
});
// Add request logging middleware
app.use((req, res, next) => {
    const start = Date.now();
    const originalSend = res.send;
    
    // Store response data
    let responseBody = '';
    res.send = function(body) {
        responseBody = body;
        return originalSend.call(this, body);
    };
    
    // Log after response is sent
    res.on('finish', () => {
        const duration = Date.now() - start;
        const logEntry = {
            timestamp: new Date().toISOString(),
            method: req.method,
            url: req.url,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            userEmail: req.headers['x-user-email'] || 'anonymous',
            userRole: req.headers['x-user-role'] || 'guest',
            requestBody: req.body ? JSON.stringify(req.body).substring(0, 500) : null,
            responseBody: typeof responseBody === 'string' ? responseBody.substring(0, 500) : null,
            memoryUsage: process.memoryUsage()
        };
        
        logs.unshift(logEntry); // Add to beginning for reverse chronological order
        
        // Keep only last 1000 logs to prevent memory issues
        if (logs.length > 1000) {
            logs.pop();
        }
        
        // Console log for debugging
        console.log(`[${logEntry.timestamp}] ${req.method} ${req.url} - ${res.statusCode} - ${duration}ms - User: ${logEntry.userEmail}`);
    });
    
    next();
});

// Middleware - Allow ALL origins
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-User-Email', 'X-User-Role']
}));

app.options('*', cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://trenny:trennydev@trennydev.hieeqv2.mongodb.net/eduhub_school?retryWrites=true&w=majority';
const client = new MongoClient(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

let db;
let dbName = 'eduhub_school';

// Connect to MongoDB
const connectToMongoDB = async () => {
    try {
        console.log('🔄 Connecting to MongoDB...');
        await client.connect();
        db = client.db(dbName);
        console.log(`✅ MongoDB connected successfully to database: ${dbName}`);
        
        // Create collections
        await initializeCollections();
        await initializeDefaultData();
        
        // Add connection log
        logs.unshift({
            timestamp: new Date().toISOString(),
            event: 'MongoDB Connection',
            message: `Connected to database: ${dbName}`,
            status: 'success'
        });
        
    } catch (error) {
        console.error('❌ MongoDB connection failed:', error.message);
        logs.unshift({
            timestamp: new Date().toISOString(),
            event: 'MongoDB Connection',
            message: `Connection failed: ${error.message}`,
            status: 'error',
            error: error.message
        });
        
        console.log('🔄 Retrying in 5 seconds...');
        setTimeout(connectToMongoDB, 5000);
    }
};

// Initialize collections
const initializeCollections = async () => {
    const collections = [
        'users', 'students', 'teachers', 'parents', 'courses', 'attendance', 
        'results', 'announcements', 'resources', 'flashcards', 'notes', 
        'studytimes', 'videos', 'notifications', 'messages', 'assignments',
        'submissions', 'events', 'timetable', 'fees', 'payments',
        'library', 'books', 'borrowings', 'complaints', 'feedbacks',
        'exams', 'questions', 'quizzes', 'certificates', 'badges',
        'achievements', 'meetings', 'reports', 'analytics', 'settings'
    ];
    
    for (const collectionName of collections) {
        try {
            await db.createCollection(collectionName);
            console.log(`✅ Collection ${collectionName} created/verified`);
        } catch (error) {
            // Collection already exists - this is fine
        }
    }
};

// Initialize default data
const initializeDefaultData = async () => {
    try {
        console.log('🔄 Checking for default data...');

        // Check if admin exists
        const adminExists = await db.collection('users').findOne({ email: 'admin@eduhub.com' });
        if (!adminExists) {
            await db.collection('users').insertOne({
                email: 'admin@eduhub.com',
                password: 'admin123', // Plain text password
                name: 'System Administrator',
                role: 'admin',
                phone: '9876543210',
                avatar: 'https://via.placeholder.com/150/0088cc/ffffff?text=Admin',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            });
            console.log('✅ Default admin user created');
        }

        // Check if default student exists
        const studentExists = await db.collection('students').findOne({ email: 'student@kv.edu' });
        if (!studentExists) {
            await db.collection('students').insertOne({
                admissionNo: 'KV2023001',
                firstName: 'Aarav',
                lastName: 'Sharma',
                class: '11',
                section: 'A',
                rollNo: 1,
                dob: new Date('2006-05-15'),
                gender: 'Male',
                address: '123 Main Street, City',
                parentName: 'Rajesh Sharma',
                parentContact: '9876543210',
                email: 'student@kv.edu',
                password: 'student123', // Plain text password
                avatar: 'https://via.placeholder.com/150/00aa55/ffffff?text=Student',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            });
            
            // Also create user account
            await db.collection('users').insertOne({
                email: 'student@kv.edu',
                password: 'student123',
                name: 'Aarav Sharma',
                role: 'student',
                avatar: 'https://via.placeholder.com/150/00aa55/ffffff?text=Student',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            });
            console.log('✅ Default student created');
        }

        // Check if default teacher exists
        const teacherExists = await db.collection('teachers').findOne({ email: 'teacher@kv.edu' });
        if (!teacherExists) {
            await db.collection('teachers').insertOne({
                teacherId: 'TCH001',
                name: 'Dr. Rajesh Kumar',
                email: 'teacher@kv.edu',
                subject: 'Mathematics',
                qualification: 'M.Sc, Ph.D',
                experience: '10 years',
                classes: ['11-A', '12-A'],
                contact: '9876543211',
                password: 'teacher123', // Plain text password
                avatar: 'https://via.placeholder.com/150/aa5500/ffffff?text=Teacher',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            });
            
            // Also create user account
            await db.collection('users').insertOne({
                email: 'teacher@kv.edu',
                password: 'teacher123',
                name: 'Dr. Rajesh Kumar',
                role: 'teacher',
                avatar: 'https://via.placeholder.com/150/aa5500/ffffff?text=Teacher',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            });
            console.log('✅ Default teacher created');
        }

        // Check if default parent exists
        const parentExists = await db.collection('parents').findOne({ email: 'parent@example.com' });
        if (!parentExists) {
            await db.collection('parents').insertOne({
                name: 'Rajesh Sharma',
                email: 'parent@example.com',
                password: 'parent123', // Plain text password
                phone: '9876543210',
                occupation: 'Business',
                children: ['student@kv.edu'],
                avatar: 'https://via.placeholder.com/150/5500aa/ffffff?text=Parent',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            });
            
            // Also create user account
            await db.collection('users').insertOne({
                email: 'parent@example.com',
                password: 'parent123',
                name: 'Rajesh Sharma',
                role: 'parent',
                avatar: 'https://via.placeholder.com/150/5500aa/ffffff?text=Parent',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            });
            console.log('✅ Default parent created');
        }

        // Check if default courses exist
        const coursesCount = await db.collection('courses').countDocuments();
        if (coursesCount === 0) {
            const defaultCourses = [
                {
                    courseCode: 'MATH101',
                    title: 'Mathematics - Class 11',
                    description: 'Advanced Mathematics for Class 11 students',
                    subject: 'Mathematics',
                    class: '11',
                    section: 'A',
                    teacher: 'Dr. Rajesh Kumar',
                    teacherEmail: 'teacher@kv.edu',
                    schedule: 'Mon, Wed, Fri - 10:00 AM to 11:00 AM',
                    room: 'Room 101',
                    youtubeUrl: '',
                    isActive: true,
                    createdAt: new Date(),
                    updatedAt: new Date()
                },
                {
                    courseCode: 'PHY101',
                    title: 'Physics - Class 11',
                    description: 'Fundamental Physics concepts',
                    subject: 'Physics',
                    class: '11',
                    section: 'A',
                    teacher: 'Dr. Sunita Verma',
                    teacherEmail: 'physics@kv.edu',
                    schedule: 'Tue, Thu - 11:00 AM to 12:30 PM',
                    room: 'Physics Lab',
                    youtubeUrl: '',
                    isActive: true,
                    createdAt: new Date(),
                    updatedAt: new Date()
                }
            ];
            
            await db.collection('courses').insertMany(defaultCourses);
            console.log('✅ Default courses created');
        }

        console.log('✅ Default data initialization completed');
    } catch (error) {
        console.error('❌ Error initializing data:', error.message);
        logs.unshift({
            timestamp: new Date().toISOString(),
            event: 'Default Data Initialization',
            message: `Error: ${error.message}`,
            status: 'error',
            error: error.message
        });
    }
};

// Start the connection
connectToMongoDB();

// Utility Functions
const calculateGrade = (marks) => {
    if (marks >= 90) return 'A+';
    if (marks >= 85) return 'A';
    if (marks >= 80) return 'A-';
    if (marks >= 75) return 'B+';
    if (marks >= 70) return 'B';
    if (marks >= 65) return 'B-';
    if (marks >= 60) return 'C+';
    if (marks >= 55) return 'C';
    if (marks >= 50) return 'C-';
    if (marks >= 45) return 'D';
    return 'F';
};

// Authentication Middleware
const authenticateUser = async (req, res, next) => {
    try {
        const userEmail = req.headers['x-user-email'];
        const userRole = req.headers['x-user-role'];
        
        if (!userEmail || !userRole) {
            return res.status(401).json({ 
                success: false,
                error: 'Authentication required. Please provide user email and role.' 
            });
        }
        
        // Verify user exists
        const user = await db.collection('users').findOne({ 
            email: userEmail,
            role: userRole,
            isActive: true 
        });
        
        if (!user) {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid credentials or user not found' 
            });
        }
        
        req.user = {
            email: user.email,
            role: user.role,
            name: user.name,
            userId: user._id
        };
        
        next();
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: 'Authentication error: ' + error.message 
        });
    }
};

// Role-based Authorization Middleware
const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                success: false,
                error: 'Authentication required' 
            });
        }
        
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ 
                success: false,
                error: 'Access denied. Insufficient permissions.' 
            });
        }
        
        next();
    };
};

// ===== LOGS ENDPOINT (Password Protected) =====
app.get('/api/logs', async (req, res) => {
    try {
        const { password, limit = 100, filter } = req.query;
        
        // Password protection
        if (password !== LOG_PASSWORD) {
            return res.status(401).json({ 
                success: false,
                error: 'Unauthorized: Invalid password' 
            });
        }
        
        let filteredLogs = [...logs];
        
        // Apply filters if provided
        if (filter) {
            filteredLogs = filteredLogs.filter(log => {
                return JSON.stringify(log).toLowerCase().includes(filter.toLowerCase());
            });
        }
        
        // Limit the number of logs returned
        const limitedLogs = filteredLogs.slice(0, parseInt(limit));
        
        // Get server statistics
        const serverStats = {
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            nodeVersion: process.version,
            platform: process.platform,
            arch: process.arch,
            totalLogs: logs.length,
            database: db ? 'connected' : 'disconnected',
            currentDatabase: dbName,
            timestamp: new Date().toISOString()
        };
        
        res.json({
            success: true,
            logs: limitedLogs,
            statistics: serverStats,
            totalAvailableLogs: logs.length,
            passwordValidated: true,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== HEALTH CHECK =====
app.get('/api/health', (req, res) => {
    const dbStatus = db ? 'connected' : 'disconnected';
    
    const healthData = { 
        success: true,
        status: 'OK', 
        message: 'EduHub School Management System API is running!',
        database: {
            status: dbStatus,
            name: dbName
        },
        deployment: {
            url: process.env.VERCEL_URL || 'http://localhost:' + PORT,
            environment: process.env.NODE_ENV || 'development',
            serverless: true
        },
        logs: {
            totalLogs: logs.length,
            viewLogs: '/api/logs?password=YOUR_PASSWORD',
            password: LOG_PASSWORD
        },
        version: '3.0.0',
        timestamp: new Date().toISOString()
    };
    
    res.json(healthData);
});

// ===== DATABASE MANAGEMENT =====
app.post('/api/switch-database', authenticateUser, authorizeRoles('admin'), async (req, res) => {
    try {
        const { databaseName } = req.body;
        
        if (!databaseName) {
            return res.status(400).json({ 
                success: false,
                error: 'Database name is required' 
            });
        }
        
        // Switch to new database
        dbName = databaseName;
        db = client.db(dbName);
        
        console.log(`🔄 Switched to database: ${dbName}`);
        
        // Initialize collections in the new database
        await initializeCollections();
        
        res.json({
            success: true,
            message: `Successfully switched to database: ${dbName}`,
            database: dbName,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.get('/api/databases', authenticateUser, authorizeRoles('admin'), async (req, res) => {
    try {
        const adminDb = client.db('admin');
        const databases = await adminDb.admin().listDatabases();
        
        res.json({
            success: true,
            databases: databases.databases.map(db => db.name),
            currentDatabase: dbName,
            totalDatabases: databases.databases.length
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== AUTHENTICATION ROUTES =====
app.post('/api/auth/register', async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ 
                success: false,
                error: 'Database not connected. Please try again.' 
            });
        }

        const { email, password, name, role, phone, subject, classes, class: userClass, section, rollNo, parentName, parentContact, avatar } = req.body;

        // Validate required fields
        if (!email || !password || !name || !role) {
            return res.status(400).json({ 
                success: false,
                error: 'Email, password, name, and role are required' 
            });
        }

        // Check if user already exists
        const existingUser = await db.collection('users').findOne({ email });
        if (existingUser) {
            return res.status(400).json({ 
                success: false,
                error: 'User with this email already exists' 
            });
        }

        // Default avatar based on role
        const defaultAvatars = {
            admin: 'https://via.placeholder.com/150/0088cc/ffffff?text=Admin',
            student: 'https://via.placeholder.com/150/00aa55/ffffff?text=Student',
            teacher: 'https://via.placeholder.com/150/aa5500/ffffff?text=Teacher',
            parent: 'https://via.placeholder.com/150/5500aa/ffffff?text=Parent'
        };

        const userData = {
            email,
            password: password, // Plain text password
            name,
            role,
            phone: phone || '',
            avatar: avatar || defaultAvatars[role] || 'https://via.placeholder.com/150/666666/ffffff?text=User',
            isActive: true,
            lastLogin: null,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Add role-specific data
        if (role === 'teacher') {
            userData.subject = subject || '';
            userData.classes = classes || [];
        } else if (role === 'student') {
            userData.class = userClass || '';
            userData.section = section || '';
            userData.rollNo = rollNo || 0;
            userData.parentName = parentName || '';
            userData.parentContact = parentContact || '';
        }

        const result = await db.collection('users').insertOne(userData);
        const user = await db.collection('users').findOne({ _id: result.insertedId });

        // Remove password from response
        const userResponse = {
            _id: user._id,
            email: user.email,
            name: user.name,
            role: user.role,
            phone: user.phone,
            avatar: user.avatar,
            isActive: user.isActive,
            createdAt: user.createdAt
        };

        // Create role-specific record if needed
        if (role === 'student') {
            // Generate admission number
            const year = new Date().getFullYear().toString().slice(-2);
            const lastStudent = await db.collection('students').find().sort({ admissionNo: -1 }).limit(1).toArray();
            let admissionNo;
            
            if (lastStudent.length > 0 && lastStudent[0].admissionNo) {
                const lastNo = parseInt(lastStudent[0].admissionNo.slice(-3));
                admissionNo = `KV${year}${(lastNo + 1).toString().padStart(3, '0')}`;
            } else {
                admissionNo = `KV${year}001`;
            }
            
            const studentData = {
                admissionNo: admissionNo,
                firstName: name.split(' ')[0],
                lastName: name.split(' ').slice(1).join(' ') || '',
                class: userClass || '',
                section: section || '',
                rollNo: rollNo || 0,
                email: email,
                password: password,
                parentName: parentName || '',
                parentContact: parentContact || '',
                avatar: userData.avatar,
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            };
            await db.collection('students').insertOne(studentData);
        } else if (role === 'teacher') {
            // Generate teacher ID
            const lastTeacher = await db.collection('teachers').find().sort({ teacherId: -1 }).limit(1).toArray();
            let teacherId;
            
            if (lastTeacher.length > 0 && lastTeacher[0].teacherId) {
                const lastNo = parseInt(lastTeacher[0].teacherId.slice(-3));
                teacherId = `TCH${(lastNo + 1).toString().padStart(3, '0')}`;
            } else {
                teacherId = 'TCH001';
            }
            
            const teacherData = {
                teacherId: teacherId,
                name: name,
                email: email,
                subject: subject || '',
                qualification: '',
                experience: '',
                classes: classes || [],
                contact: phone || '',
                password: password,
                avatar: userData.avatar,
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            };
            await db.collection('teachers').insertOne(teacherData);
        } else if (role === 'parent') {
            const parentData = {
                name: name,
                email: email,
                password: password,
                phone: phone || '',
                occupation: '',
                children: [],
                avatar: userData.avatar,
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date()
            };
            await db.collection('parents').insertOne(parentData);
        }

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: userResponse,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ 
                success: false,
                error: 'Database not connected. Please try again.' 
            });
        }

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false,
                error: 'Email and password are required' 
            });
        }

        // Find user in users collection
        let user = await db.collection('users').findOne({ email, isActive: true });
        
        if (!user) {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid credentials or account not active' 
            });
        }

        // Verify password (plain text comparison)
        if (password !== user.password) {
            return res.status(401).json({ 
                success: false,
                error: 'Invalid credentials' 
            });
        }

        // Update last login
        await db.collection('users').updateOne(
            { email },
            { $set: { lastLogin: new Date() } }
        );

        // Get additional user data based on role
        let userData = { ...user };
        
        if (user.role === 'student') {
            const student = await db.collection('students').findOne({ email });
            if (student) {
                // Merge student data
                userData.admissionNo = student.admissionNo;
                userData.firstName = student.firstName;
                userData.lastName = student.lastName;
                userData.class = student.class;
                userData.section = student.section;
                userData.rollNo = student.rollNo;
                userData.parentName = student.parentName;
                userData.parentContact = student.parentContact;
            }
        } else if (user.role === 'teacher') {
            const teacher = await db.collection('teachers').findOne({ email });
            if (teacher) {
                // Merge teacher data
                userData.teacherId = teacher.teacherId;
                userData.subject = teacher.subject;
                userData.qualification = teacher.qualification;
                userData.experience = teacher.experience;
                userData.classes = teacher.classes;
                userData.contact = teacher.contact;
            }
        } else if (user.role === 'parent') {
            const parent = await db.collection('parents').findOne({ email });
            if (parent) {
                // Merge parent data
                userData.occupation = parent.occupation;
                userData.children = parent.children;
            }
        }

        // Remove password from response
        const userResponse = {
            _id: userData._id,
            email: userData.email,
            name: userData.name,
            role: userData.role,
            phone: userData.phone,
            avatar: userData.avatar,
            isActive: userData.isActive,
            lastLogin: userData.lastLogin,
            createdAt: userData.createdAt,
            // Role-specific fields
            admissionNo: userData.admissionNo,
            firstName: userData.firstName,
            lastName: userData.lastName,
            class: userData.class,
            section: userData.section,
            rollNo: userData.rollNo,
            parentName: userData.parentName,
            parentContact: userData.parentContact,
            teacherId: userData.teacherId,
            subject: userData.subject,
            qualification: userData.qualification,
            experience: userData.experience,
            classes: userData.classes,
            occupation: userData.occupation,
            children: userData.children
        };

        res.json({
            success: true,
            message: 'Login successful',
            user: userResponse,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/auth/change-password', authenticateUser, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userEmail = req.user.email;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ 
                success: false,
                error: 'Current password and new password are required' 
            });
        }

        // Find user
        const user = await db.collection('users').findOne({ email: userEmail });
        if (!user) {
            return res.status(404).json({ 
                success: false,
                error: 'User not found' 
            });
        }

        // Verify current password
        if (currentPassword !== user.password) {
            return res.status(401).json({ 
                success: false,
                error: 'Current password is incorrect' 
            });
        }

        // Update password in users collection
        await db.collection('users').updateOne(
            { email: userEmail },
            { $set: { password: newPassword, updatedAt: new Date() } }
        );

        // Update password in role-specific collection if exists
        if (req.user.role === 'student') {
            await db.collection('students').updateOne(
                { email: userEmail },
                { $set: { password: newPassword, updatedAt: new Date() } }
            );
        } else if (req.user.role === 'teacher') {
            await db.collection('teachers').updateOne(
                { email: userEmail },
                { $set: { password: newPassword, updatedAt: new Date() } }
            );
        } else if (req.user.role === 'parent') {
            await db.collection('parents').updateOne(
                { email: userEmail },
                { $set: { password: newPassword, updatedAt: new Date() } }
            );
        }

        res.json({
            success: true,
            message: 'Password changed successfully',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== USER MANAGEMENT =====
app.get('/api/users', authenticateUser, authorizeRoles('admin'), async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ 
                success: false,
                error: 'Database not connected' 
            });
        }
        
        const users = await db.collection('users').find().toArray();
        
        // Remove passwords from response
        const usersWithoutPasswords = users.map(user => {
            return {
                _id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                phone: user.phone,
                avatar: user.avatar,
                isActive: user.isActive,
                lastLogin: user.lastLogin,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt
            };
        });
        
        res.json({
            success: true,
            users: usersWithoutPasswords,
            total: users.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.get('/api/users/:email', authenticateUser, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ 
                success: false,
                error: 'Database not connected' 
            });
        }
        
        const user = await db.collection('users').findOne({ email: req.params.email });
        
        if (!user) {
            return res.status(404).json({ 
                success: false,
                error: 'User not found' 
            });
        }
        
        // Check if requesting user has permission
        if (req.user.role !== 'admin' && req.user.email !== req.params.email) {
            return res.status(403).json({ 
                success: false,
                error: 'Access denied' 
            });
        }
        
        // Remove password from response
        const userResponse = {
            _id: user._id,
            email: user.email,
            name: user.name,
            role: user.role,
            phone: user.phone,
            avatar: user.avatar,
            isActive: user.isActive,
            lastLogin: user.lastLogin,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        };
        
        res.json({
            success: true,
            user: userResponse,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Update user avatar/profile image
app.put('/api/users/:email/avatar', authenticateUser, async (req, res) => {
    try {
        const { avatar } = req.body;
        
        if (!avatar) {
            return res.status(400).json({ 
                success: false,
                error: 'Avatar URL is required' 
            });
        }
        
        // Check permissions
        if (req.user.role !== 'admin' && req.user.email !== req.params.email) {
            return res.status(403).json({ 
                success: false,
                error: 'Access denied' 
            });
        }
        
        // Update user avatar
        await db.collection('users').updateOne(
            { email: req.params.email },
            { $set: { avatar: avatar, updatedAt: new Date() } }
        );
        
        // Update role-specific collection if exists
        if (req.user.role === 'student') {
            await db.collection('students').updateOne(
                { email: req.params.email },
                { $set: { avatar: avatar, updatedAt: new Date() } }
            );
        } else if (req.user.role === 'teacher') {
            await db.collection('teachers').updateOne(
                { email: req.params.email },
                { $set: { avatar: avatar, updatedAt: new Date() } }
            );
        } else if (req.user.role === 'parent') {
            await db.collection('parents').updateOne(
                { email: req.params.email },
                { $set: { avatar: avatar, updatedAt: new Date() } }
            );
        }
        
        res.json({
            success: true,
            message: 'Avatar updated successfully',
            avatar: avatar,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== STUDENT ROUTES =====
app.get('/api/students', authenticateUser, authorizeRoles('admin', 'teacher'), async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ 
                success: false,
                error: 'Database not connected' 
            });
        }
        
        const students = await db.collection('students').find().toArray();
        
        // Remove passwords from response
        const studentsWithoutPasswords = students.map(student => {
            return {
                _id: student._id,
                admissionNo: student.admissionNo,
                firstName: student.firstName,
                lastName: student.lastName,
                class: student.class,
                section: student.section,
                rollNo: student.rollNo,
                dob: student.dob,
                gender: student.gender,
                address: student.address,
                parentName: student.parentName,
                parentContact: student.parentContact,
                email: student.email,
                avatar: student.avatar,
                isActive: student.isActive,
                createdAt: student.createdAt,
                updatedAt: student.updatedAt
            };
        });
        
        res.json({
            success: true,
            students: studentsWithoutPasswords,
            total: students.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/students', authenticateUser, authorizeRoles('admin'), async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ 
                success: false,
                error: 'Database not connected' 
            });
        }

        const { 
            firstName, lastName, class: studentClass, section, rollNo, 
            email, parentName, parentContact, avatar
        } = req.body;

        // Validate required fields
        if (!firstName || !lastName || !studentClass || !section || !email) {
            return res.status(400).json({ 
                success: false,
                error: 'First name, last name, class, section, and email are required' 
            });
        }

        // Check if student already exists
        const existingStudent = await db.collection('students').findOne({ email });
        if (existingStudent) {
            return res.status(400).json({ 
                success: false,
                error: 'Student with this email already exists' 
            });
        }

        // Generate admission number
        const year = new Date().getFullYear().toString().slice(-2);
        const lastStudent = await db.collection('students').find().sort({ admissionNo: -1 }).limit(1).toArray();
        let admissionNo;
        
        if (lastStudent.length > 0 && lastStudent[0].admissionNo) {
            const lastNo = parseInt(lastStudent[0].admissionNo.slice(-3));
            admissionNo = `KV${year}${(lastNo + 1).toString().padStart(3, '0')}`;
        } else {
            admissionNo = `KV${year}001`;
        }

        // Default avatar
        const defaultAvatar = 'https://via.placeholder.com/150/00aa55/ffffff?text=Student';

        // Prepare student data
        const studentData = {
            admissionNo: admissionNo,
            firstName: firstName,
            lastName: lastName,
            class: studentClass,
            section: section,
            rollNo: parseInt(rollNo) || 0,
            email: email,
            password: 'student123', // Default password
            parentName: parentName || '',
            parentContact: parentContact || '',
            avatar: avatar || defaultAvatar,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert student
        const result = await db.collection('students').insertOne(studentData);
        const student = await db.collection('students').findOne({ _id: result.insertedId });

        // Also create user account
        await db.collection('users').insertOne({
            email: email,
            password: 'student123',
            name: firstName + ' ' + lastName,
            role: 'student',
            class: studentClass,
            section: section,
            rollNo: rollNo || 0,
            admissionNo: admissionNo,
            parentName: parentName || '',
            parentContact: parentContact || '',
            avatar: avatar || defaultAvatar,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        });

        // Remove password from response
        const studentResponse = {
            _id: student._id,
            admissionNo: student.admissionNo,
            firstName: student.firstName,
            lastName: student.lastName,
            class: student.class,
            section: student.section,
            rollNo: student.rollNo,
            email: student.email,
            parentName: student.parentName,
            parentContact: student.parentContact,
            avatar: student.avatar,
            isActive: student.isActive,
            createdAt: student.createdAt
        };

        res.status(201).json({ 
            success: true,
            message: 'Student created successfully', 
            student: studentResponse,
            defaultPassword: 'student123',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.get('/api/students/:email', authenticateUser, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ 
                success: false,
                error: 'Database not connected' 
            });
        }
        
        const student = await db.collection('students').findOne({ email: req.params.email });
        
        if (!student) {
            return res.status(404).json({ 
                success: false,
                error: 'Student not found' 
            });
        }
        
        // Check if requesting user has permission
        if (req.user.role !== 'admin' && req.user.role !== 'teacher' && req.user.email !== req.params.email) {
            return res.status(403).json({ 
                success: false,
                error: 'Access denied' 
            });
        }
        
        // Remove password from response
        const studentResponse = {
            _id: student._id,
            admissionNo: student.admissionNo,
            firstName: student.firstName,
            lastName: student.lastName,
            class: student.class,
            section: student.section,
            rollNo: student.rollNo,
            email: student.email,
            parentName: student.parentName,
            parentContact: student.parentContact,
            avatar: student.avatar,
            isActive: student.isActive,
            createdAt: student.createdAt,
            updatedAt: student.updatedAt
        };
        
        res.json({
            success: true,
            student: studentResponse,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.put('/api/students/:email', authenticateUser, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ 
                success: false,
                error: 'Database not connected' 
            });
        }

        // Check permissions
        if (req.user.role !== 'admin' && req.user.email !== req.params.email) {
            return res.status(403).json({ 
                success: false,
                error: 'Access denied' 
            });
        }

        const updateData = { ...req.body };
        
        // Don't allow updating email, password, or admissionNo
        delete updateData.email;
        delete updateData.password;
        delete updateData.admissionNo;
        
        // Convert rollNo to number if provided
        if (updateData.rollNo) {
            updateData.rollNo = parseInt(updateData.rollNo);
        }
        
        updateData.updatedAt = new Date();

        const result = await db.collection('students').updateOne(
            { email: req.params.email },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ 
                success: false,
                error: 'Student not found' 
            });
        }

        // Update user account
        const userUpdate = {
            name: updateData.firstName && updateData.lastName ? 
                updateData.firstName + ' ' + updateData.lastName : undefined,
            class: updateData.class,
            section: updateData.section,
            rollNo: updateData.rollNo,
            parentName: updateData.parentName,
            parentContact: updateData.parentContact,
            avatar: updateData.avatar,
            updatedAt: new Date()
        };
        
        // Remove undefined fields
        Object.keys(userUpdate).forEach(key => {
            if (userUpdate[key] === undefined) {
                delete userUpdate[key];
            }
        });
        
        await db.collection('users').updateOne(
            { email: req.params.email },
            { $set: userUpdate }
        );

        res.json({
            success: true,
            message: 'Student updated successfully',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Get students by class and section
app.get('/api/students/class/:class/section/:section', authenticateUser, async (req, res) => {
    try {
        const students = await db.collection('students')
            .find({ 
                class: req.params.class,
                section: req.params.section,
                isActive: true 
            })
            .sort({ rollNo: 1 })
            .toArray();
        
        // Remove passwords from response
        const studentsWithoutPasswords = students.map(student => {
            return {
                _id: student._id,
                admissionNo: student.admissionNo,
                firstName: student.firstName,
                lastName: student.lastName,
                class: student.class,
                section: student.section,
                rollNo: student.rollNo,
                email: student.email,
                avatar: student.avatar
            };
        });
        
        res.json({
            success: true,
            students: studentsWithoutPasswords,
            count: students.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== TEACHER ROUTES =====
app.get('/api/teachers', authenticateUser, async (req, res) => {
    try {
        const teachers = await db.collection('teachers').find({ isActive: true }).toArray();
        
        // Remove passwords from response
        const teachersWithoutPasswords = teachers.map(teacher => {
            return {
                _id: teacher._id,
                teacherId: teacher.teacherId,
                name: teacher.name,
                email: teacher.email,
                subject: teacher.subject,
                qualification: teacher.qualification,
                experience: teacher.experience,
                classes: teacher.classes,
                contact: teacher.contact,
                avatar: teacher.avatar,
                isActive: teacher.isActive,
                createdAt: teacher.createdAt,
                updatedAt: teacher.updatedAt
            };
        });
        
        res.json({
            success: true,
            teachers: teachersWithoutPasswords,
            total: teachers.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/teachers', authenticateUser, authorizeRoles('admin'), async (req, res) => {
    try {
        const { 
            name, email, subject, classes, contact, avatar
        } = req.body;

        // Validate required fields
        if (!name || !email || !subject) {
            return res.status(400).json({ 
                success: false,
                error: 'Name, email, and subject are required' 
            });
        }

        // Check if teacher already exists
        const existingTeacher = await db.collection('teachers').findOne({ email });
        if (existingTeacher) {
            return res.status(400).json({ 
                success: false,
                error: 'Teacher with this email already exists' 
            });
        }

        // Generate teacher ID
        const lastTeacher = await db.collection('teachers').find().sort({ teacherId: -1 }).limit(1).toArray();
        let teacherId;
        
        if (lastTeacher.length > 0 && lastTeacher[0].teacherId) {
            const lastNo = parseInt(lastTeacher[0].teacherId.slice(-3));
            teacherId = `TCH${(lastNo + 1).toString().padStart(3, '0')}`;
        } else {
            teacherId = 'TCH001';
        }

        // Default avatar
        const defaultAvatar = 'https://via.placeholder.com/150/aa5500/ffffff?text=Teacher';

        // Prepare teacher data
        const teacherData = {
            teacherId: teacherId,
            name: name,
            email: email,
            subject: subject,
            qualification: '',
            experience: '',
            classes: classes || [],
            contact: contact || '',
            password: 'teacher123', // Default password
            avatar: avatar || defaultAvatar,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert teacher
        const result = await db.collection('teachers').insertOne(teacherData);
        const teacher = await db.collection('teachers').findOne({ _id: result.insertedId });

        // Also create user account
        await db.collection('users').insertOne({
            email: email,
            password: 'teacher123',
            name: name,
            role: 'teacher',
            subject: subject,
            classes: classes || [],
            contact: contact || '',
            avatar: avatar || defaultAvatar,
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        });

        // Remove password from response
        const teacherResponse = {
            _id: teacher._id,
            teacherId: teacher.teacherId,
            name: teacher.name,
            email: teacher.email,
            subject: teacher.subject,
            qualification: teacher.qualification,
            experience: teacher.experience,
            classes: teacher.classes,
            contact: teacher.contact,
            avatar: teacher.avatar,
            isActive: teacher.isActive,
            createdAt: teacher.createdAt
        };

        res.status(201).json({ 
            success: true,
            message: 'Teacher created successfully', 
            teacher: teacherResponse,
            defaultPassword: 'teacher123',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.get('/api/teachers/:email', authenticateUser, async (req, res) => {
    try {
        const teacher = await db.collection('teachers').findOne({ email: req.params.email });
        
        if (!teacher) {
            return res.status(404).json({ 
                success: false,
                error: 'Teacher not found' 
            });
        }
        
        // Check if requesting user has permission
        if (req.user.role !== 'admin' && req.user.email !== req.params.email) {
            return res.status(403).json({ 
                success: false,
                error: 'Access denied' 
            });
        }
        
        // Remove password from response
        const teacherResponse = {
            _id: teacher._id,
            teacherId: teacher.teacherId,
            name: teacher.name,
            email: teacher.email,
            subject: teacher.subject,
            qualification: teacher.qualification,
            experience: teacher.experience,
            classes: teacher.classes,
            contact: teacher.contact,
            avatar: teacher.avatar,
            isActive: teacher.isActive,
            createdAt: teacher.createdAt,
            updatedAt: teacher.updatedAt
        };
        
        res.json({
            success: true,
            teacher: teacherResponse,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== COURSE ROUTES =====
app.get('/api/courses', authenticateUser, async (req, res) => {
    try {
        const courses = await db.collection('courses').find({ isActive: true }).toArray();
        
        res.json({
            success: true,
            courses: courses,
            total: courses.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/courses', authenticateUser, authorizeRoles('admin', 'teacher'), async (req, res) => {
    try {
        const { 
            courseCode, title, description, subject, class: courseClass, 
            section, teacher, teacherEmail, schedule, room, youtubeUrl 
        } = req.body;

        // Validate required fields
        if (!courseCode || !title || !subject || !courseClass) {
            return res.status(400).json({ 
                success: false,
                error: 'Course code, title, subject, and class are required' 
            });
        }

        // Check if course already exists
        const existingCourse = await db.collection('courses').findOne({ courseCode });
        if (existingCourse) {
            return res.status(400).json({ 
                success: false,
                error: 'Course with this code already exists' 
            });
        }

        // Prepare course data
        const courseData = {
            courseCode: courseCode,
            title: title,
            description: description || '',
            subject: subject,
            class: courseClass,
            section: section || 'A',
            teacher: teacher || '',
            teacherEmail: teacherEmail || req.user.email,
            schedule: schedule || '',
            room: room || '',
            youtubeUrl: youtubeUrl || '',
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert course
        const result = await db.collection('courses').insertOne(courseData);
        const course = await db.collection('courses').findOne({ _id: result.insertedId });

        res.status(201).json({
            success: true,
            message: 'Course created successfully',
            course: course,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.get('/api/courses/:id', authenticateUser, async (req, res) => {
    try {
        const course = await db.collection('courses').findOne({ 
            _id: new ObjectId(req.params.id) 
        });
        
        if (!course) {
            return res.status(404).json({ 
                success: false,
                error: 'Course not found' 
            });
        }
        
        res.json({
            success: true,
            course: course,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Get courses by class
app.get('/api/courses/class/:class', authenticateUser, async (req, res) => {
    try {
        let query = { 
            class: req.params.class,
            isActive: true 
        };
        
        // If section is provided in query
        if (req.query.section) {
            query.section = req.query.section;
        }
        
        const courses = await db.collection('courses').find(query).toArray();
        
        res.json({
            success: true,
            courses: courses,
            count: courses.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== ATTENDANCE ROUTES =====
app.get('/api/attendance', authenticateUser, async (req, res) => {
    try {
        const attendance = await db.collection('attendance').find().toArray();
        
        res.json({
            success: true,
            attendance: attendance,
            total: attendance.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/attendance', authenticateUser, authorizeRoles('teacher', 'admin'), async (req, res) => {
    try {
        const { date, class: attendanceClass, section, subject, students } = req.body;

        // Validate required fields
        if (!date || !attendanceClass || !section || !subject || !students || !Array.isArray(students)) {
            return res.status(400).json({ 
                success: false,
                error: 'Date, class, section, subject, and students array are required' 
            });
        }

        // Prepare attendance data
        const attendanceData = {
            date: new Date(date),
            class: attendanceClass,
            section: section,
            subject: subject,
            teacherEmail: req.user.email,
            students: students,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert attendance
        const result = await db.collection('attendance').insertOne(attendanceData);
        const attendance = await db.collection('attendance').findOne({ _id: result.insertedId });

        res.status(201).json({
            success: true,
            message: 'Attendance recorded successfully',
            attendance: attendance,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Get attendance by class and date
app.get('/api/attendance/class/:class/date/:date', authenticateUser, async (req, res) => {
    try {
        const dateObj = new Date(req.params.date);
        const startOfDay = new Date(dateObj.setHours(0, 0, 0, 0));
        const endOfDay = new Date(dateObj.setHours(23, 59, 59, 999));
        
        const attendance = await db.collection('attendance').find({
            class: req.params.class,
            date: { $gte: startOfDay, $lte: endOfDay }
        }).toArray();
        
        res.json({
            success: true,
            attendance: attendance,
            count: attendance.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Get attendance for a specific student
app.get('/api/attendance/student/:email', authenticateUser, async (req, res) => {
    try {
        const attendance = await db.collection('attendance').find({
            'students.email': req.params.email
        }).toArray();
        
        res.json({
            success: true,
            attendance: attendance,
            count: attendance.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== RESULTS ROUTES =====
app.get('/api/results', authenticateUser, async (req, res) => {
    try {
        const results = await db.collection('results').find().toArray();
        
        res.json({
            success: true,
            results: results,
            total: results.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/results', authenticateUser, authorizeRoles('teacher', 'admin'), async (req, res) => {
    try {
        const { studentEmail, examType, subject, marks, totalMarks, class: resultClass, driveLink } = req.body;

        // Validate required fields
        if (!studentEmail || !examType || !subject || !marks || !totalMarks || !resultClass) {
            return res.status(400).json({ 
                success: false,
                error: 'Student email, exam type, subject, marks, total marks, and class are required' 
            });
        }

        // Calculate grade
        const percentage = (marks / totalMarks) * 100;
        const grade = calculateGrade(percentage);

        // Prepare result data
        const resultData = {
            studentEmail: studentEmail,
            examType: examType,
            subject: subject,
            marks: parseFloat(marks),
            totalMarks: parseFloat(totalMarks),
            percentage: Math.round(percentage * 100) / 100,
            grade: grade,
            class: resultClass,
            driveLink: driveLink || '',
            createdBy: req.user.email,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert result
        const result = await db.collection('results').insertOne(resultData);
        const newResult = await db.collection('results').findOne({ _id: result.insertedId });

        res.status(201).json({
            success: true,
            message: 'Result saved successfully',
            result: newResult,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Get results by student email
app.get('/api/results/student/:email', authenticateUser, async (req, res) => {
    try {
        const results = await db.collection('results').find({
            studentEmail: req.params.email
        }).toArray();
        
        res.json({
            success: true,
            results: results,
            count: results.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== ANNOUNCEMENT ROUTES =====
app.get('/api/announcements', authenticateUser, async (req, res) => {
    try {
        const announcements = await db.collection('announcements').find().toArray();
        
        res.json({
            success: true,
            announcements: announcements,
            total: announcements.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/announcements', authenticateUser, authorizeRoles('admin', 'teacher'), async (req, res) => {
    try {
        const { title, content, audience, priority } = req.body;

        // Validate required fields
        if (!title || !content || !audience) {
            return res.status(400).json({ 
                success: false,
                error: 'Title, content, and audience are required' 
            });
        }

        // Prepare announcement data
        const announcementData = {
            title: title,
            content: content,
            audience: audience,
            priority: priority || 'medium',
            createdBy: req.user.email,
            createdByName: req.user.name,
            date: new Date(),
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert announcement
        const result = await db.collection('announcements').insertOne(announcementData);
        const announcement = await db.collection('announcements').findOne({ _id: result.insertedId });

        res.status(201).json({
            success: true,
            message: 'Announcement created successfully',
            announcement: announcement,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== RESOURCE ROUTES =====
app.get('/api/resources', authenticateUser, async (req, res) => {
    try {
        const resources = await db.collection('resources').find().toArray();
        
        res.json({
            success: true,
            resources: resources,
            total: resources.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/resources', authenticateUser, async (req, res) => {
    try {
        const { type, title, content, subject, class: resourceClass, fileUrl } = req.body;

        // Prepare resource data
        const resourceData = {
            type: type,
            title: title,
            content: content,
            subject: subject,
            class: resourceClass,
            fileUrl: fileUrl || '',
            createdBy: req.user.email,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert resource
        const result = await db.collection('resources').insertOne(resourceData);
        const resource = await db.collection('resources').findOne({ _id: result.insertedId });

        res.status(201).json({
            success: true,
            message: 'Resource created successfully',
            resource: resource,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== FLASHCARD ROUTES =====
app.get('/api/flashcards', authenticateUser, async (req, res) => {
    try {
        const flashcards = await db.collection('flashcards').find({ createdBy: req.user.email }).toArray();
        
        res.json({
            success: true,
            flashcards: flashcards,
            total: flashcards.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/flashcards', authenticateUser, async (req, res) => {
    try {
        const { question, answer } = req.body;

        // Prepare flashcard data
        const flashcardData = {
            question: question,
            answer: answer,
            createdBy: req.user.email,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert flashcard
        const result = await db.collection('flashcards').insertOne(flashcardData);
        const flashcard = await db.collection('flashcards').findOne({ _id: result.insertedId });

        res.status(201).json({
            success: true,
            message: 'Flashcard created successfully',
            flashcard: flashcard,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== NOTE ROUTES =====
app.get('/api/notes', authenticateUser, async (req, res) => {
    try {
        const notes = await db.collection('notes').find({ createdBy: req.user.email }).toArray();
        
        res.json({
            success: true,
            notes: notes,
            total: notes.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/notes', authenticateUser, async (req, res) => {
    try {
        const { content } = req.body;

        // Prepare note data
        const noteData = {
            content: content,
            createdBy: req.user.email,
            date: new Date(),
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert note
        const result = await db.collection('notes').insertOne(noteData);
        const note = await db.collection('notes').findOne({ _id: result.insertedId });

        res.status(201).json({
            success: true,
            message: 'Note created successfully',
            note: note,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.delete('/api/notes/:id', authenticateUser, async (req, res) => {
    try {
        await db.collection('notes').deleteOne({ 
            _id: new ObjectId(req.params.id), 
            createdBy: req.user.email 
        });
        
        res.json({
            success: true,
            message: 'Note deleted successfully',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== STUDY TIME ROUTES =====
app.get('/api/study-times', authenticateUser, async (req, res) => {
    try {
        const studyTimes = await db.collection('studytimes').find({ userId: req.user.email }).toArray();
        
        res.json({
            success: true,
            studyTimes: studyTimes,
            total: studyTimes.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/study-times', authenticateUser, async (req, res) => {
    try {
        const { minutes } = req.body;

        // Prepare study time data
        const studyTimeData = {
            userId: req.user.email,
            minutes: parseInt(minutes) || 0,
            date: new Date(),
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert study time
        const result = await db.collection('studytimes').insertOne(studyTimeData);
        const studyTime = await db.collection('studytimes').findOne({ _id: result.insertedId });

        res.status(201).json({
            success: true,
            message: 'Study time updated successfully',
            studyTime: studyTime,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== VIDEO ROUTES =====
app.get('/api/videos', authenticateUser, async (req, res) => {
    try {
        const videos = await db.collection('videos').find().toArray();
        
        res.json({
            success: true,
            videos: videos,
            total: videos.length,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

app.post('/api/videos', authenticateUser, async (req, res) => {
    try {
        const { courseId, title, description, youtubeId, order } = req.body;

        // Prepare video data
        const videoData = {
            courseId: courseId,
            title: title,
            description: description,
            youtubeId: youtubeId,
            order: parseInt(order) || 0,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Insert video
        const result = await db.collection('videos').insertOne(videoData);
        const video = await db.collection('videos').findOne({ _id: result.insertedId });

        res.status(201).json({
            success: true,
            message: 'Video added successfully',
            video: video,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== FILE URL UPLOAD ENDPOINT =====
app.post('/api/upload-url', authenticateUser, async (req, res) => {
    try {
        const { url, fileName, fileType, fileSize } = req.body;

        if (!url) {
            return res.status(400).json({ 
                success: false,
                error: 'File URL is required' 
            });
        }

        const fileInfo = {
            url: url,
            fileName: fileName || url.split('/').pop(),
            fileType: fileType || 'unknown',
            fileSize: fileSize || 0,
            uploadedBy: req.user.email,
            uploadedAt: new Date(),
            uploadedByName: req.user.name
        };

        res.json({
            success: true,
            message: 'File URL saved successfully',
            file: fileInfo,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== DASHBOARD STATS =====
app.get('/api/dashboard/stats', authenticateUser, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ 
                success: false,
                error: 'Database not connected' 
            });
        }

        const today = new Date();
        const startOfDay = new Date(today.setHours(0, 0, 0, 0));
        const endOfDay = new Date(today.setHours(23, 59, 59, 999));
        
        let stats = {
            role: req.user.role,
            name: req.user.name,
            email: req.user.email,
            today: today.toISOString().split('T')[0]
        };
        
        if (req.user.role === 'admin') {
            // Admin dashboard stats
            const totalStudents = await db.collection('students').countDocuments({ isActive: true });
            const totalTeachers = await db.collection('teachers').countDocuments({ isActive: true });
            const totalCourses = await db.collection('courses').countDocuments({ isActive: true });
            const totalAnnouncements = await db.collection('announcements').countDocuments({ isActive: true });
            
            // Today's attendance
            const todaysAttendance = await db.collection('attendance').find({
                date: { $gte: startOfDay, $lte: endOfDay }
            }).toArray();
            
            let presentCount = 0;
            let totalCount = 0;
            
            todaysAttendance.forEach(att => {
                att.students.forEach(student => {
                    totalCount++;
                    if (student.status === 'present') {
                        presentCount++;
                    }
                });
            });
            
            const attendanceRate = totalCount > 0 ? Math.round((presentCount / totalCount) * 100) : 0;
            
            stats.totalStudents = totalStudents;
            stats.totalTeachers = totalTeachers;
            stats.totalCourses = totalCourses;
            stats.totalAnnouncements = totalAnnouncements;
            stats.todaysAttendance = {
                present: presentCount,
                total: totalCount,
                rate: attendanceRate + '%'
            };
            stats.pendingTasks = Math.floor(Math.random() * 20) + 5;
            stats.activeUsers = Math.floor(Math.random() * 50) + 10;
            
        } else if (req.user.role === 'teacher') {
            // Teacher dashboard stats
            const teacher = await db.collection('teachers').findOne({ email: req.user.email });
            if (teacher) {
                stats.subject = teacher.subject;
                stats.classes = teacher.classes;
                stats.teacherId = teacher.teacherId;
            }
            
            // Count students in teacher's classes
            const totalStudents = await db.collection('students').countDocuments({
                class: { $in: teacher.classes ? teacher.classes.map(cls => cls.split('-')[0]) : [] }
            });
            
            // Count courses taught by teacher
            const courses = await db.collection('courses').find({ teacherEmail: req.user.email }).toArray();
            stats.totalCourses = courses.length;
            
            // Count today's attendance
            const todaysAttendance = await db.collection('attendance').countDocuments({
                date: { $gte: startOfDay, $lte: endOfDay },
                teacherEmail: req.user.email
            });
            
            stats.totalStudents = totalStudents;
            stats.todaysAttendance = todaysAttendance;
            
        } else if (req.user.role === 'student') {
            // Student dashboard stats
            const student = await db.collection('students').findOne({ email: req.user.email });
            if (student) {
                stats.class = student.class + '-' + student.section;
                stats.rollNo = student.rollNo;
                stats.admissionNo = student.admissionNo;
            }
            
            // Get student's courses
            const courses = await db.collection('courses').find({
                class: student ? student.class : '',
                section: student ? student.section : '',
                isActive: true
            }).toArray();
            
            stats.totalCourses = courses.length;
            
            // Today's attendance
            const todaysAttendance = await db.collection('attendance').find({
                date: { $gte: startOfDay, $lte: endOfDay },
                'students.email': req.user.email
            }).toArray();
            
            let attendanceStatus = 'Not marked';
            if (todaysAttendance.length > 0) {
                const studentRecord = todaysAttendance[0].students.find(s => s.email === req.user.email);
                attendanceStatus = studentRecord ? studentRecord.status : 'Not marked';
            }
            
            stats.todaysAttendance = attendanceStatus;
            
            // Pending assignments
            const pendingAssignments = await db.collection('assignments')
                .find({
                    class: student ? student.class : '',
                    section: student ? student.section : '',
                    dueDate: { $gte: today }
                })
                .toArray();
            
            stats.pendingAssignments = pendingAssignments.length;
            
        } else if (req.user.role === 'parent') {
            // Parent dashboard stats
            const parent = await db.collection('parents').findOne({ email: req.user.email });
            if (parent) {
                stats.children = parent.children || [];
            }
            
            // Get children details
            const children = await db.collection('students')
                .find({ email: { $in: parent ? parent.children : [] } })
                .toArray();
            
            stats.totalChildren = children.length;
        }
        
        res.json({
            success: true,
            stats: stats,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== SEARCH ENDPOINTS =====
app.get('/api/search/:query', authenticateUser, async (req, res) => {
    try {
        const query = req.params.query;
        
        const searchResults = {
            students: [],
            teachers: [],
            courses: [],
            announcements: []
        };

        // Search students
        searchResults.students = await db.collection('students').find({
            $or: [
                { firstName: { $regex: query, $options: 'i' } },
                { lastName: { $regex: query, $options: 'i' } },
                { email: { $regex: query, $options: 'i' } },
                { admissionNo: { $regex: query, $options: 'i' } }
            ]
        }).limit(10).toArray();

        // Remove passwords
        searchResults.students = searchResults.students.map(student => {
            return {
                _id: student._id,
                admissionNo: student.admissionNo,
                firstName: student.firstName,
                lastName: student.lastName,
                class: student.class,
                section: student.section,
                rollNo: student.rollNo,
                email: student.email,
                avatar: student.avatar
            };
        });

        // Search teachers
        searchResults.teachers = await db.collection('teachers').find({
            $or: [
                { name: { $regex: query, $options: 'i' } },
                { email: { $regex: query, $options: 'i' } },
                { teacherId: { $regex: query, $options: 'i' } },
                { subject: { $regex: query, $options: 'i' } }
            ]
        }).limit(10).toArray();

        // Remove passwords
        searchResults.teachers = searchResults.teachers.map(teacher => {
            return {
                _id: teacher._id,
                teacherId: teacher.teacherId,
                name: teacher.name,
                email: teacher.email,
                subject: teacher.subject,
                avatar: teacher.avatar
            };
        });

        // Search courses
        searchResults.courses = await db.collection('courses').find({
            $or: [
                { title: { $regex: query, $options: 'i' } },
                { courseCode: { $regex: query, $options: 'i' } },
                { subject: { $regex: query, $options: 'i' } },
                { teacher: { $regex: query, $options: 'i' } }
            ]
        }).limit(10).toArray();

        // Search announcements
        searchResults.announcements = await db.collection('announcements').find({
            $or: [
                { title: { $regex: query, $options: 'i' } },
                { content: { $regex: query, $options: 'i' } }
            ]
        }).limit(10).toArray();

        res.json({
            success: true,
            query: query,
            results: searchResults,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// ===== ROOT ENDPOINT =====
app.get('/', (req, res) => {
    const dbStatus = db ? 'connected' : 'disconnected';
    
    res.json({ 
        success: true,
        message: 'EduHub School Management System API',
        version: '3.0.0',
        status: 'operational',
        deployment: {
            url: process.env.VERCEL_URL || 'http://localhost:' + PORT,
            database: dbStatus,
            currentDatabase: dbName,
            serverless: true
        },
        features: [
            'Complete school management system (Serverless)',
            'Role-based access control (Admin, Teacher, Student, Parent)',
            'Student information management',
            'Teacher management',
            'Course and subject management',
            'Attendance tracking',
            'Result management',
            'Announcement system',
            'Study tools (flashcards, notes, study times)',
            'Video management',
            'URL-based file uploads',
            'Advanced logging system',
            'Dashboard with statistics',
            'Search functionality',
            'Vercel Serverless Ready'
        ],
        important_endpoints: {
            health_check: 'GET /api/health',
            logs: 'GET /api/logs?password=bunny',
            auth_register: 'POST /api/auth/register',
            auth_login: 'POST /api/auth/login',
            upload_file_url: 'POST /api/upload-url (authenticated)'
        },
        default_credentials: {
            admin: 'admin@eduhub.com / admin123',
            student: 'student@kv.edu / student123',
            teacher: 'teacher@kv.edu / teacher123',
            parent: 'parent@example.com / parent123'
        },
        logs_password: 'bunny',
        timestamp: new Date().toISOString()
    });
});

// ===== ERROR HANDLING MIDDLEWARE =====
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.message);
    
    // Log the error
    logs.unshift({
        timestamp: new Date().toISOString(),
        event: 'Server Error',
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        status: 'error'
    });
    
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: err.message
    });
});

// ===== 404 HANDLER =====
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        message: 'The requested endpoint ' + req.method + ' ' + req.path + ' does not exist',
        availableEndpoints: {
            root: 'GET /',
            health: 'GET /api/health',
            logs: 'GET /api/logs?password=bunny',
            auth: 'POST /api/auth/login'
        }
    });
});

// ===== START SERVER =====
app.listen(PORT, () => {
    console.log('🚀 EduHub Backend running on port ' + PORT);
    console.log('📊 Environment: ' + (process.env.NODE_ENV || 'development'));
    console.log('🔄 Serverless mode: Enabled');
    console.log('🗄️ Current database: ' + dbName);
    console.log('📝 Logs password: ' + LOG_PASSWORD);
    console.log('');
    console.log('📡 Important Endpoints:');
    console.log('   👁️  View logs: http://localhost:' + PORT + '/api/logs?password=' + LOG_PASSWORD);
    console.log('   🩺 Health check: http://localhost:' + PORT + '/api/health');
    console.log('   👤 Login: http://localhost:' + PORT + '/api/auth/login');
    console.log('');
    console.log('🔐 Default credentials:');
    console.log('   Admin: admin@eduhub.com / admin123');
    console.log('   Student: student@kv.edu / student123');
    console.log('   Teacher: teacher@kv.edu / teacher123');
    console.log('   Parent: parent@example.com / parent123');
    console.log('');
    console.log('🔄 Server is ready to handle requests...');
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('');
    console.log('🛑 Shutting down server gracefully...');
    
    try {
        await client.close();
        console.log('✅ MongoDB connection closed');
    } catch (error) {
        console.error('❌ Error closing MongoDB connection:', error.message);
    }
    
    console.log('👋 Server stopped');
    process.exit(0);
});

