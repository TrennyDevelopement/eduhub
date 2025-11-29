require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// Secure JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'eduhub-' + Date.now() + '-' + Math.random().toString(36).substring(2, 15) + '-secure-key';

// CORS configuration - ACCEPTS ANY FRONTEND URL
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.options('*', cors());
app.use(express.json());

// ✅ MULTIPLE MONGODB URI OPTIONS
const MONGODB_URIS = [
    // Option 1: Direct connection without SRV
    'mongodb://trennydevelopement:trennyontop@cluster0.eprlndt.mongodb.net:27017/eduhub_school?retryWrites=true&w=majority&ssl=true',
    
    // Option 2: Standard connection
    'mongodb://trennydevelopement:trennyontop@cluster0.eprlndt.mongodb.net/eduhub_school?retryWrites=true&w=majority&ssl=true',
    
    // Option 3: Your original URI (will fail but we try anyway)
    'mongodb+srv://trennydevelopement:trennyontop@cluster0.eprlndt.mongodb.net/eduhub_school?retryWrites=true&w=majority'
];

let currentUriIndex = 0;

// ✅ IMPROVED MONGODB CONNECTION WITH MULTIPLE STRATEGIES
const connectWithRetry = async (uriIndex = 0) => {
    if (uriIndex >= MONGODB_URIS.length) {
        console.error('❌ All MongoDB connection attempts failed');
        console.log('🔄 Will retry all URIs in 30 seconds...');
        setTimeout(() => connectWithRetry(0), 30000);
        return;
    }

    const currentUri = MONGODB_URIS[uriIndex];
    
    try {
        console.log(`🔄 Attempting MongoDB connection (Attempt ${uriIndex + 1}/3)...`);
        console.log(`📡 Using URI: ${currentUri.replace(/mongodb[+srv]*:\/\/([^:]+):([^@]+)@/, 'mongodb://***:***@')}`);
        
        await mongoose.connect(currentUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 15000, // 15 seconds
            socketTimeoutMS: 45000,
            maxPoolSize: 10,
            retryWrites: true,
            w: 'majority'
        });
        
        console.log('✅ MongoDB connected successfully!');
        console.log('📊 Database:', mongoose.connection.db?.databaseName || 'Unknown');
        console.log('🔗 Connection URI used:', MONGODB_URIS[currentUriIndex].replace(/mongodb[+srv]*:\/\/([^:]+):([^@]+)@/, 'mongodb://***:***@'));
        
        // Initialize data after successful connection
        await initializeDefaultData();
        
    } catch (error) {
        console.error(`❌ MongoDB connection failed (Attempt ${uriIndex + 1}/3):`, error.message);
        
        // Close any existing connection
        if (mongoose.connection.readyState !== 0) {
            await mongoose.connection.close();
        }
        
        // Try next URI
        console.log(`🔄 Trying next connection option in 3 seconds...`);
        setTimeout(() => connectWithRetry(uriIndex + 1), 3000);
    }
};

// Start the connection
connectWithRetry(0);


// Database Schemas
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    role: { type: String, required: true },
    phone: String,
    subject: String,
    classes: [String],
    class: String,
    section: String,
    rollNo: Number,
    admissionNo: String,
    parentName: String,
    parentContact: String,
    childId: String,
    createdAt: { type: Date, default: Date.now }
});

const StudentSchema = new mongoose.Schema({
    admissionNo: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    class: { type: String, required: true },
    section: { type: String, required: true },
    rollNo: { type: Number, required: true },
    parentName: { type: String, required: true },
    parentContact: { type: String, required: true },
    email: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const TeacherSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    classes: [String],
    contact: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const CourseSchema = new mongoose.Schema({
    title: { type: String, required: true },
    subject: { type: String, required: true },
    class: { type: String, required: true },
    description: String,
    teacher: { type: String, required: true },
    youtubeUrl: String,
    createdAt: { type: Date, default: Date.now }
});

const AttendanceSchema = new mongoose.Schema({
    date: { type: Date, required: true },
    class: { type: String, required: true },
    students: [{
        studentId: { type: String, required: true },
        status: { type: String, required: true }
    }],
    createdAt: { type: Date, default: Date.now }
});

const ResultSchema = new mongoose.Schema({
    studentId: { type: String, required: true },
    examType: { type: String, required: true },
    subject: { type: String, required: true },
    marks: { type: Number, required: true },
    totalMarks: { type: Number, default: 100 },
    grade: { type: String, required: true },
    class: { type: String, required: true },
    driveLink: String,
    createdAt: { type: Date, default: Date.now }
});

const AnnouncementSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    audience: { type: String, required: true },
    priority: { type: String, required: true },
    createdBy: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

const ResourceSchema = new mongoose.Schema({
    type: { type: String, required: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    subject: { type: String, required: true },
    class: { type: String, required: true },
    createdBy: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const FlashcardSchema = new mongoose.Schema({
    question: { type: String, required: true },
    answer: { type: String, required: true },
    createdBy: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const NoteSchema = new mongoose.Schema({
    content: { type: String, required: true },
    createdBy: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

const StudyTimeSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    date: { type: Date, default: Date.now },
    minutes: { type: Number, required: true }
});

const VideoSchema = new mongoose.Schema({
    courseId: { type: String, required: true },
    title: { type: String, required: true },
    description: String,
    youtubeId: { type: String, required: true },
    order: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Student = mongoose.model('Student', StudentSchema);
const Teacher = mongoose.model('Teacher', TeacherSchema);
const Course = mongoose.model('Course', CourseSchema);
const Attendance = mongoose.model('Attendance', AttendanceSchema);
const Result = mongoose.model('Result', ResultSchema);
const Announcement = mongoose.model('Announcement', AnnouncementSchema);
const Resource = mongoose.model('Resource', ResourceSchema);
const Flashcard = mongoose.model('Flashcard', FlashcardSchema);
const Note = mongoose.model('Note', NoteSchema);
const StudyTime = mongoose.model('StudyTime', StudyTimeSchema);
const Video = mongoose.model('Video', VideoSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Initialize Default Data - WITH ERROR HANDLING
const initializeDefaultData = async () => {
    try {
        console.log('🔄 Checking for default data...');
        
        // Wait for mongoose connection to be ready
        if (mongoose.connection.readyState !== 1) {
            console.log('⏳ Waiting for database connection...');
            return;
        }

        const adminExists = await User.findOne({ email: 'admin@eduhub.com' });
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await User.create({
                email: 'admin@eduhub.com',
                password: hashedPassword,
                name: 'System Administrator',
                role: 'admin',
                phone: '9876543210'
            });
            console.log('✅ Default admin user created');
        } else {
            console.log('✅ Admin user already exists');
        }

        console.log('✅ Default data initialization completed');
    } catch (error) {
        console.error('❌ Error initializing data:', error.message);
    }
};

// Health check that works even if DB is not connected
app.get('/api/health', (req, res) => {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    res.json({ 
        status: 'OK', 
        message: 'EduHub Backend is running!',
        database: dbStatus,
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        // Check if DB is connected
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not connected. Please try again.' });
        }

        const { email, password, name, role, phone, subject, classes, class: userClass, section, rollNo, parentName, parentContact, childId } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const userData = {
            email,
            password: hashedPassword,
            name,
            role,
            phone,
            subject,
            classes,
            class: userClass,
            section,
            rollNo,
            parentName,
            parentContact,
            childId
        };

        const user = new User(userData);
        await user.save();

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                _id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                class: user.class,
                section: user.section,
                rollNo: user.rollNo,
                subject: user.subject,
                classes: user.classes,
                childId: user.childId
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        // Check if DB is connected
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not connected. Please try again.' });
        }

        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                _id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                class: user.class,
                section: user.section,
                rollNo: user.rollNo,
                subject: user.subject,
                classes: user.classes,
                childId: user.childId
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Student Routes
app.get('/api/students', authenticateToken, async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const students = await Student.find();
        res.json(students);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/students', authenticateToken, async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { firstName, lastName, class: studentClass, section, rollNo, admissionNo, email, parentName, parentContact } = req.body;

        const studentData = {
            firstName,
            lastName,
            class: studentClass,
            section,
            rollNo,
            admissionNo,
            email,
            parentName,
            parentContact
        };

        const student = new Student(studentData);
        await student.save();

        const hashedPassword = await bcrypt.hash('student123', 10);
        await User.create({
            email: email,
            password: hashedPassword,
            name: `${firstName} ${lastName}`,
            role: 'student',
            class: studentClass,
            section: section,
            rollNo: rollNo,
            admissionNo: admissionNo,
            parentName: parentName,
            parentContact: parentContact
        });

        res.status(201).json({ message: 'Student created successfully', student });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Teacher Routes
app.get('/api/teachers', authenticateToken, async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const teachers = await Teacher.find();
        res.json(teachers);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/teachers', authenticateToken, async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { name, email, subject, classes, contact } = req.body;

        const teacherData = {
            name,
            email,
            subject,
            classes,
            contact
        };

        const teacher = new Teacher(teacherData);
        await teacher.save();

        const hashedPassword = await bcrypt.hash('teacher123', 10);
        await User.create({
            email: email,
            password: hashedPassword,
            name: name,
            role: 'teacher',
            subject: subject,
            classes: classes,
            contact: contact
        });

        res.status(201).json({ message: 'Teacher created successfully', teacher });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Course Routes
app.get('/api/courses', authenticateToken, async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const courses = await Course.find();
        res.json(courses);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/courses', authenticateToken, async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { title, subject, class: courseClass, description, teacher, youtubeUrl } = req.body;

        const courseData = {
            title,
            subject,
            class: courseClass,
            description,
            teacher,
            youtubeUrl
        };

        const course = new Course(courseData);
        await course.save();

        res.status(201).json({ message: 'Course created successfully', course });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Dashboard Stats
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const totalStudents = await Student.countDocuments();
        const totalTeachers = await Teacher.countDocuments();
        const totalCourses = await Course.countDocuments();
        
        res.json({
            totalStudents,
            totalTeachers,
            totalCourses,
            attendanceRate: '92%',
            pendingTasks: Math.floor(Math.random() * 20) + 5
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Root Endpoint
app.get('/', (req, res) => {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    res.json({ 
        message: 'EduHub School Management System API',
        version: '1.0.0',
        database: dbStatus,
        endpoints: {
            health: 'GET /api/health',
            auth: ['POST /api/auth/login', 'POST /api/auth/register'],
            students: ['GET /api/students', 'POST /api/students'],
            teachers: ['GET /api/teachers', 'POST /api/teachers'],
            courses: ['GET /api/courses', 'POST /api/courses'],
            dashboard: 'GET /api/dashboard/stats'
        }
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 EduHub Backend running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
    console.log(`🌐 API Root: http://localhost:${PORT}/`);
});
