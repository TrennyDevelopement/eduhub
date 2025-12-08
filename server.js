
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;

// Secure JWT Secret
   const JWT_SECRET = 'eduhub-school-management-system-2024-secure-key';


// CORS configuration - ACCEPTS ANY FRONTEND URL
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.options('*', cors());
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://trenny:trennydev@trennydev.hieeqv2.mongodb.net/trennydev?retryWrites=true&w=majority';

const client = new MongoClient(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

let db;

// Connect to MongoDB
const connectToMongoDB = async () => {
    try {
        console.log('🔄 Connecting to MongoDB...');
        await client.connect();
        db = client.db('eduhub_school');
        console.log('✅ MongoDB connected successfully');
        
        // Create collections if they don't exist
        await initializeCollections();
        await initializeDefaultData();
        
    } catch (error) {
        console.error('❌ MongoDB connection failed:', error.message);
        console.log('🔄 Retrying in 5 seconds...');
        setTimeout(connectToMongoDB, 5000);
    }
};

// Initialize collections
const initializeCollections = async () => {
    const collections = ['users', 'students', 'teachers', 'courses', 'attendance', 'results', 'announcements', 'resources', 'flashcards', 'notes', 'studytimes', 'videos'];
    
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
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await db.collection('users').insertOne({
                email: 'admin@eduhub.com',
                password: hashedPassword,
                name: 'System Administrator',
                role: 'admin',
                phone: '9876543210',
                createdAt: new Date()
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
                parentName: 'Rajesh Sharma',
                parentContact: '9876543210',
                email: 'student@kv.edu',
                createdAt: new Date()
            });
            console.log('✅ Default student created');
        }

        console.log('✅ Default data initialization completed');
    } catch (error) {
        console.error('❌ Error initializing data:', error.message);
    }
};

// Start the connection
connectToMongoDB();

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

// Utility function to calculate grade
const calculateGrade = (marks) => {
    if (marks >= 90) return 'A';
    if (marks >= 80) return 'B';
    if (marks >= 70) return 'C';
    if (marks >= 60) return 'D';
    return 'F';
};

// ===== HEALTH CHECK =====
app.get('/api/health', (req, res) => {
    const dbStatus = db ? 'connected' : 'disconnected';
    
    res.json({ 
        status: 'OK', 
        message: 'EduHub Backend is running!',
        database: dbStatus,
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// ===== AUTHENTICATION ROUTES =====
app.post('/api/auth/register', async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected. Please try again.' });
        }

        const { email, password, name, role, phone, subject, classes, class: userClass, section, rollNo, parentName, parentContact, childId } = req.body;

        const existingUser = await db.collection('users').findOne({ email });
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
            childId,
            createdAt: new Date()
        };

        const result = await db.collection('users').insertOne(userData);
        const user = await db.collection('users').findOne({ _id: result.insertedId });

        const token = jwt.sign(
            { userId: user._id.toString(), email: user.email, role: user.role },
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
        if (!db) {
            return res.status(503).json({ error: 'Database not connected. Please try again.' });
        }

        const { email, password } = req.body;

        const user = await db.collection('users').findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id.toString(), email: user.email, role: user.role },
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

// ===== STUDENT ROUTES =====
app.get('/api/students', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const students = await db.collection('students').find().toArray();
        res.json(students);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/students', authenticateToken, async (req, res) => {
    try {
        if (!db) {
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
            parentContact,
            createdAt: new Date()
        };

        const result = await db.collection('students').insertOne(studentData);
        const student = await db.collection('students').findOne({ _id: result.insertedId });

        // Also create user account
        const hashedPassword = await bcrypt.hash('student123', 10);
        await db.collection('users').insertOne({
            email: email,
            password: hashedPassword,
            name: `${firstName} ${lastName}`,
            role: 'student',
            class: studentClass,
            section: section,
            rollNo: rollNo,
            admissionNo: admissionNo,
            parentName: parentName,
            parentContact: parentContact,
            createdAt: new Date()
        });

        res.status(201).json({ message: 'Student created successfully', student });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== TEACHER ROUTES =====
app.get('/api/teachers', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const teachers = await db.collection('teachers').find().toArray();
        res.json(teachers);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/teachers', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { name, email, subject, classes, contact } = req.body;

        const teacherData = {
            name,
            email,
            subject,
            classes,
            contact,
            createdAt: new Date()
        };

        const result = await db.collection('teachers').insertOne(teacherData);
        const teacher = await db.collection('teachers').findOne({ _id: result.insertedId });

        // Also create user account
        const hashedPassword = await bcrypt.hash('teacher123', 10);
        await db.collection('users').insertOne({
            email: email,
            password: hashedPassword,
            name: name,
            role: 'teacher',
            subject: subject,
            classes: classes,
            contact: contact,
            createdAt: new Date()
        });

        res.status(201).json({ message: 'Teacher created successfully', teacher });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== COURSE ROUTES =====
app.get('/api/courses', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const courses = await db.collection('courses').find().toArray();
        res.json(courses);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/courses', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { title, subject, class: courseClass, description, teacher, youtubeUrl } = req.body;

        const courseData = {
            title,
            subject,
            class: courseClass,
            description,
            teacher,
            youtubeUrl,
            createdAt: new Date()
        };

        const result = await db.collection('courses').insertOne(courseData);
        const course = await db.collection('courses').findOne({ _id: result.insertedId });

        res.status(201).json({ message: 'Course created successfully', course });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== ATTENDANCE ROUTES =====
app.get('/api/attendance', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const attendance = await db.collection('attendance').find().toArray();
        res.json(attendance);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/attendance', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { date, class: attendanceClass, students } = req.body;

        const attendanceData = {
            date: new Date(date),
            class: attendanceClass,
            students,
            createdAt: new Date()
        };

        const result = await db.collection('attendance').insertOne(attendanceData);
        const attendance = await db.collection('attendance').findOne({ _id: result.insertedId });

        res.status(201).json({ message: 'Attendance recorded successfully', attendance });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== RESULTS ROUTES =====
app.get('/api/results', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const results = await db.collection('results').find().toArray();
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/results', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { studentId, examType, subject, marks, totalMarks, class: resultClass, driveLink } = req.body;

        const grade = calculateGrade(marks);

        const resultData = {
            studentId,
            examType,
            subject,
            marks,
            totalMarks,
            grade,
            class: resultClass,
            driveLink,
            createdAt: new Date()
        };

        const result = await db.collection('results').insertOne(resultData);
        const newResult = await db.collection('results').findOne({ _id: result.insertedId });

        res.status(201).json({ message: 'Result saved successfully', result: newResult });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== ANNOUNCEMENT ROUTES =====
app.get('/api/announcements', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const announcements = await db.collection('announcements').find().toArray();
        res.json(announcements);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/announcements', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { title, content, audience, priority } = req.body;

        const announcementData = {
            title,
            content,
            audience,
            priority,
            createdBy: req.user.userId,
            date: new Date()
        };

        const result = await db.collection('announcements').insertOne(announcementData);
        const announcement = await db.collection('announcements').findOne({ _id: result.insertedId });

        res.status(201).json({ message: 'Announcement created successfully', announcement });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== RESOURCE ROUTES =====
app.get('/api/resources', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const resources = await db.collection('resources').find().toArray();
        res.json(resources);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/resources', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { type, title, content, subject, class: resourceClass } = req.body;

        const resourceData = {
            type,
            title,
            content,
            subject,
            class: resourceClass,
            createdBy: req.user.userId,
            createdAt: new Date()
        };

        const result = await db.collection('resources').insertOne(resourceData);
        const resource = await db.collection('resources').findOne({ _id: result.insertedId });

        res.status(201).json({ message: 'Resource created successfully', resource });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== FLASHCARD ROUTES =====
app.get('/api/flashcards', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const flashcards = await db.collection('flashcards').find({ createdBy: req.user.userId }).toArray();
        res.json(flashcards);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/flashcards', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { question, answer } = req.body;

        const flashcardData = {
            question,
            answer,
            createdBy: req.user.userId,
            createdAt: new Date()
        };

        const result = await db.collection('flashcards').insertOne(flashcardData);
        const flashcard = await db.collection('flashcards').findOne({ _id: result.insertedId });

        res.status(201).json({ message: 'Flashcard created successfully', flashcard });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== NOTE ROUTES =====
app.get('/api/notes', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const notes = await db.collection('notes').find({ createdBy: req.user.userId }).toArray();
        res.json(notes);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/notes', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { content } = req.body;

        const noteData = {
            content,
            createdBy: req.user.userId,
            date: new Date()
        };

        const result = await db.collection('notes').insertOne(noteData);
        const note = await db.collection('notes').findOne({ _id: result.insertedId });

        res.status(201).json({ message: 'Note created successfully', note });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/notes/:id', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        await db.collection('notes').deleteOne({ _id: new ObjectId(req.params.id), createdBy: req.user.userId });
        res.json({ message: 'Note deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== STUDY TIME ROUTES =====
app.get('/api/study-times', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const studyTimes = await db.collection('studytimes').find({ userId: req.user.userId }).toArray();
        res.json(studyTimes);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/study-times', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { minutes } = req.body;

        const studyTimeData = {
            userId: req.user.userId,
            minutes,
            date: new Date()
        };

        const result = await db.collection('studytimes').insertOne(studyTimeData);
        const studyTime = await db.collection('studytimes').findOne({ _id: result.insertedId });

        res.status(201).json({ message: 'Study time updated successfully', studyTime });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== VIDEO ROUTES =====
app.get('/api/videos', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }
        const videos = await db.collection('videos').find().toArray();
        res.json(videos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/videos', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const { courseId, title, description, youtubeId, order } = req.body;

        const videoData = {
            courseId,
            title,
            description,
            youtubeId,
            order,
            createdAt: new Date()
        };

        const result = await db.collection('videos').insertOne(videoData);
        const video = await db.collection('videos').findOne({ _id: result.insertedId });

        res.status(201).json({ message: 'Video added successfully', video });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== DASHBOARD STATS =====
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        if (!db) {
            return res.status(503).json({ error: 'Database not connected' });
        }

        const totalStudents = await db.collection('students').countDocuments();
        const totalTeachers = await db.collection('teachers').countDocuments();
        const totalCourses = await db.collection('courses').countDocuments();
        
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

// ===== ROOT ENDPOINT =====
app.get('/', (req, res) => {
    const dbStatus = db ? 'connected' : 'disconnected';
    
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
            attendance: ['GET /api/attendance', 'POST /api/attendance'],
            results: ['GET /api/results', 'POST /api/results'],
            announcements: ['GET /api/announcements', 'POST /api/announcements'],
            resources: ['GET /api/resources', 'POST /api/resources'],
            flashcards: ['GET /api/flashcards', 'POST /api/flashcards'],
            notes: ['GET /api/notes', 'POST /api/notes', 'DELETE /api/notes/:id'],
            study_times: ['GET /api/study-times', 'POST /api/study-times'],
            videos: ['GET /api/videos', 'POST /api/videos'],
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
